#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cplane_unit.h"
#include <cplane/server.h>

#include "../../tap/tap.h"



static const int ITERATIONS = 1000000;
static const int TABLE_VALIDITY_CHECKS = 1000;
static const int IFINDEX = 1;

/* The control plane doesn't do anything very much with preferred source
 * addresses and next hops, so we just use one of each when building
 * routing tables. */
static const in_addr_t PREF_SRC = 0x01010101;
static const in_addr_t NEXT_HOP = 0x02020202;

static bool tests_pass = true;

static void generate_random_route_table(struct cp_session* s)
{
  /* Simulate a dump of the OS's route tables.  This should cause the control
   * plane to forget about any previous routes.
   *
   * We must emulate all the normal dumping process to avoid ci_assert().
   */
  cp_ipif_dump_start(s, AF_INET);
  cp_rule_dump_start(s, AF_INET);
  cp_rule_dump_done(s, AF_INET);
  cp_route_dump_start(s, AF_INET);
  s->state = CP_DUMP_ROUTE;

  /* Always provide a default gateway. */
  cp_unit_insert_gateway(s, NEXT_HOP, 0, 0, IFINDEX);

  /* Provide some number of random routes.  Nothing prevents the resulting
   * table from containing pairwise-inconsistent entries, but that's OK: the
   * kernel can do the same thing, and the control plane doesn't care anyway.
   */
  int i;
  int other_routes = 2 + (rand() & 15);
  for( i = 0; i < other_routes; ++i ) {
    int prefix;
    in_addr_t dest;
    do {
      /* Prefer longer prefixes. */
      prefix = 32 - __builtin_ffs(rand32());
      dest = rand32() & cp_prefixlen2bitmask(prefix);
    } while( prefix == 0 || dest == 0 );
    if( rand() & 1 )
      cp_unit_insert_route(s, dest, prefix, PREF_SRC, IFINDEX);
    else
      cp_unit_insert_gateway(s, NEXT_HOP, dest, prefix, IFINDEX);
  }

  cp_route_dump_done(s, AF_INET);
  cp_nl_dump_all_done(s);
}


static void check_resolution(struct cp_session* s, in_addr_t dest,
                             in_addr_t src, in_addr_t next_hop)
{
  struct cp_fwd_key key = {
    .src.ip4 = src,
    .src.ones = 0xffff,
    .dst.ip4 = dest,
    .dst.ones = 0xffff,
  };
  struct cp_fwd_state* fwd_state = cp_fwd_state_get(s, 0);
  cicp_mac_rowid_t id = cp_fwd_find_match(&fwd_state->fwd_table, &key,
                                          CP_FWD_MULTIPATH_WEIGHT_NONE);
  if( CICP_MAC_ROWID_IS_VALID(id) ) {
    struct cp_fwd_state* fwd_state = cp_fwd_state_get(s, 0);
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(&fwd_state->fwd_table, id);
    if( cp_get_fwd_data_current(fwd)->base.next_hop.ip4 != next_hop ) {
      char dst_str[16], src_str[16];
      CP_TEST(inet_ntop(AF_INET, &dest, dst_str, INET_ADDRSTRLEN));
      CP_TEST(inet_ntop(AF_INET, &src, src_str, INET_ADDRSTRLEN));
      diag("Failed check %s from %s", dst_str, src_str);
      diag("Next hop is incorrect: %u != %u",
           cp_get_fwd_data_current(fwd)->base.next_hop.ip4, next_hop);
      tests_pass = false;
    }
  }
  else {
    diag("No resolution found.");
    tests_pass = false;
  }
}


static void add_random_resolution(struct cp_session* s)
{
  /* Add in a resolution via a gateway.  We don't test link-scoped resolutions
   * here as, since we don't ensure that we insert consistent routes, they
   * would weaken the tests that we can make on the state of the table. */
  in_addr_t dest = rand32();
  in_addr_t next_hop;
  do {
    next_hop = rand32();
  } while( next_hop == 0 );
  cp_unit_insert_resolution(s, dest, 0, PREF_SRC, next_hop, IFINDEX);
  check_resolution(s, dest, 0, next_hop);
}


static void add_random_existing_resolution(struct cp_session* s)
{
  /* Choose an entry at random from the table and add another resolution for
   * the same address.  If the routing tables are unchanged since the existing
   * entry was added, that entry will simply be updated.  Otherwise, the change
   * to the table might be more complicated. */
  struct cp_fwd_state* fwd_state = cp_fwd_state_get(s, 0);
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  int seq = rand() & fwd_table->mask;
  cicp_mac_rowid_t id = CICP_MAC_ROWID_BAD;
  do {
    if( id == CICP_MAC_ROWID_BAD )
      id = 0;
    id = cp_row_mask_iter_set(fwd_state->fwd_used, id,
                              fwd_table->mask + 1, true);
  } while( seq-- > 0 );

  if( id != CICP_MAC_ROWID_BAD ) {
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, id);
    in_addr_t dest = fwd->key.dst.ip4;
    in_addr_t src = fwd->key.src.ip4;
    /* Tweak the next hop so that we can check that the table has been updated.
     */
    in_addr_t new_next_hop = cp_get_fwd_data_current(fwd)->base.next_hop.ip4 + 1;

    cp_unit_insert_resolution(s, dest, src, PREF_SRC, new_next_hop, IFINDEX);
    check_resolution(s, dest, src, new_next_hop);
  }
}


/* Does a/a_prefix intersect with b/b_prefix? */
static bool
networks_overlap(in_addr_t a, int a_prefix, in_addr_t b, int b_prefix)
{
  int prefix = CI_MIN(a_prefix, b_prefix);
  in_addr_t mask = cp_prefixlen2bitmask(prefix);
  return (a & mask) == (b & mask);
}

/* Tests whether two cp_fwd_key values (together with the prefixes in the
 * corresponding cp_fwd_key_ext structures) describe overlapping networks. */
static bool
fwd_keys_overlap(struct cp_fwd_key* a, struct cp_fwd_key_ext* a_ext,
                 struct cp_fwd_key* b, struct cp_fwd_key_ext* b_ext)
{
  return networks_overlap(a->src.ip4, a_ext->src_prefix,
                          b->src.ip4, b_ext->src_prefix) &&
         networks_overlap(a->dst.ip4, a_ext->dst_prefix,
                          b->dst.ip4, b_ext->dst_prefix);
}


/* Calculates the inverse of n modulo modulus, where modulus is a power of two.
 */
static uint32_t inverse(uint32_t n, uint32_t modulus)
{
  unsigned x, x_next = 1;

  /* n must be odd to have an inverse. */
  ci_assert_flags(n, 1);

  do {
    x = x_next;
    x_next = (x * (2u - n * x)) & (modulus - 1);
  } while( x_next != x );

  return x;
}


/* The fwd table has a number of nice invariants:
 *  - no two entries should have overlapping keys,
 *  - every entry should be found when cp_fwd_find_match() is called for that
 *    entry's key, and
 *  - all entries lie on a valid path through the hash table.
 * This function checks these properties.  Its running time is quadratic in the
 * number of populated entries in the table. */
static bool check_fwd_table_validity(struct cp_session* s)
{
  struct cp_fwd_state* fwd_state = cp_fwd_state_get(s, 0);
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_mac_rowid_t i, j;
  uint64_t recorded_hops = 0;
  uint64_t actual_hops = 0;
  bool table_ok = true;

  for( i = 0; i < fwd_table->mask + 1; ++i ) {
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, i);
    recorded_hops += fwd->use;

    if( fwd->flags & CICP_FWD_FLAG_OCCUPIED ) {
      cicp_mac_rowid_t hash1, hash2;
      cp_calc_fwd_hash(fwd_table, &fwd->key, &hash1, &hash2);
      actual_hops += (((i - hash1) * inverse(hash2, fwd_table->mask + 1)) &
                      fwd_table->mask) + 1;

      j = cp_fwd_find_match(fwd_table, &fwd->key,
                                   CP_FWD_MULTIPATH_WEIGHT_NONE);
      if( i != j ) {
        diag("lookup for %d found %d instead", i, j);
        table_ok = false;
      }

      for( j = i + 1; j < fwd_table->mask + 1; ++j ) {
        struct cp_fwd_row* fwd_other = cp_get_fwd_by_id(fwd_table, j);
        if( fwd_other->flags & CICP_FWD_FLAG_OCCUPIED &&
            fwd_keys_overlap(&fwd->key, &fwd->key_ext, &fwd_other->key,
                             &fwd_other->key_ext) ) {
          diag("fwd entries %d and %d overlap", i, j);
          table_ok = false;
        }
      }
    }
  }

  if( actual_hops != recorded_hops ) {
    diag("Hop-count mismatch: actual=%u recorded=%u", actual_hops,
         recorded_hops);
    table_ok = false;
  }

  if( ! table_ok ) {
    fail("Table invariant violated.");
    cp_unit_dump_cplane_tables(s);
  }

  return table_ok;
}


int main(void)
{
  cp_unit_init();
  struct cp_session s;

  srand(0x5eed5eed);

  cp_unit_init_session(&s);

  /* To prevent overflow, we add at most one entry to the fwd table per tick,
   * and ensure that we expire entries before we have a chance to fill the
   * table. */
  const int TICKS_PER_ITERATION = s.khz * 1000ull;
  s.frc_fwd_cache_ttl = 128 * TICKS_PER_ITERATION;
  CP_TEST(s.frc_fwd_cache_ttl <
          (s.mib[0].dim->fwd_mask + 1) * TICKS_PER_ITERATION);

  /* There is not much in the way of interaction between the routing and LLAP
   * tables, so we only use a single interface. */
  const char mac[] = {0x00, 0x0f, 0x53, 0x00, 0x00, 0x00};
  cp_unit_nl_handle_link_msg(&s, RTM_NEWLINK, IFINDEX, "ethO0", mac);

  generate_random_route_table(&s);

  /* Too much output slows down the JUnit formatter, so keep to one test point.
   */
  plan(1);

  int i;
  for( i = 0; i < ITERATIONS; ++i ) {
    /* In each iteration, we either add an entry, update an entry or update the
     * route tables.  Choose from amongst these operations randomly with
     * different weights. */
    int op = rand() & 0xff;
    if( op < 0xf0 )
      add_random_resolution(&s);
    else if( op < 0xff )
      add_random_existing_resolution(&s);
    else
      generate_random_route_table(&s);

    /* This check is expensive, so we don't do it very often. */
    if( (i + 1) % (ITERATIONS / TABLE_VALIDITY_CHECKS) == 0 )
      if( ! check_fwd_table_validity(&s) )
        done_testing();

    cp_time_elapse(TICKS_PER_ITERATION);
    cp_fwd_timer(&s);
  }

  /* Make a final validity check, unless we just did. */
  if( ITERATIONS % TABLE_VALIDITY_CHECKS != 0 )
    if( ! check_fwd_table_validity(&s) )
      done_testing();

  ok(tests_pass, "Survived stress test");

  done_testing();

  return 0;
}
