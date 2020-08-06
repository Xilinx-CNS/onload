/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/* Forward cache implementation
 * ============================
 *
 * The idea of forward cache is to map a cp_fwd_key structure (which
 * contains destination IP address, an optional source IP address, optional
 * ifindex to send via it, and optional Type-Of-Service) to a cp_fwd_data
 * structure with all the information needed to perform such a send.
 * To avoid parsing and re-implementing rules for policy routing
 * (man ip-rule), the Control Plane Server asks Linux to resolve each
 * particular key via netlink (similar to "ip route get").  The result is
 * stored in the forward cache table; this table is updated if route table,
 * rule table, or other pertinent tables change.
 *
 * 1. Any match is good (with a few exceptions, see below).
 * 2. All the information needed by the user of the forward cache is in one
 *    table entry; no external reference is allowed.
 * 3. Each forward entry is protected by a version-lock.  In case of even
 *    verlock value, user should use fwd->data[0], and fwd->data[1]
 *    otherwise.  Start again if verlock changes under feet.
 * 4. Fwd cache is a hash table; size is set from command line.
 * 5. Bitmap of all prefixes in use: fwd_prefix.
 * 6. How client uses it: cp_fwd_find_match() in English.
 * 7. Time-to-live for fwd entries.
 *
 *
 * Rationale and implementation details for each point
 * ---------------------------------------------------
 *
 * 1. Any match is good
 * --------------------
 *
 * A forward entry defines route when sending packets
 * - from  key.src/key_ext.src_prefix IP address
 * - to    key.dst/key_ext.dst_prefix IP address
 * - via   key.ifindex (CI_IFID_BAD=0 means "any")
 * - with  key.tos (0 means "any"; specific TOS wins)
 *
 * In the most cases, forward cache contains no more than one entry which
 * fits any given cp_fwd_key structure.  Unlike traditional route tables,
 * which can contain something like
 *   to 10.0.0.0/8    via A
 *   to 10.10.10.0/24 via B
 * forward cache would split the first of these 2 routes into the entries
 * like
 *   to 10.128.0.0/9 via A
 *   to 10.64.0.0/10 via A
 *   ....
 * So the user of forward cache does not need to traverse all the cache
 * searching for the best prefix; any match is good.
 *
 *
 * 1a. PMTU exception.
 *
 * When we receive Path MTU information, we add src/32 -> dst/32 forward
 * cache entry (IPv4 case).  And we do not delete any generic entries, but
 * update that generic entry verlock.  After that, any user of the generic
 * entry re-resolves the route, and will catch the specific /32 route with
 * the Path MTU information if needed.
 *
 * This approach requires that any user starts to resolve a route from the
 * explicit one.
 *
 *
 * 1b. TOS exception.
 *
 * If user resolves a route with specific TOS, they should start searching
 * an entry with this specific TOS value, then repeat with tos=0 if nothing
 * found.
 *
 * When a forward entry with non-zero tos is added, and similar entry with
 * zero tos exists, the verlock of the pre-existing one must be incremented.
 * This ensures that users will notice the change.
 *
 *
 * 2. All the info is here
 * -----------------------
 *
 * When a cplane user (Onload, ZF, etc) wants to send a packet, all the
 * necessary information is already in the fwd entry.  It includes MAC
 * addresses (both source and destination), hw port number(s), vlan
 * information, bonding information (hash type).  User has no need to do
 * any additional lookups in ARP table, llap table, bonding table or
 * anything else.  All that information is in one fwd entry, protected by
 * one version lock.  If verlock does not change, than the information is
 * guaranteed to be consistent.  I.e. if the route changes outgoing
 * interface, then the hwport field and source mac address field will be
 * changed together, and user gets the old values for both fields or the
 * new ones for both.
 *
 * It may happen that a fwd entry does not have ARP information, because
 * this ARP is not resolved yet.  Cplane does its best to resolve ARP as
 * soon as possible, as long as the fwd entry is in the fwd table.
 *
 * As a result of this tenet, a direct link-route is not stored in the fwd
 * cache as a one entry; instead, each particular destination is stored in
 * a separate fwd entry with its particular ARP information.
 *
 * 3. Version lock
 * ---------------
 *
 * Each fwd entry is protected by a separate version lock.  Mibs structure
 * has a global version lock, but fwd entries are out of this global
 * verlock responsibility.  If verlock is odd, user must use fwd->data[1]; if
 * verlock is even, user must use fwd->data[0].  In the most cases, user
 * can use cp_get_fwd_data_current() to get the up-to-date data structure
 * and check that verlock value does not change under their feet.
 *
 * When cplane updates a fwd entry, it performs it in following sequence:
 * - update non-active data structure;
 * - move verlock;
 * - update another data structure;
 * - move verlock again.
 * The last step does not look necessary, but it is easier to code this
 * all.  For example in some cases cplane updates verlock without any
 * update to the data itself (see sections 1 and 7).
 *
 *
 * 4. Hash table
 * -------------
 *
 * Forward table is a hash table mapping from cp_fwd_key structure to
 * cp_fwd_data structure, with an addition of cp_fwd_key_ext structure.
 *
 * The cp_fwd_key stores:
 * - source IP address (0 if any address is good);
 * - destination IP address;
 * - ifindex of the outgoing interface (CI_IFID_BAD=0 for any interface);
 * - TOS value.
 * The cp_fwd_key_ext structure contains prefix length for the source and
 * destination IP addresses.
 *
 * When stored in the fwd table, the source and destination IPs from the
 * key should be masked by the corresponding prefixes from cp_fwd_key_ext.
 * It means that we do not store destination 192.168.239.91/24; we store
 * 192.168.239.0/24.
 *
 * onload_hash1() calculates hash of a cp_fwd_key structure, and the
 * resulting hash is used as an index to store the fwd entry.  If this slot
 * is already in use, cplane_hash2() is added to the previous value
 * (multiple times if necessary).
 *
 * Ideally, we'd prefer to avoid the use of cplane_hash2() completely.  For
 * this, the size of the fwd table should be large enough.  When running
 * "onload_mibdump fwd", there is "in use" field printed.  If any of these
 * field is more than 1, it is a hint that fwd table size may be worth
 * increasing.  Another hint is almost-full fwd table.  Normally, about
 * a half of the table is expected to be free (use "onload_mibdump usage"
 * to check for this condition).
 * TODO: Do we want to copy this paragraph to Onload User Guide?
 *
 *
 * 5. Ask kernel to find out a route
 * ---------------------------------
 *
 * When cplane has to resolve a route, it asks kernel about this particular
 * route.  It is equivalent to command line
 *   ip route get 1.2.3.4 from 5.6.7.8 tos 2 oif 7
 * See fwd_resolve() function.
 *
 * To store the kernel reply in the fwd cache we determine the widest
 * prefix for the source and destination addresses.  It is done with the
 * help of (ip6_)route_dst and (ip6_)rule_src lists.  See
 * cp_nl_route_handle() function.
 *
 *
 * 6. Multipath
 * ------------
 *
 * In the previous section, if the route looks like a multipath route, we
 * do some crazy things.  This all happens to work by a miracle.
 *
 *
 * 7. Time-to-live
 * ---------------
 *
 * The fwd entries are stored in the fwd cache as long as some client uses
 * them.  To facilitate this fwd_table->rw_rows[id].frc_used field is used;
 * it must be updated by the client.
 *
 * If a fwd entry is not accessed for frc_fwd_cache_ttl/2, the entry is
 * marked by CICP_FWD_FLAG_STALE and verlock is incremented.  If there is
 * a user interested in this row, they notice the verlock change and call
 * __oo_cp_route_resolve(), which results in the frc_used field update.
 *
 *
 * 8. fwd_table->prefix bitmaps
 * ----------------------------
 *
 * As mentioned in (1), when a cplane user tries to resolve a route from
 * 1.2.3.4 to 5.6.7.8, they should try to find 1.2.3.4/32->5.6.7.8/32
 * entry, then 1.2.3.0->5.6.7.8, etc etc.  To optimize the search there
 * are bitmaps which contain all the prefix lengths really used in the fwd
 * cache.
 *
 * Prefix lengths are never removed from these bitmaps.
 */

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <ci/compat.h>
#include <ci/tools/sysdep.h>
#include <ci/tools/utils.h>
#include <ci/net/ethernet.h>
#include <ci/net/ipv4.h>
#include "private.h"
#include "mibdump.h"
#include <cplane/ioctl.h>
#include <cplane/server.h>
#include <cplane/mmap.h>


/* Maximum address prefix leangth */
#define CP_MAX_PREFIX_LEN 128

/* Duplicate default Hop Limit value from transport_config_opt.h.
 * IPv6 Hop Limit and IPv4 TTL are equal, so there is no reason do branching. */
#define CI_IPV6_DFLT_HOPLIMIT  64


static struct cp_route_table**
cp_route_table_array_by_af(struct cp_session* s, int af)
{
  if( af == AF_INET )
    return s->rt_table;
  else
    return s->rt6_table;
}

/* Part of cp_route_compare(), also used to determine if the entries are
 * part of the same multipath routes */
static int
cp_route_cmp_multipath(const void* void_a, const void* void_b)
{
  const struct cp_route* a = void_a;
  const struct cp_route* b = void_b;

  if( a->dst.prefix != b->dst.prefix )
    return b->dst.prefix - a->dst.prefix; /* larger is better */
  if( a->metric != b->metric )
    return a->metric - b->metric; /* lesser is better */
  if( a->scope != b->scope )
    return a->scope - b->scope; /* lesser is better */
  if( a->tos != b->tos )
    return b->tos - a->tos; /* perfect match is better than 0 */

  /* any ordering */
  return memcmp(b->dst.addr.ip6, a->dst.addr.ip6, sizeof(a->dst.addr.ip6));
}
static int cp_route_compare(const void *void_a, const void *void_b)
{
  const struct cp_route* a = void_a;
  const struct cp_route* b = void_b;

  int ret = cp_route_cmp_multipath(a, b);
  if( ret != 0 )
    return ret;
 
  /* lesser is better: first entries first */
  return a->weight.end - b->weight.end;
}

static struct cp_route_table*
cp_route_table_find(struct cp_session* s, uint32_t table_id, int af)
{
  struct cp_route_table* table =
      cp_route_table_array_by_af(s, af)[table_id & (ROUTE_TABLE_HASH_SIZE-1)];

  while( table != NULL ) {
    if( table->id == table_id )
      return table;
    table = table->next;
  }
  return NULL;
}

static inline bool
cp_routes_under_dump(struct cp_session* s, int af)
{
  return s->state == (af == AF_INET ? CP_DUMP_ROUTE : CP_DUMP_ROUTE6);
}

static struct cp_route*
cp_route_entry_from_dst(struct cp_ip_with_prefix* dst)
{
  return CI_CONTAINER(struct cp_route, dst, dst);
}

static bool
cp_route_del(struct cp_session* s, uint32_t table_id,
             struct cp_route* route, int af)
{
  struct cp_route_table* table = cp_route_table_find(s, table_id, af);
  if( table == NULL )
    return false;

  bool changed = false;
  bool multipath = false;
  do {
    /* In theory, we can so something similar to cp_route_add() and
     * leverage ordering of the route list.  But for del() it is trickier
     * than for add(), because we really have to handle non-ordered case
     * when the route table is in_dump. */
    struct cp_ip_with_prefix* dst = __cp_ippl_search(&table->routes,
                                                     &route->dst,
                                                     cp_route_cmp_multipath);
    if( dst == NULL )
      return changed; /* multipath exit is here */

    if( ! multipath )
      multipath = cp_route_entry_from_dst(dst)->weight.end != 0;

    cp_ippl_del(&table->routes, dst);
    changed = true;
    if( s->flags & CP_SESSION_LADDR_USE_PREF_SRC )
      s->flags |= CP_SESSION_LADDR_REFRESH_NEEDED;
  } while( multipath );

  return changed;
}

static struct cp_route*
cp_route_entry_by_idx(struct cp_route_table* table, int idx)
{
  return cp_route_entry_from_dst(cp_ippl_entry(&table->routes, idx));
}

static void
cp_route2laddr(struct cp_session* s, struct cp_route* route, int af)
{
  if( route->type != RTN_LOCAL && route->data.ifindex > CI_IFID_LOOP &&
      ! CI_IPX_ADDR_IS_ANY(route->data.src) )
    cp_laddr_add(s, af, route->data.src, route->data.ifindex);

}

static bool
cp_route_add(struct cp_session* s, uint32_t table_id,
             struct cp_route* route, int af)
{
  struct cp_route_table* table = cp_route_table_find(s, table_id, af);

  if( table == NULL ) {
    table = malloc(sizeof(*table));
    table->id = table_id;
    cp_ippl_init(&table->routes, sizeof(struct cp_route),
                 cp_route_compare, 4);
    if( cp_routes_under_dump(s,af) )
      cp_ippl_start_dump(&table->routes);
    table->next =
      cp_route_table_array_by_af(s, af)[table_id & (ROUTE_TABLE_HASH_SIZE-1)];
    cp_route_table_array_by_af(s, af)[table_id & (ROUTE_TABLE_HASH_SIZE-1)] =
      table;
  }

  int idx;
  bool changed = cp_ippl_add(&table->routes, &route->dst, &idx);

  if( s->flags & CP_SESSION_LADDR_USE_PREF_SRC )
    cp_route2laddr(s, route, af);

  /* Failed to add - can't do anything. */
  if( idx == -1 )
    return changed;

  struct cp_route* entry = cp_route_entry_by_idx(table, idx);
  bool key_changed = changed;

  if( ! changed ) {
    /* Update route data if needed and return */
    if( memcmp(&entry->data, &route->data, sizeof(route->data)) != 0 ||
        entry->weight.val != route->weight.val ||
        entry->weight.flag != route->weight.flag) {
      memcpy(&entry->data, &route->data, sizeof(route->data));
      entry->weight.val = route->weight.val;
      bool flag_changed_to_last =
           entry->weight.flag != route->weight.flag &&
           (route->weight.flag & CP_FWD_MULTIPATH_FLAG_LAST);
      entry->weight.flag = route->weight.flag;
      if( ! flag_changed_to_last )
        return true;
      /* else fall through to remove old entries */
      changed = true;
    }
    else {
      return false;
    }
  }
  /* else cp_ippl_add() have already added a new entry with the correct
   * route data */

  /* When we are under dump, the route table may be unsorted, and we
   * must not sort it.  On the flip side, dumping takes care on removing
   * all the obsolete routes. */
  if( table->routes.in_dump )
    return changed;

  if( key_changed ) {
    cp_ippl_sort(&table->routes);

    /* Find the just-added route entry again, after sort. */
    idx = cp_ippl_idx(&table->routes,
                      cp_ippl_search(&table->routes, &route->dst));
    entry = cp_route_entry_by_idx(table, idx);
  }
  /* else the table is already sorted */

  /* We changed the route list.  It may happen that it was a multipath route
   * change, and we have to remove all old-weighted paths from the table.
   * The next 2 loops heavily use that
   * - The route list is sorted.
   * - We always add the full spectrum of the paths, see the code under
   *   RTA_MULTIPATH below.
   */
  key_changed = false;
  int id;
  int in_dump = table->routes.in_dump;

  /* Prevent any re-order of the routes now */
  table->routes.in_dump = true;

  /* Remove all entries with smaller "end" and overlapping this entry. */
  for( id = idx - 1; id >= 0; id--) {
    struct cp_route* t = cp_route_entry_by_idx(table, id);
    if( cp_route_cmp_multipath(entry, t) != 0 )
      break;
    if( t->weight.end == 0 ) {
      /* Non-multipath entry is definitely wrong, and definitely the
       * only one. */
      cp_ippl_del(&table->routes, &t->dst);
      key_changed = true;
      break;
    }
    if( t->weight.end <= entry->weight.end - entry->weight.val )
      break;
    cp_ippl_del(&table->routes, &t->dst);
    key_changed = true;
  }

  /* In case of the last path, all the other paths for the same route
   * are old ones.  Remove them! */
  if( route->weight.end == 0 ||
      route->weight.flag & CP_FWD_MULTIPATH_FLAG_LAST ) {
    for( id = idx + 1; id < table->routes.sorted; id++) {
      struct cp_route* t = cp_route_entry_by_idx(table, id);
      if( cp_route_cmp_multipath(entry, t) != 0 )
        break;
      cp_ippl_del(&table->routes, &t->dst);
      key_changed = true;
    }
  }

  table->routes.in_dump = in_dump;
  if( key_changed ) {
    if( ! in_dump )
      cp_ippl_sort(&table->routes);
    changed = true;
  }

  return changed;
}

void
cp_routes_update_laddr(struct cp_session* s, struct cp_route_table** tables,
                       int af)
{
  int i, id;
  for( i = 0; i < ROUTE_TABLE_HASH_SIZE; i++ ) {
    struct cp_route_table* table;
    for( table = tables[i];
         table != NULL; table = table->next ) {
      for( id = 0; id < table->routes.used; id++ )
        cp_route2laddr(s, cp_route_entry_by_idx(table, id), af);
    }
  }
}


#define RTA_ADDRESS(attr, af) \
  ( af == AF_INET6 ) ?                              \
    CI_ADDR_SH_FROM_IP6(RTA_DATA(attr)) :           \
    CI_ADDR_SH_FROM_IP4(*((uint32_t *)RTA_DATA(attr)))

/* Parse NETLINK route message */
void
cp_nl_route_table_update(struct cp_session* s, struct nlmsghdr* nlhdr,
                         struct rtmsg* rtm, size_t bytes)
{
  struct cp_route route;
  uint32_t table_id = rtm->rtm_table;
  bool changed = false;
  const int af = rtm->rtm_family;
  ci_int16 hlim = -1;

  memset(&route, 0, sizeof(route));
  route.dst.prefix = rtm->rtm_dst_len;
  route.tos = rtm->rtm_tos;
  route.scope = rtm->rtm_scope;
  route.type = rtm->rtm_type;
  if( af == AF_INET ) {
    route.dst.addr = ip4_addr_sh_any;
    route.data.src = ip4_addr_sh_any;
    route.data.next_hop = ip4_addr_sh_any;
  }

  RTA_LOOP(rtm, attr, bytes) {
    switch( attr->rta_type & NLA_TYPE_MASK ) {
      case RTA_DST:
        route.dst.addr = RTA_ADDRESS(attr, af);
        break;

      case RTA_PREFSRC:
        route.data.src = RTA_ADDRESS(attr, af);
        break;

      case RTA_OIF:
        route.data.ifindex = *((uint32_t *)RTA_DATA(attr));
        break;

      case RTA_GATEWAY:
        route.data.next_hop = RTA_ADDRESS(attr, af);
        break;

      case RTA_MULTIPATH:
      {
        /* Linux kernel sources guarantee that RTA_MULTIPATH is the last
         * attribute, so we assume that all the other fields have been
         * already parsed correctly. */
        route.data.hop_limit = ( hlim == -1 ) ? CI_IPV6_DFLT_HOPLIMIT : hlim;

        if( nlhdr->nlmsg_type == RTM_DELROUTE ) {
          changed = cp_route_del(s, table_id, &route, af);
          goto out;
        }
        s->flags |= CP_SESSION_SEEN_MULTIPATH | CP_SESSION_DO_MULTIPATH;

        uint32_t end = 0;

        RTA_NESTED_LOOP(attr, attr1, bytes1) {
          struct rtnexthop *nh = (void*)attr1;
          route.weight.val = nh->rtnh_hops + 1;
          end += nh->rtnh_hops + 1;
          route.weight.end = end;
          route.data.ifindex = nh->rtnh_ifindex;
          if( af == AF_INET )
            route.data.next_hop = ip4_addr_sh_any;
          RTA_NESTED_LOOP(nh, attr2, bytes2) {
            switch( attr2->rta_type & NLA_TYPE_MASK ) {
              case RTA_GATEWAY:
                route.data.next_hop = RTA_ADDRESS(attr2, af);
                break;
            }
          }

          /* Is this the last entry in the RTA_NESTED_LOOP? */
          if( ! RTA_OK((struct rtattr*)((char*)attr1 +
                                        RTA_ALIGN(attr1->rta_len)),
                       bytes1 - RTA_ALIGN(attr1->rta_len)) )
            route.weight.flag |= CP_FWD_MULTIPATH_FLAG_LAST;
          /* We add this as a separate route */
          changed |= cp_route_add(s, table_id, &route, af);
        }
        goto out;
      }

      case RTA_METRICS:
      {
        RTA_NESTED_LOOP(attr, attr1, bytes1) {
          switch( attr1->rta_type & NLA_TYPE_MASK ) {
            case RTAX_MTU:
              route.data.mtu = *((ci_uint32 *)RTA_DATA(attr1));
              break;

            /* RTAX_HOPLIMIT attribute contains IPv4 TTL or IPv6 Hop Limit */
            case RTAX_HOPLIMIT:
              hlim = *((ci_uint32 *)RTA_DATA(attr1));
              break;
          }
        }
        break;
      }

      case RTA_TABLE:
        table_id = *((uint32_t *)RTA_DATA(attr));
        break;

      case RTA_PRIORITY:
        route.metric = *((uint32_t *)RTA_DATA(attr));
        break;

      default:
        break;
    }
  }

  route.data.hop_limit = ( hlim == -1 ) ? CI_IPV6_DFLT_HOPLIMIT : hlim;

  if( nlhdr->nlmsg_type == RTM_DELROUTE )
    changed = cp_route_del(s, table_id, &route, af);
  else
    changed = cp_route_add(s, table_id, &route, af);

 out:
  if( changed )
    s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED |
                CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED;
}

static struct cp_route *
cp_route_find(struct cp_session* s, struct cp_fwd_key* key,
              struct cp_route_table* table, int af)
{
  struct cp_ip_with_prefix* ipp = NULL;
  struct cp_route *route = NULL;
  int i;

  /* Find the best prefix and metric.
   * The list is ordered by prefix length, then by metric,
   * so the first match is the best prefix & metric. */
  for( i = 0; i < table->routes.used; i++ ) {
    ipp = cp_ippl_entry(&table->routes, i);
    route = CI_CONTAINER(struct cp_route, dst, ipp);
    if( cp_ipx_ippl_pfx_match(af, key->dst, ipp->addr, ipp->prefix) &&
        (route->tos == 0 || route->tos == key->tos) )
      break;
  }
  if( i == table->routes.used )
    return NULL;

  return route;
}

/* This function finds the preferred source address for a given route.
 * It is not needed in normal case, but we have to do it in multipath case.
 * This function is also used in --verify-routes mode, which exists solely
 * to verify this function's correctness. */
static ci_addr_sh_t
cp_route_find_src(struct cp_session* s, struct cp_fwd_key* key,
                  struct cp_route_table* table, struct cp_route *route,
                  int af)
{
  ci_addr_t next_hop = route->data.next_hop;

  if( route->type == RTN_LOCAL )
    return route->dst.addr;

  if( ! CI_IPX_ADDR_IS_ANY(route->data.next_hop) ) {
    struct cp_fwd_key newkey = *key;
    struct cp_route *route1;
    newkey.dst = route->data.next_hop;
    route1 = cp_route_find(s, &newkey, table, af);
    if( ! CI_IPX_ADDR_IS_ANY(route1->data.src) )
      return route1->data.src;
  }
  else {
    next_hop = route->dst.addr;
  }

  if( route->data.ifindex != 0 ) {
    struct cp_mibs* mib = cp_get_active_mib(s);
    cicp_rowid_t id, match = CICP_ROWID_BAD;

    /* Find any suitable address on this interface */
    if( af == AF_INET ) {
      for( id = 0; id < mib->dim->ipif_max; id++ ) {
        if( cicp_ipif_row_is_free(&mib->ipif[id]) )
          break;
        /* Should we compare route->scope and mib->ipif[id].scope?
         * Should we select the address with the max or min scope?
         * Probably no, because I do not see such code in
         * linux/net/ipv4/fib_frontend.c.
         *
         * What we should do is to check IFA_F_SECONDARY flag on the
         * interface address, but we do not store it in the llap tables for
         * now.
         */
        if( route->data.ifindex == mib->ipif[id].ifindex ) {
          if( cp_ipx_ippl_pfx_match(
                                af, next_hop,
                                CI_ADDR_SH_FROM_IP4(mib->ipif[id].net_ip),
                                mib->ipif[id].net_ipset) )
            return CI_ADDR_SH_FROM_IP4(mib->ipif[id].net_ip);
          if( match == CICP_ROWID_BAD )
            match = id;
        }
      }
      if( match != CICP_ROWID_BAD )
        return CI_ADDR_SH_FROM_IP4(mib->ipif[match].net_ip);
    }
    else {
      /* See ip6_route_get_saddr() in Linux */
      for( id = 0; id < mib->dim->ip6if_max; id++ ) {
        if( cicp_ip6if_row_is_free(&mib->ip6if[id]) )
          break;
        if( route->data.ifindex == mib->ip6if[id].ifindex ) {
          if( cp_ipx_ippl_pfx_match(
                                af, next_hop,
                                CI_ADDR_SH_FROM_IP6(mib->ip6if[id].net_ip6),
                                mib->ip6if[id].net_ipset) )
            return CI_ADDR_SH_FROM_IP6(mib->ip6if[id].net_ip6);
          if ( match == CICP_ROWID_BAD )
            match = id;
        }
      }
      if( match != CICP_ROWID_BAD )
        return CI_ADDR_SH_FROM_IP6(mib->ip6if[match].net_ip6);
    }
  }

  static bool printed = false;
  if( ! printed ) {
    ci_log("%s ERROR: failed to find source IP for "CP_FWD_KEY_FMT,
           __func__, CP_FWD_KEY_ARGS(key));
    printed = true;
  }
  s->stats.route.no_source++;
  return addr_sh_any;
}

/* Convert a route from route table to something usable: fill in ifindex
 * and source address. */
static void
cp_route_to_data(struct cp_session* s, struct cp_fwd_key* key,
                 struct cp_route_table* table, struct cp_route *route/*in*/ ,
                 struct cp_fwd_data_base* data/*out*/, int af)
{
  *data = route->data;

  /* Source address */
  if( ! CI_IPX_ADDR_IS_ANY(key->src) )
    data->src = key->src;
  if( CI_IPX_ADDR_IS_ANY(data->src) )
    data->src = cp_route_find_src(s, key, table, route, af);

  /* Ifindex */
  if( af == AF_INET && CI_IPX_ADDR_EQ(data->src, key->dst) )
    data->ifindex = CI_IFID_LOOP;
  if( key->ifindex != 0 )
    data->ifindex = key->ifindex;
  if( route->type == RTN_LOCAL )
    data->ifindex = CI_IFID_LOOP;
}

static void
cp_route_verify(struct cp_session* s, struct cp_fwd_key* key,
                struct cp_route_table* table, struct cp_route *route,
                struct cp_fwd_data_base* data, int af)
{
  struct cp_fwd_data_base new_data;
  memset(&new_data, 0, sizeof(new_data));
  cp_route_to_data(s, key, table, route, &new_data, af);

  if( memcmp(&new_data, data, sizeof(*data)) != 0 ) {
    ci_log("%s ERROR: "CP_FWD_KEY_FMT" table %d:",
           __func__, CP_FWD_KEY_ARGS(key), table->id);
    ci_log("   nl data:"CP_FWD_DATA_BASE_FMT,
           CP_FWD_DATA_BASE_ARG(s->mib, data));
    ci_log("table data:"CP_FWD_DATA_BASE_FMT,
           CP_FWD_DATA_BASE_ARG(s->mib, &new_data));
    s->stats.route.mismatch++;
  }
}

static void
fwd_resolve(struct cp_session* s, int af, struct cp_fwd_key* key,
            uint32_t nl_seq);

/* Asks kernel to resolve a sourceful route if we get a user request
 * which needs it.
 * Returns true if such a netlink request have been issued; caller
 * should not notify user via fwd_req_done() in such a case.
 */
static bool
fwd_resolve_sourceful(struct cp_session* s, uint32_t nlmsg_seq,
                      int rtm_type,
                      struct cp_fwd_key* key,
                      struct cp_fwd_data_base* data_base, int af)
{
  if( af == AF_INET6 && (s->flags & CP_SESSION_IPV6_NO_SOURCE) ) {
    /* No IPv6 sourceful resolution requests are possible. */
    ci_assert(CI_IPX_ADDR_IS_ANY(key->src));
    return false;
  }
  if( (((1 << RTN_UNICAST) | (1 << RTN_MULTICAST) | (1 << RTN_LOCAL)) &
       (1 << rtm_type)) == 0 )
    return false;

  if( (nlmsg_seq & (CP_FWD_FLAG_REQ | CP_FWD_FLAG_SOURCELESS)) ==
                    CP_FWD_FLAG_REQ &&
          CI_IPX_ADDR_IS_ANY(key->src) ) {
    struct cp_fwd_key k = *key;
    k.src = data_base->src;
    fwd_resolve(s, af, &k, nlmsg_seq);
    return true;
  }

  return false;
}

struct fwd_iterate_weight_arg {
  struct cp_session* s;
  struct cp_fwd_multipath_weight* w;
};

static void
fwd_row_del(struct cp_session* s, struct cp_fwd_state* fwd_state,
            struct cp_fwd_key* key, cicp_mac_rowid_t rowid);

/* Remove old multipath entries with lower end parameter which intersect
 * with the new one.  Entries with larger end parameter can not be removed
 * until replaced. */
static int
fwd_remove_old_multipath(struct cp_fwd_table* fwd_table,
                         cicp_mac_rowid_t fwd_id, void* arg_void)
{
  struct fwd_iterate_weight_arg* arg = arg_void;
  struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, fwd_id);
  struct cp_fwd_state* fwd_state = CI_CONTAINER(struct cp_fwd_state, fwd_table,
                                                fwd_table);

  if( fwd->data->weight.end < arg->w->end &&
      fwd->data->weight.end > arg->w->end - arg->w->val )
    fwd_row_del(arg->s, fwd_state, &fwd->key, fwd_id);
  return false; /* continue iterating */
}
/* Find the second LAST fwd entry to remove it. */
static int
fwd_find_old_last_multipath(struct cp_fwd_table* fwd_table,
                            cicp_mac_rowid_t fwd_id, void* arg_void)
{
  struct fwd_iterate_weight_arg* arg = arg_void;
  struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, fwd_id);

  if( fwd->data->weight.flag & CP_FWD_MULTIPATH_FLAG_LAST &&
      fwd->data->weight.end != arg->w->end )
    return true;
  return false;
}
/* Remove multipath entries with range beyond the current last end. */
static int
fwd_remove_larger_multipath(struct cp_fwd_table* fwd_table,
                            cicp_mac_rowid_t fwd_id, void* arg_void)
{
  struct fwd_iterate_weight_arg* arg = arg_void;
  struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, fwd_id);
  struct cp_fwd_state* fwd_state = CI_CONTAINER(struct cp_fwd_state, fwd_table,
                                                fwd_table);

  if( fwd->data->weight.end > arg->w->end )
    fwd_row_del(arg->s, fwd_state, &fwd->key, fwd_id);
  return false; /* continue iterating */
}
/* Remove multipath entries after adding a non-multipath one */
static int
fwd_remove_multipath(struct cp_fwd_table* fwd_table,
                     cicp_mac_rowid_t fwd_id, void* session)
{
  struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, fwd_id);
  struct cp_fwd_state* fwd_state = CI_CONTAINER(struct cp_fwd_state, fwd_table,
                                                fwd_table);

  if( fwd->data->weight.end != 0 )
    fwd_row_del(session, fwd_state, &fwd->key, fwd_id);
  return false; /* continue iterating */
}

static void
fwd_req_done(struct cp_session* s, uint32_t seq)
{
  uint32_t req_id = seq & CP_FWD_FLAG_REQ_MASK;
  if( (seq & (CP_FWD_FLAG_REQ | CP_FWD_FLAG_REQ_WAIT)) ==
             (CP_FWD_FLAG_REQ | CP_FWD_FLAG_REQ_WAIT) ) {
    cplane_ioctl(s->oo_fd, OO_IOC_CP_FWD_RESOLVE_COMPLETE, &req_id);
    s->stats.fwd.req_complete++;
  }
}

static void
cp_fwd_row_update(struct cp_session* s, struct cp_fwd_state* fwd_state,
                  uint32_t nlmsg_seq,
                  struct cp_fwd_key* key, uint32_t table_id,
                  unsigned char rtm_type,
                  struct cp_fwd_data_base* data_base, int flags,
                  struct cp_fwd_multipath_weight* weight);

/* Return true if the route is multipath, and have been handled here. */
static bool
cp_route_check_multipath(struct cp_session* s, struct cp_fwd_state* fwd_state,
                         uint32_t nlmsg_seq, struct cp_fwd_key* key,
                         uint32_t table_id, struct cp_fwd_data_base* data,
                         int af)
{
  struct cp_route_table* table = cp_route_table_find(s, table_id, af);

  if( table == NULL ) {
    static bool printed = false;
    if( ! printed ) {
      ci_log("%s ERROR: no table %d", __func__, table_id);
      printed = true;
    }
    s->stats.route.unknown_table++;
    return false;
  }

  /* Find the best prefix */
  struct cp_route *route = cp_route_find(s, key, table, af);
  if( route == NULL ) {
    static bool printed = false;
    if( ! printed ) {
      ci_log("%s ERROR: no route matches "CP_FWD_KEY_FMT" in table %d",
             __func__, CP_FWD_KEY_ARGS(key), table_id);
      printed = true;
    }
    s->stats.route.no_match++;
    return false;
  }

  if( route->weight.end == 0 ) {
    if( s->flags & CP_SESSION_VERIFY_ROUTES )
      cp_route_verify(s, key, table, route, data, af);
    return false;
  }
  ci_assert_flags(s->flags, CP_SESSION_DO_MULTIPATH);

  /* So, we are multipath.  We have to add all the multipath variants to
   * the fwd table, so that user may choose the route randomly, according
   * to weights. */
  if( ! (nlmsg_seq & CP_FWD_FLAG_REQ) ) {
    /* We refresh fwd entry, but we can't really rely on the fwd id here,
     * so we impersonate into request. */
    nlmsg_seq |= CP_FWD_FLAG_REQ;
    nlmsg_seq &=~ CP_FWD_FLAG_REQ_WAIT;
  }
  int idx;
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  struct fwd_iterate_weight_arg w_arg = { .s = s, .w = NULL };
  for( idx = cp_ippl_idx(&table->routes, &route->dst);
       idx < table->routes.used;
       idx++ ) {
    struct cp_route *t = cp_route_entry_by_idx(table, idx);
    if( cp_route_cmp_multipath(route, t) != 0 )
      break;

    struct cp_fwd_data_base data;
    cp_route_to_data(s, key, table, t, &data, af);

    /* Sourceful routing request may be multipath, and may be not.  So
     * we go via the usual way: netlink request, etc. */
    fwd_resolve_sourceful(s, nlmsg_seq & ~CP_FWD_FLAG_REQ_WAIT,
                          RTN_UNICAST, key, &data, af);

    cp_fwd_row_update(s, fwd_state, nlmsg_seq, key, table_id, t->type,
                      &data, 0, &t->weight);

    /* Remove all the old fwd entries with intersecting weight ranges.
     * We do not need to remove non-multipath entry, because it would be
     * picked up by cp_fwd_row_update(), using fwd_weight_is_before_new()
     * callback, and that non-multipath entry have just been updated. */
    w_arg.w = &t->weight;
    cp_fwd_find_row_iterate(fwd_table, key, key,
                            fwd_remove_old_multipath, &w_arg);
  }

  /* Remove all the old fwd entries beyond this last one.
   * We do not want to create holed in the weight sequence while
   * the old LAST entry is searchable for any cplane user. */
  ci_assert(w_arg.w);
  cicp_mac_rowid_t id =
      cp_fwd_find_row_iterate(fwd_table, key, key,
                              fwd_find_old_last_multipath, &w_arg);
  if( id != CICP_MAC_ROWID_BAD ) {
    fwd_row_del(s, fwd_state, &cp_get_fwd_by_id(fwd_table, id)->key, id);
    cp_fwd_find_row_iterate(fwd_table, key, key,
                            fwd_remove_larger_multipath, &w_arg);
  }

  /* We notify user even if sourceful request have been sent.
   * Multipath may result in multiple sources, so we have no simple
   * condition when all the answers are known. */
  fwd_req_done(s, nlmsg_seq);

  return true;
}

/* on the hash probe sequence [start, end> decrements use count for each row
 * note1: the last element is not touched
 * note2: function assumes at least one row to fixup. Passing sequence [x,x>
 * would fixup a cycle starting and ending with x with potentially
 * elements in between. */
static inline void
__fwd_row_decrement_usage(struct cp_fwd_state* fwd_state,
                          cicp_mac_rowid_t start, cicp_mac_rowid_t step,
                          cicp_mac_rowid_t end)
{
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_mac_rowid_t hash = start;
  int iter = 0;
  do {
    ci_assert_le(iter, (fwd_table->mask >> 2));
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, hash);
    ci_assert_ge(fwd->use, 1);
    fwd->use--;
    ci_assert_impl(cp_row_mask_get(fwd_state->fwd_used, hash), fwd->use);
    ci_assert_equiv(cp_row_mask_get(fwd_state->fwd_used, hash),
                    fwd->flags & CICP_FWD_FLAG_OCCUPIED);
    hash = (hash + step) & fwd_table->mask;
    iter++;
  } while( hash != end );
}

static cicp_mac_rowid_t
fwd_row_add(struct cp_session* s, struct cp_fwd_state* fwd_state,
            struct cp_fwd_key* key)
{
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_mac_rowid_t hash1, hash2, hash;
  int iter = 0;

  cp_calc_fwd_hash(fwd_table, key, &hash1, &hash2);
  hash = hash1;

  do {
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, hash);
    fwd->use++;

    if( ! cp_row_mask_get(fwd_state->fwd_used, hash) ) {
      ci_assert_nflags(fwd->flags, CICP_FWD_FLAG_OCCUPIED);
      struct cp_fwd_key_ext key_ext = {CP_MAX_PREFIX_LEN, CP_MAX_PREFIX_LEN};
      /* TODO: ideally we'd have the prefix passed us parameter,
       * for now we make sure it is by default 32 */
      fwd->key_ext = key_ext;
      fwd->key = *key;
      /* we need to set it to vaguely sane value for comparisons to work */
      fwd_table->rw_rows[hash].frc_used = cp_frc64_get();
      ci_wmb();
      fwd->flags = CICP_FWD_FLAG_OCCUPIED;
      memset(fwd->data, 0, sizeof(fwd->data));
      cp_row_mask_set(fwd_state->fwd_used, hash);
      return hash;
    }
    s->stats.fwd.collision++;
    ci_assert_gt(fwd->use, 1);
    hash = (hash + hash2) & fwd_table->mask;
  } while( ++iter < (fwd_table->mask >> 2) && hash != hash1 );

  if( hash == hash1 ) {
#ifndef NDEBUG
    CI_RLLOG(10, "%s: hash loop of length %d detected", __func__, iter);
#endif
    s->stats.fwd.hash_loop++;
  }
  s->stats.fwd.full++;

  __fwd_row_decrement_usage(fwd_state, hash1, hash2, hash);

  return CICP_MAC_ROWID_BAD;
}


static void
fwd_row_del(struct cp_session* s, struct cp_fwd_state* fwd_state,
            struct cp_fwd_key* key, cicp_mac_rowid_t rowid)
{
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_mac_rowid_t hash1, hash2;

  cp_calc_fwd_hash(fwd_table, key, &hash1, &hash2);

  /* fixup use count on the probe path up to but without the actual row to remove */
  if( rowid != hash1 )
    __fwd_row_decrement_usage(fwd_state, hash1, hash2, rowid);

  ci_assert(cp_row_mask_get(fwd_state->fwd_used, rowid));

  struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, rowid);

  ci_assert_flags(fwd->flags, CICP_FWD_FLAG_OCCUPIED);
  fwd->use--;
  fwd->flags = 0;
  /* bump version to trigger route rediscovery, no need to modify data */
  cp_fwd_under_change(fwd);
  cp_fwd_change_done(fwd);
  cp_row_mask_unset(fwd_state->fwd_used, rowid);
}

/* Return TRUE if the given address belongs to a local interface. */
static int address_is_local(struct cp_session* s, const uint32_t address)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  cicp_rowid_t id;

  for( id = 0; id < mib->dim->ipif_max; id++ ) {
    if( cicp_ipif_row_is_free(&mib->ipif[id]) )
      return 0;

    if( address == mib->ipif[id].net_ip )
      return 1;
  }

  return 0;
}

static int
ip6_address_is_local(struct cp_session* s, const ci_addr_sh_t addr)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  cicp_rowid_t id;

  for( id = 0; id < mib->dim->ip6if_max; id++ ) {
    if( cicp_ip6if_row_is_free(&mib->ip6if[id]) )
      return 0;

    if( !CI_IP6_ADDR_CMP(addr.ip6, mib->ip6if[id].net_ip6) )
      return 1;
  }

  return 0;
}

#define MAX_ATTRS 4
#define FIXED_ATTRS 1

static void
rtm_request_fill_common(struct rtmsg* rtm)
{
  rtm->rtm_table = 0;
  rtm->rtm_protocol = RTPROT_UNSPEC;
  rtm->rtm_scope = RT_SCOPE_UNIVERSE;
  rtm->rtm_type = RTN_UNSPEC;
  /* Linux always reports RT_TABLE_MAIN in case of old kernel and/or
   * when called without RTM_F_LOOKUP_TABLE flag.
   * New kernels are:
   * - Linux >= 4.4
   * - RHEL6, RHEL7.
   * Old kernels are:
   * - Debian8 with linux-3.16
   * - old SLES?
   *
   * With the old kernel, cplane will assume that all the routes belong to
   * the MAIN table.  This is unfortunate and means that resolving via
   * table lookup will not work with such old kernels.
   * I.e. Onload multipath support is will be broken if it is configured in
   * non-main table on an old kernel.
   *
   * The control plane's internal headers provide a definition of
   * RTM_F_LOOKUP_TABLE, as even many of the "new" distros listed above do not
   * define it in their UL headers.  This also means that we'll pass the flag
   * to kernels that don't support it, but they ignore it.
   */
  rtm->rtm_flags = RTM_F_LOOKUP_TABLE;
}

static void
ip4_fwd_resolve(struct cp_session* s, struct cp_fwd_key* key, uint32_t* nl_seq)
{
  struct {
    struct nlmsghdr nlhdr;
    struct {
      struct rtmsg rtm;
      struct {
        struct rtattr attr;
        uint32_t CP_RTA_PACKED val;
      } CP_RTA_PACKED attr[MAX_ATTRS];
    } CP_NLMSG_PACKED rtmsg; /* see RTM_RTA */
  } msg;

  CI_BUILD_ASSERT(sizeof(msg) == NLMSG_SPACE(sizeof(msg.rtmsg)));
  CI_BUILD_ASSERT(sizeof(msg.rtmsg) ==
                  sizeof(msg.rtmsg.rtm) +
                  RTA_SPACE(sizeof(msg.rtmsg.attr[0].val)) * MAX_ATTRS);

  int attrs = FIXED_ATTRS;
  size_t len;
  typeof(&msg.rtmsg.attr[0]) fattr = &msg.rtmsg.attr[0];
  typeof(&msg.rtmsg.attr[0]) attr = &msg.rtmsg.attr[FIXED_ATTRS];

  memset(&msg, 0, sizeof(msg));
  msg.nlhdr.nlmsg_type = RTM_GETROUTE;
  msg.nlhdr.nlmsg_flags = NLM_F_REQUEST;
  msg.nlhdr.nlmsg_pid = s->sock_net_name.nl_pid;
  rtm_request_fill_common(&msg.rtmsg.rtm);
  msg.rtmsg.rtm.rtm_family = AF_INET;
  msg.rtmsg.rtm.rtm_dst_len = 32;
  if( CI_IPX_ADDR_IS_ANY(key->src) )
    msg.rtmsg.rtm.rtm_src_len = 0;
  else
    msg.rtmsg.rtm.rtm_src_len = 32;
  msg.rtmsg.rtm.rtm_tos = key->tos;
  fattr->attr.rta_type = RTA_DST;
  fattr->attr.rta_len = RTA_LENGTH(sizeof(attr->val));
  fattr->val = key->dst.ip4;
  if( !CI_IPX_ADDR_IS_ANY(key->src) ) {
    attr->attr.rta_type = RTA_SRC;
    attr->attr.rta_len = RTA_LENGTH(sizeof(attr->val));
    attr->val = key->src.ip4;
    attrs++;
    attr++;
  }
  if( key->ifindex != 0 ) {
    attr->attr.rta_type = RTA_OIF;
    attr->attr.rta_len = RTA_LENGTH(sizeof(attr->val));
    attr->val = key->ifindex;
    attrs++;
    attr++;
    *nl_seq |= CP_FWD_FLAG_IFINDEX;
  }
  *nl_seq |= (key->flag & CP_FWD_KEY2SEQ_MASK) << CP_FWD_FLAG_KEY2NL_SHIFT;

  ci_ifid_t iif_ifindex = CI_IFID_BAD;
  if( key->iif_ifindex != CI_IFID_BAD )
    iif_ifindex = key->iif_ifindex;
  /* For transparent lookups, we hardcode the loopback interface, but really we
   * ought to use the ifindex of the interface that has a route to the
   * transparent source address.  This in turn would require clients to tell us
   * that ifindex.  See bug87317. */
  else if( (key->flag & CP_FWD_KEY_TRANSPARENT) &&
           ! address_is_local(s, key->src.ip4) )
    iif_ifindex = CI_IFID_LOOP;

  if( iif_ifindex != CI_IFID_BAD ) {
    /* The presence or absence of the RTA_IIF attribute controls
     * whether the kernel will route this as an "input" or "output"
     * packet. Output packets must always have a local source address;
     * input packets are always expected to identify the interface
     * through which they arrived.
     *
     * Most of the time the "output" routing is best suited to our
     * needs and so we don't specify this attribute. However it is
     * needed when an IP_TRANSPARENT socket is bound to a non-local
     * source address, as it is the only way to route a packet which
     * doesn't appear to originate from the local machine. Similarly,
     * it is needed when simulating forwarding of packets that traverse
     * a veth-pair.
     */

    attr->attr.rta_type = RTA_IIF;
    attr->attr.rta_len = RTA_LENGTH(sizeof(attr->val));
    attr->val = iif_ifindex;
    attrs++;
    attr++;
  }

  len = sizeof(msg) - (MAX_ATTRS - attrs) * sizeof(*attr);
  msg.nlhdr.nlmsg_len = len;
  msg.nlhdr.nlmsg_seq = *nl_seq;
  send(s->sock_net, &msg, len, 0);
}

#undef MAX_ATTRS
#undef FIXED_ATTRS

static void
msg_add_attr(struct msghdr* msghdr, struct nlmsghdr* nlhdr,
             void* data, size_t datalen)
{
  msghdr->msg_iov[msghdr->msg_iovlen].iov_base = data;
  msghdr->msg_iov[msghdr->msg_iovlen].iov_len = datalen;
  msghdr->msg_iovlen++;
  nlhdr->nlmsg_len += datalen;
}

static void
ip6_fwd_resolve(struct cp_session* s, struct cp_fwd_key* key, uint32_t* nl_seq)
{
  struct {
    struct nlmsghdr nlhdr;
    struct rtmsg rtm;
  } msg;
 CI_BUILD_ASSERT(sizeof(msg) == sizeof(struct nlmsghdr) +
                 sizeof(struct rtmsg));

  struct {
    struct rtattr attr;
    uint32_t CP_RTA_PACKED val;
  } attr[4];
  CI_BUILD_ASSERT(sizeof(attr[0]) == RTA_LENGTH(sizeof(attr[0].val)));

  struct msghdr msghdr;
  struct iovec iov[7];

  memset(&msghdr, 0, sizeof(msghdr));
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 0;

  memset(&msg, 0, sizeof(msg));
  msg.nlhdr.nlmsg_type = RTM_GETROUTE;
  msg.nlhdr.nlmsg_flags = NLM_F_REQUEST;
  msg.nlhdr.nlmsg_pid = s->sock_net_name.nl_pid;
  msg.nlhdr.nlmsg_len = 0;
  rtm_request_fill_common(&msg.rtm);
  msg.rtm.rtm_family = AF_INET6;
  msg.rtm.rtm_dst_len = CP_MAX_PREFIX_LEN;
  if( CI_IPX_ADDR_IS_ANY(key->src) )
    msg.rtm.rtm_src_len = 0;
  else
    msg.rtm.rtm_src_len = CP_MAX_PREFIX_LEN;
  msg.rtm.rtm_tos = key->tos;
  msg_add_attr(&msghdr, &msg.nlhdr, &msg, sizeof(msg));

  attr[0].attr.rta_type = RTA_DST;
  attr[0].attr.rta_len = RTA_LENGTH(sizeof(struct in6_addr));
  CI_BUILD_ASSERT(sizeof(key->dst.ip6) == sizeof(struct in6_addr));
  msg_add_attr(&msghdr, &msg.nlhdr, &attr[0].attr, sizeof(attr[0].attr));
  msg_add_attr(&msghdr, &msg.nlhdr, &key->dst.ip6 , sizeof(struct in6_addr));

  if( !CI_IPX_ADDR_IS_ANY(key->src) ) {
    attr[1].attr.rta_type = RTA_SRC;
    attr[1].attr.rta_len = RTA_LENGTH(sizeof(struct in6_addr));
    msg_add_attr(&msghdr, &msg.nlhdr, &attr[1].attr, sizeof(attr[1].attr));
    msg_add_attr(&msghdr, &msg.nlhdr, &key->src.ip6, sizeof(struct in6_addr));
  }

  if( key->ifindex != 0 ) {
    attr[2].attr.rta_type = RTA_OIF;
    attr[2].attr.rta_len = RTA_LENGTH(sizeof(attr[2].val));
    attr[2].val = key->ifindex;
    msg_add_attr(&msghdr, &msg.nlhdr, &attr[2], sizeof(attr[2]));
    *nl_seq |= CP_FWD_FLAG_IFINDEX;
  }
  *nl_seq |= (key->flag & CP_FWD_KEY2SEQ_MASK) << CP_FWD_FLAG_KEY2NL_SHIFT;

  uint32_t iif_ifindex = CI_IFID_BAD;
  if( key->iif_ifindex != CI_IFID_BAD )
    iif_ifindex = key->iif_ifindex;
  /* For transparent lookups, we hardcode the loopback interface, but really we
   * ought to use the ifindex of the interface that has a route to the
   * transparent source address.  This in turn would require clients to tell us
   * that ifindex.  See bug87317. */
  else if( (key->flag & CP_FWD_KEY_TRANSPARENT) &&
           ! ip6_address_is_local(s, key->src) )
    iif_ifindex = CI_IFID_LOOP;

  if( iif_ifindex != CI_IFID_BAD ) {
    attr[3].attr.rta_type = RTA_IIF;
    attr[3].attr.rta_len = RTA_LENGTH(sizeof(attr[3].val));
    attr[3].val = iif_ifindex;
    msg_add_attr(&msghdr, &msg.nlhdr, &attr[3], sizeof(attr[3]));
  }

  msg.nlhdr.nlmsg_seq = *nl_seq;
  ci_assert_le(msghdr.msg_iovlen, sizeof(iov) / sizeof(iov[0]));
  sendmsg(s->sock_net, &msghdr, 0);
}

#undef FWD_RESOLVE_MAX_BUF_SIZE


static int fwd_req_enqueue(struct cp_session* s, const struct cp_fwd_key* key,
                           uint32_t nl_seq)
{
  struct cp_fwd_req* req = malloc(sizeof(struct cp_fwd_req));
  if( req == NULL )
    return -ENOMEM;

  req->key = *key;
  req->nl_seq = nl_seq;

  ci_dllist_push(&s->fwd_req_ul, &req->link);
  if( ++s->stats.fwd.req_queue_len > s->stats.fwd.req_queue_hiwat )
    s->stats.fwd.req_queue_hiwat = s->stats.fwd.req_queue_len;

  return 0;
}


static int fwd_req_dequeue(struct cp_session* s, struct cp_fwd_key* key_out,
                           uint32_t nl_seq)
{
  struct cp_fwd_req* req;
  struct cp_fwd_req* prev;

  /* This list is expected to be short, so just iterate over it.  Compare
   * oo_cp_fwd_resolve_complete().  Moreover, the kernel services route
   * requests FIFO, so by iterating backwards we expect to find the matching
   * entry first time. */
  CI_DLLIST_FOR_EACH_REV3(struct cp_fwd_req, req, link, &s->fwd_req_ul, prev) {
    if( req->nl_seq == nl_seq ) {
      *key_out = req->key;
      ci_dllist_remove(&req->link);
      --s->stats.fwd.req_queue_len;
      free(req);
      return 0;
    }
  }

#ifndef CP_UNIT
  /* In the real world, fwd_req_dequeue() and fwd_req_enqueue() calls should be
   * one-to-one, but in the unit tests we mock up route responses and so this
   * property breaks down, so we disable the assertion in the unit tests. */
  ci_assert(0);
#endif
  return -ENOENT;
}


static void
fwd_resolve(struct cp_session* s, int af, struct cp_fwd_key* key,
            uint32_t nl_seq)
{
  if( key->iif_ifindex != CI_IFID_BAD )
    nl_seq |= CP_FWD_FLAG_KEY_REMEMBERED;

  if( af == AF_INET6 )
    ip6_fwd_resolve(s, key, &nl_seq);
  else
    ip4_fwd_resolve(s, key, &nl_seq);

  if( ~s->flags & CP_SESSION_OS_REPORTS_RTA_IIF &&
      nl_seq & (CP_FWD_FLAG_REQ | CP_FWD_FLAG_KEY_REMEMBERED) ) {
    int rc = fwd_req_enqueue(s, key, nl_seq);
    if( rc < 0 ) {
      CI_RLLOG(10, "Failed to enqueue route request: %s", strerror(-rc));
      fwd_req_done(s, nl_seq);
      ++s->stats.fwd.req_enqueue_fail;
    }
  }
}


CP_UNIT_EXTERN struct cp_fwd_state*
cp_fwd_state_get(struct cp_session* s, cp_fwd_table_id fwd_table_id)
{
  struct cp_fwd_state* fwd_state = &s->__fwd_state[fwd_table_id];
  struct cp_tables_dim* dim = s->mib[0].dim;
  void* fwd_mem;
  void* fwd_rw_mem;

  if( fwd_state->fwd_table.rows == NULL ) {
    struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;

    fwd_table->mask = s->mib[0].dim->fwd_mask;
#ifdef CP_UNIT
    fwd_mem = calloc(1, cp_calc_fwd_blob_size(dim));
    fwd_rw_mem = calloc(1, cp_calc_fwd_rw_size(dim));
#else
    fwd_mem = mmap(NULL, CI_ROUND_UP(cp_calc_fwd_blob_size(dim), CI_PAGE_SIZE),
                   PROT_READ | PROT_WRITE, MAP_SHARED, s->oo_fd,
                   CP_MMAP_MAKE_FWD_OFFSET(fwd_table_id));
    if( fwd_mem == MAP_FAILED )
      goto fail1;

    fwd_rw_mem = mmap(NULL,
                      CI_ROUND_UP(cp_calc_fwd_rw_size(dim), CI_PAGE_SIZE),
                      PROT_READ | PROT_WRITE, MAP_SHARED, s->oo_fd,
                      CP_MMAP_MAKE_FWD_RW_OFFSET(fwd_table_id));
    if( fwd_rw_mem == MAP_FAILED )
      goto fail2;
#endif

    fwd_table->rows = cp_fwd_table_within_blob(fwd_mem);
    fwd_table->prefix = cp_fwd_prefix_within_blob(fwd_mem, dim);
    fwd_table->rw_rows = fwd_rw_mem;
    fwd_state->priv_rows = calloc(fwd_table->mask + 1,
                                  sizeof(*fwd_state->priv_rows));
    if( fwd_state->priv_rows == NULL )
      goto fail3;
    fwd_state->fwd_used = cp_row_mask_alloc(fwd_table->mask + 1);
    if( fwd_state->fwd_used == NULL )
      goto fail4;
  }

  return fwd_state;

 fail4:
  free(fwd_state->priv_rows);
 fail3:
#ifndef CP_UNIT
  munmap(fwd_rw_mem, CI_ROUND_UP(cp_calc_fwd_rw_size(dim), CI_PAGE_SIZE));
 fail2:
  munmap(fwd_mem, CI_ROUND_UP(cp_calc_fwd_blob_size(dim), CI_PAGE_SIZE));
 fail1:
#endif
  return NULL;
}

static inline void
fwd_data_set_arp_valid(struct cp_fwd_data* data)
{
  data->flags &=~ CICP_FWD_DATA_FLAG_ARP_FAILED;
  data->flags |= CICP_FWD_DATA_FLAG_ARP_VALID;
}

static inline void
__fwd_mac_update(struct cp_session* s, struct cp_fwd_state* fwd_state,
                 int af, cicp_mac_rowid_t fwdid, struct cp_fwd_row* fwd,
                 struct cp_fwd_data* data, cicp_mac_rowid_t macid, int flags)
{
  if( fwd->flags & CICP_FWD_FLAG_FIXED_MAC )
    return;

  /* First of all, (un)set CICP_FWD_RW_FLAG_ARP_NEED_REFRESH flag.  It can be
   * done without cp_fwd_under_change() call. */
  struct cp_fwd_rw_row* fwd_rw = &fwd_state->fwd_table.rw_rows[fwdid];
  cicp_mac_row_t* mac = cp_get_mac_p(s, af);
  if( flags & CP_FWD_MAC_UPDATE_FLAG_NEED_UPDATE )
    ci_atomic32_or(&fwd_rw->flags, CICP_FWD_RW_FLAG_ARP_NEED_REFRESH);
  else
    ci_atomic32_and(&fwd_rw->flags, ~CICP_FWD_RW_FLAG_ARP_NEED_REFRESH);

  if( flags & CP_FWD_MAC_UPDATE_FLAG_NEED_UPDATE_ONLY )
    return;

  ci_assert_nequal(data->base.ifindex, CI_IFID_BAD);
  ci_assert_nequal(data->base.ifindex, CI_IFID_LOOP);

  fwd_state->priv_rows[fwdid].macid = macid;

  int new_arp_flags = 0;
  if( macid != CICP_MAC_ROWID_BAD ) {
    if( (mac[macid].flags &
         (CP_MAC_ROW_FLAG_FAILED | CP_MAC_ROW_FLAG_REFERENCED)) ==
        CP_MAC_ROW_FLAG_FAILED ) {
      /* This MAC is in FAILED state, but it was not in use.  Let's
       * re-resolve. */
      mac[macid].flags &=~ CP_MAC_ROW_FLAG_FAILED;
    }
    mac[macid].flags |= CP_MAC_ROW_FLAG_REFERENCED;

    if ( mac[macid].state & NUD_VALID )
      new_arp_flags = CICP_FWD_DATA_FLAG_ARP_VALID;
    else if( mac[macid].flags & CP_MAC_ROW_FLAG_FAILED )
      new_arp_flags = CICP_FWD_DATA_FLAG_ARP_FAILED;
  }
  if( new_arp_flags != (data->flags & CICP_FWD_DATA_FLAG_ARP_MASK) ) {
    cp_fwd_under_change(fwd);
    data->flags &=~ CICP_FWD_DATA_FLAG_ARP_MASK;
    data->flags |= new_arp_flags;
  }
  if( (new_arp_flags & CICP_FWD_DATA_FLAG_ARP_VALID) &&
      macid != CICP_MAC_ROWID_BAD &&
      memcmp(data->dst_mac, &mac[macid].mac, sizeof(ci_mac_addr_t)) != 0 ) {
    cp_fwd_under_change(fwd);
    memcpy(data->dst_mac, &mac[macid].mac,
           sizeof(ci_mac_addr_t));
  }
}

/* Returns true if ARP update is necessary.
 * The caller shall use arp_request_update() to perform this update after
 * the FWD_UPDATE_LOOP. */
static inline bool
fwd_mac_update_one(struct cp_session* s, struct cp_fwd_state* fwd_state,
                   int af, cicp_mac_rowid_t fwdid,
                   struct cp_fwd_row* fwd, struct cp_fwd_data* data)
{
  cicp_mac_rowid_t macid;
  int flags = 0;

  macid = cp_mac_find_row(s, af, data->base.next_hop, data->base.ifindex);
  if( macid != CICP_MAC_ROWID_BAD &&
      cp_mac_need_refresh(&s->mac[macid], cp_frc64_get()) )
    flags = CP_FWD_MAC_UPDATE_FLAG_NEED_UPDATE;
  __fwd_mac_update(s, fwd_state, af, fwdid, fwd, data, macid, flags);

  /* This route is in the cache - i.e. we want a valid MAC.  NUD_STALE is
   * considered to be valid, but let's re-check. */
  if( ! CICP_MAC_ROWID_IS_VALID(macid) ||
      ! (s->mac[macid].state & (NUD_VALID & ~NUD_STALE)) )
    return true;
  return false;
}


static void
arp_request_update(struct cp_session* s, struct cp_fwd_state* fwd_state,
                   cicp_mac_rowid_t id)
{
  struct cp_fwd_row* fwd = cp_get_fwd_by_id(&fwd_state->fwd_table, id);
  struct oo_op_cplane_arp_resolve op;
  op.verinfo.id = id;
  op.verinfo.version = *cp_fwd_version(fwd);
  op.fwd_table_id = cp_fwd_state_id(s, fwd_state);
  ci_assert_flags(fwd->flags, CICP_FWD_FLAG_OCCUPIED);
  ci_assert_nequal(fwd->data->base.ifindex, CI_IFID_BAD);
  ci_assert_nequal(fwd->data->base.ifindex, CI_IFID_LOOP);
  cplane_ioctl(s->oo_fd, OO_IOC_CP_ARP_RESOLVE, &op);
}


static void
fwd_llap_update(struct cp_session* s, struct cp_fwd_state* fwd_state,
                struct cp_mibs* mib, cicp_rowid_t llap_id,
                cicp_hwport_mask_t old_rx_hwports)
{
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_llap_row_t* llap = &mib->llap[llap_id];
  cicp_mac_rowid_t id = -1;
  int can_accel = (llap->rx_hwports != 0);

  while( (id = cp_row_mask_iter_set(fwd_state->fwd_used, ++id,
                                    fwd_table->mask + 1, true) ) !=
         CICP_MAC_ROWID_BAD ) {
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, id);
    int can_accel_this = can_accel;
    ci_assert_flags(fwd->flags,
                    CICP_FWD_FLAG_OCCUPIED | CICP_FWD_FLAG_DATA_VALID);
    if( fwd_state->priv_rows[id].ifindex != llap->ifindex )
      continue;

    struct cp_fwd_data* data;
    int ver_i;
    FWD_UPDATE_LOOP(data, fwd, ver_i)
      cp_fwd_under_change(fwd);
      memcpy(&data->encap, &llap->encap, sizeof(llap->encap));
      if( ! (fwd->flags & CICP_FWD_FLAG_MTU) )
        data->base.mtu = llap->mtu;
      if( can_accel_this ) {
        data->hwports = llap->tx_hwports;
        data->base.ifindex = llap->ifindex;
        memcpy(&data->src_mac, llap->mac, sizeof(ci_mac_addr_t));

          /* We do not update ARP here, so we ignore the return code.
           * 1. It breaks IPv6: linux manages to remember wrong route.
           * 2. If the network is reconfigured, then it is likely
           *    a non-last reconfiguration, so there is no point to rush
           *    for update.  Moreover, the fwd entry may become unused as
           *    a result of the change.
           * 3. If this fwd entry is really used, this call updated the
           *    verlock, and ARP resolution will be initiated via
           *    __oo_cp_route_resolve().
           */
          fwd_mac_update_one(s, fwd_state, fwd_key2af(&fwd->key),
                             id, fwd, data);
      }
      else {
        data->hwports = 0;
        data->base.ifindex = CI_IFID_BAD;
        fwd_state->priv_rows[id].macid = CICP_MAC_ROWID_BAD;
      }
    FWD_UPDATE_LOOP_END(fwd);
  }
}


/* Updates all forward tables to reflect a change in an LLAP. */
void
cp_fwd_llap_update(struct cp_session* s, struct cp_mibs* mib,
                   cicp_rowid_t llap_id, cicp_hwport_mask_t old_rx_hwports)
{
  struct cp_fwd_state* fwd_state = NULL;
  while( (fwd_state = cp_fwd_state_iterate_mapped(s, fwd_state)) != NULL )
    fwd_llap_update(s, fwd_state, mib, llap_id, old_rx_hwports);
}


/* Calculate the prefix lengths at which we would insert a fwd entry for [key]
 * into the table when the entry routes via a gateway.  (For a link-scoped
 * route we always use a destination prefix of 32.) */
static void
calculate_key_widths(struct cp_session* s, int af, const struct cp_fwd_key* key,
                     struct cp_fwd_key_ext* key_ext_out, uint8_t flags)
{
  if( af == AF_INET6 && (s->flags & CP_SESSION_IPV6_NO_SOURCE) )
    key_ext_out->src_prefix = 0;
  else
    key_ext_out->src_prefix =
        cp_ippl_get_prefix(cp_get_rule_src_p(s, af), af, key->src);
  if( af == AF_INET )
    key_ext_out->src_prefix += 96;

  /* rp_filter means that we must always use the exact source IP address when
   * resolving input routes. */
  if( key->iif_ifindex != CI_IFID_BAD )
    key_ext_out->src_prefix = CP_MAX_PREFIX_LEN;

  if( ! (flags & CICP_FWD_FLAG_HAS_GATEWAY) ||
      (flags & CICP_FWD_FLAG_MTU_EXPIRES) ) {
    key_ext_out->dst_prefix = CP_MAX_PREFIX_LEN;
    return;
  }
  key_ext_out->dst_prefix =
      cp_ippl_get_prefix(cp_get_route_dst_p(s, af), af, key->dst);
  if( af == AF_INET )
    key_ext_out->dst_prefix += 96;
}


static bool
fwd_row_prefixes_correct(struct cp_session* s, const struct cp_fwd_row* fwd)
{
  struct cp_fwd_key_ext key_ext;
  calculate_key_widths(s, fwd_key2af(&fwd->key),
                       &fwd->key, &key_ext, fwd->flags);
  return key_ext.src_prefix == fwd->key_ext.src_prefix &&
         key_ext.dst_prefix == fwd->key_ext.dst_prefix;
}

static void
fwd_prefix_update(ci_ipx_pfx_t* mask, int pfx)
{
  ci_ip6_pfx_t x;
  bw_shift_bit_192(x, pfx);
  bw_or_192((uint64_t*)mask->ip6, x);
}

static void
fwd_cache_refresh(struct cp_session* s, struct cp_fwd_state* fwd_state)
{
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_mac_rowid_t id = -1;

  s->flags &=~ CP_SESSION_FLAG_FWD_REFRESH_NEEDED;
  /* We should refresh all the fwd cache at the end of dump process.  But
   * there is no need to do it more than once during the dump. */
  if( s->state != CP_DUMP_IDLE )
    s->flags |= CP_SESSION_FLAG_FWD_REFRESHED;

  /* While we're iterating over the whole fwd table, we take the opportunity to
   * update the masks of in-use prefixes. */
  ci_ipx_pfx_t src_prefixes = {};
  ci_ipx_pfx_t dst_prefixes = {};

  ci_ipx_pfx_t* fwd_prefix_src = &fwd_table->prefix[CP_FWD_PREFIX_SRC];
  ci_ipx_pfx_t* fwd_prefix_dst = &fwd_table->prefix[CP_FWD_PREFIX_DST];

  /* Refresh all routes. */
  while( (id = cp_row_mask_iter_set(fwd_state->fwd_used, ++id,
                                    fwd_table->mask + 1, true) ) !=
         CICP_MAC_ROWID_BAD ) {
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, id);
    ci_assert_flags(fwd->flags, CICP_FWD_FLAG_OCCUPIED);
    ci_assert(fwd->use);

    fwd_prefix_update(&src_prefixes, fwd->key_ext.src_prefix);
    fwd_prefix_update(&dst_prefixes, fwd->key_ext.dst_prefix);

    fwd_resolve(s, fwd_key2af(&fwd->key), &fwd->key, id);

    /* If there has been a change in the routing tables, it's possible that
     * this entry now has incorrect prefix lengths, meaning that we might end
     * up inserting a conflicting entry.  Delete this entry to avoid that
     * problem.
     */
    if( s->flags & CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED &&
        ! fwd_row_prefixes_correct(s, fwd) )
      fwd_row_del(s, fwd_state, &fwd->key, id);
  }

  s->flags &=~ CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED;

#ifndef NDEBUG
  /* We might be about to remove some prefixes from the mask, but we don't
   * expect to be adding any. */
  int i;
  for( i = 0; i < 3; i++ ) {
    ci_assert_flags(fwd_prefix_src->ip6[i], src_prefixes.ip6[i]);
    ci_assert_flags(fwd_prefix_dst->ip6[i], dst_prefixes.ip6[i]);
  }
#endif

  if( cp_get_fwd_pfx_cmp(fwd_prefix_src, &src_prefixes) )
    *fwd_prefix_src = src_prefixes;
  if( cp_get_fwd_pfx_cmp(fwd_prefix_dst, &dst_prefixes) )
    *fwd_prefix_dst = dst_prefixes;
}


void cp_fwd_cache_refresh(struct cp_session* s)
{
  struct cp_fwd_state* fwd_state = NULL;
  while( (fwd_state = cp_fwd_state_iterate_mapped(s, fwd_state)) != NULL )
    fwd_cache_refresh(s, fwd_state);
}


static void
fwd_mac_update(struct cp_session* s, struct cp_fwd_state* fwd_state, int af,
               ci_addr_t addr, ci_ifid_t ifindex, cicp_mac_rowid_t macid,
               int flags)
{
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_mac_rowid_t id = -1;
  cicp_mac_row_t* mac = cp_get_mac_p(s, af);
  bool referenced = false;

  while( (id = cp_row_mask_iter_set(fwd_state->fwd_used, ++id,
                                    fwd_table->mask + 1, true) ) !=
         CICP_MAC_ROWID_BAD ) {
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, id);
    ci_assert_flags(fwd->flags, CICP_FWD_FLAG_OCCUPIED | CICP_FWD_FLAG_DATA_VALID);
    ci_assert_gt(fwd->use, 0);
    struct cp_fwd_data* data;
    int ver_i;
    bool match = false;
    FWD_UPDATE_LOOP(data, fwd, ver_i)
      if( CI_IPX_ADDR_EQ(data->base.next_hop, addr) &&
          data->base.ifindex == ifindex ) {
        __fwd_mac_update(s, fwd_state, af, id, fwd, data, macid, flags);
        match = true;
      }
    FWD_UPDATE_LOOP_END(fwd);

    /* If the OS status of the MAC entry is NUD_FAILED, but
     * CP_MAC_ROW_FLAG_FAILED is not set, then let's ask OS to re-resolve
     * it.  And we set the state to NUD_INCOMPLETE to avoid doing it twice.
     * If we get NUD_FAILED again, neigh_handle() will set is_failed to
     * true. */
    if( match && macid != CICP_MAC_ROWID_BAD ) {
      if( ! (mac[macid].flags & CP_MAC_ROW_FLAG_FAILED) &&
        mac[macid].state == NUD_FAILED ) {
        arp_request_update(s, fwd_state, id);
        mac[macid].state = NUD_INCOMPLETE;
      }
      referenced = true;
    }
  }

  if( !referenced ) {
    /* We do not update the flag every time when a fwd entry disappears,
     * but now we can update it for sure. */
    mac[macid].flags &=~ CP_MAC_ROW_FLAG_REFERENCED;
  }
}


void
cp_fwd_mac_update(struct cp_session* s, int af, ci_addr_t addr,
                  ci_ifid_t ifindex, cicp_mac_rowid_t macid, int flags)
{
  struct cp_fwd_state* fwd_state = NULL;
  while( (fwd_state = cp_fwd_state_iterate_mapped(s, fwd_state)) != NULL )
    fwd_mac_update(s, fwd_state, af, addr, ifindex, macid, flags);
}


/* This function assumes that fwdid is in fwd_used mask, macid is in
 * mac_used mask, so we do not check that rows are in use. */
static inline bool
fwd_uses_mac(struct cp_session* s, struct cp_fwd_state* fwd_state, int af,
             cicp_mac_rowid_t fwdid, cicp_mac_rowid_t macid)
{
  struct cp_fwd_row* fwd = cp_get_fwd_by_id(&fwd_state->fwd_table, fwdid);
  struct cp_fwd_data* data = cp_get_fwd_data_current(fwd);
  cicp_mac_row_t* mac = cp_get_mac_p(s, af);
  return CI_IPX_ADDR_EQ(data->base.next_hop, mac[macid].addr) &&
         data->base.ifindex == mac[macid].ifindex;
}

static void
fwd_mac_is_stale(struct cp_session* s, struct cp_fwd_state* fwd_state, int af,
                 cicp_mac_rowid_t macid)
{
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_mac_rowid_t id = -1;

  while( (id = cp_row_mask_iter_set(fwd_state->fwd_used, ++id,
                                    fwd_table->mask + 1, true) ) !=
         CICP_MAC_ROWID_BAD ) {
    ci_assert_flags(cp_get_fwd_by_id(fwd_table, id)->flags,
                    CICP_FWD_FLAG_OCCUPIED);
    if( fwd_uses_mac(s, fwd_state, af, id, macid) ) {
      arp_request_update(s, fwd_state, id);
      ci_wmb();
      return;
    }
  }
}


void
cp_fwd_mac_is_stale(struct cp_session* s, int af, cicp_mac_rowid_t macid)
{
  struct cp_fwd_state* fwd_state = NULL;
  while( (fwd_state = cp_fwd_state_iterate_mapped(s, fwd_state)) != NULL )
    fwd_mac_is_stale(s, fwd_state, af, macid);
}


/* Determine the fwd table that should be used to store the result of the route
 * lookup for a given key, and return a pointer to the corresponding
 * cp_fwd_state.  Returns NULL on error. */
static struct cp_fwd_state*
find_fwd_state(struct cp_session* s, const struct cp_fwd_key* key)
{
  cp_fwd_table_id fwd_table_id;

  if( key->iif_ifindex != CI_IFID_BAD ) {
    /* If it's an input route, find the corresponding forward table. */
    cicp_rowid_t llap_rowid = cp_llap_find_row(&s->mib[0], key->iif_ifindex);
    if( llap_rowid == CICP_ROWID_BAD )
      fwd_table_id = CP_FWD_TABLE_ID_INVALID;
    else
      fwd_table_id = s->mib[0].llap[llap_rowid].iif_fwd_table_id;
  }
  else {
    /* Otherwise, use the local table. */
    fwd_table_id = s->cplane_id;
  }

  if( fwd_table_id == CP_FWD_TABLE_ID_INVALID ) {
    /* This should only happen if a veth-pair is being torn down or is
     * otherwise in flux. */
    ++s->stats.fwd.table_missing;
    return NULL;
  }

  struct cp_fwd_state* fwd_state = cp_fwd_state_get(s, fwd_table_id);
  if( fwd_state == NULL )
    ++s->stats.fwd.table_map_fail;
  return fwd_state;
}


void
cp_fwd_req_do(struct cp_session* s, int req_id, struct cp_fwd_key* key)
{
  /* CP_FWD_KEY_REQ_REFRESH is reused as CP_FWD_FLAG_REQ, but we do not
   * need the REFRESH flag from now on. */
  ci_assert_nflags((uint32_t)key->flag << CP_FWD_FLAG_KEY2NL_SHIFT,
                   CP_FWD_FLAG_IFINDEX);
  ci_assert_nflags((uint32_t)key->flag << CP_FWD_FLAG_KEY2NL_SHIFT,
                   CP_FWD_FLAG_REQ_MASK);
  req_id |= CP_FWD_FLAG_REQ;
  req_id |= key->flag << CP_FWD_FLAG_KEY2NL_SHIFT;

  if( ! (key->flag & CP_FWD_KEY_REQ_REFRESH) ) {
    struct cp_fwd_state* fwd_state = find_fwd_state(s, key);
    if( fwd_state == NULL )
      goto no_request;

    struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
    cicp_mac_rowid_t id = cp_fwd_find_row(fwd_table, key);

    if(CI_UNLIKELY( cp_fwd_find_row_found_perfect_match(fwd_table, id, key) ))
      goto no_request;
  }

  int af = fwd_key2af(key);
  if( af == AF_INET6 && s->flags & CP_SESSION_NO_IPV6 )
    goto no_request;

  fwd_resolve(s, af, key, req_id);
  return;

 no_request:
  /* If we're not actually going to issue a request, wake a waiter if we have
   * one and then return. */
  fwd_req_done(s, req_id);
}


/* These fwd flags are really part of "data", and they are obtained from
 * the netlink message. */
#define CICP_FWD_FLAG_DATA \
    (CICP_FWD_FLAG_MTU|CICP_FWD_FLAG_MTU_EXPIRES|\
     CICP_FWD_FLAG_HAS_GATEWAY|CICP_FWD_FLAG_FIXED_MAC)


/* This cp_fwd_find_row_iterate() callback is used to find a
 * fwd entry we can safely replace by an entry with the new weight
 * parameters.  We can do it if (a) the fwd entry is non-multipath or
 * (b) the fwd entry goes after any just-added entry.
 */
static int
fwd_weight_is_before_new(struct cp_fwd_table* fwd_table,
                         cicp_mac_rowid_t fwd_id, void* arg_new)
{
  struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, fwd_id);
  struct cp_fwd_multipath_weight* new = arg_new;
  return fwd->data->weight.end == 0 ||
         new->end - new->val < fwd->data->weight.end;
}

static void
cp_fwd_row_update(struct cp_session* s, struct cp_fwd_state* fwd_state,
                  uint32_t nlmsg_seq,
                  struct cp_fwd_key* key, uint32_t table_id,
                  unsigned char rtm_type,
                  struct cp_fwd_data_base* data_base, int flags,
                  struct cp_fwd_multipath_weight* weight)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_mac_rowid_t id = CICP_MAC_ROWID_BAD;
  cicp_mac_rowid_t old_id = CICP_MAC_ROWID_BAD;
  cicp_rowid_t llap_id;
  bool ask_arp_update = false;
  struct cp_fwd_row* fwd = NULL;
  struct cp_fwd_row* old_fwd = NULL;

  if( data_base->mtu != 0 )
    flags |= CICP_FWD_FLAG_MTU;
  if( !CI_IPX_ADDR_IS_ANY(data_base->next_hop) )
    flags |= CICP_FWD_FLAG_HAS_GATEWAY;

  /* Find row id */
  if( ! (nlmsg_seq & CP_FWD_FLAG_REQ) ) {
    id = old_id = nlmsg_seq & CP_FWD_FLAG_REFRESH_MASK;
    fwd = old_fwd = cp_get_fwd_by_id(fwd_table, id);
    /* Check that the key from this message matches to this id. */
    if( ! cp_row_mask_get(fwd_state->fwd_used, id) ||
        ! cp_fwd_key_match(fwd, key) ) {
      s->stats.fwd.nlmsg_mismatch++;
      return;
    }
  }

  llap_id = cp_llap_find_row(mib, data_base->ifindex);
  if( llap_id == CICP_ROWID_BAD ) {
    CI_RLLOG(10, "ERROR: can't find llap row for ifindex %d", data_base->ifindex);
    /* TODO: Handle this in a reasonable way */
    return;
  }
  const cicp_llap_row_t* llap = &mib->llap[llap_id];

  /* remember real ifindex associated with the llap,
   * in case we replace llap with a fake one for alien routes */
  const ci_ifid_t llap_ifindex = llap->ifindex;
  static const cicp_llap_row_t llap_alien = {
    .tx_hwports = 0,
    .encap = { .type = CICP_LLAP_TYPE_NONE },
    .mtu = 0,
  };

  /* Find route type; fix data.ifindex in case of loopback route. */
  switch( rtm_type ) {
    case RTN_UNICAST:
    case RTN_MULTICAST:
      /* For non-bond interfaces rx_hwports == tx_hwports,
       * for bonded interface it is possible to have a bond
       * with currently no active interface (tx_hwports == 0)
       * nonetheless still an acceleratable one */
      if( llap->rx_hwports == 0 ) {
        data_base->ifindex = CI_IFID_BAD;
        data_base->next_hop = addr_sh_any;
        llap = &llap_alien;
      }
      break;

    case RTN_LOCAL:
      data_base->ifindex = CI_IFID_LOOP;
      break;

    default:
      data_base->ifindex = CI_IFID_BAD;
      break;
  }

  if( ! (flags & CICP_FWD_FLAG_HAS_GATEWAY) )
    data_base->next_hop = key->dst;
  if( ! (flags & CICP_FWD_FLAG_MTU) )
    data_base->mtu = llap->mtu;
  if( (flags & (CICP_FWD_FLAG_MTU | CICP_FWD_FLAG_MTU_EXPIRES)) ==
      CICP_FWD_FLAG_MTU_EXPIRES ) {
    flags &=~ CICP_FWD_FLAG_MTU_EXPIRES;
  }
  if( CI_IPX_IS_MULTICAST(data_base->next_hop) )
    flags |= CICP_FWD_FLAG_FIXED_MAC;
  else
    flags &=~ CICP_FWD_FLAG_FIXED_MAC;

  /* Find out source and destination netmasks with the same route. */
  struct cp_fwd_key_ext key_ext_wide;
  calculate_key_widths(s, fwd_key2af(key), key, &key_ext_wide, flags);
  struct cp_fwd_key key_wide = *key;

  cp_addr_apply_pfx(&key_wide.src, key_ext_wide.src_prefix);
  cp_addr_apply_pfx(&key_wide.dst, key_ext_wide.dst_prefix);

  struct cp_fwd_multipath_weight no_weight = {0,};
  if( weight == NULL )
    weight = &no_weight;

  /* Find the fwd row id. */
  id = cp_fwd_find_row_iterate(fwd_table, &key_wide, &key_wide,
                               fwd_weight_is_before_new, weight);

  int nothing_changed = false;

  if( id != CICP_MAC_ROWID_BAD ) {
    fwd =  cp_get_fwd_by_id(fwd_table, id);
    struct cp_fwd_data* fwd_data = cp_get_fwd_data_current(fwd);

    fwd_state->priv_rows[id].table_id = table_id;

    if( CI_IPX_ADDR_EQ(fwd_data->base.src, data_base->src) &&
        CI_IPX_ADDR_EQ(fwd_data->base.next_hop, data_base->next_hop) &&
        fwd_state->priv_rows[id].ifindex == llap_ifindex &&
        /* Check fwd_data in addition to fwd_priv to discover error routes
         * set by cp_nl_error_route_handle which have become unerrored now */
        fwd_data->base.ifindex == data_base->ifindex &&
        fwd_data->base.mtu == data_base->mtu &&
        fwd_data->base.hop_limit == data_base->hop_limit &&
        /* Do not touch unchanged route if prefix value can be improved,
         * but the existing value is good.
         * But we must update the route if the new netmask is longer (more
         * specific) than the old one. */
        fwd->key_ext.src_prefix >= key_ext_wide.src_prefix &&
        fwd->key_ext.dst_prefix >= key_ext_wide.dst_prefix &&
        fwd->data->weight.val == weight->val &&
        fwd->data->weight.flag == weight->flag ) {
      /* Nothing changed, we do not re-check the data fields which are
       * copied from other tables. */
      /* Note: potentially the key could be widened, we we'll do that only
       *       when asked for the route from the widenend range */
      nothing_changed = true;
      /* follow through to potentially update the non-versioned mtu */
    }
  }
  else {
    id = fwd_row_add(s, fwd_state, &key_wide);
    if( id == CICP_MAC_ROWID_BAD ) {
      CI_RLLOG(10, "ERROR: route table is full");
      id = old_id;
      nothing_changed = true;
      /* follow through to potentially update the non-versioned mtu in old row */
    }
    else {
      fwd = cp_get_fwd_by_id(fwd_table, id);
      if( old_id != CICP_MAC_ROWID_BAD ) {
        struct cp_fwd_data* fwd_data = cp_get_fwd_data_current(old_fwd);
        /* note: until DATA_VALID flag is set by the first FWD_UPDATE_LOOP below
         *       it is OK to change the content of data without minding
         *       versioning */
        fwd->data[0] = *fwd_data;
        fwd->data[1] = *fwd_data;
        fwd_state->priv_rows[id] = fwd_state->priv_rows[old_id];
      }
      fwd_state->priv_rows[id].table_id = table_id;
    }
  }

  ci_assert_impl(fwd == NULL, nothing_changed);
  /* fwd->flags are not versioned, so we set/unset it just now. */
  if( fwd ) {
    flags |= fwd->flags & ~(CICP_FWD_FLAG_DATA | CICP_FWD_FLAG_ERROR);
    fwd->flags = flags;
  }

  if( nothing_changed )
    goto delete_old_id;

  /* now we can update prefixes
   * we can widen or narrow them accordingly */
  fwd->key_ext = key_ext_wide;

  /* If the prefixes that we're using are new to the table, update the masks.
   */
  fwd_prefix_update(&fwd_table->prefix[CP_FWD_PREFIX_SRC],
                    key_ext_wide.src_prefix);
  fwd_prefix_update(&fwd_table->prefix[CP_FWD_PREFIX_DST],
                    key_ext_wide.dst_prefix);

  /* Update the fwd row */
  int ver_i;
  struct cp_fwd_data* fwd_data;
  FWD_UPDATE_LOOP(fwd_data, fwd, ver_i)
    cp_fwd_under_change(fwd);

    bool nexthop_changed = fwd_data->base.ifindex != data_base->ifindex ||
        ! CI_IPX_ADDR_EQ(fwd_data->base.next_hop, data_base->next_hop);
    fwd_data->base = *data_base;

    if( data_base->ifindex == CI_IFID_BAD ||
        data_base->ifindex == CI_IFID_LOOP ) {
      /* We do not need ARP for alien or loopback routes. */
      fwd_data_set_arp_valid(fwd_data);
      fwd_state->priv_rows[id].macid = CICP_MAC_ROWID_BAD;
    }
    else if( nexthop_changed ) {
      /* ARP data (ifindex, next hop, etc) may have changed - update it. */
      int af = fwd_key2af(&fwd->key);

      memcpy(&fwd_data->src_mac, llap->mac, sizeof(ci_mac_addr_t));
      if( flags & CICP_FWD_FLAG_FIXED_MAC ) {
        /* TODO: Add support for IPv6 multicast MAC address construction */
        if( af == AF_INET ) {
          uint32_t dst = ntohl(data_base->next_hop.ip4);
          uint8_t mac[6] = { 1, 0, 0x5e, (dst >> 16) & 0x7f,
                             (dst >> 8) & 0xff, dst & 0xff };
          memcpy(fwd_data->dst_mac, mac, sizeof(fwd_data->dst_mac));
          fwd_data_set_arp_valid(fwd_data);
        }
      }
      else if( fwd_mac_update_one(s, fwd_state, af, id, fwd, fwd_data) ) {
        ask_arp_update = true;
      }
    }

    fwd_data->hwports = llap->tx_hwports;
    fwd_data->encap = llap->encap;
    fwd_data->weight = *weight;
  FWD_UPDATE_LOOP_END(fwd);

  fwd_state->priv_rows[id].frc_used = cp_frc64_get();
  fwd_state->priv_rows[id].ifindex = llap_ifindex;
  if( ask_arp_update )
    arp_request_update(s, fwd_state, id);


  /* If we inserted a more specific entry (non-zero TOS),
   * then we should increment more generic entries.
   */
  if( old_id != id && fwd->key.tos != 0 ) {
    struct cp_fwd_key generic_key = fwd->key;
    generic_key.tos = 0;
    cicp_mac_rowid_t generic_id = cp_fwd_find_row(fwd_table, &generic_key);
    if( generic_id != CICP_MAC_ROWID_BAD )
      cp_get_fwd_by_id(fwd_table, generic_id)->version++;
  }
  /* Same for PMTU-specific */
  if( old_id != id && (flags & CICP_FWD_FLAG_MTU_EXPIRES) ) {
    struct cp_fwd_key generic_key = fwd->key;
    cicp_mac_rowid_t generic_id;
    ci_ipx_pfx_t dst_pref = fwd_table->prefix[CP_FWD_PREFIX_DST];
    dst_pref.ip6[0] = 0;

    generic_id = __cp_fwd_find_match(
                      fwd_table, &generic_key,
                      CP_FWD_MULTIPATH_WEIGHT_NONE,
                      fwd_table->prefix[CP_FWD_PREFIX_SRC],
                      dst_pref);
    if( generic_id != CICP_MAC_ROWID_BAD )
      cp_get_fwd_by_id(fwd_table, generic_id)->version++;
  }

 delete_old_id:
  /* We inserted a new fwd entry; let's delete the old one if any. */
  if( old_id != CICP_MAC_ROWID_BAD && old_id != id )
    fwd_row_del(s, fwd_state, &cp_get_fwd_by_id(fwd_table, old_id)->key,
                old_id);
}


/* Reconstruct the bits of the key that the kernel didn't echo back at us. */
static void fwd_key_reconstruct(struct cp_session* s, struct cp_fwd_key* key,
                                uint32_t nl_seq)
{
  if( ~s->flags & CP_SESSION_OS_REPORTS_RTA_IIF &&
      nl_seq & (CP_FWD_FLAG_REQ | CP_FWD_FLAG_KEY_REMEMBERED) ) {
    struct cp_fwd_key remembered_key;
    int rc = fwd_req_dequeue(s, &remembered_key, nl_seq);
    if( rc == 0 ) {
      if( key->iif_ifindex == CI_IFID_BAD )
        key->iif_ifindex = remembered_key.iif_ifindex;
      else
        ci_assert_equal(key->iif_ifindex, remembered_key.iif_ifindex);
    }
    else {
      ++s->stats.fwd.req_dequeue_fail;
    }
  }
}


/* Parse NETLINK route message */
void
cp_nl_route_handle(struct cp_session* s, struct nlmsghdr* nlhdr,
                   struct rtmsg* rtm, size_t bytes)
{
  uint8_t flags = 0;
  struct cp_fwd_key key;
  struct cp_fwd_data_base data;
  uint32_t table_id = RT_TABLE_UNSPEC;
  const int af = rtm->rtm_family;
  ci_int16 hlim = -1;

  memset(&key, 0, sizeof(key));
  memset(&data, 0, sizeof(data));
  key.tos = rtm->rtm_tos;
  if( af == AF_INET ) {
    key.dst = ip4_addr_sh_any;
    key.src = ip4_addr_sh_any;
    data.src = ip4_addr_sh_any;
    data.next_hop = ip4_addr_sh_any;
  }

  RTA_LOOP(rtm, attr, bytes) {
    switch( attr->rta_type & NLA_TYPE_MASK ) {
      case RTA_DST:
        key.dst = RTA_ADDRESS(attr, af);
        break;

      case RTA_SRC:
        key.src = RTA_ADDRESS(attr, af);
        break;

      case RTA_IIF:
        key.iif_ifindex = *((uint32_t *)RTA_DATA(attr));

        /* Kernel 3.6 introduced a regression that prevented it from reporting
         * RTA_IIF.  This was fixed in 3.15.  If we're on a good kernel,
         * remember the fact so that we can avoid ourselves some extra work. */
        if( key.iif_ifindex != CI_IFID_BAD )
          s->flags |= CP_SESSION_OS_REPORTS_RTA_IIF;

        /* The appearance of the loopback interface here is an artefact of the
         * way that we look up routes for IP_TRANSPARENT sockets, and shouldn't
         * be propagated to the key.  When bug87317 is fixed, this can be
         * removed. */
        if( key.iif_ifindex == CI_IFID_LOOP )
          key.iif_ifindex = CI_IFID_BAD;
        break;

      case RTA_PREFSRC:
        data.src = RTA_ADDRESS(attr, af);
        break;

      case RTA_OIF:
        data.ifindex = *((uint32_t *)RTA_DATA(attr));
        break;

      case RTA_GATEWAY:
        data.next_hop = RTA_ADDRESS(attr, af);
        break;

      case RTA_METRICS:
      {
        RTA_NESTED_LOOP(attr, attr1, bytes1) {
          switch( attr1->rta_type & NLA_TYPE_MASK ) {
            case RTAX_MTU:
              data.mtu = *((ci_uint32 *)RTA_DATA(attr1));
              break;

            /* RTAX_HOPLIMIT attribute contains IPv4 TTL or IPv6 Hop Limit */
            case RTAX_HOPLIMIT:
              hlim = *((ci_uint32 *)RTA_DATA(attr1));
              break;
          }
        }
        break;
      }

      case RTA_CACHEINFO:
      {
        struct rta_cacheinfo *ci = RTA_DATA(attr);
        if( ci->rta_expires != 0 ) {
          /* TODO: set up a timer to refresh the entry after
           * CI_MAX(1, ci->rta_expires * s->user_hz / 1000)
           * seconds */
          flags |= CICP_FWD_FLAG_MTU_EXPIRES;
        }
        break;
      }

      case RTA_TABLE:
        table_id = *((uint32_t *)RTA_DATA(attr));
        break;

      default:
        break;
    }
  }

  data.hop_limit = ( hlim == -1 ) ? CI_IPV6_DFLT_HOPLIMIT : hlim;

  /* Fix up all the source addresses */
  if( CI_IPX_ADDR_IS_ANY(data.src) ) {
    /* If we specify key.src, then netlink will not tell us data.src,
     * assuming we already know the source address. */
    data.src = key.src;
  }
  else if( af == AF_INET6 && ! CI_IPX_ADDR_IS_ANY(key.src) ) {
    /* When using IPv6, then data.src may differ from key.src,
     * and users do not expect this.  Let's fix. */
    data.src = key.src;
  }
  else if( af == AF_INET && CI_IPX_ADDR_IS_ANY(key.src) ) {
    /* Zero key.src IPv4 address should correspond to IPv6 form properly. */
    key.src = ip4_addr_sh_any;
  }

  /* data.src may be :: if all the IPv6 addresses are tentative.
   * Onload can't do anything reasonable here, so we set unsupported route
   * type to avoid acceleration. */
  if( CI_IPX_ADDR_IS_ANY(data.src) )
    rtm->rtm_type = RTN_BLACKHOLE;

  /* Find key.ifindex - the RTM message does not contain this
   * information, so key.ifindex can be 0 or data.ifindex. */
  if( nlhdr->nlmsg_seq & CP_FWD_FLAG_IFINDEX )
    key.ifindex = data.ifindex;

  key.flag |=
      (nlhdr->nlmsg_seq >> CP_FWD_FLAG_KEY2NL_SHIFT) & CP_FWD_KEY2SEQ_MASK;

  fwd_key_reconstruct(s, &key, nlhdr->nlmsg_seq);

  bool notify_done = false;
  struct cp_fwd_state* fwd_state = find_fwd_state(s, &key);
  if( fwd_state == NULL )
    goto out_complete;

  /* Do we have any reason to look into the route table, or can we use the
   * netlink answer straigt away? */
  if( s->flags & (CP_SESSION_DO_MULTIPATH | CP_SESSION_VERIFY_ROUTES) ) {
    /* For some reason, kernel lies about the table id for local routes. */
    if( rtm->rtm_type != RTN_UNICAST && table_id == RT_TABLE_MAIN )
      table_id = RT_TABLE_LOCAL;

    /* resolve via route table */
    if( ! (flags & CICP_FWD_FLAG_MTU_EXPIRES) &&
        cp_route_check_multipath(s, fwd_state, nlhdr->nlmsg_seq, &key,
                                 table_id, &data, af) ) {
      return;
    }
  }

  notify_done = fwd_resolve_sourceful(s, nlhdr->nlmsg_seq, rtm->rtm_type, &key,
                                      &data, af);
  cp_fwd_row_update(s, fwd_state, nlhdr->nlmsg_seq, &key, table_id,
                    rtm->rtm_type, &data, flags, NULL);

  /* If there were any multipath entries, remove them. */
  cp_fwd_find_row_iterate(&fwd_state->fwd_table,
                          &key, &key, fwd_remove_multipath, s);

 out_complete:
  /* Tell others that we are done. */
  if( ! notify_done )
    fwd_req_done(s, nlhdr->nlmsg_seq);
}

void cp_nl_error_route_handle(struct cp_session* s,
                              struct nlmsgerr* err, size_t bytes)
{
  struct cp_fwd_key key;
  struct rtmsg* rtm = NLMSG_DATA(&err->msg);
  cicp_mac_rowid_t id;
  const int af = rtm->rtm_family;

  memset(&key, 0, sizeof(key));
  key.tos = rtm->rtm_tos;
  key.dst = key.src = addr_sh_any;
  key.ifindex = 0;
  key.flag = 0;
  if( af == AF_INET ) {
    key.dst = ip4_addr_sh_any;
    key.src = ip4_addr_sh_any;
  }

  bytes -= sizeof(*rtm);

  RTA_LOOP(rtm, attr, bytes) {
    switch( attr->rta_type & NLA_TYPE_MASK ) {
      case RTA_DST:
        key.dst = RTA_ADDRESS(attr, af);
        break;

      case RTA_SRC:
        key.src = RTA_ADDRESS(attr, af);
        break;

      case RTA_OIF:
        if( err->msg.nlmsg_seq & CP_FWD_FLAG_IFINDEX )
          key.ifindex = *((uint32_t *)RTA_DATA(attr));
        break;

      case RTA_IIF:
        key.iif_ifindex = *((uint32_t *)RTA_DATA(attr));
        /* See the handling of RTA_IIF in cp_nl_route_handle() for why loopback
         * is special here.  When bug87317 is fixed, this can be removed. */
        if( key.iif_ifindex == CI_IFID_LOOP )
          key.iif_ifindex = CI_IFID_BAD;
        break;

      default:
        break;
    }
  }

  fwd_key_reconstruct(s, &key, err->msg.nlmsg_seq);

  struct cp_fwd_state* fwd_state = find_fwd_state(s, &key);
  if( fwd_state == NULL )
    goto out_complete;
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  struct cp_fwd_row* fwd = NULL;

  /* We expect NLMSG_ERROR in the following cases:
   * - local address is removed, but a socket have been bound to it (so the
   *   removed address is used as the source address);
   * - network interface goes down;
   * - (?) default route is removed.
   * In the most cases, we can apply usual rules to find out the source and
   * destination network prefixes, and we expect it all to work properly.
   * However, let's be safe:
   * assume that this OS complain affects src/32 -> dst/32 route only.
   */
  if( err->msg.nlmsg_seq & CP_FWD_FLAG_REQ ) {
    /* This was a new route request, and Linux considers it "erroneous". */
    id = cp_fwd_find_match(fwd_table, &key, CP_FWD_MULTIPATH_WEIGHT_NONE);
    if( id != CICP_MAC_ROWID_BAD )
      fwd = cp_get_fwd_by_id(fwd_table, id);
  }
  else {
    /* We are trying to update the existing route, but something is wrong:
     * the source address have gone or something like that. */
    id = err->msg.nlmsg_seq & CP_FWD_FLAG_REFRESH_MASK;
    fwd = cp_get_fwd_by_id(fwd_table, id);

    /* Check that this NLMSG_ERROR keys matches to this id. */
    if( ! cp_row_mask_get(fwd_state->fwd_used, id) ||
        ! cp_fwd_key_match(fwd, &key) ) {
      s->stats.fwd.error_mismatch++;
      return;
    }
  }

  /* Remove old non-ERROR entries for this destination */
  if( fwd != NULL && ! (fwd->flags & CICP_FWD_FLAG_ERROR) ) {
    fwd_row_del(s, fwd_state, &fwd->key, id);
    goto out_complete;
  }

  if( fwd == NULL ) {
    if( (id = fwd_row_add(s, fwd_state, &key)) == CICP_MAC_ROWID_BAD )
      goto out_complete;
    fwd = cp_get_fwd_by_id(fwd_table, id);
    fwd->key_ext.src_prefix = fwd->key_ext.dst_prefix = CP_MAX_PREFIX_LEN;
  }

  fwd_prefix_update(&fwd_table->prefix[CP_FWD_PREFIX_SRC], CP_MAX_PREFIX_LEN);
  fwd_prefix_update(&fwd_table->prefix[CP_FWD_PREFIX_DST], CP_MAX_PREFIX_LEN);
  fwd->flags |= CICP_FWD_FLAG_ERROR;

  fwd_state->priv_rows[id].ifindex = CI_IFID_BAD;
  struct cp_fwd_data* data;
  int ver_i;
  FWD_UPDATE_LOOP(data, fwd, ver_i)
    cp_fwd_under_change(fwd);
    data->hwports = 0;
    data->base.ifindex = CI_IFID_BAD;
    fwd_data_set_arp_valid(data);
  FWD_UPDATE_LOOP_END(fwd);

 out_complete:
  if( err->msg.nlmsg_seq & CP_FWD_FLAG_REQ_WAIT )
    fwd_req_done(s, err->msg.nlmsg_seq);
}

/* Set the value under pointer to `b` if it is more recent */
static void ci_frc_update1(uint64_t* p_a, uint64_t b)
{
  if( ci_frc64_after(*p_a, b) )
    *p_a = b;
}
/* Set both values to the more recent value  */
static void ci_frc_update2(uint64_t* p_a, uint64_t* p_b)
{
  if( ci_frc64_after(*p_a, *p_b) )
    *p_a = *p_b;
  else
    *p_b = *p_a;
}

/* Set CICP_FWD_FLAG_STALE when necessary.
 * Refresh PMTU.
 */
static void
fwd_row_refresh(struct cp_session* s, struct cp_fwd_state* fwd_state,
                cicp_mac_rowid_t id, struct cp_fwd_row* fwd, ci_uint64 now)
{
  int af = fwd_key2af(&fwd->key);
  cicp_mac_row_t* mac = cp_get_mac_p(s, af);
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;

  if( ci_frc64_after(fwd_state->priv_rows[id].frc_used +
                       s->frc_fwd_cache_ttl / 2,
                     now) ) {
    if( ! (fwd->flags & CICP_FWD_FLAG_STALE) ) {
      fwd->flags |= CICP_FWD_FLAG_STALE;
      ci_wmb();
      /* Bump the version: user will notice it, check that nothing changed,
       * and bump fwd_rw->frc_used. */
      fwd->version++;
    }
  }
  else if( fwd->flags & CICP_FWD_FLAG_STALE ) {
    fwd->flags &=~ CICP_FWD_FLAG_STALE;
    /* Do not disturb the user: no version bump */
  }

  /* Is ARP fresh enough? */
  cicp_mac_rowid_t macid = fwd_state->priv_rows[id].macid;
  struct cp_fwd_data* data = cp_get_fwd_data_scratch(fwd);
  if( ! CICP_MAC_ROWID_IS_VALID(macid) ||
      !CI_IPX_ADDR_EQ(mac[macid].addr, data->base.next_hop) ||
      mac[macid].ifindex != fwd_state->priv_rows[id].ifindex ) {
    fwd_state->priv_rows[id].macid = CICP_MAC_ROWID_BAD;
  }
  else if( cp_mac_need_refresh(&mac[macid], now) ) {
    /* We do not need to remove this flag here.  It is removed when we
     * receive a neighbour update via netlink or by the user. */
    ci_atomic32_or(&fwd_table->rw_rows[id].flags,
                   CICP_FWD_RW_FLAG_ARP_NEED_REFRESH);
  }

  if( fwd->flags & CICP_FWD_FLAG_MTU_EXPIRES )
    fwd_resolve(s, af, &fwd->key, id);
}

/* Remove all unused fwd cache entries.
 * Call fwd_row_refresh() for all others.
 */
static void fwd_timer(struct cp_session* s, struct cp_fwd_state* fwd_state)
{
  struct cp_fwd_table* fwd_table = &fwd_state->fwd_table;
  cicp_mac_rowid_t id = -1;
  uint64_t now = cp_frc64_get();
  cp_row_mask_t used = cp_row_mask_alloc(fwd_table->mask + 1);

  memcpy(used, fwd_state->fwd_used,
         cp_row_mask_sizeof(fwd_table->mask + 1));

  /* Go though fwd cache, remove unused entries. */
  while( (id = cp_row_mask_iter_set(used, ++id,
                                    fwd_table->mask + 1, true) ) !=
         CICP_MAC_ROWID_BAD ) {
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, id);

    ci_frc_update1(&fwd_state->priv_rows[id].frc_used,
                   fwd_table->rw_rows[id].frc_used);

    /* Find the pair route with/without source address and consider them
     * both to have the same timestamp */
    struct cp_fwd_key key;
    key = fwd->key;
    if( CI_IPX_ADDR_IS_ANY(key.src) )
      key.src = cp_get_fwd_data_current(fwd)->base.src;
    else
      key.src = addr_sh_any;

    cicp_mac_rowid_t pair_id = cp_fwd_find_match(fwd_table, &key,
                                                 CP_FWD_MULTIPATH_WEIGHT_NONE);
    struct cp_fwd_row* pair = NULL;
    if( (pair_id != CICP_MAC_ROWID_BAD) &&
        (pair_id != id)) {
      pair = cp_get_fwd_by_id(fwd_table, pair_id);
      ci_frc_update1(&fwd_state->priv_rows[pair_id].frc_used,
                     fwd_table->rw_rows[id].frc_used);
      ci_frc_update2(&fwd_state->priv_rows[pair_id].frc_used,
                     &fwd_state->priv_rows[id].frc_used);
      cp_row_mask_unset(used, pair_id);
    }

    if( ci_frc64_after(fwd_state->priv_rows[id].frc_used +
                       s->frc_fwd_cache_ttl, now) ) {
      fwd_row_del(s, fwd_state, &fwd->key, id);
      if( pair != NULL )
        fwd_row_del(s, fwd_state, &pair->key, pair_id);
      continue;
    }

    fwd_row_refresh(s, fwd_state, id, fwd, now);
    if( pair != NULL )
      fwd_row_refresh(s, fwd_state, id, pair, now);
  }
  free(used);
}


void cp_fwd_timer(struct cp_session* s)
{
  struct cp_fwd_state* fwd_state = NULL;
  while( (fwd_state = cp_fwd_state_iterate_mapped(s, fwd_state)) != NULL )
    fwd_timer(s, fwd_state);
}


/* rule_src mask is filled by CP_DUMP_IPIF and CP_DUMP_RULE;
 * route_dst mask is filled by CP_DUMP_RULE and CP_DUMP_ROUTE. */
void cp_ipif_dump_start(struct cp_session* s, int af)
{
  cp_ippl_start_dump(cp_get_rule_src_p(s, af));
}
void cp_rule_dump_start(struct cp_session* s, int af)
{
  struct cp_ip_prefix_list* route_dst = cp_get_route_dst_p(s, af);
  cp_ippl_start_dump(route_dst);
  if( af == AF_INET ) {
    /* Multicast routes resolve differently from unicast ones */
    struct cp_ip_with_prefix mdst;
    mdst.addr = CI_ADDR_FROM_IP4(CI_BSWAPC_BE32(0xe0000000));
    mdst.prefix = 4;
    cp_ippl_add(route_dst, &mdst, NULL);
  }
}

void cp_rule_dump_done(struct cp_session* s, int af)
{
  if( cp_ippl_finalize(s, cp_get_rule_src_p(s, af), NULL) ) {
    s->flags |= CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED;
    s->flags &=~ CP_SESSION_FLAG_FWD_REFRESHED;
  }
}

void cp_route_dump_start(struct cp_session* s, int af)
{
  int i;
  struct cp_route_table** tables = cp_route_table_array_by_af(s, af);
  for( i = 0; i < ROUTE_TABLE_HASH_SIZE; i++ ) {
    struct cp_route_table* table;
    for( table = tables[i]; table != NULL; table = table->next )
      cp_ippl_start_dump(&table->routes);
  }

  /* We are starting route dump.  Will we see any multipath? */
  if( af == AF_INET && (s->flags & CP_SESSION_DO_MULTIPATH) )
    s->flags &=~ CP_SESSION_SEEN_MULTIPATH;
}
void cp_route_dump_done(struct cp_session* s, int af)
{
  if( cp_ippl_finalize(s, cp_get_route_dst_p(s, af), NULL) ) {
    s->flags |= CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED;
    if( s->flags & CP_SESSION_LADDR_USE_PREF_SRC )
      s->flags|= CP_SESSION_LADDR_REFRESH_NEEDED;
    s->flags &=~ CP_SESSION_FLAG_FWD_REFRESHED;
  }

  int i;
  struct cp_route_table** tables = cp_route_table_array_by_af(s, af);
  for( i = 0; i < ROUTE_TABLE_HASH_SIZE; i++ ) {
    struct cp_route_table* table;
    for( table = tables[i]; table != NULL; table = table->next ) {
      if( cp_ippl_finalize(s, &table->routes, NULL) ) {
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED |
                    CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED;
        s->flags &=~ CP_SESSION_FLAG_FWD_REFRESHED;
      }
    }
  }

  /* We are finishing route dump.  Let's update CP_SESSION_DO_MULTIPATH
   * flag. */
  if( (s->flags & (CP_SESSION_DO_MULTIPATH | CP_SESSION_SEEN_MULTIPATH)) ==
                   CP_SESSION_DO_MULTIPATH &&
      ( af == AF_INET6 || (s->flags & CP_SESSION_NO_IPV6) ) ) {
    s->flags &=~ CP_SESSION_DO_MULTIPATH;
  }
  ci_assert_impl(s->flags & CP_SESSION_SEEN_MULTIPATH,
                 s->flags & CP_SESSION_DO_MULTIPATH);
}

/* Handles both RTM_NEWRULE and RTM_NEWROUTE.  Fills in rule_src and
 * route_dst lists. */
void cp_newrule_handle(struct cp_session* s, uint16_t nlmsg_type,
                       struct fib_rule_hdr* rule, size_t bytes)
{
  struct cp_ip_with_prefix dst;
  struct cp_ip_with_prefix src;
  bool changed = false;
  const int af = rule->family;

  if( af != AF_INET && af != AF_INET6 )
    return;

  dst.prefix = rule->dst_len;
  if( af == AF_INET )
    dst.addr = ip4_addr_sh_any;
  else
    dst.addr = addr_sh_any;

  if( nlmsg_type == RTM_NEWRULE ) {
    src.prefix = rule->src_len;
    if( af == AF_INET )
      src.addr = ip4_addr_sh_any;
    else
      src.addr = addr_sh_any;
    if( dst.prefix == 0 && src.prefix == 0 )
      return;
  }
  else if( dst.prefix == 0 )
    return;

  RTA_LOOP(rule, attr, bytes) {
    switch( attr->rta_type & NLA_TYPE_MASK ) {
      case FRA_DST:
        dst.addr = RTA_ADDRESS(attr, af);
        break;
        if( nlmsg_type == RTM_NEWROUTE ||
            (src.prefix != 0 && CI_IPX_ADDR_IS_ANY(src.addr)) ) {
          goto out;
        }
        break;

      case FRA_SRC:
        ci_assert_equal(nlmsg_type, RTM_NEWRULE);
        src.addr = RTA_ADDRESS(attr, af);
        if( dst.prefix == 0 || !CI_IPX_ADDR_IS_ANY(dst.addr) )
          goto out;
    }
  }
 out:

  if( dst.prefix > 0 )
    changed |= cp_ippl_add(cp_get_route_dst_p(s, af), &dst, NULL);
  if( nlmsg_type == RTM_NEWRULE && src.prefix > 0 )
    changed |= cp_ippl_add(cp_get_rule_src_p(s, af), &src, NULL);
  if( changed ) {
    s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED |
                CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED;
  }
}


static void print_fwd_data(struct cp_session* s, struct cp_fwd_data* data)
{
  struct cp_mibs* mib = &s->mib[0];
  cp_print(s, "\t"CP_FWD_DATA_BASE_FMT, CP_FWD_DATA_BASE_ARG(mib, &data->base));
  if( data->weight.end != 0 )
    cp_print(s, "\t"CP_FWD_MULTIPATH_WEIGHT_FMT,
             CP_FWD_MULTIPATH_WEIGHT_ARG(&data->weight));
  cp_print(s, "\thwports %x "CICP_FWD_DATA_FLAG_FMT, data->hwports,
           CICP_FWD_DATA_FLAG_ARG(data->flags));
  cp_print(s, "\tfrom "CI_MAC_PRINTF_FORMAT" to "CI_MAC_PRINTF_FORMAT,
           CI_MAC_PRINTF_ARGS(&data->src_mac),
           CI_MAC_PRINTF_ARGS(&data->dst_mac));
  if( data->encap.type != CICP_LLAP_TYPE_NONE )
    cp_print(s, "\tencap "CICP_ENCAP_NAME_FMT,
             cicp_encap_name(data->encap.type));
  if( data->encap.type & (CICP_LLAP_TYPE_VLAN | CICP_LLAP_TYPE_BOND) ) {
    cp_print_nonewline(s, "\t");
    if( data->encap.type & CICP_LLAP_TYPE_VLAN )
      cp_print_nonewline(s, "vlan id %d ", data->encap.vlan_id);
    cp_print(s, "");
  }
}


static void
print_fwd_extras(struct cp_session* s, struct cp_fwd_table* fwd_table,
                 cicp_mac_rowid_t id, ci_uint64 now, ci_uint32 khz)
{
  struct cp_fwd_rw_row* fwd_rw = &fwd_table->rw_rows[id];
  ci_uint64 frc = (now - fwd_rw->frc_used) / khz;
  struct cp_fwd_row* fwd = cp_get_fwd_by_id(fwd_table, id);
  cp_print(s, "\tlast used: %"PRIu64" ms ago", frc);
  if( fwd->flags & CICP_FWD_FLAG_ERROR )
    cp_print(s, "\tnon-existent route");
  if( fwd->flags & CICP_FWD_FLAG_STALE )
    cp_print(s, "\twill be removed from fwd cache soon");
  if( fwd_rw->flags & CICP_FWD_RW_FLAG_ARP_NEED_REFRESH )
    cp_print(s, "\tARP entry need confirmation if possible");
  cp_print(s, "\tin use: %d \tverinfo: %x-%x", fwd->use, id, fwd->version);
}


static void
print_fwd_priv(struct cp_session* s, struct cp_fwd_priv* fwd_priv,
               ci_uint64 now, ci_uint32 khz)
{
  cp_print(s, "\tpriv: table %d %s(%d) macid=%d used %"PRIu64" ms ago",
           fwd_priv->table_id,
           cp_ifindex2name(s->mib, fwd_priv->ifindex), fwd_priv->ifindex,
           fwd_priv->macid,
           (now - fwd_priv->frc_used) / s->khz);
}


static void
print_prefix_length_list(struct cp_session* s, ci_ipx_pfx_t* mib_mask)
{
  ci_ipx_pfx_t mask;
  int len = 0;
  int i = 2;
  memcpy(&mask, mib_mask, sizeof(ci_ipx_pfx_t));

  do {
    while( mask.ip6[i] == 0 ) {
      i--;
      if( i < 0 )
        return;
    }

    len = ffsll(mask.ip6[i]) - 1;
    cp_print_nonewline(s, " %d", 64 * (2-i) + len);
    mask.ip6[i] &= mask.ip6[i] - 1;
  } while(1);
}


void cp_fwd_print(struct cp_session* s)
{
  uint64_t now = ci_frc64_get();
  struct cp_fwd_state* fwd_state = NULL;

  while( (fwd_state = cp_fwd_state_iterate_mapped(s, fwd_state)) != NULL ) {
    cicp_mac_rowid_t id = -1;
    cp_fwd_table_id fwd_table_id = cp_fwd_state_id(s, fwd_state);

    cp_print(s, "FWD table %u:\n", fwd_table_id);

    cp_print_nonewline(s, "Source prefix length in use:");
    print_prefix_length_list(s,
                             &fwd_state->fwd_table.prefix[CP_FWD_PREFIX_SRC]);
    cp_print(s, "");
    cp_print_nonewline(s, "Destination prefix length in use:");
    print_prefix_length_list(s,
                             &fwd_state->fwd_table.prefix[CP_FWD_PREFIX_DST]);
    cp_print(s, "\n");

    while( (id = cp_row_mask_iter_set(fwd_state->fwd_used, ++id,
                                      fwd_state->fwd_table.mask + 1, true) ) !=
           CICP_MAC_ROWID_BAD ) {
      struct cp_fwd_row* fwd = cp_get_fwd_by_id(&fwd_state->fwd_table, id);
      if( ~fwd->flags & CICP_FWD_FLAG_OCCUPIED ) {
        cp_print(s, "fwd[%03u:%03d]: in use by %d paths", fwd_table_id, id,
                 fwd->use);
        continue;
      }

      cp_print(s, "fwd[%03u:%03d]:\n"
                  "\tkey: from "CP_ADDR_PREFIX_FMT" to "CP_ADDR_PREFIX_FMT"\n"
                  "\tkey: iif %s oif %s tos %d %s",
               fwd_table_id,
               id, CP_ADDR_PREFIX_ARG(fwd->key.src, fwd->key_ext.src_prefix),
               CP_ADDR_PREFIX_ARG(fwd->key.dst, fwd->key_ext.dst_prefix),
               fwd->key.iif_ifindex == 0
               ? "output" : cp_ifindex2name(&s->mib[0], fwd->key.iif_ifindex),
               fwd->key.ifindex == 0
               ? "any" : cp_ifindex2name(&s->mib[0], fwd->key.ifindex),
               fwd->key.tos,
               (fwd->key.flag & CP_FWD_KEY_TRANSPARENT)
               ?  "TRANSPARENT" : "");

      print_fwd_data(s, cp_get_fwd_data_current(fwd));
      print_fwd_extras(s, &fwd_state->fwd_table, id, now, s->khz);
      print_fwd_priv(s, &fwd_state->priv_rows[id], now, s->khz);
    }

    cp_print(s, "");
  }
}
