/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Software implemented endpoint lookup.
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

#include <ci/internal/transport_config_opt.h>
#include "ip_internal.h"
#include <onload/hash.h>
#include "netif_table.h"

/* A filter-table entry can be in one of four states:
 *   A. empty non-tombstone;
 *   B. tombstone;
 *   C. valid, containing an entry at its preferred location (i.e. hash1); or
 *   D. valid, containing an entry not at its preferred location.
 * We choose the encoding of the __id_and_state field and define the numerical
 * values that represent these states to try to help the compiler to generate
 * efficient code.  Most importantly, we want state C., which is the state that
 * sends us down the fast lookup path, to be handled with as little fuss as
 * possible.  To this end, the two bits representing the state are packed into
 * the most significant bits of the __id_and_state field, and the value for
 * state C. is chosen to be zero to make promotion of the remaining 30 bits to
 * a 32-bit socket index a no-op. */
#define FILTER_TABLE_ID_BITS    30
#define FILTER_TABLE_ID_MASK    ((1u << FILTER_TABLE_ID_BITS) - 1)
#define FILTER_TABLE_STATE_MASK (~FILTER_TABLE_ID_MASK)
enum {
  OCCUPIED_PREFERRED = 0,
  OCCUPIED_REHASHED  = (1u << FILTER_TABLE_ID_BITS),
  EMPTY              = (2u << FILTER_TABLE_ID_BITS),
  TOMBSTONE          = (3u << FILTER_TABLE_ID_BITS),
};

ci_inline ci_uint32 STATE(ci_netif_filter_table_entry_fast* entry)
{
  return entry->__id_and_state & FILTER_TABLE_STATE_MASK;
}

ci_inline ci_uint32 OCCUPIED(ci_netif_filter_table_entry_fast* entry)
{
  CI_BUILD_ASSERT(CI_IS_POW2(EMPTY & TOMBSTONE));
  return ~STATE(entry) & EMPTY & TOMBSTONE;
}

#define __ID(entry) ((entry)->__id_and_state & FILTER_TABLE_ID_MASK)
ci_inline ci_uint32 ID(ci_netif_filter_table_entry_fast* entry)
{
  ci_assert(OCCUPIED(entry));
  return __ID(entry);
}

ci_inline void
set_entry_state(ci_netif_filter_table_entry_fast* entry, ci_uint32 state)
{
  entry->__id_and_state = __ID(entry) | state;
}

ci_inline void
set_entry_id(ci_netif_filter_table_entry_fast* entry, ci_uint32 id)
{
  ci_assert_nflags(id, FILTER_TABLE_STATE_MASK);
  entry->__id_and_state = STATE(entry) | id;
}

#define CI_NETIF_FILTER_ID_TO_SOCK_ID(ni, filter_id)            \
  OO_SP_FROM_INT((ni), ID(&(ni)->filter_table->table[filter_id]))

#if CI_CFG_IPV6
#define CI_NETIF_IP6_FILTER_ID_TO_SOCK_ID(ni, filter_id)            \
  OO_SP_FROM_INT((ni), (ni)->ip6_filter_table->table[filter_id].id)
#endif


/* Returns table entry index, or -1 if lookup failed. */
static int
ci_ip4_netif_filter_lookup(ci_netif* netif, unsigned laddr, unsigned lport,
                           unsigned raddr, unsigned rport, unsigned protocol)
{
  unsigned hash1, hash2 = 0;
  ci_netif_filter_table* tbl;
  unsigned first;

  ci_assert(netif);
  ci_assert(ci_netif_is_locked(netif));
  ci_assert(netif->filter_table);

  tbl = netif->filter_table;
  hash1 = __onload_hash1(tbl->table_size_mask, laddr, lport,
                       raddr, rport, protocol);
  first = hash1;

  LOG_NV(log("tbl_lookup: %s %s:%u->%s:%u hash=%u:%u at=%u",
	     CI_IP_PROTOCOL_STR(protocol),
	     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	     first, __onload_hash2(laddr, lport, raddr, rport, protocol),
	     hash1));

  while( 1 ) {
    ci_netif_filter_table_entry_fast* entry = &tbl->table[hash1];

    /* This function is not used on fast paths, so we don't try to avoid
     * touching the extra state. */
    ci_netif_filter_table_entry_ext* entry_ext;
    entry_ext = &netif->filter_table_ext[hash1];

    if( CI_LIKELY(OCCUPIED(entry)) ) {
      ci_sock_cmn* s = ID_TO_SOCK(netif, ID(entry));
      if( ((laddr    - entry->laddr      ) |
	   (lport    - entry_ext->lport  ) |
	   (raddr    - sock_raddr_be32(s)) |
	   (rport    - sock_rport_be16(s)) |
	   (protocol - sock_protocol(s)  )) == 0 )
      	return hash1;
    }
    if( STATE(entry) == EMPTY )  break;
    /* We defer calculating hash2 until it's needed, just to make the fast
     * case that little bit faster. */
    if( hash1 == first )
      hash2 = __onload_hash2(laddr, lport, raddr, rport, protocol);
    hash1 = (hash1 + hash2) & tbl->table_size_mask;
    if( hash1 == first ) {
      LOG_E(ci_log(FN_FMT "ERROR: LOOP %s:%u->%s:%u hash=%u:%u",
                   FN_PRI_ARGS(netif), ip_addr_str(laddr), lport,
		   ip_addr_str(raddr), rport, hash1, hash2));
      return -ELOOP;
    }
  }

  return -ENOENT;
}

/* Sometimes user is not interested in particular entry id; they may be
 * interested in yes/no.  This functions looks up in both IPv4 and IPv6
 * tables and returns the answer. */
oo_sp
ci_netif_filter_lookup(ci_netif* netif, int af_space,
                           ci_addr_t laddr, unsigned lport,
                           ci_addr_t raddr, unsigned rport,
                           unsigned protocol)
{
  int rc = -ENOENT;

#if CI_CFG_IPV6
  if( IS_AF_SPACE_IP6(af_space) ) {
    rc = ci_ip6_netif_filter_lookup(netif, laddr, lport,
                                    raddr, rport, protocol);
    if( rc >= 0 )
      return CI_NETIF_IP6_FILTER_ID_TO_SOCK_ID(netif, rc);
  }

  if( IS_AF_SPACE_IP4(af_space) )
#endif
    rc = ci_ip4_netif_filter_lookup(netif, laddr.ip4, lport,
                                    raddr.ip4, rport, protocol);
  if( rc >= 0 )
    return CI_NETIF_FILTER_ID_TO_SOCK_ID(netif, rc);
  return OO_SP_NULL;
}

int ci_netif_listener_lookup(ci_netif* netif, int af_space,
                             ci_addr_t laddr, unsigned lport)
{
  oo_sp sock = ci_netif_filter_lookup(netif, af_space, laddr, lport,
                                      addr_any, 0, IPPROTO_TCP);
  if( OO_SP_IS_NULL(sock) )
    sock = ci_netif_filter_lookup(netif, af_space, addr_any, lport,
                                  addr_any, 0, IPPROTO_TCP);
  return sock;
}


ci_uint32
ci_netif_filter_hash(ci_netif* ni, ci_addr_t laddr, unsigned lport,
                     ci_addr_t raddr, unsigned rport, unsigned protocol)
{
  return onload_hash3(laddr, lport, raddr, rport, protocol);
}


ci_inline int /*bool*/
handle_entry(ci_netif* ni, ci_netif_filter_table_entry_fast* entry,
             ci_netif_filter_table_entry_ext* entry_ext,
             unsigned laddr, unsigned lport, unsigned raddr, unsigned rport,
             unsigned protocol, int intf_i, int vlan,
             int (*callback)(ci_sock_cmn*, void*), void* callback_arg,
             int /*bool*/ check_lport)
{
  ci_sock_cmn* s = ID_TO_SOCK(ni, ID(entry));
  int is_match = 0;

  /* An unconnected IPv6 socket bound to :: can receive both IPv4 and IPv6
   * packets, but it has IPv4 ipcache, so its sock_raddr_be32() is 0 and
   * can be used without checking for CI_SOCK_FLAG_CONNECTED, in contrast
   * to the equivlalent test in ci_netif_filter_for_each_match_ip6(). */
  if( ((laddr    - entry->laddr      ) |
       /* check_lport is expected to be a compile-time constant, so when
        * inlining this function the compiler should either generate sensible
        * code here. */
       (lport    - entry_ext->lport) * !! check_lport |
       (raddr    - sock_raddr_be32(s)) |
       (rport    - sock_rport_be16(s)) |
       (protocol - sock_protocol(s)  )) == 0 )
    is_match = 1;
  LOG_NV(ci_log("%s match=%d: %s %s:%u->%s:%u hash=%u:%u at=%u check_lport=%d",
                __FUNCTION__, is_match, CI_IP_PROTOCOL_STR(protocol),
                ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
                ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
                __onload_hash1(ni->filter_table->table_size_mask, laddr, lport,
                               raddr, rport, protocol),
                __onload_hash2(laddr, lport, raddr, rport, protocol),
                (unsigned) (entry - ni->filter_table->table), check_lport));

  if( is_match &&
      CI_LIKELY((s->rx_bind2dev_ifindex == CI_IFID_BAD ||
                 ci_sock_intf_check(ni, s, intf_i, vlan))) &&
      callback(s, callback_arg) != 0 )
    return 1;
  return 0;
}


int
ci_netif_filter_for_each_match(ci_netif* ni,
                               unsigned laddr, unsigned lport,
                               unsigned raddr, unsigned rport,
                               unsigned protocol, int intf_i, int vlan,
                               int (*callback)(ci_sock_cmn*, void*),
                               void* callback_arg, ci_uint32* hash_out)
{
  ci_netif_filter_table* tbl = NULL;
  unsigned hash1, hash2 = 0;
  unsigned first, table_size_mask;
  ci_netif_filter_table_entry_fast* entry;

  tbl = ni->filter_table;
  table_size_mask = tbl->table_size_mask;

  if( hash_out != NULL )
    *hash_out = __onload_hash3(laddr, lport, raddr, rport, protocol);
  hash1 = __onload_hash1(table_size_mask, laddr, lport, raddr, rport,
                         protocol);
  first = hash1;

  LOG_NV(log("%s: %s %s:%u->%s:%u hash=%u:%u at=%u",
             __FUNCTION__, CI_IP_PROTOCOL_STR(protocol),
	     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	     first, __onload_hash2(laddr, lport, raddr, rport, protocol),
	     hash1));

  /* The loop a little way below iterates over the hash table looking for
   * matches.  The test of the first entry in our walk through the table is
   * pulled out of the loop, however, as that first entry (i.e., the entry at
   * the location for hash1 of the lookup-query) has some useful properties
   * that we can exploit.
   *     If we find that this entry is at its preferred location, then we know
   * that the value of hash1 of our inputs that we have just calculated is also
   * equal to __onload_hash1() for the tuple stored in this entry.  But our
   * value of table_size_mask is large enough that __onload_hash1() has the
   * Local Port Recovery Property, as defined and proven next to the definition
   * of that function.  As such, if we find that the protocol, remote address,
   * local address and remote port of the entry match our inputs, we are
   * guaranteed also that its local port must match too, and we don't need to
   * check it.  As well as allowing us to avoid a little bit of work when
   * testing whether the entry matches, it allows us to keep the entry's local
   * port in the slow-path state, as in the common case we don't need to touch
   * it. */
  ci_assert_ge(table_size_mask + 1, 1u << 16);
  entry = &tbl->table[hash1];
  if( STATE(entry) == OCCUPIED_PREFERRED ) {
    /* We pass the entry in filter_table_ext here, but as check_lport is false
     * it won't be used, and moreover the inlining will drop it entirely. */
    if( handle_entry(ni, entry, &ni->filter_table_ext[hash1], laddr, lport,
                     raddr, rport, protocol, intf_i, vlan, callback,
                     callback_arg, 0 /*check_lport*/) )
      return 1;
  }
  /* If the state of that first entry was OCCUPIED_REHASHED, it's a guaranteed
   * non-match for this lookup, because this location is the preferred bucket
   * for the query.  So we enter the loop at the point at which we've decided
   * that the entry is a non-match. */
  while( 1 ) {
    ci_netif_filter_table_entry_ext* entry_ext;
    if( STATE(entry) == EMPTY )
      break;
    /* We defer calculating hash2 until it's needed, just to make the fast
    ** case that little bit faster. */
    if( hash1 == first )
      hash2 = __onload_hash2(laddr, lport, raddr, rport, protocol);
    hash1 = (hash1 + hash2) & table_size_mask;
    if( hash1 == first ) {
      LOG_NV(ci_log(FN_FMT "ITERATE FULL %s:%u->%s:%u hash=%u:%u",
                    FN_PRI_ARGS(ni), ip_addr_str(laddr), CI_BSWAP_BE16(lport),
                    ip_addr_str(raddr), CI_BSWAP_BE16(rport), hash1, hash2));
      break;
    }
    entry = &tbl->table[hash1];
    entry_ext = &ni->filter_table_ext[hash1];
    if( OCCUPIED(entry) ) {
      if( handle_entry(ni, entry, entry_ext, laddr, lport, raddr, rport,
                       protocol, intf_i, vlan, callback, callback_arg,
                       1 /*check_lport*/) )
        return 1;
    }
  }
  return 0;
}


/* Insert for either TCP or UDP */
static int
ci_ip4_netif_filter_insert(ci_netif_filter_table* tbl,
                           ci_netif* netif, oo_sp tcp_id,
                           unsigned laddr, unsigned lport,
                           unsigned raddr, unsigned rport,
                           unsigned protocol)
{
  ci_netif_filter_table_entry_fast* entry;
  ci_netif_filter_table_entry_ext* entry_ext;
  unsigned hash1, hash2;
#if !defined(NDEBUG) || CI_CFG_STATS_NETIF
  unsigned hops = 1;
#endif
  unsigned first;

  hash1 = __onload_hash1(tbl->table_size_mask, laddr, lport,
                         raddr, rport, protocol);
  hash2 = __onload_hash2(laddr, lport, raddr, rport, protocol);
  first = hash1;

  /* Find a free slot. */
  while( 1 ) {
    entry = &tbl->table[hash1];
    entry_ext = &netif->filter_table_ext[hash1];
    if( ! OCCUPIED(entry) )  break;

    ++entry_ext->route_count;
#if !defined(NDEBUG) || CI_CFG_STATS_NETIF
    ++hops;
#endif

    /* A socket can only have multiple entries in the filter table if each
     * entry has a different [laddr].
     */
    ci_assert(
      !((ID(entry) == OO_SP_TO_INT(tcp_id)) && (laddr == entry->laddr)) );

    hash1 = (hash1 + hash2) & tbl->table_size_mask;

    if( hash1 == first ) {
      ci_sock_cmn *s = SP_TO_SOCK_CMN(netif, tcp_id);
      if( ! (s->s_flags & CI_SOCK_FLAG_SW_FILTER_FULL) ) {
        LOG_E(ci_log(FN_FMT "%d FULL %s %s:%u->%s:%u hops=%u",
                     FN_PRI_ARGS(netif),
                     OO_SP_FMT(tcp_id), CI_IP_PROTOCOL_STR(protocol),
                     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
                     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
                     hops));
        s->s_flags |= CI_SOCK_FLAG_SW_FILTER_FULL;
      }

      CITP_STATS_NETIF_INC(netif, sw_filter_insert_table_full);
      return -ENOBUFS;
    }
  }

  /* Now insert the new entry. */
  LOG_TC(ci_log(FN_FMT "%d INSERT %s %s:%u->%s:%u hash=%u:%u at=%u "
    "over=%u:%u hops=%u", FN_PRI_ARGS(netif), OO_SP_FMT(tcp_id),
                CI_IP_PROTOCOL_STR(protocol),
    ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
    ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
    first, hash2, hash1, STATE(entry), __ID(entry), hops));

#if CI_CFG_STATS_NETIF
  if( hops > netif->state->stats.table_max_hops )
    netif->state->stats.table_max_hops = hops;
  /* Keep a rolling average of the number of hops per entry. */
  if( netif->state->stats.table_mean_hops == 0 )
    netif->state->stats.table_mean_hops = 1;
  netif->state->stats.table_mean_hops =
    (netif->state->stats.table_mean_hops * 9 + hops) / 10;

  if( STATE(entry) == EMPTY )
    ++netif->state->stats.table_n_slots;
  ++netif->state->stats.table_n_entries;
#endif

  set_entry_state(entry,
                  hash1 == first ? OCCUPIED_PREFERRED : OCCUPIED_REHASHED);
  set_entry_id(entry, OO_SP_TO_INT(tcp_id));
  entry->laddr = laddr;
  entry_ext->lport = lport;
  return 0;
}


static void
__ci_ip4_netif_filter_remove(ci_netif_filter_table* tbl, ci_netif* ni,
                             unsigned hash1, unsigned hash2,
                             int hops, unsigned last_tbl_i)
{
  ci_netif_filter_table_entry_fast* entry;
  ci_netif_filter_table_entry_ext* entry_ext;
  unsigned tbl_i;
  int i;

  tbl_i = hash1;
  for( i = 0; i < hops; ++i ) {
    entry = &tbl->table[tbl_i];
    entry_ext = &ni->filter_table_ext[tbl_i];
    ci_assert(STATE(entry) != EMPTY);
    ci_assert(entry_ext->route_count > 0);
    if( --entry_ext->route_count == 0 && STATE(entry) == TOMBSTONE ) {
      CITP_STATS_NETIF(--ni->state->stats.table_n_slots);
      set_entry_state(entry, EMPTY);
    }
    tbl_i = (tbl_i + hash2) & tbl->table_size_mask;
  }
  ci_assert(tbl_i == last_tbl_i);

  CITP_STATS_NETIF(--ni->state->stats.table_n_entries);
  entry = &tbl->table[tbl_i];
  entry_ext = &ni->filter_table_ext[tbl_i];
  if( entry_ext->route_count == 0 ) {
    CITP_STATS_NETIF(--ni->state->stats.table_n_slots);
    set_entry_state(entry, EMPTY);
  }
  else {
    set_entry_state(entry, TOMBSTONE);
  }
}


static void
ci_ip4_netif_filter_remove(ci_netif_filter_table* tbl,
                           ci_netif* netif, oo_sp sock_p,
                           unsigned laddr, unsigned lport,
                           unsigned raddr, unsigned rport,
                           unsigned protocol)
{
  ci_netif_filter_table_entry_fast* entry;
  unsigned hash1, hash2, tbl_i;
  int hops = 0;
  unsigned first;

  ci_assert(ci_netif_is_locked(netif)
#ifdef __KERNEL__
            /* release_ep_tbl might be called without the stack lock.
             * Do not complain about this. */
            || (netif2tcp_helper_resource(netif)->k_ref_count &
                TCP_HELPER_K_RC_DEAD)
#endif
            );

  hash1 = __onload_hash1(tbl->table_size_mask, laddr, lport,
                         raddr, rport, protocol);
  hash2 = __onload_hash2(laddr, lport, raddr, rport, protocol);
  first = hash1;

  LOG_TC(ci_log("%s: [%d:%d] REMOVE %s %s:%u->%s:%u hash=%u:%u",
                __FUNCTION__, NI_ID(netif), OO_SP_FMT(sock_p),
                CI_IP_PROTOCOL_STR(protocol),
    ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
    ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
    hash1, hash2));

  tbl_i = hash1;
  while( 1 ) {
    entry = &tbl->table[tbl_i];
    if( OCCUPIED(entry) && ID(entry) == OO_SP_TO_INT(sock_p) ) {
      if( laddr == entry->laddr )
        break;
    }
    else if( STATE(entry) == EMPTY ) {
      /* We allow multiple removes of the same filter -- helps avoid some
       * complexity in the filter module.
       */
      return;
    }
    tbl_i = (tbl_i + hash2) & tbl->table_size_mask;
    ++hops;
    if( tbl_i == first ) {
      LOG_E(ci_log(FN_FMT "ERROR: LOOP [%d] %s %s:%u->%s:%u",
                   FN_PRI_ARGS(netif), OO_SP_FMT(sock_p),
                   CI_IP_PROTOCOL_STR(protocol),
                   ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
                   ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport)));
      return;
    }
  }

  __ci_ip4_netif_filter_remove(tbl, netif, hash1, hash2, hops, tbl_i);
}

int
ci_netif_filter_insert(ci_netif* netif, oo_sp tcp_id, int af_space,
                       const ci_addr_t laddr, unsigned lport,
                       const ci_addr_t raddr, unsigned rport,
                       unsigned protocol)
{
  ci_netif_filter_table* ip4_tbl;
  int rc = 0;
#if CI_CFG_IPV6
  ci_ip6_netif_filter_table* ip6_tbl;
#endif

  ci_assert(netif);
  ci_assert(ci_netif_is_locked(netif));

#if CI_CFG_IPV6
  if( IS_AF_SPACE_IP6(af_space) ) {
    ci_assert(netif->ip6_filter_table);
    ip6_tbl = netif->ip6_filter_table;

    rc = ci_ip6_netif_filter_insert(ip6_tbl, netif, tcp_id, laddr, lport,
                                      raddr, rport, protocol);
    if( rc < 0 )
      return rc;
  }

  if( IS_AF_SPACE_IP4(af_space) )
#endif
  {
    ci_assert(netif->filter_table);
    ip4_tbl = netif->filter_table;

    rc = ci_ip4_netif_filter_insert(ip4_tbl, netif, tcp_id, laddr.ip4, lport,
                                     raddr.ip4, rport, protocol);
    /* Fixme: should we roll back the IPv6 insertion when trying to listen
     * in the both worlds, and IPv4 fails? */
    if( rc < 0 )
      return rc;
  }

  return 0;
}

void
ci_netif_filter_remove(ci_netif* netif, oo_sp sock_p, int af_space,
                       const ci_addr_t laddr, unsigned lport,
                       const ci_addr_t raddr, unsigned rport,
                       unsigned protocol)
{
  ci_netif_filter_table* ip4_tbl;
#if CI_CFG_IPV6
  ci_ip6_netif_filter_table* ip6_tbl;
#endif

  ci_assert(netif);

#if CI_CFG_IPV6
  if( IS_AF_SPACE_IP6(af_space) ) {
    ci_assert(netif->ip6_filter_table);
    ip6_tbl = netif->ip6_filter_table;

    ci_ip6_netif_filter_remove(ip6_tbl, netif, sock_p, laddr, lport,
                               raddr, rport, protocol);
  }

  if( IS_AF_SPACE_IP4(af_space) )
#endif
  {
    ci_assert(netif->filter_table);
    ip4_tbl = netif->filter_table;

    ci_ip4_netif_filter_remove(ip4_tbl, netif, sock_p, laddr.ip4, lport,
                               raddr.ip4, rport, protocol);
  }
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

#ifdef __ci_driver__

void ci_netif_filter_init(ci_netif* ni, int size_lg2)
{
  unsigned i;
  unsigned size = ci_pow2(size_lg2);

  ci_assert(ni);
  ci_assert(ni->filter_table);
  ci_assert(ni->filter_table_ext);
  ci_assert_ge(size_lg2, 16);  /* For ci_netif_filter_for_each_match(). */
  ci_assert_le(size_lg2, 32);

  ni->filter_table->table_size_mask = size - 1;

  for( i = 0; i < size; ++i ) {
    set_entry_state(&ni->filter_table->table[i], EMPTY);
    ni->filter_table_ext[i].route_count = 0;
    ni->filter_table_ext[i].lport = 0;
    ni->filter_table->table[i].laddr = 0;
  }
}

#endif

int
__ci_ip4_netif_filter_lookup(ci_netif* netif,
                             unsigned laddr, unsigned lport,
                             unsigned raddr, unsigned rport,
                             unsigned protocol)
{
  int rc;

  /* try full lookup */
  rc = ci_ip4_netif_filter_lookup(netif, laddr, lport,  raddr, rport, protocol);
  LOG_NV(log(LPF "FULL LOOKUP %s:%u->%s:%u rc=%d",
	     ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	     ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	     rc));    

  if(CI_LIKELY( rc >= 0 ))
    return rc;

  /* try wildcard lookup */
  raddr = rport = 0;
  rc = ci_ip4_netif_filter_lookup(netif, laddr, lport, raddr, rport, protocol);
  LOG_NV(log(LPF "WILD LOOKUP %s:%u->%s:%u rc=%d",
	    ip_addr_str(laddr), (unsigned) CI_BSWAP_BE16(lport),
	    ip_addr_str(raddr), (unsigned) CI_BSWAP_BE16(rport),
	    rc));

  if(CI_LIKELY( rc >= 0 ))
    return rc;

  return -ENOENT;
}

ci_sock_cmn*
__ci_netif_filter_lookup(ci_netif* netif, int af_space,
                         ci_addr_t laddr, unsigned lport,
                         ci_addr_t raddr, unsigned rport,
                         unsigned protocol)
{
  int rc;

#if CI_CFG_IPV6
  if( IS_AF_SPACE_IP6(af_space) ) {
    rc = __ci_ip6_netif_filter_lookup(netif, laddr, lport, raddr, rport,
                                      protocol);
    if(CI_LIKELY( rc >= 0 ))
      return ID_TO_SOCK(netif, netif->ip6_filter_table->table[rc].id);
  }

  if( IS_AF_SPACE_IP4(af_space) )
#endif
  {
    rc = __ci_ip4_netif_filter_lookup(netif, laddr.ip4, lport, raddr.ip4, rport,
                                      protocol);
    if(CI_LIKELY( rc >= 0 ))
      return ID_TO_SOCK(netif, ID(&netif->filter_table->table[rc]));
  }

  return 0;
}


/**********************************************************************
 **********************************************************************
 **********************************************************************/

void ci_netif_filter_dump(ci_netif* ni)
{
  unsigned i;
  ci_netif_filter_table* tbl;

  ci_assert(ni);
  tbl = ni->filter_table;

  log("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#if CI_CFG_STATS_NETIF
  log(FN_FMT "size=%d n_entries=%i n_slots=%i max=%i mean=%i", FN_PRI_ARGS(ni),
      tbl->table_size_mask + 1, ni->state->stats.table_n_entries,
      ni->state->stats.table_n_slots, ni->state->stats.table_max_hops,
      ni->state->stats.table_mean_hops);
#endif

  for( i = 0; i <= tbl->table_size_mask; ++i ) {
    ci_netif_filter_table_entry_fast* entry = &tbl->table[i];
    ci_netif_filter_table_entry_ext* entry_ext = &ni->filter_table_ext[i];
    if( CI_LIKELY(OCCUPIED(entry)) ) {
      ci_sock_cmn* s = ID_TO_SOCK(ni, ID(entry));
      unsigned laddr = entry->laddr;
      int lport = entry_ext->lport;
      unsigned raddr = sock_raddr_be32(s);
      int rport = sock_rport_be16(s);
      int protocol = sock_protocol(s);
      unsigned hash1 = __onload_hash1(tbl->table_size_mask, laddr, lport,
                                      raddr, rport, protocol);
      unsigned hash2 = __onload_hash2(laddr, lport, raddr, rport, protocol);
      log("%010d state=%u id=%-10d rt_ct=%d %s "CI_IP_PRINTF_FORMAT":%d "
          CI_IP_PRINTF_FORMAT":%d %010d:%010d",
          i, STATE(entry) >> FILTER_TABLE_ID_BITS, ID(entry),
          entry_ext->route_count, CI_IP_PROTOCOL_STR(protocol),
          CI_IP_PRINTF_ARGS(&laddr), CI_BSWAP_BE16(lport),
	  CI_IP_PRINTF_ARGS(&raddr), CI_BSWAP_BE16(rport), hash1, hash2);
    }
  }
#if CI_CFG_IPV6
  ci_ip6_netif_filter_dump(ni);
#endif
  log("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
}

/*! \cidoxg_end */
