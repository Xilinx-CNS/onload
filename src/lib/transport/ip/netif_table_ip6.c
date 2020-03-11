/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/internal/transport_config_opt.h>
#include "ip_internal.h"
#include <onload/hash.h>
#include "netif_table.h"

#if CI_CFG_IPV6

#define TOMBSTONE  -1
#define EMPTY      -2

int ci_ip6_netif_filter_lookup(ci_netif* netif,
                               ci_addr_t laddr, unsigned lport,
                               ci_addr_t raddr, unsigned rport,
                               unsigned protocol)
{
  unsigned hash1, hash2 = 0;
  unsigned first;
  ci_ip6_netif_filter_table* tbl;

  ci_assert(netif);
  ci_assert(ci_netif_is_locked(netif));
  ci_assert(netif->ip6_filter_table);

  tbl = netif->ip6_filter_table;

  hash1 = onload_hash1(tbl->table_size_mask, laddr, lport,
                       raddr, rport, protocol);
  first = hash1;

  LOG_NV(log("%s: %s " IPX_PORT_FMT "->" IPX_PORT_FMT " hash=%u:%u at=%u",
             __func__, CI_IP_PROTOCOL_STR(protocol),
             IPX_ARG(AF_IP(laddr)), (unsigned) CI_BSWAP_BE16(lport),
             IPX_ARG(AF_IP(raddr)), (unsigned) CI_BSWAP_BE16(rport),
             first,
             onload_hash2(laddr, lport, raddr, rport, protocol),
             hash1));

  while( 1 ) {
    int id = tbl->table[hash1].id;
    if( CI_LIKELY(id >= 0) ) {
      ci_sock_cmn* s = ID_TO_SOCK(netif, id);
      if( ((lport    - sock_lport_be16(s)     ) |
           (rport    - sock_rport_be16(s)     ) |
           (protocol - sock_protocol(s)       )) == 0 &&
          memcmp(laddr.ip6, tbl->table[hash1].laddr, sizeof(laddr)) == 0 &&
          memcmp(raddr.ip6, sock_ip6_raddr(s), sizeof(raddr)) == 0 )
        return hash1;
    }
    if( id == EMPTY )  break;
    /* We defer calculating hash2 until it's needed, just to make the fast
     * case that little bit faster. */
    if( hash1 == first )
      hash2 = onload_hash2(laddr, lport, raddr, rport, protocol);
    hash1 = (hash1 + hash2) & tbl->table_size_mask;
    if( hash1 == first ) {
      LOG_E(ci_log(FN_FMT "ERROR: LOOP " IPX_PORT_FMT "->" IPX_PORT_FMT
                   " hash=%u:%u", FN_PRI_ARGS(netif),
                   IPX_ARG(AF_IP(laddr)), lport,
                   IPX_ARG(AF_IP(raddr)), rport, hash1, hash2));
      return -ELOOP;
    }
  }

  return -ENOENT;
}


static inline unsigned laddr_xor(const void* laddr_ptr)
{
  ci_assert(laddr_ptr != NULL);
  return onload_addr_xor(*(ci_addr_t*)laddr_ptr);
}

static inline unsigned raddr_xor(const void* raddr_ptr)
{
  return raddr_ptr == NULL ? 0 : onload_addr_xor(*(ci_addr_t*)raddr_ptr);
}

/* The following variants of the hashing functions tolerate NULL for the remote
 * address. */
static inline unsigned
ip6_lookup_hash1(unsigned size_mask,
                 const void* laddr_ptr, unsigned lport,
                 const void* raddr_ptr, unsigned rport, unsigned protocol)
{
  return __onload_hash1(size_mask, laddr_xor(laddr_ptr), lport,
                        raddr_xor(raddr_ptr), rport, protocol);
}

static inline unsigned
ip6_lookup_hash2(const void* laddr_ptr, unsigned lport,
                 const void* raddr_ptr, unsigned rport, unsigned protocol)
{
  return __onload_hash2(laddr_xor(laddr_ptr), lport,
                        raddr_xor(raddr_ptr), rport, protocol);
}

static inline unsigned
ip6_lookup_hash3(const void* laddr_ptr, unsigned lport,
                 const void* raddr_ptr, unsigned rport, unsigned protocol)
{
  return __onload_hash3(laddr_xor(laddr_ptr), lport,
                        raddr_xor(raddr_ptr), rport, protocol);
}


int
ci_netif_filter_for_each_match_ip6(ci_netif* ni,
                                   const ci_addr_t* laddr_ptr, unsigned lport,
                                   /* raddr_ptr==NULL means [::] */
                                   const ci_addr_t* raddr_ptr, unsigned rport,
                                   unsigned protocol, int intf_i, int vlan,
                                   int (*callback)(ci_sock_cmn*, void*),
                                   void* callback_arg, ci_uint32* hash_out)
{
  ci_ip6_netif_filter_table* ip6_tbl = NULL;
  unsigned hash1, hash2 = 0;
  unsigned first, table_size_mask;

#ifndef NDEBUG
  ci_addr_t laddr = *((ci_addr_t*)laddr_ptr);
  ci_addr_t raddr = raddr_ptr == NULL ? addr_any : *((ci_addr_t*)raddr_ptr);
#endif

  ip6_tbl = ni->ip6_filter_table;
  table_size_mask = ip6_tbl->table_size_mask;

  if( hash_out != NULL )
    *hash_out = ip6_lookup_hash3(laddr_ptr, lport, raddr_ptr, rport, protocol);
  hash1 = ip6_lookup_hash1(table_size_mask, laddr_ptr, lport, raddr_ptr, rport,
                           protocol);
  first = hash1;

  LOG_NV(log("%s: %s " IPX_PORT_FMT "->" IPX_PORT_FMT " hash=%u:%u at=%u",
             __FUNCTION__, CI_IP_PROTOCOL_STR(protocol),
	     IPX_ARG(AF_IP(laddr)), (unsigned) CI_BSWAP_BE16(lport),
	     IPX_ARG(AF_IP(raddr)), (unsigned) CI_BSWAP_BE16(rport),
             first, ip6_lookup_hash2(laddr_ptr, lport, raddr_ptr, rport,
                                     protocol), hash1));

  while( 1 ) {
    int id = ip6_tbl->table[hash1].id;
    if( CI_LIKELY(id >= 0) ) {
      int is_match = 0;

      ci_sock_cmn* s = ID_TO_SOCK(ni, id);
      if( memcmp(laddr_ptr, ip6_tbl->table[hash1].laddr,
                 sizeof(ci_ip6_addr_t)) == 0 &&
          lport == sock_lport_be16(s) &&
          protocol == sock_protocol(s) &&
          ( (raddr_ptr == NULL && !(s->s_flags & CI_SOCK_FLAG_CONNECTED)) ||
            (raddr_ptr != NULL &&
             memcmp(raddr_ptr, sock_ip6_raddr(s),
                    sizeof(ci_ip6_addr_t)) == 0 &&
             rport == sock_rport_be16(s)) )
        )
        is_match = 1;
      LOG_NV(ci_log("%s match=%d: %s " IPX_PORT_FMT "->"
                    IPX_PORT_FMT " hash=%u:%u at=%u",
                    __FUNCTION__, is_match, CI_IP_PROTOCOL_STR(protocol),
                    IPX_ARG(AF_IP(laddr)), (unsigned) CI_BSWAP_BE16(lport),
                    IPX_ARG(AF_IP(raddr)), (unsigned) CI_BSWAP_BE16(rport),
                    first, ip6_lookup_hash2(laddr_ptr, lport, raddr_ptr,
                                            rport, protocol), hash1));

      if( is_match && CI_LIKELY((s->rx_bind2dev_ifindex == CI_IFID_BAD ||
                                 ci_sock_intf_check(ni, s, intf_i, vlan))) )
        if( callback(s, callback_arg) != 0 )
          return 1;
    }
    else if( id == EMPTY )
      break;
    /* We defer calculating hash2 until it's needed, just to make the fast
    ** case that little bit faster. */
    if( hash1 == first )
      hash2 = ip6_lookup_hash2(laddr_ptr, lport, raddr_ptr, rport, protocol);
    hash1 = (hash1 + hash2) & table_size_mask;
    if( hash1 == first ) {
      LOG_NV(ci_log(FN_FMT "ITERATE FULL " IPX_PORT_FMT "->"
                    IPX_PORT_FMT " hash=%u:%u",
                    FN_PRI_ARGS(ni), IPX_ARG(AF_IP(laddr)), lport,
                    IPX_ARG(AF_IP(raddr)), rport, hash1, hash2));
      break;
    }
  }
  return 0;
}


int
ci_ip6_netif_filter_insert(ci_ip6_netif_filter_table* tbl,
                           ci_netif* netif, oo_sp tcp_id,
                           const ci_addr_t laddr, unsigned lport,
                           const ci_addr_t raddr, unsigned rport,
                           unsigned protocol)
{
  ci_ip6_netif_filter_table_entry* entry;
  unsigned hash1, hash2;
#if !defined(NDEBUG) || CI_CFG_STATS_NETIF
  unsigned hops = 1;
#endif
  unsigned first, table_size_mask;

  ci_assert(netif);
  ci_assert(ci_netif_is_locked(netif));

  table_size_mask = tbl->table_size_mask;

  hash1 = onload_hash1(table_size_mask, laddr, lport,
                       raddr, rport, protocol);
  hash2 = onload_hash2(laddr, lport, raddr, rport, protocol);
  first = hash1;

  /* Find a free slot. */
  while( 1 ) {
    entry = &tbl->table[hash1];
    if( entry->id < 0 )  break;

    ++entry->route_count;
#if !defined(NDEBUG) || CI_CFG_STATS_NETIF
    ++hops;
#endif

    hash1 = (hash1 + hash2) & table_size_mask;

    if( hash1 == first ) {
      ci_sock_cmn *s = SP_TO_SOCK_CMN(netif, tcp_id);
      if( ! (s->s_flags & CI_SOCK_FLAG_SW_FILTER_FULL) ) {
        LOG_E(ci_log(FN_FMT "%d FULL %s " IPX_PORT_FMT "->" IPX_PORT_FMT
                     " hops=%u", FN_PRI_ARGS(netif),
                     OO_SP_FMT(tcp_id), CI_IP_PROTOCOL_STR(protocol),
                     IPX_ARG(AF_IP(laddr)), (unsigned) CI_BSWAP_BE16(lport),
                     IPX_ARG(AF_IP(raddr)), (unsigned) CI_BSWAP_BE16(rport),
                     hops));
        s->s_flags |= CI_SOCK_FLAG_SW_FILTER_FULL;
      }

      CITP_STATS_NETIF_INC(netif, sw_filter_insert_table_full);
      return -ENOBUFS;
    }
  }

  /* Now insert the new entry. */
  LOG_TC(ci_log(FN_FMT "%d INSERT %s " IPX_PORT_FMT "->" IPX_PORT_FMT
                " hash=%u:%u at=%u "
		"over=%d hops=%u", FN_PRI_ARGS(netif), OO_SP_FMT(tcp_id),
                CI_IP_PROTOCOL_STR(protocol),
		IPX_ARG(AF_IP(laddr)), (unsigned) CI_BSWAP_BE16(lport),
		IPX_ARG(AF_IP(raddr)), (unsigned) CI_BSWAP_BE16(rport),
		first, hash2, hash1, entry->id, hops));

#if CI_CFG_STATS_NETIF
  if( hops > netif->state->stats.ipv6_table_max_hops )
    netif->state->stats.ipv6_table_max_hops = hops;
  /* Keep a rolling average of the number of hops per entry. */
  if( netif->state->stats.ipv6_table_mean_hops == 0 )
    netif->state->stats.ipv6_table_mean_hops = 1;
  netif->state->stats.ipv6_table_mean_hops =
    (netif->state->stats.ipv6_table_mean_hops * 9 + hops) / 10;

  if( entry->id == EMPTY )
    ++netif->state->stats.ipv6_table_n_slots;
  ++netif->state->stats.ipv6_table_n_entries;
#endif
  entry->id = OO_SP_TO_INT(tcp_id);
  memcpy(entry->laddr, laddr.ip6, sizeof(entry->laddr));
  return 0;
}

static void
__ci_ip6_netif_filter_remove(ci_ip6_netif_filter_table* tbl, ci_netif* ni,
                             unsigned hash1, unsigned hash2,
                             int hops, unsigned last_tbl_i)
{
  ci_ip6_netif_filter_table_entry* entry;
  unsigned tbl_i, table_size_mask;
  int i;

  table_size_mask = tbl->table_size_mask;

  tbl_i = hash1;
  for( i = 0; i < hops; ++i ) {
    entry = &tbl->table[tbl_i];
    ci_assert(entry->id != EMPTY);
    ci_assert(entry->route_count > 0);
    if( --entry->route_count == 0 && entry->id == TOMBSTONE ) {
      CITP_STATS_NETIF(--ni->state->stats.ipv6_table_n_slots);
      entry->id = EMPTY;
    }
    tbl_i = (tbl_i + hash2) & table_size_mask;
  }
  ci_assert(tbl_i == last_tbl_i);

  CITP_STATS_NETIF(--ni->state->stats.ipv6_table_n_entries);
  entry = &tbl->table[tbl_i];
  if( entry->route_count == 0 ) {
    CITP_STATS_NETIF(--ni->state->stats.ipv6_table_n_slots);
    entry->id = EMPTY;
  }
  else {
    entry->id = TOMBSTONE;
  }
}

void
ci_ip6_netif_filter_remove(ci_ip6_netif_filter_table* tbl,
                           ci_netif* netif, oo_sp sock_p,
                           const ci_addr_t laddr, unsigned lport,
                           const ci_addr_t raddr, unsigned rport,
                           unsigned protocol)
{
  ci_ip6_netif_filter_table_entry* entry;
  unsigned hash1, hash2, tbl_i;
  int hops = 0;
  unsigned first, table_size_mask;

  ci_assert(ci_netif_is_locked(netif)
#ifdef __KERNEL__
            /* release_ep_tbl might be called without the stack lock.
             * Do not complain about this. */
            || (netif2tcp_helper_resource(netif)->k_ref_count &
                TCP_HELPER_K_RC_DEAD)
#endif
            );

  table_size_mask = tbl->table_size_mask;

  hash1 = onload_hash1(table_size_mask, laddr, lport,
                       raddr, rport, protocol);
  hash2 = onload_hash2(laddr, lport, raddr, rport, protocol);
  first = hash1;

  LOG_TC(ci_log("%s: [%d:%d] REMOVE %s " IPX_PORT_FMT "->" IPX_PORT_FMT
                " hash=%u:%u", __FUNCTION__, NI_ID(netif), OO_SP_FMT(sock_p),
                CI_IP_PROTOCOL_STR(protocol),
                IPX_ARG(AF_IP(laddr)), (unsigned) CI_BSWAP_BE16(lport),
                IPX_ARG(AF_IP(raddr)), (unsigned) CI_BSWAP_BE16(rport),
		            hash1, hash2));

  tbl_i = hash1;
  while( 1 ) {
    entry = &tbl->table[tbl_i];
    if( entry->id == OO_SP_TO_INT(sock_p) ) {
      if( !memcmp(laddr.ip6, entry->laddr, sizeof(entry->laddr)) )
        break;
    }
    else if( entry->id == EMPTY ) {
      /* We allow multiple removes of the same filter -- helps avoid some
       * complexity in the filter module.
       */
      return;
    }
    tbl_i = (tbl_i + hash2) & table_size_mask;
    ++hops;
    if( tbl_i == first ) {
      LOG_E(ci_log(FN_FMT "ERROR: LOOP [%d] %s " IPX_PORT_FMT "->" IPX_PORT_FMT,
                   FN_PRI_ARGS(netif), OO_SP_FMT(sock_p),
                   CI_IP_PROTOCOL_STR(protocol),
                   IPX_ARG(AF_IP(laddr)), (unsigned) CI_BSWAP_BE16(lport),
                   IPX_ARG(AF_IP(raddr)), (unsigned) CI_BSWAP_BE16(rport)));
      return;
    }
  }

  __ci_ip6_netif_filter_remove(tbl, netif, hash1, hash2, hops, tbl_i);
}

#ifdef __ci_driver__

void ci_ip6_netif_filter_init(ci_ip6_netif_filter_table* tbl, int size_lg2)
{
  unsigned i;
  unsigned size = ci_pow2(size_lg2);

  ci_assert(tbl);
  ci_assert_gt(size_lg2, 0);
  ci_assert_le(size_lg2, 32);

  tbl->table_size_mask = size - 1;

  for( i = 0; i < size; ++i ) {
    tbl->table[i].id = EMPTY;
    tbl->table[i].route_count = 0;
    memset(tbl->table[i].laddr, 0, sizeof(tbl->table[i].laddr));
  }
}

#endif /* __ci_driver__ */

int
__ci_ip6_netif_filter_lookup(ci_netif* netif,
                             ci_addr_t laddr, unsigned lport,
                             ci_addr_t raddr, unsigned rport,
                             unsigned protocol)
{
  int rc;

  /* try full lookup */
  rc = ci_ip6_netif_filter_lookup(netif, laddr, lport,  raddr, rport, protocol);
  LOG_NV(log(LPF "FULL LOOKUP " IPX_PORT_FMT "->" IPX_PORT_FMT " rc=%d",
             IPX_ARG(AF_IP(laddr)), CI_BSWAP_BE16(lport),
             IPX_ARG(AF_IP(raddr)), CI_BSWAP_BE16(rport), rc));
  if(CI_LIKELY( rc >= 0 ))
    return rc;

  /* try wildcard lookup */
  rc = ci_ip6_netif_filter_lookup(netif, laddr, lport, addr_any, 0, protocol);
  LOG_NV(log(LPF "WILD LOOKUP " IPX_PORT_FMT "->"IPX_PORT_FMT" rc=%d",
             IPX_ARG(AF_IP(laddr)), CI_BSWAP_BE16(lport),
             IPX_ARG(AF_IP(addr_any)), 0, rc));
  if(CI_LIKELY( rc >= 0 ))
    return rc;

  return -ENOENT;
}

void ci_ip6_netif_filter_dump(ci_netif* ni)
{
  int id;
  unsigned i;
  ci_ip6_netif_filter_table* ip6_tbl;

  ci_assert(ni);
  ip6_tbl = ni->ip6_filter_table;

  log("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
#if CI_CFG_STATS_NETIF
  log(FN_FMT "size=%d n_entries=%i n_slots=%i max=%i mean=%i", FN_PRI_ARGS(ni),
      ip6_tbl->table_size_mask + 1, ni->state->stats.ipv6_table_n_entries,
      ni->state->stats.ipv6_table_n_slots, ni->state->stats.ipv6_table_max_hops,
      ni->state->stats.ipv6_table_mean_hops);
#endif

  for( i = 0; i <= ip6_tbl->table_size_mask; ++i ) {
    id = ip6_tbl->table[i].id;
    if( CI_LIKELY(id >= 0) ) {
      ci_sock_cmn* s = ID_TO_SOCK(ni, id);
      ci_addr_t laddr = CI_ADDR_FROM_IP6(&ip6_tbl->table[i].laddr);
      int lport = sock_lport_be16(s);
      ci_addr_t raddr = sock_raddr(s);
      int rport = sock_rport_be16(s);
      int protocol = sock_protocol(s);
      unsigned hash1 = onload_hash1(ip6_tbl->table_size_mask,
                                    laddr, lport, raddr, rport,
                                    protocol);
      unsigned hash2 = onload_hash2(laddr, lport,
                                    raddr, rport, protocol);

      log("%010d id=%-10d rt_ct=%d %s %s:%d %s:%d %010u:%010u",
          i, id, ip6_tbl->table[i].route_count, CI_IP_PROTOCOL_STR(protocol),
          AF_IP(laddr), CI_BSWAP_BE16(lport), AF_IP(raddr),
          CI_BSWAP_BE16(rport), hash1, hash2);
    }
  }
}

#endif /* CI_CFG_IPV6 */
