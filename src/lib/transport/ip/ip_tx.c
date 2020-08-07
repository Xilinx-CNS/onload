/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ds
**  \brief  IP transmit
**   \date  2004/05/25
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include "ip_tx.h"
#include <ci/tools/pktdump.h>


#if OO_DO_STACK_POLL
void ci_ip_send_pkt_lookup(ci_netif* ni,
                           const struct oo_sock_cplane* sock_cp_opt,
                           ci_ip_pkt_fmt* pkt,
                           ci_ip_cached_hdrs* ipcache)
{
  int af = ipcache_af(ipcache);
  struct oo_sock_cplane sock_cp;

  if( sock_cp_opt != NULL )
    sock_cp = *sock_cp_opt;
  else
    oo_sock_cplane_init(&sock_cp);

  sock_cp.laddr = TX_PKT_SADDR(af,pkt);

  ci_assert(!CI_IPX_ADDR_IS_ANY(TX_PKT_SADDR(af, pkt)));
  ci_assert(!CI_IPX_ADDR_IS_ANY(TX_PKT_DADDR(af, pkt)));
  ci_ipcache_set_daddr(ipcache, TX_PKT_DADDR(af, pkt));

  switch( TX_PKT_PROTOCOL(af, pkt) ) {
  case IPPROTO_UDP:
  case IPPROTO_TCP:
    sock_cp.lport_be16 = TX_PKT_SPORT_BE16(pkt);
    ipcache->dport_be16 = TX_PKT_DPORT_BE16(pkt);
    break;
  default:
    sock_cp.lport_be16 = 0;
    ipcache->dport_be16 = 0;
    break;
  }

  cicp_user_retrieve(ni, ipcache, &sock_cp);
}


void ci_ip_send_pkt_defer(ci_netif* ni, const struct oo_sock_cplane* sock_cp,
                          cicpos_retrieve_rc_t retrieve_rc,
                          ci_uerr_t *ref_os_rc, ci_ip_pkt_fmt* pkt,
                          const ci_ip_cached_hdrs *ipcache)
{
  struct oo_deferred_pkt* dpkt;
  ci_ni_dllist_link* lnk;
  ci_assert_equal(retrieve_rc, retrrc_nomac);

  /* The upper layers think that the packet is in-flight and the NIC owns
   * it.  We pretend to be that NIC, so we take the reference.
   * tx_pkt_complete functions will drop this reference. */
  ci_netif_pkt_hold(ni, pkt);
  /* This packet should looks as in-flight for all other code, for example
   * for TCP code which tries to retransmit packets. */
  pkt->flags |= CI_PKT_FLAG_TX_PENDING;

  if( ci_ni_dllist_is_empty(ni, &ni->state->deferred_list_free) ) {
    CITP_STATS_NETIF_INC(ni, tx_defer_pkt_drop_limited);
    cicp_pkt_complete_fake(ni, pkt);
    return;
  }
  lnk = ci_ni_dllist_pop(ni, &ni->state->deferred_list_free);

  /* Ensure the pkt is ready to send */
  ci_assert_equal(pkt->intf_i, ipcache->intf_i);

  /* Store all the data in the deferred packets queue */
  dpkt = CI_CONTAINER(struct oo_deferred_pkt, link, lnk);
  dpkt->pkt_id = pkt->pp;
  dpkt->src = ipcache_laddr(ipcache);
  if( ni->cplane_init_net != NULL && sock_cp != NULL &&
      ipcache_protocol(ipcache) == IPPROTO_TCP ) {
    ci_addr_sh_t laddr = CI_ADDR_SH_FROM_ADDR(dpkt->src);
    ci_uint16 lport = sock_cp->lport_be16;
    /* We ignore failure returns from cp_svc_check_dnat().  In the event that
     * it fails, it leaves the address untranslated, which is the best that
     * we can do. */
    if( cp_svc_check_dnat(ni->cplane_init_net, &laddr, &lport) > 0 )
      dpkt->src = CI_ADDR_FROM_ADDR_SH(laddr);
  }
  dpkt->nexthop = ipcache->nexthop;
  dpkt->ifindex = ipcache->ifindex;
  dpkt->flag = OO_DEFERRED_FLAG_FIRST;
  if( IS_AF_INET6(ipcache_af(ipcache)) )
    dpkt->flag |= OO_DEFERRED_FLAG_IS_IPV6;
  if( ipcache->fwd_ver_init_net.id != CICP_MAC_ROWID_UNUSED ) {
    dpkt->ver = ipcache->fwd_ver_init_net;
    dpkt->iif_ifindex = ipcache->iif_ifindex;
    ci_assert_nequal(dpkt->iif_ifindex, CI_IFID_BAD);
  }
  else {
    dpkt->ver = ipcache->fwd_ver;
    dpkt->iif_ifindex = CI_IFID_BAD;
  }
  dpkt->ts = ci_ip_time_now(ni);

  /* We do not have the MAC table available for Onload, so we use the FWD
   * cache instead.  Kick off next hop resolution. */
  if( oo_deferred_send_one(ni, dpkt) ) {
    ci_ni_dllist_put(ni, &ni->state->deferred_list_free, &dpkt->link);
    CITP_STATS_NETIF_INC(ni, tx_defer_pkt_fast);
    return;
  }

  ci_ni_dllist_put(ni, &ni->state->deferred_list, &dpkt->link);
  ef_eplock_holder_set_flag(&ni->state->lock,
                            CI_EPLOCK_NETIF_HAS_DEFERRED_PKTS);
  CITP_STATS_NETIF_INC(ni, tx_defer_pkt);
}


int ci_ip_send_pkt_send(ci_netif* ni, const struct oo_sock_cplane* sock_cp,
                        ci_ip_pkt_fmt* pkt, const ci_ip_cached_hdrs* ipcache)
{
  int os_rc = 0;

  switch( ipcache->status ) {
  case retrrc_success:
    ci_ip_set_mac_and_port(ni, ipcache, pkt);
    ci_netif_pkt_hold(ni, pkt);
    ci_netif_send(ni, pkt);
    return 0;
  case retrrc_nomac:
    ci_ip_set_mac_and_port(ni, ipcache, pkt);
    ci_ip_send_pkt_defer(ni, sock_cp, retrrc_nomac, &os_rc, pkt, ipcache);
    return 0;
  case retrrc_noroute:
    return -EHOSTUNREACH;
  case retrrc_alienroute:
    return -ENETUNREACH;
  case retrrc_localroute:
    if( ipcache->flags & CI_IP_CACHE_IS_LOCALROUTE )
        ci_assert(0);
    /* fall through */
  default:
    if( ipcache->status < 0 )
      return ipcache->status;
    else
      /* belt and braces... */
      return 0;
  }
}


int ci_ip_send_pkt(ci_netif* ni, const struct oo_sock_cplane* sock_cp_opt,
                   ci_ip_pkt_fmt* pkt)
{
  ci_ip_cached_hdrs ipcache;
  ci_ip_cache_init(&ipcache, oo_pkt_af(pkt));
  ci_ip_send_pkt_lookup(ni, sock_cp_opt, pkt, &ipcache);
  return ci_ip_send_pkt_send(ni, sock_cp_opt, pkt, &ipcache);
}


void ci_ip_send_tcp_slow(ci_netif* ni, ci_tcp_state* ts, ci_ip_pkt_fmt* pkt)
{
  /* We're here because the ipcache is not valid. */
  int rc, prev_mtu = ts->s.pkt.mtu;

  if(CI_UNLIKELY( ! oo_cp_ipcache_is_valid(ni, &ts->s.pkt) )) {
    cicp_user_retrieve(ni, &ts->s.pkt, &ts->s.cp);
  }

  /* For success and nomac cases, we have to update various
   * packet meta-data */
  if( ts->s.pkt.mtu != prev_mtu )
    ci_tcp_tx_change_mss(ni, ts);
  ci_ip_set_mac_and_port(ni, &ts->s.pkt, pkt);

  if( ts->s.pkt.status == retrrc_success ) {
    ci_netif_pkt_hold(ni, pkt);
    ci_netif_send(ni, pkt);
    return;
  }
  else if( ts->s.pkt.status == retrrc_localroute &&
           (ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE) ) {
    ci_netif_pkt_hold(ni, pkt);
    ci_ip_local_send(ni, pkt, S_SP(ts), OO_SP_NULL);
  }

  switch( ts->s.pkt.status ) {
  case retrrc_nomac:
    rc = 0;
    /* If we resend SYN, and there is no MAC - it means ARP failed.
     * Connect() should return with EHOSTUNREACH.
     * We verify twice - on the first and the second retransmit.
     * Very hackish.
     */
    if( ts->s.b.state == CI_TCP_SYN_SENT ) {
      if( ts->retransmits == 1 )
        ts->tcpflags |= CI_TCPT_FLAG_NO_ARP;
      else if( (ts->tcpflags & CI_TCPT_FLAG_NO_ARP) &&
               ts->retransmits == 2 ) {
        ci_tcp_drop(ni, ts, EHOSTUNREACH);
        return;
      }
    }
    ++ts->stats.tx_nomac_defer;
    ci_ip_send_pkt_defer(ni, &ts->s.cp, ts->s.pkt.status, &rc, pkt, &ts->s.pkt);

    /* For TCP, we want the ipcache to only be valid when onloadable.
     * But ci_ip_send_pkt_defer() uses ipcache verinfo if available. */
    ci_ip_cache_invalidate(&ts->s.pkt);

    return;
  case retrrc_alienroute:
  case retrrc_localroute:
  case retrrc_noroute:
    rc = -EHOSTUNREACH;
    CITP_STATS_NETIF_INC(ni, tcp_send_fail_noroute);
    break;
  default:
    ci_assert_lt(ts->s.pkt.status, 0);
    if( ts->s.pkt.status < 0 )
      rc = ts->s.pkt.status;
    else
      /* belt and braces... */
      rc = 0;
  }

  ci_assert_le(rc, 0);

  /* For TCP, we want the ipcache to only be valid when onloadable. */
  ci_ip_cache_invalidate(&ts->s.pkt);

  /* In most cases, we should ignore return code; the packet will be resend
   * later, because of RTO.  However, in SYN-SENT we should pass errors to
   * user.  At the same time, we should not pass ENOBUFS to user - it is
   * pretty internal problem of cplane, so we should try again.  Possibly,
   * there may be other internal problems, such as ENOMEM.
   *
   * Also, do not break connection when the first SYN fails:
   * - Linux does not do it;
   * - cplane has some latency, so we have false positives here;
   * - ci_tcp_connect() does not expect it.
   */
  if( ts->s.b.state == CI_TCP_SYN_SENT && rc < 0 && ts->retransmits > 0 &&
      (rc == -EHOSTUNREACH || rc == -ENETUNREACH || rc == -ENETDOWN) )
    ci_tcp_drop(ni, ts, -rc);
  /* N.B. Packet lifetime here is subtle, and changes to this code should be
   * checked carefully in order to avoid introducing packet leaks. */
}

#if CI_CFG_IPV6
ci_uint32 ci_make_flowlabel(ci_netif* ni, ci_addr_t saddr, ci_uint16 sport,
                            ci_addr_t daddr, ci_uint16 dport, ci_uint8 proto)
{
  ci_uint32 hash, hash_salt;
  memcpy(&hash_salt, ni->state->hash_salt, sizeof(hash_salt));
  hash = onload_hash3(saddr, sport, daddr, dport, proto ^ hash_salt);
  return hash & CI_IP6_FLOWLABEL_MASK;
}

ci_uint32 ci_ipcache_make_flowlabel(ci_netif* ni, ci_ip_cached_hdrs* ipcache)
{
  return ci_make_flowlabel(ni, ipcache_laddr(ipcache),
      ipcache_lport_be16(ipcache), ipcache_raddr(ipcache),
      ipcache_rport_be16(ipcache), ipcache_protocol(ipcache));
}

void ci_ipcache_update_flowlabel(ci_netif* ni, ci_sock_cmn* s)
{
  if( ipcache_is_ipv6(&s->pkt) && s->s_flags & CI_SOCK_FLAG_AUTOFLOWLABEL_REQ &&
      ci_ip6_flowlabel_be32(&s->pkt.ipx.ip6) == 0 )
    ci_ip6_set_flowlabel_be32(&s->pkt.ipx.ip6, ci_ipcache_make_flowlabel(ni, &s->pkt));
}
#endif

#endif
/*! \cidoxg_end */
