/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  ds
**  \brief  Header file for ip_tx.c
**   \date  2005/09/20
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal_ip_tx */

#ifndef __CI_INTERNAL_IP_TX_H__
#define __CI_INTERNAL_IP_TX_H__

#include <ci/internal/ip.h>
#include "netif_tx.h"


/* Send packet to the IP layer.
 *
 * This function is used when sending packets that are not part of the
 * normal "stream" of packets associated with a socket.  It is assumed that
 * the caller has already filled in the source and dest IP addresses and
 * (if applicable) port numbers.
 *
 * If [sock_cp_opt] is provided then it is used only for the
 * SO_BINDTODEVICE and IP_MULTICAST_IF options.  The source IP and port in
 * [sock_cp_opt] are ignored, and rather are taken from the packet headers.
 */
extern int ci_ip_send_pkt(ci_netif* ni,
                          const struct oo_sock_cplane* sock_cp_opt,
                          ci_ip_pkt_fmt* pkt) CI_HF;


/* Defer send to the OS.
 *
 * This function is used when onload is missing the necessary information
 * to send this packet.
 */
extern void
ci_ip_send_pkt_defer(ci_netif* ni, const struct oo_sock_cplane* sock_cp,
                     cicpos_retrieve_rc_t retrieve_rc, ci_uerr_t* ref_os_rc,
                     ci_ip_pkt_fmt* pkt, const ci_ip_cached_hdrs* ipcache);


/* Do control plane lookup to send [pkt], but don't actually send it.  This
 * is a subset of ci_ip_send_pkt(), and is needed when information from the
 * control plane lookup is needed before sending.
 *
 * [ipcache] points to storage provided by caller, and need not be
 * initialised by the caller.  [sock_cp_opt] is used as described in
 * ci_ip_send_pkt().
 */
extern void ci_ip_send_pkt_lookup(ci_netif* ni,
                                  const struct oo_sock_cplane* sock_cp_opt,
                                  ci_ip_pkt_fmt* pkt,
                                  ci_ip_cached_hdrs* ipcache) CI_HF;

/* Second half of split version of ci_ip_send_pkt(). */
extern int
ci_ip_send_pkt_send(ci_netif* ni, const struct oo_sock_cplane* sock_cp_opt,
                    ci_ip_pkt_fmt* pkt, const ci_ip_cached_hdrs* ipcache) CI_HF;

/* Send the [pkt] via loopback from socket [s] to socket [dst].
 */
ci_inline void ci_ip_local_send(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                oo_sp src, oo_sp dst)
{
  ci_assert(ci_netif_is_locked(ni));
  pkt->pf.tcp_tx.lo.tx_sock = src;
  pkt->pf.tcp_tx.lo.rx_sock = dst;
  if( OO_SP_IS_NULL(pkt->pf.tcp_tx.lo.rx_sock) ) {
    ci_netif_pkt_release(ni, pkt);
    /* Fixme: it should not happen at all, but it happens. */
    return;
  }
  LOG_NT(ci_log("%d:%d loopback TX pkt %d to %d", NI_ID(ni), OO_SP_FMT(src),
                OO_PKT_FMT(pkt), OO_SP_FMT(dst)));
  pkt->next = ni->state->looppkts;
  ni->state->looppkts = OO_PKT_P(pkt);
  ni->state->n_looppkts++;
  ni->state->poll_work_outstanding = 1;
}

ci_inline void
ci_ip_set_mac_and_port(ci_netif* ni, const ci_ip_cached_hdrs* ipcache,
                       ci_ip_pkt_fmt* pkt)
{
  ci_uint16 ether_type = ipcache->ether_type;
  ci_assert(ether_type == CI_ETHERTYPE_IP || ether_type == CI_ETHERTYPE_IP6);
  oo_tx_pkt_layout_update(pkt, ipcache->ether_offset);
  memcpy(oo_tx_ether_hdr(pkt), ci_ip_cache_ether_hdr(ipcache),
         oo_tx_ether_hdr_size(pkt));
  pkt->intf_i = ipcache->intf_i;
#if CI_CFG_PORT_STRIPING
  /* ?? FIXME: This code assumes that the two ports we're striping over
   * have macs that differ only in the bottom bit (both local and remote).
   */
  pkt->intf_i ^= pkt->netif.tx.intf_swap;
  oo_ether_dhost(pkt)[5]  ^= pkt->netif.tx.intf_swap;
  oo_ether_shost(pkt)[5]  ^= pkt->netif.tx.intf_swap;
#endif
  ci_assert_equal(oo_tx_ether_type_get(pkt), ether_type);
  if( ether_type == CI_ETHERTYPE_IP )
    ci_assert_equal(CI_IP4_IHL(oo_tx_ip_hdr(pkt)), sizeof(ci_ip4_hdr));
}


extern void ci_ip_send_tcp_slow(ci_netif*, ci_tcp_state*, ci_ip_pkt_fmt*)CI_HF;


ci_inline void
__ci_ip_send_tcp(ci_netif* ni, ci_ip_pkt_fmt* pkt, ci_tcp_state* ts)
{
#if CI_CFG_IPV6
  if( ipcache_af(&ts->s.pkt) == AF_INET )
    pkt->flags &=~ CI_PKT_FLAG_IS_IP6;
  else
    pkt->flags |= CI_PKT_FLAG_IS_IP6;
#endif
  if( ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE ) {
    ci_netif_pkt_hold(ni, pkt);
    ci_ip_local_send(ni, pkt, S_SP(ts), ts->local_peer);
    return;
  }
  if(CI_LIKELY( ts->s.pkt.status == retrrc_success &&
                oo_cp_ipcache_is_valid(ni, &ts->s.pkt) )) {
    ci_ip_set_mac_and_port(ni, &ts->s.pkt, pkt);
    ci_netif_pkt_hold(ni, pkt);
    ci_netif_send(ni, pkt);
  }
  else {
    cicp_user_retrieve(ni, &ts->s.pkt, &ts->s.cp);
    ci_ip_send_tcp_slow(ni, ts, pkt);
  }
}


ci_inline void
ci_ip_send_tcp(ci_netif *ni, ci_ip_pkt_fmt *pkt, ci_tcp_state *ts)
{
#if CI_CFG_PORT_STRIPING
  pkt->netif.tx.intf_swap = 0;
#endif
  __ci_ip_send_tcp(ni, pkt, ts);
}


#endif /* __CI_INTERNAL_IP_TX_H__ */
/*! \cidoxg_end */
