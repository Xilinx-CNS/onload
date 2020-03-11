/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  UDP internals
**   \date  2008/09/26
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
#ifndef __UDP_INTERNAL_H__
#define __UDP_INTERNAL_H__

#include <onload/sleep.h>

struct ci_udp_rx_deliver_state {
  ci_netif*      ni;
  ci_ip_pkt_fmt* pkt;
  int            delivered;
  int            queued;
};


struct ci_udp_rx_future {
  ci_udp_state* socket;
};

extern int ci_udp_rx_deliver(ci_sock_cmn*, void*) CI_HF;


/* Filter handler for delivery of a future packet. If the packet is to be
 * delivered to this socket, and no others, store it for delivery once the
 * packet is complete.
 *
 * A possible enhancement would be to store multiple sockets, rather than
 * falling back to running the filters again on the complete packet.
 */
ci_inline int ci_udp_rx_deliver_to_future(ci_sock_cmn* s, void* opaque_arg)
{
  struct ci_udp_rx_future* future = opaque_arg;
  ci_udp_state* us = SOCK_TO_UDP(s);

  if( ci_udp_recv_q_pkts(&us->recv_q) >= us->stats.max_recvq_pkts ||
      future->socket != NULL ) {
    future->socket = NULL;
    return 1;
  }

  future->socket = us;
  return 0; /* Keep going to see if there are multiple sockets. */
}


/* Handle an incomplete future packet, trying to determine the target socket. */
ci_inline void ci_udp_handle_rx_pre_future(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                           ci_udp_hdr* udp, int ip_paylen,
                                           ci_uint16 ether_type,
                                           struct ci_udp_rx_future* future)
{
  ci_ip4_hdr* ip4_hdr = oo_ip_hdr(pkt);
  ci_addr_t daddr, saddr;
  int dealt_with;

  ASSERT_VALID_PKT(ni, pkt);
  future->socket = NULL;

  /* Only handling IP4 for now */
  if( ether_type != CI_ETHERTYPE_IP ||
      ni->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL )
    return;

  ci_assert_equal(ip4_hdr->ip_protocol, IPPROTO_UDP);

  pkt->pf.udp.pay_len = CI_BSWAP_BE16(udp->udp_len_be16);
  if( (pkt->pf.udp.pay_len < sizeof(ci_udp_hdr)) |
      (pkt->pf.udp.pay_len > ip_paylen) )
    return;
  pkt->pf.udp.pay_len -= sizeof(ci_udp_hdr);

  daddr = CI_ADDR_FROM_IP4(ip4_hdr->ip_daddr_be32);
  saddr = CI_ADDR_FROM_IP4(ip4_hdr->ip_saddr_be32);

  dealt_with =
    ci_netif_filter_for_each_match(ni,
                                   daddr.ip4, udp->udp_dest_be16,
                                   saddr.ip4, udp->udp_source_be16,
                                   IPPROTO_UDP, pkt->intf_i, pkt->vlan,
                                   ci_udp_rx_deliver_to_future, future, NULL);
  if( ! dealt_with )
    ci_netif_filter_for_each_match(ni,
                                   daddr.ip4, udp->udp_dest_be16, 0, 0,
                                   IPPROTO_UDP, pkt->intf_i, pkt->vlan,
                                   ci_udp_rx_deliver_to_future, future, NULL);

  if( future->socket != NULL )
    CI_UDP_STATS_INC_IN_DGRAMS(ni);
}


/* Roll back a failed future packet, forgetting the target socket. */
ci_inline void ci_udp_rollback_rx_future(ci_netif* ni,
                                         struct ci_udp_rx_future* future)
{
  if( future->socket != NULL )
    __CI_NETIF_STATS_DEC(ni, udp, udp_in_dgrams);
  future->socket = NULL;
}


/* Handle a complete future packet. If we were able to determine a target
 * socket, we can deliver it straight there.
 */
ci_inline void ci_udp_handle_rx_post_future(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                            ci_udp_hdr* udp, int ip_paylen,
                                            struct ci_udp_rx_future* future)
{
  ci_udp_state* us = future->socket;
  if( us != NULL ) {
    ci_assert_nflags(pkt->rx_flags, CI_PKT_RX_FLAG_KEEP);
    ci_assert_gt(pkt->pay_len, ip_paylen);

    oo_offbuf_set_start(&pkt->buf, udp + 1);
    ci_udp_recv_q_put(ni, &us->recv_q, pkt);
    us->s.b.sb_flags |= CI_SB_FLAG_RX_DELIVERED;
    ci_netif_put_on_post_poll(ni, &us->s.b);
    ci_udp_wake(ni, us, CI_SB_FLAG_WAKE_RX);
  }
  else {
    ci_udp_handle_rx(ni, pkt, udp, ip_paylen);
  }
}


#endif  /* __UDP_INTERNAL_H__ */
