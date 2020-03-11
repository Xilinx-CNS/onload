/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __TCP_RX_H__
#define __TCP_RX_H__

#include <onload/sleep.h>


ci_inline void ci_tcp_rx_set_isn(ci_tcp_state* ts, unsigned isn)
{
  ci_assert_equal(tcp_rcv_usr(ts), 0);
  ts->stats.rx_isn = isn;
  tcp_rcv_nxt(ts) = isn;
  ts->rcv_added = ts->rcv_delivered = isn;
}


ci_inline int ci_tcp_need_ack(ci_netif* ni, ci_tcp_state* ts)
{
  /* - More than [delack_thresh] ACKs have been requested, 
   *
   * - Right edge has moved significantly.  (This breaks RFC, but
   * reduces ack rate (and linux behaves like this).
   *
   * - We're in fast-start.
   */
  return 
#if CI_CFG_DYNAMIC_ACK_RATE 
    /* We only need to look at dynack_thresh, not also delack_thresh,
     * because we know dynack_thresh >= delack_thresh, and they are
     * equal if that feature is disabled
     */
    ((ts->acks_pending & CI_TCP_ACKS_PENDING_MASK) > NI_OPTS(ni).dynack_thresh)
#else
    ((ts->acks_pending & CI_TCP_ACKS_PENDING_MASK) > NI_OPTS(ni).delack_thresh)
#endif
    || ( SEQ_GE(ts->rcv_delivered + ts->rcv_window_max,
                ts->rcv_wnd_right_edge_sent+ci_tcp_ack_trigger_delta(ts)) |
         (ci_tcp_is_in_faststart(ts)                                    ) );
}


ci_inline void ci_tcp_rx_post_poll(ci_netif* ni, ci_tcp_state* ts)
{
  LOG_TR(ci_log("%s: "NTS_FMT "acks=%x %s", __FUNCTION__,
                NTS_PRI_ARGS(ni, ts), ts->acks_pending,
                ci_tcp_sendq_not_empty(ts) ? " SENDQ":""));

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ts->s.b.sb_flags & CI_SB_FLAG_TCP_POST_POLL);

  ts->s.b.sb_flags &=~ CI_SB_FLAG_TCP_POST_POLL;

  if( ci_tcp_sendq_not_empty(ts) )
    ci_tcp_tx_advance(ts, ni);

#if CI_CFG_TCP_FASTSTART
  if( ci_tcp_time_now(ni) - ts->t_prev_recv_payload > NI_CONF(ni).tconst_idle ) {
    if( ts->tcpflags & CI_TCPT_FLAG_NO_QUICKACK )
      ts->tcpflags &=~ CI_TCPT_FLAG_NO_QUICKACK;
    else
      ts->faststart_acks = NI_OPTS(ni).tcp_faststart_idle;
  }
  ts->t_prev_recv_payload = ts->t_last_recv_payload;
#endif

  if( ts->acks_pending ) {
#ifndef NDEBUG
    if( TCP_ACK_FORCED(ts) )
      ci_log("%s: "NTS_FMT "ACK_FORCED flag set unexpectedly: %x", 
             __FUNCTION__, NTS_PRI_ARGS(ni, ts), ts->acks_pending);
#endif

    if( OO_SP_NOT_NULL(ts->local_peer) ) {
      if( ts->acks_pending )
        ci_tcp_send_ack_loopback(ni, ts);
      return;
    }
    if( ci_tcp_need_ack(ni, ts) ) {
      ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(ni, 0);
      if(CI_LIKELY( pkt != NULL )) {
        ci_tcp_send_ack(ni, ts, pkt, CI_FALSE);
        return;
      }
    }
#if CI_CFG_DYNAMIC_ACK_RATE
    /* If these values are equal it implies dynamic_ack_rate is off */
    if( NI_OPTS(ni).dynack_thresh > NI_OPTS(ni).delack_thresh) {
      /* If up-to delack_thresh ACK request, then set delack timer as normal
       * If subsequent ACK request, then set delack timer to 1 timer tick
       * (delack soon mode)
       * Otherwise do nothing until timer expires or larger threshold
       * exceeded and ACK is sent
       */
      if( (ts->acks_pending & CI_TCP_ACKS_PENDING_MASK) <= 
          NI_OPTS(ni).delack_thresh )
        ci_tcp_delack_check_and_set(ni, ts);
      else if( !(ts->acks_pending & CI_TCP_DELACK_SOON_FLAG) )
        ci_tcp_delack_soon(ni, ts);
    } else
      ci_tcp_delack_check_and_set(ni, ts);
#else
    ci_tcp_delack_check_and_set(ni, ts);
#endif
  }
}

/* Set send window, both initially at handshake time and later when
 * receiving a new ACK.
 *
 * Caller should check for window shrinkage constraints.
 *
 * Caller must guarantee that ack + wnd >= ts->snd_una (which is
 * always true on fast path so no additional checks should be
 * necessary there).
 */
ci_inline void ci_tcp_set_snd_max(ci_tcp_state *ts, ci_uint32 seq, 
                                  ci_uint32 ack, ci_uint32 wnd)
{
#if CI_CFG_NOTICE_WINDOW_SHRINKAGE
  ts->snd_wl1 = seq;
#endif
  ts->snd_max = ack + wnd;
}

#ifndef __KERNEL__
struct ci_tcp_rx_future {
  ci_sock_cmn* socket;
  ciip_tcp_rx_pkt rxp;
};


ci_inline int ci_tcp_rx_deliver_to_future(ci_sock_cmn* s, void* opaque_arg)
{
  struct ci_tcp_rx_future* future = opaque_arg;
  future->socket = s;
  return 1;
}


ci_inline void ci_tcp_handle_rx_pre_future(ci_netif* netif, ci_ip_pkt_fmt* pkt,
                                           ci_tcp_hdr* tcp, int ip_paylen,
                                           struct ci_tcp_rx_future* future)
{
  ci_ip4_hdr* ip = oo_ip_hdr(pkt);
  future->socket = NULL;

  ci_assert_nequal(pkt->intf_i, OO_INTF_I_LOOPBACK);

  if( ip->ip_frag_off_be16 != CI_IP4_FRAG_DONT &&
      ip->ip_frag_off_be16 != 0 ) {
    return;
  }

  if( OO_PP_NOT_NULL(pkt->frag_next) )
    return;

  future->rxp.ni = netif;
  future->rxp.pkt = pkt;
  future->rxp.tcp = tcp;
  pkt->pf.tcp_rx.pay_len = ip_paylen;

  future->rxp.seq = CI_BSWAP_BE32(tcp->tcp_seq_be32);
  future->rxp.ack = CI_BSWAP_BE32(tcp->tcp_ack_be32);

  ci_netif_filter_for_each_match(netif,
                                 ip->ip_daddr_be32, tcp->tcp_dest_be16,
                                 ip->ip_saddr_be32, tcp->tcp_source_be16,
                                 IPPROTO_TCP, pkt->intf_i, pkt->vlan,
                                 ci_tcp_rx_deliver_to_future, future,
                                 &future->rxp.hash);

  if( future->socket != NULL )
    CI_TCP_STATS_INC_IN_SEGS( netif );
}


ci_inline void ci_tcp_rollback_rx_future(ci_netif* netif,
                                         struct ci_tcp_rx_future* future)
{
  if( future->socket != NULL )
    __CI_NETIF_STATS_DEC(netif, tcp, tcp_in_segs);
  future->socket = NULL;
}

/* We might consider inlining this, or a simplified version */
extern int ci_tcp_rx_deliver_to_conn(ci_sock_cmn* s, void* opaque_arg) CI_HF;

ci_inline void ci_tcp_handle_rx_post_future(ci_netif* netif,
                                            struct ci_netif_poll_state* ps,
                                            ci_ip_pkt_fmt* pkt,
                                            ci_tcp_hdr* tcp,
                                            int ip_paylen,
                                            struct ci_tcp_rx_future* future)
{
  if( future->socket != NULL ) {
    future->rxp.poll_state = ps;
    ci_assert_gt(pkt->pay_len, pkt->pf.tcp_rx.pay_len);
    ci_tcp_rx_deliver_to_conn(future->socket, &future->rxp);
    ci_assert(future->rxp.pkt == NULL);
  }
  else {
    ci_tcp_handle_rx(netif, ps, pkt, tcp, ip_paylen);
  }
}
#endif

#endif  /* __TCP_RX_H__ */
