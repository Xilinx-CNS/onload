/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __TCP_TX_H__
#define __TCP_TX_H__


/*
** Fill out the timestamp option on a given packet
*/
ci_inline int ci_tcp_tx_opt_tso(ci_uint8** opt,
                                ci_uint32 tsval, ci_uint32 tsecr)
{
  *(ci_uint32*)(*opt) = CI_TCP_TSO_WORD;
  *(ci_uint32*)(*opt + 4) = CI_BSWAP_BE32(tsval);
  *(ci_uint32*)(*opt + 8) = CI_BSWAP_BE32(tsecr);
  *opt += 12;
  return 12;
}


/* finish off a transmitted data segment by:
**   - snarfing a timestamp for RTT measurement
**   - timestamps
** could be a place to deal with ECN.
** We could not deal with outgoing SACK here, because it will change packet
** length.
*/
ci_inline void ci_tcp_tx_finish(ci_netif* netif, ci_tcp_state* ts,
                                ci_ip_pkt_fmt* pkt)
{
  ci_tcp_hdr* tcp = TX_PKT_IPX_TCP(ipcache_af(&ts->s.pkt), pkt);
  ci_uint8* opt = CI_TCP_HDR_OPTS(tcp);
  int seq = pkt->pf.tcp_tx.start_seq;

  /* Decrement the faststart counter by the number of bytes acked */
  ci_tcp_reduce_faststart(ts, SEQ_SUB(tcp_rcv_nxt(ts),ts->tslastack));

  /* put in the TSO & SACK options if needed */
  ts->tslastack = tcp_rcv_nxt(ts); /* also used for faststart */
  if( ts->tcpflags & CI_TCPT_FLAG_TSO ) {
    unsigned now =  ci_tcp_time_now(netif);
    ci_tcp_tx_opt_tso(&opt, now, ts->tsrecent);
  } else {
    /* do snarf for RTT timing if not using timestamps */
    if( CI_LIKELY((ts->congstate == CI_TCP_CONG_OPEN) |
                  (ts->congstate == CI_TCP_CONG_NOTIFIED)) ) {
      /* setup new timestamp off this packet
      ** if we are not measuring already */
      if( !SEQ_LE(tcp_snd_una(ts), ts->timed_seq) ) {
        ci_tcp_set_rtt_timing(netif, ts, seq);
      }
    } else {
      /* congested use Karn's algorithm and only measure segments
      ** after the congrecover, anything else must be a retransmit
      */
      if( SEQ_LE(ts->congrecover, seq) &&
          !SEQ_LE(tcp_snd_una(ts), ts->timed_seq) ) {
        /* forward transmission while in recovery so timing possible */
        ci_tcp_set_rtt_timing(netif, ts, seq);
      }
    }
  }

  tcp->tcp_seq_be32 = CI_BSWAP_BE32(seq);
}


ci_inline void ci_tcp_ip_hdr_init(ci_ip4_hdr* ip, unsigned len)
{
  ci_assert_equal(CI_IP4_IHL(ip), sizeof(ci_ip4_hdr));
  ip->ip_tot_len_be16 = CI_BSWAP_BE16((ci_uint16) len);
  ip->ip_check_be16 = 0;
  ip->ip_id_be16 = 0;
}

ci_inline void ci_tcp_ipx_hdr_init(int af, ci_ipx_hdr_t* hdr, unsigned len)
{
#if CI_CFG_IPV6
  if( af == AF_INET6 ) {
    ci_ip6_hdr* ip6 = &hdr->ip6;
    /* Set proper values for payload_len and next_hdr fields of IPv6 header */
    ip6->payload_len = CI_BSWAP_BE16(len - sizeof(ci_ip6_hdr));
    ip6->next_hdr = IPPROTO_TCP;
  } else
#endif
  {
    ci_tcp_ip_hdr_init((ci_ip4_hdr*)hdr, len);
  }
}

ci_inline void __ci_tcp_calc_rcv_wnd(ci_tcp_state* ts, int advance)
{
  /* Calculate receive window, avoiding silly windows and snap-back.
   * Fill-in tcp header window field. */

  int new_window;
  unsigned new_rhs;
  ci_uint16 tmp;
  unsigned delta;

  new_window = CI_MIN(ts->rcv_window_max,
                      ts->s.so.rcvbuf -
                        SEQ_SUB(tcp_rcv_nxt(ts), ts->rcv_delivered));
  new_rhs = tcp_rcv_nxt(ts) + new_window;

  /* Check that the right window edge moves forward by at least the AMSS,
   * as required by RFC1122 silly window avoidance.
   *
   * Do not apply silly window avoidance when we have nothing to read:
   * probably, rcvbuf is too small unless
   * we have pending rob data. Small advances of window will undermine
   * duplicate ACKs (turning them into plain window updates).
   */
  delta = (tcp_rcv_usr(ts) || OO_PP_NOT_NULL(ts->rob.head)) ? ts->amss : 0;

  if( advance &&
      CI_LIKELY( SEQ_GE(new_rhs, ts->rcv_wnd_right_edge_sent + delta) ) ) {
    /* We are ready to move on the window right edge. */
    ts->rcv_wnd_advertised = new_window;
    tcp_rcv_wnd_right_edge_sent(ts) = new_rhs;
  }
  else {
    /* Snapback and silly window avoidance mode: Work out a new window
     * value that keeps the right hand edge constant given the current
     * value of tcp_rcv_nxt.
     */
    new_window = ts->rcv_wnd_right_edge_sent - tcp_rcv_nxt(ts);
    ts->rcv_wnd_advertised = CI_MIN(new_window,
                                    CI_CFG_TCP_MAX_WINDOW << ts->rcv_wscl);
  }

  tmp = ts->rcv_wnd_advertised >> ts->rcv_wscl;
  TS_IPX_TCP(ts)->tcp_window_be16 = CI_BSWAP_BE16(tmp);
  CI_IP_SOCK_STATS_VAL_RXWIN(ts, ts->rcv_wnd_advertised);
}


#define ci_tcp_calc_rcv_wnd(ts, caller)  __ci_tcp_calc_rcv_wnd(ts, CI_TRUE)
#define ci_tcp_calc_rcv_wnd_rx(ts, advance, caller) \
                                     __ci_tcp_calc_rcv_wnd((ts), (advance))

ci_inline void ci_tcp_tx_maybe_do_striping(ci_ip_pkt_fmt* pkt,
                                           ci_tcp_state* ts) {
#if CI_CFG_PORT_STRIPING
  if( ts->tcpflags & CI_TCPT_FLAG_STRIPE )
    pkt->netif.tx.intf_swap = ci_ts_port_swap(pkt->pf.tcp_tx.start_seq, ts);
#endif
}

#endif  /* __TCP_TX_H__ */
