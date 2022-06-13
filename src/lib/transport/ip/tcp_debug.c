/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2005/02/08
** Description: Validation and debug ops for TCP sockets.
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */
#include "ip_internal.h"


/**********************************************************************
 * Validation of TCP packets.
 */

void ci_tcp_tx_pkt_assert_valid(ci_netif* ni, ci_tcp_state* ts,
                                ci_ip_pkt_fmt* pkt,
                                const char* file, int line)
{
  /* This should succeed for any packet on send or retrans queues. */
  ci_ip_pkt_fmt* next_pkt;
  ci_tcp_hdr* tcp;
  int i, len, paylen;

  verify(IS_VALID_PKT_ID(ni, OO_PKT_P(pkt)));
  verify(pkt->refcount > 0);

  /* Check TCP header is where we think it should be. */
  verify(pkt->pkt_eth_payload_off == ETH_HLEN);
  verify(pkt->pkt_start_off == 0 || pkt->pkt_start_off == -ETH_VLAN_HLEN);
  verify(CI_IP4_IHL(oo_tx_ip_hdr(pkt)) == sizeof(ci_ip4_hdr));
  tcp = TX_PKT_TCP(pkt);
  verify(tcp == PKT_TCP_HDR(pkt));

  /* Verify addressing. */
  verify(tcp->tcp_source_be16 == TS_IPX_TCP(ts)->tcp_source_be16);
  if( ts->s.b.state != CI_TCP_LISTEN ) {
    verify(tcp->tcp_dest_be16 == TS_IPX_TCP(ts)->tcp_dest_be16);
    verify(oo_tx_ip_hdr(pkt)->ip_saddr_be32 == ts->s.pkt.ipx.ip4.ip_saddr_be32);
    verify(oo_tx_ip_hdr(pkt)->ip_daddr_be32 == ts->s.pkt.ipx.ip4.ip_daddr_be32);
  }

  /* Verify sequence numbers are vaguely sensible. */
  /*verify(CI_BSWAP_BE32(tcp->tcp_seq_be32) == pkt->pf.tcp_tx.start_seq);*/
  verify(SEQ_LT(tcp_snd_una(ts), pkt->pf.tcp_tx.end_seq));
  verify(SEQ_LE(pkt->pf.tcp_tx.end_seq, tcp_enq_nxt(ts)));

  /* Verify lengths are consistent. */
  paylen = SEQ_SUB(pkt->pf.tcp_tx.end_seq, pkt->pf.tcp_tx.start_seq);
  if( tcp->tcp_flags & (CI_TCP_FLAG_SYN | CI_TCP_FLAG_FIN) )  --paylen;
  verify(CI_TCP_HDR_OPT_LEN(tcp) == tcp_outgoing_opts_len(ts)
         || (tcp->tcp_flags & CI_TCP_FLAG_SYN));

  if( pkt->flags & CI_PKT_FLAG_INDIRECT ) {
    struct ci_pkt_zc_header* zch = oo_tx_zc_header(pkt);
    struct ci_pkt_zc_payload* zcp;
    int zclen = 0;

    verify(pkt->n_buffers == 1);
    OO_TX_FOR_EACH_ZC_PAYLOAD(ni, zch, zcp) {
      zclen += zcp->len;
      verify(zcp->len != 0);
      verify(zcp->len <= 0x7fffffff);
    }
    verify(paylen == zclen + pkt->buf_len);
    verify(pkt->pf.tcp_tx.sock_id == ts->s.b.bufid);
  }
  else {
    verify(pkt->n_buffers >= 1);
    verify(pkt->n_buffers <= CI_IP_PKT_SEGMENTS_MAX);
    next_pkt = pkt;
    for( len = 0, i = 0; i < pkt->n_buffers; ++i ) {
      verify(next_pkt->buf_len > 0);
      len += next_pkt->buf_len;
      if( i < pkt->n_buffers-1 )
        next_pkt = PKT_CHK(ni, next_pkt->frag_next);
    }
    verify(len ==
          oo_tx_pre_l3_len(pkt) + CI_IP4_IHL(oo_tx_ip_hdr(pkt))
          + CI_TCP_HDR_LEN(tcp) + paylen);
    verify(len == pkt->pay_len);

    verify(oo_offbuf_ptr(&pkt->buf) ==
          (char*) oo_tx_l3_hdr(pkt) + ts->outgoing_hdrs_len + paylen);
    verify(oo_offbuf_end(&pkt->buf) ==
          (char*) oo_tx_l3_hdr(pkt) + ts->outgoing_hdrs_len + ts->eff_mss);
    verify(oo_offbuf_end(&pkt->buf) <= (char*) pkt + CI_CFG_PKT_BUF_SIZE);
  }
}


/**********************************************************************
 * Validation of state.
 */

void ci_tcp_state_listen_assert_valid(ci_netif* netif,
                                      ci_tcp_socket_listen* tsl,
                                      const char* file, int line)
{
  verify(tsl->s.tx_errno == EPIPE);
  verify(tsl->s.rx_errno == ENOTCONN);

  verify(ci_to_int(ci_tcp_acceptq_n(tsl)) >= 0);
  if( ci_tcp_acceptq_n(tsl) )
    verify(ci_tcp_acceptq_not_empty(tsl));

  /*
   * This verification can be failed because of next listen()
   * with new backlog (less that previously set).
   */
  if( (int) ci_tcp_acceptq_n(tsl) > tsl->acceptq_max )
    LOG_U(log(NTS_FMT" accept queue has more elements (%d) than "
              "allowed (%d)", NTS_PRI_ARGS(netif, tsl), ci_tcp_acceptq_n(tsl),
              tsl->acceptq_max));
}

#if ! defined(NDEBUG) && OO_DO_STACK_POLL
static void ci_tcp_state_retrans_assert_valid(ci_netif* ni, ci_tcp_state* ts,
                                              const char* file, int line)
{
  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt *pkt = NULL, *end, *prev_pkt;
  int num = 0, is_sacked = 0;
  oo_pkt_p id;

  id = rtq->head;
  prev_pkt = 0;

  while( OO_PP_NOT_NULL(id) ) {
    verify(IS_VALID_PKT_ID(ni, id));
    pkt = PKT(ni, id);
    if( OO_PP_EQ(id, rtq->head) ) {
      is_sacked = (pkt->flags & CI_PKT_FLAG_RTQ_SACKED) != 0;
      verify(SEQ_LE(pkt->pf.tcp_tx.start_seq, tcp_snd_una(ts)));
      verify(SEQ_LT(tcp_snd_una(ts), pkt->pf.tcp_tx.end_seq));
    }
    if( OO_PP_IS_NULL(pkt->pf.tcp_tx.block_end) )  break;

    verify(IS_VALID_PKT_ID(ni, pkt->pf.tcp_tx.block_end));
    end = PKT(ni, pkt->pf.tcp_tx.block_end);

    while( 1 ) {
      if( prev_pkt )
        verify(pkt->pf.tcp_tx.start_seq == prev_pkt->pf.tcp_tx.end_seq);
      verify(SEQ_LE(pkt->pf.tcp_tx.end_seq, end->pf.tcp_tx.end_seq));
      if( is_sacked )  verify(pkt->flags & CI_PKT_FLAG_RTQ_SACKED);
      else             verify(~pkt->flags & CI_PKT_FLAG_RTQ_SACKED);
      prev_pkt = pkt;
      ++num;
      if( pkt == end )  break;
      verify(IS_VALID_PKT_ID(ni, pkt->next));
      pkt = PKT_CHK(ni, pkt->next);
    }

    id = end->next;
    is_sacked = ! is_sacked;
  }

  if( OO_PP_IS_NULL(id) )  goto done;

  /* Check trailing unsacked region. */
  verify(! is_sacked);
  while( 1 ) {
    if( prev_pkt )
      verify(pkt->pf.tcp_tx.start_seq == prev_pkt->pf.tcp_tx.end_seq);
    verify(OO_PP_IS_NULL(pkt->pf.tcp_tx.block_end));
    verify(~pkt->flags & CI_PKT_FLAG_RTQ_SACKED);
    prev_pkt = pkt;
    ++num;
    if( OO_PP_IS_NULL(pkt->next) )  break;
    verify(IS_VALID_PKT_ID(ni, pkt->next));
    pkt = PKT_CHK(ni, pkt->next);
  }

 done:
  verify( ! pkt || OO_PP_EQ(OO_PKT_P(pkt), rtq->tail));
  verify(num == rtq->num);
}


static void ci_tcp_state_send_assert_valid(ci_netif* ni, ci_tcp_state* ts,
                                           const char* file, int line)
{
  ci_ip_pkt_queue* sendq = &ts->send;
  ci_ip_pkt_fmt *pkt;
  unsigned prev_seq = tcp_snd_nxt(ts);
  int bytes, num;
  oo_pkt_p id;

  bytes = 0;
  num = 0;

  for( id = sendq->head; OO_PP_NOT_NULL(id); id = pkt->next ) {
    verify(IS_VALID_PKT_ID(ni, id));
    pkt = PKT(ni, id);
    bytes += SEQ_SUB(pkt->pf.tcp_tx.end_seq, pkt->pf.tcp_tx.start_seq);
    verify(SEQ_EQ(pkt->pf.tcp_tx.start_seq, prev_seq));
    prev_seq = pkt->pf.tcp_tx.end_seq;
    ++num;
  }
  verify(ts->send.num == num);
  verify(bytes == SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts)));
}


static void ci_tcp_state_cong_assert_valid(ci_netif* ni, ci_tcp_state* ts,
                                           const char* file, int line)
{
  ci_ip_pkt_fmt* pkt;

  verify(!ts->cwnd_extra ||
         ((ts->congstate & (CI_TCP_CONG_FAST_RECOV|CI_TCP_CONG_COOLING)) &&
          (ts->tcpflags & CI_TCPT_FLAG_SACK)));

  if( ts->congstate != CI_TCP_CONG_OPEN &&
      ts->congstate != CI_TCP_CONG_NOTIFIED) {
    verify(ts->congstate == CI_TCP_CONG_RTO ||
           ts->congstate == CI_TCP_CONG_RTO_RECOV ||
           ts->congstate == CI_TCP_CONG_FAST_RECOV ||
           ts->congstate == CI_TCP_CONG_COOLING ||
           ts->congstate == (CI_TCP_CONG_COOLING | CI_TCP_CONG_RTO) );
    verify(SEQ_LE(ts->congrecover, tcp_snd_nxt(ts)));

    if( SEQ_LT(tcp_snd_una(ts), ts->congrecover) ) {
      if( ~ts->congstate & CI_TCP_CONG_COOLING ) {
        verify(SEQ_LE(ts->retrans_seq, ts->congrecover));
        if( SEQ_LE(tcp_snd_una(ts), ts->retrans_seq) ) {
          verify(IS_VALID_PKT_ID(ni, ts->retrans_ptr));
          pkt = PKT(ni, ts->retrans_ptr);
          verify(pkt->refcount > 0);
          verify(SEQ_LE(pkt->pf.tcp_tx.start_seq, ts->retrans_seq));
          verify(SEQ_LT(ts->retrans_seq, pkt->pf.tcp_tx.end_seq));
        }
      }
    }
  }
}


static void ci_tcp_state_recv_assert_valid(ci_netif* ni, ci_tcp_state* ts,
                                           int got_sock_lock,
                                           const char* file, int line)
{
  ci_ip_pkt_queue* q;
  int extract_points_in_recv1 = 0;
  ci_ip_pkt_fmt *pkt;
  unsigned seq, data_seq;
  int bytes = 0, num = 0;
  int drop_sock_lock = 0;
  ci_tcp_hdr* tcp;
  oo_offbuf* buf;
  oo_pkt_p id;

  if( ! got_sock_lock )
    got_sock_lock = drop_sock_lock = ci_sock_trylock(ni, &ts->s.b);

  if( ts->s.b.state & CI_TCP_STATE_ACCEPT_DATA )
    verify(SEQ_EQ(tcp_rcv_nxt(ts), ts->rcv_added));

  seq = ts->rcv_delivered;

  /* Iterate over both recv1 and recv2. */
  q = &ts->recv1;
  id = q->head;
  while( OO_PP_NOT_NULL(id) ) {
    pkt = PKT_CHK(ni, id);
    tcp = PKT_TCP_HDR(pkt);
    buf = &pkt->buf;
    verify(oo_offbuf_left(buf) >= 0);
    verify(oo_offbuf_left(buf) <= SEQ_SUB(pkt->pf.tcp_rx.end_seq, 
                                          CI_BSWAP_BE32(tcp->tcp_seq_be32)));
    data_seq = PKT_RX_BUF_SEQ(pkt);
    if( got_sock_lock || q == &ts->recv2 ) {
      verify(SEQ_EQ(data_seq + oo_offbuf_left(buf)
                    + ((tcp->tcp_flags & CI_TCP_FLAG_FIN)
		       >> CI_TCP_FLAG_FIN_BIT), pkt->pf.tcp_rx.end_seq));
    }
    if( got_sock_lock ) {
      verify(SEQ_EQ(data_seq, seq) || oo_offbuf_left(buf) == 0);
      seq += oo_offbuf_left(buf) + ((tcp->tcp_flags & CI_TCP_FLAG_FIN)
                                    >> CI_TCP_FLAG_FIN_BIT);
    }
    bytes += oo_offbuf_left(buf);
    ++num;
    if( q == &ts->recv1 ) {
      if( OO_PP_EQ(ts->recv1_extract, OO_PKT_P(pkt)) )
        extract_points_in_recv1 = 1;
      else if( extract_points_in_recv1 && got_sock_lock )
        /* Packets down-stream of the extract pointer must be non-empty. */
        verify(oo_offbuf_left(buf) > 0);
    }

    id = pkt->next;
    if( OO_PP_IS_NULL(id) && q == &ts->recv1 ) {
      verify(ts->recv1.num == num);
      num = 0;
      q = &ts->recv2;
      id = q->head;
    }
  }

  verify(ts->recv2.num == num);

  if( got_sock_lock ) {
    if( (ts->s.b.state & CI_TCP_STATE_ACCEPT_DATA) ||
        (~ts->s.b.state & CI_TCP_STATE_SYNCHRONISED) )
      verify(SEQ_EQ(seq, tcp_rcv_nxt(ts)));
    else
      verify(SEQ_EQ(seq + 1/*FIN seq number*/, tcp_rcv_nxt(ts)));
    verify(bytes == tcp_rcv_usr(ts));
    if( OO_PP_NOT_NULL(ts->recv1_extract) ) {
      verify(extract_points_in_recv1);
      pkt = PKT_CHK(ni, ts->recv1_extract);
      if( oo_offbuf_is_empty(&pkt->buf) && OO_PP_NOT_NULL(pkt->next) ) {
        pkt = PKT_CHK(ni, pkt->next);
        verify(oo_offbuf_left(&pkt->buf) > 0);
      }
    }

    /* Verify that pkts before extract are empty, and after are non-empty. */
    extract_points_in_recv1 = 0;
    for( id = ts->recv1.head; OO_PP_NOT_NULL(id); id = pkt->next ) {
      pkt = PKT_CHK(ni, id);
      buf = &pkt->buf;
      if( OO_PP_EQ(ts->recv1_extract, OO_PKT_P(pkt)) ) {
	extract_points_in_recv1 = 1;
	verify(oo_offbuf_left(buf) >= 0);
      }
      else if( extract_points_in_recv1 )
	verify(oo_offbuf_left(buf) > 0);
      else
	verify(oo_offbuf_left(buf) == 0);
    }

    if( drop_sock_lock )  ci_sock_unlock(ni, &ts->s.b);
  }
}


static void ci_tcp_state_rob_assert_valid(ci_netif* ni, ci_tcp_state* ts,
                                          const char* file, int line)
{
  ci_ip_pkt_queue* rob = &ts->rob;
  ci_ip_pkt_fmt *block, *pkt, *prev_pkt;
  ci_tcp_hdr* tcp;
  int block_num, num = 0;
  oo_pkt_p id;

  for( id = rob->head; OO_PP_NOT_NULL(id);
       id = block->pf.tcp_rx.misc.rob.next_block ) {
    block = PKT_CHK(ni, id);
    block_num = 0;
    prev_pkt = 0;

    while( 1 ) {
      pkt = PKT_CHK(ni, id);
      tcp = PKT_TCP_HDR(pkt);

      verify(SEQ_LE(pkt->pf.tcp_rx.end_seq,
                    block->pf.tcp_rx.misc.rob.end_block_seq));
      ++num;  ++block_num;
      if( prev_pkt ) {
        verify(SEQ_LE(CI_BSWAP_BE32(tcp->tcp_seq_be32), prev_pkt->pf.tcp_rx.end_seq));
        verify(SEQ_LT(prev_pkt->pf.tcp_rx.end_seq, pkt->pf.tcp_rx.end_seq));
      }

      if( OO_PP_EQ(OO_PKT_P(pkt), block->pf.tcp_rx.misc.rob.end_block) )
        break;
      id = pkt->next;
      prev_pkt = pkt;
    }

    verify(block->pf.tcp_rx.misc.rob.num == block_num);
  }

  verify(rob->num == num);
}
#endif


void ci_tcp_state_assert_valid(ci_netif* netif, ci_tcp_state* ts,
                               const char* file, int line)
{
#if ! defined(NDEBUG) && OO_DO_STACK_POLL
  ci_ip_pkt_fmt *pkt, *prev_pkt;
  int sack_points_in_rob;
  int num, need_unlock;
  oo_pkt_p id;

  /* We really need the netif lock in here, else we'll trigger assertions
  ** in PKT() etc.  So any routine callers (ie. from detailed-checks) must
  ** hold the netif lock.
  **
  ** But we still want to be able to call this without netif lock for
  ** debugging, so try to grab the netif lock here.  If a verify() fails,
  ** we will return without dropping the lock...but that is no bad thing,
  ** as we'll freeze the stack.
  */
  if( (need_unlock = ci_netif_trylock(netif)) )
    log("%s: WARNING -- netif %d was unlocked (%s:%d)", __FUNCTION__,
        NI_ID(netif), file, line);

  verify(ts);
  verify(IS_VALID_SOCK_P(netif, S_SP(ts)));
  verify(SP_TO_TCP(netif, S_SP(ts)) == ts);
  verify(ts->s.b.state & CI_TCP_STATE_TCP);
  verify((ts->s.b.state & CI_TCP_STATE_TCP_CONN) ||
         ts->s.b.state == CI_TCP_CLOSED);
  verify(ts->s.b.state >= CI_TCP_CLOSED);
  verify(ts->s.b.state <= CI_TCP_TIME_WAIT);
  ci_assert(ts->s.pkt.ipx.ip4.ip_protocol == IPPROTO_TCP);

# define chk(x)                                         \
  verify(!ci_ip_timer_pending(netif, &ts->x) ||         \
         (~ts->s.b.state & CI_TCP_STATE_NO_TIMERS) ||   \
         (ts->s.b.state == CI_TCP_LISTEN &&             \
          (ts->s.s_flags & CI_SOCK_FLAG_BOUND_ALIEN)))
  chk(rto_tid);
  chk(delack_tid);
  chk(zwin_tid);
  chk(kalive_tid);
# undef chk

  verify(SEQ_LE(tcp_snd_una(ts), tcp_snd_nxt(ts)));
  /* NB. Window can shrink, so the following is not a valid test: */
  /* verify(SEQ_LE(tcp_snd_nxt(ts), ts->snd_max)); */

  verify(ci_ip_queue_is_valid(netif, &ts->send));
  verify(ci_ip_queue_is_valid(netif, &ts->retrans));
  verify(ci_ip_queue_is_valid(netif, &ts->recv1));
  verify(ci_ip_queue_is_valid(netif, &ts->recv2));
  verify(ci_ip_queue_is_valid(netif, &ts->rob));

  if(!(ts->s.b.state & CI_TCP_STATE_TXQ_ACTIVE)){
    verify(ci_ip_queue_is_empty(&ts->send));
    verify(ci_ip_queue_is_empty(&ts->retrans));
  }

  verify((TCP_RX_ERRNO(ts) == 0 && ts->s.tx_errno == 0) ||
         ts->s.b.state != CI_TCP_ESTABLISHED);

  if( ts->s.b.state >= CI_TCP_SYN_SENT ) {
    verify(tcp_eff_mss(ts) <= CI_MAX_ETH_FRAME_LEN);
    verify(ts->cwnd >= tcp_eff_mss(ts));
    verify(ts->ssthresh >= tcp_eff_mss(ts) << 1);
    verify(ci_to_int(tcp_rcv_wnd_advertised(ts)) >= 0);
  }

  if( ts->tcpflags & CI_TCPT_FLAG_TSO ) {
    verify(ts->outgoing_hdrs_len ==
           sizeof(ci_ip4_hdr) + sizeof(ci_tcp_hdr) + 12);
    verify(tcp_outgoing_opts_len(ts) == 12);
  }
  else {
    verify(ts->outgoing_hdrs_len == sizeof(ci_ip4_hdr) + sizeof(ci_tcp_hdr));
    verify(tcp_outgoing_opts_len(ts) == 0);
  }
  verify(CI_TCP_HDR_LEN(TS_IPX_TCP(ts)) ==
         sizeof(ci_tcp_hdr) + tcp_outgoing_opts_len(ts));

  /* Validate receive queues. */
  ci_tcp_state_recv_assert_valid(netif, ts, 0, file, line);

  /* Validate receive reorder queue. */
  ci_tcp_state_rob_assert_valid(netif, ts, file, line);

  /* Validate congestion state. */
  ci_tcp_state_cong_assert_valid(netif, ts, file, line);

  /* Validate retrans queue. */
  ci_tcp_state_retrans_assert_valid(netif, ts, file, line);

  /* Validate send queue. */
  ci_tcp_state_send_assert_valid(netif, ts, file, line);

  if( ts->tcpflags & CI_TCPT_FLAG_SACK ){
    /* transmit SACK state and ROB */
    for( num = 0; num <= CI_TCP_SACK_MAX_BLOCKS; num++ ) {
      if( OO_PP_NOT_NULL(ts->last_sack[num]) ) {
        /* check that it is in the ROB */
        sack_points_in_rob = 0;
        prev_pkt = 0;
        for( id = ts->rob.head; OO_PP_NOT_NULL(id); id = pkt->next ) {
          pkt = PKT_CHK(netif, id);
          if( OO_PP_EQ(id, ts->last_sack[num]) ) {
            /* it is present in the ROB*/
            /* make sure only once! */
            verify(!sack_points_in_rob);
            sack_points_in_rob = 1;
            if(prev_pkt){
              /* make sure the id of the start of the sack block marks
                 a discontinuous region */
              verify(!SEQ_EQ(prev_pkt->pf.tcp_tx.end_seq,
                             pkt->pf.tcp_tx.start_seq));
            }
          }
          prev_pkt = pkt;
        }
        verify(sack_points_in_rob);
      }
    }
  }

  if( need_unlock )  ci_netif_unlock(netif);
#endif
}


#ifndef NDEBUG
void ci_tcp_ep_assert_valid(citp_socket* ep, const char* file, int line)
{
  ci_assert(ep);
  ci_netif_assert_valid(ep->netif, file, line);
  verify(ep->s->b.state & CI_TCP_STATE_TCP);
  if( ep->s->b.state == CI_TCP_LISTEN )
    ci_tcp_state_listen_assert_valid(ep->netif, SOCK_TO_TCP_LISTEN(ep->s),
                                     file, line);
  else
    ci_tcp_state_assert_valid(ep->netif, SOCK_TO_TCP(ep->s), file, line);
}
#endif


/**********************************************************************
 * Dumping state.
 */

#if OO_DO_STACK_POLL

void ci_tcp_pkt_dump(ci_netif *ni, ci_ip_pkt_fmt* pkt, int is_recv, int dump)
{
  ci_tcp_hdr* tcp = PKT_TCP_HDR(pkt);
  oo_pkt_p buf;

  if( is_recv ) {
    oo_offbuf* buf = &pkt->buf;
    log("  %4d: %08x-%08x ["CI_TCP_FLAGS_FMT"] left=%d", OO_PKT_FMT(pkt),
        SEQ(PKT_TCP_HDR(pkt)->tcp_seq_be32), SEQ(pkt->pf.tcp_rx.end_seq),
        CI_TCP_HDR_FLAGS_PRI_ARG(tcp), oo_offbuf_left(buf));
    if( dump & 1 )
      ci_hex_dump(ci_log_fn, oo_ether_hdr(pkt),
                  oo_pre_l3_len(pkt) + oo_ip_hdr(pkt)->ip_tot_len_be16, 0);
  }
  else {
    int i, paylen = TX_PKT_LEN(pkt) -
      (oo_tx_pre_l3_len(pkt) + CI_IP4_IHL(oo_ip_hdr(pkt))
       + CI_TCP_HDR_LEN(tcp));

    if( CI_IP_PKT_SEGMENTS_MAX != 6 )
      ci_log("FIXME: %s:%d", __FILE__, __LINE__);

    log("  %4d: %08x-%08x ["CI_TCP_FLAGS_FMT"] nbuf=%d paylen=%d "
        "seq=%d spc=%d "CI_PKT_FLAGS_FMT, OO_PKT_FMT(pkt),
        SEQ(pkt->pf.tcp_tx.start_seq),
        SEQ(pkt->pf.tcp_tx.end_seq), CI_TCP_HDR_FLAGS_PRI_ARG(tcp),
        pkt->n_buffers, paylen,
        SEQ_SUB(pkt->pf.tcp_tx.end_seq, pkt->pf.tcp_tx.start_seq),
        oo_offbuf_left(&pkt->buf),
        CI_PKT_FLAGS_PRI_ARG(pkt));
    buf = OO_PKT_P(pkt);
    for( i = 0; i < pkt->n_buffers; ++i ) {
      ci_ip_pkt_fmt* apkt = PKT_CHK(ni, buf);
      log("      : "EF_ADDR_FMT":%d",
          pkt_dma_addr(ni, apkt, pkt->intf_i), apkt->buf_len);
      buf = apkt->frag_next;
    }
    if( dump & 1 )
      ci_hex_dump(ci_log_fn, oo_ether_hdr(pkt), pkt->buf_len, 0);
  }
}


void ci_tcp_state_dump_qs(ci_netif* ni, int ep_id, int dump)
{
  ci_tcp_state* ts;

  if( ! IS_VALID_SOCK_ID(ni, ep_id) )
    log("%s: invalid id %d", __FUNCTION__, ep_id);

  ts = ID_TO_TCP(ni, ep_id);

  if( ts->s.b.state == CI_TCP_LISTEN ) {
    log("%s: %d LISTEN (TODO)", __FUNCTION__, S_FMT(ts));
    return;
  }

  log("%s: "NTS_FMT, __FUNCTION__, NTS_PRI_ARGS(ni, ts));
  log("recv1: extract=%d", OO_PP_FMT(ts->recv1_extract));
  ci_netif_pkt_queue_dump(ni, &ts->recv1, 1, dump);
  log("recv2:");
  ci_netif_pkt_queue_dump(ni, &ts->recv2, 1, dump);
  log("rob:");  /* ?? would be better to treat this specially */
  ci_netif_pkt_queue_dump(ni, &ts->rob, 1, dump);
  log("send:");
  ci_netif_pkt_queue_dump(ni, &ts->send, 0, dump);
  log("retrans:");
  ci_netif_pkt_queue_dump(ni, &ts->retrans, 0, dump);
}


void ci_tcp_state_dump_rob(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_pkt_queue* rob = &ts->rob;
  int i = 1;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pkt_id;
  oo_pkt_p start_id = rob->head;

  log("%s: "NTS_FMT, __FUNCTION__, NTS_PRI_ARGS(netif, ts));
  for( pkt_id = rob->head; OO_PP_NOT_NULL(pkt_id); pkt_id = pkt->next) {
    pkt = PKT(netif, pkt_id);
    if( OO_PP_EQ(pkt_id, start_id) ) {
      log("  %d block in ROB", i);
      start_id = PKT_TCP_RX_ROB(pkt)->next_block;
    }
    ci_tcp_pkt_dump(netif, pkt, 1, 0);
  }
  log("End of ROB dump");
}


void ci_tcp_state_dump_retrans_blocks(ci_netif* ni, ci_tcp_state* ts)
{
  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt *pkt, *end;
  oo_pkt_p id;

  log("%s: "NTS_FMT TCP_SND_FMT, __FUNCTION__, NTS_PRI_ARGS(ni, ts),
      TCP_SND_PRI_ARG(ts));

  for( id = rtq->head; OO_PP_NOT_NULL(id); id = end->next ) {
    pkt = PKT(ni, id);
    if( OO_PP_NOT_NULL(pkt->pf.tcp_tx.block_end) )
      end = PKT(ni, pkt->pf.tcp_tx.block_end);
    else
      end = PKT(ni, rtq->tail);
    log("  %08x-%08x %d-%d len=%d%s%s", pkt->pf.tcp_tx.start_seq,
        end->pf.tcp_tx.end_seq, OO_PKT_FMT(pkt), OO_PKT_FMT(end),
        SEQ_SUB(end->pf.tcp_tx.end_seq, pkt->pf.tcp_tx.start_seq),
        end->flags & CI_PKT_FLAG_TX_PENDING ? " inflight":"",
        pkt->flags & CI_PKT_FLAG_RTQ_SACKED ? " sacked":"");
  }
}


void ci_tcp_state_dump_retrans(ci_netif* ni, ci_tcp_state* ts)
{
  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p id;

  log("%s: "NTS_FMT" "TCP_SND_FMT, __FUNCTION__,
      NTS_PRI_ARGS(ni, ts), TCP_SND_PRI_ARG(ts));

  for( id = rtq->head; OO_PP_NOT_NULL(id); id = pkt->next ) {
    pkt = PKT(ni, id);
    log("  %4d: %08x-%08x len=%u block_end=%d %s%s%s",
        OO_PP_FMT(id), SEQ(pkt->pf.tcp_tx.start_seq),
        SEQ(pkt->pf.tcp_tx.end_seq), pkt->buf_len,
        OO_PP_FMT(pkt->pf.tcp_tx.block_end),
        pkt->flags & CI_PKT_FLAG_RTQ_SACKED ? " sacked":"",
        pkt->flags & CI_PKT_FLAG_RTQ_RETRANS ? " retrans":"",
        pkt->flags & CI_PKT_FLAG_TX_PENDING ? " inflight":"");
  }
}



static void ci_tcp_socket_cmn_dump(ci_netif* ni, ci_tcp_socket_cmn* tsc,
                                   const char* pf,
                                   oo_dump_log_fn_t logger, void* log_arg)
{
  /* fixme: dump tsc fields */
}


void ci_tcp_socket_listen_dump(ci_netif* ni, ci_tcp_socket_listen* tls,
			       const char* pf,
                               oo_dump_log_fn_t logger, void* log_arg)
{
  ci_tcp_socket_cmn_dump(ni, &tls->c, pf, logger, log_arg);

  logger(log_arg, "%s  listenq: max=%d n=%d new=%d buckets=%d", pf, 
         ci_tcp_listenq_max(ni), tls->n_listenq, tls->n_listenq_new,
         tls->n_buckets);
  logger(log_arg, "%s  acceptq: max=%d n=%d accepted=%d", pf,
         tls->acceptq_max, ci_tcp_acceptq_n(tls), tls->acceptq_n_out);
  logger(log_arg, "%s  defer_accept=%d", pf, tls->c.tcp_defer_accept);
#if CI_CFG_FD_CACHING
  logger(log_arg, "%s  sockcache: n=%d sock_n=%d cache=%s pending=%s connected=%s",
         pf, ni->state->passive_cache_avail_stack, tls->cache_avail_sock,
         oo_p_dllink_is_empty(ni, oo_p_dllink_sb(ni, &tls->s.b,
                                                 &tls->epcache.cache))
            ? "EMPTY":"yes",
         oo_p_dllink_is_empty(ni, oo_p_dllink_sb(ni, &tls->s.b,
                                                 &tls->epcache.pending))
            ? "EMPTY":"yes",
         oo_p_dllink_is_empty(ni, oo_p_dllink_sb(ni, &tls->s.b,
                                                 &tls->epcache_connected))
            ? "EMPTY":"yes");
#endif
#if CI_CFG_STATS_TCP_LISTEN
  {
    ci_tcp_socket_listen_stats* s = &tls->stats;
#if CI_CFG_FD_CACHING
    logger(log_arg, "%s  sockcache_hit=%d", pf, s->n_sockcache_hit);
#endif
    logger(log_arg,
           "%s  l_overflow=%d l_no_synrecv=%d aq_overflow=%d aq_no_sock=%d aq_no_pkts=%d",
           pf, s->n_listenq_overflow, s->n_listenq_no_synrecv,
           s->n_acceptq_overflow, s->n_acceptq_no_sock, s->n_acceptq_no_pkts);
    logger(log_arg, "%s  a_loop2_closed=%u a_no_fd=%u ack_rsts=%u os=%u rx_pkts=%u",
           pf, s->n_accept_loop2_closed, s->n_accept_no_fd,
           s->n_acks_reset, s->n_accept_os, s->n_rx_pkts);
    if( NI_OPTS(ni).tcp_syncookies ) {
      logger(log_arg, "%s  syncookies: syn_recv=%u ack_recv=%u ack_answ=%u",
             pf, s->n_syncookie_syn, s->n_syncookie_ack_recv,
             s->n_syncookie_ack_answ);
      logger(log_arg, "%s  syncookies rejected: timestamp=%u crypto_hash=%u",
             pf, s->n_syncookie_ack_ts_rej, s->n_syncookie_ack_hash_rej);
    }
  }
#endif
}

static int line_fmt_timer(char *buf, int len, int pos,
                         const char *fmt, ci_iptime_t delta,
                          ci_iptime_t t,
                          oo_dump_log_fn_t logger, void* log_arg)
{
  int avail = len - pos;
  int n;
  if ( (n = ci_snprintf(buf + pos, avail, fmt, delta, t)) >= avail) {
    buf[pos] = '\0';
    logger(log_arg, "%s", buf);
    pos = 0;
    n = ci_snprintf(buf, avail, fmt, delta, t);
  }
  return pos + n;
}


#if CI_CFG_CONGESTION_WINDOW_VALIDATION
# define tcp_cwnd_used(ts)  ((ts)->cwnd_used)
#else
# define tcp_cwnd_used(ts)  0
#endif


#define LINE_LEN (79)
void ci_tcp_state_dump(ci_netif* ni, ci_tcp_state* ts, 
		       const char *pf,
                       oo_dump_log_fn_t logger, void* log_arg)
{
  struct oo_tcp_socket_stats stats = ts->stats;
  ci_iptime_t now = ci_ip_time_now(ni);
  char buf[LINE_LEN + 1];
  int n;

#if CI_CFG_TIMESTAMPING
  ci_udp_recvq_dump(ni, &ts->timestamp_q, pf, "  TX timestamping queue:",
                    logger, log_arg);
#endif
  if( ts->s.s_flags & CI_SOCK_FLAG_DNAT )
    logger(log_arg, "%s  DNAT: original destination "CI_IP_PRINTF_FORMAT":%d",
           pf, CI_IP_PRINTF_ARGS(&ts->pre_nat.daddr_be32),
           CI_BSWAP_BE16(ts->pre_nat.dport_be16));

  ci_tcp_socket_cmn_dump(ni, &ts->c, pf, logger, log_arg);

  logger(log_arg, "%s  tcpflags: "CI_TCP_SOCKET_FLAGS_FMT" local_peer: %d",
         pf, CI_TCP_SOCKET_FLAGS_PRI_ARG(ts), ts->local_peer);

  logger(log_arg, "%s  snd: up=%08x una-nxt-max=%08x-%08x-%08x enq=%08x%s",
         pf,
         tcp_snd_up(ts), tcp_snd_una(ts), tcp_snd_nxt(ts), ts->snd_max,
         tcp_enq_nxt(ts),
         SEQ_LT(tcp_snd_nxt(ts) + ts->snd_delegated, tcp_snd_up(ts)) ?
           " URG":"");
  logger(log_arg,
         "%s  snd: send=%d(%d) send+pre=%d inflight=%d(%d) wnd=%d unused=%d",
         pf, SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts)), ts->send.num,
         ci_tcp_sendq_n_pkts(ts),
         ci_tcp_inflight(ts), ts->retrans.num, tcp_snd_wnd(ts),
         SEQ_SUB(ts->snd_max, tcp_snd_nxt(ts)));
  if( ts->snd_delegated != 0 )
    logger(log_arg, "%s  snd delegated=%d", pf, ts->snd_delegated);
  logger(log_arg, "%s  snd: cwnd=%d+%d used=%d ssthresh=%d bytes_acked=%d %s",
         pf, ts->cwnd, ts->cwnd_extra, tcp_cwnd_used(ts),
         ts->ssthresh, ts->bytes_acked, congstate_str(ts));
  logger(log_arg, "%s  snd: timed_seq %x timed_ts %x",
         pf, ts->timed_seq, ts->timed_ts);
  logger(log_arg, "%s  snd: sndbuf_pkts=%d "OOF_IPCACHE_STATE" "
	 OOF_IPCACHE_DETAIL,
	 pf, ts->so_sndbuf_pkts, OOFA_IPCACHE_STATE(ni, &ts->s.pkt),
         OOFA_IPCACHE_DETAIL(&ts->s.pkt));
  logger(log_arg, "%s  snd: limited rwnd=%d cwnd=%d nagle=%d more=%d app=%d",
         pf, stats.tx_stop_rwnd, stats.tx_stop_cwnd, stats.tx_stop_nagle,
         stats.tx_stop_more, stats.tx_stop_app);
#if CI_CFG_TAIL_DROP_PROBE
  if( ts->tcpflags & CI_TCPT_FLAG_TAIL_DROP_MARKED )
    logger(log_arg, "%s  snd: tail loss probe at %x", pf, ts->taildrop_mark);
#endif

  logger(log_arg, "%s  rcv: nxt-max=%08x-%08x wnd adv=%d cur=%d %s%s", pf,
         tcp_rcv_nxt(ts), tcp_rcv_wnd_right_edge_sent(ts),
         tcp_rcv_wnd_advertised(ts), tcp_rcv_wnd_current(ts),
         ci_tcp_is_in_faststart(ts) ? " FASTSTART":"",
         ci_tcp_can_use_fast_path(ts) ? " FAST":"");
  logger(log_arg, "%s  rcv: isn=%08x up=%08x urg_data=%04x q=%s", pf,
         stats.rx_isn, tcp_rcv_up(ts), tcp_urg_data(ts),
         TS_QUEUE_RX(ts) == &ts->recv1 ? "recv1" : "recv2");
  logger(log_arg, "%s  rcv: bytes=%u tot_pkts=%" PRIx64
                  " rob_pkts=%d q_pkts=%d+%d usr=%u",
         pf, ts->rcv_added - stats.rx_isn, stats.rx_pkts, ts->rob.num,
         ts->recv1.num, ts->recv2.num, tcp_rcv_usr(ts));

  logger(log_arg,
         "%s  eff_mss=%d smss=%d amss=%d  used_bufs=%d wscl s=%d r=%d",
         pf, ts->eff_mss, ts->smss, ts->amss,
         ts->send.num + ts->retrans.num + ts->rob.num+ts->recv1.num
         + ts->recv2.num, ts->snd_wscl, ts->rcv_wscl);
  logger(log_arg, "%s  srtt=%02d rttvar=%03d rto=%d zwins=%u,%u", pf,
         tcp_srtt(ts), tcp_rttvar(ts), ts->rto, ts->zwin_probes,
         ts->zwin_acks);
  logger(log_arg,
         "%s  curr_retrans=%d total_retrans=%d dupacks=%u congrecover=%x",
         pf, ts->retransmits, stats.total_retrans, ts->dup_acks,
         ts->congrecover);
  logger(log_arg,
         "%s  rtos=%u frecs=%u seqerr=%u,%u ooo_pkts=%d "
         "ooo=%d", pf, stats.rtos,
         stats.fast_recovers, stats.rx_seq_errs, stats.rx_ack_seq_errs,
         stats.rx_ooo_pkts, stats.rx_ooo_fill);
  logger(log_arg, "%s  tx: defer=%d nomac=%u warm=%u warm_aborted=%u", pf,
         stats.tx_defer, stats.tx_nomac_defer, stats.tx_msg_warm,
         stats.tx_msg_warm_abort);
  logger(log_arg, "%s  tmpl: send_fast=%u send_slow=%u active=%u", pf,
         stats.tx_tmpl_send_fast, stats.tx_tmpl_send_slow,
         stats.tx_tmpl_active);
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  logger(log_arg, "%s  plugin: stream_id=%x ddr_base=%"PRIx64
                  " ddr_size=%"PRIx64,
         pf, ts->plugin_stream_id, ts->plugin_ddr_base, ts->plugin_ddr_size);
#endif
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  if( NI_OPTS(ni).tcp_offload_plugin == CITP_TCP_OFFLOAD_NVME )
    logger(log_arg, "%s  nvme_plugin: last_id=%u", pf, ts->current_crc_id);
#endif
#ifndef __KERNEL__
# define fmt_timer(_b, _l, _n, name, tid)                       \
  if( ci_ip_timer_pending(ni, &tid) )                           \
    _n = line_fmt_timer(_b, _l, _n, #name"(%ums[%x]) ",         \
                        ci_ip_time_ticks2ms(ni, tid.time-now),  \
                        tid.time,                               \
                        logger, log_arg)
#else
# define fmt_timer(_b, _l, _n, name, tid)                   \
  if( ci_ip_timer_pending(ni, &tid) )                       \
    _n = line_fmt_timer(_b, _l, _n,  #name"(%uticks[%x]) ", \
                        tid.time-now, tid.time,             \
                        ci_log_dump_fn, NULL)
#endif

  logger(log_arg, "%s  timers: ", pf);
  n = 0;
  buf[0] = '\0';
  fmt_timer(buf, LINE_LEN, n, rto, ts->rto_tid);
  fmt_timer(buf, LINE_LEN, n, delack, ts->delack_tid);
  fmt_timer(buf, LINE_LEN, n, zwin, ts->zwin_tid);
  fmt_timer(buf, LINE_LEN, n, kalive, ts->kalive_tid);
  if( OO_PP_NOT_NULL(ts->pmtus) ) {
    ci_pmtu_state_t* pmtus = ci_ni_aux_p2pmtus(ni, ts->pmtus);
    fmt_timer(buf, LINE_LEN, n, pmtu, pmtus->tid);
  }
#undef fmt_timer
  logger(log_arg, "%s", buf);
  if( OO_PP_NOT_NULL(ts->pmtus) ) {
    ci_pmtu_state_t* pmtus = ci_ni_aux_p2pmtus(ni, ts->pmtus);
    logger(log_arg, "%s  pmtu=%d: ", pf, pmtus->pmtu);
  }
}


void ci_tcp_state_dump_id(ci_netif* ni, int ep_id)
{
  if( ! IS_VALID_SOCK_ID(ni, ep_id) ) {
    log("%s: invalid id=%d", __FUNCTION__, ep_id);
    return;
  }

  ci_tcp_state_dump(ni, ID_TO_TCP(ni, ep_id), "", ci_log_dump_fn, NULL);
}


/**********************************************************************
 * Extra online traffic checks.
 */

/* tcp_rx_checks is a bit-field that requests the checks.  Do not use bit
** 0; it is reserved for pushing us onto this path.
*/
                        /* Don't use 0x1 */
#define CI_TCP_RX_CHK_DEST_MAC       0x2
#define CI_TCP_RX_CHK_SRC_MAC        0x4
#define CI_TCP_RX_CHK_SRC_IS_EFAB    0x8
#define CI_TCP_RX_CHK_IP_CSUM        0x10
#define CI_TCP_RX_CHK_TCP_CSUM       0x20
#define CI_TCP_RX_CHK_PORT           0x40

#define DUMP_PKT                     1
#define DUMP_PKT_ADDR               (2|1)
#define DUMP_SOCK                    4
#define DUMP_SOCK_ADDR              (8|4)

#undef LPF
#define LPF "ci_tcp_rx_checks: "

static void tcp_rx_checks_cmn(ci_netif* ni, ci_sock_cmn* s,
			      ci_ip_pkt_fmt* pkt, unsigned* dump)
{
  unsigned chk = NI_OPTS(ni).tcp_rx_checks;
  ci_tcp_hdr* tcp = PKT_TCP_HDR(pkt);

  if( chk & CI_TCP_RX_CHK_SRC_IS_EFAB ) {
    ci_uint8 mac_prefix[] = { 0x00, 0x0F, 0x53, 0x00 };
    if( memcmp(oo_ether_shost(pkt), mac_prefix, sizeof(mac_prefix)) ) {
      ci_log(LPF "SHOST_NOT_EFAB:");
      *dump |= DUMP_PKT_ADDR | DUMP_SOCK_ADDR;
    }
  }

  if( chk & CI_TCP_RX_CHK_IP_CSUM ) {
    /* TODO */
  }

  if( chk & CI_TCP_RX_CHK_TCP_CSUM ) {
    /* TODO */
  }

  /* Log packets with interesting flags. */
  if( tcp->tcp_flags & NI_OPTS(ni).tcp_rx_log_flags )
    *dump |= DUMP_SOCK | DUMP_PKT;
}


static void tcp_rx_checks_dump_cmn(ci_netif* ni, ci_ip_pkt_fmt* pkt,
				   unsigned dump)
{
  ci_tcp_hdr* tcp = PKT_TCP_HDR(pkt);

  if( (dump & DUMP_PKT) == DUMP_PKT )
    ci_log(LPF "pkt "CI_IP_PRINTF_FORMAT":%u=>"CI_IP_PRINTF_FORMAT":%u ["
	   CI_TCP_FLAGS_FMT"]",
	   CI_IP_PRINTF_ARGS(&oo_ip_hdr(pkt)->ip_saddr_be32),
	   (unsigned) CI_BSWAP_BE16(tcp->tcp_source_be16),
	   CI_IP_PRINTF_ARGS(&oo_ip_hdr(pkt)->ip_daddr_be32),
	   (unsigned) CI_BSWAP_BE16(tcp->tcp_dest_be16),
	   CI_TCP_HDR_FLAGS_PRI_ARG(tcp));

  if( (dump & DUMP_PKT_ADDR) == DUMP_PKT_ADDR )
    ci_log(LPF "pkt "CI_MAC_PRINTF_FORMAT"=>"CI_MAC_PRINTF_FORMAT,
	   CI_MAC_PRINTF_ARGS(oo_ether_shost(pkt)),
	   CI_MAC_PRINTF_ARGS(oo_ether_dhost(pkt)));
}


void ci_tcp_rx_checks(ci_netif* ni, ci_tcp_state* ts, ci_ip_pkt_fmt* pkt)
{
  unsigned chk = NI_OPTS(ni).tcp_rx_checks;
  unsigned dump = 0;

  tcp_rx_checks_cmn(ni, &ts->s, pkt, &dump);

  if( chk & CI_TCP_RX_CHK_SRC_MAC ) {  /* Verify the source MAC. */
    /* We may have to twiddle the bottom bit of the mac address if we are
    ** striping.
    */
    ci_uint8 mac[ETH_ALEN];
    unsigned twiddle;
    twiddle = oo_ether_dhost(pkt)[5] ^
        ((char *)ci_ip_cache_ether_shost(&ts->s.pkt))[5];
    memcpy(mac, ci_ip_cache_ether_dhost(&ts->s.pkt), ETH_ALEN);
    mac[5] ^= twiddle;
    if( memcmp(oo_ether_shost(pkt), mac, ETH_ALEN) ) {
      ci_log(LPF "SHOST_BAD: expected="CI_MAC_PRINTF_FORMAT,
	     CI_MAC_PRINTF_ARGS(mac));
      dump |= DUMP_PKT_ADDR | DUMP_SOCK_ADDR;
    }
  }

  /**********************************************************************
   * Checks done.  Now dump info as required.
   */
  tcp_rx_checks_dump_cmn(ni, pkt, dump);

  if( (dump & DUMP_SOCK) == DUMP_SOCK ) {
    ci_log(LNT_FMT "snd=%d inf=%d rcv=%d %s", LNT_PRI_ARGS(ni, ts),
	   SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts)),
	   ci_tcp_inflight(ts), tcp_rcv_usr(ts), state_str(ts));
    ci_log(LNT_FMT CI_IP_PRINTF_FORMAT":%u=>"CI_IP_PRINTF_FORMAT":%u",
	   LNT_PRI_ARGS(ni, ts),
	   CI_IP_PRINTF_ARGS(&tcp_laddr_be32(ts)),
	   (unsigned) CI_BSWAP_BE16(tcp_lport_be16(ts)),
	   CI_IP_PRINTF_ARGS(&tcp_raddr_be32(ts)),
	   (unsigned) CI_BSWAP_BE16(tcp_rport_be16(ts)));
  }
  if( (dump & DUMP_SOCK_ADDR) == DUMP_SOCK_ADDR )
    ci_log(LNT_FMT CI_MAC_PRINTF_FORMAT"=>"CI_MAC_PRINTF_FORMAT" hwport=%d"
	   " stripe=%x", LNT_PRI_ARGS(ni, ts),
	   CI_MAC_PRINTF_ARGS(ci_ip_cache_ether_shost(&ts->s.pkt)),
	   CI_MAC_PRINTF_ARGS(ci_ip_cache_ether_dhost(&ts->s.pkt)),
	   (int) ts->s.pkt.hwport,
#if CI_CFG_PORT_STRIPING
           !!(ts->tcpflags & CI_TCPT_FLAG_STRIPE)
#else
           0
#endif
           );
}


void ci_tcp_listen_rx_checks(ci_netif* ni, ci_tcp_socket_listen* tls,
			     ci_ip_pkt_fmt* pkt)
{
  unsigned dump = 0;

  tcp_rx_checks_cmn(ni, &tls->s, pkt, &dump);
  tcp_rx_checks_dump_cmn(ni, pkt, dump);
}

#endif
/*! \cidoxg_end */
