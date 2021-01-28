/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  TCP transmit
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <onload/sleep.h>
#include "ip_tx.h"
#include <ci/internal/pio_buddy.h>
#include "tcp_tx.h"


#if OO_DO_STACK_POLL
#define LPF "TCP TX "


ci_inline void check_tx_timestamping(ci_tcp_state* ts, int af,
                                     ci_ip_pkt_fmt* pkt)
{
#if CI_CFG_TIMESTAMPING
  if( onload_timestamping_want_tx_nic(ts->s.timestamping_flags) &&
      CI_TCP_PAYLEN(oo_tx_ip_hdr(pkt), TX_PKT_IPX_TCP(af, pkt)) != 0 ) {
    pkt->flags |= CI_PKT_FLAG_TX_TIMESTAMPED;
    pkt->pf.tcp_tx.sock_id = ts->s.b.bufid;
  }
  if( pkt->flags & CI_PKT_FLAG_INDIRECT )
    ci_assert_equal(pkt->pf.tcp_tx.sock_id, ts->s.b.bufid);
#endif
}


ci_inline void ci_ip_tcp_list_to_dmaq(ci_netif* ni, ci_tcp_state* ts,
                                      oo_pkt_p head_id, 
                                      ci_ip_pkt_fmt* tail_pkt)
{
  ci_ip_pkt_fmt* pkt;
  oo_pktq* dmaq;
  oo_pkt_p pp;
  ef_vi* vi;
  int n;
#if CI_CFG_USE_PIO
  int rc;
  ci_uint8 order;
  ci_int32 offset;
  ci_pio_buddy_allocator* buddy;
#endif

  pp = head_id;
  n = 0;
  do {
    pkt = PKT_CHK(ni, pp);
    pp = pkt->next;
    check_tx_timestamping(ts, oo_pkt_af(pkt), pkt);
    ci_ip_set_mac_and_port(ni, &ts->s.pkt, pkt);
    ci_netif_pkt_hold(ni, pkt);
    if(CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_MSG_WARM ))
      pkt->flags |= CI_PKT_FLAG_MSG_WARM;
    __ci_netif_dmaq_insert_prep_pkt(ni, pkt);
    pkt->netif.tx.dmaq_next = pkt->next;
    ++n;
  } while( pkt != tail_pkt );

  ci_netif_dmaq_and_vi_for_pkt(ni, tail_pkt, &dmaq, &vi);

#if CI_CFG_USE_PIO
    /* pio_thresh is set to zero if PIO disabled on this stack, so don't
     * need to check NI_OPTS().pio here
     */
  order = ci_log2_ge(tail_pkt->pay_len, CI_CFG_MIN_PIO_BLOCK_ORDER);
  buddy = &ni->state->nic[tail_pkt->intf_i].pio_buddy;
  if( n == 1 && oo_pktq_is_empty(dmaq) &&
      ! ci_netif_may_ctpio(ni, tail_pkt->intf_i, tail_pkt->pay_len) &&
      ! (pkt->flags & CI_PKT_FLAG_INDIRECT) &&
      (ni->state->nic[tail_pkt->intf_i].oo_vi_flags & OO_VI_FLAGS_PIO_EN) ) {
    if( tail_pkt->pay_len <= NI_OPTS(ni).pio_thresh ) {
      if( (offset = ci_pio_buddy_alloc(ni, buddy, order)) >= 0 ) {
        if(CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_MSG_WARM )) {
          __ci_netif_dmaq_insert_prep_pkt_warm_undo(ni, tail_pkt);
          ci_pio_buddy_free(ni, &ni->state->nic[tail_pkt->intf_i].pio_buddy,
                            offset, order);
          return;
        }
        rc = ef_vi_transmit_copy_pio(vi, offset, PKT_START(tail_pkt),
                                     tail_pkt->buf_len, OO_PKT_ID(pkt));
        if( rc == 0 ) {
          CITP_STATS_NETIF_INC(ni, pio_pkts);
          ci_assert(tail_pkt->pio_addr == -1);
          tail_pkt->pio_addr = offset;
          tail_pkt->pio_order = order;
          return;
        }
        else {
          CITP_STATS_NETIF_INC(ni, no_pio_err);
          ci_pio_buddy_free(ni, buddy, offset, order);
          /* Continue and do normal send. */
        }
      }
      else {
        CI_DEBUG(CITP_STATS_NETIF_INC(ni, no_pio_busy));
      }
    }
    else {
      CI_DEBUG(CITP_STATS_NETIF_INC(ni, no_pio_too_long));
    }
  }
#endif

  if(CI_LIKELY( ! (ts->tcpflags & CI_TCPT_FLAG_MSG_WARM) )) {
    int is_fresh = oo_pktq_is_empty(dmaq);
    __oo_pktq_put_list(ni, dmaq, head_id, tail_pkt, n, netif.tx.dmaq_next);
    ci_netif_dmaq_shove2(ni, tail_pkt->intf_i, is_fresh);
  }
  else {
    __ci_netif_dmaq_insert_prep_pkt_warm_undo(ni, tail_pkt);
  }
}


#if CI_CFG_PORT_STRIPING
static void ci_ip_tcp_list_to_dmaq_striping(ci_netif* ni, ci_tcp_state* ts,
                                            oo_pkt_p head_id, 
                                            ci_ip_pkt_fmt* tail_pkt)
{
  int shove_intf_i[2] = {-1, -1};
  ci_ip_pkt_fmt* pkt;
  ci_ip_pkt_fmt* next_pkt;
  oo_pktq* dmaq;
  oo_pkt_p pp;
  ef_vi* vi;
  int n;

  pp = head_id;
  n = 0;
  do {
    pkt = PKT_CHK(ni, pp);
    check_tx_timestamping(ts, af, pkt);
    ci_ip_set_mac_and_port(ni, &ts->s.pkt, pkt);
    pp = pkt->next;
    ci_netif_pkt_hold(ni, pkt);
    if(CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_MSG_WARM ))
      pkt->flags |= CI_PKT_FLAG_MSG_WARM;
    __ci_netif_dmaq_insert_prep_pkt(ni, pkt);
    pkt->netif.tx.dmaq_next = pkt->next;
    ++n;

    if( pkt == tail_pkt ) {
      /* Queue remaining pkts */
      ci_netif_dmaq_and_vi_for_pkt(ni, tail_pkt, &dmaq, &vi);
      __oo_pktq_put_list(ni, dmaq, head_id, tail_pkt, n, netif.tx.dmaq_next);

      /* Remember which interfaces need shoving */
      ci_assert((shove_intf_i[pkt->netif.tx.intf_swap] == -1) || 
                (shove_intf_i[pkt->netif.tx.intf_swap] == pkt->intf_i));
      shove_intf_i[pkt->netif.tx.intf_swap] = pkt->intf_i;
      
      break;
    }
    else {
      next_pkt = PKT_CHK(ni, pp);
      if( pkt->netif.tx.intf_swap != next_pkt->netif.tx.intf_swap ) {
        /* Queue what we've got already before switching ports */
        ci_netif_dmaq_and_vi_for_pkt(ni, pkt, &dmaq, &vi);
        __oo_pktq_put_list(ni, dmaq, head_id, pkt, n, netif.tx.dmaq_next);
        
        /* Remember which interfaces need shoving */
        ci_assert((shove_intf_i[pkt->netif.tx.intf_swap] == -1) || 
                  (shove_intf_i[pkt->netif.tx.intf_swap] == pkt->intf_i));
        shove_intf_i[pkt->netif.tx.intf_swap] = pkt->intf_i;

        /* Reset state for next block to begin here */
        head_id = pp;
        n = 0;
      }
    }
  } while(1);

  /* We make no attempt to set the freshness hint when striping. */
  if( shove_intf_i[0] != -1 )
    ci_netif_dmaq_shove2(ni, shove_intf_i[0], 0 /*is_fresh*/);
  if( shove_intf_i[1] != -1 )
    ci_netif_dmaq_shove2(ni, shove_intf_i[1], 0 /*is_fresh*/);
}
#endif

static void ci_ip_send_tcp_list_loopback(ci_netif* ni, ci_tcp_state* ts,
                                         oo_pkt_p head_id,
                                         ci_ip_pkt_fmt* tail_pkt)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp;
  
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE);

  pp = head_id;
  do {
    pkt = PKT_CHK(ni, pp);
    pp = pkt->next;
    pkt->pf.tcp_tx.lo.tx_sock = S_SP(ts);
    pkt->pf.tcp_tx.lo.rx_sock = ts->local_peer;
    if( CI_UNLIKELY(OO_SP_IS_NULL(pkt->pf.tcp_tx.lo.rx_sock)) ) {
      ci_netif_pkt_release(ni, pkt);
      continue;
    }
    pkt->next = ni->state->looppkts;
    ni->state->looppkts = OO_PKT_ID(pkt);
    ni->state->n_looppkts++;
    LOG_NT(ci_log(NS_FMT "loopback TX pkt %d to %d", NS_PRI_ARGS(ni, &ts->s),
                  OO_PKT_FMT(pkt), OO_SP_FMT(pkt->pf.tcp_tx.lo.rx_sock)));
  } while( pkt != tail_pkt );

  /* really send all the packets */
  if( CI_UNLIKELY(OO_SP_IS_NULL(pkt->pf.tcp_tx.lo.rx_sock)) ) {
    ci_tcp_drop(ni, ts, ECONNRESET);
  }
  else {
    /* Normally, the packet contains ACK and window size.
     * Loopback in-packet ACK value is ignored - deliver it now! */
    if( SEQ_LE(ts->ack_trigger, ts->rcv_delivered) )
      ci_tcp_send_ack_loopback(ni, ts);
    if( !ni->state->in_poll )
      ci_netif_poll(ni);
  }
}

static void ci_ip_send_tcp_list(ci_netif* ni, ci_tcp_state* ts,
                                oo_pkt_p head_id, ci_ip_pkt_fmt* tail_pkt)
{
  ci_ip_pkt_fmt* pkt;
  int af = ipcache_af(&ts->s.pkt);
  
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(~ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE);

  if(CI_LIKELY( ts->s.pkt.status == retrrc_success &&
                oo_cp_ipcache_is_valid(ni, &ts->s.pkt) )) {
fast:
#if CI_CFG_PORT_STRIPING
    if( ts->tcpflags & CI_TCPT_FLAG_STRIPE ) {
      ci_assert(! (ts->tcpflags & CI_TCPT_FLAG_MSG_WARM));
      ci_assert(! (pkt->flags & CI_PKT_FLAG_INDIRECT));
      ci_ip_tcp_list_to_dmaq_striping(ni, ts, head_id, tail_pkt);
    }
    else
#endif
      ci_ip_tcp_list_to_dmaq(ni, ts, head_id, tail_pkt);
  }
  else {
    int prev_mtu = ts->s.pkt.mtu;

    /* Update the ipcache first - ask for ARP as early as possible. */
    cicp_user_retrieve(ni, &ts->s.pkt, &ts->s.cp);

    if( ts->s.pkt.status == retrrc_success && ts->s.pkt.mtu != prev_mtu )
      ci_tcp_tx_change_mss(ni, ts);

    if(CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_MSG_WARM ))
      return;

    do {
      if( ts->s.pkt.status == retrrc_success &&
          oo_cp_ipcache_is_valid(ni, &ts->s.pkt) )
        goto fast;

      pkt = PKT_CHK(ni, head_id);
      head_id = pkt->next;

      check_tx_timestamping(ts, af, pkt);
      ci_ip_send_tcp_slow(ni, ts, pkt);
      if( pkt == tail_pkt )
        break;
    } while( 1 );
  }
}

/* Initialise the receive window, by setting tcp_rcv_wnd_right_edge_sent
 * for the first time.  Called when rcv_nxt is first set.
 */
void ci_tcp_init_rcv_wnd(ci_tcp_state* ts, const char* caller)
{
  tcp_rcv_wnd_right_edge_sent(ts) = tcp_rcv_nxt(ts) + ts->rcv_window_max;
  ci_tcp_calc_rcv_wnd(ts, caller);
}


/*
** Fill out the mss option on a given packet
*/
ci_inline int ci_tcp_tx_opt_mss(ci_uint8** opt, ci_uint16 amss)
{
  *(*opt) = CI_TCP_OPT_MSS;
  *(*opt+1) = 0x4;
  *(ci_uint16*)(*opt+2) = CI_BSWAP_BE16(amss);
  *opt += 4;
  return 4;
}

/*
** Fill out the window scale option on a given packet
*/
ci_inline int ci_tcp_tx_opt_wscl(ci_uint8** opt, ci_uint8 wscl)
{
  *(*opt) = CI_TCP_OPT_WINSCALE;
  *(*opt+1) = 0x3;
  *(*opt+2) = wscl;
  *(*opt+3) = CI_TCP_OPT_NOP;
  *opt += 4;
  return 4;
}

/*
** Set SackOK option on a given packet
*/
ci_inline int ci_tcp_tx_opt_sack_perm(ci_uint8** opt)
{
  (*opt)[0] = CI_TCP_OPT_SACK_PERM;
  (*opt)[1] = 0x2;
  *opt += 2;
  return 2;
}


ci_inline bool rob_is_empty(ci_netif* netif, ci_tcp_state* ts)
{
  if( ci_ip_queue_is_empty(&ts->rob) )
    return true;
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  if( SEQ_LE(PKT_CHK(netif, ts->rob.tail)->pf.tcp_rx.end_seq,
             tcp_rcv_nxt(ts)) )
    return true;
#endif
  return false;
}


/*
** Set Sack (and DSACK) option on a given packet
** used_length is length of existing options.
*/
static int ci_tcp_tx_opt_sack(ci_uint8** opt, int used_length,
                              ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_pkt_queue* rob = &ts->rob;
  ci_ip_pkt_fmt* pkt;
  int i, j = 0;
  oo_pkt_p used[CI_TCP_SACK_MAX_BLOCKS];
  oo_pkt_p cid;
  ci_uint32 *sack_blocks;
  int block = 0;
  ci_uint32 start_be32, end_be32;
  int af = ipcache_af(&ts->s.pkt);

  ci_assert(ts->tcpflags & CI_TCPT_FLAG_SACK);

  /* If there is nothing to SACK or no place for SACK option, just return. */
  if( (OO_PP_EQ(ts->dsack_block, OO_PP_INVALID) && rob_is_empty(netif, ts)) ||
      used_length + 5 + 8 > CI_TCP_MAX_OPTS_LEN ){
    /* have to clear dsack_block as we're not going to send it now */
    ts->dsack_block = OO_PP_INVALID;
    return 0;
  }
  *(*opt + 1) = *(*opt) = CI_TCP_OPT_NOP;
  *(*opt + 2) = CI_TCP_OPT_SACK;
  *(*opt + 3) = 0x2;
  sack_blocks = (ci_uint32 *)(*opt + 4);

#define ADD_SACK_BLOCK(id, set_use, logmessage)                         \
  do {                                                                  \
    sack_blocks[2 * block] = start_be32;                                \
    sack_blocks[2 * block + 1] = end_be32;                              \
    block++;                                                            \
    if( set_use )                                                       \
      used[j++] = id;                                                   \
    LOG_TL(log(LNT_FMT logmessage " %x - %x", LNT_PRI_ARGS(netif, ts),  \
               CI_BSWAP_BE32(start_be32), CI_BSWAP_BE32(end_be32)));    \
  } while(0)
  /* DSACK */
  if( NI_OPTS(netif).use_dsack && 
      ! OO_PP_EQ(ts->dsack_block, OO_PP_INVALID) ) {
    start_be32 = CI_BSWAP_BE32(ts->dsack_start);
    end_be32 = CI_BSWAP_BE32(ts->dsack_end);
    ADD_SACK_BLOCK(OO_PP_INVALID, 0, "DSACKing");
    if( ! OO_PP_EQ(ts->dsack_block, OO_PP_NULL) &&
        used_length + 4 + 8 * 2  < CI_TCP_MAX_OPTS_LEN) {
      pkt = PKT_CHK(netif, ts->dsack_block);
      start_be32 = PKT_IPX_TCP_HDR(af, pkt)->tcp_seq_be32;
      end_be32 = CI_BSWAP_BE32(PKT_TCP_RX_ROB(pkt)->end_block_seq);
      ADD_SACK_BLOCK(ts->dsack_block, 1, "DSACK companion SACKing");
    }
    ts->dsack_block = OO_PP_INVALID;
  }

  /* Fill in blocks defined in RFC. We can't break from this for() on the
   * first invalid entry. */
  for( i = 0; i <= CI_TCP_SACK_MAX_BLOCKS &&
       used_length + 4 + 8 * (block + 1) < CI_TCP_MAX_OPTS_LEN;
       i++ ) {
    if( OO_PP_NOT_NULL(ts->last_sack[i]) ) {
      pkt = PKT_CHK(netif, ts->last_sack[i]);
      if( j > 0 && OO_PP_EQ(OO_PKT_P(pkt), used[0]) )
        continue;
      start_be32 = PKT_IPX_TCP_HDR(af, pkt)->tcp_seq_be32;
      end_be32 = CI_BSWAP_BE32(PKT_TCP_RX_ROB(pkt)->end_block_seq);
      ADD_SACK_BLOCK(ts->last_sack[i], 1, "SACKing (last_sack)");
    }
  }

  /*
   * Now, if there is any space, pick up any other block from reorder
   * buffer
   */
  cid = rob->head;
  while( OO_PP_NOT_NULL(cid) &&
         used_length + 4 + 8 * (block + 1) < CI_TCP_MAX_OPTS_LEN ) {
    pkt = PKT_CHK(netif, cid);
#if CI_CFG_TCP_OFFLOAD_RECYCLER
    if( SEQ_LE(pkt->pf.tcp_rx.end_seq, tcp_rcv_nxt(ts)) )
      goto next_block;
#endif
    for( i = 0; i < j; i++ ) {
      if( OO_PP_EQ(cid, used[i]) )
        goto next_block;
    }
    start_be32 = PKT_IPX_TCP_HDR(af, pkt)->tcp_seq_be32;
    end_be32 = CI_BSWAP_BE32(PKT_TCP_RX_ROB(pkt)->end_block_seq);
    ADD_SACK_BLOCK(cid, 1, "SACKing (ROB)");
  next_block:
    cid = PKT_TCP_RX_ROB(pkt)->next_block;
  }

  ts->last_sack[0] = OO_PP_NULL;
  for( i = 0; i < j; i++ )
    ts->last_sack[i + 1] = used[i];
  for( ; i < CI_TCP_SACK_MAX_BLOCKS; i++ )
    ts->last_sack[i + 1] = OO_PP_NULL;
  *(*opt + 3) = 2 + 8 * block;
  *opt += 4 + 8 * block;
  LOG_TV(log(LNT_FMT "SACKing %d blocks", LNT_PRI_ARGS(netif, ts), block));
  return 4 + 8 * block;
#undef ADD_SACK_BLOCK
}


/**
 * If we are in urgent mode set the urgent pointer in the tcp header
 * appropriately. If not in urgent mode, set [snd_up = snd_una] to avoid
 * sequence number wraparound problems.
 */
ci_inline void
ci_tcp_tx_set_urg_ptr(ci_tcp_state* ts, ci_netif* netif, ci_tcp_hdr* tcp)
{
  /*! \TODO: this test could be removed from the fast path */
  if(CI_LIKELY( SEQ_GE(tcp_snd_nxt(ts) + ts->snd_delegated, tcp_snd_up(ts)) )) {
    tcp_snd_up(ts) = tcp_snd_una(ts);
  }
  else {
    tcp->tcp_flags |= CI_TCP_FLAG_URG;
    tcp->tcp_urg_ptr_be16 = tcp_snd_urg_off(ts, tcp) - NI_OPTS(netif).urg_rfc;
    tcp->tcp_urg_ptr_be16 = CI_BSWAP_BE16(tcp->tcp_urg_ptr_be16);
    LOG_URG(ci_log("%s: snd_nxt=%u, snd_up=%u, urg_off=%u flags=%X",
                   __FUNCTION__, tcp_snd_nxt(ts), tcp_snd_up(ts),
                   CI_BSWAP_BE16(tcp->tcp_urg_ptr_be16), tcp->tcp_flags));
  }
}



ci_inline void ci_tcp_tx_cwv_idle(ci_netif* netif, ci_tcp_state* ts)
{
#if CI_CFG_CONGESTION_WINDOW_VALIDATION
  unsigned win, i;

  /* congestion window validation RFC2861 */
  /* has there been >rto time since the last packet was sent? */
  i = ci_tcp_time_now(netif) - ts->t_last_sent;
  if( i > ts->rto ) {
    /* sender idle for more than an RTO */
    /* set the ssthresh to 3/4 of cwnd, if larger than ssthresh */
    win = (3*ts->cwnd)>>2u;
    ts->ssthresh = CI_MAX(ts->ssthresh, win);
    /* Not sure why we care about snd_wnd: perhaps because otherwise
       the change in cwnd will have no effect if we're limited by
       snd_wnd at the moment? */
    ts->cwnd = CI_MIN(ts->cwnd, tcp_snd_wnd(ts));
    do {
    /* half cwnd for each rto that it has been idle */
      ts->cwnd = ts->cwnd >> 1u;
      i -= ts->rto;
    } while( i > ts->rto );
#if CI_CFG_CONGESTION_WINDOW_VALIDATION_DELACK_SCALING
    /* make sure cwnd doesn't go below one segment per delack */
    ts->cwnd = CI_MAX(ts->cwnd, ts->smss * 2);
#else
    /* make sure cwnd doesn't go below one segment */
    ts->cwnd = CI_MAX(ts->cwnd, ts->smss);
#endif
    ts->cwnd = CI_MAX(ts->cwnd, NI_OPTS(netif).min_cwnd);
    /* Record this time to work out if app ltd */
    ts->t_last_full = ci_tcp_time_now(netif);
    /* Reset cwnd_used to zero for app ltd calculations */
    ts->cwnd_used = 0;
    ci_assert(ts->cwnd >= tcp_eff_mss(ts));
  }
#endif
}

ci_inline void ci_tcp_tx_cwv_app_lmtd(ci_netif* netif, ci_tcp_state* ts)
{
#if CI_CFG_CONGESTION_WINDOW_VALIDATION
  unsigned win;

  /* This is called to see if the sender is limited by the application */

  if( ci_tcp_inflight(ts) + ts->smss >= CI_MIN(ts->cwnd, tcp_snd_wnd(ts)) ) {
    /* Window is exercised, so network limited.  Record time for later
     * comparisons.
     */
    ts->t_last_full = ci_tcp_time_now(netif);
  }
  else if( ci_tcp_sendq_is_empty(ts) ) {
    /* Window not full and no more data to send => app limited.  Work out
     * how much of the cwnd we've actually used.
     */
    ts->cwnd_used = CI_MAX(ts->cwnd_used, ci_tcp_inflight(ts));

    /* If it has been an rto since it was last fully utilised... */
    if( ci_tcp_time_now(netif) - ts->t_last_full > ts->rto ) {
      /* ... increase ssthresh to 3/4 of cwnd (if larger) */
      win = (3*ts->cwnd) >> 2u;
      ts->ssthresh = CI_MAX(ts->ssthresh, win);
      /* Not sure why we care about snd_wnd: perhaps because otherwise the
       * change in cwnd will have no effect if we're limited by snd_wnd at
       * the moment.
       */
      win = CI_MIN(ts->cwnd, tcp_snd_wnd(ts));
      /* cwnd becomes average of cwnd and cwnd_used */
      ts->cwnd = CI_MAX(ts->smss, (win+ts->cwnd_used) >> 1u);
      ts->cwnd = CI_MAX(ts->cwnd, NI_OPTS(netif).min_cwnd);
      ci_assert(ts->cwnd >= tcp_eff_mss(ts));
      /* record this time for next comparison */
      ts->t_last_full = ci_tcp_time_now(netif);
      /* reset the cwnd_used */
      ts->cwnd_used = 0;
    }
  }
#endif
}


static void ci_tcp_tx_reset_q_end(ci_netif* ni, ci_tcp_state* ts,
                                  ci_ip_pkt_queue* q)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p id;
  ci_assert(ci_netif_is_locked(ni));
  
  /* This adjusts the "end" pointer in the offbuf to reflect a change
     in the mss.  NB: it may result in existing payload being past the
     end of the payload */

  for( id = q->head; OO_PP_NOT_NULL(id); id = pkt->next ) {
    pkt = PKT_CHK(ni, id);
    /* there's no need to do the equivalent for indirect (aka zero-copy)
     * packets because the checks done at the time of data insertion and
     * splitting on such packets already include the current mss from the tcp
     * state - the correct mss is not (effectively) embedded in the packet
     * metadata as it is for non-zc packets */
    if(CI_LIKELY( ! (pkt->flags & CI_PKT_FLAG_INDIRECT) ))
      ci_tcp_tx_pkt_set_end(ts, pkt);
  }
}


void ci_tcp_tx_change_mss(ci_netif* ni, ci_tcp_state* ts)
{
  int prev_eff_mss = tcp_eff_mss(ts);
  ci_assert(ci_netif_is_locked(ni));

  ci_tcp_set_eff_mss(ni, ts);

  LOG_TL(ci_log(LNTS_FMT "%s: before=%d after=%d", LNTS_PRI_ARGS(ni, ts),
                __FUNCTION__, prev_eff_mss, tcp_eff_mss(ts)));

  ci_tcp_tx_reset_q_end(ni, ts, &ts->send);
  ci_tcp_tx_reset_q_end(ni, ts, &ts->retrans);

  if( tcp_eff_mss(ts) < (unsigned) prev_eff_mss &&
      ! ci_ip_queue_is_empty(&ts->retrans) ) {

    /* Use RTO recovery to retransmit reformatted packets. */
    ts->congstate = CI_TCP_CONG_RTO_RECOV;
    ts->cwnd_extra = 0;
    ci_tcp_clear_sacks(ni, ts);
    ts->congrecover = tcp_snd_nxt(ts);
    ci_tcp_rto_restart(ni, ts);
    ci_tcp_retrans_recover(ni, ts, 0);
  }
}


static int ci_tcp_tx_insert_syn_options(ci_netif* ni, ci_uint16 amss,
                                        unsigned optflags, unsigned rcv_wscl,
                                        ci_uint8** opt)
{
  int optlen = 0;

  /* Must send MSS (RFC1122). */
  optlen += ci_tcp_tx_opt_mss(opt, amss);

  /* Window scale (RFC1323). */
  if( optflags & CI_TCPT_FLAG_WSCL )
    optlen += ci_tcp_tx_opt_wscl(opt, (ci_uint8)rcv_wscl);

  /* SACK (RFC2018). */
  if( optflags & CI_TCPT_FLAG_SACK )
    optlen += ci_tcp_tx_opt_sack_perm(opt);

#if CI_CFG_PORT_STRIPING
  if( optflags & CI_TCPT_FLAG_STRIPE ) {
    (*opt)[0] = (ci_uint8) NI_OPTS(ni).stripe_tcp_opt;
    (*opt)[1] = 2;
    *opt += 2;
    optlen += 2;
  }
#endif

  /* Pad to dword boundary. */
  while( optlen & 3 ) {
    *(*opt)++ = CI_TCP_OPT_END;
    ++optlen;
  }

  return optlen;
}


/*
** called to enqueue a packet with no data (i.e. SYN/FIN) the segment
** is placed on the TX queue and so is reliably transmitted
*/
void ci_tcp_enqueue_no_data(ci_tcp_state* ts, ci_netif* netif,
                            ci_ip_pkt_fmt* pkt)
{
  ci_tcp_hdr* thdr;
  int af = ipcache_af(&ts->s.pkt);
  int optlen = tcp_ipx_outgoing_opts_len(af, ts);

  ci_assert(ts);
  ci_assert(netif);
  ASSERT_VALID_PKT_ID(netif, OO_PKT_P(pkt));
  /* ASSERT_VALID_PKT(netif, pkt); iov_len may be -4 */
  ci_assert(pkt->refcount == 1 ); /* packet will be consumed. */
  ci_assert(TS_IPX_TCP(ts)->tcp_flags & (CI_TCP_FLAG_SYN|CI_TCP_FLAG_FIN));

  oo_tx_pkt_layout_init(pkt);
  ci_ipcache_update_flowlabel(netif, &ts->s);
  ci_pkt_init_from_ipcache(pkt, &ts->s.pkt);

  /* options for connection negotiation */
  thdr = PKT_IPX_TCP_HDR(af, pkt);
  if( TS_IPX_TCP(ts)->tcp_flags & CI_TCP_FLAG_SYN ) {
    ci_uint8* opt = CI_TCP_HDR_OPTS(thdr);
    opt += optlen;
    optlen += ci_tcp_tx_insert_syn_options(netif, ts->amss,
                                           ts->tcpflags, ts->rcv_wscl, &opt);

    /* If we don't get timestamps, we'll need to calculate RTT without
     * them.  Let's prepare: */
    ci_tcp_set_rtt_timing(netif, ts, tcp_enq_nxt(ts));
  }

  CI_TCP_HDR_SET_LEN(thdr, sizeof(*thdr) + optlen);

  pkt->buf_len = ( oo_tx_ether_hdr_size(pkt) + CI_IPX_HDR_SIZE(af)
                   + sizeof(ci_tcp_hdr) + optlen );
  pkt->pay_len = pkt->buf_len;
  oo_offbuf_init(&pkt->buf, PKT_START(pkt) + pkt->buf_len, 0);
  pkt->flags &= CI_PKT_FLAG_NONB_POOL;
  ASSERT_VALID_PKT(netif, pkt);

  pkt->pf.tcp_tx.start_seq = tcp_enq_nxt(ts);
  tcp_enq_nxt(ts) += 1;
  pkt->pf.tcp_tx.end_seq = tcp_enq_nxt(ts);
  pkt->pf.tcp_tx.block_end = OO_PP_NULL;

  ci_ip_queue_enqueue(netif, &ts->send, pkt);
  ++ts->send_in;

  LOG_TC(log(LNTS_FMT "enqueue ["CI_TCP_FLAGS_FMT"] seq=%x",
             LNTS_PRI_ARGS(netif, ts),
             CI_TCP_HDR_FLAGS_PRI_ARG(TX_PKT_IPX_TCP(af, pkt)),
             tcp_enq_nxt(ts) - 1));

  ci_tcp_tx_advance(ts, netif);
}

/* Rewrite the first SYN packet as a SYNACK for simultaneous open */
int ci_tcp_send_sim_synack(ci_netif* netif, ci_tcp_state *ts)
{
  ci_ip_pkt_fmt* pkt;
  ci_tcp_hdr* tcp;
  int optlen = 0;
  ci_uint8* opt;
  int af = ipcache_af(&ts->s.pkt);

  ci_assert(netif);
  ci_assert(ts);

  /* check txq is non empty */
  ci_assert(!ci_ip_queue_is_empty(&ts->retrans));
  ci_assert(ci_ip_queue_is_valid(netif, &ts->retrans));

  pkt = PKT_CHK(netif, ts->retrans.head);
  tcp = TX_PKT_IPX_TCP(af, pkt);

  /* check first packet on txq is the SYN */
  ci_assert(tcp->tcp_flags & CI_TCP_FLAG_SYN);


  /* Check whether this packet is already being
  ** trasmitted.  If it is, then we can't transmit it again here.
  */
  if( pkt->flags & CI_PKT_FLAG_TX_PENDING ) {
    LOG_U(ci_log(LNT_FMT
          "packet %d s=%x-%x already posted, I choose not to send a synack",
          LNT_PRI_ARGS(netif,ts), S_FMT(ts), pkt->pf.tcp_tx.start_seq,
          pkt->pf.tcp_tx.end_seq));
    return 0;
  }

  /* fill out options */
  opt = CI_TCP_HDR_OPTS(tcp);
  if( ts->tcpflags & CI_TCPT_FLAG_TSO )
    optlen += ci_tcp_tx_opt_tso(&opt, ci_tcp_time_now(netif), 0);

  optlen += ci_tcp_tx_insert_syn_options(netif, ts->amss,
                                         ts->tcpflags, ts->rcv_wscl, &opt);

  CI_TCP_HDR_SET_LEN(tcp, sizeof(*tcp) + optlen);
  tcp->tcp_flags |= CI_TCP_FLAG_ACK;

  oo_offbuf_init(&pkt->buf,
                 (uint8_t*) oo_tx_ip_data(pkt) + sizeof(ci_tcp_hdr) + optlen,
                 0);

  LOG_TC(log(LNTS_FMT "simultaneous SYN-ACK ["CI_TCP_FLAGS_FMT"]",
             LNTS_PRI_ARGS(netif, ts),
             CI_TCP_HDR_FLAGS_PRI_ARG(TX_PKT_IPX_TCP(af, pkt))));

  /* Set length of the first (single) segment */
  pkt->buf_len = pkt->pay_len = 
    (ci_int32)(oo_offbuf_ptr(&pkt->buf) - PKT_START(pkt));

  /* send the newly formed packet from the retransmission queue */
  ci_tcp_retrans_one(ts, netif, pkt);
  return 1;
}


/* Send a packet from a SYNRECV.  Used to send or retransmit SYN-ACK, ACK
 * or FIN.
 *
 * [ipcache] is optional, and is supplied when the caller happens to
 * already have up-to-date info about how to reach the other end.  Only
 * reason it is needed is for efficiency.
 */
int ci_tcp_synrecv_send(ci_netif* netif, ci_tcp_socket_listen* tls,
                        ci_tcp_state_synrecv* tsr,
                        ci_ip_pkt_fmt* pkt, ci_uint8 tcp_flags,
                        ci_ip_cached_hdrs* ipcache)
{
  ci_ip_cached_hdrs ipcache_storage;
  ci_tcp_hdr* thdr;
  ci_ipx_hdr_t* iphdr;
  ci_uint8* opt;
  ci_uint32 seq;
  int rc, optlen;
  int af = CI_IS_ADDR_IP6(tsr->l_addr) ? AF_INET6 : AF_INET;

  ci_assert(netif);
  ci_assert(tls);
  /* CLOSED state is acceptable if called from __ci_tcp_listen_shutdown() */
  ci_assert(tls->s.b.state == CI_TCP_LISTEN || tls->s.b.state == CI_TCP_CLOSED);
  ci_assert(tsr);
  if( ipcache != NULL ) {
    ci_assert(ipcache->status == retrrc_success ||
              ipcache->status == retrrc_nomac ||
              (ipcache->status == retrrc_localroute &&
               (ipcache->flags & CI_IP_CACHE_IS_LOCALROUTE)));
    ci_assert(CI_IPX_ADDR_EQ(ipcache_raddr(ipcache), tsr->r_addr));
    ci_assert(CI_IPX_ADDR_EQ(ipcache_laddr(ipcache), tsr->l_addr));
    ci_assert_equal(ipcache->dport_be16, tsr->r_port);
  }

  LOG_TC(log(LNT_FMT "SYNRECV ["CI_TCP_FLAGS_FMT"] isn=%08x "
             "rcv=%08x-%08x", LNT_PRI_ARGS(netif, tls),
             CI_TCP_FLAGS_PRI_ARG(tcp_flags),
             tsr->snd_isn, tsr->rcv_nxt,
             tsr->rcv_nxt +
             ci_tcp_rcvbuf2window(tls->s.so.rcvbuf, tsr->amss,
                                  tsr->rcv_wscl)));

  ci_assert(pkt);

  /* hdrs for SYN-ACK */
  oo_tx_pkt_layout_init(pkt);
  iphdr = oo_tx_ipx_hdr(af, pkt);
#if CI_CFG_IPV6
  if( CI_IS_ADDR_IP6(tsr->l_addr) ) {
    oo_tx_ether_type_set(pkt, CI_ETHERTYPE_IP6);
  }
  else
#endif
  {
    oo_tx_ether_type_set(pkt, CI_ETHERTYPE_IP);
    iphdr->ip4.ip_check_be16 = 0;
    iphdr->ip4.ip_id_be16 = 0;
  }
  ci_ipx_hdr_init_fixed(oo_tx_ipx_hdr(af, pkt), af, IPPROTO_TCP,
                        sock_cp_ttl_hoplimit(af, &tls->s.cp),
                        sock_tos_tclass(af, &tls->s.cp));
  TX_PKT_SET_SADDR(af, pkt, tsr->l_addr);
  TX_PKT_SET_DADDR(af, pkt, tsr->r_addr);

  /* If sending or retransmitting a SYN, we want to use the ISN.  Otherwise
  ** the only sequence number that can be sent from SYNRECV is the ISN+1.
  */
  seq = (tcp_flags & CI_TCP_FLAG_SYN) ? tsr->snd_isn : tsr->snd_isn + 1;

  thdr = PKT_IPX_TCP_HDR(af, pkt);
  thdr->tcp_urg_ptr_be16 = 0;
  thdr->tcp_source_be16 = tsr->l_port;
  thdr->tcp_dest_be16   = tsr->r_port;
  thdr->tcp_seq_be32    = CI_BSWAP_BE32(seq);
  thdr->tcp_ack_be32    = CI_BSWAP_BE32(tsr->rcv_nxt);
  thdr->tcp_flags       = tcp_flags;

  /* options */
  opt = CI_TCP_HDR_OPTS(thdr);
  optlen = 0;

  /* align TSO option so that tcp_tx_finish can overwrite it if need be */
  if( tsr->tcpopts.flags & CI_TCPT_FLAG_TSO ) {
    unsigned now;
    if( tsr->tcpopts.flags & CI_TCPT_FLAG_SYNCOOKIE )
      now = tsr->timest;
    else
      now = ci_tcp_time_now(netif);
    optlen += ci_tcp_tx_opt_tso(&opt, now, tsr->tspeer);
  }

  if( ipcache == NULL ) {
    ipcache = &ipcache_storage;
    ci_ip_cache_init(ipcache, CI_ADDR_AF(tsr->l_addr));
    ci_ip_send_pkt_lookup(netif, &tls->s.cp, pkt, ipcache);
  }

  TX_PKT_TTL(af, pkt) = ipcache_ttl(ipcache);

#if CI_CFG_IPV6
  if( IS_AF_INET6(af) && tls->s.s_flags & CI_SOCK_FLAG_AUTOFLOWLABEL_REQ ) {
    ci_uint32 flowlabel = ci_make_flowlabel(netif, tsr->l_addr,
        thdr->tcp_source_be16, tsr->r_addr, thdr->tcp_dest_be16, IPPROTO_TCP);
    ci_ip6_set_flowlabel_be32(&ipcache->ipx.ip6, flowlabel);
    TX_PKT_SET_FLOWLABEL(af, pkt, flowlabel);
  }
#endif

  if( (tcp_flags & CI_TCP_FLAG_SYN) &&
      (ipcache->status == retrrc_success ||
       ipcache->status == retrrc_nomac ||
       OO_SP_NOT_NULL(tsr->local_peer)) ) {
    tsr->amss = ci_tcp_amss(netif, &tls->c, ipcache, __func__);
    optlen += ci_tcp_tx_insert_syn_options(netif, tsr->amss,
                                           tsr->tcpopts.flags,
                                           tsr->rcv_wscl, &opt);
    pkt->pf.tcp_tx.sock_id = OO_SP_NULL;
  }
  /* NB. If [ipcache->status] has some other value, then packet won't be
   * sent in any case.
   */

  thdr->tcp_window_be16 = ci_tcp_calc_rcv_wnd_syn(tls->s.so.rcvbuf, tsr->amss,
                                                  tsr->rcv_wscl);
  thdr->tcp_window_be16 = CI_BSWAP_BE16(thdr->tcp_window_be16);

  ci_tcp_ipx_hdr_init(af, iphdr,
                      CI_IPX_HDR_SIZE(af) + sizeof(ci_tcp_hdr) + optlen);
  CI_TCP_HDR_SET_LEN(thdr, sizeof(*thdr) + optlen);

  pkt->buf_len = ( oo_tx_ether_hdr_size(pkt) + CI_IPX_HDR_SIZE(af)
                   + sizeof(ci_tcp_hdr) + optlen );
  pkt->pay_len = pkt->buf_len;

  if( OO_SP_NOT_NULL(tsr->local_peer) ) {
    ci_ip_local_send(netif, pkt, S_SP(tls), tsr->local_peer);
    rc = 0;
  }
  else {
    rc = ci_ip_send_pkt_send(netif, &tls->s.cp, pkt, ipcache);
    ci_netif_pkt_release(netif, pkt);
  }
  if(CI_UNLIKELY( rc != 0 ))
    CITP_STATS_NETIF(++netif->state->stats.synrecv_send_fails);
  else
    CI_TCP_STATS_INC_OUT_SEGS(netif);
  return rc;
}


/* Retransmit the indicated packet, returns 0 on success, 1 if packet
   tx in progress */
int ci_tcp_retrans_one(ci_tcp_state* ts, ci_netif* netif, ci_ip_pkt_fmt* pkt)
{
  ci_tcp_hdr* tcp;
  int af = ipcache_af(&ts->s.pkt);

  ci_assert(ts);
  ci_assert(netif);

  /* Return code 1 means packet in progress */
  if( pkt->flags & CI_PKT_FLAG_TX_PENDING )  return 1;

  /* If we're going to reset any connection that has to retransmit,
   * just pretend here that we've sent it, and then it will either (i)
   * sort itself out due to a delay or reordering in the network; or
   * (ii) RTO and we will reset.  The check on congstate avoids
   * messing with the non-fast-recovery callers of ci_tcp_retrans_one()
   */
  if( NI_OPTS(netif).rst_delayed_conn &&
      ts->congstate == CI_TCP_CONG_FAST_RECOV )
    return 1;

  CITP_STATS_NETIF_INC(netif, retransmits);
  ++ts->stats.total_retrans;

  tcp = TX_PKT_IPX_TCP(af, pkt);

  /* To retransmit a packet it has to have already been sent.  And we
  ** should only retransmit segments that consume sequence space.
  */
  ci_assert(SEQ_LT(pkt->pf.tcp_tx.start_seq, tcp_snd_nxt(ts)) &&
            SEQ_LE(pkt->pf.tcp_tx.end_seq, tcp_snd_nxt(ts)));

  /* The sequence space consumed should match the bytes in the buffer
  ** (unless it contains a SYN or FIN).
  */
  if ( af == AF_INET && !(tcp->tcp_flags & (CI_TCP_FLAG_SYN|CI_TCP_FLAG_FIN)))
    ci_assert_equal(CI_IPX_HDR_SIZE(af) + sizeof(*tcp) + CI_TCP_HDR_OPT_LEN(tcp)
                    + SEQ_SUB(pkt->pf.tcp_tx.end_seq, pkt->pf.tcp_tx.start_seq),
                    oo_tx_l3_len(pkt));

  /* place TCP options, ECN, and take RTT on outgoing packet */
  ci_tcp_tx_finish(netif, ts, pkt);

  /* set the urgent pointer */
  ci_tcp_tx_set_urg_ptr(ts, netif, tcp);

  /* Update window (with silly window avoidance). */
  if( ts->s.b.state != CI_TCP_SYN_SENT )
    ci_tcp_calc_rcv_wnd(ts, "retrans_one");
  if( SEQ_EQ(pkt->pf.tcp_tx.start_seq, ts->timed_seq) )
    ci_tcp_clear_rtt_timing(ts);    /* Per RFC6298/3, RTT estimation is
                                       ambiguous if retransmits happened. */

  /* Finish-off the TCP header (using latest ack and window). */
  tcp->tcp_ack_be32 = CI_BSWAP_BE32(tcp_rcv_nxt(ts));
  tcp->tcp_window_be16 = TS_IPX_TCP(ts)->tcp_window_be16;

  ci_tcp_ipx_hdr_init(af, oo_tx_ipx_hdr(af, pkt), oo_tx_l3_len(pkt));

  LOG_TL(log(LNT_FMT "RETRANSMIT id=%d ["CI_TCP_FLAGS_FMT"] s=%08x-%08x "
             "paylen=%d", LNT_PRI_ARGS(netif,ts), OO_PKT_FMT(pkt),
             CI_TCP_HDR_FLAGS_PRI_ARG(tcp), pkt->pf.tcp_tx.start_seq,
             pkt->pf.tcp_tx.end_seq,
             ci_tx_pkt_ipx_tcp_payload_len(af, pkt));
         log(LNT_FMT"  "TCP_RCV_FMT,
             LNT_PRI_ARGS(netif, ts), TCP_RCV_PRI_ARG(ts));
         log(LNT_FMT"  "TCP_SND_FMT,
             LNT_PRI_ARGS(netif, ts), TCP_SND_PRI_ARG(ts)));

#if CI_CFG_CONGESTION_WINDOW_VALIDATION
  ts->t_last_sent = ci_tcp_time_now(netif);
#endif

#if CI_CFG_TIMESTAMPING
  if( (pkt->flags & (CI_PKT_FLAG_RTQ_RETRANS | CI_PKT_FLAG_TX_TIMESTAMPED)) ==
      CI_PKT_FLAG_TX_TIMESTAMPED )
    pkt->pf.tcp_tx.first_tx_hw_stamp = pkt->hw_stamp;
#endif
  ci_tcp_tx_maybe_do_striping(pkt, ts);
  __ci_ip_send_tcp(netif, pkt, ts);
  CI_TCP_STATS_INC_OUT_SEGS(netif);

  /* here we must increment TcpRetransSegs */
  CI_TCP_STATS_INC_RETRAN_SEGS( netif );
  CI_IP_SOCK_STATS_ADD_TXBYTE(ts, TX_PKT_LEN(pkt));
  CI_IP_SOCK_STATS_INC_RETX( ts );

  if(CI_UNLIKELY( ts->s.b.state == CI_TCP_CLOSED ))
    return 1; /* we've closed the connection as a result of send() */

  /* caller must have setup or already have a pending RTO timer */
  ci_assert( ci_ip_timer_pending(netif, &ts->rto_tid) );

  return 0;
}


/* Counts the number of segments in the retransmit queue that have not been
 * SACKed.  TODO: it might be beneficial to keep track of the number of
 * un-SACKed segments/blocks, and so avoid having to walk the list here in
 * order to count them. */
int ci_tcp_unsacked_segments_in_flight(ci_netif* ni, ci_tcp_state* ts)
{
  int unsacked = 0;
  oo_pkt_p pp;
  ci_ip_pkt_fmt *pkt;

  ci_assert(ts->tcpflags & CI_TCPT_FLAG_SACK);

  pp = ts->retrans.head;
  while( OO_PP_NOT_NULL(pp) ) {
    pkt = PKT_CHK(ni, pp);
    if( pkt->flags & CI_PKT_FLAG_RTQ_SACKED )
      pkt = PKT_CHK(ni, pkt->pf.tcp_tx.block_end);
    else
      ++unsacked;
    pp = pkt->next;
  }

  LOG_TL(log(LNT_FMT "unsacked=%d", LNT_PRI_ARGS(ni, ts), unsacked));

  return unsacked;
}


/* Retransmit packets starting at [ts->retrans_ptr].  The number of packets
** to transmit is limited by [seq_limit], which places a limit on the
** number of bytes of sequence space that may be injected into the network.
**
** We also stop retransmitting if we reach [ts->congrecover].  If
** [before_sacked_only] is true, then after the first we only continue
** retransmitting packets that are before a SACK block.
**
** Returns true if we should now exit recovery (reached congrecover or end
** of retransmit queue).  False otherwise.
**
** Currently packets are taken contiguously from the retransmit queue.  In
** future we should not retransmit packets that have been SACKed.
*/
int ci_tcp_retrans(ci_netif* ni, ci_tcp_state* ts, int seq_limit,
                   int before_sacked_only, int* seq_used)
{
  ci_ip_pkt_fmt* pkt;
  int at_start_of_block = 0;
  int seq_space, is_fin;

  /* Mustn't call this when there's nothing to send. */
  ci_assert(OO_PP_NOT_NULL(ts->retrans_ptr));

  *seq_used = 0;
  pkt = PKT_CHK(ni, ts->retrans_ptr);
  LOG_TV(log(LPF "rtq: %d -> %d ->...-> %d, %d packets", OO_PKT_FMT(pkt),
            OO_PKT_FMT(pkt), OO_PP_FMT(ts->retrans.tail), ts->retrans.num));

  while( 1 ) {
    /* Skip SACKed packets. */
    if( pkt->flags & CI_PKT_FLAG_RTQ_SACKED ) {
      pkt = PKT_CHK(ni, pkt->pf.tcp_tx.block_end);
      ts->retrans_ptr = pkt->next;
      if( OO_PP_IS_NULL(ts->retrans_ptr) )  break;
      pkt = PKT_CHK(ni, ts->retrans_ptr);
      ts->retrans_seq = pkt->pf.tcp_tx.start_seq;
      at_start_of_block = 1;
      ci_assert(~pkt->flags & CI_PKT_FLAG_RTQ_SACKED);
    }

    if( at_start_of_block )  ci_tcp_retrans_coalesce_block(ni, ts, pkt);

    seq_space = PKT_TCP_TX_SEQ_SPACE(pkt);
    is_fin = (TX_PKT_IPX_TCP(ipcache_af(&ts->s.pkt), pkt)->tcp_flags &
              CI_TCP_FLAG_FIN) ? 1 : 0;
    if( seq_space - is_fin > tcp_eff_mss(ts) ) {
      /* This can happen if [eff_mss] changes.  We clear out sack info
      ** first because splitting will damage the sack data-structure.
      */
      ci_tcp_clear_sacks(ni, ts);
      if( ci_tcp_tx_split(ni,ts, &ts->retrans, pkt, tcp_eff_mss(ts), 0) < 0 )
        /* Unlucky.  Never mind...try again later. */
        return 0;
    }

    /* If [before_sacked_only], then we should stop if we're beyond the
    ** last SACK block.
    */
    if( before_sacked_only && OO_PP_IS_NULL(pkt->pf.tcp_tx.block_end) )
      return 1;

    /* Stop if we've reached the recovery sequence number. */
    if( SEQ_LE(ts->congrecover, pkt->pf.tcp_tx.start_seq) )  return 1;

#if CI_CFG_BURST_CONTROL
    if(ts->burst_window && ci_tcp_burst_exhausted(ni, ts)){
      LOG_TV(log(LNT_FMT "tx limited by burst avoidance",
                 LNT_PRI_ARGS(ni, ts)));
      return 0;
    }
#endif

    /* Do we have sufficient congestion window? */
    if( seq_space > seq_limit )  return 0;

    if( ci_tcp_retrans_one(ts, ni, pkt) ) {
      /* Do not retransmit packet if it is in NIC TX. */
      return 1;
    }

    pkt->flags |= CI_PKT_FLAG_RTQ_RETRANS;
    *seq_used += seq_space;
    seq_limit -= seq_space;
    ts->retrans_seq = pkt->pf.tcp_tx.end_seq;
    ts->retrans_ptr = pkt->next;
    if( OO_PP_IS_NULL(ts->retrans_ptr) )  break;
    pkt = PKT_CHK(ni, ts->retrans_ptr);
    ts->retrans_seq = pkt->pf.tcp_tx.start_seq;
  }

  return 1;
}


void ci_tcp_retrans_recover(ci_netif* ni, ci_tcp_state* ts,
                            int force_retrans_first)
{
  ci_ip_pkt_queue* rtq = &ts->retrans;
  int before_sacked_only = 0;
  int cwnd_avail, rc, seq_used;
  int retrans_data;
  unsigned fack;

  /* We're in recovery.
   * The function is called on arrival of non-old ACK (CONG_FAST_RECOV), or
   * new ACK (CONG_RTO_RECOV).
   * If the state originally was CONG_RTO the ACK must have been
   * processed already by ci_tcp_try_cwndrecover() and congstate progressed
   * to CONG_RTO_RECOV. */
  ci_assert_impl(ts->congstate - CI_TCP_CONG_RTO_RECOV,
                 ts->congstate == CI_TCP_CONG_FAST_RECOV);
  /* Check pointers point where they should. */
  ci_assert(SEQ_LE(ts->congrecover, tcp_snd_nxt(ts)));

  if( SEQ_LE(ts->congrecover, tcp_snd_una(ts)) ) {
    ci_tcp_recovered(ni, ts);
    return;
  }

  ci_assert(SEQ_LT(ts->retrans_seq, ts->congrecover));

  /* Careful: snd_una could have advanced beyond retrans_seq. */
  if( SEQ_LT(ts->retrans_seq, tcp_snd_una(ts)) ) {
    ts->retrans_ptr = rtq->head;
    ts->retrans_seq = tcp_snd_una(ts);
  }

  /* Use forward-ack algorithm to account for packets thought to be
  ** inflight or not.
  */
  ci_tcp_get_fack(ni, ts, &fack, &retrans_data);

  if( ts->congstate == CI_TCP_CONG_FAST_RECOV ) {
    ts->cwnd_extra = SEQ_SUB(fack, tcp_snd_una(ts)) - retrans_data;
    ts->cwnd_extra = CI_MAX(ts->cwnd_extra, 0);
    cwnd_avail = ts->cwnd + ts->cwnd_extra - ci_tcp_inflight(ts);
    before_sacked_only = 1;
    if( force_retrans_first ) {
      /* Make [cwnd_avail] sufficiently large if necessary to ensure we can
      ** retransmit at least one packet.  This is used when entering fast
      ** recovery.
      */
      ci_ip_pkt_fmt* pkt = PKT_CHK(ni, ts->retrans_ptr);
      int n = SEQ_SUB(pkt->pf.tcp_tx.end_seq, pkt->pf.tcp_tx.start_seq);
      cwnd_avail = CI_MAX(cwnd_avail, n);
    }
#if CI_CFG_BURST_CONTROL
    if(
#if CI_CFG_CONG_AVOID_NOTIFIED
       ts->congstate != CI_TCP_CONG_OPEN &&
#endif
       (!ts->burst_window) && NI_OPTS(ni).burst_control_limit)
      ts->burst_window = ci_tcp_inflight(ts) +
                         (NI_OPTS(ni).burst_control_limit *
                          tcp_eff_mss(ts)) - ts->cwnd_extra;
#endif
  }
  else {
    /* In RTO recovery, we know that segments between retrans_ptr and
    ** congrecover are not in the network, so we can make that sequence
    ** range available for retransmission.  We also know that segments
    ** before the forward aCK are not in the network.
    */
    ci_assert(ts->cwnd_extra == 0);
    cwnd_avail = ts->cwnd - ci_tcp_inflight(ts);
    cwnd_avail += SEQ_SUB(ts->congrecover, ts->retrans_seq);
    cwnd_avail += SEQ_SUB(fack, tcp_snd_una(ts));
  }
  cwnd_avail = CI_MAX(cwnd_avail, 0);

  LOG_TL(log("%s: %s %s una=%08x cwnd=%05d cwnd_avail=%05d inf=%05d a=%05d "
             "b=%05d c=%d", __FUNCTION__,
             ts->cwnd < ts->ssthresh ? "SS":"CA", congstate_str(ts),
             tcp_snd_una(ts), ts->cwnd, cwnd_avail, ci_tcp_inflight(ts),
             SEQ_SUB(ts->retrans_seq, tcp_snd_una(ts)),
             SEQ_SUB(ts->congrecover, ts->retrans_seq),
             SEQ_SUB(tcp_snd_nxt(ts), ts->congrecover)));

  rc = ci_tcp_retrans(ni, ts, cwnd_avail, before_sacked_only, &seq_used);

  if( ts->congstate == CI_TCP_CONG_FAST_RECOV ) {
    ci_assert(seq_used <= cwnd_avail);
    retrans_data += seq_used;
    ts->cwnd_extra = SEQ_SUB(fack, tcp_snd_una(ts)) - retrans_data;
    ts->cwnd_extra = CI_MAX(ts->cwnd_extra, 0);
  }

  ci_assert(SEQ_LT(tcp_snd_una(ts), ts->congrecover));

  if( rc != 0 )
    ts->congstate = CI_TCP_CONG_COOLING;
}


/* Called to handle packets with MSG_MORE.  Return true if packet should
 * not be transmitted yet.
 */
static int ci_tcp_tx_handle_cork(ci_netif* ni, ci_tcp_state* ts,
                                 ci_ip_pkt_fmt* pkt)
{
  /* Last packet in send queue, and app has indicated there is more to come
   * (via TCP_CORK or MSG_MORE).
   *
   * Note that we can delay even a full segment here.  This is intended, as
   * otherwise we'd have to set the PSH flag, which seems undesirable as
   * the application has told us there is more to come.  (Note that
   * regardless of frame size we'll push a delayed frame out on receipt of
   * next ACK or after CORK timeout).  We differ from Linux in this, but I
   * think our behaviour is better as we treat all frame sizes consistently.
   */
  ci_assert(! (ts->tcpflags & CI_TCPT_FLAG_MSG_WARM));
  if( ts->s.tx_errno || (pkt->flags & CI_PKT_FLAG_TX_PSH_ON_ACK) ) {
    /* Push this frame out now. */
    TX_PKT_IPX_TCP(ipcache_af(&ts->s.pkt), pkt)->tcp_flags |= CI_TCP_FLAG_PSH;
    return 0;
  }
  else {
    /* Don't send yet, but ensure packet will be sent eventually.  If there
     * are packets in-flight, rely on the ACK, else set the CORK timer.
     */
    if( ! ci_tcp_inflight(ts) ) {
      /* Timeout is double the delack timeout (50ms).  Gives about the
       * right timeout once granularity of periodic timer is taken into
       * account.
       */
      ci_iptime_t timeout;
      timeout = ci_tcp_time_now(ni) + (NI_CONF(ni).tconst_delack << 1);
      ci_ip_timer_clear(ni, &ts->cork_tid);
      ci_ip_timer_set(ni, &ts->cork_tid, timeout);
    }
    return 1;
  }
}


static void ci_tcp_tx_advance_too_long(ci_netif* ni, ci_tcp_state* ts,
                                       ci_ip_pkt_fmt* pkt)
{
  const ci_tcp_hdr* tcp = TX_PKT_IPX_TCP(ipcache_af(&ts->s.pkt), pkt);
  int pay_len = PKT_TCP_TX_SEQ_SPACE(pkt);
  pay_len -= (tcp->tcp_flags & CI_TCP_FLAG_SYN) ? 1 : 0;
  pay_len -= (tcp->tcp_flags & CI_TCP_FLAG_FIN) ? 1 : 0;
  if( pay_len > tcp_eff_mss(ts) ) {
    ci_assert(! (ts->tcpflags & CI_TCPT_FLAG_MSG_WARM));
    ci_tcp_tx_split(ni, ts, &ts->send, pkt, tcp_eff_mss(ts), 1);
  }
}


void ci_tcp_tx_advance(ci_tcp_state* ts, ci_netif* ni)
{
  unsigned cwnd_right_edge, right_edge;
  ci_uint32* p_stop_cntr;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ci_ip_queue_not_empty(&ts->send));
  ci_assert(OO_PP_NOT_NULL(ts->send.head));

  LOG_TV(ci_log("%s: "NTS_FMT "sendq.num=%d inflight=%d", __FUNCTION__,
                NTS_PRI_ARGS(ni, ts), ts->send.num, ci_tcp_inflight(ts)));

  if( CI_UNLIKELY(ts->tcpflags & CI_TCPT_FLAG_NO_TX_ADVANCE) )
    return;

  ci_tcp_tx_cwv_idle(ni, ts);

  if( OO_SP_NOT_NULL(ts->local_peer) ) {
    cwnd_right_edge = ts->snd_max;
    ci_assert_nflags(ts->tcpflags, CI_TCPT_FLAG_LIMITED_TRANSMIT);
  }
  else {
    cwnd_right_edge = ts->snd_nxt + ts->cwnd + ts->cwnd_extra
      - ci_tcp_inflight(ts);
    /* Limited Transmit, RFC 3042: if the RX path has identified that we've met
     * the conditions for Limited Transmit, allow sending up to two segments
     * beyond the end of the congestion window.
     *     FIXME: It would be nice to avoid this branch.  One possibility would
     * be to adjust [cwnd_extra] instead of setting a flag, but currently that
     * is not compatible with other uses of that field, and would trip
     * assertions. */
    if( ts->tcpflags & CI_TCPT_FLAG_LIMITED_TRANSMIT ) {
      cwnd_right_edge += tcp_eff_mss(ts) << 1;
      ts->tcpflags &= ~CI_TCPT_FLAG_LIMITED_TRANSMIT;
    }
  }

  p_stop_cntr = &ts->stats.tx_stop_cwnd;
  right_edge = cwnd_right_edge;

#if CI_CFG_BURST_CONTROL
  if( NI_OPTS(ni).burst_control_limit ) {
    if( ts->burst_window == 0 )
      if( ! CI_CFG_CONG_AVOID_NOTIFIED || ts->congstate != CI_TCP_CONG_OPEN )
        ts->burst_window = ci_tcp_inflight(ts) +
          NI_OPTS(ni).burst_control_limit * tcp_eff_mss(ts);
    if( ts->burst_window ) {
      unsigned burst_right_edge =
        tcp_snd_nxt(ts) + ts->burst_window - ci_tcp_inflight(ts);
      if( SEQ_LT(burst_right_edge, right_edge) ) {
        p_stop_cntr = &ts->stats.tx_stop_burst;
        right_edge = burst_right_edge;
      }
    }
  }
#endif

  ci_tcp_tx_advance_to(ni, ts, right_edge, p_stop_cntr);
}


void ci_tcp_tx_advance_to(ci_netif* ni, ci_tcp_state* ts,
                          unsigned right_edge, ci_uint32* p_stop_cntr)
{
  ci_ip_pkt_queue* sendq = &ts->send;
  ci_ip_pkt_fmt* last_pkt = NULL;
  oo_pkt_p id = sendq->head;
  int sent_num = 0;
  int af = ipcache_af(&ts->s.pkt);

  while( 1 ) {
    ci_ip_pkt_fmt* pkt = PKT_CHK(ni, id);
    ci_tcp_hdr* tcp = TX_PKT_IPX_TCP(af, pkt);

    if(CI_UNLIKELY( PKT_TCP_TX_SEQ_SPACE(pkt) > tcp_eff_mss(ts) ))
      /* Likely MSS has changed (or FIN added to MSS segment).  If we're
       * unable to split then we go ahead and push out the over-length
       * frame anyway.
       */
      ci_tcp_tx_advance_too_long(ni, ts, pkt);

    if(CI_UNLIKELY( SEQ_GT(pkt->pf.tcp_tx.end_seq, ts->snd_max) )) {
      /* Packet won't fit in the receive window. Even though big packets are
       * good for efficiency, we want to split this anyway because
       * pathological deadlocks are possible with some peers (ON-11312)
       */
      if( ci_tcp_inflight(ts) ||
          SEQ_LE(ts->snd_max, pkt->pf.tcp_tx.start_seq) ||
          ci_tcp_tx_split(ni, ts, sendq, pkt,
                          SEQ_SUB(ts->snd_max, pkt->pf.tcp_tx.start_seq), 1) ){
        ++ts->stats.tx_stop_rwnd;
        break;
      }
    }
    if( SEQ_GT(pkt->pf.tcp_tx.end_seq, right_edge) ) {
      ++(*p_stop_cntr);
      break;
    }
    if( (pkt->flags & CI_PKT_FLAG_TX_MORE) && OO_PP_IS_NULL(pkt->next) )
      if( ci_tcp_tx_handle_cork(ni, ts, pkt) ) {
        ++ts->stats.tx_stop_more;
        break;
      }

#if CI_CFG_CONG_AVOID_NOTIFIED
    /* Is there local congestion, suggesting we should back off a bit? */
    if( ef_vi_transmit_fill_level(&ni->ep) > NI_OPTS(ni).cong_notify_thresh
	&& ts->congstate == CI_TCP_CONG_OPEN ) {
      ts->congstate = CI_TCP_CONG_NOTIFIED;
      ts->congrecover = tcp_snd_nxt(ts);
    }
#endif

    /* Update window (with silly window avoidance).  FIXME: No need to do
     * this each time around the loop.
     *
     * We don't want to do this when sending a syn, as we don't scale that
     * window so must calculate it differently.
     */
    if( CI_LIKELY(!(tcp->tcp_flags & CI_TCP_FLAG_SYN)) )
      ci_tcp_calc_rcv_wnd(ts, "tx_advance");

    /* place TCP options into outgoing packet */
    ci_tcp_tx_finish(ni, ts, pkt);

    /* Finish-off the IP header.  We increment the ID field for payload
     * segments because some old versions of Linux GRO require incrementing
     * ID in order to combine segments.
     */
    ci_tcp_ipx_hdr_init(af, oo_tx_ipx_hdr(af, pkt), oo_tx_l3_len(pkt));

    /* set the urgent pointer */
    ci_tcp_tx_set_urg_ptr(ts, ni, tcp);

    /* Finish-off the TCP header (using latest ack and window). */
    tcp->tcp_ack_be32 = CI_BSWAP_BE32(tcp_rcv_nxt(ts));
    tcp->tcp_window_be16 = TS_IPX_TCP(ts)->tcp_window_be16;
    ci_tcp_tx_maybe_do_striping(pkt, ts);

    LOG_TT(log(LNTS_FMT RCV_WND_FMT " snd=%08x-%08x-%08x enq=%08x",
               LNTS_PRI_ARGS(ni,ts), RCV_WND_ARGS(ts),
               tcp_snd_una(ts), tcp_snd_nxt(ts), ts->snd_max, tcp_enq_nxt(ts));
           log(LNT_FMT "["CI_TCP_FLAGS_FMT"] id=%d s=%08x-%08x a=%08x w=%u "
               "paylen=%d", LNT_PRI_ARGS(ni,ts),
               CI_TCP_HDR_FLAGS_PRI_ARG(tcp),
               OO_PKT_FMT(pkt), (unsigned) CI_BSWAP_BE32(tcp->tcp_seq_be32),
               pkt->pf.tcp_tx.end_seq,
               (unsigned) CI_BSWAP_BE32(tcp->tcp_ack_be32),
               (unsigned) CI_BSWAP_BE16(tcp->tcp_window_be16),
               ci_tx_pkt_ipx_tcp_payload_len(af, pkt)));

    tcp_snd_nxt(ts) = pkt->pf.tcp_tx.end_seq;
    sent_num++;
    CI_TCP_STATS_INC_OUT_SEGS(ni);
    last_pkt = pkt;

    /* Prep the packet for the retransmit queue. */
    ci_assert( ! (pkt->flags & CI_PKT_FLAG_TX_PENDING));
    ci_assert_equal(pkt->flags & ~CI_PKT_FLAG_TX_MASK_ALLOWED, 0);

    CI_IP_SOCK_STATS_ADD_TXBYTE(ts, TX_PKT_LEN(pkt));

    if( OO_PP_IS_NULL(pkt->next) ) {
      ++ts->stats.tx_stop_app;
      break;
    }
    id = pkt->next;
  }

  if( ts->tcpflags & CI_TCPT_FLAG_MSG_WARM )
    ci_assert(sent_num == 1);

  if( sent_num != 0 ) {
    LOG_TT(log(LNT_FMT "%d packets sent in tx_advance: from %d to %d",
               LNT_PRI_ARGS(ni,ts), sent_num, OO_PP_FMT(sendq->head),
               OO_PKT_FMT(last_pkt)));

    if( ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE ) {
      oo_pkt_p head = sendq->head;
      ci_assert(! (ts->tcpflags & CI_TCPT_FLAG_MSG_WARM ));
      ci_assert(! (ts->s.pkt.flags & CI_PKT_FLAG_INDIRECT));
      /* No retransmit queue in case of local connection:
       * just send them to peer and clear out from sendq. */
      sendq->head = last_pkt->next;
      sendq->num -= sent_num;
      ts->send_out += sent_num;
      ci_assert_equiv(ci_ip_queue_not_empty(sendq),
                      OO_PP_NOT_NULL(sendq->head));

      /* Wake up TX if necessary */
      if ( ci_tcp_tx_advertise_space(ni, ts) )
          ci_tcp_wake_possibly_not_in_poll(ni, ts, CI_SB_FLAG_WAKE_TX);

      if( ts->tcpflags & CI_TCPT_FLAG_LOOP_DEFERRED ) {
        ci_ip_pkt_fmt *pkt = PKT_CHK(ni, head);
        head = pkt->next;
        ci_ip_local_send(ni, pkt, S_SP(ts), ts->local_peer);

        /* deliver this packet to listening socket, it will call
         * ci_tcp_listenq_try_promote() and fix up ts->local_peer. */
        ci_netif_poll(ni);
        ts->tcpflags &= ~CI_TCPT_FLAG_LOOP_DEFERRED;

        if( OO_PP_NOT_NULL(head) )
          ci_ip_send_tcp_list_loopback(ni, ts, head, last_pkt);
      }
      else
        ci_ip_send_tcp_list_loopback(ni, ts, head, last_pkt);
      return;
    }
    else {
      ci_ip_send_tcp_list(ni, ts, sendq->head, last_pkt);
      if(CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_MSG_WARM ))
        /* This function updated tcp_snd_nxt, burst_window,
         * ts->stats.tx_stop_app.  We made copies of tcp_snd_nxt and
         * burst_window in tcp_sendmsg().  We will restore these
         * in unroll_msg_warm called from tcp_sendmsg().
         */
        return;
    }

    if(CI_UNLIKELY( ts->s.b.state == CI_TCP_CLOSED )) {
      /* We've closed the connection as a result of send().
       * It can be only in SYN-SENT state. */
      ci_assert_equal(sent_num, 1);
      return;
    }
    ci_ip_queue_move(ni, sendq, &ts->retrans, last_pkt, sent_num);
    ts->send_out += sent_num;

    /* Wake up TX if necessary */
    if( NI_OPTS(ni).tcp_sndbuf_mode == 0 &&
        ci_tcp_tx_advertise_space(ni, ts) )
      ci_tcp_wake_possibly_not_in_poll(ni, ts, CI_SB_FLAG_WAKE_TX);

#if CI_CFG_CONGESTION_WINDOW_VALIDATION
    ts->t_last_sent = ci_tcp_time_now(ni);
#endif

    ci_tcp_kalive_check_and_clear(ni, ts);
    ci_tcp_delack_clear(ni, ts);
    ts->acks_pending = 0;

    /* Start the RTO/TLP timer (if not already running). */
    if( ! ci_ip_timer_pending(ni, &(ts->rto_tid)) ) {
      ci_iptime_t timeout;
      if( ci_tcp_taildrop_probe_enabled(ni, ts) ) {
        timeout = ci_tcp_taildrop_timeout(ni, ts);
        ts->tcpflags |= CI_TCPT_FLAG_TAIL_DROP_TIMING;
      }
      else {
        timeout = ts->rto;
        ts->tcpflags &=~ CI_TCPT_FLAG_TAIL_DROP_TIMING;
      }
      ci_tcp_rto_set_with_timeout(ni, ts, timeout);
    }
  }

  /* congestion window validation rfc2861 */
  ci_tcp_tx_cwv_app_lmtd(ni, ts);
}



/* Most callers should use ci_tcp_send_rst(), to send a RST-ACK.  This function
 * allows customisation of the flags for the exceptional cases. */
void ci_tcp_send_rst_with_flags(ci_netif* netif, ci_tcp_state* ts,
                                ci_uint8 extra_flags)
{
  ci_ip_pkt_fmt* pkt;
  ci_tcp_hdr* tcp;
  int af = ipcache_af(&ts->s.pkt);

  /* NB for CI_PKT_ALLOC_NO_REAP:
   * Reaping packets is a slow process with unguaranteed result.  In some
   * cases, we send a lot of RSTs:
   * - when shutting down a listening socket with a lot of non-accepted
   *   sockets in the queue;
   * - when shutting down an application and the stack.
   * We can repeatedly try to reap packets in vain; in the worst scenario
   * we'll soft lockup the kernel.
   *
   * So we avoid reaping and do not send RSTs when under such serious
   * memory pressure; we'll re-send RST if we get any packets from peer.
   */
  pkt = ci_netif_pkt_alloc(netif, CI_PKT_ALLOC_NO_REAP);
  if( CI_UNLIKELY(! pkt) ) {
    CI_TCP_EXT_STATS_INC_TCP_ABORT_FAILED( netif );
    LOG_U(log(LNTS_FMT "%s: out of pkt buffers, RST not sent",
              LNTS_PRI_ARGS(netif,ts), __FUNCTION__));
    return;
  }

  oo_tx_pkt_layout_init(pkt);
  ci_ipcache_update_flowlabel(netif, &ts->s);
  ci_pkt_init_from_ipcache(pkt, &ts->s.pkt);
  ci_tcp_ipx_hdr_init(af, oo_tx_ipx_hdr(af, pkt),
                      CI_IPX_HDR_SIZE(af) + sizeof(ci_tcp_hdr));

  tcp = TX_PKT_IPX_TCP(af, pkt);
  tcp->tcp_urg_ptr_be16 = 0;
  tcp->tcp_flags = CI_TCP_FLAG_RST | extra_flags;
  tcp->tcp_seq_be32 = CI_BSWAP_BE32(tcp_snd_nxt(ts) + ts->snd_delegated);
  tcp->tcp_ack_be32 = CI_BSWAP_BE32(tcp_rcv_nxt(ts));
  tcp->tcp_window_be16 = 0;
  CI_TCP_HDR_SET_LEN(tcp, sizeof(ci_tcp_hdr));

  LOG_TV(log(LNT_FMT "RST %s:%u->%s:%u s=%08x a=%08x",
            LNT_PRI_ARGS(netif,ts),
            ip_addr_str(oo_tx_ip_hdr(pkt)->ip_saddr_be32),
            (unsigned) CI_BSWAP_BE16(tcp->tcp_source_be16),
            ip_addr_str(oo_tx_ip_hdr(pkt)->ip_daddr_be32),
            (unsigned) CI_BSWAP_BE16(tcp->tcp_dest_be16),
            (unsigned) CI_BSWAP_BE32(tcp->tcp_seq_be32),
            (unsigned) CI_BSWAP_BE32(tcp->tcp_ack_be32)));

  pkt->buf_len = pkt->pay_len = 
    oo_tx_ether_hdr_size(pkt) + CI_IPX_HDR_SIZE(af) + sizeof(ci_tcp_hdr);
  ci_ip_send_tcp(netif, pkt, ts);
  CI_TCP_STATS_INC_OUT_SEGS(netif);
  CI_IP_SOCK_STATS_ADD_TXBYTE(ts, pkt->buf_len);
  ci_netif_pkt_release(netif, pkt);

  CI_TCP_STATS_INC_OUT_RSTS( netif );
}


/* called to send an active reset on a connection (e.g. abort) */
void ci_tcp_send_rst(ci_netif* netif, ci_tcp_state* ts)
{
  ci_tcp_send_rst_with_flags(netif, ts, CI_TCP_FLAG_ACK);
}


#ifdef __KERNEL__
int ci_tcp_reset_untrusted(ci_netif *netif, ci_tcp_state *ts)
{
  ci_ipx_hdr_t* ipx;
  ci_tcp_hdr *tcp;
  int rc, payload_len;
  int af = ipcache_af(&ts->s.pkt);

  /* local_peer might be corrupted, but from the other side there is no
   * need to send RST to the local peer. */
  if( OO_SP_NOT_NULL(ts->local_peer) )
    return 0;
  if( ts->s.pkt.status != retrrc_success &&
      ts->s.pkt.status != retrrc_nomac ) {
    /* We do not know how to send RST.  Or the packet cache have been
     * corrupted. */
    return -ENOENT;
  }

  ipx = ci_alloc(sizeof(ci_tcp_hdr) + CI_IPX_HDR_SIZE(af));
  if( !ipx )
    return -ENOMEM;

  /* Check for corrupted values in ts */
  if( ts->outgoing_hdrs_len < sizeof(ci_tcp_hdr) + CI_IPX_HDR_SIZE(af) ||
      ipx_hdr_protocol(af, &ts->s.pkt.ipx) != IPPROTO_TCP ) {
    ci_free(ipx);
    return -EFAULT;
  }

#if CI_CFG_IPV6
  if( af == AF_INET6 ) {
    if( CI_IP6_VERSION(&ts->s.pkt.ipx.ip6) != 6 ) {
      ci_free(ipx);
      return -EFAULT;
    }
  }
  else
#endif
  {
    if( ts->s.pkt.ipx.ip4.ip_ihl_version !=
                              CI_IP4_IHL_VERSION( sizeof(ci_ip4_hdr) ) ||
        ts->s.pkt.ipx.ip4.ip_frag_off_be16 != CI_IP4_FRAG_DONT ) {
      ci_free(ipx);
      return -EFAULT;
    }
  }

  memcpy(ipx, &ts->s.pkt.ipx, CI_IPX_HDR_SIZE(af));
  payload_len = sizeof(ci_tcp_hdr);
  ipx_hdr_set_payload_len(af, ipx, payload_len);

#if CI_CFG_IPV6
  if( af == AF_INET )
#endif
  ci_assert_equal(ipx->ip4.ip_check_be16, 0);

  tcp = ipx_hdr_data(af, ipx);
  tcp->tcp_urg_ptr_be16 = 0;
  tcp->tcp_flags = CI_TCP_FLAG_RST;
  tcp->tcp_seq_be32 = CI_BSWAP_BE32(tcp_snd_nxt(ts));
  tcp->tcp_ack_be32 = CI_BSWAP_BE32(tcp_rcv_nxt(ts));
  tcp->tcp_source_be16 = tcp_lport_be16(ts);
  tcp->tcp_dest_be16 = tcp_rport_be16(ts);
  tcp->tcp_window_be16 = 0;
  CI_TCP_HDR_SET_LEN(tcp, sizeof(ci_tcp_hdr));
  tcp->tcp_check_be16 = 0;

  LOG_E(ci_log(NT_FMT IPX_PORT_FMT "->" IPX_PORT_FMT " RESET",
               NT_PRI_ARGS(netif, ts),
               IPX_ARG(AF_IP(ipx_hdr_saddr(af, ipx))),
               CI_BSWAP_BE16(tcp->tcp_source_be16),
               IPX_ARG(AF_IP(ipx_hdr_daddr(af, ipx))),
               CI_BSWAP_BE16(tcp->tcp_dest_be16)));
  rc = cicp_raw_ip_send(netif->cplane, af, ipx,
                        CI_IPX_HDR_SIZE(af) + payload_len,
                        ts->s.pkt.ifindex, ts->s.pkt.nexthop);
  ci_free(ipx);
  return rc;
}
#endif

void
ci_tcp_reply_with_rst(ci_netif* netif, const struct oo_sock_cplane* sock_cp,
                      ciip_tcp_rx_pkt* rxp)
{
  /* If the incoming seg has an ACK, use that as the seq no, otherwise use
  ** 0.  Calculate a proper ACK from the incoming seg.  A consequence of this
  ** is that this function is invalid for synchronised TCP states.
  */
  /*! ?? \TODO Check for dodgy source IP (to avoid broadcasting, for
  ** example).
  */
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_tcp_hdr rtcp;
  ci_uint32 rtcp_endseq;
  int af = oo_pkt_af(pkt);
  ci_ipx_hdr_t rip;
  ci_tcp_hdr* tcp;
  ci_ipx_hdr_t* ip;

  ci_assert(netif);
  ASSERT_VALID_PKT(netif, pkt);

  /* Remember some of the RX packet's properties before the packet becomes
   * invalid in the course of ci_netif_pkt_rx_to_tx(). */
  rtcp = *rxp->tcp;
  rip = *oo_ipx_hdr(pkt);
  rtcp_endseq = pkt->pf.tcp_rx.end_seq;

  if( (pkt = ci_netif_pkt_rx_to_tx(netif, pkt)) == NULL )
    return;

  /* Initialise headers, swapping addressing info around.  Ensure fields
  ** are fully kosher.  (Don't trust what they sent!)
  */
  oo_tx_pkt_layout_init(pkt);
  oo_tx_ether_type_set(pkt,
                       af == AF_INET ? CI_ETHERTYPE_IP : CI_ETHERTYPE_IP6);
  ip = oo_tx_ipx_hdr(af, pkt);
  ci_ipx_hdr_init_fixed(ip, af, IPPROTO_TCP,
                        CI_IPX_DFLT_TTL_HOPLIMIT(af),
                        CI_IPX_DFLT_TOS_TCLASS(af));
  ipx_hdr_set_daddr(af, ip, ipx_hdr_saddr(af, &rip));
  ipx_hdr_set_saddr(af, ip, ipx_hdr_daddr(af, &rip));

  tcp = ipx_hdr_data(af, ip);
  tcp->tcp_urg_ptr_be16 = 0;
  tcp->tcp_source_be16 = rtcp.tcp_dest_be16;
  tcp->tcp_dest_be16 = rtcp.tcp_source_be16;

#if CI_CFG_IPV6
  {
    ci_uint32 auto_flowlabels = NI_OPTS(netif).auto_flowlabels;
    if( IS_AF_INET6(af) &&
        (auto_flowlabels == CITP_IP6_AUTO_FLOW_LABEL_OPTOUT ||
         auto_flowlabels == CITP_IP6_AUTO_FLOW_LABEL_FORCED) ) {
      TX_PKT_SET_FLOWLABEL(af, pkt, ci_make_flowlabel(netif,
          ipx_hdr_saddr(af, ip), tcp->tcp_source_be16, ipx_hdr_daddr(af, ip),
          tcp->tcp_dest_be16, IPPROTO_TCP));
    }
  }
#endif

  /* rfc793 p63-p75 describes ACK flag for RST generation
  ** if ACK flag set then use that as SEQ otherwise
  ** use 0 and fill out the ACK field of the reset segment
  */
  if( (rtcp.tcp_flags & CI_TCP_FLAG_ACK) ) {
    tcp->tcp_seq_be32 = rtcp.tcp_ack_be32;
    tcp->tcp_flags = CI_TCP_FLAG_RST;
    tcp->tcp_ack_be32 = 0;
  } else {
    tcp->tcp_seq_be32 = 0;
    tcp->tcp_flags = CI_TCP_FLAG_RST | CI_TCP_FLAG_ACK;
    tcp->tcp_ack_be32 = CI_BSWAP_BE32(rtcp_endseq);
  }
  CI_TCP_HDR_SET_LEN(tcp, sizeof(*tcp));
  tcp->tcp_window_be16 = 0;
  tcp->tcp_check_be16 = 0;
  ci_tcp_ipx_hdr_init(af, ip, CI_IPX_HDR_SIZE(af) + sizeof(ci_tcp_hdr));

  LOG_TR(log(LN_FMT "RSTACK "IPX_FMT":%u->"IPX_FMT":%u s=%08x a=%08x",
             LN_PRI_ARGS(netif), IPX_ARG(AF_IP(ipx_hdr_saddr(af, ip))),
             (unsigned) CI_BSWAP_BE16(tcp->tcp_source_be16),
             IPX_ARG(AF_IP(ipx_hdr_daddr(af, ip))),
             (unsigned) CI_BSWAP_BE16(tcp->tcp_dest_be16),
             (unsigned) CI_BSWAP_BE32(tcp->tcp_seq_be32),
             (unsigned) CI_BSWAP_BE32(tcp->tcp_ack_be32)));

  pkt->buf_len = pkt->pay_len = 
    oo_tx_ether_hdr_size(pkt) + CI_IPX_HDR_SIZE(af) + sizeof(ci_tcp_hdr);
  if( pkt->intf_i == OO_INTF_I_LOOPBACK ) {
    ci_netif_pkt_hold(netif, pkt);
    ci_ip_local_send(netif, pkt, pkt->pf.tcp_tx.lo.rx_sock,
                     pkt->pf.tcp_tx.lo.tx_sock);
  }
  else {
    /* ?? TODO: should we respect here SO_BINDTODEVICE? */
    ci_ip_cached_hdrs ipcache;
    ci_ip_cache_init(&ipcache, af);
    ci_ip_send_pkt_lookup(netif, NULL, pkt, &ipcache);
    ci_ip_send_pkt_send(netif, sock_cp, pkt, &ipcache);
  }
  CI_TCP_STATS_INC_OUT_SEGS(netif);
  ci_netif_pkt_release(netif, pkt);
  CI_TCP_STATS_INC_OUT_RSTS( netif );
}


void ci_tcp_send_zwin_probe(ci_netif* netif, ci_tcp_state* ts)
{
  /*
   * Send an ACK segment out of window (ie with seq
   * snd_una-1) to get an acknowledgement from the other end.
   */
  ci_ip_pkt_fmt* pkt;
  ci_tcp_hdr* tcp;
  ci_uint8* opt;
  int optlen = 0;
  int af = ipcache_af(&ts->s.pkt);

  ci_assert(netif);
  ci_assert(ci_ip_queue_is_empty(&ts->retrans));
  ci_assert(OO_SP_IS_NULL(ts->local_peer));

  pkt = ci_netif_pkt_alloc(netif, 0);
  if( ! pkt ) {
    LOG_U(log(LNTS_FMT "out of pkt buffers, not sending zwin probe",
              LNTS_PRI_ARGS(netif, ts)));
    return;
  }

  oo_tx_pkt_layout_init(pkt);
  ci_ipcache_update_flowlabel(netif, &ts->s);
  ci_pkt_init_from_ipcache(pkt, &ts->s.pkt);
  tcp = TX_PKT_IPX_TCP(af, pkt);
  opt = CI_TCP_HDR_OPTS(tcp);

  /* Decrement the faststart counter by the number of bytes acked */
  ci_tcp_reduce_faststart(ts, SEQ_SUB(tcp_rcv_nxt(ts), ts->tslastack));

  /* put in the TSO & SACK options if needed */
  ts->tslastack = tcp_rcv_nxt(ts); /* also used for faststart */
  if( ts->tcpflags & CI_TCPT_FLAG_TSO ) {
    optlen += ci_tcp_tx_opt_tso(&opt, ci_tcp_time_now(netif), ts->tsrecent);
  }
  if( ts->tcpflags & CI_TCPT_FLAG_SACK )
    optlen += ci_tcp_tx_opt_sack(&opt, optlen, netif, ts);

  tcp->tcp_flags = CI_TCP_FLAG_ACK;
  /* SACK option may change pre-computed header length. */
  CI_TCP_HDR_SET_LEN(tcp, sizeof(ci_tcp_hdr) + optlen);

  /* send seq with snd_una-1, to trigger an ack for unacceptable seq */
  tcp->tcp_seq_be32 = CI_BSWAP_BE32(tcp_snd_una(ts)-1);
  ci_tcp_ipx_hdr_init(af, oo_tx_ipx_hdr(af, pkt),
                      CI_IPX_HDR_SIZE(af) + sizeof(ci_tcp_hdr) + optlen);
  pkt->buf_len = ( oo_tx_ether_hdr_size(pkt) + CI_IPX_HDR_SIZE(af)
                   + sizeof(ci_tcp_hdr) + optlen );
  pkt->pay_len = pkt->buf_len;

  /* Update window (with silly window avoidance). */
  ci_tcp_calc_rcv_wnd(ts, "zwin_probe");

  ci_tcp_tx_set_urg_ptr(ts, netif, tcp);
  tcp->tcp_ack_be32 = CI_BSWAP_BE32(tcp_rcv_nxt(ts));
  tcp->tcp_window_be16 = TS_IPX_TCP(ts)->tcp_window_be16;

  LOG_TT(log(LNT_FMT "ZWIN id=%i s=%08x a=%08x w=%u",
             LNT_PRI_ARGS(netif,ts), OO_PKT_FMT(pkt),
             (unsigned) CI_BSWAP_BE32(tcp->tcp_seq_be32),
             (unsigned) CI_BSWAP_BE32(tcp->tcp_ack_be32),
             (unsigned) CI_BSWAP_BE16(tcp->tcp_window_be16)));

  ci_ip_send_tcp(netif, pkt, ts);

  CI_IP_SOCK_STATS_ADD_TXBYTE(ts,  pkt->buf_len);

  ci_netif_pkt_release(netif, pkt);
}


void ci_tcp_send_ack_loopback(ci_netif* netif, ci_tcp_state* ts)
{
  ci_tcp_state* peer;
  citp_waitable* w_peer;

  ci_assert( OO_SP_NOT_NULL(ts->local_peer) );
  w_peer = ID_TO_WAITABLE(netif, ts->local_peer);

  ts->acks_pending = 0;

  /* check that the peer was not changed since it sent the packet we are
   * ACKing.
   * TODO: make better checks. */
  if( ~w_peer->state & CI_TCP_STATE_TCP_CONN )
    return;
  peer = (ci_tcp_state *)w_peer;
  if( peer->local_peer != S_SP(ts) )
    return;

  /* ci_tcp_tx_advance() calls ci_tcp_wake_possibly_not_in_poll().
   * Make sure it works properly when in poll. */
  if( netif->state->in_poll )
    ci_netif_put_on_post_poll(netif, &peer->s.b);

  do {
    ts->acks_pending = 0;
    ci_tcp_calc_rcv_wnd(ts, "send_ack");
    ci_assert(!ci_ip_timer_pending(netif, &ts->delack_tid));

    peer->snd_una = tcp_rcv_nxt(ts);
    peer->snd_max = tcp_rcv_wnd_right_edge_sent(ts);

    /* If peer has non-empty sendq, we should call ci_tcp_tx_advance().
     * ci_tcp_tx_advance() also send TX wakeup if necessary. */
    if( ci_ip_queue_not_empty(&peer->send) )
      ci_tcp_tx_advance(peer, netif);
   } while( ts->acks_pending != 0 );

  ci_assert_equal(ts->acks_pending, 0);

  LOG_TC(log(LPF "loopback ACK %d: %d->%d", NI_ID(netif),
             S_FMT(ts), S_FMT(peer));
         log(LNTS_FMT RCV_WND_FMT " snd=%08x-%08x-%08x enq=%08x",
             LNTS_PRI_ARGS(netif, ts), RCV_WND_ARGS(ts),
             tcp_snd_una(ts),
             tcp_snd_nxt(ts), ts->snd_max, tcp_enq_nxt(ts));
         log(LNTS_FMT RCV_WND_FMT " snd=%08x-%08x-%08x enq=%08x",
             LNTS_PRI_ARGS(netif, peer), RCV_WND_ARGS(peer),
             tcp_snd_una(peer),
             tcp_snd_nxt(peer), peer->snd_max, tcp_enq_nxt(peer)));
}

/* this function will always output an acknowledgement */
void ci_tcp_send_ack_rx(ci_netif* netif, ci_tcp_state* ts, ci_ip_pkt_fmt* pkt,
                        int sock_locked, int update_window)
{
  ci_tcp_hdr* tcp;
  ci_uint8* opt;
  int optlen = 0;
  int af = ipcache_af(&ts->s.pkt);

  CITP_STATS_NETIF_INC(netif, acks_sent);


  if( OO_SP_NOT_NULL(ts->local_peer) ) {
    ci_netif_pkt_release(netif, pkt);
    ci_tcp_send_ack_loopback(netif, ts);
    return;
  }

  /* We can drop reorder buffer here, so let's call it before filling in
   * the SACK option. */
  if( ci_tcp_rcvbuf_abused(netif, ts) )
    ci_tcp_rcvbuf_unabuse(netif, ts, sock_locked);

  ts->acks_pending = 0;
  ci_tcp_delack_clear(netif, ts);

  ci_tcp_calc_rcv_wnd_rx(ts, update_window, "send_ack");

  ci_assert(netif);
  ASSERT_VALID_PKT(netif, pkt);
  ci_assert(pkt->refcount == 1); /* packet will be consumed */
  ci_assert( ! (pkt->flags & CI_PKT_FLAG_TX_PENDING));

  oo_tx_pkt_layout_init(pkt);
  ci_ipcache_update_flowlabel(netif, &ts->s);
  ci_pkt_init_from_ipcache(pkt, &ts->s.pkt);
  if( !ipcache_is_ipv6(&ts->s.pkt) ) {
    ci_assert_equal(ts->s.pkt.ipx.ip4.ip_check_be16, 0); 
    ci_assert_equal(oo_tx_ip_hdr(pkt)->ip_check_be16, 0);
  }

  tcp = TX_PKT_IPX_TCP(af, pkt);
  ci_assert_equal(tcp->tcp_check_be16, 0);
  opt = CI_TCP_HDR_OPTS(tcp);

  /* Fixup the sequence number: We want snd_nxt, not enq_nxt. */
  /* Fixme: snd_delegated should be speculative, but here we use it in
   * non-speculative way.  On the other side, if we do not add snd_delegated
   * the peer will reject our ACK because of incorrect sequence number. */
  tcp->tcp_seq_be32 = CI_BSWAP_BE32(tcp_snd_nxt(ts) + ts->snd_delegated);

  /* Decrement the faststart counter by the number of bytes acked */
  ci_tcp_reduce_faststart(ts, SEQ_SUB(tcp_rcv_nxt(ts), ts->tslastack));

  /* put in the TSO & SACK options if needed */
  ts->tslastack = tcp_rcv_nxt(ts); /* also used for faststart */
  if( ts->tcpflags & CI_TCPT_FLAG_TSO ) {
    optlen += ci_tcp_tx_opt_tso(&opt, ci_tcp_time_now(netif), ts->tsrecent);
  }
  if( ts->tcpflags & CI_TCPT_FLAG_SACK ) {
    optlen += ci_tcp_tx_opt_sack(&opt, optlen, netif, ts);
  }

  tcp->tcp_flags = CI_TCP_FLAG_ACK;
  /* SACK option may change pre-computed header length. */
  CI_TCP_HDR_SET_LEN(tcp, sizeof(ci_tcp_hdr) + optlen);

  ci_tcp_tx_set_urg_ptr(ts, netif, tcp);

  /* Rest of packet creation */
  ci_tcp_ipx_hdr_init(af, oo_tx_ipx_hdr(af, pkt),
                      CI_IPX_HDR_SIZE(af) + sizeof(ci_tcp_hdr) + optlen);
  tcp->tcp_ack_be32 = CI_BSWAP_BE32(tcp_rcv_nxt(ts));
  tcp->tcp_window_be16 = TS_IPX_TCP(ts)->tcp_window_be16;

  LOG_TT(log(LNT_FMT "ACK id=%i s=%08x a=%08x w(unscaled)=%u w_cur=%u",
             LNT_PRI_ARGS(netif,ts), OO_PKT_FMT(pkt),
             (unsigned) CI_BSWAP_BE32(tcp->tcp_seq_be32),
             (unsigned) CI_BSWAP_BE32(tcp->tcp_ack_be32),
             (unsigned) CI_BSWAP_BE16(tcp->tcp_window_be16),
             tcp_rcv_wnd_current(ts)));

  pkt->buf_len = ( oo_tx_ether_hdr_size(pkt) + CI_IPX_HDR_SIZE(af)
                   + sizeof(ci_tcp_hdr) + optlen );
  pkt->pay_len = pkt->buf_len;

  ci_tcp_tx_maybe_do_striping(pkt, ts);
  __ci_ip_send_tcp(netif, pkt, ts);
  CI_TCP_STATS_INC_OUT_SEGS(netif);
  CI_IP_SOCK_STATS_ADD_TXBYTE(ts,  pkt->buf_len);
  ci_netif_pkt_release(netif, pkt);
}

int/*bool*/
ci_tcp_may_send_ack_ratelimited(ci_netif* netif, ci_tcp_state* ts)
{
  if( ci_tcp_time_now(netif) - ts->t_last_invalid_ack >=
      NI_CONF(netif).tconst_invalid_ack_ratelimit ) {
    ts->t_last_invalid_ack = ci_tcp_time_now(netif);
    return 1;
  }

  CITP_STATS_NETIF_INC(netif, invalid_ack_limited);
  return 0;
}

/* Return 1 if the packet have been consumed. */
int ci_tcp_send_challenge_ack(ci_netif* netif, ci_tcp_state* ts,
                               ci_ip_pkt_fmt* pkt)
{
  if( ! ci_tcp_may_send_ack_ratelimited(netif, ts) )
    return 0;

  if( netif->state->challenge_ack_time != ci_tcp_time_now(netif) ) {
    netif->state->challenge_ack_time = ci_tcp_time_now(netif);
    netif->state->challenge_ack_num = 0;
  }
  if( netif->state->challenge_ack_num >=
      NI_CONF(netif).tconst_challenge_ack_limit ) {
    CITP_STATS_NETIF_INC(netif, challenge_ack_limited);
    return 0;
  }

  netif->state->challenge_ack_num++;
  pkt = ci_netif_pkt_rx_to_tx(netif, pkt);
  if( pkt == NULL ) {
    /* Avoid more challenge ACK during this tick. */
    netif->state->challenge_ack_num =
                    NI_CONF(netif).tconst_challenge_ack_limit;
    CITP_STATS_NETIF_INC(netif, challenge_ack_out_of_pkts);
    return 1; /* The packet have been consumed in any case */
  }
  ci_tcp_send_ack_rx(netif, ts, pkt, 0/*sock_locked*/, 0/*update_window*/);
  CITP_STATS_NETIF_INC(netif, challenge_ack_sent);
  return 1;
}

int ci_tcp_send_wnd_update(ci_netif* ni, ci_tcp_state* ts, int sock_locked)
{
  ci_assert(ci_netif_is_locked(ni));

  if(CI_UNLIKELY( ! (ts->s.b.state & CI_TCP_STATE_ACCEPT_DATA) ))
    return 0;

  ci_assert_lt(ci_tcp_ack_trigger_delta(ts), ci_tcp_max_rcv_window(ts));

  if( SEQ_SUB(ts->rcv_delivered + ci_tcp_max_rcv_window(ts),
              tcp_rcv_wnd_right_edge_sent(ts))
      >= ci_tcp_ack_trigger_delta(ts) ) {
    ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(ni, 0);
    if( pkt ) {
      LOG_TR(log(LNTS_FMT "window update advertised=%d",
                 LNTS_PRI_ARGS(ni, ts), tcp_rcv_wnd_advertised(ts)));
      CITP_STATS_NETIF_INC(ni, wnd_updates_sent);
      ci_tcp_send_ack_rx(ni, ts, pkt, sock_locked, CI_TRUE);
      /* Update the ack trigger so we won't attempt to send another windows
      ** update for a while.
      */
      ts->ack_trigger += ci_tcp_ack_trigger_delta(ts);
      return 1;
    }
  }
  return 0;
}

/**********************************************************************/
/**********************************************************************/
/**********************************************************************/

static inline void
ci_ip_hdr_init_fixed(ci_ip4_hdr* ip, int protocol, int ttl, unsigned tos)
{
  ci_assert(ttl);

  ip->ip_ihl_version = CI_IP4_IHL_VERSION(sizeof(*ip));
  ip->ip_tos = (ci_uint8)tos;
  ip->ip_frag_off_be16 = CI_IP4_FRAG_DONT;
  ip->ip_ttl = ( ttl == -1 ) ? CI_IP_DFLT_TTL : (ci_uint8)ttl;
  ip->ip_protocol = (ci_uint8)protocol;
}

#if CI_CFG_IPV6
static inline void
ci_ip6_hdr_init_fixed(ci_ip6_hdr* ip6, int protocol, int hop_limit,
                      unsigned tclass)
{
  ip6->prio_version = 6 << 4u;
  ci_ip6_set_flowinfo(ip6, tclass, 0);
  ip6->hop_limit = ( hop_limit == -1 ) ? CI_IPV6_DFLT_HOPLIMIT :
                   (ci_uint8)hop_limit;
  ip6->next_hdr = (ci_uint8)protocol;
}
#endif

void ci_ipx_hdr_init_fixed(ci_ipx_hdr_t* ip, int af, int protocol,
                           int ttl, unsigned tos)
{
#if CI_CFG_IPV6
  if( af == AF_INET6 )
    ci_ip6_hdr_init_fixed(&ip->ip6, protocol, ttl, tos);
  else
#endif
    ci_ip_hdr_init_fixed(&ip->ip4, protocol, ttl, tos);
}

#endif
/*! \cidoxg_end */
