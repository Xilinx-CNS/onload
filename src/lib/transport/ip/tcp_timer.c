/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ctk
**  \brief  TCP timer initiated actions.
**   \date  2004/01/14
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include "tcp_rx.h" /* for ci_tcp_set_snd_max() */

#define LPF "TCP TIMER "

/* Called to setup the TCP time constants in terms of ticks for this
** machine.
**
** TODO: Could be done once per driver, rather than once per stack...
*/
void ci_tcp_timer_init(ci_netif* netif)
{
  NI_CONF(netif).tconst_rto_initial = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).rto_initial);
  /* When converting to ticks we will end up with a rounded down value.  This
   * would result in an effective lower min, so add an extra tick to ensure
   * that the minimum value does not fall below that requested.
   */
  NI_CONF(netif).tconst_rto_min = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).rto_min) + 1;
  NI_CONF(netif).tconst_rto_max = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).rto_max);

  NI_CONF(netif).tconst_delack = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_DELACK);

  NI_CONF(netif).tconst_idle = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_IDLE);

  NI_CONF(netif).tconst_keepalive_time = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).keepalive_time);
  NI_CONF(netif).tconst_keepalive_intvl = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).keepalive_intvl);
  
  NI_CONF(netif).tconst_zwin_max = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_ZWIN_MAX);

  NI_CONF(netif).tconst_paws_idle = 
    ci_tcp_time_ms2ticks(netif, CI_TCP_TCONST_PAWS_IDLE);

  NI_CONF(netif).tconst_2msl_time = 
    ci_tcp_time_ms2ticks(netif, 2*NI_OPTS(netif).msl_seconds*1000);
  NI_CONF(netif).tconst_fin_timeout = 
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).fin_timeout*1000);
  NI_CONF(netif).tconst_peer2msl_time =
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).tcp_isn_2msl * 1000);

  NI_CONF(netif).tconst_pmtu_discover_slow = 
    ci_tcp_time_ms2ticks(netif, CI_PMTU_TCONST_DISCOVER_SLOW);

  NI_CONF(netif).tconst_pmtu_discover_fast = 
    ci_tcp_time_ms2ticks(netif, CI_PMTU_TCONST_DISCOVER_FAST);

  NI_CONF(netif).tconst_pmtu_discover_recover = 
    ci_tcp_time_ms2ticks(netif, CI_PMTU_TCONST_DISCOVER_RECOVER);

  /* Convert per-second challenge ACK limit to a per-tick.
   * +1 to ensure that the result is non-zero. */
  NI_CONF(netif).tconst_challenge_ack_limit =
      ci_ip_time_freq_hz2tick(netif, NI_OPTS(netif).challenge_ack_limit) + 1;

  if( NI_OPTS(netif).oow_ack_ratelimit == 0 )
    NI_CONF(netif).tconst_invalid_ack_ratelimit = 0;
  else
    NI_CONF(netif).tconst_invalid_ack_ratelimit =
      ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).oow_ack_ratelimit) + 1;

  NI_CONF(netif).tconst_defer_arp =
    ci_tcp_time_ms2ticks(netif, NI_OPTS(netif).defer_arp_timeout * 1000);

  NI_CONF(netif).tconst_stats = 
    ci_tcp_time_ms2ticks(netif, CI_TCONST_STATS);
}


#if OO_DO_STACK_POLL

static void ci_tcp_timeout_taildrop(ci_netif* netif, ci_tcp_state* ts);


/* Called as action on a listen timeout */
void ci_tcp_timeout_listen(ci_netif* netif, ci_tcp_socket_listen* tls)
{
  struct oo_p_dllink_state list;
  struct oo_p_dllink_state l;
  int max_retries, retries, synrecv_timeout = 0;
  int out_of_packets = 0;
  ci_iptime_t next_timeout = ci_tcp_time_now(netif);

  ci_assert(netif);
  ci_assert(tls);
  ci_assert(tls->s.b.state == CI_TCP_LISTEN);

  ci_assert(tls->n_listenq > 0);

  if( tls->c.tcp_defer_accept != OO_TCP_DEFER_ACCEPT_OFF )
    max_retries = tls->c.tcp_defer_accept;
  else
    max_retries = NI_OPTS(netif).retransmit_threshold_synack;

  /*
  **  - send any pending SYNACK retranmsits 
  */
  for( retries = 0; retries < max_retries && ! out_of_packets; ++retries ) {
    struct oo_p_dllink_state last_l;

    list = oo_p_dllink_sb(netif, &tls->s.b, &tls->listenq[retries]);
    last_l.p = OO_P_NULL;
    last_l.l = NULL;

    oo_p_dllink_for_each(netif, l, list) {
      ci_tcp_state_synrecv* tsr =  ci_tcp_link2synrecv(l.l);

      ci_assert( OO_SP_IS_NULL(tsr->local_peer) );

      /* The list is time-ordered - break if timeout is ahead */
      if( TIME_GT(tsr->timeout, ci_tcp_time_now(netif)) ) {
        if( next_timeout == ci_tcp_time_now(netif) ||
            TIME_LT(tsr->timeout, next_timeout) )
          next_timeout = tsr->timeout;
        break;
      }

      ci_assert_equal(tsr->retries & CI_FLAG_TSR_RETRIES_MASK, retries);

      /* We have to re-send our SYN-ACK if:
       * - not acked: let's get an ACK!
       * - acked, but TCP_DEFER_ACCEPT is off: probably, we've failed to
       *   promote. Check that the peer is alive and try to promote
       *   again.
       */
      if( tls->c.tcp_defer_accept != OO_TCP_DEFER_ACCEPT_OFF &&
          (tsr->retries & CI_FLAG_TSR_RETRIES_MASK) == max_retries - 1 )
        tsr->retries &= ~CI_FLAG_TSR_RETRIES_ACKED;
      if( (~tsr->retries & CI_FLAG_TSR_RETRIES_ACKED) ||
          tls->c.tcp_defer_accept == OO_TCP_DEFER_ACCEPT_OFF ) {
        int rc = 0;
        ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(netif, 0);

        if( pkt == NULL ) {
          /* We have no packet buffers to process the synacks any further,
           * break here and continue to moving processed part of the list
           * to the next retry list in order to maintain coherency.
           */
          LOG_TV(ci_log(LNT_FMT"SYNRECV[retries=%d] no buffers, not re-sending "
                        "synacks for %d half-opened connections",
                        LNT_PRI_ARGS(netif, tls), retries,
                        tls->n_listenq - tls->n_listenq_new));
          CITP_STATS_NETIF_INC(netif, tcp_listen_synack_retrans_no_buffer);
          out_of_packets = 1;
          break;
        }

        rc = ci_tcp_synrecv_send(netif, tls, tsr, pkt,
                                 CI_TCP_FLAG_SYN | CI_TCP_FLAG_ACK, NULL);
        if( rc == 0 ) {
          CITP_STATS_NETIF(++netif->state->stats.synrecv_retransmits);
          LOG_TC(log(LPF "SYNRECV retransmited %d SYNACK%s\n" 
                     "  next will be sent at %d",
                     tsr->retries & CI_FLAG_TSR_RETRIES_MASK,
                     (tsr->retries & CI_FLAG_TSR_RETRIES_ACKED) ?
                                                        " ACKed" : "",
                     tsr->timeout));
        }
        else {
          LOG_U(ci_log("%s: no return route exists "IPX_FMT,
                       __FUNCTION__, IPX_ARG(AF_IP_L3(tsr->r_addr))));
        }
      }

      last_l = l;

      if( retries == 0 )
        --tls->n_listenq_new;
      tsr->retries++;
      ci_assert_equal(tsr->retries & CI_FLAG_TSR_RETRIES_MASK, retries + 1);

      tsr->timeout = NI_CONF(netif).tconst_rto_initial << (retries + 1);
      tsr->timeout = CI_MIN(tsr->timeout, NI_CONF(netif).tconst_rto_max);
      tsr->timeout += ci_tcp_time_now(netif);
    }

    /* Move the beginning of the processed listenq[retries] list
     * to the end of listenq[retries + 1] list. */
    if( last_l.p != OO_P_NULL ) {
      struct oo_p_dllink_state next_list =
                oo_p_dllink_sb(netif, &tls->s.b, &tls->listenq[retries + 1]);
      struct oo_p_dllink_state start_l =
                oo_p_dllink_statep(netif, list.l->next);
      struct oo_p_dllink_state link_to_l =
               oo_p_dllink_statep(netif, next_list.l->prev);
      struct oo_p_dllink_state unlink_from_l =
               oo_p_dllink_statep(netif, last_l.l->next);

      /* cut the beginning off the list: */
      list.l->next = unlink_from_l.p;
      unlink_from_l.l->prev = list.p;

      /* append the processed part of the old "list"
       * to the end of the "next_list" */
      start_l.l->prev = link_to_l.p;
      link_to_l.l->next = start_l.p;
      last_l.l->next = next_list.p;
      next_list.l->prev = last_l.p;
    }
  }

  /*
  **  - delete connections which have exceeded max_retries
  */
  for( retries = max_retries;
       retries <= CI_CFG_TCP_SYNACK_RETRANS_MAX;
       ++retries ) {
    struct oo_p_dllink_state tmp;

    list = oo_p_dllink_sb(netif, &tls->s.b, &tls->listenq[retries]);
    oo_p_dllink_for_each_safe(netif, l, tmp, list) {
      ci_tcp_state_synrecv* tsr =  ci_tcp_link2synrecv(l.l);

      ci_assert( OO_SP_IS_NULL(tsr->local_peer) );

      /* The list is time-ordered - break if timeout is ahead */
      if( TIME_GT(tsr->timeout, ci_tcp_time_now(netif)) ) {
        if( next_timeout == ci_tcp_time_now(netif) ||
            TIME_LT(tsr->timeout, next_timeout) )
          next_timeout = tsr->timeout;
        break;
      }

      ci_assert_equal(tsr->retries & CI_FLAG_TSR_RETRIES_MASK, retries);

      ci_tcp_listenq_drop(netif, tls, tsr);
      ci_tcp_synrecv_free(netif, tsr);
      CITP_STATS_NETIF(++netif->state->stats.synrecv_timeouts);

      LOG_TC(log(LPF "SYNRECV retries %d exceeded %d,"
                 " returned to listen",
                 tsr->retries & CI_FLAG_TSR_RETRIES_MASK,
                 NI_OPTS(netif).retransmit_threshold_synack));

      ++synrecv_timeout;
    }
  }

  if( synrecv_timeout )
    NI_LOG(netif, CONN_DROP, "%s: [%d] %d half-open timeouts\n", __func__,
           NI_ID(netif), synrecv_timeout);

  /* if still any pending connectings */
  if(  out_of_packets || next_timeout != ci_tcp_time_now(netif) ) {
    /* If out-of-packets, we should return here soon to send the synacks
     * we've failed to send now.  But not too soon - get a chance to
     * fix the problem as time passes. */
    ci_ip_timer_set(netif, &tls->listenq_tid,
                    out_of_packets ?
                            ci_tcp_time_now(netif) + 1 : next_timeout);
  }
  return;
}


/* Called as action on a keep alive timeout (KALIVE) */
void ci_tcp_timeout_kalive(ci_netif* netif, ci_tcp_state* ts)
{
  ci_iptime_t t_last_recv = 
    CI_MAX(ts->t_last_recv_payload, ts->t_last_recv_ack);

  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_CLOSED);

  /* Check to see if this has expired prematurely */
  if (ts->ka_probes == 0 && 
      ci_tcp_time_now(netif) - t_last_recv < ci_tcp_kalive_idle_get(ts)) {
    /* NB. The above old code alludes to a special case on Linux where
     * instead of waiting for t_idle it waits for t_intvl if t_idle <
     * t_intvl.  It's not clear if this is just the case when we've
     * received a keepalive-ACK or from the start of the algorithm.
     * Ignoring this for now - fix again if it's a problem */

    ci_tcp_kalive_restart(netif, ts, 
                          ci_tcp_kalive_idle_get(ts) - 
                          (ci_tcp_time_now(netif) - t_last_recv));
    return;
  }

  if (ts->ka_probes != 0 && 
      ci_tcp_time_now(netif) - t_last_recv < 
      ci_tcp_kalive_intvl_get(netif, ts)) {
    ci_tcp_kalive_restart(netif, ts, 
                          ci_tcp_kalive_intvl_get(netif, ts) - 
                          (ci_tcp_time_now(netif) - t_last_recv));
    return;
  }

  ci_assert(ci_ip_queue_is_empty(&ts->retrans));

  /* TCP loopback does not have ACKs, so we just check the other side. */
  if( OO_SP_NOT_NULL(ts->local_peer) ) {
    citp_waitable* peer = ID_TO_WAITABLE(netif, ts->local_peer);
    if( ~peer->state & CI_TCP_STATE_TCP_CONN )
      ci_tcp_drop(netif, ts, ETIMEDOUT);
    return;
  }

  LOG_TL(log(LPF "%d KALIVE: 0x%x rto:%u\n",
	     S_FMT(ts), ci_tcp_time_now(netif), ts->rto));
  if (ts->ka_probes > ci_tcp_kalive_probes_get(ts) )
    CI_TCP_EXT_STATS_INC_TCP_ABORT_ON_TIMEOUT( netif );
  if( ts->ka_probes >= ci_tcp_kalive_probes_get(ts) ) {
    LOG_U(log(LPF "%d KALIVE: (should drop) ka_probes=%u ka_probe_th=%u",
	      S_FMT(ts), ts->ka_probes, ci_tcp_kalive_probes_get(ts)));

    ci_tcp_send_rst(netif, ts);
    ci_tcp_drop(netif, ts, ETIMEDOUT);
    return;
  }

  ci_tcp_send_zwin_probe(netif, ts);

  ++ts->ka_probes;
  ci_tcp_kalive_restart(netif, ts, ci_tcp_kalive_intvl_get(netif, ts));
}


/* Called as action on a zero window probe timeout (ZWIN) */
void ci_tcp_timeout_zwin(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_CLOSED);

  /* Either 
   * - Window has opened up;
   * - TCP is in state where we won't send anything;
   * - Retrans queue is not empty (and so retransmissions will be
   *   forcing ACKs)
   * so we can stop probing.  If retrans queue goes empty they will be
   * restarted
   */
  if( tcp_snd_wnd(ts) > 0 ||
      ! (ts->s.b.state & CI_TCP_STATE_TXQ_ACTIVE) ||
      ci_ip_queue_not_empty(&ts->retrans) ) {
    ts->zwin_probes = 0;
    ts->zwin_acks = 0;
    return;
  }
  if( ci_tcp_sendq_is_empty(ts) ) {
    /* Keep running timer so we don't have to start it (and make the
     * associated check) on the data fast path when sendq goes
     * non-empty */
    ci_tcp_zwin_set(netif, ts);
    return;
  }

  LOG_TT(log(LNTS_FMT "ZWIN: now=0x%x rto=%u snd_wnd=%d probes=%d,%d",
	     LNTS_PRI_ARGS(netif, ts), ci_tcp_time_now(netif), ts->rto,
	     tcp_snd_wnd(ts), ts->zwin_probes, ts->zwin_acks));

  ci_tcp_send_zwin_probe(netif, ts);
  ci_tcp_zwin_set(netif, ts);
  ts->zwin_probes++;
}


/* Called as action on a delayed acknowledgement timeout (DELACK) */
void ci_tcp_timeout_delack(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_pkt_fmt* pkt;

  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_CLOSED);
  ci_assert((ts->acks_pending & CI_TCP_ACKS_PENDING_MASK) > 0);

  LOG_TV(log(LNT_FMT "DELACK now=0x%x acks_pending=%x", LNT_PRI_ARGS(netif,ts),
	     ci_tcp_time_now(netif), ts->acks_pending));

  pkt = ci_netif_pkt_alloc(netif, 0);
  if( pkt ) {
    CI_TCP_EXT_STATS_INC_DELAYED_ACK( netif );
    CITP_STATS_NETIF_INC(netif, acks_sent);
    ci_tcp_send_ack(netif, ts, pkt, CI_FALSE);
  }
  else {
    LOG_TR(log(LNT_FMT "DELACK now=%x acks_pending=%x NO BUFS (will retry)",
	       LNT_PRI_ARGS(netif, ts),
	       ci_tcp_time_now(netif), ts->acks_pending));
    ci_ip_timer_set(netif, &ts->delack_tid,
		    ci_tcp_time_now(netif) + NI_CONF(netif).tconst_delack);
  }
}


static void ci_tcp_drop_due_to_rto(ci_netif *ni, ci_tcp_state *ts,
                                   int max_retrans)
{
  LOG_U(log(LNTS_FMT " (%s) state=%u so_error=%d retransmits=%u max=%u",
            LNTS_PRI_ARGS(ni, ts), __FUNCTION__,
            ts->s.b.state, ts->s.so_error, ts->retransmits, max_retrans));
  /* Linux does NOT send RST here. */
  ts->retransmits = 0;
  if( ts->s.b.state == CI_TCP_SYN_SENT )
    CITP_STATS_NETIF(++ni->state->stats.tcp_connect_timedout);
  ci_tcp_drop(ni, ts, ETIMEDOUT);
}


void ci_tcp_send_corked_packets(ci_netif* netif, ci_tcp_state* ts)
{
  /* Remove CI_PKT_FLAG_TX_MORE flag flag to ensure that we no more defer
   * sending unnecessarily.  Set PSH flag in the last packet.
   *
   * ci_tcp_tx_advance() may be unable to send all the packets because of
   * congestion window or other limitations, but we have to ensure that the
   * packets are sent as soon as these other limitations cease to exist.
   */
  if( ci_ip_queue_not_empty(&ts->send) ) {
    oo_pkt_p pp = ts->send.head;
    ci_ip_pkt_fmt* pkt;
    do {
      pkt = PKT_CHK(netif, pp);
      pp = pkt->next;
      pkt->flags &=~ CI_PKT_FLAG_TX_MORE;
    } while( OO_PP_NOT_NULL(pp) );
    TX_PKT_TCP(pkt)->tcp_flags |= CI_TCP_FLAG_PSH;
    ci_tcp_tx_advance(ts, netif);
  }
}

/* Called as TCP_CORK timeout */
void ci_tcp_timeout_cork(ci_netif* netif, ci_tcp_state* ts)
{
  ci_tcp_send_corked_packets(netif, ts);
}


/* Called as action on a retransmission timer timeout (RTO) */
void ci_tcp_timeout_rto(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_pkt_queue* rtq = &ts->retrans;
  unsigned max_retrans;
  int seq_used;

  if( CI_CFG_TAIL_DROP_PROBE &&
      (ts->tcpflags & CI_TCPT_FLAG_TAIL_DROP_TIMING) ) {
    ci_tcp_timeout_taildrop(netif, ts);
    return;
  }

  ci_assert(netif);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_CLOSED);

  /* Must have data unacknowledged for an RTO timeout. */
  ci_assert(!ci_tcp_retransq_is_empty(ts));

  LOG_TL(ci_ip_pkt_fmt* pkt = PKT(netif, rtq->head);
	 log(LNTS_FMT "RTO now=%x srtt=%u rttvar=%u rto=%u retransmits=%d",
	     LNTS_PRI_ARGS(netif, ts), ci_tcp_time_now(netif), 
	     tcp_srtt(ts), tcp_rttvar(ts), ts->rto, ts->retransmits);
	 log("  "TCP_SND_FMT, TCP_SND_PRI_ARG(ts));
	 log("  "TCP_CONG_FMT, TCP_CONG_PRI_ARG(ts));
	 log("  head=%08x-%08x tsval=%x pkt_flag=%u",
	     pkt->pf.tcp_tx.start_seq, pkt->pf.tcp_tx.end_seq,
	     (ts->tcpflags&CI_TCPT_FLAG_TSO) ?
       PKT_IPX_TCP_TSO_TSVAL(ipcache_af(&ts->s.pkt), pkt):0x0, pkt->flags));
  CI_IP_SOCK_STATS_INC_RTTO( ts );

#if CI_CFG_BURST_CONTROL
  /* We've waited a whole RTO timeout, so disable any burst control
     from previous sends. Otherwise we might not send anything at
     all. (Bug 1208). */
  ts->burst_window = 0;
#endif

  if( ts->s.b.state == CI_TCP_SYN_SENT ) {
    max_retrans = NI_OPTS(netif).retransmit_threshold_syn;
    switch( ts->retransmits ) {
      case 0:
        CITP_STATS_NETIF(++netif->state->stats.tcp_syn_retrans_once);
        break;
      case 1:
        CITP_STATS_NETIF(++netif->state->stats.tcp_syn_retrans_twice);
        break;
      case 2:
        CITP_STATS_NETIF(++netif->state->stats.tcp_syn_retrans_thrice);
        break;
    }
    CITP_STATS_NETIF(++netif->state->stats.tcp_syn_retrans);
  }
  else if( ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN ) {
    max_retrans = NI_OPTS(netif).retransmit_threshold_orphan;
    CITP_STATS_NETIF(++netif->state->stats.tcp_rtos);
  }
  else {
    max_retrans = NI_OPTS(netif).retransmit_threshold;
    CITP_STATS_NETIF(++netif->state->stats.tcp_rtos);
  }

  /* Re-send FIN if necessary */
  if( CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_FIN_PENDING ) ) {
    if( ci_tcp_resend_fin(ts, netif) ) {
      /* ci_tcp_add_fin() calls ci_tcp_tx_advance(), so we've already
       * pushed something to the net, and restarted RTO.  Return. */
      return;
    }
    if( ts->retransmits >= max_retrans) {
      ci_tcp_drop_due_to_rto(netif, ts, max_retrans);
      CITP_STATS_NETIF_INC(netif, tcp_cant_fin_dropped);
      return;
    }
    /* There are no packets.  It is useless to retransmit anything.
     * Do not use too large RTO - we know that FIN was "lost" on this side
     * of network.
     */
    ++ts->retransmits;
    ci_tcp_rto_set(netif, ts);
    return;
  }

  if( ts->retransmits >= max_retrans || NI_OPTS(netif).rst_delayed_conn ) {
    ts->s.so_error = ETIMEDOUT;
    ci_tcp_drop_due_to_rto(netif, ts, max_retrans);
    return;
  }

  if( ts->s.b.state == CI_TCP_SYN_SENT && ts->s.so_error != 0 &&
       ts->retransmits > 0 /* ts->retransmits is incremented further down */ )
  {
    ci_tcp_drop_due_to_rto(netif, ts, max_retrans);
    return;
  }

  if( ts->congstate & CI_TCP_CONG_RTO ){
    /* RTO after a retransmission based on an RTO.
    **
    ** Ambiguous what to do here, but 2*SMSS is sensible: See:
    ** http://www.postel.org/pipermail/end2end-interest/2003-July/003244.html
    **
    ** (NB. ctk had 003374.html here, but it doesn't exist!  The one I've
    ** replaced it with looks right).
    */
    ts->ssthresh = tcp_eff_mss(ts) << 1u;
  }
  else {
    /* Set cwnd to 1SMSS and ssthresh to half flightsize.  But careful as
    ** NewReno fast-recovery will have an inflated flightsize.
    */
    if( ts->congstate == CI_TCP_CONG_FAST_RECOV &&
	!(ts->tcpflags & CI_TCPT_FLAG_SACK) ) {
      unsigned x = ts->ssthresh >> 1u;
      unsigned y = tcp_eff_mss(ts) << 1u;
      ts->ssthresh = CI_MAX(x, y);
    }
    else
      ts->ssthresh = ci_tcp_losswnd(ts);

    ts->congstate = CI_TCP_CONG_RTO;
    ts->cwnd_extra = 0;
    ++ts->stats.rtos;
  }

  ts->congrecover = tcp_snd_nxt(ts);

  /* Reset congestion window to one segment (RFC2581 p5). */
  ts->cwnd = CI_MAX((ci_uint32)tcp_eff_mss(ts), NI_OPTS(netif).loss_min_cwnd);
  ts->cwnd = CI_MAX(ts->cwnd, NI_OPTS(netif).min_cwnd);
  ts->bytes_acked = 0;

  /* Backoff RTO timer and restart. */
  ts->rto <<= 1u;
  ts->rto = CI_MIN(ts->rto, NI_CONF(netif).tconst_rto_max);    
  ci_tcp_rto_set(netif, ts);
  ci_assert(!(ts->tcpflags & CI_TCPT_FLAG_TAIL_DROP_TIMING));

  /* Delete all SACK marks (RFC2018 p6).  The reason is that the receiver
  ** is permitted to drop data that it has SACKed but not ACKed.  This
  ** ensures that we will eventually retransmit such data.
  */
  ci_tcp_clear_sacks(netif, ts);

  if( ci_tcp_inflight(ts) < (tcp_eff_mss(ts) >> 1) * ts->retrans.num )
    /* At least half the space in the retransmit queue is wasted, so see if
    ** we can coalesce it to make retransmits more efficient.
    */
    ci_tcp_retrans_coalesce_block(netif, ts, PKT_CHK(netif, rtq->head));

  /* Start recovery.  Because cwnd is only 1 MSS, we'll only transmit one
  ** packet from here.  (This is the right thing to do).
  */
  ++ts->retransmits;

  if( ci_tcp_retrans(netif, ts, ts->cwnd, 0, &seq_used) )
    /* All data has already been retransmitted and state can move to COOLING.
     * However, we keep CONG_RTO flag so that on next incoming ACK srtt
     * could be updated */
    ts->congstate = CI_TCP_CONG_RTO | CI_TCP_CONG_COOLING;
  ci_assert(SEQ_LT(tcp_snd_una(ts), ts->congrecover));
}


static void ci_tcp_timeout_taildrop(ci_netif* netif, ci_tcp_state* ts)
{
#if CI_CFG_TAIL_DROP_PROBE
  ci_assert(NI_OPTS(netif).tail_drop_probe);
  ci_assert(ts->tcpflags & CI_TCPT_FLAG_TAIL_DROP_TIMING);

  LOG_TL(log(FNTS_FMT "now=%x srtt=%u+%u "TCP_SND_FMT,
	     FNTS_PRI_ARGS(netif, ts), ci_tcp_time_now(netif), 
	     tcp_srtt(ts), tcp_rttvar(ts), TCP_SND_PRI_ARG(ts)));

  if( CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_FIN_PENDING ) ) {
    if( ci_tcp_resend_fin(ts, netif) )
      return;
    if( ts->retrans.num == 0 ) {
      /* Force normal RTO for the unsent FIN */
      ts->tcpflags &=~ CI_TCPT_FLAG_TAIL_DROP_TIMING;
      ci_tcp_rto_set(netif, ts);
      return;
    }
  }
  ci_assert(ts->retrans.num > 0);

  /* Restart RTO timer before calling ci_tcp_tx_advance() (so that it
   * doesn't enable TLP timer) and before calling ci_tcp_retrans_one()
   * (which asserts that the RTO timer is already running).
   */
  ts->tcpflags &=~ CI_TCPT_FLAG_TAIL_DROP_TIMING;
  ci_tcp_rto_set(netif, ts);

  /* If we have new data to send, and window, send that. */
  if( ts->send.num > 0 ) {
    const ci_ip_pkt_fmt* pkt = PKT_CHK(netif, ts->send.head);
    if( SEQ_LE(pkt->pf.tcp_tx.end_seq, ts->snd_max) ) {
      ci_uint32 cntr;
      ci_tcp_tx_advance_to(netif, ts, pkt->pf.tcp_tx.end_seq, &cntr);
      CITP_STATS_NETIF(++netif->state->stats.tail_drop_probe_sendq);
      return;
    }
  }

  /* At most one outstanding TLP retransmission */
  if( (ts->tcpflags & CI_TCPT_FLAG_TAIL_DROP_MARKED) &&
      /* MARKED doesn't get cleared until snd_una goes past the mark, so
       * una has to be before the mark to indicate a probe is inflight.
       */
      SEQ_LT(tcp_snd_una(ts), ts->taildrop_mark) )
    return;

  if( ci_tcp_retrans_one(ts, netif, PKT_CHK(netif, ts->retrans.tail)) )
    return;

  ts->taildrop_mark = ts->snd_nxt;
  ts->tcpflags |= CI_TCPT_FLAG_TAIL_DROP_MARKED;
  CITP_STATS_NETIF(++netif->state->stats.tail_drop_probe_retrans);
#endif
}


#endif
/*! \cidoxg_end */
