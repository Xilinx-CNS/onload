/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr/ctk
**  \brief  TCP receive
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

/*
** If run short of RX buffers (ie. cannot refill RX DMA Q), can either
** allocate more, or start copying into non-pinned memory, or possibly drop
** received data from TCP queues (where it hasn't already been acked).
** Important to avoid overcommitting buffers to transmit side I guess.
**
** Acknowledgement strategy?  Would like to avoid acking every packet.
** Could ack after timeout provided timeout is less than the timeout that
** would cause the transmitter to retransmit.  (What is transmit timeout
** based on?  RTT?).
** This delayed ack timer is typically set to 200ms in many OS.
** We should ACK every other at least and within 500ms; see RFC2581/RFC1122.
**
** In fact in practice Linux is retransmitting if we don't ack within
** 200ms.  So we need our delayed-ack timer to be less than this.
*/

#include "ip_internal.h"
#include "tcp_rx.h"
#if CI_CFG_TCP_OFFLOAD_RECYCLER
#include <onload/tcp-ceph.h>
#endif


#if OO_DO_STACK_POLL
#define LPF "TCP RX "

/* TCP RX status */
#define TCP_RX_FMT              "pkt=%08x-%08x " RCV_WND_FMT
#define TCP_RX_ARGS(rxp, ts)     rxp->seq, rxp->pkt->pf.tcp_rx.end_seq, \
    RCV_WND_ARGS(ts)

#define ARP_REINFORCE_ON_SYN

static void handle_rx_slow(ci_tcp_state* ts, ci_netif* netif,
			   ciip_tcp_rx_pkt* rxp);

static int ci_tcp_rx_enqueue_ooo(ci_netif* netif, ci_tcp_state* ts,
                                  ciip_tcp_rx_pkt* rxp);


static inline bool tcp_plugin_pkt_was_recycled(ci_tcp_state* ts,
                                               const ci_ip_pkt_fmt* pkt)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  ci_assert(ci_tcp_is_pluginized(ts));
  /* rx_sock is the user_mark from the plugin. See SF-123622 for encoding
   * information. The top bit is set to rdp_in_net, i.e. cleared when this
   * packet has already been seen by Onload at least once. */
  return ! (pkt->pf.tcp_rx.lo.rx_sock >> 31);
#else
  return false;
#endif
}


ci_ip_pkt_fmt* __ci_netif_pkt_rx_to_tx(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                       const char* caller)
{
  if( pkt->refcount == 1 ) {
    if( ~pkt->flags & CI_PKT_FLAG_RX ) {
      ci_assert_equal(pkt->intf_i, OO_INTF_I_LOOPBACK);
    }
    else {
      pkt->flags &= ~CI_PKT_FLAG_RX;
      --ni->state->n_rx_pkts;
    }
    CI_DEBUG(pkt->pkt_start_off = PKT_START_OFF_BAD;
             pkt->pkt_eth_payload_off = PKT_START_OFF_BAD);
  }
  else {
    /* Let's cheat and avoid slow path: try bufset of this packet first,
     * the currently-used bufset second. */
    int old_bufset_id, new_bufset_id;

    old_bufset_id = PKT_SET_ID(pkt);
    new_bufset_id = NI_PKT_SET(ni);
    ci_netif_pkt_release(ni, pkt);
    if(CI_LIKELY( ni->packets->set[old_bufset_id].n_free > 0 ))
      pkt = ci_netif_pkt_get(ni, old_bufset_id);
    else if( old_bufset_id != new_bufset_id &&
             ni->packets->set[new_bufset_id].n_free > 0 )
      pkt = ci_netif_pkt_get(ni, new_bufset_id);
    else
      pkt = ci_netif_pkt_alloc_slow(ni, CI_PKT_ALLOC_USE_NONB);
    if( pkt == NULL ) {
      LOG_U(ci_log("%s: can't allocate reply packet", caller));
      CITP_STATS_NETIF_INC(ni, poll_no_pkt);
      return NULL;
    }
  }
  return pkt;
}


ci_inline void ci_tcp_rx_update_state_on_add(ci_tcp_state* ts, int recvd)
{
  /* Ensure packet has been enqueued onto async receive queue. */
  ci_wmb();
  /* Only then make data available to receive path. */
  ts->rcv_added += recvd;
  /* This tells the receive path at what point it should send a window
  ** update after freeing space in the recv queue.
  */
  ts->ack_trigger = ts->rcv_delivered + ci_tcp_ack_trigger_delta(ts);
  /* Tells post-poll loop to put socket on the [reap_list]. */
  ts->s.b.sb_flags |= CI_SB_FLAG_RX_DELIVERED;
}


void ci_tcp_rx_reap_rxq_bufs(ci_netif* netif, ci_tcp_state* ts)
{
  /* Free all packets from the head of the queue to just before the extract
  ** pointer.
  */
  ci_ip_pkt_queue* rxq = &ts->recv1;
  int n = 0;

  ci_assert(ci_netif_is_locked(netif));

  while( ! OO_PP_EQ(rxq->head, ts->recv1_extract) ) {
    ci_ip_pkt_fmt* pkt = PKT_CHK(netif, rxq->head);
    oo_pkt_p next = pkt->next;

    ci_netif_pkt_release_check_keep(netif, pkt);
    ++n;
    rxq->head = next;
  }
  if( n == 0 )
    return;
  ci_tcp_rx_buf_adjust(netif, ts, rxq, -n);
  rxq->num -= n;
}

void ci_tcp_rx_reap_rxq_last_buf(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_pkt_fmt* pkt = PKT_CHK(netif, ts->recv1_extract);

  ci_assert(ci_sock_is_locked(netif, &ts->s.b));

  ci_assert(OO_PP_EQ(ts->recv1_extract, ts->recv1.head));

  if( oo_offbuf_is_empty(&pkt->buf) ) {
    ts->recv1_extract = ts->recv1.head = pkt->next;
    ci_netif_pkt_release_check_keep(netif, pkt);
    ci_tcp_rx_buf_adjust(netif, ts, &ts->recv1, -1);
    --ts->recv1.num;
  }
}


static void remove_from_last_sack(ci_tcp_state* ts, oo_pkt_p id)
{
  if( ts->tcpflags & CI_TCPT_FLAG_SACK ) {
    int i;
    for( i = 0; i <= CI_TCP_SACK_MAX_BLOCKS; i++ )
      if( OO_PP_EQ(ts->last_sack[i], id) )
        ts->last_sack[i] = OO_PP_NULL;
        /* We should not break from for(), because duplicate last_sack
         * entries are possible after the arrival of a new segment which
         * caused ci_tcp_rx_glue_rob() to glue two blocks. */
  }
}


static void ci_tcp_rx_add_to_recvq(ci_netif *netif, ci_tcp_state *ts,
                                   ci_ip_pkt_fmt *pkt, int bytes)
{
  ci_ip_pkt_queue* rxq = TS_QUEUE_RX(ts);
  oo_pkt_p prevhead = rxq->head;

  ci_assert(ci_netif_is_locked(netif));
  pkt->next = OO_PP_NULL;
  /* Barrier ensures concurring thread is able to read metadata
   * of pkt buffers pointed to by recv1_extract. */
  ci_wmb();
  __ci_tcp_rx_queue_enqueue(netif, ts, rxq, pkt);

  if( rxq == &ts->recv1 ) {
    if( OO_PP_IS_NULL(prevhead) ) {
      ci_assert(OO_PP_IS_NULL(ts->recv1_extract));
      /* recv1_extract is protected by socket lock.  However,
       * modification here is correct as both rxq->head and
       * recv1_extract have been NULL, which excludes simultaneous
       * processing. */
      ts->recv1_extract = rxq->head;
    }
    ci_tcp_rx_reap_rxq_bufs(netif, ts);
  }

  ci_tcp_rx_update_state_on_add(ts, bytes);
}


static void ci_tcp_rx_clean_plugin_rob(ci_netif *netif, ci_tcp_state *ts,
                                       uint32_t nxt)
{
  /* In pluginized mode the rob doubles up as the to-recycle queue so we must
   * clean that up now that we've guaranteed that the plugin will give us the
   * ooo data. (the rob is conceptually in two halves, head..rcv_nxt (what's
   * dropped here) and tcp_nxt..tail (the 'classic' rob); see commentary in
   * ci_tcp_rx_deliver_rob()) */
  ci_ip_pkt_fmt* p;

  if( ci_ip_queue_is_empty(&ts->rob) )
    return;
  ci_assert(ci_ip_queue_is_valid(netif, &ts->rob));
  ci_assert(ci_tcp_is_pluginized(ts));
  while( (p = PKT_CHK(netif, ts->rob.head)) != NULL &&
         SEQ_LE(p->pf.tcp_rx.end_seq, nxt) ) {
    remove_from_last_sack(ts, ts->rob.head);
    ci_ip_queue_dequeue(netif, &ts->rob, p);
    if( ci_ip_queue_is_empty(&ts->rob) ) {
      ci_netif_pkt_release_rx(netif, p);
      break;
    }
    if( PKT_TCP_RX_ROB(p)->num > 1 ) {
      ci_ip_pkt_fmt* p2 = PKT_CHK(netif, ts->rob.head);
      if( p2 ) {
        *PKT_TCP_RX_ROB(p2) = *PKT_TCP_RX_ROB(p);
        --PKT_TCP_RX_ROB(p2)->num;
      }
    }
    ci_netif_pkt_release_rx(netif, p);
  }
}


/** Enqueue a single packet pkt on the receive queue of [ts]. */
static void ci_tcp_rx_enqueue_packet(ci_netif *netif, ci_tcp_state *ts,
                                     ci_ip_pkt_fmt *pkt)
{
  ci_assert(ci_netif_is_locked(netif));
  ci_assert_equal(SEQ_SUB(pkt->pf.tcp_rx.end_seq, tcp_rcv_nxt(ts)) -
                  ((PKT_IPX_TCP_HDR(ipcache_af(&ts->s.pkt),
                  pkt)->tcp_flags & CI_TCP_FLAG_FIN) ? 1 : 0),
                  oo_offbuf_left(&pkt->buf));

  if( ci_tcp_is_pluginized(ts) ) {
    if( SEQ_LT(tcp_rcv_nxt(ts), pkt->pf.tcp_rx.end_seq) )
        tcp_rcv_nxt(ts) = pkt->pf.tcp_rx.end_seq;
    /* Just bin it - we're going to get the actual payload from a different
     * queue, and shoehorn it in to the recvq from there. */
    ci_netif_pkt_release_rx(netif, pkt);
    ci_tcp_rx_clean_plugin_rob(netif, ts, tcp_rcv_nxt(ts));
    return;
  }

  tcp_rcv_nxt(ts) = pkt->pf.tcp_rx.end_seq;
  ci_tcp_rx_add_to_recvq(netif, ts, pkt, oo_offbuf_left(&pkt->buf));
}


#ifdef NDEBUG
# define DO_SLOW_CHAIN_LENGTH_CHECK 0
#else
# define DO_SLOW_CHAIN_LENGTH_CHECK 1
#endif


/* A version of ci_tcp_rx_enqueue_packet that handles a chain of packets
** from another recv queue.
*/
static void ci_tcp_rx_enqueue_chain(ci_netif *netif, ci_tcp_state *ts,
                                    ci_ip_pkt_queue *from,
                                    ci_ip_pkt_fmt *last, int num)
{
  /* We need to know how many bytes of data are in the chain of
     packets we are enqueing. Due to things such as FINs that can
     consume sequenece space, we cannot just use the amount of
     sequence space used. Instead, we assume that the only non-data
     things consuming packet space could be a FIN in the last packet
     in the queue and deal with that case. The code predicated on
     DO_SLOW_CHAIN_LENGTH_CHECK in this function tests this
     assumption, and has not been seen to assertion fail. */

  ci_ip_pkt_queue *rxq = TS_QUEUE_RX(ts);
  oo_pkt_p prevhead = rxq->head;
  int bytes;
#if DO_SLOW_CHAIN_LENGTH_CHECK
  int count = 0;
#endif

  ci_assert(!ci_tcp_is_pluginized(ts));
  ci_assert(ci_netif_is_locked(netif));

  ci_assert(from);
  ci_assert(OO_PP_NOT_NULL(from->head));
  ci_assert(last);

  if (ci_ip_queue_is_empty(from))
    return;

#if DO_SLOW_CHAIN_LENGTH_CHECK
  {
    ci_ip_pkt_fmt *pkt;
    pkt = PKT_CHK(netif, from->head);

    while (pkt) {
      count += oo_offbuf_left(&pkt->buf);
      if( OO_PP_IS_NULL(pkt->next) )
        break;
      if( pkt == last )
        break;
      pkt = PKT_CHK(netif, pkt->next);
    }
  }
#endif

  bytes = last->pf.tcp_rx.end_seq - tcp_rcv_nxt(ts);
  if( PKT_IPX_TCP_HDR(ipcache_af(&ts->s.pkt), last)->tcp_flags & CI_TCP_FLAG_FIN )
    --bytes;

#if DO_SLOW_CHAIN_LENGTH_CHECK
  ci_assert_equal(bytes, count);
#endif

  tcp_rcv_nxt(ts) = last->pf.tcp_rx.end_seq;

  /* move between two rx queues */
  ci_ip_queue_move(netif, from, rxq, last, num);

  if( rxq == &ts->recv1 ) {
    if( OO_PP_IS_NULL(prevhead) ) {
      ci_assert(OO_PP_IS_NULL(ts->recv1_extract));
      ts->recv1_extract = rxq->head;
    }
    ci_tcp_rx_reap_rxq_bufs(netif, ts);
  }

  ci_tcp_rx_update_state_on_add(ts, bytes);
}


#ifdef __ci_driver__
static inline int ci_kill_owner(ci_netif* netif, ci_tcp_state *ts,
                                int sig)
{
  struct pid *pid;
  int ret;

  rcu_read_lock();
  pid = ci_netif_pid_lookup(netif, ts->s.b.sigown);
  ret = kill_pid(pid, sig, 1/*use SEND_SIG_PRIV*/);
  rcu_read_unlock();
  return ret;
}
#endif

/*! If appropriate, send a signal the application that it is to go in TCP
    urgent mode. */
static void ci_tcp_send_sig_urg(ci_netif* netif, ci_tcp_state *ts)
{
  int rc;

  if (!ts->s.b.sigown)
    return;

  LOG_URG(ci_log("%s: sending SIGURG to pid %d", __FUNCTION__,ts->s.b.sigown));

# ifdef __ci_driver__
  rc = ci_kill_owner(netif, ts, SIGURG);
# else
  rc = kill(ts->s.b.sigown, SIGURG);
# endif

  if (rc)
    LOG_U(ci_log("%s: failed to send SIGURG to app, pid=%d, ts=%p(%d)",
                 __FUNCTION__, ts->s.b.sigown, ts, S_FMT(ts)));
}



/*! process an incoming TCP packet which has the urgent pointer set.
 *
 * By default we aim to handle urgent data in a manner compatible with linux.
 * That means that we treat the urgent pointer as referring to a single byte
 * of out-of-band data.
 *
 * We store both the byte of OOB data, and flags relating to its state as
 * tcp_urg_data(ts), and the sequence number of the OOB byte as tcp_rcv_up(ts).
 * The flags stored with the OOB byte indicate its current validity.
 *
 * When we receive a segment containing the OOB byte we switch to the recv2
 * queue, and stick with this until the app has read beyond the point of the
 * OOB byte.  Once we switch back to recv1 the OOB byte can no longer be
 * read.
 *
 * When the urgent byte has been read (directly from the urgent data) then
 * the urgent state will be cleared by ci_tcp_recvmsg_urg().
 *
 * Once we receive a new urgent pointer any old urgent state is lost.  That
 * means that if an old urgent byte is still present in the recvq then it
 * will be returned via a normal recv (even if it's already been read via
 * MSG_OOB).  Onload is not entirely consistent with linux here, but I don't
 * judge it worthwhile to try and exactly emulate the linux behaviour
 * (see bug81108).
 */
static void ci_tcp_urg_pkt_process(ci_tcp_state *ts, ci_netif *netif,
                                   ciip_tcp_rx_pkt *rxp)
{
  ci_ip_pkt_fmt *pkt = rxp->pkt;
  ci_tcp_hdr *tcp = rxp->tcp;
  /*! 1 = RFC compliance, 0 = BSD compliance */
  int urg_ptr_adj = NI_OPTS(netif).urg_rfc;
  int urg_ptr_offset = CI_BSWAP_BE16(tcp->tcp_urg_ptr_be16) + urg_ptr_adj;
  ci_uint32 rcv_up;
  unsigned lastseq = SEQ_SUB(pkt->pf.tcp_rx.end_seq,
                             (tcp->tcp_flags & CI_TCP_FLAG_SYN) ? 2 : 1);

  /* If we already have urgent data we should be using recv2 */
  ci_assert_impl(tcp_urg_data(ts) & CI_TCP_URG_IS_HERE,
                 TS_QUEUE_RX(ts) == &ts->recv2);

  /* If we're already expecting urgent data we should have a valid urg ptr */
  ci_assert_impl(tcp_urg_data(ts) & CI_TCP_URG_COMING,
                 tcp_urg_data(ts) & CI_TCP_URG_PTR_VALID);

  /* If new urgent data is coming, it replaces old urgent data, so we can't
   * have urgent data both coming and here.
   */
  ci_assert_nequal(tcp_urg_data(ts) & (CI_TCP_URG_COMING | CI_TCP_URG_IS_HERE),
                   CI_TCP_URG_COMING | CI_TCP_URG_IS_HERE);

  ci_assert(ci_netif_is_locked(netif));

  if( NI_OPTS(netif).urg_mode == EF_TCP_URG_MODE_IGNORE ) {
    CITP_STATS_NETIF_INC(netif, tcp_urgent_ignore_rx);
    return;
  }
  else
    CITP_STATS_NETIF_INC(netif, tcp_urgent_process_rx);

  /* If the urgent flag was set, then the urgent pointer in this segment is
   * probably valid and we should use it.  Otherwise we use the stored value.
   */
  if( tcp->tcp_flags & CI_TCP_FLAG_URG ) {
    /* If the urgent flag is set, but the ptr value is 0 then treat this as
     * though the urgent flag was not set, as long as we already have a valid
     * urgent pointer.  We do this because if the actual urgent data is in
     * this segment then we need to process it here and it's what linux does.
     */
    if( (urg_ptr_offset == 0) && (tcp_urg_data(ts) & CI_TCP_URG_COMING) )
      rcv_up = tcp_rcv_up(ts);
    else
      rcv_up = rxp->seq + urg_ptr_offset - 1;
  }
  else {
    ci_assert_flags(tcp_urg_data(ts), CI_TCP_URG_PTR_VALID);
    rcv_up = tcp_rcv_up(ts);
  }

  if( SEQ_LT(rcv_up, tcp_rcv_nxt(ts)) ) {
    /* rcv urg ptr falls to the left of the left edge of the rcv wnd */
    LOG_U(log(LPF "rcv_up(%08x) <= rcv_nxt(%08x)", rcv_up, tcp_rcv_nxt(ts)));
    return;
  }
  if( tcp_urg_data(ts) & CI_TCP_URG_PTR_VALID ) {
    /* An OOB byte is in the scope of our receive queue. */
    if( SEQ_LT(rcv_up, tcp_rcv_up(ts)) ) {
      LOG_U(log(LNTS_FMT "URG ptr gone back rcv_up(%08x) < tcp_rcv_up(%08x)",
                LNTS_PRI_ARGS(netif, ts), rcv_up, tcp_rcv_up(ts)));
      return;
    }
    /* This is either a duplicate notification, or a new one. */
  }

  /* This urgent pointer looks valid, update our stored value */
  tcp_rcv_up(ts) = rcv_up;

  /* We're in urgent mode.  If we haven't already done so, we need to
  ** tell the app by sending it a signal.
  */
  if( !(tcp_urg_data(ts) & CI_TCP_URG_COMING) ) {
    ci_tcp_send_sig_urg(netif, ts);
    tcp_urg_data(ts) |= CI_TCP_URG_COMING | CI_TCP_URG_PTR_VALID;
  }

  if( SEQ_LE(rcv_up, lastseq) ) {
    /* the urgent byte is within this packet */
    ci_octet* payload = (ci_octet*) CI_TCP_PAYLOAD(tcp);

    /* copy the urgent byte from the packet and store it tcp state */
    tcp_urg_data(ts) &=~ (CI_TCP_URG_DATA_MASK | CI_TCP_URG_COMING);
    tcp_urg_data(ts) |= CI_TCP_URG_IS_HERE | payload[urg_ptr_offset - 1];
    
    /* Switch to the second RX queue.  NB. If we are already using recv2,
    ** then we could shift all data from recv2 to recv1 here, because
    ** later urgent data renders earlier urgent data obsolete.
    */
    TS_QUEUE_RX_SET(ts, recv2);

    /* we got the OOB byte, hence, we can enable the fast path;
       note that the fast path will carry on adding to the 2nd rx queue
       until the application has read past the OOB mark */
    if( ci_tcp_can_use_fast_path(ts) )
      ci_tcp_fast_path_enable(ts);

    LOG_URG(log(LNTS_FMT "URG data=0x%02X tcp_rcv_up=%08x off=%d",
                LNTS_PRI_ARGS(netif, ts), tcp_urg_data(ts), tcp_rcv_up(ts),
                urg_ptr_offset));

    /* If we want BSD socket semantics, we should remove the urgent byte
    ** from the packet here.
    */
  } else {
    /* we are in urgent mode and haven't received the urgent byte yet */
    tcp_urg_data(ts) &=~ (CI_TCP_URG_DATA_MASK | CI_TCP_URG_IS_HERE);

    /* we disable the fast path if we are in urgent mode, to avoid having to
       pull the tcp state urgent pointer behind rcv_nxt in the fast path */
    ci_tcp_fast_path_disable(ts);

    LOG_URG(log(LNTS_FMT "URG (future) tcp_rcv_up=%08x off=%u",
                LNTS_PRI_ARGS(netif, ts), tcp_rcv_up(ts), urg_ptr_offset));
  }

}

/*
** Incoming seq is acceptable provided it overlaps the window.  See
** rfc793 p25. end_seq includes any FIN/SYN bits. This conforms with
** RFC793 but rejects some good packets.  See
** ci_tcp_seq_definitely_unacceptable for full explanation
*
* The companion (ci_tcp_seq_definitely_unacceptable) checks those
* rejected cases.
*/

ci_inline int ci_tcp_seq_probably_unacceptable(unsigned rcv_nxt,
                                               unsigned rcv_rhs,
                                               unsigned tcp_seq,
                                               unsigned end_seq)
{
  if(SEQ_LE(end_seq, rcv_nxt) | SEQ_LE(rcv_rhs, tcp_seq)){
    /* a non-empty packet outside the window, a zero receive window
    ** and a empty packet will execute here */
    if( SEQ_EQ(end_seq, tcp_seq) && SEQ_EQ(rcv_nxt, tcp_seq)) {
      /* was a zero length packet in an acceptable window */
    } else {
      return 1;
    }
  }
  return 0;
}

/* Checks the cases that ci_tcp_seq_probably_unacceptable() misses.
   assumes you have called ci_tcp_seq_probably_unacceptable() first

   Tests from rfc793:

    Segment Receive  Test
    Length  Window
    ------- -------  -------------------------------------------

       0       0     tcp_seq = rcv_nxt

       0      >0     rcv_nxt =< tcp_seq < rcv_nxt+rcv_wnd

      >0       0     not acceptable

      >0      >0     rcv_nxt =< tcp_seq < rcv_nxt+rcv_wnd
                  or rcv_nxt =< end_seq-1 < rcv_nxt+rcv_wnd
                  ie rcv_nxt < end_seq <= rcv_nxt+rcv_wnd

   Should be, in my opinion:

    Segment Receive  Test
    Length  Window
    ------- -------  -------------------------------------------

       0       0     tcp_seq = rcv_nxt

       0      >0     rcv_nxt =< tcp_seq <= rcv_nxt+rcv_wnd   (added "=")

      >0       0     not acceptable

      >0      >0     rcv_nxt =< tcp_seq < rcv_nxt+rcv_wnd
                  or rcv_nxt =< end_seq-1 < rcv_nxt+rcv_wnd
                  ie rcv_nxt < end_seq <= rcv_nxt+rcv_wnd

   The added term allows a zero length packet (e.g. ACK) at the right
   window edge.  This occurs when packet at left window edge is lost
   (so rcv_nxt doesn't advance) and then transmitter sends whole
   window plus an ACK.  If the packet wasn't lost, the last ACK would
   be accepted (as the first line of the truth table above would
   apply) but because of the lost packet the second line of the truth
   table is used and the inconsistency between them leads to it being
   rejected.  Line 2 in the table is also inconsistent with line 4 in
   the same way: if those tests were applied (and as we know tcp_seq
   == end_seq) the packet would be allowed.  The added "=" rectifies
   these inconsistencies, but technically breaks conformance with RFC793.

*/
ci_inline int ci_tcp_seq_definitely_unacceptable(unsigned rcv_nxt,
                                                 unsigned rcv_rhs,
                                                 unsigned tcp_seq,
                                                 unsigned end_seq)
{
  ci_assert(ci_tcp_seq_probably_unacceptable(rcv_nxt, rcv_rhs,
                                             tcp_seq, end_seq));

  if(SEQ_EQ(end_seq, tcp_seq)
     && rcv_nxt != rcv_rhs
     && SEQ_EQ(tcp_seq, rcv_rhs))
    return 0;
  return 1;
}


static void handle_unacceptable_ack(ci_netif* netif, ci_tcp_state* ts,
                                    ciip_tcp_rx_pkt* rxp)
{
  /* ACK is unacceptable.  Reply with RST if unsynchronised, or empty ACK
  ** otherwise (rfc793 p37).
  */
  CI_IP_SOCK_STATS_INC_ACKERR( ts );
  LOG_U(log(LPF "%d ACK UNACCEPTABLE %s snd_nxt=%08x ack=%08x", S_FMT(ts),
            state_str(ts), tcp_snd_nxt(ts), rxp->ack));

  CITP_STATS_NETIF_INC(netif, unacceptable_acks);

  if( ts->s.b.state & CI_TCP_STATE_SYNCHRONISED ) {
    if( ! ci_tcp_send_challenge_ack(netif, ts, rxp->pkt) ) {
      ci_netif_pkt_release(netif, rxp->pkt);
      return;
    }
  }
  else {
    CITP_STATS_NETIF_INC(netif, rst_sent_unacceptable_ack);
    ci_tcp_reply_with_rst(netif, &ts->s.cp, rxp);
  }

  CI_TCP_STATS_INC_OUT_SEGS( netif );
}


/*
** for an acceptable segment check whether the packet updates the
** current timestamp echo reply
*/
ci_inline void ci_tcp_tso_update(ci_netif* ni, ci_tcp_state* ts,
                                 ci_uint32 beg_seq, ci_uint32 end_seq,
                                 ci_uint32 tsval)
{
  if( SEQ_LE(beg_seq, ts->tslastack) &&
#if CI_CFG_TCP_RFC1323_STRICT_TSO
      SEQ_LT(ts->tslastack, end_seq)
#else
      SEQ_LE(ts->tslastack, end_seq)
#endif
      ) {
      ts->tsrecent = tsval;
      ts->tspaws = ci_tcp_time_now(ni);
#ifndef NDEBUG
      ts->tslastseq = beg_seq; /* temporary debugging */
#endif
  }
}


/* thorough version of PAWs check on slow path */
ci_inline unsigned ci_tcp_paws_check(ci_netif* netif, ci_uint32 tsval,
                                     unsigned tspaws, unsigned tsrecent)
{
  if( CI_LIKELY(TIME_LE(tsrecent, tsval)) )
    return 0;

  /* ugly, but in spec, need to invalidate PAWs if idle for 24 days
  **
  ** NB need to be careful about the test on 32bit since tconst_paws_idle
  ** is close to overflow.
  */
  if(ci_tcp_time_now(netif) - tspaws > NI_CONF(netif).tconst_paws_idle){
    LOG_TC(log(LPF "PAWs idle timeout now=0x%x paws_idle=0x%x tspaws=0x%x",
               ci_tcp_time_now(netif),
               NI_CONF(netif).tconst_paws_idle, tspaws));
    return 0;
  }

  /* ?? CI_IP_SOCK_STATS_INC_PAWSERR(ts); */
  CI_TCP_EXT_STATS_INC_PAWS_ESTAB_REJECTED( netif );

  return CI_TCP_PAWS_FAILED;
}


/* function to open the congestion window following the
** reception of an ack for new data. Implements RFC3465 (ABC)
*/
ci_inline void ci_tcp_opencwnd(ci_netif *ni, ci_tcp_state* ts)
{
#if CI_CFG_CONG_AVOID_NOTIFIED
  /* If congestion has been notified (but no loss detected yet)
     gradually scale the cwnd back */
  if( ts->congstate == CI_TCP_CONG_NOTIFIED ){
    if(SEQ_LE(tcp_snd_una(ts), ts->congrecover))
      ts->congstate = CI_TCP_CONG_OPEN;
  }
  else
#endif
  if( ts->cwnd >= ts->ssthresh ) {
    /* Hack - Increase less aggresively on small round trip times */
#if CI_CFG_CONG_AVOID_SCALE_BACK
    unsigned tmp = 0, cwnd_scaled;
    /* tcp_srtt(ts) would relatively easy exceed 32 for a round trip time
     * on longer links */
    if( tcp_srtt(ts) < 32 )
      tmp = NI_OPTS(ni).cong_avoid_scale_back >> tcp_srtt(ts);
    cwnd_scaled = CI_MAX(1, tmp) * ts->cwnd;
#else
    unsigned cwnd_scaled = ts->cwnd;
#endif
    /* Congestion avoidance.  RFC3465 says: increase the congestion window
    ** by one segment each RTT.  i.e. wait for bytes_acked to be > cwnd
    ** (which takes one RTT), then reset bytes_acked by subtracting the
    ** cwnd from it, and add one segment to cwnd.
    */
    LOG_TV(log(LPF "%d OPENCWND: CA eff_mss=%u bytes_acked=%u cwnd=%u",
               S_FMT(ts), tcp_eff_mss(ts), ts->bytes_acked, ts->cwnd));
    if( ts->bytes_acked >= cwnd_scaled ) {
      ts->bytes_acked -= cwnd_scaled;
      ts->cwnd += tcp_eff_mss(ts);
    }
  }
  else {
    /* Slow-start. */
    unsigned cwnd_inc;
    LOG_TV(log(LPF "%d OPENCWND: SS eff_mss=%u bytes_acked=%u cwnd=%u",
               S_FMT(ts), tcp_eff_mss(ts), ts->bytes_acked, ts->cwnd));
#if CI_CFG_CONG_AVOID_SLOW_START_MODE == 2
    cwnd_inc = CI_MIN(ts->ssthresh - ts->cwnd, ts->bytes_acked);
    ts->cwnd += cwnd_inc;
    ts->bytes_acked -= cwnd_inc;
#else
    if( CI_CFG_CONG_AVOID_SLOW_START_MODE == 0 && ts->stats.rtos == 0 )
      /* RFC3465 sec 2.2: May only increase cwnd by more than mss if we've
      * never had any RTOs on this connection.
      */
      cwnd_inc = tcp_eff_mss(ts) * CI_CFG_CONG_AVOID_RFC3465_L_VALUE;
    else
      cwnd_inc = tcp_eff_mss(ts);
    cwnd_inc = CI_MIN(cwnd_inc, ts->bytes_acked);
    ts->cwnd += cwnd_inc;
    ts->bytes_acked = 0;
#endif
  }

  LOG_TV(log(LPF "%d OPENCWND: end cwnd=%u", S_FMT(ts), ts->cwnd));

  ci_assert_le(tcp_eff_mss(ts), CI_MAX_ETH_FRAME_LEN);
  ci_assert_ge(ts->cwnd, tcp_eff_mss(ts));
  ci_assert_ge(ts->ssthresh, (ci_uint32)(tcp_eff_mss(ts) << 1));
}


static void ci_tcp_reset_cwnd_on_loss(ci_netif* ni, ci_tcp_state* ts)
{
  ts->ssthresh = ci_tcp_losswnd(ts);
  ts->cwnd = ts->ssthresh + ci_tcp_base_dupack_thresh(ts) * tcp_eff_mss(ts);
  ts->cwnd = CI_MAX(ts->cwnd, NI_OPTS(ni).loss_min_cwnd);
  ts->cwnd = CI_MAX(ts->cwnd, NI_OPTS(ni).min_cwnd);
  ci_assert(ts->cwnd >= tcp_eff_mss(ts));
}


/* Enters fast recovery if we've received enough dupacks.  Returns non-zero
 * iff we enter fast recovery. */
int /*bool*/ ci_tcp_maybe_enter_fast_recovery(ci_netif* ni, ci_tcp_state* ts)
{
  ci_uint32 dup_thresh = ci_tcp_base_dupack_thresh(ts);
  ci_ip_pkt_fmt *pkt;

  if( ts->dup_acks == 0 ) {
    return 0;
  }
  else if( ts->dup_acks >= dup_thresh ) {
    /* Standard case: we've received a number of dupacks that takes us to the
     * static threshold for entering fast recovery. */
  }
  else if( NI_OPTS(ni).tcp_early_retransmit &&
           ts->dup_acks >= ts->retrans.num - 1 ) {
    /* We haven't received enough dupacks to enter fast recovery according to
     * the classic scheme, but we have reached the early retransmit (RFC 5827)
     * threshold of (inflight - 1) dupacks.  There are some further conditions
     * that we need to satisfy, though. */
    LOG_TL(log(LNT_FMT "Checking early retransmit at dups=%d "TCP_SND_FMT,
               LNT_PRI_ARGS(ni, ts), ts->dup_acks, TCP_SND_PRI_ARG(ts)));

    /* If we've got new segments queued up and we have sufficient window to
     * send them, we should use limited transmit instead of early retransmit.
     */
    if( ci_ip_queue_not_empty(&ts->send) ) {
      LOG_TL(log(LNT_FMT "Have unsent; use limited transmit if window is open",
                 LNT_PRI_ARGS(ni, ts)));
      pkt = PKT_CHK(ni, ts->send.head);
      if( SEQ_LE(pkt->pf.tcp_tx.end_seq, ts->snd_max) )
        return 0;
      LOG_TL(log(LNT_FMT "Insufficient window for limited transmit; continue "
                 "with ER", LNT_PRI_ARGS(ni, ts)));
    }

    /* If we're using SACK, there must be precisely one un-SACKed segment in
     * flight.  This is what the RFC says, but (TODO) we might wish to consider
     * whether it would be better instead to allow a single un-SACKed _block_.
     */
    if( ts->tcpflags & CI_TCPT_FLAG_SACK &&
        ci_tcp_unsacked_segments_in_flight(ni, ts) != 1 ) {
      LOG_TL(log(LNT_FMT "unsacked != 1", LNT_PRI_ARGS(ni, ts)));
      return 0;
    }
  }
  else {
    /* Not enough dupacks to enter fast recovery. */
    return 0;
  }

  if( ci_ip_queue_is_empty(&ts->retrans) ) {
    LOG_U(log(LNT_FMT "%d DUPACKs, but no data to retransmit!",
              LNT_PRI_ARGS(ni, ts), ts->dup_acks));
    return 0;
  }

  ++ts->stats.fast_recovers;
  ci_tcp_reset_cwnd_on_loss(ni, ts);

  ts->congrecover = tcp_snd_nxt(ts);
  ci_tcp_retrans_init_ptrs(ni, ts, &ts->congrecover);
  if(!SEQ_LE(ts->congrecover, tcp_snd_nxt(ts)))
    LOG_U(log("About to assert on congrecover: %u, %u",
              ts->congrecover, tcp_snd_nxt(ts)));
  ci_assert(SEQ_LE(ts->congrecover, tcp_snd_nxt(ts)));

  LOG_TL(log(LNT_FMT "%s => FastRecovery dups=%d "TCP_SND_FMT,
             LNT_PRI_ARGS(ni, ts), congstate_str(ts), ts->dup_acks,
             TCP_SND_PRI_ARG(ts));
         log(LNT_FMT "  "TCP_CONG_FMT,
             LNT_PRI_ARGS(ni, ts), TCP_CONG_PRI_ARG(ts)));

  ts->congstate = CI_TCP_CONG_FAST_RECOV;

  if( ts->tcpflags & CI_TCPT_FLAG_SACK )
    ci_tcp_retrans_recover(ni, ts, 1);
  else
    ci_tcp_retrans_one(ts, ni, PKT_CHK(ni, ts->retrans.head));

  /* ?? Before or after retransmits?  Not sure. */
  ci_tcp_clear_rtt_timing(ts);
  /* Fast recovery => no TLP timer, force RTO */
  ci_tcp_rto_restart(ni, ts);

  CI_IP_SOCK_STATS_INC_DUPACKFREC( ts );
  if( ts->tcpflags & CI_TCPT_FLAG_SACK )
    CI_TCP_EXT_STATS_INC_TCP_SACK_RECOVERY( ni );
  else
    CI_TCP_EXT_STATS_INC_TCP_RENO_RECOVERY( ni );

  return 1;
}


static void ci_tcp_cwnd_extra_update(ci_netif* netif, ci_tcp_state* ts)
{
  unsigned fack;
  int retrans_data;
  ci_tcp_get_fack(netif, ts, &fack, &retrans_data);
  ts->cwnd_extra = SEQ_SUB(fack, tcp_snd_una(ts)) - retrans_data;
  ts->cwnd_extra = CI_MAX(ts->cwnd_extra, 0);
}

/*
** Called when a duplicate acknowledgement found
*/
static void ci_tcp_rx_dupack(ci_tcp_state* ts, ci_netif* netif,
                             ciip_tcp_rx_pkt* rxp)
{
  ci_assert(SEQ_EQ(tcp_snd_una(ts), rxp->ack));

#if CI_CFG_TAIL_DROP_PROBE
  if(CI_UNLIKELY( (ts->tcpflags & CI_TCPT_FLAG_TAIL_DROP_MARKED) &&
                  SEQ_EQ(rxp->ack, ts->taildrop_mark) )) {
    /* This dupack acknowledges the probe.  There was another ack before,
     * so it must have acknowledged the original.  Therefore no loss
     * indicated (unless SACK says otherwise).
     */
    CITP_STATS_NETIF(++netif->state->stats.tail_drop_probe_unnecessary);
    ts->tcpflags &=~ CI_TCPT_FLAG_TAIL_DROP_MARKED;
    if( ! (rxp->flags & CI_TCP_SACKED) )
      return;
  }
#endif

  ++(ts->dup_acks);

  LOG_TL(log(LNT_FMT "DUPACK dups=%d "TCP_SND_FMT,
             LNT_PRI_ARGS(netif, ts), ts->dup_acks, TCP_SND_PRI_ARG(ts));
         log(LNT_FMT "  %s cwnd=%i crecover=%08x now-rto_to=%u rto=%u",
             LNT_PRI_ARGS(netif, ts), congstate_str(ts), ts->cwnd,
             ts->congrecover, ci_tcp_time_now(netif) - ts->rto_tid.time,
             ts->rto));
  CI_IP_SOCK_STATS_INC_DUPACK( ts );

  /* Limited Transmit, RFC 3042: if we receive a dupack with new SACK
   * information but we haven't quite received enough dupacks for fast recovery
   * (RFC says exactly two, but that assumes that the fast recovery threshold
   * is fixed at three), then allow sends a little way beyond the end of the
   * congestion window.  Inform the TX path, which will be called in the
   * post-poll loop, if we meet the necessary conditions. */
  if( NI_OPTS(netif).tcp_early_retransmit &&
      ts->dup_acks == ci_tcp_base_dupack_thresh(ts) - 1 &&
      (! (ts->tcpflags & CI_TCPT_FLAG_SACK) || rxp->flags & CI_TCP_SACKED) )
    ts->tcpflags |= CI_TCPT_FLAG_LIMITED_TRANSMIT;

  if( (ts->congstate == CI_TCP_CONG_OPEN)
      | (ts->congstate == CI_TCP_CONG_NOTIFIED) ) {
    /* Goto fast recovery if we've received enough dupacks. */
    ci_tcp_maybe_enter_fast_recovery(netif, ts);
  }
  else if( ts->congstate == CI_TCP_CONG_FAST_RECOV ) {
    if( !(ts->tcpflags & CI_TCPT_FLAG_SACK) ) {
      /* RFC3465 - ABC - makes no mention of what to do in this situation.
      ** So therefore stick with what RFC2581 p7 tells us: Inflate window
      ** since packet left network.  This will inflate by too much if the
      ** segment that left wasn't full.  We would try to fix this by
      ** guessing which segment it was, but I don't think it's worth it.
      */
      ts->cwnd += tcp_eff_mss(ts);
      CI_IP_SOCK_STATS_INC_DUPACKCONGFREC( ts );
    }
    /* else sack might have advanced the window */
    ci_tcp_retrans_recover(netif, ts, 0);
  }
  else if( (ts->congstate & CI_TCP_CONG_COOLING) &&
           (rxp->flags & CI_TCP_SACKED) ) {
    /* We're in COOLING, so no need to retransmit, but want to continue
    ** adjusting congestion window for packets that have left the network
    ** ci_tcp_rx_sack_process() processed SACK information, which
    ** will now be used to compute fack.
    **/
    ci_tcp_cwnd_extra_update(netif, ts);
  }
  else {
    /* Note: there is nothing to send here in CONG_RTO* states as dupack
     * does not advance cwnd */
    /* FIXME: consider
     *  NewReno rfc6582 p4.1 (or at least ci_tcp_maybe_enter_fast_recovery() )
     *  F-RTO rfc5682 p2.1 3b
     */
  }

  ci_assert(ts->cwnd >= tcp_eff_mss(ts));
}


/* This is called when we're in a congested state and new data has been
** ACKed.  It is called after ACKed buffers have been freed and snd_una has
** been updated.
*/
static void ci_tcp_try_cwndrecover(ci_tcp_state* ts, ci_netif* netif,
                                   ci_ip_pkt_fmt* pkt)
{
  ci_ip_pkt_queue* rtq = &ts->retrans;

  ci_assert(ts->congstate != CI_TCP_CONG_OPEN
            && ts->congstate != CI_TCP_CONG_NOTIFIED);

  LOG_TL(log(LNT_FMT "%s snd_una=%08x cwnd=%d ssthresh=%d crecover=%08x",
             LNT_PRI_ARGS(netif, ts), congstate_str(ts),
             tcp_snd_una(ts), ts->cwnd, ts->ssthresh, ts->congrecover));

  if( ts->congstate & CI_TCP_CONG_RTO ) {
    /* The RTO is backed-off when it fires.  Now that we've had some data
    ** ACKed we reset it to a sensible value.
    */
    ts->rto = tcp_srtt(ts) + ts->sv;
    ci_tcp_rto_bound(netif, ts);
    if( ts->congstate == (CI_TCP_CONG_COOLING | CI_TCP_CONG_RTO) )
      ts->congstate = CI_TCP_CONG_COOLING;
  }

  if( SEQ_LE(ts->congrecover, tcp_snd_una(ts)) ) {
    ci_tcp_recovered(netif, ts);
    return;
  }

  switch( ts->congstate ) {
    case CI_TCP_CONG_FAST_RECOV:
      if( !(ts->tcpflags & CI_TCPT_FLAG_SACK) ) {
        /* NewReno rfc2582.  Partial ACK, so retransmit the packet at the
        ** head of the retransmit queue.
        */
        ci_tcp_retrans_one(ts, netif, PKT_CHK(netif, rtq->head));
        return;
      }
      break;

    case CI_TCP_CONG_RTO:
      ci_assert(! ci_ip_queue_is_empty(rtq));
      ci_tcp_rto_restart(netif, ts);
      ts->congstate = CI_TCP_CONG_RTO_RECOV;
      /* fall through to RTO_RECOV */

    case CI_TCP_CONG_RTO_RECOV:
      break; /* Just proceed below to ci_tcp_retrans_recover() */

    case CI_TCP_CONG_COOLING:
      /* We're waiting until we reach congrecover before going back to
      ** OPEN.  In the meantime, keep maintaining [cwnd_extra].
      */
      ci_tcp_cwnd_extra_update(netif, ts);
      return;
  }

  ci_tcp_retrans_recover(netif, ts, 0);
}


/* Marks packets in the retransmit queue as having been SACKed.  Returns non-
 * zero if and only if the block allowed us to mark an entire packet, not
 * previously SACKed, as having now been SACKed. */
static int /*bool*/
ci_tcp_rx_sack_process_block(ci_netif* ni, ci_tcp_state* ts, unsigned start,
                             unsigned end)
{
  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt* start_block;
  ci_ip_pkt_fmt* start_block_end;
  ci_ip_pkt_fmt* start_pkt;
  ci_ip_pkt_fmt* start_pkt_prev;
  ci_ip_pkt_fmt* end_block;
  ci_ip_pkt_fmt* end_pkt;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p next_pp;

  /* ?? TODO:
  **
  ** If in CI_TCP_CONG_COOLING, then we would like to spot any new SACK
  ** blocks beyond existing ones.  We should then jump back into fast
  ** recovery so we can transmit the unsacked ones before the new sack.
  **
  ** We'd like to spot any SACKs that give us new info about further
  ** losses.  Either a new SACK block before an existing one, or an
  ** existing blocking extending backwards.  We should respond by mangling
  ** retrans_next pointers to re-retransmit the packets we've deduced got
  ** lost (again).
  **
  ** An alternative to the above is to spot any new sacks that preceed
  ** [retrans_seq].  Which is better?
  */

  /* Find the block the first packet covered is in.  (The packet at the
  ** head of rtq certainly won't qualify).
  */
  next_pp = rtq->head;
  while( 1 ) {
    start_block = PKT_CHK(ni, next_pp);
    if( OO_PP_IS_NULL(start_block->pf.tcp_tx.block_end) ) {
      /* This is the trailing unsacked region. */
      ci_assert(!(start_block->flags & CI_PKT_FLAG_RTQ_SACKED));
      start_block_end = PKT_CHK(ni, rtq->tail);
      ci_assert(SEQ_LE(end, start_block_end->pf.tcp_tx.end_seq));
    }
    else
      start_block_end = PKT_CHK(ni, start_block->pf.tcp_tx.block_end);
    if( SEQ_LE(start, start_block_end->pf.tcp_tx.start_seq) )  break;
    if( (start_block->flags & CI_PKT_FLAG_RTQ_SACKED) &&
        SEQ_LE(start, start_block_end->pf.tcp_tx.end_seq) ) {
      /* This only happens if other end is giving inconsistent info. */
      LOG_TV(log(LNT_FMT "SACK %08x-%08x partial overlap %08x-%08x",
                 LNT_PRI_ARGS(ni, ts), start, end,
                 start_block->pf.tcp_tx.start_seq,
                 start_block_end->pf.tcp_tx.end_seq));
      start_pkt = start_block_end;
      start_pkt_prev = 0;
      goto got_start_pkt;
    }
    next_pp = start_block_end->next;
    if( OO_PP_IS_NULL(next_pp) )  break;
  }

  /* Find the starting packet. */
  start_pkt_prev = 0;
  start_pkt = start_block;
  while( SEQ_LT(start_pkt->pf.tcp_tx.start_seq, start) ) {
    if( OO_PP_IS_NULL(start_pkt->next) ) {
      LOG_TV(log(LNT_FMT "SACK %08x-%08x partial of last %08x-%08x",
         LNT_PRI_ARGS(ni, ts), start, end, start_pkt->pf.tcp_tx.start_seq,
         start_pkt->pf.tcp_tx.end_seq));
      return 0;
    }
    start_pkt_prev = start_pkt;
    start_pkt = PKT_CHK(ni, start_pkt->next);
  }
 got_start_pkt:

  /* Find which block the last packet covered is in. */
  end_block = start_block;
  pkt = start_block_end;
  while( 1 ) {
    if( OO_PP_IS_NULL(pkt->next) )  break;
    pkt = PKT_CHK(ni, pkt->next);
    if( SEQ_LT(end, pkt->pf.tcp_tx.end_seq) )  break;
    end_block = pkt;
    if( OO_PP_IS_NULL(end_block->pf.tcp_tx.block_end) )  break;
    pkt = PKT_CHK(ni, end_block->pf.tcp_tx.block_end);
  }

  /* Check for duplicate. */
  if( (start_block->flags & CI_PKT_FLAG_RTQ_SACKED) &&
      start_block == end_block ) {
    LOG_TV(log(LNT_FMT "SACK %08x-%08x duplicate or subset of %08x-%08x",
               LNT_PRI_ARGS(ni, ts), start, end,
               start_block->pf.tcp_tx.start_seq,
               start_block_end->pf.tcp_tx.end_seq));
    return 0;
  }

  /* When marching through the SACKed packets we'll need to update their
  ** [end_block] pointers, so find out what that'll be (ie. find the end
  ** packet).
  */
  if( start_block == end_block )  pkt = start_pkt;
  else                            pkt = end_block;
  end_pkt = 0;
  while( 1 ) {
    if( SEQ_LT(end, pkt->pf.tcp_tx.end_seq) )  break;
    end_pkt = pkt;
    /* This is a common case, so extra test for it here. */
    if( SEQ_EQ(end, pkt->pf.tcp_tx.end_seq) )  break;
    if( OO_PP_IS_NULL(pkt->next) )  break;
    pkt = PKT_CHK(ni, end_pkt->next);
  }
  if( ! end_pkt ) {
    /* [start, end) didn't even cover start_pkt.  This is expected when the
    ** retransmit queue is coalesced.
    */
    LOG_TV(log(LNT_FMT "SACK %08x-%08x within pkt %08x-%08x",
               LNT_PRI_ARGS(ni, ts), start, end,
               start_pkt->pf.tcp_tx.start_seq, start_pkt->pf.tcp_tx.end_seq));
    return 0;
  }

  /* Double check that packets we've chosen are wholly covered by [start,
  ** end).  (NB. Special case for a SACK that partially overlaps the end of
  ** a block).
  */
  ci_assert(SEQ_LE(start, start_pkt->pf.tcp_tx.start_seq) ||
            ((start_block->flags & CI_PKT_FLAG_RTQ_SACKED) &&
             SEQ_LT(start_block->pf.tcp_tx.start_seq, start)));
  ci_assert(SEQ_LE(end_pkt->pf.tcp_tx.end_seq, end));

  if( !(start_block->flags & CI_PKT_FLAG_RTQ_SACKED) && start_pkt_prev ) {
    /* Terminate the unSACKed block properly.
    **
    ** ?? NB. If [retrans_seq] points into this region and we're in
    ** COOLING, then we may want to consider going back into recovery,
    ** since we've got new evidence of loss.  We may need to advance
    ** congrecover in this case.
    */
    ci_assert(start_block != start_pkt);
    while( 1 ) {
      start_block->pf.tcp_tx.block_end = OO_PKT_P(start_pkt_prev);
      if( OO_PP_EQ(start_block->next, OO_PKT_P(start_pkt)) )  break;
      start_block = PKT_CHK(ni, start_block->next);
    }
  }

  /* Check whether this SACK block butts up against an existing one.  If it
  ** does we just need to snarf the end of block.  (This only happens if
  ** other end is giving us inconsistent information).
  */
  next_pp = OO_PKT_P(end_pkt);
  if( OO_PP_NOT_NULL(end_pkt->next) ) {
    pkt = PKT_CHK(ni, end_pkt->next);
    if( pkt->flags & CI_PKT_FLAG_RTQ_SACKED ) {
      LOG_TV(log(LNT_FMT "SACK %08x-%08x inconsistent with %08x-%08x",
                 LNT_PRI_ARGS(ni, ts), start, end,
                 pkt->pf.tcp_tx.start_seq,
                 PKT_CHK(ni, pkt->pf.tcp_tx.block_end)->pf.tcp_tx.end_seq));
      next_pp = pkt->pf.tcp_tx.block_end;
    }
  }

  /* Set [block_end] pointers for the SACKed block. */
  if( start_block->flags & CI_PKT_FLAG_RTQ_SACKED )
    pkt = start_block;
  else
    pkt = start_pkt;
  while( pkt != end_pkt ) {
    pkt->pf.tcp_tx.block_end = next_pp;
    pkt->flags |= CI_PKT_FLAG_RTQ_SACKED;
    pkt = PKT_CHK(ni, pkt->next);
  }
  pkt->pf.tcp_tx.block_end = next_pp;
  pkt->flags |= CI_PKT_FLAG_RTQ_SACKED;

  /* We took early exits from this function when this SACK block was contained
   * within an earlier one, so we know that we have recorded new SACK
   * information. */
  return 1;
}


/*
** Return 1 if the first SACK block is a DSACK, or 0 otherwise.
*/
ci_inline int ci_tcp_rx_dsack_check(ci_netif* ni, ci_tcp_state* ts,
                                    ciip_tcp_rx_pkt* rxp)
{
  unsigned start = rxp->sack[0];
  unsigned end = rxp->sack[1];
  int rc = 0;

  /* DSACK RFC2883 p4 and p9.  It is a DSACK if it covers data that has
  ** been acknowledged (less-than case).  NB. The equals case below is
  ** silly, since it contradicts the ACK field.  But we include it just to
  ** get it out of the way.
  */
  if( SEQ_LE(start, rxp->ack) ) {
    LOG_TO(log(LNT_FMT "DSACK option %08x-%08x ack=%08x una=%08x",
               LNT_PRI_ARGS(ni, ts), start, end, rxp->ack, tcp_snd_una(ts)));
    rxp->flags |= CI_TCP_DSACK;
    rc = 1;
  }
  else if( rxp->sack_blocks > 1 ) {
    /* Alternatively it is a DSACK if block 0 is contained in block 1. */
    unsigned start1 = rxp->sack[2];
    unsigned end1 = rxp->sack[3];
    if( SEQ_LE(start1, start) && SEQ_LE(end, end1) ) {
      LOG_TO(log(LNT_FMT "DSACK option %08x-%08x with next %08x-%08x",
                 LNT_PRI_ARGS(ni, ts), start, end, start1, end1));
      rxp->flags |= CI_TCP_DSACK;
      rc = 1;
    }
  }

#if CI_CFG_TAIL_DROP_PROBE
  if( rc && (ts->tcpflags & CI_TCPT_FLAG_TAIL_DROP_MARKED) &&
      SEQ_GE(rxp->ack, ts->taildrop_mark)) {
    /* Both original packet and our retransmission arrived.  No loss. */
    CITP_STATS_NETIF(++ni->state->stats.tail_drop_probe_unnecessary);
    ts->tcpflags &=~ CI_TCPT_FLAG_TAIL_DROP_MARKED;
  }
#endif
  return rc;
}


/*
 * Process SACK options in the packet and make appropriate marks in
 * transmit queue. After this function, rxp->flags have
 * CI_TCP_SACKED flag only if something is really SACKed. For DSACK
 * CI_TCP_DSACK flag is used.
 */
static void ci_tcp_rx_sack_process(ci_netif* netif, ci_tcp_state* ts,
				   ciip_tcp_rx_pkt* rxp)
{
  int i;
  unsigned start;
  unsigned end;
  int sacked = 0;

  if( !(ts->tcpflags & CI_TCPT_FLAG_SACK) ) {
    LOG_U(log(LNT_FMT "SACK received but not negotiated",
              LNT_PRI_ARGS(netif, ts)));
    return;
  }

  LOG_TO(log(LPF "%d: %d SACK blocks", S_FMT(ts), rxp->sack_blocks));

  ci_assert(ci_ip_queue_is_valid(netif, &ts->retrans));
  ci_assert(rxp->flags & CI_TCPT_FLAG_SACK);
  ci_assert(SEQ_LE(tcp_snd_una(ts), rxp->ack));

  /* The option parser (ci_tcp_parse_options()) guarantees this. */
  ci_assert(rxp->sack_blocks >= 1);

  /* Not sure whether we really care about SYN here: it'd be a pretty odd
  ** thing for the remote end to do, and I can't see that it'd cause us to
  ** do anything bad.  But just to be safe, we check.
  */
  if( ci_ip_queue_is_empty(&ts->retrans) |
      (rxp->tcp->tcp_flags & CI_TCP_FLAG_SYN) )
    return;

  /* Check for DSACK.  If it is, then skip the first block. */
  i = ci_tcp_rx_dsack_check(netif, ts, rxp);

  /* Iterate over each sack block, deciding what action to take */
  for( ; i < rxp->sack_blocks; i++ ) {
    /* sequence numbers being selectively acknowledged */
    start = rxp->sack[2 * i];
    end = rxp->sack[2 * i + 1];

    LOG_TO(log(LNT_FMT "SACK %d %08x-%08x "TCP_SND_FMT,
               LNT_PRI_ARGS(netif, ts), i, start, end, TCP_SND_PRI_ARG(ts)));

    /* First some sanity checks on the block: (1) The block must not cover
    ** acked data.  Only DSACK can do that, and we've already handled that
    ** case.  (2) It must not ack data we haven't sent.  (3) It must not be
    ** zero-length.
    **
    ** NB. Don't forget that snd_una <= ack here, so we don't need to worry
    ** about that.
    */
    if( ! (/*1*/SEQ_LE(start, rxp->ack) | /*2*/SEQ_LT(tcp_snd_nxt(ts), end) |
           /*3*/SEQ_LE(end, start)) ) {
      if( ci_tcp_rx_sack_process_block(netif, ts, start, end) )
        sacked = 1;
    }
    else {
      /* Bad SACK block: sender is not behaving.  Prev code would clear the
      ** DSACK flag in this case, but I don't think that is necessary.  If
      ** sender is messing around anything could happen.
      */
      LOG_U(if( /*1*/SEQ_LE(start, rxp->ack) ||
                /*2bis*/SEQ_LT(tcp_snd_nxt(ts) + ts->snd_delegated, end) ||
                /*3*/SEQ_LE(end, start) )
            log(LNT_FMT "SACK %d %08x-%08x invalid snd=%08x-%08x",
                LNT_PRI_ARGS(netif, ts), i, start, end,
                tcp_snd_una(ts), tcp_snd_nxt(ts)));
    }
  }

  if( sacked != 0 )
    rxp->flags |= CI_TCP_SACKED;
}


#if CI_CFG_TIMESTAMPING
static bool ci_tcp_zc_has_cookies(ci_netif* ni, ci_ip_pkt_fmt* pkt)
{
  struct ci_pkt_zc_header* zch = oo_tx_zc_header(pkt);
  struct ci_pkt_zc_payload* zcp;
  OO_TX_FOR_EACH_ZC_PAYLOAD(ni, zch, zcp)
    if( zcp->is_remote && zcp->use_remote_cookie )
      return true;
  return false;
}
#endif


static void ci_tcp_rx_free_acked_bufs(ci_netif* netif, ci_tcp_state* ts,
                                      ciip_tcp_rx_pkt* rxp)
{
  struct ci_netif_poll_state* ps = rxp->poll_state;
  ci_ip_pkt_queue* rtq = &ts->retrans;
#if CI_CFG_TIMESTAMPING
  oo_pkt_p ts_q_pending = ts->timestamp_q_pending;
  unsigned ts_q_bufs = 0;
#endif

  ci_assert(ci_ip_queue_is_valid(netif, rtq));
  ts->retransmits=0;

  if( ci_ip_queue_is_empty(rtq) ) {
    ci_assert(ts->snd_delegated);
    ci_assert(SEQ_GE(tcp_snd_nxt(ts) + ts->snd_delegated, rxp->ack));
    goto done;
  }

  while( 1 ) {
    ci_ip_pkt_fmt* p = PKT_CHK(netif, rtq->head);
#ifndef NDEBUG
    int af = ipcache_af(&ts->s.pkt);
#endif

    if( SEQ_LT(rxp->ack, p->pf.tcp_tx.end_seq) ) {
      /* New data acknowledged: restart RTO/TLP timer. */
      if( ci_tcp_taildrop_probe_enabled(netif, ts) ) {
        ts->tcpflags |= CI_TCPT_FLAG_TAIL_DROP_TIMING;
        ci_tcp_rto_clear(netif, ts);
        ci_tcp_rto_set_with_timeout(netif, ts,
                                    ci_tcp_taildrop_timeout(netif, ts));
      }
      else {
        ci_tcp_rto_restart(netif, ts);
      }
      break;
    }
    LOG_TV(log(LNT_FMT "ACKED id=%d seq=%08x-%08x ["CI_TCP_FLAGS_FMT"]"
               " (%08x) %d", LNT_PRI_ARGS(netif, ts), OO_PKT_FMT(p),
               p->pf.tcp_tx.start_seq, p->pf.tcp_tx.end_seq,
               CI_TCP_HDR_FLAGS_PRI_ARG(PKT_IPX_TCP_HDR(af, p)),
               rxp->ack, rtq->num));

    ci_ip_queue_dequeue(netif, rtq, p);

    ci_assert(p->refcount > 0);

#if CI_CFG_TIMESTAMPING
    if( (p->flags & CI_PKT_FLAG_TX_TIMESTAMPED &&
         ts->s.timestamping_flags & ONLOAD_SOF_TIMESTAMPING_STREAM) ||
        (p->flags & CI_PKT_FLAG_INDIRECT &&
         ci_tcp_zc_has_cookies(netif, p)) ) {
      ci_udp_recv_q_put_pending(netif, &ts->timestamp_q, p);
      if( p->flags & CI_PKT_FLAG_TX_PENDING)
        ts_q_pending = OO_PKT_P(p);
      else if( OO_PP_IS_NULL(ts_q_pending) )
        ts_q_bufs += p->n_buffers;
    }
    else
#endif
    {
      ci_netif_pkt_release_in_poll(netif, p, ps);
    }

    if( ci_ip_queue_is_empty(rtq) ) {
      /* We should not use ci_tcp_retransq_is_empty() instead of
       * ci_ip_queue_is_empty(rtq) above, to break out of the loop
       * when FIN_PENDING is set but rtq is empty. */
      if( CI_LIKELY(! (ts->tcpflags & CI_TCPT_FLAG_FIN_PENDING)) ) {
        /* all data acknowledged: clear RTO timer */
        ci_tcp_rto_clear(netif, ts);
        ci_tcp_kalive_restart(netif, ts, ci_tcp_kalive_idle_get(ts));
      }
      break;
    }
  }

#if CI_CFG_TIMESTAMPING
  ts->timestamp_q_pending = ts_q_pending;
  if( ts_q_bufs ) {
    ci_udp_recv_q_put_complete(&ts->timestamp_q, ts_q_bufs);

    /* Tells post-poll loop to put socket on the [reap_list]. */
    ts->s.b.sb_flags |= CI_SB_FLAG_RX_DELIVERED;
  }
#endif

  /* Make sure reap will happen in a timely manner if we've added
   * packets to the timestamp queue 
   */
  if( ts->s.b.sb_flags & CI_SB_FLAG_RX_DELIVERED ) {
    ci_netif_put_on_post_poll(netif, &ts->s.b);
    ci_tcp_wake(netif, ts, CI_SB_FLAG_WAKE_RX);
  }

 done:
  ci_assert( !ci_ip_queue_is_empty(rtq) ||
             SEQ_EQ(rxp->ack, tcp_snd_nxt(ts)) ||
             ts->snd_delegated != 0 ||
             (ts->tcpflags & CI_TCPT_FLAG_FIN_PENDING) );
  tcp_snd_una(ts) = rxp->ack;

  /* Wake up TX if necessary */
  if( NI_OPTS(netif).tcp_sndbuf_mode >= 1 &&
      ( ci_tcp_tx_advertise_space(netif, ts) || ts->s.tx_errno ) )
    ci_tcp_wake(netif, ts, CI_SB_FLAG_WAKE_TX);
}


/* Updates the send window if the advertised window in the packet is a
** larger one.  Returns the amount by which the right edge of the send
** window would move if we applied this change.
** Caller should check that rxp->ack == ts->snd_una (in most cases)
** or rxp->ack + pkt->pf.tcp_rx.window >= ts->snd_una.
*/
ci_inline int ci_tcp_rx_try_snd_wnd_inflate(ci_tcp_state *ts,
                                            ciip_tcp_rx_pkt *rxp)
{
  ci_ip_pkt_fmt *pkt = rxp->pkt;

  /* The send window should only be updated if: (see Stevens II:29.6)
   * i. The segment contains new data; or
   * ii. The segment acknowledges new data; or
   * iii. The advertised window is larger than the current send window
   * 
   * See also RFC793 Section 3.7, page 41
   *
   * See also various window update algorithms overview in
   * http://www6.ietf.org/mail-archive/web/tcpm/current/msg03667.html 
   * Here we implement the Linux one.
   */

  /* assert: snd_una <= ack <= snd_nxt */
  ci_assert(SEQ_LE(ts->snd_una, rxp->ack));
  ci_assert(SEQ_LE(rxp->ack, ts->snd_nxt + ts->snd_delegated));
  /* no such assert for seq number: we are also called for some
   * unacceptable-seq packets.  However, we silently assume that the
   * sequence number is "good" in some sense. */

  if(
#if CI_CFG_NOTICE_WINDOW_SHRINKAGE
      SEQ_LT(ts->snd_una, rxp->ack) || /* new data acked */
      SEQ_LT(ts->snd_wl1, rxp->seq) || /* new data received */
      ( SEQ_EQ(ts->snd_wl1, rxp->seq) &&  /* old segment (and old ack) */
#endif
        SEQ_LT(ts->snd_max, rxp->ack + pkt->pf.tcp_rx.window)
                                             /* window increase */
#if CI_CFG_NOTICE_WINDOW_SHRINKAGE
        )
#endif
      ) {
    ci_uint32 prev_snd_max = ts->snd_max;
    ci_tcp_set_snd_max(ts, rxp->seq, rxp->ack, pkt->pf.tcp_rx.window);
    ci_assert(SEQ_GE(ts->snd_max, ts->snd_una));
    return ts->snd_max - prev_snd_max;
  }

  return 0;
}

/*
** This function is called when an ack is received, it:
**  1. performs congestion control and rtt measurement
**  2. advances the sender's estimate of the receive window via snd_max
**  3. frees data on the TX queue and advances snd_una with RTO advance
*/
static void ci_tcp_rx_handle_ack(ci_tcp_state* ts, ci_netif* netif,
				 ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  int snd_max_different;

  /* NB. Do not assert that ACK flag is set here, because it might not be!
  ** (See below; we don't check ACK flag when connection is synchronised).
  */

  /* Must have checked that ACK is acceptable already. */
  ci_assert(SEQ_LE(rxp->ack, tcp_snd_nxt(ts) + ts->snd_delegated));
  ci_assert(SEQ_LE(tcp_snd_una(ts), rxp->ack));
  ci_assert( OO_SP_IS_NULL(ts->local_peer) );

  if (ts->snd_max == rxp->ack)
    CI_TCP_EXT_STATS_INC_TCP_FULL_UNDO( netif );

  snd_max_different = ci_tcp_rx_try_snd_wnd_inflate(ts, rxp);
  if( SEQ_LT(tcp_snd_una(ts), rxp->ack) ) {
    /* New data acknowledged: do congestion control and rtt measurement. */
    unsigned acked = SEQ_SUB(rxp->ack, tcp_snd_una(ts));

    /* If something new was acked, we should restart
     * zero window probes counter. */
    ts->zwin_probes = 0;
    ts->zwin_acks = 0;

    /* Left edge is acked: Update RTT estimation.
     * Following Linux implementation do not update RTT if segment does not
     * contain TSO. */
    if( ts->tcpflags & rxp->flags & CI_TCPT_FLAG_TSO ) {
      ci_tcp_update_rtt(netif, ts,
                        ci_tcp_time_now(netif) - rxp->timestamp_echo);
    }
    else if( SEQ_LE(tcp_snd_una(ts), ts->timed_seq) &&
             SEQ_LT(ts->timed_seq, rxp->ack) &&
             ((ts->congstate == CI_TCP_CONG_OPEN) |
              (ts->congstate == CI_TCP_CONG_NOTIFIED)) ) {
      /* need to check:
      **   (i)   not using timestamps
      **   (ii)  timed_seq valid (could be an ack for a packet in a burst)
      **   (iii) timed_seq is being acked...
      **   (iv)  not congested
      */
      ci_tcp_update_rtt(netif, ts, ci_tcp_time_now(netif) - ts->timed_ts);
    }

    /* Open the congestion window. */
    ts->bytes_acked += acked;
    ci_tcp_opencwnd(netif, ts);

    /* New acknowledgement clears any dup_acks. */
    ts->dup_acks = 0;

    /* Free TX buffers that have been acked. */
    ci_tcp_rx_free_acked_bufs(netif, ts, rxp);

    if( ts->congstate != CI_TCP_CONG_OPEN && ts->congstate != CI_TCP_CONG_NOTIFIED)
      /* Congested: try to recover. */
      ci_tcp_try_cwndrecover(ts, netif, pkt);

    if( NI_OPTS(netif).tcp_sndbuf_mode == 2 &&
	ci_tcp_should_expand_sndbuf(netif, ts) )
      ci_tcp_expand_sndbuf(netif, ts);

  }
  else{
    /* (From Stevens Vol II, p970.)
     * Its only a duplicate ack if:
     *  1) ACK is <= snd_una (i.e. it doesn't ACK new data)
     *  2) length of received packet is zero (i.e. no payload)
     *  3) the advertised window hasn't changed
     *  4) There is outstanding unacknowledged data
     *  5) The ACK is == snd_una (NB. this is an contraction of (1) as
     *      action is different depending on failure)
     *
     * snd_una <= ACK is asserted at the start of this function
     * snd_una < ACK takes other code branch
     * => snd_una == ACK (i.e. 5) if execution reaches here.
     *
     * If it passes all five, should call dupack function
     * If it only passes 1-3, should count in stats and reset dup_ack counter
     * If it only passes 1, should reset dup_ack counter
     *
     * In the modern era we note that new SACK info also indicates that a
     * packet has left the network (ie. gives the same hint as a dupack).
     */
    int is_dupack = ( SEQ_EQ(pkt->pf.tcp_rx.end_seq, rxp->seq) &&
                      ! snd_max_different                       );
    if( ci_ip_queue_is_empty(&ts->retrans) ||
        (! is_dupack && ! (rxp->flags & CI_TCP_SACKED)) )
      ts->dup_acks = 0;
    else
      ci_tcp_rx_dupack(ts, netif, rxp);
  }

  if( SEQ_SUB(ts->snd_max, rxp->ack) <= 0 &&
      ci_ip_queue_is_empty(&ts->retrans) &&
      OO_SP_IS_NULL(ts->local_peer) ) {
    /* Zero window: need to start probes.
     *
     * If retransmit queue is non-empty (i.e. if the peer shrunk window),
     * then retransmits will serve as zero window probes.
     */
    if( ci_ip_timer_pending(netif, &ts->zwin_tid) ) {
      if( ts->zwin_probes > 0 ) {
        ++ts->zwin_acks;
        ts->zwin_probes = 0;
      }
      ci_ip_timer_clear(netif, &ts->zwin_tid);
    }
    ci_tcp_zwin_set(netif, ts);
    CI_IP_SOCK_STATS_INC_ZWIN(ts);
  }

#if CI_CFG_TAIL_DROP_PROBE
  if( (ts->tcpflags & CI_TCPT_FLAG_TAIL_DROP_MARKED) &&
      SEQ_GT(rxp->ack, ts->taildrop_mark) ) {
    /* We didn't get a dupack for the probe, so therefore either the probe
     * or the original was lost.  Linux reduces cwnd and changes congestion
     * state to CWR.
     */
    CITP_STATS_NETIF(++netif->state->stats.tail_drop_probe_success);
    ts->tcpflags &=~ CI_TCPT_FLAG_TAIL_DROP_MARKED;
    if( ts->congstate == CI_TCP_CONG_OPEN ||
        ts->congstate == CI_TCP_CONG_NOTIFIED )
      /* We've detected loss, so reduce cwnd.  But the loss detected has
       * already been recovered, so don't enter recovery.
       */
      ci_tcp_reset_cwnd_on_loss(netif, ts);
  }
#endif

  /* Clear keepalive counter -- it is important to clear this counter up on
   * every ACK for our keepalive request. */
  ci_tcp_kalive_reset(netif, ts);
}


/* processes the state changes for a FIN segment,
** assumes that the rcv_wnd has already been updated
*/
static void ci_tcp_rx_process_fin(ci_netif* netif, ci_tcp_state* ts)
{
  CI_DEBUG(unsigned prev_state = ts->s.b.state);

  /* If we're pluginized then the first 'half' of the ROB may still need to be
   * recycled, so we leave the entire ROB in place. It's only consuming a few
   * packets for a bit longer. */
  if( ! ci_ip_queue_is_empty(&ts->rob) && ! ci_tcp_is_pluginized(ts) ) {
    LOG_U(log(LNTS_FMT "non-empty ROB after FIN", LNTS_PRI_ARGS(netif, ts)));
    ci_tcp_rx_queue_drop(netif, ts, &ts->rob);
  }

  /* TODO does the dropping of packets from the ROB above require us
     to update SACK state? */

  ts->tcpflags |= CI_TCPT_FLAG_FIN_RECEIVED;
  ts->s.rx_errno = CI_SHUT_RD;
  if( ts->s.b.state == CI_TCP_ESTABLISHED ) {
    ci_tcp_set_slow_state(netif, ts, CI_TCP_CLOSE_WAIT);
  } else if( ts->s.b.state == CI_TCP_FIN_WAIT1 ) {
    if( SEQ_EQ(tcp_snd_una(ts), tcp_enq_nxt(ts)) ) {
      ci_assert(ci_tcp_sendq_is_empty(ts));
      ci_assert(ci_tcp_retransq_is_empty(ts));
      ci_netif_timewait_enter(netif, ts);
      ci_tcp_set_slow_state(netif, ts, CI_TCP_TIME_WAIT);
    }
    else {
      ci_tcp_set_slow_state(netif, ts, CI_TCP_CLOSING);
      /* peer is going to TIME_WAIT state despite us doing the same,
       * ISN for next connection need to be recorded */
      ci_tcp_prev_seq_remember(netif, ts);
    }
  }
  else {
    ci_assert(ts->s.b.state == CI_TCP_FIN_WAIT2);
    ci_assert(ci_tcp_sendq_is_empty(ts));
    ci_assert(ci_tcp_retransq_is_empty(ts));
    ci_assert_equal(ts->send_prequeue, -2);

    ci_netif_timewait_enter(netif, ts);
    ci_tcp_set_slow_state(netif, ts, CI_TCP_TIME_WAIT);
  }
  LOG_TC(log(LPF "%d FIN %s->%s", S_FMT(ts),
            ci_tcp_state_str(prev_state), state_str(ts)));

  /* Cleanup the receive queue to avoid leaving lots of junk there for
  ** (potentially) ages. */
  if( ci_tcp_is_pluginized(ts) )
    ci_tcp_rx_clean_plugin_rob(netif, ts, tcp_rcv_nxt(ts));
  ci_tcp_rx_reap_rxq_bufs(netif, ts);
  if( tcp_rcv_usr(ts) == 0 && ci_sock_trylock(netif, &ts->s.b) ) {
    ci_assert_equal(tcp_rcv_usr(ts), 0);
    if( OO_PP_NOT_NULL(ts->recv1_extract) )
      ci_tcp_rx_reap_rxq_last_buf(netif, ts);
    else
      ci_assert_equal(ts->recv1.num, 0);
    ci_sock_unlock(netif, &ts->s.b);
  }

  ci_tcp_wake(netif, ts, CI_SB_FLAG_WAKE_RX);

  if( OO_SP_NOT_NULL(ts->local_peer) ) {
    /* "Send ACK" to peer */
    ci_tcp_state* peer = ID_TO_TCP(netif, ts->local_peer);
    if( peer->s.b.state == CI_TCP_LAST_ACK )
      ci_tcp_drop(netif, peer, 0);
    else
      ci_tcp_set_slow_state(netif, peer, CI_TCP_FIN_WAIT2);
  }

}

#if CI_CFG_PORT_STRIPING
static int ci_tcp_check_ooo_stripe(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_pkt_fmt* block_pkt = PKT_CHK(netif, ts->rob.head);
  unsigned gap_start_seqno = tcp_rcv_nxt(ts);
  int gap_port_swap;
  /* Records if we've found a gap on each port, indexed by gap_port_swap */
  int gap_found[2] = {0, 0};

  while( 1 ) {
    gap_port_swap = ci_ts_port_swap(gap_start_seqno, ts);
    gap_found[gap_port_swap] = 1;
    if( gap_found[0] && gap_found[1] )
      return 1;
    if( PKT_TCP_RX_ROB(block_pkt)->next_block < 0 )  break;
    gap_start_seqno = PKT_TCP_RX_ROB(block_pkt)->end_block_seq;
    block_pkt = PKT_CHK(netif, PKT_TCP_RX_ROB(block_pkt)->next_block);
  }
  return 0;
}
#endif


static bool ci_tcp_rx_plugin_recycle(ci_netif* netif, ci_tcp_state* ts,
                                     ci_ip_pkt_fmt* pkt)
{
  bool rc;
  struct ef_vi_tx_extra extra = {
    .flags = EF_VI_TX_EXTRA_MARK,
    .mark = ts->plugin_stream_id,
  };
  /* Smarter retry logic would be better here, in particular we shouldn't
   * keep trying if we reckon the plugin's blocked because of insufficient
   * FPGA DDR. This smarter logic probably belongs near the top of
   * ci_tcp_rx_deliver_rob(), not here */

  ci_tcp_recycle_reset(netif, ts);

  /* We're quite aggressive about recycling, so a double attempt is totally
   * possible */
  if( pkt->flags & CI_PKT_FLAG_TX_PENDING )
    return true;
  ci_assert_equal(pkt->frag_next, OO_PP_NULL);
  pkt->q_id = CI_Q_ID_TCP_RECYCLER;
  pkt->buf_len = pkt->pay_len;
  ci_netif_pkt_hold(netif, pkt);  /* It stays on the recycle queue until we
                                   * know that the plugin processed it in
                                   * order */
  pkt->flags |= CI_PKT_FLAG_TX_PENDING;
  /* Need to use the immediate version to avoid the possibility of putting the
   * packet on the dmaq - we can't do that because we're already using
   * pkt::next for the rob. */
  rc = ci_netif_send_immediate(netif, pkt, &extra);
  if( ! rc ) {
    pkt->flags &=~ CI_PKT_FLAG_TX_PENDING;
    ci_netif_pkt_release(netif, pkt);
  }
  return rc;
}


static int ci_tcp_rx_deliver_rob(ci_netif* netif, ci_tcp_state* ts)
{
  ci_ip_pkt_fmt* pkt;
  ci_ip_pkt_fmt* end_pkt = NULL;
  oo_pkt_p end_block_id, id;
  ci_tcp_hdr* tcp;
  ci_ip_pkt_queue* rob;
  ci_uint32 last_seq;
  int num;
  ci_uint32 seq;
  int af = ipcache_af(&ts->s.pkt);

  ++ts->stats.rx_ooo_fill;
  rob = &ts->rob;
  ci_assert(ci_ip_queue_is_valid(netif, rob));
  id = rob->head;
  pkt = PKT_CHK(netif, id);
  seq = CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, pkt)->tcp_seq_be32);

  end_block_id = PKT_TCP_RX_ROB(pkt)->end_block;
  ASSERT_VALID_PKT_ID(netif, end_block_id);
  /* In pluginized mode this cleanup is done in ci_tcp_rx_enqueue_packet() */
  if( ! ci_tcp_is_pluginized(ts) ) {
    /* Remove all packets covered by already delivered packets. */
    while( SEQ_LE(pkt->pf.tcp_rx.end_seq, tcp_rcv_nxt(ts)) ) {
      /* This should only happen if there was a retransmission after
         coalescing, so the retransmitted packet covers a "hole" and a
         pile of things that were received out of order */
      LOG_TR(log(LPF "%d drop packet from ROB %d: %x-%x",
                S_FMT(ts), OO_PP_FMT(id), seq,
                pkt->pf.tcp_rx.end_seq));
      remove_from_last_sack(ts, id);
      ci_tcp_rx_queue_dequeue(netif, ts, rob, pkt);
      if( OO_PP_EQ(id, end_block_id) )
        end_block_id = OO_PP_NULL;
      ci_netif_pkt_release_rx(netif, pkt);
      if( ci_ip_queue_is_empty(rob) )
        return 0;
      id = rob->head;
      pkt = PKT_CHK(netif, id);
      seq = CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, pkt)->tcp_seq_be32);
      if( OO_PP_IS_NULL(end_block_id) ) {
        end_block_id = PKT_TCP_RX_ROB(pkt)->end_block;
        ASSERT_VALID_PKT_ID(netif, end_block_id);
      }
    }
  }
  tcp = PKT_IPX_TCP_HDR(af, pkt);

  /* Check that first packet could be delivered. */
  if( SEQ_LT(tcp_rcv_nxt(ts), seq) ) {
    LOG_TV(log("%d %s ROB can't deliver rcv_nxt=%08x rob_nxt=%08x",
               S_FMT(ts), state_str(ts), tcp_rcv_nxt(ts), seq));
#if CI_CFG_PORT_STRIPING
    if( ts->tcpflags & CI_TCPT_FLAG_STRIPE )
      return ci_tcp_check_ooo_stripe(netif, ts);
    else
#endif
      return 1;
  }

  LOG_TO(log(LPF "%d ROB deliver rcv=%08x-%08x cur %08x rob_seq=%08x-%08x",
             S_FMT(ts), tcp_rcv_nxt(ts), tcp_rcv_wnd_right_edge_sent(ts),
             tcp_rcv_wnd_current(ts), seq,
             PKT(netif, end_block_id)->pf.tcp_rx.end_seq));
  if( ! ci_tcp_is_pluginized(ts) )
    ci_assert(SEQ_LE(tcp_rcv_nxt(ts),
                   PKT(netif, end_block_id)->pf.tcp_rx.end_seq));

  if( ts->tcpflags & CI_TCPT_FLAG_SACK ) {
    int i;
    for( i = 0; i <= CI_TCP_SACK_MAX_BLOCKS; i++ )
      if( OO_PP_EQ(ts->last_sack[i], id) )
        ts->last_sack[i] = OO_PP_NULL;
        /* We should not break from for(), because duplicates are possible
         * after arriving new segment which glued two blocks. */
  }

  /* Deliver all the block (whilst looking out for FINs). */
  last_seq = tcp_rcv_nxt(ts);
  num = 0;
  while( 1 ) {
    LOG_TV(log(LPF "%d ROB deliver packet %d: %x-%x, last_seq = %x, "
               "pay_len = %d", S_FMT(ts), OO_PP_FMT(id), seq,
               pkt->pf.tcp_rx.end_seq, last_seq, pkt->pf.tcp_rx.pay_len));
    if( ! ci_tcp_is_pluginized(ts) ) {
      ci_assert(SEQ_LE(seq, last_seq));
      ci_assert(SEQ_LT(last_seq, pkt->pf.tcp_rx.end_seq));
      oo_offbuf_init(&pkt->buf,
                     CI_TCP_PAYLOAD(tcp) + (last_seq - seq),
                     pkt->pf.tcp_rx.pay_len - (last_seq - seq));
    }

    if( CI_UNLIKELY(tcp->tcp_flags & CI_TCP_FLAG_FIN) ) {
      LOG_TC(log(LPF "%d out-of-order FIN", S_FMT(ts)));
      break;
    }
    ci_assert(oo_offbuf_not_empty(&pkt->buf));

    num++;
    end_pkt = pkt;
    last_seq = pkt->pf.tcp_rx.end_seq;
    if( OO_PP_EQ(OO_PKT_P(pkt), end_block_id) )
      break;
    id = pkt->next;
    pkt = PKT_CHK(netif, id);
    tcp = PKT_IPX_TCP_HDR(af, pkt);
    seq = CI_BSWAP_BE32(tcp->tcp_seq_be32);
  }

  /* 3 cases - a) only FIN, num=0
   *           b) FIN and data as the only packet, num=0
   *           c) FIN and data as the last past, num=packets-1
   */
  ci_assert(num > 0 || (tcp->tcp_flags & CI_TCP_FLAG_FIN));

  /* Attach list of packets in the block to receive queue. */
  if( num != 0 ) {
    if( ci_tcp_is_pluginized(ts) ) {
      /* ...unless we're using the TCP plugin, in which case the rob works as
       * the to-recycle queue. These packets are now known to be in-order so
       * we feed them back in to the hardware so that it sees everything
       * in-order too and can do simple processing. The payload of these
       * packets is irrelevant to us (i.e. we don't enqueue it to the recvq)
       * because it's the plugin which wants it, not us (although the plugin
       * can choose to give subsets of it back to us, it does that through
       * completely different means). */
      int i;
      ci_ip_pkt_fmt* p = PKT_CHK(netif, rob->head);
      for( i = 0; ; ) {
        ci_tcp_rx_plugin_recycle(netif, ts, p);
        if( ++i >= num )
          break;
        p = PKT_CHK(netif, p->next);
      }
      /* The rob is effectively two back-to-back queues, where the join is
       * rcv_nxt. head..rcv_nxt are in-order/contiguous and are being sent to
       * the plugin ("recycled"). rcv_nxt..tail are discontiguous and are
       * still being buffered in Onload (the same as the traditional rob). The
       * first half remain on the rob until the plugin ACKs them (by sending
       * us the equivalent elided-payload packet back, handled in
       * ci_tcp_rx_enqueue_packet()), since the plugin may have to drop
       * anything at any time due to lack of buffering. */
      if( SEQ_LT(tcp_rcv_nxt(ts), p->pf.tcp_rx.end_seq) )
        tcp_rcv_nxt(ts) = p->pf.tcp_rx.end_seq;
    }
    else {
      ci_tcp_rx_enqueue_chain(netif, ts, rob, end_pkt, num);
    }
  }

  if(CI_UNLIKELY( tcp->tcp_flags & CI_TCP_FLAG_FIN )) {
    bool has_data = pkt->pf.tcp_rx.end_seq - seq != 1;
    if( ts->tcpflags & CI_TCPT_FLAG_SACK ) {
      int i;
      for( i = 0; i <= CI_TCP_SACK_MAX_BLOCKS; i++ ) {
        if( OO_PP_EQ(ts->last_sack[i], OO_PKT_P(pkt)) ) {
          ts->last_sack[i] = OO_PP_NULL;
          /* We should not break from for(), because duplicates are possible
           * after arriving new segment which glued two blocks. */
        }
      }
    }
    if( ci_tcp_is_pluginized(ts) ) {
      ci_tcp_rx_plugin_recycle(netif, ts, pkt);
      /* Leave the FIN itself unprocessed, so that the normal recv logic can
       * handle all the special cases with regard to the data not having
       * all arrived on the meta VI yet: */
      tcp_rcv_nxt(ts) = pkt->pf.tcp_rx.end_seq - 1;
    }
    else {
      ci_tcp_rx_queue_dequeue(netif, ts, rob, pkt);
      /* Deal with any data that was also in the pkt with a FIN */
      if( has_data ) {
        ci_tcp_rx_enqueue_packet(netif, ts, pkt);
      } else {
        tcp_rcv_nxt(ts) = pkt->pf.tcp_rx.end_seq;
        ci_netif_pkt_release_rx(netif, pkt);
      }
      ci_tcp_rx_process_fin(netif, ts);
    }
  }

  ci_assert(ci_ip_queue_is_valid(netif, rob));

  if( ci_tcp_can_use_fast_path(ts) )
    ci_tcp_fast_path_enable(ts);

  /* Following code attempts to determine if there is residual
   * out-of-orderness (not explained by striping) and send an ACK if
   * so as sending an ACK when we have received a packet and there is
   * loss is important.
   */
#if CI_CFG_PORT_STRIPING
  if( ts->tcpflags & CI_TCPT_FLAG_STRIPE ) {
    if( ci_ip_queue_not_empty(&ts->rob) ) {
      if( ci_tcp_check_ooo_stripe(netif, ts) ) {
        TCP_FORCE_ACK(ts);
        return 1;
      }
    }
    /* There is a case here (just-received packet filled gap that was
     * due to loss rather than striping) where we should force an ACK,
     * but we can't distinguish that from the cases that are explained
     * by striping, so don't bother with the ACK; caller will likely
     * send one anyway.
     */
    return 0;
  }
  else
#endif
    {
      TCP_FORCE_ACK(ts);
      return ci_ip_queue_not_empty(&ts->rob);
    }
}


void ci_tcp_timeout_recycle(ci_netif* netif, ci_tcp_state* ts)
{
  if( ! ci_ip_queue_is_empty(&ts->rob) )
    ci_tcp_rx_deliver_rob(netif, ts);
}


ci_inline int ci_tcp_rx_deliver_to_recvq(ci_tcp_state* ts, ci_netif* netif,
                                         ciip_tcp_rx_pkt *rxp)
{
  ci_ip_pkt_fmt *pkt = rxp->pkt;
  ci_tcp_hdr *tcp = rxp->tcp;
  int rc = 0;

  /* We now have at least one in-order packet!  Deliver it, and any
  ** out-of-order packets that are now in-order.
  */
  /* NB SEQ_LE rather than SEQ_EQ as may have partial duplicate */
  ci_assert(SEQ_LE(rxp->seq, tcp_rcv_nxt(ts)));
  ci_assert(pkt->pf.tcp_rx.pay_len);
  if( ci_tcp_is_pluginized(ts) && pkt->pf.tcp_rx.pay_len != 0 &&
      ! ci_tcp_plugin_elided_payload(pkt) ) {
    /* This packet was in-order but the plugin didn't process it for some
     * reason (backpressure, not yet initialised, etc.). We need to treat it
     * as out of order and recycle it */
    ci_tcp_rx_enqueue_ooo(netif, ts, rxp);
    if( ! ci_ip_queue_is_empty(&ts->rob) )
      rc = ci_tcp_rx_deliver_rob(netif, ts);
    return rc;
  }

  oo_offbuf_init(&pkt->buf, CI_TCP_PAYLOAD(tcp), pkt->pf.tcp_rx.pay_len);

  /* Handle the case that this packet is a partial duplicate. */
  oo_offbuf_advance(&pkt->buf, SEQ_SUB(tcp_rcv_nxt(ts), rxp->seq));
  ci_assert(oo_offbuf_not_empty(&pkt->buf));

  ci_tcp_rx_enqueue_packet(netif, ts, pkt);

  if( !ci_ip_queue_is_empty(&ts->rob) )
    rc = ci_tcp_rx_deliver_rob(netif, ts);

  ci_tcp_wake(netif, ts, CI_SB_FLAG_WAKE_RX);
  return rc;
}


void ci_tcp_rx_deliver2(ci_tcp_state* ts, ci_netif* netif,
			ciip_tcp_rx_pkt* rxp)
{
  /* This is just an out-of-line version of ci_tcp_rx_deliver(). */
  ci_tcp_rx_deliver_to_recvq(ts, netif, rxp);
}


/*
 * Clean up re-order buffer starting from the packet pkt. This packet
 * should be the first packet of some block. If the first block can be
 * glued with next block(s), it will be done.  It is supposed that all next
 * blocks can't be glued with each other. It is supposed that 'pkt' block
 * is not covered by other blocks.
 */
static void ci_tcp_rx_glue_rob(ci_netif* netif, ci_tcp_state* ts,
                               ci_ip_pkt_fmt* pkt)
{
  oo_pkt_p last_id;         /* Id of the last packet in current block */
  unsigned last_seq;        /* End sequence number of current block */
  ci_ip_pkt_fmt* next_pkt;  /* First packet of the next block */
  oo_pkt_p next_id;         /* Id of next_pkt */
  ci_ip_pkt_fmt* tmp;
  oo_pkt_p tmp_id;

  for( next_id = PKT_TCP_RX_ROB(pkt)->next_block;
       OO_PP_NOT_NULL(next_id);
       next_id = PKT_TCP_RX_ROB(pkt)->next_block) {
    int af = ipcache_af(&ts->s.pkt);
    next_pkt = PKT_CHK(netif, next_id);
    last_seq = PKT_TCP_RX_ROB(pkt)->end_block_seq;
    if( SEQ_LT(last_seq, CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, next_pkt)->tcp_seq_be32)) )
        return;
    LOG_TV(log(LPF "ROB glue %d and %d blocks",
               OO_PKT_FMT(pkt), OO_PP_FMT(next_id)));

    /* next_id block will desappear, clear it from SACK structures. */
    if( ts->tcpflags & CI_TCPT_FLAG_SACK) {
      int i;
      for( i = 0; i <= CI_TCP_SACK_MAX_BLOCKS; i++ )
        if( OO_PP_EQ(next_id, ts->last_sack[i]) )
          ts->last_sack[i] = OO_PKT_P(pkt);
          /* We should not break from for(), because duplicates are possible
           * after arriving new segment which glued two blocks. */
    }

    /* Now we should glue two blocks. */
    last_id = PKT_TCP_RX_ROB(pkt)->end_block;
    ASSERT_VALID_PKT_ID(netif, last_id);
    PKT_TCP_RX_ROB(pkt)->next_block = PKT_TCP_RX_ROB(next_pkt)->next_block;
    /* Check if the next block contains any new data. */
    if( SEQ_LT(last_seq, PKT_TCP_RX_ROB(next_pkt)->end_block_seq) ) {
      /* Really glue two blocks */
      PKT_TCP_RX_ROB(pkt)->end_block = PKT_TCP_RX_ROB(next_pkt)->end_block;
      PKT_TCP_RX_ROB(pkt)->end_block_seq = PKT_TCP_RX_ROB(next_pkt)->end_block_seq;
      PKT_TCP_RX_ROB(pkt)->num += PKT_TCP_RX_ROB(next_pkt)->num;

      /* Remove all packets which are covered by preceeding packets. */
      for( tmp_id = next_id, tmp = next_pkt;
           OO_PP_NOT_NULL(tmp_id) && SEQ_LE(tmp->pf.tcp_rx.end_seq, last_seq);
           tmp_id = next_id, tmp = PKT_CHK(netif, tmp_id)) {
        ci_assert( ! OO_PP_EQ(tmp_id, PKT_TCP_RX_ROB(pkt)->end_block) );
        next_id = tmp->next;
        ci_netif_pkt_release_rx(netif, tmp);
        PKT_TCP_RX_ROB(pkt)->num--;
        ci_tcp_rx_buf_adjust(netif, ts, &ts->rob, -1);
        ts->rob.num--;
      }
      PKT_CHK(netif, last_id)->next = next_id;
      if( OO_PP_IS_NULL(next_id) )
	ts->rob.tail = OO_PKT_P(pkt);
    } else {
      /* Drop all the next block -- it is covered by the first block. */
      PKT(netif, last_id)->next = PKT_TCP_RX_ROB(next_pkt)->next_block;
      if( OO_PP_IS_NULL(PKT(netif, last_id)->next) ) 
	ts->rob.tail = last_id;

      last_id = PKT_TCP_RX_ROB(next_pkt)->next_block;
      for( tmp_id = next_id;
           OO_PP_NOT_NULL(tmp_id) && ! OO_PP_EQ(tmp_id, last_id);
           tmp_id = next_id ) {
        ci_assert( ! OO_PP_EQ(tmp_id, PKT_TCP_RX_ROB(pkt)->end_block) );
        tmp = PKT_CHK(netif, tmp_id);
        next_id = tmp->next;
        ci_netif_pkt_release_rx(netif, tmp);
        PKT_TCP_RX_ROB(pkt)->num--;
        ci_tcp_rx_buf_adjust(netif, ts, &ts->rob, -1);
        ts->rob.num--;
      }
    }
  }
  return;
}


#if CI_CFG_PORT_STRIPING
/* This function attempts to distinguish between out-or-orderness caused by
** striping, and that caused by loss.  Returns 1 if loss is detected and a
** dup-ack should be generated.  Otherwise 0 is returned, and we don't send
** an ack.
*/
static int ci_tcp_rx_ooo_stripe(ci_netif* netif, ci_tcp_state* ts,
                                ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_queue* rob = &ts->rob;
  ci_ip_pkt_fmt* block_pkt = PKT_CHK(netif, rob->head);

  /* The port the receiver expects the missing packet to have used
  ** (indicates default or swapped).
  */
  int gap_port_swap;

  /* The port the receiver expects the transmitter to have used for this
  ** packet (indicates default or swapped).
  */
  int tx_port_swap = ci_ts_port_swap(rxp->seq, ts);

  /* The sequence number of the first gap in received data.  The following
  ** assumes that a gap is made of a single missing packet.  If there were
  ** in fact >1 missing packets, only the first in the gap is checked.
  */
  unsigned gap_start_seqno = tcp_rcv_nxt(ts);
  int af = ipcache_af(&ts->s.pkt);

  LOG_TV(log(LNT_FMT "OOO port_swap=%d s=%08x-%08x", LNT_PRI_ARGS(netif, ts),
             tx_port_swap, rxp->seq, rxp->pkt->pf.tcp_rx.end_seq));

  /* Check each gap to see if the missing packet was on the same port as
  ** this packet.
  */
  while( 1 ) {
    if( SEQ_LE(rxp->seq, gap_start_seqno) ) {
      /* There are no gaps in the sequence space before this packet on the
      ** same port.  So probably no loss.
      */
      LOG_TV(log(LNT_FMT "OOO terminated at gap %08x-%08x",
                 LNT_PRI_ARGS(netif, ts), gap_start_seqno,
                 CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, block_pkt)->tcp_seq_be32)));
      return 0;
    }

    gap_port_swap = ci_ts_port_swap(gap_start_seqno, ts);
    LOG_TV(log(LNT_FMT "OOO comparing port %d gap %08x-%08x",
               LNT_PRI_ARGS(netif, ts), gap_port_swap, gap_start_seqno,
               CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, block_pkt)->tcp_seq_be32)));

    if( gap_port_swap == tx_port_swap ) {
      /* Gap on same port => loss. */
      LOG_TV(log(LNT_FMT "OOO requesting dupack for %08x",
                 LNT_PRI_ARGS(netif, ts), tcp_rcv_nxt(ts)));
      return 1;
    }

    /* look for another gap */
    if( PKT_TCP_RX_ROB(block_pkt)->next_block < 0 )  break;

    gap_start_seqno = PKT_TCP_RX_ROB(block_pkt)->end_block_seq;
    block_pkt = PKT_CHK(netif, PKT_TCP_RX_ROB(block_pkt)->next_block);
  }

  /* only gets here if all attributable to port striping */
  return 0;
}
#endif


/*! Enqueue an out-of-order segment. Returns a hint about whether or
  not to ACK this packet.  This will be 0 if an ACK should be avoided,
  as it has detected that the out-or-order situation is probably due
  to striping over different ports rather than loss*/
static int ci_tcp_rx_enqueue_ooo(ci_netif* netif, ci_tcp_state* ts,
                                  ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_ip_pkt_queue* rob = &ts->rob;

  oo_pkt_p       prev_id;
  ci_ip_pkt_fmt* prev_pkt = NULL;  /* \todo Initialize in debug build only */
  oo_pkt_p       block_id;
  ci_ip_pkt_fmt* block_pkt = NULL;  /* \todo Initialize in debug build only */
  int af = ipcache_af(&ts->s.pkt);

  if( ci_tcp_is_pluginized(ts) && tcp_plugin_pkt_was_recycled(ts, pkt) )
    return 0;

  CITP_STATS_NETIF_INC(netif, rx_out_of_order);
  CI_IP_SOCK_STATS_INC_OOO( ts );
  ++ts->stats.rx_ooo_pkts;
  LOG_TO(log(LNT_FMT "ENQ-OOO "TCP_RCV_FMT" s=%08x",
             LNT_PRI_ARGS(netif, ts), TCP_RCV_PRI_ARG(ts), rxp->seq));

  /* Races between recycling and retransmits from the peer can cause duplicate
   * elided-payload packets to be received, but they'll always be of
   * present-or-past packets, never future */
  ci_assert(! ci_tcp_plugin_elided_payload(pkt));

  ci_assert(OO_SP_IS_NULL(ts->local_peer));
  ci_assert(ci_ip_queue_is_valid(netif, rob));
  for( prev_id = OO_PP_NULL, block_id = rob->head;
       OO_PP_NOT_NULL(block_id) &&
       (block_pkt = PKT_CHK(netif, block_id),
        SEQ_LT(CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, block_pkt)->tcp_seq_be32),
               rxp->seq));
       prev_id = block_id, prev_pkt = block_pkt,
       block_id = PKT_TCP_RX_ROB(block_pkt)->next_block ) {

    LOG_TV(log(LNT_FMT "OOO check: from %08x-%08x to %08x-%08x",
               LNT_PRI_ARGS(netif, ts),
               OO_PP_NOT_NULL(prev_id) ?
                 CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, prev_pkt)->tcp_seq_be32) : 0,
               OO_PP_NOT_NULL(prev_id) ?
                 PKT_TCP_RX_ROB(prev_pkt)->end_block_seq : 0,
               OO_PP_NOT_NULL(block_id) ?
                 CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, block_pkt)->tcp_seq_be32) : 0,
               OO_PP_NOT_NULL(block_id) ?
                 PKT_TCP_RX_ROB(block_pkt)->end_block_seq : 0));
  }

  /* Check if the packet is subset of existing blocks */
  if( (OO_PP_NOT_NULL(prev_id) &&
       SEQ_LE(pkt->pf.tcp_rx.end_seq,
              PKT_TCP_RX_ROB(prev_pkt)->end_block_seq)) ||
      (OO_PP_NOT_NULL(block_id) &&
       SEQ_EQ(rxp->seq,
              CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, block_pkt)->tcp_seq_be32)) &&
       SEQ_LE(pkt->pf.tcp_rx.end_seq,
              PKT_TCP_RX_ROB(block_pkt)->end_block_seq)) ) {
    LOG_TL(log(LNT_FMT "OOO DROP duplicate %08x-%08x",
               LNT_PRI_ARGS(netif, ts), rxp->seq,
               PKT_TCP_RX_ROB(pkt)->end_block_seq));
    if( NI_OPTS(netif).use_dsack && (ts->tcpflags & CI_TCPT_FLAG_SACK) ) {
      ts->dsack_start = rxp->seq;
      ts->dsack_end = pkt->pf.tcp_rx.end_seq;
      ts->dsack_block = prev_id;
    }
    ci_netif_pkt_release_rx(netif, pkt);
    ci_assert(ci_ip_queue_is_valid(netif, rob));
    return 1;
  }

  /* Place the new packet here. */
  LOG_TV(log(LNT_FMT "OOO %d between %d and %d", LNT_PRI_ARGS(netif, ts),
             OO_PKT_FMT(pkt), OO_PP_FMT(prev_id), OO_PP_FMT(block_id)));

  if( ts->tcpflags & CI_TCPT_FLAG_SACK ) {
    ts->last_sack[0] = OO_PKT_P(pkt);
  }
  pkt->next = block_id;

  PKT_TCP_RX_ROB(pkt)->next_block = block_id;
  PKT_TCP_RX_ROB(pkt)->end_block = OO_PKT_P(pkt);
  PKT_TCP_RX_ROB(pkt)->end_block_seq = pkt->pf.tcp_rx.end_seq;
  PKT_TCP_RX_ROB(pkt)->num = 1;
  ci_tcp_rx_buf_adjust(netif, ts, rob, 1);
  rob->num++;

  if( OO_PP_IS_NULL(block_id) )
    rob->tail = OO_PKT_P(pkt);

  /* NB. CHECK_TS(netif, ts) reports that ROB and sack state are
     inconsistent at this point because blocks have not yet been glued
     together.  */

  if( OO_PP_IS_NULL(prev_id) ) {
    rob->head = OO_PKT_P(pkt);
    ci_tcp_rx_glue_rob(netif, ts, pkt);
  } else {
    ci_tcp_rx_glue_rob(netif, ts, pkt);
    PKT_CHK(netif, PKT_TCP_RX_ROB(prev_pkt)->end_block)->next = OO_PKT_P(pkt);
    PKT_TCP_RX_ROB(prev_pkt)->next_block = OO_PKT_P(pkt);
    ci_tcp_rx_glue_rob(netif, ts, prev_pkt);
  }

  CHECK_TS(netif, ts);

  ci_tcp_fast_path_disable(ts);

#if CI_CFG_PORT_STRIPING
  if( ts->tcpflags & CI_TCPT_FLAG_STRIPE )
    return ci_tcp_rx_ooo_stripe(netif, ts, rxp);
#endif

  return 1;
}


static void handle_rx_listen_rst(ci_netif* ni, ci_tcp_socket_listen* tls,
                                 ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
#ifndef NDEBUG
  ci_ip4_hdr* ip = oo_ip_hdr(pkt);
#endif
  ci_tcp_hdr* tcp = rxp->tcp;
  ci_tcp_state_synrecv* tsr;

  /* rfc793 p37.  An RST is acceptable if its seq no is in the receive
  ** window.  Except: if you are in SYN-SENT, then its acceptable if the
  ** ACK acknowledges the SYN we sent.
  **
  ** If valid, go to CLOSED state and tell the user.
  */

  /* RST segments can contain data.  See rfc1122 4.2.2.12.  It is suggested
  ** that this might be used to give reason for RST (but I don't think this
  ** is widely [or at all] implemented).
  */
  if( pkt->pf.tcp_rx.pay_len ) {
    LOG_U(log(LPF "%d RST with data (%d bytes)",
              S_FMT(tls), pkt->pf.tcp_rx.pay_len));
    LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt),
                       oo_pre_l3_len(pkt) + CI_BSWAP_BE16(ip->ip_tot_len_be16),
                       0));
  }

  if( (tcp->tcp_flags & ~(CI_TCP_FLAG_RST|CI_TCP_FLAG_ACK)
       & CI_TCP_FLAG_MASK) )
    LOG_U(log(LPF "%d RST with unexpected flags (%x)", S_FMT(tls),
              (unsigned) tcp->tcp_flags));

  /* Reset on a synrecv structure with reset seq number equal to the
  ** next expected byte of the SYNACK returns the connection to listen
  ** (RFC793 pg33, pg35).
  */
  tsr = ci_tcp_listenq_lookup(ni, tls, rxp);

  if( tsr ) {
    ci_uint32 tsr_rcv_wnd = ci_tcp_rcvbuf2window(tls->s.so.rcvbuf,
                                                 tsr->amss, tsr->rcv_wscl);
    if( SEQ_LE(tsr->rcv_nxt, rxp->seq) &&
        SEQ_LT(rxp->seq, tsr->rcv_nxt + tsr_rcv_wnd) ) {
      if( (tsr->tcpopts.flags & CI_TCPT_FLAG_TSO) &&
          (rxp->flags & CI_TCPT_FLAG_TSO) &&
          ci_tcp_paws_check(ni, rxp->timestamp,
                            tsr->timest, tsr->tspeer) ) {
        LOG_U(log(LPF "%d SYNRECV %s:%d->%s:%d RST PAWS failed", S_FMT(tls),
                  ip_addr_str(ip->ip_saddr_be32),
                  (int) CI_BSWAP_BE16(tcp->tcp_source_be16),
                  ip_addr_str(ip->ip_daddr_be32),
                  (int) CI_BSWAP_BE16(tcp->tcp_dest_be16)));
        CITP_STATS_NETIF_INC(ni, rst_recv_synrecv_paws_rejected);
      }
      else {
        ci_tcp_listenq_remove(ni, tls, tsr);
        ci_tcp_synrecv_free(ni, tsr);
        CITP_STATS_NETIF_INC(ni, rst_recv_synrecv);
        LOG_TC(log(LPF "%d SYNRECV %s:%d->%s:%d RST",
                  S_FMT(tls),
                  ip_addr_str(ip->ip_saddr_be32),
                  (int) CI_BSWAP_BE16(tcp->tcp_source_be16),
                  ip_addr_str(ip->ip_daddr_be32),
                  (int) CI_BSWAP_BE16(tcp->tcp_dest_be16)));
      }
    }
    else {
      LOG_U(log(LPF "%d SYNRECV %s:%d->%s:%d RST unacceptable", S_FMT(tls),
                ip_addr_str(ip->ip_saddr_be32),
                (int) CI_BSWAP_BE16(tcp->tcp_source_be16),
                ip_addr_str(ip->ip_daddr_be32),
                (int) CI_BSWAP_BE16(tcp->tcp_dest_be16)));
      CITP_STATS_NETIF_INC(ni, rst_recv_unacceptable);
    }
  }
  else {
    /* This happens when a passively opened connection is closed or
    ** dropped, and an RST segment subsequently arrives for it.  So it
    ** is expected.
    */
    LOG_TR(log(LPF "%d LISTEN %s:%d->%s:%d RST ignored (no SYNRECV)",
               S_FMT(tls), ip_addr_str(ip->ip_saddr_be32),
               (int) CI_BSWAP_BE16(tcp->tcp_source_be16),
               ip_addr_str(ip->ip_daddr_be32),
               (int) CI_BSWAP_BE16(tcp->tcp_dest_be16)));
  }

  ci_netif_pkt_release_rx(ni, pkt);
}

static void handle_rx_rst(ci_tcp_state* ts, ci_netif* netif,
                          ciip_tcp_rx_pkt* rxp)
{
  /* rfc793 p37.  An RST is acceptable if its seq no is in the receive
  ** window.  Except: if you are in SYN-SENT, then its acceptable if the
  ** ACK acknowledges the SYN we sent.
  **
  ** If valid, go to CLOSED state and tell the user.
  */
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_tcp_hdr* tcp = rxp->tcp;

  LOG_TC(log(FNTS_FMT "RST "TCP_RCV_FMT" PKT seq=%08x ack=%08x",
             FNTS_PRI_ARGS(netif, ts), TCP_RCV_PRI_ARG(ts),
             rxp->seq, rxp->ack));

  /* RST segments can contain data.  See rfc1122 4.2.2.12.  It is suggested
  ** that this might be used to give reason for RST (but I don't think this
  ** is widely [or at all] implemented).
  */
  if( pkt->pf.tcp_rx.pay_len ) {
    LOG_U(log(LPF "%d RST with data (%d bytes)",
              S_FMT(ts), pkt->pf.tcp_rx.pay_len));
    LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt),
                       oo_pre_l3_len(pkt) +
                       CI_BSWAP_BE16(oo_ip_hdr(pkt)->ip_tot_len_be16), 0));
  }

  if( (tcp->tcp_flags & ~(CI_TCP_FLAG_RST|CI_TCP_FLAG_ACK)
       & CI_TCP_FLAG_MASK) )
    LOG_U(log(LPF "%d RST with unexpected flags (%x)", S_FMT(ts),
              (unsigned) tcp->tcp_flags));

  if( ts->s.b.state == CI_TCP_SYN_SENT ) {
    /* rfc793 p66:
    **    If the ACK was acceptable then signal the user "error:
    **    connection reset", drop the segment, enter CLOSED state,
    **    delete TCB, and return.  Otherwise (no ACK) drop the segment
    **    and return.
    */
    if( (tcp->tcp_flags & CI_TCP_FLAG_ACK) &&
        SEQ_EQ(rxp->ack, ts->snd_max) ) {
      LOG_TC(log(LPF "%d SYN-SENT->CLOSED (RESET)", S_FMT(ts)));
      CITP_STATS_NETIF(++netif->state->stats.tcp_connect_refused);
      ci_tcp_drop(netif, ts, ECONNREFUSED);
    }
    else
      goto unacceptable_rst;

    goto freepkt_out;
  }

  /* rfc793 p69-70
  ** for all of the remaining states we need to:
  **  - check sequence number is correct
  **  - ditch any connection and segments on receive/retransmission queue
  **  - return the correct error code
  */

  /* check sequence number is acceptable */
  if( ci_tcp_seq_probably_unacceptable(tcp_rcv_nxt(ts),
                                       tcp_rcv_wnd_right_edge_sent(ts),
                                       rxp->seq, rxp->seq) ) {
    /* Accept RST for rcv_nxt - 1 after a FIN.
     * Same as Linux.
     */
    if( ! (ts->s.b.state & CI_TCP_STATE_RECVD_FIN) ||
        ts->s.b.state == CI_TCP_TIME_WAIT ||
        tcp_rcv_nxt(ts) - 1 != rxp->seq )
      goto unacceptable_rst;
#if CI_CFG_STATS_NETIF
    CITP_STATS_NETIF_INC(netif, rst_recv_after_fin);
#endif
  }
  else if( ! SEQ_EQ(rxp->seq, tcp_rcv_nxt(ts)) ) {
    /* RFC 5961: non-precise SEQ number in RST results in challenge ACK.
     * ci_tcp_send_challenge_ack() returns true if it consumed the packet. */
    if( ci_tcp_send_challenge_ack(netif, ts, pkt) )
      return;
    goto freepkt_out;
  }

#if CI_CFG_STATS_NETIF
  if( ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ )
    CITP_STATS_NETIF_INC(netif, rst_recv_acceptq);
  if( tcp_rcv_usr(ts) )
    CITP_STATS_NETIF_INC(netif, rst_recv_has_recvq);
  if( ! SEQ_EQ(tcp_enq_nxt(ts), tcp_snd_nxt(ts)) )
    CITP_STATS_NETIF_INC(netif, rst_recv_has_sendq);
  if( ! SEQ_EQ(tcp_snd_nxt(ts), tcp_snd_una(ts)) )
    CITP_STATS_NETIF_INC(netif, rst_recv_has_unack);
#endif

  /* do the correct ditch and error code */
  switch( ts->s.b.state ) {
  case CI_TCP_ESTABLISHED:
  case CI_TCP_FIN_WAIT1:
  case CI_TCP_FIN_WAIT2:
  case CI_TCP_CLOSING:
  case CI_TCP_LAST_ACK:
    LOG_TC(log(LPF"%d %s->CLOSED (RESET)",S_FMT(ts),state_str(ts)));
    ci_tcp_drop(netif, ts, ECONNRESET);
    goto freepkt_out;
  case CI_TCP_CLOSE_WAIT:
    ci_tcp_drop(netif, ts, EPIPE);
    goto freepkt_out;
  case CI_TCP_TIME_WAIT:
    /* Good sequence number, good paws => possible TIME-WAIT assassination.
     */
    if( NI_OPTS(netif).time_wait_assassinate &&
        ( ! (ts->tcpflags & rxp->flags & CI_TCPT_FLAG_TSO) ||
          ci_tcp_paws_check(netif, rxp->timestamp, ts->tspaws, ts->tsrecent)
        ) ) {
      ci_tcp_drop(netif, ts, 0);
    }
  case CI_TCP_CLOSED:
    goto unacceptable_rst;
  default:
    /* should never get here */
    log(LPF"Unexpected value in ts->s.b.state %d", ts->s.b.state);
    ci_assert(0);
  }

 unacceptable_rst:
  LOG_U(log(FNTS_FMT "UNACCEPTABLE RST "TCP_RCV_FMT" PKT seq=%08x ack=%08x",
            FNTS_PRI_ARGS(netif, ts), TCP_RCV_PRI_ARG(ts),
            rxp->seq, rxp->ack));
  CITP_STATS_NETIF_INC(netif, rst_recv_unacceptable);

 freepkt_out:
  ci_netif_pkt_release_rx(netif, pkt);
  return;
}


/*
 * Called for a packet destined for a passive open SYNRECV.  [ipcache]
 * contains the control plane state to contact the sender.
 */
static void handle_rx_synrecv_ack(ci_netif* netif, ci_tcp_socket_listen* tls,
                                  ci_tcp_state_synrecv* tsr,
                                  ciip_tcp_rx_pkt* rxp,
                                  ci_ip_cached_hdrs* ipcache)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_tcp_hdr* tcp = rxp->tcp;
  ci_uint32 tsr_rcv_wnd = ci_tcp_rcvbuf2window(tls->s.so.rcvbuf, tsr->amss,
                                               tsr->rcv_wscl);
  ci_tcp_state* ts;
  ci_assert(netif);
  ci_assert(tls);
  ci_assert(tls->s.b.state == CI_TCP_LISTEN);
  ci_assert(tsr);
  ASSERT_VALID_PKT(netif, pkt);

  LOG_TC(log(LNT_FMT "SYN-RECV %s:%d->%s:%d on socket %s:%d",
             LNT_PRI_ARGS(netif, tls),
             ip_addr_str(oo_ip_hdr(pkt)->ip_saddr_be32),
             (unsigned) CI_BSWAP_BE16(tcp->tcp_source_be16),
             ip_addr_str(oo_ip_hdr(pkt)->ip_daddr_be32),
             (unsigned) CI_BSWAP_BE16(tcp->tcp_dest_be16),
             ip_addr_str(tcp_laddr_be32(tls)),
             (unsigned) CI_BSWAP_BE16(tcp_lport_be16(tls))));

  /*
  ** Either:
  **  - duplicate or resent SYN from other side (resent synack)
  **  - out of window, send an ACK
  **  - reset from other end which should revert us to listen
  **    (this is currently handled in handle_rx_rst)
  **  - this is an ACK for SYNACK and the connection is established
  **  - incoming segment ack does not ack our SYNACK then we reset,
  **    SYN or SYNACK not for our SYNACK then also reset,
  **    unless it is out of window (rfc793 p71)
  */

  /* Check for bad SYN packets: process it before seq_unacceptable */
  if( tcp->tcp_flags & CI_TCP_FLAG_SYN ) {
    if( !SEQ_EQ(rxp->seq+1, tsr->rcv_nxt) ) {
      LOG_U(log(LNT_FMT "SYNRECV non-dup SYN will reset pkt=%08x-%08x"
                " rcv=%08x-%08x", LNT_PRI_ARGS(netif, tls),
                rxp->seq, pkt->pf.tcp_rx.end_seq,
                tsr->rcv_nxt, tsr->rcv_nxt + tsr_rcv_wnd));
      /* ?? fixme CI_IP_SOCK_STATS_INC_BADSYN( tls );*/
      CITP_STATS_NETIF_INC(netif, rst_sent_synrecv_bad_syn);
      goto reset_out;
    }
    LOG_TV(log(LNT_FMT "SYNRECV dup SYN", LNT_PRI_ARGS(netif, tls)));
    /* ?? fixme CI_IP_SOCK_STATS_INC_SYNDUP( ts );*/
    goto retransmit_synack;
  }

  /* check sequence number */
  if( ci_tcp_seq_probably_unacceptable(tsr->rcv_nxt,
                                       tsr_rcv_wnd+tsr->rcv_nxt,
                                       rxp->seq,
                                       pkt->pf.tcp_rx.end_seq) ) {
    LOG_U(log(LNT_FMT "SYNRECV unacceptable SEQ pkt=%08x-%08x "
              "["CI_TCP_FLAGS_FMT"] rcv=%08x-%08x", LNT_PRI_ARGS(netif, tls),
              rxp->seq, pkt->pf.tcp_rx.end_seq,
              CI_TCP_HDR_FLAGS_PRI_ARG(tcp),
              tsr->rcv_nxt, tsr->rcv_nxt + tsr_rcv_wnd));
    /* ?? fixme CI_IP_SOCK_STATS_INC_BADSYNSEQ( ts );*/
    goto retransmit_synack;
  }

  /* RST handled elsewhere; see handle_rx_rst. */
  ci_assert(~tcp->tcp_flags & CI_TCP_FLAG_RST);

  /* check it is an ACK */
  if( ~tcp->tcp_flags & CI_TCP_FLAG_ACK ) {
    LOG_U(log(LNT_FMT "SYNRECV non ACK",
              LNT_PRI_ARGS(netif, tls)));
    /* ?? fixme CI_IP_SOCK_STATS_INC_SYNNONACK( ts );*/
    goto freepkt_out;
  }

  /* Is this ACK for our SYNACK? */
  if( !SEQ_EQ(tsr->snd_isn+1, rxp->ack) ) {
    LOG_U(log(LNT_FMT "SYNRECV bad ACK",
              LNT_PRI_ARGS(netif, tls)));
    /* ?? fixme CI_IP_SOCK_STATS_INC_SYNBADACK( ts );*/
    CITP_STATS_NETIF_INC(netif, rst_sent_synrecv_bad_ack);
    goto reset_out;
  }

  /* check paws */
  if( tsr->tcpopts.flags & CI_TCPT_FLAG_TSO &&
      rxp->flags & CI_TCPT_FLAG_TSO ) {
    if( ci_tcp_paws_check(netif, rxp->timestamp, tsr->timest, tsr->tspeer) ) {
      LOG_U(log(LNT_FMT "SYNRECV PAWS failed pkt=%08x-%08x "
                "rcv=%08x-%08x", LNT_PRI_ARGS(netif, tls),
                rxp->seq, pkt->pf.tcp_rx.end_seq,
                tsr->rcv_nxt, tsr->rcv_nxt + tsr_rcv_wnd));
      goto retransmit_synack;
    }
    /* update latest packet timestamp */
    tsr->tspeer = rxp->timestamp;
  }

  /* ACK is for our SYNACK so promote the socket */
  tsr->retries |= CI_FLAG_TSR_RETRIES_ACKED;
  if( (tls->c.tcp_defer_accept != OO_TCP_DEFER_ACCEPT_OFF ) &&
      SEQ_EQ(rxp->seq, pkt->pf.tcp_rx.end_seq) &&
      (tsr->retries & CI_FLAG_TSR_RETRIES_MASK) < tls->c.tcp_defer_accept ) {
    CITP_STATS_TCP_LISTEN(++netif->state->stats.accepts_deferred);
    ci_netif_pkt_release(netif, pkt);
  }
  else if( ci_tcp_listenq_try_promote(netif, tls, tsr, ipcache, pkt,
                                      &ts) < 0 ) {
    CI_TCP_EXT_STATS_INC_LISTEN_DROPS( netif );
    LOG_U(log(LNT_FMT "SYNRECV failed to promote to acceptq, seq=%08x",
              LNT_PRI_ARGS(netif, tls), rxp->seq));
    ci_netif_pkt_release_rx(netif, pkt);
  }
  else {
    /* Make packet length re-calculation correct */
    pkt->pf.tcp_rx.pay_len += CI_TCP_HDR_LEN(tcp) - ts->incoming_tcp_hdr_len;
    /* handle_rx_slow does not see that new data was ACKed, because
     * retransmit queue if empty. */
    if( ts->tcpflags & rxp->flags & CI_TCPT_FLAG_TSO )
      ci_tcp_update_rtt(netif, ts,
                        ci_tcp_time_now(netif) - rxp->timestamp_echo);
    else if( ~ts->tcpflags & CI_TCPT_FLAG_SYNCOOKIE )
      ci_tcp_update_rtt(netif, ts, ci_tcp_time_now(netif) - ts->timed_ts);

    /* Do not defer ACK if we have data here to avoid
     * unnecessary retransmits (mostly used for TCP_DEFER_ACCEPT). */
    if( ! SEQ_EQ(rxp->seq, pkt->pf.tcp_rx.end_seq) )
      TCP_FORCE_ACK(ts);
    /* put the socket on post poll list - vital if we have new data */
    ci_netif_put_on_post_poll(netif, &ts->s.b);
    /* Now handle ACK and data */
    handle_rx_slow(ts, netif, rxp);
  }
  return;

 freepkt_out:
  ci_netif_pkt_release_rx(netif, pkt);
  return;
 retransmit_synack:
  pkt = ci_netif_pkt_rx_to_tx(netif, pkt);
  if( pkt != NULL )
    ci_tcp_synrecv_send(netif, tls, tsr, pkt,
                        CI_TCP_FLAG_SYN | CI_TCP_FLAG_ACK, ipcache);
  return;
 reset_out:
  /* LOG_U already printed in all paths to here */
  ci_tcp_reply_with_rst(netif, &tls->s.cp, rxp);
  return;
}


/*
** This function is assumed to be called when a SYN packet is routed
** to a listening socket it:
**  - demux to determine if we have already received a syn for this one
**  - allocate one of the synrecved structures from our pool
**  - insert the synrecved structures into listen hash table
**
** sends a SYN-ACK, inserts the connection
** into the filters, and will be moved to the accept queue when the
** SYN-ACK is acknowledged */
static void handle_rx_listen(ci_netif* netif, ci_tcp_socket_listen* tls,
                             ciip_tcp_rx_pkt* rxp, int already_parsed)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_ip_pkt_fmt* tx_pkt;
  ci_ipx_hdr_t* ip = RX_PKT_IPX_HDR(pkt);
  ci_tcp_hdr* tcp = rxp->tcp;
  ci_tcp_state_synrecv* tsr;
  ci_ip_cached_hdrs ipcache;
  oo_sp local_peer = OO_SP_NULL;
  int do_syncookie = 0;
#if CI_CFG_IPV6
  int af = oo_pkt_af(pkt);
#endif
  ci_addr_t saddr, daddr;

  ci_assert(tls);
  ci_assert(tls->s.b.state == CI_TCP_LISTEN);

  if( NI_OPTS(netif).tcp_rx_checks )
    ci_tcp_listen_rx_checks(netif, tls, pkt);

  ci_netif_put_on_post_poll(netif, &tls->s.b);

  if( pkt->intf_i == OO_INTF_I_LOOPBACK ) {
    local_peer = pkt->pf.tcp_rx.lo.tx_sock;
    ci_assert_equal(pkt->pf.tcp_rx.lo.rx_sock, tls->s.b.bufid);
  }
  pkt->pf.tcp_rx.window = CI_BSWAP_BE16(tcp->tcp_window_be16);
  pkt->pf.tcp_rx.pay_len -= CI_TCP_HDR_LEN(tcp);
  pkt->pf.tcp_rx.end_seq = rxp->seq + pkt->pf.tcp_rx.pay_len;
  pkt->pf.tcp_rx.end_seq +=
    (tcp->tcp_flags & CI_TCP_FLAG_SYN) >> CI_TCP_FLAG_SYN_BIT;
  pkt->pf.tcp_rx.end_seq +=
    (tcp->tcp_flags & CI_TCP_FLAG_FIN) >> CI_TCP_FLAG_FIN_BIT;

  /* The checksum already checked this... ?? But what about when h/w
  ** does the checksum?  Will h/w detect this error?
  */
  ci_assert_ge(pkt->pf.tcp_rx.pay_len, 0);

  if( CI_TCP_HDR_LEN(tcp) < sizeof(ci_tcp_hdr) ) {
    ci_netif_pkt_release_rx(netif, pkt);
    return;
  }

  if (!already_parsed)
    ci_tcp_parse_options(netif, rxp, NULL);

  if( CI_UNLIKELY(tcp->tcp_flags & CI_TCP_FLAG_RST) ) {
    handle_rx_listen_rst(netif, tls, rxp);
    return;
  }

  /* RST handled elsewhere; we shouldn't see it here. */
  ci_assert(~tcp->tcp_flags & CI_TCP_FLAG_RST);

  if( (tcp->tcp_flags & CI_TCP_FLAG_MASK) == CI_TCP_FLAG_SYN ) {
    /* Bin the SYN if we've got a reasonable number of fresh synrecvs
    ** already, and the accept queue is full, or there are no socket
    ** buffers to promote into.  ie. Don't SYN-ACK if we've not prepared to
    ** do anything when we get the ACK.
    */
    if( tls->n_listenq_new > CI_MIN(tls->acceptq_max,
                                    ci_tcp_listenq_max(netif)) / 4 &&
        (ci_tcp_acceptq_n(tls) >= tls->acceptq_max ||
         (OO_SP_IS_NULL(netif->state->free_eps_head) &&
          netif->state->n_ep_bufs == netif->state->max_ep_bufs
          /*&& ci_ni_dllist_is_empty(netif, &netif->state->timeout_q)*/)) ) {
      CITP_STATS_NETIF(++netif->state->stats.syn_drop_busy);
      goto freepkt_out;
    }

    /* If listen queue is full: */
    if( (tls->n_listenq >= ci_tcp_listenq_max(netif)) |
        ( ! ci_ni_aux_can_alloc(netif, CI_TCP_AUX_TYPE_SYNRECV) ) ) {

      /* If we cope with acceptq, we can try syncookie. */
      if( NI_OPTS(netif).tcp_syncookies ) {
            do_syncookie = 1;
      }
      /* If we're overloaded then we need to minimise the work we do.  So
      ** fail early if this is a SYN and the listen queue is full. */
      else if( tls->n_listenq >= ci_tcp_listenq_max(netif) ) {
        /* If listen queue is full, then normally we'll drop the SYN.  However,
        ** if the accept queue is also full, then we're liable to be left with
        ** a listen queue full of synrecvs that will only be promoted after a
        ** timeout.  This can lead to the accept queue drying up (and killing
        ** app performance).
        **
        ** Therefore if the accept queue is also full, boot out the oldest
        ** synrecv.
        */
        if( ci_tcp_acceptq_n(tls) >= tls->acceptq_max )
          ci_tcp_listenq_drop_oldest(netif, tls);
        else
          CITP_STATS_TCP_LISTEN(++tls->stats.n_listenq_overflow);
      }
      else {
        CITP_STATS_TCP_LISTEN(++tls->stats.n_listenq_no_synrecv);
      }
      if( !do_syncookie )
        goto freepkt_out;
    }
  }

  /* Do control plane lookup to find out how to contact the other end.
   * We'll need this info to send a reply, or to initialise the new
   * ci_tcp_state if we wind up promoting.
   *
   * NB. We could potentially get a win by remembering some of this info
   * from when we receive the SYN to when we get the SYN-ACK-ACK.  A little
   * bit fiddly though: Route etc. is independent of the port numbers, but
   * some info in the ipcache does depend on them when interface is a bond.
   */
  ci_ip_cache_init(&ipcache, oo_pkt_af(pkt));
  ci_ipcache_set_daddr(&ipcache, RX_PKT_SADDR(pkt));
  ipcache_protocol(&ipcache) = IPPROTO_TCP;
  ipcache.dport_be16 = tcp->tcp_source_be16;
  if( CI_UNLIKELY( pkt->intf_i == OO_INTF_I_LOOPBACK ) ) {
    /* This packet was received via loopback, so there is no need to call
     * cicp_user_retrieve().  Even if the route table has a strange route,
     * we always should reply back. */
    ipcache.status = retrrc_localroute;
    ipcache.encap.type = CICP_LLAP_TYPE_NONE;
    ipcache.ether_offset = 4;
    ipcache.intf_i = OO_INTF_I_LOOPBACK;
    ipcache.mtu = netif->state->max_mss;
    /* Fixme: make this verinfo "valid" so the route is not re-resolved
     * later. */
    ci_ip_cache_invalidate(&ipcache);
  }
  else {
    struct oo_sock_cplane sock_cp = tls->s.cp;
    sock_cp.laddr = RX_PKT_DADDR(pkt);
#if CI_CFG_IPV6
    if( CI_IPX_IS_LINKLOCAL(sock_cp.laddr) &&
        (sock_cp.so_bindtodevice = ci_rx_pkt_ifindex(netif, pkt)) == 0 ) {
      LOG_U(ci_log("%s: no interface matching link-local address " IPX_FMT
                   " found", __FUNCTION__, IPX_ARG(AF_IP_L3(sock_cp.laddr))));
      goto freepkt_out;
    }
#endif
    sock_cp.lport_be16 = tcp->tcp_dest_be16;
    sock_cp.sock_cp_flags |= OO_SCP_BOUND_ADDR;
    cicp_user_retrieve(netif, &ipcache, &sock_cp);
  }

  switch( ipcache.status ) {
  case retrrc_success:
  case retrrc_nomac:
    break;
  case retrrc_localroute:
    if( pkt->intf_i == OO_INTF_I_LOOPBACK ) {
      ipcache.flags |= CI_IP_CACHE_IS_LOCALROUTE;
      ci_ipcache_set_saddr(&ipcache, RX_PKT_DADDR(pkt));
      break;
    }
    /* fall through */
  default:
    LOG_U(ci_log("%s: no return route to "IPX_FMT" exists, "
                 "dropping listen response pkt",
		 __FUNCTION__, IPX_ARG(AF_IP_L3(ipcache_raddr(&ipcache)))));
    LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt),
                       ip_pkt_dump_len(RX_PKT_PAYLOAD_LEN(pkt)),
		       0));
    CITP_STATS_NETIF(++netif->state->stats.syn_drop_no_return_route);
    goto freepkt_out;
  }

  /* Does this packet match a connection in the synrecv state? */
  if( (tsr = ci_tcp_listenq_lookup(netif, tls, rxp)) ) {
    /* pass to relevant synrecv structure for processing */
    handle_rx_synrecv_ack(netif, tls, tsr, rxp, &ipcache);
    return;
  }
  
  /* Is it a syncookie? */
  if( NI_OPTS(netif).tcp_syncookies && (tcp->tcp_flags & CI_TCP_FLAG_ACK) &&
      ci_tcp_acceptq_n(tls) < tls->acceptq_max ) {
    ci_tcp_state_synrecv* tsr;
    ci_tcp_syncookie_ack(netif, tls, rxp, &tsr);
    if( tsr != NULL ) {
      tsr->amss = ci_tcp_amss(netif, &tls->c, &ipcache, __func__);
      handle_rx_synrecv_ack(netif, tls, tsr, rxp, &ipcache);
      return;
    }
  }

  /*
  ** This should be the first SYN of a new connection on a listening socket
  ** process as rfc793 p65.
  */
  LOG_TC(log(LNT_FMT "LISTEN "IPX_FMT":%d->"IPX_FMT":%d on socket "IPX_FMT":%d",
             LNT_PRI_ARGS(netif, tls), IPX_ARG(AF_IP(RX_PKT_SADDR(pkt))),
             (unsigned) CI_BSWAP_BE16(tcp->tcp_source_be16),
             IPX_ARG(AF_IP(RX_PKT_DADDR(pkt))),
             (unsigned) CI_BSWAP_BE16(tcp->tcp_dest_be16),
             IPX_ARG(AF_IP(sock_ipx_laddr(&tls->s))),
             (unsigned) CI_BSWAP_BE16(tcp_lport_be16(tls))));

  /* Want to do minimum work when overloaded, so check for listen queue
  ** overflow early. */
  if(CI_UNLIKELY( !do_syncookie &&
                  tls->n_listenq >= ci_tcp_listenq_max(netif) )) {
    CITP_STATS_TCP_LISTEN(++tls->stats.n_listenq_overflow);
    goto freepkt_out;
  }
  if(CI_UNLIKELY( !do_syncookie &&
                  ! ci_ni_aux_can_alloc(netif, CI_TCP_AUX_TYPE_SYNRECV) )) {
    CITP_STATS_TCP_LISTEN(++tls->stats.n_listenq_no_synrecv);
    goto freepkt_out;
  }

  if( tcp->tcp_flags & CI_TCP_FLAG_ACK ) {
    /* This is fairly common on windows, due to the penchant for abortive
    ** closes. */
    LOG_TC(log(LNT_FMT"LISTEN got ACK, will reset",LNT_PRI_ARGS(netif,tls)));
    CITP_STATS_TCP_LISTEN(++tls->stats.n_acks_reset);
    CITP_STATS_NETIF_INC(netif, rst_sent_listen_got_ack);
    goto reset_out;
  }

  if( ~tcp->tcp_flags & CI_TCP_FLAG_SYN ) {
    LOG_U(log(LNT_FMT "LISTEN got packet without SYN, will drop",
              LNT_PRI_ARGS(netif, tls)));
    LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt),
                       ip_pkt_dump_len(RX_PKT_PAYLOAD_LEN(pkt)),
		       0));
    /* shouldn't get here but silence is response, rfc793 p66 */
    goto freepkt_out;
  }

  /* Don't think this should ever be tripped but if it does... */
  if( (tcp->tcp_flags & CI_TCP_FLAG_MASK) != CI_TCP_FLAG_SYN ) {
    LOG_U(log(LNT_FMT "LISTEN got SYN with other flags",
              LNT_PRI_ARGS(netif, tls)));
    LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt),
                       ip_pkt_dump_len(RX_PKT_PAYLOAD_LEN(pkt)),
		       0));
  }

  saddr = ipx_hdr_saddr(af, ip);
  daddr = ipx_hdr_daddr(af, ip);

  /* ANVL tcp-core 23.x tests - check the source address is OK */
  /* 23.1: if source address is our destination address then reject */
  if( CI_IPX_ADDR_EQ(daddr, saddr) && pkt->intf_i != OO_INTF_I_LOOPBACK)
    goto ignore_pkt;

  /* 23.2: if source address is 0 then reject */
  if( CI_IPX_ADDR_IS_ANY(saddr) )
    goto ignore_pkt;

#if CI_CFG_IPV6
  if( CI_IS_ADDR_IP6(saddr) ) {
    const ci_ip6_addr_t addr_none =
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};

    /* if source address is -1 then reject */
    if( CI_IP6_ADDR_CMP(saddr.ip6, addr_none) == 0 )
      goto ignore_pkt;

    /* reject connections from loopback address */
    if( CI_IP6_ADDR_CMP(saddr.ip6, ip6_addr_loop.ip6) == 0 &&
        pkt->intf_i != OO_INTF_I_LOOPBACK )
      goto ignore_pkt;

    if( !NI_OPTS(netif).unconfine_syn ) {
      const ci_addr_t unique_local_addr = {.ip6 = {0xfc}};
      const ci_addr_t unique_local_mask = {.ip6 = {0xfe}};

      /* accept fc00::/7 connections only from fc00::/7 */
      if( ci_ipx_addr_masked_eq(&saddr, &unique_local_addr, &unique_local_mask) &&
         !ci_ipx_addr_masked_eq(&daddr, &unique_local_addr, &unique_local_mask) )
        goto ignore_pkt;
    }
  }
  else
#endif
  {
    /* 23.2: if source address is -1 then reject */
    if( saddr.ip4 == 0xffffffff )
      goto ignore_pkt;

    /* 23.4: reject connections from 127.x.x.x */
    if( CI_IP_ADDR_EQUAL(saddr.ip4, 127,0,0,0, 0xff000000) &&
        pkt->intf_i != OO_INTF_I_LOOPBACK )
      goto ignore_pkt;

    if( !NI_OPTS(netif).unconfine_syn &&
        /* 23.3: accept 10.x.x.x connections only from 10.x.x.x */
        (  (CI_IP_ADDR_EQUAL(saddr.ip4, 10,0,0,0, 0xff000000) &&
           !CI_IP_ADDR_EQUAL(daddr.ip4, 10,0,0,0, 0xff000000))
        /* 23.5: accept 172.16.x.x connections only from 172.16.x.x */
        || (CI_IP_ADDR_EQUAL(saddr.ip4, 172,16,0,0, 0xffff0000) &&
           !CI_IP_ADDR_EQUAL(daddr.ip4, 172,16,0,0, 0xffff0000))
        /* 23.6: accept 192.168.x.x connections only from 192.168.x.x */
        || (CI_IP_ADDR_EQUAL(saddr.ip4, 192,168,0,0, 0xffff0000) &&
           !CI_IP_ADDR_EQUAL(daddr.ip4, 192,168,0,0, 0xffff0000))
        ))
      goto ignore_pkt;
  }

  /* It is legal to pass data with a SYN, but it is not desirable to keep
  ** the data because it provides a simple way to do a DOS.  So we bin the
  ** data, and the other end can retransmit it.
  */
  if( pkt->pf.tcp_rx.pay_len ) {
    LOG_U(log(LPF "%d LISTEN SYN with data (%d bytes)", S_FMT(tls),
          pkt->pf.tcp_rx.pay_len));
    LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt),
                       ip_pkt_dump_len(RX_PKT_PAYLOAD_LEN(pkt)),
		       0));
  }

  /* Drop segment if it has a FIN. */
  if( tcp->tcp_flags & CI_TCP_FLAG_FIN ) {
    LOG_U(log(LPF "%d LISTEN got segment with FIN, will drop", S_FMT(tls)));
    goto freepkt_out;
  }

  /* Allocate synrecv. */
  if( do_syncookie ) {
    tsr = ci_alloc(sizeof(ci_tcp_state_synrecv));
  }
  else {
    /* We've already called ci_ni_aux_can_alloc() above, so we are sure
     * that we *really* can alloc tsr. */
    tsr = ci_ni_aux_p2synrecv(netif,
                              ci_ni_aux_alloc(netif,
                                              CI_TCP_AUX_TYPE_SYNRECV));
    tsr->bucket_link = OO_P_NULL;
    tsr->hash = rxp->hash;
  }

  /* parse the SYN options */
  memset(&tsr->tcpopts, 0, sizeof(tsr->tcpopts));
  tsr->tcpopts.smss = CI_CFG_TCP_DEFAULT_MSS;
  if( ipcache.flags & CI_IP_CACHE_IS_LOCALROUTE )
    tsr->local_peer = local_peer;
  else
    tsr->local_peer = OO_SP_NULL;

  tsr->tcpopts.flags = 0;
  if( ci_tcp_parse_options(netif, rxp, &tsr->tcpopts)
      < 0 ) {
#if CI_CFG_TCP_INVALID_OPT_RST
    /* bad option block, send reset rfc1122 4.2.2.5 */
    LOG_U(log(LPF "%d LISTEN bad SYN options will reset", S_FMT(tls)));
    if( do_syncookie )
      ci_free(tsr);
    else
      ci_tcp_synrecv_free(netif, tsr);
    CITP_STATS_NETIF_INC(netif, rst_sent_bad_options);
    goto reset_out;
#endif
  }

  tsr->tcpopts.flags |= rxp->flags & CI_TCPT_FLAG_TSO;
  if( tsr->tcpopts.flags & CI_TCPT_FLAG_TSO )
    tsr->tspeer = rxp->timestamp;

  if( !do_syncookie ) {
    if( ! ci_tcp_can_stripe(netif, ip->ip4.ip_daddr_be32,ip->ip4.ip_saddr_be32) )
      tsr->tcpopts.flags &=~ CI_TCPT_FLAG_STRIPE;
    tsr->tcpopts.flags &= NI_OPTS(netif).syn_opts | CI_TCPT_FLAG_STRIPE;
  }

  /* setup synrecv state */
  tsr->l_addr = RX_PKT_DADDR(pkt);
  tsr->r_addr = RX_PKT_SADDR(pkt);
  tsr->l_port = tcp->tcp_dest_be16;
  tsr->r_port = tcp->tcp_source_be16;

  /* store timestamp in echo reply */
  tsr->timest = ci_tcp_time_now(netif);
  tsr->rcv_nxt = rxp->seq + 1;
  if( tsr->tcpopts.flags & CI_TCPT_FLAG_WSCL ) {
    if( NI_OPTS(netif).tcp_rcvbuf_mode == 1 ) {
      /* may overestimate MSS, but this is "OK" */
      tsr->rcv_wscl = (ci_uint8)
        ci_tcp_wscl_by_buff(netif,
                            ci_tcp_max_rcvbuf(netif, netif->state->max_mss));
    }
    else {
      tsr->rcv_wscl = (ci_uint8)
        ci_tcp_wscl_by_buff(netif,
                            ci_tcp_rcvbuf_established(netif, &tls->s));
    }
  }
  else {
    tsr->rcv_wscl = 0;
  }

  if( do_syncookie )
    ci_tcp_syncookie_syn(netif, tls, tsr);
  else {
    tsr->snd_isn = ci_tcp_initial_seqno(netif, tsr->l_addr, tsr->l_port,
                                        tsr->r_addr, tsr->r_port);

    /* Insert synrecv into the listen queue. */
    ci_tcp_listenq_insert(netif, tls, tsr);
    CITP_STATS_NETIF(++netif->state->stats.listen2synrecv);
  }

  LOG_TC(if( tsr->amss == 0 ) tsr->amss = netif->state->max_mss;
         log(LNT_FMT "SYN-RECV rcv=%08x-%08x snd=%08x-%08x",
             LNT_PRI_ARGS(netif, tls),
             tsr->rcv_nxt, tsr->rcv_nxt +
             ci_tcp_rcvbuf2window(tls->s.so.rcvbuf,
                                  tsr->amss, tsr->rcv_wscl),
             tsr->snd_isn, tsr->snd_isn + pkt->pf.tcp_rx.window));

  /* send SYN-ACK packet */
  CI_TCP_STATS_INC_PASSIVE_OPENS( netif );
  if( OO_SP_NOT_NULL(tsr->local_peer) )
    ci_netif_pkt_hold(netif, pkt);
  tx_pkt = ci_netif_pkt_rx_to_tx(netif, pkt);
  if( tx_pkt != NULL )
    ci_tcp_synrecv_send(netif, tls, tsr, tx_pkt,
                        CI_TCP_FLAG_SYN | CI_TCP_FLAG_ACK, &ipcache);

  if( OO_SP_NOT_NULL(tsr->local_peer) ) {
    ci_tcp_state *ts = NULL;
    ci_tcp_state* peer = ID_TO_TCP(netif, tsr->local_peer);

    if( (tls->c.tcp_defer_accept != OO_TCP_DEFER_ACCEPT_OFF ) &&
        SEQ_EQ(rxp->seq + 1, pkt->pf.tcp_rx.end_seq) ) {
      CITP_STATS_TCP_LISTEN(++netif->state->stats.accepts_deferred);
      peer->tcpflags |= CI_TCPT_FLAG_LOOP_DEFERRED;
      LOG_TC(log(LNT_FMT "loopback connection deferred",
                 LNT_PRI_ARGS(netif, peer)));
    }
    else if( ci_tcp_listenq_try_promote(netif, tls, tsr, &ipcache, pkt,
                                        &ts) < 0 ) {
      CI_TCP_EXT_STATS_INC_LISTEN_DROPS( netif );
      LOG_U(log(LNT_FMT "SYNRECV failed to promote local connection "
                "to acceptq", LNT_PRI_ARGS(netif, tls)));
      ci_tcp_drop(netif, peer, EBUSY);
    }
    ci_netif_pkt_release(netif, pkt);
  }

  if( do_syncookie )
    ci_free(tsr);
  return;

 ignore_pkt:
  LOG_U(log(LNT_FMT "LISTEN ignoring SYN: bad src/dst",
            LNT_PRI_ARGS(netif, tls));
        log(LPF " ----> S[" IPX_FMT "], D[" IPX_FMT "]",
            IPX_ARG(AF_IP(saddr)), IPX_ARG(AF_IP(daddr))));

 freepkt_out:
  ci_netif_pkt_release_rx(netif, pkt);
  return;

 reset_out:
  /* LOG_U already printed in all three paths to this point */
  ci_tcp_reply_with_rst(netif, &tls->s.cp, rxp);
  return;
}


/* parse the option block of the received packet and setup
** TCB state to match
*/
static int handle_syn_sent_opts(ci_netif* netif, ci_tcp_state* ts,
                                ciip_tcp_rx_pkt* rxp)
{
  ci_tcp_options tcpopts;
  int optlen = 0;
  int af = ipcache_af(&ts->s.pkt);

  /* parse TCP options */
  memset(&tcpopts, 0, sizeof(tcpopts));
  tcpopts.smss = CI_CFG_TCP_DEFAULT_MSS;

  tcpopts.flags = 0;
  if( ci_tcp_parse_options(netif, rxp, &tcpopts) < 0 ) {
#if CI_CFG_TCP_INVALID_OPT_RST
    /* bad option block send reset */
    LOG_U(log(LPF "%d SYN-SENT error in options will reset",
              S_FMT(ts)));
    ci_tcp_drop(netif, ts, ECONNRESET);
    /* We should set ACK in our RST */
    ci_tcp_set_flags(ts, CI_TCP_FLAG_ACK);
    CITP_STATS_NETIF_INC(netif, rst_sent_bad_options);
    ci_tcp_reply_with_rst(netif, &ts->s.cp, rxp);
    return -1;
#endif
  }
  tcpopts.flags |= rxp->flags & CI_TCPT_FLAG_TSO;

  if( ts->tcpflags & tcpopts.flags & CI_TCPT_FLAG_WSCL ) {
    ts->snd_wscl = tcpopts.wscl_shft; /* rcv_wscl set when SYN sent */
    CI_IP_SOCK_STATS_VAL_TXWSCL( ts, ts->snd_wscl );
  }
  else {
    ts->snd_wscl = ts->rcv_wscl = 0u;
    CI_IP_SOCK_STATS_VAL_TXWSCL( ts, ts->snd_wscl );
    CI_IP_SOCK_STATS_VAL_RXWSCL( ts, ts->rcv_wscl );
    ts->tcpflags &=~ CI_TCPT_FLAG_WSCL;
  }

  ts->tslastack = tcp_rcv_nxt(ts); /* used for faststart as well as TSO */
  if( ts->tcpflags & CI_TCPT_FLAG_TSO ) {
    if( rxp->flags & CI_TCPT_FLAG_TSO) {
      /* assume that sender will send TSO aligned as in RFC1323 app A */
      ts->incoming_tcp_hdr_len += 12;
      optlen = 12;

#ifndef NDEBUG
      ts->tslastseq = rxp->seq;
#endif
      ts->tsrecent = rxp->timestamp;
      ts->tspaws = ci_tcp_time_now(netif);
    }
    else {
      oo_pkt_p id;
      ci_ip_pkt_queue *txq = &ts->send;
      ci_ip_pkt_fmt *p;
      ci_uint8 *opt;

      for( id = txq->head; OO_PP_NOT_NULL(id); id = p->next ) {
        p = PKT_CHK(netif, id);
        opt = CI_TCP_HDR_OPTS(TX_PKT_IPX_TCP(af, p));
        if( CI_TCP_HDR_OPT_LEN(TX_PKT_IPX_TCP(af, p)) >= 12 )
          *opt = 0; /* end of options */
      }
      ts->tcpflags &= ~CI_TCPT_FLAG_TSO;
    }
  }
  if( !(tcpopts.flags & CI_TCPT_FLAG_SACK) )
    ts->tcpflags &=~ CI_TCPT_FLAG_SACK;
  if( !(tcpopts.flags & CI_TCPT_FLAG_STRIPE) )
    ts->tcpflags &=~ CI_TCPT_FLAG_STRIPE;

  ts->outgoing_hdrs_len = CI_IPX_HDR_SIZE(af) + sizeof(ci_tcp_hdr) + optlen;
  ci_tcp_set_hdr_len(ts, sizeof(ci_tcp_hdr) + optlen);

  ts->smss = tcpopts.smss;
  if (ts->c.user_mss && ts->c.user_mss < ts->smss)
    ts->smss = ts->c.user_mss;
#if CI_CFG_LIMIT_SMSS
  ts->smss = ci_tcp_limit_mss(ts->smss, netif, __FUNCTION__);
#endif
  ci_assert_gt(ts->smss, 0);
  ci_tcp_set_eff_mss(netif, ts);
  ci_tcp_set_initialcwnd(netif, ts);
  return 0;
}


static void handle_rx_syn_sent(ci_netif* netif, ci_tcp_state* ts,
                               ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_tcp_hdr* tcp = rxp->tcp;

  /* RST handled elsewhere; we shouldn't see it here. */
  ci_assert(~tcp->tcp_flags & CI_TCP_FLAG_RST);

  /* If this is a local packet, do no checks */
  if( pkt->intf_i == OO_INTF_I_LOOPBACK ) {
    ci_tcp_state* peer = ID_TO_TCP(netif, ts->local_peer);
    ci_assert(ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE);
    if( handle_syn_sent_opts(netif, ts, rxp) < 0 ) return;
    ts->snd_una = ts->snd_nxt;
    /* Use s.so.rcvbuf as a window value, because pf.tcp_rx.window in SYN
     * can be too small.  For normal connection it is updated via the ACK
     * which finalizes the handshake, but loopback does not send it. */
    ts->snd_max = ts->snd_nxt + peer->s.so.rcvbuf;

    goto set_isn;
  }

  /* We should have SYN in RTQ. */
  ci_assert(!ci_ip_queue_is_empty(&ts->retrans));

  /*
  ** Are we *required* to complete the handshake before sending any data?
  ** Answer: NO, but we mustn't deliver any data to the user until we reach
  ** the ESTABLISHED state.  (?? What is the source of this wisdom?).
  */

  /* Segments containing FINs should be dropped, since we cannot verify the
  ** sequence number (rfc793 p75). But we don't check FIN flag here since we
  ** have to send RST for stray FIN-ACK to ensure that the old peer moves its
  ** socket from FIN-WAIT1 or LAST-ACK forward in timely manner.
  */

  /*
  ** Following rfc793 p66
  */

  /* "first check the ACK bit" */
  if( tcp->tcp_flags & CI_TCP_FLAG_ACK ) {
    if( SEQ_LE(rxp->ack, tcp_snd_una(ts)) ||
        SEQ_LT(tcp_snd_nxt(ts), rxp->ack) ) {
      LOG_U(log(LPF "%d SYN-SENT unacceptable ACK will reset",
                S_FMT(ts)));
      CITP_STATS_NETIF_INC(netif, rst_sent_unacceptable_ack);
      ci_tcp_reply_with_rst(netif, &ts->s.cp, rxp);
      return;
    }
  }

  /* "second check the RST bit"
  ** RST handled in handle_rx_rst; we shouldn't see it here. */
  ci_assert(~tcp->tcp_flags & CI_TCP_FLAG_RST);

  /* "third check the security and precedence"
  ** Not applicable.
  */

  /* "fourth check the SYN bit" */
  if( tcp->tcp_flags & CI_TCP_FLAG_SYN ) {
    if( ~tcp->tcp_flags & CI_TCP_FLAG_ACK ) {
      /* NB. We don't implement simultaneous open. */
      LOG_U(log(LPF "%d SYN-SENT simultaneous open", S_FMT(ts)));
      goto free_out;
    }
  } else {
    /* "fifth, if neither of the SYN or RST bits is set then drop the
    ** segment and return." */
    LOG_U(log(LPF "%d SYN-SENT ignored packet without SYN/RST flags=0x%x "
              "(binned)",
              S_FMT(ts), tcp->tcp_flags));
    goto free_out;
  }

  /* we have an acceptable SYN/ACK here so we need to transition to
  ** established and setup any negotiated options.
  ** We need to parse options before ci_tcp_rx_handle_ack(),
  ** because we need SYN-specific options.
  */

  if( handle_syn_sent_opts(netif, ts, rxp) < 0 ) return;

  /* remove SYN (and any sent data) from retransmission queue
  ** and seed RTT */
  ci_assert(tcp->tcp_flags & CI_TCP_FLAG_ACK);
  ci_tcp_rx_handle_ack(ts, netif, rxp);

  /*
   * It's not necessary to shift the window because it should not be
   * done in SYN and SYN-ACK. See chapter 2.2 of RFC1323.
   */
  ci_tcp_set_snd_max(ts, rxp->seq, rxp->ack, pkt->pf.tcp_rx.window);

set_isn:
  /* Snarf their initial sequence no. and window. */
  ci_tcp_rx_set_isn(ts, pkt->pf.tcp_rx.end_seq);
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  if( ci_tcp_is_pluginized(ts) ) {
#ifdef __KERNEL__
    if( in_atomic() ) {
      /* The workqueue lag here will tend to cause us to go in to recycling
       * instantly. We'll recover. */
      tcp_helper_endpoint_t* ep = ci_netif_get_valid_ep(netif, S_SP(ts));
      tcp_helper_endpoint_queue_non_atomic(ep,
                                           OO_THR_EP_AFLAG_TCP_OFFLOAD_ISN);
    }
    else {
      efab_tcp_helper_tcp_offload_set_isn(netif2tcp_helper_resource(netif),
                                          S_SP(ts), tcp_rcv_nxt(ts));
    }
#else
    ci_tcp_offload_set_isn_t set = {
      .ep_id = S_SP(ts),
      .isn = tcp_rcv_nxt(ts),
    };
    oo_resource_op(ci_netif_get_driver_handle(netif),
                   OO_IOC_TCP_OFFLOAD_SET_ISN, &set);
#endif
  }
#endif

#if CI_CFG_TCP_OFFLOAD_RECYCLER
  if( ci_tcp_is_pluginized(ts) )
    ci_tcp_offload_get_stream_id(netif, ts, pkt->intf_i);
#endif

  ci_tcp_set_established_state(netif, ts);
  CITP_STATS_NETIF(++netif->state->stats.active_opens);

  ci_assert(CI_TCP_HDR_LEN(TS_IPX_TCP(ts)) ==
      sizeof(ci_tcp_hdr) + tcp_ipx_outgoing_opts_len(ipcache_af(&ts->s.pkt), ts));
  ci_tcp_set_initialcwnd(netif, ts);
  ci_assert_gt(ts->rcv_window_max,0);
  ci_tcp_init_rcv_wnd(ts, "SYN SENT");
  if( pkt->intf_i == OO_INTF_I_LOOPBACK ) {
    ci_tcp_state* peer = ID_TO_TCP(netif, ts->local_peer);
    /* peer is the listening socket in case of TCP_DEFER_ACCEPT */
    if( peer->s.b.state != CI_TCP_LISTEN ) {
      /* ci_tcp_init_rcv_wnd() sets rcv_wnd_right_edge_sent.  Deliver this
       * value to the peer. */
      peer->snd_max = ts->rcv_wnd_right_edge_sent;
      peer->rcv_wnd_right_edge_sent = ts->snd_max;
    }
  }

  LOG_TC(log(LPF "%d SYN-SENT->ESTABLISHED " RCV_WND_FMT " snd=%08x-%08x-%08x"
             " enq=%08x",
             S_FMT(ts), RCV_WND_ARGS(ts),
             tcp_snd_una(ts), tcp_snd_nxt(ts), ts->snd_max, tcp_enq_nxt(ts)));

  /* Send any data that was enqueued in advance. */
  if( ci_tcp_sendq_not_empty(ts) ) {
    ci_netif_pkt_release_rx(netif, pkt);
    ci_tcp_tx_advance(ts, netif);
  }
  else if ( OO_SP_NOT_NULL(ts->local_peer) ) {
    ci_tcp_send_ack_loopback(netif, ts);
    ci_netif_pkt_release_rx(netif, pkt);
  }
  else {
    pkt = ci_netif_pkt_rx_to_tx(netif, pkt);
    if( pkt != NULL )
      ci_tcp_send_ack(netif, ts, pkt, CI_FALSE);
  }

  ci_tcp_wake(netif, ts, CI_SB_FLAG_WAKE_RX | CI_SB_FLAG_WAKE_TX);
  return;

 free_out:
  ci_netif_pkt_release_rx(netif, pkt);
  return;
}


static void handle_rx_close_wait(ci_tcp_state* ts, ci_netif* netif,
                                 ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  int send_challenge_ack = 0;

  /* RST handled elsewhere; we shouldn't see it here. */
  ci_assert(~rxp->tcp->tcp_flags & CI_TCP_FLAG_RST);

  /* We've already seen a FIN from the other guy, so any data we see should
  ** be duplicates only.
  */
  if( SEQ_LT(tcp_rcv_nxt(ts), pkt->pf.tcp_rx.end_seq) ) {
    LOG_TR(log(LPF "%d CLOSE-WAIT data after FIN " TCP_RX_FMT,
              S_FMT(ts), TCP_RX_ARGS(rxp, ts)));
    send_challenge_ack = 1;
  }
  else if( pkt->pf.tcp_rx.pay_len ) {
    LOG_TR(log(LPF "%d CLOSE-WAIT duplicate data " TCP_RX_FMT,
               S_FMT(ts), TCP_RX_ARGS(rxp, ts)));
    send_challenge_ack = 1;
  }
  if( rxp->tcp->tcp_flags & CI_TCP_FLAG_SYN ) {
    LOG_TR(log(LPF "%d CLOSE-WAIT got SYN", S_FMT(ts)));
    send_challenge_ack = 1;
  }

  if( ci_tcp_sendq_not_empty(ts) ) {
    ci_tcp_tx_advance(ts, netif);
    send_challenge_ack = 0;
  }

  if( ! send_challenge_ack || ! ci_tcp_send_challenge_ack(netif, ts, pkt) )
    ci_netif_pkt_release_rx(netif, pkt);
}


static void handle_rx_last_ack_or_closing(ci_tcp_state* ts, ci_netif* netif,
                                          ciip_tcp_rx_pkt* rxp,
                                          int next_state)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;

  /* RST handled elsewhere; we shouldn't see it here. */
  ci_assert(~rxp->tcp->tcp_flags & CI_TCP_FLAG_RST);

  if( rxp->tcp->tcp_flags & CI_TCP_FLAG_SYN ) {
#ifndef NDEBUG
    LOG_U(log(LPF "%d %s saw SYN!", S_FMT(ts), state_str(ts)));
#endif
    pkt = ci_netif_pkt_rx_to_tx(netif, pkt);
    if( pkt != NULL )
      ci_tcp_send_ack(netif, ts, pkt, CI_FALSE);
    return;
  }

  /* If our txq is empty, then our FIN has been ACKed, and we can go home. */

  if( SEQ_EQ(tcp_snd_una(ts), tcp_enq_nxt(ts)) ) {
    ci_assert(ci_tcp_sendq_is_empty(ts));
    ci_assert(ci_tcp_retransq_is_empty(ts));

    /* This packet must be the one that ACKed our FIN (or we would have
    ** closed before).
    */
    ci_assert(SEQ_EQ(rxp->ack, tcp_snd_nxt(ts)));

    /* We've each seen each other's FINs, so there's no way he should be
    ** sending any data...
    */
    if( pkt->pf.tcp_rx.pay_len ) {
      LOG_U(log(LPF "%d %s bad data " TCP_RX_FMT,
                S_FMT(ts), state_str(ts), TCP_RX_ARGS(rxp, ts)));
    }

    LOG_TC(log(LNT_FMT "%s->%s", LNT_PRI_ARGS(netif, ts), state_str(ts),
               ci_tcp_state_str(next_state)));

    ci_tcp_wake(netif, ts, CI_SB_FLAG_WAKE_RX | CI_SB_FLAG_WAKE_TX);

    /* On Linux, receiving of FIN is the same as shutdown(rd);
     * we should not set anything except CI_SHUT_RD into rx_errno.
     * See bug 10638 for details */
    if( next_state == CI_TCP_CLOSED ) {
      ci_tcp_drop(netif, ts, 0);

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
      /* If we're sharing an active wild then we've just made our 4-tuple
       * available for re-use, by removing filters.  The peer will be sitting
       * in TIME-WAIT however, so we need to be careful about our sequence
       * numbers if we re-use this quickly.
       */
      if( ts->tcpflags & CI_TCPT_FLAG_ACTIVE_WILD )
        ci_netif_active_wild_sharer_closed(netif, &ts->s);
#endif
    }
    else {
      ci_assert(next_state == CI_TCP_TIME_WAIT);
      ts->s.tx_errno = EPIPE;
      ts->s.rx_errno |= CI_SHUT_RD;
      ci_assert(ci_tcp_sendq_is_empty(ts));
      ci_assert(ci_tcp_retransq_is_empty(ts));
      ci_assert(ci_ip_queue_is_empty(&ts->rob));
      ci_netif_timewait_enter(netif, ts);
      ci_tcp_set_slow_state(netif, ts, next_state);
    }
  } else {
    /* try to make forward progress if the TXQ has data */
    if( ci_tcp_sendq_not_empty(ts) )
      ci_tcp_tx_advance(ts, netif);

#ifndef NDEBUG
    /* We've already seen a FIN from the other guy, so any data we see should
    ** be duplicates only.
    */
    if( SEQ_LT(tcp_rcv_nxt(ts), pkt->pf.tcp_rx.end_seq) ) {
      LOG_U(log(LPF "%d %s data after " TCP_RX_FMT,
                S_FMT(ts), state_str(ts), TCP_RX_ARGS(rxp, ts)));
    }
    else if( pkt->pf.tcp_rx.pay_len ) {
      LOG_TR(log(LPF "%d %s duplicate data " TCP_RX_FMT,
                 S_FMT(ts), state_str(ts), TCP_RX_ARGS(rxp, ts)));
    }
#endif
  }

  ci_netif_pkt_release_rx(netif, pkt);
}


ci_inline void handle_rx_fin_wait_1(ci_tcp_state* ts, ci_netif* netif)
{
  if( ci_tcp_sendq_is_empty(ts) && ci_tcp_retransq_is_empty(ts) ) {
    LOG_TC(log(LPF "%d FIN-WAIT1->FIN-WAIT2", S_FMT(ts)));
    ci_tcp_set_slow_state(netif, ts, CI_TCP_FIN_WAIT2);
    ci_tcp_wake(netif, ts, CI_SB_FLAG_WAKE_TX);

    if ( ci_tcp_is_timeout_orphan(ts) )
      ci_netif_timeout_restart(netif, ts);
  }
}


/* RX slow-path handler for states which either don't accept data, or which
 * (besides their usual handling on the accepting-data path) might need to
 * transition into another state as the result of an ACK that arrived in a
 * zero-window probe. Returns non-zero if we did anything.
 */
static int handle_rx_minor_states(ci_tcp_state* ts, ci_netif* netif,
                                      ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_tcp_hdr* tcp = rxp->tcp;

  if( CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_FIN_PENDING ) )
    ci_tcp_resend_fin(ts, netif);

  switch( ts->s.b.state ) {
  case CI_TCP_SYN_SENT:
    handle_rx_syn_sent(netif, ts, rxp);
    break;
  case CI_TCP_CLOSE_WAIT:
    handle_rx_close_wait(ts, netif, rxp);
    break;
  case CI_TCP_LAST_ACK:
    handle_rx_last_ack_or_closing(ts, netif, rxp, CI_TCP_CLOSED);
    break;
  case CI_TCP_CLOSING:
    handle_rx_last_ack_or_closing(ts, netif, rxp, CI_TCP_TIME_WAIT);
    break;
  case CI_TCP_FIN_WAIT1:
    /* Can only get here when rxp is a zero-window probe. Might need to
     * transition to FIN_WAIT_2.
     */
    handle_rx_fin_wait_1(ts, netif);
    ci_netif_pkt_release_rx(netif, rxp->pkt);
    break;
  case CI_TCP_TIME_WAIT:
    /*! rfc1122 p88 4.2.2.13 reopening with SYN */
    /* RFC 1122 allows us to re-open a connection in TIME-WAIT only if
     * the sequence number on the incomming SYN is greater than the
     * previous maximum sequence number.
     * (Like Linux) we also allow the SYN if PAWS is in use and the SYN
     * timestamp is newer than any previous one we've seen
     */
    if(tcp->tcp_flags & CI_TCP_FLAG_SYN) {
      if (SEQ_LT(tcp_rcv_nxt(ts), rxp->seq) ||
          ((ts->tcpflags & rxp->flags & CI_TCPT_FLAG_TSO) &&
           TIME_GE(rxp->timestamp, ts->tsrecent)) ){
        oo_sp sock_id;
        ci_sock_cmn* s;
        LOG_TV(
            if (!SEQ_LT(tcp_rcv_nxt(ts), rxp->seq))
              log(LPF "old SYN seq number accepted using timestamp %x >= %x",
                  rxp->timestamp, ts->tsrecent);
            );

        /* There is an attempt to reopen a connection in TIME WAIT.
           First, lookup and verify there is a listen socket, then
           remove this connection from TIME WAIT, and
           pass to listen socket for processing */

        sock_id = ci_netif_listener_lookup(netif, sock_af_space(&ts->s),
                                           sock_ipx_laddr(&ts->s),
                                           sock_lport_be16(&ts->s));
        if( OO_SP_IS_NULL(sock_id) ) {
          LOG_U(log(LPF "no matching listener for SYN in TIME_WAIT"));
          goto reopen_failed;
        }
        s = SP_TO_SOCK(netif, sock_id);
        if( s->b.state != CI_TCP_LISTEN ) {
          LOG_U(log(LPF "non-listener targeted by SYN in TIME_WAIT"));
          goto reopen_failed;
        }

        LOG_TV(log(LPF "SYN in TIME WAIT state, recycling connection"));
        ci_netif_timeout_leave(netif, ts);

        /* handle_rx_listen() expects pf.tcp_rx.pay_len to not be munged,
         * so undo the change we have made
         */
        pkt->pf.tcp_rx.pay_len += CI_TCP_HDR_LEN(tcp);
        handle_rx_listen(netif, SOCK_TO_TCP_LISTEN(s), rxp, 1);
        break;
      }
      else
        LOG_U(log(LPF "SYN in TIME_WAIT has old SEQ - staying in TIME_WAIT"));
    }
 reopen_failed:
    /* Not normal, do nothing! (rfc793 p23)  That being said, pure ACKs can be
     * generated by the peer if we retransmitted our FIN, so don't complain
     * about those. */
    if( pkt->pf.tcp_rx.pay_len > 0 ||
        (tcp->tcp_flags & CI_TCP_FLAG_MASK) != CI_TCP_FLAG_ACK ) {
      if( ! ci_tcp_send_challenge_ack(netif, ts, pkt) )
        ci_netif_pkt_release(netif, pkt);
    }
    else {
      ci_netif_pkt_release(netif, pkt);
    }
    break;
  case CI_TCP_CLOSED:
    /* For non-loopback connections:
    ** If doing a s/w demux, then this can't happen, 'cos this connection
    ** wouldn't be in the hash table.  If h/w does demux and identifies
    ** connection for us, then it potentially can, since events can take a
    ** while to arrive.
    **
    ** We are doing s/w demux, and I don't anticipate this changing any
    ** time soon.  We shouldn't get here.
    **
    ** However, if we do, we'll cope gracefully by handling in the same way
    ** as a loopback connection.
    */
    ci_assert(pkt->intf_i == OO_INTF_I_LOOPBACK);
    if(!(pkt->intf_i == OO_INTF_I_LOOPBACK))
      LOG_E(ci_log(LNT_FMT "ERROR demux to CLOSED socket",
                   LNT_PRI_ARGS(netif, ts)));
    CITP_STATS_NETIF_INC(netif, rst_sent_no_match);
    ci_tcp_reply_with_rst(netif, &ts->s.cp, rxp);
    break;
  default:
    return 0;
  }

  return 1;
}


#ifndef NDEBUG

static void explain_why_seq_unacceptable(ci_netif* netif, ci_tcp_state* ts,
                                         ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;

  log(LNTS_FMT "SEQ UNACCEPTABLE "TCP_RX_FMT" ...",
         LNTS_PRI_ARGS(netif, ts), TCP_RX_ARGS(rxp, ts));

  /* Fast exit if nothing interesting */
  if( ! SEQ_EQ(pkt->pf.tcp_rx.end_seq, rxp->seq) &&
      tcp_rcv_wnd_right_edge_sent(ts) == tcp_rcv_nxt(ts) &&
      SEQ_LT(pkt->pf.tcp_rx.end_seq-1, tcp_rcv_nxt(ts)) &&
      (~ci_tp_log & CI_TP_LOG_TV) )
    /* if seg.len > 0 && rcv.wnd > 0 && pkt_seq_num < seq_we_are_waiting &&
     * LOG_TV is off  =>  go away. */
    return;

  if( ts->tcpflags & rxp->flags & CI_TCPT_FLAG_TSO ) {
    if( ci_tcp_paws_check(netif, rxp->timestamp,
                          ts->tspaws, ts->tsrecent) ) {
      /* Possible PAWS failure, try and work out if it's interesting.  If
       * this is in sequence, zero length, and the same seqno as the one
       * that updated tsrecent, it could have been undetectably reordered.
       */
      if( SEQ_EQ(rxp->seq, ts->tslastack)
          && SEQ_EQ(ts->tslastack, ts->tslastseq)
          && SEQ_EQ(rxp->seq, pkt->pf.tcp_rx.end_seq) )
        log("\tPAWS reordered tsval=0x%x tsrecent=0x%x "
            "tslastack=0x%x tslastseq=0x%x", rxp->timestamp,
            ts->tsrecent, ts->tslastack, ts->tslastseq);
      else
        log("\tPAWS FAILED tsval=0x%x tsrecent=0x%x "
            "tslastack=0x%x tslastseq=0x%x", rxp->timestamp,
            ts->tsrecent, ts->tslastack, ts->tslastseq);
    }
  }
  else if( ts->tcpflags & CI_TCPT_FLAG_TSO )
    log("\tTSO missing");

  if( SEQ_EQ(pkt->pf.tcp_rx.end_seq, rxp->seq) ) {
    if( tcp_rcv_wnd_right_edge_sent(ts) == tcp_rcv_nxt(ts) ) {
      /* seg.len = 0, rcv.wnd = 0 */
      if( ! SEQ_EQ(rxp->seq, tcp_rcv_nxt(ts)) )
        log("\tseg.len=0, rcv.wnd=0, seg.seq!=rcv.nxt");
    }
    else if( SEQ_LT(rxp->seq, tcp_rcv_nxt(ts)) )
      log("\tseg.len=0, rcv.wnd>0, seg.seq<rcv.nxt");
    else if( SEQ_LE(tcp_rcv_wnd_right_edge_sent(ts), rxp->seq) )
      log("\tseg.len=0, rcv.wnd>0, seg.seq>rcv.nxt+rcv.wnd");
  }
  else if(tcp_rcv_wnd_right_edge_sent(ts) == tcp_rcv_nxt(ts)) {
    /* seg.len > 0, rcv.wnd = 0 */
    log("\tseg.len>0, rcv.wnd=0");
  }
  else {
    /* seg.len > 0, rcv.wnd > 0 */
    if( SEQ_LT(pkt->pf.tcp_rx.end_seq-1, tcp_rcv_nxt(ts)) ) {
      log("\tseg.len>0, rcv.wnd>0, "
          "seg.seq+seg.len-1<rcv.nxt, seg.seq<rcv.nxt");
      log("\tIf experiencing loss & reordering, probably unnecessary "
          "retransmit");
    }
    if( SEQ_LE(tcp_rcv_wnd_right_edge_sent(ts), rxp->seq) )
      log("\tseg.len>0, rcv.wnd>0, seg.seq>=rcv.nxt+rcv.wnd,"
          " and seq.seq+seg.len-1>=rcv.nxt+rcv.wnd");
  }
}

static void explain_why_on_slow_path(ci_netif* netif, ci_tcp_state* ts,
                                     ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_tcp_hdr* tcp = rxp->tcp;

  log(LPF "%d SLOW...", S_FMT(ts));

  if( ts->fast_path_check == ~CI_TCP_FAST_PATH_MASK )
    log("\tfast_disabled");
  else if( (CI_TCP_FAST_PATH_WORD(tcp) & CI_TCP_FAST_PATH_MASK)
           != ts->fast_path_check )
    log("\tfast_check(%x,%x)",
        (unsigned)(CI_TCP_FAST_PATH_WORD(tcp)&CI_TCP_FAST_PATH_MASK),
        (unsigned)ts->fast_path_check);
  if( rxp->seq - tcp_rcv_nxt(ts) )
    log("\tseq(%08x)!=rcv_nxt(%08x)", rxp->seq, tcp_rcv_nxt(ts));
  if( SEQ_LT(tcp_rcv_wnd_right_edge_sent(ts), pkt->pf.tcp_rx.end_seq) )
     log("\tnot_in_win(" RCV_WND_FMT " end_seq=%08x)",
         RCV_WND_ARGS(ts), pkt->pf.tcp_rx.end_seq);
  if( tcp_snd_una(ts) - rxp->ack )
     log("\tnew_ack(una=%08x ack=%08x)", tcp_snd_una(ts), rxp->ack);
  if( pkt->pf.tcp_rx.pay_len <= 0 )
     log("\tshort(pay_len=%d)", pkt->pf.tcp_rx.pay_len);
}
#endif

static void handle_unacceptable_seq(ci_netif* netif, ci_tcp_state* ts,
                                    ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_tcp_hdr* tcp = rxp->tcp;
  int inflate;

  /* if we are awaiting their seq then it is likely to be unacceptable */
  if( ts->s.b.state == CI_TCP_SYN_SENT ) {
    handle_rx_syn_sent(netif, ts, rxp);
    /* if handle_rx_syn_sent didn't send an ACK, need to clear the DSACK flag */
    ts->dsack_block = OO_PP_INVALID;
    return;
  }

  if( ci_tcp_is_pluginized(ts) ) {
    if( ci_tcp_plugin_elided_payload(pkt) &&
        SEQ_LE(pkt->pf.tcp_rx.end_seq, tcp_rcv_nxt(ts)) )
      ci_tcp_rx_clean_plugin_rob(netif, ts, pkt->pf.tcp_rx.end_seq);
    if( tcp_plugin_pkt_was_recycled(ts, pkt) ) {
      ci_netif_pkt_release_rx(netif, pkt);
      ts->dsack_block = OO_PP_INVALID;
      return;
    }
  }

  /* Only consider updating the send window for unacceptable sequence
   * number packets if the received packet was recently retransmitted,
   * has recent ack and has a legitimate larger window.
   * This is to avoid deadlock in the case where an unnecessary
   * retransmission includes a larger window that we would
   * otherwise ignore.
   * Particularily, this code accepts window update from
   * zero-window-probe/keepalive if they ack new data.
   */
  if( SEQ_GT(pkt->pf.tcp_rx.end_seq, rxp->seq) && /* has payload */
      SEQ_BTW(rxp->seq, SEQ_SUB(tcp_rcv_nxt(ts), 0x2000), 
              tcp_rcv_nxt(ts)) && /* recent in sequence space */ 
      SEQ_GE(rxp->ack, ts->snd_una) && /* recent ack */
      SEQ_LE(rxp->ack, ts->snd_nxt) && /* reasonable ack */
      SEQ_GT(rxp->ack + rxp->pkt->pf.tcp_rx.window,
             ts->snd_max) && /* increases snd_max */
      (inflate = ci_tcp_rx_try_snd_wnd_inflate(ts, rxp)) > 0 ) {
    if ( ci_tcp_sendq_not_empty(ts) ) {
      LOG_TR(log(LNTS_FMT "%08x-%08x unacceptable "TCP_RCV_FMT,
                 LNTS_PRI_ARGS(netif, ts), rxp->seq,
                 pkt->pf.tcp_rx.end_seq, TCP_RCV_PRI_ARG(ts)));
      LOG_TR(log("  inflated window by %d", inflate));
      ci_tcp_tx_advance(ts, netif);
    }
  }

  /* TODO other things could be found out from this out of order packet:
   * - test for duplicate ACKs? */

#if CI_CFG_PORT_STRIPING
  /* If striping, then pure ACKs with out of order seqnos are
   * expected, and so acceptable.
   */
  if( (ts->tcpflags & CI_TCPT_FLAG_STRIPE)
      && SEQ_EQ(pkt->pf.tcp_rx.end_seq, rxp->seq)
      && SEQ_LE(rxp->seq, tcp_rcv_nxt(ts)) ) {
    /* It is a zero length packet that falls before rcv_nxt.  This
     * sometimes happens when striping and an ACK is received out of order.
     * Can safely ignore.  Zero-window probes would be detected before
     * calling this function.
     */
    ci_netif_pkt_release_rx(netif, pkt);
    /* Because we're not going to send an ACK here, the dsack block needs
     * to be cleared to prevent the next packet getting confused when it
     * finds there is a old block still waiting.
     */
    ts->dsack_block = OO_PP_INVALID;
    return;
  }
#endif

  if( SEQ_EQ(pkt->pf.tcp_rx.end_seq, rxp->seq) ) {
    /* Pure ACK. */
    ++ts->stats.rx_ack_seq_errs;
#ifndef NDEBUG
    if( ts->stats.rx_ack_seq_errs <= NI_OPTS(netif).tcp_max_seqerr_msg )
      LOG_TE(explain_why_seq_unacceptable(netif, ts, rxp));
#endif
  }
  else {
    CITP_TCP_FASTSTART(ts->faststart_acks = NI_OPTS(netif).tcp_faststart_loss);
    ++ts->stats.rx_seq_errs;
#ifndef NDEBUG
    if( ts->stats.rx_seq_errs <= NI_OPTS(netif).tcp_max_seqerr_msg )
      LOG_TE(explain_why_seq_unacceptable(netif, ts, rxp));
#endif
  }

  /* if a retransmission of the FIN then we should restart 2*msl timeout */
  if( ts->s.b.state == CI_TCP_TIME_WAIT ) {
    if( tcp->tcp_flags & CI_TCP_FLAG_FIN &&
        SEQ_EQ(rxp->seq+1, tcp_rcv_nxt(ts)) ) {
      LOG_TC(log(LNT_FMT "dup FIN in TIME_WAIT restarting 2MSL",
                 LNT_PRI_ARGS(netif, ts)));
      ci_netif_timeout_restart(netif, ts);
    }
  }

  /* Reply with RST if unsynchronised, or empty ACK otherwise (rfc793 p37). */
  if( ts->s.b.state & CI_TCP_STATE_SYNCHRONISED ) {
    if( OO_PP_EQ(ts->dsack_block, OO_PP_INVALID) &&
        ! ci_tcp_may_send_ack_ratelimited(netif, ts) ) {
      ci_netif_pkt_release(netif, pkt);
    }
    else {
      pkt = ci_netif_pkt_rx_to_tx(netif, pkt);
      if( pkt != NULL )
        ci_tcp_send_ack(netif, ts, pkt, CI_FALSE);
    }
  }
  else{
    LOG_U(log(LPF "%d handle unacceptable seq RSTACK needed because "
              "not in synchronized state",S_FMT(ts)));
    CITP_STATS_NETIF_INC(netif, rst_sent_bad_seq);
    ci_tcp_reply_with_rst(netif, &ts->s.cp, rxp);
    /* because we're not going to send an ACK here, the dsack block needs
       to be cleared to prevent the next packet getting confused when
       it finds there is a old block still waiting */
    ts->dsack_block = OO_PP_INVALID;
  }
}


static void handle_rx_slow(ci_tcp_state* ts, ci_netif* netif,
			   ciip_tcp_rx_pkt* rxp)
{
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_tcp_hdr* tcp = rxp->tcp;
  int do_update_wnd = CI_TRUE;

  CI_IP_SOCK_STATS_INC_RXSLOW( ts );
  ci_assert(ts->s.b.state != CI_TCP_LISTEN);

  LOG_TV(explain_why_on_slow_path(netif, ts, rxp));
  CITP_STATS_NETIF_INC(netif, rx_slow);

  /* We may have gotten these wrong in [ci_tcp_handle_rx()], 'cos we
  ** assumed the fast path.
  */
  pkt->pf.tcp_rx.pay_len -= CI_TCP_HDR_LEN(tcp) - ts->incoming_tcp_hdr_len;
  pkt->pf.tcp_rx.end_seq = rxp->seq + pkt->pf.tcp_rx.pay_len;
  pkt->pf.tcp_rx.end_seq +=
    (tcp->tcp_flags & CI_TCP_FLAG_SYN) >> CI_TCP_FLAG_SYN_BIT;
  pkt->pf.tcp_rx.end_seq +=
    (tcp->tcp_flags & CI_TCP_FLAG_FIN) >> CI_TCP_FLAG_FIN_BIT;
  pkt->pf.tcp_rx.window = ci_tcp_wnd_from_hdr(tcp, ts->snd_wscl);

  /* The checksum already checked this... ?? But what about when h/w does
  ** the checksum?  Will h/w detect this error?
  */
  ci_assert_ge(pkt->pf.tcp_rx.pay_len, 0);

  if(CI_UNLIKELY( CI_TCP_HDR_LEN(tcp) < sizeof(ci_tcp_hdr) ))
    goto bad_pkt;
  if(CI_UNLIKELY( tcp->tcp_flags & CI_TCP_FLAG_RST ))
    goto handle_rst;

  /*! \TODO We don't support ECN yet. */
  LOG_TR(if( tcp->tcp_flags & (CI_TCP_FLAG_ECE|CI_TCP_FLAG_CWR) )
           log(LNT_FMT "ECN flags=%x not implemented (ignored)",
               LNT_PRI_ARGS(netif, ts), (unsigned) tcp->tcp_flags));

  ci_assert(CI_IPX_ADDR_EQ(RX_PKT_SADDR(pkt),
                             ipcache_raddr(&ts->s.pkt)));
  ci_assert(CI_IPX_ADDR_EQ(RX_PKT_DADDR(pkt),
                             ipcache_laddr(&ts->s.pkt)));

  ci_assert_equal(tcp->tcp_source_be16, TS_IPX_TCP(ts)->tcp_dest_be16);
  ci_assert_equal(tcp->tcp_dest_be16, TS_IPX_TCP(ts)->tcp_source_be16);

  /* Okay, we can now check the ACKs and sequence nos in detail.
  ** First PAWS rfc1323
  */
  if( ts->tcpflags & rxp->flags & CI_TCPT_FLAG_TSO ) {
    if( ci_tcp_paws_check(netif, rxp->timestamp,
                          ts->tspaws, ts->tsrecent) )
      goto unacceptable_paws;
    /* We defer updating our peer timestamp until after we've validated
     * the ack, as we want to avoid pulling timestamps from packets that
     * we reject. */
  }
  else if( CI_UNLIKELY(ts->tcpflags & CI_TCPT_FLAG_TSO) ) {
    /* with no TSO we are unable to perform checks and can
     * only accept segment in good faith */
    CI_TCP_EXT_STATS_INC_TSO_MISSING( netif );
  }

 not_unacceptable_paws:
  /* Maybe we should protect ourselves by confirming ARP later; but we
     don't want to leave it so late that we are not confirming ARP in 
     useful cases (e.g. zero window probe, tail drop probe) so let's do
     it now. If a black hat can inject packets, they can probably do more
     harm than just confusing the ARP stuff anyway. */

  /*
  ** Incoming seq is acceptable provided it overlaps the window.  See
  ** rfc793 p25.
  */
  if( ci_tcp_seq_probably_unacceptable(tcp_rcv_nxt(ts),
                                       tcp_rcv_wnd_right_edge_sent(ts),
                                       rxp->seq,
                                       pkt->pf.tcp_rx.end_seq) )
    goto unacceptable_seq;
 not_unacceptable_seqno:

  if(CI_UNLIKELY( netif->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL ))
    goto mem_pressure;
 continue_mem_pressure:

  /* Record time to enable detection of keepalive timer expiring early
   * and heuristics to send ACKs if gap that may have caused sender to
   * validate its congestion window
   */
  if( pkt->pf.tcp_rx.pay_len )
    ts->t_last_recv_payload = ci_tcp_time_now(netif);
  else
    ts->t_last_recv_ack = ci_tcp_time_now(netif);

  /* Reconfirm ARP entry if necessary. */
  if( SEQ_GT(rxp->ack, tcp_snd_una(ts)) )
    oo_cp_arp_confirm(netif->cplane, &ts->s.pkt.fwd_ver,
                      ci_ni_fwd_table_id(netif));

  /* Once you're synchronised rfc793 says all segments must have an ACK.
  ** So we don't even bother to check the ACK flag.  The worst that can
  ** happen is a bad ACK that will be dropped or acknowledge data too soon.
  ** So only the other end suffers, and it was their fault anyway.
  */
  if( CI_LIKELY(ts->s.b.state & CI_TCP_STATE_SYNCHRONISED) &&
      ! (ci_tcp_is_pluginized(ts) && tcp_plugin_pkt_was_recycled(ts, pkt)) ) {
    /* An ACK is acceptable provided it doesn't acknowledge sequence
    ** numbers we haven't sent yet.
    */
    if( CI_UNLIKELY(SEQ_LT(tcp_snd_nxt(ts) + ts->snd_delegated, rxp->ack)) )
      /* So far we know the ack number is bogus, but it is possible that
         this packet does not have an ACK flag (e.g. SYNs in TIME-WAIT);
         we move the code to handle this unlikely case out of line here,
         have have probably_unacceptable_ack branch back to
         not_unacceptable_ack below when this happens */
      goto probably_unacceptable_ack;

    if( CI_LIKELY(ts->s.b.state & CI_TCP_STATE_TXQ_ACTIVE) ) {

      if( SEQ_LE(tcp_snd_una(ts), rxp->ack) ) {
        /* ACK is not old.  Check for SACK option, and process the ACK. */

        if( rxp->flags & CI_TCPT_FLAG_SACK )
          ci_tcp_rx_sack_process(netif, ts, rxp);

        if( OO_SP_IS_NULL(ts->local_peer) )
          ci_tcp_rx_handle_ack(ts, netif, rxp);
        else
          ci_assert_equal(tcp_snd_una(ts), rxp->ack);

        if( ci_tcp_sendq_is_empty(ts) &&
            (ts->s.s_flags & CI_SOCK_FLAG_LINGER) &&
            ci_tcp_retransq_is_empty(ts) )
          /* Need this to wake thread in ci_tcp_ul_close(). */
          ci_tcp_wake(netif, ts, CI_SB_FLAG_WAKE_TX);
      }
    } else 
      /* Important to do this even if TXQ is not active */
      ci_tcp_kalive_reset(netif, ts);
  }

 not_unacceptable_ack:
  /* Update our peer timestamp now that we know we have a valid ack */
  if( ts->tcpflags & rxp->flags & CI_TCPT_FLAG_TSO &&
      SEQ_GE(rxp->ack, tcp_snd_una(ts)) ) {
    ci_tcp_tso_update(netif, ts, rxp->seq,
                      pkt->pf.tcp_rx.end_seq, rxp->timestamp);
  }

  if( CI_LIKELY(ts->s.b.state & CI_TCP_STATE_ACCEPT_DATA) ) {
    bool is_plugin_ooo_fin;

    /* If it's windows don't process URG until reordering done */
    if( CI_UNLIKELY((tcp->tcp_flags & CI_TCP_FLAG_URG) ||
                    (tcp_urg_data(ts) & CI_TCP_URG_COMING)) )
      ci_tcp_urg_pkt_process(ts, netif, rxp);

    if( CI_UNLIKELY(tcp->tcp_flags & CI_TCP_FLAG_SYN) ) {
      /* We can get a SYN when connected: A duplicate, or blind window
       * attack.  Send challenge ACK, in the same way as Linux does it
       * (see tcp_validate_incoming()).
      */
      LOG_TC(log(LNTS_FMT "SYN (duplicate?) ignored "TCP_RX_FMT,
                 LNTS_PRI_ARGS(netif,ts), TCP_RX_ARGS(rxp, ts)));
      if( ! ci_tcp_send_challenge_ack(netif, ts, rxp->pkt) )
        ci_netif_pkt_release(netif, rxp->pkt);
      return;
    }

    /* Delivering data needs to be the last thing we do, 'cos we may not
    ** have access to [pkt] after (it may have been freed already).
    */
    is_plugin_ooo_fin = ci_tcp_is_pluginized(ts) &&
                        tcp->tcp_flags & CI_TCP_FLAG_FIN &&
                        SEQ_LT(ts->rcv_added, rxp->seq);
    if( CI_UNLIKELY(is_plugin_ooo_fin &&
                    ! ci_tcp_plugin_elided_payload(pkt)) ) {
      /* If we get a FIN before we've received all the payload segments from
       * the meta-VI then we send it round for recycling. To do otherwise
       * would block our ability to receive and mark the socket as SHUT_RD,
       * which would make is always-ready even when it's not */
      do_update_wnd = CI_FALSE;
      ci_tcp_rx_enqueue_ooo(netif, ts, rxp);
      if( ! ci_ip_queue_is_empty(&ts->rob) )
        ci_tcp_rx_deliver_rob(netif, ts);
      TCP_FORCE_ACK(ts);
    }
    else if( pkt->pf.tcp_rx.pay_len ) {
      if( CI_UNLIKELY(is_plugin_ooo_fin) ) {
        /* Further to the comment just above, however, if the FIN had some
         * in-order payload too then we can't recycle it and we can't drop it
         * entirely. The easiest option is to remove the FIN flag and wait for
         * the retransmit. It's suboptimal, but it's only the FIN. */
        tcp->tcp_flags &=~ CI_TCP_FLAG_FIN;
        pkt->pf.tcp_rx.end_seq--;
        if( pkt->pf.tcp_rx.end_seq == tcp_rcv_nxt(ts) ) {
          /* That FIN removal has made it so there's no useful payload any
           * more: give up now */
          ci_netif_pkt_release_rx(netif, pkt);
          ts->s.b.sb_flags |= CI_SB_FLAG_TCP_POST_POLL;
          TCP_NEED_ACK(ts);
          return;
        }
      }
      if( CI_UNLIKELY(ts->s.rx_errno) ) {
        /* If the socket will never read again then send reset See
        ** Steven's p238 or rfc1122 4.2.2.13.
        ** Linux queues data in ESTABLISHED + RCV_SHUTDOWN.
        ** Linux sends RST without ACK here, i.e. we should call
        ** ci_tcp_send_rst_with_flags() instead of ci_tcp_send_rst().
        */
        if( (ts->s.b.state & CI_TCP_STATE_RECVD_FIN) ||
            ts->s.tx_errno != 0 )
        {
          LOG_U(log(LNTS_FMT" data arrived with SHUT_RD (rx=%x tx=%x)",
                    LNTS_PRI_ARGS(netif, ts), ts->s.rx_errno, ts->s.tx_errno));
          ci_netif_pkt_release_rx(netif, pkt);
          ci_tcp_send_rst_with_flags(netif, ts, 0);
          ci_tcp_drop(netif, ts, ECONNRESET);
          return;
        }
      }

      /* We do not accept data beyond our window (since it makes window
      ** management painful).
      ** However, we accept an out-of-window FIN in case that all of the
      ** payload is in-window.  This is to improve interoperability with
      ** protocol violators (Windows OS e.g. 2k12R2).
      */
      if( SEQ_LT(tcp_rcv_wnd_right_edge_sent(ts) +
                  ((tcp->tcp_flags & CI_TCP_FLAG_FIN) ? 1 : 0),
                 pkt->pf.tcp_rx.end_seq) ) {
        int n;
        if( CI_UNLIKELY(tcp->tcp_flags & CI_TCP_FLAG_FIN) ) {
          tcp->tcp_flags &=~ CI_TCP_FLAG_FIN;
          pkt->pf.tcp_rx.end_seq--;
        }
        /* This segment extends beyond the right-edge that we've
        ** advertised.  We do not accept such data at the moment, since it
        ** makes window management painful.  So we bodge the packet to
        ** pretend that data wasn't there.
        */
        n = SEQ_SUB(pkt->pf.tcp_rx.end_seq,tcp_rcv_wnd_right_edge_sent(ts));
        LOG_U(log(LPF "%d %s EXCEEDS WIN by %d " TCP_RX_FMT " flags %x",
                  S_FMT(ts), state_str(ts), n, TCP_RX_ARGS(rxp, ts),
                  tcp->tcp_flags));
        ci_assert( OO_SP_IS_NULL(ts->local_peer) );
        pkt->pf.tcp_rx.end_seq -= n;
        pkt->pf.tcp_rx.pay_len -= n;
        if( SEQ_LE(pkt->pf.tcp_rx.end_seq, tcp_rcv_nxt(ts)) ) {
          /* There's nothing left that overlaps our window (we started by
           * saying that there is some new data but now we've realised that
           * it's all out-of-window). We've called ci_tcp_rx_handle_ack() so
           * there's a possibility that we can now advance the sendq. We send
           * an ACK as well because the sender is clearly doing something a
           * little odd, so it's best to remind them what they're supposed to
           * be doing. */
          ci_netif_pkt_release_rx(netif, pkt);
          ts->s.b.sb_flags |= CI_SB_FLAG_TCP_POST_POLL;
          TCP_NEED_ACK(ts);
          return;
        }
      }

      /* Deliver the segment's payload to the endpoint. */

      if( SEQ_LE(rxp->seq, tcp_rcv_nxt(ts)) ) {
	/* Segment contains on-order payload. */

        if( ! (tcp->tcp_flags & CI_TCP_FLAG_FIN) ){
          if( ci_tcp_rx_deliver_to_recvq(ts, netif, rxp) == 0 )
            TCP_NEED_ACK(ts);
          else {
            /* Implies there is something in re-order buffer, and if
             * striping that there is a gap on this port. Keep them
             * ACKs a comin' while we're recovering from loss.
             */
            TCP_FORCE_ACK(ts);
            CITP_STATS_NETIF_INC(netif, rx_rob_non_empty);
            CITP_TCP_FASTSTART(ts->faststart_acks =
                                 NI_OPTS(netif).tcp_faststart_loss);
          }
        }
        else{
          /* looks like a packet with data and a FIN */
          /* check that there is some in order payload, once FIN is
             discounted, before delivering */
          do_update_wnd = CI_FALSE;
          if(SEQ_LT(tcp_rcv_nxt(ts), pkt->pf.tcp_rx.end_seq-1)){
            ci_tcp_rx_deliver_to_recvq(ts, netif, rxp);
            /* ci_tcp_rx_deliver_to_recvq() could have changed the state if
             * there was a FIN in the ROB.
             */
            if(ts->s.b.state & CI_TCP_STATE_ACCEPT_DATA) {
              ci_tcp_rx_process_fin(netif, ts);
            }
          }
          else{
            /* No in-order payload, so just process the FIN. */
            /* make sure the FIN is, as expected, the next sequence number */
            ci_assert(SEQ_EQ(pkt->pf.tcp_rx.end_seq, tcp_rcv_nxt(ts) + 1));
            tcp_rcv_nxt(ts) = pkt->pf.tcp_rx.end_seq;
            ci_tcp_rx_process_fin(netif, ts);
            ci_netif_pkt_release_rx(netif, pkt);
          }
          TCP_FORCE_ACK(ts);
        }
      }
      else {
        /* An out-of-order segment: We need to send an ACK straight away to
        ** ensure we get the proper fast retransmit/recovery behaviour at
        ** the other end.
        */
        if( ci_tcp_rx_enqueue_ooo(netif, ts, rxp) ) {
          CITP_TCP_FASTSTART(ts->faststart_acks =
                               NI_OPTS(netif).tcp_faststart_loss);
          do_update_wnd = CI_FALSE;
          if( ts->acks_pending ) {
            /* We have a delayed-ack in hand.  We are entitled to send this
            ** as well as forcing an ack for the new segment.  Should speed
            ** fast recovery...
            */
            ci_ip_pkt_fmt* ackpkt = ci_netif_pkt_alloc(netif, 0);
            if( ackpkt ) ci_tcp_send_ack(netif, ts, ackpkt, CI_FALSE);
          }
          TCP_FORCE_ACK(ts);
        }
      }
    }
    else if( CI_UNLIKELY(tcp->tcp_flags & CI_TCP_FLAG_FIN) ) {
      /* should be a pure FIN */
      ci_assert(!pkt->pf.tcp_rx.pay_len);

      if(SEQ_EQ(rxp->seq, tcp_rcv_nxt(ts))) {
        /* No payload, so rcv_nxt won't get updated by packet delivery. */
        ci_assert(SEQ_EQ(pkt->pf.tcp_rx.end_seq, rxp->seq + 1));
        tcp_rcv_nxt(ts) = pkt->pf.tcp_rx.end_seq;

        ci_tcp_rx_process_fin(netif, ts);

        ci_netif_pkt_release_rx(netif, pkt);
        TCP_FORCE_ACK(ts);
      }
      else if( ci_tcp_rx_enqueue_ooo(netif, ts, rxp) ) {
        do_update_wnd = CI_FALSE;
        TCP_FORCE_ACK(ts);
      }
    }
    else {
      /* only a pure ACK should get here (or could be a duplicate SYN
       * that we ignored above and removed the SYN flag for). Other flags may
       * have been bogusly set by the peer. */
      ci_assert(!pkt->pf.tcp_rx.pay_len);
      ci_assert_nflags(tcp->tcp_flags, CI_TCP_FLAG_SYN | CI_TCP_FLAG_RST |
                                       CI_TCP_FLAG_FIN);
      ci_netif_pkt_release_rx(netif, pkt);
    }

    if( TCP_ACK_FORCED(ts) ) {
      /* ACK was forced.  I assuming for now that it would be a bad idea to
      ** piggy-back this ACK onto a segment with payload, since then it
      ** can't be interpreted as a dupack.
      */
      pkt = ci_netif_pkt_alloc(netif, 0);
      if( pkt )  ci_tcp_send_ack_rx(netif, ts, pkt, CI_FALSE, do_update_wnd);
    }

    /* May need to advance TX or send ACK. */
    ts->s.b.sb_flags |= CI_SB_FLAG_TCP_POST_POLL;

    /* Done with established connections, so get them out of the way
    ** quickly.
    */
    if( ts->s.b.state == CI_TCP_ESTABLISHED )
      return;

    if( ts->s.b.state == CI_TCP_FIN_WAIT1 )
      handle_rx_fin_wait_1(ts, netif);

    return;
  }

  if( ts->s.b.state & CI_TCP_STATE_TXQ_ACTIVE )
    /* May need to advance TX. */
    ts->s.b.sb_flags |= CI_SB_FLAG_TCP_POST_POLL;

  if ( !handle_rx_minor_states(ts, netif, rxp) ) {
    /* State not recognised: shouldn't happen here. */
    ci_log("Unknown state %d ('%s')\n", ts->s.b.state, state_str(ts));
    ci_netif_pkt_release_rx(netif, pkt);
    ci_assert(0);
  }

  return;

 probably_unacceptable_ack:
  if (!(tcp->tcp_flags & CI_TCP_FLAG_ACK)) {
    /* Some packets don't have ACKs (e.g. SYNs to TIME-WAIT states to
       reopen connections so this is not fatal) */
    if (!(ts->s.b.state == CI_TCP_TIME_WAIT &&
          (tcp->tcp_flags & CI_TCP_FLAG_SYN))) {
      /* This is either bad incoming data, or an unanticipated case */
      LOG_U(log(LPF "%d %s packet with no ACK flags %x " TCP_RX_FMT,
                S_FMT(ts), state_str(ts), tcp->tcp_flags,
                TCP_RX_ARGS(rxp, ts)));
    }

    goto not_unacceptable_ack;
  }
  handle_unacceptable_ack(netif, ts, rxp);
  return;

 unacceptable_seq:
  /* was it really unacceptable? */
  if( ts->s.b.state == CI_TCP_TIME_WAIT &&
      (tcp->tcp_flags & (CI_TCP_FLAG_SYN | CI_TCP_FLAG_ACK))
      == CI_TCP_FLAG_SYN )
    goto not_unacceptable_seqno;
  if( !ci_tcp_seq_definitely_unacceptable(tcp_rcv_nxt(ts),
                                          tcp_rcv_wnd_right_edge_sent(ts),
                                          rxp->seq,
                                          pkt->pf.tcp_rx.end_seq) )
    goto not_unacceptable_seqno;

  /* Is it a zero-window probe? */
  if( (ts->s.b.state & CI_TCP_STATE_SYNCHRONISED) &&
      SEQ_EQ(rxp->seq + 1, tcp_rcv_nxt(ts)) &&
      tcp->tcp_flags == CI_TCP_FLAG_ACK ) {
    ci_uint32 snd_nxt_before, snd_nxt_after;
    LOG_TR(log(LNT_FMT "ZWIN probe "TCP_RX_FMT,
               LNT_PRI_ARGS(netif, ts), TCP_RX_ARGS(rxp, ts)));
    snd_nxt_before = tcp_snd_nxt(ts);
    /* Even though it's a zwin probe it may give us more window, so
     * have to look more closely at the ACK.  NB. There's more we
     * could do here, e.g. SACK, but don't bother for now */
    if( ts->s.b.state & CI_TCP_STATE_TXQ_ACTIVE &&
        SEQ_GE(tcp_snd_nxt(ts), rxp->ack) && 
        SEQ_LE(tcp_snd_una(ts), rxp->ack) ) {
      ci_tcp_rx_handle_ack(ts, netif, rxp);

      /* handle_rx_minor_states might release a reference. */
      ci_netif_pkt_hold(netif, pkt);

      /* ACK may have allowed us to advance. We might need to make a state
       * transition, so handle that. We also want to ensure that we advance the
       * send queue if we can, so if we don't do that as a result of the usual
       * state-handling, do it now rather than post-poll so we can send a pure
       * ACK in response (for real ZWIN case) if no data to send.
       */
      if( !handle_rx_minor_states(ts, netif, rxp) )
        ci_netif_pkt_release_rx(netif, pkt);
      if( ci_tcp_sendq_not_empty(ts) )
        ci_tcp_tx_advance(ts, netif);
    }

    snd_nxt_after = tcp_snd_nxt(ts);
    /* Only send a pure ACK if tx_advance did nothing */
    if( snd_nxt_before == snd_nxt_after ) {
      pkt = ci_netif_pkt_rx_to_tx(netif, pkt);
      if( pkt != NULL )
        ci_tcp_send_ack(netif, ts, pkt, CI_FALSE);
    }
    else {
      ci_netif_pkt_release_rx(netif, pkt);
      ci_tcp_wake(netif, ts, CI_SB_FLAG_WAKE_TX);
    }
    return;
  }

  /* Should we DSACK it? */
  if( NI_OPTS(netif).use_dsack && (ts->tcpflags & CI_TCPT_FLAG_SACK) &&
      SEQ_LE(pkt->pf.tcp_rx.end_seq, tcp_rcv_nxt(ts)) &&
      SEQ_LT(rxp->seq, pkt->pf.tcp_rx.end_seq) ) {
    /* This is data we've already received; so DSACK it. */
    ts->dsack_start = rxp->seq;
    ts->dsack_end = pkt->pf.tcp_rx.end_seq;
    ts->dsack_block = OO_PP_NULL;
  }
  handle_unacceptable_seq(netif, ts, rxp);
  return;

 unacceptable_paws:
  /* For SYN in TIME-WAIT the standard PAWS check is the opposite of
   * what we want, so ignore normal failure, and we'll do the special
   * SYN-IN-TIME-WAIT PAWS check later */
  if( ts->s.b.state == CI_TCP_TIME_WAIT &&
      (tcp->tcp_flags & (CI_TCP_FLAG_SYN | CI_TCP_FLAG_ACK))
      == CI_TCP_FLAG_SYN )
    goto not_unacceptable_paws;
  handle_unacceptable_seq(netif, ts, rxp);
  return;

 mem_pressure:
  if( pkt->pf.tcp_rx.pay_len <= 0 )
    /* Process segments without payload, as they'll be freed immediately. */
    goto continue_mem_pressure;
  CITP_STATS_NETIF_INC(netif, memory_pressure_drops);
  ts->tcpflags |= CI_TCPT_FLAG_MEM_DROP;
  ci_tcp_drop_rob(netif, ts);
  goto drop;

 handle_rst:
  handle_rx_rst(ts, netif, rxp);
  return;

 bad_pkt:
  LOG_U(log(LPF "BAD PACKET (short TCP header len %d)",
            (int) CI_TCP_HDR_LEN(tcp)));
  LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt), 64, 0));
  /* Intentional fall through... */
 drop:
  ci_netif_pkt_release_rx(netif, pkt);
  return;
}


static void handle_no_match(ci_netif* ni, ciip_tcp_rx_pkt* rxp)
{
  /* No match, so we may want to reply with a reset.  But note that the
  ** EF1 hardware filter does not do exact matches, so we have to
  ** double check that this packet really was addressed to us at the IP
  ** level.
  */
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  int af = oo_pkt_af(pkt);
  ci_ipx_hdr_t* ip = oo_ipx_hdr(pkt);
  ci_tcp_hdr* tcp = rxp->tcp;
  int reset = 1; /* We send a TCP reset unless we have a good reason
                        not to. See RFC793 p36 */
#if ! CI_CFG_IPV6
  (void)af;
#endif

  if( oo_tcpdump_check_no_match(ni, pkt, pkt->intf_i) ) {
    /* note: metada of the packet might get overwritten below on reply
     * with RST. Nonetheless, payload is left intact and
     * this should pose no problem for tcpdump dump */
    oo_tcpdump_dump_pkt(ni, pkt);
  }

  LOG_TR(
    /* Do not print message in RST case: it is pretty normal for
     * just-dropped connection with some packets inflight. */
    if( !(tcp->tcp_flags & CI_TCP_FLAG_RST) )
        log(LN_FMT "NO MATCH "IPX_FMT":%u->"IPX_FMT":%u "
            "["CI_TCP_FLAGS_FMT"] " "s=%08x a=%08x", LN_PRI_ARGS(ni),
	    IPX_ARG(AF_IP(ipx_hdr_saddr(af, ip))),
	    (unsigned) CI_BSWAP_BE16(tcp->tcp_source_be16),
	    IPX_ARG(AF_IP(ipx_hdr_daddr(af, ip))),
	    (unsigned) CI_BSWAP_BE16(tcp->tcp_dest_be16),
	    CI_TCP_HDR_FLAGS_PRI_ARG(tcp),
	    SEQ(rxp->seq), SEQ(rxp->ack))
        );

  /*! \TODO: The following two calls to cicp_user_is_local_addr() could be
   *         merged into a one. If this code is run in U/L context each call
   *         results in a system call.
   */
  
  if( ! cicp_user_is_local_addr(ni->cplane, ipx_hdr_daddr(af, ip)) ) {
    /* The EF1 hardware filter only checks (remote ip, remote port, local
    ** port) matches; it is possible that a correct packet for another flow
    ** matches, so discard it (bug 1119).
    */
    LOG_U(log(LN_FMT "Non-local dest IP, ignored.  Prob wrong switch port.",
    	      LN_PRI_ARGS(ni)));
    reset = 0;
  }
  else if( cicp_user_is_local_addr(ni->cplane, ipx_hdr_saddr(af, ip)) ) {
    /* Either someone is lying, or packets are somehow making their way
    ** back to us.  Either way, the proper route for packets to us from us
    ** is via loopback, so just drop this.
    **
    ** NB. Could be Bug1730: LAND attack if saddr==daddr.
    */
    LOG_U(ci_log("STRANGE: Received TCP pkt from local addr"));
    reset = 0;
  }
  else { 

    if( tcp->tcp_flags & CI_TCP_FLAG_RST )
      /* Don't reply to a reset with a reset (See RFC793 p36) */
      reset = 0;
  }

  if( reset ) {
    pkt->pf.tcp_rx.pay_len -= CI_TCP_HDR_LEN(tcp);
    pkt->pf.tcp_rx.end_seq = rxp->seq + pkt->pf.tcp_rx.pay_len;
    pkt->pf.tcp_rx.end_seq +=
      (tcp->tcp_flags & CI_TCP_FLAG_SYN) >> CI_TCP_FLAG_SYN_BIT;
    CITP_STATS_NETIF_INC(ni, rst_sent_no_match);
    /* We have no matching socket, so we have no sock_cp to pass here.  The
     * only case where we actually need a sock_cp is when our local address is
     * being NAT-ed.  In that case we'll to send the RST if we can't find a
     * route over which to send it, but the same is true for the kernel. */
    ci_tcp_reply_with_rst(ni, NULL, rxp);
  }
  else
    ci_netif_pkt_release_rx_1ref(ni, pkt);
}


int ci_tcp_rx_deliver_to_conn(ci_sock_cmn* s, void* opaque_arg)
{
  ciip_tcp_rx_pkt* rxp = opaque_arg;
  ci_tcp_state* ts = SOCK_TO_TCP(s);
  ci_ip_pkt_fmt* pkt = rxp->pkt;
  ci_tcp_hdr* tcp = rxp->tcp;
  ci_netif* ni = rxp->ni;
  int not_fast;

  CHECK_TS(ni, ts);

  ci_assert(CI_IPX_ADDR_EQ(RX_PKT_DADDR(pkt),
                             ipcache_laddr(&s->pkt)));
#ifndef NDEBUG
  if( NI_OPTS(ni).tcp_rx_checks )
    ci_tcp_rx_checks(ni, ts, pkt);
#endif

  /* When we're done polling, we'll have a look at this socket to see if we
   * need to do any wakeups etc.
   */
  ci_netif_put_on_post_poll(ni, &ts->s.b);

  CI_IP_SOCK_STATS_ADD_RXBYTE( ts, pkt->pf.tcp_rx.pay_len );
  ++ts->stats.rx_pkts;

  LOG_TR(log(LNTS_FMT RCV_WND_FMT " snd=%08x-%08x-%08x",
             LNTS_PRI_ARGS(ni, ts), RCV_WND_ARGS(ts),
             tcp_snd_una(ts), tcp_snd_nxt(ts), ts->snd_max);
         log(LNT_FMT "["CI_TCP_FLAGS_FMT"] id=%d s=%08x-%08x a=%08x "
             "w=%u(%u) hlen=%d paylen=%d", LNT_PRI_ARGS(ni, ts),
             CI_TCP_HDR_FLAGS_PRI_ARG(tcp), OO_PKT_FMT(pkt), rxp->seq,
             rxp->seq + pkt->pf.tcp_rx.pay_len - CI_TCP_HDR_LEN(tcp),
             rxp->ack,
             (unsigned)(CI_BSWAP_BE16(tcp->tcp_window_be16)),
             ci_tcp_wnd_from_hdr(tcp, ts->snd_wscl),
             CI_TCP_HDR_LEN(tcp),
             pkt->pf.tcp_rx.pay_len - CI_TCP_HDR_LEN(tcp)));

  { /* Parse the options.  For the fastest path we expect to see a
     * timestamp option, and we expect it to be aligned in the obvious way.
     * Otherwise we call the full option parser (even if no options).
     */
    ci_uint8* opt = CI_TCP_HDR_OPTS(tcp);
    if( tcp->tcp_hdr_len_sl4 == (sizeof(ci_tcp_hdr) + 12u) << 2u &&
        *(ci_uint32*) opt == CI_TCP_TSO_WORD ) {
      rxp->timestamp = CI_BSWAP_BE32(*(ci_uint32*) &opt[4]);
      rxp->timestamp_echo = CI_BSWAP_BE32(*(ci_uint32*) &opt[8]);
      rxp->flags = CI_TCPT_FLAG_TSO;
    }
    else
      ci_tcp_parse_options(ni, rxp, NULL);
  }

  /* These calculations assume the fast path.  We'll fix them up later if
   * we can't use the fast path.
   */
  pkt->pf.tcp_rx.pay_len -= ts->incoming_tcp_hdr_len;
  pkt->pf.tcp_rx.end_seq = rxp->seq + pkt->pf.tcp_rx.pay_len;

#if CI_CFG_BURST_CONTROL
  ts->burst_window = 0;
#endif

  /* Test whether we can use the fast path.  Fast path currently only
   * handles in-order receives.  Possibly also want a transmitter fast path
   * that handles acceptable acks.
   */
  not_fast = (/* flags and header length as expected, and in a state in
               * which we can execute the fast path? */
              ((CI_TCP_FAST_PATH_WORD(tcp) & CI_TCP_FAST_PATH_MASK)
               - ts->fast_path_check) |
              /* seq no. in-order? */
              (rxp->seq - tcp_rcv_nxt(ts)) |
              /* data within receive window? */
              SEQ_LT(tcp_rcv_wnd_right_edge_sent(ts),
                     pkt->pf.tcp_rx.end_seq) |
              /* nothing new ACKed? */
              (tcp_snd_una(ts) - rxp->ack) |
              /* fits in the IP datagram and has data? */
              (pkt->pf.tcp_rx.pay_len <= 0) |
              /* we're suffering from memory pressure */
              (ni->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL) |
              /* some recycling is needed */
              (ci_tcp_is_pluginized(ts) &&
               ! ci_tcp_plugin_elided_payload(pkt)));

  /* All DSACKs should be cleared when ACK is sent;
   * dsack_block may be != CI_ILL_UNUSED only when duplicate packet is
   * processed now.
   *
   * NB strictly speaking, this assertion is not true.  It may happen that
   * we failed to send ACK because we are out of packets.
   */
  ci_ss_assert_or(ni, ts->s.b.state == CI_TCP_LISTEN,
                  OO_PP_EQ(ts->dsack_block, OO_PP_INVALID));

  if( not_fast == 0 ) {

    /* Record this time so we can tell if the keepalive timer has expired
     * prematurely.
     */
    ts->t_last_recv_payload = ci_tcp_time_now(ni);

    /* Fast receiver path.  Packet contains in-order data, no unexpected
     * flags, and doesn't ack any new data.  Also, we've not got any
     * out-of-order segments, and we're in a state that can receive data.
     */
    ci_assert(ts->s.b.state & CI_TCP_STATE_ACCEPT_DATA);
    ci_assert(ci_ip_queue_is_empty(&ts->rob));

    pkt->pf.tcp_rx.window =
      (unsigned) CI_BSWAP_BE16(tcp->tcp_window_be16) << ts->snd_wscl;

    if( ts->tcpflags & rxp->flags & CI_TCPT_FLAG_TSO ) {
      /* Packet has timestamp option, and this socket is using it.  We
       * choose not to care if there is a mismatch between the socket flags
       * and what's in the packet (on the fast path at least).
       */
#if CI_CFG_TCP_PAWS_ON_FASTPATH
      if(CI_UNLIKELY( TIME_GT(ts->tsrecent, rxp->timestamp) ))
        goto paws_fail_on_fast_path;
#endif
      ci_tcp_tso_update(ni, ts, rxp->seq,
                        pkt->pf.tcp_rx.end_seq, rxp->timestamp);
      /* When we change fast path to include segments that ack new data,
       * we'll need to enable this:
       */
      /*if( SEQ_LT(tcp_snd_una(ts), rxp->ack) )
          ci_tcp_update_rtt(ni, ts, (ci_tcp_time_now(ni) -
                            rxp->timestamp[1]));*/
    }

#if CI_CFG_NOTICE_WINDOW_SHRINKAGE
    /* No need to do ci_tcp_rx_try_snd_wnd_inflate() on fast path - we
     * know the payload is in order so just update the window directly 
     */
    ci_tcp_set_snd_max(ts, rxp->seq, rxp->ack, pkt->pf.tcp_rx.window);
#else
    if( SEQ_LT(ts->snd_max, rxp->ack + pkt->pf.tcp_rx.window) )
      ci_tcp_set_snd_max(ts, rxp->seq, rxp->ack, pkt->pf.tcp_rx.window);
#endif

    TCP_NEED_ACK(ts);
    ts->s.b.sb_flags |= CI_SB_FLAG_TCP_POST_POLL;
    ci_tcp_wake(ni, ts, CI_SB_FLAG_WAKE_RX);

    oo_offbuf_init(&pkt->buf, (char*) tcp + ts->incoming_tcp_hdr_len,
                   pkt->pf.tcp_rx.pay_len);
    ci_tcp_rx_enqueue_packet(ni, ts, pkt);

    rxp->pkt = NULL;

    return 1;  /* finished -- don't deliver to any other socket */
  }

  handle_rx_slow(ts, ni, rxp);
  rxp->pkt = NULL;
  return 1;  /* finished -- don't deliver to any other socket */

#if CI_CFG_TCP_PAWS_ON_FASTPATH
 paws_fail_on_fast_path:
  LOG_U(log(LPF "%d PAWS failed (fast) tsval=%x tsrecent=%x", S_FMT(ts),
            rxp->timestamp, ts->tsrecent));
  handle_unacceptable_seq(ni, ts, rxp);
  rxp->pkt = NULL;
  return 1;  /* finished -- don't deliver to any other socket */
#endif
}


static int ci_tcp_rx_deliver_to_listen(ci_sock_cmn* s, void* opaque_arg)
{
  ciip_tcp_rx_pkt* rxp = opaque_arg;

  if( s->b.state == CI_TCP_STATE_ACTIVE_WILD ) {
    /* do not inject into kernel, but handle inside Onload */
    handle_no_match(rxp->ni, rxp);
    CITP_STATS_NETIF_INC(rxp->ni, no_match_in_active_wild);
    rxp->pkt = NULL;
    return 1;
  }

  handle_rx_listen(rxp->ni, SOCK_TO_TCP_LISTEN(s), rxp, 0);
  rxp->pkt = NULL;
  CITP_STATS_TCP_LISTEN(++SOCK_TO_TCP_LISTEN(s)->stats.n_rx_pkts);
  return 1;  /* finished -- don't deliver to any other socket */
}


void ci_tcp_handle_rx(ci_netif* netif, struct ci_netif_poll_state* ps,
                      ci_ip_pkt_fmt* pkt, ci_tcp_hdr* tcp, int ip_paylen)
{
  ci_ip4_hdr* ip4 = oo_ip_hdr(pkt);
  ciip_tcp_rx_pkt rxp;
  ci_addr_t daddr, saddr;

  ci_assert(netif);
  ASSERT_VALID_PKT(netif, pkt);
  ci_ss_assert_eq(netif, RX_PKT_PROTOCOL(pkt), IPPROTO_TCP);

  CI_TCP_STATS_INC_IN_SEGS( netif );

  /* IPv4 TCP MUST use the DF flags, but some TCP implementations don't.
   * We accept both, but we do not accept fragmented packets. */
  if( oo_pkt_af(pkt) == AF_INET &&
      ip4->ip_frag_off_be16 != CI_IP4_FRAG_DONT &&
      ip4->ip_frag_off_be16 != 0 )
    goto scattered;

  if( OO_PP_NOT_NULL(pkt->frag_next) )
    goto scattered;

  rxp.ni = netif;
  rxp.poll_state = ps;
  rxp.pkt = pkt;
  rxp.tcp = tcp;
  if( pkt->q_id != CI_Q_ID_TCP_RECYCLER || ! ci_tcp_plugin_elided_payload(pkt) )
    ci_assert_gt(pkt->pay_len, ip_paylen);
  pkt->pf.tcp_rx.pay_len = ip_paylen;

  rxp.seq = CI_BSWAP_BE32(tcp->tcp_seq_be32);
  rxp.ack = CI_BSWAP_BE32(tcp->tcp_ack_be32);

  daddr = RX_PKT_DADDR(pkt);
  saddr = RX_PKT_SADDR(pkt);

  if( pkt->intf_i == OO_INTF_I_LOOPBACK ) {
    ci_sock_cmn *s = ID_TO_SOCK_CMN(netif, pkt->pf.tcp_rx.lo.rx_sock);
    ci_sock_cmn *sender = ID_TO_SOCK_CMN(netif, pkt->pf.tcp_rx.lo.tx_sock);
    int bad_recipient = (s == NULL) ||
        (~s->b.state & CI_TCP_STATE_TCP) ||
        (tcp->tcp_dest_be16 != S_IPX_TCP_HDR(s)->tcp_source_be16);
    ci_addr_t cache_daddr = ipcache_raddr(&s->pkt);
    /* s->laddr is faster than ipcache_laddr(), so we use it */
    ci_addr_t cache_saddr = s->laddr;

    /* Fast path: these sockets are connected */
    if( !bad_recipient && sender != NULL &&
        (sender->b.state & CI_TCP_STATE_TCP) &&
        sender->b.state != CI_TCP_LISTEN &&
        SOCK_TO_TCP(sender)->local_peer == pkt->pf.tcp_rx.lo.rx_sock &&
        s->b.state != CI_TCP_LISTEN &&
        SOCK_TO_TCP(s)->local_peer == pkt->pf.tcp_rx.lo.tx_sock ) {
      ci_tcp_rx_deliver_to_conn(s, &rxp);
      return;
    }

    if( !bad_recipient && tcp->tcp_dest_be16 != S_IPX_TCP_HDR(s)->tcp_source_be16 )
      bad_recipient = 1;

    if( !bad_recipient && s->b.state == CI_TCP_LISTEN &&
        ( CI_IPX_ADDR_IS_ANY(cache_saddr) ||
          CI_IPX_ADDR_EQ(cache_saddr, daddr) )) {
      ci_assert( ((tcp->tcp_flags & CI_TCP_FLAG_SYN) &&
                  ! (tcp->tcp_flags & CI_TCP_FLAG_ACK)) ||
                 (! (tcp->tcp_flags & CI_TCP_FLAG_SYN) &&
                  (tcp->tcp_flags & CI_TCP_FLAG_ACK) &&
                  (SOCK_TO_TCP(sender)->tcpflags &
                   CI_TCPT_FLAG_LOOP_DEFERRED)) );
      /* SYN to listening socket or data with TCP_DEFER_ACCEPT */
      rxp.hash = ci_netif_filter_hash(netif,
                                      daddr, tcp->tcp_dest_be16,
                                      saddr, tcp->tcp_source_be16,
                                      IPPROTO_TCP);
      ci_tcp_rx_deliver_to_listen(s, &rxp);
    }
    else if( !bad_recipient && s->b.state & CI_TCP_STATE_TCP_CONN &&
            CI_IPX_ADDR_EQ(daddr, cache_saddr) &&
            CI_IPX_ADDR_EQ(saddr, cache_daddr) &&
            tcp->tcp_source_be16 == S_IPX_TCP_HDR(s)->tcp_dest_be16) {
      /* FIN from now-dead socket or SINACK */
      ci_assert( (tcp->tcp_flags & (CI_TCP_FLAG_FIN | CI_TCP_FLAG_RST)) ||
                 ( (tcp->tcp_flags & CI_TCP_FLAG_SYN) &&
                   (tcp->tcp_flags & CI_TCP_FLAG_ACK) ) );
      ci_tcp_rx_deliver_to_conn(s, &rxp);
    }
    else {
      ci_log(FN_FMT "loopback packet to destroyed socket: %d -> %d",
             FN_PRI_ARGS(netif), pkt->pf.tcp_rx.lo.tx_sock,
             pkt->pf.tcp_rx.lo.rx_sock);
      if( (sender->b.state & CI_TCP_STATE_TCP_CONN) &&
          sender->b.state != CI_TCP_TIME_WAIT &&
          CI_IPX_ADDR_EQ(daddr, cache_daddr) &&
          CI_IPX_ADDR_EQ(saddr, cache_saddr) &&
          tcp->tcp_source_be16 == S_IPX_TCP_HDR(sender)->tcp_source_be16 &&
          tcp->tcp_dest_be16 == S_IPX_TCP_HDR(sender)->tcp_dest_be16 )
        ci_tcp_drop(netif, SOCK_TO_TCP(sender), ECONNRESET);
      ci_netif_pkt_release(netif, pkt);
      return;
    }
    return;
  }

#if CI_CFG_TCP_OFFLOAD_RECYCLER
  if( pkt->q_id == CI_Q_ID_TCP_RECYCLER ) {
    int ep_id = pkt->pf.tcp_rx.lo.rx_sock & 0x7fffffff;
    ci_sock_cmn* s = ID_TO_SOCK(netif, ep_id);
    /* We might transform this same packet and send it out as an ACK or
     * something, so prepare for that eventuality: */
    pkt->q_id = CI_Q_ID_NORMAL;
    /* Only a broken/buggy plugin or a race at socket close can cause this to
     * fail: */
    if(CI_LIKELY( s->b.state & CI_TCP_STATE_TCP_CONN &&
                  sock_rport_be16(s) == tcp->tcp_source_be16 &&
                  sock_lport_be16(s) == tcp->tcp_dest_be16 &&
                  CI_IPX_ADDR_EQ(sock_ipx_raddr(s), saddr) &&
                  CI_IPX_ADDR_EQ(sock_ipx_laddr(s), daddr) )) {
      if( ci_tcp_plugin_elided_payload(pkt) ) {
        /* Hack around with the payload size to undo the plugin's removal of
         * it. The actual payload contents we have in memory are drivel, of
         * course. */
        char *payload = (char*)tcp + CI_TCP_HDR_LEN(tcp);
        uint16_t pay_len = *(uint16_t*)payload;
        pkt->pf.tcp_rx.pay_len = CI_TCP_HDR_LEN(tcp) + pay_len;
      }
      ci_tcp_rx_deliver_to_conn(s, &rxp);
      return;
    }
    handle_no_match(netif, &rxp);
    return;
  }
#endif

#if CI_CFG_IPV6
  if( oo_pkt_af(pkt) == AF_INET6 ) {
    ci_netif_filter_for_each_match_ip6(netif,
                                       &daddr, tcp->tcp_dest_be16,
                                       &saddr, tcp->tcp_source_be16,
                                       IPPROTO_TCP, pkt->intf_i, pkt->vlan,
                                       ci_tcp_rx_deliver_to_conn, &rxp,
                                       &rxp.hash);
    if(CI_LIKELY( rxp.pkt == NULL ))
      return;

    ci_netif_filter_for_each_match_ip6(netif,
                                       &daddr, tcp->tcp_dest_be16,
                                       NULL, 0, IPPROTO_TCP, pkt->intf_i,
                                       pkt->vlan, ci_tcp_rx_deliver_to_listen,
                                       &rxp, NULL);
    if(CI_LIKELY( rxp.pkt == NULL ))
      return;

    ci_netif_filter_for_each_match_ip6(netif,
                                       &addr_any, tcp->tcp_dest_be16,
                                       NULL, 0, IPPROTO_TCP, pkt->intf_i,
                                       pkt->vlan, ci_tcp_rx_deliver_to_listen,
                                       &rxp, NULL);
    if(CI_LIKELY( rxp.pkt == NULL ))
      return;
  }
  else
#endif
  {
    ci_netif_filter_for_each_match(netif,
                                   ip4->ip_daddr_be32, tcp->tcp_dest_be16,
                                   ip4->ip_saddr_be32, tcp->tcp_source_be16,
                                   IPPROTO_TCP, pkt->intf_i, pkt->vlan,
                                   ci_tcp_rx_deliver_to_conn, &rxp,
                                   &rxp.hash);
    if(CI_LIKELY( rxp.pkt == NULL ))
      return;

    ci_netif_filter_for_each_match(netif,
                                   ip4->ip_daddr_be32, tcp->tcp_dest_be16,
                                   0, 0, IPPROTO_TCP, pkt->intf_i, pkt->vlan,
                                   ci_tcp_rx_deliver_to_listen, &rxp, NULL);
    if(CI_LIKELY( rxp.pkt == NULL ))
      return;

    ci_netif_filter_for_each_match(netif,
                                   0, tcp->tcp_dest_be16,
                                   0, 0, IPPROTO_TCP, pkt->intf_i, pkt->vlan,
                                   ci_tcp_rx_deliver_to_listen, &rxp, NULL);
    if(CI_LIKELY( rxp.pkt == NULL ))
      return;
  }

  if( ci_netif_pkt_pass_to_kernel(netif, pkt) ) {
    CITP_STATS_NETIF_INC(netif, no_match_pass_to_kernel_tcp);
    return;
  }

  handle_no_match(netif, &rxp);
  return;

 scattered:
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  ci_assert_le(pkt->q_id, CI_Q_ID_TCP_RECYCLER);
  if( pkt->q_id != CI_Q_ID_NORMAL && ci_tcp_plugin_elided_payload(pkt) ) {
    /* This packet isn't formatted normally, so we mustn't pass it to the
     * kernel. This essentially can't happen, because the plugin is going to
     * remove all the payload when it sets the user_flag so the only way we
     * could get here is with a super-small PKT_BUF_SIZE. */
    LOG_E(ci_log(FN_FMT "plugin scattered or fragmented packet dropped"
                 "(ep %d, seq %08x, %d IP bytes),", FN_PRI_ARGS(netif),
                 pkt->pf.tcp_rx.lo.rx_sock, CI_BSWAP_BE32(tcp->tcp_seq_be32),
                 ip_paylen));
    ci_netif_pkt_release_rx_1ref(netif, pkt);
    return;
  }
#endif
  if( ci_netif_pkt_pass_to_kernel(netif, pkt) ) {
    CITP_STATS_NETIF_INC(netif, no_match_pass_to_kernel_tcp);
    return;
  }
  LOG_E(ci_log(FN_FMT "scattered or fragmented packet dropped"
               "(seq %08x, %d IP bytes),", FN_PRI_ARGS(netif), 
               CI_BSWAP_BE32(tcp->tcp_seq_be32), ip_paylen));
  ci_netif_pkt_release_rx_1ref(netif, pkt);
}


#if CI_CFG_TCP_OFFLOAD_RECYCLER
/* Returns the number of real bytes which were actually on the wire in a Ceph
 * packet. It's unfortunate that we need to do this (since we're going to do
 * the same parsing again in recv()), but fortunate that it'll frequently be
 * the case that this only touches a small number of cache lines. An
 * alternative design would be to make the plugin pass this sum in the
 * user_mark, but that's a bit sneaky too. We can't get away with putting the
 * wrong value in to rcv_added because it ultimately ends up in window size
 * calculations and suchlike. */
static int get_actual_ceph_bytes(ci_ip_pkt_fmt* pkt)
{
  int n = oo_offbuf_left(&pkt->buf);
  char* p = oo_offbuf_ptr(&pkt->buf);
  int bytes = 0;

  while( n ) {
    const int hdr_len = CI_MEMBER_OFFSET(struct ceph_data_pkt, data);
    struct ceph_data_pkt data;

    if( n < hdr_len )
      goto unrecoverable;

    memcpy(&data, p, hdr_len);
    n -= hdr_len;
    p += hdr_len;
    switch( data.msg_type ) {
    case XSN_CEPH_DATA_INLINE:
      if( n < data.msg_len )
        goto unrecoverable;
      bytes += data.msg_len;
      break;

    case XSN_CEPH_DATA_REMOTE:
      if( n < sizeof(data.remote) || data.msg_len != sizeof(data.remote) )
        goto unrecoverable;
      memcpy(&data.remote, p, sizeof(data.remote));
      bytes += data.remote.data_len;
      break;

    case XSN_CEPH_DATA_LOST_SYNC:
      /* recv() is going to give up at this point, so we can do too */
      break;

    default:
      goto unrecoverable;
    }

    n -= data.msg_len;
    p += data.msg_len;
  }

  return bytes;

 unrecoverable:
  LOG_TR(log("bogus plugin metastream - see later logging from recv()"));
  return bytes;
}
#endif


void ci_tcp_rx_plugin_meta(ci_netif* netif, struct ci_netif_poll_state* ps,
                           ci_ip_pkt_fmt* pkt)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  int ep_id = pkt->pf.tcp_rx.lo.rx_sock;
  ci_tcp_state* ts = ID_TO_TCP(netif, ep_id);
  if( ts->s.b.state != CI_TCP_ESTABLISHED || ! ci_tcp_is_pluginized(ts) ) {
    ci_netif_pkt_release_rx_1ref(netif, pkt);
    return;
  }
  /* For Ceph, we enqueue the whole thing in to the socket recvq, mini-headers
   * and all. The alternative would be to try to break it up here, but that's
   * tricky because we could switch between zc and non-zc arbitrarily and the
   * recv path needs to be able to cope with that kind of thing anyway. */

  ci_assert(oo_offbuf_not_empty(&pkt->buf));  /* broken plugin */
  ci_tcp_rx_add_to_recvq(netif, ts, pkt, get_actual_ceph_bytes(pkt));
  ci_tcp_wake(netif, ts, CI_SB_FLAG_WAKE_RX);
#endif
}

#endif

/*! \cidoxg_end */
