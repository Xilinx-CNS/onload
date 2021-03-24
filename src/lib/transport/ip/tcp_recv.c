/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  TCP recvmsg() etc.
**   \date  2003/09/02
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/ip_timestamp.h>
#include <onload/sleep.h>
#include <onload/tcp-ceph.h>
#ifndef __KERNEL__
#include <onload/extensions_zc.h>
#include <stddef.h>
#endif


#if OO_DO_STACK_POLL
#define LPF "TCP RECV "

struct tcp_recv_info;
typedef int (*pkt_copy_t)(ci_netif* netif, struct tcp_recv_info* rinf,
                          ci_ip_pkt_fmt* pkt, int peek_off, int* rc);

struct tcp_recv_info {
  int rc;
  int stack_locked;
  ci_iovec_ptr piov;
  const ci_tcp_recvmsg_args* a;
  pkt_copy_t copier;
  int msg_flags;
  struct onload_zc_recv_args* zc_args;
  size_t controllen;
};

#ifndef __KERNEL__
static int ci_tcp_recvmsg_urg(struct tcp_recv_info *rinf);
#endif

static int ci_tcp_recvmsg_recv2(struct tcp_recv_info *rinf);


static bool iovec_roll_over(ci_iovec_ptr* piov)
{
  if( CI_IOVEC_LEN(&piov->io) == 0 ) {
    if( piov->iovlen == 0 )
      return false;
    piov->io = *piov->iov++;
    --piov->iovlen;
  }
  return true;
}


/*
 * \todo It looks like it's common with getpeername().
 */
ci_inline void
ci_tcp_recv_fill_msgname(ci_tcp_state* ts, struct sockaddr *name,
                         socklen_t *namelen)
{
#if CI_CFG_TCP_RECVMSG_MSGNAME
  if( name ) {
    struct sockaddr_in* sinp;
    struct sockaddr_in  sin_buf;

    ci_assert(ts);
    ci_assert(namelen);

    if( CI_LIKELY(*namelen >= sizeof(struct sockaddr_in)) ) {
      sinp = (struct sockaddr_in *)name;
      sinp->sin_family = AF_INET;
      sinp->sin_port = TS_IPX_TCP(ts)->tcp_dest_be16;
      sinp->sin_addr.s_addr = ts->s.pkt.ip.ip_daddr_be32;
      *namelen = sizeof(struct sockaddr_in);
    }
    else {
      sin_buf.sin_family = AF_INET;
      sin_buf.sin_port = TS_IPX_TCP(ts)->tcp_dest_be16;
      sin_buf.sin_addr.s_addr = ts->s.pkt.ip.ip_daddr_be32;
      memcpy(name, &sin_buf, *namelen);
    }
  }
#else
  *namelen = 0;
#endif
}


/* This is called after we've pulled a certain amount of data from the
** receive queue, and sends a window update if appropriate.
*/
static void ci_tcp_recvmsg_send_wnd_update(ci_netif* ni, ci_tcp_state* ts)
{
  if( ! ci_netif_trylock(ni) ) {
    ci_bit_set(&ts->s.s_aflags, CI_SOCK_AFLAG_NEED_ACK_BIT);
    if( ! ci_netif_lock_or_defer_work(ni, &ts->s.b) )
      return;
    ci_bit_clear(&ts->s.s_aflags, CI_SOCK_AFLAG_NEED_ACK_BIT);
  }

  CHECK_TS(ni, ts);

  LOG_TR(log(LNTS_FMT "ack_trigger=%x c/w rcv_delivered=%x "
             "rcv_added=%u buff=%u wnd_rhs=%x current=%u",
             LNTS_PRI_ARGS(ni, ts), ts->ack_trigger, ts->rcv_delivered,
             ts->rcv_added, ts->rcv_window_max,
             tcp_rcv_wnd_right_edge_sent(ts),
             tcp_rcv_wnd_current(ts)));

  if( ts->s.b.state & CI_TCP_STATE_NOT_CONNECTED )  goto out;

  /* Free-up some receive buffers now we have the netif lock. */
  ci_tcp_rx_reap_rxq_bufs(ni, ts);

  /* RFC1122 silly window avoidance requires that we do not send window
  ** updates of less than an MSS.
  **
  ** The reason we're here is because we think the window should have grown
  ** sufficiently that an update is needed.  However, because the recv code
  ** is asynchronous, the window could have closed down again, so we do
  ** have to check we're not about to advertise a silly window.  We
  ** actually check that the right edge has moved by at least
  ** ci_tcp_ack_trigger_delta() since we last advertised a window.
  */
  if( ! ci_tcp_send_wnd_update(ni, ts, CI_TRUE) )
    /* Reset [ack_trigger] so it'll fire when we would advertise a window
    ** which is at least tcp_rcv_wnd_advertised() + delta.
    */
    ts->ack_trigger = ts->rcv_delivered
      + ci_tcp_ack_trigger_delta(ts)
      - SEQ_SUB(ts->rcv_delivered + ts->rcv_window_max,
                tcp_rcv_wnd_right_edge_sent(ts));

 out:
  CHECK_TS(ni, ts);

  ci_netif_unlock(ni);
}

/* This function calculates the appropriate TCP receive buffer space
 * using Dynamic Right Sizing. It should be called whenever data is copied
 * to the application.
 */
void ci_tcp_rcvbuf_drs(ci_netif* netif, ci_tcp_state* ts)
{
  ci_iptime_t time;
  ci_uint32 rcv_bytes;

  /* Set an upper ceiling on rcvbuf for a single socket.
   * In general, DRS will pick a smaller size than this, based on how much
   * data the socket is transfering each RTT.
   * Useful to make this fairly big so that a stack with a single socket can 
   * achieve good throughput. If we find that resource contention with many
   * sockets is a problem can adjust via EF_TCP_SOCKBUF_MAX_FRACTION.
   * If neceesary, could implement a fairness algorithm to control access to
   * the buffers (similar to flow WFQ). But general advice would be to make
   * sufficient packet buffers available (e.g. at least sum of Bandwidth Delay
   * Products * 4) */
  int max_rcvbuf_packets =
    NI_OPTS(netif).max_rx_packets >> NI_OPTS(netif).tcp_sockbuf_max_fraction;

  time = ci_tcp_time_now(netif) - ts->rcvbuf_drs.time;
  if( time < (ts->sa >> 3) || ts->sa == 0 )
    return;

  /* Number of bytes delivered to user in last RTT */
  rcv_bytes = ts->rcv_delivered - ts->rcvbuf_drs.seq;
  if( rcv_bytes <= ts->rcvbuf_drs.bytes )
    goto new_period;

  /* rcv_bytes gives the number of bytes received in the previous RTT.
   * The current RTT worth of data is already in flight and so we need
   * to size the buffer (to advertise in the next ACK) for the following RTT:
   * [prev RTT][current RTT][following RTT]
   */

  if( ! (ts->s.s_flags & CI_SOCK_FLAG_SET_SNDBUF) ) {
    int rcv_wnd, rcvbuf;

    /* at least 2x factor to cope with packet loss, plus small extra cushion */
    rcv_wnd = (rcv_bytes << 1) + 16 * ts->amss;

    if( rcv_bytes >= ts->rcvbuf_drs.bytes + (ts->rcvbuf_drs.bytes >> 2) ) {
      /* traffic grew, but by how much ? */
      if (rcv_bytes >= ts->rcvbuf_drs.bytes + (ts->rcvbuf_drs.bytes >> 1))
	/* looks like 2x growth per RTT so we need rcv_win > 4 * rcv_bytes */
	rcv_wnd <<= 1;
      else
	/* looks like slow start, so want rcv_win > 3 * rcv_bytes */
	rcv_wnd += (rcv_wnd >> 1);
    }

    rcvbuf = CI_MIN(rcv_wnd, (ci_uint64)max_rcvbuf_packets * ts->amss);

    if( rcvbuf > ts->s.so.rcvbuf ) {
      ts->s.so.rcvbuf = rcvbuf;
      ci_tcp_set_rcvbuf(netif, ts);
      /* Window will be calculated from this new value.  */
    }
  }
  ts->rcvbuf_drs.bytes = rcv_bytes;

 new_period:
  ts->rcvbuf_drs.seq = ts->rcv_delivered;
  ts->rcvbuf_drs.time = ci_tcp_time_now(netif);
}


static inline int /* bool */
ci_tcp_recvmsg_get_nopeek(int peek_off, ci_tcp_state *ts, ci_netif *netif,
                          ci_ip_pkt_fmt **pkt, int total, int n, int max_bytes)
{
  ci_assert(peek_off == 0);
  ts->rcv_delivered += n;
  if( NI_OPTS(netif).tcp_rcvbuf_mode == 1 )
    /* for now run every time we update rcv_delivered */
    ci_tcp_rcvbuf_drs(netif, ts);
  if( oo_offbuf_left(&(*pkt)->buf) == 0 ) {
    if( total == max_bytes || OO_PP_IS_NULL((*pkt)->next) )
      /* We've emptied the receive queue. Return non-zero to report this
       * to the calling function, so that it can return appropriately. */
      return 1;
    ci_assert(OO_PP_EQ(ts->recv1_extract, OO_PKT_P(*pkt)));
    ts->recv1_extract = (*pkt)->next;
    *pkt = PKT_CHK_NNL(netif, ts->recv1_extract);
    ci_assert(oo_offbuf_not_empty(&(*pkt)->buf));
  }
  return 0;
}


#ifndef __KERNEL__
#if CI_CFG_TIMESTAMPING
/* We currently don't need to do any cmsg recvmsg stuff in-kernel
 * as calls are all via recv/read
 */

/* Turn timestamps into the requested cmsg structure(s). */
ci_inline void
ci_tcp_fill_recv_timestamp(struct tcp_recv_info* rinf, ci_ip_pkt_fmt* pkt)
{
  ci_netif* ni = rinf->a->ni;
  ci_tcp_state* ts = rinf->a->ts;
  ci_msghdr* msg = rinf->a->msg;

  if( msg != NULL ) {
    struct cmsg_state cmsg_state;
    if( CI_UNLIKELY( ts->s.cmsg_flags & CI_IP_CMSG_TIMESTAMP_ANY ) ) {
      msg->msg_controllen = rinf->controllen;
      cmsg_state.msg = msg;
      cmsg_state.cmsg_bytes_used = 0;
      cmsg_state.cm = CMSG_FIRSTHDR(msg);
      cmsg_state.p_msg_flags = &rinf->msg_flags;

      if ( ts->s.cmsg_flags & CI_IP_CMSG_TIMESTAMPNS )
        ip_cmsg_recv_timestampns(ni, pkt->tstamp_frc, &cmsg_state);
      else /* CI_IP_CMSG_TIMESTAMP flag gets ignored if NS counterpart is set */
        if( ts->s.cmsg_flags & CI_IP_CMSG_TIMESTAMP )
          ip_cmsg_recv_timestamp(ni, pkt->tstamp_frc, &cmsg_state);

      if( ts->s.cmsg_flags & CI_IP_CMSG_TIMESTAMPING )
        ip_cmsg_recv_timestamping(ni, pkt, ts->s.timestamping_flags,
                                  &cmsg_state);

      msg->msg_controllen = cmsg_state.cmsg_bytes_used;
    }
    else
      msg->msg_controllen = 0;
  }
}
#endif
#endif


#if CI_CFG_TCP_OFFLOAD_RECYCLER && CI_CFG_TCP_PLUGIN_RECV_NONZC
static int offloaded_copy_block(ci_iovec* iov, const void* src, size_t max,
                                int flags, int* rc)
{
  int n = CI_MIN(max, CI_IOVEC_LEN(iov));
  if(CI_LIKELY( ! (flags & MSG_TRUNC) )) {
#ifdef __KERNEL__
    if( copy_to_user(CI_IOVEC_BASE(iov), src, n) )
      return -EFAULT;
#else
    memcpy(CI_IOVEC_BASE(iov), src, n);
#endif
  }
  CI_IOVEC_BASE(iov) = (char*)CI_IOVEC_BASE(iov) + n;
  CI_IOVEC_LEN(iov) -= n;
  *rc += n;
  return n;
}

static int copy_ceph_pkt(ci_netif* netif, struct tcp_recv_info* rinf,
                            ci_ip_pkt_fmt* pkt, int peek_off, int* ndata)
{
  /* This function is essentially entirely bogus, most prominently in the fact
   * that it'll emit zeros for all 'remote' data. It exists primarily so that
   * test tools (e.g. packetdrill) can work on pluginized streams. */
  int total = oo_offbuf_left(&pkt->buf);
  int ofs = 0;
  char* p = oo_offbuf_ptr(&pkt->buf);
  int out_rc = 0;
  static const char zeros[64];

  /* Not currently required, and a little tricky to get right: */
  if( rinf->msg_flags & MSG_PEEK )
    return -EOPNOTSUPP;

  while( ofs != total && CI_IOVEC_LEN(&rinf->piov.io) != 0 ) {
    const int hdr_len = offsetof(struct ceph_data_pkt, data);
    struct ceph_data_pkt data;
    int n;

    if( total - ofs < hdr_len ) {
      LOG_TR(log(LNTS_FMT "bogus plugin metastream ofs=%d total=%d", 
                 LNTS_PRI_ARGS(netif, rinf->a->ts), ofs, total));
      goto unrecoverable;
    }

    memcpy(&data, p + ofs, hdr_len);
    ofs += hdr_len;
    /* NB: if adding a new msg_type here, don't forget that zc_ceph_callback()
     * has a similar switch statement */
    switch( data.msg_type ) {
    case XSN_CEPH_DATA_INLINE:
      if( total - ofs < data.msg_len ) {
        LOG_TR(log(LNTS_FMT "bogus plugin inline len %d-%d<%u", 
                  LNTS_PRI_ARGS(netif, rinf->a->ts), total, ofs,
                  data.msg_len));
        goto unrecoverable;
      }
      n = offloaded_copy_block(&rinf->piov.io, p + ofs, data.msg_len,
                               rinf->a->flags, &out_rc);
      if( n < 0 )
        return -EFAULT;
      if( n != data.msg_len ) {
        /* Stopped in the middle: hack the packet so that we can resume next
         * time. NB: this can potentially make onload_tcpdump output a little
         * odd */
        data.msg_len -= n;
        memcpy(p + ofs + n - hdr_len, &data, hdr_len);
        ofs += n - hdr_len;
        goto out;
      }
      break;

    case XSN_CEPH_DATA_REMOTE:
      if( total - ofs < sizeof(data.remote) ||
          data.msg_len != sizeof(data.remote) ) {
        LOG_TR(log(LNTS_FMT "bogus plugin remote block %d-%d/%u", 
                  LNTS_PRI_ARGS(netif, rinf->a->ts), total, ofs,
                  data.msg_len));
        goto unrecoverable;
      }
      memcpy(&data.remote, p + ofs, sizeof(data.remote));
      while( data.remote.data_len ) {
        n = offloaded_copy_block(&rinf->piov.io, zeros,
                                 CI_MIN(sizeof(zeros), data.remote.data_len),
                                 rinf->a->flags, &out_rc);
        if( n < 0 )
          return -EFAULT;
        data.remote.data_len -= n;
        data.remote.start_ptr += n;
        if( n != sizeof(zeros) ) {
          memcpy(p + ofs, &data.remote, sizeof(data.remote));
          ofs -= hdr_len;
          goto out;
        }
      }
      break;

    case XSN_CEPH_DATA_LOST_SYNC:
      if( total - ofs < sizeof(data.lost_sync) ||
          data.msg_len != sizeof(data.lost_sync) ) {
        LOG_TR(log(LNTS_FMT "bogus plugin lost-sync block %d-%d/%u", 
                  LNTS_PRI_ARGS(netif, rinf->a->ts), total, ofs,
                  data.msg_len));
        goto unrecoverable;
      }
      memcpy(&data.lost_sync, p, sizeof(data.lost_sync));
      log(LNTS_FMT "plugin lost sync: %u/%u", 
          LNTS_PRI_ARGS(netif, rinf->a->ts), data.lost_sync.reason,
          data.lost_sync.subreason);
      /* Set the return value so that we'll keep hitting this same lost-sync
       * message on every receive, and hence block the socket from making
       * further progress */
      ofs -= hdr_len;
      goto out;

    default:
      LOG_TR(log(LNTS_FMT "bogus plugin metastream header %u/%u", 
                 LNTS_PRI_ARGS(netif, rinf->a->ts), data.msg_type,
                 data.msg_len));
      goto unrecoverable;
    }
    ofs += data.msg_len;
  }

 out:
  *ndata = out_rc;
  return ofs;

 unrecoverable:
  /* Return the number of bytes successfully consumed, so that if the user
   * tries again then we'll log the same error again. This is a different
   * decision to the one we made at the identical label in zc_ceph_callback()
   * because this function is only targetted at debugging/testing scenarios,
   * where freezing in place and allowing the user to debug it is likely to be
   * preferable. */
  return total;
}
#endif


static int copy_one_pkt(ci_netif* netif, struct tcp_recv_info* rinf,
                        ci_ip_pkt_fmt* pkt, int peek_off, int* ndata)
{
  int n;

#if CI_CFG_TCP_OFFLOAD_RECYCLER
  if( ci_tcp_is_pluginized(rinf->a->ts) ) {
#if CI_CFG_TCP_PLUGIN_RECV_NONZC
    return copy_ceph_pkt(netif, rinf, pkt, peek_off, ndata);
#else
    return -EOPNOTSUPP;
#endif
  }
#endif

  if(CI_LIKELY( ! (rinf->a->flags & MSG_TRUNC) ))
    n = ci_ip_copy_pkt_to_user(netif, &rinf->piov.io, pkt, peek_off);
  else {
    /* Very strange kernel behaviour: MSG_TRUNC will consume the number
     * of bytes requested, but will not write to the user's pointer in any
     * circumstances. This code does the same. */
    n = CI_MIN(oo_offbuf_left(&pkt->buf) - peek_off, rinf->piov.io.iov_len);
    CI_IOVEC_LEN(&rinf->piov.io) -= n;
  }
  /* NB: on failure of this function (i.e. n<0) the caller doesn't make any
   * assumptions about the validity or otherwise of the output (including the
   * 'out' parameter), so the side-effect of mangling *rc here is fine. */
  *ndata = n;
  return n;
}


/* Copy data from the receive queue to the app's buffer(s).  Returns the
** number of bytes copied.  This function also sends window updates as
** appropriate.
**
** User-level callers must hold the socket lock.  Other, trusted,
** stacks can get away without it as long as they avoid concurrent
** receives (currently assumes use of the netif lock).  Use the flags
** arg and the CI_MSG_*_LOCKED constants to specify which locks are
** already held.
*/
__attribute__((always_inline))
static inline int
ci_tcp_recvmsg_get_impl(struct tcp_recv_info *rinf)
{
  ci_netif* netif = rinf->a->ni;
  ci_tcp_state* ts = rinf->a->ts;
  int n, ndata, peek_off, total, rc;
  ci_ip_pkt_fmt* pkt;
  int max_bytes;
#if CI_CFG_TIMESTAMPING && ! defined(__KERNEL__)
  int fill_tstamp;
#endif
  oo_pkt_p initial_recv1_extract;

  ci_assert(netif);
  ci_assert(ts);

  /* The socket must be locked. */
  ci_assert(ci_sock_is_locked(netif, &ts->s.b));

  peek_off = 0;
  total = 0;
  rc = 0;

  /* Maximum number of bytes we have in both recv1 and recv2.
   * In this function, we get data from recv1 only, so the actual amount
   * of received data may be less than max_bytes. */
  max_bytes = tcp_rcv_usr(ts);

  if( max_bytes <= 0 || OO_PP_IS_NULL(ts->recv1_extract))
    return rc;       /* Receive queue is empty. */

  ci_assert(OO_PP_NOT_NULL(ts->recv1.head));

  pkt = PKT_CHK_NNL(netif, ts->recv1_extract);
  if( oo_offbuf_is_empty(&pkt->buf) ) {
    if( OO_PP_IS_NULL(pkt->next) )  return rc;  /* recv1 is empty. */
    ts->recv1_extract = pkt->next;
    pkt = PKT_CHK_NNL(netif, ts->recv1_extract);
    ci_assert(oo_offbuf_not_empty(&pkt->buf));
  }
  initial_recv1_extract = ts->recv1_extract;

  /* If we carry on here when in error then we'd be ignoring them. */
  ci_assert_ge(rinf->rc, 0);

#if CI_CFG_TIMESTAMPING && ! defined(__KERNEL__)
  /* Intention is to return the timestamp from the first packet seen, when
   * ci_tcp_recvmsg_get could be called multiple times; so only update
   * if zero bytes received so far. */
  fill_tstamp = rinf->rc == 0 || rinf->zc_args;
#endif

  if( rinf->rc > 0 ) {
    /* If we've already got data that we're returning to the app then we
     * shouldn't be trying to add any more to it.
     */
    ci_assert_nflags(rinf->a->flags, ONLOAD_MSG_ONEPKT);
  }

  while( 1 ) {
    PKT_TCP_RX_BUF_ASSERT_VALID(netif, pkt);
    ci_assert(oo_offbuf_not_empty(&pkt->buf));
    ci_assert(oo_offbuf_left(&pkt->buf) > peek_off);

#if CI_CFG_TIMESTAMPING && ! defined(__KERNEL__)
  if( fill_tstamp ) {
    ci_tcp_fill_recv_timestamp(rinf, pkt);
    if( ! rinf->zc_args )
      fill_tstamp = 0;
  }
#endif

    n = rinf->copier(netif, rinf, pkt, peek_off, &ndata);
#ifdef  __KERNEL__
    if( n < 0 )  break;
#endif
    rc += ndata;
    oo_offbuf_advance(&pkt->buf, n);

    total += ndata;
    ci_assert_le(total, max_bytes);

    if(CI_LIKELY( ! (rinf->a->flags & (MSG_PEEK | ONLOAD_MSG_ONEPKT)) )) {
      if( ci_tcp_recvmsg_get_nopeek(peek_off, ts, netif, &pkt, total, ndata,
                                    max_bytes) != 0 )
        break;
    }
    else {
      if( rinf->a->flags & MSG_PEEK ) {
        /* copy did an implicit advance of the offbuf which we do not want */
        oo_offbuf_retard(&pkt->buf, n);

        peek_off += n;
        if( oo_offbuf_left(&pkt->buf) - peek_off == 0 ) {
          /* We've emptied the current packet. */
          if( total == max_bytes || OO_PP_IS_NULL(pkt->next) )
            /* We've emptied the receive queue. */
            return rc;
          pkt = PKT_CHK_NNL(netif, pkt->next);
          peek_off = 0;
          ci_assert(oo_offbuf_not_empty(&pkt->buf));
        }
      }
      else {
        if( ci_tcp_recvmsg_get_nopeek(peek_off, ts, netif, &pkt, total, ndata,
                                      max_bytes) != 0 )
          break;
      }

      if( rinf->a->flags & ONLOAD_MSG_ONEPKT )
        break;
    }

    /* Exit here if we've filled the app's buffer. */
    if( ! iovec_roll_over(&rinf->piov) )
      break;
    /* Yes, [piov->io.iov_len] could be zero here.  Just means we'll waste
    ** time going round the loop an extra time and not copy an data.  This
    ** is harmless.  Doing it this way makes the common case faster, and
    ** saves 3 characters.  Which I've just more than wasted in this
    ** comment; darn.
    */
  }
  /* we do this here as the last thing to avoid sending many small window updates
   * in cases with small recv window and small segments */
  if( initial_recv1_extract != ts->recv1_extract &&
      CI_UNLIKELY(SEQ_LE(ts->ack_trigger, ts->rcv_delivered)) ) {
    ci_tcp_recvmsg_send_wnd_update(netif, ts);
  }
  return total;
}


__attribute__((always_inline))
static inline int
ci_tcp_recvmsg_get_inline(struct tcp_recv_info *rinf)
{
  return ci_tcp_recvmsg_get_impl(rinf);
}


static int
ci_tcp_recvmsg_get_outofline(struct tcp_recv_info *rinf)
{
  return ci_tcp_recvmsg_get_impl(rinf);
}


#ifndef __KERNEL__
/* Returns >0 if socket is readable.  Returns 0 if spin times-out.  Returns
 * -ve error code otherwise.
 */
static int ci_tcp_recvmsg_spin(ci_netif* ni, ci_tcp_state* ts,
                               ci_uint64 start_frc)
{
  ci_uint64 now_frc;
  ci_uint64 schedule_frc = start_frc;
  citp_signal_info* si = citp_signal_get_specific_inited();
  ci_uint64 max_spin = ts->s.b.spin_cycles;
  int rc, spin_limit_by_so = 0;

  /* Cache the next expected packet buffer to save work within the loop.
   * We need to update this after polling. If someone else polls, then this
   * pointer might no longer point to the expected packet. This might lead to
   * missing a packet from the future, but will not cause any functional
   * problems as the packet will be handled correctly in due course.
   *
   * If there is no future packet to poll, then we point to a local location
   * which always contains the "poison" value.
   */
  int intf_i = ts->s.pkt.intf_i;
  const uint32_t poison = CI_PKT_RX_POISON;
  const volatile uint32_t* future = ci_netif_intf_rx_future(ni, intf_i, &poison);

  if( ts->s.so.rcvtimeo_msec ) {
    ci_uint64 max_so_spin = (ci_uint64)ts->s.so.rcvtimeo_msec *
        IPTIMER_STATE(ni)->khz;
    if( max_so_spin <= max_spin ) {
      max_spin = max_so_spin;
      spin_limit_by_so = 1;
    }
  }

  now_frc = start_frc;

  do {
    rc = 1;
    if( ci_netif_may_poll(ni) ) {
      if( *future != CI_PKT_RX_POISON && ci_netif_trylock(ni) ) {
        ci_netif_poll_intf_future(ni, intf_i, now_frc);
        ci_netif_unlock(ni);
        if( tcp_rcv_usr(ts) )
          goto out;
        future = ci_netif_intf_rx_future(ni, intf_i, &poison);
      }

      if( ni->state->poll_work_outstanding ||
          ci_netif_need_poll_spinning(ni, now_frc) ) {
        if( ci_netif_trylock(ni) ) {
          ci_netif_poll(ni);
          ci_netif_unlock(ni);
        }
        if( tcp_rcv_usr(ts) )
          goto out;
        future = ci_netif_intf_rx_future(ni, intf_i, &poison);
      }
      else if( ! ni->state->is_spinner )
        ni->state->is_spinner = 1;
    }
    if( tcp_rcv_usr(ts) || TCP_RX_DONE(ts) )
      goto out;

    ci_frc64(&now_frc);
    rc = OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, &schedule_frc, 
                                         ts->s.so.rcvtimeo_msec, &ts->s.b, si);
    if( rc != 0 )
      goto out;
#if CI_CFG_SPIN_STATS
    ni->state->stats.spin_tcp_recv++;
#endif
  } while( now_frc - start_frc < max_spin );

  rc = spin_limit_by_so ? -EAGAIN : 0;
 out:
  ni->state->is_spinner = 0;
  return rc;
}
#endif


/* This macro returns true if the combination of [flags] and receive
** low-water-mark permit us to return given the amount of data we've
** received already.
**
** We can return if they've not asked to fill their buffer (no MSG_WAITALL)
** provided we've reached the low-water-mark, or if they've specified
** MSG_DONTWAIT or MSG_PEEK.  (On linux at least: MSG_PEEK cancels
** MSG_WAITALL, and MSG_DONTWAIT overrides MSG_WAITALL).
*/
#define FLAGS_AND_LOWAT_PERMIT_FAST_RET_WITH_DATA(ts, bytes, flags)     \
  ((flags & (MSG_DONTWAIT | MSG_PEEK)) ||                               \
   ((~flags & MSG_WAITALL) && (bytes) >= (ts)->s.so.rcvlowat))


__attribute__((always_inline))
static inline int ci_tcp_recvmsg_impl(const ci_tcp_recvmsg_args* a,
                                      pkt_copy_t copier,
                                      struct onload_zc_recv_args* zc_args)
{
  int                   have_polled;
  ci_uint64             sleep_seq;
  ci_tcp_state*         ts = a->ts;
  ci_netif*             ni = a->ni;
  int                   flags = a->flags;
  ci_uint64             start_frc = 0; /* suppress compiler warning */
#ifndef __KERNEL__
  unsigned              tcp_recv_spin = 0;
#endif
  ci_uint32             timeout = ts->s.so.rcvtimeo_msec;
  struct tcp_recv_info  rinf;

  ci_assert(a);
  ci_assert(ni);
  ci_assert(ts);
  ci_assert(a->msg);

  rinf.stack_locked = 0;
  rinf.a = a;
  rinf.rc = 0;
  rinf.msg_flags = 0;
  rinf.copier = copier;
  rinf.zc_args = zc_args;
#ifdef __KERNEL__
  rinf.controllen = 0;
#else
  rinf.controllen = a->msg->msg_controllen;
  a->msg->msg_controllen = 0;
#endif

  /* Grab the per-socket lock so we can access the receive queue. */
  rinf.rc = ci_sock_lock(ni, &ts->s.b);
  if(CI_UNLIKELY( rinf.rc != 0 ))
    return rinf.rc;

  if( ts->s.b.state == CI_TCP_LISTEN )  goto check_errno;

  have_polled = 0;
  ci_assert_equal(rinf.rc, 0);

#ifndef __KERNEL__
  if( (flags & (MSG_OOB | MSG_ERRQUEUE)) )
    goto slow_path;
#else
  ci_assert_equal(flags & ~MSG_DONTWAIT, 0);
#endif

  if( zc_args ) {
    /* Several other bits of code check these things to determine how much
     * data to copy. It's neater if we fake it to ensure that those checks
     * always see that there's 'infinite' space left, but let's set the
     * pointers to NULL as well, to catch anywhere that might actually try to
     * write anything. */
    rinf.piov.iov = NULL;
    rinf.piov.iovlen = 1;
    rinf.piov.io.iov_len = ~(size_t)0;
    rinf.piov.io.iov_base = NULL;
  }
  else {
    /* [piov] gives keeps track of our position in the apps buffer(s). */
    ci_iovec_ptr_init_nz(&rinf.piov, a->msg->msg_iov, a->msg->msg_iovlen);
  }

  LOG_TR(log(LNTS_FMT "recvmsg len=%d flags=%x bytes_in_rxq=%d", 
             LNTS_PRI_ARGS(ni, ts),
             zc_args ? -1 : ci_iovec_ptr_bytes_count(&rinf.piov),
             flags, tcp_rcv_usr(ts)));

#ifndef __KERNEL__
  tcp_recv_spin = 
    oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_TCP_RECV);
#endif
  ci_frc64(&start_frc);

 poll_recv_queue:
  rinf.rc += ci_tcp_recvmsg_get_inline(&rinf);

  /* Return immediately if we've filled the app's buffer(s).
   * In case of empty buffer, we should wait for socket to be readable.
  */
  if( ci_iovec_ptr_is_empty_proper(&rinf.piov) &&
      ( rinf.rc != 0 || TCP_RX_DONE(ts) || tcp_rcv_usr(ts) ) ) {
    if( CI_UNLIKELY(rinf.rc == 0) )  goto check_errno;
    goto success_unlock_out;
  }

  /* With ONLOAD_MSG_ONEPKT we only return data from one ethernet frame,
   * so if we've got anything at all then we need to return.
   */
  if( (rinf.a->flags & ONLOAD_MSG_ONEPKT) && (rinf.rc > 0) )
    goto success_unlock_out;

  if( ! have_polled ) {
    /* We've not yet filled the app's buffer.  But the receive queue may
    ** not be up-to-date, so we need to check that it is, or bring it
    ** up-to-date ourselves.
    */
    have_polled = 1;

    if( ci_netif_may_poll(ni) && ci_netif_need_poll_spinning(ni, start_frc) ) {
      if( ci_netif_trylock(ni) ) {
        ci_uint32 rcv_added_before = ts->rcv_added;
        int any_evs = ci_netif_poll(ni);
        if( ts->rcv_added != rcv_added_before ) {
          /* We've handled some events, but possibly not all.  So if the
           * events we've handled do not satisfy the request, we need to
           * ensure we come back and poll some more.
           */
          have_polled = 0;
        }
        else if( any_evs )
          ci_netif_poll(ni);
	ci_netif_unlock(ni);
	if( ts->rcv_added != rcv_added_before )
	  goto poll_recv_queue;
      }
      else {
        /* The netif lock is contended, so the chances are we're up-to-date.
        ** Even if we're not, at least we will be soon.  So we pretend we are
        ** up-to-date, and continue...
        */
      }
    }
  }

  /* We haven't filled the app's buffer, but recv2 might contain more data
  ** before the mark.
  */
  /* \todo For MSG_PEEK, we always will re-copy all data if we did not
   * filled user buffer. */
  if(CI_UNLIKELY( OO_PP_NOT_NULL(ts->recv2.head) ))
    if( ci_tcp_recvmsg_recv2(&rinf) )
      goto success_unlock_out;

  /* We've done at least one ci_netif_poll(), so we're up-to-date.  But we
  ** haven't filled the app's buffer.
  */

  if( rinf.rc && FLAGS_AND_LOWAT_PERMIT_FAST_RET_WITH_DATA(ts, rinf.rc, flags) )
    goto success_unlock_out;

  if( TCP_RX_DONE(ts) )  goto rx_done;

  if( rinf.rc == 0 && (flags & MSG_DONTWAIT) ) {
    rinf.rc = -EAGAIN;
    goto unlock_out;
  }

  /* Must not delay return if we have any data and are peeking. */
  ci_assert(!(flags & MSG_PEEK) || rinf.rc == 0);

#ifndef __KERNEL__
  /* Spin (if enabled) until timeout, or something happens, or we get
  ** contention on the netif lock.
  */
  if( tcp_recv_spin ) {
    int rc2;

    if( (rc2 = ci_tcp_recvmsg_spin(ni, ts, start_frc)) ) {
      if( rc2 < 0 ) {
        /* -ERESTARTSYS, -EINTR or -EAGAIN */
        rinf.rc = rc2;
        goto unlock_out;
      }
      goto poll_recv_queue;
    }

    tcp_recv_spin = 0;
    if( timeout ) {
      ci_uint32 spin_ms = NI_OPTS(ni).spin_usec >> 10;
      if( spin_ms < timeout )
        timeout -= spin_ms;
      else {
        rinf.rc = -EAGAIN;
        goto rx_done;
      }
    }
  }
#endif

  /* Time to block. */

  sleep_seq = ts->s.b.sleep_seq.all;
  ci_rmb();
  if( tcp_rcv_usr(ts) )  goto poll_recv_queue;
  if( TCP_RX_DONE(ts) )  goto rx_done;

  /* ?? TODO: lock recv queue so other thread can't get in in middle of our
  ** receive.  NB. Need to check what happens on Linux if one thread blocks
  ** in receive (w & w/o WAITALL) and another does concurrent non-blocking
  ** receive.
  */

  {
    int rc2;

    /* This function drops the socket lock, and returns unlocked. */
    ci_assert(!rinf.stack_locked);
    rc2 = ci_sock_sleep(ni, &ts->s.b, CI_SB_FLAG_WAKE_RX,
                        CI_SLEEP_SOCK_LOCKED | CI_SLEEP_SOCK_RQ,
                        sleep_seq, &timeout);
    if( rc2 == 0 )
      rc2 = ci_sock_lock(ni, &ts->s.b);
    if( rc2 < 0 ) {
      /* If we've received anything at all, we must say how much. */
      if( rinf.rc ) {
#ifndef __KERNEL__
        ci_tcp_recv_fill_msgname(ts, (struct sockaddr*) a->msg->msg_name,
                                 &a->msg->msg_namelen);
#endif
      } else
        rinf.rc = rc2;
      goto out;
    }
  }
  ci_assert(have_polled);
  goto poll_recv_queue;


#ifndef __KERNEL__
 slow_path:

  if( flags & MSG_ERRQUEUE ) {
#if CI_CFG_TIMESTAMPING
    ci_ip_pkt_fmt* pkt;

  timestamp_q_check:

    /* The timestamp is stored at TX complete event.  We should not read it
     * until TX_PENDING flag is removed. */
    if( (pkt = ci_udp_recv_q_get(ni, &ts->timestamp_q)) != NULL &&
        ! (pkt->flags & CI_PKT_FLAG_TX_PENDING) ) {
      struct cmsg_state cmsg_state;

    timestamp_q_nonempty:

      ci_udp_recv_q_deliver(ni, &ts->timestamp_q, pkt);

      /* Ensure we read the proper timestamp - see
       * __ci_netif_tx_pkt_complete() for the counterpart ci_wmb(). */
      ci_rmb();

      if( ! (pkt->flags &
             (CI_PKT_FLAG_TX_TIMESTAMPED | CI_PKT_FLAG_INDIRECT)) ) {
        if( ! rinf.stack_locked ) {
          ci_netif_lock(ni);
          rinf.stack_locked = 1;
        }

        ci_netif_pkt_release(ni, pkt);
        goto slow_path;
      }

      a->msg->msg_controllen = rinf.controllen;
      cmsg_state.msg = a->msg;
      cmsg_state.cm = a->msg->msg_control;
      cmsg_state.cmsg_bytes_used = 0;
      cmsg_state.p_msg_flags = &rinf.msg_flags;

      if( pkt->flags & CI_PKT_FLAG_TX_TIMESTAMPED ) {
        if( ts->s.timestamping_flags & ONLOAD_SOF_TIMESTAMPING_ONLOAD ) {
          if( pkt->flags & ~CI_PKT_FLAG_RTQ_RETRANS ) {
            struct onload_timestamp ts = {pkt->hw_stamp.tv_sec,
                                          pkt->hw_stamp.tv_nsec};
            ci_put_cmsg(&cmsg_state, SOL_SOCKET, ONLOAD_SCM_TIMESTAMPING,
                        sizeof(ts), &ts);
          }
          else {
            /* Ignore retransmit timestamps. We might want something like
            * ONLOAD_SCM_TIMESTAMPING_STREAM to report them along with the
            * original transmission time */
            goto timestamp_q_check;
          }
        }
        else {
          struct onload_scm_timestamping_stream stamps;
          int tx_hw_stamp_in_sync;
          memset(&stamps, 0, sizeof(stamps));
          tx_hw_stamp_in_sync = pkt->hw_stamp.tv_nsec &
                                CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC;

          if( pkt->flags & CI_PKT_FLAG_RTQ_RETRANS ) {
            if( pkt->pf.tcp_tx.first_tx_hw_stamp.tv_nsec &
                CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC ) {
              stamps.first_sent.tv_sec = pkt->pf.tcp_tx.first_tx_hw_stamp.tv_sec;
              stamps.first_sent.tv_nsec = pkt->pf.tcp_tx.first_tx_hw_stamp.tv_nsec;
            }
            if( tx_hw_stamp_in_sync ) {
              stamps.last_sent.tv_sec = pkt->hw_stamp.tv_sec;
              stamps.last_sent.tv_nsec = pkt->hw_stamp.tv_nsec;
            }
          }
          else if( tx_hw_stamp_in_sync ) {
            stamps.first_sent.tv_sec = pkt->hw_stamp.tv_sec;
            stamps.first_sent.tv_nsec = pkt->hw_stamp.tv_nsec;
          }
          stamps.len = pkt->pf.tcp_tx.end_seq - pkt->pf.tcp_tx.start_seq;

          /* FIN and SYN eat seq space, but the user is not interested in them */
          if( TX_PKT_IPX_TCP(ipcache_af(&ts->s.pkt), pkt)->tcp_flags &
              (CI_TCP_FLAG_SYN|CI_TCP_FLAG_FIN) )
            stamps.len--;

          ci_put_cmsg(&cmsg_state, SOL_SOCKET, ONLOAD_SCM_TIMESTAMPING_STREAM,
                      sizeof(stamps), &stamps);
        }
      }
      if( pkt->flags & CI_PKT_FLAG_INDIRECT ) {
        struct ci_pkt_zc_header* zch = oo_tx_zc_header(pkt);
        struct ci_pkt_zc_payload* zcp;
        OO_TX_FOR_EACH_ZC_PAYLOAD(ni, zch, zcp) {
          if( zcp->is_remote && zcp->use_remote_cookie ) {
            ci_put_cmsg(&cmsg_state, SOL_IP, ONLOAD_SO_ONLOADZC_COMPLETE,
                        sizeof(zcp->remote.app_cookie),
                        &zcp->remote.app_cookie);
          }
        }
      }

      ci_ip_cmsg_finish(&cmsg_state);
      rinf.msg_flags |= MSG_ERRQUEUE;
 
      /* Wake up TX if necessary as a result of delivering from timestamp_q */
      if( NI_OPTS(ni).tcp_sndbuf_mode >= 1 &&
          ci_tcp_tx_advertise_space(ni, ts) ) {
        if( ! rinf.stack_locked )
          ci_netif_lock(ni);
        ci_tcp_wake_possibly_not_in_poll(ni, ts, CI_SB_FLAG_WAKE_TX);
        ci_netif_unlock(ni);
        rinf.stack_locked = 0;
      }

      rinf.rc = 0;
      goto unlock_out;
    }
    else {
      /* Try polling to see if there is a TX timestamp event available
       * to satisfy this request
       */
      if( ci_netif_may_poll(ni) &&
          ci_netif_need_poll_spinning(ni, start_frc) &&
          ci_netif_trylock(ni) ) {
        ci_netif_poll(ni);
        ci_netif_unlock(ni);
        if( pkt != NULL ) {
          if( ! (pkt->flags & CI_PKT_FLAG_TX_PENDING) )
            goto timestamp_q_nonempty;
        }
        else if( (pkt = ci_udp_recv_q_get(ni, &ts->timestamp_q)) != NULL
                 && ! (pkt->flags & CI_PKT_FLAG_TX_PENDING) ) {
          goto timestamp_q_nonempty;
        }
      }
    }
#endif
    rinf.rc = -EAGAIN;
    goto check_errno;
  }

  ci_assert(flags & MSG_OOB);
  rinf.rc = ci_tcp_recvmsg_urg(&rinf);

  if( rinf.rc >= 0 )  goto success_unlock_out;
  goto unlock_out;
#endif

 rx_done:
  if( tcp_rcv_usr(ts) && !ci_iovec_ptr_is_empty_proper(&rinf.piov) )
    /* Race breaker: rx_errno can get updated asynchronously just after
    ** we've looked at the receive queue.  We need to go back and get that
    ** data.
    */
    goto poll_recv_queue;
  if( rinf.rc )  goto success_unlock_out;
 check_errno:
  /* tcp recv() does not set errno if the connection was properly shut down */
  if( ts->tcpflags & CI_TCPT_FLAG_FIN_RECEIVED )
    goto unlock_out;
  if (ts->s.so_error) {
    ci_int32 rc1 = ci_get_so_error(&ts->s);
    if (rc1 != 0)
      rinf.rc = -rc1;
  } else if( TCP_RX_ERRNO(ts) ) {
    rinf.rc = -TCP_RX_ERRNO(ts);
  }
  goto unlock_out;

 success_unlock_out:
#ifndef __KERNEL__
  ci_tcp_recv_fill_msgname(ts, (struct sockaddr*) a->msg->msg_name,
                           &a->msg->msg_namelen);  /*!\TODO fixme remove cast*/
#endif
 unlock_out:

  /* If we've received FIN and RXQ is empty, let's reap it.
   * See the counterpart in ci_tcp_rx_process_fin(), if FIN arrives with
   * the empty receive queue. */
  if( ( ( (ts->s.b.state & CI_TCP_STATE_RECVD_FIN) && tcp_rcv_usr(ts) == 0 )
        || ni->state->mem_pressure ) && ci_netif_trylock(ni) ) {
    ci_tcp_rx_reap_rxq_bufs_socklocked(ni, ts);
    ci_netif_unlock(ni);
  }

  ci_sock_unlock(ni, &ts->s.b);
 out:
  if(CI_UNLIKELY( ni->state->rxq_low ))
    ci_netif_rxq_low_on_recv(ni, &ts->s, rinf.rc);
#ifndef __KERNEL__
  if( rinf.rc >= 0 )
    a->msg->msg_flags = rinf.msg_flags;
#endif
  return rinf.rc;
}


int ci_tcp_recvmsg(const ci_tcp_recvmsg_args* a)
{
  int rc = ci_tcp_recvmsg_impl(a, copy_one_pkt, NULL);
  if( rc < 0 )
    CI_SET_ERROR(rc, -rc);
  return rc;
}


static void move_from_recv2_to_recv1(ci_netif* ni, ci_tcp_state* ts,
                                     ci_ip_pkt_fmt* head,
                                     ci_ip_pkt_fmt* tail, int n)
{
  /* Move the [n] packets from [head] to [tail] inclusive from the
  ** beginning of [recv2] to [recv1].  If [recv2] is emptied, switch back
  ** to using [recv1].
  */
  ci_ip_pkt_queue* recv1 = &ts->recv1;
  ci_ip_pkt_queue* recv2 = &ts->recv2;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ci_sock_is_locked(ni, &ts->s.b));
  ci_assert(n > 0);
  ci_assert(recv2->num >= n);
  ci_assert(OO_PP_EQ(recv2->head, OO_PKT_P(head)));
  ci_assert(n < recv2->num || OO_PP_IS_NULL(tail->next));

  if( n ) {
    LOG_URG(log(NTS_FMT "recvmsg: moving %d pkts from recv2 to recv1",
                NTS_PRI_ARGS(ni, ts), n));
    /* as this is move between recv queues - no pkt receive adjustment needed */
    ci_ip_queue_move(ni, recv2, recv1, tail, n);
    /* The extract pointer can only be made -ve when the receive queues are
    ** emptied (and both locks are held).  It can only be -ve here if after
    ** the queue was empty the first packet that arrived contained urgent
    ** data.
    */
    if( OO_PP_IS_NULL(ts->recv1_extract) ) {
      ts->recv1_extract = recv1->head;
    }
    else {
      /*
       * must point to an emptied packet
       * - pull up to the first packet moved from recv2
       */
      ci_assert(oo_offbuf_is_empty(&(PKT_CHK(ni, ts->recv1_extract)->buf)));
      ts->recv1_extract = OO_PKT_P(head);
      ci_assert_impl(OO_PP_IS_NULL(recv1->head),
                     OO_PP_IS_NULL(ts->recv1_extract));
    }
    
  }

  /* If we've managed to empty recv2, and we're not still waiting for the
   * urgent data to arrive, then we can switch back to recv1.
   */
  if( OO_PP_IS_NULL(recv2->head) && !(tcp_urg_data(ts) & CI_TCP_URG_COMING) ) {
    LOG_URG(log(NTS_FMT "recvmsg: switch to recv1", NTS_PRI_ARGS(ni, ts)));
    TS_QUEUE_RX_SET(ts, recv1);
    ci_assert(!(tcp_urg_data(ts) & CI_TCP_URG_PTR_VALID));
  }
}


#ifndef __KERNEL__
static int ci_tcp_recvmsg_urg(struct tcp_recv_info *rinf)
{
  ci_netif* ni = rinf->a->ni;
  ci_tcp_state* ts = rinf->a->ts;
  struct msghdr* msg = rinf->a->msg;
  ci_iovec_ptr piov;
  ci_uint8 oob;
  int can_write;
  int rc = 0;

  if( !rinf->stack_locked ) {
    rc = ci_netif_lock(ni);
    if( rc != 0 )
      return rc;
    rinf->stack_locked = 1;
  }
  CHECK_TS(ni, ts);

  LOG_URG(ci_log(TCP_URG_FMT, TCP_URG_ARGS(ts)));

  ci_assert(msg->msg_iovlen > 0);
  ci_iovec_ptr_init_nz(&piov, msg->msg_iov, msg->msg_iovlen);
  can_write = !ci_iovec_ptr_is_empty_proper(&piov);

  if( ts->s.s_flags & CI_SOCK_FLAG_OOBINLINE ) {
    LOG_URG(ci_log("%s: OOBINLINE is set, rc=-EINVAL", __FUNCTION__));
    rc = -EINVAL;
    goto out;
  }

  /* unconditional poll - ensure up to date */
  ci_netif_poll(ni);

  if( tcp_urg_data(ts) & CI_TCP_URG_COMING ) {
    LOG_URG(log("%s: no OOB byte, rc=-EINVAL", __FUNCTION__));
    rc = -EAGAIN;
    goto out;
  }
  if( ~tcp_urg_data(ts) & CI_TCP_URG_IS_HERE ) {
    LOG_URG(ci_log("%s: OOB byte hasn't arrived, rc=-EAGAIN", __FUNCTION__));
    rc = -EINVAL;
    goto out;
  }

  if (ts->s.b.state == CI_TCP_CLOSED) {
    LOG_URG(ci_log("%s: tcp state is CLOSED, rc=0", __FUNCTION__));
    goto out;
  }

  /* at this point, we have an OOB byte */

  /* read the out-of-band byte */
  oob = tcp_urg_data(ts) & CI_TCP_URG_DATA_MASK;
  rinf->msg_flags |= MSG_OOB;

  LOG_URG(ci_log("Reading OOB byte, oob=0x%X, flags=0x%X", oob, rinf->a->flags));

  /* if we are not in peek mode, mark the oob state as read */
  if (~rinf->a->flags & MSG_PEEK)
    tcp_urg_data(ts) &=~ (CI_TCP_URG_IS_HERE | CI_TCP_URG_DATA_MASK);

  /*! Linux appears to treat the MSG_TRUNC flag, in TCP, as a
   *  "PEEK and clear data" flag.
   *  \TODO: review this in the future */
  if( rinf->a->flags & MSG_TRUNC ) {
    rc = can_write;
    goto out;
  }

  if( ! can_write ) {
    rinf->msg_flags |= MSG_TRUNC;
    rc = 0;
    goto out;
  }

  /* We passed all the checks, just copy the byte now.
  ** ci_iovec_ptr_is_empty_proper() above has moved us to a non-zero-length
  ** buffer, so we can just copy the byte here.
  */
  *(char*)CI_IOVEC_BASE(&piov.io) = oob;
  rc = 1;

 out:
  CHECK_TS(ni, ts);
  ci_netif_unlock(ni);
  rinf->stack_locked = 0;
  return rc;
}
#endif


static void ci_tcp_recvmsg_recv2_peek2(struct tcp_recv_info *rinfo,
                                       int start_skip, int stop_at_mark,
                                       unsigned rd_nxt_seq)
{
  /* 
   * This function is used to peek at data on recv2.  Either to look a data
   ** before the mark, or at data after the OOB byte.
   * 
   * Windows: unlike normal reads, peeks will not read past any OOBB
   */
  ci_tcp_state* ts = rinfo->a->ts;
  ci_netif* ni = rinfo->a->ni;
  ci_ip_pkt_queue* recv2 = &ts->recv2;
  ci_ip_pkt_fmt* pkt = PKT_CHK(ni, recv2->head);
  oo_offbuf* buf = &pkt->buf;
  int rc, n, peek_off = start_skip;
  int orig_buf_end;

  ci_assert(oo_offbuf_left(buf) >= start_skip);
  ci_assert(tcp_urg_data(ts) & CI_TCP_URG_PTR_VALID);
  ci_assert(!stop_at_mark || SEQ_LE(rd_nxt_seq, tcp_rcv_up(ts)));

  LOG_URG(log(LNTS_FMT "recv2_peek: so_far=%d skip=%d stop@mark=%d "
              "rd_nxt_seq=%08x rcv_up=%08x", LNTS_PRI_ARGS(ni, ts),
              rinfo->rc, start_skip, stop_at_mark,
              rd_nxt_seq, tcp_rcv_up(ts)));

  rd_nxt_seq += start_skip;

  while( 1 ) {
    orig_buf_end = pkt->buf.end;
    if( stop_at_mark ) {
      int dist_to_urg = tcp_rcv_up(ts) - rd_nxt_seq;
      if( dist_to_urg == 0 ) {
        ci_log("dist_to_urg == 0");
        break;
      }
      /* Hack the end of the packet so that the copier doesn't take too much.
       * This is safe even for a zero-copy copier because we disallow
       * ONLOAD_ZC_KEEP in that case */
      pkt->buf.end = CI_MIN(pkt->buf.end, pkt->buf.off + dist_to_urg);
    }

    rc = 0;
    n = rinfo->copier(ni, rinfo, pkt, peek_off, &rc);
    ci_assert_equal(n, rc); /* zc shenanigans not supported with urgent data */
    pkt->buf.end = orig_buf_end;
#ifdef __KERNEL__
    if( n < 0 ) {
      LOG_URG(log(LNTS_FMT "%s: copy_to_user returned %d", 
                  LNTS_PRI_ARGS(ni, ts), __FUNCTION__, n));
      if( rinfo->rc == 0 )
        rinfo->rc = n;
      break;
    }
#endif
    rinfo->rc += n;
    peek_off += n;
    rd_nxt_seq += n;

    if( ! iovec_roll_over(&rinfo->piov) )
      break;
    if( oo_offbuf_left(buf) - peek_off == 0 ) {
      if( OO_PP_IS_NULL(pkt->next) ) 
	break;
      pkt = PKT_CHK(ni, pkt->next);
      buf = &pkt->buf;
      peek_off = 0;
    }
  }
}


static int ci_tcp_recvmsg_recv2_peek(struct tcp_recv_info *rinf)
{
  ci_tcp_state* ts = rinf->a->ts;
  ci_netif* ni = rinf->a->ni;
  ci_ip_pkt_queue* recv2 = &ts->recv2;
  ci_ip_pkt_fmt* pkt;
  int skip, stop_at_mark;
  unsigned rd_nxt_seq;
  int af = ipcache_af(&ts->s.pkt);

  if( !rinf->stack_locked ) {
    int rc = ci_netif_lock(ni);
    if( rc != 0 )
      return rc;
    rinf->stack_locked = 1;
  }

  pkt = PKT_CHK(ni, recv2->head);
  rd_nxt_seq = PKT_IPX_RX_BUF_SEQ(af, pkt);

  /* Double-check for packets added to recv1 after we finished sucking data
  ** from it.
  */
  if( OO_PP_NOT_NULL(ts->recv1_extract) ) {
    ci_ip_pkt_fmt* r1pkt = PKT_CHK(ni, ts->recv1_extract);
    unsigned seq = PKT_IPX_RX_BUF_SEQ(af, r1pkt) + rinf->rc;
    /* We think we've read everything in recv1, and [seq] points just
    ** beyond that.  So it ought to match the beginning of recv2.  If it
    ** doesn't, then something else has been added to recv1.
    */
    if( seq != CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, pkt)->tcp_seq_be32) )
      /* Ooops...more data appended to recv1.  But it arrived after we
      ** started reading, so we can legitimately return without reading
      ** this data.  If we've not read anything yet, we can safely return
      ** to recvmsg() which will try recv1 again.
      */
      goto out;
  }

  /* If we're at the mark, peek the OOB byte (if inline) and data following
  ** it.  Otherwise peek the data up to the mark.
  */
  if( tcp_rcv_up(ts) == rd_nxt_seq ) {
    skip = !(ts->s.s_flags & CI_SOCK_FLAG_OOBINLINE);
    stop_at_mark = 0;
  }
  else {
    skip = 0;
    stop_at_mark = 1;
  }
  ci_tcp_recvmsg_recv2_peek2(rinf, skip, stop_at_mark, rd_nxt_seq);

 out:
  ci_netif_unlock(ni);
  rinf->stack_locked = 0;
  return rinf->rc;
}


static int ci_tcp_recvmsg_handle_race(struct tcp_recv_info *rinf)
{
  int rc;

  /* One or more packets were added to recv1 after we finished looking at
  ** it, but before we looked at recv2.  So we need to go and pick up that
  ** data.
  */
  ci_netif_unlock(rinf->a->ni);
  rinf->stack_locked = 0;
  rinf->rc += ci_tcp_recvmsg_get_outofline(rinf);
  rc = ci_netif_lock(rinf->a->ni);
  if( rc != 0 )
    return rc;
  rinf->stack_locked = 1;
  /* NB. No more data can have arrived in recv1, because once we start
  ** using recv2 we stick with it until the consumer switches back to
  ** recv1.  Which we haven't.
  */
  return ci_iovec_ptr_is_empty_proper(&rinf->piov) ||
         ((rinf->a->flags & ONLOAD_MSG_ONEPKT) && (rinf->rc > 0));
}


ci_inline int ci_tcp_recv1_is_empty(ci_netif* ni, ci_tcp_state* ts)
{
  /* NB. The first buffer pointed to by the extract pointer may be empty,
  ** but any subsequent ones must not be.
  */
  ci_ip_pkt_fmt *pkt;
  if( OO_PP_IS_NULL(ts->recv1_extract) )  return 1;
  pkt = PKT_CHK_NNL(ni, ts->recv1_extract);
  return oo_offbuf_is_empty(&pkt->buf) && OO_PP_IS_NULL(pkt->next);
}


static int ci_tcp_recvmsg_recv2(struct tcp_recv_info *rinf)
{
  ci_tcp_state* ts = rinf->a->ts;
  ci_netif* ni = rinf->a->ni;
  ci_ip_pkt_queue* recv2 = &ts->recv2;
  ci_ip_pkt_fmt* pkt, *head_pkt, *tail_pkt;
  oo_offbuf* buf;
  unsigned rd_nxt_seq, n;
  int must_return_from_recv = 0;
  int af = ipcache_af(&ts->s.pkt);

  if( rinf->a->flags & MSG_PEEK )
    return ci_tcp_recvmsg_recv2_peek(rinf);

 again:
  LOG_URG(ci_log("%s: again rc=%d", __FUNCTION__, rinf->rc));
  
  ci_assert(ci_sock_is_locked(ni, &ts->s.b));
  if( !rinf->stack_locked ) {
    int rc = ci_netif_lock(ni);
    if( rc != 0 )
      return rc;
    rinf->stack_locked = 1;
  }
  CHECK_TS(ni, ts);

  /* Double-check for packets added to recv1. */
  if( ! ci_tcp_recv1_is_empty(ni, ts) ) {
    must_return_from_recv = ci_tcp_recvmsg_handle_race(rinf);
    if( must_return_from_recv )  goto unlock_out;
  }

  ci_assert(ci_tcp_recv1_is_empty(ni, ts));

  pkt = PKT_CHK(ni, recv2->head);
  buf = &pkt->buf;
  ci_assert(oo_offbuf_left(buf));

  /* Calculate the sequence number of the first un-read byte in this pkt. */
  rd_nxt_seq = PKT_IPX_RX_BUF_SEQ(af, pkt);

  LOG_URG(log("%s: "NTS_FMT "so_far=%d flags=%x nxt_seq=%08x rcv_up=%08x "
              "urg_data=%03x", __FUNCTION__, NTS_PRI_ARGS(ni, ts),
              rinf->rc, rinf->a->flags, rd_nxt_seq, tcp_rcv_up(ts),
              tcp_urg_data(ts)));

  ci_assert(tcp_urg_data(ts) & CI_TCP_URG_PTR_VALID);

  /* If we're in onload_zc_recv then we unconditionally deliver all the recv2
  ** data. There are two problems with allowing zc_recv to be given partial
  ** packets:
  ** 1) Without significant code surgery, it would mean that the callback
  **    gets called with the stack lock held, which means instant deadlock
  **    if the callback calls onload_zc_release_buffers().
  ** 2) It would cause the callback to be called for the same packet
  **    multiple times (once up to the urgent pointer, then again for the
  **    remainder). This means that if ONLOAD_ZC_KEEP was used, it would
  **    think it had two refcounts. In theory, we could actually give it
  **    two refcounts (since the stack lock was held), but that creates
  **    extreme difficulties for apps using onload_zc_buffer_incref().
  ** Overall, it's just easier if we don't bother. This makes apps using
  ** onload_zc_recv get the equivalent behaviour to EF_TCP_URG_MODE=ignore,
  ** which is totally fine.
  **/
  if( tcp_rcv_up(ts) == rd_nxt_seq || rinf->zc_args ) {
    /* We are staring at the urgent byte. */
    LOG_URG(ci_log("%s: We're staring at the oob byte and rc=%d",
              __FUNCTION__, rinf->rc));

    /*
     * windows allows in-band reads to pass the mark - so don't quit here
     */
    if( rinf->rc && ! rinf->zc_args ) {
      /* We've consumed some data, so stop at the mark. */
      LOG_URG(ci_log("%s: We're staring at the oob byte and rc=%d",
              __FUNCTION__, rinf->rc));
      must_return_from_recv = 1;
      goto unlock_out;
    }
    

    if( ! (ts->s.s_flags & CI_SOCK_FLAG_OOBINLINE) &&
        ! oo_offbuf_is_empty(buf) ) {
      /* App is trying to read past the urgent data.  In this case the
      ** urgent data just disappears (just as if it had never been there).
      ** buf may be empty iff the urgent pointer pointed to the FIN: in that
      ** case we can safely ignore it
      */
      oo_offbuf_advance(buf, 1);
      ++ts->rcv_delivered;
    }
    /* Now we can move everything onto recv1 and look and recv1.  This
    ** packet might be empty, but recv1 is permitted to have an empty
    ** packet at the start, so we don't have to worry about it.
    */
    /*
     * windows allows MSG_OOB read after in-band reads have passed the mark
     * - so leave as valid
     */
    tcp_urg_data_invalidate(ts);
    move_from_recv2_to_recv1(ni, ts, pkt, PKT_CHK(ni,recv2->tail), recv2->num);
    ci_assert(OO_PP_IS_NULL(recv2->head));
    ci_assert(TS_QUEUE_RX(ts) == &ts->recv1);
    ci_netif_unlock(ni);
    rinf->stack_locked = 0;
    rinf->rc += ci_tcp_recvmsg_get_outofline(rinf);
    goto out;
  }

  /* There is some normal data before the urgent data.  Look for any whole
  ** packets that come before the mark.
  */
  head_pkt = pkt;
  n = 0;
  tail_pkt = 0; /* just to suppress compiler warning */
  while( SEQ_GE(tcp_rcv_up(ts), pkt->pf.tcp_rx.end_seq) ) {
    tail_pkt = pkt;
    ++n;
    if( OO_PP_IS_NULL(pkt->next) )  break;
    pkt = PKT_CHK(ni, pkt->next);
  }
  if( n ) {
    /* We've got [n] whole packets before the mark.  (This happens when
    ** more urgent data arrives before we've gone past the mark).  We move
    ** them onto recv1.
    */
    move_from_recv2_to_recv1(ni, ts, head_pkt, tail_pkt, n);
    CHECK_TS(ni, ts);
    ci_netif_unlock(ni);
    rinf->stack_locked = 0;
    /* Pull data out of recv1 and return if we fill app's buffer. */
    rinf->rc += ci_tcp_recvmsg_get_outofline(rinf);
    must_return_from_recv = ci_iovec_ptr_is_empty_proper(&rinf->piov) ||
                      ((rinf->a->flags & ONLOAD_MSG_ONEPKT) && (rinf->rc > 0));
    if( must_return_from_recv )  goto out;
    /* May need to pull some more from recv2 before the mark.  NB. Can't
    ** just fall through to the code below, because the mark may have moved
    ** forward because we dropped the netif lock.
    */
    if( OO_PP_NOT_NULL(recv2->head) )  goto again;
    goto out;
  }
  else {
    /* The packet at the head of recv2 (if any) contains normal data
    ** followed by urgent data.  So read the normal data.
    */
    int n;
    ci_assert(! rinf->zc_args);
    if( OO_PP_IS_NULL(recv2->head) )  goto unlock_out;
    n = tcp_rcv_up(ts) - rd_nxt_seq;    /* number of normal bytes */
    LOG_URG(ci_log("%s: reading %d bytes from urg segment before OOBB",
		   __FUNCTION__, n));
    ci_assert(n > 0);
    ci_assert_lt(n, oo_offbuf_left(buf));
    n = ci_copy_to_iovec(&rinf->piov, oo_offbuf_ptr(buf), n);
    rinf->rc += n;
    oo_offbuf_advance(buf, n);
    ts->rcv_delivered += n;
    ci_assert(oo_offbuf_left(buf));
    /* We've either filled the app buffer, or read up to the mark, so
    ** recvmsg() can return now.
    */
    must_return_from_recv = 1;

  }

 unlock_out:
  CHECK_TS(ni, ts);
  if( rinf->stack_locked ) {
    ci_netif_unlock(ni);
    rinf->stack_locked = 0;
  }
 out:
  if( NI_OPTS(ni).tcp_rcvbuf_mode == 1 )
    ci_tcp_rcvbuf_drs(ni, ts);

  /* Must return if we've filled the app buffer. */
  must_return_from_recv |= ci_iovec_ptr_is_empty_proper(&rinf->piov) ||
                      ((rinf->a->flags & ONLOAD_MSG_ONEPKT) && (rinf->rc > 0));

  LOG_URG(ci_log("%s: returning %d rc=%d "
		 "ci_iovec_ptr_is_empty_proper=%d",
		 __FUNCTION__, must_return_from_recv,
		 rinf->rc,
		 ci_iovec_ptr_is_empty_proper(&rinf->piov)));
  
  return must_return_from_recv;
}


#ifndef __KERNEL__

#if CI_CFG_TCP_OFFLOAD_RECYCLER
#define CI_ZC_IOV_STATIC_MAX  32


static int zc_ceph_callback(ci_netif* netif, struct tcp_recv_info* rinf,
                            ci_ip_pkt_fmt* pkt, int peek_off, int* ndata)
{
  int total = oo_offbuf_left(&pkt->buf);
  int n = total;
  char* p = oo_offbuf_ptr(&pkt->buf);
  struct onload_zc_iovec static_iov[CI_ZC_IOV_STATIC_MAX];
  struct onload_zc_iovec* iov = static_iov;
  int iovlen = 0;
  int iov_max = CI_ZC_IOV_STATIC_MAX;
  int out_rc = 0;
  enum onload_zc_callback_rc cb_rc;

  /* Not currently a required feature, and a little tricky to get right: */
  if( rinf->msg_flags & MSG_PEEK )
    return -EOPNOTSUPP;

  while( n ) {
    const int hdr_len = offsetof(struct ceph_data_pkt, data);
    struct ceph_data_pkt data;

    if( n < hdr_len ) {
      LOG_TR(log(LNTS_FMT "bogus plugin metastream len=%d",
                 LNTS_PRI_ARGS(netif, rinf->a->ts), n));
      goto unrecoverable;
    }

    if( iovlen == iov_max ) {
      /* There are no good options for what to do if we get here. Dynamic
       * memory allocation is the least-worst option: giving up is mean, and
       * calling the callback here so we can start again creates immense
       * difficulties with pkt refcounts. */
      struct onload_zc_iovec* iov_new;
      LOG_TR(log(LNTS_FMT "large number of iovs in metapkt (%d @ %d/%d)", 
                 LNTS_PRI_ARGS(netif, rinf->a->ts), iovlen,
                 (int)(p - PKT_START(pkt)),
                 (int)(oo_offbuf_end(&pkt->buf) - PKT_START(pkt))));
      iov_max = iov_max + (iov_max >> 1);
      iov_new = realloc(iov == static_iov ? NULL : iov,
                        iov_max * sizeof(*iov));
      if( ! iov_new ) {
        log(LNTS_FMT "OOM growing iov array (%d)", 
            LNTS_PRI_ARGS(netif, rinf->a->ts), iov_max);
        goto unrecoverable;
      }
      iov = iov_new;
    }

    memcpy(&data, p, hdr_len);
    n -= hdr_len;
    p += hdr_len;
    /* NB: if adding a new msg_type here, don't forget that copy_ceph_pkt()
     * has a similar switch statement */
    switch( data.msg_type ) {
    case XSN_CEPH_DATA_INLINE:
      if( n < data.msg_len ) {
        LOG_TR(log(LNTS_FMT "bogus plugin inline len %d<%u", 
                  LNTS_PRI_ARGS(netif, rinf->a->ts), n, data.msg_len));
        goto unrecoverable;
      }
      iov[iovlen].iov_base = p;
      iov[iovlen].iov_len = data.msg_len;
      iov[iovlen].rx_memreg_idx = PKT_ID2SET(pkt->pp);
      iov[iovlen].addr_space = EF_ADDRSPACE_LOCAL;
      out_rc += data.msg_len;
      break;

    case XSN_CEPH_DATA_REMOTE:
      if( n < sizeof(data.remote) || data.msg_len != sizeof(data.remote) ) {
        LOG_TR(log(LNTS_FMT "bogus plugin remote block %d/%u", 
                  LNTS_PRI_ARGS(netif, rinf->a->ts), n, data.msg_len));
        goto unrecoverable;
      }
      memcpy(&data.remote, p, sizeof(data.remote));
      iov[iovlen].iov_ptr = data.remote.start_ptr;
      iov[iovlen].iov_len = data.remote.data_len;
      iov[iovlen].rx_memreg_idx = 0;
      iov[iovlen].addr_space = netif->state->nic[pkt->intf_i].plugin_addr_space;
      out_rc += data.remote.data_len;
      break;

    case XSN_CEPH_DATA_LOST_SYNC:
      if( n < sizeof(data.lost_sync) ||
          data.msg_len != sizeof(data.lost_sync) ) {
        LOG_TR(log(LNTS_FMT "bogus plugin lost-sync block %d/%u", 
                  LNTS_PRI_ARGS(netif, rinf->a->ts), n, data.msg_len));
        goto unrecoverable;
      }
      memcpy(&data.lost_sync, p, sizeof(data.lost_sync));
      log(LNTS_FMT "plugin lost sync: %u/%u", 
                 LNTS_PRI_ARGS(netif, rinf->a->ts), data.lost_sync.reason,
                 data.lost_sync.subreason);
      rinf->a->msg->msg_controllen = 0;
      *ndata = out_rc;
      /* Set the return value so that we'll keep hitting this same lost-sync
       * message on every receive, and hence block the socket from making
       * further progress */
      return total - n - hdr_len;

    default:
      LOG_TR(log(LNTS_FMT "bogus plugin metastream header %u/%u", 
                 LNTS_PRI_ARGS(netif, rinf->a->ts), data.msg_type,
                 data.msg_len));
      goto unrecoverable;
    }

    iov[iovlen].buf = ONLOAD_ZC_HANDLE_NONZC;
    iov[iovlen].iov_flags = 0;
    ++iovlen;
    n -= data.msg_len;
    p += data.msg_len;
  }

  ci_assert_gt(iovlen, 0);

  /* See comment about refcounting in zc_call_callback() below, but here
   * it's even more interesting because a single packet may be given to
   * the callback multiple times. In that case we pass iov.buf as
   * ONLOAD_ZC_HANDLE_NONZC for all but the last occurrence, because prior
   * to that it's being kept alive by the recvq. The 'last occurrence', in
   * this case, is the first iov of the last batch, to match how UDP uses the
   * zc callback. */
  pkt->rx_flags |= CI_PKT_RX_FLAG_KEEP;
  pkt->user_refcount = CI_ZC_USER_REFCOUNT_ONE;
  iov[0].buf = zc_pktbuf_to_handle(pkt);
  rinf->zc_args->msg.iov = iov;
  rinf->zc_args->msg.msghdr.msg_iovlen = iovlen;
  rinf->zc_args->msg.msghdr.msg_flags = rinf->msg_flags;
  cb_rc = rinf->zc_args->cb(rinf->zc_args, 0);

  if( cb_rc & ONLOAD_ZC_TERMINATE ) {
    /* Make it look like the non-zc buffer is full */
    rinf->piov.io.iov_len = 0;
    rinf->piov.iovlen = 0;
  }
  if( ! (cb_rc & ONLOAD_ZC_KEEP) ) {
    /* Remove the ref we added earlier iff the user didn't retain it */
    pkt->rx_flags &=~ CI_PKT_RX_FLAG_KEEP;
    pkt->pio_addr = -1;  /* Reset to normal after user_refcount overwrote it */
  }

  *ndata = out_rc;
 unrecoverable:
  /* The correct thing to do with bad framing is debatable. This code throws
   * away the remainder of the packet and continues on without telling the
   * app. An easy other option would be to put the app in a continuous loop of
   * retry, fail, log. Neither of these are great, but at some point we have
   * to trust that the hardware behaves itself. */
  if( iov != static_iov )
    free(iov);
  rinf->a->msg->msg_controllen = 0;
  return total;
}
#endif


static int zc_call_callback(ci_netif* netif, struct tcp_recv_info* rinf,
                            ci_ip_pkt_fmt* pkt, int peek_off, int* ndata)
{
  int n = oo_offbuf_left(&pkt->buf);
  enum onload_zc_callback_rc cb_rc;
  struct onload_zc_iovec iov;

#if CI_CFG_TCP_OFFLOAD_RECYCLER
  if( ci_tcp_is_pluginized(rinf->a->ts) )
    return zc_ceph_callback(netif, rinf, pkt, peek_off, ndata);
#endif

  /* Add KEEP flag before calling callback, and remove it after
   * if not needed.  This prevents races where the app releases
   * the pkt before we've added the flag.
   * It might look like it's possible to use an actual refcount here
   * because the recvq is the only owner of the packet, but
   * unfortunately that's only very-nearly-true: onload_tcpdump
   * might have one.
   */
  pkt->rx_flags |= CI_PKT_RX_FLAG_KEEP;

  rinf->zc_args->msg.iov = &iov;
  rinf->zc_args->msg.msghdr.msg_iovlen = 1;
  rinf->zc_args->msg.msghdr.msg_flags = rinf->msg_flags;
  iov.buf = zc_pktbuf_to_handle(pkt);
  iov.iov_base = oo_offbuf_ptr(&pkt->buf) + peek_off;
  iov.iov_len = oo_offbuf_left(&pkt->buf) - peek_off;
  iov.iov_flags = 0;
  iov.rx_memreg_idx = PKT_ID2SET(pkt->pp);
  iov.addr_space = EF_ADDRSPACE_LOCAL;
  pkt->user_refcount = CI_ZC_USER_REFCOUNT_ONE;
  cb_rc = rinf->zc_args->cb(rinf->zc_args, 0);

  if( ! (cb_rc & ONLOAD_ZC_KEEP) ) {
    /* Remove the ref we added earlier iff the user didn't retain it */
    pkt->rx_flags &=~ CI_PKT_RX_FLAG_KEEP;
    pkt->pio_addr = -1;  /* Reset to normal after user_refcount overwrote it */
  }
  else {
    /* The refcount ownership semantics when both peeking and keeping are too
     * horrifying to think about, so just ban it (as stated in the docs). */
    ci_assert_nflags(rinf->msg_flags, MSG_PEEK);
  }

  if( cb_rc & ONLOAD_ZC_TERMINATE ) {
    /* Make it look like the non-zc buffer is full */
    rinf->piov.io.iov_len = 0;
    rinf->piov.iovlen = 0;
  }

  rinf->a->msg->msg_controllen = 0;

  *ndata = n;
  return n;
}


int ci_tcp_zc_recvmsg(const ci_tcp_recvmsg_args* a,
                      struct onload_zc_recv_args* args)
{
  /* This fill_msgname is duplicated at the end of ci_tcp_recvmsg_impl, but we
   * want to get the value filled in before the callback is called. The
   * potential for inefficiency is basically irrelevant since the function
   * does very little in all standard build configurations */
  ci_tcp_recv_fill_msgname(a->ts, (struct sockaddr*) a->msg->msg_name,
                           &a->msg->msg_namelen);
  return ci_tcp_recvmsg_impl(a, zc_call_callback, args);
}
#endif
#endif

/*! \cidoxg_end */
