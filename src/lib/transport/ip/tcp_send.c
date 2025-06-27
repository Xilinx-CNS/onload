/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  TCP sendmsg() etc.
**   \date  2003/09/02
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include "tcp_tx.h"
#include "ip_tx.h"

#if !defined(__KERNEL__)
#include <sys/socket.h>
#include <onload/extensions_zc.h>
#include <limits.h>
#endif
#include <onload/pkt_filler.h>
#include <onload/sleep.h>
#include <onload/tmpl.h>
#include <ci/internal/pio_buddy.h>


#if OO_DO_STACK_POLL
#define LPF "TCP SEND "


#ifdef __KERNEL__
# define OO_EINTR  ERESTARTSYS
#else
# define OO_EINTR  EINTR
#endif

/* If not locked then trylock, and if successful set locked flag and (in
 * some cases) increment the counter.  Return true if lock held, else
 * false.  si_ variants take a [struct udp_send_info*].
 */

#define trylock(ni, locked)                                     \
  ((locked) || (ci_netif_trylock(ni) && ((locked) = 1)))
#define si_trylock(ni, sinf)                    \
  trylock((ni), (sinf)->stack_locked)

struct tcp_send_info {
  int rc;
  ci_uint32 timeout;
  ci_uint32 old_tcp_snd_nxt;
#if CI_CFG_BURST_CONTROL
  ci_uint32 old_burst_window;
#endif
  ci_uint64 start_frc;
  int set_errno;
  int stack_locked;
  int total_unsent;
  int total_sent;
  int sendq_credit;
  int n_needed;
  int n_filled;
  int fill_list_bytes;
  unsigned tcp_send_spin;
  ci_ip_pkt_fmt* fill_list;
  struct oo_pkt_filler pf;
};


static void ci_tcp_tx_advance_nagle(ci_netif* ni, ci_tcp_state* ts)
{
  /* Nagle's algorithm (rfc896).  Summary: when user pushes data, don't
  ** send it if there is less than an MSS and we have unacknowledged data
  ** in the network.  Exceptions: we do want to push SYN/FINs, and we must
  ** push urgent data.
  */
  ci_ip_pkt_queue* sendq = &ts->send;
  ci_ip_pkt_fmt* pkt = NULL;

  ci_assert(ci_ip_queue_is_valid(ni, sendq));
  ci_assert(! ci_ip_queue_is_empty(sendq));

  if( (sendq->num != 1) | (!ci_tcp_is_inflight(ts)) |
      OO_SP_NOT_NULL(ts->local_peer)) {
  advance_now:
    /* NB. We call advance() before poll() to get best latency. */
    ci_ip_time_resync(IPTIMER_STATE(ni));
    ci_tcp_tx_advance(ts, ni);
    if(CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_MSG_WARM ))
      return;
    goto poll_and_out;
  }

  ci_assert(! (ts->tcpflags & CI_TCPT_FLAG_MSG_WARM));
  /* There can't be a SYN, because connection is established, so the SYN
  ** must already be acked.  There can't be a FIN, because if there was
  ** tx_errno would be non zero, and we would not have attempted to
  ** enqueue data.
  */
  pkt = PKT_CHK(ni, sendq->head);
  ci_assert(!(TX_PKT_IPX_TCP(ipcache_af(&ts->s.pkt), pkt)->tcp_flags &
            (CI_TCP_FLAG_SYN|CI_TCP_FLAG_FIN)));

  if( (PKT_TCP_TX_SEQ_SPACE(pkt) >= tcp_eff_mss(ts)) |
      (SEQ_LT(tcp_snd_una(ts), tcp_snd_up(ts))     ) )
    goto advance_now;

  if( ts->s.s_aflags & CI_SOCK_AFLAG_NODELAY ) {
    /* With nagle off it is possible for a sender to push zillions of tiny
     * packets onto the network, which consumes loads of memory.  To
     * prevent this we choose not to advance if many packets are already
     * inflight, and on average they are less than half full.  This
     * behaviour can be disabled by setting [nonagle_inflight_max] to a
     * large value.
     */
    if( ts->retrans.num < NI_OPTS(ni).nonagle_inflight_max ||
        (ts->eff_mss * ts->retrans.num < ci_tcp_inflight(ts) * 2) )
      goto advance_now;
  }

  LOG_TV(log(LPF "%d Nagle snd=%08x-%08x-%08x enq=%08x pkt=%x-%x",
             S_FMT(ts), tcp_snd_una(ts), tcp_snd_nxt(ts),
             ts->snd_max, tcp_enq_nxt(ts),
             pkt->pf.tcp_tx.start_seq, pkt->pf.tcp_tx.end_seq));
  ++ts->stats.tx_stop_nagle;

 poll_and_out:
  if( ci_netif_may_poll(ni) && ci_netif_has_event(ni) )
    ci_netif_poll(ni);
}


ci_inline int ci_tcp_tx_n_pkts_needed(int eff_mss, int maxbytes,
                                      int maxbufs, int sendq_credit) {
  /* Calculate how many packet buffers we need to accommodate <maxbytes>,
  ** assuming each will hold <eff_mss> bytes, but do not exceed <maxbufs>.
  */
  int n = (maxbytes + eff_mss - 1) / eff_mss;
  if( n > sendq_credit )  n = sendq_credit;
  if( n > maxbufs      )  n = maxbufs;
  return n;
}


ci_inline void __ci_tcp_tx_pkt_init(ci_ip_pkt_fmt* pkt, int hdrlen, int mss)
{
  oo_offbuf_init(&pkt->buf, (uint8_t*) oo_tx_l3_hdr(pkt) + hdrlen, mss);
  pkt->buf_len = pkt->pay_len = oo_tx_ether_hdr_size(pkt) + hdrlen;
  pkt->pf.tcp_tx.start_seq = hdrlen;
  pkt->pf.tcp_tx.end_seq = 0;
}


ci_inline void ci_tcp_tx_pkt_init(ci_ip_pkt_fmt* pkt, int hdrlen, int mss)
{
  oo_tx_pkt_layout_init(pkt);
  __ci_tcp_tx_pkt_init(pkt, hdrlen, mss);
}


static 
int ci_tcp_sendmsg_fill_pkt(ci_netif* ni, ci_tcp_state* ts,
                            struct tcp_send_info* sinf,
                            ci_iovec_ptr* piov, int hdrlen,
                            int maxlen
                            CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  /* Initialise and fill a packet buffer from an iovec. */
  int n;
  ci_ip_pkt_fmt* pkt = oo_pkt_filler_next_pkt(ni, &sinf->pf, sinf->stack_locked);

  ci_assert(pkt);
  ci_assert(! ci_iovec_ptr_is_empty_proper(piov));
  ci_tcp_tx_pkt_init(pkt, hdrlen, maxlen);
  oo_pkt_filler_init(&sinf->pf, pkt,
                     (uint8_t*) oo_tx_l3_hdr(pkt) + hdrlen);

#if CI_CFG_IPV6
  if( ipcache_af(&ts->s.pkt) == AF_INET )
    pkt->flags &=~ CI_PKT_FLAG_IS_IP6;
  else
    pkt->flags |= CI_PKT_FLAG_IS_IP6;
#endif

#ifndef NDEBUG
  ci_assert_equal(pkt->n_buffers, 1);
  ci_assert_equal(pkt->buf_len, TX_PKT_LEN(pkt));
#endif

  n = sinf->total_unsent - sinf->fill_list_bytes;
  n = CI_MIN(maxlen, n);
  sinf->rc = oo_pkt_fill(ni, &ts->s, &sinf->stack_locked/*p_netif_locked*/, 
                         CI_FALSE/*can_block*/, &sinf->pf, piov,
                         n CI_KERNEL_ARG(addr_spc));
  /* oo_pkt_fill does not allocate packets.  So, it can fail with
   * -EFAULT only, in kernel mode only, because of oo_pkt_fill_copy(). */
#ifdef __KERNEL__
  if( CI_UNLIKELY( sinf->rc < 0 ) ) {
    ci_assert_equal(sinf->rc, -EFAULT);
    goto fill_failed;
  }
#else
  ci_assert_equal(sinf->rc, 0);
#endif

  /* This assumes that packet filler only used a single buffer.
   * offbuf use on the TCP send path needs to go long term 
   */
  ci_assert_ge(oo_offbuf_left(&pkt->buf), n);
  oo_offbuf_advance(&pkt->buf, n);

  /* We should have either filled the segment, or run out of data. */
  LOG_TV(log("%s: iov.len=%d iovlen=%d n=%d pkt=%d left=%d", __FUNCTION__,
             (int) CI_IOVEC_LEN(&piov->io), piov->iovlen, n,
             OO_PKT_FMT(pkt), oo_offbuf_left(&pkt->buf)));
#ifndef __KERNEL__
  /* This can fail in the kernel due to bad user-level pointer, so
     can't assert this */
  ci_assert(ci_iovec_ptr_is_empty_proper(piov) ||
            oo_offbuf_left(&pkt->buf) == 0 ||
            pkt->n_buffers == CI_IP_PKT_SEGMENTS_MAX);
#else
# ifndef NDEBUG
  if(!(ci_iovec_ptr_is_empty_proper(piov) ||
       oo_offbuf_left(&pkt->buf) == 0 ||
       pkt->n_buffers == CI_IP_PKT_SEGMENTS_MAX))
    LOG_U(ci_log("%s: couldn't copy data, probably bad user-level pointer",
                 __FUNCTION__));
# endif
#endif

  /* We must remember the header length the packet was initialised with, and
  ** the amount of data we added.  The sequence number fields are a reasonable
  ** place for this, as they have to be fixed up when the packet is moved from
  ** the prequeue to the send queue in any case.
  */
  pkt->pf.tcp_tx.end_seq = n;

  ci_assert_equal(TX_PKT_LEN(pkt),
                  oo_offbuf_ptr(&pkt->buf) - PKT_START(pkt));
  return n;

#ifdef __KERNEL__
 fill_failed:
  LOG_U(ci_log("%s: fill failed: %d\n", __FUNCTION__, sinf->rc));
  ci_assert(0);
  return 0;
#endif
}


static int ci_tcp_fill_stolen_buffer(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                     ci_iovec_ptr* piov 
                                     CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  /* Fill a single packet, which must be initialised already (and may
  ** contain data), from an iovec.  Used for the "stolen packet" case.
  */
  int n;

  n = ci_ip_copy_pkt_from_piov(ni, pkt, piov, addr_spc);

  /* We should have either filled the segment, or run out of data. */
  LOG_TV(log("%s: iov.len=%d iovlen=%d n=%d pkt=%d left=%d", __FUNCTION__,
             (int) CI_IOVEC_LEN(&piov->io), piov->iovlen, n,
             OO_PKT_FMT(pkt), oo_offbuf_left(&pkt->buf)));
#ifndef __KERNEL__ 
  /* This can fail in the kernel due to bad user-level pointer, so
     can't assert this */
  ci_assert(ci_iovec_ptr_is_empty(piov) ||
            oo_offbuf_left(&pkt->buf) == 0 ||
            pkt->n_buffers == CI_IP_PKT_SEGMENTS_MAX);
#else
# ifndef NDEBUG
  if(!(ci_iovec_ptr_is_empty(piov) ||
       oo_offbuf_left(&pkt->buf) == 0 ||
       pkt->n_buffers == CI_IP_PKT_SEGMENTS_MAX))
    LOG_U(ci_log("%s: couldn't copy data, probably bad user-level pointer",
                 __FUNCTION__));
# endif
#endif
  /* Fixup the packet meta-data. */
  pkt->pf.tcp_tx.end_seq += n;

  return n;
}


static
void ci_tcp_tx_fill_sendq_tail(ci_netif* ni, ci_tcp_state* ts,
                               ci_iovec_ptr* piov,
                               struct tcp_send_info* sinf
                               CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  ci_ip_pkt_queue* sendq = &ts->send;
  ci_ip_pkt_fmt* pkt;
  int n;

  /* Caller checked this, so we don't have to */
  ci_assert(ci_ip_queue_not_empty(sendq));

  pkt = PKT_CHK(ni, sendq->tail);
  if( ts->s.tx_errno == 0 &&
      (NI_OPTS(ni).tcp_combine_sends_mode == 0 ||
       pkt->flags & CI_PKT_FLAG_TX_MORE) ) {
    if( oo_offbuf_left(&pkt->buf) > 0 ) {
      n = ci_tcp_fill_stolen_buffer(ni, pkt, piov  CI_KERNEL_ARG(addr_spc));
      LOG_TV(ci_log("%s: "NT_FMT "sq=%d if=%d bytes=%d piov.left=%d "
                    "pkt.left=%d", __FUNCTION__, NT_PRI_ARGS(ni, ts),
                    SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts)),
                    ci_tcp_inflight(ts), n, ci_iovec_ptr_bytes_count(piov),
                    oo_offbuf_left(&pkt->buf)));
      tcp_enq_nxt(ts) += n;
      sinf->total_sent += n;
      sinf->total_unsent -= n;
    }

    /* The fact that there is something in the send queue means that it
    ** is being advanced.  So there is really no point whatsoever in us
    ** attempting to advance the send queue now.  If it could have been
    ** advanced further, it already would have.  We just need to poll
    ** (which may cause the data to go out...not our problem).  This is
    ** nagle compliant!
    */
  }
}


ci_inline void ci_tcp_sendmsg_prep_pkt(ci_netif* ni, ci_tcp_state* ts,
                                       ci_ip_pkt_fmt* pkt, unsigned seq)
{
  int orig_hdrlen, extra_opts;
#ifndef NDEBUG
  int af = ipcache_af(&ts->s.pkt);
#endif

  ci_ipcache_update_flowlabel(ni, &ts->s);

  /* Copy in the headers */
  ci_pkt_init_from_ipcache(pkt, &ts->s.pkt);

  /* Recover the original header length that we initialised the packet with,
  ** before we correct the sequence numbers (we stashed it away in [start_seq]
  ** when the buffer was filled).
  */
  orig_hdrlen = (int)pkt->pf.tcp_tx.start_seq;

  /* Sequence numbers in packet are 0...n, so we need to fix them up.
  ** (Note that, in the stolen packet case, the sequence numbers are OK and
  ** <n> was set earlier.)
  */
  pkt->pf.tcp_tx.start_seq = seq;
  pkt->pf.tcp_tx.end_seq += seq;

  pkt->pf.tcp_tx.block_end = OO_PP_NULL;

  LOG_TV(log(LPF "%s: %d: %x-%x", __FUNCTION__, OO_PKT_FMT(pkt),
             pkt->pf.tcp_tx.start_seq, pkt->pf.tcp_tx.end_seq));

  /* It's possible that we thought we didn't need space for TCP options when
  ** the buffer was initialised, but now it turns out that we do.  (The dup
  ** tester can send from one thread to a socket that is still in the middle of
  ** being connected from another thread: when this happens there is a race
  ** condition between connection setup and ci_tcp_sendmsg().  Note that no
  ** sane app would do this!)  So, if the setting we saved away on buffer
  ** initialisation does not match the current setting, the packet must be
  ** fixed up.
  */
  extra_opts = ts->outgoing_hdrs_len - orig_hdrlen;
  if( extra_opts )
    ci_tcp_tx_insert_option_space(ni, ts, pkt, 
                                  orig_hdrlen + oo_tx_ether_hdr_size(pkt),
                                  extra_opts);

  /* The sequence space consumed should match the bytes in the buffer. */
  ci_assert_equal(oo_tx_l3_len(pkt),
                  CI_IPX_HDR_SIZE(af) + sizeof(ci_tcp_hdr)
                  + CI_TCP_HDR_OPT_LEN(TX_PKT_IPX_TCP(af, pkt))
                  + SEQ_SUB(pkt->pf.tcp_tx.end_seq, pkt->pf.tcp_tx.start_seq));

  /* Correct offbuf end as might have been constructed with diff eff_mss */
  if(CI_LIKELY( ! (pkt->flags & CI_PKT_FLAG_INDIRECT) ))
    ci_tcp_tx_pkt_set_end(ts, pkt);
}


#if CI_CFG_PIO

static int ci_tcp_tmpl_offset(void)
{
  return CI_CFG_PKT_BUF_SIZE - sizeof(struct tcp_send_info) -
    sizeof(struct oo_msg_template);
}


static struct oo_msg_template* ci_tcp_tmpl_pkt_to_omt(ci_ip_pkt_fmt* pkt)
{
  return (void*) ((char*) pkt + ci_tcp_tmpl_offset());
}


static void __ci_tcp_tmpl_handle_nic_reset(ci_netif* ni, ci_tcp_state* ts)
{
  oo_pkt_p* pp;
  for( pp = &ts->tmpl_head; OO_PP_NOT_NULL(*pp); ) {
    ci_ip_pkt_fmt* tmpl = PKT_CHK(ni, *pp);
    if( tmpl->pio_addr >= 0 ) {
      if( ni->state->nic[tmpl->intf_i].oo_vi_flags & OO_VI_FLAGS_PIO_EN ) {
        CI_DEBUG_TRY(ef_pio_memcpy(ci_netif_vi(ni, tmpl->intf_i),
                                   PKT_START(tmpl),
                                   tmpl->pio_addr, tmpl->buf_len));
      }
      else {
        ci_pio_buddy_free(ni, &ni->state->nic[tmpl->intf_i].pio_buddy,
                          tmpl->pio_addr, tmpl->pio_order);
        tmpl->pio_addr = -1;
      }
    }
    pp = &tmpl->next;
  }
}


/* Iterate over all the sockets on this netif to handle ongoing
 * templated sends that can be impacted due to the NIC reset.
 */
void ci_tcp_tmpl_handle_nic_reset(ci_netif* ni)
{
  unsigned i;

  for( i = 0; i < ni->state->n_ep_bufs; ++i ) {
    citp_waitable_obj* wo = SP_TO_WAITABLE_OBJ(ni, i);
    citp_waitable* w = &wo->waitable;
    if( (w->state & CI_TCP_STATE_TCP_CONN) || w->state == CI_TCP_CLOSED ) {
      ci_tcp_state* ts = &wo->tcp;
      if( OO_PP_NOT_NULL(ts->tmpl_head) )
        __ci_tcp_tmpl_handle_nic_reset(ni, ts);
    }
  }
}


/* Remove this template from the socket's template list.
 */
static void ci_tcp_tmpl_remove(ci_netif* ni, ci_tcp_state* ts,
                               ci_ip_pkt_fmt* tmpl)
{
  struct oo_msg_template* omt = ci_tcp_tmpl_pkt_to_omt(tmpl);
  oo_pkt_p* pp;

  for( pp = &ts->tmpl_head; *pp != OO_PKT_P(tmpl); )
    pp = &(PKT_CHK(ni, *pp)->next);
  *pp = tmpl->next;
  --(ts->stats.tx_tmpl_active);
  omt->oomt_sock_id = OO_SP_NULL;  /* TODO: debug only? */
}


/* Free a template.  Removes template from socket's list and frees
 * resources.
 *
 * Must be called with the stack lock held.
 */
static void ci_tcp_tmpl_free(ci_netif* ni, ci_tcp_state* ts,
                             ci_ip_pkt_fmt* tmpl, int in_list)
{
  ci_assert(ni);
  ci_assert(ts);
  ci_assert(ci_netif_is_locked(ni));

  if( tmpl->pio_addr >= 0 ) {
    ci_pio_buddy_free(ni, &ni->state->nic[tmpl->intf_i].pio_buddy,
                      tmpl->pio_addr, tmpl->pio_order);
    tmpl->pio_addr = -1;
  }
  if( in_list )
    ci_tcp_tmpl_remove(ni, ts, tmpl);
  --ni->state->n_async_pkts;
  ci_netif_pkt_release_1ref(ni, tmpl);
}


/* Frees all of the socket's templates.
 *
 * Must be called with the stack lock held.
 */
void ci_tcp_tmpl_free_all(ci_netif* ni, ci_tcp_state* ts)
{
  ci_assert(ci_netif_is_locked(ni));
  while( OO_PP_NOT_NULL(ts->tmpl_head) ) {
    ci_ip_pkt_fmt* tmpl = PKT_CHK(ni, ts->tmpl_head);
    ts->tmpl_head = tmpl->next;
    ci_tcp_tmpl_free(ni, ts, tmpl, 0);
  }
}


#ifndef __KERNEL__

static ci_ip_pkt_fmt* ci_tcp_tmpl_omt_to_pkt(struct oo_msg_template* omt)
{
  return (void*) ((char*) omt - ci_tcp_tmpl_offset());
}


static struct tcp_send_info*
  ci_tcp_tmpl_omt_to_sinf(struct oo_msg_template* omt)
{
  return (void*) (omt + 1);
}


/* This function is used to convert a templated send into a normal
 * one.  This is needed when we are unable to do a templated send for
 * example when the sendq is not empty.
 *
 * This function expects the netif to be locked and will release the
 * lock before returning.  It has to release the lock to call
 * ci_tcp_sendmsg().  This function can block if ci_tcp_sendmsg()
 * blocks.  It returns the errno returned by ci_tcp_sendmsg().
 */
static int __ci_tcp_tmpl_normal_send(ci_netif* ni, ci_tcp_state* ts,
                                     ci_ip_pkt_fmt* tmpl,
                                     struct tcp_send_info* sinf, unsigned flags)
{
#define CI_NOT_NULL     ((void *)-1)
  struct iovec iov[1];
  int rc;

  ci_assert(ci_netif_is_locked(ni));

  iov[0].iov_base = CI_TCP_PAYLOAD(PKT_IPX_TCP_HDR(ipcache_af(&ts->s.pkt), tmpl));
  iov[0].iov_len = sinf->total_unsent;

  if( ts->s.b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK | CI_SB_AFLAG_O_NDELAY) )
    flags |= MSG_DONTWAIT;

  ++ts->stats.tx_tmpl_send_slow;

  /* Drop the netif lock as ci_tcp_sendmsg() expects it to not be held. */
  ci_netif_unlock(ni);
  rc = ci_tcp_sendmsg(ni, ts, iov, 1, flags & ~ONLOAD_TEMPLATE_FLAGS_SEND_NOW);
  if( rc < 0 ) {
    rc = -errno;
  }
  else if( rc < sinf->total_unsent ) {
    /* We sent less than we wanted to.  Connection probably closed. */
    rc = -ts->s.tx_errno;
  }
  else {
    ci_assert_equal(rc, sinf->total_unsent);
    rc = 0;
  }

  ci_netif_lock(ni);
  ci_tcp_tmpl_free(ni, ts, tmpl, 1);
  ci_netif_unlock(ni);

  return rc;
}


int ci_tcp_tmpl_alloc(ci_netif* ni, ci_tcp_state* ts,
                      struct oo_msg_template** omt_pp,
                      const struct iovec* initial_msg, int mlen, unsigned flags)
{
  int i, max_payload;
  int rc = 0;
  size_t total_unsent = 0;
  ci_ip_cached_hdrs* ipcache = &ts->s.pkt;
  int intf_i;
  ci_netif_state_nic_t* nsn;
  ci_ip_pkt_fmt* pkt;
  ci_iovec_ptr piov;
  struct oo_msg_template* omt;
  struct tcp_send_info* sinf;
  int af = ipcache_af(&ts->s.pkt);

#if defined(__powerpc64__)
  LOG_U(ci_log("%s: This API is not supported on PowerPC yet.", __FUNCTION__));
  return -ENOSYS;
#endif

  /* Templated sends currently require two data structures both of
   * which are stored on the packet buffer to avoid memory
   * allocations.  They are placed at the end of the packet buffer.
  */

  /* This is needed to ensure that an app written to a later version of the
   * API gets an error if they try to use a flag we don't understand.
   */
  if(CI_UNLIKELY( flags & ~ONLOAD_TEMPLATE_FLAGS_PIO_RETRY )) {
    LOG_E(ci_log("%s: called with unsupported flags=%x", __FUNCTION__, flags));
    return -EINVAL;
  }

  ci_netif_lock(ni);

  if(CI_UNLIKELY( (~ts->s.b.state & CI_TCP_STATE_SYNCHRONISED) )) {
    /* Only handling connected connections.
     */
    LOG_U(ci_log("ci_tcp_tmpl_alloc: not synchronized\n"));
    rc = -ENOTCONN;
    goto out;
  }
  ci_assert_equal(ts->s.tx_errno, 0);

  /* Check for valid cplane information.
   */
  if(CI_UNLIKELY( ! oo_cp_ipcache_is_valid(ni, ipcache) )) {
    oo_tcp_ipcache_update(ni, ts);
    switch( ipcache->status ) {
    case retrrc_success:
      /* Successfully validated cplane info on the socket.  We will copy
       * it into the packet later in this function.
       */
      break;

    case retrrc_nomac:
      /* We could not validate cplane info on the socket.  We will
       * copy incorrect MAC info to the packet later in this function.
       * But it doesn't matter as we will do additional testing in
       * tmpl_update() to ensure that we only send with valid cplane
       * info.
       *
       * TODO: Maybe we want to request an arp at this point
       */
      break;

    case retrrc_localroute:
      goto local_route;

    default:
      LOG_U(ci_log("%s: cplane status=%d", __FUNCTION__, ipcache->status));
      rc = -EHOSTUNREACH;
      goto out;
    }
  }

  if( ipcache->flags & CI_IP_CACHE_IS_LOCALROUTE ) {
   local_route:
    LOG_U(ci_log("%s: templated sends not supported on loopback connections",
                 __FUNCTION__));
    rc = -EOPNOTSUPP;
    goto out;
  }

  intf_i = ipcache->intf_i;
  nsn = &ni->state->nic[intf_i];

  /* Compute total msg size. */
  for( i = 0; i < mlen; ++i ) {
#ifndef NDEBUG
    if( initial_msg[i].iov_base == NULL ) {
      rc = -EFAULT;
      goto out;
    }
#endif
    total_unsent += initial_msg[i].iov_len;
  }

  {
    /* Maximum size of message is minimum of the Effective MSS and the
     * usable bit of the PIO region.  The usable bit is the size of
     * the PIO region minus the size of the headers.
     *
     * We also assume that effective MSS plus the meta data for
     * templated sends (sizeof(struct tcp_send_info) and
     * sizeof(struct oo_msg_template)) fit in the packet buffer.
     *
     * XXX: maybe add a assertion to the effect of the above comment.
     */
    int max_pio_pkt, max_buf_pkt;
    max_pio_pkt = nsn->pio_io_len - ETH_VLAN_HLEN;
    max_buf_pkt =
      CI_CFG_PKT_BUF_SIZE - CI_MEMBER_OFFSET(ci_ip_pkt_fmt, dma_start);
    max_payload = CI_MIN(max_buf_pkt, max_pio_pkt);
    max_payload -= ts->outgoing_hdrs_len + ETH_HLEN;
    max_payload -= sizeof(struct tcp_send_info);
    max_payload -= sizeof(struct oo_msg_template);
  }
  if( total_unsent > max_payload ) {
    rc = -E2BIG;
    goto out;
  }

  /* TODO: have flag to control whether to block waiting for buffer. */
  if( (pkt = ci_netif_pkt_tx_tcp_alloc(ni, ts)) == NULL ) {
    rc = -EBUSY;
    goto out;
  }
  ++(ni->state->n_async_pkts);

  /* We allocate enough space to incorporate a vlan tag.  This is done
   * so if the route changes from no-vlan to vlan, we are guaranteed
   * to have enough space in the PIO region.
   *
   * TODO: use fls
   */
  ci_assert_equal(pkt->pio_addr, -1);
  pkt->intf_i = intf_i;
  pkt->pio_order = ci_log2_ge(ts->outgoing_hdrs_len + ETH_HLEN + ETH_VLAN_HLEN
                              + total_unsent, CI_CFG_MIN_PIO_BLOCK_ORDER);
  pkt->pio_addr = ci_pio_buddy_alloc(ni, &nsn->pio_buddy, pkt->pio_order);
  if( pkt->pio_addr < 0 ) {
    pkt->pio_addr = -1;
    if( ! (flags & ONLOAD_TEMPLATE_FLAGS_PIO_RETRY) ) {
      ci_netif_pkt_release_1ref(ni, pkt);
      --(ni->state->n_async_pkts);
      rc = -ENOMEM;
      goto out;
    }
  }
#if CI_CFG_IPV6
  if( af == AF_INET )
    pkt->flags &=~ CI_PKT_FLAG_IS_IP6;
  else
    pkt->flags |= CI_PKT_FLAG_IS_IP6;
#endif

  omt = ci_tcp_tmpl_pkt_to_omt(pkt);
  *omt_pp = omt;
  omt->oomt_sock_id = S_SP(ts);

  sinf = ci_tcp_tmpl_omt_to_sinf(omt);
  sinf->n_needed = 1;
  sinf->total_unsent = total_unsent;
  sinf->total_sent = 0;
  sinf->pf.alloc_pkt = NULL;
  sinf->fill_list = 0;
  sinf->fill_list_bytes = 0;
  sinf->n_filled = 0;
  oo_pkt_filler_add_pkt(&sinf->pf, pkt);
  pkt->next = ts->tmpl_head;
  ts->tmpl_head = OO_PKT_P(pkt);

#if CI_CFG_TIMESTAMPING
  /* This flag should not be set on a segment of length 0,
   * we assume this is never the case with templated sends */
  if( onload_timestamping_want_tx_nic(ts->s.timestamping_flags) ) {
    pkt->flags |= CI_PKT_FLAG_TX_TIMESTAMPED;
    pkt->pf.tcp_tx.sock_id = ts->s.b.bufid;
  }
#endif

  /* XXX: Do I have to worry about MSG_CORK? */
  /* TODO: look at this sinf stuff */
  ci_iovec_ptr_init_nz(&piov, initial_msg, mlen);
  sinf->fill_list_bytes +=
    ci_tcp_sendmsg_fill_pkt(ni, ts, sinf, &piov, ts->outgoing_hdrs_len,
                            tcp_eff_mss(ts));
  ++sinf->n_filled;
  CI_USER_PTR_SET(sinf->pf.pkt->pf.tcp_tx.next, sinf->fill_list);
  sinf->fill_list = sinf->pf.pkt;
  ci_tcp_sendmsg_prep_pkt(ni, ts, pkt, tcp_enq_nxt(ts));

  TX_PKT_IPX_TCP(af, sinf->fill_list)->tcp_flags =
    CI_TCP_FLAG_PSH | CI_TCP_FLAG_ACK;

  /* Initialise the protocol headers.  We don't set those parts that will
   * always be rewritten when we do the actual send. */
  ci_tcp_tx_finish(ni, ts, pkt);
  ci_tcp_ipx_hdr_init(af, oo_tx_ipx_hdr(af, pkt), oo_tx_l3_len(pkt));

  /* XXX: Do I need to ci_tcp_tx_set_urg_ptr(ts, ni, tcp);
   *
   * DJR: TODO: I think right thing to do is document that this feature is
   * not compatible with urgent data, and add an assertion that there is no
   * urgent data pending.
   */
  ci_ip_set_mac_and_port(ni, ipcache, pkt);

  if( pkt->pio_addr >= 0 ) {
    rc = ef_pio_memcpy(ci_netif_vi(ni, intf_i), PKT_START(pkt),
                       pkt->pio_addr, pkt->buf_len);
    ci_assert_equal(rc, 0);
  }

  ++ts->stats.tx_tmpl_active;

 out:
  ci_netif_unlock(ni);
  return rc;
}


int
ci_tcp_tmpl_update(ci_netif* ni, ci_tcp_state* ts,
                   struct oo_msg_template* omt,
                   const struct onload_template_msg_update_iovec* updates,
                   int ulen, unsigned flags)
{
  /* XXX: In fast path, check if need to update ack.  If send next is
   * what we expect it to be, we are in fast path.  We should save
   * send next somewhere in the pkt buffer.  We will not not check if
   * the ip cache is valid in the fast path.  We need to think about
   * how we handle timestamping efficiently.  Not straightforward.
   */

  int i, diff, rc, cplane_is_valid;
  ci_ip_cached_hdrs* ipcache;
  ci_ip_pkt_fmt* pkt;
  ci_tcp_hdr* tcp;
  ef_vi* vi;
  ci_uint8* tcp_opts;
  struct tcp_send_info* sinf;
  int af = ipcache_af(&ts->s.pkt);

  /* This is needed to ensure that an app written to a later version of the
   * API gets an error if they try to use a flag we don't understand.
   */
  if(CI_UNLIKELY( flags & ~(ONLOAD_TEMPLATE_FLAGS_SEND_NOW |
                            ONLOAD_TEMPLATE_FLAGS_DONTWAIT) )) {
    LOG_E(ci_log("%s: called with unsupported flags=%x", __FUNCTION__, flags));
    return -EINVAL;
  }

  ci_netif_lock(ni);

  ipcache = &ts->s.pkt;
  pkt = ci_tcp_tmpl_omt_to_pkt(omt);
  tcp = TX_PKT_IPX_TCP(af, pkt);;
  vi = ci_netif_vi(ni, pkt->intf_i);
  tcp_opts = CI_TCP_HDR_OPTS(tcp);
  sinf = ci_tcp_tmpl_omt_to_sinf(omt);

  if(CI_UNLIKELY( omt->oomt_sock_id != S_SP(ts) )) {
    rc = -EINVAL;
    ci_tcp_tmpl_free(ni, ts, pkt, 1);
    goto out;
  }
  if(CI_UNLIKELY( ts->s.so_error )) {
    rc = -ci_get_so_error(&ts->s);
    if( rc < 0 ) {
      ci_tcp_tmpl_free(ni, ts, pkt, 1);
      goto out;
    }
  }
  if(CI_UNLIKELY( ts->s.tx_errno )) {
    rc = -ts->s.tx_errno;
    ci_tcp_tmpl_free(ni, ts, pkt, 1);
    goto out;
  }

  if(CI_UNLIKELY( pkt->pio_addr == -1 &&
                  ! (flags & ONLOAD_TEMPLATE_FLAGS_SEND_NOW) )) {
    pkt->pio_addr =
      ci_pio_buddy_alloc(ni, &ni->state->nic[pkt->intf_i].pio_buddy,
                         pkt->pio_order);
    if( pkt->pio_addr >= 0 ) {
      rc = ef_pio_memcpy(vi, PKT_START(pkt),
                         pkt->pio_addr, pkt->buf_len);
      ci_assert(rc == 0);
    }
    else {
      pkt->pio_addr = -1;
    }
  }

  /* Apply requested updates.
   */
  for( i = 0; i < ulen; ++i ) {
    /* TODO: Think about what checks we want at runtime. */
    if( updates[i].otmu_len == 0 ||
        updates[i].otmu_offset < 0 ||
#ifndef NDEBUG
        updates[i].otmu_base == NULL ||
#endif
        updates[i].otmu_offset + updates[i].otmu_len > sinf->total_unsent ) {
      rc = -EINVAL;
      goto out;
    }
    ci_assert((CI_TCP_PAYLOAD(PKT_IPX_TCP_HDR(af, pkt)) - PKT_START(pkt)) +
                 updates[i].otmu_offset >= 0);

    if(CI_UNLIKELY( pkt->pio_addr != -1 )) {
      rc = ef_pio_memcpy(vi, updates[i].otmu_base,
                         pkt->pio_addr + (ci_uint32)
                         (CI_TCP_PAYLOAD(PKT_IPX_TCP_HDR(af, pkt)) - PKT_START(pkt)) +
                         updates[i].otmu_offset,
                         updates[i].otmu_len);
      ci_assert_equal(rc, 0);
    }
    memcpy((char*)CI_TCP_PAYLOAD(PKT_IPX_TCP_HDR(af, pkt)) + updates[i].otmu_offset,
           updates[i].otmu_base, updates[i].otmu_len);
  }

  if( ! (flags & ONLOAD_TEMPLATE_FLAGS_SEND_NOW) ) {
    /* Just update tempated send and return. */
    /* XXX: Should we also consider updating seq nums, acks and other
     * bits of the header?
     */
    /* XXX: Should we poll the stack or something similar right now */
    rc = 0;
    goto out;
  }

  cplane_is_valid = oo_cp_ipcache_is_valid(ni, ipcache);
  if( cplane_is_valid &&
      ! memcmp(oo_tx_ether_hdr(pkt), ci_ip_cache_ether_hdr(ipcache),
               oo_tx_ether_hdr_size(pkt)) &&
      pkt->pio_addr != -1 ) {
    /* Socket has valid cplane info, the same info is on the pkt, and
     * it has a pio region allocated so we can send using pio.
     */
  }
  else if( pkt->pio_addr == -1 ) {
    /* We didn't get a PIO region.  This can happen due to various
     * reasons including a NIC reset while the template was allocated
     * or we never had one to start with so use normal send.
     * __ci_tcp_tmpl_normal_send() releases the lock.
     */
    return __ci_tcp_tmpl_normal_send(ni, ts, pkt, sinf, flags);
  }
  else if( cplane_is_valid ) {
    /* The pkt doesn't have the right cplane info but the socket does.
     * So update the pkt with the latest information.  This can cause
     * the pkt size to change if the route changed from one with vlan
     * to one without or vice versa.  We allocated enough PIO region
     * to accomodate a vlan tag so if pkt size has changed, we simply
     * copy the entire pkt.
     */
    ci_assert_ge(pkt->pio_addr, 0);
    ci_ip_set_mac_and_port(ni, ipcache, pkt);
    if( oo_tx_ether_hdr_size(pkt) == 
        (char*)&ipcache->ipx.ip4 - (char*)ci_ip_cache_ether_hdr(ipcache) )
      /* TODO: we need to copy just the ethernet header here. */
      rc = ef_pio_memcpy(vi, PKT_START(pkt), pkt->pio_addr,
                         (char*)PKT_IPX_TCP_HDR(af, pkt) - PKT_START(pkt));
    else
      rc = ef_pio_memcpy(vi, PKT_START(pkt), pkt->pio_addr, pkt->buf_len);
    ci_assert_equal(rc, 0);
  }
  else {
    /* We could not get mac info, do a normal send.
     * __ci_tcp_tmpl_normal_send() releases the lock. */
    return __ci_tcp_tmpl_normal_send(ni, ts, pkt, sinf, flags);
  }

  ci_assert_ge(pkt->pio_addr, 0);

  if( ci_ip_queue_is_empty(&ts->send) && ef_vi_transmit_space(vi) > 0 &&
      ci_tcp_inflight(ts) + ts->smss < CI_MIN(ts->cwnd, tcp_snd_wnd(ts)) ) {
    /* Sendq is empty, TXQ is not full, and send window allows us to
     * send the requested amount of data, so go ahead and send
     */

    if( CI_BSWAP_BE32(tcp->tcp_seq_be32) != tcp_enq_nxt(ts) ) {
      /* Sequence number do not match maybe because of interim sends.
       * But we can still send after updating them.
       */
      diff = tcp_enq_nxt(ts) - CI_BSWAP_BE32(tcp->tcp_seq_be32);
      pkt->pf.tcp_tx.end_seq += diff;
      pkt->pf.tcp_tx.start_seq += diff;
      tcp->tcp_seq_be32 = CI_BSWAP_BE32(tcp_enq_nxt(ts));
    }

    /* Update ack and window on the pkt */
    tcp->tcp_ack_be32 = CI_BSWAP_BE32(tcp_rcv_nxt(ts));
    ci_tcp_calc_rcv_wnd(ts, "tmpl_update");
    tcp->tcp_window_be16 = TS_IPX_TCP(ts)->tcp_window_be16;

    /* Update TCP timestamp */
    if( ts->tcpflags & CI_TCPT_FLAG_TSO ) {
      unsigned now = ci_tcp_time_now(ni);
      ci_tcp_tx_opt_tso(&tcp_opts, now, ts->tsrecent);
    }

    ci_netif_pkt_hold(ni, pkt);
    __ci_netif_dmaq_insert_prep_pkt(ni, pkt);

    /* Update the PIO region */
    /* XXX: Currently, updating the entire TCP header.  Should only
     * update the affected portion and only if necessary */
    rc = ef_pio_memcpy(vi, TX_PKT_IPX_TCP(af, pkt),
                       pkt->pio_addr + (char*) TX_PKT_IPX_TCP(af, pkt) -
                       PKT_START(pkt), CI_TCP_PAYLOAD(PKT_IPX_TCP_HDR(af, pkt)) -
                       (char*)TX_PKT_IPX_TCP(af, pkt));
    ci_assert_equal(rc, 0);

    /* This cannot fail as we already checked that there is space in
     * the TXQ */
    rc = ef_vi_transmit_pio(vi, pkt->pio_addr, pkt->pay_len, OO_PKT_ID(pkt));
    ci_assert_equal(rc, 0);

    /* Update tcp state machinery state */
    tcp_snd_nxt(ts) = pkt->pf.tcp_tx.end_seq;
    tcp_enq_nxt(ts) = pkt->pf.tcp_tx.end_seq;
    pkt->pf.tcp_tx.block_end = OO_PP_NULL;
    ci_tcp_tmpl_remove(ni, ts, pkt);
    ci_ip_queue_enqueue(ni, &ts->retrans, pkt);
    --ni->state->n_async_pkts;
    ++ts->stats.tx_tmpl_send_fast;
    CITP_STATS_NETIF_INC(ni, pio_pkts);
  }
  else {
    /* Unable to send via pio due to tcp state machinery or full TXQ.
     * So do a normal send.  __ci_tcp_tmpl_normal_send() releases the
     * lock.
     */
    return __ci_tcp_tmpl_normal_send(ni, ts, pkt, sinf, flags);
  }

 out:
  ci_netif_unlock(ni);
  return rc;
}


int ci_tcp_tmpl_abort(ci_netif* ni, ci_tcp_state* ts,
                      struct oo_msg_template* omt)
{
  ci_ip_pkt_fmt* tmpl = ci_tcp_tmpl_omt_to_pkt(omt);
  int rc = 0;
  ci_netif_lock(ni);
  if( omt->oomt_sock_id != S_SP(ts) ) {
    rc = -EINVAL;
    goto out;
  }
  ci_tcp_tmpl_free(ni, ts, tmpl, 1);
 out:
  ci_netif_unlock(ni);
  return rc;
}

#endif /* __KERNEL__ */
#endif /* CI_CFG_PIO */


static int ci_tcp_sendmsg_enqueue(ci_netif* ni, ci_tcp_state* ts,
                                   ci_ip_pkt_fmt* reverse_list,
                                   int total_bytes,
                                   ci_ip_pkt_queue* sendq)
{
  unsigned seq = tcp_enq_nxt(ts) + total_bytes;
  oo_pkt_p tail_pkt_id = OO_PKT_P(reverse_list);
  oo_pkt_p send_list = OO_PP_NULL;
  ci_ip_pkt_fmt* pkt;
  int n_pkts = 0;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert_equal(ts->s.tx_errno, 0);

  do {
    pkt = reverse_list;
    reverse_list = (ci_ip_pkt_fmt *)CI_USER_PTR_GET(pkt->pf.tcp_tx.next);

    seq -= pkt->pf.tcp_tx.end_seq;
    ci_tcp_sendmsg_prep_pkt(ni, ts, pkt, seq);

    pkt->next = send_list;
    send_list = OO_PKT_P(pkt);
    ++n_pkts;
  }
  while( reverse_list );

  ci_assert_equal(tcp_enq_nxt(ts), seq);
  tcp_enq_nxt(ts) += total_bytes;

  /* Append these packets to the send queue. */
  ni->state->n_async_pkts -= n_pkts;
  sendq->num += n_pkts;
  if( OO_PP_IS_NULL(sendq->head) )
    sendq->head = send_list;
  else
    PKT_CHK(ni, sendq->tail)->next = send_list;
  sendq->tail = tail_pkt_id;

  LOG_TV(ci_log("%s: "NT_FMT "sendq.num=%d enq_nxt=%x",
                __FUNCTION__, NT_PRI_ARGS(ni, ts),
                sendq->num, tcp_enq_nxt(ts)));
  CHECK_TS(ni, ts);

  return n_pkts;
}


static int/*bool*/
ci_tcp_tx_prequeue(ci_netif* ni, ci_tcp_state* ts, ci_ip_pkt_fmt* fill_list)
{
  ci_ip_pkt_fmt* next;
  ci_ip_pkt_fmt* pkt;
  int n_pkts = 0;

  /* Walk the fill_list to convert pointers to indirected pointers. */
  pkt = fill_list;
  while( 1 ) {
    ++n_pkts;
    if( ! (next = CI_USER_PTR_GET(pkt->pf.tcp_tx.next)) )  break;
    pkt->next = OO_PKT_P(next);
    pkt = next;
  }

  /* Put [fill_list] onto the prequeue. */
  do {
    oo_pkt_p next = ts->send_prequeue;
    if( next == OO_PP_ID_INVALID )
      return 0;
    OO_PP_INIT(ni, pkt->next, next);
  }
  while( ci_cas32_fail(&ts->send_prequeue,
                       OO_PP_ID(pkt->next), OO_PKT_ID(fill_list)) );

  oo_atomic_add(&ts->send_prequeue_in, n_pkts);
  ++ts->stats.tx_defer;

  return 1;
}


void ci_tcp_sendmsg_enqueue_prequeue(ci_netif* ni, ci_tcp_state* ts,
                                     int/*bool*/ shutdown)
{
  ci_ip_pkt_queue* sendq = &ts->send;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p tail_pkt_id, send_list, id;
  int bytes, n_pkts = 0;
  ci_assert(ci_netif_is_locked(ni));

  if( ts->send_prequeue == OO_PP_ID_INVALID )
    return;
  if( shutdown )
    ci_assert_nequal(ts->s.tx_errno, 0);

  /* Grab the contents of the prequeue atomically. */
  do {
    OO_PP_INIT(ni, id, ts->send_prequeue);
    if( OO_PP_IS_NULL(id) && ! shutdown)
      return;
  } while( ci_cas32_fail(&ts->send_prequeue, OO_PP_ID(id),
                         shutdown ? OO_PP_ID_INVALID : OO_PP_ID_NULL) );

  /* Exit if nothing to send */
  if( OO_PP_IS_NULL(id) ) {
    ci_assert(shutdown);
    return;
  }

  /* Reverse the list. */
  send_list = OO_PP_NULL;
  do {
    pkt = PKT_CHK(ni, id);
    id = pkt->next;
    pkt->next = send_list;
    send_list = OO_PKT_P(pkt);
    ++n_pkts;
  }
  while( OO_PP_NOT_NULL(id) );

  /* Prep each packet. */
  while( 1 ) {
    bytes = pkt->pf.tcp_tx.end_seq;
    ci_tcp_sendmsg_prep_pkt(ni, ts, pkt, tcp_enq_nxt(ts));
    if( pkt->flags & CI_PKT_FLAG_TX_PSH )
      TX_PKT_IPX_TCP(ipcache_af(&ts->s.pkt), pkt)->tcp_flags |= CI_TCP_FLAG_PSH;
    tcp_enq_nxt(ts) += bytes;

    if( OO_PP_IS_NULL(pkt->next) )  break;
    pkt = PKT_CHK(ni, pkt->next);
  }

  /* Append onto the sendq. */
  ni->state->n_async_pkts -= n_pkts;
  sendq->num += n_pkts;
  /* NB do not update ts->send_in here, as that does not include
   * things added via prequeue
   */
  tail_pkt_id = OO_PKT_P(pkt);
  if( OO_PP_IS_NULL(sendq->head) ) {
    sendq->head = send_list;
    pkt = PKT_CHK(ni, send_list);
  }
  else {
    pkt = PKT_CHK(ni, sendq->tail);
    pkt->next = send_list;
  }
  sendq->tail = tail_pkt_id;
}


static int ci_tcp_sendmsg_free_pkt_list(ci_netif* ni, ci_tcp_state* ts,
                                        oo_pkt_p pkt_list, int netif_locked,
                                        int check_aop)
{
  /* NB. Packets must be "asynchronous".  That is, accounted for in
   * [n_async_pkts].
   */
  ci_ip_pkt_fmt* pkt;
  int n_pkts = 0;

  ci_assert(OO_PP_NOT_NULL(pkt_list));
  ci_assert( ! netif_locked || ci_netif_is_locked(ni));

  if( ! netif_locked && ! ci_netif_trylock(ni) ) {
    do {
      pkt = PKT(ni, pkt_list);
      pkt_list = pkt->next;
      /* ?? TODO: cope with these cases */
      ci_assert_equal(pkt->refcount, 1);
      ci_assert(!(pkt->flags & CI_PKT_FLAG_RX));
      pkt->refcount = 0;
      __ci_netif_pkt_clean(pkt);
      ci_netif_pkt_free_nonb_list(ni, OO_PKT_P(pkt), pkt);
      ++n_pkts;
    } while( OO_PP_NOT_NULL(pkt_list) );
  }
  else {
    do {
      pkt = PKT_CHK(ni, pkt_list);
      pkt_list = pkt->next;
      ci_netif_pkt_release_1ref(ni, pkt);
      ++n_pkts;
    } while( OO_PP_NOT_NULL(pkt_list) );
    ni->state->n_async_pkts -= n_pkts;
    if( ! netif_locked )  ci_netif_unlock(ni);
  }

  return n_pkts;
}


/* Convert linked list using pointers to linked list using indirection.
 * Also, set pf.tcp_tx.aop_id to -1 -- ci_tcp_sendmsg_free_pkt_list()
 * needs it. */
static void ci_netif_pkt_convert_ptr_list(ci_netif* ni, ci_ip_pkt_fmt* list)
{
  ci_ip_pkt_fmt* next;
  while( CI_USER_PTR_GET(list->pf.tcp_tx.next) ) {
    next = (ci_ip_pkt_fmt*) CI_USER_PTR_GET(list->pf.tcp_tx.next);
    list->next = OO_PKT_P(next);
    list = next;
  }
  list->next = OO_PP_NULL;
}


static void
ci_tcp_tx_free_prequeue(ci_netif* ni, ci_tcp_state* ts, int netif_locked)
{
  int n_pkts;
  oo_pkt_p id;

  ci_assert( ! netif_locked || ci_netif_is_locked(ni));

  /* Grab contents of prequeue atomically.  We might not be the only thread
  ** trying to free it! */
  do {
    OO_PP_INIT(ni, id, ts->send_prequeue);
    if( OO_PP_IS_NULL(id) )  return;
  } while( ci_cas32_fail(&ts->send_prequeue, OO_PP_ID(id), OO_PP_ID_NULL) );

  n_pkts = ci_tcp_sendmsg_free_pkt_list(ni, ts, id, netif_locked, 1);

  /* Despite the comment at send_prequeue_in definition, we do decrement it
   * here.  This function is called from ci_tcp_sendmsg_handle_tx_errno()
   * only, i.e. these packets have not really got into sendq, and should
   * not be accounted at all.  */
  oo_atomic_add(&ts->send_prequeue_in, -n_pkts);
}


void ci_tcp_sendmsg_enqueue_prequeue_deferred(ci_netif* ni, ci_tcp_state* ts)
{
  ci_assert(ci_netif_is_locked(ni));

  /* Even if CI_SOCK_AFLAG_NEED_SHUT_WR is set, we do not pass
   * shutdown=TRUE here.  ci_tcp_perform_deferred_socket_work() will shut
   * the socket down later. */
  ci_tcp_sendmsg_enqueue_prequeue(ni, ts, 0);

  if( ci_tcp_sendq_not_empty(ts) ) {
    /* This is called in the context of unlocking the netif, so it is highly
    ** likely that the stack has been polled recently.  So we don't want to
    ** poll it here. */
    ci_tcp_tx_advance(ts, ni);
  }
}


ci_inline void ci_tcp_sendmsg_free_unused_pkts(ci_netif* ni, 
                                               struct tcp_send_info* sinf)
{
  oo_pkt_filler_free_unused_pkts(ni, &sinf->stack_locked, &sinf->pf);
}


static int ci_tcp_sendmsg_notsynchronised(ci_netif* ni, ci_tcp_state* ts, 
                                          int flags, struct tcp_send_info* sinf)
{
  sinf->rc = 1;
  /* The same sanity check is done in intercept. This one here is to make
  ** sure (whether needed or not) that internal calls are checked.
  */
  if( ts->s.b.state == CI_TCP_CLOSED )
    sinf->rc = 0;  /* use tx_errno */
  /* State must be SYN-SENT, but can change under our feet as we don't have
  ** the netif lock.  If non-blocking, return EAGAIN.
  */
  else if( flags & MSG_DONTWAIT )
    sinf->rc = -EAGAIN;

  if( sinf->rc <= 0 )
    return -1;

#define CONNECT_IN_PROGRESS ((ts->s.b.state == CI_TCP_SYN_SENT) && \
                             ts->s.tx_errno == 0)

  if( !sinf->stack_locked ) {
    if( (sinf->rc = ci_netif_lock(ni)) )
      return -1;
    sinf->stack_locked = 1;
  }
  CI_TCP_SLEEP_WHILE(ni, ts, CI_SB_FLAG_WAKE_RX, ts->s.so.rcvtimeo_msec, 
                     CONNECT_IN_PROGRESS, &sinf->rc);
  if( sinf->rc != 0 || ts->s.tx_errno != 0 )
    return -1;

  return 0;
}


static void ci_tcp_sendmsg_handle_rc_or_tx_errno(ci_netif* ni, 
                                                 ci_tcp_state* ts, 
                                                 int flags, 
                                                 struct tcp_send_info* sinf)
{
  sinf->set_errno = 0;

  if( sinf->rc ) {
    sinf->rc = -sinf->rc;
    sinf->set_errno = 1;
  }

  if( sinf->total_sent ) {
    sinf->rc = sinf->total_sent;
    sinf->set_errno = 0;
  }
  else {
    if( ts->s.so_error ) {
      ci_int32 rc1 = ci_get_so_error(&ts->s);
      if( rc1 != 0 ) {
        sinf->rc = rc1;
        sinf->set_errno = 1;
      }
    }

    if( sinf->rc == 0 && ts->s.tx_errno ) {
      LOG_TC(log(LNT_FMT "tx_errno=%d flags=%x total_sent=%d",
                 LNT_PRI_ARGS(ni, ts), ts->s.tx_errno, flags, sinf->total_sent));
      sinf->rc = ts->s.tx_errno;
      sinf->set_errno = 1;
    }
  }
  ci_tcp_sendmsg_free_unused_pkts(ni, sinf);
  if( sinf->stack_locked ) {
    ci_netif_unlock(ni);
    sinf->stack_locked = 0;
  }
}


static void ci_tcp_sendmsg_handle_zero_or_tx_errno(ci_netif* ni, 
                                                   ci_tcp_state* ts, 
                                                   int flags, 
                                                   struct tcp_send_info* sinf)
{
  sinf->rc = 0;
  return ci_tcp_sendmsg_handle_rc_or_tx_errno(ni, ts, flags, sinf);
}


static void ci_tcp_sendmsg_free_fill_list(ci_netif* ni, ci_tcp_state* ts,
                                          int flags, 
                                          struct tcp_send_info* sinf)
{
  if( sinf->fill_list ) {
    ci_netif_pkt_convert_ptr_list(ni, sinf->fill_list);
    ci_tcp_sendmsg_free_pkt_list(ni, ts, OO_PKT_P(sinf->fill_list), 
                                 sinf->stack_locked, 0);
  }
}


static void ci_tcp_sendmsg_handle_tx_errno(ci_netif* ni, ci_tcp_state* ts, 
                                           int flags, 
                                           struct tcp_send_info* sinf)
{
  ci_tcp_sendmsg_free_fill_list(ni, ts, flags, sinf);
  ci_tcp_sendmsg_free_unused_pkts(ni, sinf);
  ci_tcp_tx_free_prequeue(ni, ts, sinf->stack_locked);
  return ci_tcp_sendmsg_handle_zero_or_tx_errno(ni, ts, flags, sinf);
}


static void ci_tcp_sendmsg_handle_sent_or_rc(ci_netif* ni, ci_tcp_state* ts, 
                                             int flags, 
                                             struct tcp_send_info* sinf)
{
  ci_tcp_sendmsg_free_fill_list(ni, ts, flags, sinf);
  ci_tcp_sendmsg_free_unused_pkts(ni, sinf);
  if( sinf->stack_locked ) {
    ci_netif_unlock(ni);
    sinf->stack_locked = 0;
  }
  if( sinf->total_sent ) {
    sinf->rc = sinf->total_sent;
    sinf->set_errno = 0;
  }
  else {
    sinf->rc = -sinf->rc;
    sinf->set_errno = 1;
  }
}


static int ci_tcp_sendmsg_no_pkt_buf(ci_netif* ni, ci_tcp_state* ts, 
                                     int flags, struct tcp_send_info* sinf)
{
  ci_ip_pkt_fmt* pkt;
  do {
    pkt = ci_netif_pkt_alloc_nonb(ni);
    if( pkt ) 
      oo_pkt_filler_add_pkt(&sinf->pf, pkt);
    else
      break;
  } while( --sinf->n_needed > 0 );

  if( sinf->n_needed == 0 )
    return 0;
  else {
    CITP_STATS_NETIF_INC(ni, tcp_send_nonb_pool_empty);
    if( !si_trylock(ni, sinf) ) {
      if( sinf->n_filled )
        return 1;
      if( (sinf->rc = ci_netif_lock(ni)) != 0 ) {
        ci_tcp_sendmsg_handle_sent_or_rc(ni, ts, flags, sinf);
        return -1;
      }
      sinf->stack_locked = 1;
      CITP_STATS_NETIF_INC(ni, tcp_send_ni_lock_contends);
    }
    ci_assert(ci_netif_is_locked(ni));

    if( ci_netif_may_poll(ni) && ci_netif_need_poll(ni) &&
        ! ci_netif_pkt_tx_may_alloc(ni) )
      /* Bring us up-to-date before calling ci_netif_pkt_alloc_slow() else
       * it might be provoked to allocate more memory when none is needed.
       */
      ci_netif_poll(ni);
    
    while( 1 ) {
      ci_assert(ci_netif_is_locked(ni));
      do {
        pkt = ci_netif_pkt_tx_tcp_alloc(ni, ts);
        if( pkt ) {
          /* We would have preferred to have gotten this from the non
           * blocking pool.  So arrange for it to be freed to that pool.
           */
          pkt->flags = CI_PKT_FLAG_NONB_POOL;
          ++ni->state->n_async_pkts;
          oo_pkt_filler_add_pkt(&sinf->pf, pkt);
        }
        else if( sinf->n_filled ) {
          /* If we've filled any packets, push them out before blocking. */
          return 1;
        } 
        else
          break;
      } while( --sinf->n_needed > 0 );

      if( sinf->n_needed == 0 )
        return 0;

      ci_assert(sinf->fill_list == 0);

      /* Do not block on pkt allocation if this is non-blocking send */
      if( (flags & MSG_DONTWAIT) && 
          (NI_OPTS(ni).tcp_nonblock_no_pkts_mode == 1) ) {
        /* errno based on reading of __ip_append_data() and
         * udp_sendmsg() when skb allocation fails in kernel 3.16.
         */
        sinf->rc = -ENOBUFS;
        ci_tcp_sendmsg_handle_sent_or_rc(ni, ts, flags, sinf);
        return -1;
      }

      sinf->rc = ci_netif_pkt_wait(ni, &ts->s, sinf->stack_locked ? 
                                   CI_SLEEP_NETIF_LOCKED : 0);
      sinf->stack_locked = 0;
      if( ci_netif_pkt_wait_was_interrupted(sinf->rc) ) {
        ci_tcp_sendmsg_handle_sent_or_rc(ni, ts, flags, sinf);
        return -1;
      }
      do {
        pkt = ci_netif_pkt_alloc_nonb(ni);
        if( pkt ) 
          oo_pkt_filler_add_pkt(&sinf->pf, pkt);
        else
          break;
      } while( --sinf->n_needed > 0 );

      if( ts->s.tx_errno ) {
        ci_tcp_sendmsg_handle_tx_errno(ni, ts, flags, sinf);
        return -1;
      }

      if( sinf->n_needed == 0 )
        return 0;

      /* Start of loop expects lock to be held */
      ci_assert(sinf->stack_locked == 0);
      if( !si_trylock(ni, sinf) ) {
        if( (sinf->rc = ci_netif_lock(ni)) != 0 ) {
          ci_tcp_sendmsg_handle_sent_or_rc(ni, ts, flags, sinf);
          return -1;
        }
        sinf->stack_locked = 1;
        CITP_STATS_NETIF_INC(ni, tcp_send_ni_lock_contends);
      }
    }
  }
  /* Can't get here */
  ci_assert(0);
  return -1;
}


ci_inline int ci_tcp_sendmsg_spin(ci_netif* ni, ci_tcp_state* ts, 
                                  int flags, struct tcp_send_info* sinf)
{
  ci_uint64 now_frc;
  ci_uint64 schedule_frc;
  ci_uint64 max_spin = ts->s.b.spin_cycles;
  int spin_limit_by_so = 0;
#ifndef __KERNEL__
  citp_signal_info* si = citp_signal_get_specific_inited();
#endif

  ci_frc64(&now_frc);
  schedule_frc = now_frc;

  if( ts->s.so.sndtimeo_msec ) {
    ci_uint64 max_so_spin = (ci_uint64)ts->s.so.sndtimeo_msec *
      IPTIMER_STATE(ni)->khz;
    if( max_so_spin <= max_spin ) {
      max_spin = max_so_spin;
      spin_limit_by_so = 1;
    }
  }

  do {
    if( ci_netif_may_poll(ni) ) {
      if( ci_netif_need_poll_spinning(ni, now_frc) && si_trylock(ni, sinf) )
        ci_netif_poll(ni);
      else if( ! ni->state->is_spinner )
        ni->state->is_spinner = 1;
    }
    sinf->sendq_credit = ci_tcp_tx_send_space(ni, ts);
    if( sinf->sendq_credit > 0 ) {
      ni->state->is_spinner = 0;
      return 0;
    }
    if( ts->s.tx_errno ) {
      ni->state->is_spinner = 0;
      ci_tcp_sendmsg_handle_tx_errno(ni, ts, flags, sinf);
      return -1;
    }
    if( sinf->stack_locked ) {
      ci_netif_unlock(ni);
      sinf->stack_locked = 0;
    }
    ci_frc64(&now_frc);
    sinf->rc = OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, &schedule_frc, 
                                               ts->s.so.sndtimeo_msec,
                                               NULL, si);
    if( sinf->rc != 0 ) {
      ni->state->is_spinner = 0;
      ci_tcp_sendmsg_handle_sent_or_rc(ni, ts, flags, sinf);
      return -1;
    }
#if CI_CFG_SPIN_STATS
    ni->state->stats.spin_tcp_send++;
#endif
  } while( now_frc - sinf->start_frc < max_spin );
  ni->state->is_spinner = 0;

  if( spin_limit_by_so && now_frc - sinf->start_frc >= max_spin ) {
    sinf->rc = -EAGAIN;
    ci_tcp_sendmsg_handle_sent_or_rc(ni, ts, flags, sinf);
    return -1;
  }

  if( sinf->timeout ) {
    ci_uint32 time_spin = NI_OPTS(ni).spin_usec >> 10;
    if( time_spin >= sinf->timeout ) {
      sinf->rc = -EAGAIN;
      ci_tcp_sendmsg_handle_sent_or_rc(ni, ts, flags, sinf);
      return -1;
    }
    sinf->timeout -= time_spin;
  }
  return 1;
}
                                  


static int ci_tcp_sendmsg_block(ci_netif* ni, ci_tcp_state* ts,
                                int flags, struct tcp_send_info* sinf)
{
  ci_uint64 sleep_seq;

  CI_IP_SOCK_STATS_INC_TXSTUCK( ts );

  do {
    if( ts->s.tx_errno ) {
      ci_tcp_sendmsg_handle_tx_errno(ni, ts, flags, sinf);
      return -1;
    }
   
    /* Record the current [sleep_seq] and check again to ensure we do a
     * race-free block.
     */
    sleep_seq = ts->s.b.sleep_seq.all;
    ci_rmb();
    sinf->sendq_credit = ci_tcp_tx_send_space(ni, ts);
    if( sinf->sendq_credit > 0 )
      return 0;
   
    CI_IP_SOCK_STATS_INC_TXSLEEP( ts );
   
    sinf->rc = 
      ci_sock_sleep(ni, &ts->s.b, CI_SB_FLAG_WAKE_TX,
                    sinf->stack_locked ? CI_SLEEP_NETIF_LOCKED : 0,
                    sleep_seq, &sinf->timeout);
    /* ci_sock_sleep drops lock */
    sinf->stack_locked = 0;
   
    if( sinf->rc < 0 ) {
      ci_tcp_sendmsg_handle_sent_or_rc(ni, ts, flags, sinf);
      return -1;
    }
  } while(1);
}


static int ci_tcp_sendmsg_slowpath(ci_netif* ni, ci_tcp_state* ts, 
                                   const ci_iovec* iov, unsigned long iovlen,
                                   int flags, struct tcp_send_info* sinf
                                   CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  /* Set NO_TX_ADVANCE flag out here in order to ensure that
   * ci_tcp_sendmsg can't really push any packets out; all it can do
   * is enqueue packets.  Then we set [snd_up] to the correct value
   * before unsetting the flag. 
   *
   * The whole point is that ci_tcp_sendmsg() can proceed without giving a
   * damn about urgent data.
   */
  int rc;
  unsigned enq_nxt_before;
  
  if( !sinf->total_unsent ) {
    sinf->rc = 0;
    return -1;
  }

  ci_assert(flags & MSG_OOB);

  rc = ci_netif_lock(ni);
  if( rc != 0 ) {
    sinf->rc = rc;
    return -1;
  }
  
  /* Poll first, so we have an accurate view of space in the send queue. */
  if( ci_netif_may_poll(ni) && ci_netif_need_poll(ni) )
    ci_netif_poll(ni);

  /* Set the urgent pointer on the assumption that we're going to send
   * everything.  Also save the current enq_nxt; we need it below.  I
   * think this is only necessary to deal with the case where there
   * might be a concurrent send while we drop the netif lock.
   */
  tcp_snd_up(ts) = tcp_enq_nxt(ts) + sinf->total_unsent;
  enq_nxt_before = tcp_enq_nxt(ts);
  
  ts->tcpflags |= CI_TCPT_FLAG_NO_TX_ADVANCE;

  ci_netif_unlock(ni);

  sinf->rc = ci_tcp_sendmsg(ni, ts, iov, iovlen, (flags &~ MSG_OOB) 
                            CI_KERNEL_ARG(addr_spc));
  
  rc = ci_netif_lock(ni);
  if( rc != 0 ) {
    /* If this happens (should only be from the kernel, which can't
     * set MSG_OOB at the moment) and we couldn't send it all, then
     * tcp_send_up() won't be set correctly.
     */
    sinf->rc = rc;
    return -1;
  }

  /* If there was a concurrent send that raced with this, then
   * enq_nxt_before and so tcp_snd_up() could be completely wrong.
   * Not worth worrying about.
   */

  if( sinf->rc > 0 ) {
    /* Correct tcp_send_up() in case where we didn't sent it all */
    tcp_snd_up(ts) = enq_nxt_before + sinf->rc;
    ts->tcpflags &= ~CI_TCPT_FLAG_NO_TX_ADVANCE;
    ci_tcp_tx_advance(ts, ni);
  }

  ci_netif_unlock(ni);
  return 0;
}


static int can_do_msg_warm(ci_netif* ni, ci_tcp_state* ts,
                           struct tcp_send_info* sinf, int total_unsent,
                           int flags)
{
  /* Check all conditions that put us on the slow path for a normal
   * sends or unsupported conditions for ONLOAD_MSG_WARM.
   *
   * For normal sends, sinf holds total_unsent but it doesn't for
   * zc_send() so we explicitly pass it.
   *
   * Not implemented for port striping or loopback yet, we can
   * consider doing that in the future if we suspect that msg_warm can
   * help with them.
   */
  return si_trylock(ni, sinf) &&
    ci_ip_queue_is_empty(&ts->send) &&
    ci_ip_queue_is_empty(&ts->retrans) &&
    ! (flags & MSG_MORE) &&
    total_unsent < tcp_eff_mss(ts) &&
    total_unsent > 0 &&
    ! (ts->s.s_aflags & CI_SOCK_AFLAG_CORK) &&
    ! ts->s.tx_errno &&
    SEQ_LE(tcp_enq_nxt(ts) + total_unsent, ts->snd_max) &&
#if CI_CFG_PORT_STRIPING
    ! (ts->tcpflags & CI_TCPT_FLAG_STRIPE) &&
#endif
    ! (ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE);
}


static __attribute__ ((__noinline__)) void
unroll_msg_warm(ci_netif* ni, ci_tcp_state* ts, struct tcp_send_info* sinf,
                int is_zc_send)
{
  ci_ip_pkt_fmt* pkt;
  ++ts->stats.tx_msg_warm;
  ts->tcpflags &= ~CI_TCPT_FLAG_MSG_WARM;
  ci_ip_queue_init(&ts->send);
  ts->send_in = 0;
  tcp_enq_nxt(ts) -= sinf->fill_list_bytes;
#if CI_CFG_BURST_CONTROL
  ts->burst_window = sinf->old_burst_window;
#endif
  tcp_snd_nxt(ts) = sinf->old_tcp_snd_nxt;

  /* If we updated our rtt seq based on the warm send then timed_seq will
   * will be the seq for the warm packet.  If so, clear the timing so
   * the timed values will be reset when we sent the packet for real.
   */
  if( SEQ_EQ(tcp_snd_nxt(ts), ts->timed_seq) )
    ci_tcp_clear_rtt_timing(ts);

  --ts->stats.tx_stop_app;
  CI_TCP_STATS_DEC_OUT_SEGS(ni);
  if( ! is_zc_send ) {
    pkt = PKT_CHK(ni, ts->send.tail);
    ci_netif_pkt_release_1ref(ni, pkt);
  }
  else {
    /* ci_tcp_sendmsg_enqueue() decrements n_async_pkts.  It is normally
     * rolled back in some way by pkt_release(), but in case of zc_send
     * we should fix this number. */
    ni->state->n_async_pkts++;
  }
}


/* Grab packet buffers. */
static int
ci_tcp_send_alloc_pkts(ci_netif* ni, ci_tcp_state* ts,
                       struct tcp_send_info* sinf, int got)
{
  ci_ip_pkt_fmt* pkt;
  int rc;

  ci_assert_gt(sinf->total_unsent, 0);
  ci_assert_gt(sinf->sendq_credit, 0);

  sinf->n_needed = ci_tcp_tx_n_pkts_needed(ts->eff_mss, sinf->total_unsent, 
                                          CI_CFG_TCP_TX_BATCH,
                                          sinf->sendq_credit);
  rc = sinf->n_needed;
  sinf->fill_list = 0;
  sinf->fill_list_bytes = 0;
  sinf->n_filled = 0;

  sinf->n_needed -= got;

  while( sinf->n_needed > 0 ) {
    if( si_trylock(ni, sinf) ) {
      if( (pkt = ci_netif_pkt_tx_tcp_alloc(ni, ts)) ) {
        ++ni->state->n_async_pkts;
        oo_pkt_filler_add_pkt(&sinf->pf, pkt);
      }
      else
        return rc;;
    } else 
      return rc;
    sinf->n_needed--;
  }

  return rc;
}

static void
ci_tcp_send_fill_pkts(ci_netif* ni, ci_tcp_state* ts,
                      struct tcp_send_info* sinf, ci_iovec_ptr* piov,
                      int n_pkts
                      CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  ci_assert(! ci_iovec_ptr_is_empty_proper(piov));
  ci_assert_equal(sinf->n_needed, 0);

  do {
    sinf->fill_list_bytes +=
      ci_tcp_sendmsg_fill_pkt(ni, ts, sinf, piov, ts->outgoing_hdrs_len,
                              ts->eff_mss CI_KERNEL_ARG(addr_spc));
    ++sinf->n_filled;

    CI_USER_PTR_SET(sinf->pf.pkt->pf.tcp_tx.next, sinf->fill_list);
    sinf->fill_list = sinf->pf.pkt;
  }
  while( --n_pkts > 0 );
}

/* returns 1 if data sent, 0 otherwise */
static int ci_tcp_send_via_prequeue(ci_netif* ni, ci_tcp_state* ts,
                                    struct tcp_send_info* sinf)
{
  int queued = ci_tcp_tx_prequeue(ni, ts, sinf->fill_list);

  if( ! queued ) {
    /* ! queued means that the connection was shut down, or closed, or
     * reset.  Whoever does it, must
     * - set so_error (if needed) and tx_errno first,
     * - close prequeue next.
     */
    ci_assert_nequal(ts->s.tx_errno, 0);
    return 0;
  }

  ci_assert_equal(sinf->stack_locked, 0);
  if( ci_netif_lock_or_defer_work(ni, &ts->s.b) )
    sinf->stack_locked = 1;
  return 1;
}

/* It is not safe to call this function while holding the netif lock */
/*! \todo Confirm */
int ci_tcp_sendmsg(ci_netif* ni, ci_tcp_state* ts,
                   const ci_iovec* iov, unsigned long iovlen,
                   int flags 
                   CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  ci_ip_pkt_queue* sendq = &ts->send;
  ci_ip_pkt_fmt* pkt;
  ci_iovec_ptr piov;
  int m;
  struct tcp_send_info sinf;
  int af = ipcache_af(&ts->s.pkt);

  ci_assert(iov != NULL);
  ci_assert_gt(iovlen, 0);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_LISTEN);

  if( ts->snd_delegated ) {
    int rc;
    /* We do not know which seq number to use.  Call
     * onload_delegated_send_cancel(). */
    CI_SET_ERROR(rc, EBUSY);
    return rc;
  }

  sinf.rc = 0;
  sinf.stack_locked = 0;
  sinf.total_unsent = 0;
  sinf.total_sent = 0;
  sinf.pf.alloc_pkt = NULL;
  sinf.timeout = ts->s.so.sndtimeo_msec;
  sinf.sendq_credit = 0;
#ifndef __KERNEL__
  sinf.tcp_send_spin = 
    oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_TCP_SEND);
  if( sinf.tcp_send_spin )
    ci_frc64(&sinf.start_frc);
#else
  sinf.tcp_send_spin = 0;
#endif


  if(CI_UNLIKELY( (~ts->s.b.state & CI_TCP_STATE_SYNCHRONISED) ))
    goto not_synchronised;

 is_sync:

  /* We want (int)(2 * MAX_SEND_CHUNK) > 0
   * sinf.total_unsent is `int` and must be positive, otherwise our code
   * misbehaves.  We call `total_unsent += addition;`.  To guarantee that
   * the result is positive we require both parts to be within
   * MAX_SEND_CHUNK.
   */
#define MAX_SEND_CHUNK 0x3fffffff
  for( m = 0; m < (int)iovlen; ++m ) {
    sinf.total_unsent += CI_IOVEC_LEN(&iov[m]);
    if(CI_UNLIKELY( CI_IOVEC_BASE(&iov[m]) == NULL &&
                    CI_IOVEC_LEN(&iov[m]) > 0 )) {
      sinf.rc = -EFAULT;
      ci_tcp_sendmsg_handle_rc_or_tx_errno(ni, ts, flags, &sinf);
      if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
      return sinf.rc;
    }
    if( CI_IOVEC_LEN(&iov[m]) > MAX_SEND_CHUNK ||
        sinf.total_unsent > MAX_SEND_CHUNK ) {
      sinf.total_unsent = MAX_SEND_CHUNK;
      break;
    }
  }
#undef MAX_SEND_CHUNK

  if(CI_UNLIKELY( ! sinf.total_unsent ||
                  (flags & (MSG_OOB | ONLOAD_MSG_WARM)) ))
    goto slow_path;

 fast_path:
  ci_iovec_ptr_init_nz(&piov, iov, iovlen);

  ci_assert_le(tcp_eff_mss(ts),
               CI_MAX_ETH_DATA_LEN - sizeof(ci_tcp_hdr) - sizeof(ci_ip4_hdr));

  if( si_trylock(ni, &sinf) && ci_ip_queue_not_empty(sendq) ) {
    ci_assert(! (flags & ONLOAD_MSG_WARM));
    /* Usually, non-empty sendq means we do not have any window to
     * send more data.  However, there is another case:
     * MSG_MORE/TCP_CORK.  In this case, we should really send some
     * data. */
    ci_tcp_tx_fill_sendq_tail(ni, ts, &piov, &sinf CI_KERNEL_ARG(addr_spc));
    /* If we have more data to send, do it. */
    if( sinf.total_unsent > 0 )
      goto non_fast;
    
    /* This is last packet.  Set PUSH flag and MORE flag.
     * Send it if possible. */
    pkt = PKT_CHK(ni, sendq->tail);
    if( (flags & MSG_MORE) || (ts->s.s_aflags & CI_SOCK_AFLAG_CORK) ) {
      pkt->flags |= CI_PKT_FLAG_TX_MORE;
      pkt->flags &=~ CI_PKT_FLAG_TX_PSH_ON_ACK;
    }
    else {
      pkt->flags &= ~CI_PKT_FLAG_TX_MORE;
      TX_PKT_IPX_TCP(af, pkt)->tcp_flags |= CI_TCP_FLAG_PSH;
    }
    
    /* We should somehow push the packet.  However, it was not pushed
     * before.  It means:
     * - we have no window, and zero window timer will wake us up;
     * - there was CI_PKT_FLAG_TX_MORE, and the CORK timer is going
     *   to wake us up.
     * - Nagle.
     * All the cases are nicely handled in ci_tcp_tx_advance_nagle(), so
     * just call it.
     */
#ifdef MSG_SENDPAGE_NOTLAST
    if( ~flags & MSG_SENDPAGE_NOTLAST ||
        ci_tcp_tx_send_space(ni, ts) <= 0 )
#endif
    ci_tcp_tx_advance_nagle(ni, ts);

    if( sinf.stack_locked ) ci_netif_unlock(ni);
    return sinf.total_sent;
  }

 non_fast:
  ci_assert(sinf.total_unsent > 0);
  ci_assert(! ci_iovec_ptr_is_empty_proper(&piov));

  /* How much space is there in the send queue? */
  sinf.sendq_credit = ci_tcp_tx_send_space(ni, ts);

  /* Application is not interested in sending a first small piece of data.
   * If the connection is going on well (CONG_OPEN or CONG_FAST_RECOV),
   * then give a bit more send credit.  We hope that retransmit queue
   * packets will be acked soon and we'll return to
   * ci_tcp_tx_send_space() constrains. */
  if( sinf.sendq_credit <= 0 && NI_OPTS(ni).tcp_sndbuf_mode &&
      sinf.total_sent &&
      ( ts->congstate == CI_TCP_CONG_OPEN ||
        ts->congstate == CI_TCP_CONG_FAST_RECOV ) )
    sinf.sendq_credit += ts->retrans.num >> 1;

  if( sinf.sendq_credit <= 0 )  goto send_q_full;

 try_again:
  while( 1 ) {
    /* Grab packet buffers and fill them with data. */
    m = ci_tcp_send_alloc_pkts(ni, ts, &sinf, 0);
    if( sinf.n_needed > 0 )
      goto no_pkt_buf;

  got_pkt_buf:
    ci_tcp_send_fill_pkts(ni, ts, &sinf, &piov, m CI_KERNEL_ARG(addr_spc));
    m = 0;
    /* Look on MSG_MORE: do not send the last packet if it is not full */
    if( (flags & MSG_MORE) || (ts->s.s_aflags & CI_SOCK_AFLAG_CORK) ) {
      sinf.pf.pkt->flags |= CI_PKT_FLAG_TX_MORE;
      sinf.pf.pkt->flags &=~ CI_PKT_FLAG_TX_PSH_ON_ACK;
    }

  filled_some_pkts:
    /* If we can grab the lock now, setup the meta-data and get sending.
     * Otherwise queue the packets for sending by the netif lock holder.
     */
    if( si_trylock(ni, &sinf) ) {
      if( ts->s.tx_errno ) {
        ci_assert(! (flags & ONLOAD_MSG_WARM));
        ci_tcp_sendmsg_handle_tx_errno(ni, ts, flags, &sinf);
        if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
        return sinf.rc;
      }

      /* eff_mss may now be != ts->eff_mss */
      ts->send_in += ci_tcp_sendmsg_enqueue(ni, ts,
                                            sinf.fill_list,
                                            sinf.fill_list_bytes,
                                            &ts->send);
      sinf.total_sent += sinf.fill_list_bytes;
      sinf.total_unsent -= sinf.fill_list_bytes;

      /* Now we've sent all the packets we grabbed, but not necessarily all
       * of the data -- so check to see if we're done yet.  The last
       * segment gets the PSH flag.
       */
      if( sinf.total_unsent == 0 ) {
        if( (sinf.fill_list->flags & CI_PKT_FLAG_TX_MORE) )
          TX_PKT_IPX_TCP(af, sinf.fill_list)->tcp_flags = CI_TCP_FLAG_ACK;
        else
          TX_PKT_IPX_TCP(af, sinf.fill_list)->tcp_flags =
              CI_TCP_FLAG_PSH | CI_TCP_FLAG_ACK;
#ifdef MSG_SENDPAGE_NOTLAST
        if( ~flags & MSG_SENDPAGE_NOTLAST ||
            ci_tcp_tx_send_space(ni, ts) <= 0 )
#endif
        {
        ci_tcp_tx_advance_nagle(ni, ts);
        if(CI_UNLIKELY( flags & ONLOAD_MSG_WARM ))
          unroll_msg_warm(ni, ts, &sinf, 0);
        }
        /* Assert that there's no need to free unused packets */
        ci_assert_equal(sinf.pf.alloc_pkt, NULL);
        if( sinf.stack_locked ) ci_netif_unlock(ni);
        return sinf.total_sent;
      }

#ifdef MSG_SENDPAGE_NOTLAST
      if( (~flags & MSG_SENDPAGE_NOTLAST) ||
          ci_tcp_tx_send_space(ni, ts) <= 0 )
#endif
      {
      /* Stuff left to do -- push out what we've got first. */
      ci_assert(! (flags & ONLOAD_MSG_WARM));
      if( ci_netif_may_poll(ni) && ci_netif_need_poll(ni) )
        ci_netif_poll(ni);
      sinf.fill_list = 0;
      if( ts->s.tx_errno ) {
        ci_tcp_sendmsg_handle_tx_errno(ni, ts, flags, &sinf);
        if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
        return sinf.rc;
      }
      if(CI_LIKELY( ! ci_ip_queue_is_empty(sendq) ))
        ci_tcp_tx_advance(ts, ni);
      }
    }
    else {
      if( sinf.total_unsent == sinf.fill_list_bytes )
        /* The last segment needs to have the PSH flag set. */
        if ( ! (sinf.fill_list->flags & CI_PKT_FLAG_TX_MORE) )
          sinf.fill_list->flags |= CI_PKT_FLAG_TX_PSH;

      /* Couldn't get the netif lock, so enqueue packets on the prequeue. */
      if( ! ci_tcp_send_via_prequeue(ni, ts, &sinf) ) {
        ci_tcp_sendmsg_handle_tx_errno(ni, ts, flags, &sinf);
        if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
        return sinf.rc;
      }
      sinf.total_sent += sinf.fill_list_bytes;
      sinf.total_unsent -= sinf.fill_list_bytes;
      if( sinf.total_unsent == 0 ) {
        /* Assert that there's no need to free unused packets */
        ci_assert_equal(sinf.pf.alloc_pkt, NULL);
        if( sinf.stack_locked ) ci_netif_unlock(ni);
        return sinf.total_sent;
      }
      /* We've more to send, so keep filling buffers. */
    }

    sinf.sendq_credit -= sinf.n_filled;
    if( sinf.sendq_credit <= 0 ) {
      /* It looks like we don't have any credit in the send queue;
       * let's check for sure. */
      sinf.sendq_credit = ci_tcp_tx_send_space(ni, ts);
      if( sinf.sendq_credit <= 0 )  goto send_q_full;
    }
  }

 send_q_full:
  /* We jump into here when the send queue (including prequeue) is full. */
  ci_assert(! (flags & ONLOAD_MSG_WARM));
  ci_assert(sinf.total_unsent > 0);
  sinf.fill_list = 0;

  if( ci_netif_may_poll(ni) && ci_netif_need_poll(ni) &&
      si_trylock(ni, &sinf) ) {
    ci_netif_poll(ni);
    if( ts->s.tx_errno ) {
      ci_tcp_sendmsg_handle_tx_errno(ni, ts, flags, &sinf);
      if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
      return sinf.rc;
    }
    sinf.sendq_credit = ci_tcp_tx_send_space(ni, ts);
    if( sinf.sendq_credit > 0 )  goto try_again;
  }

  /* The send queue is full, the prequeue is empty, and the netif has been
  ** polled recently (or is contended, in which case it will be polled
  ** soon).  We either want to block or return.
  */
  if( flags & MSG_DONTWAIT ) {
    /* We don't need to check tx_errno here.  We are here because the send
    ** queue is (was) full.  Therefore tx_errno was not set when we did
    ** that check.  ie. We got in before tx_errno was set (so we don't care
    ** if it got set subsequently).
    */
    sinf.rc = -EAGAIN;
    ci_tcp_sendmsg_handle_sent_or_rc(ni, ts, flags, &sinf);
    if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
    return sinf.rc;
  }

  if( sinf.tcp_send_spin ) {
    int rc;
    rc = ci_tcp_sendmsg_spin(ni, ts, flags, &sinf);
    if( rc == 0 )
      goto try_again;
    else if( rc == -1 ) {
      if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
      return sinf.rc;
    }
    sinf.tcp_send_spin = 0;
  }

  if( ci_tcp_sendmsg_block(ni, ts, flags, &sinf) == 0 )
    goto try_again;
  else {
    if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
    return sinf.rc;
  }

 no_pkt_buf:
  {
    int rc;
    if(CI_UNLIKELY( flags & ONLOAD_MSG_WARM )) {
      /* ONLOAD_MSG_WARM should only try to allocate 1 buffer and if
       * that failed, then the buffer list should be empty.  As we are
       * not hitting the fast path, just return.
       */
      ++ts->stats.tx_msg_warm_abort;
      ci_assert_equal(sinf.pf.alloc_pkt, NULL);
      if( sinf.stack_locked )
        ci_netif_unlock(ni);
      return 0;
    }
    rc = ci_tcp_sendmsg_no_pkt_buf(ni, ts, flags, &sinf);
    if( rc == 0 )
      goto got_pkt_buf;
    else if( rc == 1 )
      goto filled_some_pkts;
    else {
      ci_assert(rc == -1);
      if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
      return sinf.rc;
    }
  }

 not_synchronised:
  if(CI_UNLIKELY( flags & ONLOAD_MSG_WARM )) {
    ++ts->stats.tx_msg_warm_abort;
    if( sinf.stack_locked )
      ci_netif_unlock(ni);
    RET_WITH_ERRNO(EPIPE);
  }

  if( ci_tcp_sendmsg_notsynchronised(ni, ts, flags, &sinf) == -1 ) {
    ci_tcp_sendmsg_handle_rc_or_tx_errno(ni, ts, flags, &sinf);
    if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
    return sinf.rc;
  }
  goto is_sync;

 slow_path:
  if(CI_UNLIKELY( flags & ONLOAD_MSG_WARM )) {
    if( can_do_msg_warm(ni, ts, &sinf, sinf.total_unsent, flags) ) {
      ts->tcpflags |= CI_TCPT_FLAG_MSG_WARM;
#if CI_CFG_BURST_CONTROL
      sinf.old_burst_window = ts->burst_window;
#endif
      sinf.old_tcp_snd_nxt = tcp_snd_nxt(ts);
      goto fast_path;
    }
    ++ts->stats.tx_msg_warm_abort;
    if( sinf.stack_locked )
      ci_netif_unlock(ni);
    if( sinf.total_unsent >= tcp_eff_mss(ts) )
      RET_WITH_ERRNO(EINVAL);
    return 0;
  }
  if( ci_tcp_sendmsg_slowpath(ni, ts, iov, iovlen, flags, &sinf 
                              CI_KERNEL_ARG(addr_spc)) == -1 ) {
    ci_tcp_sendmsg_handle_rc_or_tx_errno(ni, ts, flags, &sinf);
    if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
    return sinf.rc;
  }
  return sinf.rc;
}


#ifndef __KERNEL__
/* 
 * TODO:
 *  - improve TCP send path (in general) to handle fragmented buffers, then:
 *   o append a small buffer to the existing send queue (via frag
 *     next) if there's space;
 *   o coalesce small buffers together (via * frag next) into a single
 *     packet;
 */

int ci_tcp_zc_send(ci_netif* ni, ci_tcp_state* ts, struct onload_zc_mmsg* msg,
                   int flags)
{
  struct tcp_send_info sinf;
  ci_ip_pkt_fmt* pkt;
  int j;
  unsigned eff_mss;
  int af = ipcache_af(&ts->s.pkt);

  ci_assert(msg != NULL);
  ci_assert(ts);
  ci_assert(ts->s.b.state != CI_TCP_LISTEN);
  ci_assert(msg->msg.msghdr.msg_iovlen);

  sinf.rc = 0;
  sinf.stack_locked = 0;
  sinf.fill_list = 0;
  sinf.fill_list_bytes = 0;
  sinf.n_filled = 0;
  sinf.total_sent = 0;
  sinf.pf.alloc_pkt = NULL;
  sinf.timeout = ts->s.so.sndtimeo_msec;
#ifndef __KERNEL__
  sinf.tcp_send_spin = 
    oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_TCP_SEND);
  if( sinf.tcp_send_spin )
    ci_frc64(&sinf.start_frc);
#else
  sinf.tcp_send_spin = 0;
#endif

  if( !(ts->s.b.state & CI_TCP_STATE_SYNCHRONISED) &&
      ci_tcp_sendmsg_notsynchronised(ni, ts, flags, &sinf) == -1) {
    ci_tcp_sendmsg_handle_rc_or_tx_errno(ni, ts, flags, &sinf);
    msg->rc = sinf.set_errno ? -sinf.rc : sinf.rc;
    return 1;
  }

  eff_mss = tcp_eff_mss(ts);
  ci_assert_le(eff_mss,
               CI_MAX_ETH_DATA_LEN - sizeof(ci_tcp_hdr) - sizeof(ci_ip4_hdr));

  j = 0;

  sinf.sendq_credit = ci_tcp_tx_send_space(ni, ts);
  /* Combine sendq_credit and ONLOAD_MSG_WARM checking to reduce
   * branches in fast path.
   */
  if( sinf.sendq_credit <= 0 || flags & ONLOAD_MSG_WARM ) {
    if(CI_UNLIKELY( flags & ONLOAD_MSG_WARM )) {
      if( ! can_do_msg_warm(ni, ts, &sinf, msg->msg.iov[0].iov_len, flags) ||
          msg->msg.msghdr.msg_iovlen > 1 ) {
        ++ts->stats.tx_msg_warm_abort;
        if( sinf.stack_locked )
          ci_netif_unlock(ni);
        msg->rc = 0;
        if( msg->msg.iov[0].iov_len >= tcp_eff_mss(ts) ||
            msg->msg.msghdr.msg_iovlen > 1 )
          msg->rc = -EINVAL;
        return 1;
      }
      ts->tcpflags |= CI_TCPT_FLAG_MSG_WARM;
#if CI_CFG_BURST_CONTROL
      sinf.old_burst_window = ts->burst_window;
#endif
      sinf.old_tcp_snd_nxt = tcp_snd_nxt(ts);
    }
    else {
      goto send_q_full;
    }
  }
  
 send_q_not_full:
  pkt = NULL;
  while( j < msg->msg.msghdr.msg_iovlen ) {
    pkt = zc_handle_to_pktbuf(msg->msg.iov[j].buf);

    ci_assert_equal(pkt->stack_id, ni->state->stack_id);
    ci_assert(msg->msg.iov[j].iov_base != NULL);
    ci_assert_gt(msg->msg.iov[j].iov_len, 0);
    ci_assert_le(msg->msg.iov[j].iov_len, eff_mss);
    ci_assert_gt((char*)msg->msg.iov[j].iov_base,
                 PKT_START(pkt) + ts->outgoing_hdrs_len);
    ci_assert_lt((char*)msg->msg.iov[j].iov_base +
                 msg->msg.iov[j].iov_len,
                 ((char*)pkt) + CI_CFG_PKT_BUF_SIZE);

    if( pkt->stack_id != ni->state->stack_id ||
        msg->msg.iov[j].iov_len <= 0 ||
        msg->msg.iov[j].iov_len > eff_mss ||
        (char*)msg->msg.iov[j].iov_base <
        PKT_START(pkt) + ts->outgoing_hdrs_len ||
        (char*)msg->msg.iov[j].iov_base + msg->msg.iov[j].iov_len >
        ((char*)pkt) + CI_CFG_PKT_BUF_SIZE )
      goto bad_buffer;

    pkt->pio_addr = -1;
    oo_pkt_af_set(pkt, af);
    __ci_tcp_tx_pkt_init(pkt, ((uint8_t*) msg->msg.iov[j].iov_base -
                              (uint8_t*) oo_tx_l3_hdr(pkt)), eff_mss);
    pkt->n_buffers = 1;
    pkt->buf_len += msg->msg.iov[j].iov_len;
    pkt->pay_len += msg->msg.iov[j].iov_len;
    oo_offbuf_advance(&pkt->buf, msg->msg.iov[j].iov_len);
    pkt->pf.tcp_tx.end_seq = msg->msg.iov[j].iov_len;

    ci_assert_equal(TX_PKT_LEN(pkt), oo_offbuf_ptr(&pkt->buf) - PKT_START(pkt));
    CI_USER_PTR_SET(pkt->pf.tcp_tx.next, sinf.fill_list);
    sinf.fill_list = pkt;
    --sinf.sendq_credit;
    sinf.fill_list_bytes += msg->msg.iov[j].iov_len;
    ++sinf.n_filled;
    ++j;
    if( sinf.sendq_credit <= 0 )
      break;
  }

  if( ((flags & MSG_MORE) || (ts->s.s_aflags & CI_SOCK_AFLAG_CORK)) ) {
    pkt->flags |= CI_PKT_FLAG_TX_MORE;
    pkt->flags &=~ CI_PKT_FLAG_TX_PSH_ON_ACK;
  }

  /* If we can grab the lock now, setup the meta-data and get sending.
   * Otherwise queue the packets for sending by the netif lock holder.
   */
  if( si_trylock(ni, &sinf) ) {
    if( ts->s.tx_errno )
      goto tx_errno;
    if( sinf.fill_list ) {
      ts->send_in += ci_tcp_sendmsg_enqueue(ni, ts,
                                            sinf.fill_list,
                                            sinf.fill_list_bytes,
                                            &ts->send);
      sinf.total_sent += sinf.fill_list_bytes;
    }

    if( pkt->flags & CI_PKT_FLAG_TX_MORE )
      TX_PKT_IPX_TCP(af, pkt)->tcp_flags = CI_TCP_FLAG_ACK;
    else
      TX_PKT_IPX_TCP(af, pkt)->tcp_flags = CI_TCP_FLAG_PSH|CI_TCP_FLAG_ACK;
    ci_tcp_tx_advance_nagle(ni, ts);
    if(CI_UNLIKELY( flags & ONLOAD_MSG_WARM )) {
      unroll_msg_warm(ni, ts, &sinf, 1);
    }
  }
  else {
    if( ts->s.tx_errno )
      goto tx_errno;

    if( !(pkt->flags & CI_PKT_FLAG_TX_MORE) )
      pkt->flags |= CI_PKT_FLAG_TX_PSH;

    if( ! ci_tcp_send_via_prequeue(ni, ts, &sinf) )
      goto tx_errno;
    sinf.total_sent += sinf.fill_list_bytes;
  }

  if( sinf.n_filled < msg->msg.msghdr.msg_iovlen ) {
    sinf.fill_list = 0;
    sinf.fill_list_bytes = 0;
    sinf.sendq_credit = ci_tcp_tx_send_space(ni, ts);
    if( sinf.sendq_credit > 0 )
      goto send_q_not_full;
    else
      goto send_q_full;
  }
  if( sinf.stack_locked ) 
    ci_netif_unlock(ni);
  msg->rc = sinf.total_sent;
  return 1;

 send_q_full:
  if( ci_netif_may_poll(ni) && ci_netif_need_poll(ni) &&
      si_trylock(ni, &sinf) ) {
    ci_netif_poll(ni);
    if( ts->s.tx_errno )
      goto tx_errno;
    sinf.sendq_credit = ci_tcp_tx_send_space(ni, ts);
    if( sinf.sendq_credit > 0 )
      goto send_q_not_full;
  }

  msg->rc = sinf.total_sent;
  if( flags & MSG_DONTWAIT ) {
    if( j == 0 )
      msg->rc = -EAGAIN;
    if( sinf.stack_locked )
      ci_netif_unlock(ni);
    return 1;
  }

  if( sinf.tcp_send_spin ) {
    int rc;
    rc = ci_tcp_sendmsg_spin(ni, ts, flags, &sinf);
    if( rc == 0 )
      goto send_q_not_full;
    else if( rc == -1 ) {
      if( sinf.stack_locked ) 
        ci_netif_unlock(ni);
      if( j == 0 )
        /* Must invert error sign as functions shared with sendmsg store
         * error as positive 
         */
        msg->rc = -sinf.rc;
      return 1;
    }
  }

  if( ci_tcp_sendmsg_block(ni, ts, flags, &sinf) == 0 )
    goto send_q_not_full;
  else {
    if( sinf.stack_locked ) 
      ci_netif_unlock(ni);
    if( j == 0 )
      /* Must invert error sign as functions shared with sendmsg store
       * error as positive 
       */
      msg->rc = -sinf.rc;
    return 1;
  }


 bad_buffer:
  if(CI_UNLIKELY( ts->tcpflags & CI_TCPT_FLAG_MSG_WARM )) {
    ++ts->stats.tx_msg_warm_abort;
    if( sinf.stack_locked )
      ci_netif_unlock(ni);
    msg->rc = -EINVAL;
    return 1;
  }
  /* First make sure we've got rid of the fill list */
  if( sinf.fill_list ) {
    if( si_trylock(ni, &sinf) ) {
      if( ts->s.tx_errno )
        goto tx_errno;
      ts->send_in += ci_tcp_sendmsg_enqueue(ni, ts,
                                            sinf.fill_list,
                                            sinf.fill_list_bytes,
                                            &ts->send);
      sinf.total_sent += sinf.fill_list_bytes;
      sinf.fill_list = 0;
    } 
    else {
      if( ! ci_tcp_send_via_prequeue(ni, ts, &sinf) )
        goto tx_errno;
      sinf.total_sent += sinf.fill_list_bytes;
    }
  }

  if( j == 0 )
    msg->rc = -EINVAL;
  else
    msg->rc = sinf.total_sent;
  if( sinf.stack_locked )
    ci_netif_unlock(ni);
  return 1;

 tx_errno:
  /* Similar to ci_tcp_sendmsg_handle_tx_errno(), but
   * - no need to free the fill_list: user owns the packets in case of
   *   error;
   * - there are no such thing as "unused_pkts".
   */
  ci_tcp_sendmsg_handle_zero_or_tx_errno(ni, ts, flags, &sinf);
  msg->rc = sinf.set_errno ? -sinf.rc : sinf.rc;
  if( sinf.stack_locked )
    ci_netif_unlock(ni);
  return 1;
}


static int ci_tcp_ds_get_arp(ci_netif* ni, ci_tcp_state* ts)
{
  int i;

  ci_assert(ci_netif_is_locked(ni));

  oo_tcp_ipcache_update(ni, ts);
  if( ts->s.pkt.status == retrrc_success )
    return 1;
  if( ts->s.pkt.status != retrrc_nomac )
    goto fail;

  if( ! ci_ip_queue_is_empty(&ts->retrans) )
    ci_tcp_retrans_one(ts, ni, PKT_CHK(ni, ts->retrans.head));
  else {
    ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(ni, 0);
    if( pkt == NULL )
      goto fail;

    ci_tcp_send_ack(ni, ts, pkt, 0);
  }

  /* We can set up netlink notification, but let's spin for now */
  for( i = 0; i < 1000; i++ ) {
    oo_tcp_ipcache_update(ni, ts);
    if( ts->s.pkt.status == retrrc_success )
      return 1;
    if( ts->s.pkt.status != retrrc_nomac )
      goto fail;
    usleep(1);
  }

fail:
  /* For TCP, we want the ipcache to only be valid when onloadable. */
  ci_ip_cache_invalidate(&ts->s.pkt);
  return 0;
}

#define MAX_HEADERS_LEN                             \
  ( ETH_HLEN + ETH_VLAN_HLEN + sizeof(ci_ip4_hdr) +  \
    0xf * sizeof(ci_uint32) )

enum onload_delegated_send_rc
ci_tcp_ds_fill_headers(ci_netif* ni, ci_tcp_state* ts, unsigned flags,
                       void* headers, int* headers_len_inout,
                       int* ip_tcp_hdr_len_out,
                       int* tcp_seq_offset_out, int* ip_len_offset_out)
{
  int headers_len;
  int ether_header_len;
  ci_tcp_hdr* tcp;
  ci_ip4_hdr* ip;

  /* Get the ARP, validate the packet cache.
   * Packet cache could be used under the stack lock only. */
  ci_assert(ci_netif_is_locked(ni));

  /* Try to get valid cache */
  if( ! oo_cp_ipcache_is_valid(ni, &ts->s.pkt) &&
      (~flags & ONLOAD_DELEGATED_SEND_FLAG_IGNORE_ARP ) &&
      ! ci_tcp_ds_get_arp(ni, ts) ) {
    return ONLOAD_DELEGATED_SEND_RC_NOARP;
  }

  /* Check header length size */
  ether_header_len = ETH_HLEN + ETH_VLAN_HLEN - ts->s.pkt.ether_offset;
  headers_len = ether_header_len + ts->outgoing_hdrs_len;
  ci_assert_le(headers_len, MAX_HEADERS_LEN);

  if( *headers_len_inout < headers_len ) {
    *headers_len_inout = headers_len;
    return ONLOAD_DELEGATED_SEND_RC_SMALL_HEADER;
  }
  *headers_len_inout = headers_len;

  /* Create a "packet" which we are pretending to transmit. */
  memcpy(headers, ci_ip_cache_ether_hdr(&ts->s.pkt), headers_len);

  ip = (void*)((ci_uintptr_t)headers + ether_header_len);
  tcp = (void*)((ci_uintptr_t)headers + ether_header_len + sizeof(ci_ip4_hdr));

  /* tcp_snd_nxt, tcp_rcv_nxt, tsrecent, eff_mss could change after we've
   * passed our header to the user, so there is nothing to do with it. */
  tcp->tcp_seq_be32 = CI_BSWAP_BE32(tcp_snd_nxt(ts));
  tcp->tcp_flags = CI_TCP_FLAG_ACK;
  tcp->tcp_ack_be32 = CI_BSWAP_BE32(tcp_rcv_nxt(ts));
  ci_tcp_calc_rcv_wnd(ts, "ds_fill_headers");
  tcp->tcp_window_be16 = TS_IPX_TCP(ts)->tcp_window_be16;
  if( ts->tcpflags & CI_TCPT_FLAG_TSO ) {
    ci_uint8* opt = CI_TCP_HDR_OPTS(tcp);
    ci_tcp_tx_opt_tso(&opt, ci_tcp_time_now(ni), ts->tsrecent);
  }
  ip->ip_tot_len_be16 =
      CI_BSWAP_BE16(ts->outgoing_hdrs_len + ts->eff_mss);
  ip->ip_id_be16 = 0;
  ci_assert_equal(CI_TCP_HDR_LEN(tcp),
                  ts->outgoing_hdrs_len - sizeof(ci_tcp_hdr));
  ci_assert_equal(ip->ip_check_be16, 0);
  ci_assert_equal(tcp->tcp_check_be16, 0);
  ci_assert_equal(tcp->tcp_urg_ptr_be16, 0);

  /* Get values user asked for: */
  *ip_tcp_hdr_len_out = ts->outgoing_hdrs_len;
  *tcp_seq_offset_out = ether_header_len + sizeof(ci_ip4_hdr) +
                        CI_MEMBER_OFFSET(ci_tcp_hdr, tcp_seq_be32);
  *ip_len_offset_out = ether_header_len +
                       CI_MEMBER_OFFSET(ci_ip4_hdr, ip_tot_len_be16);

  return ONLOAD_DELEGATED_SEND_RC_OK;
}

int
ci_tcp_ds_done(ci_netif* ni, ci_tcp_state* ts,
               const ci_iovec *iov, int iovlen, int flags)
{
  int already_acked, i;
  ci_iovec_ptr piov;
  struct tcp_send_info sinf;
  int last_needed CI_DEBUG(= 0x7fffffff);
  int got = 0;
  int iov_offset = 0;

  sinf.total_unsent = 0;
  sinf.total_sent = 0;
  sinf.stack_locked = 0;
  sinf.rc = 0;
  sinf.pf.alloc_pkt = NULL;
  sinf.timeout = 0; /* ignore ts->s.so.sndtimeo_msec */
  sinf.tcp_send_spin =
    oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_TCP_SEND);
  sinf.fill_list = 0;

  for( i = 0; i < iovlen; ++i )
    sinf.total_unsent += CI_IOVEC_LEN(&iov[i]);

  /* snd_delegated is not protected by the stack lock - the caller must
   * care about it. */
  if( sinf.total_unsent > ts->snd_delegated )
    RET_WITH_ERRNO(EMSGSIZE);

 try_again:
  while( 1 ) {
    if( ! si_trylock(ni, &sinf) ) {
      ci_netif_lock(ni);
      sinf.stack_locked = 1;
    }

    already_acked = SEQ_SUB(ts->snd_una,  ts->snd_nxt);
    /* already_acked > 0  => some of our data is already ACKed;
     * already_acked == 0 => retransmit queue is empty, but our data is not
     *                       acked;
     * already_acked < 0 => retransmit queue is not empty, our data is not
     *                      acked yet. */
    if( already_acked < 0 )
      already_acked = 0;
    if( already_acked > 0 ) {
      already_acked = CI_MIN(already_acked, sinf.total_unsent);

      ts->snd_delegated -= already_acked;
      ts->snd_nxt += already_acked;
      sinf.total_unsent -= already_acked;
      sinf.total_sent += already_acked;
      tcp_enq_nxt(ts) += already_acked;

      /* If iov_offset > 0 it's because some of the data in the iovec was
       * already acked last time we were here.  We ditch any completely
       * acked iovecs, so the offset must be < this iovec's length.
       */
      ci_assert_lt(iov_offset, CI_IOVEC_LEN(iov));

      /* drop already_acked data from iov */
      while( iov_offset + already_acked > CI_IOVEC_LEN(iov) ) {
        already_acked -= (CI_IOVEC_LEN(iov) - iov_offset);
        iov++;
        iovlen--;
        iov_offset = 0;
      }
    }
    if( sinf.total_unsent == 0)
      goto out;

    /* copy data from iov to retransmit queue */
    sinf.sendq_credit = ci_tcp_tx_send_space(ni, ts);

    /* Earlier we dropped entirely-ACKed buffers from the iovec, but we must
     * still account for partial ACKs within the first buffer. The appropriate
     * offset is the sum of already_acked, which counts new ACKs discovered in
     * this loop iteration, and iov_offset, which measures anything already
     * enqueued in a previous iteration.
     */
    ci_iovec_ptr_init_nz(&piov, iov, iovlen);
    ci_iovec_ptr_advance(&piov, already_acked + iov_offset);
    ci_assert(! ci_iovec_ptr_is_empty_proper(&piov));

    if( sinf.sendq_credit <= 0 )  goto send_q_full;

    /* Either:
     *  - we got all the buffers we needed and then used them, so got is 0;
     *  - we didn't get everything we needed, so got < last_needed; or
     *  - we didn't get everything we needed at first, but then made up the
     *    difference from the non-blocking pool and retried, so got ==
     *    last_needed.
     */
    ci_assert_le(got, last_needed);
    last_needed = ci_tcp_send_alloc_pkts(ni, ts, &sinf, got);

    if( sinf.n_needed > 0 )
      goto no_pkt_buf;

    /* got = last_needed here, but if we're here we're definately going to
     * use them, so don't bother setting it.
     */

    /* If we've filled anything it should have been used, we shouldn't get
     * here with some stuff filled.
     */
    ci_assert_equal(sinf.n_filled, 0);

    /* From this point there is nothing that can derail us from either
     * putting these packets on the retransmit queue before anything changes
     * or bailing out completely.
     */
    ci_tcp_send_fill_pkts(ni, ts, &sinf, &piov, last_needed);

    /* All our allocated pkts have been moved to the fill list */
    ci_assert_equal(sinf.n_filled, last_needed);
    got = 0;

    if( ts->s.tx_errno ) {
      ci_assert(! (flags & ONLOAD_MSG_WARM));
      ci_tcp_sendmsg_handle_tx_errno(ni, ts, flags, &sinf);
      if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
      return sinf.rc;
    }
    /* add to retrans q */
    ci_tcp_sendmsg_enqueue(ni, ts, sinf.fill_list, sinf.fill_list_bytes,
                           &ts->retrans);
    sinf.total_sent += sinf.fill_list_bytes;
    sinf.total_unsent -= sinf.fill_list_bytes;
    ts->snd_nxt += sinf.fill_list_bytes;
    ts->snd_delegated -= sinf.fill_list_bytes;
    if( sinf.total_unsent == 0 )
      goto out;

    /* drop enqueued data from iov */
    iov_offset += already_acked + sinf.fill_list_bytes;
    while( iov_offset > CI_IOVEC_LEN(iov) ) {
      iov_offset -= CI_IOVEC_LEN(iov);
      iov++;
      iovlen--;
    }

    /* Stuff left to do -- push out what we've got first. */
    if( ci_netif_may_poll(ni) && ci_netif_need_poll(ni) )
      ci_netif_poll(ni);

    /* Used up all the packets we filled, update sinf */
    sinf.fill_list = 0;
    sinf.n_filled = 0;

    if( ts->s.tx_errno ) {
      ci_tcp_sendmsg_handle_tx_errno(ni, ts, flags, &sinf);
      if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
      return sinf.rc;
    }

    sinf.sendq_credit -= sinf.n_filled;
    if( sinf.sendq_credit <= 0 ) {
      /* It looks like we don't have any credit in the send queue;
       * let's check for sure. */
      sinf.sendq_credit = ci_tcp_tx_send_space(ni, ts);
      if( sinf.sendq_credit <= 0 )  goto send_q_full;
    }
  }


 out:
  ci_assert(sinf.stack_locked);

  /* Set up the retransmit timer if:
   * (1) we've added something to the retrans queue;
   * (2) it was not acked in ci_netif_poll() we call above. */
  if( sinf.total_sent > already_acked && !ci_ip_queue_is_empty(&ts->retrans))
    ci_tcp_rto_check_and_set(ni, ts);

  /* We may have allocated some packets and then found they weren't neeeded.
   * Make sure we free them if so.
   */
  if( got > 0 )
    ci_tcp_sendmsg_free_unused_pkts(ni, &sinf);

  ci_netif_unlock(ni);

  return sinf.total_sent;

send_q_full:
  /* We can't get here easily because we check the ci_tcp_tx_send_space()
   * in citp_tcp_ds_prepare() so testing this code path is difficult.
   * Probably, it is possible to archieve it with MTU shrink. */
  ci_assert_equal(sinf.fill_list, NULL);

  if( ci_netif_may_poll(ni) && ci_netif_need_poll(ni) &&
      si_trylock(ni, &sinf) ) {
    ci_netif_poll(ni);
    if( ts->s.tx_errno ) {
      ci_tcp_sendmsg_handle_tx_errno(ni, ts, flags, &sinf);
      if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
      return sinf.rc;
    }
    sinf.sendq_credit = ci_tcp_tx_send_space(ni, ts);
    if( sinf.sendq_credit > 0 )  goto try_again;

    /* We are pushing our data to retransmit queue; send queue is empty;
     * tx timestamp queue is guaranteed to be disabled.  So, the only
     * non-empty queue is the retransmit one. */
    ci_assert(OO_PP_NOT_NULL(ts->retrans.num));
  }

  if( flags & MSG_DONTWAIT ) {
    sinf.rc = -EAGAIN;
    ci_tcp_sendmsg_handle_sent_or_rc(ni, ts, flags, &sinf);
    if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
    return sinf.rc;
  }

  if( sinf.tcp_send_spin ) {
    int rc;
    rc = ci_tcp_sendmsg_spin(ni, ts, flags, &sinf);
    if( rc == 0 )
      goto try_again;
    else if( rc == -1 ) {
      if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
      return sinf.rc;
    }
    sinf.tcp_send_spin = 0;
  }

  if( ci_tcp_sendmsg_block(ni, ts, flags, &sinf) == 0 )
    goto try_again;
  else {
    if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
    return sinf.rc;
  }

 no_pkt_buf:
  {
    int rc;
    rc = ci_tcp_sendmsg_no_pkt_buf(ni, ts, flags, &sinf);
    if( rc == 0 ) {
      got = last_needed - sinf.n_needed;
      goto try_again;
    }
    else {
      /* Once we've filled some packets we're guaranteed to queue them, so
       * we should never be calling ci_tcp_sendmsg_no_pkt_buf with some
       * packets filled.
       */
      ci_assert(rc == -1);
      if( sinf.set_errno ) CI_SET_ERROR(sinf.rc, sinf.rc);
      return sinf.rc;
    }
  }

}

#endif
#endif

/*! \cidoxg_end */
