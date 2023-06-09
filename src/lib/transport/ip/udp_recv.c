/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  UDP recvmsg() etc.
**   \date  2003/12/29
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

#define _GNU_SOURCE  /* for recvmmsg */

#include "ip_internal.h"
#include "ip_tx_cmsg.h"
#include <onload/osfile.h>
#ifndef __KERNEL__
# include <ci/internal/ip_signal.h>
#endif

#if !defined(__KERNEL__)
#include <sys/socket.h>
#include <onload/extensions_zc.h>
#endif

#if OO_DO_STACK_POLL
#define VERB(x)

#define LPF "ci_udp_"
#define LPFIN LPF
#define LPFOUT LPF

/* Implementation:
**  MSG_PEEK         supported
**  MSG_ERRQUEUE     supported (Linux only)
**  MSG_OOB          not supported (ignored)
**  MSG_WAITALL      supported (as is O_NONBLOCK through fcntl)
**  MSG_NOSIGNAL     not UDP
**  MSG_TRUNC        supported
**
**  Fragmentation is not supported (by netif_event.c functions)
*/


/* Set [MSG_OOB_CHK] to [MSG_OOB] if it should be rejected, or to [0] if it
** should be ignored in UDP recv*() functions.
**
** On Linux, MSG_OOB is ignored.
*/
#define MSG_OOB_CHK	0

#ifdef MSG_ERRQUEUE
# define MSG_ERRQUEUE_CHK	MSG_ERRQUEUE
#else
# define MSG_ERRQUEUE_CHK	0
#endif

#ifndef __KERNEL__
# define HAVE_MSG_FLAGS		1
#else
# define HAVE_MSG_FLAGS		0
#endif

typedef struct {
  ci_udp_iomsg_args *a;
  ci_msghdr* msg;
  int sock_locked;
  int flags;
#if HAVE_MSG_FLAGS
  int msg_flags;
#endif
} ci_udp_recv_info;


ci_inline void ci_udp_recvmsg_fill_msghdr(ci_netif* ni, ci_msghdr* msg,
					  const ci_ip_pkt_fmt* pkt,
					  ci_sock_cmn* s)
{
#ifndef __KERNEL__
  if( msg != NULL ) {
    if( msg->msg_name != NULL ) {
      int af;
      const ci_udp_hdr* udp;
      ci_addr_t saddr;

      if( pkt->flags & CI_PKT_FLAG_INDIRECT )
        pkt = PKT_CHK_NNL(ni, pkt->frag_next);
      af = oo_pkt_af(pkt);
      udp = oo_ipx_data(af, (ci_ip_pkt_fmt*)pkt);
      saddr = RX_PKT_SADDR((ci_ip_pkt_fmt*)pkt);

#if CI_CFG_IPV6
      if( CI_IPX_IS_LINKLOCAL(saddr) )
        s->cp.so_bindtodevice = ci_rx_pkt_ifindex(ni, pkt);
#endif

      ci_addr_to_user(CI_SA(msg->msg_name), &msg->msg_namelen, af, s->domain,
                      udp->udp_source_be16, CI_IPX_ADDR_PTR(af, saddr),
                      s->cp.so_bindtodevice);
    }
  }
#endif
}


static int
oo_copy_pkt_to_iovec_no_adv(ci_netif* ni, const ci_ip_pkt_fmt* pkt,
                            ci_iovec_ptr* piov, int bytes_to_copy)
{
  /* Copy data from [pkt] to [piov], following [pkt->frag_next] as
   * necessary.  Does not modify [pkt].  May or may not advance [piov].
   * The packet must contain at least [bytes_to_copy] of data in the
   * [pkt->buf].  [piov] may contain an arbitrary amount of space.
   *
   * Returns number of bytes copied on success, or -EFAULT otherwise.
   */
  int rc;
  struct oo_copy_state ocs;
  ocs.bytes_copied = 0;
  ocs.bytes_to_copy = bytes_to_copy;
  ocs.pkt_off = 0;
  ocs.pkt = pkt;

  while( 1 ) {
    ocs.pkt_left = oo_offbuf_left(&(ocs.pkt->buf)) - ocs.pkt_off;
    ocs.from = oo_offbuf_ptr(&(ocs.pkt->buf));
    rc = __oo_copy_frag_to_iovec_no_adv(ni, piov, &ocs);
    if( rc == 0 )
      return ocs.bytes_copied;
    else if( rc == 1 )
      continue;
    else if( rc < 0 )
      return rc;
    else
      ci_assert(0);
  }
}


#ifndef __KERNEL__
/* Max number of iovecs needed:
 * = max_datagram / (min_mtu - udp_header)
 * = 65536 / (576 - 28) 
 * = 120
 */
#define CI_UDP_ZC_IOVEC_MAX 120

static void ci_udp_pkt_to_zc_msg(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                 struct onload_zc_msg* zc_msg)
{
  int i, bytes_left = pkt->pf.udp.pay_len;
  ci_ip_pkt_fmt* frag;
  ci_ip_pkt_fmt* handle_frag;

  handle_frag = frag = pkt;
  i = 0;
  ci_assert_nequal(zc_msg->iov, NULL);

  /* Ignore first frag if zero length and there is another frag, but
   * still pass the zero-length buffer as the onload_zc_handle so it
   * will get freed correctly
   */
  if( oo_offbuf_left(&frag->buf) == 0 && OO_PP_NOT_NULL(frag->frag_next) )
    frag = PKT_CHK_NNL(ni, frag->frag_next);

  handle_frag->user_refcount = CI_ZC_USER_REFCOUNT_ONE;
  do {
    zc_msg->iov[i].iov_len = CI_MIN(oo_offbuf_left(&frag->buf), 
                                    bytes_left);
    zc_msg->iov[i].iov_base = oo_offbuf_ptr(&frag->buf);
    zc_msg->iov[i].buf = zc_pktbuf_to_handle(handle_frag);
    zc_msg->iov[i].iov_flags = 0;
    zc_msg->iov[i].addr_space = EF_ADDRSPACE_LOCAL;
    bytes_left -= zc_msg->iov[i].iov_len;
    ++i;
    if( OO_PP_IS_NULL(frag->frag_next) || 
        (i == CI_UDP_ZC_IOVEC_MAX) ||
        (bytes_left == 0) )
      break;
    frag = PKT_CHK_NNL(ni, frag->frag_next);
    handle_frag = frag;
  } while( 1 );
  zc_msg->msghdr.msg_iovlen = i;
}

# if CI_CFG_ZC_RECV_FILTER
static void ci_udp_filter_kernel_pkt(ci_netif* ni, ci_udp_state* us,
                                     struct msghdr* msg, int *bytes)
{
  enum onload_zc_callback_rc rc;
  struct onload_zc_msg zc_msg;
  struct onload_zc_iovec zc_iovec[CI_UDP_ZC_IOVEC_MAX];
  unsigned cb_flags = 0;
  int i = 0, bytes_remaining = *bytes;

  if( msg->msg_iovlen > CI_UDP_ZC_IOVEC_MAX ) {
    LOG_U(log("%s: too many fragments (%d), passing packet unfiltered",
              __FUNCTION__, (int)msg->msg_iovlen));
    return;
  }

  zc_msg.iov = zc_iovec;
  zc_msg.msghdr = *msg;
  zc_msg.msghdr.msg_iov = NULL;

  ci_assert_gt(msg->msg_iovlen, 0);

  do {
    zc_msg.iov[i].iov_base = msg->msg_iov[i].iov_base;
    zc_msg.iov[i].iov_len = msg->msg_iov[i].iov_len > bytes_remaining ?
      bytes_remaining : msg->msg_iov[i].iov_len;
    zc_msg.iov[i].buf = ONLOAD_ZC_HANDLE_NONZC;
    zc_msg.iov[i].iov_flags = 0;
    bytes_remaining -= zc_msg.iov[i].iov_len;
  } while(++i < msg->msg_iovlen && bytes_remaining);

  zc_msg.msghdr.msg_iovlen = i;

  rc = (*(onload_zc_recv_filter_callback)((ci_uintptr_t)us->recv_q_filter))
    (&zc_msg, (void *)((ci_uintptr_t)us->recv_q_filter_arg), cb_flags);

  ci_assert_equal(rc, ONLOAD_ZC_CONTINUE);
  (void)rc;
}
# endif
#endif /* __KERNEL__ */


static int ci_udp_recvmsg_get(ci_udp_recv_info* rinf, ci_iovec_ptr* piov)
{
  ci_netif* ni = rinf->a->ni;
  ci_udp_state* us = rinf->a->us;
  ci_msghdr* msg = rinf->msg;
  ci_ip_pkt_fmt* pkt;
  int rc;

  /* NB. [msg] can be NULL for async recv. */

  if( (pkt = ci_udp_recv_q_get(ni, &us->recv_q)) == NULL )
    goto recv_q_is_empty;

#ifndef __KERNEL__
  if( msg != NULL ) {
    if( CI_UNLIKELY(us->s.cmsg_flags != 0 ) )
      ci_ip_cmsg_recv(ni, us, pkt, msg, 0, &rinf->msg_flags);
    else
      msg->msg_controllen = 0;
  }
#endif
  us->stamp = pkt->tstamp_frc;
  us->future_intf_i = pkt->intf_i;

  rc = oo_copy_pkt_to_iovec_no_adv(ni, pkt, piov, pkt->pf.udp.pay_len);

  if(CI_LIKELY( rc >= 0 )) {
#if HAVE_MSG_FLAGS
    if(CI_UNLIKELY( rc < pkt->pf.udp.pay_len )) {
      if( msg != NULL )
        rinf->msg_flags |= LOCAL_MSG_TRUNC;
      if( rinf->flags & MSG_TRUNC )
        rc = pkt->pf.udp.pay_len;
    }
#endif
    ci_udp_recvmsg_fill_msghdr(ni, msg, pkt, &us->s);
    if( ! (rinf->flags & MSG_PEEK) ) {
#ifndef __KERNEL__
# if CI_CFG_ZC_RECV_FILTER
      if( us->recv_q_filter ) {
        struct onload_zc_msg zc_msg;
        struct onload_zc_iovec zc_iovec[CI_UDP_ZC_IOVEC_MAX];
        unsigned cb_flags;
        int filterrc;

        zc_msg.iov = zc_iovec;
        zc_msg.msghdr.msg_controllen = 0;
        zc_msg.msghdr.msg_flags = 0;

        ci_udp_pkt_to_zc_msg(ni, pkt, &zc_msg);

        cb_flags = CI_IP_IS_MULTICAST(oo_ip_hdr(pkt)->ip_daddr_be32) ?
          ONLOAD_ZC_MSG_SHARED : 0;
        filterrc =
          (*(onload_zc_recv_filter_callback)((ci_uintptr_t)us->recv_q_filter))
            (&zc_msg, (void *)((ci_uintptr_t)us->recv_q_filter_arg), cb_flags);

        ci_assert_equal(filterrc, ONLOAD_ZC_CONTINUE);
        (void)filterrc;
        pkt->pio_addr = -1;
      }
# endif
#endif

      ci_udp_recv_q_deliver(ni, &us->recv_q, pkt);
    }
    us->udpflags |= CI_UDPF_LAST_RECV_ON;
  }

  return rc;

 recv_q_is_empty:
  return -EAGAIN;
}


#ifndef __KERNEL__

static int __ci_udp_recvmsg_try_os(ci_netif *ni, ci_udp_state *us,
                                   struct msghdr* msg, int flags, int* prc)
{
  int rc;

  rc = oo_os_sock_recvmsg(ni, SC_SP(&us->s), msg, flags | MSG_DONTWAIT);

  if( rc >= 0 ) {
    ++us->stats.n_rx_os;
    us->udpflags &= ~CI_UDPF_LAST_RECV_ON;
    if( ! (flags & MSG_PEEK) )
      us->udpflags &=~ CI_UDPF_PEEK_FROM_OS;
    else
      us->udpflags |=  CI_UDPF_PEEK_FROM_OS;
  }
  else {
    if( rc == -EAGAIN )
      return 0;
    CI_SET_ERROR(rc, -rc);
    ++us->stats.n_rx_os_error;
  }

  *prc = rc;
  return 1;
}

#else  /* __KERNEL__ */

static int __ci_udp_recvmsg_try_os(ci_netif *ni, ci_udp_state *us,
                                   ci_msghdr* msg, int flags, int* prc)
{
  int rc, total_bytes, i;
  tcp_helper_endpoint_t *ep = ci_netif_ep_get(ni, us->s.b.bufid);
  struct socket *sock;
  oo_os_file os_sock;
  struct msghdr kmsg;

  total_bytes = 0;
  for( i = 0; i < msg->msg_iovlen; ++i )
    total_bytes += msg->msg_iov[i].iov_len;
  rc = -EMSGSIZE;
  if( total_bytes < 0 )
    return -EINVAL;

  rc = oo_os_sock_get_from_ep(ep, &os_sock);
  if( rc != 0 )
    return rc;
  ci_assert(S_ISSOCK(os_sock->f_path.dentry->d_inode->i_mode));
  sock = SOCKET_I(os_sock->f_path.dentry->d_inode);
  ci_assert(sock);

  oo_msg_iov_init(&kmsg, READ, msg->msg_iov, msg->msg_iovlen, total_bytes);
  /* We are in read/readv syscall, because recvfrom/recvmsg return
   * -ENOTSOCK immediately.  So, we are not interested in address or
   * control data. */
  kmsg.msg_namelen = 0;
  kmsg.msg_name = NULL;
  kmsg.msg_controllen = 0;
  rc = sock_recvmsg(sock, &kmsg, flags | MSG_DONTWAIT);
  /* Clear OS RX flag if we've got everything  */
  oo_os_sock_status_bit_clear_handled(ep, os_sock, OO_OS_STATUS_RX);
  oo_os_sock_put(os_sock);

  if( rc >= 0 ) {
    ++us->stats.n_rx_os;
  }
  else {
    if( rc == -EAGAIN )
      return 0;
    ++us->stats.n_rx_os_error;
  }

  if( rc >= 0 ) {
    us->udpflags &= ~CI_UDPF_LAST_RECV_ON;
    if( ! (flags & MSG_PEEK) )
      us->udpflags &=~ CI_UDPF_PEEK_FROM_OS;
    else
      us->udpflags |=  CI_UDPF_PEEK_FROM_OS;
  }
  *prc = rc;
  return 1;
}

#endif  /* __KERNEL__ */

static int ci_udp_recvmsg_try_os(ci_udp_recv_info *rinf, int* prc)
{
  ci_udp_state *us = rinf->a->us;
  int rc;

  if( !(us->s.os_sock_status & OO_OS_STATUS_RX) )
    return 0;
  rc = __ci_udp_recvmsg_try_os(rinf->a->ni, us, rinf->msg, rinf->flags, prc);
#if HAVE_MSG_FLAGS
  /* In case of non-negative rc, we copy msg_flags from rinf->msg_flags.
   * Here we should copy the flags back to ensure we end up with the
   * correct value. */
  if( rc >= 0 )
    rinf->msg_flags = rinf->msg->msg_flags;
#endif

#ifndef __KERNEL__
# if CI_CFG_ZC_RECV_FILTER
  if( us->recv_q_filter && rc == 1 && *prc >= 0)
    ci_udp_filter_kernel_pkt(rinf->a->ni, us, rinf->msg, prc);
# endif
#endif

  return rc;
}


static int ci_udp_recvmsg_socklocked_slowpath(ci_udp_recv_info* rinf,
                                              ci_iovec_ptr *piov)
{
  int rc = 0;
  ci_netif* ni = rinf->a->ni;
  ci_udp_state* us = rinf->a->us;

  if(CI_UNLIKELY( ni->state->rxq_low ))
    ci_netif_rxq_low_on_recv(ni, &us->s,
                             1 /* assume at least one pkt freed */);
  /* In the kernel recv() with flags is not called.
   * only read(). So flags may only contain MSG_DONTWAIT */
#ifdef __KERNEL__
  ci_assert_equal(rinf->flags, 0);
#endif

  if( rinf->msg->msg_iovlen > 0 && rinf->msg->msg_iov == NULL ) {
    CI_SET_ERROR(rc, EFAULT);
    return rc;
  }

#ifndef __KERNEL__
  if( rinf->flags & MSG_ERRQUEUE_CHK ) {
#if CI_CFG_TIMESTAMPING
    ci_ip_pkt_fmt* pkt;
    if( (pkt = ci_udp_recv_q_get(ni, &us->timestamp_q)) != NULL ) {
      struct cmsg_state cmsg_state;

      cmsg_state.msg = rinf->msg;
      cmsg_state.cm = rinf->msg->msg_control;
      cmsg_state.cmsg_bytes_used = 0;
      cmsg_state.p_msg_flags = &rinf->msg_flags;

      rc = ci_ip_tx_timestamping_to_cmsg(IPPROTO_UDP, ni, pkt, &us->s,
                                         &cmsg_state, piov);

      ci_rmb(); /* we are done with pkt - somebody can free it now */
      ci_udp_recv_q_deliver(ni, &us->timestamp_q, pkt);

      ci_ip_cmsg_finish(&cmsg_state);
      rinf->msg_flags |= MSG_ERRQUEUE_CHK;
      return rc;
    }
#endif
    /* ICMP is handled via OS, so get OS error */
    rc = oo_os_sock_recvmsg(ni, SC_SP(&us->s), rinf->msg, rinf->flags);
    if( rc < 0 ) {
      RET_WITH_ERRNO(-rc);
    }
    else {
      rinf->msg_flags = rinf->msg->msg_flags;
      return rc == 0 ? SLOWPATH_RET_ZERO : rc;
    }
  }
#endif
  if( (rc = ci_get_so_error(&us->s)) != 0 ) {
    CI_SET_ERROR(rc, rc);
    return rc;
  }
#if MSG_OOB_CHK
  if( rinf->flags & MSG_OOB_CHK ) {
    CI_SET_ERROR(rc, EOPNOTSUPP);
    return rc;
  }
#endif
#if CI_CFG_POSIX_RECV  
  if( ! udp_lport_be16(us)) {
    LOG_UV(log("%s: -1 (ENOTCONN)", __FUNCTION__));
    CI_SET_ERROR(rc, ENOTCONN);
    return rc;
  }
#endif
  if( rinf->msg->msg_iovlen == 0 ) {
    /* We initialise piov and will ask OS or Onload for data.  They both
     * will probably set MSG_TRUNC. */
    CI_IOVEC_LEN(&piov->io) = piov->iovlen = 0;
    return SLOWPATH_RET_IOVLEN_INITED;
  }
  return 0;
}


struct recvmsg_spinstate {
  ci_uint64 start_frc;
  ci_uint64 schedule_frc;
  ci_uint64 max_spin;
  int do_spin;
  int spin_limit_by_so;
  ci_uint32 timeout;
#ifndef __KERNEL__
  uint32_t poison;
  const volatile uint32_t* future;
  citp_signal_info* si;
#endif
};


static int 
ci_udp_recvmsg_block(ci_udp_iomsg_args* a, ci_netif* ni, ci_udp_state* us,
                     int timeout)
{
  int rc;

#ifndef __KERNEL__
  {
    citp_signal_info* si;
    struct pollfd pfd;
    int inside_lib;
    pfd.fd = a->fd;
    pfd.events = POLLIN;

    if( timeout == 0 )
      timeout = -1;

    /* Ideally, we should do the same as in citp_tcp_accept(), but since
     * we do not have lib_context and citp_exit_lib() out of unix/
     * subdirectory, we copy it contents. */
    si = citp_signal_get_specific_inited();
  continue_to_block:
    inside_lib = oo_exit_lib_temporary_begin(si);
    rc = ci_sys_poll(&pfd, 1, timeout);
    oo_exit_lib_temporary_end(si, inside_lib);

    if( rc > 0 )
      return 0;
    else if( rc == 0 )
      rc = -EAGAIN;
    else if( errno == EINTR && (si->c.aflags & OO_SIGNAL_FLAG_NEED_RESTART) &&
             timeout == -1 ) {
      /* Blocking recv() should only be restarted if there is no timeout. */
      goto continue_to_block;
    } else 
      rc = -errno;

    return rc;
  }
#else  /* __KERNEL__ */
  {
    int mask;
    s64 t;

    if( timeout == 0 )
      t = -1;
    else
      t = msecs_to_jiffies(timeout);

    mask = POLLIN;
    rc = efab_tcp_helper_poll_udp(a->filp, &mask, &t);
    if( rc == 0 ) {
      if( mask ) {
        return 0;
      }
      else
        rc = -EAGAIN;
    }
    else if( rc == -ERESTARTSYS &&  us->s.so.rcvtimeo_msec )
      rc = -EINTR;
  }
  return rc;
#endif /* __KERNEL__ */
}


ci_inline int
ci_udp_recvmsg_socklocked_spin(ci_netif* ni, ci_udp_state* us,
                               struct recvmsg_spinstate* spin_state)
{
  ci_uint64 now_frc;

  ci_frc64(&now_frc);
  if( now_frc - spin_state->start_frc < spin_state->max_spin ) {
#if CI_CFG_SPIN_STATS
    ni->state->stats.spin_udp_recv++;
#endif
    if( ci_netif_may_poll(ni) ) {
#ifndef __KERNEL__
      if( spin_state->future == &spin_state->poison )
        spin_state->future = ci_netif_intf_rx_future(ni, us->future_intf_i,
                                                     &spin_state->poison);

      if( *spin_state->future != CI_PKT_RX_POISON && ci_netif_trylock(ni) ) {
        if( ! ci_netif_poll_intf_future(ni, us->future_intf_i, now_frc) ) {
          /* If PftF failed (e.g. IPv6) then we still need to be able to
           * consume the packet (it might not be in the evq just yet, but it
           * will be one of these times) */
          ci_netif_poll(ni);
        }
        ci_netif_unlock(ni);
        spin_state->future = &spin_state->poison;
        return 0;
      }
#endif
      if( ni->state->poll_work_outstanding ||
          ci_netif_need_poll_spinning(ni, now_frc) )
        if( ci_netif_trylock(ni) ) {
          ci_netif_poll(ni);
          ci_netif_unlock(ni);
#ifndef __KERNEL__
          spin_state->future = &spin_state->poison;
#endif
        }
      if( ! ni->state->is_spinner )
        ni->state->is_spinner = 1;
    }
    return OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, 
                                           &spin_state->schedule_frc,
                                           us->s.so.rcvtimeo_msec,
                                           &us->s.b, spin_state->si);
  }
  else {
    if( spin_state->spin_limit_by_so ) {
      ++us->stats.n_rx_eagain;
      return -EAGAIN;
    }

    if( spin_state->timeout ) {
      ci_uint32 spin_ms = NI_OPTS(ni).spin_usec >> 10;
      if( spin_ms < spin_state->timeout )
        spin_state->timeout -= spin_ms;
      else {
        ++us->stats.n_rx_eagain;
        return -EAGAIN;
      }
    }
    spin_state->do_spin = 0;
  }

  ni->state->is_spinner = 0;
  return 1;
}


static int 
ci_udp_recvmsg_common(ci_udp_recv_info *rinf)
{
  ci_netif* ni = rinf->a->ni;
  ci_udp_state* us = rinf->a->us;
  int have_polled = 0;
  ci_iovec_ptr  piov = {NULL,0, {NULL, 0}};
  int rc = 0, slow;
  struct recvmsg_spinstate spin_state = {0};

#ifndef __KERNEL__
  spin_state.do_spin = -1;
  spin_state.si = citp_signal_get_specific_inited();
#endif
  spin_state.timeout = us->s.so.rcvtimeo_msec;

  /* Grab the per-socket lock so we can access the receive queue. */
  if( !rinf->sock_locked ) {
    rc = ci_sock_lock(ni, &us->s.b);
    if(CI_UNLIKELY( rc != 0 )) {
      CI_SET_ERROR(rc, -rc);
      return rc;
    }
    rinf->sock_locked = 1;
  }

#if HAVE_MSG_FLAGS
  rinf->msg_flags = 0;
#endif

  slow = ((rinf->flags & (MSG_OOB_CHK | MSG_ERRQUEUE_CHK)) |
	  (rinf->msg->msg_iovlen == 0              ) |
	  (rinf->msg->msg_iov == NULL              ) |
	  (ni->state->rxq_low                      ) |
#if CI_CFG_POSIX_RECV  
	  (udp_lport_be16(us) == 0                 ) |
#endif
	  (us->s.so_error                          ));
  if( slow )
    goto slow_path;

 back_to_fast_path:
  ci_iovec_ptr_init_nz(&piov, rinf->msg->msg_iov, rinf->msg->msg_iovlen);
  
 piov_inited:
  if(CI_UNLIKELY( us->udpflags & CI_UDPF_PEEK_FROM_OS ))
    goto peek_from_os;

 check_ul_recv_q:
  rc = ci_udp_recvmsg_get(rinf, &piov);
  if( rc >= 0 )
    goto out;

  /* User-level receive queue is empty. */

  if( ! have_polled ) {
    have_polled = 1;
    ci_frc64(&spin_state.start_frc);

    if( ci_netif_may_poll(ni) &&
        ci_netif_need_poll_spinning(ni, spin_state.start_frc) &&
        ci_netif_trylock(ni) ) {
      int any_evs = ci_netif_poll(ni);
      if( ci_udp_recv_q_is_empty(&us->recv_q) && any_evs )
        ci_netif_poll(ni);
      ci_netif_unlock(ni);
      if( ci_udp_recv_q_not_empty(&us->recv_q) )
        goto check_ul_recv_q;
    }
  }

  if(CI_UNLIKELY( (rc = UDP_RX_ERRNO(us)) )) {
    CI_SET_ERROR(rc, rc);
    us->s.rx_errno = us->s.rx_errno & 0xf0000000;
    goto out;
  }
  if(CI_UNLIKELY( us->s.so_error )) {
    int rc1 = ci_get_so_error(&us->s);
    if( rc1 != 0 ) {
      CI_SET_ERROR(rc, rc1);
      goto out;
    }
  }

  /* Nothing doing at userlevel.  Need to check the O/S socket. */
  if( ci_udp_recvmsg_try_os(rinf, &rc) )
    goto out;

  if( ((rinf->flags | us->s.b.sb_aflags) & MSG_DONTWAIT)) {
    /* UDP returns EAGAIN when non-blocking even when shutdown. */
    CI_SET_ERROR(rc, EAGAIN);
    ++us->stats.n_rx_eagain;
    goto out;
  }
  else if (UDP_IS_SHUT_RD(us)) {
    /* Blocking and shutdowned */
    rc = 0;
    goto out;
  }

  /* We need to block (optionally spinning first). */

#ifndef __KERNEL__    
  /* -1 is special value for uninitialised */
  if( spin_state.do_spin == -1 ) {
    spin_state.do_spin = 
      oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_UDP_RECV);

    if( spin_state.do_spin ) {
      spin_state.poison = CI_PKT_RX_POISON;
      spin_state.future = &spin_state.poison;
      spin_state.schedule_frc = spin_state.start_frc;
      spin_state.max_spin = us->s.b.spin_cycles;
      if( us->s.so.rcvtimeo_msec ) {
        ci_uint64 max_so_spin = (ci_uint64)us->s.so.rcvtimeo_msec *
            IPTIMER_STATE(ni)->khz;
        if( max_so_spin <= spin_state.max_spin ) {
          spin_state.max_spin = max_so_spin;
          spin_state.spin_limit_by_so = 1;
        }
      }
    }
  }

  if( spin_state.do_spin ) {
    rc = ci_udp_recvmsg_socklocked_spin(ni, us, &spin_state);
    if( rc == 0 )
      goto check_ul_recv_q;
    else if( rc < 0 ) {
      CI_SET_ERROR(rc, -rc);
      goto out;
    }
  }
#endif

  ci_sock_unlock(ni, &us->s.b);
  rinf->sock_locked = 0;
  rc = ci_udp_recvmsg_block(rinf->a, ni, us, spin_state.timeout);
  if( rc == 0 ) {
    if( !rinf->sock_locked )
      rc = ci_sock_lock(ni, &us->s.b);
  }
  if( rc == 0 ) {
    rinf->sock_locked = 1;
    goto check_ul_recv_q;
  }
  CI_SET_ERROR(rc, -rc);

 out:
  ni->state->is_spinner = 0;
  return rc;

 slow_path:
  rc = ci_udp_recvmsg_socklocked_slowpath(rinf, &piov);
  if( rc == 0 ) 
    goto back_to_fast_path;
  else if( rc == SLOWPATH_RET_IOVLEN_INITED )
    goto piov_inited;
  else if( rc == SLOWPATH_RET_ZERO ) {
    rc = 0;
    goto out;
  }
  else
    goto out;

 peek_from_os:
  if( ci_udp_recvmsg_try_os(rinf, &rc) )
    goto out;
  
  goto check_ul_recv_q;
}


int ci_udp_recvmsg(ci_udp_iomsg_args *a, ci_msghdr* msg, int flags)
{
  ci_netif* ni = a->ni;
  ci_udp_state* us = a->us;
  int rc;
  ci_udp_recv_info rinf;

  rinf.a = a;
  rinf.msg = msg;
  rinf.sock_locked = 0;
  rinf.flags = flags;

  rc = ci_udp_recvmsg_common(&rinf);
  if( rinf.sock_locked )
    ci_sock_unlock(ni, &us->s.b);
#if HAVE_MSG_FLAGS
  if( rc >= 0 )
    msg->msg_flags = rinf.msg_flags;
#endif

  return rc;
}


#ifndef __KERNEL__
int ci_udp_recvmmsg(ci_udp_iomsg_args *a, struct mmsghdr* mmsg, 
                    unsigned int vlen, int flags, 
                    const struct timespec* timeout)
{
  ci_netif* ni = a->ni;
  ci_udp_state* us = a->us;
  int rc, i;
  struct timeval tv_before;
  int timeout_msec = -1;
  ci_udp_recv_info rinf;

  rinf.a = a;
  rinf.sock_locked = 0;
  rinf.flags = flags;

  if( timeout ) {
    timeout_msec = timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000;
    gettimeofday(&tv_before, NULL);
  }

  i = 0;
  while( i < vlen ) {
    rinf.msg = &mmsg[i].msg_hdr;
    rc = ci_udp_recvmsg_common(&rinf);
    if( rc >= 0 ) {
      mmsg[i].msg_len = rc;
#if HAVE_MSG_FLAGS
      mmsg[i].msg_hdr.msg_flags = rinf.msg_flags;
#endif
    }
    else {
      if( i != 0 && errno != EAGAIN )
        us->s.so_error = errno;
      if( rinf.sock_locked )
        ci_sock_unlock(ni, &us->s.b);
      if( i != 0 )
        return i;
      else
        return rc;
    }

    if( ( rinf.flags & MSG_DONTWAIT ) && rc == 0 )
      break;

    if( rinf.flags & MSG_WAITFORONE )
      rinf.flags |= MSG_DONTWAIT;

    ++i;

    if( timeout_msec >= 0 ) {
      struct timeval tv_after, tv_sub;
      gettimeofday(&tv_after, NULL);
      /* Ignore any time where time seems to have gone backwards */
      if( timercmp(&tv_before, &tv_after, <) ) {
        timersub(&tv_after, &tv_before, &tv_sub);
        timeout_msec -= tv_sub.tv_sec * 1000 + tv_sub.tv_usec / 1000;
        if( timeout_msec < 0 )
          break;
      }
      tv_before = tv_after;
    }
  }

  if( rinf.sock_locked )
    ci_sock_unlock(ni, &us->s.b);
  
  return i;
}
#endif


#ifndef __KERNEL__

static int ci_udp_zc_recv_from_os(ci_netif* ni, ci_udp_state* us,
                                  struct onload_zc_recv_args* args, 
                                  enum onload_zc_callback_rc* cb_rc)
{
#define ZC_BUFFERS_FOR_64K_DATAGRAM                                     \
  ((0x10000 / (CI_CFG_PKT_BUF_SIZE -                                    \
               CI_MEMBER_OFFSET(ci_ip_pkt_fmt, dma_start))) + 1)

  int rc, i, cb_flags;
  struct msghdr msg;
  struct iovec iov[ZC_BUFFERS_FOR_64K_DATAGRAM];
  struct onload_zc_iovec zc_iov[ZC_BUFFERS_FOR_64K_DATAGRAM];
  oo_pkt_p pkt_p, first_pkt_p;
  ci_ip_pkt_fmt* pkt;

  ci_assert_le(us->zc_kernel_datagram_count, ZC_BUFFERS_FOR_64K_DATAGRAM);

  if( us->zc_kernel_datagram_count < ZC_BUFFERS_FOR_64K_DATAGRAM) {
    if( us->zc_kernel_datagram_count == 0 )
      ci_assert_equal(us->zc_kernel_datagram, OO_PP_NULL);

    /* We've not come this way before, or we've handed some buffers from a
     * previous iteration to the application, so allocate enough packet bufs to
     * hold max size UDP datagram.
     */
    ci_netif_lock(ni);
    while( us->zc_kernel_datagram_count < ZC_BUFFERS_FOR_64K_DATAGRAM ) {
      pkt = ci_netif_pkt_alloc(ni, 0);
      if( !pkt ) {
        ci_netif_unlock(ni);
        return -ENOBUFS;
      }
      pkt->flags |= CI_PKT_FLAG_RX;
      ++ni->state->n_rx_pkts;
      pkt->frag_next = us->zc_kernel_datagram;
      us->zc_kernel_datagram = OO_PKT_P(pkt);
      ++us->zc_kernel_datagram_count;
    }
    ci_netif_unlock(ni);
  }

  pkt_p = us->zc_kernel_datagram;
  i = 0;
  while( OO_PP_NOT_NULL(pkt_p) ) {
#ifndef NDEBUG
    ci_assert_lt(i, us->zc_kernel_datagram_count);
#endif
    pkt = PKT_CHK_NNL(ni, pkt_p);
    iov[i].iov_base = pkt->dma_start;
    iov[i].iov_len = (CI_CFG_PKT_BUF_SIZE -
                      ((char *)pkt->dma_start - (char*)pkt));
    ++i;
    pkt_p = pkt->frag_next;
  }

  msg.msg_iov = iov;
  msg.msg_iovlen = i;
  msg.msg_control = args->msg.msghdr.msg_control;
  msg.msg_controllen = args->msg.msghdr.msg_controllen;
  msg.msg_name = args->msg.msghdr.msg_name;
  msg.msg_namelen = args->msg.msghdr.msg_namelen;
  msg.msg_flags = 0;

  ci_assert(us->s.os_sock_status & OO_OS_STATUS_RX);
  i = __ci_udp_recvmsg_try_os(ni, us, &msg, 
                              args->flags & ONLOAD_ZC_RECV_FLAGS_PTHRU_MASK,
                              &rc);
  ci_assert_equal(i, 1); /* should be data on the OS socket */
  if(CI_UNLIKELY( rc < 0 )) return rc;

  /* We now have to translate the result from OS recvmsg - stored as
   * an iovec - into something we can pass to the callback, stored in
   * the caller's onload_zc_iovec 
   */
  
  i = 0;
  pkt_p = us->zc_kernel_datagram;
  do {
#ifndef NDEBUG
    ci_assert_lt(i, us->zc_kernel_datagram_count);
#endif
    pkt = PKT_CHK_NNL(ni, pkt_p);
    zc_iov[i].iov_len = rc > iov[i].iov_len ? iov[i].iov_len : rc;
    zc_iov[i].iov_base = iov[i].iov_base;
    zc_iov[i].buf = zc_pktbuf_to_handle(pkt);
    zc_iov[i].addr_space = EF_ADDRSPACE_LOCAL;

    rc -= zc_iov[i].iov_len;
    ++i;
    pkt_p = pkt->frag_next;
  } while (rc > 0);

  /* Clear last packet's frag_next in chain we're passing to callback.
   * We'll restore it later if they don't keep the buffers  
   */
  pkt->frag_next = OO_PP_NULL;
  /* pkt_p handily points to the buffer after the last one used for
   * this datagram, and i is the number of buffers we used.  Remove
   * them from the zc_kernel_datagram list
   */
  first_pkt_p = us->zc_kernel_datagram;
  PKT_CHK_NNL(ni, first_pkt_p)->user_refcount = CI_ZC_USER_REFCOUNT_ONE;
  us->zc_kernel_datagram = pkt_p;
#ifndef NDEBUG
  ci_assert_ge(us->zc_kernel_datagram_count, i);
#endif
  us->zc_kernel_datagram_count -= i;

  args->msg.iov = zc_iov;
  args->msg.msghdr.msg_iovlen = i;
  args->msg.msghdr.msg_control = msg.msg_control;
  args->msg.msghdr.msg_controllen = msg.msg_controllen;
  args->msg.msghdr.msg_name = msg.msg_name;
  args->msg.msghdr.msg_namelen = msg.msg_namelen;
  args->msg.msghdr.msg_flags = msg.msg_flags;

  cb_flags = 0;
  if( (ci_udp_recv_q_pkts(&us->recv_q) == 0) && 
      (us->s.os_sock_status & OO_OS_STATUS_RX) == 0 )
    cb_flags |= ONLOAD_ZC_END_OF_BURST;

  /* Beware - as soon as we provide the pkts to the callback we can't 
   * touch them anymore as we don't know what the app might be doing with
   * them, such as releasing them.
   */
  *cb_rc = (*args->cb)(args, cb_flags);

  if( !((*cb_rc) & ONLOAD_ZC_KEEP) ) {
#ifndef NDEBUG
  /* Check the integrity of the list structure on the packets that we passed to
   * the application. */
    int app_packet_count = 0;
    pkt_p = first_pkt_p;
    while( OO_PP_NOT_NULL(pkt_p) ) {
      ci_assert_lt(app_packet_count, i);
      ci_assert_nequal(pkt_p, us->zc_kernel_datagram);
      pkt = PKT_CHK_NNL(ni, pkt_p);
      ++app_packet_count;
      pkt_p = pkt->frag_next;
    }
    ci_assert_equal(app_packet_count, i);
#endif

    /* Put the buffers back on the zc_kernel_datagram list */
    PKT_CHK_NNL(ni, first_pkt_p)->pio_addr = -1;
    pkt->frag_next = us->zc_kernel_datagram;
    us->zc_kernel_datagram = first_pkt_p;
    us->zc_kernel_datagram_count += i;
  }

  ci_assert_le(us->zc_kernel_datagram_count, ZC_BUFFERS_FOR_64K_DATAGRAM);

  if( cb_flags & ONLOAD_ZC_END_OF_BURST ) {
    /* If we've advertised an end of burst, we should return to match
     * receive-via-Onload behaviour.  Note this assumes that setting
     * ONLOAD_ZC_TERMINATE clears ONLOAD_ZC_CONTINUE, and that
     * done_big_poll = 1 and done_kernel_poll = 1 in calling function
     */
    (*cb_rc) |= ONLOAD_ZC_TERMINATE;
    ci_assert(((*cb_rc) & ONLOAD_ZC_CONTINUE) == 0);
  }

  return 0;
}


int ci_udp_zc_recv(ci_udp_iomsg_args* a, struct onload_zc_recv_args* args)
{
  int rc, done_big_poll = 0, done_kernel_poll = 0, done_callback = 0;
  ci_netif* ni = a->ni;
  ci_udp_state* us = a->us;
  enum onload_zc_callback_rc cb_rc = ONLOAD_ZC_CONTINUE;
  struct recvmsg_spinstate spin_state = {0};
  size_t supplied_controllen = args->msg.msghdr.msg_controllen;
  void* supplied_control = args->msg.msghdr.msg_control;
  socklen_t supplied_namelen = args->msg.msghdr.msg_namelen;
  void* supplied_name = args->msg.msghdr.msg_name;
  struct onload_zc_iovec iovec[CI_UDP_ZC_IOVEC_MAX];
  unsigned cb_flags;

  spin_state.do_spin = -1;
  spin_state.si = citp_signal_get_specific_inited();
  spin_state.timeout = us->s.so.rcvtimeo_msec;

  rc = ci_sock_lock(ni, &us->s.b);
  if(CI_UNLIKELY( rc != 0 ))
    return rc;

#if CI_CFG_ZC_RECV_FILTER
  ci_assert(!us->recv_q_filter);
#endif

  if( CI_UNLIKELY(us->s.so_error) ) {
    if( (rc = ci_get_so_error(&us->s)) != 0 )
      return -rc;
  }

  if( ci_udp_recv_q_is_empty(&us->recv_q) )
    goto empty;

  while( 1 ) {
    ci_ip_pkt_fmt* pkt;
  not_empty:
    cb_flags = 0;

    while( (pkt = ci_udp_recv_q_get(ni, &us->recv_q)) != NULL ) {
      /* Reinitialise our own state within [args] each time around the loop, as
       * the app's callback might have changed it. */
      args->msg.iov = iovec;
      args->msg.msghdr.msg_name = supplied_name;
      args->msg.msghdr.msg_namelen = supplied_namelen;
      args->msg.msghdr.msg_flags = 0;

      if( CI_UNLIKELY(us->s.cmsg_flags != 0 ) ) {
        args->msg.msghdr.msg_controllen = supplied_controllen;
        args->msg.msghdr.msg_control = supplied_control;
        ci_ip_cmsg_recv(ni, us, pkt, &args->msg.msghdr, 0,
                        &args->msg.msghdr.msg_flags);
      }
      else
        args->msg.msghdr.msg_controllen = 0;

      ci_udp_recvmsg_fill_msghdr(ni, &args->msg.msghdr, pkt, 
                                 &us->s);

      ci_udp_pkt_to_zc_msg(ni, pkt, &args->msg);

      us->stamp = pkt->tstamp_frc;
      us->udpflags |= CI_UDPF_LAST_RECV_ON;
    
      cb_flags = CI_IP_IS_MULTICAST(oo_ip_hdr(pkt)->ip_daddr_be32) ? 
        ONLOAD_ZC_MSG_SHARED : 0;
      if( (ci_udp_recv_q_pkts(&us->recv_q) == 1) &&
          ((us->s.os_sock_status & OO_OS_STATUS_RX) == 0) )
        cb_flags |= ONLOAD_ZC_END_OF_BURST;

      /* Add KEEP flag before calling callback, and remove it after
       * if not needed.  This prevents races where the app releases
       * the pkt before we've added the flag.
       */
      pkt->rx_flags |= CI_PKT_RX_FLAG_KEEP;

      cb_rc = (*args->cb)(args, cb_flags);

      ci_pkt_zc_free_clean(pkt, cb_rc);

      ci_udp_recv_q_deliver(ni, &us->recv_q, pkt);

      done_callback = 1;

      if( cb_rc & ONLOAD_ZC_TERMINATE )
        goto out;
    }

    if( done_big_poll && done_kernel_poll && 
        (cb_flags & ONLOAD_ZC_END_OF_BURST) )
      goto out;

    goto empty;
  }

 out:
  ni->state->is_spinner = 0;
  ci_sock_unlock(ni, &us->s.b);
  
  return rc;

 empty:
  if( spin_state.start_frc == 0 )
    ci_frc64(&spin_state.start_frc);

  if( ci_netif_may_poll(ni) &&
      ci_netif_need_poll_spinning(ni, spin_state.start_frc) && 
      ci_netif_trylock(ni) ) {
    /* If only a few events, we don't need to bother with the full poll */
    if( ci_netif_poll(ni) <
        NI_OPTS(ni).evs_per_poll )
      done_big_poll = 1;

    /* If polling a few events didn't get us anything, do a full poll */
    if( !done_big_poll && ci_udp_recv_q_is_empty(&us->recv_q) ) {
      done_big_poll = 1;
      ci_netif_poll(ni);
    }

    ci_netif_unlock(ni);

    if( ci_udp_recv_q_not_empty(&us->recv_q) )
      goto not_empty;

  } else 
    done_big_poll = 1; /* pretend we did if we can't poll */

 spin_loop:
  if(CI_UNLIKELY( (rc = UDP_RX_ERRNO(us)) )) {
    rc = -rc;
    us->s.rx_errno = us->s.rx_errno & 0xf0000000;
    goto out;
  }
  if(CI_UNLIKELY( us->s.so_error )) {
    int rc1 = ci_get_so_error(&us->s);
    if( rc1 != 0 ) {
      rc = -rc1;
      goto out;
    }
  }

  done_kernel_poll = 1;
  if( us->s.os_sock_status & OO_OS_STATUS_RX ) {
    if( args->flags & ONLOAD_MSG_RECV_OS_INLINE ) {
      do {
        /* Restore these just in case they are needed */
        args->msg.msghdr.msg_controllen = supplied_controllen;
        args->msg.msghdr.msg_control = supplied_control;
        args->msg.msghdr.msg_name = supplied_name;
        args->msg.msghdr.msg_namelen = supplied_namelen;
        rc = ci_udp_zc_recv_from_os(ni, us, args, &cb_rc);
        done_callback = 1;
        if( rc != 0 || cb_rc & ONLOAD_ZC_TERMINATE ) {
          ci_assert(done_big_poll);
          goto out;
        }
        if( ci_udp_recv_q_not_empty(&us->recv_q) )
          goto not_empty;
      } while( us->s.os_sock_status & OO_OS_STATUS_RX );
    }
    else {
      /* Return error */
      rc = -ENOTEMPTY;
      goto out;
    }
  }

  /* If we've done some callbacks, and checked everywhere for data,
   * we're at the end of a burst and should return without spinning
   * and blocking
   */
  if( done_callback ) {
    ci_assert(done_big_poll);
    ci_assert(done_kernel_poll);
    rc = 0;
    goto out;
  }

  if( ((args->flags | us->s.b.sb_aflags) & MSG_DONTWAIT)) {
    /* UDP returns EAGAIN when non-blocking even when shutdown. */
    rc = -EAGAIN;
    ++us->stats.n_rx_eagain;
    goto out;
  }
  else if (UDP_IS_SHUT_RD(us)) {
    /* Blocking and shutdowned */
    rc = 0;
    goto out;
  }

  /* We need to block (optionally spinning first). */

  /* -1 is special value that means uninitialised */
  if( spin_state.do_spin == -1 ) {
    spin_state.do_spin = 
      oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_UDP_RECV);
  
    if( spin_state.do_spin ) {
      spin_state.si = citp_signal_get_specific_inited();
      spin_state.max_spin = us->s.b.spin_cycles;
      spin_state.poison = CI_PKT_RX_POISON;
      spin_state.future = &spin_state.poison;

      if( us->s.so.rcvtimeo_msec ) {
        ci_uint64 max_so_spin = (ci_uint64)us->s.so.rcvtimeo_msec *
            IPTIMER_STATE(ni)->khz;
        if( max_so_spin <= spin_state.max_spin ) {
          spin_state.max_spin = max_so_spin;
          spin_state.spin_limit_by_so = 1;
        }
      }
    }
  }

  if( spin_state.do_spin ) {
    rc = ci_udp_recvmsg_socklocked_spin(ni, us, &spin_state);
    /* 0 => ul maybe readable 
     * 1 => spin complete 
     * -ve => error 
     */
    if( rc == 0 ) {
      if( ci_udp_recv_q_not_empty(&us->recv_q) )
        goto not_empty;
      goto spin_loop;
    }
    else if( rc < 0 )
      goto out;
  }

  ci_sock_unlock(ni, &us->s.b);
  rc = ci_udp_recvmsg_block(a, ni, us, spin_state.timeout);
  ci_sock_lock(ni, &us->s.b);
  if( rc == 0 ) {
    if( ci_udp_recv_q_not_empty(&us->recv_q) )
      goto not_empty;
    else
      goto empty;
  }
  else
    goto out;
}


int ci_udp_recvmsg_kernel(int fd, ci_netif* ni, ci_udp_state* us,
                          struct msghdr* msg, int flags)
{
  int rc = 0;
  int rc1;

  if( us->s.os_sock_status & OO_OS_STATUS_RX ) {
    rc1 = __ci_udp_recvmsg_try_os(ni, us, msg, flags, &rc);
    if( rc1 != 1 ) {
      if( rc1 == 0 )
        rc = -EAGAIN;
      else
        rc = rc1;
    }
  } 
  else {
    rc = -EAGAIN;
  }

  if( rc < 0 )
    CI_SET_ERROR(rc, -rc);

  return rc;
}
#endif
#endif
