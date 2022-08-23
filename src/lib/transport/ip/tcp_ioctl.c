/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  adp
**  \brief  TCP ioctl control; ioctl
**   \date  2004/07/28
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include <linux/sockios.h>

#include "ip_internal.h"
#include <ci/net/ioctls.h>
#include <onload/osfile.h>
#ifndef __KERNEL__
#include <onload/extensions_zc.h>
#include <onload/extensions_zc_hlrx.h>
#include <onload/tcp-ceph.h>
#endif


/* NOTE: in the kernel version [fd] is unused and, if it's a ptr, [arg] will
 * be in user-space and may need to be fetched into kernel memory. */
static int ci_tcp_ioctl_lk(citp_socket* ep, ci_fd_t fd, int request,
                           void* arg)
{
  ci_netif* netif = ep->netif;
  ci_sock_cmn* s = ep->s;
  ci_tcp_state* ts = NULL;
  int rc = 0;
  int os_socket_exists = s->b.sb_aflags & CI_SB_AFLAG_OS_BACKED;

  if( s->b.state != CI_TCP_LISTEN )
    ts = SOCK_TO_TCP(s);

  /* Keep the os socket in sync.  If this is a "get" request then the
   * return will be based on our support, not the os's (except for EFAULT
   * handling which we get for free).
   * Exceptions:
   *  - FIONBIO is applied just in time on handover if needed (listening
   *    sockets always have a non-blocking OS socket)
   *  - FIONREAD, TIOCOUTQ, SIOCOUTQNSD and SIOCATMARK are useless on OS
   *    socket, let's avoid syscall.
   */
  if( os_socket_exists && request != FIONREAD && request != SIOCATMARK &&
      request != FIOASYNC && request != TIOCOUTQ && request != SIOCOUTQNSD &&
      request != (int) FIONBIO
#ifndef __KERNEL__
      && request != ONLOAD_SIOC_CEPH_REMOTE_CONSUME
#endif
      ) {
    rc = oo_os_sock_ioctl(netif, s->b.bufid, request, arg, NULL);
    if( rc < 0 )
      return rc;
  }

  /* ioctl defines are listed in `man ioctl_list` and the CI equivalent
   * CI defines are in include/ci/net/ioctls.h  */
  LOG_TV( ci_log("%s:  request = %d, arg = %ld", __FUNCTION__, request, 
		 (long)arg));

  switch( request ) {
  case FIONBIO:
    if( CI_IOCTL_ARG_OK(int, arg) ) {
      CI_CMN_IOCTL_FIONBIO(ep->s, arg);
      rc = 0;
      break;
    }
    goto fail_fault;
  case FIONREAD: /* synonym of SIOCINQ */
    if( !CI_IOCTL_ARG_OK(int, arg) )
      goto fail_fault;
    if( s->b.state == CI_TCP_LISTEN )
      goto fail_inval;

    if( s->b.state == CI_TCP_SYN_SENT ) {
      CI_IOCTL_SETARG((int*)arg, 0);
    } else {
      /* In inline mode, return the total number of bytes in the receive queue.
         If SO_OOBINLINE isn't set then return the number of bytes up to the
         mark but without counting the mark */
      int bytes_in_rxq = tcp_rcv_usr(ts);
      if (bytes_in_rxq && ! (ts->s.s_flags & CI_SOCK_FLAG_OOBINLINE)) {

        if (tcp_urg_data(ts) & CI_TCP_URG_PTR_VALID) {
          /*! \TODO: what if FIN has been received? */
          unsigned int readnxt = tcp_rcv_nxt(ts) - bytes_in_rxq;
          if (SEQ_LT(readnxt, tcp_rcv_up(ts))) {
            bytes_in_rxq = tcp_rcv_up(ts) - readnxt;
          } else if (SEQ_EQ(readnxt, tcp_rcv_up(ts))) {
            bytes_in_rxq--;
          }
        }
      }
      CI_IOCTL_SETARG((int*)arg, bytes_in_rxq);
    }
    break;

  case TIOCOUTQ: /* synonym of SIOCOUTQ */
  case SIOCOUTQNSD:
    {
    CI_BUILD_ASSERT(TIOCOUTQ == SIOCOUTQ);
    int outq_bytes = 0;

    if( !CI_IOCTL_ARG_OK(int, arg) )
      goto fail_fault;
    if( s->b.state == CI_TCP_LISTEN )
      goto fail_inval;

    if( s->b.state != CI_TCP_SYN_SENT ) {

      /* TIOCOUTQ counts all unacknowledged data, so includes retrans queue. */
      if( request == TIOCOUTQ )
        outq_bytes = SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_una(ts));
      else
        outq_bytes = SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts));
    }
    CI_IOCTL_SETARG((int*)arg, outq_bytes);
    }
    break;

  case SIOCATMARK:
    {
     if( !CI_IOCTL_ARG_OK(int, arg) )
       goto fail_fault;

      /* return true, if we are at the out-of-band byte */
      CI_IOCTL_SETARG((int*)arg, 0);
      if( s->b.state != CI_TCP_LISTEN ) {
        int readnxt;

        readnxt = SEQ_SUB(tcp_rcv_nxt(ts), tcp_rcv_usr(ts));
        if( ~ts->s.b.state & CI_TCP_STATE_ACCEPT_DATA )
          readnxt = SEQ_SUB(readnxt, 1);
        if( tcp_urg_data(ts) & CI_TCP_URG_PTR_VALID )
          CI_IOCTL_SETARG((int*)arg, readnxt == tcp_rcv_up(ts));
        LOG_URG(log(NTS_FMT "SIOCATMARK atmark=%d  readnxt=%u rcv_up=%u%s",
                    NTS_PRI_ARGS(ep->netif, ts), readnxt == tcp_rcv_up(ts), 
		    readnxt,  tcp_rcv_up(SOCK_TO_TCP(ep->s)),
                    (tcp_urg_data(ts)&CI_TCP_URG_PTR_VALID)?"":" (invalid)"));
      }
      break;
    }

#ifndef __KERNEL__
  case FIOASYNC:
    /* Need to apply this to [fd] so that our fasync file-op will be
     * invoked.
     */
    rc = ci_sys_ioctl(fd, request, arg);
    break;

  case SIOCSPGRP:
    if( !CI_IOCTL_ARG_OK(int, arg) )
      goto fail_fault;
    /* Need to apply this to [fd] to get signal delivery to work.  However,
     * SIOCSPGRP is only supported on sockets, so we need to convert to
     * fcntl().
     */
    rc = ci_sys_fcntl(fd, F_SETOWN, CI_IOCTL_GETARG(int, arg));
    if( rc == 0 ) {
      rc = ci_cmn_ioctl(netif, ep->s, request, arg, rc, os_socket_exists);
    }
    else {
      CI_SET_ERROR(rc, -rc);
    }
    break;
#endif

#if CI_CFG_TCP_OFFLOAD_RECYCLER
#ifndef __KERNEL__
  case ONLOAD_SIOC_CEPH_REMOTE_CONSUME:
    if( ! ci_tcp_is_pluginized(ts) )
      goto fail_inval;
    else {
      ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(netif, 0);
      union ceph_control_pkt cmd = {
        .consume_payload.cmd = XSN_CEPH_CTRL_CONSUME_PAYLOAD,
        .consume_payload.stream_id = ts->plugin_stream_id,
        .consume_payload.buf_tail = CI_IOCTL_GETARG(uint64_t, arg) - ts->plugin_ddr_base,
      };
      if( ! pkt )
        return -ENOMEM;
      ci_netif_send_plugin_app_ctrl(netif, ts->s.pkt.intf_i, pkt,
                                    &cmd, sizeof(cmd));
    }
    break;
#endif
#endif

  default:
    return ci_cmn_ioctl(netif, ep->s, request, arg, rc, os_socket_exists);
  }

  /* Successful handling */
  return rc;

 fail_inval:
  LOG_SC(ci_log("%s: "NSS_FMT" unhandled req %d/%#x arg %ld/%#lx (EINVAL)", 
                __FUNCTION__,  NSS_PRI_ARGS(netif, s), request, request, 
                (long)arg, (long)arg));
  return -EINVAL;

 fail_fault:
  LOG_SC(ci_log("%s: "NSS_FMT" unhandled req %d/%#x arg %#lx (EFAULT)", 
                __FUNCTION__,  NSS_PRI_ARGS(netif, s), request, request, 
                (long)arg));
  return -EFAULT;
}


/* TCP Ioctl handler.  Call with os_sock either our backing socket
 * or CI_INVALID_SOCKET.  The caller must release [os_sock] if 
 * required (i.e. Linux.requires a release, Windows does not).
 *
 * \param    ep
 * \param    fd       Our socket
 * \param    request  Original callers request
 * \param    arg      [in|out] request arg space
 */
int ci_tcp_ioctl(citp_socket* ep, ci_fd_t fd, int request, void* arg)
{
  int rc;

  ci_netif_lock(ep->netif);
  rc = ci_tcp_ioctl_lk(ep, fd, request, arg);
  ci_netif_unlock(ep->netif);
  return rc;
}

/*! \cidoxg_end */
