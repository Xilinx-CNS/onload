/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  adp
**  \brief  UDP ioctl control; ioctl
**   \date  2004/07/28
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

#include <linux/sockios.h>
#include <sys/time.h>

#include "ip_internal.h"
#include <ci/net/ioctls.h>
#include <onload/osfile.h>


void ci_synchronise_clock(ci_netif *ni, struct oo_timesync* oo_ts_local)
{
  ci_uint32 gc;
  struct oo_timesync *oo_ts = ni->timesync;

  /* Check if our current datapoint for clock_gettime is up to date,
   * and take another if not
   */
  if( oo_ts_local->generation_count != oo_ts->generation_count ) {
    do {
      gc = oo_ts->generation_count;
      ci_rmb();
      oo_ts_local->smoothed_ticks = oo_ts->smoothed_ticks;
      oo_ts_local->smoothed_ns = oo_ts->smoothed_ns;
      oo_ts_local->wall_clock.tv_sec = oo_ts->wall_clock.tv_sec;
      oo_ts_local->wall_clock.tv_nsec = oo_ts->wall_clock.tv_nsec;
      oo_ts_local->mono_clock.tv_sec = oo_ts->mono_clock.tv_sec;
      oo_ts_local->mono_clock.tv_nsec = oo_ts->mono_clock.tv_nsec;
      oo_ts_local->clock_made = oo_ts->clock_made;
      ci_rmb();
    } while (gc & 1 || gc != oo_ts->generation_count);
    oo_ts_local->generation_count = gc;
  }
}


void ci_udp_compute_stamp(ci_netif *ni, ci_uint64 stamp, struct timespec *ts)
{
  ci_uint64 delta, delta_sec, delta_nsec;
  struct oo_timesync* oo_ts_local;
  double ns_rate;

  oo_ts_local = &(__oo_per_thread_get()->timesync);
  ci_synchronise_clock(ni, oo_ts_local);

  ts->tv_sec = oo_ts_local->wall_clock.tv_sec;
  ts->tv_nsec = oo_ts_local->wall_clock.tv_nsec;

  ns_rate = (double)oo_ts_local->smoothed_ns / 
    (double)oo_ts_local->smoothed_ticks;
  
  if( oo_ts_local->clock_made >= stamp ) {
    /* Calculate offset in nanosecs.  We have to use floating point
     * here and do division first as frc_delta * ns could overflow 64
     * bits
     */
    delta = (ci_uint64)((double)(oo_ts_local->clock_made - stamp) * ns_rate);
    delta_sec  = delta / 1000000000llu;
    delta_nsec = delta % 1000000000llu;
    /* clock updated after packet stamped, so need to decrease ts */
    ts->tv_sec -= delta_sec;
    if(ts->tv_nsec < delta_nsec){
      --ts->tv_sec;
      ts->tv_nsec += 1000000000;
    }
    ts->tv_nsec -= delta_nsec;
  }
  else {
    /* Calculate positive offset in nanosecs. We have to use floating
     * point here and do division first as frc_delta * ns could
     * overflow 64 bits
     */
    delta = (ci_uint64)((double)(stamp - oo_ts_local->clock_made) * ns_rate);
    delta_sec  = delta / 1000000000llu;
    delta_nsec = delta % 1000000000llu;
    /* clock updated before packet stamped, so need to increase ts */
    ts->tv_sec += delta_sec;
    ts->tv_nsec += delta_nsec;
    if(ts->tv_nsec >= 1000000000){
      ++ts->tv_sec;
      ts->tv_nsec -= 1000000000;
    }
  }
  ci_assert_lt(ts->tv_nsec, 1000000000);
}


static void ci_udp_update_stamp_cache(ci_netif *netif, ci_udp_state *us,
                                      ci_uint64 *stamp)
{
  struct timespec ts;
  
  ci_udp_compute_stamp(netif, *stamp, &ts);

  /* The FRC and gettimeofday are not based on the same clock, so
   * multiple SIOCGSTAMP ioctls for the same packet would return
   * slightly different results.  We cache the first result and return
   * that assuming 'stamp' hasn't been updated by passing another
   * packet to the application.
   */
  *stamp = 1;
  us->stamp_cache.tv_sec = ts.tv_sec;
  us->stamp_cache.tv_nsec = ts.tv_nsec;
}


static int ci_udp_ioctl_siocgstamp(ci_netif *netif, ci_udp_state *us, 
                                   void* arg, int micros)
{
  ci_uint64 stamp = us->stamp;

  if( us->s.cmsg_flags & CI_IP_CMSG_TIMESTAMP_ANY )
    stamp = us->stamp_pre_sots;

  if( stamp == 0 )
    return -ENOENT;
  else if( arg == NULL )
    return -EFAULT;
  else if( stamp != 1 ) {
    if( us->s.cmsg_flags & CI_IP_CMSG_TIMESTAMP_ANY )
      ci_udp_update_stamp_cache(netif, us, &us->stamp_pre_sots);
    else 
      ci_udp_update_stamp_cache(netif, us, &us->stamp);
  }

  ((struct timeval*)arg)->tv_sec = us->stamp_cache.tv_sec;
  if( micros )
    ((struct timeval*)arg)->tv_usec = us->stamp_cache.tv_nsec / 1000;
  else 
    ((struct timeval*)arg)->tv_usec = us->stamp_cache.tv_nsec;
  return 0;
}


static int ci_udp_ioctl_slow(ci_netif* ni, ci_udp_state* us,
                             ci_fd_t fd, int request, void* arg)
{
  int os_rc, rc = 0;

  /* Keep the O/S socket in sync.  Also checks that this is a valid ioctl()
   * for a UDP socket on this kernel.
   */
  if( request != FIOASYNC &&
      (os_rc = oo_os_sock_ioctl(ni, us->s.b.bufid, request, arg, NULL)) < 0 )
    return os_rc;

  switch( request ) {
  case FIONBIO:
    /* set asynchronous (*arg == 1) or synchronous (*arg == 0) IO 
     * Want this to stay efficient, so we don't do the extra call to the common 
     * ioctl handler. */
    CI_CMN_IOCTL_FIONBIO(&us->s, arg);
    break;

  case FIOASYNC:
    /* Need to apply this to [fd] so that our fasync file-op will be invoked.
     */
    rc = ci_sys_ioctl(fd, request, arg);
    if( rc < 0 ) {
      /* This is very unexpected, as it worked on the OS socket. */
      LOG_E(ci_log("%s: ERROR: FIOASYNC failed on fd=%d rc=%d errno=%d",
                   __FUNCTION__, fd, rc, errno));
      rc = -errno;
    }
    break;

  case SIOCSPGRP:
    /* Need to apply this to [fd] to get signal delivery to work.  However,
     * SIOCSPGRP is only supported on sockets, so we need to convert to
     * fcntl().
     */
    rc = ci_sys_fcntl(fd, F_SETOWN, CI_IOCTL_GETARG(int, arg));
    if( rc < 0 )
      /* This is very unexpected, as it worked on the OS socket. */
      LOG_E(ci_log("%s: ERROR: fcntl(F_SETOWN) failed on fd=%d rc=%d errno=%d",
                   __FUNCTION__, fd, rc, errno));
    rc = ci_cmn_ioctl(ni, &us->s, request, arg, os_rc, 1);
    break;

  default:
    rc = ci_cmn_ioctl(ni, &us->s, request, arg, os_rc, 1);
  }

  return rc;
}


static int ci_udp_ioctl_locked(ci_netif* ni, ci_udp_state* us,
                               ci_fd_t fd, int request, void* arg)
{
  int rc;

  switch( request ) {
  case FIONREAD: /* synonym of SIOCINQ */
    if( ! CI_IOCTL_ARG_OK(int, arg) )
      return -EFAULT;
    rc = 1;
    if( rc ) {
      /* Return the size of the datagram at the head of the receive queue.
       *
       * Careful: extract side of receive queue is owned by sock lock,
       * which we don't have.  However, freeing of bufs is owned by netif
       * lock, which we do have.  So we're safe so long as we only read
       * [extract] once.
       */
      oo_pkt_p extract = OO_ACCESS_ONCE(us->recv_q.extract);
      if( OO_PP_NOT_NULL(extract) ) {
        ci_ip_pkt_fmt* pkt = PKT_CHK(ni, extract);
        if( (pkt->rx_flags & CI_PKT_RX_FLAG_RECV_Q_CONSUMED) &&
            OO_PP_NOT_NULL(pkt->udp_rx_next) )
          pkt = PKT_CHK(ni, pkt->udp_rx_next);
        if( !(pkt->rx_flags & CI_PKT_RX_FLAG_RECV_Q_CONSUMED) ) {
          *(int*) arg = pkt->pf.udp.pay_len;
          return 0;
        }
      }
    }
    /* Nothing in userlevel receive queue: So take the value returned by
     * the O/S socket.
     */
    if( !(us->s.os_sock_status & OO_OS_STATUS_RX) ) {
      *(int*)arg = 0;
      return 0;
    }
    goto sys_ioctl;

  case TIOCOUTQ: /* synonym of SIOCOUTQ */
    if( ! CI_IOCTL_ARG_OK(int, arg) )
      return -EFAULT;

    *(int*)arg = us->tx_count + oo_atomic_read(&us->tx_async_q_level);
    return 0;

  case SIOCGSTAMP:
#ifdef __KERNEL__
/* The following code assumes the width of the timespec and timeval fields */
# error "Need to consider 32-on-64 bit setting of timeval arg" 
#endif
    if( ! (us->udpflags & CI_UDPF_LAST_RECV_ON) )
      return oo_os_sock_ioctl(ni, us->s.b.bufid, request, arg, NULL);
    return ci_udp_ioctl_siocgstamp(ni, us, arg, 1);
  case SIOCGSTAMPNS:
    if( ! (us->udpflags & CI_UDPF_LAST_RECV_ON) )
      return oo_os_sock_ioctl(ni, us->s.b.bufid, request, arg, NULL);
    return ci_udp_ioctl_siocgstamp(ni, us, arg, 0);
  }

  return ci_udp_ioctl_slow(ni, us, fd, request, arg);

 sys_ioctl:
  return oo_os_sock_ioctl(ni, us->s.b.bufid, request, arg, NULL);
}


int ci_udp_ioctl(citp_socket *ep, ci_fd_t fd, int request, void* arg)
{
  ci_netif* ni = ep->netif;
  ci_udp_state* us = SOCK_TO_UDP(ep->s);
  int rc;

  ci_netif_lock(ni);
  rc = ci_udp_ioctl_locked(ni, us, fd, request, arg);
  ci_netif_unlock(ni);
  return rc;
}
