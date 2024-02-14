/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  kjm
**  \brief  Intercept of onload extension API calls
**   \date  2010/12/11
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#define _GNU_SOURCE /* for dlsym(), RTLD_NEXT, etc */

#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>

#include "internal.h"
#include <onload/extensions.h>
#include <onload/ul/stackname.h>
#include <ci/internal/ip_timestamp.h>

#include "ul_pipe.h"
#include "ul_epoll.h"


int onload_is_present(void)
{
  return 1;
}


static int onload_fd_stat_netif(ci_netif *ni, struct onload_stat* stat)
{
  int len;

  stat->stack_id = NI_ID(ni);
  len = strlen(ni->state->name);
  stat->stack_name = malloc(len + 1);
  if( stat->stack_name == NULL )
    return -ENOMEM;
  strcpy(stat->stack_name, ni->state->name);
  return 1;
}


int onload_fd_stat(int fd, struct onload_stat* stat)
{
  citp_fdinfo* fdi;
  citp_sock_fdi* sock_epi;
  citp_alien_fdi* alien_epi;
  int rc;
  citp_lib_context_t lib_context;

  citp_enter_lib(&lib_context);

  if( (fdi = citp_fdtable_lookup(fd)) != NULL ) {
    switch( citp_fdinfo_get_type(fdi) ) {
    case CITP_UDP_SOCKET:
    case CITP_TCP_SOCKET:
      if( stat ==  NULL ) {
        rc = 1;
      }
      else {
        sock_epi = fdi_to_sock_fdi(fdi);
        stat->endpoint_id = SC_FMT(sock_epi->sock.s);
        stat->endpoint_state = sock_epi->sock.s->b.state;
        rc = onload_fd_stat_netif(sock_epi->sock.netif, stat);
      }
      break;
    case CITP_EPOLL_FD:
      rc = 0;
      break;
    case CITP_PIPE_FD:
      if( stat ==  NULL ) {
        rc = 1;
      }
      else {
        citp_pipe_fdi* pipe_epi;
        pipe_epi = fdi_to_pipe_fdi(fdi);
        stat->endpoint_id = W_FMT(&pipe_epi->pipe->b);
        stat->endpoint_state = pipe_epi->pipe->b.state;
        rc = onload_fd_stat_netif(pipe_epi->ni, stat);
      }
      break;
    case CITP_PASSTHROUGH_FD:
      if( stat ==  NULL ) {
        rc = 1;
      }
      else {
        alien_epi = fdi_to_alien_fdi(fdi);
        stat->endpoint_id = W_FMT(alien_epi->ep);
        stat->endpoint_state = alien_epi->ep->state;
        rc = onload_fd_stat_netif(alien_epi->netif, stat);
      }
      break;
    default:
      LOG_U(log("%s: unknown fdinfo type %d", __FUNCTION__, 
                citp_fdinfo_get_type(fdi)));
      rc = 0;
    }
    citp_fdinfo_release_ref(fdi, 0);
  }
  else
    rc = 0;
  citp_exit_lib(&lib_context, TRUE);
  return rc;
}


static void onload_thread_set_spin2(enum onload_spin_type type, int spin)
{
  struct oo_per_thread* pt = oo_per_thread_get();
  if( spin ) 
    pt->spinstate |= (1 << type);
  else
    pt->spinstate &= ~(1 << type);
}


int onload_thread_set_spin(enum onload_spin_type type, int spin) 
{
  if( (unsigned) type >= (unsigned) ONLOAD_SPIN_MAX )
    return -EINVAL;

  if( type == ONLOAD_SPIN_ALL ) {
    for( type = ONLOAD_SPIN_ALL + 1; type < ONLOAD_SPIN_MAX; ++type )
      if ( type != ONLOAD_SPIN_MIMIC_EF_POLL )
        onload_thread_set_spin2(type, spin);
  }
  else if( type == ONLOAD_SPIN_MIMIC_EF_POLL ) {
  /* This option is to provide an extensions API meta option with
   * similar spin configuration to EF_POLL_USEC (as configured in
   * citp_opts_getenv(). Any changes to how EF_POLL_USEC is
   * interpreted needs to be reflected here
   */
    onload_thread_set_spin2(ONLOAD_SPIN_UDP_RECV, spin);
    onload_thread_set_spin2(ONLOAD_SPIN_UDP_SEND, spin);
    onload_thread_set_spin2(ONLOAD_SPIN_TCP_RECV, spin);
    onload_thread_set_spin2(ONLOAD_SPIN_TCP_SEND, spin);
    onload_thread_set_spin2(ONLOAD_SPIN_SELECT, spin);
    onload_thread_set_spin2(ONLOAD_SPIN_POLL, spin);
    onload_thread_set_spin2(ONLOAD_SPIN_EPOLL_WAIT, spin);
    onload_thread_set_spin2(ONLOAD_SPIN_PKT_WAIT, spin);
    onload_thread_set_spin2(ONLOAD_SPIN_STACK_LOCK, spin);
    onload_thread_set_spin2(ONLOAD_SPIN_SOCK_LOCK, spin);
  }
  else {
    onload_thread_set_spin2(type, spin);
  }

  return 0;
}

int onload_thread_get_spin(unsigned* state)
{
  struct oo_per_thread* pt = oo_per_thread_get();
  *state = pt->spinstate;
  return 0;
}

int onload_move_fd(int fd)
{
#if CI_CFG_ENDPOINT_MOVE
  ef_driver_handle fd_ni;
  ci_fixed_descriptor_t op_arg;
  int rc;
  ci_netif* ni;
  citp_lib_context_t lib_context;
  citp_fdinfo *fdi;

  Log_CALL(ci_log("%s(%d)", __func__, fd));
  citp_enter_lib(&lib_context);

  rc = citp_netif_alloc_and_init(&fd_ni, &ni);
  if( rc != 0 )
    goto out;

  op_arg = fd;
  rc = oo_resource_op(ci_netif_get_driver_handle(ni),
                      OO_IOC_MOVE_FD, &op_arg);
  if( rc != 0 )
    goto out;

  fdi = citp_fdtable_lookup(fd);
  fdi = citp_reprobe_moved(fdi, CI_FALSE, CI_FALSE);
  citp_fdinfo_release_ref(fdi, CI_FALSE);

out:
  citp_exit_lib(&lib_context, CI_TRUE);
  Log_CALL_RESULT(rc);
  return rc;
#else
  return -ENOSYS;
#endif
}


static int onload_fd_check_msg_warm(int fd)
{
  struct onload_stat stat = { .stack_name = NULL };
  int ok = CI_TCP_STATE_TCP | CI_TCP_STATE_TCP_CONN;
  int rc;

  if ( ( onload_fd_stat(fd, &stat) > 0 ) &&
       ( CI_TCP_STATE_IS_SOCKET(stat.endpoint_state) ) &&
       ( ok == (stat.endpoint_state & ok) ) )
    rc = 1;
  else
    rc = 0;

  free(stat.stack_name);

  return rc;
}


int onload_fd_check_feature(int fd, enum onload_fd_feature feature)
{
  switch ( feature ) {
  case ONLOAD_FD_FEAT_MSG_WARM:
    return onload_fd_check_msg_warm(fd);
    break;
  case ONLOAD_FD_FEAT_UDP_TX_TS_HDR:
    return 1;
    break;
  case ONLOAD_FD_FEAT_TX_SCM_TS_PKTINFO:
    return 1;
    break;
  default:
    break;
  }
  return -EOPNOTSUPP;
}


int onload_ordered_epoll_wait(int epfd, struct epoll_event *events,
                              struct onload_ordered_epoll_event *oo_events,
                              int maxevents, int timeout)
{
  int rc = -EINVAL;

#if CI_CFG_TIMESTAMPING
  citp_fdinfo* fdi;
  citp_lib_context_t lib_context;
  citp_enter_lib(&lib_context);

  if( (fdi = citp_fdtable_lookup(epfd)) != NULL ) {
    if( fdi->protocol->type == CITP_EPOLL_FD ) {
      rc = citp_epoll_ordered_wait(fdi, events, oo_events, maxevents, timeout,
                                     NULL, &lib_context);
      citp_reenter_lib(&lib_context);
      citp_fdinfo_release_ref(fdi, 0);
      citp_exit_lib(&lib_context, rc >= 0);
      return rc;
    }
    citp_fdinfo_release_ref(fdi, 0);
  }

  citp_exit_lib(&lib_context, FALSE);

#else
  rc = -EOPNOTSUPP;
#endif
  return rc;
}


int onload_timestamping_request(int fd, unsigned flags)
{
#if CI_CFG_TIMESTAMPING
  if( flags & ~ONLOAD_TIMESTAMPING_FLAG_MASK )
    return -EINVAL;

  citp_fdinfo* fdi;
  int rc;
  citp_lib_context_t lib_context;

  citp_enter_lib(&lib_context);

  if( (fdi = citp_fdtable_lookup(fd)) != NULL && citp_fdinfo_is_socket(fdi) ) {
    ci_sock_cmn* sock = fdi_to_socket(fdi)->s;
    if( flags & ONLOAD_TIMESTAMPING_FLAG_RX_MASK )
      sock->cmsg_flags |= CI_IP_CMSG_TIMESTAMPING;
    else
      sock->cmsg_flags &= ~CI_IP_CMSG_TIMESTAMPING;

    sock->timestamping_flags = ONLOAD_SOF_TIMESTAMPING_ONLOAD | flags;
    rc = 0;
  }
  else {
    rc = -ENOTTY;
  }

  citp_exit_lib(&lib_context, 0);
  return rc;
#else
  return -EOPNOTSUPP;
#endif
}


static int oo_extensions_version_check(void)
{
  static unsigned int* oev;

  /* Accept version of onload_ext library if:
   * - onload_ext is not present (no onload_ext_version symbol) 
   * - or major versions match and lib's minor is less than or
   *   equal to onload's
   */
  if( oev == NULL )
    if( (oev = dlsym(RTLD_NEXT, "onload_ext_version")) == NULL )
      return 0;
  if( (oev[0] == ONLOAD_EXT_VERSION_MAJOR) &&
      (oev[1] <= ONLOAD_EXT_VERSION_MINOR) )
    /* Onload is compatible with the extensions lib. */
    return 0;

  /* Extensions lib has different major version, or supports new features
   * that this version of Onload doesn't know about.  We don't know for
   * certain that the app is using the new features, be we can't detect
   * that either.
   */
  ci_log("ERROR: Onload extension library has incompatible version");
  ci_log("ERROR: libonload=%d.%d.%d libonload_ext=%d.%d.%d",
         ONLOAD_EXT_VERSION_MAJOR, ONLOAD_EXT_VERSION_MINOR,
         ONLOAD_EXT_VERSION_MICRO, oev[0], oev[1], oev[2]);
  return -1;
}


int oo_extensions_init(void)
{
  int rc; 

  if( (rc = oo_extensions_version_check()) != 0 ) 
    return rc;

  oo_stackname_init();

  return 0;
}


/* Export the version of the extensions interface this library supports.
 * This is used by the static version of the extensions stub library to
 * validate compatibility.
 */
unsigned onload_lib_ext_version[] = {
  ONLOAD_EXT_VERSION_MAJOR,
  ONLOAD_EXT_VERSION_MINOR,
  ONLOAD_EXT_VERSION_MICRO
};


/**************************************************************************/

enum onload_delegated_send_rc
onload_delegated_send_prepare(int fd, int size, unsigned flags,
                              struct onload_delegated_send* out)
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  enum onload_delegated_send_rc rc = ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET;

  Log_CALL(ci_log("%s(%d, %d, %p)", __FUNCTION__, fd, size, out));

  citp_enter_lib(&lib_context);
  fdi = citp_fdtable_lookup(fd);
  if( fdi != NULL ) {
    if( citp_fdinfo_get_ops(fdi)->dsend_prepare != NULL )
      rc = citp_fdinfo_get_ops(fdi)->dsend_prepare(fdi, size, flags, out);
    citp_fdinfo_release_ref(fdi, 0);
  }
  citp_exit_lib(&lib_context, rc == 0);

  Log_CALL_RESULT(rc);
  return rc;
}

int
onload_delegated_send_complete(int fd, const struct iovec* iov, int iovlen,
                               int flags)
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  int rc;

  Log_CALL(ci_log("%s(%d, %p, %d, 0x%x)", __FUNCTION__,
                  fd, iov, iovlen, flags));

  citp_enter_lib(&lib_context);
  fdi = citp_fdtable_lookup(fd);
  if( fdi != NULL && citp_fdinfo_get_ops(fdi)->dsend_complete != NULL ) {
    rc = citp_fdinfo_get_ops(fdi)->dsend_complete(fdi, iov, iovlen, flags);
  }
  else {
    errno = ENOTTY;
    rc = -1;
  }
  if( fdi != NULL )
    citp_fdinfo_release_ref(fdi, 0);
  citp_exit_lib(&lib_context, rc == 0);

  Log_CALL_RESULT(rc);
  return rc;
}

int
onload_delegated_send_cancel(int fd)
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  int rc = -1;

  Log_CALL(ci_log("%s(%d)", __FUNCTION__, fd));

  citp_enter_lib(&lib_context);
  fdi = citp_fdtable_lookup(fd);
  if( fdi != NULL && citp_fdinfo_get_ops(fdi)->dsend_cancel != NULL ) {
    rc = citp_fdinfo_get_ops(fdi)->dsend_cancel(fdi);
  }
  else {
    errno = ENOTTY;
    rc = -1;
  }
  if( fdi != NULL )
    citp_fdinfo_release_ref(fdi, 0);
  citp_exit_lib(&lib_context, rc == 0);

  Log_CALL_RESULT(rc);
  return rc;
}

int
oo_raw_send(int fd, int hwport, const struct iovec *iov, int iovcnt)
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
   citp_sock_fdi* epi;
  ci_netif* ni;
  int rc = -1;
  int intf_i = -1;

  Log_CALL(ci_log("%s(%d, %p, %d)", __FUNCTION__, fd, iov, iovcnt));

  citp_enter_lib(&lib_context);
  fdi = citp_fdtable_lookup(fd);
  if( fdi == NULL || ! citp_fdinfo_is_socket(fdi) ) {
    errno = ENOTTY;
    goto out;
  }
  epi = fdi_to_sock_fdi(fdi);
  ni = epi->sock.netif;

  if( hwport >= 0 && hwport < CI_CFG_MAX_HWPORTS )
    intf_i = ci_hwport_to_intf_i(ni, hwport);
  if( intf_i < 0 )
    intf_i = epi->sock.s->pkt.intf_i;
  if( intf_i < 0 ) {
    errno = ENETDOWN;
    return -1;
  }
  rc = ci_netif_raw_send(ni, intf_i,  iov, iovcnt);
  if( rc < 0 ) {
    errno = -rc;
    rc = -1;
  }

out:
  if( fdi != NULL )
    citp_fdinfo_release_ref(fdi, 0);
  citp_exit_lib(&lib_context, rc == 0);
  Log_CALL_RESULT(rc);

  return rc;
}


int onload_get_tcp_info(int fd, struct onload_tcp_info* uinfo, int* len_in_out)
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  citp_sock_fdi* sock_epi;
  ci_tcp_state* ts;
  int rc = -1;
  struct onload_tcp_info info;

  Log_CALL(ci_log("%s(%d, %p, %p(%d))", __FUNCTION__,
                  fd, uinfo, len_in_out, *len_in_out));

  citp_enter_lib(&lib_context);
  fdi = citp_fdtable_lookup(fd);
  if( fdi == NULL || citp_fdinfo_get_type(fdi) != CITP_TCP_SOCKET )
    goto fail;
  sock_epi = fdi_to_sock_fdi(fdi);
  if( sock_epi->sock.s->b.state == CI_TCP_LISTEN ||
      sock_epi->sock.s->b.state == CI_TCP_CLOSED )
    goto fail;
  ts = SOCK_TO_TCP(sock_epi->sock.s);

  info.so_recvbuf = ts->s.so.rcvbuf;
  info.rcvbuf_used = tcp_rcv_usr(ts);
  info.rcv_window = tcp_rcv_wnd_right_edge_sent(ts) - ts->rcv_added;

  info.so_sndbuf = ts->s.so.sndbuf;
  info.so_sndbuf_pkts = ts->so_sndbuf_pkts;
  info.sndbuf_pkts_avail = ci_tcp_tx_send_space(sock_epi->sock.netif, ts);
  info.snd_mss = tcp_eff_mss(ts);

  info.snd_window = SEQ_SUB(ts->snd_max, tcp_snd_nxt(ts));
  info.cong_window = ts->cwnd + ts->cwnd_extra - ci_tcp_inflight(ts);
  if( info.cong_window < info.snd_mss )
    info.cong_window = 0;

  if( *len_in_out > sizeof(info) )
    *len_in_out = sizeof(info);
  memcpy(uinfo, &info, *len_in_out);

  rc = 0;
  goto out;

fail:
  errno = EINVAL;
 out:
  if( fdi != NULL )
    citp_fdinfo_release_ref(fdi, 0);
  citp_exit_lib(&lib_context, FALSE);
  return rc;
}



int onload_socket_nonaccel(int domain, int type, int protocol)
{
  return ci_sys_socket(domain, type, protocol);
}


extern int onload_socket(int domain, int type, int protocol);
int onload_socket_unicast_nonaccel(int domain, int type, int protocol)
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  int fd;

  Log_CALL(ci_log("%s(%d, %d, %d)", __FUNCTION__, domain, type, protocol));

#if CI_CFG_IPV6 || CI_CFG_FAKE_IPV6
  if( (domain == AF_INET || domain == AF_INET6) &&
#else
  if( (domain == AF_INET) &&
#endif
      (type == SOCK_DGRAM) &&
      ((protocol == 0) || (protocol == IPPROTO_UDP))) {
    fd = onload_socket(domain, type, protocol);

    if( fd >= 0 ) {
      citp_enter_lib(&lib_context);
      fdi = citp_fdtable_lookup(fd);
      if( fdi != NULL ) {
        ci_assert_equal(citp_fdinfo_get_type(fdi), CITP_UDP_SOCKET);
        ci_udp_set_no_unicast(&fdi_to_sock_fdi(fdi)->sock);
        citp_fdinfo_release_ref(fdi, 0);
      }

      citp_exit_lib(&lib_context, TRUE);
    }
  }
  else {
    fd = ci_sys_socket(domain, type, protocol);
  }

  Log_CALL_RESULT(fd);
  return fd;
}

