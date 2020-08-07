/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2019 Xilinx, Inc. */

#include "internal.h"
#include "nonsock.h"
#include <onload/osfile.h>
#include <onload/dup2_lock.h>
#include <onload/ul/tcp_helper.h>

static void citp_passthrough_dtor(citp_fdinfo* fdi, int fdt_locked)
{
  citp_alien_fdi* epi = fdi_to_alien_fdi(fdi);

  if( ! fdt_locked )
    CITP_FDTABLE_LOCK();
  ci_tcp_helper_close_no_trampoline(epi->os_socket);
  __citp_fdtable_reserve(epi->os_socket, 0);
  if( ! fdt_locked )
    CITP_FDTABLE_UNLOCK();
  citp_netif_release_ref(fdi_to_alien_fdi(fdi)->netif, fdt_locked);
}

static int
citp_passthrough_ioctl(citp_fdinfo* fdi, int request, void* arg)
{
  return ci_sys_ioctl(fdi_to_alien_fdi(fdi)->os_socket,
                      request, arg);
}

int
citp_passthrough_bind(citp_fdinfo* fdi,
                      const struct sockaddr* sa, socklen_t sa_len)
{
  int rc = ci_sys_bind(fdi_to_alien_fdi(fdi)->os_socket,
                       sa, sa_len);
  citp_fdinfo_release_ref(fdi, 0);
  return rc;
}

static int citp_passthrough_listen(citp_fdinfo* fdi, int backlog)
{
  int rc = ci_sys_listen(fdi_to_alien_fdi(fdi)->os_socket,
                         backlog);
  citp_fdinfo_release_ref(fdi, 0);
  return rc;
}
int
citp_passthrough_accept(citp_fdinfo* fdi,
                        struct sockaddr* sa, socklen_t* p_sa_len, int flags,
                        citp_lib_context_t* lib_context)
{
  return ci_sys_accept4(fdi_to_alien_fdi(fdi)->os_socket,
                        sa, p_sa_len, flags);
}
int
citp_passthrough_connect(citp_fdinfo* fdi,
                         const struct sockaddr* sa, socklen_t sa_len,
                         citp_lib_context_t* lib_context)
{
  int rc;
  citp_exit_lib(lib_context, 0);
  rc = ci_sys_connect(fdi_to_alien_fdi(fdi)->os_socket, sa, sa_len);
  citp_reenter_lib(lib_context);
  citp_fdinfo_release_ref(fdi, 0);
  return rc;
}
static int citp_passthrough_shutdown(citp_fdinfo* fdi, int how)
{
  return ci_sys_shutdown(fdi_to_alien_fdi(fdi)->os_socket, how);
}
static int
citp_passthrough_getsockname(citp_fdinfo* fdi,
                             struct sockaddr* sa, socklen_t* p_sa_len)
{
  return ci_sys_getsockname(fdi_to_alien_fdi(fdi)->os_socket,
                            sa, p_sa_len);
}
static int
citp_passthrough_getpeername(citp_fdinfo* fdi,
                             struct sockaddr* sa, socklen_t* p_sa_len)
{
  return ci_sys_getpeername(fdi_to_alien_fdi(fdi)->os_socket,
                            sa, p_sa_len);
}
static int
citp_passthrough_getsockopt(citp_fdinfo* fdi, int level,
                            int optname, void* optval, socklen_t* optlen)
{
  return ci_sys_getsockopt(fdi_to_alien_fdi(fdi)->os_socket,
                           level, optname, optval, optlen);
}
static int
citp_passthrough_setsockopt(citp_fdinfo* fdi, int level, int optname,
                            const void* optval, socklen_t optlen)
{
  int rc = ci_sys_setsockopt(fdi_to_alien_fdi(fdi)->os_socket,
                             level, optname, optval, optlen);
  citp_fdinfo_release_ref(fdi, 0);
  return rc;
}

static int
citp_passthrough_recv(citp_fdinfo* fdi, struct msghdr* msg, int flags)
{
  return ci_sys_recvmsg(fdi_to_alien_fdi(fdi)->os_socket,
                        msg, flags);
}
static int
citp_passthrough_send(citp_fdinfo* fdi, const struct msghdr* msg, int flags)
{
  return ci_sys_sendmsg(fdi_to_alien_fdi(fdi)->os_socket,
                        msg, flags);
}
static int
citp_passthrough_recvmmsg(citp_fdinfo* fdi, struct mmsghdr* msg, 
                          unsigned vlen, int flags,
                          ci_recvmmsg_timespec* timeout)
{
  return ci_sys_recvmmsg(fdi_to_alien_fdi(fdi)->os_socket,
                         msg, vlen, flags, timeout);
}

static int
citp_passthrough_sendmmsg(citp_fdinfo* fdinfo, struct mmsghdr* mmsg, 
                          unsigned vlen, int flags)
{
  return ci_sys_sendmmsg(fdi_to_alien_fdi(fdinfo)->os_socket,
                         mmsg, vlen, flags);
}



citp_protocol_impl citp_passthrough_protocol_impl = {
  .type        = CITP_PASSTHROUGH_FD,
  .ops         = {
    .dtor               = citp_passthrough_dtor,
    .dup                = citp_tcp_dup,

    .select             = citp_passthrough_select,
    .poll               = citp_passthrough_poll,

    .fcntl              = citp_passthrough_fcntl,
    .ioctl              = citp_passthrough_ioctl,
    .bind               = citp_passthrough_bind,
    .listen             = citp_passthrough_listen,
    .accept             = citp_passthrough_accept,
    .connect            = citp_passthrough_connect,
    .shutdown           = citp_passthrough_shutdown,
    .getsockname        = citp_passthrough_getsockname,
    .getpeername        = citp_passthrough_getpeername,
    .getsockopt         = citp_passthrough_getsockopt,
    .setsockopt         = citp_passthrough_setsockopt,
    .recv               = citp_passthrough_recv,
    .recvmmsg           = citp_passthrough_recvmmsg,
    .send               = citp_passthrough_send,
    .sendmmsg           = citp_passthrough_sendmmsg,

    .zc_send     = citp_nonsock_zc_send,
    .zc_recv     = citp_nonsock_zc_recv,
    .zc_recv_filter = citp_nonsock_zc_recv_filter,
    .recvmsg_kernel = citp_nonsock_recvmsg_kernel,
    .tmpl_alloc     = citp_nonsock_tmpl_alloc,
    .tmpl_update    = citp_nonsock_tmpl_update,
    .tmpl_abort     = citp_nonsock_tmpl_abort,
#if CI_CFG_TIMESTAMPING
    .ordered_data   = citp_nonsock_ordered_data,
#endif
#if CI_CFG_FD_CACHING
    .cache          = citp_nonsock_cache,
#endif
  }
};

void citp_passthrough_init(citp_alien_fdi* epi)
{
  int rc = oo_os_sock_get(epi->netif, epi->ep->bufid, &epi->os_socket);

  /* No sensible way to handle oo_os_sock_get failure.  Just record it. */
  if( rc != 0 ) {
    Log_U(ci_log("%s: oo_os_sock_get([%d:%d]) returned %d",
                 __func__, NI_ID(epi->netif), epi->ep->bufid, rc));
    epi->os_socket = -1;
    return;
  }
  __citp_fdtable_reserve(epi->os_socket, 1);
  /* ci_tcp_helper_get_sock_fd gets the citp_dup2_lock lock: release it  */
  oo_rwlock_unlock_read(&citp_dup2_lock);
}

