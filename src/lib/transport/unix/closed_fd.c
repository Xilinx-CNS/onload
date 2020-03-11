/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  File operations for fds that app should think are closed.
**   \date  2003/01/09
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_unix */
 
#include <netinet/in.h>
#include <internal.h>


#define LPF      "citp_closedfd_"


citp_fdinfo  citp_the_closed_fd = {
  .ref_count = CI_ATOMIC_INITIALISER(1000000),
  .fd = -1,
  .protocol = &citp_closed_protocol_impl,
  .is_special = 1,
};

citp_fdinfo  citp_the_reserved_fd = {
  .ref_count = CI_ATOMIC_INITIALISER(1000000),
  .fd = -1,
  .protocol = &citp_closed_protocol_impl,
  .is_special = 1,
};


int citp_closedfd_socket(int domain, int type, int protocol)
{
  CI_DEBUG(ci_fail((LPF "socket: shouldn't ever happen!")));
  return -1;
}


static void citp_closedfd_dtor(citp_fdinfo* fdinfo, int fdt_locked)
{
  CI_DEBUG(ci_fail((LPF "dtor: shouldn't ever happen!")));
}


/* bind(), listen() at al should not use citp_nonsock_* functions because
 * we have to return EBADF instead of ENOTSOCK */

static int citp_closedfd_bind(citp_fdinfo* fdinfo,
			    const struct sockaddr* sa, socklen_t sa_len)
{
  Log_E(log(LPF "bind(%d, sa, %d)", fdinfo->fd, (int) sa_len));
  errno = EBADF;
  citp_fdinfo_release_ref(fdinfo, 0);
  return -1;
}


static int citp_closedfd_listen(citp_fdinfo* fdinfo, int backlog)
{
  Log_E(log(LPF "listen(%d, %d)", fdinfo->fd, backlog));
  errno = EBADF;
  citp_fdinfo_release_ref(fdinfo, 0);
  return -1;
}


static int citp_closedfd_accept(citp_fdinfo* fdinfo,
			      struct sockaddr* sa, socklen_t* p_sa_len,
                              int flags,
                              citp_lib_context_t* lib_context)
{
  Log_E(log(LPF "accept(%d, sa, p_sa_len)", fdinfo->fd));
  errno = EBADF;
  return -1;
}


static int citp_closedfd_connect(citp_fdinfo* fdinfo,
			       const struct sockaddr* sa, socklen_t sa_len,
                               citp_lib_context_t* lib_context)
{
  Log_V(log(LPF "connect(%d, sa, %d)", fdinfo->fd, sa_len));
  errno = EBADF;
  citp_fdinfo_release_ref(fdinfo, 0);
  return -1;
}


static int citp_closedfd_shutdown(citp_fdinfo* fdinfo, int how)
{
  Log_V(log(LPF "shutdown(%d, %d)", fdinfo->fd, how));
  errno = EBADF;
  return -1;
}


static int citp_closedfd_getsockname(citp_fdinfo* fdinfo,
				   struct sockaddr* sa, socklen_t* p_sa_len)
{
  Log_V(log(LPF "getsockname(%d)", fdinfo->fd));
  errno = EBADF;
  return -1;
}


static int citp_closedfd_getpeername(citp_fdinfo* fdinfo,
				   struct sockaddr* sa, socklen_t* p_sa_len)
{
  Log_V(log(LPF "getpeername(%d)", fdinfo->fd));
  errno = EBADF;
  return -1;
}


static int citp_closedfd_getsockopt(citp_fdinfo* fdinfo, int level,
				  int optname, void* optval, socklen_t* optlen)
{
  Log_V(log(LPF "getsockopt(%d, %d, %d)", fdinfo->fd, level, optname));
  errno = EBADF;
  return -1;
}


static int citp_closedfd_setsockopt(citp_fdinfo* fdinfo, int level,
			  int optname, const void* optval, socklen_t optlen)
{
  Log_V(log(LPF "setsockopt(%d, %d, %d)", fdinfo->fd, level, optname));
  errno = EBADF;
  return -1;
}


static int citp_closedfd_recv(citp_fdinfo* fdinfo,
			      struct msghdr* msg, int flags)
{
  Log_V(log(LPF "recv(%d, msg, 0x%x)", fdinfo->fd, (unsigned) flags));
  errno = EBADF;
  return -1;
}


static int citp_closedfd_recvmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg, 
                                  unsigned vlen, int flags,
                                  ci_recvmmsg_timespec* timeout)
{
  Log_V(log(LPF "recvmmsg(%d, msg, %d, 0x%x)", fdinfo->fd, vlen, 
            (unsigned) flags));
  errno = EBADF;
  return -1;
}


static int citp_closedfd_send(citp_fdinfo* fdinfo,
			      const struct msghdr* msg, int flags)
{
  Log_V(log(LPF "send(%d, msg, 0x%x)", fdinfo->fd, (unsigned) flags));
  errno = EBADF;
  return -1;
}

static int citp_closedfd_sendmmsg(citp_fdinfo* fdinfo,
                                  struct mmsghdr* msg, 
                                  unsigned vlen, int flags)
{
  Log_V(log(LPF "sendmmsg(%d, msg, %d, 0x%x)", fdinfo->fd, vlen, 
            (unsigned) flags));
  errno = EBADF;
  return -1;
}

static int citp_closedfd_fcntl(citp_fdinfo *fdinfo, int cmd, long arg)
{
  Log_V(log(LPF "fcntl(%d, cmd=%d, arg=%ld)", fdinfo->fd, cmd, arg));
  errno = EBADF;
  return -1;
}


static int citp_closedfd_ioctl(citp_fdinfo* fdinfo, int request, void* arg)
{
  Log_V(log(LPF "ioctl(%d)", fdinfo->fd ));
  errno = EBADF;
  return -1;
}


static int citp_closedfd_select(citp_fdinfo* fdinfo, int* n, int rd, int wr,
                                int ex, struct oo_ul_select_state* ss)
{
  return 0;
}


static int citp_closedfd_poll(citp_fdinfo* fdinfo, struct pollfd* pfd,
			      struct oo_ul_poll_state* ps)
{
  pfd->revents = POLLNVAL;
  return 1;
}


static int citp_closedfd_zc_send(citp_fdinfo* fdi, struct onload_zc_mmsg* msg, 
                                 int flags)
{
  msg->rc = -EBADF;
  return 1;
}


static int citp_closedfd_zc_recv(citp_fdinfo* fdi, 
                                 struct onload_zc_recv_args* args)
{
  return -EBADF;
}


static int citp_closedfd_recvmsg_kernel(citp_fdinfo* fdi, struct msghdr *msg, 
                                        int flags)
{
  return -EBADF;
}


static int citp_closedfd_zc_recv_filter(citp_fdinfo* fdi,
                                        onload_zc_recv_filter_callback filter,
                                        void* cb_arg, int flags)
{
#if CI_CFG_ZC_RECV_FILTER
  return -EBADF;
#else
  return -ENOSYS;
#endif
}


#if CI_CFG_FD_CACHING
static int citp_closedfd_cache(citp_fdinfo* fdi)
{
  /* This should only be called as we're deciding whether to actually close an
   * fd - the closedfd doesn't really have an fd, so we shouldn't get here!
   */
  ci_assert(0);
  return -EBADF;
}
#endif


citp_protocol_impl citp_closed_protocol_impl = {
  .type        = -1,
  .ops         = {
    .socket      = citp_closedfd_socket,
    .dtor        = citp_closedfd_dtor,
    .bind        = citp_closedfd_bind,
    .listen      = citp_closedfd_listen,
    .accept      = citp_closedfd_accept,
    .connect     = citp_closedfd_connect,
    .shutdown    = citp_closedfd_shutdown,
    .getsockname = citp_closedfd_getsockname,
    .getpeername = citp_closedfd_getpeername,
    .getsockopt  = citp_closedfd_getsockopt,
    .setsockopt  = citp_closedfd_setsockopt,
    .recv        = citp_closedfd_recv,
    .recvmmsg    = citp_closedfd_recvmmsg,
    .send        = citp_closedfd_send,
    .sendmmsg    = citp_closedfd_sendmmsg,
    .ioctl       = citp_closedfd_ioctl,
    .fcntl       = citp_closedfd_fcntl,
    .select	 = citp_closedfd_select,
    .poll	 = citp_closedfd_poll,
    .zc_send     = citp_closedfd_zc_send,
    .zc_recv     = citp_closedfd_zc_recv,
    .zc_recv_filter = citp_closedfd_zc_recv_filter,
    .recvmsg_kernel = citp_closedfd_recvmsg_kernel,
#if CI_CFG_FD_CACHING
    .cache       = citp_closedfd_cache,
#endif
  }
};

/*! \cidoxg_end */
