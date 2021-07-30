/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file epoll_common.c
** <L5_PRIVATE L5_HEADER >
** \author  oktet sasha
**  \brief  epoll-related functions common for different epoll implementations
**   \date  2011/02/14
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */


#include "internal.h"
#include "nonsock.h"

#define LPF "nonsock_fd: "

int citp_passthrough_fcntl(citp_fdinfo *fdi, int cmd, long arg)
{
  switch( cmd ) {

  case F_DUPFD:
    return citp_ep_dup(fdi->fd, citp_ep_dup_fcntl_dup, arg);
  case F_DUPFD_CLOEXEC:
    return citp_ep_dup(fdi->fd, citp_ep_dup_fcntl_dup_cloexec, arg);

  /* F_GETFL/F_SETFL, F_GETOWN/F_SETOWN, F_GETFD/F_SETFD,
   * F_GETLK/F_SETLK/F_SETLKW
   * have no effect on epoll fd, let's kernel report it together with
   * unknown fcntl cmds. */
  default:
    return ci_sys_fcntl(fdi->fd, cmd, arg);
  }
  /*UNREACHABLE*/
}

/* Poll/select via kernel */
int citp_passthrough_select(citp_fdinfo* fdinfo, int* n, int rd, int wr, int ex,
                            struct oo_ul_select_state* ss)
{
  return 0;
}
int citp_passthrough_poll(citp_fdinfo* fdinfo, struct pollfd* pfd,
                          struct oo_ul_poll_state* ps)
{
  return 0;
}

/* File operations which are "invalid" -- just pass them to OS in
 * appropriate way. */
int citp_nonsock_bind(citp_fdinfo* fdinfo,
                      const struct sockaddr* sa, socklen_t sa_len)
{
  Log_V(log(LPF "bind(%d)", fdinfo->fd));
  citp_fdinfo_release_ref(fdinfo, 0);
  errno = ENOTSOCK;
  return -1;
}
int citp_nonsock_listen(citp_fdinfo* fdinfo, int backlog)
{
  Log_V(log(LPF "listen(%d)", fdinfo->fd));
  citp_fdinfo_release_ref(fdinfo, 0);
  errno = ENOTSOCK;
  return -1;
}
int citp_nonsock_accept(citp_fdinfo* fdinfo,
                        struct sockaddr* sa, socklen_t* p_sa_len, int flags,
                        citp_lib_context_t* lib_context)
{
  Log_V(log(LPF "accept(%d)", fdinfo->fd));
  errno = ENOTSOCK;
  return -1;
}
int citp_nonsock_connect(citp_fdinfo* fdinfo,
                         const struct sockaddr* sa, socklen_t sa_len,
                         citp_lib_context_t* lib_context)
{
  Log_V(log(LPF "connect(%d)", fdinfo->fd));
  citp_fdinfo_release_ref(fdinfo, 0);
  errno = ENOTSOCK;
  return -1;
}
int citp_nonsock_shutdown(citp_fdinfo* fdinfo, int how)
{
  Log_V(log(LPF "shutdown(%d)", fdinfo->fd));
  errno = ENOTSOCK;
  return -1;
}
int citp_nonsock_getsockname(citp_fdinfo* fdinfo,
                             struct sockaddr* sa, socklen_t* p_sa_len)
{
  Log_V(log(LPF "getsockname(%d)", fdinfo->fd));
  errno = ENOTSOCK;
  return -1;
}
int citp_nonsock_getpeername(citp_fdinfo* fdinfo,
                             struct sockaddr* sa, socklen_t* p_sa_len)
{
  Log_V(log(LPF "getpeername(%d)", fdinfo->fd));
  errno = ENOTSOCK;
  return -1;
}
int citp_nonsock_getsockopt(citp_fdinfo* fdinfo, int level,
                            int optname, void* optval, socklen_t* optlen)
{
  Log_V(log(LPF "getsockopt(%d)", fdinfo->fd));
  errno = ENOTSOCK;
  return -1;
}
int citp_nonsock_setsockopt(citp_fdinfo* fdinfo, int level, int optname,
                            const void* optval, socklen_t optlen)
{
  Log_V(log(LPF "setsockopt(%d)", fdinfo->fd));
  citp_fdinfo_release_ref(fdinfo, 0);
  errno = ENOTSOCK;
  return -1;
}
int citp_nonsock_recv(citp_fdinfo* fdinfo, struct msghdr* msg, int flags)
{
  return ci_sys_recvmsg(fdinfo->fd, msg, flags);
}
int citp_nonsock_send(citp_fdinfo* fdinfo, const struct msghdr* msg,
                          int flags)
{
  return ci_sys_sendmsg(fdinfo->fd, msg, flags);
}

int citp_nonsock_zc_send(citp_fdinfo* fdi, struct onload_zc_mmsg* msg, 
                        int flags)
{
  Log_V(log(LPF "sc_send(%d)", fdi->fd));
  msg->rc = -ESOCKTNOSUPPORT;
  return 1;
}
int citp_nonsock_zc_recv(citp_fdinfo* fdi, 
                         struct onload_zc_recv_args* args)
{
  Log_V(log(LPF "sc_recv(%d)", fdi->fd));
  return -ESOCKTNOSUPPORT;
}
int citp_nonsock_recvmsg_kernel(citp_fdinfo* fdi, struct msghdr *msg, 
                                int flags)
{
  Log_V(log(LPF "recvmsg_kernel(%d)", fdi->fd));
  return -ENOTSOCK;
}
int citp_nonsock_zc_recv_filter(citp_fdinfo* fdi,
                                onload_zc_recv_filter_callback filter,
                                void* cb_arg, int flags)
{
  Log_V(log(LPF "zc_recv_filter(%d)", fdi->fd));
# if CI_CFG_ZC_RECV_FILTER
  return -ESOCKTNOSUPPORT;
# else
  return -ENOSYS;
# endif
}

int citp_nonsock_tmpl_alloc(citp_fdinfo* fdi, const struct iovec* initial_msg,
                            int mlen, struct oo_msg_template** omt_pp,
                            unsigned flags)
{
  Log_V(log(LPF "tmpl_alloc(%d)", fdi->fd));
  return -EOPNOTSUPP;
}


int
citp_nonsock_tmpl_update(citp_fdinfo* fdi, struct oo_msg_template* omt,
                         const struct onload_template_msg_update_iovec* updates,
                         int ulen, unsigned flags)
{
  Log_V(log(LPF "tmpl_update(%d)", fdi->fd));
  return -EOPNOTSUPP;
}


int citp_nonsock_tmpl_abort(citp_fdinfo* fdi, struct oo_msg_template* omt)
{
  Log_V(log(LPF "tmpl_abort(%d)", fdi->fd));
  return -EOPNOTSUPP;
}


#if CI_CFG_TIMESTAMPING
int citp_nonsock_ordered_data(citp_fdinfo* fdi, struct timespec* limit,
                              struct timespec* first_out, int* bytes_out)
{
  Log_V(log(LPF "ordered_data(%d)", fdi->fd));
  return -EOPNOTSUPP;
}
#endif

int citp_nonsock_is_spinning(citp_fdinfo* fdi)
{
  return 0;
}

int citp_nonsock_recvmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg, 
                          unsigned vlen, int flags,
                          ci_recvmmsg_timespec* timeout)
{
  errno = ENOTSOCK;
  return -1;
}

int citp_nonsock_sendmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg, 
                          unsigned vlen, int flags)
{
  errno = ENOTSOCK;
  return -1;
}

#if CI_CFG_FD_CACHING
int citp_nonsock_cache(citp_fdinfo* fdi, enum citp_ep_close_flag close_flag)
{
  Log_V(log(LPF "cache(%d)", fdi->fd));
  return -EOPNOTSUPP;
}
#endif

