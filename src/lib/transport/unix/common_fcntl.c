/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr/ctk
**  \brief  Sockets interface to user level TCP
**   \date
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */

#include <internal.h>
#include <netinet/in.h>
#include <ci/internal/transport_config_opt.h>
#include <onload/ul/tcp_helper.h>


#define VERB(x)

int citp_sock_fcntl_os_sock(citp_sock_fdi* epi, int fd,
                            int cmd, long arg, const char* cmd_str,
                            int *fcntl_result)
{
  /* If we have an OS sock associated with this socket, then apply fcntl()
   * to it and return the result in fcntl_result.  The rc of the function
   * is 0 or error.
   */
  int dummy;
  int os_sock;
  int rc;

  if( fcntl_result == NULL )
    fcntl_result = &dummy;
  *fcntl_result = 0;

  if( (epi->sock.s->b.sb_aflags & CI_SB_AFLAG_OS_BACKED) == 0 ) {
    /* This socket doesn't have an OS socket.  O_ASYNC is tricky to deal with
     * later, and we can't cache sockets using it anyway as we need to enter
     * the kernel to sort out the async queue.  If we don't have an OS socket
     * just because we're deferring creation then just create one now.
     */
    if( (cmd == F_SETFL) && (arg & O_ASYNC) &&
        (epi->sock.s->b.state == CI_TCP_CLOSED) &&
        !(SOCK_TO_TCP(epi->sock.s)->tcpflags & CI_TCPT_FLAG_PASSIVE_OPENED) ) {
      ci_netif_lock(epi->sock.netif);
      rc = ci_tcp_helper_os_sock_create_and_set(epi->sock.netif, fd,
                                                epi->sock.s, -1, 0, NULL, 0);
      ci_netif_unlock(epi->sock.netif);
      if( rc < 0 )
        return rc;
    }
    else {
      /* Either we'll never have an OS socket, or we'll sync this up when
       * it's created.
       */
      return 0;
    }
  }

  os_sock = ci_get_os_sock_fd(fd);
  if( ! CI_IS_VALID_SOCKET(os_sock) ) {
    /* Only errors that are possible are:
     *   i) There is no OS socket (handled above, (impossible))
     *  ii) There are no more file-descriptors available (ENFILE)
     */
    ci_log("%s: ERROR: could not get fd for OS sock "
           "(fd=%d state=%s cmd=%s error=%d)",
           __func__, fd, ci_tcp_state_str(epi->sock.s->b.state),
           cmd_str, -os_sock);
    ci_assert(os_sock == -ENFILE || os_sock == -EMFILE);
    return os_sock;
  }

  *fcntl_result = ci_sys_fcntl(os_sock, cmd, arg);
  ci_rel_os_sock_fd(os_sock);
  if( *fcntl_result < 0 )
    ci_log("%s: ERROR: fcntl on OS sock failed (fd=%d cmd=%s error=%d)",
           __func__, fd, cmd_str, -(*fcntl_result));
  return 0;
}



static unsigned fd_flags_to_sbflags(int fd_flags)
{
  unsigned sbflags = 0;
  if( fd_flags & O_ASYNC    )  sbflags |= CI_SB_AFLAG_O_ASYNC;
  if( fd_flags & O_APPEND   )  sbflags |= CI_SB_AFLAG_O_APPEND;
  if( fd_flags & O_NONBLOCK )  sbflags |= CI_SB_AFLAG_O_NONBLOCK;
  if( fd_flags & O_NDELAY   )  sbflags |= CI_SB_AFLAG_O_NDELAY;
  return sbflags;
}


static int sbflags_to_fd_flags(unsigned sbflags)
{
  int fd_flags = 0;
  if( sbflags & CI_SB_AFLAG_O_ASYNC    )  fd_flags |= O_ASYNC;
  if( sbflags & CI_SB_AFLAG_O_APPEND   )  fd_flags |= O_APPEND;
  if( sbflags & CI_SB_AFLAG_O_NONBLOCK )  fd_flags |= O_NONBLOCK;
  if( sbflags & CI_SB_AFLAG_O_NDELAY   )  fd_flags |= O_NDELAY;
  return fd_flags;
}


int citp_sock_fcntl(citp_sock_fdi *epi, int fd, int cmd, long arg)
{
  ci_sock_cmn* s = epi->sock.s;
  int rc = 0;

  Log_VSC(log("%s("EF_FMT", %#x, %#lx)", __FUNCTION__, EF_PRI_ARGS(epi,fd),
              (unsigned)cmd, (unsigned long)arg));

  switch( cmd ) {

  case F_GETFL: {
    rc = sbflags_to_fd_flags(s->b.sb_aflags) | O_RDWR;
    break;
  }

  case F_SETFL: {
    /* Set the descriptor's flags.  Only O_APPEND, O_NONBLOCK, O_ASYNC
    ** (linux only) can be set.  O_DIRECT provokes EINVAL, whereas other
    ** flags are ignored silently.
    */
    ci_uint32 mask;

    if( arg & O_DIRECT ) {
      CI_SET_ERROR(rc, EINVAL);
      break;
    }

    /* Apply to this fd and also the OS socket.
     * FASYNC should be set to our fd first, because our in-kernel code
     * pushes it to OS socket with correct fd.
     */
    rc = ci_sys_fcntl(fd, cmd, arg);
    if( rc < 0 )
      break;

    {
      long os_arg = arg;
      citp_sock_fcntl_os_sock(epi, fd, cmd, os_arg, "F_SETFL", NULL);
    }


    mask = (CI_SB_AFLAG_O_APPEND | CI_SB_AFLAG_O_NONBLOCK |
            CI_SB_AFLAG_O_NDELAY | CI_SB_AFLAG_O_ASYNC);
    ci_atomic32_merge(&s->b.sb_aflags, fd_flags_to_sbflags(arg), mask);
    break;
  }

  case F_GETOWN:
    /* get the process ID/group that is receiving signals for this fd */
    rc = s->b.sigown;
    break;

  case F_SETOWN:
    /* On Solaris, fcntl(fd, F_SETOWN, arg) returns error
     * for non-socket fd's */
    if( (rc = ci_sys_fcntl(fd, cmd, arg)) != 0 )
        break;
    s->b.sigown = arg;
    citp_sock_fcntl_os_sock(epi, fd, cmd, arg, "F_SETOWN", NULL);
    if( s->b.sigown && (s->b.sb_aflags & CI_SB_AFLAG_O_ASYNC) )
      ci_bit_set(&s->b.wake_request, CI_SB_FLAG_WAKE_RX_B);
    break;

/* F_GETOWN_EX/F_SETOWN_EX are not supported on all platforms */
  case F_GETOWN_EX:
    /* Grab the owner from the kernel so we don't have to remember the owner
     * type.
     */
    rc = ci_sys_fcntl(fd, cmd, arg);
    break;

  case F_SETOWN_EX: {
    struct f_owner_ex* own;
    rc = ci_sys_fcntl(fd, cmd, arg);
    if( rc != 0 )
      break;
    own = (struct f_owner_ex*)arg;
    if( own->type == F_OWNER_PGRP )
      s->b.sigown = -(own->pid);
    else
      s->b.sigown = own->pid;
    citp_sock_fcntl_os_sock(epi, fd, cmd, arg, "F_SETOWN_EX", NULL);
    if( s->b.sigown && (s->b.sb_aflags & CI_SB_AFLAG_O_ASYNC) )
      ci_bit_set(&s->b.wake_request, CI_SB_FLAG_WAKE_RX_B);
    break;
  }

  case F_GETSIG:
    rc = ci_sys_fcntl(fd, cmd, arg);
    break;

  case F_SETSIG:
    if( (rc = ci_sys_fcntl(fd, cmd, arg)) != 0 )
      break;
    citp_sock_fcntl_os_sock(epi, fd, cmd, arg, "F_SETSIG", NULL);
    break;

  case F_DUPFD:
    rc = citp_ep_dup(fd, citp_ep_dup_fcntl_dup, arg);
    break;
  case F_DUPFD_CLOEXEC:
    rc = citp_ep_dup(fd, citp_ep_dup_fcntl_dup_cloexec, arg);
    break;

  case F_GETFD:
  case F_SETFD:
    rc = ci_sys_fcntl(fd, cmd, arg);
    if( rc < 0 )
      break;

    if( cmd == F_GETFD ) {
      arg = rc;
      if( ! (arg & FD_CLOEXEC) !=
          ! (s->b.sb_aflags & CI_SB_AFLAG_O_CLOEXEC) ) {
        Log_U(ci_log("F_GETFD: unexpected CLOEXEC settings: "
                     "expecting %s, got %s",
                     s->b.sb_aflags & CI_SB_AFLAG_O_CLOEXEC ? "on" : "off",
                     arg & FD_CLOEXEC ? "on" : "off"));
      }
    }
    ci_atomic32_merge(&s->b.sb_aflags,
                      arg & FD_CLOEXEC ? CI_SB_AFLAG_O_CLOEXEC : 0,
                      CI_SB_AFLAG_O_CLOEXEC);
    break;

  case F_GETLK:
  case F_SETLK:
  case F_SETLKW:
#if defined F_GETLK64 && F_GETLK64 != F_GETLK
  case F_GETLK64:
  case F_SETLK64:
  case F_SETLKW64:
#endif
    /* File locks not supported on sockets */
    Log_U(ci_log("%s: "EF_FMT" cmd %d not supported on sockets!",__FUNCTION__,
                 EF_PRI_ARGS(epi, fd), cmd));
    errno = ENOTSUP;
    rc = CI_SOCKET_ERROR;
    break;

  default:
    Log_U(ci_log("%s: "EF_FMT" unknown cmd %d", __FUNCTION__,
                 EF_PRI_ARGS(epi, fd), cmd));
    errno = ENOTSUP;
    rc = CI_SOCKET_ERROR;
    break;
  }

  Log_VSC(log("%s(%d, %d, %ld) = %d  (errno=%d)",
	      __FUNCTION__, fd, cmd, arg, rc, errno));

  return rc;
}

/*! \cidoxg_end */
