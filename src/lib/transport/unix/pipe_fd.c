/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr/ctk/stg
**  \brief  Sockets interface to user level pipe
**   \date  2004/06/02 (pipe version)
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include "internal.h"
#include "ul_pipe.h"
#include "ul_poll.h"
#include "ul_select.h"
#include "ul_epoll.h"
#include <onload/ul/tcp_helper.h>
#include <onload/oo_pipe.h>
#include <onload/tcp_poll.h>


#define VERB(x) Log_VTC(x)

#if 0
# define LOG_PIPE(x...) ci_log(x)
#else
# define LOG_PIPE(x...)
#endif

#define LPF "citp_pipe_"

#define fdi_to_pipe(_fdi) (fdi_to_pipe_fdi(_fdi))->pipe
#define fdi_is_reader(_fdi) ((_fdi)->protocol == &citp_pipe_read_protocol_impl)


static void citp_pipe_dtor(citp_fdinfo* fdinfo, int fdt_locked)
{
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdinfo);

  LOG_PIPE("%s: fdinfo=%p epi=%p", __FUNCTION__, fdinfo, epi);

  citp_netif_release_ref(epi->ni, fdt_locked);
  LOG_PIPE("%s: done", __FUNCTION__);
}

static citp_fdinfo* citp_pipe_dup(citp_fdinfo* orig_fdi)
{
  citp_fdinfo*   fdi;
  citp_pipe_fdi* epi;
  struct oo_pipe*       p = fdi_to_pipe(orig_fdi);

  epi = CI_ALLOC_OBJ(citp_pipe_fdi);
  if (!epi)
    return NULL;

  fdi = &epi->fdinfo;
  citp_fdinfo_init(fdi, orig_fdi->protocol);
  epi->ni = (fdi_to_pipe_fdi(orig_fdi))->ni;
  epi->pipe = p;

  /* we use pages_buf from netif - don't want it to be gone too fast */
  citp_netif_add_ref(epi->ni);
  return fdi;
}

static int citp_pipe_recv(citp_fdinfo* fdinfo,
                          struct msghdr* msg, int flags)
{
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdinfo);

  ci_assert_equal(flags, 0);
  ci_assert(msg);
  ci_assert(msg->msg_iov);

  return ci_pipe_read(epi->ni, epi->pipe, msg->msg_iov, msg->msg_iovlen);
}


static int citp_pipe_send(citp_fdinfo* fdinfo,
                          const struct msghdr* msg, int flags)
{
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdinfo);

  ci_assert_equal(flags, 0);
  ci_assert(msg);
  ci_assert(msg->msg_iov);

  return ci_pipe_write(epi->ni, epi->pipe, msg->msg_iov, msg->msg_iovlen);
}



int citp_splice_pipe_pipe(citp_pipe_fdi* in_pipe_fdi,
                          citp_pipe_fdi* out_pipe_fdi, size_t rlen, int flags)
{
  return ci_pipe_zc_move(in_pipe_fdi->ni, in_pipe_fdi->pipe,
                         out_pipe_fdi->pipe, rlen,
                         (flags & SPLICE_F_NONBLOCK) ? MSG_DONTWAIT : 0);
}


/* Copies data from an alien descriptor to pipe
 *
 * Some observations on kernel implementation behaviour:
 * * when alien fd is blocking, the call will block if a single byte cannot
 *   be read
 * * when pipe fd is blocking (and no F_NONBLOCK flag) the call will block
 *   only if a single byte cannot be written
 * otherwise the call will not block and typically moves
 *  MIN(alien_fd_data_available, pipe_capacity) bytes...
 * however read operation on kernel pipe might not always return all data
 * so it seems there is no warranty all available data has been moved.
 *
 * For now we do just one iteration allocating all the necessary iovec memory
 * to avoid potential block on readv.
 *
 * If we new we deal with socket we could use instead of readv with
 * recvmsg and non-blocking flags.
 */
#define CITP_PIPE_SPLICE_WRITE_STACK_IOV_LEN 64
int citp_pipe_splice_write(citp_fdinfo* fdi, int alien_fd, loff_t* alien_off,
                           size_t olen, int flags,
                           citp_lib_context_t* lib_context)
{
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdi);
  struct iovec iov_on_stack[CITP_PIPE_SPLICE_WRITE_STACK_IOV_LEN];
  struct iovec* iov = iov_on_stack;
  int iov_num_allocated = CITP_PIPE_SPLICE_WRITE_STACK_IOV_LEN;
  int want_buf_count;
  int rc;
  int bytes_to_read;
  int len = olen;
  int no_more = 1; /* for now we only run single loop */
  int written_total = 0;
  int non_block = flags & SPLICE_F_NONBLOCK;
  if( fdi_is_reader(fdi) ) {
    errno = EINVAL;
    return -1;
  }
  if( alien_off ) {
    /* TODO support this */
    errno = ENOTSUP;
    return -1;
  }

  {
    struct pollfd pfd;

    pfd.fd = alien_fd;
    pfd.events = POLLIN;

    if( onload_fcntl(alien_fd, F_GETFL) & O_NONBLOCK ) {
      /* alien_fd is non-blocking.  Do we have any data? */
      if( onload_poll(&pfd, 1, 0) == 0 ) {
        errno = EAGAIN;
        return -1;
      }
    }
    else {
      /* alien_fd could block.  Do it before allocating pipe buffers. */
    restart_poll:
      rc = onload_poll(&pfd, 1, -1);

      /* Run pending signals. */
      {
        int inside_lib =
              oo_exit_lib_temporary_begin(&lib_context->thread->sig);
        oo_exit_lib_temporary_end(&lib_context->thread->sig, inside_lib);
      }

      if( rc < 0 ) {
        /* When poll() is interrupted by a signal with the SA_RESTART flag set,
         * it returns EINTR errno. We should to restart it manually. */
        if( errno == EINTR &&
            (lib_context->thread->sig.c.aflags & OO_SIGNAL_FLAG_NEED_RESTART) )
          goto restart_poll;
        return rc;
      }
    }
  }

  do {
    int count;
    int iov_num;
    int bytes_to_write;
    struct ci_pipe_pkt_list pkts = {};
    struct ci_pipe_pkt_list pkts2;
    int bytes_in_sock;

    if( onload_ioctl(alien_fd, FIONREAD, &bytes_in_sock) == 0 ) {
      if( bytes_in_sock == 0 ) {
        if( written_total ) {
          rc = written_total;
          break;
        }
        /* Someone could read from alien_fd after the poll() above.
         * It is silly, but it could happen.  We just assume the minimal
         * amount of data in the alien_fd. */
        bytes_in_sock = 1;
      }
    }
    else
      bytes_in_sock = olen;
    bytes_in_sock = CI_MIN(bytes_in_sock, olen - written_total);
    want_buf_count = OO_PIPE_SIZE_TO_BUFS(bytes_in_sock);

    /* We might need to wait for buffers here on the first iteration */
    rc = ci_pipe_zc_alloc_buffers(epi->ni, epi->pipe, want_buf_count,
                                  MSG_NOSIGNAL | (non_block || written_total ?
                                  MSG_DONTWAIT : 0),
                                  &pkts);
    if( rc < 0 && written_total ) {
      /* whatever the error we need to report already written_bytes */
      rc = written_total;
      break;
    }
    else if( rc < 0 )
      break;
    else if( pkts.count == 0 && non_block ) {
      errno = EAGAIN;
      rc = -1;
      break;
    }
    else
      ci_assert_gt(pkts.count, 0);
    count = pkts.count;

    if( count > iov_num_allocated ) {
      void* niov = realloc(iov == iov_on_stack ? NULL : iov,
                           sizeof(*iov) * count);
      if( niov == NULL ) {
        /* we can still move quite a few pkts */
        count = iov_num_allocated;
      }
      else {
        iov = niov;
        iov_num_allocated = count;
      }
    }

    ci_assert_ge(count, 1);

    iov_num = count;
    pkts2 = pkts;
    bytes_to_read = ci_pipe_list_to_iovec(epi->ni, epi->pipe, iov, &iov_num,
                                          &pkts2, len);

    citp_exit_lib_if(lib_context, TRUE);
    /* Note: the following call might be non-blocking as well as blocking */
    rc = onload_readv(alien_fd, iov, count);
    citp_reenter_lib(lib_context);

    if( rc > 0 ) {
      bytes_to_write = rc;
      written_total += bytes_to_write;
      len -= bytes_to_write;
      no_more |= bytes_to_write < bytes_to_read;
    }
    else {
      bytes_to_write = 0;
      no_more = 1;
    }

    {
      /* pipe zc_write will write non_empty buffers and release the empty
       * ones */
      int rc2 = ci_pipe_zc_write(epi->ni, epi->pipe, &pkts, bytes_to_write,
                  CI_PIPE_ZC_WRITE_FLAG_FORCE | MSG_DONTWAIT | MSG_NOSIGNAL);
      (void) rc2;
      ci_assert_equal(rc2, bytes_to_write);
    }
    /* for now we will not be doing second iteration, to allow for that
     * we'd need to have guarantee that read will not block
     * e.g. insight into type of fd and a nonblokcing operation
     * (to name a valid case: socket, recvmsg) */
  } while( ! no_more );

  if( iov != iov_on_stack )
    free(iov);
  if( rc > 0 )
    return written_total;
  if( rc < 0 && errno == EPIPE && ! (flags & MSG_NOSIGNAL) ) {
    oo_resource_op(ci_netif_get_driver_handle(epi->ni),
                   OO_IOC_KILL_SELF_SIGPIPE, NULL);
  }
  return rc;
}


struct oo_splice_read_context {
  int alien_fd;
  size_t len;
  citp_lib_context_t* lib_context;
};


#define CITP_PIPE_SPLICE_READ_STACK_IOV_LEN 64
static int oo_splice_read_cb(void* context, struct iovec* iov,
                             int iov_num, int flags)
{
  struct oo_splice_read_context* ctx = context;
  int rc;
  citp_exit_lib_if(ctx->lib_context, TRUE);
  rc = onload_writev(ctx->alien_fd, iov, iov_num);
  citp_enter_lib(ctx->lib_context);
  return rc;
}


int citp_pipe_splice_read(citp_fdinfo* fdi, int alien_fd, loff_t* alien_off,
                          size_t len, int flags,
                          citp_lib_context_t* lib_context)
{
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdi);
  int rc;
  int read_len = 0;
  int non_block = flags & SPLICE_F_NONBLOCK;
  if( ! fdi_is_reader(fdi) ) {
    errno = EINVAL;
    return -1;
  }
  if( alien_off ) {
    /* TODO support this */
    errno = ENOTSUP;
    return -1;
  }
  if( len == 0 )
    return 0;
  do {
    struct oo_splice_read_context ctx = {
      .alien_fd = alien_fd,
      .len = len,
      .lib_context = lib_context
    };
    rc = ci_pipe_zc_read(epi->ni, epi->pipe, len,
                         non_block ? MSG_DONTWAIT : 0,
                         oo_splice_read_cb, &ctx);
    if( rc > 0 )
      read_len += rc;
  } while(0);

  if( rc < 0 && errno == EPIPE && ! (flags & MSG_NOSIGNAL) ) {
    oo_resource_op(ci_netif_get_driver_handle(epi->ni),
                   OO_IOC_KILL_SELF_SIGPIPE, NULL);
    return rc;
  }
  if( rc > 0 )
    return read_len;
  return rc;
}



static int citp_pipe_select_reader(citp_fdinfo* fdinfo, int* n,
                                   int rd, int wr, int ex,
                                   struct oo_ul_select_state* ss)
{
  citp_pipe_fdi* epi;
  struct oo_pipe* p;
  unsigned mask = 0;

  epi = fdi_to_pipe_fdi(fdinfo);
  p = epi->pipe;

#if CI_CFG_SPIN_STATS
  if( CI_UNLIKELY(! ss->stat_incremented) ) {
    epi->ni->state->stats.spin_select++;
    ss->stat_incremented = 1;
  }
#endif

  /* set mask */
  mask = oo_pipe_poll_read_events(p);

  if( rd && (mask & SELECT_RD_SET) ) {
    FD_SET(fdinfo->fd, ss->rdu);
    ++*n;
  }

  return 1;
}

static int citp_pipe_select_writer(citp_fdinfo* fdinfo, int* n,
                                   int rd, int wr, int ex,
                                   struct oo_ul_select_state* ss)
{
  citp_pipe_fdi* epi;
  struct oo_pipe* p;
  unsigned mask;

  epi = fdi_to_pipe_fdi(fdinfo);
  p = epi->pipe;

#if CI_CFG_SPIN_STATS
  epi->ni->state->stats.spin_select++;
#endif

  /* set mask */
  mask = oo_pipe_poll_write_events(p);

  if( wr && (mask & SELECT_WR_SET) ) {
    FD_SET(fdinfo->fd, ss->wru);
    ++*n;
  }

  return 1;
}

static int citp_pipe_poll_reader(citp_fdinfo* fdinfo, struct pollfd* pfd,
                                 struct oo_ul_poll_state* ps)
{
  citp_pipe_fdi* epi;
  struct oo_pipe* p;
  unsigned mask;

  epi = fdi_to_pipe_fdi(fdinfo);
  p = epi->pipe;

#if CI_CFG_SPIN_STATS
  if( CI_UNLIKELY(! ps->stat_incremented) ) {
    epi->ni->state->stats.spin_poll++;
    ps->stat_incremented = 1;
  }
#endif

  /* set mask */
  mask = oo_pipe_poll_read_events(p);

  /* set revents */
  pfd->revents = mask & (pfd->events | POLLERR | POLLHUP);

  return 1;
}


static int citp_pipe_poll_writer(citp_fdinfo* fdinfo, struct pollfd* pfd,
                                 struct oo_ul_poll_state* ps)
{
  citp_pipe_fdi* epi;
  struct oo_pipe* p;
  unsigned mask;

  epi = fdi_to_pipe_fdi(fdinfo);
  p = epi->pipe;

#if CI_CFG_SPIN_STATS
  if( CI_UNLIKELY(! ps->stat_incremented) ) {
    epi->ni->state->stats.spin_poll++;
    ps->stat_incremented = 1;
  }
#endif

  /* set mask */
  mask = oo_pipe_poll_write_events(p);

  /* set revents */
  pfd->revents = mask & (pfd->events | POLLERR | POLLHUP);

  return 1;
}



static int citp_pipe_epoll_reader(citp_fdinfo* fdinfo,
                                  struct citp_epoll_member* eitem,
                                  struct oo_ul_epoll_state* eps,
                                  int* stored_event)
{
  unsigned mask;
  struct oo_pipe* pipe = fdi_to_pipe_fdi(fdinfo)->pipe;
  ci_uint64 sleep_seq;
  int seq_mismatch = 0;

#if CI_CFG_SPIN_STATS
  if( CI_UNLIKELY(! eps->stat_incremented) ) {
    fdi_to_pipe_fdi(fdinfo)->ni->state->stats.spin_epoll++;
    eps->stat_incremented = 1;
  }
#endif

  sleep_seq = pipe->b.sleep_seq.all;
  mask = oo_pipe_poll_read_events(pipe);
  *stored_event = citp_ul_epoll_set_ul_events(eps, eitem, mask, sleep_seq,
                                              &pipe->b.sleep_seq.all,
                                              &seq_mismatch);
  return seq_mismatch;
}


static int citp_pipe_epoll_writer(citp_fdinfo* fdinfo,
                                  struct citp_epoll_member* eitem,
                                  struct oo_ul_epoll_state* eps,
                                  int* stored_event)
{
  unsigned mask;
  struct oo_pipe* pipe = fdi_to_pipe_fdi(fdinfo)->pipe;
  ci_uint64 sleep_seq;
  int seq_mismatch = 0;

#if CI_CFG_SPIN_STATS
  if( CI_UNLIKELY(! eps->stat_incremented) ) {
    fdi_to_pipe_fdi(fdinfo)->ni->state->stats.spin_epoll++;
    eps->stat_incremented = 1;
  }
#endif

  sleep_seq = pipe->b.sleep_seq.all;
  mask = oo_pipe_poll_write_events(pipe);
  *stored_event = citp_ul_epoll_set_ul_events(eps, eitem, mask, sleep_seq,
                                              &pipe->b.sleep_seq.all,
                                              &seq_mismatch);

  return seq_mismatch;
}

static ci_uint64  citp_pipe_sock_sleep_seq(citp_fdinfo* fdi)
{
  return fdi_to_pipe_fdi(fdi)->pipe->b.sleep_seq.all;
}


/* fixme kostik: this is partially copy-paste from citp_sock_fcntl */
static int citp_pipe_fcntl(citp_fdinfo* fdinfo, int cmd, long arg)
{
  int rc = 0;
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdinfo);
  struct oo_pipe* p = epi->pipe;

  switch ( cmd ) {
  case F_GETFL: {
    ci_uint32 flag_nonb = CI_PFD_AFLAG_NONBLOCK;
    if( ! fdi_is_reader(fdinfo) ) {
      rc = O_WRONLY;
      flag_nonb <<= CI_PFD_AFLAG_WRITER_SHIFT;
    }
    else
      flag_nonb <<= CI_PFD_AFLAG_READER_SHIFT;
    if ( p->aflags & flag_nonb ) rc |= O_NONBLOCK;
    break;
  }
  case F_SETFL: {
    ci_uint32 bit;

    rc = ci_sys_fcntl(fdinfo->fd, cmd, arg);
    if( rc < 0 )
      break;

    bit = CI_PFD_AFLAG_NONBLOCK <<
                (fdi_is_reader(fdinfo) ? CI_PFD_AFLAG_READER_SHIFT :
                 CI_PFD_AFLAG_WRITER_SHIFT);
    if( arg & (O_NONBLOCK | O_NDELAY) )
      ci_bit_mask_set(&p->aflags, bit);
    else
      ci_bit_mask_clear(&p->aflags, bit);
    break;
  }
  case F_DUPFD:
    rc = citp_ep_dup(fdinfo->fd, citp_ep_dup_fcntl_dup, arg);
    break;
  case F_DUPFD_CLOEXEC:
    rc = citp_ep_dup(fdinfo->fd, citp_ep_dup_fcntl_dup_cloexec, arg);
    break;
  case F_GETFD:
  case F_SETFD:
    rc = ci_sys_fcntl(fdinfo->fd, cmd, arg);
    break;
  case F_GETLK:
  case F_SETLK:
  case F_SETLKW:
    /* File locks not supported on sockets */
    Log_U(ci_log("%s: cmd %d not supported on sockets!",__FUNCTION__,
                 cmd));
    errno = ENOTSUP;
    rc = CI_SOCKET_ERROR;
    break;
  case F_GETOWN:
  case F_SETOWN:
  case F_GETOWN_EX:
  case F_SETOWN_EX:
    rc = ci_sys_fcntl(fdinfo->fd, cmd, arg);
    if( rc != 0 )
        break;
    p->b.sigown = arg;
    if( p->b.sigown && (p->b.sb_aflags & CI_SB_AFLAG_O_ASYNC) )
      ci_bit_set(&p->b.wake_request, CI_SB_FLAG_WAKE_RX_B);
    break;
  case F_SETPIPE_SZ:
    /* System pipe buf size is rounded up to power of two. We
     * cannot replicate this.
     */
    rc = ci_pipe_set_size(epi->ni, p, arg);
    if( rc < 0 ) {
        errno = -rc;
        rc = CI_SOCKET_ERROR;
        break;
    }
    rc = 0;
    break;
  case F_GETPIPE_SZ:
    rc = p->bufs_max * OO_PIPE_BUF_MAX_SIZE;
    break;
  default:
    /* fixme kostik: logging should include some pipe identification */
    errno = ENOTSUP;
    rc = CI_SOCKET_ERROR;
  }

  Log_VSC(log("%s(%d, %d, %ld) = %d  (errno=%d)",
              __FUNCTION__, fdinfo->fd, cmd, arg, rc, errno));

  return rc;
}

/* handler for io operations on _wrong_ side of the pipe */
static int citp_pipe_send_none(citp_fdinfo* fdinfo,
                               const struct msghdr* msg, int flags)
{
  errno = EBADF;
  return -1;
}

/* handler for io operations on _wrong_ side of the pipe */
static int citp_pipe_recv_none(citp_fdinfo* fdinfo,
                               struct msghdr* msg, int flags)
{
  errno = EBADF;
  return -1;
}

static int citp_pipe_ioctl(citp_fdinfo *fdinfo, int cmd, void *arg)
{
  int rc = 0;
  citp_pipe_fdi* epi = fdi_to_pipe_fdi(fdinfo);
  struct oo_pipe* p = epi->pipe;

  switch( cmd ) {
  case FIONBIO:
  {
    int b = *(int* )arg;
    ci_uint32 bit = CI_PFD_AFLAG_NONBLOCK <<
                      (fdi_is_reader(fdinfo) ? CI_PFD_AFLAG_READER_SHIFT :
                       CI_PFD_AFLAG_WRITER_SHIFT);

    LOG_PIPE("%s: set non-blocking mode '%s'",
             __FUNCTION__, b ? "ON" : "OFF");

    if( b )
      ci_bit_mask_set(&p->aflags, bit);
    else
      ci_bit_mask_clear(&p->aflags, bit);

    break;
  }
  case FIONREAD:
  {
    /* NOTE: a normal user would expect that FIONREAD returns zero or
     * even an error when called on 'write' end of the pipe. But Linux
     * thinks it's reasonable to return 'correct' amount of data in the pipe
     * regardless of the actul fd. */
    int *r = (int* )arg;

    /* we don't need any lock here as actual 'read' of the variable is atomic */
    *r = p->bytes_added - p->bytes_removed;
    break;
  }
  default:
    errno = ENOSYS;
    rc = -1;
    break;
  }
  /* fixme kostik : support of ioctl should be added */
  return rc;
}

int citp_pipe_is_spinning(citp_fdinfo* fdinfo)
{
  return !!fdi_to_pipe_fdi(fdinfo)->pipe->b.spin_cycles;
}




/* Read and write ends of the pipe have different protocol implementations in the same
 * manner as they have them separate in linux kernel. All io-unrelated hooks are common,
 * reader has no write/send support of any kind, writer has no read/recv support.
 */
citp_protocol_impl citp_pipe_read_protocol_impl = {
  .type        = CITP_PIPE_FD,
  .ops         = {
    .socket      = NULL,        /* nobody should ever call this */
    .dtor        = citp_pipe_dtor,
    .dup         = citp_pipe_dup,

    .recv        = citp_pipe_recv,
    .send        = citp_pipe_send_none,

    .fcntl       = citp_pipe_fcntl,
    .ioctl       = citp_pipe_ioctl,
    .select	 = citp_pipe_select_reader,
    .poll	 = citp_pipe_poll_reader,
    .epoll       = citp_pipe_epoll_reader,
    .sleep_seq   = citp_pipe_sock_sleep_seq,

    .bind        = citp_nonsock_bind,
    .listen      = citp_nonsock_listen,
    .accept      = citp_nonsock_accept,
    .connect     = citp_nonsock_connect,
    .shutdown    = citp_nonsock_shutdown,
    .getsockname = citp_nonsock_getsockname,
    .getpeername = citp_nonsock_getpeername,
    .getsockopt  = citp_nonsock_getsockopt,
    .setsockopt  = citp_nonsock_setsockopt,
    .recvmmsg    = citp_nonsock_recvmmsg,
    .sendmmsg    = citp_nonsock_sendmmsg,
    .zc_send     = citp_nonsock_zc_send,
    .zc_recv     = citp_nonsock_zc_recv,
    .zc_recv_filter = citp_nonsock_zc_recv_filter,
    .recvmsg_kernel = citp_nonsock_recvmsg_kernel,
    .tmpl_alloc    = citp_nonsock_tmpl_alloc,
    .tmpl_update   = citp_nonsock_tmpl_update,
    .tmpl_abort    = citp_nonsock_tmpl_abort,
#if CI_CFG_TIMESTAMPING
    .ordered_data   = citp_nonsock_ordered_data,
#endif
    .is_spinning   = citp_pipe_is_spinning,
#if CI_CFG_FD_CACHING
    .cache          = citp_nonsock_cache,
#endif
  }
};

citp_protocol_impl citp_pipe_write_protocol_impl = {
  .type        = CITP_PIPE_FD,
  .ops         = {
    .socket      = NULL,        /* nobody should ever call this */
    .dtor        = citp_pipe_dtor,
    .dup         = citp_pipe_dup,

    .recv        = citp_pipe_recv_none,
    .send        = citp_pipe_send,

    .fcntl       = citp_pipe_fcntl,
    .ioctl       = citp_pipe_ioctl,
    .select	 = citp_pipe_select_writer,
    .poll	 = citp_pipe_poll_writer,
    .epoll       = citp_pipe_epoll_writer,
    .sleep_seq   = citp_pipe_sock_sleep_seq,

    .bind        = citp_nonsock_bind,
    .listen      = citp_nonsock_listen,
    .accept      = citp_nonsock_accept,
    .connect     = citp_nonsock_connect,
    .shutdown    = citp_nonsock_shutdown,
    .getsockname = citp_nonsock_getsockname,
    .getpeername = citp_nonsock_getpeername,
    .getsockopt  = citp_nonsock_getsockopt,
    .setsockopt  = citp_nonsock_setsockopt,
    .recvmmsg    = citp_nonsock_recvmmsg,
    .sendmmsg    = citp_nonsock_sendmmsg,
    .zc_send     = citp_nonsock_zc_send,
    .zc_recv     = citp_nonsock_zc_recv,
    .zc_recv_filter = citp_nonsock_zc_recv_filter,
    .recvmsg_kernel = citp_nonsock_recvmsg_kernel,
    .tmpl_alloc    = citp_nonsock_tmpl_alloc,
    .tmpl_update   = citp_nonsock_tmpl_update,
    .tmpl_abort    = citp_nonsock_tmpl_abort,
#if CI_CFG_TIMESTAMPING
    .ordered_data   = citp_nonsock_ordered_data,
#endif
    .is_spinning   = citp_pipe_is_spinning,
#if CI_CFG_FD_CACHING
    .cache          = citp_nonsock_cache,
#endif
  }
};

static citp_pipe_fdi *citp_pipe_epi_alloc(ci_netif *ni, int flags)
{
  citp_pipe_fdi* epi;

  epi = CI_ALLOC_OBJ(citp_pipe_fdi);
  if( ! epi ) {
    Log_U(ci_log(LPF "pipe: failed to allocate epi"));
    errno = ENOMEM;
    return NULL;
  }
  if( flags == O_WRONLY )
    citp_fdinfo_init(&epi->fdinfo, &citp_pipe_write_protocol_impl);
  else
    citp_fdinfo_init(&epi->fdinfo, &citp_pipe_read_protocol_impl);
  epi->ni = ni;

  return epi;
}

/* Should be called when netif is locked */
static int oo_pipe_init(ci_netif* ni, struct oo_pipe* p)
{
  ci_assert(ni);
  ci_assert(p);

  /* init waitable */
  citp_waitable_reinit(ni, &p->b);

  p->b.state = CI_TCP_STATE_PIPE;

  p->bytes_added = 0;
  p->bytes_removed = 0;

  p->aflags = 0;

  oo_pipe_buf_clear_state(ni, p);

  p->bufs_num = 0;

  /* We add extra buffer to ensure we can always fill the pipe to at least
   * pipe_size bytes. This extra buffer is needed because the buffer
   * under read_ptr can be blocked */
  p->bufs_max = OO_PIPE_SIZE_TO_BUFS(CITP_OPTS.pipe_size) + 1;

  return 0;
}

static struct oo_pipe* oo_pipe_buf_get(ci_netif* netif)
{
  citp_waitable_obj *wo;
  int rc = -1;

  wo = citp_waitable_obj_alloc(netif);
  if( ! wo )
    return NULL;

  rc = oo_pipe_init(netif, &wo->pipe);
  if( rc != 0 ) {
    citp_waitable_obj_free(netif, &wo->waitable);

    return NULL;
  }

  return &wo->pipe;
}

static int oo_pipe_ctor(ci_netif* netif, struct oo_pipe** out_pipe,
                        int fds[2], int flags)
{
  struct oo_pipe* p;
  int rc;

  ci_assert(netif);

  ci_netif_lock(netif);
  p = oo_pipe_buf_get(netif);
  if( !p ) {
    rc = -1;
    errno = EMFILE;
    goto out;
  }

  if( flags & O_NONBLOCK ) {
    p->aflags = (CI_PFD_AFLAG_NONBLOCK << CI_PFD_AFLAG_READER_SHIFT) |
        (CI_PFD_AFLAG_NONBLOCK << CI_PFD_AFLAG_WRITER_SHIFT);
  }

  /* attach */
  rc = ci_tcp_helper_pipe_attach(ci_netif_get_driver_handle(netif),
                                 W_SP(&p->b), flags, fds);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ci_tcp_helper_pipe_attach %d", __FUNCTION__, rc));
    errno = -rc;
    rc = -1;
    goto out;
  }

  *out_pipe = p;

out:
  ci_netif_unlock(netif);

  return rc;
}

/* we don't register protocol impl */
int citp_pipe_create(int fds[2], int flags)
{
  citp_pipe_fdi* epi_read;
  citp_pipe_fdi* epi_write;
  struct oo_pipe* p = NULL;         /* make compiler happy */
  ci_netif* ni;
  int rc = -1;
  ef_driver_handle fd = -1;

  Log_V(log(LPF "pipe()"));

  /* citp_netif_exists() does not need citp_ul_lock here */
  if( CITP_OPTS.ul_pipe == CI_UNIX_PIPE_ACCELERATE_IF_NETIF &&
      ! citp_netif_exists() ) {
    return CITP_NOT_HANDLED;
  }

  rc = citp_netif_alloc_and_init(&fd, &ni);
  if( rc != 0 ) {
    if( rc == CI_SOCKET_HANDOVER ) {
      /* This implies EF_DONT_ACCELERATE is set, so we handover
       * regardless of CITP_OPTS.no_fail */
      return CITP_NOT_HANDLED;
    }
    /* may be lib mismatch - errno will be ELIBACC */
    goto fail1;
  }
  rc = -1;

  CI_MAGIC_CHECK(ni, NETIF_MAGIC);

  /* add another reference as we have 2 fdis */
  citp_netif_add_ref(ni);

  epi_read = citp_pipe_epi_alloc(ni, O_RDONLY);
  if( epi_read == NULL )
    goto fail2;
  epi_write = citp_pipe_epi_alloc(ni, O_WRONLY);
  if( epi_write == NULL )
    goto fail3;

  /* oo_pipe init code */
  if( fdtable_strict() )  CITP_FDTABLE_LOCK();
  rc = oo_pipe_ctor(ni, &p, fds, flags);
  if( rc < 0 )
      goto fail4;
  citp_fdtable_new_fd_set(fds[0], fdip_busy, fdtable_strict());
  citp_fdtable_new_fd_set(fds[1], fdip_busy, fdtable_strict());
  if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();

  LOG_PIPE("%s: pipe=%p id=%d", __FUNCTION__, p, p->b.bufid);

  /* as pipe is created it should be attached to the end-points */
  epi_read->pipe = p;
  epi_write->pipe = p;

  /* We're ready.  Unleash us onto the world! */
  ci_assert(epi_read->pipe->b.sb_aflags & CI_SB_AFLAG_NOT_READY);
  ci_assert(epi_write->pipe->b.sb_aflags & CI_SB_AFLAG_NOT_READY);
  ci_atomic32_and(&epi_read->pipe->b.sb_aflags, ~CI_SB_AFLAG_NOT_READY);
  ci_atomic32_and(&epi_read->pipe->b.sb_aflags, ~CI_SB_AFLAG_NOT_READY);
  citp_fdtable_insert(&epi_read->fdinfo, fds[0], 0);
  citp_fdtable_insert(&epi_write->fdinfo, fds[1], 0);

  CI_MAGIC_CHECK(ni, NETIF_MAGIC);

  return 0;

fail4:
  if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
fail3:
  CI_FREE_OBJ(epi_write);
fail2:
  CI_FREE_OBJ(epi_read);
  citp_netif_release_ref(ni, 0);
  citp_netif_release_ref(ni, 0);
fail1:
  if( CITP_OPTS.no_fail && errno != ELIBACC ) {
    Log_U(ci_log("%s: failed (errno:%d) - PASSING TO OS", __FUNCTION__, errno));
    return CITP_NOT_HANDLED;
  }

  return rc;
}
