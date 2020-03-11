/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/* Implementation of the onload_zc_hlrx_* zero-copy extension API functions */

#include "internal.h"
#include <unistd.h>
#include <onload/extensions.h>
#include <onload/extensions_zc.h>


/* Top-level state object the user owns for the whole hlrx thing */
struct onload_zc_hlrx {
  /* fd the user gave us, i.e. where we're getting packets from */
  int fd;

  /* Index into the 'pending' array of the bit of data that the should be
   * given to the user next. If pending_begin == pending_end then pending is
   * conceptually empty */
  int pending_begin;

  /* Total number of items in the 'pending' array */
  int pending_end;

  /* true if this is a UDP socket, so we can implement the right semantics
   * for recv */
  bool udp;

  /* 6 elements is a nominal value, chosen because it's 9000/1500. We only use
   * this buffer for TCP which, at the time of writing, can only pass a single
   * buffer in a zc recv. This code is written to cope with a future where
   * that changes (for jumbograms and GRO). When that happens, we'll know the
   * true value to put here. */
  struct onload_zc_iovec pending[6];
};


int onload_zc_hlrx_alloc(int fd, int flags, struct onload_zc_hlrx** hlrx_out)
{
  int rc;
  struct onload_zc_hlrx* hlrx;
  int sock_type;
  socklen_t optlen = sizeof(sock_type);

  Log_CALL(ci_log("%s(%d, %p)", __FUNCTION__, fd, hlrx_out));

  rc = onload_getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen);
  if( rc == 0 ) {
    if( sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM )
      rc = -ESOCKTNOSUPPORT;
    else {
      hlrx = calloc(1, sizeof(*hlrx));
      if( ! hlrx ) {
        rc = -ENOMEM;
      }
      else {
        hlrx->fd = fd;
        hlrx->udp = sock_type == SOCK_DGRAM;
        *hlrx_out = hlrx;
        rc = 0;
      }
    }
  }

  Log_CALL_RESULT(rc);
  return rc;
}


int onload_zc_hlrx_free(struct onload_zc_hlrx* hlrx)
{
  int rc = 0;

  Log_CALL(ci_log("%s(%p)", __FUNCTION__, hlrx));
  if( hlrx->pending_begin != hlrx->pending_end )
    onload_zc_buffer_decref(hlrx->fd, hlrx->pending[0].buf);
  free(hlrx);
  Log_CALL_RESULT(rc);
  return rc;
}


/* *********************************************************************** */

/* Temporary structure we need to pass as the cookie to the callback of
 * onload_zc_recv() */
struct zc_cb_copy_state {
  struct onload_zc_hlrx* hlrx;
  ssize_t rc;
  ci_iovec_ptr dest;
};


/* Stash in hlrx->pending the set of iovs which haven't yet been passed to the
 * user */
static void save_pending(struct onload_zc_hlrx* hlrx,
                         struct onload_zc_recv_args* args, int begin, int end)
{
  ci_assert_equal(hlrx->udp, false);
  memcpy(hlrx->pending + begin, args->msg.iov + begin,
        (end - begin) * sizeof(args->msg.iov[0]));
  hlrx->pending_begin = begin;
  hlrx->pending_end = end;
  /* For chained packet buffers, onload_zc_recv()'s ONLOAD_ZC_KEEP return code
   * only tracks ownership of the first packet, therefore we must ensure that
   * we hold on to that one so we can release it again when done. */
  hlrx->pending[0].buf = args->msg.iov[0].buf;
}


/* Copy data from 'iovs' to state->dest, updating the tracking as we go */
static void copy_iovs(struct zc_cb_copy_state* state,
                      struct onload_zc_iovec* iovs, int* pbegin, int end)
{
  int begin = *pbegin;
  while( begin != end ) {
    int n = ci_copy_to_iovec(&state->dest, iovs[begin].iov_base,
                             iovs[begin].iov_len);
    iovs[begin].iov_base = (char*)iovs[begin].iov_base + n;
    iovs[begin].iov_len -= n;
    state->rc += n;
    if( iovs[begin].iov_len )
      break;     /* dest buffer must be full */
    ++begin;
  }
  *pbegin = begin;
}


/* Callback for onload_zc_recv when we're copying data into user buffers */
static enum onload_zc_callback_rc
copy_cb(struct onload_zc_recv_args *args, int flags)
{
  struct zc_cb_copy_state* state = args->user_ptr;
  int begin = 0;
  int end = args->msg.msghdr.msg_iovlen;

  ci_assert_equal(state->hlrx->pending_begin, state->hlrx->pending_end);
  ci_assert_le(end,
               sizeof(state->hlrx->pending) / sizeof(state->hlrx->pending[0]));
  copy_iovs(state, args->msg.iov, &begin, end);

  if( state->hlrx->udp )
    return ONLOAD_ZC_TERMINATE;
  if( end != begin ) {
    save_pending(state->hlrx, args, begin, end);
    /* No need for complex refcount management here: we keep the one and only
     * ref in our 'pending' array - the data to the user was a memcpy */
    return ONLOAD_ZC_KEEP | ONLOAD_ZC_TERMINATE;
  }

  if( ci_iovec_ptr_is_empty(&state->dest) )
    return ONLOAD_ZC_TERMINATE;
  return ONLOAD_ZC_CONTINUE;
}


ssize_t onload_zc_hlrx_recv_copy(struct onload_zc_hlrx* hlrx,
                                 struct msghdr* msg, int flags)
{
  struct zc_cb_copy_state state = {
    .hlrx = hlrx,
    .rc = 0,
  };

  Log_CALL(ci_log("%s(%p, %p, %d)", __FUNCTION__, hlrx, msg, flags));

  if( flags & MSG_ERRQUEUE ) {
    state.rc = onload_recvmsg(hlrx->fd, msg, flags);
    if( state.rc < 0 )
      state.rc = -errno;
  }
  else if( flags & (MSG_PEEK | MSG_TRUNC) ) {
    state.rc = -EINVAL;
  }
  else {
    ci_iovec_ptr_init(&state.dest, msg->msg_iov, msg->msg_iovlen);

    /* Consume leftovers from previous call */
    if( hlrx->pending_begin != hlrx->pending_end ) {
      copy_iovs(&state, hlrx->pending, &hlrx->pending_begin,
                hlrx->pending_end);
      /* Set DONTWAIT because we've got some data therefore normal semantics
       * are to return when we can */
      flags |= MSG_DONTWAIT;
      if( hlrx->pending_begin == hlrx->pending_end )
        onload_zc_buffer_decref(hlrx->fd, hlrx->pending[0].buf);
    }

    /* Get new packet(s) */
    if( ! ci_iovec_ptr_is_empty(&state.dest) ) {
      struct onload_zc_recv_args args = {
        .cb = copy_cb,
        .user_ptr = &state,
        .flags = flags,
      };
      int n = onload_zc_recv(hlrx->fd, &args);
      if( n < 0 && state.rc == 0 )
        state.rc = n;
    }
  }

  Log_CALL_RESULT((int)state.rc);
  return state.rc;
}

/* *********************************************************************** */

/* Temporary structure we need to pass as the cookie to the callback of
 * onload_zc_recv() */
struct zc_cb_zc_state {
  struct onload_zc_hlrx* hlrx;
  struct onload_zc_msg* msg;
  ssize_t rc;
  size_t max_bytes;
  int curr_iov;      /* Index into the user's iov array msg->iov */
};


/* Pass buffers from 'iovs' to state->msg->iov, updating the tracking as we
 * go */
static void zc_iovs(struct zc_cb_zc_state* state,
                    struct onload_zc_iovec* iovs, int* pbegin, int end)
{
  int begin = *pbegin;
  while( begin != end && state->max_bytes &&
         state->curr_iov < state->msg->msghdr.msg_iovlen ) {
    struct onload_zc_iovec* dst = &state->msg->iov[state->curr_iov];
    *dst = iovs[begin];
    if( begin ) {
      /* The semantics of multiple buffers are a little odd: the refcount
       * holder is the 0th packet only. We hide this complexity from the
       * caller by giving out refs for all the others too. At time of
       * writing, multi-iov packets are used for UDP only, but this could
       * change with jumbograms. Because this occurrence is rare, we don't
       * worry about the inefficiency of calling incref lots of times. */
      dst->buf = iovs[0].buf;
      onload_zc_buffer_incref(state->hlrx->fd, dst->buf);
    }
    if( dst->iov_len > state->max_bytes ) {
      dst->iov_len = state->max_bytes;
      iovs[begin].iov_ptr += state->max_bytes;
      iovs[begin].iov_len -= state->max_bytes;
      state->rc += state->max_bytes;
      state->max_bytes = 0;
    }
    else {
      state->max_bytes -= dst->iov_len;
      state->rc += dst->iov_len;
      ++begin;
    }
    ++state->curr_iov;
  }
  *pbegin = begin;
}


/* Callback for onload_zc_recv when we're doing zero-copy into user iovs */
static enum onload_zc_callback_rc
zc_cb(struct onload_zc_recv_args *args, int flags)
{
  struct zc_cb_zc_state* state = args->user_ptr;
  int begin = 0;
  int end = args->msg.msghdr.msg_iovlen;

  ci_assert_gt(end, 0);
  ci_assert_equal(state->hlrx->pending_begin, state->hlrx->pending_end);
  ci_assert_le(end,
               sizeof(state->hlrx->pending) / sizeof(state->hlrx->pending[0]));
  zc_iovs(state, args->msg.iov, &begin, end);

  if( state->hlrx->udp )
    return ONLOAD_ZC_KEEP | ONLOAD_ZC_TERMINATE;
  if( end != begin ) {
    save_pending(state->hlrx, args, begin, end);
    /* zc_iovs() gave out additional refcounts to the user for all iovs
     * except the 0th so that if we *didn't* go down this branch then the 0th
     * iov's refcount is effectively handed over from this function to the
     * user's callback. Since we are in this branch then that refcount is too
     * small by 1 (because we're saving the packet for ourselves too) and we
     * need a refcount of our own (see comment in zc_iovs() about the odd
     * semantics for the explanation of why all these refcounts are on
     * iov[0]). */
    onload_zc_buffer_incref(state->hlrx->fd, state->hlrx->pending[0].buf);
    return ONLOAD_ZC_KEEP | ONLOAD_ZC_TERMINATE;
  }

  if( state->max_bytes && state->curr_iov < state->msg->msghdr.msg_iovlen )
    return ONLOAD_ZC_KEEP | ONLOAD_ZC_CONTINUE;
  return ONLOAD_ZC_KEEP | ONLOAD_ZC_TERMINATE;
}


ssize_t onload_zc_hlrx_recv_zc(struct onload_zc_hlrx* hlrx,
                               struct onload_zc_msg* msg, size_t max_bytes,
                               int flags)
{
  struct zc_cb_zc_state state = {
    .hlrx = hlrx,
    .msg = msg,
    .rc = 0,
    .max_bytes = max_bytes,
    .curr_iov = 0,
  };

  Log_CALL(ci_log("%s(%p, %p, %zu, %d)", __FUNCTION__, hlrx, msg, max_bytes,
                  flags));

  if( flags & MSG_ERRQUEUE ) {
    state.rc = onload_recvmsg(hlrx->fd, &msg->msghdr, flags);
    if( state.rc < 0 )
      state.rc = -errno;
  }
  else if( flags & (MSG_PEEK | MSG_TRUNC) ) {
    state.rc = -EINVAL;
  }
  else {
    /* Consume leftovers from previous call */
    zc_iovs(&state, hlrx->pending, &hlrx->pending_begin, hlrx->pending_end);
    if( state.rc ) {
      /* Set DONTWAIT because we've got some data therefore normal semantics
       * are to return when we can */
      flags |= MSG_DONTWAIT;
      /* The existing refcount owned by us is considered to have been given to
       * the caller. If we've still got some too then we need another. */
      if( hlrx->pending_begin != hlrx->pending_end )
        onload_zc_buffer_incref(hlrx->fd, hlrx->pending[0].buf);
    }

    /* Get new packet(s) */
    if( state.max_bytes && state.curr_iov < msg->msghdr.msg_iovlen ) {
      struct onload_zc_recv_args args = {
        .cb = zc_cb,
        .user_ptr = &state,
        .flags = flags,
      };
      int n = onload_zc_recv(hlrx->fd, &args);
      if( n < 0 && state.rc == 0 )
        state.rc = n;
    }

    msg->msghdr.msg_iovlen = state.curr_iov;
  }

  Log_CALL_RESULT((int)state.rc);
  return state.rc;
}
