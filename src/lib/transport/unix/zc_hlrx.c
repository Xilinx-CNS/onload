/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

/* Implementation of the onload_zc_hlrx_* zero-copy extension API functions */

#include "internal.h"
#include <unistd.h>
#include <onload/extensions.h>
#include <onload/extensions_zc.h>


struct zc_remote_data;

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

  /* Allocated size of the 'pending' array */
  int pending_capacity;

  /* true if this is a UDP socket, so we can implement the right semantics
   * for recv */
  bool udp;

  /* 32 is CI_ZC_IOV_STATIC_MAX in tcp_recv.c, but there's no reason this
   * value has to be the same. This buffer is only used for TCP - UDP is
   * always immediate so doesn't need buffering. */
  struct onload_zc_iovec static_pending[32];
  struct onload_zc_iovec* pending;

  /* Singly-linked list of objects given out to the user which point to
   * non-local address space data. These are in order, so we know what to
   * post to the underlying app plugin when the app's done with them. */
  struct zc_remote_data* remotes_head;
  struct zc_remote_data** remotes_ptail;
  /* Protects fd and remotes_* */
  pthread_mutex_t mtx;
};


/* Pointers to these are given out to the user instead of packets as
 * onload_zc_handles (see ZC_IS_REMOTE_FLAG) when a non-local address space is
 * seen. The caller is expected to free them as usual with
 * onload_zc_hlrx_buffer_release,  whereupon we can figure out the max_ptr and
 * send the appropriate free request to the NIC plugin */
struct zc_remote_data {
  struct onload_zc_hlrx* owner;
  struct zc_remote_data* next;
  uint64_t max_ptr;
  bool done;
};


/* We could have used 1 and it would have worked fine, but that's the same as
 * is used for zc_is_usermem(), so we make things potentially a little easier
 * to debug if we use something different. */
#define ZC_IS_REMOTE_FLAG  2

static inline onload_zc_handle zc_remote_to_handle(struct zc_remote_data* rd)
{
  return (onload_zc_handle)((uintptr_t)rd | ZC_IS_REMOTE_FLAG);
}

static inline bool zc_is_remote(onload_zc_handle h)
{
  return ((uintptr_t)h & ZC_IS_REMOTE_FLAG) != 0;
}

static inline struct zc_remote_data* zc_handle_to_remote(onload_zc_handle h)
{
  ci_assert(zc_is_remote(h));
  /* -2 rather than &~2 because it allows better codegen */
  return (struct zc_remote_data*)((uintptr_t)h - ZC_IS_REMOTE_FLAG);
}


int onload_zc_hlrx_alloc(int fd, int flags, struct onload_zc_hlrx** hlrx_out)
{
  int rc;
  struct onload_zc_hlrx* hlrx;
  int sock_type;
  socklen_t optlen = sizeof(sock_type);

  Log_CALL(ci_log("%s(%d, %p)", __FUNCTION__, fd, hlrx_out));

  rc = onload_getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen);
  if( rc )
    rc = -errno;
  else if( sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM )
    rc = -ESOCKTNOSUPPORT;
  else {
    hlrx = calloc(1, sizeof(*hlrx));
    if( ! hlrx ) {
      rc = -ENOMEM;
    }
    else {
      pthread_mutex_init(&hlrx->mtx, NULL);
      hlrx->fd = fd;
      hlrx->udp = sock_type == SOCK_DGRAM;
      hlrx->pending = hlrx->static_pending;
      hlrx->pending_capacity = sizeof(hlrx->static_pending) /
                               sizeof(hlrx->static_pending[0]);
      hlrx->remotes_ptail = &hlrx->remotes_head;
      *hlrx_out = hlrx;
    }
  }

  Log_CALL_RESULT(rc);
  return rc;
}


int onload_zc_hlrx_free(struct onload_zc_hlrx* hlrx)
{
  int rc = 0;

  Log_CALL(ci_log("%s(%p)", __FUNCTION__, hlrx));
  pthread_mutex_lock(&hlrx->mtx);
  if( hlrx->remotes_head ) {
    Log_E(ci_log("%s: remote ZC blocks remain unfreed", __FUNCTION__));
    rc = -EBUSY;
  }
  pthread_mutex_unlock(&hlrx->mtx);

  if( rc == 0 ) {
    if( hlrx->pending_begin != hlrx->pending_end )
      onload_zc_buffer_decref(hlrx->fd, hlrx->pending[0].buf);
    if( hlrx->pending != hlrx->static_pending )
      free(hlrx->pending);
    pthread_mutex_destroy(&hlrx->mtx);
    free(hlrx);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


static void consume_done_remotes(struct onload_zc_hlrx* hlrx)
{
  struct zc_remote_data* rd;
  uint64_t max = 0;
  bool freed_some = false;

  if( OO_ACCESS_ONCE(hlrx->remotes_head) == NULL )
    return;

  pthread_mutex_lock(&hlrx->mtx);
  rd = OO_ACCESS_ONCE(hlrx->remotes_head);
  while( rd && rd->done ) {
    struct zc_remote_data* next = rd->next;
    max = rd->max_ptr;
    freed_some = true;
    free(rd);
    rd = next;
  }

  if( freed_some ) {
    hlrx->remotes_head = rd;
    if( ! rd )
      hlrx->remotes_ptail = &hlrx->remotes_head;
    ioctl(hlrx->fd, ONLOAD_SIOC_CEPH_REMOTE_CONSUME, &max);
  }
  pthread_mutex_unlock(&hlrx->mtx);
}


int onload_zc_hlrx_buffer_release(int fd, onload_zc_handle buf)
{
  if(CI_UNLIKELY( zc_is_remote(buf) )) {
    struct zc_remote_data* rd = zc_handle_to_remote(buf);
    struct onload_zc_hlrx* hlrx = OO_ACCESS_ONCE(rd->owner);

    OO_ACCESS_ONCE(rd->done) = true;
    /* Do not access rd any more: it could have been freed */
    consume_done_remotes(hlrx);
    /* Do not access hlrx any more: it could have been destroyed */
    return 0;
  }
  return onload_zc_buffer_decref(fd, buf);
}


/* *********************************************************************** */

/* Temporary structure we need to pass as the cookie to the callback of
 * onload_zc_recv() */
struct zc_cb_copy_state {
  struct onload_zc_hlrx* hlrx;
  ssize_t rc;
  ci_iovec_ptr dest;
  int msg_flags;
};


/* Stash in hlrx->pending the set of iovs which haven't yet been passed to the
 * user */
static bool save_pending(struct onload_zc_hlrx* hlrx,
                         struct onload_zc_recv_args* args, int begin, int end)
{
  ci_assert_equal(hlrx->udp, false);
  if( end > hlrx->pending_capacity ) {
    if( hlrx->pending != hlrx->static_pending )
      free(hlrx->pending);
    hlrx->pending_capacity = end;
    hlrx->pending = malloc(end * sizeof(*hlrx->pending));
    if( ! hlrx->pending ) {
      hlrx->pending = hlrx->static_pending;
      hlrx->pending = hlrx->static_pending;
      hlrx->pending_capacity = sizeof(hlrx->static_pending) /
                               sizeof(hlrx->static_pending[0]);
      return false;
    }
  }
  memcpy(hlrx->pending + begin, args->msg.iov + begin,
        (end - begin) * sizeof(args->msg.iov[0]));
  hlrx->pending_begin = begin;
  hlrx->pending_end = end;
  /* For chained packet buffers, onload_zc_recv()'s ONLOAD_ZC_KEEP return code
   * only tracks ownership of the first packet, therefore we must ensure that
   * we hold on to that one so we can release it again when done. */
  hlrx->pending[0].buf = args->msg.iov[0].buf;
  return true;
}


/* Copy data from 'iovs' to state->dest, updating the tracking as we go */
static void copy_iovs(struct zc_cb_copy_state* state,
                      struct onload_zc_iovec* iovs, int* pbegin, int end)
{
  int begin = *pbegin;
  while( begin != end ) {
    int n;
    if( iovs[begin].addr_space != EF_ADDRSPACE_LOCAL ) {
      if( state->rc == 0 )
        state->rc = -EREMOTEIO;
      break;
    }
    n = ci_copy_to_iovec(&state->dest, iovs[begin].iov_base,
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
  copy_iovs(state, args->msg.iov, &begin, end);

  if( state->hlrx->udp ) {
    if( end != begin )
      state->msg_flags |= MSG_TRUNC;
    return ONLOAD_ZC_TERMINATE;
  }
  if( end != begin ) {
    if( ! save_pending(state->hlrx, args, begin, end) )
      state->rc = -ENOMEM;
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
    .msg_flags = 0,
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
        .msg.msghdr.msg_name = msg->msg_name,
        .msg.msghdr.msg_namelen = msg->msg_namelen,
      };
      int n = onload_zc_recv(hlrx->fd, &args);
      if( n < 0 && state.rc == 0 )
        state.rc = n;
    }
    msg->msg_flags = state.msg_flags;
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
  struct zc_remote_data* remotes_head;
  struct zc_remote_data** remotes_ptail;
};


static void zc_buffer_addref(int fd, onload_zc_handle buf, int delta)
{
  /* In due course (and if benchmarks show it's needed) a built-in
   * implementation of this function is a good idea */
  while( delta < 0 ) {
    onload_zc_buffer_decref(fd, buf);
    ++delta;
  }
  while( delta > 0 ) {
    onload_zc_buffer_incref(fd, buf);
    --delta;
  }
}


/* Pass buffers from 'iovs' to state->msg->iov, updating the tracking as we
 * go */
static void zc_iovs(struct zc_cb_zc_state* state,
                    struct onload_zc_iovec* iovs, int* pbegin, int end)
{
  int ref_delta = 0;
  int begin = *pbegin;
  while( begin != end && state->max_bytes &&
         state->curr_iov < state->msg->msghdr.msg_iovlen ) {
    struct onload_zc_iovec* dst = &state->msg->iov[state->curr_iov];
    *dst = iovs[begin];
    if( iovs[begin].addr_space != EF_ADDRSPACE_LOCAL ) {
      struct zc_remote_data* rd = malloc(sizeof(struct zc_remote_data));
      if( ! rd ) {
        if( state->rc == 0 )
          state->rc = -ENOMEM;
        break;
      }
      *rd = (struct zc_remote_data){
        .owner = state->hlrx,
        .next = NULL,
        .done = false,
        .max_ptr = iovs[begin].iov_ptr + CI_MIN(iovs[begin].iov_len64,
                                                state->max_bytes),
      };
      /* Append to the linked list at state->remotes_head */
      *state->remotes_ptail = rd;
      state->remotes_ptail = &rd->next;
      dst->buf = zc_remote_to_handle(rd);
    }
    else {
      /* The semantics of multiple buffers are a little odd: the refcount
       * holder is the 0th packet only. We hide this complexity from the
       * caller by giving out refs for all the others too. */
      dst->buf = iovs[0].buf;
      ++ref_delta;
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
  if( begin == end ) {
    /* This is the ref that hlrx owns internally, i.e. the packet's all done
     * so we don't want that ref any more */
    --ref_delta;
  }
  zc_buffer_addref(state->hlrx->fd, state->hlrx->pending[0].buf, ref_delta);
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
  zc_iovs(state, args->msg.iov, &begin, end);

  if( state->hlrx->udp ) {
    if( end != begin )
      state->msg->msghdr.msg_flags |= MSG_TRUNC;
    return ONLOAD_ZC_KEEP | ONLOAD_ZC_TERMINATE;
  }
  if( end != begin ) {
    if( ! save_pending(state->hlrx, args, begin, end) ) {
      state->rc = -ENOMEM;
      onload_zc_buffer_decref(state->hlrx->fd, state->hlrx->pending[0].buf);
    }
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
  state.remotes_ptail = &state.remotes_head;

  Log_CALL(ci_log("%s(%p, %p, %zu, %d)", __FUNCTION__, hlrx, msg, max_bytes,
                  flags));

  if( flags & (MSG_PEEK | MSG_TRUNC | MSG_ERRQUEUE) ) {
    state.rc = -EINVAL;
  }
  else {
    msg->msghdr.msg_flags = 0;
    if( hlrx->pending_begin != hlrx->pending_end ) {
      /* Consume leftovers from previous call */
      zc_iovs(&state, hlrx->pending, &hlrx->pending_begin, hlrx->pending_end);
      if( state.rc > 0 ) {
        /* Set DONTWAIT because we've got some data therefore normal semantics
        * are to return when we can */
        flags |= MSG_DONTWAIT;
      }
    }

    /* Get new packet(s) */
    if( state.rc >= 0 && state.max_bytes &&
        state.curr_iov < msg->msghdr.msg_iovlen ) {
      struct onload_zc_recv_args args = {
        .cb = zc_cb,
        .user_ptr = &state,
        .flags = flags,
        .msg.msghdr.msg_name = msg->msghdr.msg_name,
        .msg.msghdr.msg_namelen = msg->msghdr.msg_namelen,
      };
      int n = onload_zc_recv(hlrx->fd, &args);
      if( n < 0 && state.rc == 0 )
        state.rc = n;
    }

    msg->msghdr.msg_iovlen = state.curr_iov;
  }

  if( state.remotes_head ) {
    pthread_mutex_lock(&hlrx->mtx);
    *hlrx->remotes_ptail = state.remotes_head;
    hlrx->remotes_ptail = state.remotes_ptail;
    pthread_mutex_unlock(&hlrx->mtx);
  }

  Log_CALL_RESULT((int)state.rc);
  return state.rc;
}
