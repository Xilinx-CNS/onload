/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

/* Implementation of the onload_zc_hlrx_* zero-copy extension API functions */

#include "internal.h"
#include <unistd.h>
#include <onload/extensions.h>
#include <onload/extensions_zc.h>


#define HLRX_REMOTE_RING_BLOCK_SHIFT  8  /* 2KB */
#define HLRX_REMOTE_RING_BLOCK_SIZE  (1 << HLRX_REMOTE_RING_BLOCK_SHIFT)
#define HLRX_REMOTE_PTR_DONE_FLAG  0x8000000000000000ull
struct hlrx_remote_ring_block {
  /* Pointers to these are given out to the user instead of packets as
   * onload_zc_handles (see ZC_IS_REMOTE_FLAG) when a non-local address space
   * is seen. The caller is expected to free them as usual with
   * onload_zc_hlrx_buffer_release,  whereupon we can figure out the max_ptr
   * and send the appropriate free request to the NIC plugin */
  uint64_t max_ptr[HLRX_REMOTE_RING_BLOCK_SIZE];
};

struct hlrx_remote_ring {
  struct hlrx_remote_ring_block** blocks;
  size_t nblocks;
  size_t added, removed;
};

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

  /* Storage for the things that are given out to the user to point to
   * non-local address space data. These are in order, so we know what to
   * post to the underlying app plugin when the app's done with them. */
  struct hlrx_remote_ring remote_ring;
};


/* We could have used 1 and it would have worked fine, but that's the same as
 * is used for zc_is_usermem(), so we make things potentially a little easier
 * to debug if we use something different. */
#define ZC_IS_REMOTE_FLAG  2

static inline onload_zc_handle zc_remote_to_handle(uint64_t* rd)
{
  return (onload_zc_handle)((uintptr_t)rd | ZC_IS_REMOTE_FLAG);
}

static inline bool zc_is_remote(onload_zc_handle h)
{
  return ((uintptr_t)h & ZC_IS_REMOTE_FLAG) != 0;
}

static inline uint64_t* zc_handle_to_remote(onload_zc_handle h)
{
  ci_assert(zc_is_remote(h));
  /* -2 rather than &~2 because it allows better codegen */
  return (uint64_t*)((uintptr_t)h - ZC_IS_REMOTE_FLAG);
}


static size_t remote_ring_inc(const struct hlrx_remote_ring* ring, size_t i)
{
  /* We need >= rather than == here in order to handle the case where the ring
   * is empty. */
  return i + 1 >= ring->nblocks * HLRX_REMOTE_RING_BLOCK_SIZE ? 0 : i + 1;
}


static uint64_t* remote_ring_entry(struct hlrx_remote_ring* ring, size_t i)
{
  ci_assert_lt(i, ring->nblocks * HLRX_REMOTE_RING_BLOCK_SIZE);
  return &ring->blocks[i >> HLRX_REMOTE_RING_BLOCK_SHIFT]
              ->max_ptr[i & (HLRX_REMOTE_RING_BLOCK_SIZE - 1)];
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
      hlrx->fd = fd;
      hlrx->udp = sock_type == SOCK_DGRAM;
      hlrx->pending = hlrx->static_pending;
      hlrx->pending_capacity = sizeof(hlrx->static_pending) /
                               sizeof(hlrx->static_pending[0]);
      *hlrx_out = hlrx;
    }
  }

  Log_CALL_RESULT(rc);
  return rc;
}


int onload_zc_hlrx_free(struct onload_zc_hlrx* hlrx)
{
  int rc = 0;
  size_t i;

  Log_CALL(ci_log("%s(%p)", __FUNCTION__, hlrx));
  for( i = hlrx->remote_ring.removed; i != hlrx->remote_ring.added;
       i = remote_ring_inc(&hlrx->remote_ring, i) ) {
    uint64_t ptr = *remote_ring_entry(&hlrx->remote_ring, i);
    if( ! (ptr & HLRX_REMOTE_PTR_DONE_FLAG) ) {
      Log_E(ci_log("%s: remote ZC blocks remain unfreed", __FUNCTION__));
      rc = -EBUSY;
      break;
    }
  }

  if( rc == 0 ) {
    for( i = 0; i < hlrx->remote_ring.nblocks; ++i )
      free(hlrx->remote_ring.blocks[i]);
    if( hlrx->pending_begin != hlrx->pending_end )
      onload_zc_buffer_decref(hlrx->fd, hlrx->pending[0].buf);
    if( hlrx->pending != hlrx->static_pending )
      free(hlrx->pending);
    free(hlrx);
  }
  Log_CALL_RESULT(rc);
  return rc;
}


static void consume_done_remotes(struct onload_zc_hlrx* hlrx)
{
  unsigned added = hlrx->remote_ring.added;
  unsigned removed = hlrx->remote_ring.removed;
  unsigned old_removed = removed;
  uint64_t max_ptr = 0;

  while( removed != added ) {
    uint64_t v = *remote_ring_entry(&hlrx->remote_ring, removed);
    if( ! (v & HLRX_REMOTE_PTR_DONE_FLAG) )
      break;
    max_ptr = v;
    removed = remote_ring_inc(&hlrx->remote_ring, removed);
  }
  if( removed != old_removed ) {
    max_ptr &= ~HLRX_REMOTE_PTR_DONE_FLAG;
    ioctl(hlrx->fd, ONLOAD_SIOC_CEPH_REMOTE_CONSUME, &max_ptr);
    hlrx->remote_ring.removed = removed;
  }
}


int onload_zc_hlrx_buffer_release(int fd, onload_zc_handle buf)
{
  if(CI_UNLIKELY( zc_is_remote(buf) )) {
    uint64_t* rd = zc_handle_to_remote(buf);
    OO_ACCESS_ONCE(*rd) |= HLRX_REMOTE_PTR_DONE_FLAG;
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

  consume_done_remotes(hlrx);
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
    if( ! ci_iovec_ptr_is_empty(&state.dest) &&
        hlrx->pending_begin == hlrx->pending_end ) {
      struct onload_zc_recv_args args = {
        .cb = copy_cb,
        .user_ptr = &state,
        .flags = flags,
        .msg.msghdr.msg_name = msg->msg_name,
        .msg.msghdr.msg_namelen = msg->msg_namelen,
      };
      int n;
      ci_assert_ge(state.rc, 0);
      n = onload_zc_recv(hlrx->fd, &args);
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


/* Allocate a new item on the end of hlrx->remote_ring */
static uint64_t* zc_remote_block_add(struct hlrx_remote_ring* ring)
{
  /* Note that added is the _count_ (modulo the ring-size) of added buffers,
   * and thus is also the _index_ of the _next_ buffer to add. */
  unsigned added = ring->added;
  unsigned added_inc = remote_ring_inc(ring, added);
  unsigned removed = ring->removed;
  unsigned added_inc_block = added_inc >> HLRX_REMOTE_RING_BLOCK_SHIFT;
  unsigned removed_block = removed >> HLRX_REMOTE_RING_BLOCK_SHIFT;

  /* We're sloppy about overlap in order to make ring resize possible: we
   * consider the ring to be full when the added block catches up to the
   * removed block, so we can insert entire new blocks in to the middle rather
   * than shuffling existing pointers which we've already given-out */
  if(CI_UNLIKELY( added_inc_block == removed_block && added_inc <= removed )) {
    size_t to_add = ring->nblocks == 0 ? 2 : 1;
    size_t i;
    struct hlrx_remote_ring_block** new_blocks;
    unsigned first_new_block = added_inc_block ? added_inc_block
                                               : ring->nblocks;

    /* We must be entering a new block. */
    ci_assert_equal(added_inc % HLRX_REMOTE_RING_BLOCK_SIZE, 0);

    new_blocks = calloc(ring->nblocks + to_add, sizeof(*new_blocks));
    if( ! new_blocks )
      return NULL;
    /* Inserting new blocks starting at first_new_block will not interrupt the
     * contiguous sequence of in-flight buffers in the range [removed, added).
     * Begin by populating the new ring with the blocks on either side of the
     * new blocks. */
    memcpy(new_blocks, ring->blocks, sizeof(*new_blocks) * first_new_block);
    memcpy(new_blocks + first_new_block + to_add,
           ring->blocks + first_new_block,
           sizeof(*new_blocks) * (ring->nblocks - first_new_block));
    /* Allocate the new blocks. */
    for( i = 0; i < to_add; ++i ) {
      new_blocks[first_new_block + i] = malloc(sizeof(**new_blocks));
      if( ! new_blocks[first_new_block + i] ) {
        while( i )
          free(new_blocks[first_new_block + --i]);
        free(new_blocks);
        return NULL;
      }
    }
    free(ring->blocks);
    ring->blocks = new_blocks;
    ring->nblocks += to_add;
    if( removed > added )
      ring->removed += to_add * HLRX_REMOTE_RING_BLOCK_SIZE;
    else
      ci_assert_equal(removed_block, 0);
    added_inc = added + 1;
  }

  ring->added = added_inc;
  return remote_ring_entry(ring, added);
}


/* Pass buffers from 'iovs' to state->msg->iov, updating the tracking as we
 * go */
static void zc_iovs(struct zc_cb_zc_state* state,
                    struct onload_zc_iovec* iovs, int* pbegin, int end,
                    enum onload_zc_callback_rc* cb_flags)
{
  int ref_delta = 0;
  int begin = *pbegin;
  while( begin != end && state->max_bytes &&
         state->curr_iov < state->msg->msghdr.msg_iovlen ) {
    struct onload_zc_iovec* dst = &state->msg->iov[state->curr_iov];
    *dst = iovs[begin];
    if( iovs[begin].addr_space != EF_ADDRSPACE_LOCAL ) {
      uint64_t* rd = zc_remote_block_add(&state->hlrx->remote_ring);
      if( ! rd ) {
        if( state->rc == 0 )
          state->rc = -ENOMEM;
        break;
      }
      *rd = iovs[begin].iov_ptr + CI_MIN(iovs[begin].iov_len64,
                                         state->max_bytes),
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
  if( ref_delta == -1 && cb_flags ) {
    /* The 'else' branch works fine too, but this is more efficient (less
     * stack locking) and a common case with zc_remote_data. */
    ci_assert_flags(*cb_flags, ONLOAD_ZC_KEEP);
    *cb_flags &=~ ONLOAD_ZC_KEEP;
  }
  else {
    zc_buffer_addref(state->hlrx->fd, iovs[0].buf, ref_delta);
  }
}


/* Callback for onload_zc_recv when we're doing zero-copy into user iovs */
static enum onload_zc_callback_rc
zc_cb(struct onload_zc_recv_args *args, int flags)
{
  struct zc_cb_zc_state* state = args->user_ptr;
  int begin = 0;
  int end = args->msg.msghdr.msg_iovlen;
  enum onload_zc_callback_rc ret = ONLOAD_ZC_KEEP;

  ci_assert_gt(end, 0);
  ci_assert_equal(state->hlrx->pending_begin, state->hlrx->pending_end);
  zc_iovs(state, args->msg.iov, &begin, end, &ret);

  if( state->hlrx->udp ) {
    if( end != begin )
      state->msg->msghdr.msg_flags |= MSG_TRUNC;
    return ret | ONLOAD_ZC_TERMINATE;
  }
  if( end != begin ) {
    ci_assert_flags(ret, ONLOAD_ZC_KEEP);
    if( ! save_pending(state->hlrx, args, begin, end) ) {
      state->rc = -ENOMEM;
      onload_zc_buffer_decref(state->hlrx->fd, state->hlrx->pending[0].buf);
    }
    return ONLOAD_ZC_KEEP | ONLOAD_ZC_TERMINATE;
  }

  if( state->max_bytes && state->curr_iov < state->msg->msghdr.msg_iovlen )
    return ret | ONLOAD_ZC_CONTINUE;
  return ret | ONLOAD_ZC_TERMINATE;
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

  consume_done_remotes(hlrx);
  if( flags & (MSG_PEEK | MSG_TRUNC | MSG_ERRQUEUE) ) {
    state.rc = -EINVAL;
  }
  else {
    msg->msghdr.msg_flags = 0;
    if( hlrx->pending_begin != hlrx->pending_end ) {
      /* Consume leftovers from previous call */
      zc_iovs(&state, hlrx->pending, &hlrx->pending_begin, hlrx->pending_end,
              NULL);
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

  Log_CALL_RESULT((int)state.rc);
  return state.rc;
}
