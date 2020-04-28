/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr/ctk/stg
**  \brief  PIPE routines
**   \date  2003/06/04
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"

#include <onload/common.h>
#include <onload/oo_pipe.h>
#include <onload/sleep.h>

#define LPF "ci_pipe_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF


/* Many-many logging messages */
#define OO_PIPE_VERBOSE           0

#define OO_PIPE_DUMP              0

#if OO_PIPE_VERBOSE
# define LOG_PIPE(x...) ci_log(x)
#else
# define LOG_PIPE(x...)
#endif


void pipe_dump(ci_netif* ni, struct oo_pipe* p)
{
  if( OO_PIPE_DUMP ) {
    ci_log("Pipe: p=%d", p->b.bufid);
    ci_log("  [%d] read_ptr: %d %u", p->b.bufid,
           OO_PP_FMT(p->read_ptr.pp), p->read_ptr.offset);
    ci_log("  [%d] write_ptr: %d %d", p->b.bufid,
           OO_PP_FMT(p->write_ptr.pp), OO_PP_FMT(p->write_ptr.pp_wait));
    ci_log("  [%d] aflags=%x ", p->b.bufid, p->aflags);
    ci_log("  [%d] bufs_num=%u/%u", p->b.bufid, p->bufs_num, p->bufs_max);
    ci_log("  [%d] bytes_added=%u bytes_removed=%u", p->b.bufid,
           p->bytes_added, p->bytes_removed);
    if( ci_netif_is_locked(ni) && OO_PP_NOT_NULL(p->pipe_bufs.pp) ) {
      ci_ip_pkt_fmt* pkt = PKT_CHK(ni, p->pipe_bufs.pp);
      int bufs_num = 0;
      do {
        ci_log("  [%d:%d] pkt %d base=%d pay_len=%d", p->b.bufid, bufs_num,
               OO_PKT_P(pkt), pkt->pf.pipe.base, pkt->pf.pipe.pay_len);
        pkt = PKT_CHK(ni, pkt->next);
      } while( OO_PKT_P(pkt) != p->pipe_bufs.pp &&
               ++bufs_num < 2 * p->bufs_num );
      /* The coefficient 2 in the bound-check is to help debug the case when
       * the recorded number of packets is inconsistent with the actual
       * packets. */
      if( bufs_num >= p->bufs_num )
        ci_log("  [%d] WARNING: More than p->bufs_num buffers.", p->b.bufid);
    }
  }
}


ci_inline void oo_pipe_buf_list_init(oo_pipe_buf_list_t* list)
{
  list->pp = OO_PP_NULL;
}


void oo_pipe_buf_clear_state(ci_netif* ni, struct oo_pipe* p)
{
  p->read_ptr.pp = OO_PP_NULL;
  p->read_ptr.offset = 0;
  p->write_ptr.pp = OO_PP_NULL;
  p->write_ptr.pp_wait = OO_PP_NULL;
  oo_pipe_buf_list_init(&p->pipe_bufs);
}


/* Following the convention elsewhere, [link] is the new node to be inserted
 * after the node [list]. */
ci_inline void oo_pipe_buf_list_insert_after(ci_ip_pkt_fmt* list,
                                             ci_ip_pkt_fmt* link)
{
  link->next = list->next;
  list->next = OO_PKT_P(link);
}


ci_inline void oo_pipe_buf_list_push(ci_netif* ni, oo_pipe_buf_list_t* list,
                                     ci_ip_pkt_fmt* link)
{
  if( OO_PP_NOT_NULL(list->pp) ) {
    oo_pipe_buf_list_insert_after(PKT_CHK(ni, list->pp), link);
  }
  else {
    list->pp = OO_PKT_P(link);
    link->next = OO_PKT_P(link);
  }
}


/* finds pkt preceeding item */
ci_inline ci_ip_pkt_fmt* oo_pipe_buf_list_find(ci_netif* ni,
                                               ci_ip_pkt_fmt* list,
                                               oo_pkt_p item)
{
  ci_ip_pkt_fmt* pkt = list;
  while( pkt->next != item )
    pkt = PKT_CHK(ni, pkt->next);
  return pkt;
}


ci_inline oo_pkt_p oo_pipe_buf_list_start(oo_pipe_buf_list_t* list)
{
  return list->pp;
}


ci_inline int oo_pipe_buf_list_is_last(ci_ip_pkt_fmt* pkt)
{
  return pkt->next == OO_PKT_P(pkt);
}


/* Get next packet in pipe list. Caller is responsible for holding the correct
 * lock(s) to ensure that the the pointer to the next node remains valid; the
 * necessary locks will depend on the circumstances. */
ci_inline oo_pkt_p oo_pipe_next_buf(struct oo_pipe* p, ci_ip_pkt_fmt* pkt)
{
  return pkt->next;
}


#ifndef __KERNEL__
/* Take packet from pipe buffer list,
 * minding its circularity
 */
ci_inline ci_ip_pkt_fmt*
oo_pipe_buf_list_pop_after(ci_netif* ni, struct oo_pipe* p,
                           ci_ip_pkt_fmt* list)
{
  ci_ip_pkt_fmt* pkt;
  ci_assert(list);
  ci_assert(OO_PP_NOT_NULL(p->pipe_bufs.pp));
  ci_assert(! oo_pipe_buf_list_is_last(list));
  pkt = PKT_CHK(ni, list->next);
  if( p->pipe_bufs.pp == list->next )
    p->pipe_bufs.pp = OO_PKT_P(list);
  list->next = pkt->next;
  return pkt;
}
#endif


ci_inline void __oo_pipe_wake_peer(ci_netif* ni, struct oo_pipe* p,
                                   unsigned wake)
{
  ci_wmb();
  if( wake & CI_SB_FLAG_WAKE_RX )
    ++p->b.sleep_seq.rw.rx;
  if( wake & CI_SB_FLAG_WAKE_TX )
    ++p->b.sleep_seq.rw.tx;
  ci_mb();
  if( p->b.wake_request & wake ) {
    p->b.sb_flags |= wake;
    citp_waitable_wakeup(ni, &p->b);
  }
}


#ifdef __KERNEL__
void oo_pipe_wake_peer(ci_netif* ni, struct oo_pipe* p, unsigned wake)
{
  __oo_pipe_wake_peer(ni, p, wake);
}
#endif


ci_inline ci_uint8* pipe_get_point(ci_netif* ni, struct oo_pipe *p,
                                   ci_ip_pkt_fmt* pkt, ci_uint32 offset)
{
  ci_assert(p);
  ci_assert_lt(offset, OO_PIPE_BUF_MAX_SIZE - pkt->pf.pipe.base);

  return pkt->dma_start + pkt->pf.pipe.base + offset;
}


/* Returns the number of free bytes for payload use in a pipe buffer. Note
 * that, owing to splicing, having free space does not indicate that the buffer
 * is the last in the list.
 */
ci_inline ci_uint32 oo_pipe_buf_space(ci_ip_pkt_fmt* pkt)
{
  ci_assert_le(pkt->pf.pipe.base + pkt->pf.pipe.pay_len, OO_PIPE_BUF_MAX_SIZE);
  return OO_PIPE_BUF_MAX_SIZE - (pkt->pf.pipe.base + pkt->pf.pipe.pay_len);
}


ci_inline int do_copy_read(void* to, const void* from, int n_bytes)
{
#ifdef __KERNEL__
  return copy_to_user(to, from, n_bytes) != 0;
#else
  memcpy(to, from, n_bytes);
  return 0;
#endif
}


ci_inline int do_copy_write(void* to, const void* from, int n_bytes)
{
#ifdef __KERNEL__
  return copy_from_user(to, from, n_bytes) != 0;
#else
  memcpy(to, from, n_bytes);
  return 0;
#endif
}


static int oo_pipe_read_wait(ci_netif* ni, struct oo_pipe* p, int non_block)
{
  ci_uint64 sleep_seq;
  int rc;

  if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_WRITER_SHIFT) ) {
  closed_double_check:
    ci_mb();
    return oo_pipe_data_len(p) ? 1 : 0;
  }

  LOG_PIPE("%s: not enough data in the pipe",
           __FUNCTION__);

  if( non_block ) {
    LOG_PIPE("%s: O_NONBLOCK is set so exit", __FUNCTION__);
    CI_SET_ERROR(rc, EAGAIN);
    return rc;
  }

#ifndef __KERNEL__
  if( oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_PIPE_RECV) ) {
    ci_uint64 now_frc, start_frc;
    ci_uint64 schedule_frc;
    citp_signal_info* si = citp_signal_get_specific_inited();
    ci_uint64 max_spin_cycles = p->b.spin_cycles;

    ci_frc64(&now_frc);
    start_frc = now_frc;
    schedule_frc = now_frc;
    do {
      rc = OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, &schedule_frc, 
                                           false, NULL, si);
      if( rc < 0 ) {
        CI_SET_ERROR(rc, -rc);
        return rc;
      }
      if( oo_pipe_data_len(p) )
        return 1;
      if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_WRITER_SHIFT) )
        goto closed_double_check;
      ci_frc64(&now_frc);
#if CI_CFG_SPIN_STATS
      ni->state->stats.spin_pipe_read++;
#endif
    } while( now_frc - start_frc < max_spin_cycles );
  }
#endif

  while( 1 ) {
    sleep_seq = p->b.sleep_seq.all;
    ci_rmb();
    if( oo_pipe_data_len(p) )
      return 1;
    if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_WRITER_SHIFT) )
      goto closed_double_check;

    LOG_PIPE("%s [%u]: going to sleep seq=(%u, %u) data_len=%d aflags=%x",
             __FUNCTION__, p->b.bufid,
             ((ci_sleep_seq_t *)(&sleep_seq))->rw.rx,
             ((ci_sleep_seq_t *)(&sleep_seq))->rw.tx,
             oo_pipe_data_len(p), p->aflags);
    rc = ci_sock_sleep(ni, &p->b, CI_SB_FLAG_WAKE_RX, 0, sleep_seq, 0);
    LOG_PIPE("%s[%u]: woke up: rc=%d data_len=%d aflags=%x", __FUNCTION__,
             p->b.bufid, rc, (int)oo_pipe_data_len(p), p->aflags);
    if( rc < 0 ) {
      LOG_PIPE("%s: sleep rc = %d", __FUNCTION__, rc);
      CI_SET_ERROR(rc, -rc);
      return rc;
    }
    if( oo_pipe_data_len(p) )
      return 1;
  }
}


/* Advances from an arbitrary read-point to the next byte that would be read.
 * Returns number of buffers advanced. */
ci_inline int
oo_pipe_move_read_ptr(ci_netif* ni, struct oo_pipe* p, ci_ip_pkt_fmt** pkt,
                      ci_uint32 *offset, int stack_locked)
{
  int moved = 0;
  /* It might be we need to skip a 0 length payload pkt.
   * The need may arise when pkts were inserted when there had been
   * only empty buffers left in the pipe */
  while( *offset >= (*pkt)->pf.pipe.pay_len ) {
    /* read_ptr should not get ahead of write_ptr */
    ci_assert_nequal(OO_PKT_P(*pkt), p->write_ptr.pp);
    *pkt = PKT_CHK_NML(ni, oo_pipe_next_buf(p, *pkt), stack_locked);
    *offset = 0;
    ++moved;
  }
  return moved;
}


int ci_pipe_read(ci_netif* ni, struct oo_pipe* p,
                 const struct iovec *iov, size_t iovlen)
{
  int bytes_available;
  int rc;
  int i;
  ci_ip_pkt_fmt* pkt;
  int do_wake = 0;
  ci_uint32 offset;

  ci_assert(p);
  ci_assert(ni);
  ci_assert(iov);
  ci_assert_gt(iovlen, 0);

  LOG_PIPE("%s[%u]: ENTER data_len=%d aflags=%x",
           __FUNCTION__, p->b.bufid, oo_pipe_data_len(p), p->aflags);
  pipe_dump(ni, p);

 again:
  bytes_available = oo_pipe_data_len(p);
  if( bytes_available == 0 ) {
    if( (rc = oo_pipe_read_wait(ni, p,
                                p->aflags & (CI_PFD_AFLAG_NONBLOCK <<
                                             CI_PFD_AFLAG_READER_SHIFT))) != 1 )
      goto out;
  }

  rc = ci_sock_lock(ni, &p->b);
#ifdef __KERNEL__
  if( rc < 0 ) {
    CI_SET_ERROR(rc, ERESTARTSYS);
    goto out;
  }
#endif
  /* Recheck available data now that we have the lock. */
  if( (bytes_available = oo_pipe_data_len(p)) == 0 ) {
    ci_sock_unlock(ni, &p->b);
    goto again;
  }

  rc = 0;
  pkt = PKT_CHK_NNL(ni, p->read_ptr.pp);
  offset = p->read_ptr.offset;
  for( i = 0; i < iovlen; i++ ) {
    char* start = iov[i].iov_base;
    char* end = start + iov[i].iov_len;
    while ( end - start ) {
      ci_uint8* read_point;
      int burst;

      /* We wish to do a wake if we advance the pointer, but to avoid branching,
       * detect this by keeping a cumulative count of the number of buffers
       * advanced. */
      do_wake += oo_pipe_move_read_ptr(ni, p, &pkt, &offset, 0);

      read_point = pipe_get_point(ni, p, pkt, offset);
      burst = CI_MIN(pkt->pf.pipe.pay_len - offset, end - start);
      burst = CI_MIN(burst, bytes_available - rc);
      ci_assert_lt(offset, pkt->pf.pipe.pay_len);
      ci_assert_le(offset + burst, pkt->pf.pipe.pay_len);

      if(CI_UNLIKELY( do_copy_read(start, read_point, burst) != 0 )) {
        ci_wmb();
        p->bytes_removed += rc;
        CI_SET_ERROR(rc, EFAULT);
        goto wake_and_unlock_out;
      }

      rc += burst;
      start += burst;
      offset += burst;

      if( bytes_available == rc )
        goto read;
    }
  }

 read:
  ci_wmb();
  p->bytes_removed += rc;
  p->read_ptr.pp = OO_PKT_P(pkt);
  p->read_ptr.offset = offset;
 wake_and_unlock_out:
  if( do_wake || bytes_available == rc )
    __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_TX);
  ci_sock_unlock(ni, &p->b);
 out:
  LOG_PIPE("%s[%u]: EXIT return %d", __FUNCTION__, p->b.bufid, rc);
  return rc;
}


ci_inline void oo_pipe_signal(ci_netif* ni)
{
#ifndef __KERNEL__
  (void)ci_sys_ioctl(ci_netif_get_driver_handle(ni),
                     OO_IOC_KILL_SELF_SIGPIPE,
                     NULL);
#else
  (void)send_sig(SIGPIPE, current, 0);
#endif
}


/* This function is a helper for ci_pipe_write. It is called with the stack
 * lock held, and will set *stack_locked to indicate whether it is still locked
 * when it returns. */
static int oo_pipe_wait_write(ci_netif* ni, struct oo_pipe* p, int flags,
                              int *stack_locked)
{
  ci_uint64 sleep_seq;
  int rc = 0;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert_equal(*stack_locked, 1);

  if ( oo_pipe_is_writable(p) )
    return 0;
  ci_netif_unlock(ni);
  *stack_locked = 0;

#ifndef __KERNEL__
  if( oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_PIPE_SEND) ) {
    ci_uint64 now_frc, start_frc;
    ci_uint64 schedule_frc;
    citp_signal_info* si = citp_signal_get_specific_inited();
    ci_uint64 max_spin_cycles = p->b.spin_cycles;

    ci_frc64(&now_frc);
    start_frc = now_frc;
    schedule_frc = now_frc;

    do {
      rc = OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, &schedule_frc, 
                                           false, NULL, si);
      if( rc < 0 ) {
        CI_SET_ERROR(rc, -rc);
        return rc;
      }

      if ( oo_pipe_is_writable(p) )
        return 0;

      if ( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_READER_SHIFT) ) {
        CI_SET_ERROR(rc, EPIPE);
        if( ! (flags & MSG_NOSIGNAL) )
          oo_pipe_signal(ni);
        return rc;
      }

      ci_frc64(&now_frc);
#if CI_CFG_SPIN_STATS
      ni->state->stats.spin_pipe_write++;
#endif

    } while( now_frc - start_frc < max_spin_cycles );
  }
#endif /* spin code end */

  do {
    sleep_seq = p->b.sleep_seq.all;
    ci_rmb();

    /* if we have enough space at this moment - just exit */
    if( oo_pipe_is_writable(p) )
      break;

    /* we should sleep here */
    LOG_PIPE("%s: going to sleep", __FUNCTION__);
    rc = ci_sock_sleep(ni, &p->b, CI_SB_FLAG_WAKE_TX, 0, sleep_seq, 0);
    if ( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_READER_SHIFT) ) {
      CI_SET_ERROR(rc, EPIPE);
      if( ! (flags & MSG_NOSIGNAL) )
        oo_pipe_signal(ni);
      return rc;
    }

    LOG_PIPE("%s[%u]: woke up - %d", __FUNCTION__, p->b.bufid, rc);

    if( rc < 0 ) {
      LOG_PIPE("%s: sleep rc = %d", __FUNCTION__, rc);
      CI_SET_ERROR(rc, -rc);
      return rc;
    }
  } while( ! oo_pipe_is_writable(p) );

  /* we have some space! */
  return 0;
}


/* Called before writing into a logically empty pipe buffer. */
ci_inline void oo_pipe_buf_write_init(struct oo_pipe* p, ci_ip_pkt_fmt* pkt)
{
  pkt->pf.pipe.base = 0;
  pkt->pf.pipe.pay_len = 0;
}


#ifndef __KERNEL__
/* pkt list is non-circular list of pkts that do not belong to pipe
 *
 * Field pkts->tail->next is ignored
 */
ci_inline ci_ip_pkt_fmt* oo_pipe_pkt_list_pop(ci_netif* ni,
                                              struct ci_pipe_pkt_list* pkts)
{
  ci_ip_pkt_fmt* pkt;
  ci_assert(pkts);
  if( ! pkts->count )
    return NULL;
  ci_assert(pkts->head);
  pkt = pkts->head;
  pkts->head = PKT_CHK(ni, pkt->next);
  --pkts->count;
  return pkt;
}


ci_inline void oo_pipe_pkt_list_push(struct ci_pipe_pkt_list* list,
                                     ci_ip_pkt_fmt* pkt)
{
  if( list->count ) {
    list->tail->next = OO_PKT_P(pkt);
    list->tail = pkt;
    ++list->count;
    return;
  }
  list->head = pkt;
  list->tail = pkt;
  list->count = 1;
}


ci_inline oo_pkt_p oo_pipe_pkt_list_next(ci_ip_pkt_fmt* pkt)
{
  return pkt->next;
}
#endif


/* Called when we want more space to write data into.  Returns >0 if more
 * space was allocated, 0 if we've already got the max, positive value
 * indicating number of buffers allocated and -ENOBUFS if we
 * can't get more memory.
 *
 * When need is 0 the function will:
 *  * in case pipe is empty, allocate OO_PIPE_INITIAL_BUFS buffers
 *  * otherwise double the current amount of buffers subject to limit
 *    of bufs_max
 *
 * When requested is non 0, function will allocate no more than need buffers.
 *
 * The caller must hold the stack lock.
 */
static int oo_pipe_more_buffers(ci_netif* ni, struct oo_pipe* p, int requested,
                                struct ci_pipe_pkt_list* pkts)

{
  ci_uint32 num_alloced, total_to_alloc;
  ci_ip_pkt_fmt* write_pkt = NULL;

  ci_assert_ge(requested, 0);

  LOG_PIPE("%s: called for ni=%d p=%d wr=%d rd=%d",
           __FUNCTION__, ni->state->stack_id, p->b.bufid,
           OO_PP_FMT(p->write_ptr.pp), OO_PP_FMT(p->read_ptr.pp));

  ci_assert(ci_netif_is_locked(ni));

  if( p->bufs_num >= p->bufs_max )
    return 0;
  if( OO_PP_NOT_NULL(p->write_ptr.pp) )
    write_pkt = PKT_CHK(ni, p->write_ptr.pp);
  if( requested )
    total_to_alloc = CI_MIN(requested, p->bufs_max - p->bufs_num);
  else
    total_to_alloc = p->bufs_num > 0 ?
        CI_MIN(p->bufs_num, p->bufs_max - p->bufs_num) :
        CI_MIN(OO_PIPE_INITIAL_BUFS, p->bufs_max);
  for( num_alloced = 0; num_alloced < total_to_alloc; ++num_alloced ) {
    ci_ip_pkt_fmt* pkt;
#ifndef __KERNEL__
    if( pkts != NULL && pkts->count )
      pkt = oo_pipe_pkt_list_pop(ni, pkts);
    else
#endif
      pkt = ci_netif_pkt_alloc(ni, 0);
    if( ! pkt ) {
      LOG_NV(ci_log("Failed to alloc pipe packet buffer"));
      break;
    }
    oo_pipe_buf_write_init(p, pkt);
    if( write_pkt != NULL )
      oo_pipe_buf_list_insert_after(write_pkt, pkt);
    else
      oo_pipe_buf_list_push(ni, &p->pipe_bufs, pkt);
  }

  if( num_alloced > 0 ) {
    if( write_pkt == NULL ) {
      p->write_ptr.pp = oo_pipe_buf_list_start(&p->pipe_bufs);
      /* Safe to set the read pointer as the pipe is empty. */
      p->read_ptr.pp = p->write_ptr.pp;
    }
    else
      p->write_ptr.pp = oo_pipe_next_buf(p, write_pkt);
    p->write_ptr.pp_wait = OO_PP_NULL;
    p->bufs_num += num_alloced;
    return num_alloced;
  }
  return -ENOBUFS;
}


#ifndef __KERNEL__
/* Inserts filled buffers into pipe's queue.
 *
 * The buffers need to be pipe compatible
 * That is iov_base == pkt->dma_start.
 *
 * The caller must hold the stack lock.
 */
static void oo_pipe_insert_buffers(ci_netif* ni, struct oo_pipe* p,
                                   struct ci_pipe_pkt_list* pkts)
{
  ci_ip_pkt_fmt* write_pkt = NULL;
  oo_pkt_p pp_read;

  LOG_PIPE("%s: called for ni=%d p=%d wr=%d rd=%d",
           __FUNCTION__, ni->state->stack_id, p->b.bufid,
           OO_PP_FMT(p->write_ptr.pp), OO_PP_FMT(p->read_ptr.pp));

  ci_assert(ci_netif_is_locked(ni));
  ci_assert_gt(pkts->count, 0);
  ci_assert(pkts->head);
  ci_assert(pkts->tail);

  if( OO_PP_IS_NULL(p->write_ptr.pp) ) {
    ci_assert_equal(p->bufs_num, 0);
    p->pipe_bufs.pp = OO_PKT_P(pkts->head);
    pkts->tail->next = OO_PKT_P(pkts->head);
    /* Safe to set the read pointer as the pipe is empty.*/
    p->read_ptr.offset = 0;
    p->read_ptr.pp = OO_PKT_P(pkts->head);
    ci_assert_gt(pkts->tail->pf.pipe.pay_len, 0);
  }
  else {
    write_pkt = PKT_CHK(ni, p->write_ptr.pp);
    pkts->tail->next = oo_pipe_next_buf(p, write_pkt);
    write_pkt->next = OO_PKT_P(pkts->head);
  }

  p->write_ptr.pp = OO_PKT_P(pkts->tail);
  pp_read = OO_ACCESS_ONCE(p->read_ptr.pp);
  if( pkts->tail->next == pp_read && oo_pipe_buf_space(pkts->tail) == 0 )
    p->write_ptr.pp_wait = pp_read;
  p->bufs_num += pkts->count;
}


/* Reaps up to [count] empty packet buffers from pipe
 * list and either frees them or adds to pkts list.
 * If [count] is zero, all empty buffers are reaped.
 *
 * The packets are removed from pipe starting from
 * the packet after write_ptr.
 * This operations does not intefere with read,
 * and does not require socket lock.
 */
static int oo_pipe_reap_empty_buffers(ci_netif* ni,
                                      struct oo_pipe* p,
                                      int count,
                                      struct ci_pipe_pkt_list* pkts)
{
  int freed = 0;
  oo_pkt_p pkt_p;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p p_end;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(OO_PP_NOT_NULL(p));
  ci_assert_ge(count, 0);

  pkt_p = p->write_ptr.pp;
  p_end = OO_ACCESS_ONCE(p->read_ptr.pp);

  if( p->bufs_num == 0 )
    return 0;
  p->pipe_bufs.pp = pkt_p;
  pkt = PKT_CHK(ni, pkt_p);
  while( freed != count || count == 0 ) {
    /* TODO when pkts is set cut the buffers at once not one by one */
    ci_ip_pkt_fmt* fpkt;
    oo_pkt_p pp_next = oo_pipe_next_buf(p, pkt);
    if( pp_next == p_end )
      break;
    fpkt = oo_pipe_buf_list_pop_after(ni, p, pkt);
    ci_assert_nequal(pkt, fpkt);
    ci_assert_nequal(OO_PKT_P(fpkt), p_end);
    ci_assert_equal(fpkt->refcount, 1);
    if( pkts == NULL )
      ci_netif_pkt_release(ni, fpkt);
    else {
      oo_pipe_buf_write_init(p, fpkt);
      /* Mark this buffer as full even though we haven't yet written the data.
       * This length will be correct for all of the buffers with the possible
       * exception of the final one, and so this will save us from having to
       * walk the list later. */
      fpkt->pf.pipe.pay_len = oo_pipe_buf_space(fpkt);
      oo_pipe_pkt_list_push(pkts, fpkt);
    }
    ++freed;
  }
  p->bufs_num -= freed;
  if( oo_pipe_buf_space(pkt) == 0 ) {
    oo_pkt_p pp_next = oo_pipe_next_buf(p, pkt);
    p->write_ptr.pp_wait = pp_next == p_end ? pp_next : OO_PP_NULL;
  }
  ci_assert_ge(p->bufs_num, 0);
  return freed;
}


/* Produces set of empty buffers obeying pipe capacity restriction.
 *
 * The function will fill iovec with details of empty buffers.
 * The buffers will either be removed from pipe. And in case
 * pipe cannot meet the demand, new buffers will be allocated.
 */
static int oo_pipe_grab_pipe_buffers(ci_netif* ni,
                                     struct oo_pipe* p,
                                     int count,
                                     struct ci_pipe_pkt_list* pkts)
{
  int pipe_buf_space = CI_MAX(p->bufs_max - p->bufs_num, 0);
  int buf_num;

  ci_assert_gt(count, 0);
  ci_assert(ci_netif_is_locked(ni));

  buf_num = oo_pipe_reap_empty_buffers(ni, p, count, pkts);
  count -= buf_num;
  if( ! count )
    return buf_num;
  for( count = CI_MIN(pipe_buf_space, count); count; --count ) {
    ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(ni, 0);
    if( ! pkt ) {
      LOG_NV(ci_log("Failed to alloc pipe packet buffer"));
      break;
    }
    ci_assert_equal(pkt->refcount, 1);
    oo_pipe_buf_write_init(p, pkt);
    /* Mark this buffer as full even though we haven't yet written the data.
     * This length will be correct for all of the buffers with the possible
     * exception of the final one, and so this will save us from having to walk
     * the list later. */
    pkt->pf.pipe.pay_len = oo_pipe_buf_space(pkt);
    oo_pipe_pkt_list_push(pkts, pkt);
    ++buf_num;
  }
  return buf_num;
}


/* Allocates zc buffers for use with pipes possibly blocking
 *
 * Buffers are either reaped from pipe or freshly allocated.
 *
 * Pkts are empty, and pf.pipe.pay_len tells pkt capacity.
 *
 * Suported flags: MSG_DONTWAIT, MSG_NOSIGNAL
 */
int ci_pipe_zc_alloc_buffers(ci_netif* ni,
                             struct oo_pipe* p,
                             int count,
                             int flags,
                             struct ci_pipe_pkt_list* pkts_out)
{
  int c;
  int rc = 0;
  int stack_locked = 1;
  ci_netif_lock(ni);

  do {
    c = oo_pipe_grab_pipe_buffers(ni, p, count, pkts_out);
    if( c ) {
      ni->state->n_async_pkts += c;
      break;
    }
    if(flags & MSG_DONTWAIT ) {
      CI_SET_ERROR(rc, EAGAIN);
      break;
    }
    rc = oo_pipe_wait_write(ni, p, flags, &stack_locked);
    if( rc != 0 )
      break;
    if( ! stack_locked ) {
      ci_netif_lock(ni);
      stack_locked = 1;
    }
  } while( 1 );

  if( stack_locked )
    ci_netif_unlock(ni);
  return rc;
}


static void oo_pipe_free_buffers(ci_netif* ni,
                                 struct ci_pipe_pkt_list* pkts)
{
  ci_ip_pkt_fmt* pkt = pkts->head;
  ci_assert(ci_netif_is_locked(ni));
  for( ; pkts->count; --pkts->count ) {
    oo_pkt_p pp;
    ci_assert(pkt);
    ci_assert_equal(pkt->refcount, 1);
    pp = oo_pipe_pkt_list_next(pkt);
    ci_netif_pkt_release(ni, pkt);
    pkt = PKT_CHK(ni, pp);
  }
}


/* Releases buffers
 *
 * The buffers had been previously allocated with ci_pipe_alloc_buffers
 * but not passed back with ci_pipe_zc_write.
 */
static int oo_pipe_zc_release_buffers(ci_netif* ni,
                               struct oo_pipe* p,
                               struct ci_pipe_pkt_list* pkts)
{
  int i;
  int count = pkts->count;
  /* return the buffers to pipe rather than release them */
  i = oo_pipe_more_buffers(ni, p, pkts->count, pkts);
  (void) i;
  ci_assert_le(0, i);
  if( pkts->count )
    /* pipe could not accomodate all the buffers, let's release the rest */
    oo_pipe_free_buffers(ni, pkts);
  ni->state->n_async_pkts -= count;
  return 0;
}


/* external netif lock guarded version of oo_pipe_zc_release_buffers */
int ci_pipe_zc_release_buffers(ci_netif* ni,
                               struct oo_pipe* p,
                               struct ci_pipe_pkt_list* pkts)
{
  int rc;
  ci_netif_lock(ni);
  rc = oo_pipe_zc_release_buffers(ni, p, pkts);
  ci_netif_unlock(ni);
  return rc;
}


/* Finds the buffer and offset at [*advance] bytes logically beyond the start
 * of [*list]. [*list] is set to the buffer in which that point lies, and
 * [*advance] is updated to be the corresponding offset within that buffer. The
 * number of buffers walked is returned. If [pre_tail] is not NULL, [*pre_tail]
 * is set to the buffer in the list that comes before the new [*list], or NULL
 * if [*list] is not moved as a result of the operation.
 *
 * Preconditions: List must hold ast least [*advance] bytes beyond the start of
 * the initial [*list].
 */
ci_inline int oo_pipe_list_ptr_move(ci_netif* ni, struct oo_pipe* p,
                                    ci_ip_pkt_fmt** list, int *advance,
                                    ci_ip_pkt_fmt** pre_tail)
{
  int count = 1;

  /* The initial head is only required for an assertion. */
  ci_ip_pkt_fmt* head = *list;
  (void) head;

  ci_assert_ge(*advance, 0);
  ci_assert(*list);

  if( pre_tail != NULL )
    *pre_tail = NULL;

  while( *advance > (*list)->pf.pipe.pay_len ) {
    *advance -= (*list)->pf.pipe.pay_len;
    ++count;
    if( pre_tail != NULL )
      *pre_tail = *list;
    *list = PKT_CHK(ni, oo_pipe_next_buf(p, *list));
    ci_assert(*list);
    ci_assert_ge(*advance, 0);
    if( *advance != 0 )
      ci_assert_nequal(OO_PKT_P(*list), OO_PKT_P(head));
    ci_assert_gt((*list)->pf.pipe.pay_len, 0);
  }
  return count;
}


/* Zero copy write to the pipe.
 *
 * This is an atomic operation.
 * All the filled buffers are added to the pipe at once,
 * non-filled buffers are released.
 *
 * The call will block (or return -1, errno EAGAIN with MSG_DONTWAIT) only
 * when the pipe is already full. Otherwise all
 * packets are accepted even when violating bufs_max limit.
 *
 * pkts - list of pkts, pf.pipe.pipe_len indicates capacity,
 *   pkts are assumed to be filled up to their capacity beside the last of
 *   those containing payload (the actuall fill level of pkt is worked out
 *   with len arg). Redundant pkts in the list get freed.
 *
 * SIGPIPE is never generated, -1 with errno EPIPE is returned instead.
 *
 * CI_PIPE_ZC_WRITE_FLAG_FORCE - allows violating pipe size restriction,
 *   implies MSG_DONTWAIT
 * Other supported flags: MSG_DONTWAIT
 */
int ci_pipe_zc_write(ci_netif* ni, struct oo_pipe* p,
                     struct ci_pipe_pkt_list* pkts,
                     int len, int flags)
{
  int rc;
  int bytes_added;
  int stack_locked;
  int buf_space;
  int count = pkts->count;

  ci_assert(p);
  ci_assert(ni);
  ci_assert(pkts);
  ci_assert_gt(pkts->count, 0);

  LOG_PIPE("%s[%u]: ENTER nonblock=%s bufs=%d wr=%d wr_wait=%d rd=%d",
           __FUNCTION__,
           p->b.bufid,
           (flags & MSG_DONTWAIT) ?
           "true" : "false",
           p->bufs_num,
           OO_PP_FMT(p->write_ptr.pp),
           OO_PP_FMT(p->write_ptr.pp_wait),
           OO_PP_FMT(p->read_ptr.pp));

  ci_netif_lock(ni);
  stack_locked = 1;

  pipe_dump(ni, p);

  if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_READER_SHIFT) ) {
    CI_SET_ERROR(rc, EPIPE);
    goto out;
  }

  if( len == 0 ) {
    (void) oo_pipe_zc_release_buffers(ni, p, pkts);
    rc = 0;
    goto out;
  }
  else {
    /* the list we have got might only be partially filled,
     * let's split list into filled and empty buffers */
    int advance = len;
    struct ci_pipe_pkt_list pkts_to_free = *pkts;
    oo_pkt_p first_to_free;
    int pkt_cnt;
    /* lets go to the end of data */
    pkts->tail = pkts->head;
    pkt_cnt = oo_pipe_list_ptr_move(ni, p, &pkts->tail, &advance, NULL);
    pkts->tail->pf.pipe.pay_len = advance;
    pkts->count = pkt_cnt;
    pkts_to_free.count -= pkt_cnt;
    if( pkts_to_free.count ) {
      first_to_free = oo_pipe_pkt_list_next(pkts->tail);
      pkts_to_free.head = PKT_CHK(ni, first_to_free);
      (void) oo_pipe_zc_release_buffers(ni, p, &pkts_to_free);
    }
  }

  buf_space = p->bufs_max - p->bufs_num;
  if( buf_space < count ) {
    (void) oo_pipe_reap_empty_buffers(ni, p, count - buf_space, NULL);
    buf_space = p->bufs_max - p->bufs_num;
  }
  if( (flags & CI_PIPE_ZC_WRITE_FLAG_FORCE) == 0 ) {
    while( buf_space <= 0 ) {
      if( flags & MSG_DONTWAIT ) {
        LOG_PIPE("%s: O_NONBLOCK is set so exit", __FUNCTION__);
        CI_SET_ERROR(rc, EAGAIN);
        goto out;
      }
      rc = oo_pipe_wait_write(ni, p, MSG_NOSIGNAL, &stack_locked);
      if( rc != 0 )
        goto out;
      if( ! stack_locked ) {
        ci_netif_lock(ni);
        stack_locked = 1;
      }
      /* We fall through even when we have less space than in fact needed.
       * This will potentially overflow the pipe with
       * all the buffers we are being given. */
      buf_space = p->bufs_max - p->bufs_num;
      if( buf_space < pkts->count ) {
        (void) oo_pipe_reap_empty_buffers(ni, p, count - buf_space, NULL);
        buf_space = p->bufs_max - p->bufs_num;
      }
    }
  }

  oo_pipe_insert_buffers(ni, p, pkts);
  bytes_added = len;

  if( bytes_added > 0 ) {
    ci_wmb();
    p->bytes_added += bytes_added;
    ni->state->n_async_pkts -= count;
    __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_RX);
  }
  rc = bytes_added;

 out:
  pipe_dump(ni, p);

  if( stack_locked )
    ci_netif_unlock(ni);

  LOG_PIPE("%s[%u]: EXIT return %d", __FUNCTION__, p->b.bufid, rc);
  return rc;
}


/* Fill in iovec array based on zc_iovec
 *
 * *iov_num is length of iovec, *iov_num is updated
 *   to reflect actual iov usage
 * pkts list is updated, used up buffers are removed.
 * returns how much bytes will fit into the iov array of length *iov_num
 */
int ci_pipe_list_to_iovec(ci_netif* ni, struct oo_pipe* p,
                          struct iovec* iov,
                          int* iov_num,
                          struct ci_pipe_pkt_list* pkts,
                          int len)
{
  int byte_len = 0;
  int i;
  oo_pkt_p pp = OO_PP_ID_NULL;
  ci_ip_pkt_fmt* pkt;
  int count;
  ci_assert_gt(len, 0);
  ci_assert(pkts);
  ci_assert_gt(pkts->count, 0);
  pkt = pkts->head;
  ci_assert(pkt);
  count = CI_MIN(*iov_num, pkts->count);
  for( i = 0; i < count; ++i ) {
    int iov_len;
    if( i != 0 )
      pkt = PKT_CHK(ni, pp);
    iov_len = CI_MIN(pkt->pf.pipe.pay_len, len);
    if( iov_len == 0 )
      break;
    iov[i].iov_base = pipe_get_point(ni, p, pkt, 0);
    iov[i].iov_len = iov_len;
    ci_assert(iov[i].iov_base);
    len -= iov_len;
    byte_len += iov_len;
    pp = oo_pipe_pkt_list_next(pkt);
  }
  *iov_num = i;
  pkts->count -= i;
  pkts->head = pkt;
  return byte_len;
}


#define OO_PIPE_ZC_READ_IOV_IOV_LEN 64
struct oo_pipe_zc_read_iov_ctx {
  struct iovec iov_on_stack[OO_PIPE_ZC_READ_IOV_IOV_LEN];
  struct iovec* iov;
  ci_pipe_zc_read_cb cb;
  void* cb_ctx;
};
/* Functions fills in zc_iovec that accomodates all
 * the buffers that contain readable data
 *
 * Initial iovec might be static buffer if this runs out a bigger one
 * will be allocated and it is resposibility of caller to free it.
 */
ci_inline int oo_pipe_zc_read_iov_cb(void* zc_read_iov_ctx,
                                     ci_netif* ni,
                                     struct oo_pipe* p,
                                     int flags,
                                     ci_ip_pkt_fmt* head,
                                     int bytes_available,
                                     int len,
                                     ci_ip_pkt_fmt** lastpkt_read_out,
                                     int* lastpkt_payload_read_out,
                                     int* pkts_read_out)
{
  struct oo_pipe_zc_read_iov_ctx* ctx = zc_read_iov_ctx;
  struct iovec* iov = ctx->iov_on_stack;
  ci_ip_pkt_fmt* pkt = head;
  int bytes_to_read = CI_MIN(bytes_available, len);
  int last_pkt_bytes_written;
  int bytes_written;
  int size;
  int i;
  int rc;

  /* check how much data/how many buffers can be read */
  iov[0].iov_base = pipe_get_point(ni, p, pkt, p->read_ptr.offset);
  size = pkt->pf.pipe.pay_len - p->read_ptr.offset;
  iov[0].iov_len = size;
  for( i = 1; size < bytes_to_read; ++i ) {
    oo_pkt_p pp = oo_pipe_next_buf(p, pkt);
    /* read_ptr should not get ahead of write_ptr */
    ci_assert_nequal(OO_PKT_P(pkt), p->write_ptr.pp);
    pkt = PKT_CHK(ni, pp);
    ci_assert(pkt);
    if( i == OO_PIPE_ZC_READ_IOV_IOV_LEN ) {
      void* niov;
      int size2 = bytes_to_read - size;
      ci_ip_pkt_fmt* pkt2 = pkt;
      /* lets calculate needed iovec size */
      int iov_len = i + oo_pipe_list_ptr_move(ni, p, &pkt2, &size2, NULL) + 1;
      niov = realloc(iov == ctx->iov_on_stack ? NULL : iov,
                     sizeof(*iov) * iov_len);
      if( niov == NULL )
        break; /* we can pass a lot of buffers anyway */
      if( iov == ctx->iov_on_stack )
        memcpy(niov, iov, sizeof(*iov) * i);
      /* else realloc copies data */
      iov = niov;
      ctx->iov = niov;
    }
    iov[i].iov_base = pipe_get_point(ni, p, pkt, 0);
    iov[i].iov_len = CI_MIN(pkt->pf.pipe.pay_len,
                              bytes_to_read - size);
    size += iov[i].iov_len;
  }
  iov[i - 1].iov_len += CI_MIN(0, bytes_to_read - size);

  rc = ctx->cb(ctx->cb_ctx, iov, i, flags);

  if( rc <= 0 )
    return rc;

  bytes_written = rc;
  ci_assert_le(bytes_written, bytes_to_read);

  last_pkt_bytes_written = bytes_written -
                           (bytes_to_read - iov[i - 1].iov_len);

  if( last_pkt_bytes_written <= 0 ) {
    /* Not all bytes had been written and
     * the last pkt of iovec certainly has not been written even partially,
     * we need to check how many pkts have actually been */
    int size2 = bytes_written + p->read_ptr.offset;
    pkt = head;
    i = oo_pipe_list_ptr_move(ni, p, &pkt, &size2, NULL);
    last_pkt_bytes_written = size2;
  }

  ci_assert_le(last_pkt_bytes_written, pkt->pf.pipe.pay_len);

  *lastpkt_read_out = pkt;
  *lastpkt_payload_read_out = last_pkt_bytes_written;
  *pkts_read_out = i - 1;
  return bytes_written;
}


/* Callback for oo_pipe_zc_read_bare */
typedef int (*oo_pipe_zc_read_cb_t)(void* zc_read_iov_ctx,
                                    ci_netif* ni,
                                    struct oo_pipe* p,
                                    int flags,
                                    ci_ip_pkt_fmt* head,
                                    int bytes_available,
                                    int len,
                                    ci_ip_pkt_fmt** lastpkt_read_out,
                                    int* lastpkt_payload_read_out,
                                    int* pkts_read_out);


/* Bare zero copy read from pipe
 *
 * Function passes an iovec listing filled buffers to the callback.
 * And read ptr is advanced by returned bytes.
 *
 * The call will block (or return EAGAIN with MSG_DONTWAIT),
 * when there is no data in the pipe,
 * or when the callback blocks.
 *
 * Callback is supposed to return number of bytes read or error (negative value)
 * The error will be passed back to the caller with errno unchanged.
 *
 * Callback also needs to provide ptr to last pkt it read data from,
 * amount of bytes it read from that pkt, number of pkts it read.
 */
#define OO_PIPE_ZC_READ_BARE_FLAG_LOCK_STACK 1
#define OO_PIPE_ZC_READ_BARE_FLAG_REMOVE_BUFFERS 2
ci_inline int oo_pipe_zc_read_bare(ci_netif* ni, struct oo_pipe* p,
                                   int len, int flags, int zc_flags,
                                   oo_pipe_zc_read_cb_t cb, void* cb_ctx)
{
  int bytes_available;
  int bytes_read_total = 0;
  int bufs_read_total = 0;
  int rc;
  ci_ip_pkt_fmt* pkt;
  ci_ip_pkt_fmt* pre_first_pkt;
  oo_pkt_p write_ptr_next = OO_PP_NULL;
  int lock_stack = zc_flags & OO_PIPE_ZC_READ_BARE_FLAG_LOCK_STACK;
  int remove_buffers = zc_flags & OO_PIPE_ZC_READ_BARE_FLAG_REMOVE_BUFFERS;
  ci_assert(p);
  ci_assert(ni);
  ci_assert(! remove_buffers || lock_stack);

  LOG_PIPE("%s[%u]: ENTER data_len=%d aflags=%x",
           __FUNCTION__, p->b.bufid, oo_pipe_data_len(p), p->aflags);

again:
  rc = ci_sock_lock(ni, &p->b);
  bytes_available = oo_pipe_data_len(p);

  if( bytes_available == 0 ) {
    ci_sock_unlock(ni, &p->b);
    goto wait_for_bytes;
  }

  if( lock_stack )
    ci_netif_lock(ni);

  pipe_dump(ni, p);

again_locked:
  pkt = PKT_CHK_NML(ni, p->read_ptr.pp, lock_stack);
  pre_first_pkt = pkt;

  bufs_read_total += oo_pipe_move_read_ptr(ni, p, &pkt, &p->read_ptr.offset,
                                           lock_stack);

  if( bufs_read_total > 0 ) {
    /* If we advanced the pointer, synchronise the pipe state now, as the
     * callback will expect consistent state. */
    p->read_ptr.pp = OO_PKT_P(pkt);
    __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_TX);
  }

  do {
    int bytes_read;
    ci_ip_pkt_fmt* last_pkt;
    int last_pkt_bytes_read;
    int bufs_read;

    if( remove_buffers ) {
      ci_ip_pkt_fmt* write_ptr_pkt = PKT_CHK(ni, p->write_ptr.pp);
      if( pre_first_pkt == pkt ) {
        /* TODO ideally we should store previously read pkt somewhere
         * for now we might in worst case go through the entire empty list.
         * Typically though we should not have empty buffers in
         * zero_copy splice usecase.
         */
        pre_first_pkt = write_ptr_pkt;
      }
      pre_first_pkt = oo_pipe_buf_list_find(ni, pre_first_pkt, OO_PKT_P(pkt));
      /* in some cases pkt pointed by write_ptr may get removed, lets store
       * where to move write_ptr when this happens */
      write_ptr_next = write_ptr_pkt->next;
    }

    /* What is expected of the callback:
     * * rc < 0 - socket error to be propagated to the callee (unless
     *   we have already transferred some bytes in previous iteration). As a
     *   special case, if rc == -EINTR, the callback will be retried. This
     *   allows the callback to block if necessary and then be called again to
     *   retry whatever it couldn't do the first time.
     *
     * In copy mode:
     * * new read_ptr will be last_pkt:last_pkt_bytes_read... unless
     *   no pkt has been really completed, where last_pkt_bytes_read will be
     *   added to read offset.
     *
     * In pkt reap mode:
     * * bufs_read == p->bufs_num
     *   pipe is left with no pkts of its own
     * * last_pkt_bytes_read == 0
     *   Only whole pkts before last_pkt were removed.
     *   read_ptr and potentially write_ptr need to be updated.
     * * last_pkt_bytes_read != 0
     *   means pkts preceding last pkt were taken away (if any), however
     *   last_pkt itself was not taken.  Some data was copied
     *   only read_ptr needs to be updated
     */
    rc = cb(cb_ctx, ni, p, flags, pkt, bytes_available, len,
            &last_pkt, &last_pkt_bytes_read, &bufs_read);

    if( rc <= 0 ) {
      if( rc == -EINTR )
        goto again_locked;
      if( bytes_read_total ) {
        /* As we've succeded writing some data (in previous iteration),
         * let's bail out with success despite failure this time */
        rc = bytes_read_total;
      }
      break;
     }

    bytes_read = rc;

    if( remove_buffers && bufs_read > 0 ) {
      ci_assert_ge(p->bufs_num, bufs_read);
      p->bufs_num -= bufs_read;
      if( p->bufs_num == 0 ) {
        /* no buffers left ... */
        oo_pipe_buf_clear_state(ni, p);
        last_pkt = NULL;
        ci_assert_equal(last_pkt_bytes_read, 0);
      }
      else {
        /* the buffers have been removed, lets close the pkt list cycle */
        pre_first_pkt->next = OO_PKT_P(last_pkt);
        if( write_ptr_next == OO_PKT_P(last_pkt) ) {
          /* pkt pointed by write_ptr have been removed, lets update
           * write_ptr */
          p->write_ptr.pp_wait = OO_PP_NULL;
          p->write_ptr.pp = write_ptr_next;
          oo_pipe_buf_write_init(p, last_pkt);
        }
        /* We cannot really tell whether pkt pointed by pipe_bufs.pp
         * has been removed, let's just update it. */
        p->pipe_bufs.pp = OO_PKT_P(last_pkt);
      }
    }

    bufs_read_total += bufs_read;

    bytes_read_total += bytes_read;
    bytes_available -= bytes_read;

    if( last_pkt ) {
      p->read_ptr.pp = OO_PKT_P(last_pkt);
      if( bufs_read == 0 )
        p->read_ptr.offset += last_pkt_bytes_read;
      else
        p->read_ptr.offset = last_pkt_bytes_read;

      if( bufs_read > 0 || bytes_available == 0 )
        __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_TX);

      ci_assert_le(p->read_ptr.offset, last_pkt->pf.pipe.pay_len);
    }
    /* It could block if another iteration was allowed...
     * TODO: unless we have got the clue from callback
     */
  } while( 0 );

  ci_wmb();
  p->bytes_removed += bytes_read_total;
  if( lock_stack )
    ci_netif_unlock(ni);
  ci_sock_unlock(ni, &p->b);
 out:
  LOG_PIPE("%s[%u]: EXIT return %d", __FUNCTION__, p->b.bufid, rc);
  return rc;

 wait_for_bytes:
  LOG_PIPE("%s[%u]: wait_for_bytes", __FUNCTION__, p->b.bufid);
  if( (rc = oo_pipe_read_wait(ni, p, flags & MSG_DONTWAIT)) != 1 )
     goto out;
  goto again;
}


/* Zero copy read from pipe
 *
 * Function passes an iovec listing filled buffers to the callback.
 * And read ptr is advanced by returned bytes.
 *
 * The call will block (or return EAGAIN with MSG_DONTWAIT),
 * when there is no data in the pipe,
 * or when the callback blocks.
 *
 * Callback is supposed to return number of bytes read or error (negative value)
 * The error will be passed back to the caller with errno unchanged.
 */
int ci_pipe_zc_read(ci_netif* ni, struct oo_pipe* p, int len, int flags,
                    ci_pipe_zc_read_cb cb, void* cb_ctx)
{
  struct oo_pipe_zc_read_iov_ctx ctx = {
    .cb = cb,
    .cb_ctx = cb_ctx,
  };
  int rc;
  ctx.iov = ctx.iov_on_stack;
  rc = oo_pipe_zc_read_bare(ni, p, len, flags, 0,
                            oo_pipe_zc_read_iov_cb, &ctx);
  if( ctx.iov != ctx.iov_on_stack )
    free(ctx.iov);
  return rc;
}


/* Helper function for oo_pipe_zc_move_cb. Moves as many complete buffers as
 * possible from [pipe_src] to [pipe_dest] beginning from [head], up to a
 * length of [len] bytes. It then sets [*next_pkt_out] to the subsequent buffer
 * and returns the number of bytes from that buffer remaining to be copied, or
 * negative on error. [*last_pkt_offset_out] is set to the offset at which the
 * remaining bytes in the last packet begin, and [*n_pkts_out] is set to the
 * number of buffers moved.
 */
static int
__oo_pipe_zc_move_buffers(ci_netif* ni, struct oo_pipe* pipe_src,
                          struct oo_pipe* pipe_dest, int flags, int len,
                          ci_ip_pkt_fmt* head, ci_ip_pkt_fmt** next_pkt_out,
                          int* n_pkts_out, int* last_pkt_offset_out)
{
  ci_ip_pkt_fmt* pre_tail;
  int bytes_remaining;
  int stack_locked = 1;
  struct ci_pipe_pkt_list pkts = {
    .head = head,
    .tail = head,
  };

  ci_assert(ci_netif_is_locked(ni));

  while( pipe_dest->bufs_num >= pipe_dest->bufs_max ) {
    oo_pipe_reap_empty_buffers(ni, pipe_dest, 0, NULL);
    if( pipe_dest->bufs_num >= pipe_dest->bufs_max ) {
      int rc;
      LOG_PIPE("%s[%u,%u]: still too few buffers post-reap (%d/%d)",
               __FUNCTION__, pipe_src->b.bufid, pipe_dest->b.bufid,
               pipe_dest->bufs_num, pipe_dest->bufs_max);
      if( flags & MSG_DONTWAIT )
        return -EAGAIN;
      rc = oo_pipe_wait_write(ni, pipe_dest, 0, &stack_locked);
      if( ! stack_locked ) {
        ci_netif_lock(ni);
        if( rc == 0 )
          return -EINTR;
      }
      if( rc < 0 )
        return rc;
    }
  }

  /* Begin by moving as many complete buffers from pipe_src to pipe_dest as
   * possible. */
  bytes_remaining = len + pipe_src->read_ptr.offset;
  pkts.count = oo_pipe_list_ptr_move(ni, pipe_src, &pkts.tail, &bytes_remaining,
                                     &pre_tail);
  if( bytes_remaining == pkts.tail->pf.pipe.pay_len ) {
    /* We're splicing the whole of the final buffer. */
    bytes_remaining = 0;
    *next_pkt_out = PKT_CHK(ni, oo_pipe_next_buf(pipe_src, pkts.tail));
  }
  else {
    /* We're splicing only part of the final buffer and so can't move it to
     * pipe_dest. Remove it from the list. */
    *next_pkt_out = pkts.tail;
    pkts.tail = pre_tail;
    --pkts.count;
  }

  if( pkts.tail != NULL ) {
    ci_assert_gt(pkts.count, 0);
    pkts.head->pf.pipe.pay_len -= pipe_src->read_ptr.offset;
    pkts.head->pf.pipe.base    += pipe_src->read_ptr.offset;
    oo_pipe_insert_buffers(ni, pipe_dest, &pkts);
    /* Read pointer is not pointing into the final buffer, so that buffer is to
     * be copied from its beginning. */
    *last_pkt_offset_out = 0;
  }
  else {
    /* No complete buffers to splice. */
    *last_pkt_offset_out = pipe_src->read_ptr.offset;
    bytes_remaining -= *last_pkt_offset_out;
  }

  *n_pkts_out = pkts.count;
  return bytes_remaining;
}


static int
__oo_pipe_zc_copy_last_buffer(ci_netif* ni, struct oo_pipe* pipe_src,
                              struct oo_pipe* pipe_dest, int flags,
                              ci_ip_pkt_fmt* pkt_src, int len, int offset,
                              int bytes_already_spliced)
{
  int stack_locked = 1;
  ci_uint8* write_point;
  ci_uint8* read_point;
  oo_pkt_p pp_dest_read = OO_ACCESS_ONCE(pipe_dest->read_ptr.pp);
  ci_ip_pkt_fmt* pkt_dest = OO_PP_NOT_NULL(pipe_dest->write_ptr.pp) ?
                              PKT_CHK(ni, pipe_dest->write_ptr.pp) : NULL;
  int dest_buf_space = pkt_dest != NULL ? oo_pipe_buf_space(pkt_dest) : 0;
  int first_portion = CI_MIN(dest_buf_space, len);
  int bytes_copied;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert_le(len, pkt_src->pf.pipe.pay_len - offset);

  /* The portion of the source buffer that we need to copy will straddle at
   * most two destination buffers. To start with, copy as much as will fit
   * into the current destination buffer. */
  read_point = pipe_get_point(ni, pipe_src, pkt_src, offset);
  if( dest_buf_space > 0 ) {
    pkt_dest = PKT_CHK(ni, pipe_dest->write_ptr.pp);
    write_point =
      pipe_get_point(ni, pipe_dest, pkt_dest, pkt_dest->pf.pipe.pay_len);
    do_copy_write(write_point, read_point, first_portion);
    pkt_dest->pf.pipe.pay_len += first_portion;
    len -= first_portion;
    read_point += first_portion;
    if( first_portion == dest_buf_space && pkt_dest->next == pp_dest_read )
      pipe_dest->write_ptr.pp_wait = pkt_dest->next;
  }

  bytes_copied = first_portion;

  /* If we also need to use a second destination buffer, do so. */
  if( len > 0 ) {
    if( CI_UNLIKELY(! oo_pipe_has_space(pipe_dest)) ) {
      int rc;
      LOG_PIPE("%s[%u,%u]: need more space", __FUNCTION__, pipe_src->b.bufid,
               pipe_dest->b.bufid);
      rc = oo_pipe_more_buffers(ni, pipe_dest, 0, NULL);
      /* If we failed to get more buffers for whatever reason but we've
       * already spliced some data, we can give up on the final buffer and
       * return success to the caller. */
      if( rc <= 0 && bytes_already_spliced > 0 ) {
        return bytes_copied;
      }
      /* A negative return code is a genuine allocation error and in that
       * case we should bail out right now. */
      else if( rc < 0 ) {
        return -ENOBUFS;
      }
      /* On the other hand, if the pipe's just full, we can block. */
      else if( rc == 0 ) {
        if( flags & MSG_DONTWAIT )
          return -EAGAIN;
        rc = oo_pipe_wait_write(ni, pipe_dest, 0, &stack_locked);
        if( ! stack_locked ) {
          /* Returning -EINTR will cause the zero-copy framework to call us
           * again. */
          ci_netif_lock(ni);
          stack_locked = 1;
          if( rc == 0 )
            return -EINTR;
        }
        if( rc < 0 )
          return rc;
        /* If we get here, that means that space became available while we
         * still held the lock, so we can press ahead. */
        pipe_dest->write_ptr.pp = pipe_dest->write_ptr.pp_wait;
        pipe_dest->write_ptr.pp_wait = OO_PP_NULL;
      }
    }
    else {
      pipe_dest->write_ptr.pp = pkt_dest->next;
    }

    pkt_dest = PKT_CHK(ni, pipe_dest->write_ptr.pp);
    oo_pipe_buf_write_init(pipe_dest, pkt_dest);
    write_point = pipe_get_point(ni, pipe_dest, pkt_dest, 0);
    do_copy_write(write_point, read_point, len);
    pkt_dest->pf.pipe.pay_len = len;
    bytes_copied += len;

    /* As we're copying only a portion of the buffer here, we know that the
     * destination buffer is not full and so we never need to set pp_wait. */
    ci_assert_gt(oo_pipe_buf_space(pkt_dest), 0);
  }

  return bytes_copied;
}


struct oo_pipe_zc_move_ctx {
  struct oo_pipe* pipe_dest;
};


/* Move bytes from pipe_src to pipe_dest.  User has requested transfer
 * of read_len bytes.  Number of bytes we can actually transfer is
 * min(bytes_available, read_len, pipe_dest->available_space).
 *
 * Below is a layout of what we can expect from the source pipe.
 *      0           1           2
 * |______xxx||xxxxxxxxxxx|xxxx.......|
 *
 * '|' denote buffer boundaries.
 * '_' denotes data that has already been read.
 * 'x' data that can be read.
 * '.' data that can be read but should not be copied.
 *
 *
 * The dest pipe is:
 *
 * |_______^^|
 *
 * '^' is where the write pointer is.
 *
 * To minimize copying, we terminate this buffer, move buffer 0, 1
 * from pipe_src, and copy data from buffer 2.
 *
 * N.B. The source and destination pipes are asymmetric in the sense that
 * pipe_src is managed by the zero-copy framework but pipe_dest is not, and in
 * particular we're responsible for updating all relevant state for pipe_dest
 * (but not for pipe_src).
 */

#define PIPE_TO_PIPE_SPLICE_COPY_THRESHOLD 300

static int
oo_pipe_zc_move_cb(void* c, ci_netif* ni, struct oo_pipe* pipe_src, int flags,
                   ci_ip_pkt_fmt* head, int bytes_available, int read_len,
                   ci_ip_pkt_fmt** next_pkt_out, int* next_pkt_payload_out,
                   int* n_pkts_out)
{
  struct oo_pipe_zc_move_ctx* ctx = c;
  struct oo_pipe* pipe_dest = ctx->pipe_dest;
  int last_pkt_bytes, last_pkt_offset;
  int bytes_can_move = CI_MIN(bytes_available, read_len);

  /* We assume that we never fill a buffer when copying the last portion. */
  CI_BUILD_ASSERT(PIPE_TO_PIPE_SPLICE_COPY_THRESHOLD < OO_PIPE_BUF_MAX_SIZE);

  LOG_PIPE("%s[%u,%u]: ENTER", __FUNCTION__, pipe_src->b.bufid,
           pipe_dest->b.bufid);
  pipe_dump(ni, pipe_dest);

  ci_assert(ci_netif_is_locked(ni));
  ci_assert_equal(OO_PKT_P(head), pipe_src->read_ptr.pp);

  *next_pkt_payload_out = 0;

  /* Early exit if we have nothing to splice. */
  if( bytes_can_move == 0 ) {
    *next_pkt_out = head;
    *n_pkts_out = 0;
    return 0;
  }

  /* Heuristic fall-back to single-copy for small buffers. */
  if( bytes_can_move == head->pf.pipe.pay_len - pipe_src->read_ptr.offset &&
      bytes_can_move <= PIPE_TO_PIPE_SPLICE_COPY_THRESHOLD ) {
    last_pkt_bytes = bytes_can_move;
    last_pkt_offset = pipe_src->read_ptr.offset;
    *next_pkt_out = head;
    *n_pkts_out = 0;
  }
  else {
    /* Move as many complete buffers as possible. */
    last_pkt_bytes =
      __oo_pipe_zc_move_buffers(ni, pipe_src, pipe_dest, flags, bytes_can_move,
                                head, next_pkt_out, n_pkts_out,
                                &last_pkt_offset);
    if( last_pkt_bytes < 0 )
      return last_pkt_bytes;
  }

  /* Full buffers have been spliced as far as possible. Now deal with anything
   * that might still be needed from the final buffer. */
  LOG_PIPE("%s[%u,%u]: copy %d bytes offset %d/%d", __FUNCTION__,
           pipe_src->b.bufid, pipe_dest->b.bufid, last_pkt_bytes,
           last_pkt_offset, (*next_pkt_out)->pf.pipe.pay_len);
  if( last_pkt_bytes > 0 ) {
    int bytes_copied;
    ci_assert_lt(*n_pkts_out, pipe_src->bufs_num);
    bytes_copied =
      __oo_pipe_zc_copy_last_buffer(ni, pipe_src, pipe_dest, flags,
                                    *next_pkt_out, last_pkt_bytes,
                                    last_pkt_offset,
                                    bytes_can_move - last_pkt_bytes);
    if( bytes_copied < 0 )
      return bytes_copied;
    *next_pkt_payload_out = bytes_copied;
    bytes_can_move -= last_pkt_bytes - bytes_copied;
  }

  if( bytes_can_move > 0 ) {
    ci_wmb();
    pipe_dest->bytes_added += bytes_can_move;
    __oo_pipe_wake_peer(ni, pipe_dest, CI_SB_FLAG_WAKE_RX);
  }

  return bytes_can_move;
}


int ci_pipe_zc_move(ci_netif* ni, struct oo_pipe* pipe_src,
                    struct oo_pipe* pipe_dest, int rlen, int flags)
{
  struct oo_pipe_zc_move_ctx ctx = {
    .pipe_dest = pipe_dest,
  };
  return oo_pipe_zc_read_bare(ni, pipe_src, rlen, flags,
                              OO_PIPE_ZC_READ_BARE_FLAG_LOCK_STACK |
                              OO_PIPE_ZC_READ_BARE_FLAG_REMOVE_BUFFERS,
                              oo_pipe_zc_move_cb, &ctx);
}

#endif


int ci_pipe_write(ci_netif* ni, struct oo_pipe* p,
                  const struct iovec *iov,
                  size_t iovlen)
{
  int total_bytes = 0, rc;
  int i;
  int add = 0;
  int stack_locked = 0;
  ci_ip_pkt_fmt* pkt = NULL;
  oo_pkt_p pp_read;

  ci_assert(p);
  ci_assert(ni);
  ci_assert(iov);
  ci_assert_gt(iovlen, 0);

  LOG_PIPE("%s[%u]: ENTER nonblock=%s bufs=%d wr=%d wr_wait=%d rd=%d",
           __FUNCTION__,
           p->b.bufid,
           (p->aflags &
            (CI_PFD_AFLAG_NONBLOCK << CI_PFD_AFLAG_WRITER_SHIFT)) ?
           "true" : "false",
           p->bufs_num,
           OO_PP_FMT(p->write_ptr.pp),
           OO_PP_FMT(p->write_ptr.pp_wait),
           OO_PP_FMT(p->read_ptr.pp));

  rc = ci_netif_lock(ni);
#ifdef __KERNEL__
  if( rc < 0 ) {
    CI_SET_ERROR(rc, ERESTARTSYS);
    goto out;
  }
#endif
  stack_locked = 1;

  pipe_dump(ni, p);

  if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_READER_SHIFT)) {
    /* send sigpipe: not sure if anything can be done
     * in case of failure*/
    CI_SET_ERROR(rc, EPIPE);
    oo_pipe_signal(ni);
    goto out;
  }

  pp_read = OO_ACCESS_ONCE(p->read_ptr.pp);
  for( i = 0; i < iovlen; i++ ) {
    char* start = iov[i].iov_base;
    char* end = start + iov[i].iov_len;

    for (;;) {
      ci_uint8* write_point;
      int burst;
      ci_assert(iov[i].iov_len == 0 || end - start);

      if( pkt == NULL && OO_PP_NOT_NULL(p->write_ptr.pp) )
        pkt = PKT_CHK(ni, p->write_ptr.pp);

      if( pkt != NULL && oo_pipe_buf_space(pkt) > 0 ) {
        /* There's room in this buffer, so there's nothing to do. */
      }
      else if( pkt != NULL && pkt->next != pp_read ) {
        p->write_ptr.pp_wait = OO_PP_NULL;
        p->write_ptr.pp = pkt->next;
        pkt = PKT_CHK(ni, pkt->next);
        oo_pipe_buf_write_init(p, pkt);
      }
      else
        goto out_of_space;

      LOG_PIPE("%s: ->%d+%u %d %d",
               __FUNCTION__, OO_PP_FMT(p->write_ptr.pp), pkt->pf.pipe.pay_len,
               (int)(oo_pipe_buf_space(pkt)),
               (int)(end - start));

      write_point = pipe_get_point(ni, p, pkt, pkt->pf.pipe.pay_len);
      /* don't write more than left from the buffer */
      burst = CI_MIN(oo_pipe_buf_space(pkt), end - start);

      if( burst ) {
        if(CI_UNLIKELY( do_copy_write(write_point, start, burst) != 0 )) {
          CI_SET_ERROR(rc, EFAULT);
          if( add > 0 )
            goto sent_out;
          else
            goto out;
        }

        /* local move */
        add += burst;
        start += burst;
        pkt->pf.pipe.pay_len += burst;
        ci_assert_ge(oo_pipe_buf_space(pkt), 0);

        LOG_PIPE("%s: end-start=%d burst=%d add=%d",
                 __FUNCTION__, (int)(end - start), burst, add);
      }

      if( ! ( end - start ) )
        break;

      /* Try to move to the next buffer in the pipe. */
      continue;

     out_of_space:
      /* Out of space. Try to allocate. */
      rc = oo_pipe_more_buffers(ni, p, 0, NULL);
      if( rc <= 0 ) {
        if( p->bufs_num == 0 ) {
          LOG_PIPE("%s: No buffers and failed to allocate", __FUNCTION__);
          CI_SET_ERROR(rc, ENOMEM);
          goto out;
        }
        ci_assert_nequal(pkt, NULL);
        p->write_ptr.pp_wait = pkt->next;
        if( p->aflags &
            (CI_PFD_AFLAG_NONBLOCK << CI_PFD_AFLAG_WRITER_SHIFT) ) {
          /* Since we're non-blocking, [add] is the total count of bytes we've
           * written. */
          if( add > 0 )
            goto sent_success;
          CI_SET_ERROR(rc, EAGAIN);
          goto out;
        }
      }

      /* Pipe is full and we're not non-blocking. Update totals and wait for
       * the pipe to become ready for writing. */
      total_bytes += add;
      ci_wmb();
      p->bytes_added += add;
      add = 0;

      if( total_bytes )
        __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_RX);
      rc = oo_pipe_wait_write(ni, p, 0, &stack_locked);
      if (rc != 0) {
        if( total_bytes ) {
          /* Partial write followed by failed wait is success. */
          goto sent_success;
        }
        goto out;
      }
      if( ! stack_locked ) {
        rc = ci_netif_lock(ni);
#ifdef __KERNEL__
        if( rc < 0 ) {
          CI_SET_ERROR(rc, ERESTARTSYS);
          goto out;
        }
#endif
        stack_locked = 1;
        pkt = NULL;
      }
      /* Make sure our idea of the position of the read pointer is at least as
       * recent as that which woke us up. */
      pp_read = OO_ACCESS_ONCE(p->read_ptr.pp);
    }
  }

  /* If we filled the pipe, mark it as full. */
  if( pkt != NULL && oo_pipe_buf_space(pkt) == 0 &&
      pkt->next == OO_ACCESS_ONCE(p->read_ptr.pp) )
    p->write_ptr.pp_wait = pkt->next;

 sent_success:
  rc = total_bytes + add;
 sent_out:
  if( CI_LIKELY(add > 0) ) {
    ci_assert(ci_netif_is_locked(ni));
    total_bytes += add;
    ci_wmb();
    p->bytes_added += add;
    __oo_pipe_wake_peer(ni, p, CI_SB_FLAG_WAKE_RX);
  }
 out:
  if( stack_locked )
    ci_netif_unlock(ni);
  LOG_PIPE("%s[%u]: EXIT return %d", __FUNCTION__, p->b.bufid, rc);
  return rc;
}


#if OO_DO_STACK_POLL
static void oo_pipe_free_bufs(ci_netif* ni, struct oo_pipe* p)
{
  oo_pkt_p pp = oo_pipe_buf_list_start(&p->pipe_bufs);
  oo_pkt_p pp_end = pp; /* this is circular list */
  if( ! OO_PP_NOT_NULL(pp) )
    return;
  do {
    ci_ip_pkt_fmt* pkt = PKT_CHK(ni, pp);
    pp = oo_pipe_next_buf(p, pkt);
    ci_netif_pkt_release(ni, pkt);
  } while( pp != pp_end );
}


static void oo_pipe_free(ci_netif* ni, struct oo_pipe* p)
{
  ci_assert(ci_netif_is_locked(ni));

  LOG_PIPE("%s: free pipe waitable id=%d", __FUNCTION__,
           p->b.bufid);
  /* fixme kostik: no async ops */

  citp_waitable_obj_free(ni, &p->b);
}


void ci_pipe_all_fds_gone(ci_netif* ni, struct oo_pipe* p, int do_free)
{
  ci_assert(p);
  ci_assert(ni);
  ci_assert(ci_netif_is_locked(ni));
  ci_assert(do_free); /* do_free==0 in case of handover; it is not for pipe */

  pipe_dump(ni, p);

  oo_pipe_free_bufs(ni, p);
  oo_pipe_free(ni, p);

  LOG_PIPE("%s: done", __FUNCTION__);
}
#endif


#ifndef __KERNEL__
int ci_pipe_set_size(ci_netif* ni, struct oo_pipe* pipe, size_t size)
{
  int bufs = OO_PIPE_SIZE_TO_BUFS(size);

  /* The case in which a pipe is not allowed to exceed a single buffer is not
   * compatible with the mechanism for detecting whether a pipe is writable. */
  CI_BUILD_ASSERT(OO_PIPE_MIN_BUFS > 1);

  if( bufs < OO_PIPE_MIN_BUFS || bufs > OO_PIPE_MAX_BUFS)
    return -EINVAL;

  ci_netif_lock(ni);

  /* We get rid of empty buffers in case the shrinkage is requested.
   * When pages are in use this might not take (full) effect. */
  if( bufs < pipe->bufs_num )
    oo_pipe_reap_empty_buffers(ni, pipe, 0, NULL);

  if( pipe->bufs_num > bufs ) {
    ci_netif_unlock(ni);
    return -EBUSY;
  }
  pipe->bufs_max = bufs;

  ci_netif_unlock(ni);

  return 0;
}

#endif


void oo_pipe_dump(ci_netif* ni, struct oo_pipe* p, const char* pf,
                  oo_dump_log_fn_t logger, void* log_arg)
{
  logger(log_arg, "%s  read_p=%d:%u bytes=%u flags=%x", pf,
         OO_PP_FMT(p->read_ptr.pp), p->read_ptr.offset, p->bytes_removed,
         (p->aflags & CI_PFD_AFLAG_READER_MASK ) >> CI_PFD_AFLAG_READER_SHIFT);
  logger(log_arg, "%s  writ_p=%d:%u bytes=%u flags=%x", pf,
         OO_PP_FMT(p->write_ptr.pp),
         OO_PP_NOT_NULL(p->write_ptr.pp) ?
           PKT_CHK(ni, p->write_ptr.pp)->pf.pipe.pay_len : 0,
         p->bytes_added,
         (p->aflags & CI_PFD_AFLAG_WRITER_MASK ) >> CI_PFD_AFLAG_WRITER_SHIFT);
  logger(log_arg, "%s  num_bufs=%d/%d", pf, p->bufs_num, p->bufs_max);
}

