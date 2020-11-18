/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2005/01/29
** Description: Code related to blocking.
** </L5_PRIVATE>
\**************************************************************************/

#include <onload/debug.h>
#include <onload/tcp_helper_fns.h>


/**********************************************************************
************************* Blocking on a socket ************************
**********************************************************************/

ci_inline int
sock_sleep__on_wakeup(ci_waiter_t* waiter, void* opaque_trs,
		    void* opaque_op, int rc, ci_waitable_timeout_t timeout)
{
  tcp_helper_resource_t* trs = (tcp_helper_resource_t*) opaque_trs;
  oo_tcp_sock_sleep_t* op = (oo_tcp_sock_sleep_t*) opaque_op;
  tcp_helper_endpoint_t* ep = ci_trs_ep_get(trs, op->sock_id);

  if( rc == -ETIMEDOUT )  rc = -EAGAIN;

  ci_waiter_post(waiter, &ep->waitq);

  if( rc == 0 && (op->lock_flags & CI_SLEEP_NETIF_RQ) )
    if( trs->netif.state->lock.lock & CI_EPLOCK_LOCKED ) {
      rc = efab_eplock_lock_wait(&trs->netif, 0);
      rc = CI_WAITER_CONVERT_REENTRANT(rc);
    }

  if( rc == 0 && (op->lock_flags & CI_SLEEP_SOCK_RQ) ) {
    citp_waitable* w = SP_TO_WAITABLE(&trs->netif, ep->id);
    if( w->lock.wl_val & OO_WAITABLE_LK_LOCKED ) {
      rc = efab_tcp_helper_sock_lock_slow(trs, op->sock_id);
      rc = CI_WAITER_CONVERT_REENTRANT(rc);
    }
  }
  if( op->timeout_ms ) {
    op->timeout_ms = jiffies_to_msecs(timeout);
    if( op->timeout_ms == 0 )
      rc = -EAGAIN;
  }
  return rc;
}


ci_inline ci_int32 my_get_user(ci_int32* p)
{
  ci_int32 tmp;
  get_user(tmp, p);
  return tmp;
}


int
efab_tcp_helper_sock_sleep(tcp_helper_resource_t* trs, 
                           oo_tcp_sock_sleep_t* op)
{
  tcp_helper_endpoint_t* ep;
  ci_netif* ni = &trs->netif;
  struct oo_signal_common_state* sts;
  citp_waitable* w;
  ci_waitable_timeout_t  timeout;
  ci_waiter_t waiter;
  int rc;

  if( ! IS_VALID_SOCK_P(ni, op->sock_id) ) {
    CI_DEBUG(ci_log("%s: bad sock_id=%d",
                    __FUNCTION__, OO_SP_FMT(op->sock_id)));
    return -EINVAL;
  }
  ep = ci_trs_ep_get(trs, op->sock_id);
  w = SP_TO_WAITABLE(ni, ep->id);

  /* NB. We have to clear lock_flags bits so that we don't try to drop
   * locks again if we're reentered due to ERESTARTSYS.
   * To make it work, we have to copy op back to user in
   * oo_fop_unlocked_ioctl().
   */
#if ! CI_CFG_UL_INTERRUPT_HELPER
  if( op->lock_flags & CI_SLEEP_NETIF_LOCKED ) {
    ci_netif_unlock(ni);
    op->lock_flags &=~ CI_SLEEP_NETIF_LOCKED;
  }
#endif
  if( op->lock_flags & CI_SLEEP_SOCK_LOCKED ) {
    ci_sock_unlock(ni, w);
    op->lock_flags &=~ CI_SLEEP_SOCK_LOCKED;
  }

  /* Now that we've dropped locks, "exit" the intercept library.  If any
   * signal handlers need to run, we return immediately.
   */
  sts = CI_USER_PTR_GET(op->sig_state);
  if( sts && my_get_user(&sts->inside_lib) ) {
    put_user(0, &sts->inside_lib);
    ci_compiler_barrier();
    if( my_get_user(&sts->aflags) & OO_SIGNAL_FLAG_HAVE_PENDING )
      return -EBUSY;
  }

  /* Put ourselves on the wait queue to avoid races. */
  rc = ci_waiter_pre(&waiter, &ep->waitq);
  if( rc )  return rc;

  /* Set [wake_needed] so stack knows to wake us up. */
  if( op->why & CI_SB_FLAG_WAKE_RX )
    ci_bit_set(&w->wake_request, CI_SB_FLAG_WAKE_RX_B);
  if( op->why & CI_SB_FLAG_WAKE_TX )
    ci_bit_set(&w->wake_request, CI_SB_FLAG_WAKE_TX_B);

  if( w->sleep_seq.all != op->sleep_seq ) {
    ci_waiter_dont_wait(&waiter, &ep->waitq);
    return 0;
  }

  ci_waitable_init_timeout_from_ms(&timeout, op->timeout_ms);

  if( ! ci_netif_is_spinner(ni) ) {
    CITP_STATS_NETIF(++trs->netif.state->stats.sock_sleep_primes);
    tcp_helper_request_wakeup(trs);
#if ! CI_CFG_UL_INTERRUPT_HELPER
    tcp_helper_request_timer(trs);
#endif
    ci_frc64(&ni->state->last_sleep_frc);
  }

  CITP_STATS_NETIF(++trs->netif.state->stats.sock_sleeps);

  return ci_waiter_wait(&waiter, &ep->waitq, &timeout, trs, op,
			sock_sleep__on_wakeup);
}


/**********************************************************************
*********************** Waiting for pkt buffers ***********************
**********************************************************************/

int efab_tcp_helper_pkt_wait(tcp_helper_resource_t* trs,
                             int* lock_flags)
{
  /* TODO: [lock_flags] is no longer used.  Should be removed. */

  ci_netif* ni = &trs->netif;
  wait_queue_entry_t wait;
  int rc;
  ci_uint64 l;

  init_waitqueue_entry(&wait, current);
  add_wait_queue(&trs->pkt_waitq, &wait);

  while( 1 ) {
    set_current_state(TASK_INTERRUPTIBLE);
    if( ci_netif_pkt_tx_can_alloc_now(ni) ) {
      rc = 0;
      break;
    }
    if( ! ((l = ni->state->lock.lock) & CI_EPLOCK_NETIF_IS_PKT_WAITER) )
      if( ci_cas64u_fail(&ni->state->lock.lock, l,
                         l | CI_EPLOCK_NETIF_IS_PKT_WAITER) )
        continue;
    CITP_STATS_NETIF_INC(&trs->netif, pkt_wait_primes);
    tcp_helper_request_wakeup(trs);
    schedule();
    if( signal_pending(current) ) {
      rc = -ERESTARTSYS;
      break;
    }
  }

  remove_wait_queue(&trs->pkt_waitq, &wait);
  set_current_state(TASK_RUNNING);
  return rc;
}


/**********************************************************************
************************** Per-socket locks ***************************
**********************************************************************/

static int efab_tcp_helper_sock_is_unlocked_or_request_wake(
				    tcp_helper_resource_t* trs, oo_sp sock_id)
{
  citp_waitable* w;
  unsigned l;

  /* Calling code must have validated [sock_id]. */
  ci_assert(IS_VALID_SOCK_P(&trs->netif, sock_id));

  w = SP_TO_WAITABLE(&trs->netif, sock_id);

  while( ! ((l = w->lock.wl_val) & OO_WAITABLE_LK_NEED_WAKE) ) {
    if( l & OO_WAITABLE_LK_LOCKED ) {
      /* Its locked...so set the wakeup flag. */
      if( ci_cas32u_succeed(&w->lock.wl_val, l, l | OO_WAITABLE_LK_NEED_WAKE) )
	return 1;
    }
    else if( ! (l & OO_WAITABLE_LK_LOCKED) ) {
      return 0;
    }
    else {
      OO_DEBUG_ERR(ci_log("%s: socket lock %d:%d corrupted (%x)", __FUNCTION__,
                          NI_ID(&trs->netif), OO_SP_FMT(sock_id), l));
      return -EIO;
    }
  }

  return 1;
}


ci_inline int sock_lock__on_wakeup(ci_waiter_t* waiter, void* opaque_trs,
				   void* opaque_sock_id, int rc,
				   ci_waitable_timeout_t timeout)
{
  tcp_helper_resource_t* trs = (tcp_helper_resource_t*) opaque_trs;
  unsigned sock_id = (unsigned) (ci_uintptr_t) opaque_sock_id;
  oo_sp sockp = OO_SP_FROM_INT(&trs->netif, sock_id);

  if( rc == 0 ) {
    ci_waiter_prepare_continue_to_wait(waiter, TCP_HELPER_WAITQ(trs, sockp));
    rc = efab_tcp_helper_sock_is_unlocked_or_request_wake(trs, sockp);
    if( rc > 0 ) {
      CITP_STATS_NETIF(++trs->netif.state->stats.sock_lock_sleeps);
      return CI_WAITER_CONTINUE_TO_WAIT;
    }
    ci_waiter_dont_continue_to_wait(waiter, TCP_HELPER_WAITQ(trs, sockp));
  }

  ci_waiter_post(waiter, TCP_HELPER_WAITQ(trs, sockp));

  /* NB. We don't need to reset NEED_WAKE, because all waiters are woken.
  ** We'll need to change this if we ever use wakeone here.  (In that case
  ** testing where the waitqueue is still active may be one solution).
  */
  return rc;
}


int efab_tcp_helper_sock_lock_slow(tcp_helper_resource_t* trs, oo_sp sock_id)
{
  ci_waiter_t waiter;
  ci_waitable_t* wq;
  int rc;

  if( ! IS_VALID_SOCK_P(&trs->netif, sock_id) )  return -EINVAL;

  /* Put ourselves on the wait queue to avoid races. */
  wq = TCP_HELPER_WAITQ(trs, sock_id);
  rc = ci_waiter_pre(&waiter, wq);
  if( rc < 0 )  return rc;

  rc = efab_tcp_helper_sock_is_unlocked_or_request_wake(trs, sock_id);
  if( rc <= 0 ) {
    ci_waiter_dont_wait(&waiter, wq);
    return rc;
  }
  CITP_STATS_NETIF(++trs->netif.state->stats.sock_lock_sleeps);
  return ci_waiter_wait(&waiter, wq, NULL, trs,
                        (void*)(ci_uintptr_t) OO_SP_TO_INT(sock_id),
			 sock_lock__on_wakeup);
}


void efab_tcp_helper_sock_unlock_slow(tcp_helper_resource_t*trs, oo_sp sock_id)
{
  citp_waitable* w;
  int l;

  if(CI_UNLIKELY( ! IS_VALID_SOCK_P(&trs->netif, sock_id) )) {
    LOG_E(ci_log("%s: bad sock_id=%d", __FUNCTION__, OO_SP_FMT(sock_id)));
    return;
  }

  w = SP_TO_WAITABLE(&trs->netif, sock_id);

 again:
  l = w->lock.wl_val;
  if( ci_cas32_fail(&w->lock.wl_val, l,
                    l & ~(OO_WAITABLE_LK_LOCKED | OO_WAITABLE_LK_NEED_WAKE)) )
    goto again;
  if( l & OO_WAITABLE_LK_NEED_WAKE )
    ci_waitable_wakeup_all(TCP_HELPER_WAITQ(trs, sock_id));
}

/*! \cidoxg_end */
