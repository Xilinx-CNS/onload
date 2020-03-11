/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file wqlock.c
** <L5_PRIVATE L5_HEADER >
** \author  David Riddoch <driddoch@solarflare.com>
**  \brief  Implementation of oo_wqlock.
**   \date  2012/01/10
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <onload/ul/wqlock.h>


void oo_wqlock_init(struct oo_wqlock* wql)
{
  wql->lock = 0;
  pthread_mutex_init(&wql->mutex, NULL);
  pthread_cond_init(&wql->cond, NULL);
}

void oo_wqlock_work_do(struct oo_wqlock_work* work_list, void *unlock_param)
{
  struct oo_wqlock_work* work;
  struct oo_wqlock_work* work_rev = NULL;

  /* Reverse the list */
  do {
    work = work_list;
    work_list = work->next;
    work->next = work_rev;
    work_rev = work;
  } while( work_list != NULL );

  do {
    work = work_rev;
    work_rev = work->next;
    /* work->fn() call can free the "work" structure or spoil it in any
     * other way, so we save work->next pointer above. */
    work->fn(work, unlock_param);
  } while( work_rev != NULL );
}

void oo_wqlock_lock_slow(struct oo_wqlock* wql)
{
  pthread_mutex_lock(&wql->mutex);
  while( 1 ) {
    uintptr_t v = wql->lock;
    if( v == 0 ) {
      if( ci_cas_uintptr_succeed(&wql->lock, 0, OO_WQLOCK_LOCKED) )
        break;
    }
    else {
      if( ! (v & OO_WQLOCK_NEED_WAKE) )
        ci_cas_uintptr_succeed(&wql->lock, v, v | OO_WQLOCK_NEED_WAKE);
      else
        pthread_cond_wait(&wql->cond, &wql->mutex);
    }
  }
  pthread_mutex_unlock(&wql->mutex);
}


void oo_wqlock_unlock_slow(struct oo_wqlock* wql,
                           void* unlock_param)
{
  uintptr_t v;
  while( 1 ) {
    v = wql->lock;
    ci_assert(v & OO_WQLOCK_LOCKED);
    if( (v & OO_WQLOCK_WORK_BITS) == 0 )
      if( ci_cas_uintptr_succeed(&wql->lock, v, 0) )
        break;
    oo_wqlock_try_drain_work(wql, unlock_param);
  }
  if( v & OO_WQLOCK_NEED_WAKE ) {
    /* See bug 66816 for some details of interlocking here. */
    /* If someone has set NEED_WAKE, we need to get the lock to ensure that
     * he is sleeping in cond_wait(). */
    pthread_mutex_lock(&wql->mutex);
    /* But now we can unlock for the sake of performance: unlock+broadcast
     * is faster than broadcast+unlock. */
    pthread_mutex_unlock(&wql->mutex);
    /* Anybody can enter critical section now, but we do not care to wake
     * them because wql->lock have been set to 0 by us, and he can get the
     * lock. */
    pthread_cond_broadcast(&wql->cond);
  }
}
