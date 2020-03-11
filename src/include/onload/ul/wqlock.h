/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file wqlock.c
** <L5_PRIVATE L5_HEADER >
** \author  David Riddoch <driddoch@solarflare.com>
**  \brief  oo_wqlock interface.
**   \date  2012/01/09
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_UL_WQLOCK_H__
#define __ONLOAD_UL_WQLOCK_H__

#include <ci/tools.h>
#include <stdint.h>
#include <pthread.h>


#define OO_WQLOCK_LOCKED     ((uintptr_t) 0x1)
#define OO_WQLOCK_NEED_WAKE  ((uintptr_t) 0x2)

#define OO_WQLOCK_LOCK_BITS  ((uintptr_t) 0x3)
#define OO_WQLOCK_WORK_BITS  (~OO_WQLOCK_LOCK_BITS)


struct oo_wqlock {
  volatile uintptr_t  lock;
  pthread_mutex_t     mutex;
  pthread_cond_t      cond;
};

struct oo_wqlock_work {
  void (*fn)(struct oo_wqlock_work* work, void* unlock_param);
  struct oo_wqlock_work* next;
};

extern void oo_wqlock_init(struct oo_wqlock* wql);

void oo_wqlock_work_do(struct oo_wqlock_work* work_list, void *unlock_param);

extern void oo_wqlock_lock_slow(struct oo_wqlock* wql) CI_HF;

extern void oo_wqlock_unlock_slow(struct oo_wqlock* wql,
                                  void* unlock_param) CI_HF;

static inline int oo_wqlock_is_locked(struct oo_wqlock* wql)
{
  return wql->lock & OO_WQLOCK_LOCKED;
}

static inline int oo_wqlock_try_lock(struct oo_wqlock* wql)
{
  return wql->lock == 0 &&
    ci_cas_uintptr_succeed(&wql->lock, 0, OO_WQLOCK_LOCKED);
}


static inline int oo_wqlock_try_queue(struct oo_wqlock* wql,
                                      struct oo_wqlock_work* work)
{
  uintptr_t new_v, v = wql->lock;
  if( v & OO_WQLOCK_LOCKED ) {
    work->next = (void*) (v & OO_WQLOCK_WORK_BITS);
    new_v = (v & OO_WQLOCK_LOCK_BITS) | (uintptr_t) work;
    if( ci_cas_uintptr_succeed(&wql->lock, v, new_v) )
      return 1;
  }
  return 0;
}


static inline void oo_wqlock_lock(struct oo_wqlock* wql)
{
  if( wql->lock == 0 &&
      ci_cas_uintptr_succeed(&wql->lock, 0, OO_WQLOCK_LOCKED) )
    return;
  oo_wqlock_lock_slow(wql);
}


static inline int oo_wqlock_lock_or_queue(struct oo_wqlock* wql,
                                          struct oo_wqlock_work* work)
{
  while( 1 )
    if( oo_wqlock_try_queue(wql, work) )
      return 0;
    else if( oo_wqlock_try_lock(wql) )
      return 1;
}


static inline void oo_wqlock_try_drain_work(struct oo_wqlock* wql,
                                            void* unlock_param)
{
  uintptr_t v = wql->lock;
  ci_assert((v & OO_WQLOCK_LOCKED) || !(v & OO_WQLOCK_WORK_BITS));
  if( v & OO_WQLOCK_WORK_BITS ) {
    if( ci_cas_uintptr_succeed(&wql->lock, v, v & OO_WQLOCK_LOCK_BITS) )
      oo_wqlock_work_do((void*) (v & OO_WQLOCK_WORK_BITS), unlock_param);
    /* the queued jobs should not unlock the wqlock: */
    ci_assert(oo_wqlock_is_locked(wql));
  }
}


static inline void oo_wqlock_unlock(struct oo_wqlock* wql,
                                    void* unlock_param)
{
  if( wql->lock == OO_WQLOCK_LOCKED &&
      ci_cas_uintptr_succeed(&wql->lock, OO_WQLOCK_LOCKED, 0) )
    return;
  oo_wqlock_unlock_slow(wql, unlock_param);
}

#endif  /* __ONLOAD_UL_WQLOCK_H__ */
