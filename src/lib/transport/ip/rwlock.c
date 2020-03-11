/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#include <onload/ul/rwlock.h>

/* Should be called with p->l->mutex locked */
static void rwlock_not_reading(struct oo_rwlock_perthread *p)
{
  p->next->prev = p->prev;
  p->prev->next = p->next;
  p->l->val--;
}

/* Unmark the current thread as "reading" thread.
 * Should be called for current thread only. */
void rwlock_stop_read(struct oo_rwlock_perthread *p)
{
  ci_uint32 flags;
  int locked = 0;

  do {
    flags = p->flags;
    if( ~flags & OO_RWLOCK_KEY_IS_READER ) {
      if( locked )
        CI_TRY( pthread_mutex_unlock(&p->l->mutex) );
      return;
    }
    if( ! locked ) {
      CI_TRY( pthread_mutex_lock(&p->l->mutex) );
      locked = 1;
    }
  } while( ci_cas32u_fail(&p->flags, flags,
                          flags &~ OO_RWLOCK_KEY_IS_READER) );

  rwlock_not_reading(p);
  if( p->l->val == OO_RWLOCK_VAL_WRITER )
    pthread_cond_broadcast(&p->l->cond);
  CI_TRY( pthread_mutex_unlock(&p->l->mutex) );
}

/* Callback for pthread_key_create: destroy per-thread data, tell the world
 * that we are not in the read-critical section any more. */
void rwlock_perthread_dtor(void *data)
{
  struct oo_rwlock_perthread *p = data;

  CI_TRY(pthread_setspecific(p->l->key, NULL));

  if( p->flags & OO_RWLOCK_KEY_READING_NOW ) {
    /* Something is terribly wrong: we think that we are reading _now_. */
    ci_log("%s: exit from a thread while holding read lock", __func__);
  }

  /* If we've declared ourself as a reader, we should decrement
   * l->val and get out from the thread list. */
  if( p->flags & OO_RWLOCK_KEY_IS_READER )
    rwlock_stop_read(p);

  free(p);
}

/* Try to mark the current thread as "reading" thread.
 * Should be called with p->l->mutex locked. */
int rwlock_try_start_read(struct oo_rwlock_perthread *p)
{
  ci_uint32 flags;

  ci_assert(~p->flags & OO_RWLOCK_KEY_IS_READER);

  /* A writer is here - readers, go away! */
  if( p->l->val & OO_RWLOCK_VAL_WRITER )
    return 0;

  do {
    flags = p->flags;
    /* Only this thread may set flags */
    ci_assert( ~flags & OO_RWLOCK_KEY_IS_READER );
    ci_assert( ~flags & OO_RWLOCK_KEY_READING_NOW );
  } while( ci_cas32u_fail(&p->flags, flags,
                          flags
                          | OO_RWLOCK_KEY_IS_READER
                          | OO_RWLOCK_KEY_READING_NOW) );
  p->l->thread_head.next->prev = p;
  p->next = p->l->thread_head.next;
  p->l->thread_head.next = p;
  p->prev = &p->l->thread_head;

  p->l->val++;
  return 1;
}

/* Clear up all readers which are not reading now.
 * Should be called with l->mutex locked.*/
void rwlock_clear_readers(oo_rwlock *l)
{
  struct oo_rwlock_perthread *p;
  ci_uint32 flags;

  /* The loop modifies the list, but as long as we hold p->mutex we can
   * safely use p->next link. */
  for( p = l->thread_head.next; p != &l->thread_head; p = p->next ) {
    ci_assert(p->flags & OO_RWLOCK_KEY_IS_READER );
    do {
      flags = p->flags;
      if( flags & OO_RWLOCK_KEY_READING_NOW )
        break;
    } while( ci_cas32u_fail(&p->flags, flags,
                            flags &~ OO_RWLOCK_KEY_IS_READER) );
    if( ~flags & OO_RWLOCK_KEY_READING_NOW )
      rwlock_not_reading(p);
  }

  /* Wake up any writers if we've purged all readers, so they can make
   * some progress toward taking the real write lock. */
  if( l->val == OO_RWLOCK_VAL_WRITER )
    pthread_cond_broadcast(&l->cond);
}

/* Decrements the number of writers and wakes up readers if necessary.
 * Returns unlocked. */
void rwlock_writers_dec(oo_rwlock *l, int locked)
{
  ci_uint64 tmp;

  /* OO_RWLOCK_VAL_WRITER is always set before the writers counter is
   * incremented, so the bit must be here now. */
  ci_assert(l->val & OO_RWLOCK_VAL_WRITER);

  do {
    tmp = l->writers;
    ci_assert(tmp);
    if( tmp == 1 ) {
      if( ! locked )
        CI_TRY( pthread_mutex_lock(&l->mutex) );
      locked = 1;
    }
    else if( locked ) {
      CI_TRY( pthread_mutex_unlock(&l->mutex) );
      locked = 0;
    }
  } while( ci_cas64u_fail(&l->writers, tmp, tmp - 1) );
  ci_assert_equiv(locked, tmp == 1);

  /* If there are other writers, they are probably waiting for write_lock.
   * No need for any special wake up. */
  if( !locked)
    return;

  /* The last writer is gone.  We should remove the OO_RWLOCK_VAL_WRITER
   * bit and wake up any readers. */
  ci_assert(l->val & OO_RWLOCK_VAL_WRITER);
  l->val &=~ OO_RWLOCK_VAL_WRITER;
  pthread_cond_broadcast(&l->cond);
  CI_TRY( pthread_mutex_unlock(&l->mutex) );
}

