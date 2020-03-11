/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  gel
**  \brief  Low-overhead un-shared user-space reader-writer locks.
**   \date  2004/01/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_ul */
#ifndef __ONLOAD_UL_RWLOCK_H__
#define __ONLOAD_UL_RWLOCK_H__


#include <ci/tools.h>
#include <pthread.h>


struct oo_rwlock_perthread {
  /* linked list pointer */
  struct oo_rwlock_perthread *prev;
  struct oo_rwlock_perthread *next;

  /* Reader flags, to be changed atomically. */
  volatile ci_uint32 flags;
  /* IS_READER flag can be set by this thread and removed by anybody;
   * remover should hold the l->mutex. */
#define OO_RWLOCK_KEY_IS_READER   1
  /* READING_NOW flag can be changed by this thread only */
#define OO_RWLOCK_KEY_READING_NOW 2

  /* the key we belong to */
  struct oo_rwlock *l;
};

typedef struct oo_rwlock {
  /* val is number of readers | writer flag.
   * Number of readers is the number of threads registered in the
   * thread_head below; some of them can be reading just now, others are
   * not reading.
   * Writer flag is set when a writer is working or pending.
   * The val must be updated under mutex only. */
  volatile ci_uint64 val;
  /* Some writer is pending or working.  We assume that the number of
   * reader threads fit in the rest 63 bits. */
#define OO_RWLOCK_VAL_WRITER  0x8000000000000000ULL

  /* Number of writers pending, changed atomically.
   * May be set to 0 under the mutex only. */
  volatile ci_uint64 writers;

  /* A sleeper sleeps here: */
  pthread_cond_t  cond;
  /* The mutex protects internal integrity of oo_rwlock structure.
   * It should be taken for short periods of time only; i.e. all functions
   * from external API should enter and exit unlocked. */
  pthread_mutex_t mutex;

  /* Writer lock: get it to become the writer in action. */
  pthread_mutex_t write_lock;

  /* Per-thread storage. */
  pthread_key_t key;

  /* Linked list of the reader threads. */
  struct oo_rwlock_perthread thread_head;
} oo_rwlock;


extern void rwlock_perthread_dtor(void *data);
extern int rwlock_try_start_read(struct oo_rwlock_perthread *p);
extern void rwlock_stop_read(struct oo_rwlock_perthread *p);
extern void rwlock_writers_dec(oo_rwlock *l, int locked);
extern void rwlock_clear_readers(oo_rwlock *l);


/* Get per-thread data for this lock. */
ci_inline struct oo_rwlock_perthread *oo_rwlock_perthread_get(oo_rwlock *l)
{
  struct oo_rwlock_perthread *p;

  p = pthread_getspecific(l->key);
  if( p != NULL )
    return p;

  p = calloc(sizeof(struct oo_rwlock_perthread), 1);
  p->l = l;
  CI_TRY(pthread_setspecific(l->key, p));
  return p;
}

#if 0
/* Very useful for debugging rwlock itself, but probably not needed
 * otherwise. */
ci_inline void rwlock_state_dump(oo_rwlock *l, const char *func, int line)
{
  struct oo_rwlock_perthread *p = pthread_getspecific(l->key);
  unsigned long long readers;

  ci_log("%s %d: lock %p thread %p key_specific %p",
         func, line, l, (void *)pthread_self(), p);
  ci_log("reader threads=%lld pending writers=%lld (writer flag %s)",
         (unsigned long long)l->val &~ OO_RWLOCK_VAL_WRITER,
         (unsigned long long)l->writers,
         l->val & OO_RWLOCK_VAL_WRITER ? "on" : "off");
  if( p != NULL ) {
    ci_log("this thread is %sa reader, %sreading now",
           p->flags & OO_RWLOCK_KEY_IS_READER ? "" : "not ",
           p->flags & OO_RWLOCK_KEY_READING_NOW ? "" : "not ");
  }

  /* All the assertions are incorrect because we should take the lock. */
  for( readers = 0, p = l->thread_head.next;
       p != &l->thread_head;
       readers++, p = p->next ) {
    ci_assert(p->flags & OO_RWLOCK_KEY_IS_READER);
    ci_log("reader %lld: %p %sreading now", readers, p,
           p->flags & OO_RWLOCK_KEY_READING_NOW ? "" : "not ");
  }
  ci_assert_equal(readers, l->val &~ OO_RWLOCK_VAL_WRITER);
}
#define RWLOCK_DUMP_STATE(l) rwlock_state_dump(l, __func__, __LINE__)
#endif


ci_inline int oo_rwlock_ctor(oo_rwlock *l)
{
  l->val = 0;
  l->writers = 0;
  l->thread_head.next = &l->thread_head;
  l->thread_head.prev = &l->thread_head;
  CI_TRY( pthread_mutex_init(&l->write_lock, NULL) );
  CI_TRY( pthread_cond_init(&l->cond, NULL) );
  CI_TRY( pthread_mutex_init(&l->mutex, NULL) );
  CI_TRY( pthread_key_create(&l->key, rwlock_perthread_dtor) );
  return 0;
}
ci_inline void oo_rwlock_dtor(oo_rwlock *l)
{
  CI_TRY( pthread_mutex_destroy(&l->write_lock) );
  CI_TRY( pthread_cond_destroy(&l->cond) );
  CI_TRY( pthread_mutex_destroy(&l->mutex) );
  CI_TRY( pthread_key_delete(l->key) );
}


ci_inline int oo_rwlock_try_read(oo_rwlock *l)
{
  ci_uint32 flags;
  struct oo_rwlock_perthread *p = oo_rwlock_perthread_get(l);

  do {
    flags = p->flags;
    if( ~flags & OO_RWLOCK_KEY_IS_READER ) {
      int rc;
      CI_TRY( pthread_mutex_lock(&p->l->mutex) );
      rc = rwlock_try_start_read(p);
      CI_TRY( pthread_mutex_unlock(&p->l->mutex) );
      return rc;
    }
  } while( ci_cas32u_fail(&p->flags, flags,
                          flags | OO_RWLOCK_KEY_READING_NOW) );
  return 1;
}

ci_inline void oo_rwlock_lock_read(oo_rwlock *l)
{
  ci_uint32 flags;
  struct oo_rwlock_perthread *p = oo_rwlock_perthread_get(l);

  do {
    flags = p->flags;
    if( ~flags & OO_RWLOCK_KEY_IS_READER ) {
      CI_TRY( pthread_mutex_lock(&p->l->mutex) );
      while( ! rwlock_try_start_read(p) )
        pthread_cond_wait(&l->cond, &l->mutex);
      CI_TRY( pthread_mutex_unlock(&p->l->mutex) );
      return;
    }
  } while( ci_cas32u_fail(&p->flags, flags,
                          flags | OO_RWLOCK_KEY_READING_NOW) );
}

ci_inline void oo_rwlock_unlock_read(oo_rwlock *l)
{
  ci_uint32 flags;
  struct oo_rwlock_perthread *p = oo_rwlock_perthread_get(l);

  do {
    flags = p->flags;
    ci_assert_equal(
      flags & (OO_RWLOCK_KEY_IS_READER | OO_RWLOCK_KEY_READING_NOW),
      OO_RWLOCK_KEY_IS_READER | OO_RWLOCK_KEY_READING_NOW
      );
  } while( ci_cas32u_fail(&p->flags, flags,
                          flags &~ OO_RWLOCK_KEY_READING_NOW) );

  /* See comment in oo_rwlock_lock_write for why this barrier is needed */
  ci_mb();

  /* If there is a writer pending and we are the last reader,
   * we should wake him up. */
  if( l->val & OO_RWLOCK_VAL_WRITER )
    rwlock_stop_read(p);
}


ci_inline int oo_rwlock_try_write(oo_rwlock *l)
{
  ci_assert( ~oo_rwlock_perthread_get(l)->flags & OO_RWLOCK_KEY_READING_NOW );

  /* Announce the existance of a writer */
  do {
    if( l->writers != 0 )
      return 0;
  } while( ci_cas64u_fail(&l->writers, 0, 1) );

  /* Try to purge any readers and annonce a writer in val. */
  CI_TRY( pthread_mutex_lock(&l->mutex) );
  l->val |= OO_RWLOCK_VAL_WRITER;
  if( l->val != OO_RWLOCK_VAL_WRITER) {
    rwlock_clear_readers(l);
    if( l->val != OO_RWLOCK_VAL_WRITER ) {
      /* rwlock_writers_dec unlocks l->mutex */
      rwlock_writers_dec(l, 1);
      return 0;
    }
  }
  ci_assert_equal(l->val, 0);
  CI_TRY( pthread_mutex_unlock(&l->mutex) );

  /* We've pushed all readers out - let's get the write lock */
  if( pthread_mutex_trylock(&l->write_lock) == 0 )
    return 1;

  /* No luck.  Back off and return. */
  rwlock_writers_dec(l, 0);
  return 0;
}

ci_inline void oo_rwlock_lock_write(oo_rwlock* l)
{
  ci_uint64 tmp;

  ci_assert( ~oo_rwlock_perthread_get(l)->flags & OO_RWLOCK_KEY_READING_NOW );

  /* Announce the existance of a writer */
  do {
    tmp = l->writers;
  } while( ci_cas64u_fail(&l->writers, tmp, tmp + 1) );

  /* Annonce the writer in val */
  CI_TRY( pthread_mutex_lock(&l->mutex) );
  l->val |= OO_RWLOCK_VAL_WRITER;

  /* We can only write once all readers are gone.  We will try and clear
   * inactive readers below, but if there's someone still reading we need to
   * wait for them to complete, when we'll be woken.  The reader unlock will
   * test l->val for the presence of a writer after setting itself inactive,
   * and wake up any waiting writers.
   *
   * This is effectively:
   *
   * writer:
   * A set l->val writer flag
   * B read per-thread read state
   *
   * reader:
   * X set per-thread read state
   * Y read l->val writer flag
   *
   * This requires a memory barrier in both oo_rwlock_unlock_read and here, as
   * re-ordering of either of these can cause problems:
   * BXYA
   * YABX
   */
  ci_mb();

  if( l->val != OO_RWLOCK_VAL_WRITER ) {
    rwlock_clear_readers(l);

    /* We have a guarantee that there will be no new readers.  Let's wait for
     * existing readers to exit. */
    while( l->val != OO_RWLOCK_VAL_WRITER )
      pthread_cond_wait(&l->cond, &l->mutex);
  }
  CI_TRY( pthread_mutex_unlock(&l->mutex) );

  /* When all readers have gone, we can just take the write lock,
   * contending with other writers if necessary. */
  CI_TRY( pthread_mutex_lock(&l->write_lock) );
}


ci_inline void oo_rwlock_unlock_write(oo_rwlock* l)
{
  /* Release the writer lock */
  CI_TRY( pthread_mutex_unlock(&l->write_lock) );

  /* Decrement the writers counter and tell readers they can use the lock
   * if needed */
  rwlock_writers_dec(l, 0);
}




typedef struct {
  pthread_cond_t  c;
} oo_rwlock_cond;


ci_inline void oo_rwlock_cond_init(oo_rwlock_cond *cond)
{
  CI_TRY( pthread_cond_init(&cond->c, NULL) );
}
ci_inline void oo_rwlock_cond_destroy(oo_rwlock_cond *cond) {
  CI_TRY( pthread_cond_destroy(&cond->c) );
}

/* This function releases the write_lock mutex in the oo_rwlock argument.
 * It means that other writers can occationally get the oo_rwlock lock, but
 * readers can not.  However, it does not look too bad if used for
 * short-time sleeps. */
ci_inline int
oo_rwlock_cond_wait(oo_rwlock_cond *cond, oo_rwlock *rwlock)
{
  return pthread_cond_wait(&cond->c, &rwlock->write_lock);
}
/* pthread_cond_broadcast() should be called while holding write-lock of
 * the same oo_rwlock which is used in the corresponding
 * oo_rwlock_cond_wait().
 * Moreover, the lock should be taken in advance, before the condition can
 * become true.  See man pthread_cond_broadcast and man pthread_cond_wait
 * for details.
 */
ci_inline int
oo_rwlock_cond_broadcast(oo_rwlock_cond *cond)
{
  return pthread_cond_broadcast(&cond->c);
}


#endif  /* __ONLOAD_UL_RWLOCK_H__ */
