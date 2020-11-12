/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019 Xilinx, Inc. */
#include <ci/kcompat.h>
#include <ci/tools.h>

struct seq_file;

void mutex_lock(struct mutex* m) {
  int rc = pthread_mutex_lock(&m->mutex);
  ci_assert(rc == 0);
  (void) rc;
}

void mutex_unlock(struct mutex* m) {
  int rc = pthread_mutex_unlock(&m->mutex);
  ci_assert(rc == 0);
  (void) rc;
}

void mutex_init(struct mutex* m) {
  int rc = pthread_mutex_init(&m->mutex, NULL);
  ci_assert(rc == 0);
  (void) rc;
}

int mutex_is_locked(struct mutex* m) {
  int rc = pthread_mutex_trylock(&m->mutex);
  if(rc == 0) {
    pthread_mutex_unlock(&m->mutex);
    return 0;
  }
  else {
    return 1;
  }
}

void mutex_destroy(struct mutex* m) {
  int rc = pthread_mutex_destroy(&m->mutex);
  ci_assert(rc == 0);
  (void) rc;
}

/* The spinlock implementation currently uses the pthread spinlock, however,
 * this requires a destroy() function be called, which the oof code does not
 * call, so should probably be replaced.
 */
void spin_lock_init(spinlock_t* s) {
  int rc = pthread_spin_init(&s->spin, PTHREAD_PROCESS_PRIVATE);
  ci_assert(rc == 0);
  (void) rc;
}

int spin_is_locked(spinlock_t* s) {
  int rc = pthread_spin_trylock(&s->spin);
  if(rc == 0) {
    pthread_spin_unlock(&s->spin);
    return 0;
  }
  else {
    return 1;
  }
};

int spin_lock_bh(spinlock_t* s) {
  return pthread_spin_lock(&s->spin);
}

void spin_unlock_bh(spinlock_t* s) {
  int rc = pthread_spin_unlock(&s->spin);
  ci_assert(rc == 0);
  (void) rc;
}

int in_atomic(void) {
  return 0;
}

int in_interrupt(void) {
  return 0;
}

/* Used to test for CAP_NET_RAW for MAC filter install */
int ns_capable(struct user_namespace* user_ns, int c) {
  return 1;
}

/* Used to compare with scalable_filters_gid for MAC filter install */
int ci_in_egroup(int gid)
{
  return 1;
}


void kfree(void *objp)
{
  ci_free(objp);
}
