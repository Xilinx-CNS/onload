/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2019 Xilinx, Inc. */
#ifndef __TEST_KERNEL_COMPAT_H__
#define __TEST_KERNEL_COMPAT_H__

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

#ifndef bool
#define bool int
#define true 1
#define false 0
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

typedef uint16_t __be16;
typedef uint32_t __be32;

struct seq_file;
struct oof_manager;
struct net_device;

struct mutex {
  pthread_mutex_t mutex;
};

extern void mutex_lock(struct mutex* m);
extern void mutex_unlock(struct mutex* m);
extern void mutex_init(struct mutex* m);
extern void mutex_destroy(struct mutex* m);
extern int mutex_is_locked(struct mutex* m);

typedef struct {
  pthread_spinlock_t spin;
} spinlock_t;

extern void spin_lock_init(spinlock_t* s);
extern int spin_is_locked(spinlock_t* s);
extern int spin_lock_bh(spinlock_t* s);
extern void spin_unlock_bh(spinlock_t* s);

extern int in_atomic(void);
extern int in_interrupt(void);

#define CAP_NET_RAW 13
#define EFRM_NET_HAS_USER_NS
struct user_namespace;
extern int ns_capable(struct user_namespace* user_ns, int c);

#define BUG_ON(x) ci_assert(!(x))

extern int ci_getgid(void);

struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);
struct work_struct {
  work_func_t func;
};

extern void kfree(void *objp);

#define container_of(p_,t_,f_) CI_CONTAINER(t_,f_,p_)
#define INIT_WORK(w, f) (w)->func = (f);

#endif /* __TEST_KERNEL_COMPAT_H__ */
