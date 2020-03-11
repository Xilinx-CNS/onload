/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_platform  */

#ifndef __CI_DRIVER_PLATFORM_LINUX_KERNEL_H__
#define __CI_DRIVER_PLATFORM_LINUX_KERNEL_H__


/**********************************************************************
 * Kernel headers.
 */

#ifndef __ci_driver_shell__	/* required to get ksym versions working */
#define __NO_VERSION__
#endif

#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/kd.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/vmalloc.h>	
#include <linux/ioport.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/lp.h>
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/utsname.h>
#include <linux/wait.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>   
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/bitops.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/dma.h>
#include <asm/uaccess.h>
#if defined(__x86__)
#include <asm/mtrr.h>
#endif
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/moduleparam.h>
#include <linux/pid.h>

#ifndef LINUX_VERSION_CODE
# error No LINUX_VERSION_CODE.
#endif

#include <linux/fdtable.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
# error "Linux 3.10+ required"
#endif

#include <linux/init.h>     /* module_init/module_exit */

#include <driver/linux_net/kernel_compat.h>
#include <driver/linux_affinity/kernel_compat.h>

typedef int socklen_t;


/*--------------------------------------------------------------------
 *
 * Misc version fixups.
 *
 *--------------------------------------------------------------------*/

/* These have disappeared */
#define copy_to_user_ret(to,from,n,retval) \
    do{ if (copy_to_user(to,from,n)) return retval; }while(0)
#define copy_from_user_ret(to,from,n,retval) \
    do{ if (copy_from_user(to,from,n)) return retval; }while(0)


#include <linux/capability.h>
/* Do allow system administration via ioctl? */
ci_inline int ci_is_sysadmin(void)
{
  return capable(CAP_SYS_ADMIN);
}


#ifndef DEFINE_RWLOCK
#define DEFINE_RWLOCK(name) rwlock_t name = RW_LOCK_UNLOCKED
#endif

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(name) spinlock_t name = SPIN_LOCK_UNLOCKED
#endif

/*--------------------------------------------------------------------
 *
 * VMALLOC and helpers
 *
 *--------------------------------------------------------------------*/

#define VMALLOC_VMADDR(x) ((unsigned long)(x))    /* depreciated */


ci_inline void
ci_sleep_ms(ulong ms)
{
  set_current_state(TASK_INTERRUPTIBLE);
  schedule_timeout((HZ*ms)/1000);
}

/*--------------------------------------------------------------------
 *
 * Kernel definitions for SHUT_RD and friends
 *
 *--------------------------------------------------------------------*/

#define SHUT_RD   0
#define SHUT_WR   1
#define SHUT_RDWR 2


/*--------------------------------------------------------------------
 *
 * ci_waitable_t
 *
 *--------------------------------------------------------------------*/

typedef struct {
  wait_queue_head_t  wq;
} ci_waitable_t;

typedef struct {
  wait_queue_entry_t w;
} ci_waiter_t;

typedef long  ci_waitable_timeout_t;  /* jiffies */
typedef int (*ci_waiter_on_wakeup_fn)(ci_waiter_t*, void*, void*, int rc,
                                      ci_waitable_timeout_t);


#define ci_waitable_ctor(w)	init_waitqueue_head(&(w)->wq)
#define ci_waitable_dtor(w)	do{}while(0)

#define ci_waitable_active(w)	waitqueue_active(&(w)->wq)
#define ci_waitable_wakeup_one(w)			\
  do{ wake_up_interruptible(&(w)->wq); }while(0)
#define ci_waitable_wakeup_all(w)			\
  do{ wake_up_interruptible_all(&(w)->wq); }while(0)

#if HZ > 2000
# error HZ is too big for ci_waitq_init_timeout
#endif

#define ci_waitable_init_timeout(t, timeval)  \
  do {                                        \
    if( ci_waitq_wait_forever(timeval) )      \
      *(t) = -1;                \
    else                                      \
    {                                         \
      *(t) = (timeval)->tv_sec * HZ + (timeval)->tv_usec * HZ / 1000000u; \
      *(t) = CI_MAX(*(t), 1);                 \
    }                                         \
  } while(0)

#define ci_waitable_init_timeout_from_ms(t, ms)  \
  do {                                        \
    if( ms == 0 )                             \
      *(t) = -1;                \
    else                                      \
      *(t) = msecs_to_jiffies(ms);            \
  } while(0)

ci_inline int __ci_waiter_pre(ci_waiter_t* waiter, ci_waitable_t* waitable) {
  init_waitqueue_entry(&waiter->w, current);
  set_current_state(TASK_INTERRUPTIBLE);
  add_wait_queue(&waitable->wq, &waiter->w);
  return 0;
}
#define ci_waiter_pre(wr, wb)  __ci_waiter_pre(wr, wb)

ci_inline int __ci_waiter_exclusive_pre(ci_waiter_t* waiter,
					ci_waitable_t* waitable) {
  init_waitqueue_entry(&waiter->w, current);
  set_current_state(TASK_INTERRUPTIBLE);
  add_wait_queue_exclusive(&waitable->wq, &waiter->w);
  return 0;
}
#define ci_waiter_exclusive_pre  __ci_waiter_exclusive_pre

#define ci_waiter_post(waiter, waitable)		\
  remove_wait_queue(&(waitable)->wq, &(waiter)->w);	\

ci_inline void ci_waiter_dont_wait(ci_waiter_t* waiter,
				   ci_waitable_t* waitable) {
  ci_waiter_post(waiter, waitable);
  set_current_state(TASK_RUNNING);
}

#define ci_waiter_prepare_continue_to_wait(a, b)  \
  set_current_state(TASK_INTERRUPTIBLE)

#define ci_waiter_dont_continue_to_wait(a, b)  \
    set_current_state(TASK_RUNNING);

#define CI_WAITER_CONTINUE_TO_WAIT	1
#define CI_WAITER_CONTINUE_TO_WAIT_REENTRANT  2
#define CI_WAITER_CONVERT_REENTRANT(x)    (x)

/* If timeout is negative, the function will wait forever and return
 * -ERESTARTSYS in case of signal arrival.
 * If timeout is positive, the funtion will wait for the given timeout and
 * return -EINTR in case of signal.
 * Such a behaviour is implemented to match Linux one, and also because
 * there is no way to properly restart a system call with timeout.
 */
ci_inline int ci_waiter_wait(ci_waiter_t* waiter, ci_waitable_t* w,
			     ci_waitable_timeout_t *timeout,
			     void* opaque1, void* opaque2,
			     ci_waiter_on_wakeup_fn on_wakeup) {
  int rc;
  ci_waitable_timeout_t t = -1;
  if( timeout )
    t = *timeout;
 again:
  rc = 0;
  if( t >= 0 ) {
    t = schedule_timeout(t);
    if( t == 0 )                        rc = -ETIMEDOUT;
    else if( signal_pending(current) )  rc = -EINTR;
  }
  else {
    schedule();
    if( signal_pending(current) )  rc = -ERESTARTSYS;
  }
  rc = on_wakeup(waiter, opaque1, opaque2, rc, t);
  if( rc == CI_WAITER_CONTINUE_TO_WAIT )  goto again;
  if( timeout )
    *timeout = t;
  return rc;
}


/*--------------------------------------------------------------------
 *
 * wait_queue 
 *
 *--------------------------------------------------------------------*/

typedef wait_queue_head_t	ci_waitq_t;
typedef wait_queue_entry_t	ci_waitq_waiter_t;
typedef long			ci_waitq_timeout_t;  /* jiffies */

#define ci_waitq_ctor(wq)	init_waitqueue_head(wq)
#define ci_waitq_dtor(wq)	do{}while(0)

#define ci_waitq_active(wq)	waitqueue_active(wq)
#define ci_waitq_wakeup(wq)	do{ wake_up_interruptible(wq); }while(0)
#define ci_waitq_wakeup_all(wq)	do{ wake_up_interruptible_all(wq); }while(0)

#if HZ > 2000
# error HZ is too big for ci_waitq_init_timeout
#endif

ci_inline void ci_waitq_init_timeout(ci_waitq_timeout_t* t,
                                     ci_timeval_t* timeval) {
  if( ci_waitq_wait_forever(timeval) )
    *t = -1;
  else {
    *t = timeval->tv_sec * HZ + timeval->tv_usec * HZ / 1000000u;
    *t = CI_MAX(*t, 1);
  }
}

#define ci_waitq_waiter_pre(waiter, wq)		\
  do {						\
    init_waitqueue_entry(waiter, current);	\
    set_current_state(TASK_INTERRUPTIBLE);	\
    add_wait_queue((wq), (waiter));		\
  } while(0)

#define ci_waitq_waiter_exclusive_pre(waiter, wq)	\
  do {							\
    init_waitqueue_entry(waiter, current);		\
    set_current_state(TASK_INTERRUPTIBLE);		\
    add_wait_queue_exclusive((wq), (waiter));		\
  } while(0)

#define ci_waitq_waiter_wait(waiter, wq, cond)	\
  do { if( !(cond) )  schedule(); } while(0)

#define ci_waitq_waiter_timedwait(waiter, wq, cond, timeout)		\
  do {									\
    if( !(cond) ) {							\
      if( *(timeout) >= 0 ) *(timeout) = schedule_timeout(*(timeout));	\
      else                  schedule();					\
    }									\
  } while(0)

#define ci_waitq_waiter_again(waiter, wq)       \
  do {                                          \
    set_current_state(TASK_INTERRUPTIBLE);      \
  } while(0)

#define ci_waitq_waiter_post(waiter, wq)	\
  do {						\
    set_current_state(TASK_RUNNING);		\
    remove_wait_queue((wq), (waiter));		\
  } while(0)

#define ci_waitq_waiter_signalled(waiter, wq)  (signal_pending(current))

#define ci_waitq_waiter_timedout(timeout)      (*(timeout) == 0)

#endif  /* __CI_DRIVER_PLATFORM_LINUX_KERNEL_H__ */
/*! \cidoxg_end */
