/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */


/*! \cidoxg_include_ci_tools_platform  */

#ifndef __CI_TOOLS_LINUX_KERNEL_H__
#define __CI_TOOLS_LINUX_KERNEL_H__

/**********************************************************************
 * Need to know the kernel version.
 */

#include <driver/linux_resource/autocompat.h>

#ifndef LINUX_VERSION_CODE
# include <linux/version.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
# error "Linux 3.10+ required"
#endif


#include <linux/slab.h>     /* kmalloc / kfree */
#include <linux/vmalloc.h>  /* vmalloc / vfree */
#include <linux/interrupt.h>/* in_interrupt()  */
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/spinlock.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/uio.h>
#include <asm/current.h>
#include <asm/errno.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>
#include <linux/user_namespace.h>

#include <ci/tools/config.h>

#define ci_in_atomic     in_atomic


/**********************************************************************
 * Misc stuff.
 */

ci_inline void* __ci_alloc(size_t n)
{ return kmalloc(n, (in_interrupt() ? GFP_ATOMIC : GFP_KERNEL)); }

ci_inline void* __ci_atomic_alloc(size_t n)
{ return kmalloc(n, GFP_ATOMIC ); }

ci_inline void  __ci_free(void* p)     { return kfree(p);   }
ci_inline void* __ci_vmalloc(size_t n) { return vmalloc(n); }
ci_inline void  __ci_vfree(void* p)    { return vfree(p);   }


#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
  #define ci_alloc(s)     ci_alloc_memleak_debug (s, __FILE__, __LINE__)
  #define ci_atomic_alloc(s)  ci_atomic_alloc_memleak_debug(s, __FILE__, __LINE__)
  #define ci_free         ci_free_memleak_debug
  #define ci_vmalloc(s)   ci_vmalloc_memleak_debug (s, __FILE__,__LINE__)
  #define ci_vfree        ci_vfree_memleak_debug
  #define ci_alloc_fn     ci_alloc_fn_memleak_debug
  #define ci_vmalloc_fn   ci_vmalloc_fn_memleak_debug
#else /* !CI_MEMLEAK_DEBUG_ALLOC_TABLE */
  #define ci_alloc_fn     __ci_alloc
  #define ci_vmalloc_fn   __ci_vmalloc
#endif 

#ifndef ci_alloc
  #define ci_atomic_alloc __ci_atomic_alloc
  #define ci_alloc        __ci_alloc
  #define ci_free         __ci_free
  #define ci_vmalloc      __ci_vmalloc
  #define ci_vmalloc_fn   __ci_vmalloc
  #define ci_vfree        __ci_vfree
#endif

#define ci_sprintf        sprintf
#define ci_vsprintf       vsprintf
#define ci_snprintf       snprintf
#define ci_vsnprintf      vsnprintf
#define ci_scnprintf      scnprintf
#define ci_vscnprintf     vscnprintf
#define ci_sscanf         sscanf


#define CI_LOG_FN_DEFAULT  ci_log_syslog


/**********************************************************************
 * spinlock implementation: used by <ci/tools/spinlock.h>
 */


#define CI_HAVE_SPINLOCKS

typedef ci_uintptr_t    			ci_lock_holder_t;
#define ci_lock_thisthread 		(ci_lock_holder_t)current		       	
#define ci_lock_no_holder     (ci_lock_holder_t)NULL

typedef spinlock_t			ci_lock_i;
typedef spinlock_t			ci_irqlock_i;
typedef unsigned long			ci_irqlock_state_t;

#define IRQLOCK_CYCLES  500000

#define ci_lock_ctor_i(l)		spin_lock_init(l)
#define ci_lock_dtor_i(l)		do{}while(0)
#define ci_lock_lock_i(l)		spin_lock(l)
#define ci_lock_trylock_i(l)		spin_trylock(l)
#define ci_lock_unlock_i(l)		spin_unlock(l)

/* We don't run any code in hard IRQ context, so only block soft interrupts
 * (bottom-halves).
 */
#define ci_irqlock_ctor_i(l)		spin_lock_init(l)
#define ci_irqlock_dtor_i(l)		do{}while(0)
#define ci_irqlock_lock_i(l,s)		\
  do {                                  \
    (void)(s);                          \
    spin_lock_bh(l);                    \
  } while(0)
#define ci_irqlock_unlock_i(l,s)	\
  do {					\
    (void)(s);                          \
    spin_unlock_bh(l);                  \
  } while(0)

/**********************************************************************
 * register access
 */

#include <asm/io.h>

typedef volatile void __iomem*	ioaddr_t;


/**********************************************************************
 * thread implementation -- kernel dependancies probably should be
 * moved to driver/linux_kernel.h
 */

#define ci_linux_daemonize(name) daemonize(name)

#include <linux/workqueue.h>


typedef struct {
  void*			(*fn)(void* arg);
  void*			arg;
  const char*		name;
  struct task_struct*	thrd_id;
  struct completion	exit_event;
} ci_kernel_thread_t;


typedef ci_kernel_thread_t* cithread_t;


extern int cithread_create(cithread_t* tid, void* (*fn)(void*), void* arg,
			   const char* name);
extern int cithread_detach(cithread_t kt);
extern int cithread_join(cithread_t kt);


/* Kernel sysctl variables. */
extern int sysctl_tcp_wmem[3];
extern int sysctl_tcp_rmem[3];


/**********************************************************************
 * struct iovec abstraction (for Windows port)
 */

typedef struct iovec ci_iovec;

/* Accessors for buffer/length */
#define CI_IOVEC_BASE(i) ((i)->iov_base)
#define CI_IOVEC_LEN(i)  ((i)->iov_len)

/**********************************************************************
 * UID
 */

#ifdef EFRM_HAVE_CRED_H
#include <linux/cred.h>
#endif

ci_inline uid_t ci_geteuid(void)
{
  return __kuid_val(current_euid());
}


ci_inline uid_t ci_getuid(void)
{
  return __kuid_val(current_uid());
}

ci_inline uid_t ci_getegid(void)
{
  return from_kgid(&init_user_ns, current_egid());
}

/* gid: -2 - none group, -1 - everyone group or actual gid */
ci_inline int ci_in_egroup(int gid)
{
  return gid != -2 && (gid == -1 || in_egroup_p(KGIDT_INIT(gid)));
}


/* Although some support for user namespaces is present in earlier kernel
 * versions there's some variation in exactly what is supported, and no
 * supported distributions enable it with earlier kernels than 3.10.  We
 * can avoid having to support interim kernel versions by only
 * supporting user namespaces in more recent kernels.
 */
#if defined(CONFIG_USER_NS)
#define EFRM_DO_USER_NS
#endif

ci_inline uid_t ci_current_from_kuid_munged(uid_t uid)
{
#ifdef EFRM_DO_USER_NS
  uid = from_kuid_munged(current_user_ns(), KUIDT_INIT(uid));
#endif
  return uid;
}

ci_inline uid_t ci_from_kuid_munged(struct user_namespace* ns, uid_t uid)
{
#ifdef EFRM_DO_USER_NS
  return from_kuid_munged(ns, KUIDT_INIT(uid));
#else
  return uid;
#endif
}

ci_inline uid_t ci_make_kuid(struct user_namespace*ns, uid_t uid)
{
#ifdef EFRM_DO_USER_NS
  kuid_t kuid = make_kuid(ns, uid);
  return __kuid_val(kuid);
#else
  return uid;
#endif
}

#endif  /* __CI_TOOLS_LINUX_KERNEL_H__ */
/*! \cidoxg_end */
