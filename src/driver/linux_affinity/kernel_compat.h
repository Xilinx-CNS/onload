/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef SFC_AFFINITY_KERNEL_COMPAT_H
#define SFC_AFFINITY_KERNEL_COMPAT_H

#include "driver/linux_affinity/autocompat.h"
#include <linux/proc_fs.h>
#include <linux/version.h>


#ifndef EFRM_HAVE_WAIT_QUEUE_ENTRY
#define wait_queue_entry_t wait_queue_t
#endif

#ifndef EFRM_HAVE_NEW_FAULT
typedef int vm_fault_t;
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#define get_netns_id(net_ns)     ((net_ns)->ns.inum)
#elif defined(EFRM_NET_HAS_PROC_INUM)
#define get_netns_id(net_ns)     ((net_ns)->proc_inum)
#else
#define get_netns_id(net_ns)     0
#endif


/* Correct sequence for per-cpu variable access is: disable preemption to
 * guarantee that the CPU is not changed under your feet - read/write the
 * variable - enable preemption.  In linux >=3.17, we have this_cpu_read()
 * which checks for preemption and get_cpu_var()/put_cpu_var() which
 * disable/enable preemption.
 *
 * We do not care about preemption at all, for 2 reasons:
 * 1. We do not really care if we sometimes get variable from wrong CPU.
 * 2. The most of uses are from driverlink, and NAPI thread can not
 *    change CPU.
 *
 * So, we use fast-and-unreliable raw_cpu_read().
 * For older kernels, we implement raw_cpu_read() and raw_cpu_write().
 */
#ifndef raw_cpu_read
/* linux < 3.17 */

#ifndef raw_cpu_ptr
/* linux < 3.15 */

#define raw_cpu_ptr(var) \
      per_cpu_ptr(&(var), raw_smp_processor_id())

#endif /* raw_cpu_ptr */

#define raw_cpu_read(var) (*raw_cpu_ptr(var))
#define raw_cpu_write(var,val) \
  do {                          \
    *raw_cpu_ptr(var) = (val);  \
  } while(0)

#endif /* raw_cpu_read */

#ifndef EFRM_HAVE_FILE_INODE
/* Only RHEL6 doesn't have this function */
static inline struct inode *file_inode(const struct file *f)
{
        return f->f_path.dentry->d_inode;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#define get_netns_id(net_ns)     ((net_ns)->ns.inum)
#elif defined(EFRM_NET_HAS_PROC_INUM)
#define get_netns_id(net_ns)     ((net_ns)->proc_inum)
#else
#define get_netns_id(net_ns)     0
#endif


/* Compat for linux < 5.5 */
#ifndef EFRM_HAVE_STRUCT_PROC_OPS
#define proc_ops file_operations
#define proc_open open
#define proc_read read
#define proc_write write
#define proc_lseek llseek
#define proc_release release
#define PROC_OPS_SET_OWNER .owner = THIS_MODULE,
#else
#define PROC_OPS_SET_OWNER
#endif

/* Compat for linux <= 3.16 */
#ifndef EFRM_HAS_STRUCT_TIMESPEC64
#define timespec64 timespec
#define ktime_get_ts64 ktime_get_ts
#endif

#endif
