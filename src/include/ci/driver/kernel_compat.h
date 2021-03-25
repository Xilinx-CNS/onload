/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides compatibility layer for various Linux kernel versions
 * (starting from 2.6.9 RHEL kernel).
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
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

#ifndef DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H
#define DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H

#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
# include <linux/io.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/net.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/fdtable.h>
#include <asm/syscall.h>

#include <driver/linux_resource/autocompat.h>

/********* Memory allocation *************/

#ifndef IN_KERNEL_COMPAT_C
#  ifndef __GFP_COMP
#    define __GFP_COMP 0
#  endif
#  ifndef __GFP_ZERO
#    define __GFP_ZERO 0
#  endif
#endif


/* VM_IO is used on mappings of PCI space to inform the kernel that the mapping
 * is not backed by host memory, and so to prevent it from doing anything that
 * it shouldn't.
 *
 * VM_DONTEXPAND prevents the MM from attempting to swap-out these
 * pages.  On very old kernels (2.4) this property belonged instead to
 * VM_RESERVED, but that also prevents core dumps, and we don't require it on
 * any of our supported kernels.  We continue to set it when setting VM_IO,
 * though, for consistency with other users in the kernel, even though its
 * effects are implied by VM_IO.  Similarly, on modern (>= 3.7) kernels in
 * which VM_RESERVED has been purged, we set VM_DONTDUMP if and only if we have
 * set VM_IO.
 */
#define EFRM_VM_BASE_FLAGS VM_DONTEXPAND
#ifdef VM_RESERVED
#define EFRM_VM_IO_FLAGS   (EFRM_VM_BASE_FLAGS | VM_IO | VM_RESERVED)
#else
#define EFRM_VM_IO_FLAGS   (EFRM_VM_BASE_FLAGS | VM_IO | VM_DONTDUMP)
#endif


#ifndef FOLL_WRITE
#define FOLL_WRITE	0x01
#endif

#ifndef FOLL_FORCE
#define FOLL_FORCE	0x10
#endif

/* linux-5.6 have got pin_user_pages() */
#ifndef EFRM_GUP_HAS_PIN
static inline long
pin_user_pages(unsigned long start, unsigned long nr_pages,
	       unsigned int gup_flags, struct page **pages,
	       struct vm_area_struct **vmas)
{
  /* We support four get_user_pages() function prototypes here,
   * including an intermediate one that has one of the changes but not
   * the other, and we assume that intermediate case if the main three
   * are not defined:
   *
   * Pre-3.9: EFRM_GUP_RCINT_TASK_SEPARATE_FLAGS
   * int get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
   *                    unsigned long start, int nr_pages, int write, int force,
   *                    struct page **pages, struct vm_area_struct **vmas);
   *
   * Pre-4.6.0: EFRM_GUP_RCLONG_TASK_SEPARATEFLAGS
   * long get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
   *                     unsigned long start, unsigned long nr_pages,
   *                     int write, int force, struct page **pages,
   *                     struct vm_area_struct **vmas);
   *
   * 4.4.(>=168): EFRM_GUP_RCLONG_TASK_COMBINEDFLAGS
   * long get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
   *                     unsigned long start, unsigned long nr_pages,
   *                     unsigned int gup_flags, struct page **pages,
   *                     struct vm_area_struct **vmas)
   *
   * Intermediate (up to 4.9.0): (would be EFRM_GUP_RCLONG_NOTASK_SEPARATEFLAGS)
   * long get_user_pages(unsigned long start, unsigned long nr_pages,
   *                     int write, int force, struct page **pages,
   *                     struct vm_area_struct **vmas);
   *
   * Post-4.9.0: EFRM_GUP_RCLONG_NOTASK_COMBINEDFLAGS
   * long get_user_pages(unsigned long start, unsigned long nr_pages,
   *                     unsigned int gup_flags, struct page **pages,
   *                     struct vm_area_struct **vmas);
   */

#ifdef EFRM_GUP_RCINT_TASK_SEPARATEFLAGS
#define EFRM_GUP_NRPAGES_CAST (int)
#define EFRM_GUP_RC_CAST (long)
#else
#define EFRM_GUP_NRPAGES_CAST 
#define EFRM_GUP_RC_CAST 
#endif

  return EFRM_GUP_RC_CAST get_user_pages(
#if defined(EFRM_GUP_RCINT_TASK_SEPARATEFLAGS) ||    \
    defined(EFRM_GUP_RCLONG_TASK_SEPARATEFLAGS) ||   \
    defined(EFRM_GUP_RCLONG_TASK_COMBINEDFLAGS)
                                         current, current->mm,
#endif
                                         start, EFRM_GUP_NRPAGES_CAST nr_pages,
#if defined(EFRM_GUP_RCLONG_NOTASK_COMBINEDFLAGS) || \
    defined(EFRM_GUP_RCLONG_TASK_COMBINEDFLAGS)
                                         gup_flags,
#else
                                         gup_flags & FOLL_WRITE, 
                                         gup_flags & FOLL_FORCE,
#endif
                                         pages, vmas);
}

static inline void unpin_user_page(struct page *page)
{
  put_page(page);
}
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
#define VM_FAULT_ADDRESS(_vmf) (_vmf)->address
#else
#define VM_FAULT_ADDRESS(_vmf) (unsigned long)(_vmf)->virtual_address
#endif

/* ioremap_nocache() was removed in linux-5.6 */
#ifdef EFRM_HAVE_IOREMAP_NOCACHE
	/* On old kernels ioremap_nocache() differs from ioremap() */
	#define ci_ioremap(phys,size)	ioremap_nocache(phys,size)
#else
	#define ci_ioremap(phys,size)	ioremap(phys,size)
#endif


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

/* Linux < 5.8 does not have mmap_write_lock() */
#ifndef EFRM_HAVE_MMAP_LOCK_WRAPPERS
static inline void mmap_write_lock(struct mm_struct *mm)
{
  down_write(&mm->mmap_sem);
}
static inline void mmap_write_unlock(struct mm_struct *mm)
{
  up_write(&mm->mmap_sem);
}
static inline void mmap_read_lock(struct mm_struct *mm)
{
  down_read(&mm->mmap_sem);
}
static inline void mmap_read_unlock(struct mm_struct *mm)
{
  up_read(&mm->mmap_sem);
}
#endif

/* For linux<=5.7 you can use kernel_setsockopt(),
 * but newer versions do not have this function. */
static inline int sock_ops_setsockopt(struct socket *sock,
                                      int level, int optname,
                                      char *optval, unsigned int optlen)
{
  int rc;
#ifndef EFRM_HAS_SOCKPTR
  mm_segment_t oldfs = get_fs();

  /* You should call sock_setsockopt() for SOL_SOCKET */
  WARN_ON(level == SOL_SOCKET);

  set_fs(KERNEL_DS);
  rc = sock->ops->setsockopt(sock, level, optname, optval, optlen);
  set_fs(oldfs);
#else
  rc = sock->ops->setsockopt(sock, level, optname,
                             KERNEL_SOCKPTR(optval), optlen);
#endif
  return rc;
}
#ifndef EFRM_HAS_SOCKPTR
#define USER_SOCKPTR(val) val
#endif

/* Linux<=4.16 exports sys_close. Later versions export __close_fd.
 * Linux>=5.11 exports close_fd.
 */
static inline int ci_close_fd(int fd)
{
#ifdef EFRM_SYS_CLOSE_EXPORTED
  return sys_close(fd);
#elif defined(EFRM_CLOSE_FD_EXPORTED)
  return close_fd(fd);
#else
  return __close_fd(current->files, fd);
#endif
}


/* linux>=4.4 has ktime_get_real_seconds(), but linux-3.10 does not */
#ifndef EFRM_HAS_KTIME_GET_REAL_SECONDS
static inline time64_t ktime_get_real_seconds(void)
{
  return get_seconds();
}
#endif


static inline int oo_file_is_in_epoll(struct file* file)
{
#ifdef EFRM_FILE_HAS_F_EP
  /* linux>= 5.11 */
  return file->f_ep != NULL && ! hlist_empty(file->f_ep);
#else
  return ! list_empty(&file->f_ep_links);
#endif
}


#endif /* DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H */
