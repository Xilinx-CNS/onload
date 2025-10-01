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
#include <linux/file.h>
#include <asm/syscall.h>
#include <net/sock.h>
#include <linux/filter.h>

#include <driver/linux_resource/autocompat.h>
#include <ci/tools.h>

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
ci_pin_user_pages(unsigned long start, unsigned long nr_pages,
		  unsigned int gup_flags, struct page **pages)
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
                                         pages, NULL);
}

static inline void unpin_user_page(struct page *page)
{
  put_page(page);
}

static inline void unpin_user_pages(struct page **pages, unsigned long npages)
{
  int i;

  for( i = 0; i < npages; i++ )
    put_page(pages[i]);
}
#else /* EFRM_GUP_HAS_PIN */

/* linux-6.5 removes vmas parameter from pin_user_pages() */
#ifndef EFRM_GUP_PIN_HAS_VMAS
#define ci_pin_user_pages pin_user_pages
#else
#define ci_pin_user_pages(start, nr_pages, gup_flags, pages) \
  pin_user_pages((start), (nr_pages), (gup_flags), (pages), NULL)
#endif

#endif

#ifndef EFRM_GUP_HAS_DMA_PINNED
/* page_maybe_dma_pinned() was not added at the same time as pin_user_pages(),
 * but shortly after, around linux-5.7. We could mimic it, but the real value
 * for us is the post linux-6.1 kernels, which may change the pinning semantics
 * and break our assumptions that vm_munmap() does not unpin pages. */
static inline bool page_maybe_dma_pinned(struct page *page)
{
  return true;
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


#ifndef EFRM_HAVE_VM_FLAGS_SET
/* Linux < 6.3 */
static inline void vm_flags_set(struct vm_area_struct *vma, vm_flags_t flags)
{
  vma->vm_flags |= flags;
}
static inline void vm_flags_clear(struct vm_area_struct *vma, vm_flags_t flags)
{
  vma->vm_flags &= ~flags;
}
#endif /* EFRM_HAVE_VM_FLAGS_SET */


static inline int
oo_remap_vmalloc_range_partial(struct vm_area_struct *vma, unsigned long uaddr,
                               void *kaddr, unsigned long size)
{
#ifdef EFRM_HAS_REMAP_VMALLOC_RANGE_PARTIAL
  /* linux<5.13 */
  int rc = remap_vmalloc_range_partial(vma, uaddr, kaddr,
#ifdef EFRM_REMAP_VMALLOC_RANGE_PARTIAL_NEW
                                     0 /*pgoff, in linux>=5.7 */,
#endif
                                     size);

  if( rc >= 0 )
    /* remap_vmalloc_range_partial sets this */
    vm_flags_clear(vma, VM_DONTDUMP);

  return rc;
#else
  /* linux>=5.13 */
  unsigned long npages = size >> PAGE_SHIFT;
  struct page** pages = kmalloc_array(npages, sizeof(struct page*),
                                      GFP_KERNEL);
  unsigned long i;
  int rc;

  if( pages == NULL )
    return -ENOMEM;

  for( i = 0; i < npages; i++ ) {
    pages[i] = vmalloc_to_page(kaddr);
    ci_assert(pages[i]);
    kaddr += PAGE_SIZE;
  }

  rc = vm_insert_pages(vma, uaddr, pages, &i);

  /* There is not much we can do in case of an error. "npages - i"
   * pages have been already inserted into vma, and we can't get them out
   * of there.  So we log the error and return.
   */
  if( rc != 0 )
    ci_log("%s: partial remap for shmbuf: rc=%d, inserting %lu pages, "
           "%lu remain", __func__, rc, npages, i);

  kfree(pages);
  return rc;
#endif
}

#ifndef EFRM_HAVE_LOWCASE_PDE_DATA
/* linux < 5.17 */
#define pde_data PDE_DATA
#endif /* ! EFRM_HAVE_LOWCASE_PDE_DATA */

#ifdef EFRM_HAVE_NETIF_RX_NI
/* linux < 5.18 */
#define ci_netif_rx_non_irq netif_rx_ni
#else
#define ci_netif_rx_non_irq netif_rx
#endif /* EFRM_HAVE_NETIF_RX_NI */

#ifndef EFRM_HAVE_GET_RANDOM_U32
/* linux < 4.11 */
static inline u32 get_random_u32(void)
{
	return get_random_int();
}
#endif

#ifndef EFRM_HAVE_KSTRTOBOOL
static inline int kstrtobool(const char *s, bool *res)
{
	return strtobool(s, res);
}
#endif

#ifdef EFRM_NEED_STRSCPY
#define strscpy strlcpy
#endif

#ifdef EFRM_CLASS_CREATE_NO_MODULE
/* linux >= 6.4 */
/* NOTE: there are revisions between linux-6.3 and linux-6.4 where
 *       'class_create' is defined as follows:
 *       #define class_create(name)
 *       Such definition is not handled by this compat code, so build is broken
 *       on those revisions. It does not involve any release Linux versions, but
 *       you may face build problems when bisecting Linux. */
#define ci_class_create(__name) class_create(__name)
#else
#define ci_class_create(__name) class_create(THIS_MODULE, __name)
#endif

#ifdef EFRM_HAVE_FOLLOW_PFNMAP_START
/* linux >= 6.12 */
static inline int efrm_follow_pfn(struct vm_area_struct *vma,
                                  unsigned long addr, unsigned long *pfn)
{
	struct follow_pfnmap_args args;
	int rc;

	args.vma = vma;
	args.address = addr;
	rc = follow_pfnmap_start(&args);
	if( rc == 0 ) {
		*pfn = args.pfn;
		follow_pfnmap_end(&args);
	}

	return rc;
}
#elif defined(EFRM_HAVE_FOLLOW_PTE)
/* exported in linux 5.10+ */

#ifdef EFRM_HAVE_FOLLOW_PTE_VMA
/* linux >= 6.10 */
#define efrm_follow_pte follow_pte
#else
#define efrm_follow_pte(vma, addr, ptep, ptl) \
  follow_pte((vma)->vm_mm, addr, ptep, ptl)
#endif /* EFRM_HAVE_FOLLOW_PTE_VMA */

static inline int efrm_follow_pfn(struct vm_area_struct *vma,
                                  unsigned long addr, unsigned long *pfn)
{
	int rc;
	pte_t *ptep;
	spinlock_t *ptl;

	/* On some kernels follow_pte does this check for us, but not all,
	 * so do it explicitly here. */
	if( !(vma->vm_flags & (VM_IO | VM_PFNMAP)) )
		return -EINVAL;

	rc = efrm_follow_pte(vma, addr, &ptep, &ptl);
	if( rc == 0 ) {
		*pfn = pte_pfn(ptep_get(ptep));
		pte_unmap_unlock(ptep, ptl);
	}

	return rc;
}
#else
static inline int efrm_follow_pfn(struct vm_area_struct *vma,
                                  unsigned long addr, unsigned long *pfn)
{
	return follow_pfn(vma, addr, pfn);
}
#endif

/* Historically, page->index was expressed in the huge page size units.
 * Then, it changed to the PAGE_SIZE units. We use the presence of the
 * hugetlb_basepage_index() function as a marker of this transition.
 * We also use the presence of filemap_lock_hugetlb_folio() to
 * distinguish between older Linux kernels (< 5.4) and newer (>= 6.7
 * for vanilla, and >= 5.14 for RHEL 9.6) where hugetlb_basepage_index()
 * was not present.
 */
#if defined(EFRM_HAS_FILEMAP_LOCK_HUGETLB_FOLIO) && ! defined(EFRM_HAS_HUGETLB_BASEPAGE_INDEX)
#define EFRM_HUGETLB_INDEX_BY_PAGE yes
#endif


#endif /* DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H */
