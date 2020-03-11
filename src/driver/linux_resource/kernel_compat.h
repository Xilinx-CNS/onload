/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
#include <driver/linux_affinity/kernel_compat.h>

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


#ifndef NOPAGE_SIGBUS
#  define NOPAGE_SIGBUS (NULL)
#endif

#ifndef FOLL_WRITE
#define FOLL_WRITE	0x01
#endif

#ifndef FOLL_FORCE
#define FOLL_FORCE	0x10
#endif

static inline long
get_user_pages_onload_compat(unsigned long start, unsigned long nr_pages,
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
#define get_user_pages get_user_pages_onload_compat


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
#define VM_FAULT_ADDRESS(_vmf) (_vmf)->address
#else
#define VM_FAULT_ADDRESS(_vmf) (unsigned long)(_vmf)->virtual_address
#endif

#endif /* DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H */
