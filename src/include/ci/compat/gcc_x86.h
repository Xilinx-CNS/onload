/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
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

/*! \cidoxg_include_ci_compat  */

#ifndef __CI_COMPAT_GCC_X86_H__
#define __CI_COMPAT_GCC_X86_H__

/*
** The facts:
**
**   SSE   sfence
**   SSE2  lfence, mfence, pause
*/

/* 
   Barriers to enforce ordering with respect to:

   normal memory use: ci_wmb, ci_rmb, ci_wmb
*/
#if defined(__x86_64__)
# define ci_x86_mb() __asm__ __volatile__ ("lock; addl $0,0(%%rsp)":::"memory")
#else
# define ci_x86_mb() __asm__ __volatile__ ("lock; addl $0,0(%%esp)":::"memory")
#endif

/* ?? measure the impact of latency of sfence on a modern processor before we
   take a decision on how to integrate with respect to writecombining */

#define ci_x86_sfence()  __asm__ __volatile__ ("sfence")
#define ci_x86_lfence()  __asm__ __volatile__ ("lfence")
#define ci_x86_mfence()  __asm__ __volatile__ ("mfence")


/* x86 processors to P4 Xeon store in-order unless executing streaming
   extensions or when using writecombining 

   Hence we do not define ci_wmb to use sfence by default. Requirement is that
   we do not use writecombining to memory and any code which uses SSE
   extensions must call sfence directly 

   We need to track non intel clones which may support out of order store.

*/

#if CI_CPU_OOS
# if CI_CPU_HAS_SSE
#  define ci_wmb()	ci_x86_sfence()
# else
#  define ci_wmb()	ci_x86_mb()
# endif
#else
# define ci_wmb()       ci_compiler_barrier()
#endif

#if CI_CPU_HAS_SSE2
# define ci_rmb()	ci_x86_lfence()
# define ci_mb()	ci_x86_mfence()
#else
# define ci_rmb()	ci_x86_mb()
# define ci_mb()   	ci_x86_mb()
#endif

#define ci_ul_iowb() ((void)0)

typedef unsigned long   ci_phys_addr_t;
#define ci_phys_addr_fmt  "%lx"

#endif  /* __CI_COMPAT_GCC_X86_H__ */

/*! \cidoxg_end */
