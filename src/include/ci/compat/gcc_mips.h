/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2019 Xilinx, Inc. */
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

#ifndef __CI_COMPAT_GCC_MIPS_H__
#define __CI_COMPAT_GCC_MIPS_H__

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

/* TODO: do we need to expand this? */
#define ci_mips_mb() 

/* DJR: I don't think we need to add "memory" here.  It means the asm does
** something to memory that GCC doesn't understand.  But all this does is
** commit changes that GCC thinks have already happened.  NB. GCC will not
** reorder across a __volatile__ __asm__ anyway.
*/
#define ci_gcc_fence()    __asm__ __volatile__ ("")

#define ci_wmb()       ci_gcc_fence()
#define ci_rmb()       ci_mips_mb()
#define ci_mb()        ci_mips_mb()

#define ci_ul_iowb() ((void)0)

typedef unsigned long   ci_phys_addr_t;
#define ci_phys_addr_fmt  "%lx"

#endif  /* __CI_COMPAT_GCC_MIPS_H__ */

/*! \cidoxg_end */
