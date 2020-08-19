/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
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

/*
 * \author  djr
 *  \brief  Arch stuff for AMD x86_64.
 *   \date  2004/08/17
 */

/*! \cidoxg_include_ci_compat  */
#ifndef __CI_COMPAT_X86_64_H__
#define __CI_COMPAT_X86_64_H__


#define CI_MY_BYTE_ORDER	CI_LITTLE_ENDIAN

#define CI_WORD_SIZE		8
#define CI_PTR_SIZE		8

#define CI_PAGE_SIZE		4096
#define CI_PAGE_SHIFT		12
#define CI_PAGE_MASK		(~((ci_uintptr_t) CI_PAGE_SIZE - 1))

#define CI_CACHE_LINE_SIZE      64

#define CI_CPU_HAS_SSE		1	/* SSE extensions supported */

/* SSE2 disabled while investigating BUG1060 */
#define CI_CPU_HAS_SSE2		0	/* SSE2 extensions supported */
#define CI_CPU_OOS		0	/* CPU does out of order stores */

#define CI_CPU_HAS_IOSPACE 1 /* CPU has a separate IO space */

#define CI_MAX_TIME_T 0x7fffffffffffffffLL

#endif  /* __CI_COMPAT_X86_64_H__ */
/*! \cidoxg_end */
