/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2019 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides EF10 definition for buffer table management
 *
 * Copyright 2013:      Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <onload-dev@solarflare.com>
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

#ifndef __CI_DRIVER_EFAB_HARDWARE_EF10_VADDR_H__
#define __CI_DRIVER_EFAB_HARDWARE_EF10_VADDR_H__

/*----------------------------------------------------------------------------
 *
 * Buffer virtual addresses
 *
 *---------------------------------------------------------------------------*/

#define EF10_BUF_VADDR_ORDER_SHIFT 48
#define EF10_BUF_VADDR_2_ID_OFFSET(vaddr) ((vaddr) & 0xffffffffffffULL)
#define EF10_BUF_VADDR_2_ORDER(vaddr) ((vaddr) >> EF10_BUF_VADDR_ORDER_SHIFT)
#define EF10_BUF_ID_ORDER_2_VADDR(id, order) \
	(((uint64_t)(order) << EF10_BUF_VADDR_ORDER_SHIFT) + \
	 ((uint64_t)(id) << (order + EFHW_NIC_PAGE_SHIFT)))
#define EF10_BUF_VADDR_2_ID(vaddr) \
	(EF10_BUF_VADDR_2_ID_OFFSET(vaddr) >> \
	 (EFHW_NIC_PAGE_SHIFT + EF10_BUF_VADDR_2_ORDER(vaddr)))


#endif
