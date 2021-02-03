/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains OS-independent API for allocating iopage types.
 * The implementation of these functions is highly OS-dependent.
 * This file is not designed for use outside of the SFC resource driver.
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

#ifndef __CI_DRIVER_RESOURCE_IOPAGE_H__
#define __CI_DRIVER_RESOURCE_IOPAGE_H__

#include <ci/efhw/efhw_types.h>

/*--------------------------------------------------------------------
 *
 * memory allocation
 *
 *--------------------------------------------------------------------*/

/* Allocate a set of IO pages, map them into the specified NIC (nic)
 * and initialise the efhw_iopages structure (p).  The pages will be
 * contiguous in the kernel address space and can be contiguous in the
 * device address space.  The number of pages allocated is 1<<order. The
 * caller must release the pages using efhw_iopages_free when they is
 * no longer needed.  Returns zero on success or a negative error
 * number on failure. */
extern int efhw_iopages_alloc(struct efhw_nic *nic, struct efhw_iopages *p,
			      unsigned order, int phys_cont_only,
			      unsigned long iova_base);

/* Free IO pages allocated using efhw_iopages_alloc.  This reverses
 * the effects of efhw_iopages_alloc.  The same values must be
 * supplied to the nic and p arguments to the two functions. */
extern void efhw_iopages_free(struct efhw_nic *nic, struct efhw_iopages *p);

#endif /* __CI_DRIVER_RESOURCE_IOPAGE_H__ */
