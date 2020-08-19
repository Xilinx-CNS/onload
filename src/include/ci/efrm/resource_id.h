/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides public type and definitions resource handle, and the
 * definitions of resource types.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
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

#ifndef __CI_DRIVER_EFRM_RESOURCE_ID_H__
#define __CI_DRIVER_EFRM_RESOURCE_ID_H__


/***********************************************************************
 * Resource type codes
 ***********************************************************************/

#define EFRM_RESOURCE_VI                0x1
#define EFRM_RESOURCE_VI_SET            0x2
#define EFRM_RESOURCE_VF                0x3
#define EFRM_RESOURCE_MEMREG            0x4
#define EFRM_RESOURCE_PD                0x5
#define EFRM_RESOURCE_PIO               0x6
#define EFRM_RESOURCE_NUM               0x7	/* This isn't a resource! */

#define	EFRM_RESOURCE_NAME(type) \
	 (type) == EFRM_RESOURCE_VI?		"VI"		: \
	 (type) == EFRM_RESOURCE_VI_SET?	"VI_SET"	: \
	 (type) == EFRM_RESOURCE_VF?		"VF"		: \
	 (type) == EFRM_RESOURCE_MEMREG?	"MEMREG"	: \
	 (type) == EFRM_RESOURCE_PD?		"PD"		: \
	 (type) == EFRM_RESOURCE_PIO?		"PIO"		: \
						"<invalid>"


#endif /* __CI_DRIVER_EFRM_RESOURCE_ID_H__ */
