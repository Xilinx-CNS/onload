/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides private API of efrm library to be used from the SFC
 * resource driver.
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

#ifndef __CI_EFRM_DRIVER_PRIVATE_H__
#define __CI_EFRM_DRIVER_PRIVATE_H__


#include <ci/driver/driverlink_api.h>
#include <ci/efrm/resource.h>
#include <ci/efrm/sysdep.h>

/*--------------------------------------------------------------------
 *
 * global variables
 *
 *--------------------------------------------------------------------*/

/* Internal structure for resource driver */
extern struct efrm_resource_manager *efrm_rm_table[];


/*--------------------------------------------------------------------
 *
 * efrm_nic_table handling
 *
 *--------------------------------------------------------------------*/

struct efrm_nic;
struct vi_resource_dimensions;

extern void efrm_driver_ctor(void);
extern void efrm_driver_stop(void);
extern void efrm_driver_dtor(void);
extern int  efrm_nic_ctor(struct efrm_nic *,
			  const struct vi_resource_dimensions *);
extern void efrm_nic_dtor(struct efrm_nic *);
extern int  efrm_driver_register_nic(struct efrm_nic *);
extern void efrm_driver_unregister_nic(struct efrm_nic *);


/*--------------------------------------------------------------------
 *
 * create/destroy resource managers
 *
 *--------------------------------------------------------------------*/

struct vi_resource_dimensions {
	/* EF10 Only */
	unsigned rss_channel_count;
	unsigned vi_min, vi_lim;
	unsigned vi_base, vi_shift;
#define VI_RES_MEM_BAR_UNDEFINED ((unsigned)~0)
	unsigned mem_bar;
	unsigned vi_stride;

	/* SRIOV Only */
	unsigned vf_vi_base;
	unsigned vf_vi_scale;
	unsigned vf_count;

	/* EF100 only */
	/* 8 is an arbitrary number which is empirically larger than any number
	 * which has been observed to be needed. It can't go too high without
	 * moving this struct off the stack. */
#define IRQ_N_RANGES_MAX 8
	unsigned irq_n_ranges;
	struct irq_ranges {
		unsigned irq_base;
		unsigned irq_range;
	} irq_ranges[IRQ_N_RANGES_MAX];
	void __iomem *irq_prime_reg;
};

/*! Initialise resources */
extern int
efrm_resources_init(void);

/*! Tear down resources */
extern void efrm_resources_fini(void);

#endif /* __CI_EFRM_DRIVER_PRIVATE_H__ */
