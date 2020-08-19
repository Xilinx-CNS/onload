/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains API provided by efhw/nic.c file.  This file is not
 * designed for use outside of the SFC resource driver.
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

#ifndef __CI_EFHW_NIC_H__
#define __CI_EFHW_NIC_H__

#include <ci/efhw/efhw_types.h>
#include <ci/efhw/public.h>
#include <ci/driver/driverlink_api.h>


/* Initialise the device type as appropriate.  Returns false when device is not
 * recognised.
 */
extern int efhw_device_type_init(struct efhw_device_type *dt,
				 struct pci_dev* dev);


/* Initialise fields that do not involve touching hardware. */
#define EFHW_MEM_BAR_UNDEFINED ((unsigned)~0)
extern void efhw_nic_init(struct efhw_nic *nic, unsigned flags,
			  unsigned options, struct efhw_device_type *dev_type,
			  unsigned map_min, unsigned map_max, unsigned vi_base,
			  unsigned vi_shift, unsigned mem_bar, unsigned vi_stride);

/*! Destruct NIC resources */
extern void efhw_nic_dtor(struct efhw_nic *nic);

extern struct pci_dev* efhw_nic_get_pci_dev(struct efhw_nic* nic);
extern struct net_device* efhw_nic_get_net_dev(struct efhw_nic* nic);

/* Driverlink-handle management. */
extern struct efx_dl_device* efhw_nic_acquire_dl_device(struct efhw_nic*);
extern void efhw_nic_release_dl_device(struct efhw_nic*, struct efx_dl_device*);
extern void efhw_nic_flush_dl(struct efhw_nic*);

static inline uint8_t efhw_vi_nic_flags(const struct efhw_nic* nic)
{
	return (nic->flags & NIC_FLAG_BUG35388_WORKAROUND) ?
	       EFHW_VI_NIC_BUG35388_WORKAROUND : 0;
}

#endif /* __CI_EFHW_NIC_H__ */
