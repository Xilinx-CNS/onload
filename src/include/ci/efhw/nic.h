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
#include <ci/driver/driverlink_api.h>


/* Initialise the device type as appropriate.  Returns false when device is not
 * recognised.
 */
extern int efhw_sfc_device_type_init(struct efhw_device_type *dt,
				     struct pci_dev* dev);
extern int efhw_nondl_device_type_init(struct efhw_device_type *dt);


/* Initialise fields that do not involve touching hardware. */
extern void efhw_nic_ctor(struct efhw_nic *nic, unsigned flags,
			  const struct vi_resource_dimensions *nic_res,
			  const struct efhw_device_type *dev_type,
			  struct net_device *net_dev, struct device *dev);
extern void efhw_nic_update_pci_info(struct efhw_nic *nic);

/*! Destruct NIC resources */
extern void efhw_nic_dtor(struct efhw_nic *nic);

extern struct device* efhw_nic_get_dev(struct efhw_nic* nic);
extern struct net_device* efhw_nic_get_net_dev(struct efhw_nic* nic);

/* Driver-handle management. */
extern void* efhw_nic_acquire_drv_device(struct efhw_nic*);
extern void efhw_nic_release_drv_device(struct efhw_nic*, void*);
extern void efhw_nic_flush_drv(struct efhw_nic*);

static inline uint8_t efhw_vi_nic_flags(const struct efhw_nic* nic)
{
	uint8_t flags = 0;
	flags |= (nic->flags & NIC_FLAG_BUG35388_WORKAROUND) ?
		 EFHW_VI_NIC_BUG35388_WORKAROUND : 0;
	flags |= (nic->flags & NIC_FLAG_CTPIO_ONLY) ?
		 EFHW_VI_NIC_CTPIO_ONLY : 0;
	flags |= (nic->flags & NIC_FLAG_RX_SHARED) ?
		 EFHW_VI_NIC_RX_SHARED : 0;
	flags |= (nic->flags & NIC_FLAG_RX_MCAST_REPLICATION) ?
		 EFHW_VI_NIC_RX_MCAST_REPLICATION : 0;
	return flags;
}

extern bool efhw_nic_phys_contig_queue(struct efhw_nic *nic,
				       enum efhw_q_type type);

#endif /* __CI_EFHW_NIC_H__ */
