/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains Linux-specific API internal for the resource driver.
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

#ifndef __LINUX_RESOURCE_INTERNAL__
#define __LINUX_RESOURCE_INTERNAL__

#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/efrm/debug.h>
#include <ci/efrm/driver_private.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/af_xdp.h>

extern void efrm_driverlink_unregister(void);

extern int
efrm_nic_add(void *drv_device, struct device *dev,
	     const struct efhw_device_type *dev_type,
	     struct net_device *net_dev,
	     struct linux_efhw_nic **lnic_inout,
	     const struct vi_resource_dimensions *,
	     unsigned timer_quantum_ns);
extern int
efrm_nic_unplug(struct efhw_nic* nic);
/* Same as _unplug, but also assumes the underlying 'struct device' may go */
extern int
efrm_nic_unplug_hard(struct efhw_nic* nic);
extern void
efrm_nic_del_device(struct net_device *);

extern int efrm_install_proc_entries(void);
extern void efrm_uninstall_proc_entries(void);

extern void efrm_nic_add_sysfs(const struct net_device* net_dev,
			       struct device *dev);
extern void efrm_nic_del_sysfs(struct device *dev);

#ifdef EFHW_HAS_AF_XDP
extern void efrm_install_sysfs_entries(void);
extern void efrm_remove_sysfs_entries(void);
#else
static inline void efrm_install_sysfs_entries(void) {}
static inline void efrm_remove_sysfs_entries(void) {}
#endif

extern void efrm_nondl_register(void);
extern void efrm_nondl_unregister(void);



void efrm_nondl_init(void);
void efrm_nondl_shutdown(void);


int efrm_nondl_unregister_netdev(struct net_device *netdev);
int efrm_nondl_register_netdev(struct net_device *netdev,
			       unsigned int n_vis);


void efrm_notify_nic_probe(const struct efhw_nic* nic,
			   const struct net_device *netdev);
void efrm_notify_nic_remove(const struct efhw_nic* nic);

extern int efrm_nic_set_accel_allowed(struct efhw_nic* nic,
				      int enable);
extern int efrm_nic_get_accel_allowed(struct efhw_nic* nic);

extern struct auxiliary_driver ef10_drv;
extern struct auxiliary_driver efct_drv;
extern struct auxiliary_driver ef10ct_drv;
extern int efrm_auxbus_register(void);
extern void efrm_auxbus_unregister(void);

#endif  /* __LINUX_RESOURCE_INTERNAL__ */
