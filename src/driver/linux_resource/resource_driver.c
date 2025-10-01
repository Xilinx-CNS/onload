/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/*
** Copyright 2005-2012  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains main driver entry points.
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

#include "linux_resource_internal.h"
#include <ci/driver/kernel_compat.h>
#include <ci/efrm/nic_table.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/nic.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/nic_notifier.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efrm/syscall.h>
#include <ci/driver/internal.h>
#include "efrm_internal.h"
#include "sfcaffinity.h"
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/driver/resource/driverlink.h>
#include <linux/reboot.h>
#include "debugfs.h"

MODULE_AUTHOR("Solarflare Communications");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Common resource driver for onload and ef_vi");

static struct efhw_ev_handler ev_handler = {
	.wakeup_fn = efrm_handle_wakeup_event,
	.timeout_fn = efrm_handle_timeout_event,
	.dmaq_flushed_fn = efrm_handle_dmaq_flushed_schedule,
	.efct_rxq_flushed_fn = efrm_handle_efct_rxq_flushed_schedule,
};

const int max_hardware_init_repeats = 1;

/*--------------------------------------------------------------------
 *
 * Module load time variables
 *
 *--------------------------------------------------------------------*/

int pio = 1;
module_param(pio, int, S_IRUGO);
MODULE_PARM_DESC(pio,
                 "Set to 0 to prevent this driver from using PIO");
int efrm_is_pio_enabled(void)
  { return pio; }
EXPORT_SYMBOL(efrm_is_pio_enabled);

static int enable_accel_by_default = 1;
module_param(enable_accel_by_default, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(enable_accel_by_default,
		 "Allow Onload acceleration and use of ef_vi of all network "
		 "devices by default. Individual devices may be enabled or "
		 "disabled by writing to "
		 "/sys/class/net/<name>/device/sfc_resource/enable. "
		 "If this parameter is set to zero then devices must be "
		 "enabled in this way to allow Onload acceleration or "
		 "use of ef_vi.");

int enable_driverlink = 1;
module_param(enable_driverlink, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(enable_driverlink,
		 "Attach SFC devices using native interface."
		 "When disabled, it is possible to attach SFC devices "
		 "with AF_XDP interface.");


/*********************************************************************
 *
 * Export efrm_find_ksym()
 *
 *********************************************************************/

#ifdef EFRM_HAVE_NEW_KALLSYMS

struct efrm_ksym_name {
	const char *name;
	void *addr;
};
static int efrm_check_ksym(void *data, const char *name, struct module *mod,
			  unsigned long addr)
{
	struct efrm_ksym_name *t = data;
	if( strcmp(t->name, name) == 0 ) {
		t->addr = (void *)addr;
		return 1;
	}
	return 0;
}
void *efrm_find_ksym(const char *name)
{
	struct efrm_ksym_name t;

	t.name = name;
	t.addr = NULL;

	/* In kernel versions earlier than 5.12 kallsyms_on_each_symbol could call
	* module_kallsyms_on_each_symbol which would require module_mutex.
	*
	* Since 5.12 kallsyms_on_each_symbol and module_kallsyms_on_each_symbol
	* have been separated, and module_kallsyms_on_each_symbol now acquires the
	* mutex internally. A subsequent change resulted in the mutex no longer
	* being available.
	*
	* For details see:
	* https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit?id=013c1667cf78c1d847152f7116436d82dcab3db4
	* https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit?id=922f2a7c822bf76dffb218331bd95b1eea3cf637
	*/
	#ifdef EFRM_HAVE_MODULE_MUTEX
	mutex_lock(&module_mutex);
	#endif  /* EFRM_HAVE_MODULE_MUTEX */
	kallsyms_on_each_symbol(efrm_check_ksym, &t);
	#ifdef EFRM_HAVE_MODULE_MUTEX
	mutex_unlock(&module_mutex);
	#endif  /* EFRM_HAVE_MODULE_MUTEX */
	return t.addr;
}
EXPORT_SYMBOL(efrm_find_ksym);

#endif  /* EFRM_HAVE_NEW_KALLSYMS */

/*--------------------------------------------------------------------
 *
 * Linux specific NIC initialisation
 *
 *--------------------------------------------------------------------*/


static void
irq_ranges_init(struct efhw_nic *nic, const struct vi_resource_dimensions *res_dim)
{
	unsigned i;

	nic->vi_irq_n_ranges = res_dim->irq_n_ranges;
	if (res_dim->irq_n_ranges == 0)
		return;

	EFRM_ASSERT(res_dim->irq_n_ranges <= NIC_IRQ_MAX_RANGES);
	nic->int_prime_reg = res_dim->irq_prime_reg;
	for (i = 0; i < res_dim->irq_n_ranges; i++ ) {
		nic->vi_irq_ranges[i].base = res_dim->irq_ranges[i].irq_base;
		nic->vi_irq_ranges[i].range = res_dim->irq_ranges[i].irq_range;
	}
}


static int
linux_efrm_nic_ctor(struct linux_efhw_nic *lnic, struct device *dev,
		    struct net_device *net_dev,
		    const struct vi_resource_dimensions *res_dim,
		    const struct efhw_device_type *dev_type,
		    unsigned timer_quantum_ns)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;
	int rc;

	/* Tie the lifetime of the kernel's state to that of our own. */
	if( dev )
		get_device(dev);
	netdev_hold(net_dev, &nic->net_dev_tracker, GFP_KERNEL);

	rc = efhw_nic_ctor(nic, res_dim, dev_type, net_dev, dev,
			   timer_quantum_ns);
	if (rc < 0)
		goto fail1;
	irq_ranges_init(nic, res_dim);

	init_rwsem(&lnic->drv_sem);

	rc = efrm_affinity_interface_probe(lnic);
	if (rc < 0)
		goto fail2;

	rc = efrm_nic_ctor(&lnic->efrm_nic, res_dim);
	if (rc < 0)
		goto fail3;

	if (enable_accel_by_default)
		lnic->efrm_nic.rnic_flags |= EFRM_NIC_FLAG_ADMIN_ENABLED;

	efrm_init_resource_filter(dev ? dev : &net_dev->dev, net_dev->ifindex);

	return 0;
fail3:
	efrm_affinity_interface_remove(lnic);
fail2:
	efhw_nic_dtor(nic);
fail1:
	if( dev )
		put_device(dev);
	netdev_put(net_dev, &nic->net_dev_tracker);
	return rc;
}


/* This should be called instead of linux_efrm_nic_ctor() when reusing existing
 * NIC state (i.e. when a new NIC is compatible with one that had gone away).
 */
static void
linux_efrm_nic_reclaim(struct linux_efhw_nic *lnic,
		       void *drv_device,
		       struct device *dev,
		       struct net_device *net_dev,
		       const struct vi_resource_dimensions *res_dim,
		       const struct efhw_device_type *dev_type,
		       unsigned timer_quantum_ns)
{
	struct efrm_nic *efrm_nic = &lnic->efrm_nic;
	struct efhw_nic* nic = &efrm_nic->efhw_nic;
	struct device* old_dev;
#ifndef NDEBUG
	struct net_device* old_net_dev;
#endif

	/* Replace the net & pci devs */
	get_device(dev);
	netdev_hold(net_dev, &nic->net_dev_tracker, GFP_KERNEL);
	spin_lock_bh(&nic->pci_dev_lock);
	old_dev = nic->dev;
	nic->dev = dev;
#ifndef NDEBUG
	old_net_dev = nic->net_dev;
#endif
	nic->net_dev = net_dev;
	nic->pci_dev = res_dim->pci_dev;
	spin_unlock_bh(&nic->pci_dev_lock);

	/* Replace drv_device. */
	lnic->drv_device = drv_device;

	/* Tell NIC to spread wakeup events. */
	efrm_nic->rss_channel_count = res_dim->rss_channel_count;

	/* Overwrite if better value is known. */
	if (timer_quantum_ns)
		nic->timer_quantum_ns = timer_quantum_ns;

	/* Tidy up old state. */
	efrm_shutdown_resource_filter(old_dev);

	/* Bring up new state. */
	efhw_nic_update_pci_info(nic);
	nic->vi_base = res_dim->vi_base;
	nic->vi_shift = res_dim->vi_shift;
	irq_ranges_init(nic, res_dim);
	efrm_init_resource_filter(nic->dev, net_dev->ifindex);

	/* Drop reference to [old_dev] now that the race window has been
	 * closed for someone else trying to take out a new reference. */
	put_device(old_dev);
	EFRM_ASSERT(old_net_dev == NULL);
}

static void linux_efrm_nic_dtor(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;

	efrm_shutdown_resource_filter(nic->dev);
	efrm_nic_dtor(&lnic->efrm_nic);
	efrm_affinity_interface_remove(lnic);
	efhw_nic_dtor(nic);

	if(nic->dev) {
		put_device(nic->dev);
	}
	EFRM_ASSERT(nic->net_dev == NULL);
}


int efrm_nic_set_accel_allowed(struct efhw_nic* nic,
			       int enable)
{
	struct efrm_nic* rnic = efrm_nic(nic);
	spin_lock_bh(&rnic->lock);
	if (enable)
		rnic->rnic_flags |= EFRM_NIC_FLAG_ADMIN_ENABLED;
	else
		rnic->rnic_flags &=~ EFRM_NIC_FLAG_ADMIN_ENABLED;
	spin_unlock_bh(&rnic->lock);
	return 0;
}


int efrm_nic_get_accel_allowed(struct efhw_nic* nic)
{
	struct efrm_nic* rnic = efrm_nic(nic);
	int enabled;
	spin_lock_bh(&rnic->lock);
	enabled = (rnic->rnic_flags & EFRM_NIC_FLAG_ADMIN_ENABLED) != 0;
	spin_unlock_bh(&rnic->lock);
	return enabled;
}

static void efrm_nic_bringup(struct linux_efhw_nic *lnic)
{
	struct efrm_nic *efrm_nic = NULL;
	struct efhw_nic *nic = NULL;
	struct net_device *net_dev = NULL;
	struct device *dev = NULL;
	int count = 0, rc = 0;

	efrm_nic = &lnic->efrm_nic;
	nic = &efrm_nic->efhw_nic;

	net_dev = nic->net_dev;
	dev = nic->dev;

	/* There is a race here: we need to clear [nic->resetting] so that
	 * efhw_nic_init_hardware() can do MCDI, but that means that any
	 * existing clients can also attempt MCDI, potentially before
	 * efhw_nic_init_hardware() completes. NIC resets already suffer from
	 * an equivalent race. TODO: Fix this, perhaps by introducing an
	 * intermediate degree of resetting-ness during which we can do MCDI
	 * but no-one else can. */
	ci_wmb();
	nic->resetting = 0;

	/****************************************************/
	/* hardware bringup                                 */
	/****************************************************/
	/* Detecting hardware can be a slightly unreliable process;
	 * we want to make sure that we maximise our chances, so we
	 * loop a few times until all is good. */
	for (count = 0; count < max_hardware_init_repeats; count++) {
		rc = efhw_nic_init_hardware(nic, &ev_handler, net_dev->dev_addr);
		if (rc >= 0)
			break;

		/* pain */
		EFRM_TRACE("%s hardware init failed (%d, attempt %d of %d)",
			   dev && dev_name(dev) ? dev_name(dev) : "?",
			   rc, count + 1, max_hardware_init_repeats);
	}
	if (rc < 0) {
		/* Again, PCI VFs may be available. */
		EFRM_ERR("%s: ERROR: hardware init failed rc=%d",
			 dev && dev_name(dev) ? dev_name(dev) : "?", rc);
	}
	efrm_resource_manager_add_total(EFRM_RESOURCE_VI,
					efrm_nic->max_vis);
	efrm_resource_manager_add_total(EFRM_RESOURCE_PD,
					efrm_nic->max_vis);

	EFRM_NOTICE("%s index=%d ifindex=%d",
		    dev ? (dev_name(dev) ? dev_name(dev) : "?") : net_dev->name,
		    nic->index, net_dev->ifindex);

	efrm_nic->dmaq_state.unplugging = 0;

	efrm_nic_enable_post_reset(nic);
	efrm_nic_post_reset(nic);
}

/****************************************************************************
 *
 * efrm_nic_add: add the NIC to the resource driver
 *
 * NOTE: the flow of control through this routine is quite subtle
 * because of the number of operations that can fail. We therefore
 * take the approaching of keeping the return code (rc) variable
 * accurate, and only do operations while it is non-negative. Tear down
 * is done at the end if rc is negative, depending on what has been set up
 * by that point.
 *
 * So basically just make sure that any code you add checks rc>=0 before
 * doing any work and you'll be fine.
 *
 * For probers that support hotplug the original lnic should be obtained by
 * the caller and provided through lnic_inout. If an old device cannot be
 * found, or the prober does not support hotplug, this should be NULL.
 ****************************************************************************/
int
efrm_nic_add(void *drv_device, struct device *dev,
	     const struct efhw_device_type* dev_type,
	     struct net_device *net_dev,
	     struct linux_efhw_nic **lnic_inout,
	     const struct vi_resource_dimensions *res_dim,
	     unsigned timer_quantum_ns)
{
	struct linux_efhw_nic *lnic = *lnic_inout;
	int rc = 0;

	if (lnic != NULL) {
		linux_efrm_nic_reclaim(lnic, drv_device, dev, net_dev, res_dim,
				       dev_type, timer_quantum_ns);

		/* We have now taken ownership of the state and should pull it
		 * down on failure. */
	}
	else {
		rc = efrm_nic_create(drv_device, dev, dev_type, net_dev,
				     &lnic, res_dim, timer_quantum_ns);
		if (rc < 0) {
			EFRM_ERR("%s: ERROR: efrm_nic_create failed (%d)",
				 __func__, rc);
			return rc;
		}

		/* Tell the driver about the NIC - this needs to be done before
		 * the resources managers get created below. Note we haven't
		 * initialised the hardware yet, and I don't like doing this
		 * before the perhaps unreliable hardware initialisation.
		 * However, there's quite a lot of code to review if we wanted
		 * to hardware init before bringing up the resource managers.
		 */
		rc = efrm_driver_register_nic(&lnic->efrm_nic);
		if (rc < 0) {
			EFRM_ERR("%s: ERROR: efrm_driver_register_nic failed "
				 "(%d)", __func__, rc);
			goto failed;
		}

		*lnic_inout = lnic;
	}

	efrm_nic_bringup(lnic);

	return 0;

failed:
	efrm_nic_destroy(lnic);
	return rc;
}

int
efrm_nic_create(void *drv_device, struct device *dev,
		const struct efhw_device_type *dev_type,
		struct net_device *net_dev,
		struct linux_efhw_nic **lnic_inout,
		const struct vi_resource_dimensions *res_dim,
		unsigned timer_quantum_ns)
{
	struct linux_efhw_nic *lnic = *lnic_inout;
	int rc = 0;

	/* Allocate memory for the new adapter-structure. */
	lnic = kzalloc(sizeof(*lnic), GFP_KERNEL);
	if (lnic == NULL) {
		EFRM_ERR("%s: ERROR: failed to allocate memory", __func__);
		return -ENOMEM;
	}

	/* OS specific hardware mappings */
	rc = linux_efrm_nic_ctor(lnic, dev, net_dev, res_dim, dev_type,
				 timer_quantum_ns);
	if (rc < 0) {
		EFRM_ERR("%s: ERROR: linux_efrm_nic_ctor failed (%d)",
			 __func__, rc);
		goto failed;
	}

	lnic->drv_device = drv_device;

	*lnic_inout = lnic;
	return 0;

failed:
	kfree(lnic);
	return rc;
}

/* This is called when we fail to fully initialise the efrm_nic. Although the
 * linux_efrm_nic_ctor takes a reference to the net dev for this NIC, the dtor
 * expects the reference to have already been dropped before it is called.
 * This is because the net dev ref is dropped on NIC unplug, but we retain
 * the NIC at that point, to support hotplug. Because we haven't fully gone
 * through the init stage here, we don't do a full unplug at this point, but
 * instead just drop the net dev ref, allowing us to call the dtor to do the
 * rest of the tidyup. */
void
efrm_nic_destroy(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;
	if(nic->net_dev) {
		dev_put(nic->net_dev);
		nic->net_dev = NULL;
	}
	linux_efrm_nic_dtor(lnic);
	kfree(lnic);
}

int
efrm_nic_register(struct linux_efhw_nic *lnic)
{
	/* Repeat the efrm_nic_add() workflow for the new NIC. */
	int rc = efrm_driver_register_nic(&lnic->efrm_nic);
	if (rc < 0) {
		EFRM_ERR("%s: ERROR: efrm_driver_register_nic failed "
			 "(%d)", __func__, rc);
		return rc;
	}

	efrm_nic_bringup(lnic);

	return 0;
}


/* "hard" mode declares that the underlying struct device* should be discarded
 * too. This applies to cases where it's some kind of software device (e.g.
 * aux bus, AF_XDP) which can be made to disappear at any time (now that we've
 * decrefed the net_device). When the dev is a real PCI device then it's worth
 * keeping it around so that we can reattach to a new NIC which hot-plugged
 * back in to the slot. */
static int
efrm_nic_do_unplug(struct efhw_nic* nic, bool hard)
{
	struct net_device* net_dev;
	struct device* dev = NULL;
	struct efrm_nic *efrm_nic = efrm_nic(nic);

	efhw_nic_release_hardware(nic);
	if (hard) {
		/* Filter tables are tracked by device (for management reasons), so if
		 * we're getting rid of the device then we'd best drop the filter
		 * table(s) too */
		EFRM_ASSERT(nic->dev != NULL);
		efrm_shutdown_resource_filter(nic->dev);

		efrm_interrupt_vectors_release(efrm_nic);
	}

	/* We keep the pci device to reclaim it after hot-plug, but release
	 * the net device. */
	spin_lock_bh(&nic->pci_dev_lock);
	net_dev = nic->net_dev;
	nic->net_dev = NULL;
	if (hard) {
		dev = nic->dev;
		nic->dev = NULL;
	}
	spin_unlock_bh(&nic->pci_dev_lock);

	EFRM_ASSERT(net_dev != NULL);
	netdev_put(net_dev, &nic->net_dev_tracker);
	put_device(dev);

	return 0;
}


int
efrm_nic_unplug(struct efhw_nic* nic)
{
	return efrm_nic_do_unplug(nic, false);
}


int
efrm_nic_unplug_hard(struct efhw_nic* nic)
{
	return efrm_nic_do_unplug(nic, true);
}


/****************************************************************************
 *
 * efrm_nic_shutdown: Shut down our access to the NIC hw
 *
 * Note: After execution of this function device is no longer associated with
 *       net_device
 *
 ****************************************************************************/
static void efrm_nic_shutdown(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;

	EFRM_TRACE("%s:", __func__);
	EFRM_ASSERT(nic);

	/* Absent hardware is treated as a protracted reset. */
	efrm_nic_reset_suspend(nic);
	ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_UNPLUGGED);

	efrm_vi_wait_nic_complete_flushes(nic);
	linux_efrm_nic_dtor(lnic);

	efrm_resource_manager_del_total(EFRM_RESOURCE_VI,
					lnic->efrm_nic.max_vis);
	efrm_resource_manager_del_total(EFRM_RESOURCE_PD,
					lnic->efrm_nic.max_vis);

	EFRM_TRACE("%s: done", __func__);
}
/****************************************************************************
 *
 * efrm_nic_del: Remove the nic from the resource driver structures
 *
 ****************************************************************************/
static void efrm_nic_del(struct linux_efhw_nic *lnic)
{
	EFRM_TRACE("%s:", __func__);

	efrm_driver_unregister_nic(&lnic->efrm_nic);
	kfree(lnic);

	EFRM_TRACE("%s: done", __func__);
}

/* Completely removes device from efrm.
 *
 * Removal from efrm happens in two stages, unplug and delete. Devices that
 * support hotplug should only be efrm_nic_unplug()ed on removal, which will
 * leave sufficient state in efrm to recognise them on return. If we don't
 * support hotplug then the device should be fully deleted, which is what this
 * function is for. If the device subsequently returns it will be handled as
 * completely new device.
 *
 * Requires the caller holds the rtnl lock.
 *
 * Note: after shutdown device has no associated net_device meaning
 *       the removal needs to be done in one step.
 */
void efrm_nic_del_device(struct net_device *net_dev)
{
	int i;
	struct efhw_nic* nic;

	ASSERT_RTNL();

	EFRM_TRACE("%s:", __func__);
	EFRM_FOR_EACH_NIC(i, nic) {
		if( nic->net_dev == net_dev ) {
			efrm_nic_unplug(nic);
			efrm_nic_shutdown(linux_efhw_nic(nic));
			efrm_nic_del(linux_efhw_nic(nic));
		}
	}
	EFRM_TRACE("%s: done", __func__);
}

/****************************************************************************
 *
 * efrm_nic_del_all: Shut down our access to any hw or driverlink
 *
 ****************************************************************************/
static void efrm_nic_shutdown_all(void)
{
	int i;
	struct efhw_nic* nic;

	EFRM_FOR_EACH_NIC(i, nic)
		efrm_nic_shutdown(linux_efhw_nic(nic));
}
/****************************************************************************
 *
 * efrm_nic_del_all: Delete all remaining efrm_nics. Call this before
 * efrm_driver_stop().
 *
 ****************************************************************************/
static void efrm_nic_del_all(void)
{
	int i;
	struct efhw_nic* nic;

	EFRM_FOR_EACH_NIC(i, nic)
		efrm_nic_del(linux_efhw_nic(nic));
}

static int sfc_resource_shutdown_notify(struct notifier_block *unused1,
				        unsigned long unused2, void *unused3)
{
	/* Due to refcounting reasons in netdev, these must
	 * be called for the shutdown to happen without delays
	 */
	efrm_nondl_unregister();
	efrm_nondl_shutdown();

	return NOTIFY_DONE;
}

static struct notifier_block sfc_resource_shutdown_nb = {
	.notifier_call = sfc_resource_shutdown_notify,
};

/****************************************************************************
 *
 * init_module: register as a PCI driver.
 *
 ****************************************************************************/
static int init_sfc_resource(void)
{
	int rc = 0;

	EFRM_TRACE("%s: RESOURCE driver starting", __func__);

	rc = efrm_syscall_ctor();
	if( rc != 0 ) {
		EFRM_ERR("%s: ERROR: failed to find syscall table", __func__);
		return rc;
	}

	efrm_driver_ctor();

	rc = efrm_resources_init();
	if( rc != 0 ) {
		EFRM_ERR("%s: ERROR: init resources", __func__);
		goto failed_resources;
	}

	efrm_filter_init();

	efrm_init_debugfs();

        /* efrm_auxbus_register() attempts to create files in
         * /proc, so it is important that /proc is initialised
         * first. */
	if (efrm_install_proc_entries() != 0) {
		/* Do not fail, but print a warning */
		EFRM_WARN("%s: WARNING: failed to install /proc entries",
			  __func__);
	}
	efrm_filter_install_proc_entries();

	rc = efrm_auxbus_register();
	if (rc < 0)
		goto failed_auxbus;

	rc = efrm_register_netdev_notifier();
	if (rc < 0)
		goto failed_notifier;

	efrm_nondl_init();
	efrm_install_sysfs_entries();
	efrm_nondl_register();

	register_reboot_notifier(&sfc_resource_shutdown_nb);

	return 0;

failed_notifier:
	efrm_auxbus_unregister();
failed_auxbus:
	efrm_filter_remove_proc_entries();
	efrm_uninstall_proc_entries();
	efrm_driver_stop();
	efrm_filter_shutdown();
	efrm_resources_fini();
failed_resources:
	efrm_driver_dtor();
	return rc;
}

/****************************************************************************
 *
 * cleanup_module: module-removal entry-point
 *
 ****************************************************************************/
static void cleanup_sfc_resource(void)
{
	unregister_reboot_notifier(&sfc_resource_shutdown_nb);

	efrm_nondl_unregister();
	efrm_remove_sysfs_entries();
	efrm_nondl_shutdown();
	efrm_unregister_netdev_notifier();
	efrm_auxbus_unregister();
	efrm_nic_shutdown_all();
	efrm_nic_del_all();

	efrm_filter_shutdown();
	efrm_filter_remove_proc_entries();
	efrm_uninstall_proc_entries();
	efrm_fini_debugfs();

	efrm_driver_stop();
	efrm_resources_fini();

	/* Clean up char-driver specific initialisation.
	   - driver dtor can use both work queue and buffer table entries */
	efrm_driver_dtor();

	EFRM_TRACE("%s: unloaded", __func__);
}

module_init(init_sfc_resource);
module_exit(cleanup_sfc_resource);
