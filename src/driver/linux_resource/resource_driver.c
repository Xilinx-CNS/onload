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
#include <ci/driver/driverlink_api.h>
#include <ci/efrm/nic_table.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/nic.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efrm/syscall.h>
#include <ci/driver/internal.h>
#include "efrm_internal.h"
#include "sfcaffinity.h"
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/driver/resource/driverlink.h>

MODULE_AUTHOR("Solarflare Communications");
MODULE_LICENSE("GPL");

static struct efhw_ev_handler ev_handler = {
	.wakeup_fn = efrm_handle_wakeup_event,
	.timeout_fn = efrm_handle_timeout_event,
	.dmaq_flushed_fn = efrm_handle_dmaq_flushed_schedule,
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
				 "Attach SFC devices using driverlink interface."
				 "When disabled, it is possible to attach SFC devices "
				 "with AF_XDP interface.");

#ifdef HAS_COMPAT_PAT_WC
static int compat_pat_wc_inited = 0;
#endif

/*********************************************************************
 *
 * Export efrm_find_ksym()
 *
 *********************************************************************/

#ifdef ERFM_HAVE_NEW_KALLSYMS

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
	mutex_lock(&module_mutex);
	kallsyms_on_each_symbol(efrm_check_ksym, &t);
	mutex_unlock(&module_mutex);
	return t.addr;
}
EXPORT_SYMBOL(efrm_find_ksym);

#endif  /* ERFM_HAVE_NEW_KALLSYMS */

/*--------------------------------------------------------------------
 *
 * Linux specific NIC initialisation
 *
 *--------------------------------------------------------------------*/

/* Free buffer table entries allocated for a particular NIC.
 */
static int iomap_bar(struct linux_efhw_nic *lnic, size_t len)
{
	volatile char __iomem *ioaddr;

	ioaddr = ci_ioremap(lnic->efrm_nic.efhw_nic.ctr_ap_dma_addr, len);
	if (ioaddr == 0)
		return -ENOMEM;

	lnic->efrm_nic.efhw_nic.bar_ioaddr = ioaddr;
	return 0;
}

static int linux_efhw_nic_map_ctr_ap(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;
	int rc = 0;

	if (nic->devtype.arch == EFHW_ARCH_EF10 ||
	    nic->devtype.arch == EFHW_ARCH_EF100) {
		if (nic->ctr_ap_bytes == 0)
			return 0;

		rc = iomap_bar(lnic, nic->ctr_ap_bytes);

		/* Bug 5195: workaround for now. */
		if (rc != 0 && nic->ctr_ap_bytes > 16 * 1024 * 1024) {
			/* Try half the size for now. */
			nic->ctr_ap_bytes /= 2;
			EFRM_WARN("Bug 5195 WORKAROUND: retrying iomap of %d "
				  "bytes", nic->ctr_ap_bytes);
			rc = iomap_bar(lnic, nic->ctr_ap_bytes);
		}
		if (rc < 0) {
			EFRM_ERR("Failed (%d) to map bar (%d bytes)",
				 rc, nic->ctr_ap_bytes);
			return rc;
		}
	}
	else if (nic->devtype.arch == EFHW_ARCH_AF_XDP) {
		/* we need a page for a VI */
		unsigned long space_needed = nic->vi_lim * PAGE_SIZE;
		int order = get_order(space_needed);
		unsigned long addr = __get_free_pages(GFP_KERNEL, order);

		if(addr == 0)
			return -ENOMEM;

		lnic->efrm_nic.efhw_nic.bar_ioaddr = (void *)addr;
		memset((void *)lnic->efrm_nic.efhw_nic.bar_ioaddr,
			   0, nic->vi_lim * PAGE_SIZE);
		lnic->efrm_nic.efhw_nic.ctr_ap_dma_addr = __pa(addr);
	}

	return rc;
}

static void linux_efhw_nic_unmap_ctr_ap(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;

	if (nic->devtype.arch == EFHW_ARCH_AF_XDP) {
		unsigned long space_needed = nic->vi_lim * PAGE_SIZE;
		int order = get_order(space_needed);
		free_pages((unsigned long)nic->bar_ioaddr, order);
	}
	else if (nic->bar_ioaddr) {
		iounmap(nic->bar_ioaddr);
	}
	nic->bar_ioaddr = 0;
}


/* Determines whether the control BAR for the device [dev] is where we expect
 * it to be for the NIC [nic]. This is a requirement for hotplug
 * revivification. */
static inline int
efrm_nic_bar_is_good(struct efhw_nic* nic, struct pci_dev* dev)
{
	return !dev || nic->ctr_ap_dma_addr == pci_resource_start(dev, nic->ctr_ap_bar);
}


static void
irq_ranges_init(struct efhw_nic *nic, const struct vi_resource_dimensions *res_dim)
{
	unsigned i;
	unsigned n_irqs = 0;

	if (res_dim->irq_n_ranges == 0)
		return;

	EFRM_ASSERT(res_dim->irq_n_ranges <= NIC_IRQ_MAX_RANGES);
	nic->int_prime_reg = res_dim->irq_prime_reg;
	nic->vi_irq_n_ranges = res_dim->irq_n_ranges;
	for (i = 0; i < res_dim->irq_n_ranges; i++ ) {
		nic->vi_irq_ranges[i].base = res_dim->irq_ranges[i].irq_base;
		nic->vi_irq_ranges[i].range = res_dim->irq_ranges[i].irq_range;
		n_irqs += nic->vi_irq_ranges[i].range;
	}

	/* For EF100 the number of VIs must match number of IRQs.
	 * See ON-10914.
	 */
	if (nic->devtype.arch == EFHW_ARCH_EF100 &&
	    n_irqs < nic->vi_lim - nic->vi_min) {
		nic->vi_lim = nic->vi_min + n_irqs;
	}
}


static int
linux_efrm_nic_ctor(struct linux_efhw_nic *lnic, struct pci_dev *dev,
		    unsigned nic_flags,
		    struct net_device *net_dev,
		    const struct vi_resource_dimensions *res_dim,
		    const struct efhw_device_type *dev_type)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;
	int rc;
	unsigned map_min, map_max;
	unsigned vi_base = 0;
	unsigned vi_shift = 0;
	unsigned mem_bar = EFHW_MEM_BAR_UNDEFINED;
	unsigned vi_stride = 0;

	/* Tie the lifetime of the kernel's state to that of our own. */
	if( dev )
		pci_dev_get(dev);
	dev_hold(net_dev);

	if (dev_type->arch == EFHW_ARCH_EF10 ||
	    dev_type->arch == EFHW_ARCH_EF100) {
		map_min = res_dim->vi_min;
		map_max = res_dim->vi_lim;
		vi_base = res_dim->vi_base;
		vi_shift = res_dim->vi_shift;
		if( res_dim->mem_bar != VI_RES_MEM_BAR_UNDEFINED )
			mem_bar = res_dim->mem_bar;
		vi_stride = res_dim->vi_stride;
	}
	else if (dev_type->arch == EFHW_ARCH_AF_XDP) {
		map_min = res_dim->vi_min;
		map_max = res_dim->vi_lim;;
	}
	else {
		rc = -EINVAL;
		goto fail;
	}

	efhw_nic_init(nic, nic_flags, NIC_OPT_DEFAULT, dev_type, map_min,
		      map_max, vi_base, vi_shift, mem_bar, vi_stride, net_dev,
		      dev);
	if( dev ) {
		lnic->efrm_nic.efhw_nic.ctr_ap_dma_addr = pci_resource_start(dev, nic->ctr_ap_bar);
	}
	EFRM_WARN("%s: ctr_ap_dma_addr=%p", __func__,
		  (void*) lnic->efrm_nic.efhw_nic.ctr_ap_dma_addr);
	irq_ranges_init(nic, res_dim);

	EFRM_ASSERT(!dev || dev_type->arch == EFHW_ARCH_AF_XDP ||
                    efrm_nic_bar_is_good(nic, dev));

	spin_lock_init(&lnic->efrm_nic.efhw_nic.pci_dev_lock);
	init_rwsem(&lnic->drv_sem);

	rc = linux_efhw_nic_map_ctr_ap(lnic);
	if (rc < 0)
		goto fail;

	rc = efrm_affinity_interface_probe(lnic);
	if (rc < 0)
		goto fail;

	rc = efrm_nic_ctor(&lnic->efrm_nic, res_dim);
	if (rc < 0) {
		linux_efhw_nic_unmap_ctr_ap(lnic);
		goto fail2;
	}

	if (enable_accel_by_default)
		lnic->efrm_nic.rnic_flags |= EFRM_NIC_FLAG_ADMIN_ENABLED;

	efrm_init_resource_filter(dev ? &dev->dev : &net_dev->dev, net_dev->ifindex);

	return 0;
fail2:
	efrm_affinity_interface_remove(lnic);
fail:
	if( dev )
		pci_dev_put(dev);
	dev_put(net_dev);
	return rc;
}


/* This should be called instead of linux_efrm_nic_ctor() when reusing existing
 * NIC state (i.e. when a new NIC is compatible with one that had gone away).
 */
static void
linux_efrm_nic_reclaim(struct linux_efhw_nic *lnic,
                       struct pci_dev *dev,
		       struct net_device *net_dev,
		       const struct vi_resource_dimensions *res_dim,
                       const struct efhw_device_type *dev_type)
{
	struct efhw_nic* nic = &lnic->efrm_nic.efhw_nic;
	struct pci_dev* old_pci_dev;
#ifndef NDEBUG
	struct net_device* old_net_dev;
#endif

	/* Replace the net & pci devs */
	pci_dev_get(dev);
	dev_hold(net_dev);
	spin_lock_bh(&nic->pci_dev_lock);
	old_pci_dev = nic->pci_dev;
	nic->pci_dev = dev;
#ifndef NDEBUG
	old_net_dev = nic->net_dev;
#endif
	nic->net_dev = net_dev;
	spin_unlock_bh(&nic->pci_dev_lock);

	/* Tidy up old state. */
	efrm_shutdown_resource_filter(&old_pci_dev->dev);

	/* Bring up new state. */
	efhw_nic_update_pci_info(nic);
	if (dev_type->arch == EFHW_ARCH_EF10) {
		nic->vi_base = res_dim->vi_base;
	}
	efrm_init_resource_filter(&nic->pci_dev->dev, net_dev->ifindex);

	/* Drop reference to [old_pci_dev] now that the race window has been
	 * closed for someone else trying to take out a new reference. */
	pci_dev_put(old_pci_dev);
	EFRM_ASSERT(old_net_dev == NULL);
}

static void linux_efrm_nic_dtor(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;

	efrm_shutdown_resource_filter(&nic->pci_dev->dev);
	efrm_nic_dtor(&lnic->efrm_nic);
	efrm_affinity_interface_remove(lnic);
	linux_efhw_nic_unmap_ctr_ap(lnic);
	efhw_nic_dtor(nic);

	if(nic->pci_dev) {
		pci_dev_put(nic->pci_dev);
	}
	EFRM_ASSERT(nic->net_dev == NULL);
}


/* Determines whether a known NIC is equivalent to one that would be
 * instantiated according to a [pci_dev] and an [efhw_device_type]. The
 * intended use-case is to check whether a new NIC can step into the shoes of
 * one that went away. */
static inline int
efrm_nic_matches_device(struct efhw_nic* nic, const struct pci_dev* dev,
			const struct efhw_device_type* dev_type)
{
	struct pci_dev* nic_dev = efhw_nic_get_pci_dev(nic);
	int result = nic->domain           == pci_domain_nr(dev->bus) &&
		     nic->bus_number	   == dev->bus->number	 &&
		     nic_dev->devfn	   == dev->devfn	 &&
		     nic_dev->device	   == dev->device	 &&
		     nic->devtype.arch	   == dev_type->arch	 &&
		     nic->devtype.revision == dev_type->revision &&
		     nic->devtype.variant  == dev_type->variant;
	pci_dev_put(nic_dev);
	return result;
}


static struct linux_efhw_nic*
efrm_get_redisovered_nic(struct pci_dev* dev,
			 const struct efhw_device_type* dev_type)
{
	struct linux_efhw_nic* lnic = NULL;
	struct efhw_nic* old_nic;
	int nic_index;

	/* We can't detect hotplug without the pci information to compare */
	if( !dev )
		return NULL;

	spin_lock_bh(&efrm_nic_tablep->lock);
	EFRM_FOR_EACH_NIC(nic_index, old_nic) {
		/* We would like to break out of this loop after rediscovering
		 * a NIC, but the EFRM_FOR_EACH_NIC construct doesn't allow
		 * this, so instead we check explicitly that we haven't set
		 * [lnic] yet. */
		if (lnic == NULL && old_nic != NULL &&
			efrm_nic_matches_device(old_nic, dev, dev_type)) {
			EFRM_ASSERT(old_nic->resetting);
			if (efrm_nic_bar_is_good(old_nic, dev)) {
				EFRM_NOTICE("%s: Rediscovered nic_index %d",
					    __func__, nic_index);
				lnic = linux_efhw_nic(old_nic);
			}
			else {
				EFRM_WARN("%s: New device matches nic_index %d "
					  "but has different BAR. Existing "
					  "Onload stacks will not use the new "
					  "device.",
					  __func__, nic_index);
			}
		}
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);
	/* We can drop the lock now as [lnic] will not go away until the module
	 * unloads. */

	return lnic;
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

/****************************************************************************
 *
 * efrm_nic_add: add the NIC to the resource driver
 *
 * NOTE: the flow of control through this routine is quite subtle
 * because of the number of operations that can fail. We therefore
 * take the apporaching of keeping the return code (rc) variable
 * accurate, and only do operations while it is non-negative. Tear down
 * is done at the end if rc is negative, depending on what has been set up
 * by that point.
 *
 * So basically just make sure that any code you add checks rc>=0 before
 * doing any work and you'll be fine.
 *
 * TODO AF_XDP: more elegantly handle non-driverlink devices
 ****************************************************************************/
int
efrm_nic_add(void *drv_device, struct pci_dev *dev,
	     const struct efhw_device_type* dev_type, unsigned flags,
	     struct net_device *net_dev,
	     struct linux_efhw_nic **lnic_out,
	     const struct vi_resource_dimensions *res_dim,
	     unsigned timer_quantum_ns)
{
	struct linux_efhw_nic *lnic = NULL;
	struct efrm_nic *efrm_nic = NULL;
	struct efhw_nic *nic = NULL;
	int count = 0, rc = 0;
	int constructed = 0;
	int registered_nic = 0;

	lnic = efrm_get_redisovered_nic(dev, dev_type);
	if (lnic != NULL) {
		linux_efrm_nic_reclaim(lnic, dev, net_dev, res_dim,
				       dev_type);
		/* We have now taken ownership of the state and should pull it
		 * down on failure. */
		constructed = registered_nic = 1;
	}
	else {
		/* Allocate memory for the new adapter-structure. */
		lnic = kmalloc(sizeof(*lnic), GFP_KERNEL);
		if (lnic == NULL) {
			EFRM_ERR("%s: ERROR: failed to allocate memory",
				 __func__);
			rc = -ENOMEM;
			goto failed;
		}
		memset(lnic, 0, sizeof(*lnic));

		lnic->ev_handlers = &ev_handler;

		/* OS specific hardware mappings */
		rc = linux_efrm_nic_ctor(lnic, dev, flags,
					 net_dev, res_dim, dev_type);
		if (rc < 0) {
			EFRM_ERR("%s: ERROR: linux_efrm_nic_ctor failed (%d)",
				 __func__, rc);
			goto failed;
		}
		constructed = 1;

		/* Tell the driver about the NIC - this needs to be done before
		   the resources managers get created below. Note we haven't
		   initialised the hardware yet, and I don't like doing this
		   before the perhaps unreliable hardware initialisation.
		   However, there's quite a lot of code to review if we wanted
		   to hardware init before bringing up the resource managers.
		   */
		rc = efrm_driver_register_nic(&lnic->efrm_nic);
		if (rc < 0) {
			EFRM_ERR("%s: ERROR: efrm_driver_register_nic failed "
				 "(%d)", __func__, rc);
			goto failed;
		}
		registered_nic = 1;
	}

	lnic->drv_device = drv_device;
	efrm_nic = &lnic->efrm_nic;
	nic = &efrm_nic->efhw_nic;
	efrm_driverlink_resume(nic);

	if( timer_quantum_ns )
		nic->timer_quantum_ns = timer_quantum_ns;

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
	   we want to make sure that we maximise our chances, so we
	   loop a few times until all is good. */
	for (count = 0; count < max_hardware_init_repeats; count++) {
		rc = efhw_nic_init_hardware(nic, &ev_handler, net_dev->dev_addr);
		if (rc >= 0)
			break;

		/* pain */
		EFRM_TRACE("%s hardware init failed (%d, attempt %d of %d)",
			   dev && pci_name(dev) ? pci_name(dev) : "?",
			   rc, count + 1, max_hardware_init_repeats);
	}
	if (rc < 0) {
		/* Again, PCI VFs may be available. */
		EFRM_ERR("%s: ERROR: hardware init failed rc=%d",
			 dev && pci_name(dev) ? pci_name(dev) : "?", rc);
	}
	efrm_resource_manager_add_total(EFRM_RESOURCE_VI,
					efrm_nic->max_vis);
	efrm_resource_manager_add_total(EFRM_RESOURCE_PD,
					efrm_nic->max_vis);

	/* Tell NIC to spread wakeup events. */
	efrm_nic->rss_channel_count = res_dim->rss_channel_count;

	EFRM_NOTICE("%s index=%d ifindex=%d",
		    dev ? (pci_name(dev) ? pci_name(dev) : "?") : net_dev->name,
		    nic->index, net_dev->ifindex);

	efrm_nic->dmaq_state.unplugging = 0;

	*lnic_out = lnic;
	efrm_nic_enable_post_reset(nic);
	efrm_nic_post_reset(nic);

	return 0;

failed:
	if (registered_nic)
		efrm_driver_unregister_nic(efrm_nic);
	if (constructed)
		linux_efrm_nic_dtor(lnic);
	kfree(lnic); /* safe in any case */
	return rc;
}

int
efrm_nic_unplug(struct efhw_nic* nic)
{
	struct net_device* net_dev;

	efhw_nic_release_hardware(nic);

	/* We keep the pci device to reclaim it after hot-plug, but release
	 * the net device. */
	spin_lock_bh(&nic->pci_dev_lock);
	net_dev = nic->net_dev;
	nic->net_dev = NULL;
	spin_unlock_bh(&nic->pci_dev_lock);

	EFRM_ASSERT(net_dev != NULL);
	dev_put(net_dev);

	return 0;
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

        /* efrm_driverlink_register() attempts to create files in
         * /proc, so it is important that /proc is initialised
         * first. */

	if (efrm_install_proc_entries() != 0) {
		/* Do not fail, but print a warning */
		EFRM_WARN("%s: WARNING: failed to install /proc entries",
			  __func__);
	}
	efrm_filter_install_proc_entries();

	/* Register the driver so that our 'probe' function is called for
	 * each EtherFabric device in the system.
	 */
	rc = efrm_driverlink_register();
	if (rc == -ENODEV)
		EFRM_ERR("%s: no devices found", __func__);
	if (rc < 0)
		goto failed_driverlink;

	efrm_nondl_init();
	efrm_install_sysfs_entries();
	efrm_nondl_register();

#ifdef HAS_COMPAT_PAT_WC
	compat_pat_wc_inited = 0;
	if (pio)
		if (compat_pat_wc_init() == 0)
			compat_pat_wc_inited = 1;
#endif

	return 0;

failed_driverlink:
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
#ifdef HAS_COMPAT_PAT_WC
	if (compat_pat_wc_inited) {
		compat_pat_wc_inited = 0;
		compat_pat_wc_shutdown();
	}
#endif

	efrm_nondl_unregister();
	efrm_remove_sysfs_entries();
	efrm_nondl_shutdown();
	/* Unregister from driverlink first, free
	 * the per-NIC structures next. */
	efrm_driverlink_unregister();
	efrm_nic_shutdown_all();
	efrm_nic_del_all();

	efrm_filter_shutdown();
	efrm_filter_remove_proc_entries();
	efrm_uninstall_proc_entries();

	efrm_driver_stop();
	efrm_resources_fini();

	/* Clean up char-driver specific initialisation.
	   - driver dtor can use both work queue and buffer table entries */
	efrm_driver_dtor();

	EFRM_TRACE("%s: unloaded", __func__);
}

module_init(init_sfc_resource);
module_exit(cleanup_sfc_resource);
