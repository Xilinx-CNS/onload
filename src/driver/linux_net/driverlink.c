/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005      Fen Systems Ltd.
 * Copyright 2005-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/module.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include "net_driver.h"

/* Global lists are protected by rtnl_lock */

/* List of all registered drivers */
static LIST_HEAD(efx_driver_list);

/* List of all registered devices. Protected by the rtnl_lock */
static LIST_HEAD(efx_nic_list);

/**
 * Internal extension of efx_dev
 * @efx_dev: driverlink device handle exported to consumers
 * @efx: efx_nic backing the driverlink device
 * @nic_node: per-device list node
 * @driver_node: per-driver list node
 * @block_kernel_count: Number of times client has requested each kernel block,
 *     indexed by enum efx_dl_filter_block_kernel_type
 */
struct efx_dl_handle {
	struct efx_dl_device efx_dev;
	struct list_head nic_node;
	struct list_head driver_node;
	unsigned int block_kernel_count[EFX_DL_FILTER_BLOCK_KERNEL_MAX];
};

static struct efx_dl_handle *efx_dl_handle(struct efx_dl_device *efx_dev)
{
	return container_of(efx_dev, struct efx_dl_handle, efx_dev);
}

/* Warn if a driverlink call takes longer than 1 second */
#define EFX_DL_DURATION_WARN (1 * HZ)
/* Onload probe verifies a SW licenses which can take >1s. See SFC bug 62649 */
#define EFX_DL_DURATION_PROBE_WARN (3 * HZ)

#define _EFX_DL_CHECK_DURATION(duration, limit, label)				\
	do {									\
		if ((duration) > (limit) &&					\
		    !efx_dev->nic->ops->hw_unavailable(efx_dev))		\
			netif_warn(efx_dev->nic, drv, efx_dev->nic->net_dev,	\
				   "%s: driverlink " label " took %ums\n",	\
				   efx_dev->driver->name,			\
				   jiffies_to_msecs(duration));			\
	} while (0)
#define EFX_DL_CHECK_DURATION(duration, label) \
   _EFX_DL_CHECK_DURATION(duration, EFX_DL_DURATION_WARN, label)
#define EFX_DL_CHECK_DURATION_PROBE(duration, label) \
   _EFX_DL_CHECK_DURATION(duration, EFX_DL_DURATION_PROBE_WARN, label)

/* Remove an Efx device, and call the driver's remove() callback if
 * present. The caller must hold rtnl_lock. */
static void efx_dl_del_device(struct efx_dl_device *efx_dev)
{
	struct efx_dl_handle *efx_handle = efx_dl_handle(efx_dev);
	struct efx_dl_nic *nic = efx_dev->nic;
	unsigned int type;
	u64 before, after, duration;

	netif_info(nic, drv, nic->net_dev,
		   "%s driverlink client unregistering\n",
		   efx_dev->driver->name);

	before = get_jiffies_64();

	if (efx_dev->driver->remove)
		efx_dev->driver->remove(efx_dev);

	after = get_jiffies_64();
	duration = after - before;
	EFX_DL_CHECK_DURATION(duration, "remove()");

	list_del(&efx_handle->driver_node);

	/* Disable and then re-enable NAPI when removing efx interface from list
	 * to prevent a race with read access from NAPI context; napi_disable()
	 * ensures that NAPI is no longer running when it returns.  Also
	 * internally lock NAPI while disabled to prevent busy-polling.
	 */
	nic->ops->pause(efx_dev);
	list_del(&efx_handle->nic_node);
	nic->ops->resume(efx_dev);

	/* Remove this client's kernel blocks */
	for (type = 0; type < EFX_DL_FILTER_BLOCK_KERNEL_MAX; type++)
		while (efx_handle->block_kernel_count[type])
			efx_dl_filter_unblock_kernel(efx_dev, type);

	kfree(efx_handle);
}

/* Attempt to probe the given device with the driver, creating a
 * new &struct efx_dl_device. If the probe routine returns an error,
 * then the &struct efx_dl_device is destroyed */
static void efx_dl_try_add_device(struct efx_dl_nic *nic,
				  struct efx_dl_driver *driver)
{
	struct efx_dl_handle *efx_handle;
	struct efx_dl_handle *ex_efx_handle;
	struct efx_dl_device *efx_dev;
	struct net_device *net_dev = nic->net_dev;
	int rc;
	bool added = false;
	u64 before, after, duration;

	/* First check if device is supported by driver */
	if ((nic->pci_dev->device & 0x0f00) >= 0x0b00 &&
	    !(driver->flags & EFX_DL_DRIVER_CHECKS_MEDFORD2_VI_STRIDE)) {
		netif_info(nic, drv, net_dev,
			   "%s driverlink client skipped: does not support X2 adapters\n",
			   driver->name);
		return;
	}

	efx_handle = kzalloc(sizeof(*efx_handle), GFP_KERNEL);
	if (!efx_handle)
		goto fail;
	efx_dev = &efx_handle->efx_dev;
	efx_dev->driver = driver;
	efx_dev->nic = nic;
	efx_dev->pci_dev = nic->pci_dev;
	INIT_LIST_HEAD(&efx_handle->nic_node);
	INIT_LIST_HEAD(&efx_handle->driver_node);

	before = get_jiffies_64();

	rc = driver->probe(efx_dev, net_dev, nic->dl_info, "");

	after = get_jiffies_64();
	duration = after - before;
#if defined(EFX_WORKAROUND_62649)
	EFX_DL_CHECK_DURATION_PROBE(duration, "probe()");
#else
	EFX_DL_CHECK_DURATION(duration, "probe()");
#endif

	if (rc)
		goto fail;

	/* Rather than just add to the end of the list,
	 * find the point that is at the end of the desired priority level
	 * and insert there. This will ensure that remove() callbacks are
	 * called in the reverse of the order of insertion.
	 */

	list_for_each_entry(ex_efx_handle, &nic->device_list, nic_node) {
		if (ex_efx_handle->efx_dev.driver->priority >
			driver->priority) {
			list_add_tail(&efx_handle->nic_node,
				      &ex_efx_handle->nic_node);
			added = true;
			break;
		}
	}
	if (!added)
		list_add_tail(&efx_handle->nic_node, &nic->device_list);

	list_add_tail(&efx_handle->driver_node, &driver->device_list);

	netif_info(nic, drv, net_dev,
		   "%s driverlink client registered\n", driver->name);
	return;

fail:
	netif_info(nic, drv, net_dev,
		   "%s driverlink client skipped\n", driver->name);

	kfree(efx_handle);
}

/* Unregister a driver from the driverlink layer, calling the
 * driver's remove() callback for every attached device */
void efx_dl_unregister_driver(struct efx_dl_driver *driver)
{
	struct efx_dl_handle *efx_handle, *efx_handle_n;

	printk(KERN_INFO "Efx driverlink unregistering %s driver\n",
		 driver->name);

	rtnl_lock();

	list_for_each_entry_safe(efx_handle, efx_handle_n,
				 &driver->device_list, driver_node)
		efx_dl_del_device(&efx_handle->efx_dev);

	list_del(&driver->driver_node);

	rtnl_unlock();
}
EXPORT_SYMBOL(efx_dl_unregister_driver);

/* Register a new driver with the driverlink layer. The driver's
 * probe routine will be called for every attached nic. */
int efx_dl_register_driver(struct efx_dl_driver *driver)
{
	struct efx_dl_nic *nic;

	if (!(driver->flags & EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE)) {
		pr_err("Efx driverlink: %s did not promise to check rx_usr_buf_size\n",
		       driver->name);
		return -EPERM;
	}

	if (driver->flags & EFX_DL_DRIVER_REQUIRES_MINOR_VER &&
	    driver->minor_ver > EFX_DRIVERLINK_API_VERSION_MINOR) {
		pr_err("Efx driverlink: %s requires API %d.%d, %s has %d.%d\n",
		       driver->name, EFX_DRIVERLINK_API_VERSION,
		       driver->minor_ver, KBUILD_MODNAME,
		       EFX_DRIVERLINK_API_VERSION,
		       EFX_DRIVERLINK_API_VERSION_MINOR);
		return -EPERM;
	}
	driver->flags |= EFX_DL_DRIVER_SUPPORTS_MINOR_VER;

	printk(KERN_INFO "Efx driverlink registering %s driver\n",
		 driver->name);

	INIT_LIST_HEAD(&driver->driver_node);
	INIT_LIST_HEAD(&driver->device_list);

	rtnl_lock();

	list_add_tail(&driver->driver_node, &efx_driver_list);

	list_for_each_entry(nic, &efx_nic_list, nic_node)
		efx_dl_try_add_device(nic, driver);

	rtnl_unlock();
	return 0;
}
EXPORT_SYMBOL(efx_dl_register_driver);

void efx_dl_unregister_nic(struct efx_dl_nic *nic)
{
	struct efx_dl_handle *efx_handle, *efx_handle_n;

	ASSERT_RTNL();

	list_for_each_entry_safe_reverse(efx_handle, efx_handle_n,
					 &nic->device_list,
					 nic_node)
		efx_dl_del_device(&efx_handle->efx_dev);

	list_del_init(&nic->nic_node);
}
EXPORT_SYMBOL(efx_dl_unregister_nic);

void efx_dl_register_nic(struct efx_dl_nic *nic)
{
	struct efx_dl_driver *driver;

	ASSERT_RTNL();

	netif_info(nic, drv, nic->net_dev, "driverlink registering nic\n");

	list_add_tail(&nic->nic_node, &efx_nic_list);

	list_for_each_entry(driver, &efx_driver_list, driver_node)
		efx_dl_try_add_device(nic, driver);
}
EXPORT_SYMBOL(efx_dl_register_nic);

bool efx_dl_netdev_is_ours(const struct net_device *net_dev)
{
	struct efx_dl_nic *nic;

	list_for_each_entry(nic, &efx_nic_list, nic_node)
		if (nic->net_dev == net_dev)
			return true;

	return false;
}
EXPORT_SYMBOL(efx_dl_netdev_is_ours);

struct efx_dl_device *efx_dl_dev_from_netdev(const struct net_device *net_dev,
					     struct efx_dl_driver *driver)
{
	struct efx_dl_handle *handle;

	list_for_each_entry(handle, &driver->device_list, driver_node)
		if (handle->efx_dev.nic->net_dev == net_dev)
			return &handle->efx_dev;

	return NULL;
}
EXPORT_SYMBOL(efx_dl_dev_from_netdev);

/* Suspend ready for reset, calling the reset_suspend() callback of every
 * registered driver */
void efx_dl_reset_suspend(struct efx_dl_nic *nic)
{
	struct efx_dl_handle *efx_handle;
	struct efx_dl_device *efx_dev;

	ASSERT_RTNL();

	list_for_each_entry_reverse(efx_handle,
				    &nic->device_list,
				    nic_node) {
		efx_dev = &efx_handle->efx_dev;
		if (efx_dev->driver->reset_suspend) {
			u64 before, after, duration;

			before = get_jiffies_64();

			efx_dev->driver->reset_suspend(efx_dev);

			after = get_jiffies_64();
			duration = after - before;
			EFX_DL_CHECK_DURATION(duration, "reset_suspend()");
		}
	}
}
EXPORT_SYMBOL(efx_dl_reset_suspend);

/* Resume after a reset, calling the resume() callback of every registered
 * driver */
void efx_dl_reset_resume(struct efx_dl_nic *nic, int ok)
{
	struct efx_dl_handle *efx_handle;
	struct efx_dl_device *efx_dev;

	ASSERT_RTNL();

	list_for_each_entry(efx_handle, &nic->device_list,
			    nic_node) {
		efx_dev = &efx_handle->efx_dev;
		if (efx_dev->driver->reset_resume) {
			u64 before, after, duration;

			before = get_jiffies_64();

			efx_dev->driver->reset_resume(efx_dev, ok);

			after = get_jiffies_64();
			duration = after - before;
			EFX_DL_CHECK_DURATION(duration, "reset_resume()");
		}
	}
}
EXPORT_SYMBOL(efx_dl_reset_resume);

int efx_dl_handle_event(struct efx_dl_nic *nic, void *event, int budget)
{
	struct efx_dl_handle *efx_handle;
	struct efx_dl_device *efx_dev;

	list_for_each_entry(efx_handle, &nic->device_list, nic_node) {
		efx_dev = &efx_handle->efx_dev;
		if (efx_dev->driver->handle_event ) {
			u64 before, after, duration;
			int rc;

			before = get_jiffies_64();

			rc = efx_dev->driver->handle_event(efx_dev,
							   event, budget);

			after = get_jiffies_64();
			duration = after - before;
			EFX_DL_CHECK_DURATION(duration, "handle_event()");

			if (rc >= 0 )
				return rc > budget ? budget : rc;
		}
	}

	return -EINVAL;
}
EXPORT_SYMBOL(efx_dl_handle_event);

int efx_dl_filter_block_kernel(struct efx_dl_device *dl_dev,
			       enum efx_dl_filter_block_kernel_type type)
{
	struct efx_dl_handle *handle = efx_dl_handle(dl_dev);
	int rc = 0;

	if (handle->block_kernel_count[type] == 0)
		rc = dl_dev->nic->ops->filter_block_kernel(dl_dev, type);
	if (!rc)
		++handle->block_kernel_count[type];
	return rc;
}
EXPORT_SYMBOL(efx_dl_filter_block_kernel);

void efx_dl_filter_unblock_kernel(struct efx_dl_device *dl_dev,
				  enum efx_dl_filter_block_kernel_type type)
{
	struct efx_dl_handle *handle = efx_dl_handle(dl_dev);

	if (handle->block_kernel_count[type] == 0) {
		WARN_ON(1);
		return;
	}

	if (--handle->block_kernel_count[type] == 0)
		dl_dev->nic->ops->filter_unblock_kernel(dl_dev, type);
}
EXPORT_SYMBOL(efx_dl_filter_unblock_kernel);

#define stringify2(x) #x
#define stringify(x) stringify2(x)
#define DRIVERLINK_API_VERSION stringify(EFX_DRIVERLINK_API_VERSION) "." \
	stringify(EFX_DRIVERLINK_API_VERSION_MINOR)

static int __init efx_dl_init_module(void)
{
	printk(KERN_INFO "Solarflare driverlink driver v" EFX_DRIVER_VERSION
			 " API v" DRIVERLINK_API_VERSION "\n");

	return 0;
}

static void __exit efx_dl_exit_module(void)
{
	printk(KERN_INFO "Solarflare driverlink driver unloading\n");
}

module_init(efx_dl_init_module);
module_exit(efx_dl_exit_module);

MODULE_AUTHOR("Solarflare Communications");
MODULE_DESCRIPTION("Solarflare driverlink driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(EFX_DRIVER_VERSION);

