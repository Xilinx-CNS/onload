/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
/* This file contains the infrastructure for managing for non driverlink
 * devices. */

#include "linux_resource_internal.h"
#include <ci/driver/kernel_compat.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/nondl.h>
#include <linux/rtnetlink.h>

/* Maximum number of VIs we will try to create for each device. */
#define MAX_VIS 128

/* List of all registered drivers. Protected by the RTNL lock. */
static LIST_HEAD(nondl_driver_list);

/* List of all registered devices. Protected by the RTNL lock. */
static LIST_HEAD(nondl_device_list);

/* Try to create a new handle associating a device with a driver. */
static void efrm_nondl_try_add_device(struct efrm_nondl_device *device,
                                     struct efrm_nondl_driver *driver)
{
        struct efrm_nondl_handle *handle;
        int rc = 0;

	ASSERT_RTNL();

        handle = kzalloc(sizeof *handle, GFP_KERNEL);
        if(!handle) {
                rc = -ENOMEM;
                goto fail;
        }

        INIT_LIST_HEAD(&handle->driver_node);
        INIT_LIST_HEAD(&handle->device_node);

        handle->driver = driver;
        handle->device = device;

        rc = driver->register_device(handle);
        if(rc)
                goto fail;

        if(handle->device->is_up)
		efrm_notify_nic_probe(handle->device->netdev);

        list_add_tail(&handle->driver_node, &driver->handles);
        list_add_tail(&handle->device_node, &device->handles);

        return;

fail:
        EFRM_ERR("Couldn't register device '%s': %d",
                 device->netdev->name, rc);
        kfree(handle);
}

/* Destroy an existing association between a device and a driver. */
static void efrm_nondl_del_device(struct efrm_nondl_handle *handle)
{
	ASSERT_RTNL();

        if(handle->device->is_up)
		efrm_notify_nic_remove(handle->device->netdev);

        handle->driver->unregister_device(handle);

        list_del(&handle->driver_node);
        list_del(&handle->device_node);
        kfree(handle);
}

/* Register a new driver with the non-driverlink resource manager. */
int efrm_nondl_register_driver(struct efrm_nondl_driver *driver)
{
        struct efrm_nondl_device *device;

	INIT_LIST_HEAD(&driver->node);
	INIT_LIST_HEAD(&driver->handles);

        rtnl_lock();

	list_add_tail(&driver->node, &nondl_driver_list);

	list_for_each_entry(device, &nondl_device_list, node)
		efrm_nondl_try_add_device(device, driver);

        rtnl_unlock();

        return 0;
}
EXPORT_SYMBOL(efrm_nondl_register_driver);

/* Unregister a driver from the non-driverlink resource manager. */
void efrm_nondl_unregister_driver(struct efrm_nondl_driver *driver)
{
        struct efrm_nondl_handle *handle, *handle_n;

        rtnl_lock();

	list_for_each_entry_safe_reverse(handle, handle_n,
					 &driver->handles, driver_node)
                efrm_nondl_del_device(handle);

        BUG_ON(!list_empty(&driver->handles));

        list_del(&driver->node);

        rtnl_unlock();
}
EXPORT_SYMBOL(efrm_nondl_unregister_driver);

/* Register a new network device with the non-driverlink resource manager. */
int efrm_nondl_register_netdev(struct net_device *netdev,
                              unsigned int n_vis)
{
        struct efrm_nondl_driver *driver;
        struct efrm_nondl_device *device;

        if((n_vis == 0) || (n_vis > MAX_VIS))
                return -EINVAL;

	ASSERT_RTNL();

        /* First check that the device isn't registered already. */
	list_for_each_entry(device, &nondl_device_list, node) {
                if(device->netdev == netdev) {
                        return -EALREADY;
                }
        }

        device = kzalloc(sizeof *device, GFP_KERNEL);

        if(!device)
                return -ENOMEM;

        INIT_LIST_HEAD(&device->node);
        INIT_LIST_HEAD(&device->handles);

        dev_hold(netdev);
        device->netdev = netdev;
        device->n_vis = n_vis;
        device->is_up = 1;

	list_add_tail(&device->node, &nondl_device_list);

	list_for_each_entry(driver, &nondl_driver_list, node)
		efrm_nondl_try_add_device(device, driver);

        return 0;
}

/* Clean up after a network device has been unregistered. */
static void efrm_nondl_cleanup_netdev(struct efrm_nondl_device *device)
{
	ASSERT_RTNL();

        BUG_ON(!list_empty(&device->handles));

        list_del(&device->node);
        dev_put(device->netdev);

        kfree(device);
}

/* Unregister a network device from the non-driverlink resource manager. */
int efrm_nondl_unregister_netdev(struct net_device *netdev)
{
        struct efrm_nondl_handle *handle, *handle_n;
        struct efrm_nondl_device *device;
        int found = 0;

	ASSERT_RTNL();

	list_for_each_entry(device, &nondl_device_list, node)
                if(device->netdev == netdev) {
                        found = 1;
                        break;
                }

        if(!found)
                return -ENOENT;

        if(device->is_up)
                return -EBUSY;

	list_for_each_entry_safe_reverse(handle, handle_n,
					 &device->handles, device_node)
                efrm_nondl_del_device(handle);

        efrm_nondl_cleanup_netdev(device);

        return 0;
}

void efrm_nondl_init(void)
{
        /* Nothing to do; provided for completeness */
}

void efrm_nondl_shutdown(void)
{
        struct efrm_nondl_device *device, *device_n;

        /* If we are being unloaded then any module which depends on
         * us should have been unloaded already, so our driver list
         * should be empty. If not then something went badly wrong.
         *
         * We still might have devices registered with us, though.  If
         * so they need to be cleaned up. */

        rtnl_lock();

        BUG_ON(!list_empty(&nondl_driver_list));

	list_for_each_entry_safe_reverse(device, device_n,
					 &nondl_device_list, node)
                efrm_nondl_cleanup_netdev(device);

        BUG_ON(!list_empty(&nondl_device_list));

        rtnl_unlock();
}
