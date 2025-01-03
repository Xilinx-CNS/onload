/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
/* This file contains the infrastructure for managing for non driverlink
 * devices. */

#include "linux_resource_internal.h"
#include <ci/driver/kernel_compat.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/nondl.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>

/* Maximum number of VIs we will try to create for each device. */
#define MAX_VIS 128

/* Registered driver. Protected by the RTNL lock. */
static struct efrm_nondl_driver *nondl_driver;

/* List of all registered devices. Protected by the RTNL lock. */
static LIST_HEAD(nondl_device_list);

/* Try to create a new handle associating a device with a driver. */
static void efrm_nondl_try_add_device(struct efrm_nondl_device *device,
                                      struct efrm_nondl_driver *driver)
{
  int rc = 0;
  struct efhw_nic *nic;

  ASSERT_RTNL();

  EFRM_ASSERT(!device->driver);
  EFRM_ASSERT(driver);

  rc = driver->register_device(device);
  if(rc)
    goto fail;

  INIT_LIST_HEAD(&device->driver_node);
  device->driver = driver;
  list_add_tail(&device->driver_node, &driver->devices);

  if(device->is_up) {
    nic = efhw_nic_find(device->netdev);
    efrm_notify_nic_probe(nic, device->netdev);
  }

  return;

fail:
  EFRM_ERR("Couldn't register device '%s': %d", device->netdev->name, rc);
}

/* Destroy an existing association between a device and a driver. */
static void efrm_nondl_del_device(struct efrm_nondl_device *device)
{
  struct efhw_nic *nic;
  ASSERT_RTNL();

  if(device->is_up) {
    nic = efhw_nic_find(device->netdev);
    efrm_notify_nic_remove(nic);
  }

  if( device->driver ) {
    device->driver->unregister_device(device);
    list_del(&device->driver_node);
  }

  device->driver = NULL;
}

/* Register a new driver with the non-driverlink resource manager. */
void efrm_nondl_register_driver(struct efrm_nondl_driver *driver)
{
  struct efrm_nondl_device *device;
  INIT_LIST_HEAD(&driver->devices);

  rtnl_lock();

  EFRM_ASSERT(!nondl_driver);

  nondl_driver = driver;

  list_for_each_entry(device, &nondl_device_list, node)
    efrm_nondl_try_add_device(device, driver);

  rtnl_unlock();
}
EXPORT_SYMBOL(efrm_nondl_register_driver);

/* Unregister a driver from the non-driverlink resource manager. */
void efrm_nondl_unregister_driver(struct efrm_nondl_driver *driver)
{
  struct efrm_nondl_device *device, *device_n;

  rtnl_lock();

  if (!nondl_driver)
    goto out;

  EFRM_ASSERT(nondl_driver == driver);

  list_for_each_entry_safe_reverse(device, device_n, &driver->devices,
                                   driver_node)
    efrm_nondl_del_device(device);

  BUG_ON(!list_empty(&driver->devices));

  nondl_driver = NULL;

out:
  rtnl_unlock();
}
EXPORT_SYMBOL(efrm_nondl_unregister_driver);

/* Register a new network device with the non-driverlink resource manager. */
int efrm_nondl_register_netdev(struct net_device *netdev,
                               unsigned int n_vis)
{
  struct efrm_nondl_device *device;

  if((n_vis == 0) || (n_vis > MAX_VIS))
    return -EINVAL;

  ASSERT_RTNL();

  /* First check that the device isn't registered already. */
  list_for_each_entry(device, &nondl_device_list, node) {
    if(device->netdev == netdev)
      return -EALREADY;
  }

  device = kzalloc(sizeof *device, GFP_KERNEL);

  if(!device)
    return -ENOMEM;

  INIT_LIST_HEAD(&device->node);

  netdev_hold(netdev, &device->netdev_tracker, GFP_KERNEL);
  device->netdev = netdev;
  device->n_vis = n_vis;
  device->is_up = 1;

  list_add_tail(&device->node, &nondl_device_list);

  if( nondl_driver )
    efrm_nondl_try_add_device(device, nondl_driver);

  return 0;
}

/* Clean up after a network device has been unregistered. */
static void efrm_nondl_cleanup_netdev(struct efrm_nondl_device *device)
{
  ASSERT_RTNL();

  BUG_ON(device->driver);

  list_del(&device->node);
  netdev_put(device->netdev, &device->netdev_tracker);

  kfree(device);
}

/* Unregister a network device from the non-driverlink resource manager. */
int efrm_nondl_unregister_netdev(struct net_device *netdev)
{
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

  efrm_nondl_del_device(device);

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

  BUG_ON(nondl_driver);

  list_for_each_entry_safe_reverse(device, device_n, &nondl_device_list, node)
    efrm_nondl_cleanup_netdev(device);

  BUG_ON(!list_empty(&nondl_device_list));

  rtnl_unlock();
}
