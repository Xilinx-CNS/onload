/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

/* This file provides internal API for registering of components for
 * non-driverlink devices. */

#ifndef __EFRM_NONDL_H__
#define __EFRM_NONDL_H__

#include <linux/types.h>
#include <ci/driver/kernel_compat.h>


/* Non-driverlink network device.
 *
 * This structure represents a netdev which is known to the non-driverlink
 * resource driver.
 *
 *
 * The lifecycle of a non-driverlnk device looks like this:
 *
 *                 Register                Device goes
 *                 via /proc               up
 * +------------+  ------>  +-----------+  ------>  +-------------+
 * | Unknown to |           | Hot-      |           | Plugged in  |
 * |    efrm    |           | Unplugged |           | and running |
 * +------------+  <------  +-----------+  <------  +-------------+
 *                 Unregister              Device goes
 *                 via /proc               down
 *
 * The four callbacks in the efrm_nondl_driver structure correspond to
 * the four state transitions in this diagram. */

struct efrm_nondl_device {
  /* List of all currently registered devices. */
  struct list_head node;

  /* Driver using this device. */
  struct efrm_nondl_driver *driver;

  /* List of all devices used by this driver. */
  struct list_head driver_node;

  /* Network device currently associated with this non-driverlink
   * device. */
  struct net_device *netdev;
  netdevice_tracker netdev_tracker;

  /* Number of VIs we would like to create on this device. */
  unsigned int n_vis;

  /* Flag indicating which state this netdev is in. If clear,
   * we're in the "Hot-Unplugged" state; if set, we're in the
   * "Running" state. */
  int is_up;
};

/* Non-driverlink device driver structure.
 *
 * A driver which knows about non-driverlink devices must create a static
 * instance of this structure, register it with the non-driverlink resource
 * driver on module load, and unregister it on module unload. */

struct efrm_nondl_driver {
  /* List of all devices belonging to this driver. */
  struct list_head devices;

  /* A new network device is being registered. */
  int (*register_device)(struct efrm_nondl_device *);

  /* A network device is being unregistered. */
  void (*unregister_device)(struct efrm_nondl_device *);
};

/* Register a non-driverlink device client driver.
 *
 * Newly loaded modules should call this function. It will result in
 * register_device callbacks for all the non-driverlink NICs currently known to
 * the manager. */

void efrm_nondl_register_driver(struct efrm_nondl_driver *driver);

/* Unregister a non-driverlink driver.
 *
 * Modules should call this when they are unloaded. It will result in
 * unregister_device callbacks for every non-driverlink NIC currently registered
 * with this driver. */

void efrm_nondl_unregister_driver(struct efrm_nondl_driver *driver);

#endif
