/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/* This file provides internal API for registering of components for
 * non-driverlink devices. */

#ifndef __EFRM_NONDL_H__
#define __EFRM_NONDL_H__

#include <linux/types.h>

/* Non-driverlink NIC handle.
 *
 * This structure represents an association between a net device
 * and a driver module which is interested in it. It is allocated and
 * maintained by the non-driverlink resource driver and protected by
 * the RTNL lock. */

struct efrm_nondl_handle {
        /* List of all handles belonging to the same driver. */
        struct list_head driver_node;

        /* List of all handles belonging to the same netdev. */
        struct list_head device_node;

        /* The driver which owns this handle. */
        struct efrm_nondl_driver *driver;

        /* The device that this handle refers to. */
        struct efrm_nondl_device *device;

        /* This field is available for the client driver module to use
         * as it wishes, eg to store a pointer to per-device state. */
        void *private;
};

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

        /* List of all handles referencing this device. */
        struct list_head handles;

        /* Network device currently associated with this non-driverlink
         * device. */
        struct net_device *netdev;

        /* Number of VIs we would like to create on this device. */
        unsigned int n_vis;

        /* Flag indicating which state this netdev is in. If clear,
         * we're in the "Hot-Unplugged" state; if set, we're in the
         * "Running" state. */
        int is_up;
};

/* Non-driverlink device driver structure.
 *
 * Each driver (sfc_resource, onload, affinity) which knows about
 * non-driverlink devices must create a static instance of this structure,
 * register it with the non-driverlink resource driver on module load, and
 * unregister it on module unload. */

struct efrm_nondl_driver {
        /* List of all currently registered drivers. */
        struct list_head node;

        /* List of all handles belonging to this driver. */
        struct list_head handles;

        /* A new network device is being registered. */
        int (*register_device)(struct efrm_nondl_handle *);

        /* A network device is being unregistered. */
        void (*unregister_device)(struct efrm_nondl_handle *);

        /* A network device is starting. */
        void (*start_device)(struct efrm_nondl_handle *);

        /* A network device is stopping. */
        void (*stop_device)(struct efrm_nondl_handle *);
};

/* Register a non-driverlink device client driver.
 *
 * Newly loaded modules should call this function. It will result in
 * register_device callbacks for all the non-driverlink NICs currently known to
 * the manager. */

int efrm_nondl_register_driver(struct efrm_nondl_driver *driver);

/* Unregister a non-driverlink driver.
 *
 * Modules should call this when they are unloaded. It will result in
 * unregister_device callbacks for every non-driverlink NIC currently registered
 * with this driver. */

void efrm_nondl_unregister_driver(struct efrm_nondl_driver *driver);

/* Tell the non-driverlink resource manager that
 * the devices should be brought up. */
void efrm_nondl_start_all(void);

/* Tell the non-driverlink resource manager that
 * the non-driverlink devices should be taken down. */
void efrm_nondl_stop_all(void);

#endif
