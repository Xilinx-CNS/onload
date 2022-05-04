/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * virtual_bus.h - lightweight software bus
 *
 * Copyright (c) 2019-20 Intel Corporation
 *
 * Please see Documentation/driver-api/virtual_bus.rst for more information
 */

#ifndef _VIRTUAL_BUS_H_
#define _VIRTUAL_BUS_H_

#include <linux/device.h>
#ifndef VIRTBUS_NAME_SIZE
#define VIRTBUS_NAME_SIZE 20
#define VIRTBUS_MODULE_PREFIX "virtbus:"

struct virtbus_dev_id {
	char name[VIRTBUS_NAME_SIZE];
	unsigned long driver_data;
};
#endif

struct virtbus_device {
	struct device dev;
	const char *name;
	void (*release)(struct virtbus_device *);
	int id;
};

struct virtbus_driver {
	int (*probe)(struct virtbus_device *);
	int (*remove)(struct virtbus_device *);
	void (*shutdown)(struct virtbus_device *);
	int (*suspend)(struct virtbus_device *, pm_message_t);
	int (*resume)(struct virtbus_device *);
	struct device_driver driver;
	const struct virtbus_dev_id *id_table;
};

static inline
struct virtbus_device *to_virtbus_dev(struct device *dev)
{
	return container_of(dev, struct virtbus_device, dev);
}

static inline
struct virtbus_driver *to_virtbus_drv(struct device_driver *drv)
{
	return container_of(drv, struct virtbus_driver, driver);
}

int virtbus_register_device(struct virtbus_device *vdev);
void virtbus_unregister_device(struct virtbus_device *vdev);
int
__virtbus_register_driver(struct virtbus_driver *vdrv, struct module *owner);
void virtbus_unregister_driver(struct virtbus_driver *vdrv);

#define virtbus_register_driver(vdrv) \
	__virtbus_register_driver(vdrv, THIS_MODULE)

#endif /* _VIRTUAL_BUS_H_ */
