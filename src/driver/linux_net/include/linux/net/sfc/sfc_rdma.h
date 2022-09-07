/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sfc_rdma.h - RDMA interface using the virtual bus
 *
 * Copyright 2019 Solarflare Communications Inc.
 * Copyright 2019-2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef _SFC_RDMA_H
#define _SFC_RDMA_H

#define SFC_RDMA_DEVNAME	"rdma"

/* RDMA client API */
enum sfc_event_type {
	SFC_EVENT_UNREGISTER,	/**< Device is being removed */
	SFC_EVENT_RESET_DOWN,	/**< Hardware is down for reset */
	SFC_EVENT_RESET_UP,	/**< Hardware is back after reset */
};

struct sfc_rdma_event {
	enum sfc_event_type	type;
	bool			value;	/**< Link state */
};

/** RDMA driver operations */
struct sfc_rdma_drvops {
	void (*handle_event)(struct auxiliary_device *auxdev,
			     const struct sfc_rdma_event *event);
};

struct sfc_rdma_client;

/* RDMA server API */
/** Device parameters */
enum sfc_rdma_param {
	SFC_RDMA_NETDEV,
};

struct sfc_rdma_param_value {
	union {
		struct net_device *net_dev;
	};
};

/** Remote Procedure Call to the firmware */
struct sfc_rdma_rpc {
	unsigned int cmd;
	size_t inlen;
	const u32 *inbuf;
	size_t outlen;
	size_t *outlen_actual;
	u32 *outbuf;
};

/**
 * RDMA device operations.
 *
 * @open: Clients need to open a device before using it. This will prevent it
 *	  from being removed and provides a handle for further operations.
 * @close: Closing a device unlocks it.
 */
struct sfc_rdma_devops {
	struct sfc_rdma_client *(*open)(struct auxiliary_device *auxdev,
					const struct sfc_rdma_drvops *ops);
	int (*close)(struct sfc_rdma_client *handle);

	int (*get_param)(struct sfc_rdma_client *handle, enum sfc_rdma_param p,
			 struct sfc_rdma_param_value *arg);
	int (*fw_rpc)(struct sfc_rdma_client *handle, struct sfc_rdma_rpc *rpc);
};

/**
 * RDMA device interface.
 *
 * @vdev: The parent virtual bus device.
 * @ops: Device API.
 */
struct sfc_rdma_device {
	struct auxiliary_device auxdev;
	const struct sfc_rdma_devops *ops;
};

#endif /* _SFC_RDMA_H */
