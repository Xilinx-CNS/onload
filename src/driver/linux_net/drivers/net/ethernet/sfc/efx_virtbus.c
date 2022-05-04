// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Solarflare and Xilinx network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 * Copyright 2019-2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include "nic.h"
#include <linux/virtual_bus.h>
#include <linux/net/sfc/sfc_rdma.h>
#include "efx_virtbus.h"

struct sfc_rdma_dev {
	struct sfc_rdma_device dev;	/* Must be first, drivers use this */
	struct list_head clients;
	struct efx_nic *efx;
};

struct sfc_rdma_client {
	struct sfc_rdma_dev		*rdev;
	const struct sfc_rdma_drvops	*ops;
	struct list_head		list;
};

static struct efx_nic *rdma_client_to_efx(struct sfc_rdma_client *client)
{
	if (client && client->rdev)
		return client->rdev->efx;
	return NULL;
}

static struct device *rdma_client_to_dev(struct sfc_rdma_client *client)
{
	if (client && client->rdev)
		return &client->rdev->dev.vdev.dev;
	return NULL;
}

static struct sfc_rdma_client *efx_rdma_open(struct virtbus_device *vdev,
					     const struct sfc_rdma_drvops *ops)
{
	struct sfc_rdma_client *client;

	if (!vdev || !ops || !ops->handle_event)
		return ERR_PTR(-EINVAL);

	client = kmalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);

	client->rdev = container_of(vdev, struct sfc_rdma_dev, dev.vdev);
	client->ops = ops;
	list_add(&client->list, &client->rdev->clients);
	return client;
}

static int efx_rdma_close(struct sfc_rdma_client *client)
{
	if (!client)
		return -EINVAL;

	list_del(&client->list);
	kfree(client);
	return 0;
}

static int efx_rdma_get_param(struct sfc_rdma_client *client,
			      enum sfc_rdma_param param,
			      struct sfc_rdma_param_value *data)
{
	struct efx_nic *efx = rdma_client_to_efx(client);
	int rc;

	if (!efx)
		return -ENODEV;

	switch (param) {
	case SFC_RDMA_NETDEV:
		data->net_dev = efx->net_dev;
		rc = 0;
		break;
	default:
		dev_info(rdma_client_to_dev(client),
			 "Unknown parameter %u\n", param);
		rc = -EOPNOTSUPP;
	}
	return rc;
}

static int efx_rdma_fw_rpc(struct sfc_rdma_client *client,
			   struct sfc_rdma_rpc *rpc)
{
	struct efx_nic *efx = rdma_client_to_efx(client);
	int rc;

	if (!efx)
		return -ENODEV;

	rc = efx_mcdi_rpc_quiet(efx, rpc->cmd,
				(const efx_dword_t *) rpc->inbuf, rpc->inlen,
				(efx_dword_t *) rpc->outbuf, rpc->outlen,
				rpc->outlen_actual);
	return rc;
}

static void efx_rdma_send_event(struct sfc_rdma_client *client,
				enum sfc_event_type type, u64 value)
{
	struct sfc_rdma_event ev;

	ev.type = type;
	ev.value = value;
	(*client->ops->handle_event)(&client->rdev->dev.vdev, &ev);
}

static const struct sfc_rdma_devops rdma_devops = {
	.open = efx_rdma_open,
	.close = efx_rdma_close,
	.get_param = efx_rdma_get_param,
	.fw_rpc = efx_rdma_fw_rpc,
};

static void efx_virtbus_release(struct virtbus_device *vdev)
{
	struct sfc_rdma_dev *rdev;

	rdev = container_of(vdev, struct sfc_rdma_dev, dev.vdev);
	rdev->efx = NULL;
	kfree(rdev);
}

void efx_virtbus_unregister(struct efx_nic *efx)
{
	struct sfc_rdma_dev *rdev = efx->rdev;
	struct sfc_rdma_client *client, *temp;

	if (!rdev)
		return;

	/* Disconnect all users */
	list_for_each_entry_safe(client, temp, &rdev->clients, list) {
		efx_rdma_send_event(client, SFC_EVENT_UNREGISTER, 0);
		(void) efx_rdma_close(client);
	}

	efx->rdev = NULL;
	virtbus_unregister_device(&rdev->dev.vdev);
}

int efx_virtbus_register(struct efx_nic *efx)
{
	struct sfc_rdma_dev *rdev;
	int rc;

	rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
	if (!rdev)
		return -ENOMEM;

	rdev->dev.vdev.name = SFC_RDMA_DEVNAME;
	rdev->dev.vdev.release = efx_virtbus_release;
	rdev->dev.vdev.dev.parent = &efx->pci_dev->dev;
	rdev->dev.ops = &rdma_devops;
	INIT_LIST_HEAD(&rdev->clients);

	rc = virtbus_register_device(&rdev->dev.vdev);
	if (rc) {
		kfree(rdev);
		return rc;
	}

	rdev->efx = efx;
	efx->rdev = rdev;
	return 0;
}
