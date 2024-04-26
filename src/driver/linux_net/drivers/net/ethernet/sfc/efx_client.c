// SPDX-License-Identifier: GPL-2.0
/****************************************************************************
 * Driver for AMD network controllers and boards
 *
 * Copyright 2023, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include "net_driver.h"
#include "efx_client.h"
#include "mcdi_pcol.h"
#include "nic_common.h"
#include "mcdi_functions.h"
#include "efx_auxbus_internal.h"

#if !defined(EFX_USE_KCOMPAT) || defined (EFX_HAVE_XARRAY)
/* Allocate a unique identifier for a client */
static int efx_client_alloc_id(struct efx_client *client)
{
	struct xa_limit limit = XA_LIMIT(1, UINT_MAX);	/* Avoid client_id 0 */
	struct efx_client_type_data *client_type = client->client_type;
	struct efx_probe_data *pd = client_type->pd;
	unsigned long index;
	int rc;

	if (pd->fw_client_supported || !pd->fw_client_support_probed) {
		pd->fw_client_support_probed = true;
		rc = efx_mcdi_client_alloc(&pd->efx, MC_CMD_CLIENT_ID_SELF,
					   &client->client_id);
		if (!rc) {
			pd->fw_client_supported = true;
			index = client->client_id;
			return xa_insert(&client_type->open, index, client,
					 GFP_KERNEL);
		}
		/* Do not fall back to driver allocation if the initial
		 * MCDI call succeeded.
		 */
		if (pd->fw_client_supported)
			return rc;

		pci_dbg(pd->pci_dev,
			"Firmware does not support client IDs, using driver allocation\n");
	}

	return xa_alloc(&client_type->open, &client->client_id, client,
			limit, GFP_KERNEL);
}

static void efx_client_free_id(struct efx_client *client)
{
	struct efx_client_type_data *client_type = client->client_type;
	struct efx_probe_data *pd = client_type->pd;

	if (pd->fw_client_supported)
		efx_mcdi_client_free(&pd->efx,
				     client->client_id);
	xa_erase(&client_type->open, client->client_id);
	client->client_id = 0;
}

struct efx_client *efx_client_add(struct efx_probe_data *pd,
				  enum efx_client_type type)
{
	struct efx_client_type_data *client_type;
	struct efx_client *new;
	int rc;

	if (type >= _EFX_CLIENT_MAX)
		return ERR_PTR(-EINVAL);
	client_type = pd->client_type[type];
	if (!client_type)
		return NULL;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return ERR_PTR(-ENOMEM);
	new->client_type = client_type;
	rc = efx_client_alloc_id(new);
	if (rc < 0) {
		kfree(new);
		return ERR_PTR(rc);
	}
	return new;
}

void efx_client_del(struct efx_client *client)
	__must_hold(client->client_type->open_lock)
{
	if (!client)
		return;

	efx_client_free_id(client);
	kfree(client);
}

/* Support for types of clients */
static void efx_client_del_type(struct efx_probe_data *pd,
				enum efx_client_type type)
{
	struct efx_client_type_data *client_type;
	struct efx_client *client;
	unsigned long index;

	if (type >= _EFX_CLIENT_MAX)
		return;
	client_type = pd->client_type[type];
	if (!client_type)
		return;

	/* Remove all clients. Remove the auxiliary bus device first, this
	 * could cause auxiliary bus drivers to close their clients.
	 */
	efx_auxbus_del_dev(client_type);
	down_write(&client_type->open_lock);
	xa_for_each(&client_type->open, index, client)
		efx_client_del(client);
	xa_destroy(&client_type->open);
	up_write(&client_type->open_lock);

	pd->client_type[type] = NULL;
	kfree(client_type);
}

static void efx_client_add_type(struct efx_probe_data *pd,
				enum efx_client_type type)
{
	struct efx_client_type_data *new;
	int rc;

	if (!efx_nic_client_supported(&pd->efx, type))
		return;

	new = kzalloc(sizeof(struct efx_client_type_data), GFP_KERNEL);
	if (!new)
		return;
	new->type = type;
	new->pd = pd;
	xa_init_flags(&new->open, XA_FLAGS_ALLOC1);
	init_rwsem(&new->open_lock);
	pd->client_type[type] = new;

	rc = efx_auxbus_add_dev(new);
	if (!rc)
		return;
	pci_err(pd->pci_dev,
		"Failed to add auxiliary bus device for client %d, rc=%d\n",
		type, rc);
	efx_client_del_type(pd, type);
}

void efx_client_fini(struct efx_probe_data *pd)
{
	enum efx_client_type type;

	/* Disable all clients */
	for (type = 0; type < _EFX_CLIENT_MAX; type++)
		efx_client_del_type(pd, type);

	pd->fw_client_support_probed = false;
	pd->fw_client_supported = false;
}

int efx_client_init(struct efx_probe_data *pd)
{
	enum efx_client_type type;

	/* Enable all clients that this NIC supports */
	for (type = 0; type < _EFX_CLIENT_MAX; type++)
		efx_client_add_type(pd, type);

	return 0;
}
#endif	/* EFX_HAVE_XARRAY */
