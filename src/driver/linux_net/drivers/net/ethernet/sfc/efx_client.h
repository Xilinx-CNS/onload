/* SPDX-License-Identifier: GPL-2.0-only */
/****************************************************************************
 * Driver for AMD network controllers and boards
 *
 * Copyright 2023, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#ifndef EFX_CLIENT_H
#define EFX_CLIENT_H

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_AUXILIARY_BUS)
#include <linux/auxiliary_bus.h>
#else
struct auxiliary_device {
	int	dummy;
};
#endif
#include <linux/sfc/efx_auxbus.h>

struct efx_probe_data;

/**
 * struct efx_client_type_data - Data needed for each client type.
 * @auxiliary_info: Data shared with auxiliary bus drivers.
 * @type: Type of client.
 * @pd: Parent device.
 * @type_data: Specifics for a client type.
 * @open_lock: Protect removal of entries in the @open array. This includes
 *	the zeroing of fields in a client, and freeing of client memory.
 * @open: All open clients that use this type. Each entry points to
 *	a struct efx_client.
 *
 * This structure is created at function probe time, with a separate one
 * for every client type supported. This structure will exist even if a client
 * type is not exposed via the auxiliary bus.
 */
struct efx_client_type_data {
	struct efx_auxdev_client auxiliary_info;
	enum efx_client_type type;
	struct efx_probe_data *pd;
	void *type_data;
#ifdef EFX_NOT_UPSTREAM
	/**
	 * @vis_allocated: Flag denoting whether VIs have been allocated using
	 *  @efx_net_alloc, which can only be allowed to happen once.
	 */
	bool vis_allocated;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined (EFX_HAVE_XARRAY)
	struct rw_semaphore open_lock;
	struct xarray open;
#endif
};

/**
 * struct efx_client - Data needed for each client.
 * @client_id: Unique identifier to manage resources for this client.
 * @client_type: Information general for the type of client.
 * @auxiliary_info: Information exposed to the user of the auxiliary bus device.
 *
 * This structure is created when an auxiliary bus device is opened. It will
 * only exist for clients that are exposed via the auxiliary bus.
 * It has the information exposed to auxiliary bus drivers, and has a link to
 * the client type specifics.
 */
struct efx_client {
	u32 client_id;
	struct efx_client_type_data *client_type;
#ifdef CONFIG_AUXILIARY_BUS
	struct efx_auxdev_client auxiliary_info;
#endif
};

#if !defined(EFX_USE_KCOMPAT) || defined (EFX_HAVE_XARRAY)
/**
 * efx_client_init() - Initialise support for client types.
 *
 * @pd: Function affected.
 *
 * Return: 0 for success, or an error code.
 */
int efx_client_init(struct efx_probe_data *pd);

/**
 * efx_client_fini() - Detach all clients and disable all support.
 *
 * @pd: Function affected.
 */
void efx_client_fini(struct efx_probe_data *pd);

/**
 * efx_onload_client_fini() - Detach all Onload clients.
 *
 * @pd: Function affected.
 */
void efx_onload_client_fini(struct efx_probe_data *pd);

/**
 * efx_client_add() - Add a client to the parent NIC.
 *
 * This allocates a new client, and links the client to the parent.
 *
 * @pd: Function affected.
 * @type: Type of client to add.
 *
 * Return: new client structure for success, or the pointer equivalent for
 * an error code.
 */
struct efx_client *efx_client_add(struct efx_probe_data *pd,
				  enum efx_client_type type);

/**
 * efx_client_del() - Remove a NIC client
 *
 * @client: The client to remove.
 */
void efx_client_del(struct efx_client *client);

#else	/* EFX_HAVE_XARRAY */
/* No support is needed for this on old kernels. */
static inline int efx_client_init(struct efx_probe_data *pd)
{
	return 0;
}

static inline void efx_client_fini(struct efx_probe_data *pd)
{
}

static inline void efx_onload_client_fini(struct efx_probe_data *pd)
{
}

static inline struct efx_client *efx_client_add(struct efx_probe_data *pd,
						enum efx_client_type type)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void efx_client_del(struct efx_client *client)
{
}
#endif	/* EFX_HAVE_XARRAY */

#endif	/* EFX_CLIENT_H */
