// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Solarflare and Xilinx network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 * Copyright 2019-2020 Xilinx Inc.
 * Copyright 2020-2024, Advanced Micro Devices, Inc.
 */
#include <linux/xarray.h>
#include <linux/auxiliary_bus.h>
#include "net_driver.h"
#include <linux/sfc/efx_auxbus.h>
#include "nic.h"
#include "efx_client.h"
#include "rx_common.h"
#include "efx_auxbus_internal.h"

/* Numbers for auxiliary bus devices need to be unique in the host. */
static DEFINE_IDA(efx_auxbus_ida);

/* Driver data for an exposed auxiliary bus device.
 * This structure is created at function probe time, with a separate one
 * for every client type supported. This structure will only exist if a
 * client type is exposed via the auxiliary bus.
 */
struct sfc_auxdev {
	struct efx_client_type_data *client_type;
	struct efx_auxdev auxdev;
};

static
struct efx_probe_data *cdev_to_probe_data(struct efx_auxdev_client *cdev)
{
	struct efx_client *client;

	if (!cdev)
		return NULL;
	client = container_of(cdev, struct efx_client, auxiliary_info);
	return client->client_type->pd;
}

static enum efx_client_type cdev_to_client_type(struct efx_auxdev_client *cdev)
{
	struct efx_client *client;

	if (!cdev)
		return _EFX_CLIENT_MAX;
	client = container_of(cdev, struct efx_client, auxiliary_info);
	return client->client_type->type;
}

static bool client_supports_rss(struct efx_auxdev_client *cdev)
{
	/* No LL support for RSS contexts. */
	return cdev_to_client_type(cdev) != EFX_CLIENT_LLCT;
}

static bool client_supports_filters(struct efx_auxdev_client *cdev)
{
	/* No LL support for filters yet. */
	return cdev_to_client_type(cdev) != EFX_CLIENT_LLCT;
}

static bool client_supports_vports(struct efx_auxdev_client *cdev)
{
	/* No LL support for virtual ports. */
	return cdev_to_client_type(cdev) != EFX_CLIENT_LLCT;
}

static
struct efx_auxdev_client *efx_auxbus_open(struct auxiliary_device *auxdev,
					  efx_auxdev_event_handler func,
					  unsigned int events_requested)
{
	struct efx_client_type_data *client_type;
	struct efx_auxdev_client *cdev;
	struct efx_probe_data *pd;
	struct efx_client *client;
	struct efx_auxdev *adev;
	struct sfc_auxdev *sdev;

	EFX_WARN_ON_ONCE_PARANOID(!auxdev);
	if (!auxdev || (events_requested && !func))
		return ERR_PTR(-EINVAL);

	adev = to_efx_auxdev(auxdev);
	sdev = container_of(adev, struct sfc_auxdev, auxdev);
	client_type = sdev->client_type;
	pd = client_type->pd;
	client = efx_client_add(pd, client_type->type);
	if (IS_ERR(client))
		return (struct efx_auxdev_client *)client;

	cdev = &client->auxiliary_info;
	cdev->client_id = client->client_id;
	cdev->net_dev = pd->efx.net_dev;
	cdev->auxdev = adev;
	cdev->events_requested = events_requested;
	/* Assign the event handler last. This enables event delivery from
	 * efx_auxbus_send_events().
	 */
	smp_wmb();
	cdev->event_handler = func;
	return cdev;
}

static void efx_auxbus_dl_unpublish(struct efx_auxdev_client *handle)
{
	struct efx_probe_data *pd;
	struct efx_client *client;

	if (!handle)
		return;

	client = container_of(handle, struct efx_client, auxiliary_info);
	pd = cdev_to_probe_data(handle);
	if (!pd)
		return;

	if (!client->client_type->vis_allocated)
		return;

	/* efx_net_dealloc requires the rtnl lock. */
	rtnl_lock();
	efx_net_dealloc(&pd->efx);
	rtnl_unlock();
	client->client_type->vis_allocated = false;
}

static void efx_auxbus_close(struct efx_auxdev_client *cdev)
{
	struct efx_client_type_data *client_type;
	struct efx_client *client;

	if (!cdev)
		return;

	/* Disable event delivery from efx_auxbus_send_events() */
	cdev->event_handler = NULL;
	smp_wmb();
	/* Wait until any event callbacks are done */
	client = container_of(cdev, struct efx_client, auxiliary_info);
	client_type = client->client_type;
	efx_auxbus_wait_for_event_callbacks(client_type);

	cdev->net_dev = NULL;
	cdev->client_id = 0;
	/* If @dl_publish has been called, @dl_unpublish must have been called
	 * before we try and close the auxdev client.
	 */
	if (client->client_type->vis_allocated) {
		dev_warn(&cdev->auxdev->auxdev.dev,
			 "Close called on auxdev client with published VIs, this may crash the kernel; attempting cleanup.");
		WARN_ON_ONCE(1);
		efx_auxbus_dl_unpublish(cdev);
	}
	efx_client_del(client);
}

static int efx_auxbus_fw_rpc(struct efx_auxdev_client *cdev,
			     struct efx_auxdev_rpc *rpc)
{
	struct efx_probe_data *pd = cdev_to_probe_data(cdev);
	int rc;

	if (!pd)
		return -ENODEV;

	rc = efx_mcdi_rpc_quiet(&pd->efx, rpc->cmd,
				(const efx_dword_t *) rpc->inbuf, rpc->inlen,
				(efx_dword_t *) rpc->outbuf, rpc->outlen,
				&rpc->outlen_actual);
	return rc;
}

static int efx_auxbus_remove_rxfh_context(struct efx_auxdev_client *cdev,
					  struct ethtool_rxfh_param *rxfh)
{
	struct efx_rss_context *ctx;
	struct efx_probe_data *pd;
	struct efx_nic *efx;
	int rc;

	pd = cdev_to_probe_data(cdev);
	if (!pd)
		return -ENODEV;
	if (!client_supports_rss(cdev))
		return -EOPNOTSUPP;
	efx = &pd->efx;
	if (!efx->type->rx_push_rss_context_config)
		return -EOPNOTSUPP;

	mutex_lock(&efx->rss_lock);
	ctx = efx_find_rss_context_entry(efx, rxfh->rss_context);
	if (!ctx) {
		rc = -ENOENT;
		goto out_unlock;
	}

	rc = efx->type->rx_push_rss_context_config(efx, ctx, NULL, NULL);
	if (!rc)
		efx_free_rss_context_entry(ctx);
out_unlock:
	mutex_unlock(&efx->rss_lock);
	return rc;
}

static int efx_auxbus_modify_rxfh_context(struct efx_auxdev_client *cdev,
					  struct ethtool_rxfh_param *rxfh)
{
	struct efx_rss_context *ctx;
	struct efx_probe_data *pd;
	struct efx_nic *efx;
	size_t i;
	int rc;

	if (!client_supports_rss(cdev))
		return -EOPNOTSUPP;
	/* Hash function is Toeplitz, cannot be changed */
	if (rxfh->hfunc != ETH_RSS_HASH_NO_CHANGE &&
	    rxfh->hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;
	/* A hash key supplied has to be the right length */
	if (rxfh->key && rxfh->key_size != EFX_RX_KEY_LEN)
		return -EINVAL;
	/* An indirection table supplied must have at least one row */
	if (rxfh->indir && !rxfh->indir_size)
		return -EINVAL;

	pd = cdev_to_probe_data(cdev);
	if (!pd)
		return -ENODEV;
	efx = &pd->efx;
	if (!efx->type->rx_push_rss_context_config)
		return -EOPNOTSUPP;

	mutex_lock(&efx->rss_lock);
	ctx = efx_find_rss_context_entry(efx, rxfh->rss_context);
	if (!ctx) {
		rc = -ENOENT;
		goto out_unlock;
	}
	if (!rxfh->key)
		rxfh->key = ctx->rx_hash_key;
	rxfh->key_size = sizeof(ctx->rx_hash_key);
	if (rxfh->indir) {
		/* Replicate (or truncate) the supplied indirection table
		 * to fill the full firmware indirection table size.
		 */
		for (i = 0; i < ARRAY_SIZE(ctx->rx_indir_table); i++)
			ctx->rx_indir_table[i] =
				rxfh->indir[i % rxfh->indir_size];
	}

	rc = efx->type->rx_push_rss_context_config(efx, ctx,
						   ctx->rx_indir_table,
						   rxfh->key);
out_unlock:
	mutex_unlock(&efx->rss_lock);
	return rc;
}

static int efx_auxbus_create_rxfh_context(struct efx_auxdev_client *cdev,
					  struct ethtool_rxfh_param *rxfh,
					  u8 num_queues)
{
	struct efx_rss_context *ctx;
	struct efx_probe_data *pd;
	struct efx_nic *efx;
	int rc;

	if (!client_supports_rss(cdev))
		return -EOPNOTSUPP;
	if (rxfh->rss_delete)	/* create + delete == Nothing to do */
		return -EINVAL;
	/* num_queues=0 is used internally by the driver to represent
	 * efx->rss_spread, and is not appropriate for auxbus clients
	 */
	if (!num_queues)
		return -EINVAL;

	pd = cdev_to_probe_data(cdev);
	if (!pd)
		return -ENODEV;
	efx = &pd->efx;
	if (!efx->type->rx_push_rss_context_config)
		return -EOPNOTSUPP;

	mutex_lock(&efx->rss_lock);
	ctx = efx_alloc_rss_context_entry(efx);
	if (!ctx) {
		rc = -ENOMEM;
		goto out_unlock;
	}
	if (num_queues > ARRAY_SIZE(ctx->rx_indir_table)) {
		rc = -EOVERFLOW;
		efx_free_rss_context_entry(ctx);
		goto out_unlock;
	}
	ctx->num_queues = num_queues;
	efx_set_default_rx_indir_table(ctx, num_queues);
	netdev_rss_key_fill(ctx->rx_hash_key, sizeof(ctx->rx_hash_key));

	rc = efx->type->rx_push_rss_context_config(efx, ctx,
						   ctx->rx_indir_table,
						   ctx->rx_hash_key);
	if (rc) {
		efx_free_rss_context_entry(ctx);
		goto out_unlock;
	}
	rxfh->key = ctx->rx_hash_key;
	rxfh->key_size = sizeof(ctx->rx_hash_key);
	rxfh->indir = ctx->rx_indir_table;
	rxfh->indir_size = ARRAY_SIZE(ctx->rx_indir_table);
	rxfh->hfunc = ETH_RSS_HASH_TOP;
	rxfh->rss_context = ctx->user_id;

out_unlock:
	mutex_unlock(&efx->rss_lock);
	return rc;
}

static int efx_auxbus_filter_insert(struct efx_auxdev_client *cdev,
				    const struct efx_filter_spec *spec,
				    bool replace_equal)
{
	struct efx_probe_data *pd = cdev_to_probe_data(cdev);
	s32 filter_id;

	if (!client_supports_filters(cdev))
		return -EOPNOTSUPP;

	filter_id = efx_filter_insert_filter(&pd->efx,
					     spec, replace_equal);
	if (filter_id >= 0) {
		EFX_WARN_ON_PARANOID(filter_id & ~EFX_FILTER_ID_MASK);
		filter_id |= spec->priority << EFX_FILTER_PRI_SHIFT;
	}
	return filter_id;
}

static int efx_auxbus_filter_remove(struct efx_auxdev_client *cdev,
				    int filter_id)
{
	struct efx_probe_data *pd = cdev_to_probe_data(cdev);

	if (filter_id < 0)
		return -EINVAL;
	if (!client_supports_filters(cdev))
		return -EOPNOTSUPP;

	return efx_filter_remove_id_safe(&pd->efx,
					 filter_id >> EFX_FILTER_PRI_SHIFT,
					 filter_id & EFX_FILTER_ID_MASK);
}

static int efx_auxbus_filter_redirect(struct efx_auxdev_client *handle,
				      int filter_id, int rxq_i, u32 *rss_context,
				      int stack_id)
{
	struct efx_probe_data *pd;

	if (!handle)
		return -EINVAL;
	if (!client_supports_filters(handle))
		return -EOPNOTSUPP;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	if (WARN_ON(filter_id < 0))
		return -EINVAL;

	return pd->efx.type->filter_redirect(&pd->efx, filter_id & EFX_FILTER_ID_MASK,
					     rss_context, rxq_i, stack_id);
}

static int efx_auxbus_filter_get_block(struct efx_nic *efx,
				       enum efx_filter_block_kernel_type type,
				       bool *does_block)
{
	int rc = 0;

	if (!efx || type < 0 || type >= EFX_FILTER_BLOCK_KERNEL_MAX)
		return -EINVAL;

	mutex_lock(&efx->block_kernel_mutex);
	*does_block = (efx->block_kernel_count[type] != 0);
	mutex_unlock(&efx->block_kernel_mutex);

	return rc;
}

static int efx_auxbus_filter_set_block(struct efx_nic *efx,
				       enum efx_filter_block_kernel_type type,
				       bool should_block)
{
	int rc = 0;

	if (!efx || type < 0 || type >= EFX_FILTER_BLOCK_KERNEL_MAX)
		return -EINVAL;

	mutex_lock(&efx->block_kernel_mutex);
	if (should_block) {
		if (efx->block_kernel_count[type] == 0)
			rc = efx->type->filter_block_kernel(efx, type);
		if (rc == 0)
			efx->block_kernel_count[type]++;
	} else {
		if (efx->block_kernel_count[type] == 0)
			rc = -EALREADY;
		else if (--efx->block_kernel_count[type] == 0)
			efx->type->filter_unblock_kernel(efx, type);
	}
	mutex_unlock(&efx->block_kernel_mutex);

	return rc;
}

static int efx_auxbus_get_param(struct efx_auxdev_client *handle,
				enum efx_auxiliary_param p,
				union efx_auxiliary_param_value *arg)
{
	struct efx_probe_data *pd;
	struct efx_nic *efx;
	int rc = 0;

	if (!handle || !arg)
		return -EINVAL;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	efx = &pd->efx;

	switch (p) {
	case EFX_NETDEV:
		arg->net_dev = handle->net_dev;
		break;
	case EFX_MEMBASE:
		arg->membase_addr = efx->membase;
		break;
	case EFX_MEMBAR:
		arg->value = efx->type->mem_bar(efx);
		break;
	case EFX_USE_MSI:
		arg->b = efx->pci_dev->msi_enabled &&
			 !efx->pci_dev->msix_enabled;
		break;
	case EFX_CHANNELS:
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XARRAY)
		arg->channels = handle->channels;
#else
		rc = -EOPNOTSUPP;
#endif
		break;
	case EFX_RXFH_DEFAULT_FLAGS:
		if (efx->type->rx_get_default_rss_flags)
			arg->value = efx->type->rx_get_default_rss_flags(efx);
		else	/* NIC does not support RSS flags */
			arg->value = 0;
		break;
	case EFX_DESIGN_PARAM:
		arg->design_params = &handle->design_params;
		break;
	case EFX_PCI_DEV:
		arg->pci_dev = efx->pci_dev;
		break;
	case EFX_PCI_DEV_DEVICE:
		arg->value = efx->pci_dev->device;
		break;
	case EFX_DEVICE_REVISION:
		rc = pci_read_config_byte(efx->pci_dev, PCI_CLASS_REVISION,
					  (u8 *)&arg->value);
		break;
	case EFX_TIMER_QUANTUM_NS:
		arg->value = efx->timer_quantum_ns;
		break;
	case EFX_DRIVER_DATA:
		arg->driver_data = handle->driver_data;
		break;
	case EFX_PARAM_FILTER_BLOCK_KERNEL_UCAST:
		rc = efx_auxbus_filter_get_block(efx,
						 EFX_FILTER_BLOCK_KERNEL_UCAST,
						 &arg->b);
		break;
	case EFX_PARAM_FILTER_BLOCK_KERNEL_MCAST:
		rc = efx_auxbus_filter_get_block(efx,
						 EFX_FILTER_BLOCK_KERNEL_MCAST,
						 &arg->b);
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}

	return rc;
}

static int efx_auxbus_set_param(struct efx_auxdev_client *handle,
				enum efx_auxiliary_param p,
				union efx_auxiliary_param_value *arg)
{
	struct efx_probe_data *pd;
	struct efx_nic *efx;
	int rc = 0;

	if (!handle || !arg)
		return -EINVAL;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	efx = &pd->efx;

	switch (p) {
	case EFX_NETDEV:
	case EFX_MEMBASE:
	case EFX_MEMBAR:
	case EFX_USE_MSI:
	case EFX_CHANNELS:
	case EFX_RXFH_DEFAULT_FLAGS:
	case EFX_DESIGN_PARAM:
	case EFX_PCI_DEV:
	case EFX_PCI_DEV_DEVICE:
	case EFX_DEVICE_REVISION:
	case EFX_TIMER_QUANTUM_NS:
		/* These parameters are _get_ only! */
		rc = -EINVAL;
		break;
	case EFX_DRIVER_DATA:
		handle->driver_data = arg->driver_data;
		break;
	case EFX_PARAM_FILTER_BLOCK_KERNEL_UCAST:
		if (!client_supports_filters(handle))
			return -EOPNOTSUPP;

		rc = efx_auxbus_filter_set_block(efx,
						 EFX_FILTER_BLOCK_KERNEL_UCAST,
						 arg->b);
		break;
	case EFX_PARAM_FILTER_BLOCK_KERNEL_MCAST:
		if (!client_supports_filters(handle))
			return -EOPNOTSUPP;

		rc = efx_auxbus_filter_set_block(efx,
						 EFX_FILTER_BLOCK_KERNEL_MCAST,
						 arg->b);
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}

	return rc;
}

static struct efx_auxdev_dl_vi_resources *
efx_auxbus_dl_publish(struct efx_auxdev_client *handle)
{
	struct efx_auxdev_dl_vi_resources *result;
	struct efx_probe_data *pd;
	struct efx_client *client;
	int rc;

	if (!handle)
		return ERR_PTR(-EINVAL);
	if (cdev_to_client_type(handle) != EFX_CLIENT_ONLOAD)
		return ERR_PTR(-EOPNOTSUPP);

	client = container_of(handle, struct efx_client, auxiliary_info);
	pd = cdev_to_probe_data(handle);
	if (!pd)
		return ERR_PTR(-ENODEV);

	if (client->client_type->vis_allocated)
		return ERR_PTR(-EALREADY);

	/* Both efx_net_alloc and efx_net_dealloc require the RTNL lock. */
	rtnl_lock();
	rc = efx_net_alloc(&pd->efx);
	if (rc) {
		efx_net_dealloc(&pd->efx);
		result = ERR_PTR(rc);
	} else {
		client->client_type->vis_allocated = true;
		result = &pd->efx.vi_resources;
	}
	rtnl_unlock();

	return result;
}

static
int efx_aux_set_multicast_loopback_suppression(struct efx_auxdev_client *handle,
					       bool suppress, u16 vport_id,
					       u8 stack_id)
{
	struct efx_probe_data *pd;

	if (!handle)
		return -EINVAL;
	if (!client_supports_filters(handle))
		return -EOPNOTSUPP;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	return efx_set_multicast_loopback_suppression(&pd->efx, suppress,
						      vport_id, stack_id);
}

static int efx_auxbus_set_rxfh_flags(struct efx_auxdev_client *cdev,
				     u32 rss_context, u32 flags)
{
	struct efx_rss_context *ctx;
	struct efx_probe_data *pd;
	struct efx_nic *efx;
	int rc;

	pd = cdev_to_probe_data(cdev);
	if (!pd)
		return -ENODEV;
	/* No LL support for RSS contexts. */
	if (!client_supports_rss(cdev))
		return -EOPNOTSUPP;
	efx = &pd->efx;
	if (!efx->type->rx_set_rss_flags)
		return -EOPNOTSUPP;

	mutex_lock(&efx->rss_lock);
	ctx = efx_find_rss_context_entry(efx, rss_context);
	if (!ctx) {
		rc = -ENOENT;
		goto out_unlock;
	}
	rc = efx->type->rx_set_rss_flags(efx, ctx, flags);
	if (rc)
		goto out_unlock;
	ctx->flags = flags;

out_unlock:
	mutex_unlock(&efx->rss_lock);
	return rc;
}

static int efx_auxbus_vport_new(struct efx_auxdev_client *handle, u16 vlan,
				bool vlan_restrict)
{
	struct efx_probe_data *pd;

	if (!handle)
		return -EINVAL;
	if (!client_supports_vports(handle))
		return -EOPNOTSUPP;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	return efx_vport_add(&pd->efx, vlan, vlan_restrict);
}

static int efx_auxbus_vport_free(struct efx_auxdev_client *handle, u16 port_id)
{
	struct efx_probe_data *pd;

	if (!handle)
		return -EINVAL;
	if (!client_supports_vports(handle))
		return -EOPNOTSUPP;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	return efx_vport_del(&pd->efx, port_id);
}

static s64 efx_auxbus_vport_id_get(struct efx_auxdev_client *handle,
				   u16 port_id)
{
	struct efx_probe_data *pd;
	struct efx_vport *vpx;

	if (!handle)
		return -EINVAL;
	if (!client_supports_vports(handle))
		return -EOPNOTSUPP;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	if (port_id == 0) {
		vpx = &pd->efx.vport;
	} else {
		vpx = efx_find_vport_entry(&pd->efx, port_id);
		if (!vpx)
			return -ENOENT;
	}
	return vpx->vport_id;
}

static const struct efx_auxdev_ops aux_devops = {
	.open = efx_auxbus_open,
	.close = efx_auxbus_close,
	.fw_rpc = efx_auxbus_fw_rpc,
	.create_rxfh_context = efx_auxbus_create_rxfh_context,
	.modify_rxfh_context = efx_auxbus_modify_rxfh_context,
	.remove_rxfh_context = efx_auxbus_remove_rxfh_context,
	.filter_insert = efx_auxbus_filter_insert,
	.filter_remove = efx_auxbus_filter_remove,
	.filter_redirect = efx_auxbus_filter_redirect,
	.get_param = efx_auxbus_get_param,
	.set_param = efx_auxbus_set_param,
	.dl_publish = efx_auxbus_dl_publish,
	.dl_unpublish = efx_auxbus_dl_unpublish,
	.set_multicast_loopback_suppression =
		efx_aux_set_multicast_loopback_suppression,
	.set_rxfh_flags = efx_auxbus_set_rxfh_flags,
	.vport_new = efx_auxbus_vport_new,
	.vport_free = efx_auxbus_vport_free,
	.vport_id_get = efx_auxbus_vport_id_get,
};

int efx_auxbus_send_events(struct efx_probe_data *pd,
			   struct efx_auxdev_event *event)
{
	struct efx_client_type_data *client_type;
	struct efx_auxdev_client *cdev;
	struct efx_client *client;
	enum efx_client_type type;
	unsigned int count = 0;
	unsigned long idx;
	int rc;

	/* Notify all auxiliary bus devices for this function. */
	for (type = 0; type < _EFX_CLIENT_MAX; type++) {
		client_type = pd->client_type[type];
		if (!client_type || !client_type->type_data)
			continue;

		/* Notify open clients that want this event */
		refcount_inc(&client_type->in_callback);
		xa_for_each(&client_type->open, idx, client) {
			efx_auxdev_event_handler *event_handler;

			if (!client)
				continue;

			cdev = &client->auxiliary_info;
			if (!(cdev->events_requested & BIT(event->type)))
				continue;
			event_handler = READ_ONCE(cdev->event_handler);
			if (!event_handler)
				continue;

			rc = (*event_handler)(cdev, event);
			if (rc > 0)
				count += rc;
		}
		refcount_dec(&client_type->in_callback);
	}
	return count;
}

int efx_auxbus_send_poll_event(struct efx_probe_data *pd, int channel,
			       efx_qword_t *event, int budget)
{
	struct efx_client_type_data *client_type;
	struct efx_auxdev_event ev;

	if (!pd)
		return -ENODEV;

	/* Only send these events to legacy Onload drivers, i.e. those that
	 * have called the dl_publish API.
	 */
	client_type = pd->client_type[EFX_CLIENT_ONLOAD];
	if (!client_type || !client_type->vis_allocated)
		return -ENODEV;

	ev.type = EFX_AUXDEV_EVENT_POLL;
	ev.value = channel;
	ev.budget = budget;
	ev.p_event = event;
	return efx_auxbus_send_events(pd, &ev);
}

static void efx_auxbus_release(struct device *dev)
{
	struct auxiliary_device *auxdev = to_auxiliary_dev(dev);
	struct efx_auxdev *adev = to_efx_auxdev(auxdev);
	struct sfc_auxdev *sdev;

	ida_free(&efx_auxbus_ida, auxdev->id);
	sdev = container_of(adev, struct sfc_auxdev, auxdev);
	kfree(sdev);
}

static const char *to_auxbus_name(enum efx_client_type type)
{
	/* Not all client types use the auxiliary bus */
	switch (type) {
	case EFX_CLIENT_ONLOAD:
		return EFX_ONLOAD_DEVNAME;
	case EFX_CLIENT_LLCT:
		return EFX_LLCT_DEVNAME;
	default:
		return NULL;
	}
}

void efx_auxbus_del_dev(struct efx_client_type_data *client_type)
{
	const char *auxbus_name = to_auxbus_name(client_type->type);
	struct auxiliary_device *auxdev;
	struct sfc_auxdev *sdev;

	/* Not all client types use the auxiliary bus */
	if (!auxbus_name)
		return;
	sdev = client_type->type_data;
	if (!sdev)
		return;

	auxdev = &sdev->auxdev.auxdev;
	auxiliary_device_delete(auxdev);
	auxiliary_device_uninit(auxdev);
	client_type->type_data = NULL;
	/* efx_auxbus_release will be called when all users are gone. */
}

int efx_auxbus_add_dev(struct efx_client_type_data *client_type)
{
	const char *auxbus_name = to_auxbus_name(client_type->type);
	struct auxiliary_device *auxdev;
	struct sfc_auxdev *sdev;
	int rc;

	/* Not all client types use the auxiliary bus */
	if (!auxbus_name)
		return 0;
	/* There is only 1 auxbus exposed for a given function and type. */
	if (client_type->type_data)
		return -EALREADY;

	sdev = kzalloc(sizeof(*sdev), GFP_KERNEL);
	if (!sdev)
		return -ENOMEM;
	auxdev = &sdev->auxdev.auxdev;

	rc = ida_alloc(&efx_auxbus_ida, GFP_KERNEL);
	if (rc < 0)
		goto out_free;
	auxdev->id = rc;

	auxdev->name = auxbus_name;
	auxdev->dev.release = efx_auxbus_release;
	auxdev->dev.parent = &client_type->pd->pci_dev->dev;
	sdev->auxdev.ops = &aux_devops;
	sdev->client_type = client_type;

	rc = auxiliary_device_init(auxdev);
	if (rc)
		goto fail;

	client_type->type_data = sdev;
	rc = auxiliary_device_add(auxdev);
	if (rc) {
		auxiliary_device_uninit(auxdev);
		goto fail;
	}
	return 0;
fail:
	client_type->type_data = NULL;
	ida_free(&efx_auxbus_ida, auxdev->id);
out_free:
	kfree(sdev);
	return rc;
}
