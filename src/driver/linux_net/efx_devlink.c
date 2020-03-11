/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include "net_driver.h"
#include "efx_devlink.h"
#include "nic.h"
#include "mcdi.h"
#include "mcdi_pcol.h"

/* These must match with enum efx_info_type. */
static const char *type_name[EFX_INFO_TYPE_MAX] = {
	[EFX_INFO_TYPE_DRIVER] = "driver",
	[EFX_INFO_TYPE_MCFW] = "fw.mc",
	[EFX_INFO_TYPE_SUCFW] = "fw.suc",
	[EFX_INFO_TYPE_NMCFW] = "fw.nmc",
	[EFX_INFO_TYPE_CMCFW] = "fw.cmc",
	[EFX_INFO_TYPE_FPGA] = "fpga",
	[EFX_INFO_TYPE_BOARD_ID] = "board.id",
	[EFX_INFO_TYPE_BOARD_REV] = "board.rev",
	[EFX_INFO_TYPE_SERIAL] = "board.sn"
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK)
#ifdef CONFIG_NET_DEVLINK
#define _EFX_USE_DEVLINK
#endif
#endif

#ifdef _EFX_USE_DEVLINK
#include <net/devlink.h>

/* This is the private data we have in struct devlink */
struct efx_devlink {
	struct efx_nic *efx;
	struct devlink_port dl_port;
};

void efx_devlink_dump_version(void *info, enum efx_info_type type,
			      const char *buf)
{
	struct devlink_info_req *req = info;

	switch(type) {
	case EFX_INFO_TYPE_BOARD_ID:
	case EFX_INFO_TYPE_BOARD_REV:
		devlink_info_version_fixed_put(req, type_name[type], buf);
		break;
	case EFX_INFO_TYPE_SERIAL:
		devlink_info_serial_number_put(req, buf);
		break;
	default:
		devlink_info_version_running_put(req, type_name[type], buf);
	}
}

static int efx_devlink_info_get(struct devlink *devlink,
				struct devlink_info_req *req,
				struct netlink_ext_ack *extack)
{
	struct efx_devlink *devlink_private = devlink_priv(devlink);
	struct efx_nic *efx = devlink_private->efx;
	int rc;

	if (efx_nic_rev(efx) == EFX_REV_EF100)
		rc = devlink_info_driver_name_put(req, "sfc_ef100");
	else
		rc = devlink_info_driver_name_put(req, "sfc");

	efx_mcdi_dump_versions(efx, req);
	return rc;
}

struct devlink_port *efx_get_devlink_port(struct net_device *dev)
{
	struct efx_nic *efx = netdev_priv(dev);
	struct efx_devlink *devlink_private;

	if (!efx->devlink)
		return NULL;

	devlink_private = devlink_priv(efx->devlink);
	if (devlink_private)
		return &devlink_private->dl_port;
	else
		return NULL;
}

static const struct devlink_ops sfc_devlink_ops = {
	.info_get	= efx_devlink_info_get,
};

void efx_fini_devlink(struct efx_nic *efx)
{
	if (efx->devlink) {
		struct efx_devlink *devlink_private;

		devlink_private = devlink_priv(efx->devlink);
		devlink_port_unregister(&devlink_private->dl_port);

		devlink_unregister(efx->devlink);
		devlink_free(efx->devlink);
	}
	efx->devlink = NULL;
}

int efx_probe_devlink(struct efx_nic *efx)
{
	struct efx_devlink *devlink_private;
	int rc;

	efx->devlink = devlink_alloc(&sfc_devlink_ops,
				     sizeof(struct efx_devlink));
	if (!efx->devlink)
		return -ENOMEM;
	devlink_private = devlink_priv(efx->devlink);
	devlink_private->efx = efx;

	rc = devlink_register(efx->devlink, &efx->pci_dev->dev);
	if (rc)
		goto out_free;

	rc = devlink_port_register(efx->devlink, &devlink_private->dl_port,
				   efx->port_num);
	if (rc)
		goto out_unreg;

	devlink_port_type_eth_set(&devlink_private->dl_port, efx->net_dev);
	return 0;

out_unreg:
	devlink_unregister(efx->devlink);
out_free:
	devlink_free(efx->devlink);
	efx->devlink = NULL;
	return rc;
}
#else
/* devlink is not available, provide the version information via a file
 * in sysfs.
 */
#include <linux/device.h>

void efx_devlink_dump_version(void *info,
			      enum efx_info_type type,
			      const char *buf_in)
{
	char *buf_out = info;
	int offset = strlen(buf_out);

	scnprintf(&buf_out[offset], PAGE_SIZE-offset, "%s: %s\n",
		  type_name[type], buf_in);
}

static ssize_t versions_show(struct device *dev,
			     struct device_attribute *attr, char *buf_out)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	if (efx_nic_rev(efx) == EFX_REV_EF100)
		sprintf(buf_out, "driver: sfc_ef100\n");
	else
		sprintf(buf_out, "driver: sfc\n");

	efx_mcdi_dump_versions(efx, buf_out);
	return strlen(buf_out);
}

static DEVICE_ATTR_RO(versions);

int efx_probe_devlink(struct efx_nic *efx)
{
	return device_create_file(&efx->pci_dev->dev, &dev_attr_versions);
}

void efx_fini_devlink(struct efx_nic *efx)
{
	device_remove_file(&efx->pci_dev->dev, &dev_attr_versions);
}

#endif	/* _EFX_USE_DEVLINK */
