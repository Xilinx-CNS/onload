// SPDX-License-Identifier: GPL-2.0
/* Driver for Xilinx network controllers and boards
 * Copyright 2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/err.h>
#include <linux/vdpa.h>
#include "ef100_vdpa.h"
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
#include <uapi/linux/vdpa.h>
#endif
#include "mcdi_vdpa.h"
#include "filter.h"
#include "mcdi_functions.h"
#include "mcdi_filters.h"
#ifdef CONFIG_SFC_DEBUGFS
#include "debugfs.h"
#endif
#include "ef100_iova.h"
#include "ef100_netdev.h"

#if defined(CONFIG_SFC_VDPA)
#define EFX_VDPA_NAME_LEN 32
#define EFX_INVALID_FILTER_ID -1

static const char * const filter_names[] = { "bcast", "ucast", "mcast" };

static int ef100_vdpa_set_mac_filter(struct efx_nic *efx,
				     struct efx_filter_spec *spec,
				     u32 qid,
				     u8 *mac_addr)
{
	int rc;

	efx_filter_init_rx(spec, EFX_FILTER_PRI_MANUAL, 0, qid);

	if (mac_addr) {
		rc = efx_filter_set_eth_local(spec, EFX_FILTER_VID_UNSPEC,
					      mac_addr);
		if (rc != 0)
			pci_err(efx->pci_dev,
				"Filter set eth local failed, err: %d\n", rc);
	} else {
		efx_filter_set_mc_def(spec);
	}

	rc = efx_filter_insert_filter(efx, spec, true);
	if (rc < 0)
		pci_err(efx->pci_dev,
			"Filter insert failed, err: %d\n", rc);

	return rc;
}

static int ef100_vdpa_delete_filter(struct ef100_vdpa_nic *vdpa_nic,
				    enum ef100_vdpa_mac_filter_type type)
{
	struct vdpa_device *vdev = &vdpa_nic->vdpa_dev;
	int rc = 0;

	if (vdpa_nic->filters[type].filter_id == EFX_INVALID_FILTER_ID)
		return rc;

	rc = efx_filter_remove_id_safe(vdpa_nic->efx,
				       EFX_FILTER_PRI_MANUAL,
				       vdpa_nic->filters[type].filter_id);
	if (rc) {
		dev_err(&vdev->dev, "%s filter id: %d remove failed, err: %d\n",
			filter_names[type], vdpa_nic->filters[type].filter_id,
			rc);
	} else {
		dev_dbg(&vdev->dev, "%s filter id: %d removed\n",
			filter_names[type], vdpa_nic->filters[type].filter_id);
		vdpa_nic->filters[type].filter_id = EFX_INVALID_FILTER_ID;
		vdpa_nic->filter_cnt--;
	}
	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_INTERFACE)

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_ALLOC_ASID_NAME_USEVA_PARAMS)
static struct virtio_device_id ef100_vdpa_id_table[] =
#else
static const struct virtio_device_id ef100_vdpa_id_table[] =
#endif
{
	{ .device = VIRTIO_ID_NET, .vendor = PCI_VENDOR_ID_REDHAT_QUMRANET },
	{ 0 },
};

static void ef100_vdpa_net_dev_del(struct vdpa_mgmt_dev *mgmt_dev,
				   struct vdpa_device *vdev)
{
	struct efx_probe_data *probe_data;
	struct ef100_nic_data *nic_data;
	struct efx_nic *efx;
	int rc;

	efx = pci_get_drvdata(to_pci_dev(mgmt_dev->device));
	probe_data = container_of(efx, struct efx_probe_data, efx);
	nic_data = efx->nic_data;

	ef100_vdpa_fini(probe_data);
	rc = ef100_probe_netdev(probe_data);
	/* Update the bar_config value to maintain consistency across
	 * different user interfaces for vdpa device management
	 */
	if (rc) {
#ifdef EFX_NOT_UPSTREAM
		nic_data->bar_config = EF100_BAR_CONFIG_NONE;
#endif
		pci_err(efx->pci_dev,
			"netdev initialisation failed, err: %d\n", rc);
	} else {
		nic_data->bar_config = EF100_BAR_CONFIG_EF100;
		pci_dbg(efx->pci_dev,
			"vdpa net device deleted, vf: %u\n",
			nic_data->vf_index);
	}
}

static int ef100_vdpa_net_dev_add(struct vdpa_mgmt_dev *mgmt_dev,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
				  const char *name,
				  const struct vdpa_dev_set_config *config)
#else
				  const char *name)
#endif
{
	struct efx_probe_data *probe_data;
	struct ef100_vdpa_nic *vdpa_nic;
	struct ef100_nic_data *nic_data;
	struct efx_nic *efx;
	int rc, err;

	efx = pci_get_drvdata(to_pci_dev(mgmt_dev->device));
	if (efx->vdpa_nic) {
		pci_warn(efx->pci_dev,
			 "vDPA device already exists on this VF\n");
		return -EEXIST;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
	if (config->mask & BIT_ULL(VDPA_ATTR_DEV_NET_CFG_MACADDR)) {
		if (!is_valid_ether_addr(config->net.mac)) {
			pci_err(efx->pci_dev, "Invalid MAC address %pM\n",
				config->net.mac);
			return -EINVAL;
		}
	}
#endif

	probe_data = container_of(efx, struct efx_probe_data, efx);
	nic_data = efx->nic_data;

	ef100_remove_netdev(probe_data);
	rc = ef100_vdpa_init(probe_data);
	if (rc) {
		pci_err(efx->pci_dev,
			"ef100_vdpa_init failed, err: %d\n", rc);
		goto err_vdpa_init;
	}

	/* Update the bar_config value to maintain consistency across
	 * different user interfaces for vdpa device management
	 */
	nic_data->bar_config = EF100_BAR_CONFIG_VDPA;

	/* TODO: handle in_order feature with management interface
	 * This will be done in VDPALINUX-242
	 */

	vdpa_nic = ef100_vdpa_create(efx, name);
	if (IS_ERR(vdpa_nic)) {
		pci_err(efx->pci_dev,
			"vDPA device creation failed, vf: %u, err: %ld\n",
			nic_data->vf_index, PTR_ERR(vdpa_nic));
		rc = PTR_ERR(vdpa_nic);
		ef100_vdpa_fini(probe_data);
		goto err_vdpa_init;
	} else {
		pci_info(efx->pci_dev,
			 "vDPA net device created, vf: %u\n",
			 nic_data->vf_index);
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
	if (config->mask & BIT_ULL(VDPA_ATTR_DEV_NET_CFG_MACADDR)) {
		ether_addr_copy(vdpa_nic->mac_address, config->net.mac);
		vdpa_nic->mac_configured = true;

		if (vdpa_nic->vring[0].vring_created)
			ef100_vdpa_add_filter(vdpa_nic, EF100_VDPA_UCAST_MAC_FILTER);
	}
#endif

	/* TODO: handle MAC and MTU configuration from config parameter */
	return 0;

err_vdpa_init:
	err = ef100_probe_netdev(probe_data);
	if (err) {
#ifdef EFX_NOT_UPSTREAM
		nic_data->bar_config = EF100_BAR_CONFIG_NONE;
#endif
		pci_err(efx->pci_dev,
			"netdev initialisation failed, err: %d\n", err);
	} else {
		nic_data->bar_config = EF100_BAR_CONFIG_EF100;
		pci_dbg(efx->pci_dev,
			"ef100 netdev initialized, vf: %u\n",
			nic_data->vf_index);
	}
	return rc;
}

static const struct vdpa_mgmtdev_ops ef100_vdpa_net_mgmtdev_ops = {
	.dev_add = ef100_vdpa_net_dev_add,
	.dev_del = ef100_vdpa_net_dev_del
};

int ef100_vdpa_register_mgmtdev(struct efx_nic *efx)
{
	struct vdpa_mgmt_dev *mgmt_dev;
	int rc;

	mgmt_dev = kzalloc(sizeof(*mgmt_dev), GFP_KERNEL);
	if (!mgmt_dev)
		return -ENOMEM;

	efx->mgmt_dev = mgmt_dev;
	mgmt_dev->device = &efx->pci_dev->dev;
	mgmt_dev->id_table = ef100_vdpa_id_table;
	mgmt_dev->ops = &ef100_vdpa_net_mgmtdev_ops;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
	mgmt_dev->config_attr_mask = BIT_ULL(VDPA_ATTR_DEV_NET_CFG_MACADDR);
#endif
	rc = vdpa_mgmtdev_register(mgmt_dev);
	if (rc) {
		pci_err(efx->pci_dev,
			"vdpa management device register failed, err: %d\n",
			rc);
		kfree(mgmt_dev);
		efx->mgmt_dev = NULL;
	} else {
		pci_dbg(efx->pci_dev, "vdpa management device created\n");
	}

	return rc;
}

void ef100_vdpa_unregister_mgmtdev(struct efx_nic *efx)
{
	pci_dbg(efx->pci_dev, "Unregister vdpa_management_device\n");
	if (efx->mgmt_dev)
		vdpa_mgmtdev_unregister(efx->mgmt_dev);
	efx->mgmt_dev = NULL;
}
#endif

int ef100_vdpa_add_filter(struct ef100_vdpa_nic *vdpa_nic,
			  enum ef100_vdpa_mac_filter_type type)
{
	struct vdpa_device *vdev = &vdpa_nic->vdpa_dev;
	struct efx_nic *efx = vdpa_nic->efx;
	/* Configure filter on base Rx queue only */
	u32 qid = EF100_VDPA_BASE_RX_QID;
	struct efx_filter_spec *spec;
	u8 baddr[ETH_ALEN];
	int rc;

	/* remove existing filter */
	rc = ef100_vdpa_delete_filter(vdpa_nic, type);
	if (rc < 0) {
		dev_err(&vdev->dev, "%s MAC filter deletion failed, err: %d",
			filter_names[type], rc);
		return rc;
	}

	/* Configure MAC Filter */
	spec = &vdpa_nic->filters[type].spec;
	if (type == EF100_VDPA_BCAST_MAC_FILTER) {
		eth_broadcast_addr(baddr);
		rc = ef100_vdpa_set_mac_filter(efx, spec, qid, baddr);
	} else if (type == EF100_VDPA_UNKNOWN_MCAST_MAC_FILTER) {
		rc = ef100_vdpa_set_mac_filter(efx, spec, qid, NULL);
	} else {
		if (!vdpa_nic->mac_configured ||
		    !vdpa_nic->vring[0].vring_created ||
		    !is_valid_ether_addr(vdpa_nic->mac_address)) {
			dev_err(&vdev->dev,
				"MAC: %pM, mac_conf: %d, vring_created: %d\n",
				vdpa_nic->mac_address, vdpa_nic->mac_configured,
				vdpa_nic->vring[0].vring_created);
			return -EINVAL;
		}

		rc = ef100_vdpa_set_mac_filter(efx, spec, qid,
					       vdpa_nic->mac_address);
		dev_dbg(&vdev->dev, "ucast mac: %pM\n", vdpa_nic->mac_address);
	}

	if (rc < 0) {
		if (type != EF100_VDPA_UNKNOWN_MCAST_MAC_FILTER) {
			dev_err(&vdev->dev,
				"%s MAC filter insert failed, err: %d\n",
				filter_names[type], rc);
			goto fail;
		} else {
			dev_warn(&vdev->dev,
				 "%s MAC filter insert failed, err: %d\n",
				 filter_names[type], rc);
			/* return success, mcast filter not mandatory */
			return 0;
		}
	}

	vdpa_nic->filters[type].filter_id = rc;
	vdpa_nic->filter_cnt++;
	dev_dbg(&vdev->dev, "vDPA %s filter created, filter_id: %d\n",
		filter_names[type], rc);
	return 0;

fail:
	ef100_vdpa_filter_remove(vdpa_nic);
	return rc;
}

int ef100_vdpa_filter_remove(struct ef100_vdpa_nic *vdpa_nic)
{
	enum ef100_vdpa_mac_filter_type filter;
	int err = 0;
	int rc = 0;

	for (filter = EF100_VDPA_BCAST_MAC_FILTER;
	     filter <= EF100_VDPA_UNKNOWN_MCAST_MAC_FILTER; filter++) {
		rc = ef100_vdpa_delete_filter(vdpa_nic, filter);
		if (rc < 0)
			/* store status of last failed filter remove */
			err = rc;
	}
	return err;
}

int ef100_vdpa_filter_configure(struct ef100_vdpa_nic *vdpa_nic)
{
	struct vdpa_device *vdev = &vdpa_nic->vdpa_dev;
	enum ef100_vdpa_mac_filter_type filter;
	struct efx_nic *efx = vdpa_nic->efx;
	int rc = 0;

	/* remove existing filters, if any */
	rc = ef100_vdpa_filter_remove(vdpa_nic);
	if (rc < 0) {
		dev_err(&vdev->dev,
			"MAC filter deletion failed, err: %d", rc);
		goto fail;
	}

	rc = efx->type->filter_table_up(efx);
	if (rc < 0) {
		dev_err(&vdev->dev,
			"filter_table_up failed, err: %d", rc);
		goto fail;
	}

	for (filter = EF100_VDPA_BCAST_MAC_FILTER;
	     filter <= EF100_VDPA_UNKNOWN_MCAST_MAC_FILTER; filter++) {
		if (filter == EF100_VDPA_UCAST_MAC_FILTER &&
		    !vdpa_nic->mac_configured)
			continue;
		rc = ef100_vdpa_add_filter(vdpa_nic, filter);
		if (rc < 0)
			goto fail;
	}
fail:
	return rc;
}

#ifdef EFX_NOT_UPSTREAM
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
static ssize_t vdpa_mac_show(struct device *dev,
				struct device_attribute *attr,
				char *buf_out)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct ef100_vdpa_nic *vdpa_nic = efx->vdpa_nic;
	int len;

	/* print MAC in big-endian format */
	len = scnprintf(buf_out, PAGE_SIZE, "%pM\n", vdpa_nic->mac_address);

	return len;
}

static ssize_t vdpa_mac_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
	struct ef100_nic_data *nic_data = efx->nic_data;
#endif
	struct ef100_vdpa_nic *vdpa_nic;
	struct vdpa_device *vdev;
	u8 mac_address[ETH_ALEN];
	int rc = 0;

	vdpa_nic = efx->vdpa_nic;
	if (vdpa_nic == NULL) {
		pci_err(efx->pci_dev,
			"vDPA device doesn't exist!\n");
		return -ENOENT;
	}

	mutex_lock(&vdpa_nic->lock);
	vdev = &vdpa_nic->vdpa_dev;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
	if (nic_data->vdpa_class != EF100_VDPA_CLASS_NET) {
		dev_err(&vdev->dev,
			"Invalid vDPA device class: %u\n", nic_data->vdpa_class);
		rc = -EINVAL;
		goto err;
	}
#endif

	rc = sscanf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		    &mac_address[0], &mac_address[1], &mac_address[2],
		    &mac_address[3], &mac_address[4], &mac_address[5]);

	if (rc != ETH_ALEN) {
		dev_err(&vdev->dev,
			"Invalid MAC address %s\n", buf);
		rc = -EINVAL;
		goto err;
	}

	ether_addr_copy(vdpa_nic->mac_address, (const u8 *)&mac_address);
	vdpa_nic->mac_configured = true;

	if (vdpa_nic->vring[0].vring_created)
		ef100_vdpa_add_filter(vdpa_nic, EF100_VDPA_UCAST_MAC_FILTER);

err:
	mutex_unlock(&vdpa_nic->lock);
	if (rc < 0)
		return rc;
	return count;
}

static DEVICE_ATTR_RW(vdpa_mac);
#endif
#endif /* EFX_NOT_UPSTREAM */

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
static ssize_t vdpa_class_show(struct device *dev,
				struct device_attribute *attr,
				char *buf_out)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct ef100_nic_data *nic_data = efx->nic_data;
	int len = 0;

	mutex_lock(&nic_data->bar_config_lock);
	switch (nic_data->vdpa_class) {
	case EF100_VDPA_CLASS_NONE:
		len = scnprintf(buf_out, PAGE_SIZE,
				"VDPA_CLASS_NONE\n");
		break;
	case EF100_VDPA_CLASS_NET:
		len = scnprintf(buf_out, PAGE_SIZE,
				"VDPA_CLASS_NET\n");
		break;
	case EF100_VDPA_CLASS_BLOCK:
		len = scnprintf(buf_out, PAGE_SIZE,
				"VDPA_CLASS_BLOCK\n");
		break;
	default:
		len = scnprintf(buf_out, PAGE_SIZE,
				"VDPA_CLASS_INVALID\n");
	}

	mutex_unlock(&nic_data->bar_config_lock);
	return len;
}

static ssize_t vdpa_class_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct ef100_nic_data *nic_data = efx->nic_data;
	enum ef100_vdpa_class vdpa_class;
	struct ef100_vdpa_nic *vdpa_nic;
	bool in_order = false;
	int rc = 0;

	mutex_lock(&nic_data->bar_config_lock);
	if (sysfs_streq(buf, "net")) {
		vdpa_class = EF100_VDPA_CLASS_NET;
	} else if (sysfs_streq(buf, "net_io")) {
		vdpa_class = EF100_VDPA_CLASS_NET;
		in_order = true;
	} else if (sysfs_streq(buf, "block")) {
		vdpa_class = EF100_VDPA_CLASS_BLOCK;
	} else if (sysfs_streq(buf, "none")) {
		vdpa_class = EF100_VDPA_CLASS_NONE;
	} else {
		rc = -EINVAL;
		goto fail;
	}

	switch (nic_data->vdpa_class) {
	case EF100_VDPA_CLASS_NONE:
		if (vdpa_class == EF100_VDPA_CLASS_NET) {
			char name[EFX_VDPA_NAME_LEN];

			snprintf(name, sizeof(name), EFX_VDPA_NAME(nic_data));
			/* only vdpa net devices are supported as of now */
			vdpa_nic = ef100_vdpa_create(efx, name, EF100_VDPA_CLASS_NET);
			if (IS_ERR(vdpa_nic)) {
				pci_err(efx->pci_dev,
					"vDPA device creation failed, err: %ld",
					PTR_ERR(vdpa_nic));
				rc = PTR_ERR(vdpa_nic);
				goto fail;
			}

			vdpa_nic->in_order = in_order;
			pci_info(efx->pci_dev,
				 "vDPA net device created, vf: %u\n",
				 nic_data->vf_index);
		} else if (vdpa_class == EF100_VDPA_CLASS_BLOCK) {
			/* TODO: handle block vdpa device creation */
			pci_info(efx->pci_dev,
				 "vDPA block device not supported\n");
			rc = -EINVAL;
			goto fail;
		} else {
			pci_err(efx->pci_dev,
				"Invalid vdpa class transition %u->%u",
				EF100_VDPA_CLASS_NONE, vdpa_class);
			rc = -EINVAL;
			goto fail;
		}
		break;

	case EF100_VDPA_CLASS_NET:

		if (vdpa_class == EF100_VDPA_CLASS_NONE) {
			if (ef100_vdpa_dev_in_use(efx)) {
				pci_warn(efx->pci_dev,
					 "Device in use cannot change class");
				rc = -EBUSY;
				goto fail;
			}
			ef100_vdpa_delete(efx);
			nic_data->vdpa_class = EF100_VDPA_CLASS_NONE;
			pci_info(efx->pci_dev,
				 "vDPA net device removed, vf: %u\n",
				 nic_data->vf_index);
		} else {
			pci_err(efx->pci_dev,
				"Invalid vdpa class transition %u->%u",
				EF100_VDPA_CLASS_NET, vdpa_class);
			rc = -EINVAL;
			goto fail;
		}
		break;

	case EF100_VDPA_CLASS_BLOCK:
		/* TODO: delete vdpa block device */
		pci_info(efx->pci_dev,
			 "vDPA block device not implemented\n");
		rc = -EINVAL;
		goto fail;

	default:
		break;
	}

fail:
	mutex_unlock(&nic_data->bar_config_lock);
	if (rc)
		return rc;
	return count;
}

static DEVICE_ATTR_RW(vdpa_class);
#endif

static int vdpa_create_files(struct efx_nic *efx)
{
#if (defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)) ||\
defined(EFX_NOT_UPSTREAM)
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
	int rc;
#endif
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_vdpa_class);
	if (rc) {
		pci_err(efx->pci_dev, "vdpa_class file creation failed\n");
		return rc;
	}
#endif

#ifdef EFX_NOT_UPSTREAM
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_vdpa_mac);
	if (rc) {
		pci_err(efx->pci_dev, "vdpa_mac file creation failed\n");
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
		device_remove_file(&efx->pci_dev->dev, &dev_attr_vdpa_class);
#endif
		return rc;
	}
#endif
#endif

	return 0;
}

static void vdpa_remove_files(struct efx_nic *efx)
{
#ifdef EFX_NOT_UPSTREAM
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
	device_remove_file(&efx->pci_dev->dev, &dev_attr_vdpa_mac);
#endif
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
	device_remove_file(&efx->pci_dev->dev, &dev_attr_vdpa_class);
#endif
}

static int vdpa_update_domain(struct ef100_vdpa_nic *vdpa_nic)
{
	struct vdpa_device *vdpa = &vdpa_nic->vdpa_dev;
	struct device *dma_dev = vdpa_get_dma_dev(vdpa);
	struct iommu_domain_geometry *geo;
	struct bus_type *bus;

	bus = dma_dev->bus;
	if (!bus)
		return -EFAULT;

	if (!iommu_capable(bus, IOMMU_CAP_CACHE_COHERENCY))
		return -ENOTSUPP;

	vdpa_nic->domain = iommu_get_domain_for_dev(dma_dev);
	if (!vdpa_nic->domain)
		return -ENODEV;

	geo = &vdpa_nic->domain->geometry;
	dev_info(&vdpa_nic->vdpa_dev.dev,
		 "iova_range_start: %llx, iova_range_end: %llx\n",
		 geo->aperture_start, geo->aperture_end);

	/* save the geo aperture range for validation in dma_map */
	vdpa_nic->geo_aper_start = geo->aperture_start;

	/* Handle the boundary case */
	if (geo->aperture_end == ~0ULL)
		geo->aperture_end -= 1;
	vdpa_nic->geo_aper_end = geo->aperture_end;

	/* insert a sentinel node */
	return efx_ef100_insert_iova_node(vdpa_nic,
					  vdpa_nic->geo_aper_end + 1, 0);
}

int ef100_vdpa_init(struct efx_probe_data *probe_data)
{
	struct efx_nic *efx = &probe_data->efx;
	int rc = 0;

	if (efx->state != STATE_PROBED) {
		pci_err(efx->pci_dev, "Invalid efx state %u", efx->state);
		return -EBUSY;
	}

	rc = vdpa_create_files(efx);
	if (rc) {
		pci_err(efx->pci_dev, "vdpa_create_file failed, err: %d\n", rc);
		return rc;
	}
	efx->state = STATE_VDPA;
	rc = ef100_filter_table_probe(efx);
	if (rc) {
		pci_err(efx->pci_dev, "filter probe failed, err: %d\n", rc);
		goto err_remove_vdpa_files;
	}

	if (!efx->type->filter_table_probe)
		goto err_remove_vdpa_files;

	rc = efx->type->filter_table_probe(efx);
	if (!rc)
		return 0;

	pci_err(efx->pci_dev, "filter_table_probe failed, err: %d\n", rc);
	efx_mcdi_filter_table_remove(efx);

err_remove_vdpa_files:
	vdpa_remove_files(efx);
	efx->state = STATE_PROBED;
	return rc;
}

void ef100_vdpa_fini(struct efx_probe_data *probe_data)
{
	struct efx_nic *efx = &probe_data->efx;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
	struct ef100_nic_data *nic_data = efx->nic_data;
#endif

	if (efx->state != STATE_VDPA && efx->state != STATE_DISABLED) {
		pci_err(efx->pci_dev, "Invalid efx state %u", efx->state);
		return;
	}

	/* Handle vdpa device deletion, if not done explicitly */
	ef100_vdpa_delete(efx);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
	nic_data->vdpa_class = EF100_VDPA_CLASS_NONE;
#endif

	vdpa_remove_files(efx);

	efx->state = STATE_PROBED;

	if (efx->type->filter_table_remove)
		efx->type->filter_table_remove(efx);
	efx_mcdi_filter_table_remove(efx);
}

static int get_net_config(struct ef100_vdpa_nic *vdpa_nic)
{
	struct efx_nic *efx = vdpa_nic->efx;
	u16 mtu, link_up;
	u32 speed;
	u8 duplex;
	int rc = 0;

	vdpa_nic->mac_configured = false;
	rc = efx_vdpa_get_mac_address(efx,
				      vdpa_nic->net_config.mac);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Get MAC address for vf:%u failed, rc:%d\n",
			 __func__, vdpa_nic->vf_index, rc);
		return rc;
	}

	/* Set mac_configured to true for Non-Zero MAC address */
	if (!is_zero_ether_addr(vdpa_nic->mac_address))
		vdpa_nic->mac_configured = true;

	vdpa_nic->net_config.max_virtqueue_pairs =
		(__virtio16 __force)vdpa_nic->max_queue_pairs;

	rc = efx_vdpa_get_mtu(efx, &mtu);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Get MTU for vf:%u failed:%d\n", __func__,
			vdpa_nic->vf_index, rc);
		return rc;
	}
	vdpa_nic->net_config.mtu = (__virtio16 __force)mtu;

	rc = efx_vdpa_get_link_details(efx, &link_up, &speed, &duplex);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Get Link details for vf:%u failed:%d\n", __func__,
			vdpa_nic->vf_index, rc);
		return rc;
	}
	vdpa_nic->net_config.status = (__virtio16 __force)link_up;
	vdpa_nic->net_config.speed = (__le32 __force)speed;
	vdpa_nic->net_config.duplex = duplex;

	dev_info(&vdpa_nic->vdpa_dev.dev, "%s: mac address: %pM\n", __func__,
		 vdpa_nic->net_config.mac);
	dev_info(&vdpa_nic->vdpa_dev.dev, "%s: MTU:%u\n", __func__,
		 vdpa_nic->net_config.mtu);
	dev_info(&vdpa_nic->vdpa_dev.dev,
		 "%s: Status:%u Link Speed:%u Duplex:%u\n", __func__,
		 vdpa_nic->net_config.status,
		 vdpa_nic->net_config.speed,
		 vdpa_nic->net_config.duplex);
	return 0;
}

static int vdpa_allocate_vis(struct efx_nic *efx, unsigned int *allocated_vis)
{
	/* The first VI is reserved for MCDI
	 * 1 VI each for rx + tx ring
	 */
	unsigned int max_vis = 1 + EF100_VDPA_MAX_QUEUES_PAIRS;
	unsigned int min_vis = 1 + 1;
	int rc = 0;

	rc = efx_mcdi_alloc_vis(efx, min_vis, max_vis,
				NULL, NULL,
				allocated_vis);
	if (!rc)
		return rc;
	if (*allocated_vis < min_vis)
		return -ENOSPC;
	return 0;
}

static void vdpa_free_vis(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	int rc;

	rc = efx_mcdi_free_vis(efx);
	if (rc)
		pci_err(efx->pci_dev, "vDPA free vis failed for vf: %u\n",
			nic_data->vf_index);
}

static int ef100_vdpa_alloc_buffer(struct efx_nic *efx, struct efx_buffer *buf)
{
       struct ef100_vdpa_nic *vdpa_nic = efx->vdpa_nic;
       struct device *dev;
       int rc = 0;

       dev = &vdpa_nic->vdpa_dev.dev;

       buf->addr = kzalloc(buf->len, GFP_KERNEL);
       if (!buf->addr) {
               dev_err(dev, "vdpa buf alloc failed\n");
               return -ENOMEM;
       }

       rc = iommu_map(vdpa_nic->domain, buf->dma_addr,
                      virt_to_phys(buf->addr), buf->len,
                      IOMMU_READ|IOMMU_WRITE|IOMMU_CACHE);
       if (rc)
               dev_err(dev, "iommu_map failed, rc: %d\n", rc);

       return rc;
}

int ef100_vdpa_free_buffer(struct ef100_vdpa_nic *vdpa_nic,
			   struct efx_buffer *buf)
{
       struct device *dev;
       int rc = 0;

       dev = &vdpa_nic->vdpa_dev.dev;
       rc = iommu_unmap(vdpa_nic->domain, buf->dma_addr, buf->len);
       if (rc < 0)
               dev_err(dev, "iommu_unmap failed, rc: %d\n", rc);

       kfree(buf->addr);
       return rc;
}

int setup_ef100_mcdi_buffer(struct ef100_vdpa_nic *vdpa_nic)
{
	struct efx_nic *efx = vdpa_nic->efx;
       struct ef100_nic_data *nic_data = efx->nic_data;
       struct efx_mcdi_iface *mcdi;
       struct efx_buffer mcdi_buf;
       enum efx_mcdi_mode mode;
       struct device *dev;
       int rc;

       /* Set MCDI mode to fail to prevent any new commands and
	* then wait for outstanding commands to complete.
	*/
       mcdi = efx_mcdi(efx);
       spin_lock_bh(&mcdi->iface_lock);
       mode = mcdi->mode;
       mcdi->mode = MCDI_MODE_FAIL;
       spin_unlock_bh(&mcdi->iface_lock);
       efx_mcdi_wait_for_cleanup(efx);

       dev = &vdpa_nic->vdpa_dev.dev;

       /* First, allocate the MCDI buffer for EF100 mode */
       rc = efx_nic_alloc_buffer(efx, &mcdi_buf,
                                 MCDI_BUF_LEN, GFP_KERNEL);
       if (rc) {
               dev_err(dev, "nic alloc buf failed, rc: %d\n", rc);
               goto fail_alloc;
       }

       /* unmap and free the vDPA MCDI buffer now */
       ef100_vdpa_free_buffer(vdpa_nic, &nic_data->mcdi_buf);
       memcpy(&nic_data->mcdi_buf, &mcdi_buf, sizeof(struct efx_buffer));
       efx->mcdi_buf_mode = EFX_BUF_MODE_EF100;
       spin_lock_bh(&mcdi->iface_lock);
       mcdi->mode = mode;
       spin_unlock_bh(&mcdi->iface_lock);

       return 0;

fail_alloc:
       return rc;
}

int setup_vdpa_mcdi_buffer(struct efx_nic *efx, u64 mcdi_iova)
{
       struct ef100_nic_data *nic_data = efx->nic_data;
       struct efx_mcdi_iface *mcdi;
       struct efx_buffer mcdi_buf;
       enum efx_mcdi_mode mode;
       int rc;

       /* Set MCDI mode to fail to prevent any new commands and
	* then wait for outstanding commands to complete.
	*/
       mcdi = efx_mcdi(efx);
       spin_lock_bh(&mcdi->iface_lock);
       mode = mcdi->mode;
       mcdi->mode = MCDI_MODE_FAIL;
       spin_unlock_bh(&mcdi->iface_lock);
       efx_mcdi_wait_for_cleanup(efx);

       /* First, prepare the MCDI buffer for vDPA mode */
       mcdi_buf.dma_addr = mcdi_iova;
       /* iommu_map requires page aligned memory */
       mcdi_buf.len = PAGE_ALIGN(MCDI_BUF_LEN);
       rc = ef100_vdpa_alloc_buffer(efx, &mcdi_buf);
       if (rc) {
               pci_err(efx->pci_dev, "alloc vdpa buf failed, rc: %d\n", rc);
               goto fail;
       }

       /* All set-up, free the EF100 MCDI buffer now */
       efx_nic_free_buffer(efx, &nic_data->mcdi_buf);
       memcpy(&nic_data->mcdi_buf, &mcdi_buf, sizeof(struct efx_buffer));
       efx->mcdi_buf_mode = EFX_BUF_MODE_VDPA;
       spin_lock_bh(&mcdi->iface_lock);
       mcdi->mode = mode;
       spin_unlock_bh(&mcdi->iface_lock);

       return 0;

fail:
       return rc;
}

int remap_vdpa_mcdi_buffer(struct efx_nic *efx, u64 mcdi_iova)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct ef100_vdpa_nic *vdpa_nic = efx->vdpa_nic;
	struct efx_mcdi_iface *mcdi;
	struct efx_buffer *mcdi_buf;
	int rc;

	mcdi_buf = &nic_data->mcdi_buf;
	mcdi = efx_mcdi(efx);
	spin_lock_bh(&mcdi->iface_lock);

	pci_info(efx->pci_dev,
		 "mcdi_buf current dma_addr: %llx\n", mcdi_buf->dma_addr);

	rc = iommu_unmap(vdpa_nic->domain, mcdi_buf->dma_addr, mcdi_buf->len);
	if (rc < 0) {
		pci_err(efx->pci_dev, "iommu_unmap failed, rc: %d\n", rc);
		goto out;
	}

	rc = iommu_map(vdpa_nic->domain, mcdi_iova,
		       virt_to_phys(mcdi_buf->addr),
		       mcdi_buf->len,
		       IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE);
	if (rc) {
		pci_err(efx->pci_dev, "iommu_map failed, rc: %d\n", rc);
		goto out;
	}

	mcdi_buf->dma_addr = mcdi_iova;
	pci_info(efx->pci_dev,
		 "remapped mcdi_buf to dma_addr: %llx\n", mcdi_iova);

out:
	spin_unlock_bh(&mcdi->iface_lock);
	return rc;
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
struct ef100_vdpa_nic *ef100_vdpa_create(struct efx_nic *efx,
					 const char *dev_name,
					 enum ef100_vdpa_class dev_type)
#else
struct ef100_vdpa_nic *ef100_vdpa_create(struct efx_nic *efx,
					 const char *dev_name)
#endif
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct ef100_vdpa_nic *vdpa_nic;
	unsigned int allocated_vis;
	struct device *dev;
	int rc;
	u8 i;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
	if (dev_type != EF100_VDPA_CLASS_NET) {
		/* only vdpa net devices are supported as of now */
		pci_err(efx->pci_dev,
			"Invalid vDPA device class: %u\n", dev_type);
		return ERR_PTR(-EINVAL);
	} else {
		nic_data->vdpa_class = dev_type;
	}
#endif

	rc = vdpa_allocate_vis(efx, &allocated_vis);
	if (rc) {
		pci_err(efx->pci_dev,
			"%s Alloc VIs failed for vf:%u error:%d\n",
			 __func__, nic_data->vf_index, rc);
		return ERR_PTR(rc);
	}

	vdpa_nic = vdpa_alloc_device(struct ef100_vdpa_nic,
				     vdpa_dev, &efx->pci_dev->dev,
				     &ef100_vdpa_config_ops
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_REGISTER_NVQS_PARAM) && defined(EFX_HAVE_VDPA_ALLOC_NVQS_PARAM)
				     , (allocated_vis - 1) * 2
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_ALLOC_ASID_NAME_USEVA_PARAMS)
				     , 1, 1
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_ALLOC_NAME_PARAM) || defined(EFX_HAVE_VDPA_ALLOC_NAME_USEVA_PARAMS) || defined(EFX_HAVE_VDPA_ALLOC_ASID_NAME_USEVA_PARAMS)
				     , dev_name
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_ALLOC_NAME_USEVA_PARAMS) || defined(EFX_HAVE_VDPA_ALLOC_ASID_NAME_USEVA_PARAMS)
				     , false
#endif
				     );
	if (!vdpa_nic) {
		pci_err(efx->pci_dev,
			"vDPA device allocation failed for vf: %u\n",
			nic_data->vf_index);
		rc = -ENOMEM;
		goto err_alloc_vis_free;
	}

	mutex_init(&vdpa_nic->lock);
	mutex_init(&vdpa_nic->iova_lock);
	vdpa_nic->vdpa_dev.dma_dev = &efx->pci_dev->dev;
	efx->vdpa_nic = vdpa_nic;
	vdpa_nic->efx = efx;
	vdpa_nic->max_queue_pairs = allocated_vis - 1;
	vdpa_nic->pf_index = nic_data->pf_index;
	vdpa_nic->vf_index = nic_data->vf_index;
	vdpa_nic->vdpa_state = EF100_VDPA_STATE_INITIALIZED;
	vdpa_nic->iova_root = RB_ROOT;
	vdpa_nic->mac_address = (u8 *)&vdpa_nic->net_config.mac;
	INIT_LIST_HEAD(&vdpa_nic->free_list);

	dev = &vdpa_nic->vdpa_dev.dev;
	dev_info(dev, "%s: vDPA dev pf_index:%u vf_index:%u max_queues:%u\n",
		 __func__, vdpa_nic->pf_index, vdpa_nic->vf_index,
		 vdpa_nic->max_queue_pairs);

	for (i = 0; i < EF100_VDPA_MAC_FILTER_NTYPES; i++)
		vdpa_nic->filters[i].filter_id = EFX_INVALID_FILTER_ID;

	for (i = 0; i < (2 * vdpa_nic->max_queue_pairs); i++)
		vdpa_nic->vring[i].irq = -EINVAL;

	rc = ef100_vdpa_irq_vectors_alloc(efx->pci_dev,
					  (vdpa_nic->max_queue_pairs * 2),
					  (vdpa_nic->max_queue_pairs * 2));
	if (rc < 0) {
		pci_err(efx->pci_dev,
			"vDPA IRQ alloc failed for vf: %u err:%d\n",
			nic_data->vf_index, rc);
		goto err_put_device;
	}

	rc = devm_add_action_or_reset(&efx->pci_dev->dev,
				      ef100_vdpa_irq_vectors_free,
				      efx->pci_dev);
	if (rc) {
		pci_err(efx->pci_dev,
			"Failed adding devres for freeing irq vectors\n");
		goto err_put_device;
	}

	rc = vdpa_update_domain(vdpa_nic);
	if (rc) {
		pci_err(efx->pci_dev, "update_domain failed, err: %d\n", rc);
		goto err_put_device;
	}

	rc = setup_vdpa_mcdi_buffer(efx, EF100_VDPA_IOVA_BASE_ADDR);
	if (rc) {
		pci_err(efx->pci_dev, "realloc mcdi failed, err: %d\n", rc);
		goto err_put_device;
	}

#ifdef CONFIG_SFC_DEBUGFS
	rc = efx_init_debugfs_vdpa(vdpa_nic);
	if (rc)
		goto err_put_device;
#endif

	rc = get_net_config(vdpa_nic);
	if (rc)
		goto err_put_device;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
	vdpa_nic->vdpa_dev.mdev = efx->mgmt_dev;
	/* Caller must invoke this routine in the management device
	 * dev_add() callback
	 */
	rc = _vdpa_register_device(&vdpa_nic->vdpa_dev,
				   (allocated_vis - 1) * 2);
#else
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_REGISTER_NVQS_PARAM)
	rc = vdpa_register_device(&vdpa_nic->vdpa_dev,
				  (allocated_vis - 1) * 2);
#else
	rc = vdpa_register_device(&vdpa_nic->vdpa_dev);
#endif
#endif
	if (rc) {
		pci_err(efx->pci_dev,
			"vDPA device registration failed for vf: %u\n",
			nic_data->vf_index);
		goto err_put_device;
	}

	return vdpa_nic;

err_put_device:
	/* put_device invokes ef100_vdpa_free */
	put_device(&vdpa_nic->vdpa_dev.dev);

err_alloc_vis_free:
	vdpa_free_vis(efx);
	return ERR_PTR(rc);
}

void ef100_vdpa_delete(struct efx_nic *efx)
{
	if (efx->vdpa_nic) {
		mutex_lock(&efx->vdpa_nic->lock);
		reset_vdpa_device(efx->vdpa_nic);
		mutex_unlock(&efx->vdpa_nic->lock);

#ifdef EFX_NOT_UPSTREAM
		pci_info(efx->pci_dev,
			 "%s: Calling vdpa unregister device\n", __func__);
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
		vdpa_unregister_device(&efx->vdpa_nic->vdpa_dev);
#else
		/* Caller must invoke this routine as part of
		 * management device dev_del() callback
		 */
		_vdpa_unregister_device(&efx->vdpa_nic->vdpa_dev);
#endif

#ifdef EFX_NOT_UPSTREAM
		pci_info(efx->pci_dev,
			 "%s: vdpa unregister device completed\n", __func__);
#endif
		efx->vdpa_nic = NULL;
		vdpa_free_vis(efx);
	}
}

/* A non zero value of vdpa status signifies that the vDPA device
 * is in use and hence cannot be removed. Also on killing qemu
 * a device reset is called with status equal to 0.
 */
bool ef100_vdpa_dev_in_use(struct efx_nic *efx)
{
	struct ef100_vdpa_nic *vdpa_nic = efx->vdpa_nic;

	if (vdpa_nic)
		if (vdpa_nic->status >= VIRTIO_CONFIG_S_DRIVER)
			return true;

	return false;
}

#endif

