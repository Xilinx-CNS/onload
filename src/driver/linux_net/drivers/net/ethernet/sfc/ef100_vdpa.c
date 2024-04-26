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
#include "ef100_netdev.h"
#include "mcdi_filters.h"
#include "debugfs.h"

#if defined(CONFIG_SFC_VDPA)
#define EFX_VDPA_NAME_LEN 32

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
	struct ef100_nic_data *nic_data;
	struct efx_nic *efx;
	int rc;

	efx = pci_get_drvdata(to_pci_dev(mgmt_dev->device));
	nic_data = efx->nic_data;

	rc = efx_ef100_set_bar_config(efx, EF100_BAR_CONFIG_EF100);
	if (rc)
		pci_err(efx->pci_dev,
			"set_bar_config EF100 failed, err: %d\n", rc);
	else
		pci_dbg(efx->pci_dev,
			"vdpa net device deleted, vf: %u\n",
			nic_data->vf_index);
}

static int ef100_vdpa_net_dev_add(struct vdpa_mgmt_dev *mgmt_dev,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
				  const char *name,
				  const struct vdpa_dev_set_config *config)
#else
				  const char *name)
#endif
{
	struct ef100_vdpa_nic *vdpa_nic;
	struct ef100_nic_data *nic_data;
	struct efx_nic *efx;
	int rc, err;

	efx = pci_get_drvdata(to_pci_dev(mgmt_dev->device));
	nic_data = efx->nic_data;

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

	rc = efx_ef100_set_bar_config(efx, EF100_BAR_CONFIG_VDPA);
	if (rc) {
		pci_err(efx->pci_dev,
			"set_bar_config vDPA failed, err: %d\n", rc);
		goto err_set_bar_config;
	}

	/* TODO: handle in_order feature with management interface
	 * This will be done in VDPALINUX-242
	 */

	vdpa_nic = ef100_vdpa_create(efx, name);
	if (IS_ERR(vdpa_nic)) {
		pci_err(efx->pci_dev,
			"vDPA device creation failed, vf: %u, err: %ld\n",
			nic_data->vf_index, PTR_ERR(vdpa_nic));
		rc = PTR_ERR(vdpa_nic);
		goto err_set_bar_config;
	} else {
		pci_info(efx->pci_dev,
			 "vDPA net device created, vf: %u\n",
			 nic_data->vf_index);
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
	if (config->mask & BIT_ULL(VDPA_ATTR_DEV_NET_CFG_MACADDR)) {
		ether_addr_copy(vdpa_nic->mac_address, config->net.mac);

		/* It has been observed during testing with virtio-vdpa
		 * that virtio feature negotiation and vring creation
		 * happens before control reaches here.
		 */
		if (vdpa_nic->vring[0].vring_state & EF100_VRING_CREATED)
			ef100_vdpa_insert_filter(efx);
	}
#endif

	/* TODO: handle MTU configuration from config parameter */
	return 0;

err_set_bar_config:
	err = efx_ef100_set_bar_config(efx, EF100_BAR_CONFIG_EF100);
	if (err)
		pci_err(efx->pci_dev,
			"set_bar_config EF100 failed, err: %d\n", err);

	return rc;
}

static const struct vdpa_mgmtdev_ops ef100_vdpa_net_mgmtdev_ops = {
	.dev_add = ef100_vdpa_net_dev_add,
	.dev_del = ef100_vdpa_net_dev_del
};

int ef100_vdpa_register_mgmtdev(struct efx_nic *efx)
{
	struct vdpa_mgmt_dev *mgmt_dev;
	u64 features;
	int rc;

	mgmt_dev = kzalloc(sizeof(*mgmt_dev), GFP_KERNEL);
	if (!mgmt_dev)
		return -ENOMEM;

	rc = efx_vdpa_get_features(efx, EF100_VDPA_DEVICE_TYPE_NET, &features);
	if (rc) {
		pci_err(efx->pci_dev, "%s: MCDI get features error:%d\n",
			__func__, rc);
		goto free_mgmt_dev;
	}

	efx->mgmt_dev = mgmt_dev;
	mgmt_dev->device = &efx->pci_dev->dev;
	mgmt_dev->id_table = ef100_vdpa_id_table;
	mgmt_dev->ops = &ef100_vdpa_net_mgmtdev_ops;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_SUPPORTED_FEATURES)
	mgmt_dev->supported_features = features;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MAX_SUPPORTED_VQS)
	mgmt_dev->max_supported_vqs = EF100_VDPA_MAX_QUEUES_PAIRS * 2;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM)
	mgmt_dev->config_attr_mask = BIT_ULL(VDPA_ATTR_DEV_NET_CFG_MACADDR);
#endif
	rc = vdpa_mgmtdev_register(mgmt_dev);
	if (rc) {
		pci_err(efx->pci_dev,
			"vdpa management device register failed, err: %d\n",
			rc);
		goto free_mgmt_dev;
#ifdef EFX_NOT_UPSTREAM
	} else {
		pci_dbg(efx->pci_dev, "vdpa management device created\n");
#endif
	}

	return 0;

free_mgmt_dev:
	kfree(mgmt_dev);
	efx->mgmt_dev = NULL;
	return rc;
}

void ef100_vdpa_unregister_mgmtdev(struct efx_nic *efx)
{
#ifdef EFX_NOT_UPSTREAM
	pci_dbg(efx->pci_dev, "Unregister vdpa_management_device\n");
#endif
	if (efx->mgmt_dev) {
		vdpa_mgmtdev_unregister(efx->mgmt_dev);
		kfree(efx->mgmt_dev);
		efx->mgmt_dev = NULL;
	}
}
#endif

static void
ef100_vdpa_get_addrs(struct efx_nic *efx,
		     bool *uc_promisc,
		     bool *mc_promisc)
{
	struct ef100_vdpa_nic *vdpa_nic = efx->vdpa_nic;
	struct efx_mcdi_dev_addr addr;

	*uc_promisc = false;
	/* As Control Virtqueue is yet to be implemented in vDPA
	 * driver, it is not possible to pass on the MAC address
	 * corresponding to Solicited-Node Multicast Address via
	 * VIRTIO_NET_CTRL_MAC_TABLE_SET to hypervisor. To deal
	 * with this limitation, enable multicast promiscuous to
	 * receive neighbor solicitation messages in order to
	 * allow the IPv6 ping to succeed.
	 */
	*mc_promisc = true;

	if (is_valid_ether_addr(vdpa_nic->mac_address)) {
		dev_dbg(&vdpa_nic->vdpa_dev.dev, "ucast mac: %pM\n",
			vdpa_nic->mac_address);
		ether_addr_copy(addr.addr, vdpa_nic->mac_address);
		efx_mcdi_filter_uc_addr(efx, &addr);
	} else {
		dev_dbg(&vdpa_nic->vdpa_dev.dev, "Invalid MAC address %pM\n",
			 vdpa_nic->mac_address);
	}
}

void ef100_vdpa_insert_filter(struct efx_nic *efx)
{
	mutex_lock(&efx->mac_lock);
	down_read(&efx->filter_sem);
	efx_mcdi_filter_sync_rx_mode(efx);
	up_read(&efx->filter_sem);
	mutex_unlock(&efx->mac_lock);
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

	if (vdpa_nic->vring[0].vring_state & EF100_VRING_CREATED)
		ef100_vdpa_insert_filter(efx);

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

static const struct efx_mcdi_filter_addr_ops vdpa_addr_ops = {
	.get_addrs = ef100_vdpa_get_addrs,
};

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

	/* Add unspecified VID to support VLAN filtering being disabled */
	rc = efx_mcdi_filter_add_vlan(efx, EFX_FILTER_VID_UNSPEC);
	if (rc)
		goto err_remove_filter_table;

	efx_mcdi_filter_set_addr_ops(efx, &vdpa_addr_ops);

	if (!efx->type->filter_table_probe)
		goto err_remove_filter_table;

	rc = efx->type->filter_table_probe(efx);
	if (!rc)
		return 0;

	pci_err(efx->pci_dev, "filter_table_probe failed, err: %d\n", rc);

err_remove_filter_table:
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
		pci_err(efx->pci_dev, "%s: Invalid efx state %u",
			__func__, efx->state);
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

	rc = efx_vdpa_get_mac_address(efx,
				      vdpa_nic->net_config.mac);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Get MAC address for vf:%u failed, rc:%d\n",
			 __func__, vdpa_nic->vf_index, rc);
		return rc;
	}

	vdpa_nic->net_config.max_virtqueue_pairs =
		cpu_to_efx_vdpa16(vdpa_nic, vdpa_nic->max_queue_pairs);

	rc = efx_vdpa_get_mtu(efx, &mtu);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Get MTU for vf:%u failed:%d\n", __func__,
			vdpa_nic->vf_index, rc);
		return rc;
	}
	vdpa_nic->net_config.mtu = cpu_to_efx_vdpa16(vdpa_nic, mtu);

	rc = efx_vdpa_get_link_details(efx, &link_up, &speed, &duplex);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Get Link details for vf:%u failed:%d\n", __func__,
			vdpa_nic->vf_index, rc);
		return rc;
	}
	vdpa_nic->net_config.status = cpu_to_efx_vdpa16(vdpa_nic, link_up);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VIRTIO_NET_SPEED_LE32)
	vdpa_nic->net_config.speed = cpu_to_le32(speed);
#else
	vdpa_nic->net_config.speed = cpu_to_efx_vdpa32(speed);
#endif
	vdpa_nic->net_config.duplex = duplex;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdpa_nic->vdpa_dev.dev, "%s: mac address: %pM\n", __func__,
		 vdpa_nic->net_config.mac);
	dev_info(&vdpa_nic->vdpa_dev.dev, "%s: MTU:%u\n", __func__,
		 vdpa_nic->net_config.mtu);
	dev_info(&vdpa_nic->vdpa_dev.dev,
		 "%s: Status:%u Link Speed:%u Duplex:%u\n", __func__,
		 vdpa_nic->net_config.status,
		 vdpa_nic->net_config.speed,
		 vdpa_nic->net_config.duplex);
#endif
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

static void unmap_mcdi_buffer(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct efx_mcdi_iface *mcdi;

	mcdi = efx_mcdi(efx);
	spin_lock_bh(&mcdi->iface_lock);
	/* Save current MCDI mode to be restored later */
	efx->vdpa_nic->mcdi_mode = mcdi->mode;
	efx->mcdi_buf_mode = EFX_BUF_MODE_VDPA;
	mcdi->mode = MCDI_MODE_FAIL;
	spin_unlock_bh(&mcdi->iface_lock);
	efx_mcdi_wait_for_cleanup(efx);
	efx_nic_free_buffer(efx, &nic_data->mcdi_buf);
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
	u16 i;

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
	vdpa_nic->vdpa_dev.dma_dev = &efx->pci_dev->dev;
	efx->vdpa_nic = vdpa_nic;
	vdpa_nic->efx = efx;
	vdpa_nic->max_queue_pairs = allocated_vis - 1;
	vdpa_nic->pf_index = nic_data->pf_index;
	vdpa_nic->vf_index = nic_data->vf_index;
	vdpa_nic->vdpa_state = EF100_VDPA_STATE_INITIALIZED;
	vdpa_nic->mac_address = (u8 *)&vdpa_nic->net_config.mac;

	dev = &vdpa_nic->vdpa_dev.dev;
#ifdef EFX_NOT_UPSTREAM
	dev_info(dev, "%s: vDPA dev pf_index:%u vf_index:%u max_queues:%u\n",
		 __func__, vdpa_nic->pf_index, vdpa_nic->vf_index,
		 vdpa_nic->max_queue_pairs);
#endif

	for (i = 0; i < (2 * vdpa_nic->max_queue_pairs); i++) {
		rc = ef100_vdpa_init_vring(vdpa_nic, i);
		if (rc) {
			pci_err(efx->pci_dev,
				"vring init idx: %u failed, rc: %d\n", i, rc);
			goto err_put_device;
		}
	}

	rc = devm_add_action_or_reset(&efx->pci_dev->dev,
				      ef100_vdpa_irq_vectors_free,
				      efx->pci_dev);
	if (rc) {
		pci_err(efx->pci_dev,
			"Failed adding devres for freeing irq vectors\n");
		goto err_put_device;
	}

	unmap_mcdi_buffer(efx);

	rc = efx_init_debugfs_vdpa(vdpa_nic);
	if (rc)
		goto err_put_device;

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
	int rc;

	if (efx->vdpa_nic) {
		mutex_lock(&efx->vdpa_nic->lock);
		if (efx->mcdi_buf_mode == EFX_BUF_MODE_VDPA) {
			rc = ef100_vdpa_map_mcdi_buffer(efx);
			if (rc) {
				pci_err(efx->pci_dev,
					"map_mcdi_buffer failed, err: %d\n",
					rc);
			}
		}
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

