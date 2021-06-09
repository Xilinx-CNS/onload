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
#include "mcdi_vdpa.h"
#include "filter.h"
#include "mcdi_functions.h"
#include "mcdi_filters.h"
#ifdef CONFIG_SFC_DEBUGFS
#include "debugfs.h"
#endif
#include "ef100_iova.h"

#if defined(CONFIG_SFC_VDPA)
extern struct vdpa_config_ops ef100_vdpa_config_ops;

static int
ef100_vdpa_set_mac_filter(struct efx_nic *efx,
			  struct efx_filter_spec *spec,
			  u32 qid,
			  u8 *mac_addr)
{
	int rc = 0;

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

int ef100_vdpa_filter_remove(struct ef100_vdpa_nic *vdpa_nic)
{
	struct vdpa_device *vdev = &vdpa_nic->vdpa_dev;
	u8 fail_cnt = 0;
	int err = 0;
	int rc = 0;
	int i;

	for (i = 0; i < vdpa_nic->filter_cnt; i++) {
		if (vdpa_nic->filters[i].filter_id == -1)
			continue;

		rc = efx_filter_remove_id_safe(vdpa_nic->efx,
					       EFX_FILTER_PRI_MANUAL,
					       vdpa_nic->filters[i].filter_id);
		if (rc != 0) {
			dev_err(&vdev->dev,
				"filter %d id: %d remove failed, err: %d\n",
				i, vdpa_nic->filters[i].filter_id, rc);
			fail_cnt++;
			err = rc;
		} else {
			dev_info(&vdev->dev,
				 "filter %d id %d removed\n",
				 i, vdpa_nic->filters[i].filter_id);
		}

		vdpa_nic->filters[i].filter_id = -1;
	}

	if (fail_cnt) {
		dev_err(&vdev->dev,
			"%d filters couldn't be removed\n", fail_cnt);
		rc = err;
	}

	vdpa_nic->filter_cnt = 0;
	return rc;
}

int ef100_vdpa_filter_configure(struct ef100_vdpa_nic *vdpa_nic)
{
	struct vdpa_device *vdev = &vdpa_nic->vdpa_dev;
	struct efx_nic *efx = vdpa_nic->efx;
	struct efx_filter_spec *spec;
	u8 baddr[ETH_ALEN];
	/* Configure filter on base Rx queue only */
	u32 qid = EF100_VDPA_BASE_RX_QID;
	int rc = 0;

	/* remove existing filters, if any */
	rc = ef100_vdpa_filter_remove(vdpa_nic);
	if (rc < 0) {
		dev_err(&vdev->dev,
			"MAC filter deletion failed, err: %d", rc);
		goto fail2;
	}

	/* Configure broadcast MAC Filter */
	eth_broadcast_addr(baddr);
	spec = &vdpa_nic->filters[EF100_VDPA_BCAST_MAC_FILTER].spec;
	rc = ef100_vdpa_set_mac_filter(efx, spec, qid, baddr);
	if (rc < 0) {
		dev_err(&vdev->dev,
			"bcast MAC filter insert failed, err: %d", rc);
		goto fail2;
	}
	vdpa_nic->filters[EF100_VDPA_BCAST_MAC_FILTER].filter_id = rc;
	vdpa_nic->filter_cnt++;
	dev_info(&vdev->dev,
		 "vDPA bcast filter created, filter_id: %d\n", rc);

	/* Configure unicast MAC Filter */
	spec = &vdpa_nic->filters[EF100_VDPA_UCAST_MAC_FILTER].spec;
	rc = ef100_vdpa_set_mac_filter(efx, spec, qid, vdpa_nic->mac_address);
	if (rc < 0) {
		dev_err(&vdev->dev,
			"ucast MAC filter insert failed, err: %d", rc);
		goto fail;
	}
	vdpa_nic->filters[EF100_VDPA_UCAST_MAC_FILTER].filter_id = rc;
	vdpa_nic->filter_cnt++;
	dev_info(&vdev->dev,
		 "vDPA ucast filter created, filter_id: %d\n", rc);

	/* Configure unknown multicast filter */
	spec = &vdpa_nic->filters[EF100_VDPA_UNKNOWN_MCAST_MAC_FILTER].spec;
	rc = ef100_vdpa_set_mac_filter(efx, spec, qid, NULL);
	if (rc < 0) {
		dev_err(&vdev->dev,
			"vDPA mcast MAC filter insert failed, err: %d", rc);
		goto fail;
	}
	vdpa_nic->filters[EF100_VDPA_UNKNOWN_MCAST_MAC_FILTER].filter_id = rc;
	vdpa_nic->filter_cnt++;
	dev_info(&vdev->dev,
		 "vDPA UNKNOWN_MCAST filter created, filter_id: %d\n", rc);

	return 0;

fail:
	ef100_vdpa_filter_remove(vdpa_nic);

fail2:
	return rc;
}

#ifdef EFX_NOT_UPSTREAM
static ssize_t vdpa_mac_show(struct device *dev,
				struct device_attribute *attr,
				char *buf_out)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct ef100_vdpa_nic *vdpa_nic = efx->vdpa_nic;
	int len;

	/* print MAC in big-endian format */
	len = scnprintf(buf_out, PAGE_SIZE, "%pMR\n", vdpa_nic->mac_address);

	return len;
}

static ssize_t vdpa_mac_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct ef100_nic_data *nic_data = efx->nic_data;
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
	if (nic_data->vdpa_class != EF100_VDPA_CLASS_NET) {
		dev_err(&vdev->dev,
			"Invalid vDPA device class: %u\n", nic_data->vdpa_class);
		rc = -EINVAL;
		goto err;
	}

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
		ef100_vdpa_filter_configure(vdpa_nic);

err:
	mutex_unlock(&vdpa_nic->lock);
	if (rc < 0)
		return rc;
	return count;
}

static DEVICE_ATTR_RW(vdpa_mac);
#endif

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
	int rc = 0;

	mutex_lock(&nic_data->bar_config_lock);
	if (sysfs_streq(buf, "net")) {
		vdpa_class = EF100_VDPA_CLASS_NET;
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
			vdpa_nic = ef100_vdpa_create(efx);
			if (IS_ERR(vdpa_nic)) {
				pci_err(efx->pci_dev,
					"vDPA device creation failed, err: %ld",
					PTR_ERR(vdpa_nic));
				rc = PTR_ERR(vdpa_nic);
				goto fail;
			}

			nic_data->vdpa_class = EF100_VDPA_CLASS_NET;
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

static int vdpa_create_files(struct efx_nic *efx)
{
	int rc;

	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_vdpa_class);
	if (rc) {
		pci_err(efx->pci_dev, "vdpa_class file creation failed\n");
		goto fail;
	}

#ifdef EFX_NOT_UPSTREAM
	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_vdpa_mac);
	if (rc) {
		pci_err(efx->pci_dev, "vdpa_mac file creation failed\n");
		goto fail;
	}
#endif

	return 0;
fail:
	return rc;
}

static void vdpa_remove_files(struct efx_nic *efx)
{
#ifdef EFX_NOT_UPSTREAM
	device_remove_file(&efx->pci_dev->dev, &dev_attr_vdpa_mac);
#endif
	device_remove_file(&efx->pci_dev->dev, &dev_attr_vdpa_class);
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
	int rc;

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
		return rc;
	}

	if (efx->type->filter_table_probe)
		rc = efx->type->filter_table_probe(efx);

	return 0;
}

void ef100_vdpa_fini(struct efx_probe_data *probe_data)
{
	struct efx_nic *efx = &probe_data->efx;
	struct ef100_nic_data *nic_data = efx->nic_data;

	if (efx->state != STATE_VDPA) {
		pci_err(efx->pci_dev, "Invalid efx state %u", efx->state);
		return;
	}

	/* Handle vdpa device deletion, if not done explicitly */
	ef100_vdpa_delete(efx);
	nic_data->vdpa_class = EF100_VDPA_CLASS_NONE;

	vdpa_remove_files(efx);

	efx->state = STATE_PROBED;

	if (efx->type->filter_table_remove)
		efx->type->filter_table_remove(efx);
	efx_mcdi_filter_table_remove(efx);
}

static int get_net_config(struct ef100_vdpa_nic *vdpa_nic)
{
	struct efx_nic *efx = vdpa_nic->efx;
	int rc = 0;

	rc = efx_vdpa_get_mac_address(efx,
				      vdpa_nic->net_config.mac);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Get MAC address for vf:%u failed:%d\n", __func__,
			vdpa_nic->vf_index, rc);
		return rc;
	}

	vdpa_nic->net_config.max_virtqueue_pairs = vdpa_nic->max_queue_pairs;

	rc = efx_vdpa_get_mtu(efx, &vdpa_nic->net_config.mtu);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Get MTU for vf:%u failed:%d\n", __func__,
			vdpa_nic->vf_index, rc);
		return rc;
	}

	rc = efx_vdpa_get_link_details(efx, &vdpa_nic->net_config.status,
				       &vdpa_nic->net_config.speed,
				       &vdpa_nic->net_config.duplex);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Get Link details for vf:%u failed:%d\n", __func__,
			vdpa_nic->vf_index, rc);
		return rc;
	}

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
       struct device *dev;
       int rc;

       mcdi = efx_mcdi(efx);
       dev = &vdpa_nic->vdpa_dev.dev;
       spin_lock_bh(&mcdi->iface_lock);

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
       spin_unlock_bh(&mcdi->iface_lock);

       return 0;

fail_alloc:
       spin_unlock_bh(&mcdi->iface_lock);
       return rc;
}

int setup_vdpa_mcdi_buffer(struct efx_nic *efx, u64 mcdi_iova)
{
       struct ef100_nic_data *nic_data = efx->nic_data;
       struct efx_mcdi_iface *mcdi;
       struct efx_buffer mcdi_buf;
       int rc;

       mcdi = efx_mcdi(efx);
       spin_lock_bh(&mcdi->iface_lock);

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
       spin_unlock_bh(&mcdi->iface_lock);

       return 0;

fail:
       spin_unlock_bh(&mcdi->iface_lock);
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

struct ef100_vdpa_nic *ef100_vdpa_create(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct ef100_vdpa_nic *vdpa_nic;
	unsigned int allocated_vis;
	struct device *dev;
	int rc;
	u8 i;

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
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_ALLOC_NVQS_PARAM)
				     , (allocated_vis - 1) * 2
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
	INIT_LIST_HEAD(&vdpa_nic->free_list);

	dev = &vdpa_nic->vdpa_dev.dev;
	dev_info(dev, "%s: vDPA dev pf_index:%u vf_index:%u max_queues:%u\n",
		 __func__, vdpa_nic->pf_index, vdpa_nic->vf_index,
		 vdpa_nic->max_queue_pairs);

	for (i = 0; i < EF100_VDPA_MAC_FILTER_NTYPES; i++)
		vdpa_nic->filters[i].filter_id = -1;

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

	rc = vdpa_update_domain(vdpa_nic);
	if (rc) {
		pci_err(efx->pci_dev, "update_domain failed, err: %d\n", rc);
		goto err_irq_vectors_free;
	}

	rc = setup_vdpa_mcdi_buffer(efx, EF100_VDPA_IOVA_BASE_ADDR);
	if (rc) {
		pci_err(efx->pci_dev, "realloc mcdi failed, err: %d\n", rc);
		goto err_irq_vectors_free;
	}

#ifdef CONFIG_SFC_DEBUGFS
	rc = efx_init_debugfs_vdpa(vdpa_nic);
	if (rc)
		goto err_irq_vectors_free;
#endif

	rc = vdpa_register_device(&vdpa_nic->vdpa_dev);
	if (rc) {
		pci_err(efx->pci_dev,
			"vDPA device registration failed for vf: %u\n",
			nic_data->vf_index);
		goto err_fini_debugfs;
	}

	rc = devm_add_action_or_reset(dev, ef100_vdpa_irq_vectors_free, efx->pci_dev);
	if (rc) {
		pci_err(efx->pci_dev,
			"Failed adding devres for freeing irq vectors\n");
		goto err_fini_debugfs;
	}

	rc = get_net_config(vdpa_nic);
	if (rc)
		goto err_fini_debugfs;

	return vdpa_nic;

err_fini_debugfs:
	efx_fini_debugfs_vdpa(vdpa_nic);

err_irq_vectors_free:
	ef100_vdpa_irq_vectors_free(efx->pci_dev);

err_put_device:
	mutex_destroy(&vdpa_nic->lock);
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
		vdpa_unregister_device(&efx->vdpa_nic->vdpa_dev);
#ifdef EFX_NOT_UPSTREAM
		pci_info(efx->pci_dev,
			 "%s: vdpa unregister device completed\n", __func__);
#endif
		efx->vdpa_nic = NULL;
		ef100_vdpa_irq_vectors_free(efx->pci_dev);
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
		if (vdpa_nic->status > 0)
			return true;

	return false;
}

#endif

