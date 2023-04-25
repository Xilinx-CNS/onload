// SPDX-License-Identifier: GPL-2.0
/* Driver for Xilinx network controllers and boards
 * Copyright 2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/vdpa.h>
#include <linux/virtio_ids.h>
#include <linux/pci_ids.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <uapi/linux/virtio_config.h>
#include <uapi/linux/virtio_net.h>
#include "ef100_nic.h"
#include "io.h"
#include "ef100_vdpa.h"
#include "mcdi_vdpa.h"
#include "mcdi_filters.h"
#include "debugfs.h"

#if defined(CONFIG_SFC_VDPA)

/* Get the queue's function-local index of the associated VI
 * virtqueue number queue 0 is reserved for MCDI
 */
#define EFX_GET_VI_INDEX(vq_num) (((vq_num) / 2) + 1)

#if defined(EFX_USE_KCOMPAT) && !defined(VIRTIO_F_IN_ORDER)
/* Virtio feature bit number 35 is not defined in
 * include/uapi/linux/virtio_config.h, make it available for the
 * out-of-tree builds. VIRTIO_F_IN_ORDER is defined in section 6
 * (Reserved Feature Bits) of the VirtIO v1.1 spec
 */
#define VIRTIO_F_IN_ORDER 35
#endif


struct feature_bit {
	u8 bit;
	char *str;
};

static const struct feature_bit feature_table[] = {
	{VIRTIO_F_NOTIFY_ON_EMPTY, "VIRTIO_F_NOTIFY_ON_EMPTY"},
	{VIRTIO_F_ANY_LAYOUT, "VIRTIO_F_ANY_LAYOUT"},
	{VIRTIO_F_VERSION_1, "VIRTIO_F_VERSION_1"},
	{VIRTIO_F_ACCESS_PLATFORM, "VIRTIO_F_ACCESS_PLATFORM"},
	{VIRTIO_F_RING_PACKED, "VIRTIO_F_RING_PACKED"},
	{VIRTIO_F_ORDER_PLATFORM, "VIRTIO_F_ORDER_PLATFORM"},
#if defined(EFX_USE_KCOMPAT)
	{VIRTIO_F_IN_ORDER, "VIRTIO_F_IN_ORDER"},
#endif
	{VIRTIO_F_SR_IOV, "VIRTIO_F_SR_IOV"},
	{VIRTIO_NET_F_CSUM, "VIRTIO_NET_F_CSUM"},
	{VIRTIO_NET_F_GUEST_CSUM, "VIRTIO_NET_F_GUEST_CSUM"},
	{VIRTIO_NET_F_CTRL_GUEST_OFFLOADS, "VIRTIO_NET_F_CTRL_GUEST_OFFLOADS"},
	{VIRTIO_NET_F_MTU, "VIRTIO_NET_F_MTU"},
	{VIRTIO_NET_F_MAC, "VIRTIO_NET_F_MAC"},
	{VIRTIO_NET_F_GUEST_TSO4, "VIRTIO_NET_F_GUEST_TSO4"},
	{VIRTIO_NET_F_GUEST_TSO6, "VIRTIO_NET_F_GUEST_TSO6"},
	{VIRTIO_NET_F_GUEST_ECN, "VIRTIO_NET_F_GUEST_ECN"},
	{VIRTIO_NET_F_GUEST_UFO, "VIRTIO_NET_F_GUEST_UFO"},
	{VIRTIO_NET_F_HOST_TSO4, "VIRTIO_NET_F_HOST_TSO4"},
	{VIRTIO_NET_F_HOST_TSO6, "VIRTIO_NET_F_HOST_TSO6"},
	{VIRTIO_NET_F_HOST_ECN, "VIRTIO_NET_F_HOST_ECN"},
	{VIRTIO_NET_F_HOST_UFO, "VIRTIO_NET_F_HOST_UFO"},
	{VIRTIO_NET_F_MRG_RXBUF, "VIRTIO_NET_F_MRG_RXBUF"},
	{VIRTIO_NET_F_STATUS, "VIRTIO_NET_F_STATUS"},
	{VIRTIO_NET_F_CTRL_VQ, "VIRTIO_NET_F_CTRL_VQ"},
	{VIRTIO_NET_F_CTRL_RX, "VIRTIO_NET_F_CTRL_RX"},
	{VIRTIO_NET_F_CTRL_VLAN, "VIRTIO_NET_F_CTRL_VLAN"},
	{VIRTIO_NET_F_CTRL_RX_EXTRA, "VIRTIO_NET_F_CTRL_RX_EXTRA"},
	{VIRTIO_NET_F_GUEST_ANNOUNCE, "VIRTIO_NET_F_GUEST_ANNOUNCE"},
	{VIRTIO_NET_F_MQ, "VIRTIO_NET_F_MQ"},
	{VIRTIO_NET_F_CTRL_MAC_ADDR, "VIRTIO_NET_F_CTRL_MAC_ADDR"},
	{VIRTIO_NET_F_HASH_REPORT, "VIRTIO_NET_F_HASH_REPORT"},
	{VIRTIO_NET_F_RSS, "VIRTIO_NET_F_RSS"},
	{VIRTIO_NET_F_RSC_EXT, "VIRTIO_NET_F_RSC_EXT"},
	{VIRTIO_NET_F_STANDBY, "VIRTIO_NET_F_STANDBY"},
	{VIRTIO_NET_F_SPEED_DUPLEX, "VIRTIO_NET_F_SPEED_DUPLEX"},
	{VIRTIO_NET_F_GSO, "VIRTIO_NET_F_GSO"},
};

struct status_val {
	u8 bit;
	char *str;
};

static const struct status_val status_val_table[] = {
	{VIRTIO_CONFIG_S_ACKNOWLEDGE, "ACKNOWLEDGE"},
	{VIRTIO_CONFIG_S_DRIVER, "DRIVER"},
	{VIRTIO_CONFIG_S_FEATURES_OK, "FEATURES_OK"},
	{VIRTIO_CONFIG_S_DRIVER_OK, "DRIVER_OK"},
	{VIRTIO_CONFIG_S_FAILED, "FAILED"}
};

static struct ef100_vdpa_nic *get_vdpa_nic(struct vdpa_device *vdev)
{
	return container_of(vdev, struct ef100_vdpa_nic, vdpa_dev);
}

static void print_status_str(u8 status, struct vdpa_device *vdev)
{
	u16 table_len =  sizeof(status_val_table) / sizeof(struct status_val);
	char concat_str[] = ", ";
	char buf[100];
	u16 i = 0;

	buf[0] = '\0';
	if (status == 0) {
		dev_info(&vdev->dev, "RESET\n");
		return;
	}
	for ( ; (i < table_len) && status; i++) {
		if (status & status_val_table[i].bit) {
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
				 "%s", status_val_table[i].str);
			status &= ~status_val_table[i].bit;
			if (status > 0)
				snprintf(buf + strlen(buf),
					 sizeof(buf) - strlen(buf), "%s",
					 concat_str);
		}
	}
	dev_info(&vdev->dev, "%s\n", buf);
	if (status)
		dev_info(&vdev->dev, "Unknown status:0x%x\n", status);
}

#ifdef EFX_NOT_UPSTREAM
static void print_features_str(u64 features, struct vdpa_device *vdev)
{
	int table_len = sizeof(feature_table) / sizeof(struct feature_bit);
	int i = 0;

	for (; (i < table_len) && features; i++) {
		if (features & (1ULL << feature_table[i].bit)) {
			dev_info(&vdev->dev, "%s: %s\n", __func__,
				 feature_table[i].str);
			features &= ~(1ULL << feature_table[i].bit);
		}
	}
	if (features) {
		dev_info(&vdev->dev,
			 "%s: Unknown Features:0x%llx\n",
			 __func__, features);
	}
}
#endif

static char *get_vdpa_state_str(enum ef100_vdpa_nic_state state)
{
	switch (state) {
	case EF100_VDPA_STATE_INITIALIZED:
		return "INITIALIZED";
	case EF100_VDPA_STATE_NEGOTIATED:
		return "NEGOTIATED";
	case EF100_VDPA_STATE_STARTED:
		return "STARTED";
	default:
		return "UNKNOWN";
	}
}

static irqreturn_t vring_intr_handler(int irq, void *arg)
{
	struct ef100_vdpa_vring_info *vring = arg;

	if (vring->cb.callback)
		return vring->cb.callback(vring->cb.private);

	return IRQ_NONE;
}

#ifdef EFX_NOT_UPSTREAM
static void print_vring_state(u16 state, struct vdpa_device *vdev)
{
	dev_info(&vdev->dev, "%s: Vring state:\n", __func__);
	dev_info(&vdev->dev, "%s: Address Configured:%s\n", __func__,
		 (state & EF100_VRING_ADDRESS_CONFIGURED) ? "true" : "false");
	dev_info(&vdev->dev, "%s: Size Configured:%s\n", __func__,
		 (state & EF100_VRING_SIZE_CONFIGURED) ? "true" : "false");
	dev_info(&vdev->dev, "%s: Ready Configured:%s\n", __func__,
		 (state & EF100_VRING_READY_CONFIGURED) ? "true" : "false");
	dev_info(&vdev->dev, "%s: Vring Created:%s\n", __func__,
		 (state & EF100_VRING_CREATED) ? "true" : "false");
}
#endif

static int ef100_vdpa_irq_vectors_alloc(struct pci_dev *pci_dev, u16 nvqs)
{
	int rc;

	rc = pci_alloc_irq_vectors(pci_dev, nvqs, nvqs, PCI_IRQ_MSIX);
	if (rc < 0)
		pci_err(pci_dev,
			"Failed to alloc %d IRQ vectors, err:%d\n", nvqs, rc);
	return rc;
}

void ef100_vdpa_irq_vectors_free(void *data)
{
	pci_free_irq_vectors(data);
}

static bool is_qid_invalid(struct ef100_vdpa_nic *vdpa_nic, u16 idx,
			   const char *caller)
{
	if (unlikely(idx >= (vdpa_nic->max_queue_pairs * 2))) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Invalid qid %u\n", caller, idx);
		return true;
	}
	return false;
}

int ef100_vdpa_map_mcdi_buffer(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct efx_mcdi_iface *mcdi;
	int rc;

	/* Update VF's MCDI buffer when switching out of vdpa mode */
	rc = efx_nic_alloc_buffer(efx, &nic_data->mcdi_buf,
				  MCDI_BUF_LEN, GFP_KERNEL);
	if (rc)
		return rc;

	mcdi = efx_mcdi(efx);
	spin_lock_bh(&mcdi->iface_lock);
	mcdi->mode = efx->vdpa_nic->mcdi_mode;
	efx->mcdi_buf_mode = EFX_BUF_MODE_EF100;
	spin_unlock_bh(&mcdi->iface_lock);

	return 0;
}

static int irq_vring_init(struct ef100_vdpa_nic *vdpa_nic, u16 idx)
{
	struct ef100_vdpa_vring_info *vring = &vdpa_nic->vring[idx];
	struct pci_dev *pci_dev = vdpa_nic->efx->pci_dev;
	int irq;
	int rc;

	snprintf(vring->msix_name, 256, "x_vdpa[%s]-%d\n",
		 pci_name(pci_dev), idx);
	irq = pci_irq_vector(pci_dev, idx);
	rc = devm_request_irq(&pci_dev->dev, irq, vring_intr_handler, 0,
			      vring->msix_name, vring);
	if (rc)
		pci_err(pci_dev,
			"Failed to request irq for vring %d, rc %u\n", idx, rc);
	else
		vring->irq = irq;

	return rc;
}

static void irq_vring_fini(struct ef100_vdpa_nic *vdpa_nic, u16 idx)
{
	struct ef100_vdpa_vring_info *vring = &vdpa_nic->vring[idx];
	struct pci_dev *pci_dev = vdpa_nic->efx->pci_dev;

	devm_free_irq(&pci_dev->dev, vring->irq, vring);
	vring->irq = -EINVAL;
}

static int ef100_vdpa_filter_configure(struct ef100_vdpa_nic *vdpa_nic)
{
	struct efx_nic *efx = vdpa_nic->efx;
	struct ef100_nic_data *nic_data;
	int rc;

	nic_data = efx->nic_data;
	if (efx->type->filter_table_up) {
		rc = efx->type->filter_table_up(efx);
		if (rc)
			return rc;
	}
	efx_mcdi_push_default_indir_table(efx,
					  vdpa_nic->max_queue_pairs);
	ef100_vdpa_insert_filter(vdpa_nic->efx);

	return 0;
}

static bool can_create_vring(struct ef100_vdpa_nic *vdpa_nic, u16 idx)
{
	if (vdpa_nic->vring[idx].vring_state == EF100_VRING_CONFIGURED &&
	    vdpa_nic->status & VIRTIO_CONFIG_S_DRIVER_OK &&
	    !(vdpa_nic->vring[idx].vring_state & EF100_VRING_CREATED)) {
#ifdef EFX_NOT_UPSTREAM
		dev_info(&vdpa_nic->vdpa_dev.dev,
			 "%s: vring to be created for Index:%u\n", __func__,
			 idx);
#endif
		return true;
	}
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdpa_nic->vdpa_dev.dev,
		 "%s: vring cannot be created for Index:%u\n", __func__,
		 idx);
	print_vring_state(vdpa_nic->vring[idx].vring_state,
			  &vdpa_nic->vdpa_dev);
	dev_info(&vdpa_nic->vdpa_dev.dev, "%s: Vring  status:\n",
		 __func__);
	print_status_str(vdpa_nic->status, &vdpa_nic->vdpa_dev);
	dev_info(&vdpa_nic->vdpa_dev.dev,
		 "%s: Vring %u created\n", __func__, idx);
#endif
	return false;
}

static int create_vring_ctx(struct ef100_vdpa_nic *vdpa_nic, u16 idx)
{
	struct efx_vring_ctx *vring_ctx;
	u32 vi_index;
	int rc = 0;

	if (!vdpa_nic->efx) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Invalid efx for idx:%u\n", __func__, idx);
		return -EINVAL;
	}
	if (idx % 2) /* Even VQ for RX and odd for TX */
		vdpa_nic->vring[idx].vring_type = EF100_VDPA_VQ_TYPE_NET_TXQ;
	else
		vdpa_nic->vring[idx].vring_type = EF100_VDPA_VQ_TYPE_NET_RXQ;
	vi_index = EFX_GET_VI_INDEX(idx);
	vring_ctx = efx_vdpa_vring_init(vdpa_nic->efx, vi_index,
					vdpa_nic->vring[idx].vring_type);
	if (IS_ERR(vring_ctx)) {
		rc = PTR_ERR(vring_ctx);
		return rc;
	}
	vdpa_nic->vring[idx].vring_ctx = vring_ctx;
	return 0;
}

static void delete_vring_ctx(struct ef100_vdpa_nic *vdpa_nic, u16 idx)
{
	efx_vdpa_vring_fini(vdpa_nic->vring[idx].vring_ctx);
	vdpa_nic->vring[idx].vring_ctx = NULL;
}

static int delete_vring(struct ef100_vdpa_nic *vdpa_nic, u16 idx)
{
	struct efx_vring_dyn_cfg vring_dyn_cfg;
	int rc = 0;

	if (!(vdpa_nic->vring[idx].vring_state & EF100_VRING_CREATED))
		return 0;

	/* delete vring debugfs directory */
	efx_fini_debugfs_vdpa_vring(&vdpa_nic->vring[idx]);
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdpa_nic->vdpa_dev.dev,
		 "%s: Called for %u\n", __func__, idx);
#endif
	rc = efx_vdpa_vring_destroy(vdpa_nic->vring[idx].vring_ctx,
				    &vring_dyn_cfg);
	if (rc)
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Queue delete failed index:%u Err:%d\n",
			__func__, idx, rc);
	vdpa_nic->vring[idx].last_avail_idx = vring_dyn_cfg.avail_idx;
	vdpa_nic->vring[idx].last_used_idx = vring_dyn_cfg.used_idx;
	vdpa_nic->vring[idx].vring_state &= ~EF100_VRING_CREATED;

	irq_vring_fini(vdpa_nic, idx);

	return rc;
}

int ef100_vdpa_init_vring(struct ef100_vdpa_nic *vdpa_nic, u16 idx)
{
	u32 offset;
	int rc;

	vdpa_nic->vring[idx].irq = -EINVAL;
	rc = create_vring_ctx(vdpa_nic, idx);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: create_vring_ctx failed, idx:%u, err:%d\n",
			__func__, idx, rc);
		return rc;
	}

	rc = efx_vdpa_get_doorbell_offset(vdpa_nic->vring[idx].vring_ctx,
					  &offset);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: get_doorbell failed idx:%u, err:%d\n",
			__func__, idx, rc);
		goto err_get_doorbell_offset;
	}
	vdpa_nic->vring[idx].doorbell_offset = offset;
	vdpa_nic->vring[idx].doorbell_offset_valid = true;

	return 0;

err_get_doorbell_offset:
	delete_vring_ctx(vdpa_nic, idx);
	return rc;
}

static void ef100_vdpa_kick_vq(struct vdpa_device *vdev, u16 idx)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);
	u32 idx_val;

	if (is_qid_invalid(vdpa_nic, idx, __func__))
		return;

	if (!(vdpa_nic->vring[idx].vring_state & EF100_VRING_CREATED)) {
		dev_err(&vdev->dev, "%s: Invalid vring%u\n", __func__, idx);
		return;
	}
	idx_val = idx;
	dev_vdbg(&vdev->dev, "%s: Writing value:%u in offset register:%u\n",
		 __func__, idx_val, vdpa_nic->vring[idx].doorbell_offset);
	_efx_writed(vdpa_nic->efx, cpu_to_le32(idx_val),
		    vdpa_nic->vring[idx].doorbell_offset);
}

static int create_vring(struct ef100_vdpa_nic *vdpa_nic, u16 idx)
{
	struct efx_vring_dyn_cfg vring_dyn_cfg;
	struct efx_vring_cfg vring_cfg;
	int rc;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdpa_nic->vdpa_dev.dev,
		 "%s: Called for %u\n", __func__, idx);
#endif

	rc = irq_vring_init(vdpa_nic, idx);
	if (rc) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: irq_vring_init failed. index:%u Err:%d\n",
			__func__, idx, rc);
		return rc;
	}
	vring_cfg.desc = vdpa_nic->vring[idx].desc;
	vring_cfg.avail = vdpa_nic->vring[idx].avail;
	vring_cfg.used = vdpa_nic->vring[idx].used;
	vring_cfg.size = vdpa_nic->vring[idx].size;
	vring_cfg.features = vdpa_nic->features;
	vring_cfg.use_pasid = false;
	vring_cfg.pasid = 0;
	vring_cfg.msix_vector = idx;
	vring_dyn_cfg.avail_idx = vdpa_nic->vring[idx].last_avail_idx;
	vring_dyn_cfg.used_idx = vdpa_nic->vring[idx].last_used_idx;

	rc = efx_vdpa_vring_create(vdpa_nic->vring[idx].vring_ctx, &vring_cfg,
				   &vring_dyn_cfg);
	if (rc != 0) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: Queue create failed index:%u Err:%d\n",
			__func__, idx, rc);
		goto err_vring_create;
	}
	vdpa_nic->vring[idx].vring_state |= EF100_VRING_CREATED;


	rc = efx_init_debugfs_vdpa_vring(vdpa_nic, &vdpa_nic->vring[idx], idx);
	if (rc)
		goto err_debugfs_vdpa_init;

	/* A VQ kick allows the device to read the avail_idx, which will be
	 * required at the destination after live migration.
	 */
	ef100_vdpa_kick_vq(&vdpa_nic->vdpa_dev, idx);

	return 0;

err_debugfs_vdpa_init:
	efx_vdpa_vring_destroy(vdpa_nic->vring[idx].vring_ctx,
			       &vring_dyn_cfg);
	vdpa_nic->vring[idx].vring_state &= ~EF100_VRING_CREATED;
err_vring_create:
	irq_vring_fini(vdpa_nic, idx);

	return rc;
}

static void reset_vring(struct ef100_vdpa_nic *vdpa_nic, u16 idx)
{
	delete_vring(vdpa_nic, idx);
	vdpa_nic->vring[idx].vring_type = EF100_VDPA_VQ_NTYPES;
	vdpa_nic->vring[idx].vring_state = 0;
	vdpa_nic->vring[idx].last_avail_idx = 0;
	vdpa_nic->vring[idx].last_used_idx = 0;
}

void reset_vdpa_device(struct ef100_vdpa_nic *vdpa_nic)
{
	struct efx_nic *efx = vdpa_nic->efx;
	int i, rc;

	WARN_ON(!mutex_is_locked(&vdpa_nic->lock));

	if (!vdpa_nic->status)
		return;

	rc = efx_mcdi_filter_remove_all(vdpa_nic->efx,
					EFX_FILTER_PRI_AUTO);
	if (rc < 0) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"%s: vdpa remove filter failed, err:%d\n",
			__func__, rc);
	}
	efx->type->filter_table_down(efx);
	vdpa_nic->vdpa_state = EF100_VDPA_STATE_INITIALIZED;
	vdpa_nic->status = 0;
	vdpa_nic->features = 0;
	for (i = 0; i < (vdpa_nic->max_queue_pairs * 2); i++)
		reset_vring(vdpa_nic, i);
	ef100_vdpa_irq_vectors_free(vdpa_nic->efx->pci_dev);
}

/* May be called under the rtnl lock */
int ef100_vdpa_reset(struct vdpa_device *vdev)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);

	/* vdpa device can be deleted anytime but the bar_config
	 * could still be vdpa and hence efx->state would be STATE_VDPA.
	 * Accordingly, ensure vdpa device exists before reset handling
	 */
	if (!vdpa_nic)
		return -ENODEV;

	mutex_lock(&vdpa_nic->lock);
	reset_vdpa_device(vdpa_nic);
	mutex_unlock(&vdpa_nic->lock);
	return 0;
}

static int start_vdpa_device(struct ef100_vdpa_nic *vdpa_nic)
{
	struct efx_nic *efx = vdpa_nic->efx;
	struct ef100_nic_data *nic_data;
	int rc, i, j;

	nic_data = efx->nic_data;
	rc = ef100_vdpa_irq_vectors_alloc(efx->pci_dev,
					  vdpa_nic->max_queue_pairs * 2);
	if (rc < 0) {
		dev_err(&vdpa_nic->vdpa_dev.dev,
			"vDPA IRQ alloc failed for vf: %u err:%d\n",
			nic_data->vf_index, rc);
		return rc;
	}

	for (i = 0; i < (vdpa_nic->max_queue_pairs * 2); i++) {
		if (can_create_vring(vdpa_nic, i)) {
			rc = create_vring(vdpa_nic, i);
			if (rc)
				goto clear_vring;
		}
	}

	rc = ef100_vdpa_filter_configure(vdpa_nic);
	if (rc)
		goto clear_vring;

	vdpa_nic->vdpa_state = EF100_VDPA_STATE_STARTED;
	return 0;

clear_vring:
	for (j = 0; j < i; j++)
		delete_vring(vdpa_nic, j);

	ef100_vdpa_irq_vectors_free(efx->pci_dev);
	return rc;
}

static int ef100_vdpa_set_vq_address(struct vdpa_device *vdev,
				     u16 idx, u64 desc_area, u64 driver_area,
				     u64 device_area)
{
	struct ef100_vdpa_nic *vdpa_nic = NULL;
	int rc = 0;

	vdpa_nic = get_vdpa_nic(vdev);
	if (is_qid_invalid(vdpa_nic, idx, __func__))
		return -EINVAL;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Invoked for index %u\n", __func__, idx);
#endif
	mutex_lock(&vdpa_nic->lock);
	vdpa_nic->vring[idx].desc = desc_area;
	vdpa_nic->vring[idx].avail = driver_area;
	vdpa_nic->vring[idx].used = device_area;
	vdpa_nic->vring[idx].vring_state |= EF100_VRING_ADDRESS_CONFIGURED;
	mutex_unlock(&vdpa_nic->lock);
	return rc;
}

static void ef100_vdpa_set_vq_num(struct vdpa_device *vdev, u16 idx, u32 num)
{
	struct ef100_vdpa_nic *vdpa_nic;

	vdpa_nic = get_vdpa_nic(vdev);
	if (is_qid_invalid(vdpa_nic, idx, __func__))
		return;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Invoked for index:%u size:%u\n", __func__,
		 idx, num);
#endif
	if (!is_power_of_2(num)) {
		dev_err(&vdev->dev, "%s: Index:%u size:%u not power of 2\n",
			__func__, idx, num);
		return;
	}
	if (num > EF100_VDPA_VQ_NUM_MAX_SIZE) {
		dev_err(&vdev->dev, "%s: Index:%u size:%u more than max:%u\n",
			__func__, idx, num, EF100_VDPA_VQ_NUM_MAX_SIZE);
		return;
	}
	mutex_lock(&vdpa_nic->lock);
	vdpa_nic->vring[idx].size  = num;
	vdpa_nic->vring[idx].vring_state |= EF100_VRING_SIZE_CONFIGURED;
	mutex_unlock(&vdpa_nic->lock);
}

static void ef100_vdpa_set_vq_cb(struct vdpa_device *vdev, u16 idx,
				 struct vdpa_callback *cb)
{
	struct ef100_vdpa_nic *vdpa_nic;

	vdpa_nic = get_vdpa_nic(vdev);
	if (is_qid_invalid(vdpa_nic, idx, __func__))
		return;

	if (cb)
		vdpa_nic->vring[idx].cb = *cb;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Setting vq callback for vring %u\n",
		 __func__, idx);
#endif
}

static void ef100_vdpa_set_vq_ready(struct vdpa_device *vdev, u16 idx,
				    bool ready)
{
	struct ef100_vdpa_nic *vdpa_nic;
	int rc;

	vdpa_nic = get_vdpa_nic(vdev);
	if (is_qid_invalid(vdpa_nic, idx, __func__))
		return;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Queue Id: %u Ready :%u\n", __func__,
		 idx, ready);
#endif
	mutex_lock(&vdpa_nic->lock);
	if (ready) {
		vdpa_nic->vring[idx].vring_state |=
					EF100_VRING_READY_CONFIGURED;
		if (vdpa_nic->vdpa_state == EF100_VDPA_STATE_STARTED &&
		    can_create_vring(vdpa_nic, idx)) {
			rc = create_vring(vdpa_nic, idx);
			if (rc)
				/* Rollback ready configuration
				 * So that the above layer driver
				 * can make another attempt to set ready
				 */
				vdpa_nic->vring[idx].vring_state &=
					~EF100_VRING_READY_CONFIGURED;
		}
	} else {
		vdpa_nic->vring[idx].vring_state &=
					~EF100_VRING_READY_CONFIGURED;
		delete_vring(vdpa_nic, idx);
	}
	mutex_unlock(&vdpa_nic->lock);
}

static bool ef100_vdpa_get_vq_ready(struct vdpa_device *vdev, u16 idx)
{
	struct ef100_vdpa_nic *vdpa_nic;
	bool ready;

	vdpa_nic = get_vdpa_nic(vdev);
	if (is_qid_invalid(vdpa_nic, idx, __func__))
		return false;

	mutex_lock(&vdpa_nic->lock);
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Index:%u Value returned: %u\n", __func__,
		 idx, vdpa_nic->vring[idx].vring_state &
		 EF100_VRING_READY_CONFIGURED);
#endif
	ready = vdpa_nic->vring[idx].vring_state & EF100_VRING_READY_CONFIGURED;
	mutex_unlock(&vdpa_nic->lock);
	return ready;
}

static int ef100_vdpa_set_vq_state(struct vdpa_device *vdev, u16 idx,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_VQ_STATE)
				   const struct vdpa_vq_state *state)
#else
				   u64 state)
#endif
{
	struct ef100_vdpa_nic *vdpa_nic;

	vdpa_nic = get_vdpa_nic(vdev);
	if (is_qid_invalid(vdpa_nic, idx, __func__))
		return -EINVAL;

	mutex_lock(&vdpa_nic->lock);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_VQ_STATE)
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Queue:%u State:0x%x", __func__, idx,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_VQ_STATE_SPLIT)
		 state->split.avail_index);
#else
		 state->avail_index);
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_VQ_STATE_SPLIT)
	vdpa_nic->vring[idx].last_avail_idx = state->split.avail_index;
	vdpa_nic->vring[idx].last_used_idx = state->split.avail_index;
#else
	vdpa_nic->vring[idx].last_avail_idx = state->avail_index;
	vdpa_nic->vring[idx].last_used_idx = state->avail_index;
#endif
#else
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Queue:%u State:0x%llx", __func__, idx, state);
#endif
	vdpa_nic->vring[idx].last_avail_idx = state;
	vdpa_nic->vring[idx].last_used_idx = state;
#endif
	mutex_unlock(&vdpa_nic->lock);
	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_VQ_STATE)
static int ef100_vdpa_get_vq_state(struct vdpa_device *vdev,
				   u16 idx, struct vdpa_vq_state *state)
#else
static u64 ef100_vdpa_get_vq_state(struct vdpa_device *vdev, u16 idx)
#endif
{
	struct ef100_vdpa_nic *vdpa_nic;
	u32 last_avail_index = 0;

	vdpa_nic = get_vdpa_nic(vdev);
	if (is_qid_invalid(vdpa_nic, idx, __func__))
		return -EINVAL;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Queue:%u State:0x%x", __func__, idx,
		 vdpa_nic->vring[idx].last_avail_idx);
#endif

	mutex_lock(&vdpa_nic->lock);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_VQ_STATE)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_VQ_STATE_SPLIT)
	/* In get_vq_state, we have to return the indices of the
	 * last processed descriptor buffer by the device.
	 */
	state->split.avail_index = (u16)vdpa_nic->vring[idx].last_used_idx;
#else
	state->avail_index = (u16)vdpa_nic->vring[idx].last_used_idx;
#endif
#else
	last_avail_index = vdpa_nic->vring[idx].last_used_idx;
#endif
	mutex_unlock(&vdpa_nic->lock);

	return last_avail_index;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GET_VQ_NOTIFY)
static struct vdpa_notification_area
		ef100_vdpa_get_vq_notification(struct vdpa_device *vdev, u16 idx)
{
	struct vdpa_notification_area notify_area = {0, 0};
	struct ef100_vdpa_nic *vdpa_nic;
	struct efx_nic *efx;

	vdpa_nic = get_vdpa_nic(vdev);
	if (is_qid_invalid(vdpa_nic, idx, __func__))
		return notify_area;

	mutex_lock(&vdpa_nic->lock);

	efx = vdpa_nic->efx;
	notify_area.addr = (uintptr_t)(efx->membase_phys +
				vdpa_nic->vring[idx].doorbell_offset);

	/* VDPA doorbells are at a stride of VI/2
	 * One VI stride is shared by both rx & tx doorbells
	 */
	notify_area.size = efx->vi_stride / 2;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Queue Id:%u Notification addr:0x%x size:0x%x",
		 __func__, idx, (u32)notify_area.addr, (u32)notify_area.size);
#endif
	mutex_unlock(&vdpa_nic->lock);

	return notify_area;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GET_VQ_IRQ)
static int ef100_get_vq_irq(struct vdpa_device *vdev, u16 idx)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);
	u32 irq;

	if (is_qid_invalid(vdpa_nic, idx, __func__))
		return -EINVAL;

	mutex_lock(&vdpa_nic->lock);
	irq = vdpa_nic->vring[idx].irq;
	mutex_unlock(&vdpa_nic->lock);

	dev_info(&vdev->dev, "%s: Queue Id %u, irq: %d\n", __func__, idx, irq);

	return irq;
}
#endif

static u32 ef100_vdpa_get_vq_align(struct vdpa_device *vdev)
{
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Returning value:%u\n", __func__,
		 EF100_VDPA_VQ_ALIGN);
#endif
	return EF100_VDPA_VQ_ALIGN;
}

static u64 ef100_vdpa_get_device_features(struct vdpa_device *vdev)
{
	struct ef100_vdpa_nic *vdpa_nic;
	u64 features = 0;
	int rc = 0;

	vdpa_nic = get_vdpa_nic(vdev);
	rc = efx_vdpa_get_features(vdpa_nic->efx,
				   EF100_VDPA_DEVICE_TYPE_NET, &features);
	if (rc != 0) {
		dev_err(&vdev->dev, "%s: MCDI get features error:%d\n",
			__func__, rc);
		/* Returning 0 as value of features will lead to failure
		 * of feature negotiation.
		 */
		return 0;
	}

#if defined(EFX_USE_KCOMPAT)
	if (!vdpa_nic->in_order)
		features &= ~(1ULL << VIRTIO_F_IN_ORDER);
#endif
	features |= (1ULL << VIRTIO_NET_F_MAC);
	/* TODO: QEMU Shadow VirtQueue (SVQ) doesn't support
	 * VIRTIO_F_ORDER_PLATFORM, so masking it off to allow Live Migration
	 */
	features &= ~(1ULL << VIRTIO_F_ORDER_PLATFORM);
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Features returned:\n", __func__);
	print_features_str(features, vdev);
#endif
	return features;
}

static int ef100_vdpa_set_driver_features(struct vdpa_device *vdev,
					  u64 features)
{
	struct ef100_vdpa_nic *vdpa_nic;
	u64 verify_features = features;
	int rc = 0;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Features received:\n", __func__);
	print_features_str(features, vdev);
#endif
	vdpa_nic = get_vdpa_nic(vdev);
	mutex_lock(&vdpa_nic->lock);
	if (vdpa_nic->vdpa_state != EF100_VDPA_STATE_INITIALIZED) {
		dev_err(&vdev->dev, "%s: Invalid current state %s\n",
			__func__,
			get_vdpa_state_str(vdpa_nic->vdpa_state));
		rc = -EINVAL;
		goto err;
	}
	verify_features = features & ~(1ULL << VIRTIO_NET_F_MAC);
	rc = efx_vdpa_verify_features(vdpa_nic->efx,
				      EF100_VDPA_DEVICE_TYPE_NET,
				      verify_features);

	if (rc != 0) {
		dev_err(&vdev->dev, "%s: MCDI verify features error:%d\n",
			__func__, rc);
		goto err;
	}

	vdpa_nic->features = features;
err:
	mutex_unlock(&vdpa_nic->lock);
	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GET_DEVICE_FEATURES)
static u64 ef100_vdpa_get_driver_features(struct vdpa_device *vdev)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);

	return vdpa_nic->features;
}
#endif

static void ef100_vdpa_set_config_cb(struct vdpa_device *vdev,
				     struct vdpa_callback *cb)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);

	if (cb)
		vdpa_nic->cfg_cb = *cb;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Setting config callback\n", __func__);
#endif
}

static u16 ef100_vdpa_get_vq_num_max(struct vdpa_device *vdev)
{
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Returning value:%u\n", __func__,
		 EF100_VDPA_VQ_NUM_MAX_SIZE);
#endif
	return EF100_VDPA_VQ_NUM_MAX_SIZE;
}

static u32 ef100_vdpa_get_device_id(struct vdpa_device *vdev)
{
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Returning value:%u\n", __func__,
		 EF100_VDPA_VIRTIO_NET_DEVICE_ID);
#endif
	return EF100_VDPA_VIRTIO_NET_DEVICE_ID;
}

static u32 ef100_vdpa_get_vendor_id(struct vdpa_device *vdev)
{
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Returning value:0x%x\n", __func__,
		 EF100_VDPA_XNX_VENDOR_ID);
#endif
	return EF100_VDPA_XNX_VENDOR_ID;
}

static u8 ef100_vdpa_get_status(struct vdpa_device *vdev)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);
	u8 status;

	mutex_lock(&vdpa_nic->lock);
	status = vdpa_nic->status;
	mutex_unlock(&vdpa_nic->lock);
#ifdef EFX_NOT_UPSTREAM
		dev_info(&vdev->dev, "%s: Returning current status bit(s):\n",
			 __func__);
		print_status_str(status, vdev);
#endif
	return status;
}

static void ef100_vdpa_set_status(struct vdpa_device *vdev, u8 status)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);
	u8 new_status;
	int rc = 0;

	mutex_lock(&vdpa_nic->lock);
	if (!status) {
		dev_info(&vdev->dev,
			 "%s: Status received is 0. Device reset being done\n",
			 __func__);
		reset_vdpa_device(vdpa_nic);
		goto unlock_return;
	}
	new_status = status & ~vdpa_nic->status;
	if (new_status == 0) {
		dev_info(&vdev->dev,
			 "%s: New status equal/subset of existing status:\n",
			 __func__);
		dev_info(&vdev->dev, "%s: New status bits:\n", __func__);
		print_status_str(status, vdev);
		dev_info(&vdev->dev, "%s: Existing status bits:\n", __func__);
		print_status_str(vdpa_nic->status, vdev);
		goto unlock_return;
	}
	if (new_status & VIRTIO_CONFIG_S_FAILED) {
		reset_vdpa_device(vdpa_nic);
		goto unlock_return;
	}
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: New status:\n", __func__);
	print_status_str(new_status, vdev);
#endif
	while (new_status) {
		if (new_status & VIRTIO_CONFIG_S_ACKNOWLEDGE &&
		    vdpa_nic->vdpa_state == EF100_VDPA_STATE_INITIALIZED) {
			vdpa_nic->status |= VIRTIO_CONFIG_S_ACKNOWLEDGE;
			new_status = new_status & ~VIRTIO_CONFIG_S_ACKNOWLEDGE;
		} else if (new_status & VIRTIO_CONFIG_S_DRIVER &&
			   vdpa_nic->vdpa_state ==
					EF100_VDPA_STATE_INITIALIZED) {
			vdpa_nic->status |= VIRTIO_CONFIG_S_DRIVER;
			new_status = new_status & ~VIRTIO_CONFIG_S_DRIVER;
		} else if (new_status & VIRTIO_CONFIG_S_FEATURES_OK &&
			   vdpa_nic->vdpa_state ==
						EF100_VDPA_STATE_INITIALIZED) {
			vdpa_nic->status |= VIRTIO_CONFIG_S_FEATURES_OK;
			vdpa_nic->vdpa_state = EF100_VDPA_STATE_NEGOTIATED;
			new_status = new_status & ~VIRTIO_CONFIG_S_FEATURES_OK;
		} else if (new_status & VIRTIO_CONFIG_S_DRIVER_OK &&
			   vdpa_nic->vdpa_state ==
					EF100_VDPA_STATE_NEGOTIATED) {
			vdpa_nic->status |= VIRTIO_CONFIG_S_DRIVER_OK;
			rc = start_vdpa_device(vdpa_nic);
			if (rc) {
				dev_err(&vdpa_nic->vdpa_dev.dev,
					"%s: vDPA device failed:%d\n",
					__func__, rc);
				vdpa_nic->status &=
					~VIRTIO_CONFIG_S_DRIVER_OK;
				goto unlock_return;
			}
			new_status = new_status & ~VIRTIO_CONFIG_S_DRIVER_OK;
		} else {
			dev_warn(&vdev->dev, "%s: Mismatch Status & State\n",
				 __func__);
			dev_warn(&vdev->dev, "%s: New status Bits:\n", __func__);
			print_status_str(new_status, &vdpa_nic->vdpa_dev);
			dev_warn(&vdev->dev, "%s: Current vDPA State: %s\n",
				 __func__,
				 get_vdpa_state_str(vdpa_nic->vdpa_state));
			break;
		}
	}
unlock_return:
	mutex_unlock(&vdpa_nic->lock);
	return;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GET_CONFIG_SIZE)
static size_t ef100_vdpa_get_config_size(struct vdpa_device *vdev)
{
#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: config size:%lu\n", __func__,
		 sizeof(struct virtio_net_config));
#endif
	return sizeof(struct virtio_net_config);
}
#endif

static void ef100_vdpa_get_config(struct vdpa_device *vdev, unsigned int offset,
				  void *buf, unsigned int len)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: offset:%u len:%u\n", __func__, offset, len);
#endif
	/* Avoid the possibility of wrap-up after the sum exceeds U32_MAX */
	if (WARN_ON(((u64)offset + len) > sizeof(struct virtio_net_config))) {
		dev_err(&vdev->dev,
			"%s: Offset + len exceeds config size\n", __func__);
		return;
	}
	memcpy(buf, (u8 *)&vdpa_nic->net_config + offset, len);
}

static void ef100_vdpa_set_config(struct vdpa_device *vdev, unsigned int offset,
				  const void *buf, unsigned int len)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: offset:%u len:%u config size:%lu\n",
		 __func__, offset, len, sizeof(vdpa_nic->net_config));
#endif
	/* Avoid the possibility of wrap-up after the sum exceeds U32_MAX */
	if (WARN_ON(((u64)offset + len) > sizeof(vdpa_nic->net_config))) {
		dev_err(&vdev->dev,
			"%s: Offset + len exceeds config size\n", __func__);
		return;
	}

	memcpy((u8 *)&vdpa_nic->net_config + offset, buf, len);
	ef100_vdpa_insert_filter(vdpa_nic->efx);

	dev_dbg(&vdpa_nic->vdpa_dev.dev,
		 "%s: Status:%u MAC:%pM max_qps:%u MTU:%u\n",
		 __func__, vdpa_nic->net_config.status,
		 vdpa_nic->net_config.mac,
		 vdpa_nic->net_config.max_virtqueue_pairs,
		 vdpa_nic->net_config.mtu);
}

static void ef100_vdpa_free(struct vdpa_device *vdev)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);
	int rc;
	int i;

#ifdef EFX_NOT_UPSTREAM
	dev_info(&vdev->dev, "%s: Releasing vDPA resources\n", __func__);
#endif
	if (vdpa_nic) {
		efx_fini_debugfs_vdpa(vdpa_nic);
		if (vdpa_nic->efx->mcdi_buf_mode == EFX_BUF_MODE_VDPA) {
			rc = ef100_vdpa_map_mcdi_buffer(vdpa_nic->efx);
			if (rc) {
				dev_err(&vdev->dev,
					"map_mcdi_buffer failed, err: %d\n",
					rc);
			}
		}
		for (i = 0; i < (vdpa_nic->max_queue_pairs * 2); i++) {
			reset_vring(vdpa_nic, i);
			if (vdpa_nic->vring[i].vring_ctx)
				delete_vring_ctx(vdpa_nic, i);
		}
		mutex_destroy(&vdpa_nic->lock);
	}
	vdpa_nic->efx->vdpa_nic = NULL;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_CONFIG_OP_SUSPEND)
static int ef100_vdpa_suspend(struct vdpa_device *vdev)
{
	struct ef100_vdpa_nic *vdpa_nic = get_vdpa_nic(vdev);
	int i, rc;

	mutex_lock(&vdpa_nic->lock);
	for (i = 0; i < vdpa_nic->max_queue_pairs * 2; i++) {
		rc = delete_vring(vdpa_nic, i);
		if (rc)
			break;
	}
	mutex_unlock(&vdpa_nic->lock);
	return rc;
}
#endif

const struct vdpa_config_ops ef100_vdpa_config_ops = {
	.set_vq_address	     = ef100_vdpa_set_vq_address,
	.set_vq_num	     = ef100_vdpa_set_vq_num,
	.kick_vq	     = ef100_vdpa_kick_vq,
	.set_vq_cb	     = ef100_vdpa_set_vq_cb,
	.set_vq_ready	     = ef100_vdpa_set_vq_ready,
	.get_vq_ready	     = ef100_vdpa_get_vq_ready,
	.set_vq_state	     = ef100_vdpa_set_vq_state,
	.get_vq_state	     = ef100_vdpa_get_vq_state,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GET_VQ_NOTIFY)
	.get_vq_notification = ef100_vdpa_get_vq_notification,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GET_VQ_IRQ)
	.get_vq_irq          = ef100_get_vq_irq,
#endif
	.get_vq_align	     = ef100_vdpa_get_vq_align,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GET_DEVICE_FEATURES)
	.get_device_features = ef100_vdpa_get_device_features,
	.set_driver_features = ef100_vdpa_set_driver_features,
	.get_driver_features = ef100_vdpa_get_driver_features,
#else
	.get_features	     = ef100_vdpa_get_device_features,
	.set_features	     = ef100_vdpa_set_driver_features,
#endif
	.set_config_cb	     = ef100_vdpa_set_config_cb,
	.get_vq_num_max      = ef100_vdpa_get_vq_num_max,
	.get_device_id	     = ef100_vdpa_get_device_id,
	.get_vendor_id	     = ef100_vdpa_get_vendor_id,
	.get_status	     = ef100_vdpa_get_status,
	.set_status	     = ef100_vdpa_set_status,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_RESET)
	.reset               = ef100_vdpa_reset,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GET_CONFIG_SIZE)
	.get_config_size     = ef100_vdpa_get_config_size,
#endif
	.get_config	     = ef100_vdpa_get_config,
	.set_config	     = ef100_vdpa_set_config,
	.get_generation      = NULL,
	.set_map             = NULL,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_CONFIG_OP_SUSPEND)
	.suspend             = ef100_vdpa_suspend,
#endif
	.free	             = ef100_vdpa_free,
};
#endif
