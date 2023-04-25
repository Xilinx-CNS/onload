/* SPDX-License-Identifier: GPL-2.0 */
/* Driver for Xilinx network controllers and boards
 * Copyright 2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef __EF100_VDPA_H__
#define __EF100_VDPA_H__

#include <linux/vdpa.h>
#include <linux/iommu.h>
#include <uapi/linux/virtio_net.h>
#include <linux/rbtree.h>
#include "net_driver.h"
#include "ef100_nic.h"

#if defined(CONFIG_SFC_VDPA)

/* Device ID of a virtio net device */
#define EF100_VDPA_VIRTIO_NET_DEVICE_ID VIRTIO_ID_NET

/* Vendor ID of Xilinx vDPA NIC */
#define EF100_VDPA_XNX_VENDOR_ID  PCI_VENDOR_ID_XILINX

/* Max Queue pairs currently supported */
#define EF100_VDPA_MAX_QUEUES_PAIRS 1

/* Vector 0 assigned for vring */
#define EF100_VDPA_VRING_VECTOR_BASE 0

/* Max number of Buffers supported in the virtqueue */
#define EF100_VDPA_VQ_NUM_MAX_SIZE 512

/* Alignment requirement of the Virtqueue */
#define EF100_VDPA_VQ_ALIGN 4096

/* Vring configuration definitions */
#define EF100_VRING_ADDRESS_CONFIGURED 0x1
#define EF100_VRING_SIZE_CONFIGURED 0x2
#define EF100_VRING_READY_CONFIGURED 0x4
#define EF100_VRING_CONFIGURED (EF100_VRING_ADDRESS_CONFIGURED | \
				EF100_VRING_SIZE_CONFIGURED | \
				EF100_VRING_READY_CONFIGURED)

#define EF100_VRING_CREATED 0x8

/* Maximum size of msix name */
#define EF100_VDPA_MAX_MSIX_NAME_SIZE 256

/* Default high IOVA for MCDI buffer */
#define EF100_VDPA_IOVA_BASE_ADDR 0x20000000000

#define EFX_VDPA_NAME(_vdpa) "vdpa_%d_%d", (_vdpa)->pf_index, (_vdpa)->vf_index
#define EFX_VDPA_VRING_NAME(_idx) "vring_%d", _idx

/* Following are the states for a vDPA NIC
 * @EF100_VDPA_STATE_INITIALIZED: State after vDPA NIC created
 * @EF100_VDPA_STATE_NEGOTIATED: State after feature negotiation
 * @EF100_VDPA_STATE_STARTED: State after driver ok
 */
enum ef100_vdpa_nic_state {
	EF100_VDPA_STATE_INITIALIZED = 0,
	EF100_VDPA_STATE_NEGOTIATED = 1,
	EF100_VDPA_STATE_STARTED = 2,
	EF100_VDPA_STATE_NSTATES
};

/* Enum defining the virtio device types
 * @EF100_VDPA_DEVICE_TYPE_NET: virtio net device type
 */
enum ef100_vdpa_device_type {
	EF100_VDPA_DEVICE_TYPE_NET,
	EF100_VDPA_DEVICE_NTYPES
};

/* Enum defining the virtquque types
 * @EF100_VDPA_VQ_TYPE_NET_RXQ: NET RX type
 * @EF100_VDPA_VQ_TYPE_NET_TXQ: NET TX type
 */
enum ef100_vdpa_vq_type {
	EF100_VDPA_VQ_TYPE_NET_RXQ,
	EF100_VDPA_VQ_TYPE_NET_TXQ,
	EF100_VDPA_VQ_NTYPES
};

/* struct ef100_vdpa_vring_info - vDPA vring data structure
 * @desc: Descriptor area address of the vring
 * @avail: Available area address of the vring
 * @used: Device area address of the vring
 * @size: Size of the vring
 * @vring_state: bit map to track vring configuration
 * @vring_created: set to true when vring is created.
 * @last_avail_idx: last available index of the vring
 * @last_used_idx: last used index of the vring
 * @doorbell_offset: doorbell offset
 * @doorbell_offset_valid: true if @doorbell_offset is updated
 * @vring_type: type of vring created
 * @vring_ctx: vring context information
 * @msix_name: device name for vring irq handler
 * @irq: irq number for vring irq handler
 * @cb: callback for vring interrupts
 * @debug_dir: vDPA vring debugfs directory
 */
struct ef100_vdpa_vring_info {
	dma_addr_t desc;
	dma_addr_t avail;
	dma_addr_t used;
	u32 size;
	u16 vring_state;
	u32 last_avail_idx;
	u32 last_used_idx;
	u32 doorbell_offset;
	bool doorbell_offset_valid;
	enum ef100_vdpa_vq_type vring_type;
	struct efx_vring_ctx *vring_ctx;
	char msix_name[EF100_VDPA_MAX_MSIX_NAME_SIZE];
	u32 irq;
	struct vdpa_callback cb;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debug_dir;
#endif
};

/* struct ef100_vdpa_nic - vDPA NIC data structure
 * @vdpa_dev: vdpa_device object which registers on the vDPA bus.
 * @vdpa_state: NIC state machine governed by ef100_vdpa_nic_state
 * @mcdi_mode: MCDI mode at the time of unmapping VF mcdi buffer
 * @efx: pointer to the VF's efx_nic object
 * @lock: Managing access to vdpa config operations
 * @pf_index: PF index of the vDPA VF
 * @vf_index: VF index of the vDPA VF
 * @status: device status as per VIRTIO spec
 * @features: negotiated feature bits
 * @net_config: virtio_net_config data
 * @vring: vring information of the vDPA device.
 * @mac_address: mac address of interface associated with this vdpa device
 * @cfg_cb: callback for config change
 * @debug_dir: vDPA debugfs directory
 * @in_order: if true, allow VIRTIO_F_IN_ORDER feature negotiation
 */
struct ef100_vdpa_nic {
	struct vdpa_device vdpa_dev;
	enum ef100_vdpa_nic_state vdpa_state;
	enum efx_mcdi_mode mcdi_mode;
	struct efx_nic *efx;
	struct mutex lock;
	u32 pf_index;
	u32 vf_index;
	u8 status;
	u64 features;
	u32 max_queue_pairs;
	struct virtio_net_config net_config;
	struct ef100_vdpa_vring_info vring[EF100_VDPA_MAX_QUEUES_PAIRS * 2];
	u8 *mac_address;
	struct vdpa_callback cfg_cb;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debug_dir;
#endif
	bool in_order;
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
int ef100_vdpa_register_mgmtdev(struct efx_nic *efx);
void ef100_vdpa_unregister_mgmtdev(struct efx_nic *efx);
struct ef100_vdpa_nic *ef100_vdpa_create(struct efx_nic *efx,
					 const char *dev_name);
#else
struct ef100_vdpa_nic *ef100_vdpa_create(struct efx_nic *efx,
					 const char *dev_name,
					 enum ef100_vdpa_class dev_type);
#endif
int ef100_vdpa_init(struct efx_probe_data *probe_data);
void ef100_vdpa_fini(struct efx_probe_data *probe_data);
void ef100_vdpa_delete(struct efx_nic *efx);
void ef100_vdpa_insert_filter(struct efx_nic *efx);
void ef100_vdpa_irq_vectors_free(void *data);
void reset_vdpa_device(struct ef100_vdpa_nic *vdpa_nic);
int ef100_vdpa_reset(struct vdpa_device *vdev);
bool ef100_vdpa_dev_in_use(struct efx_nic *efx);
int ef100_vdpa_init_vring(struct ef100_vdpa_nic *vdpa_nic, u16 idx);
int ef100_vdpa_map_mcdi_buffer(struct efx_nic *efx);

extern const struct vdpa_config_ops ef100_vdpa_config_ops;
#endif /* CONFIG_SFC_VDPA */

#endif /* __EF100_VDPA_H__ */
