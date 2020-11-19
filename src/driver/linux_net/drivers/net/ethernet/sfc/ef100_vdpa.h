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
#include <uapi/linux/virtio_net.h>
#include "net_driver.h"
#include "ef100_nic.h"

#if defined(CONFIG_SFC_VDPA)
#if !defined(EFX_USE_KCOMPAT) && !defined(EFX_DISABLE_SFC_VDPA)

/* Device ID of a virtio net device */
#define EF100_VDPA_VIRTIO_NET_DEVICE_ID VIRTIO_ID_NET

/* Vendor ID of Xilinx vDPA NIC */
#define EF100_VDPA_XNX_VENDOR_ID  PCI_VENDOR_ID_XILINX

/* Max Queue pairs currently supported */
#define EF100_VDPA_MAX_QUEUES_PAIRS 1

/* vDPA queues starts from 2nd VI or qid 1 */
#define EF100_VDPA_BASE_RX_QID 1

/* Vector 0 assigned for vring */
#define EF100_VDPA_VRING_VECTOR_BASE 0

/* Max number of Buffers supported in the virtqueue */
#define EF100_VDPA_VQ_NUM_MAX_SIZE 512

/* Alignment requirement of the Virtqueue */
#define EF100_VDPA_VQ_ALIGN 4096

/* Vring configuration definitions */
#define EF100_VRING_ADDRESS_CONFIGURED 0x1
#define EF100_VRING_SIZE_CONFIGURED 0x10
#define EF100_VRING_READY_CONFIGURED 0x100
#define EF100_VRING_CONFIGURED (EF100_VRING_ADDRESS_CONFIGURED | \
				EF100_VRING_SIZE_CONFIGURED | \
				EF100_VRING_READY_CONFIGURED)

/* Maximum number of supported filters */
#define EF100_VDPA_MAX_SUPPORTED_FILTERS 2

/* Maximum size of msix name */
#define EF100_VDPA_MAX_MSIX_NAME_SIZE 256

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
 * @EF100_VDPA_DEVICE_TYPE_BLOCK: virtio block device type
 */
enum ef100_vdpa_device_type {
	EF100_VDPA_DEVICE_TYPE_RESERVED,
	EF100_VDPA_DEVICE_TYPE_NET,
	EF100_VDPA_DEVICE_TYPE_BLOCK,
	EF100_VDPA_DEVICE_NTYPES
};

/* Enum defining the virtquque types
 * @EF100_VDPA_VQ_TYPE_NET_RXQ: NET RX type
 * @EF100_VDPA_VQ_TYPE_NET_TXQ: NET TX type
 * @EF100_VDPA_VQ_TYPE_BLOCK:  block type
 *
 */
enum ef100_vdpa_vq_type {
	EF100_VDPA_VQ_TYPE_NET_RXQ,
	EF100_VDPA_VQ_TYPE_NET_TXQ,
	EF100_VDPA_VQ_TYPE_BLOCK,
	EF100_VDPA_VQ_NTYPES
};

/* Enum defining the vdpa filter type
 * @EF100_VDPA_BCAST_MAC_FILTER: Broadcast MAC filter
 * @EF100_VDPA_UCAST_MAC_FILTER: Unicast MAC filter
 *
 */
enum ef100_vdpa_mac_filter_type {
	EF100_VDPA_BCAST_MAC_FILTER,
	EF100_VDPA_UCAST_MAC_FILTER,
	EF100_VDPA_MAC_FILTER_NTYPES,
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
 * @vring_type: type of vring created
 * @vring_ctx: vring context information
 * @msix_name: device name for vring irq handler
 * @irq: irq number for vring irq handler
 * @cb: callback for vring interrupts
 */
struct ef100_vdpa_vring_info {
	dma_addr_t desc;
	dma_addr_t avail;
	dma_addr_t used;
	u32 size;
	u16 vring_state;
	bool vring_created;
	u32 last_avail_idx;
	u32 last_used_idx;
	u32 doorbell_offset;
	enum ef100_vdpa_vq_type vring_type;
	struct efx_vring_ctx *vring_ctx;
	char msix_name[EF100_VDPA_MAX_MSIX_NAME_SIZE];
	u32 irq;
	struct vdpa_callback cb;
};

/* struct ef100_vdpa_filter - vDPA filter data structure
 * @filter_id: filter id of this filter
 * @efx_filter_spec: hardware filter specs for this vdpa device
 */
struct ef100_vdpa_filter {
	s32 filter_id;
	struct efx_filter_spec spec;
};

/* struct ef100_vdpa_nic - vDPA NIC data structure
 * @vdpa_dev: vdpa_device object which registers on the vDPA bus.
 * @vdpa_state: NIC state machine governed by ef100_vdpa_nic_state
 * @efx: pointer to the VF's efx_nic object
 * @pf_index: PF index of the vDPA VF
 * @vf_index: VF index of the vDPA VF
 * @status: device status as per VIRTIO spec
 * @features: negotiated feature bits
 * @net_config: virtio_net_config data
 * @vring: vring information of the vDPA device.
 * @mac_address: mac address of interface associated with this vdpa device
 * @filter_cnt: total number of filters created on this vdpa device
 * @filters: details of all filters created on this vdpa device
 * @cfg_cb: callback for config change
 */
struct ef100_vdpa_nic {
	struct vdpa_device vdpa_dev;
	enum ef100_vdpa_nic_state vdpa_state;
	struct efx_nic *efx;
	u32 pf_index;
	u32 vf_index;
	u8 status;
	u64 features;
	u32 max_queue_pairs;
	struct virtio_net_config net_config;
	struct ef100_vdpa_vring_info vring[EF100_VDPA_MAX_QUEUES_PAIRS * 2];
	u8 mac_address[ETH_ALEN];
	u32 filter_cnt;
	bool mac_configured;
	struct ef100_vdpa_filter filters[EF100_VDPA_MAX_SUPPORTED_FILTERS];
	struct vdpa_callback cfg_cb;
};

int ef100_vdpa_init(struct efx_probe_data *probe_data);
void ef100_vdpa_fini(struct efx_probe_data *probe_data);
struct ef100_vdpa_nic *ef100_vdpa_create(struct efx_nic *efx);
void ef100_vdpa_delete(struct efx_nic *efx);
int ef100_vdpa_filter_configure(struct ef100_vdpa_nic *vdpa_nic);
int ef100_vdpa_filter_remove(struct ef100_vdpa_nic *vdpa_nic);
int ef100_vdpa_irq_vectors_alloc(struct pci_dev *pci_dev, u16 min, u16 max);
void ef100_vdpa_irq_vectors_free(void *data);

#endif
#endif

#endif
