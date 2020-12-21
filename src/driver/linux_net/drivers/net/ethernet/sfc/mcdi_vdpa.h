/* SPDX-License-Identifier: GPL-2.0 */
/* Driver for Xilinx network controllers and boards
 * Copyright 2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_MCDI_VDPA_H
#define EFX_MCDI_VDPA_H

#if defined(CONFIG_SFC_VDPA)

/* MAE Port selector value*/
#define MAE_MPORT_SELECTOR_ASSIGNED 0x1000000

/* struct efx_vring_ctx: Store the vring context
 * @nic: pointer of the VF's efx_nic object
 * @vf_index: VF index of the vDPA VF
 * @vi_index: vi index to be used for queue creation
 * @mcdi_vring_type: corresponding MCDI vring type
 */
struct efx_vring_ctx {
	struct efx_nic *nic;
	u32 vf_index;
	u32 vi_index;
	u32 mcdi_vring_type;
};

/* struct efx_vring_cfg: Configuration for vring creation
 * @desc: Descriptor area address of the vring
 * @avail: Available area address of the vring
 * @used: Device area address of the vring
 * @size: Size of the vring
 * @use_pasid: boolean whether to use pasid for queue creation
 * @pasid: pasid to use for queue creation
 * @msix_vector: msix vector address for the queue
 * @features: negotiated feature bits
 */
struct efx_vring_cfg {
	u64 desc;
	u64 avail;
	u64 used;
	u32 size;
	bool use_pasid;
	u32 pasid;
	u16 msix_vector;
	u64 features;
};

/* struct efx_vring_dyn_cfg:
 * @avail_idx: last available index of the vring
 * @used_idx: last used index of the vring
 */
struct efx_vring_dyn_cfg {
	u32 avail_idx;
	u32 used_idx;
};

int efx_vdpa_get_features(struct efx_nic *efx, enum ef100_vdpa_device_type type,
			  u64 *featuresp);

int efx_vdpa_verify_features(struct efx_nic *efx,
			     enum ef100_vdpa_device_type type, u64 features);

struct efx_vring_ctx *efx_vdpa_vring_init(struct efx_nic *efx, u32 vi,
					  enum ef100_vdpa_vq_type vring_type);

void efx_vdpa_vring_fini(struct efx_vring_ctx *vring_ctx);

int efx_vdpa_vring_create(struct efx_vring_ctx *vring_ctx,
			  struct efx_vring_cfg *vring_cfg,
			  struct efx_vring_dyn_cfg *vring_dyn_cfg);

int efx_vdpa_vring_destroy(struct efx_vring_ctx *vring_ctx,
			   struct efx_vring_dyn_cfg *vring_dyn_cfg);

int efx_vdpa_get_doorbell_offset(struct efx_vring_ctx *vring_ctx,
				 u32 *offsetp);
int efx_vdpa_get_mac_address(struct efx_nic *efx, u8 *mac_address);
int efx_vdpa_get_link_details(struct efx_nic *efx, u16 *link_up,
			      u32 *link_speed, u8 *duplex);
int efx_vdpa_get_mtu(struct efx_nic *efx, u16 *mtu);
#endif

#endif
