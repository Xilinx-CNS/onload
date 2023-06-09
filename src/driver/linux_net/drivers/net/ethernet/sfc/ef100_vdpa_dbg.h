/* SPDX-License-Identifier: GPL-2.0 */
/* Driver for AMD network controllers and boards
 * Copyright(C) 2023, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_EF100_VDPA_DBG_H
#define EFX_EF100_VDPA_DBG_H

void print_status_str(u8 status, struct vdpa_device *vdev);
void print_vring_state(u16 state, struct vdpa_device *vdev);
void print_features_str(u64 features, struct vdpa_device *vdev);

#endif /* EFX_EF100_VDPA_DBG_H */
