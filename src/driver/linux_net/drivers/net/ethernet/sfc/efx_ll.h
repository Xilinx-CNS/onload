/* SPDX-License-Identifier: GPL-2.0-only */
/****************************************************************************
 * Driver for AMD network controllers and boards
 *
 * Copyright 2024, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#ifndef EFX_LL_H
#define EFX_LL_H

#include <linux/types.h>
#include <linux/sfc/efx_design_params.h>

struct efx_nic;
struct efx_probe_data;

int efx_ll_init(struct efx_nic *efx);
void efx_ll_fini(struct efx_nic *efx);
bool efx_ll_is_enabled(struct efx_nic *efx);
bool efx_ll_is_bar_remapped(struct efx_nic *efx);
int efx_ll_remap_bar(struct efx_nic *efx);
resource_size_t efx_llct_mem_phys(struct efx_probe_data *pd,
				  unsigned int addr);
void __iomem *efx_llct_mem(struct efx_probe_data *pd, unsigned int addr);

struct efx_design_params *efx_llct_get_design_parameters(struct efx_nic *efx);
#endif /* EFX_LL_H */
