/* SPDX-License-Identifier: GPL-2.0-only */
/****************************************************************************
 * Driver for AMD network controllers and boards
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_CXL_H
#define EFX_CXL_H

#include "net_driver.h"

#if defined(CONFIG_SFC_CXL) && (!defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CXL))

#include <cxl/cxl.h>

struct efx_probe_data;

struct efx_cxl {
	struct cxl_dev_state cxlds;
	struct cxl_memdev *cxlmd;
	void __iomem *ctpio_cxl;
	resource_size_t ctpio_membase;
	bool cxl_datapath_configured;
	enum cxl_transmit_mode transmit_mode;
	enum cxl_receive_mode receive_mode;
};

int efx_cxl_init(struct efx_probe_data *probe_data);
void efx_cxl_exit(struct efx_probe_data *probe_data);

int efx_cxl_configure_datapath(struct efx_nic *efx);
int efx_cxl_set_datapath(struct efx_nic *nic,
			 enum cxl_transmit_mode *got_transmit_mode,
			 enum cxl_receive_mode *got_receive_mode);
int efx_cxl_get_config(struct efx_probe_data *probe_data,
		       bool *cxl_mem_enabled,
		       bool *cxl_cache_enabled);
int efx_cxl_get_ctpio_membase(struct efx_probe_data *probe_data,
			      resource_size_t *membase);
#else
static inline int efx_cxl_init(struct efx_probe_data *probe_data) { return 0; }
static inline void efx_cxl_exit(struct efx_probe_data *probe_data) {}

static inline
int efx_cxl_configure_datapath(struct efx_nic *efx)
{
	return 0;
}

static inline
int efx_cxl_set_datapath(struct efx_nic *efx,
			 enum cxl_transmit_mode *got_transmit_mode,
			 enum cxl_receive_mode *got_receive_mode)
{
	return -EOPNOTSUPP;
}

static inline
int efx_cxl_get_config(struct efx_probe_data *probe_data,
		       bool *cxl_mem_enabled,
		       bool *cxl_cache_enabled)
{
	if (cxl_mem_enabled)
		*cxl_mem_enabled = false;
	if (cxl_cache_enabled)
		*cxl_cache_enabled = false;
	return 0;
}

static inline
int efx_cxl_get_ctpio_membase(struct efx_probe_data *probe_data,
			      resource_size_t *membase)
{
	return -EOPNOTSUPP;
}
#endif

#endif /* EFX_CXL_H */
