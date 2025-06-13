/* SPDX-License-Identifier: GPL-2.0 */
/****************************************************************************
 * Driver for AMD Solarflare network controllers and boards
 * Copyright 2025 Advanced Micro Devices Inc.
 */

#ifndef EFX_NVCFG_H
#define EFX_NVCFG_H

#include "nvlog.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER)
int efx_nvcfg_read(struct efx_nic *efx, struct efx_nvlog_data *nvlog_data,
		   u32 type);
#endif
#endif /* EFX_NVLOG_H */
