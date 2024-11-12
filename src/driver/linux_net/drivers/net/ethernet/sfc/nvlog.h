/****************************************************************************
 * Driver for AMD Solarflare network controllers and boards
 * Copyright 2023 Advanced Micro Devices Inc.
 */

#ifndef EFX_NVLOG_H
#define EFX_NVLOG_H

#include "net_driver.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER)
struct efx_nvlog_data;

int efx_nvlog_init(struct efx_nic *efx);
void efx_nvlog_fini(struct efx_nic *efx);

int efx_nvlog_to_devlink(struct efx_nic *efx, struct devlink_fmsg *fmsg);
int efx_nvlog_do(struct efx_nic *efx, u32 type, bool read, bool clear);
#else
static inline int efx_nvlog_init(struct efx_nic *efx)
{
	return -EOPNOTSUPP;
}

static inline void efx_nvlog_fini(struct efx_nic *efx) {}

struct devlink_fmsg;
static inline int efx_nvlog_to_devlink(struct efx_nic *efx,
				       struct devlink_fmsg *fmsg)
{
	return -EOPNOTSUPP;
}

static inline int efx_nvlog_do(struct efx_nic *efx, u32 type, bool read,
			       bool clear)
{
	return -EOPNOTSUPP;
}
#endif

#endif /* EFX_NVLOG_H */
