/****************************************************************************
 * Driver for AMD Solarflare network controllers and boards
 * Copyright 2023 Advanced Micro Devices Inc.
 */

#ifndef EFX_NVLOG_H
#define EFX_NVLOG_H

#include "net_driver.h"

struct devlink_fmsg;

struct efx_nvlog_data {
	char *nvlog;
	size_t nvlog_len;
	size_t nvlog_max_len;
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEVLINK)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER)
int efx_nvlog_to_devlink(struct efx_nvlog_data *nvlog_data,
			 struct devlink_fmsg *fmsg);

#define EFX_NVLOG_F_READ	0x1
#define EFX_NVLOG_F_CLEAR	0x2
int efx_nvlog_do(struct efx_nic *efx, struct efx_nvlog_data *nvlog_data,
		 u32 type, unsigned int flags);
#else
static inline int efx_nvlog_to_devlink(struct efx_nic *efx,
				       struct devlink_fmsg *fmsg)
{
	return -EOPNOTSUPP;
}

static inline int efx_nvlog_do(struct efx_nic *efx,
			       struct efx_nvlog_data *nvlog_data,
			       u32 type, unsigned int flags)
{
	return -EOPNOTSUPP;
}
#endif /* EFX_HAVE_DEVLINK_HEALTH_REPORTER */
#endif /* EFX_USE_DEVLINK */

#endif /* EFX_NVLOG_H */
