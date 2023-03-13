/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#ifndef _EFX_DEVLINK_H
#define _EFX_DEVLINK_H

#include "net_driver.h"
#ifndef EFX_USE_KCOMPAT
#include <net/devlink.h>
#endif

int efx_probe_devlink(struct efx_nic *efx);
void efx_fini_devlink(struct efx_nic *efx);

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_GET_DEVLINK_PORT)
struct devlink_port *efx_get_devlink_port(struct net_device *dev);
#endif

#endif	/* _EFX_DEVLINK_H */
