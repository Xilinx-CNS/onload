/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Driver for Solarflare and Xilinx network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 * Copyright 2019-2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_AUXBUS_H
#define EFX_AUXBUS_H

/* Driver API */
#ifdef CONFIG_AUXILIARY_BUS
int efx_auxbus_register(struct efx_nic *efx);
void efx_auxbus_unregister(struct efx_nic *efx);
#else
static inline int efx_auxbus_register(struct efx_nic *efx)
{
	return 0;
}

static inline void efx_auxbus_unregister(struct efx_nic *efx) {}
#endif
#endif
