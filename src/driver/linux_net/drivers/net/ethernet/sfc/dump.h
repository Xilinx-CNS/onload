/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_DUMP_H
#define EFX_DUMP_H

#ifdef CONFIG_SFC_DUMP

#define EFX_DUMP_DISABLE  0x0
#define EFX_DUMP_ENABLE   0x1
#define EFX_DUMP_FORCE    0x2

struct efx_dump_data;
struct ethtool_dump;

int efx_dump_init(struct efx_nic *efx);
void efx_dump_fini(struct efx_nic *efx);
int efx_dump_reset(struct efx_nic *efx);
int efx_dump_get_flag(struct efx_nic *efx, struct ethtool_dump *dump);
int efx_dump_get_data(struct efx_nic *efx, struct ethtool_dump *dump,
		      void *buffer);
int efx_dump_set(struct efx_nic *efx, struct ethtool_dump *val);

#else /* !CONFIG_SFC_DUMP */

static inline int efx_dump_init(struct efx_nic *efx)
{
	return 0;
}
static inline void efx_dump_fini(struct efx_nic *efx) {}

#endif /* CONFIG_SFC_DUMP */

#endif /* EFX_DUMP_H */
