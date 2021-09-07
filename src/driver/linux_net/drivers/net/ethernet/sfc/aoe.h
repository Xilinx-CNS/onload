/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_AOE_H
#define EFX_AOE_H

#include "net_driver.h"
#include "efx.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "io.h"
#include "nic.h"

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
#include "efx_ioctl.h"
#include "mcdi_pcol_aoe.h"

int efx_aoe_event(struct efx_nic *efx, efx_qword_t *event, int budget);
int efx_aoe_update_cpld(struct efx_nic *efx, struct efx_update_cpld *cpld);
int efx_aoe_update_keys(struct efx_nic *efx,
			struct efx_update_license *key_stats);
int efx_aoe_reset_aoe(struct efx_nic *efx,
			struct efx_aoe_reset *reset_flags);
#else
static inline int efx_aoe_event(struct efx_nic *efx, efx_qword_t *event, int budget)
{ return -ENOENT; };
#endif

#endif /* EFX_AOE_H */
