/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2021 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_EF100_DUMP_H
#define EFX_EF100_DUMP_H

#include "net_driver.h"

/* Dump state of Streaming Sub-System to dmesg */
int efx_ef100_dump_sss_regs(struct efx_nic *efx);

#endif /* EFX_EF100_DUMP_H */
