/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2022 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_TC_DEBUGFS_H
#define EFX_TC_DEBUGFS_H
#include "net_driver.h"

#include "debugfs.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
#ifdef CONFIG_SFC_DEBUGFS
extern struct efx_debugfs_parameter efx_tc_debugfs[];
#endif
#endif

#endif /* EFX_TC_DEBUGFS_H */
