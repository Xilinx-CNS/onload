/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2020 Xilinx, Inc. */
#ifndef __CI_DRIVER_DRIVERLINK_API__
#define __CI_DRIVER_DRIVERLINK_API__

#define EFX_DRIVERLINK_API_VERSION_MINOR 0

#include <../driver/linux_net/drivers/net/ethernet/sfc/driverlink_api.h>
#include <../driver/linux_net/drivers/net/ethernet/sfc/filter.h>

/* Every time the major driverlink version is bumped, this check forces a build
 * failure, as it's necessary to audit the net driver change for compatibility
 * with driverlink clients.  */
#if EFX_DRIVERLINK_API_VERSION > 33
#error "Driverlink API has changed.  Audit client code for compatibility."
#endif

#if EFX_DRIVERLINK_API_VERSION < 33
#error "Driverlink API version too low."
#endif


#endif  /* __CI_DRIVER_DRIVERLINK_API__ */
