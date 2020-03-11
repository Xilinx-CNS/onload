/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __CI_DRIVER_DRIVERLINK_API__
#define __CI_DRIVER_DRIVERLINK_API__

#define EFX_DRIVERLINK_API_VERSION_MINOR 0

#include <driver/linux_net/driverlink_api.h>

/* Every time the major driverlink version is bumped, this check forces a build
 * failure, as it's necessary to audit the net driver change for compatibility
 * with driverlink clients.  */
#if EFX_DRIVERLINK_API_VERSION > 27
#error "Driverlink API has changed.  Audit client code for compatibility."
#endif

#if EFX_DRIVERLINK_API_VERSION < 25
#error "Driverlink API version too low."
#endif


#endif  /* __CI_DRIVER_DRIVERLINK_API__ */
