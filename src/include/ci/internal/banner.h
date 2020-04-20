/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  dar
**  \brief  Helper function to print startup banner
**   \date  2019/08/05
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __KERNEL__
#include <stdlib.h>
#include <string.h>

#include <ci/internal/ip.h>
#include <onload/version.h>
#include <cplane/mib.h>

static inline void ci_netif_log_startup_banner(ci_netif* ni, const char* verb)
{
  struct cp_mibs* mib;
  cp_version_t version;
  char* sku;

  CP_VERLOCK_START(version, mib, ni->cplane)
    /* This is safe even in the event of a race, as the string is always
     * terminated somewhere. */
    sku = strdup(mib->sku->value);
  CP_VERLOCK_STOP(version, mib)

  NI_LOG(ni, BANNER, "%s %s %s [%s]",
         verb,
         sku != NULL ? sku : ONLOAD_PRODUCT,
         ONLOAD_VERSION,
         ni->state->pretty_name);
  NI_LOG(ni, BANNER, ONLOAD_COPYRIGHT);

  free(sku);
}
#endif
