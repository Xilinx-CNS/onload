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

#include <ci/internal/ip.h>
#include <onload/version.h>

#ifndef __KERNEL__
static inline void ci_netif_log_startup_banner(ci_netif* ni, const char* verb) {
  NI_LOG(ni, BANNER, "%s %s %s [%s]",
         verb,
         ONLOAD_PRODUCT,
         ONLOAD_VERSION,
         ni->state->pretty_name);
  NI_LOG(ni, BANNER, ONLOAD_COPYRIGHT);
}
#endif
