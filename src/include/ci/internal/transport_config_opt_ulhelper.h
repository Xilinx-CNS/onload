/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_ULHELPER_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_ULHELPER_H__

/* Use default values for the most of options: */
#include <ci/internal/transport_config_opt_extra.h>

#undef CI_CFG_UL_INTERRUPT_HELPER
#define CI_CFG_UL_INTERRUPT_HELPER 1

/* This mode does not support some features for now. */
#undef CI_CFG_FD_CACHING
#define CI_CFG_FD_CACHING 0
#undef CI_CFG_ENDPOINT_MOVE
#define CI_CFG_ENDPOINT_MOVE 0

#endif
