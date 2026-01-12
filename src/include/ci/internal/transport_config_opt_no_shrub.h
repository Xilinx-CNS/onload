/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */
#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_NO_SHRUB_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_NO_SHRUB_H__

/* Use default values for the most of options: */
#include <ci/internal/transport_config_opt_extra.h>

#define ONLOAD_BUILD_PROFILE "no_shrub"

#undef CI_CFG_WANT_SHRUB
#define CI_CFG_WANT_SHRUB 0

#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_CLOUD_H__ */
