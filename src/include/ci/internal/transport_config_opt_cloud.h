/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_CLOUD_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_CLOUD_H__

/* Use default values for the most of options: */
#include <ci/internal/transport_config_opt_extra.h>

#define ONLOAD_BUILD_PROFILE "cloud"

#undef CI_CFG_IPV6
#define CI_CFG_IPV6 1

#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_CLOUD_H__ */
