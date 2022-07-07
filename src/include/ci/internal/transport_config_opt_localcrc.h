/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2022 Xilinx, Inc. */
#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_LOCALCRC_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_LOCALCRC_H__

/* This build profile is identical to "cloud" except that it also enables
 * the CI_CFG_NVME_LOCAL_CRC_MODE feature. This mode does CRC "offload" in
 * software to allow testing without a plugin. */
#include <ci/internal/transport_config_opt_cloud.h>

#undef ONLOAD_BUILD_PROFILE
#define ONLOAD_BUILD_PROFILE "localcrc"

#undef CI_CFG_NVME_LOCAL_CRC_MODE
#define CI_CFG_NVME_LOCAL_CRC_MODE 1

#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_LOCALCRC_H__ */
