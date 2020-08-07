/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_CLOUD_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_CLOUD_H__

/* Use default values for the most of options: */
#include <ci/internal/transport_config_opt_extra.h>

#undef CI_CFG_IPV6
#define CI_CFG_IPV6 1

/* Enable Berkeley Packet Filter program functionality. */
#undef CI_CFG_BPF
#define CI_CFG_BPF 1

/* Enable the SmartNIC TCP+Ceph plugin */
#undef CI_CFG_TCP_OFFLOAD_RECYCLER
#define CI_CFG_TCP_OFFLOAD_RECYCLER 1
#undef CI_CFG_TCP_PLUGIN_EXTRA_VIS
#define CI_CFG_TCP_PLUGIN_EXTRA_VIS 1

#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_CLOUD_H__ */
