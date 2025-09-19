/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */
#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_CXL_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_CXL_H__

/* Disable IPv6 by default */
#undef CI_CFG_IPV6
#define CI_CFG_IPV6 0

/* Disable Userland interrupt and timer helper */
#define CI_CFG_UL_INTERRUPT_HELPER 0

/* Enable code necessary to support CXL */
#undef CI_CFG_CXL
#define CI_CFG_CXL 1

#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_CXL_H__ */
