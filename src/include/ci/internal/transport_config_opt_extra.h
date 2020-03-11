/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_EXTRA_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_EXTRA_H__

/* Disable IPv6 by default */
#undef CI_CFG_IPV6
#define CI_CFG_IPV6 0

/* Disable Berkeley Packet Filter program functionality. */
#undef CI_CFG_BPF
#define CI_CFG_BPF 0
/* Disable Userland interrupt and timer helper */
#define CI_CFG_UL_INTERRUPT_HELPER 0

#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_EXTRA_H__ */
