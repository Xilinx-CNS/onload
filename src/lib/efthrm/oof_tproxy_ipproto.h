/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __OOF_TPROXY_IPPROTO_H__
#define __OOF_TPROXY_IPPROTO_H__

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_IP6 0x86DD

static const ci_uint16 oof_tproxy_ipprotos[][2] = {
  {ETHERTYPE_IP, IPPROTO_ICMP},
  {ETHERTYPE_IP, IPPROTO_IGMP},
  {ETHERTYPE_IP, IPPROTO_UDP},
#if CI_CFG_IPV6
  {ETHERTYPE_IP6, IPPROTO_ICMPV6},
  {ETHERTYPE_IP6, IPPROTO_UDP},
#endif
};

#define OOF_TPROXY_IPPROTO_FILTER_COUNT (sizeof(oof_tproxy_ipprotos) /       \
                                         sizeof(oof_tproxy_ipprotos[0]))

#define OOF_TPROXY_GLOBAL_FILTER_COUNT OOF_TPROXY_IPPROTO_FILTER_COUNT


#endif  /* __TPROXY_IPPROTO_IMPL_H__ */
