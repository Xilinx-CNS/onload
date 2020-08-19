/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2019 Xilinx, Inc. */
#ifndef __CI_NET_IPVX_SH_H__
#define __CI_NET_IPVX_SH_H__

#include <ci/net/ipv4.h>
#include <ci/net/ipv6.h>

#ifdef CI_ADDR_SH_IS_TYPEDEF
typedef ci_addr_t ci_addr_sh_t CI_ALIGN(8);
#else
/*
 * ci_addr_sh_t type is similar to ci_addr_t, but there is no dependency of
 * CI_CFG_IPV6 option because address values should be shared between cplane
 * and onload. Cplane server has a permanent IPv6 support. Onload can be built
 * with or without IPv6 support according to CI_CFG_IPV6 value.
 */
typedef union {
  struct {
      /*
       * There should be padding to be able to compare IPv4 mapped addresses
       * with IPv6 ones. IPv4 address padding should be filled with ::ffff: value.
       */
      ci_uint8 pad[12];
      ci_ip_addr_t ip4;
  };
  ci_uint64     u64[2];
  ci_uint32     u32[4];
  ci_uint16     u16[8];
  ci_ip6_addr_t ip6;
} ci_addr_sh_t CI_ALIGN(8);
#endif

extern const ci_addr_sh_t addr_sh_any;
extern const ci_addr_sh_t ip4_addr_sh_any;

#define CI_IS_ADDR_SH_IP6(addr) \
    (memcmp((addr).pad, ip4_addr_sh_any.pad, sizeof((addr).pad)))

#define CI_ADDR_SH_FROM_IP4(ip) ({ ci_addr_sh_t a = \
    {.u64 = {0, CI_BSWAP_LE64(((ci_uint64)CI_BSWAP_LE32(ip) << 32) | 0xffff0000)}}; a; })

#define CI_ADDR_SH_FROM_IP6(ip6_addr) ({ ci_addr_sh_t a = {}; \
    memcpy(a.ip6, (ip6_addr), sizeof(ci_ip6_addr_t)); a; })

#define CI_IPX_ADDR_SH_PTR(af, addr) ((af) == AF_INET6 ? (void*)(&(addr).ip6) : \
    (void*)(&(addr).ip4))

/* Compares ci_addr_sh_t addresses with network mask applied. Returns 0 when
   both addresses belong to the same subnetwork. */
ci_inline ci_uint64
ci_ipx_addr_sh_masked_cmp(const ci_addr_sh_t* a, const ci_addr_sh_t* b,
                          const ci_addr_sh_t* m)
{
  return ((a->u64[0] ^ b->u64[0]) & m->u64[0]) |
         ((a->u64[1] ^ b->u64[1]) & m->u64[1]);
}

ci_inline int
ci_ipx_addr_sh_masked_eq(const ci_addr_sh_t* a, const ci_addr_sh_t* b,
                         const ci_addr_sh_t* m)
{
  return ci_ipx_addr_sh_masked_cmp(a, b, m) == 0;
}

#endif /* __CI_NET_IPVX_SH_H__ */
