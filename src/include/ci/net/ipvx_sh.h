/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2019 Xilinx, Inc. */
#ifndef __CI_NET_IPVX_SH_H__
#define __CI_NET_IPVX_SH_H__

#include <ci/net/ipv4.h>
#include <ci/net/ipv6.h>

#ifdef CI_ADDR_SH_IS_TYPEDEF
typedef ci_addr_t ci_addr_sh_t CI_ALIGN(8);
#else
/* The layout of the commonly used ci_addr_t type is different in cplane
 * and Onload, when the latter is built without IPv6 support. Thus, to make
 * Onload interface gracefully with cplane, i.e. make direct function calls
 * involving IP addresses, we need to use a "shared" type, ci_addr_sh_t.
 *
 * Because the IPv4 flavour of ci_addr_t is literally a subset of its more
 * comprehensive IPv6 flavour, we make ci_addr_sh_t identical to the IPv6
 * flavour of ci_addr_t. This way, we allow Onload to use the IPv4 flavour
 * of ci_addr_t, which makes a significant difference in the hot I/O paths,
 * but we will require Onload to arrange the IPv6 flavour of ci_addr_t
 * (named ci_addr_sh_t) to interface with cplane. At the same time, this
 * requires no effort from cplane, which thinks that ci_addr_sh_t is exactly
 * the same as ci_addr_t (see the typedef above).
 */
typedef union {
  struct {
    union {
      /*
       * There should be padding to be able to compare IPv4 mapped addresses
       * with IPv6 ones. IPv4 address padding should be filled with ::ffff: value.
       */
      ci_uint8 pad[12];
      struct {
        /* IPv6 mapped address ::ffff:A.B.C.D */
        ci_uint8 zeroes[10];
        ci_uint16 ones;
      };
    };
    ci_ip_addr_t ip4;
  };
  ci_uint64     u64[2] CI_ALIGN(8);
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
