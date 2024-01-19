/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2020 Xilinx, Inc. */
#ifndef __CI_NET_IPVX_H__
#define __CI_NET_IPVX_H__

#ifndef __KERNEL__
#include <stdbool.h>
#endif

#include <ci/net/ipv4.h>
#include <ci/net/ipv6.h>

typedef union {
  struct {
#if CI_CFG_IPV6
    union {
      ci_uint8 pad[12];
      struct {
        /* IPv6 mapped address ::ffff:A.B.C.D */
        ci_uint8 zeroes[10];
        ci_uint16 ones;
      };
    };
#endif
    ci_ip_addr_t ip4;
  };
#if CI_CFG_IPV6
  ci_uint64     u64[2] CI_ALIGN(8);
  ci_uint32     u32[4];
  ci_uint16     u16[8];
  ci_ip6_addr_t ip6;
#endif
} ci_addr_t;

/* Include this after ci_addr_t definition! */
#if CI_CFG_IPV6
#define CI_ADDR_SH_IS_TYPEDEF
#endif
#include <ci/net/ipvx_sh.h>

#if CI_CFG_IPV6
#define WITH_CI_CFG_IPV6(x) x
#else
#define WITH_CI_CFG_IPV6(x)
#endif

static const ci_addr_t addr_any = {};
#if CI_CFG_IPV6
static const ci_addr_t ip4_addr_any = {{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}}}};
static const ci_addr_t ip6_addr_loop = {.ip6={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}};
#else
static const ci_addr_t ip4_addr_any;
#endif

#if CI_CFG_IPV6
/* Returns IPv4-mapped IPv6 address. IPv4 address is extended with ::ffff padding. */
#define CI_ADDR_FROM_IP4(ip) ({ ci_addr_t a = \
    {.u64 = {0, CI_BSWAP_LE64(((ci_uint64)CI_BSWAP_LE32(ip) << 32) | 0xffff0000)}}; a; })
#else
#define CI_ADDR_FROM_IP4(ip) (({ struct { ci_addr_t a[1]; } a = {}; \
                                 a.a[0].ip4 = (ip); a; }).a[0])
#endif

#if CI_CFG_IPV6
#define CI_ADDR_FROM_IP6(ip6_addr) ({ ci_addr_t a = {}; \
    memcpy(a.ip6, (ip6_addr), sizeof(ci_ip6_addr_t)); a; })
#else
/* This macro is not expected to be really called, but it is used with
 * following expression:
 * IS_AF_INET6(af) ? CI_ADDR_FROM_IP6() : CI_ADDR_FROM_IP4()
 * and IS_AF_INET6(af) is always 0 in !CI_CFG_IPV6 case. */
#define CI_ADDR_FROM_IP6(ip6_addr) addr_any
#endif

#if CI_CFG_IPV6
#define CI_IPX_ADDR_SIZE(af) ((af) == AF_INET6 ? sizeof(ci_ip6_addr_t) \
        : sizeof(ci_ip_addr_t))
#else
#define CI_IPX_ADDR_SIZE(af) sizeof(ci_ip_addr_t)
#endif

#if CI_CFG_IPV6
/*
 * Returns zero if address is IPv4-mapped IPv6 and non-zero otherwise. Uses
 * bitwise XOR to compare 9-th to 12-th bytes to 0xffff0000 value.
 */
ci_inline ci_uint64 ci_is_addr_ip6(ci_addr_t a)
{
  return a.u64[0] | ((CI_BSWAP_LE64(a.u64[1]) & 0xffffffff) ^ 0xffff0000);
}

#define CI_IS_ADDR_IP6(addr) (ci_is_addr_ip6(addr))
#define CI_ADDR_AF(addr) (ci_is_addr_ip6(addr) ? AF_INET6 : AF_INET)
#else
#define CI_IS_ADDR_IP6(addr) 0
#define CI_ADDR_AF(addr) AF_INET
#endif

#if CI_CFG_IPV6
ci_inline int ci_ipx_is_multicast(ci_addr_t a)
{
  if( CI_IS_ADDR_IP6(a) )
    return CI_IP6_IS_MULTICAST((a).ip6);
  else
    return CI_IP_IS_MULTICAST((a).ip4);
}

#define CI_IPX_IS_MULTICAST(addr) ci_ipx_is_multicast(addr)
#else
#define CI_IPX_IS_MULTICAST(addr) CI_IP_IS_MULTICAST((addr).ip4)
#endif

#if CI_CFG_IPV6
#define CI_IPX_IS_LINKLOCAL(addr) (CI_IS_ADDR_IP6(addr) ? \
  CI_IP6_IS_LINKLOCAL((addr).u32) : 0)
#else
#define CI_IPX_IS_LINKLOCAL(addr) 0
#endif

#if CI_CFG_IPV6
ci_inline ci_uint64 ci_ipx_addr_cmp(ci_addr_t a, ci_addr_t b)
{
  return (a.u64[0] ^ b.u64[0]) | (a.u64[1] ^ b.u64[1]);
}

#define CI_IPX_ADDR_EQ(a, b) (!ci_ipx_addr_cmp((a), (b)))
#else
#define CI_IPX_ADDR_EQ(a, b) (!CI_IP_ADDR_CMP((a).ip4, (b).ip4))
#endif

#if CI_CFG_IPV6
/*
 * Checks, if addr is equal to addr_any or ip4_addr_any. Returns zero if equal
 * and non-zero otherwise. Uses bitwise OR for first 8 and last 4 bytes of
 * addrss. Compares 9-th to 12-th bytes to 0x00000000 and 0xffff0000 values
 * by adding 0x10000.
 */
ci_inline ci_uint64 ci_ipx_addr_cmp_any(ci_addr_t a)
{
  ci_uint64 v = CI_BSWAP_LE64(a.u64[1]);
  return a.u64[0] | ((((v << 32) | ( v >> 32)) + 0x1000000000000ull) & ~0x1000000000000ull);
}

#define CI_IPX_ADDR_IS_ANY(a) (!ci_ipx_addr_cmp_any(a))
#else
#define CI_IPX_ADDR_IS_ANY(a) (!CI_IP_ADDR_CMP((a).ip4, addr_any.ip4))
#endif

#if CI_CFG_IPV6
ci_inline int ci_ipx_is_loopback(ci_addr_t addr)
{
  if( CI_IS_ADDR_IP6(addr) )
    return CI_IPX_ADDR_EQ(addr, ip6_addr_loop);
  else
    return CI_IP_IS_LOOPBACK((addr).ip4);
}

#define CI_IPX_IS_LOOPBACK(addr) ci_ipx_is_loopback(addr)
#else
#define CI_IPX_IS_LOOPBACK(addr) CI_IP_IS_LOOPBACK((addr).ip4)
#endif

typedef enum {
  AF_SPACE_FLAG_IP4=1,
  AF_SPACE_FLAG_IP6=2,
} ci_af_space_t;

#if CI_CFG_IPV6
#define IS_AF_SPACE_IP6(af_space) ((af_space) & AF_SPACE_FLAG_IP6)
#define IS_AF_SPACE_IP4(af_space) ((af_space) & AF_SPACE_FLAG_IP4)
#else
#define IS_AF_SPACE_IP6(af_space) 0
#define IS_AF_SPACE_IP4(af_space) 1
#endif

#if CI_CFG_IPV6
#define IS_AF_INET6(af) ((af) == AF_INET6)
#else
#define IS_AF_INET6(af) 0
#endif

/* Use this carefully, because AF_INET6 sometimes mean
 * AF_SPACE_FLAG_IP6 | AF_SPACE_FLAG_IP4.  See sock_af_space()
 * for complicated cases. */
#define OO_AF_FAMILY2SPACE(af) \
  (IS_AF_INET6(af) ? AF_SPACE_FLAG_IP6 : AF_SPACE_FLAG_IP4)

ci_inline char *ci_get_ip_str(const ci_addr_t src, char *dst, size_t size,
                              int ipv6_add_brackets)
{
  int n = 0;

#define CI_SPRINTF_APPEND(...) ({ \
    n += ci_snprintf(dst + n, size - n, __VA_ARGS__); \
    if( (size_t) n >= size ) \
      goto fail; \
  })

#if CI_CFG_IPV6
  if( CI_IS_ADDR_IP6(src) ) {
    int i;
    int in_zero = 0, been_in_zero = 0;

    if( ipv6_add_brackets )
      CI_SPRINTF_APPEND("[");

    for( i = 0; i < (int)sizeof(src.ip6) / 2; i++ ) {
      if( i != 0 && ! in_zero )
        CI_SPRINTF_APPEND(":");
      /* :: can be printed only once, so we use !been_in_zero here */
      if( src.u16[i] == 0 && (in_zero || !been_in_zero) ) {
        if( ! been_in_zero )
          been_in_zero = 1;
        if( ! in_zero ) {
          in_zero = 1;
          /* Print additional : when entering zero mode */
          CI_SPRINTF_APPEND(":");
        }
      }
      else {
        if( in_zero )
          in_zero = 0;
        CI_SPRINTF_APPEND("%x", CI_BSWAP_BE16(src.u16[i]));
      }
    }
    /* And if we end printing in zero mode, then print another : */
    if( in_zero )
      CI_SPRINTF_APPEND(":");
    if( ipv6_add_brackets )
      CI_SPRINTF_APPEND("]");
  }
  else
#endif
  {
    CI_SPRINTF_APPEND(CI_IP_PRINTF_FORMAT, CI_IP_PRINTF_ARGS(&src.ip4));
  }

  return dst;
#undef CI_SPRINTF_APPEND

fail:
  ci_assert_ge(n, 0); /* has snprintf returned error? */
  ci_assert_ge(size, (size_t)n); /* it is buffer overlow then */
  dst[size - 1] = 0; /* release build - terminate string */
  return dst;
}

#if CI_CFG_IPV6
#define IPX_FMT            "%s"
#define IPX_ARG(ip)        (ip)
#define IPX_PORT_FMT       "%s:%d"
#define __AF_IP(ip,brackets) ( &({ \
    struct { char buf[CI_INET6_ADDRSTRLEN]; } str; \
    ci_get_ip_str(ip, str.buf, sizeof(str.buf), brackets); \
    str; }).buf[0] )
#define AF_IP(ip) __AF_IP((ip),1)
#define AF_IP_L3(ip) __AF_IP((ip),0)
#else
#define IPX_FMT            CI_IP_PRINTF_FORMAT
#define IPX_ARG(ip)        CI_IP_PRINTF_ARGS(&((ip).ip4))
#define IPX_PORT_FMT       IPX_FMT":%d"
#define AF_IP(ip)          (ip)
#define AF_IP_L3           AF_IP
#endif

#if CI_CFG_IPV6
#define IPX_SOCKADDR_SIZE(af) ((af) == AF_INET ? \
    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#else
#define IPX_SOCKADDR_SIZE(af) (sizeof(struct sockaddr_in))
#endif

#if CI_CFG_IPV6
#define CI_ADDR_FROM_ADDR_SH(addr) ({ ci_addr_t a = {}; \
    memcpy(&a, &addr, sizeof(a)); a; })
#else
#define CI_ADDR_FROM_ADDR_SH(addr) ({ ci_addr_t a = {}; \
    a = CI_ADDR_FROM_IP4((addr).ip4); a; })
#endif

#if CI_CFG_IPV6
#define CI_ADDR_SH_FROM_ADDR(addr) ({ ci_addr_sh_t a = {}; \
    memcpy(&a, &addr, sizeof(a)); a; })
#else
#define CI_ADDR_SH_FROM_ADDR(addr) ({ ci_addr_sh_t a = {}; \
    a = CI_ADDR_SH_FROM_IP4((addr).ip4); a; })
#endif

#if CI_CFG_IPV6
#define CI_IPX_ADDR_PTR(af, addr) ((af) == AF_INET6 ? (void*)(&(addr).ip6) : \
    (void*)(&(addr).ip4))
#else
#define CI_IPX_ADDR_PTR(af, addr) ((af) == AF_INET6 ? NULL : \
    (void*)(&(addr).ip4))
#endif

#if CI_CFG_IPV6
#define CI_IPX_HDR_SIZE(af) ((af) == AF_INET6 ? sizeof(ci_ip6_hdr) : \
    sizeof(ci_ip4_hdr))
#else
#define CI_IPX_HDR_SIZE(af) sizeof(ci_ip4_hdr)
#endif

#define CI_IPX_FRAG_HDR_SIZE(af) \
    ( WITH_CI_CFG_IPV6( IS_AF_INET6(af) ? sizeof(ci_ip6_frag_hdr) : ) 0 )

#if CI_CFG_IPV6
#define CI_IPX_IHL(af, ipx) ((af) == AF_INET6 ? sizeof(ci_ip6_hdr) : \
    CI_IP4_IHL(&(ipx)->ip4))
#else
#define CI_IPX_IHL(af, ipx) CI_IP4_IHL(&(ipx)->ip4)
#endif

#define CI_IPX_DFLT_TOS_TCLASS(af) (IS_AF_INET6(af) ? CI_IPV6_DFLT_TCLASS : \
    CI_IP_DFLT_TOS)

#define CI_IPX_DFLT_TTL_HOPLIMIT(af) (IS_AF_INET6(af) ? \
    CI_IPV6_DFLT_HOPLIMIT : CI_IP_DFLT_TTL)

typedef union ci_ipx_hdr {
  ci_ip4_hdr ip4;
#if CI_CFG_IPV6
  ci_ip6_hdr ip6;
#endif
} ci_ipx_hdr_t;

#if CI_CFG_IPV6
#define ipx_hdr_ptr(af, ipx) \
  (af == AF_INET6 ? (void*)&ipx->ip6 : (void*)&ipx->ip4)
#else
#define ipx_hdr_ptr(af, ipx) (&ipx->ip4)
#endif

#define ipx_hdr_saddr(af, hdr) ({ struct { ci_addr_t a[1]; } a = {};     \
  a.a[0] = IS_AF_INET6(af) ? CI_ADDR_FROM_IP6((hdr)->ip6.saddr) :        \
                             CI_ADDR_FROM_IP4((hdr)->ip4.ip_saddr_be32); \
  a;}).a[0]
#define ipx_hdr_daddr(af, hdr) ({ struct { ci_addr_t a[1]; } a = {};     \
  a.a[0] = IS_AF_INET6(af) ? CI_ADDR_FROM_IP6((hdr)->ip6.daddr) :        \
                             CI_ADDR_FROM_IP4((hdr)->ip4.ip_daddr_be32); \
  a;}).a[0]


static inline void ipx_hdr_set_saddr(int af, ci_ipx_hdr_t* hdr, ci_addr_t addr)
{
#if CI_CFG_IPV6
  if( af == AF_INET6 ) {
    memcpy(hdr->ip6.saddr, addr.ip6, sizeof(ci_ip6_addr_t));
  }
  else
#endif
  {
    hdr->ip4.ip_saddr_be32 = addr.ip4;
  }
}

static inline void ipx_hdr_set_daddr(int af, ci_ipx_hdr_t* hdr, ci_addr_t addr)
{
#if CI_CFG_IPV6
  if( af == AF_INET6 ) {
    memcpy(hdr->ip6.daddr, addr.ip6, sizeof(ci_ip6_addr_t));
  }
  else
#endif
  {
    hdr->ip4.ip_daddr_be32 = addr.ip4;
  }
}

static inline int ipx_hdr_tot_len(int af, const ci_ipx_hdr_t* hdr)
{
#if CI_CFG_IPV6
  if( af == AF_INET6 )
    return CI_BSWAP_BE16(hdr->ip6.payload_len) + sizeof(ci_ip6_hdr);
  else
#endif
    return CI_BSWAP_BE16(hdr->ip4.ip_tot_len_be16);
}

static inline void ipx_hdr_set_payload_len(int af, ci_ipx_hdr_t* hdr,
                                           ci_uint16 len)
{
#if CI_CFG_IPV6
  if( af == AF_INET6 )
    hdr->ip6.payload_len = CI_BSWAP_BE16(len);
  else
#endif
    hdr->ip4.ip_tot_len_be16 = CI_BSWAP_BE16(sizeof(ci_ip4_hdr) + len);
}

#if CI_CFG_IPV6
ci_inline void ipx_hdr_set_flowlabel(int af, ci_ipx_hdr_t* hdr,
                                    ci_uint32 flowlabel)
{
  if( IS_AF_INET6(af) )
    ci_ip6_set_flowlabel_be32(&hdr->ip6, flowlabel);
}
#else
#define ipx_hdr_set_flowlabel(af, hdr, flowlabel)
#endif

static inline void* ipx_hdr_data(int af, ci_ipx_hdr_t* hdr)
{
#if CI_CFG_IPV6
  if( af == AF_INET6 )
    return ci_ip6_data(&hdr->ip6);
  else
#endif
    return ci_ip_data(&hdr->ip4);

}

#if CI_CFG_IPV6
#define ipx_hdr_protocol(af, ipx) (*((af) == AF_INET6 ? \
    &(ipx)->ip6.next_hdr : &(ipx)->ip4.ip_protocol))
#define ipx_hdr_ttl(af, ipx) (*((af) == AF_INET6 ? \
    &(ipx)->ip6.hop_limit : &(ipx)->ip4.ip_ttl))
#else
#define ipx_hdr_protocol(af, ipx) ((ipx)->ip4.ip_protocol)
#define ipx_hdr_ttl(af, ipx) ((ipx)->ip4.ip_ttl)
#endif

ci_inline ci_uint8
ipx_hdr_tos_tclass(int af, const ci_ipx_hdr_t* hdr)
{
  return WITH_CI_CFG_IPV6( IS_AF_INET6(af) ? ci_ip6_tclass(&hdr->ip6) : )
      hdr->ip4.ip_tos;
}

ci_inline ci_addr_t
ci_ipx_addr_xor(int af, ci_addr_t* a, ci_addr_t* b)
{
  ci_addr_t v = *a;
#if CI_CFG_IPV6
  if( af == AF_INET6 ) {
    v.u64[0] ^= b->u64[0];
    v.u64[1] ^= b->u64[1];
  }
  else
#endif
    v.ip4 ^= b->ip4;
  return v;
}

#if CI_CFG_IPV6
/* Compares ci_addr_t addresses with network mask applied. Returns 0 when both
   addresses belong to the same subnetwork. */
ci_inline ci_uint64
ci_ipx_addr_masked_cmp(const ci_addr_t* a, const ci_addr_t* b,
                       const ci_addr_t* m)
{
  return ((a->u64[0] ^ b->u64[0]) & m->u64[0]) |
         ((a->u64[1] ^ b->u64[1]) & m->u64[1]);
}

ci_inline int
ci_ipx_addr_masked_eq(const ci_addr_t* a, const ci_addr_t* b,
                      const ci_addr_t* m)
{
  return ci_ipx_addr_masked_cmp(a, b, m) == 0;
}
#endif

#if CI_CFG_IPV6
static inline int ipx_hdr_af(const ci_ipx_hdr_t* ipx)
{
  return CI_IP6_VERSION(&(ipx)->ip6) == 6 ? AF_INET6 : AF_INET;
}
#else
#define ipx_hdr_af(ipx) AF_INET
#endif

ci_inline bool ci_ipx_is_frag(int af, const ci_ipx_hdr_t* ipx)
{
#if CI_CFG_IPV6
  if( IS_AF_INET6(af) ) {
    if( ipx->ip6.next_hdr == CI_NEXTHDR_FRAGMENT )
      return true;
  }
  else
#endif
  {
    if( ipx->ip4.ip_frag_off_be16 & ~CI_IP4_FRAG_DONT )
      return true;
  }
  return false;
}

#endif /* __CI_NET_IPVX_H__ */
