/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2009-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  kjm
**  \brief  Internet protocol definitions.
**   \date  2009/03
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_net  */

#ifndef __CI_NET_IPV6_H__
#define __CI_NET_IPV6_H__

#include <ci/tools/byteorder.h>

/**********************************************************************
 ** IP
 */

typedef ci_uint8 ci_ip6_addr_t[16];

typedef struct ci_ip6_hdr_s {
  ci_uint8  prio_version;
  ci_uint8  flow[3];
  ci_uint16 payload_len;
  ci_uint8  next_hdr;
  ci_uint8  hop_limit;
  ci_ip6_addr_t saddr;
  ci_ip6_addr_t daddr;
} ci_ip6_hdr;

/* Fixme: We use this function to finr TCP or UDP header, but there may be
 * extension headers in between. */
ci_inline void* ci_ip6_data(ci_ip6_hdr* ip6)
{
  return ip6 + 1;
}

#define CI_IP6_PRIORITY(ip) ((ip)->prio_version & 0xf)
#define CI_IP6_VERSION(ip)  ((ip)->prio_version >> 4u)

#define CI_IP6_PRINTF_FORMAT \
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"

#define CI_IP6_PRINTF_ARGS(ip) \
    ip[0], ip[1], ip[2], ip[3], \
    ip[4], ip[5], ip[6], ip[7], \
    ip[8], ip[9], ip[10], ip[11], \
    ip[12], ip[13], ip[14], ip[15]

#define CI_INET6_ADDRSTRLEN 48

#define CI_IP6_IS_MULTICAST(a) (((const ci_uint8 *) (a))[0] == 0xff)

#define CI_IP6_IS_LINKLOCAL(a) \
  ((((const ci_uint32 *) (a))[0] & CI_BSWAP_BE32(0xffc00000)) \
  == CI_BSWAP_BE32(0xfe800000))

#define CI_IP6_ADDR_CMP(addr1, addr2) memcmp((addr1), (addr2), \
    sizeof(ci_ip6_addr_t))

enum { /* ICMPv6 type field */
  CI_ICMPV6_DEST_UNREACH = 1,
  CI_ICMPV6_PKT_TOOBIG   = 2,
  CI_ICMPV6_TYPE_MAX     = 3
};

enum { /* ICMPv6 code field for type = ICMPV6_DEST_UNREACH */
  CI_ICMPV6_DU_NOROUTE        = 0,
  CI_ICMPV6_DU_ADM_PROHIBITED = 1,
  CI_ICMPV6_DU_NOT_NEIGHBOUR  = 2,
  CI_ICMPV6_DU_ADDR_UNREACH   = 3,
  CI_ICMPV6_DU_PORT_UNREACH   = 4,
  CI_ICMPV6_DU_POLICY_FAIL    = 5,
  CI_ICMPV6_DU_REJECT_ROUTE   = 6,
  CI_ICMPV6_DU_CODE_MAX       = 7
};

/* The following struct declaration is needed to delivery of the IPV6_PKTINFO
 * control message on incoming datagrams. We have to declare our own version
 * here because this struct is available in /usr/include/linux/ipv6.h but
 * that .h file has kernel IPv6 declarations that conflict with standard
 * user-space IPv6 declarations.
 */
struct ci_in6_pktinfo {
  struct in6_addr ipi6_addr;      /* src/dst IPv6 address */
  unsigned int ipi6_ifindex;      /* send/recv interface index */
};

#define CI_IP6_TCLASS_MASK CI_BSWAP_BE32(0x0FF00000)
#define CI_IP6_FLOWLABEL_MASK CI_BSWAP_BE32(0x000FFFFF)
#define CI_IP6_TCLASS_SHIFT 20

/* Retrieve IPv6 header Traffic Class field */
ci_inline ci_uint8 ci_ip6_tclass(const ci_ip6_hdr* hdr)
{
  return CI_BSWAP_BE32(*(ci_uint32*)hdr & CI_IP6_TCLASS_MASK) >> CI_IP6_TCLASS_SHIFT;
}

/* Retrieve IPv6 header Flow Label field */
ci_inline ci_uint32 ci_ip6_flowlabel_be32(const ci_ip6_hdr* hdr)
{
  return *(ci_uint32*)hdr & CI_IP6_FLOWLABEL_MASK;
}

/* Set IPv6 header flow information identified by Traffic Class and Flow Label values */
ci_inline void ci_ip6_set_flowinfo(ci_ip6_hdr* hdr, ci_uint8 tclass,
                                   ci_uint32 flowlabel_be32)
{
  *(ci_uint32*)hdr = CI_BSWAP_BE32(0x60000000 | (tclass << CI_IP6_TCLASS_SHIFT)) |
                     flowlabel_be32;
}

ci_inline void ci_ip6_set_tclass(ci_ip6_hdr* hdr, ci_uint8 tclass)
{

  ci_uint32 flowlabel = ci_ip6_flowlabel_be32(hdr);
  ci_ip6_set_flowinfo(hdr, tclass, flowlabel);
}

ci_inline void ci_ip6_set_flowlabel_be32(ci_ip6_hdr* hdr, ci_uint32 flowlabel)
{
  ci_uint8 tclass = ci_ip6_tclass(hdr);
  ci_ip6_set_flowinfo(hdr, tclass, flowlabel);
}

#define CI_NEXTHDR_FRAGMENT 44

/* Fragmentation header */
typedef struct ci_ip6_frag_hdr_s {
  ci_uint8  next_hdr;
  ci_uint8  reserved;
  ci_uint16 frag_off;
  ci_uint32 frag_id;
} ci_ip6_frag_hdr;

/* More fragments flag */
#define CI_IP6_MF 0x0001
/* Fragment offset mask */
#define CI_IP6_OFFSET 0xFFF8

ci_inline void ci_ip6_frag_hdr_init(ci_ip6_frag_hdr* fh, ci_uint8 next_hdr,
                                    ci_uint16 frag_off, int mf,
                                    ci_uint32 frag_id_be32)
{
  fh->next_hdr = next_hdr;
  fh->reserved = 0;
  fh->frag_off = CI_BSWAP_BE16(frag_off);
  if( mf )
    fh->frag_off |= CI_BSWAPC_BE16(CI_IP6_MF);
  fh->frag_id = frag_id_be32;
}

#endif /* __CI_NET_IPV6_H__ */
