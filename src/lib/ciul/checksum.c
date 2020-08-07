/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2020 Xilinx, Inc. */
#ifdef __KERNEL__
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#else
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif
#include <linux/ipv6.h>

#include "ef_vi_internal.h"

/* The pseudo-header used for TCP and UDP checksum calculation. */
typedef struct {
  uint32_t  ip_saddr_be32;
  uint32_t  ip_daddr_be32;
  uint8_t   zero;
  uint8_t   ip_protocol;
  uint16_t  length_be16;  /* udp hdr + payload */
} ip4_pseudo_hdr;

typedef struct {
  struct in6_addr saddr;
  struct in6_addr daddr;
  uint32_t length;
  uint8_t  zeros[3];
  uint8_t  next_hdr;
} ip6_pseudo_hdr;


/* NB: csum can be maintained as BE value even with LE addition operations
 * because all inputs are BE values and the folding of overflow means that
 * carry going the "wrong way" between the bytes doesn't matter after folding
 * as the scheme is somewhat "symmetrical".
 */

ef_vi_inline uint64_t
ip_csum64_partial(uint64_t csum64, const void*__restrict__ buf, size_t bytes)
{
  EF_VI_ASSERT(buf || bytes == 0);
  EF_VI_ASSERT(bytes >= 0);
  EF_VI_ASSERT((bytes & 1) == 0);

  while( bytes >= 4 ) {
    uint32_t bounce;
    memcpy(&bounce, buf, sizeof(bounce));
    csum64 += bounce;
    buf = (char*) buf + sizeof(bounce);
    bytes -= sizeof(bounce);
  }
  if( bytes ) {
    uint16_t bounce;
    memcpy(&bounce, buf, sizeof(bounce));
    csum64 += bounce;
  }

  return csum64;
}


static uint64_t
ip_csum64_partialv(uint64_t csum64, const struct iovec* iov, int iovlen)
{
  int n, carry = 0;
  union {
    uint8_t u8[2];
    uint16_t u16;
  } carried;
  carried.u8[0] = 0;  /* avoid compiler warning */

  for( n = 0; n < iovlen; n++ ) {
    uint8_t* data = (uint8_t*)iov[n].iov_base;
    int bytes = iov[n].iov_len;
    if( bytes == 0 )
      continue;
    if( carry ) {
      carried.u8[1] = data[0];
      csum64 += carried.u16;
      data++;
      bytes--;
    }
    csum64 = ip_csum64_partial(csum64, data, bytes & ~1);
    if( (bytes & 1) == 0 ) {
      carry = 0;
    }
    else {
      carry = 1;
      carried.u8[0] = data[bytes - 1];
    }
  }
  if( carry )
    csum64 += carried.u8[0];
  return csum64;
}


ef_vi_inline uint32_t ip_proto_csum64_finish(uint64_t csum64)
{
  /* The top 16bits of csum64 will be zero because we're only summing IP
   * datagrams (so total length is < 64KiB).
   */
  EF_VI_ASSERT((csum64 >> 48) == 0);
  {
    unsigned sum = ( ((csum64 >> 32) & 0xffff) + ((csum64 >> 16) & 0xffff)
                     + (csum64 & 0xffff) );
    sum =  (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    sum = ~sum & 0xffff;
    return sum;
  }
}


ef_vi_inline uint32_t ip_hdr_csum32_finish(uint32_t csum32)
{
  unsigned sum =  (csum32 >> 16u) + (csum32 & 0xffff);
  sum += (sum >> 16u);
  return ~sum & 0xffff;
}


uint32_t ef_ip_checksum(const struct iphdr* ip)
{
  const uint16_t*__restrict__ p = (const uint16_t*) ip;
  uint32_t csum32;
  int bytes;

  csum32  = p[0];
  csum32 += p[1];
  csum32 += p[2];
  csum32 += p[3];
  csum32 += p[4];
  /* omit ip_check_be16 */
  csum32 += p[6];
  csum32 += p[7];
  csum32 += p[8];
  csum32 += p[9];

  bytes = ip->ihl * 4;
  if(CI_UNLIKELY( bytes > 20 )) {
    p += 10;
    bytes -= 20;
    do {
      csum32 += *p++;
      bytes -= 2;
    } while( bytes );
  }

  return ip_hdr_csum32_finish(csum32);
}

static uint64_t
ef_ip6_pseudo_hdr_checksum(const struct ipv6hdr* ip6, uint16_t length_be16,
                           uint8_t protocol)
{
  /* Calculate checksum for both saddr and daddr */
  uint64_t csum64 = ip_csum64_partial(0, &ip6->saddr, sizeof(ip6->saddr) * 2);
  csum64 += length_be16;
  return csum64 + htonl(protocol);
}

uint32_t ef_udp_checksum(const struct iphdr* ip, const struct udphdr* udp,
			 const struct iovec* iov, int iovlen)
{
  uint64_t csum64;
  uint32_t csum;

  csum64 = (uint64_t)ip->saddr + ip->daddr +    /* This is the UDP */
           htons(IPPROTO_UDP) + udp->len;       /* pseudo-header */
  csum64 = ip_csum64_partial(csum64, udp, 6); /* omit udp_check_be16 */
  csum64 = ip_csum64_partialv(csum64, iov, iovlen);
  csum = ip_proto_csum64_finish(csum64);
  return csum ? csum : 0xffff;
}

uint32_t ef_udp_checksum_ip6(const struct ipv6hdr* ip6, const struct udphdr* udp,
                             const struct iovec* iov, int iovlen)
{
  uint32_t csum;
  uint64_t csum64 = ef_ip6_pseudo_hdr_checksum(ip6, udp->len, IPPROTO_UDP);
  csum64 = ip_csum64_partial(csum64, udp, 6);
  csum64 = ip_csum64_partialv(csum64, iov, iovlen);
  csum = ip_proto_csum64_finish(csum64);
  return csum ? csum : 0xffff;
}

uint32_t ef_udp_checksum_ipx(int af, const void* ipx, const struct udphdr* udp,
                             const struct iovec* iov, int iovlen)
{
  if( af == AF_INET6 )
    return ef_udp_checksum_ip6((const struct ipv6hdr*)ipx, udp, iov, iovlen);
  else
    return ef_udp_checksum((const struct iphdr*)ipx, udp, iov, iovlen);
}

uint32_t ef_tcp_checksum(const struct iphdr* ip, const struct tcphdr* tcp,
                         const struct iovec* iov, int iovlen)
{
  uint16_t paylen;
  uint64_t csum64;

  paylen = ntohs(ip->tot_len) - (ip->ihl * 4);

  csum64 = (uint64_t)ip->saddr + ip->daddr +       /* This is the TCP */
           htonl((IPPROTO_TCP << 16) | paylen);    /* pseudo-header */
  csum64 = ip_csum64_partial(csum64, tcp, (tcp->doff * 4));
  csum64 -= tcp->check;
  csum64 = ip_csum64_partialv(csum64, iov, iovlen);
  return ip_proto_csum64_finish(csum64);
}

uint32_t ef_tcp_checksum_ip6(const struct ipv6hdr* ip6, const struct tcphdr* tcp,
                             const struct iovec* iov, int iovlen)
{

  uint64_t csum64 =
      ef_ip6_pseudo_hdr_checksum(ip6, ip6->payload_len, IPPROTO_TCP);
  csum64 = ip_csum64_partial(csum64, tcp, (tcp->doff * 4));
  csum64 -= tcp->check;
  csum64 = ip_csum64_partialv(csum64, iov, iovlen);
  return ip_proto_csum64_finish(csum64);
}

uint32_t ef_tcp_checksum_ipx(int af, const void* ipx, const struct tcphdr* tcp,
                             const struct iovec* iov, int iovlen)
{
  if( af == AF_INET6 )
    return ef_tcp_checksum_ip6((const struct ipv6hdr*)ipx, tcp, iov, iovlen);
  else
    return ef_tcp_checksum((const struct iphdr*)ipx, tcp, iov, iovlen);
}

uint32_t ef_icmpv6_checksum(const struct ipv6hdr* ip6, const void* icmp,
                            const struct iovec* iov, int iovlen)
{
  uint64_t csum64 =
      ef_ip6_pseudo_hdr_checksum(ip6, ip6->payload_len, IPPROTO_ICMPV6);
  csum64 = ip_csum64_partial(csum64, icmp, 2);
  csum64 = ip_csum64_partialv(csum64, iov, iovlen);
  return ip_proto_csum64_finish(csum64);
}
