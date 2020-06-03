/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Compute Internet checksums.
**   \date  2003/01/05
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */

#include "citools_internal.h"
#include <ci/net/ipv4.h>
#include <ci/net/ipv6.h>
#include <etherfabric/checksum.h>

/* 0xffff is an impossible checksum for TCP and IP (special case for UDP)
** This is because you would need the partial checksum when folded to be
** 0 (so it inverts to ffff). The checksum is additive so you can only
** add to the next multiple of 0x10000 and that will always get folded
** back again
*/

unsigned ci_tcp_checksum(const ci_ip4_hdr* ip, const ci_tcp_hdr* tcp,
			 const void* payload)
{
  const ci_iovec iov = {
    .iov_base = (void*)payload,
    .iov_len = CI_BSWAP_BE16(ip->ip_tot_len_be16) - CI_IP4_IHL(ip) -
               CI_TCP_HDR_LEN(tcp)
  };
  return ef_tcp_checksum((struct iphdr*)ip, (struct tcphdr*)tcp, &iov, 1);
}

unsigned ci_ip6_tcp_checksum(const ci_ip6_hdr* ip6, const ci_tcp_hdr* tcp,
                             const void* payload)
{
  const ci_iovec iov = {
    .iov_base = (void*)payload,
    .iov_len = CI_BSWAP_BE16(ip6->payload_len) - CI_TCP_HDR_LEN(tcp)
  };
  return ef_tcp_checksum_ip6((struct ipv6hdr*)ip6, (struct tcphdr*)tcp, &iov, 1);
}

/*! \cidoxg_end */
