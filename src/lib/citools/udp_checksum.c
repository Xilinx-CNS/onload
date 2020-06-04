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

unsigned ci_udp_checksum(const ci_ip4_hdr* ip, const ci_udp_hdr* udp,
			 const ci_iovec *iov, int iovlen)
{
  return ef_udp_checksum((struct iphdr*)ip, (struct udphdr*)udp, iov, iovlen);
}

unsigned ci_ip6_udp_checksum(const ci_ip6_hdr* ip6, const ci_udp_hdr* udp,
                             const ci_iovec *iov, int iovlen)
{
  return ef_udp_checksum_ip6((struct ipv6hdr*)ip6, (struct udphdr*)udp, iov, iovlen);
}

/*! \cidoxg_end */
