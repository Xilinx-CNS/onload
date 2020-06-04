/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr/stg
**  \brief  Compute Internet checksums.
**   \date  2004/10/26
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */

#include "citools_internal.h"
#include <ci/net/ipv4.h>
#include <ci/net/ipv6.h>
#include <ci/tools/ipcsum_base.h>
#include <etherfabric/checksum.h>


unsigned ci_icmp_checksum(const ci_ip4_hdr* ip, const ci_icmp_hdr* icmp)
{
  unsigned csum;

  ci_assert(ip);
  ci_assert(icmp);
  ci_assert(CI_PTR_OFFSET(ip, 4) == 0);
  ci_assert(CI_PTR_OFFSET(icmp, 4) == 0);
  ci_assert(sizeof(ci_icmp_hdr) == 4);
  ci_assert(CI_BSWAP_BE16(ip->ip_tot_len_be16) >=
	    (int) (CI_IP4_IHL(ip) + sizeof(ci_icmp_hdr)));

  /* This gets the [type] and [code] fields. */
  csum = *(ci_uint16*) icmp;
  /* Omit the [check] field and sum the rest. */
  csum = ci_ip_csum_partial(csum, icmp, (CI_BSWAP_BE16(ip->ip_tot_len_be16)
					 - CI_IP4_IHL(ip)
					 - sizeof(ci_icmp_hdr)));
  return ci_icmp_csum_finish(csum);
}

unsigned ci_icmpv6_checksum(const ci_ip6_hdr* ip6, const ci_icmp_hdr* icmp)
{
  const ci_iovec iov = {
    .iov_base = (void*)(icmp + 1),
    .iov_len = CI_BSWAP_BE16(ip6->payload_len) - sizeof(ci_icmp_hdr)
  };
  return ef_icmpv6_checksum((struct ipv6hdr*)ip6, icmp, &iov, 1);
}

/*! \cidoxg_end */
