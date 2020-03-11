/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
 /**************************************************************************\
 *//*! \file
 ** <L5_PRIVATE L5_SOURCE>
 ** \author  djr
 **  \brief  Precompute partial checksum for IP header.
 **   \date  2004/01/21
 **    \cop  (c) Level 5 Networks Limited.
 ** </L5_PRIVATE>
 *//*
 \**************************************************************************/
  
 /*! \cidoxg_lib_citools */
  
#include "citools_internal.h"
#include <ci/net/ipv4.h>


unsigned ci_ip_csum_precompute(const ci_ip4_hdr* ip)
{
  const ci_uint16* p = (const ci_uint16*) ip;
  unsigned csum;

  ci_assert(ip);
  ci_assert(CI_PTR_OFFSET(ip, 4) == 0);

  csum  = p[0];	/* ip_ihl_version, ip_tos */
  csum += p[3];	/* ip_frag_off_be16	  */
  csum += p[4];	/* ip_ttl, ip_protocol	  */
  csum += p[6];	/* ip_saddr_be32	  */
  csum += p[7];
  csum += p[8];	/* ip_daddr_be32	  */
  csum += p[9];
  return csum;
}

/*! \cidoxg_end */
