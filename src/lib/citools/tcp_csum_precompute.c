/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Precompute partial checksum for TCP packet.
**   \date  2004/01/21
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */

#include "citools_internal.h"
#include <ci/net/ipv4.h>


unsigned ci_tcp_csum_precompute(const ci_ip4_hdr* ip, const ci_tcp_hdr* tcp)
{
  const ci_uint16* p;
  unsigned csum;

  ci_assert(ip);
  ci_assert(tcp);
  ci_assert(CI_PTR_OFFSET(ip, 4) == 0);
  ci_assert(CI_PTR_OFFSET(tcp, 4) == 0);


  p = (const ci_uint16*) ip;
  csum  = p[6];	/* ip_saddr_be32	  */
  csum += p[7];
  csum += p[8];	/* ip_daddr_be32	  */
  csum += p[9];

  csum += htons(IPPROTO_TCP); /* zero, ip_protocol */

  p = (const ci_uint16*) tcp;
  csum += p[0];	/* tcp_source_be16	      */
  csum += p[1];	/* tcp_dest_be16	      */
  csum += p[9];	/* tcp_urg_ptr_be16	      */

  return csum;
}

/*! \cidoxg_end */
