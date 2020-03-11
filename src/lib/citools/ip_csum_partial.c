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


unsigned ci_ip_csum_partial(unsigned sum, const volatile void* in_buf,
			    int bytes)
{
  const ci_uint16* buf = (const ci_uint16*) in_buf;

  ci_assert(in_buf || bytes == 0);
  ci_assert(bytes >= 0);

  while( bytes > 1 ) {
    sum += *buf++;
    bytes -= 2;
  }

  /* If there's a lone final byte, it needs to be treated as if it was
   * padded by an extra zero byte.  Casting to ci_uint8* introduces an
   * implicit CI_BSWAP_LE16 which needs to be reversed. */
  sum += bytes ? CI_BSWAP_LE16(*(ci_uint8*) buf) : 0;

  return sum;
}

/*! \cidoxg_end */
