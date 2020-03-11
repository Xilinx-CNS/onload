/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Data copy with Internet checksum.
**   \date  2004/01/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_citools */

#include "citools_internal.h"


typedef union {
  ci_uint16  u16;
  char       c[2];
} ci_uint16_bytes;


/* Length must be a multiple of half-words */
unsigned ci_ip_csum_copy2(void* dest, const void* src, int n, unsigned sum)
{
  ci_uint32* d4 = (ci_uint32*) dest;
  const ci_uint32 *es4, *s4 = (const ci_uint32*) src;
  ci_uint32 v;

  ci_assert(dest || n == 0);
  ci_assert(src  || n == 0);
  ci_assert(n >= 0);
  ci_assert(CI_OFFSET(n, 2) == 0);

  es4 = s4 + (n >> 2);

  while( s4 != es4 ) {
    *d4++ = v = *s4++;
    ci_add_carry32(sum, v);
  }

  if( n & 2 ) {
    v = *(const ci_uint16*) s4;
    ci_add_carry32(sum, v);
    *(ci_uint16*) d4 = v;
  }

  return sum;
}

/*! \cidoxg_end */
