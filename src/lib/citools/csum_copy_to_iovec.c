/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2004/01/07
** Description: Copy to iovec with Internet checksum.
** </L5_PRIVATE>
\**************************************************************************/

#include "citools_internal.h"


typedef union {
  ci_uint16  u16;
  char       c[2];
} ci_uint16_bytes;


#define ptr_inc(p, n)  ((p) = (char*) (p) + (n))


extern int ci_ip_csum_copy_to_iovec(ci_iovec_ptr* dest, const void* src,
				    int src_len, unsigned* psum)
{
  int total = 0, n, n2;
  unsigned sum = *psum;

  ci_assert(dest);
  ci_assert(src || src_len == 0);
  ci_assert(src_len >= 0);

  while( 1 ) {
  continue_please:
    n = CI_IOVEC_LEN(&dest->io);
    if( n > src_len )  n = src_len;
    n2 = CI_ALIGN_BACK(n, 2);

    sum = ci_ip_csum_copy2(CI_IOVEC_BASE(&dest->io), src, n2, sum);
    src_len -= n2;
    total += n2;

    if( src_len == 0 ) {
      ptr_inc(CI_IOVEC_BASE(&dest->io), n2);
      CI_IOVEC_LEN(&dest->io) -= n2;
      *psum = sum;
      return total;
    }

    if( n & 1 )  goto handle_odd_byte;

    /* Current segment of [dest] is exhausted. */
    ci_assert(n == n2);
    ci_assert(n2 == (int) CI_IOVEC_LEN(&dest->io));

    if( dest->iovlen == 0 ) {
      CI_IOVEC_LEN(&dest->io) = 0;
      *psum = sum;
      return total;
    }

    ptr_inc(src, n2);
    --dest->iovlen;
    dest->io = *dest->iov++;
  }

 handle_odd_byte:
  {
    ci_uint16_bytes tmp;
    ci_assert(n2 == n - 1);

    /* We know we can copy at least one more byte. */

    ptr_inc(src, n + 1);
    src_len -= 2;
    tmp.c[0] = ((char*) src)[-2];

    ptr_inc(CI_IOVEC_BASE(&dest->io), n);
    CI_IOVEC_LEN(&dest->io) -= n;
    ((char*) CI_IOVEC_BASE(&dest->io))[-1] = tmp.c[0];

    /* Beyond here we have no idea.  [src] or [dest] or both may run out,
    ** or we may have to move further through [dest].
    */

    while( CI_IOVEC_LEN(&dest->io) == 0 && dest->iovlen ) {
      --dest->iovlen;
      dest->io = *dest->iov++;
    }
    if( (src_len < 0) | (CI_IOVEC_LEN(&dest->io) == 0) ) {
      tmp.c[1] = 0;
      ci_add_carry32(sum, tmp.u16);
      *psum = sum;
      return total + 1;
    }

    /* NB. [src] and [src_len] already point beyond this byte. */
    tmp.c[1] = ((char*) src)[-1];
    ((char*) CI_IOVEC_BASE(&dest->io))[0] = tmp.c[1];
    ptr_inc(CI_IOVEC_BASE(&dest->io), 1);
    --CI_IOVEC_LEN(&dest->io);
    ci_add_carry32(sum, tmp.u16);
    total += 2;
    goto continue_please;
  }
}

