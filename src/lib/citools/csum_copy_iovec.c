/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
 /**************************************************************************\
 *//*! \file
 ** <L5_PRIVATE L5_SOURCE>
 ** \author  cjr/ctk
 **  \brief  Copy from iovec with Internet checksum.
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

/* copy an iovec to a destination buffer. 
** The dest_unalign flag, denotes whether the first byte of the
** dest buffer is aligned for checksumming purposes
*/
int ci_ip_csum_copy_iovec(void* dest, int dest_len, int dest_unalign,
			  ci_iovec_ptr* src, unsigned* psum)
{
  int total = 0, n;
  unsigned sum = *psum;

  ci_assert(dest || dest_len == 0);
  ci_assert(dest_len >= 0);

  if(dest_unalign) goto unaligned_output;

  while( 1 ) {
  continue_please:
    n = CI_ALIGN_BACK( CI_IOVEC_LEN(&src->io), 2);
    if( n > dest_len ) n = dest_len;

    sum = ci_ip_csum_copy_aligned(dest, CI_IOVEC_BASE(&src->io), n, sum); 
    dest_len -= n;
    total += n;

    if( dest_len == 0 ) {
      CI_IOVEC_BASE(&src->io) = (char*)CI_IOVEC_BASE(&src->io) + n;
      CI_IOVEC_LEN(&src->io) -= n;
      *psum = sum;
      return total;
    }

    if( CI_IOVEC_LEN(&src->io) & 1u ) goto handle_odd_byte;

    /* Current segment of [src] is exhausted. */
    ci_assert(n == (int) CI_IOVEC_LEN(&src->io));

    if( src->iovlen == 0 ) {
      CI_IOVEC_LEN(&src->io) = 0;
      *psum = sum;
      return total;
    }

    dest = (char*) dest + n;
    --src->iovlen;
    src->io = *src->iov++;
  }

 handle_odd_byte:
  {
    ci_uint16_bytes tmp;
    ci_assert((int) CI_IOVEC_LEN(&src->io) ==  n + 1);
    CI_IOVEC_LEN(&src->io) = 0;

    dest = (char*) dest + n;
    *((char*) dest) = tmp.c[0] = *((char*) CI_IOVEC_BASE(&src->io) + n);
    dest = (char*) dest + 1;
    --dest_len;
    ++total;
    if( dest_len == 0 ) goto terminal_byte;
    do {
      if( src->iovlen == 0 )  goto terminal_byte;
      --src->iovlen;
      src->io = *src->iov++;
    } while( CI_IOVEC_LEN(&src->io) == 0 );
    *((char*) dest ) = tmp.c[1] = *(char*) CI_IOVEC_BASE(&src->io);
    CI_IOVEC_BASE(&src->io) = (char*)CI_IOVEC_BASE(&src->io) + 1;
    dest = (char*) dest + 1;
    --dest_len;
    --CI_IOVEC_LEN(&src->io);
    ++total;
    ci_add_carry32(sum, tmp.u16);
    goto continue_please;

  terminal_byte:
    tmp.c[1] = 0;
    ci_add_carry32(sum, tmp.u16);
    *psum = sum;
    return total;
  }

 unaligned_output:
  {
    ci_uint16_bytes tmp;

    while( CI_IOVEC_LEN(&src->io) == 0 ){ 
      if( src->iovlen == 0 ) return 0;
      --src->iovlen;
      src->io = *src->iov++;
    }
    
    if( dest_len == 0 ) return 0;

    tmp.c[0] = 0;
    *( (char*)dest ) = tmp.c[1] = *((char*)CI_IOVEC_BASE(&src->io));
    dest = (char*) dest + 1;
    CI_IOVEC_BASE(&src->io) = (char*)CI_IOVEC_BASE(&src->io) + 1;
    ++total;
    --dest_len;  
    --CI_IOVEC_LEN(&src->io);
    ci_add_carry32(sum, tmp.u16);

    goto continue_please;
  }
}

/*! \cidoxg_end */
