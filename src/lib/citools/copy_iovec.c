/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
 /**************************************************************************\
 *//*! \file
 ** <L5_PRIVATE L5_SOURCE>
 ** \author  djr
 **  \brief  Copy from ci_iovec_ptr to linear buffer.
 **   \date  2004/11/06
 **    \cop  (c) Level 5 Networks Limited.
 ** </L5_PRIVATE>
 *//*
 \**************************************************************************/
 
 /*! \cidoxg_lib_citools */
#include "citools_internal.h"


int ci_copy_iovec(void* dest, int dest_len, ci_iovec_ptr* src)
{
  int total = 0, n;

  ci_assert(dest || dest_len == 0);
  ci_assert(dest_len >= 0);

  while( 1 ) {
    n = CI_MIN((int)CI_IOVEC_LEN(&src->io), dest_len);
    memcpy(dest, CI_IOVEC_BASE(&src->io), n);
    dest_len -= n;
    total += n;

    if( dest_len == 0 ) {
      CI_IOVEC_BASE(&src->io) = (char*)CI_IOVEC_BASE(&src->io) + n;
      CI_IOVEC_LEN(&src->io) -= n;
      return total;
    }

    /* Current segment of [src] is exhausted. */
    ci_assert_equal(n, (int)CI_IOVEC_LEN(&src->io));

    if( src->iovlen == 0 ) {
      CI_IOVEC_LEN(&src->io) = 0;
      return total;
    }

    dest = (char*) dest + n;
    --src->iovlen;
    src->io = *src->iov++;
  }
}

/*! \cidoxg_end */
