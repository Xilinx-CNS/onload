/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>


int  ci_app_put_record(int fileno, const void* buf, int bytes)
{
  ci_uint32 rlen;

  ci_assert(buf);
  ci_assert(bytes >= 0);

  rlen = CI_BSWAP_LE32(bytes);
  if( ci_write_exact(fileno, &rlen, 4)   != 4 ||
      ci_write_exact(fileno, buf, bytes) != bytes )
    return -errno;

  return 0;
}

/*! \cidoxg_end */
