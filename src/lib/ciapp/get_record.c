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


int  ci_app_get_record(int fileno, void* buf, int buf_len, size_t* bytes_out)
{
  ci_uint32 rlen;
  int n;

  ci_assert(buf);
  ci_assert(buf_len > 0);
  ci_assert(bytes_out);

  n = ci_read_exact(fileno, &rlen, 4);
  if( n == 0 ) {
    *bytes_out = 0;
    return 0;
  }
  if( n != 4 )  return -1;

  rlen = CI_BSWAP_LE32(rlen);

  /* consume the record, and return error */
  if( (int) rlen > buf_len ) {
    while( rlen ) {
      n = read(fileno, buf, buf_len);
      if( n <= 0 )  break;
      rlen -= n;
    }
    return -E2BIG;
  }

  if( ci_read_exact(fileno, buf, rlen) != (int) rlen )  return -1;

  *bytes_out = rlen;
  return 0;
}

/*! \cidoxg_end */
