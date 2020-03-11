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


int ci_swallow_input(int fileno, int len_limit, char** buf_out, size_t* len_out)
{
  char* buf;
  char* p;
  int buf_len = 512;
  int rc;
  int n;

  ci_assert(buf_out);
  ci_assert(len_out);

  /* allocate a buffer first time around */
  p = buf = (char*) ci_alloc(buf_len);
  if( !p )  return -ENOMEM;

  while( 1 ) {
    if( p == buf + buf_len ) {
      int   new_len;
      char* new_buf;
      if( buf_len >= len_limit )  break;
      new_len = buf_len * 2;
      if( new_len > len_limit )  new_len = len_limit;
      new_buf = (char*) ci_alloc(new_len);
      if( !new_buf ) { rc = -ENOMEM; goto fail; }
      memcpy(new_buf, buf, p - buf);
      ci_free(buf);
      p = new_buf + (p - buf);
      buf = new_buf;
      buf_len = new_len;
    }

    n = read(fileno, p, buf + buf_len - p);
    if( n == 0 )  break;
    if( n < 0 ) {
      ci_log("ci_swallow_input: read(%d) failed (%d)", fileno, errno);
      rc = -errno;
      goto fail;
    }

    p += n;
  }

  *buf_out = buf;
  *len_out = p - buf;
  return 0;

 fail:
  ci_free(buf);
  return rc;
}

/*! \cidoxg_end */
