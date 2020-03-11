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


int ci_write_exact(int fileno, const void* buf, int bytes)
{
  int n = 0, rc;

  ci_assert(buf);
  ci_assert(bytes >= 0);

  while( bytes ) {
    rc = write(fileno, buf, bytes);
    if( rc <= 0 )  return n;

    buf = (const char*) buf + rc;
    n += rc;
    bytes -= rc;
  }

  return n;
}

/*! \cidoxg_end */
