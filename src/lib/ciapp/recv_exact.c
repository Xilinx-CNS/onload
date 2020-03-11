/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Receive an exact number of bytes from a socket.
**   \date  2004/12/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>


int  ci_recv_exact(int sock, void* buf, size_t len, int flags)
{
  int n = 0, rc;

  ci_assert(buf);
  ci_assert(len >= 0);

  while( len ) {
    rc = recv(sock, buf, len, flags);
    if( rc <= 0 )  return n;

    buf = (char*) buf + rc;
    n += rc;
    len -= rc;
  }

  return n;
}

/*! \cidoxg_end */
