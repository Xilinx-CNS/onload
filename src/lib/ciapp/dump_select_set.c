/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Dump contents of select set.
**   \date  2005/01/12
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */
#include <ci/app.h>


#define INLINE_BUF_SIZE		256


void ci_dump_select_set(ci_log_fn_t log_fn, const fd_set* fds)
{
  char stack_s[256];
  char* s = stack_s;
  int i, n = 0, si;

  /* We assume the caller ain't too worried about performance.  So we find
  ** out in advance whether we can format the string into [stack_s], or
  ** need to malloc() a buffer.
  */
  for( i = 0; i < FD_SETSIZE; ++i )
    if( FD_ISSET(i, fds) )  ++n;

  if( n * 4 + 3 >= INLINE_BUF_SIZE )
    /* Hope this doesn't fail... */
    CI_TEST(s = (char*) malloc(n * 4 + 3));

  si = sprintf(s, "[");
  for( i = 0; i < FD_SETSIZE; ++i )
    if( FD_ISSET(i, fds) )
      si += sprintf(s + si, i ? " %d":"%d", i);

  ci_assert(s != stack_s || si < n * 4 + 3);
  log_fn(s);

  if( s != stack_s )  free(s);
}

/*! \cidoxg_end */
