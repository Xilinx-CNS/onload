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
  char stack_s[INLINE_BUF_SIZE];
  char* s = stack_s;
  int i, n = 0, si, buf_size;

  /* We assume the caller ain't too worried about performance.  So we find
  ** out in advance whether we can format the string into [stack_s], or
  ** need to malloc() a buffer.
  */
  for( i = 0; i < FD_SETSIZE; ++i )
    if( FD_ISSET(i, fds) )  ++n;

  buf_size = n * 4 + 3;
  if( buf_size > INLINE_BUF_SIZE )
    /* Hope this doesn't fail... */
    CI_TEST(s = (char*) malloc(buf_size));

  si = snprintf(s, buf_size, "[");
  for( i = 0; i < FD_SETSIZE && si < buf_size; ++i )
    if( FD_ISSET(i, fds) )
      si += snprintf(s + si, buf_size - si, i ? " %d":"%d", i);

  ci_assert(si < buf_size);
  log_fn(s);

  if( s != stack_s )  free(s);
}

/*! \cidoxg_end */
