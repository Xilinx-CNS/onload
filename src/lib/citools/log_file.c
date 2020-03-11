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
  
/*! \cidoxg_lib_citools */

#include "citools_internal.h"
#include <sys/uio.h>

int  ci_log_file_fd = STDERR_FILENO;


void ci_log_file(const char* msg)
{
  struct iovec v[2];

  v[0].iov_base = (void*) msg;
  v[0].iov_len = strlen(msg);
  v[1].iov_base = "\n";
  v[1].iov_len = 1;

  writev(ci_log_file_fd, v, 2);
}

/*! \cidoxg_end */
