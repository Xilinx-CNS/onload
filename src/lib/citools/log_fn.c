/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
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

#include <syslog.h>
#include <sys/uio.h>


void ci_log_stderr(const char* msg)
{
  struct iovec v[2];

  v[0].iov_base = (void*) msg;
  v[0].iov_len = strlen(msg);
  v[1].iov_base = (char*) "\n";
  v[1].iov_len = 1;

  writev(STDERR_FILENO, v, 2);
}


void ci_log_stdout(const char* msg)
{
  struct iovec v[2];

  v[0].iov_base = (void*) msg;
  v[0].iov_len = strlen(msg);
  v[1].iov_base = (char*) "\n";
  v[1].iov_len = 1;

  writev(STDOUT_FILENO, v, 2);
}

/*this function acts like configuration for ci_log_fn: no new line (works like printf)*/
void ci_log_stdout_nonl(const char* msg)
{
  struct iovec v[1];
  v[0].iov_base = (void*) msg;
  v[0].iov_len = strlen(msg);

  writev(STDOUT_FILENO, v, 1);
}

void ci_log_syslog(const char* msg)
{
  syslog(LOG_INFO, "%s\n", msg);
}


void ci_log_null(const char* msg)
{
}

/*! \cidoxg_end */
