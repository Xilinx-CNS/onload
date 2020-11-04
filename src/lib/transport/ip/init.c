/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include <onload/ul/per_thread.h>


/* By default, log anything unexpected that happens. */
unsigned ci_tp_log = CI_TP_LOG_DEFAULT;
unsigned ci_tp_max_dump = 80;


int ci_tp_init(citp_init_thread_callback cb, oo_exit_hook_fn hook)
{
  const char* s;

#ifndef NDEBUG
  static int done = 0;
  ci_assert(!done);
  done = 1;
#endif

  /*! ?? \TODO setup config options etc. */
  if( (s = getenv("TP_LOG")) )  sscanf(s, "%x", &ci_tp_log);
  LOG_S(log("TP_LOG = %x", ci_tp_log));

  init_thread_callback = cb;
  oo_per_thread_init();

  signal_exit_hook = hook;

  return 0;
}

/*! \cidoxg_end */
