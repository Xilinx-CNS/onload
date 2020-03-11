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

#ifndef  CI_LOG_FN_DEFAULT
# define CI_LOG_FN_DEFAULT  ci_log_stderr
#endif

void (*__ci_log_nth_fn)(const char* msg) = CI_LOG_FN_DEFAULT;
int  ci_log_nth_n = 100;


void __ci_log_nth(const char* msg)
{
  static int n = 0;

  /* Avoid the obvious loop.  Other loops possible though... */
  if( __ci_log_nth_fn == ci_log_fn )  return;

  if( n % ci_log_nth_n == 0 )  __ci_log_nth_fn(msg);
  ++n;
}

/*! \cidoxg_end */
