/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
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
# define CI_LOG_FN_DEFAULT  ci_log_stdout_nonl        //for this file giving the the function value: no new line
#endif


void ci_log_nonl(const char* fmt, ...)
{
  va_list args;
  //storing the previous value of ci_log_fn. so it can return back to previous function once this execution is done. 
  void (*ci_log_fn_tmp)(const char* msg)=ci_log_fn; 
  ci_log_fn=CI_LOG_FN_DEFAULT;
  va_start(args, fmt);
  ci_vlog(fmt, args);
  va_end(args);
  ci_log_fn = ci_log_fn_tmp; 
}

/*! \cidoxg_end */
