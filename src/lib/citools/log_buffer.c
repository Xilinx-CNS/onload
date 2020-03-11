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

/*
** To setup logging to the log buffer call: ci_log_buffer_till_fail()
** To dump the contents of the buffer call: ci_log_buffer_dump()
** NB: kernel asserts, if it can't allocate the buffer as a single block,
**     hence, use small MAX_LINES if used from kernel
*/

#include "citools_internal.h"


#define MAX_LINES   10000


static char** log_buf;
static int  log_buf_i = 0;
static void (*real_log_fn)(const char* msg) = 0;
static CI_NORETURN (*real_stop_fn)(void) = 0;


static void my_log_fn(const char* msg)
{
  strcpy(log_buf[log_buf_i], msg);
  log_buf_i = (log_buf_i + 1) % MAX_LINES;
}


extern void ci_log_buffer_dump(void)
{
  int i = log_buf_i;

  do {
    if( log_buf[i][0] ) {
      real_log_fn(log_buf[i]);
      log_buf[i][0] = '\0';
    }
    i = (i + 1) % MAX_LINES;
  }
  while( i != log_buf_i );
}


static CI_NORETURN my_stop_fn(void)
{
  ci_log_buffer_dump();
  real_stop_fn();
}


extern void ci_log_buffer_till_fail(void)
{
  int i;

  if( real_log_fn )  return;

  CI_TEST(log_buf = CI_ALLOC_ARRAY(char*, MAX_LINES));
  CI_TEST(log_buf[0] = CI_ALLOC_ARRAY(char, CI_LOG_MAX_LINE * MAX_LINES));
  for( i = 0; i < MAX_LINES; ++i ) {
    log_buf[i] = log_buf[0] + i * CI_LOG_MAX_LINE;
    log_buf[i][0] = '\0';
  }

  real_log_fn = ci_log_fn;
  real_stop_fn = ci_fail_stop_fn;
  ci_log_fn = my_log_fn;
  ci_fail_stop_fn = my_stop_fn;
}


#ifndef __KERNEL__
static void at_exit_fn(void)
{
  ci_log_buffer_dump();
}


void ci_log_buffer_till_exit(void)
{
  if( real_log_fn )  return;

  ci_log_buffer_till_fail();
  atexit(at_exit_fn);
}
#endif

/*! \cidoxg_end */
