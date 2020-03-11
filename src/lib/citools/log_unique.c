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


#ifndef __KERNEL__
/* __ci_log_unique uses a lot of stack, and it should be rewritten if
 * it is to be used from the Linux kernel */

#define MAX_REPEAT_LINES  3
#define RBUF_SIZE         (MAX_REPEAT_LINES * 2)

#ifndef  CI_LOG_FN_DEFAULT
# define CI_LOG_FN_DEFAULT  ci_log_stderr
#endif

void (*__ci_log_unique_fn)(const char* msg) = CI_LOG_FN_DEFAULT;


static char rbuf[RBUF_SIZE][CI_LOG_MAX_LINE];

static int rbuf_i = 0;
static int loop_i;
static int loop_size;
static int loop_iter;
static int loop_iter_print = 1;

#define STATE_NONE   0
#define STATE_MEBBE  1
#define STATE_LOOP   2
static int state = STATE_NONE;


void __ci_log_unique(const char* msg)
{
  /* ?? Currently detects the shortest loop.  eg. abaabaabaaba: it detects
  ** the aa repeats, but not the aba repeats, so keeps jumping out of loop
  ** mode.
  */
  char tmps[CI_LOG_MAX_LINE]; /* TODO possible stack overflow */
  int i;

  ci_assert(msg);
  ci_assert(strlen(msg) < CI_LOG_MAX_LINE);

  /* Avoid the obvious loop.  Other loops possible though... */
  if( __ci_log_unique_fn == ci_log_fn )  return;

  /* ?? could really do with locking here. */

  if( state != STATE_LOOP ) {
    strcpy(rbuf[rbuf_i], msg);
    __ci_log_unique_fn(msg);
  }

  switch( state ) {
  case STATE_MEBBE:
    i = (rbuf_i + RBUF_SIZE - loop_size) % RBUF_SIZE;
    if( !strcmp(msg, rbuf[i]) ) {
      if( --loop_i == 0 ) {
	state = STATE_LOOP;
	rbuf_i = (rbuf_i + 1 + RBUF_SIZE - loop_size) % RBUF_SIZE;
	sprintf(tmps, "%sLOOP DETECTED (%d)", ci_log_prefix, loop_size);
	__ci_log_unique_fn(tmps);
	return;
      }
      break;
    }
    state = STATE_NONE;
    /* Fall through to look for new loop... */

  case STATE_NONE:
    for( loop_size = 1; loop_size <= MAX_REPEAT_LINES; ++loop_size ) {
      i = (rbuf_i + RBUF_SIZE - loop_size) % RBUF_SIZE;
      if( !strcmp(msg, rbuf[i]) ) {
	loop_i = loop_size - 1;
	if( loop_size == 1 ) {
	  state = STATE_LOOP;
	  sprintf(tmps, "%sLOOP DETECTED (1)", ci_log_prefix);
	  __ci_log_unique_fn(tmps);
	  return;
	}
	state = STATE_MEBBE;
	break;
      }
    }
    break;

  case STATE_LOOP:
    i = (rbuf_i + loop_i) % RBUF_SIZE;
    if( strcmp(msg, rbuf[i]) ) {
      /* Dump out the partial loop. */
      for( i = 0; i < loop_i; ++i )
	__ci_log_unique_fn(rbuf[(rbuf_i + i) % RBUF_SIZE]);
      loop_iter = 0;
      loop_iter_print = 1;
      state = STATE_NONE;
      rbuf_i = (rbuf_i + loop_size) % RBUF_SIZE;
      strcpy(rbuf[rbuf_i], msg);
      __ci_log_unique_fn(msg);
      break;
    }
    loop_i = (loop_i + 1) % loop_size;
    if( loop_i == 0 ) {
      ++loop_iter;
      if( loop_iter >= loop_iter_print ) {
	sprintf(tmps, "%sLOOP: %d", ci_log_prefix, loop_iter);
	__ci_log_unique_fn(tmps);
	loop_iter_print *= 2;
      }
    }
    return;
  }

  rbuf_i = (rbuf_i + 1) % RBUF_SIZE;
}
#endif

/*! \cidoxg_end */
