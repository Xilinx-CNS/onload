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


#ifndef  CI_LOG_PREFIX_DEFAULT 
# define CI_LOG_PREFIX_DEFAULT  "ci "
#endif

#ifndef  CI_LOG_LEVEL_DEFAULT 
# define CI_LOG_LEVEL_DEFAULT   1  /* critical */
#endif

#ifndef  CI_LOG_FN_DEFAULT
# define CI_LOG_FN_DEFAULT  ci_log_stderr
#endif

void (*ci_log_fn)(const char* msg) = CI_LOG_FN_DEFAULT;
int    ci_log_level                = CI_LOG_LEVEL_DEFAULT;
int    ci_log_options		   = 0;

const char* ci_log_prefix     = CI_LOG_PREFIX_DEFAULT;
static int ci_log_prefix_len = sizeof(CI_LOG_PREFIX_DEFAULT) - 1;


void ci_vlog_common(const char *prefix, size_t prefix_len, const char* fmt,
                    va_list args)
{
  int n = 0;
  char line[CI_LOG_MAX_LINE];

  ci_assert(fmt);

  if( ci_log_options ) {
#ifdef __KERNEL__
    if( ci_log_options & CI_LOG_CPU )
      n += ci_scnprintf(line + n, CI_LOG_MAX_LINE - n, "%d ",
                        (int) smp_processor_id());
    if( ci_log_options & CI_LOG_PID )
      n += ci_scnprintf(line + n, CI_LOG_MAX_LINE - n, "%d ",
                        in_interrupt() ? 0 : (int) current->tgid);
    if( ci_log_options & CI_LOG_TID )
      n += ci_scnprintf(line + n, CI_LOG_MAX_LINE - n, "%d ",
                        in_interrupt() ? 0: (int) current->pid);
#else
    if( ci_log_options & CI_LOG_PID )
      n += ci_scnprintf(line + n, CI_LOG_MAX_LINE - n, "%d ", (int) getpid());
    if( ci_log_options & CI_LOG_TID )
      n += ci_scnprintf(line + n, CI_LOG_MAX_LINE - n, "%lx ",
                        (long) pthread_self());
#endif
#ifdef CI_HAVE_FRC64
    if( ci_log_options & CI_LOG_TIME )
      n += ci_scnprintf(line + n, CI_LOG_MAX_LINE - n, "%010"CI_PRIu64" ",
                        (ci_uint64) (ci_frc64_get() & 0xffffffffffull));
#elif defined(CI_HAVE_FRC32)
    if( ci_log_options & CI_LOG_TIME )
      n += ci_scnprintf(line + n, CI_LOG_MAX_LINE - n, "%010u ",
                        (unsigned) ci_frc32_get());
#endif
    if( ci_log_options & CI_LOG_DELTA ) {
      static ci_uint32 prev = 0;
      ci_uint32 now = ci_frc32_get();
      n += ci_scnprintf(line + n, CI_LOG_MAX_LINE - n, "%06u ",
                        (unsigned) now - prev);
      prev = now;
    }
  }

  memcpy(line + n, prefix, prefix_len);
  vsnprintf(line + n + prefix_len,
	    CI_LOG_MAX_LINE - prefix_len - n, fmt, args);

  ci_log_fn(line);
}


void ci_vlog(const char* fmt, va_list args)
{
  ci_assert(ci_log_prefix);

  ci_vlog_common(ci_log_prefix, ci_log_prefix_len, fmt, args);
}


void ci_log(const char* fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  ci_vlog(fmt, args);
  va_end(args);
}

/* Wrapper to make ci_log conform to the signature of an oo_dump_log_fn_t. */
void ci_log_dump_fn(void* unused, const char* fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  ci_vlog(fmt, args);
  va_end(args);
}

/* Wrapper to make ci_log conform to the signature of an oo_dump_log_fn_t. */
void ci_log_dump_on_exit_fn(void* stack_id, const char* fmt, ...)
{
  va_list args;
  int id = *(int*)stack_id;
  char prefix[CI_LOG_MAX_LINE];

  snprintf(prefix, CI_LOG_MAX_LINE, "[onload] exit ni%d ", id);

  va_start(args, fmt);
  ci_vlog_common(prefix, strlen(prefix), fmt, args);
  va_end(args);
}


void ci_set_log_prefix(const char* prefix)
{
  if( !prefix ) {
    ci_log_prefix = CI_LOG_PREFIX_DEFAULT;
    ci_log_prefix_len = strlen(ci_log_prefix);
    return;
  }

  ci_assert(strlen(prefix) < CI_LOG_MAX_LINE);

  ci_log_prefix = prefix;

  ci_log_prefix_len = strlen(ci_log_prefix);
}


void ci_rlvlog(int* limit, const char* fmt, va_list args)
{
  if( *limit <= 0 )
    return;
  ci_vlog(fmt, args);
  if( --(*limit) == 0 )
    ci_log("... message limit reached");
}

void ci_rllog(int* limit, const char* fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  ci_rlvlog(limit, fmt, args);
  va_end(args);
}

/*! \cidoxg_end */
