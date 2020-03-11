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

/* actually problem isn't alpha, but old gcc version */
#if !defined(__KERNEL__) && defined(__GLIBC__)
# include <execinfo.h>
# include <unistd.h> /*??*/
#endif
#ifdef __KERNEL__
#include <linux/kernel.h>
#endif


#ifndef __KERNEL__
CI_NORETURN (*ci_fail_stop_fn)(void) = ci_fail_abort;
#else
CI_NORETURN (*ci_fail_stop_fn)(void) = ci_fail_bomb;
#endif


static void ci_backtrace_internal(int do_backtrace_if_kernel) {
# ifndef __KERNEL__
#  if defined(__GLIBC__)
  { /* produce a stack trace if possible */
    void* stack[15];
    int n = 15;
    n = backtrace(stack, n);
    backtrace_symbols_fd(stack, n, STDERR_FILENO);
  }
#  endif
# else
  /* Use the Linux kernel backtrace function */
  if( do_backtrace_if_kernel )
    dump_stack();
# endif
}


CI_NORETURN __ci_fail(const char* fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  if( fmt )  ci_vlog(fmt, args);
  va_end(args);

#ifndef __KERNEL__
  {
    char hostname[50];
    if( gethostname(hostname, 50) )  hostname[0] = '\0';
    ci_log("hostname=%s pid=%d", hostname, (int) getpid());
  }
#endif

  ci_backtrace_internal(0);  /* if kernel, don't want duplicate backtrace */
  ci_fail_stop_fn();
}


void ci_backtrace(void)
{
  ci_backtrace_internal(1);  /* always backtrace if we're called explicitly */
}

#ifndef __KERNEL__

CI_NORETURN ci_fail_exit(void)
{
  exit(-1);
}


CI_NORETURN ci_fail_hang(void)
{
  while( 1 )  sleep(1000);
}


CI_NORETURN ci_fail_stop(void)
{
  /* Halt entire process (not just this thread). */
  kill(getpid(), SIGSTOP);
  ci_fail_hang();
}
CI_NORETURN ci_fail_abort(void)
{
  abort();
}

#endif


#ifndef  CI_BOMB
# define CI_BOMB()  do{ *(volatile int*)0 = 0; }while(1)
#endif


CI_NORETURN ci_fail_bomb(void)
{
  CI_BOMB();
}

/*! \cidoxg_end */
