/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  sasha
**  \brief  Operations for signal interception
**   \date  2011/09/08
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/ip_signal.h>
#include <ci/internal/ip_log.h>
#include <linux/version.h>
#include <ci/internal/transport_common.h>
#include <ci/internal/efabcfg.h>

#ifdef __KERNEL__
#error "Non-kernel file"
#endif

/*! Signal handlers storage.  Indexed by signum-1.
 * Read by UL, written by kernel only. */
struct oo_sigaction citp_signal_data[NSIG];




/*! Run a signal handler
** \param  signum   Signal number
** \param  info     Saved info for sa_sigaction handler
** \param  context  Saved context for sa_sigaction handler
** \return sa_restart flag value
*/
static int
citp_signal_run_app_handler(int sig, siginfo_t *info, void *context)
{
  struct oo_sigaction *p_data = &citp_signal_data[sig-1];
  struct oo_sigaction act;
  ci_int32 type1, type2;
  int ret;
  sa_sigaction_t handler;

  do {
    type1 = p_data->type;
    act = *p_data;
    type2 = p_data->type;
  } while( type1 != type2 ||
           (type1 & OO_SIGHANGLER_TYPE_MASK) == OO_SIGHANGLER_BUSY );

  /* When the signal was delivered and set pending, it was intercepted.
   * Now it is not.
   * It is possible if, for example, user-provided handler is replaced by
   * SIG_DFL for SIGABORT.
   *
   * We just run old handler in this case, so we drop
   * OO_SIGHANGLER_IGN_BIT.
   */

  ret = act.flags & SA_RESTART;
  LOG_SIG(log("%s: signal %d type %d run handler %p flags %x",
              __FUNCTION__, sig, act.type, CI_USER_PTR_GET(act.handler),
              act.flags));

  handler = CI_USER_PTR_GET(act.handler);
  ci_assert(handler);
  ci_assert_nequal(handler, citp_signal_intercept);
  ci_assert(info);
  ci_assert(context);

  /* If sighandler was reset because of SA_ONESHOT, we should properly
   * handle termination.
   * Also, signal flags possibly differs from the time when kernel was
   * running the sighandler: so, we should ensure that ONESHOT shoots
   * only once. */
  if( (act.flags & SA_ONESHOT) &&
      act.type == citp_signal_data[sig-1].type ) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = act.flags &~ SA_ONESHOT;
    sigaction(sig, &sa, NULL);
    LOG_SIG(log("%s: SA_ONESHOT fixup", __func__));
  }

  if( (act.type & OO_SIGHANGLER_TYPE_MASK) != OO_SIGHANGLER_USER ||
      (act.flags & SA_SIGINFO) ) {
    (*handler)(sig, info, context);
  } else {
    __sighandler_t handler1 = (void *)handler;
    (*handler1)(sig);
  }
  LOG_SIG(log("%s: returned from handler for signal %d: ret=%x", __FUNCTION__,
              sig, ret));

  return ret;
}


/*! Run any pending signal handlers
** \param  our_info  Thread-specific context for current thread
*/
void citp_signal_run_pending(citp_signal_info *our_info)
{
  /* preserve errno across calls to this function, as it's often
     called at error time as a result of EXIT_LIB */
  int old_errno = errno;
  int i;

  LOG_SIG(log("%s: start", __FUNCTION__));
  ci_wmb();
  ci_assert(our_info->c.aflags & OO_SIGNAL_FLAG_HAVE_PENDING);

  ci_atomic32_and(&our_info->c.aflags, ~OO_SIGNAL_FLAG_HAVE_PENDING);
  for( i = 0; i < OO_SIGNAL_MAX_PENDING; i++ ) {
    siginfo_t saved_info;
    void *saved_context;
    int signum;

    if (our_info->signals[i].signum == 0)
      break;

    saved_context = our_info->signals[i].saved_context;
    if( our_info->signals[i].saved_context )
      memcpy(&saved_info, &our_info->signals[i].saved_info,
             sizeof(saved_info));
    signum = our_info->signals[i].signum;
    if( ci_cas32_fail(&our_info->signals[i].signum, signum, 0) )
      break;

    /* Segfault in Onload code (such as ci_assert) violate this assertion,
     * so we check for SIGSEGV here. */
    if( signum != SIGABRT && signum != SIGSEGV )
      ci_assert_equal(our_info->c.inside_lib, 0);

    if( citp_signal_run_app_handler(
                signum,
                saved_context == NULL ? NULL : &saved_info,
                saved_context) )
      ci_atomic32_or(&our_info->c.aflags, OO_SIGNAL_FLAG_NEED_RESTART);
    else
      ci_atomic32_and(&our_info->c.aflags, ~OO_SIGNAL_FLAG_NEED_RESTART);
  }
  LOG_SIG(log("%s: end", __FUNCTION__));
  errno = old_errno;
}


/*! Mark a signal as pending.
 * Should be called from signal handler only.
 *
** \param  signum   Signal number
** \param  info     Saved info for sa_sigaction handler
** \param  context  Saved context for sa_sigaction handler
** \param  our_info Our signal info
*/
ci_inline void citp_signal_set_pending(int signum, siginfo_t *info,
                                       void *context,
                                       citp_signal_info *our_info)
{
  int i;

  ci_assert(our_info->c.inside_lib);

  for( i = 0; i < OO_SIGNAL_MAX_PENDING; i++ ) {
    if( our_info->signals[i].signum )
      continue;
    if( ci_cas32_fail(&our_info->signals[i].signum, 0, signum) )
      continue;
    LOG_SIG(log("%s: signal %d pending", __FUNCTION__, signum));
    ci_assert(info);
    ci_assert(context);
    memcpy(&our_info->signals[i].saved_info, info, sizeof(siginfo_t));
    our_info->signals[i].saved_context = context;

    /* Hack: in case of SA_ONESHOT, make sure that we intercept
     * the signal.  At the end of citp_signal_run_app_handler,
     * we will reset the signal handler properly. */
    if( citp_signal_data[signum-1].flags & SA_ONESHOT )
      sigaction(signum, NULL, NULL);

    ci_atomic32_or(&our_info->c.aflags, OO_SIGNAL_FLAG_HAVE_PENDING);
    return;
  }

  log("%s: no empty slot to set pending signal %d", __FUNCTION__, signum);
}

/*! Run signal handler immediatedly, just now.
** \param  signum   Signal number
** \param  info     Saved info for sa_sigaction handler
** \param  context  Saved context for sa_sigaction handler
** \param  our_info Our signal info
*/
ci_inline void citp_signal_run_now(int signum, siginfo_t *info,
                                   void *context,
                                   citp_signal_info *our_info)
{
  int need_restart;

  LOG_SIG(log("%s: SIGNAL %d - run immediately", __FUNCTION__, signum));

  /* Try to keep order: old signals first, and need_restart is from the
   * last one */
  if (our_info && (our_info->c.aflags & OO_SIGNAL_FLAG_HAVE_PENDING))
    citp_signal_run_pending(our_info);

  need_restart = citp_signal_run_app_handler(signum, info, context);

  /* Set need_restart flag in accordance with sa_restart.
   * The last signal wins, so we set need_restart to 1 if necessary.
   */
  if (our_info) {
    LOG_SIG(log("%s: SIGNAL %d - set need restart flag to %d", __FUNCTION__,
                signum, need_restart));
    if( need_restart )
      ci_atomic32_or(&our_info->c.aflags, OO_SIGNAL_FLAG_NEED_RESTART);
    else
      ci_atomic32_and(&our_info->c.aflags, ~OO_SIGNAL_FLAG_NEED_RESTART);
  }
}

/*! Handler we register for sigaction() sa_sigaction interception
** \param  signum   Signal number
** \param  info     Additional information passed in by the kernel
** \param  context  Context passed in by the kernel
*/
void citp_signal_intercept(int signum, siginfo_t *info, void *context)
{
  citp_signal_info *our_info = citp_signal_get_specific_inited();
  LOG_SIG(log("%s(%d, %p, %p) %smasked", __func__,
              signum, info, context,
              CITP_OPTS.signals_no_postpone & (1 << (signum-1)) ? "" : "not "));
  /* Note: our thread-specific data is initialised on the way in to the our
   * library if necessary, so if our_info is NULL, we can assume that this
   * thread is not currently running inside the library.  (This can happen
   * if a signal is delivered to a thread which has been created after the
   * intercept handler has been installed, but before that thread uses any
   * of the interposing library functions.)
   */
  if (our_info && our_info->c.inside_lib &&
      (CITP_OPTS.signals_no_postpone & (1 << (signum-1))) == 0)
    citp_signal_set_pending(signum, info, context, our_info);
  else
    citp_signal_run_now(signum, info, context, our_info);
}

/* SIG_DFL simulator for signals like SIGINT, SIGTERM: it is postponed
 * properly to safe shared stacks. */
static void citp_signal_terminate(int signum, siginfo_t *info, void *context)
{
  int fd;
  int rc;

  /* get any Onload fd to call ioctl */
  rc = ef_onload_driver_open(&fd, OO_STACK_DEV, 1);

  /* Die now:
   * _exit sets incorrect status in waitpid(), so we should try to exit via
   * signal.  Use _exit() if there is no other way. */
  if( rc == 0 )
    oo_resource_op(fd, OO_IOC_DIE_SIGNAL, &signum);
  else
    _exit(128 + signum);
}

/*! sa_restorer used by libc (SA_SIGINFO case!) */
static void *citp_signal_sarestorer;
static int citp_signal_sarestorer_inited = 0;

#ifndef SA_RESTORER
/* kernel+libc keep it private, but we need it */
#define SA_RESTORER 0x04000000
#endif
/* Get sa_restorer which is set by libc. */
void *citp_signal_sarestorer_get(void)
{
  int sig = SIGINT;
  struct sigaction act;
  int rc;

  if( citp_signal_sarestorer_inited )
    return citp_signal_sarestorer;

  LOG_SIG(log("%s: citp_signal_intercept=%p",
              __func__, citp_signal_intercept));
  LOG_SIG(log("%s: citp_signal_terminate=%p", __func__, 
              citp_signal_terminate));
  for( sig = 1; sig < _NSIG; sig++ ) {
    LOG_SIG(log("find sa_restorer via signal %d", sig));
    /* If the handler was already set by libc, we get sa_restorer just now */
    rc = sigaction(sig, NULL, &act);
    if( rc != 0 )
      continue;
    if( act.sa_restorer != NULL && (act.sa_flags & SA_SIGINFO) ) {
      citp_signal_sarestorer = act.sa_restorer;
      LOG_SIG(ci_log("%s: initially citp_signal_sarestorer=%p", __func__,
                     citp_signal_sarestorer));
      citp_signal_sarestorer_inited = 1;
      return citp_signal_sarestorer;
    }

    /* Do not set SA_SIGINFO for user handlers! */
    if( act.sa_handler != SIG_IGN && act.sa_handler != SIG_DFL )
      continue;

    LOG_SIG(ci_log("%s: non-siginfo sa_restorer=%p", __func__,
                   act.sa_restorer));
    /* Let's go via libc and set sa_restorer */
    act.sa_flags |= SA_SIGINFO;
    rc = sigaction(sig, &act, NULL);
    if( rc != 0 )
      continue;
    /* And now we get sa_restorer as it was set by libc! */
    rc = sigaction(sig, NULL, &act);
    if( rc == 0 ) {
      citp_signal_sarestorer_inited = 1;
      LOG_SIG(ci_log("%s: set/get flags %x citp_signal_sarestorer=%p",
                     __func__, act.sa_flags, act.sa_restorer));
      if( !(act.sa_flags & SA_RESTORER) )
        return NULL;
      citp_signal_sarestorer = act.sa_restorer;
      return citp_signal_sarestorer;
    }
  }

  return NULL;
}

/*! Our signal handlers for various interception types */
sa_sigaction_t citp_signal_handlers[OO_SIGHANGLER_DFL_MAX+1] = {
  citp_signal_terminate  /*OO_SIGHANGLER_TERM*/,
  NULL, /*OO_SIGHANGLER_STOP - do not break gdb! */
  citp_signal_terminate /*OO_SIGHANGLER_CORE*/
};



int oo_spinloop_run_pending_sigs(ci_netif* ni, citp_waitable* w,
                                 citp_signal_info* si, int have_timeout)
{
  int inside_lib;
  if( have_timeout )
    return -EINTR;
  if( w )
    ci_sock_unlock(ni, w);
  inside_lib = si->c.inside_lib;
  si->c.inside_lib = 0;
  ci_compiler_barrier();
  citp_signal_run_pending(si);
  si->c.inside_lib = inside_lib;
  ci_compiler_barrier();
  if( w )
    ci_sock_lock(ni, w);
  if( ~si->c.aflags & OO_SIGNAL_FLAG_NEED_RESTART )
    /* handler sets need_restart, exit if no restart is necessary */
    return -EINTR;
  return 0;
}


/*! \cidoxg_end */
