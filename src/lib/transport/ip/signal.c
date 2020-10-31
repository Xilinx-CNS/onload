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
#include <ci/internal/transport_common.h>
#include <ci/internal/efabcfg.h>

#ifdef __KERNEL__
#error "Non-kernel file"
#endif

struct oo_sigstore {
  ci_uint32 seq;
#define OO_SIGSTORE_BUSY        0x80000000
  struct sigaction act[2]; /* use act[seq&1] */
};

/*! Signal handlers storage.  Indexed by signum-1. */
struct oo_sigstore sigstore[_NSIG];

static void citp_signal_intercept(int signum, siginfo_t *info, void *context);

static void oo_get_sigaction(int sig, struct sigaction* sa)
{
  struct oo_sigstore* store = &sigstore[sig - 1];
  ci_uint32 seq;
  ci_uint32 seq1 = OO_ACCESS_ONCE(store->seq);

  do {
    seq = seq1;
    memcpy(sa, &store->act[seq & 1], sizeof(*sa));
    ci_rmb();
  } while( (seq1 = OO_ACCESS_ONCE(store->seq)) != seq );
}

/* Get a write lock: set the OO_SIGSTORE_BUSY flag */
static int oo_signal_write_lock(int sig, ci_uint32* seq_p)
{
  struct oo_sigstore* store = &sigstore[sig - 1];
  ci_uint32 seq;
  int i = 0;

  do {
    seq = OO_ACCESS_ONCE(store->seq);
    if( seq & OO_SIGSTORE_BUSY ) {
      if( i++ > 1000000 ) {
        ci_log("ERROR: can't set a new signal handler for signal %d", sig);
        return -EBUSY;
      }
      ci_spinloop_pause();
    }
  } while( ci_cas32u_fail(&store->seq, seq, seq | OO_SIGSTORE_BUSY) );

  *seq_p = seq;
  return 0;
}

static void oo_signal_write_unlock(int sig, ci_uint32 seq)
{
  struct oo_sigstore* store = &sigstore[sig - 1];
  ci_assert_equal(seq | OO_SIGSTORE_BUSY, store->seq);
  ci_wmb();
  OO_ACCESS_ONCE(store->seq) = (seq + 1) & ~OO_SIGSTORE_BUSY;
}


/*! Run a signal handler
** \param  signum   Signal number
** \param  info     Saved info for sa_sigaction handler
** \param  context  Saved context for sa_sigaction handler
** \return sa_restart flag value
*/
static int
citp_signal_run_app_handler(int sig, siginfo_t *info, void *context)
{
  struct sigaction act;
  int ret;

  oo_get_sigaction(sig, &act);

  ret = act.sa_flags & SA_RESTART;
  ci_assert_nequal(act.sa_sigaction, citp_signal_intercept);
  ci_assert(info);
  ci_assert(context);

  LOG_SIG(log("%s: signal %d run handler %p flags %x",
              __FUNCTION__, sig, act.sa_handler, act.sa_flags));

  if( act.sa_flags & SA_ONESHOT ) {
    struct sigaction sa;
    int rc;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sa.sa_mask = act.sa_mask;
    rc = oo_do_sigaction(sig, &sa, NULL);
    LOG_SIG(log("%s: SA_ONESHOT fixup", __func__));
    if( rc != 0 ) {
      ci_log("ERROR: faild to reset signal %d with SA_ONESHOT: %d", sig, rc);
      ci_assert(0);
    }
  }

  if( act.sa_flags & SA_SIGINFO )
    (*act.sa_sigaction)(sig, info, context);
  else
    (*act.sa_handler)(sig);

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
static void citp_signal_intercept(int signum, siginfo_t *info, void *context)
{
  citp_signal_info *our_info = citp_signal_get_specific_inited();
  LOG_SIG(log("%s(%d, %p, %p)", __func__, signum, info, context));
  /* Note: our thread-specific data is initialised on the way in to the our
   * library if necessary, so if our_info is NULL, we can assume that this
   * thread is not currently running inside the library.  (This can happen
   * if a signal is delivered to a thread which has been created after the
   * intercept handler has been installed, but before that thread uses any
   * of the interposing library functions.)
   */
  if( our_info && our_info->c.inside_lib )
    citp_signal_set_pending(signum, info, context, our_info);
  else
    citp_signal_run_now(signum, info, context, our_info);
}

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

#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__)
#define SA_RESTORER 0x04000000

static void* oo_saved_restorer = NULL;

/* Appease the Socket Tester, mimic glibc: report SA_RESTORER. */
static void oo_fixup_oldact(int sig, struct sigaction *oldact)
{
  oldact->sa_flags |= 0x04000000;
  if( oo_saved_restorer == NULL ) {
    struct sigaction s;
    ci_sys_sigaction(sig, NULL, &s);
    oo_saved_restorer = s.sa_restorer;
  }
  oldact->sa_restorer = oo_saved_restorer;

}
#else
#define oo_fixup_oldact(sig, oldact)
#define SA_RESTORER 0
#endif


bool oo_is_signal_intercepted(int sig, void* handler)
{
  if( CITP_OPTS.signals_no_postpone & (1 << (sig-1)) )
    return false;
  if( handler == SIG_IGN || handler == SIG_ERR )
    return false;
  if( handler != SIG_DFL )
    return true;

  /* We'll intercept termonating SIG_DFL in the next patches */
  return false;
}

static int
oo_signal_install_to_onload(int sig, const struct sigaction *act,
                            struct sigaction *oldact)
{
  struct oo_sigstore* store = &sigstore[sig - 1];
  ci_uint32 seq;
  int rc;

  rc = oo_signal_write_lock(sig, &seq);
  if( rc != 0 ) {
    ci_log("ERROR: %s(%d) failed to lock signal store", __func__, sig);
    return rc;
  }
  LOG_SIG(ci_log("%s(%d): new handler %p seq %x",
                 __func__, sig, act ? act->sa_handler : (void*)-1, seq));

  if( oldact != NULL )
    memcpy(oldact, &store->act[seq & 1], sizeof(*oldact));
  if( act != NULL )
    memcpy(&store->act[! (seq & 1)], act, sizeof(*act));
  else
    store->act[! (seq & 1) ].sa_handler = SIG_DFL;
  oo_signal_write_unlock(sig, seq);

  return 0;
}

static int
oo_signal_install_to_os(int sig, const struct sigaction *act,
                        void* oo_handler, struct sigaction *oldact)
{
  int rc;
  struct sigaction new;

  ci_assert(act);

  new.sa_flags = (act->sa_flags | SA_SIGINFO) & ~(SA_RESETHAND | SA_RESTORER);
  new.sa_sigaction = oo_handler;
  new.sa_mask = act->sa_mask;
  LOG_SIG(ci_log("%s(%d): intercept with "OO_PRINT_SIGACTION_FMT,
                 __func__, sig, OO_PRINT_SIGACTION_ARG(&new)));

  /* We want to intercept SIGCANCEL, so can't use libc's wrapper for the
   * syscall.
   */
  rc = ci_sys_sigaction(sig, &new, oldact);
  LOG_SIG(ci_log("%s: rc=%d: signal %d intercept now "OO_PRINT_SIGACTION_FMT,
                 __func__, rc, sig, OO_PRINT_SIGACTION_ARG(act)));
  return rc;
}

/*! Do all the processing for interception of signal()
** \param  signum   Signal number
** \param  act      Pointer to requested action, or NULL
** \param  oldact   Pointer to storage for previous action, or NULL
** \return          0 for success, -1 for failure
*/
int oo_do_sigaction(int sig, const struct sigaction *act,
                    struct sigaction *oldact)
{
  struct sigaction old;
  int rc = 0;

  if( sig < 0 || sig >= _NSIG ) {
    errno = EINVAL;
    return -1;
  }

  /* Read only: fast exit */
  if( act == NULL ) {
    if( oldact == NULL )
      return 0;
    oo_get_sigaction(sig, oldact);
    LOG_SIG(ci_log("%s(%d) read-only sa_handler=%p",
                   __func__, sig, oldact->sa_handler));
    if( oldact->sa_handler != SIG_DFL ) {
      oo_fixup_oldact(sig, oldact);
      return 0;
    }
    return ci_sys_sigaction(sig, NULL, oldact);
  }

  /* Are we going to intercept this signal? */
  if( ! oo_is_signal_intercepted(sig, act->sa_handler) ) {
    rc = ci_sys_sigaction(sig, act, &old);
    LOG_SIG(ci_log("%s: rc=%d: do not intercept signal %d "
                   OO_PRINT_SIGACTION_FMT,
                   __func__, rc, sig, OO_PRINT_SIGACTION_ARG(act)));
    if( rc != 0 )
      return rc;

    /* Was the signal not intercepted previously?
     * Should we look up our old handler?
     */
    if( old.sa_sigaction != citp_signal_intercept ) {
      LOG_SIG(ci_log("%s: rc=%d: continue passthrough for signal %d "
                     OO_PRINT_SIGACTION_FMT,
                     __func__, rc, sig, OO_PRINT_SIGACTION_ARG(act)));
      if( oldact )
        memcpy(oldact, &old, sizeof(old));
      return rc;
    }


    /* The signal was intercepted, and now it is not.  Mark it in the
     * store.
     */
    rc = oo_signal_install_to_onload(sig, NULL, oldact);
    if( rc < 0 )
      return rc;
    if( oldact )
      oo_fixup_oldact(sig, oldact);
    return 0;
  }

  /* Install a new Onload-intercepted handler. */
  rc = oo_signal_install_to_onload(sig, act, &old);
  if( rc < 0 )
    return rc;

  /* If we were not intercepting this signal previously, then we have to
   * install Onload handler to OS and pass oldact from OS to user.
   */
  if( old.sa_handler == SIG_DFL )
    return oo_signal_install_to_os(sig, act, citp_signal_intercept, oldact);

  /* We should call kernel's sigaction if:
   * - the signal was intercepted, but with different SA_* flags
   *   (except for SA_SIGINFO);
   * - the signal was intercepted, but with a different sa_mask.
   */
  if( ((act->sa_flags ^ old.sa_flags) & ~SA_SIGINFO) != 0 ||
      memcmp(&act->sa_mask, &old.sa_mask, sizeof(old.sa_mask)) != 0 ) {
    rc = oo_signal_install_to_os(sig, act, citp_signal_intercept, NULL);
  }
  if( oldact != NULL ) {
    memcpy(oldact, &old, sizeof(old));
    oo_fixup_oldact(sig, oldact);
  }

  return rc;
}
