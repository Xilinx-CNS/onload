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

#if ! CI_CFG_USERSPACE_SYSCALL
#define ci_sys_syscall syscall
#endif

struct oo_sigstore {
  ci_uint32 seq;
#define OO_SIGSTORE_BUSY        0x80000000
  struct sigaction act[2]; /* use act[seq&1] */
  bool libc_safe; /* Does libc allow user to change handler? */
};

/*! Signal handlers storage.  Indexed by signum-1. */
struct oo_sigstore sigstore[_NSIG];

#if defined(__x86_64__)
#define SA_RESTORER 0x04000000
#define USE_SA_RESTORER
static void* oo_saved_restorer = NULL;
#elif defined(__i386__) || defined(__aarch64__)
/* In theory i386 & aarch64 have SA_RESTORER.  But it is not used for
 * dynamically-linked binaries; DSO is used instead.  However we must
 * remove SA_RESTORER flag when reusing user's flags with a different
 * handler, so we need to know the value.
 */
#define SA_RESTORER 0x04000000
#else
#error Does this architecture use SA_RESTORER?
#endif


static void citp_signal_intercept(int signum, siginfo_t *info, void *context);

static void oo_get_sigaction(int sig, struct sigaction* sa)
{
  struct oo_sigstore* store = &sigstore[sig - 1];
  ci_uint32 seq;
  ci_uint32 seq1 = OO_ACCESS_ONCE(store->seq);

  memset(sa, 0, sizeof(*sa));
  do {
    seq = seq1;
    *sa = store->act[seq & 1];
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
    sa.sa_flags = act.sa_flags & ~(SA_RESTORER | SA_ONESHOT);
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


/* We'd like to intercept all signals including SIGCANCEL.
 * Libc does not allow it, so we use a direct syscall.
 * Infortunately we have to re-pack the sigaction structure.
 */
#define SA_MASK_WORDS (_NSIG / 8 / sizeof(unsigned long))
struct kernel_sigaction {
  __sighandler_t    k_handler;
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__)
  unsigned long     k_flags;
  void*             k_restorer;
  unsigned long     k_mask[SA_MASK_WORDS];
#else
#error Please define kernel_sigaction for this architecture
#endif
};

static int oo_syscall_sigaction(int sig, const struct sigaction* user_act,
                                struct sigaction* user_oldact)
{
  struct kernel_sigaction act, oldact;
  int rc;

  if( user_act ) {
    act.k_flags = user_act->sa_flags;
    act.k_handler = user_act->sa_handler;
    memcpy(&act.k_mask, &user_act->sa_mask, sizeof(act.k_mask));
#ifdef USE_SA_RESTORER
    act.k_restorer = oo_saved_restorer;
    act.k_flags |= SA_RESTORER;
#endif
  }
  rc = ci_sys_syscall(__NR_rt_sigaction, sig, user_act ? &act : NULL,
                      user_oldact ? &oldact : NULL, _NSIG / 8);
  if( user_oldact ) {
    user_oldact->sa_flags = oldact.k_flags;
    user_oldact->sa_handler = oldact.k_handler;
    memcpy(&user_oldact->sa_mask, &oldact.k_mask, sizeof(oldact.k_mask));
    user_oldact->sa_restorer = oldact.k_restorer;
  }

  return rc;
}

static int oo_libc_sigaction(int sig, const struct sigaction* user_act,
                             struct sigaction* user_oldact)
{
  int rc = ci_sys_sigaction(sig, user_act, user_oldact);
  if( rc != 0 )
    return rc;

  if( ! sigstore[sig - 1].libc_safe )
    sigstore[sig - 1].libc_safe = true;
  return 0;
}


oo_exit_hook_fn signal_exit_hook;

static void oo_signal_terminate(int signum)
{
  struct sigaction act = { };

  LOG_SIG(ci_log("%s(%d)", __func__, signum));
  signal_exit_hook();

  /* Set SIGDFL and trigger it */
  oo_syscall_sigaction(signum, &act, NULL);
  ci_sys_syscall(__NR_tgkill, getpid(), ci_sys_syscall(__NR_gettid), signum);
}
static void oo_signal_terminate_siginfo(int signum,
                                        siginfo_t *info, void *context)
{
  oo_signal_terminate(signum);
}


/* Convert the sigaction from our store to what the user expects to see */
static void oo_fixup_oldact(struct sigaction *oldact)
{
  if( oldact->sa_handler == oo_signal_terminate ||
      oldact->sa_sigaction == oo_signal_terminate_siginfo )
    oldact->sa_handler = SIG_DFL;
#ifdef USE_SA_RESTORER
  oldact->sa_flags |= SA_RESTORER;
  oldact->sa_restorer = oo_saved_restorer;
#endif
}


bool oo_is_signal_intercepted(int sig, void* handler)
{
  if( CITP_OPTS.signals_no_postpone & (1 << (sig-1)) )
    return false;
  if( handler == SIG_IGN || handler == SIG_ERR )
    return false;
  if( handler != SIG_DFL )
    return true;

  switch( sig ) {
    /* For deadly SIG_DFL we install our handler.
     * "man 7 signal" provides the following list of signals which
     * terminate a process when SIG_DFL is installed.
     * SIGKILL is removed from the list because it can't be intercepted.
     */
    case SIGHUP:
    case SIGINT:
    case SIGPIPE:
    case SIGALRM:
    case SIGTERM:
    case SIGUSR1:
    case SIGUSR2:
    case SIGPOLL:
    case SIGPROF:
    case SIGVTALRM:
    case SIGSTKFLT:
    case SIGPWR:
      return true;
  }
  return false;
}

static int
oo_signal_install_to_onload(int sig, const struct sigaction *act,
                            struct sigaction *oldact)
{
  struct oo_sigstore* store = &sigstore[sig - 1];
  struct sigaction* new_store;
  ci_uint32 seq;
  int rc;

  rc = oo_signal_write_lock(sig, &seq);
  if( rc != 0 ) {
    ci_log("ERROR: %s(%d) failed to lock signal store", __func__, sig);
    return rc;
  }
  LOG_SIG(ci_log("%s(%d): new handler %p seq %x",
                 __func__, sig, act ? act->sa_handler : (void*)-1, seq));
  new_store = &store->act[! (seq & 1)];

  if( oldact != NULL )
    *oldact = store->act[seq & 1];
  if( act != NULL ) {
    *new_store = *act;
    if( act->sa_handler == SIG_DFL ) {
      /* We'd like to preserve SA_SIGINFO flag which user is possibly
       * using.
       */
      if( new_store->sa_flags & SA_SIGINFO )
        new_store->sa_sigaction = oo_signal_terminate_siginfo;
      else
        new_store->sa_handler = oo_signal_terminate;
    }
  }
  else {
    /* Non-intercepted signal */
    new_store->sa_handler = SIG_DFL;
  }

  LOG_SIG(ci_log("%s(%d): new seq %x "OO_PRINT_SIGACTION_FMT,
                 __func__, sig, seq + 1, OO_PRINT_SIGACTION_ARG(new_store)));
  oo_signal_write_unlock(sig, seq);

  return 0;
}

static int
oo_signal_install_to_os(int sig, const struct sigaction *act,
                        struct sigaction *oldact, bool from_app)
{
  int rc;
  struct sigaction new;

  ci_assert(act);

  new.sa_flags = (act->sa_flags | SA_SIGINFO) & ~(SA_RESETHAND | SA_RESTORER);
  new.sa_sigaction = citp_signal_intercept;
  new.sa_mask = act->sa_mask;
  LOG_SIG(ci_log("%s(%d): intercept with "OO_PRINT_SIGACTION_FMT,
                 __func__, sig, OO_PRINT_SIGACTION_ARG(&new)));

  if( from_app )
    rc = oo_libc_sigaction(sig, &new, oldact);
  else
    rc = oo_syscall_sigaction(sig, &new, oldact);
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

  if( sig <= 0 || sig > _NSIG ) {
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
      oo_fixup_oldact(oldact);
      return 0;
    }
    return oo_libc_sigaction(sig, NULL, oldact);
  }

  /* Are we going to intercept this signal? */
  if( ! oo_is_signal_intercepted(sig, act->sa_handler) ) {
    rc = oo_libc_sigaction(sig, act, &old);
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
        *oldact = old;
      return rc;
    }


    /* The signal was intercepted, and now it is not.  Mark it in the
     * store.
     */
    rc = oo_signal_install_to_onload(sig, NULL, oldact);
    if( rc < 0 )
      return rc;
    if( oldact )
      oo_fixup_oldact(oldact);
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
    return oo_signal_install_to_os(sig, act, oldact, true);

  /* We should call kernel's sigaction if:
   * - the signal was intercepted, but with different SA_* flags
   *   (except for SA_SIGINFO);
   * - the signal was intercepted, but with a different sa_mask.
   */
  if( ((act->sa_flags ^ old.sa_flags) & ~SA_SIGINFO) != 0 ||
      memcmp(&act->sa_mask, &old.sa_mask, sizeof(old.sa_mask)) != 0 ) {
    rc = oo_signal_install_to_os(sig, act, NULL, true);
  }
  else if( ! sigstore[sig - 1].libc_safe ) {
    /* We did not call libc's sigaction on this path so far, so we should
     * check whether the user tries to install a handler for SIGCANCEL and
     * such.
     */
    rc = oo_libc_sigaction(sig, NULL, NULL);
  }

  if( oldact != NULL ) {
    *oldact = old;
    oo_fixup_oldact(oldact);
  }

  return rc;
}

int oo_sigonload_init(void* handler)
{
  struct sigaction sa, oldsa;
  int rc;

  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = handler;
  rc = oo_do_sigaction(SIGONLOAD, &sa, &oldsa);
  ci_assert_equal(rc, 0);
  if( rc < 0 ) {
    ci_log("%s: ERROR: failed to install SIGONLOAD handler %s",
           __func__, strerror(errno));
    return rc;
  }

  ci_assert_equal(oldsa.sa_handler, SIG_DFL);
  if( oldsa.sa_handler != SIG_DFL ) {
    ci_log("ERROR: a signal handler for signal %d has been "
           "overwritten by Onload!  "
           "See SIGONLOAD definition in the Onload source code", SIGONLOAD);
    errno = EBUSY;
    return -1;
  }

#ifdef USE_SA_RESTORER
  /* It is a good chance to find out the libc's sa_restorer. */
  oo_syscall_sigaction(SIGONLOAD, NULL, &sa);
  ci_assert_flags(sa.sa_flags, SA_RESTORER);
  oo_saved_restorer = sa.sa_restorer;
  ci_assert(oo_saved_restorer);
#endif

  return 0;
}

static bool sa_equal(struct sigaction* sa1, struct sigaction* sa2)
{
  /* sa_handler & sa_sigaction share the same offset and size; they differ
   * by type only.  There is no need to check both. */
  return sa1->sa_handler == sa2->sa_handler &&
      sa1->sa_flags == sa2->sa_flags &&
#ifdef SA_RESTORER
      ( (sa1->sa_flags & SA_RESTORER) == 0 ||
        sa1->sa_restorer == sa2->sa_restorer ) &&
#endif
      memcmp(&sa1->sa_mask, &sa2->sa_mask, sizeof(sa1->sa_mask)) == 0;
}

/* Intercept all already-installed signals.
 * It may be needed for:
 * - sigaction() called before Onload reached CITP_INIT_ALL;
 * - glibc calls __sigaction(), for example for SIGCANCEL.
 */
int oo_init_signals(void)
{
  struct sigaction act, oldact;
  int sig;
  int rc;

  LOG_SIG(ci_log("%s()", __func__));
  for( sig = 1; sig < NSIG; sig++) {
    /* SIGKILL can't be intercepted;
     * non-zero sequence number means that we've already been intercepted.
     *
     * Now we are interested in signals which possibly installed their
     * handler in a stealthy way.
     */
    if( sig == SIGKILL || sigstore[sig - 1].seq != 0 )
      continue;

    /* We do want to intercept SIGCANCEL.  It means we should not use
     * libc's wrapper around this syscall. */
    rc = oo_syscall_sigaction(sig, NULL, &act);
    if( rc < 0 )
      continue;
    if( ! oo_is_signal_intercepted(sig, act.sa_handler) )
      continue;

    /* Intercept! */
    rc = oo_signal_install_to_onload(sig, &act, NULL);
    ci_assert_equal(rc, 0);
    if( rc != 0 )
      continue;

    rc = oo_signal_install_to_os(sig, &act, &oldact, false);
    ci_assert_equal(rc, 0);
    if( rc < 0 )
      continue;

    /* Re-check that act == oldact, and install the new signal handler in
     * case of the race.
     */
    if( sa_equal(&act, &oldact) )
      continue;

    rc = oo_signal_install_to_onload(sig, &oldact, NULL);
    ci_assert_equal(rc, 0);
  }
  return 0;
}
