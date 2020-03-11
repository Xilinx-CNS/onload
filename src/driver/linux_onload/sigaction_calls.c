/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file sigaction_calls.c
** <L5_PRIVATE L5_HEADER >
** \author  oktet sasha
**  \brief  siggaction calls via ioctl
**   \date  2011/09/05
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include "onload_kernel_compat.h"

#include <onload/linux_onload_internal.h>
#include <onload/linux_onload.h>
#include <onload/linux_trampoline.h>
#include <onload/linux_mmap.h>

static int
efab_signal_handler_type(int sig, __sighandler_t user_handler)
{
  if( user_handler == SIG_IGN )
    return OO_SIGHANGLER_IGN_BIT;
  else if( user_handler != SIG_DFL )
    return OO_SIGHANGLER_USER;
  else if( sig_kernel_stop(sig) )
    return OO_SIGHANGLER_STOP;
  else if( sig_kernel_coredump(sig) )
    return OO_SIGHANGLER_CORE;
  else if( sig_kernel_ignore(sig) )
    return OO_SIGHANGLER_IGN_BIT;
  else
    return OO_SIGHANGLER_TERM;
}

/* Depending on the kernel version and arch,
 * __put_user may expand to something that accepts volatile
 * pointers (e.g. on x86-64) or not (on newer ARM64 kernels).
 * We want to get rid of compiler warnings, but we do not want
 * to remove volatileness if it is not really needed, hence
 * this macro is defined conditionally
 */
#ifdef EFRM_PUT_USER_ACCEPTS_VOLATILE
#define put_user_signal_type(_kerneldata, _userdata) \
  __put_user((_kerneldata)->type, &(_userdata)->type)
#else
#define put_user_signal_type(_kerneldata, _userdata) \
  __put_user((_kerneldata)->type, (ci_int32 *)&(_userdata)->type)
#endif

/* Substitute signal handler by our variant. */
static int
efab_signal_substitute(int sig, struct sigaction *new_act,
                       struct mm_signal_data *tramp_data)
{
  int rc;
  __sighandler_t handler;
  struct k_sigaction *k;
  int type;
  __user struct oo_sigaction *user_data;
  struct oo_sigaction *signal_data = &(tramp_data->signal_data[sig - 1]);
  ci_int32 old_type;
  ci_int32 seq;

  user_data = &(((struct oo_sigaction *)
                 (CI_USER_PTR_GET(tramp_data->user_data)))[sig - 1]);
  if( !efab_access_ok(user_data, sizeof(struct oo_sigaction) ) )
    return -EFAULT;

  do {
    old_type = signal_data->type;
    seq = (old_type & OO_SIGHANGLER_SEQ_MASK) + (1 << OO_SIGHANGLER_SEQ_SHIFT);
  } while( ci_cas32_fail(&signal_data->type, old_type,
                         OO_SIGHANGLER_BUSY | seq) );

  /* We are going to change signal handler: UL should wait until we've
   * finished */
  rc = put_user_signal_type(signal_data, user_data);
  if( rc != 0 ) {
    signal_data->type = old_type;
    return -EFAULT;
  }

  spin_lock_irq(&current->sighand->siglock);
  k = &current->sighand->action[sig - 1];
  if( new_act )
    k->sa = *new_act;
  type = efab_signal_handler_type(sig, k->sa.sa_handler);
  handler = type <= OO_SIGHANGLER_DFL_MAX ? tramp_data->handlers[type] : NULL;
  BUILD_BUG_ON(SIG_DFL != NULL);

  /* We do not handle this signal: */
  if( type != OO_SIGHANGLER_USER && handler == NULL ) {
    spin_unlock_irq(&current->sighand->siglock);
    signal_data->type = old_type | OO_SIGHANGLER_IGN_BIT | seq;
    ci_verify(put_user_signal_type(signal_data, user_data) == 0);

    return 0;
  }

  OO_DEBUG_SIGNAL(ci_log("%s: %d change sig=%d handler %p flags %lx "
                         "restorer %p type %d", __func__,
                         current->pid, sig, k->sa.sa_handler,
                         k->sa.sa_flags, k->sa.sa_restorer, type));
  signal_data->flags = k->sa.sa_flags;
  k->sa.sa_flags |= SA_SIGINFO;
#if defined(SA_IA32_ABI) && defined(CONFIG_COMPAT)
  if( in_ia32_syscall() )
    k->sa.sa_flags |= SA_IA32_ABI;
#endif
  if( type == OO_SIGHANGLER_USER )
    CI_USER_PTR_SET(signal_data->handler, k->sa.sa_handler);
  else {
    CI_USER_PTR_SET(signal_data->handler, handler);
    if( tramp_data->sarestorer ) {
      k->sa.sa_flags |= SA_RESTORER;
      k->sa.sa_restorer = tramp_data->sarestorer;
    }
  }
  k->sa.sa_handler = tramp_data->handler_postpone;
  spin_unlock_irq(&current->sighand->siglock);

  OO_DEBUG_SIGNAL(ci_log("%s: %d set sig=%d handler %p flags %lx restorer %p",
                         __func__, current->pid, sig, k->sa.sa_handler,
                         k->sa.sa_flags, k->sa.sa_restorer));

  /* Copy signal_data to UL; type BUSY */
  rc = __copy_to_user(user_data, signal_data, sizeof(*signal_data));
  signal_data->type = type | seq;
  if( rc != 0 )
    return -EFAULT;
  /* Fill in the real type */
  ci_verify(put_user_signal_type(signal_data, user_data) == 0);

  return 0;
}

static void
efab_signal_recheck(int sig, const struct mm_signal_data *tramp_data)
{
  const struct oo_sigaction *signal_data = &(tramp_data->signal_data[sig - 1]);
  struct k_sigaction *k;

  if( (signal_data->type & (OO_SIGHANGLER_TYPE_MASK | OO_SIGHANGLER_IGN_BIT)) !=
      OO_SIGHANGLER_USER )
    return;

  spin_lock_irq(&current->sighand->siglock);
  k = &current->sighand->action[sig - 1];
  if( k->sa.sa_handler == NULL ) {
    k->sa.sa_flags = SA_SIGINFO;
    k->sa.sa_handler = tramp_data->handler_postpone;
    OO_DEBUG_SIGNAL(ci_log("%s: fix sig=%d; probable SA_ONESHOT",
                           __func__, sig));
  }
  spin_unlock_irq(&current->sighand->siglock);
}

int efab_signal_mm_init(const ci_tramp_reg_args_t *args, struct mm_hash *p)
{
  int i;

  if( args->max_signum < _NSIG )
    return -E2BIG;

  p->signal_data.handler_postpone =
                    CI_USER_PTR_GET(args->signal_handler_postpone);
  p->signal_data.sarestorer = CI_USER_PTR_GET(args->signal_sarestorer);

  for( i = 0; i <= OO_SIGHANGLER_DFL_MAX; i++ )
    p->signal_data.handlers[i] = CI_USER_PTR_GET(args->signal_handlers[i]);

  p->signal_data.user_data = args->signal_data;
  p->signal_data.sa_onstack_intercept = args->sa_onstack_intercept;

  return 0;
}

void efab_signal_process_init(struct mm_signal_data *tramp_data)
{
  int sig;
  int rc;

  OO_DEBUG_SIGNAL(ci_log("%s(%p) pid %d",
                         __func__, tramp_data, current->pid));

  /* At start-of-day, we intercept all already-installed handlers
   * and deadly SIG_DFL */
  for( sig = 1; sig <= _NSIG; sig++ ) {
    struct k_sigaction *k;

    tramp_data->signal_data[sig - 1].type = OO_SIGHANGLER_USER |
                                            OO_SIGHANGLER_IGN_BIT;
    CI_USER_PTR_SET(tramp_data->signal_data[sig - 1].handler, NULL);

    /* Never, never intercept SIGKILL. You'll get deadlock since exit_group
     * sends SIGKILL to all other threads. */
    if( sig_kernel_only(sig) )
      continue;

    /* If this is our handler, do nothing.  This is second init from the
     * same process.  It happens in fork hooks, when second netif is
     * created, etc. */
    spin_lock_irq(&current->sighand->siglock);
    k = &current->sighand->action[sig - 1];
    if( k->sa.sa_handler == tramp_data->handler_postpone ) {
      spin_unlock_irq(&current->sighand->siglock);
      OO_DEBUG_SIGNAL(ci_log("%s: double init pid=%d",
                             __func__, current->pid));
      rc = copy_from_user(tramp_data->signal_data,
                          CI_USER_PTR_GET(tramp_data->user_data),
                          sizeof(tramp_data->signal_data));
      if( rc != 0 )
        ci_log("%s: ERROR: failed to copy signal data (%d)", __func__, rc);

      break;
    }
    spin_unlock_irq(&current->sighand->siglock);

    /* Ignore any errors */
    (void) efab_signal_substitute(sig, NULL, tramp_data);
  }

  tramp_data->kernel_sighand = current->sighand;
}

/* Change substituted sigaction to the structure really meant by user.
 * If sa is provided, copy user sigaction data here to pass to user.
 * If sa==NULL, substitute in-place. */
static int
efab_signal_report_sigaction(int sig, struct sigaction *sa,
                             struct mm_signal_data *tramp_data)
{
  struct oo_sigaction *signal_data = &(tramp_data->signal_data[sig - 1]);
  ci_int32 type;
#define MAX_TRIES_BUSY 1000
  int tried_busy = 0;
  int tried_changed = 0;
  int sa_provided = (sa != NULL);

re_read_data:
  do {
    tried_busy++;
    type = signal_data->type;
  } while( (type & OO_SIGHANGLER_TYPE_MASK) == OO_SIGHANGLER_BUSY &&
           tried_busy <= MAX_TRIES_BUSY );
  if( tried_busy > MAX_TRIES_BUSY ) {
    ci_log("%s(%d): pid %d signal() or sigaction() runs for too long",
           __func__, sig, current->pid);
    return -EBUSY;
  }

report:
  spin_lock_irq(&current->sighand->siglock);
  if( sa_provided )
    *sa = current->sighand->action[sig - 1].sa;
  else
    sa = &current->sighand->action[sig - 1].sa;

  if( sa->sa_handler != tramp_data->handler_postpone ) {
    spin_unlock_irq(&current->sighand->siglock);
    return 0;
  }

  OO_DEBUG_SIGNAL(ci_log("%s: %d process sig=%d type %d handler %p "
                         "flags %lx restorer %p", __func__, current->pid,
                         sig, type & OO_SIGHANGLER_TYPE_MASK, sa->sa_handler,
                         sa->sa_flags, sa->sa_restorer));
  if( (signal_data->type & OO_SIGHANGLER_TYPE_MASK) == OO_SIGHANGLER_USER) {
    sa->sa_handler = CI_USER_PTR_GET(signal_data->handler);
    if( ! (signal_data->flags & SA_SIGINFO) )
      sa->sa_flags &= ~SA_SIGINFO;
  }
  else if( ! (signal_data->type & OO_SIGHANGLER_IGN_BIT) ) {
    sa->sa_handler = SIG_DFL;
    if( ! (signal_data->flags & SA_SIGINFO) )
      sa->sa_flags &= ~SA_SIGINFO;
  }
  OO_DEBUG_SIGNAL(ci_log("%s: %d to user sig=%d handler %p flags %lx "
                         "restorer %p", __func__,
                         current->pid, sig, sa->sa_handler,
                         sa->sa_flags, sa->sa_restorer));

  spin_unlock_irq(&current->sighand->siglock);

  /* Re-check that UL have not changed signal_data. */
  if( type != signal_data->type ) {
    tried_changed++;
    if( tried_changed > MAX_TRIES_BUSY ) {
      ci_log("%s: signal() or sigaction() called too fast: "
             "pid=%d sig=%d type=%x != stored_type=%x", __func__,
             current->pid, sig, type, signal_data->type);
      return -EBUSY;
    }
    if( (signal_data->type & OO_SIGHANGLER_TYPE_MASK) == OO_SIGHANGLER_BUSY ) {
      tried_busy = 0;
      goto re_read_data;
    }
    else
      goto report;
  }

  return 0;
}

void efab_signal_process_fini(struct mm_signal_data *tramp_data)
{
  int sig;

  OO_DEBUG_SIGNAL(ci_log("%s(%p) pid %d: current->flags=%x, "
                         "tramp_data->user_data=%p", __func__,
                         tramp_data, current->pid, (int)current->flags,
                         CI_USER_PTR_GET(tramp_data->user_data)));
  /* Check if we should really do anything */
  if( current->flags & PF_EXITING )
    return; /* the process is exiting */
  if( current->in_execve )
    return; /* in execve() */
  if( CI_USER_PTR_GET(tramp_data->user_data) == NULL )
    return; /* nothing was inited */

  OO_DEBUG_SIGNAL(ci_log("%s(%p) pid %d: uninstall interception",
                         __func__, tramp_data, current->pid));
  for( sig = 1; sig <= _NSIG; sig++ ) {
    if( sig_kernel_only(sig) )
      continue;
    if( efab_signal_report_sigaction(sig, NULL, tramp_data) != 0 ) {
      ci_log("%s: ERROR: pid %d failed to back off signal %d handler",
             __func__, current->pid, sig);
      continue;
    }
  }
}


static int
efab_signal_do_sigaction(int sig, struct sigaction *act,
                         struct sigaction *oact,
                         struct mm_signal_data *tramp_data,
                         int *out_pass_to_kernel)
{
  int rc = 0;

  if( !valid_signal(sig) || sig < 1 || (act != NULL && sig_kernel_only(sig)) )
    return -EINVAL;


  if( oact != NULL ) {
    rc = efab_signal_report_sigaction(sig, oact, tramp_data);
    if( rc != 0 )
      return rc;
#if defined(SA_IA32_ABI) && defined(CONFIG_COMPAT)
    /* efab_signal_report_sigaction is used from efab_signal_process_fini(),
     * so it must not remove SA_IA32_ABI flag.  But we should not leak this
     * flag to UL, see sigaction_compat_abi() in linux kernel. */
    oact->sa_flags &= ~SA_IA32_ABI;
#endif
  }

  if( act != NULL ) {
    sigdelsetmask(&act->sa_mask, sigmask(SIGKILL) | sigmask(SIGSTOP));

  /* If the signal is ignored now, we should ignore all already-pending
   * signals.  Instead of doing it, pass this to OS. */
    if( act->sa_handler == SIG_IGN ||
        (act->sa_handler == SIG_DFL && sig_kernel_ignore(sig)) )
      *out_pass_to_kernel = 1;
    else if( act->sa_flags & SA_ONSTACK && !tramp_data->sa_onstack_intercept )
      *out_pass_to_kernel = 1;
    else
      rc = efab_signal_substitute(sig, act, tramp_data);
  }
  else
    efab_signal_recheck(sig, tramp_data);

  return rc;
}

static int
efab_signal_get_tramp_data(struct mm_signal_data **tramp_data)
{
  struct mm_hash *p;

  write_lock (&oo_mm_tbl_lock);
  p = oo_mm_tbl_lookup(current->mm);
  if( p == NULL || CI_USER_PTR_GET(p->signal_data.user_data) == NULL) {
    write_unlock (&oo_mm_tbl_lock);
    return -ENOSYS;
  }
  efab_get_mm_hash_locked(p);
  *tramp_data = &p->signal_data;

  write_unlock (&oo_mm_tbl_lock);

  return 0;
}


void
efab_signal_put_tramp_data(struct mm_signal_data *tramp_data)
{
  struct mm_hash *p = container_of(tramp_data, struct mm_hash, signal_data);
  int do_free = 0;

  write_lock (&oo_mm_tbl_lock);
  efab_put_mm_hash_locked(p);
  write_unlock (&oo_mm_tbl_lock);

  if( do_free )
    efab_free_mm_hash(p);
}

asmlinkage long
#ifdef ONLOAD_SYSCALL_PTREGS
efab_linux_trampoline_sigaction(const struct pt_regs *regs)
#else
efab_linux_trampoline_sigaction(int sig, const struct sigaction *act,
                                struct sigaction *oact, size_t sigsetsize)
#endif
{
#ifdef ONLOAD_SYSCALL_PTREGS
#if defined(__x86_64__)
  int sig = regs->di;
  const struct sigaction *act = (const struct sigaction *)regs->si;
  struct sigaction *oact = (struct sigaction *)regs->dx;
  size_t sigsetsize = regs->r10;
#elif defined(__aarch64__)
  int sig = regs->regs[0];
  const struct sigaction *act = (const struct sigaction *)regs->regs[1];
  struct sigaction *oact = (struct sigaction *)regs->regs[2];
  size_t sigsetsize = regs->regs[3];
#else
#error "Trampolines are not supported on this platform"
#endif
#endif
  int rc = 0;
  struct sigaction old, new;
  struct mm_signal_data *tramp_data;
  int pass_to_kernel = 0;

  efab_syscall_enter();

  if( sigsetsize != sizeof(sigset_t) ) {
    efab_syscall_exit();
    return -EINVAL;
  }

  /* Is it our process? */
  if( efab_signal_get_tramp_data(&tramp_data) ) {
    rc = efab_linux_sys_sigaction(sig, act, oact);
    efab_syscall_exit();
    return rc;
  }

  if( act != NULL ) {
    /* If we are in vfork child, we have the same mm but different sighand.
     * We should not change parent UL structure in this case, se we'd
     * better off from this signal while running in the child. */
    if( tramp_data->kernel_sighand != current->sighand )
      pass_to_kernel = 1;
    else {
      rc = copy_from_user(&new, act, sizeof(new));
      if( rc != 0 ) {
        efab_signal_put_tramp_data(tramp_data);
        efab_syscall_exit();
        return -EFAULT;
      }
    }
  }

  rc = efab_signal_do_sigaction(sig,
                                (act && !pass_to_kernel) ? &new : NULL,
                                oact ? &old : NULL, tramp_data,
                                &pass_to_kernel);
  efab_signal_put_tramp_data(tramp_data);

  if( pass_to_kernel )
    efab_linux_sys_sigaction(sig, act, NULL);

  if( rc == 0 && oact != NULL ) {
    rc = copy_to_user(oact, &old, sizeof(old));
    if( rc != 0 ) {
      efab_syscall_exit();
      return -EFAULT;
    }
  }
  efab_syscall_exit();
  return rc;
}

#if defined(CONFIG_COMPAT) && !defined(__aarch64__)
/* On PPC there is no 32-bit sigaction - or rather, all sigaction calls are 32-bit.
 */
asmlinkage int
#ifdef ONLOAD_SYSCALL_PTREGS
efab_linux_trampoline_sigaction32(const struct pt_regs *regs)
#else
efab_linux_trampoline_sigaction32(int sig, const struct sigaction32 *act32,
                                  struct sigaction32 *oact32,
                                  unsigned int sigsetsize)
#endif
{
#ifdef ONLOAD_SYSCALL_PTREGS
  int sig = regs->bx;
  const struct sigaction32 *act32 = (const struct sigaction32 *)regs->cx;
  struct sigaction32 *oact32 = (struct sigaction32 *)regs->dx;
  unsigned int sigsetsize = regs->si;
#endif
  struct sigaction act, oact;
  compat_sigset_t set32;
  int rc;
  struct mm_signal_data *tramp_data;
  int pass_to_kernel = 0;

  efab_syscall_enter();

  if( sigsetsize != sizeof(compat_sigset_t) ) {
    efab_syscall_exit();
    return -EINVAL;
  }

  /* Is it our process? */
  if( efab_signal_get_tramp_data(&tramp_data) ) {
    rc = efab_linux_sys_sigaction32(sig, act32, oact32);
    efab_syscall_exit();
    return rc;
  }

  /* Do not change UL data if we are in vfork child */
  if( act32 != NULL && tramp_data->kernel_sighand != current->sighand )
    pass_to_kernel = 1;

  if( act32 != NULL && !pass_to_kernel ) {
    compat_uptr_t handler, restorer;

    if( !efab_access_ok(act32, sizeof(*act32)) ||
        __get_user(handler, &act32->sa_handler) ||
        __get_user(act.sa_flags, &act32->sa_flags) ||
        __get_user(restorer, &act32->sa_restorer) ||
        __copy_from_user(&set32, &act32->sa_mask, sizeof(compat_sigset_t)) ) {
      efab_signal_put_tramp_data(tramp_data);
      efab_syscall_exit();
      return -EFAULT;
    }
    act.sa_handler = compat_ptr(handler);
    act.sa_restorer = compat_ptr(restorer);

    ci_assert_ge(_COMPAT_NSIG_WORDS, _NSIG_WORDS << 1);
    switch (_NSIG_WORDS) { /* Note: no break */
    case 4:
      act.sa_mask.sig[3] = set32.sig[6] | (((long)set32.sig[7]) << 32);
      /* fall-through */
    case 3:
      act.sa_mask.sig[2] = set32.sig[4] | (((long)set32.sig[5]) << 32);
      /* fall-through */
    case 2:
      act.sa_mask.sig[1] = set32.sig[2] | (((long)set32.sig[3]) << 32);
      /* fall-through */
    case 1:
      act.sa_mask.sig[0] = set32.sig[0] | (((long)set32.sig[1]) << 32);
    }
  }

  rc = efab_signal_do_sigaction(sig,
                                (act32 && !pass_to_kernel) ? &act : NULL,
                                oact32 ? &oact : NULL, tramp_data,
                                &pass_to_kernel);
  efab_signal_put_tramp_data(tramp_data);
  if( pass_to_kernel )
    efab_linux_sys_sigaction32(sig, act32, NULL);

  if( rc == 0 && oact32 != NULL ) {
    switch (_NSIG_WORDS) { /* Note: no break */
    case 4:
      set32.sig[7] = (oact.sa_mask.sig[3] >> 32);
      set32.sig[6] = oact.sa_mask.sig[3];
      /* fall-through */
    case 3:
      set32.sig[5] = (oact.sa_mask.sig[2] >> 32);
      set32.sig[4] = oact.sa_mask.sig[2];
      /* fall-through */
    case 2:
      set32.sig[3] = (oact.sa_mask.sig[1] >> 32);
      set32.sig[2] = oact.sa_mask.sig[1];
      /* fall-through */
    case 1:
      set32.sig[1] = (oact.sa_mask.sig[0] >> 32);
      set32.sig[0] = oact.sa_mask.sig[0];
    }

    if( !efab_access_ok(oact32, sizeof(*oact32)) ||
        __put_user(ptr_to_compat(oact.sa_handler), &oact32->sa_handler) ||
        __put_user(ptr_to_compat(oact.sa_restorer), &oact32->sa_restorer) ||
        __put_user(oact.sa_flags, &oact32->sa_flags) ||
        __copy_to_user(&oact32->sa_mask, &set32, sizeof(compat_sigset_t))) {
      efab_syscall_exit();
      return -EFAULT;
    }
  }

  efab_syscall_exit();
  return rc;
}

#endif
