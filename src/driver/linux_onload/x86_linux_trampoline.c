/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/*
** Copyright 2005-2012  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/**************************************************************************\
*//*! \file linux_trampoline.c System call trampolines for Linux
** <L5_PRIVATE L5_SOURCE>
** \author  gel,mjs
**  \brief  Package - driver/linux	Linux driver support
**   \date  2005/03/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */
 
/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include <ci/efrm/syscall.h>
#include "onload_kernel_compat.h"

#include <onload/linux_onload_internal.h>
#include <onload/linux_trampoline.h>
#include <onload/linux_mmap.h>
#include <onload/linux_onload.h>
#include <linux/unistd.h>
#include <linux/stop_machine.h>

/*--------------------------------------------------------------------
 *
 * Platform-specific stuff
 *
 *--------------------------------------------------------------------*/

#  include <asm/processor.h>
#  include <asm/msr.h>
#  include <asm/percpu.h>



#ifdef CONFIG_COMPAT
#  include <asm/ia32_unistd.h>
#endif



/*--------------------------------------------------------------------
 *
 * Tracing / debugging
 *
 *--------------------------------------------------------------------*/

/* Debugging for internal use only */
#if 1
#  define TRAMP_DEBUG(x...) (void)0
#else
#  define TRAMP_DEBUG ci_log
#endif

/* On 4.17+ on x86_64 the system calls are taking a single
   ptregs argument.
   (The user-space calling convention is the same as before, though).
*/
#ifdef EFRM_SYSCALL_PTREGS
#  define SYSCALL_PTR_DEF(_name, _args)                     \
  asmlinkage long (*_name)(const struct pt_regs *regs)
#  define PASS_SYSCALL1(_name, _arg)                \
  ((_name)(&(struct pt_regs){.di = (unsigned long)(_arg)}))
#  define PASS_SYSCALL2(_name, _arg1, _arg2)                            \
  ((_name)(&(struct pt_regs){.di = (unsigned long)(_arg1),         \
      .si = (unsigned long)(_arg2)}))
#  define PASS_SYSCALL3(_name, _arg1, _arg2, _arg3)                     \
  ((_name)(&(struct pt_regs){.di = (unsigned long)(_arg1),         \
      .si = (unsigned long)(_arg2),                                     \
      .dx = (unsigned long)(_arg3)}))
#  define PASS_SYSCALL4(_name, _arg1, _arg2, _arg3, _arg4)              \
  ((_name)(&(struct pt_regs){.di = (unsigned long)(_arg1),         \
      .si = (unsigned long)(_arg2),                                     \
      .dx = (unsigned long)(_arg3),                                     \
      .r10 = (unsigned long)(_arg4)}))
#  ifdef CONFIG_COMPAT
   /* In the most cases, we call non-compat syscall with non-compat
    * parameters.  We can't do it easily for rt_sigaction and sendmsg,
    * because someone should convert compat structures. */
#  define COMPAT_PASS_SYSCALL2(_name, _arg1, _arg2)                 \
      (_name)(&(struct pt_regs){.bx = (unsigned long)(_arg1),       \
                                .cx = (unsigned long)(_arg2)})
#  define COMPAT_PASS_SYSCALL4(_name, _arg1, _arg2, _arg3, _arg4)   \
      (_name)(&(struct pt_regs){.bx = (unsigned long)(_arg1),       \
                                .cx = (unsigned long)(_arg2),       \
                                .dx = (unsigned long)(_arg3),       \
                                .si = (unsigned long)(_arg4)})
#  endif
#else
#  define SYSCALL_PTR_DEF(_name, _args)         \
  asmlinkage long (*_name) _args
#  define PASS_SYSCALL1(_name, _arg) ((_name)(_arg))
#  define PASS_SYSCALL2(_name, _arg1, _arg2) ((_name)(_arg1, _arg2))
#  define PASS_SYSCALL3(_name, _arg1, _arg2, _arg3) \
  ((_name)(_arg1, _arg2, _arg3))
#  define PASS_SYSCALL4(_name, _arg1, _arg2, _arg3, _arg4)    \
  ((_name)(_arg1, _arg2, _arg3, _arg4))
#  ifdef CONFIG_COMPAT
#    define COMPAT_PASS_SYSCALL2 PASS_SYSCALL2
#    define COMPAT_PASS_SYSCALL4 PASS_SYSCALL4
#  endif
#endif


/**************************************************************************** 
 * System-call trampoline stuff.
 *
 * The trampoline mechanism will bodge the return address on the stack, then
 * return from syscall.  The bodged return address points at a handler stub in
 * the user-library, which does the appropriate thing.
 *
 * This is very useful when we detect a system call that we would have normally
 * expected to intercept in the user-library.  Currently we do this only for
 * close.  The trampoline will call the close in the user-library, before
 * returning to immediately after where the original system call was issued.
 *
 * Can also be useful when an error is detected in the system call -- rather
 * than kernel panic, trampoline back to the user-lib wich assert-fails there.
 */


/* We must save the original addresses of the routines we intercept.
 */
static SYSCALL_PTR_DEF(saved_sys_close, (int));
static SYSCALL_PTR_DEF(saved_sys_exit_group, (int));
static SYSCALL_PTR_DEF(saved_sys_rt_sigaction, (int, const struct sigaction *,
                                                struct sigaction *, size_t));
#ifdef CONFIG_COMPAT
static SYSCALL_PTR_DEF(saved_sys_rt_sigaction32, (int,
                                                  const struct sigaction32 *,
                                                  struct sigaction32 *,
                                                  unsigned int));
#endif

atomic_t efab_syscall_used;

/* A way to call the original sys_close, exported to other parts of the code.
 */
asmlinkage int efab_linux_sys_close(int fd)
{
  int rc;

  if( saved_sys_close == NULL ) {
    ci_log("Unexpected close() request before full init");
    return -EFAULT;
  }

  TRAMP_DEBUG ("close %d via saved_sys_close=%p...", fd, saved_sys_close);
  rc = PASS_SYSCALL1(saved_sys_close, fd);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}


asmlinkage int efab_linux_sys_exit_group(int status)
{
  if( saved_sys_exit_group == NULL ) {
    ci_log("Unexpected exit_group() request before full init");
    return -EFAULT;
  }
  return PASS_SYSCALL1(saved_sys_exit_group, status);
}

asmlinkage int efab_linux_sys_epoll_create1(int flags)
{
  SYSCALL_PTR_DEF(sys_epoll_create_fn, (int));
  int rc;

  if( efrm_syscall_table == NULL ) {
    ci_log("Unexpected epoll_ctl() request before full init");
    return -EFAULT;
  }

  sys_epoll_create_fn = efrm_syscall_table[__NR_epoll_create1];
  TRAMP_DEBUG ("epoll_create1(%d) via %p...", flags, sys_epoll_create_fn);
  rc = PASS_SYSCALL1(sys_epoll_create_fn, flags);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
asmlinkage int efab_linux_sys_epoll_ctl(int epfd, int op, int fd,
                                        struct epoll_event *event)
{
  SYSCALL_PTR_DEF(sys_epoll_ctl_fn, (int, int, int, struct epoll_event *));
  int rc;

  if( efrm_syscall_table == NULL ) {
    ci_log("Unexpected epoll_ctl() request before full init");
    return -EFAULT;
  }

  sys_epoll_ctl_fn = efrm_syscall_table[__NR_epoll_ctl];
  TRAMP_DEBUG ("epoll_ctl(%d,%d,%d,%p) via %p...", epfd, op, fd, event,
               sys_epoll_ctl_fn);
  rc = PASS_SYSCALL4(sys_epoll_ctl_fn, epfd, op, fd, event);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
asmlinkage int efab_linux_sys_epoll_wait(int epfd, struct epoll_event *events,
                                         int maxevents, int timeout)
{
  SYSCALL_PTR_DEF(sys_epoll_wait_fn, (int, struct epoll_event *, int, int));
  int rc;

  if( efrm_syscall_table == NULL ) {
    ci_log("Unexpected epoll_wait() request before full init");
    return -EFAULT;
  }

  sys_epoll_wait_fn = efrm_syscall_table[__NR_epoll_wait];
  TRAMP_DEBUG ("epoll_wait(%d,%p,%d,%d) via %p...", epfd, events, maxevents,
               timeout, sys_epoll_wait_fn);
  rc = PASS_SYSCALL4(sys_epoll_wait_fn, epfd, events, maxevents, timeout);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}


asmlinkage int efab_linux_sys_sendmsg(int fd, struct msghdr __user* msg,
                                      unsigned long __user* socketcall_args,
                                      unsigned flags)
{
  int rc;

  if( efrm_syscall_table == NULL ) {
    ci_log("Unexpected sendmsg() request before full init");
    return -EFAULT;
  }

  {
#ifdef __NR_sendmsg
    SYSCALL_PTR_DEF(sys_sendmsg_fn, (int, struct msghdr *, unsigned));

    sys_sendmsg_fn = efrm_syscall_table[__NR_sendmsg];
    TRAMP_DEBUG ("sendmsg(%d,%p,%d) via %p...", fd, msg, flags, sys_sendmsg_fn);
    rc = PASS_SYSCALL3(sys_sendmsg_fn, fd, msg, flags);
#elif defined(__NR_socketcall)
    SYSCALL_PTR_DEF(sys_socketcall_fn, (int, unsigned long *));
    unsigned long args[3];

    sys_socketcall_fn = efrm_syscall_table[__NR_socketcall];
    TRAMP_DEBUG ("sendmsg(%d,%p,%d) via %p...", fd, msg,
                 flags, sys_socketcall_fn);
    memset(args, 0, sizeof(args));
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)msg;
    args[2] = (unsigned long)flags;
    rc = -EFAULT;
    if (copy_to_user(socketcall_args, args, sizeof(args)) == 0)
      rc = PASS_SYSCALL2(sys_socketcall_fn, SYS_SENDMSG, socketcall_args);
#else
#error "Can't find sendmsg syscall number"
#endif
  }

  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}

asmlinkage int efab_linux_sys_bpf(int cmd, union bpf_attr __user* attr,
                                  int size)
{
  int rc;

  if( efrm_syscall_table == NULL ) {
    ci_log("Unexpected bpf() request before full init");
    return -EFAULT;
  }

  {
#ifdef __NR_bpf
    SYSCALL_PTR_DEF(sys_bpf_fn, (int, union bpf_attr *, int));

    sys_bpf_fn = efrm_syscall_table[__NR_bpf];
    TRAMP_DEBUG ("bpf(%d,%p,%d) via %p...", cmd, attr, size, sys_bpf_fn);
    rc = PASS_SYSCALL3(sys_bpf_fn, cmd, attr, size);
#else
    /* All callers should have checked for this capability before getting
     * here */
    ci_log("Unexpected bpf() call on kernel without BPF support");
    rc = -ENOSYS;
#endif
  }

  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}

#ifdef CONFIG_COMPAT
asmlinkage int
efab_linux_sys_sendmsg32(int fd, struct compat_msghdr __user* msg,
                         unsigned long __user* socketcall_args,
                         unsigned flags)
{
  int rc;

  if( efrm_syscall_table == NULL ) {
    ci_log("Unexpected sendmsg() request before full init");
    return -EFAULT;
  }

  if( efrm_compat_syscall_table != NULL ) {
    SYSCALL_PTR_DEF(sys_socketcall_fn, (int, unsigned long *));
    compat_ulong_t args[3];

    sys_socketcall_fn = efrm_compat_syscall_table[102/*__NR_socketcall*/];
    TRAMP_DEBUG ("sendmsg32(%d,%p,%d) via %p...", fd, msg,
                 flags, sys_socketcall_fn);
    memset(args, 0, sizeof(args));
    args[0] = (unsigned long)fd;
    args[1] = (unsigned long)msg;
    args[2] = (unsigned long)flags;
    rc = -EFAULT;
    if (copy_to_user(socketcall_args, args, sizeof(args)) == 0)
      rc = COMPAT_PASS_SYSCALL2(sys_socketcall_fn, SYS_SENDMSG, socketcall_args);
  }
  else
    rc = -EOPNOTSUPP;

  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
#endif

asmlinkage int efab_linux_sys_sigaction(int signum,
                                        const struct sigaction *act,
                                        struct sigaction *oact)
{
  int rc;

  if( saved_sys_rt_sigaction == NULL ) {
    ci_log("Unexpected rt_sigaction() request before full init");
    return -EFAULT;
  }

  rc = PASS_SYSCALL4(saved_sys_rt_sigaction, signum, act, oact, sizeof(sigset_t));
  return rc;
}
#ifdef CONFIG_COMPAT
asmlinkage int efab_linux_sys_sigaction32(int signum,
                                          const struct sigaction32 *act,
                                          struct sigaction32 *oact)
{
  int rc;

  if( saved_sys_rt_sigaction32 == NULL ) {
    ci_log("Unexpected rt_sigaction32() request before full init");
    return -EFAULT;
  }

  rc = COMPAT_PASS_SYSCALL4(saved_sys_rt_sigaction32, signum, act, oact,
                            sizeof(compat_sigset_t));
  return rc;
}

#endif


#ifdef OO_DO_HUGE_PAGES
#include <linux/unistd.h>
asmlinkage int efab_linux_sys_shmget(key_t key, size_t size, int shmflg)
{
  SYSCALL_PTR_DEF(sys_shmget_fn, (key_t, size_t, int));
  int rc;

  ci_assert(efrm_syscall_table);

  sys_shmget_fn = efrm_syscall_table[__NR_shmget];
  TRAMP_DEBUG ("shmget(%d,%ld,%d) via %p...", key, size, shmflg,
               sys_shmget_fn);
  rc = PASS_SYSCALL3(sys_shmget_fn, key, size, shmflg);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
asmlinkage long efab_linux_sys_shmat(int shmid, char __user *addr, int shmflg)
{
  SYSCALL_PTR_DEF(sys_shmat_fn, (int, char __user *, int));
  long rc;

  ci_assert(efrm_syscall_table);

  sys_shmat_fn = efrm_syscall_table[__NR_shmat];
  TRAMP_DEBUG ("shmat(%d,%p,%d) via %p...", shmid, addr, shmflg,
               sys_shmat_fn);
  rc = PASS_SYSCALL3(sys_shmat_fn, shmid, addr, shmflg);
  TRAMP_DEBUG ("... = %ld", rc);
  return rc;
}
asmlinkage int efab_linux_sys_shmdt(char __user *addr)
{
  SYSCALL_PTR_DEF(sys_shmdt_fn, (char __user *));
  int rc;

  ci_assert(efrm_syscall_table);

  sys_shmdt_fn = efrm_syscall_table[__NR_shmdt];
  TRAMP_DEBUG ("shmdt(%p) via %p...", addr, sys_shmdt_fn);
  rc = PASS_SYSCALL1(sys_shmdt_fn, addr);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
asmlinkage int efab_linux_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
  SYSCALL_PTR_DEF(sys_shmctl_fn, (int, int, struct shmid_ds __user *));
  int rc;

  ci_assert(efrm_syscall_table);

  sys_shmctl_fn = efrm_syscall_table[__NR_shmctl];
  TRAMP_DEBUG ("shmdt(%d,%d,%p) via %p...", shmid, cmd, buf, sys_shmctl_fn);
  rc = PASS_SYSCALL3(sys_shmctl_fn, shmid, cmd, buf);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
#endif


/* This function abstracts writing to the syscall.  Sadly some later kernels
 * map the syscall tables read-only.  Fidling with permissions is tricky, so we
 * just kmap ourselves a new mapping onto the table.
 */
static void
patch_syscall_table (void **table, unsigned entry, void *func,
                     void* prev_func)
{
  void *mapped;
  void **loc = table + entry;
  ci_uintptr_t offs = ((ci_uintptr_t)loc) & (PAGE_SIZE-1);
  struct page *pg;

  pg = virt_to_page (loc);

  TRAMP_DEBUG ("calling vmap (%p, 1, VM_MAP, PAGE_KERNEL)", pg);
  mapped = vmap (&pg, 1, VM_MAP, PAGE_KERNEL);
  TRAMP_DEBUG ("%s: mapped to %p", __FUNCTION__, mapped);
  if (mapped == NULL) {
    ci_log ("ERROR: could not map syscall table -- there will be no trampolining");
    return;
  }

  loc = (void**) ((ci_uintptr_t) mapped + offs);
  if( *loc == prev_func ) {
    TRAMP_DEBUG ("%s: writing to %p", __FUNCTION__, loc);
    *loc = func;
  }
  else
    ci_log("ERROR: Did not patch syscall table (*loc=%p prev_func=%p)",
           *loc, prev_func);

  TRAMP_DEBUG ("%s: unmapping", __FUNCTION__);
  vunmap (mapped);
  TRAMP_DEBUG ("%s: all done", __FUNCTION__);
}


/* This function initializes the mm hash-table, and hacks the sys call table
 * so that we intercept close.
 */
int efab_linux_trampoline_ctor(int no_sct)
{
  ci_assert(efrm_syscall_table);

  atomic_set(&efab_syscall_used, 0);
  if (efrm_syscall_table) {
    /* We really have to hope that efrm_syscall_table was found correctly.  There
     * is no reliable way to check it (e.g. by looking at the contents) which
     * will work on all platforms...
     */
    TRAMP_DEBUG("efrm_syscall_table=%p: close=%p exit_group=%p, rt_sigaction=%p",
                efrm_syscall_table, efrm_syscall_table[__NR_close],
                efrm_syscall_table[__NR_exit_group],
                efrm_syscall_table[__NR_rt_sigaction]);

    efab_linux_termination_ctor();

    saved_sys_close = efrm_syscall_table [__NR_close];
    saved_sys_exit_group = efrm_syscall_table [__NR_exit_group];
    saved_sys_rt_sigaction = efrm_syscall_table [__NR_rt_sigaction];

    ci_mb();
    if (no_sct) {
      TRAMP_DEBUG("syscalls NOT hooked - no_sct requested");
    } else {
      if( safe_signals_and_exit ) {
        patch_syscall_table (efrm_syscall_table, __NR_rt_sigaction,
                             efab_linux_trampoline_sigaction,
                             saved_sys_rt_sigaction);
      }
      TRAMP_DEBUG("syscalls hooked: rt_sigaction=%p",
                  efrm_syscall_table[__NR_rt_sigaction]);
    }
  } else {
    /* efrm_syscall_table wasn't found, so we may have no way to sys_close()... */
    OO_DEBUG_ERR(ci_log("ERROR: syscall table not found"));
    return -ENOEXEC;
  }

#ifdef CONFIG_COMPAT
  if (efrm_compat_syscall_table && !no_sct) {
    /* On pre-4.17 kernels we can do a sanity check on the
     * efrm_compat_syscall_table value: sys_close is the same for both
     * 64-bit and 32-bit, so the current entry for sys_close
     * in the 32-bit table should match the original value from the 64-bit
     * table, which we've saved in saved_sys_close in the code above.
     * For post-4.17 kernels with a new calling convention, the 32-bit entry
     * stub will be different, so no sensible check is possible here
     */
#ifndef EFRM_SYSCALL_PTREGS
#define CHECK_ENTRY(_n, _ptr) (efrm_compat_syscall_table[_n] == (_ptr))
#else
#define CHECK_ENTRY(_n, _ptr) 1
#endif
    TRAMP_DEBUG("efrm_compat_syscall_table=%p: "
                "rt_sigaction=%p", efrm_compat_syscall_table,
                efrm_compat_syscall_table[__NR_ia32_rt_sigaction]);
    saved_sys_rt_sigaction32 = efrm_compat_syscall_table[__NR_ia32_rt_sigaction];
    ci_mb();

    if( safe_signals_and_exit )
      patch_syscall_table (efrm_compat_syscall_table, __NR_ia32_rt_sigaction,
                           efab_linux_trampoline_sigaction32,
                           saved_sys_rt_sigaction32);
    TRAMP_DEBUG("ia32 syscalls hooked: rt_sigaction=%p",
                efrm_compat_syscall_table[__NR_ia32_rt_sigaction]);
  }
#undef CHECK_ENTRY
#endif

  return 0;
}


int stop_machine_do_nothing(void *arg)
{
  /* Can we somehow detect that we are in one of the intercepted syscalls?
   * May be ORC unwinder?
   * And even if we can, what can we do?  Wait and try again? */
  return 0;
}

void wait_for_other_syscall_callers(void)
{
  /* For some older kernels, we used to call synchronize_sched()
   * and it was a guarantee that any other CPU is not in the short chunk of
   * code between syscall enter and efab_syscall_used++, or between
   * efab_syscall_used-- and syscall exit.
   *
   * But even at that time, synchronize_sched() did not provide this
   * guarantee for CONFIG_PREEMPT-enabled kernel, because they MAY schedule
   * at the points described above.
   *
   * From linux-5.1, there is no synchronize_sched(), and it have been
   * more-or-less equivalent to synchronize_rcu() for a long time already.
   *
   * We are using stop_machine() to schedule all the CPUs, but it has the
   * same issue with CONFIG_PREEMPT-enabled kernel as the old
   * synchronize_sched() solution.
   */
  stop_machine(stop_machine_do_nothing, NULL, NULL);
#ifdef CONFIG_PREEMPT
  /* No guarantee, but let's try to wait */
  schedule_timeout(msecs_to_jiffies(50));
#endif
}

int
efab_linux_trampoline_dtor (int no_sct) {
  if (efrm_syscall_table != NULL && !no_sct) {
    int waiting = 0;

    /* Restore the system-call table to its proper state */
    if( safe_signals_and_exit ) {
      patch_syscall_table (efrm_syscall_table, __NR_rt_sigaction,
                           saved_sys_rt_sigaction,
                           efab_linux_trampoline_sigaction);
    }
    TRAMP_DEBUG("syscalls restored: rt_sigaction=%p",
                efrm_syscall_table[__NR_rt_sigaction]);

    /* If anybody have already entered our syscall handlers, he should get
     * to efab_syscall_used++ now: let's wait a bit. */
    wait_for_other_syscall_callers();

    while( atomic_read(&efab_syscall_used) ) {
      if( !waiting ) {
        ci_log("%s: Waiting for intercepted syscalls to finish...",
               __FUNCTION__);
        waiting = 1;
      }
      schedule_timeout(msecs_to_jiffies(50));
    }
    if( waiting )
      ci_log("%s: All syscalls have finished", __FUNCTION__);
    /* And now wait for exiting from syscall after efab_syscall_used-- */
    wait_for_other_syscall_callers();
  }

#ifdef CONFIG_COMPAT
  if (efrm_compat_syscall_table != NULL && !no_sct) {
    /* Restore the ia32 system-call table to its proper state */
    if( safe_signals_and_exit ) {
      patch_syscall_table (efrm_compat_syscall_table, __NR_ia32_rt_sigaction,
                           saved_sys_rt_sigaction32,
                           efab_linux_trampoline_sigaction32);
    }
    TRAMP_DEBUG("ia32 syscalls restored: rt_sigaction=%p",
                efrm_compat_syscall_table[__NR_ia32_rt_sigaction]);
  }
#endif

  return 0;
}


