/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include <ci/efrm/syscall.h>
#include "onload_kernel_compat.h"

#include <onload/linux_onload_internal.h>
#include <onload/linux_trampoline.h>
#include <onload/linux_mmap.h>
#include <onload/linux_onload.h>
#include <asm/unistd.h>
#include <linux/unistd.h>
#include <asm/errno.h>
#include <asm/sysreg.h>
#include <asm/esr.h>
#include <asm/insn.h>
#include <asm/ptrace.h>
#include <linux/stop_machine.h>

/* On 4.17+ on ARM64 the system calls are taking a single
   ptregs argument.
   (The user-space calling convention is the same as before, though).
*/
#ifdef EFRM_SYSCALL_PTREGS
#  define SYSCALL_PTR_DEF(_name)                        \
  asmlinkage long (*saved_##_name)(const struct pt_regs *regs)
#  define PASS_SYSCALL1(_name, _arg)                    \
  ((saved_##_name)(&(struct pt_regs){.regs[0] = (u64)(_arg)}))
#  define PASS_SYSCALL2(_name, _arg1, _arg2)                  \
  ((saved_##_name)(&(struct pt_regs){.regs[0] = (u64)(_arg1), \
        .regs[1] = (u64)(_arg2)}))
#  define PASS_SYSCALL3(_name, _arg1, _arg2, _arg3)                     \
  ((saved_##_name)(&(struct pt_regs){.regs[0] = (u64)(_arg1),           \
        .regs[1] = (unsigned long)(_arg2),                              \
        .regs[2] = (unsigned long)(_arg3)}))
#  define PASS_SYSCALL4(_name, _arg1, _arg2, _arg3, _arg4)              \
  ((saved_##_name)(&(struct pt_regs){.regs[0] = (u64)(_arg1),           \
        .regs[1] = (u64)(_arg2),                                        \
        .regs[2] = (u64)(_arg3),                                        \
        .regs[3] = (u64)(_arg4)}))
#  define PASS_SYSCALL6(_name, _arg1, _arg2, _arg3, _arg4, _arg5, _arg6) \
  ((saved_##_name)(&(struct pt_regs){.regs[0] = (u64)(_arg1),           \
        .regs[1] = (u64)(_arg2),                                        \
        .regs[2] = (u64)(_arg3),                                        \
        .regs[3] = (u64)(_arg4),                                        \
        .regs[4] = (u64)(_arg5),                                        \
        .regs[5] = (u64)(_arg6)}))
#else
#  define SYSCALL_PTR_DEF(_name)                \
    asmlinkage typeof(_name) *saved_##_name
#  define PASS_SYSCALL1(_name, _arg) ((saved_##_name)(_arg))
#  define PASS_SYSCALL2(_name, _arg1, _arg2) ((saved_##_name)(_arg1, _arg2))
#  define PASS_SYSCALL3(_name, _arg1, _arg2, _arg3) \
  ((saved_##_name)(_arg1, _arg2, _arg3))
#  define PASS_SYSCALL4(_name, _arg1, _arg2, _arg3, _arg4)    \
  ((saved_##_name)(_arg1, _arg2, _arg3, _arg4))
#  define PASS_SYSCALL6(_name, _arg1, _arg2, _arg3, _arg4, _arg5, _arg6)    \
  ((saved_##_name)(_arg1, _arg2, _arg3, _arg4, _arg5, _arg6))
#endif

/* ARM64 TODO these are stub implementations only */
atomic_t efab_syscall_used;

#ifndef NDEBUG

void efab_linux_trampoline_ul_fail(void)
{
  return;
}

#endif

/*
 * This is somewhat dubious. On the one hand, the syscall
 * number is available to the syscall routine in x8 register,
 * so if it would ever like to consult it, it should be very much
 * upset by finding some random garbage there.
 * On another hand, in most contexts x8 is just a scratch register,
 * so the compiler theoretically could use it for its own purposes,
 * which the following code would mess up with. (Note that x8 is
 * _intentionally_ not marked as clobbered in the asm statement, so
 * that it would be forwarded to the original syscall).
 * However, in such short functions as our thunks, it seems unlikely and
 * empirically confirmed not to be.
 */
#define SET_SYSCALL_NO(_sc) \
  asm volatile("mov x8, %0" :: "i" (__NR_##_sc))

static SYSCALL_PTR_DEF(sys_close);

asmlinkage int efab_linux_sys_close(int fd)
{
  int rc;
  SET_SYSCALL_NO(close);
  rc = (int)PASS_SYSCALL1(sys_close, fd);
  return rc;
}

static SYSCALL_PTR_DEF(sys_exit_group);

asmlinkage int efab_linux_sys_exit_group(int status)
{
  int rc;
  SET_SYSCALL_NO(exit_group);
  rc = (int)PASS_SYSCALL1(sys_exit_group, status);
  return rc;
}

static SYSCALL_PTR_DEF(sys_epoll_create1);

int efab_linux_sys_epoll_create1(int flags)
{
  int rc;
  SET_SYSCALL_NO(epoll_create1);
  rc = (int)PASS_SYSCALL1(sys_epoll_create1, flags);
  return rc;
}

static SYSCALL_PTR_DEF(sys_epoll_ctl);

int efab_linux_sys_epoll_ctl(int epfd, int op, int fd,
                             struct epoll_event *event)
{
  int rc;
  SET_SYSCALL_NO(epoll_ctl);
  rc = (int)PASS_SYSCALL4(sys_epoll_ctl, epfd, op, fd, event);
  return rc;
}

static SYSCALL_PTR_DEF(sys_epoll_pwait);

int efab_linux_sys_epoll_wait(int epfd, struct epoll_event *events,
                              int maxevents, int timeout)
{
  int rc;
  SET_SYSCALL_NO(epoll_pwait);
  rc = (int)PASS_SYSCALL6(sys_epoll_pwait,
                          epfd, events, maxevents, timeout,
                          NULL, sizeof(sigset_t));
  return rc;
}

static SYSCALL_PTR_DEF(sys_rt_sigaction);

int efab_linux_sys_sigaction(int signum,
                             const struct sigaction *act,
                             struct sigaction *oact)
{
  int rc;
  SET_SYSCALL_NO(rt_sigaction);
  rc = (int)PASS_SYSCALL4(sys_rt_sigaction, signum, act, oact, sizeof(sigset_t));
  return rc;
}

static SYSCALL_PTR_DEF(sys_sendmsg);

int efab_linux_sys_sendmsg(int fd, struct msghdr __user* msg,
                           unsigned long __user* socketcall_args,
                           unsigned flags)
{
  int rc;
  SET_SYSCALL_NO(sendmsg);
  rc = (int)PASS_SYSCALL3(sys_sendmsg, fd, (struct user_msghdr __user *)msg, flags);
  return rc;
}

#ifdef CONFIG_COMPAT
int
efab_linux_sys_sendmsg32(int fd, struct compat_msghdr __user* msg,
                         unsigned long __user* socketcall_args,
                         unsigned flags)
{
  return 0;
}

int efab_linux_sys_sigaction32(int signum,
                               const struct sigaction32 *act,
                               struct sigaction32 *oact)
{
  return 0;
}
#endif


static inline int /* bool */
tramp_close_begin(int fd, ci_uintptr_t *tramp_entry_out)
{
  struct file *f;
  efab_syscall_enter();

  f = fget(fd);
  if( f != NULL ) {
    if( FILE_IS_ENDPOINT(f) ) {
      struct mm_hash *p;

      read_lock (&oo_mm_tbl_lock);
      p = oo_mm_tbl_lookup(current->mm);
      if (p) {
        *tramp_entry_out =
            (ci_uintptr_t)CI_USER_PTR_GET(p->trampoline_entry);
      }
      read_unlock (&oo_mm_tbl_lock);

      if( *tramp_entry_out != 0 &&
          efab_access_ok((const void *)*tramp_entry_out, 1)) {
        fput(f);
        return true;
      }
    }
    fput(f);
  }

  /* Not one of our FDs -- usual close */
  return false;
}

static inline int
tramp_close_passthrough(int fd)
{
  int rc = PASS_SYSCALL1(sys_close, fd);
  efab_syscall_exit();
  return rc;
}

#ifndef EFRM_SYSCALL_PTREGS
asmlinkage long efab_linux_aarch64_trampoline_close(int fd, struct pt_regs *regs)
#else
asmlinkage int efab_linux_trampoline_close(struct pt_regs *regs)
#endif
{
#ifdef EFRM_SYSCALL_PTREGS
  int fd = regs->regs[0];
#endif
  ci_uintptr_t trampoline_entry = 0;

  if (!tramp_close_begin(fd, &trampoline_entry))
      return tramp_close_passthrough(fd);

  regs->regs[1] = fd;
  regs->regs[2] = regs->pc;

  /* Hack the return address on the stack to do the trampoline */
  regs->pc = trampoline_entry;

  efab_syscall_exit();
  /* this is the return value in x0 that will become the first argument
     of trampoline_entry */
  return CI_TRAMP_OPCODE_CLOSE;
}

struct patch_item {
    unsigned syscall;
    void *addr;
};

static int patch_syscall_table(void **table,
                               const struct patch_item *patches)
{

  for (; patches->addr != NULL; patches++) {
    int rc = probe_kernel_write(table + patches->syscall, &patches->addr,
                                sizeof(patches->addr));
    if (rc != 0) {
      unsigned offset = ((uintptr_t)(table + patches->syscall) &
                         ~PAGE_MASK) / sizeof(*table);
      struct page *page = phys_to_page(__pa_symbol(table +
                                                   patches->syscall));
      void **waddr;
      BUG_ON(!page);

      waddr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
      if (waddr == NULL)
      {
        ci_log("cannot map sys_call_table r/w");
        return -EFAULT;
      }

      if (waddr[offset] != table[patches->syscall])
      {
        ci_log("mapped table mismatch: %p != %p",
               waddr[offset], table[patches->syscall]);
        vunmap(waddr);
        return -EFAULT;
      }

      waddr[offset] = patches->addr;

      vunmap(waddr);
    }
  }
  return 0;
}

int efab_linux_trampoline_ctor(int no_sct)
{
  void *check_sys_close;

  ci_assert(efrm_syscall_table);

  atomic_set(&efab_syscall_used, 0);
  efab_linux_termination_ctor();

  saved_sys_close = efrm_syscall_table[__NR_close];
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
  check_sys_close = efrm_find_ksym("__arm64_sys_close");
#else
  check_sys_close = efrm_find_ksym("sys_close");
#endif
  if (check_sys_close != NULL) {
    if (check_sys_close != saved_sys_close) {
      ci_log("ERROR: sys_close address does not match (%p != %p)",
             check_sys_close, saved_sys_close);
      return -EFAULT;
    }
  }
  saved_sys_exit_group = efrm_syscall_table[__NR_exit_group];
  saved_sys_sendmsg = efrm_syscall_table[__NR_sendmsg];
  saved_sys_rt_sigaction = efrm_syscall_table[__NR_rt_sigaction];
  saved_sys_epoll_create1 = efrm_syscall_table[__NR_epoll_create1];
  saved_sys_epoll_ctl = efrm_syscall_table[__NR_epoll_ctl];
  saved_sys_epoll_pwait = efrm_syscall_table[__NR_epoll_pwait];

  if (!no_sct) {
    struct patch_item patches[] = {
      {__NR_close, efab_linux_trampoline_close},
      {__NR_exit_group, efab_linux_trampoline_exit_group},
      {__NR_rt_sigaction, efab_linux_trampoline_sigaction},
      {0, NULL}
    };
    int rc = patch_syscall_table(efrm_syscall_table, patches);

    if (rc != 0)
      return rc;
  }

  return 0;
}

/* See wait_for_other_syscall_callers() in x86_linux_trampoline.c */
static int stop_machine_do_nothing(void *arg)
{
  return 0;
}


int efab_linux_trampoline_dtor (int no_sct)
{
  if (!no_sct) {
    int waiting = 0;
    struct patch_item patches[] = {
      {__NR_close, *saved_sys_close},
      {__NR_exit_group, *saved_sys_exit_group},
      {__NR_rt_sigaction, *saved_sys_rt_sigaction},
      {0, NULL}
    };
    int rc = patch_syscall_table(efrm_syscall_table, patches);

    if (rc != 0)
      return rc;

    /* If anybody have already entered our syscall handlers, he should get
     * to efab_syscall_used++ now: let's wait a bit.
     *
     * See wait_for_other_syscall_callers() in x86_linux_trampoline.c
     * for further details
     */
    stop_machine(stop_machine_do_nothing, NULL, NULL);
#ifdef CONFIG_PREEMPT
    /* No guarantee, but let's try to wait */
    schedule_timeout(msecs_to_jiffies(50));
#endif
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
    stop_machine(stop_machine_do_nothing, NULL, NULL);
#ifdef CONFIG_PREEMPT
    /* No guarantee, but let's try to wait */
    schedule_timeout(msecs_to_jiffies(50));
#endif
  }

  return 0;
}
