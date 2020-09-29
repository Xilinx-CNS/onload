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

#ifdef CONFIG_COMPAT
int efab_linux_sys_sigaction32(int signum,
                               const struct sigaction32 *act,
                               struct sigaction32 *oact)
{
  return 0;
}
#endif


int efab_linux_trampoline_ctor()
{
  void *check_sys_close;

  ci_assert(efrm_syscall_table);

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
  saved_sys_rt_sigaction = efrm_syscall_table[__NR_rt_sigaction];
  saved_sys_epoll_create1 = efrm_syscall_table[__NR_epoll_create1];
  saved_sys_epoll_ctl = efrm_syscall_table[__NR_epoll_ctl];
  saved_sys_epoll_pwait = efrm_syscall_table[__NR_epoll_pwait];

  return 0;
}

/* See wait_for_other_syscall_callers() in x86_linux_trampoline.c */
static int stop_machine_do_nothing(void *arg)
{
  return 0;
}

