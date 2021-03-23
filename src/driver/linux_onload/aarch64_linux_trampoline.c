/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include <ci/efrm/syscall.h>
#include "onload_kernel_compat.h"

#include <onload/linux_onload_internal.h>
#include <onload/linux_mmap.h>
#include <onload/linux_onload.h>
#include <asm/unistd.h>
#include <linux/unistd.h>
#include <asm/errno.h>
#include <asm/sysreg.h>
#include <asm/esr.h>
#include <asm/insn.h>
#include <asm/ptrace.h>

/* On 4.17+ on ARM64 the system calls are taking a single
   ptregs argument.
   (The user-space calling convention is the same as before, though).
*/
#ifdef EFRM_SYSCALL_PTREGS
#  define SYSCALL_PTR_DEF(_name)                                \
  asmlinkage long (*syscall_fn)(const struct pt_regs *regs) =   \
    efrm_syscall_table[__NR_##_name];
#  define PASS_SYSCALL1(_arg)                                   \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg)}))
#  define PASS_SYSCALL2(_arg1, _arg2)                           \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg1),        \
        .regs[1] = (u64)(_arg2)}))
#  define PASS_SYSCALL3(_arg1, _arg2, _arg3)                        \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg1),            \
        .regs[1] = (unsigned long)(_arg2),                          \
        .regs[2] = (unsigned long)(_arg3)}))
#  define PASS_SYSCALL4(_arg1, _arg2, _arg3, _arg4)                 \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg1),            \
        .regs[1] = (u64)(_arg2),                                    \
        .regs[2] = (u64)(_arg3),                                    \
        .regs[3] = (u64)(_arg4)}))
#  define PASS_SYSCALL6(_arg1, _arg2, _arg3, _arg4, _arg5, _arg6)   \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg1),            \
        .regs[1] = (u64)(_arg2),                                    \
        .regs[2] = (u64)(_arg3),                                    \
        .regs[3] = (u64)(_arg4),                                    \
        .regs[4] = (u64)(_arg5),                                    \
        .regs[5] = (u64)(_arg6)}))
#else
#  define SYSCALL_PTR_DEF(_name)                \
    asmlinkage typeof(_name) *syscall_fn = efrm_syscall_table[__NR_##name];
#  define PASS_SYSCALL1(_arg) (syscall_fn(_arg))
#  define PASS_SYSCALL2(_arg1, _arg2) (syscall_fn(_arg1, _arg2))
#  define PASS_SYSCALL3(_arg1, _arg2, _arg3) \
  (syscall_fn(_arg1, _arg2, _arg3))
#  define PASS_SYSCALL4(_arg1, _arg2, _arg3, _arg4)    \
  (syscall_fn(_arg1, _arg2, _arg3, _arg4))
#  define PASS_SYSCALL6(_arg1, _arg2, _arg3, _arg4, _arg5, _arg6)    \
  (syscall_fn(_arg1, _arg2, _arg3, _arg4, _arg5, _arg6))
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


asmlinkage int efab_linux_sys_close(int fd)
{
  int rc;
  SYSCALL_PTR_DEF(close);
  SET_SYSCALL_NO(close);
  rc = (int)PASS_SYSCALL1(fd);
  return rc;
}

int efab_linux_sys_epoll_create1(int flags)
{
  int rc;
  SYSCALL_PTR_DEF(epoll_create1);
  SET_SYSCALL_NO(epoll_create1);
  rc = (int)PASS_SYSCALL1(flags);
  return rc;
}

int efab_linux_sys_epoll_ctl(int epfd, int op, int fd,
                             struct epoll_event *event)
{
  int rc;
  SYSCALL_PTR_DEF(epoll_ctl);
  SET_SYSCALL_NO(epoll_ctl);
  rc = (int)PASS_SYSCALL4(epfd, op, fd, event);
  return rc;
}

int efab_linux_sys_epoll_wait(int epfd, struct epoll_event *events,
                              int maxevents, int timeout)
{
  int rc;
  SYSCALL_PTR_DEF(epoll_pwait);
  SET_SYSCALL_NO(epoll_pwait);
  rc = (int)PASS_SYSCALL6(epfd, events, maxevents, timeout,
                          NULL, sizeof(sigset_t));
  return rc;
}

int efab_linux_sys_sendmsg(int fd, struct msghdr __user* msg,
                           unsigned long __user* socketcall_args,
                           unsigned flags)
{
  int rc;
  SYSCALL_PTR_DEF(sendmsg);
  SET_SYSCALL_NO(sendmsg);
  rc = (int)PASS_SYSCALL3(fd, (struct user_msghdr __user *)msg, flags);
  return rc;
}


#ifdef OO_DO_HUGE_PAGES

int efab_linux_sys_shmget(key_t key, size_t size, int shmflg)
{
  int rc;
  SYSCALL_PTR_DEF(shmget);
  SET_SYSCALL_NO(shmget);
  rc = (int)PASS_SYSCALL3(key, size, shmflg);
  return rc;
}

long efab_linux_sys_shmat(int shmid, char __user *addr, int shmflg)
{
  long rc;
  SYSCALL_PTR_DEF(shmat);
  SET_SYSCALL_NO(shmat);
  rc = (long)PASS_SYSCALL3(shmid, addr, shmflg);
  return rc;
}

int efab_linux_sys_shmdt(char __user *addr)
{
  int rc;
  SYSCALL_PTR_DEF(shmdt);
  SET_SYSCALL_NO(shmdt);
  rc = (int)PASS_SYSCALL1(addr);
  return rc;
}

int efab_linux_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
  int rc;
  SYSCALL_PTR_DEF(shmctl);
  SET_SYSCALL_NO(shmctl);
  rc = (int)PASS_SYSCALL3(shmid, cmd, buf);
  return rc;
}
#endif

