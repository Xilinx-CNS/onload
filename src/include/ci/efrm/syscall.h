/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#ifndef __CI_EFRM_SYSCALL_H__
#define __CI_EFRM_SYSCALL_H__

#include <linux/version.h>
#include "debug.h"
#include <ci/driver/kernel_compat.h>

/* On 4.17+ on x86_64 and ARM64 the system calls are taking a single
   ptregs argument.
   (The user-space calling convention is the same as before, though).
*/
#if (defined(__x86_64__) || defined(__aarch64__))
#define EFRM_SYSCALL_PTREGS 1
#endif

extern void** efrm_syscall_table;

#if defined(__x86_64__)
/* forward declaration needed for function pointer */
struct pt_regs;
typedef long (*syscall_fn_t)(const struct pt_regs *regs, unsigned int nr);
extern syscall_fn_t efrm_x64_sys_call;
extern long efrm_syscall_table_call(const struct pt_regs *regs, unsigned int nr);
#endif

extern int efrm_syscall_ctor(void);

#ifdef __x86_64__
/* On 4.17+ on x86_64 the system calls are taking a single
   ptregs argument.
   (The user-space calling convention is the same as before, though).
*/
#ifdef EFRM_SYSCALL_PTREGS


#  define SYSCALL_PTR_DEF(_name, _sig)                                         \
  asmlinkage syscall_fn_t syscall_fn = \
  efrm_syscall_table ? efrm_syscall_table_call : efrm_x64_sys_call
#  define PASS_SYSCALL1(_name, _arg)                \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg)}, __NR_##_name))
#  define PASS_SYSCALL2(_name, _arg1, _arg2)                            \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg1),           \
      .si = (unsigned long)(_arg2)}, __NR_##_name))
#  define PASS_SYSCALL3(_name, _arg1, _arg2, _arg3)                     \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg1),           \
      .si = (unsigned long)(_arg2),                                     \
      .dx = (unsigned long)(_arg3)}, __NR_##_name))
#  define PASS_SYSCALL4(_name, _arg1, _arg2, _arg3, _arg4)              \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg1),           \
      .si = (unsigned long)(_arg2),                                     \
      .dx = (unsigned long)(_arg3),                                     \
      .r10 = (unsigned long)(_arg4)}, __NR_##_name))
#  define PASS_SYSCALL5(_name, _arg1, _arg2, _arg3, _arg4, _arg5)       \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg1),           \
      .si = (unsigned long)(_arg2),                                     \
      .dx = (unsigned long)(_arg3),                                     \
      .r10 = (unsigned long)(_arg4),                                    \
      .r8 = (unsigned long)(_arg5)}, __NR_##_name))
#  define PASS_SYSCALL6(_name, _arg1, _arg2, _arg3, _arg4, _arg5, _arg6)\
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg1),           \
      .si = (unsigned long)(_arg2),                                     \
      .dx = (unsigned long)(_arg3),                                     \
      .r10 = (unsigned long)(_arg4),                                    \
      .r8 = (unsigned long)(_arg5),                                     \
      .r9 = (unsigned long)(_arg6)}, __NR_##_name))
#else
#  define SYSCALL_PTR_DEF(_name, _sig)         \
    asmlinkage long (*syscall_fn)_sig = efrm_syscall_table[__NR_##_name]
#  define PASS_SYSCALL1(_name, _arg) (syscall_fn(_arg))
#  define PASS_SYSCALL2(_name, _arg1, _arg2) (syscall_fn(_arg1, _arg2))
#  define PASS_SYSCALL3(_name, _arg1, _arg2, _arg3) \
  (syscall_fn(_arg1, _arg2, _arg3))
#  define PASS_SYSCALL4(_name, _arg1, _arg2, _arg3, _arg4)    \
  (syscall_fn(_arg1, _arg2, _arg3, _arg4))
#  define PASS_SYSCALL5(_name, _arg1, _arg2, _arg3, _arg4, _arg5)    \
  (syscall_fn(_arg1, _arg2, _arg3, _arg4, _arg5))
#  define PASS_SYSCALL6(_name, _arg1, _arg2, _arg3, _arg4, _arg5, _arg6)    \
  (syscall_fn(_arg1, _arg2, _arg3, _arg4, _arg5, _arg6))
#endif

#define SET_SYSCALL_NO(_sc)
#endif  /* __x86_64__ */

#ifdef __aarch64__
/* On 4.17+ on ARM64 the system calls are taking a single
   ptregs argument.
   (The user-space calling convention is the same as before, though).
*/
#ifdef EFRM_SYSCALL_PTREGS
#  define SYSCALL_PTR_DEF(_name, _sig)                          \
  asmlinkage long (*syscall_fn)(const struct pt_regs *regs) =   \
    efrm_syscall_table[__NR_##_name]
#  define PASS_SYSCALL1(_name, _arg)                            \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg)}))
#  define PASS_SYSCALL2(_name, _arg1, _arg2)                    \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg1),        \
        .regs[1] = (u64)(_arg2)}))
#  define PASS_SYSCALL3(_name, _arg1, _arg2, _arg3)                 \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg1),            \
        .regs[1] = (u64)(_arg2),                                    \
        .regs[2] = (u64)(_arg3)}))
#  define PASS_SYSCALL4(_name, _arg1, _arg2, _arg3, _arg4)          \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg1),            \
        .regs[1] = (u64)(_arg2),                                    \
        .regs[2] = (u64)(_arg3),                                    \
        .regs[3] = (u64)(_arg4)}))
#  define PASS_SYSCALL6(_name, _arg1, _arg2, _arg3, _arg4, _arg5, _arg6)   \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg1),            \
        .regs[1] = (u64)(_arg2),                                    \
        .regs[2] = (u64)(_arg3),                                    \
        .regs[3] = (u64)(_arg4),                                    \
        .regs[4] = (u64)(_arg5),                                    \
        .regs[5] = (u64)(_arg6)}))
#else
#  define SYSCALL_PTR_DEF(_name, _sig)                \
    asmlinkage typeof(_name) *syscall_fn = efrm_syscall_table[__NR_##name]
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

#endif /* __aarch64__ */

#ifdef EFRM_HAVE_EPOLL_PWAIT2
#define IF_EFRM_HAVE_EPOLL_PWAIT2(x) x
#else
#define IF_EFRM_HAVE_EPOLL_PWAIT2(x)
#endif

/* This list must contain all syscalls we want to use in the SYSCALL_DISPATCHn
 * macro below. */
#define FOR_EACH_DISPATCHABLE_SYSCALL(OP) \
  OP(epoll_create1) \
  OP(epoll_ctl) \
  OP(epoll_pwait) \
  OP(epoll_wait) \
  IF_EFRM_HAVE_EPOLL_PWAIT2(OP(epoll_pwait2)) \
  OP(bpf)

/* To avoid the above list becoming stale, we assert that all call sites for
 * SYSCALL_DISPATCHn register their respective syscall name at build time.
 * This works by creating a struct from the list of valid syscalls, where each
 * is an integer member, and asserting the size of the member corresponding
 * with the syscall we are trying to dispatch exists within that struct. */
#define SYSCALL_DEFINE_INT(syscall) int syscall;
#define EFRM_BUILD_ASSERT_SYSCALL_DISPATCHABLE(syscall) \
  ({ \
    struct { \
      FOR_EACH_DISPATCHABLE_SYSCALL(SYSCALL_DEFINE_INT) \
    } x; \
    EFRM_BUILD_ASSERT(sizeof(x.syscall) != 0); \
  })

/* This macro should be used as the sole content of a syscall caller function.
 * The surrounding function definition is omitted from this macro solely
 * because it's tricky to come up with a compact way to get parameter types
 * and names defined in a readable way. If the containing function is static
 * then it should also be noinline (see SET_SYSCALL_NO). */
#define SYSCALL_DISPATCHn(_n, _name, _sig, ...)                   \
  ({                                                              \
    SYSCALL_PTR_DEF(_name, _sig);                                 \
    EFRM_BUILD_ASSERT_SYSCALL_DISPATCHABLE(_name);                \
    EFRM_ASSERT(syscall_fn != NULL);                              \
    SET_SYSCALL_NO(_name);                                        \
    PASS_SYSCALL##_n(_name, __VA_ARGS__);                         \
  })

#endif /* __CI_EFRM_SYSCALL_H__ */
