/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#ifndef __CI_EFRM_SYSCALL_H__
#define __CI_EFRM_SYSCALL_H__

#include <linux/version.h>
#include "debug.h"

/* On 4.17+ on x86_64 and ARM64 the system calls are taking a single
   ptregs argument.
   (The user-space calling convention is the same as before, though).
*/
#if (defined(__x86_64__) || defined(__aarch64__)) &&    \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define EFRM_SYSCALL_PTREGS 1
#endif

extern void** efrm_syscall_table;

#ifdef CONFIG_COMPAT
extern void** efrm_compat_syscall_table;
#endif

#ifdef __x86_64__
/* The address of entry_SYSCALL_64() */
extern void *efrm_entry_SYSCALL_64_addr;
#endif

extern int efrm_syscall_ctor(void);

#ifdef __x86_64__
/* On 4.17+ on x86_64 the system calls are taking a single
   ptregs argument.
   (The user-space calling convention is the same as before, though).
*/
#ifdef EFRM_SYSCALL_PTREGS
#  define SYSCALL_PTR_DEF(_name, _sig)                          \
  asmlinkage long (*syscall_fn)(const struct pt_regs *regs) =   \
    efrm_syscall_table[__NR_##_name]
#  define PASS_SYSCALL1(_arg)                \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg)}))
#  define PASS_SYSCALL2(_arg1, _arg2)                                   \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg1),           \
      .si = (unsigned long)(_arg2)}))
#  define PASS_SYSCALL3(_arg1, _arg2, _arg3)                            \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg1),           \
      .si = (unsigned long)(_arg2),                                     \
      .dx = (unsigned long)(_arg3)}))
#  define PASS_SYSCALL4(_arg1, _arg2, _arg3, _arg4)                     \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg1),           \
      .si = (unsigned long)(_arg2),                                     \
      .dx = (unsigned long)(_arg3),                                     \
      .r10 = (unsigned long)(_arg4)}))
#  define PASS_SYSCALL5(_arg1, _arg2, _arg3, _arg4, _arg5)              \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg1),           \
      .si = (unsigned long)(_arg2),                                     \
      .dx = (unsigned long)(_arg3),                                     \
      .r10 = (unsigned long)(_arg4),                                    \
      .r8 = (unsigned long)(_arg5)}))
#  define PASS_SYSCALL6(_arg1, _arg2, _arg3, _arg4, _arg5, _arg6)       \
  (syscall_fn(&(struct pt_regs){.di = (unsigned long)(_arg1),           \
      .si = (unsigned long)(_arg2),                                     \
      .dx = (unsigned long)(_arg3),                                     \
      .r10 = (unsigned long)(_arg4),                                    \
      .r8 = (unsigned long)(_arg5),                                     \
      .r9 = (unsigned long)(_arg6)}))
#else
#  define SYSCALL_PTR_DEF(_name, _sig)         \
    asmlinkage long (*syscall_fn)_sig = efrm_syscall_table[__NR_##_name]
#  define PASS_SYSCALL1(_arg) (syscall_fn(_arg))
#  define PASS_SYSCALL2(_arg1, _arg2) (syscall_fn(_arg1, _arg2))
#  define PASS_SYSCALL3(_arg1, _arg2, _arg3) \
  (syscall_fn(_arg1, _arg2, _arg3))
#  define PASS_SYSCALL4(_arg1, _arg2, _arg3, _arg4)    \
  (syscall_fn(_arg1, _arg2, _arg3, _arg4))
#  define PASS_SYSCALL5(_arg1, _arg2, _arg3, _arg4, _arg5)    \
  (syscall_fn(_arg1, _arg2, _arg3, _arg4, _arg5))
#  define PASS_SYSCALL6(_arg1, _arg2, _arg3, _arg4, _arg5, _arg6)    \
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
#  define PASS_SYSCALL1(_arg)                                   \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg)}))
#  define PASS_SYSCALL2(_arg1, _arg2)                           \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg1),        \
        .regs[1] = (u64)(_arg2)}))
#  define PASS_SYSCALL3(_arg1, _arg2, _arg3)                        \
  (syscall_fn(&(struct pt_regs){.regs[0] = (u64)(_arg1),            \
        .regs[1] = (u64)(_arg2),                                    \
        .regs[2] = (u64)(_arg3)}))
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

/* This macro should be used as the sole content of a syscall caller function.
 * The surrounding function definition is omitted from this macro solely
 * because it's tricky to come up with a compact way to get parameter types
 * and names defined in a readable way. If the containing function is static
 * then it should also be noinline (see SET_SYSCALL_NO). */
#define SYSCALL_DISPATCHn(_n, _name, _sig, ...)                   \
  ({                                                              \
    SYSCALL_PTR_DEF(_name, _sig);                                 \
    EFRM_ASSERT(syscall_fn != NULL);                              \
    SET_SYSCALL_NO(_name);                                        \
    PASS_SYSCALL##_n(__VA_ARGS__);                                \
  })

#endif /* __CI_EFRM_SYSCALL_H__ */
