/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file linux_trampoline.h
** <L5_PRIVATE L5_HEADER >
** \author  gel,mjs
**  \brief  System call trampolines for Linux
**   \date  2005/03/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_LINUX_TRAMPOLINE_H__
#define __CI_DRIVER_EFAB_LINUX_TRAMPOLINE_H__

#include <ci/internal/transport_config_opt.h>
#include <ci/internal/trampoline.h>
#include <onload/common.h>
#include <onload/fd_private.h>

#ifndef __ci_driver__
#error "This is a driver module."
#endif

/* Count users of our syscall interceprion.  Prevent crash when close()
 * with SO_LINGER runs if Onload module is unloaded simultaneously.
 */
extern atomic_t efab_syscall_used;
static inline void efab_syscall_enter(void)
{
  atomic_inc(&efab_syscall_used);
  ci_wmb();
}
static inline void efab_syscall_exit(void)
{
  /* For non-PREEMPT kernel, we'll exit our code just after this,
   * so synchronize_sched() in unload code is safe enough. 
   * For CONFIG_PREEMPT, we'd like to preempt_disable() for the next few
   * instructions.  Unluckily, we have no way to do this. */
#ifdef CONFIG_PREEMPT
#ifdef preempt_check_resched
  preempt_check_resched(); /* try to be more safe: better resched now */
#endif
#endif

  atomic_dec(&efab_syscall_used);
}

extern int efab_linux_trampoline_ctor(int no_sct);
extern int efab_linux_trampoline_dtor(int no_sct);
extern int efab_linux_trampoline_register(ci_private_t *priv, void *arg);

#ifdef EFRM_SYSCALL_PTREGS
extern asmlinkage int efab_linux_trampoline_close(struct pt_regs *regs);
#ifdef CONFIG_COMPAT
extern asmlinkage int efab_linux_trampoline_close32(struct pt_regs *regs);
#endif
#else
extern asmlinkage int efab_linux_trampoline_close(int fd);
#ifdef CONFIG_COMPAT
extern asmlinkage int efab_linux_trampoline_close32(int fd);
#endif
#endif
extern asmlinkage int efab_linux_trampoline_ioctl (unsigned int fd,
                                                   unsigned int cmd,
                                                   unsigned long arg);

/* Close trampoline: gates between C and asm.
 * The gates have different parameters to make asm simpler. */
#ifdef EFRM_SYSCALL_PTREGS
extern asmlinkage long
efab_linux_trampoline_handler_close64(struct pt_regs *regs);
#ifdef CONFIG_COMPAT
extern asmlinkage int
efab_linux_trampoline_handler_close32(struct pt_regs *regs);
#endif
#else
extern asmlinkage long
efab_linux_trampoline_handler_close64(int fd);
#ifdef CONFIG_COMPAT
extern asmlinkage int
efab_linux_trampoline_handler_close32(unsigned long bx, unsigned long cx,
                                      unsigned long dx, unsigned long si,
                                      unsigned long di, unsigned long bp,
                                      struct pt_regs *regs);
#endif
#endif

extern int safe_signals_and_exit;
#ifdef EFRM_SYSCALL_PTREGS
extern asmlinkage long efab_linux_trampoline_exit_group(const struct pt_regs *regs);
#else
extern asmlinkage long efab_linux_trampoline_exit_group(int status);
#endif
extern void efab_linux_termination_ctor(void);

#ifdef EFRM_SYSCALL_PTREGS
extern asmlinkage long
efab_linux_trampoline_sigaction(const struct pt_regs *regs);
#else
extern asmlinkage long
efab_linux_trampoline_sigaction(int sig, const struct sigaction *act,
                                struct sigaction *oact, size_t sigsetsize);
#endif

#ifdef CONFIG_COMPAT
/* ARM64 TODO */
#if ! defined (__PPC__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
# include <linux/compat.h>
# define sigaction32 compat_sigaction
#else
# include <asm/ia32.h>
#endif
#else
#include <linux/compat.h>
/* sigaction32 is not public on PPC, extracted from arch/powerpc/kernel/ppc32.h */
/* It shall not be a problem, since it's kernel-to-userspace interface which 
 * unlikely to change
 */
struct sigaction32 {
       compat_uptr_t  sa_handler;       /* Really a pointer, but need to deal with 32 bits */
       unsigned int sa_flags;
       compat_uptr_t sa_restorer;       /* Another 32 bit pointer */
       compat_sigset_t sa_mask;         /* A 32 bit mask */
};
#endif

#ifdef EFRM_SYSCALL_PTREGS
extern asmlinkage int
efab_linux_trampoline_sigaction32(const struct pt_regs *regs);
#else
extern asmlinkage int
efab_linux_trampoline_sigaction32(int sig, const struct sigaction32 *act32,
                                  struct sigaction32 *oact32,
                                  unsigned int sigsetsize);
#endif
#endif


struct mm_hash;
struct mm_signal_data;
extern int efab_signal_mm_init(const ci_tramp_reg_args_t *args,
                               struct mm_hash *p);
extern void efab_signal_process_init(struct mm_signal_data *tramp_data);
extern void efab_signal_process_fini(struct mm_signal_data *tramp_data);
extern int efab_signal_die(ci_private_t *priv_unused, void *arg);
extern void efab_signal_put_tramp_data(struct mm_signal_data *tramp_data);

#endif
/*! \cidoxg_end */
