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

extern int efab_linux_trampoline_ctor(void);

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


#endif
/*! \cidoxg_end */
