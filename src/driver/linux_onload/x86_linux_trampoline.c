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

/* A way to call the original sys_close, exported to other parts of the code.
 */
asmlinkage int efab_linux_sys_close(int fd)
{
  SYSCALL_PTR_DEF(sys_close_fn, (int));
  int rc;

  if( efrm_syscall_table == NULL ) {
    ci_log("Unexpected close() request before full init");
    return -EFAULT;
  }

  sys_close_fn = efrm_syscall_table[__NR_close];
  TRAMP_DEBUG ("close %d via %p...", fd, sys_close_fn);
  rc = PASS_SYSCALL1(sys_close_fn, fd);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
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

