/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2019 Xilinx, Inc. */
/*
** Copyright 2012     Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
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
*//*! \file linux_trampoline_ppc64.c System call trampolines for Linux/PPC64
** <L5_PRIVATE L5_SOURCE>
** \author  <rrw@kynesim.co.uk>
**  \brief  Package - driver/linux	Linux driver support
**   \date  2012/11/27
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

#include <onload/linux_onload_internal.h>
#include <onload/linux_trampoline.h>
#include <onload/linux_mmap.h>
#include <onload/linux_onload.h>
#include <linux/unistd.h>
#include "ppc64_linux_trampoline_internal.h"

/* Debugging for internal use only */
#  define TRAMP_DEBUG(x...) (void)0

#define TRAMPOLINE_BITS_64  0
#define TRAMPOLINE_BITS_32  1

typedef struct state_struct
{
    syscall_entry_t *replace_close;
    syscall_entry_t *replace_exit_group;
    syscall_entry_t *replace_rt_sigaction;
    
    /* We don't actually replace these syscalls, but we do thunk them so
     * that we can call them ourselves.
     */
    syscall_entry_t *no_replace_epoll_create1;
    syscall_entry_t *no_replace_epoll_create;

    syscall_entry_t *no_replace_epoll_ctl;
    syscall_entry_t *no_replace_epoll_wait;

    syscall_entry_t *no_replace_socketcall;
} state_t;

state_t state;
atomic_t efab_syscall_used;

static int setup_trampoline(struct pt_regs *regs, 
                            int opcode, int arg, 
                            int bits);

/* We (somewhat arbitrarily) regard calls from onload as calls to the 64-bit
 *  syscall entry points.
 */

asmlinkage int efab_linux_sys_close(int fd)
{
    int rc;

    if (state.replace_close)
    {
        TRAMP_DEBUG ("close %d via saved_sys_close=%p...", fd, THUNKPTR(state.replace_close->original_entry64));
        rc = ((int (*)(int))THUNKPTR(state.replace_close->original_entry64))(fd);
        TRAMP_DEBUG (".. = %d", rc);
    }
    else
    {
        ci_log("Unexpected close() request before full init");
        return -EFAULT;
    }
    return rc;
}

asmlinkage int efab_linux_sys_exit_group(int status)
{
    if (state.replace_exit_group)
    {
        return ((int (*)(int))THUNKPTR(state.replace_exit_group->original_entry64))(status);
    }
    else
    {
        ci_log("Unexpected exit_group() request before full init");
        return -EFAULT;
    }
}

asmlinkage int efab_linux_sys_epoll_create1(int flags)
{
    asmlinkage int (*sys_epoll_create_fn)(int);
    int rc;

    if (state.no_replace_epoll_create1)
    {
        sys_epoll_create_fn = (int (*)(int))THUNKPTR(state.no_replace_epoll_create1->original_entry64);
        TRAMP_DEBUG("epoll_create1 via %p .. ", sys_epoll_create_fn);
        rc = sys_epoll_create_fn(flags);
        if (rc != -ENOSYS)
            goto out;
    }
    if (!state.no_replace_epoll_create)
    {
        ci_log("Unexpected epoll_ctl() request before full init");
        return -EFAULT;
    }
    sys_epoll_create_fn = (int (*)(int))THUNKPTR(state.no_replace_epoll_create->original_entry64);
    TRAMP_DEBUG("epoll_create via %p .. ", sys_epoll_create_fn);
    rc = sys_epoll_create_fn(1);
    ci_assert_equal(flags & ~EPOLL_CLOEXEC, 0);
    if (rc >= 0 && (flags & EPOLL_CLOEXEC))
    {
        struct files_struct *files = current->files;
        struct fdtable *fdt;
        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        efx_set_close_on_exec(rc, fdt);
        spin_unlock(&files->file_lock);
    }
    
    goto out;
out:
    TRAMP_DEBUG(" ... = %d ", rc);
    return rc;
}

asmlinkage int efab_linux_sys_epoll_ctl(int epfd, int op, int fd,
                                        struct epoll_event *event)
{
    asmlinkage int (*sys_epoll_ctl_fn)(int, int, int, struct epoll_event *);
    int rc;

    if (!state.no_replace_epoll_ctl)
    {
        ci_log("Unexpected epoll_ctl() request before full init");
        return -EFAULT;
    }

    sys_epoll_ctl_fn = (int (*)(int, int , int, struct epoll_event *))
        THUNKPTR(state.no_replace_epoll_ctl->original_entry64);
  TRAMP_DEBUG ("epoll_ctl(%d,%d,%d,%p) via %p...", epfd, op, fd, event,
               sys_epoll_ctl_fn);
  rc = sys_epoll_ctl_fn(epfd, op, fd, event);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}

asmlinkage int efab_linux_sys_epoll_wait(int epfd, struct epoll_event *events,
                                         int maxevents, int timeout)
{
  asmlinkage int (*sys_epoll_wait_fn)(int, struct epoll_event *, int, int);
  int rc;

  if( !state.no_replace_epoll_wait ) {
    ci_log("Unexpected epoll_wait() request before full init");
    return -EFAULT;
  }

  sys_epoll_wait_fn = (int (*)(int, struct epoll_event *, int, int))
                       THUNKPTR(state.no_replace_epoll_wait->original_entry64);
  TRAMP_DEBUG ("epoll_wait(%d,%p,%d,%d) via %p...", epfd, events, maxevents,
               timeout, sys_epoll_wait_fn);
  rc = sys_epoll_wait_fn(epfd, events, maxevents, timeout);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}

asmlinkage int efab_linux_sys_sigaction(int signum,
                                        const struct sigaction *act,
                                        struct sigaction *oact)
{
  int rc;

  if (state.replace_rt_sigaction == NULL) {
    ci_log("Unexpected rt_sigaction() request before full init");
    return -EFAULT;
  }

  TRAMP_DEBUG ("sigaction(%d,%p,%p,%d) via %p...", signum, act, oact,
               (int)sizeof(sigset_t), THUNKPTR(state.replace_rt_sigaction->original_entry64));
  rc = ((int (*)(int, const struct sigaction *, struct sigaction *, size_t))
        THUNKPTR(state.replace_rt_sigaction->original_entry64))(signum, act, oact, sizeof(sigset_t));
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}

#ifdef CONFIG_COMPAT
asmlinkage int efab_linux_sys_sigaction32(int signum,
                                          const struct sigaction32 *act,
                                          struct sigaction32 *oact)
{
  int rc;

  if (state.replace_rt_sigaction == NULL) {
    ci_log("Unexpected rt_sigaction() request before full init");
    return -EFAULT;
  }

  TRAMP_DEBUG ("sigaction32(%d,%p,%p,%d) via %p...", signum, act, oact,
               (int)sizeof(sigset_t), THUNKPTR(state.replace_rt_sigaction->original_entry32));
  rc = ((int (*)(int, const struct sigaction32 *, struct sigaction32 *, size_t))
        THUNKPTR(state.replace_rt_sigaction->original_entry32))(signum, act, oact, sizeof(sigset_t));
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
#endif

/* Our close handler, 64-bit */
static int efab_linux_trampoline_close64(int fd)
{
  /* Firstly, is this one our sockets?  If not, do the usual thing */
  struct file *f;
  int rc;

  TRAMP_DEBUG("close64: %d\n", fd);

  efab_syscall_enter();

  f = fget (fd);
  if (f) {
      if (FILE_IS_ENDPOINT(f)) {
        /* Yep -- it's one of ours.  This means current process must be using the
         * module (otherwise how did one of our sockets get in this proc's fd
         * table?).  It seems it didn't get intercepted -- trampoline back up.
         * However, only set up trampoline if this has been called via the
         * correct sys-call entry point
         */
        if (setup_trampoline (PT_REGS_FROM_SYSCALL(), 
                              CI_TRAMP_OPCODE_CLOSE, fd, TRAMPOLINE_BITS_64) == 0)
        {
            /* The trampoline will get run.  Let it handle the rest. */
            fput(f);
            efab_syscall_exit();
            return 0;
        }
    }
    /* Undo the fget above */
    fput(f);
  }

  TRAMP_DEBUG("going unto %p\n", THUNKPTR(state.replace_close->original_entry64));
  /* Not one of our FDs -- usual close */
  rc = ((int (*)(int))THUNKPTR(state.replace_close->original_entry64))(fd);
  TRAMP_DEBUG("Close64: Chain returns %d \n", rc);
  efab_syscall_exit();
  return rc;
}

#ifdef CONFIG_COMPAT
int efab_linux_trampoline_close32(int fd)
{
  /* Firstly, is this one our sockets?  If not, do the usual thing */
  struct file *f;
  int rc;

  TRAMP_DEBUG("close32: %d\n", fd);

  efab_syscall_enter();

  f = fget (fd);
  if (f) {
      if (FILE_IS_ENDPOINT(f)) {
      /* Yep -- it's one of ours.  This means current process must be using the
       * module (otherwise how did one of our sockets get in this proc's fd
       * table?).  It seems it didn't get intercepted -- trampoline back up.
       * However, only set up trampoline if this has been called via the
       * correct sys-call entry point
       */
        if (setup_trampoline (PT_REGS_FROM_SYSCALL(), 
                              CI_TRAMP_OPCODE_CLOSE, fd, TRAMPOLINE_BITS_32) == 0)
        {
            /* The trampoline will get run.  Let it handle the rest. */
            fput(f);
            efab_syscall_exit();
            return 0;
        }
    }
    /* Undo the fget above */
    fput(f);
  }
  
  /* Not one of our FDs -- usual close */
  rc = ((int (*)(int))THUNKPTR(state.replace_close->original_entry32))(fd);
  TRAMP_DEBUG("Close32: Chain returns %d \n", rc);
  efab_syscall_exit();
  return rc;
}
#endif

static int setup_trampoline(struct pt_regs *regs, 
                            int opcode, int arg, 
                            int bits)
{
    struct mm_hash *p;
    ci_uintptr_t trampoline_entry = 0, trampoline_exclude = 0,
        trampoline_toc = 0, trampoline_fixup = 0;
    int rc = -EBADF;
    
    read_lock(&oo_mm_tbl_lock);
    p = oo_mm_tbl_lookup(current->mm);
    if (p)
    {
        trampoline_entry = (ci_uintptr_t) CI_USER_PTR_GET(p->trampoline_entry);
        trampoline_exclude = (ci_uintptr_t) CI_USER_PTR_GET(p->trampoline_exclude);
        trampoline_toc = (ci_uintptr_t) CI_USER_PTR_GET(p->trampoline_toc);
        trampoline_fixup = (ci_uintptr_t) CI_USER_PTR_GET(p->trampoline_user_fixup);
    }
    read_unlock(&oo_mm_tbl_lock);
    
    TRAMP_DEBUG("%s: trampoline_entry = %p \n", __func__, (void *)trampoline_entry);

    /* OK. We have the entry - set up a trampoline to user space */
    if (trampoline_entry)
    {
        if (!access_ok(VERIFY_READ, trampoline_entry, 1))
        {
            /* Can't read this address. Fail! */
            ci_log("Pid %d (mm=%p) has bad trampoline entry: %p",
                   current->tgid, current->mm, (void *)trampoline_entry);
            return -EBADF;
        }

        /* Check for the excluded address */
        if (regs->nip == trampoline_exclude)
        {
            TRAMP_DEBUG("Ignoring call from excluded address 0x%08lx",
                        (unsigned long)trampoline_exclude);
            return -EBUSY;
        }

        TRAMP_DEBUG("%s: bits = %d; set up trampoline. \n", __func__, bits);
        if (bits == TRAMPOLINE_BITS_64)
        {
            setup_trampoline64(regs, opcode, arg, 
                               (void *)trampoline_entry, (void *)trampoline_toc,
                               (void *)trampoline_fixup);
        }
#ifdef CONFIG_COMPAT
        else
        {
            setup_trampoline32(regs, opcode, arg,
                               (void *)trampoline_entry, (void *)trampoline_toc,
                               (void *)trampoline_fixup);
        }
#endif
        rc = 0;
    }
    else
    {
        OO_DEBUG_VERB(ci_log("Error -- attempt to trampoline for unknown process"));
        rc = -ENOENT;
    }
    return rc;
}


int efab_linux_trampoline_ctor(int no_sct)
{
    int rc;

    atomic_set(&efab_syscall_used, 0);

    memset(&state, '\0', sizeof(struct state_struct));

    rc = linux_trampoline_ppc64_internal_ctor();
    if (!rc) 
    {
        if (no_sct)
        {
            TRAMP_DEBUG("syscalls NOT hooked - no_sct requested");
        }
        else
        {
            state.replace_close = 
                linux_trampoline_ppc64_intercept_syscall(__NR_close,
                                                         efab_linux_trampoline_close64,
                                                         efab_linux_trampoline_close32);
            state.replace_exit_group =
                linux_trampoline_ppc64_intercept_syscall(__NR_exit_group,
                                                         efab_linux_trampoline_exit_group,
                                                         efab_linux_trampoline_exit_group);
            state.replace_rt_sigaction =
                linux_trampoline_ppc64_intercept_syscall(__NR_rt_sigaction,
                                                         efab_linux_trampoline_sigaction,
                                                         efab_linux_trampoline_sigaction32);
        }

        state.no_replace_epoll_create1 = 
            linux_trampoline_ppc64_intercept_syscall(__NR_epoll_create1,
                                                     NULL, NULL);
        state.no_replace_epoll_create =
            linux_trampoline_ppc64_intercept_syscall(__NR_epoll_create, NULL, NULL);
        state.no_replace_epoll_ctl =
            linux_trampoline_ppc64_intercept_syscall(__NR_epoll_ctl, NULL, NULL);
        state.no_replace_epoll_wait = 
            linux_trampoline_ppc64_intercept_syscall(__NR_epoll_wait, NULL, NULL);

        state.no_replace_socketcall =
            linux_trampoline_ppc64_intercept_syscall(__NR_socketcall, NULL, NULL);
    }
    else
    {
        TRAMP_DEBUG("Warning: syscall table not found - can't read sys_close");
        return 0;
    }
    return 0;
}


int efab_linux_trampoline_dtor(int no_sct)
{
    int waiting = 0;

    /* Restore syscalls */
    linux_trampoline_ppc64_restore_syscalls();

    /* Give any just-entered syscalls a chance to increment their
     *  atomic
     */
    synchronize_sched();
#ifdef CONFIG_PREEMPT
    schedule_timeout(msecs_to_jiffies(50));
#endif
    while (atomic_read(&efab_syscall_used))
    {
        if (!waiting)
        {
            ci_log("Waiting for intercepted syscalls to finish .. ");
            waiting = 1;
        }
        schedule_timeout(msecs_to_jiffies(50));
    }
    if (waiting)
    {
        ci_log("\t .. OK");
        synchronize_sched();
#ifdef CONFIG_PREEMPT
        /* Try to wait .. */
        schedule_timeout(msecs_to_jiffies(50));
        ci_log("Unload is dangerous on RT kernels: prepare to crash.");
#endif
    }
 
    linux_trampoline_ppc64_dispose();
   
    return 0;
}


/* End file */

