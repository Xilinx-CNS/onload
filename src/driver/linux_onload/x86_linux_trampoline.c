/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

#ifdef __x86_64__
#  include <asm/processor.h>
#  include <asm/msr.h>
#  include <asm/percpu.h>

#    if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
     /* We do not use current_top_of_stack() function directly, but we
      * assume that Linux code is structured in known way.
      * And this function is a good starting point to look into
      * if this code breaks for a next linux kernel release. */
#    define HAS_CURRENT_TOP_OF_STACK 1
#    else
     DECLARE_PER_CPU(unsigned long, kernel_stack);
#    endif

      /* Copy'n'paste percpu_read() and percpu_write() definitions.
       * We can't use percpu_read/percpu_write directly, since they access
       * the variable per_cpu__old_rsp, which we can't emulate (we just
       * know its address).
       */
#      define percpu_read_from_p(pointer) ({ \
         typeof(*pointer) __tmp_var__;                              \
         preempt_disable();                                         \
         __tmp_var__ = (*SHIFT_PERCPU_PTR(pointer, my_cpu_offset)); \
         preempt_enable();                                          \
         __tmp_var__;                                               \
       })
#      define percpu_write_to_p(pointer, val) ({ \
         preempt_disable();                                   \
         (*SHIFT_PERCPU_PTR(pointer, my_cpu_offset)) = val;  \
         preempt_enable();                                    \
       })
#    define percpu_p(name) (&(name))


#ifdef CONFIG_COMPAT
#  include <asm/ia32_unistd.h>

/* Kernels >=2.6.18 do not define __NR_ia32_close after some muppet decided to
 * do some "tidying up" (quite why an enumerated list with random holes in it
 * is more tidy than a complete list I know not).  Anyway, define it here
 * (there's no way it can change).
 */
#  define __NR_ia32_close 6
#  define __NR_ia32_exit_group 252
#  define __NR_ia32_rt_sigaction 174
#endif /*CONFIG_COMPAT*/


#  define cs(r) (r)->cs
#  define ds(r) (r)->ds
#  define es(r) (r)->es
#  define ss(r) (r)->ss
#    define ip(r) (r)->ip
#    define di(r) (r)->di
#    define si(r) (r)->si
#    define sp(r) (r)->sp
#    define bp(r) (r)->bp
#    define ax(r) (r)->ax
#    define bx(r) (r)->bx
#    define cx(r) (r)->cx
#    define dx(r) (r)->dx
#    define orig_ax(r) (r)->orig_ax
#    define flags(r) (r)->flags
#  ifdef cpu_current_top_of_stack
#    define sp0(t) (t)->sp
#  else
#    define sp0(t) (t)->sp0
#  endif
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
#ifdef ONLOAD_SYSCALL_PTREGS
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


/* The address of the system call table.
 */
static void **syscall_table = 0;

#ifdef CONFIG_COMPAT

/* The address of the 32-bit compatibility system call table.
 */
static void **ia32_syscall_table = 0;

#endif


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
/* On newer kernels the 32-bit syscall stubs are different from the 64-bit ones */
static SYSCALL_PTR_DEF(saved_sys_close32, (int));
static SYSCALL_PTR_DEF(saved_sys_exit_group32, (int));
#endif

atomic_t efab_syscall_used;


static void* oo_entry_SYSCALL_64(void)
{
  static void *oo_entry_SYSCALL_64_addr = NULL;
  unsigned long result = 0;

  if( oo_entry_SYSCALL_64_addr != NULL )
    return oo_entry_SYSCALL_64_addr;

  /* linux<4.2:
   *   MSR_LSTAR points to system_call(); we are returning this address.
   * 4.3<=linux<5.0:
   *   MSR_LSTAR points to per-cpu SYSCALL64_entry_trampoline variable,
   *   which is a wrapper for entry_SYSCALL_64_trampoline(),
   *   which is a wrapper for entry_SYSCALL_64_stage2(),
   *   which is a wrapper for entry_SYSCALL_64().
   *   We need the entry_SYSCALL_64() address to parse the content of this
   *   function.
   * 5.1<=linux:
   *   MSR_LSTAR points to entry_SYSCALL_64().
   */
#ifdef ERFM_HAVE_NEW_KALLSYMS
  oo_entry_SYSCALL_64_addr = efrm_find_ksym("entry_SYSCALL_64");
  if( oo_entry_SYSCALL_64_addr != NULL )
    return oo_entry_SYSCALL_64_addr;
#endif

  rdmsrl(MSR_LSTAR, result);
  oo_entry_SYSCALL_64_addr = (void*)result;
  return oo_entry_SYSCALL_64_addr;
}

static void **find_syscall_table(void)
{
  unsigned char *p = NULL;
  unsigned long result;
  unsigned char *pend;

  /* First see if it is in kallsyms */
#ifdef ERFM_HAVE_NEW_KALLSYMS
  /* It works with CONFIG_KALLSYMS_ALL=y only. */
  p = efrm_find_ksym("sys_call_table");
#endif
  if( p != NULL ) {
    TRAMP_DEBUG("syscall table ksym at %px", (unsigned long*)p);
    return (void**)p;
  }

  /* If kallsyms lookup failed, fall back to looking at some assembly
   * code that we know references the syscall table.
   */
  p = oo_entry_SYSCALL_64();
  if( p == NULL )
    return NULL;

  TRAMP_DEBUG("entry_SYSCALL_64=%px", p);
  /* linux>=4.17 has following layout:
   * linux/arch/x86/entry/entry_64.S: entry_SYSCALL_64():
   * movq	%rax, %rdi
   *    48 89 c7
   * movq	%rsp, %rsi
   *    48 89 e6
   * call	do_syscall_64
   *    e8 XX XX XX XX
   *
   * NB It is possible to extend this to support linux>=4.6,
   * which is slightly different.  We do not have any DUTs to test such
   * a linux system without KALLSYMS, though.
   */
  p += 0x40; /* skip the first part of entry_SYSCALL_64() */
  result = 0;
  pend = p + 1024 - 11;
  while (p < pend) {
    if( p[0] == 0x48 && p[1] == 0x89 && p[2] == 0xc7 &&
        p[3] == 0x48 && p[4] == 0x89 && p[5] == 0xe6 &&
        p[6] == 0xe8 ) {
      result = (unsigned long)p + 11;
      result += p[7] | (p[8] << 8) | (p[9] << 16) | (p[10] << 24);
      break;
    }
    p++;
  }

  if( result == 0 ) {
    ci_log("ERROR: didn't find do_syscall_64()");
    return 0;
  }

  p = (void*)result;
  TRAMP_DEBUG("do_syscall_64=%px", p);
  /* For linux>=4.6 do_syscall_64() resides in
   * linux/arch/x86/entry/common.c:
   * regs->ax = sys_call_table[nr](regs);
   * in objdump -Dl:
   * 48 8b 04 fd XX XX XX XX	mov    0x0(,%rdi,8),%rax
   * 48 89 ef            	mov    %rbp,%rdi
   * (or
   *    4c 89 e7: mov    %r12,%rdi
   * or whatever)
   * (or the 2 movs above swapped)
   * e8 YY YY YY YY      	callq
   */
  p += 0x20; /* skip the first part of do_syscall_64() */
  result = 0;
  pend = p + 1024 - 12;
  while (p < pend) {
    if( p[0] == 0x48 && p[1] == 0x8b && p[2] == 0x04 && p[3] == 0xfd ) {
      TRAMP_DEBUG("%px: %02x %02x %02x %02x %02x %02x %02x %02x %02x "
                  "%02x %02x %02x %02x %02x %02x %02x %02x",
                  p, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8],
                  p[9], p[10], p[11], p[12], p[13], p[14], p[15], p[16]);
      if( (p[9] == 0x89 && p[11] == 0xe8) ||
          (*(p-2) == 0x89 && p[8] == 0xe8) ) {
        s32 addr = p[4] | (p[5] << 8) | (p[6] << 16) | (p[7] << 24);
        result = (long)addr;
        TRAMP_DEBUG("sys_call_table=%lx", result);
        return (void**)result;
      }
    }
    p++;
  }

  TRAMP_DEBUG("didn't find syscall table address");
  return NULL;
}

#ifdef CONFIG_COMPAT
/* We also need to find the ia32_syscall_table used by 32-bit apps in 64-bit
 * mode.  This can be found via int 0x80 in a similar way to x86 -- but the
 * IDTR and entries in it are larger here, and the instruction we're looking
 * for is "call *table(,%rax,8)" (as for the 64-bit syscall table).
 */
static void **find_ia32_syscall_table(void)
{
#ifdef ERFM_HAVE_NEW_KALLSYMS
  /* It works with CONFIG_KALLSYMS_ALL=y only. */
  /* Linux>=4.2: ia32_sys_call_table is not a local variable any more, so
   * we can use kallsyms to find it if CONFIG_KALLSYMS_ALL=y. */
  void *addr;
  addr = efrm_find_ksym("ia32_sys_call_table");
  if( addr != NULL )
    return addr;
#endif

  /* Sasha fixme: get ia32_sys_call_table out of asm
   * based on oo_entry_sys_call_table()
   */

  ci_log("ERROR: didn't find ia32_sys_call_table address");

  return NULL;
}
#endif


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

  if( syscall_table == NULL ) {
    ci_log("Unexpected epoll_ctl() request before full init");
    return -EFAULT;
  }

  sys_epoll_create_fn = syscall_table[__NR_epoll_create1];
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

  if( syscall_table == NULL ) {
    ci_log("Unexpected epoll_ctl() request before full init");
    return -EFAULT;
  }

  sys_epoll_ctl_fn = syscall_table[__NR_epoll_ctl];
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

  if( syscall_table == NULL ) {
    ci_log("Unexpected epoll_wait() request before full init");
    return -EFAULT;
  }

  sys_epoll_wait_fn = syscall_table[__NR_epoll_wait];
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

  if( syscall_table == NULL ) {
    ci_log("Unexpected sendmsg() request before full init");
    return -EFAULT;
  }

  {
#ifdef __NR_sendmsg
    SYSCALL_PTR_DEF(sys_sendmsg_fn, (int, struct msghdr *, unsigned));

    sys_sendmsg_fn = syscall_table[__NR_sendmsg];
    TRAMP_DEBUG ("sendmsg(%d,%p,%d) via %p...", fd, msg, flags, sys_sendmsg_fn);
    rc = PASS_SYSCALL3(sys_sendmsg_fn, fd, msg, flags);
#elif defined(__NR_socketcall)
    SYSCALL_PTR_DEF(sys_socketcall_fn, (int, unsigned long *));
    unsigned long args[3];

    sys_socketcall_fn = syscall_table[__NR_socketcall];
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

  if( syscall_table == NULL ) {
    ci_log("Unexpected bpf() request before full init");
    return -EFAULT;
  }

  {
#ifdef __NR_bpf
    SYSCALL_PTR_DEF(sys_bpf_fn, (int, union bpf_attr *, int));

    sys_bpf_fn = syscall_table[__NR_bpf];
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

  if( syscall_table == NULL ) {
    ci_log("Unexpected sendmsg() request before full init");
    return -EFAULT;
  }

  if( ia32_syscall_table != NULL ) {
    SYSCALL_PTR_DEF(sys_socketcall_fn, (int, unsigned long *));
    compat_ulong_t args[3];

    sys_socketcall_fn = ia32_syscall_table[102/*__NR_socketcall*/];
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

#if defined(__x86_64__)

#ifdef HAS_CURRENT_TOP_OF_STACK
   /* current_top_of_stack() reads cpu_tss.x86_tss.sp0, and it is the
    * pointer we need.  On these kernels, the value is taken before the IRET
    * frame is pushed onto the stack, so we don't need to look beyond it to
    * find that frame. */
#  define OO_KERNEL_STACK_END_OFFSET 0ul
#  ifdef cpu_current_top_of_stack
   /* KPTI rework (in linux-4.14) results in this */
#    define OO_KERNEL_STACK cpu_current_top_of_stack
#  else
#    define OO_KERNEL_STACK cpu_tss.x86_tss.sp0
#  endif
#else
  /* On these older kernels, the value of the kernel_stack variable is the
   * _beginning_ of the IRET frame. */
#  define OO_KERNEL_STACK_END_OFFSET (unsigned long) \
     (sizeof(struct pt_regs) - CI_MEMBER_OFFSET(struct pt_regs, ip))
#  define OO_KERNEL_STACK kernel_stack
#endif


/* Find the storage of the old (UL) stack pointer. */
ci_inline unsigned long *get_oldrsp_addr(void)
{
  static unsigned long *oldrsp_addr = NULL;
  if (oldrsp_addr)
    return oldrsp_addr;

  /* 
   * Dirty hack to find location of old_rsp, which is not exported.
   * 1. get entry_SYSCALL_64
   * It looks following:
   *   swapgs
   *        0f 01 f8
   *   <some CFI stuff (?)>
   *   movq   %rsp,PER_CPU_VAR(old_rsp)
   *        65 48 89 24 25 XX XX XX XX
   *   <some zeroes, or SWITCH_TO_KERNEL_CR3 %rsp>
   *   movq   PER_CPU_VAR(kernel_stack),%rsp
   *        65 48 8b 24 25 YY YY YY YY
   * where kernel_stack is exported, so it can be checked.
   * 2. look through the code and find/check we have what we expect.
   */
  {
    unsigned long result;
#ifndef NDEBUG
    unsigned char *ptr;
#endif
    unsigned char *p;
    unsigned long kernel_stack_p = (unsigned long) percpu_p(OO_KERNEL_STACK);
    unsigned char *p_end;

    p = oo_entry_SYSCALL_64();
#ifndef NDEBUG
    ptr = p;
#define OOPS(msg) { \
    int i;                                                                \
    ci_log(msg);                                                          \
    for (i = 0; i < 10; i++) {                                             \
      ci_log("system_call + %d*4: %02x %02x %02x %02x", i,                \
             ptr[i * 4], ptr[i * 4 + 1], ptr[i * 4 + 2], ptr[i * 4 + 3]); \
    }                                                                     \
    ci_assert(0);                                                         \
  }
#else
#define OOPS(msg) { ci_log(msg); return NULL;}
#endif
    if (p[0] != 0x0f || p[1] != 0x01 || p[2] != 0xf8) {
      OOPS("Unexpected code at the beginning of system_call(), "
           "can't trampoline.");
    }
    p += 3;
    p_end = p + 256; /* RHEL6 needs >=128 */
    while (p[0] != 0x65 || p[1] != 0x48 || p[2] != 0x89 ||
           p[3] != 0x24 || p[4] != 0x25) {
      p++;
      if (p >= p_end) {
        OOPS("Unexpected code in system_call(), can't trampoline.\n"
             "Can't find movq %%rsp,PER_CPU_VAR(old_rsp)");
      }
    }
    p += 5;
    result = p[0] + (p[1] << 8) + (p[2] << 16);
    p +=3;
    p_end = p + 32;
    while (p[0] != 0x65 || p[1] != 0x48 || p[2] != 0x8b ||
           p[3] != 0x24 || p[4] != 0x25 ||
           p[5] != (kernel_stack_p & 0xff) ||
           p[6] != ((kernel_stack_p >> 8) & 0xff) ||
           p[7] != ((kernel_stack_p >> 16) & 0xff)) {
      p++;
      if (p >= p_end) {
        ci_log("Looking up for movq PER_CPU_VAR(kernel_stack=%lx),%%rsp",
               kernel_stack_p);
        OOPS("Unexpected code in system_call(), can't trampoline.");
      }
    }
    TRAMP_DEBUG("&per_cpu__old_rsp=%08lx", result);

#undef OOPS

    oldrsp_addr = (unsigned long *)result;
  }
  return oldrsp_addr;
}
#endif


#if defined(CONFIG_COMPAT)
/* Avoid returning to UL via short-path sysret.  The problem exists at
 * least on RHEL4 2.6.9 64-bit kernel + 32-bit UL.  Previously, we've done
 * it with TIF_IRET flag.  The problem is, TIF_IRET is not supposed to be
 * set for x86_64 kernel, so nobody clear it.   As a result, we have
 * performance degradation at best (all syscalls go via long path iret),
 * and various bugs in some cases (bug 19262).  So, we set TIF_NEED_RESCHED
 * flag, which is guaranteed to be handled in any kernel.  We do not really
 * need to be rescheduled, but we need to avoid the fast sysret path. */
ci_inline void
avoid_sysret(void)
{
  set_thread_flag (TIF_NEED_RESCHED);
}

#ifndef ONLOAD_SYSCALL_PTREGS
/* There are 2 ways to enter syscall: int80 and vsyscall page.
 * We'll store offsets for 2 different stack layouts. */
#define TRAMP_PRESAVED_OFF32 2
static int tramp_offset32[TRAMP_PRESAVED_OFF32] = {0,0};
#endif

#endif

static inline int
tramp_close_passthrough(int fd)
{
  int rc = PASS_SYSCALL1(saved_sys_close, fd);
  efab_syscall_exit();
  return rc;
}

static inline int /* bool */
tramp_close_begin(int fd, ci_uintptr_t *tramp_entry_out,
                  ci_uintptr_t *tramp_exclude_out)
{
  struct file *f;
  efab_syscall_enter();

  f = fget(fd);
  if( f != NULL ) {
    if( FILE_IS_ENDPOINT(f) ) {
      struct mm_hash *p;
      TRAMP_DEBUG("%s: file is endpoint", __FUNCTION__);

      read_lock (&oo_mm_tbl_lock);
      p = oo_mm_tbl_lookup(current->mm);
      if (p) {
        *tramp_entry_out =
            (ci_uintptr_t)CI_USER_PTR_GET(p->trampoline_entry);
        *tramp_exclude_out =
            (ci_uintptr_t)CI_USER_PTR_GET(p->trampoline_exclude);
      }
      read_unlock (&oo_mm_tbl_lock);

      if( *tramp_entry_out != 0 &&
          efab_access_ok(*tramp_entry_out, 1)) {
        fput(f);
        return false;
      }
    }
    fput(f);
  }

  /* Not one of our FDs -- usual close */
  return true;
}


#ifndef ONLOAD_SYSCALL_PTREGS
#ifndef NDEBUG
/* Heuristic for deciding whether a struct pt_regs looks valid. */
static inline int /* bool */
looks_like_pt_regs64(const struct pt_regs* regs, unsigned long syscall_num)
{
  const unsigned long flags_set_bits =
    X86_EFLAGS_IF
#ifdef X86_EFLAGS_FIXED
    | X86_EFLAGS_FIXED
#endif
    ;
  const unsigned long flags_clear_bits = X86_EFLAGS_VM;
  struct vm_area_struct* ip_vma;
  unsigned vm_flags = 0;

  /* %rip had better point to executable memory. */
  down_read(&current->mm->mmap_sem);
  ip_vma = find_vma(current->mm, ip(regs));
  if( ip_vma != NULL )
    vm_flags = ip_vma->vm_flags;
  up_read(&current->mm->mmap_sem);
  if( ~vm_flags & VM_EXEC )
    return 0;

  return
    /* %rax contains the syscall number. */
    orig_ax(regs) == syscall_num &&
    /* %rdi contains the fd.  The only ABI guarantee that we have here is that
     * this will be 32-bit. */
    (di(regs) & ~((1ull << 32) - 1)) == 0 &&
    /* %r11 contains the flags.  Check some known bits. */
    (regs->r11 & flags_set_bits) == flags_set_bits &&
    (regs->r11 & flags_clear_bits) == 0;
}
#endif
#endif

asmlinkage long
#ifndef ONLOAD_SYSCALL_PTREGS
efab_linux_trampoline_handler_close64(int fd)
#else
/* The argument is defined as const pointer in the kernel,
   but we do need to modify it
*/
efab_linux_trampoline_handler_close64(struct pt_regs *regs)
#endif
{
  ci_uintptr_t trampoline_entry = 0;
  ci_uintptr_t trampoline_exclude = 0;
  unsigned long *user_sp =0;
#ifndef ONLOAD_SYSCALL_PTREGS
  struct pt_regs* regs;
  char* stack_end = (char*) percpu_read_from_p(percpu_p(OO_KERNEL_STACK)) +
                    OO_KERNEL_STACK_END_OFFSET;
#else
  int fd = di(regs);
#endif

  if( tramp_close_begin(fd, &trampoline_entry, &trampoline_exclude) )
    return tramp_close_passthrough(fd);

#ifndef ONLOAD_SYSCALL_PTREGS
  TRAMP_DEBUG("kernel stack is %p (after adding offset %lu)", stack_end,
              OO_KERNEL_STACK_END_OFFSET);
  /* The struct pt_regs should end at the end of the stack.  Move to the start
   * of the structure. */
  regs = (struct pt_regs*) stack_end - 1;
  ci_assert(looks_like_pt_regs64(regs, __NR_close));
#endif

  /* Let's trampoline! */
  /* There probably isn't any useful verification we can do here...
   * The good news is that on x86_64 it is impossible to issue a system-call
   * from supervisor mode (unlike IA32), and so calls to 'close' from the
   * kernel don't go via the system-call table.  The bad news is that it is
   * still theoretically possible to call via the system-call table, in which
   * case all kinds of badness is liable to happen -- TODO: Is there any way
   * to verify we're called from user-mode on x86_64?
   */

  TRAMP_DEBUG("setup_trampoline:");
  /* Only a partial pt_regs stack frame is set up -- these are missing: */
  TRAMP_DEBUG("  r15 %016lx XX",regs->r15); /* not saved by syscall entry */
  TRAMP_DEBUG("  r14 %016lx XX",regs->r14); /* not saved by syscall entry */
  TRAMP_DEBUG("  r13 %016lx XX",regs->r13); /* not saved by syscall entry */
  TRAMP_DEBUG("  r12 %016lx XX",regs->r12); /* not saved by syscall entry */
  TRAMP_DEBUG("  bp %016lx XX", bp(regs)); /* not saved by syscall entry */
  TRAMP_DEBUG("  bx %016lx XX", bx(regs)); /* not saved by syscall entry */
  /* These are always present: */
  TRAMP_DEBUG("  r11 %016lx",regs->r11);
  TRAMP_DEBUG("  r10 %016lx",regs->r10);
  TRAMP_DEBUG("  r9  %016lx",regs->r9);
  TRAMP_DEBUG("  r8  %016lx",regs->r8);
  TRAMP_DEBUG("  ax %016lx", ax(regs));
  TRAMP_DEBUG("  cx %016lx", cx(regs));
  TRAMP_DEBUG("  dx %016lx", dx(regs));
  TRAMP_DEBUG("  si %016lx", si(regs));
  TRAMP_DEBUG("  di %016lx", di(regs));
  TRAMP_DEBUG("  orig_ax %016lx", orig_ax(regs));
  TRAMP_DEBUG("  ip %016lx", ip(regs));
  /* Not always present but may be fixed up on syscall handler slow paths: */
  TRAMP_DEBUG("  cs  %016lx XX",regs->cs);
  TRAMP_DEBUG("  flags %016lx XX", flags(regs));
  TRAMP_DEBUG("  rsp %016lx XX", sp(regs));
  TRAMP_DEBUG("  ss  %016lx XX",regs->ss);
  TRAMP_DEBUG("trampoline_exclude %016lx", (unsigned long) trampoline_exclude);
  TRAMP_DEBUG("thread_info->flags %016lx",
              (unsigned long)current_thread_info()->flags);

  if (ip(regs) == trampoline_exclude) {
    TRAMP_DEBUG("Ignoring call from excluded address");
    return tramp_close_passthrough(fd);
  }

  /* We need to get data back to the user-mode stub handler.  Specifically
   * -- the real return address, the op-code, and the "data" field (eg.
   * file-descriptor for close).  We do this by corrupting the registers that
   * are saved on the stack, so when we trampoline back the trampoline has
   * these values in its regs as expected.  However, note that the trampoline
   * handler must not trash ANY registers, since Linux system-calls don't.
   * Therefore, we save the original values of the registers on the user-mode
   * stack, to allow the trampoline stub to restore register state before
   * returning to whoever called the syscall in the first place.
   *
   * On Linux x86_64 the old user-sp is stored in the per-cpu variable
   * oldrsp.
   */
  {
    unsigned long *orig_user_sp;
#ifdef cpu_current_top_of_stack
    orig_user_sp = (void*)sp(regs);
#else
    orig_user_sp = (unsigned long *)percpu_read_from_p(get_oldrsp_addr());
#endif

    user_sp = orig_user_sp;
    TRAMP_DEBUG("read user_sp=%p", user_sp);

    /* Make sure there is sufficient user-space stack */
    if (!efab_access_ok (user_sp - 24, 24)) {
      ci_log ("Invalid user-space stack-pointer; cannot trampoline!");
      return tramp_close_passthrough(fd);
    }

    ci_assert (sizeof *user_sp == 8);

    user_sp--;
    /* Return address */
    if( put_user(ip(regs), user_sp) != 0 )
      return tramp_close_passthrough(fd);
    user_sp--;
    /* %rdi will be trashed by opcode */
    if( put_user(di(regs), user_sp) != 0 )
      return tramp_close_passthrough(fd);
    user_sp--;
    /* %rsi will be trashed by data */
    if( put_user(si(regs), user_sp) != 0 )
      return tramp_close_passthrough(fd);

    /* Write the updated rsp */
    percpu_write_to_p(get_oldrsp_addr(), (unsigned long)user_sp);
    TRAMP_DEBUG("wrote user_sp=%p", user_sp);

    /* On some slow paths through the syscall code (e.g. when ptracing) the
     * top of the stack frame gets fixed up, and the rsp there may get copied
     * back to the pda oldrsp field on exit from the syscall.  So, if we find
     * the original rsp in the rsp field on the stack, we need to update that
     * too.
     */
    if (sp(regs) == (unsigned long)orig_user_sp) {
      sp(regs) = (unsigned long)user_sp;
      TRAMP_DEBUG("wrote sp=%p as well", user_sp);
    }
  }

  /* The little stub in user-mode expects the fd to close in rsi, and
   * the original return address (so that it can get back) in rdx.  We've
   * saved away the original values of these regs on the user stack so that
   * the trampoline stub may restore the state before returning to whoever
   * made the system-call.
   */
  di(regs) = CI_TRAMP_OPCODE_CLOSE;
  si(regs) = fd;

  /* Hack the return address on the stack to do the trampoline */
  ip(regs) = trampoline_entry;

  TRAMP_DEBUG("set tramp entry %016lx", (unsigned long) trampoline_entry);

  efab_syscall_exit();
  return 0;
}

#ifdef CONFIG_COMPAT

#ifndef ONLOAD_SYSCALL_PTREGS
/* Find struct pt_regs on the stack using the stack base pointer and four known
 * registers.  RHEL 7 backports of CONFIG_RETPOLINE changed the syscall entry
 * paths.  Now, on these kernels, the struct pt_regs is not always at the
 * (logical) top of the stack on entry to our trampoline handler.  This is also
 * true on kernels >= 4.4, regardless of CONFIG_RETPOLINE.
 *     We used to check the values of EBX and EBP here, but these are not
 * preserved on the stack in the aforementioned RHEL 7 kernels, so we can't do
 * it in general.
 * In practice, all that registers are 0, so we have extremely high
 * probability of false positives.  We check that CS is correct in hope
 * that it helps.
 */
static inline struct pt_regs *
tramp_stack_find_regs32(unsigned long cx, unsigned long dx, unsigned long si,
                        unsigned long di, unsigned long *stack)
{
  unsigned long regs4[4] = {cx, dx, si, di};
  int i, off;
  struct pt_regs *regs;

  /* Is one of our saved offsets good? */
  for( i = 0; i < TRAMP_PRESAVED_OFF32; i++ ) {
    regs = (void *)(stack + tramp_offset32[i]);
    /* Zero is a valid offset as well as being the sentinel value for the end
     * of the remembered offsets, but that's OK: we'll use it in the loop
     * below. */
    if( tramp_offset32[i] == 0 )
      break;
    if( memcmp(&regs->cx, regs4, 4 * sizeof(regs4[0])) == 0 &&
        regs->cs == __USER32_CS ) {
      TRAMP_DEBUG("%s: reuse offset[%d] = %d", __func__, i, tramp_offset32[i]);
      return regs;
    }
  }

  for( off = 0; off < 20; off++ ) {
    regs = (void *)(stack + off);
    if( memcmp(&regs->cx, regs4, 4 * sizeof(regs4[0])) == 0 &&
        regs->cs == __USER32_CS ) {
      if( i < TRAMP_PRESAVED_OFF32 ) {
        tramp_offset32[i] = off;
        TRAMP_DEBUG("%s: offset[%d] = %d", __func__, i, off);
      }
      else {
        TRAMP_DEBUG("%s: 3rd offset %d", __func__, off);
      }
      return regs;
    }
  }
  return NULL;
}
#endif

#ifndef ONLOAD_SYSCALL_PTREGS
extern asmlinkage int
efab_linux_trampoline_handler_close32(unsigned long bx, unsigned long cx,
                                      unsigned long dx, unsigned long si,
                                      unsigned long di, unsigned long bp,
                                      struct pt_regs *regs)
#else
extern asmlinkage int
efab_linux_trampoline_handler_close32(struct pt_regs *regs)
#endif
{
  ci_uintptr_t trampoline_entry = 0;
  ci_uintptr_t trampoline_exclude = 0;
  unsigned int *user32_sp =0;
#ifdef ONLOAD_SYSCALL_PTREGS
  unsigned long bx = regs->bx;
#endif

  if( tramp_close_begin(bx, &trampoline_entry, &trampoline_exclude) )
    return tramp_close_passthrough(bx);


  /* Let's trampoline! */
  ci_assert (sizeof *user32_sp == 4);

#ifndef ONLOAD_SYSCALL_PTREGS
  regs = tramp_stack_find_regs32(cx, dx, si, di, (void *)regs);
  if( regs == NULL )
    return tramp_close_passthrough(bx);
#endif

  /* It's one of our's.  We would normally have expected to intercept
   * this call from the user-library; trampoling by hacking stack.
   * We verify the stack is as we expect first.
   */

  ci_assert (sizeof *user32_sp == 4);

  TRAMP_DEBUG("setup_trampoline32:");
  TRAMP_DEBUG("  r15 %016lx XX",regs->r15);
  TRAMP_DEBUG("  r14 %016lx XX",regs->r14);
  TRAMP_DEBUG("  r13 %016lx XX",regs->r13);
  TRAMP_DEBUG("  r12 %016lx XX",regs->r12);
  TRAMP_DEBUG("  bp %016lx XX", bp(regs));
  TRAMP_DEBUG("  bx %016lx XX", bx(regs));
  TRAMP_DEBUG("  r11 %016lx",regs->r11);
  TRAMP_DEBUG("  r10 %016lx",regs->r10);
  TRAMP_DEBUG("  r9  %016lx",regs->r9);
  TRAMP_DEBUG("  r8  %016lx",regs->r8);
  TRAMP_DEBUG("  ax %016lx", ax(regs));
  TRAMP_DEBUG("  cx %016lx", cx(regs));
  TRAMP_DEBUG("  dx %016lx", dx(regs));
  TRAMP_DEBUG("  si %016lx", si(regs));
  TRAMP_DEBUG("  di %016lx", di(regs));
  TRAMP_DEBUG("  orig_ax %016lx", orig_ax(regs));
  TRAMP_DEBUG("  ip %016lx", ip(regs));
  /* Extra context from entry via interrupt: */
  TRAMP_DEBUG("  cs  %016lx",regs->cs);
  TRAMP_DEBUG("  flags %016lx", flags(regs)); 
  TRAMP_DEBUG("  sp %016lx", sp(regs));
  TRAMP_DEBUG("  ss  %016lx",regs->ss);
  TRAMP_DEBUG("trampoline_exclude %016lx", (unsigned long) trampoline_exclude);

  if (ip(regs) == trampoline_exclude) {
    TRAMP_DEBUG("Ignoring call from excluded address");
    return tramp_close_passthrough(bx);
  }
  /* The little stub in user-mode needs the opcode and data on the user-mode
   * stack (originally we passed these in registers, ecx and edx, but this
   * doesn't work in the case of a 32-bit app on a 64-bit machine calling a
   * system call via the SYSCALL instruction, as used in 2.6 kernels).  The
   * trampoline handler function may trash ecx and edx (which are scratch
   * registers for x86 functions, but NOT for system calls), so we also push
   * the original contents of these registers after we push the return
   * address onto the user-mode stack.
   *
   * First we ensure there is sufficient user-space stack
   */
  if (!efab_access_ok (sp(regs) - 20, 20)) {
    ci_log ("Bogus 32-bit user-mode stack; cannot trampoline!");
    return tramp_close_passthrough(bx);
  }
  user32_sp = (unsigned int*)sp(regs);
  user32_sp--;
  if( put_user(ip(regs), user32_sp) != 0 )
    return tramp_close_passthrough(bx);
  user32_sp--;
  if( put_user(cx(regs), user32_sp) != 0 )
    return tramp_close_passthrough(bx);
  user32_sp--;
  if( put_user(dx(regs), user32_sp) != 0)
    return tramp_close_passthrough(bx);
  user32_sp--;
  if( put_user(bx, user32_sp) != 0 )
    return tramp_close_passthrough(bx);
  user32_sp--;
  if( put_user(CI_TRAMP_OPCODE_CLOSE, user32_sp) != 0 )
    return tramp_close_passthrough(bx);

  /* Hack registers so they're restored to state expected by tramp handler */
  sp(regs) = (ci_uintptr_t) user32_sp;

  /* Hack the return address on the stack to do the trampoline */
  ip(regs) = trampoline_entry;

  TRAMP_DEBUG("set tramp entry 0x%08lx", (unsigned long)trampoline_entry);
  avoid_sysret();
  efab_syscall_exit();
  return 0;
}

#endif /* CONFIG_COMPAT */



#ifdef OO_DO_HUGE_PAGES
#include <linux/unistd.h>
asmlinkage int efab_linux_sys_shmget(key_t key, size_t size, int shmflg)
{
  SYSCALL_PTR_DEF(sys_shmget_fn, (key_t, size_t, int));
  int rc;

  ci_assert(syscall_table);

  sys_shmget_fn = syscall_table[__NR_shmget];
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

  ci_assert(syscall_table);

  sys_shmat_fn = syscall_table[__NR_shmat];
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

  ci_assert(syscall_table);

  sys_shmdt_fn = syscall_table[__NR_shmdt];
  TRAMP_DEBUG ("shmdt(%p) via %p...", addr, sys_shmdt_fn);
  rc = PASS_SYSCALL1(sys_shmdt_fn, addr);
  TRAMP_DEBUG ("... = %d", rc);
  return rc;
}
asmlinkage int efab_linux_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
  SYSCALL_PTR_DEF(sys_shmctl_fn, (int, int, struct shmid_ds __user *));
  int rc;

  ci_assert(syscall_table);

  sys_shmctl_fn = syscall_table[__NR_shmctl];
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
  syscall_table = find_syscall_table();

  atomic_set(&efab_syscall_used, 0);
  if (syscall_table) {
    /* We really have to hope that syscall_table was found correctly.  There
     * is no reliable way to check it (e.g. by looking at the contents) which
     * will work on all platforms...
     */
    TRAMP_DEBUG("syscall_table=%p: close=%p exit_group=%p, rt_sigaction=%p",
                syscall_table, syscall_table[__NR_close],
                syscall_table[__NR_exit_group],
                syscall_table[__NR_rt_sigaction]);

    efab_linux_termination_ctor();

    saved_sys_close = syscall_table [__NR_close];
    saved_sys_exit_group = syscall_table [__NR_exit_group];
    saved_sys_rt_sigaction = syscall_table [__NR_rt_sigaction];

    ci_mb();
    if (no_sct) {
      TRAMP_DEBUG("syscalls NOT hooked - no_sct requested");
    } else {
      patch_syscall_table (syscall_table, __NR_close,
                           efab_linux_trampoline_close, saved_sys_close);
      if( safe_signals_and_exit ) {
        patch_syscall_table (syscall_table, __NR_exit_group,
                             efab_linux_trampoline_exit_group,
                             saved_sys_exit_group);
        patch_syscall_table (syscall_table, __NR_rt_sigaction,
                             efab_linux_trampoline_sigaction,
                             saved_sys_rt_sigaction);
      }
      TRAMP_DEBUG("syscalls hooked: close=%p exit_group=%p, rt_sigaction=%p",
                  syscall_table[__NR_close], syscall_table[__NR_exit_group],
                  syscall_table[__NR_rt_sigaction]);
    }
  } else {
    /* syscall_table wasn't found, so we may have no way to sys_close()... */
    OO_DEBUG_ERR(ci_log("ERROR: syscall table not found"));
    return -ENOEXEC;
  }

#ifdef CONFIG_COMPAT

  ia32_syscall_table = find_ia32_syscall_table();

  if (ia32_syscall_table && !no_sct) {
    /* On pre-4.17 kernels we can do a sanity check on the
     * ia32_syscall_table value: sys_close is the same for both
     * 64-bit and 32-bit, so the current entry for sys_close
     * in the 32-bit table should match the original value from the 64-bit
     * table, which we've saved in saved_sys_close in the code above.
     * For post-4.17 kernels with a new calling convention, the 32-bit entry
     * stub will be different, so no sensible check is possible here
     */
#ifndef ONLOAD_SYSCALL_PTREGS
#define CHECK_ENTRY(_n, _ptr) (ia32_syscall_table[_n] == (_ptr))
#else
#define CHECK_ENTRY(_n, _ptr) 1
#endif
    TRAMP_DEBUG("ia32_syscall_table=%p: close=%p, exit_group=%p, "
                "rt_sigaction=%p", ia32_syscall_table,
                ia32_syscall_table[__NR_ia32_close],
                ia32_syscall_table[__NR_ia32_exit_group],
                ia32_syscall_table[__NR_ia32_rt_sigaction]);
    saved_sys_rt_sigaction32 = ia32_syscall_table[__NR_ia32_rt_sigaction];
    saved_sys_close32 = ia32_syscall_table[__NR_ia32_close];
    saved_sys_exit_group32 = ia32_syscall_table[__NR_ia32_exit_group];
    ci_mb();

    if (CHECK_ENTRY(__NR_ia32_close, saved_sys_close)) {
      patch_syscall_table (ia32_syscall_table, __NR_ia32_close,
                           efab_linux_trampoline_close32,
                           saved_sys_close32);
    } else {
      TRAMP_DEBUG("expected ia32 sys_close=%p, but got %p", saved_sys_close,
                  ia32_syscall_table[__NR_ia32_close]);
      ci_log("ia32 close syscall NOT hooked");
    }
    if( safe_signals_and_exit &&
        CHECK_ENTRY(__NR_ia32_exit_group, saved_sys_exit_group)) {
#ifndef ONLOAD_SYSCALL_PTREGS
      ci_assert_equal(ia32_syscall_table[__NR_ia32_exit_group],
                      saved_sys_exit_group);
#endif
      patch_syscall_table (ia32_syscall_table, __NR_ia32_exit_group,
                           efab_linux_trampoline_exit_group,
                           saved_sys_exit_group32);
      patch_syscall_table (ia32_syscall_table, __NR_ia32_rt_sigaction,
                           efab_linux_trampoline_sigaction32,
                           saved_sys_rt_sigaction32);
    } else {
      TRAMP_DEBUG("expected ia32 sys_exit_group=%p, but got %p",
                  saved_sys_exit_group,
                  ia32_syscall_table[__NR_ia32_exit_group]);
      ci_log("ia32 exit_group syscall NOT hooked");
    }
    TRAMP_DEBUG("ia32 syscalls hooked: close=%p, exit_group=%p, "
                "rt_sigaction=%p",
                ia32_syscall_table[__NR_ia32_close],
                ia32_syscall_table[__NR_ia32_exit_group],
                ia32_syscall_table[__NR_ia32_rt_sigaction]);
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
  if (syscall_table != NULL && !no_sct) {
    int waiting = 0;

    /* Restore the system-call table to its proper state */
    patch_syscall_table (syscall_table, __NR_close, saved_sys_close,
                         efab_linux_trampoline_close);
    if( safe_signals_and_exit ) {
      patch_syscall_table (syscall_table, __NR_exit_group, saved_sys_exit_group,
                           efab_linux_trampoline_exit_group);
      patch_syscall_table (syscall_table, __NR_rt_sigaction,
                           saved_sys_rt_sigaction,
                           efab_linux_trampoline_sigaction);
    }
    TRAMP_DEBUG("syscalls restored: close=%p, exit_group=%p, rt_sigaction=%p",
                syscall_table[__NR_close], syscall_table[__NR_exit_group],
                syscall_table[__NR_rt_sigaction]);

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
  if (ia32_syscall_table != NULL && !no_sct) {
    /* Restore the ia32 system-call table to its proper state */
    patch_syscall_table (ia32_syscall_table,  __NR_ia32_close,
                         saved_sys_close32, efab_linux_trampoline_close32);
    if( safe_signals_and_exit ) {
      patch_syscall_table (ia32_syscall_table, __NR_ia32_exit_group,
                           saved_sys_exit_group32,
                           efab_linux_trampoline_exit_group);
      patch_syscall_table (ia32_syscall_table, __NR_ia32_rt_sigaction,
                           saved_sys_rt_sigaction32,
                           efab_linux_trampoline_sigaction32);
    }
    TRAMP_DEBUG("ia32 syscalls restored: close=%p, exit_group=%p, "
                "rt_sigaction=%p",
                ia32_syscall_table[__NR_ia32_close],
                ia32_syscall_table[__NR_ia32_exit_group],
                ia32_syscall_table[__NR_ia32_rt_sigaction]);
  }
#endif

  return 0;
}


#ifndef NDEBUG

/* Use the trampoline mechanism to cause userland to fail with a backtrace on
 * exit from this syscall.  We have to find the right place to mess around with
 * the stack, but that's easy: as long as we're executing within a system call,
 * the top of the stack page contains the struct pt_regs that we need.  (Bad
 * things will almost certainly happen if you call this function from any other
 * context!)
 */
void efab_linux_trampoline_ul_fail(void)
{
  struct pt_regs *regs = ((struct pt_regs *)(sp0(&current->thread))) - 1;
  struct mm_hash *p;
  ci_uintptr_t trampoline_ul_fail = 0;

  ci_assert(regs);

  if (current->mm) {
    read_lock (&oo_mm_tbl_lock);
    p = oo_mm_tbl_lookup(current->mm);
    read_unlock (&oo_mm_tbl_lock);
    if (p) {
      trampoline_ul_fail = (ci_uintptr_t) CI_USER_PTR_GET (p->trampoline_ul_fail);
    }
    else {
      ci_log("%s: no entry for pid %u", __FUNCTION__, current->tgid);
      return;
    }
  }
  else {
    ci_log("%s: pid %u is dying - no mm", __FUNCTION__, current->tgid);
    return;
  }

  ci_log("%s: syscall backtrace (pid %d)", __FUNCTION__, current->tgid);
  ci_backtrace();
  ci_log("%s: provoking user-level fail on syscall exit for pid %d",
         __FUNCTION__, current->tgid);

  ip(regs) = trampoline_ul_fail;

  return;
}

#endif /* !NDEBUG */

