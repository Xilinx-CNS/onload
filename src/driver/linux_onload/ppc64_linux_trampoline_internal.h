/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
*//*! \file linux_trampoline_ppc64_internal.h  Internal interface for PPC64 trampolines.
** <L5_PRIVATE L5_SOURCE>
** \author  <rrw@kynesim.co.uk>
**  \brief  Package - driver/linux	Linux driver support
**   \date  2012/11/27
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/


#ifndef __ONLOAD_LINUX_TRAMPOLINE_PPC64_INTERNAL_H__
#define __ONLOAD_LINUX_TRAMPOLINE_PPC64_INTERNAL_H__

/* The main difference between POWER ABIv1 and POWER ABIv2 is
 * the structure of function pointers.
 * For ABIv1 the function pointer is a pointer to a pair (entrypoint pointer, TOC),
 * but for ABIv2 it's just entry point pointer, as is common in other archs.
 * Thunks are always (entry point, TOC), so for ABIv2 we must take the first element.
 */
#if defined(_CALL_ELF) && _CALL_ELF >= 2
#define THUNKPTR(_x) ((_x)[0])
#define THUNK_ADDR_SIZE (sizeof(void *))
#else
#define THUNKPTR(_x) (_x)
#define THUNK_ADDR_SIZE (2 * sizeof(void *))
#endif

typedef struct syscall_entry_struct
{
    int syscall_nr;

    void *entry64;
#ifdef CONFIG_COMPAT
    void *entry32;
#endif
    
    /* These are in fact type-punned indirect function pointers,
     * ( fn, toc ), so that you can call them to get the original
     * syscall entry point - obviously you will want to cast to
     * appropriate function pointers.
     *
     * Note that this only works because there is just one kernel
     * toc - if that ever becomes per-CPU, horrific things will
     * happen and we will have to think again.
     */
    void *original_entry64[2];
#ifdef CONFIG_COMPAT
    void *original_entry32[2];
#endif
} syscall_entry_t;

/* Initialise the trampoline */
int linux_trampoline_ppc64_internal_ctor(void);

/* Restore all our syscall hooks */
void linux_trampoline_ppc64_restore_syscalls(void);

/* Dispose of our memory */
void linux_trampoline_ppc64_dispose(void);

/* We actually use 15 of these slots at present */
#define NR_MAX_SYSCALL_INTERCEPT  24

/* Intercept a system call - _dtor() will automatically unregister
 * you on exit.
 *
 * You can only register up to NR_MAX_SYSCALL_INTERCEPT syscalls
 *
 * Pass NULL for entry64 and entry32 to not replace the syscall table entry -
 *   just return the entry so that we can call the functions ourselves.
 */
syscall_entry_t *linux_trampoline_ppc64_intercept_syscall(int syscall_nr,
                                                          void *entry64,
                                                          void *entry32);


typedef int (*user_mode_trampoline_fn_t)(int sys_rv, int opcode, int data);

/* Set up a trampoline 
 *
 * fn is the user mode trampoline function. This is a proper (ptr, toc) function
 *  pointer - expressed here as a void * because I am afraid that the compiler
 *  might otherwise attempt to do something clever with it.
 *
 * fixup_fn is a (userspace) pointer to the fixup assembler.
 *
 */
int setup_trampoline64(struct pt_regs *regs, int opcode, int data, 
                       u32 __user *fn, u64 __user *toc,
                       u32 __user *fixup_fn);

/* The 32-bit version of setup_trampoline64
 */
int setup_trampoline32(struct pt_regs *regs, int opcode, int data, 
                       u32 __user *fn, u32 __user *toc, 
                       u32 __user *fixup_fn);

/* This must be a macro because making it a function might cause it to
 *  allocate space on the stack ..  The '1' is magic - your syscall
 *  function has one stack frame above it (we know this because you
 *  were called via our thunk).
 */
#define PT_REGS_FROM_SYSCALL()  ((struct pt_regs *)(&((u8 *)__builtin_frame_address(1))[STACK_FRAME_OVERHEAD]))

#endif


/* End file */
