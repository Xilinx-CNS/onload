/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
	.file	"linux_trampoline_asm.S"

#include <linux/version.h>

	/* This wraps our replacement for sys_close.  It calls our handler with
	 * a second argument pointing to the stack frame so that we can hook in
	 * the trampoline.
	 *
	 * (This is not strictly necessary for x86, where we can use the
	 * address of the first argument, but is needed for x86_64 where args
	 * are passed in registers.  Doing it the same way for both keeps
	 * things tidy.)
	 */

#if defined(__x86_64__)

/* We have at least the return address on the stack before pt_regs, so pt_regs
 * is no earlier than 8(%rsp).  There might be other stuff in the way, too,
 * but it's up to the handler in C to sort that out. */
#define RSP_TP_PT_REGS_OFFSET_BASE 8

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
/* See Linux changeset 76f5df43cab5e765c0bd42289103e8f625813ae1
 * "Always allocate a complete "struct pt_regs" on the kernel stack":
 * linux used to skip callee-preserved r15-bx registers on older kernels.
 * 6 registers, 8 bytes each gives 48 bytes of offset above base. */
#define RSP_TP_PT_REGS_OFFSET (RSP_TP_PT_REGS_OFFSET_BASE - 6*8)
#else
#define RSP_TP_PT_REGS_OFFSET (RSP_TP_PT_REGS_OFFSET_BASE)
#endif

	.globl	efab_linux_trampoline_close
	.type	efab_linux_trampoline_close,@function
	.align 16
efab_linux_trampoline_close:
	/* The only argument to the C handler is the fd, which is already in
	 * the correct register. */
	jmp	efab_linux_trampoline_handler_close64
.Lfe1:
	.size	efab_linux_trampoline_close,.Lfe1-efab_linux_trampoline_close

# ifdef CONFIG_COMPAT
	.globl	efab_linux_trampoline_close32
	.type	efab_linux_trampoline_close32,@function
	.align 16
efab_linux_trampoline_close32:
/* Unfortunately, ci/efrm/syscall.h where EFRM_SYSCALL_PTREGS is defined,
 * cannot be included in an assembler source
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
	jmp	efab_linux_trampoline_handler_close32
#else
	leaq	RSP_TP_PT_REGS_OFFSET(%rsp),%rax	/* struct pt_regs */
	pushq	%rax					/* last arg */
	call	efab_linux_trampoline_handler_close32
	add	$8,%rsp					/* pop pt_regs */
	ret
#endif
.Lfe2:
	.size	efab_linux_trampoline_close32,.Lfe2-efab_linux_trampoline_close32
# endif

#elif defined(__PPC__)

	.globl	efab_linux_trampoline_close
	.type	efab_linux_trampoline_close,@function
	.align 4
efab_linux_trampoline_close:
	nop
	nop
	nop
	nop
	nop
.Lfe1:
	.size	efab_linux_trampoline_close,.Lfe1-efab_linux_trampoline_close

/*  end elif __PPC__ */

#else

#error "Don't know how to build trampolines for this platform"

#endif

