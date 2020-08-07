/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2019 Xilinx, Inc. */
	.file	"trampoline_asm.S"

	/* This code just sorts out the stack for the trampoline receiving
	 * C code.  (Stack and registers are set up appropriately by the kernel
	 * side.)
	 */

#if defined(__i386__)

	/* x86 calling convention: args pushed on stack in reverse order */

	.text
	.align 16
	.globl	ci_trampoline_handler_entry
	.hidden ci_trampoline_handler_entry
	.type	ci_trampoline_handler_entry,@function
ci_trampoline_handler_entry:
	/* stack layout set up by kernel is:
	 *    return address
	 *    original %ecx
	 *    original %edx
	 *    data argument
	 *    opcode argument   <- %esp
	 */
	call	ci_trampoline_handler
	add	$8,%esp		/* Fix stack (ie. remove params) */
        pop     %edx            /* restore preserved edx */
        pop     %ecx            /* restore preserved ecx */
	ret			/* Return to whence sys-call originally came */
.Lfe1:
	.size	ci_trampoline_handler_entry,.Lfe1-ci_trampoline_handler_entry

#elif defined(__x86_64__)

	/* x86_64 calling convention: args 1,2,3 in registers rdi,rsi,rdx */

	.text
	.align 16
	.globl	ci_trampoline_handler_entry
	.hidden ci_trampoline_handler_entry
	.type	ci_trampoline_handler_entry,@function
ci_trampoline_handler_entry:
        /* calling conventions for syscall and func call differ.  The function
         * may trash rsi,rdi,rdx,r8,r9; syscalls do not (note: preserved rsi/
         * rdi already placed on stack by kernel trampoline code)
         */
        push    %rdx
        push    %r8
        push    %r9
#if __GNUC__ < 6
        /* Modern x86_64 ABI requires that stack pointer be 16-byte aligned
         * on function entry. Not doing so may result in SSE-related memory
         * traps (see bug 84269).
         *
         * For gcc 6+ onwards this code is replaced by force_align_arg_pointer
         * attribute for ci_trampoline_handler.
         */
        push    %rbp
        movq    %rsp, %rbp
        and     $~0x0f, %rsp
#endif
	call	ci_trampoline_handler@PLT
#if __GNUC__ < 6
        leave
#endif
        pop     %r9
        pop     %r8
        pop     %rdx
        pop     %rsi
        pop     %rdi
	ret			/* Return to whence sys-call originally came */
.Lfe1:
	.size	ci_trampoline_handler_entry,.Lfe1-ci_trampoline_handler_entry

#endif	 /* __1386__ or __x86_64__ */



#if defined(__PPC__)

   .text
   .align   3

#if defined(__PPC64__)
   /* Note lack of a .func declaration for this bit of code - it is
    * emphatically _not_ a function
    */
   .globl onload_trampoline_user_fixup_64
onload_trampoline_user_fixup_64:
        /* Restore the link register */
        ld 2, 72(1)
        mtlr 2
        /* Restore the old IP to ctr */
        ld 2, 88(1)
        mtctr 2
        /* Restore the TOC */
        ld 2, 80(1)
        /* Restore the stack */
        ld 1, 0(1)
        /* And branch */
        bctr
#else
        .globl onload_trampoline_user_fixup_32
onload_trampoline_user_fixup_32:
        lwz 2, 36(1)
        mtlr 2
        lwz 2, 44(1)
        mtctr 2
        lwz 2, 40(1)
        lwz 1, 0(1)
        bctr
#endif

#endif	/* __PPC__ */

#if defined(__aarch64__)

   .text
   .align   3

   .globl	ci_trampoline_handler_entry
   .hidden ci_trampoline_handler_entry
   .type	ci_trampoline_handler_entry,@function
ci_trampoline_handler_entry:
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    str     x2,  [x29, #24]
    bl ci_trampoline_handler
    ldr     x2,  [x29, #24]
    ldp     x29, x30, [sp], #32
    br x2
#endif

    /* Tell everybody that we do not need executable stack.
     * Make SELinux happy. */
    .section .note.GNU-stack
    .previous
