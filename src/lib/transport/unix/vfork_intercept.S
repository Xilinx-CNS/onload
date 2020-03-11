/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
	.file	"vfork_intercept.S"
/*
   The general idea for all platforms is as follows:
   After vfork() the two processes share the whole address space,
   including the stack, but not including registers and other CPU state.
   The calling process is suspended until the child terminates or calls exec...(),
   however since the stack is shared, the child process must be extra careful as to not
   corrupt the stack. Therefore, it is strictly forbidden for a child process to return
   from a function that calls vfork(), because that would leave the stack in an unpredictable state,
   and the calling process would barf once resumed.
   However, when we intercept vfork(), we *do* need to call from the function calling system vfork().
   Hence we need to preserve the return address and jump to it, instead of doing normal return
   There are also additional caveats:
   - the code should be position-independent
   - if the intercepting code need some auxiliary registers to hold data before and after the call to system
   vfork() (and it may be needed to implement the previous), extra precautions need to be taken, because:
   - a register that is declared volatile in ABI could be destroyed by system vfork()
   - a register that is declared non-volatile in ABI should be preserved by the intercepting code.
   Thankfully, since vfork() usage is in itself very fragile, several assumptions may be safely made:
   - we only need to protect the immediate return address, not the whole call chain, because the caller of vfork()
   must not return in the child process
   - fixing vfork and threads is a sort of painful suicide, so we need not care about thread-safety
;;;
   The general code flow is as follows:
   - test the flag onload__vfork_is_vfork
   (it is actually a function, because it tests a field in configuration structure, and it is simpler
   to call the function from assembler than to ensure proper field offset)
   - if it is zero, call onload__vfork_as_fork() function which does not require any special
   treatment and is defined in sockall_intercept.c
   - save what need to be saved, in particular, the return address
   - call ci_sys_vfork which is an address of system vfork()
   - in parent, call citp_netif_parent_vfork_hook
   - in child, call citp_netif_child_vfork_hook
   - restore what need to be restored
   - jump to the saved return address (not doing a normal function return)

   The details are platform-dependent and are documented below
*/

#if defined(__i386__)

	/* x86 calling convention: args pushed on stack in reverse order */

	.text
	.align 16
	.globl	onload_vfork
	.type	onload_vfork,@function
	.globl onload___vfork_as_fork
	.globl ci_sys_vfork
	.globl onload___vfork_is_vfork
	.globl citp_netif_child_vfork_hook
	.globl citp_netif_parent_vfork_hook
onload_vfork:
/* EBX must be preserved for PIC code, because it holds GOT  */
	pushl %ebx
/* This is the ABI-recommended way to do PIC (hint: we need to know the contents of IP) */
	call 1f
1:
    popl %ebx
	addl $_GLOBAL_OFFSET_TABLE_+[.-1b], %ebx
	call onload___vfork_is_vfork@PLT
	test %eax, %eax
	jz 1f
	popl 4(%eax)                  /* save caller's EBX */
	popl (%eax)                   /* save return address */
/* Calling system vfork() through function pointer */
	movl ci_sys_vfork@GOT(%ebx), %eax
	call *(%eax)
/* Need to preserve the returned value of system vfork */
/* across calling the hooks */
	push %eax
	testl %eax, %eax
	jz 2f
	call citp_netif_parent_vfork_hook
	jmp 3f
2:
	call citp_netif_child_vfork_hook
3:
/* Restoring everything */
	mov 4(%eax), %ebx
	mov (%eax), %edx
	pop %eax
/* Jump to the preserved return address */
	jmp *%edx
1:
	call onload___vfork_as_fork@PLT
	popl %ebx
	ret

	.globl vfork
	vfork = onload_vfork
#elif defined(__x86_64__)

	/* x86_64 calling convention: args 1,2,3 in registers rdi,rsi,rdx */
	.text
	.align 16
	.globl	onload_vfork
	.type	onload_vfork,@function
	.globl ci_sys_vfork
	.globl onload___vfork_as_fork
	.globl onload___vfork_is_vfork
	.globl citp_netif_child_vfork_hook
	.globl citp_netif_parent_vfork_hook
onload_vfork:

/* x86_64 has direct support for IP-relative addressing, */
/* hence no special support for PIC, only need to save the return adddress */
	call onload___vfork_is_vfork@PLT
	test %rax, %rax
	jz 1f
	popq (%rax)            /* saving return address */
/* Calling system vfork() */
	movq ci_sys_vfork@GOTPCREL(%rip), %rax
	call *(%rax)
/* Preserving the return value of vfork() across calling hooks */
	pushq %rax
	testl %eax, %eax
	jz 2f
	call citp_netif_parent_vfork_hook
	jmp 3f
2:
	call citp_netif_child_vfork_hook
3:
/* Restore everything */
	movq (%rax), %rdx
	popq %rax
/* Jump to the returned address */
	jmp *%rdx
1:
	jmp onload___vfork_as_fork@PLT

	.globl vfork
	vfork = onload_vfork

#endif	 /* __1386__ or __x86_64__ */
#if defined(__PPC64__) && (!defined(_CALL_ELF) || _CALL_ELF < 2)

   .text
   .align   3
   .globl .onload_vfork
   .type .onload_vfork,@function
   .section ".opd","aw";
   .globl onload_vfork;
   .align 3;
onload_vfork: .quad .onload_vfork, .TOC.@tocbase, 0;
   .previous
/* The main caveat for PPC64 is that function pointer are not just code pointers, */
/* they hold PIC-related data as well */

.onload_vfork:
	mflr %r0
/* R2 is GOT pointer */
/* Saving the return address and R31 which we will need as temporary storage */
/* (and which is non-volatile as per ABI) */
	ld %r6, onload___vfork_rtaddr@got(%r2)
	std %r0, 0(%r6)
	ld %r6, onload___vfork_r31@got(%r2)
	std %r31, 0(%r6)
	bl .onload___vfork_is_vfork
	nop
 	cmpdi %r3,0
	beq .Lfork
/* Calling system vfork through pointer */
	ld    %r6,ci_sys_vfork@got(%r2)
    ld    %r6,0(%r6)
    ld    %r0,0(%r6)
/* R31 will hold our copy of R2 (TOC) */
    mr   %r31,%r2
    mtctr %r0
/* Load new R2 from function pointer */
    ld    %r2,8(%r6)
    bctrl
/* Restore our R2 */
    mr    %r2,%r31
/* Save vfork return value across calling hooks */
	mr    %r31,%r3
	cmpdi %r3,0
    beq .Linchild
    bl .citp_netif_parent_vfork_hook
	nop
	mr %r3,%r31
	b .Lret
.Linchild:
    bl .citp_netif_child_vfork_hook
	nop
	mr %r3,%r31
	b .Lret
.Lfork:
    bl .onload___vfork_as_fork
	nop
.Lret:
/* Restore everything */
	ld %r6, onload___vfork_r31@got(%r2)
	ld %r31, 0(%r6)
	ld %r6, onload___vfork_rtaddr@got(%r2)
	ld %r0, 0(%r6)
/* Return to the preserved link address */
	mtlr %r0
	blr

.globl vfork
vfork = onload_vfork
.globl .vfork
.vfork = .onload_vfork


#elif defined(__PPC64__) && defined(_CALL_ELF) && _CALL_ELF >= 2
        /* assume for now that this is called as a normal function - create
         * GEP and LEP entry points .  Also, add symbol table entry for LEP,
         * and mark it as ABI ELFv2 mkg
         */
        .abiversion 2
        .text
        .align 3
        .globl onload_vfork
        .type onload_vfork,@function

onload_vfork:
        addis    %r2, %r12, (.TOC. - onload_vfork)@ha
        addi  %r2, %r2, (.TOC. - onload_vfork)@l
.localentry onload_vfork,. - onload_vfork
        mflr %r0
        ld %r6, onload___vfork_rtaddr@got(%r2)
        std %r0, 0(%r6)
        ld %r6, onload___vfork_r31@got(%r2)
        std %r31, 0(%r6)
        bl .onload___vfork_is_vfork
        nop
        cmpdi %r3,0
        beq .Lfork
        ld    %r6,ci_sys_vfork@got(%r2)
        ld    %r6,0(%r6)
        ld    %r0,0(%r6)
        mr   %r31,%r2
        mtctr %r0
        ld    %r2,8(%r6)
        bctrl
        mr    %r2,%r31
        mr    %r31,%r3
        cmpdi %r3,0
        beq .Linchild
        bl .citp_netif_parent_vfork_hook
        nop
        mr %r3,%r31
        b .Lret
.Linchild:
        bl .citp_netif_child_vfork_hook
        nop
        mr %r3,%r31
        b .Lret
.Lfork:
        bl .onload___vfork_as_fork
        nop
.Lret:
        ld %r6, onload___vfork_r31@got(%r2)
        ld %r31, 0(%r6)
        ld %r6, onload___vfork_rtaddr@got(%r2)
        ld %r0, 0(%r6)
        mtlr %r0
        blr

.globl vfork
vfork = onload_vfork


#elif defined(__PPC__)
    .text
    .align 3
    .globl onload_vfork
    .type onload_vfork,@function

/* On PPC32, unlike PPC64, function pointers are plain code pointers */

onload_vfork:
     mflr %r0
/* Determining our GOT address (the same principle as with i386) */
     bcl     20,31,1f
1:   mflr    %r6
     addis   %r6,%r6,_GLOBAL_OFFSET_TABLE_-1b@ha
     addi    %r6,%r6,_GLOBAL_OFFSET_TABLE_-1b@l
/* Saving the return address and R31 */
     lwz %r7, onload___vfork_rtaddr@got(%r6)
     stw %r0, 0(%r7)
     lwz %r7, onload___vfork_r31@got(%r6)
     stw %r31, 0(%r7)
/* Saving our GOT address  */
     mr %r31, %r6
     bl onload___vfork_is_vfork
     cmpwi %r3, 0
     beq 2f
/* Calling system vfork */
     lwz %r6, ci_sys_vfork@got(%r31)
     lwz %r0, 0(%r6)
     mtctr %r0
     bctrl
/* Saving vfork return value across calling hooks */
     lwz %r7, onload___vfork_r3@got(%r31)
     stw %r3, 0(%r7)
     cmpwi %r3, 0
     beq 4f
     bl citp_netif_parent_vfork_hook
     b 5f
4:
     bl citp_netif_child_vfork_hook
5:
/* Restore vfork return value */
     lwz %r7, onload___vfork_r3@got(%r31)
     lwz %r3, 0(%r7)
     b 3f
2:
     bl onload___vfork_as_fork
3:
/* Restore return address and R31 */
     lwz %r6, onload___vfork_rtaddr@got(%r31)
     lwz %r0, 0(%r6)
     mtlr %r0
     lwz %r6, onload___vfork_r31@got(%r31)
     lwz %r31, 0(%r6)
/*  Jump to the saved link address */
     blr

.globl vfork
vfork = onload_vfork

#endif /* __PPC64__ */
#if defined(__aarch64__)
/* AArch64 code is always position-independent,
   so it poses the least trouble
 */

    .text
    .align 3
    .globl onload_vfork
    .type onload_vfork,@function

onload_vfork:
/* AArch64 has direct support for IP-relative addressing, */
/* hence no special support for PIC, only need to save the return adddress */
     /* save lr on stack across call to __vfork_is_vfork */
     sub sp, sp, #16
     str x30, [sp]
     bl onload___vfork_is_vfork
     ldr x30, [sp]
     add sp, sp, #16

     cmp x0, #0
     b.eq 1f
     str x30, [x0]     /* save return addr in TLS */
/* Calling system vfork() */
/* This should be just adrl x0, ci_sys_vfork, */
/* but GNU as 2.28 does not understand this pseudo-instruction */
     adrp x0, ci_sys_vfork
     ldr x0, [x0, #:lo12:ci_sys_vfork]
     blr x0
/* Preserving the return value of vfork() across calling hooks */
     sub sp, sp, #16
     str w0, [sp]
     cmp w0, #0
	 b.eq 2f
	 bl citp_netif_parent_vfork_hook
	 b 3f
2:
	 bl citp_netif_child_vfork_hook
3:
/* Restore everything */
     ldr x30, [x0]
     ldr w0, [sp]
     add sp, sp, #16
/* Jump to the returned address */
	 ret
1:
	 b onload___vfork_as_fork

.globl vfork
vfork = onload_vfork

#endif


    /* Tell everybody that we do not need executable stack.
     * Make SELinux happy. */
    .section .note.GNU-stack
    .previous
