/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifdef __i386__
/* Registers to use:
 *   eax - oldval_lo
 *   edx - oldval_hi
 *   ebx - newval_lo (call preserved)
 *   ecx - newval_hi
 *   esi - pointer   (call preserved)
 *
 * Stack contents on entry:
 *    4(%esp) - pointer
 *    8(%esp) - oldval_lo
 *   12(%esp) - oldval_hi
 *   16(%esp) - newval_lo
 *   20(%esp) - newval_hi
 */
        .text

        .p2align 4,,15
.globl ci_cas64u_succeed
        .type   ci_cas64u_succeed, @function
ci_cas64u_succeed:

        /* Reserve some stack space. */
        subl    $8, %esp

        /* Load the arguments, saving old values. */
        movl    %esi,     0(%esp)
        movl    12(%esp), %esi     /* pointer */

        movl    16(%esp), %eax     /* oldval_lo */

        movl    20(%esp), %edx     /* oldval_hi */

        movl    %ebx,     4(%esp)
        movl    24(%esp), %ebx     /* newval_lo */

        movl    28(%esp), %ecx     /* newval_hi */

        /* Do the atomic operation and save the result. */
        lock
          cmpxchg8b (%esi)
        sete %al

        /* Restore registers. */
        movl    0(%esp),  %esi
        movl    4(%esp),  %ebx

        /* Zero extend the result. */
        movsbl  %al, %eax

        /* Restore the stack pointer and return. */
        addl    $8, %esp
        ret

        .size   ci_cas64u_succeed, .-ci_cas64u_succeed

        .p2align 4,,15
.globl ci_cas64u_fail
        .type   ci_cas64u_fail, @function
ci_cas64u_fail:

        /* Reserve some stack space. */
        subl    $8, %esp

        /* Load the arguments, saving old values. */
        movl    %esi,     0(%esp)
        movl    12(%esp), %esi     /* pointer */

        movl    16(%esp), %eax     /* oldval_lo */

        movl    20(%esp), %edx     /* oldval_hi */

        movl    %ebx,     4(%esp)
        movl    24(%esp), %ebx     /* newval_lo */

        movl    28(%esp), %ecx     /* newval_hi */

        /* Do the atomic operation and save the result. */
        lock
          cmpxchg8b (%esi)
        setne %al

        /* Restore registers. */
        movl    0(%esp),  %esi
        movl    4(%esp),  %ebx

        /* Zero extend the result. */
        movsbl  %al, %eax

        /* Restore the stack pointer and return. */
        addl    $8, %esp
        ret

        .size   ci_cas64u_fail, .-ci_cas64u_fail
#endif
