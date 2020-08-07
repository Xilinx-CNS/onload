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
*//*! \file linux_trampoline_ppc64_asm.S      Assembler trampoline functions for PPC64 trampolines
** <L5_PRIVATE L5_SOURCE>
** \author  <rrw@kynesim.co.uk>
**  \brief  Package - driver/linux	Linux driver support
**   \date  2012/11/27
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/


        /* @todo One could shorten this trampoline if one were only interested in
        *        intercepting system calls - syscalls involve a toc transition
        *        so you don't need to preserve the toc across the syscall - it'll
        *        be restored automagically when the sc returns anyway.
        *
        *        This only works because the syscall table is never entered from
        *        more than one place - if it ever is, we will have to copy the
        *        stack frame down from the syscall.
        */

        .section ".text"
        .align 3
        .globl __onload_trampoline_ppc64
        .globl __onload_end_trampoline_ppc64
__onload_trampoline_ppc64:
        std 31, 8(1)
        bl 1f
1:      mflr 31
#if !defined(_CALL_ELF) || _CALL_ELF < 2
        ld 2, __onload_end_trampoline_ppc64-1b+8(31)
#else
        std 2, __onload_end_trampoline_ppc64-1b+8(31)
#endif
        ld 31, __onload_end_trampoline_ppc64-1b(31)
        mtlr 31
#if defined(_CALL_ELF) && _CALL_ELF >= 2
	mr 12, 31
#endif
        ld 31, 8(1)
        blrl
        /* Same trick again on the way back */
        std 31, 8(1)
        bl 2f
2:      mflr 31
#if !defined(_CALL_ELF) || _CALL_ELF < 2
        ld 2, __onload_end_trampoline_ppc64-2b+24(31)
#else
        ld 2, __onload_end_trampoline_ppc64-2b+8(31)
#endif
        ld 31, __onload_end_trampoline_ppc64-2b+16(31)
        mtlr 31
        ld 31, 8(1)
        blr
        .align 3
__onload_end_trampoline_ppc64:
        /* Put a pointer ( fn, toc ) to the trampoline here */
        /* Put a pointer ( fn, toc ) to the return address here */

        /* End file */
