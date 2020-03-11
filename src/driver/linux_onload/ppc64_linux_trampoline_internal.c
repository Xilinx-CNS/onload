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
*//*! \file linux_trampoline_ppc64_internal.c Utility functions for system call trampolines for Linux/PPC64
** <L5_PRIVATE L5_SOURCE>
** \author  <rrw@kynesim.co.uk>
**  \brief  Package - driver/linux	Linux driver support
**   \date  2012/11/27
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <linux/unistd.h>
#include <linux/ctype.h>	/* for isalnum */
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <asm/paca.h>
#include <asm/cacheflush.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <asm/page.h>		/* PAGE_SIZE */
#include <asm/io.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include "ppc64_linux_trampoline_internal.h"
#include <onload/linux_onload_internal.h>
#include <onload/linux_trampoline.h>

/*! \cidoxg_driver_linux */

/* Macros to extract POWER opcodes and branch addresses */
#define POWER_OPCODE(x) (((x) >> 26)&0x3F)
#define POWER_B_ADDR(cia, b) \
    (((u64)(cia)) + ((b) & 0x03FFFFFC))
#define KERNEL_BASE(paca) ((paca)->kernelbase)

/* Debugging for internal use only */
#  define TRAMP_DEBUG(x...) (void)0

/* These are in fact labels in the PPC64 trampoline assembler */
extern uint32_t __onload_trampoline_ppc64, __onload_end_trampoline_ppc64;

struct ppc64_data_struct
{
    /** Where is the syscall table? */
    void *syscall_table;

    /** Where do we return from? */
    void *syscall_return_point;

    /* An executable page used to hold the thunks, and a pointer to its end, which
    *  the _flush() routines would really like.
    */
    uint8_t *thunks_p, *thunks_q;

    /* Current (byte) offset into the thunk page at which to begin
     *  the next thunk.
     */
    int thunks_used;

    /* Intercepted system calls */
    syscall_entry_t intercept[NR_MAX_SYSCALL_INTERCEPT];

    int nr_intercept;
};

struct ppc64_data_struct ppc64_data;

/* Bytes reserved for thunks - a page should be ample */
#define TOTAL_THUNK_BYTES  PAGE_SIZE


void *get_syscall_return_address(void) { return ppc64_data.syscall_return_point; }

/* Retrieve the DS field from an LD instruction, or return -1 
 */
static int power_ld_ds(uint32_t instr, int32_t *offset)
{
    int opcode = (instr >> 26);
    if (opcode == 58)
    {
        // DS-form; remember to get our sign bits right.
        /* Now, the data manual (PowerISA_203_Final_Public.pdf 
         * says that EA = (RA | 0) + (DS || 0b00) . But in fact,
         * the offset actually applied is just DS. I don't know
         * why?
         *
         * @todo Work out why the data manual doesn't correspond with
         *  actual behaviour.
         */
        (*offset) = ((int32_t)((int16_t)(instr & 0xFFFE))); //   << 1;
        return 0;
    }
    else
    {
        return -1;
    }
}


static inline void *find_toc(void) 
{
    void *p;
    asm ("mr %0, 2" : "=r"(p));
    return p;
}

static void restore_syscall_entry(syscall_entry_t *ent, void *syscall_table)
{
    uint64_t **syscall_p = &((((uint64_t **)syscall_table))[ent->syscall_nr << 1]);    
    TRAMP_DEBUG("Restore syscall entry @ 0x%p to %p, %p\n", syscall_p, 
              ent->original_entry64[0], ent->original_entry32[0]);
    
    syscall_p[0] = (uint64_t *)ent->original_entry64[0];
#ifdef CONFIG_COMPAT
    syscall_p[1] = (uint64_t *)ent->original_entry32[0];
#endif
    flush_dcache_range((unsigned long)syscall_p, (unsigned long)syscall_p + 16);
}

static void patch_syscall_entry(syscall_entry_t *to_patch, void *syscall_table)
{
    uint64_t **syscall_p = &((((uint64_t **)syscall_table))[to_patch->syscall_nr << 1]);

    TRAMP_DEBUG("patching syscall entry @ 0x%p\n", syscall_p);
    {
        struct paca_struct *alpaca = get_paca();

        to_patch->original_entry64[0] = (uint64_t *)syscall_p[0]; // Pointer to 64-bit entry.
        to_patch->original_entry64[1] = (uint64_t *)alpaca->kernel_toc;
        TRAMP_DEBUG("64-bit 0x%p 0x%p \n", to_patch->original_entry64[0], 
                  to_patch->original_entry64[1]);
#ifdef CONFIG_COMPAT
        to_patch->original_entry32[0] = (uint64_t *)syscall_p[1];
        to_patch->original_entry32[1] = (uint64_t *)alpaca->kernel_toc;
        TRAMP_DEBUG("32-bit 0x%p 0x%p \n", to_patch->original_entry32[0], 
                  to_patch->original_entry32[1]);
#endif
    }

    TRAMP_DEBUG("syscall_p[0] = 0x%p \n", syscall_p[0]);

    /* Yes, Jim, this does work. PowerISA book II S1.4: Single-copy atomicity
     *  guarantees 64-bit atomicity for double word writes to aligned locations.
     *  Which is a relief, since otherwise we would have had to hotplug all the
     *  processors down and disable interrupts on this one .. 
     */
    if (to_patch->entry64)
        syscall_p[0] = (uint64_t *)to_patch->entry64;
#ifdef CONFIG_COMPAT
    if (to_patch->entry32)
        syscall_p[1] = (uint64_t *)to_patch->entry32;
#endif
    TRAMP_DEBUG("now syscall_p[0] = 0x%p \n", syscall_p[0]);

    flush_dcache_range((unsigned long)syscall_p, (unsigned long)syscall_p + 16);
}


static uint64_t *find_syscall_table(void **return_addr)
{
    /* POWER instructions are always 32-bits long and it appears
     *  that they change order with the order of the machine, 
     *  so we need to cast to uint32_t to make sure we have the
     *  instruction endianness correct.
     */
    uint32_t *pv;
    struct paca_struct *a_paca = 
        get_paca();
    int i;
    uint32_t sys_call_entry_offset = -1;
    uint32_t *system_call_common = NULL;
    int syscall_toc_offset = INT_MIN;
    uint32_t *clrldis_ends_at = NULL;
    uint64_t *rv = ERR_PTR(-ENOEXEC);

    TRAMP_DEBUG("%s: PACA = %p \n", __func__, a_paca);
    pv = phys_to_virt(0xc00);
    TRAMP_DEBUG("0xC00 = %p", 
              pv);
    (*return_addr) = NULL;

    /* Kernels starting from 3.8 use ORI instead of ADDI */
#define ADDI_ORI_SIGNATURE  0x614A0000

    for (i =0 ;i < (0x80>>2); ++i)
    {
        if ((pv[i] & 0xFFFF0000) == ADDI_ORI_SIGNATURE )
        {
            sys_call_entry_offset = (pv[i] & 0xFFFF);
        }
    }

    if (sys_call_entry_offset & 0x80000000)
    {
        TRAMP_DEBUG("Failed to find ADDI/ORI - sorry, chaps.\n");
        rv = ERR_PTR(-EIO);
        goto end;
    }

    TRAMP_DEBUG("sys_call_entry_offset = 0x%08x \n",
              sys_call_entry_offset);
    /* sys_call_entry_offset is just a branch instruction: 
     */
    TRAMP_DEBUG("Branch @ %p (kb = 0x%016llx)\n",
              (uint32_t *)(KERNEL_BASE(a_paca) + 
                           sys_call_entry_offset), 
              (unsigned long long) KERNEL_BASE(a_paca));
    {
        uint32_t *branch_addr = 
            (uint32_t *)(KERNEL_BASE(a_paca) + sys_call_entry_offset);
        u64 branch_loc = (u64)branch_addr;
        uint32_t branch = *branch_addr;

        /* This is a relative branch and the target address is
           (branch & 0x3FFFFFFC)
        */

        if (POWER_OPCODE(branch) == 0x12)
        {
            system_call_common = (uint32_t *)POWER_B_ADDR(branch_loc, branch);
            TRAMP_DEBUG("system_call_common = %p \n",
                      (uint32_t *)POWER_B_ADDR(branch_loc, branch));
        }
        TRAMP_DEBUG("branch = 0x%08x opcode = 0x%02x\n", branch, 
                  POWER_OPCODE(branch));
    }


    if (!system_call_common)
    {
        TRAMP_DEBUG("Sorry: can't locate system_call_common.\n");
        rv = ERR_PTR(-EIO);
        goto end;
    }

    /* Now, the system call code on PowerPC is pretty horrific and
     *  tracing forwards through it all is quite nasty. So 
     *  we will exploit the fact that just after the toc lookup
     *  there are a series of quite charateristic clrldi instructions.
     */
    {
        static const uint32_t clrldis_sig[] = 
            { 
                0x78630020, // clrldi r3,r3,32
                0x78840020, // clrldi r4,r4,32 
                0x78a50020, // clrldi r5,r5,32
                0x78c60020, // clrldi r6,r6,32
                0x78e70020,  // clrldi r7,r7,32
                0x79080020  // clrldi r8,r8,32
            };
        int match = 0;
        uint32_t *pv = (uint32_t *) system_call_common;

        for (i =0 ;i < 0x200>>2; ++i)
        {
            if (pv[i] == clrldis_sig[match])
            {
                ++match;
                if (match == (sizeof(clrldis_sig) / sizeof(uint32_t)))
                {
                    // Here we are. Our ld is just above.
                    int32_t ds;
                    int ok;
                    ok = power_ld_ds(pv[i-match-3], &ds);
                    
                    if (ok < 0)
                    {
                        TRAMP_DEBUG("LD @ 0x%08x - cannot disassemble. \n",
                                  pv[i-match-3]);
                        rv = ERR_PTR(-EIO);
                        goto end;
                    }
                    syscall_toc_offset = ds;
                    clrldis_ends_at = &pv[i];

                    TRAMP_DEBUG("Found our LD @ 0x%08x - DS = %d \n", 
                              pv[i-match-3], 
                              ds);
                }
            }
            else
            {
                match = 0;
            }
        }
    }
    if (syscall_toc_offset == INT_MIN)
    {
        TRAMP_DEBUG("Cannot find syscall TOC offset. \n");
        rv = ERR_PTR(-EIO);
        goto end;
    }
    
    // dumphex(clrldis_ends_at, 0x200);

    /* Now find the bctrl after the clrldis - this where we come back to.
     */
    {
        int i;
        for (i =0; i < 0x20; ++i)
        {
            if (clrldis_ends_at[i] == 0x4e800421)
            {
                // Found it!
                (*return_addr) = &clrldis_ends_at[i+1];
            }
        }
    }

    if (!(*return_addr))
        {
            TRAMP_DEBUG("Cannot find branch to synthesise return address from.\n");
            rv = ERR_PTR(-EIO);
            goto end;
        }

    {
        uint64_t **syscall_toc = 
            (uint64_t **)(a_paca->kernel_toc + syscall_toc_offset);
        uint64_t *syscall_table = *syscall_toc;
        TRAMP_DEBUG("syscall TOC @ %p (TOC @ 0x%16llx) \n", syscall_toc,
                  (unsigned long long)a_paca->kernel_toc);
        TRAMP_DEBUG("syscall table @ %p\n", syscall_table);

        rv = syscall_table;
    }

    // dumphex((uint32_t *)system_call_common, 0x200);

end:
    return rv;
}

static int thunks_init(struct ppc64_data_struct *ppc64)
{
    ppc64->thunks_p = ppc64->thunks_q = 0;
    ppc64->thunks_used = 0;

    ppc64->thunks_p = (uint8_t *)__vmalloc(TOTAL_THUNK_BYTES, GFP_KERNEL, PAGE_KERNEL_EXEC);
    TRAMP_DEBUG("Allocated thunks @ 0x%p \n", ppc64->thunks_p);
    ppc64->thunks_q = &ppc64->thunks_p[TOTAL_THUNK_BYTES];
    ppc64->thunks_used = 0;
    if (!ppc64->thunks_p)
    {
        return -ENOSPC;
    }
    return 0;
}
       
static void thunks_exit(struct ppc64_data_struct *ppc64)
{
    if (ppc64->thunks_p)
    {
        TRAMP_DEBUG("Free memory @ 0x%p \n", ppc64->thunks_p);
        vfree(ppc64->thunks_p); 
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0) || \
    LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
/* linux<3.12: flush_icache_range is inline, __flush_icache_range is exported;
 * linux>=3.15: flush_icache_range is exported */
#define my_flush_icache_range flush_icache_range
#else
/* flush_icache_range is a non-exported function; we are going to get it
 * out of the kernel using efrm_find_ksym(). */
#define NEED_FLUSH_ICACHE_HACK
#include <ci/efrm/sysdep_linux.h>
static void (*my_flush_icache_range)(unsigned long, unsigned long) = NULL;
#endif

static int thunks_add(struct ppc64_data_struct *ppc64, 
                      void *mod_func, void *return_addr, void *return_toc, void **pptr)
{
    /* We will need sizeof(thunk) + 16 bytes */
    int thunk_bytes = (&__onload_end_trampoline_ppc64 - &__onload_trampoline_ppc64) << 2;
    int new_used = ppc64->thunks_used + thunk_bytes + 32;

    TRAMP_DEBUG("T: p = 0x%p bytes = %d, new_used = %d \n", ppc64->thunks_p, thunk_bytes, new_used);
    (*pptr) = 0;

    if (new_used > TOTAL_THUNK_BYTES)
    {
        return -ENOSPC;
    }
    
    /* Copy the thunk code in */
    memcpy(&ppc64->thunks_p[ppc64->thunks_used], &__onload_trampoline_ppc64, thunk_bytes);
    /* You can just copy the function pointer */
#if defined(_CALL_ELF) && _CALL_ELF >= 2
    memcpy(&ppc64->thunks_p[ppc64->thunks_used + thunk_bytes], 
           (uint8_t *)&mod_func, THUNK_ADDR_SIZE);
#else
    memcpy(&ppc64->thunks_p[ppc64->thunks_used + thunk_bytes], 
           (uint8_t *)mod_func, THUNK_ADDR_SIZE);
#endif
    /* Now the return pointer */
    {
        uint64_t **returnp = (uint64_t **)(&ppc64->thunks_p[ppc64->thunks_used + thunk_bytes + 16]);
        returnp[0] = return_addr;
        returnp[1] = return_toc;
    }


    (*pptr) = (uint32_t *)&ppc64->thunks_p[ppc64->thunks_used];
    ppc64->thunks_used = new_used;
    
    // ..aaand flush.
    flush_dcache_range((unsigned long)ppc64->thunks_p, (unsigned long)ppc64->thunks_q);
    my_flush_icache_range((unsigned long)ppc64->thunks_p, (unsigned long)ppc64->thunks_q);

    return 0;
}

int linux_trampoline_ppc64_internal_ctor(void)
{
    int rv = 0;

#ifdef NEED_FLUSH_ICACHE_HACK
    if( my_flush_icache_range == NULL )
      my_flush_icache_range = efrm_find_ksym("flush_icache_range");
    if( my_flush_icache_range == NULL ) {
      ci_log("%s: failed to find flush_icache_range() function.  "
             "Proceeding as if no_sct parameter was set to 1/",
             __func__);
      return -EINVAL;
    }
#endif

    memset(&ppc64_data, '\0', sizeof(struct ppc64_data_struct));

    TRAMP_DEBUG("%s: running.\n", __func__);
    /* Find the syscall table */
    ppc64_data.syscall_table = 
        find_syscall_table(&ppc64_data.syscall_return_point);
    if (IS_ERR(ppc64_data.syscall_table))
    {
        pr_err("Cannot find syscall table - %ld\n", PTR_ERR(ppc64_data.syscall_table));
        rv = -EIO;
        goto end;
    }

    if( ppc64_data.syscall_table )
      efab_linux_termination_ctor();

    thunks_init(&ppc64_data);

end:
    return rv;
}

void linux_trampoline_ppc64_restore_syscalls(void)
{
    int i;
    TRAMP_DEBUG("%s: running nr_intercept = %d p = 0x%p.\n", __func__, 
              ppc64_data.nr_intercept, ppc64_data.thunks_p);
    for (i =0 ;i < ppc64_data.nr_intercept; ++i)
    {
        restore_syscall_entry(&ppc64_data.intercept[i], 
                              ppc64_data.syscall_table);
    }
}

void linux_trampoline_ppc64_dispose(void)
{
    thunks_exit(&ppc64_data);
}

syscall_entry_t *linux_trampoline_ppc64_intercept_syscall(int syscall_nr,
                                                          void *entry64, 
                                                          void *entry32)
{
    syscall_entry_t *ent;
    int rc;

    if (ppc64_data.nr_intercept >= NR_MAX_SYSCALL_INTERCEPT) 
    {
        ent = ERR_PTR(-ENOSPC);
        goto end;
    }

    ent = &ppc64_data.intercept[ppc64_data.nr_intercept];
    ent->syscall_nr = syscall_nr;

    /* @todo
     *
     *  No reason why we have to have different thunks - most
     *  64-bit entry points are the same as 32-bit entry points
     *  so we could theoretically share the thunk.
     */
    if (entry64)
    {
        rc = thunks_add(&ppc64_data, entry64, ppc64_data.syscall_return_point,
                        (void *)get_paca()->kernel_toc,  &ent->entry64);
        if (rc)
        {
            TRAMP_DEBUG("Cannot create 64-bit thunk: %d \n", rc);
            ent = ERR_PTR(rc);
            goto end;
        }
    }
    else
    {
        ent->entry64 = NULL;
    }

#ifdef CONFIG_COMPAT
    if (entry32)
    {
        rc = thunks_add(&ppc64_data, entry32, ppc64_data.syscall_return_point,
                        (void *)get_paca()->kernel_toc, &ent->entry32);
        if (rc)
        {
            TRAMP_DEBUG("Cannot create 32-bit thunk: %d \n", rc);
            ent = ERR_PTR(rc);
            goto end;
        }
    }
    else
    {
        ent->entry32 = NULL;
    }
#endif

    TRAMP_DEBUG("64-bit thunk @ %p , 32-bit thunk @ %p, \n",
              ent->entry64, ent->entry32);

    TRAMP_DEBUG("Patch syscall entry .. \n");
    patch_syscall_entry(ent, ppc64_data.syscall_table);

end:
    if (!IS_ERR(ent))
    {
        ++ppc64_data.nr_intercept;
    }
    return ent;
}


int setup_trampoline32(struct pt_regs *regs, int opcode, int data, 
                       u32 __user *fn, u32 __user *toc,
                       u32 __user *fixup_fn)
{
    /* This is just like tramp64, but with 32-bit pointers; note that
     * our kernel data structures are still 64-bit.
     */
#define PPC32_STACK_FRAME_BYTES ((64+48) >> 1)
    uint32_t new_stack_buf[(PPC32_STACK_FRAME_BYTES >> 2)];
    uint64_t new_user_sp;
    
    TRAMP_DEBUG("%s: pt_regs = 0x%p \n", __func__,  regs);
    TRAMP_DEBUG("userspace stack = 0x%p pt->nip 0x%p toc = 0x%p pt->link 0x%p \n", 
              (void *)regs->gpr[1], (void *)regs->nip, (void *)regs->gpr[2], (void *)regs->link);

    new_user_sp = regs->gpr[1] - PPC32_STACK_FRAME_BYTES;
    memset(new_stack_buf, '\0', PPC32_STACK_FRAME_BYTES);

    /* The trampolined user function will use all the "system" areas of
     * this stack frame to save data in, so we need to stash all our
     * stuff in the parameter save area at the top, with the exception
     * of the frame pointer, which can go in our stack entry.
     *
     * Parameter save is at 24(1) ==> 8.
     */
    new_stack_buf[0] = regs->gpr[1];
    new_stack_buf[9] = regs->link;
    new_stack_buf[10] = regs->gpr[2]; // Save the old TOC
    new_stack_buf[11] = regs->nip; // This is where we should return to.

    /* We need to stash these, annoyingly. Some kernels actually corrupt
     *  r4, r5 on return from a syscall since they assume the compiler
     *  won't believe they're unchanged - so we have to stash these
     *  on the user mode stack and use a bit of assembler to steal them
     *  back later.
     */
    new_stack_buf[12] = opcode;
    new_stack_buf[13] = data;
    if (copy_to_user((void *)(new_user_sp), new_stack_buf, PPC32_STACK_FRAME_BYTES))
    {
        TRAMP_DEBUG("Can't copy new userspace stack entry! \n");
        return -EIO;
    }
    /* Now the new user-mode stack is in place, modify the saved registers
     * so that we will magically return to it on return from whatever syscall
     * we are processing.
     */
    TRAMP_DEBUG("Userspace fn = 0x%p , toc = %p fixup = 0x%p \n", fn, toc, 
              fixup_fn);
    TRAMP_DEBUG("New_user_sp = 0x%p \n", (void *)new_user_sp);
    regs->gpr[1] = new_user_sp;
    regs->link = (u64)fixup_fn;
    regs->gpr[2] = (u64)toc;
    regs->nip = (u64)fn;


    TRAMP_DEBUG("Dump new userspace stack @ 0x%p \n", (void *)new_user_sp);
    {
        uint8_t stack_buf[0x200];
        if (copy_from_user(stack_buf, (void * )new_user_sp, 0x200))
        {
            TRAMP_DEBUG("Can't copy stack back! \n");
        }
        else
        {
            // dumphex(stack_buf, 0x200);
        }
    }
    
    return 0;

}

int setup_trampoline64(struct pt_regs *regs, int opcode, int data, 
                       u32 __user *fn, u64 __user *toc,
                       u32 __user *fixup_fn)
{
    /* Essentially everything gets restored from the user-mode stack.
     * Since our user-mode thunk has two arguments, we pass them in registers.
     * So let's invent a fake stack frame for our user-mode thunk. We can then
     * just paste it onto the bottom of the user-mode stack and return from the
     * syscall and the Linux return code will take care of returning to the
     * "right" place, as though we had called a function rather than issuing
     * a syscall.
     *
     * PowerPC stack frame layout, from
     * http://www.ibm.com/developerworks/linux/library/l-powasm4/index.html
     *
     * 
     *         .. parameter save area must be min 64 bytes .. 
     *          56(1)  - Parameter 1
     *          48(1)  - Parameter 0
     *          40(1)  - TOC save area.
     *          32(1)  - Link editor area.
     *          24(1)  - Compiler area.
     *          16(1)  - LR save.
     *           8(1)  - CR save.
     *           0(1)  - Pointer to top of previous stack frame.
     *
     * Parameter 1 wants also to go in GP3, while parameter 0 ends up in GP4.
     *
     * The last entry on the kernel stack is a perfectly normal user-mode stack pointer.
     */
    // == 112, the minimum PowerPC stack frame size.
#define PPC64_STACK_FRAME_BYTES (64+48)

    uint64_t new_stack_buf[(PPC64_STACK_FRAME_BYTES >> 3)];
    uint64_t new_user_sp;
    
    TRAMP_DEBUG("%s: pt_regs = 0x%p \n", __func__,  regs);
    TRAMP_DEBUG("userspace stack = 0x%p pt->nip 0x%p toc = 0x%p pt->link 0x%p \n", 
              (void *)regs->gpr[1], (void *)regs->nip, (void *)regs->gpr[2], (void *)regs->link);
    new_user_sp = regs->gpr[1] - PPC64_STACK_FRAME_BYTES;
    memset(new_stack_buf, '\0', PPC64_STACK_FRAME_BYTES);

    /* The trampolined user function will use all the "system" areas of
     * this stack frame to save data in, so we need to stash all our
     * stuff in the parameter save area at the top, with the exception
     * of the frame pointer, which can go in our stack entry.
     *
     * Parameter save is at 48(1) ==> 8.
     */
    new_stack_buf[0] = regs->gpr[1];
    new_stack_buf[9] = regs->link;
    new_stack_buf[10] = regs->gpr[2]; // Save the old TOC
    new_stack_buf[11] = regs->nip; // This is where we should return to.

    /* We need to stash these, annoyingly. Some kernels actually corrupt
     *  r4, r5 on return from a syscall since they assume the compiler
     *  won't believe they're unchanged - so we have to stash these
     *  on the user mode stack and use a bit of assembler to steal them
     *  back later.
     */
    new_stack_buf[12] = opcode;
    new_stack_buf[13] = data;
    if (copy_to_user((void *) new_user_sp, new_stack_buf, PPC64_STACK_FRAME_BYTES))
    {
        TRAMP_DEBUG("Can't copy new userspace stack entry! \n");
        return -EIO;
    }
    
    /* Now the new user-mode stack is in place, modify the saved registers
     * so that we will magically return to it on return from whatever syscall
     * we are processing.
     */
    TRAMP_DEBUG("Userspace fn = 0x%p , toc = %p fixup = 0x%p \n",fn, toc, 
              fixup_fn);
    TRAMP_DEBUG("New_user_sp = 0x%p \n", (void *)new_user_sp);
    regs->gpr[1] = new_user_sp;
    regs->link = (u64)fixup_fn;
    regs->gpr[2] = (u64)toc;
    regs->nip = (u64)fn;

    TRAMP_DEBUG("Dump new userspace stack @ 0x%p \n", (void *)new_user_sp);
    {
        uint8_t stack_buf[0x200];
        if (copy_from_user(stack_buf, (void * )new_user_sp, 0x200))
        {
            TRAMP_DEBUG("Can't copy stack back! \n");
        }
        else
        {
            // dumphex(stack_buf, 0x200);
        }
    }
    
    return 0;
}

/* End file */


