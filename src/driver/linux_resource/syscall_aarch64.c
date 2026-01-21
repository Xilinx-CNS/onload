/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#include <ci/compat.h>
#include <ci/efrm/sysdep_linux.h>
#include <ci/efrm/debug_linux.h>
#include <ci/efrm/syscall.h>

#if 1
#define TRAMP_DEBUG(x...) (void)0
#else
#define TRAMP_DEBUG(x...) EFRM_WARN(x)
#endif

void** efrm_syscall_table = NULL;
EXPORT_SYMBOL(efrm_syscall_table);


/* The kernel contains some neat routines for doing AArch64 code inspection.
 * Some of them are available as inline routines, but some are unfortunately
 * not exported to modules.
 * So we use efrm_find_ksym() to resolve these functions if it is available.
 * Otherwise we copy their implementations here.
 */
#ifdef EFRM_HAVE_NEW_KALLSYMS
static typeof(aarch64_insn_decode_immediate) *ci_aarch64_insn_decode_immediate;
static typeof(aarch64_insn_read) *ci_aarch64_insn_read;
static typeof(aarch64_insn_extract_system_reg) *ci_aarch64_insn_extract_system_reg;
static typeof(aarch64_get_branch_offset) *ci_aarch64_get_branch_offset;
static typeof(aarch64_insn_adrp_get_offset) *ci_aarch64_insn_adrp_get_offset;
#else
#include "ci_arm64_patching.h"
#include "ci_arm64_insn.h"
#endif /* EFRM_HAVE_NEW_KALLSYMS */

#define CI_AARCH64_INSN_READ(_ptr, _insn)            \
  do {                                               \
    if (ci_aarch64_insn_read(_ptr, &(_insn))) {      \
      EFRM_WARN("%s:%d: cannot read insn at %px",    \
                __FUNCTION__, __LINE__, _ptr);       \
      return NULL;                                   \
    }                                                \
  } while (0);

/* Linux does not have any function to check for 'bti' instruction. So we
 * define it by ourselves. */
static inline bool aarch64_insn_is_bti(u32 code)
{
  u32 mask = 0xFFFFFF3F;
  u32 val = 0xD503241F;
  return (code & mask) == val;
}

/* Depending on the kernel version, locating the syscall table may be more
 * or less straigthforward.
 * In the most lucky event, sys_call_table symbol is declared extern, and so
 * it can be fetched directly with efrm_find_ksym().
 * Otherwise we need to proceed through syscall calling sequence. There are
 * some intermediate symbols that may happen to be available so we try to
 * use them first, and if they are not found, resort to assembler code
 * scanning.
 *
 * So the syscall routine looks like this:
 * - the address of exception handler table is in vbar_el1 system register;
 *   this is the value used by `svc` instruction in the user space and so
 *   it is always available irrespective to any kernel symbols being exposed
 * - the exception table is a table of 128-byte blocks. The handler for
 *   user-space generated exceptions is 9th. The content of the block is
 *   some code which includes a jump to real handler. Depending on the
 *   kernel version and configuration, that may be either a first instruction
 *   in the block or at some fixed position forward.
 * - the handler is labelled `el0_sync` and it may be an extern symbol.
 *   Locating it is the task of find_el_sync() function.
 *   The handler itself does some dispatching based on the exception
 *   syndrome register.
 *   So it consist of the kernel entry code which we must skip and then a
 *   read from esr_el1 register which uniquely identifies the start of the
 *   code we're looking for.
 *   Then there will be a cascade of comparisons, and we expect that the
 *   branch we are interested in is the first one. However, we make sure
 *   that this is the case by ensuring that there is indeed the cmp
 *   instruction with a proper immediate argument.
 *   The next instruction is a jump to the actual handler for syscalls.
 * - it is labelled `el0_svc` and it may also be an extern symbol, and
 *   finding it is the task of find_el_svc() function.
 *   Now the first instruction of `el0_svc` should be the load of the
 *   address of the sys_call_table, where we can obtain it in the function
 *   find_syscall_table_via_vbar().
 *
 * The employed scheme should be robust enough to survive small changes in
 * the syscall calling sequence across the kernel, but of course we cannot
 * be sure it will never break, so there are as many safety checks here as possible.
 */

/* Modern kernels way (since 5.5) (tested on 5.15.83 and 5.10.110):
 * - Instead of `el_sync` we look for `el0t_64_sync`. Some new code was added
 *   to the exception handler. See find_el_sync() for more comments.
 * - `el0t_64_sync` jumps to C function el0t_64_sync_handler(), which calls
 *   specific function based on the value of esr_el1 system register. We look
 *   for `el0_svc` here. See find_el_svc_entry() for more comments.
 * - `el0_svc()` calls `do_el0_svc()`, which calls `el0_svc_common()` and passes
 *   pointer to the syscall table as an argument. See find_syscall_table_via_vbar()
 *   for more comments.
 */

static ci_uint8 *
find_el_sync(void)
{
  ci_uint8 *vectors;
  ci_uint32 insn;
  ci_uint8 *el_sync = NULL;

#ifdef EFRM_HAVE_NEW_KALLSYMS
  el_sync = efrm_find_ksym("el0_sync");
#endif
  if (el_sync != NULL)
    return el_sync;

  vectors = (ci_uint8 *)read_sysreg(vbar_el1);
  vectors += 8 * 128;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 105)
  /* Skip code that was added in 5.10.105:
   * 14000003        b       40c <vectors+0x40c>
   */
  vectors += AARCH64_INSN_SIZE;
#endif
  /* Skip code that was added in 4.15:
   * d53bd07e        mrs     x30, tpidrro_el0
   * d51bd07f        msr     tpidrro_el0, xzr
   */
  vectors += 2 * AARCH64_INSN_SIZE;

  vectors += sizeof(ci_uint32);
#if defined(CONFIG_VMAP_STACK)
  vectors += 5 * sizeof(ci_uint32);
#endif
  if (ci_aarch64_insn_read(vectors, &insn)) {
    EFRM_WARN("%s: cannot read vbar_el1", __func__);
    return NULL;
  }
  if (!aarch64_insn_is_b(insn)) {
    EFRM_WARN("%s: el0_sync entry is not a branch", __func__);
    return NULL;
  }
  el_sync = vectors + ci_aarch64_get_branch_offset(insn);

  TRAMP_DEBUG("%s:%d: 'b el_sync' = %px (%x)", __FUNCTION__, __LINE__, vectors,
              insn);
  TRAMP_DEBUG("%s:%d: el_sync = %px", __FUNCTION__, __LINE__, el_sync);

  return el_sync;
}

static inline ci_uint8 *
find_next_bl(ci_uint8 *ptr)
{
  ci_uint32 insn;

  CI_AARCH64_INSN_READ(ptr, insn);

  while (!aarch64_insn_is_bl(insn)) {
    ptr += AARCH64_INSN_SIZE;
    CI_AARCH64_INSN_READ(ptr, insn);
  }

  return ptr;
}

static ci_uint8 *
find_el_svc_entry(void)
{
  ci_uint8 *el_svc = NULL;
  ci_uint8 *el_sync;
  ci_uint32 insn;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
  ci_uint8 *last_bl;
#endif

#ifdef EFRM_HAVE_NEW_KALLSYMS
  el_svc = efrm_find_ksym("el0_svc");
#endif
  if (el_svc != NULL)
    return el_svc;
  el_sync = find_el_sync();
  if (el_sync == NULL)
    return NULL;

  /* syscall entry code was rewritten to C in 5.5. So we need to use another
   * approach for searching el0_svc.  */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)

  /* Find el0t_64_sync_handler() call and jump to it. We assume that el0_sync
   * does not contain any other `bl` instructions before this one. */
  el_sync = find_next_bl(el_sync);
  CI_AARCH64_INSN_READ(el_sync, insn);
  TRAMP_DEBUG("%s:%d: 'bl el0t_64_sync_handler' = %px (%x)", __FUNCTION__,
              __LINE__, el_sync, insn);
  el_sync += ci_aarch64_get_branch_offset(insn);
  TRAMP_DEBUG("%s:%d: el0t_64_sync_handler = %px", __FUNCTION__, __LINE__, el_sync);

  /* el0t_64_sync_handler() contains switch-case:
   *
   * unsigned long esr = read_sysreg(esr_el1);
   * switch (ESR_ELx_EC(esr)) {
   * case ESR_ELx_EC_SVC64:
   *     el0_svc(regs);
   *     break;
   * and so on ...
   *
   * Assembler looks like:
   * d503233f        paciasp
   * a9bf7bfd        stp     x29, x30, [sp, #-16]!
   * 910003fd        mov     x29, sp
   * d5385201        mrs     x1, esr_el1
   * 531a7c22        lsr     w2, w1, #26
   * f100f05f        cmp     x2, #0x3c
   * 540000a9        b.ls    ffffffc008b6d2ec <el0t_64_sync_handler+0x2c>  // b.plast
   * 97fffd2d        bl      ffffffc008b6c790 <el0_inv>
   * a8c17bfd        ldp     x29, x30, [sp], #16
   * d50323bf        autiasp
   * d65f03c0        ret
   * 7100f05f        cmp     w2, #0x3c
   * 54ffff68        b.hi    ffffffc008b6d2dc <el0t_64_sync_handler+0x1c>  // b.pmore
   * 90000123        adrp    x3, ffffffc008b91000 <__entry_tramp_data_start>
   * 91004063        add     x3, x3, #0x10
   * 38624862        ldrb    w2, [x3, w2, uxtw]
   * 10000063        adr     x3, ffffffc008b6d30c <el0t_64_sync_handler+0x4c>
   * 8b228862        add     x2, x3, w2, sxtb #2
   * d61f0040        br      x2
   * 97fffbf9        bl      ffffffc008b6c2f0 <el0_dbg>
   * 17fffff4        b       ffffffc008b6d2e0 <el0t_64_sync_handler+0x20>
   * ...
   * 97ffff0a        bl      ffffffc008b6cf94 <el0_svc>
   * 17ffffdc        b       ffffffc008b6d2e0 <el0t_64_sync_handler+0x20>
   *
   * We need `el0_svc`, which is the last one. Firstly jump to the `br`, and then
   * find the last `bl` instruction.
   */

  /* Skip some code until we reach `br` instruction. */
  while (!aarch64_insn_is_br(insn)) {
    CI_AARCH64_INSN_READ(el_sync, insn);
    el_sync += AARCH64_INSN_SIZE;
  }

  /* Find next 'bl' instruction. There may be a few 'bti' instructions
   * or may be nothing (see listing above).
   * Example for Linux-5.10 where we have them:
   * d61f0040        br      x2
   * d503249f        bti     j
   * d503249f        bti     j
   * d503249f        bti     j
   * d503249f        bti     j
   * 97ffff61        bl      b30 <el0_dbg>
   */
  el_sync = find_next_bl(el_sync);

  /* Find the last bl instruction. It is jump to el0_svc. */
  while (1) {
    CI_AARCH64_INSN_READ(el_sync, insn);
    /* Skip 'bti' instructions, which may be between 'bl's. */
    if (aarch64_insn_is_bti(insn)) {
      el_sync += AARCH64_INSN_SIZE;
      continue;
    }
    if (!aarch64_insn_is_bl(insn))
      break;
    last_bl = el_sync;
    el_sync += 2 * AARCH64_INSN_SIZE;
  }
  CI_AARCH64_INSN_READ(last_bl, insn);
  el_svc = last_bl + ci_aarch64_get_branch_offset(insn);
  TRAMP_DEBUG("%s:%d: 'bl el0_svc' = %px (%x)", __FUNCTION__, __LINE__, last_bl,
              insn);
  TRAMP_DEBUG("%s:%d: el0_svc = %px", __FUNCTION__, __LINE__, el_svc);

#else

  while (1) {
    if (ci_aarch64_insn_read(el_sync, &insn)) {
      EFRM_WARN("cannot read el0_sync code @ %d", __LINE__);
      return NULL;
    }
    if (aarch64_insn_is_mrs(insn) &&
        ci_aarch64_insn_extract_system_reg(insn) == SYS_ESR_EL1) {
      el_sync += 2 * sizeof(ci_uint32);
      if (ci_aarch64_insn_read(el_sync, &insn)) {
        EFRM_WARN("cannot read el0_sync code @ %d", __LINE__);
        return NULL;
      }
      if (!aarch64_insn_is_subs_imm(insn) ||
          ci_aarch64_insn_decode_immediate(AARCH64_INSN_IMM_12, insn) !=
          ESR_ELx_EC_SVC64) {
        EFRM_WARN("%s: expected check for ESR_ELx_EC_SVC64", __func__);
        return NULL;
      }
      el_sync += sizeof(ci_uint32);
      if (ci_aarch64_insn_read(el_sync, &insn)) {
        EFRM_WARN("cannot read el0_sync code @ %d", __LINE__);
        return NULL;
      }
      if (!aarch64_insn_is_bcond(insn) ||
          (insn & 0x0f) != AARCH64_INSN_COND_EQ) {
        EFRM_WARN("%s: branching to el0_svc not found", __func__);
        return NULL;
      }
      el_svc = el_sync + ci_aarch64_get_branch_offset(insn);
      break;
    }
    el_sync += sizeof(ci_uint32);
  }
#endif

  return el_svc;
}

static ci_uint8 *
find_syscall_table_via_vbar(void)
{
  ci_uint8 *el_svc = find_el_svc_entry();
  ci_uint32 insn;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
  ci_uint8 *do_el0_svc = NULL;
  ci_uint8 *sys_call_table = NULL;
#endif

  if (el_svc == NULL)
    return NULL;

  /* syscall entry code was rewritten to C in 5.5. So we need to use another
   * approach for sys_call_table look up.  */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)

  /*
   * Linux-5.15:
   * el0_svc() calls do_el0_svc() after some code. It is the 3d 'bl' instruction:
   * <el0_svc>:
   * d503233f        paciasp
   * a9be7bfd        stp     x29, x30, [sp, #-32]!
   * 910003fd        mov     x29, sp
   * f9000bf3        str     x19, [sp, #16]
   * aa0003f3        mov     x19, x0
   * 97d930ee        bl      ffffffc0081b9360 <trace_hardirqs_off_finish>
   * 97d2ae0d        bl      ffffffc0080187e0 <cortex_a76_erratum_1463225_svc_handler>
   * aa1303e0        mov     x0, x19
   * 97d2ebbc        bl      ffffffc008027ea4 <do_el0_svc>
   */
  el_svc = find_next_bl(el_svc);
  el_svc += AARCH64_INSN_SIZE;

  el_svc = find_next_bl(el_svc);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
  el_svc += AARCH64_INSN_SIZE;
  el_svc = find_next_bl(el_svc);
#endif

  CI_AARCH64_INSN_READ(el_svc, insn);

  /* Jumping to do_el0_svc(). */
  do_el0_svc = el_svc + ci_aarch64_get_branch_offset(insn);
  TRAMP_DEBUG("%s:%d: 'bl do_el0_svc' = %px (%x)", __FUNCTION__, __LINE__,
              el_svc, insn);
  TRAMP_DEBUG("%s:%d: do_el0_svc = %px", __FUNCTION__, __LINE__, do_el0_svc);

  /* Next (and the last) we must find the function call where sys_call_table
   * symbol is passed as an argument:
   * el0_svc_common(regs, regs->regs[8], __NR_syscalls, sys_call_table);
   *
   * Assembler looks like:
   * d0005b42        adrp    x2, ffffffc008b91000 <__entry_tramp_data_start>
   * 911d2042        add     x2, x2, #0x748
   * 97ffffad        bl      ffffffc008027d80 <el0_svc_common.constprop.0>
   *
   * The first two instructions form sys_call_table address.
   */
  do_el0_svc = find_next_bl(do_el0_svc);
  do_el0_svc -= 2 * AARCH64_INSN_SIZE;

  CI_AARCH64_INSN_READ(do_el0_svc, insn);
  if (!aarch64_insn_is_adrp(insn)) {
    EFRM_WARN("%s:%d: expected adrp instruction at %px, found %08x",
              __FUNCTION__, __LINE__, do_el0_svc, insn);
    return NULL;
  }
  sys_call_table = CI_PTR_ALIGN_BACK(do_el0_svc, SZ_4K) +
          ci_aarch64_insn_adrp_get_offset(insn);

  do_el0_svc += AARCH64_INSN_SIZE;
  CI_AARCH64_INSN_READ(do_el0_svc, insn);
  if (!aarch64_insn_is_add_imm(insn)) {
    EFRM_WARN("%s:%d: expected add instruction at %px, found %08x",
              __FUNCTION__, __LINE__, do_el0_svc, insn);
    return NULL;
  }
  sys_call_table += ci_aarch64_insn_decode_immediate(AARCH64_INSN_IMM_12, insn);
  TRAMP_DEBUG("%s: sys_call_table = %px", __FUNCTION__, sys_call_table);
  return sys_call_table;
 #endif

  if (ci_aarch64_insn_read(el_svc, &insn)) {
    EFRM_WARN("cannot read el0_svc start @ %016lx", (unsigned long)el_svc);
    return NULL;
  }
  if (!aarch64_insn_is_adrp(insn)) {
    EFRM_WARN("expected adrp instruction at el0_svc, found %08x", insn);
    return NULL;
  }
  return CI_PTR_ALIGN_BACK(el_svc, SZ_4K) + ci_aarch64_insn_adrp_get_offset(insn);
}

static void *find_syscall_table(void)
{
  void *syscalls = NULL;

#ifdef EFRM_HAVE_NEW_KALLSYMS
  syscalls = efrm_find_ksym("sys_call_table");
#endif
  if (syscalls != NULL)
    return syscalls;

#ifdef EFRM_HAVE_NEW_KALLSYMS
  ci_aarch64_insn_decode_immediate =
                          efrm_find_ksym("aarch64_insn_decode_immediate");
  ci_aarch64_insn_read = efrm_find_ksym("aarch64_insn_read");
  ci_aarch64_insn_extract_system_reg =
                          efrm_find_ksym("aarch64_insn_extract_system_reg");
  ci_aarch64_get_branch_offset =
                          efrm_find_ksym("aarch64_get_branch_offset");
  ci_aarch64_insn_adrp_get_offset =
                          efrm_find_ksym("aarch64_insn_adrp_get_offset");
  if (ci_aarch64_insn_decode_immediate == NULL ||
      ci_aarch64_insn_read == NULL ||
      ci_aarch64_insn_extract_system_reg == NULL ||
      ci_aarch64_get_branch_offset == NULL ||
      ci_aarch64_insn_adrp_get_offset == NULL) {
    EFRM_WARN("%s: some symbols required for AArch64 assembler analysis "
              "are not found", __func__);
    return NULL;
  }
#endif

  return find_syscall_table_via_vbar();
}

int efrm_syscall_ctor(void)
{
  efrm_syscall_table = find_syscall_table();
  if( efrm_syscall_table == NULL )
    return -ENOENT;
  return 0;
}
