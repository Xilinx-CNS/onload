/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#include <ci/compat.h>
#include <ci/efrm/sysdep_linux.h>
#include <ci/efrm/debug_linux.h>
#include <ci/efrm/syscall.h>

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
  vectors += sizeof(ci_uint32);
#if defined(CONFIG_VMAP_STACK)
  vectors += 5 * sizeof(ci_uint32);
#endif
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

  return el_sync;
}

static ci_uint8 *
find_el_svc_entry(void)
{
  ci_uint8 *el_svc = NULL;
  ci_uint8 *el_sync;
  ci_uint32 insn;

#ifdef EFRM_HAVE_NEW_KALLSYMS
  el_svc = efrm_find_ksym("el0_svc");
#endif
  if (el_svc != NULL)
    return el_svc;
  el_sync = find_el_sync();
  if (el_sync == NULL)
    return NULL;

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
  return el_svc;
}

static ci_uint8 *
find_syscall_table_via_vbar(void)
{
  ci_uint8 *el_svc = find_el_svc_entry();
  ci_uint32 insn;

  if (el_svc == NULL)
    return NULL;

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
