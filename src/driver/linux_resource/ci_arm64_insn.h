/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CI_ARM64_INSN_H__
#define __CI_ARM64_INSN_H__

#include <ci/efrm/sysdep_linux.h>

u64 ci_aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn);
s32 ci_aarch64_get_branch_offset(u32 insn);
u32 ci_aarch64_insn_extract_system_reg(u32 insn);
s32 ci_aarch64_insn_adrp_get_offset(u32 insn);

#endif /* __CI_ARM64_INSN_H__ */
