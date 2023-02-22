/* SPDX-License-Identifier: GPL-2.0 */

#include "ci_arm64_insn.h"

#ifndef EFRM_HAVE_NEW_KALLSYMS
/* X-SPDX-Source-URL: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git */
/* X-SPDX-Source-Tag: v5.15.83 */
/* X-SPDX-Source-File: arch/arm64/lib/insn.c */
/* X-SPDX-License-Identifier: GPL-2.0-only */
/* X-SPDX-Comment: Functions to inspect aarch64 instructions for the case when
 *                 efrm_find_ksym() is unavailable. The "ci" prefix is added to
 *                 public functions in order not to clash with kernel names. */

static int aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type,
						u32 *maskp, int *shiftp)
{
	u32 mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_26:
		mask = BIT(26) - 1;
		shift = 0;
		break;
	case AARCH64_INSN_IMM_19:
		mask = BIT(19) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_16:
		mask = BIT(16) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_14:
		mask = BIT(14) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_12:
		mask = BIT(12) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_9:
		mask = BIT(9) - 1;
		shift = 12;
		break;
	case AARCH64_INSN_IMM_7:
		mask = BIT(7) - 1;
		shift = 15;
		break;
	case AARCH64_INSN_IMM_6:
	case AARCH64_INSN_IMM_S:
		mask = BIT(6) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_R:
		mask = BIT(6) - 1;
		shift = 16;
		break;
	case AARCH64_INSN_IMM_N:
		mask = 1;
		shift = 22;
		break;
	default:
		return -EINVAL;
	}

	*maskp = mask;
	*shiftp = shift;

	return 0;
}

#define ADR_IMM_HILOSPLIT	2
#define ADR_IMM_SIZE		SZ_2M
#define ADR_IMM_LOMASK		((1 << ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_HIMASK		((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_LOSHIFT		29
#define ADR_IMM_HISHIFT		5

u64 ci_aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
{
	u32 immlo, immhi, mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (insn >> ADR_IMM_LOSHIFT) & ADR_IMM_LOMASK;
		immhi = (insn >> ADR_IMM_HISHIFT) & ADR_IMM_HIMASK;
		insn = (immhi << ADR_IMM_HILOSPLIT) | immlo;
		mask = ADR_IMM_SIZE - 1;
		break;
	default:
		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			pr_err("%s: unknown immediate encoding %d\n", __func__,
			       type);
			return 0;
		}
	}

	return (insn >> shift) & mask;
}

/*
 * Decode the imm field of a branch, and return the byte offset as a
 * signed value (so it can be used when computing a new branch
 * target).
 */
s32 ci_aarch64_get_branch_offset(u32 insn)
{
	s32 imm;

	if (aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn)) {
		imm = ci_aarch64_insn_decode_immediate(AARCH64_INSN_IMM_26, insn);
		return (imm << 6) >> 4;
	}

	if (aarch64_insn_is_cbz(insn) || aarch64_insn_is_cbnz(insn) ||
	    aarch64_insn_is_bcond(insn)) {
		imm = ci_aarch64_insn_decode_immediate(AARCH64_INSN_IMM_19, insn);
		return (imm << 13) >> 11;
	}

	if (aarch64_insn_is_tbz(insn) || aarch64_insn_is_tbnz(insn)) {
		imm = ci_aarch64_insn_decode_immediate(AARCH64_INSN_IMM_14, insn);
		return (imm << 18) >> 16;
	}

	/* Unhandled instruction */
	BUG();
}

/*
 * Extract the Op/CR data from a msr/mrs instruction.
 */
u32 ci_aarch64_insn_extract_system_reg(u32 insn)
{
	return (insn & 0x1FFFE0) >> 5;
}

s32 ci_aarch64_insn_adrp_get_offset(u32 insn)
{
	BUG_ON(!aarch64_insn_is_adrp(insn));
	return ci_aarch64_insn_decode_immediate(AARCH64_INSN_IMM_ADR, insn) << 12;
}
/* X-SPDX-Restore: */
#endif /* ! EFRM_HAVE_NEW_KALLSYMS */
