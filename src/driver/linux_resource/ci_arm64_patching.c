/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: Copyright (c) 2023 Advanced Micro Devices, Inc. */

#include "ci_arm64_patching.h"
#include <ci/efrm/sysdep_linux.h>

#ifndef EFRM_HAVE_NEW_KALLSYMS
/* SPDX-SnippetBegin */
/* SPDX-SnippetCopyrightText: Copyright (C) 2013 Huawei Ltd. */
/* SPDX-SnippetCopyrightText: Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com> */
/* SPDX-License-Identifier: GPL-2.0-only */
/* X-SPDX-Source-URL: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git */
/* X-SPDX-Source-Tag: v5.15.83 */
/* X-SPDX-Source-File: arch/arm64/kernel/patching.c */
/* SPDX-SnippetComment: aarch64_insn_read() is used to read aarch64 instructions.
 *                      We copy it here, for the case when efrm_find_ksym() is
 *                      unavailable, since it is not exported for modules. The "ci"
 *                      prefix is added in order not to clash with the kernel. */

/*
 * In ARMv8-A, A64 instructions have a fixed length of 32 bits and are always
 * little-endian.
 */
int ci_aarch64_insn_read(void *addr, u32 *insnp)
{
	int ret;
	__le32 val;

	ret = copy_from_kernel_nofault(&val, addr, AARCH64_INSN_SIZE);
	if (!ret)
		*insnp = le32_to_cpu(val);

	return ret;
}
/* SPDX-SnippetEnd */
#endif /* ! EFRM_HAVE_NEW_KALLSYMS */
