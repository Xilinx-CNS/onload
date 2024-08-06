/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: Copyright (c) 2023 Advanced Micro Devices, Inc. */

#ifndef __CI_ARM64_PATCHING_H__
#define __CI_ARM64_PATCHING_H__

#include <linux/types.h>

int ci_aarch64_insn_read(void *addr, u32 *insnp);

#endif /* __CI_ARM64_PATCHING_H__ */
