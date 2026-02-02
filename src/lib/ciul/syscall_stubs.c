/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2026 Advanced Micro Devices, Inc. */
#include "syscall_stubs.h"

#define CI_SYS_DECLARE(fn) typeof(fn)* ci_sys_ ## fn __attribute__((weak)) = fn;
CI_SYS_DECLARE_ALL

