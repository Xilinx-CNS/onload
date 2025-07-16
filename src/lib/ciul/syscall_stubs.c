/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */
#include <sys/socket.h>

/* libciul can exist as a standalone library that uses stdlib, or it can
 * be part of libcitransport, which intercepts stdlib calls. This creates
 * ambiguity for LTO at build-time in cases where a call to stdlib can be
 * partially inlined into its caller. The compile-time of the static
 * libciul assumes the use of stdlib. However, the link-time of the shared
 * libcitransport overrides stdlib calls with calls to Onload to intercept
 * them later in runtime. The ambiguity results in the link-time failure.
 *
 * To resolve the above ambiguity, we replace the affected stdlib calls
 * with their ci_sys_ equivalents, which will point to the stdlib functions
 * in runtime (see citp_syscall_init). This makes the LTO build-time
 * optimisations unavailable. However, ci_sys_ functions pointers are not
 * available in libciul. In this case, we create a weak alias to the stdlib
 * functions.
 *
 * As a result, both libciul and libcitransport should end up making the
 * direct stdlib call when using the functions below.
 */

ssize_t (*ci_sys_recv)(int s, void*, size_t, int) __attribute__((weak)) = recv;
