/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include <unistd.h>
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

#define CI_SYS_DECLARE_ALL \
  CI_SYS_DECLARE(accept) \
  CI_SYS_DECLARE(bind) \
  CI_SYS_DECLARE(close) \
  CI_SYS_DECLARE(connect) \
  CI_SYS_DECLARE(listen) \
  CI_SYS_DECLARE(recv) \
  CI_SYS_DECLARE(recvmsg) \
  CI_SYS_DECLARE(send) \
  CI_SYS_DECLARE(socket) \

#define CI_SYS_DECLARE(fn) extern typeof(fn)* ci_sys_ ## fn;
CI_SYS_DECLARE_ALL
#undef CI_SYS_DECLARE

