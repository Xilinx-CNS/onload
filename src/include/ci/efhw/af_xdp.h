/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#ifndef CI_EFHW_AF_XDP_H
#define CI_EFHW_AF_XDP_H

#include <linux/unistd.h>
#include <ci/efrm/syscall.h>

/* For Onload over AF_XDP we need:
 * - CONFIG_XDP_SOCKETS
 * - __NR_bpf
 */
#if defined(CONFIG_XDP_SOCKETS) && defined(__NR_bpf)
#define EFHW_HAS_AF_XDP
#endif

#ifdef EFHW_HAS_AF_XDP

extern struct efhw_func_ops af_xdp_char_functional_units;

#endif

#if !defined(EFHW_HAS_AF_XDP) && !CI_HAVE_SFC
#error HAVE_SFC=0 build mode is unavailable since AF_XDP is not supported
#endif

#endif /* CI_EFHW_AF_XDP_H */
