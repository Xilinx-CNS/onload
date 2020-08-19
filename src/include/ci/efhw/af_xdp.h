/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#ifndef CI_EFHW_AF_XDP_H
#define CI_EFHW_AF_XDP_H

#ifdef CONFIG_XDP_SOCKETS
#define EFHW_HAS_AF_XDP
#endif

#ifdef EFHW_HAS_AF_XDP

extern struct efhw_func_ops af_xdp_char_functional_units;

#endif

#endif /* CI_EFHW_AF_XDP_H */
