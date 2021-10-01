/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
#ifndef CI_EFAB_AF_XDP_TYPES_H
#define CI_EFAB_AF_XDP_TYPES_H

#include <ci/compat.h>
#include <linux/if_xdp.h>
/* AF_XDP doesn't have any hardware definitions as such, but
 * we use data structures which are shared between kernel and
 * userland. We define these here. */


struct efab_af_xdp_offsets
{
  int64_t mmap_bytes;
  struct xdp_mmap_offsets rings;
};

#endif

