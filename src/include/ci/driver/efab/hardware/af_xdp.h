/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
#ifndef CI_EFAB_AF_XDP_TYPES_H
#define CI_EFAB_AF_XDP_TYPES_H

#include <ci/compat.h>
/* AF_XDP doesn't have any hardware definitions as such, but
 * we use data structures which are shared between kernel and
 * userland. We define these here. */

#define EFAB_AF_XDP_DESC_BYTES 16

struct efab_af_xdp_offsets_ring
{
  int64_t producer;
  int64_t consumer;
  int64_t desc;
};

struct efab_af_xdp_offsets_rings
{
  struct efab_af_xdp_offsets_ring rx;
  struct efab_af_xdp_offsets_ring tx;
  struct efab_af_xdp_offsets_ring fr;
  struct efab_af_xdp_offsets_ring cr;
};

struct efab_af_xdp_offsets
{
  int64_t mmap_bytes;
  struct efab_af_xdp_offsets_rings rings;
};

#endif

