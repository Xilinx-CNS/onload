/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef CI_EFHW_AF_XDP_TYPES_H
#define CI_EFHW_AF_XDP_TYPES_H

struct efhw_af_xdp_offsets_ring
{
  int64_t producer;
  int64_t consumer;
  int64_t desc;
};

struct efhw_af_xdp_offsets_rings
{
  struct efhw_af_xdp_offsets_ring rx; 
  struct efhw_af_xdp_offsets_ring tx; 
  struct efhw_af_xdp_offsets_ring fr; 
  struct efhw_af_xdp_offsets_ring cr;
};

struct efhw_af_xdp_offsets
{
  int64_t mmap_bytes;
  struct efhw_af_xdp_offsets_rings rings;
};

#endif

