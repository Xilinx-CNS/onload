/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */

#ifndef LIB_EFHW_EFCT_FILTERS_H
#define LIB_EFHW_EFCT_FILTERS_H

struct efct_filter_insert_in {
  void *drv_opaque;
  const struct ethtool_rx_flow_spec *filter;
};
struct efct_filter_insert_out {
  int rxq;
  uint64_t drv_id;
  u32 filter_handle;
};
struct efct_filter_state;

#define EFCT_HW_FILTER_DRV_ID_DUMMY ((uint64_t)~0)

typedef int (*drv_filter_insert)(const struct efct_filter_insert_in *in,
                                 struct efct_filter_insert_out *out);

extern int
efct_filter_insert(struct efct_filter_state *state, struct efx_filter_spec *spec,
                   struct ethtool_rx_flow_spec *hw_filter,
                   int *rxq, unsigned pd_excl_token, unsigned flags,
                   drv_filter_insert insert_op, void *insert_data,
                   uint64_t filter_flags);
extern bool
efct_filter_remove(struct efct_filter_state *state, int filter_id,
                   uint64_t *drv_id_out, unsigned *flags_out);
extern int
efct_filter_query(struct efct_filter_state *state, int filter_id,
                  struct efhw_filter_info *info);
extern int
efct_multicast_block(struct efct_filter_state *state, bool block);
extern int
efct_unicast_block(struct efct_filter_state *state, bool block);

extern int
efct_filter_state_init(struct efct_filter_state *state, int num_filter,
                       int rx_queues);
extern void
efct_filter_state_free(struct efct_filter_state *state);
extern void
efct_filter_state_reserve_rxq(struct efct_filter_state *state, int rxq);
#endif

