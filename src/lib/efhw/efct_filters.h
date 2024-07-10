/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */

#ifndef LIB_EFHW_EFCT_FILTERS_H
#define LIB_EFHW_EFCT_FILTERS_H

extern int
efct_filter_insert(struct efhw_nic *nic, struct efx_filter_spec *spec,
                   int *rxq, unsigned pd_excl_token, const struct cpumask *mask,
                   unsigned flags);
extern void
efct_filter_remove(struct efhw_nic *nic, int filter_id);
extern int
efct_filter_query(struct efhw_nic *nic, int filter_id,
                  struct efhw_filter_info *info);
extern int
efct_multicast_block(struct efhw_nic *nic, bool block);
extern int
efct_unicast_block(struct efhw_nic *nic, bool block);

#endif

