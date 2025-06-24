/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
#ifndef INCLUDED_ETHTOOL_FLOW_H_
#define INCLUDED_ETHTOOL_FLOW_H_

#include <ci/tools/bitfield.h>

struct efx_filter_spec;
struct ethtool_rx_flow_spec;

/* Converts src to dst. Note that the capabilities of this function may be
 * enhanced arbitrarily in the future, so callers must perform their own
 * validation that they're not getting a flow with more features than they
 * support. Zeros and does not populate the ring_cookie field: the caller
 * needs to do that. */
int efx_spec_to_ethtool_flow(const struct efx_filter_spec *src,
                             struct ethtool_rx_flow_spec *dst);

/** Converts an ethtool filter spec into an mcdi request. Does no additional
 * checking or validation that the filter would be supported by the nic. */
void ethtool_flow_to_mcdi_op(ci_dword_t *buf, int rxq, int op,
                             const struct ethtool_rx_flow_spec *filter);
#endif
