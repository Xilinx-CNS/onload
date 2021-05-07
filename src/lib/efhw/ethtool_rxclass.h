/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2019 Xilinx, Inc. */

struct net_device;
struct ethtool_rx_flow_spec;
struct cmd_context {
  struct net_device* netdev;
};
int rmgr_set_location(struct cmd_context* ctx,
                      struct ethtool_rx_flow_spec* fsp);
