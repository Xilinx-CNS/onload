/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2015-2020 Xilinx, Inc. */
#ifndef __TCP_HELPER_RESOURCE_H__
#define __TCP_HELPER_RESOURCE_H__

struct vi_allocate_info {
  int try_rx_ts;
  int try_tx_ts;
  int retry_without_rx_ts;
  int retry_without_tx_ts;
  int wakeup_cpu_core;

  struct efrm_client *client;
  struct efrm_vi_set *vi_set;
  struct efrm_pd *pd;
  const char *name;
  unsigned ef_vi_flags;
  unsigned efhw_flags;
  unsigned oo_vi_flags;
  unsigned int hwport_flags;
  int evq_capacity;
  int txq_capacity;
  int rxq_capacity;
  int wakeup_channel;
  struct efrm_vi **virs;
  tcp_helper_cluster_t* cluster;
  unsigned vi_io_mmap_bytes;
  unsigned vi_ctpio_mmap_bytes;
  unsigned ctpio_threshold;
  int try_ctpio;
  int retry_without_ctpio;

  int release_pd;
  int log_resource_warnings;
  int intf_i;
};

#endif  /* __TCP_HELPER_RESOURCE_H__ */
