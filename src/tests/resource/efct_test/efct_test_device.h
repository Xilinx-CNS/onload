/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef EFCT_TEST_DEVICE_H
#define EFCT_TEST_DEVICE_H

#include <ci/driver/ci_efct.h>

struct efct_test_evq {
  bool inited;
  unsigned txqs;
  size_t entries;
  uint64_t *q_base;
  unsigned ptr;
  unsigned mask;
};

struct efct_test_txq {
  int evq;
  uint8_t* ctpio;
  unsigned ptr;
  unsigned pkt_ctr;
  atomic_t timer_running;
  struct delayed_work timer;
  struct efct_test_device *tdev;
};

#define EFCT_TEST_EVQS_N 12
#define EFCT_TEST_TXQS_N 12
#define EFCT_TEST_RXQS_N  8
#define EFCT_TEST_MAX_SUPERBUFS  512

struct net_device;
struct xlnx_efct_client;
struct efct_test_rxq {
  int ix;
  struct xlnx_efct_hugepage hugepages[EFCT_TEST_MAX_SUPERBUFS/2];
  DECLARE_BITMAP(freelist, EFCT_TEST_MAX_SUPERBUFS);
  DECLARE_BITMAP(curr_sentinel, EFCT_TEST_MAX_SUPERBUFS);
  size_t current_n_hugepages;
  size_t target_n_hugepages;
  struct hrtimer rx_tick;
  int ms_per_pkt;
  int current_sbid;
  uint32_t next_pkt;
  unsigned sbseq;
};

struct efct_test_device {
  struct xlnx_efct_device dev;
  struct net_device* net_dev;
  struct xlnx_efct_client* client;
  struct efct_test_evq evqs[EFCT_TEST_EVQS_N];
  struct efct_test_txq txqs[EFCT_TEST_TXQS_N];
  struct efct_test_rxq rxqs[EFCT_TEST_RXQS_N];
};

extern struct efct_test_device* efct_test_add_test_dev(struct device* parent, struct net_device* net_dev);
extern void efct_test_remove_test_dev(struct efct_test_device* tdev);
extern int efct_test_set_rxq_ms_per_pkt(struct efct_test_device* tdev, int rxq,
                                        int ms_per_pkt);
extern enum hrtimer_restart efct_rx_tick(struct hrtimer *hr);

#endif /* EFCT_TEST_DEVICE_H */
