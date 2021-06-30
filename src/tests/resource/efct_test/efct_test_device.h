/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef EFCT_TEST_DEVICE_H
#define EFCT_TEST_DEVICE_H

#include <ci/driver/ci_efct.h>

struct efct_test_evq {
  bool inited;
  unsigned txqs;
};

struct efct_test_txq {
  int evq;
  void* ctpio;
};

#define EFCT_TEST_EVQS_N 12
#define EFCT_TEST_TXQS_N 12

struct net_device;
struct xlnx_efct_client;
struct efct_test_device {
  struct xlnx_efct_device dev;
  struct net_device* net_dev;
  struct xlnx_efct_client* client;
  u64 dma_mask;
  struct efct_test_evq evqs[EFCT_TEST_EVQS_N];
  struct efct_test_txq txqs[EFCT_TEST_TXQS_N];
};

extern struct efct_test_device* efct_test_add_test_dev(struct device* parent, struct net_device* net_dev);
extern void efct_test_remove_test_dev(struct efct_test_device* tdev);

#endif /* EFCT_TEST_DEVICE_H */
