/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef EFCT_TEST_DEVICE_H
#define EFCT_TEST_DEVICE_H

#include <ci/driver/ci_ef10ct_test.h>

struct efct_test_device;
struct efx_auxiliary_client {
  struct efct_test_device *tdev;
  efx_event_handler func;
  void* drv_priv;
  u32 client_id;
  efx_event_handler event_handler;
  unsigned int events_requested;
  struct net_device *net_dev;
};

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
struct efx_auxiliary_client;

struct efct_test_device {
  struct efx_auxiliary_device dev;
  struct net_device* net_dev;
  struct efx_auxiliary_client* client;
  struct efct_test_evq evqs[EFCT_TEST_EVQS_N];
  struct efct_test_txq txqs[EFCT_TEST_TXQS_N];
  uint8_t *evq_window;
};

extern struct efct_test_device* efct_test_add_test_dev(struct device* parent, struct net_device* net_dev);
extern void efct_test_remove_test_dev(struct efct_test_device* tdev);

#endif /* EFCT_TEST_DEVICE_H */
