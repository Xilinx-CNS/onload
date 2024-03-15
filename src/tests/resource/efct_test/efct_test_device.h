/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef EFCT_TEST_DEVICE_H
#define EFCT_TEST_DEVICE_H

#include <ci/tools.h>
#include <ci/tools/bitfield.h>
#include <ci/driver/ci_ef10ct_test.h>
#include <ci/driver/efab/hardware/efct.h>

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
  unsigned rxqs;
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

#define EFCT_TEST_MAX_SUPERBUFS   512
#define EFCT_TEST_PKT_BYTES       2048
#define EFCT_TEST_PKTS_PER_SUPERBUF   \
          (EFCT_RX_SUPERBUF_BYTES / EFCT_TEST_PKT_BYTES)

struct efct_test_suberbuf {
  /* Page address of the superbuf */
  void *page;
  /* Sentinel value to be included in packet metadata */
  bool sentinel;
  /* Force discard of other buffers? */
  bool rollover;
};

/* The currently "active" superbuffers are the half-open interval
 * [curr_bid, next_bid) (% EFCT_TEST_MAX_SUPERBUFS) */
struct efct_test_rxq {
  /* Associated event queue */
  int evq;
  /* Location of the "register" which uses post buffer locations */
  ci_qword_t *post_register;
  /* Are rx completion events suppressed for this queue? */
  bool events_suppressed;
  /* Periodic timer to check for writes to post_register */
  struct delayed_work timer;
  /* Is the timer currently running? */
  atomic_t timer_running;
  /* Array of buffers -- Acts like a fifo */
  struct efct_test_suberbuf buffers[EFCT_TEST_MAX_SUPERBUFS];
  /* id of next buffer to be posted to the nic */
  unsigned next_bid;
  /* Current buffer that packets will be written to */
  unsigned curr_bid;
  /* index of the next packet in the current superbuf */
  unsigned pkt;
  /* Timer for packet injection */
  struct hrtimer rx_tick;
  /* Time period between injecting packets */
  int ms_per_pkt;
  /* Total number of packets to be sent. Updated by num_pkts configfs param */
  int num_pkts;
  /* Current number of packets sent. Resets when num_pkts is updated. */
  int curr_pkts;
  /* Pointer to test device */
  struct efct_test_device *tdev;
};

#define EFCT_TEST_EVQS_N 12
#define EFCT_TEST_TXQS_N 12
#define EFCT_TEST_RXQS_N  8

struct net_device;
struct efx_auxiliary_client;

struct efct_test_device {
  struct efx_auxiliary_device dev;
  struct net_device* net_dev;
  struct efx_auxiliary_client* client;
  struct efct_test_evq evqs[EFCT_TEST_EVQS_N];
  struct efct_test_txq txqs[EFCT_TEST_TXQS_N];
  struct efct_test_rxq rxqs[EFCT_TEST_RXQS_N];
  uint8_t *evq_window;
};

extern struct efct_test_device* efct_test_add_test_dev(struct device* parent, struct net_device* net_dev);
extern void efct_test_remove_test_dev(struct efct_test_device* tdev);
extern int efct_test_set_rxq_ms_per_pkt(struct efct_test_device* tdev, int rxq,
                                        int ms_per_pkt);
extern int efct_test_set_rxq_num_pkts(struct efct_test_device* tdev, int rxq,
                                        int num_pkts);

#endif /* EFCT_TEST_DEVICE_H */
