/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef EFCT_TEST_DEVICE_H
#define EFCT_TEST_DEVICE_H

#include "auxiliary_bus.h"
#include "sfc_efct.h"

struct net_device;
struct sfc_efct_client;
struct efct_test_device {
  struct sfc_efct_device dev;
  struct net_device* net_dev;
  struct sfc_efct_client* client;
};

extern struct efct_test_device* efct_test_add_test_dev(struct device* parent, struct net_device* net_dev);
extern void efct_test_remove_test_dev(struct efct_test_device* tdev);

#endif /* EFCT_TEST_DEVICE_H */
