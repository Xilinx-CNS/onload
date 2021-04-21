/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef EFCT_TEST_DEVICE_H
#define EFCT_TEST_DEVICE_H

#include "sfc_efct.h"

struct efct_test_device {
  struct sfc_efct_device dev;
};

extern struct efct_test_device* efct_test_add_test_dev(struct device* parent);
extern void efct_test_remove_test_dev(struct efct_test_device* tdev);

#endif /* EFCT_TEST_DEVICE_H */
