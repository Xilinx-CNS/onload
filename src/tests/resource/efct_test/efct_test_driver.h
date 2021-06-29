/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef EFCT_TEST_DRIVER_H
#define EFCT_TEST_DRIVER_H

#include <ci/driver/ci_aux.h>
#include <ci/driver/ci_efct.h>

extern int efct_test_add_netdev(struct net_device* dev);
extern int efct_test_remove_netdev(struct net_device* dev);
extern int efct_test_netdev_set_rxq_ms_per_pkt(struct net_device* dev, int rxq,
                                               int ms_per_pkt);

#endif /* EFCT_TEST_DRIVER_H */
