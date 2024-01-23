/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#ifndef EFCT_TEST_RX_H
#define EFCT_TEST_RX_H

#include <linux/workqueue.h>

#include <ci/driver/efab/hardware/ef10ct.h>

extern void efct_test_rx_timer(struct work_struct *work);
extern enum hrtimer_restart efct_rx_tick(struct hrtimer *hr);

extern void evq_push_rx_flush_complete(struct efct_test_evq *evq, int rxq);

#endif /* EFCT_TEST_RX_H */
