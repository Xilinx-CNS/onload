/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef EFCT_TEST_TX_H
#define EFCT_TEST_TX_H

#include <linux/workqueue.h>

extern void efct_test_tx_timer(struct work_struct *work);
extern void evq_push_tx_flush_complete(struct efct_test_evq *evq, int txq);

ci_qword_t* evq_next_desc(struct efct_test_evq *evq);
unsigned evq_next_phase(struct efct_test_evq *evq);

#endif /* EFCT_TEST_TX_H */
