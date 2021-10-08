/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */

#ifndef CI_EFHW_EFCT_SUPERBUF_H
#define CI_EFHW_EFCT_SUPERBUF_H

#include <ci/efhw/efct.h>

void efct_destruct_apps_work(struct work_struct* work);

int efct_poll(void *driver_data, int qid, int budget);
int efct_buffer_end(void *driver_data, int qid, int sbid, bool force);
int efct_buffer_start(void *driver_data, int qid, unsigned sbseq,
                      int sbid, bool sentinel);

#endif
