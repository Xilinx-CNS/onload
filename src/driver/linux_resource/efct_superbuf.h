/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */

#ifndef CI_EFHW_EFCT_SUPERBUF_H
#define CI_EFHW_EFCT_SUPERBUF_H

#include <ci/efhw/efct.h>

void efct_destruct_apps_work(struct work_struct* work);

int
__efct_nic_rxq_bind(struct efct_client_device* edev,
                    struct efct_client* cli,
                    struct efct_client_rxq_params *rxq_params,
                    struct efhw_nic_efct *efct,
                    int n_hugepages,
                    struct efab_efct_rxq_uk_shm_q *shm,
                    unsigned wakeup_instance,
                    struct efhw_efct_rxq *rxq);

void
__efct_nic_rxq_free(struct efct_client_device* edev,
                    struct efct_client* cli,
                    struct efhw_efct_rxq *rxq,
                    efhw_efct_rxq_free_func_t *freer);

int efct_poll(void *driver_data, int qid, int budget);
int efct_buffer_end(void *driver_data, int qid, int sbid, bool force);
int efct_buffer_start(void *driver_data, int qid, unsigned sbseq,
                      int sbid, bool sentinel);

#endif
