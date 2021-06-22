/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#ifndef CI_EFHW_EFCT_H
#define CI_EFHW_EFCT_H

extern struct efhw_func_ops efct_char_functional_units;

struct efhw_efct_rxq {
  struct list_head rxq_list;
  struct efab_efct_rxq_uk_shm *shm;
  unsigned qid;
  size_t n_hugepages;
};

/* TODO EFCT find somewhere better to put this */
#define CI_EFCT_MAX_RXQS  8

struct efhw_nic_efct_rxq {
  uint32_t superbuf_seqno;
};

struct efhw_nic_efct {
  struct efhw_nic_efct_rxq rxq[CI_EFCT_MAX_RXQS];
};

int efct_nic_rxq_bind(struct efhw_nic *nic, int qid,
                      const struct cpumask *mask, bool timestamp_req,
                      size_t n_hugepages, struct efhw_efct_rxq *rxq);
void efct_nic_rxq_free(struct efhw_nic *nic, struct efhw_efct_rxq *rxq);

#endif /* CI_EFHW_EFCT_H */
