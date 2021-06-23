/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#ifndef CI_EFHW_EFCT_H
#define CI_EFHW_EFCT_H
#include <etherfabric/internal/efct_uk_api.h>

extern struct efhw_func_ops efct_char_functional_units;

struct efhw_efct_rxq {
  struct efhw_efct_rxq *next;
  struct efab_efct_rxq_uk_shm *shm;
  unsigned qid;
  bool destroy;
  size_t n_hugepages;
  uint32_t current_owned_superbufs;
  uint32_t max_allowed_superbufs;
  DECLARE_BITMAP(owns_superbuf, CI_EFCT_MAX_SUPERBUFS);
};

/* TODO EFCT find somewhere better to put this */
#define CI_EFCT_MAX_RXQS  8

struct efhw_nic_efct_rxq {
  struct efhw_efct_rxq *new_apps;  /* Owned by process context */
  struct efhw_efct_rxq *live_apps; /* Owned by NAPI context */
  /* Global superbuf sequence number, used for filter management (since
   * per-app sequence numbers aren't reliable because they don't increment
   * on nodescdrop) */
  uint32_t superbuf_seqno;
};

struct efhw_nic_efct {
  struct efhw_nic_efct_rxq rxq[CI_EFCT_MAX_RXQS];
  struct xlnx_efct_device *edev;
  struct xlnx_efct_client *client;
};

int efct_nic_rxq_bind(struct efhw_nic *nic, int qid,
                      const struct cpumask *mask, bool timestamp_req,
                      size_t n_hugepages, struct efhw_efct_rxq *rxq);
void efct_nic_rxq_free(struct efhw_nic *nic, struct efhw_efct_rxq *rxq);

#endif /* CI_EFHW_EFCT_H */
