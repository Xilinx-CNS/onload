/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#ifndef CI_EFHW_EF10CT_H
#define CI_EFHW_EF10CT_H

#include <ci/efhw/efct.h>
#include <ci/driver/ci_ef10ct.h>
#include <ci/tools/sysdep.h>
#include <ci/efhw/stack_vi_allocator.h>
#include <linux/mutex.h>

extern struct efhw_func_ops ef10ct_char_functional_units;

#define EF10CT_EVQ_DUMMY_MAX 1024
#define EF10CT_EVQ_NO_TXQ -1
struct efhw_nic_ef10ct_evq {
  struct efhw_nic *nic;
  atomic_t queues_flushing;
  struct delayed_work check_flushes;
  void *base;
  unsigned capacity;
  unsigned next;
  int txq;
};

struct efhw_nic_ef10ct_rxq {
  int evq;
  int ref_count;
  uint64_t *post_buffer_addr;
};

struct ef10ct_shared_kernel_evq {
  int evq_id;
  struct efhw_nic_ef10ct_evq *evq;
  struct page *page;
  /* Some kind of interrupt stuff? */
};

struct efhw_nic_ef10ct {
  uint32_t evq_n;
  struct efhw_nic_ef10ct_evq *evq;
  uint32_t shared_n;
  struct ef10ct_shared_kernel_evq *shared;
  uint32_t rxq_n;
  struct efhw_nic_ef10ct_rxq *rxq;
  struct efx_auxdev *edev;
  struct efx_auxiliary_client *client;
  struct efhw_nic *nic;
  struct {
    struct efhw_stack_vi_allocator tx;
    struct efhw_stack_vi_allocator rx;
    struct mutex lock;
  } vi_allocator;
  struct efct_filter_state filter_state;
  struct dentry* debug_dir;
};

int ef10ct_alloc_evq(struct efhw_nic *nic);
void ef10ct_free_evq(struct efhw_nic *nic, int evq);

#endif /* CI_EFHW_EF10CT_H */
