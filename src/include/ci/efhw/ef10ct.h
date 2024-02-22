/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#ifndef CI_EFHW_EF10CT_H
#define CI_EFHW_EF10CT_H

#include <ci/driver/ci_ef10ct.h>
#include <ci/tools/sysdep.h>
#include <ci/efhw/stack_vi_allocator.h>

extern struct efhw_func_ops ef10ct_char_functional_units;

#define EF10CT_EVQ_DUMMY_MAX 1024
#define EF10CT_EVQ_NO_TXQ -1
struct efhw_nic_ef10ct_evq {
  struct efhw_nic *nic;
  atomic_t queues_flushing;
  struct delayed_work check_flushes;
  void *base;
  unsigned capacity;
  int txq;
};

struct efhw_nic_ef10ct {
  uint32_t evq_n;
  struct efhw_nic_ef10ct_evq *evq;
  struct efx_auxiliary_device *edev;
  struct efx_auxiliary_client *client;
  struct efhw_nic *nic;
  struct {
    struct efhw_stack_vi_allocator tx;
    struct efhw_stack_vi_allocator rx;
  } vi_allocator;
};

#endif /* CI_EFHW_EF10CT_H */
