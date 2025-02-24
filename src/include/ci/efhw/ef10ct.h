/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#ifndef CI_EFHW_EF10CT_H
#define CI_EFHW_EF10CT_H

#include <ci/efhw/efct.h>
#include <ci/driver/ci_ef10ct.h>
#include <ci/tools/sysdep.h>
#include <ci/efhw/efhw_stack_allocator.h>
#include <ci/efhw/mc_driver_pcol.h>
#include <lib/efhw/mcdi_common.h>
#include <linux/mutex.h>

extern struct efhw_func_ops ef10ct_char_functional_units;

#define EF10CT_EVQ_DUMMY_MAX 1024
#define EF10CT_EVQ_NO_TXQ -1
struct efhw_nic_ef10ct_evq {
  struct efhw_nic *nic;
  atomic_t queues_flushing;
  struct delayed_work check_flushes_polled;
  struct delayed_work check_flushes_irq;
  ci_qword_t *base;
  unsigned capacity;
  unsigned next;
  int txq;
  unsigned queue_num;
};

/** enum_nic_ef10ct_rxq_state - Current state of the rxq.
 * @EF10CT_RXQ_STATE_FREE: rxq is neither allocated nor inited.
 *                         Transitions to EF10CT_RXQ_STATE_ALLOCATED.
 * @EF10CT_RXQ_STATE_ALLOCATED: rxq has been allocated via mcdi, but not inited.
 *                              Transitions to EF10CT_RXQ_STATE_INITIALISED.
 * @EF10CT_RXQ_STATE_INITIALISED: rxq has been allocated and inited.
 *                                Transitions to EF10CT_RXQ_STATE_FREEING.
 * @EF10CT_RXQ_STATE_FREEING: rxq in the process of being freed. Don't attach.
 *                            Transitions to EF10CT_RXQ_STATE_FREE.
 *
 * Used to keep track of the current state of the rxq. The first three states
 * FREE, ALLOCATED and INITIALISED all represent the actual state of the queue
 * as it would be understood from firmware/hardware. The FREEING state is
 * introduced as this is the only process that happens asynchronously. Therefore
 * to prevent any bugs that would occur from concurrent users trying to use the
 * queue as if it were initialised, even though it is currently being freed, we
 * state that the queue is no longer in the INITIALISED state after the FINI
 * request has been made.
 */
enum efhw_nic_ef10ct_rxq_state {
  EF10CT_RXQ_STATE_FREE = 0,
  EF10CT_RXQ_STATE_ALLOCATED,
  EF10CT_RXQ_STATE_INITIALISED,
  EF10CT_RXQ_STATE_FREEING,
};

struct efhw_nic_ef10ct_rxq {
  int evq;
  int ref_count;
  struct mutex bind_lock; /* Lock to serialise concurrent binds/unbinds */
  enum efhw_nic_ef10ct_rxq_state state;
  uint64_t *post_buffer_addr;
  struct oo_hugetlb_page *buffer_pages;
  size_t n_buffer_pages;
};

struct ef10ct_shared_kernel_evq {
  int evq_id;
  struct efhw_nic_ef10ct_evq *evq;
  struct efhw_iopages iopages;
  uint32_t irq;
  uint32_t channel;
  char name[IFNAMSIZ + 6];
};

enum ef10ct_queue_handle_type {
  EF10CT_QUEUE_HANDLE_TYPE_TXQ = MC_CMD_QUEUE_HANDLE_QUEUE_TYPE_LL_TXQ,
  EF10CT_QUEUE_HANDLE_TYPE_RXQ = MC_CMD_QUEUE_HANDLE_QUEUE_TYPE_LL_RXQ,
  EF10CT_QUEUE_HANDLE_TYPE_EVQ = MC_CMD_QUEUE_HANDLE_QUEUE_TYPE_LL_EVQ,
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
    struct efhw_stack_allocator rx;
    struct mutex lock;
  } vi_allocator;
  struct efct_filter_state filter_state;
  struct efrm_debugfs_dir debug_dir;
  struct xarray irqs;
  struct mutex irq_lock;
};

static inline u32 ef10ct_get_queue_num(u32 queue_handle)
{
  ci_dword_t data;

  EFHW_MCDI_SET_DWORD(&data, QUEUE_HANDLE_QUEUE_HANDLE, queue_handle);
  return EFHW_MCDI_DWORD_FIELD(&data, QUEUE_HANDLE_QUEUE_NUM);
}

static inline enum ef10ct_queue_handle_type
ef10ct_get_queue_type(u32 queue_handle)
{
  ci_dword_t data;

  EFHW_MCDI_SET_DWORD(&data, QUEUE_HANDLE_QUEUE_HANDLE, queue_handle);
  return EFHW_MCDI_DWORD_FIELD(&data, QUEUE_HANDLE_QUEUE_TYPE);
}

static inline u32
ef10ct_reconstruct_queue_handle(u32 queue_num,
                                enum ef10ct_queue_handle_type type)
{
  ci_dword_t data;

  EFHW_MCDI_POPULATE_DWORD_2(&data, QUEUE_HANDLE_QUEUE_HANDLE,
                             QUEUE_HANDLE_QUEUE_NUM, queue_num,
                             QUEUE_HANDLE_QUEUE_TYPE, type);
  return EFHW_MCDI_DWORD(&data, QUEUE_HANDLE_QUEUE_HANDLE);
}

int ef10ct_alloc_evq(struct efhw_nic *nic);
void ef10ct_free_evq(struct efhw_nic *nic, int evq);

#endif /* CI_EFHW_EF10CT_H */
