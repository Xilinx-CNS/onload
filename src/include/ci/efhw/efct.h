/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#ifndef CI_EFHW_EFCT_H
#define CI_EFHW_EFCT_H
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/driver/ci_efct.h>
#include <ci/tools/sysdep.h>
#include <ci/efhw/efhw_stack_allocator.h>

/* Avoid dragging the full efhw_types.h header into the ZF unit test build. */
#ifdef __KERNEL__
  #include <ci/efhw/efhw_types.h>
#else
  typedef void efhw_efct_rxq_free_func_t(struct efhw_efct_rxq*);
#endif

/* Avoid dragging the full efhw_types.h header into the ZF unit test build. */
#ifdef __KERNEL__
  #include <ci/efhw/efhw_types.h>
#endif

extern struct efhw_func_ops efct_char_functional_units;

struct efhw_efct_rxq;
struct xlnx_efct_hugepage;
struct xlnx_efct_rxq_params;
struct oo_hugetlb_allocator;
typedef void efhw_efct_rxq_int_wake_func_t(struct efhw_efct_rxq*);

/* Packet sequences are defined as (superbuf_seqno << 16) | pkt_index_in_sb,
 * therefore -1 is an impossible value because we'll never have 65535 packets
 * in a single superbuf */
#define EFCT_INVALID_PKT_SEQNO (~0u)

struct efhw_efct_krxq {
  struct efab_efct_rxq_uk_shm_q *shm;
  bool destroy;
  uint32_t next_sbuf_seq;
  size_t n_hugepages;
  uint32_t current_owned_superbufs;
  uint32_t max_allowed_superbufs;
  CI_BITS_DECLARE(owns_superbuf, CI_EFCT_MAX_SUPERBUFS);
  efhw_efct_rxq_free_func_t *freer;
};

struct efhw_efct_urxq {
  resource_size_t rx_buffer_post_register;
};

struct efhw_efct_rxq {
  struct efhw_efct_rxq *next;
  unsigned qid;
  int qix;
  uint32_t wake_at_seqno;
  unsigned wakeup_instance;
  bool uses_shared_evq;
  unsigned last_req_seqno;
  unsigned last_req_now;
  union {
    struct efhw_efct_krxq krxq;
    struct efhw_efct_urxq urxq;
  };
};

struct efhw_nic_efct_rxq_wakeup_bits {
  struct efhw_efct_rxq *live_apps; /* Owned by NAPI context -- X3 only */
  uint32_t now;
  uint32_t awaiters;
};

/* TODO ON-16705 find somewhere better to put this */
#define CI_EFCT_EVQ_DUMMY_MAX 1024

struct efhw_nic_efct_rxq {
  struct efhw_nic_efct_rxq_wakeup_bits apps;
  struct efhw_efct_rxq *new_apps;  /* Owned by process context */
  struct efhw_efct_rxq *destroy_apps; /* Owned by NAPI context */
  uint32_t superbuf_refcount[CI_EFCT_MAX_SUPERBUFS];
  /* Tracks buffers passed to us from the driver in order they are going
   * to be filled by HW. We need to do this to:
   *  * progressively refill client app superbuf queues,
   *    as x3net can refill RX ring with more superbufs than an app can hold
   *    (or if queues are equal there is a race)
   *  * resume a stopped app (subset of the above really),
   *  * start new app (without rollover)
   */
  struct {
    struct efab_efct_rxq_uk_shm_rxq_entry q[CI_EFCT_MAX_SUPERBUFS];
    uint32_t added;
    /* Points one past the last buffer the x3 driver has finished with. */
    uint32_t removed;
    /* Points one past the last buffer all apps have finished with. */
    uint32_t oldest_app_seq;
  } sbufs;
  uint32_t apps_max_sbufs;
  struct work_struct destruct_wq;
  uint64_t time_sync;
  uint16_t total_sbufs;
};

#define EFCT_EVQ_NO_TXQ -1
struct efhw_nic_efct_evq {
  struct efhw_nic *nic;
  atomic_t queues_flushing;
  struct delayed_work check_flushes;
  void *base;
  unsigned capacity;
  int txq;
};

struct efct_filter_state;
struct efhw_nic_efct {
  uint32_t rxq_n;
  uint32_t evq_n;
  struct efhw_nic_efct_rxq *rxq;
  struct efhw_nic_efct_evq *evq;
  struct xlnx_efct_device *edev;
  struct xlnx_efct_client *client;
  struct efhw_nic *nic;
  struct {
    struct efhw_stack_allocator tx;
    struct efhw_stack_allocator rx;
#ifdef __KERNEL__
    struct mutex lock;
#endif
  } vi_allocator;
  /* ZF emu includes this file from UL */
#ifdef __KERNEL__
  struct efct_filter_state *filter_state;
  struct efrm_debugfs_dir debug_dir;
#endif
  struct {
    struct efhw_stack_allocator alloc;
#ifdef __KERNEL__
    struct mutex lock;
#endif
  } irq_allocator;
};

#if CI_HAVE_EFCT_AUX
int efct_get_hugepages(struct efhw_nic *nic, int hwqid,
                       struct xlnx_efct_hugepage *pages, size_t n_pages);
bool efct_packet_matches_filter(struct efct_filter_state *state,
                                struct net_device *net_dev, int rxq,
                                const unsigned char* pkt, size_t pkt_len);
#endif

static inline void efct_app_list_push(struct efhw_efct_rxq **head,
                                      struct efhw_efct_rxq *app)
{
  struct efhw_efct_rxq *next;
  do {
    app->next = next = *head;
  } while( ci_cas_uintptr_fail(head, (uintptr_t) next, (uintptr_t)app) );
}

#endif /* CI_EFHW_EFCT_H */
