/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* EFCT buffer management using X3-style kernel-allocated buffers */

#ifndef __KERNEL__
#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/mman.h>
#include "driver_access.h"
#include <ci/efch/op_types.h>
#include <linux/memfd.h>
#endif
#include "ef_vi_internal.h"
#include "logging.h"
#include <etherfabric/vi.h>
#include <etherfabric/efct_vi.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/efhw/common.h>
#include <ci/tools/sysdep.h>

#ifndef __KERNEL__
struct efct_kbufs_rxq
{
  unsigned resource_id;
};
#endif

struct efct_kbufs
{
  ef_vi_efct_rxq_ops ops;
  struct efab_efct_rxq_uk_shm_base* shm;
#ifndef __KERNEL__
  struct efct_kbufs_rxq q[EF_VI_MAX_EFCT_RXQS];
#endif
};

static struct efct_kbufs* get_kbufs(ef_vi* vi)
{
  return CI_CONTAINER(struct efct_kbufs, ops, vi->efct_rxqs.ops);
}

static const struct efct_kbufs* const_kbufs(const ef_vi* vi)
{
  return CI_CONTAINER(struct efct_kbufs, ops, vi->efct_rxqs.ops);
}

#ifndef __KERNEL__
static int efct_kbufs_refresh(ef_vi* vi, int qid)
{
  ef_vi_efct_rxq* rxq = &vi->efct_rxqs.q[qid];
  struct efct_kbufs_rxq* kbq = &get_kbufs(vi)->q[qid];

  ci_resource_op_t op;
  op.op = CI_RSOP_RXQ_REFRESH;
  op.id = efch_make_resource_id(kbq->resource_id);
  op.u.rxq_refresh.superbufs = (uintptr_t)rxq->superbuf;
  op.u.rxq_refresh.current_mappings = (uintptr_t)rxq->mappings;
  op.u.rxq_refresh.max_superbufs = CI_EFCT_MAX_SUPERBUFS;
  return ci_resource_op(vi->dh, &op);
}
#endif

static int efct_kbufs_next(ef_vi* vi, int qid, bool* sentinel, unsigned* sbseq)
{
  struct efab_efct_rxq_uk_shm_q* shm = &get_kbufs(vi)->shm->q[qid];
  struct efab_efct_rxq_uk_shm_rxq_entry* entry;
  uint32_t added, removed;
  int sbid;

  added = OO_ACCESS_ONCE(shm->rxq.added);
  removed = shm->rxq.removed;
  if( added == removed ) {
    ++shm->stats.no_bufs;
    return -EAGAIN;
  }
  entry = &shm->rxq.q[removed & (CI_ARRAY_SIZE(shm->rxq.q) - 1)];
  ci_rmb();
  *sbseq = OO_ACCESS_ONCE(entry->sbseq);
  *sentinel = OO_ACCESS_ONCE(entry->sentinel);
  sbid = OO_ACCESS_ONCE(entry->sbid);
  EF_VI_ASSERT(sbid < CI_EFCT_MAX_SUPERBUFS);
  OO_ACCESS_ONCE(shm->rxq.removed) = removed + 1;
  return sbid;
}

static void efct_kbufs_free(ef_vi* vi, int qid, int sbid)
{
  struct efab_efct_rxq_uk_shm_q* shm = &get_kbufs(vi)->shm->q[qid];
  ef_vi_efct_rxq_state* state = &vi->ep_state->rxq.efct_state[qid];
  uint32_t added, removed, freeq_size;

  added = shm->freeq.added;
  removed = OO_ACCESS_ONCE(shm->freeq.removed);
  EF_VI_ASSERT(added - removed <= CI_ARRAY_SIZE(shm->freeq.q));
  freeq_size = added - removed;
  if( freeq_size < CI_ARRAY_SIZE(shm->freeq.q) ) {
    int16_t sbid_cur;
    shm->freeq.q[added++ & (CI_ARRAY_SIZE(shm->freeq.q) - 1)] = sbid;
    /* See if we can free any remaining sbufs in the descriptor free
     * list. */
    for( sbid_cur = state->free_head;
         sbid_cur != -1 && added - removed < CI_ARRAY_SIZE(shm->freeq.q);
         added++ ) {
      shm->freeq.q[added & (CI_ARRAY_SIZE(shm->freeq.q) - 1)] = sbid_cur;
      sbid_cur = efct_rx_desc_for_sb(vi, qid, sbid_cur)->sbid_next;
    }
    ci_wmb();
    OO_ACCESS_ONCE(shm->freeq.added) = added;
    state->free_head = sbid_cur;
  }
  else {
    /* No space in the freeq add to descriptor free list */
    efct_rx_sb_free_push(vi, qid, sbid);
  }
}

static bool efct_kbufs_available(const ef_vi* vi, int qid)
{
  const struct efab_efct_rxq_uk_shm_q* shm = &const_kbufs(vi)->shm->q[qid];
  return OO_ACCESS_ONCE(shm->rxq.added) != shm->rxq.removed;
}

static int efct_kbufs_attach(ef_vi* vi,
                             int qid,
                             int buf_fd,
                             unsigned n_superbufs,
                             bool shared_mode)
{
#ifdef __KERNEL__
  /* Onload does its own thing before calling attach_internal */
  BUG();
  return -EOPNOTSUPP;
#else
  int rc;
  ci_resource_alloc_t ra;
  int ix;
  int mfd = -1;
  unsigned n_hugepages = (n_superbufs + CI_EFCT_SUPERBUFS_PER_PAGE - 1) /
                         CI_EFCT_SUPERBUFS_PER_PAGE;

  ix = efct_vi_find_free_rxq(vi, qid);
  if( ix < 0 )
    return ix;

  /* The kernel code can cope with no memfd being provided, but only on older
   * kernels, i.e. older than 5.7 where the fallback with efrm_find_ksym()
   * stopped working. Overall:
   * - Onload uses the efrm_find_ksym() fallback on Linux older than 4.14.
   * - Both efrm_find_ksym() and memfd_create(MFD_HUGETLB) are available
   *   on Linux between 4.14 and 5.7.
   * - Onload can use only memfd_create(MFD_HUGETLB) on Linux 5.7+. */
  {
    char name[32];
    snprintf(name, sizeof(name), "ef_vi:%d", qid);
    mfd = syscall(__NR_memfd_create, name,
                  MFD_CLOEXEC | MFD_HUGETLB | MFD_HUGE_2MB);
    if( mfd < 0 && errno != ENOSYS && errno != EINVAL ) {
      rc = -errno;
      LOGVV(ef_log("%s: memfd_create failed %d", __FUNCTION__, rc));
      return rc;
    }

    /* The kernel will happily do this fallocation for us if we didn't,
     * however doing it here gives us nicer error reporting */
    if( mfd >= 0 ) {
      rc = fallocate(mfd, 0, 0, n_hugepages * CI_HUGEPAGE_SIZE);
      if( rc < 0 ) {
        rc = -errno;
        close(mfd);
        if( rc == -ENOSPC )
          LOGVV(ef_log("%s: memfd fallocate failed ENOSPC: insufficient huge "
                       "pages reserved with /proc/sys/vm/nr_hugepages?",
                       __FUNCTION__));
        else
          LOGVV(ef_log("%s: memfd fallocate failed %d", __FUNCTION__, rc));
        return rc;
      }
    }
  }

  ef_vi_init_resource_alloc(&ra, EFRM_RESOURCE_EFCT_RXQ);
  ra.u.rxq.in_abi_version = CI_EFCT_SWRXQ_ABI_VERSION;
  ra.u.rxq.in_flags = 0;
  ra.u.rxq.in_qid = qid;
  ra.u.rxq.in_shm_ix = ix;
  ra.u.rxq.in_vi_rs_id = efch_make_resource_id(vi->vi_resource_id);
  ra.u.rxq.in_n_hugepages = n_hugepages;
  ra.u.rxq.in_timestamp_req = true;
  ra.u.rxq.in_memfd = mfd;
  rc = ci_resource_alloc(vi->dh, &ra);
  if( mfd >= 0 )
    close(mfd);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: ci_resource_alloc rxq %d", __FUNCTION__, rc));
    return rc;
  }

  get_kbufs(vi)->q[ix].resource_id = ra.out_id.index;
  efct_vi_start_rxq(vi, ix, qid);
  return 0;
#endif
}

static int efct_kbufs_prime(ef_vi* vi, ef_driver_handle dh)
{
#ifdef __KERNEL__
  /* Onload does its own thing before calling attach_internal */
  BUG();
  return -EOPNOTSUPP;
#else
  ci_resource_prime_qs_op_t  op;
  int i;

  /* The loop below assumes that all rxqs will fit in the fixed array in
   * the operations's arguments. If that assumption no longer holds, then
   * this assertion will fail and we'll need a more complicated loop to split
   * the queues across multiple operations. */
  EF_VI_BUILD_ASSERT(CI_ARRAY_SIZE(op.rxq_current) >= EF_VI_MAX_EFCT_RXQS);

  op.crp_id = efch_make_resource_id(vi->vi_resource_id);
  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    op.rxq_current[i].rxq_id =
      efch_make_resource_id(get_kbufs(vi)->q[i].resource_id);
    if( efch_resource_id_is_none(op.rxq_current[i].rxq_id) )
      break;
    if( efct_vi_get_wakeup_params(vi, i, &op.rxq_current[i].sbseq,
                                  &op.rxq_current[i].pktix) < 0 )
      break;
  }
  op.n_rxqs = i;
  op.n_txqs = vi->vi_txq.mask != 0 ? 1 : 0;
  if( op.n_txqs )
    op.txq_current = vi->ep_state->evq.evq_ptr;
  return ci_resource_prime_qs(dh, &op);
#endif
}

static void efct_kbufs_cleanup_internal(ef_vi* vi)
{
  efct_superbufs_cleanup(vi);

#ifdef __KERNEL__
  kfree(get_kbufs(vi));
#else
  free((void*)vi->efct_rxqs.q[0].mappings);
  free(get_kbufs(vi));
#endif
}

#ifndef __KERNEL__
static void efct_kbufs_cleanup(ef_vi* vi)
{
  efct_kbufs_cleanup_internal(vi);
  ci_resource_munmap(vi->dh, get_kbufs(vi)->shm,
                     CI_ROUND_UP(CI_EFCT_SHM_BYTES(EF_VI_MAX_EFCT_RXQS),
                                 CI_PAGE_SIZE));
}
#endif

static void efct_kbufs_dump_stats(struct ef_vi* vi, ef_vi_dump_log_fn_t logger,
                                  void* log_arg)
{
  int i;

  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    const struct efab_efct_rxq_uk_shm_q* q = &vi->efct_rxqs.shm->q[i];
    if( ! q->superbuf_pkts )
      continue;
    logger(log_arg, "  rxq[%d]: hw=%d cfg=%u pkts=%u in=%u out=%u",
           i, q->qid, q->config_generation, q->superbuf_pkts,
           q->rxq.added - q->rxq.removed, q->freeq.added - q->freeq.removed);
    logger(log_arg, "  rxq[%d]: nospc=%u full=%u nobufs=%u skipped=%u",
           i, q->stats.no_rxq_space, q->stats.too_many_owned, q->stats.no_bufs,
           q->stats.skipped_bufs);
  }
}

int efct_kbufs_init_internal(ef_vi* vi,
                             struct efab_efct_rxq_uk_shm_base *shm,
                             void* space)
{
  struct efct_kbufs* rxqs;
  int i, rc;

  rc = efct_superbufs_reserve(vi, space);
  if( rc < 0 )
    return rc;

#ifdef __KERNEL__
  rxqs = kzalloc(sizeof(*rxqs), GFP_KERNEL);
  if( rxqs == NULL )
    goto fail_alloc;
#else
  uint64_t* mappings;
  const size_t mappings_bytes =
    vi->efct_rxqs.max_qs * CI_EFCT_MAX_HUGEPAGES * sizeof(mappings[0]);

  rxqs = calloc(1, sizeof(*rxqs));
  if( rxqs == NULL )
    goto fail_alloc;

  mappings = malloc(mappings_bytes);
  if( mappings == NULL ) {
    free(rxqs);
    goto fail_alloc;
  }

  memset(mappings, 0xff, mappings_bytes);
#endif

  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    ef_vi_efct_rxq* rxq = &vi->efct_rxqs.q[i];

    efct_get_rxq_state(vi, i)->qid = shm->q[i].qid;
#ifndef __KERNEL__
    rxqs->q[i].resource_id = EFCH_RESOURCE_ID_PRI_ARG(efch_resource_id_none());
    rxq->mappings = mappings + i * CI_EFCT_MAX_HUGEPAGES;
#endif
    rxq->live.superbuf_pkts = &shm->q[i].superbuf_pkts;
    rxq->live.config_generation = &shm->q[i].config_generation;
    rxq->live.time_sync = &shm->q[i].time_sync;
  }

  rxqs->shm = shm;
  rxqs->ops.available = efct_kbufs_available;
  rxqs->ops.next = efct_kbufs_next;
  rxqs->ops.free = efct_kbufs_free;
  rxqs->ops.attach = efct_kbufs_attach;
  rxqs->ops.prime = efct_kbufs_prime;
  rxqs->ops.cleanup = efct_kbufs_cleanup_internal;
  rxqs->ops.dump_stats = efct_kbufs_dump_stats;

  vi->efct_rxqs.active_qs = &shm->active_qs;
  vi->efct_rxqs.ops = &rxqs->ops;
  vi->efct_rxqs.shm = shm;

  return 0;

fail_alloc:
  efct_superbufs_cleanup(vi);
  return -ENOMEM;
}

#ifndef __KERNEL__
int efct_kbufs_init(ef_vi* vi)
{
  int rc;
  void* p;

  rc = ci_resource_mmap(vi->dh, vi->vi_resource_id, EFCH_VI_MMAP_RXQ_SHM,
                        CI_ROUND_UP(CI_EFCT_SHM_BYTES(EF_VI_MAX_EFCT_RXQS),
                                    CI_PAGE_SIZE),
                        &p);
  if( rc ) {
    LOGVV(ef_log("%s: ci_resource_mmap rxq shm %d", __FUNCTION__, rc));
    return rc;
  }

  rc = efct_kbufs_init_internal(vi, p, NULL);
  if( rc )
    ci_resource_munmap(vi->dh, get_kbufs(vi)->shm,
                       CI_ROUND_UP(CI_EFCT_SHM_BYTES(EF_VI_MAX_EFCT_RXQS),
                                   CI_PAGE_SIZE));
  vi->efct_rxqs.ops->refresh = efct_kbufs_refresh;
  vi->efct_rxqs.ops->cleanup = efct_kbufs_cleanup;
  return rc;
}
#endif


