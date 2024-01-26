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
#endif
#include "ef_vi_internal.h"
#include <etherfabric/vi.h>
#include <etherfabric/efct_vi.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/efhw/common.h>
#include <ci/tools/sysdep.h>

#ifndef __KERNEL__
struct efct_kbufs_rxq
{
  unsigned resource_id;
  uint64_t* current_mappings;
};
#endif

struct efct_kbufs
{
  ef_vi_efct_rxq_ops ops;
  struct efab_efct_rxq_uk_shm_base* shm;
#ifndef __KERNEL__
  uintptr_t refresh_user;
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
void efct_kbufs_set_refresh_user(ef_vi* vi, uintptr_t user)
{
  get_kbufs(vi)->refresh_user = user;
}

void efct_kbufs_get_refresh_params(ef_vi* vi, int qid,
                                   uintptr_t* user,
                                   const void** superbufs,
                                   const void** mappings)
{
  *user = get_kbufs(vi)->refresh_user;
  *superbufs = vi->efct_rxqs.q[qid].superbuf;
  *mappings = get_kbufs(vi)->q[qid].current_mappings;
}
#endif

static int efct_kbufs_refresh(ef_vi* vi, int qid)
{
#ifdef __KERNEL__
  /* Onload provides alternative functions so this shouldn't be called */
  BUG();
  return -EOPNOTSUPP;
#else
  ef_vi_efct_rxq* rxq = &vi->efct_rxqs.q[qid];
  struct efct_kbufs_rxq* kbq = &get_kbufs(vi)->q[qid];

  ci_resource_op_t op;
  op.op = CI_RSOP_RXQ_REFRESH;
  op.id = efch_make_resource_id(kbq->resource_id);
  op.u.rxq_refresh.superbufs = (uintptr_t)rxq->superbuf;
  op.u.rxq_refresh.current_mappings = (uintptr_t)kbq->current_mappings;
  op.u.rxq_refresh.max_superbufs = CI_EFCT_MAX_SUPERBUFS;
  return ci_resource_op(vi->dh, &op);
#endif
}

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
    for( sbid_cur = vi->ep_state->rxq.sb_desc_free_head[qid];
         sbid_cur != -1 && added - removed < CI_ARRAY_SIZE(shm->freeq.q);
         added++ ) {
      shm->freeq.q[added & (CI_ARRAY_SIZE(shm->freeq.q) - 1)] = sbid_cur;
      sbid_cur = efct_rx_sb_free_next(vi, qid, sbid_cur);
    }
    ci_wmb();
    OO_ACCESS_ONCE(shm->freeq.added) = added;
    vi->ep_state->rxq.sb_desc_free_head[qid] = sbid_cur;
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

static int efct_kbufs_attach(ef_vi* vi, int qid, unsigned n_superbufs)
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
    mfd = syscall(__NR_memfd_create, name, MFD_CLOEXEC | MFD_HUGETLB);
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

  memset(&ra, 0, sizeof(ra));
  ef_vi_set_intf_ver(ra.intf_ver, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_EFCT_RXQ;
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

int efct_kbufs_prime(ef_vi* vi, ef_driver_handle dh)
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
#ifdef __KERNEL__
  kvfree(vi->efct_rxqs.q[0].superbufs);
  kfree(get_kbufs(vi));
#else
  munmap((void*)vi->efct_rxqs.q[0].superbuf,
         (size_t)vi->efct_rxqs.max_qs * CI_EFCT_MAX_SUPERBUFS * EFCT_RX_SUPERBUF_BYTES);
  free(get_kbufs(vi)->q[0].current_mappings);
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

int efct_vi_mmap_init_internal(ef_vi* vi,
                               struct efab_efct_rxq_uk_shm_base *shm)
{
  struct efct_kbufs* rxqs;
  void* space;
  int i;

  vi->efct_rxqs.max_qs = EF_VI_MAX_EFCT_RXQS;

#ifdef __KERNEL__
  rxqs = kzalloc(sizeof(*rxqs), GFP_KERNEL);
  if( rxqs == NULL )
    return -ENOMEM;

  space = kvmalloc(vi->efct_rxqs.max_qs * CI_EFCT_MAX_HUGEPAGES *
                   CI_EFCT_SUPERBUFS_PER_PAGE *
                   sizeof(vi->efct_rxqs.q[0].superbufs[0]), GFP_KERNEL);
  if( space == NULL ) {
    kfree(rxqs);
    return -ENOMEM;
  }
#else
  uint64_t* mappings;
  const size_t bytes_per_rxq =
    (size_t)CI_EFCT_MAX_SUPERBUFS * EFCT_RX_SUPERBUF_BYTES;
  const size_t mappings_bytes =
    vi->efct_rxqs.max_qs * CI_EFCT_MAX_HUGEPAGES * sizeof(mappings[0]);

  rxqs = calloc(1, sizeof(*rxqs));
  if( rxqs == NULL )
    return -ENOMEM;

  mappings = malloc(mappings_bytes);
  if( mappings == NULL ) {
    free(rxqs);
    return -ENOMEM;
  }

  memset(mappings, 0xff, mappings_bytes);

  /* This is reserving a gigantic amount of virtual address space (with no
   * memory behind it) so we can later on (in efct_vi_attach_rxq()) plonk the
   * actual mmappings for each specific superbuf into a computable place
   * within this space, i.e. so that conversion from {rxq#,superbuf#} to
   * memory address is trivial arithmetic rather than needing various array
   * lookups.
   *
   * In kernelspace we can't do this trickery (see the other #ifdef branch), so
   * we pay the price of doing the naive array lookups: we have an array of
   * pointers to superbufs. */
  space = mmap(NULL, vi->efct_rxqs.max_qs * bytes_per_rxq, PROT_NONE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_HUGETLB,
               -1, 0);
  if( space == MAP_FAILED ) {
    free(mappings);
    free(rxqs);
    return -ENOMEM;
  }
  
  madvise(space, vi->efct_rxqs.max_qs * bytes_per_rxq, MADV_DONTDUMP);
#endif

  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    ef_vi_efct_rxq* rxq = &vi->efct_rxqs.q[i];
    rxq->qid = shm->q[i].qid;
#ifdef __KERNEL__
    rxq->superbufs = (const char**)space +
                     i * CI_EFCT_MAX_HUGEPAGES * CI_EFCT_SUPERBUFS_PER_PAGE;
#else
    rxqs->q[i].resource_id = EFCH_RESOURCE_ID_PRI_ARG(efch_resource_id_none());
    rxq->superbuf = (char*)space + i * bytes_per_rxq;
    rxqs->q[i].current_mappings = mappings + i * CI_EFCT_MAX_HUGEPAGES;
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
  rxqs->ops.refresh = efct_kbufs_refresh;
  rxqs->ops.cleanup = efct_kbufs_cleanup_internal;

  vi->efct_rxqs.active_qs = &shm->active_qs;
  vi->efct_rxqs.ops = &rxqs->ops;
  vi->efct_rxqs.shm = shm;

  return 0;
}

#ifndef __KERNEL__
int efct_vi_mmap_init(ef_vi* vi, int rxq_capacity)
{
  int rc;
  void* p;

  if( rxq_capacity == 0 )
    return 0;

  rc = ci_resource_mmap(vi->dh, vi->vi_resource_id, EFCH_VI_MMAP_RXQ_SHM,
                        CI_ROUND_UP(CI_EFCT_SHM_BYTES(EF_VI_MAX_EFCT_RXQS),
                                    CI_PAGE_SIZE),
                        &p);
  if( rc ) {
    LOGVV(ef_log("%s: ci_resource_mmap rxq shm %d", __FUNCTION__, rc));
    return rc;
  }

  rc = efct_vi_mmap_init_internal(vi, p);
  if( rc )
    ci_resource_munmap(vi->dh, get_kbufs(vi)->shm,
                       CI_ROUND_UP(CI_EFCT_SHM_BYTES(EF_VI_MAX_EFCT_RXQS),
                                   CI_PAGE_SIZE));
  vi->efct_rxqs.ops->cleanup = efct_kbufs_cleanup;
  return rc;
}
#endif


