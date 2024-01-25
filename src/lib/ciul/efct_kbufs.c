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
int superbuf_config_refresh(ef_vi* vi, int qid)
{
  ef_vi_efct_rxq* rxq = &vi->efct_rxq[qid];
  ci_resource_op_t op;
  op.op = CI_RSOP_RXQ_REFRESH;
  op.id = efch_make_resource_id(rxq->resource_id);
  op.u.rxq_refresh.superbufs = (uintptr_t)rxq->superbuf;
  op.u.rxq_refresh.current_mappings = (uintptr_t)rxq->current_mappings;
  op.u.rxq_refresh.max_superbufs = CI_EFCT_MAX_SUPERBUFS;
  return ci_resource_op(vi->dh, &op);
}
#endif

int superbuf_next(ef_vi* vi, int qid, bool* sentinel, unsigned* sbseq)
{
  struct efab_efct_rxq_uk_shm_q* shm = &vi->efct_shm->q[qid];
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

void superbuf_free(ef_vi* vi, int qid, int sbid)
{
  struct efab_efct_rxq_uk_shm_q* shm = &vi->efct_shm->q[qid];
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

bool efct_rxq_can_rollover(const ef_vi* vi, int qid)
{
  struct efab_efct_rxq_uk_shm_q* shm = &vi->efct_shm->q[qid];
  return OO_ACCESS_ONCE(shm->rxq.added) != shm->rxq.removed;
}

#ifndef __KERNEL__
int efct_vi_attach_rxq(ef_vi* vi, int qid, unsigned n_superbufs)
{
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

  efct_vi_attach_rxq_internal(vi, ix, ra.out_id.index,
                              superbuf_config_refresh);
  efct_vi_start_rxq(vi, ix);
  return 0;
}
#endif

void efct_vi_attach_rxq_internal(ef_vi* vi, int ix, int resource_id,
                                 ef_vi_efct_superbuf_refresh_t *refresh_func)
{
  ef_vi_efct_rxq* rxq;

  rxq = &vi->efct_rxq[ix];
  rxq->resource_id = resource_id;
  rxq->config_generation = 0;
  rxq->refresh_func = refresh_func;
}

#ifndef __KERNEL__
int efct_vi_prime(ef_vi* vi, ef_driver_handle dh)
{
    ci_resource_prime_qs_op_t  op;
    int i;

    /* The loop below assumes that all rxqs will fit in the fixed array in
     * the operations's arguments. If that assumption no longer holds, then
     * this assertion will fail and we'll need a more complicated loop to split
     * the queues across multiple operations. */
    EF_VI_BUILD_ASSERT(CI_ARRAY_SIZE(op.rxq_current) >= EF_VI_MAX_EFCT_RXQS);

    op.crp_id = efch_make_resource_id(vi->vi_resource_id);
    for( i = 0; i < vi->max_efct_rxq; ++i ) {
      ef_vi_efct_rxq* rxq = &vi->efct_rxq[i];

      op.rxq_current[i].rxq_id = efch_make_resource_id(rxq->resource_id);
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
}
#endif

void efct_vi_munmap_internal(ef_vi* vi)
{
#ifdef __KERNEL__
  kvfree(vi->efct_rxq[0].superbufs);
#else
  munmap((void*)vi->efct_rxq[0].superbuf,
         (size_t)vi->max_efct_rxq * CI_EFCT_MAX_SUPERBUFS * EFCT_RX_SUPERBUF_BYTES);
  free(vi->efct_rxq[0].current_mappings);
#endif
}

#ifndef __KERNEL__
void efct_vi_munmap(ef_vi* vi)
{
  efct_vi_munmap_internal(vi);
  ci_resource_munmap(vi->dh, vi->efct_shm,
                     CI_ROUND_UP(CI_EFCT_SHM_BYTES(EF_VI_MAX_EFCT_RXQS),
                                 CI_PAGE_SIZE));
}
#endif

int efct_vi_mmap_init_internal(ef_vi* vi,
                               struct efab_efct_rxq_uk_shm_base *shm)
{
  void* space;
  int i;

#ifdef __KERNEL__
  space = kvmalloc((size_t)vi->max_efct_rxq * CI_EFCT_MAX_HUGEPAGES *
                   CI_EFCT_SUPERBUFS_PER_PAGE *
                   sizeof(vi->efct_rxq[0].superbufs[0]), GFP_KERNEL);
  if( space == NULL )
    return -ENOMEM;
#else
  uint64_t* mappings;
  const size_t bytes_per_rxq =
    (size_t)CI_EFCT_MAX_SUPERBUFS * EFCT_RX_SUPERBUF_BYTES;
  const size_t mappings_bytes =
    vi->max_efct_rxq * CI_EFCT_MAX_HUGEPAGES * sizeof(mappings[0]);

  mappings = malloc(mappings_bytes);
  if( mappings == NULL )
    return -ENOMEM;

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
  space = mmap(NULL, vi->max_efct_rxq * bytes_per_rxq, PROT_NONE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_HUGETLB,
               -1, 0);
  if( space == MAP_FAILED ) {
    free(mappings);
    return -ENOMEM;
  }
  
  madvise(space, vi->max_efct_rxq * bytes_per_rxq, MADV_DONTDUMP);
#endif

  vi->efct_shm = shm;

  for( i = 0; i < vi->max_efct_rxq; ++i ) {
    ef_vi_efct_rxq* rxq = &vi->efct_rxq[i];
#ifdef __KERNEL__
    rxq->superbufs = (const char**)space +
                     i * CI_EFCT_MAX_HUGEPAGES * CI_EFCT_SUPERBUFS_PER_PAGE;
#else
    rxq->resource_id = EFCH_RESOURCE_ID_PRI_ARG(efch_resource_id_none());
    rxq->superbuf = (char*)space + i * bytes_per_rxq;
    rxq->current_mappings = mappings + i * CI_EFCT_MAX_HUGEPAGES;
#endif
  }

  return 0;
}

#ifndef __KERNEL__
static struct efab_efct_rxq_uk_shm_base zero_efct_shm = {
  .active_qs = 0,
};

int efct_vi_mmap_init(ef_vi* vi, int rxq_capacity)
{
  int rc;
  void* p;

  if( rxq_capacity == 0 ) {
    vi->efct_shm = &zero_efct_shm;
    vi->max_efct_rxq = 0;
    return 0;
  }

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
    ci_resource_munmap(vi->dh, vi->efct_shm,
                       CI_ROUND_UP(CI_EFCT_SHM_BYTES(EF_VI_MAX_EFCT_RXQS),
                                   CI_PAGE_SIZE));
  return rc;
}
#endif


