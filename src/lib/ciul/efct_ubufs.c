/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */

/* EFCT buffer management using user-allocated buffers */

#ifdef __KERNEL__
#error TODO support efct_ubufs for kernel ef_vi
#endif

#include <sys/mman.h>
#include "ef_vi_internal.h"
#include "shrub_pool.h"

/* TODO move CI_EFCT_MAX_SUPERBUFS somewhere more sensible, or remove
 * dependencies on it */
#include <etherfabric/internal/efct_uk_api.h>

struct efct_ubufs_desc
{
  unsigned id : 31;
  unsigned sentinel : 1;
};

/* TODO for Onload, share mutable state between kernel and user instances */
struct efct_ubufs_rxq
{
  uint32_t superbuf_pkts;
  struct ef_shrub_buffer_pool* buffer_pool;

  /* FIFO to record buffers posted to the NIC. */
  unsigned added, filled, removed;
  struct efct_ubufs_desc fifo[CI_EFCT_MAX_SUPERBUFS];
};

struct efct_ubufs
{
  ef_vi_efct_rxq_ops ops;
  uint64_t active_qs;
  unsigned nic_fifo_limit;
  struct efct_ubufs_rxq q[EF_VI_MAX_EFCT_RXQS];
};

static struct efct_ubufs* get_ubufs(ef_vi* vi)
{
  return CI_CONTAINER(struct efct_ubufs, ops, vi->efct_rxqs.ops);
}

static const struct efct_ubufs* const_ubufs(const ef_vi* vi)
{
  return CI_CONTAINER(struct efct_ubufs, ops, vi->efct_rxqs.ops);
}

static void update_filled(ef_vi* vi, struct efct_ubufs_rxq* rxq, int qid)
{
  while( rxq->added - rxq->filled > 1 ) {
    const ci_qword_t* header;
    struct efct_ubufs_desc desc;

    /* We consider a buffer to be filled once the first metadata in the
     * following buffer has been written.
     *
     * For both X3 (metadata in the following packet) and X4 (metadata located
     * with the packet) this indicates that the final packet in the current
     * buffer has been written and the buffer removed from the hardware
     * FIFO, so we may post a new buffer to replace it.
     *
     * For X4, we could instead check the final sentinel of the current
     * buffer and perhaps post a new buffer slightly earlier, but I don't
     * think the extra complexity is justified.
     */
    desc = rxq->fifo[(rxq->filled + 1) % CI_EFCT_MAX_SUPERBUFS];
    header = efct_superbuf_access(vi, qid, desc.id);
    if( CI_QWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL) != desc.sentinel )
      break;
    ++rxq->filled;
  }
}

static void post_buffers(ef_vi* vi, struct efct_ubufs_rxq* rxq, int qid)
{
  while( rxq->added - rxq->filled < get_ubufs(vi)->nic_fifo_limit ) {
    const ci_qword_t* header;
    struct efct_ubufs_desc desc;

    ef_shrub_buffer_id id = ef_shrub_alloc_buffer(rxq->buffer_pool);
    if( id == EF_SHRUB_INVALID_BUFFER )
      break;

    /* We assume that the first sentinel value applies to the whole superbuf.
     * TBD: will we ever need to deal with manual rollover?
     * TODO: write poison values to support PFTF
     */
    header = efct_superbuf_access(vi, qid, id);

    desc.id = id;
    desc.sentinel = ! CI_QWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL);

    EF_VI_ASSERT(rxq->added - rxq->removed < CI_EFCT_MAX_SUPERBUFS);
    rxq->fifo[rxq->added++ % CI_EFCT_MAX_SUPERBUFS] = desc;

    vi->efct_rxqs.ops->post(vi, qid, id, desc.sentinel);
  }
}

static int efct_ubufs_next(ef_vi* vi, int qid, bool* sentinel, unsigned* sbseq)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[qid];
  struct efct_ubufs_desc desc;
  unsigned seq;

  update_filled(vi, rxq, qid);
  post_buffers(vi, rxq, qid);

  if( rxq->added == rxq->removed )
    return -EAGAIN;

  seq = rxq->removed++;
  desc = rxq->fifo[seq % CI_EFCT_MAX_SUPERBUFS];

  *sentinel = desc.sentinel;
  *sbseq = seq;
  return desc.id;
}

static void efct_ubufs_free(ef_vi* vi, int qid, int sbid)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[qid];

  ef_shrub_free_buffer(rxq->buffer_pool, sbid);
  update_filled(vi, rxq, qid);
  post_buffers(vi, rxq, qid);
}

static bool efct_ubufs_available(const ef_vi* vi, int qid)
{
  const struct efct_ubufs_rxq* rxq = &const_ubufs(vi)->q[qid];
  return rxq->added != rxq->removed;
}

static void efct_ubufs_post(ef_vi* vi, int qid, int sbid, bool sentinel)
{
  /* TODO we'll eventually want a few implementations:
   *  direct (user/kernel), sfc_char syscall, onload syscall
   */
  (void)vi;
  (void)qid;
  (void)sbid;
  (void)sentinel;
}

static int efct_ubufs_attach(ef_vi* vi, int qid, unsigned n_superbufs)
{
#ifdef __KERNEL__
  // TODO
  BUG();
  return -EOPNOTSUPP;
#else
  int ix, rc;
  ef_shrub_buffer_id id;
  void* map;
  struct efct_ubufs_rxq* rxq;

  if( n_superbufs > CI_EFCT_MAX_SUPERBUFS )
    return -EINVAL;

  ix = efct_vi_find_free_rxq(vi, qid);
  if( ix < 0 )
    return ix;

  map = mmap((void*)vi->efct_rxqs.q[ix].superbuf,
             n_superbufs * EFCT_RX_SUPERBUF_BYTES,
             PROT_READ,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_HUGETLB |
               MAP_FIXED | MAP_POPULATE,
             -1, 0);
  if( map == MAP_FAILED )
    return -errno;
  if( map != vi->efct_rxqs.q[ix].superbuf ) {
    munmap(map, n_superbufs * EFCT_RX_SUPERBUF_BYTES);
    return -ENOMEM;
  }

  rxq = &get_ubufs(vi)->q[ix];
  rc = ef_shrub_init_pool(n_superbufs, &rxq->buffer_pool);
  if( rc < 0 ) {
    munmap(map, n_superbufs * EFCT_RX_SUPERBUF_BYTES);
    return rc;
  }
  for( id = 0; id < n_superbufs; ++id )
    ef_shrub_free_buffer(rxq->buffer_pool, id);
  post_buffers(vi, rxq, ix);

  rxq->superbuf_pkts = EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE;

  get_ubufs(vi)->active_qs |= 1 << ix;
  efct_vi_start_rxq(vi, ix, qid);

  return 0;
#endif
}

static int efct_ubufs_prime(ef_vi* vi, ef_driver_handle dh)
{
  // TODO
  return -EOPNOTSUPP;
}

static int efct_ubufs_refresh(ef_vi* vi, int qid)
{
  /* Nothing to do */
  return 0;
}

static void efct_ubufs_cleanup(ef_vi* vi)
{
  efct_superbufs_cleanup(vi);

#ifdef __KERNEL__
  kzfree(get_ubufs(vi));
#else
  int i;
  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[i];
    if( rxq->buffer_pool )
      ef_shrub_fini_pool(rxq->buffer_pool);
  }
  free(get_ubufs(vi));
#endif
}

int efct_ubufs_init(ef_vi* vi)
{
  struct efct_ubufs* ubufs;
  int i, rc;

  rc = efct_superbufs_reserve(vi, NULL);
  if( rc < 0 )
    return rc;

#ifdef __KERNEL__
  ubufs = kzalloc(sizeof(*ubufs), GFP_KERNEL);
#else
  ubufs = calloc(1, sizeof(*ubufs));
#endif

  if( ubufs == NULL ) {
    efct_superbufs_cleanup(vi);
    return -ENOMEM;
  }

  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    ef_vi_efct_rxq* rxq = &vi->efct_rxqs.q[i];
    rxq->live.superbuf_pkts = &ubufs->q[i].superbuf_pkts;
    // TODO time_sync?
  }

  /* TODO get this limit from the design parameter DP_RX_BUFFER_FIFO_SIZE,
   * perhaps allow configuration to a smaller value to reduce working set */
  ubufs->nic_fifo_limit = 128;

  ubufs->ops.available = efct_ubufs_available;
  ubufs->ops.next = efct_ubufs_next;
  ubufs->ops.free = efct_ubufs_free;
  ubufs->ops.post = efct_ubufs_post;
  ubufs->ops.attach = efct_ubufs_attach;
  ubufs->ops.refresh = efct_ubufs_refresh;
  ubufs->ops.prime = efct_ubufs_prime;
  ubufs->ops.cleanup = efct_ubufs_cleanup;

  vi->efct_rxqs.active_qs = &ubufs->active_qs;
  vi->efct_rxqs.ops = &ubufs->ops;

  return 0;
}

