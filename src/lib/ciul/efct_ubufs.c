/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */

/* EFCT buffer management using user-allocated buffers */

#ifdef __KERNEL__
#error TODO support efct_ubufs for kernel ef_vi
#endif

#include <stdio.h>

#include <sys/mman.h>
#include <etherfabric/memreg.h>
#include "ef_vi_internal.h"
#include "shrub_pool.h"
#include "driver_access.h"
#include "shrub_client.h"
#include "shrub_pool.h"
#include "logging.h"

/* TODO move CI_EFCT_MAX_SUPERBUFS somewhere more sensible, or remove
 * dependencies on it */
#include <etherfabric/internal/efct_uk_api.h>

struct efct_ubufs_desc
{
  unsigned id : 31;
  unsigned sentinel : 1;
};

struct efct_ubufs_rxq
{
  uint32_t superbuf_pkts;
  struct ef_shrub_buffer_pool* buffer_pool;
  struct ef_shrub_client shrub_client;

  /* FIFO to record buffers posted to the NIC. */
  unsigned added, filled, removed;
  struct efct_ubufs_desc fifo[CI_EFCT_MAX_SUPERBUFS];

  /* Buffer memory region */
  ef_memreg memreg;
};

struct efct_ubufs
{
  ef_vi_efct_rxq_ops ops;
  uint64_t active_qs;
  unsigned nic_fifo_limit;
  ef_pd* pd;
  ef_driver_handle pd_dh;

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

static void poison_superbuf(char *sbuf)
{
  int i;
  /* Write poison value to the start of each frame. Subtract 2 to obtain a
   * 64-bit aligned pointer.
   */
  char *pkt = sbuf + EFCT_RX_HEADER_NEXT_FRAME_LOC_1 - 2;
  for(i = 0; i < EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE; i++) {
    *((uint64_t *)pkt) = CI_EFCT_DEFAULT_POISON;
    pkt += EFCT_PKT_STRIDE;
  }
  /* Ensure writes are not reordered after post. */
  wmb();
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
     */
    header = efct_superbuf_access(vi, qid, id);
    poison_superbuf((char *)header);

    desc.id = id;
    desc.sentinel = ! CI_QWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL);

    EF_VI_ASSERT(rxq->added - rxq->removed < CI_EFCT_MAX_SUPERBUFS);
    rxq->fifo[rxq->added++ % CI_EFCT_MAX_SUPERBUFS] = desc;

    vi->efct_rxqs.ops->post(vi, qid, id, desc.sentinel);
  }
}

static int efct_ubufs_next_shared(ef_vi* vi, int qid, bool* sentinel, unsigned* sbseq)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[qid];

  ef_shrub_buffer_id id;
  int rc = ef_shrub_client_acquire_buffer(&rxq->shrub_client, &id, sentinel);
  if ( rc < 0 ) {
    return rc;
  }
  *sbseq = rxq->removed++;
  return id;
}

static int efct_ubufs_next_local(ef_vi* vi, int qid, bool* sentinel, unsigned* sbseq)
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

static int efct_ubufs_next(ef_vi* vi, int qid, bool* sentinel, unsigned* sbseq)
{
  const struct efct_ubufs_rxq* rxq = &const_ubufs(vi)->q[qid];
  if( rxq->buffer_pool )
    return efct_ubufs_next_local(vi, qid, sentinel, sbseq);
  else
    return efct_ubufs_next_shared(vi, qid, sentinel, sbseq);
}

static void efct_ubufs_free_local(ef_vi* vi, int qid, int sbid)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[qid];

  ef_shrub_free_buffer(rxq->buffer_pool, sbid);
  update_filled(vi, rxq, qid);
  post_buffers(vi, rxq, qid);
}

static void efct_ubufs_free_shared(ef_vi* vi, int qid, int sbid)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[qid];
  ef_shrub_client_release_buffer(&rxq->shrub_client, sbid);
}

static void efct_ubufs_free(ef_vi* vi, int qid, int sbid)
{
  const struct efct_ubufs_rxq* rxq = &const_ubufs(vi)->q[qid];
  if( rxq->buffer_pool )
    efct_ubufs_free_local(vi, qid, sbid);
  else
    efct_ubufs_free_shared(vi, qid, sbid);
}

static bool efct_ubufs_local_available(const ef_vi* vi, int qid)
{
  const struct efct_ubufs_rxq* rxq = &const_ubufs(vi)->q[qid];
  return rxq->added != rxq->removed;
}

static bool efct_ubufs_shared_available(const ef_vi* vi, int qid)
{
  const struct efct_ubufs_rxq* rxq = &const_ubufs(vi)->q[qid];
  return ef_shrub_client_buffer_available(&rxq->shrub_client);
}

static bool efct_ubufs_available(const ef_vi* vi, int qid)
{
  const struct efct_ubufs_rxq* rxq = &const_ubufs(vi)->q[qid];
  if( rxq->buffer_pool )
    return efct_ubufs_local_available(vi, qid);
  else
    return efct_ubufs_shared_available(vi, qid);
}


static void efct_ubufs_post_direct(ef_vi* vi, int qid, int sbid, bool sentinel)
{
  ef_addr addr = ef_memreg_dma_addr(&get_ubufs(vi)->q[qid].memreg,
                                    sbid * EFCT_RX_SUPERBUF_BYTES);
  volatile uint64_t* reg =
    (uint64_t*)(vi->vi_rx_post_buffer_mmap_ptr +
                vi->efct_rxqs.q[qid].qid * vi->efct_rxqs.rx_stride);

  ci_qword_t qword;
  CI_POPULATE_QWORD_3(qword,
                      EFCT_RX_BUFFER_POST_ADDRESS, addr >> 12,
                      EFCT_RX_BUFFER_POST_SENTINEL, sentinel,
                      EFCT_RX_BUFFER_POST_ROLLOVER, 0); // TBD support for rollover?

  *reg = qword.u64[0];
}

static void efct_ubufs_post_kernel(ef_vi* vi, int qid, int sbid, bool sentinel)
{
  ef_addr addr = ef_memreg_dma_addr(&get_ubufs(vi)->q[qid].memreg,
                                    sbid * EFCT_RX_SUPERBUF_BYTES);

  ci_resource_op_t op = {};

  op.op = CI_RSOP_RX_BUFFER_POST;
  op.id = efch_make_resource_id(vi->vi_resource_id);
  op.u.buffer_post.qid = vi->efct_rxqs.q[qid].qid;
  op.u.buffer_post.user_addr = (uint64_t)addr;
  op.u.buffer_post.sentinel = sentinel;
  op.u.buffer_post.rollover = 0; // TBD support for rollover?

  /* TBD should we handle/report errors? */
  ci_resource_op(vi->dh, &op);
}


static int efct_ubufs_local_attach(ef_vi* vi, int qid, int fd, unsigned n_superbufs)
{
#ifdef __KERNEL__
  // TODO
  BUG();
  return -EOPNOTSUPP;
#else
  int ix, rc;
  ef_shrub_buffer_id id;
  void* map;
  size_t map_bytes;
  struct efct_ubufs* ubufs = get_ubufs(vi);
  struct efct_ubufs_rxq* rxq;

  int flags = (fd < 0 ? MAP_PRIVATE | MAP_ANONYMOUS : MAP_SHARED);

  if( n_superbufs > CI_EFCT_MAX_SUPERBUFS )
    return -EINVAL;

  ix = efct_vi_find_free_rxq(vi, qid);
  if( ix < 0 )
    return ix;

  map_bytes = CI_ROUND_UP((size_t)n_superbufs * EFCT_RX_SUPERBUF_BYTES,
                          CI_HUGEPAGE_SIZE);
  map = mmap((void*)vi->efct_rxqs.q[ix].superbuf, map_bytes,
             PROT_READ | PROT_WRITE,
             flags  | MAP_NORESERVE | MAP_HUGETLB |
             MAP_FIXED | MAP_POPULATE,
             fd, 0);
  if( map == MAP_FAILED )
    return -errno;
  if( map != vi->efct_rxqs.q[ix].superbuf ) {
    munmap(map, map_bytes);
    return -ENOMEM;
  }

  rxq = &ubufs->q[ix];
  rc = ef_shrub_init_pool(n_superbufs, &rxq->buffer_pool);
  if( rc < 0 ) {
    munmap(map, map_bytes);
    return rc;
  }
  for( id = 0; id < n_superbufs; ++id )
    ef_shrub_free_buffer(rxq->buffer_pool, id);

  rxq->superbuf_pkts = EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE;

  rc = ef_memreg_alloc(&rxq->memreg, vi->dh, ubufs->pd, ubufs->pd_dh,
                       map, map_bytes);
  if( rc < 0 ) {
    ef_shrub_fini_pool(rxq->buffer_pool);
    munmap(map, map_bytes);
    return rc;
  }

  ubufs->active_qs |= 1 << ix;
  efct_vi_start_rxq(vi, ix, qid);
  post_buffers(vi, rxq, ix);

  return 0;
#endif
}

static int efct_ubufs_shared_attach(ef_vi* vi, int qid, int buf_fd, unsigned n_superbufs)
{
  int ix;
  struct efct_ubufs* ubufs = get_ubufs(vi);
  struct efct_ubufs_rxq* rxq;

  EF_VI_ASSERT(qid < vi->efct_rxqs.max_qs);

  ix = efct_vi_find_free_rxq(vi, qid);
  if( ix < 0 )
    return ix;

  rxq = &ubufs->q[ix];
  int rc = ef_shrub_client_open(&rxq->shrub_client,
                                (void*)vi->efct_rxqs.q[ix].superbuf,
                                EF_SHRUB_CONTROLLER_PATH, qid);
  if ( rc != 0 ) {
    LOG(ef_log("%s: ERROR initializing shrub client! rc=%d", __FUNCTION__, rc));
    return -rc;
  }
  rxq->superbuf_pkts = rxq->shrub_client.state->metrics.buffer_bytes / EFCT_PKT_STRIDE;

  ubufs->active_qs |= 1 << ix;
  efct_vi_start_rxq(vi, ix, qid);
  
  return 0;
}

static int efct_ubufs_attach(ef_vi* vi,
                             int qid,
                             int fd,
                             unsigned n_superbufs,
                             bool shared_mode)
{
  if ( shared_mode ) {
    return efct_ubufs_shared_attach(vi, qid, fd, n_superbufs);
  } else {
    return efct_ubufs_local_attach(vi, qid, fd, n_superbufs);
  }
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
  struct efct_ubufs* ubufs = get_ubufs(vi);
  efct_superbufs_cleanup(vi);

#ifdef __KERNEL__
  kzfree(ubufs);
#else
  int i;
  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    struct efct_ubufs_rxq* rxq = &ubufs->q[i];
    if( rxq->buffer_pool )
      ef_shrub_fini_pool(rxq->buffer_pool);
    ef_memreg_free(&rxq->memreg, vi->dh);
  }
  free(ubufs);
#endif
}

int efct_ubufs_init(ef_vi* vi, ef_pd* pd, ef_driver_handle pd_dh)
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
    rxq->qid = -1;
    rxq->live.superbuf_pkts = &ubufs->q[i].superbuf_pkts;
    rxq->live.config_generation = &rxq->config_generation;
    // TODO time_sync?
  }

  /* TODO get this limit from the design parameter DP_RX_BUFFER_FIFO_SIZE,
   * perhaps allow configuration to a smaller value to reduce working set */
  ubufs->nic_fifo_limit = 128;
  ubufs->pd = pd;
  ubufs->pd_dh = pd_dh;

  ubufs->ops.free = efct_ubufs_free;
  ubufs->ops.next = efct_ubufs_next;
  ubufs->ops.available = efct_ubufs_available;
  ubufs->ops.attach = efct_ubufs_attach;
  ubufs->ops.refresh = efct_ubufs_refresh;
  ubufs->ops.prime = efct_ubufs_prime;
  ubufs->ops.cleanup = efct_ubufs_cleanup;

  if( vi->vi_flags & EF_VI_RX_PHYS_ADDR )
    ubufs->ops.post = efct_ubufs_post_direct;
  else
    ubufs->ops.post = efct_ubufs_post_kernel;

  vi->efct_rxqs.active_qs = &ubufs->active_qs;
  vi->efct_rxqs.ops = &ubufs->ops;

  return 0;
}

