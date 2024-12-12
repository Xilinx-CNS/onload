/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */

/* EFCT buffer management using user-allocated buffers */

#include <etherfabric/memreg.h>
#include "ef_vi_internal.h"
#include "shrub_client.h"
#include "logging.h"

#ifndef __KERNEL__
#include <sys/mman.h>
#include <linux/mman.h>
#include "driver_access.h"
#endif

/* TODO move CI_EFCT_MAX_SUPERBUFS somewhere more sensible, or remove
 * dependencies on it */
#include <etherfabric/internal/efct_uk_api.h>

struct efct_ubufs_rxq
{
  uint32_t superbuf_pkts;
  struct ef_shrub_client shrub_client;

  /* Buffer memory region */
  ef_memreg memreg;

  /* shared queue resource */
  unsigned resource_id;

  volatile uint64_t *rx_post_buffer_reg;
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

static bool rxq_is_local(const ef_vi* vi, int qid)
{
  return const_ubufs(vi)->q[qid].shrub_client.buffers == NULL;
}

static void update_filled(ef_vi* vi, int qid)
{
  ef_vi_efct_rxq_state* state = &vi->ep_state->rxq.efct_state[qid];

  while( state->fifo_count_hw != 0 ) {
    const char* buffer;
    const ci_qword_t* header;
    const struct efct_rx_descriptor* desc;

    /* We consider a buffer to be filled once the final metadata in the
     * buffer has been written. This is correct for X4 (metadata located with
     * the packet) but wrong for X3 (metadata in the following packet).
     *
     * For simplicity, assume that the metadata is located with the packet.
     * In the unlikely event that we will want to use this system with X3,
     * more work would be required to look in the right place for that
     * architecture.
     *
     * (I was initially tempted to look in the following buffer for both
     * architectures; however that caused problems when a buffer was freed and
     * reused before advancing the hardware tail beyond it.)
     */
    EF_VI_ASSERT(vi->efct_rxqs.meta_offset == 0);

    EF_VI_ASSERT(state->fifo_tail_hw != -1 ); /* implied by count_hw > 0 */
    desc = efct_rx_desc_for_sb(vi, qid, state->fifo_tail_hw);
    buffer = efct_superbuf_access(vi, qid, state->fifo_tail_hw);
    header = (const ci_qword_t*)(buffer + EFCT_RX_SUPERBUF_BYTES - EFCT_PKT_STRIDE);

    if( CI_QWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL) != desc->sentinel )
      break;

    state->fifo_tail_hw = desc->sbid_next;
    state->fifo_count_hw--;
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

static void post_buffers(ef_vi* vi, int qid)
{
  ef_vi_efct_rxq_state* state = &vi->ep_state->rxq.efct_state[qid];
  unsigned limit = get_ubufs(vi)->nic_fifo_limit;

  while( state->free_head != -1 && state->fifo_count_hw < limit ) {
    int16_t id = state->free_head;
    const ci_qword_t* header = efct_superbuf_access(vi, qid, id);
    struct efct_rx_descriptor* desc = efct_rx_desc_for_sb(vi, qid, id);

    state->free_head = desc->sbid_next;
    desc->sbid_next = -1;

    /* We assume that the first sentinel value applies to the whole superbuf.
     * TBD: will we ever need to deal with manual rollover?
     */
    desc->sentinel = ! CI_QWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL);
    poison_superbuf((char *)header);

    if( state->fifo_count_hw == 0 )
      state->fifo_tail_hw = id;

    if( state->fifo_count_sw == 0 )
      state->fifo_tail_sw = id;

    if( state->fifo_head != -1 )
      efct_rx_desc_for_sb(vi, qid, state->fifo_head)->sbid_next = id;

    state->fifo_head = id;
    state->fifo_count_hw++;
    state->fifo_count_sw++;

    vi->efct_rxqs.ops->post(vi, qid, id, desc->sentinel);
  }
}

static int efct_ubufs_next_shared(ef_vi* vi, int qid, bool* sentinel, unsigned* sbseq)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[qid];
  ef_vi_efct_rxq_state* state = &vi->ep_state->rxq.efct_state[qid];

  ef_shrub_buffer_id id;
  int rc = ef_shrub_client_acquire_buffer(&rxq->shrub_client, &id, sentinel);
  if ( rc < 0 ) {
    return rc;
  }
  *sbseq = state->sbseq++;
  return id;
}

static int efct_ubufs_next_local(ef_vi* vi, int qid, bool* sentinel, unsigned* sbseq)
{
  ef_vi_efct_rxq_state* state = &vi->ep_state->rxq.efct_state[qid];
  struct efct_rx_descriptor* desc;
  int id;

  update_filled(vi, qid);
  post_buffers(vi, qid);

  if( state->fifo_count_sw == 0 )
    return -EAGAIN;

  id = state->fifo_tail_sw;
  desc = efct_rx_desc_for_sb(vi, qid, id);
  state->fifo_tail_sw = desc->sbid_next;
  state->fifo_count_sw--;
  *sbseq = state->sbseq++;
  *sentinel = desc->sentinel;
  return id;
}

static int efct_ubufs_next(ef_vi* vi, int qid, bool* sentinel, unsigned* sbseq)
{
  if( rxq_is_local(vi, qid) )
    return efct_ubufs_next_local(vi, qid, sentinel, sbseq);
  else
    return efct_ubufs_next_shared(vi, qid, sentinel, sbseq);
}

static void efct_ubufs_free_local(ef_vi* vi, int qid, int sbid)
{
  /* Order is important: make sure the hardware tail is advanced beyond this
   * buffer before freeing it; free it before attempting to post more. */
  update_filled(vi, qid);
  efct_rx_sb_free_push(vi, qid, sbid);
  post_buffers(vi, qid);
}

static void efct_ubufs_free_shared(ef_vi* vi, int qid, int sbid)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[qid];
  ef_shrub_client_release_buffer(&rxq->shrub_client, sbid);
}

static void efct_ubufs_free(ef_vi* vi, int qid, int sbid)
{
  if( rxq_is_local(vi, qid) )
    efct_ubufs_free_local(vi, qid, sbid);
  else
    efct_ubufs_free_shared(vi, qid, sbid);
}

static bool efct_ubufs_local_available(const ef_vi* vi, int qid)
{
  return vi->ep_state->rxq.efct_state[qid].fifo_count_sw != 0;
}

static bool efct_ubufs_shared_available(const ef_vi* vi, int qid)
{
  const struct efct_ubufs_rxq* rxq = &const_ubufs(vi)->q[qid];
  return ef_shrub_client_buffer_available(&rxq->shrub_client);
}

static bool efct_ubufs_available(const ef_vi* vi, int qid)
{
  if( rxq_is_local(vi, qid) )
    return efct_ubufs_local_available(vi, qid);
  else
    return efct_ubufs_shared_available(vi, qid);
}

#ifndef __KERNEL__
static void efct_ubufs_post_direct(ef_vi* vi, int qid, int sbid, bool sentinel)
{
  ef_addr addr = ef_memreg_dma_addr(&get_ubufs(vi)->q[qid].memreg,
                                    sbid * EFCT_RX_SUPERBUF_BYTES);
  struct efct_ubufs_rxq *rxq = &get_ubufs(vi)->q[qid];

  ci_qword_t qword;
  CI_POPULATE_QWORD_3(qword,
                      EFCT_RX_BUFFER_POST_ADDRESS, addr >> 12,
                      EFCT_RX_BUFFER_POST_SENTINEL, sentinel,
                      EFCT_RX_BUFFER_POST_ROLLOVER, 0); // TBD support for rollover?

  *rxq->rx_post_buffer_reg = qword.u64[0];
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

static int efct_ubufs_init_rxq_resource(ef_vi *vi, int qid,
                                        unsigned n_superbufs)
{
  int rc;
  ci_resource_alloc_t ra;
  unsigned n_hugepages = (n_superbufs + CI_EFCT_SUPERBUFS_PER_PAGE - 1) /
                          CI_EFCT_SUPERBUFS_PER_PAGE;

  ef_vi_init_resource_alloc(&ra, EFRM_RESOURCE_EFCT_RXQ);
  ra.u.rxq.in_abi_version = CI_EFCT_SWRXQ_ABI_VERSION;
  ra.u.rxq.in_flags = EFCH_EFCT_RXQ_FLAG_UBUF;
  ra.u.rxq.in_qid = qid;
  ra.u.rxq.in_shm_ix = -1;
  ra.u.rxq.in_vi_rs_id = efch_make_resource_id(vi->vi_resource_id);
  ra.u.rxq.in_n_hugepages = n_hugepages;
  ra.u.rxq.in_timestamp_req = true;
  rc = ci_resource_alloc(vi->dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: ci_resource_alloc rxq %d", __FUNCTION__, rc));
    return rc;
  }
  return ra.out_id.index;
}
#endif

static int efct_ubufs_local_attach(ef_vi* vi, int qid, int fd,
                                   unsigned n_superbufs)
{
#ifdef __KERNEL__
  // TODO
  BUG();
  return -EOPNOTSUPP;
#else
  int ix, rc;
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
  rxq = &ubufs->q[ix];

  rc = efct_ubufs_init_rxq_resource(vi, qid, n_superbufs);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: efct_ubufs_init_rxq_resource rxq %d", __FUNCTION__, rc));
    return rc;
  }
  rxq->resource_id = rc;
  /* FIXME SCJ cleanup on failure */

  map_bytes = CI_ROUND_UP((size_t)n_superbufs * EFCT_RX_SUPERBUF_BYTES,
                          CI_HUGEPAGE_SIZE);
  map = mmap((void*)vi->efct_rxqs.q[ix].superbuf, map_bytes,
             PROT_READ | PROT_WRITE,
             flags  | MAP_NORESERVE | MAP_HUGETLB | MAP_HUGE_2MB |
             MAP_FIXED | MAP_POPULATE,
             fd, 0);
  if( map == MAP_FAILED )
    return -errno;
  if( map != vi->efct_rxqs.q[ix].superbuf ) {
    munmap(map, map_bytes);
    return -ENOMEM;
  }

  rc = ef_memreg_alloc_flags(&rxq->memreg, vi->dh, ubufs->pd, ubufs->pd_dh,
                             map, map_bytes, 0);
  if( rc < 0 ) {
    munmap(map, map_bytes);
    return rc;
  }

  if( vi->vi_flags & EF_VI_RX_PHYS_ADDR ) {
    void *p;

    rc = ci_resource_mmap(vi->dh, rxq->resource_id, EFCH_VI_MMAP_RX_BUFFER_POST,
                          CI_ROUND_UP(sizeof(uint64_t), CI_PAGE_SIZE),
                          &p);
    if( rc < 0 ) {
      munmap(map, map_bytes);
      return rc;
    }
    rxq->rx_post_buffer_reg = (volatile uint64_t *)p;
  }

  efct_ubufs_attach_internal(vi, ix, qid, n_superbufs);
  return ix;
#endif
}

void efct_ubufs_attach_internal(ef_vi* vi, int ix, int qid, unsigned n_superbufs)
{
  unsigned id;
  struct efct_ubufs* ubufs = get_ubufs(vi);

  for( id = 0; id < n_superbufs; ++id )
    efct_rx_sb_free_push(vi, ix, id);

  ubufs->q[ix].superbuf_pkts = EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE;
  ubufs->active_qs |= 1 << ix;
  efct_vi_start_rxq(vi, ix, qid);
  post_buffers(vi, ix);
}

static int efct_ubufs_shared_attach(ef_vi* vi, int qid, int buf_fd,
                                    unsigned n_superbufs)
{
#ifdef __KERNEL__
  // TODO
  BUG();
  return -EOPNOTSUPP;
#else
  int ix;
  struct efct_ubufs* ubufs = get_ubufs(vi);
  struct efct_ubufs_rxq* rxq;
  int rc;

  EF_VI_ASSERT(qid < vi->efct_rxqs.max_qs);

  ix = efct_vi_find_free_rxq(vi, qid);
  if( ix < 0 )
    return ix;
  rxq = &ubufs->q[ix];

  rc = efct_ubufs_init_rxq_resource(vi, qid, n_superbufs);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: efct_ubufs_init_rxq_resource rxq %d", __FUNCTION__, rc));
    return rc;
  }
  rxq->resource_id = rc;
  /* FIXME SCJ cleanup on failure */

  rc = ef_shrub_client_open(&rxq->shrub_client,
                            (void*)vi->efct_rxqs.q[ix].superbuf,
                            EF_SHRUB_CONTROLLER_PATH, qid);
  if ( rc < 0 ) {
    LOG(ef_log("%s: ERROR initializing shrub client! rc=%d", __FUNCTION__, rc));
    return rc;
  }

  rxq->superbuf_pkts = rxq->shrub_client.state->metrics.buffer_bytes / EFCT_PKT_STRIDE;

  ubufs->active_qs |= 1 << ix;
  
  rc = efct_vi_sync_rxq(vi, ix, qid);
  if ( rc < 0 ) {
    LOG(ef_log("%s: ERROR syncing shrub_client to rxq! rc=%d", __FUNCTION__, rc));
    return rc;
  }
  return ix;
#endif
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
  kfree(ubufs);
#else
  int i;
  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    struct efct_ubufs_rxq* rxq = &ubufs->q[i];
    ef_memreg_free(&rxq->memreg, vi->dh);
    ci_resource_munmap(vi->dh, (void *)rxq->rx_post_buffer_reg,
                       CI_ROUND_UP(sizeof(uint64_t), CI_PAGE_SIZE));
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
    /* NOTE: we don't need to store the latest time sync event in
     * rxq->live.time_sync as efct only uses it to get the clock
     * status (set/in-sync) which ef10ct provides in RX packet
     * metadata. See efct_vi_rxpkt_get_precise_timestamp. */
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

#ifndef __KERNEL__
  if( vi->vi_flags & EF_VI_RX_PHYS_ADDR )
    ubufs->ops.post = efct_ubufs_post_direct;
  else
    ubufs->ops.post = efct_ubufs_post_kernel;
#endif

  vi->efct_rxqs.active_qs = &ubufs->active_qs;
  vi->efct_rxqs.ops = &ubufs->ops;

  return 0;
}

int efct_ubufs_init_internal(ef_vi* vi)
{
  return efct_ubufs_init(vi, NULL, 0);
}

