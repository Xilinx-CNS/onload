/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */

/* EFCT buffer management using user-allocated buffers */

#include <etherfabric/memreg.h>
#include "ef_vi_internal.h"
#include "shrub_client.h"
#include "shrub_socket.h"
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
  unsigned nic_fifo_limit;
  ef_pd* pd;
  int shrub_controller_id;
  int shrub_server_socket_id;
  ef_driver_handle pd_dh;
  bool is_shrub_token_set;

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

static bool rxq_is_local(const ef_vi* vi, int ix)
{
  return const_ubufs(vi)->q[ix].shrub_client.mappings[0] == 0;
}

static void update_filled(ef_vi* vi, int ix)
{
  ef_vi_efct_rxq_state* state = &vi->ep_state->rxq.efct_state[ix];

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
    desc = efct_rx_desc_for_sb(vi, ix, state->fifo_tail_hw);
    buffer = efct_superbuf_access(vi, ix, state->fifo_tail_hw);
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

static void post_buffers(ef_vi* vi, int ix)
{
  ef_vi_efct_rxq_state* state = &vi->ep_state->rxq.efct_state[ix];
  unsigned limit = get_ubufs(vi)->nic_fifo_limit;

  while( state->free_head != -1 && state->fifo_count_hw < limit ) {
    int16_t id = state->free_head;
    const ci_qword_t* header = efct_superbuf_access(vi, ix, id);
    struct efct_rx_descriptor* desc = efct_rx_desc_for_sb(vi, ix, id);

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
      efct_rx_desc_for_sb(vi, ix, state->fifo_head)->sbid_next = id;

    state->fifo_head = id;
    state->fifo_count_hw++;
    state->fifo_count_sw++;

    vi->efct_rxqs.ops->post(vi, ix, id, desc->sentinel);
  }
}

static int efct_ubufs_next_shared(ef_vi* vi, int ix, bool* sentinel, unsigned* sbseq)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[ix];
  ef_vi_efct_rxq_state* state = &vi->ep_state->rxq.efct_state[ix];

  ef_shrub_buffer_id id;
  int rc = ef_shrub_client_acquire_buffer(&rxq->shrub_client, &id, sentinel);
  if ( rc < 0 ) {
    return rc;
  }
  *sbseq = state->sbseq++;
  return id;
}

static int efct_ubufs_next_local(ef_vi* vi, int ix, bool* sentinel, unsigned* sbseq)
{
  ef_vi_efct_rxq_state* state = &vi->ep_state->rxq.efct_state[ix];
  struct efct_rx_descriptor* desc;
  int id;

  update_filled(vi, ix);
  post_buffers(vi, ix);

  if( state->fifo_count_sw == 0 )
    return -EAGAIN;

  id = state->fifo_tail_sw;
  desc = efct_rx_desc_for_sb(vi, ix, id);
  state->fifo_tail_sw = desc->sbid_next;
  state->fifo_count_sw--;
  *sbseq = state->sbseq++;
  *sentinel = desc->sentinel;
  return id;
}

static int efct_ubufs_next(ef_vi* vi, int ix, bool* sentinel, unsigned* sbseq)
{
  if( rxq_is_local(vi, ix) )
    return efct_ubufs_next_local(vi, ix, sentinel, sbseq);
  else
    return efct_ubufs_next_shared(vi, ix, sentinel, sbseq);
}

static void efct_ubufs_free_local(ef_vi* vi, int ix, int sbid)
{
  /* Order is important: make sure the hardware tail is advanced beyond this
   * buffer before freeing it; free it before attempting to post more. */
  update_filled(vi, ix);
  efct_rx_sb_free_push(vi, ix, sbid);
  post_buffers(vi, ix);
}

static void efct_ubufs_free_shared(ef_vi* vi, int ix, int sbid)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[ix];
  ef_shrub_client_release_buffer(&rxq->shrub_client, sbid);
}

static void efct_ubufs_free(ef_vi* vi, int ix, int sbid)
{
  if( rxq_is_local(vi, ix) )
    efct_ubufs_free_local(vi, ix, sbid);
  else
    efct_ubufs_free_shared(vi, ix, sbid);
}

static bool efct_ubufs_local_available(const ef_vi* vi, int ix)
{
  return vi->ep_state->rxq.efct_state[ix].fifo_count_sw != 0;
}

static bool efct_ubufs_shared_available(const ef_vi* vi, int ix)
{
  const struct efct_ubufs_rxq* rxq = &const_ubufs(vi)->q[ix];
  return ef_shrub_client_buffer_available(&rxq->shrub_client);
}

static bool efct_ubufs_available(const ef_vi* vi, int ix)
{
  if( rxq_is_local(vi, ix) )
    return efct_ubufs_local_available(vi, ix);
  else
    return efct_ubufs_shared_available(vi, ix);
}

#ifndef __KERNEL__
static void efct_ubufs_post_direct(ef_vi* vi, int ix, int sbid, bool sentinel)
{
  ef_addr addr = ef_memreg_dma_addr(&get_ubufs(vi)->q[ix].memreg,
                                    sbid * EFCT_RX_SUPERBUF_BYTES);
  struct efct_ubufs_rxq *rxq = &get_ubufs(vi)->q[ix];

  ci_qword_t qword;
  CI_POPULATE_QWORD_3(qword,
                      EFCT_RX_BUFFER_POST_ADDRESS, addr >> 12,
                      EFCT_RX_BUFFER_POST_SENTINEL, sentinel,
                      EFCT_RX_BUFFER_POST_ROLLOVER, 0); // TBD support for rollover?

  *rxq->rx_post_buffer_reg = qword.u64[0];
}

static void efct_ubufs_post_kernel(ef_vi* vi, int ix, int sbid, bool sentinel)
{
  ef_addr addr = ef_memreg_dma_addr(&get_ubufs(vi)->q[ix].memreg,
                                    sbid * EFCT_RX_SUPERBUF_BYTES);

  ci_resource_op_t op = {};

  op.op = CI_RSOP_RX_BUFFER_POST;
  op.id = efch_make_resource_id(vi->vi_resource_id);
  op.u.buffer_post.qid = efct_get_rxq_state(vi, ix)->qid;
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

volatile uint64_t* efct_ubufs_get_rxq_io_window(ef_vi* vi, int ix)
{
  return get_ubufs(vi)->q[ix].rx_post_buffer_reg;
}

void efct_ubufs_set_rxq_io_window(ef_vi* vi, int ix, volatile uint64_t* p)
{
  get_ubufs(vi)->q[ix].rx_post_buffer_reg = p;
}

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
    LOG(ef_log("%s: Unable to alloc buffers (%d). Are sufficient hugepages available?",
               __FUNCTION__, rc));
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

  efct_ubufs_local_attach_internal(vi, ix, qid, n_superbufs);
  return ix;
#endif
}

void efct_ubufs_local_attach_internal(ef_vi* vi, int ix, int qid, unsigned n_superbufs)
{
  unsigned id;
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;

  for( id = 0; id < n_superbufs; ++id )
    efct_rx_sb_free_push(vi, ix, id);

  qs->efct_state[ix].config_generation = 1; /* force an initial refresh */
  qs->efct_state[ix].superbuf_pkts = EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE;
  qs->efct_active_qs |= 1 << ix;
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
  int rc;

  EF_VI_ASSERT(qid < vi->efct_rxqs.max_qs);

  ix = efct_vi_find_free_rxq(vi, qid);
  if( ix < 0 )
    return ix;

  rc = efct_ubufs_init_rxq_resource(vi, qid, n_superbufs);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: efct_ubufs_init_rxq_resource rxq %d", __FUNCTION__, rc));
    return rc;
  }
  get_ubufs(vi)->q[ix].resource_id = rc;
  /* FIXME SCJ cleanup on failure */

  return efct_ubufs_shared_attach_internal(vi, ix, qid,
                                           (void*)vi->efct_rxqs.q[ix].superbuf);
#endif
}

int efct_ubufs_shared_attach_internal(ef_vi* vi, int ix, int qid, void* superbuf)
{
  int rc;
  struct ef_shrub_client* client = &get_ubufs(vi)->q[ix].shrub_client;
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  struct efct_ubufs*     ubufs;

  char attach_path[EF_SHRUB_SERVER_SOCKET_LEN];
  ubufs = get_ubufs(vi);

  EF_VI_ASSERT(ubufs->shrub_controller_id >= 0);
  EF_VI_ASSERT(ubufs->shrub_server_socket_id >= 0);

  memset(attach_path, 0, sizeof(attach_path));
  rc = snprintf(attach_path, sizeof(attach_path),
                EF_SHRUB_CONTROLLER_PATH_FORMAT EF_SHRUB_SHRUB_FORMAT,
                EF_SHRUB_SOCK_DIR_PATH, ubufs->shrub_controller_id,
                ubufs->shrub_server_socket_id);
  if ( rc < 0 || rc >= sizeof(attach_path) )
    return -EINVAL;

  attach_path[sizeof(attach_path) - 1] = '\0';

  rc = ef_shrub_client_open(client, superbuf, attach_path, qid);
  if ( rc < 0 ) {
    LOG(ef_log("%s: ERROR initializing shrub client! rc=%d", __FUNCTION__, rc));
    return rc;
  }

  qs->efct_state[ix].config_generation = 1; /* force an initial refresh */
  qs->efct_state[ix].superbuf_pkts =
    ef_shrub_client_get_state(client)->metrics.buffer_bytes / EFCT_PKT_STRIDE;
  qs->efct_active_qs |= 1 << ix;

  rc = efct_vi_sync_rxq(vi, ix, qid);
  if ( rc < 0 ) {
    LOG(ef_log("%s: ERROR syncing shrub_client to rxq! rc=%d", __FUNCTION__,
               rc));
    return rc;
  }
  return ix;
}

static int efct_ubufs_pre_attach(ef_vi* vi, bool shared_mode)
{
#ifdef __KERNEL__
  BUG();
  return -EOPNOTSUPP;
#else
  struct ef_shrub_token_response response;
  struct efct_ubufs *ubufs;
  char attach_path[EF_SHRUB_SERVER_SOCKET_LEN];
  int rc = 0;

  if( !shared_mode )
    return 0;

  ubufs = get_ubufs(vi);
  if( !ubufs->is_shrub_token_set ) {
    memset(attach_path, 0, sizeof(attach_path));
    rc = snprintf(attach_path, sizeof(attach_path),
                  EF_SHRUB_CONTROLLER_PATH_FORMAT EF_SHRUB_SHRUB_FORMAT,
                  EF_SHRUB_SOCK_DIR_PATH, ubufs->shrub_controller_id,
                  ubufs->shrub_server_socket_id);
    if ( rc < 0 || rc >= sizeof(attach_path) )
      return -EINVAL;
    attach_path[sizeof(attach_path) - 1] = '\0';

    rc = ef_shrub_client_request_token(attach_path, &response);
    if( rc )
      return rc;

    ci_resource_op_t op = {};
    op.op = CI_RSOP_SHARED_RXQ_TOKEN_SET;
    op.id = efch_make_resource_id(vi->vi_resource_id);
    op.u.shared_rxq_tok_set.token = response.shared_rxq_token;
    rc = ci_resource_op(vi->dh, &op);
    if( !rc )
      ubufs->is_shrub_token_set = true;
  }

  return rc;
#endif /* __KERNEL__ */
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

static int efct_ubufs_refresh(ef_vi* vi, int ix)
{
  /* Nothing to do */
  return 0;
}

static int efct_ubufs_refresh_mappings(ef_vi* vi, int ix,
                                       uint64_t user_superbuf,
                                       uint64_t* user_mappings)
{
  return ef_shrub_client_refresh_mappings(&get_ubufs(vi)->q[ix].shrub_client,
                                          user_superbuf, user_mappings);
}

static void efct_ubufs_cleanup(ef_vi* vi)
{
  int i;
  struct efct_ubufs* ubufs = get_ubufs(vi);

  efct_superbufs_cleanup(vi);
  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    struct efct_ubufs_rxq* rxq = &ubufs->q[i];
    if( ! rxq_is_local(vi, i) )
      ef_shrub_client_close(&rxq->shrub_client);
#ifndef __KERNEL__
    ef_memreg_free(&rxq->memreg, vi->dh);
    ci_resource_munmap(vi->dh, (void *)rxq->rx_post_buffer_reg,
                       CI_ROUND_UP(sizeof(uint64_t), CI_PAGE_SIZE));
#endif
  }

#ifdef __KERNEL__
  kfree(ubufs);
#else
  free(ubufs);
#endif
}

static void efct_ubufs_dump_stats(ef_vi* vi, ef_vi_dump_log_fn_t logger,
                                  void* log_arg)
{
  const struct efct_ubufs* ubufs = const_ubufs(vi);
  int ix;

  for( ix = 0; ix < vi->efct_rxqs.max_qs; ++ix ) {
    const struct ef_shrub_client* client = &ubufs->q[ix].shrub_client;
    const struct ef_shrub_client_state* client_state = ef_shrub_client_get_state(client);
    const ef_vi_efct_rxq* efct_rxq = &vi->efct_rxqs.q[ix];
    const ef_vi_efct_rxq_state *efct_state = efct_get_rxq_state(vi, ix);

    if( *efct_rxq->live.superbuf_pkts != 0 ) {
      logger(log_arg, "  rxq[%d]: hw=%d cfg=%u pkts=%u", ix,
             efct_state->qid, efct_rxq->config_generation,
             *efct_rxq->live.superbuf_pkts);
      if( client_state ) {
        logger(log_arg, "  rxq[%d]: server_fifo_size=%" CI_PRIu64
               " server_fifo_idx=%" CI_PRIu64, ix,
               client_state->metrics.server_fifo_size,
               client_state->server_fifo_index);
        logger(log_arg, "  rxq[%d]: client_fifo_size=%" CI_PRIu64
               " client_fifo_idx=%" CI_PRIu64, ix,
               client_state->metrics.client_fifo_size,
               client_state->client_fifo_index);
      } else {
        logger(log_arg, "  rxq[%d]: fifo_count_hw=%" CI_PRIu16
               " fifo_count_sw=%" CI_PRIu16, ix, efct_state->fifo_count_hw,
               efct_state->fifo_count_sw);
      }
    }
  }
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
    ef_vi_efct_rxq_state* efct_state = efct_get_rxq_state(vi, i);

    rxq->live.superbuf_pkts = &efct_state->superbuf_pkts;
    rxq->live.config_generation = &efct_state->config_generation;
#ifndef __KERNEL__
    rxq->mappings = ubufs->q[i].shrub_client.mappings;
#endif
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
  ubufs->is_shrub_token_set = false;
  ubufs->shrub_controller_id = -1;
  ubufs->shrub_server_socket_id = -1;

  ubufs->ops.free = efct_ubufs_free;
  ubufs->ops.next = efct_ubufs_next;
  ubufs->ops.available = efct_ubufs_available;
  ubufs->ops.pre_attach = efct_ubufs_pre_attach;
  ubufs->ops.attach = efct_ubufs_attach;
  ubufs->ops.refresh = efct_ubufs_refresh;
  ubufs->ops.refresh_mappings = efct_ubufs_refresh_mappings;
  ubufs->ops.prime = efct_ubufs_prime;
  ubufs->ops.cleanup = efct_ubufs_cleanup;
  ubufs->ops.dump_stats = efct_ubufs_dump_stats;

#ifndef __KERNEL__
  if( vi->vi_flags & EF_VI_RX_PHYS_ADDR )
    ubufs->ops.post = efct_ubufs_post_direct;
  else
    ubufs->ops.post = efct_ubufs_post_kernel;
#endif

  vi->efct_rxqs.active_qs = &vi->ep_state->rxq.efct_active_qs;
  vi->efct_rxqs.ops = &ubufs->ops;

  return 0;
}

int efct_ubufs_init_internal(ef_vi* vi)
{
  return efct_ubufs_init(vi, NULL, 0);
}

int efct_ubufs_set_shared(ef_vi* vi, int shrub_controller_id, int shrub_server_socket_id)
{
  struct efct_ubufs* ubufs;
  ubufs = get_ubufs(vi);
  ubufs->shrub_controller_id = shrub_controller_id;
  ubufs->shrub_server_socket_id = shrub_server_socket_id;
  return 0;
}
