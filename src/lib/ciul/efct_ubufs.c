/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */

/* EFCT buffer management using user-allocated buffers */

#include "ef_vi_internal.h"
#include "logging.h"

/* TODO move CI_EFCT_MAX_SUPERBUFS somewhere more sensible, or remove
 * dependencies on it */
#include <etherfabric/internal/efct_uk_api.h>
#include <etherfabric/internal/shrub_socket.h>
#include <etherfabric/internal/shrub_client.h>

#define EF10CT_STATS_INC(vi, ix, counter) \
  do { \
    if ((vi)->vi_stats) \
      (vi)->vi_stats->ef10ct_stats[ix].counter++; \
  } while(0)

struct efct_ubufs_rxq
{
  struct ef_shrub_client shrub_client;
  efch_resource_id_t rxq_id, memreg_id;
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
  bool sentinel_wait = false;
  bool corrupt_queue_found = false;

  if( !(vi->ep_state->rxq.efct_active_qs & (1 << ix)) ||
      state->fifo_tail_hw == -1 ) {
    EF10CT_STATS_INC(vi, ix, torn_down_out_of_order);
    return;
  }

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
    if( state->fifo_tail_hw == -1 ) {
      corrupt_queue_found = true;
      break;
    }

    desc = efct_rx_desc_for_sb(vi, ix, state->fifo_tail_hw);
    buffer = efct_superbuf_access(vi, ix, state->fifo_tail_hw);
    header = (const ci_qword_t*)(buffer + EFCT_RX_SUPERBUF_BYTES - EFCT_PKT_STRIDE);

    if( CI_QWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL) != desc->sentinel ) {
      sentinel_wait = true;
      break;
    }

    state->fifo_tail_hw = desc->sbid_next;
    state->fifo_count_hw--;
  }

  if ( corrupt_queue_found )
    EF10CT_STATS_INC(vi, ix, corrupt_rxq_state);
  if ( sentinel_wait )
    EF10CT_STATS_INC(vi, ix, sentinel_wait);
  if ( state->fifo_count_hw == 0 )
    EF10CT_STATS_INC(vi, ix, hw_fifo_empty);
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
  bool free_list_was_empty = ( state->free_head == -1 );
  bool fifo_was_full = ( state->fifo_count_hw >= limit );

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

  if ( free_list_was_empty )
    EF10CT_STATS_INC(vi, ix, free_list_empty);
  if ( fifo_was_full )
    EF10CT_STATS_INC(vi, ix, post_fifo_full);
}

static int efct_ubufs_next_shared(ef_vi* vi, int ix, bool* sentinel,
                                  unsigned* sbseq)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[ix];
  uint32_t buffer_index;
  uint32_t shrub_sbseq;

  int rc = ef_shrub_client_acquire_buffer(&rxq->shrub_client, &buffer_index,
                                          sentinel, &shrub_sbseq);
  if ( rc < 0 ) {
    EF10CT_STATS_INC(vi, ix, acquire_failures);
    return rc;
  }
  *sbseq = shrub_sbseq;
  return buffer_index;
}

static int efct_ubufs_next_local(ef_vi* vi, int ix, bool* sentinel, unsigned* sbseq)
{
  ef_vi_efct_rxq_state* state = &vi->ep_state->rxq.efct_state[ix];
  struct efct_rx_descriptor* desc;
  int id;

  update_filled(vi, ix);
  post_buffers(vi, ix);

  if( state->fifo_count_sw == 0 ) {
    EF10CT_STATS_INC(vi, ix, sw_fifo_empty);
    return -EAGAIN;
  }

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
  EF10CT_STATS_INC(vi, ix, release_count);
}

static void efct_ubufs_free(ef_vi* vi, int ix, int sbid)
{
  if( rxq_is_local(vi, ix) )
    efct_ubufs_free_local(vi, ix, sbid);
  else
    efct_ubufs_free_shared(vi, ix, sbid);

  EF10CT_STATS_INC(vi, ix, buffers_freed);
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

static void efct_ubufs_post_direct(ef_vi* vi, int ix, int sbid, bool sentinel)
{
  ef_addr addr = efct_rx_desc_for_sb(vi, ix, sbid)->dma_addr;

  ci_qword_t qword;
  CI_POPULATE_QWORD_3(qword,
                      EFCT_RX_BUFFER_POST_ADDRESS, addr >> 12,
                      EFCT_RX_BUFFER_POST_SENTINEL, sentinel,
                      EFCT_RX_BUFFER_POST_ROLLOVER, 0); // TBD support for rollover?

  *get_ubufs(vi)->q[ix].rx_post_buffer_reg = qword.u64[0];
}

volatile uint64_t* efct_ubufs_get_rxq_io_window(ef_vi* vi, int ix)
{
  return get_ubufs(vi)->q[ix].rx_post_buffer_reg;
}

void efct_ubufs_set_rxq_io_window(ef_vi* vi, int ix, volatile uint64_t* p)
{
  get_ubufs(vi)->q[ix].rx_post_buffer_reg = p;
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

    rc = efct_ubufs_set_shared_rxq_token(vi, response.shared_rxq_token);
    if( rc == 0 )
      ubufs->is_shrub_token_set = true;
  }

  return rc;
}

static int efct_ubufs_attach(ef_vi* vi,
                             int qid,
                             int fd,
                             unsigned n_superbufs,
                             bool shared_mode,
                             bool interrupt_mode)
{
  int ix, rc;
  struct efct_ubufs* ubufs = get_ubufs(vi);
  struct efct_ubufs_rxq* rxq;

  if( n_superbufs > CI_EFCT_MAX_SUPERBUFS )
    return -EINVAL;

  ix = efct_vi_find_free_rxq(vi, qid);
  if( ix < 0 )
    return ix;
  rxq = &ubufs->q[ix];

  rc = efct_ubufs_init_rxq_resource(vi, qid, n_superbufs, interrupt_mode,
                                    &rxq->rxq_id);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: efct_ubufs_init_rxq_resource %d", __FUNCTION__, rc));
    return rc;
  }

  if( shared_mode ) {
    void* superbufs = (void*)efct_superbuf_access(vi, ix, 0);
    rc = efct_ubufs_shared_attach_internal(vi, ix, qid, superbufs);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: efct_ubufs_shared_attach_internal %d", __FUNCTION__, rc));
      goto fail;
    }
  }
  else {
    rc = efct_ubufs_init_rxq_buffers(vi, ix, fd, n_superbufs,
                                     rxq->rxq_id, ubufs->pd, ubufs->pd_dh,
                                     &rxq->memreg_id, &rxq->rx_post_buffer_reg);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: efct_ubufs_init_rxq_buffers %d", __FUNCTION__, rc));
      goto fail;
    }

    efct_ubufs_local_attach_internal(vi, ix, qid, n_superbufs);
  }

  return ix;

fail:
  efct_ubufs_free_resource(vi, rxq->rxq_id);
  return rc;
}

static void efct_ubufs_detach(ef_vi* vi, int ix)
{
  struct efct_ubufs_rxq* rxq = &get_ubufs(vi)->q[ix];
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  ef_vi_efct_rxq_state* eqs = &qs->efct_state[ix];

  qs->efct_active_qs &= ~(1u << ix);

  memset(eqs, 0, sizeof(*eqs));
  eqs->free_head = eqs->fifo_head = -1;
  eqs->fifo_tail_hw = eqs->fifo_tail_sw = -1;
  eqs->qid = -1;

  if( rxq_is_local(vi, ix) )
    efct_ubufs_free_rxq_buffers(vi, ix, rxq->rx_post_buffer_reg);
  else
    ef_shrub_client_close(&rxq->shrub_client);

  efct_ubufs_free_resource(vi, rxq->rxq_id);
  efct_ubufs_free_resource(vi, rxq->memreg_id);
  rxq->rxq_id = rxq->memreg_id = efch_resource_id_none();
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
  struct efct_ubufs* ubufs = get_ubufs(vi);

  efct_superbufs_cleanup(vi);
  efct_ubufs_free_mem(ubufs);
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

      if ( vi->vi_stats != NULL ) {
        logger(log_arg, "  rxq[%d]: buffers freed=%" CI_PRIu64
               " torn_down_out_of_order=%" CI_PRIu64 " corrupt_rxq_state=%" CI_PRIu64,
               ix, vi->vi_stats->ef10ct_stats[ix].buffers_freed,
               vi->vi_stats->ef10ct_stats[ix].torn_down_out_of_order,
               vi->vi_stats->ef10ct_stats[ix].corrupt_rxq_state);

        logger(log_arg, "  rxq[%d]: sw_fifo_empty=%" CI_PRIu64 
               " hw_fifo_empty=%" CI_PRIu64 " free_list_empty=%" CI_PRIu64, ix,
               vi->vi_stats->ef10ct_stats[ix].sw_fifo_empty,
               vi->vi_stats->ef10ct_stats[ix].hw_fifo_empty,
               vi->vi_stats->ef10ct_stats[ix].free_list_empty);

        logger(log_arg, "  rxq[%d]: sentinel_wait=%" CI_PRIu64
               " post_fifo_full=%" CI_PRIu64, ix,
               vi->vi_stats->ef10ct_stats[ix].sentinel_wait,
               vi->vi_stats->ef10ct_stats[ix].post_fifo_full);
      }

      if( client_state ) {
        logger(log_arg, "  rxq[%d]: server_fifo_size=%" CI_PRIu64
               " server_fifo_idx=%" CI_PRIu64, ix,
               client_state->metrics.server_fifo_size,
               client_state->server_fifo_index);
        logger(log_arg, "  rxq[%d]: client_fifo_size=%" CI_PRIu64
               " client_fifo_idx=%" CI_PRIu64, ix,
               client_state->metrics.client_fifo_size,
               client_state->client_fifo_index);
        if ( vi->vi_stats != NULL ) {
          logger(log_arg, "  rxq[%d]: acquire_failures=%" CI_PRIu64 
                 " release_count=%" CI_PRIu64, ix,
                 vi->vi_stats->ef10ct_stats[ix].acquire_failures,
                 vi->vi_stats->ef10ct_stats[ix].release_count);
        }
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

  ubufs = efct_ubufs_alloc_mem(sizeof(*ubufs));
  if( ubufs == NULL ) {
    efct_superbufs_cleanup(vi);
    return -ENOMEM;
  }

  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    struct efct_ubufs_rxq* rxq = &ubufs->q[i];
    ef_vi_efct_rxq* efct_rxq = &vi->efct_rxqs.q[i];
    ef_vi_efct_rxq_state* efct_state = efct_get_rxq_state(vi, i);

    rxq->rxq_id = rxq->memreg_id = efch_resource_id_none();
    efct_rxq->live.superbuf_pkts = &efct_state->superbuf_pkts;
    efct_rxq->live.config_generation = &efct_state->config_generation;
#ifndef __KERNEL__
    efct_rxq->mappings = ubufs->q[i].shrub_client.mappings;
#endif
    /* NOTE: we don't need to store the latest time sync event in
     * rxq->live.time_sync as efct only uses it to get the clock
     * status (set/in-sync) which ef10ct provides in RX packet
     * metadata. See efct_vi_rxpkt_get_precise_timestamp. */
  }

  /* TODO ON-16686 get this limit from the design parameter DP_RX_BUFFER_FIFO_SIZE,
   * perhaps allow configuration to a smaller value to reduce working set.
   * The current value here is selected such that completions for a full
   * set of buffers will not exceed the kernel EVQ size. Overflow is still
   * possible if the kernel poll does not keep up as the user space code
   * judges fill level based on RX buffer fill, so the hw fifo can be empty
   * without the kernel EVQ having been drained. */
  ubufs->nic_fifo_limit = 64;
  ubufs->pd = pd;
  ubufs->pd_dh = pd_dh;
  ubufs->is_shrub_token_set = false;
  ubufs->shrub_controller_id = EF_SHRUB_NO_SHRUB;
  ubufs->shrub_server_socket_id = -1;

  ubufs->ops.free = efct_ubufs_free;
  ubufs->ops.next = efct_ubufs_next;
  ubufs->ops.available = efct_ubufs_available;
  ubufs->ops.pre_attach = efct_ubufs_pre_attach;
  ubufs->ops.attach = efct_ubufs_attach;
  ubufs->ops.detach = efct_ubufs_detach;
  ubufs->ops.refresh = efct_ubufs_refresh;
  ubufs->ops.refresh_mappings = efct_ubufs_refresh_mappings;
  ubufs->ops.prime = efct_ubufs_prime;
  ubufs->ops.cleanup = efct_ubufs_cleanup;
  ubufs->ops.dump_stats = efct_ubufs_dump_stats;
  ubufs->ops.post = efct_ubufs_post_direct;

#ifndef __KERNEL__
  if( ! (vi->vi_flags & EF_VI_RX_PHYS_ADDR) )
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
