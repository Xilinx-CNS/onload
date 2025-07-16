/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */

/* Functions under test */
#include <etherfabric/ef_vi.h>
#include <etherfabric/efct_vi.h>

#include <etherfabric/vi.h>
#include <ci/efhw/common.h>
#include "ef_vi_internal.h"

/* Needed for CI_EFCT_MAX_SUPERBUFS an EFCT_RX_SUPERBUF_BYTES.
 * TODO decouple superbuf memory layout from hardware/kernel interfaces */
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/driver/efab/hardware/efct.h>

/* Test infrastructure */
#include "unit_test.h"

/* Default rx metadata values */
static uint64_t rx_len = 42;
static uint64_t rx_flt = 7;
static uint16_t PKTS_PER_SB = EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE;

/* Arbitrary TX values */
#define TX_LEN (EFCT_TX_ALIGNMENT - EFCT_TX_HEADER_BYTES)
static char tx_buf[TX_LEN];
static struct iovec tx_iov = { tx_buf, TX_LEN };
static const int tx_qid = 0;

/* The last event overwritten in the TX EVQ for rollback purposes */
static ci_qword_t last_evq_event = { 0 };

/* Dependencies */
static int test_filter_is_block_only;
int ef_vi_filter_is_block_only(const struct ef_filter_cookie* cookie)
{
  return test_filter_is_block_only;
}

/* Mock implementation of queue/buffer management */
struct efct_mock_rxq {
  uint32_t superbuf_pkts;
  unsigned config_generation;
  uint64_t time_sync;
  bool shared_mode;

  int* shared_sbids;
  int shared_index;
  int shared_size;
  int shared_sbid_to_free;

  bool* shared_sentinels;

  /* The below are used for local rxq*/
  int next_sbid;
  bool next_sentinel;
  int next_seq;

  char* next_pkt;
  char* next_meta;
  char* superbuf;
  char* superbuf_end;
};

struct efct_mock_ops {
  ef_vi_efct_rxq_ops ops;
  struct efct_mock_rxqs* rxqs;

  int anything_called;

  int available_called;
  int available_qid;

  int next_called;
  int next_qid;

  int free_called;
  int free_qid;
  int free_sbid;

  int attach_called;
  int attach_qid;
  int attach_superbufs;

  int refresh_called;
  int refresh_qid;
};

struct efct_mock_rxqs {
  uint64_t active_qs;
  struct efct_mock_rxq* q;
  char* superbuf;
  int q_max;
};

struct efct_test {
  /* Check any changes to these */
  ef_vi* vi;
  struct efct_mock_ops* mock_ops;

  /* Don't explicitly check changes to internal state */
  ef_vi_state ep_state;
  struct efct_mock_rxqs mock_rxqs;
  uint32_t evq_write_ptr;
  unsigned tx_completions;
};

static int meta_offset;

/* Mock implementations of rxq operations */
static struct efct_mock_ops* mock_ops(ef_vi* vi)
{
  return CI_CONTAINER(struct efct_mock_ops, ops, vi->efct_rxqs.ops);
}

static int peek_sbid(struct efct_mock_rxq* q) {
  if ( q->shared_mode ) {
    if ( q->shared_index >= q->shared_size )
      return -EAGAIN;
    return q->shared_sbids[q->shared_index];
  }
  return q->next_sbid;
}

static int get_sbid(struct efct_mock_rxq* q) {
  int curr_active_sbid = peek_sbid(q);
  if ( q->shared_mode ) {
    q->shared_sbid_to_free = curr_active_sbid;
    q->shared_index++;
  }
  return curr_active_sbid;
}

static int peek_sentinel(struct efct_mock_rxq* q, int sbid) {
  if ( q->shared_mode ) {
    if ( sbid >= q->shared_size )
      return !q->shared_sentinels[q->shared_size - 1];
    return q->shared_sentinels[sbid];
  }
  return q->next_sentinel;
}

static void init_shared_state(struct efct_mock_rxq* q, int sbid_size) {
  q->shared_size = sbid_size;
  q->shared_sbids = calloc(sbid_size, sizeof(int));
  assert(q->shared_sbids != NULL);
  q->shared_index = 0;
  q->shared_sentinels = calloc(sbid_size, sizeof(bool));
  assert(q->shared_sentinels != NULL);
  int i;
  for (i = 0; i < sbid_size; i++)
    q->shared_sentinels[i] = (i % 2 != 0);
}

static bool efct_mock_available(const ef_vi* vi, int qid)
{
  struct efct_mock_ops* ops = mock_ops((ef_vi*)vi);

  ops->anything_called += 1;
  ops->available_called += 1;
  ops->available_qid = qid;

  return peek_sbid(&ops->rxqs->q[qid]) >= 0;
}

static int efct_mock_next(ef_vi* vi, int qid, bool* sentinel, unsigned* seq)
{
  struct efct_mock_ops* ops = mock_ops(vi);
  struct efct_mock_rxq* rxq = &ops->rxqs->q[qid];
  int sbid = get_sbid(rxq);

  char* p;

  ops->anything_called += 1;
  ops->next_called += 1;
  ops->next_qid = qid;

  if( sbid >= 0 ) {
    *sentinel = peek_sentinel(rxq, sbid);
    *seq = rxq->next_seq++;

    rxq->superbuf = ops->rxqs->superbuf +
      (size_t)(qid * CI_EFCT_MAX_SUPERBUFS + sbid) * EFCT_RX_SUPERBUF_BYTES;
    rxq->superbuf_end = rxq->superbuf + EFCT_RX_SUPERBUF_BYTES;

    for( p = rxq->superbuf; p < rxq->superbuf_end; p += EFCT_PKT_STRIDE ) {
      uint64_t* poison = (uint64_t*)(p + EFCT_RX_HEADER_NEXT_FRAME_LOC_1 - 2);
      *poison = CI_EFCT_DEFAULT_POISON;
    }

    if( rxq->next_pkt ) {
      /* Natural rollover */
      rxq->next_meta = rxq->superbuf;
    }
    else {
      /* First buffer or forced rollover */
      rxq->next_pkt = rxq->superbuf + EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
      rxq->next_meta = rxq->superbuf + EFCT_PKT_STRIDE * meta_offset;
    }
  }
  return sbid;
}

static void efct_mock_free(ef_vi* vi, int qid, int sbid)
{
  struct efct_mock_ops* ops = mock_ops(vi);
  CHECK(sbid, >=, 0);
  CHECK(qid, >=, 0);
  ops->anything_called += 1;
  ops->free_called += 1;
  ops->free_qid = qid;
  ops->free_sbid = sbid;

  if ( ops->rxqs->q[qid].shared_mode )
    STATE_CHECK(ops, free_sbid, ops->rxqs->q[qid].shared_sbid_to_free);
}

static int efct_mock_attach(ef_vi* vi, int qid, int buf_fd, unsigned n_superbufs, bool shared_mode)
{
  struct efct_mock_ops* ops = mock_ops(vi);

  ops->anything_called += 1;
  ops->attach_called += 1;
  ops->attach_qid = qid; /* TODO should distinguish "hardware" id from index */
  ops->attach_superbufs = n_superbufs;

  if( qid < 0 || qid >= ops->rxqs->q_max )
    return -EINVAL;
  if( !shared_mode && ops->rxqs->active_qs & (1 << qid) )
    return -EALREADY;

  ops->rxqs->active_qs |= (1 << qid);
  ops->rxqs->q[qid].superbuf_pkts = EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE;
  
  if ( !shared_mode )
    ops->rxqs->q[qid].next_sbid = -EAGAIN;

  if ( shared_mode ) {
    efct_vi_sync_rxq(vi, qid, qid);
  } else {
    efct_vi_start_rxq(vi, qid, qid);
  }
  return 0;
}

static int efct_mock_refresh(ef_vi* vi, int qid)
{
  struct efct_mock_ops* ops = mock_ops(vi);
  ops->anything_called += 1;
  ops->refresh_called += 1;
  ops->refresh_qid = qid;
  return 0;
}

static int efct_mock_prime(ef_vi* vi, ef_driver_handle dh)
{
  struct efct_mock_ops* ops = mock_ops(vi);
  ops->anything_called += 1;

  /* This is not called from within efct_vi so nothing to test */
  return -EOPNOTSUPP;
}

static void efct_mock_cleanup(ef_vi* vi)
{
  struct efct_mock_ops* ops = mock_ops(vi);
  ops->anything_called += 1;

  /* This is not called from within efct_vi so nothing to test */
}


/* Helper functions */
static struct efct_test* efct_test_init_test(int q_max, int arch, int nic_flags)
{
  int i;

  struct efct_test* t = calloc(1, sizeof(*t));
  assert(t != NULL);

  STATE_ALLOC(ef_vi, vi);
  STATE_ALLOC(struct efct_mock_ops, mock_ops);

  vi->ep_state = &t->ep_state;
  vi->nic_type.arch = arch;
  vi->nic_type.nic_flags = nic_flags;
  efct_vi_init(vi);

  mock_ops->rxqs = &t->mock_rxqs;
  mock_ops->ops.available = efct_mock_available;
  mock_ops->ops.next = efct_mock_next;
  mock_ops->ops.free = efct_mock_free;
  mock_ops->ops.attach = efct_mock_attach;
  mock_ops->ops.refresh = efct_mock_refresh;
  mock_ops->ops.prime = efct_mock_prime;
  mock_ops->ops.cleanup = efct_mock_cleanup;

  t->mock_rxqs.q_max = q_max;
  t->mock_rxqs.q = calloc(q_max, sizeof(struct efct_mock_rxq));
  assert(t->mock_rxqs.q != NULL);
  t->mock_rxqs.superbuf = calloc(q_max, (size_t)CI_EFCT_MAX_SUPERBUFS * EFCT_RX_SUPERBUF_BYTES);
  assert(t->mock_rxqs.superbuf != NULL);

  vi->efct_rxqs.ops = &mock_ops->ops;
  vi->efct_rxqs.active_qs = &t->mock_rxqs.active_qs;
  vi->efct_rxqs.active_qs = &t->mock_rxqs.active_qs;

  for( i = 0; i < q_max; ++i ) {
    ef_vi_efct_rxq* q = &vi->efct_rxqs.q[i];
    efct_get_rxq_state(vi, i)->qid = i;
    q->live.superbuf_pkts = &t->mock_rxqs.q[i].superbuf_pkts;
    q->live.config_generation = &t->mock_rxqs.q[i].config_generation;
    q->live.time_sync = &t->mock_rxqs.q[i].time_sync;
    q->superbuf = t->mock_rxqs.superbuf +
      (size_t)i * CI_EFCT_MAX_SUPERBUFS * EFCT_RX_SUPERBUF_BYTES;
  }

  vi->vi_rxq.mask =
    (size_t)CI_EFCT_MAX_SUPERBUFS * EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE - 1;
  vi->vi_rxq.descriptors =
    calloc(q_max, CI_EFCT_MAX_SUPERBUFS * EFCT_RX_DESCRIPTOR_BYTES);
  assert(vi->vi_rxq.descriptors != NULL);
  vi->efct_rxqs.meta_offset = meta_offset;

  t->vi = vi;
  t->mock_ops = mock_ops;

  return t;
}

static struct efct_test* efct_test_init_rx_default(int q_max, int arch, int nic_flags)
{
  struct efct_test* t = efct_test_init_test(q_max, arch, nic_flags);

  STATE_STASH(t->vi);
  STATE_STASH(t->mock_ops);

  return t;
}

static struct efct_test*
efct_test_init_tx_default(int q_max, int evq_size, int txq_size, int arch,
                          int nic_flags)
{
  struct efct_test* t = efct_test_init_test(q_max, arch, nic_flags);

  assert(EF_VI_IS_POW2(evq_size));
  t->vi->evq_mask = evq_size * 8 - 1;
  t->vi->evq_base = calloc(evq_size * 8, sizeof(char));
  assert(t->vi->evq_base);

  /* evq phase should be 1 to begin with, so cheat and just set everything to 1 */
  memset(t->vi->evq_base, 0xff, evq_size * 8);

  assert(EF_VI_IS_POW2(txq_size));
  t->vi->vi_txq.mask = txq_size - 1;
  t->vi->vi_txq.ct_fifo_bytes = EFCT_TX_ALIGNMENT * txq_size;
  t->vi->vi_txq.descriptors = calloc(txq_size, sizeof(struct efct_tx_descriptor));
  assert(t->vi->vi_txq.descriptors);
  t->vi->vi_txq.ids = calloc(txq_size, sizeof(uint32_t));
  assert(t->vi->vi_txq.ids);
  t->vi->tx_push_thresh = 0;

  t->vi->vi_txq.efct_aperture_mask = (4096 - 1) >> 3;
  t->vi->vi_ctpio_mmap_ptr = calloc(4096, sizeof(uint8_t));
  assert(t->vi->vi_ctpio_mmap_ptr != NULL);

  STATE_STASH(t->vi);
  STATE_STASH(t->mock_ops);

  return t;
}

static struct efct_test* efct_test_init_rx_x3(int q_max) {
  return efct_test_init_rx_default(q_max, EF_VI_ARCH_EFCT, EFHW_VI_NIC_CTPIO_ONLY);
}

static struct efct_test* efct_test_init_tx_x3(int q_max, int evq_size, int txq_size) {
  return efct_test_init_tx_default(q_max, evq_size, txq_size, EF_VI_ARCH_EFCT,
                                   EFHW_VI_NIC_CTPIO_ONLY);
}

static struct efct_test* efct_test_init_rx_x4(int q_max, bool shared_mode) {
  int nic_flags = EFHW_VI_NIC_CTPIO_ONLY;
  if ( shared_mode )
    nic_flags |= NIC_FLAG_RX_SHARED;
  return efct_test_init_rx_default(q_max, EF_VI_ARCH_EF10CT, nic_flags);
}

static void efct_test_cleanup(struct efct_test* t)
{
  free(t->vi->vi_rxq.descriptors);

  if ( t->mock_rxqs.q->shared_size > 0 ) {
    free(t->mock_rxqs.q->shared_sbids);
    free(t->mock_rxqs.q->shared_sentinels);
  }

  free(t->vi->evq_base);
  free(t->vi->vi_txq.descriptors);
  free(t->vi->vi_txq.ids);
  free(t->vi->vi_ctpio_mmap_ptr);

  free(t->mock_rxqs.q);
  free(t->mock_rxqs.superbuf);
  STATE_FREE(t->mock_ops);
  STATE_FREE(t->vi);
  free(t);
}

static void efct_test_poll_idle(struct efct_test* t)
{
  int i;
  ef_event evs[1];
  for( i = 0; i < 3; ++i ) {
    CHECK(efct_ef_eventq_check_event(t->vi), ==, 0);
    CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 0);
  }
  STATE_CHECK(t->mock_ops, anything_called, 0);
}

#define FOR_EACH_ACTIVE_EFCT_RXQ(vi, qs, ix) \
  for( qs = *(vi)->efct_rxqs.active_qs, ix = __builtin_ffsll(qs) - 1; \
       qs != 0; \
       qs &= ~(1 << ix), ix = __builtin_ffsll(qs) - 1 )

static void
efct_test_get_queues_pending_rollover(struct efct_test* t, int qid,
                                      int *pending_qs,
                                      int *min_pending_qid,
                                      int *max_pending_qid,
                                      int *n_pending_before_qid)
{
  uint64_t qs;
  int ix;

  *pending_qs = 0;
  *min_pending_qid = -1;
  *max_pending_qid = -1;
  *n_pending_before_qid = 0;

  assert(*t->vi->efct_rxqs.q[qid].live.superbuf_pkts != 0);

  FOR_EACH_ACTIVE_EFCT_RXQ(t->vi, qs, ix) {
    const ef_vi_efct_rxq_ptr* rxq_ptr = &t->vi->ep_state->rxq.rxq_ptr[ix];

    assert(*t->vi->efct_rxqs.q[ix].live.superbuf_pkts != 0);

    if( (rxq_ptr->meta_pkt & ((1u << 16 /* PKT_ID_PKT_BITS */) - 1)) >=
        rxq_ptr->superbuf_pkts ) {
      (*pending_qs)++;
      *min_pending_qid = (*min_pending_qid == -1) ? ix : *min_pending_qid;
      *max_pending_qid = ix;
      if( ix < qid )
        (*n_pending_before_qid)++;
    }
  }

  assert(*min_pending_qid <= *max_pending_qid);
}

static void
efct_test_rollover(struct efct_test* t, int qid, int sbid, int sentinel,
                   bool expect_rollover, bool pending_packets)
{
  int i;
  ef_event evs[1];
  struct efct_mock_rxq* rxq = &t->mock_rxqs.q[qid];
  int generates_events = t->vi->ep_state->rxq.efct_state[qid].generates_events;
  int n_evq_rx_pkts = t->vi->ep_state->rxq.n_evq_rx_pkts;
  int n_pending_before_qid = 0;
  int min_pending_qid = 0;
  int max_pending_qid = 0;
  int pending_qs = 0;

  efct_test_get_queues_pending_rollover(t, qid, &pending_qs, &min_pending_qid,
                                        &max_pending_qid,
                                        &n_pending_before_qid);
  assert(pending_qs > 0);
  assert(qid <= max_pending_qid && qid >= min_pending_qid);
  assert(pending_qs != 1 ||
         (max_pending_qid == qid && min_pending_qid == qid));

  /* No buffer available yet. Check and poll a few times to make sure
   * it consistently does nothing except look for a buffer */
  rxq->next_sbid = -EAGAIN;
  for( i = 0; i < 3; ++i ) {
    CHECK(efct_ef_eventq_check_event(t->vi), ==, pending_packets);
    if( pending_packets ) {
      STATE_CHECK(t->mock_ops, anything_called, 0);
      STATE_CHECK(t->mock_ops, available_called, 0);
    } else {
      STATE_CHECK(t->mock_ops, anything_called, pending_qs);
      STATE_CHECK(t->mock_ops, available_called, pending_qs);
      STATE_CHECK(t->mock_ops, available_qid, max_pending_qid);
    }

    CHECK(ef_eventq_poll(t->vi, evs, 1 - (int)pending_packets), ==, 0);
    if( ! generates_events || n_evq_rx_pkts >= PKTS_PER_SB ) {
      STATE_CHECK(t->mock_ops, anything_called, pending_qs);
      STATE_CHECK(t->mock_ops, next_called, pending_qs);
      STATE_CHECK(t->mock_ops, next_qid, max_pending_qid);
    } else {
      STATE_CHECK(t->mock_ops, anything_called, 0);
      STATE_CHECK(t->mock_ops, next_called, 0);
    }

    /* We shouldn't have rolled over, and thus shouldn't have consumed any
     * packets. Likewise if we had no packets in the first place. */
    CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, ==, n_evq_rx_pkts);
  }

  /* Make a buffer available. Make sure check_event indicates that a poll
   * is needed but doesn't do anything itself */
  rxq->next_sbid = sbid;
  rxq->next_sentinel = sentinel;
  for( i = 0; i < 3; ++i ) {
    /* This check is less useful if we're pending_packets */
    CHECK(efct_ef_eventq_check_event(t->vi), ==, 1);
    if( pending_packets ) {
      STATE_CHECK(t->mock_ops, anything_called, 0);
      STATE_CHECK(t->mock_ops, available_called, 0);
    } else {
      STATE_CHECK(t->mock_ops, anything_called, 1);
      STATE_CHECK(t->mock_ops, available_called, 1);
      STATE_CHECK(t->mock_ops, available_qid, min_pending_qid);
    }
  }

  /* The next poll will rollover and take the buffer, unless not enough packets
   * are available to allow for a rollover. */
  CHECK(ef_eventq_poll(t->vi, evs, 1 - (int)pending_packets), ==, 0);
  if( generates_events && n_evq_rx_pkts < PKTS_PER_SB ) {
    STATE_CHECK(t->mock_ops, anything_called, 0);
    STATE_CHECK(t->mock_ops, next_called, 0);
    CHECK(n_evq_rx_pkts, ==, t->vi->ep_state->rxq.n_evq_rx_pkts);
    CHECK(expect_rollover, ==, false);
  } else {
    /* Don't support checking multiple rollovers in a single poll for now */
    assert(!generates_events || n_evq_rx_pkts / PKTS_PER_SB == 1);
    STATE_CHECK(t->mock_ops, anything_called, 1 + n_pending_before_qid);
    STATE_CHECK(t->mock_ops, next_called, 1 + n_pending_before_qid);
    STATE_CHECK(t->mock_ops, next_qid, qid);
    CHECK(expect_rollover, ==, true);
    /* We should consume a superbuf worth of packets if we rollover */
    CHECK(n_evq_rx_pkts - (generates_events * PKTS_PER_SB), ==,
          t->vi->ep_state->rxq.n_evq_rx_pkts);
  }
  rxq->next_sbid = -EAGAIN;

  /* Now we've taken the buffer we should stop looking for one */
  if( expect_rollover ) {
    int old_pending_qs = pending_qs;

    efct_test_get_queues_pending_rollover(t, qid, &pending_qs,
                                          &min_pending_qid, &max_pending_qid,
                                          &n_pending_before_qid);
    CHECK(pending_qs, ==, old_pending_qs - 1);

    for( i = 0; i < 3; ++i ) {
      CHECK(efct_ef_eventq_check_event(t->vi), ==, pending_packets);
      if( pending_packets ) {
        STATE_CHECK(t->mock_ops, anything_called, 0);
        STATE_CHECK(t->mock_ops, available_called, 0);
      } else {
        STATE_CHECK(t->mock_ops, anything_called, pending_qs);
        STATE_CHECK(t->mock_ops, available_called, pending_qs);
        if( pending_qs )
          STATE_CHECK(t->mock_ops, available_qid, max_pending_qid);
      }

      assert(t->vi->ep_state->rxq.n_evq_rx_pkts < PKTS_PER_SB);
      CHECK(ef_eventq_poll(t->vi, evs, 1 - (int)pending_packets), ==, 0);
      STATE_CHECK(t->mock_ops, anything_called, 0);
      STATE_CHECK(t->mock_ops, next_called, 0);
    }
  }
}

static void efct_test_attach_only(struct efct_test* t, int qid, bool shared_mode,
                                  int exp_next_calls, int exp_free_calls)
{
  CHECK(t->vi->internal_ops.post_filter_add(t->vi, NULL, NULL, qid, shared_mode), ==, 0);
  int exp_anything_called = 1;
  if (shared_mode) {
    exp_anything_called += exp_next_calls + exp_free_calls;
    STATE_CHECK(t->mock_ops, next_called, exp_next_calls);
    STATE_CHECK(t->mock_ops, free_called, exp_free_calls);
  }

  STATE_CHECK(t->mock_ops, anything_called, exp_anything_called);
  STATE_CHECK(t->mock_ops, attach_called, 1);
  STATE_CHECK(t->mock_ops, attach_qid, qid);
  STATE_CHECK(t->mock_ops, attach_superbufs, CI_EFCT_MAX_SUPERBUFS);
}

static void efct_test_attach(struct efct_test* t, int qid)
{
  efct_test_attach_only(t, qid, false, 0, 0);
  efct_test_rollover(t, qid, 0, 1, true, false);
}

static void efct_test_rx_meta_extra(struct efct_test* t, int qid,
                                    uint64_t extra_meta, uint64_t timestamp)
{
  struct efct_mock_rxq* q = &t->mock_rxqs.q[qid];
  uint64_t* dest = (uint64_t*)q->next_meta;
  dest[1] = timestamp;
  dest[0] = extra_meta | rx_len |
    (1 << EFCT_RX_HEADER_NEXT_FRAME_LOC_LBN) | /* fixed in current hardware */
    ((uint64_t)q->next_sentinel << EFCT_RX_HEADER_SENTINEL_LBN) |
    (rx_flt << EFCT_RX_HEADER_FILTER_LBN);
  q->next_meta += EFCT_PKT_STRIDE;
  if( q->next_meta == q->superbuf_end )
    q->next_meta = NULL;
}

static void efct_test_rx_meta(struct efct_test* t, int qid)
{
  efct_test_rx_meta_extra(t, qid, 0, 0);
}

static bool efct_test_rxq_finished_superbuf(struct efct_test* t, int qid)
{
  return t->mock_rxqs.q[qid].next_meta == NULL;
}

static ci_qword_t efct_test_rx_event(struct efct_test* t, int qid,
                                     int n_packets, int rollover)
{
  ci_qword_t event = {0};

  /* If rolling over, n_packets must be 1 (for 1 superbuf rolled over) */
  assert(rollover != 1 || n_packets == 1);

  CI_POPULATE_QWORD_4(event,
                      EFCT_EVENT_TYPE, EFCT_EVENT_TYPE_RX,
                      EFCT_RX_EVENT_LABEL, qid,
                      EFCT_RX_EVENT_NUM_PACKETS, n_packets,
                      EFCT_RX_EVENT_ROLLOVER, rollover);

  return event;
}

static ci_qword_t efct_test_tx_event(struct efct_test* t, int seq)
{
  ci_qword_t event = {0};

  assert(seq <= (1 << EFCT_TX_EVENT_SEQUENCE_WIDTH) - 1);

  CI_POPULATE_QWORD_3(event,
                      EFCT_EVENT_TYPE, EFCT_EVENT_TYPE_TX,
                      EFCT_TX_EVENT_SEQUENCE, seq,
                      EFCT_TX_EVENT_LABEL, tx_qid);

  return event;
}

static ci_qword_t efct_test_tx_ts_event(struct efct_test* t, int seq,
                                        int ts_status, uint64_t partial_ts)
{
  ci_qword_t event;

  CI_POPULATE_QWORD_2(event,
                      EFCT_TX_EVENT_TIMESTAMP_STATUS, ts_status,
                      EFCT_TX_EVENT_PARTIAL_TSTAMP, partial_ts);

  event.u64[0] |= efct_test_tx_event(t, seq).u64[0];

  return event;
}

static void efct_test_push_event(struct efct_test* t, ci_qword_t event)
{
  ci_qword_t* evq_next_event =
    (ci_qword_t*)(t->vi->evq_base + (t->evq_write_ptr & t->vi->evq_mask));
  int phase = (t->evq_write_ptr & (t->vi->evq_mask + 1)) != 0;
  ci_qword_t temp;

  CI_POPULATE_QWORD_1(temp, EFCT_EVENT_PHASE, phase);
  event.u64[0] |= temp.u64[0];

  last_evq_event = *evq_next_event;
  *evq_next_event = event;
  t->evq_write_ptr += sizeof(event);
}

static void efct_test_rollback_event(struct efct_test* t)
{
  ci_qword_t* evq_last_event;

  t->evq_write_ptr -= sizeof(*evq_last_event);
  evq_last_event =
    (ci_qword_t*)(t->vi->evq_base + (t->evq_write_ptr & t->vi->evq_mask));

  *evq_last_event = last_evq_event;
}

static bool efct_test_evq_overflowed(struct efct_test* t)
{
  uint32_t evq_ptr = t->vi->ep_state->evq.evq_ptr - sizeof(ci_qword_t);
  ci_qword_t* event =
    (ci_qword_t*)(t->vi->evq_base + (evq_ptr & t->vi->evq_mask));
  int expect_phase = (evq_ptr & (t->vi->evq_mask + 1)) != 0;
  int actual_phase = CI_QWORD_FIELD(*event, EFCT_EVENT_PHASE);
  bool overflow = (expect_phase != actual_phase);

  return overflow;
}

static bool is_tx_warming(struct efct_test* t)
{
  ci_qword_t qword;
  qword.u64[0] = t->vi->vi_txq.efct_fixed_header;
  return CI_QWORD_FIELD(qword, EFCT_TX_HEADER_WARM_FLAG);
}

static bool is_tx_ts_enabled(struct efct_test* t)
{
  ci_qword_t qword;
  qword.u64[0] = t->vi->vi_txq.efct_fixed_header;
  return CI_QWORD_FIELD(qword, EFCT_TX_HEADER_TIMESTAMP_FLAG);
}

static void efct_test_transmit(struct efct_test* t, int n_packets)
{
  int i;

  for( i = 0; i < n_packets; i++) {
    assert(ef_vi_transmit_space_bytes(t->vi) >= TX_LEN);
    ef_vi_transmitv_ctpio(t->vi, TX_LEN, &tx_iov, 1, 0);
  }
}

static void efct_test_rx_complete(struct efct_test* t, int qid, int n_packets)
{
  efct_test_push_event(t, efct_test_rx_event(t, qid, n_packets, 0));
}

static void efct_test_rx_rollover_ev(struct efct_test* t, int qid)
{
  efct_test_push_event(t, efct_test_rx_event(t, qid, 1, 1));
}

static void efct_test_tx_complete(struct efct_test* t, int n_completions)
{
  ef_vi_txq_state* qs = &t->vi->ep_state->txq;
  ef_vi_txq* txq = &t->vi->vi_txq;
  unsigned seq_mask = (1 << EFCT_TX_EVENT_SEQUENCE_WIDTH) - 1;
  int seq = (t->tx_completions + n_completions - 1) & seq_mask;
  ci_qword_t event;

  /* don't complete more than we've sent */
  assert(((seq + 1 - qs->previous) & txq->mask) <=
         ((qs->added - qs->previous) & txq->mask));

  if( is_tx_ts_enabled(t) && ! is_tx_warming(t) ) {
    int ts_status = 3;
    uint64_t partial_ts = 0;

    assert(n_completions == 1);

    event = efct_test_tx_ts_event(t, seq, ts_status, partial_ts);
  } else {
    event = efct_test_tx_event(t, seq);
  }

  efct_test_push_event(t, event);
  t->tx_completions += n_completions;
}

static void efct_test_handle_tx_event(struct efct_test* t, ef_event* ev,
                                      int expected_pkts)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  int i;

  assert(expected_pkts <= EF_VI_TRANSMIT_BATCH);

  CHECK((int)ev->tx.type, ==, EF_EVENT_TYPE_TX);
  CHECK((int)ev->tx.q_id, ==, tx_qid);
  CHECK((int)ev->tx.flags, ==, EF_EVENT_FLAG_CTPIO);

  CHECK(ef_vi_transmit_unbundle(t->vi, ev, ids), ==, expected_pkts);
  for( i = 0; i < expected_pkts; i++ )
    CHECK(ids[i], ==, 0xefc7efc7);
}

/* Test cases */
static void test_efct_idle(void)
{
  struct efct_test* t = efct_test_init_rx_x3(3);
  efct_test_poll_idle(t);
  efct_test_cleanup(t);
}

static void test_efct_attach_local(void)
{
  struct efct_test* t = efct_test_init_rx_x3(3);
  bool test_shared_mode = false;

  test_filter_is_block_only = true;
  CHECK(t->vi->internal_ops.post_filter_add(t->vi, NULL, NULL, 1, test_shared_mode), ==, 0);
  STATE_CHECK(t->mock_ops, anything_called, 0);
  test_filter_is_block_only = false;

  CHECK(t->vi->internal_ops.post_filter_add(t->vi, NULL, NULL, 3, test_shared_mode), ==, -EINVAL);
  STATE_CHECK(t->mock_ops, anything_called, 1);
  STATE_CHECK(t->mock_ops, attach_called, 1);
  STATE_CHECK(t->mock_ops, attach_qid, 3);
  STATE_CHECK(t->mock_ops, attach_superbufs, CI_EFCT_MAX_SUPERBUFS);

  efct_test_attach(t, 1);
  efct_test_attach(t, 2);
  efct_test_attach(t, 0);

  efct_test_attach_only(t, 1, test_shared_mode, 0, 0); /* Duplicates are silently accepted */
  efct_test_poll_idle(t);

  efct_test_cleanup(t);
}

static void fill_superbuf(char* superbuf, char* superbuf_end, int pkts_to_fill, bool sb_sentinel, uint64_t timestamp)
{
  char* p;
  int i = 0;
  for( p=superbuf; p != superbuf_end; p+=EFCT_PKT_STRIDE, i++ ) {
    uint64_t* dest = (uint64_t*)(p);
    int sent = (i <= pkts_to_fill ? sb_sentinel: !sb_sentinel);

    dest[1] = timestamp;
    dest[0] = 0 | rx_len |
              (1 << EFCT_RX_HEADER_NEXT_FRAME_LOC_LBN) | /* fixed in current hardware */
              ((uint64_t)sent << EFCT_RX_HEADER_SENTINEL_LBN) |
              (rx_flt << EFCT_RX_HEADER_FILTER_LBN);
  }
}

static void test_efct_attach_shared_helper(int sbids, int pkts)
{
  struct efct_test* t = efct_test_init_rx_x4(3, true);
  bool test_shared_mode = true;

  /* Preserved shrub_client compatablity behavior. */
  test_filter_is_block_only = true;
  CHECK(t->vi->internal_ops.post_filter_add(t->vi, NULL, NULL, 1, test_shared_mode), ==, 0);
  STATE_CHECK(t->mock_ops, anything_called, 0);
  test_filter_is_block_only = false;

  CHECK(t->vi->internal_ops.post_filter_add(t->vi, NULL, NULL, 3, test_shared_mode), ==, -EINVAL);
  STATE_CHECK(t->mock_ops, anything_called, 1);
  STATE_CHECK(t->mock_ops, attach_called, 1);
  STATE_CHECK(t->mock_ops, attach_qid, 3);
  STATE_CHECK(t->mock_ops, attach_superbufs, CI_EFCT_MAX_SUPERBUFS);

  /* test_setup */
  int qid = 1;
  struct efct_mock_ops* ops = mock_ops(t->vi);
  struct efct_mock_rxq* rxq = &ops->rxqs->q[qid];
  rxq->shared_mode = test_shared_mode;

  int exp_pkts_to_fill = pkts % PKTS_PER_SB;
  int exp_filled_sbs = pkts / PKTS_PER_SB;

  /* Code required for testing efct_vi_sync_rxq */
  init_shared_state(rxq, sbids);
  int sbid_index;
  for ( sbid_index = 0; sbid_index < rxq->shared_size; sbid_index++, pkts -= PKTS_PER_SB ) {
    rxq->shared_sbids[sbid_index] = sbid_index;
    rxq->superbuf = ops->rxqs->superbuf +
                    (size_t)(qid * CI_EFCT_MAX_SUPERBUFS + sbid_index) * EFCT_RX_SUPERBUF_BYTES;
    rxq->superbuf_end = rxq->superbuf + EFCT_RX_SUPERBUF_BYTES;

    int pkts_to_fill;
    if ( pkts >= 512 ) {
      pkts_to_fill = 512;
    } else if ( pkts <= 0 ) {
      pkts_to_fill = -1;
    } else {
      pkts_to_fill = pkts % PKTS_PER_SB;
    }

    fill_superbuf(rxq->superbuf, rxq->superbuf_end,
                  pkts_to_fill, peek_sentinel(rxq, sbid_index), 0);
  }

  int expected_next_calls = exp_filled_sbs + 1;
  int expected_free_calls = expected_next_calls - 1;

  efct_test_attach_only(t, qid, test_shared_mode, expected_next_calls, expected_free_calls);

  int exp_data_pkts = t->vi->ep_state->rxq.rxq_ptr[qid].data_pkt % PKTS_PER_SB;

  STATE_CHECK(t->mock_ops, next_qid, qid);
  if ( expected_free_calls > 0 )
    STATE_CHECK(t->mock_ops, free_qid, qid);

  CHECK(exp_data_pkts, ==, (exp_pkts_to_fill > 0 ? exp_pkts_to_fill + 1 : 0));

  efct_test_cleanup(t);
}

static void test_efct_attach_first_partially_filled_sb(void)
{
  test_efct_attach_shared_helper(3, 100);
}

 static void test_efct_attach_first_fully_filled_sb(void)
{
  test_efct_attach_shared_helper(3, 1 * PKTS_PER_SB);
}

static void test_efct_attach_middle_partially_filled_sb(void)
{
  test_efct_attach_shared_helper(3, 1 * PKTS_PER_SB + 100);
}

static void test_efct_attach_middle_fully_filled_sb(void)
{
  test_efct_attach_shared_helper(3, 1 * PKTS_PER_SB);
}

static void test_efct_attach_end_partially_filled_sb(void)
{
  test_efct_attach_shared_helper(3, 2 * PKTS_PER_SB + 100);
}

static void test_efct_attach_end_fully_filled_sb(void)
{
  test_efct_attach_shared_helper(3, 3 * PKTS_PER_SB);
}

static void test_efct_attach_shared(void)
{
  TEST_RUN(test_efct_attach_first_partially_filled_sb);
  TEST_RUN(test_efct_attach_first_fully_filled_sb);
  TEST_RUN(test_efct_attach_middle_partially_filled_sb);
  TEST_RUN(test_efct_attach_middle_fully_filled_sb);
  TEST_RUN(test_efct_attach_end_partially_filled_sb);
  TEST_RUN(test_efct_attach_end_fully_filled_sb);
}


static void test_efct_refresh(void)
{
  int i, q;
  ef_event evs[1];
  struct efct_test* t = efct_test_init_rx_x3(3);

  for( q = 0; q < 3; ++q )
    efct_test_attach(t, q);

  for( i = 0; i < 3; ++i ) {
    for( q = 0; q < 3; ++q ) {
      int next_gen = ++t->mock_rxqs.q[q].config_generation;

      CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 0);
      STATE_CHECK(t->mock_ops, anything_called, 1);
      STATE_CHECK(t->mock_ops, refresh_called, 1);
      STATE_CHECK(t->mock_ops, refresh_qid, q);

      STATE_UPDATE(t->vi, efct_rxqs.q[q].config_generation, next_gen);
      efct_test_poll_idle(t);
    }
  }

  efct_test_cleanup(t);
}

static void efct_test_check_rx_event(struct efct_test* t, int qid,
                                     const ef_event* ev)
{
  CHECK((int)ev->rx_ref.type, ==, EF_EVENT_TYPE_RX_REF);
  CHECK((int)ev->rx_ref.len, ==, rx_len);
  CHECK((int)ev->rx_ref.q_id, ==, qid);
  CHECK((int)ev->rx_ref.filter_id, ==, rx_flt);

  const char* data = efct_vi_rxpkt_get(t->vi, ev->rx_ref.pkt_id);
  CHECK(data, ==, t->mock_rxqs.q[qid].next_pkt);
}

static void efct_test_rx_poll_discard(struct efct_test* t, int qid, int flags)
{
  ef_event ev;
  CHECK(efct_ef_eventq_check_event(t->vi), ==, 1);
  CHECK(ef_eventq_poll(t->vi, &ev, 1), ==, 1);
  CHECK((int)ev.rx_ref_discard.type, ==, EF_EVENT_TYPE_RX_REF_DISCARD);
  CHECK((int)ev.rx_ref_discard.len, ==, rx_len);
  CHECK((int)ev.rx_ref_discard.q_id, ==, qid);
  CHECK((int)ev.rx_ref_discard.filter_id, ==, rx_flt);
  CHECK((int)ev.rx_ref_discard.flags, ==, flags);

  const char* data = efct_vi_rxpkt_get(t->vi, ev.rx_ref_discard.pkt_id);
  CHECK(data, ==, t->mock_rxqs.q[qid].next_pkt);

  t->mock_rxqs.q[qid].next_pkt += EFCT_PKT_STRIDE;
  efct_vi_rxpkt_release(t->vi, ev.rx_ref_discard.pkt_id);
}

static void efct_test_rx_poll(struct efct_test* t, int qid,
                              int expect_evs, int max_evs)
{
  int i;
  ef_event evs[16];
  assert(max_evs <= 16);

  CHECK(efct_ef_eventq_check_event(t->vi), ==, 1);
  CHECK(ef_eventq_poll(t->vi, evs, max_evs), ==, expect_evs);

  for( i = 0; i < expect_evs; ++i ) {
    efct_test_check_rx_event(t, qid, &evs[i]);
    t->mock_rxqs.q[qid].next_pkt += EFCT_PKT_STRIDE;
    efct_vi_rxpkt_release(t->vi, evs[i].rx_ref.pkt_id);
  }
}


static void test_efct_rx(void)
{
  int q, i;
  struct efct_test* t = efct_test_init_rx_x3(3);

  for( q = 0; q < 3; ++q )
    efct_test_attach(t, q);

  /* Single packet */
  for( q = 0; q < 3; ++q ) {
    efct_test_rx_meta(t, q);
    efct_test_rx_poll(t, q, 1, 16);
  }

  /* Multiple packets, single poll */
  for( q = 0; q < 3; ++q ) {
    for( i = 0; i < 8; ++i )
      efct_test_rx_meta(t, q);
    efct_test_rx_poll(t, q, 8, 16);
  }

  /* Multiple packets, multiple polls */
  for( q = 0; q < 3; ++q ) {
    for( i = 0; i < 8; ++i )
      efct_test_rx_meta(t, q);
    efct_test_rx_poll(t, q, 4, 4);
    efct_test_rx_poll(t, q, 4, 16);
  }

  efct_test_cleanup(t);
}

static void test_efct_rx_discard(void)
{
  struct efct_test* t = efct_test_init_rx_x3(1);
  efct_test_attach(t, 0);

  /* class/status bitfield values */
  uint64_t l2c_eth = 1ll << EFCT_RX_HEADER_L2_CLASS_LBN;
  uint64_t l2c_oth = 0;
  uint64_t l2s_len = 1ll << EFCT_RX_HEADER_L2_STATUS_LBN;
  uint64_t l2s_fcs = 2ll << EFCT_RX_HEADER_L2_STATUS_LBN;

  uint64_t l3c_ip4 = 0;
  uint64_t l3c_ip6 = 1ll << EFCT_RX_HEADER_L3_CLASS_LBN;
  uint64_t l3c_oth = 2ll << EFCT_RX_HEADER_L3_CLASS_LBN;
  uint64_t l3s_bad = 1ll << EFCT_RX_HEADER_L3_STATUS_LBN;

  uint64_t l4c_tcp = 0;
  uint64_t l4c_udp = 1ll << EFCT_RX_HEADER_L4_CLASS_LBN;
  uint64_t l4c_frg = 2ll << EFCT_RX_HEADER_L4_CLASS_LBN;
  uint64_t l4c_oth = 3ll << EFCT_RX_HEADER_L4_CLASS_LBN;
  uint64_t l4s_bad = 1ll << EFCT_RX_HEADER_L4_STATUS_LBN;

  /* Valid combinations */
  uint64_t l2_bad_len = l2c_eth | l2s_len | l3c_oth | l3s_bad | l4c_oth | l4s_bad;
  uint64_t l2_bad_fcs = l2c_eth | l2s_fcs | l3c_oth | l3s_bad | l4c_oth | l4s_bad;
  uint64_t l2_other = l2c_oth | l3c_oth | l3s_bad | l4c_oth | l4s_bad;

  uint64_t l3_bad_ip4 = l2c_eth | l3c_ip4 | l3s_bad | l4c_oth | l4s_bad;
  uint64_t l3_bad_ip6 = l2c_eth | l3c_ip6 | l3s_bad | l4c_oth | l4s_bad;
  uint64_t l3_other   = l2c_eth | l3c_oth | l3s_bad | l4c_oth | l4s_bad;

  uint64_t l4_bad_tcp = l2c_eth | l3c_ip4 | l4c_tcp | l4s_bad;
  uint64_t l4_bad_udp = l2c_eth | l3c_ip4 | l4c_udp | l4s_bad;
  uint64_t l4_frag    = l2c_eth | l3c_ip4 | l4c_frg | l4s_bad;
  uint64_t l4_other   = l2c_eth | l3c_ip4 | l4c_oth | l4s_bad;

  uint64_t good_tcp = l2c_eth | l3c_ip4 | l4c_tcp;
  uint64_t good_udp = l2c_eth | l3c_ip4 | l4c_udp;

  CHECK(ef_vi_receive_get_discards(t->vi), ==,
           EF_VI_DISCARD_RX_ETH_LEN_ERR |
           EF_VI_DISCARD_RX_ETH_FCS_ERR |
           EF_VI_DISCARD_RX_L3_CSUM_ERR |
           EF_VI_DISCARD_RX_L4_CSUM_ERR);

  efct_test_rx_meta_extra(t, 0, good_tcp, 0);
  efct_test_rx_poll(t, 0, 1, 1);
  efct_test_rx_meta_extra(t, 0, good_udp, 0);
  efct_test_rx_poll(t, 0, 1, 1);

  /* Bad status */
  efct_test_rx_meta_extra(t, 0, l2_bad_len, 0);
  efct_test_rx_poll_discard(t, 0, EF_VI_DISCARD_RX_ETH_LEN_ERR);
  efct_test_rx_meta_extra(t, 0, l2_bad_fcs, 0);
  efct_test_rx_poll_discard(t, 0, EF_VI_DISCARD_RX_ETH_FCS_ERR);

  efct_test_rx_meta_extra(t, 0, l3_bad_ip4, 0);
  efct_test_rx_poll_discard(t, 0, EF_VI_DISCARD_RX_L3_CSUM_ERR);
  efct_test_rx_meta_extra(t, 0, l3_bad_ip6, 0);
  efct_test_rx_poll_discard(t, 0, EF_VI_DISCARD_RX_L3_CSUM_ERR);

  efct_test_rx_meta_extra(t, 0, l4_bad_tcp, 0);
  efct_test_rx_poll_discard(t, 0, EF_VI_DISCARD_RX_L4_CSUM_ERR);
  efct_test_rx_meta_extra(t, 0, l4_bad_udp, 0);
  efct_test_rx_poll_discard(t, 0, EF_VI_DISCARD_RX_L4_CSUM_ERR);

  /* Unknown class: not enabled by default */
  efct_test_rx_meta_extra(t, 0, l2_other, 0);
  efct_test_rx_poll(t, 0, 1, 1);
  efct_test_rx_meta_extra(t, 0, l3_other, 0);
  efct_test_rx_poll(t, 0, 1, 1);
  efct_test_rx_meta_extra(t, 0, l4_other, 0);
  efct_test_rx_poll(t, 0, 1, 1);
  efct_test_rx_meta_extra(t, 0, l4_frag, 0);
  efct_test_rx_poll(t, 0, 1, 1);

  unsigned expect_discards = EF_VI_DISCARD_RX_ETH_LEN_ERR |
                             EF_VI_DISCARD_RX_ETH_FCS_ERR |
                             EF_VI_DISCARD_RX_L3_CSUM_ERR |
                             EF_VI_DISCARD_RX_L4_CSUM_ERR |
                             EF_VI_DISCARD_RX_L2_CLASS_OTHER |
                             EF_VI_DISCARD_RX_L3_CLASS_OTHER |
                             EF_VI_DISCARD_RX_L4_CLASS_OTHER;

  ef_vi_receive_set_discards(t->vi, -1);
  CHECK(ef_vi_receive_get_discards(t->vi), ==, expect_discards);

  efct_test_rx_meta_extra(t, 0, l2_other, 0);
  efct_test_rx_poll_discard(t, 0, EF_VI_DISCARD_RX_L2_CLASS_OTHER |
                                  EF_VI_DISCARD_RX_L3_CLASS_OTHER |
                                  EF_VI_DISCARD_RX_L4_CLASS_OTHER);
  efct_test_rx_meta_extra(t, 0, l3_other, 0);
  efct_test_rx_poll_discard(t, 0, EF_VI_DISCARD_RX_L3_CLASS_OTHER |
                                  EF_VI_DISCARD_RX_L4_CLASS_OTHER);
  efct_test_rx_meta_extra(t, 0, l4_other, 0);
  efct_test_rx_poll_discard(t, 0, EF_VI_DISCARD_RX_L4_CLASS_OTHER);

  STATE_CHECK(t->vi, rx_discard_mask, expect_discards);
  efct_test_cleanup(t);
}

static void test_efct_natural_rollover(void)
{
  int q, sb, i;
  struct efct_test* t = efct_test_init_rx_x3(3);

  for( q = 0; q < 3; ++q )
    efct_test_attach(t, q);

  for( sb = 0; sb < 4; ++sb ) {
    for( q = 0; q < 3; ++q ) {
      for( i = 0; i < t->mock_rxqs.q[q].superbuf_pkts - 1; ++i ) {
        efct_test_rx_meta(t, q);
        efct_test_rx_poll(t, q, 1, 16);
      }

      if( meta_offset == 1 )
        /* We've read the final metadata (but not the final packet) so the
         * next poll should cause a rollover */
        efct_test_rollover(t, q, sb+1, 1, true, false);

      /* Processing the final packet should free the old buffer */
      efct_test_rx_meta(t, q);
      efct_test_rx_poll(t, q, 1, 16);
      STATE_CHECK(t->mock_ops, anything_called, 1);
      STATE_CHECK(t->mock_ops, free_called, 1);
      STATE_CHECK(t->mock_ops, free_qid, q);
      STATE_CHECK(t->mock_ops, free_sbid, sb);

      if( meta_offset == 0 )
        efct_test_rollover(t, q, sb+1, 1, true, false);
    }
  }

  efct_test_cleanup(t);
}

/* Forced rollover without delivering any packets to the buffer */
static void test_efct_forced_rollover_none(void)
{
  int q, i;
  struct efct_test* t = efct_test_init_rx_x3(3);

  for( q = 0; q < 3; ++q )
    efct_test_attach(t, q);

  for( q = 0; q < 3; ++q ) {
    /* Set the ROLLOVER bit in the next metadata */
    efct_test_rx_meta_extra(t, q, 1ll << EFCT_RX_HEADER_ROLLOVER_LBN, 0);

    /* The buffer should be freed on the next poll */
    efct_test_rx_poll(t, q, 0, 16);
    STATE_CHECK(t->mock_ops, anything_called, 1);
    STATE_CHECK(t->mock_ops, free_called, 1);
    STATE_CHECK(t->mock_ops, free_qid, q);
    STATE_CHECK(t->mock_ops, free_sbid, 0);

    /* That should force a rollover on the next poll */
    t->mock_rxqs.q[q].next_pkt = NULL;
    efct_test_rollover(t, q, 1, 1, true, false);
  }

  /* The next buffer should work as expected */
  for( q = 0; q < 3; ++q ) {
    for( i = 0; i < 4; ++i )
      efct_test_rx_meta(t, q);
    efct_test_rx_poll(t, q, 4, 16);
  }

  efct_test_cleanup(t);
}

/* Forced rollover after delivering some packets to the buffer */
static void test_efct_forced_rollover_some(void)
{
  int q, i;
  ef_event evs[16];
  struct efct_test* t = efct_test_init_rx_x3(3);

  for( q = 0; q < 3; ++q )
    efct_test_attach(t, q);

  for( q = 0; q < 3; ++q ) {
    /* Consume most of the buffer leaving two slots */
    for( i = 0; i < t->mock_rxqs.q[q].superbuf_pkts - 3; ++i ) {
      efct_test_rx_meta(t, q);
      efct_test_rx_poll(t, q, 1, 16);
    }

    /* One final packet leaving one free slot */
    efct_test_rx_meta(t, q);

    /* Set the ROLLOVER bit in the next metadata (last in this buffer) */
    efct_test_rx_meta_extra(t, q, 1ll << EFCT_RX_HEADER_ROLLOVER_LBN, 0);

    /* Process the final packet but don't release it yet */
    CHECK(ef_eventq_poll(t->vi, evs, 16), ==, 1);
    efct_test_check_rx_event(t, q, &evs[0]);
    STATE_CHECK(t->mock_ops, anything_called, 0);

    /* That should force a rollover on the next poll */
    t->mock_rxqs.q[q].next_pkt = NULL;
    efct_test_rollover(t, q, 1, 1, true, false);

    /* Releasing the packet should free the buffer */
    efct_vi_rxpkt_release(t->vi, evs[0].rx_ref.pkt_id);
    STATE_CHECK(t->mock_ops, anything_called, 1);
    STATE_CHECK(t->mock_ops, free_called, 1);
    STATE_CHECK(t->mock_ops, free_qid, q);
    STATE_CHECK(t->mock_ops, free_sbid, 0);
  }

  /* The next buffer should work as expected */
  for( q = 0; q < 3; ++q ) {
    for( i = 0; i < 4; ++i )
      efct_test_rx_meta(t, q);
    efct_test_rx_poll(t, q, 4, 16);
  }

  efct_test_cleanup(t);
}

/* Forced rollover after delivering all packets to the buffer */
static void test_efct_forced_rollover_all(void)
{
  int q, i;
  ef_event evs[16];
  struct efct_test* t = efct_test_init_rx_x3(3);

  for( q = 0; q < 3; ++q )
    efct_test_attach(t, q);

  for( q = 0; q < 3; ++q ) {
    struct efct_mock_rxq* rxq = &t->mock_rxqs.q[q];

    /* Consume most of the buffer leaving one slot */
    for( i = meta_offset; i < rxq->superbuf_pkts - 1; ++i ) {
      efct_test_rx_meta(t, q);
      efct_test_rx_poll(t, q, 1, 16);
    }

    /* One final packet filling the buffer */
    efct_test_rx_meta(t, q);

    /* Process the final packet but don't release it yet */
    CHECK(ef_eventq_poll(t->vi, evs, 16), ==, 1);
    efct_test_check_rx_event(t, q, &evs[0]);
    STATE_CHECK(t->mock_ops, anything_called, 0);

    /* Natural rollover */
    rxq->next_sbid = 1;
    CHECK(ef_eventq_poll(t->vi, evs, 16), ==, 0);
    STATE_CHECK(t->mock_ops, anything_called, 1);
    STATE_CHECK(t->mock_ops, next_called, 1);
    STATE_CHECK(t->mock_ops, next_qid, q);

    /* Set the ROLLOVER bit in the next metadata (first in the new buffer) */
    efct_test_rx_meta_extra(t, q, 1ll << EFCT_RX_HEADER_ROLLOVER_LBN, 0);

    if( meta_offset == 0 ) {
      /* The next poll should discard the new buffer */
      CHECK(ef_eventq_poll(t->vi, evs, 16), ==, 0);
      STATE_CHECK(t->mock_ops, anything_called, 1);
      STATE_CHECK(t->mock_ops, free_called, 1);
      STATE_CHECK(t->mock_ops, free_qid, q);
      STATE_CHECK(t->mock_ops, free_sbid, 1);

      /* The next poll should rollover to yet another buffer */
      rxq->next_sbid = 2;
      rxq->next_pkt = NULL;
      CHECK(ef_eventq_poll(t->vi, evs, 16), ==, 0);
      STATE_CHECK(t->mock_ops, anything_called, 1);
      STATE_CHECK(t->mock_ops, next_called, 1);
      STATE_CHECK(t->mock_ops, next_qid, q);
    }
    else {
      /* The next poll should skip to the new buffer */
      rxq->next_pkt = rxq->superbuf + EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
      CHECK(ef_eventq_poll(t->vi, evs, 16), ==, 0);
      STATE_CHECK(t->mock_ops, anything_called, 0);
      efct_test_rx_meta(t, q);
      efct_test_rx_poll(t, q, 1, 16);
    }

    /* Releasing the packet should free the old buffer */
    efct_vi_rxpkt_release(t->vi, evs[0].rx_ref.pkt_id);
    STATE_CHECK(t->mock_ops, anything_called, 1);
    STATE_CHECK(t->mock_ops, free_called, 1);
    STATE_CHECK(t->mock_ops, free_qid, q);
    STATE_CHECK(t->mock_ops, free_sbid, 0);
  }

  /* The next buffer should work as expected */
  for( q = 0; q < 3; ++q ) {
    for( i = 0; i < 4; ++i )
      efct_test_rx_meta(t, q);
    efct_test_rx_poll(t, q, 4, 16);
  }  

  efct_test_cleanup(t);
}

static void test_efct_future(void)
{
  int i;
  ef_event evs[16];
  struct efct_test* t = efct_test_init_rx_x3(2);
  struct efct_mock_rxq *q0, *q1;


  efct_test_attach(t, 0);
  efct_test_attach(t, 1);

  q0 = &t->mock_rxqs.q[0];
  q1 = &t->mock_rxqs.q[1];

  /* Consume most of the buffer leaving one slot */
  for( i = meta_offset; i < q0->superbuf_pkts - 1; ++i ) {
    CHECK(efct_vi_rx_future_peek(t->vi), ==, NULL);

    strcpy(q0->next_pkt, "FUTURE");
    strcpy(q1->next_pkt, "FUTURE");

    CHECK(efct_vi_rx_future_peek(t->vi), ==, q0->next_pkt);
    CHECK(efct_vi_rx_future_poll(t->vi, evs, 16), ==, 0);

    efct_test_rx_meta(t, 0);
    efct_test_rx_meta(t, 1);

    CHECK(efct_vi_rx_future_poll(t->vi, evs, 16), ==, 1);
    efct_test_check_rx_event(t, 0, evs);
    q0->next_pkt += EFCT_PKT_STRIDE;
    efct_vi_rxpkt_release(t->vi, evs[0].rx_ref.pkt_id);

    CHECK(efct_vi_rx_future_peek(t->vi), ==, q1->next_pkt);
    CHECK(efct_vi_rx_future_poll(t->vi, evs, 16), ==, 1);
    efct_test_check_rx_event(t, 1, evs);
    q1->next_pkt += EFCT_PKT_STRIDE;
    efct_vi_rxpkt_release(t->vi, evs[0].rx_ref.pkt_id);
  }

  /* We need to poll for a rollover after the final packet. */
  CHECK(efct_vi_rx_future_peek(t->vi), ==, NULL);

  strcpy(q0->next_pkt, "FUTURE");

  CHECK(efct_vi_rx_future_peek(t->vi), ==, q0->next_pkt);
  CHECK(efct_vi_rx_future_poll(t->vi, evs, 16), ==, 0);

  efct_test_rx_meta(t, 0);
  CHECK(efct_vi_rx_future_poll(t->vi, evs, 16), ==, 1);
  efct_test_check_rx_event(t, 0, evs);
  q0->next_pkt += EFCT_PKT_STRIDE;
  efct_vi_rxpkt_release(t->vi, evs[0].rx_ref.pkt_id);

  if( meta_offset == 0 ) {
    /* We have released the final packet */
    STATE_CHECK(t->mock_ops, anything_called, 1);
    STATE_CHECK(t->mock_ops, free_called, 1);
    STATE_CHECK(t->mock_ops, free_qid, 0);
    STATE_CHECK(t->mock_ops, free_sbid, 0);
    efct_test_rollover(t, 0, 1, 1, true, false);
    CHECK(efct_vi_rx_future_peek(t->vi), ==, NULL);
    strcpy(q0->next_pkt, "FUTURE");
  }
  else {
    /* Peeking the final packet will see data */
    strcpy(q0->next_pkt, "FUTURE");
    CHECK(efct_vi_rx_future_peek(t->vi), ==, q0->next_pkt);

    /* Polling will roll to the next buffer to find the metadata,
     * but won't find it yet */
    q0->next_sbid = 1;
    q0->next_sentinel = 1;
    CHECK(efct_vi_rx_future_poll(t->vi, evs, 16), ==, 0);
    STATE_CHECK(t->mock_ops, anything_called, 1);
    STATE_CHECK(t->mock_ops, next_called, 1);
    STATE_CHECK(t->mock_ops, next_qid, 0);
  }

  CHECK(efct_vi_rx_future_peek(t->vi), ==, q0->next_pkt);
  CHECK(efct_vi_rx_future_poll(t->vi, evs, 16), ==, 0);

  efct_test_rx_meta(t, 0);
  CHECK(efct_vi_rx_future_poll(t->vi, evs, 16), ==, 1);
  efct_test_check_rx_event(t, 0, evs);

  q0->next_pkt += EFCT_PKT_STRIDE;
  efct_vi_rxpkt_release(t->vi, evs[0].rx_ref.pkt_id);
  if( meta_offset != 0 ) {
    STATE_CHECK(t->mock_ops, anything_called, 1);
    STATE_CHECK(t->mock_ops, free_called, 1);
    STATE_CHECK(t->mock_ops, free_qid, 0);
    STATE_CHECK(t->mock_ops, free_sbid, 0);
  }

  /* Future detection continues as normal now we're in the next superbuf */
  for( i = 0; i < 10; ++i ) {
    CHECK(efct_vi_rx_future_peek(t->vi), ==, NULL);

    strcpy(q0->next_pkt, "FUTURE");
    CHECK(efct_vi_rx_future_peek(t->vi), ==, q0->next_pkt);
    CHECK(efct_vi_rx_future_poll(t->vi, evs, 16), ==, 0);

    efct_test_rx_meta(t, 0);
    CHECK(efct_vi_rx_future_poll(t->vi, evs, 16), ==, 1);
    efct_test_check_rx_event(t, 0, evs);

    q0->next_pkt += EFCT_PKT_STRIDE;
    efct_vi_rxpkt_release(t->vi, evs[0].rx_ref.pkt_id);
  }
}

static void test_efct_tx(void)
{
  struct efct_test* t = efct_test_init_tx_x3(1, 512, 512);
  ef_event evs[8];
  int i;

  /* Single packet */
  CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 0);
  efct_test_transmit(t, 1);
  efct_test_tx_complete(t, 1);
  CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 1);
  efct_test_handle_tx_event(t, &evs[0], 1);

  /* Multiple packets, single poll */
  CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 0);
  efct_test_transmit(t, 8);
  efct_test_tx_complete(t, 6);
  efct_test_tx_complete(t, 2);
  CHECK(ef_eventq_poll(t->vi, evs, 8), ==, 2);
  efct_test_handle_tx_event(t, &evs[0], 6);
  efct_test_handle_tx_event(t, &evs[1], 2);

  /* Multiple packets, multiple polls */
  CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 0);
  efct_test_transmit(t, 16);
  for( i = 0; i < 16; i++ )
    efct_test_tx_complete(t, 1);
  CHECK(ef_eventq_poll(t->vi, evs, 8), ==, 8);
  for( i = 0; i < 8; i++ )
    efct_test_handle_tx_event(t, &evs[i], 1);
  CHECK(ef_eventq_poll(t->vi, evs, 8), ==, 8);
  for( i = 0; i < 8; i++ )
    efct_test_handle_tx_event(t, &evs[i], 1);
  CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 0);

  /* Check large merges get split into multiple events */
  efct_test_transmit(t, 256);
  efct_test_tx_complete(t, 2 * EF_VI_TRANSMIT_BATCH);
  CHECK(ef_eventq_poll(t->vi, evs, 8), ==, 2);
  for( i = 0; i < 2; i++ )
    efct_test_handle_tx_event(t, &evs[i], EF_VI_TRANSMIT_BATCH);

  efct_test_cleanup(t);
}

static void test_efct_polling_rx_evs_evq_overflow(void)
{
  const unsigned n_rxqs = 3;
  const unsigned rxq_size = 1 * PKTS_PER_SB;
  const unsigned txq_size = 512;
  /* We don't consider the extra time-sync events here that might occur if we
   * were to have a VI with timestamping enabled */
  const unsigned evq_size = rxq_size * n_rxqs + txq_size;
  const unsigned max_rx_pkts = PKTS_PER_SB - meta_offset;
  const unsigned max_tx_pkts = txq_size - 1;
  struct efct_test* t = efct_test_init_tx_x3(n_rxqs, evq_size, txq_size);
  ci_qword_t event = { 0 };
  /* Arbitrary number of packets to RX before posting an RX rollover event */
  int rollover_pkts = 7;
  int other_q_pkts = 0;
  int start_pkts = 0;
  ef_event evs[16];
  int rxq, i;

  /* Attach to all RXQs */
  for( rxq = 0; rxq < n_rxqs; rxq++ ) {
    /* Worth noting that QID == QIX in this test harness */
    t->vi->ep_state->rxq.efct_state[rxq].generates_events = true;
    efct_test_attach_only(t, rxq, false, 0, 0);
  }

  for( rxq = 0; rxq < n_rxqs; rxq++ ) {
    efct_test_rollover(t, rxq, 0, 1, false, false);
    t->vi->ep_state->rxq.n_evq_rx_pkts += rxq_size;
    efct_test_rollover(t, rxq, 0, 1, true, false);
  }

  /* Transmit as many packets as we can (before polling), leaving a couple
   * to interleave between RX events. */
  for( i = 0; i < max_tx_pkts - n_rxqs; i++ ) {
    efct_test_transmit(t, 1);
    efct_test_tx_complete(t, 1);
  }

  /* Receive as many packets as we can (before polling) */
  for( rxq = 0; rxq < n_rxqs; rxq++ ) {
    int rx_pkts = 0;
    while( ! efct_test_rxq_finished_superbuf(t, rxq) ) {
      efct_test_rx_meta(t, rxq);
      efct_test_rx_complete(t, rxq, 1);
      rx_pkts++;
    }
    CHECK(rx_pkts, ==, max_rx_pkts);

    /* Place a TX event after each batch of RX events */
    efct_test_transmit(t, 1);
    efct_test_tx_complete(t, 1);
  }
  CHECK(t->tx_completions, ==, max_tx_pkts);
  CHECK(ef_vi_transmit_space(t->vi), ==, 0);

  /* At this point, we've posted as many events as we're able to. Importantly,
   * this value should always leave at least one empty slot in the EVQ to allow
   * overflow detection, this is guaranteed by the transmit space. */
  event = last_evq_event;
  for( i = 0; i < evq_size - max_tx_pkts - (n_rxqs * max_rx_pkts); i++ ) {
    ci_qword_t dummy_event = { 0 };
    CHECK(efct_test_evq_overflowed(t), ==, false);
    efct_test_push_event(t, dummy_event);
  }

  /* After filling in the remaining slots in the EVQ, we should have overflowed
   * by now, having consumed exactly every single slot in the EVQ. */
  CHECK(efct_test_evq_overflowed(t), ==, true);

  /* Roll back the rest, we don't keep enough context to properly roll these
   * back, but this will at least guarantee the phase is correct, and will put
   * the evq_write_ptr back in the correct place. */
  last_evq_event = event;
  efct_test_rollback_event(t);
  CHECK(efct_test_evq_overflowed(t), ==, false);
  while( --i > 0 )
    efct_test_rollback_event(t);

  /* Consume all of the RX packets by directly looking into the superbuf */
  for( rxq = 0; rxq < n_rxqs; rxq++ ) {
    int remaining;

    for( i = 0; i < max_rx_pkts / 16; i++ )
      efct_test_rx_poll(t, rxq, 16, 16);

    remaining = max_rx_pkts - i * 16;
    if( remaining )
      efct_test_rx_poll(t, rxq, remaining, remaining);

    /* If the meta offset is in another superbuf, then we need to poll the last
     * packet there */

    if( meta_offset == 0 ) {
      STATE_CHECK(t->mock_ops, anything_called, 1);
      STATE_CHECK(t->mock_ops, free_called, 1);
      STATE_CHECK(t->mock_ops, free_qid, rxq);
      STATE_CHECK(t->mock_ops, free_sbid, 0);
    }
  }

  /* Eat up all the TX events in the TX EVQ */
  for( i = 0; i < max_tx_pkts - n_rxqs; i++ ) {
    CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 1);
    efct_test_handle_tx_event(t, &evs[0], 1);
  }

  /* Next time we poll, we shouldn't end up calling `next` because RX polling
   * happens before TX polling. As such, the only effect we should observe is
   * that n_evq_rx_pkts fills up with all of the created RX events. */
  CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, ==, 0);
  STATE_CHECK(t->mock_ops, next_called, 0);
  STATE_CHECK(t->mock_ops, anything_called, 0);

  /* In this case, we have consumed 511 packets (and all descriptors) in a buf,
   * so we need to poll again to get a rollover. Notably, the current solution
   * is not designed for meta_offset == 1 but it should work well with it as
   * long as we can rely on other buffers being consumed and letting us steal
   * their final packet. */
  if( meta_offset == 1 ) {
    CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 1);
    efct_test_handle_tx_event(t, &evs[0], 1);

    for( rxq = 0; rxq < n_rxqs - 1; rxq++ ) {
      int n_evq_rx_pkts = t->vi->ep_state->rxq.n_evq_rx_pkts;

      CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 1);
      efct_test_handle_tx_event(t, &evs[0], 1);
      CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, ==, n_evq_rx_pkts + max_rx_pkts);
      CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, >=, PKTS_PER_SB);
      CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, <, 2 * PKTS_PER_SB);

      efct_test_rollover(t, rxq, 1, 1, true, rxq == 0);
    }

    /* The final superbuf won't be allowed to rollover because the other RXQs
     * have "stolen" it's packet. */
    CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 0);
    CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, ==, PKTS_PER_SB - n_rxqs);
    efct_test_rollover(t, rxq, 1, 1, false, false);

    /* RX enough packets to rxq0 to allow the last rxq to rollover */
    for( i = 0; i < n_rxqs; i++ ) {
      efct_test_rx_meta(t, 0);
      efct_test_rx_complete(t, 0, 1);
    }
    efct_test_rx_poll(t, 0, n_rxqs, 16);
    STATE_CHECK(t->mock_ops, anything_called, 1);
    STATE_CHECK(t->mock_ops, free_called, 1);
    STATE_CHECK(t->mock_ops, free_qid, 0);
    STATE_CHECK(t->mock_ops, free_sbid, 0);

    efct_test_rollover(t, rxq, 1, 1, true, false);

    /* Force a free of the remaining RXQs */
    for( rxq = 1; rxq < n_rxqs; rxq++ ) {
      efct_test_rx_meta(t, rxq);
      efct_test_rx_complete(t, rxq, 1);
      efct_test_rx_poll(t, rxq, 1, 16);
      STATE_CHECK(t->mock_ops, anything_called, 1);
      STATE_CHECK(t->mock_ops, free_called, 1);
      STATE_CHECK(t->mock_ops, free_qid, rxq);
      STATE_CHECK(t->mock_ops, free_sbid, 0);
    }
  } else {
    for( rxq = 0; rxq < n_rxqs; rxq++ ) {
      int n_evq_rx_pkts = t->vi->ep_state->rxq.n_evq_rx_pkts;

      CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 1);
      efct_test_handle_tx_event(t, &evs[0], 1);
      CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, ==, n_evq_rx_pkts + max_rx_pkts);
      CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, >=, PKTS_PER_SB);
      CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, <, 2 * PKTS_PER_SB);

      efct_test_rollover(t, rxq, 1, 1, true, rxq != n_rxqs - 1);
    }
  }

  /* Put a packet on each other RXQ so we can verify these are treated
   * independently in the rollover case. */
  for( rxq = 1; rxq < n_rxqs; rxq++ ) {
    efct_test_rx_meta(t, rxq);
    efct_test_rx_complete(t, rxq, 1);
    efct_test_rx_poll(t, rxq, 1, 16);
  }
  other_q_pkts = n_rxqs - 1;

  /* Verify that the our accounting is correct for the first batch, and make
   * sure (later) that these are handled even from a separate poll. */
  start_pkts = (meta_offset == 1) ? n_rxqs - 1 : 0;
  rxq = 0;
  CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, ==, start_pkts + other_q_pkts);
  for( i = 0; i < rollover_pkts / 2; i++ ) {
    efct_test_rx_meta(t, rxq);
    efct_test_rx_complete(t, rxq, 1);
  }
  efct_test_rx_poll(t, rxq, rollover_pkts / 2, 16);
  CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, ==,
        start_pkts + other_q_pkts + rollover_pkts / 2);

  /* Send the remaining packets, write the rollover packet to the buffer, then
   * verify that the buffer is freed and our accounting only has the remaining
   * number of packets from other queues. */
  for( ; i < rollover_pkts; i++ ) {
    efct_test_rx_meta(t, rxq);
    efct_test_rx_complete(t, rxq, 1);
  }
  efct_test_rx_meta_extra(t, rxq, 1ull << EFCT_RX_HEADER_ROLLOVER_LBN, 0);
  efct_test_rx_poll(t, rxq, rollover_pkts - rollover_pkts / 2, 16);
  CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, ==, other_q_pkts);
  STATE_CHECK(t->mock_ops, anything_called, 1);
  STATE_CHECK(t->mock_ops, free_called, 1);
  STATE_CHECK(t->mock_ops, free_qid, rxq);
  STATE_CHECK(t->mock_ops, free_sbid, 1);

  /* Finally, put the rollover event in the event queue and make sure we manage
   * to rollover properly. */
  efct_test_rx_rollover_ev(t, rxq);
  CHECK(ef_eventq_poll(t->vi, evs, 1), ==, 0);
  CHECK(t->vi->ep_state->rxq.n_evq_rx_pkts, ==, other_q_pkts + PKTS_PER_SB);
  efct_test_rollover(t, rxq, 2, 1, true, false);

  efct_test_cleanup(t);
}

int main(void)
{
  for( meta_offset = 0; meta_offset < 2; ++meta_offset ) {
    TEST_RUN(test_efct_idle);
    TEST_RUN(test_efct_attach_local);
    TEST_RUN(test_efct_attach_shared);
    TEST_RUN(test_efct_refresh);
    TEST_RUN(test_efct_rx);
    TEST_RUN(test_efct_rx_discard);
    TEST_RUN(test_efct_natural_rollover);
    TEST_RUN(test_efct_forced_rollover_none);
    TEST_RUN(test_efct_forced_rollover_some);
    TEST_RUN(test_efct_forced_rollover_all);
    TEST_RUN(test_efct_future);
    TEST_RUN(test_efct_tx);
    TEST_RUN(test_efct_polling_rx_evs_evq_overflow);
  }
  TEST_END();
}
