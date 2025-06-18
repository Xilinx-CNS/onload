/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */

#include <linux/mman.h>
#include "ef_vi_internal.h"
#include "logging.h"
#include <etherfabric/vi.h>
#include <etherfabric/efct_vi.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/efhw/common.h>
#include <ci/tools/byteorder.h>
#include <ci/tools/sysdep.h>


#define EF_VI_EVENT_OFFSET(q, i)                                \
  (((q)->ep_state->evq.evq_ptr + (i) * sizeof(ef_vi_qword)) &   \
   (q)->evq_mask)

#define EF_VI_EVENT_PTR(q, i)                                           \
  ((ef_vi_qword*) ((q)->evq_base + EF_VI_EVENT_OFFSET((q), (i))))

#define EFCT_PHASE_LBN 59
#define EFCT_PHASE_WIDTH 1
#define EF_VI_EVENT_PHASE(evp)                  \
  QWORD_GET_U(EFCT_PHASE, *(evp))

#define EF_VI_EVQ_PHASE(q, i)                                     \
  ((((q)->ep_state->evq.evq_ptr + sizeof(ef_vi_qword) * (i)) &    \
    ((q)->evq_mask + 1)) != 0)


static int efct_ef_eventq_has_many_events(const ef_vi* vi, int n_events)
{
  ef_vi_qword* ev;

  EF_VI_ASSERT(vi->evq_base);
  EF_VI_BUG_ON(n_events < 0);

  ev = EF_VI_EVENT_PTR(vi, n_events);
  return (EF_VI_EVENT_PHASE(ev) == EF_VI_EVQ_PHASE(vi, n_events));
}


#define M_(FIELD) (CI_MASK64(FIELD ## _WIDTH) << FIELD ## _LBN)
#define M(FIELD) M_(EFCT_RX_HEADER_ ## FIELD)
#define CHECK_FIELDS (M(L2_STATUS) | M(L3_STATUS) | M(L4_STATUS) | M(ROLLOVER))

/* pkt_ids are:
 *  bits 0..15 packet index in superbuf
 *  bits 16..26 superbuf index
 *  bits 27..29 rxq (as an index in to vi->efct_rxqs.q, not as a hardware ID)
 *  bits 30..31 unused/zero
 *  [NB: bit 31 is stolen by some users to cache the superbuf's sentinel]
 * This layout is not part of the stable ABI. rxq index is slammed up against
 * superbuf index to allow for dirty tricks where we mmap all superbufs in
 * contiguous virtual address space and thus avoid some arithmetic.
 */

#define PKT_ID_PKT_BITS  16
#define PKT_ID_SBUF_BITS 11
#define PKT_ID_RXQ_BITS   3
#define PKT_ID_TOTAL_BITS (PKT_ID_PKT_BITS + PKT_ID_SBUF_BITS + PKT_ID_RXQ_BITS)

/* Enforce compile-time restrictions on the pkt_id fields */
static inline void assert_pkt_id_fields(void)
{
  /* Packet index must be large enough for the number of packets in a superbuf.
   * We check against the expected value here, and (at runtime) against the
   * actual value provided by the driver in rx_rollover.
   *
   * The value of 16 is fairly arbitrary and could be reduced to 9 if more
   * bits are needed elsewhere.
   */
  EF_VI_BUILD_ASSERT((1u << PKT_ID_PKT_BITS) >=
                     (EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE));

  /* Superbuf index must be exactly the right size for the number of superbufs
   * per rxq, since the two fields are combined to give the global index.
   *
   * In principle, CI_EFCT_MAX_SUPERBUFS can be changed, but the bitfield size
   * must be changed to match.
   */
  EF_VI_BUILD_ASSERT((1u << PKT_ID_SBUF_BITS) == CI_EFCT_MAX_SUPERBUFS);

  /* Queue index must be large enough for the number of queues. */
  EF_VI_BUILD_ASSERT((1u << PKT_ID_RXQ_BITS) >= EF_VI_MAX_EFCT_RXQS);

  /* Bit 31 must be available for abuse. */
  EF_VI_BUILD_ASSERT(PKT_ID_TOTAL_BITS <= 31);
}

static int pkt_id_to_index_in_superbuf(uint32_t pkt_id)
{
  return pkt_id & ((1u << PKT_ID_PKT_BITS) - 1);
}

static int pkt_id_to_global_superbuf_ix(uint32_t pkt_id)
{
  EF_VI_ASSERT(pkt_id >> PKT_ID_TOTAL_BITS == 0);
  return pkt_id >> PKT_ID_PKT_BITS;
}

static int pkt_id_to_local_superbuf_ix(uint32_t pkt_id)
{
  return pkt_id_to_global_superbuf_ix(pkt_id) & (CI_EFCT_MAX_SUPERBUFS - 1);
}

static int pkt_id_to_rxq_ix(uint32_t pkt_id)
{
  return pkt_id_to_global_superbuf_ix(pkt_id) / CI_EFCT_MAX_SUPERBUFS;
}

struct efct_rx_descriptor*
efct_rx_desc_for_sb(ef_vi* vi, uint32_t ix, uint32_t sbid)
{
  ef_vi_rxq* q = &vi->vi_rxq;
  struct efct_rx_descriptor* desc = q->descriptors;
  return desc + ((ix * CI_EFCT_MAX_SUPERBUFS) | sbid);
}

static bool efct_rxq_is_active(const ef_vi_efct_rxq* rxq)
{
  return *rxq->live.superbuf_pkts != 0;
}

/* The superbuf descriptor for this packet */
static struct efct_rx_descriptor* efct_rx_desc(ef_vi* vi, uint32_t pkt_id)
{
  ef_vi_rxq* q = &vi->vi_rxq;
  struct efct_rx_descriptor* desc = q->descriptors;
  return desc + pkt_id_to_global_superbuf_ix(pkt_id);
}

/* The header preceding this packet. Note: this contains metadata for the
 * previous packet, not this one. */
static const ci_oword_t* efct_rx_header(const ef_vi* vi, size_t pkt_id)
{
  /* Sneakily rely on vi->efct_rxqs.q[i].superbuf being contiguous, avoiding
   * extra arithmetic to extract the queue and sbuf ids separately. */
  const char* base =
    efct_superbuf_access(vi, 0, pkt_id_to_global_superbuf_ix(pkt_id));

  unsigned ix = pkt_id_to_index_in_superbuf(pkt_id);
  EF_VI_ASSERT(ix < *vi->efct_rxqs.q[pkt_id_to_rxq_ix(pkt_id)].live.superbuf_pkts);

  return (const ci_oword_t*)(base + ix * EFCT_PKT_STRIDE);
}

static uint32_t rxq_ptr_to_pkt_id(uint32_t ptr)
{
  /* Masking off the sentinel */
  return ptr & 0x7fffffff;
}

static int rxq_ptr_to_sentinel(uint32_t ptr)
{
  return ptr >> 31;
}

static bool efct_rxq_need_rollover(const ef_vi_efct_rxq_ptr* rxq_ptr)
{
  return pkt_id_to_index_in_superbuf(rxq_ptr->meta_pkt) >= rxq_ptr->superbuf_pkts;
}

static bool efct_rxq_need_config(const ef_vi_efct_rxq* rxq)
{
  return *rxq->live.config_generation != rxq->config_generation;
}

/* The header following the next packet, or null if not available.
 * `meta_pkt` contains both the packet id and sentinel. */
static const ci_oword_t* efct_rx_next_header(const ef_vi* vi, uint32_t meta_pkt)
{
  const ci_oword_t* header = efct_rx_header(vi, rxq_ptr_to_pkt_id(meta_pkt));
  int sentinel = CI_QWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL);
  bool pkt_available = sentinel == rxq_ptr_to_sentinel(meta_pkt);
#ifndef NDEBUG
  /* Given that user specified extensions are not supported, we expect 'user' to
   * be zero on efct when a packet has arrived. This is not guaranteed by the
   * efct host spec but the RTL currently sets these bits to zero. It is very
   * unlikely for this to change. This means we can later perform a 16 bit
   * read of filter_id despite the field being 10 bits on efct but 16 bits on
   * ef10ct.*/
  uint8_t user = CI_OWORD_FIELD(*header, EFCT_RX_HEADER_USER);
  EF_VI_ASSERT(!(pkt_available && ef_vi_get_real_arch(vi) == EF_VI_ARCH_EFCT &&
                 user != 0));
#endif

  return pkt_available ? header : NULL;
}

/* Check for actions needed on an rxq. This must match the checks made in
 * efct_poll_rx to ensure none are missed. */
static bool efct_rxq_check_event(const ef_vi* vi, int qid)
{
  const ef_vi_efct_rxq* rxq = &vi->efct_rxqs.q[qid];
  const ef_vi_efct_rxq_ptr* rxq_ptr = &vi->ep_state->rxq.rxq_ptr[qid];
  uint32_t meta_pkt;

  if( ! efct_rxq_is_active(rxq) )
    return false;

  /* This function might be called concurrently with polling (by onload,
   * but not by legitimate ef_vi applications), so make sure we use the same
   * value to check for rollover and access the next header */
  meta_pkt = OO_ACCESS_ONCE(rxq_ptr->meta_pkt);
  if( pkt_id_to_index_in_superbuf(meta_pkt) >= rxq_ptr->superbuf_pkts )
#ifndef __KERNEL__
    /* only signal new event if rollover can be done */
    return vi->efct_rxqs.ops->available(vi, qid);
#else
    /* Returning no event interferes with oo_handle_wakeup_int_driven
     * Let the interrupt handler deal with the event */
    return true;
#endif

  return efct_rxq_need_config(rxq) || efct_rx_next_header(vi, meta_pkt) != NULL;
}

/* Check whether a received packet is available */
static bool efct_rx_check_event(const ef_vi* vi)
{
  int i;

  if( ! vi->vi_rxq.mask )
    return false;
  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i )
    if( efct_rxq_check_event(vi, i) )
      return true;
  return false;
}

/* state of a partially-completed tx operation */
struct efct_tx_state
{
  /* base address of the aperture */
  volatile uint64_t* aperture;
  /* up to 7 bytes left over after writing a block in 64-bit chunks */
  uint64_t tail;
  /* number of left over bytes in 'tail' */
  unsigned tail_len;
  /* number of 64-bit words from start of aperture */
  uint64_t offset;
  /* mask to keep offset within the aperture range */
  uint64_t mask;
};

/* generic tx header */
ci_inline uint64_t efct_tx_header(unsigned packet_length, unsigned ct_thresh,
                               unsigned timestamp_flag, unsigned warm_flag,
                               unsigned action)
{
  ci_qword_t qword;

  RANGECHCK(packet_length, EFCT_TX_HEADER_PACKET_LENGTH_WIDTH);
  RANGECHCK(ct_thresh, EFCT_TX_HEADER_CT_THRESH_WIDTH);
  RANGECHCK(timestamp_flag, EFCT_TX_HEADER_TIMESTAMP_FLAG_WIDTH);
  RANGECHCK(warm_flag, EFCT_TX_HEADER_WARM_FLAG_WIDTH);
  RANGECHCK(action, EFCT_TX_HEADER_ACTION_WIDTH);

  CI_POPULATE_QWORD_5(qword,
      EFCT_TX_HEADER_PACKET_LENGTH, packet_length,
      EFCT_TX_HEADER_CT_THRESH, ct_thresh,
      EFCT_TX_HEADER_TIMESTAMP_FLAG, timestamp_flag,
      EFCT_TX_HEADER_WARM_FLAG, warm_flag,
      EFCT_TX_HEADER_ACTION, action);

  return qword.u64[0];
}

/* tx header for standard (non-templated) send */
ci_inline uint64_t
efct_tx_pkt_header(ef_vi* vi, unsigned length, unsigned ct_thresh)
{
  return efct_tx_header(length, ct_thresh, 0, 0, 0) |
         vi->vi_txq.efct_fixed_header;
}

/* check that we have space to send a packet of this length */
ci_inline bool efct_tx_check(ef_vi* vi, int len)
{
  /* We require the txq to be large enough for the maximum number of packets
   * which can be written to the FIFO. Each packet consumes at least 64 bytes.
   */
  BUG_ON((vi->vi_txq.mask + 1) <
         (vi->vi_txq.ct_fifo_bytes + EFCT_TX_HEADER_BYTES) / EFCT_TX_ALIGNMENT);

  return ef_vi_transmit_space_bytes(vi) >= len;
}

/* initialise state for a transmit operation */
ci_inline void efct_tx_init(ef_vi* vi, struct efct_tx_state* tx)
{
  unsigned offset = vi->ep_state->txq.ct_added;
  BUG_ON(offset % EFCT_TX_ALIGNMENT != 0);
  tx->aperture = (void*) vi->vi_ctpio_mmap_ptr;
  tx->tail = 0;
  tx->tail_len = 0;
  tx->offset = offset >> 3;
  tx->mask = vi->vi_txq.efct_aperture_mask;
}

/* store a left-over byte from the start or end of a block */
ci_inline void efct_tx_tail_byte(struct efct_tx_state* tx, uint8_t byte)
{
  BUG_ON(tx->tail_len >= 8);
  tx->tail = (tx->tail << 8) | byte;
  tx->tail_len++;
}

/* write a 64-bit word to the CTPIO aperture, dealing with wrapping */
ci_inline void efct_tx_word(struct efct_tx_state* tx, uint64_t value)
{
  tx->aperture[tx->offset++ & tx->mask] = value;
}

/* write a block of bytes to the CTPIO aperture, dealing with wrapping and leftovers */
ci_inline void efct_tx_block(struct efct_tx_state* __restrict__ tx, char* base, int len)
{
  if( tx->tail_len != 0 ) {
    while( len > 0 && tx->tail_len < 8 ) {
      efct_tx_tail_byte(tx, *base);
      base++;
      len--;
    }

    if( tx->tail_len == 8 ) {
      efct_tx_word(tx, CI_BSWAP_BE64(tx->tail));
      tx->tail = 0;
      tx->tail_len = 0;
    }
  }

  while( len >= 8 ) {
    efct_tx_word(tx, *(uint64_t*)base);
    base += 8;
    len -= 8;
  }

  while( len > 0 ) {
    efct_tx_tail_byte(tx, *base);
    base++;
    len--;
  }
}

/* complete a tx operation, writing leftover bytes and padding as needed */
ci_inline void efct_tx_complete(ef_vi* vi, struct efct_tx_state* tx, uint32_t dma_id, int len)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  struct efct_tx_descriptor* desc = q->descriptors;
  int i = qs->added & q->mask;

  if( tx->tail_len != 0 ) {
    tx->tail <<= (8 - tx->tail_len) * 8;
    efct_tx_word(tx, CI_BSWAP_BE64(tx->tail));
  }
  while( tx->offset % (EFCT_TX_ALIGNMENT >> 3) != 0 )
    efct_tx_word(tx, 0);

  /* Force the write-combined traffic to be flushed to PCIe, to limit the
   * maximum possible reordering the NIC will see to one packet. Benchmarks
   * demonstrate that this sfence is well-parallelised by the CPU, so smarter
   * algorithms trying to avoid it for small packets are unlikely to be
   * cost-effective */
#if defined __x86_64__ || defined __i386__
  /* Our compat tools define ci_wmb() as just a compiler fence on x86, since
   * that's usually right due to TSO. Not in this case. */
  ci_x86_sfence();
#else
  ci_wmb();
#endif

  len = CI_ROUND_UP(len + EFCT_TX_HEADER_BYTES, EFCT_TX_ALIGNMENT);
  desc[i].len = len;
  q->ids[i] = dma_id;
  qs->ct_added += len;
  qs->added += 1;
}

/* get a tx completion event, or null if no valid event available */
ci_inline ci_qword_t* efct_tx_get_event(const ef_vi* vi, uint32_t evq_ptr)
{
  ci_qword_t* event = (ci_qword_t*)(vi->evq_base + (evq_ptr & vi->evq_mask));

  int expect_phase = (evq_ptr & (vi->evq_mask + 1)) != 0;
  int actual_phase = CI_QWORD_FIELD(*event, EFCT_EVENT_PHASE);

  return actual_phase == expect_phase ? event : NULL;
}

/* check whether a tx completion event is available */
ci_inline bool efct_tx_check_event(const ef_vi* vi)
{
  return vi->evq_mask && efct_tx_get_event(vi, vi->ep_state->evq.evq_ptr);
}

/* Writes an unsolicited credit sequence value (max 7-bit wide) to the appropiate 
 * register. This function should be called on timesync events, and upon an 
 * unsolicited_credit_overflow. The sequence should correspond to how many 
 * unsolicited credit events have been seen + a small buffer extra. When this
 * extra buffer is consumed, an unsolicited credit overflow is expected, and
 * the register should be reset with a sensible default. */
static void efct_grant_unsol_credit(ef_vi* vi, bool clear_overflow, uint32_t credit_seq)
{
  uint32_t* unsol_reg = (void*) (vi->io + EFCT_EVQ_UNSOL_CREDIT_REGISTER_OFFSET);
  ci_qword_t qword;

  credit_seq &= vi->unsol_credit_seq_mask;
  CI_POPULATE_QWORD_2(qword,
                      EFCT_EVQ_UNSOL_GRANT_SEQ, credit_seq,
                      EFCT_EVQ_UNSOL_CLEAR_OVERFLOW, clear_overflow);

  writel(qword.u64[0], unsol_reg);
}

/* handle a tx completion event */
static void efct_tx_handle_event(ef_vi* vi, ci_qword_t event, ef_event* ev_out,
                                bool* again)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  struct efct_tx_descriptor* desc = vi->vi_txq.descriptors;

  unsigned count;
  unsigned seq = CI_QWORD_FIELD(event, EFCT_TX_EVENT_SEQUENCE);
  unsigned seq_mask = (1 << EFCT_TX_EVENT_SEQUENCE_WIDTH) - 1;

  /* Count is inclusive bound of descriptors but should be limited to
   * advancing EF_VI_TRANSMIT_BATCH descriptors per ef_event*/
  count =  (seq + 1 - qs->previous) & seq_mask;
  *again = count > EF_VI_TRANSMIT_BATCH;
  if( unlikely(*again) )
    count = EF_VI_TRANSMIT_BATCH;

  while( count-- ) {
    BUG_ON(qs->previous == qs->added);
    qs->ct_removed += desc[qs->previous & q->mask].len;
    qs->previous += 1;
  }

  if( CI_QWORD_FIELD(event, EFCT_TX_EVENT_TIMESTAMP_STATUS) ) {
    uint64_t ptstamp;
    uint32_t ptstamp_seconds;
    uint32_t timesync_seconds;

    EF_VI_ASSERT(vi->vi_flags & EF_VI_TX_TIMESTAMPS);
    ptstamp = CI_QWORD_FIELD64(event, EFCT_TX_EVENT_PARTIAL_TSTAMP);
    ptstamp_seconds = ptstamp >> 32;
    timesync_seconds = (vi->ep_state->evq.sync_timestamp_major & 0xFF);
    ev_out->tx_timestamp.ts_sec = vi->ep_state->evq.sync_timestamp_major;
    if ( ptstamp_seconds == ((timesync_seconds + 1) % 256) ) {
      ev_out->tx_timestamp.ts_sec++;
    }
    ev_out->tx_timestamp.ts_nsec = (ptstamp & 0xFFFFFFFF) >> vi->ts_subnano_bits;
    /* We assert that there is enough space to store the number of subnano bits
     * in efct_design_parameters, so we can have confidence that we are safely
     * populating ts_nsec_frac. */
    ev_out->tx_timestamp.ts_nsec_frac =
                  ptstamp << (EF_VI_TX_TS_FRAC_NS_BITS - vi->ts_subnano_bits);
    ev_out->tx_timestamp.ts_flags = vi->ep_state->evq.sync_flags;
    ev_out->tx_timestamp.type = EF_EVENT_TYPE_TX_WITH_TIMESTAMP;
    ev_out->tx_timestamp.rq_id = q->ids[(qs->previous - 1) & q->mask];
    ev_out->tx_timestamp.flags = EF_EVENT_FLAG_CTPIO;
    ev_out->tx_timestamp.q_id = CI_QWORD_FIELD(event, EFCT_TX_EVENT_LABEL);
    /* Delivering the tx event with timestamp counts as removing it, as we
     * must only be delivering a single event, so _unbundle isn't used. */
    qs->removed++;

  } else {
    ev_out->tx.type = EF_EVENT_TYPE_TX;
    ev_out->tx.desc_id = qs->previous;
    ev_out->tx.flags = EF_EVENT_FLAG_CTPIO;
    ev_out->tx.q_id = CI_QWORD_FIELD(event, EFCT_TX_EVENT_LABEL);
  }
}

static int efct_ef_vi_transmit(ef_vi* vi, ef_addr base, int len,
                               ef_request_id dma_id)
{
  /* TODO need to avoid calling this with CTPIO fallback buffers */
  struct efct_tx_state tx;

  if( ! efct_tx_check(vi, len) )
    return -EAGAIN;

  efct_tx_init(vi, &tx);
  efct_tx_word(&tx, efct_tx_pkt_header(vi, len, EFCT_TX_CT_DISABLE));
  efct_tx_block(&tx, (void*)(uintptr_t)base, len);
  efct_tx_complete(vi, &tx, dma_id, len);

  return 0;
}

static int efct_ef_vi_transmitv(ef_vi* vi, const ef_iovec* iov, int iov_len,
                                ef_request_id dma_id)
{
  struct efct_tx_state tx;
  int len = 0, i;

  efct_tx_init(vi, &tx);

  for( i = 0; i < iov_len; ++i )
    len += iov[i].iov_len;

  if( ! efct_tx_check(vi, len) )
    return -EAGAIN;

  efct_tx_word(&tx, efct_tx_pkt_header(vi, len, EFCT_TX_CT_DISABLE));

  for( i = 0; i < iov_len; ++i )
    efct_tx_block(&tx, (void*)(uintptr_t)iov[i].iov_base, iov[i].iov_len);

  efct_tx_complete(vi, &tx, dma_id, len);

  return 0;
}

static void efct_ef_vi_transmit_push(ef_vi* vi)
{
}

static int efct_ef_vi_transmit_pio(ef_vi* vi, int offset, int len,
                                   ef_request_id dma_id)
{
  return -EOPNOTSUPP;
}

static int efct_ef_vi_transmit_copy_pio(ef_vi* vi, int offset,
                                        const void* src_buf, int len,
                                        ef_request_id dma_id)
{
  return -EOPNOTSUPP;
}

static void efct_ef_vi_start_transmit_warm(ef_vi* vi,
                                           ef_vi_tx_warm_state* saved_state,
                                           char* warm_ctpio_mmap_ptr)
{
  ci_qword_t qword;
  qword.u64[0] = vi->vi_txq.efct_fixed_header;

  EF_VI_ASSERT(CI_QWORD_FIELD(qword, EFCT_TX_HEADER_WARM_FLAG) == 0);

  CI_SET_QWORD_FIELD(qword, EFCT_TX_HEADER_WARM_FLAG, 1);
  vi->vi_txq.efct_fixed_header = qword.u64[0];
}

static void efct_ef_vi_stop_transmit_warm(ef_vi* vi,
                                          ef_vi_tx_warm_state* saved_state)
{
  ci_qword_t qword;
  qword.u64[0] = vi->vi_txq.efct_fixed_header;

  EF_VI_ASSERT(CI_QWORD_FIELD(qword, EFCT_TX_HEADER_WARM_FLAG) == 1);

  CI_SET_QWORD_FIELD(qword, EFCT_TX_HEADER_WARM_FLAG, 0);
  vi->vi_txq.efct_fixed_header = qword.u64[0];
}

static void efct_ef_vi_transmit_pio_warm(ef_vi* vi)
{
}

static void efct_ef_vi_transmit_copy_pio_warm(ef_vi* vi, int pio_offset,
                                              const void* src_buf, int len)
{
}

static bool tx_warm_active(ef_vi* vi)
{
  ci_qword_t qword;
  qword.u64[0] = vi->vi_txq.efct_fixed_header;
  return CI_QWORD_FIELD(qword, EFCT_TX_HEADER_WARM_FLAG);
}

#define EFCT_TX_POSTED_ID 0xefc7efc7
static void efct_ef_vi_transmitv_ctpio(ef_vi* vi, size_t len,
                                       const struct iovec* iov, int iovcnt,
                                       unsigned threshold)
{
  struct efct_tx_state tx;
  unsigned threshold_extra;
  int i;
  uint32_t dma_id;

  /* If we didn't have space then we must report this in _fallback and have
   * another go */
  vi->last_ctpio_failed = !efct_tx_check(vi, len);
  if(unlikely( vi->last_ctpio_failed ))
    return;
  efct_tx_init(vi, &tx);

  /* ef_vi interface takes threshold in bytes, but the efct hardware interface
   * takes multiples of 64 (rounded up), and includes the 8-byte header in the
   * count. Anything too big to fit in the field is equivalent to disabling
   * cut-through; test that first to avoid arithmetic overflow.
   */
  threshold_extra = EFCT_TX_HEADER_BYTES + EFCT_TX_ALIGNMENT - 1;
  if( threshold > EFCT_TX_CT_DISABLE * EFCT_TX_ALIGNMENT - threshold_extra )
    threshold = EFCT_TX_CT_DISABLE;
  else
    threshold = (threshold + threshold_extra) / EFCT_TX_ALIGNMENT;

  threshold = CI_MAX((unsigned)vi->vi_txq.ct_thresh_min, threshold);
  efct_tx_word(&tx, efct_tx_pkt_header(vi, len, threshold));

  for( i = 0; i < iovcnt; ++i )
    efct_tx_block(&tx, iov[i].iov_base, iov[i].iov_len);

  /* Use a valid but bogus dma_id rather than invalid EF_REQUEST_ID_MASK to
   * support tcpdirect, which relies on the correct return value from
   * ef_vi_transmit_unbundle to free its otherwise unused transmit buffers.
   *
   * For compat with existing ef_vi apps which will post a fallback and may
   * want to use the dma_id we'll replace this value with the real one then.
   *
   * For transmit warmup, use an invalid dma_id so that it is ignored.
   */
  dma_id = tx_warm_active(vi) ? EF_REQUEST_ID_MASK : EFCT_TX_POSTED_ID;
  efct_tx_complete(vi, &tx, dma_id, len);
}

static void efct_ef_vi_transmitv_ctpio_copy(ef_vi* vi, size_t frame_len,
                                            const struct iovec* iov, int iovcnt,
                                            unsigned threshold, void* fallback)
{
  int i;

  efct_ef_vi_transmitv_ctpio(vi, frame_len, iov, iovcnt, threshold);

  /* This could be made more efficient, if anyone cares enough */
  for( i = 0; i < iovcnt; ++i ) {
    memcpy(fallback, iov[i].iov_base, iov[i].iov_len);
    fallback = (char*)fallback + iov[i].iov_len;
  }
}

static inline int efct_ef_vi_ctpio_fallback(ef_vi* vi, ef_request_id dma_id)
{
  ef_vi_txq *q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  unsigned di = (qs->added - 1) & q->mask;

  EF_VI_BUG_ON(qs->added == qs->removed);
  EF_VI_BUG_ON(q->ids[di] != EFCT_TX_POSTED_ID);
  q->ids[di] = dma_id;

  return 0;
}

static int efct_ef_vi_transmit_ctpio_fallback(ef_vi* vi, ef_addr dma_addr,
                                              size_t len, ef_request_id dma_id)
{
  if(unlikely( vi->last_ctpio_failed )) {
    int rc = efct_ef_vi_transmit(vi, dma_addr, len, dma_id);
    vi->last_ctpio_failed = rc == -EAGAIN;
    return rc;
  }
  return efct_ef_vi_ctpio_fallback(vi, dma_id);
}


static int efct_ef_vi_transmitv_ctpio_fallback(ef_vi* vi,
                                               const ef_iovec* dma_iov,
                                               int dma_iov_len,
                                               ef_request_id dma_id)
{
  if(unlikely( vi->last_ctpio_failed )) {
    int rc = efct_ef_vi_transmitv(vi, dma_iov, dma_iov_len, dma_id);
    vi->last_ctpio_failed = rc == -EAGAIN;
    return rc;
  }
  return efct_ef_vi_ctpio_fallback(vi, dma_id);
}

static int efct_ef_vi_transmit_alt_select(ef_vi* vi, unsigned alt_id)
{
  return -EOPNOTSUPP;
}

static int efct_ef_vi_transmit_alt_select_default(ef_vi* vi)
{
  return -EOPNOTSUPP;
}

static int efct_ef_vi_transmit_alt_stop(ef_vi* vi, unsigned alt_id)
{
  return -EOPNOTSUPP;
}

static int efct_ef_vi_transmit_alt_go(ef_vi* vi, unsigned alt_id)
{
  return -EOPNOTSUPP;
}

static int efct_ef_vi_receive_set_discards(ef_vi* vi, unsigned discard_err_flags)
{
  discard_err_flags &= EF_VI_DISCARD_RX_L4_CSUM_ERR |
                       EF_VI_DISCARD_RX_L3_CSUM_ERR |
                       EF_VI_DISCARD_RX_ETH_FCS_ERR |
                       EF_VI_DISCARD_RX_ETH_LEN_ERR |
                       EF_VI_DISCARD_RX_L2_CLASS_OTHER |
                       EF_VI_DISCARD_RX_L3_CLASS_OTHER |
                       EF_VI_DISCARD_RX_L4_CLASS_OTHER;

  vi->rx_discard_mask = discard_err_flags;
  return 0;
}

static uint64_t efct_ef_vi_receive_get_discards(ef_vi* vi)
{
  return vi->rx_discard_mask;
}

static int efct_ef_vi_transmit_alt_discard(ef_vi* vi, unsigned alt_id)
{
  return -EOPNOTSUPP;
}

static int efct_ef_vi_receive_init(ef_vi* vi, ef_addr addr,
                                   ef_request_id dma_id)
{
  return -ENOSYS;
}

static void efct_ef_vi_receive_push(ef_vi* vi)
{
}

static int rx_rollover(ef_vi* vi, int qid)
{
  uint32_t meta_pkt;
  ef_vi_efct_rxq_ptr* rxq_ptr = &vi->ep_state->rxq.rxq_ptr[qid];
  unsigned sbseq;
  bool sentinel;
  struct efct_rx_descriptor* desc;

  int rc = vi->efct_rxqs.ops->next(vi, qid, &sentinel, &sbseq);
  if( rc < 0 )
    return rc;

  meta_pkt = (qid * CI_EFCT_MAX_SUPERBUFS + rc) << PKT_ID_PKT_BITS;

  if( rxq_ptr->meta_offset == 0 ) {
    /* Simple case, metadata located with data in the first new packet */
    rxq_ptr->data_pkt = meta_pkt;
  }
  else if( pkt_id_to_index_in_superbuf(rxq_ptr->meta_pkt) > rxq_ptr->superbuf_pkts ) {
    /* special case for when we want to ignore the first metadata
     * at queue startup or after manual rollover */
    rxq_ptr->data_pkt = meta_pkt;
    meta_pkt += rxq_ptr->meta_offset;
  }
  else if( sbseq != (rxq_ptr->meta_pkt >> 32) + 1 ) {
    /* nodescdrop on the swrxq. This is the same as the startup case, but it
     * also means that we're going to discard the last packet of the previous
     * superbuf */
    efct_vi_rxpkt_release(vi, rxq_ptr->data_pkt);
    rxq_ptr->data_pkt = meta_pkt;
    meta_pkt += rxq_ptr->meta_offset;
  }
  else {
    /* meta_pkt refers to the first packet of the new buffer,
     * data_pkt remains in the previous buffer.
     * store the final metadata packet id, to access the final timestamp */
    efct_rx_desc(vi, rxq_ptr->data_pkt)->final_meta_pkt = meta_pkt;
  }

  rxq_ptr->meta_pkt =
    ((uint64_t)sbseq << 32) | ((uint64_t)sentinel << 31) | meta_pkt;

  /* Preload the superbuf's refcount with all the (potential) packets in
   * it - more efficient than incrementing for each rx individually */
  EF_VI_ASSERT(rxq_ptr->superbuf_pkts > 0);
  EF_VI_ASSERT(rxq_ptr->superbuf_pkts < (1 << PKT_ID_PKT_BITS));
  desc = efct_rx_desc(vi, meta_pkt);
  desc->refcnt = rxq_ptr->superbuf_pkts;
  desc->superbuf_pkts = rxq_ptr->superbuf_pkts;

  return 0;
}

static void efct_rx_discard(int qid, uint32_t pkt_id, uint16_t discard_flags,
                            const ci_oword_t* header, ef_event* ev)
{
  ev->rx_ref_discard.type = EF_EVENT_TYPE_RX_REF_DISCARD;
  ev->rx_ref_discard.len = CI_OWORD_FIELD(*header,
                                             EFCT_RX_HEADER_PACKET_LENGTH);
  ev->rx_ref_discard.pkt_id = pkt_id;
  ev->rx_ref_discard.q_id = qid;
  ev->rx_ref_discard.filter_id = CI_OWORD_FIELD(*header, EFCT_RX_HEADER_FILTER);
  ev->rx_ref_discard.flags = discard_flags;
}

static inline uint16_t header_status_flags(const ci_oword_t *header)
{
  uint16_t flags = 0;

  if ( CI_OWORD_FIELD(*header, EFCT_RX_HEADER_L2_STATUS) ==
                      EFCT_RX_HEADER_L2_STATUS_FCS_ERR )
    flags |= EF_VI_DISCARD_RX_ETH_FCS_ERR;
  if ( CI_OWORD_FIELD(*header, EFCT_RX_HEADER_L2_STATUS) ==
                      EFCT_RX_HEADER_L2_STATUS_LEN_ERR )
    flags |= EF_VI_DISCARD_RX_ETH_LEN_ERR;
  if ( (CI_OWORD_FIELD(*header, EFCT_RX_HEADER_L3_CLASS) ==
                       EFCT_RX_HEADER_L3_CLASS_IP4) &&
       (header->u64[0] & M(L3_STATUS)) )
    flags |= EF_VI_DISCARD_RX_L3_CSUM_ERR;
  if ( (CI_OWORD_FIELD(*header, EFCT_RX_HEADER_L3_CLASS) ==
                       EFCT_RX_HEADER_L3_CLASS_IP6) &&
       (header->u64[0] & M(L3_STATUS)) )
    flags |= EF_VI_DISCARD_RX_L3_CSUM_ERR;
  if ( (CI_OWORD_FIELD(*header, EFCT_RX_HEADER_L4_CLASS) ==
                       EFCT_RX_HEADER_L4_CLASS_TCP) &&
       (header->u64[0] & M(L4_STATUS)) )
    flags |= EF_VI_DISCARD_RX_L4_CSUM_ERR;
  if ( (CI_OWORD_FIELD(*header, EFCT_RX_HEADER_L4_CLASS) ==
                       EFCT_RX_HEADER_L4_CLASS_UDP) &&
       (header->u64[0] & M(L4_STATUS)) )
    flags |= EF_VI_DISCARD_RX_L4_CSUM_ERR;
  if ( (CI_OWORD_FIELD(*header, EFCT_RX_HEADER_L4_CLASS) ==
                        EFCT_RX_HEADER_L4_CLASS_OTHER) )
      flags |= EF_VI_DISCARD_RX_L4_CLASS_OTHER;
  if ( (CI_OWORD_FIELD(*header, EFCT_RX_HEADER_L3_CLASS) ==
                        EFCT_RX_HEADER_L3_CLASS_OTHER) )
      flags |= EF_VI_DISCARD_RX_L3_CLASS_OTHER;
  if ( (CI_OWORD_FIELD(*header, EFCT_RX_HEADER_L2_CLASS) ==
                        EFCT_RX_HEADER_L2_CLASS_OTHER) )
      flags |= EF_VI_DISCARD_RX_L2_CLASS_OTHER;
  return flags;
}

static inline int efct_poll_rx(ef_vi* vi, int ix, ef_event* evs, int evs_len)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  ef_vi_efct_rxq_ptr* rxq_ptr = &qs->rxq_ptr[ix];
  ef_vi_efct_rxq* rxq = &vi->efct_rxqs.q[ix];
  int qid;
  int i;

  if( efct_rxq_need_config(rxq) ) {
    unsigned new_generation = OO_ACCESS_ONCE(*rxq->live.config_generation);
    /* We have to use the live config_generation from before we started
     * thinking, to deal with multiple successive refreshes correctly, but we
     * must write it after we're done, to deal with concurrent calls to
     * efct_rxq_check_event() */
    if( vi->efct_rxqs.ops->refresh(vi, ix) < 0 ) {
#ifndef __KERNEL__
      /* Update rxq's value even if the refresh_func fails, since retrying it
       * every poll is unlikely to be productive either. Except in
       * kernelspace, since one of the possible outcomes is a crash and we
       * don't want that */
      rxq->config_generation = new_generation;
#endif
      return 0;
    }
    rxq->config_generation = new_generation;
  }

  if( efct_rxq_need_rollover(rxq_ptr) )
    if( rx_rollover(vi, ix) < 0 )
      /* ef_eventq_poll() has historically never been able to fail, so we
       * maintain that policy */
      return 0;

  /* Avoid crossing a superbuf in a single poll. Otherwise we'd need to check
   * for rollover after each packet. */
  evs_len = CI_MIN(evs_len, (int)(rxq_ptr->superbuf_pkts -
                                  pkt_id_to_index_in_superbuf(rxq_ptr->meta_pkt)));

  qid = qs->efct_state[ix].qid;
  for( i = 0; i < evs_len; ++i ) {
    const ci_oword_t* header;
    uint32_t pkt_id;
    uint16_t discard_flags = 0;

    header = efct_rx_next_header(vi, rxq_ptr->meta_pkt);
    if( header == NULL )
      break;

    pkt_id = rxq_ptr->data_pkt;

    /* Do a coarse grained check first, then get rid of the false positives. */
    if(unlikely( header->u64[0] & CHECK_FIELDS ) &&
       (header->u64[0] & M(ROLLOVER) ||
        (discard_flags = header_status_flags(header) & vi->rx_discard_mask)) ) {
      if( CI_OWORD_FIELD(*header, EFCT_RX_HEADER_ROLLOVER) ) {
        struct efct_rx_descriptor* desc = efct_rx_desc(vi, pkt_id);
        int prev_sb = pkt_id_to_local_superbuf_ix(pkt_id);
        int next_sb = pkt_id_to_local_superbuf_ix(rxq_ptr_to_pkt_id(rxq_ptr->meta_pkt));
        int nskipped;
        if( next_sb == prev_sb ) {
          /* We created the desc->refcnt assuming that this superbuf would be
           * full of packets. It wasn't, so consume all the unused refs */
          nskipped = rxq_ptr->superbuf_pkts - pkt_id_to_index_in_superbuf(pkt_id);

          /* Force a rollover on the next poll.
           * This sets the packet index greater than superbuf_pkts to trigger
           * the special case for startup/manual rollover in rx_rollover. */
          rxq_ptr->meta_pkt += nskipped + 1;
        }
        else {
          /* i.e. the current packet is the one straddling a superbuf
           * boundary. We consume the last packet of the first superbuf
           * (it's the bogus 'manual rollover' packet) and continue with
           * the new superbuf */
          EF_VI_ASSERT(rxq_ptr->meta_offset == 1);
          nskipped = 1;
          rxq_ptr->data_pkt = rxq_ptr_to_pkt_id(rxq_ptr->meta_pkt++);
        }

        EF_VI_ASSERT(nskipped > 0);
        EF_VI_ASSERT(nskipped <= desc->refcnt);
        desc->refcnt -= nskipped;
        if( desc->refcnt == 0 )
          vi->efct_rxqs.ops->free(vi, ix, prev_sb);

        break;
      }

      efct_rx_discard(qid, pkt_id, discard_flags, header, &evs[i]);
    }
    else {
      /* For simplicity, require configuration for a fixed data offset.
       * Otherwise, we'd also have to check NEXT_FRAME_LOC in the previous
       * buffer. In theory the hardware could use variable offsets, but for now
       * we rely on knowing that the current implementation uses fixed offsets.
       */
      BUG_ON(CI_OWORD_FIELD(*header, EFCT_RX_HEADER_NEXT_FRAME_LOC) != 1);

      evs[i].rx_ref.type = EF_EVENT_TYPE_RX_REF;
      evs[i].rx_ref.len = CI_OWORD_FIELD(*header, EFCT_RX_HEADER_PACKET_LENGTH);
      evs[i].rx_ref.pkt_id = pkt_id;
      /* q_id should technically be set to the queue label, however currently
       * we don't allow the label to be changed so it's always the hardware
       * qid */
      evs[i].rx_ref.q_id = qid;
      evs[i].rx_ref.filter_id = CI_OWORD_FIELD(*header, EFCT_RX_HEADER_FILTER);
    }

    /* The following arithmetic assumes that the next data packet will be in
     * the same buffer as the next metadata. That won't be the case for the
     * first packet(s) in each buffer if the metadata offset is more than 1. */
    EF_VI_ASSERT(rxq_ptr->meta_offset <= 1);

    rxq_ptr->meta_pkt += 1;
    rxq_ptr->data_pkt = rxq_ptr_to_pkt_id(rxq_ptr->meta_pkt) - rxq_ptr->meta_offset;
  }

  return i;
}

static void efct_tx_handle_error_event(ef_vi* vi, ci_qword_t event,
                                       ef_event* ev_out)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;

  /* If we get an error event then all that we'll get subsequently for this
   * TXQ is a flush, as the queue will be torn down. That means there's no
   * need to update any of our queue state tracking.
   */
  ev_out->tx_error.type = EF_EVENT_TYPE_TX_ERROR;
  ev_out->tx_error.q_id = CI_QWORD_FIELD(event, EFCT_ERROR_LABEL);
  ev_out->tx_error.flags = 0;
  ev_out->tx_error.desc_id = ++qs->previous;
  ev_out->tx_error.subtype = CI_QWORD_FIELD(event, EFCT_ERROR_REASON);
}

static int efct_tx_handle_control_event(ef_vi* vi, ci_qword_t event,
                                        ef_event* ev_out)
{
  uint8_t time_sync;
  uint8_t time_set;
  int n_evs = 0;

  switch( CI_QWORD_FIELD(event, EFCT_CTRL_SUBTYPE) ) {
    case EFCT_CTRL_EV_ERROR:
      efct_tx_handle_error_event(vi, event, ev_out);
      n_evs++;
      ef_log("%s: ERROR: MCDI TX error event %u (raw: "CI_QWORD_FMT") - "
             "check parameters to transmit_init()", __FUNCTION__,
             QWORD_GET_U(EFCT_ERROR_REASON, event), CI_QWORD_VAL(event));
      break;
    case EFCT_CTRL_EV_FLUSH:
      LOG(ef_log("%s: Saw flush in poll", __FUNCTION__));
      break;
    case EFCT_CTRL_EV_TIME_SYNC:
      vi->ep_state->evq.sync_timestamp_major = CI_QWORD_FIELD64(event, EFCT_TIME_SYNC_EVENT_TIME_HIGH) >> 16;
      vi->ep_state->evq.sync_timestamp_minor = CI_QWORD_FIELD64(event, EFCT_TIME_SYNC_EVENT_TIME_HIGH) & 0xFFFF;
      time_sync = (CI_QWORD_FIELD(event, EFCT_TIME_SYNC_EVENT_CLOCK_IN_SYNC) ? EF_VI_SYNC_FLAG_CLOCK_IN_SYNC : 0);
      time_set = (CI_QWORD_FIELD(event, EFCT_TIME_SYNC_EVENT_CLOCK_IS_SET) ? EF_VI_SYNC_FLAG_CLOCK_SET : 0);
      /* If we managed to request reporting of the clock sync status in time
       * sync events, then we should use those values, else default to assuming
       * both set and in sync to match the behaviour in ef10_mcdi_event. */
      vi->ep_state->evq.sync_flags =
        (vi->vi_out_flags & EF_VI_OUT_CLOCK_SYNC_STATUS) ?
        time_sync | time_set :
        EF_VI_SYNC_FLAG_CLOCK_SET | EF_VI_SYNC_FLAG_CLOCK_IN_SYNC;
      vi->ep_state->evq.unsol_credit_seq++;
      efct_grant_unsol_credit(vi, false, vi->ep_state->evq.unsol_credit_seq);
      break;
    case EFCT_CTRL_EV_UNSOL_OVERFLOW:
      LOG(ef_log("%s: Saw unsol overflow", __FUNCTION__));
      /* Set unsol_seq to default, but leave 1 credit-space in reserve for overflow event. */
      vi->ep_state->evq.unsol_credit_seq = CI_CFG_TIME_SYNC_EVENT_EVQ_CAPACITY - 1;
      efct_grant_unsol_credit(vi, true, vi->ep_state->evq.unsol_credit_seq);
      break;
  }

  return n_evs;
}

int efct_poll_tx(ef_vi* vi, ef_event* evs, int evs_len)
{
  ef_eventq_state* evq = &vi->ep_state->evq;
  ci_qword_t* event;
  bool again = false;
  int n_evs = 0;

  /* Check for overflow. If the previous entry has been overwritten already,
   * then it will have the wrong phase value and will appear invalid */
  BUG_ON(efct_tx_get_event(vi, evq->evq_ptr - sizeof(*event)) == NULL);

  while( n_evs < evs_len ) {
    event = efct_tx_get_event(vi, evq->evq_ptr);
    if( event == NULL )
      break;
    evq->evq_ptr += sizeof(*event);

    switch( CI_QWORD_FIELD(*event, EFCT_EVENT_TYPE) ) {
      case EFCT_EVENT_TYPE_TX:
        efct_tx_handle_event(vi, *event, &evs[n_evs], &again);
        n_evs++;
        /* More than EF_VI_TRANSMIT_BATCH descriptors returned from HW event
         * we will complete rest on the next poll. Therefore, we move back
         * the evq_ptr.*/
        if(unlikely(again))
            evq->evq_ptr -= sizeof(*event);
        /* Don't report more than one tx event per poll. This is to avoid a
         * horrendous sequencing problem if a simple TX event is followed by a
         * TX_WITH_TIMESTAMP; we'd need to update the queue state for the
         * second event *after* the later call to ef_vi_transmit_unbundle()
         * for the first event. */
        return n_evs;
      case EFCT_EVENT_TYPE_CONTROL:
        n_evs += efct_tx_handle_control_event(vi, *event, &evs[n_evs]);
        break;
      case EFCT_EVENT_TYPE_RX:
        /* processing the rxq should already be handled via efct_poll_rx, so
         * there is no need to report events here. */
        break;
      default:
        ef_log("%s:%d: ERROR: event="CI_QWORD_FMT,
               __FUNCTION__, __LINE__, CI_QWORD_VAL(*event));
        break;
    }
  }

  return n_evs;
}

static int efct_ef_receive_poll(ef_vi* vi, ef_event* evs, int evs_len)
{
  int n = 0;
  uint64_t qs = *vi->efct_rxqs.active_qs;
  for ( ; ; ) {
    int i = __builtin_ffsll(qs);
    if (i == 0)
      break;
    --i;
    qs &= ~(1ull << i);
    n += efct_poll_rx(vi, i, evs + n, evs_len - n);
  }
  return n;
}

static int efct_ef_eventq_poll(ef_vi* vi, ef_event* evs, int evs_len)
{
  int n = efct_ef_receive_poll(vi, evs, evs_len);
  if( vi->vi_txq.mask )
    n += efct_poll_tx(vi, evs + n, evs_len - n);
  return n;
}

static void efct_ef_eventq_prime(ef_vi* vi)
{
  /* TODO X3 */
}

static void efct_ef_eventq_timer_prime(ef_vi* vi, unsigned v)
{
  /* TODO X3 */
}

static void efct_ef_eventq_timer_run(ef_vi* vi, unsigned v)
{
  /* TODO X3 */
}

static void efct_ef_eventq_timer_clear(ef_vi* vi)
{
  /* TODO X3 */
}

static void efct_ef_eventq_timer_zero(ef_vi* vi)
{
  /* TODO X3 */
}

static bool efct_vi_sb_has_been_filled(ef_vi *vi, uint32_t sbid,
                                      bool sb_sentinel, uint32_t superbuf_pkts,
                                      int ix, int qid)
{
  const ci_oword_t *header;
  EF_VI_DEBUG(ef_vi_efct_rxq_ptr *rxq_ptr);
  EF_VI_DEBUG(rxq_ptr = &vi->ep_state->rxq.rxq_ptr[ix]);
  EF_VI_ASSERT(rxq_ptr->meta_offset == 0);

  header = (void *)((char *)efct_superbuf_access(vi, ix, sbid)
                            + (superbuf_pkts - 1) * EFCT_PKT_STRIDE);
  return CI_OWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL) == sb_sentinel;
}

int efct_vi_find_free_rxq(ef_vi* vi, int qid)
{
  int ix;

  for( ix = 0; ix < vi->efct_rxqs.max_qs; ++ix ) {
    if( efct_get_rxq_state(vi, ix)->qid == qid )
      return -EALREADY;
    if( ! efct_rxq_is_active(&vi->efct_rxqs.q[ix]) )
      return ix;
  }
  return -ENOSPC;
}

void efct_vi_start_rxq(ef_vi* vi, int ix, int qid)
{
  ef_vi_efct_rxq* rxq = &vi->efct_rxqs.q[ix];
  ef_vi_efct_rxq_ptr* rxq_ptr = &vi->ep_state->rxq.rxq_ptr[ix];

  efct_get_rxq_state(vi, ix)->qid = qid;
  rxq->config_generation = 0;
  rxq_ptr->superbuf_pkts = *rxq->live.superbuf_pkts;
  rxq_ptr->meta_pkt = rxq_ptr->superbuf_pkts + 1;
  rxq_ptr->meta_offset = vi->efct_rxqs.meta_offset;

  EF_VI_ASSERT(rxq_ptr->superbuf_pkts > 0);
}

int efct_vi_sync_rxq(ef_vi *vi, int ix, int qid)
{
  int rc;
  ef_vi_efct_rxq *rxq;
  ef_vi_efct_rxq_ptr *rxq_ptr;
  struct efct_rx_descriptor *desc;
  ci_oword_t *header;
  bool sentinel;
  bool pkt_sentinel;
  unsigned sbseq;
  uint32_t meta_pkt;
  uint16_t pkt_index;

  rxq = &vi->efct_rxqs.q[ix];
  rxq_ptr = &vi->ep_state->rxq.rxq_ptr[ix];

  efct_get_rxq_state(vi, ix)->qid = qid;
  rxq->config_generation = *rxq->live.config_generation;
  rxq_ptr->superbuf_pkts = *rxq->live.superbuf_pkts;
  rxq_ptr->meta_offset = 0;

  rc = vi->efct_rxqs.ops->next(vi, ix, &sentinel, &sbseq);
  if ( rc < 0 )
    return rc;

  while ( efct_vi_sb_has_been_filled(vi, rc, sentinel, rxq_ptr->superbuf_pkts, ix, qid) )
  {
    vi->efct_rxqs.ops->free(vi, ix, rc);
    rc = vi->efct_rxqs.ops->next(vi, ix, &sentinel, &sbseq);
    if (rc < 0)
      return rc;
  }

  meta_pkt = (ix * CI_EFCT_MAX_SUPERBUFS + rc) << PKT_ID_PKT_BITS;
  header = (void *)((char *)efct_superbuf_access(vi, ix, rc));
  for ( pkt_index = 0; pkt_index < rxq_ptr->superbuf_pkts;
        header += EFCT_PKT_STRIDE / sizeof(*header), pkt_index++ )
  {
    pkt_sentinel = CI_OWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL);
    if ( pkt_sentinel != sentinel )
    {
      meta_pkt += pkt_index;
      break;
    }
  }

  rxq_ptr->meta_pkt = ((uint64_t)sbseq << 32) | ((uint64_t)sentinel << 31) | meta_pkt;
  rxq_ptr->data_pkt = meta_pkt;
  EF_VI_ASSERT(rxq_ptr->superbuf_pkts > 0);

  desc = efct_rx_desc(vi, meta_pkt);
  desc->refcnt = rxq_ptr->superbuf_pkts - pkt_index;
  desc->superbuf_pkts = rxq_ptr->superbuf_pkts;

  return 0;
}

static int
efct_design_parameters(struct ef_vi* vi, struct efab_nic_design_parameters* dp)
{
  uint32_t ct_fifo_bytes;

#define GET(PARAM) EFAB_NIC_DP_GET(*dp, PARAM)

  /* Some values which are used on the critical path which we don't expect to
   * change are hard-coded. We need to check these values, and will need to
   * accommodate run-time values if the parameter ever does change.
   */

  /* If the superbuf size changes, we will need to use it as a runtime value,
   * replacing EFCT_RX_SUPERBUF_BYTES and its dependent values */
  if( GET(rx_superbuf_bytes) != EFCT_RX_SUPERBUF_BYTES ) {
    LOG(ef_log("%s: unsupported rx_superbuf_bytes, %ld != %d", __FUNCTION__,
               (long)GET(rx_superbuf_bytes), EFCT_RX_SUPERBUF_BYTES));
    return -EOPNOTSUPP;
  }

  /* If the frame offset changes or is no longer fixed, we will need to
   * update efct_vi_rxpkt_get (and duplicated code in efct_vi_rx_future_peek).
   * It could use the parameter if it is still fixed, or read from the header.
   */
  if( GET(rx_frame_offset) != EFCT_RX_HEADER_NEXT_FRAME_LOC_1 - 2) {
    LOG(ef_log("%s: unsupported rx_frame_offset, %ld != %d", __FUNCTION__,
               (long)GET(rx_frame_offset), EFCT_RX_HEADER_NEXT_FRAME_LOC_1 - 2));
    return -EOPNOTSUPP;
  }

  /* When writing to the aperture we use a bitmask to keep within range. This
   * requires the size a power of two, and we shift by 3 because we write
   * a uint64_t (8 bytes) at a time.
   */
  if( ! EF_VI_IS_POW2(GET(tx_aperture_bytes)) ) {
    LOG(ef_log("%s: unsupported tx_aperture_bytes, %ld not a power of 2",
               __FUNCTION__, (long)GET(tx_aperture_bytes)));
    return -EOPNOTSUPP;
  }
  vi->vi_txq.efct_aperture_mask = (GET(tx_aperture_bytes) - 1) >> 3;

  /* FIXME ON-15570: We need proper handling of configurable size ctpio windows */
  /* On EF10CT nics the size of the memory backing the CTPIO window is
   * configurable. This means that it is no longer sufficient to use the size
   * reported by the design parameters as the size for the actual queue. On
   * EF10CT nics the value reported by the design is the maximum size possible
   * for a CTPIO window.
   * To calculate the size of the CTPIO fifo for this vi,
   * take the minimum of the sizes as reported by the design parameters and the
   * value received after vi allocation. This ensures that the size used is
   * bounded by the nic's limits. */
  ct_fifo_bytes = CI_MIN((uint32_t)GET(tx_fifo_bytes),
                         (uint32_t)(EFCT_TX_ALIGNMENT * (vi->vi_txq.mask + 1)));
  /* FIFO size, reduced by 8 bytes for the TX header. Hardware reduces this
   * by one cache line to make their overflow tracking easier */
  vi->vi_txq.ct_fifo_bytes = ct_fifo_bytes - EFCT_TX_ALIGNMENT -
                                             EFCT_TX_HEADER_BYTES;
  vi->vi_txq.ct_thresh_min = GET(ct_thresh_min);
  vi->ts_subnano_bits = GET(timestamp_subnano_bits);
  EF_VI_ASSERT(EF_VI_TX_TS_FRAC_NS_BITS >= vi->ts_subnano_bits);
  vi->unsol_credit_seq_mask = GET(unsol_credit_seq_mask);
  vi->efct_rxqs.rx_stride = GET(rx_stride);
  switch( GET(md_location) ) {
    case 0:
      vi->efct_rxqs.meta_offset = 1;
      break;
    case 1:
      vi->efct_rxqs.meta_offset = 0;
      break;
    default:
      LOG(ef_log("%s: unsupported md_location %ld",
                 __FUNCTION__, (long)GET(md_location)));
      return -EOPNOTSUPP;
  }
  return 0;
}

static int efct_pre_filter_add(struct ef_vi* vi, bool shared_mode)
{
  int rc = 0;
  if( vi->efct_rxqs.ops->pre_attach )
    rc = vi->efct_rxqs.ops->pre_attach(vi, shared_mode);

  return rc;
}

static int efct_post_filter_add(struct ef_vi* vi,
                                const ef_filter_spec* fs,
                                const ef_filter_cookie* cookie,
                                int rxq,
                                bool shared_mode)
{
#ifdef __KERNEL__
  return -EOPNOTSUPP;
#else
  int rc;
  unsigned n_superbufs;

   /* Block filters don't attach to an RXQ */
  if( ef_vi_filter_is_block_only(cookie) )
    return 0;

  EF_VI_ASSERT(rxq >= 0);
  n_superbufs = CI_ROUND_UP((vi->vi_rxq.mask + 1) * EFCT_PKT_STRIDE,
                            EFCT_RX_SUPERBUF_BYTES) / EFCT_RX_SUPERBUF_BYTES;
  rc = vi->efct_rxqs.ops->attach(vi, rxq, -1, n_superbufs, shared_mode);
  if( rc == -EALREADY )
    rc = 0;
  return rc;
#endif
}

const void* efct_vi_rxpkt_get(ef_vi* vi, uint32_t pkt_id)
{
  EF_VI_ASSERT(ef_vi_get_real_arch(vi) == EF_VI_ARCH_EFCT ||
               ef_vi_get_real_arch(vi) == EF_VI_ARCH_EF10CT);

  /* assume DP_FRAME_OFFSET_FIXED (correct for initial hardware) */
  return (char*)efct_rx_header(vi, pkt_id) + EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
}

/* This function is the inverse of `efct_vi_rxpkt_get` */
static uint32_t efct_vi_rxpkt_get_pkt_id(ef_vi* vi, const void* pkt)
{
#ifndef __KERNEL__
  char* ptr = (char*)pkt;
  uint32_t pkt_id = 0;
  size_t delta;

  EF_VI_ASSERT(ef_vi_get_real_arch(vi) == EF_VI_ARCH_EFCT ||
               ef_vi_get_real_arch(vi) == EF_VI_ARCH_EF10CT);

  /* In userspace, we have a contiguous chunk of memory for packets, so we can
   * calculate the location of a packet as below:
   * ptr = (char*)vi->efct_rxqs.q[0].superbuf
   *       + (size_t)(pkt_id >> PKT_ID_PKT_BITS) * EFCT_RX_SUPERBUF_BYTES
   *       + (pkt_id & ((1u << PKT_ID_PKT_BITS) - 1)) * EFCT_PKT_STRIDE
   *       + EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
   */
  ptr = ptr - EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
  delta = ptr - (char*)vi->efct_rxqs.q[0].superbuf;

  /* The compiler should be smart enough to optimise this to be bit masks and
   * shifts as the divisors are all powers of 2. In reality, because the packet
   * ID squishes all of the rxq, superbuf, and pkt number together this will
   * likely simplify to (delta >> log_2(EFCT_PKT_STRIDE)). */
  pkt_id = ((delta / EFCT_RX_SUPERBUF_BYTES) << PKT_ID_PKT_BITS) +
           ((delta % EFCT_RX_SUPERBUF_BYTES) / EFCT_PKT_STRIDE);

  EF_VI_ASSERT(efct_vi_rxpkt_get(vi, pkt_id) == pkt);
  return pkt_id;
#else
  /* This function could be made to work in the kernel, but it would involve a
   * lot of dirty work. In the kernel, we instead get an array of superbuf
   * starting locations with no guarantee of being contiguous. */
  EF_VI_ASSERT(0);
  return 0;
#endif
}

void efct_vi_rxpkt_release(ef_vi* vi, uint32_t pkt_id)
{
  EF_VI_ASSERT(efct_rx_desc(vi, pkt_id)->refcnt > 0);

  if( --efct_rx_desc(vi, pkt_id)->refcnt == 0 )
    vi->efct_rxqs.ops->free(vi, pkt_id_to_rxq_ix(pkt_id),
                            pkt_id_to_local_superbuf_ix(pkt_id));
}

const void* efct_vi_rx_future_peek(ef_vi* vi)
{
  uint64_t qs = *vi->efct_rxqs.active_qs;
  for( ; CI_LIKELY( qs ); qs &= (qs - 1) ) {
    unsigned qid = __builtin_ctzll(qs);
    ef_vi_efct_rxq_ptr* rxq_ptr = &vi->ep_state->rxq.rxq_ptr[qid];
    unsigned pkt_id;

    /* Skip queues that have pending non-packet related work
     * The work will be picked up by poll or noticed by efct_rxq_check_event */
    if( efct_rxq_need_config(&vi->efct_rxqs.q[qid]) )
      continue;

    /* Beware: under onload, the kernel may be polling and updating `rxq_ptr`
     * under our feet, so make sure we only rely on one value, read once. It's
     * fine if this changes after we read it; we'll spot a packet that's already
     * being handled, and trigger a poll which will ignore it.
     *
     * Do not check `efct_rxq_need_rollover` as that might read an inconsistent
     * value of `meta_pkt`. This check is equivalent (if the metadata is with
     * the data) and good enough otherwise; if we find data when rollover is
     * needed, then that will be sorted out on the subsequent poll.
     *
     * `superbuf_pkts` is safe to read as it is not updated after queue
     * attachment.
     */
    pkt_id = OO_ACCESS_ONCE(rxq_ptr->data_pkt);
    if( pkt_id_to_index_in_superbuf(pkt_id) >= rxq_ptr->superbuf_pkts )
      continue;

    {
      const char* start = (char*)efct_rx_header(vi, pkt_id) +
                          EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
      const char* poison_addr = start - 2;
      uint64_t v = *(volatile uint64_t*)poison_addr;
      if(CI_LIKELY( v != CI_EFCT_DEFAULT_POISON )) {
        vi->future_qid = qid;
        return start;
      }
      else {
        ci_prefetch_multiline_4(poison_addr, 1);
        ci_prefetch_multiline_4(poison_addr, 5);
      }
    }
  }
  return NULL;
}

int efct_vi_rx_future_poll(ef_vi* vi, ef_event* evs, int evs_len)
{
  int count;

  EF_VI_ASSERT(((ci_int8) vi->future_qid) >= 0);
  EF_VI_ASSERT(efct_rxq_is_active(&vi->efct_rxqs.q[vi->future_qid]));
  count = efct_poll_rx(vi, vi->future_qid, evs, evs_len);
#ifndef NDEBUG
  if( count )
    vi->future_qid = -1;
#endif
  return count;
}

static int efct_ef_eventq_has_event(const ef_vi* vi)
{
  return efct_tx_check_event(vi) || efct_rx_check_event(vi);
}

unsigned efct_vi_next_rx_rq_id(ef_vi* vi, int qid)
{
  if( efct_rxq_need_config(&vi->efct_rxqs.q[qid]) )
    return ~0u;
  return vi->ep_state->rxq.rxq_ptr[qid].data_pkt;
}

int efct_vi_rxpkt_get_precise_timestamp(ef_vi* vi, uint32_t pkt_id,
                                        ef_precisetime* ts_out)
{
  const struct efct_rx_descriptor* desc = efct_rx_desc(vi, pkt_id);
  const ci_oword_t* header;
  uint64_t ts;
  unsigned status;
  int clock_set;
  int clock_in_sync;

  pkt_id += vi->efct_rxqs.meta_offset;
  if( pkt_id_to_index_in_superbuf(pkt_id) >= desc->superbuf_pkts )
    pkt_id = desc->final_meta_pkt;

  header = efct_rx_header(vi, pkt_id);
  ts = CI_OWORD_FIELD(*header, EFCT_RX_HEADER_TIMESTAMP);
  status = CI_OWORD_FIELD(*header, EFCT_RX_HEADER_TIMESTAMP_STATUS);

  if( status == 0 )
    return -ENODATA;

  if( vi->efct_rxqs.q[pkt_id_to_rxq_ix(pkt_id)].live.time_sync == NULL ) {
    /* If we don't have access to the last time_sync event, then we must be
     * using ef10ct which provides more information about the clock status
     * in the timestamp status header field. While efct only provides valid
     * or invalid, ef10ct has the following:
     * 0 = 0b00 = no timestamp
     * 1 = 0b01 = valid timestamp,  SET and  SYNC
     * 2 = 0b10 = valid timestamp, !SET and !SYNC
     * 3 = 0b11 = valid timestamp,  SET and !SYNC
     * So SET iff 0b01 is set and SYNC iff 0b10 is not set. */
    clock_set = status & 0x1;
    clock_in_sync = !(status & 0x2);
  } else {
    ci_qword_t time_sync;
    time_sync.u64[0] =
      OO_ACCESS_ONCE(*vi->efct_rxqs.q[pkt_id_to_rxq_ix(pkt_id)].live.time_sync);
    clock_set = CI_QWORD_FIELD(time_sync, EFCT_TIME_SYNC_CLOCK_IS_SET);
    clock_in_sync = CI_QWORD_FIELD(time_sync, EFCT_TIME_SYNC_CLOCK_IN_SYNC);
  }

  /* The `ts` variable contains the full timestamp data for the packet, and has
   * the following layout:
   * - Bits  0-31: seconds
   * - Bits 32-61: nanoseconds
   * - Bits 62-63: fractional (quarter-) nanoseconds
   *
   * Because we only have quarter-nanosecond resolution, we put these two bits
   * in the most-significant position of `tv_nsec_frac`, such that future
   * precision may be appended with minimal change. */
  ts_out->tv_sec = ts >> 32;
  ts_out->tv_nsec = (uint32_t)ts >> 2;
  ts_out->tv_nsec_frac = (uint16_t)ts << 14;
  ts_out->tv_flags = (clock_set ? EF_VI_SYNC_FLAG_CLOCK_SET : 0) |
                     (clock_in_sync ? EF_VI_SYNC_FLAG_CLOCK_IN_SYNC : 0);

  return 0;
}

static int efct_ef_vi_receive_get_timestamp(struct ef_vi* vi, const void* pkt,
                                            ef_precisetime* ts_out)
{
  uint32_t pkt_id;

  EF_VI_ASSERT(ef_vi_get_real_arch(vi) == EF_VI_ARCH_EFCT ||
               ef_vi_get_real_arch(vi) == EF_VI_ARCH_EF10CT);

  pkt_id = efct_vi_rxpkt_get_pkt_id(vi, pkt);

  return efct_vi_rxpkt_get_precise_timestamp(vi, pkt_id, ts_out);
}

int efct_vi_get_wakeup_params(ef_vi* vi, int qid, unsigned* sbseq,
                              unsigned* pktix)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  ef_vi_efct_rxq_ptr* rxq_ptr = &qs->rxq_ptr[qid];
  ef_vi_efct_rxq* rxq = &vi->efct_rxqs.q[qid];
  uint64_t sbseq_next;
  unsigned ix;

  if( ! efct_rxq_is_active(rxq) )
    return -ENOENT;

  sbseq_next = OO_ACCESS_ONCE(rxq_ptr->meta_pkt);
  ix = pkt_id_to_index_in_superbuf(sbseq_next);

  if( ix >= *rxq->live.superbuf_pkts ) {
    *sbseq = (sbseq_next >> 32) + 1;
    *pktix = 0;
  }
  else {
    *sbseq = sbseq_next >> 32;
    *pktix = ix;
  }
  return 0;
}

void efct_vi_start_transmit_warm(ef_vi* vi)
{
  ci_qword_t qword;
  qword.u64[0] = vi->vi_txq.efct_fixed_header;

  EF_VI_ASSERT(ef_vi_get_real_arch(vi) == EF_VI_ARCH_EFCT ||
               ef_vi_get_real_arch(vi) == EF_VI_ARCH_EF10CT);
  EF_VI_ASSERT(CI_QWORD_FIELD(qword, EFCT_TX_HEADER_WARM_FLAG) == 0);

  CI_SET_QWORD_FIELD(qword, EFCT_TX_HEADER_WARM_FLAG, 1);
  vi->vi_txq.efct_fixed_header = qword.u64[0];
}

void efct_vi_stop_transmit_warm(ef_vi* vi)
{
  ci_qword_t qword;
  qword.u64[0] = vi->vi_txq.efct_fixed_header;

  EF_VI_ASSERT(ef_vi_get_real_arch(vi) == EF_VI_ARCH_EFCT ||
               ef_vi_get_real_arch(vi) == EF_VI_ARCH_EF10CT);
  EF_VI_ASSERT(CI_QWORD_FIELD(qword, EFCT_TX_HEADER_WARM_FLAG) == 1);

  CI_SET_QWORD_FIELD(qword, EFCT_TX_HEADER_WARM_FLAG, 0);
  vi->vi_txq.efct_fixed_header = qword.u64[0];
}

static const size_t sbuf_bytes_per_rxq =
  (size_t)CI_EFCT_MAX_SUPERBUFS * EFCT_RX_SUPERBUF_BYTES;

int efct_superbufs_reserve(ef_vi* vi, void* space)
{
  int i;

  vi->efct_rxqs.max_qs = EF_VI_MAX_EFCT_RXQS;

#ifdef __KERNEL__
  space = kvmalloc(CI_EFCT_MAX_SUPERBUFS * vi->efct_rxqs.max_qs
                                         * sizeof(const char**),
                   GFP_KERNEL);
  if( space == NULL )
    return -ENOMEM;
#else
  if( space == NULL ) {
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
    space = mmap(NULL, sbuf_bytes_per_rxq * vi->efct_rxqs.max_qs, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE |
                 MAP_HUGETLB | MAP_HUGE_2MB,
                 -1, 0);
    if( space == MAP_FAILED )
      return -ENOMEM;
  }

  madvise(space, sbuf_bytes_per_rxq * vi->efct_rxqs.max_qs, MADV_DONTDUMP);
#endif

  for( i = 0; i < vi->efct_rxqs.max_qs; ++i ) {
    ef_vi_efct_rxq* rxq = &vi->efct_rxqs.q[i];
#ifdef __KERNEL__
    rxq->superbufs = (const char**)space + i * CI_EFCT_MAX_SUPERBUFS;
#else
    rxq->superbuf = (const char*)space + i * sbuf_bytes_per_rxq;
#endif
  }

  return 0;
}

void efct_superbufs_cleanup(ef_vi* vi)
{
#ifdef __KERNEL__
  kvfree(vi->efct_rxqs.q[0].superbufs);
#else
  munmap((void*)vi->efct_rxqs.q[0].superbuf,
         sbuf_bytes_per_rxq * vi->efct_rxqs.max_qs);
#endif
}

static void efct_vi_initialise_ops(ef_vi* vi)
{
  vi->ops.transmit               = efct_ef_vi_transmit;
  vi->ops.transmitv              = efct_ef_vi_transmitv;
  vi->ops.transmitv_init         = efct_ef_vi_transmitv;
  vi->ops.transmit_push          = efct_ef_vi_transmit_push;
  vi->ops.transmit_pio           = efct_ef_vi_transmit_pio;
  vi->ops.transmit_copy_pio      = efct_ef_vi_transmit_copy_pio;
  vi->ops.start_transmit_warm    = efct_ef_vi_start_transmit_warm;
  vi->ops.stop_transmit_warm     = efct_ef_vi_stop_transmit_warm;
  vi->ops.transmit_pio_warm      = efct_ef_vi_transmit_pio_warm;
  vi->ops.transmit_copy_pio_warm = efct_ef_vi_transmit_copy_pio_warm;
  vi->ops.transmitv_ctpio        = efct_ef_vi_transmitv_ctpio;
  vi->ops.transmitv_ctpio_copy   = efct_ef_vi_transmitv_ctpio_copy;
  vi->ops.transmit_alt_select    = efct_ef_vi_transmit_alt_select;
  vi->ops.transmit_alt_select_default = efct_ef_vi_transmit_alt_select_default;
  vi->ops.transmit_alt_stop      = efct_ef_vi_transmit_alt_stop;
  vi->ops.transmit_alt_go        = efct_ef_vi_transmit_alt_go;
  vi->ops.receive_set_discards   = efct_ef_vi_receive_set_discards;
  vi->ops.receive_get_discards   = efct_ef_vi_receive_get_discards;
  vi->ops.transmit_alt_discard   = efct_ef_vi_transmit_alt_discard;
  vi->ops.receive_init           = efct_ef_vi_receive_init;
  vi->ops.receive_push           = efct_ef_vi_receive_push;
  vi->ops.receive_get_timestamp  = efct_ef_vi_receive_get_timestamp;
  vi->ops.eventq_prime           = efct_ef_eventq_prime;
  vi->ops.eventq_timer_prime     = efct_ef_eventq_timer_prime;
  vi->ops.eventq_timer_run       = efct_ef_eventq_timer_run;
  vi->ops.eventq_timer_clear     = efct_ef_eventq_timer_clear;
  vi->ops.eventq_timer_zero      = efct_ef_eventq_timer_zero;
  vi->ops.eventq_has_many_events = efct_ef_eventq_has_many_events;
  vi->ops.eventq_has_event       = efct_ef_eventq_has_event;
  vi->ops.transmit_ctpio_fallback = efct_ef_vi_transmit_ctpio_fallback;
  vi->ops.transmitv_ctpio_fallback = efct_ef_vi_transmitv_ctpio_fallback;
  vi->internal_ops.design_parameters = efct_design_parameters;
  vi->internal_ops.pre_filter_add = efct_pre_filter_add;
  vi->internal_ops.post_filter_add = efct_post_filter_add;
  vi->ops.eventq_poll = efct_ef_eventq_poll;
  vi->ops.receive_poll = efct_ef_receive_poll;
}

void efct_vi_init(ef_vi* vi)
{
  int i;
  EF_VI_ASSERT( vi->nic_type.nic_flags & EFHW_VI_NIC_CTPIO_ONLY );

  efct_vi_initialise_ops(vi);
  vi->evq_phase_bits = 1;
  /* Set default rx_discard_mask for EFCT */
  vi->rx_discard_mask = (
     EF_VI_DISCARD_RX_L4_CSUM_ERR |
     EF_VI_DISCARD_RX_L3_CSUM_ERR |
     EF_VI_DISCARD_RX_ETH_FCS_ERR |
     EF_VI_DISCARD_RX_ETH_LEN_ERR
  );

  vi->vi_txq.efct_fixed_header =
      efct_tx_header(0, 0, (vi->vi_flags & EF_VI_TX_TIMESTAMPS) ? 1 : 0, 0, 0);
  vi->efct_rxqs.active_qs = &vi->efct_rxqs.max_qs;

  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i ) {
    ef_vi_efct_rxq* q = &vi->efct_rxqs.q[i];
    q->live.superbuf_pkts = &q->config_generation;
  }
}

