/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */

#include "ef_vi_internal.h"
#include "efct_hw_defs.h"

/* FIXME EFCT: make this variable */
#define EFCT_PKT_STRIDE 2048

#include <stdbool.h>

struct efct_rx_descriptor
{
  uint16_t refcnt;
};

/* The superbuf descriptor for this packet */
static struct efct_rx_descriptor* efct_rx_desc(ef_vi* vi, uint32_t pkt_id)
{
  ef_vi_rxq* q = &vi->vi_rxq;
  struct efct_rx_descriptor* desc = q->descriptors;
  return desc + pkt_id / q->superbuf_pkts;
}

/* The header preceding this packet */
static const ci_qword_t* efct_rx_header(const ef_vi* vi, size_t pkt_id)
{
  /* TODO non-power-of-two packet buffer sizes */
  return (const ci_qword_t*)(vi->vi_rxq.superbuf + pkt_id * EFCT_PKT_STRIDE);
}

/* The header following the next packet, or null if not available */
static const ci_qword_t* efct_rx_next_header(const ef_vi* vi)
{
  const ef_vi_rxq* q = &vi->vi_rxq;
  const ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  const ci_qword_t* header;

  BUG_ON(qs->added == qs->removed);
  if( qs->added == qs->removed + 1 )
    return NULL;

  header = efct_rx_header(vi, (qs->removed + 1) & q->mask);
  return CI_QWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL) ? header : NULL;
}

/* Check whether a received packet is available */
static bool efct_rx_check_event(const ef_vi* vi)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  return (qs->added != qs->removed) && (efct_rx_next_header(vi) != NULL);
}

/* tx packet descriptor, stored in the ring until completion */
/* TODO fix the size of this, and update tx_desc_bytes in vi_init.c */
struct efct_tx_descriptor
{
  /* total length including header and padding, in bytes */
  uint16_t len;
};

/* state of a partially-completed tx operation */
struct efct_tx_state
{
  /* next write location within the aperture. NOTE: we assume the aperture is
   * mapped twice, so that each packet can be written contiguously */
  volatile uint64_t* aperture;
  /* up to 7 bytes left over after writing a block in 64-bit chunks */
  union {uint64_t word; uint8_t bytes[8];} tail;
  /* number of left over bytes in 'tail' */
  unsigned tail_len;
};

/* generic tx header */
static uint64_t efct_tx_header(unsigned packet_length, unsigned ct_thresh,
                               unsigned timestamp_flag, unsigned warm_flag,
                               unsigned action)
{
  ci_qword_t qword;

  CI_POPULATE_QWORD_5(qword,
      EFCT_TX_HEADER_PACKET_LENGTH, packet_length,
      EFCT_TX_HEADER_CT_THRESH, ct_thresh,
      EFCT_TX_HEADER_TIMESTAMP_FLAG, timestamp_flag,
      EFCT_TX_HEADER_WARM_FLAG, warm_flag,
      EFCT_TX_HEADER_ACTION, action);

  return qword.u64[0];
}

/* tx header for standard (non-templated) send */
static uint64_t efct_tx_pkt_header(unsigned length, unsigned ct_thresh,
                                   unsigned timestamp_flag)
{
  return efct_tx_header(length, ct_thresh, timestamp_flag, 0, 0);
}

/* check that we have space to send a packet of this length */
static bool efct_tx_check(ef_vi* vi, int len)
{
  /* We require the txq to be large enough for the maximum number of packets
   * which can be written to the FIFO. Each packet consumes at least 64 bytes.
   */
  BUG_ON((vi->vi_txq.mask + 1) <
         (vi->vi_txq.ct_fifo_bytes + EFCT_TX_HEADER_BYTES) / EFCT_TX_ALIGNMENT);

  return ef_vi_transmit_space_bytes(vi) >= len;
}

/* initialise state for a transmit operation */
static void efct_tx_init(ef_vi* vi, struct efct_tx_state* tx)
{
  unsigned offset = vi->ep_state->txq.ct_added % EFCT_TX_APERTURE;

  BUG_ON(offset % EFCT_TX_ALIGNMENT != 0);
  tx->aperture = (void*)(vi->vi_ctpio_mmap_ptr + offset);
  tx->tail.word = 0;
  tx->tail_len = 0;
}

/* store a left-over byte from the start or end of a block */
static void efct_tx_tail_byte(struct efct_tx_state* tx, uint8_t byte)
{
  BUG_ON(tx->tail_len >= 8);
  tx->tail.bytes[tx->tail_len++] = byte;
}

/* write a 64-bit word to the CTPIO aperture */
static void efct_tx_word(struct efct_tx_state* tx, uint64_t value)
{
  *tx->aperture++ = value;
}

/* write a block of bytes to the CTPIO aperture, dealing with leftovers */
static void efct_tx_block(struct efct_tx_state* tx, char* base, int len)
{
  if( tx->tail_len != 0 ) {
    while( len > 0 && tx->tail_len < 8 ) {
      efct_tx_tail_byte(tx, *base);
      base++;
      len--;
    }

    if( tx->tail_len == 8 ) {
      efct_tx_word(tx, tx->tail.word);
      tx->tail.word = 0;
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
static void efct_tx_complete(ef_vi* vi, struct efct_tx_state* tx, uint32_t dma_id)
{
  unsigned start, end, len;

  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  struct efct_tx_descriptor* desc = q->descriptors;
  int i = qs->added & q->mask;

  if( tx->tail_len != 0 )
    efct_tx_word(tx, tx->tail.word);
  while( (uintptr_t)tx->aperture % EFCT_TX_ALIGNMENT != 0 )
    efct_tx_word(tx, 0);

  start = qs->ct_added % EFCT_TX_APERTURE;
  end = ((char*)tx->aperture - vi->vi_ctpio_mmap_ptr);
  len = end - start;

  desc[i].len = len;
  q->ids[i] = dma_id;
  qs->ct_added += len;
  qs->added += 1;
}

/* get a tx completion event, or null if no valid event available */
static ci_qword_t* efct_tx_get_event(const ef_vi* vi, uint32_t evq_ptr)
{
  ci_qword_t* event = (ci_qword_t*)(vi->evq_base + (evq_ptr & vi->evq_mask));

  int expect_phase = (evq_ptr & (vi->evq_mask + 1)) != 0;
  int actual_phase = CI_QWORD_FIELD(*event, EFCT_EVENT_PHASE);

  return actual_phase == expect_phase ? event : NULL;
}

/* check whether a tx completion event is available */
static bool efct_tx_check_event(const ef_vi* vi)
{
  return efct_tx_get_event(vi, vi->ep_state->evq.evq_ptr) != NULL;
}

/* handle a tx completion event */
static void efct_tx_handle_event(ef_vi* vi, ci_qword_t event, ef_event* ev_out)
{
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  struct efct_tx_descriptor* desc = vi->vi_txq.descriptors;

  unsigned seq = CI_QWORD_FIELD(event, EFCT_TX_EVENT_SEQUENCE);
  unsigned seq_mask = (1 << EFCT_TX_EVENT_SEQUENCE_WIDTH) - 1;

  while( (qs->previous & seq_mask) != seq ) {
    BUG_ON(qs->previous == qs->added);
    qs->ct_removed += desc[qs->previous & q->mask].len;
    qs->previous += 1;
  }

  ev_out->tx.type = EF_EVENT_TYPE_TX; /* TODO _WITH_TIMESTAMP */
  ev_out->tx.q_id = CI_QWORD_FIELD(event, EFCT_TX_EVENT_LABEL);
  ev_out->tx.flags = EF_EVENT_FLAG_CTPIO;
  ev_out->tx.desc_id = qs->previous;
}

static int efct_ef_vi_transmit(ef_vi* vi, ef_addr base, int len,
                               ef_request_id dma_id)
{
  /* TODO need to avoid calling this with CTPIO fallback buffers */
  struct efct_tx_state tx;

  if( ! efct_tx_check(vi, len) )
    return -EAGAIN;

  efct_tx_init(vi, &tx);
  /* TODO timestamp flag */
  efct_tx_word(&tx, efct_tx_pkt_header(len, EFCT_TX_CT_DISABLE, 0));
  efct_tx_block(&tx, (void*)(uintptr_t)base, len);
  efct_tx_complete(vi, &tx, dma_id);

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

  /* TODO timestamp flag */
  efct_tx_word(&tx, efct_tx_pkt_header(len, EFCT_TX_CT_DISABLE, 0));

  for( i = 0; i < iov_len; ++i )
    efct_tx_block(&tx, (void*)(uintptr_t)iov[i].iov_base, iov[i].iov_len);

  efct_tx_complete(vi, &tx, dma_id);

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

static void efct_ef_vi_transmit_pio_warm(ef_vi* vi)
{
}

static void efct_ef_vi_transmit_copy_pio_warm(ef_vi* vi, int pio_offset,
                                              const void* src_buf, int len)
{
}

static void efct_ef_vi_transmitv_ctpio(ef_vi* vi, size_t len,
                                       const struct iovec* iov, int iovcnt,
                                       unsigned threshold)
{
  struct efct_tx_state tx;
  int i;

  /* The caller must check space, as this function can't report failure. */
  /* TODO this function should probably remain compatible with legacy ef_vi,
   * perhaps by doing nothing and deferring transmission to when the fallback
   * buffer is posted. In that case we'd need another API, very similar to
   * this, but without the requirement for a fallback buffer, for best speed.
   */
  BUG_ON(!efct_tx_check(vi, len));
  efct_tx_init(vi, &tx);

  /* TODO timestamp flag */
  efct_tx_word(&tx, efct_tx_pkt_header(len, threshold, 0));

  for( i = 0; i < iovcnt; ++i )
    efct_tx_block(&tx, iov[i].iov_base, iov[i].iov_len);

  /* Use a valid but bogus dma_id rather than invalid EF_REQUEST_ID_MASK to
   * support tcpdirect, which relies on the correct return value from
   * ef_vi_transmit_unbundle to free its otherwise * unused transmit buffers.
   */
  efct_tx_complete(vi, &tx, 0);

  /* TODO for ef_vi compatibility, we probably need an efct-specific version of
   * ef_vi_transmit_ctpio_fallback to record the correct dma_id.
   */
}

static void efct_ef_vi_transmitv_ctpio_copy(ef_vi* vi, size_t frame_len,
                                            const struct iovec* iov, int iovcnt,
                                            unsigned threshold, void* fallback)
{
  /* Fallback is unnecessary for this architecture */
  efct_ef_vi_transmitv_ctpio(vi, frame_len, iov, iovcnt, threshold);
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

static int efct_ef_vi_transmit_alt_discard(ef_vi* vi, unsigned alt_id)
{
  return -EOPNOTSUPP;
}

static int efct_ef_vi_receive_init(ef_vi* vi, ef_addr addr,
                                   ef_request_id dma_id)
{
  /* TODO X3 */
  return -ENOSYS;
}

static void efct_ef_vi_receive_push(ef_vi* vi)
{
  /* TODO X3 */
}

static int efct_poll_rx(ef_vi* vi, ef_event* evs, int evs_len)
{
  ef_vi_rxq* q = &vi->vi_rxq;
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  int i;

  if( qs->removed == qs->added )
    return 0;

  for( i = 0; i < evs_len; ++i, ++qs->removed ) {
    const ci_qword_t* header = efct_rx_next_header(vi);
    if( header == NULL )
      break;

    /* For simplicity, require configuration for a fixed data offset.
     * Otherwise, we'd also have to check NEXT_FRAME_LOC in the previous buffer.
     */
    BUG_ON(CI_QWORD_FIELD(*header, EFCT_RX_HEADER_NEXT_FRAME_LOC) != 1);

    evs[i].rx.type = EF_EVENT_TYPE_RX;
    /* TODO q_id from rx event? */
    evs[i].rx.rq_id = qs->removed & q->mask;
    evs[i].rx.len = CI_QWORD_FIELD(*header, EFCT_RX_HEADER_PACKET_LENGTH);
    evs[i].rx.flags = EF_EVENT_FLAG_SOP;
    evs[i].rx.ofs = EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
    /* TODO might be nice to provide more of the available metadata */

    /* Pre-emptively take references for all packets in a new superbuf.
     * TODO: move this to the point at which the superbuf is provided.
     * TODO: handle manual rollover
     */
    if( qs->removed % q->superbuf_pkts == 0 )
      efct_rx_desc(vi, qs->removed & q->mask)->refcnt = q->superbuf_pkts;
  }

  return i;
}

static int efct_poll_tx(ef_vi* vi, ef_event* evs, int evs_len)
{
  ef_eventq_state* evq = &vi->ep_state->evq;
  ci_qword_t* event;
  int i;

  /* Check for overflow. If the previous entry has been overwritten already,
   * then it will have the wrong phase value and will appear invalid */
  BUG_ON(efct_tx_get_event(vi, evq->evq_ptr - sizeof(*event)) == NULL);

  for( i = 0; i < evs_len; ++i, evq->evq_ptr += sizeof(*event) ) {
    event = efct_tx_get_event(vi, evq->evq_ptr);
    if( event == NULL )
      break;

    switch( CI_QWORD_FIELD(*event, EFCT_EVENT_TYPE) ) {
      case EFCT_EVENT_TYPE_TX:
        efct_tx_handle_event(vi, *event, &evs[i]);
        break;
      case EFCT_EVENT_TYPE_CONTROL:
        /* TODO X3 */
        break;
      default:
        ef_log("%s:%d: ERROR: event="CI_QWORD_FMT,
               __FUNCTION__, __LINE__, CI_QWORD_VAL(*event));
        break;
    }
  }

  return i;
}

static int efct_ef_eventq_poll(ef_vi* vi, ef_event* evs, int evs_len)
{
  int i = 0;

  if( vi->vi_rxq.mask )
    i += efct_poll_rx(vi, evs, evs_len);
  if( vi->vi_txq.mask )
    i += efct_poll_tx(vi, evs, evs_len);

  return i;
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

static ssize_t efct_ef_vi_transmit_memcpy(struct ef_vi* vi,
                                          const ef_remote_iovec* dst_iov,
                                          int dst_iov_len,
                                          const ef_remote_iovec* src_iov,
                                          int src_iov_len)
{
  return -EOPNOTSUPP;
}

static int efct_ef_vi_transmit_memcpy_sync(struct ef_vi* vi,
                                           ef_request_id dma_id)
{
  return -EOPNOTSUPP;
}

static void efct_vi_initialise_ops(ef_vi* vi)
{
  vi->ops.transmit               = efct_ef_vi_transmit;
  vi->ops.transmitv              = efct_ef_vi_transmitv;
  vi->ops.transmitv_init         = efct_ef_vi_transmitv;
  vi->ops.transmit_push          = efct_ef_vi_transmit_push;
  vi->ops.transmit_pio           = efct_ef_vi_transmit_pio;
  vi->ops.transmit_copy_pio      = efct_ef_vi_transmit_copy_pio;
  vi->ops.transmit_pio_warm      = efct_ef_vi_transmit_pio_warm;
  vi->ops.transmit_copy_pio_warm = efct_ef_vi_transmit_copy_pio_warm;
  vi->ops.transmitv_ctpio        = efct_ef_vi_transmitv_ctpio;
  vi->ops.transmitv_ctpio_copy   = efct_ef_vi_transmitv_ctpio_copy;
  vi->ops.transmit_alt_select    = efct_ef_vi_transmit_alt_select;
  vi->ops.transmit_alt_select_default = efct_ef_vi_transmit_alt_select_default;
  vi->ops.transmit_alt_stop      = efct_ef_vi_transmit_alt_stop;
  vi->ops.transmit_alt_go        = efct_ef_vi_transmit_alt_go;
  vi->ops.transmit_alt_discard   = efct_ef_vi_transmit_alt_discard;
  vi->ops.receive_init           = efct_ef_vi_receive_init;
  vi->ops.receive_push           = efct_ef_vi_receive_push;
  vi->ops.eventq_poll            = efct_ef_eventq_poll;
  vi->ops.eventq_prime           = efct_ef_eventq_prime;
  vi->ops.eventq_timer_prime     = efct_ef_eventq_timer_prime;
  vi->ops.eventq_timer_run       = efct_ef_eventq_timer_run;
  vi->ops.eventq_timer_clear     = efct_ef_eventq_timer_clear;
  vi->ops.eventq_timer_zero      = efct_ef_eventq_timer_zero;
  vi->ops.transmit_memcpy        = efct_ef_vi_transmit_memcpy;
  vi->ops.transmit_memcpy_sync   = efct_ef_vi_transmit_memcpy_sync;
}

void efct_vi_init(ef_vi* vi)
{
  EF_VI_BUILD_ASSERT(sizeof(struct efct_tx_descriptor) ==
                     EFCT_TX_DESCRIPTOR_BYTES);
  EF_VI_BUILD_ASSERT(sizeof(struct efct_rx_descriptor) ==
                     EFCT_RX_DESCRIPTOR_BYTES);

  efct_vi_initialise_ops(vi);
  vi->evq_phase_bits = 1;
}

void efct_vi_rxpkt_get(ef_vi* vi, uint32_t pkt_id, const void** pkt_start)
{
  EF_VI_ASSERT(vi->nic_type.arch == EF_VI_ARCH_EFCT);
  EF_VI_ASSERT(pkt_id <= vi->vi_rxq.mask);

  *pkt_start = ((char*)efct_rx_header(vi, pkt_id)) + EFCT_RX_HEADER_BYTES;
}

void efct_vi_rxpkt_release(ef_vi* vi, uint32_t pkt_id)
{
  EF_VI_ASSERT(efct_rx_desc(vi, pkt_id)->refcnt > 0);

  if( --efct_rx_desc(vi, pkt_id)->refcnt == 0 )
    ++vi->ep_state->rxq.superbufs_removed;
}

int efct_ef_eventq_check_event(const ef_vi* vi)
{
  return efct_tx_check_event(vi) || efct_rx_check_event(vi);
}

