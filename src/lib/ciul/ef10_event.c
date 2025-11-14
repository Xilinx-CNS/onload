/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */

/*
 * \author  djr
 *  \brief  Routine to poll event queues.
 *   \date  2003/03/04
 */

/*! \cidoxg_lib_ef */
#include "ef_vi_internal.h"
#include "logging.h"
#include <ci/efhw/mc_driver_pcol.h>
#include <ci/driver/efab/hardware/ef10_evq.h>
#include <etherfabric/packedstream.h>


typedef ci_qword_t ef_vi_event;


#define EF_VI_EVENT_OFFSET(q, i)                                \
  (((q)->ep_state->evq.evq_ptr + (i) * sizeof(ef_vi_qword)) &	\
   (q)->evq_mask)

#define EF_VI_EVENT_PTR(q, i)                                           \
  ((ef_vi_event*) ((q)->evq_base + EF_VI_EVENT_OFFSET((q), (i))))

/* Due to crazy chipsets, we see the event words being written in
** arbitrary order (bug4539).  So test for presence of event must ensure
** that both halves have changed from the null.
*/
#define EF_VI_IS_EVENT(evp)                     \
  (!(CI_DWORD_IS_ALL_ONES((evp)->dword[0]) |	\
     CI_DWORD_IS_ALL_ONES((evp)->dword[1])))


#define INC_ERROR_STAT(vi, name)		\
  do {                                          \
    if ((vi)->vi_stats != NULL)                 \
      ++(vi)->vi_stats->name;                   \
  } while (0)

#define INC_VI_STAT INC_ERROR_STAT


/* The space occupied by a minimum sized (60 byte) packet. */
#define EF_VI_PS_MIN_PKT_SPACE						\
  (EF_VI_ALIGN_FWD((ES_DZ_PS_RX_PREFIX_SIZE + 60 + EF_VI_PS_PACKET_GAP), \
		   EF_VI_PS_ALIGNMENT))

/* When allocating credit, we take into account the worst case event count
** per credit. This is when we get no event batching for minumum sized packets.
*/
#define EF_VI_PS_MAX_EVENTS_PER_CREDIT			\
  (EF_VI_PS_SPACE_PER_CREDIT / EF_VI_PS_MIN_PKT_SPACE)


ef_vi_inline unsigned discard_type(uint64_t error_bits)
{
  const uint64_t l2_errors = ( (1llu << ESF_DZ_RX_ECC_ERR_LBN) |
                               (1llu << ESF_DZ_RX_ECRC_ERR_LBN) |
                               (1llu << ESF_DZ_RX_TRUNC_ERR_LBN) );
  const uint64_t l3_errors = ( (1llu << ESF_DZ_RX_TCPUDP_CKSUM_ERR_LBN) |
                               (1llu << ESF_DZ_RX_IPCKSUM_ERR_LBN) );

  if( error_bits & l2_errors )
    return EF_EVENT_RX_DISCARD_CRC_BAD;
  else if( error_bits & l3_errors )
    return EF_EVENT_RX_DISCARD_CSUM_BAD;
  else
    return EF_EVENT_RX_DISCARD_INNER_CSUM_BAD;


}


static void no_desc_trunc(ef_vi* vi, ef_event** evs, int* evs_len, int q_label)
{
  /* Adapter ran out of descriptors in middle of a jumbo. */
  ef_event* ev_out = (*evs)++;
  --(*evs_len);
  ev_out->rx_no_desc_trunc.type = EF_EVENT_TYPE_RX_NO_DESC_TRUNC;
  ev_out->rx_no_desc_trunc.q_id = q_label;
  vi->ep_state->rxq.in_jumbo = 0;
}


ef_vi_inline void huntington_rx_desc_consumed(ef_vi* vi, const ef_vi_event* ev,
					      ef_event** evs, int* evs_len,
					      int q_label)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  unsigned desc_i = qs->removed & vi->vi_rxq.mask;
  unsigned rx_bytes;
  uint64_t error_bits;

  ef_event* ev_out = (*evs)++;
  --(*evs_len);
  ev_out->rx.type = EF_EVENT_TYPE_RX;
  ev_out->rx.ofs = 0;
  ev_out->rx.q_id = q_label;
  ev_out->rx.rq_id = vi->vi_rxq.ids[desc_i];
  vi->vi_rxq.ids[desc_i] = EF_REQUEST_ID_MASK;  /* ?? killme */
  rx_bytes = QWORD_GET_U(ESF_DZ_RX_BYTES, *ev);
  if(likely( ! qs->in_jumbo )) {
    ev_out->rx.flags = EF_EVENT_FLAG_SOP;
    qs->bytes_acc = rx_bytes;
  }
  else {
    ev_out->rx.flags = 0;
    qs->bytes_acc += rx_bytes;
  }
  if(likely( ! QWORD_GET_U(ESF_DZ_RX_CONT, *ev) )) {
    qs->in_jumbo = 0;
  }
  else {
    ev_out->rx.flags |= EF_EVENT_FLAG_CONT;
    qs->in_jumbo = 1;
  }
  ev_out->rx.len = qs->bytes_acc;

  if( QWORD_GET_U(ESF_DZ_RX_MAC_CLASS, *ev) == ESE_DZ_MAC_CLASS_MCAST )
    ev_out->rx.flags |= EF_EVENT_FLAG_MULTICAST;

  error_bits = ev->u64[0] & vi->rx_discard_mask;
  if(likely( error_bits == 0 )) {
    ++(qs->removed);
  }
  else {
    /* NB. Other fields already set via ev_out->rx (layout is the same). */
    ev_out->rx_discard.type = EF_EVENT_TYPE_RX_DISCARD;
    ev_out->rx_discard.subtype = discard_type(error_bits);
    ++(qs->removed);
  }
}


/* This has the following differences from huntington_rx_desc_consumed to
 * support RX event batching:
 *
 * - It creates an event of type EF_EVENT_TYPE_RX_MULTI.  This event
 *   does not contain a len field, as when batching is enabled we are only
 *   guaranteed a length in the packet prefix.  It also does not contain
 *   an ef_request_id, as it may complete multiple events.  The application
 *   must unbundle the batched event with ef_vi_receive_unbundle to retrieve
 *   the individual request ids.
 *
 * - Bytes accumulated during a jumbo are not tracked, as we don't
 *   necessarily have that information for all pieces.  This means that the
 *   application must keep track of the total length of a jumbo.
 *
 * - We keep track of which descriptors have been completed, separately from
 *   which descriptors have been removed from the ring.  A descriptor has
 *   been completed once we have an RX event for it, but it is not removed
 *   until the application has called ef_vi_receive_unbundle and we can
 *   clear the request id.  This is necessary as we only have 4 bits of
 *   descriptor index to identify the descriptor, so can wrap before the
 *   application removes the descriptors.
 *
 * - We determine whether an event is an abort by simply checking if this is
 *   a second completion for the same descriptor - we can't use the rx_bytes
 *   field as this is commonly 0.
 */
ef_vi_inline void huntington_rx_descs_consumed(ef_vi* vi, const ef_vi_event* ev,
                                               ef_event** evs, int* evs_len,
                                               int q_label, unsigned n_descs)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  uint64_t error_bits;

  EF_VI_ASSERT( vi->vi_flags & EF_VI_RX_EVENT_MERGE );

  if(likely( n_descs )) {
    ef_event* ev_out = (*evs)++;
    --(*evs_len);
    ev_out->rx_multi.type = EF_EVENT_TYPE_RX_MULTI;
    ev_out->rx_multi.q_id = q_label;
    ev_out->rx_multi.n_descs = n_descs;
    if(likely( ! qs->in_jumbo ))
      ev_out->rx_multi.flags = EF_EVENT_FLAG_SOP;
    else
      ev_out->rx_multi.flags = 0;
    if(likely( ! QWORD_GET_U(ESF_DZ_RX_CONT, *ev) )) {
      qs->in_jumbo = 0;
    }
    else {
      ev_out->rx_multi.flags |= EF_EVENT_FLAG_CONT;
      qs->in_jumbo = 1;
    }

    if( QWORD_GET_U(ESF_DZ_RX_MAC_CLASS, *ev) == ESE_DZ_MAC_CLASS_MCAST)
      ev_out->rx_multi.flags |= EF_EVENT_FLAG_MULTICAST;

    error_bits = ev->u64[0] & vi->rx_discard_mask;
    if(unlikely( error_bits != 0 )) {
      ev_out->rx_multi_discard.type = EF_EVENT_TYPE_RX_MULTI_DISCARD;
      ev_out->rx_multi_discard.subtype = discard_type(error_bits);
    }
  }
  else {
    no_desc_trunc(vi, evs, evs_len, q_label);
  }
}


ef_vi_inline void ef10_packed_stream_rx_event(ef_vi* vi, const ef_vi_event* ev,
                                              ef_event** evs, int* evs_len,
                                              unsigned q_label,
                                              unsigned short_di)
{
  ef_vi_rxq_state* qs = &(vi->ep_state->rxq);
  unsigned short_di_mask = (1u << ESF_DZ_RX_DSC_PTR_LBITS_WIDTH) - 1u;
  ci_qword_t interesting_errors;

  ef_event* ev_out = (*evs)++;
  --(*evs_len);
  ev_out->rx_packed_stream.type = EF_EVENT_TYPE_RX_PACKED_STREAM;
  ev_out->rx_packed_stream.q_id = q_label;
  ev_out->rx_packed_stream.flags = 0;
  ev_out->rx_packed_stream.ps_flags = 0;
  ev_out->rx_packed_stream.n_pkts =
    (short_di - qs->last_desc_i) & short_di_mask;
  qs->last_desc_i = short_di;

  if(unlikely( QWORD_GET_U(ESF_DZ_RX_EV_ROTATE, *ev) )) {
    unsigned desc_id = qs->removed & vi->vi_rxq.mask;
    vi->vi_rxq.ids[desc_id] = EF_REQUEST_ID_MASK;
    ++(qs->removed);
    EF_VI_ASSERT( qs->rx_ps_credit_avail > 0 );
    --(qs->rx_ps_credit_avail);
    ev_out->rx_packed_stream.flags |= EF_EVENT_FLAG_PS_NEXT_BUFFER;
  }

  EF_VI_ASSERT(ev_out->rx_packed_stream.n_pkts <= EF_VI_RECEIVE_BATCH);
  EF_VI_ASSERT(ev_out->rx_packed_stream.n_pkts > 0 ||
               QWORD_GET_U(ESF_DZ_RX_CONT, *ev));

  interesting_errors.u64[0] = ev->u64[0] & vi->rx_discard_mask;
  if(likely( ! interesting_errors.u64[0] ))
    return;

  if (QWORD_GET_U(ESF_DZ_RX_ECC_ERR, interesting_errors)  |
      QWORD_GET_U(ESF_DZ_RX_ECRC_ERR, interesting_errors))
    ev_out->rx_packed_stream.ps_flags |= EF_VI_PS_FLAG_BAD_FCS;
  if (QWORD_GET_U(ESF_DZ_RX_TCPUDP_CKSUM_ERR, interesting_errors))
    ev_out->rx_packed_stream.ps_flags |= EF_VI_PS_FLAG_BAD_L4_CSUM;
  if (QWORD_GET_U(ESF_DZ_RX_IPCKSUM_ERR, interesting_errors))
    ev_out->rx_packed_stream.ps_flags |= EF_VI_PS_FLAG_BAD_L3_CSUM;
}


ef_vi_inline void ef10_rx_event(ef_vi* evq_vi, const ef_vi_event* ev,
				ef_event** evs, int* evs_len)
{
  unsigned q_label = QWORD_GET_U(ESF_DZ_RX_QLABEL, *ev);
  ef_vi* vi = evq_vi->vi_qs[q_label];

  if(likely( vi != NULL )) {
    ef_vi_rxq_state* qs = &(vi->ep_state->rxq);
    const unsigned short_di_mask = (1u << ESF_DZ_RX_DSC_PTR_LBITS_WIDTH) - 1u;
    unsigned short_di = QWORD_GET_U(ESF_DZ_RX_DSC_PTR_LBITS, *ev);
    if( vi->vi_is_normal ) {
      unsigned n_descs = (short_di - qs->removed) & short_di_mask;
      if(likely( n_descs == 1 ))
        huntington_rx_desc_consumed(vi, ev, evs, evs_len, q_label);
      else if( n_descs == 0 )
        no_desc_trunc(vi, evs, evs_len, q_label);
      else
        EF_VI_ASSERT( n_descs == 1 || n_descs == 2 );
    }
    else if( vi->vi_is_packed_stream ) {
      ef10_packed_stream_rx_event(vi, ev, evs, evs_len, q_label, short_di);
    }
    else {
      unsigned n_descs = (short_di - qs->last_desc_i) & short_di_mask;
      qs->last_desc_i = short_di;
      huntington_rx_descs_consumed(vi, ev, evs, evs_len, q_label, n_descs);
    }
  }
  else {
    INC_ERROR_STAT(evq_vi, rx_ev_bad_q_label);
  }
}


/* These constants describe useful values to combine major ticks with
 * TX timestamp events on Medford
 */
#define MEDFORD_TX_SECS_EVENT_BITS 16
#define MEDFORD_TX_SECS_EVENT_MASK ((1 << MEDFORD_TX_SECS_EVENT_BITS) - 1)
/* This is in theory (1 << (MEDFORD_TX_SECS_EVENT_BITS - 1)) but we
 * set it to 1 as we don't expect the timestamp events to differ from
 * the timesync events by more than 1 second.
 */
#define MEDFORD_TX_SECS_SYNC_MIN_OFFSET 1
/* Top bit of event tells us if the timestamp is valid or MAC is in drain */
#define MEDFORD_TX_SECS_VALID_BIT 0x8000
/* Next bit of event tells us if the timestamp was generated by MAC or TXDP */
#define MEDFORD_TX_SECS_TXDP_BIT 0x4000


static uint32_t timestamp_extract(ef_vi_event ev)
{
  uint32_t lo = QWORD_GET_U(ESF_DZ_TX_DESCR_INDX, ev);
  uint32_t hi = QWORD_GET_U(ESF_DZ_TX_SOFT2, ev);
  return (hi << 16) | lo;
}

static uint32_t timestamp_extract_medford_seconds(ef_vi_event ev,
                                                  uint16_t *metabits)
{
  uint32_t lo = QWORD_GET_U(ESF_DZ_TX_DESCR_INDX, ev);
  /* Currently only the top bit is interesting, so ignore the others.
   * The next bit also has meaning (source of the timestamp), but we
   * don't use it at the moment.
   */
  *metabits = QWORD_GET_U(ESF_DZ_TX_SOFT2, ev) & MEDFORD_TX_SECS_VALID_BIT;
  return lo;
}


static inline void ef10_tx_event_ts_lo(ef_vi* evq, const ef_vi_event* ev)
{
  ef_vi_txq_state* qs = &evq->ep_state->txq;
  uint32_t rawts = timestamp_extract(*ev);
  EF_VI_DEBUG(EF_VI_BUG_ON(qs->ts_nsec != EF_VI_TX_TIMESTAMP_TS_NSEC_INVALID));
  if( evq->ts_format == TS_FORMAT_SECONDS_QTR_NANOSECONDS ) {
    /* Convert 2-bit binary fixed-point nanoseconds value into:
     *  - an integral ns part
     *  - a 16-bit binary fixed point fractional ns part. */
    qs->ts_nsec = rawts >> 2;
    qs->ts_nsec_frac = rawts << (16 - 2);
  } else {
    /* Convert fractional part of 27-bit binary fixed-point seconds value into:
     *  - an integral ns part
     *  - a 16-bit binary fixed point fractional ns part. This fractional part
     *    represents the correction from the binary to decimal seconds
     *    fractional seconds conversion not any real fractional precision;
     *    we could happily omit this. */
    uint64_t nanosecs_fp27 = ((uint64_t) rawts) * 1000000000UL;
    qs->ts_nsec = nanosecs_fp27 >> 27;
    qs->ts_nsec_frac = nanosecs_fp27 >> (27 - 16);
  }
  qs->ts_flags = evq->ep_state->evq.sync_flags;
}


static inline void ef10_tx_event_ts_hi(ef_vi* evq, const ef_vi_event* ev,
                                       ef_event* ev_out)
{
  ef_vi_txq_state* qs = &(evq->ep_state->txq);
  ev_out->tx_timestamp.q_id = QWORD_GET_U(ESF_DZ_TX_QLABEL, *ev);
  EF_VI_DEBUG(EF_VI_BUG_ON(qs->ts_nsec == EF_VI_TX_TIMESTAMP_TS_NSEC_INVALID));
  ev_out->tx_timestamp.ts_nsec = qs->ts_nsec;
  /* Squeeze the 16-bit fractional nanoseconds part of the timestamp into
   * the limited bits available in the ef_vi transmit event structure */
  ev_out->tx_timestamp.ts_nsec_frac = qs->ts_nsec_frac >>
      (16 - EF_VI_TX_TS_FRAC_NS_BITS);
  ev_out->tx_timestamp.ts_flags = qs->ts_flags;
  EF_VI_DEBUG(qs->ts_nsec = EF_VI_TX_TIMESTAMP_TS_NSEC_INVALID);

  if( (evq)->nic_type.variant > 'A' ) {
    uint16_t metabits, delta;
    ef_eventq_state* evqs = &(evq->ep_state->evq);
    /* Medford provides 48 bits of timestamp, so we must get the top
     * 16 bits from the timesync event state.
     *
     * See Bug57928 for a description of this section of code and
     * why it gives the correct result
     */
    ev_out->tx_timestamp.ts_sec =
      timestamp_extract_medford_seconds(*ev, &metabits);
    /* Because delta is uint16_t this does an implicit mask down to 16 bits
     * which is what we need, assuming MEDFORD_TX_SECS_EVENT_BITS is 16
     */
    delta = ev_out->tx_timestamp.ts_sec - evqs->sync_timestamp_minimum;
    /* Check that the timestamp in the event is valid.  Must be
     * synchronsied, not marked as invalid, and within expected
     * range
     */
    if( evqs->sync_timestamp_synchronised && (metabits == 0)
        EF_VI_DEBUG(&& delta <= 2*MEDFORD_TX_SECS_SYNC_MIN_OFFSET) ) {
      ev_out->tx_timestamp.ts_sec = delta + evqs->sync_timestamp_minimum;
    }
    else {
      ev_out->tx_timestamp.ts_sec = 0;
      ev_out->tx_timestamp.ts_nsec = 0;
    }
  }
  else {
    ev_out->tx_timestamp.ts_sec = timestamp_extract(*ev);
  }

  ev_out->tx_timestamp.ts_nsec += evq->tx_ts_correction_ns;
  if( ev_out->tx_timestamp.ts_nsec >= 1000000000 ) {
    ev_out->tx_timestamp.ts_nsec -= 1000000000;
    ev_out->tx_timestamp.ts_sec += 1;
  }
}


static inline void ef10_tx_event_ts_rq_id(ef_vi* evq, ef_event* ev_out)
{
  ef_vi_txq_state* qs = &(evq->ep_state->txq);
  ef_vi_txq* q = &evq->vi_txq;
  while( q->ids[qs->removed & q->mask] == EF_REQUEST_ID_MASK )
    ++qs->removed;
  ev_out->tx_timestamp.rq_id = q->ids[qs->removed & q->mask];
  q->ids[qs->removed & q->mask] = EF_REQUEST_ID_MASK;
  ++qs->removed;
}


static void ef10_tx_event_ts_enabled(ef_vi* evq, const ef_vi_event* ev,
				     ef_event** evs, int* evs_len)
{
  /* When TX timestamping is enabled, we get three events for every
   * transmit.  A TX completion and two timestamp events.  We ignore the
   * completion and store the first timestamp in the per TXQ state.  On the
   * second timestamp we retrieve the first one and construct a
   * EF_EVENT_TYPE_TX_WITH_TIMESTAMP event to send to the user.
   */
  ef_event* ev_out;
  uint32_t ev_type = QWORD_GET_U(ESF_EZ_TX_SOFT1, *ev);
  switch( ev_type ) {
  case TX_TIMESTAMP_EVENT_TX_EV_COMPLETION:
  case TX_TIMESTAMP_EVENT_TX_EV_CTPIO_COMPLETION:
    break;
  case TX_TIMESTAMP_EVENT_TX_EV_TSTAMP_LO:
  case TX_TIMESTAMP_EVENT_TX_EV_CTPIO_TS_LO:
    ef10_tx_event_ts_lo(evq, ev);
    break;
  case TX_TIMESTAMP_EVENT_TX_EV_TSTAMP_HI:
  case TX_TIMESTAMP_EVENT_TX_EV_CTPIO_TS_HI:
    ev_out = (*evs)++;
    --(*evs_len);
    ev_out->tx.type = EF_EVENT_TYPE_TX_WITH_TIMESTAMP;
    if( ev_type == TX_TIMESTAMP_EVENT_TX_EV_CTPIO_TS_HI )
      ev_out->tx.flags = EF_EVENT_FLAG_CTPIO;
    else
      ev_out->tx.flags = 0;
    ef10_tx_event_ts_hi(evq, ev, ev_out);
    ef10_tx_event_ts_rq_id(evq, ev_out);
    break;
  default:
    ef_log("%s:%d: ERROR: soft1=%x ev="CI_QWORD_FMT, __FUNCTION__,
           __LINE__, (unsigned) QWORD_GET_U(ESF_EZ_TX_SOFT1, *ev),
           CI_QWORD_VAL(*ev));
    break;
  }
}


static inline void ef10_tx_event_completion(ef_vi* evq, const ef_vi_event* ev,
                                            ef_event** evs, int* evs_len)
{
  ef_event* ev_out = (*evs)++;
  unsigned ev_type = QWORD_GET_U(ESF_EZ_TX_SOFT1, *ev);

  EF_VI_ASSERT( ev_type == TX_TIMESTAMP_EVENT_TX_EV_COMPLETION ||
                ev_type == TX_TIMESTAMP_EVENT_TX_EV_CTPIO_COMPLETION );

  --(*evs_len);
  ev_out->tx.q_id = QWORD_GET_U(ESF_DZ_TX_QLABEL, *ev);
  ev_out->tx.desc_id = QWORD_GET_U(ESF_DZ_TX_DESCR_INDX, *ev) + 1;
  ev_out->tx.type = EF_EVENT_TYPE_TX;
  if( ev_type == TX_TIMESTAMP_EVENT_TX_EV_CTPIO_COMPLETION )
    ev_out->tx.flags = EF_EVENT_FLAG_CTPIO;
  else
    ev_out->tx.flags = 0;
  ev_out->tx.deferred_evs = 0;
}


static void ef10_tx_event_alt(ef_vi* evq, const ef_vi_event* ev,
                              ef_event** evs, int* evs_len)
{
  ef_event* ev_out;
  unsigned alt_id;

  /* User is not permitted to ask for timestamps at time of writing, as it
   * makes handling completions hard.  (Note however that the hardware TXQ
   * does have timestamp events enabled, as these are needed to handle
   * 'alt' completions).
   */
  EF_VI_ASSERT( ! (evq->vi_flags & EF_VI_TX_TIMESTAMPS) );

  switch( QWORD_GET_U(ESF_EZ_TX_SOFT1, *ev) ) {
  case TX_TIMESTAMP_EVENT_TX_EV_COMPLETION:
  case TX_TIMESTAMP_EVENT_TX_EV_CTPIO_COMPLETION:
    ef10_tx_event_completion(evq, ev, evs, evs_len);
    break;
  case TX_TIMESTAMP_EVENT_TX_EV_TSTAMP_LO:
    break;
  case TX_TIMESTAMP_EVENT_TX_EV_TSTAMP_HI:
    alt_id = QWORD_GET_U(ESF_DZ_TX_SOFT2, *ev) & 0x1f/*??magic*/;
    if( alt_id != 0x1f ) {  /* 0x1f means a normal send completed. */
      ev_out = (*evs)++;
      --(*evs_len);
      ev_out->tx.type = EF_EVENT_TYPE_TX_ALT;
      ev_out->tx_alt.q_id = QWORD_GET_U(ESF_DZ_TX_QLABEL, *ev);
      ev_out->tx_alt.alt_id = evq->tx_alt_hw2id[alt_id];
    }
    break;
  default:
    break;
  }
}


ef_vi_inline void ef10_tx_event(ef_vi* evq, const ef_vi_event* ev,
				ef_event** evs, int* evs_len)
{
  EF_VI_ASSERT( EF_VI_IS_EVENT(ev) );
  if( (evq->vi_flags & (EF_VI_TX_TIMESTAMPS | EF_VI_TX_ALT)) == 0 ) {
    /* Transmit completion event.  Indicates how many descriptors have been
     * consumed and that DMA reads have completed.
     */
    ef10_tx_event_completion(evq, ev, evs, evs_len);
  }
  /* It would make sense to check (evq->vi_flags & EF_VI_TX_ALT)
   * instead of tx_alt_num here, but we don't because although the VI
   * might have been allocated with alternatives, it's possible they
   * aren't in use.
   */
  else if( evq->tx_alt_num ) {
    EF_VI_ASSERT( evq->vi_flags & EF_VI_TX_ALT );
    ef10_tx_event_alt(evq, ev, evs, evs_len);
  }
  else {
    EF_VI_ASSERT( evq->vi_flags & EF_VI_TX_ALT || 
		  evq->vi_flags & EF_VI_TX_TIMESTAMPS );
    if( evq->vi_flags & EF_VI_TX_TIMESTAMPS )
      ef10_tx_event_ts_enabled(evq, ev, evs, evs_len);
    else
      ef10_tx_event_completion(evq, ev, evs, evs_len);
  }
}

ef_vi_inline int
ef10_ef_vi_receive_get_precise_timestamp_from_tsync(ef_vi* vi,
	const void* pkt, ef_precisetime* ts_out,
	uint32_t tsync_minor, uint32_t tsync_major)
{
  const uint32_t FLAG_NO_TIMESTAMP = 0x80000000;
  const uint32_t ONE_SEC = 0x8000000;
  const uint32_t MAX_RX_PKT_DELAY = 0xCCCCCC;  /* ONE_SECOND / 10 */
  const uint32_t MAX_TIME_SYNC_DELAY = 0x1999999; /* ONE_SECOND * 2 / 10 */
  const uint32_t SYNC_EVENTS_PER_SECOND = 4;

  /* sync_timestamp_major contains the number of seconds and
   * sync_timestamp_minor contains the upper bits of ns.
   *
   * The API dictates that this function be called before
   * eventq_poll() is called again.  We do not allow
   * eventq_poll() to process mcdi events (time sync events) if
   * it has already processed any normal events.  Hence, we are
   * guaranteed that the RX events should be happening in the
   * range [MAX_RX_PKT_DELAY before time sync event, ONE_SECOND
   * / SYNC_EVENTS_PER_SECOND + MAX_TIME_SYNC_DELAY after time
   * sync event].
   */

  /* Note that pkt_minor is not ns since last sync event but
   * simply the current ns.
   */

  /* Note that it is possible for us to incorrectly associate a
   * pkt_minor with an invalid sync event and there is no way to
   * detect it.
   */

  ef_eventq_state* evqs = &(vi->ep_state->evq);
  uint32_t* data = (uint32_t*) ((uint8_t*)pkt +
                                ES_DZ_RX_PREFIX_TSTAMP_OFST);
  /* pkt_minor contains 27 bits of ns */
  uint32_t pkt_minor_raw = le32_to_cpu(*data);
  uint32_t diff;

  if( ~pkt_minor_raw & FLAG_NO_TIMESTAMP ) {
    uint32_t pkt_minor =
      ( pkt_minor_raw + vi->rx_ts_correction) & 0x7FFFFFF;
    uint64_t nsec_fp27 = ((uint64_t) pkt_minor) * 1000000000UL;
    ts_out->tv_nsec = nsec_fp27 >> 27;
    ts_out->tv_nsec_frac = nsec_fp27 >> (27 - 16);
    diff = (pkt_minor - tsync_minor) & (ONE_SEC - 1);
    if (diff < (ONE_SEC / SYNC_EVENTS_PER_SECOND) +
        MAX_TIME_SYNC_DELAY) {
      /* pkt_minor taken after sync event in the
       * valid range.  Adjust seconds if sync event
       * happened, then the second boundary, and
       * then the pkt_minor.
       */
      ts_out->tv_sec = tsync_major;
      ts_out->tv_sec +=
        diff + tsync_minor >= ONE_SEC;
      ts_out->tv_flags = evqs->sync_flags;
      return 0;
    } else if (diff > ONE_SEC - MAX_RX_PKT_DELAY) {
      /* pkt_minor taken before sync event in the
       * valid range.  Adjust seconds if pkt_minor
       * happened, then the second boundary, and
       * then the sync event.
       */
      ts_out->tv_sec = tsync_major;
      ts_out->tv_sec -=
        diff + tsync_minor < ONE_SEC;
      ts_out->tv_flags = evqs->sync_flags;
      return 0;
    } else {
      /* diff between pkt_minor and sync event in
       * invalid range.  Either function used
       * incorrectly or we lost some sync events.
       */
      evqs->sync_timestamp_synchronised = 0;
    }
  }
  *ts_out = (ef_precisetime) { 0 };
  if( (pkt_minor_raw & FLAG_NO_TIMESTAMP) != 0 )
    return -ENODATA;
  return (tsync_major == ~0u) ? -ENOMSG : -EL2NSYNC;
}

ef_vi_inline int
ef10_ef_vi_receive_get_precise_timestamp_from_tsync_qns
	(ef_vi* vi, const void* pkt, ef_precisetime* ts_out,
	 uint32_t tsync_minor, uint32_t tsync_major)
{
  const uint32_t NO_TIMESTAMP = 0xFFFFFFFF;
  /* Since M2, timestamp_minor unit is quarter nanoseconds */
  const uint32_t ONE_SEC             = 4000000000U;
  const uint32_t MAX_RX_PKT_DELAY    =  400000000U; /* ONE_SEC / 10 */
  const uint32_t MAX_TIME_SYNC_DELAY =  800000000U; /* ONE_SEC * 2 / 10 */
  const uint32_t SYNC_EVENTS_PER_SECOND = 4;

  /* M2 can overrun pkt_minor a little due to an adjustment that isn't
   * wrapped.  According to bugzilla it can overrun by up to 15.  We
   * inflate a little in case that is wrong.
   */
  const uint32_t BUG75412_OVERRUN    = 20;

  /* Comments in sibling function,
   * ef10_ef_vi_receive_get_precise_timestamp_from_tsync apply here.
   */

  ef_eventq_state* evqs = &(vi->ep_state->evq);
  uint32_t* data = (uint32_t*) ((uint8_t*)pkt + ES_DZ_RX_PREFIX_TSTAMP_OFST);
  uint32_t pkt_minor = le32_to_cpu(*data);
  uint32_t diff;
  int pkt_lt_tsync;

  /* Ensure correction does not move NO_TIMESTAMP into the positive range. */
  EF_VI_ASSERT(vi->rx_ts_correction <= 0);

  /* pkt_minor is in the range [0, ONE_SEC + BUG75412_OVERRUN), or has the
   * value NO_TIMESTAMP.  
   *
   * Apply rx_ts_correction, which accounts for time delta between wire and
   * MAC (+ 2ns to improve rounding).  It is expected to be negative but
   * could be slightly positive if MAC delay was tiny.
   */
  pkt_minor += vi->rx_ts_correction;

  /* pkt_minor is logically in the range
   *   [slightly_negative, ONE_SEC + BUG75412_OVERRUN).
   *
   * But pkt_minor is uint32_t, so slightly_negative translates to
   * (1<<32)-a_bit.  This allows us to test for [0, ONE_SEC) more cheaply
   * than if pkt_minor were int64_t.
   */
  if(likely( pkt_minor < ONE_SEC ))
    ;
  else if(likely( pkt_minor < ONE_SEC + BUG75412_OVERRUN + 2 ))
    pkt_minor -= ONE_SEC;
  /* It would be cleaner to test for NO_TIMESTAMP prior to applying the
   * correction, but doing it this way moves the test off the fast path.
   */
  else if(likely( pkt_minor != NO_TIMESTAMP + vi->rx_ts_correction ))
    pkt_minor += ONE_SEC;
  else {
    *ts_out = (ef_precisetime) { 0 };
    return -ENODATA;
  }
  EF_VI_ASSERT( pkt_minor < ONE_SEC );

  /* Take the difference mod ONE_SEC.  The upper end of the ONE_SEC range
   * is 'negative'.  (This slightly obfuscated code avoids a conditional
   * jump, at least on x86_64).
   */
  pkt_lt_tsync = pkt_minor < tsync_minor;
  diff = pkt_minor - tsync_minor + (ONE_SEC & -pkt_lt_tsync);

  if(likely( diff < (ONE_SEC/SYNC_EVENTS_PER_SECOND) + MAX_TIME_SYNC_DELAY )) {
    /* tsync before pkt (and in expected range).  Most common case. */
    tsync_major += pkt_lt_tsync;
  }
  else if(likely( diff > ONE_SEC - MAX_RX_PKT_DELAY )) {
    /* pkt before tsync (and in expected range).
     *
     * NB. We really want "tsync_major -= tsync_lt_pkt", but this is okay
     * because pkt_minor!=tsync_minor here (as diff would be 0).
     */
    int tsync_le_pkt = ! pkt_lt_tsync;
    tsync_major -= tsync_le_pkt;
  }
  else {
    /* Zero ts_out in case of failure to avoid returning garbage. */
    *ts_out = (ef_precisetime) { 0 };
    evqs->sync_timestamp_synchronised = 0;
    return (tsync_major == ~0u) ? -ENOMSG : -EL2NSYNC;
  }

  ts_out->tv_sec = tsync_major;
  ts_out->tv_nsec = pkt_minor >> 2;
  ts_out->tv_nsec_frac = pkt_minor << (16 - 2);
  ts_out->tv_flags = evqs->sync_flags;
  return 0;
}

int ef10_receive_get_precise_timestamp_internal
	(ef_vi* vi, const void* pkt, ef_precisetime* ts_out,
	 uint32_t tsync_minor, uint32_t tsync_major)
{
  /* This function is where TCPDirect hooks in to implement its own
   * timestamping API; making changes hereon has the benefit of not needing
   * any TCPDirect changes.
   */
  if( vi->ts_format == TS_FORMAT_SECONDS_QTR_NANOSECONDS )
    return ef10_ef_vi_receive_get_precise_timestamp_from_tsync_qns
             (vi, pkt, ts_out, tsync_minor, tsync_major);
  else
    return ef10_ef_vi_receive_get_precise_timestamp_from_tsync
             (vi, pkt, ts_out, tsync_minor, tsync_major);
}

int
ef10_receive_get_precise_timestamp(ef_vi* vi, const void* pkt,
                                   ef_precisetime* ts_out)
{

  /* Divided so we can calculate timestamps for packets using older
   * `sync_timstamp`s. Useful in finding a way around the interaction with
   * ef_eventq_poll.
   **/

  ef_eventq_state* evqs = &(vi->ep_state->evq);
  uint32_t tsync_minor = evqs->sync_timestamp_minor;
  uint32_t tsync_major = evqs->sync_timestamp_major;

  /* We want to check whether the eventq is in sync here rather than in the
   * internal hook that we've created. This is because TCPDirect will be
   * storing timestamps to translate them later and will be dealing with
   * the case of the eventq being out of sync itself. */
  if(unlikely( ! evqs->sync_timestamp_synchronised )) {
    *ts_out = (ef_precisetime) { 0 };
    return -EL2NSYNC;
  }
  else {
    return ef10_receive_get_precise_timestamp_internal
	    (vi, pkt, ts_out, tsync_minor, tsync_major);
  }
}


extern int
ef_vi_receive_get_timestamp_with_sync_flags(ef_vi* vi, const void* pkt,
                                            ef_timespec* ts_out,
                                            unsigned* flags_out)
{
  ef_precisetime ts;
  int rc;

  rc = ef_vi_receive_get_precise_timestamp(vi, pkt, &ts);
  ts_out->tv_sec = ts.tv_sec;
  ts_out->tv_nsec = ts.tv_nsec;
  *flags_out = ts.tv_flags;
  return rc;
}


extern int
ef_vi_receive_get_timestamp(ef_vi* vi, const void* pkt,
			    ef_timespec* ts_out)
{
  ef_precisetime ts;
  int rc;

  rc = ef_vi_receive_get_precise_timestamp(vi, pkt, &ts);
  ts_out->tv_sec = ts.tv_sec;
  ts_out->tv_nsec = ts.tv_nsec;
  return rc < 0 ? -1 : 0;
}


static void ef10_major_tick(ef_vi* vi, unsigned major, unsigned minor,
			    unsigned sync_flags)
{
  ef_eventq_state* evqs = &(vi->ep_state->evq);
  evqs->sync_timestamp_major = major;
  evqs->sync_timestamp_minor = minor;
  /* Only used for Medford TX timestamps, but quicker to precompute
   * here rather than on every timestamp event
   */
  evqs->sync_timestamp_minimum =
    evqs->sync_timestamp_major - MEDFORD_TX_SECS_SYNC_MIN_OFFSET;
  evqs->sync_timestamp_synchronised = 1;
  evqs->sync_flags = sync_flags;
}


static void ef10_mcdi_event(ef_vi* evq, const ef_vi_event* ev,
			    ef_event** evs, int* evs_len)
{
  int code = QWORD_GET_U(MCDI_EVENT_CODE, *ev);
  uint32_t major, minor;
  /* Sync status reporting not supported, let's assume clock is
   * always in sync */
  uint32_t sync_flags = EF_VI_SYNC_FLAG_CLOCK_SET |
    EF_VI_SYNC_FLAG_CLOCK_IN_SYNC;

  switch( code ) {
  case MCDI_EVENT_CODE_PTP_TIME:
    major = QWORD_GET_U(MCDI_EVENT_PTP_TIME_MAJOR, *ev);
    if( evq->ts_format == TS_FORMAT_SECONDS_QTR_NANOSECONDS )
      minor = QWORD_GET_U(MCDI_EVENT_PTP_TIME_MINOR_26_21, *ev) << 26;
    else
      minor = QWORD_GET_U(MCDI_EVENT_PTP_TIME_MINOR_26_21, *ev) << 21;
    if( evq->vi_out_flags & EF_VI_OUT_CLOCK_SYNC_STATUS )
      sync_flags =
        (QWORD_GET_U(MCDI_EVENT_PTP_TIME_NIC_CLOCK_VALID, *ev) ?
         EF_VI_SYNC_FLAG_CLOCK_SET: 0) |
        (QWORD_GET_U(MCDI_EVENT_PTP_TIME_HOST_NIC_IN_SYNC, *ev) ?
         EF_VI_SYNC_FLAG_CLOCK_IN_SYNC: 0);
    ef10_major_tick(evq, major, minor, sync_flags);
    break;
  case 0: {
    /* MCDI event code 0 indicates a software event
     * generated using ef10_nic_sw_event.
     * TODO: event code 0 should be added to MCDI headers */
    ef_event* ev_out = (*evs)++;
    --(*evs_len);
    ev_out->sw.type = EF_EVENT_TYPE_SW;
    ev_out->sw.data = CI_DWORD_VAL(*ev);
    break;
  }
  case MCDI_EVENT_CODE_TX_FLUSH:
  case MCDI_EVENT_CODE_RX_FLUSH:
    /* Normally we will stop polling before flushing. The exception is the case
     * where we issue an emergency flush in response to a device-removal
     * notification. At user-level there is no clean way to determine whether
     * this has happened, so just swallow the event in NDEBUG builds. */
    LOG(ef_log("%s: Saw flush in poll (code=%u)", __FUNCTION__, code));
    break;
  case MCDI_EVENT_CODE_TX_ERR:
    ef_log("%s: ERROR: MCDI TX error event %x (raw: "CI_QWORD_FMT") - "
           "check parameters to transmit_init()", __FUNCTION__,
           QWORD_GET_U(MCDI_EVENT_TX_ERR_DATA, *ev), CI_QWORD_VAL(*ev));
    break;
  case MCDI_EVENT_CODE_RX_ERR:
    ef_log("%s: ERROR: MCDI RX error event %x (raw: "CI_QWORD_FMT") - "
           "check parameters to receive_init()", __FUNCTION__,
           QWORD_GET_U(MCDI_EVENT_RX_ERR_DATA, *ev), CI_QWORD_VAL(*ev));
    break;
  case MCDI_EVENT_CODE_MC_REBOOT: {
    ef_event* ev_out = (*evs)++;
    --(*evs_len);
    ev_out->generic.type = EF_EVENT_TYPE_RESET;
    break;
  }
  default:
    ef_log("%s: ERROR: Unhandled MCDI event code=%u desc=" CI_QWORD_FMT,
           __FUNCTION__, code, CI_QWORD_VAL(*ev));
    break;
  }
}


int ef10_ef_eventq_poll(ef_vi* evq, ef_event* evs, int evs_len)
{
  int evs_len_orig = evs_len;
  ef_vi_event *pev, ev;
  static int overflow_logged = 0;

  EF_VI_BUG_ON(evs == NULL);

  if(unlikely( EF_VI_IS_EVENT(EF_VI_EVENT_PTR(evq,
                                   evq->ep_state->evq.evq_clear_stride - 1)) ))
    goto overflow;

 not_empty:
  /* Read the event out of the ring, then fiddle with copied version.
   * Reason is that the ring is likely to get pushed out of cache by
   * another event being delivered by hardware.
   */
  pev = EF_VI_EVENT_PTR(evq, 0);
  ev = *pev;
  if (!EF_VI_IS_EVENT(&ev))
    goto empty;
  do {
    /* Ugly: Exploit the fact that event code lies in top bits
     * of event. */
    BUG_ON(ESF_DZ_EV_CODE_LBN < 32u);
    switch( CI_QWORD_FIELD(ev, ESF_DZ_EV_CODE) ) {
    case ESE_DZ_EV_CODE_RX_EV:
      ef10_rx_event(evq, &ev, &evs, &evs_len);
      break;

    case ESE_DZ_EV_CODE_TX_EV:
      ef10_tx_event(evq, &ev, &evs, &evs_len);
      break;

    case ESE_DZ_EV_CODE_MCDI_EV:
      /* Do not process MCDI events if we have
       * already delivered other events to the
       * app */
      if (evs_len != evs_len_orig)
        goto out;
      ef10_mcdi_event(evq, &ev, &evs, &evs_len);
      break;

    case ESE_DZ_EV_CODE_DRIVER_EV:
      if (QWORD_GET_U(ESF_DZ_DRV_SUB_CODE, ev) ==
          ESE_DZ_DRV_START_UP_EV)
        /* Ignore. */
        break;
      ci_fallthrough;
    default:
      ef_log("%s: ERROR: event type=%u ev="CI_QWORD_FMT,
             __FUNCTION__,
             (unsigned) CI_QWORD_FIELD(ev, ESF_DZ_EV_CODE),
             CI_QWORD_VAL(ev));
      break;
    }

    /* Consume event.  Must do after event checking above,
     * in case we don't want to consume it. */
    CI_SET_QWORD(*EF_VI_EVENT_PTR(evq, evq->ep_state->evq.evq_clear_stride));
    evq->ep_state->evq.evq_ptr += sizeof(ef_vi_event);

    if (evs_len == 0)
      break;

    pev = EF_VI_EVENT_PTR(evq, 0);
    ev = *pev;
  } while (EF_VI_IS_EVENT(&ev));

 out:
  return evs_len_orig - evs_len;

 empty:
  if (EF_VI_IS_EVENT(EF_VI_EVENT_PTR(evq, 1))) {
    smp_rmb();
    if (!EF_VI_IS_EVENT(EF_VI_EVENT_PTR(evq, 0))) {
      ef_log("%s: misplaced event (empty) in %u",
             __FUNCTION__, evq->vi_i);
      /* No event in current slot, but there is one in
       * the next slot.  Has NIC failed to write event
       * somehow?
       */
      evq->ep_state->evq.evq_ptr += sizeof(ef_vi_event);
      INC_ERROR_STAT(evq, evq_gap);
      goto not_empty;
    }
  }

  return 0;

 overflow:
  evs->generic.type = EF_EVENT_TYPE_OFLOW;
  if( overflow_logged == 0 ) {
    int i;

    ef_log("%s: ERROR: overflow in %d at 0x%x", __FUNCTION__, evq->vi_i,
           (unsigned) EF_VI_EVENT_OFFSET(evq, 0));

    for( i = 0; i <= evq->evq_mask / EF_VI_EV_SIZE; i++ )
      ef_log("%04x: "CI_QWORD_FMT, i, CI_QWORD_VAL(*EF_VI_EVENT_PTR(evq, i)));

    overflow_logged = 1;
  }
  return 1;
}


void ef10_ef_eventq_prime(ef_vi* vi)
{
  unsigned ring_i = (ef_eventq_current(vi) & vi->evq_mask) / 8;
  EF_VI_ASSERT(vi->inited & EF_VI_INITED_IO);
  ef10_update_evq_rptr(vi->io, ring_i);
}


void ef10_ef_eventq_prime_bug35388_workaround(ef_vi* vi)
{
  unsigned ring_i = (ef_eventq_current(vi) & vi->evq_mask) / 8;
  EF_VI_ASSERT(vi->inited & EF_VI_INITED_IO);
  ef10_update_evq_rptr_bug35388_workaround(vi->io, ring_i);
}


ef_vi_inline int ef10_unbundle_one_packet(ef_vi* vi,
					  ef_packed_stream_packet* pkt)
{
  const uint8_t* prefix = (void*)((char*) pkt + EF_VI_PS_METADATA_OFFSET);
  uint16_t pkt_len, orig_len;
  ef_precisetime ts = { 0 };
  int offset, rc;

  EF_VI_ASSERT(((ci_uintptr_t) prefix & (EF_VI_PS_ALIGNMENT - 1)) == 0);

  pkt_len = *(uint16_t*) (prefix + ES_DZ_PS_RX_PREFIX_CAP_LEN_OFST);
  pkt_len = le16_to_cpu(pkt_len);
  orig_len = *(uint16_t*) (prefix + ES_DZ_PS_RX_PREFIX_ORIG_LEN_OFST);
  orig_len = le16_to_cpu(orig_len);
  pkt->ps_cap_len = pkt_len;
  pkt->ps_orig_len = orig_len;
  pkt->ps_pkt_start_offset =
    EF_VI_PS_METADATA_OFFSET + ES_DZ_PS_RX_PREFIX_SIZE;
  rc = ef_vi_receive_get_precise_timestamp
    (vi, (prefix + ES_DZ_PS_RX_PREFIX_TSTAMP_OFST -
          ES_DZ_RX_PREFIX_TSTAMP_OFST),
     &ts);
  pkt->ps_ts_sec = ts.tv_sec;
  pkt->ps_ts_nsec = ts.tv_nsec;
  /* Zeroing space after header to avoid it being interpreted as an option
   * record.
   */
  *(uint32_t*)(pkt + 1) = 0;
  EF_VI_ASSERT(EF_VI_PS_FLAG_CLOCK_SET ==
               EF_VI_SYNC_FLAG_CLOCK_SET);
  EF_VI_ASSERT(EF_VI_PS_FLAG_CLOCK_IN_SYNC ==
               EF_VI_SYNC_FLAG_CLOCK_IN_SYNC);
  EF_VI_ASSERT((ts.tv_flags & ~(EF_VI_SYNC_FLAG_CLOCK_SET |
                             EF_VI_SYNC_FLAG_CLOCK_IN_SYNC)) == 0);
  pkt->ps_flags = ts.tv_flags;
  offset = EF_VI_ALIGN_FWD(pkt_len + ES_DZ_PS_RX_PREFIX_SIZE
                           + EF_VI_PS_PACKET_GAP,
                           (ci_uintptr_t) EF_VI_PS_ALIGNMENT);
  pkt->ps_next_offset = (uint16_t) offset;
  return rc;
}


ef_vi_inline int ef_ps_max_credits(ef_vi* vi)
{
  int events_available, max_credit;
  int tx_reservation = ef_vi_transmit_capacity(vi);
  /* If TX timestamping is enabled, we may get as many as three events for
   * each transmit.  (Note that TX alternatives use timestamp events to
   * indicate completion).
   */
  if( vi->vi_flags & (EF_VI_TX_TIMESTAMPS | EF_VI_TX_ALT) )
    tx_reservation *= 3;
  /* Leaving extra allowance for periodic timesync events. These arrive at 4
   * per second, so 100 gives us 25 seconds of leeway.
   */
  events_available = ef_eventq_capacity(vi) - tx_reservation - 100;
  max_credit = events_available / EF_VI_PS_MAX_EVENTS_PER_CREDIT;
  if( max_credit < 0 )
    max_credit = 0;
  return max_credit;
}


ef_vi_inline void ef_vi_packed_stream_alloc_credits(ef_vi* vi, int n_credits)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  uint32_t* doorbell = (void*) (vi->io + ER_DZ_RX_DESC_UPD_REG);
  qs->rx_ps_credit_avail += n_credits;
  EF_VI_ASSERT(qs->rx_ps_credit_avail < 128);
  writel(ES_DZ_PS_MAGIC_DOORBELL_CREDIT | n_credits, doorbell);
  mmiowb();
}


void ef_vi_packed_stream_update_credit(ef_vi* vi)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  EF_VI_ASSERT(qs->rx_ps_credit_avail < 128);
  EF_VI_ASSERT(qs->rx_ps_credit_avail <= ef_ps_max_credits(vi));

  if( qs->rx_ps_credit_avail < ef_ps_max_credits(vi) )
    ef_vi_packed_stream_alloc_credits(vi, ef_ps_max_credits(vi) -
                                      qs->rx_ps_credit_avail);
}


ef_vi_inline void ef10_packed_stream_update_credit(ef_vi* vi,
						   ci_uintptr_t start_addr,
						   ci_uintptr_t end_addr)
{
  int credits_consumed = 0;

  EF_VI_ASSERT(((start_addr ^ end_addr) &
                vi->vi_ps_buf_size) == 0);

  /* Can consume at most two credits per event */
  if( (start_addr ^ end_addr) &
      (ci_uintptr_t)EF_VI_PS_SPACE_PER_CREDIT )
    credits_consumed = 1;
  else if ( (start_addr ^ end_addr) &
            (ci_uintptr_t)(EF_VI_PS_SPACE_PER_CREDIT << 1) )
    credits_consumed = 2;

  EF_VI_ASSERT( vi->ep_state->rxq.rx_ps_credit_avail >= credits_consumed);
  vi->ep_state->rxq.rx_ps_credit_avail -= credits_consumed;

  ef_vi_packed_stream_update_credit(vi);
}


int ef_vi_packed_stream_unbundle(ef_vi* vi, const ef_event* ev,
				 ef_packed_stream_packet** pkt_iter,
				 int* n_pkts_out, int* n_bytes_out)
{
  ef_packed_stream_packet* pkt;
  int i, rc, bytes_unpacked = 0;
  ci_uintptr_t dma_start, dma_end;

  EF_VI_ASSERT(EF_EVENT_TYPE(*ev) == EF_EVENT_TYPE_RX_PACKED_STREAM);
  EF_VI_ASSERT(ev->rx_packed_stream.n_pkts > 0);

  rc = 0;
  pkt = *pkt_iter;
  for( i = 0 ; i < ev->rx_packed_stream.n_pkts ; ++i ) {
    /* rc comes from
     * ef10_receive_get_timestamp_with_sync_flags().  Each call
     * in this loop will necessarily return the same value (in
     * the current implementation).  Hence we can return the rc
     * returned by the last call.
     */
    rc = ef10_unbundle_one_packet(vi, pkt);
    pkt->ps_flags |= ev->rx_packed_stream.ps_flags;
    bytes_unpacked += pkt->ps_cap_len;
    pkt = (void*) ((char*) pkt + pkt->ps_next_offset);
  }

  /* Credit update needs to know whether adapter has crossed certain
   * boundaries, so needs to know the start and end DMA addresses.
   */
  dma_start = (ci_uintptr_t) *pkt_iter + EF_VI_PS_METADATA_OFFSET;
  dma_end = (ci_uintptr_t) pkt + EF_VI_PS_METADATA_OFFSET;
  ef10_packed_stream_update_credit(vi, dma_start, dma_end);
  *pkt_iter = pkt;
  *n_pkts_out = ev->rx_packed_stream.n_pkts;
  *n_bytes_out = bytes_unpacked;
  return rc;
}


int ef_vi_packed_stream_get_params(ef_vi* vi,
				   ef_packed_stream_params* psp_out)
{
  if (! vi->vi_is_packed_stream)
    return -EINVAL;
  psp_out->psp_buffer_size = vi->vi_ps_buf_size;
  psp_out->psp_buffer_align = psp_out->psp_buffer_size;
  psp_out->psp_start_offset =
    EF_VI_PS_DMA_START_OFFSET - EF_VI_PS_METADATA_OFFSET;
  psp_out->psp_max_usable_buffers =
    ef_ps_max_credits(vi) * EF_VI_PS_SPACE_PER_CREDIT /
    psp_out->psp_buffer_size
    + 1;
  /* This adjustment is needed because we only post RX descriptors in
   * batches of 8.
   */
  psp_out->psp_max_usable_buffers =
    EF_VI_ROUND_UP(psp_out->psp_max_usable_buffers, 8) + 8;
  return 0;
}

int ef10_ef_eventq_has_many_events(const ef_vi* vi, int n_events)
{
  EF_VI_ASSERT(vi->evq_base);
  EF_VI_BUG_ON(n_events < 0);
  return EF_VI_IS_EVENT(EF_VI_EVENT_PTR(vi, n_events));
}

/*! \cidoxg_end */
