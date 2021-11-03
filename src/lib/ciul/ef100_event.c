/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#include "ef_vi_internal.h"
#include "logging.h"
#include <ci/efhw/mc_driver_pcol.h>
#include <etherfabric/packedstream.h>
#include <ci/efhw/common.h>

typedef ci_qword_t ef_vi_event;


#define EF_VI_EVENT_OFFSET(q, i)                                \
  (((q)->ep_state->evq.evq_ptr + (i) * sizeof(ef_vi_qword)) &	\
   (q)->evq_mask)

#define EF_VI_EVENT_PTR(q, i)                                           \
  ((ef_vi_event*) ((q)->evq_base + EF_VI_EVENT_OFFSET((q), (i))))

#define EF_VI_EVENT_PHASE(evp)                  \
  QWORD_GET_U(ESF_GZ_EV_RXPKTS_PHASE, *(evp))

#define EF_VI_EVQ_PHASE(q, i)                                     \
  ((((q)->ep_state->evq.evq_ptr + sizeof(ef_vi_event) * (i)) &    \
    ((q)->evq_mask + 1)) != 0)

#define INC_ERROR_STAT(vi, name)		\
  do {                                          \
    if ((vi)->vi_stats != NULL)                 \
      ++(vi)->vi_stats->name;                   \
  } while (0)


static inline ef_vi_event* ef100_eventq_get_event_by_offset(ef_vi* evq,
                                                                int offset)
{
  ef_vi_event* ev = EF_VI_EVENT_PTR(evq, offset);
  return (EF_VI_EVENT_PHASE(ev) == EF_VI_EVQ_PHASE(evq, offset)) ? ev : NULL;
}


static inline ef_vi_event* ef100_eventq_get_event(ef_vi* evq)
{
  return ef100_eventq_get_event_by_offset(evq, 0);
}


static inline bool ef100_eventq_is_overflow(ef_vi* evq)
{
  return ef100_eventq_get_event_by_offset(evq, evq->ep_state->evq.evq_clear_stride - 1) == NULL;
}


ef_vi_inline void riverhead_rx_pkts_consumed(ef_vi* vi, const ef_vi_event* ev,
					      ef_event** evs, int* evs_len,
					      int q_label)
{
  ef_event* ev_out = (*evs)++;
  --(*evs_len);

  ev_out->rx_multi_pkts.type = EF_EVENT_TYPE_RX_MULTI_PKTS;
  ev_out->rx_multi_pkts.q_id = q_label;
  ev_out->rx_multi_pkts.n_pkts = QWORD_GET_U(ESF_GZ_EV_RXPKTS_NUM_PKT, *ev);
}


static void ef100_mcdi_event(ef_vi* evq, const ef_vi_event* ev,
			    ef_event** evs, int* evs_len)
{
  int code = QWORD_GET_U(MCDI_EVENT_CODE, *ev);

  switch( code ) {
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
    ef_log("%s: ERROR: Unhandled MCDI event code=%u", __FUNCTION__,
           code);
    break;
  }
}


static void ef100_driver_event(ef_vi* evq, const ef_vi_event* ev,
			    ef_event** evs, int* evs_len)
{
  int subtype = QWORD_GET_U(EF_VI_EV_DRIVER_SUBTYPE, *ev);

  switch( subtype ) {
  case EF_VI_EV_DRIVER_SUBTYPE_MEMCPY_SYNC: {
    ef_event* ev_out = (*evs)++;
    --(*evs_len);
    ev_out->memcpy.type = EF_EVENT_TYPE_MEMCPY;
    ev_out->memcpy.dma_id =
                      QWORD_GET_U(EF_VI_EV_DRIVER_MEMCPY_SYNC_DMA_ID, *ev);
    break;
  }
  default:
    ef_log("%s: ERROR: Unhandled driver event code=%u", __FUNCTION__,
           subtype);
    break;
  }
}


ef_vi_inline void ef100_rx_event(ef_vi* evq_vi, const ef_vi_event* ev,
				ef_event** evs, int* evs_len)
{
  unsigned q_label = QWORD_GET_U(ESF_GZ_EV_RXPKTS_Q_LABEL, *ev);
  ef_vi* vi = evq_vi->vi_qs[q_label];
  if(likely( vi != NULL )) {
    riverhead_rx_pkts_consumed(vi, ev, evs, evs_len, q_label);
  }
  else {
    INC_ERROR_STAT(evq_vi, rx_ev_bad_q_label);
  }
}


static inline void write_tx_event(ef_event** evs, int* evs_len, int q_label,
                                  unsigned num_desc, unsigned* desc_id)
{
  ef_event* ev_out = (*evs)++;
  --(*evs_len);
  ev_out->tx.type = EF_EVENT_TYPE_TX;
  ev_out->tx.q_id = q_label;
  desc_id[q_label] += num_desc;
  ev_out->tx.desc_id = desc_id[q_label];
}


static inline void ef100_tx_event_completion(ef_vi* evq, const ef_vi_event* ev,
                                            ef_vi_event* pev, ef_event** evs,
                                            int* evs_len, unsigned* desc_id,
                                            unsigned* desc_init)
{
  int q_label = QWORD_GET_U(ESF_GZ_EV_TXCMPL_Q_LABEL, *ev);
  unsigned num_desc = QWORD_GET_U(ESF_GZ_EV_TXCMPL_NUM_DESC, *ev);

  if(likely( ! (*desc_init & (1u << q_label)) )) {
    ef_vi* vi = evq->vi_qs[q_label];
    if( ! vi ) {
      INC_ERROR_STAT(evq, rx_ev_bad_q_label);
      return;
    }
    desc_id[q_label] = vi->ep_state->txq.removed;
    *desc_init |= 1u << q_label;
  }

  if(unlikely( num_desc > EF_VI_TRANSMIT_BATCH )) {
    /* This would (potentially) overflow the output array of
     * ef_vi_transmit_unbundle(), so we create multiple ef_vi_events from the
     * single ef_event by consuming it piecemeal and leaving it in-place */
    do {
      write_tx_event(evs, evs_len, q_label, EF_VI_TRANSMIT_BATCH, desc_id);
      num_desc -= EF_VI_TRANSMIT_BATCH;
      if( *evs_len == 0 ) {
        /* Doubly-unlikely: we expanded this so much that we need to resume
         * next time */
        CI_SET_QWORD_FIELD(*pev, ESF_GZ_EV_TXCMPL_NUM_DESC, num_desc);
        evq->ep_state->evq.evq_ptr -= sizeof(ef_vi_event);
        return;
      }
    } while( num_desc > EF_VI_TRANSMIT_BATCH );
  }
  write_tx_event(evs, evs_len, q_label, num_desc, desc_id);
}


ef_vi_inline void ef100_tx_event(ef_vi* evq, const ef_vi_event* ev,
				ef_vi_event* pev, ef_event** evs, int* evs_len,
				unsigned* desc_id, unsigned* desc_init)
{
  if( (evq->vi_flags & EF_VI_TX_TIMESTAMPS) == 0 ) {
    ef100_tx_event_completion(evq, ev, pev, evs, evs_len, desc_id, desc_init);
  }
  else {
    /* TODO: */
    ef_log("%s: ERROR: TX TIMESTAMPS", __FUNCTION__);
    EF_VI_ASSERT(0);
  }
}


int ef100_ef_eventq_poll(ef_vi* evq, ef_event* evs, int evs_len)
{
  unsigned ev_type;
  int evs_len_orig = evs_len;
  ef_vi_event *pev, ev;
  static int overflow_logged = 0;
  unsigned tx_desc_id[EF_VI_MAX_QS];
  unsigned tx_desc_init = 0;

  EF_VI_BUG_ON(evs == NULL);
  EF_VI_BUG_ON(ESF_GZ_EV_RXPKTS_PHASE_LBN != ESF_GZ_EV_TXCMPL_PHASE_LBN);

  if(unlikely( ef100_eventq_is_overflow(evq) ))
    goto overflow;

  pev = ef100_eventq_get_event(evq);
  if( !pev )
    return 0;

  do {
    ev = *pev;

    /* Ugly: Exploit the fact that event code lies in top bits
     * of event. */
    ev_type = QWORD_GET_U(ESF_GZ_E_TYPE, ev);
    switch( ev_type ) {
    case ESE_GZ_EF100_EV_RX_PKTS:
      ef100_rx_event(evq, &ev, &evs, &evs_len);
      break;

    case ESE_GZ_EF100_EV_TX_COMPLETION:
      ef100_tx_event(evq, &ev, pev, &evs, &evs_len, tx_desc_id, &tx_desc_init);
      break;

    case ESE_GZ_EF100_EV_MCDI:
      /* Do not process MCDI events if we have
       * already delivered other events to the
       * app */
      if (evs_len != evs_len_orig)
        goto out;
      ef100_mcdi_event(evq, &ev, &evs, &evs_len);
      break;

    case ESE_GZ_EF100_EV_DRIVER:
      ef100_driver_event(evq, &ev, &evs, &evs_len);
      break;

    case ESE_GZ_EF100_EV_CONTROL:
      ef_log("%s: ERROR: ESE_GZ_EF100_EV_CONTROL is not supported", __FUNCTION__);
      --evs_len;
        break;
      /* ...deliberate fall-through... */
    default:
      ef_log("%s: ERROR: event ev="CI_QWORD_FMT,
             __FUNCTION__,
             CI_QWORD_VAL(ev));
      break;
    }

    evq->ep_state->evq.evq_ptr += sizeof(ef_vi_event);

    if (evs_len == 0)
      break;

    pev = ef100_eventq_get_event(evq);
  } while( pev );

 out:
  return evs_len_orig - evs_len;

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


int ef_eventq_check_event_phase_bit(const ef_vi* vi, int look_ahead)
{
  ef_vi_event* ev;

  EF_VI_ASSERT(vi->evq_base);
  EF_VI_BUG_ON(look_ahead < 0);

  ev = EF_VI_EVENT_PTR(vi, look_ahead);
  return (EF_VI_EVENT_PHASE(ev) == EF_VI_EVQ_PHASE(vi, look_ahead));
}


/* TODO: */
void ef100_ef_eventq_prime(ef_vi* vi)
{
  ef100_unsupported_msg(__FUNCTION__);
}


void ef100_ef_eventq_timer_prime(ef_vi* q, unsigned v)
{
  /* FIXME: it is used by Onload */
}


void ef100_ef_eventq_timer_run(ef_vi* q, unsigned v)
{
  /* FIXME: it is used by Onload */
}


void ef100_ef_eventq_timer_clear(ef_vi* q)
{
  /* FIXME: it is used by Onload */
}


void ef100_ef_eventq_timer_zero(ef_vi* q)
{
  ef100_unsupported_msg(__FUNCTION__);
}

/*! \cidoxg_end */
