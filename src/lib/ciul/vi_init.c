/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */

/*
 * \author  djr
 *  \brief  Initialisation of VIs.
 *   \date  2007/06/08
 */

#include "ef_vi_internal.h"
#include "efch_intf_ver.h"
#include <onload/version.h>
#include "logging.h"
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/efhw/common.h>
#define ONLOAD_BUILD_PROFILE "ef_vi"
#include "onload_version.h"

#ifndef __KERNEL__
#include <limits.h>
#endif

#define EF_VI_STATE_BYTES(rxq_sz, txq_sz)               \
  (sizeof(ef_vi_state) + (rxq_sz) * sizeof(uint32_t)	\
   + (txq_sz) * sizeof(uint32_t))


unsigned ef_vi_evq_clear_stride(void)
{
#ifndef __KERNEL__
  const char* s = getenv("EF_VI_EVQ_CLEAR_STRIDE");
  if( s != NULL )
    return atoi(s);
#endif

# ifdef __x86_64__
  return sys_is_numa() ? EF_VI_EVS_PER_CACHE_LINE : 0;
# else
  return EF_VI_EVS_PER_CACHE_LINE;
# endif
}


int ef_vi_calc_state_bytes(int rxq_sz, int txq_sz)
{
  EF_VI_BUG_ON(rxq_sz != 0 && ! EF_VI_IS_POW2(rxq_sz));
  EF_VI_BUG_ON(txq_sz != 0 && ! EF_VI_IS_POW2(txq_sz));

  return EF_VI_STATE_BYTES(rxq_sz, txq_sz);
}


int ef_vi_state_bytes(ef_vi* vi)
{
  int rxq_sz = 0, txq_sz = 0;
  if( vi->vi_rxq.mask )
    rxq_sz = vi->vi_rxq.mask + 1;
  if( vi->vi_txq.mask )
    txq_sz = vi->vi_txq.mask + 1;

  EF_VI_BUG_ON(rxq_sz != 0 && ! EF_VI_IS_POW2(rxq_sz));
  EF_VI_BUG_ON(txq_sz != 0 && ! EF_VI_IS_POW2(txq_sz));

  return EF_VI_STATE_BYTES(rxq_sz, txq_sz);
}


void ef_vi_init_state(ef_vi* vi)
{
  ef_vi_reset_rxq(vi);
  ef_vi_reset_txq(vi);
  /* NB. Must not clear the ring as it may already have an
   * initialisation event in it.
   */
  ef_vi_reset_evq(vi, 0);
}


int ef_vi_add_queue(ef_vi* evq_vi, ef_vi* add_vi)
{
  int q_label;
  if (evq_vi->vi_qs_n == EF_VI_MAX_QS)
    return -EBUSY;
  q_label = evq_vi->vi_qs_n++;
  EF_VI_BUG_ON(evq_vi->vi_qs[q_label] != NULL);
  evq_vi->vi_qs[q_label] = add_vi;
  return q_label;
}


void ef_vi_set_stats_buf(ef_vi* vi, ef_vi_stats* s)
{
  vi->vi_stats = s;
}


void ef_vi_set_tx_push_threshold(ef_vi* vi, unsigned threshold)
{
  vi->tx_push_thresh = threshold;
}


const char* ef_vi_version_str(void)
{
  return ONLOAD_VERSION;
}


const char* ef_vi_driver_interface_str(void)
{
  return EFCH_INTF_VER;
}


int ef_vi_rxq_reinit(ef_vi* vi, ef_vi_reinit_callback cb, void* cb_arg)
{
  ef_vi_state* state = vi->ep_state;
  int di;
  
  /* shared rxqs always claim to have a full rxq because buffer posting is
   * managed elsewhere, but it's a lie. */
  if( vi->vi_rxq.mask && ! vi->efct_rxqs.active_qs ) {
    while( state->rxq.removed < state->rxq.added ) {
      di = state->rxq.removed & vi->vi_rxq.mask;
      BUG_ON(vi->vi_rxq.ids[di] == EF_REQUEST_ID_MASK);
      (*cb)(vi->vi_rxq.ids[di], cb_arg);
      vi->vi_rxq.ids[di] = EF_REQUEST_ID_MASK;
      ++state->rxq.removed;
    }
  }

  ef_vi_reset_rxq(vi);

  return 0;
}


int ef_vi_txq_reinit(ef_vi* vi, ef_vi_reinit_callback cb, void* cb_arg)
{
  ef_vi_state* state = vi->ep_state;
  int di;

  while( state->txq.removed < state->txq.added ) {
    di = state->txq.removed & vi->vi_txq.mask;
    if( vi->vi_txq.ids[di] != EF_REQUEST_ID_MASK )
      (*cb)(vi->vi_txq.ids[di], cb_arg);
    vi->vi_txq.ids[di] = EF_REQUEST_ID_MASK;
    ++state->txq.removed;
  }

  ef_vi_reset_txq(vi);

  return 0;
}


int ef_vi_evq_reinit(ef_vi* vi)
{
  memset(vi->evq_base, (char)0xff, vi->evq_mask + 1);
  vi->ep_state->evq.evq_ptr = 0;
  return 0;
}


/**********************************************************************
 * ef_vi_init*
 */

static int ef_vi_calc_rxq_descriptors_bytes(enum ef_vi_arch arch, int qsize)
{
  switch( arch ) {
  case EF_VI_ARCH_EF10:
  case EF_VI_ARCH_EF100:
    return 8 * qsize;
  case EF_VI_ARCH_EFCT:
  case EF_VI_ARCH_EF10CT:
    return EFCT_RX_DESCRIPTOR_BYTES * CI_EFCT_MAX_SUPERBUFS *
           EF_VI_MAX_EFCT_RXQS;
  default:
    EF_VI_BUG_ON(1);
    return 8 * qsize;
  }
}

static int tx_desc_bytes(struct ef_vi* vi)
{
  switch( ef_vi_get_real_arch(vi) ) {
  case EF_VI_ARCH_EF10:
    return 8;
  case EF_VI_ARCH_EF100:
    return 16;
  case EF_VI_ARCH_EFCT:
  case EF_VI_ARCH_EF10CT:
    return EFCT_TX_DESCRIPTOR_BYTES;
  default:
    EF_VI_BUG_ON(1);
    return 8;
  }
}

int ef_vi_rx_ring_bytes(struct ef_vi* vi)
{
  EF_VI_ASSERT(vi->inited & EF_VI_INITED_RXQ);
  return ef_vi_calc_rxq_descriptors_bytes(ef_vi_get_real_arch(vi),
                                          vi->vi_rxq.mask + 1);
}


int ef_vi_tx_ring_bytes(struct ef_vi* vi)
{
  EF_VI_ASSERT(vi->inited & EF_VI_INITED_TXQ);
  return (vi->vi_txq.mask + 1) * tx_desc_bytes(vi);
}


int ef_vi_init(struct ef_vi* vi, int arch, int variant, int revision,
	       enum ef_vi_flags ef_vi_flags, unsigned char nic_flags,
	       ef_vi_state* state)
{
  int rc;

  memset(vi, 0, sizeof(*vi));
  /* vi->vi_qs_n = 0; */
  /* vi->inited = 0; */
  /* vi->vi_i = 0; */
  vi->nic_type.arch = arch;
  vi->nic_type.variant = variant;
  vi->nic_type.revision = revision;
  vi->nic_type.nic_flags = nic_flags;
  vi->vi_flags = (enum ef_vi_flags) ef_vi_flags;
  vi->ep_state = state;
  /* vi->vi_stats = NULL; */
  /* vi->io = NULL; */
  /* vi->linked_pio = NULL; */
  /* vi->tx_alt_num = 0; */
  /* vi->tx_alt_ids = NULL; */
  vi->vi_is_normal = !(ef_vi_flags & EF_VI_RX_EVENT_MERGE) &&
                     !(ef_vi_flags & EF_VI_RX_PACKED_STREAM);
  switch( arch ) {
  case EF_VI_ARCH_EF10:
    rc = ef10_vi_init(vi);
    break;
  case EF_VI_ARCH_EFCT:
  case EF_VI_ARCH_EF10CT:
    rc = efct_vi_init(vi);
    break;
  case EF_VI_ARCH_AF_XDP:
    rc = efxdp_vi_init(vi);
    break;
  default:
    return -EINVAL;
  }

  if( rc == 0 )
    vi->inited |= EF_VI_INITED_NIC;

  return rc;
}


void ef_vi_init_io(struct ef_vi* vi, void* io_area)
{
  EF_VI_BUG_ON(vi->inited & EF_VI_INITED_IO);
  /* FIXME EF10CT: EF10CT provides a zero-length io region for rx-only vis. This
   * causes the test below to fail. In order to allow for the creation of these
   * vis, I have disabled the check but it needs to be re-enabled based on the
   * resolution of ON-16095 */
  // EF_VI_BUG_ON((vi->nic_type.arch != EF_VI_ARCH_AF_XDP) && io_area == NULL);
  vi->io = io_area;
  vi->inited |= EF_VI_INITED_IO;
}


void ef_vi_init_rxq(struct ef_vi* vi, int ring_size, void* descriptors,
		    void* ids, int prefix_len)
{
  EF_VI_BUG_ON(vi->inited & EF_VI_INITED_RXQ);
  EF_VI_BUG_ON(ring_size & (ring_size - 1)); /* not power-of-2 */
  vi->vi_rxq.mask = ring_size - 1;
  vi->vi_rxq.descriptors = descriptors;
  vi->vi_rxq.ids = ids;
  vi->rx_prefix_len = prefix_len;
  vi->inited |= EF_VI_INITED_RXQ;
}


void ef_vi_init_txq(struct ef_vi* vi, int ring_size, void* descriptors,
		    void* ids)
{
  EF_VI_BUG_ON(vi->inited & EF_VI_INITED_TXQ);
  vi->vi_txq.mask = ring_size - 1;
  vi->vi_txq.ct_fifo_bytes = INT_MAX;
  vi->vi_txq.descriptors = descriptors;
  vi->vi_txq.ids = ids;
  vi->tx_push_thresh = 16;
  if( vi->vi_flags & EF_VI_TX_PUSH_DISABLE )
    vi->tx_push_thresh = 0;
  if( vi->vi_flags & EF_VI_TX_PUSH_ALWAYS )
    vi->tx_push_thresh = (unsigned) -1;
  vi->inited |= EF_VI_INITED_TXQ;
}


static char* ef_vi_xdp_init_qs(struct ef_vi* vi, char* q_mem, uint32_t* ids,
                               int rxq_size, int rx_prefix_len, int txq_size)
{
  /* We need to initialise event queue to access things in the mapped memory */
  ef_vi_init_evq(vi, 1, q_mem);
  ef_vi_init_rxq(vi, rxq_size, NULL, ids, rx_prefix_len);
  ef_vi_init_txq(vi, txq_size, NULL, ids + rxq_size);

  return q_mem + efxdp_vi_mmap_bytes(vi);
}


static char* ef_vi_sfc_init_qs(struct ef_vi* vi, char* q_mem, uint32_t* ids,
                               int evq_size, int rxq_size, int rx_prefix_len,
                               int txq_size)
{
  if( evq_size ) {
    ef_vi_init_evq(vi, evq_size, q_mem);
    q_mem += ((evq_size * 8 + CI_PAGE_SIZE - 1) & CI_PAGE_MASK);
  }
  if( rxq_size ) {
    ef_vi_init_rxq(vi, rxq_size, q_mem, ids, rx_prefix_len);
    q_mem += (ef_vi_rx_ring_bytes(vi) + CI_PAGE_SIZE-1) & CI_PAGE_MASK;
    ids += rxq_size;
  }
  if( txq_size ) {
    ef_vi_init_txq(vi, txq_size, q_mem, ids);
    q_mem += (ef_vi_tx_ring_bytes(vi) + CI_PAGE_SIZE-1) & CI_PAGE_MASK;
  }

  return q_mem;
}


char* ef_vi_init_qs(struct ef_vi* vi, char* q_mem, uint32_t* ids,
                    int evq_size, int rxq_size, int rx_prefix_len,
                    int txq_size)
{
  if( vi->nic_type.arch == EF_VI_ARCH_AF_XDP )
    return ef_vi_xdp_init_qs(vi, q_mem, ids, rxq_size, rx_prefix_len, txq_size);
  else
    return ef_vi_sfc_init_qs(vi, q_mem, ids, evq_size, rxq_size,
                             rx_prefix_len, txq_size);
}


void ef_vi_init_evq(struct ef_vi* vi, int ring_size, void* event_ring)
{
  EF_VI_BUG_ON(vi->inited & EF_VI_INITED_EVQ);
  vi->evq_mask = ring_size * 8 - 1;
  vi->evq_base = event_ring;
  vi->inited |= EF_VI_INITED_EVQ;
}


void ef_vi_init_timer(struct ef_vi* vi, int timer_quantum_ns)
{
  vi->timer_quantum_ns = timer_quantum_ns;
  vi->inited |= EF_VI_INITED_TIMER;
}


void ef_vi_init_rx_timestamping(struct ef_vi* vi, int rx_ts_correction)
{
  vi->rx_ts_correction = rx_ts_correction;
  if( vi->ts_format == TS_FORMAT_SECONDS_QTR_NANOSECONDS ) {
    /* If a packet arrives more than halfway through a nanosecond, then the
     * resulting timestamp is more accurate if we round up rather than
     * down.
     *
     * Ensure that rx_ts_correction ends up <= 0.  It always will if the
     * correction is realistic!
     */
    if( vi->rx_ts_correction > 0 ) {
      /* There are no valid cases where we should have a positive correction
       * here. There's not a lot we can do about it at this point, so just
       * grumble alarmingly in release builds. */
       LOG(ef_log("%s: ERROR: NIC returned positive timestamp correction. "
                  "Firmware update required to get accurate timestamps.",
                  __FUNCTION__));
    }

    /* There are two cases where firmware can report a correction of 0:
     * a) the correction is already applied, so onload should do nothing
     * b) the firmware is so old it doesn't properly report
     * We assume that case b no longer exists, so don't try and distinguish
     * these cases. */
    EF_VI_ASSERT(vi->rx_ts_correction <= 0);
    if( vi->rx_ts_correction <= -2 )
      vi->rx_ts_correction += 2;
  }
  vi->inited |= EF_VI_INITED_RX_TIMESTAMPING;
}


void ef_vi_set_ts_format(struct ef_vi* vi, enum ef_timestamp_format ts_format)
{
  vi->ts_format = ts_format;
}


void ef_vi_init_tx_timestamping(struct ef_vi* vi, int tx_ts_correction)
{
  /* Driver gives TX correction in ns for hunti and medford, and ticks for
   * medford2 and later.
   */
  if( vi->nic_type.variant >= 'C' )
    tx_ts_correction /= 4;  /* convert to ns */

  vi->tx_ts_correction_ns = tx_ts_correction;
  vi->inited |= EF_VI_INITED_TX_TIMESTAMPING;
}


void ef_vi_init_out_flags(struct ef_vi* vi, unsigned flags)
{
  vi->inited |= EF_VI_INITED_OUT_FLAGS;
  vi->vi_out_flags = flags;
}


void ef_vi_reset_rxq(struct ef_vi* vi)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  ef_vi_efct_rxq_state* eqs;
  int i;
  qs->posted = 0;
  if( vi->efct_rxqs.active_qs ) {
    for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i ) {
      eqs = &vi->ep_state->rxq.efct_state[i];
      eqs->free_head = eqs->fifo_head = -1;
      eqs->fifo_tail_hw = eqs->fifo_tail_sw = -1;
      eqs->qid = -1;
    }
    /* shared rxqs have their buffer posting managed elsewhere, not by the app,
     * so let's make it look like the queue is constantly full. If we are using
     * the ef10 compat layer, then we still need users to post descriptors */
    if( ! ef_vi_is_compat_vi(vi, EF_VI_ARCH_EF10) )
      qs->added = vi->vi_rxq.mask + 1;
  }
  else {
    qs->added = 0;
  }
  qs->removed = 0;
  qs->in_jumbo = 0;
  qs->bytes_acc = 0;
  qs->rx_ps_credit_avail = 1;
  qs->last_desc_i = vi->vi_is_packed_stream ? vi->vi_rxq.mask : 0;
  if( vi->vi_rxq.mask ) {
    int i;
    for( i = 0; i <= vi->vi_rxq.mask; ++i )
      vi->vi_rxq.ids[i] = EF_REQUEST_ID_MASK;
  }
}


void ef_vi_reset_txq(struct ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  qs->previous = 0;
  qs->added = 0;
  qs->removed = 0;
  qs->ct_added = 0;
  qs->ct_removed = 0;
  qs->ts_nsec = EF_VI_TX_TIMESTAMP_TS_NSEC_INVALID;

  if( vi->vi_txq.mask ) {
    int i;
    for( i = 0; i <= vi->vi_txq.mask; ++i )
      vi->vi_txq.ids[i] = EF_REQUEST_ID_MASK;
  }
}


void ef_vi_reset_evq(struct ef_vi* vi, int clear_ring)
{
  if( clear_ring )
    memset(vi->evq_base, (char) 0xff, vi->evq_mask + 1);
  vi->ep_state->evq.evq_ptr = 0;
  vi->ep_state->evq.evq_clear_stride = -((int) ef_vi_evq_clear_stride());
  EF_VI_BUG_ON( vi->ep_state->evq.evq_clear_stride > 0 );
  vi->ep_state->evq.sync_timestamp_synchronised = 0;
  vi->ep_state->evq.sync_timestamp_major = ~0u;
  /* Set unsol_seq to default, but leave 1 credit-space in reserve for overflow event. */
  vi->ep_state->evq.unsol_credit_seq = CI_CFG_TIME_SYNC_EVENT_EVQ_CAPACITY - 1;
  vi->ep_state->evq.sync_flags = 0;
}


int ef_eventq_capacity(ef_vi* vi)
{
  EF_VI_ASSERT( vi->ep_state->evq.evq_clear_stride <= 0 );
  return vi->evq_mask / EF_VI_EV_SIZE - 1u + vi->ep_state->evq.evq_clear_stride;
}

/* TODO move this to driver code as EFHW_* APIs are not userspace interface */
int ef_vi_arch_from_efhw_arch(int efhw_arch)
{
  switch( efhw_arch ) {
  case EFHW_ARCH_EF10:
    return EF_VI_ARCH_EF10;
  case EFHW_ARCH_EFCT:
    return EF_VI_ARCH_EFCT;
  case EFHW_ARCH_EF10CT:
    return EF_VI_ARCH_EF10CT;
  case EFHW_ARCH_AF_XDP:
    return EF_VI_ARCH_AF_XDP;
  default:
    return -1;
  }
}
