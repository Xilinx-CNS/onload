/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */

/*! \cidoxg_lib_ef */
#include "ef_vi_internal.h"


int ef_vi_receive_post(ef_vi* vi, ef_addr addr, ef_request_id dma_id)
{
  int rc = ef_vi_receive_init(vi, addr, dma_id);
  if( rc == 0 )  ef_vi_receive_push(vi);
  return rc;
}


int ef_vi_receive_unbundle(ef_vi* vi, const ef_event* ev,
                           ef_request_id* ids)
{
  ef_request_id* ids_in = ids;
  ef_vi_rxq* q = &vi->vi_rxq;
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  unsigned i;

  EF_VI_BUG_ON( EF_EVENT_TYPE(*ev) != EF_EVENT_TYPE_RX_MULTI &&
                EF_EVENT_TYPE(*ev) != EF_EVENT_TYPE_RX_MULTI_DISCARD );
  EF_VI_BUG_ON( ev->rx_multi.n_descs > EF_VI_RECEIVE_BATCH );

  for( i = 0; i < ev->rx_multi.n_descs; ++i ) {
    unsigned di = qs->removed & q->mask;
    ++(qs->removed);
    if( q->ids[di] != EF_REQUEST_ID_MASK ) {
      *ids++ = q->ids[di];
      q->ids[di] = EF_REQUEST_ID_MASK;
    }
  }

  /* Check we didn't remove more than we've added. */
  EF_VI_ASSERT( qs->added - qs->removed <= q->mask );

  return (int) (ids - ids_in);
}


int
ef_vi_receive_get_bytes(ef_vi* vi, const void* pkt, uint16_t* bytes_out)
{
  uint16_t *p_len;

  EF_VI_ASSERT(ef_vi_receive_prefix_len(vi));

  p_len = (void*) ((const uint8_t*) pkt + vi->rx_pkt_len_offset);
  *bytes_out = le16_to_cpu(*p_len) & vi->rx_pkt_len_mask;
  return 0;
}


int
ef_vi_receive_get_user_data(ef_vi* vi, const void* pkt, uint32_t* user_mark,
                            uint8_t* user_flag)
{
  return -EINVAL;
}


int
ef_vi_receive_get_discard_flags(ef_vi* vi, const void* pkt,
                                unsigned* discard_flags)
{
  return -EINVAL;
}


ef_request_id ef_vi_rxq_next_desc_id(ef_vi* vi)
{
  ef_vi_rxq* q = &vi->vi_rxq;
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  unsigned di = qs->removed & q->mask;
  ef_request_id rq_id;

  EF_VI_ASSERT( q->ids[di] != EF_REQUEST_ID_MASK );

  rq_id = q->ids[di];
  q->ids[di] = EF_REQUEST_ID_MASK;
  ++(qs->removed);

  return rq_id;
}

/*! \cidoxg_end */
