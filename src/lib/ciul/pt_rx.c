/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

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
  uint32_t dw;
  EF_VI_ASSERT(vi->nic_type.arch == EF_VI_ARCH_EF100);
  EF_VI_ASSERT(ef_vi_receive_prefix_len(vi) > 4);

  /* The 32-bitness of the mark is so fundamental to everything that it's not
   * worth pretending that other sizes could happen */
  EF_VI_BUILD_ASSERT(ESF_GZ_RX_PREFIX_USER_MARK_LBN % 32 == 0);
  EF_VI_BUILD_ASSERT(ESF_GZ_RX_PREFIX_USER_MARK_WIDTH == 32);
  memcpy(&dw, (const uint8_t*) pkt + ESF_GZ_RX_PREFIX_USER_MARK_LBN / 8, 4);
  *user_mark = le32_to_cpu(dw);

  EF_VI_BUILD_ASSERT(ESF_GZ_RX_PREFIX_USER_FLAG_WIDTH == 1);
  memcpy(&dw,
         (const uint8_t*) pkt + ESF_GZ_RX_PREFIX_USER_FLAG_LBN / 32 * 4, 4);
  *user_flag = (le32_to_cpu(dw) >> (ESF_GZ_RX_PREFIX_USER_FLAG_LBN % 32)) & 1;
  return 0;
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
