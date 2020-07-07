/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/*! \cidoxg_lib_ef */
#include "ef_vi_internal.h"


/* Helper definitions to work with the prefix of received packet */
#define EF_VI_PREFIX_OFFSET_DWORDS(_field) (CI_LOW_BIT(_field) / 32)
#define EF_VI_PREFIX_OFFSET_BITS(_field) (CI_LOW_BIT(_field) % 32)
#define EF_VI_PREFIX_DWORD(_prefix, _field) \
  le32_to_cpu(*(uint32_t *)((const uint32_t*) _prefix + \
                            EF_VI_PREFIX_OFFSET_DWORDS(_field)))
#define EF_VI_PREFIX_FIELD(_prefix, _field) \
  ((EF_VI_PREFIX_DWORD(_prefix, _field) >> EF_VI_PREFIX_OFFSET_BITS(_field)) & \
   CI_MASK32(CI_WIDTH(_field)))
#define EF_VI_PREFIX_SUBFIELD(_val, _subfield) \
  ((_val >> CI_LOW_BIT(_subfield)) & CI_MASK32(CI_WIDTH(_subfield)))


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


/* Mask and values for CLASS field of the prefix of received packet to check
 * that packet is good before parsing subfields.
 * Packet is good when L2_STATUS is OK, L2_CLASS is ETH, L3_CLASS is IP4GOOD or
 * IP6 and L4_CSUM is GOOD.
 */
#define EF100_CLASS_SUBFIELD_MASK(_subfield)                      \
  (CI_MASK32(CI_WIDTH(ESF_GZ_RX_PREFIX_HCLASS_ ## _subfield)) <<  \
   CI_LOW_BIT(ESF_GZ_RX_PREFIX_HCLASS_ ## _subfield))
#define EF100_CLASS_SUBFIELD_VAL(_subfield, _val)     \
  ((ESE_GZ_RH_HCLASS_ ## _val) <<                     \
   CI_LOW_BIT(ESF_GZ_RX_PREFIX_HCLASS_ ## _subfield))

#define EF100_CLASS_GOOD_MASK                         \
  (EF100_CLASS_SUBFIELD_MASK(L2_STATUS) |             \
   EF100_CLASS_SUBFIELD_MASK(L2_CLASS) |              \
   EF100_CLASS_SUBFIELD_MASK(NT_OR_INNER_L3_CLASS) |  \
   EF100_CLASS_SUBFIELD_MASK(NT_OR_INNER_L4_CSUM))

#define EF100_CLASS_GOOD_VALS                                 \
  (EF100_CLASS_SUBFIELD_VAL(L2_STATUS, L2_STATUS_OK) |        \
   EF100_CLASS_SUBFIELD_VAL(L2_CLASS, L2_CLASS_E2_0123VLAN) | \
   EF100_CLASS_SUBFIELD_VAL(NT_OR_INNER_L4_CSUM, L4_CSUM_GOOD))

#define EF100_CLASS_GOOD_VALS_IP4                             \
  (EF100_CLASS_GOOD_VALS |                                    \
   EF100_CLASS_SUBFIELD_VAL(NT_OR_INNER_L3_CLASS, L3_CLASS_IP4GOOD))

#define EF100_CLASS_GOOD_VALS_IP6                             \
  (EF100_CLASS_GOOD_VALS |                                    \
   EF100_CLASS_SUBFIELD_VAL(NT_OR_INNER_L3_CLASS, L3_CLASS_IP6))


int
ef_vi_receive_get_discard_flags(ef_vi* vi, const void* pkt,
                                unsigned* discard_flags)
{
  uint32_t class;
  uint32_t val;

  *discard_flags = 0;

  /* Only EF100 returns RX_MULTI_PKTS type of events */
  EF_VI_ASSERT(vi->nic_type.arch == EF_VI_ARCH_EF100);
  EF_VI_BUILD_ASSERT(ESF_GZ_RX_PREFIX_CLASS_LBN == 16);
  EF_VI_BUILD_ASSERT(ESF_GZ_RX_PREFIX_CLASS_WIDTH == 16);

  class = EF_VI_PREFIX_FIELD(pkt, ESF_GZ_RX_PREFIX_CLASS);

  if(likely( (class & EF100_CLASS_GOOD_MASK) == EF100_CLASS_GOOD_VALS_IP4 ||
             (class & EF100_CLASS_GOOD_MASK) == EF100_CLASS_GOOD_VALS_IP6 ))
    return 0;

  val = EF_VI_PREFIX_SUBFIELD(class, ESF_GZ_RX_PREFIX_HCLASS_L2_STATUS);
  if( val == ESE_GZ_RH_HCLASS_L2_STATUS_LEN_ERR )
    *discard_flags |= EF_VI_DISCARD_RX_ETH_LEN_ERR;
  else if( val == ESE_GZ_RH_HCLASS_L2_STATUS_FCS_ERR )
    *discard_flags |= EF_VI_DISCARD_RX_ETH_FCS_ERR;

  if( EF_VI_PREFIX_SUBFIELD(class, ESF_GZ_RX_PREFIX_HCLASS_NT_OR_INNER_L3_CLASS) ==
      ESE_GZ_RH_HCLASS_L3_CLASS_IP4BAD )
    *discard_flags |= EF_VI_DISCARD_RX_L3_CSUM_ERR;

  /* Check L4 checksum only for TCP/UDP packets. EF100 reports bad/unknown
   * checksum for fragmented datagrams and non TCP/UDP packets if validation
   * of the L4 protocol isn't supported by the NIC (see SF-119689-TC for
   * details). */
  val = EF_VI_PREFIX_SUBFIELD(class, ESF_GZ_RX_PREFIX_HCLASS_NT_OR_INNER_L4_CLASS);
  if( val != ESE_GZ_RH_HCLASS_L4_CLASS_UDP &&
      val != ESE_GZ_RH_HCLASS_L4_CLASS_TCP )
    return 0;

  if( EF_VI_PREFIX_SUBFIELD(class, ESF_GZ_RX_PREFIX_HCLASS_NT_OR_INNER_L4_CSUM) ==
      ESE_GZ_RH_HCLASS_L4_CSUM_BAD_OR_UNKNOWN )
    *discard_flags |= EF_VI_DISCARD_RX_L4_CSUM_ERR;

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
