/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */

#include <etherfabric/vi.h>

#ifndef __KERNEL__

#include "ef_vi_internal.h"
#include "logging.h"
#include <etherfabric/efct_vi.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/efhw/common.h>
#include <ci/tools/byteorder.h>
#include <ci/tools/sysdep.h>
#include <ci/net/ethernet.h>
#include <stdlib.h>
#include <emmintrin.h>

static int ef10compat_ef_vi_receive_init(ef_vi* vi, ef_addr addr,
                                         ef_request_id dma_id)
{
  if( ef_vi_receive_space(vi) ) {
    ef_vi_rxq *q = &vi->vi_rxq;
    ef_vi_rxq_state *qs = &vi->ep_state->rxq;
    unsigned di;

    di = qs->added++ & q->mask;
    EF_VI_BUG_ON(q->ids[di] != EF_REQUEST_ID_MASK);
    EF_VI_BUG_ON(vi->compat_data->arch.ef10.rx_descriptors[di] != EF_INVALID_ADDR);
    q->ids[di] = dma_id;
    vi->compat_data->arch.ef10.rx_descriptors[di] = addr;

    return 0;
  }

  return -EAGAIN;
}

static void ef10compat_ef_vi_receive_push(ef_vi* vi)
{
  /* no-op, the hardware doesn't want these descriptors */
}

static int convert_rx_ref_to_rx_ev(ef_vi *vi, ef_event *rx_ref, ef_event *rx)
{
  ef_vi_rxq *q = &vi->vi_rxq;
  ef_vi_rxq_state *qs = &vi->ep_state->rxq;
  unsigned desc_i = qs->removed & q->mask;
  const void *efct_pkt;
  void *ef10_pkt;

  if( q->ids[desc_i] == EF_REQUEST_ID_MASK ||
      vi->compat_data->arch.ef10.rx_descriptors[desc_i] == EF_INVALID_ADDR )
    return -ENOBUFS;

  efct_pkt = efct_vi_rxpkt_get(vi, rx_ref->rx_ref.pkt_id);
  ef10_pkt =
    (void*)(uintptr_t)vi->compat_data->arch.ef10.rx_descriptors[desc_i];

  /* Copy the efct packet to the expected ef10 location */
  memcpy(ef10_pkt, efct_pkt, rx_ref->rx_ref.len);

  efct_vi_rxpkt_release(vi, rx_ref->rx_ref.pkt_id);

  rx->rx.len = rx_ref->rx_ref.len;
  rx->rx.q_id = rx_ref->rx_ref.q_id;
  rx->rx.rq_id = q->ids[desc_i];

  rx->rx.flags = EF_EVENT_FLAG_SOP;
  if( ((ci_ether_hdr*)efct_pkt)->ether_dhost[0] & 0x01 )
    rx->rx.flags |= EF_EVENT_FLAG_MULTICAST;

  q->ids[desc_i] = EF_REQUEST_ID_MASK;
  vi->compat_data->arch.ef10.rx_descriptors[desc_i] = EF_INVALID_ADDR;
  qs->removed++;

  return 0;
}

static int ef10compat_ef_vi_receive_get_timestamp(struct ef_vi* vi,
                                                  const void* pkt,
                                                  ef_precisetime* ts_out)
{
  return -ENODATA;
}

static int ef10compat_ef_eventq_poll(ef_vi *vi, ef_event *evs, int evs_len)
{
  ef_event temp;
  int i, ev_count;

  /* Ensure we don't recurse */
  EF_VI_ASSERT(vi->compat_data->underlying_ops.eventq_poll
               != ef10compat_ef_eventq_poll);

  ev_count = vi->compat_data->underlying_ops.eventq_poll(vi, evs, evs_len);

  for( i = 0; i < ev_count; i++ ) {
    temp = evs[i];
    switch( EF_EVENT_TYPE(temp) ) {
    case EF_EVENT_TYPE_RESET:
      /* This VI is no longer valid, consumers should not continue looking at
       * events after this one, so we stop converting them to ef10-style RX
       * events because we might do invalid scary things. */
      return ev_count;
    case EF_EVENT_TYPE_RX_REF:
      if( convert_rx_ref_to_rx_ev(vi, &temp, &evs[i]) == 0 ) {
        evs[i].rx.type = EF_EVENT_TYPE_RX;
        evs[i].rx.__reserved = 0;
        evs[i].rx.ofs = 0;
      } else {
        evs[i].rx_no_desc_trunc.type = EF_EVENT_TYPE_RX_NO_DESC_TRUNC;
        evs[i].rx_no_desc_trunc.q_id = temp.rx_ref.q_id;
      }
      break;
    case EF_EVENT_TYPE_RX_REF_DISCARD:
      if( convert_rx_ref_to_rx_ev(vi, &temp, &evs[i]) == 0 ) {
        evs[i].rx_discard.type = EF_EVENT_TYPE_RX_DISCARD;
        evs[i].rx_discard.subtype =
          ef_vi_get_rx_discard_subtype_from_flags(temp.rx_ref_discard.flags);
      } else {
        evs[i].rx_no_desc_trunc.type = EF_EVENT_TYPE_RX_NO_DESC_TRUNC;
        evs[i].rx_no_desc_trunc.q_id = temp.rx_ref_discard.q_id;
      }
      break;
    }
  }

  return ev_count;
}

static void ef_vi_compat_init_ef10_ops(ef_vi* vi)
{
  /* Intercept RX bits to convert RX_REF* events to RX* events */
  vi->ops.receive_init                = ef10compat_ef_vi_receive_init;
  vi->ops.receive_push                = ef10compat_ef_vi_receive_push;
  vi->ops.receive_get_timestamp       = ef10compat_ef_vi_receive_get_timestamp;
  vi->ops.eventq_poll                 = ef10compat_ef_eventq_poll;

  /* All ops not explicitly set above here will remain the same, and any
   * support for them will be identical to the underlying efct support */
}

int ef_vi_compat_init_ef10(ef_vi* vi)
{
  int i;

  /* We only care about a compat layer with efct */
  if( vi->nic_type.arch != EF_VI_ARCH_EFCT )
    return 0;

  EF_VI_ASSERT(vi->compat_data == NULL);
  vi->compat_data = malloc(sizeof(struct ef_vi_compat_data));
  if( ! vi->compat_data ) {
    ef_log("ERROR: failed to allocate ef10 compat data");
    return -ENOMEM;
  }

  vi->compat_data->underlying_arch = vi->nic_type.arch;
  vi->compat_data->underlying_ops = vi->ops;
  vi->compat_data->arch.ef10.rx_descriptors =
    malloc(sizeof(ef_addr) * (vi->vi_rxq.mask + 1));
  if( ! vi->compat_data->arch.ef10.rx_descriptors ) {
    free(vi->compat_data);
    vi->compat_data = NULL;
    ef_log("ERROR: failed to allocate ef10 compat descriptors");
    return -ENOMEM;
  }

  for( i = 0; i <= vi->vi_rxq.mask; ++i )
    vi->compat_data->arch.ef10.rx_descriptors[i] = EF_INVALID_ADDR;

  vi->nic_type.arch = EF_VI_ARCH_EF10;

  ef_vi_compat_init_ef10_ops(vi);

  return 0;
}

int ef_vi_compat_init(ef_vi* vi)
{
  const char *s = NULL;

  s = getenv("EF_VI_COMPAT_MODE");
  if( ! s )
    return 0;

  if( strcasecmp(s, "ef10") == 0 )
    return ef_vi_compat_init_ef10(vi);

  ef_log("Unrecognised EF_VI_COMPAT_MODE %s", s);

  return -EINVAL;
}

void ef_vi_compat_free(ef_vi* vi)
{
  if( ! vi->compat_data )
    return;

  switch( vi->nic_type.arch ) {
  case EF_VI_ARCH_EF10:
    free(vi->compat_data->arch.ef10.rx_descriptors);
    vi->compat_data->arch.ef10.rx_descriptors = NULL;
    break;
  default:
    break;
  }

  free(vi->compat_data);
  vi->compat_data = NULL;
}

#else /* ! __KERNEL__ */

/* If we're in the kernel, then it's probably onload doing things, but onload
 * will never use this compat so just do nothing here. */
int ef_vi_compat_init(ef_vi* vi) { return 0; }
void ef_vi_compat_free(ef_vi* vi) {}

#endif /* ! __KERNEL__ */
