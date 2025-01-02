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

struct efcompat_ts {
  uint32_t tv_sec : 32;
  uint32_t tv_nsec : 30;
  uint32_t tv_nsec_frac : 2;
  uint16_t tv_valid : 1;
  uint16_t tv_flags : 15;
};

#define EFCOMPAT_TS_INVALID ((struct efcompat_ts) {0})

static void
convert_efcompat_ts_to_ef_precisetime(const struct efcompat_ts *ts_compat,
                                      ef_precisetime *ts_precise)
{
  EF_VI_BUG_ON(ts_precise == NULL);
  EF_VI_BUG_ON(ts_compat == NULL);

  ts_precise->tv_sec       = ts_compat->tv_sec;
  ts_precise->tv_nsec      = ts_compat->tv_nsec;
  ts_precise->tv_nsec_frac = ts_compat->tv_nsec_frac << 14;
  ts_precise->tv_flags     = ts_compat->tv_flags;
}

static void
convert_ef_precisetime_to_efcompat_ts(const ef_precisetime *ts_precise,
                                      struct efcompat_ts *ts_compat)
{
  EF_VI_BUG_ON(ts_precise == NULL);
  EF_VI_BUG_ON(ts_compat == NULL);

  /* These assertions ensure all values fit entirely inside our compact
   * representation, and are taken from efct_vi_rxpkt_get_precise_timestamp. */

  /* Assumption: 32-bits are required to represent ts_precise->tv_sec, so the
   * top 32 bits should never be set. */
  EF_VI_ASSERT(!(ts_precise->tv_sec & 0xffffffff00000000ull));
  /* Assumption: 30-bits are required to represent ts_precise->tv_nsec, so the
   * top 2 bits should never be set. */
  EF_VI_ASSERT(!(ts_precise->tv_nsec & 0xc0000000ul));
  /* Assumption: 2-bits are required to represent ts_precise->tv_nsec_frac and
   * these are stored in the top bits, so the bottom 14 bits are not set. */
  EF_VI_ASSERT(!(ts_precise->tv_nsec_frac & 0x3fffu));
  /* Assumption: the top bit is not used as a flag, as we steal this for our
   * own "valid" flag. In reality, only two flags currently exist, so this
   * could assert that the top 14 bits are unset. */
  EF_VI_ASSERT(!(ts_precise->tv_flags & 0x8000u));

  ts_compat->tv_sec       = ts_precise->tv_sec;
  ts_compat->tv_nsec      = ts_precise->tv_nsec;
  ts_compat->tv_nsec_frac = ts_precise->tv_nsec_frac >> 14;
  ts_compat->tv_flags     = ts_precise->tv_flags;
  ts_compat->tv_valid     = 1;

#ifndef NDEBUG
  {
    ef_precisetime temp;
    convert_efcompat_ts_to_ef_precisetime(ts_compat, &temp);

    EF_VI_ASSERT(temp.tv_sec       == ts_precise->tv_sec &&
                 temp.tv_nsec      == ts_precise->tv_nsec &&
                 temp.tv_nsec_frac == ts_precise->tv_nsec_frac &&
                 temp.tv_flags     == ts_precise->tv_flags);
  }
#endif
}

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

  /* Because the sizeof(ef_precisetime) exceeds the space available in the
   * packet prefix (16 > 14), we squish the timestamp into an efcompat_ts by
   * making some assumptions about how much data the efct architecture really
   * has about timestamps. We could expand the prefix, but bad apps might have
   * hard-coded the 14 value. */
  EF_VI_BUILD_ASSERT(sizeof(struct efcompat_ts) <= ES_DZ_RX_PREFIX_SIZE);
  if( (vi->vi_flags & EF_VI_RX_TIMESTAMPS) != 0 ) {
    struct efcompat_ts *ts_compat = (struct efcompat_ts*)ef10_pkt;
    ef_precisetime ts_precise;
    int rc =
      vi->compat_data->underlying_ops.receive_get_timestamp(vi, efct_pkt,
                                                            &ts_precise);
    if( rc == 0 )
      convert_ef_precisetime_to_efcompat_ts(&ts_precise, ts_compat);
    else
      *ts_compat = EFCOMPAT_TS_INVALID;
  }

  /* After (maybe) copying the timestamp in place, put the rest of the packet
   * where the user expects it */
  memcpy((void*)((uint8_t*)ef10_pkt + vi->rx_prefix_len),
         efct_pkt, rx_ref->rx_ref.len);

  efct_vi_rxpkt_release(vi, rx_ref->rx_ref.pkt_id);

  rx->rx.len = rx_ref->rx_ref.len + vi->rx_prefix_len;
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
  struct efcompat_ts *ts_compat = (struct efcompat_ts*)pkt;

  if( (vi->vi_flags & EF_VI_RX_TIMESTAMPS) == 0 || ! ts_compat->tv_valid )
    return -ENODATA;

  convert_efcompat_ts_to_ef_precisetime(ts_compat, ts_out);

  return 0;
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

  if( (vi->vi_flags & EF_VI_RX_TIMESTAMPS) != 0 )
    vi->rx_prefix_len = ES_DZ_RX_PREFIX_SIZE;

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
