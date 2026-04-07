/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2019-2024 Advanced Micro Devices, Inc. */
#ifndef __CI_INTERNAL_IP_TIMESTAMP_H__
#define __CI_INTERNAL_IP_TIMESTAMP_H__

#include <ci/internal/ip.h>
#include <onload/extensions_timestamping.h>

#if CI_CFG_TIMESTAMPING

#ifdef CI_UNIT_MOCK_TIMESYNC_WALLCLOCK
extern struct oo_timespec mocked_timesync_wallclock;
#elif defined(__KERNEL__)
# include <onload/tcp_driver.h>
#else
# include <onload/ul/per_thread.h>
extern void ci_synchronise_clock(ci_netif *ni, struct oo_timesync* oo_ts_local);
#endif

enum {
  /* PART 1
   * The following values need to match their counterparts in
   * linux kernel header linux/net_tstamp.h
   */
  ONLOAD_SOF_TIMESTAMPING_TX_HARDWARE = (1<<0),
  ONLOAD_SOF_TIMESTAMPING_TX_SOFTWARE = (1<<1),
  ONLOAD_SOF_TIMESTAMPING_RX_HARDWARE = (1<<2),
  ONLOAD_SOF_TIMESTAMPING_RX_SOFTWARE = (1<<3),
  ONLOAD_SOF_TIMESTAMPING_SOFTWARE = (1<<4),
  ONLOAD_SOF_TIMESTAMPING_SYS_HARDWARE = (1<<5),
  ONLOAD_SOF_TIMESTAMPING_RAW_HARDWARE = (1<<6),
  ONLOAD_SOF_TIMESTAMPING_OPT_ID = (1<<7),
  ONLOAD_SOF_TIMESTAMPING_TX_SCHED = (1<<8),
  ONLOAD_SOF_TIMESTAMPING_TX_ACK = (1<<9),
  ONLOAD_SOF_TIMESTAMPING_OPT_CMSG = (1<<10),
  ONLOAD_SOF_TIMESTAMPING_OPT_TSONLY = (1<<11),
  ONLOAD_SOF_TIMESTAMPING_OPT_STATS = (1<<12),
  ONLOAD_SOF_TIMESTAMPING_OPT_PKTINFO = (1<<13),
  ONLOAD_SOF_TIMESTAMPING_OPT_TX_SWHW = (1<<14),
  ONLOAD_SOF_TIMESTAMPING_BIND_PHC = (1 << 15),
  ONLOAD_SOF_TIMESTAMPING_OPT_ID_TCP = (1<<16),

  ONLOAD_SOF_TIMESTAMPING_LAST = ONLOAD_SOF_TIMESTAMPING_OPT_ID_TCP,
  /* All bits used in part 1 */
  ONLOAD_SOF_TIMESTAMPING_MASK = (ONLOAD_SOF_TIMESTAMPING_LAST << 1) - 1,

  /* PART 2
   * The following values control how timestamping option flags are handled,
   * and what they mean.
   */

  /* Indicates that the behaviour has been overridden by the extension API,
   * onload_timestamping_request(). If set, then the lower bits contain
   * onload_timestamping_flags values, not the ONLOAD_SOF_* values defined here.
   */
  ONLOAD_SOF_TIMESTAMPING_ONLOAD = (ONLOAD_SOF_TIMESTAMPING_LAST << 1),

  /* Indicates that Onload extension API v2 timestamps have been requested.
   * The timestamps will use the extended CMSG format but option bits will
   * otherwise be treated as found above.
   */
  ONLOAD_SOF_TIMESTAMPING_ONLOAD_V2 = (ONLOAD_SOF_TIMESTAMPING_LAST << 2),

  ONLOAD_SOF_TIMESTAMPING_ONLOAD_LAST = ONLOAD_SOF_TIMESTAMPING_ONLOAD_V2,
   /* All bits used in part 2 */
  ONLOAD_SOF_TIMESTAMPING_ONLOAD_MASK = (((ONLOAD_SOF_TIMESTAMPING_ONLOAD_LAST << 1) - 1)
                                         & (~(ONLOAD_SOF_TIMESTAMPING_MASK))),

  /* PART 3
   * Onload extension flags. Used with extension API v2.
   */
  ONLOAD_SOF_TIMESTAMPING_TRAILER = SOF_TIMESTAMPING_OOEXT_TRAILER,
};

/* Ensure no overlapping bits from three parts of flags. */
CI_BUILD_ASSERT((ONLOAD_SOF_TIMESTAMPING_ONLOAD_MASK & SOF_TIMESTAMPING_OOEXT_MASK) == 0);
CI_BUILD_ASSERT((ONLOAD_SOF_TIMESTAMPING_ONLOAD_MASK & ONLOAD_SOF_TIMESTAMPING_MASK) == 0);
CI_BUILD_ASSERT((SOF_TIMESTAMPING_OOEXT_MASK & ONLOAD_SOF_TIMESTAMPING_MASK) == 0);

/* ... or the STREAM timestamping option. */
CI_BUILD_ASSERT(((ONLOAD_SOF_TIMESTAMPING_ONLOAD_MASK |
                  ONLOAD_SOF_TIMESTAMPING_MASK |
                  SOF_TIMESTAMPING_OOEXT_MASK) & ONLOAD_SOF_TIMESTAMPING_STREAM) == 0);

/* Ideally also check that all the kernel flags are covered,
 * but we don't include the definitions currently. */
/* CI_BUILD_ASSERT((ONLOAD_SOF_TIMESTAMPING_MASK & SOF_TIMESTAMPING_MASK) == \
 *                 SOF_TIMESTAMPING_MASK); */

/* Constants to suport v1 Onload extension API implementation. */
enum {
  ONLOAD_TIMESTAMPING_FLAG_TX_MASK = ONLOAD_TIMESTAMPING_FLAG_TX_NIC,
  ONLOAD_TIMESTAMPING_FLAG_RX_MASK = ONLOAD_TIMESTAMPING_FLAG_RX_NIC |
                                     ONLOAD_TIMESTAMPING_FLAG_RX_CPACKET |
                                     ONLOAD_SOF_TIMESTAMPING_OPT_PKTINFO,

  ONLOAD_TIMESTAMPING_FLAG_MASK = ONLOAD_TIMESTAMPING_FLAG_TX_MASK |
                                  ONLOAD_TIMESTAMPING_FLAG_RX_MASK,

  ONLOAD_TIMESTAMPING_FLAG_TX_COUNT = 1,
  ONLOAD_TIMESTAMPING_FLAG_RX_COUNT = 2,
};

/* Constants to suport v2 Onload extension API implementation. */

/* Meaningful receive flag combinations:
     RX software timestamp
     RX hardware timestamp
     RX hardware timestamp gated by validity sync flags
     RX trailer timestamp
 */
enum {
  ONLOAD_TIMESTAMPING_V2_FLAG_RX_COUNT = 4,
};

/* Meaningful and supported transmit flag combinations:
     TX hardware timestamp
     TX hardware timestamp gated by validity sync flags
 */
enum {
  ONLOAD_TIMESTAMPING_V2_FLAG_TX_COUNT = 2,
};

struct ci_scm_ts_pktinfo {
  ci_uint32 if_index;
  ci_uint32 pkt_length;
  ci_uint32 reserved[2];
};

/* Indicates whether we want TX NIC timestamping, regardless of whether
 * SO_TIMESTAMPING has been overridden for onload timestamps */
static inline int /*bool*/
onload_timestamping_want_tx_nic(unsigned flags)
{
  /* HACK: If these flags are the same, we can get away with a single test */
  CI_BUILD_ASSERT((unsigned)ONLOAD_SOF_TIMESTAMPING_TX_HARDWARE ==
                  (unsigned)ONLOAD_TIMESTAMPING_FLAG_TX_NIC);

  return flags & ONLOAD_SOF_TIMESTAMPING_TX_HARDWARE;
}

static inline void
onload_timestamp_to_timespec(const struct onload_timestamp* in,
                             ef_timespec* out)
{
  out->tv_sec = in->sec;
  out->tv_nsec = in->sec == 0 ? 0 : in->nsec;
}

static inline void
ci_rx_pkt_timestamp_nic(const ci_ip_pkt_fmt* pkt,
                        struct onload_timestamp* ts_out)
{
  ts_out->sec = pkt->hw_stamp.tv_sec;
  ts_out->nsec = pkt->hw_stamp.tv_nsec;

  /* Shift fractional 16-bit fractional nanoseconds value to left align
   * with the 24-bit fractional nanoseconds value in onload extension. */
  ts_out->nsec_frac = ((uint32_t) pkt->hw_stamp.tv_nsec_frac) << 8;

  ts_out->flags = pkt->hw_stamp.tv_flags;
}

static inline void
ci_rx_pkt_timestamp_cpacket(struct onload_timestamp* ts_out,
                            const char *buf_end, const char *pkt_end)
{
  /* These fields are appended to the packet, after the IP payload, the
   * original Ethernet FCS, and any extension tags. A new FCS was added to
   * the end to make a valid packet, then checked and removed by the NIC.
   *
   * We look for this at the very end of the packet, assuming that nothing
   * else has added any other trailer after it. If there are multiple cpacket
   * trailers, then we will take the last (most recent) one.
   */
  struct cpacket {
    uint32_t sec;
    uint32_t nsec;
    uint8_t  flags;
    uint16_t dev;
    uint8_t  port;
  } __attribute__((packed));

  const struct cpacket* cp = (const struct cpacket*)buf_end - 1;

  if( buf_end - pkt_end < sizeof(struct cpacket) )
    return;

  ts_out->sec = ntohl(cp->sec);
  ts_out->nsec = ntohl(cp->nsec);
  ts_out->nsec_frac = 0;
  ts_out->flags = 0;

  /* If extensions are present, search for a sub-ns timestamp */
  if( cp->flags & 0x2 ) {
    /* This points to the last byte of the current tag */
    const uint8_t* ext = (const uint8_t*)cp - 1;
    const uint8_t* end = (const uint8_t*)pkt_end;

    for( ;; ) {
      int tag = *ext;
      int type = tag & 0x1f;
      int len;

      /* Optimise for the expected case of a single sub-ns timestamp tag.
       *
       * NOTE: it's possible that a malformed trailer could cause us to read
       * a garbage value here, and we do not check for that. That should be
       * the worst possible failure since, however badly formed the trailer,
       * we will always calculate a non-zero length below and eventually
       * reach the packet data and bail out. */
      if(CI_LIKELY( type == 0x01 )) {
        ts_out->nsec_frac = ext[-1] | (ext[-2] << 8) | (ext[-3] << 16);
        break;
      }

      /* Check the flag that indicates this is the last extension */
      if( tag & 0x20 )
        break;

      /* Extract the length depending on tag type */
      if( type == 0x1f )
        /* secondary tag: 10 bits excluding first and second words */
        len = ((tag >> 6) | (ext[-1] << 2)) + 2;
      else
        /* primary tag: 2 bits excluding first word */
        len = (tag >> 6) + 1;

      /* length field gives 32-bit words */
      len *= 4;

      /* Bail out if a bogus length takes us out of range */
      if( ext - end < len )
        break;

      ext -= len;
    }
  }
}

static inline uint64_t
ci_timestamp_extend_generic(uint64_t ts, uint64_t ref_ts,
                            uint64_t max_tolerance,
                            uint8_t valid_bits)
{
  uint64_t wrap, mask, ref_lo, delta;

  wrap = 1ULL << valid_bits;
  mask = wrap - 1;
  ref_lo = ref_ts & mask;
  /* ts should not have any of the higher bits set */
  ci_assert(!(ts & ~mask));

  /* The delta should satisfy modular arithmetic rules, mod the value of wrap.
   *
   * As an example, for a valid_bits = 4 (i.e. wrap = 16),
   * a number on the high end subtracted by a number on the low end,
   * such as 14 - 2, should be treated the same as a low negative minus
   * a low positive, in this case (-2) - 2. The evaluation is different
   * in u64, but masking to only bits in the field yields identical values.
   */
  delta = (ts - ref_lo) & mask;

  if( delta > wrap / 2 ) {
    /* In the previous example, delta after mask is 12, same as -4.
     * Since delta is greater than wrap / 2 = 8, we know the negative is
     * closer to 0. This wrap - delta normalizes the delta to the
     * absolute value of the negative version */
    delta = wrap - delta;
    if( CI_UNLIKELY(delta > max_tolerance) )
      return ~0ULL;
    return ref_ts - delta;
  } else {
    if( CI_UNLIKELY(delta > max_tolerance) )
      return ~0ULL;
    return ref_ts + delta;
  }
}

static inline void
ci_rx_pkt_timestamp_ttag(struct onload_timestamp* ts_out,
                         const char *buf_end, const char *pkt_end,
                         const struct oo_timespec *refclock)
{
  struct ttag {
    uint8_t ts[6];       /* 48b nsecs */
  } __attribute__((packed));

  const struct ttag* ttag = (const struct ttag*)buf_end - 1;
  const uint64_t nsec_per_sec = 1000ULL * 1000 * 1000;
  uint64_t ref_ts, ts;

  if( buf_end - pkt_end < sizeof(struct ttag) )
    return;

  /* 64bit nanoseconds is lossless till year 2554 */
  ref_ts = refclock->tv_sec * nsec_per_sec + refclock->tv_nsec;
  ts = ((uint64_t)ttag->ts[0] << 40) | ((uint64_t)ttag->ts[1] << 32) |
       ((uint64_t)ttag->ts[2] << 24) | ((uint64_t)ttag->ts[3] << 16) |
       ((uint64_t)ttag->ts[4] << 8)  | ((uint64_t)ttag->ts[5]);

  /* Huge overestimation of worst case prop delay: 1 hour. */
  ts = ci_timestamp_extend_generic(ts, ref_ts, 3600 * nsec_per_sec, 48);
  if( ts == ~0ULL )
    return;

  ts_out->sec = ts / nsec_per_sec;
  ts_out->nsec = ts - (ts_out->sec * nsec_per_sec);
  ts_out->nsec_frac = 0;
  ts_out->flags = 0;
}

static inline void
ci_rx_pkt_timestamp_brcm(struct onload_timestamp* ts_out,
                         const char *buf_end, const char *pkt_end,
                         const struct oo_timespec *refclock)
{
  struct brcm_trailer {
    uint8_t ts[6];      /* 48b timestamp: 18b sec + 30b nsec */

    uint8_t reserved;
    uint8_t origin[3];
    /* Followed by FCS, already removed by the NIC for this packet.
     * With multiple trailers, each ends in such a 4B reserved field.
     */
  } __attribute__((packed));

  const struct brcm_trailer* tt = (const struct brcm_trailer*)buf_end - 1;

  if( buf_end - pkt_end < sizeof(struct brcm_trailer) )
    return;

  ts_out->sec = ((uint32_t)(tt->ts[0]) << 10) |
                ((uint32_t)(tt->ts[1]) << 2) |
                (tt->ts[2] >> 6);

  /* As above, worst case prop delay: 1 hour. */
  ts_out->sec = ci_timestamp_extend_generic(ts_out->sec, refclock->tv_sec,
                                            3600, 18);
  if( ts_out->sec == ~0ULL ) {
    ts_out->sec = 0;
    return;
  }

  ts_out->nsec = ((tt->ts[2] & 0x3F) << 24) |
                 ((uint32_t)(tt->ts[3]) << 16) |
                 ((uint32_t)(tt->ts[4]) << 8) |
                 tt->ts[5];
  ts_out->nsec_frac = 0;
  ts_out->flags = 0;
}

static inline const struct oo_timespec *
ci_rx_pkt_timestamp_refclock(ci_netif *ni)
{
#ifdef CI_UNIT_MOCK_TIMESYNC_WALLCLOCK
  return &mocked_timesync_wallclock;
#elif defined(__KERNEL__)
  return &efab_tcp_driver.timesync->wall_clock;
#else
  struct oo_timesync *oo_ts_local = &(__oo_per_thread_get()->timesync);
  ci_synchronise_clock(ni, oo_ts_local);
  return &oo_ts_local->wall_clock;
#endif
}

static inline void
ci_rx_pkt_timestamp_trailer(const ci_ip_pkt_fmt* pkt,
                            struct onload_timestamp* ts_out, int format,
                            ci_netif *ni)
{
  const char *buf_end, *pkt_end;

  ts_out->sec = 0;

  /* fixme: fragmented packets will need different treatment */
  if(CI_UNLIKELY( !OO_PP_IS_NULL(pkt->frag_next) ))
    return;

  buf_end = PKT_START(pkt) + pkt->pay_len;
  pkt_end = (char*)RX_PKT_IPX_HDR(pkt) + RX_PKT_PAYLOAD_LEN(pkt);
  ci_assert_ge(buf_end, pkt_end);

  switch( format ) {
  case CITP_RX_TIMESTAMPING_TRAILER_FORMAT_CPACKET:
    ci_rx_pkt_timestamp_cpacket(ts_out, buf_end, pkt_end);
    break;
  case CITP_RX_TIMESTAMPING_TRAILER_FORMAT_TTAG:
    ci_rx_pkt_timestamp_ttag(ts_out, buf_end, pkt_end,
                             ci_rx_pkt_timestamp_refclock(ni));
    break;
  case CITP_RX_TIMESTAMPING_TRAILER_FORMAT_BRCM:
    ci_rx_pkt_timestamp_brcm(ts_out, buf_end, pkt_end,
                             ci_rx_pkt_timestamp_refclock(ni));
    break;
  }
}

static inline void
ci_rx_pkt_timestamp(ci_netif *ni, const ci_ip_pkt_fmt* pkt, struct onload_timestamp* ts_out,
                    int src, int format)
{
  switch( src ) {
  case CITP_RX_TIMESTAMPING_SOURCE_NIC:
    ci_rx_pkt_timestamp_nic(pkt, ts_out);
    break;
  case CITP_RX_TIMESTAMPING_SOURCE_TRAILER:
    ci_rx_pkt_timestamp_trailer(pkt, ts_out, format, ni);
    break;
  default:
    ts_out->sec = 0;
    break;
  }
}

static inline void
ci_rx_pkt_timespec(ci_netif *ni, const ci_ip_pkt_fmt* pkt,
                   ef_timespec* ts_out, int src, int trailer_type)
{
  struct onload_timestamp ts;
  ci_rx_pkt_timestamp(ni, pkt, &ts, src, trailer_type);
  onload_timestamp_to_timespec(&ts, ts_out);
}

#endif
#endif
