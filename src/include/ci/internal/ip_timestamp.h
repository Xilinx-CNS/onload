/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
#ifndef __CI_INTERNAL_IP_TIMESTAMP_H__
#define __CI_INTERNAL_IP_TIMESTAMP_H__

#include <ci/internal/ip.h>
#include <onload/extensions_timestamping.h>

#if CI_CFG_TIMESTAMPING
/* The following values need to match their counterparts in
 * linux kernel header linux/net_tstamp.h
 */
enum {
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
  ONLOAD_SOF_TIMESTAMPING_MASK = (ONLOAD_SOF_TIMESTAMPING_LAST << 1) - 1,

  /* Indicates that the behaviour has been overridden by the extension API,
   * onload_timestamping_request(). If set, then the lower bits contain
   * onload_timestamping_flags values, not the ONLOAD_SOF_* values defined here.
   */
  ONLOAD_SOF_TIMESTAMPING_ONLOAD = (ONLOAD_SOF_TIMESTAMPING_LAST << 1),
};

enum {
  ONLOAD_TIMESTAMPING_FLAG_TX_MASK = ONLOAD_TIMESTAMPING_FLAG_TX_NIC,
  ONLOAD_TIMESTAMPING_FLAG_RX_MASK = ONLOAD_TIMESTAMPING_FLAG_RX_NIC |
                                     ONLOAD_TIMESTAMPING_FLAG_RX_CPACKET,

  ONLOAD_TIMESTAMPING_FLAG_MASK = ONLOAD_TIMESTAMPING_FLAG_TX_MASK |
                                  ONLOAD_TIMESTAMPING_FLAG_RX_MASK,

  ONLOAD_TIMESTAMPING_FLAG_TX_COUNT = 1,
  ONLOAD_TIMESTAMPING_FLAG_RX_COUNT = 2,
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
  ts_out->nsec_frac = 0;
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

static inline void
ci_rx_pkt_timestamp_ttag(struct onload_timestamp* ts_out,
                         const char *buf_end, const char *pkt_end)
{
  struct ttag {
    uint8_t ts[6];       /* 48b nsecs */
  } __attribute__((packed));

  const struct ttag* ttag = (const struct ttag*)buf_end - 1;
  const uint64_t nsec_per_sec = 1000ULL * 1000 * 1000;
  uint64_t ts;

  if( buf_end - pkt_end < sizeof(struct ttag) )
    return;

  ts = ((uint64_t)ttag->ts[0] << 40) | ((uint64_t)ttag->ts[1] << 32) |
       ((uint64_t)ttag->ts[2] << 24) | ((uint64_t)ttag->ts[3] << 16) |
       ((uint64_t)ttag->ts[4] << 8)  | ((uint64_t)ttag->ts[5]);

  ts_out->sec = ts / nsec_per_sec;
  ts_out->nsec = ts - (ts_out->sec * nsec_per_sec);
  ts_out->nsec_frac = 0;
}

static inline void
ci_rx_pkt_timestamp_brcm(struct onload_timestamp* ts_out,
                         const char *buf_end, const char *pkt_end)
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
  ts_out->nsec = ((tt->ts[2] & 0x3F) << 24) |
                 ((uint32_t)(tt->ts[3]) << 16) |
                 ((uint32_t)(tt->ts[4]) << 8) |
                 tt->ts[5];
  ts_out->nsec_frac = 0;
}

static inline void
ci_rx_pkt_timestamp_trailer(const ci_ip_pkt_fmt* pkt,
                            struct onload_timestamp* ts_out, int format)
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
    ci_rx_pkt_timestamp_ttag(ts_out, buf_end, pkt_end);
    break;
  case CITP_RX_TIMESTAMPING_TRAILER_FORMAT_BRCM:
    ci_rx_pkt_timestamp_brcm(ts_out, buf_end, pkt_end);
    break;
  }
}

static inline void
ci_rx_pkt_timestamp(const ci_ip_pkt_fmt* pkt, struct onload_timestamp* ts_out,
                    int src, int format)
{
  switch( src ) {
  case CITP_RX_TIMESTAMPING_SOURCE_NIC:
    ci_rx_pkt_timestamp_nic(pkt, ts_out);
    break;
  case CITP_RX_TIMESTAMPING_SOURCE_TRAILER:
    ci_rx_pkt_timestamp_trailer(pkt, ts_out, format);
    break;
  default:
    ts_out->sec = 0;
    break;
  }
}

static inline void
ci_rx_pkt_timespec(const ci_ip_pkt_fmt* pkt, ef_timespec* ts_out, int src,
                   int trailer_type)
{
  struct onload_timestamp ts;
  ci_rx_pkt_timestamp(pkt, &ts, src, trailer_type);
  onload_timestamp_to_timespec(&ts, ts_out);
}

#endif
#endif
