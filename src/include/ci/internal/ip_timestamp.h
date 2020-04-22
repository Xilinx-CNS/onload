/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

  ONLOAD_SOF_TIMESTAMPING_LAST = ONLOAD_SOF_TIMESTAMPING_OPT_TSONLY,
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
ci_rx_pkt_timestamp_cpacket(const ci_ip_pkt_fmt* pkt,
                            struct onload_timestamp* ts_out)
{
  /* fixme: fragmented packets will need different treatment */
  if(CI_LIKELY( OO_PP_IS_NULL(pkt->frag_next) )) {

    /* These fields are appended to the packet, after the IP payload.
     *
     * [crc] is the original Ethernet FCS; a new one is added to the end to
     * make a valid packet. That was checked and removed by the NIC.
     *
     * We need to support extensions, which place additional data between [crc]
     * and [sec]. Therefore don't assume that [crc] actually contains the
     * original FCS, and look for this data at the very end of the packet, not
     * necessarily straight after the IP payload.
     */
    struct cpacket {
      uint32_t crc;
      uint32_t sec;
      uint32_t nsec;
      uint8_t  ver;
      uint16_t dev;
      uint8_t  port;
    } __attribute__((packed));

    char* buf_end = PKT_START(pkt) + pkt->pay_len;
    char* pkt_end = (char*)RX_PKT_IPX_HDR(pkt) + RX_PKT_PAYLOAD_LEN(pkt);
    ci_assert_ge(buf_end, pkt_end);

    if( buf_end >= pkt_end + sizeof(struct cpacket) ) {
      struct cpacket* cp = (struct cpacket*)buf_end - 1;
      ts_out->sec = ntohl(cp->sec);
      ts_out->nsec = ntohl(cp->nsec);
      /* fixme: look for sub-nanosecond Metamako extension */
      ts_out->nsec_frac = 0;
      return;
    }
  }

  ts_out->sec = 0;
}

static inline void
ci_rx_pkt_timestamp(const ci_ip_pkt_fmt* pkt, struct onload_timestamp* ts_out, int src)
{
  switch( src ) {
  case CITP_RX_TIMESTAMPING_SOURCE_NIC:
    ci_rx_pkt_timestamp_nic(pkt, ts_out);
    break;
  case CITP_RX_TIMESTAMPING_SOURCE_CPACKET:
    ci_rx_pkt_timestamp_cpacket(pkt, ts_out);
    break;
  default:
    ts_out->sec = 0;
    break;
  }
}

static inline void
ci_rx_pkt_timespec(const ci_ip_pkt_fmt* pkt, ef_timespec* ts_out, int src)
{
  struct onload_timestamp ts;
  ci_rx_pkt_timestamp(pkt, &ts, src);
  onload_timestamp_to_timespec(&ts, ts_out);
}

#endif
#endif
