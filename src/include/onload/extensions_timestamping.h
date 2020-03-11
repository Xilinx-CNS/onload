/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_EXTENSIONS_TIMESTAMPING_H__
#define __ONLOAD_EXTENSIONS_TIMESTAMPING_H__

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************************
 * onload_timestamping_request: request enhanced packet timestamps
 *
 * This can be called instead of setsockopt(SO_TIMESTAMPING) to enable packet
 * timestamping in an enhanced format. It modifies the SCM_TIMESTAMPING control
 * messages for a socket to allow for timestamps with sub-nanosecond precision,
 * and to report externally applied timestamps (e.g. from cPacket trailers) for
 * received packets.
 *
 * ONLOAD_TIMESTAMPING_FLAG_RX_CPACKET will report a single timestamp from the
 * outermost (most recently applied) cPacket trailer of each packet if present.
 * This is currently the only supported format for external timestamps.
 *
 * The control messages will contain an array of onload_timestamp structures,
 * replacing the usual timespec structures. The array will contain only those
 * timestamps requested by the "flags" argument for the relevant direction,
 * in the order that the flags are declared below. If a timestamp is not
 * available, then its "sec" field will be zero and the value of other fields is
 * unspecified.
 *
 * Returns 0 on success, or a negative error code on failure.
 *   -EINVAL     unknown flag is set
 *   -ENOTTY     fd does not refer to an onload-accelerated socket
 *   -EOPNOTSUPP this build of onload does not support timestamping
 */

/* High precision timestamp with 24 bits of sub-nanosecond resolution.
 *
 * The overall value in seconds is:
 *     sec + (nsec * pow(10,-9)) + (nsec_frac * pow(10,-9) * pow(2,-24))
 */
struct onload_timestamp {
  uint64_t sec;
  uint32_t nsec;
  unsigned nsec_frac : 24;
  unsigned reserved  : 8;
};

/* Flags for requesting timestamps */
enum onload_timestamping_flags {
  /* Request NIC timestamps for sent packets */
  ONLOAD_TIMESTAMPING_FLAG_TX_NIC = 1 << 0,

  /* Request NIC and/or external timestamps for received packets */
  ONLOAD_TIMESTAMPING_FLAG_RX_NIC = 1 << 1,
  ONLOAD_TIMESTAMPING_FLAG_RX_CPACKET = 1 << 2,
};

extern int onload_timestamping_request(int fd, unsigned flags);

#ifdef __cplusplus
}
#endif
#endif

