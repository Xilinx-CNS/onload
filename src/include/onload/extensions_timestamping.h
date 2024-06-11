/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2019-2024 Advanced Micro Devices, Inc. */
#ifndef __ONLOAD_EXTENSIONS_TIMESTAMPING_H__
#define __ONLOAD_EXTENSIONS_TIMESTAMPING_H__

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************************
 * Version 1 of Onload extension timestamping.
 *
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
  unsigned flags     : 8;
};

/* Flags for requesting timestamps */
enum onload_timestamping_flags {
  /* Request NIC timestamps for sent packets */
  ONLOAD_TIMESTAMPING_FLAG_TX_NIC = 1 << 0,

  /* Request NIC and/or external timestamps for received packets */
  ONLOAD_TIMESTAMPING_FLAG_RX_NIC = 1 << 1,
  ONLOAD_TIMESTAMPING_FLAG_RX_CPACKET = 1 << 2,
};

/* Flags in received timestamps */
enum onload_ts_flags {
  /* The clock from which this timestamp was taken has ever been set. */
  ONLOAD_TS_FLAG_CLOCK_SET     = 1 << 0,

  /* The clock from which this timestamp was taken was synchronised to
   * a suitable remote source. */
  ONLOAD_TS_FLAG_CLOCK_IN_SYNC = 1 << 1,

  /* The state of the above flags meets the configured requirements for
   * the Onload stack. */
  ONLOAD_TS_FLAG_ACCEPTABLE    = 1 << 7,
};

extern int onload_timestamping_request(int fd, unsigned flags);

/**********************************************************************
 * Version 2 of Onload extension timestamping.
 *
 * Timestamping is set using the Onload custom socket option with
 * standard flags plus additional Onload extension flag if trailer
 * timestamps are required.
 *
 * The custom ONLOAD_SOF_TIMESTAMPING_STREAM stream timestamping method
 * is not compatible with v2 Onload extension timestamping; use standard
 * TCP timestamping instead if extension timestamping benefits are required.
 *
 * struct so_timestamping val = {
 *   .flags = SOF_TIMESTAMPING_TX_HARDWARE
 *          | SOF_TIMESTAMPING_RX_HARDWARE
 *          | SOF_TIMESTAMPING_RAW_HARDWARE
 *          | SOF_TIMESTAMPING_OOEXT_TRAILER
 * };
 * setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING_OOEXT, &val, sizeof val);
 *
 * Timestamps are read out of a CMSG packet of type SCM_TIMESTAMPING_OOEXT:
 *
 * void handle_cmsg(uint8_t *data, size_t length) {
 *   struct scm_timestamping_ooext *t, *tend;
 *
 *   t = (struct scm_timestamping_ooext *) data;
 *   tend = t + length / sizeof *t;
 *
 *   for (; t != tend; t++) {
 *     switch (t->type) {
 *     case SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE:
 *       handle_rx_oo_ts(t->timestamp);
 *       // ...
 *     }
 *   }
 * }
 */

/* Extension socket option type */
#define SO_OOEXT_BASE 0x000F5300
#define SO_TIMESTAMPING_OOEXT ((SO_OOEXT_BASE) + 0)

/* Extension CMSG types */
#define SCM_TIMESTAMPING_OOEXT SO_TIMESTAMPING_OOEXT

/* Extension timestamping option flags.
 * These fit in an 'int' bitfield. They also need to be stable, so
 * cannot be allocate up from last known standard flag, therefore
 * allocate down from top of the word. */
#define SOF_TIMESTAMPING_OOEXT_LAST    (1U << 31)
#define SOF_TIMESTAMPING_OOEXT_TRAILER (1U << 31)
#define SOF_TIMESTAMPING_OOEXT_FIRST   (1U << 31)
#define SOF_TIMESTAMPING_OOEXT_MASK ((((SOF_TIMESTAMPING_OOEXT_LAST) << 1) - 1) \
                                     - ((SOF_TIMESTAMPING_OOEXT_FIRST) - 1))

/* Repeated structure within extension CMSG for each type present */
struct scm_timestamping_ooext {
  /* Flags indicating which timestamp is represented,
   * e.g. SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE,
   *      SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE or
   *      SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_OOEXT_TRAILER
   */
  uint32_t type;

  /* Padding */
  uint32_t padding;

  /* Onload extension timestamp */
  struct onload_timestamp timestamp;
};


#ifdef __cplusplus
}
#endif
#endif

