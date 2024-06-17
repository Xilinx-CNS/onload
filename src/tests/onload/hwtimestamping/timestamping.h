/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2014-2024 Advanced Micro Devices, Inc. */

/* Common code for Rx and Tx timestamping API demonstrations. */

/**** Definitions *********************************************************/

#ifdef ONLOADEXT_AVAILABLE
#include "onload/extensions.h"
#include "onload/extensions_zc.h"
#include "onload/extensions_timestamping.h"
#endif

/* Seconds.nanoseconds format */
#define TIME_FMT "%" PRIu64 ".%.9" PRIu64 " "
#define OTIME_FMT "%" PRIu64 ".%.9" PRIu32 " "

/* Picosecond resolution format */
#define SUBNS_TIME_FMT "%" PRIu64 ".%.9" PRIu32 "%03" PRIu64
#define SUBNS_TIME_SCALE 1000


/**** Helper macros *******************************************************/

/* Assert-like macros */
#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )

#define TRY(x)                                                          \
  do {                                                                  \
    int __rc = (x);                                                     \
      if( __rc < 0 ) {                                                  \
        fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);                 \
        fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);       \
        fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",                 \
                __rc, errno, strerror(errno));                          \
        exit(1);                                                        \
      }                                                                 \
  } while( 0 )


/**** Helper functions ****************************************************/

#define MATCHES(_x,_y) ( strncasecmp((_x),(_y),strlen((_x)))==0 )

static int get_protocol(char const* proto)
{
  if (MATCHES( "udp", proto )) return IPPROTO_UDP;
  if (MATCHES( "tcp", proto )) return IPPROTO_TCP;

  printf("Could not understand requested protocol %s\n", proto);
  return -EINVAL;
}
#undef MATCHES

/* This requires a bit of explanation.
 * Typically, you have to enable hardware timestamping on an interface.
 * Any application can do it, and then it's available to everyone, but there
 * is no reference counting for this request so it really needs to be
 * managed by an operator at system level.
 *
 * Running sfptpd automatically enables hardware timestamping and by
 * configuration can keep it enabled on exit; use this approach if also
 * planning to synchronise clocks.
 *
 * To let this application enable hardware timestamping globally on the
 * relevant interface, use the following option:
 *
 *   --ioctl ethX
 */
static void do_ioctl(struct configuration* cfg,
                     int sock,
                     bool enable_rx,
                     bool enable_tx)
{
  struct ifreq ifr;
  struct hwtstamp_config hwc;
  int ok;

  if(cfg->cfg_ioctl == NULL)
    return;

  bzero(&ifr, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", cfg->cfg_ioctl);

  hwc.flags = 0;
  hwc.tx_type = enable_tx ? HWTSTAMP_TX_ON : 0;
  hwc.rx_filter = enable_rx ? HWTSTAMP_FILTER_ALL : 0;

  ifr.ifr_data = (char*)&hwc;
  
  /* If using a TCP socket, we need to create a UDP one for the ioctl
   * call.  This is fine as the setting is global for that
   * interface 
   */
  if ( cfg->cfg_protocol == IPPROTO_TCP ) {
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    TEST(sock != -1);
  }

  ok = ioctl(sock, SIOCSHWTSTAMP, &ifr);
  if ( ok < 0 ) {
    printf("Setting SIOCSHWTSTAMP ioctl failed %d (%d - %s)\n", 
           ok, errno, strerror(errno));
  } else {
    printf("Accepted SIOCHWTSTAMP ioctl.\n");
  }

  if ( cfg->cfg_protocol == IPPROTO_TCP )
    close(sock);

  return;
}

/**** Onload Extensions API features **************************************/

#ifdef ONLOADEXT_AVAILABLE
static const char *sof_ts_dir(int sof)
{
  if( sof & (SOF_TIMESTAMPING_RX_HARDWARE |
             SOF_TIMESTAMPING_RX_SOFTWARE) )
    return "rx";
  else if( sof & (SOF_TIMESTAMPING_TX_HARDWARE |
                  SOF_TIMESTAMPING_TX_SOFTWARE) )
    return "tx";
  else
    return "?x";
}

static const char *sof_ts_type(int sof)
{
  if( sof & SOF_TIMESTAMPING_SOFTWARE )
    return "sw";
  else if( sof & SOF_TIMESTAMPING_SYS_HARDWARE )
    return "xfrm";
  else if( sof & SOF_TIMESTAMPING_RAW_HARDWARE )
    return "hw";
  else if( sof & SOF_TIMESTAMPING_OOEXT_TRAILER )
    return "trailer";
  else
    return "?";
}

/* Render extension v2 timestamp */
static void print_time_ext2(struct scm_timestamping_ooext* ts)
{
  printf(" %s.%s " SUBNS_TIME_FMT " %c%c%s",
         sof_ts_dir(ts->type),
         sof_ts_type(ts->type),
         ts->timestamp.sec,
         ts->timestamp.nsec,
         (SUBNS_TIME_SCALE * ((uint64_t) ts->timestamp.nsec_frac)) >> 24,
         ts->timestamp.flags & ONLOAD_TS_FLAG_CLOCK_SET     ? 's' : '-',
         ts->timestamp.flags & ONLOAD_TS_FLAG_CLOCK_IN_SYNC ? 'S' : '-',
         ts->timestamp.flags & ONLOAD_TS_FLAG_ACCEPTABLE    ?
           u8"\u2714" : u8"\u2718");
}
#endif
