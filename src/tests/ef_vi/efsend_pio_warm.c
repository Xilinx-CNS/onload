/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
/* efsend_pio_warm
 *
 * Sample app to demonstrate PIO transmit warming.
 *
 * The application sends a UDP packet using PIO each time a
 * trigger fires.  While waiting for a trigger, the
 * application can warm the PIO transmit path to reduce latency
 * of the subsequent send.
 *
 * The effect of warming can be assessed by measuring the time
 * from when the trigger fires to when the corresponding packet
 * leaves the adapter.
 *
 * Several parameters can be controlled including the delay between
 * triggers, the enablement of warming and the frequency of warming
 * while waiting for a trigger.
 *
 * 2017 Solarflare Communications Inc.
 * Author: Paul Emberson
 * Date: 2017/05/09
 */

#include "efsend_common.h"

#if defined(__x86_64__) || defined(__PPC64__) || defined(__aarch64__)

#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>
#include <etherfabric/pio.h>

static int parse_opts(int argc, char* argv[]);
static void assert_capability(ef_driver_handle dh, int ifindex, int cap);
static useconds_t usecs_since(const struct timespec* last_ts);

#define MAX_UDP_PAYLEN	(1500 - sizeof(ci_ip4_hdr) - sizeof(ci_udp_hdr))
#define BUF_SIZE        2048

/* This gives a frame len of 70, which is the same as:
**   eth + ip + tcp + tso + 4 bytes payload
*/
#define DEFAULT_PAYLOAD_SIZE  28
#define LOCAL_PORT            12345

struct transmit_timeinfo {
  struct timespec trigger_ts;
  struct timespec hw_ts;
  unsigned ts_flags;
};

static ef_vi vi;
static ef_driver_handle dh;
static int tx_frame_len;
static int cfg_local_port = LOCAL_PORT;
static int cfg_payload_len = DEFAULT_PAYLOAD_SIZE;
static int cfg_iter = 10;
static int cfg_usleep = 10000;
static int cfg_tx_delta = 0;
static int cfg_warm = 0;
static int cfg_warm_interval_us = 400;
static int ifindex;
static int n_sent;
volatile static int n_send_triggers;
struct transmit_timeinfo* ts_data;


static void wait_for_single_completion(void)
{
  ef_event      evs[EF_VI_EVENT_POLL_MIN_EVS];
  int           n_ev;

  while( 1 ) {
    n_ev = ef_eventq_poll(&vi, evs, sizeof(evs) / sizeof(evs[0]));
    if( n_ev == 1 ) {
      if( EF_EVENT_TYPE(evs[0]) == EF_EVENT_TYPE_TX_WITH_TIMESTAMP) {
        struct transmit_timeinfo* ti = &ts_data[n_sent];
        TEST(cfg_tx_delta);
        TEST(EF_EVENT_TX_WITH_TIMESTAMP_RQ_ID(evs[0]) == n_sent);
        ti->hw_ts.tv_nsec = EF_EVENT_TX_WITH_TIMESTAMP_NSEC(evs[0]);
        ti->hw_ts.tv_sec = EF_EVENT_TX_WITH_TIMESTAMP_SEC(evs[0]);
        ti->ts_flags = EF_EVENT_TX_WITH_TIMESTAMP_SYNC_FLAGS(evs[0]);
        ++n_sent;
        return;
      }
      else if( EF_EVENT_TYPE(evs[0]) == EF_EVENT_TYPE_TX) {
        int n_unbundled;
        ef_request_id ids[EF_VI_TRANSMIT_BATCH];
        TEST(!cfg_tx_delta);
        n_unbundled = ef_vi_transmit_unbundle(&vi, &evs[0], ids);
        TEST(n_unbundled == 1);
        TEST(ids[0] == n_sent);
        n_sent += n_unbundled;
        return;
      }
      else {
        TEST(!"Unexpected event received");
      }
    }
    else if( n_ev > 1 ) {
      TEST(!"More events than expected.");
    }
  }
}


static void* trigger_fn(void *arg)
{
  while( n_send_triggers < cfg_iter ) {
    struct transmit_timeinfo* ti = &ts_data[n_send_triggers];
    if( cfg_usleep )
      usleep(cfg_usleep);
    clock_gettime(CLOCK_REALTIME, &ti->trigger_ts);
    ++n_send_triggers;
  }
  return NULL;
}


int main(int argc, char* argv[])
{
  ef_pd pd;
  ef_pio pio;
  char pbuf[BUF_SIZE];
  int vi_flags = EF_VI_FLAGS_DEFAULT;
  pthread_t trigger_thread_id;
  unsigned long n_warm = 0;
  struct timespec warm_ts = { 0, 0 };

  TRY(parse_opts(argc, argv));
  TRY(ef_driver_open(&dh));
  assert_capability(dh, ifindex, EF_VI_CAP_PIO);

  if( cfg_tx_delta ) {
    assert_capability(dh, ifindex, EF_VI_CAP_HW_TX_TIMESTAMPING);
    vi_flags |= EF_VI_TX_TIMESTAMPS;
  }
  /* Initialize and configure hardware resources */
  TRY(ef_pd_alloc(&pd, dh, ifindex, EF_PD_DEFAULT));
  TRY(ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, 0, -1, NULL, -1, vi_flags));
  TRY(ef_pio_alloc(&pio, dh, &pd, -1, dh));
  TRY(ef_pio_link_vi(&pio, dh, &vi, dh));

  printf("txq_size=%d\n", ef_vi_transmit_capacity(&vi));
  printf("rxq_size=%d\n", ef_vi_receive_capacity(&vi));
  printf("evq_size=%d\n", ef_eventq_capacity(&vi));
  printf("sync_check_enabled=%d\n",
         (vi.vi_out_flags & EF_VI_OUT_CLOCK_SYNC_STATUS) != 0);
  printf("trigger_interval=%dus\n", cfg_usleep);
  printf("warm_enabled=%d\n", cfg_warm);
  printf("warm_interval=%dus\n", cfg_warm_interval_us);

  /* Allocate memory for timestamps */
  TEST(ts_data = malloc(cfg_iter * sizeof(*ts_data)));

  /* Prepare packet content and copy to PIO buffer.
   * This test application always sends the same data. */
  tx_frame_len = init_udp_pkt(pbuf, cfg_payload_len, &vi, dh, -1, 0);
  TRY(ef_pio_memcpy(&vi, pbuf, 0, tx_frame_len));

  /* Start triggering thread */
  TEST(pthread_create(&trigger_thread_id, NULL, trigger_fn, NULL) == 0);

  /* Wait for triggers and send packets. */
  while( n_sent < cfg_iter ) {
    if( n_sent < n_send_triggers ) {
      /* Got trigger, do send. */
      TRY(ef_vi_transmit_pio(&vi, 0, tx_frame_len, n_sent));

      /* Wait for completion.  This application uses only one offset
       * of the PIO buffer so must wait for completion before next
       * transmit.  A real applicaiton could make better use of the
       * PIO buffer and move completion handling off the critical path.
       */
      wait_for_single_completion();
    }
    else if( cfg_warm && usecs_since(&warm_ts) >= cfg_warm_interval_us ) {
      /* No send required, warm transmit path. */
      ++n_warm;
      clock_gettime(CLOCK_REALTIME, &warm_ts);
      ef_vi_transmit_pio_warm(&vi);
    }
  }
  printf("Sent %d packets.\n", cfg_iter);
  printf("Warmed transmit path %lu times.\n", n_warm);
  if( cfg_tx_delta ) {
    int i;
    int sync_flag = EF_VI_SYNC_FLAG_CLOCK_IN_SYNC;
    for( i = 0; i < cfg_iter; ++i ) {
      struct transmit_timeinfo* ti = &ts_data[i];
      printf("trigger_delta=%lu\n",
                (ti->hw_ts.tv_sec - ti->trigger_ts.tv_sec) * 1000000000
                + (ti->hw_ts.tv_nsec - ti->trigger_ts.tv_nsec));
      sync_flag &= ti->ts_flags;
    }
    if( ! (sync_flag & EF_VI_SYNC_FLAG_CLOCK_IN_SYNC) )
      fprintf(stderr,
              "WARNING: Measurements taken with unsynchronised clocks.\n");
  }
  return 0;
}


/* Utilities */
static int parse_opts(int argc, char*argv[])
{
  int c;

  while( (c = getopt(argc, argv, "n:m:s:l:twu:")) != -1 )
    switch( c ) {
    case 'n':
      cfg_iter = atoi(optarg);
      TEST(cfg_iter > 0);
      break;
    case 'm':
      cfg_payload_len = atoi(optarg);
      break;
    case 'l':
      cfg_local_port = atoi(optarg);
      break;
    case 's':
      cfg_usleep = atoi(optarg);
      break;
    case 't':
      cfg_tx_delta = 1;
      break;
    case 'w':
      cfg_warm = 1;
      break;
    case 'u':
      cfg_warm_interval_us = atoi(optarg);
      break;
    case '?':
      usage();
      break;
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc != 3 )
    usage();

  if( cfg_payload_len > MAX_UDP_PAYLEN ) {
    fprintf(stderr, "WARNING: UDP payload length %d is larger than standard "
            "MTU\n", cfg_payload_len);
  }

  /* Parse arguments after options */
  parse_args(argv, &ifindex, cfg_local_port, -1);
  return 0;
}


static void assert_capability(ef_driver_handle dh, int ifindex, int cap)
{
  unsigned long cap_val;
  int rc = ef_vi_capabilities_get(dh, ifindex, cap, &cap_val);
  if( rc != 0 ) {
    if( rc == -EOPNOTSUPP ) {
      fprintf(stderr,
        "ERROR: Interface does not have required capability %s (rc=%d).\n",
        ef_vi_capabilities_name(cap), rc);
      abort();
    }
    else {
      fprintf(stderr,
        "WARNING: Could not determine support for capability %s (rc=%d).\n",
        ef_vi_capabilities_name(cap), rc);
    }
  }
}


static useconds_t usecs_since(const struct timespec* last_ts)
{
  struct timespec now_ts;
  long us_since;
  clock_gettime(CLOCK_REALTIME, &now_ts);
  us_since = (now_ts.tv_sec - last_ts->tv_sec) * 1000000 +
                (now_ts.tv_nsec - last_ts->tv_nsec) / 1000;
  return us_since < 0 ? 0 : (useconds_t)us_since;
}

#else
#include <stdio.h>
#include <stdlib.h>
int main(void)
{
  fprintf(stderr, "ERROR: PIO not supported on this platform.\n");
  return 1;
}
#endif


void usage(void)
{
 fprintf(stderr,
    "This application sends a UDP packet using PIO each time a\n"
    "trigger fires.  While waiting for a trigger, the application\n"
    "can warm the PIO transmit path to reduce latency of the\n"
    "subsequent send.\n");
  fprintf(stderr, "\n");
  common_usage();
  fprintf(stderr, "  -t                  - enable hardware TX timestamps\n");
  fprintf(stderr, "  -w                  - enable PIO transmit warming\n");
  fprintf(stderr, "  -u <warm-interval>  - how often to warm (microseconds)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "e.g.:\n");
  fprintf(stderr, "  Trigger send every 0.5s with warming enabled and \n"
                  "  measure trigger to wire latency.\n"
              "    ./efsend_pio_warm -t -w -s 500000 eth2 239.1.2.3 1234\n");
  exit(1);
}


