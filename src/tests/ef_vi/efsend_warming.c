/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2024 Advance Micro Devices, Inc.*/
/* efsend_warming
 *
 * Sample app to demonstrate transmit warming.
 *
 * The application sends a UDP packet each time a
 * trigger fires.  While waiting for a trigger, the
 * application can warm the transmit path to reduce latency
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
 * Option '-p' runs simple function to pollute cache on selected CPU
 * in-order to simulate a full application where CPU might be busy with other
 * tasks in-between sends.
 *
 * 2017-2024 AMD Solarflare
 * Authors: Paul Emberson & Ian Beecraft
 * Date: 2017/05/09 - 2024/06/10
 */
#define _GNU_SOURCE
#include "efsend_common.h"

#if defined(__x86_64__)

#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>
#include <etherfabric/pio.h>
#include <etherfabric/efct_vi.h>

static int parse_opts(int argc, char* argv[]);
static void assert_capability(ef_driver_handle dh, int ifindex, int cap);
static useconds_t usecs_since(const struct timespec* last_ts);

#define BUF_SIZE        2048

/* This gives a frame len of 70, which is the same as:
**   eth + ip + tcp + tso + 4 bytes payload
*/
#define DEFAULT_PAYLOAD_SIZE  28
#define LOCAL_PORT            12345

#define EV_POLL_BATCH_SIZE   16

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
static int cfg_affinity[2];
static int cfg_ct_threshold = 64;
static char *pollution_buf;
static bool polluted = false;
static unsigned long cfg_pollute = 0;
static int ifindex;
static int n_sent;
volatile static int n_send_triggers;
struct transmit_timeinfo* ts_data;
static unsigned long n_warm = 0;
static struct timespec warm_ts = { 0, 0 };

enum mode {
  MODE_PIO = 1,
  MODE_CTPIO = 2,
};
static unsigned cfg_mode = MODE_CTPIO;
static bool efct = false;
static void *ctpio_region;
char pbuf[BUF_SIZE];
ef_vi_tx_warm_state state;
typedef void (*send_fn_t)(void);
send_fn_t send_function;
ef_addr dma_buf_addr;

/* Unfortunately the gcc built-in for clearing cache is a no-op on __x86_64__
 * therefore to 'flush/clear' the data cache we exercise a block of memory
 * larger than the specific cache of the CPU.
 *
 * This certainly is not an elegant solution but does help to highlight the
 * need and benefit of warming the send path. In an actual application you can
 * imagine how the send operation/data can be flushed from cache.
 *
 * It is worth noting that if the transmit timeout is too low this can cause
 * the calculated latency to be in-correct by delaying the send call.*/
static void pollute_cache(void)
{
  int i;
  for( i = 0; i < cfg_pollute; ++i ) {
    pollution_buf[i] += i%0xFF;
  }
  polluted = true;
}

static void wait_for_completion(void)
{
  ef_event      evs[EV_POLL_BATCH_SIZE];
  int           n_ev;

  while( 1 ) {
    n_ev = ef_eventq_poll(&vi, evs, EV_POLL_BATCH_SIZE);
    for( int i = 0; i < n_ev; ++i ) {
      if( EF_EVENT_TYPE(evs[i]) == EF_EVENT_TYPE_TX ) {
        int n_unbundled;
        ef_request_id ids[EF_VI_TRANSMIT_BATCH];
        n_unbundled = ef_vi_transmit_unbundle(&vi, &evs[i], ids);
        /* If using hw TX timestamps send will be an event of type
         * EF_EVENT_TYPE_TX_WITH_TIMESTAMP so return early */
        if( cfg_tx_delta )
          continue;

        for( int j = 0; j < n_unbundled; ++j ) {
          if( ids[j] != EF_REQUEST_ID_MASK ) {
            n_sent++;
            return;
          }
        }
      }
      else if( EF_EVENT_TYPE(evs[i]) == EF_EVENT_TYPE_TX_WITH_TIMESTAMP ) {
        /* Should only reach this point for valid packets */
        struct transmit_timeinfo* ti = &ts_data[n_sent];
        TEST(cfg_tx_delta);
        ti->hw_ts.tv_nsec = EF_EVENT_TX_WITH_TIMESTAMP_NSEC(evs[i]);
        ti->hw_ts.tv_sec = EF_EVENT_TX_WITH_TIMESTAMP_SEC(evs[i]);
        ti->ts_flags = EF_EVENT_TX_WITH_TIMESTAMP_SYNC_FLAGS(evs[i]);
        ++n_sent;
        return;
      }
      else {
        TEST(!"Unexpected event received");
      }
    }
  }
}

static void drain_queue(void)
{
  ef_event      evs[EV_POLL_BATCH_SIZE];
  while( 1 ) {
    int n_ev = ef_eventq_poll(&vi, evs, EV_POLL_BATCH_SIZE);
    if( n_ev == 0 )
      break;

    for( int i = 0; i < n_ev; ++i ) {
      if( EF_EVENT_TYPE(evs[i]) == EF_EVENT_TYPE_TX ){
          ef_request_id ids[EF_VI_TRANSMIT_BATCH];
          ef_vi_transmit_unbundle(&vi, &evs[i], ids);
      }
    }
  }
}

/* When warming the send calls will return -EAGAIN because the TXQ is deemed
 * full. This is to be expected, but it means that in a real application
 * separate calls for warming and actual sends should be used to check the
 * return codes of non-warming sends.*/
static void ctpio_send(void)
{
  ef_vi_transmit_ctpio(&vi, pbuf, tx_frame_len, cfg_ct_threshold);
  ef_vi_transmit_ctpio_fallback(&vi, dma_buf_addr, tx_frame_len, n_sent);
}

static void pio_send(void)
{
  ef_vi_transmit_pio(&vi, 0, tx_frame_len, n_sent);
}

static void warming_loop(void)
{
  /* Wait for triggers and send packets. */
  while( n_sent < cfg_iter ) {
    if( n_sent < n_send_triggers ) {
      send_function();
      polluted = false;
      wait_for_completion();
    }
    else if( cfg_warm && usecs_since(&warm_ts) >= cfg_warm_interval_us ) {
      /* No send required, warm transmit path.*/
      ++n_warm;
      clock_gettime(CLOCK_REALTIME, &warm_ts);
      ef_vi_start_transmit_warm(&vi, &state, ctpio_region);
      send_function();
      ef_vi_stop_transmit_warm(&vi, &state);
      /* EFCT arch generate events that need to be handled otherwise TXQ could
       * overflow causing send failures*/
      if( n_warm % EV_POLL_BATCH_SIZE == 0 && efct )
        drain_queue();
    }
    else if( cfg_pollute && !polluted )
      pollute_cache();
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
  int vi_flags = EF_VI_FLAGS_DEFAULT;
  pthread_t trigger_thread_id;
  cpu_set_t cpuset;
  ef_memreg mr;

  /* set initial affinities to 0,1 */
  cfg_affinity[0] = 0;
  cfg_affinity[1] = 1;
  TRY(parse_opts(argc, argv));

  TRY(ef_driver_open(&dh));
  if( cfg_mode == MODE_PIO )
    assert_capability(dh, ifindex, EF_VI_CAP_PIO);
  else
    assert_capability(dh, ifindex, EF_VI_CAP_CTPIO);

  if( cfg_tx_delta ) {
    assert_capability(dh, ifindex, EF_VI_CAP_HW_TX_TIMESTAMPING);
    vi_flags |= EF_VI_TX_TIMESTAMPS;
  }

  if( cfg_mode == MODE_CTPIO )
    vi_flags |= EF_VI_TX_CTPIO;

  /* Initialize and configure hardware resources */
  TRY(ef_pd_alloc(&pd, dh, ifindex, EF_PD_DEFAULT));
  TRY(ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, 0, -1, NULL, -1, vi_flags));
  if( cfg_mode == MODE_PIO ) {
    TRY(ef_pio_alloc(&pio, dh, &pd, -1, dh));
    TRY(ef_pio_link_vi(&pio, dh, &vi, dh));
  }
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

  /* Prepare packet content and copy to PIO buffer, if using PIO.
   * This test application always sends the same data. */
  tx_frame_len = init_udp_pkt(pbuf, cfg_payload_len, &vi, dh, -1, 1);
  if( cfg_mode == MODE_PIO )
    TRY(ef_pio_memcpy(&vi, pbuf, 0, tx_frame_len));

  /*Set CPU affinities and launch trigger thread*/
  CPU_ZERO(&cpuset);
  CPU_SET(cfg_affinity[0], &cpuset);
  TRY(sched_setaffinity(0, sizeof(cpuset), &cpuset));
  /* Start triggering thread */
  TEST(pthread_create(&trigger_thread_id, NULL, trigger_fn, NULL) == 0);
  CPU_ZERO(&cpuset);
  CPU_SET(cfg_affinity[1], &cpuset);
  TRY(pthread_setaffinity_np(trigger_thread_id, sizeof(cpuset), &cpuset));

  if( vi.nic_type.arch == EF_VI_ARCH_EFCT )
    efct = true;

  if( cfg_mode == MODE_CTPIO ) {
    TEST(posix_memalign(&ctpio_region, 4096, BUF_SIZE) == 0);
    /* Register memory with NIC for fallback */
    TEST(ef_memreg_alloc(&mr, dh, &pd, dh, ctpio_region, 2048) == 0);
    memcpy(ctpio_region, pbuf, 2048);
    /* Store DMA address of the packet buffer memory */
    dma_buf_addr = ef_memreg_dma_addr(&mr, 0);
  }

  if( cfg_pollute ) {
    int i;
    TEST(pollution_buf = calloc(1, cfg_pollute));
    for (i = 0; i < cfg_pollute; ++i)
      pollution_buf[i] = (char)i;
  }
  printf("cache_pollution=%d\n", cfg_pollute > 0);

  switch( cfg_mode ) {
    case MODE_CTPIO:
      send_function = ctpio_send;
      printf("send mode=CTPIO\n");
      break;
    case MODE_PIO:
    default:
      send_function = pio_send;
      printf("send mode=PIO\n");
      break;
  }

  warming_loop();

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
  char *affinity_token;

  while( (c = getopt(argc, argv, "n:m:s:l:a:x:c:p:twu:")) != -1 )
    switch( c ) {
    case 'a':
      affinity_token = strtok(optarg, ";");
      cfg_affinity[0] = (affinity_token == NULL) ? 0: atoi(affinity_token);
      TEST(cfg_affinity[0] >= 0);
      affinity_token = strtok(NULL, ";");
      cfg_affinity[1] = (affinity_token == NULL) ? 1: atoi(affinity_token);
      TEST(cfg_affinity[1] >= 0);
      break;
    case 'c':
      cfg_ct_threshold = atoi(optarg);
      TEST(cfg_ct_threshold >= 0);
      break;
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
    case 'x':
      if( strlen(optarg) > 1 )
          fprintf(stderr, "Incorrect argument length for 'x' expected: 1 "
                                            "got '%lu'\n", strlen(optarg));
      switch( optarg[0] ) {
        case 'c': cfg_mode = MODE_CTPIO; break;
        case 'p': cfg_mode = MODE_PIO; break;
        default:
          fprintf(stderr, "Unknown mode '%c'\n", optarg[0]);
      }
      break;
    case 'p':
      cfg_pollute = atoi(optarg);
      cfg_pollute = cfg_pollute > 128 ? 128 * 1024 * 1024
                                : cfg_pollute * 1024 * 1024;
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

/* If not running on x86_64 return error */
#else
#include <stdio.h>
#include <stdlib.h>
int main(void)
{
  fprintf(stderr, "ERROR: warming not supported on this platform.\n");
  return 1;
}
#endif


void usage(void)
{
 fprintf(stderr,
    "This application sends a UDP packet each time a\n"
    "trigger fires.  While waiting for a trigger, the application\n"
    "can warm the transmit path to reduce latency of the\n"
    "subsequent send.\n");
  fprintf(stderr, "\n");
  common_usage();
  fprintf(stderr, "  -t                  - enable hardware TX timestamps\n");
  fprintf(stderr, "  -w                  - enable transmit warming\n");
  fprintf(stderr, "  -u <warm-interval>  - how often to warm (microseconds)\n");
  fprintf(stderr, "  -p <size (MB)>      - pollute xMB of cache after sends\n");
  fprintf(stderr, "  -x <send-mode>      - method of send to warm:\n");
  fprintf(stderr, "                        [c]tpio (default), [p]io\n");
  fprintf(stderr, "  -c <ct-threshold>   - set the ctpio ct threshold, when\n");
  fprintf(stderr, "                        using CTPIO mode: 64 (default)\n");
  fprintf(stderr, "  -a '<main>;<trig>'  - set affinity of main and trigger\n");
  fprintf(stderr, "                        threads e.g. '0;1' (default)");
  fprintf(stderr, "\n");
  fprintf(stderr, "e.g.:\n");
  fprintf(stderr, "  Trigger pio send every 0.5s with warming enabled and \n"
                  "  measure trigger to wire latency.\n"
              "    ./efsend_warming -t -w -s 500000 eth2 239.1.2.3 1234\n");
  exit(1);
}


