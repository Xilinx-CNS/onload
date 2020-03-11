/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* efsend_timestamping
 *
 * Sample app that sends UDP packets on a specified interface.
 *
 * The application sends a UDP packet, waits for transmission of the
 * packet to finish and then sends the next.
 *
 * This application requests tx timestamping, allowing it to report the time
 * each packet was transmitted.
 *
 * The number of packets sent, the size of the packet, the amount of
 * time to wait between sends can be controlled.
 *
 * 2016 Solarflare Communications Inc.
 * Author: Richard Crowe
 * Date: 2016/06/06
 */

#include "efsend_common.h"

#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>

static int parse_opts(int argc, char* argv[]);

#define MAX_UDP_PAYLEN	(1500 - sizeof(ci_ip4_hdr) - sizeof(ci_udp_hdr))
#define N_BUFS          1
#define BUF_SIZE        2048

/* This gives a frame len of 70, which is the same as:
**   eth + ip + tcp + tso + 4 bytes payload
*/
#define DEFAULT_PAYLOAD_SIZE  28
#define LOCAL_PORT            12345

static ef_vi vi;
static ef_driver_handle dh;
static int tx_frame_len;
static int cfg_local_port = LOCAL_PORT;
static int cfg_payload_len = DEFAULT_PAYLOAD_SIZE;
static int cfg_iter = 10;
static int cfg_usleep = 0;
static int cfg_verbose = 0;
static int n_sent;
static int ifindex;


static void wait_for_some_completions(void)
{
  ef_event      evs[EF_VI_EVENT_POLL_MIN_EVS];
  int           n_ev, i;
  struct timespec ts;
  unsigned ts_flags;

  while( 1 ) {
    n_ev = ef_eventq_poll(&vi, evs, sizeof(evs) / sizeof(evs[0]));
    if( n_ev > 0 ) {
      for( i = 0; i < n_ev; ++i ) {
        if( EF_EVENT_TYPE(evs[i]) == EF_EVENT_TYPE_TX_WITH_TIMESTAMP) {
          /* One TX_with_timestamp event can signal completion of just one
           * TX, so there is no need to call ef_vi_transmit_unbundle().
           */
          TEST(EF_EVENT_TX_WITH_TIMESTAMP_RQ_ID(evs[i]) == n_sent);
          ++n_sent;
          if( cfg_verbose ) {
            ts.tv_nsec = EF_EVENT_TX_WITH_TIMESTAMP_NSEC(evs[i]);
            ts.tv_sec = EF_EVENT_TX_WITH_TIMESTAMP_SEC(evs[i]);
            ts_flags = EF_EVENT_TX_WITH_TIMESTAMP_SYNC_FLAGS(evs[i]);
            printf("Timestamp: %ld.%09ld  sync-flags:%s%s\n", ts.tv_sec,
                ts.tv_nsec,
                (ts_flags & EF_VI_SYNC_FLAG_CLOCK_SET) ? " ClockSet" : "",
                (ts_flags & EF_VI_SYNC_FLAG_CLOCK_IN_SYNC) ? " ClockInSync" :
                                                             "");
          }
          return;
        }
        else {
          TEST(!"Unexpected event received");
        }
      }
    }
  }
}


int main(int argc, char* argv[])
{

  ef_pd pd;
  ef_memreg mr;
  int i;
  void* p;
  ef_addr dma_buf_addr;
  /* Set flag to allow tx timestamping */
  int vi_flags = EF_VI_FLAGS_DEFAULT | EF_VI_TX_TIMESTAMPS;

  TRY(parse_opts(argc, argv));

  /* Intialize and configure hardware resources */
  TRY(ef_driver_open(&dh));
  TRY(ef_pd_alloc(&pd, dh, ifindex, EF_PD_DEFAULT));
  TRY(ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, 0, -1, NULL, -1, vi_flags));

  printf("txq_size=%d\n", ef_vi_transmit_capacity(&vi));
  printf("rxq_size=%d\n", ef_vi_receive_capacity(&vi));
  printf("evq_size=%d\n", ef_eventq_capacity(&vi));
  printf("sync_check_enabled=%d\n",
         (vi.vi_out_flags & EF_VI_OUT_CLOCK_SYNC_STATUS) != 0);

  /* Allocate memory for packet buffers, note alignment */
  TEST(posix_memalign(&p, CI_PAGE_SIZE, BUF_SIZE) == 0);
  /* Regiser memory with NIC */
  TRY(ef_memreg_alloc(&mr, dh, &pd, dh, p, BUF_SIZE));
  /* Store DMA address of the packet buffer memory */
  dma_buf_addr = ef_memreg_dma_addr(&mr, 0);

  /* Prepare packet content */
  tx_frame_len = init_udp_pkt(p, cfg_payload_len, &vi, dh, -1);

  /* Start sending */
  for( i = 0; i < cfg_iter; ++i ) {
    /* Transmit packet pointed by dma buffer address */
    TRY(ef_vi_transmit(&vi, dma_buf_addr, tx_frame_len, n_sent));
    wait_for_some_completions();
    if( cfg_usleep )
      usleep(cfg_usleep);
  }

  printf("Sent %d packets\n", cfg_iter);
  return 0;
}


/* Utilities */
void usage(void)
{
  common_usage();

  fprintf(stderr, "\n");
  fprintf(stderr, "e.g.:\n");
  fprintf(stderr, "  - Send pkts to 239.1.2.3:1234 from eth2:\n"
          "          efsend eth2 239.1.2.3 1234\n");
  exit(1);
}


static int parse_opts(int argc, char*argv[])
{
  int c;

  while( (c = getopt(argc, argv, "n:m:s:l:v")) != -1 )
    switch( c ) {
    case 'n':
      cfg_iter = atoi(optarg);
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
    case 'v':
      cfg_verbose = 1;
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
