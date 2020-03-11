/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* efsend
 *
 * Sample app that sends UDP packets on a specified interface.
 *
 * The application cycles between posting packets to the TX ring
 * and handling TX completion events which allows TX ring slots
 * to be re-used.
 *
 * The number of packets sent, the size of the packet, the amount of
 * time to wait between sends can be controlled.
 *
 * 2014 Solarflare Communications Inc.
 * Author: Akhi Singhania
 * Date: 2014/02/17
 */

#include "efsend_common.h"

#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>

static int parse_opts(int argc, char* argv[]);


#define MAX_UDP_PAYLEN	(1500 - sizeof(ci_ip4_hdr) - sizeof(ci_udp_hdr))
#define N_BUFS          1
#define BUF_SIZE        2048
  /* Must be >= EF_VI_EVENT_POLL_MIN_EVS, but deliberately setting
   * larger to increase batching, and therefore throughput. */
#define EVENT_BATCH_SIZE 64


/* This gives a frame len of 70, which is the same as:
**   eth + ip + tcp + tso + 4 bytes payload
*/
#define DEFAULT_PAYLOAD_SIZE  28
#define LOCAL_PORT            12345

static ef_vi              vi;
static ef_driver_handle   dh;
static int                tx_frame_len;
static int                cfg_local_port = LOCAL_PORT;
static int                cfg_payload_len = DEFAULT_PAYLOAD_SIZE;
static int                cfg_iter = 10;
static int                cfg_usleep = 0;
static int                cfg_loopback = 0;
static int                cfg_phys_mode;
static int                cfg_disable_tx_push;
static int                cfg_use_vf;
static int                cfg_max_batch = 8192;
static int                cfg_vlan = -1;
static int                cfg_af_xdp;
static int                n_sent;
static int                n_pushed;
static int                ifindex;

static void handle_completions(void)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event      evs[EVENT_BATCH_SIZE];
  int           n_ev, i, j, n_unbundled = 0;

  n_ev = ef_eventq_poll(&vi, evs, sizeof(evs) / sizeof(evs[0]));
  if( n_ev > 0 ) {
    for( i = 0; i < n_ev; ++i ) {
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_TX:
        /* One TX event can signal completion of multiple TXs */
        n_unbundled = ef_vi_transmit_unbundle(&vi, &evs[i], ids);
        for ( j = 0; j < n_unbundled; ++j )
          TEST(ids[j] == n_sent + j);
        n_sent += n_unbundled;
        break;
      default:
        TEST(!"Unexpected event received");
      }
    }
  }
  /* No events yet is entirely acceptable */
}

static inline
int send_more_packets(int desired, ef_vi* vi, ef_addr dma_buf_addr) {
  int i;
  /* Don't try to send more packets than currently fit on the TX ring */
  int to_send;
  int possible = ef_vi_transmit_space(vi);
  to_send = (possible > desired) ? desired : possible;
  /* Further limit to requested batch size, if needed */
  to_send = (to_send > cfg_max_batch) ? cfg_max_batch : to_send;

  if( to_send > 0 ) {
    /* This is sending the same packet buffer over and over again.
     * a real application would usually send new data. */
    for( i = 0; i < to_send; ++i )
      TRY(ef_vi_transmit_init(vi, dma_buf_addr, tx_frame_len,
          n_pushed + i));

    /* Actually submit the packets to the NIC for transmission. */
    ef_vi_transmit_push(vi);
  }

  return to_send;
}

int main(int argc, char* argv[])
{

  ef_pd pd;
  ef_memreg mr;
  void* p;
  ef_addr dma_buf_addr;
  enum ef_pd_flags pd_flags = EF_PD_DEFAULT;
  enum ef_vi_flags vi_flags = EF_VI_FLAGS_DEFAULT;

  TRY(parse_opts(argc, argv));


  /* Set flags for options requested on command line */
  if( cfg_use_vf )
    pd_flags |= EF_PD_VF;
  if( cfg_phys_mode )
    pd_flags |= EF_PD_PHYS_MODE;
  if( cfg_loopback )
    pd_flags |= EF_PD_MCAST_LOOP;
  if( cfg_af_xdp )
    pd_flags |= EF_PD_AF_XDP;
  if( cfg_disable_tx_push )
    vi_flags |= EF_VI_TX_PUSH_DISABLE;

  /* Intialize and configure hardware resources */
  if( ! cfg_af_xdp )
    TRY(ef_driver_open(&dh));
  TRY(ef_pd_alloc(&pd, dh, ifindex, pd_flags));
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

  /* Prepare packet contents */
  tx_frame_len = init_udp_pkt(p, cfg_payload_len, &vi, dh, cfg_vlan);

  /* Continue until all sends are complete */
  while( n_sent < cfg_iter ) {
    /* Try to push up to the requested iterations, likely fewer get sent */
    n_pushed += send_more_packets(cfg_iter - n_pushed, &vi, dma_buf_addr);
    /* Check for transmit complete */
    handle_completions();
    if( cfg_usleep )
      usleep(cfg_usleep);
  }
  TEST(n_pushed == cfg_iter);

  printf("Sent %d packets\n", cfg_iter);
  return 0;
}


/* Utilities */
void usage(void)
{
  common_usage();

  fprintf(stderr, "  -b                  - enable loopback on the VI\n");
  fprintf(stderr, "  -p                  - enable physical address mode\n");
  fprintf(stderr, "  -t                  - disable tx push (on by default)\n");
  fprintf(stderr, "  -B                  - maximum send batch size\n");
  fprintf(stderr, "  -s                  - microseconds to sleep between batches\n");
  fprintf(stderr, "  -v                  - use a VF\n");
  fprintf(stderr, "  -V <vlan>           - vlan to send to (interface must have an IP)\n");
  fprintf(stderr, "  -x                  - use AF_XDP\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "e.g.:\n");
  fprintf(stderr, "  - Send pkts to 239.1.2.3:1234 from eth2:\n"
          "          efsend eth2 239.1.2.3 1234\n");
  exit(1);
}


static int parse_opts(int argc, char *argv[])
{
  int c;

  while((c = getopt(argc, argv, "n:m:s:B:l:V:bptvx")) != -1)
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
    case 'B':
      cfg_max_batch = atoi(optarg);
      break;
    case 'V':
      cfg_vlan = atoi(optarg);
      break;
    case 'b':
      cfg_loopback = 1;
      break;
    case 'p':
      cfg_phys_mode = 1;
      break;
    case 't':
      cfg_disable_tx_push = 1;
      break;
    case 'v':
      cfg_use_vf = 1;
      break;
    case 'x':
      cfg_af_xdp = 1;
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
  parse_args(argv, &ifindex, cfg_local_port, cfg_vlan);
  return 0;
}
