/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2020 Xilinx, Inc. */
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
#include <signal.h>

#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>

static int parse_opts(int argc, char* argv[], enum ef_pd_flags *pd_flags_out,
                      ef_driver_handle driver_handle);


#define N_BUFS          1
#define BUF_SIZE        2048
#define PAGE_SIZE       4096
/* Must be >= EF_VI_EVENT_POLL_MIN_EVS, but deliberately setting
 * larger to increase batching, and therefore throughput. */
#define EVENT_BATCH_SIZE 64


/* This gives a frame len of 70, which is the same as:
**   eth + ip + tcp + tso + 4 bytes payload
*/
#define DEFAULT_PAYLOAD_SIZE  28
#define LOCAL_PORT            12345

#define CI_MIN(x,y) (((x) < (y)) ? (x) : (y))

static int                cfg_local_port = LOCAL_PORT;
static int                cfg_payload_len = DEFAULT_PAYLOAD_SIZE;
static uint64_t           cfg_iter = 10;
static int                cfg_usleep = 0;
static int                cfg_loopback = 0;
static int                cfg_disable_tx_push;
static int                cfg_use_vf;
static int                cfg_max_batch = 8192;
static int                cfg_vlan = -1;
static bool               cfg_ctpio = false;
static uint64_t           n_sent;
static uint64_t           n_pushed;
static int                ifindex;
static bool               abort_test = false;

static void handle_tx_error(ef_vi *vi)
{
  /* Restart our TXQ */
  TRY(ef_vi_reinit_txq_post_error(vi));
  fprintf(stderr, "TXQ restarted after TX error event\n");
}

static void handle_completions(ef_vi *vi)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event      evs[EVENT_BATCH_SIZE];
  int           n_ev, i, j, n_unbundled = 0;

  n_ev = ef_eventq_poll(vi, evs, sizeof(evs) / sizeof(evs[0]));
  if( n_ev > 0 ) {
    for( i = 0; i < n_ev; ++i ) {
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_TX:
        /* One TX event can signal completion of multiple TXs */
        n_unbundled = ef_vi_transmit_unbundle(vi, &evs[i], ids);
        for ( j = 0; j < n_unbundled; ++j )
          TEST(ids[j] == (uint16_t)(n_sent + j));
        n_sent += n_unbundled;
        break;
      case EF_EVENT_TYPE_TX_ERROR:
        handle_tx_error(vi);
        break;
      default:
        TEST(!"Unexpected event received");
      }
    }
  }
  /* No events yet is entirely acceptable */
}

static uint16_t pkt_num_to_dma_id(uint64_t pkt_num) {
    return (uint16_t)pkt_num;
}

static
int send_more_packets_ctpio(uint64_t desired, ef_vi* vi,
                            const void* host_buf_addr,
                            ef_addr dma_buf_addr, int tx_frame_len)
{
  int i;
  uint64_t to_send = CI_MIN(cfg_max_batch, desired);
  int space = ef_vi_transmit_space_bytes(vi);

  to_send = CI_MIN(to_send, space / tx_frame_len);

  /* This is sending the same packet buffer over and over again.
   * a real application would usually send new data. */
  for( i = 0; i < to_send; ++i ) {
    ef_vi_transmit_ctpio(vi, host_buf_addr, tx_frame_len,
                         EF_VI_CTPIO_CT_THRESHOLD_SNF);
    /* Also post a fallback */
    int rc = ef_vi_transmit_ctpio_fallback(vi, dma_buf_addr, tx_frame_len,
                                           pkt_num_to_dma_id(n_pushed + i));
    if( rc == -EAGAIN )
      break;
    TRY(rc);
  }

  return i;
}

static
int send_more_packets_dma(uint64_t desired, ef_vi* vi, const void* host_buf_addr,
                          ef_addr dma_buf_addr, int tx_frame_len)
{
  int i;
  uint64_t to_send = cfg_max_batch < desired ? cfg_max_batch : desired;

  if( to_send < 0 )
    to_send = cfg_max_batch;

  /* This is sending the same packet buffer over and over again.
   * a real application would usually send new data. */
  for( i = 0; i < to_send; ++i ) {
    /* use 16-bit dma_id to avoid the invalid 0xffffffff value */
    int rc = ef_vi_transmit_init(vi, dma_buf_addr, tx_frame_len,
                                 pkt_num_to_dma_id(n_pushed + i));
    if( rc == -EAGAIN )
      break;
    TRY(rc);
  }

  if( i ) {
    /* Actually submit the packets to the NIC for transmission. */
    ef_vi_transmit_push(vi);
  }

  return i;
}

static void abort_signal(int signum, siginfo_t *p_siginfo, void *p_context)
{
  abort_test = true;
}

int main(int argc, char* argv[])
{
  ef_vi vi;
  ef_driver_handle dh;
  ef_pd pd;
  ef_memreg mr;
  void* p;
  ef_addr dma_buf_addr;
  enum ef_pd_flags pd_flags = EF_PD_DEFAULT;
  enum ef_vi_flags vi_flags = EF_VI_FLAGS_DEFAULT;
  unsigned long min_page_size, ctpio_only;
  size_t alloc_size;
  int tx_frame_len;
  int (*send_more_packets)(uint64_t, ef_vi*, const void*, ef_addr, int);
  struct timespec start_ts;
  struct timespec end_ts;
  long   delta_ms;
  double pkt_rate_mpps;
  double bw_mbps;

  struct sigaction sigact;

  /* open EF_VI driver handle */
  TRY(ef_driver_open(&dh));
  TRY(parse_opts(argc, argv, &pd_flags, dh));

  /* Set flags for options requested on command line */
  if( cfg_use_vf )
    pd_flags |= EF_PD_VF;
  if( cfg_loopback )
    pd_flags |= EF_PD_MCAST_LOOP;
  if( cfg_disable_tx_push )
    vi_flags |= EF_VI_TX_PUSH_DISABLE;

  /* Initialize and configure hardware resources */
  TRY(ef_pd_alloc(&pd, dh, ifindex, pd_flags));

  if ( !ef_pd_capabilities_get(dh, &pd, dh, EF_VI_CAP_CTPIO_ONLY, &ctpio_only)
       && ctpio_only )
    cfg_ctpio = true; /* Only supports CTPIO, so always use it */
  if( cfg_ctpio )
    vi_flags |= EF_VI_TX_CTPIO;

  TRY(ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, 0, -1, NULL, -1, vi_flags));

  printf("send_method=%s\n", cfg_ctpio ? "CTPIO" : "DMA");
  printf("txq_size=%d\n", ef_vi_transmit_capacity(&vi));
  printf("rxq_size=%d\n", ef_vi_receive_capacity(&vi));
  printf("evq_size=%d\n", ef_eventq_capacity(&vi));
  printf("sync_check_enabled=%d\n",
         (vi.vi_out_flags & EF_VI_OUT_CLOCK_SYNC_STATUS) != 0);

  /* Allocate memory for packet buffers, note alignment */
  if (pd_flags & EF_PD_PHYS_MODE)
    min_page_size = PAGE_SIZE;
  else
    TRY(ef_vi_capabilities_get(dh, ifindex, EF_VI_CAP_MIN_BUFFER_MODE_SIZE,
                               &min_page_size));
  alloc_size = MAX(min_page_size, BUF_SIZE);
  if (min_page_size >= 2 * 1024 * 1024) {
    /* Assume this means huge pages are mandatory */
    p = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    TEST(p != MAP_FAILED);
  }
  else {
    TEST(posix_memalign(&p, min_page_size, alloc_size) == 0);
  }
  /* Register memory with NIC */
  TRY(ef_memreg_alloc(&mr, dh, &pd, dh, p, alloc_size));
  /* Store DMA address of the packet buffer memory */
  dma_buf_addr = ef_memreg_dma_addr(&mr, 0);

  /* Prepare packet contents */
  tx_frame_len = init_udp_pkt(p, cfg_payload_len, &vi, dh, cfg_vlan, 1);
  printf("tx_frame_len=%d\n", tx_frame_len);

  /* Select TX method */
  if( cfg_ctpio )
    send_more_packets = send_more_packets_ctpio;
  else
    send_more_packets = send_more_packets_dma;

  sigact.sa_sigaction = abort_signal;
  sigact.sa_flags = SA_SIGINFO;
  sigaction(SIGINT, &sigact, 0);

  clock_gettime(CLOCK_MONOTONIC, &start_ts);

  /* Continue until all sends are complete */
  while( (n_sent < cfg_iter) && !abort_test ) {
    /* Try to push up to the requested iterations, likely fewer get sent */
    n_pushed += send_more_packets(cfg_iter - n_pushed, &vi, p,
                                  dma_buf_addr, tx_frame_len);
    /* Check for transmit complete */
    handle_completions(&vi);
    if( cfg_usleep )
      usleep(cfg_usleep);
  }

  if( !abort_test )
    TEST(n_pushed == cfg_iter);

  clock_gettime(CLOCK_MONOTONIC, &end_ts);

  delta_ms = (end_ts.tv_sec - start_ts.tv_sec) * 1000;
  delta_ms += (end_ts.tv_nsec - start_ts.tv_nsec) / 1e6;

  printf("Sent %ld packets\n", n_pushed);

  if( delta_ms == 0 ) {
    printf("Time: 0.000 seconds\n");
  } else {
    pkt_rate_mpps = n_pushed / (delta_ms * 1.0e3);
    bw_mbps = pkt_rate_mpps * tx_frame_len * 8;

    printf("Time: %ld.%03ld seconds\n", delta_ms / 1000, delta_ms % 1000);
    printf("Rate: %.3f Mpps\n", pkt_rate_mpps);
    printf("Bw: %.2f Mbps\n", bw_mbps);
  }

  return 0;
}


/* Utilities */
void usage(void)
{
  common_usage();

  fprintf(stderr, "  -n                  - number of packets to send (negative = unlimited)\n");
  fprintf(stderr, "  -b                  - enable loopback on the VI\n");
  fprintf(stderr, "  -p                  - enable physical address mode\n");
  fprintf(stderr, "  -t                  - disable tx push (on by default)\n");
  fprintf(stderr, "  -B                  - maximum send batch size\n");
  fprintf(stderr, "  -s                  - microseconds to sleep between batches\n");
  fprintf(stderr, "  -v                  - use a VF\n");
  fprintf(stderr, "  -V <vlan>           - vlan to send to (interface must have an IP)\n");
  fprintf(stderr, "  -c                  - use CTPIO for sends\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "e.g.:\n");
  fprintf(stderr, "  - Send pkts to 239.1.2.3:1234 from eth2:\n"
          "          efsend eth2 239.1.2.3 1234\n");
  exit(1);
}


static int parse_opts(int argc, char *argv[], enum ef_pd_flags *pd_flags_out,
                      ef_driver_handle driver_handle)
{
  int c;

  while((c = getopt(argc, argv, "n:m:s:B:l:V:bptvxc")) != -1)
    switch( c ) {
    case 'n':
      cfg_iter = (uint64_t)atoll(optarg);
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
      *pd_flags_out |= EF_PD_PHYS_MODE;
      break;
    case 't':
      cfg_disable_tx_push = 1;
      break;
    case 'v':
      cfg_use_vf = 1;
      break;
    case 'c':
      cfg_ctpio = true;
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
  parse_args(argv, &ifindex, cfg_local_port, cfg_vlan,
             pd_flags_out, driver_handle);
  return 0;
}
