/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* efrink_controller
 *
 * Receive streams of packets on a single interface into a shared memory ring.
 * This can be read by multiple consumers e.g. efrink_consumer
 *
 */


#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <ci/compat.h>

#include <signal.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>


#include "utils.h"
#include "efrink.h"

#define EV_POLL_BATCH_SIZE   16
#define REFILL_BATCH_SIZE    16


/* Align address where data is delivered onto EF_VI_DMA_ALIGN boundary,
 * because that gives best performance.
 */
#define RX_DMA_OFF           ROUND_UP(sizeof(struct pkt_buf), EF_VI_DMA_ALIGN)

struct resources {
  /* handle for accessing the driver */
  ef_driver_handle   dh;

  /* protection domain */
  struct ef_pd       pd;

  /* virtual interface (rxq + txq) */
  struct ef_vi       vi;
  int                rx_prefix_len;
  int                pktlen_offset;
  int                refill_level;
  int                refill_min;

  /* shared memory */
  int                shm_id;

  /* registered memory for DMA */
  void*              pkt_bufs;
  struct ef_memreg   memreg;

  /* next packet buffer to post on RX ring*/
  unsigned           current_id;

  /* statistics */
  uint64_t           n_rx_pkts;
  uint64_t           n_rx_bytes;
  uint64_t           n_ht_events;
};


static int cfg_verbose;
static int cfg_max_fill = -1;

static struct resources* gres;


static void handle_rx(struct resources* res, unsigned pkt_buf_i, int len,
                      int is_good, int discard_type)
{
  struct pkt_buf* pkt_buf;

  pkt_buf = pkt_buf_from_id(res->pkt_bufs, pkt_buf_i);
  pkt_buf->len = len;
  pkt_buf->flags = is_good ? FLAG_RX_GOOD : FLAG_RX_BAD;

  mark_packet_ready(pkt_buf);

  if( is_good ) {
    LOGV("PKT: received pkt=%d len=%d gc=%"PRIu64"\n",
         pkt_buf_i, len, pkt_buf->gen_c);

    res->n_rx_pkts += 1;
    res->n_rx_bytes += len;
  } else {
    LOGE("ERROR: discard type=%d\n", discard_type);
  }
}


static bool refill_rx_ring(struct resources* res)
{
  struct pkt_buf* pkt_buf;
  int i;

  if( ef_vi_receive_fill_level(&res->vi) > res->refill_level )
    return false;

  do {
    for( i = 0; i < REFILL_BATCH_SIZE; ++i ) {
      pkt_buf = pkt_buf_from_id(res->pkt_bufs, res->current_id);
      /* need to increment Gen count to show buffer is now posted */
      mark_packet_pending(pkt_buf);

      ef_vi_receive_init(&res->vi, pkt_buf->ef_addr + RX_DMA_OFF,
                         res->current_id);
      res->current_id = next_pkt_buf_id(res->current_id);
    }
  } while( ef_vi_receive_fill_level(&res->vi) < res->refill_min );
  ef_vi_receive_push(&res->vi);
  return true;
}


static int poll_evq(struct resources* res)
{
  ef_event evs[EV_POLL_BATCH_SIZE];
  int i;

  int n_ev = ef_eventq_poll(&res->vi, evs, EV_POLL_BATCH_SIZE);

  for( i = 0; i < n_ev; ++i ) {
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_RX:
      /* This code does not handle scattered jumbos. */
      TEST( EF_EVENT_RX_SOP(evs[i]) && ! EF_EVENT_RX_CONT(evs[i]) );
      handle_rx(res, EF_EVENT_RX_RQ_ID(evs[i]),
                EF_EVENT_RX_BYTES(evs[i]) - res->rx_prefix_len,
                1, 0);
      break;
    case EF_EVENT_TYPE_RX_DISCARD:
      handle_rx(res, EF_EVENT_RX_DISCARD_RQ_ID(evs[i]),
                EF_EVENT_RX_DISCARD_BYTES(evs[i]) - res->rx_prefix_len,
                0, EF_EVENT_RX_DISCARD_TYPE(evs[i]));
      break;
    default:
      LOGE("ERROR: unexpected event type=%d\n", (int) EF_EVENT_TYPE(evs[i]));
      break;
    }
  }

  return n_ev;
}


static void event_loop_low_latency(struct resources* res)
{
  while( 1 ) {
    refill_rx_ring(res);
    poll_evq(res);
  }
}
/**********************************************************************/


static void monitor(struct resources* res)
{
  /* Print approx packet rate and bandwidth every second.
   * When requested also print vi error statistics. */

  uint64_t now_bytes, prev_bytes;
  struct timeval start, end;
  uint64_t prev_pkts, now_pkts;
  int ms, pkt_rate, mbps;

  printf("#%9s %16s %16s\n",
         "pkt-rate", "bandwidth(Mbps)", "total-pkts");

  prev_pkts = res->n_rx_pkts;
  prev_bytes = res->n_rx_bytes;
  gettimeofday(&start, NULL);

  while( 1 ) {
    sleep(1);
    now_pkts = res->n_rx_pkts;
    now_bytes = res->n_rx_bytes;
    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;
    pkt_rate = (int) ((now_pkts - prev_pkts) * 1000 / ms);
    mbps = (int) ((now_bytes - prev_bytes) * 8 / 1000 / ms);
    printf("%10d %16d %16"PRIu64"\n", pkt_rate, mbps, now_pkts);
    fflush(stdout);
    prev_pkts = now_pkts;
    prev_bytes = now_bytes;
    start = end;
  }
}


static void* monitor_fn(void* arg)
{
  struct resources* res = arg;
  monitor(res);
  return NULL;
}


void signal_handler(int signal_number) {
  assert( signal_number == SIGINT );
  LOGV("About to exit, closing shared memory region\n");
  TRY(shmdt(gres->pkt_bufs));
  TRY(shmctl(gres->shm_id, IPC_RMID, NULL));
  exit(0);
}


static __attribute__ ((__noreturn__)) void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efsink [options] <interface> [<filter-spec>...]\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "filter-spec:\n");
  fprintf(stderr, "  {udp|tcp}:[mcastloop-rx,][vid=<vlan>,]<local-host>:"
          "<local-port>[,<remote-host>:<remote-port>]\n");
  fprintf(stderr, "  eth:[vid=<vlan>,][{ipproto,ethertype}=<val>,]"
                  "<local-mac>\n");
  fprintf(stderr, "  ethertype:[vid=<vlan>,]<ethertype>\n");
  fprintf(stderr, "  ipproto:[vid=<vlan>,]<protocol>\n");
  fprintf(stderr, "  {unicast-all,multicast-all}\n");
  fprintf(stderr, "  {unicast-mis,multicast-mis}:[vid=<vlan>]\n");
  fprintf(stderr, "  {sniff}:[promisc|no-promisc]\n");
  fprintf(stderr, "  {tx-sniff}\n");
  fprintf(stderr, "  {block-kernel|block-kernel-unicast|"
          "block-kernel-multicast}\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -v       enable verbose logging\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  const char* interface;
  pthread_t thread_id;
  struct resources* res;
  unsigned vi_flags;
  int c;

  while( (c = getopt (argc, argv, "v")) != -1 )
    switch( c ) {
    case 'v':
      cfg_verbose = 1;
      break;
    case '?':
      usage();
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc < 1 )
    usage();
  interface = argv[0];
  ++argv; --argc;

  TEST((res = calloc(1, sizeof(*res))) != NULL);
  gres = res;

  /* Open driver and allocate a VI. */
  TRY(ef_driver_open(&res->dh));
  TRY(ef_pd_alloc_by_name(&res->pd, res->dh, interface, EF_PD_DEFAULT));
  vi_flags = EF_VI_FLAGS_DEFAULT;
  TRY(ef_vi_alloc_from_pd(&res->vi, res->dh, &res->pd, res->dh,
                          -1, cfg_max_fill, 0, NULL, -1, vi_flags));
  res->rx_prefix_len = ef_vi_receive_prefix_len(&res->vi);

  cfg_max_fill = ef_vi_receive_capacity(&res->vi) - 16;

  LOGI("rxq_size=%d\n", ef_vi_receive_capacity(&res->vi));
  LOGI("max_fill=%d\n", cfg_max_fill);
  LOGI("evq_size=%d\n", ef_eventq_capacity(&res->vi));
  LOGI("rx_prefix_len=%d\n", res->rx_prefix_len);



  size_t alloc_size = PKT_BUFS_N * PKT_BUF_SIZE;
  alloc_size = ROUND_UP(alloc_size, huge_page_size);
  /* allocate shared memory */
  res->shm_id = shmget(ftok(SHM_NAME, 'R'),
                       alloc_size,
                       SHM_HUGETLB | IPC_CREAT | IPC_EXCL | SHM_R | SHM_W);
  if( res->shm_id < 0 ) {
    LOGW("shmget() failed. Possibile reasons include:\n"
         "- not enough huge pages available (e.g. configure vm.nr_hugepages)\n"
         "- SHM already exists due to unclean exit (check via 'ipcs')\n"
         "- another controller already running\n");
    TEST(0);
  }
  res->pkt_bufs = shmat(res->shm_id, NULL, 0);
  if( res->pkt_bufs == (char *)(-1) ) {
    LOGW("shmat() failed.\n");
    TEST(0);
  }
  signal(SIGINT, signal_handler);

  unsigned i;
  for( i = 0; i < PKT_BUFS_N; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(res->pkt_bufs, i);
    pkt_buf->rx_offset = RX_DMA_OFF + res->rx_prefix_len;
    /* initialise to unused */
    pkt_buf->len = 0;
    pkt_buf->flags = FLAG_RX_BAD;
    pkt_buf->gen_c = 0;
  }

  res->current_id = 0;

  /* Register the memory so that the adapter can access it. */
  TRY(ef_memreg_alloc(&res->memreg, res->dh, &res->pd, res->dh,
                      res->pkt_bufs, alloc_size));
  for( i = 0; i < PKT_BUFS_N; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(res->pkt_bufs, i);
    pkt_buf->ef_addr = ef_memreg_dma_addr(&res->memreg, i * PKT_BUF_SIZE);
  }

  /* Fill the RX ring. */
  res->refill_level = cfg_max_fill - REFILL_BATCH_SIZE;
  res->refill_min = cfg_max_fill / 2;
  while( ef_vi_receive_fill_level(&res->vi) <= res->refill_level )
    refill_rx_ring(res);

  /* Add filters so that adapter will send packets to this VI. */
  while( argc > 0 ) {
    ef_filter_spec filter_spec;
    if( filter_parse(&filter_spec, argv[0]) != 0 ) {
      LOGE("ERROR: Bad filter spec '%s'\n", argv[0]);
      exit(1);
    }
    TRY(ef_vi_filter_add(&res->vi, res->dh, &filter_spec, NULL));
    ++argv; --argc;
  }

  TEST(pthread_create(&thread_id, NULL, monitor_fn, res) == 0);

  event_loop_low_latency(res);

  return 0;
}
