/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2020 Xilinx, Inc. */
/* efsink
 *
 * Receive streams of packets on a single interface.
 *
 * 2011 Solarflare Communications Inc.
 * Author: David Riddoch
 * Date: 2011/04/28
 */

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>

#include <poll.h>

#include "utils.h"


#define EV_POLL_BATCH_SIZE   16
#define REFILL_BATCH_SIZE    16


/* Hardware delivers at most ef_vi_receive_buffer_len() bytes to each
 * buffer (default 1792), and for best performance buffers should be
 * aligned on a 64-byte boundary.  Also, RX DMA will not cross a 4K
 * boundary.  The I/O address space may be discontiguous at 4K boundaries.
 * So easiest thing to do is to make buffers always be 2K in size.
 */
#define PKT_BUF_SIZE         2048

/* Align address where data is delivered onto EF_VI_DMA_ALIGN boundary,
 * because that gives best performance.
 */
#define RX_DMA_OFF           ROUND_UP(sizeof(struct pkt_buf), EF_VI_DMA_ALIGN)


struct pkt_buf {
  /* I/O address corresponding to the start of this pkt_buf struct */
  ef_addr            ef_addr;

  /* pointer to where received packets start */
  void*              rx_ptr;

  int                id;
  struct pkt_buf*    next;
};


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
  unsigned           batch_loops;

  /* registered memory for DMA */
  void*              pkt_bufs;
  int                pkt_bufs_n;
  struct ef_memreg   memreg;

  /* pool of free packet buffers (LIFO to minimise working set) */
  struct pkt_buf*    free_pkt_bufs;
  int                free_pkt_bufs_n;

  /* statistics */
  uint64_t           n_rx_pkts;
  uint64_t           n_rx_bytes;
  uint64_t           n_ht_events;
};


static int cfg_hexdump;
static int cfg_timestamping;
static int cfg_vport;
static int cfg_vlan_id = EF_PD_VLAN_NONE;
static int cfg_verbose;
static int cfg_monitor_vi_stats;
static int cfg_rx_merge;
static int cfg_eventq_wait;
static int cfg_fd_wait;
static int cfg_max_fill = -1;
static int cfg_exit_pkts = -1;
static int cfg_register_mcast;

/* Mutex to protect printing from different threads */
static pthread_mutex_t printf_mutex;


static inline
struct pkt_buf* pkt_buf_from_id(struct resources* res, int pkt_buf_i)
{
  assert((unsigned) pkt_buf_i < (unsigned) res->pkt_bufs_n);
  return (void*) ((char*) res->pkt_bufs + (size_t) pkt_buf_i * PKT_BUF_SIZE);
}


static inline void pkt_buf_free(struct resources* res, struct pkt_buf* pkt_buf)
{
  pkt_buf->next = res->free_pkt_bufs;
  res->free_pkt_bufs = pkt_buf;
  ++(res->free_pkt_bufs_n);
}

static int join_mc_group(const char* interface, const struct in_addr *sa_mcast, int *sock) {
  int ifindex, rc = 0;
  char* local_ip;
  struct ip_mreqn mreq;

  // Assuming IPv4
  *sock = socket(AF_INET, SOCK_DGRAM, 0);
  TEST(*sock);

  get_ipaddr_of_intf(interface, &local_ip);
  if( ! parse_interface(interface, &ifindex) ) {
    LOGE("ERROR: Failed to parse interface %s\n",interface);
    rc = -1;
  }

  bzero(&mreq, sizeof(mreq));
  mreq.imr_address.s_addr = inet_addr(local_ip);
  mreq.imr_ifindex = ifindex;
  mreq.imr_multiaddr = *sa_mcast;

  //If multicast address is invalid, setsockopt(2) fails with the error EINVAL
  rc = setsockopt(*sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
  return rc;
}

static void hexdump(const void* pv, int len)
{
  const unsigned char* p = (const unsigned char*) pv;
  int i;
  pthread_mutex_lock(&printf_mutex);
  for( i = 0; i < len; ++i ) {
    const char* eos;
    switch( i & 15 ) {
    case 0:
      printf("%08x  ", i);
      eos = "";
      break;
    case 1:
      eos = " ";
      break;
    case 15:
      eos = "\n";
      break;
    default:
      eos = (i & 1) ? " " : "";
      break;
    }
    printf("%02x%s", (unsigned) p[i], eos);
  }
  printf(((len & 15) == 0) ? "\n" : "\n\n");
  pthread_mutex_unlock(&printf_mutex);
}


static inline int64_t timespec_diff_ns(struct timespec a, struct timespec b)
{
  assert(a.tv_nsec >= 0 && a.tv_nsec < 1000000000);
  assert(b.tv_nsec >= 0 && b.tv_nsec < 1000000000);
  return (a.tv_sec - b.tv_sec) * (int64_t) 1000000000
    + (a.tv_nsec - b.tv_nsec);
}


static void handle_rx(struct resources* res, int pkt_buf_i, int len)
{
  struct pkt_buf* pkt_buf;

  LOGV("PKT: received pkt=%d len=%d\n", pkt_buf_i, len);

  pkt_buf = pkt_buf_from_id(res, pkt_buf_i);

  if( cfg_timestamping ) {
    struct timespec hw_ts, sw_ts;
    unsigned ts_flags;
    TRY(clock_gettime(CLOCK_REALTIME, &sw_ts));
    void* dma_ptr = (char*) pkt_buf + RX_DMA_OFF;
    TRY(ef_vi_receive_get_timestamp_with_sync_flags(&res->vi, dma_ptr,
                                                    &hw_ts, &ts_flags));
    pthread_mutex_lock(&printf_mutex);
    printf("HW_TSTAMP=%ld.%09ld  delta=%"PRId64"ns  %s %s\n",
           hw_ts.tv_sec, hw_ts.tv_nsec, timespec_diff_ns(sw_ts, hw_ts),
           (ts_flags & EF_VI_SYNC_FLAG_CLOCK_SET) ? "ClockSet" : "",
           (ts_flags & EF_VI_SYNC_FLAG_CLOCK_IN_SYNC) ? "ClockInSync" : "");
    pthread_mutex_unlock(&printf_mutex);
  }

  /* Do something useful with packet contents here! */
  if( cfg_hexdump )
    hexdump(pkt_buf->rx_ptr, len);

  pkt_buf_free(res, pkt_buf);
  res->n_rx_pkts += 1;
  res->n_rx_bytes += len;
}


static void handle_rx_discard(struct resources* res,
                              int pkt_buf_i, int len, int discard_type)
{
  struct pkt_buf* pkt_buf;

  LOGE("ERROR: discard type=%d\n", discard_type);

  if( /* accept_discard_pkts */ 1 ) {
    handle_rx(res, pkt_buf_i, len);
  }
  else {
    pkt_buf = pkt_buf_from_id(res, pkt_buf_i);
    pkt_buf_free(res, pkt_buf);
  }
}


static void handle_batched_rx(struct resources* res, int pkt_buf_i)
{
  struct pkt_buf* pkt_buf = pkt_buf_from_id(res, pkt_buf_i);
  void* dma_ptr = (char*) pkt_buf + RX_DMA_OFF;
  uint16_t len = *(uint16_t*) ((uint8_t*) dma_ptr + res->pktlen_offset);
  len = le16toh(len);

  handle_rx(res, pkt_buf_i, len);
}


static void handle_rx_multi_pkts(struct resources* res)
{
  int pkt_buf_i = ef_vi_rxq_next_desc_id(&res->vi);
  struct pkt_buf* pkt_buf = pkt_buf_from_id(res, pkt_buf_i);
  void* dma_ptr = (char*) pkt_buf + RX_DMA_OFF;
  unsigned discard_flags;
  uint16_t len;

  ef_vi_receive_get_bytes(&res->vi, dma_ptr, &len);
  /* This code does not support jumbos: */
  TEST( len + res->rx_prefix_len < ef_vi_receive_buffer_len(&res->vi) );
  ef_vi_receive_get_discard_flags(&res->vi, dma_ptr, &discard_flags);
  if( discard_flags )
    handle_rx_discard(res, pkt_buf_i, len, discard_flags);
  else
    handle_rx(res, pkt_buf_i, len);
}


static bool refill_rx_ring(struct resources* res)
{
  struct pkt_buf* pkt_buf;
  int i;

  if( ef_vi_receive_fill_level(&res->vi) > res->refill_level ||
      res->free_pkt_bufs_n < REFILL_BATCH_SIZE )
    return false;

  do {
    for( i = 0; i < REFILL_BATCH_SIZE; ++i ) {
      pkt_buf = res->free_pkt_bufs;
      res->free_pkt_bufs = res->free_pkt_bufs->next;
      --(res->free_pkt_bufs_n);
      ef_vi_receive_init(&res->vi, pkt_buf->ef_addr + RX_DMA_OFF, pkt_buf->id);
    }
  } while( ef_vi_receive_fill_level(&res->vi) < res->refill_min &&
           res->free_pkt_bufs_n >= REFILL_BATCH_SIZE );
  ef_vi_receive_push(&res->vi);
  return true;
}


static int poll_evq(struct resources* res)
{
  ef_event evs[EV_POLL_BATCH_SIZE];
  ef_request_id ids[EF_VI_RECEIVE_BATCH];
  int i, j, n_rx;

  int n_ev = ef_eventq_poll(&res->vi, evs, EV_POLL_BATCH_SIZE);

  for( i = 0; i < n_ev; ++i ) {
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_RX:
      /* This code does not handle scattered jumbos. */
      TEST( EF_EVENT_RX_SOP(evs[i]) && ! EF_EVENT_RX_CONT(evs[i]) );
      assert( ! cfg_rx_merge );
      handle_rx(res, EF_EVENT_RX_RQ_ID(evs[i]),
                EF_EVENT_RX_BYTES(evs[i]) - res->rx_prefix_len);
      break;
    case EF_EVENT_TYPE_RX_MULTI:
    case EF_EVENT_TYPE_RX_MULTI_DISCARD:
      /* This code does not handle scattered jumbos. */
      TEST( EF_EVENT_RX_MULTI_SOP(evs[i]) && ! EF_EVENT_RX_MULTI_CONT(evs[i]) );
      assert( cfg_rx_merge );
      n_rx = ef_vi_receive_unbundle(&res->vi, &evs[i], ids);
      for( j = 0; j < n_rx; ++j )
        handle_batched_rx(res, ids[j]);
      res->n_ht_events += 1;
      break;
    case EF_EVENT_TYPE_RX_DISCARD:
      handle_rx_discard(res, EF_EVENT_RX_DISCARD_RQ_ID(evs[i]),
                        EF_EVENT_RX_DISCARD_BYTES(evs[i]) - res->rx_prefix_len,
                        EF_EVENT_RX_DISCARD_TYPE(evs[i]));
      break;
    case EF_EVENT_TYPE_RX_MULTI_PKTS:
      for( j = 0; j < evs[i].rx_multi_pkts.n_pkts; ++j )
        handle_rx_multi_pkts(res);
      res->n_ht_events += 1;
      break;
    default:
      LOGE("ERROR: unexpected event type=%d\n", (int) EF_EVENT_TYPE(evs[i]));
      break;
    }
  }

  return n_ev;
}


static void event_loop_throughput(struct resources* res)
{
  const int ev_lookahead = EV_POLL_BATCH_SIZE + 7;

  while( 1 ) {
    refill_rx_ring(res);
    /* Avoid reading entries in the EVQ that are in the same cache line
     * that the network adapter is writing to.
     */
    if( ef_eventq_has_many_events(&(res->vi), ev_lookahead) ||
        (res->batch_loops)-- == 0 ) {
      poll_evq(res);
      res->batch_loops = 100;
    }
  }
}


static void event_loop_low_latency(struct resources* res)
{
  while( 1 ) {
    refill_rx_ring(res);
    poll_evq(res);
  }
}


static void event_loop_blocking(struct resources* res)
{
  while( 1 ) {
    if( ! refill_rx_ring(res) && poll_evq(res) == 0 )
      TRY( ef_eventq_wait(&res->vi, res->dh, ef_eventq_current(&res->vi), 0) );
  }
}


static void event_loop_blocking_poll(struct resources* res)
{
  struct pollfd pollfd = {
    .fd      = res->dh,
    .events  = POLLIN,
    .revents = 0,
  };

  TRY( ef_vi_prime(&res->vi, res->dh, ef_eventq_current(&res->vi)) );

  while( 1 ) {
    TRY( poll(&pollfd, 1, -1) );
    if( pollfd.events & POLLIN ) {
      while( poll_evq(res) | refill_rx_ring(res) )
        ;
      TRY( ef_vi_prime(&res->vi, res->dh, ef_eventq_current(&res->vi)) );
    }
  }
}

/**********************************************************************/

static void efvi_stats_header_print(struct resources* res,
                                    const ef_vi_stats_layout** vi_stats_layout)
{
  int i;

  TRY(ef_vi_stats_query_layout(&res->vi, vi_stats_layout));

  for( i = 0; i < (*vi_stats_layout)->evsl_fields_num; ++i)
    printf("  %10s", (*vi_stats_layout)->evsl_fields[i].evsfl_name);
}


static void efvi_stats_print(struct resources* res, int reset_stats,
                             const ef_vi_stats_layout* vi_stats_layout)
{
  uint8_t* stats_data;
  int i, n_pad;

  TEST((stats_data = malloc(vi_stats_layout->evsl_data_size)) != NULL);

  ef_vi_stats_query(&res->vi, res->dh, stats_data, reset_stats);
  for( i = 0; i < vi_stats_layout->evsl_fields_num; ++i ) {
    const ef_vi_stats_field_layout* f = &vi_stats_layout->evsl_fields[i];
    n_pad = strlen(f->evsfl_name);
    if( n_pad < 10 )
      n_pad = 10;
    switch( f->evsfl_size ) {
      case sizeof(uint32_t):
        printf("  %*d", n_pad, *(uint32_t*)(stats_data + f->evsfl_offset));
        break;
      default:
        printf("  %*s", n_pad, ".");
    };
  }

  free(stats_data);
}


static void monitor(struct resources* res)
{
  /* Print approx packet rate and bandwidth every second.
   * When requested also print vi error statistics. */

  uint64_t now_bytes, prev_bytes;
  struct timeval start, end;
  uint64_t prev_pkts, now_pkts;
  int ms, pkt_rate, mbps;
  const ef_vi_stats_layout* vi_stats_layout;

  if( cfg_rx_merge )
    printf("#%9s %16s %16s %16s",
           "pkt-rate", "bandwidth(Mbps)", "total-pkts", "events");
  else
    printf("#%9s %16s %16s",
           "pkt-rate", "bandwidth(Mbps)", "total-pkts");
  if( cfg_monitor_vi_stats )
    efvi_stats_header_print(res, &vi_stats_layout);
  printf("\n");

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
    pthread_mutex_lock(&printf_mutex);
    if( cfg_rx_merge )
      printf("%10d %16d %16"PRIu64" %16"PRIu64,
             pkt_rate, mbps, now_pkts, res->n_ht_events);
    else
      printf("%10d %16d %16"PRIu64, pkt_rate, mbps, now_pkts);
    if( cfg_monitor_vi_stats )
      efvi_stats_print(res, 1, vi_stats_layout);
    printf("\n");
    pthread_mutex_unlock(&printf_mutex);
    fflush(stdout);
    prev_pkts = now_pkts;
    prev_bytes = now_bytes;
    start = end;

    if( cfg_exit_pkts > 0 && now_pkts >= cfg_exit_pkts )
      exit(0);
  }
}


static void* monitor_fn(void* arg)
{
  struct resources* res = arg;
  monitor(res);
  return NULL;
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
  fprintf(stderr, "  -d       hexdump received packet\n");
  fprintf(stderr, "  -t       enable hardware timestamps\n");
  fprintf(stderr, "  -V       allocate a virtual port\n");
  fprintf(stderr, "  -L <vid> assign vlan id to virtual port\n");
  fprintf(stderr, "  -v       enable verbose logging\n");
  fprintf(stderr, "  -m       monitor vi error statistics\n");
  fprintf(stderr, "  -b       use high RX event merge (batched) mode\n");
  fprintf(stderr, "  -e       block on eventq instead of busy wait\n");
  fprintf(stderr, "  -f       block on fd instead of busy wait\n");
  fprintf(stderr, "  -F <fl>  set max fill level for RX ring\n");
  fprintf(stderr, "  -n <num> exit after receiving n packets\n");
  fprintf(stderr, "  -j       join multicast ipv4 address mentioned in filter-spec\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  const char* interface;
  pthread_t thread_id;
  struct resources* res;
  unsigned pd_flags, vi_flags;
  struct in_addr sa_mcast;
  int c, sock;

  while( (c = getopt (argc, argv, "dtVL:vmbefF:n:j")) != -1 )
    switch( c ) {
    case 'd':
      cfg_hexdump = 1;
      break;
    case 't':
      cfg_timestamping = 1;
      break;
    case 'V':
      cfg_vport = 1;
      break;
    case 'L':
      cfg_vlan_id = atoi(optarg);
      break;
    case 'v':
      cfg_verbose = 1;
      break;
    case 'm':
      cfg_monitor_vi_stats = 1;
      break;
    case 'b':
      cfg_rx_merge = 1;
      break;
    case 'e':
      cfg_eventq_wait = 1;
      break;
    case 'f':
      cfg_fd_wait = 1;
      break;
    case 'F':
      cfg_max_fill = atoi(optarg);
      break;
    case 'n':
      cfg_exit_pkts = atoi(optarg);
      break;
    case 'j':
      cfg_register_mcast = 1;
      break;
    case '?':
      usage();
    default:
      TEST(0);
    }

  if ( cfg_eventq_wait && cfg_fd_wait ) {
    LOGE("ERROR: you cannot specify both -e (block on eventq) and -f (block on"
         " fd) as options\n");
    exit(1);
  }

  argc -= optind;
  argv += optind;
  if( argc < 1 )
    usage();
  interface = argv[0];
  ++argv; --argc;

  TEST((res = calloc(1, sizeof(*res))) != NULL);

  vi_flags = EF_VI_FLAGS_DEFAULT;
  if( cfg_timestamping )
    vi_flags |= EF_VI_RX_TIMESTAMPS;
  if( cfg_rx_merge )
    vi_flags |= EF_VI_RX_EVENT_MERGE;

  pd_flags = EF_PD_DEFAULT;

  /* Open driver and allocate a VI. */
  TRY(ef_driver_open(&res->dh));
  if( cfg_vport )
    TRY(ef_pd_alloc_with_vport(&res->pd, res->dh, interface,
                               pd_flags, cfg_vlan_id));
  else
    TRY(ef_pd_alloc_by_name(&res->pd, res->dh, interface, pd_flags));

  TRY(ef_vi_alloc_from_pd(&res->vi, res->dh, &res->pd, res->dh,
                          -1, cfg_max_fill, 0, NULL, -1, vi_flags));

  res->rx_prefix_len = ef_vi_receive_prefix_len(&res->vi);

  if( cfg_rx_merge ) {
    const ef_vi_layout_entry* layout;
    int len, i;
    TRY( ef_vi_receive_query_layout(&res->vi, &layout, &len) );
    for( i = 0; i < len; i++ )
      if( layout[i].evle_type == EF_VI_LAYOUT_PACKET_LENGTH )
        res->pktlen_offset = layout[i].evle_offset;
    TEST( res->pktlen_offset );
    TEST( res->rx_prefix_len );
  }

  if( cfg_max_fill < 0 )
    cfg_max_fill = ef_vi_receive_capacity(&res->vi) - 15;
  if( cfg_max_fill > ef_vi_receive_capacity(&res->vi) ) {
    LOGE("ERROR: max fill (%d) is bigger than ring capacity (%d)\n",
         cfg_max_fill, ef_vi_receive_capacity(&res->vi));
    exit(1);
  }

  LOGI("rxq_size=%d\n", ef_vi_receive_capacity(&res->vi));
  LOGI("max_fill=%d\n", cfg_max_fill);
  LOGI("evq_size=%d\n", ef_eventq_capacity(&res->vi));
  LOGI("rx_prefix_len=%d\n", res->rx_prefix_len);

  /* Allocate memory for DMA transfers. Try mmap() with MAP_HUGETLB to get huge
   * pages. If that fails, fall back to posix_memalign() and hope that we do
   * get them. */
  res->pkt_bufs_n = cfg_max_fill;
  size_t alloc_size = res->pkt_bufs_n * PKT_BUF_SIZE;
  alloc_size = ROUND_UP(alloc_size, huge_page_size);
  res->pkt_bufs = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
  if( res->pkt_bufs == MAP_FAILED ) {
    LOGW("mmap() failed. Are huge pages configured?\n");

    /* Allocate huge-page-aligned memory to give best chance of allocating
     * transparent huge-pages.
     */
    TEST(posix_memalign(&res->pkt_bufs, huge_page_size, alloc_size) == 0);
  }
  int i;
  for( i = 0; i < res->pkt_bufs_n; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(res, i);
    pkt_buf->rx_ptr = (char*) pkt_buf + RX_DMA_OFF + res->rx_prefix_len;
    pkt_buf->id = i;
    pkt_buf_free(res, pkt_buf);
  }

  /* Register the memory so that the adapter can access it. */
  TRY(ef_memreg_alloc(&res->memreg, res->dh, &res->pd, res->dh,
                      res->pkt_bufs, alloc_size));
  for( i = 0; i < res->pkt_bufs_n; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(res, i);
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
    if( filter_parse(&filter_spec, argv[0], &sa_mcast) != 0 ) {
      LOGE("ERROR: Bad filter spec '%s'\n", argv[0]);
      exit(1);
    }
    TRY(ef_vi_filter_add(&res->vi, res->dh, &filter_spec, NULL));
    ++argv; --argc;
  }

  if(cfg_register_mcast && join_mc_group(interface, &sa_mcast, &sock)) {
    if(sock >=0 )
      close(sock);
    LOGE("ERROR: multicast join failed");
    exit(1);
  }

  pthread_mutex_init(&printf_mutex, NULL);

  TEST(pthread_create(&thread_id, NULL, monitor_fn, res) == 0);

  printf("efsink is now ready to receive\n");
  fflush(stdout);

  if( cfg_eventq_wait )
    event_loop_blocking(res);
  else if( cfg_fd_wait )
    event_loop_blocking_poll(res);
  else if( 0 )
    event_loop_low_latency(res);
  else
    event_loop_throughput(res);

  /* Ideally, we should have a socket clean up here */
  /*if(sock >=0 )
    close(sock);*/
  return 0;
}
