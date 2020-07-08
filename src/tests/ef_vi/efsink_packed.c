/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2019 Xilinx, Inc. */
/* efsink_packed
 *
 * Receive packets using "packed stream" mode.
 *
 * 2014 Solarflare Communications Inc.
 * Author: David Riddoch
 * Date: 2014/08/27
 */

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/packedstream.h>

#include "utils.h"


struct buf {
  ef_addr     ef_addr;
  struct buf* next;
};


struct thread {
  ef_driver_handle         dh;
  struct ef_pd             pd;
  struct ef_vi             vi;
  struct ef_memreg         memreg;
  int                      psp_start_offset;
  struct buf*              current_buf;
  struct buf*              posted_bufs;
  struct buf**             posted_bufs_tail;
  ef_packed_stream_packet* ps_pkt_iter;
  uint64_t                 n_rx_pkts;
  uint64_t                 n_rx_bytes;
};


static int cfg_hexdump;
static int cfg_timestamping;
static int cfg_max_fill;
static int cfg_verbose;


static void hexdump(const void* pv, int len)
{
  const unsigned char* p = (const unsigned char*) pv;
  int i;
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
}


static inline void posted_buf_put(struct thread* t, struct buf* buf)
{
  buf->next = NULL;
  *(t->posted_bufs_tail) = buf;
  t->posted_bufs_tail = &buf->next;
}


static inline struct buf* posted_buf_get(struct thread* t)
{
  struct buf* buf = t->posted_bufs;
  if( buf != NULL ) {
    t->posted_bufs = buf->next;
    if( t->posted_bufs == NULL )
      t->posted_bufs_tail = &(t->posted_bufs);
  }
  return buf;
}


static inline void consume_packet(struct thread* t,
                                  ef_packed_stream_packet* ps_pkt)
{
  /* Do something useful with the received packet! */

  if( cfg_verbose )
    printf("PKT: ts=%d.%09d cap_len=%d orig_len=%d flags=%s%s%s%s%s\n",
           ps_pkt->ps_ts_sec, ps_pkt->ps_ts_nsec,
           (int) ps_pkt->ps_cap_len, (int) ps_pkt->ps_orig_len,
           (ps_pkt->ps_flags & EF_VI_PS_FLAG_CLOCK_SET) ? "ClkSet,":"",
           (ps_pkt->ps_flags & EF_VI_PS_FLAG_CLOCK_IN_SYNC) ? "InSync,":"",
           (ps_pkt->ps_flags & EF_VI_PS_FLAG_BAD_FCS) ? "BadFcs,":"",
           (ps_pkt->ps_flags & EF_VI_PS_FLAG_BAD_L3_CSUM) ? "BadL3Csum,":"",
           (ps_pkt->ps_flags & EF_VI_PS_FLAG_BAD_L4_CSUM) ? "BadL4Csum,":"");

  if( cfg_hexdump )
    hexdump(ef_packed_stream_packet_payload(ps_pkt), ps_pkt->ps_cap_len);
}


static inline void handle_rx_ps(struct thread* t, const ef_event* pev)
{
  int n_pkts, n_bytes, rc;

  if( EF_EVENT_RX_PS_NEXT_BUFFER(*pev) ) {
    if( t->current_buf != NULL ) {
      TRY(ef_vi_receive_post(&t->vi, t->current_buf->ef_addr, 0));
      posted_buf_put(t, t->current_buf);
    }
    t->current_buf = posted_buf_get(t);
    t->ps_pkt_iter = ef_packed_stream_packet_first(t->current_buf,
                                                   t->psp_start_offset);
  }

  ef_packed_stream_packet* ps_pkt = t->ps_pkt_iter;
  rc = ef_vi_packed_stream_unbundle(&t->vi, pev, &t->ps_pkt_iter,
                                    &n_pkts, &n_bytes);
  t->n_rx_pkts += n_pkts;
  t->n_rx_bytes += n_bytes;

  if( cfg_verbose )
    printf("EVT: rc=%d n_pkts=%d n_bytes=%d\n", rc, n_pkts, n_bytes);

  int i;
  for( i = 0; i < n_pkts; ++i ) {
    consume_packet(t, ps_pkt);
    ps_pkt = ef_packed_stream_packet_next(ps_pkt);
  }
}


static void thread_main_loop(struct thread* t)
{
  ef_event evs[16];
  const int max_evs = sizeof(evs) / sizeof(evs[0]);
  int i, n_ev;

  while( 1 ) {
    n_ev = ef_eventq_poll(&t->vi, evs, max_evs);

    for( i = 0; i < n_ev; ++i ) {
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_RX_PACKED_STREAM:
        handle_rx_ps(t, &(evs[i]));
        break;
      default:
        LOGE("ERROR: unexpected event type=%d\n", (int) EF_EVENT_TYPE(evs[i]));
        break;
      }
    }
  }
}

/**********************************************************************/

static void monitor(struct thread* thread)
{
  /* Print approx packet rate and bandwidth every second. */

  uint64_t now_bytes, prev_bytes;
  struct timeval start, end;
  uint64_t prev_pkts, now_pkts;
  int ms, pkt_rate, mbps;

  printf("# pkt-rate  bandwidth(Mbps)  pkts\n");

  prev_pkts = thread->n_rx_pkts;
  prev_bytes = thread->n_rx_bytes;
  gettimeofday(&start, NULL);

  while( 1 ) {
    sleep(1);
    now_pkts = thread->n_rx_pkts;
    now_bytes = thread->n_rx_bytes;
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
  struct thread* thread = arg;
  monitor(thread);
  return NULL;
}


static __attribute__ ((__noreturn__)) void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efsink_packed [options] <interface> <filter-spec>...\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "filter-spec:\n");
  fprintf(stderr, "  {udp|tcp}:[mcastloop-rx,][vid=<vlan>,]<local-host>:"
          "<local-port>[,<remote-host>:<remote-port>]\n");
  fprintf(stderr, "  eth:[vid=<vlan>,]<local-mac>\n");
  fprintf(stderr, "  {unicast-all,multicast-all}\n");
  fprintf(stderr, "  {unicast-mis,multicast-mis}:[vid=<vlan>]\n");
  fprintf(stderr, "  {sniff}:[promisc|no-promisc]\n");
  fprintf(stderr, "  {tx-sniff}\n");
  fprintf(stderr, "  {block-kernel|block-kernel-unicast|"
          "block-kernel-multicast}\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -d     hexdump received packet\n");
  fprintf(stderr, "  -t     Request hardware timestamping of packets\n");
  fprintf(stderr, "  -F FL  set max fill level for RX ring\n");
  fprintf(stderr, "  -v     output per-packet info\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  const char* interface;
  pthread_t thread_id;
  struct thread* t;
  unsigned vi_flags;
  int c, i;

  while( (c = getopt (argc, argv, "dtvF:")) != -1 )
    switch( c ) {
    case 'd':
      cfg_hexdump = 1;
      break;
    case 't':
      cfg_timestamping = 1;
      break;
    case 'v':
      cfg_verbose = 1;
      break;
    case 'F':
      cfg_max_fill = atoi(optarg);
      break;
    case '?':
      usage();
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc < 2 )
    usage();
  interface = argv[0];
  ++argv; --argc;

  TEST((t = calloc(1, sizeof(*t))) != NULL);
  t->current_buf = NULL;
  t->posted_bufs = NULL;
  t->posted_bufs_tail = &(t->posted_bufs);

  TRY(ef_driver_open(&t->dh));
  TRY(ef_pd_alloc_by_name(&t->pd, t->dh, interface, EF_PD_RX_PACKED_STREAM));
  vi_flags = EF_VI_RX_PACKED_STREAM | EF_VI_RX_PS_BUF_SIZE_64K;
  if( cfg_timestamping )
    vi_flags |= EF_VI_RX_TIMESTAMPS;
  TRY(ef_vi_alloc_from_pd(&t->vi, t->dh, &t->pd, t->dh,
                          -1, -1, -1, NULL, -1, vi_flags));

  ef_packed_stream_params psp;
  TRY(ef_vi_packed_stream_get_params(&t->vi, &psp));
  if( cfg_max_fill == 0 )
    cfg_max_fill = psp.psp_max_usable_buffers;
  fprintf(stderr, "rxq_size=%d\n", ef_vi_receive_capacity(&t->vi));
  fprintf(stderr, "evq_size=%d\n", ef_eventq_capacity(&t->vi));
  fprintf(stderr, "max_fill=%d\n", cfg_max_fill);
  fprintf(stderr, "psp_buffer_size=%d\n", psp.psp_buffer_size);
  fprintf(stderr, "psp_buffer_align=%d\n", psp.psp_buffer_align);
  fprintf(stderr, "psp_start_offset=%d\n", psp.psp_start_offset);
  fprintf(stderr, "psp_max_usable_buffers=%d\n", psp.psp_max_usable_buffers);
  t->psp_start_offset = psp.psp_start_offset;

  TEST( cfg_max_fill <= ef_vi_receive_capacity(&t->vi) );

  /* Packed stream mode requires large contiguous buffers, so allocate huge
   * pages.  (Also makes consuming packets more efficient of course).
   */
  int n_bufs = cfg_max_fill;
  size_t buf_size = psp.psp_buffer_size;
  size_t alloc_size = n_bufs * buf_size;
  alloc_size = ROUND_UP(alloc_size, huge_page_size);
  void* p;
  p = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
           MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
  if( p == MAP_FAILED ) {
    fprintf(stderr, "ERROR: mmap failed.  You probably need to allocate some "
            "huge pages.\n");
    exit(2);
  }
  TEST(p != MAP_FAILED);
  TEST(((uintptr_t) p & (psp.psp_buffer_align - 1)) == 0);
  TRY(ef_memreg_alloc(&t->memreg, t->dh, &t->pd, t->dh, p, alloc_size));
  for( i = 0; i < n_bufs; ++i ) {
    struct buf* buf = (void*) ((char*) p + i * buf_size);
    buf->ef_addr = ef_memreg_dma_addr(&t->memreg, i * buf_size);
    TRY(ef_vi_receive_post(&t->vi, buf->ef_addr, 0));
    posted_buf_put(t, buf);
  }

  while( argc > 0 ) {
    ef_filter_spec filter_spec;
    if( filter_parse(&filter_spec, argv[0], NULL) != 0 ) {
      LOGE("ERROR: Bad filter spec '%s'\n", argv[0]);
      exit(1);
    }
    TRY(ef_vi_filter_add(&t->vi, t->dh, &filter_spec, NULL));
    ++argv; --argc;
  }

  TEST(pthread_create(&thread_id, NULL, monitor_fn, t) == 0);
  thread_main_loop(t);
  return 0;
}
