/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2019 Xilinx, Inc. */
/* efforward
 *
 * Forward packets between two interfaces without modification.
 *
 * For best forwarding rates:
 * - use '-u' unidirectional option and run one instance in each direction
 * - turn off pause frames with ethtool
 * - increasing the NIC RX/TX descriptor cache sizes may also help
 *   e.g. 'sfboot rx-dc-size=32 tx-dc-size=64 vi-count=1024'
 *
 * 2011-17 Solarflare Communications Inc.
 * Author: David Riddoch
 * Date: 2011/04/13
 */

#define _GNU_SOURCE

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>

#include "utils.h"

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

#define RX_RING_SIZE         512
#define TX_RING_SIZE         2048


struct pkt_buf {
  /* I/O address corresponding to the start of this pkt_buf struct.
   * The pkt_buf is mapped into both VIs so there are two sets of rx
   * and tx IO addresses. */
  ef_addr            rx_ef_addr[2];
  ef_addr            tx_ef_addr[2];

  /* id to help look up the buffer when polling the EVQ */
  int                id;

  struct pkt_buf*    next;
};


struct pkt_bufs {
  /* Memory for packet buffers */
  void*  mem;
  size_t mem_size;

  /* Number of packet buffers allocated */
  int    num;

  /* pool of free packet buffers (LIFO to minimise working set) */
  struct pkt_buf*    free_pool;
  int                free_pool_n;
};


struct vi {
  /* handle for accessing the driver */
  ef_driver_handle   dh;

  /* protection domain */
  ef_pd              pd;

  /* virtual interface (rxq + txq + evq) */
  ef_vi              vi;

  /* registered memory for DMA */
  ef_memreg          memreg;

  /* number of TX waiting to be pushed (in '-x' mode) */
  unsigned int       tx_outstanding;

  /* statistics */
  uint64_t           n_pkts;
};


static struct vi vis[2];
static struct pkt_bufs pbs;
static int cfg_rx_merge = 1;
static int cfg_unidirectional;
static int cfg_stats = 1;


/* Given a id to a packet buffer, look up the data structure.  The ids
 * are assigned in ascending order so this is simple to do. */
static inline struct pkt_buf* pkt_buf_from_id(int pkt_buf_i)
{
  assert((unsigned) pkt_buf_i < (unsigned) pbs.num);
  return (void*) ((char*) pbs.mem + (size_t) pkt_buf_i * PKT_BUF_SIZE);
}


/* Use slightly different start address for DMA transfers into different
 * packet buffers to make better use of memory channels / cache */
static inline int addr_offset_from_id(int pkt_buf_i)
{
  return ( pkt_buf_i % 2 ) * EF_VI_DMA_ALIGN;
}


/* Try to refill the RXQ on the given VI with at most
 * REFILL_BATCH_SIZE packets if it has enough space and we have
 * enough free buffers. */
static void vi_refill_rx_ring(int vi_i)
{
  ef_vi* vi = &vis[vi_i].vi;
#define REFILL_BATCH_SIZE  64
  struct pkt_buf* pkt_buf;
  int i;

  if( ef_vi_receive_space(vi) < REFILL_BATCH_SIZE ||
      pbs.free_pool_n < REFILL_BATCH_SIZE )
    return;

  for( i = 0; i < REFILL_BATCH_SIZE; ++i ) {
    pkt_buf = pbs.free_pool;
    pbs.free_pool = pbs.free_pool->next;
    --pbs.free_pool_n;
    ef_vi_receive_init(vi, pkt_buf->rx_ef_addr[vi_i], pkt_buf->id);
  }
  ef_vi_receive_push(vi);
}


/* Free buffer into free pool in LIFO order to minimize cache footprint. */
static inline void pkt_buf_free(struct pkt_buf* pkt_buf)
{
  pkt_buf->next = pbs.free_pool;
  pbs.free_pool = pkt_buf;
  ++pbs.free_pool_n;
}


/* Handle an RX event on a VI.  We forward the packet on the other VI. */
static void handle_rx(int rx_vi_i, int pkt_buf_i, int len)
{
  int rc;
  int tx_vi_i = 2 - 1 - rx_vi_i;
  struct vi* rx_vi = &vis[rx_vi_i];
  struct vi* tx_vi = &vis[tx_vi_i];
  struct pkt_buf* pkt_buf = pkt_buf_from_id(pkt_buf_i);

  ++rx_vi->n_pkts;
  rc = ef_vi_transmit_init(&tx_vi->vi, pkt_buf->tx_ef_addr[tx_vi_i], len,
                           pkt_buf->id);
  if( rc == 0 ) {
    ++tx_vi->tx_outstanding;
  }
  else {
    assert(rc == -EAGAIN);
    /* TXQ is full.  A real app might consider implementing an overflow
     * queue in software.  We simply choose not to send.
     */
    pkt_buf_free(pkt_buf);
  }
}


static void handle_batched_rx(int rx_vi_i, int pkt_buf_i)
{
  void* dma_ptr = (char*) pkt_buf_from_id(pkt_buf_i) + RX_DMA_OFF
    + addr_offset_from_id(pkt_buf_i);
  uint16_t len;
  TRY( ef_vi_receive_get_bytes(&vis[rx_vi_i].vi, dma_ptr ,&len) );

  handle_rx(rx_vi_i, pkt_buf_i, len);
}


static void handle_rx_discard(int pkt_buf_i, int discard_type)
{
  struct pkt_buf* pkt_buf = pkt_buf_from_id(pkt_buf_i);
  pkt_buf_free(pkt_buf);
}


static void complete_tx(int vi_i, int pkt_buf_i)
{
  struct pkt_buf* pkt_buf = pkt_buf_from_id(pkt_buf_i);
  pkt_buf_free(pkt_buf);
}


/* The main loop.  Poll each VI handling various types of events and
 * then try to refill them. */
static void main_loop(void)
{
  int i, j, k;

  while( 1 ) {
    for( i = 0; i < 2; ++i ) {
      ef_vi* vi = &vis[i].vi;

      if( vis[i].tx_outstanding ) {
        ef_vi_transmit_push(vi);
        vis[i].tx_outstanding = 0;
      }

      ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
      int n_ev = ef_eventq_poll(vi, evs, sizeof(evs) / sizeof(evs[0]));

      for( j = 0; j < n_ev; ++j ) {
        switch( EF_EVENT_TYPE(evs[j]) ) {
        case EF_EVENT_TYPE_RX:
          /* This code does not handle jumbos. */
          assert(EF_EVENT_RX_SOP(evs[j]) != 0);
          assert(EF_EVENT_RX_CONT(evs[j]) == 0);
          handle_rx(i, EF_EVENT_RX_RQ_ID(evs[j]),
                    EF_EVENT_RX_BYTES(evs[j]) -
                    ef_vi_receive_prefix_len(vi));
          break;
        case EF_EVENT_TYPE_RX_MULTI: {
          ef_request_id ids[EF_VI_RECEIVE_BATCH];
          TEST( EF_EVENT_RX_MULTI_SOP(evs[j])
                && ! EF_EVENT_RX_MULTI_CONT(evs[j]) );
          assert( cfg_rx_merge );
          int n_rx = ef_vi_receive_unbundle(vi, &evs[j], ids);
          for( k = 0; k < n_rx; ++k )
            handle_batched_rx(i, ids[k]);
          break;
        }
        case EF_EVENT_TYPE_TX: {
          ef_request_id ids[EF_VI_TRANSMIT_BATCH];
          int ntx = ef_vi_transmit_unbundle(vi, &evs[j], ids);
          for( k = 0; k < ntx; ++k )
            complete_tx(i, ids[k]);
          break;
        }
        case EF_EVENT_TYPE_RX_DISCARD:
          handle_rx_discard(EF_EVENT_RX_DISCARD_RQ_ID(evs[j]),
                            EF_EVENT_RX_DISCARD_TYPE(evs[j]));
          break;
        case EF_EVENT_TYPE_RX_MULTI_DISCARD: {
          ef_request_id ids[EF_VI_RECEIVE_BATCH];
          TEST( EF_EVENT_RX_MULTI_SOP(evs[j])
                && ! EF_EVENT_RX_MULTI_CONT(evs[j]) );
          assert( cfg_rx_merge );
          int n_rx = ef_vi_receive_unbundle(vi, &evs[j], ids);
          for( k = 0; k < n_rx; ++k )
            handle_rx_discard(ids[k],EF_EVENT_RX_MULTI_DISCARD_TYPE(evs[j]));
          break;
        }
        default:
          LOGE("ERROR: unexpected event %d\n", (int) EF_EVENT_TYPE(evs[j]));
          break;
        }
      }

      vi_refill_rx_ring(i);
    }
  }
}


/* Print approx packet rate every second. */
static void* monitor_fn(void* dummy)
{
  struct timeval start, end;
  int prev_pkts[2], now_pkts[2];
  int pkt_rates[2];
  int ms, i;

  /* The thread name is limited to 15 characters so abbreviate. */
  pthread_setname_np(pthread_self(), "efforward_mon");

  for( i = 0; i < 2; ++i )
    prev_pkts[i] = vis[i].n_pkts;
  gettimeofday(&start, NULL);

  printf("  vi0-rx\t  vi1-rx\n");
  while( 1 ) {
    sleep(1);
    for( i = 0; i < 2; ++i )
      now_pkts[i] = vis[i].n_pkts;
    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;

    for( i = 0; i < 2; ++i )
      pkt_rates[i] = (int64_t)(now_pkts[i] - prev_pkts[i]) * 1000 / ms;
    printf("%8d\t%8d\n", pkt_rates[0], pkt_rates[1]);
    fflush(stdout);
    for( i = 0; i < 2; ++i )
      prev_pkts[i] = now_pkts[i];
    start = end;
  }
  return NULL;
}


/* Allocate and initialize the packet buffers. */
static int init_pkts_memory(void)
{
  int i;

  /* Number of buffers is the worst case to fill up TX and RX queues.
   * For bi-directional forwarding need buffers for both VIs */
  pbs.num = RX_RING_SIZE + TX_RING_SIZE;
  if( ! cfg_unidirectional )
    pbs.num = 2 * pbs.num;
  pbs.mem_size = pbs.num * PKT_BUF_SIZE;
  pbs.mem_size = ROUND_UP(pbs.mem_size, huge_page_size);

  /* Allocate memory for DMA transfers. Try mmap() with MAP_HUGETLB to get huge
   * pages. If that fails, fall back to posix_memalign() and hope that we do
   * get them. */
  pbs.mem = mmap(NULL, pbs.mem_size, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
  if( pbs.mem == MAP_FAILED ) {
    fprintf(stderr, "mmap() failed. Are huge pages configured?\n");

    /* Allocate huge-page-aligned memory to give best chance of allocating
     * transparent huge-pages.
     */
    TEST(posix_memalign(&pbs.mem, huge_page_size, pbs.mem_size) == 0);
  }

  for( i = 0; i < pbs.num; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(i);
    pkt_buf->id = i;
    pkt_buf_free(pkt_buf);
  }
  return 0;
}


/* Allocate and initialize a VI. */
static int init(const char* intf, int vi_i)
{
  struct vi* vi = &vis[vi_i];
  int i;
  unsigned vi_flags = EF_VI_FLAGS_DEFAULT;

  TRY(ef_driver_open(&vi->dh));
  /* check that RX merge is supported */
  if( cfg_rx_merge ) {
    unsigned long value;
    int ifindex = if_nametoindex(intf);
    TEST(ifindex > 0);
    int rc = ef_vi_capabilities_get(vi->dh, ifindex, EF_VI_CAP_RX_MERGE, &value);
    if( rc < 0 || ! value ) {
      fprintf(stderr, "WARNING: RX merge not supported on %s. Use '-c' "
              "option instead.\n", intf);
      exit(EXIT_FAILURE);
    }
    else {
      vi_flags |= EF_VI_RX_EVENT_MERGE;
    }
  }
  TRY(ef_pd_alloc_by_name(&vi->pd, vi->dh, intf, EF_PD_DEFAULT));
  TRY(ef_vi_alloc_from_pd(&vi->vi, vi->dh, &vi->pd, vi->dh, -1, RX_RING_SIZE,
                          TX_RING_SIZE, NULL, -1, vi_flags));


  /* Memory for pkt buffers has already been allocated.  Map it into
   * the VI. */
  TRY(ef_memreg_alloc(&vi->memreg, vi->dh, &vi->pd, vi->dh,
                      pbs.mem, pbs.mem_size));
  for( i = 0; i < pbs.num; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(i);
    pkt_buf->rx_ef_addr[vi_i] =
      ef_memreg_dma_addr(&vi->memreg, i * PKT_BUF_SIZE) + RX_DMA_OFF
      + addr_offset_from_id(i);
    pkt_buf->tx_ef_addr[vi_i] =
      ef_memreg_dma_addr(&vi->memreg, i * PKT_BUF_SIZE) + RX_DMA_OFF +
      ef_vi_receive_prefix_len(&vi->vi) + addr_offset_from_id(i);
  }

  /* Our pkt buffer allocation function makes assumptions on queue sizes */
  assert(ef_vi_receive_capacity(&vi->vi) == RX_RING_SIZE - 1);
  assert(ef_vi_transmit_capacity(&vi->vi) == TX_RING_SIZE - 1);

  if( cfg_unidirectional && vi_i == 1 )
    return 0; /* only need filter and RX fill for ingress VI */

  while( ef_vi_receive_space(&vi->vi) > REFILL_BATCH_SIZE )
    vi_refill_rx_ring(vi_i);

  ef_filter_spec fs;
  ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
  TRY(ef_filter_spec_set_unicast_all(&fs));
  TRY(ef_vi_filter_add(&vi->vi, vi->dh, &fs, NULL));
  ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
  TRY(ef_filter_spec_set_multicast_all(&fs));
  TRY(ef_vi_filter_add(&vi->vi, vi->dh, &fs, NULL));
  return 0;
}


static __attribute__ ((__noreturn__)) void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efforward <intf0> <intf1>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -c       use cut-though RX mode (default is RX merge"
          " / batched mode)\n");
  fprintf(stderr, "  -u       unidirectional - only forward from <intf0> to"
          " <intf1>\n");
  fprintf(stderr, "  -n       don't output per-second stats\n");

  exit(1);
}


int main(int argc, char* argv[])
{
  pthread_t thread_id;
  int c;

  while( (c = getopt(argc, argv, "cnu")) != -1 )
    switch( c ) {
    case 'c':
      cfg_rx_merge = 0;
      break;
    case 'u':
      cfg_unidirectional = 1;
      break;
    case 'n':
      cfg_stats = 0;
      break;
    case '?':
      usage();
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc != 2 )
    usage();

  TRY(init_pkts_memory());
  TRY(init(argv[0], 0));
  TRY(init(argv[1], 1));

  if( cfg_stats )
    TEST(pthread_create(&thread_id, NULL, monitor_fn, NULL) == 0);
  main_loop();

  return 0;
}
