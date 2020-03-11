/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* efrss
 *
 * Receive packets on an interface spreading load over multiple VIs/threads.
 *
 * 2011 Solarflare Communications Inc.
 * Author: David Riddoch
 * Date: 2011/04/14
 */

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>

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


struct pkt_buf {
  /* I/O address corresponding to the start of this pkt_buf struct. */
  ef_addr            rx_ef_addr;

  /* pointer to where received packets start. */
  void*              rx_ptr;

  /* ID to associate with the pkt_buf */
  int                id;

  /* For building a linked list */
  struct pkt_buf*    next;
};

/* handle for accessing the driver */
static ef_driver_handle   dh;
/* protection domain */
static ef_pd              pd;
/* VI set */
static ef_vi_set          vi_set;

static pthread_cond_t  ready_cond  = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t ready_mutex = PTHREAD_MUTEX_INITIALIZER;
static int             ready_cnt;

static int cfg_hexdump;
static int cfg_loopback;

struct vi_state {
  /* virtual interface (rxq + evq) */
  ef_vi              vi;

  /* Memory for packet buffers */
  void*              mem;
  size_t             mem_size;

  /* registered memory for DMA */
  ef_memreg          memreg;

  /* Number of packet buffers allocated */
  int                num;

  /* pool of free packet buffers (LIFO to minimise working set) */
  struct pkt_buf*    free_pool;
  int                free_pool_n;

  /* statistics */
  uint64_t           n_pkts;
};

/* One per thread */
struct vi_state* vi_states;

/**********************************************************************/


/* Given a id to a packet buffer, look up the data structure.  The ids
 * are assigned in ascending order so this is simple to do. */
static inline struct pkt_buf* pkt_buf_from_id(struct vi_state* vi_state,
                                              int pkt_buf_i)
{
  assert((unsigned) pkt_buf_i < (unsigned) vi_state->num);
  return (void*) ((char*) vi_state->mem + (size_t) pkt_buf_i * PKT_BUF_SIZE);
}


/* Try to refill the RXQ on the given VI with at most
 * REFILL_BATCH_SIZE packets if it has enough space and we have
 * enough free buffers. */
static void vi_refill_rx_ring(struct vi_state* vi_state)
{
  ef_vi* vi = &vi_state->vi;
#define REFILL_BATCH_SIZE  16
  struct pkt_buf* pkt_buf;
  int i;

  if( ef_vi_receive_space(vi) < REFILL_BATCH_SIZE ||
      vi_state->free_pool_n < REFILL_BATCH_SIZE )
    return;

  for( i = 0; i < REFILL_BATCH_SIZE; ++i ) {
    pkt_buf = vi_state->free_pool;
    vi_state->free_pool = vi_state->free_pool->next;
    --vi_state->free_pool_n;
    ef_vi_receive_init(vi, pkt_buf->rx_ef_addr, pkt_buf->id);
  }
  ef_vi_receive_push(vi);
}


/* Free buffer into free pool in LIFO order to minimize cache footprint. */
static inline void pkt_buf_free(struct vi_state* vi_state,
                                struct pkt_buf* pkt_buf)
{
  pkt_buf->next = vi_state->free_pool;
  vi_state->free_pool = pkt_buf;
  ++vi_state->free_pool_n;
}


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


/* Handle an RX event on a VI. */
static void handle_rx(struct vi_state* vi_state, int pkt_buf_i, int len)
{
  struct pkt_buf* pkt_buf = pkt_buf_from_id(vi_state, pkt_buf_i);
  ++vi_state->n_pkts;
  if( cfg_hexdump )
    hexdump(pkt_buf->rx_ptr, len);
  pkt_buf_free(vi_state, pkt_buf);
}


static void handle_rx_discard(struct vi_state* vi_state, int pkt_buf_i,
                              int discard_type)
{
  struct pkt_buf* pkt_buf = pkt_buf_from_id(vi_state, pkt_buf_i);
  pkt_buf_free(vi_state, pkt_buf);
}


static void loop(struct vi_state* vi_state)
{
  ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
  ef_vi* vi = &vi_state->vi;
  int i;

  pthread_mutex_lock(&ready_mutex);
  ++ready_cnt;
  pthread_cond_signal(&ready_cond);
  pthread_mutex_unlock(&ready_mutex);

  while( 1 ) {
    int n_ev = ef_eventq_poll(vi, evs, sizeof(evs) / sizeof(evs[0]));
    for( i = 0; i < n_ev; ++i )
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_RX:
        /* This code does not handle jumbos. */
        assert(EF_EVENT_RX_SOP(evs[i]) != 0);
        assert(EF_EVENT_RX_CONT(evs[i]) == 0);
        handle_rx(vi_state, EF_EVENT_RX_RQ_ID(evs[i]),
                  EF_EVENT_RX_BYTES(evs[i]) - ef_vi_receive_prefix_len(vi));
        break;
      case EF_EVENT_TYPE_RX_DISCARD:
        handle_rx_discard(vi_state, EF_EVENT_RX_DISCARD_RQ_ID(evs[i]),
                          EF_EVENT_RX_DISCARD_TYPE(evs[i]));
        break;
      default:
        LOGE("ERROR: unexpected event %d\n", (int) EF_EVENT_TYPE(evs[i]));
        break;
      }
    vi_refill_rx_ring(vi_state);
  }
}


/* Allocate and initialize a VI. */
static int init_vi(struct vi_state* vi_state)
{
  int i;
  TRY(ef_vi_alloc_from_set(&vi_state->vi, dh, &vi_set, dh, -1, -1, -1, 0, NULL,
                          -1, EF_VI_FLAGS_DEFAULT));

  /* The VI has just an RXQ with default capacity of 512 */
  vi_state->num = 512;
  vi_state->mem_size = vi_state->num * PKT_BUF_SIZE;
  vi_state->mem_size = ROUND_UP(vi_state->mem_size, huge_page_size);
  /* Allocate huge-page-aligned memory to give best chance of allocating
   * transparent huge-pages.
   */
  TEST(posix_memalign(&vi_state->mem, huge_page_size, vi_state->mem_size) == 0);
  TRY(ef_memreg_alloc(&vi_state->memreg, dh, &pd, dh, vi_state->mem,
                      vi_state->mem_size));

  for( i = 0; i < vi_state->num; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(vi_state, i);
    pkt_buf->id = i;
    pkt_buf->rx_ef_addr =
      ef_memreg_dma_addr(&vi_state->memreg, i * PKT_BUF_SIZE) + RX_DMA_OFF;
    pkt_buf->rx_ptr = (char*) pkt_buf + RX_DMA_OFF +
      ef_vi_receive_prefix_len(&vi_state->vi);
    pkt_buf_free(vi_state, pkt_buf);
  }

  /* Our pkt buffer allocation function makes assumptions on queue sizes */
  assert(ef_vi_receive_capacity(&vi_state->vi) == 511);

  while( ef_vi_receive_space(&vi_state->vi) > REFILL_BATCH_SIZE )
    vi_refill_rx_ring(vi_state);

  return 0;
}


static void* thread_fn(void* arg)
{
  struct vi_state* vi_state = arg;
  init_vi(vi_state);
  loop(vi_state);
  return NULL;
}


static void monitor(int n_threads)
{
  struct timeval start, end;
  int* prev_pkts = calloc(n_threads, sizeof(*prev_pkts));
  int* now_pkts = calloc(n_threads, sizeof(*now_pkts));
  int* pkt_rates = calloc(n_threads, sizeof(*pkt_rates));
  int ms, i;

  for( i = 0; i < n_threads; ++i )
    prev_pkts[i] = vi_states[i].n_pkts;
  gettimeofday(&start, NULL);

  for( i = 0; i < n_threads; ++i )
    printf("vi%d-rx\t", i);
  printf("\n");
  while( 1 ) {
    sleep(1);
    for( i = 0; i < n_threads; ++i )
      now_pkts[i] = vi_states[i].n_pkts;
    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;

    for( i = 0; i < n_threads; ++i ) {
      pkt_rates[i] = (int64_t)(now_pkts[i] - prev_pkts[i]) * 1000 / ms;
      printf("%d\t", pkt_rates[i]);
    }
    printf("\n");
    fflush(stdout);
    for( i = 0; i < n_threads; ++i )
      prev_pkts[i] = now_pkts[i];
    start = end;
  }
}


/* Allocate and initialize the VI set from which we will allocate
 * VIs. */
static int init_vi_set(const char* intf, int n_threads)
{
  TRY(ef_driver_open(&dh));
  TRY(ef_pd_alloc_by_name(&pd, dh, intf, EF_PD_DEFAULT));
  TRY(ef_vi_set_alloc_from_pd(&vi_set, dh, &pd, dh, n_threads));
  return 0;
}


static int install_filters(void)
{
  ef_filter_spec fs;
  ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
  TRY(ef_filter_spec_set_unicast_all(&fs));
  TRY(ef_vi_set_filter_add(&vi_set, dh, &fs, NULL));
  ef_filter_spec_init(&fs, cfg_loopback ?
                      EF_FILTER_FLAG_MCAST_LOOP_RECEIVE :
                      EF_FILTER_FLAG_NONE);
  TRY(ef_filter_spec_set_multicast_all(&fs));
  TRY(ef_vi_set_filter_add(&vi_set, dh, &fs, NULL));
  return 0;
}


static __attribute__ ((__noreturn__)) void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efrss <num-threads> <intf>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -d     hexdump received packet\n");
  fprintf(stderr, "  -b     enable receive from mcast loopback\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  const char* intf;
  pthread_t thread;
  int i, n_threads;
  int c;

  while( (c = getopt(argc, argv, "db")) != -1 )
    switch( c ) {
    case 'd':
      cfg_hexdump = 1;
      break;
    case 'b':
      cfg_loopback = 1;
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
  n_threads = atoi(argv[0]);
  ++argv;
  --argc;
  intf = argv[0];

  TEST(vi_states = calloc(n_threads, sizeof(*vi_states)));
  TRY(init_vi_set(intf, n_threads));
  for( i = 0; i < n_threads; ++i )
    TRY(pthread_create(&thread, NULL, thread_fn, &vi_states[i]));

  /* Wait till workers have initialized before installing filters.
   * Installing filters too early can cause drops on the VI. */
  pthread_mutex_lock(&ready_mutex);
  while( ready_cnt != n_threads )
    pthread_cond_wait(&ready_cond, &ready_mutex);
  pthread_mutex_unlock(&ready_mutex);
  TRY(install_filters());

  monitor(n_threads);
  return 0;
}
