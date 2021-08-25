/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2020 Xilinx, Inc. */
/* eflatency
 *
 * Copyright 2016 Solarflare Communications Inc.
 * Date: 2016/05/06
 */

#include "utils.h"

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/pio.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>
#include <etherfabric/checksum.h>
#include <ci/tools.h>
#include <ci/tools/ipcsum_base.h>
#include <ci/tools/ippacket.h>

#include <stddef.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>


/* Forward declarations. */
static inline void rx_wait_no_ts(ef_vi*);
static inline void rx_wait_with_ts(ef_vi*);


#define DEFAULT_PAYLOAD_SIZE  0


static int              cfg_iter = 100000;
static int              cfg_warmups = 10000;
static unsigned		cfg_payload_len = DEFAULT_PAYLOAD_SIZE;
static int              cfg_ctpio_no_poison;
static unsigned         cfg_ctpio_thresh = 64;
enum mode {
  MODE_DMA = 1,
  MODE_PIO = 2,
  MODE_ALT = 4,
  MODE_CTPIO = 8,
  MODE_DEFAULT = MODE_CTPIO | MODE_ALT | MODE_PIO | MODE_DMA
};
static unsigned         cfg_mode = MODE_DEFAULT;


#define N_RX_BUFS	256u
#define N_TX_BUFS	1u
#define N_BUFS          (N_RX_BUFS + N_TX_BUFS)
#define FIRST_TX_BUF    N_RX_BUFS
#define BUF_SIZE        2048
#define MAX_UDP_PAYLEN	(1500 - sizeof(ci_ip4_hdr) - sizeof(ci_udp_hdr))
/* Protocol header length: Ethernet + IP + UDP. */
#define HEADER_SIZE     (14 + 20 + 8)


struct pkt_buf {
  struct pkt_buf* next;
  ef_addr         dma_buf_addr;
  int             id;
  unsigned        dma_buf[1] EF_VI_ALIGN(EF_VI_DMA_ALIGN);
};


static ef_driver_handle  driver_handle;
static ef_vi		 vi;

struct pkt_buf*          pkt_bufs[N_BUFS];
static ef_pd             pd;
static ef_memreg         memreg;
static ef_pio            pio;
static int               tx_frame_len;


/* The IP addresses can be chosen arbitrarily. */
const uint32_t laddr_he = 0xac108564;  /* 172.16.133.100 */
const uint32_t raddr_he = 0xac010203;  /* 172.1.2.3 */
const uint16_t port_he = 8080;


static void init_udp_pkt(void* pkt_buf, int paylen)
{
  int ip_len = sizeof(ci_ip4_hdr) + sizeof(ci_udp_hdr) + paylen;
  ci_ether_hdr* eth;
  ci_ip4_hdr* ip4;
  ci_udp_hdr* udp;
  struct iovec iov;

  /* Use a broadcast destination MAC to ensure that the packet is not dropped
   * by 5000- and 6000-series NICs. */
  const uint8_t remote_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  eth = (ci_ether_hdr*) pkt_buf;
  ip4 = (void*) ((char*) eth + 14);
  udp = (void*) (ip4 + 1);

  memcpy(eth->ether_dhost, remote_mac, sizeof(remote_mac));
  ef_vi_get_mac(&vi, driver_handle, eth->ether_shost);
  eth->ether_type = htons(0x0800);
  ci_ip4_hdr_init(ip4, CI_NO_OPTS, ip_len, 0, IPPROTO_UDP, htonl(laddr_he),
                  htonl(raddr_he), 0);
  ci_udp_hdr_init(udp, ip4, htons(port_he), htons(port_he), udp + 1, paylen, 0);

  iov.iov_base = udp + 1;
  iov.iov_len = paylen;
  ip4->ip_check_be16 = ef_ip_checksum((const struct iphdr*) ip4);
  udp->udp_check_be16 = ef_udp_checksum((const struct iphdr*) ip4,
                                        (const struct udphdr*) udp, &iov, 1);
}


static inline void rx_post(ef_vi* vi)
{
  static int rx_posted = 0;
  struct pkt_buf* pb = pkt_bufs[rx_posted++ & (N_RX_BUFS - 1)];
  TRY(ef_vi_receive_post(vi, pb->dma_buf_addr, pb->id));
}



/**********************************************************************/


typedef struct {
  const char* name;
  void (*ping)(ef_vi*);
  void (*pong)(ef_vi*);
  void (*cleanup)(ef_vi*);
} test_t;

static void
generic_ping(ef_vi* vi, void (*rx_wait)(ef_vi*), void (*tx_send)(ef_vi*))
{
  struct timeval start, end;
  int i, usec;

  for( i = 0; i < N_RX_BUFS; ++i )
    rx_post(vi);

  for( i = 0; i < cfg_warmups; ++i ) {
    tx_send(vi);
    rx_post(vi);
    rx_wait(vi);
  }

  gettimeofday(&start, NULL);

  for( i = 0; i < cfg_iter; ++i ) {
    tx_send(vi);
    rx_post(vi);
    rx_wait(vi);
  }

  gettimeofday(&end, NULL);

  usec = (end.tv_sec - start.tv_sec) * 1000000;
  usec += end.tv_usec - start.tv_usec;
  printf("mean round-trip time: %0.3f usec\n", (double) usec / cfg_iter);
}

static void
generic_pong(ef_vi* vi, void (*rx_wait)(ef_vi*), void (*tx_send)(ef_vi*))
{
  int i;

  for( i = 0; i < N_RX_BUFS; ++i )
    rx_post(vi);

  for( i = 0; i < cfg_warmups + cfg_iter; ++i ) {
    rx_wait(vi);
    tx_send(vi);
    rx_post(vi);
  }
}


/*
 * DMA
 */

static inline void dma_send(ef_vi* vi)
{
  struct pkt_buf* pb = pkt_bufs[FIRST_TX_BUF];
  TRY(ef_vi_transmit(vi, pb->dma_buf_addr, tx_frame_len, 0));
}

static void dma_ping(ef_vi* vi) { generic_ping(vi, rx_wait_no_ts, dma_send); }
static void dma_pong(ef_vi* vi) { generic_pong(vi, rx_wait_no_ts, dma_send); }

static const test_t dma_test = {
  .name = "DMA",
  .ping = dma_ping,
  .pong = dma_pong,
  .cleanup = NULL,
};


/*
 * PIO
 */

static inline void pio_send(ef_vi* vi)
{
  TRY(ef_vi_transmit_pio(vi, 0, tx_frame_len, 0));
}

static void pio_ping(ef_vi* vi) { generic_ping(vi, rx_wait_no_ts, pio_send); }
static void pio_pong(ef_vi* vi) { generic_pong(vi, rx_wait_no_ts, pio_send); }

static const test_t pio_test = {
  .name = "PIO",
  .ping = pio_ping,
  .pong = pio_pong,
  .cleanup = NULL,
};



/*
 * Alternatives
 */

#define N_TX_ALT       2
#define TX_ALT_MASK    (N_TX_ALT - 1)

struct {
  /* Track the alternatives that are awaiting completion and those that are
   * available for use. */
  uint32_t complete_id;
  uint32_t send_id;
} tx_alt;


static void alt_assert_state_validity(void)
{
  assert( tx_alt.complete_id - tx_alt.send_id <= INT32_MAX );
}

static inline void alt_fill(ef_vi* vi)
{
  TRY(ef_vi_transmit_alt_stop(vi, tx_alt.send_id & TX_ALT_MASK));
  if( N_TX_ALT > 1 )
    TRY(ef_vi_transmit_alt_select(vi, tx_alt.send_id & TX_ALT_MASK));
  dma_send(vi);
}

static inline void alt_go(ef_vi* vi)
{
  TRY(ef_vi_transmit_alt_go(vi, tx_alt.send_id++ & TX_ALT_MASK));
}

static inline void alt_discard(ef_vi* vi)
{
  TRY(ef_vi_transmit_alt_discard(vi, tx_alt.send_id & TX_ALT_MASK));
  TRY(ef_vi_transmit_alt_free(vi, driver_handle));
}

static inline void alt_send(ef_vi* vi)
{
  alt_assert_state_validity();

  /* Release the previously-posted packet onto the wire. */
  alt_go(vi);

  /* Pre-fill the next packet. */
  alt_fill(vi);
}

static void alt_ping(ef_vi* vi) { generic_ping(vi, rx_wait_with_ts, alt_send); }
static void alt_pong(ef_vi* vi) { generic_pong(vi, rx_wait_with_ts, alt_send); }

static const test_t alt_test = {
  .name = "Alternatives",
  .ping = alt_ping,
  .pong = alt_pong,
  /* Flush the alternative before freeing it. */
  .cleanup = alt_discard,
};



/*
 * CTPIO
 */

static inline void ctpio_send(ef_vi* vi)
{
  /* TODO: May be desirable to compute cut-through threshold from frame
   * length.
   */
  struct pkt_buf* pb = pkt_bufs[FIRST_TX_BUF];
  ef_vi_transmit_ctpio(vi, pb->dma_buf, tx_frame_len, cfg_ctpio_thresh);
  TRY(ef_vi_transmit_ctpio_fallback(vi, pb->dma_buf_addr, tx_frame_len, 0));
}

static void ctpio_ping(ef_vi* vi)
{
  generic_ping(vi, rx_wait_no_ts, ctpio_send);
}

static void ctpio_pong(ef_vi* vi)
{
  generic_pong(vi, rx_wait_no_ts, ctpio_send);
}

static const test_t ctpio_test = {
  .name = "CTPIO",
  .ping = ctpio_ping,
  .pong = ctpio_pong,
  .cleanup = NULL,
};



/**********************************************************************/

static void
generic_rx_wait(ef_vi* vi)
{
  /* We might exit with events read but unprocessed. */
  static int      n_ev = 0;
  static int      i = 0;
  static ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
  int n_rx;
  ef_request_id   tx_ids[EF_VI_TRANSMIT_BATCH];
  ef_request_id   rx_ids[EF_VI_RECEIVE_BATCH];

  while( 1 ) {
    for( ; i < n_ev; ++i )
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_RX:
        ++i;
        return;
      case EF_EVENT_TYPE_TX:
        ef_vi_transmit_unbundle(vi, &(evs[i]), tx_ids);
        break;
      case EF_EVENT_TYPE_TX_ALT:
        ++(tx_alt.complete_id);
        break;
      case EF_EVENT_TYPE_RX_MULTI:
      case EF_EVENT_TYPE_RX_MULTI_DISCARD:
        n_rx = ef_vi_receive_unbundle(vi, &(evs[i]), rx_ids);
        TEST(n_rx == 1);
        ++i;
        return;
      case EF_EVENT_TYPE_RX_DISCARD:
        if( EF_EVENT_RX_DISCARD_TYPE(evs[i]) == EF_EVENT_RX_DISCARD_CRC_BAD &&
            (ef_vi_flags(vi) & EF_VI_TX_CTPIO) && ! cfg_ctpio_no_poison ) {
          /* Likely a poisoned frame caused by underrun.  A good copy will
           * follow.
           */
          rx_post(vi);
          break;
        }
        /* Otherwise, fall through. */
      default:
        fprintf(stderr, "ERROR: unexpected event "EF_EVENT_FMT"\n",
                EF_EVENT_PRI_ARG(evs[i]));
        TEST(0);
        break;
      }
    n_ev = ef_eventq_poll((vi), evs, sizeof(evs) / sizeof(evs[0]));
    i = 0;
  }
}

static inline void rx_wait_no_ts(ef_vi* vi)
{
  generic_rx_wait(vi);
}

static inline int
tx_with_ts_handler(ef_vi* vi, const ef_event* ev, ef_request_id* ids)
{
  ++tx_alt.complete_id;
  alt_assert_state_validity();
  return 0;
}

static inline void rx_wait_with_ts(ef_vi* vi)
{
  generic_rx_wait(vi);
}

/**********************************************************************/

static const test_t* do_init(int ifindex)
{
  enum ef_pd_flags pd_flags = 0;
  ef_filter_spec filter_spec;
  enum ef_vi_flags vi_flags = 0;
  int i, rc;
  const test_t* t;
  unsigned long capability_val;

  TRY(ef_driver_open(&driver_handle));
  TRY(ef_pd_alloc(&pd, driver_handle, ifindex, pd_flags));

  if( cfg_ctpio_no_poison )
    vi_flags |= EF_VI_TX_CTPIO_NO_POISON;

  /* Try with CTPIO first. */
  if( cfg_mode & MODE_CTPIO &&
      ef_vi_capabilities_get(driver_handle, ifindex, EF_VI_CAP_CTPIO,
                             &capability_val) == 0 && capability_val ) {
    vi_flags |= EF_VI_TX_CTPIO;
    if( ef_vi_alloc_from_pd(&vi, driver_handle, &pd, driver_handle,
                            -1, -1, -1, NULL, -1, vi_flags) == 0 )
        goto got_vi;
    fprintf(stderr, "Failed to allocate VI with CTPIO.\n");
    vi_flags &= ~(EF_VI_TX_CTPIO | EF_VI_TX_CTPIO_NO_POISON);
  }

  /* Try with TX alternatives if CTPIO failed. */
  if( cfg_mode & MODE_ALT &&
      ef_vi_capabilities_get(driver_handle, ifindex, EF_VI_CAP_TX_ALTERNATIVES,
                             &capability_val) == 0 && capability_val ) {
    vi_flags |= EF_VI_TX_ALT;
    if( ef_vi_alloc_from_pd(&vi, driver_handle, &pd, driver_handle,
                            -1, -1, -1, NULL, -1, vi_flags) == 0 ) {
      if( ef_vi_transmit_alt_alloc(&vi, driver_handle,
                                   N_TX_ALT, N_TX_ALT * BUF_SIZE) == 0 ) 
        goto got_vi;
      ef_vi_free(&vi, driver_handle);
    }
    fprintf(stderr, "Failed to allocate VI with TX alternatives.\n");
    vi_flags &=~ EF_VI_TX_ALT;
  }

  if( (rc = ef_vi_alloc_from_pd(&vi, driver_handle, &pd, driver_handle, -1, -1, -1,
                                NULL, -1, vi_flags)) < 0 ) {
    if( rc == -EPERM ) {
      fprintf(stderr, "Failed to allocate VI without event merging\n");
      vi_flags |= EF_VI_RX_EVENT_MERGE;
      TRY( ef_vi_alloc_from_pd(&vi, driver_handle, &pd, driver_handle, -1, -1, -1,
                               NULL, -1, vi_flags) );
    }
    else
      TRY( rc );
  }

 got_vi:
  ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
  TRY(ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_UDP, htonl(raddr_he),
                                   htons(port_he)));
  TRY(ef_vi_filter_add(&vi, driver_handle, &filter_spec, NULL));

  {
    int bytes = N_BUFS * BUF_SIZE;
    void* p;
    TEST(posix_memalign(&p, 4096, bytes) == 0);

    TRY(ef_memreg_alloc(&memreg, driver_handle, &pd, driver_handle, p,
                        CI_ROUND_UP(bytes, 4096)));
    for( i = 0; i < N_BUFS; ++i ) {
      struct pkt_buf* pb = (void*) ((char*) p + i * BUF_SIZE);
      pkt_bufs[i] = pb;
      pb->dma_buf_addr = ef_memreg_dma_addr(&memreg, i * BUF_SIZE);
      pb->dma_buf_addr += offsetof(struct pkt_buf, dma_buf);
      pb->id = i;
    }
  }


  /* Build the UDP packet inside the DMA buffer.  As well as being used for
   * straightforward DMA sends, it will also be used to fill alternatives, and
   * as a source buffer to populate the PIO region. */
  init_udp_pkt(pkt_bufs[FIRST_TX_BUF]->dma_buf, cfg_payload_len);
  tx_frame_len = cfg_payload_len + HEADER_SIZE;

  /* First, try CTPIO. */
  if( vi_flags & EF_VI_TX_CTPIO ) {
    t = &ctpio_test;
  }
  /* Next, try to allocate alternatives. */
  else if( vi_flags & EF_VI_TX_ALT ) {
    /* Check that the packet will fit in the available buffer space. */
    struct ef_vi_transmit_alt_overhead overhead;
    TRY(ef_vi_transmit_alt_query_overhead(&vi, &overhead));
    int pkt_bytes = ef_vi_transmit_alt_usage(&overhead, tx_frame_len);
    TEST(pkt_bytes <= BUF_SIZE);
    /* Pre-fill the first packet. */
    alt_fill(&vi);
    t = &alt_test;
  }
  /* If we couldn't allocate an alternative, try PIO. */
  else if( cfg_mode & MODE_PIO &&
           ef_pio_alloc(&pio, driver_handle, &pd, -1, driver_handle) == 0 ) {
    TRY(ef_pio_link_vi(&pio, driver_handle, &vi, driver_handle));
    TRY(ef_pio_memcpy(&vi, pkt_bufs[FIRST_TX_BUF]->dma_buf, 0, tx_frame_len));
    t = &pio_test;
  }
  /* In the worst case, fall back to DMA sends. */
  else if( cfg_mode & MODE_DMA ) {
    t = &dma_test;
  }
  else {
    fprintf(stderr, "No compatible mode found\n");
    exit(1);
  }
  return t;
}


static CI_NORETURN usage(void)
{
  fprintf(stderr, "\nusage:\n");
  fprintf(stderr, "  eflatency [options] <ping|pong> <interface>\n");
  fprintf(stderr, "\noptions:\n");
  fprintf(stderr, "  -n <iterations>     - set number of iterations\n");
  fprintf(stderr, "  -s <message-size>   - set udp payload size\n");
  fprintf(stderr, "  -w <iterations>     - set number of warmup iterations\n");
  fprintf(stderr, "  -c <cut-through>    - CTPIO cut-through threshold\n");
  fprintf(stderr, "  -p                  - CTPIO no-poison mode\n");
  fprintf(stderr, "  -m <modes>          - allow mode of the set: [c]tpio, \n");
  fprintf(stderr, "                      [pio], [a]lternatives, [d]ma, [x]dp\n");
  fprintf(stderr, "\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  int ifindex;
  int c;
  bool ping = false;
  const test_t* t;

  printf("# ef_vi_version_str: %s\n", ef_vi_version_str());

  while( (c = getopt (argc, argv, "n:s:w:c:pm:")) != -1 )
    switch( c ) {
    case 'n':
      cfg_iter = atoi(optarg);
      break;
    case 's':
      cfg_payload_len = atoi(optarg);
      break;
    case 'w':
      cfg_warmups = atoi(optarg);
      break;
    case 'c':
      cfg_ctpio_thresh = atoi(optarg);
      break;
    case 'p':
      cfg_ctpio_no_poison = 1;
      break;
    case 'm':
      #define OPT_C(ch) (strchr(optarg, ch) != NULL)
      cfg_mode =
        OPT_C('c') * MODE_CTPIO |
        OPT_C('a') * MODE_ALT |
        OPT_C('p') * MODE_PIO |
        OPT_C('d') * MODE_DMA;
      #undef OPT_C
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
  if( ! parse_interface(argv[1], &ifindex) )
    usage();

  if( cfg_payload_len > MAX_UDP_PAYLEN ) {
    fprintf(stderr, "WARNING: UDP payload length %d is larger than standard "
            "MTU\n", cfg_payload_len);
  }

  if( strcmp(argv[0], "ping") == 0 )
    ping = true;
  else if( strcmp(argv[0], "pong") != 0 )
    usage();

  /* Initialize a VI and configure it to operate with the lowest latency
   * possible.  The return value specifies the test that the application must
   * run to use the VI in its configured mode. */
  t = do_init(ifindex);

  printf("# udp payload len: %d\n", cfg_payload_len);
  printf("# iterations: %d\n", cfg_iter);
  printf("# warmups: %d\n", cfg_warmups);
  printf("# frame len: %d\n", tx_frame_len);
  printf("# mode: %s\n", t->name);

  (ping ? t->ping : t->pong)(&vi);
  if( t->cleanup != NULL )
    t->cleanup(&vi);

  return 0;
}

/*! \cidoxg_end */
