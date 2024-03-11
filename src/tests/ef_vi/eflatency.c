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
#include <etherfabric/efct_vi.h>
#include <ci/tools.h>
#include <ci/tools/ipcsum_base.h>
#include <ci/tools/ippacket.h>

#include <stdarg.h>
#include <stddef.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <limits.h>


/* Forward declarations. */
struct eflatency_vi;
static inline void rx_wait_no_ts(struct eflatency_vi*);
static inline void rx_wait_with_ts(struct eflatency_vi*);


#define DEFAULT_PAYLOAD_SIZE  0


static int              cfg_iter = 100000;
static int              cfg_warmups = 10000;
static int              cfg_payload_len = DEFAULT_PAYLOAD_SIZE;
static int              cfg_payload_end = DEFAULT_PAYLOAD_SIZE;
static int              cfg_payload_step = 1;
static int              cfg_ctpio_no_poison;
static unsigned         cfg_ctpio_thresh = 64;
static const char*      cfg_save_file = NULL;
enum mode {
  MODE_DMA = 1,
  MODE_PIO = 2,
  MODE_ALT = 4,
  MODE_CTPIO = 8,
  MODE_DEFAULT = MODE_CTPIO | MODE_ALT | MODE_PIO | MODE_DMA
};
static unsigned         cfg_mode = MODE_DEFAULT;
static enum ef_vi_flags cfg_vi_flags = 0;


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

struct eflatency_vi {
  ef_vi     vi;
  int       n_ev;
  int       i;
  ef_event  evs[EF_VI_EVENT_POLL_MIN_EVS];
  ef_pd     pd;
  ef_memreg memreg;
};

static ef_driver_handle  driver_handle;
static struct eflatency_vi rx_vi, tx_vi;

struct pkt_buf*          pkt_bufs[N_BUFS];
static ef_pio            pio;
static int               tx_frame_len;
static uint64_t*         timings;
static double            last_mean_latency_usec;


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
  ef_vi_get_mac(&rx_vi.vi, driver_handle, eth->ether_shost);
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


static int cmp_u64(const void* ap, const void* bp)
{
  uint64_t a = *(const uint64_t*)ap;
  uint64_t b = *(const uint64_t*)bp;
  if (a < b)
    return -1;
  return a > b;
}


static void output_results(struct timeval start, struct timeval end)
{
  unsigned freq = 0;
  double div;
  int usec = (end.tv_sec - start.tv_sec) * 1000000;
  usec += end.tv_usec - start.tv_usec;

  ci_get_cpu_khz(&freq);
  div = freq / 1e3;
  if( cfg_save_file ) {
    int i;
    char* subst = strstr(cfg_save_file, "$s");
    FILE* fp;

    if( subst ) {
      size_t ix = subst - cfg_save_file;
      size_t len = strlen(cfg_save_file);
      char* path = malloc(len + 12);
      memcpy(path, cfg_save_file, ix);
      snprintf(path + ix, 12, "%d", cfg_payload_len);
      memcpy(path + strlen(path), cfg_save_file + ix + 2, len - ix - 1);
      fp = fopen(path, "wt");
      free(path);
    }
    else {
      fp = fopen(cfg_save_file, "wt");
    }
    TEST(fp != NULL);
    for( i = 0 ; i < cfg_iter; ++i )
      fprintf(fp, "%lld\n", (long long)(timings[i] * 1000. / div));
    fclose(fp);
  }

  qsort(timings, cfg_iter, sizeof(timings[0]), cmp_u64);
  printf("%d\t%0.3lf\t%0.3lf\t%0.3lf\t%0.3lf\t%0.3lf\t%0.3lf\n",
         cfg_payload_len,
         (double) usec / cfg_iter,
         timings[0] / div,
         timings[cfg_iter / 2] / div,
         timings[cfg_iter - cfg_iter / 20] / div,
         timings[cfg_iter - cfg_iter / 100] / div,
         timings[cfg_iter - 1] / div);
  last_mean_latency_usec = (double) usec / cfg_iter;
}

/**********************************************************************/


typedef struct {
  const char* name;
  void (*init)(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi);
  void (*ping)(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi);
  void (*pong)(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi);
  void (*cleanup)(ef_vi* rx_vi, ef_vi* tx_vi);
} test_t;

static void
generic_desc_check(struct eflatency_vi* vi, int wait);

static void
generic_ping(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi,
             void (*rx_wait)(struct eflatency_vi*),
             void (*tx_send)(struct eflatency_vi*))
{
  struct timeval start, end;
  int i;
  int do_rx_post = ( rx_vi->vi.nic_type.arch != EF_VI_ARCH_EFCT );

  for( i = 0; i < cfg_warmups; ++i ) {
    tx_send(tx_vi);
    if( do_rx_post )
      rx_post(&rx_vi->vi);
    rx_wait(rx_vi);
   generic_desc_check(tx_vi, 0);
  }

  gettimeofday(&start, NULL);

  for( i = 0; i < cfg_iter; ++i ) {
    uint64_t start = ci_frc64_get();
    tx_send(tx_vi);
    if( do_rx_post )
      rx_post(&rx_vi->vi);
    rx_wait(rx_vi);
    uint64_t stop = ci_frc64_get();
    timings[i] = stop - start;
    generic_desc_check(tx_vi, 0);
  }

  gettimeofday(&end, NULL);
  output_results(start, end);
}



static void
generic_pong(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi,
             void (*rx_wait)(struct eflatency_vi*),
             void (*tx_send)(struct eflatency_vi*))
{
  int i;
  int do_rx_post = ( rx_vi->vi.nic_type.arch != EF_VI_ARCH_EFCT );

  for( i = 0; i < cfg_warmups + cfg_iter; ++i ) {
    rx_wait(rx_vi);
    tx_send(tx_vi);
    if( do_rx_post )
      rx_post(&rx_vi->vi);
  }
}

static void handle_rx_ref(ef_vi* vi, unsigned pkt_id, int len)
{
  efct_vi_rxpkt_release(vi, pkt_id);
}

/*
 * DMA
 */

static inline void dma_send(struct eflatency_vi* vi)
{
  struct pkt_buf* pb = pkt_bufs[FIRST_TX_BUF];
  TRY(ef_vi_transmit(&vi->vi, pb->dma_buf_addr, tx_frame_len, 0));
}

static void dma_ping(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi)
{
  generic_ping(rx_vi, tx_vi, rx_wait_no_ts, dma_send);
}

static void dma_pong(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi)
{
  generic_pong(rx_vi, tx_vi, rx_wait_no_ts, dma_send);
}

static const test_t dma_test = {
  .name = "DMA",
  .ping = dma_ping,
  .pong = dma_pong,
  .cleanup = NULL,
};


/*
 * PIO
 */

static inline void pio_send(struct eflatency_vi* vi)
{
  TRY(ef_vi_transmit_pio(&vi->vi, 0, tx_frame_len, 0));
}

static void pio_init(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi)
{
  TRY(ef_pio_memcpy(&tx_vi->vi, pkt_bufs[FIRST_TX_BUF]->dma_buf, 0,
                    tx_frame_len));
}

static void pio_ping(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi)
{
  generic_ping(rx_vi, tx_vi, rx_wait_no_ts, pio_send);
}

static void pio_pong(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi)
{
  generic_pong(rx_vi, tx_vi, rx_wait_no_ts, pio_send);
}

static const test_t pio_test = {
  .name = "PIO",
  .init = pio_init,
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

static inline void alt_fill(struct eflatency_vi* vi)
{
  TRY(ef_vi_transmit_alt_stop(&vi->vi, tx_alt.send_id & TX_ALT_MASK));
  if( N_TX_ALT > 1 )
    TRY(ef_vi_transmit_alt_select(&vi->vi, tx_alt.send_id & TX_ALT_MASK));
  dma_send(vi);
}

static inline void alt_go(ef_vi* vi)
{
  TRY(ef_vi_transmit_alt_go(vi, tx_alt.send_id++ & TX_ALT_MASK));
}

static void alt_init(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi)
{
  /* Check that the packet will fit in the available buffer space. */
  struct ef_vi_transmit_alt_overhead overhead;
  TRY(ef_vi_transmit_alt_query_overhead(&tx_vi->vi, &overhead));
  int pkt_bytes = ef_vi_transmit_alt_usage(&overhead, tx_frame_len);
  TEST(pkt_bytes <= BUF_SIZE);
  /* Pre-fill the first packet. */
  alt_fill(tx_vi);
}

static inline void alt_discard(ef_vi* rx_vi, ef_vi* vi)
{
  TRY(ef_vi_transmit_alt_discard(vi, tx_alt.send_id & TX_ALT_MASK));
  TRY(ef_vi_transmit_alt_free(vi, driver_handle));
}

static inline void alt_send(struct eflatency_vi* vi)
{
  alt_assert_state_validity();

  /* Release the previously-posted packet onto the wire. */
  alt_go(&vi->vi);

  /* Pre-fill the next packet. */
  alt_fill(vi);
}

static void alt_ping(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi)
{
  generic_ping(rx_vi, tx_vi, rx_wait_with_ts, alt_send);
}

static void alt_pong(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi)
{
  generic_pong(rx_vi, tx_vi, rx_wait_with_ts, alt_send);
}

static const test_t alt_test = {
  .name = "Alternatives",
  .init = alt_init,
  .ping = alt_ping,
  .pong = alt_pong,
  /* Flush the alternative before freeing it. */
  .cleanup = alt_discard,
};



/*
 * CTPIO
 */

static inline void ctpio_send(struct eflatency_vi* vi)
{
  /* TODO: May be desirable to compute cut-through threshold from frame
   * length.
   */
  struct pkt_buf* pb = pkt_bufs[FIRST_TX_BUF];
  ef_vi_transmit_ctpio(&vi->vi, pb->dma_buf, tx_frame_len, cfg_ctpio_thresh);
  for( ; ; ) {
    int rc = ef_vi_transmit_ctpio_fallback(&vi->vi, pb->dma_buf_addr, tx_frame_len, 0);
    if( rc != -EAGAIN ) {
      TRY(rc);
      break;
    }
    generic_desc_check(vi, 0);
  }
}

static void ctpio_ping(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi)
{
  generic_ping(rx_vi, tx_vi, rx_wait_no_ts, ctpio_send);
}

static void ctpio_pong(struct eflatency_vi* rx_vi, struct eflatency_vi* tx_vi)
{
  generic_pong(rx_vi, tx_vi, rx_wait_no_ts, ctpio_send);
}

static const test_t ctpio_test = {
  .name = "CTPIO",
  .ping = ctpio_ping,
  .pong = ctpio_pong,
  .cleanup = NULL,
};

static const test_t x3_ctpio_test = {
  .name = "X3 CTPIO",
  .ping = ctpio_ping,
  .pong = ctpio_pong,
  .cleanup = NULL,
};



/**********************************************************************/

static void
generic_desc_check(struct eflatency_vi* vi, int wait)
{
  /* We might exit with events read but unprocessed. */
  int i = vi->i;
  int n_ev = vi->n_ev;
  ef_event* evs = vi->evs;
  int n_rx;
  ef_request_id   tx_ids[EF_VI_TRANSMIT_BATCH];
  ef_request_id   rx_ids[EF_VI_RECEIVE_BATCH];

  while( 1 ) {
    for( ; i < n_ev; vi->i = ++i )
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_RX:
        vi->i = ++i;
        return;
      case EF_EVENT_TYPE_RX_REF:
        handle_rx_ref(&vi->vi, evs[i].rx_ref.pkt_id, evs[i].rx_ref.len);
        vi->i = ++i;
        return;
      case EF_EVENT_TYPE_TX:
        ef_vi_transmit_unbundle(&vi->vi, &(evs[i]), tx_ids);
        break;
      case EF_EVENT_TYPE_TX_ALT:
        ++(tx_alt.complete_id);
        break;
      case EF_EVENT_TYPE_RX_MULTI:
      case EF_EVENT_TYPE_RX_MULTI_DISCARD:
        n_rx = ef_vi_receive_unbundle(&vi->vi, &(evs[i]), rx_ids);
        TEST(n_rx == 1);
        vi->i = ++i;
        return;
      case EF_EVENT_TYPE_RX_MULTI_PKTS:
        n_rx = evs[i].rx_multi_pkts.n_pkts;
        TEST(n_rx == 1);
        ef_vi_rxq_next_desc_id(&vi->vi);
        vi->i = ++i;
        return;
      case EF_EVENT_TYPE_RX_REF_DISCARD:
        handle_rx_ref(&vi->vi, evs[i].rx_ref_discard.pkt_id,
                      evs[i].rx_ref_discard.len);
        if( evs[i].rx_ref_discard.flags & EF_VI_DISCARD_RX_ETH_FCS_ERR &&
            cfg_ctpio_thresh < tx_frame_len ) {
          break;
        }
        fprintf(stderr, "ERROR: unexpected ref discard flags=%x\n",
                evs[i].rx_ref_discard.flags);
        TEST(0);
        break;
      case EF_EVENT_TYPE_RX_DISCARD:
        if( EF_EVENT_RX_DISCARD_TYPE(evs[i]) == EF_EVENT_RX_DISCARD_CRC_BAD &&
            (ef_vi_flags(&vi->vi) & EF_VI_TX_CTPIO) && ! cfg_ctpio_no_poison ) {
          /* Likely a poisoned frame caused by underrun.  A good copy will
           * follow.
           */
          rx_post(&vi->vi);
          break;
        }
        ci_fallthrough;
      default:
        fprintf(stderr, "ERROR: unexpected event "EF_EVENT_FMT"\n",
                EF_EVENT_PRI_ARG(evs[i]));
        TEST(0);
        break;
      }
    vi->n_ev = n_ev = ef_eventq_poll(&vi->vi, evs,
                                     sizeof(vi->evs) / sizeof(vi->evs[0]));
    vi->i = i = 0;
    if( ! n_ev && ! wait )
      break;
  }
}

static void
generic_rx_wait(struct eflatency_vi* vi)
{
  generic_desc_check(vi, 1);
}

static inline void rx_wait_no_ts(struct eflatency_vi* vi)
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

static inline void rx_wait_with_ts(struct eflatency_vi* vi)
{
  generic_rx_wait(vi);
}

/**********************************************************************/

static const test_t* do_init(int ifindex, int mode,
                             struct eflatency_vi* latency_vi, void* pkt_mem,
                             size_t pkt_mem_bytes)
{
  ef_vi* vi = &latency_vi->vi;
  enum ef_pd_flags pd_flags = 0;
  ef_filter_spec filter_spec;
  enum ef_vi_flags vi_flags = cfg_vi_flags;
  int rc;
  const test_t* t;
  unsigned long capability_val;

  TRY(ef_pd_alloc(&latency_vi->pd, driver_handle, ifindex, pd_flags));

  if( cfg_ctpio_no_poison )
    vi_flags |= EF_VI_TX_CTPIO_NO_POISON;

  /* Try with CTPIO first. */
  if( mode & MODE_CTPIO &&
      ef_vi_capabilities_get(driver_handle, ifindex, EF_VI_CAP_CTPIO,
                             &capability_val) == 0 && capability_val ) {
    vi_flags |= EF_VI_TX_CTPIO;
    if( ef_vi_alloc_from_pd(vi, driver_handle, &latency_vi->pd, driver_handle,
                            -1, -1, -1, NULL, -1, vi_flags) == 0 )
        goto got_vi;
    fprintf(stderr, "Failed to allocate VI with CTPIO.\n");
    vi_flags &= ~(EF_VI_TX_CTPIO | EF_VI_TX_CTPIO_NO_POISON);
  }

  /* Try with TX alternatives if CTPIO failed. */
  if( mode & MODE_ALT &&
      ef_vi_capabilities_get(driver_handle, ifindex, EF_VI_CAP_TX_ALTERNATIVES,
                             &capability_val) == 0 && capability_val ) {
    vi_flags |= EF_VI_TX_ALT;
    if( ef_vi_alloc_from_pd(vi, driver_handle, &latency_vi->pd, driver_handle,
                            -1, -1, -1, NULL, -1, vi_flags) == 0 ) {
      if( ef_vi_transmit_alt_alloc(vi, driver_handle,
                                   N_TX_ALT, N_TX_ALT * BUF_SIZE) == 0 ) 
        goto got_vi;
      ef_vi_free(vi, driver_handle);
    }
    fprintf(stderr, "Failed to allocate VI with TX alternatives.\n");
    vi_flags &=~ EF_VI_TX_ALT;
  }

  if( (rc = ef_vi_alloc_from_pd(vi, driver_handle, &latency_vi->pd,
                                driver_handle, -1, -1, -1, NULL, -1,
                                vi_flags)) < 0 ) {
    if( rc == -EPERM ) {
      fprintf(stderr, "Failed to allocate VI without event merging\n");
      vi_flags |= EF_VI_RX_EVENT_MERGE;
      TRY( ef_vi_alloc_from_pd(vi, driver_handle, &latency_vi->pd,
                               driver_handle, -1, -1, -1, NULL, -1,
                               vi_flags) );
    }
    else
      TRY( rc );
  }

 got_vi:
  if( latency_vi == &rx_vi ) {
    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_EXCLUSIVE_RXQ);
    TRY(ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_UDP, htonl(raddr_he),
                                    htons(port_he)));
    TRY(ef_vi_filter_add(vi, driver_handle, &filter_spec, NULL));
  }

  TRY(ef_memreg_alloc(&latency_vi->memreg, driver_handle, &latency_vi->pd,
                      driver_handle, pkt_mem,
                      CI_ROUND_UP(pkt_mem_bytes, 4096)));

  /* Build the UDP packet inside the DMA buffer.  As well as being used for
   * straightforward DMA sends, it will also be used to fill alternatives, and
   * as a source buffer to populate the PIO region. */
  init_udp_pkt(pkt_bufs[FIRST_TX_BUF]->dma_buf, cfg_payload_len);
  tx_frame_len = cfg_payload_len + HEADER_SIZE;

  /* Other modes don't work with X3 */
  if ( vi->nic_type.arch == EF_VI_ARCH_EFCT ) {
    t = &x3_ctpio_test;
  }
  /* First, try CTPIO. */
  else if ( vi_flags & EF_VI_TX_CTPIO ) {
    t = &ctpio_test;
  }
  /* Next, try to allocate alternatives. */
  else if( vi_flags & EF_VI_TX_ALT ) {
    t = &alt_test;
  }
  /* If we couldn't allocate an alternative, try PIO. */
  else if( cfg_mode & MODE_PIO &&
           ef_pio_alloc(&pio, driver_handle, &latency_vi->pd, -1,
                        driver_handle) == 0 ) {
    TRY(ef_pio_link_vi(&pio, driver_handle, vi, driver_handle));
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

static void prepare(ef_vi* vi)
{
  int i;
  if( vi->nic_type.arch != EF_VI_ARCH_EFCT ) {
    /* Ensure we leave space to allow ping/pong to unconditionally post a
     * buffer, which they do at the start of their loop.
     */
    for( i = 0; i < N_RX_BUFS && ef_vi_receive_space(vi) > 1; ++i )
      rx_post(vi);
  }
}


static CI_NORETURN usage(const char* fmt, ...)
{
  if( fmt ) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "\n");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
  }
  fprintf(stderr, "\nusage:\n");
  fprintf(stderr, "  eflatency [options] <ping|pong> <interface> [<tx_interface>]\n");
  fprintf(stderr, "\noptions:\n");
  fprintf(stderr, "  -n <iterations>     - set number of iterations\n");
  fprintf(stderr, "  -s <message-size>   - set udp payload size. Accepts Python slices\n");
  fprintf(stderr, "  -w <iterations>     - set number of warmup iterations\n");
  fprintf(stderr, "  -c <cut-through>    - CTPIO cut-through threshold\n");
  fprintf(stderr, "  -p                  - CTPIO no-poison mode\n");
  fprintf(stderr, "  -m <modes>          - allow mode of the set: [c]tpio, \n");
  fprintf(stderr, "                        [p]io, [a]lternatives, [d]ma\n");
  fprintf(stderr, "  -t <modes>          - set TX_PUSH: [a]lways, [d]isable\n");
  fprintf(stderr, "  -o <filename>       - save raw timings to file\n");
  fprintf(stderr, "\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  int rx_ifindex = -1 , tx_ifindex = -1;
  int c;
  bool ping = false;
  const test_t* t;
  int iters_run = 0;
  struct eflatency_vi* tx_vi_ptr;
  unsigned long rx_min_page_size;
  unsigned long min_page_size;
  void* pkt_mem;
  int pkt_mem_bytes;
  int i;

  printf("# ef_vi_version_str: %s\n", ef_vi_version_str());

  #define OPT_INT(s, p) do {                                 \
    long __v;                                                \
    if( ! parse_long(s, INT_MIN, INT_MAX, &__v) ) {          \
      usage("Unable to parse '%s': %s", s, strerror(errno)); \
    }                                                        \
    p = (int)__v;                                            \
  } while( 0 );

  #define OPT_UINT(s, p) do {                                \
    long __v;                                                \
    if( ! parse_long(s, 0, INT_MAX, &__v) ) {                \
      usage("Unable to parse '%s': %s", s, strerror(errno)); \
    }                                                        \
    p = (unsigned int)__v;                                   \
  } while( 0 );

  while( (c = getopt (argc, argv, "n:s:w:c:pm:t:o:")) != -1 )
    switch( c ) {
    case 'n':
      OPT_INT(optarg, cfg_iter);
      break;
    case 's': {
      char* colon;
      OPT_INT(optarg, cfg_payload_len);
      colon = strchr(optarg, ':');
      if( colon ) {
        OPT_INT(colon + 1, cfg_payload_end);
        colon = strchr(colon + 1, ':');
        if( colon )
          OPT_INT(colon + 1, cfg_payload_step);
      } else {
        cfg_payload_end = cfg_payload_len;
      }
      break;
    }
    case 'w':
      OPT_INT(optarg, cfg_warmups);
      break;
    case 'c':
      OPT_UINT(optarg, cfg_ctpio_thresh);
      break;
    case 'p':
      cfg_ctpio_no_poison = 1;
      break;
    case 'o':
      cfg_save_file = optarg;
      break;
    case 'm':
      cfg_mode = 0;
      for( i = 0; i < strlen(optarg); ++i ) {
        switch( optarg[i] ) {
        case 'c': cfg_mode |= MODE_CTPIO; break;
        case 'a': cfg_mode |= MODE_ALT; break;
        case 'p': cfg_mode |= MODE_PIO; break;
        case 'd': cfg_mode |= MODE_DMA; break;
        default:
          usage("Unknown mode '%c'", optarg[i]);
        }
      }
      break;
    case 't':
      for( i = 0; i < strlen(optarg); ++i ) {
        switch( optarg[i] ) {
        case 'a': cfg_vi_flags |= EF_VI_TX_PUSH_ALWAYS; break;
        case 'd': cfg_vi_flags |= EF_VI_TX_PUSH_DISABLE; break;
        default:
          usage("Unknown mode '%c'", optarg[i]);
        }
      }
      break;
    case '?':
      usage(NULL);
    default:
      TEST(0);
    }

  #undef OPT_INT
  #undef OPT_UINT

  argc -= optind;
  argv += optind;

  if( argc != 2 && argc != 3 )
    usage(NULL);
  if( ! parse_interface(argv[1], &rx_ifindex) )
    usage("Unable to parse RX interface '%s': %s", argv[1], strerror(errno));

  if( argc == 3 && ! parse_interface(argv[2], &tx_ifindex) )
    usage("Unable to parse TX interface '%s': %s", argv[2], strerror(errno));

  if( cfg_payload_len > MAX_UDP_PAYLEN || cfg_payload_end > MAX_UDP_PAYLEN ) {
    fprintf(stderr, "WARNING: UDP payload length %d is larger than standard "
            "MTU\n", cfg_payload_len);
  }
  if( cfg_payload_step == 0 && cfg_payload_len != cfg_payload_end )
    usage("Please provide payload step");
  if( (cfg_payload_step < 0 && cfg_payload_end > cfg_payload_len) ||
      (cfg_payload_step > 0 && cfg_payload_end < cfg_payload_len) ) {
    usage("Max payload size not reachable from min");
  }

  if( strcmp(argv[0], "ping") == 0 )
    ping = true;
  else if( strcmp(argv[0], "pong") != 0 )
    usage("Unknown command '%s'", argv[0]);

  TRY(ef_driver_open(&driver_handle));
  TRY(ef_vi_capabilities_get(driver_handle, rx_ifindex,
                             EF_VI_CAP_MIN_BUFFER_MODE_SIZE, &rx_min_page_size));
  if( tx_ifindex < 0 ) {
    min_page_size = rx_min_page_size;
  }
  else {
    TRY(ef_vi_capabilities_get(driver_handle, tx_ifindex,
                               EF_VI_CAP_MIN_BUFFER_MODE_SIZE, &min_page_size));
    min_page_size = CI_MAX(rx_min_page_size, min_page_size);
  }

  pkt_mem_bytes = N_BUFS * BUF_SIZE;
  pkt_mem_bytes = CI_MAX(min_page_size, pkt_mem_bytes);
  if (min_page_size >= 2 * 1024 * 1024) {
    /* Assume this means huge pages are mandatory */
    pkt_mem = mmap(NULL, pkt_mem_bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    TEST(pkt_mem != MAP_FAILED);
  }
  else {
    TEST(posix_memalign(&pkt_mem, min_page_size, pkt_mem_bytes) == 0);
  }
  for( i = 0; i < N_BUFS; ++i ) {
    struct pkt_buf* pb = (void*) ((char*) pkt_mem + i * BUF_SIZE);
    pkt_bufs[i] = pb;
    pb->id = i;
  }

  /* Initialize a VI and configure it to operate with the lowest latency
   * possible.  The return value specifies the test that the application must
   * run to use the VI in its configured mode. */
  t = do_init(rx_ifindex, cfg_mode, &rx_vi, pkt_mem, pkt_mem_bytes);

  if( tx_ifindex < 0 ) {
    tx_vi_ptr = &rx_vi;
  } else {
    /* mode really selects tx method */
    t = do_init(tx_ifindex, cfg_mode, &tx_vi, pkt_mem, pkt_mem_bytes);
    tx_vi_ptr = &tx_vi;
  }

  for( i = 0; i < N_BUFS; ++i ) {
    struct pkt_buf* pb = (void*) ((char*) pkt_mem + i * BUF_SIZE);
    ef_memreg* memreg = i < N_RX_BUFS ? &rx_vi.memreg : &tx_vi_ptr->memreg;
    pb->dma_buf_addr = ef_memreg_dma_addr(memreg, i * BUF_SIZE);
    pb->dma_buf_addr += offsetof(struct pkt_buf, dma_buf);
  }

  prepare(&rx_vi.vi);

  if( ping ) {
    timings = mmap(NULL, cfg_iter * sizeof(timings[0]), PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  }

  printf("# NIC(s) %d %d\n", rx_ifindex, tx_ifindex);
  printf("# udp payload len: %d:%d:%d\n", cfg_payload_len, cfg_payload_end,
         cfg_payload_step);
  printf("# iterations: %d\n", cfg_iter);
  printf("# warmups: %d\n", cfg_warmups);
  printf("# frame len: %d\n", tx_frame_len);
  printf("# mode: %s\n", t->name);
  if( ping )
    printf("paylen\tmean\tmin\t50%%\t95%%\t99%%\tmax\n");

  for( ; ; ) {
    ++iters_run;
    if( t->init )
      t->init(&rx_vi, tx_vi_ptr);
    (ping ? t->ping : t->pong)(&rx_vi, tx_vi_ptr);
    if( t->cleanup != NULL )
      t->cleanup(&rx_vi.vi, &tx_vi_ptr->vi);
    cfg_payload_len += cfg_payload_step;
    if( cfg_payload_step < 0 ) {
      if( cfg_payload_len <= cfg_payload_end )
        break;
    }
    else if( cfg_payload_len >= cfg_payload_end )
      break;
    init_udp_pkt(pkt_bufs[FIRST_TX_BUF]->dma_buf, cfg_payload_len);
    tx_frame_len = cfg_payload_len + HEADER_SIZE;
  }
  if( ping && iters_run == 1 )
    printf("mean round-trip time: %.3lf usec\n", last_mean_latency_usec);

  return 0;
}

/*! \cidoxg_end */
