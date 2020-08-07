/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2019 Xilinx, Inc. */
#include "rtt.h"

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/pio.h>
#include <etherfabric/memreg.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/checksum.h>

#include <stdbool.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#define BUF_SIZE    2048
#define N_TX_ALT    2


struct pkt_buf {
  ef_addr           dma_addr;
  uint8_t           payload[1] EF_VI_ALIGN(EF_VI_DMA_ALIGN);
};


struct tx_alt {
  bool                 busy;
};


struct vi {
  ef_driver_handle     dh;
  ef_vi		       vi;
  ef_pd                pd;
  ef_memreg            memreg;
  ef_pio               pio;
  uint8_t*             bufs;
  unsigned             num_bufs;
  unsigned             posted;
  unsigned             completed;
  unsigned             ctpio_ok;
  unsigned             ctpio_ok_total;
};


struct efvi_endpoint {
  struct rtt_endpoint  ep;
  bool                 mcast;
  unsigned             dirs;

  struct vi            tx_vi;
  struct vi            rx_vi;

  unsigned             rx_max_fill;

  void*                tx_buf;
  int                  tx_len;
  ef_addr              tx_dma_addr;
  union {
    struct {
      struct tx_alt    alt[N_TX_ALT];
      unsigned         prep;
      unsigned         send;
    } alt;
    struct {
      int              thresh;
      bool             nopoison;
    } ctpio;
  } tx;
};


#define PKT_BUF(vi, id)  ((struct pkt_buf*) ((vi)->bufs + (id) * BUF_SIZE))


#define EFVI_ENDPOINT(pep)                      \
  CONTAINER_OF(struct efvi_endpoint, ep, (pep))


static const char* local_ip = "192.168.0.1";
static const char* dest_ip_uc = "192.168.0.2";
static const char* dest_ip_mc = "224.1.2.3";
static int udp_port = 8080;


static const char* dest_ip(bool mcast)
{
  if( mcast )
    return dest_ip_mc;
  else
    return dest_ip_uc;
}


static void poll_tx_completions(struct vi* tx)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
  const int max_evs = sizeof(evs) / sizeof(evs[0]);
  int i, n;

  int n_ev = ef_eventq_poll(&(tx->vi), evs, max_evs);
  for( i = 0; i < n_ev; ++i )
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_TX:
      n = ef_vi_transmit_unbundle(&(tx->vi), &(evs[i]), ids);
      tx->completed += n;
      if( EF_EVENT_TX_CTPIO(evs[i]) )
        tx->ctpio_ok += n;
      break;
    default:
      RTT_TEST( 0 );
      break;
    }
}


static void efvi_ping_pio(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  RTT_TRY( ef_vi_transmit_copy_pio(&(eep->tx_vi.vi), 0,
                                   eep->tx_buf, eep->tx_len, 0) );
  poll_tx_completions(&(eep->tx_vi));
  ++(eep->tx_vi.posted);
}


static void efvi_ping_pio_nc(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  RTT_TRY( ef_vi_transmit_pio(&(eep->tx_vi.vi), 0, eep->tx_len, 0) );
  poll_tx_completions(&(eep->tx_vi));
  ++(eep->tx_vi.posted);
}


static void efvi_ping_dma(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  RTT_TRY( ef_vi_transmit(&(eep->tx_vi.vi), eep->tx_dma_addr, eep->tx_len, 0) );
  poll_tx_completions(&(eep->tx_vi));
}


static void efvi_ping_ctpio(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  ef_vi_transmit_ctpio(&(eep->tx_vi.vi), eep->tx_buf, eep->tx_len,
                       eep->tx.ctpio.thresh);
  RTT_TRY(ef_vi_transmit_ctpio_fallback(&(eep->tx_vi.vi), eep->tx_dma_addr,
                                        eep->tx_len, 0));
  poll_tx_completions(&(eep->tx_vi));
}


static int poll_tx_alt_completions(struct vi* tx)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
  const int max_evs = sizeof(evs) / sizeof(evs[0]);
  int n_completions = 0;
  int i;

  int n_ev = ef_eventq_poll(&(tx->vi), evs, max_evs);
  for( i = 0; i < n_ev; ++i )
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_TX_ALT:
      /* Indicates packet transmitted via TX-alt. */
      ++n_completions;
      break;
    case EF_EVENT_TYPE_TX:
      /* Indicates completion of packet fetches. */
      ef_vi_transmit_unbundle(&(tx->vi), &(evs[i]), ids);
      break;
    default:
      fprintf(stderr, "%s: ERROR: unexpected event type %d\n",
              __func__, (int) EF_EVENT_TYPE(evs[i]));
      RTT_TEST( 0 );
      break;
    }

  return n_completions;
}


static void efvi_ping_alt(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);

  unsigned alt_id = (eep->tx.alt.send)++ % N_TX_ALT;
  struct tx_alt* alt = &(eep->tx.alt.alt[alt_id]);
  RTT_TRY( ef_vi_transmit_alt_go(&(eep->tx_vi.vi), alt_id) );
  RTT_TEST( ! alt->busy );
  alt->busy = true;

  alt_id = (eep->tx.alt.prep)++ % N_TX_ALT;
  alt = &(eep->tx.alt.alt[alt_id]);
  if( alt->busy ) {
    int i, rc;
    do
      rc = poll_tx_alt_completions(&(eep->tx_vi));
    while( rc == 0 );
    RTT_TEST( rc <= N_TX_ALT );
    for( i = 0; i < rc; ++i )
      eep->tx.alt.alt[(alt_id + i) % N_TX_ALT].busy = false;
  }

  RTT_TEST( ! alt->busy );
  RTT_TRY( ef_vi_transmit_alt_stop(&(eep->tx_vi.vi), alt_id) );
  if( N_TX_ALT > 1 )
    RTT_TRY( ef_vi_transmit_alt_select(&(eep->tx_vi.vi), alt_id) );
  RTT_TRY( ef_vi_transmit(&(eep->tx_vi.vi), eep->tx_dma_addr, eep->tx_len, 1) );
}


static void efvi_pong(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  struct vi* rx = &(eep->rx_vi);
  ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
  const int max_evs = sizeof(evs) / sizeof(evs[0]);
  int n_ev, i;

  if( rx->posted - rx->completed < rx->num_bufs ) {
    struct pkt_buf* pb = PKT_BUF(rx, rx->posted % rx->num_bufs);
    RTT_TRY( ef_vi_receive_post(&(rx->vi), pb->dma_addr, rx->posted) );
    ++(rx->posted);
  }

  bool seen_rx_ev = false;
  do {
    n_ev = ef_eventq_poll(&(rx->vi), evs, max_evs);
    for( i = 0; i < n_ev; ++i )
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_RX:
        ++(rx->completed);
        seen_rx_ev = true;
        break;
      case EF_EVENT_TYPE_RX_DISCARD:
        if( EF_EVENT_RX_DISCARD_TYPE(evs[i]) == EF_EVENT_RX_DISCARD_CRC_BAD ) {
          /* Likely this is a poisoned frame due to CTPIO underrun.
           * (NB. We can't test for CTPIO being used here, as it is the
           * configuration of the other end that matters).
           */
          ++(rx->completed);
          struct pkt_buf* pb = PKT_BUF(rx, rx->posted % rx->num_bufs);
          RTT_TRY( ef_vi_receive_post(&(rx->vi), pb->dma_addr, rx->posted) );
          ++(rx->posted);
        }
        else {
          fprintf(stderr, "%s: ERROR: unexpected RX_DISCARD type=%d\n",
                  __func__, (int) EF_EVENT_RX_DISCARD_TYPE(evs[i]));
          RTT_TEST( 0 );
        }
        break;
      default:
        fprintf(stderr, "%s: ERROR: unexpected event type=%d\n",
                __func__, (int) EF_EVENT_TYPE(evs[i]));
        RTT_TEST( 0 );
        break;
      }
  } while( ! seen_rx_ev );
}


static void init_packet(void* buf, size_t frame_len, bool mcast)
{
  uint8_t shost[] = { 0x02, 0xff, 0x01, 0x02, 0x03, 0x04 };
  uint8_t dhost_mc[] = { 0x01, 0x00, 0x5e, 0x01, 0x02, 0x03 };
  uint8_t dhost_bc[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  uint8_t* dhost = mcast ? dhost_mc : dhost_bc;

  ssize_t ip_len = frame_len - sizeof(struct ether_header);

  struct ether_header* eth = buf;
  struct iphdr* ip = (void*) (eth + 1);
  struct udphdr* udp = (void*) (ip + 1);

  memcpy(eth->ether_dhost, dhost, 6);
  memcpy(eth->ether_shost, shost, 6);
  eth->ether_type = htons(ETHERTYPE_IP);

  ip->ihl = sizeof(*ip) >> 2;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len = htons(ip_len);
  ip->id = 0;
  ip->frag_off = htons(IP_DF);
  ip->ttl = 1;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = inet_addr(local_ip);
  ip->daddr = inet_addr(dest_ip(mcast));
  ip->check = ef_ip_checksum(ip);

  udp->source = htons(udp_port);
  udp->dest = htons(udp_port);
  udp->len = htons(ip_len - (ip->ihl << 2));
  struct iovec iov = {udp + 1, ntohs(udp->len)};
  udp->check = ef_udp_checksum(ip, udp, &iov, 1);
}


static size_t read_packet_from_file(void* buf, char const* path)
{
  size_t size;
  FILE*  file;

  /* Open the file. */
  file = fopen(path, "rb");
  RTT_TEST( file != NULL );

  /* Check that the file is small enough to fit into buf. */
  fseek(file, 0, SEEK_END);
  size = ftell(file);
  if( size > BUF_SIZE ) {
    rtt_err("ERROR: %s is too big to send as a single packet.\n", path);
    rtt_err("The provided file's size is %zu.\n", size);
    rtt_err("The maximum supported file size is %i.\n", BUF_SIZE);
    fclose(file);
    RTT_TEST(0);
  }
  rewind(file);

  /* Read the file into memory. */
  fread(buf, 1, BUF_SIZE, file);
  if( ! feof(file) ) {
    rtt_err("ERROR: Failed to read entire file.\n");
    rtt_err("Bad byte at position %li\n", ftell(file));
    fclose(file);
    RTT_TEST(0);
  }
  fclose(file);
  return size;
}


static void init_vi(struct vi* vi, const char* interface,
                    unsigned n_bufs, bool for_tx, bool tx_alt, bool tx_pio,
                    bool tx_ctpio, bool nopoison)
{
  vi->posted = 0;
  vi->completed = 0;
  vi->ctpio_ok = 0;
  vi->ctpio_ok_total = 0;

  unsigned vi_flags = 0;
  if( tx_ctpio ) {
    vi_flags |= EF_VI_TX_CTPIO;
    if( nopoison )
      vi_flags |= EF_VI_TX_CTPIO_NO_POISON;
  }
  if( tx_alt )
    vi_flags |= EF_VI_TX_ALT;

  RTT_TRY( ef_driver_open(&(vi->dh)) );
  RTT_TRY( ef_pd_alloc_by_name(&(vi->pd), vi->dh, interface, 0) );
  RTT_TRY( ef_vi_alloc_from_pd(&(vi->vi), vi->dh, &(vi->pd), vi->dh,
                               -1, for_tx ? 0 : -1, for_tx ? -1 : 0,
                               NULL, -1, vi_flags) );
  if( tx_pio ) {
    #if EF_VI_CONFIG_PIO
      RTT_TRY( ef_pio_alloc(&(vi->pio), vi->dh, &(vi->pd), -1, vi->dh) );
      RTT_TRY( ef_pio_link_vi(&(vi->pio), vi->dh, &(vi->vi), vi->dh) );
    #else
      fprintf(stderr, "PIO not available on this CPU type\n");
      RTT_TEST( 0 );
    #endif
  }
  if( tx_alt )
    RTT_TRY( ef_vi_transmit_alt_alloc(&(vi->vi), vi->dh,
                                      N_TX_ALT, N_TX_ALT * BUF_SIZE) );

  size_t bytes = n_bufs * BUF_SIZE;
  void* p;
  RTT_TEST( posix_memalign(&p, 4096, bytes) == 0 );
  RTT_TRY( ef_memreg_alloc(&(vi->memreg), vi->dh, &vi->pd, vi->dh, p, bytes) );
  vi->bufs = p;
  vi->num_bufs = n_bufs;
  unsigned i;
  for( i = 0; i < n_bufs; ++i ) {
    struct pkt_buf* pb = PKT_BUF(vi, i);
    pb->dma_addr = ef_memreg_dma_addr(&(vi->memreg), pb->payload - vi->bufs);
  }
}


static void efvi_cleanup(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  if( eep->ep.ping == efvi_ping_alt ) {
    unsigned alt_id = (eep->tx.alt.send)++ % N_TX_ALT;
    RTT_TRY( ef_vi_transmit_alt_discard(&(eep->tx_vi.vi), alt_id) );
  }
}


static void efvi_reset_stats(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  eep->tx_vi.ctpio_ok_total += eep->tx_vi.ctpio_ok;
  eep->tx_vi.ctpio_ok = 0;
}


static void efvi_dump_info(struct rtt_endpoint* ep, FILE* f)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  const char* dir_s;
  if( eep->dirs == (RTT_DIR_RX | RTT_DIR_TX) )
    dir_s = "bi";
  else if( eep->dirs & RTT_DIR_RX )
    dir_s = "rx";
  else
    dir_s = "tx";
  if( eep->dirs & RTT_DIR_RX )
    fprintf(f, "# efvi_rx_max_fill: %u\n", eep->rx_max_fill);
  if( eep->ep.ping == efvi_ping_ctpio ) {
    fprintf(f, "# efvi_%s_ctpio_ok: %u\n", dir_s, eep->tx_vi.ctpio_ok);
    fprintf(f, "# efvi_%s_ctpio_ok_inc_warms: %u\n",
            dir_s, eep->tx_vi.ctpio_ok_total + eep->tx_vi.ctpio_ok);
  }
}


static void vi_filter_udp_full(struct vi* vi, bool mcast)
{
  ef_filter_spec fs;
  ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
  RTT_TRY( ef_filter_spec_set_ip4_full(&fs, IPPROTO_UDP,
                                    inet_addr(dest_ip(mcast)), htons(udp_port),
                                    inet_addr(local_ip), htons(udp_port)) );
  RTT_TRY( ef_vi_filter_add(&(vi->vi), vi->dh, &fs, NULL) );
}


/* Install a destination MAC address filter that accepts all VLANs. */
static void vi_filter_mac_dest(struct vi* vi, unsigned char* mac)
{
  ef_filter_spec fs;
  ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
  RTT_TRY( ef_filter_spec_set_eth_local(&fs, EF_FILTER_VLAN_ID_ANY, mac) );
  RTT_TRY( ef_vi_filter_add(&(vi->vi), vi->dh, &fs, NULL) );
}


/* Read in the destination MAC address and add a filter for it. */
static void vi_filter_packet_by_mac_dest(struct vi* vi, char const* path)
{
  unsigned char packet_buf[BUF_SIZE];
  read_packet_from_file(packet_buf, path);
  struct ether_header* eth = (struct ether_header*)packet_buf;
  vi_filter_mac_dest(vi, eth->ether_dhost);
}


static void rx_fill(struct vi* rx)
{
  unsigned i;
  for( i = 0; i < rx->num_bufs; ++i ) {
    struct pkt_buf* pb = PKT_BUF(rx, i);
    RTT_TRY( ef_vi_receive_post(&(rx->vi), pb->dma_addr, rx->posted) );
    ++rx->posted;
  }
}


bool match_prefix(const char* str, const char* prefix,
                  const char** suffix_out_opt)
{
  size_t prefix_len = strlen(prefix);
  if( strncmp(str, prefix, prefix_len) == 0 ) {
    if( suffix_out_opt != NULL )
      *suffix_out_opt = str + prefix_len;
    return true;
  }
  return false;
}


int rtt_efvi_build_endpoint(struct rtt_endpoint** ep_out,
                            const struct rtt_options* opts, unsigned dirs,
                            const char** args, int n_args)
{
  bool tx_pio = false, tx_alt = false, tx_ctpio = false;
  const char* interface = NULL;
  const char* file_path = NULL;
  unsigned u;
  char dummy;

  struct efvi_endpoint* eep = calloc(1, sizeof(*eep));
  eep->mcast = 0;
  eep->dirs = dirs;
  eep->ep.cleanup = efvi_cleanup;
  eep->ep.reset_stats = efvi_reset_stats;
  eep->ep.dump_info = efvi_dump_info;
  eep->rx_max_fill = 504;

  int arg_i;
  for( arg_i = 0; arg_i < n_args; ++arg_i ) {
    const char* arg = args[arg_i];
    if( ! strcmp(arg, "help") ) {
      fprintf(stdout, "  intf=INTERFACE       - Ethernet interface name\n");
      fprintf(stdout, "  file=FILE_PATH       - file path of binary frame\n");
      fprintf(stdout, "  tx=dma               - DMA transmit\n");
      fprintf(stdout, "  tx=ctpio             - CTPIO transmit\n");
      fprintf(stdout, "    ctpio_nopoison=1   - disallow poisoned frames\n");
      fprintf(stdout, "    ctpio_thresh=BYTES - set cut-through threshold\n");
      fprintf(stdout, "  tx=pio               - PIO transmit\n");
      fprintf(stdout, "  tx=pio_nc            - PIO transmit with pre-copy\n");
      fprintf(stdout, "  tx=alt               - TX alternatives\n");
      fprintf(stdout, "  mc                   - multicast IP\n");
      fprintf(stdout, "  rx_max_fill=N        - max fill level for Rx ring\n");
      exit(0);
    }
    else if( ! strcmp(arg, "tx=pio_nc") ) {
      eep->ep.ping = efvi_ping_pio_nc;
      tx_pio = true;
    }
    else if( ! strcmp(arg, "tx=pio") ) {
      eep->ep.ping = efvi_ping_pio;
      tx_pio = true;
    }
    else if( ! strcmp(arg, "tx=dma") ) {
      eep->ep.ping = efvi_ping_dma;
    }
    else if( ! strcmp(arg, "tx=alt") ) {
      eep->ep.ping = efvi_ping_alt;
      tx_alt = true;
    }
    else if( ! strcmp(arg, "tx=ctpio") ) {
      eep->ep.ping = efvi_ping_ctpio;
      tx_ctpio = true;
    }
    else if( sscanf(arg, "ctpio_nopoison=%u%c", &u, &dummy) == 1 ) {
      RTT_TEST( tx_ctpio );
      RTT_TEST( eep->tx.ctpio.thresh == 0 );
      eep->tx.ctpio.nopoison = !!u;
    }
    else if( sscanf(arg, "ctpio_thresh=%u%c", &u, &dummy) == 1 ) {
      RTT_TEST( tx_ctpio );
      RTT_TEST( ! eep->tx.ctpio.nopoison );
      eep->tx.ctpio.thresh = u;
    }
    else if( ! strcmp(arg, "mc") ) {
      eep->mcast = true;
    }
    else if( match_prefix(arg, "intf=", &interface) ) {
    }
    else if( match_prefix(arg, "file=", &file_path) ) {
    }
    else if( sscanf(arg, "rx_max_fill=%u%c", &u, &dummy) == 1 ||
             /* old name also accepted for compatibility */
             sscanf(arg, "n_rx_bufs=%u%c", &u, &dummy) == 1 ) {
      eep->rx_max_fill = u;
    }
    else {
      return rtt_err("ERROR: bad arg: %s\n", arg);
    }
  }

  if( interface == NULL )
    return rtt_err("ERROR: no intf= given for efvi:\n");
  if( tx_ctpio && eep->tx.ctpio.thresh == 0 )
    eep->tx.ctpio.thresh = EF_VI_CTPIO_CT_THRESHOLD_SNF;

  if( dirs & RTT_DIR_RX ) {
    eep->ep.pong = efvi_pong;
    init_vi(&(eep->rx_vi), interface, eep->rx_max_fill, false, false,
            false, false, false);
    if( file_path != NULL )
      vi_filter_packet_by_mac_dest(&(eep->rx_vi), file_path);
    else
      vi_filter_udp_full(&(eep->rx_vi), eep->mcast);

    rx_fill(&(eep->rx_vi));
  }

  if( dirs & RTT_DIR_TX ) {
    if( eep->ep.ping == NULL )
      return rtt_err("ERROR: TX mode not given (eg. tx=dma)\n");
    init_vi(&(eep->tx_vi), interface, 1, true, tx_alt, tx_pio, tx_ctpio,
            (tx_ctpio) ? eep->tx.ctpio.nopoison : false);

    struct pkt_buf* tx_buf = PKT_BUF(&(eep->tx_vi), 0);
    eep->tx_buf = tx_buf->payload;
    eep->tx_dma_addr = tx_buf->dma_addr;
    if( file_path != NULL ) {
      eep->tx_len = read_packet_from_file(eep->tx_buf, file_path);
    }
    else {
      eep->tx_len = opts->ping_frame_len;
      init_packet(eep->tx_buf, eep->tx_len, eep->mcast);
    }
    if( tx_pio )
      RTT_TRY( ef_pio_memcpy(&(eep->tx_vi.vi), eep->tx_buf, 0, eep->tx_len) );
  }

  if( tx_alt ) {
    int i;
    for( i = 0; i < N_TX_ALT; ++i ) {
      struct tx_alt* alt = &(eep->tx.alt.alt[i]);
      alt->busy = false;
    }
    RTT_TRY( ef_vi_transmit_alt_select(&(eep->tx_vi.vi), 0) );
    RTT_TRY( ef_vi_transmit_alt_stop(&(eep->tx_vi.vi), 0) );
    RTT_TRY( ef_vi_transmit(&(eep->tx_vi.vi), eep->tx_dma_addr,
                            eep->tx_len, 13) );
    eep->tx.alt.send = 0;
    eep->tx.alt.prep = 1;
  }

  *ep_out = &(eep->ep);
  return 0;
}
