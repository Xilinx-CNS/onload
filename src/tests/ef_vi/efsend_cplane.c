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

#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>

static int parse_opts(int argc, char* argv[], int *ifindex);


#define MAX_UDP_PAYLEN	(1500 - sizeof(ci_ip4_hdr) - sizeof(ci_udp_hdr))
#define N_BUFS          1
#define BUF_SIZE        4096
#define BUF_HUGE_SIZE   (2 * 1024 * 1024)
  /* Must be >= EF_VI_EVENT_POLL_MIN_EVS, but deliberately setting
   * larger to increase batching, and therefore throughput. */
#define EVENT_BATCH_SIZE 64


/* This gives a frame len of 70, which is the same as:
**   eth + ip + tcp + tso + 4 bytes payload
*/
#define DEFAULT_PAYLOAD_SIZE  28
#define LOCAL_PORT            12345

static ef_driver_handle      dh;
static struct sockaddr_in    sa_local = { 0 }, sa_dest = { 0 };
static char*                 cfg_interface = NULL;
static int                   cfg_local_port = LOCAL_PORT;
static int                   cfg_payload_len = DEFAULT_PAYLOAD_SIZE;
static int                   cfg_iter = 10;
static int                   cfg_usleep = 0;
static int                   cfg_loopback = 0;
static int                   cfg_phys_mode = 0;
static int                   cfg_disable_tx_push = 0;
static int                   cfg_use_vf = 0;
static int                   cfg_max_batch = 8192;
static int                   cfg_vlan = -1;
static int                   n_sent = 0;
static int                   n_pushed = 0;
static enum ef_pd_flags      pd_flags = EF_PD_DEFAULT;
static enum ef_vi_flags      vi_flags = EF_VI_FLAGS_DEFAULT;

struct intf_state {
  ef_vi vi;
  ef_pd pd;
  ef_memreg mr;
  ef_addr dma_buf_addr;
  int tx_frame_len;
};

struct pkt_buf {
  void *p;
  size_t size;
};

bool dest_is_mcast(void)
{
  return (ntohl(sa_dest.sin_addr.s_addr) & 0xf0000000) == 0xe0000000;
}

static void handle_completions(ef_vi* vi)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event      evs[EVENT_BATCH_SIZE];
  int           n_ev, i, n_unbundled = 0;

  n_ev = ef_eventq_poll(vi, evs, sizeof(evs) / sizeof(evs[0]));
  for( i = 0; i < n_ev; ++i ) {
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_TX:
      /* One TX event can signal completion of multiple TXs */
      n_unbundled = ef_vi_transmit_unbundle(vi, &evs[i], ids);
      n_sent += n_unbundled;
      break;
    default:
      TEST(!"Unexpected event received");
    }
  }
  /* No events yet is entirely acceptable */
}

static inline
int send_more_packets(int desired, struct intf_state *intf)
{
  int i, rc;
  int to_send = cfg_max_batch < desired ? cfg_max_batch : desired;

  /* This is sending the same packet buffer over and over again.
   * a real application would usually send new data. */
  for( i = 0; i < to_send; ++i ) {
    rc = ef_vi_transmit_init(&intf->vi, intf->dma_buf_addr, intf->tx_frame_len,
                             n_pushed + i);
    if( rc == -EAGAIN )
      break;
    TRY(rc);
  }

  if( i ) {
    /* Actually submit the packets to the NIC for transmission. */
    ef_vi_transmit_push(&intf->vi);
  }

  return i;
}

static void print_vi_stats(ef_vi *vi)
{
  printf("\ttxq_size=%d\n", ef_vi_transmit_capacity(vi));
  printf("\trxq_size=%d\n", ef_vi_receive_capacity(vi));
  printf("\tevq_size=%d\n", ef_eventq_capacity(vi));
  printf("\tsync_check_enabled=%d\n",
         (vi->vi_out_flags & EF_VI_OUT_CLOCK_SYNC_STATUS) != 0);
}

static void allocate_packet_buffer(struct pkt_buf *buf)
{
  /* Try using hugepages and fall back to normal allocation on failure */
  buf->size = BUF_HUGE_SIZE;
  buf->p = mmap(NULL, buf->size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
  if( buf->p == MAP_FAILED ) {
    buf->p = NULL;
    buf->size = BUF_SIZE;
    if( cfg_phys_mode )
      buf->size = CI_MAX(CI_PAGE_SIZE, buf->size);
    TEST(posix_memalign(&buf->p, CI_PAGE_SIZE, buf->size) == 0);
  }

  /* Populate the IP and UDP headers of the packet. */
  init_ip_udp_pkt((char*)buf->p + PREFIX_RESERVED, cfg_payload_len);
}

static void allocate_vi_memory(struct intf_state *intf, int ifindex,
                               struct pkt_buf *buf)
{
  unsigned long min_page_size;
  size_t alloc_size;

  TRY(ef_pd_alloc(&intf->pd, dh, ifindex, pd_flags));
  TRY(ef_vi_alloc_from_pd(&intf->vi, dh, &intf->pd, dh, -1, 0, -1, NULL, -1,
                          vi_flags));

  /* Make sure we have enough space, and fail with a message if not. */
  if (cfg_phys_mode)
    min_page_size = CI_PAGE_SIZE;
  else
    TRY(ef_vi_capabilities_get(dh, ifindex, EF_VI_CAP_MIN_BUFFER_MODE_SIZE,
                               &min_page_size));
  alloc_size = CI_MAX(min_page_size, BUF_SIZE);
  if( alloc_size > buf->size ) {
    printf("Interface %d requires a buffer of size %zu, but we were only able "
           "to allocate a block of size %zu.", ifindex, alloc_size, buf->size);
    TEST(alloc_size <= buf->size);
  }

  /* Register memory with NIC. The buffer size could become stale if we realloc
   * later, but because we only use the start of the buffer we should be ok */
  TRY(ef_memreg_alloc(&intf->mr, dh, &intf->pd, dh, buf->p, buf->size));
  /* Store DMA address of the packet buffer memory */
  intf->dma_buf_addr = ef_memreg_dma_addr(&intf->mr, 0);
}

static struct intf_state* register_intf(int ifindex, struct pkt_buf *buf)
{
  struct intf_state *intf;

  intf = calloc(1, sizeof(struct intf_state));
  TEST(intf != NULL);

  allocate_vi_memory(intf, ifindex, buf);
  print_vi_stats(&intf->vi);

  /* Populate the IP and UDP headers of the packet. */
  intf->tx_frame_len = init_udp_pkt(buf->p, cfg_payload_len, &intf->vi, dh,
                                    cfg_vlan, 1);

  return intf;
}

int main(int argc, char* argv[])
{
  struct intf_state *active_intf = NULL;
  struct pkt_buf pkt_buf = { 0 };
  int tx_ifindex = 0;

  TRY(parse_opts(argc, argv, &tx_ifindex));

  TRY(ef_driver_open(&dh));
  allocate_packet_buffer(&pkt_buf);
  active_intf = register_intf(tx_ifindex);

  /* Continue until all sends are complete */
  while( n_sent < cfg_iter ) {
    /* Try to push up to the requested iterations, likely fewer get sent */
    n_pushed += send_more_packets(cfg_iter - n_pushed, &active_intf->vi,
                                  active_intf->dma_buf_addr);
    /* Check for transmit complete */
    handle_completions(&active_intf->vi);
    if( cfg_usleep )
      usleep(cfg_usleep);
  }

  printf("Sent %d packets\n", n_sent);

  free(active_intf);
  if( pkt_buf.size == BUF_HUGE_SIZE )
    munmap(pkt_buf.p, pkt_buf.size);
  else
    free(pkt_buf.p);
  ef_cp_fini(cp);
  return 0;
}


/* Utilities */
void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efsend_cplane [options] <dest-ip> <dest-port>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "positionals:\n");
  fprintf(stderr, " <dest-ip>       destination ip address to send packets to\n");
  fprintf(stderr, " <dest-port>     destination port to send packets to\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -n <iterations>     - number of packets to send\n");
  fprintf(stderr, "  -m <message-size>   - set udp payload size\n");
  fprintf(stderr, "  -s <microseconds>   - time to sleep between sends\n");
  fprintf(stderr, "  -l <local-port>     - change local port to send from\n");
  fprintf(stderr, "  -i <interface>      - local interface to send over\n");
  fprintf(stderr, "  -b                  - enable loopback on the VI\n");
  fprintf(stderr, "  -p                  - enable physical address mode\n");
  fprintf(stderr, "  -t                  - disable tx push (on by default)\n");
  fprintf(stderr, "  -B                  - maximum send batch size\n");
  fprintf(stderr, "  -s                  - microseconds to sleep between batches\n");
  fprintf(stderr, "  -v                  - use a VF\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "e.g.:\n");
  fprintf(stderr, "  - Send pkts to 192.168.111.2:1234:\n"
                  "          efsend_cplane 192.168.111.2 1234\n");
  fprintf(stderr, "  - Send pkts to 239.1.2.3:1234 from bond0.1:\n"
                  "          efsend_cplane -i bond0.1 239.1.2.3 1234\n");
  exit(1);
}


static int parse_opts(int argc, char *argv[], int* ifindex)
{
  int c;
  const char *dest_ip;
  char* local_ip;
  int dest_port;

  while((c = getopt(argc, argv, "n:m:s:B:l:i:bptvx")) != -1)
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
    case 'i':
      cfg_interface = optarg;
      break;
    case 's':
      cfg_usleep = atoi(optarg);
      break;
    case 'B':
      cfg_max_batch = atoi(optarg);
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
    case '?':
      usage();
      break;
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;

  if( argc != 2 )
    usage();

  if( cfg_payload_len > MAX_UDP_PAYLEN ) {
    fprintf(stderr, "WARNING: UDP payload length %d is larger than standard "
            "MTU\n", cfg_payload_len);
  }

  /* Set flags for options requested on command line */
  if( cfg_use_vf )
    pd_flags |= EF_PD_VF;
  if( cfg_phys_mode )
    pd_flags |= EF_PD_PHYS_MODE;
  if( cfg_loopback )
    pd_flags |= EF_PD_MCAST_LOOP;
  if( cfg_disable_tx_push )
    vi_flags |= EF_VI_TX_PUSH_DISABLE;

  /* Parse arguments after options */
  dest_ip = (argv++)[0];
  dest_port = atoi(argv[0]);

  if (cfg_interface) {
    get_ipaddr_of_vlan_intf(cfg_interface, -1, &local_ip);

    if( ! parse_interface(cfg_interface, ifindex) ) {
      printf("ERROR: Failed to parse interface %s\n", cfg_interface);
      exit(1);
    }
  }

  /* We don't parse the IP as the route resolution should do this for us */
  sa_local.sin_port = htons(cfg_local_port);

  if ( ! parse_host(dest_ip, &sa_dest.sin_addr) ) {
    printf("ERROR: Failed to parse destination address %s\n", dest_ip);
    exit(1);
  }

  if (dest_is_mcast() && cfg_interface == NULL) {
    printf("ERROR: no interface specified to send to multicast address\n");
    exit(1);
  }

  sa_dest.sin_port = htons(dest_port);

  return 0;
}
