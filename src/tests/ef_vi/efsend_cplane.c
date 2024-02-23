/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */
/* efsend_cplane
 *
 * Sample app that sends UDP packets to a specified destination. This app is
 * based on the "efsend" app, with the addition of the cplane API. A key
 * feature of this API allows the user to resolve routes to find which
 * interface to send a packet over, including handling of logical interfaces
 * such as bonds and VLANs.
 *
 * Limitations of this sample app:
 * - Only supports traffic routing over interfaces with at least one physical
 *   interface below it, notably excluding loopback or an empty bond.
 * - Multicast data can only be sent if the interface to send it over is
 *   provided, as any interface could be valid as the sender.
 * - Route re-resolution can be quite noisy as the fwd data may change rapidly,
 *   leading to excess work done to free/init similar state.
 */

#include "utils.h"
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>
#include <etherfabric/checksum.h>
#include <ci/tools.h>
#include <ci/tools/ipcsum_base.h>
#include <ci/tools/ippacket.h>
#include <ci/net/ipv4.h>
#include <cplane/api.h>

static int parse_opts(int argc, char* argv[], int *ifindex);

#define PREFIX_RESERVED 64
#define HEADER_LEN      (PREFIX_RESERVED + sizeof(ci_ip4_hdr) + sizeof(ci_udp_hdr))
#define MAX_UDP_PAYLEN  (1500 - HEADER_LEN)
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
static int                   n_sent = 0;
static int                   n_pushed = 0;
static enum ef_pd_flags      pd_flags = EF_PD_DEFAULT;
static enum ef_vi_flags      vi_flags = EF_VI_FLAGS_DEFAULT;
static struct ef_cp_fwd_meta route_meta = { 0 };

struct intf_state {
  ef_vi vi;
  ef_pd pd;
  ef_memreg mr;
  ef_addr dma_buf_addr;
  ef_addr dma_start;
  int tx_frame_len;
  int ifindex;
  struct intf_state *next;
};

struct pkt_buf {
  void *p;
  size_t size;
};

bool dest_is_mcast(void)
{
  return (ntohl(sa_dest.sin_addr.s_addr) & 0xf0000000) == 0xe0000000;
}

void init_ip_udp_pkt(void* ip_pkt, int paylen)
{
  int ip_len = sizeof(ci_ip4_hdr) + sizeof(ci_udp_hdr) + paylen;
  ci_ip4_hdr* ip4;
  ci_udp_hdr* udp;

  ip4 = (void*) (ip_pkt);
  udp = (void*) (ip4 + 1);

  ci_ip4_hdr_init(ip4, CI_NO_OPTS, ip_len, 0, IPPROTO_UDP,
                  sa_local.sin_addr.s_addr, sa_dest.sin_addr.s_addr, 0);
  ci_udp_hdr_init(udp, ip4, sa_local.sin_port, sa_dest.sin_port, udp + 1,
                  paylen, 0);
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
    rc = ef_vi_transmit_init(&intf->vi, intf->dma_start, intf->tx_frame_len,
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

static struct intf_state* register_intf(struct ef_cp_handle *cp, int ifindex,
                                        struct pkt_buf *buf)
{
  struct intf_state *intf;
  struct ef_cp_intf port_cp_intf;

  TRY(ef_cp_get_intf(cp, ifindex, &port_cp_intf, 0));
  if( port_cp_intf.registered_cookie != NULL ) {
    /* We have registered this interface already, so just skip it. */
    return NULL;
  }

  intf = calloc(1, sizeof(struct intf_state));
  TEST(intf != NULL);
  intf->ifindex = ifindex;

  allocate_vi_memory(intf, ifindex, buf);
  TRY(ef_cp_register_intf(cp, ifindex, intf, 0));

  printf("%d %s:\n", ifindex, port_cp_intf.name);
  print_vi_stats(&intf->vi);

  return intf;
}

static struct intf_state* init_intfs(struct ef_cp_handle *cp,
                                     struct intf_state **intfs,
                                     int ifindex, struct pkt_buf *pkt_buf)
{
  struct ef_cp_intf cp_intf;
  struct intf_state *intf;
  int rc, i;
  /* Allocate space for a decent number of physical interfaces to avoid having
   * to reallocate the memory dynamically. */
  int n_physical_intfs = 8;
  int *physical_ifindices;
  int flags = EF_CP_GET_INTFS_F_NATIVE | EF_CP_GET_INTFS_F_MOST_DERIVED |
              EF_CP_GET_INTFS_F_UP_ONLY;

  TRY(ef_cp_get_intf(cp, ifindex, &cp_intf, 0));

  physical_ifindices = malloc(sizeof(int) * n_physical_intfs);
  TEST(physical_ifindices != NULL);
  rc = ef_cp_get_lower_intfs(cp, cp_intf.ifindex, physical_ifindices,
                             n_physical_intfs, flags);
  TRY(rc);

  while( rc > n_physical_intfs ) {
    n_physical_intfs = rc;

    free(physical_ifindices);
    physical_ifindices = malloc(sizeof(int) * n_physical_intfs);
    TEST(physical_ifindices != NULL);

    rc = ef_cp_get_lower_intfs(cp, cp_intf.ifindex, physical_ifindices,
                               n_physical_intfs, flags);
    TRY(rc);
  }
  n_physical_intfs = rc;
  /* We could reasonably have n_physical_intfs=0 if a logical interface has no
   * physical interfaces below it, or they are all down. For the sake of
   * simplicity, we just assume this can never happen. */
  if( n_physical_intfs <= 0 ) {
    printf("Interface parsing resulted in no physical interfaces. Either you "
           "are trying to send over a logical interface, such as loopback, or "
           "there are no physical interfaces that are UP below the provided "
           "interface. These are unsupported in efsend_cplane, so the program "
           "will now exit.\n");
    TEST(n_physical_intfs > 0);
  }

  for( i = 0; i < n_physical_intfs; i++ ) {
    intf = register_intf(cp, physical_ifindices[i], pkt_buf);
    if( intf ) {
      intf->next = *intfs;
      *intfs = intf;
    }
  }
  free(physical_ifindices);

  return intf;
}

static void free_intfs(struct ef_cp_handle *cp, struct intf_state **intfs)
{
  struct intf_state *intf, *next;

  for( intf = *intfs; intf; intf = next ) {
    next = intf->next;
    TRY(ef_cp_unregister_intf(cp, intf->ifindex, 0));
    TRY(ef_memreg_free(&intf->mr, dh));
    TRY(ef_vi_free(&intf->vi, dh));
    TRY(ef_pd_free(&intf->pd, dh));
    free(intf);
  }

  *intfs = NULL;
}

static void resolve_route(struct ef_cp_handle *cp, struct pkt_buf *pkt_buf,
                          struct ef_cp_route_verinfo *route_ver,
                          struct intf_state **active_intf,
                          int *ifindex)
{
  int rc;
  size_t prefix_space = PREFIX_RESERVED;
  void *pkt_ip = (char*)pkt_buf->p + prefix_space;
  int flags = (*ifindex == 0) ? EF_CP_RESOLVE_F_UNREGISTERED : 0;
  struct intf_state *intf;
  ci_ip4_hdr *ip4;
  ci_udp_hdr *udp;
  struct iovec iov;

  /* If we are sending to a multicast address, route resolution could
   * reasonably return any valid ifindex. In that case, lets suggest
   * an appropriate one to use instead. */
  route_meta.ifindex = dest_is_mcast() ? *ifindex : -1;

  /* Route resolution could come back before we have the destination
   * MAC address, so if we get -EAGAIN just jump right back into it. */
  do {
    rc = ef_cp_resolve(cp, pkt_ip, &prefix_space, &route_meta,
                       route_ver, flags);
  } while( -EAGAIN == rc );
  TEST(rc == 0 || rc & EF_CP_RESOLVE_S_UNREGISTERED);

  /* We could retry in this case, but lets just give
   * up if we don't resolve to a valid ifindex. */
  TEST(route_meta.ifindex > 0);

  intf = (struct intf_state*)route_meta.intf_cookie;
  *active_intf = intf;
  if( intf == NULL ) {
    if ( cfg_interface == NULL ) {
      printf("Routing over ifindex=%d\n", route_meta.ifindex);
      *ifindex = route_meta.ifindex;
      /* We want to reset the route version so we resolve the actual
       * VI to send over after initialising all possible VIs. */
      *route_ver = EF_CP_ROUTE_VERINFO_INIT;
    }

    /* Either the interface config has changed, or we are hot-loading intfs
     * to send over. In any case, we need to reinitialise the interfaces. */
    return;
  }

  printf("Sending over ifindex=%d\n", route_meta.ifindex);

  /* Let's recalculate the checksums; this is not always necessary where the HW
   * being used can do this instead, but we just assume it can't. */
  ip4 = pkt_ip;
  udp = (ci_udp_hdr*)(ip4 + 1);
  iov.iov_base = udp + 1;
  iov.iov_len = cfg_payload_len;
  ip4->ip_check_be16 = ef_ip_checksum((const struct iphdr*)ip4);
  udp->udp_check_be16 = ef_udp_checksum((const struct iphdr*)ip4,
                                        (const struct udphdr*)udp, &iov, 1);

  /* Update the DMA address to be the start of the packet headers, and
   * calculate the full length of the packet. */
  intf->dma_start = intf->dma_buf_addr + PREFIX_RESERVED - prefix_space;
  intf->tx_frame_len = cfg_payload_len + prefix_space +
                       sizeof(ci_ip4_hdr) + sizeof(ci_udp_hdr);
}

int main(int argc, char* argv[])
{
  struct ef_cp_handle *cp;
  struct ef_cp_intf_verinfo ver = EF_CP_INTF_VERINFO_INIT;
  struct intf_state *intfs_head = NULL;
  struct intf_state *intf = NULL;
  struct intf_state *active_intf = NULL;
  struct pkt_buf pkt_buf = { 0 };
  struct ef_cp_route_verinfo route_ver = EF_CP_ROUTE_VERINFO_INIT;
  int tx_ifindex = 0;

  TRY(parse_opts(argc, argv, &tx_ifindex));

  TRY(ef_driver_open(&dh));
  TRY(ef_cp_init(&cp, 0));

  allocate_packet_buffer(&pkt_buf);

  /* Continue until all sends are complete */
  while( n_sent < cfg_iter ) {
    /* If our interface version is outdated, then lets have a look at what the
     * current state is, and register any new interfaces we may need. */
    if( ! ef_cp_intf_version_verify(cp, &ver) ) {
      /* If we don't have a fixed interface to send over, then we should have
       * the route re-resolved, so we skip initialisation for now. */
      if( cfg_interface == NULL && active_intf != NULL ) {
        tx_ifindex = 0;
      }

      /* Only (re)initialise our state if we have a valid ifindex. */
      if( tx_ifindex != 0 ) {
        printf("Detected outdated interface version... Reinitialising.\n");
        ver = ef_cp_intf_version_get(cp);
        init_intfs(cp, &intfs_head, tx_ifindex, &pkt_buf);
        TEST(intfs_head != NULL);
      }

      /* Invalidate our route as we either need to resolve an ifindex to send
       * over, or the specific VI to use. */
      route_ver = EF_CP_ROUTE_VERINFO_INIT;
    }

    /* If our route is outdated then lets try to resolve it, and potentially
     * fallback to reinitialising our state if we don't have a valid active
     * interface to send over. */
    if( ! ef_cp_route_verify(cp, &route_ver) ) {
      active_intf = NULL;
      resolve_route(cp, &pkt_buf, &route_ver, &active_intf, &tx_ifindex);
      if( active_intf == NULL ) {
        ver = EF_CP_INTF_VERINFO_INIT;
        continue;
      }
    }
    TEST(active_intf != NULL);

    /* Send our packets, and check for completions on any of our VIs. */
    n_pushed += send_more_packets(cfg_iter - n_pushed, active_intf);
    for( intf = intfs_head; intf; intf = intf->next ) {
      handle_completions(&intf->vi);
    }
    if( cfg_usleep )
      usleep(cfg_usleep);
  }

  printf("Sent %d packets\n", n_sent);

  free_intfs(cp, &intfs_head);
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
