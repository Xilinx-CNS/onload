/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2020 Xilinx, Inc. */
/* Function definitions common to apps in the efsend suite.
 *
 * CUSTOMER NOTE: This code  is not intended to be used outside of the efsend
 * suite!
 */

#include "efsend_common.h"
#include <etherfabric/checksum.h>

static uint8_t mcast_mac[6];
static struct sockaddr_in sa_local, sa_mcast;

int init_udp_pkt(void* pkt_buf, int paylen, ef_vi *vi,
                 ef_driver_handle dh, int vlan, int checksum)
{
  int ip_len = sizeof(struct iphdr) + sizeof(struct udphdr) + paylen;
  struct ethhdr* eth;
  struct iphdr* ip4;
  struct udphdr* udp;

  eth = pkt_buf;
  int etherlen = ETH_HLEN + ((vlan >= 0) ? 4 : 0);
  ip4 = (void*) ((char*) eth + etherlen);
  udp = (void*) (ip4 + 1);

  if(vlan >= 0) {
    struct vlanhdr* ethv = (void*)((char*) pkt_buf + ETH_HLEN);
    eth->h_proto = htons(0x8100);
    ethv->ether_vtag = htons(vlan);
    ethv->ether_type = htons(0x0800);
  }
  else {
    eth->h_proto = htons(0x0800);
  }
  memcpy(eth->h_dest, mcast_mac, 6);
  ef_vi_get_mac(vi, dh, eth->h_source);

  iphdr_init(ip4, ip_len, 0, IPPROTO_UDP,
	     sa_local.sin_addr.s_addr,
	     sa_mcast.sin_addr.s_addr);
  udphdr_init(udp, ip4, sa_local.sin_port,
	      sa_mcast.sin_port, paylen);
  if( checksum ) {
    struct iovec iov = { udp + 1, paylen };
    ip4->check = ef_ip_checksum(ip4);
    udp->check = ef_udp_checksum(ip4, udp, &iov, 1);
  }

  return etherlen + ip_len;
}

void common_usage()
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efsend [options] <interface> <mcast-ip> <mcast-port>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "positionals:\n");
  fprintf(stderr, " <interface>     local interface for sends and receives\n");
  fprintf(stderr, " <mcast-ip>      multicast ip address to send packets to\n");
  fprintf(stderr, " <mcast-port>    multicast port to send packets to\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "interface:\n");
  fprintf(stderr, "  <interface-name>[/<flag>[,<flag>...]]\n");
  fprintf(stderr, "  where flag is one of:\n");
  fprintf(stderr, "     * express - request Express datapath\n");
  fprintf(stderr, "     * enterprise - request Enterprise datapath\n");
  fprintf(stderr, "     * phys - request physical addressing mode\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -n <iterations>     - number of packets to send\n");
  fprintf(stderr, "  -m <message-size>   - set udp payload size\n");
  fprintf(stderr, "  -s <microseconds>   - time to sleep between sends\n");
  fprintf(stderr, "  -l <local-port>     - change local port to send from\n");
}

void print_and_exit(char* format, ...) {
  va_list argptr;
  va_start(argptr, format);
  vfprintf(stderr, format, argptr);
  va_end(argptr);
  exit(1);
}

void parse_args(char *argv[], int *ifindex, int local_port, int vlan,
                enum ef_pd_flags *pd_flags_out, ef_driver_handle driver_handle)
{
  const char *mcast_ip;
  char *interface, *local_ip;
  int mcast_port;

  if( ! parse_interface_with_flags(argv[0], &interface, ifindex,
                                   pd_flags_out, driver_handle) )
    print_and_exit("ERROR: Failed to parse interface '%s': %s\n",
                   argv[0], strerror(errno));
  argv++;
  printf("interface is %s\n", interface);
  get_ipaddr_of_vlan_intf(interface, vlan, &local_ip);
  free(interface);
  mcast_ip = (argv++)[0];
  mcast_port = atoi(argv[0]);

  if( ! parse_host(local_ip, &sa_local.sin_addr) )
    print_and_exit("ERROR: Failed to parse local address %s\n", local_ip);
  sa_local.sin_port = htons(local_port);

  if ( ! parse_host(mcast_ip, &sa_mcast.sin_addr) )
    print_and_exit("ERROR: Failed to parse multicast address %s\n", mcast_ip);

  sa_mcast.sin_port = htons(mcast_port);

  mcast_mac[0] = 0x1;
  mcast_mac[1] = 0;
  mcast_mac[2] = 0x5e;
  mcast_mac[3] = 0x7f & (sa_mcast.sin_addr.s_addr >> 8);
  mcast_mac[4] = 0xff & (sa_mcast.sin_addr.s_addr >> 16);
  mcast_mac[5] = 0xff & (sa_mcast.sin_addr.s_addr >> 24);
}
