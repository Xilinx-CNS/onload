/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* Function definitions common to apps in the efsend suite.
 *
 * CUSTOMER NOTE: This code  is not intended to be used outside of the efsend
 * suite!
 */

#include "efsend_common.h"

static uint8_t mcast_mac[6];
static struct sockaddr_in sa_local, sa_mcast;

int init_udp_pkt(void* pkt_buf, int paylen, ef_vi *vi,
                 ef_driver_handle dh, int vlan, int ip_checksum)
{
  int ip_len = sizeof(ci_ip4_hdr) + sizeof(ci_udp_hdr) + paylen;
  ci_ether_hdr* eth;
  ci_ip4_hdr* ip4;
  ci_udp_hdr* udp;

  eth = pkt_buf;
  int etherlen = ETH_HLEN + ((vlan >= 0) ? 4 : 0);
  ip4 = (void*) ((char*) eth + etherlen);
  udp = (void*) (ip4 + 1);

  if(vlan >= 0) {
    ci_ethhdr_vlan_t* ethv = pkt_buf;
    ethv->ether_vtype = htons(0x8100);
    ethv->ether_vtag = htons(vlan);
    ethv->ether_type = htons(0x0800);
  }
  else {
    eth->ether_type = htons(0x0800);
  }
  memcpy(eth->ether_dhost, mcast_mac, 6);
  ef_vi_get_mac(vi, dh, eth->ether_shost);

  ci_ip4_hdr_init(ip4, CI_NO_OPTS, ip_len, 0, IPPROTO_UDP,
		  sa_local.sin_addr.s_addr,
		  sa_mcast.sin_addr.s_addr, ip_checksum);
  ci_udp_hdr_init(udp, ip4, sa_local.sin_port,
		  sa_mcast.sin_port, udp + 1, paylen, 0);

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

void parse_args(char *argv[], int *ifindex, int local_port, int vlan)
{
  const char *interface, *mcast_ip;
  char* local_ip;
  int mcast_port;

  interface = (argv++)[0];
  mcast_ip = (argv++)[0];
  mcast_port = atoi(argv[0]);

  get_ipaddr_of_vlan_intf(interface, vlan, &local_ip);

  if( ! parse_interface(interface, ifindex) )
    print_and_exit("ERROR: Failed to parse interface %s\n", interface);

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
