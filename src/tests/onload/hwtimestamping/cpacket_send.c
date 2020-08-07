/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019 Xilinx, Inc. */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <unistd.h>
#include <inttypes.h>

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define PAYLOAD_SIZE 6
#define EXTENSION_SIZE 5

#define FLAG_FCS       (1 << 0)  /* Original FCS was correct */
#define FLAG_EXTENSION (1 << 1)  /* Extension headers are present */

uint16_t ip_checksum(void* data, int bytes)
{
  uint32_t sum = 0;
  uint16_t* p = data;
  int n = bytes/2;

  while( n-- )
    sum += *p++;

  while( sum > 0xffff )
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}


uint32_t eth_checksum(void* data, int bytes)
{
  uint32_t sum = ~0;
  uint8_t* p = data;
  int bit;

  while( bytes-- ) {
    sum ^= *p++;
    for( bit = 0; bit < 8; ++bit )
      sum = (sum & 1) ? (sum >> 1) ^ 0xedb88320 : (sum >> 1);
  }

  return ~sum;
}


int main(int argc, char** argv)
{
  /* Packet data: a regular ethernet packet, with extra timestamp data
   * bodged onto the end, after the original ethernet FCS.
   */
  struct {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    char payload[PAYLOAD_SIZE];
    uint32_t fcs;
#if EXTENSION_SIZE != 0
    char extension[EXTENSION_SIZE];
#endif
    uint32_t ts_sec_be;
    uint32_t ts_nsec_be;
    uint8_t  flags;
    uint16_t device_id_be;
    uint8_t  port;
  } __attribute__((packed)) pkt;

  int sock;
  struct ifreq ifr;
  struct hostent* he;
  struct sockaddr_ll addr;
  struct timespec ts;

  if( argc < 4 ) {
    fprintf(stderr, "Usage: %s interface host port\n", argv[0]);
    return EXIT_FAILURE;
  }

  sock = socket(AF_PACKET, SOCK_RAW, 0);
  if( sock < 0 ) {
    perror("Failed to create raw socket");
    return EXIT_FAILURE;
  }

  /* Query properties of local interface */
  if( strlen(argv[1]) >= sizeof(ifr.ifr_name) ) {
    fprintf(stderr, "Invalid interface %s\n", argv[1]);
    return EXIT_FAILURE;
  }

  strcpy(ifr.ifr_name, argv[1]);
  if( ioctl(sock, SIOCGIFADDR, &ifr) != 0 ) {
    fprintf(stderr, "Failed to get IP address for %s\n", argv[1]);
    return EXIT_FAILURE;
  }
  pkt.ip.saddr = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

  if( ioctl(sock, SIOCGIFHWADDR, &ifr) != 0 ) {
    fprintf(stderr, "Failed to get MAC address for %s\n", argv[1]);
    return EXIT_FAILURE;
  }
  memcpy(pkt.eth.h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  if( ioctl(sock, SIOCGIFINDEX, &ifr) != 0 ) {
    fprintf(stderr, "Failed to get index for %s\n", argv[1]);
    return EXIT_FAILURE;
  }
  addr.sll_ifindex = ifr.ifr_ifindex;

  /* Resolve remote host address */
  he = gethostbyname(argv[2]);
  if( he == NULL || he->h_addr_list == NULL || he->h_addr_list[0] == NULL ) {
    fprintf(stderr, "Failed to resolve %s: %s\n", argv[1], hstrerror(h_errno));
    return EXIT_FAILURE;
  }
  if( he->h_addrtype != AF_INET ) {
    fprintf(stderr, "Unknown address type %d\n", he->h_addrtype);
    return EXIT_FAILURE;
  }
  pkt.ip.daddr = ((struct in_addr*)he->h_addr_list[0])->s_addr;

  /* Fill in remaining fields */
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = ETH_P_ARP;
  addr.sll_hatype = 0;
  addr.sll_pkttype = 0;
  addr.sll_halen = ETH_ALEN;
  memcpy(addr.sll_addr, pkt.eth.h_source, ETH_ALEN);

  /* Ethernet broadcast is simpler than figuring out the correct target MAC */
  memset(pkt.eth.h_dest, 0xff, ETH_ALEN);
  pkt.eth.h_proto = htons(ETH_P_IP);

  pkt.ip.ihl = 5;
  pkt.ip.version = IPVERSION;
  pkt.ip.tos = 0;
  pkt.ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_SIZE);
  pkt.ip.id = 0;
  pkt.ip.frag_off = 0;
  pkt.ip.ttl = IPDEFTTL;
  pkt.ip.protocol = IPPROTO_UDP;
  pkt.ip.check = 0;
  pkt.ip.check = ip_checksum(&pkt.ip, sizeof(struct iphdr));

  pkt.udp.source = htons(12345);
  pkt.udp.dest = htons(atoi(argv[3]));
  pkt.udp.len = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
  pkt.udp.check = 0;

  memcpy(pkt.payload, "Hello\n", PAYLOAD_SIZE);
  pkt.fcs = eth_checksum(&pkt, (char*)&pkt.fcs - (char*)&pkt);
  pkt.flags = FLAG_FCS | (EXTENSION_SIZE == 0 ? 0 : FLAG_EXTENSION);
  pkt.device_id_be = 0xabcd;
  pkt.port = 42;

  clock_gettime(CLOCK_REALTIME, &ts);
  pkt.ts_sec_be = htonl(ts.tv_sec);
  pkt.ts_nsec_be = htonl(ts.tv_nsec);

  sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&addr, sizeof(addr));


  printf("timestamp %llu.%.9lu \n",
     (long long unsigned int)ts.tv_sec, (long unsigned int)ts.tv_nsec);

  return EXIT_SUCCESS;
}
