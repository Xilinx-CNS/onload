/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2024 Xilinx, Inc. */

/* Example application to demonstrate use of the transmit timestamping API
 *
 * This application will echo packets, and display their TX timestamps.
 * With multiple different options for types of timestamp; including
 * hardware timestamps.
 *
 * Example:
 * (host1)$ EF_TX_TIMESTAMPING=1 onload tx_timestamping --proto tcp 
 * (host2)$ echo payload | nc host1 9000
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <getopt.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>

#ifndef SOF_TIMESTAMPING_OPT_ID
  #define SOF_TIMESTAMPING_OPT_ID (1<<7)
#endif
#ifndef SOF_TIMESTAMPING_OPT_TSONLY
  #define SOF_TIMESTAMPING_OPT_TSONLY (1<<11)
#endif


#define SEQ_LE(s1, s2)      ((uint32_t)((s1) - (s2)) <= 0)

struct configuration {
  int            cfg_protocol;  /* protocol: udp or tcp */
  char const*    cfg_host;      /* listen address */
  char const*    cfg_intf;      /* interface address */
  char const*    cfg_mcast;     /* e.g. 239.10.10.10 - sets IP_ADD_MULTICAST */
  char const*    cfg_ioctl;     /* e.g. eth6  - calls the ts enable ioctl */
  unsigned short cfg_port;      /* listen port */
  unsigned int   cfg_max_packets; /* Stop after this many (0=forever) */
  int            cfg_templated; /* use templated send */
  int            cfg_ext;       /* Use extension API? Which one, v1 or v2? */
  bool           cfg_data;      /* Return a copy of TX packet.
                                 * Clears SOF_TIMESTAMPING_OPT_TSONLY */
  bool           cfg_cmsg;      /* Set SOF_TIMESTAMPING_OPT_CMSG */
  bool           cfg_stream;    /* Set ONLOAD_SOF_TIMESTAMPING_STREAM */
  bool           cfg_rx;        /* Timestamp received packets */
};


/* Include code in common with receive timestamping example */

#include "timestamping.h"


/* Commandline options, configuration etc. */

void print_help(void)
{
  printf("Usage:\n"
         "\t--proto\t<udp|tcp>\tProtocol.  Default: UDP\n"
         "\t--host\t<hostname>\tHost to listen on / connect to.  "
           "Default: Localhost\n"
         "\t--port\t<hostname>\tHost to listen on / connect to.  "
           "Default: Localhost\n"
         "\t--ioctl\t<ethX>\tDevice to send timestamping enable ioctl.  "
           "Default: None\n"
         "\t--max\t<num>\tStop after n packets.  Default: Run forever\n"
         "\t--mcast\t<group>\tSubscribe to multicast group.\n"
         "\t--data\tRequest a copy of outgoing packet with timestamp\n"
         "\t--cmsg\tUse SOF_TIMESTAMPING_OPT_CMSG (off by default)\n"
#ifdef ONLOADEXT_AVAILABLE
         "\t--stream\tSet ONLOAD_SOF_TIMESTAMPING_STREAM (proprietary format)\n"
         "\t--templated\tUse templated sends.\n"
         "\t--ext\t\tUse extensions API rather than SO_TIMESTAMPING.\n"
         "\t--ext2\t\tUse extensions API v2 rather than SO_TIMESTAMPING.\n"
         "\t--rx\t\tTimestamp received packets.\n"
         "\t--intf\t\tAddress for interface to use for multicast receive.\n"
#endif
        );
  exit(-1);
}

static void parse_options( int argc, char** argv, struct configuration* cfg )
{
  int option_index = 0;
  int opt;
  static struct option long_options[] = {
    { "proto", required_argument, 0, 't' },
    { "host", required_argument, 0, 'l' },
    { "intf", required_argument, 0, 'I' },
    { "ioctl", required_argument, 0, 'i' },
    { "port", required_argument, 0, 'p' },
    { "mcast", required_argument, 0, 'c' },
    { "max", required_argument, 0, 'n' },
    { "data", no_argument, 0, 'd' },
    { "cmsg", no_argument, 0, 'C' },
    { "stream", no_argument, 0, 's' },
    { "templated", no_argument, 0, 'T' },
    { "ext", no_argument, 0, 'e' },
    { "ext2", no_argument, 0, 'E' },
    { "help", no_argument, 0, 'h' },
    { "rx", no_argument, 0, 'r' },
    { 0, no_argument, 0, 0 }
  };
  char const* optstring = "t:l:i:p:c:n:TheErI:";

  /* Defaults */
  bzero(cfg, sizeof(struct configuration));
  cfg->cfg_protocol = IPPROTO_UDP;
  cfg->cfg_port = 9000;

  opt = getopt_long(argc, argv, optstring, long_options, &option_index);
  while( opt != -1 ) {
    switch( opt ) {
      case 't':
        cfg->cfg_protocol = get_protocol(optarg);
        break;
      case 'l':
        cfg->cfg_host = optarg;
        break;
      case 'I':
        cfg->cfg_intf = optarg;
        break;
      case 'i':
        cfg->cfg_ioctl = optarg;
        break;
      case 'p':
        cfg->cfg_port = atoi(optarg);
        break;
      case 'c':
        cfg->cfg_mcast = optarg;
        break;
      case 'n':
        cfg->cfg_max_packets = atoi(optarg);
        break;
      case 'd':
        cfg->cfg_data = true;
        break;
    case 'C':
        cfg->cfg_cmsg = true;
        break;
    case 's':
        cfg->cfg_stream = true;
        break;
#ifdef ONLOADEXT_AVAILABLE
      case 'T':
        cfg->cfg_templated = 1;
        break;
      case 'e':
        cfg->cfg_ext = 1;
        break;
      case 'E':
        cfg->cfg_ext = 2;
        break;
#endif
      case 'r':
        cfg->cfg_rx = true;
        break;
      case 'h':
      default:
        print_help();
        break;
    }
    opt = getopt_long(argc, argv, optstring, long_options, &option_index);
  }
}


/* Connection */
static void make_address(char const* host, unsigned short port, struct sockaddr_in* host_address)
{
  struct hostent *hPtr;

  bzero(host_address, sizeof(struct sockaddr_in));

  host_address->sin_family = AF_INET;
  host_address->sin_port = htons(port);

  if (host != NULL) {
    hPtr = (struct hostent *) gethostbyname(host);
    TEST( hPtr != NULL );

    memcpy((char *)&host_address->sin_addr, hPtr->h_addr, hPtr->h_length);
  } else {
    host_address->sin_addr.s_addr=INADDR_ANY;
  }
}

/* Option: --mcast group_ip_address */
static void do_mcast(struct configuration* cfg, int sock)
{
  struct sockaddr_in intf;
  struct ip_mreq req;

  if (cfg->cfg_mcast == NULL)
    return;

  make_address(cfg->cfg_intf, 0, &intf);

  bzero(&req, sizeof(req));
  TRY(inet_aton(cfg->cfg_mcast, &req.imr_multiaddr));

  req.imr_interface.s_addr = intf.sin_addr.s_addr;
  TRY(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &req, sizeof(req)));
}

/* This routine selects the correct socket option to enable timestamping.
 */
static void do_ts_sockopt(struct configuration* cfg, int sock)
{
  int optname = SO_TIMESTAMPING;

  printf("Selecting hardware timestamping mode.\n");
 
#ifdef ONLOADEXT_AVAILABLE 
  if( cfg->cfg_ext == 2)
    optname = SO_TIMESTAMPING_OOEXT;

  if( cfg->cfg_ext == 1 )
    TRY(onload_timestamping_request(sock,
        ONLOAD_TIMESTAMPING_FLAG_TX_NIC |
        (cfg->cfg_rx ? ONLOAD_TIMESTAMPING_FLAG_RX_NIC : 0)));
  else
#endif
  {
    struct so_timestamping enable = {
      .flags = SOF_TIMESTAMPING_TX_HARDWARE |
               SOF_TIMESTAMPING_RAW_HARDWARE |
               SOF_TIMESTAMPING_SYS_HARDWARE |
               SOF_TIMESTAMPING_SOFTWARE
    };

    if( cfg->cfg_rx )
      enable.flags |= SOF_TIMESTAMPING_RX_HARDWARE;

    int ok = 0;

    enable.flags |= SOF_TIMESTAMPING_OPT_ID;
    if( ! (cfg->cfg_data || cfg->cfg_cmsg))
      enable.flags |= SOF_TIMESTAMPING_OPT_TSONLY;
    if( cfg->cfg_cmsg )
      enable.flags |= SOF_TIMESTAMPING_OPT_CMSG;
#ifdef ONLOADEXT_AVAILABLE
    if( cfg->cfg_stream &&
        cfg->cfg_protocol == IPPROTO_TCP ) {
      enable.flags |= ONLOAD_SOF_TIMESTAMPING_STREAM;
#if defined(SOF_TIMESTAMPING_OPT_ID_TCP)
      if( enable.flags & SOF_TIMESTAMPING_OPT_ID )
        enable.flags |= SOF_TIMESTAMPING_OPT_ID_TCP;
#endif
    }
#endif
    ok = setsockopt(sock, SOL_SOCKET, optname, &enable, sizeof enable);
    if (ok < 0) {
      printf("Timestamp socket option failed.  %d (%d - %s)\n",
              ok, errno, strerror(errno));
      exit(ok);
    }
  }
}

/* Option: --proto udp (default), also --port nnn (default 9000) */
static int add_udp(struct configuration* cfg)
{
  int s;
  struct sockaddr_in host_address;

  make_address(cfg->cfg_host, cfg->cfg_port, &host_address);

  s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  TEST(s >= 0);

  TRY(bind(s, (struct sockaddr*)&host_address, sizeof(host_address)) );

  printf("UDP socket created, listening on port %d\n", cfg->cfg_port);

  return s;
}

/* Option: --proto: tcp, also --port nnn (default 9000) */
static int add_tcp(struct configuration* cfg)
{
  int s;

  struct sockaddr_in host_address;
  socklen_t clilen;
  struct sockaddr_in cli_addr;
  clilen = sizeof(cli_addr);
  int connected_fd;

  make_address(cfg->cfg_host, cfg->cfg_port, &host_address);
  s = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
  TEST(s >= 0);
  TRY( bind(s, (struct sockaddr*)&host_address, sizeof(host_address)) );
  TRY( listen( s, -1 ) );

  printf( "TCP listening on port %d\n ", cfg->cfg_port );

  connected_fd = accept(s, (struct sockaddr *) &cli_addr, &clilen);
  TEST(connected_fd >= 0);
  close(s);

  printf("TCP connection accepted\n");
  return connected_fd;
}

static int add_socket(struct configuration* cfg)
{
  switch(cfg->cfg_protocol) {
  case IPPROTO_UDP:
    return add_udp(cfg);
  case IPPROTO_TCP:
    return add_tcp(cfg);
  default:
    printf("Unsupported protocol %d\n", cfg->cfg_protocol);
    exit(-1);
  }
}


/* Processing */
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
  if( len & 15 )
    printf("\n");
}


static void print_time(char *s, struct timespec* ts)
{
   printf("%s timestamp " TIME_FMT "\n", s, 
          (uint64_t)ts->tv_sec, (uint64_t)ts->tv_nsec);
}


/* Given a packet, extract the timestamp(s) */
static void handle_time(struct msghdr* msg, struct configuration* cfg)
{
#ifdef ONLOADEXT_AVAILABLE
  struct onload_scm_timestamping_stream* tcp_tx_stamps;
#endif
  struct timespec* udp_tx_stamp;
  struct cmsghdr* cmsg;
  struct sock_extended_err* err;
  static uint32_t last_id = (uint32_t) -1;

  for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET &&
        cmsg->cmsg_level != SOL_IP )
      continue;
    switch(cmsg->cmsg_type) {
#ifdef ONLOADEXT_AVAILABLE
    case ONLOAD_SCM_TIMESTAMPING_STREAM:
      tcp_tx_stamps = (struct onload_scm_timestamping_stream*)CMSG_DATA(cmsg);
      printf("Timestamp for tx - %d bytes:\n",
             (int)tcp_tx_stamps->len);
      bool retrans = ( (tcp_tx_stamps->last_sent.tv_sec != 0) ||
                       (tcp_tx_stamps->last_sent.tv_nsec != 0) );
      if( retrans )
        printf("TCP retransmission:\n");
      /* Time data was originally sent */
      print_time("First sent", &tcp_tx_stamps->first_sent);
      /* Time retransmit sent */
      print_time("Last sent", &tcp_tx_stamps->last_sent);
      break;
#endif
    case SO_TIMESTAMPING:
#ifdef ONLOADEXT_AVAILABLE
      if( cfg->cfg_ext == 1 ) {
        struct onload_timestamp* ts = (struct onload_timestamp*) CMSG_DATA(cmsg);
        printf("NIC timestamp " OTIME_FMT "\n", ts[0].sec, ts[0].nsec);
        break;
      }
#endif
      udp_tx_stamp = (struct timespec*) CMSG_DATA(cmsg);
      print_time("System", &(udp_tx_stamp[0]));
      print_time("Transformed", &(udp_tx_stamp[1]));
      print_time("Raw", &(udp_tx_stamp[2]));
      break;
    case IP_RECVERR:
      err = (struct sock_extended_err*) CMSG_DATA(cmsg);
      if( err->ee_origin == SO_EE_ORIGIN_TIMESTAMPING ) {
        printf("Timestamp ID %u\n", err->ee_data);
        bool retrans = SEQ_LE(err->ee_data, last_id);
        last_id = err->ee_data;
        if( retrans )
          printf("TCP retransmission:\n");

        if( cfg->cfg_cmsg ) {
          struct sockaddr_in* saddr;
          char ip[INET_ADDRSTRLEN];
          saddr = (struct sockaddr_in*) ((void*) (err + 1));
          inet_ntop(AF_INET, &(saddr->sin_addr), ip, INET_ADDRSTRLEN);
          printf("Source address: %s\n", ip);
        }
      }
      break;
#ifdef ONLOADEXT_AVAILABLE
    case SO_TIMESTAMPING_OOEXT:
      struct scm_timestamping_ooext *t, *tend;
      t = (struct scm_timestamping_ooext *) CMSG_DATA(cmsg);
      tend = t + cmsg->cmsg_len / sizeof *t;
      printf("ext v2 timestamps");
      for (; t != tend; t++)
        print_time_ext2(t);
      printf("\n");
      return;
#endif
    default:
      /* Ignore other cmsg options */
      break;
    }
  }
}

#ifdef ONLOADEXT_AVAILABLE
int templated_send(int handle, struct iovec* iov)
{
  onload_template_handle tmpl;
  struct onload_template_msg_update_iovec update;

  struct iovec initial;
  initial.iov_base = iov->iov_base;
  initial.iov_len = iov->iov_len;

  update.otmu_base = iov->iov_base;
  update.otmu_len = iov->iov_len;
  update.otmu_offset = 0;
  update.otmu_flags = 0;

  /* Note: This is initialising, and then updating to the same values.
   * A real application would update only a subset of the values, and
   * usually with different values.
   */
  TRY( onload_msg_template_alloc(handle, &initial, 1, &tmpl, 0));
  return onload_msg_template_update(handle, tmpl, &update, 1,
                                    ONLOAD_TEMPLATE_FLAGS_SEND_NOW);
}
#endif

/* Receive a packet, and echo back a response */
int do_echo(int sock, unsigned int pkt_num, struct configuration* cfg)
{
  struct msghdr msg;
  struct iovec iov;
  struct sockaddr_in host_address;
  char buffer[2048];
  char control[1024];
  int got;

  /* recvmsg header structure */
  make_address(0, 0, &host_address);
  iov.iov_base = buffer;
  iov.iov_len = 2048;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_name = &host_address;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  msg.msg_control = control;
  msg.msg_controllen = 1024;

  /* message should be ready */
  got = recvmsg(sock, &msg, MSG_DONTWAIT);
  TEST(got >= 0);

  printf("Packet %d - %d bytes\n", pkt_num, got);
  handle_time(&msg, cfg);

  /* echo back */
  msg.msg_controllen = 0;
  iov.iov_len = got;
#ifdef ONLOADEXT_AVAILABLE
  if ( cfg->cfg_templated )
    TRY(templated_send(sock, &iov) );
  else
#endif
    TRY(sendmsg(sock, &msg, 0));

  return 0;
}

/* Receive a packet, and discard it */
int do_drop(int sock, unsigned int pkt_num, struct configuration* cfg)
{
  char buffer[2048];

  /* message should be ready */
  TRY(recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT));

  printf("Ignoring extra packet. pkt_num = %d\n", pkt_num);

  return 0;
}

/* retrieve TX timestamp and print it*/
int get_tx_ts(int sock, struct configuration* cfg)
{
  struct msghdr msg;
  struct iovec iov;
  struct sockaddr_in host_address;
  char buffer[2048];
  char control[1024];
  int got;

  make_address(0, 0, &host_address);
  iov.iov_base = buffer;
  iov.iov_len = 2048;
  msg.msg_iov = cfg->cfg_data ? &iov : NULL;
  msg.msg_iovlen = cfg->cfg_data ? 1 : 0;
  msg.msg_name = &host_address;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  msg.msg_control = control;
  msg.msg_controllen = 1024;
  TRY( got = recvmsg(sock, &msg, MSG_ERRQUEUE | MSG_DONTWAIT) );
  handle_time(&msg, cfg);
  if( cfg->cfg_data && got > 0 )
    hexdump(buffer, got);
  return 0;
};


int main(int argc, char** argv)
{
  struct configuration cfg;
  int sock, epoll;
  unsigned int pkt_num = 0;
  int rc;
  struct epoll_event e;

  parse_options(argc, argv, &cfg);

  /* Initialise */
  sock = add_socket(&cfg);
  do_mcast(&cfg, sock);
  do_ioctl(&cfg, sock, cfg.cfg_rx, true);
  do_ts_sockopt(&cfg, sock);

  TRY( epoll = epoll_create(10) );
  e.events = EPOLLIN | EPOLLRDHUP;
  e.data.fd = sock;
  TRY( epoll_ctl(epoll, EPOLL_CTL_ADD, sock, &e) );

  /* Run until we've got enough packets, or an error occurs */
  while( 1 ) {
    TRY( rc = epoll_wait(epoll, &e, 1, 1000) );

    /* break out of the loop after timeout if we've echoed all packets */
    if( rc == 0 ) {
      if( (cfg.cfg_max_packets != 0) &&
          (pkt_num >= cfg.cfg_max_packets) )
        break;
      else
        continue;
    }

    TEST( e.data.fd == sock );

    if( e.events & EPOLLRDHUP ) {
      /* TCP connection closed */
      printf("Remote end closed connection\n");
      break;
    }

    if( e.events & EPOLLIN ) {
      /* RX packet */
      if( (pkt_num < cfg.cfg_max_packets) || (cfg.cfg_max_packets == 0)) {
        TRY( do_echo(sock, pkt_num, &cfg) );
        ++pkt_num;
      }
      else {
        TRY( do_drop(sock, pkt_num, &cfg) );
        ++pkt_num;
      }
    }
    if( e.events & EPOLLERR ) {
      /* TX timestamp */
      TRY( get_tx_ts(sock, &cfg) );
    }
  }

  close(sock);
  return 0;
}
