/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  kjm
**  \brief  Example for TX timestamping sockets API
**   \date  2014/04/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  

/* Example application to demonstrate use of the timestamping API
 *
 * This application will echo packets, and display their TX timestamps.
 * With multiple different options for types of timestamp; including
 * hardware timestamps.
 *
 * Example:
 * (host1)$ EF_TX_TIMESTAMPING=1 onload tx_timestamping --proto tcp 
 * (host2)$ echo payload | nc host1 9000
 * 
 * (If not using onload, on most kernels, no TCP timestamp will be seen)
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
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

#include "onload/extensions.h"
#ifdef ONLOADEXT_AVAILABLE
#include "onload/extensions_zc.h"
#endif

/* Use the kernel definitions if possible -
 * But if not, use our own local definitions, and Onload will allow it.
 * - Though you still need a reasonably recent kernel to get hardware
 *   timestamping.  Software timestamps can go back several more versions.
 */
#ifndef NO_KERNEL_TS_INCLUDE
  #include <linux/net_tstamp.h>
  #include <linux/sockios.h>
#else
  #include <time.h>
  struct hwtstamp_config {
      int flags;           /* no flags defined right now, must be zero */
      int tx_type;         /* HWTSTAMP_TX_* */
      int rx_filter;       /* HWTSTAMP_FILTER_* */
  };
  enum {
        SOF_TIMESTAMPING_TX_HARDWARE = (1<<0),
        SOF_TIMESTAMPING_TX_SOFTWARE = (1<<1),
        SOF_TIMESTAMPING_RX_HARDWARE = (1<<2),
        SOF_TIMESTAMPING_RX_SOFTWARE = (1<<3),
        SOF_TIMESTAMPING_SOFTWARE = (1<<4),
        SOF_TIMESTAMPING_SYS_HARDWARE = (1<<5),
        SOF_TIMESTAMPING_RAW_HARDWARE = (1<<6),
        SOF_TIMESTAMPING_MASK =
        (SOF_TIMESTAMPING_RAW_HARDWARE - 1) |
        SOF_TIMESTAMPING_RAW_HARDWARE
  };
#endif

/* These are defined in socket.h, but older versions might not have all 3 */
#ifndef SO_TIMESTAMP
  #define SO_TIMESTAMP            29
#endif
#ifndef SO_TIMESTAMPNS
  #define SO_TIMESTAMPNS          35
#endif
#ifndef SO_TIMESTAMPING
  #define SO_TIMESTAMPING         37
#endif

/* Assert-like macros */
#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )

#define TRY(x)                                                          \
  do {                                                                  \
    int __rc = (x);                                                     \
      if( __rc < 0 ) {                                                  \
        fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);                 \
        fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);       \
        fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",                 \
                __rc, errno, strerror(errno));                          \
        exit(1);                                                        \
      }                                                                 \
  } while( 0 )

struct configuration {
  int            cfg_protocol;  /* protocol: udp or tcp */
  char const*    cfg_host;      /* listen address */
  char const*    cfg_mcast;     /* e.g. 239.10.10.10 - sets IP_ADD_MULTICAST */
  char const*    cfg_ioctl;     /* e.g. eth6  - calls the ts enable ioctl */
  unsigned short cfg_port;      /* listen port */
  unsigned int   cfg_max_packets; /* Stop after this many (0=forever) */
  int            cfg_templated; /* use templated send */
  int            cfg_ext;       /* Use extension API? */
};

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
#ifdef ONLOADEXT_AVAILABLE
         "\t--templated\tUse templated sends.\n"
         "\t--ext\t\tUse extensions API rather than SO_TIMESTAMPING.\n"
#endif
        );
  exit(-1);
}

#define MATCHES(_x,_y) ( strncasecmp((_x),(_y),strlen((_x)))==0 )

static int get_protocol(char const* proto)
{
  if (MATCHES( "udp", proto )) return IPPROTO_UDP;
  if (MATCHES( "tcp", proto )) return IPPROTO_TCP;

  printf("Could not understand requested protocol %s\n", proto);
  print_help();
  return -1;
}
#undef MATCHES

static void parse_options( int argc, char** argv, struct configuration* cfg )
{
  int option_index = 0;
  int opt;
  static struct option long_options[] = {
    { "proto", required_argument, 0, 't' },
    { "host", required_argument, 0, 'l' },
    { "ioctl", required_argument, 0, 'i' },
    { "port", required_argument, 0, 'p' },
    { "mcast", required_argument, 0, 'c' },
    { "max", required_argument, 0, 'n' },
    { "templated", no_argument, 0, 'T' },
    { "ext", no_argument, 0, 'e' },
    { "help", no_argument, 0, 'h' },
    { 0, no_argument, 0, 0 }
  };
  char const* optstring = "t:l:i:p:c:n:Th";

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
#ifdef ONLOADEXT_AVAILABLE
      case 'T':
        cfg->cfg_templated = 1;
        break;
      case 'e':
        cfg->cfg_ext = 1;
        break;
#endif
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
  struct ip_mreq req;

  if (cfg->cfg_mcast == NULL)
    return;

  bzero(&req, sizeof(req));
  TRY(inet_aton(cfg->cfg_mcast, &req.imr_multiaddr));

  req.imr_interface.s_addr = INADDR_ANY;
  TRY(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &req, sizeof(req)));
}

/* This requires a bit of explanation.
 * Typically, you have to enable hardware timestamping on an interface.
 * Any application can do it, and then it's available to everyone.
 * The easiest way to do this, is just to run sfptpd.
 *
 * But in case you need to do it manually; here is the code, but
 * that's only supported on reasonably recent versions
 *
 * Option: --ioctl ethX
 *
 * NOTE:
 * Usage of the ioctl call is discouraged. A better method, if using
 * hardware timestamping, would be to use sfptpd as it will effectively
 * make the ioctl call for you.
 *
 */
static void do_ioctl(struct configuration* cfg, int sock)
{
#ifdef SIOCSHWTSTAMP
  struct ifreq ifr;
  struct hwtstamp_config hwc;
  int ok;
#endif

  if(cfg->cfg_ioctl == NULL)
    return;

#ifdef SIOCSHWTSTAMP
  bzero(&ifr, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", cfg->cfg_ioctl);

  hwc.flags = 0;
  hwc.tx_type = HWTSTAMP_TX_ON;
  hwc.rx_filter = 0;

  ifr.ifr_data = (char*)&hwc;
  
  /* If using a TCP socket, we need to create a UDP one for the ioctl
   * call.  This is fine as the setting is global for that
   * interface 
   */
  if ( cfg->cfg_protocol == IPPROTO_TCP ) {
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    TEST(sock != -1);
  }

  ok = ioctl(sock, SIOCSHWTSTAMP, &ifr);
  if ( ok < 0 ) {
    printf("Setting SIOCSHWTSTAMP ioctl failed %d (%d - %s)\n", 
           ok, errno, strerror(errno));
  } else {
    printf("Accepted SIOCHWTSTAMP ioctl.\n");
  }

  if ( cfg->cfg_protocol == IPPROTO_TCP )
    close(sock);

  return;
#else
  (void) sock;
  printf("SIOCHWTSTAMP ioctl not supported, ignoring --ioctl\n"
         "HW timestamps will be unavailable unless sfptpd is running\n");
  return; 
#endif
}

/* This routine selects the correct socket option to enable timestamping.
 */
static void do_ts_sockopt(struct configuration* cfg, int sock)
{
  printf("Selecting hardware timestamping mode.\n");
 
#ifdef ONLOADEXT_AVAILABLE 
  if( cfg->cfg_ext )
    TRY(onload_timestamping_request(sock, ONLOAD_TIMESTAMPING_FLAG_TX_NIC));
  else
#endif
  {
    int enable = 1;
    int ok = 0;

    enable = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_SYS_HARDWARE |
      SOF_TIMESTAMPING_RAW_HARDWARE;
    if (cfg->cfg_protocol == IPPROTO_TCP)
      enable |= ONLOAD_SOF_TIMESTAMPING_STREAM;
    ok = setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &enable, sizeof(int));
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
#define TIME_FMT "%" PRIu64 ".%.9" PRIu64 " "
#define OTIME_FMT "%" PRIu64 ".%.9" PRIu32 " "
static void print_time(char *s, struct timespec* ts)
{
   printf("%s timestamp " TIME_FMT "\n", s, 
          (uint64_t)ts->tv_sec, (uint64_t)ts->tv_nsec);
}

/* Given a packet, extract the timestamp(s) */
static void handle_time(struct msghdr* msg, int tx_num,
                        struct configuration* cfg)
{
  struct onload_scm_timestamping_stream* tcp_tx_stamps;
  struct timespec* udp_tx_stamp;
  struct cmsghdr* cmsg;

  for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET)
      continue;
    switch(cmsg->cmsg_type) {
    case ONLOAD_SCM_TIMESTAMPING_STREAM:
      tcp_tx_stamps = (struct onload_scm_timestamping_stream*)CMSG_DATA(cmsg);
      printf("Timestamp for tx %d - %d bytes:\n",
             tx_num, (int)tcp_tx_stamps->len);
      print_time("First sent", &tcp_tx_stamps->first_sent);
      print_time("Last sent", &tcp_tx_stamps->last_sent);
      break;
    case SO_TIMESTAMPING:
#ifdef ONLOADEXT_AVAILABLE
      if( cfg->cfg_ext ) {
        struct onload_timestamp* ts = (struct onload_timestamp*) CMSG_DATA(cmsg);
        printf("NIC timestamp " OTIME_FMT "\n", ts[0].sec, ts[0].nsec);
        break;
      }
#endif
      udp_tx_stamp = (struct timespec*) CMSG_DATA(cmsg);
      printf("Timestamp for tx %d\n", tx_num);
      print_time("System", &(udp_tx_stamp[0]));
      print_time("Transformed", &(udp_tx_stamp[1]));
      print_time("Raw", &(udp_tx_stamp[2]));
      break;
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
int get_tx_ts(int sock, unsigned int tx_num, struct configuration* cfg)
{
  struct msghdr msg;
  struct iovec iov;
  struct sockaddr_in host_address;
  char buffer[2048];
  char control[1024];

  make_address(0, 0, &host_address);
  iov.iov_base = buffer;
  iov.iov_len = 2048;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_name = &host_address;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  msg.msg_control = control;
  msg.msg_controllen = 1024;
  TRY( recvmsg(sock, &msg, MSG_ERRQUEUE | MSG_DONTWAIT) );
  handle_time(&msg, tx_num, cfg);
  return 0;
};


int main(int argc, char** argv)
{
  struct configuration cfg;
  int sock, epoll;
  unsigned int pkt_num = 0;
  unsigned int tx_num = 0;
  int rc;
  struct epoll_event e;

  parse_options(argc, argv, &cfg);

  /* Initialise */
  sock = add_socket(&cfg);
  do_mcast(&cfg, sock);
  do_ioctl(&cfg, sock);
  do_ts_sockopt(&cfg, sock);

  TRY( epoll = epoll_create(10) );
  e.events = EPOLLIN | EPOLLRDHUP;
  e.data.fd = sock;
  TRY( epoll_ctl(epoll, EPOLL_CTL_ADD, sock, &e) );

  /* Run until we've got enough packets, or an error occurs */
  while( 1 ) {
    /* break out of loop if all timestamps received */
    if( (cfg.cfg_max_packets != 0) &&
        (tx_num >= cfg.cfg_max_packets) )
      break;


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
      TRY( get_tx_ts(sock, tx_num, &cfg) );
      ++tx_num;
    }
  }

  close(sock);
  return 0;
}
