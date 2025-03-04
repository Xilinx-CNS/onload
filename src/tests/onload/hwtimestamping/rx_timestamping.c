/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2024 Xilinx, Inc. */

/* Example application to demonstrate use of the receive timestamping API
 *
 * This application will receive packets, and display their 
 * hardware timestamps.
 *
 * Invoke with "--help" to see the options it supports.
 *
 * Example:
 * (host1)$ EF_RX_TIMESTAMPING=2 rx_timestamping
 * UDP socket created, listening on port 9000
 * Selecting hardware timestamping mode.
 * (host2)$ echo payload | nc -u host1 9000
 * Packet 0 - 8 bytes timestamp timestamps 1460374944.990960465 ...
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>


struct configuration {
  char const*    cfg_ioctl;     /* e.g. eth6  - calls the ts enable ioctl */
  unsigned short cfg_port;      /* listen port */
  int            cfg_protocol;  /* udp or tcp? */
  unsigned int   cfg_max_packets; /* Stop after this many (0=forever) */
  bool           cfg_pktinfo;   /* Whether to obtain incoming phys intf */
  int            cfg_ext;       /* Use extension API? Which version, 1 or 2? */
};

/* Include code in common with transmit timestamping example */

#include "timestamping.h"

/* Commandline options, configuration etc. */

void print_help(void)
{
  printf("Usage:\n"
         "\t--ioctl\t<ethX>\tDevice to send timestamping enable ioctl.  "
           "Default: None\n"
         "\t--port\t<num>\tPort to listen on.  "
           "Default: 9000\n"
         "\t--proto\t[TCP|UDP].  "
           "Default: UDP\n"
         "\t--max\t<num>\tStop after n packets.  "
           "Default: Run forever\n"
         "\t--pktinfo\t\tObtain physical timestamping interface.\n"
#ifdef ONLOADEXT_AVAILABLE
         "\t--ext\t\tUse extensions API v1 rather than SO_TIMESTAMPING.\n"
         "\t--ext2\t\tUse extensions API v2 rather than SO_TIMESTAMPING.\n"
#endif
        );
  exit(-1);
}

static void parse_options( int argc, char** argv, struct configuration* cfg )
{
  int option_index = 0;
  int valid = true;
  int opt;
  static struct option long_options[] = {
    { "ioctl", required_argument, 0, 'i' },
    { "port", required_argument, 0, 'p' },
    { "proto", required_argument, 0, 'P' },
    { "max", required_argument, 0, 'n' },
    { "pktinfo", no_argument, 0, 'k' },
    { "ext", no_argument, 0, 'e' },
    { "ext2", no_argument, 0, 'E' },
    { 0, no_argument, 0, 0 }
  };
  const char* optstring = "i:p:P:n:eEk";

  /* Defaults */
  bzero(cfg, sizeof(struct configuration));
  cfg->cfg_port = 9000;
  cfg->cfg_protocol = IPPROTO_UDP;

  opt = getopt_long(argc, argv, optstring, long_options, &option_index);
  while( opt != -1 ) {
    switch( opt ) {
      case 'i':
        cfg->cfg_ioctl = optarg;
        break;
      case 'p':
        cfg->cfg_port = atoi(optarg);
        break;
      case 'P':
        cfg->cfg_protocol = get_protocol(optarg);
        break;
      case 'n':
        cfg->cfg_max_packets = atoi(optarg);
        break;
      case 'k':
        cfg->cfg_pktinfo = true;
        break;
#ifdef ONLOADEXT_AVAILABLE
      case 'e':
        cfg->cfg_ext = 1;
        break;
      case 'E':
        cfg->cfg_ext = 2;
        break;
#endif
      default:
        valid = false;
        break;
    }
    opt = getopt_long(argc, argv, optstring, long_options, &option_index);
  }

  if( cfg->cfg_protocol < 0 )
    valid = false;

  if( !valid )
    print_help();
}


/* Connection */
static void make_address(unsigned short port, struct sockaddr_in* host_address)
{
  bzero(host_address, sizeof(struct sockaddr_in));

  host_address->sin_family = AF_INET;
  host_address->sin_port = htons(port);
  host_address->sin_addr.s_addr = INADDR_ANY;
}


/* This routine selects the correct socket option to enable timestamping. */
static void do_ts_sockopt(struct configuration* cfg, int sock)
{
  int enable = SOF_TIMESTAMPING_RX_HARDWARE |
               SOF_TIMESTAMPING_RAW_HARDWARE |
               SOF_TIMESTAMPING_SYS_HARDWARE |
               SOF_TIMESTAMPING_SOFTWARE;
  int readback;
  socklen_t readback_len = sizeof readback;
  int optname = SO_TIMESTAMPING;

  printf("Selecting hardware timestamping mode.\n");

  if( cfg->cfg_pktinfo ) {
    enable |= SOF_TIMESTAMPING_OPT_PKTINFO;
  }

#ifdef ONLOADEXT_AVAILABLE
  if( cfg->cfg_ext == 2 ) {
    enable |= SOF_TIMESTAMPING_OOEXT_TRAILER;
    optname = SO_TIMESTAMPING_OOEXT;
  }

  if( cfg->cfg_ext == 1 )
    TRY(onload_timestamping_request(sock, ONLOAD_TIMESTAMPING_FLAG_RX_NIC |
                                          ONLOAD_TIMESTAMPING_FLAG_RX_CPACKET));
  else
#endif
  {
    TRY(setsockopt(sock, SOL_SOCKET, optname, &enable, sizeof enable));
    TRY(getsockopt(sock, SOL_SOCKET, optname, &readback, &readback_len));
    if (enable != readback)
      printf("SO_TIMESTAMPING flags mismatch on read back:\n"
             "  got      0x%08x\n"
             "  expected 0x%08x\n",
             readback, enable);
  }
}

static int add_socket(struct configuration* cfg)
{
  int s;
  struct sockaddr_in host_address;
  int domain = SOCK_DGRAM;
  if ( cfg->cfg_protocol == IPPROTO_TCP )
    domain = SOCK_STREAM;

  make_address(cfg->cfg_port, &host_address);

  s = socket(PF_INET, domain, cfg->cfg_protocol);
  TEST(s >= 0);
  TRY(bind(s, (struct sockaddr*)&host_address, sizeof(host_address)) );

  printf("Socket created, listening on port %d\n", cfg->cfg_port);
  return s;
}


static int accept_child(int parent)
{
  int child;
  socklen_t clilen;
  struct sockaddr_in cli_addr;
  clilen = sizeof(cli_addr);

  TRY(listen(parent, 1));
  child = accept(parent, (struct sockaddr* ) &cli_addr, &clilen);
  TEST(child >= 0);

  printf("Socket accepted\n");
  return child;
}


/* Processing */
static void print_time(struct timespec* ts)
{
  if( ts != NULL ) {
    /* Hardware timestamping provides three timestamps -
     *   system (software)
     *   transformed (hw converted to sw)
     *   raw (hardware)
     * in that order - though depending on socket option, you may have 0 in
     * some of them.
     */
    printf("\ttimestamps " TIME_FMT TIME_FMT TIME_FMT,
      (uint64_t)ts[0].tv_sec, (uint64_t)ts[0].tv_nsec,
      (uint64_t)ts[1].tv_sec, (uint64_t)ts[1].tv_nsec,
      (uint64_t)ts[2].tv_sec, (uint64_t)ts[2].tv_nsec );
  } else
  {
    printf( "\tno timestamp" );
  }
}


/* Given a packet, extract the timestamp(s) */
static void handle_time(struct msghdr* msg, struct configuration* cfg)
{
  struct timespec* ts = NULL;
  struct cmsghdr* cmsg;

  for( cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg,cmsg) ) {
    if( cmsg->cmsg_level != SOL_SOCKET )
      continue;

    switch( cmsg->cmsg_type ) {
    case SCM_TIMESTAMPNS:
      ts = (struct timespec*) CMSG_DATA(cmsg);
      print_time(ts);
      break;
    case SCM_TIMESTAMPING:
#ifdef ONLOADEXT_AVAILABLE
      if( cfg->cfg_ext == 1 ) {
        struct onload_timestamp* ts = (struct onload_timestamp*) CMSG_DATA(cmsg);
        printf("\text v1 timestamps " OTIME_FMT OTIME_FMT,
          ts[0].sec, ts[0].nsec, ts[1].sec, ts[1].nsec);
        break;
      }
#endif
      ts = (struct timespec*) CMSG_DATA(cmsg);
      print_time(ts);
      break;
#ifdef ONLOADEXT_AVAILABLE
    case SCM_TIMESTAMPING_OOEXT:
      {
        struct scm_timestamping_ooext *t, *tend;
        t = (struct scm_timestamping_ooext *) CMSG_DATA(cmsg);
        tend = t + cmsg->cmsg_len / sizeof *t;
        printf("\text v2 timestamps");
        for (; t != tend; t++)
          print_time_ext2(t);
      }
      break;
#endif
    case SCM_TIMESTAMPING_PKTINFO:
      {
        struct scm_ts_pktinfo *pktinfo;
        pktinfo = (struct scm_ts_pktinfo *) CMSG_DATA(cmsg);
        printf("\tintf %d",
               pktinfo->if_index);
      }
      break;
    default:
      /* Ignore other cmsg options */
      break;
    }
  }
  printf("\n");
}

/* Receive a packet, and print out the timestamps from it */
static int do_recv(int sock, unsigned int pkt_num, struct configuration* cfg)
{
  struct msghdr msg;
  struct iovec iov;
  struct sockaddr_in host_address;
  char buffer[2048];
  char control[1024];
  int got;

  /* recvmsg header structure */
  make_address(0, &host_address);
  iov.iov_base = buffer;
  iov.iov_len = 2048;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_name = &host_address;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  msg.msg_control = control;
  msg.msg_controllen = 1024;

  /* block for message */
  got = recvmsg(sock, &msg, 0);
  if( !got && errno == EAGAIN )
    return 0;

  printf("Packet %d - %d bytes", pkt_num, got);
  handle_time(&msg, cfg);
  return got;
};


int main(int argc, char** argv)
{
  struct configuration cfg;
  int parent, sock, got;
  unsigned int pkt_num = 0;

  parse_options(argc, argv, &cfg);

  /* Initialise */
  parent = add_socket(&cfg);
  do_ioctl(&cfg, parent, true, false);
  sock = parent;
  if( cfg.cfg_protocol == IPPROTO_TCP )
    sock = accept_child(parent);
  do_ts_sockopt(&cfg, sock);

  /* Run forever */
  while((pkt_num++ < cfg.cfg_max_packets || (cfg.cfg_max_packets == 0) ) ) {
    got = do_recv(sock, pkt_num, &cfg);
    /* TCP can detect an exit; for UDP, zero payload packets are valid */
    if ( got == 0 && cfg.cfg_protocol == IPPROTO_TCP ) {
      printf( "recvmsg returned 0 - end of stream\n" );
      break;
    }
  }

  close(sock);
  if( cfg.cfg_protocol == IPPROTO_TCP )
    close(parent);
  return 0;
}
