/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2019 Xilinx, Inc. */
/* Example application to demonstrate use of wire order delivery API.
 *
 * This application will form a dedicated reply connection and N
 * sending connections with the wire_order_server.  Then, for the
 * specified number of iterations, it will pick a sending connection
 * at random and send it a sequence number.  It also regularly polls
 * the reply connection to verify that the echoed replies contain the
 * sequence number in the order expected.
 *
 * If the wire_order_server were not using onload_ordered_epoll_wait()
 * to poll the sockets, the sequence numbers in the reply socket will
 * not match.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "wire_order.h"


#define TEST(x)                                                  \
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


struct sock {
  int fd;
  int outstanding;
};

/* Socket the echo server will reply on
 */
static int reply_sock;

/* List of sockets to the server.  In each iteration, we pick a socket
 * at random and send on it to the server.
 */
static struct sock* socks;


static int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo**ai_out)
{
  struct addrinfo hints;
  hints.ai_flags = 0;
  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  return getaddrinfo(host, port, &hints, ai_out);
}


static int parse_host(const char* s, struct in_addr* ip_out)
{
  const struct sockaddr_in* sin;
  struct addrinfo* ai;
  if( my_getaddrinfo(s, 0, &ai) < 0 )
    return 0;
  sin = (const struct sockaddr_in*) ai->ai_addr;
  *ip_out = sin->sin_addr;
  return 1;
}


static void usage(void)
{
  fprintf(stderr, "\nusage:\n");
  fprintf(stderr, "  wire_order_client [options] <server-address>\n");
  fprintf(stderr, "\noptions:\n");
  fprintf(stderr, "  -n <iterations>         - set number of iterations\n");
  fprintf(stderr, "  -s <number of sockets>  - set number of sockets\n");
  fprintf(stderr, "  -p <port>               - port number to listen on\n");
  fprintf(stderr, "  -b <block time in us>   - sleep between iterations\n");
  fprintf(stderr, "  -u                      - use UDP sockets\n");
  fprintf(stderr, "  -o <max outstanding>    - maximum sends outstanding on ");
  fprintf(stderr, "a single socket (needs\n");
  fprintf(stderr, "                            to stay within send window for");
  fprintf(stderr, " TCP)\n");
  exit(1);
}


/* Polls the reply_sock.  Returns 1 if the reply socket is closed */
static int poll_reply_sock(int cfg_n_iterations)
{
  uint64_t data;
  static int seq = 0;
  int rc;

  if( seq == cfg_n_iterations )
    return 1;

  rc = recv(reply_sock, &data, 8, MSG_DONTWAIT);
  if( rc == -1 ) {
    if( errno == EAGAIN )
      return 0;
    else
      return rc;
  }
  else if( rc == 0 ) {
    return 1;
  }
  else {
    int index = data >> 32;
    int recved_seq = data & 0xffffffff;
    assert(socks[index].outstanding);
    --socks[index].outstanding;
    if( recved_seq != seq ) {
      fprintf(stderr, "recved_seq(%d) != seq(%d)\n", recved_seq, seq);
      exit(1);
    }
    ++seq;
    return 0;
  }
}


int main(int argc, char* argv[])
{
  int rc, i, c, seq = 0;
  struct sockaddr_in sa;
  int cfg_iterations = 10000;
  int32_t cfg_n_socks = 100;
  int cfg_port = DEFAULT_PORT;
  int cfg_udp = 0;
  int nodelay = 1;
  int cnt = 0;
  /* Maximum number of outstanding sends on a socket.  This is necessary
   * so that sends do not block due to congestion window, receive
   * window, etc. which would introduce an artificial reordering that
   * the client will not be able to account for.
   */
  int cfg_outstanding_limit = 4;
  int cfg_sleep = 0;
  uint32_t cfg_flags = 0;
  char cfg_data[WIRE_ORDER_CFG_LEN];

  while( (c = getopt(argc, argv, "un:s:p:o:b:")) != -1 )
    switch( c ) {
    case 'n':
      cfg_iterations = atoi(optarg);
      break;
    case 's':
      cfg_n_socks = atoi(optarg);
      break;
    case 'p':
      cfg_port = atoi(optarg);
      break;
    case 'o':
      cfg_outstanding_limit = atoi(optarg);
      break;
    case 'b':
      cfg_sleep = atoi(optarg);
      break;
    case 'u':
      cfg_udp = 1;
      cfg_flags |= WIRE_ORDER_CFG_FLAGS_UDP;
      break;
    case '?':
      usage();
      fallthrough;
    default:
      TRY(-1);
    }
  argc -= optind;
  argv += optind;
  if( argc != 1 )
    usage();

  printf("Going to run %d iterations over %d sockets\n", cfg_iterations,
         cfg_n_socks);

  socks = calloc(cfg_n_socks, sizeof(*socks));

  bzero(&sa, sizeof(sa));
  sa.sin_family = AF_INET;
  TRY(parse_host(argv[0], &sa.sin_addr));
  sa.sin_port = htons(cfg_port);

  TRY(reply_sock = socket(AF_INET, SOCK_STREAM, 0));
  TRY(connect(reply_sock, (struct sockaddr*) &sa, sizeof(sa)));
  memcpy(&cfg_data[WIRE_ORDER_CFG_FLAGS_OFST], &cfg_flags, sizeof(cfg_flags));
  memcpy(&cfg_data[WIRE_ORDER_CFG_N_SOCKS_OFST], &cfg_n_socks,
         sizeof(cfg_n_socks));
  TRY(send(reply_sock, &cfg_data, WIRE_ORDER_CFG_LEN, 0));

  for( i = 0; i < cfg_n_socks; ++i ) {
    if( cfg_udp ) {
      TRY(socks[i].fd = socket(AF_INET, SOCK_DGRAM, 0));
      sa.sin_port = htons(cfg_port++);
    }
    else {
      TRY(socks[i].fd = socket(AF_INET, SOCK_STREAM, 0));
      TRY(setsockopt(socks[i].fd, SOL_TCP, TCP_NODELAY, &nodelay,
                     sizeof(nodelay)));
    }
    TRY(connect(socks[i].fd, (struct sockaddr*) &sa, sizeof(sa)));
  }

  TRY(recv(reply_sock, &cfg_data, 1, 0));

  srand(time(NULL));
  while( cnt < cfg_iterations ) {
    i = rand() % cfg_n_socks;
    if( socks[i].outstanding < cfg_outstanding_limit ) {
      uint64_t send_data = ((uint64_t)i << 32) | seq++;
      TRY(send(socks[i].fd, &send_data, 8, 0));
      ++cnt;
      ++socks[i].outstanding;
      if( cfg_sleep )
        usleep(cfg_sleep);
    }
    TRY(rc = poll_reply_sock(cfg_iterations));
    assert(rc != 1);
  }

  for( i = 0; i < cfg_n_socks; ++i )
    close(socks[i].fd);
  while( 1 ) {
    TRY(rc = poll_reply_sock(cfg_iterations));
    if( rc == 1 )
      break;
  }

  return 0;
}
