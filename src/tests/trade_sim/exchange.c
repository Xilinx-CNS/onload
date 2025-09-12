/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2015-2019 Xilinx, Inc. */
/* exchange.c
 *
 * Copyright 2015 Solarflare Communications Inc.
 * Author: David Riddoch
 *
 * Please see README for details.
 */

#include "utils.h"

#include <onload/extensions.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <time.h>
#include <net/if.h>
#include <stdarg.h>


/* We use a special message to trigger the client to send a message on the
 * TCP socket.  This message is chosen for compatibility with the AOE ANTS
 * sample application.
 */
#define INTERESTING_MSG    "hit me 0 0"
#define BORING_MSG         "boring"


static const char* cfg_port = "8122";
static const char* cfg_mcast_addr = "224.1.2.3";
static int         cfg_measure_nth = 10;
static int         cfg_log_level = 1;
static bool        cfg_hw_ts = true;
static int         cfg_send_rate = 100000;
static int         cfg_iter;
static int         cfg_warm_n;


struct server_state {
  int      epoll;
  int      listen_sock;
  int      tcp_sock;
  int      udp_sock;
  int      udp_sock_ts;
  bool     have_sent;
  bool     have_rx_ts;
  bool     have_tx_ts;
  int      rx_msg_size;
  int      tx_msg_size;
  char*    rx_buf;
  char*    tx_buf;
  char*    tx_buf_ts;
  int      inter_tx_gap_ns;
  uint64_t rtt_sum;
  unsigned rtt_min, rtt_max;
  int      rtt_n;
  unsigned n_lost_msgs;
};


static void msg(int level, const char* fmt, ...)
{
  if( level <= cfg_log_level ) {
    va_list vargs;
    va_start(vargs, fmt);
    vfprintf(stderr, fmt, vargs);
    va_end(vargs);
  }
}


static int max_i(int a, int b)
{
  return a > b ? a : b;
}


static void timespec_add_ns(struct timespec* ts, unsigned long ns)
{
  assert( ns < 1000000000 );
  if( (ts->tv_nsec += ns) >= 1000000000 ) {
    ts->tv_nsec -= 1000000000;
    ts->tv_sec += 1;
  }
}


static int64_t timespec_diff_ns(struct timespec a, struct timespec b)
{
  return (a.tv_sec - b.tv_sec) * (int64_t) 1000000000
    + (a.tv_nsec - b.tv_nsec);
}


static bool timespec_le(struct timespec a, struct timespec b)
{
  return a.tv_sec < b.tv_sec ||
    (a.tv_sec == b.tv_sec && a.tv_nsec <= b.tv_nsec);
}


/*
 * Like a recv() call, except that it also returns a h/w timestamp.
 */
static int recv_ts(int sock, void* buf, size_t len, int flags,
                   struct timespec* ts)
{
  struct msghdr msg;
  struct iovec iov = { buf, len };
  char cmsg_buf[512];
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_namelen = 0;
  msg.msg_control = cmsg_buf;
  msg.msg_controllen = sizeof(cmsg_buf);
  msg.msg_flags = 0;  /* work-around for onload bug57094 */
  int rc = recvmsg(sock, &msg, flags);
  if( rc > 0 ) {
    assert( ! (msg.msg_flags & MSG_CTRUNC) );
    struct cmsghdr* cmsg;
    for( cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg) )
      if( cmsg->cmsg_level == SOL_SOCKET &&
          cmsg->cmsg_type == SO_TIMESTAMPING ) {
        memcpy(ts, (char*) CMSG_DATA(cmsg) + 2 * sizeof(struct timespec),
               sizeof(*ts));
        if( ts->tv_sec != 0 )
          return rc;
      }
    errno = ETIME;
    rc = -1;
  }
  return rc;
}


static void wait_for_client(struct server_state* ss)
{
  msg(1, "Waiting for client to connect\n");
  TRY( listen(ss->listen_sock, 1) );
  TRY( ss->tcp_sock = accept(ss->listen_sock, NULL, NULL) );
  msg(1, "Accepted client connection\n");
  TRY( shutdown(ss->listen_sock, SHUT_RD) );

  struct epoll_event e;
  e.events = EPOLLIN;
  e.data.fd = ss->tcp_sock;
  TRY( epoll_ctl(ss->epoll, EPOLL_CTL_ADD, ss->tcp_sock, &e) );

  if( cfg_hw_ts ) {
    e.events = EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLPRI;
    e.data.fd = ss->udp_sock_ts;
    TRY( epoll_ctl(ss->epoll, EPOLL_CTL_ADD, ss->udp_sock_ts, &e) );
  }

  if( cfg_hw_ts ) {
    int tsm = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
    int rc = setsockopt(ss->tcp_sock, SOL_SOCKET, SO_TIMESTAMPING,
                        &tsm, sizeof(tsm));
    if( rc < 0 ) {
      fprintf(stderr, "ERROR: failed to enable h/w timestamping for TCP RX\n");
      exit(5);
    }
  }
  int one = 1;
  TRY( setsockopt(ss->tcp_sock, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) );
  ss->rx_msg_size = sock_get_int(ss->tcp_sock);
  ss->tx_msg_size = sock_get_int(ss->tcp_sock);
  int min_tx_msg = max_i(strlen(INTERESTING_MSG), strlen(BORING_MSG));
  if( ss->tx_msg_size < min_tx_msg ) {
    fprintf(stderr, "ERROR: UDP message size %d less than minimum %d\n",
            ss->tx_msg_size, min_tx_msg);
    exit(6);
  }
  ss->tx_buf = malloc(ss->tx_msg_size);
  strncpy(ss->tx_buf, BORING_MSG, ss->tx_msg_size);
  ss->tx_buf_ts = malloc(ss->tx_msg_size);
  strncpy(ss->tx_buf_ts, INTERESTING_MSG, ss->tx_msg_size);
  ss->rx_buf = malloc(ss->rx_msg_size);

  if( cfg_iter == 0 )
    cfg_iter = 5/*seconds*/ * cfg_send_rate / cfg_measure_nth;
  if( cfg_warm_n == 0 ) {
    cfg_warm_n = cfg_iter / 10;
    if( cfg_warm_n == 0 )
      cfg_warm_n = 2;
  }
  ss->rtt_sum = 0;
  ss->rtt_min = -1;
  ss->rtt_max = 0;
  ss->rtt_n = -cfg_warm_n;
}


static void measured_rtt(struct server_state* ss, struct timespec tx_ts,
                         struct timespec rx_ts)
{
  ss->have_sent = ss->have_rx_ts = ss->have_tx_ts = false;
  uint64_t ns = (rx_ts.tv_sec - tx_ts.tv_sec) * 1000000000;
  ns += rx_ts.tv_nsec - tx_ts.tv_nsec;
  msg(2, "rtt: %d\n", (int) ns);
  if( ++(ss->rtt_n) > 0 ) {
    ss->rtt_sum += ns;
    if( ns <= ss->rtt_min )
      ss->rtt_min = ns;
    else if( ns >= ss->rtt_max )
      ss->rtt_max = ns;
    if( ss->rtt_n == cfg_iter ) {
      printf("n_lost_msgs:  %u\n", ss->n_lost_msgs);
      printf("n_samples:    %d\n", ss->rtt_n);
      printf("latency_mean: %u\n", (unsigned) (ss->rtt_sum / ss->rtt_n));
      printf("latency_min:  %u\n", ss->rtt_min);
      printf("latency_max:  %u\n", ss->rtt_max);
      exit(0);
    }
  }
}


static void event_loop(struct server_state* ss)
{
  msg(1, "Starting event loop\n");

  struct timespec tx_ts, rx_ts, next_tx_ts, lost_tx_ts = { 0, 0 };
  ss->have_sent = ss->have_tx_ts = ss->have_rx_ts = false;
  int rc, rx_left = ss->rx_msg_size;
  unsigned send_i = 0;

  clock_gettime(CLOCK_REALTIME, &next_tx_ts);
  timespec_add_ns(&next_tx_ts, ss->inter_tx_gap_ns);

  while( 1 ) {
    struct epoll_event e;
    TRY( rc = epoll_wait(ss->epoll, &e, 1, 0) );

    if( rc == 0 ) {
      struct timespec now;
      clock_gettime(CLOCK_REALTIME, &now);
      if( ! timespec_le(next_tx_ts, now) )
        continue;
      timespec_add_ns(&next_tx_ts, ss->inter_tx_gap_ns);
      if( ++send_i >= cfg_measure_nth && ! ss->have_sent ) {
        msg(3, "Send message (timed)\n");
        TEST( send(ss->udp_sock_ts, ss->tx_buf_ts, ss->tx_msg_size, 0)
                == ss->tx_msg_size );
        if( ! cfg_hw_ts ) {
          ss->have_tx_ts = true;
          tx_ts = now;
        }
        send_i = 0;
        ss->have_sent = true;
      }
      else {
        msg(3, "Send message\n");
        TEST( send(ss->udp_sock, ss->tx_buf, ss->tx_msg_size, 0)
                == ss->tx_msg_size );
        if( send_i >= cfg_measure_nth ) {
          /* Not had a reply to last timed message.  Try to detect lost
           * messages.
           */
          if( send_i == cfg_measure_nth ) {
            lost_tx_ts = now;
          }
          else if( ss->have_tx_ts &&
                   timespec_diff_ns(now, lost_tx_ts) > 10000000 ) {
            msg(2, "WARNING: No response to timed message\n");
            if( ss->rtt_n > 0 )
              ++(ss->n_lost_msgs);
            ss->have_sent = false;
            ss->have_tx_ts = false;
            ss->have_rx_ts = false;
          }
        }
      }
    }

    else if( e.data.fd == ss->tcp_sock ) {
      TEST( e.events & EPOLLIN );
      if( cfg_hw_ts ) {
        rc = recv_ts(ss->tcp_sock, ss->rx_buf, rx_left, MSG_DONTWAIT, &rx_ts);
      }
      else {
        rc = recv(ss->tcp_sock, ss->rx_buf, rx_left, MSG_DONTWAIT);
        clock_gettime(CLOCK_REALTIME, &rx_ts);
      }
      if( rc > 0 ) {
        msg(3, "Received %d from client at %d.%09d\n", rc,
            (int) rx_ts.tv_sec, (int) rx_ts.tv_nsec);
        if( (rx_left -= rc) == 0 ) {
          send(ss->tcp_sock, ss->rx_buf, 1, MSG_NOSIGNAL);
          rx_left = ss->rx_msg_size;
          ss->have_rx_ts = true;
          if( ss->have_tx_ts )
            measured_rtt(ss, tx_ts, rx_ts);
        }
      }
      else if( rc == 0 || errno == ECONNRESET ) {
        break;
      }
      else if( errno == ETIME ) {
        fprintf(stderr, "ERROR: Did not get H/W timestamp on RX\n");
        exit(3);
      }
      else {
        TRY( rc );
      }
    }

    else if( e.data.fd == ss->udp_sock_ts ) {
      assert( cfg_hw_ts );
      assert( ! ss->have_tx_ts );
      TEST( recv_ts(ss->udp_sock_ts, ss->rx_buf, 1,
                    MSG_ERRQUEUE | MSG_DONTWAIT, &tx_ts) == 1 );
      msg(3, "TX timestamp %d.%09d\n", (int) tx_ts.tv_sec,
             (int) tx_ts.tv_nsec);
      ss->have_tx_ts = true;
      if( ss->have_rx_ts )
        measured_rtt(ss, tx_ts, rx_ts);
    }
  }

  msg(1, "Client disconnected\n");
  TRY( close(ss->tcp_sock) );
}


/**********************************************************************/

static int mk_udp_sock(const char* mcast_intf, bool enable_timestamping)
{
  int sock;
  TRY( sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) );
  if( mcast_intf != NULL ) {
    struct ip_mreqn mreqn;
    mreqn.imr_multiaddr.s_addr = htonl(INADDR_ANY);
    mreqn.imr_address.s_addr = htonl(INADDR_ANY);
    TEST( (mreqn.imr_ifindex = if_nametoindex(mcast_intf)) != 0 );
    TRY( setsockopt(sock, SOL_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) );
  }
  /* NB. We have to connect after doing IP_MULTICAST_IF else we may bind to
   * the wrong local address.
   */
  struct sockaddr_storage sas;
  TRY( getaddrinfo_storage(AF_INET, cfg_mcast_addr, cfg_port, &sas) );
  TRY( connect(sock, (void*) &sas, sizeof(sas)) );
  if( enable_timestamping ) {
    int tsm = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE;
    int rc = setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &tsm, sizeof(tsm));
    if( rc < 0 )
      fprintf(stderr, "ERROR: failed to enable h/w timestamping for UDP TX\n");
  }
  return sock;
}


static void init(struct server_state* ss, const char* mcast_intf)
{
  TRY( ss->listen_sock = mk_socket(0, SOCK_STREAM, bind, NULL, cfg_port) );
  TRY( ss->udp_sock = mk_udp_sock(mcast_intf, false) );
  TRY( ss->udp_sock_ts = mk_udp_sock(mcast_intf, cfg_hw_ts) );
  TRY( ss->epoll = epoll_create(10) );
  ss->inter_tx_gap_ns = 1000000000 / cfg_send_rate;
  ss->n_lost_msgs = 0;
}


static void usage_msg(FILE* f)
{
  fprintf(f, "\nusage:\n");
  fprintf(f, "  exchange [options] <mcast-interface>\n");
  fprintf(f, "\noptions:\n");
  fprintf(f, "  -h                - print usage info\n");
  fprintf(f, "  -r <send-rate>    - set UDP message send rate\n");
  fprintf(f, "  -n <n>            - measure latency for 1-in-n sends\n");
  fprintf(f, "  -i <num-iter>     - number of samples to measure\n");
  fprintf(f, "  -w <num-warmups>  - number of warmup samples\n");
  fprintf(f, "  -s                - use software timestamps\n");
  fprintf(f, "  -l <log-level>    - set log level\n");
  fprintf(f, "  -p <port>         - set TCP/UDP port number\n");
  fprintf(f, "\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


int main(int argc, char* argv[])
{
  int c;

  while( (c = getopt(argc, argv, "hr:n:i:w:sl:p:")) != -1 )
    switch( c ) {
    case 'h':
      usage_msg(stdout);
      exit(0);
      break;
    case 'r':
      cfg_send_rate = atoi(optarg);
      break;
    case 'n':
      cfg_measure_nth = atoi(optarg);
      break;
    case 'i':
      cfg_iter = atoi(optarg);
      break;
    case 'w':
      cfg_warm_n = atoi(optarg);
      break;
    case 's':
      cfg_hw_ts = false;
      break;
    case 'l':
      cfg_log_level = atoi(optarg);
      break;
    case 'p':
      cfg_port = optarg;
      break;
    case '?':
      usage_err();
      break;
    default:
      TEST(0);
      break;
    }
  argc -= optind;
  argv += optind;
  if( argc != 1 )
    usage_err();
  const char* mcast_intf = argv[0];

  if( onload_is_present() ) {
    if( cfg_hw_ts ) {
      TRY( onload_stack_opt_set_int("EF_RX_TIMESTAMPING", 3) );
      TRY( onload_stack_opt_set_int("EF_TX_TIMESTAMPING", 3) );
    }
  }
  else if( cfg_hw_ts ) {
    fprintf(stderr, "ERROR: Cannot use hardware timestamp because Onload is "
            "not being used.  You can use -s to use software timestamps, but "
            "they are much less accurate.\n");
    exit(4);
  }
  else {
    msg(1, "Using software timestamps\n");
    cfg_hw_ts = false;
  }

  struct server_state ss;
  init(&ss, mcast_intf);
  wait_for_client(&ss);
  event_loop(&ss);
  return 0;
}

/*! \cidoxg_end */
