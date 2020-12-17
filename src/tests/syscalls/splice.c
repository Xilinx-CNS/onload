/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2016 Xilinx, Inc. */

/* splice
 *
 * Test app to benchmark performance of splice() syscall.
 *
 * There are several usecases provided.
 *
 *
 * TCP client/server usecase works by a client measuring the cost of
 * ping/pong with an echo server.
 *
 * The echo server does the following:
 *
 * read(sock) -> pipe1 -> pipe2 -> write(sock).
 *
 * You can control exactly which bits of the above transfers happen
 * via splice.
 *
 * Running server with splice:
 * ./splice -t -b -f server 4096 12345
 *
 * Running server without splice:
 * ./splice server 4096 12345
 *
 *
 * Running client:
 * ./splice client 100000 4096 dellr210g2h-l 12345
 *
 *
 * Local usecase measures performance of splice alone or splice
 * interleaved with read/write operations.
 *
 * ./splice local 20000 4096 10
 *
 *
 * Local multithreaded usecase is similar to the local one. However,
 * traffic runs between two threads.
 *
 * ./splice local_mt 20000 4096 10
 *
 *
 * Local suite mode allows running predefined set of local and
 * local multithreaded test cases.
 *
 * ./splice local_suite
 *
 *
 * Copyright 2009-2014 Solarflare Communications Inc.
 * Author: Akhi Singhania
 * Date: 2014/11/13
 */


#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>


#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )


#define TEST(x)                                                  \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )

#define TEST_OP(x,OP,y)                                         \
  do {                                                          \
    int xval=(x);                                               \
    int yval=(y);                                               \
    if( ! (xval OP yval) ) {                                    \
      fprintf(stderr, "ERROR: '%s %s %s' failed: ! %d %s %d\n", \
              #x, #OP, #y, xval, #OP, yval);                    \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )

#define TEST_EQ(x,y) TEST_OP((x),==,(y))
#define TEST_LE(x,y) TEST_OP((x),<=,(y))
#define TEST_GT(x,y) TEST_OP((x),>,(y))


#define  MIN(a,b) (((a)<(b))?(a):(b))


static int cfg_splice_from;
static int cfg_splice_to;
static int cfg_splice_between;


static void usage(void)
{
  fprintf(stderr, "\nusage:\n");
  fprintf(stderr, "  splice [options] server <msg-size> <port>\n");
  fprintf(stderr, "  splice client <iterations> <msg-size> <host> <port>\n");
  fprintf(stderr, "  splice local <iterations> <msg-size> "
                  "[<part_of_msg_to_read_or_write>] [<use_splice>]\n");
  fprintf(stderr, "  splice local_mt <iterations> <msg-size> "
                  "[<part_of_msg_to_read_or_write>] [<use_splice>]\n");
  fprintf(stderr, "\noptions:\n");
  fprintf(stderr, "  -t  - splice to socket\n");
  fprintf(stderr, "  -b  - splice between pipes\n");
  fprintf(stderr, "  -f  - splice from socket\n");
  fprintf(stderr, "\n");
  exit(1);
}


static void srv_splice(int sock, int* recv_pipe, int* reply_pipe, char* buf,
                       int msg_size)
{
  int rc, cnt;

  while( 1 ) {
    cnt = 0;
    while( cnt != msg_size ) {
      if( cfg_splice_from ) {
        rc = splice(sock, NULL, recv_pipe[1], NULL, msg_size - cnt, 0);
        TEST(rc >= 0);
        if( rc == 0 )
          return;
      }
      else {
        rc = read(sock, buf, msg_size - cnt);
        TEST(rc >= 0);
        if( rc == 0 )
          return;
        TEST(write(recv_pipe[1], buf, rc) == rc);
      }

      if( cfg_splice_between ) {
        TEST(splice(recv_pipe[0], NULL, reply_pipe[1], NULL, rc, 0) == rc);
      }
      else {
        TEST(read(recv_pipe[0], buf, rc) == rc);
        TEST(write(reply_pipe[1], buf, rc) == rc);
      }

      if( cfg_splice_to ) {
        TEST(splice(reply_pipe[0], NULL, sock, NULL, rc, 0) == rc);
      }
      else {
        TEST(read(reply_pipe[0], buf, rc) == rc);
        TEST(write(sock, buf, rc) == rc);
      }
      cnt += rc;
    }
  }
}


static void server(int argc, char* argv[])
{
  if( argc != 3 )
    usage();
  int msg_size = atoi(argv[1]);
  int port = atoi(argv[2]);
  int one = 1;
  int recv_pipe[2], reply_pipe[2];
  char* buf = malloc(sizeof(*buf) * msg_size);
  TEST(buf);

  int lsock = socket(AF_INET, SOCK_STREAM, 0);
  TEST(lsock);
  struct sockaddr_in sa;
  sa.sin_family = AF_INET;
  sa.sin_port = htons((unsigned short) port);
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  TRY(bind(lsock, (struct sockaddr*)&sa, sizeof(sa)));
  TRY(setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one)));
  TRY(listen(lsock, 1));
  TRY(pipe(recv_pipe));
  TRY(pipe(reply_pipe));

  while( 1 ) {
    int sock = accept(lsock, NULL, NULL);
    TEST(sock);
    srv_splice(sock, recv_pipe, reply_pipe, buf, msg_size);
    close(sock);
  }
}


static int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo** ai_out)
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


static void client_iteration(int sock, char* buf, int msg_size)
{
  int cnt, rc;

  TEST(write(sock, buf, msg_size) == msg_size);
  cnt = 0;
  while( cnt != msg_size ) {
    rc = read(sock, buf, msg_size - cnt);
    TEST(rc > 0);
    cnt += rc;
  }
}


static void client(int argc, char* argv[])
{
  if( argc != 5 )
    usage();
  struct sockaddr_in sa;
  int i, warmup = 10;
  int iterations = atoi(argv[1]);
  int msg_size = atoi(argv[2]);
  char* host = argv[3];
  int port = atoi(argv[4]);
  struct timespec start, stop;
  uint64_t nsec;

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  TEST(sock);
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  TRY(parse_host(host, &sa.sin_addr));
  sa.sin_port = htons(port);
  TRY(connect(sock, (struct sockaddr*)&sa, sizeof(sa)));

  char* buf = calloc(msg_size, sizeof(*buf));
  TEST(buf);
  snprintf(buf, msg_size, "deadbeef");

  for( i = 0; i < warmup; ++i )
    client_iteration(sock, buf, msg_size);

  TRY(clock_gettime(CLOCK_REALTIME, &start));
  for( i = 0; i < iterations; ++i )
    client_iteration(sock, buf, msg_size);
  TRY(clock_gettime(CLOCK_REALTIME, &stop));
  nsec = ((uint64_t)stop.tv_sec - start.tv_sec) * 1000000000;
  nsec += stop.tv_nsec - start.tv_nsec;
  printf("Round-trip time: %0.3f nsec\n", (double) nsec / iterations);
}


struct local_mt_context {
  int from_fd;
  int to_fd;
  int msg_size;
  int iterations;
  int flags;
  int splice;
  void* buf;

  volatile int done;
};


static void splice_all(int from_fd, int to_fd, int max_size,
                       size_t total_size, int flags)
{
  int rc;
  for( ; total_size; total_size -= rc ) {
    rc = splice(from_fd, NULL, to_fd, NULL, MIN(max_size, total_size), flags);
    TEST_LE(rc, max_size);
    TEST_GT(rc, 0);
  }
}


static void copy_all(int from_fd, int to_fd, void* buf,
                     int max_size, size_t total_size, int flags)
{
  int rc, to_write, written;

  (void) flags;

  for( ; total_size; total_size -= rc ) {
    rc = read(from_fd, buf, MIN(max_size, total_size) );
    TEST_LE(rc, max_size);
    TEST_GT(rc, 0);

    to_write = rc;
    for( written = 0; written != to_write; written += rc )
    {
      rc = write(to_fd, (char*)buf + written, rc);
      TEST_LE(rc, max_size);
      TEST_GT(rc, 0);
    }
  }
}


static void* local_mt_thread(void* arg)
{
  struct local_mt_context* c = (struct local_mt_context*) arg;
  size_t total_size = (size_t) c->msg_size * c->iterations;
  if( c->splice )
    splice_all(c->from_fd, c->to_fd, c->msg_size, total_size, c->flags);
  else
    copy_all(c->from_fd, c->to_fd, c->buf, c->msg_size, total_size, c->flags);
  c->done = 1;
  return NULL;
}

static void local_mt(int argc, char* argv[])
{
  int iterations = atoi(argv[0]);
  int msg_size = atoi(argv[1]);
  int i_rw_size = (argc>2)?atoi(argv[2]):0;
  int do_splice = (argc>3)?atoi(argv[3]):1;
  TEST( i_rw_size <= msg_size );
  int pipea[2], pipeb[2];

  struct timespec start, stop;
  uint64_t nsec;
  int i;

  int* buf = (int*) calloc(msg_size, sizeof(*buf));
  int* buf2 = (int*) calloc(msg_size, sizeof(*buf));
  int* refbuf = (int*) calloc(msg_size+sizeof(int), sizeof(*buf));
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  close(sock);


  printf("iterations = %d, msg_size = %d, i_rw_size = %d, do_splice = %d\n",
         iterations, msg_size, i_rw_size, do_splice);

  TRY(pipe(pipea));
  TRY(pipe(pipeb));

  for( i = 0; i < msg_size/sizeof(*buf) + 1; ++i)
    refbuf[i] = i;

  memcpy(buf, refbuf, msg_size);
  int flags = SPLICE_F_MOVE;

  struct local_mt_context c = {
     .from_fd = pipeb[0],
     .to_fd = pipea[1],
     .msg_size = msg_size,
     .iterations = iterations,
     .splice = do_splice,
     .buf = (char*) buf2,
     .flags = flags
  };

  pthread_t t;
  TRY(pthread_create(&t, NULL, local_mt_thread, (void*)&c));

  TRY(clock_gettime(CLOCK_REALTIME, &start));

  int rc = write(pipea[1], buf, msg_size);
  TEST(rc > 0);
  for( i = 0; i < iterations; ++i) {
    if( i_rw_size ) {
      copy_all(pipea[0], pipeb[1], buf, i_rw_size, i_rw_size, 0);
    }
    int rem = msg_size - i_rw_size;
    if( rem ) {
      if( do_splice )
        splice_all(pipea[0], pipeb[1], rem, rem, flags);
      else
        copy_all(pipea[0], pipeb[1], buf, rem, rem, flags);
    }
  }
  while( ! c.done );
  int sz;
  TEST(ioctl(pipea[0], FIONREAD, &sz) == 0);
  TEST_EQ(sz, msg_size);
  TEST_EQ(read(pipea[0], buf, msg_size), msg_size);

  TRY(clock_gettime(CLOCK_REALTIME, &stop));
  nsec = ((uint64_t)stop.tv_sec - start.tv_sec) * 1000000000;
  nsec += stop.tv_nsec - start.tv_nsec;
  printf("Round-trip time: %0.3f nsec\n", (double) nsec / iterations);

  TEST(memcmp(buf, refbuf, msg_size) == 0);
  close(pipea[0]);
  close(pipea[1]);
  close(pipeb[0]);
  close(pipeb[1]);
  free(buf);
  free(buf2);
  free(refbuf);
}


static void local(int argc, char* argv[])
{
  int iterations  = atoi(argv[0]);
  int msg_size    = atoi(argv[1]);
  int i_rw_size   = (argc>2)?atoi(argv[2]):0;
  int do_splice   = (argc>3)?atoi(argv[3]):1;
  int verify_data = (argc>4)?atoi(argv[4]):1;
  TEST( i_rw_size <= msg_size );
  int pipea[2], pipeb[2];

  struct timespec start, stop;
  uint64_t nsec;
  int i;

  int* buf = (int*) calloc(msg_size, sizeof(*buf));
  int* refbuf = (int*) calloc(msg_size, sizeof(*buf));
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  close(sock);


  TRY(pipe(pipea));
  TRY(pipe(pipeb));

  printf("iterations = %d, msg_size = %d, i_rw_size = %d, do_splice = %d\n",
         iterations, msg_size, i_rw_size, do_splice);

  for( i = 0; i < msg_size; ++i)
    refbuf[i] = i;

  memcpy(buf, refbuf, msg_size);

  TRY(clock_gettime(CLOCK_REALTIME, &start));

  int flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;
  int rc = write(pipea[1], buf, msg_size);
  TEST(rc > 0);
  for( i = 0; i < iterations; ++i) {
    if( i_rw_size ) {
      int irc;
      irc = read(pipea[0], buf, i_rw_size);
      if( irc < 0 )
        fprintf(stderr, "errno = %d\n", errno);
      TEST_EQ(irc, i_rw_size);
      irc = write(pipeb[1], buf, i_rw_size);
      if( irc < 0 )
        fprintf(stderr, "errno = %d\n", errno);
      TEST_EQ(irc, i_rw_size);
    }
    if( msg_size - i_rw_size ) {
      rc = splice(pipea[0], NULL, pipeb[1], NULL, msg_size - i_rw_size, flags);
      TEST(rc == msg_size - i_rw_size);
    }
    if( do_splice )
      rc = splice(pipeb[0], NULL, pipea[1], NULL, msg_size, flags);
    else {
      copy_all(pipeb[0], pipea[1], buf, msg_size, msg_size, flags);
      rc = msg_size;
    }
    TEST(rc == msg_size);
    if( verify_data ) {
      memset(buf, 0xff, msg_size);
      TEST_EQ(read(pipea[0], buf, msg_size), msg_size);
      if( memcmp(buf, refbuf, msg_size) != 0 ) {
        int j;
        fprintf(stderr, "buf: ");
        for( j = 0; j < msg_size; ++j )
          fprintf(stderr, "%02X ", buf[j]);
        fprintf(stderr, "\nrefbuf: ");
        for( j = 0; j < msg_size; ++j )
          fprintf(stderr, "%02X ", refbuf[j]);
        fprintf(stderr, "\n");
        TEST(0);
      }
      rc = write(pipea[1], buf, msg_size);
      TEST(rc > 0);
    }
  }
  int sz;
  TEST(ioctl(pipea[0], FIONREAD, &sz) == 0);
  TEST_EQ(sz, msg_size);
  TEST_EQ(read(pipea[0], buf, msg_size), msg_size);

  TRY(clock_gettime(CLOCK_REALTIME, &stop));
  nsec = ((uint64_t)stop.tv_sec - start.tv_sec) * 1000000000;
  nsec += stop.tv_nsec - start.tv_nsec;
  printf("Round-trip time: %0.3f nsec\n", (double) nsec / iterations);

  TEST(memcmp(buf, refbuf, msg_size) == 0);
  close(pipea[0]);
  close(pipea[1]);
  close(pipeb[0]);
  close(pipeb[1]);
  free(buf);
  free(refbuf);
}


void local_suite(void)
{
  const char* tests[]={
    "2 10",
    "2000 11",
    "200000 1",
    "200000 7",
    "200000 7 7",
    "20000 1400",
    "20000 1400 1400",
    "20000 256",
    "20000 1855",
    "20000 1856",
    "20000 1857",
    "20000 4095",
    "20000 4096",
    "20000 4097",
    "20000 48000",
    "20000 64000",
    "2 10 1",
    "200000 10 1",
    "200000 7 5",
    "20000 1400 221",
    "20000 1855 1",
    "20000 1856 1",
    "20000 1857 1",
    "20000 4095 1",
    "20000 4096 1",
    "20000 4096 4095",
    "20000 4096 4096",
    "20000 4097 4096",
    "20000 4097 4097",
    "20000 48000 1",
    "20000 48000 48000",
    "20000 48000 47999",
    /* "20000 64000 1", RHEL6.5 kernel pipes fail here */
    NULL
  };
  int i, j;
  typeof(local)* f[3] = { &local, &local_mt, NULL };
  for( j = 0; f[j]; ++j )
  for( i = 0; tests[i] != NULL; ++i) {
    char* argv[5];
    char* p;
    int argc = 0;
    char* s = strdup(tests[i]);
    p = strtok(s, " ");
    while(p != NULL ) {
      argv[argc++] = p;
      p = strtok(NULL, " ");
    }
    printf("Test case %2d:%2d %-24s: ",j, i, tests[i]);
    f[j](argc, argv);
    free(s);
  }
}

int main(int argc, char* argv[])
{
  int c;

  while( (c = getopt(argc, argv, "tbf")) != -1 )
    switch( c ) {
    case 't':
      cfg_splice_to = 1;
      break;
    case 'b':
      cfg_splice_between = 1;
      break;
    case 'f':
      cfg_splice_from = 1;
      break;
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;

  if( argc < 2 )
    usage();
  if( ! strcmp(argv[0], "local") )
    local(argc - 1, argv + 1);
  else if( ! strcmp(argv[0], "local_mt") )
    local_mt(argc - 1, argv + 1);
  else if( ! strcmp(argv[0], "local_suite") )
    local_suite();
  else if( ! strcmp(argv[0], "server") )
    server(argc, argv);
  else if( ! strcmp(argv[0], "client") )
    client(argc, argv);
  else
    usage();
  return 0;
}
