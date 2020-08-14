/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author Robert Stonehouse
**  \brief Client for sendfile test
**   \date June 2005 
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
/*! \cidoxg_tests_syscalls */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

#include <ci/app.h>

/* For SSL */
#if defined(USE_SSL)
#  include <openssl/crypto.h>
#  include <openssl/x509.h>
#  include <openssl/pem.h>
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#endif

#define BRIGHT 		1
#define BLACK           0
#define RED		1
#define GREEN		2

#define MAX_SOCKETS  4096 /* Adjust in line with sendfile */
#define MAX_THREADS  32
#define CONNECT_FREQ 4000

/* For SSL */
#if defined(USE_SSL)

#  define CHK_NULL(x) if ((x)==NULL) exit (1)
#  define CHK_ERR(err,s) if ((err)==-1) \
                         { fprintf(log, "%s %d\n", (s), errno); exit(1); }
#  define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
#  define SSLerror(sn,rc) SSL_get_error(sockets[sn].ssl, rc)

SSL_CTX* ctx=0;

#endif

/** Command line arguments ****************************************************/

static int cfg_udp = 0;
static int cfg_check = 0;
static unsigned int cfg_threads = 1;

static ci_cfg_desc cfg_opts[] = {
  { 0,   "udp",     CI_CFG_FLAG,  &cfg_udp,    "Use UDP"    },
  { 'c', "check",   CI_CFG_FLAG,  &cfg_check,  "check data integrity" },
  { 0,   "threads", CI_CFG_UINT,  &cfg_threads,  "check data integrity" },
};

#define N_CFG_OPTS  (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

/** Globals *******************************************************************/

/* Structures */
struct socket_s {
  int active;
  int sktfd;
  long int rcvd;
  int off;
#if defined(USE_SSL)
  SSL*     ssl;
#endif
} sockets[MAX_SOCKETS];

struct thread_info {
  pthread_t pthread_info;   /* ID returned by pthread_create() */
  int sn_start;             /* First socket number to consider */
  int sn_end;
} threads[MAX_THREADS];

/* Globals */
static struct sockaddr_in sa;
static unsigned int maxsocks;
static unsigned int nsockets;
static unsigned int nthreads;
static char* msg;
static int msg_size;

void
tcp_connect_socket(int sn, struct sockaddr_in* sa) {
  
  CI_TRY(sockets[sn].sktfd = socket(PF_INET, SOCK_STREAM, 0));
  CI_TRY(connect(sockets[sn].sktfd, (struct sockaddr*) sa,
		 sizeof(struct sockaddr)));

#if defined(USE_SSL) 
  {
    int err;
    sockets[sn].ssl = SSL_new(ctx); 
    CHK_NULL(sockets[sn].ssl);
    SSL_set_fd(sockets[sn].ssl,  sockets[sn].sktfd);
    err = SSL_connect(sockets[sn].ssl); /* This is still blocking */
    CHK_SSL(err);

  }
#endif

  CI_TRY(fcntl(sockets[sn].sktfd, F_SETFL, O_NONBLOCK));
  sockets[sn].active = 1;
  nsockets++;
}


ci_inline void
periodic_socket_check(int* cc, 
		      struct sockaddr_in* sa) {
  static struct timeval tv, last_tv;
  int sn;
  ci_uint64 good=0, bad=0, total=0, nactive=0, average;
  ci_uint64 delta_us;

  /* Try making new connections */
  if (!cfg_udp && (nsockets < maxsocks)) {
    tcp_connect_socket(nsockets, sa);
  }
  *cc = CONNECT_FREQ;

  /* Read the time - if a second passed write to file and reset
   * NB reading from 1st interval may be wrong as not 1 sec
   */
  CI_TRY(gettimeofday(&tv, NULL));
  if (tv.tv_sec != last_tv.tv_sec) {

    printf("\x1B[2J\x1B[0;0H"); /* Clear screen and move to (0,0) */
    printf("Per-stream bandwidth\n");
    if (cfg_udp)
      printf("(note sendfile --udp will only create UDP sockets as per the "
	     "request from the first sendfile_clnt)\n");

    /* Just in case more than 1 second difference */
    delta_us = ((tv.tv_sec - last_tv.tv_sec )-1) * 1000000;
    delta_us += (1000000 - last_tv.tv_usec) + tv.tv_usec;
    
    memcpy(&last_tv, &tv, sizeof(tv));

    for (sn=0 ; sn<MAX_SOCKETS ; sn++) {
      int ok;
      
      if (sockets[sn].active==0)
	continue;
      
      ok = sockets[sn].rcvd >= 320*1024/8; /* 320 kbit/sec */
      if (ok) good++;
      else    bad++;
  
      /* Print all rates if <1024 and upto 32 bad rates */
      if ((!ok && bad<32) || nsockets<1024) {
	if (ok) printf("\x1B[0;32m"); /* Green */
	else    printf("\x1B[0;31m"); /* Red */
	printf("%8.8ld ", sockets[sn].rcvd);
      }
      total += sockets[sn].rcvd;
      sockets[sn].rcvd = 0;
      nactive++;
    }
    printf("\n\x1B[0m"); /* Restore */

    printf("\nDelta(us) %"CI_PRId64"\n", delta_us);

    total = (1000000.0 / delta_us) * total;
    average = total / nactive;
    printf("Good %"CI_PRId64"\n", good);
    printf("Bad %"CI_PRId64"\n", bad);
    printf("Average (delta adjusted) %"CI_PRId64" %"CI_PRId64"Mbps %"CI_PRId64"Gbps\n",
           average, average>>17, average>>27);
    printf("Total (delta adjusted) %"CI_PRId64" %"CI_PRId64"Mbps %"CI_PRId64"Gbps\n",
           total,   total  >>17, total  >>27);
  }
}


void cmp_buf(const char* buf1, const char* buf2, int bytes)
{
  int pos, offset, len;
  
  if( memcmp(buf1, buf2, bytes) == 0)
    return;

  /* Determine byte position of discrepency */
  for(pos=0; (pos<bytes) && (buf1[pos] == buf2[pos]); ++pos);
  
  offset = CI_MAX(pos - 0x40,0) & ~0x10;
  len = 0x80;

  ci_log("Recieved segment fails data validity check at "
	 "pos=0x%x, len=0x%x", pos, bytes);
  ci_log("========");
  ci_hex_dump(ci_log_fn, buf1+offset, len, offset);
  ci_log("========");
  ci_hex_dump(ci_log_fn, buf2+offset, len, offset);
  ci_log("========");

  ci_log("Please ensure that you ran 'sendfile --all'");

  exit(1);
}


void
setup_files(void) {
  int file_fd;

  if( cfg_check ) {
    struct stat sbuf;

    /* try and open randfile... */
    ci_log("--check: Ensure you have randfile in CWD (the same randfile the server uses).");
    ci_log("--check: Ensure you use '-a' on the server");
    
    /* open the file and mmap it */
    CI_TRY(file_fd = open("randfile", O_RDONLY));
    fstat(file_fd, &sbuf);
    msg_size = sbuf.st_size;
    
    msg = (char*) mmap(NULL, msg_size, PROT_READ, MAP_SHARED, file_fd, 0);
    assert(msg);
  }
}


void udp_setup(int port)
{
  int sn, sktfd, bytes;
  unsigned char _maxsocks = maxsocks;
  struct sockaddr_in sa_udp;
  (void)bytes;

  ci_assert_le(maxsocks, 255);

  /* open the sockets before we inform the server about them */
  memcpy(&sa_udp, &sa, sizeof(sa));
  for(sn=0 ; sn<maxsocks ; sn++) {
    CI_TRY(sockets[sn].sktfd = socket(PF_INET, SOCK_DGRAM, 0));    
    sa_udp.sin_port = htons(ntohs(sa.sin_port)+sn);
    sa_udp.sin_addr.s_addr = INADDR_ANY;
    CI_TRY(bind(sockets[sn].sktfd, (struct sockaddr*)&sa_udp, sizeof(sa_udp)));
    CI_TRY(fcntl(sockets[sn].sktfd, F_SETFL, O_NONBLOCK));
    sockets[sn].active = 1;
    nsockets++;
  }

  /* Connect to server to start the data being sent 
   * This will help to ensure that the house net does not get flooded
   * due to defaults routes being used
   */
  CI_TRY(sktfd = socket(PF_INET, SOCK_STREAM, 0));
  sa.sin_port = htons(port);
  CI_TRY(connect(sktfd, (struct sockaddr*) &sa, sizeof(struct sockaddr)));
  /* write to the server */
  bytes = write(sktfd, &_maxsocks, sizeof(_maxsocks));
  ci_assert_equal(bytes, sizeof(_maxsocks));
  close(sktfd);
}


void tcp_setup(int port)
{
  /* First connection */
  tcp_connect_socket(nsockets, &sa);
}


void *main_loop(void *args)
{
  int sn;
  int rc = 0;
  int cc = CONNECT_FREQ;
  char buf[32*1024];
  struct thread_info *ti = args;

  if (ti->sn_start == ti->sn_end)
    return NULL;

  while (1) {
    cc--;

    for(sn=ti->sn_start ; sn < ti->sn_end ; sn++) {

      /* Connect the sockets, create file
       * Do this slowly to avoid overflowing the acceptQ
       */
      if (CI_UNLIKELY(ti->sn_start==0 && cc<=0))
	periodic_socket_check(&cc, &sa);

      if (CI_UNLIKELY(sockets[sn].active==0))
	continue;
      cc--;

      /* Receive data from any socket in a non-blocking way */
#if defined(USE_SSL)
      rc = SSL_read(sockets[sn].ssl, buf, sizeof(buf));
#else
      rc = recv(sockets[sn].sktfd, buf, sizeof(buf),
                MSG_NOSIGNAL | MSG_DONTWAIT);
#endif

      if (rc<0) {
#if defined(USE_SSL)
	if ((SSLerror(sn,rc)!=SSL_ERROR_WANT_READ) && 
	    (SSLerror(sn,rc)!=SSL_ERROR_WANT_WRITE))
#else
	if (errno!=EAGAIN)
#endif
	{
	  CI_TRY(rc);
	  /* TODO: Cleanup in a nicer way */
	  sockets[sn].active = 0;
	}
      }
      else {
	sockets[sn].rcvd += rc;
	if( cfg_check ) {
	  /* This could be n copies of the file */
	  int pos = 0;
	  while (pos < rc) {
	    int bytes_rem = CI_MIN(msg_size - sockets[sn].off, rc - pos);
	    cmp_buf(msg+sockets[sn].off, buf+pos, bytes_rem);
	    sockets[sn].off = (sockets[sn].off + bytes_rem) % msg_size;
	    pos += bytes_rem;
	  }
	  if (cfg_udp) /* always receive the same data as UDP loss can occur */
	    sockets[sn].off = 0;
	}
      }
    }
  } /* while (1) */

  if( cfg_check )
    munmap(msg, msg_size);
}


int
main(int argc, char* argv[]) {
  unsigned int ti, rem;
  int port, sn=0;

  ci_app_getopt("host port num_of_connections",
		&argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;
  if (argc < 3)
    ci_app_usage("Need at least 3 arguments");

#if defined(USE_SSL)
  SSL_METHOD *meth;

  ci_assert_equal(cfg_udp, 0);

  /* SSL init*/
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_client_method();
  SSL_load_error_strings();
  ctx = SSL_CTX_new(meth);
  CHK_NULL(ctx);

#endif

  port = atoi(argv[1]);
  maxsocks = atoi(argv[2]);
  ci_assert_le(maxsocks, MAX_SOCKETS);
  ci_assert_le(cfg_threads, MAX_THREADS);

  CI_TRY(ci_host_port_to_sockaddr_in(argv[0], port, &sa));

  ci_log("For large tests the following will be useful:");
  ci_log("export EF_MAX_PACKETS=65536");
  ci_log("export EF_MAX_ENDPOINTS=32768");
  ci_log("export EF_FDTABLE_SIZE=32768");
  ci_log("export EF_ACCEPT_INHERIT_NONBLOCK=1");
  ci_log("export EF_TCP_SYN_OPTS=4");
  ci_log("export EF_TCP_SNDBUF=1048576");
  ci_log("export EF_TCP_RCVBUF=1048576");
  ci_log("export EF_SOCKET_CACHE_MAX=256");
  ci_log("ulimit -SHn 32768");

  setup_files();
  if (cfg_udp)
    udp_setup(port);
  else
    tcp_setup(port);

  /* Load the first rem threads with 1 extra socket (to account for rounding) */
  rem = maxsocks - ((maxsocks / cfg_threads) * cfg_threads);
  for (ti=0; ti<cfg_threads; ti++) {
    threads[ti].sn_start = sn;
    sn += (maxsocks / cfg_threads) + ((ti<rem) ? 1 : 0);
    threads[ti].sn_end = sn;
    CI_TRY(pthread_create(&threads[ti].pthread_info, NULL, main_loop,
			  &threads[ti]));
    nthreads++;
  }

  while (1)
    sleep(100000);
}
