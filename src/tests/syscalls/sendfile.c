/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2015 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author Robert Stonehouse
**  \brief Test for sendfile() and sends()
**   \date May 2005 
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
/*! \cidoxg_tests_syscalls */

/**************************************************************************
** This is a single threaded non-blocking app
**   It emulates a webserver, listening on a port and sendfile()'s data to
**    all the clients that connect
**   In UDP mode it waits for a TCP connection and then sendfile()'s data to
**    the sender to port+1 thru port+1+maxports
**   Connect to it using sendfile_clnt 
** Setup: randfile needs to be in $CWD. Any file will do >8k
** For SSL server.pem and server.key need to be in $CWD
\**************************************************************************/

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ci/app.h>

/* For SSL */
#if defined(USE_SSL)
#  include <openssl/crypto.h>
#  include <openssl/x509.h>
#  include <openssl/pem.h>
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#endif

/* Some distro don't have this in the userland headers */
#ifndef UDP_CORK
#  define UDP_CORK	1
#endif

/* Defines */
#define RAND_LT(x) ((unsigned int)((x+0.0)*rand()/(RAND_MAX+1.0)))

#define MAX_SOCKETS  4096 /* Adjust in line with sendfile_clnt */
#define ACCEPT_FREQ  4000

#define SMALL_SEG_LEN 16
#define UDP_MAX_SIZE 64*1024

/* For SSL */
#if defined(USE_SSL)

#  define CERTF "server.crt"
#  define KEYF  "server.key"

#  define CHK_NULL(x) if ((x)==NULL) exit (1)
#  define CHK_ERR(err,s) if ((err)==-1) \
                         { fprintf(log, "%s %d\n", (s), errno); exit(1); }
#  define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
#  define SSLerror(sn,rc) SSL_get_error(sockets[sn].ssl, rc)
#  define USE_CERT 1

SSL_CTX* ctx=0;

#endif

/** Globals *******************************************************************/

struct socket_s {
  int active;
  int sktfd;
  size_t len; /* Generated so SSL command can be repeated */
  size_t corked_len;
  off_t off;
  int corked;
#if defined(USE_SSL)
  SSL*     ssl;
#endif
} sockets[MAX_SOCKETS];

static unsigned int file_len;

/** Command line arguments ****************************************************/
static int cfg_udp = 0;
static int cfg_min_len = 1;
static int cfg_max_len = 16*1024;
static int cfg_fixed_len   = -1;
static int cfg_fixed_off   = -1;
static unsigned int cfg_all = 0;
static unsigned cfg_pc_small_segs = 10;
static unsigned cfg_pc_cork = 80;
static unsigned cfg_pc_uncork = 20;
static unsigned cfg_threads = 1;

static ci_cfg_desc cfg_opts[] = {
  { 0,   "udp",          CI_CFG_FLAG, &cfg_udp,          "use UDP" },
  { 0,   "min_len",      CI_CFG_UINT, &cfg_min_len,      "minimum sendfile length" },
  { 0,   "max_len",      CI_CFG_UINT, &cfg_max_len,      "maximum sendfile length" },
  { 'l', "fixed_len",    CI_CFG_UINT, &cfg_fixed_len,    "fix the length otherwise random" },
  { 'o', "fixed_off",    CI_CFG_UINT, &cfg_fixed_off,    "fix the offset otherwise random" },
  { 'a', "all",          CI_CFG_FLAG, &cfg_all,          "send the entire file. For use with client -c" },
  { 0,   "pc_small_segs",CI_CFG_UINT, &cfg_pc_small_segs,"%%age of small segments" },
  { 0,   "pc_cork",      CI_CFG_UINT, &cfg_pc_cork,      "%%age of fragments for which the socket is corked" },
  { 0,   "pc_uncork",    CI_CFG_UINT, &cfg_pc_uncork,    "%%age of fragments for which the socket is corked" },
  { 0,   "threads",      CI_CFG_UINT, &cfg_threads,      "the number of threads" },
};
#define N_CFG_OPTS  (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

/******************************************************************************/

/* Return a length for the next sendfile() */
ci_inline unsigned get_len(unsigned int max_len) {
  unsigned int len;
  if (cfg_fixed_len != -1) { 
    len = cfg_fixed_len;
  } else {
    unsigned int range = max_len - cfg_min_len;

    if (RAND_LT(100) < cfg_pc_small_segs) 
      range = SMALL_SEG_LEN - cfg_min_len;

    len = cfg_min_len + RAND_LT(range);
  }
  return(len);
}

/* Return an offset for the next sendfile() */
ci_inline ci_uint32 get_off(void) {
  ci_uint32 off;
  if (cfg_fixed_off == -1) { off = RAND_LT(4096); }
  else                     { off = cfg_fixed_off; }

  ci_assert_lt(off, cfg_max_len);
  return(off);
}


/* Accept a new connection */
int
tcp_accept_socket(int lstn_fd, int* nsockets) 
{ 
  struct sockaddr_in clnt_addr;;
  socklen_t saddrlen = sizeof(clnt_addr);
  int sn, ret=1;

  if (cfg_udp)
    return 1;

  /* Find an empty socket */
  for (sn=0 ; sn<MAX_SOCKETS ; sn++) {
    if (sockets[sn].active==0)
      break;
  }
  if (sn==MAX_SOCKETS)
    return 0;

  sockets[sn].sktfd = accept(lstn_fd, (struct sockaddr*)&clnt_addr, &saddrlen);
  sockets[sn].len = get_len(cfg_max_len);
  sockets[sn].off = 0;

  if (sockets[sn].sktfd > 0) {
    int flag = 1;
    ci_log("[pid=%d] Accepting connection[%d]=%d ", getpid(), sn, sockets[sn].sktfd);
    sockets[sn].active = 1;
    ret = 0;
    *nsockets = CI_MAX(sn, *nsockets);

#if defined(USE_SSL) 
    {
      int err;
      sockets[sn].ssl = SSL_new(ctx); 
      CHK_NULL(sockets[sn].ssl);
      SSL_set_fd(sockets[sn].ssl,  sockets[sn].sktfd);

      CI_TRY(fcntl(sockets[sn].sktfd, F_SETFL, 0));
      err = SSL_accept(sockets[sn].ssl);                                
      CHK_SSL(err);
    }
#endif
    
    if (!cfg_udp)
      CI_TRY( setsockopt(sockets[sn].sktfd, IPPROTO_TCP, TCP_NODELAY,
			 (char *) &flag, sizeof(flag)) );
    CI_TRY(fcntl(sockets[sn].sktfd, F_SETFL, O_NONBLOCK));

  } else if (errno!=EAGAIN) {
    CI_TRY(sockets[sn].sktfd);
  }

  return ret;
}


void
tcp_setup(int lstn_fd, int *nsockets, int port) {
  CI_TRY(fcntl(lstn_fd, F_SETFL, O_NONBLOCK ));

  /* accept the first socket */
  while (tcp_accept_socket(lstn_fd, nsockets));
}


void
udp_setup(int lstn_fd, int *nsockets, int port) {
  struct sockaddr_in clnt_addr;
  socklen_t saddrlen = sizeof(clnt_addr);
  unsigned char maxsocks;
  int bytes, sn, sktfd;
  (void)bytes;

  ci_log("Waiting for client connection ...");
  CI_TRY(sktfd = accept(lstn_fd, (struct sockaddr*)&clnt_addr, &saddrlen));
  /* read a single byte with the number of connections to make */
  bytes = read(sktfd, &maxsocks, sizeof(maxsocks));
  ci_assert_equal(bytes, sizeof(maxsocks));
  close(sktfd);
  
  ci_log("Connecting to %d sockets", maxsocks);
  for (sn=0 ; sn<maxsocks; sn++) {
    clnt_addr.sin_port = htons(port);
    CI_TRY(sockets[sn].sktfd = socket(PF_INET, SOCK_DGRAM, 0));
    CI_TRY(connect(sockets[sn].sktfd, (struct sockaddr*)&clnt_addr,
		   sizeof(clnt_addr)));
    CI_TRY(fcntl(sockets[sn].sktfd, F_SETFL, O_NONBLOCK));    
    sockets[sn].active = 1;
    (*nsockets)++;
    port++;
  }
}


void
main_loop(int port) {
  struct sockaddr_in my_addr;
  struct stat buf;
  unsigned int accept_per_thread, num_busier_threads, thread_num;
  int lstn_fd, file_fd, do_uncork;
  int sn, on=1, nsockets=0;
  int cc = ACCEPT_FREQ;
  int one = 1, zero = 0;
  char *msg;

#if defined(USE_SSL)
  SSL_METHOD *meth;

  /* SSL init*/
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_server_method();
  SSL_load_error_strings();
  ctx = SSL_CTX_new(meth);
  CHK_NULL(ctx);
  
#if USE_CERT
  {
    int err;
    ci_log("Ensure you have "KEYF" in the current directory");
    ci_log("Else copy from ~rjs/work/keep");
    err = SSL_CTX_use_RSAPrivateKey_file(ctx, KEYF,  SSL_FILETYPE_PEM);
    CHK_SSL(err);
    
    ci_log("Ensure you have "CERTF" in the current directory");
    ci_log("Else copy from ~rjs/work/keep");
    err = SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM);
    CHK_SSL(err);
  }
#endif

#endif

  signal(SIGPIPE, SIG_IGN);

  my_addr.sin_family      = AF_INET;           /* host byte order */
  my_addr.sin_port        = htons(port);
                                               /* short, network byte order */
  my_addr.sin_addr.s_addr = htonl(INADDR_ANY); /* automatically fill with my IP */

  /* Listen on a socket */
  CI_TRY(lstn_fd = socket(PF_INET, SOCK_STREAM, 0));
  CI_TRY(setsockopt(lstn_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)));
  CI_TRY(bind(lstn_fd, (struct sockaddr*)&my_addr, sizeof(my_addr)));
  CI_TRY(listen(lstn_fd, 128));
  
  /* Setup */
  ci_log("Ensure you have randfile e.g.:");
  ci_log("dd if=/dev/urandom of=randfile bs=4k count=2");
  CI_TRY(file_fd = open("randfile", O_RDONLY));

  fstat(file_fd, &buf);
  file_len = buf.st_size;

  ci_log("min_len=%d max_len=%d fixed_len=%d", 
	 cfg_min_len, cfg_max_len, cfg_fixed_len);
  
  msg = malloc(cfg_max_len);
  CI_TRY(read(file_fd, msg, cfg_max_len) == cfg_max_len);

  if (cfg_udp)
    udp_setup(lstn_fd, &nsockets, port);
  else
    tcp_setup(lstn_fd, &nsockets, port);

  /* fork to create threads - just divide the number of sockets between them */
  /* share accepting socket */
  accept_per_thread = (nsockets / cfg_threads);
  num_busier_threads = nsockets - ((nsockets / cfg_threads) * cfg_threads);

  for (thread_num=0 ; thread_num<cfg_threads-1; thread_num++) {
    pid_t pid;

    CI_TRY(pid = fork());
    if (pid==0)
      break;
  }

  /* round as necessary */
  if (thread_num < num_busier_threads)
    nsockets = accept_per_thread + 1;
  else
    nsockets = accept_per_thread ;

  /* main loop */
  while (1) {
    int offset=0;
    cc--;
    if (CI_UNLIKELY(cc<=0)) {
      tcp_accept_socket(lstn_fd, &nsockets);
      cc = ACCEPT_FREQ;
    }

    /* for UDP, sockets are pre-allocated so we need to adjust the logic */
    if (cfg_udp){
      if (thread_num < num_busier_threads)
        offset=thread_num*nsockets;
      else
        offset=thread_num*nsockets + num_busier_threads;
    }

    for(sn=offset ; sn<=nsockets+offset; sn++) {
      int rc, use_sendfile = 0;
      size_t count;
      off_t off;

      if (CI_UNLIKELY(cc<=0)) {
	tcp_accept_socket(lstn_fd, &nsockets);
	cc = ACCEPT_FREQ;
      }

      if (CI_UNLIKELY(sockets[sn].active==0))
	continue;
      cc--;

      /* Decide if to cork */
      if (cfg_pc_cork && !sockets[sn].corked && (RAND_LT(100) < cfg_pc_cork)) {
	if (cfg_udp)
	  CI_TRY( setsockopt(sockets[sn].sktfd, IPPROTO_UDP, UDP_CORK,
			     (char *)&one, sizeof(one)) );
	else
	  CI_TRY( setsockopt(sockets[sn].sktfd, IPPROTO_TCP, TCP_CORK,
			     (char *)&one, sizeof(one)) );
	sockets[sn].corked = 1;
      }

      /* Send random data to anything that is ready */
#if defined(USE_SSL)
      rc = SSL_write(sockets[sn].ssl, msg, sockets[sn].len);
#else
      if (cfg_all) {
	off = sockets[sn].off;
	count = sockets[sn].len;
      } else {
	off = get_off();
	count = sockets[sn].len;
      }
      
      sockets[sn].corked_len += count;

      rc = sendfile(sockets[sn].sktfd, file_fd, &off, count);
#endif
      
      /* Disambiguate real errors from EAGAIN */
      if (rc < 0) {
	if (errno==EPIPE || errno==ECONNRESET) {
	  sockets[sn].active=0;
	  if (sn==nsockets)
	    nsockets--;
	  ci_log("Closing connection=%d *******************",
		 sockets[sn].sktfd);
#if defined(USE_SSL)
	  SSL_free(sockets[sn].ssl);
#endif
	  close(sockets[sn].sktfd);

#if defined(USE_SSL)
	} else if ((SSLerror(sn,rc)!=SSL_ERROR_WANT_READ) && 
		   (SSLerror(sn,rc)!=SSL_ERROR_WANT_WRITE)) {
	  CI_TRY(SSLerror(sn,rc));
#else
	} else if (errno!=EAGAIN && (errno!=EMSGSIZE && use_sendfile && \
				     cfg_udp)) {
	  CI_TRY(rc);
#endif
	}
      } else {

	if (cfg_udp)
	  /* Must transmit the same data as there might be UDP loss */
	  sockets[sn].off = 0;
	else if (cfg_all)
	  sockets[sn].off = (sockets[sn].off + rc) % file_len;

	if (cfg_all)
	  /* TBD remove resitriction by replicating file data to >2* MAX_LEN */
	  sockets[sn].len = get_len(file_len - sockets[sn].off);
	else
	  sockets[sn].len = get_len(cfg_max_len);
      }

      /* Decide if to uncork */
      do_uncork = cfg_pc_uncork && sockets[sn].corked &&
	( (RAND_LT(100) < cfg_pc_uncork) ||
	  (sockets[sn].corked_len + sockets[sn].len > UDP_MAX_SIZE) );
      
      if (do_uncork) {
	if (cfg_udp)
	  CI_TRY( setsockopt(sockets[sn].sktfd, IPPROTO_UDP, UDP_CORK,
			   (char *)&zero, sizeof(zero)) );
	else
	  CI_TRY( setsockopt(sockets[sn].sktfd, IPPROTO_TCP, TCP_CORK,
			     (char *)&zero, sizeof(zero)) );
	sockets[sn].corked = 0;
	sockets[sn].corked_len = 0;      
      }

    } /* for each socket */
  } /* while (1) */
}

/******************************************************************************/

int main(int argc, char* argv[]) {
  int port;

  ci_app_getopt("", &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;
  if (argc != 1) ci_app_usage("Usage: <port>");
  port = atoi(argv[0]);

#if defined(USE_SSL)
  ci_assert_equal(cfg_udp, 0);
#endif

  /* sanity check CLI args */
  ci_assert_ge(cfg_threads, 1);
  ci_assert_le(cfg_threads, 16); /* stop fork bombs */
  ci_assert_le(cfg_pc_small_segs, 100);
  ci_assert_le(cfg_pc_cork, 100);
  ci_assert_le(cfg_pc_uncork, 100);

  if (cfg_pc_small_segs > 0) ci_assert_lt(cfg_min_len, SMALL_SEG_LEN);

  if (cfg_all)
    ci_log("NB: with --all 'sendfile_client --check=1' is supported");
  else
    ci_log("NB: without --all 'sendfile_client --check=1' is *NOT* supported");

  if( cfg_all && ((cfg_fixed_off > -1) || (cfg_fixed_len > -1)) ) {
    ci_log("You can't use -a with -o or -l");
    return 1;
  }
  if( cfg_all && cfg_udp && cfg_pc_cork!=0 ) {
    ci_log("You must use --pc_cork=0 when using --udp --all");
    return 1;
  }

  /* print the config */
  ci_log("==============================================");
  ci_log("protocol:     %s", cfg_udp ? "udp" : "tcp");
  ci_log("min_len:      %d", (cfg_fixed_len != -1)? cfg_fixed_len: cfg_min_len);
  ci_log("max_len:      %d", (cfg_fixed_len != -1)? cfg_fixed_len: cfg_max_len);
  ci_log("%% small segs: %d", cfg_pc_small_segs);
  ci_log("%% cork:       %d", cfg_pc_cork);
  ci_log("%% uncork:     %d", cfg_pc_uncork);
  ci_log("==============================================\n");

  main_loop(port);
  return 0;
}


/*! \cidoxg_end */
