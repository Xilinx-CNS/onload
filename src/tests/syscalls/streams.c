/**************************************************************************\
*//*! \streams.c
** <L5_PRIVATE L5_SOURCE>
** \author  Greg Law <gel>
**  \brief  Tests using clib streams over L5 sockets
**   \date  2005/01/12
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tests_syscalls */

#include <stdio.h>
#include <ci/app.h>

/************************************
 * Logging
 */
#define LOGV(x)		do{if(!ci_cfg_quiet)do{x;}while(0);}while(0)
#define LOGVV(x)	do{if(ci_cfg_verbose)do{x;}while(0);}while(0)


#define CHECK_STR ("Hello, world!\n")

/*! The server and the time to run for are configurable from command-line */
static ci_cfg_desc cfg_opts[] = {
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))


int
main (int argc, char *argv[]) {
  struct sockaddr_in server_addr;
  int r, sock, sock2;
  FILE *stream;
  char check_str [128];
  (void)sock2;
  
  ci_cfg_protocol = IPPROTO_TCP;
  ci_app_getopt("[host:port]",
		&argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;

  LOGVV (ci_log ("Welcome to the stream tester!\n"));
  if (argc == 1) {
    if( ci_hostport_to_sockaddr_in(argv[0], &server_addr) < 0 )
      ci_app_usage("bad <host:port>");
  }
  else {
    fprintf (stderr, "%d too many arguments\n", argc);
    ci_app_usage("bad arguments");
  }

  LOGVV (ci_log ("Creating socket..."));
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    r = errno;
    perror ("Failed to create socket");
    exit (r);
  }

  LOGVV (ci_log ("Created socked %d, connecting...", sock));

  if (connect (sock, (struct sockaddr*)&server_addr, sizeof server_addr) < 0) {
    r = errno;
    perror ("Failed to connect socket");
    exit (r);
  }

  LOGVV (ci_log ("Socket open, attaching stream\n"));
  stream = fdopen (sock, "r+");
  if (!stream) {
    r = errno;
    perror ("Failed to create stream");
    exit (r);
  }

  /* Write a byte on the stream */
  LOGVV (ci_log ("Writing char on stream\n"));
  r = fprintf (stream, "a");
  fflush (stream);
  LOGVV (ci_log ("Got back %d from the write\n", r));

  if (r != 1) {
    int r2 = errno;
    if (r == -1)
      perror ("Wrote the wrong number of bytes");
    fprintf (stderr, "We wrote %d bytes, expected 1\n", r);
    exit (r2);
  }
  LOGVV (ci_log ("Reading bytes from stream"));

  /* Read a string from the stream */
  r = fscanf (stream, "%128s", check_str);
  if (r != 1) {
    int r2 = errno;
    if (r == -1) {
      perror ("Error on read");
      exit (r2);
    }
    fprintf (stderr, "Wanted to read 1 item, read %d\n", r);
    exit (1);
  }

  /* Close it */
  LOGVV (ci_log ("All done, closing"));
  r = fclose (stream);

  /* Check we cleaned up */
  LOGVV (ci_log ("OK, a bit of final testing..."));
  sock2 = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  ci_assert (sock2 == sock);

  LOGVV (ci_log ("And we're all done! "
                 "(Congratulations, you passed the stream test!\n"));

  return r;
}


/*! \cidoxg_end */
