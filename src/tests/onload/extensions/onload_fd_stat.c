/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*
 * Build the file using the following command:
 *   $ gcc -lonload_ext -o onload_fd_stat onload_fd_stat.c
 *
 * Test by running the following command:
 *   $ onload ./onload_fd_stat
 *   Socket not accelerated
 *   oo:onload_fd_stat[24570]: Using OpenOnload 201210-u1 Copyright 2006-2012
 *   Solarflare Communications, 2002-2005 Level 5 Networks [2]
 *   Socket accelerated
 *     stack ID : 2
 *     stackname:
 *   oo:onload_fd_stat[24570]: Using OpenOnload 201210-u1 Copyright 2006-2012
 *   Solarflare Communications, 2002-2005 Level 5 Networks [2]
 *   Socket accelerated
 *     stack ID : 3
 *     stackname: s_name
 *   $
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <onload/extensions.h>

static void outputStatInfo(int r, struct onload_stat *stat)
{
  if( r == 0 )
  {
    printf("Socket not accelerated\n");
    /* no memory needs to be freed */
  }
  else if( r == 1 )
  {
    /* Output from onload_stackdump will show the sockets as:
     *    <protocol> <stack_id>:<endpoint_id>
     */
    printf("Socket accelerated\n");
    printf("  stack ID   : %d\n", stat->stack_id);
    printf("  stackname  : %s\n", stat->stack_name);
    printf("  endpoint ID: %d\n", stat->endpoint_id);

    /* free memory allocated by onload_fd_stack() call */
    free(stat->stack_name);
  }
  else
    printf("onload_fd_stat call failed (rc=%d)\n", r);
}

int main(void)
{
  int s1;
  int s2;
  int r;
  struct onload_stat * stat;
  struct sockaddr_in servaddr;

  stat = malloc(sizeof(struct onload_stat));

  /* new sockets created in this thread will not be accelerated */
  if( onload_set_stackname(ONLOAD_THIS_THREAD, ONLOAD_SCOPE_THREAD,
                           ONLOAD_DONT_ACCELERATE) )
    perror("Error setting stackname:");

  /* set up a basic UDP socket */
  s1 = socket(AF_INET, SOCK_DGRAM, 0);
  r = onload_fd_stat(s1, stat);
  outputStatInfo(r, stat);
  close(s1);

  /* revert to accelerating sockets */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_NOCHANGE, "") )
    perror("Error setting stackname:");

  /* set up a basic UDP socket */
  s1 = socket(AF_INET, SOCK_DGRAM, 0);
  r = onload_fd_stat(s1, stat);
  outputStatInfo(r, stat);
  close(s1);

  /* give the stack a name */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "s_name") )
    perror("Error setting stackname:");

  /* set up two basic UDP sockets */
  s1 = socket(AF_INET, SOCK_DGRAM, 0);
  r = onload_fd_stat(s1, stat);
  outputStatInfo(r, stat);
  s2 = socket(AF_INET, SOCK_DGRAM, 0);
  r = onload_fd_stat(s2, stat);
  outputStatInfo(r, stat);
  close(s1);
  close(s2);

  /* tidy up */
  free(stat);
}
