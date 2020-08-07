/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2019 Xilinx, Inc. */
/*
gcc -lonload_ext -o onload_move_fd -I /home/rad/onload_dev/src/include -L /home/rad/onload_dev/build/gnu_x86_64/lib/onload_ext/ -Wl,-E,-rpath=/home/rad/onload_dev/build/gnu_x86_64/lib/onload_ext/ onload_move_fd.c

 * Build the file using the following command:
 *   $ gcc -lonload_ext -o onload_fd_stat onload_fd_stat.c
 *
 * Test by running the following command:
 *   $ onload ./onload_move_fd
 *
 * On a system run the following command to connect over a Solarflare interface:
 *   $ onload ./onload_move_fd <ip_address>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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
    printf("  stack ID   : %d\n", stat->stack_id);
    printf("  stackname  : %s\n", stat->stack_name);
    free(stat->stack_name);
  }
  else
    printf("onload_fd_stat call failed (rc=%d)\n", r);
}

static void do_server(void)
{
  int sl;
  int sa1;
  int sa2;
  int r;
  int i;
  struct onload_stat * stat;
  struct sockaddr_in saddr;

  stat = malloc(sizeof(struct onload_stat));

  /* create a named stack for the socket */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "initial") )
    perror("Error setting stackname:");

  /* set up a basic listening TCP socket */
  sl = socket(AF_INET, SOCK_STREAM, 0);
  bzero(&saddr, sizeof(saddr));
  saddr.sin_family      = AF_INET;
  saddr.sin_addr.s_addr = htonl(INADDR_ANY);
  saddr.sin_port        = htons(20001);
  bind(sl, (struct sockaddr *) &saddr, sizeof(saddr));
  listen(sl, 10);

  /* accept the first connection */ 
  printf("Accepting first connection\n");
  sa1 = accept(sl, (struct sockaddr *) NULL, NULL);
  r = onload_fd_stat(sa1, stat);
  outputStatInfo(r, stat);

  /* create a new named stack to move the socket to */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "stack1") )
    perror("Error setting stackname:");

  /* move the socket into the current (stack1) stack */
  printf("Moving first connection\n");
  onload_move_fd(sa1);
  r = onload_fd_stat(sa1, stat);
  outputStatInfo(r, stat);

  /* accept the second connection */
  printf("Accepting second connection\n");
  sa2 = accept(sl, (struct sockaddr *) NULL, NULL);
  r = onload_fd_stat(sa2, stat);
  outputStatInfo(r, stat);

  /* create a new named stack to move the socket to */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "stack2") )
    perror("Error setting stackname:");

  /* move the socket into the current (stack2) stack */
  printf("Moving second connection\n");
  onload_move_fd(sa2);
  r = onload_fd_stat(sa2, stat);
  outputStatInfo(r, stat);

  /* tidy up */
  close(sl);
  close(sa1);
  close(sa2);
  free(stat);
}

static void do_client(char * addr)
{
  int s1;
  int s2;
  struct sockaddr_in saddr;

  /* connect to the server twice */
  bzero(&saddr, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_port   = htons(20001);

  if( inet_pton(AF_INET, addr, &saddr.sin_addr) <= 0 ) {
    printf("Error invalid address (%s)\n", addr);
    return;
  }

  if( (s1 = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
     perror("Unable to create socket:");
  if( (s2 = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
     perror("Unable to create socket:");

  if( connect(s1, (struct sockaddr *) &saddr, sizeof(saddr)) < 0 )
    perror("First connect to failed\n");
  else if( connect(s2, (struct sockaddr *) &saddr, sizeof(saddr)) < 0 )
    perror("Second connect to failed\n");
  
  close(s1);
  close(s2);
}

int main(int argc, char *argv[])
{
  if( argc > 1 )
    do_client(argv[1]);
  else
    do_server();

  return 0;
}
