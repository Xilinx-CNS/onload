/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2019 Xilinx, Inc. */
/*
 * Build the file using the following command:
 *   $ gcc -oonload_thread_set_spin -lonload_ext onload_thread_set_spin.c
 *
 * Test using the following line:
 *   $ EF_SPIN_USEC=-1 onload ./onload_thread_set_spin
 *
 * The spinning can be monitored using 'top' or similar to view CPU usage.
 * When spinning the core will be at 100% utilisation. The test will use
 * different spin parameters so the utilisation changes can be seen.
 *
 * NB.
 *   We set "EF_SPIN_USEC=-1" because this sets an infinite spin time. If
 *   we didn't it would spin for zero microseconds, i.e. it wouldn't spin.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <onload/extensions.h>

int main(void)
{
  int s;
  char buf[10];
  struct sockaddr_in servaddr;
  struct timeval tv;

  /* set up a basic UDP socket */
  s = socket(AF_INET, SOCK_DGRAM, 0);

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family      = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port        = htons(12345); 

  bind(s, (struct sockaddr *) &servaddr, sizeof(servaddr));

  /* set a timeout for recv operations */
  tv.tv_sec = 10;
  tv.tv_usec = 0;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

  /* Set all calls to spin */
  printf("onload_thread_set_spin(ONLOAD_SPIN_ALL, 1)\n");
  if( onload_thread_set_spin(ONLOAD_SPIN_ALL, 1) )
    printf("onload_thread_set_spin(ONLOAD_SPIN_ALL, 1) failed\n");

  recv(s, buf, 10, 0);

  /* Set no calls to spin */
  printf("onload_thread_set_spin(ONLOAD_SPIN_ALL, 0)\n");
  if( onload_thread_set_spin(ONLOAD_SPIN_ALL, 0) )
    printf("onload_thread_set_spin(ONLOAD_SPIN_ALL, 0) failed\n");

  recv(s, buf, 10, 0);

  /* Just set the UDP read call to spin */
  printf("onload_thread_set_spin(ONLOAD_SPIN_UDP_RECV, 1)\n");
  if( onload_thread_set_spin(ONLOAD_SPIN_UDP_RECV, 1) )
    printf("onload_thread_set_spin(ONLOAD_SPIN_UDP_RECV, 1) failed\n");

  recv(s, buf, 10, 0);
}
