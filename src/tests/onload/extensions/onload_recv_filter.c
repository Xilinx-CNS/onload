/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2019 Xilinx, Inc. */
/*
 * Build the file using the following command:
 *   $ gcc -oonload_recv_filter -lonload_ext onload_recv_filter.c
 *
 * Test by running the following two commands:
 *   $ onload ./onload_recv_filter.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>

#include <onload/extensions.h>
#include <onload/extensions_zc.h>

static int createSocket(int port)
{
  int s;
  struct sockaddr_in servaddr;

  s = socket(AF_INET, SOCK_DGRAM, 0);

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family      = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port        = htons(port);

  bind(s, (struct sockaddr *) &servaddr, sizeof(servaddr));

  return s;
}

char callback_msg[2048] = {0};
int callback_msg_len = 0;

static enum onload_zc_callback_rc
recv_filter(struct onload_zc_msg* msg, void* arg, int flags)
{
  int i;

  callback_msg_len = 0;

  for( i = 0; i < msg->msghdr.msg_iovlen; i++ ) {
    memcpy(callback_msg + callback_msg_len,
           msg->iov[i].iov_base, msg->iov[i].iov_len);
    callback_msg_len += msg->iov[i].iov_len;
  }

  printf("UDP recv callback called with %d bytes!\n", callback_msg_len);

  return ONLOAD_ZC_CONTINUE;
}

void test_loopback(int s, const struct sockaddr_in* servaddr)
{
  int rc;

  char test_msg[2048];
  int test_msg_len;
  char recv_msg[2048];

  int sender = socket(AF_INET, SOCK_DGRAM, 0);
  if( sender < 0 )
    perror("Failed to create sending socket");

  /* Reset callback */
  callback_msg_len = 0;

  /* Generate payload */
  test_msg_len = 1400;
  memset(test_msg, test_msg_len, test_msg_len);

  /* Send payload */
  rc = sendto(sender, test_msg, test_msg_len, 0, (const struct sockaddr *)servaddr, sizeof(*servaddr));
  close(sender);

  if( rc < 0 )
    perror("sendto() failed");
  else if( rc != test_msg_len )
    printf("sendto() sent %d bytes instead of %d bytes!\n", rc, test_msg_len);

  /* Receive */
  rc = recv(s, recv_msg, sizeof(recv_msg), 0);
  if( rc < 0 )
    perror("recv() failed");
  else if( rc != test_msg_len )
    printf("recv() received %d bytes instead of %d bytes!\n", rc, test_msg_len);

  /* Check callback data */
  if( !callback_msg_len )
    printf("FAIL - callback did not get called\n");
  else if( memcmp(test_msg, callback_msg, test_msg_len) )
    printf("FAIL - callback data does not match sent data\n");
  else
    printf("OK - %d bytes\n", test_msg_len);
}

void test_onload(int s, const struct sockaddr_in* servaddr)
{
  int rc;

  /* Test recv via Onload with a smaller buffer size */
  /* The callback should get the full data */
  char recv_msg[8];

  /* Reset callback */
  callback_msg_len = 0;

  /* Receive */
  printf("Please send a UDP packet from another machine, eg:\n");
  printf("    echo -n \"testtesttesttest\" | nc --udp xxx.xxx.xxx.xxx %d\n", ntohs(servaddr->sin_port));
  printf("Awaiting recv...\n");
  rc = recv(s, recv_msg, sizeof(recv_msg), 0);
  if( rc < 0 )
    perror("recv() failed");

  /* Check callback data */
  if( !callback_msg_len )
    printf("FAIL - callback did not get called\n");
  else
    printf("OK - %d bytes\n", callback_msg_len);
}

int main(void)
{
  int rc;
  int s;

  /* Create listening socket */
  s = createSocket(20000);
  if( s < 0 )
    perror("Failed to create listening socket");

  /* Get listening address */
  struct sockaddr_in servaddr;
  socklen_t servaddrlen = sizeof(servaddr);
  rc = getsockname(s, (struct sockaddr *)&servaddr, &servaddrlen);
  if( rc < 0 )
    perror("Failed to get listening port");
  printf("Listening on port %d...\n", ntohs(servaddr.sin_port));

  /* Install recv filter */
  rc = onload_set_recv_filter(s, recv_filter, NULL, 0);
  if( rc < 0 )
    printf("Failed to set recv filter, rc = %d.\n", rc);

  printf("\n");
  printf("1. Testing UDP recv callback for OS traffic...\n");
  test_loopback(s, &servaddr);
  printf("\n");
  printf("2. Testing UDP recv callback for Onload traffic...\n");
  test_onload(s, &servaddr);

  close(s);

  return 0;
}

