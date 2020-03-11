/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*
 * Build the file using the following command:
 *   $ gcc -oonload_stackname -lonload_ext onload_stackname.c
 *
 * Test using the following line (the call will not return):
 *   $ onload ./onload_stackname
 *
 * The sockets and stacks can be checked using the following line:
 *   $ onload_stackdump lots | grep -e 'name=' -e '^UDP'
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <onload/extensions.h>


/* Set up a basic UDP socket bound to a particular port
 * number so it can be identified in onload_stackdump.
 */
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

int main(void)
{
  int s1;
  int s2;
  int s3;
  int rc;

  /* set a global stackname */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "global1") )
    perror("Error setting stackname:");

  s1 = createSocket(20001);

  /* save the current stack configuration so we can change it */
  rc = onload_stackname_save();
  if( rc ) {
    printf("onload_stackname_save() failed (rc=%d)\n", rc);
    return -1;
  }

  /* set a different global stackname */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "global2") )
    perror("Error setting stackname:");

  s2 = createSocket(20002);

  /* restore the saved stack configuration */
  rc = onload_stackname_restore();
  if( rc ) {
    printf("onload_stackname_restore() failed (rc=%d)\n", rc);
    return -1;
  }

  s3 = createSocket(20003);

  sleep(~0);

  return 0;
}