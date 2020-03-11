/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*
 * Build the file using the following command:
 *   $ gcc -oonload_set_stackname -lpthread -lonload_ext onload_set_stackname.c
 *
 * Test using the following line (the call will not return):
 *   $ onload ./onload_set_stackname
 *
 * The sockets and stacks can be checked using the following line:
 *   $ onload_stackdump lots | grep -e 'name=' -e '^UDP'
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <onload/extensions.h>

typedef struct
{
  int port;
  int who;
  int scope;
  char * name;
} S_THREAD;


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


/* Sets the stack name, if required, then creates a socket to cause
 * Onload to make the new stack, if needed, and sleeps forever.
 */
void * func_thread( void * arg )
{
  int s;
  struct sockaddr_in servaddr;

  S_THREAD *st = (S_THREAD*)arg;

  if(st->name != NULL)
    if( onload_set_stackname(st->who, st->scope, st->name) )
      perror("Error setting stackname:");

  /* set up a basic UDP socket */
  s = createSocket(st->port);

  /* sleep forever */
  sleep(-1);

  /* tidy up */
  close(s);
}

#define NUM_THREADS 5
int main(int argc, char **argv)
{
  int i, s1, s2, s3, s4, s5, s6, s7;
  S_THREAD * params;
  pthread_t t[NUM_THREADS];
  pthread_attr_t attrs[NUM_THREADS];

  params = malloc(sizeof(S_THREAD) * NUM_THREADS);

  /* set a global stackname */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "global1") )
    perror("Error setting stackname:");

  /* create a socket in the global stackname */
  s1 = createSocket(20001);

  /* temporarily switch to a different stackname */
  if( onload_set_stackname(ONLOAD_THIS_THREAD, ONLOAD_SCOPE_THREAD, "tmp_stk") )
    perror("Error setting stackname:");

  /* create a socket in the temporary stackname */
  s2 = createSocket(20002);

  /* revert back to the global stackname */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_NOCHANGE, "") )
    perror("Error setting stackname:");

  /* create a socket in the global stackname */
  s3 = createSocket(20003);

  /* temporarily stop accelerating sockets */
  if( onload_set_stackname(ONLOAD_THIS_THREAD, ONLOAD_SCOPE_THREAD,
                           ONLOAD_DONT_ACCELERATE) )
    perror("Error setting stackname:");

  /* create a socket which will not be accelerated */
  s4 = createSocket(20004);

  /* revert to accelerating in the global stackname */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_NOCHANGE, "") )
    perror("Error setting stackname:");

  /* create a socket in the global stackname */
  s5 = createSocket(20005);

  /* create thread attributes threads */
  for(i=0;i<NUM_THREADS;++i)
    pthread_attr_init( &attrs[i] );

  /* create a thread which will use the global stackname */
  params[0] = (S_THREAD){ 20006, 0, 0, NULL };
  pthread_create( &t[0], &attrs[0], &func_thread, &params[0] );
  /* sleep to allow thread to call onload_set_stackname() */
  usleep(1000);

  /* create a thread which will use its own stackname */
  params[1] = (S_THREAD){ 20007, ONLOAD_THIS_THREAD, ONLOAD_SCOPE_THREAD,
                          "thread" };
  pthread_create( &t[1], &attrs[1], &func_thread, &params[1] );
  usleep(1000);

  /* create a thread which will not use acceleration */
  params[2] = (S_THREAD){ 20008, ONLOAD_THIS_THREAD, ONLOAD_SCOPE_THREAD,
				          ONLOAD_DONT_ACCELERATE };
  pthread_create( &t[2], &attrs[2], &func_thread, &params[2] );
  usleep(1000);

  /* create a thread which creates a socket in a new global stackname
   * Note: this stackname will apply across all new and existing threads
   */
  params[3] = (S_THREAD){ 20009, ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL,
                          "global2" };
  pthread_create( &t[3], &attrs[3], &func_thread, &params[3] );
  usleep(1000);

  /* create a socket which will still be using the second global stackname */
  s6 = createSocket(20010);

  /* change this thread back to using the first global stackname */
  if( onload_set_stackname(ONLOAD_THIS_THREAD, ONLOAD_SCOPE_GLOBAL, "global1") )
    perror("Error setting stackname:");

  /* create a socket in the first global stackname */
  s7 = createSocket(20011);

  /* create a thread which creates a socket in a new global stackname
   * which will only apply to that thread and not any others
   */
  params[4] = (S_THREAD){ 20012, ONLOAD_THIS_THREAD, ONLOAD_SCOPE_GLOBAL,
                          "thread2" };
  pthread_create( &t[4], &attrs[4], &func_thread, &params[4] );
  usleep(1000);

  /* tidy up */
  for(i=0;i<NUM_THREADS;++i)
    pthread_join( t[i], NULL );
  close(s1);
  close(s2);
  close(s3);
  close(s4);
  close(s5);
  close(s6);

  return 0;
}
