/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2015-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ab
**  \brief  Example for pthread interception
**   \date  2014/11/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/* Simple test for libpthread_intercept.
 * Expected to return 0 if everything is ok.
 *
 * The test relies upon the contents of .onload_intercept being:
 *   set protocol 1
 *   set default 1
 *   name T1 E1_%
 *   name Thread1 Long_%
 *   num 2 Second
 * This test just creates a couple of threads, and a few sockets
 * and checks that they got put into the expected stacks (by the intercept)
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <linux/prctl.h>
#include <sys/socket.h>
#include <onload/extensions.h>

/* We don't actually pass any arguments into the threads */
struct thread_args { };

#define TEST(_x) {                        \
    if ( !(_x) ) {                        \
      printf( "ERR: %s failed\n", #_x );  \
      exit(-1);                           \
    } }

/* Check whether a socket is in the named stack */
static int stackname_as_expected(int fd, char const *name)
{
  struct onload_stat stat;
  int ok;
  TEST(name);

  /* Use extensions API to get info on that socket */
  ok = onload_fd_stat(fd, &stat);
  if( ok < 0 ) {
    printf("onload_fd_stat failed (%d)\n", ok);
    return ok;
  }

  /* Expected to be in a stack, but are not - fail */
  if( !ok && name )
    return 0;
  /* Not expected to be in a stack, and indeed are not - ok */
  if( !stat.stack_name && !name )
    return 1;
  /* Expected to be in a named stack - but no name - fail */
  if( !stat.stack_name && name )
    return 0;

  TEST(stat.stack_name);

  /* Name is present, is it the expected one? */
  ok = strncmp(name, stat.stack_name, 16) == 0;

  /* And make sure we don't leak the name */
  free(stat.stack_name);
  return ok;
};


/* The first thread that is spawned */
static void *thread_one(void *args)
{
  int sock;
  sleep(1);

  /* Create a socket */
  printf("child: Thread start\n");
  sock = socket(AF_INET, SOCK_STREAM, 0);
  TEST(stackname_as_expected(sock, "Long_T"));
  close(sock);

  /* Change stack name then create another */
  prctl(PR_SET_NAME, "T1");
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  TEST(stackname_as_expected(sock, "E1_U"));
  close(sock);

  printf("thread_one: exits now\n");
  return args;
}


/* Second thread that main creates */
static void *thread_two(void *args)
{
  int sock;
  sleep(1);

  /* Create a socket */
  printf("child2: Start\n");
  sock = socket(AF_INET, SOCK_STREAM, 0);
  TEST(stackname_as_expected(sock, "Second"));

  sleep(1);
  printf("thread_two: exits now\n");
  return args;
}


static void sleep_forever(void)
{
  printf("parent: Done, sleeping until you ^C me now, so that you can get a stackdump.\n");
  while( 1 ) ;
}


int main()
{
  pthread_t thread1 = 0;
  pthread_t thread2 = 0;
  pthread_attr_t attr;
  struct thread_args args;
  void *retval;
  void *retval2;
  int ok;
  int sock;

  TEST(onload_is_present());

  /* Create thread_one */
  ok = pthread_attr_init(&attr);
  printf("parent: pthread_attr_init returned %d (%d)\n", ok, errno);
  ok = pthread_create(&thread1, &attr, &thread_one, &args);
  printf("parent: pthread_create returned %d id=%d (%d)\n", ok, (int)thread1,
         errno);
  /* And name it */
  pthread_setname_np(thread1, "Thread1");
  printf("parent: name of thread is set\n");

  /* Create thread_two */
  ok = pthread_create(&thread2, &attr, &thread_two, &args);

  /* Create some sockets in the main thread, looking for default behaviour */
  printf("parent: Socket tests\n");
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  TEST(stackname_as_expected(sock, "U"));
  close(sock);
  sock = socket(AF_INET, SOCK_STREAM, 0);
  TEST(stackname_as_expected(sock, "T"));
  close(sock);
  printf("parent: sockets ok\n");

  /* Rejoin the threads */
  printf("parent: pthread_join...\n");
  ok = pthread_join(thread1, &retval);
  printf("parent: pthread_join1 returned %d (%d)\n", ok, errno);
  ok = pthread_join(thread2, &retval2);
  printf("parent: pthread_join2 returned %d (%d)\n", ok, errno);

  return ok;
}

