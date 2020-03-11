/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  mjs
**  \brief  Tests for environment handling in execve() family
**   \date  2005/02/16
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_tests_syscalls */
 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __GLIBC__
# define ci_environ __environ
#endif

void do_test(const char *test)
{
  static char *new_argv[] = { "env", "TEST=xxx", "/bin/env", NULL };
  int status;

  printf("================================================================\n");
  printf(" Testing execve() with LD_PRELOAD %s\n", test);
  printf("================================================================\n");
  fflush(stdout);

  new_argv[1] = "TEST=execve";
  if (fork()) {
    wait(&status);
  } else {
    execve("/bin/env", new_argv, ci_environ);
  }
  fflush(stdout);

  printf("================================================================\n");
  printf(" Testing execv() with LD_PRELOAD %s\n", test);
  printf("================================================================\n");
  fflush(stdout);

  new_argv[1] = "TEST=execv";
  if (fork()) {
    wait(&status);
  } else {
    execv("/bin/env", new_argv);
  }
  fflush(stdout);

  printf("================================================================\n");
  printf(" Testing execl() with LD_PRELOAD %s\n", test);
  printf("================================================================\n");
  fflush(stdout);

  if (fork()) {
    wait(&status);
  } else {
    execl("/bin/env", "env", "TEST=execl", "/bin/env", (char *)0);
  }
  fflush(stdout);

  printf("================================================================\n");
  printf(" Testing execlp() with LD_PRELOAD %s\n", test);
  printf("================================================================\n");
  fflush(stdout);

  if (fork()) {
    wait(&status);
  } else {
    execlp("env", "env", "TEST=execlp", "/bin/env", (char *)0);
  }
  fflush(stdout);

  printf("================================================================\n");
  printf(" Testing execle() with LD_PRELOAD %s\n", test);
  printf("================================================================\n");
  fflush(stdout);

  if (fork()) {
    wait(&status);
  } else {
    execl("/bin/env", "env", "TEST=execle", "/bin/env", ci_environ, (char *)0);
  }
  fflush(stdout);

  printf("================================================================\n");
  printf(" Testing execvp() with LD_PRELOAD %s\n", test);
  printf("================================================================\n");
  fflush(stdout);

  new_argv[1] = "TEST=execvp";
  if (fork()) {
    wait(&status);
  } else {
    execvp("env", new_argv);
  }
  fflush(stdout);

  printf("\n");
  fflush(stdout);
}

int main(void)
{
  if (!getenv("LD_PRELOAD")) {
    printf("LD_PRELOAD is not set - pointless test\n");
    return 1;
  }
  do_test("set");
  putenv("LD_PRELOAD");
  do_test("cleared");
  return 0;
}

/*! \cidoxg_end */
