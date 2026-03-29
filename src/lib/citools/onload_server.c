/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2025, Advanced Micro Devices, Inc. */

#define _GNU_SOURCE

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>

#include <ci/tools/log.h>
#include <ci/tools/debug.h>

#define DEV_KMSG "/dev/kmsg"


CI_NORETURN ci_server_init_failed(const char* srv_name,
                                  const char* msg, ...)
{
  va_list args;
  va_start(args, msg);
  ci_vlog(msg, args);
  va_end(args);
  ci_log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  ci_log("!!! %s has FAILED TO START !!!", srv_name);
  ci_log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  exit(1);
}


void ci_server_set_log_prefix(char** log_prefix, const char* srv_bin)
{
  asprintf(log_prefix, "%s[%d]: ", srv_bin, getpid());
  ci_set_log_prefix(*log_prefix);
}

/*
 * close_extra_fds - Close all open file descriptors excluding 0, 1 and 2
 */
static void close_extra_fds(void)
{
  int i, dfd;
  long long fd;
  char *endp = NULL;
  DIR *dir;
  struct dirent *de;
  struct rlimit rlim;

  dir = opendir("/proc/self/fd");
  if (dir) {
    dfd = dirfd(dir);

    while ( (de = readdir(dir)) != NULL ) {
      /* Entries are numeric fd names; skip . and .. */
      endp = NULL;
      fd = strtoll(de->d_name, &endp, 10);
      if ( endp == de->d_name || *endp != '\0' )
          /* Not a number */
          continue;

      if ( fd <= STDERR_FILENO || fd == dfd )
          continue;

      (void)close((int)fd);
    }
    closedir(dir);
    return;
  }
  if( getrlimit(RLIMIT_NOFILE, &rlim) == 0 )
    for( i = STDERR_FILENO + 1; i < rlim.rlim_max; ++i )
      close(i);
}

/* Fork off a daemon process according to the recipe in "man 7 daemon".  This
 * function returns only in the context of the daemon, and only on success;
 * otherwise, it exits. */
void ci_server_daemonise(bool log_to_kern, char** log_prefix,
                         const char* srv_name, const char* srv_bin)
{
  pid_t child;
  int rc;
  int devnull;
  int i;
  sigset_t sigset;

  /* Start with some tidy-up.  We don't check errors here as failure is non-
   * fatal. */

  /* Close all files above stderr. */
  close_extra_fds();

  /* Reset all signal handlers. */
  for( i = 0; i < _NSIG; ++i )
    signal(i, SIG_DFL);

  /* Unblock all signals. */
  sigfillset(&sigset);
  sigprocmask(SIG_UNBLOCK, &sigset, NULL);

  /* Make sure we're not a process group leader so that setsid() will give us a
   * new session. */
  child = fork();
  if( child == -1 )
    ci_server_init_failed(srv_name, "Failed to fork: %s", strerror(errno));
  else if( child != 0 )
    /* Parent process. */
    exit(0);

  /* Get a new session. */
  rc = setsid();
  if( rc == -1 )
    ci_server_init_failed(srv_name, "setsid() failed: %s", strerror(errno));

  /* Fork to relinquish position as process group leader. */
  child = fork();
  if( child == -1 ) {
    ci_server_init_failed(srv_name, "Failed to fork: %s", strerror(errno));
  }
  else if( child != 0 ) {
    /* Parent process.  The child is the 'real' daemon. */
    exit(0);
  }
  ci_log("Spawned daemon process %d", getpid());

  umask(0);
  rc = chdir("/");
  if( rc == -1 )
    ci_server_init_failed(srv_name, "Failed to change to root directory: %s",
                          strerror(errno));

  devnull = open("/dev/null", O_RDONLY);
  if( devnull == -1 )
    ci_server_init_failed(srv_name, "Failed to open /dev/null for reading: %s",
                          strerror(errno));
  rc = dup2(devnull, STDIN_FILENO);
  if( rc == -1 )
    ci_server_init_failed(srv_name, "Failed to dup /dev/null onto stdin: %s",
                          strerror(errno));
  close(devnull);

  devnull = open(log_to_kern ? DEV_KMSG : "/dev/null", O_WRONLY);
  if( devnull == -1 )
    ci_server_init_failed(srv_name, "Failed to open /dev/null for writing: %s",
                          strerror(errno));

  /* Start logging to syslog before we nullify std{out,err}. */
  if( ! log_to_kern ) {
    ci_set_log_prefix("");
    ci_log_fn = ci_log_syslog;
    openlog(NULL, LOG_PID, LOG_DAEMON);
  }
  else {
    /* Use the new PID when logging. */
    ci_server_set_log_prefix(log_prefix, srv_bin);
  }

  rc = dup2(devnull, STDOUT_FILENO);
  if( rc == -1 )
    ci_server_init_failed(srv_name, "Failed to dup /dev/null onto stdout: %s",
                          strerror(errno));
  rc = dup2(devnull, STDERR_FILENO);
  if( rc == -1 )
    ci_server_init_failed(srv_name, "Failed to dup /dev/null onto stderr: %s",
                          strerror(errno));
  close(devnull);
}
