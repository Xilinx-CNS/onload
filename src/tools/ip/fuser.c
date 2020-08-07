/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  sasha
**  \brief  fuser-like program to find onload'ed processes
**   \date  2012/01/25
**    \cop  (c) Solarflare Communications, Craig Small
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tests_ef */
#define _GNU_SOURCE /* for strsignal */
#include <stdlib.h>
#include <dirent.h>
#include <pwd.h>
#include <ci/internal/ip.h>
#include <onload/common.h>
#include <ci/app/testapp.h>
#include <onload/ul.h>

static int cfg_kill = 0;
static int cfg_verbose = 0;
static ci_cfg_desc cfg_opts[] = {
  {'k', "kill",   CI_CFG_FLAG, &cfg_kill,
                "kill all onloaded processes"},
  {'v', "verbose", CI_CFG_FLAG,  &cfg_verbose,
                "show processes in a ps-like style"},
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

#define USAGE_STR ""

static void usage(const char* msg)
{
  if( msg ) {
    ci_log(" ");
    ci_log("%s", msg);
  }

  ci_log(" ");
  ci_log("usage:");
  ci_log("  %s [options]", ci_appname);

  ci_log(" ");
  ci_log("options:");
  ci_app_opt_usage(cfg_opts, N_CFG_OPTS);
  ci_log(" ");
  exit(-1);
}

/* X-SPDX-Source-URL: https://gitlab.com/psmisc/psmisc.git */
/* X-SPDX-Source-Tag: 5b655f1ec99b86de0336bdabdaaf425e1570c88a */
/* X-SPDX-Source-File: src/fuser.c */
/* X-SPDX-Copyright-Text: Copyright (C) 1993-2005 Werner Almesberger and Craig
 *                        Small, Copyright (C) 2005-2017 Craig Small */
/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Comment: Heavily cut-down and modified from that source by
 *                 Solarflare, such that only the basic algorithm and data
 *                 structures remain. */

#define MAX_PATHNAME 300
#define MAX_CMDNAME 16
#define MAX_CMDLINE 60

struct procs {
  pid_t pid;
  uid_t uid;
  char *command;
  struct procs *next;
};

int
main(int argc, char* argv[])
{
  struct procs *proc_head = NULL;
  DIR *proc_dir, *fd_dir;
  struct dirent *proc_dent, *fd_dent;
  char dirpath[MAX_PATHNAME], filepath[MAX_PATHNAME];
  pid_t my_pid = getpid();
  pid_t pid;
  struct stat st;
  struct procs *proc;
  unsigned long stack_dev, epoll_dev;
  dev_t fs_dev;

  ci_app_usage = usage;
  ci_app_getopt(USAGE_STR, &argc, argv, cfg_opts, N_CFG_OPTS);

  /* Scan /proc/ and put all onloaded processes into proc_head list */
  if( (proc_dir = opendir("/proc")) == NULL ) {
    perror("open /proc");
    exit(1);
  }

  stack_dev = oo_get_st_rdev(OO_STACK_DEV);
  epoll_dev = oo_get_st_rdev(OO_EPOLL_DEV);
  fs_dev = oo_onloadfs_dev_t();

  while( (proc_dent = readdir(proc_dir)) != NULL ) {
    if (proc_dent->d_name[0] < '0' || proc_dent->d_name[0] > '9')
      continue; /* not a pid */
    pid = atoi(proc_dent->d_name);
    if( pid == my_pid )
      continue;
    /* Fixme: in theory, we should also scan /proc/%d/maps.
     * In reality, all maps are removed when stack fd is closed. */
    snprintf(dirpath, MAX_PATHNAME, "/proc/%d/fd", pid);
    if( (fd_dir = opendir(dirpath)) == NULL )
      continue;
    while( (fd_dent = readdir(fd_dir)) != NULL ) {
       snprintf(filepath, MAX_PATHNAME, "/proc/%d/fd/%s",
                pid, fd_dent->d_name);
       if (stat(filepath, &st) != 0)
        continue;
       if( st.st_rdev == stack_dev ||
           st.st_rdev == epoll_dev ||
           st.st_dev == fs_dev ) {
        proc = malloc(sizeof(struct procs));
        proc->pid = pid;

        if( cfg_verbose ) {
          FILE *fp;
          char cmdline[MAX_CMDLINE + 10];

          snprintf(filepath, MAX_PATHNAME, "/proc/%d", pid);
          if( stat(filepath, &st) != 0 ) {
            free(proc);
            break;
          }
          proc->uid = st.st_uid;

          snprintf(filepath, MAX_PATHNAME, "/proc/%d/stat", pid);
          if( (fp = fopen(filepath, "r")) == NULL ) {
            free(proc);
            break;
          }
          if( fscanf(fp, "%*d (%100[^)]", cmdline) != 1 ) {
            fclose(fp);
            free(proc);
            break;
          }
          proc->command = strdup(cmdline);
          fclose(fp);
        }
        proc->next = proc_head;
        proc_head = proc;
        break;
       }
    }
    closedir(fd_dir);
  }
  closedir(proc_dir);

  /* print or kill */
  for( proc = proc_head; proc != NULL; proc = proc->next ) {
    struct passwd *pwent = NULL;
    if( cfg_kill ) {
      kill(proc->pid, SIGKILL);
      if( ! cfg_verbose )
        continue;
    }
    if( ! cfg_verbose )
      printf("%d ", proc->pid);
    else {
      if( pwent == NULL || pwent->pw_uid != proc->uid )
        pwent = getpwuid(proc->uid);
      if( pwent == NULL )
        printf("%d(unknown)", proc->uid);
      else
        printf("%s", pwent->pw_name);
      printf("\t%d\t%s\n", proc->pid, proc->command);
    }
  }
  if( !cfg_kill && !cfg_verbose )
    printf("\n");

  return 0;
}

