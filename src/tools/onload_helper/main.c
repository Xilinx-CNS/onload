/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

/* A User-mode helper process to poll an Onload stack
 * - when interrupt happens;
 * - periodically.
 *
 * This process does not use the Socket APi, so it does not need
 * libonload.so to work.  It uses low-level Onload primitives.
 */

#define _GNU_SOURCE
#include <sys/resource.h>
#include <string.h>
#include <dirent.h>
#include <syslog.h>

#include <ci/compat.h>
#include <ci/tools/log.h>
#include <ci/tools/config.h>
#include <ci/tools/debug.h>
#include <ci/app/testapp.h>

#include <onload/common.h>
#include <onload/ioctl.h>
#include <onload/netif_dtor.h>
#include <ci/internal/ip.h>



static char* log_prefix;

static int cfg_ni_id = -1;
static int /*bool*/ ci_cfg_log_to_kern = false;

static ci_cfg_desc cfg_opts[] = {
  { 's', "stack", CI_CFG_UINT, &cfg_ni_id,
    "Stack id, numeric" },
  { 'K', "log-to-kmsg", CI_CFG_FLAG, &ci_cfg_log_to_kern,
    "log via kernel messages" },
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

static void set_log_prefix(const char* stack_name)
{
  if( ci_cfg_log_to_kern )
    asprintf(&log_prefix, "onload_helper[%d]: [%s] ", getpid(), stack_name);
  else
    asprintf(&log_prefix, "[%s] ", stack_name);
  ci_set_log_prefix(log_prefix);
}

/* Fixme: log via ioctl, always.  We need to implement log-via-syslog. */
static int log_fd;
static void citp_log_fn_drv(const char* msg)
{
  ioctl(log_fd, OO_IOC_PRINTK, (long) msg);
}

static ci_uint32
stack_next_timer_ms(ci_netif* ni)
{
  /* Find the timer value based on closest_timer */
  ci_ip_timer_state* ipts = IPTIMER_STATE(ni);
  ci_iptime_t ticks_delay = ipts->closest_timer - ipts->sched_ticks;
  ci_uint32 ms_delay;

  /* Something is going under our feet?  OK, let's that process handle it */
  if( ticks_delay < 1 )
    return 0;

  ms_delay = ci_ip_time_ticks2ms(ni, ticks_delay);
  /* The calculations above are imprecise.  Imprecision is OK, as long
   * as the periodic timer fires **after** the IP timer should be
   * run, otherwise the IP timer subsystem refuses to run the IP
   * timer.  So we add 1 ms.
   */
  return ms_delay + 1;
}

/* Finalize stack.  Exit with the stack locked, allowing module code to
 * shut down the queues, free the memory, etc.
 */
static void
do_exit(ci_netif* ni)
{
  ci_log("No time-waiting sockets: exit");
  ci_assert(ci_netif_is_locked(ni));
  oo_netif_dtor_pkts(ni);
  exit(0);
}

static void sigalarm_exit(int sig, siginfo_t *info, void *context)
{
  ci_log("Failed to get stack lock for 1s.  Exiting...");
  exit(1);
}

static void sigonload_do(int sig, siginfo_t* info, void* context)
{
  int fd;
  ci_uint32 op;

  fd = info->si_code;
  if( fd < 0 ) {
    /* We get SIGONLOAD from closing only */
    ci_assert_equal(fd, SI_ONLOAD);

    /* We do not have any UL state for any fd, and the module failed to
     * duplicate it.  Everything is already closed, we can do nothing.
     */
    return;
  }

  /* Close this fd via an ioctl */
  op = fd;
  ioctl(fd, OO_IOC_CLOSE, &op);
}

static void
stack_lock(ci_netif* ni, bool* is_locked)
{
  if( *is_locked )
    return;
  alarm(1);
  ci_netif_lock(ni);
  alarm(0);
  ci_netif_poll(ni);
  *is_locked = true;
}

/* The main loop: wait for something to happen, poll the stack, sleep
 * again. */
static void
main_loop(ci_netif* ni)
{
  struct oo_ulh_waiter arg;
  bool is_last = false;
  bool is_locked = false;

  arg.timeout_ms = 0;

  while( ioctl(ni->driver_handle, OO_IOC_WAIT_FOR_INTERRUPT, &arg) == 0 ) {
    if( arg.flags & OO_ULH_WAIT_FLAG_LOCKED )
      is_locked = true;
    else
      ci_assert( ! is_locked );
    if( is_locked || ci_netif_trylock(ni) ) {
      int n = ci_netif_poll(ni);
      CITP_STATS_NETIF_ADD(ni, interrupt_evs, n);
      is_locked = true;
    }

    if( arg.rs_ref_count == 0 ) {
      if( ! is_last ) {
        is_last = true;
        stack_lock(ni, &is_locked);

        /* Ensure all close() requests are handled */
        ci_netif_close_pending(ni);

        ci_assert_equal(ni->state->n_ep_orphaned, OO_N_EP_ORPHANED_INIT);
        ni->state->n_ep_orphaned = oo_netif_apps_gone(ni);
        ci_log("User application gone, %d sockets to be closed",
               ni->state->n_ep_orphaned);
      }

      if( ni->state->n_ep_orphaned == 0 ) {
        stack_lock(ni, &is_locked);
        do_exit(ni);
      }
    }

    if( is_locked ) {
      ci_netif_unlock(ni);
      is_locked = false;
    }
    arg.timeout_ms = stack_next_timer_ms(ni);
    ci_assert( ! is_locked );
  }
}

int main(int argc, char** argv)
{
  ci_netif* ni = malloc(sizeof(ci_netif));
  int rc;
  DIR* dir;
  struct dirent* ent;
  int devnull;
  struct sigaction act;
  char stack_name[strlen(OO_STRINGIFY(INT_MAX)) + 1];

  ci_app_getopt("", &argc, argv, cfg_opts, N_CFG_OPTS);

  ci_set_log_prefix("");
  if( cfg_ni_id < 0 ) {
    ci_log("Usage: %s -s <stack id>", argv[0]);
    ci_log("Version: %s\n%s", onload_version, onload_copyright);
    return 1;
  }

  /* We have the stack number: set up logging prefix */
  snprintf(stack_name, sizeof(stack_name), "%d", cfg_ni_id);
  stack_name[sizeof(stack_name) - 1] ='\0';
  set_log_prefix(stack_name);

  /* We can't log to kernel yet, so keep using stderr. */
  if( ci_cfg_log_to_kern )
    log_fd = STDERR_FILENO;

  /* Handle SIGONLOAD; it may come from the close() calls below. */
  memset(&act, 0, sizeof(act));
  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = sigonload_do;
  sigaction(SIGONLOAD, &act, NULL);

  /* See man 7 daemon for what's going on here.
   * And see ci_netif_start_helper() for the first part of
   * daemonizing. */

  /* We can getrlimit(RLIMIT_NOFILE) and then close() all the files up to
   * rlim_max, but RLIMIT_NOFILE is inherited from the user app and may be
   * very high; but the number of files at stack creation time is likely to
   * be low.  So let's use fewer syscalls.
   */
  dir = opendir("/proc/self/fd");
  if( dir == NULL ) {
    ci_log("Can't open /proc/self/fd: not closing "
           "inherited file descriptors");
  }
  else {
    while( (ent = readdir(dir)) != NULL ) {
      int fd = atoi(ent->d_name);
      if( fd != log_fd )
        close(fd);
    }
  }

  /* STDIN */
  devnull = open("/dev/null", O_RDONLY);
  if( devnull == -1 ) {
    ci_log("Failed to open /dev/null for reading: %s", strerror(errno));
    exit(1);
  }
  rc = dup2(devnull, STDIN_FILENO);
  if( rc < -1 ) {
    ci_log("Failed to dup /dev/null onto stdin: %s", strerror(errno));
    exit(1);
  }

  /* Set up logging via syslog */
  if( ! ci_cfg_log_to_kern ) {
    ci_log_options &=~ CI_LOG_PID;
    ci_log_fn = ci_log_syslog;
    openlog(NULL, LOG_PID, LOG_DAEMON);
  }

  /* Find the stack */
  rc = ci_netif_restore_id(ni, cfg_ni_id, true);
  if( rc != 0 ) {
    ci_log("no Onload stack [%d]", cfg_ni_id);
    return 1;
  }

  /* Now we can print the stack name to the log.  */
  if( ! ci_cfg_log_to_kern )
    set_log_prefix(ni->state->pretty_name);

  /* Fork() for the last time, to tell caller that
   * we have successully started
   */
  rc = fork();
  if( rc != 0 ) {
    if( rc > 0 )
      return 0;
    ci_log("Failed to spawn helper: %s", strerror(errno));
    return 1;
  }

  /* When logging to the kernel, we know the right pid now.  */
  if( ci_cfg_log_to_kern )
    set_log_prefix(ni->state->pretty_name);

  /* Set up logging via ioctl */
  if( ci_cfg_log_to_kern ) {
    close(log_fd);
    log_fd = ni->driver_handle;
    ci_log_fn = citp_log_fn_drv;
  }

  /* Ensure we do not hand forever trying to lock a wedged stack. */
  act.sa_sigaction = sigalarm_exit;
  sigaction(SIGALRM, &act, NULL);

  ci_log("Starting helper %s", onload_version);
  main_loop(ni);
  return 0;
}
