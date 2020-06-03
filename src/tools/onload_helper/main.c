/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/* A User-mode helper process to poll an Onload stack
 * - when interrupt happens;
 * - periodically.
 *
 * This process does not use the Socket APi, so it does not need
 * libonload.so to work.  It uses low-level Onload primitives.
 */

#include <sys/resource.h>
#include <string.h>

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
static int cfg_timer_ms = 90;

static ci_cfg_desc cfg_opts[] = {
  { 's', "stack", CI_CFG_UINT, &cfg_ni_id,
    "Stack id, numeric" },
  { 't', "timer-ms", CI_CFG_UINT, &cfg_timer_ms,
    "Interval between periodic unsolicited polls" },
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

static void set_log_prefix(const char* stack_name)
{
#define CI_LOG_PREFIX_FMT "onload_helper[%d]: [%s] "
  char pref[strlen(CI_LOG_PREFIX_FMT) + strlen(OO_STRINGIFY(INT_MAX)) +
            ONLOAD_PRETTY_NAME_MAXLEN + 1];
  sprintf(pref, CI_LOG_PREFIX_FMT, getpid(), stack_name);
  log_prefix = strdup(pref);
  ci_set_log_prefix(log_prefix);
#undef CI_LOG_PREFIX_FMT
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
  oo_deferred_free(ni);
  oo_netif_dtor_pkts(ni);
  exit(0);
}

static void
stack_lock(ci_netif* ni, bool* is_locked)
{
  if( *is_locked )
    return;
  ci_netif_lock(ni);
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

    /* Fixme: this check breaks if any other entity does the same: looks at
     * ref_count and exits when it is the only user of the stack.
     * Currently onload_tcpdump does it, so onload_tcpdump and
     * onload_helper will not detach if they both are using an
     * overwise-orphaned stack. */
    if( arg.rs_ref_count == 0 ) {
      if( ! is_last ) {
        is_last = true;
        stack_lock(ni, &is_locked);

        /* Ensure all close() requests are handled */
        ci_netif_close_pending(ni);

        oo_netif_apps_gone(ni);
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
  struct rlimit rlim;
  int i;

  set_log_prefix("starting...");
  ci_app_getopt("", &argc, argv, cfg_opts, N_CFG_OPTS);

  /* Fixme: steal daemonise() from tools/cplane/server.c,
   * and split it between this place and ci_netif_start_helper(). */

  /* Fixme: keep the stack fd and reuse it below:
   * use ci_tcp_helper_stack_attach()+ci_netif_restore()
   * instead of ci_netif_restore_id().
   *
   * Fixme2: RLIMIT_NOFILE is inherited from the user app and may be very
   * high; but the number of files at stack creation time is likely to
   * be low.  We'd better use opendir(/proc/self/fd).
   */
  if( getrlimit(RLIMIT_NOFILE, &rlim) == 0 )
    for( i = 0; i < rlim.rlim_max; ++i )
      close(i);

  rc = fork();
  if( rc != 0 ) {
    if( rc > 0 ) {
      ci_log("Spawned helper pid %d", rc);
      return 0;
    }
    ci_log("Failed to spawn helper: %s", strerror(errno));
    return 1;
  }

  /* Find the stack */
  rc = ci_netif_restore_id(ni, cfg_ni_id, true);
  if( rc != 0 ) {
    ci_log("no Onload stack [%d]", cfg_ni_id);
    return 1;
  }


  ci_log_options &=~ CI_LOG_PID;
  log_fd = ni->driver_handle;
  ci_log_fn = citp_log_fn_drv;
  set_log_prefix(ni->state->pretty_name);

  main_loop(ni);
  return 0;
}
