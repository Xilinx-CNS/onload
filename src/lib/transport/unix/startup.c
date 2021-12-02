/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr/ctk
**  \brief  Sockets interface to user level TCP
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_unix */

#include <internal.h>
#include <ci/app/rawpkt.h>
#include <ci/internal/syscall.h>
#include <unistd.h> /* for getpid() */
#include <sys/stat.h> /* for mkdir() */
#include <sys/types.h>  /* for mkdir() */
#include <ci/internal/efabcfg.h>
#include <onload/version.h>


citp_globals_t citp = {
  /* log_fd */ -1,
  /* onload_fd */ -1,

  /* And the rest default to zero. */
};


static int citp_setup_logging_early(void)
{
  /* If stderr is a tty, use it.  Else, use ioctl. */
  if( isatty(STDERR_FILENO) )
    ci_log_fn = citp_log_fn_ul;
  else {
    ci_log_fn = citp_log_fn_drv;
  }
  ci_set_log_prefix("onload: ");
  return 0;
}

static void citp_setup_logging_change(void *new_log_fn)
{
  if( ci_log_fn != new_log_fn && citp.log_fd >= 0) {
    ci_sys_close(citp.log_fd);
    citp.log_fd = -1;
  }
  ci_log_fn = new_log_fn;
}

void citp_setup_logging_prefix(void)
{
  static char s0[64];
  snprintf(s0, sizeof(s0), "oo:%.16s[%d]: ", citp.process_name, (int) getpid());
  ci_set_log_prefix(s0);
}


/* Called to intialise thread-specific state, the first time a thread needs
 * to use part of the per-thread state that requires explicit
 * initialisation.
 *
 * Some members of oo_per_thread are implicitly initialised to zero because
 * they are static data (with __thread keyword).  Those members must not be
 * reinitialised here, because they may already have been used and
 * modified.
 */
static void __oo_per_thread_init_thread(struct oo_per_thread* pt)
{
  /* It's possible that we got here because we're not initialised at all! */
  if( citp.init_level < CITP_INIT_SYSCALLS ) {
    if( _citp_do_init_inprogress == 0 )
      citp_do_init(CITP_INIT_MAX);
    else
      citp_do_init(CITP_INIT_SYSCALLS);
  }

  /* [pt->sig] is zero initialised. */

  oo_stackname_thread_init(&pt->stackname);

  pt->spinstate = 0;
  if( CITP_OPTS.udp_recv_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_UDP_RECV);
  if( CITP_OPTS.udp_send_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_UDP_SEND);
  if( CITP_OPTS.tcp_recv_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_TCP_RECV);
  if( CITP_OPTS.tcp_send_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_TCP_SEND);
  if( CITP_OPTS.tcp_accept_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_TCP_ACCEPT);
  if( CITP_OPTS.tcp_connect_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_TCP_CONNECT);
  if( CITP_OPTS.pkt_wait_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_PKT_WAIT);
  if( CITP_OPTS.pipe_recv_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_PIPE_RECV);
  if( CITP_OPTS.pipe_send_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_PIPE_SEND);
  if( CITP_OPTS.ul_select_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_SELECT);
  if( CITP_OPTS.ul_poll_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_POLL);
  if( CITP_OPTS.ul_epoll_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_EPOLL_WAIT);
  if( CITP_OPTS.sock_lock_buzz )
    pt->spinstate |= (1 << ONLOAD_SPIN_SOCK_LOCK);
  if( CITP_OPTS.stack_lock_buzz )
    pt->spinstate |= (1 << ONLOAD_SPIN_STACK_LOCK);
  if( CITP_OPTS.so_busy_poll_spin )
    pt->spinstate |= (1 << ONLOAD_SPIN_SO_BUSY_POLL);
}




static void citp_dump_config(void)
{
  char buf[80];
  confstr(_CS_GNU_LIBC_VERSION, buf, sizeof(buf));
  log("GNU_LIBC_VERSION = %s", buf);
  confstr(_CS_GNU_LIBPTHREAD_VERSION, buf, sizeof(buf));
  log("GNU_LIBPTHREAD_VERSION = %s", buf);
  log("ci_glibc_uses_nptl = %d", ci_glibc_uses_nptl());
  log("ci_is_multithreaded = %d", ci_is_multithreaded());
}

static void citp_dump_opts(citp_opts_t *o)
{
  /* ?? TODO: should be using opts_cittp_def.h here */

# define DUMP_OPT_INT(envstr, name)		\
  ci_log("%s=%d", (envstr), (int) o->name)
# define DUMP_OPT_HEX(envstr, name)		\
  ci_log("%s=%x", (envstr), (unsigned) o->name)

  DUMP_OPT_HEX("EF_UNIX_LOG",		log_level);
  DUMP_OPT_INT("EF_PROBE",		probe);
  DUMP_OPT_INT("EF_TCP",		ul_tcp);
  DUMP_OPT_INT("EF_UDP",		ul_udp);
  DUMP_OPT_INT("EF_UL_SELECT",		ul_select);
  DUMP_OPT_INT("EF_SELECT_SPIN",	ul_select_spin);
  DUMP_OPT_INT("EF_SELECT_FAST",	ul_select_fast);
  DUMP_OPT_INT("EF_UL_POLL",		ul_poll);
  DUMP_OPT_INT("EF_POLL_SPIN",		ul_poll_spin);
  DUMP_OPT_INT("EF_POLL_FAST",		ul_poll_fast);
  DUMP_OPT_INT("EF_POLL_FAST_USEC",	ul_poll_fast_usec);
  DUMP_OPT_INT("EF_POLL_NONBLOCK_FAST_USEC", ul_poll_nonblock_fast_usec);
  DUMP_OPT_INT("EF_SELECT_FAST_USEC",	ul_select_fast_usec);
  DUMP_OPT_INT("EF_SELECT_NONBLOCK_FAST_USEC", ul_select_nonblock_fast_usec);
  DUMP_OPT_INT("EF_UDP_RECV_SPIN",      udp_recv_spin);
  DUMP_OPT_INT("EF_UDP_SEND_SPIN",      udp_send_spin);
  DUMP_OPT_INT("EF_TCP_RECV_SPIN",      tcp_recv_spin);
  DUMP_OPT_INT("EF_TCP_SEND_SPIN",      tcp_send_spin);
  DUMP_OPT_INT("EF_TCP_ACCEPT_SPIN",    tcp_accept_spin);
  DUMP_OPT_INT("EF_TCP_CONNECT_SPIN",   tcp_connect_spin);
  DUMP_OPT_INT("EF_PKT_WAIT_SPIN",      pkt_wait_spin);
  DUMP_OPT_INT("EF_PIPE_RECV_SPIN",     pipe_recv_spin);
  DUMP_OPT_INT("EF_PIPE_SEND_SPIN",     pipe_send_spin);
  DUMP_OPT_INT("EF_PIPE_SIZE",          pipe_size);
  DUMP_OPT_INT("EF_SOCK_LOCK_BUZZ",     sock_lock_buzz);
  DUMP_OPT_INT("EF_STACK_LOCK_BUZZ",    stack_lock_buzz);
  DUMP_OPT_INT("EF_SO_BUSY_POLL_SPIN",  so_busy_poll_spin);
  DUMP_OPT_INT("EF_UL_EPOLL",	        ul_epoll);
  DUMP_OPT_INT("EF_EPOLL_SPIN",	        ul_epoll_spin);
  DUMP_OPT_INT("EF_EPOLL_CTL_FAST",     ul_epoll_ctl_fast);
  DUMP_OPT_INT("EF_EPOLL_CTL_HANDOFF",  ul_epoll_ctl_handoff);
  DUMP_OPT_INT("EF_EPOLL_MT_SAFE",      ul_epoll_mt_safe);
  DUMP_OPT_INT("EF_FDTABLE_SIZE",	fdtable_size);
  DUMP_OPT_INT("EF_SPIN_USEC",		ul_spin_usec);
  DUMP_OPT_INT("EF_SLEEP_SPIN_USEC",	sleep_spin_usec);
  DUMP_OPT_INT("EF_STACK_PER_THREAD",	stack_per_thread);
  DUMP_OPT_INT("EF_DONT_ACCELERATE",	dont_accelerate);
  DUMP_OPT_INT("EF_FDTABLE_STRICT",	fdtable_strict);
  DUMP_OPT_INT("EF_FDS_MT_SAFE",	fds_mt_safe);
  DUMP_OPT_INT("EF_FORK_NETIF",		fork_netif);
  DUMP_OPT_INT("EF_NETIF_DTOR",		netif_dtor);
  DUMP_OPT_INT("EF_NO_FAIL",		no_fail);
  DUMP_OPT_INT("EF_SA_ONSTACK_INTERCEPT",	sa_onstack_intercept);
  DUMP_OPT_INT("EF_ACCEPT_INHERIT_NONBLOCK", accept_force_inherit_nonblock);
  DUMP_OPT_INT("EF_PIPE", ul_pipe);
  DUMP_OPT_HEX("EF_SIGNALS_NOPOSTPONE", signals_no_postpone);
  DUMP_OPT_HEX("EF_SYNC_CPLANE_AT_CREATE", sync_cplane);
  DUMP_OPT_INT("EF_CLUSTER_SIZE",  cluster_size);
  DUMP_OPT_INT("EF_CLUSTER_RESTART",  cluster_restart_opt);
  DUMP_OPT_INT("EF_CLUSTER_HOT_RESTART", cluster_hot_restart_opt);
  ci_log("EF_CLUSTER_NAME=%s", o->cluster_name);
  if( o->tcp_reuseports == 0 ) {
    DUMP_OPT_INT("EF_TCP_FORCE_REUSEPORT", tcp_reuseports);
  } else {
    struct ci_port_list *force_reuseport;
    CI_DLLIST_FOR_EACH2(struct ci_port_list, force_reuseport, link,
                        (ci_dllist*)(ci_uintptr_t)o->tcp_reuseports)
      ci_log("%s=%d", "EF_TCP_FORCE_REUSEPORT", ntohs(force_reuseport->port));
  }
  if( o->udp_reuseports == 0 ) {
    DUMP_OPT_INT("EF_UDP_FORCE_REUSEPORT", udp_reuseports);
  } else {
    struct ci_port_list *force_reuseport;
    CI_DLLIST_FOR_EACH2(struct ci_port_list, force_reuseport, link,
                        (ci_dllist*)(ci_uintptr_t)o->udp_reuseports)
      ci_log("%s=%d", "EF_UDP_FORCE_REUSEPORT", ntohs(force_reuseport->port));
  }
}


static void citp_log_to_file(const char *s)
{
  int fd;
  ci_assert(!CITP_OPTS.log_via_ioctl);
  fd = open(s, O_WRONLY | O_CREAT | O_TRUNC, S_IREAD | S_IWRITE);
  if( fd >= 0 ) {
    if( citp.log_fd >= 0 )
      ci_sys_close(citp.log_fd);
    citp.log_fd = fd;
  }
}

static void citp_get_process_name(void)
{
  int n;

  citp.process_name = citp.process_path;

#if CI_CFG_FD_CACHING
  citp.pid = getpid();
#endif

  ci_snprintf(citp.process_path, sizeof(citp.process_path), "<unknown-proc>");

  n = readlink("/proc/self/exe", citp.process_path,
               sizeof(citp.process_path));
  if (n < 0)
    return;

  n = CI_MIN(n + 1, sizeof(citp.process_path));
  citp.process_path[n - 1] = '\0';
  citp.process_name = citp.process_path + n - 2;
  while (citp.process_name > citp.process_path &&
         citp.process_name[-1] != '/')
    --citp.process_name;
}


static int get_env_opt_int(const char* name, int old_val, int hex)
{ const char* s;
  int new_val;
  char dummy;
  if( (s = getenv(name)) ) {
    if( sscanf(s, hex ? "%x %c" : "%d %c", &new_val, &dummy) == 1 )
      /*! TODO: should use option value range checking here */
      return new_val;
    else if (s[0] != '\0')
      ci_log("citp: bad option '%s=%s'", name, s);
  }
  return old_val;
}

#define GET_ENV_OPT_INT(envstr, var)					\
  do{ opts->var = get_env_opt_int((envstr), opts->var, 0); }while(0)

#define GET_ENV_OPT_HEX(envstr, var)					\
  do{ opts->var = get_env_opt_int((envstr), opts->var, 1); }while(0)


/* This function assumes an option of the same form and types as
 * EF_TCP_FORCE_REUSEPORT
 */
static void get_env_opt_port_list(ci_uint64* opt, const char* name)
{
  char *s;
  unsigned v;
  if( (s = getenv(name)) ) {
    /* The memory used for this list is never freed, as we need it
     * persist until the process terminates 
     */
    *opt = (ci_uint64)(ci_uintptr_t)malloc(sizeof(ci_dllist));
    if( ! *opt )
      log("Could not allocate memory for %s list", name);
    else {
      struct ci_port_list *curr;
      ci_dllist *opt_list = (ci_dllist*)(ci_uintptr_t)*opt;
      ci_dllist_init(opt_list);

      while( sscanf(s, "%u", &v) == 1 ) {
        curr = malloc(sizeof(struct ci_port_list));
        if( ! curr ) {
          log("Could not allocate memory for %s list entry", name);
          break;
        }
        curr->port = v;
        if( curr->port != v ) {
          log("ERROR: %s contains value that is too large: %u", name, v);
          free(curr);
        }
        else {
          curr->port = htons(curr->port);
          ci_dllist_push(opt_list, &curr->link);
        }
        s = strchr(s, ',');
        if( s == NULL )
          break;
        s++;
      }
    }
  }
}

static void citp_update_and_crosscheck(ci_netif_config_opts* netif_opts,
                                       citp_opts_t* citp_opts)
{
  /*
   * ci_netif_config_opts_getenv() is called before
   * citp_transport_init(), so we need to update
   * update ci_cfg_opts.netif_opts.accept_inherit_nonblock,
   * making netifs to inherit flags if the O/S is
   * being forced to do so
   */
  if (citp_opts->accept_force_inherit_nonblock)
    netif_opts->accept_inherit_nonblock = 1;

  if( citp_opts->ul_epoll == 0 && netif_opts->int_driven == 0 ) {
    ci_log("EF_INT_DRIVEN=0 and EF_UL_EPOLL=0 are not compatible.  "
           "EF_INT_DRIVEN can be set to 0 implicitly, because of non-zero "
           "EF_POLL_USEC.  If you need both spinning and EF_UL_EPOLL=0, "
           "please set EF_INT_DRIVEN=1 explicitly.");
  }
  return;
}

static void citp_opts_getenv(citp_opts_t* opts)
{
  /* ?? TODO: would like to use opts_citp_def.h here */

  const char* s;
  unsigned v;

  opts->log_via_ioctl = 3;
  GET_ENV_OPT_INT("EF_LOG_VIA_IOCTL",	log_via_ioctl);

  if( (s = getenv("EF_LOG_FILE")) && opts->log_via_ioctl == 3) {
    opts->log_via_ioctl = 0;
    citp_log_to_file(s);
  } else if( opts->log_via_ioctl == 3 ) {
    /* citp_setup_logging_early() have already detected stderr as
     * tty/non-tty, so just trust it. */
    if( ci_log_fn == citp_log_fn_drv )
      opts->log_via_ioctl = 1;
    else
      opts->log_via_ioctl = 0;
  }

  if( opts->log_via_ioctl ) {
    ci_log_options &=~ CI_LOG_PID;
    citp_setup_logging_change(citp_log_fn_drv);
  } else {
    GET_ENV_OPT_INT("EF_LOG_TIMESTAMPS", log_timestamps);
    if( opts->log_timestamps )
      ci_log_options |= CI_LOG_TIME;
    citp_setup_logging_change(citp_log_fn_ul);
  }
  if( getenv("EF_LOG_THREAD") )
    ci_log_options |= CI_LOG_TID;


  if( getenv("EF_POLL_NONBLOCK_FAST_LOOPS") &&
      ! getenv("EF_POLL_NONBLOCK_FAST_USEC") )
    log("ERROR: EF_POLL_NONBLOCK_FAST_LOOPS is deprecated, use"
        " EF_POLL_NONBLOCK_FAST_USEC instead");

  if( getenv("EF_POLL_FAST_LOOPS") && ! getenv("EF_POLL_FAST_USEC") )
    log("ERROR: EF_POLL_FAST_LOOPS is deprecated, use"
        " EF_POLL_FAST_USEC instead");

  if( (s = getenv("EF_POLL_USEC")) && atoi(s) ) {
    /* Any changes to the behaviour triggered by this meta
     * option must also be made to the extensions API option
     * ONLOAD_SPIN_MIMIC_EF_POLL
     */
    GET_ENV_OPT_INT("EF_POLL_USEC", ul_spin_usec);
    GET_ENV_OPT_INT("EF_SLEEP_SPIN_USEC", sleep_spin_usec);
    opts->ul_select_spin = 1;
    opts->ul_poll_spin = 1;
    opts->ul_epoll_spin = 1;
    opts->udp_recv_spin = 1;
    opts->udp_send_spin = 1;
    opts->tcp_recv_spin = 1;
    opts->tcp_send_spin = 1;
    opts->pkt_wait_spin = 1;
    opts->sock_lock_buzz = 1;
    opts->stack_lock_buzz = 1;
  }

  if( (s = getenv("EF_BUZZ_USEC")) && atoi(s) ) {
    opts->sock_lock_buzz = 1;
    opts->stack_lock_buzz = 1;
  }

  GET_ENV_OPT_HEX("EF_UNIX_LOG",	log_level);
  GET_ENV_OPT_INT("EF_PROBE",		probe);
  GET_ENV_OPT_INT("EF_TCP",		ul_tcp);
  GET_ENV_OPT_INT("EF_UDP",		ul_udp);
  GET_ENV_OPT_INT("EF_UL_SELECT",	ul_select);
  GET_ENV_OPT_INT("EF_SELECT_SPIN",	ul_select_spin);
  GET_ENV_OPT_INT("EF_SELECT_FAST",	ul_select_fast);
  GET_ENV_OPT_INT("EF_UL_POLL",		ul_poll);
  GET_ENV_OPT_INT("EF_POLL_SPIN",	ul_poll_spin);
  GET_ENV_OPT_INT("EF_POLL_FAST",	ul_poll_fast);
  GET_ENV_OPT_INT("EF_POLL_FAST_USEC",  ul_poll_fast_usec);
  GET_ENV_OPT_INT("EF_POLL_NONBLOCK_FAST_USEC", ul_poll_nonblock_fast_usec);
  GET_ENV_OPT_INT("EF_SELECT_FAST_USEC",  ul_select_fast_usec);
  GET_ENV_OPT_INT("EF_SELECT_NONBLOCK_FAST_USEC", ul_select_nonblock_fast_usec);
  GET_ENV_OPT_INT("EF_UDP_RECV_SPIN",   udp_recv_spin);
  GET_ENV_OPT_INT("EF_UDP_SEND_SPIN",   udp_send_spin);
  GET_ENV_OPT_INT("EF_TCP_RECV_SPIN",   tcp_recv_spin);
  GET_ENV_OPT_INT("EF_TCP_SEND_SPIN",   tcp_send_spin);
  GET_ENV_OPT_INT("EF_TCP_ACCEPT_SPIN", tcp_accept_spin);
  GET_ENV_OPT_INT("EF_TCP_CONNECT_SPIN",tcp_connect_spin);
  GET_ENV_OPT_INT("EF_PKT_WAIT_SPIN",   pkt_wait_spin);
  GET_ENV_OPT_INT("EF_PIPE_RECV_SPIN",  pipe_recv_spin);
  GET_ENV_OPT_INT("EF_PIPE_SEND_SPIN",  pipe_send_spin);
  GET_ENV_OPT_INT("EF_PIPE_SIZE",       pipe_size);
  GET_ENV_OPT_INT("EF_SOCK_LOCK_BUZZ",  sock_lock_buzz);
  GET_ENV_OPT_INT("EF_STACK_LOCK_BUZZ", stack_lock_buzz);
  GET_ENV_OPT_INT("EF_SO_BUSY_POLL_SPIN", so_busy_poll_spin);
  GET_ENV_OPT_INT("EF_UL_EPOLL",        ul_epoll);
  GET_ENV_OPT_INT("EF_EPOLL_SPIN",      ul_epoll_spin);
  GET_ENV_OPT_INT("EF_EPOLL_CTL_FAST",  ul_epoll_ctl_fast);
  GET_ENV_OPT_INT("EF_EPOLL_CTL_HANDOFF",ul_epoll_ctl_handoff);
  GET_ENV_OPT_INT("EF_EPOLL_MT_SAFE",   ul_epoll_mt_safe);
  GET_ENV_OPT_INT("EF_WODA_SINGLE_INTERFACE", woda_single_if);
  GET_ENV_OPT_INT("EF_FDTABLE_SIZE",	fdtable_size);
  GET_ENV_OPT_INT("EF_SPIN_USEC",	ul_spin_usec);
  GET_ENV_OPT_INT("EF_SLEEP_SPIN_USEC",	sleep_spin_usec);
  GET_ENV_OPT_INT("EF_STACK_PER_THREAD",stack_per_thread);
  GET_ENV_OPT_INT("EF_DONT_ACCELERATE",	dont_accelerate);
  GET_ENV_OPT_INT("EF_FDTABLE_STRICT",	fdtable_strict);
  GET_ENV_OPT_INT("EF_FDS_MT_SAFE",	fds_mt_safe);
  GET_ENV_OPT_INT("EF_NO_FAIL",		no_fail);
  GET_ENV_OPT_INT("EF_SA_ONSTACK_INTERCEPT",	sa_onstack_intercept);
  GET_ENV_OPT_INT("EF_ACCEPT_INHERIT_NONBLOCK",	accept_force_inherit_nonblock);
  GET_ENV_OPT_INT("EF_VFORK_MODE",	vfork_mode);
  GET_ENV_OPT_INT("EF_PIPE",        ul_pipe);
  GET_ENV_OPT_INT("EF_SYNC_CPLANE_AT_CREATE",	sync_cplane);

  if( (s = getenv("EF_FORK_NETIF")) && sscanf(s, "%x", &v) == 1 ) {
    opts->fork_netif = CI_MIN(v, CI_UNIX_FORK_NETIF_BOTH);
  }
  if( (s = getenv("EF_NETIF_DTOR")) && sscanf(s, "%x", &v) == 1 ) {
    opts->netif_dtor = CI_MIN(v, CITP_NETIF_DTOR_ALL);
  }

  if( (s = getenv("EF_SIGNALS_NOPOSTPONE")) ) {
    opts->signals_no_postpone = 0;
    while( sscanf(s, "%u", &v) == 1 ) {
      opts->signals_no_postpone |= (1ULL << (v-1));
      s = strchr(s, ',');
      if( s == NULL )
        break;
      s++;
    }
  }
  /* SIGONLOAD is used internally, and should not be postponed. */
  opts->signals_no_postpone |= (1ULL << (SIGONLOAD-1));

  if( (s = getenv("EF_CLUSTER_NAME")) ) {
    strncpy(opts->cluster_name, s, CI_CFG_CLUSTER_NAME_LEN);
    opts->cluster_name[CI_CFG_CLUSTER_NAME_LEN] = '\0';
  }
  else {
    opts->cluster_name[0] = '\0';
  }
  GET_ENV_OPT_INT("EF_CLUSTER_SIZE",	cluster_size);
  if( opts->cluster_size < 0 )
    log("ERROR: invalid cluster_size. cluster_size needs to be 0 or a positive number");
  GET_ENV_OPT_INT("EF_CLUSTER_RESTART",	cluster_restart_opt);
  GET_ENV_OPT_INT("EF_CLUSTER_HOT_RESTART", cluster_hot_restart_opt);
  get_env_opt_port_list(&opts->tcp_reuseports, "EF_TCP_FORCE_REUSEPORT");
  get_env_opt_port_list(&opts->udp_reuseports, "EF_UDP_FORCE_REUSEPORT");

#if CI_CFG_FD_CACHING
  get_env_opt_port_list(&opts->sock_cache_ports, "EF_SOCKET_CACHE_PORTS");
#endif

  GET_ENV_OPT_INT("EF_ONLOAD_FD_BASE",	fd_base);
}


extern char** environ;
static void citp_opts_validate_env(void)
{
#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPTGROUP
#undef CI_CFG_OPT

#define CI_CFG_OPT(env, name, type, doc, bits, group, default, minimum, maximum, pres) env,

  char* ef_names[] = {
#include <ci/internal/opts_netif_def.h>
#include <ci/internal/opts_citp_def.h>
#include <ci/internal/opts_user_def.h>
    "EF_NAME",
    "EF_USERBUILD",
    "EF_NO_PRELOAD_RESTORE",
    "EF_LD_PRELOAD",
    "EF_CLUSTER_NAME",
    "EF_LOG_THREAD",
    "EF_LOG_FILE",
    "EF_VI_TXQ_SIZE",
    "EF_VI_RXQ_SIZE",
    "EF_VI_EVQ_SIZE",
    "EF_VI_CTPIO_WB_TICKS",
    "EF_VI_CTPIO_MODE",
    "EF_VI_CLUSTER_SOCKET",
    "EF_VI_PD_FLAGS",
    "EF_VI_LOG_LEVEL",
    "EF_VI_EVQ_CLEAR_STRIDE",
    "EF_BUILDTREE_UL",
    NULL
  };
  char** env_name;
  int i;
  int len;
  char* s;
  
  s = getenv("EF_VALIDATE_ENV");
  if( s ) {
    char* s_end;
    long v;
    v = strtol(s, &s_end, 0);
    
    if( ! s_end )
      ci_log("Invalid option for EF_VALIDATE_ENV: \"%s\"", s);
    else if( ! v )
      return;
  }
    
  env_name = environ;
  while( *env_name != NULL ) {
    
    if( ! strncmp(*env_name, "EF_", 3) ) {
      len = strchrnul(*env_name, '=') - *env_name;        
      for( i = 0;  ef_names[i]; ++i ) {
        if( strlen(ef_names[i]) == len &&
            ! strncmp(ef_names[i], *env_name, len) )
          break;
      }
      
      if( ! ef_names[i] )
        ci_log("Unknown option \"%s\" identified", *env_name);
    }
    env_name++;
  }
}


static int
citp_cfg_init(void)
{
  ci_cfg_query();
  return 0;
}


static int
citp_transport_init(void)
{
  const char* s;

  citp_get_process_name();
  citp_setup_logging_prefix();
  citp_opts_validate_env();

  CITP_OPTS.load_env = 1;
  if( (s = getenv("EF_LOAD_ENV")) )
    CITP_OPTS.load_env = atoi(s);
  if( CITP_OPTS.load_env )
    citp_opts_getenv(&CITP_OPTS);

  /* NB. We only look at EF_CONFIG_DUMP if EF_LOAD_ENV. */
  if( CITP_OPTS.load_env && getenv("EF_CONFIG_DUMP") ) {
    citp_dump_opts(&CITP_OPTS);
    citp_dump_config();
    /* ?? ci_netif_config_opts_dump(&citp.netif_opts); */
  }

  citp_oo_get_cpu_khz(&citp.cpu_khz);
  citp.spin_cycles = citp_usec_to_cycles64(CITP_OPTS.ul_spin_usec);
  citp.poll_nonblock_fast_cycles = 
    citp_usec_to_cycles64(CITP_OPTS.ul_poll_nonblock_fast_usec);
  citp.poll_fast_cycles = 
    citp_usec_to_cycles64(CITP_OPTS.ul_poll_fast_usec);
  citp.select_nonblock_fast_cycles = 
    citp_usec_to_cycles64(CITP_OPTS.ul_select_nonblock_fast_usec);
  citp.select_fast_cycles = 
    citp_usec_to_cycles64(CITP_OPTS.ul_select_fast_usec);
  ci_tp_init(__oo_per_thread_init_thread, oo_signal_terminate);

  citp_update_and_crosscheck(&ci_cfg_opts.netif_opts, &CITP_OPTS);
  return 0;
}


static int citp_transport_register(void)
{
  if( CITP_OPTS.ul_tcp )
    citp_protocol_manager_add(&citp_tcp_protocol_impl, 1);
  if( CITP_OPTS.ul_udp )
    citp_protocol_manager_add(&citp_udp_protocol_impl, 0);
  return 0;
}


int _citp_do_init_inprogress = 0;

typedef int (*cipt_init_func_t)(void);
cipt_init_func_t cipt_init_funcs[] =
{
#define STARTUP_ITEM(level, func) func,
#include "startup_order.h"
#undef STARTUP_ITEM
};

int citp_do_init(int max_init_level)
{
  int rc = 0;
  int level;
  int saved_errno = errno;

  if( citp.init_level < max_init_level ) {
    /* If threads are launched very early in program startup, then there could be
     * a race here as multiple threads attempt to initialise on first access.
     * The guard must be recursive, since this function might be re-entered during
     * initialisation.
     */
    static pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

    pthread_mutex_lock(&mutex);
    _citp_do_init_inprogress++;

    for (level = citp.init_level;
         level < CI_MIN(max_init_level, CITP_INIT_MAX);
         level++) {
      rc = cipt_init_funcs[level]();
      if (rc < 0)
        break;
      citp.init_level = level + 1;
    }

    --_citp_do_init_inprogress;
    pthread_mutex_unlock(&mutex);
  }
  Log_S(log("%s: reached level %d", __FUNCTION__, citp.init_level));
  if( rc == 0 )
    errno = saved_errno;
  return rc;
}

void _init(void)
{
  if (getpagesize() != CI_PAGE_SIZE)
    ci_fail(("Page size mismatch, expected %u, "
             "but the current value is %u",
             CI_PAGE_SIZE, getpagesize()));
  /* must not do any logging yet... */
  if( citp_do_init(CITP_INIT_MAX) < 0 )
    ci_fail(("EtherFabric transport library: failed to initialise (%d)",
             citp.init_level));

  Log_S(log("citp: initialisation done."));
}


void _fini(void)
{
  Log_S(log("citp: finishing up"));
  oo_exit_hook(0);
}


/* This is called if the library is run as an executable!
   Ensure that no libc() functions are used */
void onload_version_msg(void)
{
  const char* msg0[] = {
    onload_product, " ", onload_version, "\n",
    onload_copyright, "\n"
    "Built: "__DATE__" "__TIME__" "
#ifdef NDEBUG
    "(release)"
#else
    "(debug)"
#endif
    "\n"
    "Build profile header: " OO_STRINGIFY(TRANSPORT_CONFIG_OPT_HDR) "\n"};
#define MSG0_SIZE CI_ARRAY_SIZE(msg0)
  struct iovec v[MSG0_SIZE];
  int i;


  for( i = 0; i < MSG0_SIZE; i++ ) {
    v[i].iov_base = (char*)msg0[i]; /* discard const qualifier */
    v[i].iov_len = strlen(msg0[i]);
  }

  my_syscall3(writev, STDOUT_FILENO, (long) v, MSG0_SIZE);
  my_syscall3(exit, 0, 0, 0); 
}


/*! \cidoxg_end */
