/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/mount.h>
#ifndef NO_CAPS
#include <sys/capability.h>
#endif
#include <sys/prctl.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
#include <sched.h>

#include <ci/compat.h>
#include <ci/tools/log.h>
#include <ci/tools/debug.h>
#include <ci/app/testapp.h>
#include <ci/tools/namespace.h>
#include <ci/net/ipv4.h>

#include "private.h"
#include <onload/version.h>
#include <cplane/mib.h>
#include <cplane/mmap.h>
#include <cplane/ioctl.h>
#include <cplane/cplane.h>
#include <cplane/create.h>
#include <cplane/server.h>
#include "print.h"

#include <ci/internal/transport_config_opt.h>

/* CP_ANYUNIT is defined in private.h, so this check needs to come after the
 * inclusion. */
#ifndef CP_ANYUNIT
# include <onload/driveraccess.h>
#else
extern int oo_fd_open(int * fd_out);
#endif


#define DEV_KMSG "/dev/kmsg"

static char* cp_log_prefix;

/* cfg_dump_sec should be larger than license check time.  2s is too small. */
static int cfg_dump_sec = 3;
static int cfg_fwd_sec = 5;
static int ci_ver = false;
static int /*bool*/ cfg_nolisten = false;
static int cfg_fwd_cache_ttl = 300;
static char* cfg_ns_file = NULL;
static int /*bool*/ cfg_daemonise = false;
static int /*bool*/ ci_cfg_log_to_kern = false;
static int /*bool*/ ci_cfg_bootstrap = false;
static int /*bool*/ ci_cfg_no_ipv6 = false;
static int /*bool*/ ci_cfg_ipv6_no_source = false;
static uint64_t cfg_affinity = -1;
static int /*bool*/ ci_cfg_verify_routes = 0;
static int /*bool*/ cfg_track_xdp = false;

static int cfg_uid = 0;
static int cfg_gid = 0;

#ifndef NDEBUG
#define CFG_CORE_SIZE_DEFAULT -2
static int cfg_core_size = CFG_CORE_SIZE_DEFAULT;
#endif

static int cfg_hwport_max = CI_CFG_MAX_HWPORTS;
static int cfg_llap_max = 32;
static int cfg_ipif_max = CI_CFG_MAX_LOCAL_IPADDRS;
static int cfg_svc_arrays_max = 0;
static int cfg_svc_ep_max = 0;
static int cfg_bond_max = 64;
static int cfg_mac_max = 1024;
static int cfg_fwd_max = 1024;
static int cfg_dummy;
static int cfg_bond_base_msec = 100;
static int cfg_bond_peak_msec = 10;
static int cfg_bond_peak_polls = 20;
static int cfg_bond_3ad_dump_msec = 100;

static int /*bool*/ ci_cfg_pref_src_as_local = 0;

static ci_cfg_desc cfg_opts[] = {
  { 's', "dump",  CI_CFG_UINT, &cfg_dump_sec,
    "interval between table dump, in seconds" },
  { 0, "no-listen", CI_CFG_FLAG, &cfg_nolisten,
    "do not listen for netlink updates"       },
  { 0, "fwd-refresh",  CI_CFG_UINT, &cfg_fwd_sec,
    "interval between fwd cache housekeeping, in seconds" },
  { 't', "time-to-live", CI_CFG_UINT, &cfg_fwd_cache_ttl,
    "time-to-live for forward cache entries, in seconds" },
  { 0, CPLANE_SERVER_NS_CMDLINE_OPT, CI_CFG_STR, &cfg_ns_file,
    "path to a file specifying the network namespace to manage"
    "; when the Onload drivers launch the control plane server, by default "
    "this option is set" },
  { 'D', CPLANE_SERVER_DAEMONISE_CMDLINE_OPT, CI_CFG_FLAG, &cfg_daemonise,
    "daemonise at start and log to syslog"
    "; when the Onload drivers launch the control plane server, by default "
    "this option is set" },
  { 'K', "log-to-kmsg", CI_CFG_FLAG, &ci_cfg_log_to_kern,
    "log to "DEV_KMSG" (with -D only)" },
  { 0, CPLANE_SERVER_BOOTSTRAP, CI_CFG_FLAG, &ci_cfg_bootstrap,
    "manage the namespace even if there are no clients"
    "; when the Onload drivers launch the control plane server, by default "
    "this option is set" },
  { 0, CPLANE_SERVER_NO_IPV6, CI_CFG_FLAG, &ci_cfg_no_ipv6,
    "disable IPv6 support"
    "; when the Onload drivers launch the control plane server, by default "
    "this option is set" },
  { 0, CPLANE_SERVER_IPV6_NO_SOURCE, CI_CFG_FLAG, &ci_cfg_ipv6_no_source,
    "Kernel compiled without CONFIG_IPV6_SUBTREES" },
  { 0, "affinity", CI_CFG_UINT64, &cfg_affinity,
    "CPU mask to set the cp_server affinity to.  Limited to 64 cpus." },
  { 0, "verify-routes", CI_CFG_FLAG, &ci_cfg_verify_routes,
    "Verify that resolving a route via routing tables matches to the "
    "netlink opinion."},

  { 0, CPLANE_SERVER_UID, CI_CFG_UINT, &cfg_uid,
    "Drop privileges to this UID after start" },
  { 0, CPLANE_SERVER_GID, CI_CFG_UINT, &cfg_gid,
    "Drop privileges to this GID after start, see also --uid option" },

#ifndef NDEBUG
  { 0, CPLANE_SERVER_CORE_SIZE, CI_CFG_UINT, &cfg_core_size,
    "RLIMIT_CORE value" },
#endif

  { 'h', CPLANE_SERVER_HWPORT_NUM_OPT, CI_CFG_UINT, &cfg_hwport_max,
    "maximum number of hardware ports"
    "; when the Onload drivers launch the control plane server, by default "
    "this option is set to CI_CFG_MAX_HWPORTS" },
  { 'l', "llap-max", CI_CFG_UINT, &cfg_llap_max,
    "maximum number of network interfaces (including \"lo\")" },
  { 'i', CPLANE_SERVER_IPADDR_NUM_OPT, CI_CFG_UINT, &cfg_ipif_max,
    "maximum number of local IP addresses (on all interfaces)"
    "; when the Onload drivers launch the control plane server, by default "
    "this option is set to CI_CFG_MAX_LOCAL_IPADDRS" },
  { 0, "service-arrays-max", CI_CFG_UINT, &cfg_svc_arrays_max,
    "maximum number of k8s service backend arrays" },
  { 0, "service-endpoints-max", CI_CFG_UINT, &cfg_svc_ep_max,
    "maximum number of k8s service endpoints (frontends + backends) "
    "(will be rounded up to a power of 2)" },
  { 'b', "bond-max", CI_CFG_UINT, &cfg_bond_max,
    "maximum number of bond/team interfaces and their ports" },
  { 'm', "mac-max", CI_CFG_UINT, &cfg_mac_max,
    "maximum number of ARP entries in the system "
    "(will be rounded up to a power of 2)" },
  { 'f', "fwd-max", CI_CFG_UINT, &cfg_fwd_max,
    "maximum number of remote addresses used by Onload"
    "(will be rounded up to a power of 2)" },
  { 'r', "fwd-req-max", CI_CFG_UINT, &cfg_dummy, "ignored" },
  { 0, "bond-base-period",  CI_CFG_UINT, &cfg_bond_base_msec,
    "interval between background bond-state polls, in milliseconds" },
  { 0, "bond-peak-period",  CI_CFG_UINT, &cfg_bond_peak_msec,
    "interval between peak-rate bond-state polls, in milliseconds" },
  { 0, "bond-peak-polls",  CI_CFG_UINT, &cfg_bond_peak_polls,
    "number of peak-rate bond polls before reverting to background rate" },
  { 0, "bond-3ad-period", CI_CFG_UINT, &cfg_bond_3ad_dump_msec,
    "interval between re-dumping bond-3ad slave state, in milliseconds" },
  { 0, "version", CI_CFG_FLAG, &ci_ver, "print cplane version and exit" },
  { 0, CPLANE_SERVER_PREFSRC_AS_LOCAL, CI_CFG_FLAG, &ci_cfg_pref_src_as_local,
    "Tell oof that a preferred source of any accelerated route is a local "
    "address for the network interface the route goes via.  This setting "
    "allows to accelerate unbound connections via such routes." },
  { 0, CPLANE_SERVER_TRACK_XDP, CI_CFG_FLAG, &cfg_track_xdp,
    "Track XDP programs linked to network interfaces.  Such tracking "
    "is needed for EF_XDP_MODE=compatible, and prevents dropping "
    "CAP_SYS_ADMIN capability of the server." },
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))


CI_NORETURN init_failed(const char* msg, ...)
{
  va_list args;
  va_start(args, msg);
  ci_vlog(msg, args);
  va_end(args);
  ci_log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  ci_log("!!! Onload Control Plane server has FAILED TO START !!!");
  ci_log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  exit(1);
}

/* We pass the cp_session parameter through the function call chain, and in
 * the most cases we do not need it to be static.  However, signal handlers
 * are trickier, so */
static struct cp_session session;

static int init_netlink_sock(struct cp_session* s, int protocol,
                             uint32_t groups)
{
  /* /proc/sys/net/core/rmem_max is typically less than 1M, so we won't be
   * allowed to set so large rcvbuf value.  Should we use SO_RCVBUFFORCE? */
  int rcvbuf = 1 << 24;
  struct sockaddr_nl sa;
  int rc;
  int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, protocol);

#define PROTO_NAME \
  protocol == NETLINK_ROUTE ? "NETLINK_ROUTE" : "NETLINK_GENERIC"
  if( sock < 0 ) {
    init_failed("Can't open netlink socket %s: %s",
                PROTO_NAME, strerror(errno));
  }

  rc = setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                  &rcvbuf, sizeof(rcvbuf));
  if( rc != 0 ) {
    ci_log("Failed to increase SO_RCVBUF for netlink socket %s: %s",
           PROTO_NAME, strerror(errno));
  }

  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_groups = groups;
  rc = bind(sock, (struct sockaddr*)&sa, sizeof(sa));
  if( rc != 0 ) {
    init_failed("Failed to bind %s socket: %s",
                PROTO_NAME, strerror(errno));
  }
#undef PROTO_NAME

  return sock;
}

#ifndef RTMGRP_IPV6_RULE
/* For some reason Linux does not provide this macro */
#define RTMGRP_IPV6_RULE (1 << (RTNLGRP_IPV6_RULE-1))
#endif

static void init_files(struct cp_session* s)
{
  ci_uint32 khz;
  socklen_t socklen;
  int rc;
  /* We listen for ARP updates even with cfg_nolisten, because 1sec delay
   * for ARP annoys too many tests. */
  uint32_t groups = RTMGRP_NEIGH;

  if( cfg_nolisten ) {
    s->flags |= CP_SESSION_NO_LISTEN;
  }
  else {
    groups |= RTMGRP_LINK | RTMGRP_IPV4_IFADDR |
              RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_RULE;

    if( ~s->flags & CP_SESSION_NO_IPV6 )
      groups |= RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE |
                RTMGRP_IPV6_RULE;
  }

  s->sock_net = init_netlink_sock(s, NETLINK_ROUTE, groups);
  socklen = sizeof(s->sock_net_name);
  rc = getsockname(s->sock_net, (struct sockaddr*)&s->sock_net_name,
                   &socklen);
  if( rc != 0 ) {
    init_failed("getsockname(nenlink socket) failed: %s",
                strerror(errno));
  }

  s->sock_gen[CP_GENL_GROUP_CTRL] = init_netlink_sock(s, NETLINK_GENERIC, 0);
  if( ! cfg_nolisten ) {
    /* We handle dumps via the first NETLINK_GENERIC socket, so this one is
     * used for listening only. */
    s->sock_gen[CP_GENL_GROUP_TEAM] =
                                init_netlink_sock(s, NETLINK_GENERIC, 0);
  }

  rc = pipe(s->pipe);
  if( rc != 0 )
    init_failed("Pipe creation failed: %s", strerror(errno));

  s->sock = socket(AF_INET, SOCK_DGRAM, 0);
  if( s->sock < 0 )
    init_failed("Can not open a UDP socket: %s", strerror(errno));

  rc = oo_fd_open(&s->oo_fd);
  if( rc != 0 )
    init_failed("Can not open the Onload device: %s", strerror(errno));

  rc = cplane_ioctl(s->oo_fd, OO_IOC_CP_CHECK_VERSION, &oo_cplane_api_version);
  if( rc != 0 )
    init_failed("API version mismatch (see dmesg)");

  rc = cplane_ioctl(s->oo_fd, OO_IOC_GET_CPU_KHZ, &khz);
  if( rc != 0 ) {
    init_failed("Can not get CPU frequency measured by Onload: %s",
                strerror(errno));
  }
  s->khz = khz;

  /* 1000 is CLOCKS_PER_SEC converted to ms */
  s->user_hz = 1000 / sysconf(_SC_CLK_TCK);

  /* Initial sizes for route_dst and rule_src are enlarged at need. */
  cp_ippl_init(&s->route_dst, sizeof(struct cp_ip_with_prefix), NULL, 4);
  cp_ippl_init(&s->rule_src, sizeof(struct cp_ip_with_prefix), NULL, 4);
  cp_ippl_init(&s->ip6_route_dst, sizeof(struct cp_ip_with_prefix), NULL, 4);
  cp_ippl_init(&s->ip6_rule_src, sizeof(struct cp_ip_with_prefix), NULL, 4);
  cp_ippl_init(&s->laddr, sizeof(struct cp_ip_with_prefix), NULL, 4);
}


/* This is the part of the initialisation of the session's memory that is
 * common with the unit tests. */
CP_UNIT_EXTERN int
cp_session_init_memory(struct cp_session* s, struct cp_tables_dim* m,
                       void* mib_mem)
{
  s->mib[1].dim = s->mib[0].dim = mib_mem;
  cp_init_mibs(mib_mem, s->mib);

  int i;
  for( i = 0; i < 2; ++i ) {
    struct cp_mibs* mib = &s->mib[i];
    cicp_mac_rowid_t id;
    for( id = 0; id < mib->dim->ipif_max; id++ )
      cicp_ipif_row_free(&mib->ipif[id]);
    for( id = 0; id < mib->dim->ip6if_max; id++ )
      cicp_ip6if_row_free(&mib->ip6if[id]);
    for( id = 0; id < mib->dim->llap_max; id++ )
      cicp_llap_row_free(&mib->llap[id]);
    snprintf(mib->sku->value, sizeof(mib->sku->value), "%s", onload_product);
  }
  ci_wmb();

  s->seen = cp_row_mask_alloc(CI_MAX(
        CI_MAX(m->fwd_mask, s->mac_mask) + 1,
        (cicp_mac_rowid_t)CI_MAX(m->llap_max,
        CI_MAX(m->ipif_max, m->ip6if_max))));
  s->mac_used = cp_row_mask_alloc(s->mac_mask + 1);
  s->ip6_mac_used = cp_row_mask_alloc(s->mac_mask + 1);
  s->service_used = cp_row_mask_alloc(m->svc_arrays_max);

  /* Any allocations that succeed here will be leaked if others fail, but the
   * caller will exit on failure so this is fine */
  if( s->seen == NULL || s->mac_used == NULL || s->ip6_mac_used == NULL ||
      s->service_used == NULL )
    return -ENOMEM;

#define CHECK_CALLOC(target, num) \
  (target) = calloc((num), sizeof(*(target))); \
  if( (target) == NULL ) \
    return -ENOMEM;

  CHECK_CALLOC(s->llap_priv, m->llap_max);
  CHECK_CALLOC(s->bond, cfg_bond_max);
  CHECK_CALLOC(s->mac, s->mac_mask + 1);
  CHECK_CALLOC(s->ip6_mac, s->mac_mask + 1);

#undef CHECK_CALLOC

  /* The control plane server always refers to fwd tables by ID, and so it
   * never uses the fwd_table member in the mib. */
  memset(&s->mib[0].fwd_table, 0, sizeof(struct cp_fwd_table));
  memset(&s->mib[1].fwd_table, 0, sizeof(struct cp_fwd_table));

  *s->mib[0].idle_version = 1;

  return 0;
}


/* Allocate aligned memory and set up mibs. All dimentions are supposed
 * to be divisible by 4. */
static void init_memory(struct cp_tables_dim* m, struct cp_session* s)
{
  int rc;
  void* mem;
  size_t mib_size = cp_calc_mib_size(m);

  /* We need continuous chunk of memory to put the MIB tables.  The memory
   * should be continouus in kernel, cplane process and Onloaded processes.
   * The best way to archive this is to allocate continuous memory in
   * kernel and than mmap it to UL processes.
   */
  mem = mmap(NULL, CI_ROUND_UP(mib_size, CI_PAGE_SIZE), PROT_READ | PROT_WRITE,
             MAP_SHARED, s->oo_fd,
             OO_MMAP_MAKE_OFFSET(OO_MMAP_TYPE_CPLANE, OO_MMAP_CPLANE_ID_MIB));
  if( mem == MAP_FAILED ) {
    if( errno == EBUSY ) {
      /* EBUSY is possible in normal operation if multiple clients start
       * before a server is ready, so exit more gracefully than init_failed().
       */
      ci_log("A server already exists for this namespace.  Exiting.");
      exit(1);
    }
    init_failed("ERROR: failed to register MIB memory: %s", strerror(errno));
  }

  /* Kernel gives zeroed memory, so we do not need to memset it. */

  /* The cp_tables_dim structure lives at the very start of the mib memory.
   * The first thing we need to do is to populate this structure with the
   * values given to us by the caller.  Having done that, the values will be
   * visible to the kernel, and the kernel can initialise its own mibs. */
  memcpy(mem, m, sizeof(*m));
  rc = cplane_ioctl(s->oo_fd, OO_IOC_CP_INIT_KERNEL_MIBS, &s->cplane_id);
  if( rc != 0 )
    init_failed("ERROR: Failed to initialise kernel mibs: %s",
                strerror(errno));


#ifdef CP_SYSUNIT
  ci_assert_ge(CP_SHIM_MIB_BYTES, CI_ROUND_UP(mib_size, CI_PAGE_SIZE));
  ci_assert_ge(CP_SHIM_FWD_BYTES, CI_ROUND_UP(cp_calc_fwd_blob_size(m),
                                              CI_PAGE_SIZE));
  ci_assert_ge(CP_SHIM_FWD_RW_BYTES, CI_ROUND_UP(cp_calc_fwd_rw_size(m),
                                                 CI_PAGE_SIZE));
#endif

  if( cp_session_init_memory(s, m, mem) != 0 )
    init_failed("ERROR: malloc() failed");
}


static void free_session(struct cp_session* s)
{
  cp_epoll_unregister(s, s->ep_net);
  cp_epoll_unregister(s, s->ep_gen_ctrl);
  cp_epoll_unregister(s, s->ep_gen_team);
  cp_epoll_unregister(s, s->ep_mibdump);
  cp_epoll_unregister(s, s->ep_agent);
  cp_epoll_unregister(s, s->ep_oo);
}


static void handle_sigquit(int sig, siginfo_t* info, void* context)
{
  ci_log("Received signal: %s.", strsignal(sig));
  free_session(&session);
  free(cp_log_prefix);
  exit(0);
}


CP_UNIT_EXTERN void cp_timer_expire(struct cp_timer* cpt, int type)
{
  struct cp_session* s;

  switch( type ) {
    case CP_TIMER_NET:
      s = CI_CONTAINER(struct cp_session, timer_net, cpt);
      cp_periodic_dump(s);
      break;

    case CP_TIMER_FWD:
      s = CI_CONTAINER(struct cp_session, timer_fwd, cpt);
      cp_fwd_timer(s);
      break;
  }
}

static void handle_sigalarm(int sig, siginfo_t* info, void* context)
{
  struct cp_timer* cpt = CI_CONTAINER(struct cp_timer, t,
                                      (timer_t*)info->si_value.sival_ptr);
  cp_timer_expire(cpt, cpt->type);
}

static void cp_kmsg_handle(struct cp_session* s, struct cp_epoll_state* state)
{
  struct cp_helper_msg msg;
  int rc;

  /* The driver does not allow short reads.  At the same time, the driver
   * does not send us arbitrary-sized messages.  So we expect that the
   * following read() returns sizeof(msg) or 0. */
  while( (rc = read(state->fd, &msg, sizeof(msg))) > 0 ) {
    ci_assert_equal(rc, sizeof(msg));
    (void)rc; /* unused in ndebug build */
    switch( msg.hmsg_type ) {
    case CP_HMSG_FWD_REQUEST:
      cp_fwd_req_do(s, msg.u.fwd_request.id, &msg.u.fwd_request.key);
      break;
    case CP_HMSG_VETH_SET_FWD_TABLE_ID:
      cp_veth_fwd_table_id_do(s, msg.u.veth_set_fwd_table_id.veth_ifindex,
                              msg.u.veth_set_fwd_table_id.fwd_table_id);
      break;
    case CP_HMSG_SET_HWPORT:
      /* ifindex == CI_IFID_BAD denotes "dump done" */
      if( msg.u.set_hwport.ifindex != CI_IFID_BAD ) {
        cp_populate_llap_hwports(s, msg.u.set_hwport.ifindex,
                                 msg.u.set_hwport.hwport,
                                 msg.u.set_hwport.nic_flags);
        cp_llap_fix_upper_layers(s);
      }
      else if( ! (s->flags & CP_SESSION_HWPORT_DUMPED) ) {
        s->flags |= CP_SESSION_HWPORT_DUMPED;
        if( s->flags & CP_SESSION_NETLINK_DUMPED )
          cp_ready_usable(s);
      }
      break;
    default:
      CI_RLLOG(10, "%s: Unexpected hmsg_type %d", __FUNCTION__, msg.hmsg_type);
      ci_assert(0);
      break;
    }
  }
}


static void oof_req_sig(int sig, siginfo_t* info, void* context)
{
  cp_oof_req_do(&session);
}

static void llap_update_sig(int sig, siginfo_t* info, void* context)
{
  cp_llap_fix_upper_layers(&session);
}

static void handle_os_sync_signal(int sig, siginfo_t* info, void* context)
{
  struct cp_session* s = &session;

  switch( info->si_code ) {
    case CP_SYNC_DUMP:
      s->flags |= CP_SESSION_USER_DUMP;
      if( s->state == CP_DUMP_IDLE )
        cp_dump_init(s);
      else
        s->flags |= CP_SESSION_USER_DUMP_REFRESH;
      break;

    case CP_SYNC_LIGHT:
      (*s->mib[0].idle_version) |= 1;
      s->flags |= CP_SESSION_USER_OS_SYNC;
      break;
  }
}


static void init_signals(struct cp_session* s)
{
  struct sigaction act;
  sigset_t sigmask;
  struct sigevent sev;
  struct itimerspec its;
  int rc;
  int i;
  struct cp_mibs* mib = cp_get_active_mib(s);
  const int masked_signals[] = {
    mib->dim->oof_req_sig,
    mib->dim->llap_update_sig,
    SIGQUIT,
    SIGTERM,
    SIGINT,
    SIGALRM,
    mib->dim->os_sync_sig,
  };

  /* Ensure that various signals does not come when we are modifying - so we
   * do not need any interlocking between signal handlers and epoll handlers.
   */
  rc = sigemptyset(&sigmask);
  if( rc < 0 )
    init_failed("sigemptyset() failed: %s", strerror(errno));
  for( i = 0; i < sizeof(masked_signals) / sizeof(*masked_signals); ++i ) {
    rc = sigaddset(&sigmask, masked_signals[i]);
    if( rc < 0 ) {
      init_failed("sigaddset(%d) failed: %s", masked_signals[i],
                  strerror(errno));
    }
  }
  rc = sigprocmask(SIG_BLOCK, &sigmask, NULL);
  if( rc < 0 )
    init_failed("sigprocmask(SIG_BLOCK) failed: %s", strerror(errno));

  memset(&act, 0, sizeof(act));
  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = oof_req_sig;
  rc = sigaction(mib->dim->oof_req_sig, &act, NULL);
  if( rc < 0 )
    init_failed("sigaction(%d) failed: %s", mib->dim->oof_req_sig,
                strerror(errno));
  act.sa_sigaction = llap_update_sig;
  rc = sigaction(mib->dim->llap_update_sig, &act, NULL);
  if( rc < 0 )
    init_failed("sigaction(%d) failed: %s", mib->dim->llap_update_sig,
                strerror(errno));

  act.sa_sigaction = handle_sigquit;
  rc = sigaction(SIGQUIT, &act, NULL);
  if( rc < 0 )
    init_failed("sigaction(SIGQUIT) failed: %s", strerror(errno));
  rc = sigaction(SIGTERM, &act, NULL);
  if( rc < 0 )
    init_failed("sigaction(SIGTERM) failed: %s", strerror(errno));
  rc = sigaction(SIGINT, &act, NULL);
  if( rc < 0 )
    init_failed("sigaction(SIGINT) failed: %s", strerror(errno));

  act.sa_sigaction = handle_sigalarm;
  rc = sigaction(SIGALRM, &act, NULL);
  if( rc < 0 )
    init_failed("sigaction(SIGALRM) failed: %s", strerror(errno));

  /* We do not need a separate thread to handle signals, so let's use
   * SIGEV_THREAD_ID instead of SIGEV_SIGNAL to delive all the signals to
   * the main thread. */
  sev.sigev_notify = SIGEV_THREAD_ID;
  sev.sigev_signo = SIGALRM;
#if defined(sigev_notify_thread_id)
  sev.sigev_notify_thread_id = gettid();
#else
  /* RHEL6 developer build */
  sev._sigev_un._tid = syscall(SYS_gettid);
#endif

  act.sa_sigaction = handle_os_sync_signal;
  rc = sigaction(mib->dim->os_sync_sig, &act, NULL);
  if( rc < 0 )
    init_failed("sigaction(%d) failed: %s", mib->dim->os_sync_sig,
                strerror(errno));

  /* We need to dump all tables just now (i.e. it_value should be non-zero
   * but close to zero): */
  s->timer_net.type = CP_TIMER_NET;
  sev.sigev_value.sival_ptr = &s->timer_net.t;
  rc = timer_create(CLOCK_MONOTONIC, &sev, &s->timer_net.t);
  if( rc < 0 )
    init_failed("timer_create(TIMER_NET) failed: %s", strerror(errno));
  its.it_value.tv_sec = 0;
  its.it_value.tv_nsec = 1;
  /* ... and repeat it every cfg_dump_sec: */
  its.it_interval.tv_sec = cfg_dump_sec;
  its.it_interval.tv_nsec = 0;
  rc = timer_settime(s->timer_net.t, 0, &its, NULL);
  if( rc < 0 )
    init_failed("timer_settime(TIMER_NET) failed: %s", strerror(errno));

  /* Go through fwd cache and remove unused entries, re-confirm
   * almost-stale entries. */
  s->timer_fwd.type = CP_TIMER_FWD;
  sev.sigev_value.sival_ptr = &s->timer_fwd.t;
  rc = timer_create(CLOCK_MONOTONIC, &sev, &s->timer_fwd.t);
  if( rc < 0 )
    init_failed("timer_create(TIMER_FWD) failed: %s", strerror(errno));
  its.it_value.tv_sec = its.it_interval.tv_sec = cfg_fwd_sec;
  its.it_value.tv_nsec = its.it_interval.tv_nsec = 0;
  rc = timer_settime(s->timer_fwd.t, 0, &its, NULL);
  if( rc < 0 )
    init_failed("timer_settime(TIMER_FWD) failed: %s", strerror(errno));
}

static void init_epoll(struct cp_session* s)
{
  s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if( s->epoll_fd < 0 )
    init_failed("Can not create a epoll file descriptor: %s",
                strerror(errno));

  s->ep_net = cp_epoll_register(s, s->sock_net, nl_net_handle, 0);
  if( s->ep_net == NULL )
    init_failed("Can not add netlink route socket to the epoll fd: %s",
                strerror(errno));

  s->ep_gen_ctrl = cp_epoll_register(s, s->sock_gen[CP_GENL_GROUP_CTRL],
                                     nl_gen_ctrl_handle, 0);
  if( s->ep_gen_ctrl == NULL )
    init_failed("Can not add netlink generic ctrl socket to the epoll fd: %s",
                strerror(errno));

  if( ! cfg_nolisten ) {
    s->ep_gen_team = cp_epoll_register(s, s->sock_gen[CP_GENL_GROUP_TEAM],
                                       nl_gen_team_handle, 0);
    if( s->ep_gen_team == NULL )
      init_failed("Can not add netlink generic team socket to the epoll fd: %s",
                  strerror(errno));
  }

  s->ep_mibdump = cp_epoll_register(s, s->mibdump_sock,
                                    cp_mibdump_sock_handle, 0);
  if( s->ep_mibdump == NULL )
    init_failed("Can not add mibdump socket to the epoll fd: %s",
                strerror(errno));

#ifdef CP_SYSUNIT
  char pipe_name[50];
  snprintf(pipe_name, sizeof(pipe_name), "/tmp/onload_cp_server.%d", s->mib->dim->server_pid);
  pipe_name[sizeof(pipe_name) - 1] = '\0';
  int rc = mknod(pipe_name, S_IFIFO | 0666, 0);
  if( rc < 0 ) {
    init_failed("Can not create named pipe %s: %s", pipe_name, strerror(errno));
  }
  s->comm_pipe = open(pipe_name, O_RDONLY | O_NONBLOCK);
  if( s->comm_pipe < 0 ) {
    init_failed("Can not open named pipe %s: %s", pipe_name, strerror(errno));
  }
  s->ep_oo = cp_epoll_register(s, s->comm_pipe, cp_kmsg_handle, 0);
  if( s->ep_oo == NULL )
    init_failed("Can not add %s file descriptor to the epoll fd: %s",
                pipe_name, strerror(errno));
#else
  if( cfg_ns_file == NULL ) {
    s->ep_agent = cp_epoll_register(s, s->agent_sock, cp_agent_sock_handle, 0);
    if( s->ep_agent == NULL )
      init_failed("Can not add agent socket to the epoll fd: %s",
                  strerror(errno));
  }

  s->ep_oo = cp_epoll_register(s, s->oo_fd, cp_kmsg_handle, 0);
  if( s->ep_oo == NULL )
    init_failed("Can not add /dev/onload file descriptor to the epoll fd: %s",
                strerror(errno));
#endif
}


#ifndef CP_UNIT
/* Work around the fact that we want to use oo_cp_create() without depending
 * on the whole of lib/transport/unix. */
int (* ci_sys_ioctl)(int, long unsigned int, ...) = cplane_ioctl;
#endif


static int init_main_cplane(struct cp_session* s)
{
  int main_cp_fd;
  int rc = oo_fd_open(&main_cp_fd);
  if( rc < 0 ) {
    init_failed("Can't open main cplane fd: %s", strerror(-rc));
  }

  struct oo_cplane_handle* main_cp = malloc(sizeof(struct oo_cplane_handle));
  if( main_cp == NULL ) {
    init_failed("Failed to allocate main cplane memory %s\n",
                strerror(-ENOMEM));
  }

  rc = oo_cp_create(main_cp_fd, main_cp, CP_SYNC_LIGHT, 0);
  if( rc < 0 ) {
    init_failed("Failed to initialize Main Control Plane: %s\n",
                strerror(-rc));
  }
  s->main_cp_fd = main_cp_fd;
  s->main_cp_handle = main_cp;
  return 0;
}

static void set_log_prefix(void)
{
  asprintf(&cp_log_prefix, "onload_cp_server[%d]: ", getpid());
  ci_set_log_prefix(cp_log_prefix);
}

/* Fork off a daemon process according to the recipe in "man 7 daemon".  This
 * function returns only in the context of the daemon, and only on success;
 * otherwise, it exits. */
static void daemonise(void)
{
  pid_t child;
  int rc;
  int devnull;
  int i;
  sigset_t sigset;
  struct rlimit rlim;

  /* Start with some tidy-up.  We don't check errors here as failure is non-
   * fatal. */

  /* Close all files above stderr. */
  if( getrlimit(RLIMIT_NOFILE, &rlim) == 0 )
    for( i = STDERR_FILENO + 1; i < rlim.rlim_max; ++i )
      close(i);

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
    init_failed("Failed to fork: %s", strerror(errno));
  else if( child != 0 )
    /* Parent process. */
    exit(0);

  /* Get a new session. */
  rc = setsid();
  if( rc == -1 )
    init_failed("setsid() failed: %s", strerror(errno));

  /* Fork to relinquish position as process group leader. */
  child = fork();
  if( child == -1 ) {
    init_failed("Failed to fork: %s", strerror(errno));
  }
  else if( child != 0 ) {
    /* Parent process.  The child is the 'real' daemon. */
    exit(0);
  }
  ci_log("Spawned daemon process %d", getpid());

  umask(0);
  rc = chdir("/");
  if( rc == -1 )
    init_failed("Failed to change to root directory: %s", strerror(errno));

  devnull = open("/dev/null", O_RDONLY);
  if( devnull == -1 )
    init_failed("Failed to open /dev/null for reading: %s", strerror(errno));
  rc = dup2(devnull, STDIN_FILENO);
  if( rc == -1 )
    init_failed("Failed to dup /dev/null onto stdin: %s", strerror(errno));
  close(devnull);

  devnull = open(ci_cfg_log_to_kern ? DEV_KMSG : "/dev/null", O_WRONLY);
  if( devnull == -1 )
    init_failed("Failed to open /dev/null for writing: %s", strerror(errno));

  /* Start logging to syslog before we nullify std{out,err}. */
  if( ! ci_cfg_log_to_kern ) {
    ci_set_log_prefix("");
    ci_log_fn = ci_log_syslog;
    openlog(NULL, LOG_PID, LOG_DAEMON);
  }
  else {
    /* Use the new PID when logging. */
    set_log_prefix();
  }

  rc = dup2(devnull, STDOUT_FILENO);
  if( rc == -1 )
    init_failed("Failed to dup /dev/null onto stdout: %s", strerror(errno));
  rc = dup2(devnull, STDERR_FILENO);
  if( rc == -1 )
    init_failed("Failed to dup /dev/null onto stderr: %s", strerror(errno));
  close(devnull);
}


/* Normally the kernel will refuse to allow the server to start if there are no
 * active clients for the namespace (i.e. if there are sufficiently few
 * references to the kernel's cplane handle).  This prevents some races when
 * spawning servers just-in-time.  However, it is sometimes useful to start a
 * server even when there are no clients, both for testing, and as a
 * convenience in the default namespace (avoiding the delay at stack-startup).
 * This function achieves this by creating an artificial 'client' for the
 * namespace that lasts for the lifetime of this process. */
static void bring_up_kernel_state(void)
{
  int fd;
  int rc;
  int i;

  /* The kernel spawns us right at the end of module-load, and modprobe creates
   * device nodes immediately after the module has loaded, so there's a race in
   * opening /dev/onload.  Retry a few times before giving up. */
  const int DEV_ONLOAD_RETRIES = 5;
  for( i = 0;
       (rc = oo_fd_open(&fd)) == -ENOENT && i < DEV_ONLOAD_RETRIES;
       usleep(100000 << ++i) )
    ;

  if( rc != 0 )
    init_failed("%s: Failed to open /dev/onload: %s", __func__, strerror(-rc));

  rc = cplane_ioctl(fd, OO_IOC_CP_LINK);
  if( rc != 0 )
    init_failed("%s: Failed to link to cplane: %s", __func__, strerror(-rc));

  /* We deliberately leak the fd.  We want it to stay open until the process
   * exits, but we have no further direct use for it. */
}


#ifndef NO_CAPS
#ifndef CP_ANYUNIT
/* Drop all capabilities except CAP_NET_ADMIN; switch uid/gid. */
static void
drop_privileges(struct cp_session* s, bool in_main_netns)
{
  int rc;

  /* Do not drop CAP_NET_ADMIN when dropping uid/gid if we are in the main
   * namespace. */
  if( cfg_gid != 0 || cfg_uid != 0 ) {
    rc = prctl(PR_SET_KEEPCAPS, 1);
    if( rc == -1 )
      init_failed("Failed to keep capablilties via prctl: %s",
                  strerror(errno));
  }

  /* UID/GID. */
  if( cfg_gid != 0 ) {
    rc = setresgid(cfg_gid, cfg_gid, cfg_gid);
    if( rc == -1 )
      init_failed("Failed to drop GID to %d: %s", cfg_gid, strerror(errno));
  }
  if( cfg_uid != 0 ) {
    rc = setresuid(cfg_uid, cfg_uid, cfg_uid);
    if( rc == -1 )
      init_failed("Failed to drop UID to %d: %s", cfg_uid, strerror(errno));
  }

  cap_t cap = cap_init();
  if( cap == NULL )
    init_failed("Failed to allocate capabilities: %s", strerror(errno));

  /* We really need CAP_NET_ADMIN, otherwise we won't see teaming.
   * We do not need any other capabilities.
   *
   * In theory, we do not support teaming in namespace, but insufficient
   * permissions break dump state machine, so we keep CAP_NET_ADMIN in all
   * the cases.
   */
  cap_value_t cap_val = CAP_NET_ADMIN;
  rc = cap_set_flag(cap, CAP_EFFECTIVE, 1, &cap_val, CAP_SET);
  if( rc == -1 )
    init_failed("Failed to set CAP_NET_ADMIN flag to CAP_EFFECTIVE: %s",
                strerror(errno));
  rc = cap_set_flag(cap, CAP_PERMITTED, 1, &cap_val, CAP_SET);
  if( rc == -1 )
    init_failed("Failed to set CAP_NET_ADMIN flag to CAP_PERMITTED: %s",
                strerror(errno));

  /* We have to obtain a bpf file descriptor to pass it to kernel.
   * It is stupid, bpf_prog_by_id() is not exported, so can't be used by
   * the Onload module.
   *
   * Unfortunately BPF_PROG_GET_FD_BY_ID requires CAP_SYS_ADMIN
   */
  if( cfg_track_xdp ) {
    cap_val = CAP_SYS_ADMIN;
    rc = cap_set_flag(cap, CAP_EFFECTIVE, 1, &cap_val, CAP_SET);
    if( rc == -1 )
      init_failed("Failed to set CAP_SYS_ADMIN flag to CAP_EFFECTIVE: %s",
                  strerror(errno));
    rc = cap_set_flag(cap, CAP_PERMITTED, 1, &cap_val, CAP_SET);
    if( rc == -1 )
      init_failed("Failed to set CAP_SYS_ADMIN flag to CAP_PERMITTED: %s",
                  strerror(errno));
  }

  /* Set the capabilities: */
  rc = cap_set_proc(cap);
  if( rc == -1 )
    init_failed("Failed to set CAP_NET_ADMIN and CAP_SYS_ADMIN to the process: %s",
                strerror(errno));
  rc = cap_free(cap);
  if( rc == -1 )
    init_failed("Failed to free capabilities: %s", strerror(errno));

#ifndef NDEBUG
  if( cfg_core_size != CFG_CORE_SIZE_DEFAULT ) {
    struct rlimit lim;
    lim.rlim_cur = lim.rlim_max = cfg_core_size;
    rc = setrlimit(RLIMIT_CORE, &lim);
    if( rc == -1 )
      ci_log("Failed to set RLIMIT_CORE to %d: %s",
             cfg_core_size, strerror(errno));
  }
#endif
}
#endif
#endif


static int
oo_op_notify_all(struct cp_session* s)
{
  return cplane_ioctl(s->oo_fd, OO_IOC_CP_NOTIFY_LLAP_MONITORS, NULL);
}


/* This function is used in CP_SYSUNIT builds but not in CP_UNIT builds.  In
 * the latter case, we still build it in order to avoid unused-symbol warnings.
 */
#ifdef CP_ANYUNIT
int cp_server_entry(int argc, char** argv)
#else
int main(int argc, char** argv)
#endif
{
  struct cp_tables_dim dim = {}; /* clears server_pid field for tests */
  sigset_t sigmask;
  struct cp_session* s = &session;
  int rc;

  /* Set sutable prefix */
  set_log_prefix();

  /* Ensure that early errors are not lost */
  struct stat stat;
  if( fstat(STDOUT_FILENO, &stat) != 0 ) {
    int fd = open(DEV_KMSG, O_WRONLY);
    if( fd != STDERR_FILENO ) {
      dup2(fd, STDERR_FILENO);
      /* Do not check the return code from dup2, as cannot log errors anyway.
       * Maybe daemonise() will have more luck, let it check for problems. */
    }
  }

  ci_app_getopt("", &argc, argv, cfg_opts, N_CFG_OPTS);
  memset(s, 0, sizeof(*s));

  if( ci_ver ) {
    ci_log("Version: %s\n%s", onload_version, onload_copyright);
    return 0;
  }

  if( cfg_affinity != -1 )
    sched_setaffinity(0, sizeof(cfg_affinity), (cpu_set_t*)&cfg_affinity);

  if( cfg_daemonise )
    daemonise();

  /* If a namespace was specified on the command line, switch into it before
   * bringing up any of our state. */
  if( cfg_ns_file != NULL ) {
#ifndef CP_SYSUNIT
    rc = ci_check_net_namespace("/proc/1/ns/net");
    if( rc == 1 ) {
      /* We are in pid 1 network namespace (allegedly the main one),
       * check if we are going to serve a different network namespace. */
      /* TODO: Detect being run from within pid namespace */
      rc = ci_check_net_namespace(cfg_ns_file);
      if( rc == 0 ) {
        /* We are going to switch to different network namespace soon.
         * Before it happens let's obtain handle to pid 1 namespace cplane.
         * We are going to use it to look up state of lower interfaces. */
         init_main_cplane(s);
      }
    }

    if(ci_switch_net_namespace(cfg_ns_file) < 0) {
      init_failed("Couldn't switch to %s: %s",
                  cfg_ns_file, strerror(errno));
    }
#else
    (void) rc;

    /* For CP_SYSUNIT we invoke bring_up_kernel_state() to set shim into server
     * mode.  We need to do this before initializing main cplane. */
    bring_up_kernel_state();
    /* Using initial value of CP_SHIM_FILE */
    init_main_cplane(s);
    /* 'Change' namespace by replacing value of CP_SHIM_FILE with cfg_ns_file */
    ci_log("Switching from %s", getenv("CP_SHIM_FILE"));
    setenv("CP_SHIM_FILE", cfg_ns_file, 1);
    ci_log("Switched to %s", cfg_ns_file);
#endif
  }

  if( ci_cfg_no_ipv6 )
    s->flags |= CP_SESSION_NO_IPV6;
  if( ci_cfg_ipv6_no_source )
    s->flags |= CP_SESSION_IPV6_NO_SOURCE;
  if( ci_cfg_verify_routes )
    s->flags |= CP_SESSION_VERIFY_ROUTES;
  if( ci_cfg_pref_src_as_local )
    s->flags |= CP_SESSION_LADDR_USE_PREF_SRC;
  if( cfg_track_xdp )
    s->flags |= CP_SESSION_TRACK_XDP;

  if( ci_cfg_bootstrap )
    bring_up_kernel_state();

  if( cfg_hwport_max == 0 || cfg_llap_max == 0 || cfg_ipif_max == 0 )
    init_failed("Table sizes should be non-zero");
  if( ! CICP_ROWID_IS_VALID(cfg_hwport_max) )
    init_failed("Too large hwport-max parameter");
  if( ! CICP_ROWID_IS_VALID(cfg_llap_max) )
    init_failed("Too large llap-max parameter");
  if( ! CICP_ROWID_IS_VALID(cfg_ipif_max) )
    init_failed("Too large ipif-max parameter");
  dim.hwport_max = cfg_hwport_max;
  dim.llap_max = cfg_llap_max;
  dim.ipif_max = cfg_ipif_max;
  dim.ip6if_max = ( s->flags & CP_SESSION_NO_IPV6 ) ? 0 : cfg_ipif_max;
  if( cfg_ns_file == NULL ) {
    dim.svc_arrays_max = cfg_svc_arrays_max;
    /* Round up to next power of 2 */
    dim.svc_ep_max = ci_pow2(ci_log2_ge(cfg_svc_ep_max, 1));
  }
  else {
    dim.svc_arrays_max = 0;
    dim.svc_ep_max = 0;
  }

  dim.fwd_ln2 = ci_log2_ge(cfg_fwd_max, 1);
  if( dim.fwd_ln2 >= sizeof(cicp_mac_rowid_t) * 8 ||
      (1 << dim.fwd_ln2) > CP_FWD_FLAG_DUMP )
    init_failed("Too large fwd-max parameter");
  dim.fwd_mask = (1 << dim.fwd_ln2) - 1;

  /* SIGRTMIN in libc results in a function call (i.e. its result is
   * unpredictable for the kernel), so we must pass the RT
   * signal in use to the kernel. */
  dim.oof_req_sig = SIGRTMIN + 1;
  dim.llap_update_sig = dim.oof_req_sig + 1;
  dim.os_sync_sig = dim.llap_update_sig + 1;

  dim.server_pid = getpid();

  s->llap_type_os_mask = LLAP_TYPE_OS_MASK_DEFAULT;

  init_files(s);
  s->frc_fwd_cache_ttl = cfg_fwd_cache_ttl * s->khz * 1000ULL;
  s->team_dump = NULL;
  s->bond_max = cfg_bond_max;
  s->mac_max_ln2 = ci_log2_ge(cfg_mac_max, 1);
  if( s->mac_max_ln2 > sizeof(cicp_mac_rowid_t) * 8 - 1 )
    init_failed("Too large mac-max parameter");
  s->mac_mask = (1 << s->mac_max_ln2) - 1;

  init_memory(&dim, s);

#ifndef CP_ANYUNIT
  /* We need to create the agent socket before dropping privileges so that we
   * don't run into permissions problems when binding it to a location in the
   * filesystem.  We also need to do it _after_ calling init_memory(), to avoid
   * racing against other cplane server instances. */
  if( cfg_ns_file == NULL )
    cp_agent_sock_init(s);

#ifndef NO_CAPS
  /* Drop all the privileges except CAP_NET_ADMIN in this namespace. */
  drop_privileges(s, cfg_ns_file == NULL);
#endif
#endif

  /* Get current sigmask before we block signals.  This sigmask will be
   * used for epoll_pwait() to guarantee that signals handling and epoll fd
   * handling to not need any interlocking. */
  sigprocmask(SIG_SETMASK, NULL, &sigmask);
  init_signals(s);

  cp_mibdump_sock_init(s);

  init_epoll(s);

  ci_dllist_init(&s->fwd_req_ul);

  /* We have some MIBs ready - tell others about us! */
  ci_log("Onload Control Plane server %s started: id %u, pid %d", onload_version, s->cplane_id,
         dim.server_pid);

  do {
    int i;
#define EVENTS_NUM 5
    struct epoll_event events[EVENTS_NUM];
    cp_version_t mib_ver = *s->mib[0].version;

    while( (rc = epoll_pwait(s->epoll_fd, events, EVENTS_NUM, 0, &sigmask)) < 0 )
      /* handle all signals */;

    if( rc == 0 ) {
      /* We are going to sleep.  Make idle_version even and notify user */
      ci_assert((*s->mib[0].idle_version) & 1);
      (*s->mib[0].idle_version)++;
      if( s->flags & CP_SESSION_USER_OS_SYNC && s->state == CP_DUMP_IDLE &&
          cp_ready_usable(s) ) {
        s->flags &=~ CP_SESSION_USER_OS_SYNC;
      }

      /* Sleep until we have some data or user asks for sync */
      while( (rc = epoll_pwait(s->epoll_fd, events, EVENTS_NUM, -1, &sigmask)) <= 0 &&
             !(s->flags & CP_SESSION_USER_OS_SYNC) ) {
        /* handle signals */
      }

      /* ensure that idle version is odd while we are not sleeping */
      (*s->mib[0].idle_version) |= 1;
      ci_wmb();
    }

    for( i = 0; i < rc; i++ ) {
      struct cp_epoll_state* state = events[i].data.ptr;
      state->callback(s, state);
    }

    /* If we are dumping something then we'll call cp_fwd_cache_refresh() at the
     * end.  Otherwise we should call it now. */
    if( s->flags & CP_SESSION_FLAG_FWD_REFRESH_NEEDED &&
        s->state == CP_DUMP_IDLE ) {
      cp_fwd_cache_refresh(s);
    }
    if( s->flags & CP_SESSION_LADDR_REFRESH_NEEDED )
      cp_laddr_refresh(s);
    if( s->main_cp_handle == NULL && mib_ver != *s->mib[0].version ) {
        /* We are the main cp_server instace and have a duty to notify clients of
         * our llap changes.
         * TODO: Not every update is worth sending a notification
         */
      oo_op_notify_all(s);
    }
  } while(1);

  return 0;
}
