/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: ctk
**     Started: 2004/04/06
** Description: Initialisation of network interface.
** </L5_PRIVATE>
\**************************************************************************/

#define _GNU_SOURCE

#include "ip_internal.h"
#include "uk_intf_ver.h"
#include "tcp_rx.h"
#include <ci/internal/efabcfg.h>
#include <ci/efhw/device.h>
#include <ci/internal/banner.h>
#include <onload/version.h>
#include <etherfabric/internal/internal.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/tools/sysdep.h>

#ifndef __KERNEL__
#include <sys/un.h>
#include <etherfabric/shrub_adapter.h>
#include <etherfabric/shrub_shared.h>
#include <cplane/cplane.h>
#include <cplane/create.h>
#include <net/if.h>
#include <ci/internal/efabcfg.h>
#include <ci/internal/syscall.h>
#include <linux/memfd.h>
#endif


#ifdef __KERNEL__
const char* oo_uk_intf_ver = OO_UK_INTF_VER;
#endif


/*****************************************************************************
 *                                                                           *
 *          Logging                                                          *
 *          =======                                                          *
 *                                                                           *
 *****************************************************************************/




#ifdef __KERNEL__

#define assert_zero(x)  ci_assert_equal((x), 0)

void ci_netif_state_init(ci_netif* ni, int cpu_khz, const char* name)
{
  ci_netif_state_nic_t* nn;
  ci_netif_state* nis = ni->state;
  struct oo_p_dllink_state list;
  int nic_i;
  int i;

  nis->opts = ni->opts;

  /* TX DMA overflow queue. */
  OO_STACK_FOR_EACH_INTF_I(ni, nic_i) {
    nn = &nis->nic[nic_i];
    oo_pktq_init(&nn->dmaq);
    assert_zero(nn->tx_bytes_added);
    assert_zero(nn->tx_bytes_removed);
    assert_zero(nn->tx_dmaq_insert_seq);
    assert_zero(nn->tx_dmaq_insert_seq_last_poll);
    assert_zero(nn->tx_dmaq_done_seq);
    nn->rx_frags = OO_PP_NULL;
  }

  /* List of free packet buffers. */
  assert_zero(ni->packets->n_free);
  assert_zero(nis->n_rx_pkts);
  assert_zero(nis->rxq_low);
  assert_zero(nis->mem_pressure);
  nis->mem_pressure_pkt_pool = OO_PP_NULL;
  assert_zero(nis->mem_pressure_pkt_pool_n);
  nis->looppkts = OO_PP_NULL;
  nis->n_looppkts = 0;

  /* Pool of packet buffers for transmit. */
  assert_zero(nis->n_async_pkts);
  nis->nonb_pkt_pool = CI_ILL_END;

  /* Deferred packets */
  list = oo_p_dllink_ptr(ni, &nis->deferred_list);
  oo_p_dllink_init(ni, list);
  list = oo_p_dllink_ptr(ni, &nis->deferred_list_free);
  oo_p_dllink_init(ni, list);
  for( i = 0; i < NI_OPTS(ni).defer_arp_pkts; i++ ) {
    struct oo_p_dllink_state link =
                oo_p_dllink_ptr(ni, &ni->deferred_pkts[i].link);
    oo_p_dllink_init(ni, link);
    oo_p_dllink_add(ni, list, link);
  }

  ci_netif_filter_init(ni, ci_log2_le(ci_netif_filter_table_size(ni)));
#if CI_CFG_IPV6
  ci_ip6_netif_filter_init(ni->ip6_filter_table,
                           ci_log2_le(NI_OPTS(ni).max_ep_bufs) + 1);
#endif

  oo_p_dllink_init(ni, oo_p_dllink_ptr(ni,
                   &nis->timeout_q[OO_TIMEOUT_Q_TIMEWAIT]));
  oo_p_dllink_init(ni, oo_p_dllink_ptr(ni,
                   &nis->timeout_q[OO_TIMEOUT_Q_FINWAIT]));
  ci_ip_timer_init(ni, &nis->timeout_tid,
                   oo_ptr_to_statep(ni, &nis->timeout_tid),
                   "ttid");

  nis->timeout_tid.fn = CI_IP_TIMER_NETIF_TIMEOUT;

#if CI_CFG_SUPPORT_STATS_COLLECTION
  ci_ip_timer_init(ni, &nis->stats_tid,
                   oo_ptr_to_statep(ni, &nis->stats_tid),
                   "stat");
  nis->stats_tid.fn = CI_IP_TIMER_NETIF_STATS;

  ci_ip_stats_clear(&nis->stats_snapshot);
  ci_ip_stats_clear(&nis->stats_cumulative);
#endif

  oo_p_dllink_init(ni, oo_p_dllink_ptr(ni, &nis->reap_list));

  nis->free_eps_head = OO_SP_NULL;
  nis->free_eps_num = 0;
  nis->deferred_free_eps_head = CI_ILL_END;
  assert_zero(nis->n_ep_bufs);
  nis->max_ep_bufs = NI_OPTS(ni).max_ep_bufs;

  assert_zero(ni->packets->sets_n);
  ni->packets->sets_max = ni->pkt_sets_max;

  /* Fragmented packet re-assembly list */
  nis->rx_defrag_head = OO_PP_NULL;
  nis->rx_defrag_tail = OO_PP_NULL;

  strncpy(nis->name, name, CI_CFG_STACK_NAME_LEN);
  nis->name[CI_CFG_STACK_NAME_LEN] = '\0';

  assert_zero(nis->in_poll);
  oo_p_dllink_init(ni, oo_p_dllink_ptr(ni, &nis->post_poll_list));

  nis->sock_spin_cycles =
            __oo_usec_to_cycles64(cpu_khz, NI_OPTS(ni).spin_usec);
  nis->buzz_cycles =
            __oo_usec_to_cycles64(cpu_khz, NI_OPTS(ni).buzz_usec);
  nis->timer_prime_cycles =
            __oo_usec_to_cycles64(cpu_khz, NI_OPTS(ni).timer_prime_usec);
#if CI_CFG_INJECT_PACKETS
  nis->kernel_packets_cycles =
            __oo_usec_to_cycles64(cpu_khz,
                                  NI_OPTS(ni).kernel_packets_timer_usec);
#endif

  ci_ip_timer_state_init(ni, cpu_khz);
  nis->last_spin_poll_frc = IPTIMER_STATE(ni)->frc;
  nis->last_sleep_frc = IPTIMER_STATE(ni)->frc;
  
  oo_timesync_update(efab_tcp_driver.timesync);

  assert_zero(nis->defer_work_count);

#if CI_CFG_TCPDUMP
  nis->dump_read_i = 0;
  nis->dump_write_i = 0;
  memset(nis->dump_intf, 0, sizeof(nis->dump_intf));
#endif

  nis->uuid = ci_current_from_kuid_munged(ni->kuid);
#ifdef EFRM_DO_NAMESPACES
  nis->pid = task_pid_nr_ns(current, ci_netif_get_pidns(ni));
#else
  nis->pid = task_pid_vnr(current);
#endif

  nis->creation_time_sec = ktime_get_real_seconds();
#if CI_CFG_FD_CACHING
  nis->passive_cache_avail_stack = nis->opts.sock_cache_max;
#endif

  /* This gets set appropriately in tcp_helper_init_max_mss() */
  nis->max_mss = 0;

  /* hash_salt is used for TCP syncookies and IPv6 flowlabel generation */
  get_random_bytes(&nis->hash_salt, sizeof(nis->hash_salt));

#if CI_CFG_EPOLL3
  nis->ready_lists_in_use = 0;
  for( i = 0; i < CI_CFG_N_READY_LISTS; i++ ) {
    oo_p_dllink_init(ni, oo_p_dllink_ptr(ni, &nis->ready_lists[i]));
    oo_p_dllink_init(ni, oo_p_dllink_ptr(ni, &nis->unready_lists[i]));
    nis->ready_list_flags[i] = 0;
  }
#endif

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  for( i = 0;
       i < nis->active_wild_table_entries_n * nis->active_wild_pools_n;
       ++i ) {
    oo_p_dllink_init(ni, oo_p_dllink_ptr(ni, &ni->active_wild_table[i]));
  }
  nis->active_wild_n = 0;
#endif

  for( i = 0; i < nis->seq_table_entries_n; ++i )
    assert_zero(ni->seq_table[i].route_count);

  nis->packet_alloc_numa_nodes = 0;
  nis->sock_alloc_numa_nodes = 0;
  nis->interrupt_numa_nodes = 0;
  nis->creation_numa_node = numa_node_id();
  nis->load_numa_node = efab_tcp_driver.load_numa_node;

#if CI_CFG_FD_CACHING
  list = oo_p_dllink_ptr(ni, &nis->active_cache.cache);
  oo_p_dllink_init(ni, list);
  list = oo_p_dllink_ptr(ni, &nis->active_cache.pending);
  oo_p_dllink_init(ni, list);
  list = oo_p_dllink_ptr(ni, &nis->active_cache.fd_states);
  oo_p_dllink_init(ni, list);

  nis->active_cache.avail_stack = oo_ptr_to_statep(ni,
                                              &nis->active_cache_avail_stack);
  nis->active_cache_avail_stack = nis->opts.sock_cache_max;

  list = oo_p_dllink_ptr(ni, &nis->passive_scalable_cache.cache);
  oo_p_dllink_init(ni, list);
  list = oo_p_dllink_ptr(ni, &nis->passive_scalable_cache.pending);
  oo_p_dllink_init(ni, list);
  list = oo_p_dllink_ptr(ni, &nis->passive_scalable_cache.fd_states);
  oo_p_dllink_init(ni, list);

  nis->passive_scalable_cache.avail_stack = oo_ptr_to_statep
    (ni, &ni->state->passive_cache_avail_stack);
#endif

#if CI_CFG_INJECT_PACKETS
  nis->kernel_packets_head = nis->kernel_packets_tail = OO_PP_NULL;
  assert_zero(nis->kernel_packets_last_forwarded);
  assert_zero(nis->kernel_packets_pending);
#endif

#if OO_DO_STACK_POLL
  ci_tcp_rst_cooldown_init(ni);
#endif
}

#endif


static int citp_ipstack_params_inited = 0;
static ci_uint32 citp_tcp_sndbuf_min = CI_CFG_TCP_SNDBUF_MIN;
static ci_uint32 citp_tcp_sndbuf_def = CI_CFG_TCP_SNDBUF_DEFAULT;
static ci_uint32 citp_tcp_sndbuf_max = CI_CFG_TCP_SNDBUF_MAX;
static ci_uint32 citp_tcp_rcvbuf_min = CI_CFG_TCP_RCVBUF_MIN;
static ci_uint32 citp_tcp_rcvbuf_def = CI_CFG_TCP_RCVBUF_DEFAULT;
static ci_uint32 citp_tcp_rcvbuf_max = CI_CFG_TCP_RCVBUF_MAX;
static ci_uint32 citp_udp_sndbuf_max = CI_CFG_UDP_SNDBUF_MAX;
static ci_uint32 citp_udp_sndbuf_def = CI_CFG_UDP_SNDBUF_DEFAULT;
static ci_uint32 citp_udp_rcvbuf_max = CI_CFG_UDP_RCVBUF_MAX;
static ci_uint32 citp_udp_rcvbuf_def = CI_CFG_UDP_RCVBUF_DEFAULT;
static ci_uint32 citp_tcp_backlog_max = CI_TCP_LISTENQ_MAX;
static ci_uint32 citp_somaxconn = SOMAXCONN;
static ci_uint32 citp_tcp_adv_win_scale_max = CI_TCP_WSCL_MAX;
static ci_uint32 citp_fin_timeout = CI_CFG_TCP_FIN_TIMEOUT;
static ci_uint32 citp_retransmit_threshold = CI_TCP_RETRANSMIT_THRESHOLD;
static ci_uint32 citp_retransmit_threshold_orphan =
                   CI_TCP_RETRANSMIT_THRESHOLD_ORPHAN;
static ci_uint32 citp_retransmit_threshold_syn =
                   CI_TCP_RETRANSMIT_THRESHOLD_SYN;
static ci_uint32 citp_retransmit_threshold_synack =
                   CI_TCP_RETRANSMIT_THRESHOLD_SYN;
static ci_uint32 citp_keepalive_probes = CI_TCP_KEEPALIVE_PROBES;
static ci_uint32 citp_keepalive_time = CI_TCP_TCONST_KEEPALIVE_TIME;
static ci_uint32 citp_keepalive_intvl = CI_TCP_TCONST_KEEPALIVE_INTVL;
static ci_uint32 citp_syn_opts = CI_TCPT_SYN_FLAGS;
static ci_uint32 citp_tcp_dsack = CI_CFG_TCP_DSACK;
static ci_uint32 citp_tcp_time_wait_assassinate = CI_CFG_TIME_WAIT_ASSASSINATE;
static ci_uint32 citp_tcp_early_retransmit = 3;  /* default as of 3.10 */
static ci_uint32 citp_tcp_invalid_ratelimit =
                        CI_CFG_TCP_OUT_OF_WINDOW_ACK_RATELIMIT;

#if CI_CFG_IPV6
static ci_uint32 citp_auto_flowlabels = CI_AUTO_FLOWLABELS_DEFAULT;
#endif

#ifndef __KERNEL__
/* Interface for sysctl. */
ci_inline int ci_sysctl_get_values(char *path, ci_uint32 *ret, int n)
{
  char name[CI_CFG_PROC_PATH_LEN_MAX + strlen(CI_CFG_PROC_PATH)];
  char buf[CI_CFG_PROC_LINE_LEN_MAX];
  int buflen;
  char *p = buf;
  int fd;
  int i = 0;

  strcpy(name, CI_CFG_PROC_PATH);
  strncpy(name + strlen(CI_CFG_PROC_PATH), path, CI_CFG_PROC_PATH_LEN_MAX);
  fd = ci_sys_open(name, O_RDONLY);
  if (fd < 0) {
    /* There are a lot of reasons to fail:
     * - too old kernel does not know this parameter;
     * - we are in chroot, and/or /proc is not mounted;
     * - we are in non-default net namespace: depending on the kernel
     *   version, we'll get a different subset of parameters available.
     */
    return fd;
  }
  buflen = ci_sys_read(fd, buf, sizeof(buf));
  ci_sys_close(fd);
  buf[buflen - 1] = '\0';
  for( i = 0; i < n && sscanf(p, "%u", &ret[i]) > 0; ++i ) {
    while( buf + buflen > p && p[0] != '\t' )
      p++;
    p++;
  }
  if( i < n ) {
    ci_log("%s: failed to parse %s: %s", __FUNCTION__, name, buf);
    return -1;
  }
  return 0;
}

/* Read /proc/sys/net parameters and store them is global variables to
 * re-use after possible chroot(). It really helps to ftp-servers in
 * passive mode, when they call listen(), accept(), chroot() and listen().
 */

int
ci_setup_ipstack_params(void)
{
  ci_uint32 opt[3];

  /* citp_ipstack_params_inited == 1 if:
   * - we have 2 netifs in one application;
   * - chroot() was called after another intercepted call.
   */
  if (citp_ipstack_params_inited)
    return 0;

  {
    int fd = ci_sys_open(CI_CFG_PROC_PATH"net/ipv4", O_RDONLY | O_DIRECTORY);
    if( fd < 0 ) {
      ci_log("ERROR: failed to open "CI_CFG_PROC_PATH"net/ipv4");
      return -1;
    }
    ci_sys_close(fd);
  }
  /* We will re-read following values in kernel mode for every socket,
   * but we need them before the first socket is initialized. */
  if( ci_sysctl_get_values("net/ipv4/tcp_wmem", opt, 3) == 0 ) {
    /* CI_CFG_TCP_SNDBUF_MIN is used */
    citp_tcp_sndbuf_def = opt[1];
    citp_tcp_sndbuf_max = opt[2];
  }
  if( ci_sysctl_get_values("net/ipv4/tcp_rmem", opt, 3) == 0 ) {
    /* CI_CFG_TCP_RCVBUF_MIN is used */
    citp_tcp_rcvbuf_def = opt[1];
    citp_tcp_rcvbuf_max = opt[2];
  }
  if( ci_sysctl_get_values("net/core/wmem_max", opt, 1) == 0 ) {
    citp_udp_sndbuf_max = opt[0];
    if( opt[0] < citp_tcp_sndbuf_max )
      citp_tcp_sndbuf_max = opt[0];
  }
  if( ci_sysctl_get_values("net/core/wmem_default", opt, 1) == 0 )
    citp_udp_sndbuf_def = opt[0];
  if( ci_sysctl_get_values("net/core/rmem_max", opt, 1) == 0 ) {
    citp_udp_rcvbuf_max = opt[0];
    if( opt[0] < citp_tcp_rcvbuf_max )
      citp_tcp_rcvbuf_max = opt[0];
  }
  if( ci_sysctl_get_values("net/core/rmem_default", opt, 1) == 0 )
    citp_udp_rcvbuf_def = opt[0];

  if( ci_sysctl_get_values("net/core/somaxconn", opt, 1) == 0 )
    citp_somaxconn = opt[0];

  if (ci_sysctl_get_values("net/ipv4/tcp_max_syn_backlog", opt, 1) == 0)
    citp_tcp_backlog_max = opt[0];

  /* We should not use non-zero winscale if tcp_window_scaling == 0 */
  if (ci_sysctl_get_values("net/ipv4/tcp_window_scaling", opt, 1) == 0 &&
      opt[0] == 0)
    citp_tcp_adv_win_scale_max = 0;

  /* Get fin_timeout value from Linux if it is possible */
  if (ci_sysctl_get_values("net/ipv4/tcp_fin_timeout", opt, 1) == 0)
    citp_fin_timeout = opt[0];

  /* Number of retransmits */
  if (ci_sysctl_get_values("net/ipv4/tcp_retries2", opt, 1) == 0)
    citp_retransmit_threshold = opt[0];
  /* tcp_orphan_retries is usually 0, but Linux uses value 8 internally in
   * such a case.  See linux/net/ipv4/tcp_timer.c: tcp_orphan_retries()
   * for details. */
  if (ci_sysctl_get_values("net/ipv4/tcp_orphan_retries", opt, 1) == 0 &&
      opt[0] > 0 ) {
    citp_retransmit_threshold_orphan = opt[0];
  }
  if (ci_sysctl_get_values("net/ipv4/tcp_syn_retries", opt, 1) == 0)
    citp_retransmit_threshold_syn = opt[0];
  if (ci_sysctl_get_values("net/ipv4/tcp_synack_retries", opt, 1) == 0)
    citp_retransmit_threshold_synack = opt[0];

  /* Keepalive parameters */
  if (ci_sysctl_get_values("net/ipv4/tcp_keepalive_probes", opt, 1) == 0)
    citp_keepalive_probes = opt[0];
  /* These values are stored in secs, we scale to ms here */
  if (ci_sysctl_get_values("net/ipv4/tcp_keepalive_time", opt, 1) == 0)
    citp_keepalive_time = opt[0] * 1000;
  if (ci_sysctl_get_values("net/ipv4/tcp_keepalive_intvl", opt, 1) == 0)
    citp_keepalive_intvl = opt[0] * 1000;

  /* SYN options */
  if (ci_sysctl_get_values("net/ipv4/tcp_sack", opt, 1) == 0) {
    if( opt[0] )
      citp_syn_opts |= CI_TCPT_FLAG_SACK;
    else
      citp_syn_opts &=~ CI_TCPT_FLAG_SACK;
  }
  if (ci_sysctl_get_values("net/ipv4/tcp_timestamps", opt, 1) == 0) {
    if( opt[0] )
      citp_syn_opts |= CI_TCPT_FLAG_TSO;
    else
      citp_syn_opts &=~ CI_TCPT_FLAG_TSO;
  }
  if (ci_sysctl_get_values("net/ipv4/tcp_window_scaling", opt, 1) == 0) {
    if( opt[0] )
      citp_syn_opts |= CI_TCPT_FLAG_WSCL;
    else
      citp_syn_opts &=~ CI_TCPT_FLAG_WSCL;
  }

  if (ci_sysctl_get_values("net/ipv4/tcp_dsack", opt, 1) == 0)
    citp_tcp_dsack = opt[0];

  if (ci_sysctl_get_values("net/ipv4/tcp_rfc1337", opt, 1) == 0)
    citp_tcp_time_wait_assassinate = ! opt[0];

  if (ci_sysctl_get_values("net/ipv4/tcp_early_retrans", opt, 1) == 0)
    citp_tcp_early_retransmit = opt[0];

  if (ci_sysctl_get_values("net/ipv4/tcp_invalid_ratelimit", opt, 1) == 0)
    citp_tcp_invalid_ratelimit = opt[0];

#if CI_CFG_IPV6
  if( ci_sysctl_get_values("net/ipv6/auto_flowlabels", opt, 1) == 0 )
    citp_auto_flowlabels = opt[0];
#endif

  citp_ipstack_params_inited = 1;
  return 0;
}

#else

int
ci_setup_ipstack_params(void)
{
  citp_ipstack_params_inited = 0;
  return 0;
}

#endif /* __KERNEL__ */

void ci_netif_config_opts_defaults(ci_netif_config_opts* opts)
{
# undef  CI_CFG_OPTFILE_VERSION
# undef  CI_CFG_OPTGROUP
# undef  CI_CFG_OPT
# undef  CI_CFG_STR_OPT
# define CI_CFG_OPT(env, name, type, doc, type_modifider, group,     \
                    default, minimum, maximum, presentation)	      \
  opts->name = default;

# define CI_CFG_STR_OPT(env, name, type, doc, type_modifider, group,   \
                        default, minimum, maximum, presentation)       \
  strncpy(opts->name, default, sizeof(opts->name));                    \
  opts->name[sizeof(opts->name) - 1] = 0;

# include <ci/internal/opts_netif_def.h>

  /* now modify defaults with information from the operating system */
  ci_setup_ipstack_params();
  if (citp_ipstack_params_inited) {
    opts->tcp_sndbuf_min = citp_tcp_sndbuf_min;
    opts->tcp_sndbuf_def = citp_tcp_sndbuf_def;
    opts->tcp_sndbuf_max = citp_tcp_sndbuf_max;
    opts->tcp_rcvbuf_min = citp_tcp_rcvbuf_min;
    opts->tcp_rcvbuf_def = citp_tcp_rcvbuf_def;
    opts->tcp_rcvbuf_max = citp_tcp_rcvbuf_max;

    opts->udp_sndbuf_max = citp_udp_sndbuf_max;
    opts->udp_sndbuf_def = citp_udp_sndbuf_def;
    opts->udp_rcvbuf_max = citp_udp_rcvbuf_max;
    opts->udp_rcvbuf_def = citp_udp_rcvbuf_def;

    opts->tcp_backlog_max = citp_tcp_backlog_max;
    opts->tcp_synrecv_max = citp_tcp_backlog_max *
                            CI_CFG_ASSUME_LISTEN_SOCKS;
    opts->tcp_adv_win_scale_max = citp_tcp_adv_win_scale_max;
    opts->fin_timeout = citp_fin_timeout;

    opts->retransmit_threshold = citp_retransmit_threshold;
    opts->retransmit_threshold_orphan = citp_retransmit_threshold_orphan;
    opts->retransmit_threshold_syn = citp_retransmit_threshold_syn;
    opts->retransmit_threshold_synack = citp_retransmit_threshold_synack;

    opts->keepalive_probes = citp_keepalive_probes;
    opts->keepalive_time = citp_keepalive_time;
    opts->keepalive_intvl = citp_keepalive_intvl;

    opts->syn_opts = citp_syn_opts;
    opts->use_dsack = citp_tcp_dsack;
    opts->time_wait_assassinate = citp_tcp_time_wait_assassinate;
    /* Early retransmit itself has gone from modern kernels, so look in an
     * old kernel's ip-sysctl.txt for the meaning of these values. */
    opts->tcp_early_retransmit = citp_tcp_early_retransmit > 0 &&
                                 citp_tcp_early_retransmit < 4;
    opts->tail_drop_probe = citp_tcp_early_retransmit >= 3;
    opts->oow_ack_ratelimit = citp_tcp_invalid_ratelimit;

    opts->acceptq_max_backlog = citp_somaxconn;
#if CI_CFG_IPV6
    opts->auto_flowlabels = citp_auto_flowlabels;
#endif
    opts->inited = CI_TRUE;
  }
}

static void round_opts(const char* opt_name, ci_uint32* opt, int multiplier)
{
  if( *opt % multiplier != 0 ) {
    unsigned new_max = *opt;
    new_max = CI_ROUND_UP(new_max, multiplier);
    ci_log("config: %s is rounded up from %u to %u", opt_name, *opt, new_max);
    *opt = new_max;
  }
}

void ci_netif_config_opts_rangecheck(ci_netif_config_opts* opts)
{
  ci_uint64 MIN;
  ci_uint64 MAX;
  ci_int64  SMIN;
  ci_int64  SMAX;
  int _optbits;
  int _bitwidth;

  /* stop compiler complaining if these values are not used */
  (void)MIN; (void)MAX; (void)SMIN; (void)SMAX;
  (void)_optbits; (void)_bitwidth; 
  
#undef  CI_CFG_OPTFILE_VERSION
#undef  CI_CFG_OPTGROUP
#undef  CI_CFG_OPT
#undef  CI_CFG_STR_OPT

#define _CI_CFG_BITVAL   _optbits
#define _CI_CFG_BITVAL1  1
#define _CI_CFG_BITVAL2  2
#define _CI_CFG_BITVAL3  3
#define _CI_CFG_BITVAL4  4
#define _CI_CFG_BITVAL8  8
#define _CI_CFG_BITVAL12 12
#define _CI_CFG_BITVAL16 16
#define _CI_CFG_BITVALA8 _CI_CFG_BITVAL

#undef MIN
#undef MAX
#undef SMIN
#undef SMAX
    
#define CI_CFG_REDRESS(opt, val) opt = val;
#define CI_CFG_MSG "ERROR"

#define CI_CFG_STR_OPT(...)

#define CI_CFG_OPT(env, name, type, doc, bits, group, default, minimum, maximum, pres) \
{ type _val = opts->name;					          \
  type _max;								  \
  type _min;								  \
  _optbits=sizeof(type)*8;                                                \
  _bitwidth=_CI_CFG_BITVAL##bits;					  \
  MIN = 0;                                                                \
  MAX = ((1ull<<(_bitwidth-1))<<1) - 1ull;       			  \
  SMAX = MAX >> 1; SMIN = -SMAX-1;                                        \
  _max = (type)(maximum); /* try to stop the compiler warning */          \
  _min = (type)(minimum); /* about silly comparisons          */          \
  if (_val > _max) {                                                      \
    ci_log("config: "CI_CFG_MSG" - option " #name                         \
           " (%"CI_PRIu64") larger than maximum (%"CI_PRIu64")",          \
           (ci_uint64)_val, (ci_uint64) _max);                            \
    CI_CFG_REDRESS(opts->name, _max);                                     \
  }                                                                       \
  if (_val < _min) {                                                      \
    ci_log("config: "CI_CFG_MSG" - option " #name                         \
           " (%"CI_PRIu64") smaller than minimum (%"CI_PRIu64")",         \
           (ci_uint64)_val, (ci_uint64) _min);                            \
    CI_CFG_REDRESS(opts->name, _min);                                     \
  }                                                                       \
}                                               

# include <ci/internal/opts_netif_def.h>

  /* EF_MAX_ENDPOINTS should must be divisible by 2048 */
  round_opts("EF_MAX_ENDPOINTS", &opts->max_ep_bufs, EP_BUF_PER_CHUNK);
}



#ifndef __KERNEL__

struct string_to_bitmask {
  int               stb_index;
  const char*const  stb_str;
};


/* str is a ',' separated list of options.  Each option in str is
 * compared against stb_str in each entry in opts.  stb_index'st bit
 * in bitmask_out is set if stb_default in opts is set and no option
 * in str turns it off by using '-' or some option in str enables it.
 */
static void convert_string_to_bitmask(const char* str,
                                      const struct string_to_bitmask* opts,
                                      int opts_len, ci_uint32* bitmask_out)
{
  int len, i, opt_found, negate;

  if( ! str )
    return;

  /* Parse the input string to add/remove bits */
  while( 1 ) {
    while( *str == ',' )
      ++str;
    len = strchrnul(str, ',') - str;
    if( len == 0 )
      break;

    /* Check if we are removing an option */
    if( *str == '-' ) {
      negate = 1;
      ++str;
      --len;
    }
    else {
      negate = 0;
    }

    /* Iterate opts looking for the parsed str */
    opt_found = 0;
    for( i = 0; i < opts_len; ++i )
      if( ! strncmp(str, opts[i].stb_str, len) ) {
        if( negate )
          *bitmask_out &= ~(1 << opts[i].stb_index);
        else
          *bitmask_out |= 1 << opts[i].stb_index;
        ++opt_found;
        break;
      }
    if( ! opt_found ) {
      char buf[128];
      strncpy(buf, str, len);
      buf[len] = '\0';
      ci_log("Invalid option detected: %s", buf);
    }
    str += len;
  }
}


static void ci_netif_config_opts_getenv_ef_log(ci_netif_config_opts* opts)
{
  struct string_to_bitmask options[EF_LOG_MAX] = {
    {EF_LOG_BANNER, "banner"},
    {EF_LOG_RESOURCE_WARNINGS, "resource_warnings"},
    {EF_LOG_CONN_DROP, "conn_drop"},
    {EF_LOG_CONFIG_WARNINGS, "config_warnings"},
    {EF_LOG_MORE_CONFIG_WARNINGS, "more_config_warnings"},
    {EF_LOG_USAGE_WARNINGS, "usage_warnings"},
  };

  convert_string_to_bitmask(getenv("EF_LOG"), options, EF_LOG_MAX,
                            &opts->log_category);
}


static void
ci_netif_config_opts_getenv_ef_scalable_filters(ci_netif_config_opts* opts);

static int
handle_str_opt(ci_netif_config_opts* opts,
               const char* optname, char* optval_buf, size_t optval_buflen);

static int
parse_enum(ci_netif_config_opts* opts,
           const char* name, const char* const* options,
           const char* default_val);


void ci_netif_config_opts_getenv(ci_netif_config_opts* opts)
{
  const char* s;

  /* Work out what logging is enabled first, so we can log config errors */
  ci_netif_config_opts_getenv_ef_log(opts);

  /* These first options are sensitive to the order in which they are
   * initialised, because the value of one effects the default for
   * others...
   */

  if( (s = getenv("EF_POLL_USEC")) ) {
    opts->spin_usec = atoi(s);
    if( opts->spin_usec != 0 ) {
      /* Don't buzz for too long by default! */
      opts->buzz_usec = CI_MIN(opts->spin_usec, 100);
      /* Disable EF_INT_DRIVEN by default when spinning. */
      opts->int_driven = 0;
      /* These are only here to expose defaults through stackdump.  FIXME:
       * Would be much better to initialise these from the CITP options to
       * avoid potential inconsistency.
       */
    }
  }
  if( (s = getenv("EF_SPIN_USEC")) ) {
    opts->spin_usec = atoi(s);
    /* Disable EF_INT_DRIVEN by default when spinning. */
    if( opts->spin_usec != 0 )
      opts->int_driven = 0;
  }

  if( (s = getenv("EF_INT_DRIVEN")) )
    opts->int_driven = atoi(s);
#if CI_CFG_WANT_BPF_NATIVE
  if( (s = getenv("EF_POLL_IN_KERNEL")) )
    opts->poll_in_kernel = atoi(s);
  static const char* const xdp_mode_opts[] = { "disabled", "compatible", 0 };
  opts->xdp_mode = parse_enum(opts, "EF_XDP_MODE", xdp_mode_opts, "disabled");
  if( opts->xdp_mode ) {
    /* for now only in-kernel XDP is supported - enabling in-kernel mode implicitly */
    opts->poll_in_kernel = 1;
  }
#endif
  if( opts->int_driven )
    /* Disable count-down timer when interrupt driven. */
    opts->timer_usec = 0;
  if( (s = getenv("EF_HELPER_USEC")) ) {
    opts->timer_usec = atoi(s);
    if( opts->timer_usec != 0 )
      /* Set the prime interval to half the timeout by default. */
      opts->timer_prime_usec = opts->timer_usec / 2;
  }
  if( (s = getenv("EF_HELPER_PRIME_USEC")) )
    opts->timer_prime_usec = atoi(s);

  if( (s = getenv("EF_BUZZ_USEC")) ) {
    opts->buzz_usec = atoi(s);
  }

  /* The options that follow are (at time of writing) not sensitive to the
   * order in which they are read.
   */

#if CI_CFG_POISON_BUFS
  if( (s = getenv("EF_POISON")) )       opts->poison_rx_buf = atoi(s);
#endif
#if CI_CFG_RANDOM_DROP
  if( (s = getenv("EF_RX_DROP_RATE")) ) {
    int r = atoi(s);
    if( r )  opts->rx_drop_rate = RAND_MAX / r;
  }
#endif
  if( (s = getenv("EF_URG_RFC")) )
    opts->urg_rfc = atoi(s);

  static const char* const urgent_opts[] = { "allow", "ignore", 0 };
  opts->urg_mode = parse_enum(opts, "EF_TCP_URG_MODE", urgent_opts, "ignore");

  if( (s = getenv("EF_MCAST_RECV")) )
    opts->mcast_recv = atoi(s);
  if( (s = getenv("EF_FORCE_SEND_MULTICAST")) )
    opts->force_send_multicast = atoi(s);
  if( (s = getenv("EF_MCAST_SEND")) )
    opts->mcast_send = atoi(s);
  else if( (s = getenv("EF_MULTICAST_LOOP_OFF")) ) {
    opts->multicast_loop_off = atoi(s);
    switch( opts->multicast_loop_off ) {
      case 0:
        opts->mcast_send = CITP_MCAST_SEND_FLAG_LOCAL;
        break;
      case 1:
        opts->mcast_send = 0;
        break;
    }
  }
  if( (s = getenv("EF_MCAST_RECV_HW_LOOP")) )
    opts->mcast_recv_hw_loop = atoi(s);
  if( (s = getenv("EF_EVS_PER_POLL")) )
    opts->evs_per_poll = atoi(s);
#if CI_CFG_WANT_BPF_NATIVE
  else if( opts->poll_in_kernel )
    opts->evs_per_poll = 192;     /* See EF_EVS_PER_POLL documentation */
#endif
  if( (s = getenv("EF_TCP_TCONST_MSL")) )
    opts->msl_seconds = atoi(s);
  if( (s = getenv("EF_TCP_FIN_TIMEOUT")) )
    opts->fin_timeout = atoi(s);
  if( (s = getenv("EF_TCP_ADV_WIN_SCALE_MAX")) )
    opts->tcp_adv_win_scale_max = atoi(s);

  if( (s = getenv("EF_TCP_SYN_OPTS")) ) {
    unsigned v;
    ci_verify(sscanf(s, "%x", &v) == 1);
    opts->syn_opts = citp_syn_opts = v;
  }

  if ( (s = getenv("EF_MAX_PACKETS")) ) {
    int max_packets_rq = atoi(s);
    opts->max_packets = (max_packets_rq + PKTS_PER_SET - 1) &
                                                ~(PKTS_PER_SET - 1);
    if( opts->max_packets != max_packets_rq )
      /* ?? TODO: log message */
      ;
    opts->max_rx_packets = opts->max_packets * 3 / 4;
    opts->max_tx_packets = opts->max_packets * 3 / 4;
  }
  if ( (s = getenv("EF_MAX_RX_PACKETS")) ) {
    opts->max_rx_packets = atoi(s);
    if( opts->max_rx_packets > opts->max_packets )
      opts->max_rx_packets = opts->max_packets;
  }
  if ( (s = getenv("EF_MAX_TX_PACKETS")) ) {
    opts->max_tx_packets = atoi(s);
    if( opts->max_tx_packets > opts->max_packets )
      opts->max_tx_packets = opts->max_packets;
  }
  if ( (s = getenv("EF_PREALLOC_PACKETS")) )
    opts->prealloc_packets = atoi(s);
  if ( (s = getenv("EF_RXQ_MIN")) )
    opts->rxq_min = atoi(s);
  if ( (s = getenv("EF_MIN_FREE_PACKETS")) )
    opts->min_free_packets = atoi(s);
  if( (s = getenv("EF_PREFAULT_PACKETS")) )
    opts->prefault_packets = atoi(s);
  if ( (s = getenv("EF_MAX_ENDPOINTS")) )
    opts->max_ep_bufs = atoi(s);
  if ( (s = getenv("EF_ENDPOINT_PACKET_RESERVE")) )
    opts->endpoint_packet_reserve = atoi(s);
  if ( (s = getenv("EF_DEFER_ARP_MAX")) )
    opts->defer_arp_pkts = atoi(s);
  if ( (s = getenv("EF_DEFER_ARP_TIMEOUT")) )
    opts->defer_arp_timeout = atoi(s);
  if ( (s = getenv("EF_SHARE_WITH")) )
    opts->share_with = atoi(s);
#if CI_CFG_PKTS_AS_HUGE_PAGES
  if( (s = getenv("EF_USE_HUGE_PAGES")) )
    opts->huge_pages = atoi(s);
  if( opts->huge_pages != 0 && opts->share_with != 0 ) {
    CONFIG_LOG(opts, CONFIG_WARNINGS, "Turning huge pages off because the "
               "stack is going to be used by multiple users");
    opts->huge_pages = 0;
  }
#endif
  if ( (s = getenv("EF_COMPOUND_PAGES_MODE")) )
    opts->compound_pages = atoi(s);
  if ( (s = getenv("EF_RXQ_SIZE")) )
    opts->rxq_size = atoi(s);
  if ( (s = getenv("EF_RXQ_LIMIT")) )
    opts->rxq_limit = atoi(s);
  if ( (s = getenv("EF_SHARED_RXQ_NUM")) )
    opts->shared_rxq_num = atoi(s);
  if ( (s = getenv("EF_TXQ_SIZE")) )
    opts->txq_size = atoi(s);
  if ( (s = getenv("EF_SEND_POLL_THRESH")) )
    opts->send_poll_thresh = atoi(s);
  if ( (s = getenv("EF_SEND_POLL_MAX_EVS")) )
    opts->send_poll_max_events = atoi(s);
  if ( (s = getenv("EF_DEFER_WORK_LIMIT")) )
    opts->defer_work_limit = atoi(s);
  if( (s = getenv("EF_UDP_SEND_UNLOCK_THRESH")) )
    opts->udp_send_unlock_thresh = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER_MIN")) )
    opts->udp_port_handover_min = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER_MAX")) )
    opts->udp_port_handover_max = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER2_MIN")) )
    opts->udp_port_handover2_min = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER2_MAX")) )
    opts->udp_port_handover2_max = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER3_MIN")) )
    opts->udp_port_handover3_min = atoi(s);
  if( (s = getenv("EF_UDP_PORT_HANDOVER3_MAX")) )
    opts->udp_port_handover3_max = atoi(s);
  if ( (s = getenv("EF_DELACK_THRESH")) )
    opts->delack_thresh = atoi(s);
#if CI_CFG_DYNAMIC_ACK_RATE
  if ( (s = getenv("EF_DYNAMIC_ACK_THRESH")) )
    opts->dynack_thresh = atoi(s);
  /* Always want this value to be >= delack_thresh to simplify code
   * that uses it 
   */
  opts->dynack_thresh = CI_MAX(opts->dynack_thresh, opts->delack_thresh);
#endif

  if ( (s = getenv("EF_INVALID_ACK_RATELIMIT")) )
    opts->oow_ack_ratelimit = atoi(s);
#if CI_CFG_FD_CACHING
  if ( (s = getenv("EF_SOCKET_CACHE_MAX")) )
    opts->sock_cache_max = atoi(s);
  if ( (s = getenv("EF_PER_SOCKET_CACHE_MAX")) )
    opts->per_sock_cache_max = atoi(s);
  if( opts->per_sock_cache_max < 0 )
    opts->per_sock_cache_max = opts->sock_cache_max;
#endif

#if CI_CFG_PORT_STRIPING
  /* configuration opttions for striping */
  if ( (s = getenv("EF_STRIPE_NETMASK")) ) {
    int a1, a2, a3, a4;
    sscanf(s, "%d.%d.%d.%d", &a1, &a2, &a3, &a4);
    opts->stripe_netmask_be32 = (a1 << 24) | (a2 << 16) | (a3 << 8) | a4;
    opts->stripe_netmask_be32 = CI_BSWAP_BE32(opts->stripe_netmask_be32);
  }
  if ( (s = getenv("EF_STRIPE_DUPACK_THRESH")) ) {
    opts->stripe_dupack_threshold = atoi(s);
    opts->stripe_dupack_threshold =
          CI_MAX(opts->stripe_dupack_threshold, CI_CFG_TCP_DUPACK_THRESH_BASE);
    opts->stripe_dupack_threshold  =
          CI_MIN(opts->stripe_dupack_threshold, CI_CFG_TCP_DUPACK_THRESH_MAX);
  }
  if( (s = getenv("EF_STRIPE_TCP_OPT")) )
    opts->stripe_tcp_opt = atoi(s);
#endif
  if( (s = getenv("EF_TX_PUSH")) )
    opts->tx_push = atoi(s);
  if( opts->tx_push && (s = getenv("EF_TX_PUSH_THRESHOLD")) )
    opts->tx_push_thresh = atoi(s);
  if( (s = getenv("EF_PACKET_BUFFER_MODE")) )
    opts->packet_buffer_mode = atoi(s);
  if( (s = getenv("EF_TCP_RST_DELAYED_CONN")) )
    opts->rst_delayed_conn = atoi(s);
  if( (s = getenv("EF_TCP_SNDBUF_MODE")) )
    opts->tcp_sndbuf_mode = atoi(s);
  if( (s = getenv("EF_TCP_COMBINE_SENDS_MODE")) )
    opts->tcp_combine_sends_mode = atoi(s);
  if( (s = getenv("EF_TCP_SEND_NONBLOCK_NO_PACKETS_MODE")) )
    opts->tcp_nonblock_no_pkts_mode = atoi(s);
  if( (s = getenv("EF_TCP_RCVBUF_STRICT")) )
    opts->tcp_rcvbuf_strict = atoi(s);
  if( (s = getenv("EF_TCP_RCVBUF_MODE")) )
    opts->tcp_rcvbuf_mode = atoi(s);
  if( (s = getenv("EF_POLL_ON_DEMAND")) )
    opts->poll_on_demand = atoi(s);
  if( (s = getenv("EF_INT_REPRIME")) )
    opts->int_reprime = atoi(s);
  if( (s = getenv("EF_NONAGLE_INFLIGHT_MAX")) )
    opts->nonagle_inflight_max = atoi(s);
  if( (s = getenv("EF_FORCE_TCP_NODELAY")) )
    opts->tcp_force_nodelay = atoi(s);
  if( (s = getenv("EF_IRQ_CORE")) )
    opts->irq_core = atoi(s);
  if( (s = getenv("EF_IRQ_CHANNEL")) )
    opts->irq_channel = atoi(s);
  if( (s = getenv("EF_TCP_LISTEN_HANDOVER")) )
    opts->tcp_listen_handover = atoi(s);
  if( (s = getenv("EF_TCP_CONNECT_HANDOVER")) )
    opts->tcp_connect_handover = atoi(s);
  if( (s = getenv("EF_UDP_CONNECT_HANDOVER")) )
    opts->udp_connect_handover = atoi(s);
  if( (s = getenv("EF_UDP_SEND_UNLOCKED")) )
    opts->udp_send_unlocked = atoi(s);
  if( (s = getenv("EF_UDP_SEND_NONBLOCK_NO_PACKETS_MODE")) )
    opts->udp_nonblock_no_pkts_mode = atoi(s);
  if( (s = getenv("EF_UNCONFINE_SYN")) )
    opts->unconfine_syn = atoi(s) != 0;
  if( (s = getenv("EF_BINDTODEVICE_HANDOVER")) )
    opts->bindtodevice_handover = atoi(s) != 0;
  if( (s = getenv("EF_MCAST_JOIN_BINDTODEVICE")) )
    opts->mcast_join_bindtodevice = atoi(s) != 0;
  if( (s = getenv("EF_MCAST_JOIN_HANDOVER")) )
    opts->mcast_join_handover = atoi(s);

#if CI_CFG_ENDPOINT_MOVE
  if( (s = getenv("EF_TCP_SERVER_LOOPBACK")) )
    opts->tcp_server_loopback = atoi(s);
  if( (s = getenv("EF_TCP_CLIENT_LOOPBACK")) )
    opts->tcp_client_loopback = atoi(s);
  /* Forbid impossible combination of loopback options */
  if( opts->tcp_server_loopback == CITP_TCP_LOOPBACK_OFF &&
      opts->tcp_client_loopback == CITP_TCP_LOOPBACK_SAMESTACK )
    opts->tcp_client_loopback = CITP_TCP_LOOPBACK_OFF;
#endif

  if( (s = getenv("EF_TCP_RX_CHECKS")) ) {
    unsigned v;
    ci_verify(sscanf(s, "%x", &v) == 1);
    opts->tcp_rx_checks = v;
    if( (s = getenv("EF_TCP_RX_LOG_FLAGS")) ) {
      ci_verify(sscanf(s, "%x", &v) == 1);
      opts->tcp_rx_log_flags = v;
    }
  }

  if( (s = getenv("EF_ACCEPTQ_MIN_BACKLOG")) )
    opts->acceptq_min_backlog = atoi(s);
  if( (s = getenv("EF_ACCEPTQ_MAX_BACKLOG")) )
    opts->acceptq_max_backlog = atoi(s);

  if ( (s = getenv("EF_TCP_SNDBUF")) )
    opts->tcp_sndbuf_user = atoi(s);
  if ( (s = getenv("EF_TCP_RCVBUF")) )
    opts->tcp_rcvbuf_user = atoi(s);
  if ( (s = getenv("EF_UDP_SNDBUF")) )
    opts->udp_sndbuf_user = atoi(s);
  if ( (s = getenv("EF_UDP_RCVBUF")) )
    opts->udp_rcvbuf_user = atoi(s);

  if( (s = getenv("EF_TCP_SNDBUF_ESTABLISHED_DEFAULT")) )
    opts->tcp_sndbuf_est_def = atoi(s);
  if( (s = getenv("EF_TCP_RCVBUF_ESTABLISHED_DEFAULT")) )
    opts->tcp_rcvbuf_est_def = atoi(s);

  if ( (s = getenv("EF_RETRANSMIT_THRESHOLD_SYNACK")) )
    opts->retransmit_threshold_synack = atoi(s);

  if ( (s = getenv("EF_RETRANSMIT_THRESHOLD_SYN")) )
    opts->retransmit_threshold_syn = atoi(s);

  if ( (s = getenv("EF_RETRANSMIT_THRESHOLD")) )
    opts->retransmit_threshold = atoi(s);

  if ( (s = getenv("EF_TCP_BACKLOG_MAX")) ) {
    opts->tcp_backlog_max = atoi(s);
    if ( getenv("EF_TCP_SYNRECV_MAX") == NULL ) {
      opts->tcp_synrecv_max = opts->tcp_backlog_max *
                              CI_CFG_ASSUME_LISTEN_SOCKS;
    }
  }
  if ( (s = getenv("EF_TCP_SYNRECV_MAX")) ) {
    opts->tcp_synrecv_max = atoi(s);
  }
  /* Number of aux buffers is tcp_synrecv_max * 2.
   * Number of ep buffers which can be used by aux bufs is
   * tcp_synrecv_max * 2 / 7.
   * And we need some space for real endpoints. */
  if( opts->tcp_synrecv_max * 4 > opts->max_ep_bufs * 7 ) {
    if( getenv("EF_TCP_SYNRECV_MAX") == NULL && getenv("EF_MAX_ENDPOINTS") == NULL && getenv("EF_TCP_BACKLOG_MAX") == NULL ) {
      /* None have been manually set so warn at lower
       * config warning level. */
      CONFIG_LOG(opts, MORE_CONFIG_WARNINGS, "%s: EF_TCP_SYNRECV_MAX=%d and "
                "EF_MAX_ENDPOINTS=%d are inconsistent.",
                opts->tcp_synrecv_max * 2 > opts->max_ep_bufs * 7 ?
                "ERROR" : "WARNING",
                opts->tcp_synrecv_max, opts->max_ep_bufs);
      CONFIG_LOG(opts, MORE_CONFIG_WARNINGS, "EF_TCP_SYNRECV_MAX is set to %d "
                "based on /proc/sys/net/ipv4/tcp_max_syn_backlog value and assuming up to %d listening "
                "sockets in the Onload stack",
                opts->tcp_synrecv_max,
                CI_CFG_ASSUME_LISTEN_SOCKS);

      round_opts("EF_MAX_ENDPOINTS", &opts->max_ep_bufs, EP_BUF_PER_CHUNK);
      opts->tcp_synrecv_max = CI_ROUND_UP(opts->max_ep_bufs, EP_BUF_PER_CHUNK) * 7/4;
      CONFIG_LOG(opts, MORE_CONFIG_WARNINGS, "EF_TCP_SYNRECV_MAX has been decreased"
                " to %d to be consistent with EF_MAX_ENDPOINTS=%d",
                opts->tcp_synrecv_max,
                opts->max_ep_bufs);
      if( opts->tcp_backlog_max > opts->tcp_synrecv_max ) {
        opts->tcp_backlog_max = opts->tcp_synrecv_max;
        CONFIG_LOG(opts, MORE_CONFIG_WARNINGS, "EF_TCP_BACKLOG_MAX has been decreased"
                  " to %d to be consistent with EF_TCP_SYNRECV_MAX=%d",
                  opts->tcp_backlog_max,
                  opts->tcp_synrecv_max);
      }
    }
    else {
      /* Any have been manually set so give the user an Error or Warning */
      CONFIG_LOG(opts, CONFIG_WARNINGS, "%s: EF_TCP_SYNRECV_MAX=%d and "
                "EF_MAX_ENDPOINTS=%d are inconsistent.",
                opts->tcp_synrecv_max * 2 > opts->max_ep_bufs * 7 ?
                "ERROR" : "WARNING",
                opts->tcp_synrecv_max, opts->max_ep_bufs);
      if( getenv("EF_TCP_SYNRECV_MAX") == NULL ) {
        CONFIG_LOG(opts, CONFIG_WARNINGS, "EF_TCP_SYNRECV_MAX is set to %d "
                  "based on EF_TCP_BACKLOG_MAX value and assuming up to %d listening "
                  "sockets in the Onload stack",
                  opts->tcp_synrecv_max,
                  CI_CFG_ASSUME_LISTEN_SOCKS);
      }
      CONFIG_LOG(opts, CONFIG_WARNINGS, "Too few endpoints requested: ~4 "
                "syn-receive states consume one endpoint. ");
    }
  }

  if ( (s = getenv("EF_TCP_INITIAL_CWND")) )
    opts->initial_cwnd = atoi(s);
  if ( (s = getenv("EF_TCP_LOSS_MIN_CWND")) )
    opts->loss_min_cwnd = atoi(s);
  if ( (s = getenv("EF_TCP_MIN_CWND")) )
    opts->min_cwnd = atoi(s);
#if CI_CFG_TCP_FASTSTART
  if ( (s = getenv("EF_TCP_FASTSTART_INIT")) )
    opts->tcp_faststart_init = atoi(s);
  if ( (s = getenv("EF_TCP_FASTSTART_IDLE")) )
    opts->tcp_faststart_idle = atoi(s);
  if ( (s = getenv("EF_TCP_FASTSTART_LOSS")) )
    opts->tcp_faststart_loss = atoi(s);
#endif

  if ( (s = getenv("EF_RFC_RTO_INITIAL")))
    opts->rto_initial = atoi(s);
  if ( (s = getenv("EF_RFC_RTO_MIN")))
    opts->rto_min = atoi(s);
  if ( (s = getenv("EF_RFC_RTO_MAX")))
    opts->rto_max = atoi(s);

  if ( (s = getenv("EF_KEEPALIVE_TIME")))
    opts->keepalive_time = atoi(s);
  if ( (s = getenv("EF_KEEPALIVE_INTVL")))
    opts->keepalive_intvl = atoi(s);
  if ( (s = getenv("EF_KEEPALIVE_PROBES")))
    opts->keepalive_probes = atoi(s);

  if ( (s = getenv("EF_TCP_RST_COOLDOWN")))
    opts->tcp_rst_cooldown = atoi(s);

#ifndef NDEBUG
  if( (s = getenv("EF_TCP_MAX_SEQERR_MSGS")))
    opts->tcp_max_seqerr_msg = atoi(s);
#endif
#if CI_CFG_BURST_CONTROL
  if ( (s = getenv("EF_BURST_CONTROL_LIMIT")))
    opts->burst_control_limit = atoi(s);
#endif
#if CI_CFG_CONG_AVOID_NOTIFIED
  if ( (s = getenv("EF_CONG_NOTIFY_THRESH")))
    opts->cong_notify_thresh = atoi(s);
#endif
#if CI_CFG_TAIL_DROP_PROBE
  if ( (s = getenv("EF_TAIL_DROP_PROBE")))
    opts->tail_drop_probe = atoi(s);
#endif
#if CI_CFG_CONG_AVOID_SCALE_BACK
  if ( (s = getenv("EF_CONG_AVOID_SCALE_BACK")))
    opts->cong_avoid_scale_back = atoi(s);
#endif

  if ( (s = getenv("EF_TCP_TIME_WAIT_ASSASSINATION")))
    opts->time_wait_assassinate = atoi(s);

  if ( (s = getenv("EF_TPH_MODE")))
#if CI_HAVE_SDCI
    opts->tph_mode = atoi(s);
#else /* CI_HAVE_SDCI */
    ci_log("EF_TPH_MODE found, but SDCI support is not compiled in. Please "
           "recompile onload with SDCI support or avoid using EF_TPH_MODE.");
#endif /* CI_HAVE_SDCI */

  /* Get our netifs to inherit flags if the O/S is being forced to */
  if (CITP_OPTS.accept_force_inherit_nonblock)
    opts->accept_inherit_nonblock = 1;

  if ( (s = getenv("EF_FREE_PACKETS_LOW_WATERMARK")) )
    opts->free_packets_low = atoi(s);
  if( opts->free_packets_low == 0 )
    opts->free_packets_low = opts->rxq_size / 2;

#if CI_CFG_PIO
  if ( (s = getenv("EF_PIO")) )
    opts->pio = atoi(s);
  if( opts->pio == 0 )
    /* Makes for more efficient checking on fast data path */
    opts->pio_thresh = 0;
  else if ( (s = getenv("EF_PIO_THRESHOLD")) )
    opts->pio_thresh = atoi(s);
#endif

  if( (s = getenv("EF_RX_TIMESTAMPING")) )
    opts->rx_timestamping = atoi(s);

  static const char* const timestamping_opts[] = { "nic", "trailer", "cpacket", 0 };
  opts->rx_timestamping_ordering =
    parse_enum(opts, "EF_RX_TIMESTAMPING_ORDERING", timestamping_opts, "nic");
  /* cpacket (2) is a synonym for trailer (1) */
  if (opts->rx_timestamping_ordering > 1)
    opts->rx_timestamping_ordering--;

  static const char* const ts_trailer_formats[] = { "cpacket", "ttag", "brcm", 0 };
  opts->rx_timestamping_trailer_fmt =
    parse_enum(opts, "EF_RX_TIMESTAMPING_TRAILER_FORMAT", ts_trailer_formats, "cpacket");

  if( (s = getenv("EF_TX_TIMESTAMPING")) )
    opts->tx_timestamping = atoi(s);

  if( (s = getenv("EF_TIMESTAMPING_REPORTING")) )
    opts->timestamping_reporting = atoi(s);

  if( (s = getenv("EF_TCP_TSOPT_MODE")) ) {
    opts->tcp_tsopt_mode = atoi(s);
    if( !(opts->tcp_tsopt_mode == 2) ) {
      citp_syn_opts &=~ CI_TCPT_FLAG_TSO;
      citp_syn_opts |= (opts->tcp_tsopt_mode ? CI_TCPT_FLAG_TSO : 0);
      opts->syn_opts = citp_syn_opts;
    }
  }

  if( (s = getenv("EF_USE_DSACK")) )
    opts->use_dsack = atoi(s);

  if( (s = getenv("EF_PERIODIC_TIMER_CPU")) ) {
    int cpu = atoi(s);
    if( cpu >= sysconf(_SC_NPROCESSORS_ONLN) ) {
      CONFIG_LOG(opts, CONFIG_WARNINGS, "Value of EF_PERIODIC_TIMER_CPU is "
                 "invalid. Periodic work will not be affinitised.");
      cpu = -1;
    }
    opts->periodic_timer_cpu = cpu;
  }

  if( (s = getenv("EF_TCP_SYNCOOKIES")) )
    opts->tcp_syncookies = atoi(s);

  if( (s = getenv("EF_CLUSTER_IGNORE")) ) {
    ci_log("EF_CLUSTER_IGNORE is deprecated use EF_CLUSTER_SIZE instead");
    opts->cluster_ignore = atoi(s);
  }
  else if( (s = getenv("EF_CLUSTER_SIZE")) ) {
    opts->cluster_ignore = (atoi(s) == 0);
  }
  else
    opts->cluster_ignore = 1;

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  if( (s = getenv("EF_TCP_SHARED_LOCAL_PORTS")) )
    opts->tcp_shared_local_ports = atoi(s);
  if( (s = getenv("EF_TCP_SHARED_LOCAL_PORTS_REUSE_FAST")) )
    opts->tcp_shared_local_ports_reuse_fast = atoi(s);
  if( (s = getenv("EF_TCP_SHARED_LOCAL_PORTS_MAX")) )
    opts->tcp_shared_local_ports_max = atoi(s);
  if( (s = getenv("EF_TCP_SHARED_LOCAL_PORTS_NO_FALLBACK")) )
    opts->tcp_shared_local_no_fallback = atoi(s) &&
      opts->tcp_shared_local_ports > 0;
  if( (s = getenv("EF_TCP_SHARED_LOCAL_PORTS_PER_IP")) )
    opts->tcp_shared_local_ports_per_ip = atoi(s);
  if( (s = getenv("EF_TCP_SHARED_LOCAL_PORTS_PER_IP_MAX")) )
    opts->tcp_shared_local_ports_per_ip_max = atoi(s);
  if( (s = getenv("EF_TCP_SHARED_LOCAL_PORTS_STEP")) )
    opts->tcp_shared_local_ports_step = atoi(s);
#endif

  if( (s = getenv("EF_HIGH_THROUGHPUT_MODE")) )
    opts->rx_merge_mode = atoi(s);

  handle_str_opt(opts, "EF_INTERFACE_WHITELIST", opts->iface_whitelist,
                 sizeof(opts->iface_whitelist));
  handle_str_opt(opts, "EF_INTERFACE_BLACKLIST", opts->iface_blacklist,
                 sizeof(opts->iface_blacklist));

  static const char* const multiarch_tx_opts[] = { "enterprise", "express", 0 };
  opts->multiarch_tx_datapath =
    parse_enum(opts, "EF_TX_DATAPATH", multiarch_tx_opts, "express");

  static const char* const multiarch_rx_opts[] = { "enterprise", "express", "both", 0 };
  opts->multiarch_rx_datapath =
    parse_enum(opts, "EF_RX_DATAPATH", multiarch_rx_opts, "both");

  if( (s = getenv("EF_LLCT_TEST_SHRUB")) )
    opts->llct_test_shrub = atoi(s);

  if( (s = getenv("EF_KERNEL_PACKETS_BATCH_SIZE")) )
    opts->kernel_packets_batch_size = atoi(s);

  if( (s = getenv("EF_KERNEL_PACKETS_TIMER_USEC")) )
    opts->kernel_packets_timer_usec = atoi(s);

  static const char* const tcp_isn_opts[] = { "clocked", "clocked+cache", 0 };
  opts->tcp_isn_mode =
    parse_enum(opts, "EF_TCP_ISN_MODE", tcp_isn_opts, "clocked+cache");
  if( (s = getenv("EF_TCP_ISN_2MSL")) )
    opts->tcp_isn_2msl = atoi(s);
  if( (s = getenv("EF_TCP_ISN_CACHE_SIZE")) )
    opts->tcp_isn_cache_size = atoi(s);
  if( (s = getenv("EF_TCP_ISN_INCLUDE_PASSIVE")) )
    opts->tcp_isn_include_passive = atoi(s);
  if( (s = getenv("EF_TCP_ISN_OFFSET")) )
    opts->tcp_isn_offset = atoi(s);

  ci_netif_config_opts_getenv_ef_scalable_filters(opts);

#if CI_CFG_CTPIO
  if( (s = getenv("EF_CTPIO")) )
    opts->ctpio = atoi(s);

  static const char* const ctpio_opts[] = { "sf", "sf-np", "ct", 0 };
  opts->ctpio_mode = parse_enum(opts, "EF_CTPIO_MODE", ctpio_opts, "sf-np");

  if( (s = getenv("EF_CTPIO_MAX_FRAME_LEN")) )
    opts->ctpio_max_frame_len = atoi(s);
  else if( opts->ctpio_mode == EF_CTPIO_MODE_CT )
    opts->ctpio_max_frame_len = 1518;
  else
    opts->ctpio_max_frame_len = 500;
  if( (s = getenv("EF_CTPIO_CT_THRESH")) )
    opts->ctpio_ct_thresh = atoi(s);
  if( (s = getenv("EF_CTPIO_SWITCH_BYPASS")) )
    opts->ctpio_switch_bypass = atoi(s);
#endif

  if( (s = getenv("EF_TCP_EARLY_RETRANSMIT")) )
    opts->tcp_early_retransmit = atoi(s);

#if CI_CFG_IPV6
  if( (s = getenv("EF_AUTO_FLOWLABELS")) )
    opts->auto_flowlabels = atoi(s);
#endif

  if( (s = getenv("EF_AF_XDP_ZEROCOPY")) )
    opts->af_xdp_zerocopy = atoi(s);

  if( (s = getenv("EF_ICMP_PKTS")) )
    opts->icmp_msg_max = atoi(s);

  if( (s = getenv("EF_NO_HW")) )
    opts->no_hw = atoi(s);

  if( (s = getenv("EF_DUMP_STACK_ON_EXIT")) )
    opts->dump_stack_on_exit = atoi(s);

  if( (s = getenv("EF_SHRUB_CONTROLLER")) )
    opts->shrub_controller_id = atoi(s);

  if( (s = getenv("EF_SHRUB_BUFFER_COUNT")) )
    opts->shrub_buffer_count = atoi(s);

  if( (s = getenv("EF_SHRUB_DEBUG")) )
    opts->shrub_debug = atoi(s);

}


/* Set derived after the range check has been applied */
void ci_netif_config_opts_set_derived(ci_netif_config_opts* opts)
{
  if( opts->tcp_sndbuf_user != 0 ) {
    opts->tcp_sndbuf_min = opts->tcp_sndbuf_max = opts->tcp_sndbuf_user;
    opts->tcp_sndbuf_def = oo_adjust_SO_XBUF(opts->tcp_sndbuf_user);
  }
  if( opts->tcp_rcvbuf_user != 0 ) {
    opts->tcp_rcvbuf_min = opts->tcp_rcvbuf_max = opts->tcp_rcvbuf_user;
    opts->tcp_rcvbuf_def = oo_adjust_SO_XBUF(opts->tcp_rcvbuf_user);
  }
  if( opts->udp_sndbuf_user != 0 ) {
    opts->udp_sndbuf_min = opts->udp_sndbuf_max = opts->udp_sndbuf_user;
    opts->udp_sndbuf_def = oo_adjust_SO_XBUF(opts->udp_sndbuf_user);
  }
  if( opts->udp_rcvbuf_user != 0 ) {
    opts->udp_rcvbuf_min = opts->udp_rcvbuf_max = opts->udp_rcvbuf_user;
    opts->udp_rcvbuf_def = oo_adjust_SO_XBUF(opts->udp_rcvbuf_user);
  }
}


static int
handle_str_opt(ci_netif_config_opts* opts,
               const char* optname, char* optval_buf, size_t optval_buflen)
{
 char* s;
  if( (s = getenv(optname)) ) {
    if( strlen(s) >= optval_buflen ) {
      CONFIG_LOG(opts, CONFIG_WARNINGS, "Value of %s"
                 "too long - truncating. ", optname);
    }
    strncpy(optval_buf, s, optval_buflen);
    optval_buf[optval_buflen - 1] = 0;

    return 1;
  }
  else {
    return 0;
  }
}

static int
parse_enum(ci_netif_config_opts* opts,
           const char* name, const char* const* options,
           const char* default_val)
{
  const char* value;
  int i;

  if( (value = getenv(name)) == NULL )
    value = default_val;

  while( 1 ) {
    for( i = 0; options[i]; ++i )
      if( ! strcasecmp(value, options[i]) )
        return i;

    CONFIG_LOG(opts, CONFIG_WARNINGS,
               "%s='%s' not recognised, defaulting to '%s'",
               name, value, default_val);
    value = default_val;
  }
}

static const char* strmchrnul(const char *s, const char* delims)
{
  const char* r = NULL;
  while( *delims ) {
   const char * t = strchrnul(s, *delims);
   if( !r || t < r )
     r = t;
   ++delims;
  }
  return r;
}


/* Note that all ifindices in this function must be signed to allow for the
 * extra magic values such as CITP_SCALABLE_FILTERS_ALL. */
static int ci_opts_parse_scalable_filters_nic(ci_netif_config_opts* opts,
                                              const char** spec_in_out,
                                              int* mode_out,
                                              ci_int32* ifindex_out)
{
  char ifname[IFNAMSIZ] = {};
  const char* s = *spec_in_out;
  const char* modestr;
  ci_int32 ifindex = 0;
  int mode = -1;
  int rc = 0;

  modestr = strmchrnul(s, "=,");
  strncpy(ifname, s, CI_MIN(modestr - s, sizeof(ifname) - 1));
  ifindex = if_nametoindex(ifname);

  if( ifindex == CI_IFID_BAD && (strcmp(ifname, "any") == 0 ||
                                 strcmp(ifname, ".") == 0) )
    ifindex = CITP_SCALABLE_FILTERS_ALL;

  /* If we've got a valid ifindex then we need to determine the mode */
  if( ifindex > 0 || ifindex == CITP_SCALABLE_FILTERS_ALL ) {
    /* If a mode isn't present in the EF_SCALABLE_FILTERS option check
     * EF_SCALABLE_FILTERS_MODE.
     */
    if( *modestr != '=' )
      modestr = getenv("EF_SCALABLE_FILTERS_MODE");
    else
      ++modestr;

    /* If the mode is set explicitly then parse that */
    if( modestr && modestr != strmchrnul(modestr, ",") ) {
      int mode_value = CITP_SCALABLE_MODE_NONE;
      int mode_set = 0;
      struct {const char* name; int mode;} modes[] = {
        {"transparent_active", CITP_SCALABLE_MODE_TPROXY_ACTIVE},
        {"passive", CITP_SCALABLE_MODE_PASSIVE},
        {"active",  CITP_SCALABLE_MODE_ACTIVE},
        {"rss",     CITP_SCALABLE_MODE_RSS},
      };
      while ( modestr != strmchrnul(modestr, ",") ) {
        const char* mode_end = strmchrnul(modestr, ":,");
        int len  = mode_end - modestr;
        int i;
        for( i = 0; i < sizeof(modes) / sizeof(*modes); ++i )
          if( strncmp(modes[i].name, modestr, len) == 0 &&
              modes[i].name[len] == 0 ) {
            mode_value |=  modes[i].mode;
            mode_set |= 3;
            break;
        }
        if( ! (mode_set & 1) ) {
          CONFIG_LOG(opts, CONFIG_WARNINGS, "config: Error parsing "
                     "EF_SCALABLE_FILTERS, token '%s', disabling scalable "
                     "filter mode", modestr);
          mode = CITP_SCALABLE_MODE_NONE;
          mode_set = 0;
          rc = -EINVAL;
          break;
        }
        modestr = mode_end;
        if( *modestr == ':' )
          ++modestr;
        mode_set &= ~1;
      }

      if( mode_set ) {
        int modes_supported[] = {
          CITP_SCALABLE_MODE_TPROXY_ACTIVE,
          CITP_SCALABLE_MODE_PASSIVE,
          CITP_SCALABLE_MODE_ACTIVE,
          CITP_SCALABLE_MODE_TPROXY_ACTIVE | CITP_SCALABLE_MODE_PASSIVE,
          CITP_SCALABLE_MODE_TPROXY_ACTIVE | CITP_SCALABLE_MODE_RSS,
          CITP_SCALABLE_MODE_ACTIVE | CITP_SCALABLE_MODE_RSS,
          CITP_SCALABLE_MODE_PASSIVE | CITP_SCALABLE_MODE_RSS,
          CITP_SCALABLE_MODE_ACTIVE | CITP_SCALABLE_MODE_PASSIVE |
                                      CITP_SCALABLE_MODE_RSS
        };
        int n_modes = sizeof(modes_supported)/sizeof(*modes_supported);
        int fail = 1;
        int i;

        mode = mode_value;

        for( i = 0; i < n_modes; ++i) {
          if( mode == modes_supported[i] ) {
            fail = 0;
            break;
          }
        }
        if( fail ) {
          CONFIG_LOG(opts, CONFIG_WARNINGS, "config: Unsupported scalable "
                     "mode selected, disabling scalable filter mode.");
          mode = CITP_SCALABLE_MODE_NONE;
          rc = -EINVAL;
        }
      }
    }
  }
  else {
    CONFIG_LOG(opts, CONFIG_WARNINGS, "config: Could not determine ifindex "
               "from name '%s', disabling scalable filter mode.", ifname);
    mode = CITP_SCALABLE_MODE_NONE;
    rc = -EINVAL;
  }

  if( modestr && *modestr )
    ++modestr;

  *spec_in_out = modestr;
  *mode_out = mode;
  *ifindex_out = ifindex;
  return rc;
}


#define swap(x,y) ({ typeof(x) t = (x); (x) = (y); (y) = (t); })

static void
ci_netif_config_opts_getenv_ef_scalable_filters(ci_netif_config_opts* opts)
{
  const char* s;
  int enable = 0;
  int mode = CITP_SCALABLE_MODE_NONE;
  int listen_mode = CITP_SCALABLE_LISTEN_BOUND;
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  int active_wilds_need_filter = 1;
#endif
  int rc = 0;
  ci_int32 ifindexes[2] = {};

  /* Nothing is interesting unless EF_SCALABLE_FILTERS is set */
  if( (s = getenv("EF_SCALABLE_FILTERS")) ) {
    int modes[2] = {};
    int cluster_name_len;
    int i;

    strncpy(opts->scalable_filter_string, s,
            sizeof(opts->scalable_filter_string));
    opts->scalable_filter_string[sizeof(opts->scalable_filter_string) - 1] = 0;

    /* parse interfaces in EF_SCALABLE_FILTERS until: got two of them,
     * run out of the string or hit parsing error */
    for( i = 0;
         i < 2 && s && *s &&
         0 == (rc = ci_opts_parse_scalable_filters_nic(opts, &s, &modes[i],
                                                       &ifindexes[i]));
         ++i);

    if( rc != 0 ) {
      /* message has already been printed */
      goto invalid_mode;
    }
    else if( i == 0 ) {
      mode = CITP_SCALABLE_MODE_NONE;
    }
    else if( i == 1 ) {
      /* If the mode was not set explicitly then default to non-rss mode,
       * otherwise check the mode is supported */
      if( modes[0] < 0 )
        modes[0] = CITP_SCALABLE_MODE_TPROXY_ACTIVE |
                   CITP_SCALABLE_MODE_PASSIVE;
      ifindexes[1] = ifindexes[0];
    }
    else {
      /* Multiple modes specified. */

      if( ifindexes[0] == CITP_SCALABLE_FILTERS_ALL ||
          ifindexes[1] == CITP_SCALABLE_FILTERS_ALL ) {
        CONFIG_LOG(opts, CONFIG_WARNINGS,
                   "config: Multiple scalable interfaces specified when "
                   "requesting scalable filters on all interfaces.");
        goto invalid_mode;
      }

      if( modes[0] < 0 && modes[1] < 0 ) {
        modes[0] = CITP_SCALABLE_MODE_PASSIVE;
        modes[1] = CITP_SCALABLE_MODE_TPROXY_ACTIVE;
      }
      else {
        if( modes[1] < 0 ) {
          swap(modes[0], modes[1]);
          swap(ifindexes[0], ifindexes[1]);
        }
        if( modes[0] < 0 ) {
          if( modes[1] & (CITP_SCALABLE_MODE_ACTIVE | CITP_SCALABLE_MODE_TPROXY_ACTIVE) ) {
            if( modes[1] & CITP_SCALABLE_MODE_PASSIVE ) {
              CONFIG_LOG(opts, CONFIG_WARNINGS, "config: With two scalable interfaces "
                         "one needs to be exclusively active while other exclusively passive.");
              goto invalid_mode;
            }
            modes[0] = CITP_SCALABLE_MODE_PASSIVE | (modes[1] & CITP_SCALABLE_MODE_RSS);
          }
          else if( modes[1] & CITP_SCALABLE_MODE_PASSIVE ) {
            modes[0] = CITP_SCALABLE_MODE_TPROXY_ACTIVE | (modes[1] & CITP_SCALABLE_MODE_RSS);
            swap(modes[0], modes[1]);
            swap(ifindexes[0], ifindexes[1]);
          }
        }
        /* now we have both modes resolved, passive at index 1 */
        ci_assert_nflags(modes[1], CITP_SCALABLE_MODE_ACTIVE | CITP_SCALABLE_MODE_TPROXY_ACTIVE);
        ci_assert(modes[0] & (CITP_SCALABLE_MODE_ACTIVE | CITP_SCALABLE_MODE_TPROXY_ACTIVE));
        ci_assert_flags(modes[1], CITP_SCALABLE_MODE_PASSIVE);
        ci_assert_nflags(modes[0], CITP_SCALABLE_MODE_PASSIVE);
      }

      if( (modes[0] ^ modes[1]) & CITP_SCALABLE_MODE_RSS ) {
        CONFIG_LOG(opts, CONFIG_WARNINGS, "config: When specifying two scalable "
                   "modes RSS setting needs to be identical.");
        goto invalid_mode;
      }
    }

    mode = modes[0] | modes[1];

    if( mode != CITP_SCALABLE_MODE_NONE ) {
      if( (s = getenv("EF_SCALABLE_FILTERS_ENABLE")) )
        enable = atoi(s);
      else
        enable = CITP_SCALABLE_FILTERS_ENABLE;

      if( (s = getenv("EF_SCALABLE_LISTEN_MODE")) )
        listen_mode = atoi(s);
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
      if( mode & CITP_SCALABLE_MODE_ACTIVE )
        active_wilds_need_filter = 0;
      if( (s = getenv("EF_SCALABLE_ACTIVE_WILDS_NEED_FILTER")) )
        active_wilds_need_filter = atoi(s);
#endif
    }
    else {
      enable = CITP_SCALABLE_FILTERS_DISABLE;
    }

    /* Stacks cannot be named by EF_NAME in clustered scalable modes. */
    if( enable == CITP_SCALABLE_FILTERS_ENABLE &&
        mode & CITP_SCALABLE_MODE_RSS &&
        (s = getenv("EF_NAME")) && s[0] != '\0' )
      CONFIG_LOG(opts, CONFIG_WARNINGS,
                 "config: Stacks cannot be named by EF_NAME while in a "
                 "clustered scalable mode.")

    /* In scalable mode, cluster name has a max length of 5. See bug78935. */
    cluster_name_len = 5 - (CITP_OPTS.cluster_size > 9);
    if( strlen(CITP_OPTS.cluster_name) > cluster_name_len ) {
      CITP_OPTS.cluster_name[cluster_name_len] = '\0';
      CONFIG_LOG(opts, CONFIG_WARNINGS,
                 "config: The supplied EF_CLUSTER_NAME is too long and is "
                 "being truncated to: %s.", CITP_OPTS.cluster_name);
    }
  }
  else {
    if( (s = getenv("EF_SCALABLE_FILTERS_ENABLE")) )
      CONFIG_LOG(opts, CONFIG_WARNINGS, "config: EF_SCALABLE_FILTERS_ENABLE "
                 "ignored as no valid config for EF_SCALABLE_FILTERS found.");
    enable = CITP_SCALABLE_FILTERS_DISABLE;
  }

  if( enable == CITP_SCALABLE_FILTERS_DISABLE ) {
    if( (s = getenv("EF_SCALABLE_LISTEN_MODE")) )
      CONFIG_LOG(opts, CONFIG_WARNINGS, "config: EF_SCALABLE_LISTEN_MODE "
                 "ignored as no valid config for EF_SCALABLE_FILTERS found.");
    if( (s = getenv("EF_SCALABLE_ACTIVE_WILDS_NEED_FILTER")) )
      CONFIG_LOG(opts, CONFIG_WARNINGS,
                 "config: EF_SCALABLE_ACTIVE_WILDS_NEED_FILTER "
                 "ignored as no valid config for EF_SCALABLE_FILTERS found.");
  }
  opts->scalable_filter_ifindex_passive = ifindexes[1];
  opts->scalable_filter_ifindex_active = ifindexes[0];
  opts->scalable_filter_enable = enable;
  opts->scalable_filter_mode = mode;
  opts->scalable_listen = listen_mode;
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  opts->scalable_active_wilds_need_filter = active_wilds_need_filter;
#endif
  return;
invalid_mode:
  return; /* ideally, exit application */
}

#endif


/*****************************************************************************
 *                                                                           *
 *          TCP-helper Construction                                          *
 *          =======================                                          *
 *                                                                           *
 *****************************************************************************/

#ifndef __KERNEL__
static void netif_tcp_helper_build2(ci_netif* ni)
{
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  ni->active_wild_table =
    (struct oo_p_dllink*) ((char*) ni->state + ni->state->active_wild_ofs);
#endif
  ni->seq_table =
    (ci_tcp_prev_seq_t*) ((char*) ni->state + ni->state->seq_table_ofs);
  ni->deferred_pkts =
    (struct oo_deferred_pkt*) ((char*) ni->state +
                               ni->state->deferred_pkts_ofs);
  ni->filter_table =
    (ci_netif_filter_table*) ((char*) ni->state + ni->state->table_ofs);
  ni->filter_table_ext =
    (ci_netif_filter_table_entry_ext*) ((char*) ni->state +
                                        ni->state->table_ext_ofs);
#if CI_CFG_IPV6
  ni->ip6_filter_table =
    (ci_ip6_netif_filter_table*) ((char*) ni->state + ni->state->ip6_table_ofs);
#endif
  ni->packets = (oo_pktbuf_manager*) ((char*) ni->state + ni->state->buf_ofs);
  ni->dma_addrs = (ef_addr*) ((char*) ni->state + ni->state->dma_ofs);

#if CI_CFG_UL_INTERRUPT_HELPER
  oo_ringbuffer_init(&ni->closed_eps, &ni->state->closed_eps, "closed_eps",
                     (void*)((char*) ni->state + ni->state->closed_eps_ofs));
  oo_ringbuffer_init(&ni->sw_filter_ops, &ni->state->sw_filter_ops,
                     "sw_filters",
                     (void*)((char*) ni->state + ni->state->sw_filter_ofs));
#endif
}



static void netif_tcp_helper_munmap(ci_netif* ni)
{
  int rc;

  if( ni->timesync != NULL ) {
    rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                            ni->timesync, ni->state->timesync_bytes);
    if( rc < 0 )  LOG_NV(ci_log("%s: munmap timesync %d", __FUNCTION__, rc));
  }

  /* Buffer mapping. */
  if( ni->packets != NULL ) {
    unsigned id;

    /* Unmap packets pages */
    for( id = 0; id < ni->packets->sets_n; id++ ) {
      if( PKT_BUFSET_U_MMAPPED(ni, id) ) {
#if CI_CFG_PKTS_AS_HUGE_PAGES
        if( ni->packets->set[id].page_offset >= 0 )
          rc = munmap(ni->pkt_bufs[id], CI_HUGEPAGE_SIZE);
        else
#endif
        {
          rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                                  ni->pkt_bufs[id],
                                  CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET);
        }
        if( rc < 0 )
          LOG_NV(ci_log("%s: munmap packets %d", __FUNCTION__, rc));
      }
    }
  }

  if( ni->efct_shm_ptr != NULL ) {
    rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                            ni->efct_shm_ptr, ni->state->efct_shm_mmap_bytes);
    if( rc < 0 )  LOG_NV(ci_log("%s: munmap efct shm %d", __FUNCTION__, rc));
  }

  if( ni->buf_ptr != NULL ) {
    rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                            ni->buf_ptr, ni->state->buf_mmap_bytes);
    if( rc < 0 )  LOG_NV(ci_log("%s: munmap bufs %d", __FUNCTION__, rc));
  }

#if CI_CFG_PIO
  if( ni->pio_bytes_mapped != 0 && ni->pio_ptr != NULL ) {
    rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                            ni->pio_ptr, ni->pio_bytes_mapped);
    if( rc < 0 )  LOG_NV(ci_log("%s: munmap pio %d", __FUNCTION__, rc));
  }
#endif

#if CI_CFG_CTPIO
  if( ni->ctpio_bytes_mapped != 0 && ni->ctpio_ptr != NULL ) {
    rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                            ni->ctpio_ptr, ni->ctpio_bytes_mapped);
    if( rc < 0 )  LOG_NV(ci_log("%s: munmap pio %d", __FUNCTION__, rc));
  }
#endif

  if( ni->io_ptr != NULL ) {
    rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                            ni->io_ptr, ni->state->io_mmap_bytes);
    if( rc < 0 )  LOG_NV(ci_log("%s: munmap io %d", __FUNCTION__, rc));
  }

  rc = oo_resource_munmap(ci_netif_get_driver_handle(ni),
                          ni->state, ni->mmap_bytes);
  ni->state = NULL;
  if( rc < 0 )  LOG_NV(ci_log("%s: munmap shared state %d", __FUNCTION__, rc));
}


static int netif_tcp_helper_mmap(ci_netif* ni)
{
  ci_netif_state* ns = ni->state;
  void* p;
  int rc;

  /* Initialise all mappings with NULL to roll back in case of error. */
  ni->timesync = NULL;
  ni->io_ptr = NULL;
#if CI_CFG_PIO
  ni->pio_ptr = NULL;
  ni->pio_bytes_mapped = 0;
#endif
#if CI_CFG_CTPIO
  ni->ctpio_ptr = NULL;
  ni->ctpio_bytes_mapped = 0;
#endif
  ni->buf_ptr = NULL;
  ni->efct_shm_ptr = NULL;
  ni->packets = NULL;

  /****************************************************************************
   * Create timesync mapping.
   */
  if( ns->timesync_bytes != 0 ) {
    rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                          OO_MMAP_TYPE_NETIF,
                          CI_NETIF_MMAP_ID_TIMESYNC, ns->timesync_bytes,
                          OO_MMAP_FLAG_READONLY | OO_MMAP_FLAG_POPULATE, &p);
    if( rc < 0 ) {
      LOG_NV(ci_log("%s: oo_resource_mmap timesync %d", __FUNCTION__, rc));
      goto fail1;
    }
    ni->timesync = p;
  }


  /****************************************************************************
   * Create the I/O mapping.
   */
  if( ns->io_mmap_bytes != 0 ) {
    rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                          OO_MMAP_TYPE_NETIF,
                          CI_NETIF_MMAP_ID_IO, ns->io_mmap_bytes,
                          OO_MMAP_FLAG_POPULATE, &p);
    if( rc < 0 ) {
      LOG_NV(ci_log("%s: oo_resource_mmap io %d", __FUNCTION__, rc));
      goto fail1;
    }
    ni->io_ptr = (char*) p;
  }

#if CI_CFG_PIO
  /****************************************************************************
   * Create the PIO mapping.
   */
  if( ns->pio_mmap_bytes != 0 ) {
    rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                          OO_MMAP_TYPE_NETIF,
                          CI_NETIF_MMAP_ID_PIO, ns->pio_mmap_bytes,
                          OO_MMAP_FLAG_POPULATE, &p);
    if( rc < 0 ) {
      LOG_NV(ci_log("%s: oo_resource_mmap pio %d", __FUNCTION__, rc));
      goto fail2;
    }
    ni->pio_ptr = (uint8_t*) p;
    /* Record length actually mapped as the value in the shared state can
     * change across NIC reboots. */
    ni->pio_bytes_mapped = ns->pio_mmap_bytes;
  }
#endif

#if CI_CFG_CTPIO
  /****************************************************************************
   * Create the CTPIO mapping.
   */
  if( ns->ctpio_mmap_bytes != 0 ) {
    rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                          OO_MMAP_TYPE_NETIF,
                          CI_NETIF_MMAP_ID_CTPIO, ns->ctpio_mmap_bytes,
                          OO_MMAP_FLAG_POPULATE, &p);
    if( rc < 0 ) {
      LOG_NV(ci_log("%s: oo_resource_mmap ctpio %d", __FUNCTION__, rc));
      goto fail2;
    }
    ni->ctpio_ptr = (uint8_t*) p;
    /* Record length actually mapped as the value in the shared state can
     * change across NIC reboots. */
    ni->ctpio_bytes_mapped = ns->ctpio_mmap_bytes;
  }
#endif

  /****************************************************************************
   * Create the I/O buffer mapping.
   */
  if( ns->buf_mmap_bytes != 0 ) {
    rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                          OO_MMAP_TYPE_NETIF,
                          CI_NETIF_MMAP_ID_IOBUFS, ns->buf_mmap_bytes,
                          OO_MMAP_FLAG_POPULATE, &p);
    if( rc < 0 ) {
      LOG_NV(ci_log("%s: oo_resource_mmap iobufs %d", __FUNCTION__, rc));
      goto fail2;
    }
    ni->buf_ptr = (char*) p;
  }

  /****************************************************************************
   * Create the efct rxq shm mapping.
   */
  if( ns->efct_shm_mmap_bytes != 0 ) {
    rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                          OO_MMAP_TYPE_NETIF,
                          CI_NETIF_MMAP_ID_EFCT_SHM, ns->efct_shm_mmap_bytes,
                          OO_MMAP_FLAG_POPULATE, &p);
    if( rc < 0 ) {
      LOG_NV(ci_log("%s: oo_resource_mmap rxq shm %d", __FUNCTION__, rc));
      goto fail2;
    }
    ni->efct_shm_ptr = p;
  }

  return 0;

 fail2:
  netif_tcp_helper_munmap(ni);
 fail1:
  return rc;
}


static int oo_efct_superbuf_config_refresh(ef_vi* vi, int ix)
{
  int rc;
  int intf_i = vi->efct_rxqs.ops->user_data;

  oo_efct_superbuf_config_refresh_t op;
  op.intf_i = intf_i;
  op.qid = ix;
  op.max_superbufs = CI_EFCT_MAX_SUPERBUFS;
  CI_USER_PTR_SET(op.superbufs, vi->efct_rxqs.q[ix].superbuf);
  CI_USER_PTR_SET(op.current_mappings, vi->efct_rxqs.q[ix].mappings);
  rc = oo_resource_op(vi->dh, OO_IOC_EFCT_SUPERBUF_CONFIG_REFRESH, &op);

  /* Map the rx buffer post register now if needed. It couldn't be done
   * earlier because the NIC queue wasn't known, and is needed now we're
   * about to start polling the queue. */
  if( rc == 0 &&
      vi->vi_flags & EF_VI_RX_PHYS_ADDR &&
      vi->efct_rxqs.ops->post != NULL )
  {
    void *p;
    rc = oo_resource_mmap(vi->dh, OO_MMAP_TYPE_UBUF_POST,
                          OO_MMAP_UBUF_POST_MAKE_ID(ix, intf_i),
                          CI_ROUND_UP(sizeof(uint64_t), CI_PAGE_SIZE),
                          OO_MMAP_FLAG_DEFAULT, &p);

    if( rc < 0 )
      LOG_NV(ci_log("%s: oo_resource_mmap ubuf post intf_i %d ix %d rc %d",
                    __FUNCTION__, intf_i, ix, rc));
    else
      efct_ubufs_set_rxq_io_window(vi, ix, (volatile uint64_t*)p);
  }

  return rc;
}

static void oo_efct_superbuf_post_ioctl(ef_vi* vi, int ix, int sbid,
                                        bool sentinel)
{
  oo_efct_superbuf_post_t op;
  op.intf_i = vi->efct_rxqs.ops->user_data;
  op.qid = ix;
  op.sbid = sbid;
  op.sentinel = sentinel;
  oo_resource_op(vi->dh, OO_IOC_EFCT_SUPERBUF_POST, &op);
  // TODO ON-16698 should we detect errors?
}

static void unmap_efct_ubuf_rxq_io_windows(ef_vi* vi)
{
  int ix;

  for( ix = 0; ix < vi->efct_rxqs.max_qs; ix++ ) {
    void* p = (void *)efct_ubufs_get_rxq_io_window(vi, ix);
    if( p != NULL ) {
      oo_resource_munmap(vi->dh, p, CI_ROUND_UP(sizeof(uint64_t), CI_PAGE_SIZE));
      efct_ubufs_set_rxq_io_window(vi, ix, NULL);
    }
  }
}

static int spawn_shrub_controller(ci_netif* ni)
{
  ci_fd_t fp = ci_netif_get_driver_handle(ni);
  shrub_ioctl_data_t shrub_args = {0};

  ci_assert(NI_OPTS(ni).shrub_controller_id >= 0);

  shrub_args.controller_id = NI_OPTS(ni).shrub_controller_id;
  shrub_args.debug = NI_OPTS(ni).shrub_debug;
  return oo_resource_op(fp, OO_IOC_SHRUB_SPAWN_SERVER, &shrub_args);
}

static int set_shrub_sockets(ci_netif* ni, int shrub_socket_id, uint32_t intf_i) {
  ci_fd_t fp = ci_netif_get_driver_handle(ni);
  shrub_socket_ioctl_data_t shrub_args = {0};

  ci_assert(NI_OPTS(ni).shrub_controller_id >= 0);
  ci_assert(shrub_socket_id >= 0);

  shrub_args.controller_id = NI_OPTS(ni).shrub_controller_id;
  shrub_args.intf_i = intf_i;
  shrub_args.shrub_socket_id = shrub_socket_id;
  return oo_resource_op(fp, OO_IOC_SHRUB_SET_SOCKETS, &shrub_args);
}

static int set_shrub_token(ci_netif *ni, int shrub_socket_id, uint32_t intf)
{
  ci_fd_t fp = ci_netif_get_driver_handle(ni);
  shrub_socket_ioctl_data_t shrub_args = {0};

  ci_assert(NI_OPTS(ni).shrub_controller_id >= 0);
  ci_assert(shrub_socket_id >= 0);

  shrub_args.controller_id = NI_OPTS(ni).shrub_controller_id;
  shrub_args.intf_i = intf;
  shrub_args.shrub_socket_id = shrub_socket_id;
  return oo_resource_op(fp, OO_IOC_SHRUB_SET_TOKEN, &shrub_args);
}

int oo_send_shrub_request(int controller_id,
                          shrub_controller_request_t *request) {
  int rc;
  ssize_t received_bytes;
  int client_fd;
  struct sockaddr_un addr;
  char socket_path[EF_SHRUB_NEGOTIATION_SOCKET_LEN];

  ci_assert(controller_id >= 0);

  rc = snprintf(socket_path, sizeof(socket_path), EF_SHRUB_CONTROLLER_PATH_FORMAT
                "%s", EF_SHRUB_SOCK_DIR_PATH, controller_id,
                EF_SHRUB_NEGOTIATION_SOCKET);
  if ( rc < 0 || rc >= sizeof(socket_path) )
    return -EINVAL;

  client_fd = ci_sys_socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if ( client_fd == -1 )
    return -errno;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

  rc = ci_sys_connect(client_fd, (struct sockaddr *)&addr, sizeof(addr));
  if ( rc < 0 ) {
    rc = -errno;
    goto clean_exit;
  }

  rc = ci_sys_send(client_fd, request, sizeof(*request), 0);
  if ( rc == -1 ) {
    rc = -errno;
    goto clean_exit;
  }

  received_bytes = ci_sys_recv(client_fd, &rc, sizeof(int), 0);
  if ( received_bytes == -1 ) {
    rc = -errno;
    goto clean_exit;
  } else if ( received_bytes != sizeof(int) ) {
    rc = -ENOMEM;
    goto clean_exit;
  }

clean_exit:
  ci_sys_close(client_fd);
  return rc;
}

static int oo_init_shrub(ci_netif* ni, ef_vi* vi, ci_hwport_id_t hw_port, int nic_i) {
  int rc = 0;
  int shrub_socket_id = -1;
  int i;
#ifndef __KERNEL__
  if ( NI_OPTS(ni).shrub_controller_id >= 0 ) {
      /* Try requesting first, as there might be an existing shrub controller.
       * There's no reliable way to detect whether there's a listening
       * controller already, so we try and connect, and if we fail, try
       * spawning one at that point. */
      shrub_socket_id = shrub_adapter_send_hwport(
        oo_send_shrub_request,
        NI_OPTS(ni).shrub_controller_id,
        hw_port,
        NI_OPTS(ni).shrub_buffer_count
      );

      /* No listening socket, try spawning */
      if( (shrub_socket_id == -ECONNREFUSED) ||
          (shrub_socket_id == -ENOENT) ) {
        LOG_NC(ci_log("%s: send to shrub failed, trying spawn", __func__));
        rc = spawn_shrub_controller(ni);
        if( rc < 0 )
          return rc;

        /* Now retry */
        for( i = 0; i < 200; i++ ) {
          shrub_socket_id = shrub_adapter_send_hwport(oo_send_shrub_request,
                                              NI_OPTS(ni).shrub_controller_id,
                                              hw_port,
                                              NI_OPTS(ni).shrub_buffer_count);
          if( (shrub_socket_id >= 0) ||
              ((shrub_socket_id != -ECONNREFUSED) &&
               (shrub_socket_id != -ENOENT)) )
            break;
          usleep(1000 * 10); /* 10ms */
        }
      }

      /* Failure at this point is now fatal */
      if ( shrub_socket_id < 0 ) {
        rc = shrub_socket_id;
        LOG_U(ci_log("%s: retry of send after spawn failed (rc %d), giving up",
                     __func__, rc));
        return rc;
      }

      rc = set_shrub_sockets(ni, shrub_socket_id, nic_i);
      if ( rc < 0 )
        return rc;

      efct_ubufs_set_shared(vi, NI_OPTS(ni).shrub_controller_id, rc);

      rc = set_shrub_token(ni, shrub_socket_id, nic_i);
      if (rc < 0)
        return rc;

      /* Nothing needs to be done with the userland vi, as filter insertion
       * only takes place in the kernel. */
    }
#endif
  return rc;
}

static int init_ef_vi(ci_netif* ni, int nic_i, int vi_state_offset,
                      int vi_io_offset, int vi_efct_shm_offset,
                      char** vi_mem_ptr,
                      ef_vi* vi, unsigned vi_instance,
                      int evq_bytes, int txq_size, ef_vi_stats* vi_stats,
                      struct efab_nic_design_parameters* dp, ci_hwport_id_t hw_port)
{
  ef_vi_state* state = (void*) ((char*) ni->state + vi_state_offset);
  ci_netif_state_nic_t* nsn = &(ni->state->nic[nic_i]);
  uint32_t* ids = (void*) (state + 1);
  unsigned vi_bar_off = vi_instance * 8192;
  int rc;

  rc = ef_vi_init(vi, ef_vi_arch_from_efhw_arch(nsn->vi_arch), nsn->vi_variant,
                  nsn->vi_revision, nsn->vi_flags, nsn->vi_nic_flags, state);
  ci_assert(rc == 0);
  ef_vi_init_out_flags(vi, nsn->vi_out_flags);
  vi_io_offset += vi_bar_off & (CI_PAGE_SIZE - 1);
  ef_vi_init_io(vi, ni->io_ptr + vi_io_offset);
  ef_vi_init_timer(vi, nsn->timer_quantum_ns);
  vi->vi_i = vi_instance;
  vi->dh = ci_netif_get_driver_handle(ni);
  *vi_mem_ptr = ef_vi_init_qs(vi, *vi_mem_ptr, ids, evq_bytes / 8,
                              nsn->vi_rxq_size, nsn->rx_prefix_len, txq_size);
  if( vi->internal_ops.design_parameters ) {
    rc = vi->internal_ops.design_parameters(vi, dp);
    if( rc < 0 )
      return rc;
  }
  if( vi->efct_rxqs.active_qs ) {
    rc = 0;
    if( nsn->vi_arch == EFHW_ARCH_EFCT ) {
      rc = efct_kbufs_init_internal(vi,
                        (void*)((char*)ni->efct_shm_ptr + vi_efct_shm_offset),
                        NULL);
      vi->efct_rxqs.ops->refresh = oo_efct_superbuf_config_refresh;
      vi->efct_rxqs.ops->user_data = nic_i;
    } else if( NI_OPTS(ni).multiarch_rx_datapath != EF_MULTIARCH_DATAPATH_FF &&
               nsn->vi_arch == EFHW_ARCH_EF10CT ) {
      rc = efct_ubufs_init_internal(vi);
      if( rc < 0 )
        return rc;

      rc = oo_init_shrub(ni, vi, hw_port, nic_i);
      if ( rc < 0 )
        return rc;

      if( ! (vi->vi_flags & EF_VI_RX_PHYS_ADDR) )
        vi->efct_rxqs.ops->post = oo_efct_superbuf_post_ioctl;

      vi->efct_rxqs.ops->refresh = oo_efct_superbuf_config_refresh;
      vi->efct_rxqs.ops->user_data = nic_i;
    }
    if( rc < 0 )
      return rc;
  }
  ef_vi_set_ts_format(vi, nsn->ts_format);
  ef_vi_init_rx_timestamping(vi, nsn->rx_ts_correction);
  ef_vi_init_tx_timestamping(vi, nsn->tx_ts_correction);
  ef_vi_add_queue(vi, vi);
  ef_vi_set_stats_buf(vi, vi_stats);
  if( ef_vi_receive_capacity(vi) > 0 )
    ef_vi_receive_set_discards(vi,
        EF_VI_DISCARD_RX_L4_CSUM_ERR |
        EF_VI_DISCARD_RX_L3_CSUM_ERR |
        EF_VI_DISCARD_RX_ETH_FCS_ERR |
        EF_VI_DISCARD_RX_ETH_LEN_ERR |
        EF_VI_DISCARD_RX_INNER_L3_CSUM_ERR |
        EF_VI_DISCARD_RX_INNER_L4_CSUM_ERR |
        EF_VI_DISCARD_RX_L2_CLASS_OTHER |
        EF_VI_DISCARD_RX_L3_CLASS_OTHER |
        EF_VI_DISCARD_RX_L4_CLASS_OTHER);
  return 0;
}


static void cleanup_ef_vi(ef_vi* vi)
{
  if( vi->efct_rxqs.ops ) {
    /* TODO: revisit once an API is formalised as part of ON-16320 */
    if ( vi->nic_type.arch == EFHW_ARCH_EF10CT ) {
      unmap_efct_ubuf_rxq_io_windows(vi);
    }
  }
}


static void cleanup_all_vis(ci_netif* ni)
{
  int nic_i;
  OO_STACK_FOR_EACH_INTF_I(ni, nic_i)
    cleanup_ef_vi(ci_netif_vi(ni, nic_i));
}


unsigned ci_netif_build_future_intf_mask(ci_netif* ni)
{
  int nic_i;
  unsigned mask = 0;

  OO_STACK_FOR_EACH_INTF_I(ni, nic_i) {
    /* Disable future when there's an XDP prog attached because that prog may
     * alter the destination socket, in which case the future code would be
     * wrong.  XDP-attachment implies poll_in_kernel, which is what we actually
     * check here. */
    ef_vi* vi = ci_netif_vi(ni, nic_i);
    if(
#ifdef OO_HAS_POLL_IN_KERNEL
       ! ni->nic_hw[nic_i].poll_in_kernel &&
#endif
        ef_vi_receive_capacity(vi) != 0 &&
        ~ef_vi_flags(vi) & EF_VI_RX_EVENT_MERGE &&
        vi->nic_type.arch != EF_VI_ARCH_EF100 &&
        /* TODO AF_XDP future detection is not currently supported */
        vi->nic_type.arch != EF_VI_ARCH_AF_XDP )
      mask |= 1u << nic_i;
  }
  return mask;
}

static int af_xdp_kick(ef_vi* vi)
{
  ci_netif* ni = vi->xdp_kick_context;
  ci_netif_nic_t* nic = CI_CONTAINER(ci_netif_nic_t, vi, vi);
  uint32_t intf_i = nic - ni->nic_hw;
  int fd = ci_netif_get_driver_handle(ni);

  return oo_resource_op(fd, OO_IOC_AF_XDP_KICK, &intf_i);
}

static int get_design_parameters(ci_netif* ni, int nic_i,
                                 struct efab_nic_design_parameters* dp)
{
  oo_design_parameters_t op;
  int fd = ci_netif_get_driver_handle(ni);

  op.intf_i = nic_i;
  CI_USER_PTR_SET(op.data_ptr, dp);
  op.data_len = sizeof(*dp);
  return oo_resource_op(fd, OO_IOC_DESIGN_PARAMETERS, &op);
}

static int netif_tcp_helper_build(ci_netif* ni)
{
  /* On entry we require the following to be initialised:
  **
  **   ni->state (for both user and kernel builds)
  **   ci_netif_get_driver_handle(ni), ni->tcp_mmap (for user builds only)
  */
  ci_netif_state* ns = ni->state;
  int rc, nic_i, size, expected_buf_ofs;
  unsigned vi_io_offset, vi_state_offset, vi_efct_shm_offset;
  char* vi_mem_ptr;
  int vi_state_bytes = 0;
#if CI_CFG_PIO
  unsigned pio_io_offset = 0, pio_buf_offset = 0, vi_bar_off;
#endif
#if CI_CFG_CTPIO
  unsigned ctpio_io_offset = 0;
#endif

  /****************************************************************************
   * Do other mmaps.
   */
  rc = netif_tcp_helper_mmap(ni);
  if( rc < 0 )
    goto fail1;

  /****************************************************************************
   * Breakout the VIs.
   */

  /* The array of nic_hw is potentially sparse, but the memory mapping is
  ** not, so we keep a count to calculate offsets rather than use
  ** nic_index.
  */
  vi_io_offset = 0;
  vi_efct_shm_offset = 0;
  vi_mem_ptr = ni->buf_ptr;
  vi_state_offset = sizeof(*ni->state);

  ni->future_intf_mask = 0;

  OO_STACK_FOR_EACH_INTF_I(ni, nic_i) {
    ci_netif_state_nic_t* nsn = &ns->nic[nic_i];
    ef_vi* vi = ci_netif_vi(ni, nic_i);
    struct efab_nic_design_parameters dp;
    int vi_nic_state_bytes;

    /* Get interface properties. */
    rc = oo_cp_get_hwport_properties(ni->cplane, ns->intf_i_to_hwport[nic_i],
                                     NULL, NULL, NULL);
    if( rc < 0 )
      goto fail1;

    LOG_NV(ci_log("%s: ni->io_ptr=%p io_offset=%d mem_ptr=%p "
                  "state_offset=%d", __FUNCTION__, ni->io_ptr,
                  vi_io_offset, vi_mem_ptr, vi_state_offset));

    ci_assert(((vi_mem_ptr - ni->buf_ptr) & (CI_PAGE_SIZE - 1)) == 0);

    rc = ef_vi_arch_from_efhw_arch(nsn->vi_arch);
    CI_TEST(rc >= 0);

    rc = get_design_parameters(ni, nic_i, &dp);
    if( rc < 0 )
      goto fail1;

    rc = init_ef_vi(ni, nic_i, vi_state_offset, vi_io_offset,
                    vi_efct_shm_offset,
                    &vi_mem_ptr, vi, nsn->vi_instance,
                    nsn->vi_evq_bytes, nsn->vi_txq_size,
                    &ni->state->vi_stats, &dp, ns->intf_i_to_hwport[nic_i]);
    if( rc )
      goto fail2;
    if( NI_OPTS(ni).tx_push )
      ef_vi_set_tx_push_threshold(vi, NI_OPTS(ni).tx_push_thresh);

    vi_nic_state_bytes = ef_vi_calc_state_bytes(nsn->vi_rxq_size,
                                                nsn->vi_txq_size);
    vi_io_offset += nsn->vi_io_mmap_bytes;
    vi_efct_shm_offset += nsn->vi_efct_shm_mmap_bytes;
    vi_state_offset += vi_nic_state_bytes;

    vi->xdp_kick = af_xdp_kick;
    vi->xdp_kick_context = ni;

    vi_state_bytes += vi_nic_state_bytes;

#if CI_CFG_PIO
    if( NI_OPTS(ni).pio &&
        (ns->nic[nic_i].oo_vi_flags & OO_VI_FLAGS_PIO_EN) ) {
      /* There should be a mapping for this NIC */
      ci_assert(nsn->pio_io_mmap_bytes != 0);
      /* There should be some left in the all-NICs count */
      ci_assert_lt(pio_io_offset, ns->pio_mmap_bytes);
      /* The length for this NIC is smaller than the mapping for this NIC */
      ci_assert_le(nsn->pio_io_len, nsn->pio_io_mmap_bytes);
      /* Although the PIO regions are each in their own page, we have a
       * dense mapping for the host memory copy, starting at pio_bufs_ofs
       */
      ni->nic_hw[nic_i].pio.pio_buffer = (uint8_t*)ns + ns->pio_bufs_ofs + 
        pio_buf_offset;
      pio_buf_offset += nsn->pio_io_len;
      /* And set up rest of PIO struct so we can call ef_vi_pio_memcpy */
      vi_bar_off = nsn->vi_instance * 8192;
      ni->nic_hw[nic_i].pio.pio_io = ni->pio_ptr + pio_io_offset;
      ni->nic_hw[nic_i].pio.pio_io += (vi_bar_off + 4096) & (CI_PAGE_SIZE - 1);
      ni->nic_hw[nic_i].pio.pio_len = nsn->pio_io_len;
      vi->linked_pio = &ni->nic_hw[nic_i].pio;
      pio_io_offset += nsn->pio_io_mmap_bytes;
    }
#endif
#if CI_CFG_CTPIO
    if( vi->vi_flags & EF_VI_TX_CTPIO ) {
      void* ctpio_ptr = ni->ctpio_ptr + ctpio_io_offset;
      ci_assert_lt(ctpio_io_offset, ns->ctpio_mmap_bytes);
      vi->vi_ctpio_mmap_ptr = ctpio_ptr;
      ctpio_io_offset += CI_PAGE_SIZE;
      ef_vi_ctpio_init(vi);
    }
#endif
#ifdef OO_HAS_POLL_IN_KERNEL
    ni->nic_hw[nic_i].poll_in_kernel = NI_OPTS(ni).poll_in_kernel;
#endif
  }
  ni->future_intf_mask = ci_netif_build_future_intf_mask(ni);

  ci_assert_equal(vi_state_bytes, ns->vi_state_bytes);

#if CI_CFG_CTPIO
  ci_assert_equal(ctpio_io_offset, ns->ctpio_mmap_bytes);
#endif

  /* Set up ni->packets->sets_max */
  netif_tcp_helper_build2(ni);
  ni->pkt_bufs = CI_ALLOC_ARRAY(char*, ni->packets->sets_max);
  if( ni->pkt_bufs == NULL ) {
    rc = -ENOMEM;
    goto fail2;
  }
  CI_ZERO_ARRAY(ni->pkt_bufs, ni->packets->sets_max);

  /* sets_max may be smaller than the space the kernel reserved for
   * the array (if we have had trouble allocating packet buffers), so
   * we need to be aware of that when checking the sizes are sane
   */
  size = ns->dma_ofs - ns->buf_ofs - sizeof(oo_pktbuf_manager);

  expected_buf_ofs = sizeof(ci_netif_state);
  expected_buf_ofs = CI_ROUND_UP(expected_buf_ofs, __alignof__(ef_vi_state));
  expected_buf_ofs += vi_state_bytes;
  expected_buf_ofs = CI_ROUND_UP(expected_buf_ofs,
                                 __alignof__(oo_pktbuf_manager));
  if( ns->buf_ofs != expected_buf_ofs ||
      ni->packets->sets_max < 1 || 
      size / sizeof(oo_pktbuf_set) < ni->packets->sets_max ) {
    /* This typically happens if someone puts a variable width type such as
     * long in ci_netif_state_s, and a 32 bit user level library is used
     * with a 64 bit driver.  (Or if user and kernel get out of sync).
     */
    /* Omitted check that size % sizeof(oo_pktbuf_set) == 0 because the
     * padding to nearest cache line makes it not necessarily true */
    ci_log("%d %d %d", ns->buf_ofs != sizeof(ci_netif_state) +
      vi_state_bytes,
      ni->packets->sets_max < 1,
      size / sizeof(oo_pktbuf_set) < ni->packets->sets_max);
    ci_log("ERROR: data structure layout mismatch between kernel and "
           "user level detected!");
    ci_log("ns->buf_ofs=%d (expected %d)", ns->buf_ofs, expected_buf_ofs);
    ci_log("  sizeof(ci_netif_state) = %zd", sizeof(ci_netif_state));
    ci_log("  alignof(ef_vi_state) = %zd", __alignof__(ef_vi_state));
    ci_log("  vi_state_bytes = %d", vi_state_bytes);
    ci_log("  stack_intf_max = %d", oo_stack_intf_max(ni));
    ci_log("  alignof(oo_pktbuf_manager) = %zd",
           __alignof__(oo_pktbuf_manager));
    ci_log("oo_pktbuf_set=%zd, size=%d, sets_max=%d", 
           sizeof(oo_pktbuf_set), size, ni->packets->sets_max);
    ci_log("a: %zd != 0", size % sizeof(oo_pktbuf_set));
    ci_log("b: 1 <= %zd <= %d ", size / sizeof(oo_pktbuf_set), 
           ni->packets->sets_max);
    rc = -EINVAL;
    goto fail3;
  }

  ni->eps = CI_ALLOC_ARRAY(typeof(*ni->eps), ni->state->max_ep_bufs);
  if( ni->eps == NULL ) {
    rc = -ENOMEM;
    goto fail3;
  }
  {
    int i;
    struct ci_extra_ep ref = { CI_FD_BAD };
    for( i = 0; i < ni->state->max_ep_bufs; ++ i )
      ni->eps[i] = ref;
  }

  /* For diagnostic purposes, mark the stack as lacking a mapping of init_net's
   * cplane if such is the case.  We couldn't set this flag in ci_netif_init()
   * when the failure happened, as we didn't have access to the shared state at
   * that point.  We set the flag even if we decided in the first place that we
   * didn't need init_net's cplane.*/
  if( ni->cplane_init_net == NULL )
    ns->flags |= CI_NETIF_FLAG_NO_INIT_NET_CPLANE;

  return 0;

fail3:
  CI_FREE_OBJ(ni->pkt_bufs);
fail2:
  cleanup_all_vis(ni);
fail1:
  return rc;
}

#endif



#ifndef __KERNEL__

static int
netif_tcp_helper_restore(ci_netif* ni, unsigned netif_mmap_bytes)
{
  void* p;
  int rc;

  rc = oo_resource_mmap(ci_netif_get_driver_handle(ni),
                        OO_MMAP_TYPE_NETIF,
                        CI_NETIF_MMAP_ID_STATE, netif_mmap_bytes,
                        OO_MMAP_FLAG_DEFAULT, &p);
  if( rc < 0 ) {
    LOG_NV(ci_log("netif_tcp_helper_restore: oo_resource_mmap %d", rc));
    return rc;
  }
  ni->state = (ci_netif_state*) p;
  ni->mmap_bytes = netif_mmap_bytes;

  rc = netif_tcp_helper_build(ni);
  if( rc < 0 ) {
    ci_log("%s: netif_tcp_helper_build %d", __FUNCTION__, rc);
    oo_resource_munmap(ci_netif_get_driver_handle(ni),
                       ni->state, netif_mmap_bytes);
    return rc;
  }

  return rc;
}

static void ci_netif_deinit(ci_netif* ni);


ci_inline void netif_tcp_helper_free(ci_netif* ni)
{
  if( ni->state != NULL ) {
    cleanup_all_vis(ni);
    netif_tcp_helper_munmap(ni);
  }
  if( ni->eps != NULL )
    CI_FREE_OBJ(ni->eps);
  if( ni->pkt_bufs != NULL )
    CI_FREE_OBJ(ni->pkt_bufs);
  ci_netif_deinit(ni);
}

static void init_resource_alloc(ci_resource_onload_alloc_t* ra,
                                const ci_netif_config_opts* opts,
                                unsigned flags, const char* name)
{
  memset(ra, 0, sizeof(*ra));
  CI_USER_PTR_SET(ra->in_opts, opts);
  ra->in_flags = (ci_uint16) flags;
  /* No need to NULL terminate these -- driver must assume they're not in
   * any case.
   */
  strncpy(ra->in_version, onload_short_version, sizeof(ra->in_version));
  strncpy(ra->in_uk_intf_ver, OO_UK_INTF_VER, sizeof(ra->in_uk_intf_ver));
  if( flags & CI_NETIF_FLAG_DO_ALLOCATE_SCALABLE_FILTERS_RSS ) {
    ra->in_cluster_size = CITP_OPTS.cluster_size;
    ra->in_cluster_restart = CITP_OPTS.cluster_restart_opt;
    strncpy(ra->in_name, CITP_OPTS.cluster_name, CI_CFG_STACK_NAME_LEN);
  }
  else
  if( name != NULL )
    strncpy(ra->in_name, name, CI_CFG_STACK_NAME_LEN);

  ra->in_efct_memfd = -1;
  ra->in_pktbuf_memfd = -1;

  /* The kernel code can cope with no memfd being provided in both cases
   * (in_efct_memfd and in_pktbuf_memfd), but only on older kernels, i.e.
   * older than 5.7 where the fallback with efrm_find_ksym() stopped working.
   * Overall:
   * - Onload uses the efrm_find_ksym() fallback on Linux older than 4.14.
   * - Both efrm_find_ksym() and memfd_create(MFD_HUGETLB) are available
   *   on Linux between 4.14 and 5.7.
   * - Onload can use only memfd_create(MFD_HUGETLB) on Linux 5.7+. */
  {
    char mfd_name[CI_CFG_STACK_NAME_LEN + 8];
    snprintf(mfd_name, sizeof(mfd_name), "efct/%s", name);
    ra->in_efct_memfd = syscall(__NR_memfd_create, mfd_name,
                                MFD_CLOEXEC | MFD_HUGETLB | MFD_HUGE_2MB);
    if( ra->in_efct_memfd < 0 && errno != ENOSYS )
      LOG_S(ci_log("%s: memfd_create failed %d", __FUNCTION__, errno));
  }
  /* Packet buffers */
  {
    char mfd_name[CI_CFG_STACK_NAME_LEN + 8];
    snprintf(mfd_name, sizeof(mfd_name), "pktbuf/%s", name);
    ra->in_pktbuf_memfd = syscall(__NR_memfd_create, mfd_name,
                                  MFD_CLOEXEC | MFD_HUGETLB | MFD_HUGE_2MB);
    if( ra->in_pktbuf_memfd < 0 && errno != ENOSYS )
      LOG_S(ci_log("%s: memfd_create failed %d", __FUNCTION__, errno));
  }
}


static int
netif_tcp_helper_alloc_u(ef_driver_handle fd, ci_netif* ni,
                         const ci_netif_config_opts* opts, unsigned flags,
                         const char* stack_name)
{
  ci_resource_onload_alloc_t ra;
  int rc;
  ci_netif_state* ns;
  void* p;

  /****************************************************************************
   * Allocate the TCP Helper resource.
   */
  init_resource_alloc(&ra, opts, flags, stack_name);

  /* oo_resource_alloc's ioctl does an interruptible sleep while waiting for
   * the cplane. If a non-fatal signal is received while we're asleep,
   * we get an EINTR and want to try again. */
  while( (rc = oo_resource_alloc(fd, &ra)) == -EINTR );

  if( ra.in_efct_memfd >= 0 )
    my_syscall3(close, ra.in_efct_memfd, 0, 0);

  if( ra.in_pktbuf_memfd >= 0 )
    my_syscall3(close, ra.in_pktbuf_memfd, 0, 0);

  if( rc < 0 ) {
    switch( rc ) {
    case -ELIBACC: {
      static int once;
      if( ! once ) {
        once = 1;
        ci_log("ERROR: Driver/Library version mismatch detected.");
        ci_log("This application will not be accelerated.");
        ci_log("HINT: Most likely you need to reload the sfc and onload "
               "drivers");
      }
      break;
    }
    case -EEXIST:
      /* This is not really an error.  It means we "raced" with another thread
       * to create a stack with this name, and the other guy won the race.  We
       * return the error code and further up the call-chain we'll retry to
       * attach to the stack with the given name.
       */
      break;
    case -ENODEV:
      LOG_E(ci_log("%s: ENODEV.\n"
"This error can occur if:\n"
" - no Solarflare network interfaces are active/UP, or they are running\n"
"   packed stream firmware or are disabled, and\n"
" - there are no AF_XDP interfaces registered with sfc_resource\n"
"Please check your configuration.",
                   __FUNCTION__));
      break;
    default:
      LOG_E(ci_log("%s: ERROR: Failed to allocate stack (rc=%d)\n"
                   "See kernel messages in dmesg or /var/log/syslog "
                   "for more details of this failure",
                   __FUNCTION__, rc));
      break;
    }
    return rc;
  }

  /****************************************************************************
   * Perform post-alloc driver setup.
   */
  ni->nic_set = ra.out_nic_set;
  LOG_NC(ci_log("%s: nic set %" EFRM_NIC_SET_FMT, __FUNCTION__,
                efrm_nic_set_pri_arg(&ni->nic_set)));
  ni->mmap_bytes = ra.out_netif_mmap_bytes;

  /****************************************************************************
   * Set up the mem mmaping.
   */
  rc = oo_resource_mmap(fd, OO_MMAP_TYPE_NETIF, CI_NETIF_MMAP_ID_STATE,
                        ra.out_netif_mmap_bytes, OO_MMAP_FLAG_DEFAULT, &p);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: oo_resource_mmap %d", __FUNCTION__, rc));
    return rc;
  }

  ns = ni->state = (ci_netif_state*) p;
  ci_assert_equal(ra.out_netif_mmap_bytes, ns->netif_mmap_bytes);

  /****************************************************************************
   * Final Debug consistency check
   */
  if( !!(ns->flags & CI_NETIF_FLAG_DEBUG) != CI_DEBUG(1+)0 ) {
    ci_log("ERROR: Driver/Library debug build mismatch detected (%d,%d)",
           !!(ns->flags & CI_NETIF_FLAG_DEBUG), CI_DEBUG(1+)0 );
    rc = -ELIBACC;
    goto fail;
  }

  /****************************************************************************
   * Construct / attach to resources which are described in the shared state
   */
  rc = netif_tcp_helper_build(ni);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: netif_tcp_helper_build failed rc=%d", __FUNCTION__, rc));
    goto fail;
  }

  return 0;

fail:
  netif_tcp_helper_munmap(ni);
  return rc;
}

#endif


/*****************************************************************************
 *                                                                           *
 *          Netif Creation and Destruction                                   *
 *          ==============================                                   *
 *                                                                           *
 *****************************************************************************/

#ifndef __KERNEL__

static void ci_netif_sanity_checks(void)
{
  /* These had better be true, or there'll be trouble! */
  CI_BUILD_ASSERT( sizeof(citp_waitable_obj) <= CI_PAGE_SIZE );
  CI_BUILD_ASSERT( sizeof(citp_waitable_obj) <= EP_BUF_SIZE );
  CI_BUILD_ASSERT( EP_BUF_SIZE * EP_BUF_PER_PAGE == CI_PAGE_SIZE );
  CI_BUILD_ASSERT( (1u << CI_SB_FLAG_WAKE_RX_B) == CI_SB_FLAG_WAKE_RX );
  CI_BUILD_ASSERT( (1u << CI_SB_FLAG_WAKE_TX_B) == CI_SB_FLAG_WAKE_TX );
  CI_BUILD_ASSERT( sizeof(ci_ni_aux_mem) == CI_AUX_MEM_SIZE );

  /* AUX_PER_BUF aux buffers + header = ep buffer, where header is
   * oo_ep_header and fits in exactly one cache line. */
  CI_BUILD_ASSERT( sizeof(struct oo_ep_header) <= CI_AUX_HEADER_SIZE );
  CI_BUILD_ASSERT( CI_AUX_MEM_SIZE * AUX_PER_BUF + CI_AUX_HEADER_SIZE
                   <= EP_BUF_SIZE );
  /* This constraint isn't strictly necessary for functionality, but it makes
   * debugging/dumping saner */
  CI_BUILD_ASSERT( offsetof(citp_waitable, sb_aflags) +
                      sizeof(((citp_waitable*)0)->sb_aflags)
                   <= CI_AUX_HEADER_SIZE );

#ifndef NDEBUG
  {
    int i = CI_MEMBER_OFFSET(ci_ip_cached_hdrs, ipx.ip4);
    int e = CI_MEMBER_OFFSET(ci_ip_cached_hdrs, ether_header);
    int h = CI_MEMBER_OFFSET(ci_ip_cached_hdrs, hwport);
    ci_assert_equal(i - e, ETH_HLEN + 4);
    ci_assert_equal(i - h, ETH_HLEN + 4 + 2);
  }
#endif

  /* Warn if we're wasting memory. */
  if( sizeof(citp_waitable_obj) * 2 <= EP_BUF_SIZE )
    ci_log("%s: EP_BUF_SIZE=%d larger than necessary (citp_waitable_obj=%zu)",
           __FUNCTION__, EP_BUF_SIZE, sizeof(citp_waitable_obj));
}
#endif


static int ci_netif_pkt_reserve(ci_netif* ni, int n_requested,
                                int* n_reserved, oo_pkt_p* p_pkt_list)
{
  ci_ip_pkt_fmt* pkt = NULL;
  int i;

  for( i = 0; i < n_requested; ++i ) {
    pkt = ci_netif_pkt_alloc_ptrerr(ni, 0);
    if( IS_ERR(pkt) )
      break;
    *p_pkt_list = OO_PKT_P(pkt);
    p_pkt_list = &pkt->next;
  }
  *p_pkt_list = OO_PP_NULL;
  *n_reserved = i;
  return PTR_ERR_OR_ZERO(pkt);
}


static void ci_netif_pkt_reserve_free(ci_netif* ni, oo_pkt_p pkt_list, int n)
{
  ci_ip_pkt_fmt* pkt;
  while( OO_PP_NOT_NULL(pkt_list) ) {
    CI_DEBUG(--n);
    pkt = PKT_CHK(ni, pkt_list);
    pkt_list = pkt->next;
    ci_netif_pkt_release(ni, pkt);
  }

  ci_assert_equal(n, 0);
  ci_assert(OO_PP_IS_NULL(pkt_list));
}


#ifndef __KERNEL__

static int ci_netif_pkt_prefault(ci_netif* ni)
{
  /* Touch all allocated packet buffers so we don't incur the cost of
   * faulting them info this address space later.
   *
   * The return value is not useful, and only exists to prevent
   * optimisations that would render this function useless.  This is also
   * the reason the function is not static.
   *
   * Similarly, the cast into volatile is designed to prevent compiler
   * optimisations.
   */
  ci_ip_pkt_fmt* pkt;
  int i, n;
  int rc = 0;

  if( NI_OPTS(ni).prefault_packets ) {
    n = ni->packets->n_pkts_allocated;
    for( i = 0; i < n; ++i ) {
      pkt = PKT(ni, i);
      rc += *(volatile ci_int32*)(&pkt->refcount);
    }
  }
  return rc;
}


static void ci_netif_pkt_prefault_reserve(ci_netif* ni)
{
  oo_pkt_p pkt_list;
  int n;
  int actual_max_packets = ni->packets->sets_max * PKTS_PER_SET;
  /* The maximum number of packet buffers we can have is subject to rounding
   * due to packet set size. Conservative approach is to use max of this and
   * configured EF_MAX_PACKETS - ensures we will always max out the buffers
   * when EF_PREFAULT_PACKETS is bigger than both.
   */
  int target_allocated = CI_MIN( NI_OPTS(ni).prefault_packets,
                                 CI_MAX(NI_OPTS(ni).max_packets,
                                        actual_max_packets) );
  int already_reserved = (ni->packets->n_pkts_allocated - ni->packets->n_free);

  if( ! NI_OPTS(ni).prefault_packets )
    return;

  ci_netif_lock(ni);
  /* Try to reserve enough so that total allocation reaches target level */
  ci_netif_pkt_reserve(ni, target_allocated - already_reserved, &n, &pkt_list);
  if( ni->packets->n_pkts_allocated < target_allocated )
    LOG_E(ci_log("%s: Prefaulting only allocated %d of %d (reserved +%d)",
                 __FUNCTION__,
                 ni->packets->n_pkts_allocated,
                 target_allocated,
                 n));
  ci_netif_pkt_reserve_free(ni, pkt_list, n);
  ci_netif_unlock(ni);
}


void ci_netif_cluster_prefault(ci_netif* ni)
{
  if( ni->flags & CI_NETIF_FLAGS_PREFAULTED )
    return;
  ci_netif_pkt_prefault_reserve(ni);
  ci_netif_pkt_prefault(ni);

  /* Fixme: in theory, we should protect the flag change with the stack
   * lock. */
  ni->flags |= CI_NETIF_FLAGS_PREFAULTED;
}

static int ci_netif_init(ci_netif* ni, ef_driver_handle fd)
{
  int rc;
  ef_driver_handle init_net_fd;

  ni->driver_handle = fd;
  CI_MAGIC_SET(ni, NETIF_MAGIC);
  ni->flags = 0;
  ni->error_flags = 0;
  ni->cplane_init_net = NULL;

  ni->cplane = malloc(sizeof(struct oo_cplane_handle));
  if( ni->cplane == NULL )
    return -ENOMEM;

  rc = oo_cp_create(fd, ni->cplane, CITP_OPTS.sync_cplane, 0);
  if( rc != 0 ) {
    ci_log("%s: failed to get local control plane handle: %d", __func__, rc);
    goto fail;
  }

  /* If we need veth acceleration, map in the control plane for the main
   * namespace. */
  rc = oo_resource_op(fd, OO_IOC_VETH_ACCELERATION_ENABLED, NULL);
  if( rc > 0 ) {
    ni->cplane_init_net = malloc(sizeof(struct oo_cplane_handle));
    if( ni->cplane_init_net == NULL )
      goto fail;

    rc = ef_onload_driver_open(&init_net_fd, OO_STACK_DEV, 1);
    if( rc != 0 ) {
      ci_log("%s: failed to open driver handle: %d", __func__, rc);
    }
    else {
      rc = oo_cp_create(init_net_fd, ni->cplane_init_net,
                        CITP_OPTS.sync_cplane, CP_CREATE_FLAGS_INIT_NET);
      if( rc != 0 ) {
        ci_log("%s: failed to get init_net control plane handle: %d", __func__,
               rc);
        ef_onload_driver_close(init_net_fd);
      }
    }

    if( rc != 0 ) {
      /* We can tolerate failure to map init_net's control plane. */
      ci_log("%s: support for containers will be limited", __func__);
      free(ni->cplane_init_net);
      ni->cplane_init_net = NULL;
    }
  }

  return 0;

 fail:
  free(ni->cplane);
  return rc;
}

static void ci_netif_deinit(ci_netif* ni)
{
  if( ni->cplane_init_net != NULL ) {
    oo_cp_destroy(ni->cplane_init_net);
    ef_onload_driver_close(ni->cplane_init_net->fd);
    free(ni->cplane_init_net);
  }

  /* The local cplane handle uses the stack's fd, so we don't need to close
   * that fd now. */
  oo_cp_destroy(ni->cplane);
  free(ni->cplane);
}

#if CI_CFG_UL_INTERRUPT_HELPER
#include <sys/wait.h>
#include <ci/internal/syscall.h>

#define ONLOAD_HELPER_NAME "onload_helper"

/* Run this in the second-level cloned process: exec */
static void ci_netif_start_helper2(ci_netif* ni) __attribute__((noreturn));
static void ci_netif_start_helper2(ci_netif* ni)
{
  char* argv[5];
  char stack_id_str[strlen(OO_STRINGIFY(INT_MAX)) + 1];
  int rc;

  argv[0] = ONLOAD_HELPER_NAME;
  argv[1] = "-s";
  snprintf(stack_id_str, sizeof(stack_id_str), "%d", NI_ID(ni));
  argv[2] = stack_id_str;
  argv[3] = NULL;
  if( CITP_OPTS.log_via_ioctl ) {
    argv[3] = "-K";
    argv[4] = NULL;
  }

  rc = ci_sys_execvpe(ONLOAD_HELPER_NAME, argv, NULL);
  ci_assert_lt(rc, 0);
  (void)rc; /* appease gcc in NDEBUG build */
  ci_log("spawning "ONLOAD_HELPER_NAME" for [%s]: execve() failed: %s",
         ni->state->pretty_name, strerror(errno));
  _exit(4);
}

/* Run this in the first-level cloned process: fork and exit.
 * We should not exec here, because execve() overwrites exit_signal. */
static void ci_netif_start_helper1(ci_netif* ni) __attribute__((noreturn));
static void ci_netif_start_helper1(ci_netif* ni)
{
  int i;
  sigset_t sigset;
  int rc;
  int wstatus;

  /* The first part of "man 7 daemon": */

  /* Reset all signal handlers. */
  for( i = 0; i < _NSIG; ++i )
    signal(i, SIG_DFL);

  /* Unblock all signals. */
  sigfillset(&sigset);
  sigprocmask(SIG_UNBLOCK, &sigset, NULL);

  /* Get a new session. */
  rc = setsid();
  if( rc == -1 ) {
    ci_log("spawning "ONLOAD_HELPER_NAME" for [%s]: setsid() failed: %s",
           ni->state->pretty_name, strerror(errno));
    _exit(1);
  }

  umask(0);
  rc = chdir("/");
  if( rc == -1 ) {
    ci_log("spawning "ONLOAD_HELPER_NAME" for [%s]: chdir(/) failed: %s",
           ni->state->pretty_name, strerror(errno));
    _exit(1);
  }
  /* The second part of "man 7 daemon" is in onload_helper itself. */

  /* Flags:
   * CLONE_FILES: execve() unshares files so it is overridden later
   * CLONE_VFORK: stop parent until the child exits or execs.
   *
   * NB: CLONE_VFORK != vfork(); vfork uses CLONE_VFORK | CLONE_VM,
   * and CLONE_VM is really scary.  All the danderous things in man vfork
   * come from CLONE_VM.
   */
  rc = my_do_syscall3(__NR_clone, CLONE_FILES | CLONE_VFORK | SIGCHLD,
                      0, 0);
  if( rc == 0 )
    ci_netif_start_helper2(ni);

  if( rc < 0 ) {
    ci_log("spawning "ONLOAD_HELPER_NAME" for [%s]: "
           "second clone() failed %s",
           ni->state->pretty_name, strerror(errno));
    _exit(2);
  }

  ci_assert_nequal(rc, 0);
  waitpid(rc, &wstatus, 0);
  if( WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0 )
    _exit(0);

  /* Error message was printed by the child process */
  _exit(3);
}

static int ci_netif_start_helper(ci_netif* ni)
{
  int rc;
  int wstatus;

  /* See ci_netif_start_helper1() above for comments about the CLONE_*
   * flags.  We do not specify any signal, because we do not want the user
   * application to be signalled.
   */
  rc = my_do_syscall3(__NR_clone, CLONE_FILES | CLONE_VFORK, 0, 0);
  if( rc == 0 )
    ci_netif_start_helper1(ni);

  if( rc < 0 ) {
    ci_log("spawning "ONLOAD_HELPER_NAME" for [%s]: "
           "first clone() failed %s",
           ni->state->pretty_name, strerror(errno));
    _exit(1);
  }

  rc = waitpid(rc, &wstatus, __WCLONE);
  if( WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0 )
    return 0;

  LOG_S(ci_log("%s: spawning "ONLOAD_HELPER_NAME" for [%s]: exit status=%d",
               __func__, ni->state->pretty_name, wstatus));
  return -1;
}
#endif

int ci_netif_ctor(ci_netif* ni, ef_driver_handle fd, const char* stack_name,
                  unsigned flags)
{
  ci_netif_config_opts* opts;
  struct oo_per_thread* per_thread;
  int rc;

  per_thread = oo_per_thread_get();
  opts = per_thread->thread_local_netif_opts != NULL?
    per_thread->thread_local_netif_opts:
    &ci_cfg_opts.netif_opts;

  ci_assert(ni);
  ci_netif_sanity_checks();

  rc = ci_netif_init(ni, fd);
  if( rc < 0 )
    return rc;

  /***************************************
  * Allocate kernel helper and link into netif
  */
  if( (rc = netif_tcp_helper_alloc_u(fd, ni, opts, flags, stack_name)) < 0 ) {
    ci_netif_deinit(ni);
    return rc;
  }

#if CI_CFG_UL_INTERRUPT_HELPER
  rc = ci_netif_start_helper(ni);
  if( rc != 0 ) {
    /* The stack was fully initialised, so we have to call dtor() for full
     * destroy now. */
    ci_netif_dtor(ni);
    return rc;
  }

#endif

  ci_netif_pkt_prefault_reserve(ni);
  ci_netif_pkt_prefault(ni);

  ci_netif_log_startup_banner(ni, "Using");

  return 0;
}

#endif  /* __KERNEL__ */

int ci_netif_set_rxq_limit(ci_netif* ni)
{
  int intf_i, n_intf, max_ring_pkts, fill_limit;
  int rc = 0, rxq_cap = 0;
  int rxq_limit = NI_OPTS(ni).rxq_limit;

  /* Ensure we use a sensible [rxq_limit] when packet buf constrained.
   * This is necessary to ensure that the first interface doesn't fill its
   * RX ring at the expense of the last.
   */
  n_intf = 0;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    ef_vi* vi = ci_netif_vi(ni, intf_i);
    int vi_rxq_cap = ef_vi_receive_capacity(vi);

    /* Some interfaces do not receive packets.  We remove them from
     * the new RX limit calculations. */
    if( ! vi_rxq_cap )
      continue;

    /* Otherwise, operate on the assumption that all other interfaces
     * have identical receive capacity. */
    rxq_cap = vi_rxq_cap;
    ++n_intf;
  }
  /* We allow up to 80% of the total RX packet buf allocation to go in the
   * rings.  If we let the full allocation go in the rings it can be
   * impossible to get out of OO_MEM_PRESSURE_CRITICAL, due to rounding
   * effects.
   */
  max_ring_pkts = NI_OPTS(ni).max_rx_packets * 4 / 5;
  fill_limit = rxq_cap;
  if( fill_limit * n_intf > max_ring_pkts )
    fill_limit = max_ring_pkts / n_intf;
  if( fill_limit < rxq_limit ) {
    if( fill_limit < rxq_cap )
      LOG_W(ci_log("WARNING: "N_FMT "RX ring fill level reduced from %d to %d "
                   "max_ring_pkts=%d rxq_cap=%d n_intf=%d",
                   N_PRI_ARGS(ni), rxq_limit, fill_limit,
                   max_ring_pkts, rxq_cap, n_intf));
    rxq_limit = fill_limit;
  }
  if( ni->nic_n == 0 ) {
    /* we do not use .rxq_limit, but let's make all checkers happy */
     rxq_limit = CI_CFG_RX_DESC_BATCH;
  }
  else if( rxq_limit < NI_OPTS(ni).rxq_min ) {
    /* Do not allow user to create a stack that is too severely
     * constrained.
     */
    LOG_E(ci_log("ERROR: "N_FMT "rxq_limit=%d is too small (rxq_min=%d)",
                 N_PRI_ARGS(ni), rxq_limit, NI_OPTS(ni).rxq_min);
          ci_log("HINT: Use a larger value for EF_RXQ_LIMIT or "
                 "EF_MAX_RX_PACKETS or EF_MAX_PACKETS"));
    rc = -ENOMEM;
    /* NB. This isn't just called at init time -- it is also called after
     * failure to allocate more packet buffers.  So we must leave
     * [rxq_limit] with a legal value.
     */
    rxq_limit = 2 * CI_CFG_RX_DESC_BATCH + 1;
  }
  ni->state->rxq_limit = ni->state->rxq_base_limit = rxq_limit;
  return rc;
}

#ifdef __KERNEL__
static void ci_netif_af_xdp_post_fill(ci_netif* ni)
{
  /* some ZC UMEM implementation can take a jiffy to schedule HW rx ring refill */
  /* FIXME AF_XDP: fill umem rings before binding to umem */
  if( ni->flags & CI_NETIF_FLAG_AF_XDP )
    usleep_range(TICK_USEC * 2, TICK_USEC * 3);
}

static int __ci_netif_init_fill_rx_rings(ci_netif* ni)
{
  /* Saving rxq_limit as it may get modified during call to
   * ci_netif_rx_post().
   */
  int intf_i, rxq_limit = ni->state->rxq_limit;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    ef_vi* vi = ci_netif_vi(ni, intf_i);
    /* No RXQ or it's already full */
    if( ci_netif_rx_vi_space(ni, vi) < CI_CFG_RX_DESC_BATCH )
      continue;
    ci_netif_rx_post(ni, intf_i);
    if( ef_vi_receive_fill_level(vi) < rxq_limit )
      return -ENOMEM;
  }
  return 0;
}


int ci_netif_init_fill_rx_rings(ci_netif* ni)
{
  oo_pkt_p pkt_list;
  int lim, rc, n_reserved, n_requested, n_accounted;

  /* This could legitimately fail for AF_XDP, having already allocated all
   * available buffers earlier in the initialisation process. So we check
   * whether there has been a successful allocation at some point, rather than
   * whether this particular attempt succeeds. */
  rc = ci_tcp_helper_more_bufs(ni);
  if( ni->packets->n_free == 0 ) {
    if( rc != -EINTR )
      LOG_E(ci_log("%s: [%d] ERROR: failed to allocate initial packet set: %d",
                   __func__, NI_ID(ni), rc));
    return rc < 0 ? rc : -ENOMEM;
  }
  ni->packets->id = 0;

  ci_netif_mem_pressure_pkt_pool_fill(ni);
  if( (rc = ci_netif_set_rxq_limit(ni)) < 0 )
    return rc;

  /* Reserve some packet buffers for the free pool. */
  if( NI_OPTS(ni).prealloc_packets )
    n_requested = NI_OPTS(ni).max_packets;
  else
    n_requested = NI_OPTS(ni).min_free_packets;
  rc = ci_netif_pkt_reserve(ni, n_requested, &n_reserved, &pkt_list);
  n_accounted = n_reserved;

  if( NI_OPTS(ni).prealloc_packets )
    n_accounted += ni->state->mem_pressure_pkt_pool_n;
  if( n_accounted < n_requested ) {
    if( NI_OPTS(ni).prealloc_packets )
      LOG_E(ci_log("%s: ERROR: Insufficient packet buffers available for "
                   "EF_PREALLOC_PACKETS=1 EF_MAX_PACKETS=%d got %d rc %d",
                   __FUNCTION__, n_requested, n_accounted, rc));
    else
      LOG_E(ci_log("%s: ERROR: Insufficient packet buffers available for "
                   "EF_MIN_FREE_PACKETS=%d got %d rc %d",
                   __FUNCTION__, n_requested, n_accounted, rc));
    return rc ? : -ENOMEM;
  }

  if( NI_OPTS(ni).prealloc_packets ) {
    /* Free the packets now, so they can be used to fill rings */
    ci_netif_pkt_reserve_free(ni, pkt_list, n_reserved);
  }

  /* Fill the RX rings a little at a time.  Reason is to ensure that if we
   * are short of packet buffers, we don't fill some rings completely and
   * leave others empty.
   */
  for( lim = CI_CFG_RX_DESC_BATCH; lim <= ni->state->rxq_base_limit;
       lim += CI_CFG_RX_DESC_BATCH ) {
    ni->state->rxq_limit = lim;
    if( (rc = __ci_netif_init_fill_rx_rings(ni)) < 0 || ni->state->rxq_low ) {
      rc = -ENOMEM;
      if( lim < NI_OPTS(ni).rxq_min )
        LOG_E(ci_log("%s: ERROR: Insufficient packet buffers to fill RX rings "
                     "(rxq_limit=%d rxq_low=%d rxq_min=%d)", __FUNCTION__,
                     ni->state->rxq_base_limit, ni->state->rxq_low,
                     NI_OPTS(ni).rxq_min));
#if CI_CFG_PKTS_AS_HUGE_PAGES
      else if( NI_OPTS(ni).huge_pages == OO_IOBUFSET_FLAG_HUGE_PAGE_FORCE )
        LOG_E(ci_log("%s: ERROR: Failed to allocate huge pages to fill RX "
                     "rings", __FUNCTION__));
      else
#endif
        rc = 0;
      break;
    }
  }

  ci_netif_af_xdp_post_fill(ni);

  if( ! NI_OPTS(ni).prealloc_packets ) {
    /* Free the packets now, once rings are full, to ensure availability of
     * packets as indicated by EF_MIN_FREE_PACKETS */
    ci_netif_pkt_reserve_free(ni, pkt_list, n_reserved);
  }
  ni->state->rxq_limit = ni->state->rxq_base_limit;

#if CI_CFG_PKTS_AS_HUGE_PAGES
  /* Initial packets allocated: allow other packets to be in non-huge pages
   * if necessary.
   */
  if( NI_OPTS(ni).huge_pages == OO_IOBUFSET_FLAG_HUGE_PAGE_FORCE )
    NI_OPTS(ni).huge_pages = OO_IOBUFSET_FLAG_HUGE_PAGE_TRY;
#endif
  return rc;
}



#endif

#ifndef __KERNEL__

int ci_netif_dtor(ci_netif* ni)
{
  ci_assert(ni);

  /* \TODO Check if we should be calling ci_ipid_dtor() here. */
  /* Free the TCP helper resource */
  netif_tcp_helper_free(ni);

  return 0;
}



static int install_stack_by_id(ci_fd_t fp, unsigned id, bool is_service)
{
  oo_stack_lookup_and_attach_t op;
  op.stack_id = id;
  op.is_service = is_service;
  return oo_resource_op(fp, OO_IOC_INSTALL_STACK_BY_ID, &op);
}


static int install_stack_by_name(ci_fd_t fd, const char* name)
{
  struct oo_op_install_stack op;
  /* NB. No need to ensure it is NULL terminated: kernel has to anyway. */
  strncpy(op.in_name, name, CI_CFG_STACK_NAME_LEN);
  return oo_resource_op(fd, OO_IOC_INSTALL_STACK, &op);
}


/* This is used by utilities such as stackdump to restore an abitrary netif */
int ci_netif_restore_id(ci_netif* ni, unsigned thr_id, bool is_service)
{
  ef_driver_handle fd, fd2;
  ci_uint32 map_size;
  int rc;

  ci_assert(ni);

  LOG_NV(ci_log("%s: %u", __FUNCTION__, thr_id));

  /* Create a new fd, and attach the netif to it.  This is just a stepping
   * stone to give us something we can pass to ci_tcp_helper_stack_attach().
   */
  rc = ef_onload_driver_open(&fd2, OO_STACK_DEV, 1);
  if( rc != 0 ) {
    return rc;
  }
  rc = install_stack_by_id(fd2, thr_id, is_service);
  if( rc != 0 ) {
    CI_TRY(ef_onload_driver_close(fd2));
    return rc;
  }
  fd = __ci_tcp_helper_stack_attach(fd2, &ni->nic_set, &map_size, is_service);
  if( fd < 0 )
    return fd;
  CI_TRY(ef_onload_driver_close(fd2));
  return ci_netif_restore(ni, fd, map_size);
}


int ci_netif_restore_name(ci_netif* ni, const char* name)
{
  ef_driver_handle fd, fd2;
  ci_uint32 map_size;
  int rc;

  ci_assert(ni);

  LOG_NV(ci_log("%s: %s", __FUNCTION__, name));

  /* Create a new fd, and attach the netif to it.  This is just a stepping
   * stone to give us something we can pass to ci_tcp_helper_stack_attach().
   */
  if( (rc = ef_onload_driver_open(&fd2, OO_STACK_DEV, 1)) < 0 )
    goto fail1;
  if( (rc = install_stack_by_name(fd2, name)) < 0 )
    goto fail2;
  if( (rc = fd = ci_tcp_helper_stack_attach(fd2,
                                            &ni->nic_set, &map_size)) < 0 )
    goto fail3;
  if( (rc = ci_netif_restore(ni, fd, map_size)) < 0 )
    goto fail4;
  ef_onload_driver_close(fd2);

  ci_netif_log_startup_banner(ni, "Sharing");

  return 0;

 fail4:
  ef_onload_driver_close(fd);
 fail3:
 fail2:
  ef_onload_driver_close(fd2);
 fail1:
  return rc;
}


/* this is called by ci_netif_resource_using_handle, and also when tranferring
 * a netif to a new process (e.g. if the fd is used after a fork/exec). For
 * now we still need the handle but this parameter may be removed one day.
 */
int ci_netif_restore(ci_netif* ni, ef_driver_handle fd,
                     unsigned netif_mmap_bytes)
{
  int rc = 0;
  ci_assert(ni);
  
  LOG_NV(ci_log("%s: fd=%d", __FUNCTION__, fd));

  CI_TRY_RET(ci_netif_init(ni, fd));

  if( (rc = netif_tcp_helper_restore(ni, netif_mmap_bytes)) != 0) {
    ci_netif_deinit(ni);
    ci_log("netif_tcp_helper_restore returned %d at %s:%d", rc, __FILE__, __LINE__); \
    return rc;
  }

  /* We do not want this stack to be used as default */
  ni->flags |= CI_NETIF_FLAGS_DONT_USE_ANON;

  /* We don't CHECK_NI(ni) here, as it needs the netif lock and we have
   * the fdtable lock at this point.  The netif will be checked later
   * when used.
   */

  return rc;
}

#endif

/*! \cidoxg_end */
