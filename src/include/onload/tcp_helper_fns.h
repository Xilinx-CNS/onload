/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2006/06/06
** Description: Functions and inliners for the tcp_helper_resource.
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef __CI_DRIVER_EFAB_TCP_HELPER_FNS_H__
#define __CI_DRIVER_EFAB_TCP_HELPER_FNS_H__

#include <ci/efrm/vi_resource.h>
#include <ci/efrm/pio.h>
#include <onload/common.h>
#include <onload/fd_private.h>
#include <onload/tcp_helper.h>
#include <onload/tcp_driver.h> /* For efab_tcp_driver */

#if !defined(__KERNEL__)
#error "Kernel-only header!"
#endif


/**********************************************************************
 */

#define TCP_HELPER_WAITQ(rs, i) (&((rs)->netif.ep_tbl[OO_SP_TO_INT(i)]->waitq))

/* If ifindices_len=0, create stack without hw (useful for TCP loopback);
 * if ifindices_len<0, autodetect all available NICs. */
extern int tcp_helper_alloc_kernel(ci_resource_onload_alloc_t* alloc,
                                   const ci_netif_config_opts* opts,
                                   int ifindices_len,
                                   tcp_helper_resource_t** rs_out);

extern int tcp_helper_alloc_ul(ci_resource_onload_alloc_t* alloc,
                               int ifindices_len,
                               tcp_helper_resource_t** rs_out);

extern int tcp_helper_get_ns_components(struct oo_cplane_handle** cplane,
                                        struct oo_filter_ns**  filter_ns);

struct user_namespace;
extern struct user_namespace* tcp_helper_get_user_ns(tcp_helper_resource_t*);

extern int tcp_helper_rm_alloc(ci_resource_onload_alloc_t* alloc,
                               const ci_netif_config_opts* opts,
                               int ifindices_len, tcp_helper_cluster_t* thc,
                               tcp_helper_resource_t** rs_out);

extern void tcp_helper_dtor(tcp_helper_resource_t* trs);


extern int
ci_netif_requested_scalable_intf_count(struct oo_cplane_handle* cp,
                                       const ci_netif_config_opts* ni_opts)
                                      CI_HF;

#if CI_CFG_NIC_RESET_SUPPORT
extern void tcp_helper_suspend_interface(ci_netif* ni, int intf_i);

extern void tcp_helper_reset_stack(ci_netif* ni, int intf_i);
#endif

#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
extern void tcp_helper_xdp_change(ci_netif* ni, int intf_i);
#endif

extern void tcp_helper_flush_resets(ci_netif* ni);

#if ! CI_CFG_UL_INTERRUPT_HELPER
extern void tcp_helper_rm_dump(oo_fd_flags fd_flags, oo_sp sock_id,
                               tcp_helper_resource_t* trs,
                               const char *line_prefix);

#define THR_PRIV_DUMP(priv, line_prefix)                \
  tcp_helper_rm_dump((priv)->fd_flags, (priv)->sock_id, \
                     (priv)->thr, line_prefix)
#endif

extern unsigned efab_tcp_helper_netif_lock_callback(eplock_helper_t*,
                                                    ci_uint64 lock_val,
                                                    int in_dl_context);

extern int efab_ioctl_get_ep(ci_private_t*, oo_sp,
                             tcp_helper_endpoint_t** ep_out);


extern int efab_os_sock_callback(wait_queue_entry_t *wait, unsigned mode,
                                 int sync, void *key);

extern void efab_os_wakeup_work(struct work_struct *data);

extern int efab_tcp_helper_vi_stats_query(tcp_helper_resource_t*,
                                                 unsigned int, void*, size_t, int);
/* get a resource installed install_resource_into_priv, or return a
 negative error code (does not remove the resource from the priv) */
ci_inline int
efab_get_tcp_helper_of_priv(ci_private_t* priv, tcp_helper_resource_t**trs_out,
			    const char *context)
{
  ci_assert(NULL != priv);
  if (priv->thr == NULL) {
    LOG_U(ci_log("WARNING: %s no tcp helper in %p; noop", context, priv));
    return -ENOENT;
  } 

  if (!trs_out)
    return -ENXIO;
  *trs_out = priv->thr;

  return 0;
}

/* For a priv that is known to be specialised as a userlevel socket (or
** netif fd) return the tcp_helper_resource_t.
*/
ci_inline tcp_helper_resource_t* efab_priv_to_thr(ci_private_t* priv) {
  ci_assert(priv->thr);
  return priv->thr;
}

ci_inline tcp_helper_endpoint_t* efab_priv_to_ep(ci_private_t* priv)
{
  tcp_helper_resource_t* thr = efab_priv_to_thr(priv);
  ci_assert_equal(TRUSTED_SOCK_ID(&thr->netif, priv->sock_id),
                  priv->sock_id);
  return ci_trs_ep_get(thr, priv->sock_id);
}

extern int efab_thr_get_inaccessible_stack_info(unsigned id,
                                                uid_t* uid, 
                                                uid_t* euid,
                                                ci_int32* share_with, 
                                                char* name);

#define EFAB_THR_TABLE_LOOKUP_NO_CHECK_USER       0
#define EFAB_THR_TABLE_LOOKUP_CHECK_USER          1
#define EFAB_THR_TABLE_LOOKUP_NO_WARN             2
#define EFAB_THR_TABLE_LOOKUP_NO_UL               4

extern int efab_thr_can_access_stack(tcp_helper_resource_t* thr,
                                     int check_user);
extern int efab_thr_user_can_access_stack(uid_t uid, uid_t euid,
                                          tcp_helper_resource_t* thr);

/*! Lookup a stack and grab a reference if found.  If [name] is not NULL,
 * search by name, else by [id]. 
 *
 * If flags has:
 *
 * - CHECK_USER bit set then only stacks that the user has permission
 * to access will be returned.  Others will return -EACCES.
 * 
 * - NO_WARN bit set then no warning message about being unable to
 * access a stack will be output
 * 
 * - NO_UL bit set then only orphan stacks will be returned.  You may
 * still get EACCES returned for non-orphan stacks.  Without NO_UL set
 * you will only get non-orphan stacks.
 * 
 * Caller is responsible for dropping the reference taken on success.
 */
extern int efab_thr_table_lookup(const char* name, struct net* netns,
                                 unsigned id, int flags,
                                 tcp_helper_resource_t** stack_out);

#if ! CI_CFG_UL_INTERRUPT_HELPER
/*! Try to kill an orphan/zombie stack */
extern int tcp_helper_kill_stack_by_id(unsigned id);
extern void tcp_helper_kill_stack(tcp_helper_resource_t *thr);
#endif

extern int
oo_version_check(const char* version, const char* uk_intf_ver, int debug_lib);



extern int efab_tcp_helper_sock_sleep(tcp_helper_resource_t*,
				      oo_tcp_sock_sleep_t* op);

extern int efab_tcp_helper_pkt_wait(tcp_helper_resource_t* trs,
                                    int* lock_flags);

extern int efab_tcp_helper_sock_lock_slow(tcp_helper_resource_t*, oo_sp);
extern void efab_tcp_helper_sock_unlock_slow(tcp_helper_resource_t*, oo_sp);

extern int efab_tcp_helper_get_sock_fd(ci_private_t*, void*);

extern int efab_tcp_helper_os_sock_sendmsg(ci_private_t*, void*);
extern int efab_tcp_helper_os_sock_sendmsg_raw(ci_private_t*, void*);

extern int efab_tcp_helper_os_sock_recvmsg(ci_private_t *priv, void *arg);

extern int efab_tcp_helper_os_sock_accept(ci_private_t *priv, void *arg);

extern int efab_tcp_helper_create_os_sock(ci_private_t *priv);
extern int efab_tcp_helper_bind_os_sock_rsop(ci_private_t *priv, void *arg);
extern int efab_tcp_helper_bind_os_sock_kernel(tcp_helper_resource_t* trs,
                                               oo_sp sock_id,
                                               struct sockaddr *addr,
                                               int addrlen,
                                               ci_uint16 *out_port);
extern int /*bool*/
tcp_helper_active_wilds_need_filters(tcp_helper_resource_t*);

extern int efab_tcp_helper_listen_os_sock(ci_private_t *priv, void *p_backlog);

extern int efab_tcp_helper_shutdown_os_sock (tcp_helper_endpoint_t* ep,
                                             ci_int32 how);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
struct file *sock_alloc_file(struct socket *sock, int flags, void *unused);
#endif

extern int efab_tcp_helper_map_usermem(tcp_helper_resource_t* trs,
                                       struct oo_iobufs_usermem* ioum,
                                       unsigned long user_base, int n_pages,
                                       uint64_t** hw_addrs_out);

extern void efab_tcp_helper_unmap_usermem(tcp_helper_resource_t* trs,
                                          struct oo_iobufs_usermem* ioum);

extern int efab_tcp_helper_more_bufs(tcp_helper_resource_t* trs);

extern int efab_tcp_helper_more_socks(tcp_helper_resource_t* trs);

#if CI_CFG_FD_CACHING
extern int efab_tcp_helper_clear_epcache(tcp_helper_resource_t* trs);
#endif

extern void efab_tcp_helper_close_endpoint(tcp_helper_resource_t* trs,
                                           oo_sp ep_id,
                                           int already_locked);
extern int efab_file_move_to_alien_stack(ci_private_t *priv,
                                         ci_netif *alien_ni,
                                         int drop_filter,
                                         oo_sp* new_sock_id);

extern void
tcp_helper_cluster_ref(tcp_helper_cluster_t* thc);

extern void
tcp_helper_cluster_release(tcp_helper_cluster_t* thc,
                           tcp_helper_resource_t* trs);

extern int
tcp_helper_cluster_from_cluster(tcp_helper_resource_t* thr);

extern int
tcp_helper_cluster_dump(tcp_helper_resource_t* thr, void* buf, int buf_len);

extern int tcp_helper_cluster_alloc_thr(const char* name,
                                        int cluster_size,
                                        int cluster_restart,
                                        int ni_flags,
                                        const ci_netif_config_opts* ni_opts,
                                        tcp_helper_resource_t** thr_out);


/*--------------------------------------------------------------------
 *!
 * Called by kernel code to get the shared user/kernel mode netif lock
 * This obtains the kernel netif "lock" first so we can deduce who owns 
 * the eplock
 *
 * \param trs             TCP helper resource
 *
 * \return                non-zero if callee succeeded in obtaining 
 *                        the netif lock
 *
 *--------------------------------------------------------------------*/

extern int
efab_tcp_helper_netif_try_lock(tcp_helper_resource_t*, int in_dl_context);

extern int
efab_tcp_helper_netif_lock_or_set_flags(tcp_helper_resource_t* trs,
                                        unsigned trusted_flags,
                                        ci_uint64 untrusted_flags,
                                        int in_dl_context);


/*--------------------------------------------------------------------
 *!
 * Called by kernel code to unlock the netif lock. Only to be called
 * after a successful call to efab_tcp_helper_netif_try_lock
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

extern void
efab_tcp_helper_netif_unlock(tcp_helper_resource_t*, int in_dl_context);


/**********************************************************************
***************** Iterators to find netifs ***************************
**********************************************************************/
extern int
iterate_netifs_unlocked(ci_netif **p_ni, enum oo_thr_ref_type ref_type,
                        enum oo_thr_ref_type ref_zero);

ci_inline void
iterate_netifs_unlocked_dropref(ci_netif * netif, enum oo_thr_ref_type ref_type)
{
  ci_assert(netif);
  oo_thr_ref_drop(netif2tcp_helper_resource(netif)->ref, ref_type);
}


ci_inline void
tcp_helper_request_wakeup_nic(tcp_helper_resource_t* trs, int intf_i) {
  /* This assertion is good, but fails on linux so currently disabled */
  /* ci_assert(ci_bit_test(&trs->netif.state->evq_primed, nic_i)); */

  /* If we're not allowed to poll the stack in the kernel, it's neither useful
   * nor safe to prime the interrupt. */
  if( ci_netif_may_poll_in_kernel(&trs->netif, intf_i) ) {
    unsigned current_i =
      ef_eventq_current(&trs->netif.nic_hw[intf_i].vi) / sizeof(efhw_event_t);
    efrm_eventq_request_wakeup(trs->nic[intf_i].thn_vi_rs, current_i);
  }
}


ci_inline void
tcp_helper_request_wakeup_nic_if_needed(tcp_helper_resource_t* trs,
                                        int intf_i)
{
  if( ! ci_bit_test(&trs->netif.state->evq_primed, intf_i) &&
      ! ci_bit_test_and_set(&trs->netif.state->evq_primed, intf_i) )
    tcp_helper_request_wakeup_nic(trs, intf_i);
}
ci_inline void tcp_helper_request_wakeup(tcp_helper_resource_t* trs) {
  int intf_i;
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i)
    tcp_helper_request_wakeup_nic_if_needed(trs, intf_i);
}


void tcp_helper_request_timer(tcp_helper_resource_t* trs);

extern void generic_tcp_helper_close(ci_private_t* priv);


extern
int efab_tcp_helper_set_tcp_close_os_sock(tcp_helper_resource_t *thr,
                                          oo_sp sock_id);

extern
int efab_tcp_helper_setsockopt(tcp_helper_resource_t* trs, oo_sp sock_id,
                               int level, int optname, char* optval,
                               int optlen);


extern int efab_tcp_helper_handover(ci_private_t* priv, void *p_fd);
extern int oo_file_moved_rsop(ci_private_t* priv, void *p_fd);

extern int linux_tcp_helper_fop_fasync(int fd, struct file *filp, int mode);

/* UDP fd poll function, timout should be NULL in case sleep is unlimited */
extern int efab_tcp_helper_poll_udp(struct file *filp, int *mask, s64 *timeout);


/**********************************************************************
*********************** Waiting for ready list  ***********************
**********************************************************************/

static inline void
efab_tcp_helper_ready_list_wakeup(tcp_helper_resource_t* trs,
                                  int ready_list)
{
#if CI_CFG_EPOLL3
  ci_atomic32_and(&trs->netif.state->ready_list_flags[ready_list],
                  ~CI_NI_READY_LIST_FLAG_WAKE);
  ci_waitable_wakeup_all(&trs->ready_list_waitqs[ready_list]);
#endif
}

static inline unsigned
efab_tcp_helper_ready_list_events(tcp_helper_resource_t* trs,
                                  int ready_list)
{
#if CI_CFG_EPOLL3
  return ci_ni_dllist_is_empty(&trs->netif,
                               &trs->netif.state->ready_lists[ready_list])
         ?  0 : POLLIN;
#else
  return 0;
#endif
}


extern int efab_attach_os_socket(tcp_helper_endpoint_t*, struct file*);
extern int efab_create_os_socket(tcp_helper_resource_t* trs,
                                 tcp_helper_endpoint_t* ep, ci_int32 domain,
                                 ci_int32 type, int flags);

extern void
oo_os_sock_status_bit_clear_handled(tcp_helper_endpoint_t *ep,
                                    struct file* os_sock,
                                    ci_uint32 bits_handled);

extern void
tcp_helper_defer_dl2work(tcp_helper_resource_t* trs, ci_uint32 flag);


extern int
oo_create_fd(tcp_helper_resource_t* thr, oo_sp ep_id, int flags,
             oo_fd_flags fd_flags, ci_os_file* _file_ptr);
static inline int
oo_create_ep_fd(tcp_helper_endpoint_t* ep, int flags, oo_fd_flags fd_flags)
{
  return oo_create_fd(ep->thr, ep->id, flags, fd_flags,
                      (fd_flags & (OO_FDFLAG_EP_TCP | OO_FDFLAG_REATTACH)) ?
                      &ep->file_ptr : NULL);
}
static inline int
oo_create_stack_fd(tcp_helper_resource_t *thr, oo_fd_flags fd_flags)
{
  return oo_create_fd(thr, OO_SP_NULL, O_CLOEXEC,
                      OO_FDFLAG_STACK | fd_flags, NULL);
}

extern int onloadfs_get_dev_t(ci_private_t* priv, void* arg);
extern int onload_alloc_file(tcp_helper_resource_t *thr, oo_sp ep_id,
                             int flags, oo_fd_flags fd_flags,
                             ci_private_t **priv_p);

extern int oo_clone_fd(struct file* filp, int do_cloexec);

ci_inline void
efab_get_os_settings(tcp_helper_resource_t* trs)
{
  ci_netif_config_opts *opts = &NI_OPTS_TRS(trs);

  /* We do not overwrite values from userland, so exit if opts are already
   * inited. */
  if (opts->inited)
    return;

  /* The default of the MIN value is actually hardcoded. sysctl_tcp_rmem[0]
  ** stores SK_MEM_QUANTUM that is not the same as minimum value. It is the
  ** amount of _memory_ that will be allocated regardless of the state of
  ** the system and other factors that usually affect linux kernel
  ** logic. The RCVBUF can safely go beyong thyis value. */
  opts->tcp_sndbuf_min = CI_CFG_TCP_SNDBUF_MIN;
  opts->tcp_rcvbuf_min = CI_CFG_TCP_RCVBUF_MIN;

  /* Linux 4.15 moved these values into network namespace structures */
#if defined(EFRM_DO_NAMESPACES) && defined(EFRM_HAVE_NS_SYSCTL_TCP_MEM)
  opts->tcp_sndbuf_def = trs->net_ns->ipv4.sysctl_tcp_wmem[1];
  opts->tcp_sndbuf_max = trs->net_ns->ipv4.sysctl_tcp_wmem[2];
  opts->tcp_rcvbuf_def = trs->net_ns->ipv4.sysctl_tcp_rmem[1];
  opts->tcp_rcvbuf_max = trs->net_ns->ipv4.sysctl_tcp_rmem[2];
#elif defined(EFRM_HAVE_NS_SYSCTL_TCP_MEM)
  opts->tcp_sndbuf_def = init_net.ipv4.sysctl_tcp_wmem[1];
  opts->tcp_sndbuf_max = init_net.ipv4.sysctl_tcp_wmem[2];
  opts->tcp_rcvbuf_def = init_net.ipv4.sysctl_tcp_rmem[1];
  opts->tcp_rcvbuf_max = init_net.ipv4.sysctl_tcp_rmem[2];
#else
  opts->tcp_sndbuf_def = sysctl_tcp_wmem[1];
  opts->tcp_sndbuf_max = sysctl_tcp_wmem[2];
  opts->tcp_rcvbuf_def = sysctl_tcp_rmem[1];
  opts->tcp_rcvbuf_max = sysctl_tcp_rmem[2];
#endif
#ifdef LINUX_HAS_SYSCTL_MEM_MAX
  opts->udp_sndbuf_max = sysctl_wmem_max;
  opts->udp_rcvbuf_max = sysctl_rmem_max;
#endif

  if( opts->tcp_sndbuf_user != 0 ) {
    opts->tcp_sndbuf_min = opts->tcp_sndbuf_max =
      opts->tcp_sndbuf_def = opts->tcp_sndbuf_user;
  }
  if( opts->tcp_rcvbuf_user != 0 ) {
    opts->tcp_rcvbuf_min = opts->tcp_rcvbuf_max =
      opts->tcp_rcvbuf_def = opts->tcp_rcvbuf_user;
  }
  if( opts->udp_sndbuf_user != 0 ) {
    opts->udp_sndbuf_min = opts->udp_sndbuf_max =
      opts->udp_sndbuf_def = opts->udp_sndbuf_user;
  }
  if( opts->udp_rcvbuf_user != 0 ) {
    opts->udp_rcvbuf_min = opts->udp_rcvbuf_max =
      opts->udp_rcvbuf_def = opts->udp_rcvbuf_user;
  }

  opts->inited = CI_TRUE;
}


/*****************************************************************
 * Table with all ioctl handlers
 *****************************************************************/

#ifdef NDEBUG
# define OO_OPS_TABLE_HAS_NAME  0
#else
# define OO_OPS_TABLE_HAS_NAME  1
#endif

/*! Ioctl handler for a giver ioctl operation
 * \param priv      Private file structure
 * \param arg       Ioctl argument, copied in kernel memspace if necessary
 *
 * \return 0 or -errno
 *
 * \note 
 * All these handlers MUST return 0 on success, -errno on failure.
 * 1. We do not copy any out parameters on non-zero rc.
 * 2. Some OSes (for example, Solaris) has problems with handling ioctl
 * return code.
 *
 * \note Ioctl handler should not copy arguments from/to user space.
 * OS-specific part of the driver should pass them arguments which are
 * already in the kernel space.
 */
typedef int (*oo_ioctl_handler_t)(ci_private_t *priv, void *arg);

typedef struct {
  int ioc_cmd;
  oo_ioctl_handler_t handler;
#if OO_OPS_TABLE_HAS_NAME
  const char* name;
#endif
} oo_operations_table_t;

extern oo_operations_table_t oo_operations[];


/*----------------------------------------------------------------------------
 * Timesync state
 *---------------------------------------------------------------------------*/

extern unsigned oo_timesync_cpu_khz;

extern void oo_timesync_wait_for_cpu_khz_to_stabilize(void);

extern void oo_timesync_update(struct oo_timesync*);

extern int oo_timesync_ctor(struct oo_timesync *oo_ts);
extern void oo_timesync_dtor(struct oo_timesync *oo_ts);


extern int
tcp_helper_install_tproxy(int install,
                          tcp_helper_resource_t* thr,
                          tcp_helper_cluster_t* thc,
                          const ci_netif_config_opts* ni_opts,
                          ci_uint16* ifindexes_out, int out_count);


/*----------------------------------------------------------------------------
 * Shared local ports
 *---------------------------------------------------------------------------*/

extern int
efab_alloc_ephemeral_port(ci_addr_t laddr, ci_uint16 lport_be16,
                          struct efab_ephemeral_port_keeper** keeper_out);
extern void
efab_free_ephemeral_port(struct efab_ephemeral_port_keeper* keeper);

extern struct efab_ephemeral_port_head*
tcp_helper_alloc_ephem_table(ci_uint32 min_entries, ci_uint32* entries_out);

extern int
tcp_helper_get_ephemeral_port_list(struct efab_ephemeral_port_head* table,
                                   ci_addr_t laddr, ci_uint32 table_entries,
                                   struct efab_ephemeral_port_head** list_out);

/*! Tries to allocate up to size active wilds to the active wild pool.
 *
 * \return 0 size entries were added to pool
 *        -1 otherwise
 */
extern int tcp_helper_alloc_to_active_wild_pool(tcp_helper_resource_t* rs,
                                                ci_addr_t laddr_be32,
                                                ci_dllist* ephemeral_ports);

extern int tcp_helper_increase_active_wild_pool(tcp_helper_resource_t* rs,
                                                ci_addr_t laddr_be);

extern int
tcp_helper_alloc_ephemeral_ports(struct efab_ephemeral_port_head* list_head,
                                 struct efab_ephemeral_port_head* global_head,
                                 ci_addr_t laddr_be32, int count);

extern void
tcp_helper_free_ephemeral_ports(struct efab_ephemeral_port_head* table,
                                ci_uint32 entries);

#if CI_CFG_UL_INTERRUPT_HELPER
int oo_wait_for_interrupt(ci_private_t* priv, void* arg);
int oo_get_closing_ep(ci_private_t* priv, void* arg);
int oo_wakeup_waiters(ci_private_t* priv, void* arg);
#endif

static inline void
efab_eplock_wake(ci_netif *ni)
{
  CITP_STATS_NETIF_INC(ni, lock_wakes);
  wake_up_interruptible(&ni->eplock_helper.wq);
}

/*----------------------------------------------------------------------------
 * eBPF/XDP
 *---------------------------------------------------------------------------*/

#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
/* returns 1 iff packet is to be kept on rx path */
extern /* bool */ int
efab_tcp_helper_xdp_rx_pkt(tcp_helper_resource_t* trs, int intf_i, ci_ip_pkt_fmt* pkt);
#endif
#endif /* __CI_DRIVER_EFAB_TCP_HELPER_FNS_H__ */
/*! \cidoxg_end */
