/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: ctk
**     Started: 2004/03/23
** Description: User level TCP helper interface.
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef __CI_DRIVER_EFAB_TCP_HELPER_H__
#define __CI_DRIVER_EFAB_TCP_HELPER_H__


#include <ci/compat.h>
#include <ci/internal/ip.h>
#include <onload/osfile.h>
#include <onload/oof_hw_filter.h>
#include <onload/oof_socket.h>
#include <onload/tcp_helper_ref.h>


/* Forwards. */
typedef struct tcp_helper_endpoint_s tcp_helper_endpoint_t;


struct tcp_helper_nic {
  int                  thn_intf_i;
  struct oo_nic*       thn_oo_nic;
  struct efrm_vi*      thn_vi_rs[CI_MAX_VIS_PER_INTF];
  /* Track the size of the VI mmap in the kernel. */
  unsigned             thn_vi_mmap_bytes[CI_MAX_VIS_PER_INTF];
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  unsigned             thn_plugin_mapped_csr_offset;
#endif
#if CI_CFG_PIO
  struct efrm_pio*     thn_pio_rs;
  unsigned             thn_pio_io_mmap_bytes;
#endif
#if CI_CFG_CTPIO
  unsigned             thn_ctpio_io_mmap_bytes;
  void*                thn_ctpio_io_mmap;
#endif
  struct efrm_efct_rxq* thn_efct_rxq[EF_VI_MAX_EFCT_RXQS];
};


/* Keeps reference to os socket bound to an ephemeral port.
 * This is to allow reuse in multiple stacks.
 *
 * These ports will be later reused by shared local ports in more than one
 * stack (in case of cluster).
 * The structure below is assumed to have single reference to os file.  Other
 * reference holders are shared local port endpoints in one or more stacks.
 * The reference owned by the port_keeper is to be freed last after all the
 * endpoints are destroyed. */
struct efab_ephemeral_port_keeper {
   /* Instances of this structure live, in the general case, on two linked
    * lists simultaneously.  One, linked by [next], is specific to a single IP
    * address (where that IP address will be INADDR_ANY when shared local ports
    * are not per-IP), and the other, linked by [global_next], is common to all
    * IP addresses. */
   struct efab_ephemeral_port_keeper* next;
   struct efab_ephemeral_port_keeper* global_next;
   struct socket* sock;
   struct file* os_file;
   ci_addr_t laddr;
   uint16_t port_be16;
};

/* List-head for a list of efab_ephemeral_port_keeper structures. */
struct efab_ephemeral_port_head {
  struct efab_ephemeral_port_keeper* head;
  struct efab_ephemeral_port_keeper** tail_next_ptr;
  /* Pointer into the list of all (i.e. not just for this IP) local ports
   * indicating the point up to which it has been consumed by this local IP in
   * our attempts to use ports already allocated for other IPs. */
  struct efab_ephemeral_port_keeper* global_consumed;
  ci_addr_t laddr;
  uint32_t port_count;
};

struct tcp_helper_resource_s;

typedef struct tcp_helper_cluster_s {
  struct efrm_vi_set*             thc_vi_set[CI_CFG_MAX_HWPORTS];
  ci_dllist                       thc_thr_list;
  struct tcp_helper_resource_s**  thc_thr_rrobin;
  /* Indicates which stack in the round robin to switch to next. */
  int                             thc_thr_rrobin_index;
#define THC_REHEAT_FLAG_USE_SWITCH_PORT 0x1
#define THC_REHEAT_FLAG_STICKY_MODE     0x2
  unsigned                        thc_reheat_flags;
  /* Port used to determine if we should switch stack for this bind. */
  ci_addr_t                       thc_switch_addr;
  uint16_t                        thc_switch_port;
  char                            thc_name[CI_CFG_CLUSTER_NAME_LEN + 1];
  int                             thc_cluster_size;
  oo_atomic_t                     thc_thr_count;
  uid_t                           thc_keuid;
  ci_dllist                       thc_tlos;

#define THC_FLAG_PACKET_BUFFER_MODE 0x1
#define THC_FLAG_HW_LOOPBACK_ENABLE 0x2

/* Various RSS hash settings, note that they are targetted at TCP. */
#define THC_FLAG_TPROXY             0x4
#define THC_FLAG_SCALABLE          0x10

#define THC_FLAG_PREALLOC_LPORTS   0x20
  unsigned                        thc_flags;
  uint16_t*                       thc_tproxy_ifindex;
  int                             thc_tproxy_ifindex_count;

  struct tcp_helper_cluster_s*    thc_next;
  oo_atomic_t                     thc_ref_count;

  wait_queue_head_t               thr_release_done;

  struct oo_cplane_handle*        thc_cplane;
  struct oo_filter_ns*            thc_filter_ns;

  /* The ephemeral ports owned by the cluster are maintained in a hash table
   * keyed by local IP address. */
  struct efab_ephemeral_port_head* thc_ephem_table;
  uint32_t                         thc_ephem_table_entries;
} tcp_helper_cluster_t;


/* Used to backup and, if necessary restore, state during a reuseport bind. */
typedef struct tcp_helper_reheat_state_s {
  int       thr_prior_index;
  pid_t     thc_tid_effective;
  unsigned  thc_reheat_flags;
  ci_addr_t thc_switch_addr;
  unsigned  thc_switch_port;
} tcp_helper_reheat_state_t;


/* Substructure of oo_iobufs_usermem which collects chunks of the same
 * compound_order. */
struct oo_iobufs_usermem_group {
  struct oo_buffer_pages* pages;
  struct oo_iobufset* all[CI_CFG_MAX_HWPORTS];
};


/* Kernel data to track allocations initiated by onload_zc_register_buffers */
struct oo_iobufs_usermem {
  int n_groups;
  struct oo_iobufs_usermem_group* groups;
};


/* Linked list of oo_iobufs_usermem instances */
struct tcp_helper_usermem {
  struct tcp_helper_usermem* next;
  uint64_t id;    /* id we gave to userspace so they can free this */
  struct oo_iobufs_usermem um;
};

 /*--------------------------------------------------------------------
 *
 * tcp_helper_resource_t
 *
 *--------------------------------------------------------------------*/

/*! Comment? */
typedef struct tcp_helper_resource_s {
  /* A number of fields here duplicate fields in ci_netif_state.  This is
   * deliberate, and is because we do not trusted the contents of the
   * shared state.
   */
  unsigned               id;
  char                   name[CI_CFG_STACK_NAME_LEN + 1];
  oo_thr_ref_t           ref;

  ci_netif               netif;

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /*! Kernel side stack lock. Needed so we can determine who "owns" the
   *   netif lock (kernel or user).
   *
   * The flags can only be set when the lock is LOCKED.  ie. This must be
   * UNLOCKED, or LOCKED possibly in combination with the other flags.  If
   * AWAITING_FREE is set, other flags must not be.
   */
#define OO_TRUSTED_LOCK_UNLOCKED          0x0
#define OO_TRUSTED_LOCK_LOCKED            0x1
#define OO_TRUSTED_LOCK_AWAITING_FREE     0x2
#define OO_TRUSTED_LOCK_NEED_POLL         0x4
#define OO_TRUSTED_LOCK_CLOSE_ENDPOINT    0x8
#define OO_TRUSTED_LOCK_OS_READY          0x10
#define OO_TRUSTED_LOCK_NEED_PRIME        0x20
#define OO_TRUSTED_LOCK_HANDLE_ICMP       0x40
#define OO_TRUSTED_LOCK_SWF_UPDATE        0x80
#define OO_TRUSTED_LOCK_PURGE_TXQS        0x100
#define OO_TRUSTED_LOCK_PRIME_IF_IDLE     0x200
  volatile unsigned      trusted_lock;

  /*! this is used so we can schedule destruction at task time,
   * using the global workqueue */
  struct work_struct work_item_dtor;
#endif

  /*! Link for global list of stacks. */
  ci_dllink              all_stacks_link;

  /* VI descruction completion helper. */
  struct completion complete;

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* For pinning periodic work */
  int periodic_timer_cpu;

  /* For deferring work to a non-atomic context. */
#define ONLOAD_WQ_NAME "onload-wq:%s"
#define ONLOAD_WQ_NAME_BASELEN 11
  char wq_name[ONLOAD_WQ_NAME_BASELEN + ONLOAD_PRETTY_NAME_MAXLEN];
  struct workqueue_struct *wq;
  struct work_struct non_atomic_work;
  /* List of endpoints requiring work in non-atomic context. */
  ci_sllist     non_atomic_list;

#if CI_CFG_NIC_RESET_SUPPORT
  /* For deferring resets to a non-atomic context. */
#define ONLOAD_RESET_WQ_NAME "onload-rst-wq:%s"
#define ONLOAD_RESET_WQ_NAME_BASELEN 15
  char reset_wq_name[ONLOAD_RESET_WQ_NAME_BASELEN + ONLOAD_PRETTY_NAME_MAXLEN];
  struct workqueue_struct *reset_wq;
  struct work_struct reset_work;
  struct delayed_work purge_txq_work;
#endif
#endif

#ifdef CONFIG_NAMESPACES

#define EFRM_DO_NAMESPACES
  /* Namespaces this stack is living into */
  struct net* net_ns;
  struct pid_namespace* pid_ns;
#ifdef EFRM_HAVE_NEW_KALLSYMS
#define OO_HAS_IPC_NS
  /* put_ipc_ns() is not exported, so we can't use it without
   * kallsyms_on_each_symbol() */
  struct ipc_namespace* ipc_ns;
#endif /* EFRM_HAVE_NEW_KALLSYMS */
#endif /* CONFIG_NAMESPACES */

#ifdef EFRM_DO_USER_NS
  struct user_namespace* user_ns;
#endif

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /*! clear to indicate that timer should not restart itself */
  atomic_t                 timer_running;
  /*! timer - periodic poll */
  struct delayed_work      timer;
#endif

  /*! tcp_helper endpoint(s) to be closed at next calling of
   * linux_tcp_helper_fop_close() or if tcp_helper_resource is released
   */
  ci_sllist             ep_tobe_closed;

  /* This field is currently used under the trusted lock only, BUT it must
   * be modified via atomic operations ONLY.  These flags are used in
   * stealing the shared and trusted locks from atomic or driverlink
   * context to workqueue context.  When such a "steal" (or "deferral")
   * is in action, the field might be used from 2 contexts 
   * simultaneously. */
  volatile ci_uint32    trs_aflags;
  /* We've deferred locks to non-atomic handler.  Must poll and prime. */
# define OO_THR_AFLAG_POLL_AND_PRIME      0x2
  /* We've deferred locks to non-atomic handler.  Must unlock only. */
# define OO_THR_AFLAG_UNLOCK_TRUSTED      0x4
  /* Have we deferred something while holding the trusted lock? */
# define OO_THR_AFLAG_DEFERRED_TRUSTED    0x7

  /* Defer the shared lock (without the trusted lock!) to the work queue */
# define OO_THR_AFLAG_UNLOCK_UNTRUSTED    0x8

  /* Don't block on the shared lock when resetting a stack. */
# define OO_THR_AFLAG_DONT_BLOCK_SHARED   0x10

  /*! Spinlock.  Protects:
   *    - ep_tobe_closed / closed_eps
   *    - non_atomic_list
   *    - wakeup_list
   *    - intfs_to_reset 
   *    - intfs_to_xdp_update
   *    - icmp_msg
   */
  ci_irqlock_t          lock;

#if CI_CFG_NIC_RESET_SUPPORT
  /* Bit mask of intf_i that need resetting by the lock holder */
  unsigned              intfs_to_reset;
  /* Bit mask of intf_i that have been removed/suspended and not yet reset */
  unsigned              intfs_suspended;
#endif

  unsigned              mem_mmap_bytes;
  unsigned              io_mmap_bytes;
  unsigned              buf_mmap_bytes;
#if CI_CFG_PIO
  /* Length of the PIO mapping.  There is typically a page for each VI */
  unsigned              pio_mmap_bytes;
#endif
#if CI_CFG_CTPIO
  /* Length of the CTPIO mapping.  The same one is used for all VIs. */
  unsigned              ctpio_mmap_bytes;
#endif
  unsigned              efct_shm_mmap_bytes;

  /* Used to block threads that are waiting for free pkt buffers. */
  ci_waitq_t            pkt_waitq;

#if CI_CFG_UL_INTERRUPT_HELPER
  /* Wait for interrupts */
  wait_queue_head_t ulh_waitq;

  /* intfs to handle recent interrupt */
  ci_atomic_t intr_intfs;
  /* intfs to request wakeup */
  ci_atomic_t wake_intfs;

  ci_uint32 ulh_flags;
#endif
  
  struct tcp_helper_nic      nic[CI_CFG_MAX_INTERFACES];

#if CI_CFG_ENDPOINT_MOVE
  /* The cluster this stack is associated with if any */
  tcp_helper_cluster_t*         thc;
#endif
  /* TID of thread that created this stack within the cluster */
  pid_t                         thc_tid;
  /* TID of thread with right to do sticky binds on this stack in reheat mode */
  pid_t                         thc_tid_effective;
  /* Track list of stacks associated with a single thc */
  ci_dllink             thc_thr_link;
  /* bucket of rss hardware filter */
  int thc_rss_instance;
  /* backing store for efct's mmappable hugepages */
  struct file*          thc_efct_memfd;
  /* byte offset in thc_efct_memfd of the next hugepage to allocate */
  off_t                 thc_efct_memfd_off;

  ci_waitable_t         ready_list_waitqs[CI_CFG_N_READY_LISTS];
  ci_dllist             os_ready_lists[CI_CFG_N_READY_LISTS];
  spinlock_t            os_ready_list_lock;

  struct oo_filter_ns*  filter_ns;
  /* X3 only: an 'appropriate' affinity mask for the application(s) using this
   * stack, as a hint for which rxq to prefer (in the absence of any more
   * explicit constraints from the user) */
  struct cpumask        filter_irqmask;

  uint16_t*             tproxy_ifindex;
  int                   tproxy_ifindex_count;

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  /* The available ephemeral ports for active wilds are maintained in a hash
   * table keyed by local IP address.  If the stack is clustered, then this
   * table is shared by all stacks in the cluster. */
  struct efab_ephemeral_port_head* trs_ephem_table;
  uint32_t                         trs_ephem_table_entries;
  /* We also need to remember the point in each list beyond which the ports
   * have already been consumed.  We use a hash table keyed in the same way.
   * N.B.: While the table of ports may be shared between stacks, the tracking
   * of consumed ports is always per-stack. */
  struct efab_ephemeral_port_head* trs_ephem_table_consumed;
#endif

  /* Allocations performed by onload_zc_register_buffers */
  struct mutex usermem_mutex;
  uint64_t usermem_prev_id;
  struct tcp_helper_usermem* usermem;

  struct oo_icmp_msg* icmp_msg;
  int icmp_msg_n;
} tcp_helper_resource_t;


#define NI_OPTS_TRS(trs) (NI_OPTS(&(trs)->netif))

#define netif2tcp_helper_resource(ni)                   \
  CI_CONTAINER(tcp_helper_resource_t, netif, (ni))

#ifdef NDEBUG
#define TCP_HELPER_RESOURCE_ASSERT_VALID(trs, rc_mbz)
#else
extern void tcp_helper_resource_assert_valid(tcp_helper_resource_t*,
                                             int ul_rc_is_zero,
                                             const char *file, int line);
#define TCP_HELPER_RESOURCE_ASSERT_VALID(trs, ul_rc_mbz) \
    tcp_helper_resource_assert_valid(trs, ul_rc_mbz, __FILE__, __LINE__)
#endif


 /*--------------------------------------------------------------------
 *
 * tcp_helper_endpoint_t
 *
 *--------------------------------------------------------------------*/

/*! Information about endpoint accessible to kernel only */
struct tcp_helper_endpoint_s {

  /*! TCP helper resource we are a part of */
  tcp_helper_resource_t * thr;

  /*! Endpoint ID */
  oo_sp id;

  /*! Per-socket state for the filter manager. */
  struct oof_socket oofilter;

  /*! OS socket responsible for port reservation; may differ from os_socket
   * (for accepted socket) and is set/cleared together with filters.
   * Concurrency control is via atomic exchange (oo_file_xchg()).
   */
  struct file* os_port_keeper;

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /*! link so we can be in the list of endpoints to be closed in the future */
  ci_sllink tobe_closed;
#endif

  /* Link field when queued for non-atomic work. */
  ci_sllink non_atomic_link;

  /*! Links of the list with endpoints with pinned pages */
  ci_dllink ep_with_pinned_pages;
  /*! List of pinned pages */
  ci_dllist pinned_pages;
  /*! Number of pinned pages */
  unsigned int n_pinned_pages;

  /*! Head of the waitqueue */
  ci_waitable_t waitq;			

  /* IRQ lock to protect os_socket.
   * It is not ci_irqlock_t, because ci_irqlock_t is BH lock, but we need
   * IRQ lock here.  This lock is used from Linux wake up callback, and
   * __wake_up() function calls spin_lock_irqsave() before calling
   * callbacks. */
  spinlock_t lock;

  /*!< OS socket that backs this user-level socket.  May be NULL (not all
   * socket types have an OS socket).
   * os_socket and os_sock_pt should be changed under ep->lock only.
   */
  struct file* os_socket;

  /*!< Used to poll OS socket for OS events. */
  struct oo_os_sock_poll os_sock_poll;

  struct fasync_struct* fasync_queue;

  /*! Link for the wakeup list.  This *must* be reset to zero when not in
  ** use.
  */
  tcp_helper_endpoint_t* wakeup_next;

  /*! Atomic endpoint flags not visible for UL. */
  volatile ci_uint32 ep_aflags;
#define OO_THR_EP_AFLAG_PEER_CLOSED    0x2  /* Used for pipe */
#if ! CI_CFG_UL_INTERRUPT_HELPER
#define OO_THR_EP_AFLAG_NON_ATOMIC     0x4  /* On the non-atomic list */
#endif
#define OO_THR_EP_AFLAG_CLEAR_FILTERS  0x8  /* Needs filters clearing */
#define OO_THR_EP_AFLAG_NEED_FREE      0x10 /* Endpoint to be freed */
#define OO_THR_EP_AFLAG_OS_NOTIFIER    0x20 /* Pollwait registration for os */
#define OO_THR_EP_AFLAG_TCP_OFFLOAD_ISN 0x40 /* Send sync_stream to plugin */

  struct ci_private_s* alien_ref;

  struct {
    ci_dllink os_ready_link;
  } epoll[CI_CFG_N_READY_LISTS];

  /*! Back pointer to handle cases where cleaning up requires
  **  a file object, and not a handle, because all handles
  *   have been closed by that point.
  *   Note: this is a weak pointer and does not refcount the file.
  */
  ci_os_file file_ptr;

#if CI_CFG_TCP_OFFLOAD_RECYCLER
  ci_uint32 plugin_stream_id[CI_CFG_MAX_INTERFACES];
  ci_uint64 plugin_ddr_base[CI_CFG_MAX_INTERFACES];
  ci_uint64 plugin_ddr_size[CI_CFG_MAX_INTERFACES];
#endif
};


#ifdef __KERNEL__

#ifdef EFRM_DO_NAMESPACES

static inline struct pid_namespace*
ci_get_pid_ns(struct nsproxy* proxy)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0))
  return proxy->pid_ns_for_children;
#else
  return proxy->pid_ns;
#endif
}

/* Return the PID namespace in which the given ci_netif lives.
 *
 * Note that for the lifetime of the stack, thr->nsproxy is a counted
 * reference, therefore it can't become NULL while this stack is still
 * alive. */
ci_inline struct pid_namespace* ci_netif_get_pidns(ci_netif* ni)
{
  tcp_helper_resource_t* thr = netif2tcp_helper_resource(ni);
  return thr->pid_ns;
}

/* Log an error and return failure if the current process is not in
 * the right namespaces to operate on the given stack. */
ci_inline int ci_netif_check_namespace(ci_netif* ni)
{
  tcp_helper_resource_t* thr = netif2tcp_helper_resource(ni);
  if( ni == NULL ) {
    ci_log("In ci_netif_check_namespace() with ni == NULL");
    return -EINVAL;
  }
  if( current == NULL ) {
    ci_log("In ci_netif_check_namespace() outside process context");
    return -EINVAL;
  }
  if( current->nsproxy == NULL ) {
    ci_log("In ci_netif_check_namespace() without valid namespaces");
    return -EINVAL;
  }
  if( (thr->net_ns != current->nsproxy->net_ns) ||
      (thr->pid_ns != ci_get_pid_ns(current->nsproxy)) )
  {
    ci_log("NAMESPACE MISMATCH: pid %d accessed a foreign stack",
           current->pid);
    return -EINVAL;
  }
  return 0;
}

#endif /* defined(EFRM_DO_NAMESPACES) */

/* Look up a PID in this ci_netif's PID namespace. Must be called with
 * the tasklist_lock or rcu_read_lock() held. */
ci_inline struct pid* ci_netif_pid_lookup(ci_netif* ni, pid_t pid)
{
#ifdef EFRM_DO_NAMESPACES
  struct pid_namespace* ns = ci_netif_get_pidns(ni);
  return find_pid_ns(pid, ns);
#else
  return find_vpid(pid);
#endif
}

#if CI_CFG_TCP_OFFLOAD_RECYCLER
ci_inline bool ci_netif_tcp_plugin_uses_p2h(ci_netif* ni, int intf_i)
{
  ci_assert(ni->nic_hw[intf_i].plugin_rx);
  /* The plugin design using P2H doesn't exist yet. */
  return false;
}
#endif

#endif /* defined(__KERNEL__) */


#endif /* __CI_DRIVER_EFAB_TCP_HELPER_H__ */
/*! \cidoxg_end */
