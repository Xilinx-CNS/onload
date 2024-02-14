/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Definition of ci_netif etc.
**   \date  2006/06/05
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_IP_TYPES_H__
#define __CI_INTERNAL_IP_TYPES_H__

/*
** READ ME FIRST please.
**
** This header contains type definitions for the Etherfabric TCP/IP stack
** that do not form part of the state of the stack.  ie. These types are
** part of the support and infrastructure.
**
** The only stuff that may appear here is types and data structures,
** constants associated with fields in those data structures and
** documentation.
**
** NO CODE IN THIS FILE PLEASE.
*/

/*!
** ci_netif_nic_t
**
** The portion of a netif that corresponds to H/W resources and must be
** replicated per NIC.
*/
typedef struct ci_netif_nic_s {
  ef_vi                      vis[CI_MAX_VIS_PER_INTF];
#if CI_CFG_PIO
  ef_pio                     pio;
#endif // CI_CFG_PIO
#ifdef __KERNEL__
  struct oo_iobufset** pkt_rs;
#endif
#if ! defined(__KERNEL__) && CI_CFG_WANT_BPF_NATIVE
#define OO_HAS_POLL_IN_KERNEL
  ci_uint8              poll_in_kernel;
#endif
#if CI_CFG_TCP_OFFLOAD_RECYCLER
#ifdef __KERNEL__
#define INVALID_PLUGIN_HANDLE              (~0u)
  struct efrm_ext*           plugin_rx;
  ci_uint32                  plugin_rx_app_id;
  struct efrm_ext*           plugin_tx;
  ci_uint32                  plugin_tx_region_id;
#endif
  volatile void*             plugin_io;
#endif
} ci_netif_nic_t;


#ifdef __KERNEL__
struct tcp_helper_endpoint_s;
struct oof_cb_sw_filter_op;
#endif
struct oo_cplane_handle;

/* Non-shared packet buffer set structures */
#ifdef __KERNEL__
/* For eachone packet set, we store its pages */
typedef struct oo_buffer_pages* ci_pkt_bufs;
#else
/* For each packet set we have a pointer returned by mmap() */
typedef char* ci_pkt_bufs;
#endif

#ifndef __KERNEL__
struct ci_extra_ep {
  /* stores the current process cached FD to the endpoint or CI_FD_BAD */
  ci_fd_t fd;
};
#endif


/* Non-shared data structure for ringbuffer. */
struct oo_ringbuffer {
#ifdef __KERNEL__
  /* We need a trusted value of the ringbuffer sizes to use from kernel. */
  ci_uint32 mask;
  ci_uint32 stride;
#endif
#if OO_DO_STACK_POLL
  const char* name;
#endif
  struct oo_ringbuffer_state* state;
#ifndef __KERNEL__
  const
#endif
        char* data;
};


/*!
** ci_netif
**
** This is the top-level representation of an Etherfabric stack.  It is the
** key-stone that provides access to the state of the stack.
**
** This data-structure is not shared: There is one copy per userlevel
** address space, and one in the kernel.  Therefore it does not contain any
** of the "state" of the stack, merely description of whether that state
** is.
*/
struct ci_netif_s {
  ci_magic_t           magic;
  efrm_nic_set_t       nic_set; 
  int                  nic_n;
  /* resources */
  ci_netif_nic_t       nic_hw[CI_CFG_MAX_INTERFACES];

  ci_netif_state*      state;

#ifndef __KERNEL__
  unsigned             future_intf_mask;
  /* Use ci_netif_get_driver_handle() rather than this directly. */
  ef_driver_handle     driver_handle;
  unsigned             mmap_bytes;
  char*                io_ptr;
#if CI_CFG_PIO
  uint8_t*             pio_ptr;
  ci_uint32            pio_bytes_mapped;
#endif
#if CI_CFG_CTPIO
  uint8_t*             ctpio_ptr;
  ci_uint32            ctpio_bytes_mapped;
#endif
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  uint8_t*             plugin_ptr;
#endif
  char*                buf_ptr;
#endif
  struct efab_efct_rxq_uk_shm_base* efct_shm_ptr;

#ifdef __ci_driver__
  cicp_hwport_mask_t   hwport_mask; /* hwports accelerated by the stack */
  ci_int8              hwport_to_intf_i[CI_CFG_MAX_HWPORTS];
  ci_int8              intf_i_to_hwport[CI_CFG_MAX_INTERFACES];
  /* These uid_t are in the kernel init namespace */
  uid_t                kuid;
  uid_t                keuid;

  struct oo_shmbuf     shmbuf; /* shared state storage */
  /* Size of continuous chunks: */
#define OO_SHARED_BUFFER_CHUNK_ORDER (PMD_SHIFT - PAGE_SHIFT)
#define OO_SHARED_BUFFER_CHUNK_SIZE  (1ULL << PMD_SHIFT)
  /* With CI_CFG_NETIF_MAX_ENDPOINTS_MAX = 2^21,
   * there can't be more than 2^11 chunks of socket buffers
   * (+ a few chunks for the stack state itsefl). */
#endif

  struct oo_cplane_handle *cplane;
  struct oo_cplane_handle *cplane_init_net;

#ifndef __KERNEL__
  /* Currently, we do not use timesync from the common code (i.e. from the
   * code which is compiled in both kernel and user space.
   * So, kernel code uses efab_tcp_driver.timesync,
   * and UL code uses ni->timesync. */
  struct oo_timesync   *timesync;
#endif
    
#ifdef __KERNEL__
  /** eplock resource. Note that this has the SAME lifetime as [lock]. 
   *  The reference on this object is taken when the lock is created -
   *  and no other reference is taken. */
  eplock_helper_t      eplock_helper;
#endif

  ci_netif_filter_table* filter_table;
  ci_netif_filter_table_entry_ext* filter_table_ext;
#if CI_CFG_IPV6
  ci_ip6_netif_filter_table* ip6_filter_table;
#endif
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  struct oo_p_dllink* active_wild_table;
#endif
  ci_tcp_prev_seq_t*   seq_table;

  struct oo_deferred_pkt* deferred_pkts;

#ifdef __ci_driver__
  unsigned             pkt_sets_n;
  unsigned             pkt_sets_max;
  ci_uint32            ep_ofs;           /**< Copy from ci_netif_state_s */

  /*! Trusted per-socket state. */
  struct tcp_helper_endpoint_s**  ep_tbl;
  ci_uint32                       ep_tbl_n;
  unsigned                        ep_tbl_max;

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* Number of orphaned sockets which prevent the stack from destroying.
   *
   * In case of ulhelper build profile we use a similar field in the netif
   * state.
   */
  ci_uint32 n_ep_orphaned;
#endif
#endif

#if CI_CFG_UL_INTERRUPT_HELPER
  struct oo_ringbuffer closed_eps;
  struct oo_ringbuffer sw_filter_ops;
#endif

  /* This is pointer to the shared state of packet sets */
  oo_pktbuf_manager*    packets;
  /* And this is non-shared array for UL- or kernel- specific data
   * about packet sets */
  ci_pkt_bufs*          pkt_bufs;
  /* See also oo_pktbuf_set and the implementation of pkt_dma_addr(). This
   * array stores the 'base address' of each packet buffer page allocation
   * in terms that the NIC understands (i.e. for use in rxq and txq entries),
   * hence there are different values for each NIC. Addresses of specific
   * packets within that page can be trivially linearly computed. The size of
   * a page is not a constant across pktbuf sets but is a constant within one
   * (= oo_pktbuf_set::page_order), so the actual calculation of an address
   * is mildly complex. */
  ef_addr*              dma_addrs;
#ifdef __KERNEL__
  /* Next free space in dma_addrs, i.e. the index after the last used one.
   * We never need to free dma_addrs entries, so this is the implementation of
   * an allocator for that memory */
  ci_uint32             dma_addr_next;
#endif

#ifndef __ci_driver__
  /* for table of active UL netifs (unix/netif_init.c) */
  ci_dllink            link;
  
  /* Number of active endpoints this process has in this UL netif.  Used as a
  ** reference count to govern the lifetime of the UL netif.
  */
  oo_atomic_t          ref_count;
  unsigned             cached_count;
#endif /* __ci_driver__ */

  /* General flags */  
  /* This field must be protected by the netif lock.
   */
  unsigned             flags;
  /* Set to request allocation of scalable filters at stack creation
   * This flag is not stored in netif state.  It is passed to
   * tcp_helper_resource_rm_alloc_proxy function through ioctl.
   */
# define CI_NETIF_FLAG_DO_ALLOCATE_SCALABLE_FILTERS_RSS 0x2
  /* can be the same as the above */
# define CI_NETIF_FLAG_DO_DROP_SHARED_LOCAL_PORTS \
    CI_NETIF_FLAG_DO_ALLOCATE_SCALABLE_FILTERS_RSS


#ifndef __KERNEL__

  /* netif was once (and maybe still is) shared between multiple processes */
# define CI_NETIF_FLAGS_SHARED           0x10
  /* netif is protected from destruction with an extra ref_count */
# define CI_NETIF_FLAGS_DTOR_PROTECTED   0x20
  /* Don't use this stack for new sockets unless name says otherwise */
# define CI_NETIF_FLAGS_DONT_USE_ANON    0x40
  /* Packets have been prefaulted */
# define CI_NETIF_FLAGS_PREFAULTED       0x80

#else

  /* netif is a kernel-only stack and thus is trusted */
# define CI_NETIF_FLAGS_IS_TRUSTED       0x100
  /* Currently being used from a driverlink context */
# define CI_NETIF_FLAG_IN_DL_CONTEXT     0x400
#if CI_CFG_PKTS_AS_HUGE_PAGES
  /* Huge pages packet allocation have failed */
#define CI_NETIF_FLAG_HUGE_PAGES_FAILED  0x2000
#endif
  /* Shared state wedged */
#define CI_NETIF_FLAG_WEDGED             0x4000
  /* May inject packets to kernel */
#define CI_NETIF_FLAG_MAY_INJECT_TO_KERNEL 0x8000
/* one of the NICs is AF_XDP */
#define CI_NETIF_FLAG_AF_XDP               0x10000
/* one of the NICs is EFCT */
#define CI_NETIF_FLAG_EFCT                 0x20000
/* these architecture cannot handle polling in atomic */
#define CI_NETIF_FLAGS_AVOID_ATOMIC \
        (CI_NETIF_FLAG_AF_XDP|\
         CI_NETIF_FLAG_EFCT)

#endif

#ifdef __KERNEL__
  ci_netif_config_opts opts;

  /* Stack overflow avoidance, used from allocate_vi(). */
  ci_uint64 vi_data[10];

  /* List of postponed sw filter updates and its lock */
  /* It is the innermost lock - no other locks, no kfree(), etc
   * could be used under it. */
  spinlock_t swf_update_lock; /* innermost lock */
  /* The first and the last entry in the postponed
   * sw filter update list. */
  struct oof_cb_sw_filter_op *swf_update_first, *swf_update_last;
#endif

  /* Used from ci_netif_poll_evq() only.  Moved here to avoid stack
   * overflow. */
  ef_request_id tx_events[EF_VI_TRANSMIT_BATCH];
  ef_request_id rx_events[EF_VI_RECEIVE_BATCH];
  /* See also copy in ci_netif_state. */
  unsigned      error_flags;

#ifndef __KERNEL__
#define ID_TO_EPS(ni,id) (&(ni)->eps[id])
#define S_TO_EPS(ni,s) ID_TO_EPS(ni,S_ID(s))
#define SC_TO_EPS(ni,s) ID_TO_EPS(ni,SC_ID(s))
  struct ci_extra_ep* eps;
#endif
};


/*!
** citp_socket
**
** This is the keystone that provides access to a socket.  It provides
** access to the stack the socket lies in, and identifies the socket within
** that stack.
*/
struct citp_socket_s {
  ci_netif*            netif;
  ci_sock_cmn*         s;
};


/* To avoid complicated compat code, use simplified msghdr when
 * compiling in-kernel  */
#ifndef __KERNEL__
typedef struct msghdr ci_msghdr;
#else
typedef struct {
  ci_iovec*     msg_iov;
  unsigned long msg_iovlen;
} ci_msghdr;
#endif


/* Arguments to ci_tcp_recvmsg(). */
typedef struct ci_tcp_recvmsg_args {
  ci_netif*      ni;
  ci_tcp_state*  ts;
  ci_msghdr*     msg;
  int            flags;
} ci_tcp_recvmsg_args;

/* Arguments to ci_udp_sendmsg and ci_udp_recvmsg */
typedef struct ci_udp_iomsg_args {
  ci_udp_state  *us;
  ci_netif      *ni;
#ifndef __KERNEL__
  citp_socket   *ep;
  ci_fd_t        fd;
#else
  /* This one is required to call poll on filp from
   * recv */
  struct file   *filp;
  /* stored to speed up os socket recv */
#endif
} ci_udp_iomsg_args;

struct ci_netif_poll_state {
  oo_pkt_p  tx_pkt_free_list;
  oo_pkt_p* tx_pkt_free_list_insert;
  int       tx_pkt_free_list_n;
};



#endif  /* __CI_INTERNAL_IP_TYPES_H__ */
/*! \cidoxg_end */
