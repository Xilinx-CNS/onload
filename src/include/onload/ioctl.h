/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
#ifndef __ONLOAD_IOCTL_H__
#define __ONLOAD_IOCTL_H__

#include <ci/internal/transport_config_opt.h>
#include <linux/version.h>
#include <onload/ioctl_base.h>
#include <onload/ioctl_dshm.h>
#include <cplane/ioctl.h>


#define ONLOADFS_MAGIC 0xefab010d

/* A fixed code for onload version check not used in past
 * releases for any other purposes, do not modify */
#define OO_OP_CHECK_VERSION 0xFF


/*************************************************************************
 * ATTENTION! ACHTUNG! ATENCION!                                         *
 * This enum MUST be synchronised with the oo_operations table!          *
 *************************************************************************/

/* OS-independent operations enum */
enum {
  /* Debug ops */
  OO_OP_DBG_GET_STACK_INFO = OO_OP_DSHM_END,
#define OO_IOC_DBG_GET_STACK_INFO   OO_IOC_RW(DBG_GET_STACK_INFO, \
                                              ci_netif_info_t)
  OO_OP_DBG_WAIT_STACKLIST_UPDATE,
#define OO_IOC_DBG_WAIT_STACKLIST_UPDATE \
                                OO_IOC_RW(DBG_WAIT_STACKLIST_UPDATE, \
                                          struct oo_stacklist_update)
#if ! CI_CFG_UL_INTERRUPT_HELPER
  OO_OP_DEBUG_OP,
#define OO_IOC_DEBUG_OP         OO_IOC_RW(DEBUG_OP, ci_debug_onload_op_t)
#endif

  /* Logging */
  OO_OP_PRINTK,
#define OO_IOC_PRINTK           OO_IOC_W(PRINTK, char[CI_LOG_MAX_LINE])

  /* netif & EP handling */
  OO_OP_RESOURCE_ONLOAD_ALLOC, /*< allocate resources for netif;
                                ci_resource_onload_alloc_t in/out */
#define OO_IOC_RESOURCE_ONLOAD_ALLOC    OO_IOC_RW(RESOURCE_ONLOAD_ALLOC, \
                                                  ci_resource_onload_alloc_t)
  OO_OP_EP_INFO,   /*< Get endpoint information: TCP Helper handle and endpoint
                    identifier; ci_ep_info_t out */
#define OO_IOC_EP_INFO          OO_IOC_R(EP_INFO, ci_ep_info_t)
  OO_OP_VI_STATS_QUERY, /* get VI stats cf ef_vi_stats_query */
#define OO_IOC_VI_STATS_QUERY OO_IOC_RW(VI_STATS_QUERY, ci_vi_stats_query_t)

  OO_OP_CLONE_FD,              /*< Clone onload device fd; int out */
#define OO_IOC_CLONE_FD         OO_IOC_RW(CLONE_FD, ci_clone_fd_t)
  OO_OP_KILL_SELF_SIGPIPE,      /*< Send a signal to self */
#define OO_IOC_KILL_SELF_SIGPIPE    OO_IOC_NONE(KILL_SELF_SIGPIPE)

  /* TCP helper operations */
  OO_OP_TCP_SOCK_SLEEP,
#define OO_IOC_TCP_SOCK_SLEEP   OO_IOC_RW(TCP_SOCK_SLEEP, oo_tcp_sock_sleep_t)
  OO_OP_WAITABLE_WAKE,
#define OO_IOC_WAITABLE_WAKE    OO_IOC_W(WAITABLE_WAKE, oo_waitable_wake_t)

  /* Filter operations */
  OO_OP_EP_FILTER_SET,
#define OO_IOC_EP_FILTER_SET    OO_IOC_W(EP_FILTER_SET, oo_tcp_filter_set_t)
  OO_OP_EP_FILTER_CLEAR,
#define OO_IOC_EP_FILTER_CLEAR  OO_IOC_W(EP_FILTER_CLEAR, oo_tcp_filter_clear_t)
  OO_OP_EP_FILTER_MCAST_ADD,
#define OO_IOC_EP_FILTER_MCAST_ADD  OO_IOC_W(EP_FILTER_MCAST_ADD, \
                                             oo_tcp_filter_mcast_t)
  OO_OP_EP_FILTER_MCAST_DEL,
#define OO_IOC_EP_FILTER_MCAST_DEL  OO_IOC_W(EP_FILTER_MCAST_DEL, \
                                             oo_tcp_filter_mcast_t)
  OO_OP_EP_FILTER_DUMP,
#define OO_IOC_EP_FILTER_DUMP       OO_IOC_W(EP_FILTER_DUMP,            \
                                             oo_tcp_filter_dump_t)

  OO_OP_TCP_SOCK_LOCK,
#define OO_IOC_TCP_SOCK_LOCK        OO_IOC_W(TCP_SOCK_LOCK, ci_int32)
  OO_OP_TCP_SOCK_UNLOCK,
#define OO_IOC_TCP_SOCK_UNLOCK      OO_IOC_W(TCP_SOCK_UNLOCK, ci_int32)
  OO_OP_TCP_PKT_WAIT,
#define OO_IOC_TCP_PKT_WAIT         OO_IOC_W(TCP_PKT_WAIT, ci_int32)
  OO_OP_TCP_MORE_BUFS,
#define OO_IOC_TCP_MORE_BUFS        OO_IOC_NONE(TCP_MORE_BUFS)
  OO_OP_TCP_MORE_SOCKS,
#define OO_IOC_TCP_MORE_SOCKS       OO_IOC_NONE(TCP_MORE_SOCKS)

#if CI_CFG_FD_CACHING
  OO_OP_TCP_CLEAR_EPCACHE,
#define OO_IOC_TCP_CLEAR_EPCACHE  OO_IOC_NONE(TCP_CLEAR_EPCACHE)
#endif

  OO_OP_STACK_ATTACH,
#define OO_IOC_STACK_ATTACH         OO_IOC_RW(STACK_ATTACH, \
                                              oo_stack_attach_t)
  OO_OP_INSTALL_STACK_BY_ID,
#define OO_IOC_INSTALL_STACK_BY_ID  OO_IOC_W(INSTALL_STACK_BY_ID, ci_uint32)

  OO_OP_SOCK_ATTACH,
#define OO_IOC_SOCK_ATTACH          OO_IOC_RW(SOCK_ATTACH, \
                                              oo_sock_attach_t)

  OO_OP_TCP_ACCEPT_SOCK_ATTACH,
#define OO_IOC_TCP_ACCEPT_SOCK_ATTACH   OO_IOC_RW(TCP_ACCEPT_SOCK_ATTACH, \
                                              oo_tcp_accept_sock_attach_t)

  OO_OP_PIPE_ATTACH,
#define OO_IOC_PIPE_ATTACH          OO_IOC_RW(PIPE_ATTACH, \
                                              oo_pipe_attach_t)
#if CI_CFG_FD_CACHING
  OO_OP_SOCK_DETACH,
#define OO_IOC_SOCK_DETACH          OO_IOC_RW(SOCK_DETACH, \
                                              oo_sock_attach_t)
  OO_OP_SOCK_ATTACH_TO_EXISTING,
#define OO_IOC_SOCK_ATTACH_TO_EXISTING OO_IOC_RW(SOCK_ATTACH_TO_EXISTING, \
                                                 oo_sock_attach_t)
#endif

  OO_OP_CLOSE,
#define OO_IOC_CLOSE                OO_IOC_W(CLOSE, ci_uint32)

  /* OS-specific TCP helper operations */

  OO_OP_OS_SOCK_CREATE_AND_SET,
#define OO_IOC_OS_SOCK_CREATE_AND_SET OO_IOC_W(OS_SOCK_CREATE_AND_SET,  \
                                              oo_tcp_create_set_t)
  OO_OP_OS_SOCK_FD_GET,
#define OO_IOC_OS_SOCK_FD_GET       OO_IOC_RW(OS_SOCK_FD_GET,           \
                                              oo_os_sock_fd_get_t)
  OO_OP_OS_SOCK_SENDMSG,
#define OO_IOC_OS_SOCK_SENDMSG      OO_IOC_W(OS_SOCK_SENDMSG,           \
                                             oo_os_sock_sendmsg_t)
  OO_OP_OS_SOCK_RECVMSG,
#define OO_IOC_OS_SOCK_RECVMSG      OO_IOC_RW(OS_SOCK_RECVMSG,          \
                                              oo_os_sock_recvmsg_t)
  OO_OP_OS_SOCK_ACCEPT,
#define OO_IOC_OS_SOCK_ACCEPT       OO_IOC_RW(OS_SOCK_ACCEPT,           \
                                              oo_os_sock_accept_t)
  OO_OP_TCP_ENDPOINT_SHUTDOWN,
#define OO_IOC_TCP_ENDPOINT_SHUTDOWN    OO_IOC_W(TCP_ENDPOINT_SHUTDOWN, \
                                                 oo_tcp_endpoint_shutdown_t)
  OO_OP_TCP_BIND_OS_SOCK,
#define OO_IOC_TCP_BIND_OS_SOCK     OO_IOC_RW(TCP_BIND_OS_SOCK, \
                                              oo_tcp_bind_os_sock_t)
  OO_OP_TCP_LISTEN_OS_SOCK,
#define OO_IOC_TCP_LISTEN_OS_SOCK   OO_IOC_W(TCP_LISTEN_OS_SOCK, ci_int32)
  OO_OP_TCP_HANDOVER,
#define OO_IOC_TCP_HANDOVER         OO_IOC_RW(TCP_HANDOVER, ci_int32)

  OO_OP_FILE_MOVED,
#define OO_IOC_FILE_MOVED           OO_IOC_RW(FILE_MOVED, ci_int32)

  OO_OP_TCP_CLOSE_OS_SOCK,
#define OO_IOC_TCP_CLOSE_OS_SOCK    OO_IOC_W(TCP_CLOSE_OS_SOCK, oo_sp)

  OO_OP_OS_POLLERR_CLEAR,
#define OO_IOC_OS_POLLERR_CLEAR     OO_IOC_W(OS_POLLERR_CLEAR, oo_sp)

#if ! CI_CFG_UL_INTERRUPT_HELPER
  OO_OP_EPLOCK_WAKE,
#define OO_IOC_EPLOCK_WAKE          OO_IOC_NONE(EPLOCK_WAKE)
#else
  OO_OP_EPLOCK_WAKE_AND_DO,
#define OO_IOC_EPLOCK_WAKE_AND_DO   OO_IOC_W(EPLOCK_WAKE_AND_DO, ci_uint64)
#endif
  OO_OP_EPLOCK_LOCK_WAIT,
#define OO_IOC_EPLOCK_LOCK_WAIT     OO_IOC_NONE(EPLOCK_LOCK_WAIT)
  
  OO_OP_INSTALL_STACK,
#define OO_IOC_INSTALL_STACK        OO_IOC_W(INSTALL_STACK,             \
                                             struct oo_op_install_stack)

#if ! CI_CFG_UL_INTERRUPT_HELPER
  OO_OP_RSOP_DUMP,
#define OO_IOC_RSOP_DUMP            OO_IOC_NONE(RSOP_DUMP)
#endif

  OO_OP_GET_ONLOADFS_DEV,
#define OO_IOC_GET_ONLOADFS_DEV     OO_IOC_R(GET_ONLOADFS_DEV, ci_uint32)

#if CI_CFG_ENDPOINT_MOVE
  OO_OP_TCP_LOOPBACK_CONNECT,
#define OO_IOC_TCP_LOOPBACK_CONNECT OO_IOC_RW(TCP_LOOPBACK_CONNECT, \
                                              struct oo_op_loopback_connect)

  OO_OP_MOVE_FD,
#define OO_IOC_MOVE_FD              OO_IOC_W(MOVE_FD, \
                                             ci_fixed_descriptor_t)

  OO_OP_EP_REUSEPORT_BIND,
#define OO_IOC_EP_REUSEPORT_BIND                        \
  OO_IOC_W(EP_REUSEPORT_BIND, oo_tcp_reuseport_bind_t)
  OO_OP_CLUSTER_DUMP,
#define OO_IOC_CLUSTER_DUMP       OO_IOC_W(CLUSTER_DUMP,            \
                                             oo_cluster_dump_t)
#endif
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  OO_OP_ALLOC_ACTIVE_WILD,
#define OO_IOC_ALLOC_ACTIVE_WILD  OO_IOC_W(ALLOC_ACTIVE_WILD, \
                                           oo_alloc_active_wild_t)
#endif

  OO_OP_VETH_ACCELERATION_ENABLED,
#define OO_IOC_VETH_ACCELERATION_ENABLED OO_IOC_NONE(VETH_ACCELERATION_ENABLED)

#if CI_CFG_WANT_BPF_NATIVE
  OO_OP_EVQ_POLL,
#define OO_IOC_EVQ_POLL         OO_IOC_W(EVQ_POLL, ci_uint32)
#endif


  OO_OP_ZC_REGISTER_BUFFERS,
#define OO_IOC_ZC_REGISTER_BUFFERS   OO_IOC_RW(ZC_REGISTER_BUFFERS, \
                                               oo_zc_register_buffers_t)

  OO_OP_ZC_UNREGISTER_BUFFERS,
#define OO_IOC_ZC_UNREGISTER_BUFFERS OO_IOC_W(ZC_UNREGISTER_BUFFERS, ci_uint64)

#if CI_CFG_TCP_OFFLOAD_RECYCLER
  OO_OP_TCP_OFFLOAD_SET_ISN,
#define OO_IOC_TCP_OFFLOAD_SET_ISN OO_IOC_W(TCP_OFFLOAD_SET_ISN, \
                                            ci_tcp_offload_set_isn_t)

  OO_OP_TCP_OFFLOAD_GET_STREAM_ID,
#define OO_IOC_TCP_OFFLOAD_GET_STREAM_ID OO_IOC_RW(TCP_OFFLOAD_GET_STREAM_ID, \
                                            ci_tcp_offload_get_stream_id_t)
#endif

#if CI_CFG_UL_INTERRUPT_HELPER
  /* Wait for an interrupt */
  OO_OP_WAIT_FOR_INTERRUPT,
#define OO_IOC_WAIT_FOR_INTERRUPT OO_IOC_RW(WAIT_FOR_INTERRUPT, struct oo_ulh_waiter)
  OO_OP_WAKEUP_WAITERS,
#define OO_IOC_WAKEUP_WAITERS     OO_IOC_W(WAKEUP_WAITERS, struct oo_wakeup_eps)
#endif

  OO_OP_AF_XDP_KICK,
#define OO_IOC_AF_XDP_KICK OO_IOC_W(AF_XDP_KICK, ci_int32)

  OO_OP_CONTIG_END,  /* This is the last in range of contigous opcodes */

  /* Here come only placeholder for operations with arbitrary codes */
  OO_OP_FIRST_PLACEHOLDER = OO_OP_CONTIG_END,

  /* And version check is a special case - arbitrary code is used.
   * However, we leave placeholder, to reserve space in the table -
   * we restart from OO_OP_FIRST_PLACEHOLDER (which == OO_OP_CONTIG_END)
   * to avoid leaving gap in there. */
  OO_OP_CHECK_VERSION_PLACEHOLDER = OO_OP_FIRST_PLACEHOLDER,
#define OO_IOC_CHECK_VERSION   OO_IOC_W(CHECK_VERSION, \
                                        oo_version_check_t)
  OO_OP_END  /* This had better be last! */
};

CI_BUILD_ASSERT(OO_OP_CHECK_VERSION >= OO_OP_CONTIG_END);

#endif  /* __ONLOAD_IOCTL_H__ */
