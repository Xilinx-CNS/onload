/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Interface for invoking misc ops on resources.
**   \date  2003/01/17
**    \cop  (c) 2003-2005 Level 5 Networks Limited.
**              2006 Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_onload  */

#ifndef __ONLOAD_COMMON_H__
#define __ONLOAD_COMMON_H__

#if 1 && defined(__CI_DRIVER_EFAB_OPERATIONS_H__)
#error "You should select one driver to talk with -- char or onload"
#endif

#include <ci/tools/sysdep.h> /* for memset */
#include <ci/internal/transport_config_opt.h>
#include <onload/primitive_types.h>
#include <ci/internal/transport_config_opt.h>
#include <ci/efrm/nic_set.h>
#include <ci/net/ethernet.h>
#include <onload/dshm.h>
#include <onload/signals.h> /* for OO_SIGHANGLER_DFL_MAX */
#include <cplane/cplane.h>
#include <ci/net/ipvx.h>
#include <onload/version.h>



/**********************************************************************
********************** Identifying address space **********************
**********************************************************************/

#define ci_addr_spc_id_set(p, v)                        \
  ((*(p)) = (ci_addr_spc_id_t)(ci_uintptr_t) (v))


/*----------------------------------------------------------------------------
 *
 *  OS device name used e.g registered unix char special device /dev/onload
 *
 *---------------------------------------------------------------------------*/

enum oo_device_type {
  OO_STACK_DEV,
  OO_EPOLL_DEV,
  OO_MAX_DEV /* not a device type */
};

#define OO_DEV_NAME  "onload"  

#define OO_EPOLL_DEV_NAME "onload_epoll"


/*! This data structure contains the arguments required to create a new
 *  tcp helper resource and the results that the allocation operation
 *  subsequently returns.
 */
typedef struct ci_resource_onload_alloc_s {
  ci_user_ptr_t           in_opts  CI_ALIGN(8);
  ci_uint16               in_flags;
  char                    in_version[OO_VER_STR_LEN + 1];
  char                    in_uk_intf_ver[CI_CHSUM_STR_LEN + 1];
  char                    in_name[CI_CFG_STACK_NAME_LEN + 1];
  int                     in_cluster_size;
  int                     in_cluster_restart;
  efrm_nic_set_t          out_nic_set;
  ci_uint32               out_netif_mmap_bytes;
} ci_resource_onload_alloc_t;


/*--------------------------------------------------------------------
 *
 * ci_user_context_t - u/l context saved with fd
 *
 *       int ci_save_user_context(ci_fd_t, ci_user_context_t*)
 *       int ci_get_user_context(ci_fd_t, ci_user_context_t*)
 *
 * Save a context of length 0 to delete a saved context.  Currently only
 * one context may be saved with any fd.
 *
 *--------------------------------------------------------------------*/

#define CI_MAX_SAVE_CONTEXT_LEN  1024

/*--------------------------------------------------------------------
 *
 * resource operations (ioctl for resources)
 *
 *--------------------------------------------------------------------*/

/* These are shared structures. They should not use "int", "long", etc
 * because kernel and userland may have different size for such types. */

typedef struct {
  oo_sp         sock_id;
  ci_bits       why;  /* 32 bits */
  ci_uint64     sleep_seq;
  ci_int32      lock_flags;
  ci_uint32     timeout_ms; /* IN/OUT */
  ci_user_ptr_t sig_state;
} oo_tcp_sock_sleep_t;

typedef struct {
  oo_sp         sock_id;
} oo_waitable_wake_t;

typedef struct {
  oo_sp             tcp_id;
  oo_sp             from_tcp_id;
  ci_ifid_t         bindto_ifindex;
} oo_tcp_filter_set_t;

typedef struct {
  char      cluster_name[CI_CFG_CLUSTER_NAME_LEN + 1];
  ci_int32  cluster_size;
  ci_uint32 cluster_restart_opt;
  ci_uint32 cluster_hot_restart_opt;
  ci_addr_t addr;
  ci_uint16 port_be16;
} oo_tcp_reuseport_bind_t;

typedef struct {
  oo_sp             tcp_id;
  ci_int32          need_update;
} oo_tcp_filter_clear_t;

typedef struct {
  oo_sp             tcp_id;
  ci_int32          addr;
  ci_ifid_t         ifindex;
} oo_tcp_filter_mcast_t;

typedef struct {
  ci_user_ptr_t buf;
  ci_int32      buf_len;
} oo_cluster_dump_t;

typedef struct {
  oo_sp         sock_id;
  ci_user_ptr_t buf;
  ci_int32      buf_len;
} oo_tcp_filter_dump_t;

typedef struct {
  oo_sp         	ep_id;
  ci_uint32		new_trs_id;
  oo_sp         	new_ep_id;
} oo_tcp_move_state_t;

typedef struct {
  ci_int32      level;
  ci_int32      optname;
  ci_user_ptr_t optval;
  ci_int32      optlen;
} oo_tcp_create_set_t;

typedef struct {
  oo_sp         sock_id;
  ci_user_ptr_t address; /* const struct sockaddr */
  ci_uint32     addrlen; /* IN: addrlen OUT: port */
} oo_tcp_bind_os_sock_t;

typedef struct {
  ci_user_ptr_t address; /* const struct sockaddr */
  ci_uint32     addrlen;
} oo_tcp_sockaddr_with_len_t;

typedef struct {
  ci_fixed_descriptor_t fd;     /* OUT */
  efrm_nic_set_t        out_nic_set;
  ci_uint32             out_map_size;
  ci_uint32             is_service;
} oo_stack_attach_t;

typedef struct {
  ci_uint32 stack_id;
  ci_uint32 is_service;
} oo_stack_lookup_and_attach_t;

typedef struct {
  ci_fixed_descriptor_t fd;     /* OUT */
  oo_sp                 ep_id;
  ci_int32              domain;
  ci_int32              type;
  ci_int32              padding;
} oo_sock_attach_t;

typedef struct {
  ci_fixed_descriptor_t fd;     /* OUT */
  oo_sp                 ep_id;
  ci_int32              type;
} oo_tcp_accept_sock_attach_t;

typedef struct {
  ci_uint64 base_ptr;
  ci_uint64 num_pages;
  ci_uint64 hw_addrs_ptr;
  ci_uint64 id;
} oo_zc_register_buffers_t;

typedef struct {
  ci_fixed_descriptor_t rfd, wfd;   /* OUT for Unix */
  oo_sp                 ep_id;
  ci_int32              flags;
} oo_pipe_attach_t;

typedef struct {
  ci_int32      bufs_num;
  ci_int32      bufs_start;
} oo_tcp_sock_more_pipe_bufs_t;

typedef struct {
  ci_int32          other_fd;
  ci_int32          other_pid;
  oo_sp             ep_id;
} oo_tcp_xfer_t;

typedef struct {
  ci_int32  sock_id;
  ci_int32  fd_out;
} oo_os_sock_fd_get_t;

typedef struct {
  ci_int32      sock_id;
  ci_int32      flags;
  ci_uint32     sizeof_ptr;
  ci_user_ptr_t msg_iov;
  ci_user_ptr_t msg_name;
  ci_user_ptr_t msg_control;
  ci_uint32     msg_iovlen;
  ci_uint32     msg_namelen;
  ci_uint32     msg_controllen;
} oo_os_sock_sendmsg_t;

typedef struct {
  ci_int32      sock_id;
  ci_int32      flags;
  ci_uint32     sizeof_ptr;
  ci_user_ptr_t msg;
  ci_user_ptr_t socketcall_args;
} oo_os_sock_sendmsg_raw_t;

typedef struct {
  ci_int32      sock_id;
  ci_uint32     sizeof_ptr;
  ci_user_ptr_t msg_iov;
  ci_user_ptr_t msg_name;
  ci_user_ptr_t msg_control;
  ci_uint32     msg_iovlen;
  ci_uint32     msg_namelen;
  ci_uint32     msg_controllen;
  ci_int32      flags;
  ci_int32      rc;
} oo_os_sock_recvmsg_t;

typedef struct {
  ci_int32      sock_id;
  ci_user_ptr_t addr;
  ci_user_ptr_t addrlen;
  ci_int32      flags;
  ci_int32      rc;
} oo_os_sock_accept_t;

typedef struct {
  oo_sp     sock_id;
  ci_uint32 how;
  ci_uint32 old_state;
} oo_tcp_endpoint_shutdown_t;

typedef struct {
  ci_uint32	pkt;
  ci_ifid_t	ifindex;
} cp_user_pkt_dest_ifid_t;


/* Flags & types.  It could be enum if enum had fixed size. */
typedef ci_uint16 oo_fd_flags;
/* File type: */
#define OO_FDFLAG_STACK          0x01
#define OO_FDFLAG_EP_TCP         0x02
#define OO_FDFLAG_EP_UDP         0x04
#define OO_FDFLAG_EP_PASSTHROUGH 0x08
#define OO_FDFLAG_EP_ALIEN       0x10
#define OO_FDFLAG_EP_PIPE_READ   0x20
#define OO_FDFLAG_EP_PIPE_WRITE  0x40
#define OO_FDFLAG_EP_MASK        0x7e
/* Replacement for "type" when it is not known, to be used as function
 * parameter only.
 */
#define OO_FDFLAG_REATTACH       0x80

/* This is Onload service like stackdump. */
#define OO_FDFLAG_SERVICE       0x100


#define OO_FDFLAG_TYPE_STR(flags) \
  (flags) & OO_FDFLAG_STACK ? "stack" :             \
  (flags) & OO_FDFLAG_EP_TCP ? "tcp" :              \
  (flags) & OO_FDFLAG_EP_UDP ? "udp" :              \
  (flags) & OO_FDFLAG_EP_PASSTHROUGH ? "os_sock" :  \
  (flags) & OO_FDFLAG_EP_ALIEN ? "moved" :          \
  (flags) & OO_FDFLAG_EP_PIPE_READ ? "piper" :      \
  (flags) & OO_FDFLAG_EP_PIPE_WRITE ? "pipew" : "?" \

#define OO_FDFLAG_FMT "0x%x %s %s"
#define OO_FDFLAG_ARG(flags) \
  (flags), OO_FDFLAG_TYPE_STR(flags), \
  (flags & OO_FDFLAG_SERVICE) ? "service" : "app"

typedef struct {
  oo_fd_flags            fd_flags;
  ci_uint32              resource_id;
  ci_uint32              mem_mmap_bytes;
  oo_sp                  sock_id;
} ci_ep_info_t;

typedef struct {
  ci_user_ptr_t stats_data;
  ci_uint32 intf_i;
  ci_uint32 data_len;
  ci_uint8 do_reset;
} ci_vi_stats_query_t;


typedef struct {
  ci_uint64             do_cloexec; /* it's u8 really, but we need to be compat */
  ci_fixed_descriptor_t fd;
} ci_clone_fd_t;


typedef struct {
  oo_sp ep_id;
  ci_uint32 isn;
} ci_tcp_offload_set_isn_t;

/* "Donation" shared memory ioctl structures. */

typedef struct {
  ci_addr_t      laddr;
} oo_alloc_active_wild_t;

/*--------------------------------------------------------------------
 *
 * Platform dependent IOCTLS
 *
 *--------------------------------------------------------------------*/

/* struct contains arguments for the trampoline register ioctl */
typedef struct ci_tramp_reg_args {
  ci_user_ptr_t trampoline_entry;
  ci_user_ptr_t trampoline_exclude;
  ci_user_ptr_t trampoline_ul_fail;

  ci_user_ptr_t signal_handler_postpone;
  ci_user_ptr_t signal_handlers[OO_SIGHANGLER_DFL_MAX+1];
  ci_user_ptr_t signal_sarestorer;
  ci_user_ptr_t signal_data;
  ci_int32 max_signum;
  ci_int32/*bool*/ sa_onstack_intercept;

   /* Used by PPC64 and other architectures for TOC and
    *  user fixup pointers.
    */
  ci_user_ptr_t trampoline_toc;
  ci_user_ptr_t trampoline_user_fixup;
} ci_tramp_reg_args_t;


struct oo_op_install_stack {
  char in_name[CI_CFG_STACK_NAME_LEN + 1];
};

struct oo_op_sigaction {
  ci_int32 sig;
  ci_user_ptr_t new_sa;   /*!< struct sigaction */
  ci_user_ptr_t old_sa;   /*!< struct sigaction */
};

struct oo_op_loopback_connect {
  ci_addr_t dst_addr;   /*!< destination address to connect to */
  ci_uint16 dst_port;   /*!< destination port to connect to */
  ci_uint8 out_moved;   /*!< have we moved socket to another stack? */
  ci_int8  out_rc;      /*!< rc of connect() */
};

#if CI_CFG_UL_INTERRUPT_HELPER
struct oo_ulh_waiter {
  ci_uint32 flags CI_ALIGN(8);
  /* Stack is already locked, the helper should release the stack lock */
#define OO_ULH_WAIT_FLAG_LOCKED 1

  ci_uint32 timeout_ms;     /* in */
  ci_uint32 rs_ref_count;   /* out */
};

struct oo_wakeup_eps {
  ci_uint32 eps_num;
  ci_user_ptr_t eps;
};
#endif


/*----------------------------------------------------------------------------
 *
 *  Optional debug interface for resources
 *
 *---------------------------------------------------------------------------*/

#include <onload/debug_intf.h>   


/*----------------------------------------------------------------------------
 *
 *  Driver entry points used from the Control Plane
 *
 *---------------------------------------------------------------------------*/

#include <cplane/ioctl.h>

/*--------------------------------------------------------------------
 *
 * Driver entry points
 *
 *--------------------------------------------------------------------*/

#include <onload/ioctl.h>

#endif /* __ONLOAD_COMMON_H__ */
/*! \cidoxg_end */
