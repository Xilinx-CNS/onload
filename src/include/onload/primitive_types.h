/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_PRIMITIVE_TYPES_H__
#define __ONLOAD_PRIMITIVE_TYPES_H__

#include <ci/compat.h>


typedef struct ci_netif_s		ci_netif;
typedef struct ci_netif_state_s		ci_netif_state;
typedef struct ci_ip_pkt_fmt_s		ci_ip_pkt_fmt;
typedef struct ci_sock_cmn_s		ci_sock_cmn;
typedef struct ci_tcp_state_s		ci_tcp_state;
typedef struct ci_tcp_socket_listen_s	ci_tcp_socket_listen;
typedef struct ci_udp_state_s		ci_udp_state;
typedef union  citp_waitable_obj_u	citp_waitable_obj;
typedef struct citp_socket_s            citp_socket;
typedef struct ci_active_wild_s         ci_active_wild;


/*! The stack's measure of time.  In ticks. */
typedef ci_uint32  ci_iptime_t;


/* Fixed width type equivalent of struct timeval */
struct oo_timeval {
  ci_int32 tv_sec;
  ci_int32 tv_usec;
};

typedef struct {
  volatile ci_uint32 n;
} oo_atomic_t;


#include <onload/pkt_p.h>
#include <onload/state_p.h>
#include <onload/sock_p.h>


#endif  /* __ONLOAD_PRIMITIVE_TYPES_H__ */
