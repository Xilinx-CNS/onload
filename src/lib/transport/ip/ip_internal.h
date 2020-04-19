/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ctk
**  \brief  Decls & defs for IP library internal to our libraries.
**   \date  2004/02/02
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#ifndef __CI_LIB_IP_INTERNAL_H__
#define __CI_LIB_IP_INTERNAL_H__

#include <ci/internal/ip.h>
#include <ci/internal/ip_log.h>
#include <ci/internal/ip_timestamp.h>
#include <ci/net/ethernet.h>
#include <onload/ul/tcp_helper.h>
#ifdef __KERNEL__
# include <onload/oof_interface.h>
# include <onload/oof_onload.h>
#endif
#include <onload/cplane_ops.h>


#ifdef __KERNEL__
/* These types of messages can only be sent in user space and will
 * never be queued up to be sent at a later point or potentially by
 * the driver.  However, the driver compiles code that uses this
 * definition so just define it to 0.
 */
#define ONLOAD_MSG_WARM 0

/* ONLOAD_MSG_ONEPKT is only used in user space receive calls, so use
 * the same trick as for ONLOAD_MSG_WARM above.
 */
#define ONLOAD_MSG_ONEPKT 0


/* Compat for linux-5.1.  We do not support 32-bit kernels, so no
 * conditionals are needed here. */
#ifndef SO_RCVTIMEO
#define SO_RCVTIMEO SO_RCVTIMEO_OLD
#endif
#ifndef SO_SNDTIMEO
#define SO_SNDTIMEO SO_SNDTIMEO_OLD
#endif
#ifndef SO_TIMESTAMP
#define SO_TIMESTAMP SO_TIMESTAMP_OLD
#endif

#endif /*__KERNEL__*/


/**********************************************************************
**************************** Logging etc. *****************************
**********************************************************************/

extern unsigned ci_tp_log CI_HV;
extern unsigned ci_tp_max_dump CI_HV;


#define log  ci_log


ci_inline unsigned ip_pkt_dump_len(unsigned len) {
  len += ETH_HLEN; /* ?? Cout VLAN tag as well ?? */
  if( len > ETH_FRAME_LEN )   len = 80;
#if defined(__ci_driver__)
  if( len > 80 ) len = 80;
#else
  if( len > ci_tp_max_dump )  len = ci_tp_max_dump;
#endif
  return len;
}


#ifdef __ci_driver__
/* definitions for installing/removing IP filters */
# include <onload/tcp_helper_endpoint.h>
# include <onload/tcp_helper_fns.h>
#endif


/*
** called with an RTT estimate to update SRTT, RTTVAR, RTO as in RFC2988
**
** We use Jacobson's SIGCOMM 88 convention with ts->sa holding SRTT
** scaled by 8 and ts->sv holding RTTVAR scaled by 4. ts->rto is the
** real number of ticks.
*/
ci_inline void ci_tcp_update_rtt(ci_netif* netif, ci_tcp_state* ts, int m)
{
  /* ?? Jacobson's algorithm assumes a signed number which might not
  ** be the same as ci_iptime_t, hmmm... what to do? */
  if( m < 0 ) {
    /* It's possible to get here if the timestamp has been corrupted.  If so
     * it's probably best not to use it to update the rtt.
     */
    LOG_TL(ci_log("TCP RX %d:%d ditching bad timestamp echo",
                  LNT_PRI_ARGS(netif, ts)));
    return;
  }
  m = CI_MAX(1, m);

  if( CI_LIKELY(ts->sa) ) {
    /* See Jacobson's SIGCOMM 88 algorithm to calculate (2.3) of
    ** RFC2988
    */
    m -= (ts->sa >> 3u);
    ts->sa += m;          /* SRTT <- SRTT + 0.125*(M-SRTT)  */
    if( m < 0 ) m = -m;
    m -= (ts->sv >> 2u);
    ts->sv += m;          /* RTTVAR <- 0.75*RTTVAR + 0.25*|M-SRTT| */
    ts->rto = tcp_srtt(ts) + ts->sv;   /* RTO <- SRTT + 4*RTTVAR */
  }
  else {
    /* first rtt estimate so follow (2.2) of RFC2988 */
    ts->sa = (m << 3u);
    ts->sv = (m << 1u);
    ts->rto = m + ts->sv;
  }

  ci_tcp_rto_bound(netif, ts);

  CI_IP_SOCK_STATS_VAL_RTT_SRTT_RTO( ts, ts->sv >> 2, ts->sa >> 3, ts->rto );
  LOG_TR(ci_log("TCP RX %d UPDATE RTT sa=%u sv=%u SRTT=%u RTTVAR=%u RTO=%u",
	        S_FMT(ts), ts->sa, ts->sv,
	        tcp_srtt(ts), tcp_rttvar(ts), ts->rto));
}

/*
** Turn timestamps into cmsg entries.
*/
void ip_cmsg_recv_timestamp(ci_netif *ni, ci_uint64 timestamp, 
                                      struct cmsg_state *cmsg_state);
void ip_cmsg_recv_timestampns(ci_netif *ni, ci_uint64 timestamp, 
                                        struct cmsg_state *cmsg_state);
void ip_cmsg_recv_timestamping(ci_netif *ni, const ci_ip_pkt_fmt *pkt,
                               int flags, struct cmsg_state *cmsg_state);


/**********************************************************************
******************************* Sleeping ******************************
**********************************************************************/

/* Macro for sleeping until [cond] is not true (or timeout, or error). */
/* TODO timeout should be re-calculated when looping */
#define CITP_WAITABLE_SLEEP_WHILE(ni, w, why, timeout, cond, prc) \
  do {								\
    ci_uint64 __sleep_seq;					\
    ci_uint32 t = (timeout);					\
    *(prc) = 0;							\
    while( 1 ) {						\
      __sleep_seq = (w)->sleep_seq.all;				\
      ci_rmb();							\
      if( !(cond) ) break;					\
      (*prc) = ci_sock_sleep((ni), (w), (why),			\
			     CI_SLEEP_NETIF_LOCKED |		\
			     CI_SLEEP_NETIF_RQ,			\
			     __sleep_seq, &t);		\
      /* TODO (Bug24547) handle case where netif lock fails */  \
      CI_TEST(ci_netif_lock(ni) == 0);                          \
      if( *(prc) )  break;					\
      ci_netif_poll(ni);					\
    }								\
  } while(0)


#define CI_TCP_SLEEP_WHILE(ni, ts, why, timeout, cond, prc)     \
  CITP_WAITABLE_SLEEP_WHILE((ni), &(ts)->s.b, (why), (timeout), (cond), (prc))


/**********************************************************************
******************************* Filters *******************************
**********************************************************************/

/*--------------------------------------------------------------------
 *!
 * Set all the filters needed for a TCP/UDP endpoint. This includes
 *    - hardware filters
 *    - filters in the software connection hash table
 *    - driverlink filters
 *
 * \param ni              ci_netif structure
 * \param sock_id         socket id
 * \param bindto_ifindex  ifindex from SO_BINDTODEVICE
 * \param from_tcp_id     block id of listening socket to "borrow" filter from
 *                        (-1 if not required)
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

ci_inline int
ci_tcp_ep_set_filters(ci_netif *        ni,
                      oo_sp             sock_id,
                      ci_ifid_t         bindto_ifindex,
                      oo_sp             from_tcp_id)
{
  int rc;

  ci_assert(ni);

  LOG_TC(ci_log("%s: %d:%d bindto_ifindex=%d port_sock=%d",
                __FUNCTION__, NI_ID(ni), OO_SP_FMT(sock_id),
                (int) bindto_ifindex, OO_SP_FMT(from_tcp_id)));

#ifdef __ci_driver__
  rc = tcp_helper_endpoint_set_filters(ci_netif_get_valid_ep(ni, sock_id),
                                       bindto_ifindex, from_tcp_id);

#else
  if( ci_tcp_can_set_filter_in_ul(ni, SP_TO_SOCK(ni, sock_id)) )
    rc = ci_tcp_sock_set_stack_filter(ni, SP_TO_SOCK(ni, sock_id));
  else
    rc = ci_tcp_helper_ep_set_filters(ci_netif_get_driver_handle(ni), sock_id,
                                      bindto_ifindex, from_tcp_id);
#endif

  LOG_TC( if(rc < 0)
            ci_log(" ---> %s (rc=%d)", __FUNCTION__, rc) );
  return rc;
}

#if !defined(__KERNEL__) && CI_CFG_ENDPOINT_MOVE
ci_inline int
ci_tcp_ep_reuseport_bind(ci_fd_t fd, const char* cluster_name,
                         ci_int32 cluster_size, ci_uint32 cluster_restart_opt,
                         ci_uint32 cluster_hot_restart_opt,
                         ci_addr_t addr, ci_uint16 port_be16)
{
  int rc;

  if( port_be16 == 0 ) {
    /* There should be a non-zero port value to perform reuseport bind properly.
     * This condition will be violated when socket deferred bind happens, e.g.
     * when combining SO_REUSEPORT with EF_TCP_SHARED_LOCAL_PORTS option. */
    LOG_TC(ci_log("%s: Trying to perform reuseport bind with 0 port value",
                  __FUNCTION__));
    return EINVAL;
  }

  LOG_TC(ci_log("%s: %d addr: " IPX_FMT " port: %d", __FUNCTION__, fd,
                IPX_ARG(AF_IP_L3(addr)), port_be16));
  rc = ci_tcp_helper_ep_reuseport_bind(fd, cluster_name, cluster_size,
                                       cluster_restart_opt,
                                       cluster_hot_restart_opt,
                                       addr, port_be16);
  LOG_TC( if(rc < 0)
            ci_log(" ---> %s (rc=%d)", __FUNCTION__, rc) );
  return rc;
}
#endif

/*--------------------------------------------------------------------
 *!
 * Clear all filters for an endpoint
 *
 * \param ni              ci_netif structure
 * \param sock_id         id of socket
 * \param no_sw           non-zero if the s/w filter has already been removed
 *                        (e.g. if the EP was cached)
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

ci_inline int
ci_tcp_ep_clear_filters(ci_netif*         ni,
                        oo_sp             sock_id,
                        int               need_update)
{
  int rc;
#ifdef __ci_driver__
  int supress_hw_ops = ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT;
#endif
  ci_assert(ni);

  LOG_TC(ci_log("%s: %d:%d (%d)", __FUNCTION__,
                ni->state->stack_id, OO_SP_FMT(sock_id), need_update));
  ci_assert(ci_netif_is_locked(ni));

#ifdef __ci_driver__
  rc = tcp_helper_endpoint_clear_filters(
                    ci_netif_get_valid_ep(ni, sock_id),
                    (supress_hw_ops ? EP_CLEAR_FILTERS_FLAG_SUPRESS_HW : 0) |
                    (need_update ? EP_CLEAR_FILTERS_FLAG_NEED_UPDATE : 0));
#else
  if( (SP_TO_SOCK(ni, sock_id)->s_flags & CI_SOCK_FLAG_STACK_FILTER) &&
      ci_tcp_can_set_filter_in_ul(ni, SP_TO_SOCK(ni, sock_id)) ) {
    ci_tcp_sock_clear_stack_filter(ni, SP_TO_TCP(ni, sock_id));
    rc = 0;
  }
  else
    rc = ci_tcp_helper_ep_clear_filters(ci_netif_get_driver_handle(ni), sock_id,
                                        need_update);
#endif

  LOG_TC( if (rc < 0 && rc != -EAGAIN)
            ci_log(" ---> %s (rc=%d)", __FUNCTION__, rc) );
  return rc;
}


/*--------------------------------------------------------------------
 *!
 * Add multicast address to a socket list of multicast addresses. If the
 * socket is already bound, this function installs filters for this
 * address. If the socket is not bound, the function just add multicast
 * address to the list, and bind() should install the filter.
 * or
 * Delete a multicast address from a socket list of multicast addresses. 
 * If the socket is already bound, this function removes filters for this
 * address. If the socket is not bound, the function just deletes multicast
 * address from the list.
 *
 * \param ni              ci_netif structure
 * \param sock_id         socket id
 * \param sock_fd         OS socket file descriptor
 * \param phys_port       L5 physcial port index to use when joining the
 *                        group
 * \param mcast_addr      Multicast address to add to the socket list
 * \param add             add or delete multicast entry?
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

#ifndef __ci_driver__
ci_inline int
ci_tcp_ep_mcast_add_del(ci_netif*         ni,
                        oo_sp             sock_id,
                        ci_ifid_t         ifindex,
                        ci_uint32         mcast_addr,
                        int               add)
{
  int rc;

  ci_assert(ni);

  LOG_TC(ci_log("%s: id=%d (ifid=%d, maddr=%s)",
                __FUNCTION__, OO_SP_FMT(sock_id), ifindex,
                ip_addr_str(mcast_addr)));

  rc = ci_tcp_helper_ep_mcast_add_del(ci_netif_get_driver_handle(ni),
                                      sock_id, mcast_addr, ifindex, add);

  LOG_TC( if(rc < 0)
            ci_log(" ---> %s (rc=%d)", __FUNCTION__, rc) );
  return rc;
}
#endif


/*********************************************************************
**************************** Debug support ***************************
*********************************************************************/

#ifdef __KERNEL__
# define verify_fail()  return
#else
# define verify_fail()  ci_fail(("STOP."))
#endif

#define verify(exp)							  \
  do{									  \
    if( CI_UNLIKELY(!(exp)) ) {						  \
      ci_log("********** verify(%s) at %s:%d", #exp, __FILE__, __LINE__); \
      ci_log("********** from %s:%d", file?file:"", line);		  \
      verify_fail();							  \
    }									  \
  }while(0)

#undef verify
#define verify(exp)  ci_assert(exp)


/*********************************************************************
**************************** Socket options **************************
*********************************************************************/

#ifndef SO_TIMESTAMPNS
# define SO_TIMESTAMPNS 35
#endif

#ifndef SO_REUSEPORT
# define SO_REUSEPORT   15
#endif

#if CI_CFG_TIMESTAMPING
/* The following value needs to match its counterpart
 * in kernel headers.
 */
#define ONLOAD_SO_TIMESTAMPING 37
#define ONLOAD_SCM_TIMESTAMPING ONLOAD_SO_TIMESTAMPING
#endif

/* Replica of sock_extended_err - just in case we do not have ee_data in
 * the headers in use. */
struct oo_sock_extended_err {
  ci_uint32 ee_errno;
  ci_uint8  ee_origin;
  ci_uint8  ee_type;
  ci_uint8  ee_code;
  ci_uint8  ee_pad;
  ci_uint32 ee_info;
  ci_uint32 ee_data;
};

/* SO_EE_ORIGIN_TIMESTAMPING could be undefined. */
#ifndef SO_EE_ORIGIN_TIMESTAMPING
#define SO_EE_ORIGIN_TIMESTAMPING 4
#endif

/* The following value needs to match its counterpart
 * in kernel headers.
 */
#define ONLOAD_SO_BUSY_POLL 46

/* check [ov] is a non-NULL ptr & [ol] indicates the right space for
 * type [ty] */
#define opt_ok(ov,ol,ty)     ((ov) && (ol) >= sizeof(ty))
#define opt_not_ok(ov,ol,ty) \
    ((ol) < sizeof(ty) ? -EINVAL : (ov) ? 0 : -EFAULT)

ci_inline unsigned 
ci_get_optval(const void *optval, socklen_t optlen)
{
  if (optlen >= sizeof(unsigned))
    return (*(unsigned*)optval);
  else return (unsigned)(*(unsigned char*)optval);
}

/*! Do not call it, use ci_getsockopt_final(). */
ci_inline int
ci_getsockopt_final_pre(void *optval, socklen_t *optlen, int level,
                        void *val, size_t val_size)
{
  if( *optlen > 0 )
    memcpy(optval, val, CI_MIN(*optlen, val_size));
  if( *optlen > val_size )
    *optlen = val_size;
  /* TODO AFAIK, Solaris returns error if *optlen < val_size. */
  return 0;  
}

/*! Common getsockopt() part - push value to the user according to the
 * particular OS expectations. Return -1 with errno being set or 0.  */
ci_inline int
ci_getsockopt_final(void *optval, socklen_t *optlen, int level,
                    void *val, size_t val_size)
{
  if( (level == SOL_SOCKET || level == SOL_IP) &&
      val_size == sizeof(int) && 
      *optlen >= sizeof(char) && *optlen < sizeof(int) ) {
    int ival = *((int *)val);
    unsigned char ucval = (unsigned char)ival;
    if( ival >=0 && ival <= 255)
      return ci_getsockopt_final_pre(optval, optlen, level,
                                     &ucval, sizeof(ucval));
  }
  return ci_getsockopt_final_pre(optval, optlen, level,
                                 val, val_size);
}


/*! Handler for TCP getsockopt:SOL_TCP options.
 * \param netif   [in] Netif context
 * \param s       [in] Socket state context
 * \param optname [in] Option being queried
 * \param optval  [out] Location for value being returned
 * \param optlen  [in/out] Length of buffer ref'd by [optval]
 * \return        As for getsockopt()
 */
extern int ci_get_sol_tcp(ci_netif* netif, ci_sock_cmn* s,
			  int optname, void *optval,
			  socklen_t *optlen) CI_HF;

#ifdef __KERNEL__
extern int ci_ip_mtu_discover_from_sflags(int s_flags, int af) CI_HF;
#else
/*! Handler for common getsockopt:SOL_IP options. The handlers here will
 * cope with both TCP & UDP.
 * \param netif   [in] Netif context
 * \param s       [in] Socket state context
 * \param fd      [in] File descriptor
 * \param optname [in] Option being queried
 * \param optval  [out] Location for value being returned
 * \param optlen  [in/out] Length of buffer ref'd by [optval]
 * \return        As for getsockopt()
 */
extern int ci_get_sol_ip( ci_netif* netif, ci_sock_cmn* s, ci_fd_t fd,
			  int optname, void *optval,
			  socklen_t *optlen ) CI_HF;
#endif

#if CI_CFG_FAKE_IPV6
/*! Handler for common getsockopt:SOL_IPV6 options. The handlers here will
 * cope with both TCP & UDP.
 * \param s       [in] Socket state context
 * \param fd      [in] File descriptor
 * \param optname [in] Option being queried
 * \param optval  [out] Location for value being returned
 * \param optlen  [in/out] Length of buffer ref'd by [optval]
 * \return        As for getsockopt()
 */
extern int ci_get_sol_ip6( ci_netif* netif, ci_sock_cmn* s, ci_fd_t fd,
                           int optname, void *optval, 
                           socklen_t *optlen ) CI_HF;
#endif

#if defined(__KERNEL__) && ! defined(EFRM_HAS_STRUCT_TIMEVAL)
/* In-kernel user of ci_get_sol_socket(SO_RCVTIMEO) needs struct timeval,
 * which does not exist in linux>=5.6 */
#define timeval __kernel_sock_timeval
#endif

/*! Handler for common getsockopt:SOL_SOCKET options.
 * \param ni      [in] Netif context
 * \param s       [in] Socket state context
 * \param optname [in] Option being queried
 * \param optval  [out] Location for value being returned
 * \param optlen  [in/out] Length of buffer ref'd by [optval]
 * \return        As for getsockopt()
 */
extern int ci_get_sol_socket( ci_netif* netif, ci_sock_cmn* s,
			      int optname, void *optval,
			      socklen_t *optlen ) CI_HF;

/*! Handler for common setsockopt:SOL_IP handlers.
 * \param netif   [in] Netif context
 * \param s       [in] Socket state context
 * \param optname [in] Option being modified
 * \param optval  [in] Location for new value
 * \param optlen  [in] Length of buffer ref'd by [optval]
 * \return        As for setsockopt()
 */
extern int 
ci_set_sol_ip( ci_netif* netif, ci_sock_cmn* s,
	       int optname, const void *optval, socklen_t optlen) CI_HF;

#if CI_CFG_FAKE_IPV6
/*! Handler for common setsockopt:SOL_IPV6 handlers.
 * \param netif   [in] Netif context
 * \param s       [in] Socket state context
 * \param optname [in] Option being modified
 * \param optval  [in] Location for new value
 * \param optlen  [in] Length of buffer ref'd by [optval]
 * \return        As for setsockopt()
 */
extern int 
ci_set_sol_ip6( ci_netif* netif, ci_sock_cmn* s,
	        int optname, const void *optval, socklen_t optlen) CI_HF;
#endif

/*! Handler for common setsockopt:SOL_SOCKET handlers.
 * \param netif   [in] Netif context
 * \param s       [in] Socket state context
 * \param optname [in] Option being modified
 * \param optval  [in] Location for new value
 * \param optlen  [in] Length of buffer ref'd by [optval]
 * \return        As for setsockopt()
 */
extern int 
ci_set_sol_socket( ci_netif* netif, ci_sock_cmn* s,
		   int optname, const void *optval, socklen_t optlen) CI_HF;

/*! Handles socket options that don't require the netif lock. */
extern int 
ci_set_sol_socket_nolock(ci_netif*, ci_sock_cmn* s, int optname,
			 const void *optval, socklen_t optlen) CI_HF;

/*********************************************************************
 ******************************* Ioctls ******************************
*********************************************************************/

#ifdef __KERNEL__
#define CI_IOCTL_ARG_OK(t,a) ({t _v; int _rc = get_user(_v, (t*)(a)); (void)_v; _rc==0;})
#define CI_IOCTL_SETARG(a,v) do { put_user(v,a); } while(0)
#define CI_IOCTL_GETARG(t,a) ({t _v; get_user(_v, (t*)(a)); _v; })
#else
#define CI_IOCTL_ARG_OK(t,a) ((a) != 0)
#define CI_IOCTL_SETARG(a,v) do { *(a)=(v); } while(0)
#define CI_IOCTL_GETARG(t,v) (*(t*)(v))
#endif

#if defined(__KERNEL) /* Bug 18959: should be __KERNEL__ */
/* Common handler for FIONBIO - called in per-protocol handler to 
 * keep the request efficient */
#define CI_CMN_IOCTL_FIONBIO(s, arg) do {                             \
  int v, _rc = get_user(v, arg);                                      \
  if( v ) {                                                           \
      LOG_SV( ci_log("%s: set non-blocking mode", __FUNCTION__ ) );   \
      ci_bit_set(&(s)->b.sb_aflags, CI_SB_AFLAG_O_NONBLOCK_BIT);      \
    } else {                                                          \
      LOG_SV( ci_log("%s: clear non-blocking mode", __FUNCTION__ ) ); \
      ci_bit_clear(&(s)->b.sb_aflags, CI_SB_AFLAG_O_NONBLOCK_BIT);    \
    } } while (0) 
#else
/* Common handler for FIONBIO - called in per-protocol handler to 
 * keep the request efficient */
#define CI_CMN_IOCTL_FIONBIO(s, arg) do {                             \
  if( *(int*)(arg) ) {                                                \
      LOG_SV( ci_log("%s: set non-blocking mode", __FUNCTION__ ) );   \
      ci_bit_set(&(s)->b.sb_aflags, CI_SB_AFLAG_O_NONBLOCK_BIT);      \
    } else {                                                          \
      LOG_SV( ci_log("%s: clear non-blocking mode", __FUNCTION__ ) ); \
      ci_bit_clear(&(s)->b.sb_aflags, CI_SB_AFLAG_O_NONBLOCK_BIT);    \
    } } while (0) 
#endif

/*! Common handler for IOCTL calls.
 * \param  netif    Context
 * \param  s        ci_sock_cmn context
 * \param  request  Ioctl request code from ioctl() intercept
 * \param  arg      Ioctl arg ptr from ioctl() intercept
 * \param  os_rc    Return from call-down to ioctl() for backing OS socket
 * \param  os_socket_exists Non-zero if OS socket extsts
 * \return          As for ioctl()
 */
extern int ci_cmn_ioctl(ci_netif* netif, ci_sock_cmn* s, int request, 
			void* arg, int os_rc, int os_socket_exists);

/*! Compute the time stamp delta for the given packet time stamp and
 *  return in in ts
 */
extern void ci_udp_compute_stamp(ci_netif *netif, ci_uint64 stamp,
                                 struct timespec *ts);


/* Return from getsockopt(level=SOL_INVALID) with appropriate errno */
# define SOCKOPT_RET_INVALID_LEVEL(s) \
    if ((s)->domain == AF_INET6 )   \
      RET_WITH_ERRNO(ENOPROTOOPT);  \
    else                            \
      RET_WITH_ERRNO(EOPNOTSUPP)

/*********************************************************************
 ***************************** Async IO ******************************
 *********************************************************************/


#ifndef ECANCELED
#define ECANCELED 125
#endif


#if defined(__KERNEL__)
extern void ci_ip_queue_enqueue_nnl(ci_netif* netif, ci_ip_pkt_queue*qu,
				    ci_ip_pkt_fmt* pkt) CI_HF;
#endif
extern ci_ip_pkt_fmt* ci_pkt_alloc_n(ci_netif* ni, int n) CI_HF;
extern ci_ip_pkt_fmt* ci_pkt_alloc_n_nnl(ci_netif* ni, int n) CI_HF;



/*********************************************************************
 ******************************** UDP ********************************
 *********************************************************************/

/* The following two macros cope with Path MTU constraints and fragmentation
 * boundary requirements (multiple of 64 bits) */

/* How much payload space in a first fragment packet */
#define UDP_PAYLOAD1_SPACE_PMTU(af, pmtu)			\
  (((pmtu) - CI_IPX_HDR_SIZE(af) - CI_IPX_FRAG_HDR_SIZE(af) -  \
    sizeof(ci_udp_hdr)) & 0xfff8)

/* How much space in a second fragment packet */
#define UDP_PAYLOAD2_SPACE_PMTU(af, pmtu) \
  (((pmtu) - CI_IPX_HDR_SIZE(af) + CI_IPX_FRAG_HDR_SIZE(af)) & 0xfff8)

#define UDP_HAS_SENDQ_SPACE(us,l) \
  ((us)->s.so.sndbuf >= (int)((us)->tx_count + (l)))


/* Linux sets twice the buffer size that the application requests. */
#define oo_adjust_SO_XBUF(v)  ((v) * 2)


/**********************************************************************
 * OO_SPINLOOP_PAUSE_CHECK_SIGNALS()
 */

#ifdef __KERNEL__

ci_inline int
oo_spinloop_pause_check_signals(ci_netif* ni, ci_uint64 now_frc,
                                ci_uint64* schedule_frc, int have_timeout)
{
  if(CI_UNLIKELY( signal_pending(current) ))
    return have_timeout ? -EINTR : -ERESTARTSYS;
  if( now_frc - *schedule_frc > IPTIMER_STATE(ni)->khz ) {
    schedule();                  /* schedule() every 1ms */
    *schedule_frc = now_frc;
  }
  return 0;
}

#define OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, schedule_frc,      \
                                        have_timeout, w, si)            \
  oo_spinloop_pause_check_signals(ni, now_frc, schedule_frc, have_timeout)

#else

#include "ci/internal/ip_signal.h"
extern int oo_spinloop_run_pending_sigs(ci_netif*, citp_waitable*,
                                        citp_signal_info*, int) CI_HF;

ci_inline int
oo_spinloop_pause_check_signals(ci_netif* ni, ci_uint64 now_frc,
                                ci_uint64* schedule_frc /*unused*/,
                                int have_timeout,
                                citp_waitable* w, citp_signal_info* si)
{
  ci_assert_gt(si->inside_lib, 0);
  ci_assert(~si->aflags & OO_SIGNAL_FLAG_FDTABLE_LOCKED);

  if(CI_LIKELY( ! (si->aflags & OO_SIGNAL_FLAG_HAVE_PENDING) ))
    return 0;
  else
    return oo_spinloop_run_pending_sigs(ni, w, si, have_timeout);
}

#define OO_SPINLOOP_PAUSE_CHECK_SIGNALS(ni, now_frc, schedule_frc,      \
                                        have_timeout, w, si)            \
  oo_spinloop_pause_check_signals(ni, now_frc, schedule_frc,            \
                                  have_timeout, w, si)

#endif


/*********************************************************************
 ******************************** Per-Thread *************************
 *********************************************************************/

#ifndef __KERNEL__
extern citp_init_thread_callback init_thread_callback CI_HV;
#endif


/*********************************************************************
 ******************************* Post Stripe *************************
 *********************************************************************/

#if CI_CFG_PORT_STRIPING
#define ci_ts_port_swap(seq, ts) ((seq / tcp_eff_mss(ts)) & 1)
#endif

static inline int ci_intf_i_to_ifindex(ci_netif* ni, int intf_i)
{
  ci_hwport_id_t hwport;
  ci_assert_lt((unsigned) intf_i, CI_CFG_MAX_INTERFACES);
  hwport = ni->state->intf_i_to_hwport[intf_i];
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_HWPORTS);
  return oo_cp_hwport_vlan_to_ifindex(ni->cplane, hwport, 0, NULL);
}


/*********************************************************************
 ****************************** Free Packets *************************
 *********************************************************************/

/* Returns true if the packet is freed. */
ci_inline int/*bool*/
ci_netif_pkt_release_in_poll(ci_netif* netif, ci_ip_pkt_fmt* pkt,
                             struct ci_netif_poll_state* ps)
{
  if( pkt->refcount == 1 ) {
    /* We are going to free the packet, so it is not in use
     * by TX any more. */
    ci_assert(~pkt->flags & CI_PKT_FLAG_TX_PENDING);

    pkt->refcount = 0;
    if( pkt->flags & CI_PKT_FLAG_RX )
      --netif->state->n_rx_pkts;
    __ci_netif_pkt_clean(pkt);
    if( ! (pkt->flags & CI_PKT_FLAG_NONB_POOL) ) {
      ci_netif_pkt_put(netif, pkt);
    }
    else if( ps != NULL ) {
      *ps->tx_pkt_free_list_insert = OO_PKT_P(pkt);
      ps->tx_pkt_free_list_insert = &pkt->next;
      ++ps->tx_pkt_free_list_n;
    }
    else {
      ci_netif_pkt_free_nonb_list(netif, OO_PKT_P(pkt), pkt);
      netif->state->n_async_pkts ++;
    }
    return CI_TRUE;
  }
  else {
    ci_assert_gt(pkt->refcount, 1);
    --pkt->refcount;
    return CI_FALSE;
  }
}
                             

#ifdef __KERNEL__
extern void ci_netif_set_merge_atomic_flag(ci_netif* ni);
#define CI_NETIF_STATE_MOD(ni, is_locked, field, mod) \
  do {                                                                      \
    if( is_locked ) {                                                       \
      mod##mod ni->state->field;                                            \
    }                                                                       \
    else {                                                                  \
      ci_int32 val;                                                         \
      do {                                                                  \
        val = ni->state->atomic_##field;                                    \
      } while( ci_cas32u_fail(&ni->state->atomic_##field, val, val mod 1) );\
    }                                                                       \
  } while(0)
#else
#define CI_NETIF_STATE_MOD(ni, is_locked, field, mod) \
  do { mod##mod ni->state->field; } while(0)
#endif

void oo_pkt_calc_checksums(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                           struct iovec* host_iov);


/* Reset ci_ip_pkt_fmt::pio_addr back to the normal value. Called after a zc
 * callback *doesn't* return ONLOAD_ZC_KEEP, to restore the value after it got
 * optimistically overwritten by ci_ip_pkt_fmt::user_refcount */
static inline void clear_pio_addr(ci_netif* ni, ci_ip_pkt_fmt* pkt)
{
  for( ; ; ) {
    pkt->pio_addr = -1;
    if( OO_PP_IS_NULL(pkt->frag_next) )
      break;
    pkt = PKT_CHK_NNL(ni, pkt->frag_next);
  }
}


#endif /* __CI_LIB_IP_INTERNAL_H__ */
/*! \cidoxg_end */
