/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Decls & defs for IP library internal to our libraries.
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_IP_H__
#define __CI_INTERNAL_IP_H__

#include <ci/internal/transport_config_opt.h>
#include <onload/primitive_types.h>
#include <ci/internal/ip_stats.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/pio.h>
#include <etherfabric/internal/internal.h>
#include <onload/offbuf.h>
#include <ci/tools.h>
#include <ci/net/ipvx.h>
#include <cplane/cplane.h>
#include <ci/net/ethernet.h>
#include <ci/internal/ip_shared_types.h>
#include <ci/internal/ip_log.h>

#include <ci/tools.h>
#include <ci/tools/istack.h>

#if defined(__KERNEL__) && ! CI_CFG_UL_INTERRUPT_HELPER
#define OO_HAS_ATOMIC_CONTEXT 1
#else
#define OO_HAS_ATOMIC_CONTEXT 0
#endif

/* Do we compile the core TCP/IP stack functionality in? */
#if ! defined(__KERNEL__) || ! CI_CFG_UL_INTERRUPT_HELPER
#define OO_DO_STACK_POLL 1
#else
#define OO_DO_STACK_POLL 0
#endif

#ifdef __KERNEL__
# include <onload/shmbuf.h>
# include <onload/iobufset.h>
# include <onload/eplock_resource.h>
#endif

#include <etherfabric/base.h>
#include <ci/efrm/nic_set.h>
#include <ci/driver/efab/open.h>
#include <ci/internal/ip_types.h>
#include <onload/eplock.h>

#include <ci/internal/ip_shared_ops.h>
#include <ci/internal/ip_stats_ops.h>
#include <onload/pktq.h>
#include <onload/atomics.h>
#include <onload/drv/dump_to_user.h>
#include <onload/hash.h>
#include <ci/internal/ni_dllist.h>
#include <ci/internal/iptimer.h>
#include <onload/ringbuffer.h>

#if CI_CFG_TIMESTAMPING
#ifdef __KERNEL__
/* This should match with UL-only header onload/extensions.h */
#define ONLOAD_SOF_TIMESTAMPING_STREAM (1 << 23)
#else
#include <onload/extensions.h>
#endif
#endif


/**********************************************************************
 ************************* Version management *************************
 **********************************************************************/

#ifdef __KERNEL__
extern const char* oo_uk_intf_ver;
#endif


/**********************************************************************
 **************************** Debug checks ****************************
 **********************************************************************/

#if ! CI_CFG_DETAILED_CHECKS || defined(NDEBUG)
# define CHECK_NI(ni)
# define CHECK_TS(ni,ts)
# define CHECK_TLS(ni,ts)
# define CHECK_TEP(ep)
# define CHECK_US(ni,ts)
# define CHECK_UEP(ep)
# define CHECK_TIMERS(ni)
# define CHECK_FREEPKTS(ni)
# define CHECK_TEP_NNL(ep)
#else

# define CHECK_NI(ni)                           \
    ci_netif_assert_valid(ni,__FILE__,__LINE__)

# define CHECK_TS(ni,ts)                                        \
    ci_tcp_state_assert_valid((ni), (ts), __FILE__,__LINE__)

# define CHECK_TLS(ni, tls)						\
    ci_tcp_state_listen_assert_valid((ni), (tls), __FILE__,__LINE__)

# define CHECK_TEP(ep)                                  \
    ci_tcp_ep_assert_valid(ep, __FILE__, __LINE__)

# define CHECK_US(ni,ts)                                        \
    ci_udp_state_assert_valid((ni), (ts), __FILE__, __LINE__)

# define CHECK_UEP(ep)                                  \
    ci_udp_ep_assert_valid(ep, __FILE__, __LINE__)

# define CHECK_TIMERS(ni)                                       \
    ci_ip_timer_state_assert_valid((ni), __FILE__, __LINE__)

# define CHECK_FREEPKTS(ni)                             \
  ci_netif_verify_freepkts(ni, __FILE__, __LINE__);  

/* This is intended to allow some checking to be done without the netif
 * lock held. At the moment it does nothing. */
# define CHECK_TEP_NNL(ep)

#endif


/*********************************************************************
******************** Socket Level IP State Cache *********************
*********************************************************************/

/* It should be equal to EFX_MAX_MTU from driver/linux_net/net_driver.h */
#define CI_PMTU_MAX_MTU  (9 * 1024)

#define LOG_PMTU(x) LOG_IPP(x)

/* Path MTU plateau table entries (stored in ci_tcp_state) */
#define CI_PMTU_PLATEAU_ENTRIES					\
  { 68, 296, 508, 1006, 1492, 2002, 4352, 8166, 32000, 65535 }
#define CI_PMTU_PLATEAU_ENTRY_MAX	9


extern void
ci_pmtu_state_init(ci_netif* ni, ci_sock_cmn *s, oo_p pmtu_sp,
                   ci_pmtu_state_t* pmtus, int func_code);
extern void ci_pmtu_set(ci_netif *ni, ci_pmtu_state_t *pmtus, unsigned pmtu);

/*! IP timer callback for Path MTU discovery process */
extern void ci_pmtu_timeout_pmtu(ci_netif* ni, ci_tcp_state* tso) CI_HF;

extern void ci_pmtu_update_fast(ci_netif *ni, ci_pmtu_state_t *pmtus,
                                ci_ip_cached_hdrs *ipcache,
                                unsigned mtu) CI_HF;
extern void ci_pmtu_update_slow(ci_netif *ni, ci_pmtu_state_t *pmtus,
                                ci_ip_cached_hdrs *ipcache,
                                unsigned mtu) CI_HF;

#define CI_PMTU_STOP_TIMER ((ci_iptime_t)0)
#define CI_PMTU_IMMEDIATE_TIMEOUT ((ci_iptime_t)1)


#define CI_PMTU_TIMER_SET_FAST(ni, p)					   \
  ci_pmtu_discover_timer((ni), (p), NI_CONF(ni).tconst_pmtu_discover_fast)
#define CI_PMTU_TIMER_SET_SLOW(ni, p)					   \
  ci_pmtu_discover_timer((ni), (p), NI_CONF(ni).tconst_pmtu_discover_slow)
#define CI_PMTU_TIMER_SET_RECOVER(ni, p)				      \
  ci_pmtu_discover_timer((ni), (p), NI_CONF(ni).tconst_pmtu_discover_recover)
#define CI_PMTU_TIMER_KILL(ni, p)				\
  ci_pmtu_discover_timer( (ni), (p), CI_PMTU_STOP_TIMER )
#define CI_PMTU_TIMER_NOW(ni, p)					\
  ci_pmtu_discover_timer( (ni), (p), CI_PMTU_IMMEDIATE_TIMEOUT )



/*! Initializes an IP cache
 *  (to use this macro include <ci/internal/cplane_ops.h>)
 */
#define ci_ip_cache_init_common(ipcache, af)                    \
do {                                                            \
  ci_ip_cache_invalidate(ipcache);                              \
  (ipcache)->status = retrrc_noroute;                           \
  (ipcache)->intf_i = -1;                                       \
  (ipcache)->hwport = CI_HWPORT_ID_BAD;                         \
  (ipcache)->ether_type = ci_af2ethertype(af);                  \
  (ipcache)->flags = 0;                                         \
  (ipcache)->nexthop = addr_any;                                \
  ipcache_ttl(ipcache) = CI_IPX_DFLT_TTL_HOPLIMIT(af);          \
} while (0)
#define ci_ip_cache_init(ipcache, af) ci_ip_cache_init_common(ipcache, af)


static inline cp_fwd_table_id ci_ni_fwd_table_id(ci_netif* ni)
{
  /* UL does not know its fwd-table ID, and could not be trusted to pass it
   * around as a parameter in any case.  Instead, the mapping of the fwd table
   * in the mib is arranged to be the correct one by the kernel.  In the
   * kernel, on the other hand, there is no such magic mapping, which would be
   * impossible as there's only a single handle per control plane instance.
   * This function papers over that distinction, thus avoiding the need to have
   * CI_KERNEL_ARG()s sitting all over the place.  It returns a deliberately-
   * invalid value at UL, so that we trip assertions in case we ever try to use
   * it by mistake. */

#ifdef __KERNEL__
  return ni->cplane->cplane_id;
#else
  return CP_FWD_TABLE_ID_INVALID;
#endif
}


/*! Invalidates a ci_ip_cached_hdrs struct i.e. all state becomes out-of-date.
 */
ci_inline void
ci_ip_cache_invalidate(ci_ip_cached_hdrs*  ipcache)
{
  oo_cp_verinfo_init(&ipcache->fwd_ver);
  oo_cp_verinfo_init(&ipcache->fwd_ver_init_net);
  ipcache->fwd_ver_init_net.id = CICP_MAC_ROWID_UNUSED;
}


static inline int
oo_cp_ipcache_is_valid(ci_netif* ni, ci_ip_cached_hdrs* ipcache)
{
  int rc = oo_cp_verinfo_is_valid(ni->cplane, &ipcache->fwd_ver,
                                  ci_ni_fwd_table_id(ni));
  if( rc && ipcache->fwd_ver_init_net.id != CICP_MAC_ROWID_UNUSED ) {
    rc = ni->cplane_init_net != NULL &&
         oo_cp_verinfo_is_valid(ni->cplane_init_net,
                                &ipcache->fwd_ver_init_net,
                                ci_ni_fwd_table_id(ni));
  }
  return rc;
}


/*********************************************************************
*************************** Packet buffers ***************************
*********************************************************************/

/* Total length of TX packet */
#define TX_PKT_LEN(pkt) (pkt)->pay_len

/* Offset of current buffer position from start of TCP payload. */
#define PKT_RX_BUF_OFF(pkt)                                                 \
  ((ci_uint32)(oo_offbuf_ptr(&(pkt)->buf) - CI_TCP_PAYLOAD(PKT_TCP_HDR(pkt))))

#define PKT_IPX_RX_BUF_OFF(af, pkt) \
  ((ci_uint32)(oo_offbuf_ptr(&(pkt)->buf) - \
  CI_TCP_PAYLOAD(PKT_IPX_TCP_HDR(af, pkt))))

/* Sequence number at the current buffer position. */
#define PKT_RX_BUF_SEQ(pkt)                                     \
  (CI_BSWAP_BE32(PKT_TCP_HDR(pkt)->tcp_seq_be32) + PKT_RX_BUF_OFF(pkt))

#define PKT_IPX_RX_BUF_SEQ(af, pkt) \
  (CI_BSWAP_BE32(PKT_IPX_TCP_HDR(af, pkt)->tcp_seq_be32) + \
  PKT_IPX_RX_BUF_OFF(af, pkt))

#define PKT_TCP_RX_BUF_ASSERT_VALID(ni, pkt)            \
  OO_OFFBUF_ASSERT_VALID(&(pkt)->buf, PKT_START(pkt),   \
			 (pkt) + CI_CFG_PKT_BUF_SIZE)


#define PKT_START(pkt)       ((char*) oo_ether_hdr(pkt))

#define PKT_TCP_HDR(pkt)     ((ci_tcp_hdr*) oo_ip_data(pkt))

static inline ci_tcp_hdr* ci_pkt_ipx_tcp_hdr(int af, ci_ip_pkt_fmt* pkt)
  { return oo_ipx_data(af, pkt); }

#define PKT_IPX_TCP_HDR(af, pkt) ci_pkt_ipx_tcp_hdr(af, pkt)

/*! Find the amount of data in an outgoing packet */
#define PKT_TCP_TX_SEQ_SPACE(pkt)                             \
   (SEQ_SUB((pkt)->pf.tcp_tx.end_seq, (pkt)->pf.tcp_tx.start_seq))

#define TX_PKT_TCP(pkt)  ((ci_tcp_hdr*) oo_tx_ipx_data(oo_pkt_af(pkt), pkt))
#define TX_PKT_UDP(pkt)  ((ci_udp_hdr*) oo_tx_ipx_data(oo_pkt_af(pkt), pkt))
#define TX_PKT_SPORT_BE16(pkt)  (((ci_uint16*) oo_tx_ip_data(pkt))[0])
#define TX_PKT_DPORT_BE16(pkt)  (((ci_uint16*) oo_tx_ip_data(pkt))[1])

#define TX_PKT_IPX_SPORT(af, pkt) (((ci_uint16*) oo_tx_ipx_data(af, pkt))[0])
#define TX_PKT_IPX_DPORT(af, pkt) (((ci_uint16*) oo_tx_ipx_data(af, pkt))[1])

#define TX_PKT_IPX_HDR(af, pkt) ((ci_ipx_hdr_t*) (oo_tx_ipx_hdr(af, pkt)))

#define TX_PKT_PROTOCOL(af, pkt) ipx_hdr_protocol(af, TX_PKT_IPX_HDR(af, pkt))
#define TX_PKT_TTL(af, pkt) ipx_hdr_ttl(af, TX_PKT_IPX_HDR(af, pkt))
#define TX_PKT_SADDR(af, pkt) ipx_hdr_saddr(af, TX_PKT_IPX_HDR(af, pkt))
#define TX_PKT_DADDR(af, pkt) ipx_hdr_daddr(af, TX_PKT_IPX_HDR(af, pkt))
#define TX_PKT_SET_SADDR(af, pkt, addr) \
    ipx_hdr_set_saddr(af, TX_PKT_IPX_HDR(af, pkt), (addr))
#define TX_PKT_SET_DADDR(af, pkt, addr) \
    ipx_hdr_set_daddr(af, TX_PKT_IPX_HDR(af, pkt), (addr))
#define TX_PKT_SET_FLOWLABEL(af, pkt, flowlabel) \
    ipx_hdr_set_flowlabel(af, TX_PKT_IPX_HDR(af, pkt), (flowlabel))

#define RX_PKT_IPX_HDR(pkt) oo_ipx_hdr(pkt)
#define RX_PKT_PROTOCOL(pkt) \
  ipx_hdr_protocol(oo_pkt_af(pkt), RX_PKT_IPX_HDR(pkt))
#define RX_PKT_TTL(pkt) \
  ipx_hdr_ttl(oo_pkt_af(pkt), RX_PKT_IPX_HDR(pkt))
#define RX_PKT_SADDR(pkt) \
  ipx_hdr_saddr(oo_pkt_af(pkt), RX_PKT_IPX_HDR(pkt))
#define RX_PKT_DADDR(pkt) \
  ipx_hdr_daddr(oo_pkt_af(pkt), RX_PKT_IPX_HDR(pkt))
#define RX_PKT_PAYLOAD_LEN(pkt) \
  ipx_hdr_tot_len(oo_pkt_af(pkt), RX_PKT_IPX_HDR(pkt))

static inline ci_udp_hdr* ci_tx_pkt_ipx_udp(int af, ci_ip_pkt_fmt* pkt,
                                            bool is_frag)
{
  if( IS_AF_INET6(af) && is_frag )
    return (ci_udp_hdr*)((uint8_t*)oo_tx_ipx_data(af, pkt) +
        sizeof(ci_ip6_frag_hdr));
  else
    return oo_tx_ipx_data(af, pkt);
}

static inline ci_tcp_hdr* ci_tx_pkt_ipx_tcp(int af, ci_ip_pkt_fmt* pkt)
{
  return oo_tx_ipx_data(af, pkt);
}

#define TX_PKT_IPX_UDP(af, pkt, is_frag) ci_tx_pkt_ipx_udp(af, pkt, is_frag)
#define TX_PKT_IPX_TCP(af, pkt) ci_tx_pkt_ipx_tcp(af, pkt)

static inline void* ci_ipx_data_ptr(int af, ci_ipx_hdr_t* hdr)
{
#if CI_CFG_IPV6
  if( af == AF_INET6 ) {
    return &hdr->ip6 + 1;
  }
  else
#endif
  {
    return (uint8_t*)&hdr->ip4 + CI_IP4_IHL(&hdr->ip4);
  }
}

static inline ci_uint16 ci_tx_pkt_ipx_tcp_payload_len(int af, ci_ip_pkt_fmt* pkt)
{
  ci_uint16 len;
#if CI_CFG_IPV6
  if( af == AF_INET6 ) {
    len = oo_tx_l3_len(pkt) - sizeof(ci_ip6_hdr);
  }
  else
#endif
  {
    ci_ip4_hdr* ip = oo_tx_ip_hdr(pkt);
    len = CI_BSWAP_BE16(ip->ip_tot_len_be16) - CI_IP4_IHL(ip);
  }
  return len - CI_TCP_HDR_LEN(TX_PKT_IPX_TCP(af, pkt));
}

/*! Get re-order buffer structure from TCP packet */
#define PKT_TCP_RX_ROB(pkt) (&(pkt)->pf.tcp_rx.misc.rob)

/*! Get tsval from timestamp option.  This had better be a TCP packet with
** a timestamp option!  (Horribly inefficient; only use for logging). */
#define PKT_TCP_TSO_TSVAL(pkt)                                          \
  CI_BSWAP_BE32(*(ci_uint32*) (CI_TCP_HDR_OPTS(PKT_TCP_HDR(pkt)) + 4))

#define PKT_IPX_TCP_TSO_TSVAL(af, pkt) \
  CI_BSWAP_BE32(*(ci_uint32*) (CI_TCP_HDR_OPTS(PKT_IPX_TCP_HDR(af, pkt)) + 4))


/* TODO: replace PKT_UDP_HDR and PKT_IOVEC_UDP_PFX by TX-specific and
 * generic function; see oo_tx_ip_hdr() performance notes. */
#define PKT_UDP_HDR(pkt)       ((ci_udp_hdr*)oo_ip_data(pkt))

static inline ci_udp_hdr* ci_pkt_ipx_udp_hdr(int af, ci_ip_pkt_fmt* pkt)
  { return oo_ipx_data(af, pkt); }

#define PKT_IPX_UDP_HDR(af, pkt) ci_pkt_ipx_udp_hdr(af, pkt)


/**********************************************************************
**************************** TCP RX packet ****************************
**********************************************************************/

typedef struct {
  struct ci_netif_poll_state* poll_state;
  ci_netif*      ni;
  ci_ip_pkt_fmt* pkt;
  ci_tcp_hdr*    tcp;

  /* [flags] can take any of the following values, or any of the tcp
  ** options flags (e.g. CI_TCPT_FLAG_*). */
#define CI_TCP_PAWS_FAILED       0x80000000
#define CI_TCP_SACKED            0x20000000 /* Something is newly SACKed */
#define CI_TCP_DSACK             0x10000000 /* First SACK block is duplicate */

  ci_uint32     flags;
  ci_uint32     timestamp;       /* pointer to timeval, host endian */
  ci_uint32     timestamp_echo;  /* pointer to timeval, host endian */
  ci_uint32     sack[8];         /* pointer to first block, host endian */
  ci_int32      sack_blocks;
  ci_uint32     ack,seq;         /* ACK and SEQ values in host endian */
  ci_uint32     hash;            /* hash for l/r addr/port */
} ciip_tcp_rx_pkt;



/**********************************************************************
************************** Network interface **************************
**********************************************************************/

/* The following are used in netic_init.c to decode EF_UDP_OPTIONS */
#define CI_EF_UDP_UL_RECV_M     0x00000007
#define CI_EF_UDP_UL_RECV_S              0

#define CI_EF_UDP_RECV_FAST_M   0x00000008
#define CI_EF_UDP_RECV_FAST_S            3

#define CI_EF_UDP_UL_POLL_M     0x00000070
#define CI_EF_UDP_UL_POLL_S              4


#define NI_ID(ni)    ((ni)->state->stack_id)
#define NI_CONF(ni)  ((ni)->state->conf)
#ifdef __KERNEL__
# define NI_OPTS(ni)  ((ni)->opts)
#else
# define NI_OPTS(ni)  ((ni)->state->opts)
#endif
#define NI_IPID(ni)  (&(ni)->state->ipid)

#ifdef __KERNEL__
# define NI_PKT_SET(ni) \
  ( (ni)->packets->id < 0 ? 0 :              \
    (ni)->packets->id >= (ni)->pkt_sets_n ?   \
    (ni)->pkt_sets_n - 1 : (ni)->packets->id )
#else
# define NI_PKT_SET(ni) ((ni)->packets->id)
#endif


extern void ci_netif_config_opts_rangecheck(ci_netif_config_opts* opts) CI_HF;
extern void ci_netif_config_opts_getenv(ci_netif_config_opts* opts) CI_HF;
extern void ci_netif_config_opts_defaults(ci_netif_config_opts* opts) CI_HF;
#ifdef __KERNEL__
extern void ci_netif_state_init(ci_netif* ni, int cpu_khz, 
                                const char* name) CI_HF;
extern int  ci_netif_ctor(ci_netif**, const ci_netif_config_opts*,
                          unsigned flags) CI_HF;
#else
extern int  ci_netif_ctor(ci_netif*, ef_driver_handle, const char* name,
                          unsigned flags) CI_HF;
extern void ci_netif_cluster_prefault(ci_netif* ni) CI_HF;
#endif
extern int  ci_netif_restore_id(ci_netif*, unsigned stack_id, bool is_service) CI_HF;
extern int citp_netif_by_id(ci_uint32 stack_id, ci_netif** out_ni, int locked) CI_HF;
extern int  ci_netif_restore_name(ci_netif*, const char*) CI_HF;
extern int  ci_netif_restore(ci_netif* ni, ci_fd_t fd,
			     unsigned netif_mmap_bytes) CI_HF;
extern int  ci_netif_dtor(ci_netif*) CI_HF;
extern unsigned ci_netif_build_future_intf_mask(ci_netif* ni) CI_HF;

extern void ci_netif_error_detected(ci_netif*, unsigned error_flag,
                                    const char* caller) CI_HF;

#if OO_DO_STACK_POLL
#ifndef __KERNEL__
extern int  ci_netif_poll_intf_future(ci_netif*, int intf_i, ci_uint64 now_frc)
  CI_HF;
#endif
extern int  ci_netif_poll_n(ci_netif*, int max_evs) CI_HF;
#define     ci_netif_poll(ni)  ci_netif_poll_n((ni), NI_OPTS(ni).evs_per_poll)

#if CI_CFG_WANT_BPF_NATIVE
#ifdef __KERNEL__
/* in-kernel backend for ci_netif_evq_poll_k */
extern int  ci_netif_evq_poll(ci_netif*, int intf);
#else
/* makes syscall to invoke ci_netif_evq_poll */
extern int  ci_netif_evq_poll_k(ci_netif* ni, int intf_i);
#endif
#endif

extern void ci_netif_tx_pkt_complete(ci_netif*, struct ci_netif_poll_state*,
                                     ci_ip_pkt_fmt*);
/* Fake TX complete function called when a packet was deferred because of
 * no destination MAC, and dropped as a response to various error. */
ci_inline void
cicp_pkt_complete_fake(ci_netif* ni, ci_ip_pkt_fmt* pkt)
{
  ni->state->nic[pkt->intf_i].tx_bytes_removed -= TX_PKT_LEN(pkt);
  ci_netif_tx_pkt_complete(ni, NULL, pkt);
}
#endif


extern void __ci_netif_send(ci_netif*, ci_ip_pkt_fmt* pkt) CI_HF;
ci_inline void ci_netif_send(ci_netif* ni, ci_ip_pkt_fmt* pkt)
{
  ci_assert_nflags(pkt->flags, CI_PKT_FLAG_TX_PENDING);
  pkt->flags |= CI_PKT_FLAG_TX_PENDING;
  __ci_netif_send(ni, pkt);
}
extern bool ci_netif_send_immediate(ci_netif* netif, ci_ip_pkt_fmt* pkt) CI_HF;
extern void ci_netif_rx_post(ci_netif* netif, int nic_index, ef_vi* vi) CI_HF;
#ifdef __KERNEL__
extern int  ci_netif_set_rxq_limit(ci_netif*) CI_HF;
extern int  ci_netif_init_fill_rx_rings(ci_netif*) CI_HF;
#endif
extern ci_uint64 ci_netif_purge_deferred_socket_list(ci_netif* ni) CI_HF;
extern void ci_netif_merge_atomic_counters(ci_netif* ni) CI_HF;
extern void ci_netif_mem_pressure_pkt_pool_fill(ci_netif*) CI_HF;
extern int  ci_netif_mem_pressure_try_exit(ci_netif*) CI_HF;

extern void ci_netif_timeout_remove(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_netif_timeout_leave(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void  ci_netif_timeout_reap(ci_netif* ni) CI_HF;
extern void ci_netif_timeout_state(ci_netif* ni) CI_HF;
extern void ci_netif_timeout_restart(ci_netif *ni, ci_tcp_state *ts) CI_HF;

extern void ci_netif_timewait_enter(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern int  ci_netif_timewait_try_to_free_filter(ci_netif* ni) CI_HF;
extern void ci_netif_fin_timeout_enter(ci_netif* ni, ci_tcp_state* ts) CI_HF;

extern void ci_netif_dump(ci_netif* ni) CI_HF;
extern void ci_vi_info_dump(ci_netif* ni) CI_HF;
extern void ci_netif_dump_to_logger(ci_netif* ni, oo_dump_log_fn_t logger,
                                    void* log_arg) CI_HF;
extern void ci_netif_dump_vi_stats(ci_netif* ni) CI_HF;
extern void ci_netif_dump_vi_stats_to_logger(ci_netif* ni,
                                             oo_dump_log_fn_t logger,
                                             void* log_arg) CI_HF;
extern void ci_netif_dump_extra(ci_netif* ni) CI_HF;
extern void ci_netif_dump_extra_to_logger(ci_netif* ni,
                                          oo_dump_log_fn_t logger,
                                          void *log_arg) CI_HF;
extern void ci_netif_dump_sockets(ci_netif* ni) CI_HF;
extern void ci_netif_dump_sockets_to_logger(ci_netif* ni,
                                            oo_dump_log_fn_t logger,
                                            void *log_arg) CI_HF;
extern void ci_netif_netstat_sockets_to_logger(ci_netif* ni,
                                               oo_dump_log_fn_t logger,
                                               void *log_arg) CI_HF;
extern void ci_netif_print_sockets(ci_netif* ni) CI_HF;
extern void ci_netif_dump_dmaq(ci_netif* ni, int dump) CI_HF;
extern void ci_netif_dump_timeoutq(ci_netif* ni) CI_HF;
extern void ci_netif_dump_reap_list(ci_netif* ni, int verbose) CI_HF;
extern void ci_netif_config_opts_dump(ci_netif_config_opts* opts,
                                      oo_dump_log_fn_t logger,
                                      void* log_arg) CI_HF;
extern void ci_stack_time_dump(ci_netif* ni, oo_dump_log_fn_t logger,
                               void* log_arg) CI_HF;
extern void ci_netif_pkt_dump_all(ci_netif* ni) CI_HF;
extern void ci_netif_pkt_queue_dump(ci_netif* ni, ci_ip_pkt_queue* q,
                                    int is_recv, int dump) CI_HF;
extern void ci_netif_pkt_list_dump(ci_netif* ni, oo_pkt_p head,
				   int is_recv, int dump) CI_HF;
extern void ci_netif_pkt_dump(ci_netif* ni, ci_ip_pkt_fmt*, int is_recv, 
                              int dump) CI_HF;
extern int  ci_netif_bad_hwport(ci_netif*, ci_hwport_id_t) CI_HF;
extern void ci_tcp_rx_checks(ci_netif*, ci_tcp_state*, ci_ip_pkt_fmt*) CI_HF;
extern void ci_tcp_listen_rx_checks(ci_netif*, ci_tcp_socket_listen*,
				    ci_ip_pkt_fmt*) CI_HF;

extern int  ci_netif_force_wake(ci_netif* ni, int everyone) CI_HF;

#if CI_CFG_EPOLL3
#ifndef __KERNEL__
extern int ci_netif_get_ready_list(ci_netif* ni) CI_HF;
#endif
extern void ci_netif_put_ready_list(ci_netif* ni, int id) CI_HF;
extern void ci_netif_free_ready_lists(ci_netif* ni);
#endif

CI_DEBUG(extern void ci_netif_assert_valid(ci_netif*, const char*, int);)
CI_DEBUG(extern void ci_netif_verify_freepkts(ci_netif *, const char *, int);)

#define ASSERT_VALID_NETIF_ADDR(ni, addr, size)  do{            \
  ci_assert(ci_to_int(addr) >= 0);                              \
  ci_assert((addr) < (ni)->state->netif_mmap_bytes);            \
  ci_assert((addr) + (size) <= (ni)->state->netif_mmap_bytes);  \
  }while(0)

ci_inline int ci_netif_num_vis(ci_netif* ni)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  switch( NI_OPTS(ni).tcp_offload_plugin ) {
    case CITP_TCP_OFFLOAD_OFF:     return 1;
    case CITP_TCP_OFFLOAD_RAW_TCP: return 2;
    default:                       return 2 + CI_CFG_TCP_PLUGIN_EXTRA_VIS;
  }
#endif
  return 1;
}

/*********************************************************************
************************* Packet buffer mgmt *************************
*********************************************************************/

/* Assert packet is empty - but may contain payload */
#ifndef NDEBUG 
#define ASSERT_PKT_PAYLOAD_EMPTY(p) ci_assert_equal(p->pay_len, 0);
#else
#define ASSERT_PKT_PAYLOAD_EMPTY(p)
#endif


/* True if [id] is in legal range. */
#define IS_VALID_PKT_ID(ni, pp)  OO_PP_EQ((pp), VALID_PKT_ID((ni), (pp)))

/* Validate packet id. */
#define ASSERT_VALID_PKT_ID(ni, id)                     \
  ci_ss_assert((ni), IS_VALID_PKT_ID((ni), (id)))
#define __ASSERT_VALID_PKT_ID(ni, id, file, line)       \
  ci_ss_assertfl((ni), IS_VALID_PKT_ID((ni), (id)), file, line)


#ifdef NDEBUG
# define ASSERT_VALID_PKT(ni, pkt)
# define ASSERT_VALID_PKT_NNL(ni, pkt)
# define ASSERT_VALID_PKT_MAYBE_NNL(ni, pkt, ni_locked)
#else
# define ASSERT_VALID_PKT(ni, pkt)                                      \
      ci_assert_valid_pkt((ni), (pkt), CI_TRUE, __FILE__, __LINE__)
# define ASSERT_VALID_PKT_NNL(ni, pkt)                                  \
      ci_assert_valid_pkt((ni), (pkt), CI_FALSE, __FILE__, __LINE__)
# define ASSERT_VALID_PKT_MAYBE_NNL(ni, pkt, ni_locked)                 \
      ci_assert_valid_pkt((ni), (pkt), (ni_locked), __FILE__, __LINE__)
#endif


/*********************************************************************
*************************** Packet buffers ***************************
*********************************************************************/

#ifdef __KERNEL__
# define IS_VALID_SOCK_ID(ni, id)  ((unsigned) (id) < (ni)->ep_tbl_n)
#else
# define IS_VALID_SOCK_ID(ni, id)  ((unsigned) (id) < (ni)->state->n_ep_bufs)
#endif

#define IS_VALID_SOCK_P(ni, sockp)  IS_VALID_SOCK_ID((ni), OO_SP_TO_INT(sockp))


# define PKT_DBG_FMT                    "[id=%d flgs=%x]"
# define PKT_DBG_ARGS(p)                OO_PKT_FMT(p), (p)->flags


extern int ci_netif_pktset_best(ci_netif* ni) CI_HF;
extern void ci_netif_pkt_free(ci_netif* ni, ci_ip_pkt_fmt* pkt
                              CI_KERNEL_ARG(int* p_netif_is_locked)) CI_HF;

#define CI_PKT_ALLOC_FOR_TCP_TX 1
#define CI_PKT_ALLOC_USE_NONB   2
#define CI_PKT_ALLOC_NO_REAP    4
extern ci_ip_pkt_fmt* ci_netif_pkt_alloc_slow(ci_netif*, int flags) CI_HF;
extern int ci_netif_pkt_try_to_free(ci_netif* ni, int desperation,
                                    int stop_once_freed_n) CI_HF;
extern void ci_netif_try_to_reap(ci_netif* ni, int stop_once_freed_n) CI_HF;
extern void ci_netif_rxq_low_on_recv(ci_netif*, ci_sock_cmn*,
                                     int bytes_freed) CI_HF;

/*! Allocate a packet buffer, blocking if necessary.  If can_block=FALSE
 * this function returns 0 or -ENOBUFS.  At userlevel this
 * function will never fail if can_block=TRUE.  In the kernel this
 * function may return -ERESTARTSYS if interrupted by a signal.
 *
 * The stack lock may be grabbed or dropped by this function.  This call
 * does *not* "exit" the library, so if any signals occur when called from
 * userspace, they are deferred.
 */
extern int ci_netif_pkt_alloc_block(ci_netif*, ci_sock_cmn*,
                                    int* ni_locked,
                                    int can_block,
                                    ci_ip_pkt_fmt** p_pkt) CI_HF;

/*! Sleeps until a packet buffer becomes available, returning 0 on success.
 * At userlevel this function will never fail.  In the kernel it may return
 * -ERESTARTSYS if interrupted by a signal.
 *
 * On success, if CI_SLEEP_NETIF_RQ is set, the netif is locked on return.
 *
 *   [lock_flags] indicates whether the caller is holding the netif lock on
 *   entry (CI_SLEEP_NETIF_LOCKED), and whether it should be locked before
 *   return (CI_SLEEP_NETIF_RQ).
 *
 * See also ci_netif_pkt_wait_was_interrupted().
 */
extern int ci_netif_pkt_wait(ci_netif*, ci_sock_cmn* s, int lock_flags) CI_HF;

extern ci_ip_pkt_fmt* __ci_netif_pkt_rx_to_tx(ci_netif*, ci_ip_pkt_fmt*,
                                              const char*) CI_HF;
#define ci_netif_pkt_rx_to_tx(ni, pkt)                          \
      __ci_netif_pkt_rx_to_tx((ni), (pkt), __FUNCTION__)

extern int ci_netif_pkt_pass_to_kernel(ci_netif* ni, ci_ip_pkt_fmt* pkt);


/**********************************************************************
**************************** Socket buffers ***************************
**********************************************************************/

extern void oo_sock_cplane_init(struct oo_sock_cplane*) CI_HF;
extern void ci_sock_cmn_init(ci_netif*, ci_sock_cmn*, int can_poison) CI_HF;
extern void ci_sock_cmn_reinit(ci_netif*, ci_sock_cmn*) CI_HF;
extern void ci_sock_cmn_dump(ci_netif*, ci_sock_cmn*, const char* pf,
                             oo_dump_log_fn_t logger, void* log_arg) CI_HF;

# define S_SP(ss)  ((ss)->s.b.bufid)
# define SC_SP(s)  ((s)->b.bufid)
# define W_SP(w)   ((w)->bufid)

#define S_ID(ss)   OO_SP_TO_INT(S_SP(ss))
#define SC_ID(s)   OO_SP_TO_INT(SC_SP(s))
#define W_ID(w)    OO_SP_TO_INT(W_SP(w))

#define S_FMT(ss)  OO_SP_FMT(S_SP(ss))
#define SC_FMT(s)  OO_SP_FMT(SC_SP(s))
#define W_FMT(w)   OO_SP_FMT(W_SP(w))


/* Wrappers to determine whether a socket has been bound, and if so, how */
#define CI_SOCK_EXPLICIT_BIND(s) ((s)->s_flags & CI_SOCK_FLAG_BOUND)
#define CI_SOCK_IMPLICIT_BIND(s) \
  (!CI_SOCK_EXPLICIT_BIND((s)) && sock_lport_be16((s)))
#define CI_SOCK_NOT_BOUND(s)     (!sock_lport_be16((s)))

void ci_ipcache_set_saddr(ci_ip_cached_hdrs* ipcache, ci_addr_t addr);
void ci_ipcache_set_daddr(ci_ip_cached_hdrs* ipcache, ci_addr_t addr);

ci_inline void ci_sock_set_laddr(ci_sock_cmn* s, ci_addr_t addr)
{
  s->laddr = addr;
}
#define ci_sock_set_raddr(s, addr) ci_ipcache_set_daddr(&(s)->pkt, addr)

void ci_sock_set_laddr_port(ci_sock_cmn* s, ci_addr_t addr, ci_uint16 port);
void ci_sock_set_raddr_port(ci_sock_cmn* s, ci_addr_t addr, ci_uint16 port);

ci_addr_t sock_laddr(ci_sock_cmn* s);
ci_addr_t sock_raddr(ci_sock_cmn* s);

/**********************************************************************
 ****************************** so_error ******************************
 **********************************************************************/

/* Note: we do not require a lock to set the so_error field */

/* [s] = ci_sock_cmn*, [e] is >= 0 error value */
#define CI_SET_SO_ERROR(s,e) do { \
  ci_assert_ge(e,0); if((e)) (s)->so_error=(e); } while(0)

/* [t] = ci_tcp_state*, [e] = +ve error value */
#define CI_SET_TCP_SO_ERROR(t,e) CI_SET_SO_ERROR(&(t)->s,(e))
/* [u] = ci_udp_state*, [e] = +ve error value */
#define CI_SET_UDP_SO_ERROR(u,e) CI_SET_SO_ERROR(&(u)->s,(e))

ci_inline ci_int32 ci_get_so_error(ci_sock_cmn *s)
{
  ci_int32 rc;
  do {
    rc = s->so_error;
  } while( rc != 0 && ci_cas32_fail(&s->so_error, rc, 0) );
  return rc;
}

/**********************************************************************
 ************************ rx_errno & tx_errno *************************
 **********************************************************************/

#define SOCK_TX_ERRNO(s)        ((s)->tx_errno)
#define SOCK_RX_ERRNO(s)        ((s)->rx_errno & 0x3fff)

/**********************************************************************
 **************************** ICMP/Errors *****************************
 **********************************************************************/

extern int
ci_icmp_send(ci_netif *ni, ci_ip_pkt_fmt *tx_pkt,
	     const ci_addr_t saddr, const ci_addr_t daddr,
	     const ci_mac_addr_t *mac_dest,
	     ci_uint8 type, ci_uint8 code, ci_uint16 data_len) CI_HF;

extern int __ci_icmp_send_error(ci_netif* ni, int af, ci_ipx_hdr_t* ipx,
                                struct oo_eth_hdr* rx_eth, ci_uint8 type,
                                ci_uint8 code) CI_HF;

/**********************************************************************
********************************* UDP *********************************
**********************************************************************/

#define CI_UDP_INITIAL_MTU ETH_DATA_LEN

/* IPv4 "Total Length" 16-bit field defines the entire packet size in bytes,
 * including header and data, while IPv6 "Payload Length" 16-bit field defines
 * the size of payload only. So, when calculating UDP maximum payload size for
 * IPv4 case, IPv4 header size should be considered, unlike IPv6 case. */
#define CI_UDP_MAX_PAYLOAD_BYTES(af) \
  (0xffff - sizeof(ci_udp_hdr) - (IS_AF_INET6(af) ? 0 : sizeof(ci_ip4_hdr)))

#define UDP_FLAGS(us)           ((us)->udpflags)

#define UDP_SET_FLAG(us,f)      ((us)->udpflags|=(f))
#define UDP_CLR_FLAG(us,f)      ((us)->udpflags&=~(f))
#define UDP_GET_FLAG(us,f)      ((us)->udpflags&(f))

#define UDP_IP_HDR(us)          (&(us)->s.pkt.ipx.ip4)

#define udp_lport_be16(us)      (sock_lport_be16(&us->s))
#define udp_laddr_be32(us)      (sock_laddr_be32(&us->s))
#define udp_frag_off_be16(us)   (UDP_IP_HDR((us))->ip_frag_off_be16)
#define udp_rport_be16(us)      (sock_rport_be16(&us->s))
#define udp_raddr_be32(us)      (sock_raddr_be32(&us->s))

#if CI_CFG_IPV6
#define udp_ip6_laddr(us)       (sock_ip6_laddr(&us->s))
#define udp_ip6_raddr(us)       (sock_ip6_raddr(&us->s))
#endif

#define sock_ipx_laddr(s) ((s)->laddr)
#define sock_ipx_raddr(s) ipcache_raddr(&(s)->pkt)

#define udp_ipx_laddr(us) sock_ipx_laddr(&(us)->s)
#define udp_ipx_raddr(us) sock_ipx_raddr(&(us)->s)

#define UDP_TX_ERRNO(us)        (SOCK_TX_ERRNO(&(us)->s))
#define UDP_RX_ERRNO(us)	(SOCK_RX_ERRNO(&(us)->s))
#define UDP_IS_SHUT_RD(us)      ((us)->s.rx_errno & CI_SHUT_RD)
#define UDP_IS_SHUT_WR(us)      ((us)->s.rx_errno & CI_SHUT_WR)
#define UDP_IS_SHUT_RDWR(us)				\
    (((us)->s.rx_errno & (CI_SHUT_RD | CI_SHUT_WR)) ==   \
     (CI_SHUT_RD | CI_SHUT_WR))


/***  udp.c  ***/

extern void ci_udp_state_dump(ci_netif*, ci_udp_state*, const char* pf,
                              oo_dump_log_fn_t logger, void* log_arg) CI_HF;

/* Set the source IP address & port */
ci_inline void
ci_sock_cmn_set_laddr(ci_sock_cmn* s, ci_addr_t addr, int lport_be16)
{
  ci_sock_set_laddr_port(s, addr, lport_be16);
  s->cp.lport_be16 = lport_be16;
  /* FIXIT: add IPv6 multicast support */
  if( CI_IPX_IS_MULTICAST(addr) )
    s->cp.laddr = ip4_addr_any;
  else
    s->cp.laddr = addr;

}

extern void ci_udp_state_assert_valid(ci_netif*, ci_udp_state* ts,
				      const char* file, int line) CI_HF;

extern void ci_udp_ep_assert_valid(citp_socket* ep,
				   const char* file, int line) CI_HF;


/*** udp_rx.c ***/
extern void ci_udp_handle_rx(ci_netif*, ci_ip_pkt_fmt* pkt, ci_udp_hdr*,
                             int ip_paylen) CI_HF;


ci_inline 
void ci_pkt_init_from_ipcache_len(ci_ip_pkt_fmt *pkt,
                                  const ci_ip_cached_hdrs *ipcache,
                                  size_t header_len)
{
  if( !ipcache_is_ipv6(ipcache) ) {
    ci_assert_equal(CI_IP4_IHL(&ipcache->ipx.ip4), sizeof(ci_ip4_hdr));
    ci_assert_equal(ipcache->ether_type, CI_ETHERTYPE_IP);
  }
  oo_tx_pkt_layout_update(pkt, ipcache->ether_offset);
  memcpy(oo_tx_ether_hdr(pkt), ci_ip_cache_ether_hdr(ipcache),
         header_len + oo_tx_ether_hdr_size(pkt));
  if( !ipcache_is_ipv6(ipcache) ) {
    ci_assert_equal(CI_IP4_IHL(oo_tx_ip_hdr(pkt)), sizeof(ci_ip4_hdr));
    ci_assert_equal(oo_tx_ether_type_get(pkt), CI_ETHERTYPE_IP);
  }
}


ci_inline 
void ci_pkt_init_from_ipcache(ci_ip_pkt_fmt *pkt,
                              const ci_ip_cached_hdrs *ipcache)
{
  ci_pkt_init_from_ipcache_len(pkt, ipcache,
      CI_IPX_HDR_SIZE(ipcache_af(ipcache)) + sizeof(ci_tcp_hdr));
}


#if CI_CFG_IPV6
void ci_init_ipcache_ip4_hdr(ci_sock_cmn* s);
void ci_init_ipcache_ip6_hdr(ci_sock_cmn* s);
#endif


/*
** External interface
*/

struct cmsg_state {
  struct msghdr* msg;
  struct cmsghdr* cm;
  int cmsg_bytes_used;
  int* p_msg_flags;
};

extern void ci_put_cmsg(struct cmsg_state *cmsg_state, int level, int type,
                        socklen_t len, const void *data) CI_HF;
/* info_out contains a pointer to struct in_pktinfo or struct in6_pktinfo */
extern int ci_ip_cmsg_send(const struct msghdr*, void** info_out) CI_HF;
extern void ci_ip_cmsg_finish(struct cmsg_state* cmsg_state) CI_HF;

#ifndef __KERNEL__

/* extern int ci_tp_init(void); */
extern ci_fd_t ci_udp_ep_ctor(citp_socket* ep, ci_netif* sh,
                              int domain, int type) CI_HF;
extern int ci_udp_bind_start(citp_socket* ep, ci_fd_t fd,
                             const struct sockaddr* addr, socklen_t addrlen,
                             ci_uint16* lport) CI_HF;
extern int ci_udp_bind_conclude(citp_socket* ep, const struct sockaddr* addr,
                                socklen_t addrlen, ci_uint16 lport);
#if CI_CFG_ENDPOINT_MOVE
extern void ci_udp_handle_force_reuseport(ci_fd_t fd, citp_socket* ep,
                                          const struct sockaddr* sa,
                                          socklen_t sa_len) CI_HF;
extern int ci_udp_reuseport_bind(citp_socket* ep, ci_fd_t fd,
                                 const struct sockaddr* sa,
                                 socklen_t sa_len, ci_uint16 lport) CI_HF;
#endif
extern int ci_udp_connect(citp_socket*, ci_fd_t fd,
			  const struct sockaddr*, socklen_t addrlen) CI_HF;
extern int ci_udp_connect_conclude(citp_socket* ep, ci_fd_t fd,
                                   const struct sockaddr* serv_addr, 
                                   socklen_t addrlen, ci_fd_t os_sock) CI_HF;

extern int ci_udp_shutdown(citp_socket*, ci_fd_t fd, int how) CI_HF;
extern int __ci_udp_shutdown(ci_netif* netif, ci_udp_state* us, int how) CI_HF;
extern int ci_udp_getpeername(citp_socket*, struct sockaddr*,socklen_t*) CI_HF;

extern int ci_udp_getsockopt(citp_socket* ep, ci_fd_t fd, int level,
		     int optname, void *optval, socklen_t *optlen ) CI_HF;
extern int ci_udp_setsockopt(citp_socket* ep, ci_fd_t fd, int level,
		     int optname, const void*optval, socklen_t optlen) CI_HF;
extern int ci_udp_ioctl(citp_socket*, ci_fd_t, int request, void* arg) CI_HF;
#endif

/* Send/recv called from within kernel & user-library, so outside above #if */
extern int ci_udp_sendmsg(ci_udp_iomsg_args *a,
                          const ci_msghdr*, int) CI_HF;
extern int ci_udp_recvmsg(ci_udp_iomsg_args *a, ci_msghdr*,
                          int flags) CI_HF;

extern void ci_udp_set_no_unicast(citp_socket* ep) CI_HF;

#ifdef __KERNEL__
/*! A [ci_addr_spc_t] is a context in which to interpret pointers.
**
** - CI_ADDR_SPC_INVALID means do not attempt to interpret the pointers
**
** - CI_ADDR_SPC_KERNEL means the pointers can be dereferenced directly
**
** - CI_ADDR_SPC_CURRENT means we're in a context in which we can access
**   userlevel pointers via some optimised mechanism (copy_to/from_user()
**   on Linux).
*/
typedef enum {
  CI_ADDR_SPC_INVALID = 1,
  CI_ADDR_SPC_KERNEL = 2,
  CI_ADDR_SPC_CURRENT = 3,
} ci_addr_spc_t;
#endif

#ifndef __KERNEL__
struct mmsghdr;
extern int ci_udp_recvmmsg(ci_udp_iomsg_args *a, struct mmsghdr* mmsg, 
                           unsigned int vlen, int flags, 
                           const struct timespec* timeout
                           CI_KERNEL_ARG(ci_addr_spc_t addr_spc)) CI_HF;

struct onload_zc_mmsg;
extern int ci_tcp_zc_send(ci_netif* ni, ci_tcp_state* ts, 
                          struct onload_zc_mmsg* msgs, int flags);
struct onload_zc_recv_args;
int ci_udp_zc_recv(ci_udp_iomsg_args* a, struct onload_zc_recv_args* args);

/* A special version of recvmsg to grab data from kernel stack when
 * doing zero-copy 
 */
extern int ci_udp_recvmsg_kernel(int fd, ci_netif* ni, ci_udp_state* us,
                                 struct msghdr* msg, int flags);

extern enum onload_delegated_send_rc
ci_tcp_ds_fill_headers(ci_netif* ni, ci_tcp_state* ts, unsigned flags,
                       void* headers, int* headers_len_inout,
                       int* ip_tcp_hdr_len_out,
                       int* tcp_seq_offset_out, int* ip_len_offset_out);
extern int ci_tcp_ds_done(ci_netif* ni, ci_tcp_state* ts,
                          const ci_iovec *iov, int iovlen, int flags);

extern int
ci_netif_raw_send(ci_netif* ni, int intf_i,
                  const ci_iovec *iov, int iovlen);
#endif

extern void ci_ip_cmsg_recv(ci_netif*, ci_udp_state*, const ci_ip_pkt_fmt*,
                            struct msghdr*, int netif_locked,
                            int *p_msg_flags) CI_HF;
#if OO_DO_STACK_POLL
extern void ci_udp_all_fds_gone(ci_netif* netif, oo_sp, int do_free);
#endif
extern void ci_udp_state_free(ci_netif*, ci_udp_state*) CI_HF;
extern void ci_udp_state_try_free(ci_netif*, ci_udp_state*) CI_HF;
extern int ci_udp_csum_correct(ci_ip_pkt_fmt* pkt, ci_udp_hdr* udp) CI_HF;

extern void ci_udp_sendmsg_send_async_q(ci_netif*, ci_udp_state*) CI_HF;
extern void ci_udp_perform_deferred_socket_work(ci_netif*, ci_udp_state*)CI_HF;
extern int ci_udp_try_to_free_pkts(ci_netif*, ci_udp_state*,
                                    int desperation) CI_HF;

#define CI_PIPE_ZC_WRITE_FLAG_FORCE (1<<16)

struct ci_pipe_pkt_list {
  ci_ip_pkt_fmt* head;
  ci_ip_pkt_fmt* tail;
  int count;
};

typedef int (*ci_pipe_zc_read_cb)(void* context, struct iovec* iovec,
                                 int iov_num, int flags);

extern int ci_pipe_read(ci_netif*, struct oo_pipe*, const struct iovec*,
                  size_t iovlen) CI_HF;
extern int ci_pipe_write(ci_netif*, struct oo_pipe*, const struct iovec*,
                         size_t iovlen) CI_HF;
extern int ci_pipe_zc_read(ci_netif* ni, struct oo_pipe* p, int len,
                           int flags, ci_pipe_zc_read_cb cb, void* ctx) CI_HF;
extern int ci_pipe_zc_move(ci_netif* ni, struct oo_pipe* pipe_src,
                           struct oo_pipe* pipe_dest, int len, int flags) CI_HF;
extern int ci_pipe_zc_write(ci_netif* ni, struct oo_pipe* p,
                            struct ci_pipe_pkt_list* pkts,
                            int len, int flags) CI_HF;
extern int ci_pipe_zc_alloc_buffers(ci_netif* ni,
                                    struct oo_pipe* p,
                                    int flags,
                                    int count,
                                    struct ci_pipe_pkt_list* pkts_out) CI_HF;
extern int ci_pipe_zc_release_buffers(ci_netif* ni,
                                      struct oo_pipe* p,
                                      struct ci_pipe_pkt_list* pkts) CI_HF;
extern int ci_pipe_set_size(ci_netif* ni, struct oo_pipe* p,
                            size_t size) CI_HF;
extern void oo_pipe_dump(ci_netif*, struct oo_pipe*, const char* pf,
                         oo_dump_log_fn_t logger, void* log_arg) CI_HF;
extern int ci_pipe_list_to_iovec(ci_netif* ni, struct oo_pipe* p,
                                 struct iovec* iov,
                                 int* iov_num,
                                 struct ci_pipe_pkt_list* pkts,
                                 int len);


/**********************************************************************
 ********************************* TCP ********************************
 **********************************************************************/

#define SEQ_EQ(s1, s2)      ((ci_uint32)((s1) - (s2)) == 0u)
#define SEQ_LT(s1, s2)      ((ci_int32)((s1) - (s2)) < 0)
#define SEQ_LE(s1, s2)      ((ci_int32)((s1) - (s2)) <= 0)
#define SEQ_GT(s1, s2)      ((ci_int32)((s1) - (s2)) > 0)
#define SEQ_GE(s1, s2)      ((ci_int32)((s1) - (s2)) >= 0)
#define SEQ_SUB(s1, s2)     ((ci_int32)((s1) - (s2)))
#define SEQ(s)              ((unsigned) (s))

/* Is [s] between [sl] and [sh] (inclusive) */
#define SEQ_BTW(s, sl, sh)  ((sh) - (sl) >= (s) - (sl))

#define SEQ_MIN(x, y)           (SEQ_LE(x, y) ? (x) : (y))
#define SEQ_MAX(x, y)           (SEQ_LE(x, y) ? (y) : (x))


/* Flags for connection states.  These are used to determine whether
** certain things can/should be done in the current state.
*/
#define CI_TCP_STATE_SYNCHRONISED	0x001
#define CI_TCP_STATE_SLOW_PATH		0x002
#define CI_TCP_STATE_NOT_CONNECTED	0x004
#define CI_TCP_STATE_RECVD_FIN		0x008
#define CI_TCP_STATE_ACCEPT_DATA	0x010
#define CI_TCP_STATE_TXQ_ACTIVE		0x020
#define CI_TCP_STATE_NO_TIMERS		0x040
#define CI_TCP_STATE_TIMEOUT_ORPHAN	0x080
#define CI_TCP_STATE_TCP_CONN		0x100
#define CI_TCP_STATE_TCP		0x200
#define CI_TCP_STATE_INVALID		0x400

/* 0x800 is unused */

/* Connection states.  See also [tcp_misc.c] if you change these. */
#define CI_TCP_CLOSED          (0x0000 | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_NO_TIMERS)
#define CI_TCP_LISTEN          (0x1000 | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_NO_TIMERS)
#define CI_TCP_INVALID         (CI_TCP_LISTEN | CI_TCP_STATE_INVALID)
#define CI_TCP_SYN_SENT        (0x2000 | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_TXQ_ACTIVE)
#define CI_TCP_ESTABLISHED     (0x3000 | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_ACCEPT_DATA	\
                                       | CI_TCP_STATE_TXQ_ACTIVE )
#define CI_TCP_CLOSE_WAIT      (0x4000 | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_RECVD_FIN		\
                                       | CI_TCP_STATE_TXQ_ACTIVE )
#define CI_TCP_LAST_ACK        (0x5000 | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_RECVD_FIN		\
                                       | CI_TCP_STATE_TXQ_ACTIVE	\
                                       | CI_TCP_STATE_TIMEOUT_ORPHAN )
#define CI_TCP_FIN_WAIT1       (0x6000 | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_ACCEPT_DATA	\
                                       | CI_TCP_STATE_TXQ_ACTIVE	\
                                       | CI_TCP_STATE_TIMEOUT_ORPHAN )
#define CI_TCP_FIN_WAIT2       (0x7000 | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_ACCEPT_DATA	\
                                       | CI_TCP_STATE_TIMEOUT_ORPHAN )
#define CI_TCP_CLOSING         (0x8000 | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_RECVD_FIN		\
                                       | CI_TCP_STATE_TXQ_ACTIVE	\
                                       | CI_TCP_STATE_TIMEOUT_ORPHAN )
#define CI_TCP_TIME_WAIT       (0x9000 | CI_TCP_STATE_TCP		\
				       | CI_TCP_STATE_TCP_CONN		\
				       | CI_TCP_STATE_SYNCHRONISED	\
                                       | CI_TCP_STATE_SLOW_PATH		\
                                       | CI_TCP_STATE_NOT_CONNECTED	\
                                       | CI_TCP_STATE_RECVD_FIN		\
                                       /* 2MSL timer doesn't count */	\
                                       | CI_TCP_STATE_NO_TIMERS)

/* Set in a socket that is freed. */
#define CI_TCP_STATE_FREE      (0xa000 | CI_TCP_STATE_NO_TIMERS)

/* Set in a socket that is UDP */
#define CI_TCP_STATE_UDP       (0xb000)

/* Set in a waitable which is in fact a pipe meta (not a pipe end) */
#define CI_TCP_STATE_PIPE      (0xc000)

/* This endpoint is used to store aux buffers (synrecv states & some
 * others) */
#define CI_TCP_STATE_AUXBUF    (0xd000)

/* Set in a socket that is used as the owner for an active wild filter */
#define CI_TCP_STATE_ACTIVE_WILD (0xe000)


/* Convert state to number in range 0->0xe */
#define CI_TCP_STATE_NUM(s)    (((s) & 0xf000) >> 12u)


/* Flags we don't expect to see in normal data packets. */
#define CI_TCP_OOB_FLAGS     (CI_TCP_FLAG_SYN|CI_TCP_FLAG_FIN|  \
                              CI_TCP_FLAG_RST|CI_TCP_FLAG_ECE|  \
                              CI_TCP_FLAG_CWR)

/* Flags to check for a socket */
#define CI_TCP_STATE_IS_SOCKET(s) ((s) == CI_TCP_STATE_UDP ||   \
                                   (s) & CI_TCP_STATE_TCP)

/* For the fast path check we inspect header length and all flags other
** than PSH.
*/
#define CI_TCP_FAST_PATH_MASK       CI_BSWAPC_BE32(0xf0f70000)
#define CI_TCP_FAST_PATH_WORD(hdr)  (((ci_uint32*)(hdr))[3])

#ifndef MSG_NOSIGNAL    /* Introduced in glibc3. */
# define MSG_NOSIGNAL           0
#endif


#define tcp_outgoing_opts_len(ts)               \
  ((ts)->outgoing_hdrs_len - sizeof(ci_ip4_hdr) - sizeof(ci_tcp_hdr))

#define tcp_ipx_outgoing_opts_len(af, ts) \
  ((ts)->outgoing_hdrs_len - CI_IPX_HDR_SIZE(af) - sizeof(ci_tcp_hdr))

/* These names match the terminology used in the RFCs etc. */
#define tcp_snd_una(ts)  ((ts)->snd_una)
#define tcp_snd_nxt(ts)  ((ts)->snd_nxt)
#define tcp_snd_wnd(ts)  SEQ_SUB((ts)->snd_max, (ts)->snd_una)
#define tcp_snd_up(ts)   ((ts)->snd_up)

#define tcp_rcv_nxt(ts)  (TS_IPX_TCP(ts)->tcp_ack_be32)
#define tcp_rcv_usr(ts)  ((ts)->rcv_added - (ts)->rcv_delivered)
#define tcp_rcv_up(ts)   ((ts)->rcv_up)
#define tcp_rcv_wnd_advertised(ts)  ((ts)->rcv_wnd_advertised)
#define tcp_rcv_wnd_right_edge_sent(ts)  ((ts)->rcv_wnd_right_edge_sent)
#define tcp_rcv_wnd_current(ts) \
    CI_MIN((ts)->rcv_window_max, (ts)->s.so.rcvbuf - tcp_rcv_usr(ts))

/* TCP packet urgent offset - named urgent offset
   to differantiate it from snd_up of the tcp state */
#define tcp_snd_urg_off(ts,tcp) \
  ( (ci_uint16) (tcp_snd_up(ts) - CI_BSWAP_BE32((tcp)->tcp_seq_be32)) )

/* Sequence number of next data to be inserted into TX queue. */
#define tcp_enq_nxt(ts)  (TS_IPX_TCP(ts)->tcp_seq_be32)

/* TCP urgent data definitions */
#define tcp_urg_data(ts) ((ts)->urg_data)
#define tcp_urg_data_invalidate(ts) ((ts)->urg_data &=~ \
  (CI_TCP_URG_IS_HERE|CI_TCP_URG_PTR_VALID|CI_TCP_URG_DATA_MASK));

/*! Returns true if we are not expecting an urgent byte. */
#define tcp_rx_urg_fast_path(ts) (~tcp_urg_data(ts) & CI_TCP_URG_COMING)


/* conversion from scaled sa and sv to real srtt and rttvar */
#define tcp_srtt(ts)     ((ts)->sa >> 3u)
#define tcp_rttvar(ts)   ((ts)->sv >> 2u) 

#define CI_SHUT_RD  0x8000
#define CI_SHUT_WR  0x4000
#define TCP_RX_DONE(ts)  ((ts)->s.rx_errno)

#define TCP_RX_ERRNO(ts) (SOCK_RX_ERRNO(&(ts)->s))
#define TCP_TX_ERRNO(ts) (SOCK_TX_ERRNO(&(ts)->s))

/* We never transmit IP options (at the moment). */
#define S_TCP_HDR(s)  ((ci_tcp_hdr*) (&(s)->pkt.ipx.ip4 + 1))
#define TS_TCP(ts)    S_TCP_HDR(&(ts)->s)

#if CI_CFG_IPV6
#define S_IP6_TCP_HDR(s) ((ci_tcp_hdr*) (&(s)->pkt.ipx.ip6 + 1))
#define TS_IP6_TCP(ts) S_IP6_TCP_HDR(&(ts)->s)
#endif

#if CI_CFG_IPV6
#define S_IPX_TCP_HDR(s) ((ipcache_is_ipv6(&(s)->pkt)) ? \
  S_IP6_TCP_HDR(s) : S_TCP_HDR(s))
#define TS_IPX_TCP(ts) ((ipcache_is_ipv6(&(ts)->s.pkt)) ? \
  TS_IP6_TCP(ts) : TS_TCP(ts))
#else
#define S_IPX_TCP_HDR(s) S_TCP_HDR(s)
#define TS_IPX_TCP(ts) TS_TCP(ts)
#endif

/** Macro that initialises RX queue offset */
#define TS_QUEUE_RX_SET(ts, name)				\
  ((ts)->recv_off = CI_MEMBER_OFFSET(ci_tcp_state, name))

/** Get active RX queue (fast/slow as appropriate) from TCP state */
#define TS_QUEUE_RX(ts)				\
  ((ci_ip_pkt_queue*)				\
   ((ci_uintptr_t) (ts) + (ts)->recv_off))

/** Offset of TS within netif state. */
#define TS_OFF(ni, ts)  oo_sockp_to_statep((ni),S_SP(ts))
#define TS_MEMBER_OFF(ni, ts, member) ((ci_uint32)((char *)&(member)    \
                                       - (char*)(ts)        \
                                       + TS_OFF((ni),(ts)))) 
#define TS_FMT			"%d(%u)"
#define TS_ARG(ni,ts)		(S_SP(ts)), (unsigned) TS_OFF((ni),(ts))

#define TCP_STATE_FROM_LINK(lnk)                        \
  CI_CONTAINER(ci_tcp_state, timeout_q_link, (lnk))

/* Macros for controlling delayed ACK state */
#define TCP_FORCE_ACK(ts)   ((ts)->acks_pending |= CI_TCP_ACK_FORCED_FLAG)
#define TCP_NEED_ACK(ts)    (++(ts)->acks_pending)
#define TCP_ACK_FORCED(ts)  ((ts)->acks_pending & CI_TCP_ACK_FORCED_FLAG)

/* macros for getting source and dest addresses and ports */
#if CI_CFG_IPV6
#define ipcache_ttl(ipcache) (*(ipcache_is_ipv6(ipcache) ? \
  &(ipcache)->ipx.ip6.hop_limit : &(ipcache)->ipx.ip4.ip_ttl))
#else
#define ipcache_ttl(ipcache) ((ipcache)->ipx.ip4.ip_ttl)
#endif

#if CI_CFG_IPV6
#define ipcache_protocol(ipcache) (*(ipcache_is_ipv6(ipcache) ? \
  &(ipcache)->ipx.ip6.next_hdr : &(ipcache)->ipx.ip4.ip_protocol))
#else
#define ipcache_protocol(ipcache) ((ipcache)->ipx.ip4.ip_protocol)
#endif

#define sock_laddr_be32(s) ((s)->laddr.ip4)
#define sock_raddr_be32(s) ((s)->pkt.ipx.ip4.ip_daddr_be32)

#if CI_CFG_IPV6
#define sock_ip6_laddr(s) ((s)->laddr.ip6)
#define sock_ip6_raddr(s) ((s)->pkt.ipx.ip6.daddr)
#endif

#if CI_CFG_IPV6
#define ipcache_lport_be16(ipcache) \
  ((ipcache_is_ipv6(ipcache) ?                    \
    ((ci_uint16*) (&(ipcache)->ipx.ip6 + 1)) :    \
    ((ci_uint16*) (&(ipcache)->ipx.ip4 + 1)) )[0])
#define ipcache_rport_be16(ipcache) \
  ((ipcache_is_ipv6(ipcache) ?                    \
    ((ci_uint16*) (&(ipcache)->ipx.ip6 + 1)) :    \
    ((ci_uint16*) (&(ipcache)->ipx.ip4 + 1)) )[1])
#else
#define ipcache_lport_be16(ipcache) (((ci_uint16*) (&(ipcache)->ipx.ip4 + 1))[0])
#define ipcache_rport_be16(ipcache) (((ci_uint16*) (&(ipcache)->ipx.ip4 + 1))[1])
/* NB. Above two assume no IP options (which is true for now). */
#endif
#define sock_lport_be16(s) ipcache_lport_be16(&(s)->pkt)
#define sock_rport_be16(s) ipcache_rport_be16(&(s)->pkt)

#define sock_protocol(s) ipcache_protocol(&(s)->pkt)
#define sock_tos_tclass(af, cp) \
  ( WITH_CI_CFG_IPV6( IS_AF_INET6(af) ? (cp)->tclass : ) (cp)->ip_tos )
#define sock_cp_ttl_hoplimit(af, cp) \
  ( WITH_CI_CFG_IPV6( IS_AF_INET6(af) ? (cp)->hop_limit : ) (cp)->ip_ttl )

#if CI_CFG_IPV6
ci_inline int sock_af_space(ci_sock_cmn* s)
{
  /* Fixme: do we want to cache sock_af_space() somewhere in the socket
   * state? */
  if( !CI_IS_ADDR_IP6(s->laddr) )
    return AF_SPACE_FLAG_IP4;

  /* IPv6: are we bound to a specific IPv6 address? */
  if( !CI_IPX_ADDR_IS_ANY(s->laddr) )
    return AF_SPACE_FLAG_IP6;

  /* Bound to :::. Is V6ONLY set? */
  if( s->s_flags & CI_SOCK_FLAG_V6ONLY )
    return AF_SPACE_FLAG_IP6;
  else
    return AF_SPACE_FLAG_IP6 | AF_SPACE_FLAG_IP4;
}
#else
#define sock_af_space(s)  AF_SPACE_FLAG_IP4
#endif

#define tcp_laddr_be32(ts)	sock_laddr_be32(&(ts)->s)
#define tcp_raddr_be32(ts)	sock_raddr_be32(&(ts)->s)

#if CI_CFG_IPV6
#define tcp_ip6_laddr(ts)   sock_ip6_laddr(&(ts)->s)
#define tcp_ip6_raddr(ts)   sock_ip6_raddr(&(ts)->s)
#endif

#define tcp_ipx_laddr(ts) sock_ipx_laddr(&(ts)->s)
#define tcp_ipx_raddr(ts) sock_ipx_raddr(&(ts)->s)

#define tcp_protocol(ts)	sock_protocol(&(ts)->s)
#define tcp_lport_be16(ts)	sock_lport_be16(&(ts)->s)
#define tcp_rport_be16(ts)	sock_rport_be16(&(ts)->s)


/* Enable / disable the TCP fast path. */
# define ci_tcp_can_use_fast_path(ts)                   \
  ((~ts->s.b.state & CI_TCP_STATE_SLOW_PATH)    &&      \
   ci_ip_queue_is_empty(&(ts)->rob)             &&      \
   tcp_rx_urg_fast_path(ts)                     &&      \
   tcp_rcv_wnd_advertised(ts)                     )

/* is state in CI_TCP_STATE_TIMEOUT_ORPHAN and orphaned -
 * if so we timeout */
#if CI_CFG_FD_CACHING
#define ci_tcp_is_timeout_orphan(ts)			\
    (((ts)->s.b.state & CI_TCP_STATE_TIMEOUT_ORPHAN) &&	\
    (((ts)->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) |       \
     ((ts)->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE)))
#else
#define ci_tcp_is_timeout_orphan(ts)			\
    (((ts)->s.b.state & CI_TCP_STATE_TIMEOUT_ORPHAN) &&	\
    ((ts)->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN))
#endif

static inline bool
ci_tcp_is_pluginized(ci_tcp_state* ts)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  return (ts->s.s_flags & CI_SOCK_FLAG_TCP_OFFLOAD) != 0;
#else
  return false;
#endif
}

extern ci_tcp_state* ci_tcp_get_state_buf(ci_netif*) CI_HF;
#if ! defined(__KERNEL__) && CI_CFG_FD_CACHING
extern ci_tcp_state* ci_tcp_get_state_buf_from_cache(ci_netif*, int pid) CI_HF;
#endif
extern ci_udp_state* ci_udp_get_state_buf(ci_netif*) CI_HF;
extern void ci_tcp_state_init(ci_netif* netif, ci_tcp_state* ts,
                              int from_cache) CI_HF;
extern void ci_tcp_state_tcb_reinit_minimal(ci_netif* netif,
                                            ci_tcp_state* ts) CI_HF;
extern void ci_tcp_state_reinit(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_init_rcv_wnd(ci_tcp_state*, const char* caller) CI_HF;
extern void ci_tcp_drop(ci_netif*, ci_tcp_state*, int so_error) CI_HF;
extern void ci_tcp_drop_rob(ci_netif*, ci_tcp_state*) CI_HF;
extern int ci_tcp_try_to_free_pkts(ci_netif* ni, ci_tcp_state* ts,
                                    int desperation) CI_HF;
extern void ci_tcp_state_free(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_state_free_to_cache(ci_netif* ni, ci_tcp_state* ts) CI_HF;
#if OO_DO_STACK_POLL
extern void ci_tcp_listen_all_fds_gone(ci_netif*, ci_tcp_socket_listen*,
                                       int do_free) CI_HF;
extern void ci_tcp_all_fds_gone(ci_netif* netif, ci_tcp_state*,
                                int do_free) CI_HF;
#endif
extern void ci_tcp_all_fds_gone_common(ci_netif* netif, ci_tcp_state*) CI_HF;
extern void ci_tcp_rx_reap_rxq_bufs(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_rx_reap_rxq_last_buf(ci_netif* netif, ci_tcp_state* ts) CI_HF;

static inline void
ci_tcp_rx_reap_rxq_bufs_socklocked(ci_netif* netif, ci_tcp_state* ts)
{
  ci_tcp_rx_reap_rxq_bufs(netif, ts);
  ci_assert(OO_PP_EQ(ts->recv1.head, ts->recv1_extract));
  if( OO_PP_NOT_NULL(ts->recv1_extract) )
    ci_tcp_rx_reap_rxq_last_buf(netif, ts);
}

extern void ci_tcp_state_dump(ci_netif*, ci_tcp_state*, const char *pf,
                              oo_dump_log_fn_t logger, void* log_arg) CI_HF;
extern void ci_tcp_state_dump_id(ci_netif* ni, int ep_id) CI_HF;
extern void ci_tcp_state_dump_qs(ci_netif*, int ep_id, int hex_dump) CI_HF;
extern void ci_tcp_state_dump_rob(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_state_dump_retrans_blocks(ci_netif*, ci_tcp_state*) CI_HF;
extern void ci_tcp_state_dump_retrans(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_pkt_dump(ci_netif* ni, ci_ip_pkt_fmt* pkt, int is_recv, 
                            int dump) CI_HF;
extern void ci_tcp_socket_listen_dump(ci_netif*, ci_tcp_socket_listen*,
                                      const char* pf,
                                      oo_dump_log_fn_t logger,
                                      void* log_arg) CI_HF;

/* If all the packets have size of amss, the maximum number of packets is
 * (ts)->s.so.rcvbuf / (ts)->amss.  We allow the sum of receive queue to
 * be a bit larger.  In the normal case, if s.so.rcvbuf == rcv_window_max,
 * we allow the average packet size to be amss/2.
 *
 * NB. if all packet sizes are equal to amss, and there were no recent
 * changes of SO_RCVBUF value, following inequalities hold:
 * (recv1.num + recv2.num + rob.num) * amss <= so.rcvbuf
 * rob.num * amss <= rcv_window_max
 */
static inline int ci_tcp_rcvbuf_abused(ci_netif* ni, ci_tcp_state* ts)
{
  return NI_OPTS(ni).tcp_rcvbuf_strict &&
      ts->recv1.num + ts->recv2.num + ts->rob.num >
      (ts->s.so.rcvbuf + ts->rcv_window_max) / ts->amss;
}
extern void ci_tcp_rcvbuf_unabuse(ci_netif* ni, ci_tcp_state* ts,
                                  int sock_already_locked) CI_HF;

extern void
ci_tcp_syncookie_syn(ci_netif* netif, ci_tcp_socket_listen* tls,
                     ci_tcp_state_synrecv* tsr);
extern void
ci_tcp_syncookie_ack(ci_netif* netif, ci_tcp_socket_listen* tls,
                     ciip_tcp_rx_pkt* rxp,
                     ci_tcp_state_synrecv **tsr_p);

extern void ci_tcp_set_sndbuf(ci_netif* ni, ci_tcp_state* ts);
extern void ci_tcp_set_sndbuf_from_sndbuf_pkts(ci_netif* ni, ci_tcp_state* ts);

extern int
ci_tcp_use_mac_filter_listen(ci_netif* ni, ci_sock_cmn* s, ci_ifid_t ifindex);

#ifndef __KERNEL__
extern int
ci_tcp_can_set_filter_in_ul(ci_netif *ni, ci_sock_cmn* s);
#endif

extern int
ci_tcp_sock_set_stack_filter(ci_netif *ni, ci_sock_cmn* s);

extern void
ci_tcp_sock_clear_stack_filter(ci_netif *ni, ci_tcp_state* ts);

#if CI_CFG_FD_CACHING
extern int /*bool*/ ci_tcp_is_cacheable_active_wild_sharer(ci_sock_cmn*);
#endif

extern void ci_tcp_prev_seq_remember(ci_netif*, ci_tcp_state*);
extern ci_uint32 ci_tcp_prev_seq_lookup(ci_netif*, const ci_tcp_state*);

/*********************************************************************
****************************** PIPE ***********************************
**********************************************************************/

#if OO_DO_STACK_POLL
extern void ci_pipe_all_fds_gone(ci_netif* netif, struct oo_pipe* p,
                                 int do_free);
#endif

/**********************************************************************
*************************** ACTIVE WILD *******************************
**********************************************************************/

ci_inline void
ci_addr_simple_hash(ci_addr_t addr, ci_uint32 entries,
                    ci_uint32* hash1_out, ci_uint32* hash2_out)
{
  /* Convert address to uint32.  Without IPv6 there is no conversion. */
  ci_uint32 hash0 = 0;
#if CI_CFG_IPV6
  if( CI_IS_ADDR_IP6(addr) ) {
    int i;

    for( i = 0; i < sizeof(ci_addr_t) / 4; i++) {
      hash0 ^= addr.u32[i];
    }
  }
  else
#endif
    hash0 = addr.ip4;

 *hash2_out = (hash0 | 1) & (entries - 1);

  /* Spread the entropy (such as it is) from the higher-order bits of the
   * address down a bit. */
  hash0 = CI_BSWAP_BE32(hash0);
  hash0 = hash0 ^ (hash0 >> 8);
 *hash1_out = hash0 & (entries - 1);
}

extern ci_active_wild* ci_active_wild_get_state_buf(ci_netif* netif);
extern void ci_active_wild_all_fds_gone(ci_netif* ni, ci_active_wild* aw,
                                        int do_free);

/*********************************************************************
************************** citp_waitable_obj *************************
*********************************************************************/

extern void citp_waitable_reinit(ci_netif* ni, citp_waitable* w) CI_HF;
extern void citp_waitable_init(ci_netif* ni, citp_waitable* w, int id) CI_HF;
extern citp_waitable_obj* citp_waitable_obj_alloc(ci_netif* netif) CI_HF;
extern void citp_waitable_obj_free(ci_netif* ni, citp_waitable* w) CI_HF;
extern void citp_waitable_obj_free_nnl(ci_netif*, citp_waitable*) CI_HF;
#if CI_CFG_FD_CACHING
extern void citp_waitable_obj_free_to_cache(ci_netif*, citp_waitable*) CI_HF;
#endif
#if OO_DO_STACK_POLL
extern void citp_waitable_all_fds_gone(ci_netif*, oo_sp) CI_HF;
extern void citp_waitable_cleanup(ci_netif* ni, citp_waitable_obj* wo,
                                  int do_free);
#endif
extern const char* citp_waitable_type_str(citp_waitable* w) CI_HF;
extern void citp_waitable_dump(ci_netif*, citp_waitable*, const char*) CI_HF;
extern void citp_waitable_dump_to_logger(ci_netif* ni, citp_waitable* w,
                                         const char* pf, oo_dump_log_fn_t logger,
                                         void* log_arg) CI_HF;
extern void citp_waitable_print_to_logger(ci_netif*, citp_waitable*,
                                          oo_dump_log_fn_t logger,
                                          void* log_arg) CI_HF;
extern void
ci_tcp_listenq_print_to_logger(ci_netif* ni, ci_tcp_socket_listen* tls,
                               oo_dump_log_fn_t logger, void *log_arg);


/*********************************************************************
*********************************************************************/

extern void ci_tcp_listenq_insert(ci_netif*, ci_tcp_socket_listen*,
                                  ci_tcp_state_synrecv*)  CI_HF;
extern void ci_tcp_listenq_remove(ci_netif*, ci_tcp_socket_listen*,
                                  ci_tcp_state_synrecv*)  CI_HF;
extern void ci_tcp_listenq_drop(ci_netif*, ci_tcp_socket_listen*,
                                ci_tcp_state_synrecv*)  CI_HF;
extern ci_tcp_state_synrecv* ci_tcp_listenq_lookup(ci_netif* netif,
						   ci_tcp_socket_listen* tls,
						   ciip_tcp_rx_pkt*) CI_HF;
extern void ci_tcp_listenq_drop_oldest(ci_netif*, ci_tcp_socket_listen*) CI_HF;
extern int ci_tcp_listenq_drop_all(ci_netif*, ci_tcp_socket_listen*) CI_HF;

extern int ci_tcp_listenq_try_promote(ci_netif*, ci_tcp_socket_listen*,
                                      ci_tcp_state_synrecv*,
                                      ci_ip_cached_hdrs*,
                                      ci_ip_pkt_fmt*,
                                      ci_tcp_state**) CI_HF;


extern const char* ci_tcp_state_num_str(int state) CI_HF;
#define ci_tcp_state_str(state)  ci_tcp_state_num_str(CI_TCP_STATE_NUM(state))
#define state_str(ts)            ci_tcp_state_str((ts)->s.b.state)

#ifndef NDEBUG
extern void ci_tcp_state_verify_no_timers(ci_netif *ni, ci_tcp_state *ts);
#else
#define ci_tcp_state_verify_no_timers(ni,ts)
#endif


extern const char* ci_tcp_congstate_str(unsigned state) CI_HF;
#define congstate_str(ts)  ci_tcp_congstate_str((ts)->congstate)


extern void ci_tcp_handle_rx(ci_netif*, struct ci_netif_poll_state*,
                             ci_ip_pkt_fmt*, ci_tcp_hdr*, int ip_paylen) CI_HF;
extern void ci_tcp_rx_deliver2(ci_tcp_state*,ci_netif*,ciip_tcp_rx_pkt*) CI_HF;

extern void ci_tcp_tx_change_mss(ci_netif*, ci_tcp_state*) CI_HF;
extern void ci_tcp_enqueue_no_data(ci_tcp_state* ts, ci_netif* netif,
                                   ci_ip_pkt_fmt* pkt) CI_HF;
extern int ci_tcp_send_sim_synack(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern int ci_tcp_synrecv_send(ci_netif* netif, ci_tcp_socket_listen* tls,
                               ci_tcp_state_synrecv* tsr, 
                               ci_ip_pkt_fmt* pkt, ci_uint8 tcp_flags,
                               ci_ip_cached_hdrs* ipcache_opt) CI_HF;
extern int ci_tcp_unsacked_segments_in_flight(ci_netif*, ci_tcp_state*) CI_HF;
extern int ci_tcp_retrans_one(ci_tcp_state* ts, ci_netif* netif,
                              ci_ip_pkt_fmt* pkt) CI_HF;
extern int ci_tcp_retrans(ci_netif* ni, ci_tcp_state* ts, int seq_limit,
                          int before_sacked_only, int* seq_used) CI_HF;
extern void ci_tcp_retrans_recover(ci_netif* ni, ci_tcp_state* ts,
                                   int force_retrans_first) CI_HF;
extern int /*bool*/
ci_tcp_maybe_enter_fast_recovery(ci_netif* ni, ci_tcp_state* ts) CI_HF;

extern void ci_tcp_recovered(ci_netif* ni, ci_tcp_state* ts) CI_HF;

extern void ci_tcp_clear_sacks(ci_netif* ni, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_retrans_init_ptrs(ci_netif* ni, ci_tcp_state* ts,
                                     unsigned* recover_seq_out) CI_HF;
extern void ci_tcp_get_fack(ci_netif* ni, ci_tcp_state* ts,
                            unsigned* fack_out, int* retrans_data_out) CI_HF;


extern void ci_tcp_retrans_coalesce_block(ci_netif* ni, ci_tcp_state* ts,
                                          ci_ip_pkt_fmt* pkt) CI_HF;
extern int ci_tcp_tx_coalesce(ci_netif* ni, ci_tcp_state* ts,
			      ci_ip_pkt_queue* q, ci_ip_pkt_fmt* pkt,
                              ci_boolean_t is_sendq) CI_HF;
extern void ci_tcp_tx_insert_option_space(ci_netif* ni, ci_tcp_state* ts,
                                          ci_ip_pkt_fmt* pkt, int hdrlen,
					  int extra_opts) CI_HF;
extern int ci_tcp_tx_split(ci_netif* ni, ci_tcp_state* ts, ci_ip_pkt_queue* qu,
                           ci_ip_pkt_fmt* pkt, int new_paylen, 
                           ci_boolean_t is_sendq) CI_HF;


extern void ci_tcp_tx_advance(ci_tcp_state* ts, ci_netif* netif) CI_HF;
extern void ci_tcp_tx_advance_to(ci_netif* ni, ci_tcp_state* ts,
                            unsigned right_edge, ci_uint32* p_stop_cntr) CI_HF;
extern void ci_tcp_send_rst_with_flags(ci_netif*, ci_tcp_state*,
                                       ci_uint8 extra_flags) CI_HF;
extern void ci_tcp_send_rst(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void
ci_tcp_reply_with_rst(ci_netif* netif, const struct oo_sock_cplane* sock_cp,
                      ciip_tcp_rx_pkt* rxp) CI_HF;
extern int ci_tcp_reset_untrusted(ci_netif *netif, ci_tcp_state *ts) CI_HF;
extern void ci_tcp_send_zwin_probe(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_set_established_state(ci_netif*, ci_tcp_state*) CI_HF;
extern void ci_tcp_expand_sndbuf(ci_netif*, ci_tcp_state*) CI_HF;
extern bool ci_tcp_should_expand_sndbuf(ci_netif*, ci_tcp_state*) CI_HF;
extern void ci_tcp_moderate_sndbuf(ci_netif* , ci_tcp_state*) CI_HF;
extern void ci_tcp_set_slow_state(ci_netif*, ci_tcp_state*, int state) CI_HF;
extern int ci_tcp_parse_options(ci_netif*, ciip_tcp_rx_pkt*,
				ci_tcp_options*) CI_HF;

extern void ci_ipx_hdr_init_fixed(ci_ipx_hdr_t* ip, int af, int protocol,
                                  int ttl, unsigned tos) CI_HF;

extern void ci_tcp_send_ack_rx(ci_netif*, ci_tcp_state*, ci_ip_pkt_fmt*,
                               int sock_locked, int update_wnd) CI_HF;
ci_inline void ci_tcp_send_ack(ci_netif* netif, ci_tcp_state* ts,
                               ci_ip_pkt_fmt* pkt, int sock_locked)
{
  ci_tcp_send_ack_rx(netif, ts, pkt, sock_locked, 1);
}
extern int ci_tcp_send_challenge_ack(ci_netif*, ci_tcp_state*,
                                     ci_ip_pkt_fmt*) CI_HF;
extern int/*bool*/
ci_tcp_may_send_ack_ratelimited(ci_netif* netif, ci_tcp_state* ts) CI_HF;

extern void ci_tcp_send_ack_loopback(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern int  ci_tcp_send_wnd_update(ci_netif*, ci_tcp_state*,
                                   int sock_locked) CI_HF;


/* TCP/UDP filter insertion */
extern void ci_netif_filter_init(ci_netif* ni, int size_lg2) CI_HF;

#if CI_CFG_IPV6
void ci_ip6_netif_filter_init(ci_ip6_netif_filter_table* tbl,
                              int size_lg2) CI_HF;
#endif

extern ci_sock_cmn*
__ci_netif_filter_lookup(ci_netif* netif, int af_space,
                         ci_addr_t daddr, unsigned dport,
                         ci_addr_t saddr, unsigned sport,
                         unsigned prot) CI_HF;

#if CI_CFG_IPV6
extern int
ci_ip6_netif_filter_lookup(ci_netif* netif, ci_addr_t laddr, unsigned lport,
                           ci_addr_t raddr, unsigned rport, unsigned prot) CI_HF;
extern int
__ci_ip6_netif_filter_lookup(ci_netif* netif, ci_addr_t laddr, unsigned lport,
                             ci_addr_t raddr, unsigned rport, unsigned prot) CI_HF;
#endif
extern oo_sp
ci_netif_filter_lookup(ci_netif* netif, int af_space,
                           ci_addr_t laddr, unsigned lport,
                           ci_addr_t raddr, unsigned rport,
                           unsigned protocol);

/* Returns socket index, or OO_SP_NULL if lookup failed. */
extern oo_sp
ci_netif_listener_lookup(ci_netif* netif, int af_space,
                         ci_addr_t laddr, unsigned lport) CI_HF;

/* Invokes the callback on each socket that matches the supplied addressing
 * fields.  If the callback returns non-zero, then the search is
 * terminated.
 * Returns 1 if the search was terminated, 0 otherwise.
 */
extern int
ci_netif_filter_for_each_match(ci_netif*, unsigned laddr, unsigned lport,
                               unsigned raddr, unsigned rport,
                               unsigned protocol, int intf_i, int vlan,
                               int (*callback)(ci_sock_cmn*, void*),
                               void* callback_arg, ci_uint32* hash_out) CI_HF;

#if CI_CFG_IPV6
extern int
ci_netif_filter_for_each_match_ip6(ci_netif* ni,
                                   const ci_addr_t* laddr, unsigned lport,
                                   const ci_addr_t* raddr, unsigned rport,
                                   unsigned protocol, int intf_i, int vlan,
                                   int (*callback)(ci_sock_cmn*, void*),
                                   void* callback_arg, ci_uint32* hash_out) CI_HF;
#endif

extern ci_uint32
ci_netif_filter_hash(ci_netif* ni, ci_addr_t laddr, unsigned lport,
                     ci_addr_t raddr, unsigned rport,
                     unsigned protocol) CI_HF;

extern int
ci_netif_filter_insert(ci_netif* netif, oo_sp sock_id, int af_space,
                       const ci_addr_t laddr, unsigned lport,
                       const ci_addr_t raddr, unsigned rport, 
                       unsigned protocol) CI_HF;

extern void 
ci_netif_filter_remove(ci_netif* netif, oo_sp tcp_id, int af_space,
                       const ci_addr_t laddr, unsigned lport,
                       const ci_addr_t raddr, unsigned rport,
                       unsigned protocol) CI_HF;

#if CI_CFG_UL_INTERRUPT_HELPER || defined(__KERNEL__)
ci_inline void
oo_sw_filter_apply(ci_netif* ni, struct oo_sw_filter_op* op)
{
  if( op->op == OO_SW_FILTER_OP_ADD ) {
    ci_netif_filter_insert(ni, op->sock_id, op->af_space,
                           op->laddr, op->lport,
                           op->raddr, op->rport, op->protocol);
  }
  else {
    ci_netif_filter_remove(ni, op->sock_id, op->af_space,
                           op->laddr, op->lport,
                           op->raddr, op->rport, op->protocol);
  }
}
#endif

/* Applies to the IPv4 table only. */
ci_inline ci_uint32 ci_netif_filter_table_size(ci_netif* ni)
{
  /* Endpoint lookup table.
   * - The table must be a power of two in size >= 2**16.  This property is
   *   used in ci_netif_filter_for_each_match() to make some deductions about
   *   the behaviour of the hashing functions.
   * - The table must be large enough for one filter per connection +
   *   the extra filters required for wildcards i.e. "listen any" connections
   *   (so we use double the number of endpoints).
   *
   * Fixme: max_ep_bufs is the number of ep states including the states
   * used for aux buffers and pipe endpoints.  How many real sockets are
   * we going to create?  Do we need a separate option? */
  return 1u << CI_MAX(16, ci_log2_le(NI_OPTS(ni).max_ep_bufs) + 1);
}


#if CI_CFG_TCP_SHARED_LOCAL_PORTS
#ifndef __KERNEL__
extern oo_sp ci_netif_active_wild_get(ci_netif* ni, ci_addr_t laddr,
                                      ci_addr_t raddr, unsigned lport,
                                      ci_uint16* port_out,
                                      ci_uint32* prev_seq_out);
#endif
extern void ci_netif_active_wild_sharer_closed(ci_netif* ni, ci_sock_cmn* s);
#define RSS_HASH_SIZE 0x80
#define RSS_HASH_MASK (RSS_HASH_SIZE - 1)
extern int ci_netif_active_wild_nic_hash(ci_netif *ni,
                                         ci_addr_t laddr, ci_uint16 lport,
                                         ci_addr_t raddr, ci_uint16 rport);

extern int
ci_netif_get_active_wild_list(ci_netif* ni, int aw_pool,
                              ci_addr_t laddr, ci_ni_dllist_t** list_out);
#endif

/* Bind RX of socket to given interface.  Used by implementation of
 * SO_BINDTODEVICE and EF_MCAST_JOIN_BINDTODEVICE.  Returns 0 on success,
 * CI_SOCKET_HANDOVER otherwise.
 */
extern int ci_sock_rx_bind2dev(ci_netif*, ci_sock_cmn*, ci_ifid_t) CI_HF;

extern int
__ci_tcp_shutdown(ci_netif*, ci_tcp_state*, int how) CI_HF;
extern void __ci_tcp_listen_shutdown(ci_netif*, ci_tcp_socket_listen*) CI_HF;
extern void ci_tcp_listen_shutdown_queues(ci_netif* netif,
                                          ci_tcp_socket_listen* tls) CI_HF;
#if CI_CFG_FD_CACHING
extern void
ci_tcp_listen_uncache_fds(ci_netif* netif, ci_tcp_socket_listen* tls) CI_HF;
extern void ci_tcp_epcache_drop_cache(ci_netif* ni) CI_HF;
extern void ci_tcp_listen_update_cached(ci_netif* netif,
                                        ci_tcp_socket_listen* tls) CI_HF;
extern void ci_tcp_active_cache_drop_cache(ci_netif* ni) CI_HF;
extern void ci_tcp_passive_scalable_cache_drop_cache(ci_netif* ni) CI_HF;
#endif
extern void __ci_tcp_listen_to_normal(ci_netif*, ci_tcp_socket_listen*) CI_HF;

extern void ci_netif_filter_dump(ci_netif*) CI_HF;

extern unsigned int ci_tcp_wscl_by_buff(ci_netif *netif,
                                        ci_int32 rcv_buff) CI_HF;

extern ci_int32 ci_tcp_rcvbuf_established(ci_netif* ni, ci_sock_cmn* s) CI_HF;

extern ci_int32 ci_tcp_max_rcvbuf(ci_netif* ni, ci_uint16 amss) CI_HF;

#if CI_CFG_IPV6
extern void ci_tcp_ipcache_convert(int af, ci_tcp_state* ts) CI_HF;
extern void ci_udp_ipcache_convert(int af, ci_udp_state* ts) CI_HF;
#endif

/* timer handlers */
#define ci_tcp_time_now(ni) ci_ip_time_now(ni)
#define ci_tcp_time_ms2ticks(ni, x) ci_ip_time_ms2ticks(ni, (x))
extern void ci_tcp_timer_init(ci_netif* netif) CI_HF;
extern void ci_tcp_timeout_listen(ci_netif* netif,
				  ci_tcp_socket_listen* tls) CI_HF;
extern void ci_tcp_timeout_kalive(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_timeout_zwin(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_timeout_delack(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_timeout_rto(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_timeout_cork(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_timeout_recycle(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_stop_timers(ci_netif* netif, ci_tcp_state* ts) CI_HF;
extern void ci_tcp_send_corked_packets(ci_netif* netif, ci_tcp_state* ts) CI_HF;

extern void ci_tcp_tx_pkt_assert_valid(ci_netif* ni, ci_tcp_state* ts,
                                       ci_ip_pkt_fmt*,
				       const char* f, int l)  CI_HF;
extern void ci_tcp_state_assert_valid(ci_netif*, ci_tcp_state* ts,
                                      const char* file, int line) CI_HF;
extern void ci_tcp_state_listen_assert_valid(ci_netif*, ci_tcp_socket_listen*,
					     const char* file, int line) CI_HF;
extern void ci_tcp_ep_assert_valid(citp_socket*, const char*, int ln) CI_HF;


/**********************************************************************
 * External interface.
 */

#ifndef __KERNEL__

extern int
ci_opt_is_setting_reuseport(int level, int optname, const void* optval,
                            socklen_t optlen) CI_HF;
extern int
ci_setsockopt_os_fail_ignore(ci_netif* ni, ci_sock_cmn* s, int err,
                             int level, int optname,
                             const void* optval, socklen_t optlen) CI_HF;

struct oo_per_thread;
typedef void (*citp_init_thread_callback)(struct oo_per_thread*);
extern int ci_tp_init(citp_init_thread_callback cb) CI_HF;
extern int ci_tcp_bind(citp_socket* ep, const struct sockaddr* my_addr,
                       socklen_t addrlen, ci_fd_t fd) CI_HF;
#if CI_CFG_ENDPOINT_MOVE
extern int ci_tcp_reuseport_bind(ci_sock_cmn* sock, ci_fd_t fd) CI_HF;
#endif
extern void ci_tcp_get_peer_addr(ci_tcp_state* ts, struct sockaddr* name,
                                 socklen_t* namelen) CI_HF;
extern int ci_tcp_getpeername(citp_socket*, struct sockaddr*, socklen_t*) CI_HF;
extern int ci_tcp_getsockname(citp_socket*, ci_fd_t, struct sockaddr*,
                              socklen_t*) CI_HF;

extern int ci_tcp_getsockopt(citp_socket* ep, ci_fd_t fd, int level, int optname,
			     void *optval, socklen_t *optlen) CI_HF;
extern int ci_tcp_setsockopt(citp_socket* ep, ci_fd_t fd, int level, int optname,
			     const void*optval, socklen_t optlen) CI_HF;
extern int ci_tcp_ioctl(citp_socket* ep, ci_fd_t fd, int request, void* arg) CI_HF;

struct oo_msg_template;
struct onload_template_msg_update_iovec;

extern int ci_tcp_tmpl_alloc(ci_netif* ni, ci_tcp_state* ts,
                             struct oo_msg_template** omt_pp,
                             const struct iovec* initial_msg, int mlen,
                             unsigned flags) CI_HF;
extern int
ci_tcp_tmpl_update(ci_netif* ni, ci_tcp_state* ts,
                   struct oo_msg_template* omt,
                   const struct onload_template_msg_update_iovec* updates,
                   int ulen, unsigned flags) CI_HF;
extern int ci_tcp_tmpl_abort(ci_netif* ni, ci_tcp_state* ts,
                             struct oo_msg_template* omt) CI_HF;

extern int ci_tcp_listen(citp_socket* ep, ci_fd_t fd, int backlog) CI_HF;

#endif /* #ifndef __KERNEL__ */

#ifdef __KERNEL__
extern void ci_tcp_linger(ci_netif*, ci_tcp_state*) CI_HF;
extern int ci_tcp_sync_sockopts_to_os_sock(ci_netif* ni, oo_sp sock_id,
                                           struct socket* sock) CI_HF;
#endif

extern int ci_tcp_listen_init(ci_netif *ni, ci_tcp_socket_listen *tls) CI_HF;
extern int __ci_tcp_bind(ci_netif*, ci_sock_cmn*, ci_fd_t,
                         ci_addr_t addr, ci_uint16* port_be16,
                         int may_defer) CI_HF;

/* Send/recv called from within kernel & user-library, so outside above #if */
extern int ci_tcp_recvmsg(const ci_tcp_recvmsg_args*) CI_HF;
struct onload_zc_recv_args;
extern int ci_tcp_zc_recvmsg(const ci_tcp_recvmsg_args*,
                             struct onload_zc_recv_args* args) CI_HF;
extern int ci_tcp_sendmsg(ci_netif* ni, ci_tcp_state* ts,
                          const ci_iovec* iov, unsigned long iovlen,
                          int flags
                          CI_KERNEL_ARG(ci_addr_spc_t addr_spc)) CI_HF;
extern void ci_tcp_sendmsg_enqueue_prequeue_deferred(ci_netif*,
						     ci_tcp_state*) CI_HF;
extern void ci_tcp_sendmsg_enqueue_prequeue(ci_netif* ni,
                                            ci_tcp_state* ts,
                                            int/*bool*/ shutdown) CI_HF;
extern void ci_tcp_perform_deferred_socket_work(ci_netif*, ci_tcp_state*)CI_HF;

/* Guarantees that deferred work will be performed at some point in the
 * near future, either by the calling thread (in this call), or deferred to
 * another thread.
 *
 * Returns 1 if the stack lock was grabbed, else 0.
 */
extern int  ci_netif_lock_or_defer_work(ci_netif*, citp_waitable*) CI_HF;


#ifndef __KERNEL__
extern int ci_tcp_connect(citp_socket*, const struct sockaddr*, socklen_t,
                          ci_fd_t fd, int *p_moved) CI_HF;
extern int ci_tcp_shutdown(citp_socket*, int how, ci_fd_t fd) CI_HF;
#endif

extern oo_sp ci_tcp_connect_find_local_peer(ci_netif *ni, int locked,
                                            ci_addr_t dst_addr,
                                            int dport_be16) CI_HF;

#ifdef __KERNEL__
extern int ci_tcp_connect_lo_samestack(ci_netif *ni, ci_tcp_state *ts,
                                       oo_sp tls_id, int *stack_locked) CI_HF;
extern int ci_tcp_connect_lo_toconn(ci_netif *c_ni, oo_sp c_id, ci_addr_t dst,
                                    ci_netif *l_ni, oo_sp l_id) CI_HF;
#endif

#if CI_CFG_LIMIT_AMSS || CI_CFG_LIMIT_SMSS
extern ci_uint16 ci_tcp_limit_mss(ci_uint16 mss, ci_netif* ni,
                                  const char* caller) CI_HF;
#endif
extern unsigned ci_tcp_amss(ci_netif* ni, const ci_tcp_socket_cmn* c,
                            ci_ip_cached_hdrs* ipcache,
                            const char* caller) CI_HF;


/**********************************************************************
 ************************** Misc and tracing **************************
 **********************************************************************/

extern const char* /*??ci_*/ip_addr_str(unsigned addr_be32) CI_HF;
  /* Note that this function is not reentrant.  However, it won't cause
  ** seg-faults.  Two buffers are used alternately, so it can be used twice
  ** in an list of arguments.
  */

extern const char* /*??ci_*/domain_str(int domain) CI_HF;
extern const char* /*??ci_*/type_str(int type) CI_HF;
#define CI_SOCK_TYPE_FMT "%s%s%s"
#define CI_SOCK_TYPE_ARGS(type) \
    type_str(type), type & SOCK_CLOEXEC ? " | SOCK_CLOEXEC" : "", \
    type & SOCK_NONBLOCK ? " | SOCK_NONBLOCK" : ""

#ifndef __KERNEL__
/* Linux defines it in its in-kernel header only; we use it both in module
 * and from UL. */
#define SOCK_TYPE_MASK 0xf
#endif

/*! Returns zero if a socket to the destination 'ip_be32' can
 *  be handled by the L5 stack.
 *  On failure, the return value is the error condition.
 */
extern int ci_can_handle_addr(ci_netif *netif, ci_uint32 ip_be32,
                              unsigned int proto, ci_uint32 *src_ip_be32_out,
                              unsigned *nic_i_out, unsigned *mtu_out) CI_HF;


#define NETIF_MAGIC     0xd


/**********************************************************************
************************** Per-socket locks ***************************
**********************************************************************/

extern int  ci_sock_lock_slow(ci_netif* ni, citp_waitable* w) CI_HF;
extern void ci_sock_unlock_slow(ci_netif*, citp_waitable*) CI_HF;


/**********************************************************************
******************************* Sleeping ******************************
**********************************************************************/

#define CI_SLEEP_NETIF_LOCKED           0x1
#define CI_SLEEP_SOCK_LOCKED            0x2
#define CI_SLEEP_NETIF_RQ               0x4
#define CI_SLEEP_SOCK_RQ                0x8

#if OO_DO_STACK_POLL
/*! Sleep until something happens.
**
**   [why] should be a combination of CI_SB_FLAG_WAKE_RX and
**   CI_SB_FLAG_WAKE_TX.
**
**   [lock_flags] indicates which locks the caller holds on entry, and
**   which locks the caller would like to grab post-exit.  It should be 0
**   or a combination of CI_SLEEP_NETIF_LOCKED, CI_SLEEP_SOCK_LOCKED,
**   CI_SLEEP_NETIF_RQ and CI_SLEEP_SOCK_RQ.
**
**   [sleep_seq] should be the value of [w->sleep_seq] before the sleep
**   condition was tested.
**
**   [timeout] IN: timeout in ms; 0 if no timeout.
**   OUT: the rest of timeout (may be passed to the next call
**   of this function).
*/
extern int ci_sock_sleep(ci_netif* ni, citp_waitable* w, ci_bits why,
                         unsigned lock_flags, ci_uint64 sleep_seq,
                         ci_uint32 *timeout_ms_p) CI_HF;
#endif


/**********************************************************************
******************************* Polling *******************************
**********************************************************************/

#define ci_netif_is_contention(ni)				\
  (ef_eplock_flags(&(ni)->state->lock) &			\
   (CI_EPLOCK_FL_NEED_WAKE | CI_EPLOCK_NETIF_SOCKET_LIST))


/**********************************************************************
 ************************* Errno wrappers etc. ************************
 **********************************************************************/

/*! Return value where a handover is required by a higher layer. */
#define CI_SOCKET_HANDOVER -2


/* *****************
 * Errno wrappers - note that errno should not be accessed directly 
 */
#ifdef __KERNEL__
# define CI_SET_ERROR(rc, e)	                       \
  do{                                                  \
    CI_BUILD_ASSERT_CONSTANT_NON_NEGATIVE((int)(e)-1); \
    ci_assert_gt((int)(e), 0);                         \
    (rc) = -(e);                                       \
  } while(0)
# define CI_GET_ERROR(rc)	(-(rc))
#else
# define CI_SET_ERROR(rc, e)                           \
  do{                                                  \
    CI_BUILD_ASSERT_CONSTANT_NON_NEGATIVE((int)(e)-1); \
    ci_assert_gt((int)(e), 0);                         \
    errno = (e);			               \
    (rc) = CI_SOCKET_ERROR;                            \
  } while(0)
# define CI_GET_ERROR(rc)	(errno)
#endif

/* Sets errno to specified value and returns CI_SOCKET_ERROR */
#define RET_WITH_ERRNO(_errno)  do {      \
        int rc_;                          \
        CI_SET_ERROR(rc_, _errno);        \
        return rc_; } while (0)

/**********************************************************************
 **************************** OS-specific *****************************
**********************************************************************/

/* ************************** */
/*    Unix Implementation     */
/* ************************** */
/*! \i_ossock  Return value from failed socket calls. */
#define CI_SOCKET_ERROR -1

/*! \i_ossock Verify that a file descriptor/handle is valid */
#define CI_IS_VALID_SOCKET(fd) ((fd) >= 0)

/*! \i_ossock Get an Fd that can be used in UL calls to sys socket calls.
 * Linux:   call the TCP helper to get a temporary fd
 * \param fd     [in] Efab fd (the fd used by the application)
 * \return       Success: Fd (value > 0), Fail: error (value < 0)
 */
#define ci_get_os_sock_fd(fd)  ci_tcp_helper_get_sock_fd(fd)

/*! \i_ossock Release the OS fd obtained through ci_get_os_sock_fd().
 * Linux:   call the TCP helper to release the temporary fd
 * \param fd     [in] OS fd to release
 * \return       nothing
 */
#define ci_rel_os_sock_fd(fd) do { if(CI_IS_VALID_SOCKET(fd))   \
  ci_tcp_helper_rel_sock_fd((fd)); } while(0)


/**********************************************************************
************************* Payload copying funcs ***********************
**********************************************************************/


/* Copy data from [piov] into [pkt].  [buf] identifies the buffer space
** into which data can be copied.
*/
extern int __ci_copy_iovec_to_pkt(ci_netif*, ci_ip_pkt_fmt*, ci_iovec_ptr*
                                  CI_KERNEL_ARG(ci_addr_spc_t)) CI_HF;

#if defined(__KERNEL__)
# define ci_copy_iovec_to_pkt(ni, pkt, piov, addr_spc)          \
   __ci_copy_iovec_to_pkt((ni), (pkt), (piov), (addr_spc))
#else
# define ci_copy_iovec_to_pkt(ni, pkt, piov)    \
   __ci_copy_iovec_to_pkt((ni), (pkt), (piov))
#endif

# define ci_ip_copy_pkt_to_user         __ci_ip_copy_pkt_to_user
extern ssize_t __ci_ip_copy_pkt_to_user(ci_netif*, ci_iovec*,
                                        ci_ip_pkt_fmt*, int peek_off) CI_HF;

#if defined(__KERNEL__)
# define ci_ip_copy_pkt_from_piov  __ci_ip_copy_pkt_from_piov
extern size_t __ci_ip_copy_pkt_from_piov(ci_netif*, ci_ip_pkt_fmt*, 
                                         ci_iovec_ptr*, ci_addr_spc_t) CI_HF;
#else /* __KERNEL__ */

# define ci_ip_copy_pkt_from_piov(ni, pkt, iov, aspc)	\
  __ci_ip_copy_pkt_from_piov((ni), (pkt), (iov))
extern size_t __ci_ip_copy_pkt_from_piov(ci_netif*, ci_ip_pkt_fmt*,
                                         ci_iovec_ptr*) CI_HF;
#endif


extern const unsigned char ci_sock_states_linux_map[] CI_HV;


/**********************************************************************
 ** IP stack parameters to get from OS.
 */
extern int ci_setup_ipstack_params(void);


/**********************************************************************
****************************** Statistics *****************************
**********************************************************************/

#if CI_CFG_STATS_NETIF
# define CITP_STATS_NETIF(x)		x
# define CITP_STATS_NETIF_INC(ni,x)	do{ ++(ni)->state->stats.x; }while(0)
# define CITP_STATS_NETIF_ADD(ni,x,v)	do{ (ni)->state->stats.x += v; }while(0)
#else
# define CITP_STATS_NETIF(x)
# define CITP_STATS_NETIF_INC(ni,x)
# define CITP_STATS_NETIF_ADD(ni,x,v)
#endif

#if CI_CFG_STATS_TCP_LISTEN
# define CITP_STATS_TCP_LISTEN(x)	x
#else
# define CITP_STATS_TCP_LISTEN(x)
#endif

#if CI_CFG_DETAILED_CHECKS
# define CITP_DETAILED_CHECKS(x)        x
#else
# define CITP_DETAILED_CHECKS(x)
#endif


/**********************************************************************
******************** Accessing trusted kernel state *******************
**********************************************************************/

#define ci_netif_ep_get(ni, s)  ((ni)->ep_tbl[OO_SP_TO_INT(s)])
#define ci_trs_ep_get(trs, s)   ci_netif_ep_get(&(trs)->netif, (s))

#define ci_netif_get_valid_ep(ni, sockp)                \
  ((ni)->ep_tbl[TRUSTED_SOCK_ID_FROM_P((ni), (sockp))])
#define ci_trs_get_valid_ep(trs, sock_id)               \
  ci_netif_get_valid_ep(&(trs)->netif, (sock_id))


/**********************************************************************
***************************** Misc macros *****************************
**********************************************************************/

/* note bitno is undefined after loop */
#define OO_FOR_EACH_BIT(init_mask, mask, bitno)                        \
  for( (mask) = (init_mask), (bitno) = __builtin_ctz(mask);              \
       (mask) ;                                                        \
       (mask) = (mask) & ((mask) - 1), (bitno) = __builtin_ctz(mask) )

CI_BUILD_ASSERT(sizeof(unsigned) * 8 >= CI_CFG_MAX_INTERFACES);

#define OO_STACK_FOR_EACH_INTF_I(_ni, _intf_i)                          \
  for( (_intf_i) = 0; (_intf_i) < oo_stack_intf_max(_ni); ++(_intf_i) )

#define OO_STACK_FOR_EACH_FUTURE_INTF_I(_ni, _mask, _intf_i) \
  ci_assert_lt((_ni)->future_intf_mask, 1u << oo_stack_intf_max(_ni));    \
  { CI_BUILD_ASSERT(sizeof(_mask) >= sizeof((_ni)->future_intf_mask)); } \
  OO_FOR_EACH_BIT((_ni)->future_intf_mask, (_mask), (_intf_i))

/*
**
**
**
**
**
**
**
**
**
** DO NOT PUT ANY INLINE FUNCTIONS ABOVE THIS POINT.
**
**
**
**
**
**
**
**
*/


/*********************************************************************
************************ Runtime config options **********************
*********************************************************************/

ci_inline ef_driver_handle ci_netif_get_driver_handle(const ci_netif* ni) {
#ifdef __KERNEL__
  return 0;
#else
  return ni->driver_handle;
#endif
}


ci_inline ef_vi* ci_netif_vi(ci_netif* ni, int nic_i) {
  return &ni->nic_hw[nic_i].vis[0];
}


#if CI_CFG_IPV6
extern ci_uint32 ci_make_flowlabel(ci_netif* ni, ci_addr_t saddr,
    ci_uint16 sport, ci_addr_t daddr, ci_uint16 dport, ci_uint8 proto) CI_HF;
extern ci_uint32 ci_ipcache_make_flowlabel(ci_netif* ni,
    ci_ip_cached_hdrs* ipcache) CI_HF;
extern void ci_ipcache_update_flowlabel(ci_netif* ni, ci_sock_cmn* s) CI_HF;
#else
#define ci_ipcache_update_flowlabel(ni, s)
#endif

/* How many more descriptors can be posted into this VI?  Answer may be
 * negative, because rxq_limit changes dynamically.
 */
ci_inline int ci_netif_rx_vi_space(ci_netif* ni, ef_vi* vi)
{ return ni->state->rxq_limit - ef_vi_receive_fill_level(vi); }



ci_inline int oo_stack_intf_max(ci_netif* ni) {
#if defined(__KERNEL__)
  return ni->nic_n;
#else
  return ni->state->nic_n;
#endif
}


ci_inline void ci_netif_rx_post_all_batch(ci_netif* netif, int nic_index)
{
  int i;
  int num_vis = ci_netif_num_vis(netif);
  for( i = 0; i < num_vis; ++i ) {
    ef_vi* vi = &netif->nic_hw[nic_index].vis[i];
    if( ci_netif_rx_vi_space(netif, vi) >= CI_CFG_RX_DESC_BATCH )
      ci_netif_rx_post(netif, nic_index, vi);
  }
}


/**********************************************************************
 * Handling return from ci_netif_pkt_wait() and ci_netif_lock().
 */

ci_inline int ci_netif_pkt_wait_was_interrupted(int rc) {
#ifdef __KERNEL__
  ci_assert(rc == 0 || rc == -ERESTARTSYS);
  return rc < 0;
#else
  ci_assert_equal(rc, 0);
  return 0;
#endif
}


ci_inline int ci_netif_lock_was_interrupted(int rc) {
#ifdef __KERNEL__
  ci_assert(rc == 0 || rc == -ERESTARTSYS);
  return rc < 0;
#else
  ci_assert_equal(rc, 0);
  return 0;
#endif
}


/*********************************************************************
******************************** Bit arrays **************************
*********************************************************************/

ci_inline void oo_bit_array_set(ci_uint32* array, int id)
{
  array[id >> 5] |= 1 << (id & 31);
}

ci_inline void oo_bit_array_clear(ci_uint32* array, int id)
{
  array[id >> 5] &= ~(1 << (id & 31));
}

ci_inline int oo_bit_array_get(ci_uint32* array, int id)
{
  return (array[id >> 5] >> (id & 31)) & 1;
}


/*********************************************************************
************************** citp_waitable_obj *************************
*********************************************************************/

ci_inline ci_udp_state* SOCK_TO_UDP(ci_sock_cmn* s) {
  ci_assert_equal(s->b.state, CI_TCP_STATE_UDP);
  return CI_CONTAINER(ci_udp_state, s, s);
}

ci_inline ci_tcp_state* __SOCK_TO_TCP(ci_sock_cmn* s)
{ return CI_CONTAINER(ci_tcp_state, s, s); }
ci_inline ci_tcp_socket_listen* __SOCK_TO_TCP_LISTEN(ci_sock_cmn* s) {
  return CI_CONTAINER(ci_tcp_socket_listen, s, s);
}

#ifdef NDEBUG
#define SOCK_TO_TCP __SOCK_TO_TCP
#else
ci_inline ci_tcp_state* SOCK_TO_TCP_DEBUG(ci_sock_cmn*s, const char*file,
                                          int line) {
  _ci_assert(s->b.state & CI_TCP_STATE_TCP, file, line);
  _ci_assert(s->b.state == CI_TCP_CLOSED ||
             (s->b.state & CI_TCP_STATE_TCP_CONN), file, line);
  return __SOCK_TO_TCP(s);
}

# define SOCK_TO_TCP(s) SOCK_TO_TCP_DEBUG(s, __FILE__, __LINE__)
#endif

ci_inline ci_tcp_socket_listen* SOCK_TO_TCP_LISTEN(ci_sock_cmn* s) {
  ci_assert_equal(s->b.state, CI_TCP_LISTEN);
  return __SOCK_TO_TCP_LISTEN(s);
}

ci_inline citp_waitable_obj* SOCK_TO_WAITABLE_OBJ(ci_sock_cmn* s)
{ return CI_CONTAINER(citp_waitable_obj, sock, s); }


/*********************************************************************
************************** UDP Receive queue *************************
*********************************************************************/

ci_inline void ci_udp_recv_q_init(ci_udp_recv_q* q) {
  q->head = q->extract = OO_PP_NULL;
  q->pkts_reaped = q->pkts_delivered = q->pkts_added = 0;
}

ci_inline int ci_udp_recv_q_is_empty(ci_udp_recv_q* q)
{
  return q->pkts_added == q->pkts_delivered;
}

ci_inline int ci_udp_recv_q_not_empty(ci_udp_recv_q* q)
{ 
  return q->pkts_added != q->pkts_delivered;
}

ci_inline int ci_udp_recv_q_pkts(ci_udp_recv_q* q)
{
  return q->pkts_added - q->pkts_delivered; 
}

ci_inline int ci_udp_recv_q_reapable(ci_udp_recv_q* q)
{ 
  return q->pkts_delivered - q->pkts_reaped;
}


/*********************************************************************
********************** Timers and management *************************
*********************************************************************/

/*! This function gets the current cached time in ticks
**  \param its  A pointer to the ci_ip_timer_state management block
**  \return     The current cached time in ticks 
*/
ci_inline ci_iptime_t ci_ip_time_now(ci_netif *ni)
{ return IPTIMER_STATE(ni)->ci_ip_time_real_ticks; }


/* Returns true if [a] is before [b]. */
ci_inline int /*bool*/
ci_ip_time_before(ci_iptime_t a, ci_iptime_t b)
{
  return ci_seq_lt(a, b, sizeof(a) * 8);
}


/*! This function sets the initial current free cycle counter time in ticks 
**  \param its  A pointer to the ci_ip_timer_state management block
*/
ci_inline void ci_ip_time_initial_sync(ci_ip_timer_state* its) {
#if defined(CI_HAVE_FRC64) 
  ci_frc64(&its->frc);  
  its->ci_ip_time_real_ticks =
    (ci_iptime_t)(its->frc >> its->ci_ip_time_frc2tick);
#else
# error need a frc64 routine to compile iptimer support
#endif  
}

ci_inline void ci_ip_time_update(ci_ip_timer_state* its, ci_uint64 new_frc) {
  if(CI_LIKELY( new_frc >= its->frc )) {
    ci_iptime_t new_ticks;
    new_ticks = (ci_iptime_t) (new_frc >> its->ci_ip_time_frc2tick);
    its->ci_ip_time_real_ticks = new_ticks;
    its->frc = new_frc;
  }
}

/*! This function updates the current free cycle counter time in ticks 
**  \param its  A pointer to the ci_ip_timer_state management block
*/
ci_inline void ci_ip_time_resync(ci_ip_timer_state* its) {
  ci_uint64 new_frc;
  ci_frc64(&new_frc);  
  ci_ip_time_update(its, new_frc);
}

/*! This function gets the current free cycle counter time in ticks 
**  \param its  A pointer to the ci_ip_timer_state management block
**  \param t    An out parameter to write the return into
*/
ci_inline void ci_ip_time_get(ci_ip_timer_state* its, ci_iptime_t* ticks) {
#if defined(CI_HAVE_FRC64)  
  ci_uint64 frc;
  ci_frc64(&frc);  
  *ticks = (ci_iptime_t)(frc >> its->ci_ip_time_frc2tick);
#else
# error need a frc64 routine to compile iptimer support
#endif  
}

/*! This function gets the current free cycle counter time in us
**  \param its  A pointer to the ci_ip_timer_state management block
**  \param t    An out parameter to write the return into
*/
ci_inline void ci_ip_time_get_us(ci_ip_timer_state* its, ci_iptime_t* t) {
#if defined(CI_HAVE_FRC64)  
  ci_uint64 frc;
  ci_frc64(&frc);  
  *t = (ci_iptime_t)(frc >> its->ci_ip_time_frc2us);
#else
# error need a frc64 routine to compile iptimer support
#endif  
}

/*! Convert a time measure in ms to the number of ticks
**  \param ni   A pointer to the netif 
**  \param t    The time in ms
**  \return     The time t in ticks
*/
ci_inline ci_iptime_t ci_ip_time_ms2ticks(ci_netif *ni, ci_uint32 t)
{
  ci_ip_timer_state *its = IPTIMER_STATE(ni);
  t = (ci_iptime_t) ( (((ci_uint64)t) * its->ci_ip_time_ms2tick_fxp) >> 32 );
  /* rounds up 0 timers... */
  return t ? t : 1;
}

/*! Convert a time measure in ticks to ms
**  \param its  A pointer to the ci_ip_timer_state management block
**  \param t    The time in ticks
**  \return     The time t in ms
*/
ci_inline ci_uint32 ci_ip_time_ticks2ms(ci_netif* ni, ci_iptime_t t) {
  ci_ip_timer_state *its = IPTIMER_STATE(ni);
  /* As for now the function is not used on fast path should this change
   * then use of multiplication and inversed factor to be considered */
  t = (ci_iptime_t) ( (((ci_uint64)t << 32) / its->ci_ip_time_ms2tick_fxp) );
  return t;
}


/* Convert Herz (per-second value) to per tick. */
ci_inline ci_uint32 ci_ip_time_freq_hz2tick(ci_netif* ni, ci_uint32 hz)
{
  ci_ip_timer_state *its = IPTIMER_STATE(ni);
  /* We assume that 1024==1000, and khz = hz >> 10.
   * Then we use the expression from ci_ip_time_ms2ticks(). */
  return ((ci_uint64)hz << 22) / its->ci_ip_time_ms2tick_fxp;
}


ci_inline const cicp_hwport_mask_t ci_netif_get_hwport_mask(ci_netif* ni)
{
#ifdef __KERNEL__
  return ni->hwport_mask;
#else
  return ni->state->hwport_mask;
#endif
}


ci_inline const ci_int8* ci_netif_get_hwport_to_intf_i(ci_netif* ni) {
#ifdef __KERNEL__
  return ni->hwport_to_intf_i;
#else
  return ni->state->hwport_to_intf_i;
#endif
}


ci_inline int __ci_hwport_to_intf_i(ci_netif* ni, ci_hwport_id_t hwport) {
  ci_assert((unsigned) hwport < CI_CFG_MAX_HWPORTS);
  return ci_netif_get_hwport_to_intf_i(ni)[hwport];
}


ci_inline int ci_hwport_to_intf_i(ci_netif* ni, ci_hwport_id_t hwport) {
  if(CI_LIKELY( (unsigned) hwport < CI_CFG_MAX_HWPORTS ))
    return ci_netif_get_hwport_to_intf_i(ni)[hwport];
  return ci_netif_bad_hwport(ni, hwport);
}




ci_inline int ci_netif_may_poll(ci_netif* ni)
{
  return NI_OPTS(ni).poll_on_demand;
}


#if defined(__KERNEL__) || ! defined(NDEBUG)
/* If we have detected certain errors, we forbid polling stacks in the kernel.
 * In those cases, we also prevent interrupts from being primed, lest we
 * trigger an interrupt storm.  One consequence of this is that anything that
 * resets any of the relevant error conditions must also ensure that the
 * interrupt is reprimed if necessary. */
ci_inline int ci_netif_may_poll_in_kernel(ci_netif* ni, int intf_i)
{
  return ni->state->nic[intf_i].nic_error_flags == 0;
}
#endif


ci_inline int ci_netif_is_spinner(ci_netif* ni)
{
  return ni->state->is_spinner | ni->state->n_spinners;
}


/* Cheap test that returns true if the stack is "primed".  i.e. Will
** generate an interrupt when an event next arrives.
*/
ci_inline int ci_netif_is_primed(ci_netif* ni)
{ return ni->nic_set.nics == ni->state->evq_primed; }

/* Cheap test that returns true if the stack is not "primed".  i.e. Not all
** event queues have been primed to generate an interrupt when the next
** event arrives.
*/
ci_inline int ci_netif_not_primed(ci_netif* ni)
{ return ni->nic_set.nics != ni->state->evq_primed; }


/* Returns true if there are any hardware events outstanding on the given
 * interface.
 */
ci_inline int ci_netif_intf_has_event(ci_netif* ni, int intf_i)
{ return ef_eventq_has_event(ci_netif_vi(ni, intf_i)); }


/* Returns true if there are any hardware events outstanding on any
 * interface.
 */
ci_inline int ci_netif_has_event(ci_netif* ni) {
  int intf_i, rc = 0;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    if( ci_netif_intf_has_event(ni, intf_i) ) {
      rc = 1;
      break;
    }
  if( OO_PP_NOT_NULL(ni->state->looppkts) )
    rc = 1;
  return rc;
}


/* Returns true if there are any hardware events outstanding on any
 * interface, where we can act on those events efficiently.
 */
ci_inline int ci_netif_has_actionable_event(ci_netif* ni) {
  int intf_i;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    if( ci_netif_intf_has_event(ni, intf_i) ) {
#ifdef OO_HAS_POLL_IN_KERNEL
      if( ! ni->nic_hw[intf_i].poll_in_kernel )
#endif
      {
        return 1;
      }
    }
  }
  return OO_PP_NOT_NULL(ni->state->looppkts);
}


/* Returns true if there are many hardware events outstanding. */
ci_inline int ci_netif_has_many_events(ci_netif* ni, int lookahead) {
  int intf_i, rc = 0;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    if( ef_eventq_has_many_events(ci_netif_vi(ni, intf_i), lookahead) ) {
      rc = 1;
      break;
    }
  return rc;
}

/* "Poison" value written to the start of a packet buffer to detect when
 * a packet from the future is incoming.
 *
 * This must not match the first four bytes of the packet. Anything that does
 * not match our OUI or multicast addresses will do. If we add support for
 * third-party NICs, we may want a per-NIC poison value to ensure a mismatch.
 * If we add support for detecting subsequent cache lines, or if packet prefixes
 * are enabled, there will be the possibility of deciding falsely that a packet
 * is still poisonous when in fact it is not, but there is very little that we
 * can do about that. It would not cause a functional problem in any case.
 */
#define CI_PKT_RX_POISON 0xFEA0C09Cu
ci_inline volatile uint32_t* ci_netif_poison_location(ci_ip_pkt_fmt* pkt)
{
  return (volatile uint32_t*)pkt->dma_start;
}
ci_inline void ci_netif_poison_rx_pkt(ci_ip_pkt_fmt* pkt)
{
  *ci_netif_poison_location(pkt) = CI_PKT_RX_POISON;
}

#ifndef __KERNEL__
ci_inline int ci_netif_rx_pkt_is_poisoned(ci_ip_pkt_fmt* pkt)
{
  return *ci_netif_poison_location(pkt) == CI_PKT_RX_POISON;
}

ci_inline int ci_netif_intf_may_poll_future(ci_netif* ni, int intf_i)
{
  return (ni->future_intf_mask & (1u << intf_i)) != 0;
}

ci_inline ci_ip_pkt_fmt* ci_netif_intf_next_rx_pkt(ci_netif* ni, int intf_i)
{
  int id;
  oo_pkt_p pp;

  ci_assert_ge(intf_i, 0);
  ci_assert_lt(intf_i, oo_stack_intf_max(ni));

  id = ef_vi_next_rx_rq_id(ci_netif_vi(ni, intf_i));
  OO_PP_INIT(ni, pp, id);
  return OO_PP_IS_NULL(pp) ? NULL : PKT_CHK(ni, pp);
}


ci_inline int ci_netif_intf_has_rx_future(ci_netif* ni, int intf_i)
{
  ci_ip_pkt_fmt* pkt = ci_netif_intf_next_rx_pkt(ni, intf_i);
  return pkt && ! ci_netif_rx_pkt_is_poisoned(pkt);
}


/* Returns the location of the poison value in the next RX packet buffer for
 * an interface, if the interface is configured to poll the future. Otherwise,
 * or if the RX queue is empty, returns the provided pointer to a fixed
 * poison value. This should be located on the stack close to other state
 * accessed while polling, to minimise cache churn.
 */
ci_inline const volatile uint32_t*
ci_netif_intf_rx_future(ci_netif* ni, int intf_i, const uint32_t* poison)
{
  ci_ip_pkt_fmt* pkt;
  ci_uint8* p;

  ci_assert(*poison == CI_PKT_RX_POISON);

  if( ! ci_netif_intf_may_poll_future(ni, intf_i) )
    return poison;

  pkt = ci_netif_intf_next_rx_pkt(ni, intf_i);

  /* FIXME: colocate all the fields used by the rx path to reduce cache usage */
  for( p = (ci_uint8*)pkt; p < pkt->dma_start; p += CI_CACHE_LINE_SIZE )
    ci_prefetch(p);

  return pkt ? ci_netif_poison_location(pkt) : poison;
}

#endif

ci_inline int ci_netif_need_timer_prime(ci_netif* ni, ci_uint64 frc_now) {
  return frc_now - ni->state->evq_last_prime > ni->state->timer_prime_cycles;
}


ci_inline int ci_netif_need_poll_spinning(ci_netif* ni, ci_uint64 frc_now)
{
  return ci_netif_has_actionable_event(ni) ||
         ci_netif_need_timer_prime(ni, frc_now);
}


/* See ci_netif_need_poll() for description.  Use this when you already
** know a recent frc.
*/
ci_inline int ci_netif_need_poll_frc(ci_netif* ni, ci_uint64 frc_now) {
  return ci_netif_not_primed(ni) &&
         ci_netif_need_poll_spinning(ni, frc_now);
}


/* Indicates whether some work might be done if the stack is polled.  It is
** expected that this will normally be called by threads that don't hold
** the lock.
**
** Returns true if the stack is not 'primed' and there are events
** outstanding or it has been a while since the stack was last polled.
*/
ci_inline int ci_netif_need_poll(ci_netif* ni)
{ return ci_netif_need_poll_frc(ni, ci_frc64_get()); }


ci_inline int ci_netif_need_poll_maybe_spinning(ci_netif* ni, ci_uint64 frc_now,
                                         int spinning) {
  if( spinning )
    return ci_netif_need_poll_spinning(ni, frc_now);
  else
    return ci_netif_need_poll_frc(ni, frc_now);
}

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
ci_inline int ci_netif_should_allocate_tcp_shared_local_ports(ci_netif* ni)
{
  return
    NI_OPTS(ni).tcp_shared_local_ports > 0 &&
    NI_OPTS(ni).scalable_filter_enable != CITP_SCALABLE_FILTERS_ENABLE_WORKER;
}
#endif


ci_inline int oo_tx_zc_payload_size(ci_netif* ni) {
  return sizeof(struct ci_pkt_zc_payload) +
         sizeof(ef_addr) * oo_stack_intf_max(ni);
}

ci_inline struct ci_pkt_zc_payload*
oo_tx_zc_payload_next(ci_netif* ni, struct ci_pkt_zc_payload* zcp)
{
  if( zcp->is_remote )
    return (void*)((char*)zcp + oo_tx_zc_payload_size(ni));
  return (void*)(zcp->local + CI_ALIGN_FWD(zcp->len, CI_PKT_ZC_PAYLOAD_ALIGN));
}

#define OO_TX_FOR_EACH_ZC_PAYLOAD(ni, zch, zcp)  \
  for( (zcp) = (zch)->data; \
       (char*)(zcp) - (char*)(zch) < (zch)->end; \
       (zcp) = oo_tx_zc_payload_next(ni, zcp) )


/*********************************************************************
********************** Packet buffer allocation **********************
*********************************************************************/

ci_inline void __ci_netif_pkt_clean(ci_ip_pkt_fmt* pkt) 
{
  pkt->flags &= CI_PKT_FLAG_NONB_POOL;
  pkt->rx_flags = 0;
  pkt->n_buffers = 1;
  pkt->frag_next = OO_PP_NULL;
#if CI_CFG_TCP_OFFLOAD_RECYCLER || ! defined NDEBUG
  pkt->q_id = CI_Q_ID_NORMAL;
#endif
  CI_DEBUG(pkt->pkt_start_off = PKT_START_OFF_BAD;
           pkt->pkt_eth_payload_off = PKT_START_OFF_BAD);
#if CI_CFG_TIMESTAMPING
  memset(&pkt->hw_stamp, 0, sizeof(pkt->hw_stamp));
#endif
}


ci_inline ci_ip_pkt_fmt* ci_netif_pkt_get(ci_netif* ni, int bufset_id)
{
  ci_ip_pkt_fmt* pkt;
  ci_assert_gt(ni->packets->n_free, 0);
  ci_assert_gt(ni->packets->set[bufset_id].n_free, 0);
  ci_assert(OO_PP_NOT_NULL(ni->packets->set[bufset_id].free));
  pkt = PKT(ni, ni->packets->set[bufset_id].free);
  ni->packets->set[bufset_id].free = pkt->next;
  --ni->packets->set[bufset_id].n_free;
  --ni->packets->n_free;
  pkt->refcount = 1;
  CI_DEBUG(pkt->intf_i = -1);
  CHECK_FREEPKTS(ni);
  return pkt;
}

ci_inline void ci_netif_pkt_put(ci_netif* ni, ci_ip_pkt_fmt* pkt)
{
  int bufset_id = PKT_SET_ID(pkt);
  ci_assert_le(bufset_id, ni->packets->sets_n);
  pkt->next = ni->packets->set[bufset_id].free;
  ni->packets->set[bufset_id].free = OO_PKT_P(pkt);
  ++ni->packets->set[bufset_id].n_free;
  ++ni->packets->n_free;
  CHECK_FREEPKTS(ni);
}

/* If we have too few free packets in the now-current set,
 * we should allocate another set.
 * Fixme: is set_size/2 a good margin or should it be tunable? */
ci_inline int/*bool*/
ci_netif_pkt_set_is_underfilled(ci_netif* ni, int bufset_id)
{
  return ni->packets->set[bufset_id].n_free < CI_CFG_PKT_SET_LOW_WATER;
}

/* Set new current_pkt_set.
 *
 * is_underfilled is the value returned by
 * ci_netif_pkt_set_is_underfilled() when we started to use this set.
 * If the caller need to allocate a lot of packets, there is no need call
 * ci_netif_pkt_set_change() until all the allocations are done.
 */
ci_inline void ci_netif_pkt_set_change(ci_netif* ni, int bufset_id,
                                       int/*bool*/ is_underfilled)
{
  ni->packets->id = bufset_id;
  ci_assert_equal(bufset_id, NI_PKT_SET(ni));

  if( ni->packets->sets_n < ni->packets->sets_max && is_underfilled )
    ef_eplock_holder_set_flag(&ni->state->lock,
                              CI_EPLOCK_NETIF_NEED_PKT_SET);

  /* When we are called from ci_netif_rx_post(), we could already consume
   * all available packets.  Let's set NEED_PKT_SET flag above and exit. */
  if( ni->packets->set[bufset_id].n_free == 0 )
    return;
  ci_assert(OO_PP_NOT_NULL(ni->packets->set[bufset_id].free));
}

ci_inline ci_ip_pkt_fmt* ci_netif_pkt_alloc(ci_netif* ni, int flags) {
  ci_ip_pkt_fmt* pkt;
  int bufset_id;
  ci_assert( ci_netif_is_locked(ni) );
  bufset_id = NI_PKT_SET(ni);
  if(CI_LIKELY( ni->packets->set[bufset_id].n_free > 0 ))
    pkt = ci_netif_pkt_get(ni, bufset_id);
  else
    pkt = ci_netif_pkt_alloc_slow(ni, flags);
  return pkt;
}


ci_inline int ci_netif_pkt_nonb_pool_is_empty(ci_netif* ni)
{ return (ni->state->nonb_pkt_pool & 0xffffffff) == 0xffffffff; }

ci_inline int ci_netif_pkt_nonb_pool_not_empty(ci_netif* ni)
{ return (ni->state->nonb_pkt_pool & 0xffffffff) != 0xffffffff; }



#define CI_NETIF_PKT_POOL_MIN_LEVEL  512

/* Number of packet either allocated to rx or reserved to rx */
ci_inline int ci_netif_pkt_rx_n(ci_netif* ni) {
  return ni->state->n_rx_pkts + ni->state->reserved_pktbufs;
}

/* Number of packet bufs that can get allocated */
ci_inline int ci_netif_pkt_free_n(ci_netif* ni) {
  return
    ((ni->packets->sets_max - ni->packets->sets_n) << CI_CFG_PKTS_PER_SET_S) +
    ni->packets->n_free;
}

/* Number of packet bufs currently allocated to TX paths.  Packets in the
 * non-blocking free pool count as being allocated to TX.
 */
ci_inline int ci_netif_pkt_tx_n(ci_netif* ni) {
  return ni->packets->n_pkts_allocated - ni->state->n_rx_pkts
    - ni->packets->n_free;
}


/* Returns true if we are allowed to allocate a buffer for the TX path from
 * the free pool.  ie. This returns false if we've reached the limit as to
 * the number of buffers that TX path can use.
 *
 * Just because you are permitted to allocate a packet for TX does not mean
 * it is possible at the moment -- there may be none free.  See
 * ci_netif_pkt_tx_can_alloc_now().
 */
ci_inline int ci_netif_pkt_tx_may_alloc(ci_netif* ni) {
  int n_tx_pkts = ci_netif_pkt_tx_n(ni);
  return
    /* TX is not yet using all of the packet buffers that are exclusively
     * reserved for its use.
     */
    (n_tx_pkts < NI_OPTS(ni).max_packets - NI_OPTS(ni).max_rx_packets) ||
    /* The RX rings are nice and full, and TX hasn't hit its limit. */
    (ni->state->mem_pressure == 0 && n_tx_pkts < NI_OPTS(ni).max_tx_packets);
}


/* Returns true if it is permitted and possible to allocate a packet buffer
 * for the TX path -- either from the free pool of the non-blocking pool.
 */
ci_inline int ci_netif_pkt_tx_can_alloc_now(ci_netif* ni) {
  return ( (ci_netif_pkt_tx_may_alloc(ni) && ni->packets->n_free > 0) ||
           ci_netif_pkt_nonb_pool_not_empty(ni) );
}


/* Allocate a packet for the TCP TX path.  Such packets may get stuck in
 * the send queue or retransmit queue for a long time, so we must be
 * careful not to deplete the pool of free buffers too much.
 */
ci_inline ci_ip_pkt_fmt*
ci_netif_pkt_tx_tcp_alloc(ci_netif* ni, ci_tcp_state* ts) {
  int bufset_id;
  ci_assert(ci_netif_is_locked(ni));
  bufset_id = NI_PKT_SET(ni);
  if(CI_LIKELY( ci_netif_pkt_tx_may_alloc(ni) &&
                ni->packets->set[bufset_id].n_free > 0 )) {
    return ci_netif_pkt_get(ni, bufset_id);
  }
  else {
    if( (! ci_netif_pkt_tx_may_alloc(ni)) &&
        (NI_OPTS(ni).tcp_sndbuf_mode == 2) &&
        (ts != NULL) )
      ci_tcp_moderate_sndbuf(ni, ts);

    /* TCP TX path is always allowed to allocate from the non-blocking pool
     * because those packet buffers are already allocated to TX.
     */
    return ci_netif_pkt_alloc_slow(ni, CI_PKT_ALLOC_FOR_TCP_TX |
                                   CI_PKT_ALLOC_USE_NONB);
  }
}


ci_inline ci_ip_pkt_fmt* ci_netif_pkt_alloc_nonb(ci_netif* ni) 
{
  volatile ci_uint64 *nonb_pkt_pool_ptr;
  ci_uint64 link, new_link;
  unsigned id;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp;

  nonb_pkt_pool_ptr = &(ni->state->nonb_pkt_pool);
 again:
  pkt = NULL;
  link = *nonb_pkt_pool_ptr;
  id = link & 0xffffffff;
  if( id != 0xffffffff ) {
    OO_PP_INIT(ni, pp, id);
    pkt = PKT(ni, pp);
    new_link = ((unsigned)OO_PP_ID(pkt->next)) | (link & 0xffffffff00000000llu);
    if( ci_cas64u_fail(nonb_pkt_pool_ptr, link, new_link) )
      goto again;
    ci_assert_equal(pkt->refcount, 0);
    pkt->refcount = 1;
    CI_DEBUG(pkt->intf_i = -1);
  }
  return pkt;
}


ci_inline void ci_netif_pkt_free_nonb_list(ci_netif *ni, oo_pkt_p pkt_list,
                                             ci_ip_pkt_fmt *pkt_list_tail) 
{
  volatile ci_uint64 *nonb_pkt_pool_ptr;
  ci_uint64 new_link, link;

  nonb_pkt_pool_ptr = &(ni->state->nonb_pkt_pool);
  do {
    ci_assert_equal(pkt_list_tail->refcount, 0);
    link = *nonb_pkt_pool_ptr;
    OO_PP_INIT(ni, pkt_list_tail->next, link & 0xffffffff);
    new_link = ((unsigned)OO_PP_ID(pkt_list)) | 
      ((link + 0x0000000100000000llu) & 0xffffffff00000000llu);
  } while( ci_cas64u_fail(nonb_pkt_pool_ptr, link, new_link) );
}


ci_inline void ci_netif_pkt_hold(ci_netif* ni, ci_ip_pkt_fmt* pkt) {
  ci_assert_gt(pkt->refcount, 0);
  ++pkt->refcount;
}

#ifdef __KERNEL__
ci_inline void ci_netif_pkt_release_mnl(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                        int* p_netif_is_locked) {
  ci_assert_gt(pkt->refcount, 0);
  if( --pkt->refcount == 0 )
    ci_netif_pkt_free(ni, pkt, p_netif_is_locked);
}

ci_inline void ci_netif_pkt_release(ci_netif* ni, ci_ip_pkt_fmt* pkt) {
  int is_locked = 1;
  ci_assert( ci_netif_is_locked(ni) );
  ci_netif_pkt_release_mnl(ni, pkt, &is_locked);
}
#else
ci_inline void ci_netif_pkt_release(ci_netif* ni, ci_ip_pkt_fmt* pkt) {
  ci_assert_gt(pkt->refcount, 0);
  ci_assert( ci_netif_is_locked(ni) );
  if( --pkt->refcount == 0 )
    ci_netif_pkt_free(ni, pkt);
}
#endif


/* This is an optimised route for freeing packets when we know there is
** only one reference.
*/
#define ci_netif_pkt_release_1ref(ni, pkt)      \
  ci_netif_pkt_release(ni, pkt)


#define ci_netif_pkt_release_rx_1ref(ni, pkt)   \
  ci_netif_pkt_release_1ref(ni, pkt)

#define ci_netif_pkt_release_rx(ni, pkt)        \
  ci_netif_pkt_release(ni, pkt)

ci_inline int ci_netif_pkt_release_check_keep(ci_netif* ni, ci_ip_pkt_fmt* pkt)
{
  /* If this flag is set it counts as another reference, as the single
   * reference gets shared between UDP receive queue and application
   * if app returns ONLOAD_ZC_KEEP
   */
  if( (pkt->rx_flags & CI_PKT_RX_FLAG_KEEP) ) {
    /* Remove flag so other context (app or reap) will free it */
    pkt->rx_flags &=~ CI_PKT_RX_FLAG_KEEP;
    return 0;
  }
  else {
    ci_netif_pkt_release(ni, pkt);
    return 1;
  }
}

/*********************************************************************
*************************** pktbuf reserve accounting ****************
*********************************************************************/

ci_inline unsigned
__ci_tcp_rx_buf_count(ci_netif* netif, ci_tcp_state* ts)
{
  return ts->recv1.num + ts->recv2.num + ts->rob.num;
}

ci_inline unsigned
__ci_tcp_rx_reserved_bufs(ci_netif* netif, ci_tcp_state* ts, int allocated_pkts)
{
  int reserved_bufs = ts->s.b.state != CI_TCP_ESTABLISHED ? 0 :
                      NI_OPTS(netif).endpoint_packet_reserve;
  reserved_bufs -= allocated_pkts;
  /* this many buffers of this socket should have been added to
   * ns->reserved_pktbufs already */
  return CI_MAX(0, reserved_bufs);
}

ci_inline unsigned
ci_tcp_rx_reserved_bufs(ci_netif* netif, ci_tcp_state* ts)
{
  return __ci_tcp_rx_reserved_bufs(netif, ts, __ci_tcp_rx_buf_count(netif, ts));
}

/* adjusts per-nic count of reserved buffers
 * needs to be called BEFORE any of tcp recv queues gets to be modified */
ci_inline void
ci_tcp_rx_buf_adjust(ci_netif* netif, ci_tcp_state* ts, ci_ip_pkt_queue* q, int delta)
{
  int m, n;

  ci_assert(q == &ts->rob || q == &ts->recv1 || q == &ts->recv2);
  ci_assert_nflags(netif->state->flags, CI_NETIF_FLAG_PKT_ACCOUNT_PENDING);

  if( ts->s.b.state != CI_TCP_ESTABLISHED )
    return;

  m = ci_tcp_rx_reserved_bufs(netif, ts);
  n = __ci_tcp_rx_reserved_bufs(netif, ts, __ci_tcp_rx_buf_count(netif, ts) + delta);

  netif->state->reserved_pktbufs += n - m;
  ci_assert(ci_netif_is_locked(netif));
}


extern void ci_ip_queue_drop(ci_netif*, ci_ip_pkt_queue*) CI_HF;

ci_inline void
ci_tcp_rx_queue_drop(ci_netif* ni, ci_tcp_state* ts, ci_ip_pkt_queue* q)
{
  ci_tcp_rx_buf_adjust(ni, ts, q, -q->num);
  ci_ip_queue_drop(ni, q);
}

ci_inline void
ci_tcp_rx_buf_account_begin(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert( ci_netif_is_locked(netif) );
  ci_assert_nflags(netif->state->flags, CI_NETIF_FLAG_PKT_ACCOUNT_PENDING);
  CI_DEBUG(netif->state->flags |= CI_NETIF_FLAG_PKT_ACCOUNT_PENDING);

  /* now lets remove the previously accounted buffers, they will be
   * readded (if still there) in ci_tcp_recv_buf_account_end() */

  netif->state->reserved_pktbufs -= ci_tcp_rx_reserved_bufs(netif, ts);
  ci_assert_ge(netif->state->reserved_pktbufs, 0);
}

ci_inline void
ci_tcp_rx_buf_account_end(ci_netif* netif, ci_tcp_state* ts)
{
  ci_assert( ci_netif_is_locked(netif) );
  ci_assert_flags(netif->state->flags, CI_NETIF_FLAG_PKT_ACCOUNT_PENDING);
  CI_DEBUG(netif->state->flags &= ~CI_NETIF_FLAG_PKT_ACCOUNT_PENDING);

  netif->state->reserved_pktbufs += ci_tcp_rx_reserved_bufs(netif, ts);
  ci_assert_le(netif->state->reserved_pktbufs, NI_OPTS(netif).max_rx_packets);
}

/*********************************************************************
*************************** ci_ip_pkt_queue **************************
*********************************************************************/

#define CI_IP_QUEUE_UNLIMITED   INT_MAX

ci_inline void ci_ip_queue_init(ci_ip_pkt_queue *qu) {
  qu->num = 0;
  qu->head = OO_PP_NULL;
  /* tail undefined when queue is empty */
}


ci_inline int ci_ip_queue_is_empty(ci_ip_pkt_queue *qu)
{ return qu->num == 0; }

ci_inline int ci_ip_queue_not_empty(ci_ip_pkt_queue *qu)
{ return qu->num; }


ci_inline int ci_ip_queue_is_valid(ci_netif* netif, ci_ip_pkt_queue* qu)
{
  if( qu->num == 0 )
    return OO_PP_IS_NULL(qu->head);
  else
    return IS_VALID_PKT_ID(netif, qu->head) && 
      IS_VALID_PKT_ID(netif, qu->tail) &&
      OO_PP_IS_NULL(PKT(netif, qu->tail)->next);
}

#ifndef NDEBUG
/* This function should be NEVER used in production!
 * For temporary debugging only! */
ci_inline int ci_ip_queue_is_valid_long(ci_netif* netif, ci_ip_pkt_queue* qu, 
                                        const char *name)
{
  int i = 0, found_tail = 0;
  oo_pkt_p id;

  if( !ci_ip_queue_is_valid(netif, qu) )
    return 0;
  for( id = qu->head; OO_PP_NOT_NULL(id); 
       id = PKT(netif, id)->next ) {
    ci_ip_pkt_fmt *pkt = PKT(netif, id);
    i++;
    ci_log("%s queue %d: %d %08x-%08x", name, i, OO_PP_FMT(id),
           pkt->pf.tcp_tx.start_seq, pkt->pf.tcp_tx.end_seq);
    if( OO_PP_EQ(qu->tail, id) )
      found_tail = 1;
  }
  if( i != qu->num ) {
    ci_log("validation of %s queue failed: %d real members, %d declared", 
           name, i, qu->num);
    return 0;
  }
  if( i && ! found_tail ) {
    ci_log("validation of %s queue failed: tail %d not in queue", 
           name, OO_PP_FMT(qu->tail));
    return 0;
  }
  return 1;
}
#endif


ci_inline void __ci_ip_queue_enqueue(ci_netif* netif, ci_ip_pkt_queue* qu,
                                     ci_ip_pkt_fmt* pkt)
{
  if( ci_ip_queue_is_empty(qu) ) {
    ci_assert(OO_PP_IS_NULL(qu->head));
    qu->head = OO_PKT_P(pkt);
  }
  else {
    ci_assert(OO_PP_NOT_NULL(qu->head));
    /* This assumes the netif lock is held, so use
       ci_ip_queue_enqueue_nnl() if it's not */
    PKT(netif, qu->tail)->next = OO_PKT_P(pkt);
  }
  qu->tail = OO_PKT_P(pkt);
  qu->num++;
}


ci_inline void __ci_tcp_rx_queue_enqueue(ci_netif* netif, ci_tcp_state* ts,
                                         ci_ip_pkt_queue* qu, ci_ip_pkt_fmt* pkt)
{
  ci_tcp_rx_buf_adjust(netif, ts, qu, 1);
  __ci_ip_queue_enqueue(netif, qu, pkt);
}


ci_inline void ci_ip_queue_enqueue(ci_netif* netif, ci_ip_pkt_queue* qu,
                                   ci_ip_pkt_fmt* pkt)
{
  pkt->next = OO_PP_NULL;
  __ci_ip_queue_enqueue(netif, qu, pkt);
}


ci_inline void ci_ip_queue_dequeue(ci_netif* netif, ci_ip_pkt_queue* qu,
                                   ci_ip_pkt_fmt* head)
{
  ci_assert(IS_VALID_PKT_ID(netif, qu->head));
  ci_assert_gt(qu->num, 0);
  ci_assert(PKT(netif, qu->head) == head);

  qu->head = head->next;
  --qu->num;

  ci_assert_equiv(qu->num, OO_PP_NOT_NULL(qu->head));
}


ci_inline void ci_tcp_rx_queue_dequeue(ci_netif* netif, ci_tcp_state* ts,
                                       ci_ip_pkt_queue* qu, ci_ip_pkt_fmt* head)
{
  ci_tcp_rx_buf_adjust(netif, ts, qu, -1);
  ci_ip_queue_dequeue(netif, qu, head);
}

/* Move [num] packets from the start of [from] to the tail of [to].  [last]
** must point at the last packet in the chain to be moved.
*/
ci_inline void ci_ip_queue_move(ci_netif* netif, ci_ip_pkt_queue* from,
                                ci_ip_pkt_queue *to,
                                ci_ip_pkt_fmt *last, int num)
{
  oo_pkt_p originalfromhead;

  ci_assert(num);
  ci_assert_ge(from->num, num);

  originalfromhead = from->head;
  /*
   * First, cut off the bit of the from queue we are moving
   */
  from->head = last->next;
  from->num -= num;
  last->next = OO_PP_NULL;
  ci_wmb();
  /* 
   * cat the to list and the new list 
   */
  if( ci_ip_queue_is_empty(to) )
    to->head = originalfromhead;
  else
    PKT(netif, to->tail)->next = originalfromhead;
  to->tail = OO_PKT_P(last);
  to->num += num;
}

/* Move entire queue [from] to [to] and re-init [from]. [to] need not
 * be initialised. */
ci_inline void ci_ip_queue_move_all(ci_netif* netif, ci_ip_pkt_queue* from,
                                    ci_ip_pkt_queue *to)
{
  ci_assert(netif);
  ci_assert(from);
  ci_assert(to);
  *to = *from;
  ci_wmb();
  ci_ip_queue_init(from);
}

/**********************************************************************
********************************* IP **********************************
**********************************************************************/

/* Limited IPID handling - just run around the block we get at start-up */
# include <ci/internal/ipid.h>
# define NEXT_IP_ID(ni)  (NI_IPID(ni)->base | \
                         (NI_IPID(ni)->next++ & CI_IPID_BLOCK_MASK))

#if CI_CFG_IPV6
# define NEXT_IP6_ID(ni) (NI_IPID(ni)->ip6_base | \
                         (NI_IPID(ni)->ip6_next++ & CI_IP6ID_BLOCK_MASK))
#endif

typedef union {
#if CI_CFG_IPV6
  ci_uint32 ip6;
#endif
  ci_uint16 ip4;
} ci_ipx_id_t;

ci_inline ci_ipx_id_t
ci_next_ipx_id_be(int af, ci_netif* ni)
{
  ci_ipx_id_t ipx_id;
#if CI_CFG_IPV6
  if( IS_AF_INET6(af) )
    ipx_id.ip6 = CI_BSWAP_BE32(NEXT_IP6_ID(ni));
  else
#endif
    ipx_id.ip4 = CI_BSWAP_BE16(NEXT_IP_ID(ni));
  return ipx_id;
}

/* Return true if ip options contain badness.
 * Badness: Unknown option, source routing, invalid option lengths.
 */
extern int ci_ip_options_parse(ci_netif* netif, ci_ip4_hdr* ip,
                               const int hdr_size);

/**********************************************************************
**************************** citp_waitable ****************************
**********************************************************************/

ci_inline int
citp_waitable_lock_or_set_flag(citp_waitable* w, ci_uint32 flag)
{
  ci_uint32 l, new_l;
  int rc;

  do {
    l = w->lock.wl_val;
    if( ! (l & OO_WAITABLE_LK_LOCKED) ){
      new_l = l | OO_WAITABLE_LK_LOCKED;
      rc = 1;
    }
    else{
      new_l = l | flag;
      rc = 0;
    }
  } while(CI_UNLIKELY( ci_cas32u_fail(&w->lock.wl_val, l, new_l) ));
  return rc;
}


ci_inline void
citp_waitable_lock_set_flag(citp_waitable* w, ci_uint32 flag)
{
  ci_uint32 l;
  do {
    l = w->lock.wl_val;
  } while(CI_UNLIKELY( ci_cas32u_fail(&w->lock.wl_val, l, l | flag) ));
}

ci_inline void
citp_waitable_lock_clear_flag(citp_waitable* w, ci_uint32 flag)
{
  ci_uint32 l;
  do {
    l = w->lock.wl_val;
  } while(CI_UNLIKELY( ci_cas32u_fail(&w->lock.wl_val, l, l & ~flag) ));
}


/**********************************************************************
***************************** ICMP/Errors *****************************
**********************************************************************/

#define ci_icmp_send_error(ni, rx_pkt, type, code)              \
  __ci_icmp_send_error((ni), oo_pkt_af(rx_pkt),                 \
                       oo_ipx_hdr(rx_pkt),                      \
                       oo_ether_hdr(rx_pkt), (type), (code))

ci_inline int
ci_icmp_send_port_unreach(ci_netif *ni, ci_ip_pkt_fmt* rx_pkt)
{
  ci_uint8 type, code;

#if CI_CFG_IPV6
  if( IS_AF_INET6(oo_pkt_af(rx_pkt)) ) {
    type = CI_ICMPV6_DEST_UNREACH;
    code = CI_ICMPV6_DU_PORT_UNREACH;
  }
  else
#endif
  {
    type = CI_ICMP_DEST_UNREACH;
    code = CI_ICMP_DU_PORT_UNREACH;
  }
  return ci_icmp_send_error(ni, rx_pkt, type, code);
}


/**********************************************************************
********************************* UDP *********************************
**********************************************************************/

ci_inline void ci_udp_dec_tx_count(ci_udp_state* us, ci_ip_pkt_fmt* pkt) {
  ci_assert(pkt->flags & CI_PKT_FLAG_UDP);
  ci_assert_ge((int) us->tx_count, (int) pkt->pf.udp.tx_length);
  us->tx_count -= pkt->pf.udp.tx_length;
}


/* Returns true if there is sufficient space in the send queue that it is
** worth telling the app.  ie. Used to decide when to wake a thread, and
** when to indicate writable in select() and poll().
*/
ci_inline int ci_udp_tx_advertise_space(ci_udp_state* us)
{ return (int) (us->s.so.sndbuf - us->tx_count) > (int) (us->tx_count >> 1u); }


/*********************************************************************
************************** UDP Receive queue *************************
*********************************************************************/

extern void ci_udp_recv_q_drop(ci_netif*, ci_udp_recv_q*) CI_HF;
extern int ci_udp_recv_q_reap(ci_netif*, ci_udp_recv_q*) CI_HF;
extern void ci_udp_recvq_dump(ci_netif* ni, ci_udp_recv_q* q,
                              const char* pf1, const char* pf2,
                              oo_dump_log_fn_t logger, void* log_arg) CI_HF;

#if CI_CFG_TIMESTAMPING
extern int ci_udp_timestamp_q_enqueue(ci_netif* ni, ci_udp_state* us, 
                                      ci_ip_pkt_fmt* pkt);
#endif

/* Put a packet into recv_q but don't mark it as visible to the consumer yet.
 * Stack should be locked. */
ci_inline void ci_udp_recv_q_put_pending(ci_netif* ni, ci_udp_recv_q* q,
                                         ci_ip_pkt_fmt* pkt)
{
  ci_assert(ci_netif_is_locked(ni));

  if( pkt->rx_flags & CI_PKT_RX_FLAG_RECV_Q_CONSUMED ) {
    /* Changing [pkt->rx_flags] without the socket lock is safe as long as we
     * ensure that we do so before posting [pkt] to the recvq.
     * This is required for proper functioning ci_udp_recv_q_get() */
    pkt->rx_flags &=~ CI_PKT_RX_FLAG_RECV_Q_CONSUMED;
  }

  pkt->udp_rx_next = OO_PP_NULL;
  /* pkt->udp_rx_next needs to be commited
   * (along with the rest metadata)
   * before pkt buf is made visible to receive path
   * potentially performing concurrent processing.
   * This is required for proper functioning of ci_udp_recv_q_next()
   * which is used by WODA */
  ci_wmb();
  if( OO_PP_NOT_NULL(q->head) ) {
    PKT_CHK(ni, q->tail)->udp_rx_next = OO_PKT_P(pkt);
    ci_udp_recv_q_reap(ni, q);
  }
  else {
    ci_assert(OO_PP_IS_NULL(q->extract));
    /* q->extract is modified here without proper lock
     * (q->extract is proteced by socket lock).
     * This is correct in this case as q->extract have been NULL,
     * and no concurrent processing is expected */
    q->extract = OO_PKT_P(pkt);
    q->head = OO_PKT_P(pkt);
  }
  q->tail = OO_PKT_P(pkt);
}


/* Having done ci_udp_recv_q_put_pending(), now mark the packets as visible to
 * the consumer. Stack should be locked. */
ci_inline void ci_udp_recv_q_put_complete(ci_udp_recv_q* q, unsigned n_buffers)
{
  ci_wmb();

  /* Increment pkts_added as a last step: ci_udp_recv_q_not_empty() should
   * not flag event until the packet is in the list. */
  q->pkts_added += n_buffers;
}


/* Put a packet into recv_q.  Stack should be locked. */
ci_inline void ci_udp_recv_q_put(ci_netif* ni, ci_udp_recv_q* q,
                                 ci_ip_pkt_fmt* pkt)
{
  ci_udp_recv_q_put_pending(ni, q, pkt);
  ci_udp_recv_q_put_complete(q, pkt->n_buffers);
}


/* Get a packet from recv_q.  Socket should be locked. */
ci_inline ci_ip_pkt_fmt* ci_udp_recv_q_get(ci_netif* ni,
                                           ci_udp_recv_q* q)
{
  ci_ip_pkt_fmt* pkt;

  if( ci_udp_recv_q_is_empty(q) )
     return NULL;

  /* prevent reordering of access to q->extract before the above check */
  ci_rmb();

  pkt = PKT_CHK_NNL(ni, q->extract);
  if( pkt->rx_flags & CI_PKT_RX_FLAG_RECV_Q_CONSUMED ) {
    /* We know that the receive queue is not empty, so if
     * this pkt is already consumed, the next one must be OK to
     * receive.
     */
    q->extract = OO_ACCESS_ONCE(pkt->udp_rx_next);
    pkt = PKT_CHK_NNL(ni, q->extract);
    ci_assert( !(pkt->rx_flags & CI_PKT_RX_FLAG_RECV_Q_CONSUMED) );
  }
  return pkt;
}

ci_inline void ci_udp_recv_q_deliver(ci_netif* ni, ci_udp_recv_q* q,
                                     ci_ip_pkt_fmt* pkt)
{
  q->pkts_delivered  += pkt->n_buffers;
  pkt->rx_flags |= CI_PKT_RX_FLAG_RECV_Q_CONSUMED;
}

ci_inline ci_ip_pkt_fmt* ci_udp_recv_q_next(ci_netif* ni,
                                            ci_ip_pkt_fmt* pkt)
{
  /* This function is called without the stack lock, and so we had better be
   * certain that the packet is not going to be reaped under our feet. */
  ci_assert_nflags(pkt->rx_flags, CI_PKT_RX_FLAG_RECV_Q_CONSUMED);

  if( OO_PP_IS_NULL(pkt->udp_rx_next) )
    return NULL;
  return PKT_CHK_NNL(ni, pkt->udp_rx_next);
}

/* Linux-style: SO_RCVBUF & SO_SNDBUF do not limit the number of bytes in
 * packet payload.  They limit the number of bytes used to keep this
 * payload.  In our case, we should limit the number of packets. */
ci_inline int ci_udp_recv_q_bytes2packets(int bytes_limit)
{
  return bytes_limit / CI_CFG_PKT_BUF_SIZE + 1;
}


/*********************************************************************
***************************** TCP timers *****************************
*********************************************************************/


/* RTO handlers */
static inline int ci_tcp_retransq_is_empty(ci_tcp_state* ts)
{
  return ci_ip_queue_is_empty(&ts->retrans) &&
         ! (ts->tcpflags & CI_TCPT_FLAG_FIN_PENDING);
}

ci_inline void ci_tcp_rto_check_and_set(ci_netif* netif, ci_tcp_state* ts) {
  /* shouldn't set an RTO if no data to send */
  ci_assert(!ci_tcp_retransq_is_empty(ts)); 
  /* shouldn't set an RTO timer in a state that doesn't allow them */
  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
  if( ! ci_ip_timer_pending(netif, &ts->rto_tid) ) {
#if CI_CFG_TAIL_DROP_PROBE
    ts->tcpflags &=~ CI_TCPT_FLAG_TAIL_DROP_TIMING;
#endif
    ci_ip_timer_set(netif, &ts->rto_tid, ci_tcp_time_now(netif) + ts->rto);
  }
}

ci_inline void ci_tcp_rto_clear(ci_netif* netif, ci_tcp_state* ts)
{ ci_ip_timer_clear(netif, &ts->rto_tid); }

ci_inline void ci_tcp_rto_restart(ci_netif* netif, ci_tcp_state* ts) {
  /* shouldn't set an RTO if retrans queue is empty */
  ci_assert(!ci_tcp_retransq_is_empty(ts));
  /* shouldn't set an RTO timer in a state that doesn't allow them */
  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
#if CI_CFG_TAIL_DROP_PROBE
  ts->tcpflags &=~ CI_TCPT_FLAG_TAIL_DROP_TIMING;
#endif
  ci_ip_timer_modify(netif, &ts->rto_tid, ci_tcp_time_now(netif) + ts->rto);
}

ci_inline void ci_tcp_rto_set_with_timeout(ci_netif* netif, ci_tcp_state* ts,
                                           ci_iptime_t timeout) {
  /* shouldn't set an RTO if retrans queue is empty */
  ci_assert(!ci_tcp_retransq_is_empty(ts));
  /* shouldn't set an RTO timer in a state that doesn't allow them */
  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
  ci_ip_timer_set(netif, &ts->rto_tid, ci_tcp_time_now(netif) + timeout);
}

#define ci_tcp_rto_set(ni, ts) ci_tcp_rto_set_with_timeout((ni), (ts), \
                                                           (ts)->rto)

ci_inline void ci_tcp_rto_bound(ci_netif* netif, ci_tcp_state* ts) {
  ts->rto = CI_MIN(NI_CONF(netif).tconst_rto_max, ts->rto);
  ts->rto = CI_MAX(NI_CONF(netif).tconst_rto_min, ts->rto);
}

/* delayed ack timers */
ci_inline void ci_tcp_delack_check_and_set(ci_netif* netif, 
                                           ci_tcp_state* ts) {
  /* shouldn't set a timer in a state that doesn't allow them */
  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
  if( !ci_ip_timer_pending(netif, &ts->delack_tid) )
    ci_ip_timer_set(netif, &ts->delack_tid, ci_tcp_time_now(netif) +
                    NI_CONF(netif).tconst_delack);
}

ci_inline void ci_tcp_delack_clear(ci_netif* netif, ci_tcp_state* ts)
{ ci_ip_timer_clear(netif, &ts->delack_tid); }

#if CI_CFG_DYNAMIC_ACK_RATE
ci_inline void ci_tcp_delack_soon(ci_netif* netif, ci_tcp_state* ts) 
{
  /* shouldn't set a timer in a state that doesn't allow them */
  ci_assert(!(ts->s.b.state & CI_TCP_STATE_NO_TIMERS));
  ci_assert_gt(ts->acks_pending & CI_TCP_ACKS_PENDING_MASK,
               NI_OPTS(netif).delack_thresh);
  ts->acks_pending |= CI_TCP_DELACK_SOON_FLAG;
  if( ci_ip_timer_pending(netif, &ts->delack_tid) )
    ci_ip_timer_modify(netif, &ts->delack_tid, ci_tcp_time_now(netif)+1);
  else
    ci_ip_timer_set(netif, &ts->delack_tid, ci_tcp_time_now(netif)+1);
}
#endif

#if CI_CFG_TAIL_DROP_PROBE

ci_inline int ci_tcp_taildrop_probe_enabled(const ci_netif* ni,
                                            const ci_tcp_state* ts)
{
  return NI_OPTS(ni).tail_drop_probe &&
         (ts->tcpflags & CI_TCPT_FLAG_SACK) &&
         ts->congstate == CI_TCP_CONG_OPEN &&
         (ts->s.b.state & CI_TCP_STATE_SYNCHRONISED);
}

/* Minimal TCP timeout.
 *
 * In linux
 * TCP_TIMEOUT_MIN = 2 jiffies
 * TCP_RTO_MIN = HZ / 5
 * We have the same rto_min=200ms, and assuming HZ=100 we define
 * the minimal TCP timeout to be rto_min/10.
 *
 * The tradeoff is:
 * - With a small value for TCP_TIMEOUT_MIN we have a chance to retransmit
 *   the last packet too early before we get the ACK which may be already
 *   in-flight (see ON-11672).
 * - With a large value for TCP_TIMEOUT_MIN the whole idea of the taildrop
 *   probe is lost.
 */
#define TCP_TIMEOUT_MIN(netif) (NI_CONF(netif).tconst_rto_min / 10)

ci_inline unsigned ci_tcp_taildrop_timeout(const ci_netif* netif,
                                           const ci_tcp_state* ts )
{
  unsigned offset;

  ci_assert_gt(TCP_TIMEOUT_MIN(netif), 0);

  /* We follow Linux instead of the spec. */
  if( ts->sa >= TCP_TIMEOUT_MIN(netif) ) {
    /* rtt = sa >> 3; offset = rtt * 2 */
    offset = ts->sa >> 2;
    if( ts->retrans.num == 1 )
      /* Wait long enough to ensure a delayed ack will be returned. */
      offset += NI_CONF(netif).tconst_rto_min;
    else
      offset += TCP_TIMEOUT_MIN(netif);
  }
  else {
    /* ts->sa = 0 at start of day; it can be too small when 1 or 2 packets
     * were acked. */
    offset =  NI_CONF(netif).tconst_rto_initial;
  }
  return CI_MIN(offset, ts->rto);
}
#undef TCP_TIMEOUT_MIN

#else

ci_inline int ci_tcp_taildrop_probe_enabled(const ci_netif* ni,
                                            const ci_tcp_state* ts)
{
  return 0;
}

ci_inline unsigned ci_tcp_taildrop_timeout(const ci_netif* netif,
                                           const ci_tcp_state* ts )
{
  ci_assert(0);
  return 0;
}

#endif

/* keep alive timers */

/*
 * Restart keepalive timer in case CI_TCPT_FLAG_KALIVE flag is set on the
 * socket. It runs timer if it is not running yet.
 *
 * @param netif    Network interface data structure
 * @param ts     TCP control block
 * @param t        Relative time when keepalive timer should expire
 */
ci_inline void ci_tcp_kalive_restart(ci_netif *netif, ci_tcp_state* ts, 
                                     ci_iptime_t t) {
  /* 
   * Actually, if there are such situations remove this assert, 
   * but now I can't see any cases when this is false.
   */
  /* ?? Why not use ts->s.b.state & CI_TCP_STATE_NO_TIMERS?? */
  ci_assert( ts->s.b.state != CI_TCP_CLOSED && 
             ts->s.b.state != CI_TCP_LISTEN );

  if( ts->s.s_flags & CI_SOCK_FLAG_KALIVE )
    ci_ip_timer_modify(netif, &ts->kalive_tid, ci_tcp_time_now(netif) + t);
  else
    /*
     * ka_probes is not cleared somewhere, as soon as with disabled
     * keepalive feature this field should be zero 
     */
    ci_assert(ts->ka_probes == 0);
}

/*
 * Gets the value of keepalive IDLE time - time before start sending 
 * keepalive probes.
 *
 * @param ts  TCP control block
 */
ci_inline ci_iptime_t ci_tcp_kalive_idle_get(ci_tcp_state* ts)
{ return ts->c.t_ka_time; }

/*
 * Gets the value of keepalive IDLE time in seconds - time before 
 * start sending keepalive probes.
 *
 * @param ts  TCP control block
 */
ci_inline ci_iptime_t ci_tcp_kalive_idle_in_secs_get(ci_tcp_state* ts)
{ return ts->c.t_ka_time_in_secs; }

/*
 * Gets the value of keepalive probe interval - interval between two
 * consequent probes.
 *
 * @param ts    TCP control block
 * @param netif netif
 */
ci_inline ci_iptime_t ci_tcp_kalive_intvl_get(ci_netif* netif,
                                              ci_tcp_state* ts)
{
  return ts->c.t_ka_intvl;
}

/*
 * Gets the value of keepalive probe interval in seconds- interval between 
 * two consequent probes.
 *
 * @param ts  TCP control block
 */
ci_inline ci_iptime_t ci_tcp_kalive_intvl_in_secs_get(ci_tcp_state* ts)
{
  return ts->c.t_ka_intvl_in_secs;
}

/*
 * Gets the maximum number of keepalive probes.
 *
 * @param ts  TCP control block
 */
ci_inline unsigned ci_tcp_kalive_probes_get(ci_tcp_state* ts)
{ return ts->c.ka_probe_th; }

ci_inline void ci_tcp_kalive_check_and_clear(ci_netif* netif, ci_tcp_state* ts)
{ ci_ip_timer_clear(netif, &ts->kalive_tid); }


/* Sort out the keepalive timer when an ACK is received */
ci_inline void ci_tcp_kalive_reset(ci_netif *netif, ci_tcp_state *ts)
{
  if (ts->ka_probes) {
    /* This is a bit pointless, but necessary to get through WHQL for
     * chimney.  We have to restart the timer here rather than just
     * let it expire and sort things out then because if the interval
     * time is greater than the idle time, it will expire too late and
     * fail some WHQL tests.  For now we ignore the time that has
     * expired on this timer so far */
    ci_tcp_kalive_restart(netif, ts, ci_tcp_kalive_idle_get(ts));
 }

  ts->ka_probes = 0;
}


ci_inline void ci_tcp_zwin_set(ci_netif* netif, ci_tcp_state* ts)
{
  ci_iptime_t t;
  ci_assert( ! (ts->s.b.state & CI_TCP_STATE_NO_TIMERS) );
  ci_assert( OO_SP_IS_NULL(ts->local_peer) );
  if( ts->zwin_probes == 0 )
    t = ts->rto << ts->zwin_acks;
  else
    t = ts->rto << ts->zwin_probes;
  ci_assert(TIME_GT(t, 0));
  ci_ip_timer_set(netif, &ts->zwin_tid, ci_tcp_time_now(netif) + t);
}


/* Put ts on the 'some recycling needs to be done for this socket' timer
 * queue, starting the timer if needed. */
ci_inline void ci_tcp_recycle_reset(ci_netif* netif, ci_tcp_state* ts) {
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  ci_assert(ci_ip_queue_not_empty(&ts->rob));
  if( ! ci_ni_dllist_is_free(&ts->recycle_link) )
    return;
  ci_ni_dllist_push(netif, &netif->state->recycle_retry_q, &ts->recycle_link);
  if( ! ci_ip_timer_pending(netif, &netif->state->recycle_tid) ) {
    /* This recycle timer exists to deal with the possibility of drops
     * and/or queue overflows in the link between plugin and host. Since
     * that's guaranteed to be a very fast link, we hard-code the minimum
     * possible timeout and share the timer across all sockets. */
    ci_ip_timer_set(netif, &netif->state->recycle_tid,
                    ci_tcp_time_now(netif) + 1);
  }
#endif
}


/**********************************************************************
****************************** TCP sendq ******************************
**********************************************************************/

ci_inline int ci_tcp_sendq_is_empty(ci_tcp_state* ts)
{ return ci_ip_queue_is_empty(&ts->send); }

ci_inline int ci_tcp_sendq_not_empty(ci_tcp_state* ts)
{ return ci_ip_queue_not_empty(&ts->send); }

ci_inline void ci_tcp_sendq_drop(ci_netif* ni, ci_tcp_state* ts)
{ 
  ts->send_out += ts->send.num;
  ci_ip_queue_drop(ni, &ts->send);
}

ci_inline void ci_tcp_retrans_drop(ci_netif* ni, ci_tcp_state* ts)
{ ci_ip_queue_drop(ni, &ts->retrans); }

extern int ci_tcp_add_fin(ci_tcp_state* ts, ci_netif* netif) CI_HF;
/* Try to re-send pending FIN, return true in success. */
static inline int ci_tcp_resend_fin(ci_tcp_state* ts, ci_netif* netif)
{
  tcp_enq_nxt(ts) -= 1;
  if( ci_tcp_add_fin(ts, netif) == 0 ) {
    ts->tcpflags &=~ CI_TCPT_FLAG_FIN_PENDING;
    CITP_STATS_NETIF_INC(netif, tcp_cant_fin_resolved);
    return 1;
  }
  tcp_enq_nxt(ts) += 1;
  return 0;
}


/**********************************************************************
****************************** TCP socket *****************************
**********************************************************************/

ci_inline int ci_tcp_is_cached(ci_tcp_state* ts)
{
#if CI_CFG_FD_CACHING
  ci_assert_equal(!!(ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE),
                  !!(ts->cached_on_fd != -1));
  return ts->cached_on_fd != -1;
#else
  return 0;
#endif
}


ci_inline ci_uint16 tcp_eff_mss(const ci_tcp_state* ts) {
  if( ts->s.b.state != CI_TCP_CLOSED ) {
    ci_assert(ts->s.b.state != CI_TCP_LISTEN);
    ci_assert_gt(CI_CFG_TCP_MINIMUM_MSS, tcp_outgoing_opts_len(ts));
    ci_assert_ge(ts->eff_mss,CI_CFG_TCP_MINIMUM_MSS-tcp_outgoing_opts_len(ts));
  }
  return ts->eff_mss;
}


ci_inline void ci_tcp_fast_path_enable(ci_tcp_state* ts) {
  ts->fast_path_check  = ts->incoming_tcp_hdr_len << 26u;
  ts->fast_path_check |= CI_TCP_FLAG_ACK << 16u;
  ts->fast_path_check  = CI_BSWAP_BE32(ts->fast_path_check);
  ci_assert(ci_tcp_can_use_fast_path(ts));
}

ci_inline void ci_tcp_fast_path_disable(ci_tcp_state* ts) {
  ci_assert(!ci_tcp_can_use_fast_path(ts));
  ts->fast_path_check = ~CI_TCP_FAST_PATH_MASK;
}


ci_inline int ci_tcp_recv_not_blocked(ci_tcp_state* ts)
{
  /* We are not blocked if there is data available or the connection has
   * been shut down.
   * NB. does not return not blocked IFF single OOB byte in recv queue
   */
  int bytes = tcp_rcv_usr(ts);
  return TCP_RX_DONE(ts) ||
      (bytes >= ts->s.so.rcvlowat +
       ((tcp_urg_data(ts) & CI_TCP_URG_IS_HERE) ? 1 : 0));
}


ci_inline
ci_iptime_t ci_tcp_isn2tick(ci_netif* ni, ci_uint32 isn)
{
  ci_uint64 ticks = isn;
  ticks <<= IPTIMER_STATE(ni)->ci_ip_time_frc2isn; /* isn -> frc */
  ticks >>= IPTIMER_STATE(ni)->ci_ip_time_frc2tick; /* frc -> tick */
  return ticks;
}


/* Use cycle-counter to generate ISN.  We take a similar approach to the Linux
 * kernel, which hashes the four-tuple and then adds in a monotonically
 * increasing value.  This gives compatibility with peers (such as Windows)
 * that use the sequence number to decide whether a SYN matching a TIME_WAIT is
 * acceptable.
 */
ci_inline unsigned
ci_tcp_future_isn(ci_netif* ni, ci_addr_t laddr, ci_uint16 lport_be,
                  ci_addr_t raddr, ci_uint16 rport_be,
                  ci_uint64 future_delta_ticks)
{
  ci_uint64 frc;
  ci_uint32 hash = onload_hash3(laddr, lport_be,
                                raddr, rport_be, IPPROTO_TCP);
  ci_frc64(&frc);
  frc += future_delta_ticks << IPTIMER_STATE(ni)->ci_ip_time_frc2tick;

  /* For the monotonic part, the Linux kernel uses a timer that ticks every
   * 64 ns.  RFC 793 prescribes a granularity of 4 us, but this assumed 2 Mb/s
   * links.  We follow Linux. */
  return hash + (frc >> IPTIMER_STATE(ni)->ci_ip_time_frc2isn);
}

ci_inline unsigned
ci_tcp_initial_seqno(ci_netif* ni, ci_addr_t laddr, ci_uint16 lport_be,
                     ci_addr_t raddr, ci_uint16 rport_be)
{
  return ci_tcp_future_isn(ni, laddr, lport_be, raddr, rport_be, 0);
}

/* Returns non-scaled value of the receive window. */
ci_inline ci_uint32 ci_tcp_rcvbuf2window(ci_uint32 so_rcvbuf,
                                         ci_uint16 amss,
                                         ci_uint8 rcv_wscl)
{
  ci_assert(amss);
  so_rcvbuf = CI_MAX(so_rcvbuf, amss);
  if( so_rcvbuf % amss )
    so_rcvbuf += amss - (so_rcvbuf % amss);
  so_rcvbuf = CI_MIN(so_rcvbuf, CI_CFG_TCP_MAX_WINDOW << rcv_wscl);
  return so_rcvbuf;
}

ci_inline ci_uint16 ci_tcp_calc_rcv_wnd_syn(ci_uint32 so_rcvbuf,
                                            ci_uint16 amss,
                                            ci_uint8 rcv_wscl)
{
  /* We shouldn't scale the window in any SYN packet, so our max claimable
   * window is the full 16 bits.  If our unscaled window is more than that
   * then clamp it down.
   */
  return CI_MIN(ci_tcp_rcvbuf2window(so_rcvbuf, amss, rcv_wscl), 0xffff);
}

ci_inline void ci_tcp_set_rcvbuf(ci_netif* ni, ci_tcp_state* ts)
{
  ts->rcv_window_max = ci_tcp_rcvbuf2window(ts->s.so.rcvbuf, ts->amss,
                                            ts->rcv_wscl);
  if( CI_UNLIKELY( ts->rcv_window_max > ts->s.so.rcvbuf ) )
    ts->s.so.rcvbuf = ts->rcv_window_max;
}

ci_inline void ci_tcp_set_flags(ci_tcp_state* ts, unsigned flags) {
  ci_tcp_hdr* tcp = TS_IPX_TCP(ts);
  tcp->tcp_flags = (ci_uint8)flags;
}

ci_inline void ci_tcp_set_hdr_len(ci_tcp_state* ts, unsigned len) {
  ci_tcp_hdr* tcp = TS_IPX_TCP(ts);
  CI_TCP_HDR_SET_LEN(tcp, len);
}

ci_inline void ci_tcp_set_peer(ci_tcp_state* ts, ci_addr_t addr, unsigned port){
  ci_ipcache_set_daddr(&ts->s.pkt ,addr);
  TS_IPX_TCP(ts)->tcp_dest_be16 = (ci_uint16)port;
  ts->s.pkt.dport_be16 = port;
  ts->s.s_flags |= CI_SOCK_FLAG_CONNECTED;
}


ci_inline int ci_tcp_max_rcv_window(ci_tcp_state* ts)
{ return ts->rcv_window_max; }

/* We'll send window updates whenever the window increases by this much. */
ci_inline int ci_tcp_ack_trigger_delta(ci_tcp_state* ts)
{ return ci_tcp_max_rcv_window(ts) >> 3; }


#if CI_CFG_TCP_FASTSTART

# define CITP_TCP_FASTSTART(x)           do{ x; }while(0)

ci_inline void ci_tcp_reduce_faststart(ci_tcp_state* ts, unsigned reduction) {
  if(CI_LIKELY( ts->faststart_acks <= reduction ))
    ts->faststart_acks = 0;
  else
    ts->faststart_acks -= reduction;
}

ci_inline int ci_tcp_is_in_faststart(ci_tcp_state* ts)
{ return ts->faststart_acks != 0; }

#else

# define CITP_TCP_FASTSTART(x)           do{}while(0)
# define ci_tcp_reduce_faststart(ts, n)  do{}while(0)
# define ci_tcp_is_in_faststart(ts)      (0)

#endif


/*!
 * Window in SYN and SYN-ACK packets is not scaled.
 *
 * \param tcphdr    TCP header
 * \param wscl      Window scale
 *
 * \return Window size.
 */
ci_inline unsigned int ci_tcp_wnd_from_hdr(ci_tcp_hdr* tcphdr, unsigned wscl) {
  unsigned tmp = CI_BSWAP_BE16(tcphdr->tcp_window_be16);
  return (tcphdr->tcp_flags & CI_TCP_FLAG_SYN) ? tmp : (tmp << wscl);
}


/*!
 * Get the number of dupacks required to enter fast recovery in the spirit of
 * the classical three-dupacks algorithm.  More recent RFCs give other ways to
 * enter fast recovery, but these are not accounted for here.
 *
 * \param ts        TCP state
 */
ci_inline ci_uint32 ci_tcp_base_dupack_thresh(ci_tcp_state *ts) {
#if CI_CFG_PORT_STRIPING
  if( ts->tcpflags & CI_TCPT_FLAG_STRIPE )
    return NI_OPTS(ni).stripe_dupack_threshold;
#endif
  return CI_CFG_TCP_DUPACK_THRESH_BASE;
}

/* congestion control functions */

/* set the initial congestion window as in rfc3390/rfc2581/rfc2001 */ 
ci_inline void ci_tcp_set_initialcwnd(ci_netif* ni, ci_tcp_state* ts) {
  if( NI_OPTS(ni).initial_cwnd == 0 ) {
#if CI_CFG_TCP_INITIAL_CWND_RFC == 3390
    /* rfc3390: IW = min (4*SMSS, max (2*SMSS, 4380 bytes)) */
    unsigned mss4 = tcp_eff_mss(ts) << 2;
    unsigned mss2 = tcp_eff_mss(ts) << 1;
    ts->cwnd = CI_MAX(mss2, 4380);
    ts->cwnd = CI_MIN(ts->cwnd, mss4);
#elif CI_CFG_TCP_INITIAL_CWND_RFC == 2581
    /* rfc2581: "IW, the initial value of cwnd, MUST be less than or equal to
     * 2*SMSS bytes and MUST NOT be more than 2 segments."
     */
    ts->cwnd = tcp_eff_mss(ts) <<1;
#elif CI_CFG_TCP_INITIAL_CWND_RFC == 2001
    /* rfc2001: IW = ts->eff_mss */
    ts->cwnd = tcp_eff_mss(ts);
#else
# error Bad CI_CFG_TCP_INITIAL_CWND_RFC
#endif
  }
  else {
    if( NI_OPTS(ni).initial_cwnd < tcp_eff_mss(ts) ) {
      /* issue a warning and set initial_cwnd to eff_mss */
      ci_log("EF_TCP_INITIAL_CWND=%d is less than MSS value %d. Correcting.",
             NI_OPTS(ni).initial_cwnd, tcp_eff_mss(ts));
    }
    ts->cwnd = CI_MAX(tcp_eff_mss(ts),NI_OPTS(ni).initial_cwnd);
  }
  ts->cwnd = CI_MAX(ts->cwnd, NI_OPTS(ni).min_cwnd);
  /* RFC5681 suggests using the maximum possible send window as the initial
   * value for ssthresh.  N.B.: There are calls to this function before
   * [ts->snd_wscl] is set from the peer's TCP options (in which case it will
   * be zero), but the function is then always called again after we've
   * processed the options, so this is OK. */
  ci_assert_le(ts->snd_wscl, CI_TCP_WSCL_MAX);
  ts->ssthresh = 65535 << ts->snd_wscl;
}

/*! ?? \TODO should we use fackets to make things more exact ? */ 
ci_inline unsigned ci_tcp_inflight(ci_tcp_state* ts)
{ return SEQ_SUB(ts->snd_nxt, ts->snd_una);  }

/* New value for [ssthresh] after loss (RFC2581 p5). */
ci_inline unsigned ci_tcp_losswnd(ci_tcp_state* ts) {
  unsigned x = ci_tcp_inflight(ts) >> 1u;
  unsigned y = tcp_eff_mss(ts) << 1u;
  return CI_MAX(x, y);
}


#if CI_CFG_BURST_CONTROL
ci_inline unsigned ci_tcp_burst_exhausted(ci_netif* ni, ci_tcp_state* ts) {
  int extra, retrans_data;
  unsigned fack;
  ci_tcp_get_fack(ni, ts, &fack, &retrans_data);
  extra = SEQ_SUB(fack, tcp_snd_una(ts)) - retrans_data;
  extra = CI_MAX(extra, 0);
  return ci_tcp_inflight(ts) - extra > ts->burst_window;
}
#endif


ci_inline int ci_tcp_can_stripe(ci_netif* ni, unsigned laddr_be32,
				unsigned raddr_be32) {
#if CI_CFG_PORT_STRIPING
  unsigned mask = NI_OPTS(ni).stripe_netmask_be32;
  return (laddr_be32 & mask) == (raddr_be32 & mask);
#else
  return 0;
#endif
}


/* Return number of packets in the sendq, including prequeue.  Note that
 * any of these counters may be updated concurrently wrt this function, so
 * we have to protect against the result going negative.
 */
ci_inline int ci_tcp_sendq_n_pkts(ci_tcp_state* ts) {
  int n = oo_atomic_read(&ts->send_prequeue_in) + ts->send_in - ts->send_out;
  return n >= 0 ? n : 0;
}

/* This test is used to decide whether we should indicate to the app that
** it can enqueue more data on a socket.  ie. It is used to decide when to
** wake a blocking thread, and to decide whether to indicate the socket is
** writable in select() and poll().
*/
ci_inline int ci_tcp_tx_advertise_space(ci_netif* ni, ci_tcp_state* ts) {
  if( NI_OPTS(ni).tcp_sndbuf_mode ) {
    int pkts_queued = ci_tcp_sendq_n_pkts(ts)
#if CI_CFG_TIMESTAMPING
        + ci_udp_recv_q_pkts(&ts->timestamp_q)
#endif
        + ts->retrans.num;
    return ts->so_sndbuf_pkts - pkts_queued > (pkts_queued >> 1u);
  }
  else {
    int bytes_enqueued = SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts));
    return ( ts->so_sndbuf_pkts > ci_tcp_sendq_n_pkts(ts) ) &&
      ( (int) (ts->s.so.sndbuf - bytes_enqueued) >
        (int) (bytes_enqueued >> 1u) );
  }
}

/* Returns the number of additional packet buffers that this socket is
 * permitted to queue on its send queue.
 */
ci_inline int ci_tcp_tx_send_space(ci_netif* ni, ci_tcp_state* ts)
{
  if( NI_OPTS(ni).tcp_sndbuf_mode ) {
    return ts->so_sndbuf_pkts -
        (ci_tcp_sendq_n_pkts(ts)
#if CI_CFG_TIMESTAMPING
         + ci_udp_recv_q_pkts(&ts->timestamp_q)
#endif
         + ts->retrans.num);
  }
  else
    return ts->so_sndbuf_pkts - ci_tcp_sendq_n_pkts(ts);
}


/* helpers for RTT sampling without TS option */
ci_inline void ci_tcp_clear_rtt_timing(ci_tcp_state* ts) {
  ts->timed_seq = tcp_snd_una(ts) - 1;
}

ci_inline void ci_tcp_set_rtt_timing(ci_netif* netif,
                                     ci_tcp_state* ts, int seq) {
  ts->timed_seq = seq;
  ts->timed_ts = ci_tcp_time_now(netif);
}


ci_inline void ci_tcp_tx_pkt_set_end(ci_tcp_state* ts, ci_ip_pkt_fmt* pkt) {
  uint8_t* end = (uint8_t*) oo_tx_l3_hdr(pkt) + ts->outgoing_hdrs_len +
                 tcp_eff_mss(ts);
  ci_assert_nflags(pkt->flags, CI_PKT_FLAG_INDIRECT);
  oo_offbuf_set_end(&(pkt->buf), end);
}


/* Sets up the offbuf end pointer correctly for a zero-copy
 * (CI_PKT_FLAG_INDIRECT) packet, prior to populating the ci_pkt_zc_header.
 * See the diagram above ci_pkt_zc_header. This function may only be called
 * immediately after converting a packet to zc (or creating a new packet);
 * doing it again later may change where the zc_header appears to be located
 * and corrupt the packet. */
ci_inline void ci_tcp_tx_pkt_set_zc_header_pos(ci_tcp_state* ts,
                                               ci_ip_pkt_fmt* pkt) {
  char* end = CI_PTR_ALIGN_FWD((char*)oo_tx_l3_hdr(pkt) +
                               sizeof(ci_tcp_hdr) + CI_TCP_MAX_OPTS_LEN,
                               CI_PKT_ZC_PAYLOAD_ALIGN);
  ci_assert_flags(pkt->flags, CI_PKT_FLAG_INDIRECT);
  oo_offbuf_set_end(&(pkt->buf), end);
  pkt->buf.end = CI_MAX(pkt->buf.off, pkt->buf.end);
}


ci_inline int ci_tcp_listenq_max(ci_netif* ni)
{ return NI_OPTS(ni).tcp_backlog_max; }

ci_inline unsigned ci_ipx_tcp_checksum(int af, const ci_ipx_hdr_t* ipx,
                                       const ci_tcp_hdr* tcp, void* payload)
{
#if CI_CFG_IPV6
  if( af == AF_INET6 )
  {
    return ci_ip6_tcp_checksum(&ipx->ip6, tcp, payload);
  }
  else
#endif
  {
    return ci_tcp_checksum(&ipx->ip4, tcp, payload);
  }
}

ci_inline unsigned ci_ipx_udp_checksum(int af, const ci_ipx_hdr_t* ipx,
                                       const ci_udp_hdr* udp, void* payload)
{
  ci_iovec iov = {.iov_base = payload};
#if CI_CFG_IPV6
  if( af == AF_INET6 )
  {
    iov.iov_len = CI_BSWAP_BE16(ipx->ip6.payload_len) - sizeof(ci_udp_hdr);
    return ci_ip6_udp_checksum(&ipx->ip6, udp, &iov, 1);
  }
  else
#endif
  {
    iov.iov_len = CI_BSWAP_BE16(ipx->ip4.ip_tot_len_be16) -
        CI_IP4_IHL(&ipx->ip4) - sizeof(ci_udp_hdr);
    return ci_udp_checksum(&ipx->ip4, udp, &iov, 1);
  }
}

/**********************************************************************
************************** Per-socket locks ***************************
**********************************************************************/

ci_inline int ci_sock_trylock(ci_netif* ni, citp_waitable* w)
{
  ci_uint32 l = w->lock.wl_val;
  return ! (l & OO_WAITABLE_LK_LOCKED) &&
    ci_cas32u_succeed(&w->lock.wl_val, l, l | OO_WAITABLE_LK_LOCKED);
}

/* Always returns 0 (success) at userland.  Returns -ERESTARTSYS if
 * interrupted when invoked in kernel.  (TODO: Check that is right --
 * possibly EINTR?).  Return value *must* be checked when invoked in
 * kernel, else risk of proceeding without the lock held.
 */
ci_inline int ci_sock_lock(ci_netif*, citp_waitable*)
  OO_MUST_CHECK_RET_IN_KERNEL;
ci_inline int ci_sock_lock(ci_netif* ni, citp_waitable* w)
{
  if(CI_LIKELY( ci_cas32u_succeed(&w->lock.wl_val, 0, OO_WAITABLE_LK_LOCKED) ))
    return 0;
#ifdef __KERNEL__
  return ci_sock_lock_slow(ni, w);
#else
  /* Ensure the compiler knows we're returning zero, so it can optimise out
   * any code conditional on the return value.
   */
  (void) ci_sock_lock_slow(ni, w);
  return 0;
#endif
}

ci_inline void ci_sock_unlock(ci_netif* ni, citp_waitable* w)
{
  if(CI_UNLIKELY( ci_cas32u_fail(&w->lock.wl_val, OO_WAITABLE_LK_LOCKED, 0) ))
    ci_sock_unlock_slow(ni, w);
}

ci_inline int  ci_sock_is_locked(ci_netif* ni, citp_waitable* w)
{
  return w->lock.wl_val & OO_WAITABLE_LK_LOCKED;
}


/*********************************************************************
************************** TCP accept queue **************************
*********************************************************************/

/* Use this if you don't own the [get] lock. */
#define ci_tcp_acceptq_n(tls)			\
  ((tls)->acceptq_n_in - (tls)->acceptq_n_out)

/* Use this if you do own the [get] lock. */
#define ci_tcp_acceptq_not_empty(tls)                                   \
  (((tls)->acceptq_put >= 0) | OO_SP_NOT_NULL((tls)->acceptq_get))


ci_inline void ci_tcp_acceptq_put(ci_netif* ni,
                                  ci_tcp_socket_listen* tls,
				  citp_waitable* w) {
  ci_assert(OO_SP_IS_NULL(w->wt_next));
  ci_assert(ci_netif_is_locked(ni));
  do
    w->wt_next = OO_SP_FROM_INT(ni, tls->acceptq_put);
  while( ci_cas32_fail(&tls->acceptq_put,
                       OO_SP_TO_INT(w->wt_next), W_ID(w)) );
  ++tls->acceptq_n_in;
}


ci_inline void ci_tcp_acceptq_put_back_tail(ci_netif* ni,
                                  ci_tcp_socket_listen* tls,
				  citp_waitable* w) {
  ci_assert(OO_SP_IS_NULL(w->wt_next));
  ci_assert(ci_sock_is_locked(ni, &tls->s.b));
  ci_assert(w->sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ);
  do
    w->wt_next = OO_SP_FROM_INT(ni, tls->acceptq_put);
  while( ci_cas32_fail(&tls->acceptq_put,
                       OO_SP_TO_INT(w->wt_next), W_ID(w)) );
  --tls->acceptq_n_out;
}


/* Should not be called directly, use ci_tcp_acceptq_get() and
 * ci_tcp_acceptq_peek(). */
ci_inline void ci_tcp_acceptq_get_swizzle(ci_netif* ni,
					  ci_tcp_socket_listen* tls) {
  ci_int32 from;
  oo_sp from_sp;
  ci_tcp_state* ts;
  /* Atomically grab the contents of the [put] list. */
  do
    from = tls->acceptq_put;
  while( ci_cas32_fail(&tls->acceptq_put, from, CI_ILL_END) );
  /* Reverse the list onto [get]. */
  ci_assert(from >= 0);
  ci_assert(OO_SP_IS_NULL(tls->acceptq_get));
  from_sp = OO_SP_FROM_INT(ni, from);
  do {
    ts = SP_TO_TCP(ni, from_sp);
    from_sp = ts->s.b.wt_next;
    ts->s.b.wt_next = tls->acceptq_get;
    tls->acceptq_get = S_SP(ts);
  } while( OO_SP_NOT_NULL(from_sp) );
}


/* Only call this if ci_tcp_acceptq_not_empty() is true. */
ci_inline citp_waitable* ci_tcp_acceptq_get(ci_netif* ni,
					   ci_tcp_socket_listen* tls) {
  citp_waitable* w;
  ci_assert(ci_sock_is_locked(ni, &tls->s.b) ||
            (tls->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
  ++tls->acceptq_n_out;
  if( OO_SP_IS_NULL(tls->acceptq_get) )  ci_tcp_acceptq_get_swizzle(ni, tls);
  ci_assert(OO_SP_NOT_NULL(tls->acceptq_get));
  w = SP_TO_WAITABLE(ni, tls->acceptq_get);
  tls->acceptq_get = w->wt_next;
  CI_DEBUG(w->wt_next = OO_SP_NULL);
  return w;
}


#ifndef __ci_driver__
/* Only call this if ci_tcp_acceptq_not_empty() is true. */
ci_inline ci_tcp_state* ci_tcp_acceptq_peek(ci_netif* ni,
					    ci_tcp_socket_listen* tls) {
  ci_assert(ci_sock_is_locked(ni, &tls->s.b));
  if( OO_SP_IS_NULL(tls->acceptq_get) )  ci_tcp_acceptq_get_swizzle(ni, tls);
  ci_assert(OO_SP_NOT_NULL(tls->acceptq_get));
  return SP_TO_TCP(ni, tls->acceptq_get);
}
#endif


/* Must hold the sock lock. */
ci_inline void ci_tcp_acceptq_put_back(ci_netif* ni, ci_tcp_socket_listen* tls,
                                       citp_waitable* w) {
  ci_assert(ci_sock_is_locked(ni, &tls->s.b));
  ci_assert(w->sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ);
  --tls->acceptq_n_out;
  w->wt_next = tls->acceptq_get;
  tls->acceptq_get = W_SP(w);
}


/*********************************************************************
******************************** Netif *******************************
*********************************************************************/

static inline const char* ci_tcp_aux_type2str(int type)
{
  switch(type) {
    case CI_TCP_AUX_TYPE_SYNRECV: return "syn-recv state";
    case CI_TCP_AUX_TYPE_BUCKET:  return "syn-recv bucket";
    case CI_TCP_AUX_TYPE_EPOLL: return "epoll3 state";
    default: return "unknown";
  }
}

/* Does exactly what it says on the tin! */
ci_inline ci_ni_aux_mem* ci_ni_aux_p2aux(ci_netif* ni, oo_p p)
{
  ci_assert( OO_P_NOT_NULL(p) );
  return (void*)CI_NETIF_PTR(ni, p);
}
ci_inline ci_tcp_state_synrecv* ci_ni_aux_p2synrecv(ci_netif* ni, oo_p oop)
{
  ci_ni_aux_mem* aux = ci_ni_aux_p2aux(ni, oop);
  ci_assert_equal(aux->type, CI_TCP_AUX_TYPE_SYNRECV);
  return &aux->u.synrecv;
}
ci_inline ci_tcp_listen_bucket* ci_ni_aux_p2bucket(ci_netif* ni, oo_p oop)
{
  ci_ni_aux_mem* aux = ci_ni_aux_p2aux(ni, oop);
  ci_assert_equal(aux->type, CI_TCP_AUX_TYPE_BUCKET);
  return &aux->u.bucket;
}
ci_inline ci_sb_epoll_state* ci_ni_aux_p2epoll(ci_netif* ni, oo_p oop)
{
  ci_ni_aux_mem* aux = ci_ni_aux_p2aux(ni, oop);
  ci_assert_equal(aux->type, CI_TCP_AUX_TYPE_EPOLL);
  return &aux->u.epoll;
}
ci_inline ci_pmtu_state_t* ci_ni_aux_p2pmtus(ci_netif* ni, oo_p oop)
{
  ci_ni_aux_mem* aux = ci_ni_aux_p2aux(ni, oop);
  ci_assert_equal(aux->type, CI_TCP_AUX_TYPE_PMTUS);
  return &aux->u.pmtus;
}

ci_inline oo_p ci_ni_aux2p(ci_netif* ni, ci_ni_aux_mem* aux)
{
  CI_BUILD_ASSERT(CI_IS_POW2(CI_CFG_EP_BUF_SIZE));
  ci_uintptr_t ep_buf_mask = CI_CFG_EP_BUF_SIZE - 1;
  citp_waitable* w = (void *)((ci_uintptr_t)aux &~ ep_buf_mask);
  oo_p sp = oo_sockp_to_statep(ni, W_SP(w));
  OO_P_ADD(sp, (ci_uintptr_t)aux & ep_buf_mask);
  return sp;
}

ci_inline void ci_ni_aux_free(ci_netif* ni, ci_ni_aux_mem* aux)
{
  oo_p sp = ci_ni_aux2p(ni, aux);

  ci_assert( ci_netif_is_locked(ni) );
  ni->state->n_aux_bufs[aux->type]--;
  aux->link.next = ni->state->free_aux_mem;
  ni->state->free_aux_mem = sp;
  ni->state->n_free_aux_bufs++;
}
ci_inline void ci_tcp_synrecv_free(ci_netif* ni, ci_tcp_state_synrecv* tsr) {
  ci_ni_aux_free(ni, CI_CONTAINER(ci_ni_aux_mem, u.synrecv, tsr));
}
ci_inline void ci_sb_epoll_free(ci_netif* ni, ci_sb_epoll_state* epoll) {
  ci_ni_aux_free(ni, CI_CONTAINER(ci_ni_aux_mem, u.epoll, epoll));
}
ci_inline void ci_pmtu_state_free(ci_netif* ni, ci_pmtu_state_t* pmtus) {
  ci_ni_aux_free(ni, CI_CONTAINER(ci_ni_aux_mem, u.pmtus, pmtus));
}

extern void ci_ni_aux_more_bufs(ci_netif* ni);
ci_inline int/*bool*/ ci_ni_aux_can_alloc(ci_netif* ni, int type)
{
  if( ni->state->n_aux_bufs[type] >= ni->state->max_aux_bufs[type] )
    return CI_FALSE;
  if( ! OO_P_IS_NULL(ni->state->free_aux_mem) )
    return CI_TRUE;
  ci_ni_aux_more_bufs(ni);
  return ! OO_P_IS_NULL(ni->state->free_aux_mem);
}
ci_inline oo_p ci_ni_aux_alloc(ci_netif* ni, int type)
{
  ci_ni_aux_mem* aux;
  oo_p ret;

  ci_assert( ci_netif_is_locked(ni) );
  if( !ci_ni_aux_can_alloc(ni, type) ) {
    CITP_STATS_NETIF(++ni->state->stats.aux_alloc_fails);
    return OO_P_NULL;
  }
  ret = ni->state->free_aux_mem;
  ci_assert( OO_P_NOT_NULL(ret) );
  aux = ci_ni_aux_p2aux(ni, ret);
  aux->type = type;
  ni->state->free_aux_mem = aux->link.next;
  ni->state->n_free_aux_bufs--;
  ni->state->n_aux_bufs[type]++;
  return ret;
}

ci_inline oo_p ci_ni_aux_alloc_bucket(ci_netif* ni)
{
  ci_tcp_listen_bucket* bucket;
  oo_p ret = ci_ni_aux_alloc(ni, CI_TCP_AUX_TYPE_BUCKET);
  int i;

  if( OO_P_IS_NULL(ret) ) {
    CITP_STATS_NETIF(++ni->state->stats.aux_bucket_alloc_fails);
    return ret;
  }
  bucket = ci_ni_aux_p2bucket(ni, ret);
  for( i = 0; i < CI_TCP_LISTEN_BUCKET_SIZE; i++ )
    bucket->bucket[i] = OO_P_NULL;
  return ret;
}

ci_inline oo_p ci_tcp_synrecv2p(ci_netif* ni, ci_tcp_state_synrecv* tsr)
{
  return ci_ni_aux2p(ni, CI_CONTAINER(ci_ni_aux_mem, u.synrecv, tsr));
}
ci_inline ci_ni_dllist_link* ci_tcp_synrecv2link(ci_tcp_state_synrecv* tsr) {
  return &CI_CONTAINER(ci_ni_aux_mem, u.synrecv, tsr)->link;
}
ci_inline ci_tcp_state_synrecv* ci_tcp_link2synrecv(ci_ni_dllist_link* link) {
  return &CI_CONTAINER(ci_ni_aux_mem, link, link)->u.synrecv;
}

/* finc current Path MTU */
ci_inline unsigned ci_tcp_get_pmtu(ci_netif* netif, ci_tcp_state* ts)
{
  unsigned x;

  ci_assert(ts->s.b.state != CI_TCP_LISTEN);

  x = ts->s.pkt.mtu;
  if( OO_PP_NOT_NULL(ts->pmtus) ) {
    ci_pmtu_state_t* pmtus = ci_ni_aux_p2pmtus(netif, ts->pmtus);
    return CI_MIN(x, pmtus->pmtu);
  }
  return x;
}

/* find effective MSS value based on smss, PMTU and MTU and optional user
 * value */
ci_inline void ci_tcp_set_eff_mss(ci_netif* netif, ci_tcp_state* ts) {
  unsigned x;
#if CI_CFG_IPV6
  int af = ipcache_af(&ts->s.pkt);
#endif

  ci_assert(ts->s.b.state != CI_TCP_LISTEN);

  x = ci_tcp_get_pmtu(netif, ts) - sizeof(ci_tcp_hdr) - CI_IPX_HDR_SIZE(af);

  x = CI_MIN(x, ts->smss);
  ts->eff_mss = CI_MAX(x, CI_CFG_TCP_MINIMUM_MSS) -
                tcp_ipx_outgoing_opts_len(af, ts);

  /* Increase ssthresh & cwndif eff_mss has increased */
  ts->ssthresh = CI_MAX(ts->ssthresh, (ci_uint32) ts->eff_mss << 1u);
  if( ts->cwnd < ts->eff_mss )
    ci_tcp_set_initialcwnd(netif, ts);

  ci_tcp_set_sndbuf(netif, ts);
}


#define CI_READY_LIST_EACH(bitmask, tmp, i)            \
  ci_assert_lt((bitmask), 1u << CI_CFG_N_READY_LISTS); \
  OO_FOR_EACH_BIT(bitmask, tmp, i)

ci_inline void
ci_netif_put_on_post_poll_epoll(ci_netif* ni, citp_waitable* sb)
{
#if CI_CFG_EPOLL3
  ci_sb_epoll_state* epoll = ci_ni_aux_p2epoll(ni, sb->epoll);
  ci_uint32 tmp, i;
  CI_READY_LIST_EACH(sb->ready_lists_in_use, tmp, i) {
    ci_ni_dllist_remove(ni, &epoll->e[i].ready_link);
    ci_ni_dllist_put(ni, &ni->state->ready_lists[i], &epoll->e[i].ready_link);
  }
#endif
}

ci_inline void
citp_waitable_remove_from_epoll(ci_netif* ni, citp_waitable* w, int do_free)
{
  ci_sb_epoll_state* epoll;
  ci_uint32 tmp, i;

  ci_assert(ci_netif_is_locked(ni));
  if( OO_PP_IS_NULL(w->epoll) ) {
    ci_assert_equal(w->ready_lists_in_use, 0);
    return;
  }

  epoll = ci_ni_aux_p2epoll(ni, w->epoll);
  ci_assert_equal(epoll->sock_id, w->bufid);
  CI_READY_LIST_EACH(w->ready_lists_in_use, tmp, i)
    ci_ni_dllist_remove_safe(ni, &epoll->e[i].ready_link);
  w->ready_lists_in_use = 0;
  if( do_free ) {
    ci_ni_aux_free(ni, CI_CONTAINER(ci_ni_aux_mem, u.epoll, epoll));
    w->epoll = OO_PP_NULL;
  }
}

ci_inline void ci_netif_put_on_post_poll(ci_netif* ni, citp_waitable* sb)
{
  ci_ni_dllist_remove(ni, &sb->post_poll_link);
  ci_ni_dllist_put(ni, &ni->state->post_poll_list, &sb->post_poll_link);
#if CI_CFG_EPOLL3
  if( sb->ready_lists_in_use != 0 )
    ci_netif_put_on_post_poll_epoll(ni, sb);
#endif
}


ci_inline void ci_netif_poll_free_pkts(ci_netif* ni,
                                       struct ci_netif_poll_state* ps)
{
  ci_ip_pkt_fmt* tail = CI_CONTAINER(ci_ip_pkt_fmt, next,
                                     ps->tx_pkt_free_list_insert);
  ci_netif_pkt_free_nonb_list(ni, ps->tx_pkt_free_list, tail);
  ni->state->n_async_pkts += ps->tx_pkt_free_list_n;
  CITP_STATS_NETIF_ADD(ni, pkt_nonb, ps->tx_pkt_free_list_n);
}


ci_inline int citp_shutdown_how_is_valid(int how)
{
  switch( how ) {
    case SHUT_RD:
    case SHUT_WR:
    case SHUT_RDWR:
      return CI_TRUE;
    default:
      return CI_FALSE;
  }
}

/**********************************************************************
********************************* PMTU ********************************
**********************************************************************/

/*! Manage the discovery timer.  If the time is CI_PMTU_STOP_TIMER then 
 * the timer will be  killed. If the timer is pending it will be modified
 *  otherwise it will be set */
ci_inline void ci_pmtu_discover_timer(ci_netif* ni,  ci_pmtu_state_t* pmtus, 
                                      ci_iptime_t timeout) {
  ci_ip_timer_clear(ni, &pmtus->tid );
  if( timeout != CI_PMTU_STOP_TIMER )
    ci_ip_timer_set(ni, &pmtus->tid, ci_tcp_time_now(ni) + timeout);
}



/*********************************************************************
************************* IPv4/IPv6 address helpers ******************
*********************************************************************/

union ci_sockaddr_u {
  struct sockaddr sa;
  struct sockaddr_in sin;
#if CI_CFG_FAKE_IPV6
  struct sockaddr_in6 sin6;
#endif
};

#if CI_CFG_FAKE_IPV6
/*!
 * Test it this IPv6 address may be considered as IPv4 one.
 * This function DOES NOT check sa->family, because it is used in bind(),
 * and Linux bind() should not check address family.
 */
ci_inline int ci_tcp_ipv6_is_ipv4(const struct sockaddr* sa)
{
  if (CI_IP6_IS_V4MAPPED(&CI_SIN6(sa)->sin6_addr) || 
      CI_IP6_IS_ADDR_ANY(&CI_SIN6(sa)->sin6_addr)) {
    return 1;
  }
  return 0;
}
#endif


/* Get IPv4 address from IPv4 or IPv6 address structure */
ci_inline ci_uint32 ci_get_ip4_addr(int family, const struct sockaddr* sa)
{
#if CI_CFG_FAKE_IPV6
  ci_assert(family == AF_INET || family == AF_INET6);
#else
  ci_assert(family == AF_INET);
#endif

#if CI_CFG_FAKE_IPV6
  if (family == AF_INET)
    return CI_SIN(sa)->sin_addr.s_addr;
  else { /* IPv6 */
    ci_assert(ci_tcp_ipv6_is_ipv4(sa));
    return ((ci_uint32 *)(&CI_SIN6(sa)->sin6_addr))[3];
  }
#else
  return CI_SIN(sa)->sin_addr.s_addr;
#endif
}

#if CI_CFG_IPV6
ci_inline int ci_tcp_ipv6_is_addr_any(const struct sockaddr* sa)
{
  return CI_IP6_IS_ADDR_ANY(&CI_SIN6(sa)->sin6_addr) ? 1 : 0;
}

ci_inline int ci_sock_maybe_ipv6(ci_sock_cmn* s, const struct sockaddr* addr)
{
  if(s->domain == PF_INET6 && (!ci_tcp_ipv6_is_ipv4(addr) ||
      ci_tcp_ipv6_is_addr_any(addr)))
    return 1;
  return 0;
}
#endif

ci_inline ci_addr_t ci_get_addr(const struct sockaddr* sa)
{
  ci_addr_t addr;

  ci_assert(sa->sa_family == AF_INET || sa->sa_family == AF_INET6);

  if( sa->sa_family == AF_INET6 ) {
#if CI_CFG_IPV6
    memcpy(addr.ip6, &CI_SIN6(sa)->sin6_addr, sizeof(addr.ip6));
#else
    ci_assert(ci_tcp_ipv6_is_ipv4(sa));
    addr.ip4 = ((unsigned*)(&CI_SIN6(sa)->sin6_addr))[3];
#endif
  }
  else {
    addr = CI_ADDR_FROM_IP4(CI_SIN(sa)->sin_addr.s_addr);
  }
  return addr;
}


ci_inline ci_uint16 ci_get_port(const struct sockaddr* sa)
{
  if( sa->sa_family == AF_INET6 )
    return CI_SIN6(sa)->sin6_port;
  return CI_SIN(sa)->sin_port;
}

/* Functions to make a sockaddr structure from a given port/ip: */
/* Get an IPv4 address addr_be32 and fill it into sockaddr_in. */
ci_inline void
ci_make_sockaddr_from_ip4(struct sockaddr_in *sin,
                          ci_uint16 port_be16, ci_uint32 addr_be32)
{
  sin->sin_family = AF_INET;
  sin->sin_port = port_be16;
  sin->sin_addr.s_addr = addr_be32;
}

#if CI_CFG_FAKE_IPV6
/* Get an IPv4 address addr_be32 and fill an mapped address
 * into sockaddr_in6. */
ci_inline void
ci_make_sockaddr_in6_from_ip4(struct sockaddr_in6 *sin,
                              ci_uint16 port_be16, ci_uint32 addr_be32)
{
  sin->sin6_family = AF_INET6;
  sin->sin6_port = port_be16;
  CI_IP_TO_IP6_MAPPED(&sin->sin6_addr, addr_be32);
}
/* Get an IPv6 address pointed by addr_be32_p and fill it
 * into sockaddr_in6. */
ci_inline void
ci_make_sockaddr_in6_from_ip6(struct sockaddr_in6 *sin, ci_uint16 port_be16,
                              const ci_uint32* addr_be32_p)
{
  sin->sin6_family = AF_INET6;
  sin->sin6_port = port_be16;
  memcpy(&sin->sin6_addr, addr_be32_p, sizeof(sin->sin6_addr));
}
#endif

ci_inline struct sockaddr_storage
ci_make_sockaddr_storage_from_addr(ci_uint16 port_be16, ci_addr_t addr)
{
  union {
    struct sockaddr_in in;
#if CI_CFG_IPV6
    struct sockaddr_in6 in6;
#endif
    struct sockaddr_storage ss;
  } u;

  memset(&u, 0, sizeof(u));
#if CI_CFG_IPV6
  if( CI_IS_ADDR_IP6(addr) ) {
    u.in6.sin6_family = AF_INET6;
    u.in6.sin6_port = port_be16;
    memcpy(&u.in6.sin6_addr.s6_addr, addr.ip6, sizeof(addr.ip6));
  }
  else
#endif
  {
    u.in.sin_family = AF_INET;
    u.in.sin_port = port_be16;
    u.in.sin_addr.s_addr = addr.ip4;
  }

  return u.ss;
}

/* Minimum IPv6 address size. It may be included from <net/ipv6.h> */
#define SIN6_LEN_RFC2133 24

/* Copy sockaddr structure to user-supplied pointer and update its length.
 * - domain_in defines the kind of addr_be32_p address;
 * - domain_out defines the type for the resulting sockaddr structure;
 * - addr_be32_p is the pointer to IPv4 or IPv6 address, depending on
 *   domain_in parameter;
 * - scope_id defines sin6_scope_id value for IPv6 link-local addresses. */
ci_inline void
ci_addr_to_user(struct sockaddr *sa, socklen_t *sa_len,
                sa_family_t domain_in, sa_family_t domain_out,
                ci_uint16 port_be16, const ci_uint32* addr_be32_p,
                ci_ifid_t scope_id)
{
  socklen_t len = sizeof(struct sockaddr_in);

#if CI_CFG_FAKE_IPV6
  ci_assert(domain_in == AF_INET || domain_in == AF_INET6);
  ci_assert(domain_out == AF_INET || domain_out == AF_INET6);

  if (domain_out == AF_INET6)
    /* One might expect to see SIN6_LEN_RFC2133 here, but Linux uses
     * sizeof() instead. */
    len = sizeof(struct sockaddr_in6);
  else
    ci_assert_equal(domain_in, AF_INET);
#else 
  ci_assert_equal(domain_in, AF_INET);
  ci_assert_equal(domain_out, AF_INET);
#endif

  if (CI_LIKELY(*sa_len >= len)) {
    *sa_len = CI_MIN(*sa_len, len);
    memset(sa, 0, *sa_len);
#if CI_CFG_FAKE_IPV6
    if (domain_out == AF_INET) {
      ci_make_sockaddr_from_ip4(CI_SIN(sa), port_be16, *addr_be32_p);
    }
    else if( domain_in == AF_INET ) {
      ci_make_sockaddr_in6_from_ip4(CI_SIN6(sa), port_be16, *addr_be32_p);
    }
    else {
      ci_make_sockaddr_in6_from_ip6(CI_SIN6(sa), port_be16, addr_be32_p);
      if( CI_IP6_IS_LINKLOCAL(&CI_SIN6(sa)->sin6_addr) )
        CI_SIN6(sa)->sin6_scope_id = scope_id;
    }
#else
    ci_make_sockaddr_from_ip4(CI_SIN(sa), port_be16, *addr_be32_p);
#endif
  } 
  else {
    union ci_sockaddr_u ss_u;

    if (*sa_len == 0) {
      *sa_len = len;
      return;
    }

    memset(&ss_u, 0, len);
#if CI_CFG_FAKE_IPV6
    if (domain_out == AF_INET)
      ci_make_sockaddr_from_ip4(&ss_u.sin, port_be16, *addr_be32_p);
    else if( domain_in == AF_INET )
      ci_make_sockaddr_in6_from_ip4(&ss_u.sin6, port_be16, *addr_be32_p);
    else
      ci_make_sockaddr_in6_from_ip6(&ss_u.sin6, port_be16, addr_be32_p);
#else
    ci_make_sockaddr_from_ip4(&ss_u.sin, port_be16, *addr_be32_p);
#endif

    memcpy(sa, &ss_u.sa, *sa_len);
    *sa_len = len;
  }
}

#if CI_CFG_IPV6
/* Sets socket interface index derived from sockaddr struct for link-local
 * address bind()/connect(). Returns -1 if an interface is not acceleratable.
 * - addr       [in] is an address obtained via bind()/connect() parameter;
 * - addrlen    [in] specifies the size of addr;
 * - at_connect [in] set to 1 means function call on connect(),
 *                   0 means - on bind().
 * Returns 0 on success or -1 on failure. */
ci_inline int
ci_sock_set_ip6_scope_id(ci_netif* ni, ci_sock_cmn* s,
                         const struct sockaddr* addr, socklen_t addrlen,
                         int/*bool*/ at_connect)
{
  const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)addr;
  if( addrlen >= sizeof(struct sockaddr_in6) && sin6->sin6_scope_id ) {
    ci_ifid_t ifindex = sin6->sin6_scope_id;
    cicp_hwport_mask_t hwports = 0;
    int rc;
    /* If interface is set while binding, indices must coincide */
    if( at_connect && s->cp.so_bindtodevice &&
        s->cp.so_bindtodevice != ifindex )
      return -1;
    rc = oo_cp_find_llap(ni->cplane, ifindex, NULL, NULL, &hwports, NULL, NULL);
    if( rc != 0 || hwports == 0 )
      return -1;
    s->cp.so_bindtodevice = ifindex;
  }
  /* Bind/connect to link-local address requires an interface */
  if( ! s->cp.so_bindtodevice )
    return -1;
  return 0;
}
#endif

extern ci_ifid_t ci_rx_pkt_ifindex(ci_netif* ni, const ci_ip_pkt_fmt* pkt);


/*********************************************************************
 * ci_tcp_recvmsg()
 */

ci_inline void ci_tcp_recvmsg_args_init(ci_tcp_recvmsg_args* a,
                                     ci_netif* ni, ci_tcp_state* ts,
                                     ci_msghdr* msg, int flags) {
  a->ni = ni;
  a->ts = ts;
  a->msg = msg;
  a->flags = flags;
}




/*********************************************************************
***************************** Tcpdump support ************************
*********************************************************************/
#if CI_CFG_TCPDUMP
/** Current length of dump queue. */
ci_inline ci_uint16 oo_tcpdump_queue_len(ci_netif* ni)
{
  return ni->state->dump_write_i - ni->state->dump_read_i;
}

/* Should we dump this packet? */
ci_inline int oo_tcpdump_check(ci_netif *ni, ci_ip_pkt_fmt *pkt, int intf_i)
{
  if( ni->state->dump_intf[intf_i] == OO_INTF_I_DUMP_ALL ) {
    if( oo_tcpdump_queue_len(ni) < CI_CFG_DUMPQUEUE_LEN - 1 )
      return 1;
    else
      CITP_STATS_NETIF_INC(ni, tcpdump_missed);
  }
  return 0;
}

/* Should we dump this no_match */
ci_inline int oo_tcpdump_check_no_match(ci_netif *ni, ci_ip_pkt_fmt *pkt,
                                        int intf_i)
{
  if( ni->state->dump_intf[intf_i] == OO_INTF_I_DUMP_NO_MATCH ) {
    if( oo_tcpdump_queue_len(ni) < CI_CFG_DUMPQUEUE_LEN - 1 )
      return 1;
    else
      CITP_STATS_NETIF_INC(ni, tcpdump_missed);
  }
  return 0;
}

/* Release all the packets up to dump_read_i */
extern void oo_tcpdump_free_pkts(ci_netif* ni, ci_uint16 i);

/* Dump this packet */
ci_inline void oo_tcpdump_dump_pkt(ci_netif *ni, ci_ip_pkt_fmt *pkt)
{
  ci_uint16 write_i = ni->state->dump_write_i;
  oo_pkt_p* dq = ni->state->dump_queue;

  if(CI_UNLIKELY( pkt->flags & CI_PKT_FLAG_MSG_WARM ))
    return;

  if( dq[write_i % CI_CFG_DUMPQUEUE_LEN] != OO_PP_NULL )
    oo_tcpdump_free_pkts(ni, write_i);

  ci_assert_equal(dq[write_i % CI_CFG_DUMPQUEUE_LEN], OO_PP_NULL);
  ci_netif_pkt_hold(ni, pkt);
  dq[write_i % CI_CFG_DUMPQUEUE_LEN] = OO_PKT_P(pkt);
  ci_wmb();
  ni->state->dump_write_i = write_i + 1;
}
#else
#define oo_tcpdump_check(ni, pkt, intf_i) 0
#define oo_tcpdump_dump_pkt(ni, pkt)
#endif


#ifdef __KERNEL__
/*********************************************************************
**************************** OS socket status ************************
*********************************************************************/

/* _bit_set() always increment seqno, even if the bit is already set */
ci_inline void
oo_os_sock_status_bit_set(ci_sock_cmn *s, ci_int32 bits)
{
  ci_uint32 tmp;
  do {
    tmp = s->os_sock_status;
  } while( ci_cas32u_fail(&s->os_sock_status, tmp,
                          (tmp + (1 << OO_OS_STATUS_SEQ_SHIFT)) | bits) );
}

ci_inline ci_uint32 oo_os_sock_status_from_mask(int mask)
{
  ci_uint32 os_sock_status = 0;
  if( mask & POLLIN )
    os_sock_status |= OO_OS_STATUS_RX;
  if( mask & POLLOUT )
    os_sock_status |= OO_OS_STATUS_TX;
  if( mask & POLLERR )
    os_sock_status |= OO_OS_STATUS_ERR;
  return os_sock_status;
}

#endif


/* oo_cycles64_to_usec & oo_usec_to_cycles64 are not performance-critical,
 * but should be implemented carefully.
 * - do not convert non-zero value to zero;
 * - do not use 64-bit division in 32-bit Linux kernel;
 * - do now wrap on big values.
 */

#ifdef __KERNEL__
#define KERNEL_CAST_TO_UNSIGNED_LONG(v) ((unsigned long)(v))
#else
#define KERNEL_CAST_TO_UNSIGNED_LONG(v) (v)
#endif

ci_inline unsigned oo_cycles64_to_usec(ci_netif* ni, ci_uint64 cycles)
{
  unsigned val;
  ci_uint64 c;

  if( cycles > (((ci_uint64) -1) >> 10) )
    return (unsigned) -1;
  if( cycles == 0 )
    return 0;
  c = cycles * 1000;
#ifdef __KERNEL__
  /* 32-bit kernel can't divide 64-bit value */
  if( (unsigned long)c != cycles )
    val = cycles >> IPTIMER_STATE(ni)->ci_ip_time_frc2us;
  else
#endif
    val = KERNEL_CAST_TO_UNSIGNED_LONG(c) / IPTIMER_STATE(ni)->khz;
  return val == 0 ? 1 : val;
}


ci_inline ci_uint64 __oo_usec_to_cycles64(ci_uint32 khz, unsigned usec)
{
  ci_uint64 val;

  if( usec == (unsigned) -1 )
    return (ci_uint64) -1;
  if( usec == 0 )
    return 0;
  val = (ci_uint64)usec * khz;
#ifdef __KERNEL__
  /* 32-bit kernel can't divide 64-bit value */
  if( (ci_uint64)(unsigned long)val != val )
     val = val << 10;
  else
#endif
    val = KERNEL_CAST_TO_UNSIGNED_LONG(val) / 1000;
  return val == 0 ? 1 : val;
}
#undef KERNEL_CAST_TO_UNSIGNED_LONG
#define oo_usec_to_cycles64(ni, usec) \
    __oo_usec_to_cycles64(IPTIMER_STATE(ni)->khz, usec)


/**********************************************************************
 * Zero-copy API helpers
 */

struct oo_zc_buf;
typedef struct oo_zc_buf* onload_zc_handle;

/* onload_zc_handle can point to either memory owned by Onload (a
 * ci_ip_pkt_fmt) or memory owned by the app (a ci_zc_usermem). We use the
 * least significant bit of the pointer to disambiguate, so here's a bunch
 * of functions to convert back and forth. Note also that
 * ONLOAD_ZC_HANDLE_NONZC is a valid value. */

#ifdef __x86_64__
/* Solely in debugging builds, we put some magic stuff in the top bits of
 * onload_zc_handle instances (which are used in userspace only) so that
 * they're invalid pointers and users can't avoid calling zc_handle_to_...
 * in order to read them. If Intel ever do 6-level page tables then this
 * debugging facility will have to be removed. */
#define CI_ZC_HANDLE_MAGIC_MASK    0xff00000000000000ull
#define CI_ZC_HANDLE_MAGIC         0xab00000000000000ull
#else
#define CI_ZC_HANDLE_MAGIC_MASK    ((uintptr_t)0)
#define CI_ZC_HANDLE_MAGIC         ((uintptr_t)0)
#endif

struct ci_zc_usermem {
  ef_addrspace addr_space;
  uint64_t base;
  uint64_t size;
  uint64_t kernel_id;
  uint64_t hw_addrs[0];
};

static inline onload_zc_handle zc_pktbuf_to_handle(ci_ip_pkt_fmt* pkt)
{
  onload_zc_handle h = (onload_zc_handle)pkt;
  CI_DEBUG(h = (onload_zc_handle)((uintptr_t)h | CI_ZC_HANDLE_MAGIC));
  return h;
}

static inline onload_zc_handle zc_usermem_to_handle(struct ci_zc_usermem* um)
{
  onload_zc_handle h = (onload_zc_handle)((uintptr_t)um | 1);
  CI_DEBUG(h = (onload_zc_handle)((uintptr_t)h | CI_ZC_HANDLE_MAGIC));
  return h;
}

static inline void zc_handle_check(onload_zc_handle h)
{
  /* The surprising -2 in the below is because we use the bottom bit to
   * indicate pktbuf-or-usermem */
  ci_assert_equal((uintptr_t)h & (sizeof(void*) - 2), 0);
  ci_assert_equal((uintptr_t)h & CI_ZC_HANDLE_MAGIC_MASK, CI_ZC_HANDLE_MAGIC);
}

static inline bool zc_is_pktbuf(onload_zc_handle h)
{
  zc_handle_check(h);
  return ((uintptr_t)h & 1) == 0;
}

static inline bool zc_is_usermem(onload_zc_handle h)
{
  zc_handle_check(h);
  return ((uintptr_t)h & 1) == 1;
}

static inline ci_ip_pkt_fmt* zc_handle_to_pktbuf(onload_zc_handle h)
{
  ci_assert(zc_is_pktbuf(h));
  CI_DEBUG(h = (onload_zc_handle)((uintptr_t)h &~ CI_ZC_HANDLE_MAGIC_MASK));
  return (ci_ip_pkt_fmt*)h;
}

static inline struct ci_zc_usermem* zc_handle_to_usermem(onload_zc_handle h)
{
  ci_assert(zc_is_usermem(h));
  CI_DEBUG(h = (onload_zc_handle)((uintptr_t)h &~ CI_ZC_HANDLE_MAGIC_MASK));
  /* -1 rather than &~1 because it allows better codegen */
  return (struct ci_zc_usermem*)((uintptr_t)h - 1);
}

static inline ef_addr zc_usermem_dma_addr(struct ci_zc_usermem* um,
                                          uint64_t user_ptr, int intf_i)
{
  if( um->addr_space == EF_ADDRSPACE_LOCAL ) {
    uint64_t offset = user_ptr - um->base;
    uint64_t* hw_addrs = um->hw_addrs +
                         ((intf_i * um->size) >> EF_VI_NIC_PAGE_SHIFT);
    return hw_addrs[offset >> EF_VI_NIC_PAGE_SHIFT] |
           (offset & (EF_VI_NIC_PAGE_SIZE - 1));
  }
  else {
    return user_ptr;
  }
}

#if CI_CFG_UL_INTERRUPT_HELPER && ! defined(__KERNEL__)
extern void ci_netif_handle_actions(ci_netif* ni);
extern void ci_netif_close_pending(ci_netif* ni);
#endif

#endif  /* __CI_INTERNAL_IP_H__ */
/*! \cidoxg_end */
