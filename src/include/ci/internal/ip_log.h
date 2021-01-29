/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
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
#ifndef __CI_INTERNAL_IP_LOG_H__
#define __CI_INTERNAL_IP_LOG_H__


#define CI_TP_LOG_E	0x1		/* errors */
#define CI_TP_LOG_U	0x2		/* unexpected */
#define CI_TP_LOG_S	0x4		/* setup */
#define CI_TP_LOG_DU	0x8		/* dump unexpected packets */
#define CI_TP_LOG_TC	0x10		/* TCP control / per-connection */
#define CI_TP_LOG_TR	0x20		/* TCP receive */
#define CI_TP_LOG_TT	0x40		/* TCP transmit */
#define CI_TP_LOG_TL	0x80		/* TCP loss */
#define CI_TP_LOG_TV	0x100		/* TCP verbose */
#define CI_TP_LOG_NC	0x200		/* netif control */
#define CI_TP_LOG_NR	0x400		/* netif receive */
#define CI_TP_LOG_NT	0x800		/* netif transmit */
#define CI_TP_LOG_NV	0x1000		/* netif verbose */
#define CI_TP_LOG_DR	0x2000		/* dump received packets */
#define CI_TP_LOG_DT	0x4000		/* dump transmited packets */
#define CI_TP_LOG_EP	0x8000		/* EP caching */
#define CI_TP_LOG_AR	0x10000		/* analyse received packets */
#define CI_TP_LOG_AT	0x20000		/* analyse transmited packets */
#define CI_TP_LOG_ITV	0x40000		/* IP timer verbose */
#define CI_TP_LOG_ARP	0x80000		/* ARP */
#define CI_TP_LOG_IP	0x100000	/* IP verbose */
#define CI_TP_LOG_UC	0x200000	/* UDP control */
#define CI_TP_LOG_UR	0x400000	/* UDP receive */
#define CI_TP_LOG_UT	0x800000	/* UDP transmit */
#define CI_TP_LOG_UV	0x1000000	/* UDP verbose */
#define CI_TP_LOG_IPP	0x2000000	/* IPP (ICMP, IGMP etc) verbose */
#define CI_TP_LOG_STATS	0x4000000	/* Statistics */
#define CI_TP_LOG_TO	0x8000000	/* TCP out of order */
#define CI_TP_LOG_TE	0x10000000	/* TCP explain */
#define CI_TP_LOG_SIG	0x40000000	/* Signals */
#define CI_TP_LOG_URG	0x80000000	/* TCP urgent data */

#define CI_TP_LOG_SC   (CI_TP_LOG_TC|CI_TP_LOG_UC) /* socket control */
#define CI_TP_LOG_SV   (CI_TP_LOG_TV|CI_TP_LOG_UV) /* socket verbose */

#ifdef __KERNEL__
#define CI_TP_LOG_DEFAULT (CI_TP_LOG_E|CI_TP_LOG_U|CI_TP_LOG_S|CI_TP_LOG_TE)
#else
#define CI_TP_LOG_DEFAULT (CI_TP_LOG_E|CI_TP_LOG_U|CI_TP_LOG_TE)
#endif

# define LOG_C(c,x)	do{ if(c) do{x;}while(0); }while(0)
# define LOG_E(x)	do{if(ci_tp_log&CI_TP_LOG_E )do{x;}while(0);}while(0)

#ifdef NDEBUG
# define LOG_DC(c,x)    do{}while(0)
#else
# define LOG_DC(c,x)    LOG_C((c), x)
#endif

#define LOG_FL(f,x)	LOG_DC(ci_tp_log&(f), x)

#define LOG_U(x)	LOG_FL(CI_TP_LOG_U , x)
#define LOG_S(x)	LOG_FL(CI_TP_LOG_S , x)
#define LOG_DU(x)	LOG_DC((ci_tp_log&CI_TP_LOG_DU)&&	\
			       !(ci_tp_log&CI_TP_LOG_DR), x)
#define LOG_TC(x)	LOG_FL(CI_TP_LOG_TC, x)
#define LOG_TR(x)	LOG_FL(CI_TP_LOG_TR, x)
#define LOG_TT(x)	LOG_FL(CI_TP_LOG_TT, x)
#define LOG_TL(x)	LOG_FL(CI_TP_LOG_TL, x)
#define LOG_TV(x)	LOG_FL(CI_TP_LOG_TV, x)
#define LOG_NC(x)	LOG_FL(CI_TP_LOG_NC, x)
#define LOG_NR(x)	LOG_FL(CI_TP_LOG_NR, x)
#define LOG_NT(x)	LOG_FL(CI_TP_LOG_NT, x)
#define LOG_NV(x)	LOG_FL(CI_TP_LOG_NV, x)
#define LOG_DR(x)	LOG_FL(CI_TP_LOG_DR, x)
#define LOG_DT(x)	LOG_FL(CI_TP_LOG_DT, x)
#define LOG_EP(x)	LOG_FL(CI_TP_LOG_EP, x)
#define LOG_AR(x)	LOG_FL(CI_TP_LOG_AR, x)
#define LOG_AT(x)	LOG_FL(CI_TP_LOG_AT, x)
#define LOG_ITV(x)	LOG_FL(CI_TP_LOG_ITV, x)
#define LOG_ARP(x)	LOG_FL(CI_TP_LOG_ARP, x)
#define LOG_UC(x)	LOG_FL(CI_TP_LOG_UC, x)
#define LOG_UR(x)	LOG_FL(CI_TP_LOG_UR, x)
#define LOG_UT(x)	LOG_FL(CI_TP_LOG_UT, x)
#define LOG_UV(x)	LOG_FL(CI_TP_LOG_UV, x)
#define LOG_IP(x)	LOG_FL(CI_TP_LOG_IP, x)
#define LOG_IPP(x)	LOG_FL(CI_TP_LOG_IPP, x)
#define LOG_STATS(x)	LOG_FL(CI_TP_LOG_STATS, x)
#define LOG_TO(x)	LOG_FL(CI_TP_LOG_TO, x)
#define LOG_TE(x)	LOG_FL(CI_TP_LOG_TE, x)
#define LOG_IDO(x)	LOG_FL(CI_TP_LOG_IDO, x)
#define LOG_SIG(x)	LOG_FL(CI_TP_LOG_SIG, x)
#define LOG_URG(x)	LOG_FL(CI_TP_LOG_URG, x)
#define LOG_SC(x)       LOG_FL(CI_TP_LOG_SC, x)
#define LOG_SV(x)       LOG_FL(CI_TP_LOG_SV, x)
#define LOG_SSA(x)      LOG_E(x)
#define LOG_W(x)        LOG_E(x)  /* ?? TODO: make this its own bit */


/* Log level definitions to control how chatty Onload's
 * informative/warning messages are
 */
#define EF_LOG_BANNER                 0
#define EF_LOG_RESOURCE_WARNINGS      1
#define EF_LOG_CONN_DROP              2
#define EF_LOG_CONFIG_WARNINGS        3
#define EF_LOG_USAGE_WARNINGS         4
#define EF_LOG_MAX                    5  /* Must be last */


#define NI_LOG(ni, lg, ...)                                \
  do {                                                     \
    if( NI_OPTS(ni).log_category & 1 << (EF_LOG_ ## lg) )  \
      ci_log(__VA_ARGS__);                                 \
  } while( 0 );

#define NI_LOG_ONCE(ni, lg, ...)                           \
  do {                                                     \
    static int printed = 0;                                \
    if( ! printed ) {                                      \
      printed = 1;                                         \
      NI_LOG(ni, lg, __VA_ARGS__);                         \
    }                                                      \
  } while( 0 );


#define CONFIG_LOG(opts, lg, ...)                          \
  do {                                                     \
    if( (opts)->log_category & 1 << (EF_LOG_ ## lg) )      \
      ci_log(__VA_ARGS__);                                 \
  } while( 0 );


/**********************************************************************
 * Format various protocol fields.
 *
 * OOF_foo    -- printf format string
 * OOFA_foo(a) -- printf arguments
 */

#define OOF_IP_PROTO          "%s"
#define OOFA_IP_PROTO(proto)  ((proto) == IPPROTO_TCP ? "TCP" :         \
                              (proto) == IPPROTO_UDP ? "UDP" : "???")

#define OOF_PORT              "%d"
#define OOFA_PORT(port)       ((int) CI_BSWAP_BE16(port))

#define OOF_IP4               "%d.%d.%d.%d"
#define OOFA_IP4(ip4)          ((int) ((const ci_uint8*)&(ip4))[0]),    \
                              ((int) ((const ci_uint8*)&(ip4))[1]),     \
                              ((int) ((const ci_uint8*)&(ip4))[2]),     \
                              ((int) ((const ci_uint8*)&(ip4))[3])

/* FIXME: add ip6 support in ci_addr_t */
#define OOF_IPX               IPX_FMT
#define OOFA_IPX(addr)        IPX_ARG(AF_IP(addr))
#define OOFA_IPX_L3(addr)     IPX_ARG(AF_IP_L3(addr))

#define OOF_IPXPORT           OOF_IPX":"OOF_PORT
#define OOFA_IPXPORT(ip,port) OOFA_IPX(ip), OOFA_PORT(port)


/**********************************************************************
 * Format ipcache.
 */

#define OOF_IPCACHE_STATUS  "%s"
#define OOFA_IPCACHE_STATUS(s)  ((s) == retrrc_success ? "Onloaded" :   \
                                 (s) == retrrc_nomac ? "NoMac" :        \
                                 (s) == retrrc_noroute ? "NoRoute" :    \
                                 (s) == retrrc_alienroute ? "ViaOs" :   \
                                 (s) == retrrc_localroute ? "Local" :   \
                                 "MacFail")

#define OOF_IPCACHE_VALID            "%s"
#define OOFA_IPCACHE_VALID(ni, ipc)                                     \
  (oo_cp_ipcache_is_valid((ni), (ipc)) ? "Valid" : "Old")


#define OOF_IPCACHE_STATE            OOF_IPCACHE_STATUS"("OOF_IPCACHE_VALID")"
#define OOFA_IPCACHE_STATE(ni, ipc)  OOFA_IPCACHE_STATUS((ipc)->status), \
                                     OOFA_IPCACHE_VALID((ni), (ipc))

#define OOF_IPCACHE_DETAIL \
  "if=%d mtu=%d intf_i=%d vlan=%d encap=%x verinfo %x-%x"
#define OOFA_IPCACHE_DETAIL(ipc) \
  (ipc)->ifindex, (ipc)->mtu, (ipc)->intf_i, \
  (ipc)->encap.vlan_id, (ipc)->encap.type, \
  (ipc)->fwd_ver.id, (ipc)->fwd_ver.version


/**********************************************************************
 * Format various flags fields etc.
 */

#define CI_TCP_SOCKET_FLAGS_FMT                                        \
  "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
#define CI_TCP_SOCKET_FLAGS_PRI_ARG(ts)                                \
  ((ts)->tcpflags & CI_TCPT_FLAG_TSO    ? "TSO " :""),                 \
  ((ts)->tcpflags & CI_TCPT_FLAG_WSCL   ? "WSCL ":""),                 \
  ((ts)->tcpflags & CI_TCPT_FLAG_SACK   ? "SACK ":""),                 \
  ((ts)->tcpflags & CI_TCPT_FLAG_ECN    ? "ECN " :""),                 \
  ((ts)->tcpflags & CI_TCPT_FLAG_STRIPE ? "STRIPE ":""),               \
  ((ts)->tcpflags & CI_TCPT_FLAG_SYNCOOKIE        ? "SYNCOOKIE ":""),  \
  ((ts)->tcpflags & CI_TCPT_FLAG_WAS_ESTAB        ? "ESTAB "     :""), \
  ((ts)->tcpflags & CI_TCPT_FLAG_NONBLOCK_CONNECT ? "NONBCON "   :""), \
  ((ts)->tcpflags & CI_TCPT_FLAG_PASSIVE_OPENED   ? "PASSIVE "   :""), \
  ((ts)->tcpflags & CI_TCPT_FLAG_NO_ARP           ? "ARP_FAIL "  :""), \
  ((ts)->tcpflags & CI_TCPT_FLAG_NO_TX_ADVANCE    ? "NO_TX_ADVANCE "  :""), \
  ((ts)->tcpflags & CI_TCPT_FLAG_LOOP_DEFERRED    ? "LOOP_DEFER ":""),  \
  ((ts)->tcpflags & CI_TCPT_FLAG_NO_QUICKACK      ? "NO_QUICKACK ":""), \
  ((ts)->tcpflags & CI_TCPT_FLAG_MEM_DROP         ? "MEM_DROP ":""),    \
  ((ts)->tcpflags & CI_TCPT_FLAG_FIN_RECEIVED     ? "FIN_RECV ":""),    \
  ((ts)->tcpflags & CI_TCPT_FLAG_ACTIVE_WILD      ? "ACTIVE_WILD ":""), \
  ((ts)->tcpflags & CI_TCPT_FLAG_MSG_WARM         ? "MSG_WARM ":""),    \
  ((ts)->tcpflags & CI_TCPT_FLAG_LOOP_FAKE        ? "LOOP_FAKE ":""),   \
  ((ts)->tcpflags & CI_TCPT_FLAG_TAIL_DROP_TIMING ? "TLP_TIMER ":""),   \
  ((ts)->tcpflags & CI_TCPT_FLAG_TAIL_DROP_MARKED ? "TLP_SENT ":""),    \
  ((ts)->tcpflags & CI_TCPT_FLAG_FIN_PENDING      ? "FIN_PENDING ":"")


#define CI_SOCK_FLAGS_FMT \
  "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
#define CI_SOCK_FLAGS_PRI_ARG(s)                                        \
  ((s)->s_aflags & CI_SOCK_AFLAG_CORK     ? "CORK ":""),                \
  ((s)->s_aflags & CI_SOCK_AFLAG_NEED_SHUT_RD ? "SHUTRD ":""),          \
  ((s)->s_aflags & CI_SOCK_AFLAG_NEED_SHUT_WR ? "SHUTWR ":""),          \
  ((s)->s_aflags & CI_SOCK_AFLAG_NODELAY  ? "TCP_NODELAY ":""),         \
  ((s)->s_aflags & CI_SOCK_AFLAG_NEED_ACK ? "ACK ":""),                 \
  ((s)->s_flags & CI_SOCK_FLAG_REUSEADDR  ? "REUSE ":""),               \
  ((s)->s_flags & CI_SOCK_FLAG_KALIVE     ? "KALIVE ":""),              \
  ((s)->s_flags & CI_SOCK_FLAG_BROADCAST  ? "BCAST ":""),               \
  ((s)->s_flags & CI_SOCK_FLAG_OOBINLINE  ? "OOBIN ":""),               \
  ((s)->s_flags & CI_SOCK_FLAG_LINGER     ? "LINGER ":""),              \
  ((s)->s_flags & CI_SOCK_FLAG_DONTROUTE  ? "DONTROUTE ":""),           \
  ((s)->s_flags & CI_SOCK_FLAG_FILTER     ? "FILTER ":""),              \
  ((s)->s_flags & CI_SOCK_FLAG_BOUND      ? "BOUND ":""),               \
  ((s)->s_flags & CI_SOCK_FLAG_PORT_BOUND ? "PBOUND ":""),              \
  ((s)->s_flags & CI_SOCK_FLAG_SET_SNDBUF ? "SNDBUF ":""),              \
  ((s)->s_flags & CI_SOCK_FLAG_SET_RCVBUF ? "RCVBUF ":""),              \
  ((s)->s_flags & CI_SOCK_FLAG_SW_FILTER_FULL ? "SW_FILTER_FULL ":""),  \
  ((s)->s_flags & CI_SOCK_FLAG_TPROXY ? "TRANSPARENT ":""),             \
  ((s)->s_flags & CI_SOCK_FLAG_SCALACTIVE ? "SCALACTIVE ":""),          \
  ((s)->s_flags & CI_SOCK_FLAG_SCALPASSIVE ? "SCALPASSIVE ":""),        \
  ((s)->s_flags & CI_SOCK_FLAG_STACK_FILTER ? "STACK_FILTER ":""),      \
  ((s)->s_flags & CI_SOCK_FLAG_REUSEPORT  ? "REUSEPORT ":""),           \
  ((s)->s_flags & CI_SOCK_FLAG_BOUND_ALIEN  ? "BOUND_ALIEN ":""),       \
  ((s)->s_flags & CI_SOCK_FLAG_CONNECT_MUST_BIND  ? "CONNECT_MUST_BIND ":""),   \
  ((s)->s_flags & CI_SOCK_FLAG_PMTU_DO  ? "PMTU_DO ":""),               \
  ((s)->s_flags & CI_SOCK_FLAG_ALWAYS_DF  ? "ALWAYS_DF ":""),           \
  ((s)->s_flags & CI_SOCK_FLAG_SET_IP_TTL  ? "IP_TTL ":""),             \
  ((s)->s_flags & CI_SOCK_FLAG_DEFERRED_BIND  ? "DEFERRED_BIND ":""),   \
  ((s)->s_flags & CI_SOCK_FLAG_V6ONLY  ? "V6ONLY ":""),                 \
  ((s)->s_flags & CI_SOCK_FLAG_DNAT       ? "DNAT ":""),                \
  ((s)->cp.sock_cp_flags & OO_SCP_NO_MULTICAST ? "NOMCAST ":"")


#define CI_SB_FLAGS_FMT			"%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
#define CI_SB_FLAGS_PRI_ARG(sb)                                         \
  ((sb)->sb_flags  & CI_SB_FLAG_WAKE_TX         ? "WK_TX ":""),         \
  ((sb)->sb_flags  & CI_SB_FLAG_WAKE_RX         ? "WK_RX ":""),         \
  ((sb)->sb_flags  & CI_SB_FLAG_TCP_POST_POLL   ? "TCP_PP ":""),        \
  ((sb)->sb_aflags & CI_SB_AFLAG_ORPHAN         ? "ORPH ":""),          \
  ((sb)->sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ ? "ACCEPTQ ":""),       \
  ((sb)->sb_aflags & CI_SB_AFLAG_DEFERRED       ? "DEFERRED ":""),      \
  ((sb)->sb_aflags & CI_SB_AFLAG_AVOID_INTERRUPTS ? "AVOID_INT ":""),   \
  ((sb)->sb_aflags & CI_SB_AFLAG_O_ASYNC        ? "O_ASYNC ":""),       \
  ((sb)->sb_aflags & CI_SB_AFLAG_O_NONBLOCK     ? "O_NONBLOCK ":""),    \
  ((sb)->sb_aflags & CI_SB_AFLAG_O_NDELAY       ? "O_NDELAY ":""),      \
  ((sb)->sb_aflags & CI_SB_AFLAG_O_APPEND       ? "O_APPEND ":""),      \
  ((sb)->sb_aflags & CI_SB_AFLAG_O_CLOEXEC      ? "O_CLOEXEC ":""),     \
  ((sb)->sb_aflags & CI_SB_AFLAG_IN_CACHE       ? "CACHE ":""),         \
  ((sb)->sb_aflags & CI_SB_AFLAG_IN_PASSIVE_CACHE ? "PASSIVE_CACHE ":""), \
  ((sb)->sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD ? "CACHE_NO_FD ":""),   \
  ((sb)->sb_aflags & CI_SB_AFLAG_OS_BACKED      ? "OS_BACKED ":""),     \
  ((sb)->sb_aflags & CI_SB_AFLAG_O_NONBLOCK_UNSYNCED ? "NONB_UNSYNCED ":"")


#define CI_EVMASK_FMT                  "%s%s%s%s%s%s%s"
#define CI_EVMASK_PRI_ARG(m)           \
  (m & CI_EV_READ    ? "RD ":""),      \
  (m & CI_EV_WRITE   ? "WR ":""),      \
  (m & CI_EV_OOB     ? "OB ":""),      \
  (m & CI_EV_ACCEPT  ? "AC ":""),      \
  (m & CI_EV_CONNECT ? "CO ":""),      \
  (m & CI_EV_CLOSE   ? "CL ":""),      \
  (m & CI_EV_CLOSED  ? "CD ":"")


#define RCV_WND_FMT		"rcv=%08x-%08x-%08x (cur=%08x) wnd_adv=%d"
#define RCV_WND_ARGS(ts)						\
  tcp_rcv_nxt(ts), ts->ack_trigger,					\
  tcp_rcv_nxt(ts)+tcp_rcv_wnd_advertised(ts),				\
  tcp_rcv_nxt(ts)+tcp_rcv_wnd_current(ts), tcp_rcv_wnd_advertised(ts)

#define TCP_RCV_FMT		"rcv=%08x-%08x-%08x wnd=%d q=%d+%d usr=%d"
#define TCP_RCV_PRI_ARG(ts)						\
  tcp_rcv_nxt(ts), tcp_rcv_wnd_right_edge_sent(ts),			\
  tcp_rcv_nxt(ts)+tcp_rcv_wnd_current(ts), tcp_rcv_wnd_current(ts),	\
  ts->recv1.num, ts->recv2.num,			\
  tcp_rcv_usr(ts)

#define TCP_SND_FMT		"snd=%08x-%08x-%08x sq=%d if=%d w=%d"
#define TCP_SND_PRI_ARG(ts)						\
  tcp_snd_una(ts), tcp_snd_nxt(ts), (ts)->snd_max,                      \
  SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts)), ci_tcp_inflight(ts),	\
  tcp_snd_wnd(ts)

#define TCP_CONG_FMT						\
  "%s ss=%d cwnd=%d+%d recover=%08x rt_seq=%08x dups=%d"
#define TCP_CONG_PRI_ARG(ts)						\
  congstate_str(ts), (ts)->ssthresh, (ts)->cwnd, (ts)->cwnd_extra,	\
  (ts)->congrecover, (ts)->retrans_seq, (ts)->dup_acks

/*
 * UDP
 */

#define CI_UDP_STATE_FLAGS_FMT		"%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
#define CI_UDP_STATE_FLAGS_PRI_ARG(ts)				\
  (UDP_FLAGS(ts) & CI_UDPF_FILTERED     ? "FILT ":""),          \
  (UDP_FLAGS(ts) & CI_UDPF_MCAST_LOOP   ? "MCAST_LOOP ":""),    \
  (UDP_FLAGS(ts) & CI_UDPF_IMPLICIT_BIND? "IMP_BIND ":""),      \
  (UDP_FLAGS(ts) & CI_UDPF_EF_SEND      ? "EFSND ":""),         \
  (UDP_FLAGS(ts) & CI_UDPF_LAST_RECV_ON ? "LAST_RCV_ON ":""),   \
  (UDP_FLAGS(ts) & CI_UDPF_EF_BIND      ? "BIND ":""),          \
  (UDP_FLAGS(ts) & CI_UDPF_MCAST_B2D    ? "MC_B2D ":""),        \
  (UDP_FLAGS(ts) & CI_UDPF_NO_MCAST_B2D ? "NO_MC_B2D ":""),     \
  (UDP_FLAGS(ts) & CI_UDPF_PEEK_FROM_OS ? "PEEKOS ":""),        \
  (UDP_FLAGS(ts) & CI_UDPF_SO_TIMESTAMP ? "SO_TS ":""),         \
  (UDP_FLAGS(ts) & CI_UDPF_MCAST_JOIN   ? "MC ":""),            \
  (UDP_FLAGS(ts) & CI_UDPF_MCAST_FILTER ? "MC_FILT ":""),       \
  (UDP_FLAGS(ts) & CI_UDPF_NO_UCAST_FILTER ? "NO_UC_FILT ":""), \
  (UDP_FLAGS(ts) & CI_UDPF_LAST_SEND_NOMAC ? "LAST_SEND_NOMAC":"")


extern unsigned ci_tp_log CI_HV;


#define CI_PKT_FLAGS_FMT    "%s%s%s%s%s%s%s%s%s%s"
#define CI_PKT_FLAGS_PRI_ARG(pkt)  __CI_PKT_FLAGS_PRI_ARG((pkt)->flags)
#define __CI_PKT_FLAGS_PRI_ARG(flags)                           \
  ((flags) & CI_PKT_FLAG_TX_PENDING      ? "TxPend ":""),       \
  ((flags) & CI_PKT_FLAG_INDIRECT        ? "Indir ":""),       \
  ((flags) & CI_PKT_FLAG_RTQ_RETRANS     ? "Retrans ":""),      \
  ((flags) & CI_PKT_FLAG_RTQ_SACKED      ? "Sacked ":""),       \
  ((flags) & CI_PKT_FLAG_UDP             ? "Udp ":""),          \
  ((flags) & CI_PKT_FLAG_TX_PSH          ? "Psh ":""),          \
  ((flags) & CI_PKT_FLAG_TX_MORE         ? "More ":""),         \
  ((flags) & CI_PKT_FLAG_NONB_POOL       ? "Nonb ":""),         \
  ((flags) & CI_PKT_FLAG_RX              ? "Rx ":""),           \
  ((flags) & CI_PKT_FLAG_TX_PSH_ON_ACK   ? "PshOnAck ":"")


#define CI_NETIF_LOCK_FMT         "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
#define CI_NETIF_LOCK_PRI_ARG(v)                                        \
  ((v) & CI_EPLOCK_LOCKED                ? "LOCKED ":"UNLOCKED"),       \
  ((v) & CI_EPLOCK_FL_NEED_WAKE          ? "CONTENDED ":""),            \
  ((v) & CI_EPLOCK_NETIF_NEED_POLL       ? "POLL ":""),                 \
  ((v) & CI_EPLOCK_NETIF_NEED_PRIME      ? "PRIME ":""),                \
  ((v) & CI_EPLOCK_NETIF_CLOSE_ENDPOINT  ? "CLOSE_EP ":""),             \
  ((v) & CI_EPLOCK_NETIF_NEED_WAKE       ? "WAKE ":""),                 \
  ((v) & CI_EPLOCK_NETIF_PKT_WAKE        ? "PKT_WAKE ":""),             \
  ((v) & CI_EPLOCK_NETIF_SWF_UPDATE      ? "SWF_UPDATE ":""),           \
  ((v) & CI_EPLOCK_NETIF_IS_PKT_WAITER   ? "PKT_WAIT ":""),             \
  ((v) & CI_EPLOCK_NETIF_MERGE_ATOMIC_COUNTERS ? "MERGE ":""),          \
  ((v) & CI_EPLOCK_NETIF_NEED_PKT_SET    ? "PKT_SET ":""),              \
  ((v) & CI_EPLOCK_NETIF_NEED_SOCK_BUFS  ? "SOCK_BUFS ":""),            \
  ((v) & CI_EPLOCK_NETIF_PURGE_TXQS      ? "PURGE_TXQ ":""),            \
  ((v) & CI_EPLOCK_NETIF_KERNEL_PACKETS  ? "KPKTS ":""),                \
  ((v) & CI_EPLOCK_NETIF_FREE_READY_LIST ? "FREE_RLIST ":""),           \
  ((v) & CI_EPLOCK_NETIF_SOCKET_LIST     ? "DEFERRED ":"")


#define CI_NETIF_ERRORS_FMT       "%s%s%s%s"
#define CI_NETIF_ERRORS_PRI_ARG(errors)                         \
  ((errors) & CI_NETIF_ERROR_POST_POLL_LIST ? "PPL ":""),       \
  ((errors) & CI_NETIF_ERROR_LOOP_PKTS_LIST ? "LOOP ":""),      \
  ((errors) & CI_NETIF_ERROR_ASSERT         ? "ASS ":""),       \
  ((errors) & CI_NETIF_ERROR_SYNRECV_TABLE  ? "SYNRECV ":"")


#define CI_NETIF_NIC_ERRORS_FMT       "%s"
#define CI_NETIF_NIC_ERRORS_PRI_ARG(errors)                         \
  ((errors) & CI_NETIF_NIC_ERROR_REMAP      ? "REMAP ":"")


#define OO_CMSG_FLAGS_FMT  "%s%s%s%s%s%s%s%s"
#define OO_CMSG_FLAGS_PRI_ARG(v)                                \
  ((v) & CI_IP_CMSG_PKTINFO              ? "Pktinfo":""),       \
  ((v) & CI_IP_CMSG_TTL                  ? "Ttl":""),           \
  ((v) & CI_IP_CMSG_TOS                  ? "Tos":""),           \
  ((v) & CI_IP_CMSG_RECVOPTS             ? "Recvopts":""),      \
  ((v) & CI_IP_CMSG_RETOPTS              ? "Retopts":""),       \
  ((v) & CI_IP_CMSG_TIMESTAMP            ? "Timestamp":""),     \
  ((v) & CI_IP_CMSG_TIMESTAMPNS          ? "Timestampns":""),   \
  ((v) & CI_IP_CMSG_TIMESTAMPING         ? "Timestamping":"")


/**********************************************************************
************************** Std Arg Printing ***************************
**********************************************************************/

#define FD_FMT "%d"
#define FD_PRI_ARGS(fd) fd

/* Netif */
#define N_FMT "%d "
#define N_PRI_ARGS(n) NI_ID(n)

/* Netif, socket */
#define NS_FMT "%d:%d "
#define NS_PRI_ARGS(n,s) NI_ID(n), SC_FMT(s)

/* Netif ID, TCP state ID */
#define NT_FMT "%d:%d "
#define NT_PRI_ARGS(n,t) NI_ID(n), S_FMT(t)

/* Netif ID, UDP state ID */
#define NU_FMT "%d:%d "
#define NU_PRI_ARGS(n,u) NI_ID(n), S_FMT(u)

/* Function, tcp_helper_endpoint_t. */
#define EP_FMT            "%d:%d"
#define EP_PRI_ARGS(e)    NI_ID(&(e)->thr->netif), (e)->id

/* Netif ID, TCP state ID, tcp state str */
#define NTS_FMT "%d:%d %s "
#define NTS_PRI_ARGS(n,t) NI_ID(n), S_FMT(t), ci_tcp_state_str((t)->s.b.state)

/* Netif ID, socket ID, socket state str */
#define NSS_FMT "%d:%d %s "
#define NSS_PRI_ARGS(n,s) NI_ID(n), SC_FMT(s), ci_tcp_state_str((s)->b.state)

/* Netif ID, waitable ID, state str */
#define NWS_FMT "%d:%d %s "
#define NWS_PRI_ARGS(n,w) NI_ID(n), W_FMT(w), ci_tcp_state_str((w)->state)

/* Netif ID, TCP state ID, FD */
#define NTF_FMT "%d:%d/"FD_FMT" "
#define NTF_PRI_ARGS(n,t,fd) NI_ID(n), S_FMT(t), \
	                FD_PRI_ARGS(fd)

/* Netif ID, TCP state ID, FD, tcp state str */
#define NTFS_FMT "%d:%d/"FD_FMT" %s "
#define NTFS_PRI_ARGS(n,t,fd) NI_ID(n), S_FMT(t), \
						FD_PRI_ARGS(fd), state_str((t))

/* TCP state ID, FD */
#define TF_FMT "%d/"FD_FMT" "
#define TF_PRI_ARGS(t,fd) S_FMT(t), FD_PRI_ARGS(fd)

/* TCP state ID, FD, tcp state str */
#define TFS_FMT "%d/"FD_FMT" %s "
#define TFS_PRI_ARGS(t,fd) S_FMT(t), FD_PRI_ARGS(fd), \
	                    state_str((t))

/* citp_socket-based; Netif ID, TCP state ID */
#define SK_FMT "%d:%d"
#define SK_PRI_ARGS(sk) NI_ID((sk)->netif),SC_FMT((sk)->s)

/* citp_socket-based; Netif ID, TCP state ID, FD */
#define SF_FMT "%d:%d/"FD_FMT
#define SF_PRI_ARGS(sk,fd) NI_ID((sk)->netif), \
	                SC_FMT((sk)->s), FD_PRI_ARGS(fd)

/* ci_socket_epinfo-based; Netif ID, TCP state ID, FD */
#define EF_FMT "%d:%d/"FD_FMT
#define EF_PRI_ARGS(epi,fd) NI_ID((epi)->sock.netif), \
                            SC_FMT((epi)->sock.s),     \
							FD_PRI_ARGS(fd)

/* ci_socket_epinfo-based; Netif ID, state ID */
#define E_FMT            NSS_FMT
#define E_PRI_ARGS(epi)  NSS_PRI_ARGS((epi)->sock.netif, (epi)->sock.s)

/* --- With LPF first (LPF defined in module) --- */
/* Netif */
#define LN_FMT LPF "%d "
#define LN_PRI_ARGS N_PRI_ARGS

/* Netif ID, TCP state ID */
#define LNT_FMT LPF "%d:%d "
#define LNT_PRI_ARGS NT_PRI_ARGS

/* Netif ID, TCP state ID, tcp state str */
#define LNTS_FMT LPF "%d:%d %s "
#define LNTS_PRI_ARGS NTS_PRI_ARGS

/* Netif ID, TCP state ID, FD */
#define LNTF_FMT LPF "%d:%d/"FD_FMT" "
#define LNTF_PRI_ARGS NTF_PRI_ARGS

/* Netif ID, TCP state ID, FD, tcp state str */
#define LNTFS_FMT LPF "%d:%d/"FD_FMT" %s "
#define LNTFS_PRI_ARGS NTFS_PRI_ARGS

/* TCP state ID, FD */
#define LTF_FMT LPF "%d/"FD_FMT" "
#define LTF_PRI_ARGS TF_PRI_ARGS

/* TCP state ID, FD, tcp state str */
#define LTFS_FMT LPF "%d/"FD_FMT" %s "
#define LTFS_PRI_ARGS TFS_PRI_ARGS

/* Function, netif. */
#define FN_FMT             "%s: "N_FMT
#define FN_PRI_ARGS(n)     __FUNCTION__, N_PRI_ARGS(n)

/* Function, netif, socket. */
#define FNS_FMT            "%s: "NS_FMT
#define FNS_PRI_ARGS(n,s)  __FUNCTION__, NS_PRI_ARGS((n),(s))

/* Function, netif, socket. */
#define FNT_FMT            "%s: "NT_FMT
#define FNT_PRI_ARGS(n,t)  __FUNCTION__, NT_PRI_ARGS((n),(t))

/* Function, netif, socket, state. */
#define FNTS_FMT           "%s: "NTS_FMT
#define FNTS_PRI_ARGS(n,t) __FUNCTION__, NTS_PRI_ARGS((n),(t))

/* Function, tcp_helper_endpoint_t. */
#define FEP_FMT            "%s: "EP_FMT" "
#define FEP_PRI_ARGS(e)   __FUNCTION__, EP_PRI_ARGS(e)


/* TCP urgent data */
#define TCP_URG_FMT "%s: %s%s%s[%u] "
#define TCP_URG_ARGS(ts) \
__FUNCTION__, \
(tcp_urg_data(ts) & CI_TCP_URG_COMING) ? "CI_TCP_URG_COMING " : "", \
(tcp_urg_data(ts) & CI_TCP_URG_IS_HERE) ? "CI_TCP_URG_IS_HERE " : "", \
(tcp_urg_data(ts) & CI_TCP_URG_PTR_VALID) ? "CI_TCP_URG_PTR_VALID " : "", \
tcp_urg_data(ts) & CI_TCP_URG_DATA_MASK 
 

#endif  /* __CI_INTERNAL_IP_LOG_H__ */
/*! \cidoxg_end */
