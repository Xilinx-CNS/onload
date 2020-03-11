/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __FTL_DEFS_H__
#define __FTL_DEFS_H__

#ifdef IGNORE
#undef IGNORE
#endif

#ifdef DO
#undef DO
#endif

#define DO(x) x
#define IGNORE(x) 

#ifndef NDEBUG
#define ON_DEBUG DO
#else
#define ON_DEBUG IGNORE
#endif

#define ON_SUN IGNORE
#define NO_SUN DO

#if !defined(NDEBUG) || CI_CFG_STATS_NETIF
#define ON_PID_SUPPORT DO
#else
#define ON_PID_SUPPORT IGNORE
#endif

#if CI_CFG_SUPPORT_STATS_COLLECTION
#define ON_CI_CFG_SUPPORT_STATS_COLLECTION DO
#else
#define ON_CI_CFG_SUPPORT_STATS_COLLECTION IGNORE
#endif

#if CI_CFG_TCP_SOCK_STATS
#define ON_CI_CFG_TCP_SOCK_STATS DO
#else
#define ON_CI_CFG_TCP_SOCK_STATS IGNORE
#endif

#if CI_CFG_ZC_RECV_FILTER
#define ON_CI_CFG_ZC_RECV_FILTER DO
#else
#define ON_CI_CFG_ZC_RECV_FILTER IGNORE
#endif

#if CI_CFG_FD_CACHING
#define ON_CI_CFG_FD_CACHING DO
#else
#define ON_CI_CFG_FD_CACHING IGNORE
#endif

#if CI_CFG_PIO
#define ON_CI_HAVE_PIO DO
#else
#define ON_CI_HAVE_PIO IGNORE
#endif

#if CI_CFG_CTPIO
#define ON_CI_HAVE_CTPIO DO
#else
#define ON_CI_HAVE_CTPIO IGNORE
#endif

#ifndef NDEBUG
#if CI_CFG_PIO
#define ON_CI_HAVE_PIO_DEBUG DO
#else
#define ON_CI_HAVE_PIO_DEBUG IGNORE
#endif
#else
#define ON_CI_HAVE_PIO_DEBUG IGNORE
#endif

#if CI_CFG_STATS_NETIF
#define ON_CI_CFG_STATS_NETIF DO
#else
#define ON_CI_CFG_STATS_NETIF IGNORE
#endif

#if CI_CFG_PORT_STRIPING
#define ON_CI_CFG_PORT_STRIPING DO
#else
#define ON_CI_CFG_PORT_STRIPING IGNORE
#endif

#if CI_CFG_BURST_CONTROL
#define ON_CI_CFG_BURST_CONTROL DO
#else
#define ON_CI_CFG_BURST_CONTROL IGNORE
#endif

#if CI_CFG_TCP_FASTSTART
#define ON_CI_CFG_TCP_FASTSTART DO
#else
#define ON_CI_CFG_TCP_FASTSTART IGNORE
#endif

#if CI_CFG_TAIL_DROP_PROBE
#define ON_CI_CFG_TAIL_DROP_PROBE DO
#else
#define ON_CI_CFG_TAIL_DROP_PROBE IGNORE
#endif

#if CI_CFG_CONGESTION_WINDOW_VALIDATION
#define ON_CI_CFG_CONGESTION_WINDOW_VALIDATION DO
#else
#define ON_CI_CFG_CONGESTION_WINDOW_VALIDATION IGNORE
#endif

#if CI_CFG_STATS_TCP_LISTEN
#define ON_CI_CFG_STATS_TCP_LISTEN DO
#else
#define ON_CI_CFG_STATS_TCP_LISTEN IGNORE
#endif

#if CI_CFG_PKTS_AS_HUGE_PAGES
#define ON_CI_CFG_PKTS_AS_HUGE_PAGES DO
#else
#define ON_CI_CFG_PKTS_AS_HUGE_PAGES IGNORE
#endif

#if CI_CFG_TCPDUMP
#define ON_CI_CFG_TCPDUMP DO
#else
#define ON_CI_CFG_TCPDUMP IGNORE
#endif

#if CI_CFG_SPIN_STATS
#define ON_CI_CFG_SPIN_STATS DO
#else
#define ON_CI_CFG_SPIN_STATS IGNORE
#endif

#if CI_CFG_NOTICE_WINDOW_SHRINKAGE
#define ON_CI_CFG_NOTICE_WINDOW_SHRINKAGE DO
#else
#define ON_CI_CFG_NOTICE_WINDOW_SHRINKAGE IGNORE
#endif

#if CI_CFG_BURST_CONTROL
#define ON_CI_CFG_BURST_CONTROL DO
#else
#define ON_CI_CFG_BURST_CONTROL IGNORE
#endif

#if CI_CFG_TIMESTAMPING
#define ON_CI_CFG_TIMESTAMPING DO
#else
#define ON_CI_CFG_TIMESTAMPING IGNORE
#endif

#if CI_CFG_PROC_DELAY
#define ON_CI_CFG_PROC_DELAY DO
#else
#define ON_CI_CFG_PROC_DELAY IGNORE
#endif

#if CI_CFG_IPV6
#define ON_CI_CFG_IPV6 DO
#else
#define ON_CI_CFG_IPV6 IGNORE
#endif


#define oo_timespec \
  struct oo_timespec

#define oo_waitable_lock \
  struct oo_waitable_lock

#define UNION_EFAB_EVENT(ctx)                                           \
  FTL_TUNION_BEGIN(ctx, efhw_event_t,)                                  \
  FTL_TFIELD_INT(ctx, uint64_t, u64, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))                      \
  FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, opaque, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))               \
  FTL_TFIELD_ANON_STRUCT(ctx, uint32_t, opaque, a)        \
  FTL_TFIELD_ANON_STRUCT(ctx, uint32_t, opaque, b)        \
  FTL_TFIELD_ANON_STRUCT_END(ctx, opaque)                 \
  FTL_TUNION_END(ctx)

#define STRUCT_EF_EVENTQ_STATE(ctx)                                     \
  FTL_TSTRUCT_BEGIN(ctx, ef_eventq_state,)                              \
  FTL_TFIELD_INT(ctx, ef_eventq_ptr, evq_ptr, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))          \
  FTL_TFIELD_INT(ctx, unsigned, sync_timestamp_major, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))  \
  FTL_TFIELD_INT(ctx, unsigned, sync_timestamp_minor, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))  \
  FTL_TFIELD_INT(ctx, unsigned, sync_timestamp_synchronised, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS)) \
  FTL_TFIELD_INT(ctx, unsigned, sync_flags, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS)) \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_CI_NI_DLLINK(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ni_dllist_link, )                               \
    FTL_TFIELD_INT(ctx, oo_p, prev, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    FTL_TFIELD_INT(ctx, oo_p, next, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_CI_NI_DLLIST(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ni_dllist_t, )                                  \
    FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_link, l, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_PIO_BUDDY_ALLOCATOR(ctx)         \
  FTL_TSTRUCT_BEGIN(ctx, ci_pio_buddy_allocator, )                        \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_ni_dllist_t, \
                           free_lists, CI_PIO_BUDDY_MAX_ORDER + 1, ORM_OUTPUT_EXTRA, 1)   \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_ni_dllist_link, \
                           links, 1ul << CI_PIO_BUDDY_MAX_ORDER, ORM_OUTPUT_EXTRA, 1)     \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_uint8, orders,  \
                        1ul << CI_PIO_BUDDY_MAX_ORDER, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_INT(ctx, ci_int32, initialised, ORM_OUTPUT_STACK) \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_OO_TIMESPEC(ctx)                                \
  FTL_TSTRUCT_BEGIN(ctx, oo_timespec, )                        \
  FTL_TFIELD_INT(ctx, ci_int32, tv_sec, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))           \
  FTL_TFIELD_INT(ctx, ci_int32, tv_nsec, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
  FTL_TSTRUCT_END(ctx)


#define STRUCT_NETIF_STATE_NIC(ctx)                                     \
  FTL_TSTRUCT_BEGIN(ctx, ci_netif_state_nic_t, )                        \
  FTL_TFIELD_INT(ctx, ci_uint32, timer_quantum_ns, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_uint32, rx_prefix_len, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_int16, rx_ts_correction, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_int16, tx_ts_correction, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_uint32, ts_format, ORM_OUTPUT_STACK)       \
  FTL_TFIELD_INT(ctx, ci_uint32, vi_flags, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_uint32, vi_out_flags, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_uint32, oo_vi_flags, ORM_OUTPUT_STACK)     \
  ON_CI_HAVE_PIO(                                                   \
    FTL_TFIELD_CONSTINT(ctx, ci_uint32,           \
                        pio_io_mmap_bytes, ORM_OUTPUT_STACK)                              \
    FTL_TFIELD_CONSTINT(ctx, ci_uint32,           \
                        pio_io_len, ORM_OUTPUT_STACK)                                     \
    FTL_TFIELD_STRUCT(ctx, \
                      ci_pio_buddy_allocator, pio_buddy, ORM_OUTPUT_EXTRA)                \
  ) \
  FTL_TFIELD_CONSTINT(ctx, ci_uint32, vi_io_mmap_bytes, ORM_OUTPUT_STACK) \
  FTL_TFIELD_CONSTINT(ctx, ci_uint32, vi_evq_bytes, ORM_OUTPUT_STACK) \
  FTL_TFIELD_CONSTINT(ctx, ci_uint16, vi_instance, ORM_OUTPUT_STACK) \
  FTL_TFIELD_CONSTINT(ctx, ci_uint16, vi_rxq_size, ORM_OUTPUT_STACK) \
  FTL_TFIELD_CONSTINT(ctx, ci_uint16, vi_txq_size, ORM_OUTPUT_STACK) \
  FTL_TFIELD_CONSTINT(ctx, ci_uint8, vi_arch, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_CONSTINT(ctx, ci_uint8, vi_variant, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_CONSTINT(ctx, ci_uint8, vi_revision, ORM_OUTPUT_STACK) \
  FTL_TFIELD_CONSTINT(ctx, ci_uint8, vi_channel, ORM_OUTPUT_STACK) \
  FTL_TFIELD_SSTR(ctx, pci_dev, ORM_OUTPUT_STACK) \
  FTL_TFIELD_STRUCT(ctx, oo_pktq, dmaq, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_bytes_added, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_bytes_removed, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_dmaq_insert_seq, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_uint32,                  \
                 tx_dmaq_insert_seq_last_poll, ORM_OUTPUT_STACK)                          \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_dmaq_done_seq, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_int32, rx_frags, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_uint32, pd_owner, ORM_OUTPUT_STACK)        \
  ON_CI_CFG_TIMESTAMPING( \
    FTL_TFIELD_STRUCT(ctx, oo_timespec,           \
                      last_rx_timestamp, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_INT(ctx, ci_uint32, last_sync_flags, ORM_OUTPUT_STACK) \
  ) \
  FTL_TFIELD_INT(ctx, ci_uint32, nic_error_flags, ORM_OUTPUT_STACK) \
  ON_CI_HAVE_CTPIO(                                                 \
    FTL_TFIELD_INT(ctx, ci_uint32, ctpio_ct_threshold, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_uint32, ctpio_frame_len_check, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_uint32, ctpio_max_frame_len, ORM_OUTPUT_STACK) \
  ) \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_CI_EPLOCK(ctx) \
  FTL_TSTRUCT_BEGIN(ctx, ci_eplock_t,)                                  \
  FTL_TFIELD_INT(ctx, ci_uint64, lock, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_NETIF_CONFIG(ctx)                                        \
  FTL_TSTRUCT_BEGIN(ctx, ci_netif_config, )                             \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_rto_initial, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_rto_min, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_rto_max, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_delack, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_idle, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_keepalive_time, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, \
                 ci_iptime_t, tconst_keepalive_time_in_secs, ORM_OUTPUT_STACK)            \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_keepalive_intvl, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, \
                 ci_iptime_t, tconst_keepalive_intvl_in_secs, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_int32, keepalive_probes, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_zwin_max, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_paws_idle, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_2msl_time, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_fin_timeout, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_peer2msl_time, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, \
                 ci_iptime_t, tconst_pmtu_discover_slow, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, \
                 ci_iptime_t, tconst_pmtu_discover_fast, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, \
                 ci_iptime_t, tconst_pmtu_discover_recover, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, \
                 ci_uint32, tconst_challenge_ack_limit, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_iptime_t, tconst_stats, ORM_OUTPUT_STACK)       \
  FTL_TSTRUCT_END(ctx)                                                 


#define STRUCT_NETIF_IPID_CB(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_ipid_cb_t, )                              \
    FTL_TFIELD_INT(ctx, ci_uint16, base, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_uint16, next, ORM_OUTPUT_STACK)                    \
    ON_CI_CFG_IPV6(                                                           \
      FTL_TFIELD_INT(ctx, ci_uint32, ip6_base, ORM_OUTPUT_STACK)              \
      FTL_TFIELD_INT(ctx, ci_uint32, ip6_next, ORM_OUTPUT_STACK)              \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_int32, no_free, ORM_OUTPUT_STACK)                  \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_IP_TIMER_STATE(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_timer_state, )                               \
    FTL_TFIELD_INT(ctx, ci_iptime_t, sched_ticks, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_iptime_t, ci_ip_time_real_ticks, ORM_OUTPUT_STACK)\
    FTL_TFIELD_INT(ctx, ci_uint64, frc, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_INT(ctx, ci_uint32, ci_ip_time_frc2tick, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_uint32, ci_ip_time_frc2us, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_INT(ctx, ci_uint32, ci_ip_time_frc2isn, ORM_OUTPUT_STACK)     \
    FTL_TFIELD_INT(ctx, ci_uint32, khz, ORM_OUTPUT_STACK)                    \
    FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t, fire_list, ORM_OUTPUT_EXTRA)      \
    FTL_TFIELD_ARRAYOFSTRUCT(ctx, \
                             ci_ni_dllist_t, warray, CI_IPTIME_WHEELSIZE, ORM_OUTPUT_EXTRA, 1)   \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_IP_TIMER(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_timer, )                                     \
    FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_link, link, ORM_OUTPUT_EXTRA)	      \
    FTL_TFIELD_INT(ctx, ci_iptime_t, time, ORM_OUTPUT_STACK)                       \
    FTL_TFIELD_INT(ctx, oo_sp, param1, ORM_OUTPUT_EXTRA)                     \
    FTL_TFIELD_INT(ctx, ci_iptime_callback_fn_t, fn, ORM_OUTPUT_EXTRA)             \
    FTL_TSTRUCT_END(ctx)                                                 

#define STRUCT_EF_VI_TXQ_STATE(ctx)                             \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_txq_state, )                     \
  FTL_TFIELD_INT(ctx, ci_uint32, previous, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))     \
  FTL_TFIELD_INT(ctx, ci_uint32, added, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))        \
  FTL_TFIELD_INT(ctx, ci_uint32, removed, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))      \
  FTL_TFIELD_INT(ctx, ci_uint32, ts_nsec, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))      \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_EF_VI_RXQ_STATE(ctx)                                     \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_rxq_state, )                             \
  FTL_TFIELD_INT(ctx, ci_uint32, posted, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))               \
  FTL_TFIELD_INT(ctx, ci_uint32, added, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))                \
  FTL_TFIELD_INT(ctx, ci_uint32, removed, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))              \
  FTL_TFIELD_INT(ctx, ci_uint32, in_jumbo, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))             \
  FTL_TFIELD_INT(ctx, ci_uint32, bytes_acc, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))            \
  FTL_TFIELD_INT(ctx, ci_uint16, last_desc_i, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))      \
  FTL_TFIELD_INT(ctx, ci_uint16, rx_ps_credit_avail, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))   \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_EF_VI_STATE(ctx)                                 \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_state, )                         \
  FTL_TFIELD_STRUCT(ctx, ef_eventq_state, evq, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))     \
  FTL_TFIELD_STRUCT(ctx, ef_vi_txq_state, txq, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))     \
  FTL_TFIELD_STRUCT(ctx, ef_vi_rxq_state, rxq, (ORM_OUTPUT_STACK | ORM_OUTPUT_VIS))     \
  FTL_TSTRUCT_END(ctx)

#if CI_CFG_SUPPORT_STATS_COLLECTION

#define STRUCT_IPV4_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_stats_count, )                             \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, in_recvs, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, in_hdr_errs, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, in_discards, ORM_OUTPUT_STACK)   \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, in_delivers, ORM_OUTPUT_STACK)   \
    ON_CI_CFG_IPV6(                                                        \
      FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, in6_recvs, ORM_OUTPUT_STACK)   \
      FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, in6_hdr_errs, ORM_OUTPUT_STACK)\
      FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, in6_discards, ORM_OUTPUT_STACK)\
      FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, in6_delivers, ORM_OUTPUT_STACK)\
    )                                                                      \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_udp_stats_count, )                              \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,                 \
		   udp_in_dgrams, ORM_OUTPUT_STACK)                                             \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,                 \
		   udp_no_ports, ORM_OUTPUT_STACK)                                              \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,                 \
		   udp_in_errs, ORM_OUTPUT_STACK)                                               \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,                 \
		   udp_out_dgrams, ORM_OUTPUT_STACK)                                            \
    FTL_TSTRUCT_END(ctx)


#define STRUCT_IP_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_stats, )                                     \
    FTL_TFIELD_INT(ctx, __TIME_TYPE__, now, ORM_OUTPUT_STACK)                      \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats_count,      ip, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_stats_count,     tcp, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_STRUCT(ctx, ci_udp_stats_count,     udp, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_ext_stats_count, tcp_ext, ORM_OUTPUT_STACK)      \
    FTL_TSTRUCT_END(ctx)

#endif  /* CI_CFG_SUPPORT_STATS_COLLECTION */

#define STRUCT_NETIF_DBG_MAX(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_dbg_max_t, )                              \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_uint16, poll_l5_max, 2, ORM_OUTPUT_STACK) \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_uint16, poll_os_max, 2, ORM_OUTPUT_STACK) \
    FTL_TFIELD_ARRAYOFINT(ctx, \
			  ci_uint16, select_l5_max, 2, ORM_OUTPUT_STACK)                        \
    FTL_TFIELD_ARRAYOFINT(ctx, \
			  ci_uint16, select_os_max, 2, ORM_OUTPUT_STACK)                        \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_NETIF_THRD_INFO(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_thrd_info_t, )                            \
    FTL_TFIELD_INT(ctx, ci_int32, index, ORM_OUTPUT_STACK)                \
    FTL_TFIELD_INT(ctx, ci_int32, id, ORM_OUTPUT_STACK)                   \
    FTL_TFIELD_ARRAYOFINT(ctx, \
		          ci_int32, ep_id, NETIF_INFO_MAX_EPS_PER_THREAD, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_int32, lock_status, ORM_OUTPUT_STACK)          \
    FTL_TFIELD_INT(ctx, ci_int32, no_lock_contentions, ORM_OUTPUT_STACK)  \
    FTL_TFIELD_INT(ctx, ci_int32, no_select, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_int32, no_poll, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_int32, no_fork, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_INT(ctx, ci_int32, no_exec, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_INT(ctx, ci_int32, no_accept, ORM_OUTPUT_STACK)	      \
    FTL_TFIELD_INT(ctx, ci_int32, no_fini, ORM_OUTPUT_STACK)              \
    FTL_TFIELD_STRUCT(ctx, ci_netif_dbg_max_t, max, ORM_OUTPUT_STACK)     \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_EF_VI_STATS(ctx)                                         \
  FTL_TSTRUCT_BEGIN(ctx, ef_vi_stats, )                                  \
  FTL_TFIELD_INT(ctx, ci_uint32, rx_ev_lost, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_uint32, rx_ev_bad_desc_i, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_uint32, rx_ev_bad_q_label, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_uint32, evq_gap, ORM_OUTPUT_STACK)                  \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_SOCKET_CACHE(ctx)                                        \
  FTL_TSTRUCT_BEGIN(ctx, ci_socket_cache_t, )                           \
  FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t, cache, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
  FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t, pending, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t, fd_states, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
  FTL_TFIELD_INT(ctx, ci_int32, avail_stack, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_NETIF_STATE(ctx)                                         \
  FTL_TSTRUCT_BEGIN(ctx, ci_netif_state, )                              \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_netif_state_nic_t, nic, CI_CFG_MAX_INTERFACES, \
                           ORM_OUTPUT_EXTRA, stats->hwport_mask & (1 << i) )  \
  FTL_TFIELD_INT(ctx, ci_int32, nic_n, ORM_OUTPUT_STACK)                  \
  FTL_TFIELD_INT(ctx, ci_uint64, evq_last_prime, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_uint32, stack_id, ORM_OUTPUT_STACK)              \
  FTL_TFIELD_SSTR(ctx, pretty_name,  ORM_OUTPUT_STACK)                    \
  FTL_TFIELD_INT(ctx, ci_uint32, netif_mmap_bytes, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_uint32, vi_state_bytes, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_uint16, max_mss, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_INT(ctx, ci_uint32, flags, ORM_OUTPUT_STACK)                 \
  FTL_TFIELD_INT(ctx, ci_uint32, error_flags, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_uint32, evq_primed, ORM_OUTPUT_STACK)            \
  FTL_TFIELD_INT(ctx, ci_uint32, evq_prime_deferred, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, cicp_hwport_mask_t, hwport_mask, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_int8,                   \
                        hwport_to_intf_i, CI_CFG_MAX_HWPORTS, ORM_OUTPUT_STACK) \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_int8,                   \
                        intf_i_to_hwport, CI_CFG_MAX_INTERFACES, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_uint32, n_spinners, ORM_OUTPUT_STACK)            \
  FTL_TFIELD_INT(ctx, ci_int8, is_spinner, ORM_OUTPUT_STACK)              \
  FTL_TFIELD_INT(ctx, ci_int8, poll_work_outstanding, ORM_OUTPUT_STACK)   \
  FTL_TFIELD_INT(ctx, ci_uint64, last_spin_poll_frc, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_uint64, last_sleep_frc, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_STRUCT(ctx, ci_eplock_t, lock, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_int32, looppkts, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_INT(ctx, ci_int32, n_looppkts, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_int32, n_rx_pkts, ORM_OUTPUT_STACK)              \
  FTL_TFIELD_INT(ctx, ci_int32, atomic_n_rx_pkts, ORM_OUTPUT_STACK)       \
  FTL_TFIELD_INT(ctx, ci_int32, atomic_n_async_pkts, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_int32, rxq_low, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, ci_int32, rxq_limit, ORM_OUTPUT_STACK)              \
  FTL_TFIELD_INT(ctx, ci_uint32, mem_pressure, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_int32, mem_pressure_pkt_pool, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ci_int32, mem_pressure_pkt_pool_n, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_int32, n_async_pkts, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_int32, reserved_pktbufs, ORM_OUTPUT_STACK)       \
  FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t, deferred_list, ORM_OUTPUT_EXTRA) \
  FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t, deferred_list_free, ORM_OUTPUT_EXTRA) \
  FTL_TFIELD_INT(ctx, ci_uint64, nonb_pkt_pool, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_STRUCT(ctx, ci_netif_ipid_cb_t, ipid, ORM_OUTPUT_EXTRA) \
  FTL_TFIELD_INT(ctx, ci_uint32, active_wild_ofs, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_uint16, active_wild_pools_n, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_uint32, dma_ofs, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_INT(ctx, ci_uint32, table_ofs, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_uint32, table_ext_ofs, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_INT(ctx, ci_uint32, buf_ofs, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_STRUCT(ctx, ci_ip_timer_state, iptimer_state, ORM_OUTPUT_STACK) \
  FTL_TFIELD_STRUCT(ctx, ci_ip_timer, timeout_tid, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_ni_dllist_t, timeout_q, \
                           OO_TIMEOUT_Q_MAX, ORM_OUTPUT_STACK, 1)         \
  FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t, reap_list, ORM_OUTPUT_EXTRA)     \
  FTL_TFIELD_INT(ctx, ci_uint32, challenge_ack_num, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_iptime_t, challenge_ack_time, ORM_OUTPUT_STACK)  \
  ON_CI_CFG_SUPPORT_STATS_COLLECTION(                                   \
    FTL_TFIELD_INT(ctx, ci_int32, stats_fmt, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer, stats_tid, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, stats_snapshot, ORM_OUTPUT_STACK) \
    FTL_TFIELD_STRUCT(ctx, ci_ip_stats, stats_cumulative, ORM_OUTPUT_STACK) \
  )                                                                     \
  FTL_TFIELD_INT(ctx, ci_int32, free_eps_head, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_int32, deferred_free_eps_head, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_uint32, max_ep_bufs, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_uint32, n_ep_bufs, ORM_OUTPUT_STACK)             \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_int32,                 \
                        ready_list_pid, CI_CFG_N_READY_LISTS, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_ni_dllist_t,         \
                           ready_lists, CI_CFG_N_READY_LISTS, ORM_OUTPUT_EXTRA, 1) \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_uint32,                 \
                        ready_list_flags, CI_CFG_N_READY_LISTS, ORM_OUTPUT_EXTRA)         \
  FTL_TFIELD_INT(ctx, ci_uint32, ready_lists_in_use, ORM_OUTPUT_EXTRA)    \
  ON_CI_HAVE_PIO(                                                         \
    FTL_TFIELD_INT(ctx, ci_uint32, pio_bufs_ofs, ORM_OUTPUT_STACK)        \
  ) \
  FTL_TFIELD_INT(ctx, ci_uint32, ep_ofs, ORM_OUTPUT_STACK)                \
  FTL_TFIELD_INT(ctx, ci_int32, free_aux_mem, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_uint32, n_free_aux_bufs, ORM_OUTPUT_STACK)       \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_uint32, n_aux_bufs, CI_TCP_AUX_TYPE_NUM,  \
                                                             ORM_OUTPUT_STACK)            \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_uint32, max_aux_bufs, CI_TCP_AUX_TYPE_NUM,\
                                                             ORM_OUTPUT_STACK)            \
  ON_CI_CFG_FD_CACHING(                                                 \
    FTL_TFIELD_INT(ctx, ci_uint32, passive_cache_avail_stack, ORM_OUTPUT_STACK)  \
  )                                                                     \
  FTL_TFIELD_STRUCT(ctx, ci_netif_config, conf, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_STRUCT(ctx, ci_netif_config_opts, opts, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_uint64, sock_spin_cycles, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_INT(ctx, ci_uint64, buzz_cycles, ORM_OUTPUT_STACK)           \
  FTL_TFIELD_INT(ctx, ci_uint64, timer_prime_cycles, ORM_OUTPUT_STACK)    \
  FTL_TFIELD_INT(ctx, ci_uint32, timesync_bytes, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_uint32, io_mmap_bytes, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_uint32, buf_mmap_bytes, ORM_OUTPUT_STACK)        \
  ON_CI_HAVE_PIO(                                                         \
    FTL_TFIELD_INT(ctx, ci_uint32, pio_mmap_bytes, ORM_OUTPUT_STACK)      \
  )                                                                     \
  ON_CI_HAVE_CTPIO(                                                       \
    FTL_TFIELD_INT(ctx, ci_uint32, ctpio_mmap_bytes, ORM_OUTPUT_STACK)    \
  )                                                                       \
  FTL_TFIELD_INT(ctx, ci_int32, poll_did_wake, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_int32, in_poll, ORM_OUTPUT_STACK)               \
  FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t, post_poll_list, ORM_OUTPUT_EXTRA) \
  FTL_TFIELD_INT(ctx, ci_int32, rx_defrag_head, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_int32, rx_defrag_tail, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_int32, send_may_poll, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_SSTR(ctx, name,  ORM_OUTPUT_STACK)                          \
  FTL_TFIELD_INT(ctx, ci_int32, pid, ORM_OUTPUT_STACK)                    \
  FTL_TFIELD_INT(ctx, uid_t, uuid, ORM_OUTPUT_STACK)                       \
  FTL_TFIELD_INT(ctx, ci_uint32, defer_work_count, ORM_OUTPUT_STACK)      \
  FTL_TFIELD_ARRAYOFINT(ctx, ci_uint8, hash_salt, 16, ORM_OUTPUT_EXTRA) \
  ON_CI_CFG_STATS_NETIF(                                                \
    FTL_TFIELD_STRUCT(ctx, ci_netif_stats, stats, 0 /* displayed separately */)  \
  )                                                                     \
  ON_CI_CFG_TCPDUMP(                                                    \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_int32, dump_queue,    \
                          CI_CFG_DUMPQUEUE_LEN, ORM_OUTPUT_EXTRA)                      \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_uint8, dump_intf,     \
                          OO_INTF_I_NUM, ORM_OUTPUT_STACK)                                \
    FTL_TFIELD_INT(ctx, ci_uint16, dump_read_i, ORM_OUTPUT_STACK)         \
    FTL_TFIELD_INT(ctx, ci_uint16, dump_write_i, ORM_OUTPUT_STACK)        \
  ) \
  FTL_TFIELD_STRUCT(ctx, ef_vi_stats, vi_stats, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_int32, creation_numa_node, ORM_OUTPUT_STACK)     \
  FTL_TFIELD_INT(ctx, ci_int32, load_numa_node, ORM_OUTPUT_STACK)         \
  FTL_TFIELD_INT(ctx, ci_uint32, packet_alloc_numa_nodes, ORM_OUTPUT_STACK)\
  FTL_TFIELD_INT(ctx, ci_uint32, sock_alloc_numa_nodes, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_uint32, interrupt_numa_nodes, ORM_OUTPUT_STACK)  \
  ON_CI_CFG_FD_CACHING(                                                 \
    FTL_TFIELD_STRUCT(ctx, ci_socket_cache_t, active_cache, ORM_OUTPUT_EXTRA)   \
    FTL_TFIELD_INT(ctx, ci_uint32, active_cache_avail_stack, ORM_OUTPUT_STACK)  \
  )                                                                     \
  FTL_TFIELD_INT(ctx, ci_uint32, netns_id, ORM_OUTPUT_STACK)            \
  FTL_TFIELD_INT(ctx, ci_uint32, cplane_pid, ORM_OUTPUT_STACK)          \
  FTL_TFIELD_INT(ctx, ci_uint16, rss_instance, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, ci_uint16, cluster_size, ORM_OUTPUT_STACK)        \
  FTL_TFIELD_INT(ctx, oo_pkt_p, kernel_packets_head, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, oo_pkt_p, kernel_packets_tail, ORM_OUTPUT_STACK)  \
  FTL_TFIELD_INT(ctx, ci_uint32, kernel_packets_pending, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_uint64, kernel_packets_last_forwarded, ORM_OUTPUT_STACK) \
  FTL_TFIELD_INT(ctx, ci_uint64, kernel_packets_cycles, ORM_OUTPUT_STACK) \
  ON_CI_CFG_PROC_DELAY(                                                   \
    FTL_TFIELD_INT(ctx, ci_uint64, sync_frc, ORM_OUTPUT_STACK)            \
    FTL_TFIELD_INT(ctx, ci_uint64, sync_cost, ORM_OUTPUT_STACK)           \
    FTL_TFIELD_INT(ctx, ci_int64,  max_frc_diff, ORM_OUTPUT_STACK)        \
    FTL_TFIELD_INT(ctx, ci_uint64, sync_ns, ORM_OUTPUT_STACK)             \
    FTL_TFIELD_INT(ctx, ci_uint32, proc_delay_max, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_INT(ctx, ci_uint32, proc_delay_min, ORM_OUTPUT_STACK)      \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_uint32, proc_delay_hist,                \
                          CI_CFG_PROC_DELAY_BUCKETS, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_INT(ctx, ci_uint32, proc_delay_negative, ORM_OUTPUT_STACK) \
  )                                                                       \
  FTL_TSTRUCT_END(ctx)



#define STRUCT_USER_PTR(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_user_ptr_t, )                                   \
    FTL_TFIELD_INT(ctx, ci_uint64, ptr, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                        \
    FTL_TSTRUCT_END(ctx)


#define UNION_SLEEP_SEQ(ctx)                                            \
  FTL_TUNION_BEGIN(ctx, ci_sleep_seq_t,)                                \
  FTL_TFIELD_INT(ctx, ci_uint64, all, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
  FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, rw, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_uint32, rw, rx)        \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_uint32, rw, tx)        \
  FTL_TFIELD_ANON_STRUCT_END(ctx, rw)                   \
  FTL_TUNION_END(ctx)



#define STRUCT_WAITABLE(ctx)					     	      \
    FTL_TSTRUCT_BEGIN(ctx, citp_waitable, )                                   \
    FTL_TFIELD_INT(ctx, ci_int32, bufid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                       \
    FTL_TFIELD_INT(ctx, ci_uint32, state, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                      \
    FTL_TFIELD_STRUCT(ctx, ci_sleep_seq_t, sleep_seq, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_INT(ctx, ci_uint64, spin_cycles, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
    FTL_TFIELD_INT(ctx, ci_uint32, wake_request, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
    FTL_TFIELD_INT(ctx, ci_uint32, sb_flags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    FTL_TFIELD_INT(ctx, ci_uint32, sb_aflags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
    FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_link, post_poll_link, ORM_OUTPUT_EXTRA)  \
    FTL_TFIELD_INT(ctx, oo_waitable_lock, lock, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
    FTL_TFIELD_INT(ctx, ci_int32, wt_next, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_INT(ctx, ci_int32, next_id, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_INT(ctx, ci_uint32, ready_lists_in_use, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_INT(ctx, oo_p, epoll, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
    FTL_TFIELD_INT(ctx, ci_int32, sigown, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_INT(ctx, ci_uint32, moved_to_stack_id, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_INT(ctx, ci_int32, moved_to_sock_id, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_ETHER_HDR(ctx)						      \
    FTL_TSTRUCT_BEGIN(ctx, ci_ether_hdr, )                                    \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_uint8, ether_dhost, ETH_ALEN, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_uint8, ether_shost, ETH_ALEN, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INTBE16(ctx, ether_type, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                         \
    FTL_TSTRUCT_END(ctx)

#define IP4_FRAG_OFFSET(ip_frag_off_be16)               \
  (unsigned) (CI_BSWAP_BE16(ip_frag_off_be16 & CI_IP4_OFFSET_MASK)) << 3

#define STRUCT_IP4_HDR(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip4_hdr, )                                      \
    FTL_TFIELD_INT(ctx, ci_uint8, ip_ihl_version, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INT(ctx, ci_uint8, ip_tos, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                         \
    FTL_TFIELD_INTBE16(ctx, ip_tot_len_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INTBE16(ctx, ip_id_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INTBE(ctx, ci_uint16, ip_frag_off_be16, "%u", IP4_FRAG_OFFSET, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INT(ctx, ci_uint8, ip_ttl, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                         \
    FTL_TFIELD_INT(ctx, ci_uint8, ip_protocol, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    FTL_TFIELD_INTBE16(ctx, ip_check_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_IPADDR(ctx, ip_saddr_be32, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_IPADDR(ctx, ip_daddr_be32, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TSTRUCT_END(ctx)

#define UNION_IPX_HDR(ctx)                                  \
  FTL_TUNION_BEGIN(ctx, ci_ipx_hdr_t,)                      \
  FTL_TFIELD_STRUCT(ctx, ci_ip4_hdr, ip4, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TUNION_END(ctx)
  

#define STRUCT_UDP_HDR(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_udp_hdr, )                                      \
    FTL_TFIELD_PORT(ctx, udp_source_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_PORT(ctx, udp_dest_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INTBE16(ctx, udp_len_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
    FTL_TFIELD_INTBE16(ctx, udp_check_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP4_PSEUDO_HDR(ctx)                                      \
  FTL_TSTRUCT_BEGIN(ctx, ci_ip4_pseudo_hdr, )                           \
  FTL_TFIELD_IPADDR(ctx, ip_saddr_be32, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_IPADDR(ctx, ip_daddr_be32, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_uint8, zero, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
  FTL_TFIELD_INT(ctx, ci_uint8, ip_protocol, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
  FTL_TFIELD_INTBE16(ctx, length_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_CICP_VERINFO(ctx)                                              \
    FTL_TSTRUCT_BEGIN(ctx, cicp_verinfo_t, )                                    \
    FTL_TFIELD_INT(ctx, ci_uint32, version, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))\
    FTL_TFIELD_INT(ctx, ci_int32, id, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_PMTU_STATE(ctx)                                                \
    FTL_TSTRUCT_BEGIN(ctx, ci_pmtu_state_t, )                                 \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer, tid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INT(ctx, ci_uint16, pmtu, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
    FTL_TFIELD_INT(ctx, ci_uint8, plateau_id, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_ATOMIC(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_atomic_t, )                                     \
    FTL_TFIELD_INT(ctx, int, n, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                                  \
    FTL_TSTRUCT_END(ctx)


#define STRUCT_IP_HDRS(ctx)                                                   \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_cached_hdrs, )                               \
    FTL_TFIELD_STRUCT(ctx, cicp_verinfo_t,             \
		      fwd_ver, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_PORT(ctx, dport_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INT(ctx, ci_int8, status, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))       \
    FTL_TFIELD_INT(ctx, ci_uint8, flags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))       \
    FTL_TFIELD_IPXADDR(ctx, nexthop, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INT(ctx, ci_mtu_t, mtu, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
    FTL_TFIELD_INT(ctx, ci_ifid_t, ifindex, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_INT(ctx, cicp_encap_t, encap, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_INT(ctx, ci_int16, intf_i, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))            \
    FTL_TFIELD_INT(ctx, ci_ifid_t, iif_ifindex, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))            \
    FTL_TFIELD_INT(ctx, ci_hwport_id_t, hwport, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))            \
    FTL_TFIELD_INT(ctx, ci_uint8, ether_offset, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))            \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_uint8, ether_header,     \
			  2 * ETH_ALEN + 4, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))				      \
    FTL_TFIELD_INTBE16(ctx, ether_type, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
    FTL_TFIELD_STRUCT(ctx, ci_ipx_hdr_t, ipx, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TSTRUCT_END(ctx)


#define STRUCT_TCP_HDR(ctx)                                                   \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_hdr, )                                      \
    FTL_TFIELD_PORT(ctx, tcp_source_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_PORT(ctx, tcp_dest_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INTBE32(ctx, tcp_seq_be32, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INTBE32(ctx, tcp_ack_be32, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INT(ctx, ci_uint8, tcp_hdr_len_sl4, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_INT(ctx, ci_uint8, tcp_flags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                      \
    FTL_TFIELD_INTBE16(ctx, tcp_window_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_INTBE16(ctx, tcp_check_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_INTBE16(ctx, tcp_urg_ptr_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
    FTL_TSTRUCT_END(ctx)

typedef struct oo_timeval oo_timeval;

#define STRUCT_TIMEVAL(ctx)                             \
    FTL_TSTRUCT_BEGIN(ctx, oo_timeval, )                \
    FTL_TFIELD_INT(ctx, ci_int32, tv_sec, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
    FTL_TFIELD_INT(ctx, ci_int32, tv_usec, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
    FTL_TSTRUCT_END(ctx)

typedef struct oo_sock_cplane oo_sock_cplane_t;

#define STRUCT_SOCK_CPLANE(ctx)                                         \
  FTL_TSTRUCT_BEGIN(ctx, oo_sock_cplane_t, )                            \
  FTL_TFIELD_IPXADDR(ctx, laddr, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_PORT(ctx, lport_be16, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  ON_CI_CFG_IPV6(                                                                              \
    FTL_TFIELD_INT(ctx, ci_int16, hop_limit, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
  )                                                                                            \
  FTL_TFIELD_INT(ctx, ci_ifid_t, so_bindtodevice, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  FTL_TFIELD_INT(ctx, ci_ifid_t, ip_multicast_if, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  FTL_TFIELD_IPADDR(ctx, ip_multicast_if_laddr_be32, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_int16, ip_ttl, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
  FTL_TFIELD_INT(ctx, ci_uint8, ip_mcast_ttl, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
  FTL_TFIELD_INT(ctx, ci_uint8, ip_tos, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
  ON_CI_CFG_IPV6(                                                                              \
    FTL_TFIELD_INT(ctx, ci_uint8, tclass, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
  )                                                                                            \
  FTL_TFIELD_INT(ctx, ci_uint8, sock_cp_flags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
  FTL_TSTRUCT_END(ctx)


#define STRUCT_SOCK(ctx)                                                \
  FTL_TSTRUCT_BEGIN(ctx, ci_sock_cmn, )                                 \
  FTL_TFIELD_STRUCT(ctx, citp_waitable, b, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
  FTL_TFIELD_INT(ctx, ci_uint32, s_flags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
  FTL_TFIELD_INT(ctx, ci_uint32, s_aflags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
  FTL_TFIELD_IPXADDR(ctx, laddr, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_STRUCT(ctx, oo_sock_cplane_t, cp, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
  FTL_TFIELD_STRUCT(ctx, ci_ip_cached_hdrs, pkt, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))           \
  FTL_TFIELD_ANON_UNION_BEGIN(ctx, space_for_hdrs, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
  FTL_TFIELD_ANON_UNION(ctx, ci_tcp_hdr, space_for_hdrs, space_for_tcp_hdr) \
  FTL_TFIELD_ANON_UNION(ctx, ci_udp_hdr, space_for_hdrs, space_for_udp_hdr) \
  FTL_TFIELD_ANON_UNION_END(ctx, space_for_hdrs)           \
  FTL_TFIELD_INT(ctx, ci_uint16, tx_errno, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
  FTL_TFIELD_INT(ctx, ci_uint16, rx_errno, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
  FTL_TFIELD_INT(ctx, ci_uint32, os_sock_status, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))           \
  FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, so, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_int32, so, sndbuf)        \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_int32, so, rcvbuf)        \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_uint32, so, rcvtimeo_msec) \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_uint32, so, sndtimeo_msec) \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_uint32, so, linger)       \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_int32, so, rcvlowat)      \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_int32, so, so_debug)      \
  FTL_TFIELD_ANON_STRUCT_END(ctx, so)                      \
  FTL_TFIELD_INT(ctx, ci_pkt_priority_t, so_priority, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
  FTL_TFIELD_INT(ctx, ci_int32, so_error, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
  FTL_TFIELD_INT(ctx, ci_ifid_t, rx_bind2dev_ifindex, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))       \
  FTL_TFIELD_INT(ctx, cicp_hwport_mask_t, rx_bind2dev_hwports, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
  FTL_TFIELD_INT(ctx, ci_int16, rx_bind2dev_vlan, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
  FTL_TFIELD_INT(ctx, ci_uint16, cmsg_flags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
  ON_CI_CFG_TIMESTAMPING( \
    FTL_TFIELD_INT(ctx, ci_uint32, timestamping_flags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TFIELD_INT(ctx, ci_uint32, ts_key, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
  ) \
  FTL_TFIELD_INT(ctx, ci_uint32, uuid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                      \
  FTL_TFIELD_INT(ctx, ci_int32, pid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                       \
  FTL_TFIELD_INT(ctx, ci_uint8, domain, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
  FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_link, reap_link, ORM_OUTPUT_EXTRA)     \
  FTL_TSTRUCT_END(ctx)
    
#define STRUCT_IP_PKT_QUEUE(ctx)                                              \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_pkt_queue, )                                 \
    FTL_TFIELD_INT(ctx, ci_int32, head, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                      \
    FTL_TFIELD_INT(ctx, ci_int32, tail, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                      \
    FTL_TFIELD_INT(ctx, ci_int32, num, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                       \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_OO_PKTQ(ctx)                             \
    FTL_TSTRUCT_BEGIN(ctx, oo_pktq, )                   \
    FTL_TFIELD_INT(ctx, ci_int32, head, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
    FTL_TFIELD_INT(ctx, ci_int32, tail, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
    FTL_TFIELD_INT(ctx, ci_int32, num, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP_SOCKET_STATS(ctx)                                    \
  FTL_TSTRUCT_BEGIN(ctx, ci_udp_socket_stats, )                         \
  FTL_TFIELD_INT(ctx, ci_uint32, n_rx_os, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
  FTL_TFIELD_INT(ctx, ci_uint32, n_rx_os_slow, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  FTL_TFIELD_INT(ctx, ci_uint32, n_rx_os_error, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TFIELD_INT(ctx, ci_uint32, n_rx_eagain, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
  FTL_TFIELD_INT(ctx, ci_uint32, n_rx_overflow, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TFIELD_INT(ctx, ci_uint32, n_rx_mem_drop, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TFIELD_INT(ctx, ci_uint32, n_rx_pktinfo, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  FTL_TFIELD_INT(ctx, ci_uint32, max_recvq_pkts, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_os, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_os_slow, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_onload_c, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_onload_uc, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_cp_match, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_cp_uc_lookup, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_cp_c_lookup, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_cp_a_lookup, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_cp_no_mac, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_lock_poll, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_lock_pkt, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_lock_snd, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_lock_cp, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_lock_defer, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_eagain, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_spin, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_block, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))       \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_poll_avoids_full, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_fragments, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_msg_confirm, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_os_late, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  FTL_TFIELD_INT(ctx, ci_uint32, n_tx_unconnect_late, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TSTRUCT_END(ctx)

typedef struct oo_tcp_socket_stats oo_tcp_socket_stats;

#define STRUCT_TCP_SOCKET_STATS(ctx)                                    \
  FTL_TSTRUCT_BEGIN(ctx, oo_tcp_socket_stats, )                         \
  FTL_TFIELD_INT(ctx, ci_uint64, rx_pkts, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_stop_rwnd, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_stop_cwnd, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_stop_more, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_stop_nagle, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_stop_app, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
  ON_CI_CFG_BURST_CONTROL(                                              \
     FTL_TFIELD_INT(ctx, ci_uint32, tx_stop_burst, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
                                                                        ) \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_nomac_defer, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_defer, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_msg_warm_abort, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_msg_warm, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_tmpl_send_fast, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_tmpl_send_slow, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_uint32, rx_isn, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))           \
  FTL_TFIELD_INT(ctx, ci_uint16, tx_tmpl_active, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
  FTL_TFIELD_INT(ctx, ci_uint16, rtos, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
  FTL_TFIELD_INT(ctx, ci_uint16, fast_recovers, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TFIELD_INT(ctx, ci_uint16, rx_seq_errs, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
  FTL_TFIELD_INT(ctx, ci_uint16, rx_ack_seq_errs, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
  FTL_TFIELD_INT(ctx, ci_uint16, rx_ooo_pkts, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
  FTL_TFIELD_INT(ctx, ci_uint16, rx_ooo_fill, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
  FTL_TFIELD_INT(ctx, ci_uint16, total_retrans, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP_RECV_Q(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_udp_recv_q, )                                   \
    FTL_TFIELD_INT(ctx, ci_int32, head, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                        \
    FTL_TFIELD_INT(ctx, ci_int32, tail, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                        \
    FTL_TFIELD_INT(ctx, ci_uint32, pkts_added, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INT(ctx, ci_uint32, pkts_reaped, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_INT(ctx, ci_int32, extract, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
    FTL_TFIELD_INT(ctx, ci_uint32, pkts_delivered, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_UDP(ctx)                                                 \
  FTL_TSTRUCT_BEGIN(ctx, ci_udp_state, )                                \
  FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, s, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
  FTL_TFIELD_STRUCT(ctx, ci_ip_cached_hdrs, ephemeral_pkt, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_INT(ctx, ci_uint32, udpflags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
  ON_CI_CFG_ZC_RECV_FILTER( \
    FTL_TFIELD_INT(ctx, ci_uint64, recv_q_filter, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
    FTL_TFIELD_INT(ctx, ci_uint64, recv_q_filter_arg, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
  ) \
  FTL_TFIELD_STRUCT(ctx, ci_udp_recv_q, recv_q, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))           \
  ON_CI_CFG_TIMESTAMPING( \
    FTL_TFIELD_STRUCT(ctx, ci_udp_recv_q, timestamp_q, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
  ) \
  FTL_TFIELD_INT(ctx, ci_int32, zc_kernel_datagram, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))       \
  FTL_TFIELD_INT(ctx, ci_uint32, zc_kernel_datagram_count, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
  FTL_TFIELD_STRUCT(ctx, oo_timespec, stamp_cache, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
  FTL_TFIELD_INT(ctx, ci_uint64, stamp, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
  FTL_TFIELD_INT(ctx, ci_uint64, stamp_pre_sots, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
  FTL_TFIELD_INT(ctx, ci_int32, tx_async_q, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
  FTL_TFIELD_INT(ctx, oo_atomic_t, tx_async_q_level, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
  FTL_TFIELD_INT(ctx, ci_uint32, tx_count, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
  FTL_TFIELD_STRUCT(ctx, ci_udp_socket_stats, stats, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))      \
  FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_SOCK_STATS_COUNT(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_sock_stats_count, )                          \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rtto, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))       \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, cong, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))       \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_byte, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_pkt, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_slowpath, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))\
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_seqerr, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_ackerr, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_pawserr, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_dupack, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,             \
		   rx_dupack_frec, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,             \
		   rx_dupack_congfrec, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_zwin, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_ooo, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_badsyn, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,             \
		   rx_badsynseq, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_syndup, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,             \
                  rx_synbadack, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					              \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,             \
                   rx_synnonack, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                             		      \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_sleep, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_wait, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, tx_byte, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, tx_pkt, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, tx_slowpath, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))\
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,             \
		   tx_retrans_pkt, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, tx_sleep, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, tx_stuck, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_SOCK_STATS_RANGE(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_sock_stats_range, )                          \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_win, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rx_wscl, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, tx_win, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, tx_wscl, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rtt, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, srtt, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))       \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, rto, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE, tx_buffree, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,             \
                   tx_sleeptime, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_INT(ctx, CI_IP_STATS_TYPE,             \
		   rx_sleeptime, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))		                              \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_IP_SOCK_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_ip_sock_stats, )                                \
    FTL_TFIELD_INT(ctx, __TIME_TYPE__, now, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats_count, count, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))   \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats_range, actual, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats_range, min, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats_range, max, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_COMMON(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_socket_cmn, )                               \
    FTL_TFIELD_INT(ctx, ci_uint32, ka_probe_th, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))            \
    FTL_TFIELD_INT(ctx, ci_iptime_t, t_ka_time, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))            \
    FTL_TFIELD_INT(ctx, ci_iptime_t, t_ka_time_in_secs, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_INT(ctx, ci_iptime_t, t_ka_intvl, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TFIELD_INT(ctx, ci_iptime_t, t_ka_intvl_in_secs, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INT(ctx, ci_uint16, user_mss, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_INT(ctx, ci_uint8, tcp_defer_accept, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))	      \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_state, )                                    \
    FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, s, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                      \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_cmn, c, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_INT(ctx, ci_int32, local_peer, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    FTL_TFIELD_INT(ctx, ci_int32, tmpl_head, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    FTL_TFIELD_INT(ctx, ci_uint32, tcpflags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    FTL_TFIELD_INT(ctx, oo_p, pmtus, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
    FTL_TFIELD_INT(ctx, ci_int32, so_sndbuf_pkts, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
    FTL_TFIELD_INT(ctx, ci_uint32, rcv_window_max, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
    FTL_TFIELD_INT(ctx, ci_uint32, send_in, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_INT(ctx, ci_uint32, send_out, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
    FTL_TFIELD_STRUCT(ctx, ci_ip_pkt_queue, send, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_STRUCT(ctx, ci_ip_pkt_queue, retrans, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))            \
    FTL_TFIELD_STRUCT(ctx, ci_ip_pkt_queue, recv1, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
    FTL_TFIELD_STRUCT(ctx, ci_ip_pkt_queue, recv2, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
    FTL_TFIELD_INT(ctx, ci_int32, recv1_extract, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_INT(ctx, ci_uint16, recv_off, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    FTL_TFIELD_INT(ctx, ci_uint16, outgoing_hdrs_len, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))           \
    FTL_TFIELD_STRUCT(ctx, ci_ip_pkt_queue, rob, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_ARRAYOFINT(ctx, ci_int32, last_sack,             \
                          CI_TCP_SACK_MAX_BLOCKS + 1, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                         \
    FTL_TFIELD_INT(ctx, ci_uint32, dsack_start, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INT(ctx, ci_uint32, dsack_end, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    FTL_TFIELD_INT(ctx, ci_int32, dsack_block, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
  ON_CI_CFG_TIMESTAMPING( \
    FTL_TFIELD_STRUCT(ctx, ci_udp_recv_q, timestamp_q, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
  ) \
    FTL_TFIELD_INT(ctx, ci_uint32, snd_check, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    FTL_TFIELD_INT(ctx, ci_uint32, snd_nxt, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
    FTL_TFIELD_INT(ctx, ci_uint32, snd_max, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
    FTL_TFIELD_INT(ctx, ci_uint32, snd_una, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
    ON_CI_CFG_NOTICE_WINDOW_SHRINKAGE(                                  \
      FTL_TFIELD_INT(ctx, ci_uint32, snd_wl1, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    ) \
    FTL_TFIELD_INT(ctx, ci_uint32, snd_delegated, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_INT(ctx, ci_uint32, fast_path_check, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
    FTL_TFIELD_INT(ctx, ci_uint32, snd_up, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                      \
    FTL_TFIELD_INT(ctx, ci_uint16, amss, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                        \
    FTL_TFIELD_INT(ctx, ci_uint16, smss, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                        \
    FTL_TFIELD_INT(ctx, ci_uint16, eff_mss, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
    FTL_TFIELD_INT(ctx, ci_uint16, retransmits, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INT(ctx, ci_uint32, rcv_wnd_advertised, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
    FTL_TFIELD_INT(ctx, ci_uint32, rcv_wnd_right_edge_sent, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TFIELD_INT(ctx, ci_uint32, rcv_added, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    FTL_TFIELD_INT(ctx, ci_uint32, rcv_delivered, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_INT(ctx, ci_uint32, ack_trigger, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    ON_CI_CFG_BURST_CONTROL(                                            \
      FTL_TFIELD_INT(ctx, ci_uint32, burst_window, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_uint32, rcv_up, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                      \
    FTL_TFIELD_INT(ctx, ci_uint8, rcv_wscl, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    FTL_TFIELD_INT(ctx, ci_uint8, snd_wscl, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    FTL_TFIELD_INT(ctx, ci_uint8, congstate, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    FTL_TFIELD_INT(ctx, ci_uint32, congrecover, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INT(ctx, ci_int32, retrans_ptr, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
    FTL_TFIELD_INT(ctx, ci_uint32, retrans_seq, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INT(ctx, ci_uint32, cwnd, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                        \
    FTL_TFIELD_INT(ctx, ci_uint32, cwnd_extra, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
    FTL_TFIELD_INT(ctx, ci_uint32, ssthresh, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    FTL_TFIELD_INT(ctx, ci_uint32, bytes_acked, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INT(ctx, ci_uint8, dup_acks, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    ON_CI_CFG_TCP_FASTSTART(                                                  \
      FTL_TFIELD_INT(ctx, ci_uint32, faststart_acks, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))            \
    )                                                                         \
    ON_CI_CFG_TAIL_DROP_PROBE(                                                \
      FTL_TFIELD_INT(ctx, ci_uint32, taildrop_mark, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_iptime_t, t_prev_recv_payload, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INT(ctx, ci_iptime_t, t_last_recv_payload, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) \
    FTL_TFIELD_INT(ctx, ci_iptime_t, t_last_recv_ack, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))     \
    FTL_TFIELD_INT(ctx, ci_iptime_t, t_last_sent, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    ON_CI_CFG_CONGESTION_WINDOW_VALIDATION(                                   \
      FTL_TFIELD_INT(ctx, ci_iptime_t, t_last_full, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
      FTL_TFIELD_INT(ctx, ci_uint32, cwnd_used, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_iptime_t, sa, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                        \
    FTL_TFIELD_INT(ctx, ci_iptime_t, sv, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                        \
    FTL_TFIELD_INT(ctx, ci_iptime_t, rto, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                       \
    FTL_TFIELD_INT(ctx, ci_uint32, timed_seq, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    FTL_TFIELD_INT(ctx, ci_iptime_t, timed_ts, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
    FTL_TFIELD_INT(ctx, ci_uint32, tsrecent, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    FTL_TFIELD_INT(ctx, ci_uint32, tslastack, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    ON_DEBUG(                                                                 \
      FTL_TFIELD_INT(ctx, ci_uint32, tslastseq, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_iptime_t, tspaws, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    FTL_TFIELD_INT(ctx, ci_uint16, acks_pending, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_INT(ctx, ci_uint16, urg_data, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                    \
    FTL_TFIELD_INT(ctx, ci_uint32, ka_probes, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                   \
    FTL_TFIELD_INT(ctx, ci_uint16, zwin_probes, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
    FTL_TFIELD_INT(ctx, ci_uint16, zwin_acks, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
    FTL_TFIELD_INT(ctx, ci_uint8, incoming_tcp_hdr_len, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer, rto_tid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer, delack_tid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer, zwin_tid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer, kalive_tid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))             \
    ON_CI_CFG_TCP_SOCK_STATS(                                                 \
      FTL_TFIELD_STRUCT(ctx, ci_ip_timer, stats_tid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))            \
    )                                                                         \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer, cork_tid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    ON_CI_CFG_TCP_SOCK_STATS(                                                 \
      FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats, stats_snapshot, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
      FTL_TFIELD_STRUCT(ctx, ci_ip_sock_stats, stats_cumulative, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))\
      FTL_TFIELD_INT(ctx, ci_int32, stats_fmt, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
    )                                                                         \
    ON_CI_CFG_FD_CACHING(                                                     \
      FTL_TFIELD_INT(ctx, ci_int32, cached_on_fd, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
      FTL_TFIELD_INT(ctx, ci_int32, cached_on_pid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
      FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_link, epcache_link, ORM_OUTPUT_EXTRA)   \
      FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_link, epcache_fd_link, ORM_OUTPUT_EXTRA)\
    )                                                                         \
    FTL_TFIELD_INT(ctx, ci_int32, send_prequeue, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
    FTL_TFIELD_INT(ctx, oo_atomic_t, send_prequeue_in, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_link, timeout_q_link, ORM_OUTPUT_EXTRA)   \
    FTL_TFIELD_STRUCT(ctx, oo_tcp_socket_stats, stats, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
    FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, rcvbuf_drs, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_ANON_STRUCT(ctx, ci_uint32, rcvbuf_drs, bytes)                                            \
    FTL_TFIELD_ANON_STRUCT(ctx, ci_uint32, rcvbuf_drs, seq)                                              \
    FTL_TFIELD_ANON_STRUCT(ctx, ci_uint32, rcvbuf_drs, time)                                             \
    FTL_TFIELD_ANON_STRUCT_END(ctx, read_ptr)                                                            \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_SOCKET_LISTEN_STATS(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_socket_listen_stats, )                      \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_listenq_overflow, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_listenq_no_synrecv, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))				      \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_acks_reset, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_acceptq_overflow, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_acceptq_no_sock, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_acceptq_no_pkts, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					      \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_accept_loop2_closed, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))				      \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_accept_os, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))					              \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_accept_no_fd, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))				              \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_syncookie_syn, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))				              \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_syncookie_ack_recv, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                                      \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_syncookie_ack_ts_rej, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))			              \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_syncookie_ack_hash_rej, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))			              \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_syncookie_ack_answ, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))			              \
    ON_CI_CFG_FD_CACHING(						      \
      FTL_TFIELD_INT(ctx, ci_uint32,              \
  		   n_sockcache_hit, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))				              \
    ) \
    FTL_TFIELD_INT(ctx, ci_uint32,                \
		   n_rx_pkts, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                               \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_TCP_LISTEN(ctx) \
    FTL_TSTRUCT_BEGIN(ctx, ci_tcp_socket_listen, )                            \
    FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, s, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_cmn, c, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
    FTL_TFIELD_INT(ctx, ci_uint32, acceptq_max, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))         \
    FTL_TFIELD_INT(ctx, ci_int32, acceptq_put, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
    FTL_TFIELD_INT(ctx, ci_uint32, acceptq_n_in, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
    FTL_TFIELD_INT(ctx, ci_int32, acceptq_get, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))          \
    FTL_TFIELD_INT(ctx, ci_uint32, acceptq_n_out, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))       \
    FTL_TFIELD_INT(ctx, ci_int32, n_listenq, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))            \
    FTL_TFIELD_INT(ctx, ci_int32, n_listenq_new, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
    FTL_TFIELD_ARRAYOFSTRUCT(ctx, ci_ni_dllist_t,       \
			     listenq, CI_CFG_TCP_SYNACK_RETRANS_MAX + 1, ORM_OUTPUT_EXTRA, 1)    \
    FTL_TFIELD_INT(ctx, ci_int32, bucket, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))               \
    FTL_TFIELD_INT(ctx, ci_uint32, n_buckets, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))           \
    ON_CI_CFG_FD_CACHING(                                                     \
      FTL_TFIELD_STRUCT(ctx, ci_socket_cache_t, epcache, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))\
      FTL_TFIELD_STRUCT(ctx, ci_ni_dllist_t,            \
		        epcache_connected, ORM_OUTPUT_EXTRA)				      \
      FTL_TFIELD_INT(ctx, ci_uint32, cache_avail_sock, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))  \
    )                                                                         \
    FTL_TFIELD_STRUCT(ctx, ci_ip_timer, listenq_tid, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))    \
    ON_CI_CFG_STATS_TCP_LISTEN(  				              \
      FTL_TFIELD_STRUCT(ctx, ci_tcp_socket_listen_stats,\
			stats, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))           			              \
    )                                                                         \
    FTL_TSTRUCT_END(ctx)

#define STRUCT_WAITABLE_OBJ(ctx)				              \
    FTL_TSTRUCT_BEGIN(ctx, citp_waitable_obj, )                               \
    FTL_TFIELD_STRUCT(ctx, citp_waitable, waitable, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
    FTL_TFIELD_STRUCT(ctx, ci_sock_cmn, sock, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
    FTL_TFIELD_STRUCT(ctx, ci_tcp_state, tcp, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))              \
    FTL_TSTRUCT_END(ctx)
    

#define STRUCT_FILTER_TABLE_ENTRY_FAST(ctx)                                   \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_filter_table_entry_fast, )       \
    FTL_TFIELD_INT(ctx, ci_uint32, __id_and_state, ORM_OUTPUT_STACK) \
    FTL_TFIELD_INT(ctx, ci_uint32, laddr, ORM_OUTPUT_STACK)          \
    FTL_TSTRUCT_END(ctx)


#define STRUCT_FILTER_TABLE_ENTRY_EXT(ctx)                                    \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_filter_table_entry_ext, )      \
    FTL_TFIELD_INT(ctx, ci_int32, route_count, ORM_OUTPUT_STACK)   \
    FTL_TSTRUCT_END(ctx)


#define STRUCT_FILTER_TABLE(ctx)                                              \
    FTL_TSTRUCT_BEGIN(ctx, ci_netif_filter_table, )                           \
    FTL_TFIELD_INT(ctx, unsigned, table_size_mask, ORM_OUTPUT_STACK)    \
    FTL_TFIELD_ARRAYOFSTRUCT(ctx, \
			     ci_netif_filter_table_entry_fast, table, 1, ORM_OUTPUT_STACK, 1) \
    FTL_TSTRUCT_END(ctx)
    
#define STRUCT_OO_PIPE_BUF_LIST_T(ctx)                            \
  FTL_TSTRUCT_BEGIN(ctx, oo_pipe_buf_list_t, )                    \
  FTL_TFIELD_INT(ctx, ci_int32, pp, ORM_OUTPUT_STACK)           \
  FTL_TSTRUCT_END(ctx)

typedef struct oo_pipe oo_pipe;

#define STRUCT_OO_PIPE(ctx)                                             \
  FTL_TSTRUCT_BEGIN(ctx, oo_pipe, )                                     \
  FTL_TFIELD_STRUCT(ctx, citp_waitable, b, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
  FTL_TFIELD_STRUCT(ctx, oo_pipe_buf_list_t, pipe_bufs, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))        \
  FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, read_ptr, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
  FTL_TFIELD_ANON_STRUCT(ctx, oo_pkt_p, read_ptr, pp)          \
  FTL_TFIELD_ANON_STRUCT(ctx, ci_uint32, read_ptr, offset)     \
  FTL_TFIELD_ANON_STRUCT_END(ctx, read_ptr)                    \
  FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, write_ptr, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                 \
  FTL_TFIELD_ANON_STRUCT(ctx, oo_pkt_p, write_ptr, pp)         \
  FTL_TFIELD_ANON_STRUCT(ctx, oo_pkt_p, write_ptr, pp_wait)    \
  FTL_TFIELD_ANON_STRUCT_END(ctx, write_ptr)                   \
  FTL_TFIELD_INT(ctx, ci_uint32, aflags, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                       \
  FTL_TFIELD_INT(ctx, ci_uint32, bufs_num, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
  FTL_TFIELD_INT(ctx, ci_uint32, bufs_max, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                     \
  FTL_TFIELD_INT(ctx, ci_uint32, bytes_added, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                  \
  FTL_TFIELD_INT(ctx, ci_uint32, bytes_removed, (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS))                \
  FTL_TSTRUCT_END(ctx)


#endif /* __FTL_DEFS_H__ */
