/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  stg
**  \brief  UL netif statistics reporting
**   \date  2004/07/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */

  
#include "ip_internal.h"


#if CI_CFG_SUPPORT_STATS_COLLECTION


/*! Manage the statistics timer.  
 * If the time is 0 the timer will be  killed. 
 * If the value is other than 0 then:
 *   If the timer is pending it will be modified
 *   else it will be set
 */
ci_inline void
ci_netif_stats_handle_timer(ci_netif* ni, ci_iptime_t timeout)
{
  ci_ip_timer* it;
  ci_assert( ni );
  it = &ni->state->stats_tid;

  LOG_STATS( ci_log( "%s( %p, %d)", __FUNCTION__, ni, (int)timeout));
  if( ci_ip_timer_pending(ni, it ) ) {
    if( timeout == 0 )
          ci_ip_timer_clear(ni, it );
        else
          ci_ip_timer_modify(ni, it, ci_tcp_time_now(ni)+timeout);
  } else {
        if( timeout != 0 ) 
          ci_ip_timer_set(ni, it, ci_tcp_time_now(ni)+timeout);
  }
}


/* called to setup the UL stack statistics/logging */
void
ci_netif_stats_init(ci_netif* ni)
{
  int val;

  ci_assert( ni );
  LOG_STATS( ci_log("%s(%p)", __FUNCTION__, ni));

  val = CI_TCONST_STATS; /* mS */

  NI_CONF(ni).tconst_stats = val ? ci_tcp_time_ms2ticks(ni, val) : 0;
  
  LOG_STATS( ci_log("Statistics: %u ticks, %dmS ",
                                        NI_CONF(ni).tconst_stats, val ));

  ci_ip_stats_clear(&ni->state->stats_cumulative);
  ci_ip_stats_clear(&ni->state->stats_snapshot);

  /* Setting the timeout to -1 implies collection through sockopt */
  if( val )
    ci_netif_stats_action( ni, CI_IP_STATS_START,
        CI_IP_STATS_OUTPUT_DEFAULT, NULL, NULL );
}


/* Update the cumulative statistics from the snapshot */
static void
ci_netif_stats_update_netif( ci_netif *ni)
{
  if (ni->state->stats_cumulative.now <= ni->state->stats_snapshot.now) {
    ni->state->stats_cumulative.now = ni->state->stats_snapshot.now;
  } else {
    LOG_STATS( ci_log("Cummulative stats have bigger timestamp than snaphot") );
  }
  ci_ip_stats_update(&ni->state->stats_cumulative, &ni->state->stats_snapshot);
  ci_ip_stats_clear(&ni->state->stats_snapshot);
}

#define __SS(netif) (netif)->state->stats_snapshot
#define __CU(netif) (netif)->state->stats_cumulative

#if CI_CFG_SEND_STATS_TO_LOG
#define __TEXT_NETIF_COUNT_FMT "%s %u/%u"
#else
#define __TEXT_NETIF_COUNT_FMT "%s %u/%u\n"
#endif

#define __TEXT_NETIF_COUNT(s, Grp, Fld) \
  __SS(netif).Grp.Fld, \
  __CU(netif).Grp.Fld

#if CI_CFG_SEND_STATS_TO_LOG
#define __TEXT_NETIF_LOG  ci_log
#else
#define __TEXT_NETIF_LOG(x...) \
  if (len < count) { \
    len += snprintf(buf + len, count - len, x); \
  }
#endif

#define __TEXT_NETIF_COUNT_LOG(name, group, field) \
  __TEXT_NETIF_LOG(__TEXT_NETIF_COUNT_FMT, \
                   (name), __TEXT_NETIF_COUNT(netif, group, field))


/* generate statistics report in text format and store it to buffer */
static int
ci_netif_stats_report_text(ci_netif *netif, char *buf, int count)
{
#if CI_CFG_SEND_STATS_TO_LOG==0
  int len = 0;

  if (count <= 0)
    return 0;
#endif  

  /* IP statistics */
  __TEXT_NETIF_COUNT_LOG("In_recvs:", ip,
                         in_recvs);
  __TEXT_NETIF_COUNT_LOG("In_hdr_errs:", ip,
                         in_hdr_errs);
  __TEXT_NETIF_COUNT_LOG("In_discards:", ip,
                         in_discards);
  __TEXT_NETIF_COUNT_LOG("In_delivers:", ip,
                         in_delivers);
#if CI_CFG_IPV6
  __TEXT_NETIF_COUNT_LOG("In6_recvs:", ip,
                         in6_recvs);
  __TEXT_NETIF_COUNT_LOG("In6_hdr_errs:", ip,
                         in6_hdr_errs);
  __TEXT_NETIF_COUNT_LOG("In6_discards:", ip,
                         in6_discards);
  __TEXT_NETIF_COUNT_LOG("In6_delivers:", ip,
                         in6_delivers);
#endif

  /* TCP statistics */
  __TEXT_NETIF_COUNT_LOG("Tcp_active_opens:", tcp,
                         tcp_active_opens);
  __TEXT_NETIF_COUNT_LOG("Tcp_passive_opens:", tcp,
                         tcp_passive_opens);
  __TEXT_NETIF_COUNT_LOG("Tcp_estab_resets:", tcp,
                         tcp_estab_resets);
  __TEXT_NETIF_COUNT_LOG("Tcp_curr_estab:", tcp,
                         tcp_curr_estab);
  __TEXT_NETIF_COUNT_LOG("Tcp_in_segs:", tcp,
                         tcp_in_segs);
  __TEXT_NETIF_COUNT_LOG("Tcp_out_segs:", tcp,
                         tcp_out_segs);
  __TEXT_NETIF_COUNT_LOG("Tcp_retran_segs:", tcp,
                         tcp_retran_segs);
  __TEXT_NETIF_COUNT_LOG("Tcp_out_rsts:", tcp,
                         tcp_out_rsts);
  /* UDP statistics */
  __TEXT_NETIF_COUNT_LOG("Udp_in_dgrams:", udp,
                         udp_in_dgrams);
  __TEXT_NETIF_COUNT_LOG("Udp_no_ports:", udp,
                         udp_no_ports);
  __TEXT_NETIF_COUNT_LOG("Udp_in_errs:", udp,
                         udp_in_errs);
  __TEXT_NETIF_COUNT_LOG("Udp_out_dgrams:", udp,
                         udp_out_dgrams);
  /* statistics from /proc/net/netstat */
  __TEXT_NETIF_COUNT_LOG("Syncookies_sent", tcp_ext,
      syncookies_sent);
  __TEXT_NETIF_COUNT_LOG("Syncookies_recv", tcp_ext,
      syncookies_recv);
  __TEXT_NETIF_COUNT_LOG("Syncookies_failed", tcp_ext,
      syncookies_failed);
  __TEXT_NETIF_COUNT_LOG("Embrionic_rsts", tcp_ext,
      embrionic_rsts);
  __TEXT_NETIF_COUNT_LOG("Prune_called", tcp_ext,
      prune_called);
  __TEXT_NETIF_COUNT_LOG("Rcv_pruned", tcp_ext,
      rcv_pruned);
  __TEXT_NETIF_COUNT_LOG("Ofo_pruned", tcp_ext,
      ofo_pruned);
  __TEXT_NETIF_COUNT_LOG("Out_of_window_icmps", tcp_ext,
      out_of_window_icmps);
  __TEXT_NETIF_COUNT_LOG("Lock_dropped_icmps", tcp_ext,
      lock_dropped_icmps);
  __TEXT_NETIF_COUNT_LOG("Arp_filter", tcp_ext,
      arp_filter);
  __TEXT_NETIF_COUNT_LOG("Time_waited", tcp_ext,
      time_waited);
  __TEXT_NETIF_COUNT_LOG("Time_wait_recycled", tcp_ext,
      time_wait_recycled);
  __TEXT_NETIF_COUNT_LOG("Time_wait_killed", tcp_ext,
      time_wait_killed);
  __TEXT_NETIF_COUNT_LOG("Paws_passive_rejected", tcp_ext,
      paws_passive_rejected);
  __TEXT_NETIF_COUNT_LOG("Paws_active_rejected", tcp_ext,
      paws_active_rejected);
  __TEXT_NETIF_COUNT_LOG("Paws_estab_rejected", tcp_ext,
      paws_estab_rejected);
  __TEXT_NETIF_COUNT_LOG("Delayed_ack", tcp_ext,
      delayed_ack);
  __TEXT_NETIF_COUNT_LOG("Delayed_ack_locked", tcp_ext,
      delayed_ack_locked);
  __TEXT_NETIF_COUNT_LOG("Delayed_ack_lost", tcp_ext,
      delayed_ack_lost);
  __TEXT_NETIF_COUNT_LOG("Listen_overflows", tcp_ext,
      listen_overflows);
  __TEXT_NETIF_COUNT_LOG("Listen_drops", tcp_ext,
      listen_drops);
  __TEXT_NETIF_COUNT_LOG("Tcp_prequeued", tcp_ext,
      tcp_prequeued);
  __TEXT_NETIF_COUNT_LOG("Tcp_direct_copy_from_backlog", tcp_ext,
      tcp_direct_copy_from_backlog);
  __TEXT_NETIF_COUNT_LOG("Tcp_direct_copy_from_prequeue", tcp_ext,
      tcp_direct_copy_from_prequeue);
  __TEXT_NETIF_COUNT_LOG("Tcp_prequeue_dropped", tcp_ext,
      tcp_prequeue_dropped);
  __TEXT_NETIF_COUNT_LOG("Tcp_hp_hits", tcp_ext,
      tcp_hp_hits);
  __TEXT_NETIF_COUNT_LOG("Tcp_hp_hits_to_user", tcp_ext,
      tcp_hp_hits_to_user);
  __TEXT_NETIF_COUNT_LOG("Tcp_pure_acks", tcp_ext,
      tcp_pure_acks);
  __TEXT_NETIF_COUNT_LOG("Tcp_hp_acks", tcp_ext,
      tcp_hp_acks);
  __TEXT_NETIF_COUNT_LOG("Tcp_reno_recovery", tcp_ext,
      tcp_reno_recovery);
  __TEXT_NETIF_COUNT_LOG("Tcp_sack_recovery", tcp_ext,
      tcp_sack_recovery);
  __TEXT_NETIF_COUNT_LOG("Tcp_sack_reneging", tcp_ext,
      tcp_sack_reneging);
  __TEXT_NETIF_COUNT_LOG("Tcp_fack_reorder", tcp_ext,
      tcp_fack_reorder);
  __TEXT_NETIF_COUNT_LOG("Tcp_sack_reorder", tcp_ext,
      tcp_sack_reorder);
  __TEXT_NETIF_COUNT_LOG("Tcp_reno_reorder", tcp_ext,
      tcp_reno_reorder);
  __TEXT_NETIF_COUNT_LOG("Tcp_ts_reorder", tcp_ext,
      tcp_ts_reorder);
  __TEXT_NETIF_COUNT_LOG("Tcp_full_undo", tcp_ext,
      tcp_full_undo);
  __TEXT_NETIF_COUNT_LOG("Tcp_partial_undo", tcp_ext,
      tcp_partial_undo);
  __TEXT_NETIF_COUNT_LOG("Tcp_loss_undo", tcp_ext,
      tcp_loss_undo);
  __TEXT_NETIF_COUNT_LOG("Tcp_sack_undo", tcp_ext,
      tcp_sack_undo);
  __TEXT_NETIF_COUNT_LOG("Tcp_loss", tcp_ext,
      tcp_loss);
  __TEXT_NETIF_COUNT_LOG("Tcp_lost_retransmit", tcp_ext,
      tcp_lost_retransmit);
  __TEXT_NETIF_COUNT_LOG("Tcp_reno_failures", tcp_ext,
      tcp_reno_failures);
  __TEXT_NETIF_COUNT_LOG("Tcp_sack_failures", tcp_ext,
      tcp_sack_failures);
  __TEXT_NETIF_COUNT_LOG("Tcp_loss_failures", tcp_ext,
      tcp_loss_failures);
  __TEXT_NETIF_COUNT_LOG("Tcp_timeouts", tcp_ext,
      tcp_timeouts);
  __TEXT_NETIF_COUNT_LOG("Tcp_reno_recovery_fail", tcp_ext,
      tcp_reno_recovery_fail);
  __TEXT_NETIF_COUNT_LOG("Tcp_sack_recovery_fail", tcp_ext,
      tcp_sack_recovery_fail);
  __TEXT_NETIF_COUNT_LOG("Tcp_fast_retrans", tcp_ext,
      tcp_fast_retrans);
  __TEXT_NETIF_COUNT_LOG("Tcp_forward_retrans", tcp_ext,
      tcp_forward_retrans);
  __TEXT_NETIF_COUNT_LOG("Tcp_slow_start_retrans", tcp_ext,
      tcp_slow_start_retrans);
  __TEXT_NETIF_COUNT_LOG("Tcp_scheduler_failures", tcp_ext,
      tcp_scheduler_failures);
  __TEXT_NETIF_COUNT_LOG("Tcp_rcv_collapsed", tcp_ext,
      tcp_rcv_collapsed);
  __TEXT_NETIF_COUNT_LOG("Tcp_dsack_old_sent", tcp_ext,
      tcp_dsack_old_sent);
  __TEXT_NETIF_COUNT_LOG("Tcp_dsack_ofo_sent", tcp_ext,
      tcp_dsack_ofo_sent);
  __TEXT_NETIF_COUNT_LOG("Tcp_dsack_recv", tcp_ext,
      tcp_dsack_recv);
  __TEXT_NETIF_COUNT_LOG("Tcp_dsack_ofo_recv", tcp_ext,
      tcp_dsack_ofo_recv);
  __TEXT_NETIF_COUNT_LOG("Tcp_abort_on_syn", tcp_ext,
      tcp_abort_on_syn);
  __TEXT_NETIF_COUNT_LOG("Tcp_abort_on_data", tcp_ext,
      tcp_abort_on_data);
  __TEXT_NETIF_COUNT_LOG("Tcp_abort_on_close", tcp_ext,
      tcp_abort_on_close);
  __TEXT_NETIF_COUNT_LOG("Tcp_abort_on_memory", tcp_ext,
      tcp_abort_on_memory);
  __TEXT_NETIF_COUNT_LOG("Tcp_abort_on_timeout", tcp_ext,
      tcp_abort_on_timeout);
  __TEXT_NETIF_COUNT_LOG("Tcp_abort_on_linger", tcp_ext,
      tcp_abort_on_linger);
  __TEXT_NETIF_COUNT_LOG("Tcp_abort_failed", tcp_ext,
      tcp_abort_failed);
  __TEXT_NETIF_COUNT_LOG("Tcp_memory_pressures", tcp_ext,
      tcp_memory_pressures);

#if CI_CFG_SEND_STATS_TO_LOG==0
  if (len == count)
    len--;

  buf[len++] = '\0';

  return len;
#else
  return 0;
#endif
}


#define __XML_NETIF_DATASTART_FMT \
  "<record>\n" \
  " <snapshot_time>%u</snapshot_time>\n" \
  " <cumulative_time>%u</cumulative_time>\n"

#define __XML_NETIF_DATASTART(st) \
  (st)->state->stats_snapshot.now, (st)->state->stats_cumulative.now

#define __XML_NETIF_DATAEND_FMT "</record>\n"

#define __XML_NETIF_COUNT_FMT \
  "  <entry type=\"C\" name=\"%s\">\n" \
  "    <snapshot val=\"%u\"/>\n" \
  "    <cumulative val=\"%u\"/>\n" \
  "  </entry>\n"

#define __XML_NETIF_COUNT(netif, group, field) \
  __SS(netif).group.field, \
  __CU(netif).group.field

  
#define __XML_NETIF_RANGE_FMT \
  "  <entry type=\"R\" name=\"%s\">\n" \
  "    <snapshot val=\"%u\" min=\"%u\" max=\"%u\"/>\n" \
  "    <cumulative val=\"%u\" min=\"%u\" max=\"%u\"/>\n" \
  "  </entry>\n"

#define __XML_NETIF_RANGE(name, netif, group, field)  (name), \
  __SS(netif).group.actual.field, \
  __SS(netif).group.min.field, \
  __SS(netif).group.max.field, \
  __CU(netif).group.actual.field, \
  __CU(netif).group.min.field, \
  __CU(netif).group.max.field

#if CI_CFG_SEND_STATS_TO_LOG
#define __XML_NETIF_LOG ci_log
#else
#define __XML_NETIF_LOG(x...) \
  if (len < count) { \
    len += snprintf(buf + len, count - len, x); \
  }
#endif

#define __XML_NETIF_COUNT_LOG(name, group, field) \
  __XML_NETIF_LOG( __XML_NETIF_COUNT_FMT, \
                   (name), __XML_NETIF_COUNT(netif, group, field))

#define __XML_NETIF_RANGE_LOG(name, group, field) \
  __XML_NETIF_LOG( __XML_NETIF_RANGE_FMT, \
                   (name), __XML_NETIF_RANGE(netif, group, field))


/* generate statistics report in xml format and store it to buffer */
static int
ci_netif_stats_report_xml(ci_netif* netif, char *buf, int count)
{
  int len = 0;
  
  if (count <= 0)
    return 0;
  
  __XML_NETIF_LOG( __XML_NETIF_DATASTART_FMT, __XML_NETIF_DATASTART(netif));

  /* IP statistics */
  __XML_NETIF_COUNT_LOG("In_recvs:", ip,
                            in_recvs);
  __XML_NETIF_COUNT_LOG("In_hdr_errs:", ip,
                            in_hdr_errs);
  __XML_NETIF_COUNT_LOG("In_discards:", ip,
                            in_discards);
  __XML_NETIF_COUNT_LOG("In_delivers:", ip,
                            in_delivers);
#if CI_CFG_IPV6
  __XML_NETIF_COUNT_LOG("In6_recvs:", ip,
                            in6_recvs);
  __XML_NETIF_COUNT_LOG("In6_hdr_errs:", ip,
                            in6_hdr_errs);
  __XML_NETIF_COUNT_LOG("In6_discards:", ip,
                            in6_discards);
  __XML_NETIF_COUNT_LOG("In6_delivers:", ip,
                            in6_delivers);
#endif

  /* TCP statistics */
  __XML_NETIF_COUNT_LOG("Tcp_active_opens:", tcp,
                            tcp_active_opens);
  __XML_NETIF_COUNT_LOG("Tcp_passive_opens:", tcp,
                            tcp_passive_opens);
  __XML_NETIF_COUNT_LOG("Tcp_estab_resets:", tcp,
                            tcp_estab_resets);
  __XML_NETIF_COUNT_LOG("Tcp_curr_estab:", tcp,
                            tcp_estab_resets);
  __XML_NETIF_COUNT_LOG("Tcp_in_segs:", tcp,
                            tcp_in_segs);
  __XML_NETIF_COUNT_LOG("Tcp_out_segs:", tcp,
                            tcp_out_segs);
  __XML_NETIF_COUNT_LOG("Tcp_retran_segs:", tcp,
                            tcp_retran_segs);
  __XML_NETIF_COUNT_LOG("Tcp_out_rsts:", tcp,
                            tcp_out_rsts);
  
  /* UDP statistics */
  __XML_NETIF_COUNT_LOG("Udp_in_dgrams:", udp,
                            udp_in_dgrams);
  __XML_NETIF_COUNT_LOG("Udp_no_ports:", udp,
                            udp_no_ports);
  __XML_NETIF_COUNT_LOG("Udp_in_errs:", udp,
                            udp_in_errs);
  __XML_NETIF_COUNT_LOG("Udp_out_dgrams:", udp,
                            udp_out_dgrams);

  /* statistics from /proc/net/netstat */
  __XML_NETIF_COUNT_LOG("Syncookies_sent", tcp_ext,
                        syncookies_sent);
  __XML_NETIF_COUNT_LOG("Syncookies_recv", tcp_ext,
                        syncookies_recv);
  __XML_NETIF_COUNT_LOG("Syncookies_failed", tcp_ext,
                        syncookies_failed);
  __XML_NETIF_COUNT_LOG("Embrionic_rsts", tcp_ext,
                        embrionic_rsts);
  __XML_NETIF_COUNT_LOG("Prune_called", tcp_ext,
                        prune_called);
  __XML_NETIF_COUNT_LOG("Rcv_pruned", tcp_ext,
                        rcv_pruned);
  __XML_NETIF_COUNT_LOG("Ofo_pruned", tcp_ext,
                        ofo_pruned);
  __XML_NETIF_COUNT_LOG("Out_of_window_icmps", tcp_ext,
                        out_of_window_icmps);
  __XML_NETIF_COUNT_LOG("Lock_dropped_icmps", tcp_ext,
                        lock_dropped_icmps);
  __XML_NETIF_COUNT_LOG("Arp_filter", tcp_ext,
                        arp_filter);
  __XML_NETIF_COUNT_LOG("Time_waited", tcp_ext,
                        time_waited);
  __XML_NETIF_COUNT_LOG("Time_wait_recycled", tcp_ext,
                        time_wait_recycled);
  __XML_NETIF_COUNT_LOG("Time_wait_killed", tcp_ext,
                        time_wait_killed);
  __XML_NETIF_COUNT_LOG("Paws_passive_rejected", tcp_ext,
                        paws_passive_rejected);
  __XML_NETIF_COUNT_LOG("Paws_active_rejected", tcp_ext,
                        paws_active_rejected);
  __XML_NETIF_COUNT_LOG("Paws_estab_rejected", tcp_ext,
                        paws_estab_rejected);
  __XML_NETIF_COUNT_LOG("Tso_missing", tcp_ext,
                        tso_missing);
  __XML_NETIF_COUNT_LOG("Delayed_ack", tcp_ext,
                        delayed_ack);
  __XML_NETIF_COUNT_LOG("Delayed_ack_locked", tcp_ext,
                        delayed_ack_locked);
  __XML_NETIF_COUNT_LOG("Delayed_ack_lost", tcp_ext,
                        delayed_ack_lost);
  __XML_NETIF_COUNT_LOG("Listen_overflows", tcp_ext,
                        listen_overflows);
  __XML_NETIF_COUNT_LOG("Listen_drops", tcp_ext,
                        listen_drops);
  __XML_NETIF_COUNT_LOG("Tcp_prequeued", tcp_ext,
                        tcp_prequeued);
  __XML_NETIF_COUNT_LOG("Tcp_direct_copy_from_backlog", tcp_ext,
                        tcp_direct_copy_from_backlog);
  __XML_NETIF_COUNT_LOG("Tcp_direct_copy_from_prequeue", tcp_ext,
                        tcp_direct_copy_from_prequeue);
  __XML_NETIF_COUNT_LOG("Tcp_prequeue_dropped", tcp_ext,
                        tcp_prequeue_dropped);
  __XML_NETIF_COUNT_LOG("Tcp_hp_hits", tcp_ext,
                        tcp_hp_hits);
  __XML_NETIF_COUNT_LOG("Tcp_hp_hits_to_user", tcp_ext,
                        tcp_hp_hits_to_user);
  __XML_NETIF_COUNT_LOG("Tcp_pure_acks", tcp_ext,
                        tcp_pure_acks);
  __XML_NETIF_COUNT_LOG("Tcp_hp_acks", tcp_ext,
                        tcp_hp_acks);
  __XML_NETIF_COUNT_LOG("Tcp_reno_recovery", tcp_ext,
                        tcp_reno_recovery);
  __XML_NETIF_COUNT_LOG("Tcp_sack_recovery", tcp_ext,
                        tcp_sack_recovery);
  __XML_NETIF_COUNT_LOG("Tcp_sack_reneging", tcp_ext,
                        tcp_sack_reneging);
  __XML_NETIF_COUNT_LOG("Tcp_fack_reorder", tcp_ext,
                        tcp_fack_reorder);
  __XML_NETIF_COUNT_LOG("Tcp_sack_reorder", tcp_ext,
                        tcp_sack_reorder);
  __XML_NETIF_COUNT_LOG("Tcp_reno_reorder", tcp_ext,
                        tcp_reno_reorder);
  __XML_NETIF_COUNT_LOG("Tcp_ts_reorder", tcp_ext,
                        tcp_ts_reorder);
  __XML_NETIF_COUNT_LOG("Tcp_full_undo", tcp_ext,
                        tcp_full_undo);
  __XML_NETIF_COUNT_LOG("Tcp_partial_undo", tcp_ext,
                        tcp_partial_undo);
  __XML_NETIF_COUNT_LOG("Tcp_loss_undo", tcp_ext,
                        tcp_loss_undo);
  __XML_NETIF_COUNT_LOG("Tcp_sack_undo", tcp_ext,
                        tcp_sack_undo);
  __XML_NETIF_COUNT_LOG("Tcp_loss", tcp_ext,
                        tcp_loss);
  __XML_NETIF_COUNT_LOG("Tcp_lost_retransmit", tcp_ext,
                        tcp_lost_retransmit);
  __XML_NETIF_COUNT_LOG("Tcp_reno_failures", tcp_ext,
                        tcp_reno_failures);
  __XML_NETIF_COUNT_LOG("Tcp_sack_failures", tcp_ext,
                        tcp_sack_failures);
  __XML_NETIF_COUNT_LOG("Tcp_loss_failures", tcp_ext,
                        tcp_loss_failures);
  __XML_NETIF_COUNT_LOG("Tcp_timeouts", tcp_ext,
                        tcp_timeouts);
  __XML_NETIF_COUNT_LOG("Tcp_reno_recovery_fail", tcp_ext,
                        tcp_reno_recovery_fail);
  __XML_NETIF_COUNT_LOG("Tcp_sack_recovery_fail", tcp_ext,
                        tcp_sack_recovery_fail);
  __XML_NETIF_COUNT_LOG("Tcp_fast_retrans", tcp_ext,
                        tcp_fast_retrans);
  __XML_NETIF_COUNT_LOG("Tcp_forward_retrans", tcp_ext,
                        tcp_forward_retrans);
  __XML_NETIF_COUNT_LOG("Tcp_slow_start_retrans", tcp_ext,
                        tcp_slow_start_retrans);
  __XML_NETIF_COUNT_LOG("Tcp_scheduler_failures", tcp_ext,
                        tcp_scheduler_failures);
  __XML_NETIF_COUNT_LOG("Tcp_rcv_collapsed", tcp_ext,
                        tcp_rcv_collapsed);
  __XML_NETIF_COUNT_LOG("Tcp_dsack_old_sent", tcp_ext,
                        tcp_dsack_old_sent);
  __XML_NETIF_COUNT_LOG("Tcp_dsack_ofo_sent", tcp_ext,
                        tcp_dsack_ofo_sent);
  __XML_NETIF_COUNT_LOG("Tcp_dsack_recv", tcp_ext,
                        tcp_dsack_recv);
  __XML_NETIF_COUNT_LOG("Tcp_dsack_ofo_recv", tcp_ext,
                        tcp_dsack_ofo_recv);
  __XML_NETIF_COUNT_LOG("Tcp_abort_on_syn", tcp_ext,
                        tcp_abort_on_syn);
  __XML_NETIF_COUNT_LOG("Tcp_abort_on_data", tcp_ext,
                        tcp_abort_on_data);
  __XML_NETIF_COUNT_LOG("Tcp_abort_on_close", tcp_ext,
                        tcp_abort_on_close);
  __XML_NETIF_COUNT_LOG("Tcp_abort_on_memory", tcp_ext,
                        tcp_abort_on_memory);
  __XML_NETIF_COUNT_LOG("Tcp_abort_on_timeout", tcp_ext,
                        tcp_abort_on_timeout);
  __XML_NETIF_COUNT_LOG("Tcp_abort_on_linger", tcp_ext,
                        tcp_abort_on_linger);
  __XML_NETIF_COUNT_LOG("Tcp_abort_failed", tcp_ext,
                        tcp_abort_failed);
  __XML_NETIF_COUNT_LOG("Tcp_memory_pressures", tcp_ext,
                        tcp_memory_pressures);
  
  __XML_NETIF_LOG( __XML_NETIF_DATAEND_FMT);

  if (len == count)
    len--;

  buf[len++] = '\0';
  
  return len;
}

static int
ci_netif_stats_report( ci_netif* ni, ci_ip_stats_output_fmt type, char *buf, int count )
{
  int rc = 0;

  ci_assert( ni );

  switch( type ) {
  case CI_IP_STATS_OUTPUT_NONE:
#if CI_CFG_SEND_STATS_TO_LOG
    rc = ci_netif_stats_report_text(ni, NULL, 0);
#else
    rc = 0;
#endif
    break;
  case CI_IP_STATS_OUTPUT_TEXT:
    rc = ci_netif_stats_report_text(ni, buf, count );
    break;
  case CI_IP_STATS_OUTPUT_XML:
    rc = ci_netif_stats_report_xml(ni, buf, count );
    break;
  default:
    rc = -1;
    break;
  }
  ci_netif_stats_update_netif( ni );
  ci_ip_stats_clear( &ni->state->stats_snapshot );
  
  return rc;
}


/* Called when the statistics report timer fires OR at start/end of
* the session or for a manual update through a sockopt 
* \param ni netif context
* \param reason Action to perform
* \param type Type of output (0=default, 1 = text, 2 = XML)
* \param ptr Pointer to the memory where statistics is put on STATS_GET 
*            action. It has no sense with other actions and should be set to
*            NULL.
* \param which Type of statistics to report (TCP, netif or both)
*/
extern void
ci_netif_stats_action(__NI_STRUCT__ *ni,
                      ci_ip_stats_action_type action,
                      ci_ip_stats_output_fmt fmt,
                      void *data,
                      socklen_t *size)
{
  ci_iptime_t it;

  ci_assert(ni);
  ci_assert( IPTIMER_STATE(ni) );

  LOG_STATS( ci_log( "%s( %p, %d, %d, %p )", __FUNCTION__, ni, 
             action, fmt, data));

  /* update snapshot timestamp */
  ci_ip_time_get(IPTIMER_STATE(ni), &it);

  /* ci_ip_time_ticks2ms() is not defined in KERNEL space */
#ifndef __KERNEL__
  ni->state->stats_snapshot.now = ci_ip_time_ticks2ms(ni, it);
#endif

  switch (action) {
  case CI_IP_STATS_START:
    ci_ip_stats_clear( &ni->state->stats_snapshot);
    ci_ip_stats_clear( &ni->state->stats_cumulative);
    
    it = NI_CONF(ni).tconst_stats;
    ci_netif_stats_handle_timer( ni, it );
    break;
    
  case CI_IP_STATS_GET:
    if ((data != NULL) && (size != NULL) && (*size >= 2 * sizeof(ci_ip_stats))){
      /* assumed to be a valid user memory area to update */
      ci_ip_stats* ii = (ci_ip_stats*)data;
      memcpy( &ii[0], &ni->state->stats_snapshot, sizeof(ci_ip_stats) );
      memcpy( &ii[1], &ni->state->stats_cumulative, sizeof(ci_ip_stats));
      *size = 2 * sizeof(ci_ip_stats);
    }
    break;

  case CI_IP_STATS_REPORT:
#if CI_CFG_SEND_STATS_TO_LOG
    ci_netif_stats_report(ni, ni->state->stats_fmt, NULL, 0);
#else
    if ((data != NULL) && (size != NULL)) {
      *size = ci_netif_stats_report(ni, ni->state->stats_fmt,
                                    data, *size);
    }
#endif
    break;

  case CI_IP_STATS_END:
  case CI_IP_STATS_FLUSH:
    ci_netif_stats_update_netif( ni );

    /* Stop stats timer on CI_IP_STATS_END */
    it = action != CI_IP_STATS_END ? NI_CONF(ni).tconst_stats : 0;
    ci_netif_stats_handle_timer(ni, it );
    break;

  default:
    break;
  }
}


#endif        /* CI_CFG_SUPPORT_STATS_COLLECTION */

/*! \cidoxg_end */
