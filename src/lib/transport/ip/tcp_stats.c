/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  stg
**  \brief  UL stack statistics & reporting
**   \date  2004/07/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
#include "ip_internal.h"


#if CI_CFG_TCP_SOCK_STATS


/*! Manage the statistics timer.  
 * If the time is 0 the timer will be  killed. 
 * If the value is other than 0 then:
 *   If the timer is pending it will be modified
 *   else it will be set
 */
ci_inline void
ci_tcp_stats_handle_timer(ci_netif* ni, ci_tcp_state* ts, 
                                        ci_iptime_t timeout)
{
  ci_ip_timer* it;
  ci_assert( ni && ts );
  it  = &ts->stats_tid;

  LOG_STATS( ci_log( "%s( %p, %p, %d)", __FUNCTION__, ni, ts, (int)timeout));
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

/* Clear counters, initialise min and max variables with max and min values */
ci_inline void
ci_tcp_stats_init_data( ci_ip_sock_stats* tcp_stats)
{
  int ctr;
  CI_IP_STATS_TYPE* dest;

  ci_assert( tcp_stats );
  memset( &tcp_stats->count, 0, 
		  sizeof(tcp_stats->count));

  memset( &tcp_stats->actual, 0, 
		  sizeof(tcp_stats->actual));

  dest = (CI_IP_STATS_TYPE*)&tcp_stats->min;
  for( ctr =0; ctr < CI_IP_SOCK_STATS_MIN_LEN; ctr++ )
	  dest[ctr] = CI_IP_STATS_MAX_VAL;

  dest = (CI_IP_STATS_TYPE*)&tcp_stats->max;
  for( ctr =0; ctr < CI_IP_SOCK_STATS_MAX_LEN; ctr++ )
	  dest[ctr] = CI_IP_STATS_MIN_VAL;
}


/* called to setup the UL stack statistics/logging */
void
ci_tcp_stats_init(ci_netif* ni, ci_tcp_state* ts)
{
  int val;

  ci_assert( ni && ts );
  LOG_STATS( ci_log("%s(%p, %p)", __FUNCTION__, ni, ts ));

  ts->stats_fmt = CI_IP_STATS_OUTPUT_DEFAULT;
  val = CI_TCONST_STATS; /* mS */

  NI_CONF(ni).tconst_stats = val ? ci_tcp_time_ms2ticks(ni, val) : 0;
  
  LOG_STATS( ci_log("Statistics: %u ticks, %dmS, (format:%s)",
					NI_CONF(ni).tconst_stats, val,			 
					ts->stats_fmt ? "Text" : "XML" ));
  ci_tcp_stats_init_data( &ts->stats_snapshot );
  ci_tcp_stats_init_data( &ts->stats_cumulative );

  /* Setting the timeout to -1 implies collection through sockopt */
  if( val )
	ci_tcp_stats_action( ni, ts, CI_IP_STATS_START,
                         CI_IP_STATS_OUTPUT_DEFAULT, NULL, NULL );
}


/* Update the cumulative statistics from the snapshot */
static void
ci_tcp_stats_update( ci_tcp_state* ts )
{
  int ctr;
  CI_IP_STATS_TYPE* src;
  CI_IP_STATS_TYPE* dest;

  ts->stats_cumulative.now = ts->stats_snapshot.now;

  src = (CI_IP_STATS_TYPE*)&ts->stats_snapshot.count;
  dest = (CI_IP_STATS_TYPE*)&ts->stats_cumulative.count;
  for( ctr =0; ctr < CI_IP_SOCK_STATS_COUNT_LEN; ctr++ )
	dest[ctr] += src[ctr];

  src = (CI_IP_STATS_TYPE*)&ts->stats_snapshot.actual;
  dest = (CI_IP_STATS_TYPE*)&ts->stats_cumulative.actual;
  for( ctr =0; ctr < CI_IP_SOCK_STATS_ACTUAL_LEN; ctr++ ) {
	  dest[ctr] = src[ctr];
  }

  src = (CI_IP_STATS_TYPE*)&ts->stats_snapshot.min;
  dest = (CI_IP_STATS_TYPE*)&ts->stats_cumulative.min;
  for( ctr =0; ctr < CI_IP_SOCK_STATS_MIN_LEN; ctr++ ) {
	if( dest[ctr] > src[ctr] )
	  dest[ctr] = src[ctr];
  }

  src = (CI_IP_STATS_TYPE*)&ts->stats_snapshot.max;
  dest = (CI_IP_STATS_TYPE*)&ts->stats_cumulative.max;
  for( ctr =0; ctr < CI_IP_SOCK_STATS_MAX_LEN; ctr++ ) {
	if( dest[ctr] < src[ctr] )
	  dest[ctr] = src[ctr];
  }

  ci_tcp_stats_init_data( &ts->stats_snapshot );
}

#define __SS(s) (s)->stats_snapshot
#define __CU(s) (s)->stats_cumulative

#define __TEXT_TCP_COUNT_FMT  "%u/%u"
#define __TEXT_TCP_COUNT(s,Fld) \
  (s)->stats_snapshot.count.Fld, (s)->stats_cumulative.count.Fld

#define __TEXT_TCP_MINMAX_FMT " Mn:%u/%u Mx:%u/%u"
#define __TEXT_TCP_MINMAX(s,Fld) \
  __SS(s).min.Fld == CI_IP_STATS_MAX_VAL ? 0 : __SS(s).min.Fld, \
  __CU(s).min.Fld == CI_IP_STATS_MAX_VAL ? 0 : __CU(s).min.Fld, \
  (s)->stats_snapshot.max.Fld,   \
  (s)->stats_cumulative.max.Fld 

#define __TEXT_TCP_CUR_MINMAX_FMT "%u Mn:%u/%u Mx:%u/%u"
#define __TEXT_TCP_CUR_MINMAX(s,Fld) (s)->stats_snapshot.actual.Fld, \
  __SS(s).min.Fld == CI_IP_STATS_MAX_VAL ? 0 : __SS(s).min.Fld, \
  __CU(s).min.Fld == CI_IP_STATS_MAX_VAL ? 0 : __CU(s).min.Fld, \
  (s)->stats_snapshot.max.Fld,   \
  (s)->stats_cumulative.max.Fld 

#if CI_CFG_SEND_STATS_TO_LOG
#define __TEXT_TCP_LOG log
#else
#define __TEXT_TCP_LOG(fmt, args...) \
  if (len < count) { \
    len += snprintf(buf + len, count - len, fmt "\n", args); \
  }
#endif

#define __TEXT_TCP_COUNT_LOG(name, group, field) \
  __TEXT_TCP_LOG(__TEXT_NETIF_COUNT_FMT, \
                 (name), __TEXT_NETIF_COUNT(netif, group, field)); \
  }


/* generate statistics report in text format and store it to buffer */
static int
ci_tcp_stats_report_text(ci_tcp_state* ts, char *buf, int count)
{
#if CI_CFG_SEND_STATS_TO_LOG==0
  int len = 0;

  if (count <= 0)
    return 0;
#endif

  __TEXT_TCP_LOG( "Tx: byte:" __TEXT_TCP_COUNT_FMT " pkt:" __TEXT_TCP_COUNT_FMT,
                  __TEXT_TCP_COUNT(ts, tx_byte), __TEXT_TCP_COUNT(ts, tx_pkt));

  __TEXT_TCP_LOG( "    slow:" __TEXT_TCP_COUNT_FMT " ReTx:" 
                  __TEXT_TCP_COUNT_FMT,
                  __TEXT_TCP_COUNT(ts, tx_slowpath),
                  __TEXT_TCP_COUNT(ts, tx_retrans_pkt));

  __TEXT_TCP_LOG( "   sleep:" __TEXT_TCP_COUNT_FMT " time:" 
                  __TEXT_TCP_MINMAX_FMT,
                  __TEXT_TCP_COUNT(ts, tx_sleep),
                  __TEXT_TCP_MINMAX(ts, tx_sleeptime) );

  __TEXT_TCP_LOG( "     Win:" __TEXT_TCP_CUR_MINMAX_FMT,
                  __TEXT_TCP_CUR_MINMAX(ts, tx_win));

  __TEXT_TCP_LOG( "    WSCL:" __TEXT_TCP_CUR_MINMAX_FMT,
                  __TEXT_TCP_CUR_MINMAX(ts, tx_wscl));

  __TEXT_TCP_LOG( "Rx: byte:" __TEXT_TCP_COUNT_FMT " pkt:" 
                  __TEXT_TCP_COUNT_FMT " slow:" __TEXT_TCP_COUNT_FMT, 
                  __TEXT_TCP_COUNT(ts, rx_byte), __TEXT_TCP_COUNT(ts, rx_pkt),
                  __TEXT_TCP_COUNT(ts, rx_slowpath));

  __TEXT_TCP_LOG( "   SeqEr:" __TEXT_TCP_COUNT_FMT " AckEr:" 
                  __TEXT_TCP_COUNT_FMT " PawsEr:" __TEXT_TCP_COUNT_FMT,
                  __TEXT_TCP_COUNT(ts, rx_seqerr), __TEXT_TCP_COUNT(ts, rx_ackerr),
                  __TEXT_TCP_COUNT(ts, rx_pawserr));

  __TEXT_TCP_LOG( "   DupAk:" __TEXT_TCP_COUNT_FMT " daFRec:" 
                  __TEXT_TCP_COUNT_FMT " daCongFRec:" __TEXT_TCP_COUNT_FMT, 
                  __TEXT_TCP_COUNT(ts, rx_dupack),
                  __TEXT_TCP_COUNT(ts, rx_dupack_frec),
                  __TEXT_TCP_COUNT(ts, rx_dupack_congfrec));

  __TEXT_TCP_LOG( "    Zwin:" __TEXT_TCP_COUNT_FMT" Ooo:" __TEXT_TCP_COUNT_FMT, 
                  __TEXT_TCP_COUNT(ts, rx_zwin), __TEXT_TCP_COUNT(ts, rx_ooo));

  __TEXT_TCP_LOG( "  BadSyn:" __TEXT_TCP_COUNT_FMT " bsSeq:" __TEXT_TCP_COUNT_FMT, 
                  __TEXT_TCP_COUNT(ts, rx_badsyn),
                  __TEXT_TCP_COUNT(ts, rx_badsynseq));

  __TEXT_TCP_LOG( "  SynDup:" __TEXT_TCP_COUNT_FMT " SynNonAk:"
                  __TEXT_TCP_COUNT_FMT " SynBadAk:" __TEXT_TCP_COUNT_FMT, 
                  __TEXT_TCP_COUNT(ts, rx_syndup),
                  __TEXT_TCP_COUNT(ts, rx_synnonack),
                  __TEXT_TCP_COUNT(ts, rx_synbadack));

  __TEXT_TCP_LOG( "    wait:" __TEXT_TCP_COUNT_FMT,
                  __TEXT_TCP_COUNT(ts, rx_wait));

  __TEXT_TCP_LOG( "   sleep:" __TEXT_TCP_COUNT_FMT 
                  " time:" __TEXT_TCP_MINMAX_FMT,
                  __TEXT_TCP_COUNT(ts, rx_sleep),
                  __TEXT_TCP_MINMAX(ts, rx_sleeptime) );

  __TEXT_TCP_LOG( "     Win:" __TEXT_TCP_CUR_MINMAX_FMT,
                  __TEXT_TCP_CUR_MINMAX(ts, rx_win));

  __TEXT_TCP_LOG( "    WSCL:" __TEXT_TCP_CUR_MINMAX_FMT,
                  __TEXT_TCP_CUR_MINMAX(ts, rx_wscl));

  __TEXT_TCP_LOG( "     RTT:" __TEXT_TCP_CUR_MINMAX_FMT, 
                  __TEXT_TCP_CUR_MINMAX(ts, rtt));

  __TEXT_TCP_LOG( "    SRTT:" __TEXT_TCP_CUR_MINMAX_FMT,
                  __TEXT_TCP_CUR_MINMAX(ts, srtt));
                  
  __TEXT_TCP_LOG( "     RTO:" __TEXT_TCP_CUR_MINMAX_FMT,
                  __TEXT_TCP_CUR_MINMAX(ts, rto));

  __TEXT_TCP_LOG( "    RTTO:" __TEXT_TCP_COUNT_FMT,
                  __TEXT_TCP_COUNT(ts, rtto));

  __TEXT_TCP_LOG( "    Cong:" __TEXT_TCP_COUNT_FMT, 
                  __TEXT_TCP_COUNT(ts, cong));

#if CI_CFG_SEND_STATS_TO_LOG==0
  if (len == count)
    len--;

  buf[len++] = '\0';

  return len;
#else
  return 0;
#endif
}

#define __XML_TCP_DATASTART_FMT \
  "<record>\n" \
  " <udpsocket>%d</udpsocket>\n" \
  " <bufid>%d</bufid>" \
  " <snapshot_time>%u</snapshot_time>\n" \
  " <cumulative_time>%u</cumulative_time>\n"

#define __XML_TCP_DATASTART(ST) \
  S_SP(ST), \
  (ST)->udpflags & CI_UDPF_IN_USE ? 1 : 0, \
  (ST)->stats_snapshot.now,(ST)->stats_cumulative.now

#define __XML_TCP_DATAEND_FMT "</record>\n"

#define __XML_TCP_COUNT_FMT \
  "  <entry type=\"C\" name=\"%s\">\n" \
  "    <snapshot val=\"%u\"/>\n" \
  "    <cumulative val=\"%u\"/>\n" \
  "  </entry>\n"
#define __XML_TCP_COUNT(NM, ST,FLD) \
  (NM), (ST)->stats_snapshot.count.FLD, (ST)->stats_cumulative.count.FLD

  
#define __XML_TCP_RANGE_FMT \
  "  <entry type=\"R\" name=\"%s\">\n" \
  "    <snapshot val=\"%u\" min=\"%u\" max=\"%u\"/>\n" \
  "    <cumulative val=\"%u\" min=\"%u\" max=\"%u\"/>\n" \
  "  </entry>\n"

#define __XML_TCP_RANGE(NM,ST,FLD)  (NM), \
  (ST)->stats_snapshot.actual.FLD, (ST)->stats_snapshot.min.FLD, \
  (ST)->stats_snapshot.max.FLD, \
  (ST)->stats_cumulative.actual.FLD, (ST)->stats_cumulative.min.FLD, \
  (ST)->stats_cumulative.max.FLD

#if CI_CFG_SEND_STATS_TO_LOG
#define __XML_TCP_LOG ci_log
#else
#define __XML_TCP_LOG(x...) \
  if (len < count) { \
    len += snprintf(buf + len, count - len, x); \
  }
#endif

#define __XML_TCP_COUNT_LOG(name, ts, field) \
  __XML_TCP_LOG( __XML_TCP_COUNT_FMT, \
                 __XML_TCP_COUNT(name, ts, field))

#define __XML_TCP_RANGE_LOG(name, ts, field) \
  __XML_TCP_LOG( __XML_TCP_RANGE_FMT, \
                 __XML_TCP_RANGE(name, ts, field))


static int
ci_tcp_stats_report_xml( ci_tcp_state* ts, char *buf, int count )
{
  int len = 0;

#if CI_CFG_SEND_STATS_TO_LOG==0
  if (count <= 0)
    return 0;
#endif

  __XML_TCP_COUNT_LOG("Round-trip timeout", ts, rtto);
  __XML_TCP_COUNT_LOG("Congestion", ts, cong);
  __XML_TCP_COUNT_LOG("Rx bytes", ts, rx_byte);
  __XML_TCP_COUNT_LOG("Rx packets", ts, rx_pkt);
  __XML_TCP_COUNT_LOG("Rx slow path", ts, rx_slowpath);
  __XML_TCP_COUNT_LOG("Rx sequence no. err", ts, rx_seqerr);
  __XML_TCP_COUNT_LOG("Rx ack err", ts, rx_ackerr);
  __XML_TCP_COUNT_LOG("Rx PAWS err", ts, rx_pawserr);
  __XML_TCP_COUNT_LOG("Rx dup. ack", ts, rx_dupack);
  __XML_TCP_COUNT_LOG("Rx dup. ack, fast rx", ts, rx_dupack_frec );
  __XML_TCP_COUNT_LOG("Rx dup. ack, congest, fast rx", ts, rx_dupack_congfrec );
  __XML_TCP_COUNT_LOG("Rx zero window", ts, rx_zwin);
  __XML_TCP_COUNT_LOG("Rx out of order", ts, rx_ooo);
  __XML_TCP_COUNT_LOG("Rx bad syn", ts, rx_badsyn);
  __XML_TCP_COUNT_LOG("Rx bad syn seq.", ts, rx_badsynseq);
  __XML_TCP_COUNT_LOG("Rx dup. syn", ts, rx_syndup);
  __XML_TCP_COUNT_LOG("Rx syn bad ack", ts, rx_synbadack);
  __XML_TCP_COUNT_LOG("Rx syn non-ack", ts, rx_synnonack);
  __XML_TCP_COUNT_LOG("Rx sleeps", ts, rx_sleep);

  __XML_TCP_COUNT_LOG("Tx bytes", ts, tx_byte);
  __XML_TCP_COUNT_LOG("Tx packets", ts, tx_pkt);
  __XML_TCP_COUNT_LOG("Tx slow path", ts, tx_slowpath);
  __XML_TCP_COUNT_LOG("Tx retransmit", ts, tx_retrans_pkt);
  __XML_TCP_COUNT_LOG("Tx sleeps", ts, tx_sleep);
  __XML_TCP_COUNT_LOG("Tx stuck", ts, tx_stuck);

  __XML_TCP_RANGE_LOG("Rx window", ts, rx_win);
  __XML_TCP_RANGE_LOG("Rx window scale", ts, rx_wscl);
  __XML_TCP_RANGE_LOG("Tx window", ts, tx_win);
  __XML_TCP_RANGE_LOG("Tx window scale", ts, tx_wscl);

  __XML_TCP_RANGE_LOG("Round trip time", ts, rtt);
  __XML_TCP_RANGE_LOG("Smoothed round trip time", ts, srtt);
  __XML_TCP_RANGE_LOG("Round trip timeout", ts, rto);
  __XML_TCP_RANGE_LOG("Tx buffers free", ts, tx_buffree);
  __XML_TCP_RANGE_LOG("Tx sleep time", ts, tx_sleeptime);
  __XML_TCP_RANGE_LOG("Rx sleep time", ts, rx_sleeptime);

  __XML_TCP_LOG( __XML_TCP_DATAEND_FMT );

  if (len == count)
    len--;

  buf[len++] = '\0';

  return len;
}


static int
ci_tcp_stats_report( ci_netif* ni, ci_tcp_state* ts, int type, char *buf, int count )
{
  int rc = 0;

  ci_assert( ni && ts );

  switch( type ) {
  case CI_IP_STATS_OUTPUT_NONE:
#if CI_CFG_SEND_STATS_TO_LOG
    rc = ci_tcp_stats_report_text(ts, NULL, 0 );
#else
    rc = 0;
#endif
	break;

  case CI_IP_STATS_OUTPUT_TEXT:
    rc = ci_tcp_stats_report_text(ts, buf, count );
	break;

  case CI_IP_STATS_OUTPUT_XML:
    rc = ci_tcp_stats_report_xml(ts, buf, count );
	break;

  default:
    rc = -1;
	break;
  }
  
  return rc;
}


/* Called when the statistics report timer fires OR at start/end of
* the session or for a manual update through a sockopt 
* \param ni netif context
* \param ts TCP state context
* \param reason Action to perform
* \param type Type of output (0=default, 1 = text, 2 = XML)
* \param ptr Pointer to the memory where statistics is put on STATS_GET 
*            action. It has no sense with other actions and should be set to
*            NULL.
* \param which Type of statistics to report (TCP, netif or both)
*/
extern void ci_tcp_stats_action(__NI_STRUCT__ *ni,
                                __STATE_STRUCT__ *ts,
                                ci_ip_stats_action_type action,
                                ci_ip_stats_output_fmt fmt,
                                void *data,
                                socklen_t *size)
{
  ci_iptime_t it;

  ci_assert(ni);
  ci_assert( IPTIMER_STATE(ni) );
  ci_assert(ts);

  LOG_STATS( ci_log( "%s( %p, %p, %d, %d, %p )", __FUNCTION__, ni, ts, 
             action, fmt, data));

  /* update snapshot timestamp */
  ci_ip_time_get(IPTIMER_STATE(ni), &it);

  /* ci_ip_time_ticks2ms() is not defined in KERNEL space */
#ifndef __KERNEL__
  ts->stats_snapshot.now = ci_ip_time_ticks2ms(ni, it);
#endif

  switch (action) {
  case CI_IP_STATS_START:
    ci_tcp_stats_init_data( &ts->stats_snapshot);
    ci_tcp_stats_init_data( &ts->stats_cumulative);
    
    it = NI_CONF(ni).tconst_stats;
    ci_tcp_stats_handle_timer(ni, ts, it );
    break;
    
  case CI_IP_STATS_GET:
    if ((data != NULL) && (size != NULL) && (*size >= 2 * sizeof(ci_ip_stats))){
      /* assumed to be a valid user memory area to update */
      ci_ip_sock_stats* ii = (ci_ip_sock_stats*)data;
      memcpy( &ii[0], &ts->stats_snapshot, sizeof(*ii) );
      memcpy( &ii[1], &ts->stats_cumulative, sizeof(*ii));
      *size = 2 * sizeof(ci_ip_sock_stats);
    }
    break;

  case CI_IP_STATS_REPORT:
#if CI_CFG_SEND_STATS_TO_LOG
    ci_tcp_stats_report(ni, ts, ni->state->stats_fmt, NULL, 0);
#else
    if ((data != NULL) && (size != NULL)) 
    {
      *size = ci_tcp_stats_report(ni, ts, ni->state->stats_fmt, data, *size);
    }
#endif
    break;

  case CI_IP_STATS_END:
  case CI_IP_STATS_FLUSH:
    ci_tcp_stats_update( ts );

    /* Stop stats timer on CI_IP_STATS_END */
    it = action != CI_IP_STATS_END ? NI_CONF(ni).tconst_stats : 0;
    ci_tcp_stats_handle_timer(ni, ts, it );
    break;

  default:
    break;
  }
}


#endif	/* CI_CFG_TCP_SOCK_STATS */

/*! \cidoxg_end */
