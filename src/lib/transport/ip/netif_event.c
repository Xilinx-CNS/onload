/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Event handling
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include "netif_tx.h"
#include "tcp_rx.h"
#include "udp_internal.h"
#include <ci/tools/ipcsum_base.h>
#include <ci/tools/pktdump.h>
#include <etherfabric/timer.h>
#include <etherfabric/vi.h>
#include <ci/internal/pio_buddy.h>

#include <linux/ip.h>
#ifdef __KERNEL__
#include <linux/time.h>
#else
#include <time.h>
#endif

#if defined(__KERNEL__)
#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
#include <etherfabric/internal/evq_rx_iter.h>
#endif
#endif


#define SAMPLE(n) (n)

#define LPF "netif: "

#ifndef __KERNEL__
enum {
  FUTURE_DROP = 0x01,
  FUTURE_IP4  = 0x02,
  FUTURE_TCP  = 0x04, /* else UDP */

  FUTURE_NONE = 0,
  FUTURE_UDP4 = FUTURE_IP4,
  FUTURE_TCP4 = FUTURE_IP4 | FUTURE_TCP,
};


struct oo_rx_future {
  union {
    /* Protocol-specific states of partially handled packet go here */
    struct ci_tcp_rx_future tcp;
    struct ci_udp_rx_future udp;
  };
};
#endif


struct oo_rx_state {
  /* Full packet in order, once reception of scattered packet is completed. */
  ci_ip_pkt_fmt* rx_pkt;
  /* Last fragment received, chained to previous fragments via frag_next */
  ci_ip_pkt_fmt* frag_pkt;
  /* Without RX Merge: A running total of bytes received for this packet
   * With RX Merge: The full length of this packet
   */
  int            frag_bytes;
};


static int ci_ip_csum_correct(ci_ip4_hdr* ip, int max_ip_len)
{
  unsigned csum;
  int ip_len;

  if( max_ip_len < CI_IP4_IHL(ip) )
    return 0;
  ip_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);
  if( max_ip_len < ip_len )
    return 0;

  csum = ci_ip_csum_partial(0, ip, CI_IP4_IHL(ip));
  csum = ci_ip_hdr_csum_finish(csum);
  return csum == 0;
}


static int ci_tcp_csum_correct(ci_ip_pkt_fmt* pkt, int ip_paylen)
{
  int af = oo_pkt_af(pkt);
  ci_ipx_hdr_t* ipx = oo_ipx_hdr(pkt);
  ci_tcp_hdr* tcp = ipx_hdr_data(af, ipx);
  int tcp_hlen = CI_TCP_HDR_LEN(tcp);

  if( tcp_hlen < sizeof(ci_tcp_hdr) )
    return 0;
  if( ip_paylen < tcp_hlen )
    return 0;

  return ci_ipx_tcp_checksum(af, ipx, tcp, CI_TCP_PAYLOAD(tcp)) ==
         tcp->tcp_check_be16;
}


static void ci_parse_rx_vlan(ci_ip_pkt_fmt* pkt)
{
  uint16_t* p_ether_type;

  ci_assert_nequal((ci_uint8) pkt->pkt_start_off, 0xff);
  ci_assert_equal(pkt->pkt_eth_payload_off, 0xff);

  p_ether_type = &(oo_ether_hdr(pkt)->ether_type);
  if( *p_ether_type != CI_ETHERTYPE_8021Q ) {
    pkt->pkt_eth_payload_off = pkt->pkt_start_off + ETH_HLEN;
    pkt->vlan = 0;
  }
  else {
    pkt->pkt_eth_payload_off = pkt->pkt_start_off + ETH_HLEN + ETH_VLAN_HLEN;
    pkt->vlan = CI_BSWAP_BE16(p_ether_type[1]) & 0xfff;
  }
}


#if CI_CFG_PROC_DELAY

# if ! CI_CFG_TIMESTAMPING
#  error CI_CFG_PROC_DELAY requires CI_CFG_TIMESTAMPING
# endif


#ifndef __KERNEL__
static void frc_resync(ci_netif* ni)
{
  uint64_t after_frc, cost;
  struct timespec ts;

  if( ni->state->sync_cost == 0 ) {
    /* First time: Measure sync_cost and set other params. */
    int i;
    ni->state->max_frc_diff = (ci_int64) IPTIMER_STATE(ni)->khz * 1000;
    for( i = 0; i < 10; ++i ) {
      ci_frc64(&ni->state->sync_frc);
      clock_gettime(CLOCK_REALTIME, &ts);
      ci_frc64(&after_frc);
      cost = after_frc - ni->state->sync_frc;
      if( i == 0 )
        ni->state->sync_cost = cost;
      else
        ni->state->sync_cost = CI_MIN(ni->state->sync_cost, cost);
    }
  }

  /* Determine correspondence between frc and host clock. */
  do {
    ci_frc64(&ni->state->sync_frc);
    clock_gettime(CLOCK_REALTIME, &ts);
    ci_frc64(&after_frc);
  } while( after_frc - ni->state->sync_frc > ni->state->sync_cost * 3 );

  ni->state->sync_ns = ts.tv_sec * 1000000000 + ts.tv_nsec;
}
#endif


static void measure_processing_delay(ci_netif* ni, struct timespec pkt_ts,
                                     unsigned sync_flags)
{
  const ci_ip_timer_state* its = IPTIMER_STATE(ni);
  const unsigned in_sync =
    EF_VI_SYNC_FLAG_CLOCK_IN_SYNC | EF_VI_SYNC_FLAG_CLOCK_SET;
  ci_uint64 pkt_ns, stack_ns;
  ci_int64 frc_diff;

  if(CI_UNLIKELY( (sync_flags & in_sync) != in_sync ))
    return;

  frc_diff = its->frc - ni->state->sync_frc;
  if( frc_diff > ni->state->max_frc_diff ) {
    /* Ensure we keep a reasonable correspondence between frc and real
     * time.  We only do this in user-space because that is convenient.
     */
#ifdef __KERNEL__
    return;
#else
    frc_resync(ni);
    frc_diff = its->frc - ni->state->sync_frc;
#endif
  }

  stack_ns = ni->state->sync_ns + frc_diff * 1000000 / its->khz;
  pkt_ns = (ci_uint64) pkt_ts.tv_sec * 1000000000 + pkt_ts.tv_nsec;

  if( stack_ns >= pkt_ns ) {
    ci_uint64 delay_ns = stack_ns - pkt_ns;
    ci_uint64 delay = delay_ns >> CI_CFG_PROC_DELAY_NS_SHIFT;
    if( delay == 0 ) {
      ++(ni->state->proc_delay_hist[0]);
    }
    else {
      int n_buckets = (sizeof(ni->state->proc_delay_hist) /
                       sizeof(ni->state->proc_delay_hist[0]));
      int bucket_i = 63 - __builtin_clzll(delay);
      if( bucket_i < n_buckets )
        ++(ni->state->proc_delay_hist[bucket_i]);
      else
        ++(ni->state->proc_delay_hist[n_buckets - 1]);
      if( delay > ni->state->proc_delay_max )
        ni->state->proc_delay_max = delay;
    }
  }
  else {
    ci_uint64 delay_ns = pkt_ns - stack_ns;
    ci_uint64 delay = delay_ns >> CI_CFG_PROC_DELAY_NS_SHIFT;
    ++(ni->state->proc_delay_negative);
    if( delay > ni->state->proc_delay_min )
      ni->state->proc_delay_min = delay;
  }
}

#else

static inline void measure_processing_delay(ci_netif* ni,
                                            struct timespec pkt_ts,
                                            unsigned sync_flags)
{
}

#endif


int ci_ip_options_parse(ci_netif* netif, ci_ip4_hdr* ip, const int hdr_size)
{
  int error = 0;

  char* options = (char*) ip + sizeof(ci_ip4_hdr);
  char* opt_end = (char*) ip + hdr_size;
  while( *options != IPOPT_EOL && options < opt_end && ! error ) {
    switch( (ci_uint8) *options ) {
    case IPOPT_NOP:
      ++options;
      break;
    case IPOPT_RR: /* Record Packet Route */
    case IPOPT_TS: /* Time-stamp */
    case IPOPT_SEC: /* Security */
    case IPOPT_SID: /* Stream ID */
      if( options[1] < IPOPT_MINOFF || options[1] > opt_end - options ) {
        LOG_U( log(LPF "[%d] IP Option invalid offset; type=%u(op:%u), "
                   "offset=%u", netif->state->stack_id, (ci_uint8) *options,
                   (ci_uint8) (0x1f & *options), (ci_uint8) options[1]) );
        error = 1;
      }
      else {
        options += options[1];
      }
      break;
    case IPOPT_SSRR: /* Strict Source Routing */
    case IPOPT_LSRR: /* Loose Source Routing */
      LOG_U( log(LPF "[%d] IP Options: Source Routing unsupported; "
                 "type=%u(op:%u)", netif->state->stack_id, (ci_uint8) *options,
                 (ci_uint8) (0x1f & *options)) );
      error = 1;
      break;
    default:
      LOG_U( log(LPF "[%d] IP Option unsupported; type=%u(op:%u)",
                 netif->state->stack_id, (ci_uint8) *options,
                 (ci_uint8) (0x1f & *options)) );
      error = 1;
      break;
    }
  }

  if( error ) {
    CITP_STATS_NETIF_INC(netif, rx_discard_ip_options_bad);
    CI_IPV4_STATS_INC_IN_HDR_ERRS(netif);
  }
  else {
    CITP_STATS_NETIF_INC(netif, ip_options);
  }

  return error;
}


static void get_rx_timestamp(ci_netif* netif, ci_ip_pkt_fmt* pkt)
{
#if CI_CFG_TIMESTAMPING
  ci_netif_state_nic_t* nsn = &netif->state->nic[pkt->intf_i];

  if( nsn->oo_vi_flags & OO_VI_FLAGS_RX_HW_TS_EN ) {
    unsigned sync_flags;
    struct timespec stamp;
    int rc = ef_vi_receive_get_timestamp_with_sync_flags
      (&netif->nic_hw[pkt->intf_i].vi,
       PKT_START(pkt) - nsn->rx_prefix_len, &stamp, &sync_flags);
    if( rc == 0 ) {
      int tsf = (NI_OPTS(netif).timestamping_reporting &
                 CITP_TIMESTAMPING_RECORDING_FLAG_CHECK_SYNC) ?
                EF_VI_SYNC_FLAG_CLOCK_IN_SYNC :
                EF_VI_SYNC_FLAG_CLOCK_SET;
      pkt->hw_stamp.tv_sec = stamp.tv_sec;
      pkt->hw_stamp.tv_nsec = stamp.tv_nsec =
                (stamp.tv_nsec & ~CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC) |
                ((sync_flags & tsf) ? CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC : 0);
      nsn->last_rx_timestamp = pkt->hw_stamp;
      nsn->last_sync_flags = sync_flags;

      measure_processing_delay(netif, stamp, sync_flags);

      LOG_NR(log(LPF "RX id=%d timestamp: %lu.%09lu sync %d",
          OO_PKT_FMT(pkt), stamp.tv_sec, stamp.tv_nsec, sync_flags));
    } else {
      LOG_NR(log(LPF "RX id=%d missing timestamp", OO_PKT_FMT(pkt)));
      pkt->hw_stamp.tv_sec = 0;
    }
  }
  else
    pkt->hw_stamp.tv_sec = 0;
    /* no need to set tv_nsec to 0 here as socket layer ignores
     * timestamps when tv_sec is 0
     */
#else
  (void)netif;
  (void)pkt;
#endif
}


static void handle_rx_pkt(ci_netif* netif, struct ci_netif_poll_state* ps,
                          ci_ip_pkt_fmt* pkt)
{
  /* On entry: [pkt] may be a whole packet, or a linked list of scatter
   * fragments linked by [pkt->frag_next].  [pkt->pay_len] contains the
   * length of the whole frame.  Each scatter fragment has its [buf] field
   * initialised with the delivered frame payload.
   */
  int not_fast, ip_paylen, hdr_size;

  ci_uint16 ether_type = *((ci_uint16*)oo_l3_hdr(pkt) - 1);

  ci_assert_nequal(pkt->pkt_eth_payload_off, 0xff);

#if CI_CFG_RANDOM_DROP && !defined(__KERNEL__)
  if( CI_UNLIKELY(rand() < NI_OPTS(netif).rx_drop_rate) )  goto drop;
#endif

  pkt->tstamp_frc = IPTIMER_STATE(netif)->frc;

  /* Is this an IP packet? */
  if(CI_LIKELY( ether_type == CI_ETHERTYPE_IP )) {
    int ip_tot_len;
    ci_ip4_hdr *ip = oo_ip_hdr(pkt);
#if CI_CFG_IPV6
    pkt->flags &=~ CI_PKT_FLAG_IS_IP6;
#endif

    LOG_NR(log(LPF "RX id=%d ip_proto=0x%x", OO_PKT_FMT(pkt),
               (unsigned) ip->ip_protocol));
    LOG_AR(ci_analyse_pkt(PKT_START(pkt), pkt->pay_len));

    CI_IPV4_STATS_INC_IN_RECVS( netif );

    /* Do the byte-swap just once! */
    ip_tot_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);

    LOG_DR(ci_hex_dump(ci_log_fn, PKT_START(pkt),
                       ip_pkt_dump_len(ip_tot_len), 0));

    if( oo_tcpdump_check(netif, pkt, pkt->intf_i) )
      oo_tcpdump_dump_pkt(netif, pkt);

    /* Hardware should not deliver us fragments when using scalable
     * filters, but it happens in some corner cases.  We can't handle them.
     * Also check for valid IP length for non-fragmented packets.*/
    not_fast = (ip->ip_frag_off_be16 &
                (CI_IP4_OFFSET_MASK | CI_IP4_FRAG_MORE)) |
               (ip_tot_len > pkt->pay_len - oo_pre_l3_len(pkt));

    hdr_size = CI_IP4_IHL(ip);

    /* Accepting but ignoring IP options.
    ** Quick parse to check there is no badness
     */
    if(CI_UNLIKELY( hdr_size > sizeof(ci_ip4_hdr) && ! not_fast ))
      not_fast = ci_ip_options_parse(netif, ip, hdr_size);

    /* We are not checking for certain other illegalities here (invalid
    ** source address and short IP length).  That's because in some cases
    ** they can be checked for free in the transport.  It is the
    ** transport's responsibility to check these as necessary.
    */

    if( CI_LIKELY(not_fast == 0) ) {
      char* payload = (char*) ip + hdr_size;

      ip_paylen = ip_tot_len - hdr_size;
      /* This will go negative if the ip_tot_len was too small even
      ** for the IP header.  The ULP is expected to notice...
      */

      get_rx_timestamp(netif, pkt);

      /* Demux to appropriate protocol. */
      if( ip->ip_protocol == IPPROTO_TCP ) {
        ci_tcp_handle_rx(netif, ps, pkt, (ci_tcp_hdr*) payload, ip_paylen);
        CI_IPV4_STATS_INC_IN_DELIVERS( netif );
        return;
      }
      else if(CI_LIKELY( ip->ip_protocol == IPPROTO_UDP )) {
        ci_udp_handle_rx(netif, pkt, (ci_udp_hdr*) payload, ip_paylen);
        CI_IPV4_STATS_INC_IN_DELIVERS( netif );
        return;
      }

      LOG_U(CI_RLLOG(10, LPF "IGNORE IP protocol=%d",
                     (int) ip->ip_protocol));
    }
    else {
      /*! \todo IP slow path.  Don't want to deal with this yet.
       * 
       * It is probably bad idea to print all IP fragments, but we should
       * not receive them in the first place.
       */
      LOG_U(CI_RLLOG(10, LPF "[%d] IP HARD "
                     "(ihl_ver=%x ihl=%d frag=%x ip_len=%d frame_len=%d)"
                     PKT_DBG_FMT,
                     netif->state->stack_id,
                     (int) ip->ip_ihl_version, (int) CI_IP4_IHL(ip),
                     (unsigned) ip->ip_frag_off_be16,
                     ip_tot_len, pkt->pay_len, PKT_DBG_ARGS(pkt)));
      LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt), 64, 0));
    }

    CI_IPV4_STATS_INC_IN_DISCARDS( netif );
    if( ci_netif_pkt_pass_to_kernel(netif, pkt) )
      CITP_STATS_NETIF_INC(netif, no_match_pass_to_kernel_ip_other);
    else
      ci_netif_pkt_release_rx_1ref(netif, pkt);
    return;
  }
#if CI_CFG_IPV6
  else if(CI_LIKELY( ether_type == CI_ETHERTYPE_IP6 )) {
    ci_ip6_hdr *ip6_hdr = oo_ip6_hdr(pkt);
    void *payload = ip6_hdr + 1;

    LOG_NR(log(LPF "RX id=%d ip6_proto=0x%x", OO_PKT_FMT(pkt),
               ip6_hdr->next_hdr));
    pkt->flags |= CI_PKT_FLAG_IS_IP6;

    CI_IP_STATS_INC_IN6_RECVS( netif );

    if( oo_tcpdump_check(netif, pkt, pkt->intf_i) )
      oo_tcpdump_dump_pkt(netif, pkt);

    if( ip6_hdr->next_hdr == IPPROTO_TCP ) {
      ci_tcp_handle_rx(netif, ps, pkt, (ci_tcp_hdr*) payload,
                       CI_BSWAP_BE16(ip6_hdr->payload_len));
      CI_IP_STATS_INC_IN6_DELIVERS( netif );
      return;
    }
    else if( ip6_hdr->next_hdr == IPPROTO_UDP ) {
      ci_udp_handle_rx(netif, pkt, (ci_udp_hdr*) payload,
                       CI_BSWAP_BE16(ip6_hdr->payload_len));
      CI_IP_STATS_INC_IN6_DELIVERS( netif );
      return;
    }

    CI_IP_STATS_INC_IN6_DISCARDS( netif );
    if( ci_netif_pkt_pass_to_kernel(netif, pkt) )
      CITP_STATS_NETIF_INC(netif, no_match_pass_to_kernel_ip6_other);
    else
      ci_netif_pkt_release_rx_1ref(netif, pkt);
    return;
  }
#endif

  if( ci_netif_pkt_pass_to_kernel(netif, pkt) ) {
    CITP_STATS_NETIF_INC(netif, no_match_pass_to_kernel_non_ip);
  }
  else
  {
    LOG_U(CI_RLLOG(10, LPF "UNEXPECTED ether_type "PKT_DBG_FMT,
                   PKT_DBG_ARGS(pkt)));
    LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt), 64, 0));
    ci_netif_pkt_release_rx_1ref(netif, pkt);
  }
  return;

#if CI_CFG_RANDOM_DROP && !defined(__ci_driver__)
 drop:
  LOG_NR(log(LPF "DROP"));
  LOG_DR(ci_hex_dump(ci_log_fn, pkt, 40, 0));
  ci_netif_pkt_release_rx_1ref(netif, pkt);
  return;
#endif
}

#ifndef __KERNEL__
/* Partially handle an incoming packet before its completion event.
 * As much work as possible should be done here, before waiting for the packet
 * to arrive, to minimise work done on the critical path after arrival. */
ci_inline int handle_rx_pre_future(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                   struct oo_rx_future* future)
{
  /* On entry: [pkt] contains the first cache line of an incoming packet.
   * [pkt->frag_next] and [pkt->pay_len] may be invalid.
   */
  ci_uint16 ether_type;
  int valid_bytes = CI_CACHE_LINE_SIZE - pkt->pkt_start_off;

#if CI_CFG_RANDOM_DROP && !defined(__KERNEL__)
  if(CI_UNLIKELY( rand() < NI_OPTS(ni).rx_drop_rate )) {
    LOG_NR(log(LPF "DROP"));
    LOG_DR(ci_hex_dump(ci_log_fn, pkt, 40, 0));
    return FUTURE_DROP;
  }
#endif

  ci_assert_le(ETH_HLEN + ETH_VLAN_HLEN, valid_bytes);
  ci_parse_rx_vlan(pkt);
  ci_assert_le(pkt->pkt_eth_payload_off, valid_bytes);

  ether_type = *((ci_uint16*)oo_l3_hdr(pkt) - 1);
  pkt->tstamp_frc = IPTIMER_STATE(ni)->frc;

  if( ether_type == CI_ETHERTYPE_IP ) {
    ci_ip4_hdr *ip = oo_ip_hdr(pkt);
    int hdr_size = CI_IP4_IHL(ip);
    int ip_tot_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);
    int ip_paylen = ip_tot_len - hdr_size;
    int ip_payload_offset = pkt->pkt_eth_payload_off + hdr_size;
    void* payload = (char*)ip + hdr_size;

    if( ip_payload_offset > valid_bytes ||
        (hdr_size > sizeof(ci_ip4_hdr) &&
         ci_ip_options_parse(ni, ip, hdr_size)) )
      goto no_future;

    CI_IPV4_STATS_INC_IN_RECVS( ni );
#if CI_CFG_IPV6
    pkt->flags &=~ CI_PKT_FLAG_IS_IP6;
#endif

    get_rx_timestamp(ni, pkt);

    if( ip->ip_protocol == IPPROTO_TCP ) {
      CI_IPV4_STATS_INC_IN_DELIVERS( ni );
      if( ip_payload_offset + sizeof(ci_tcp_hdr) <= valid_bytes )
        ci_tcp_handle_rx_pre_future(ni, pkt, payload, ip_paylen, &future->tcp);
      else
        future->tcp.socket = NULL;
      return FUTURE_TCP4;
    }
    if(CI_LIKELY( ip->ip_protocol == IPPROTO_UDP )) {
      CI_IPV4_STATS_INC_IN_DELIVERS( ni );
      if( ip_payload_offset + sizeof(ci_udp_hdr) <= valid_bytes )
        ci_udp_handle_rx_pre_future(ni, pkt, payload, ip_paylen,
                                    CI_ETHERTYPE_IP, &future->udp);
      else
        future->udp.socket = NULL;
      return FUTURE_UDP4;
    }
    LOG_U(log(LPF "IGNORE IP protocol=%d", (int) ip->ip_protocol));
    return FUTURE_DROP;
  }
no_future:
  CI_DEBUG(pkt->pkt_eth_payload_off = 0xff);
  return FUTURE_NONE;
}


/* Undo partial handling of a packet which did not complete successfully. */
ci_inline void rollback_rx_future(ci_netif* ni, ci_ip_pkt_fmt* pkt, int status,
                                  struct oo_rx_future* future)
{
  CITP_STATS_NETIF_INC(ni, rx_future_rollback);

  ci_assert_nequal(status, FUTURE_NONE);
  CI_DEBUG(pkt->pkt_eth_payload_off = 0xff);

  /* Should we add official macros to decrease these counters? */
  CITP_STATS_NETIF_ADD(ni, rx_evs, -1);
  if( status & FUTURE_IP4 ) {
    __CI_NETIF_STATS_DEC(ni, ip, in_recvs);
    __CI_NETIF_STATS_DEC(ni, ip, in_delivers);
    if( status & FUTURE_TCP )
      ci_tcp_rollback_rx_future(ni, &future->tcp);
    else
      ci_udp_rollback_rx_future(ni, &future->udp);
  }
}


/* Finish handling a partially handled packet after its completion event.
 * This is on the critical latency path, so try to avoid any unnecessary work
 * here. Any work which doesn't require the complete packet should be done
 * in handle_rx_pre_future if possible. */
ci_inline void handle_rx_post_future(ci_netif* ni,
                                     struct ci_netif_poll_state* ps,
                                     ci_ip_pkt_fmt* pkt, int status,
                                     struct oo_rx_future* future)
{
  /* On entry: see handle_rx_pkt */
  ci_assert_nequal(status, FUTURE_NONE);

  if(CI_LIKELY( status & FUTURE_IP4 )) {
    int ip_tot_len;
    ci_ip4_hdr *ip = oo_ip_hdr(pkt);

    LOG_NR(log(LPF "RX id=%d ip_proto=0x%x", OO_PKT_FMT(pkt),
               (unsigned) ip->ip_protocol));
    LOG_AR(ci_analyse_pkt(PKT_START(pkt), pkt->pay_len));

    /* Do the byte-swap just once! */
    ip_tot_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);

    LOG_DR(ci_hex_dump(ci_log_fn, PKT_START(pkt),
                       ip_pkt_dump_len(ip_tot_len), 0));

    if( oo_tcpdump_check(ni, pkt, pkt->intf_i) )
      oo_tcpdump_dump_pkt(ni, pkt);

    /* Hardware will not deliver us fragments.  Check for valid IP length.*/
    /* NB. If you want to check for fragments, add this:
    **
    **  (ip->ip_frag_off_be16 & ~CI_IP4_FRAG_DONT)
    **
    ** We are not checking for certain other illegalities here (invalid
    ** source address and short IP length).  That's because in some cases
    ** they can be checked for free in the transport.  It is the
    ** transport's responsibility to check these as necessary.
    */
    if(CI_LIKELY( ip_tot_len <= pkt->pay_len - oo_pre_l3_len(pkt) )) {
      int hdr_size = CI_IP4_IHL(ip);
      void* payload = (char*) ip + hdr_size;
      int len = ip_tot_len - hdr_size;
      /* This will go negative if the ip_tot_len was too small even
      ** for the IP header.  The ULP is expected to notice...
      */

      /* Demux to appropriate protocol. */
      if(CI_LIKELY( status & FUTURE_TCP ))
        ci_tcp_handle_rx_post_future(ni, ps, pkt, payload, len, &future->tcp);
      else
        ci_udp_handle_rx_post_future(ni, pkt, payload, len, &future->udp);
    }
    else {
      rollback_rx_future(ni, pkt, status, future);
      LOG_U(log(LPF "[%d] IP HARD "
                "(ihl_ver=%x ihl=%d frag=%x ip_len=%d frame_len=%d)"
                PKT_DBG_FMT,
                ni->state->stack_id,
                (int) ip->ip_ihl_version, (int) CI_IP4_IHL(ip),
                (unsigned) ip->ip_frag_off_be16,
                ip_tot_len, pkt->pay_len, PKT_DBG_ARGS(pkt)));
      LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt), 64, 0));
      CI_IPV4_STATS_INC_IN_DISCARDS( ni );
      if( ci_netif_pkt_pass_to_kernel(ni, pkt) )
        CITP_STATS_NETIF_INC(ni, no_match_pass_to_kernel_ip_other);
      else
        ci_netif_pkt_release_rx_1ref(ni, pkt);
    }
  }
  else {
    ci_assert_equal(status, FUTURE_DROP);
    ci_netif_pkt_release_rx_1ref(ni, pkt);
  }
}
#endif


/* We accumulate new fragments adding them to the head of queue.  Once we've
 * got everything we need to put them back in order and set up the final
 * rx pkt.
 *
 * This function takes the accumulated state, together with the final fragment,
 * and sorts that out.
 */
static void handle_rx_scatter_last_frag(ci_netif* ni, struct oo_rx_state* s,
                                        ci_ip_pkt_fmt* pkt)
{
  oo_pkt_p next_p;

  /* Caller must have set up the length of the last fragment */
  ci_assert_gt(pkt->buf_len, 0);
  ci_assert(OO_PP_IS_NULL(pkt->frag_next));

  pkt->n_buffers = 1;
  while( 1 ) {  /* reverse the chain of fragments */
    next_p = s->frag_pkt->frag_next;
    s->frag_pkt->frag_next = OO_PKT_P(pkt);
    s->frag_pkt->n_buffers = pkt->n_buffers + 1;
    if( OO_PP_IS_NULL(next_p) )
      break;
    pkt = s->frag_pkt;
    s->frag_pkt = PKT(ni, next_p);
  }
  s->rx_pkt = s->frag_pkt;
  s->rx_pkt->pay_len = s->frag_bytes;
  s->frag_pkt = NULL;
  ASSERT_VALID_PKT(ni, s->rx_pkt);
}


/* When not using RX event merging we get a running total of bytes accumulated
 * in the jumbo.
 *
 * In this case s->frag_bytes tracks the accumulated length from received frags.
 */
static void handle_rx_scatter(ci_netif* ni, struct oo_rx_state* s,
                              ci_ip_pkt_fmt* pkt, int frame_bytes,
                              unsigned flags)
{
  s->rx_pkt = NULL;

  if( flags & EF_EVENT_FLAG_SOP ) {
    /* First fragment. */
    ci_assert(s->frag_pkt == NULL);
    ci_assert_le(frame_bytes,
                 (int) (CI_CFG_PKT_BUF_SIZE -
                        CI_MEMBER_OFFSET(ci_ip_pkt_fmt, dma_start)));
    s->frag_pkt = pkt;
    pkt->buf_len = s->frag_bytes = frame_bytes;
    oo_offbuf_init(&pkt->buf, PKT_START(pkt), s->frag_bytes);
  }
  else {
    ci_assert(s->frag_pkt != NULL);
    ci_assert_gt(s->frag_bytes, 0);
    ci_assert_gt(frame_bytes, s->frag_bytes);
    pkt->buf_len = frame_bytes - s->frag_bytes;
    oo_offbuf_init(&pkt->buf, pkt->dma_start, pkt->buf_len);
    s->frag_bytes = frame_bytes;
    CI_DEBUG(pkt->pay_len = -1);
    if( flags & EF_EVENT_FLAG_CONT ) {
      /* Middle fragment. */
      pkt->frag_next = OO_PKT_P(s->frag_pkt);
      s->frag_pkt = pkt;
    }
    else {
      /* Last fragment. */
      handle_rx_scatter_last_frag(ni, s, pkt);
    }
  }
}


/* When using rx event merge mode we need to handle jumbos differently.
 * In this case we get the full length of the packet in the SOP, with each
 * buffer before the last being filled completely.
 *
 * In this case s->frag_bytes is always the full length of the packet, set
 * when we receive the SOP.
 */
static void handle_rx_scatter_merge(ci_netif* ni, struct oo_rx_state* s,
                                    ci_ip_pkt_fmt* pkt, int prefix_bytes,
                                    ef_vi* vi, unsigned flags)
{
  int full_buffer = ef_vi_receive_buffer_len(vi);
  uint16_t pkt_bytes;

  s->rx_pkt = NULL;
  if( flags & EF_EVENT_FLAG_SOP ) {
    ef_vi_receive_get_bytes(vi, pkt->dma_start, &pkt_bytes);

    /* First fragment. */
    ci_assert(s->frag_pkt == NULL);
    ci_assert_gt(pkt_bytes, full_buffer - prefix_bytes);

    /* The packet prefix is present in the first buffer */
    pkt->buf_len = full_buffer - prefix_bytes;
    oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->buf_len);
    s->frag_pkt = pkt;
    s->frag_bytes = pkt_bytes;
  }
  else {
    ci_assert(s->frag_pkt != NULL);
    ci_assert_gt(s->frag_bytes, full_buffer - prefix_bytes);

    if( flags & EF_EVENT_FLAG_CONT ) {
      /* Middle fragment. */
      /* Middle fragments are completely filled, and don't contain a prefix */
      pkt->buf_len = full_buffer;
      oo_offbuf_init(&pkt->buf, pkt->dma_start, pkt->buf_len);
      CI_DEBUG(pkt->pay_len = -1);

      pkt->frag_next = OO_PKT_P(s->frag_pkt);
      s->frag_pkt = pkt;
    }
    else {
      /* Last fragment. */
      /* The first buffer contains a prefix, but all intervening buffers are
       * are filled, so this contains whatever's leftover.
       */
      pkt->buf_len = ((s->frag_bytes + prefix_bytes - 1) % full_buffer) + 1;
      oo_offbuf_init(&pkt->buf, pkt->dma_start, pkt->buf_len);
      CI_DEBUG(pkt->pay_len = -1);

      handle_rx_scatter_last_frag(ni, s, pkt);
    }
  }
}

static ci_ip_pkt_fmt* rx_multi_get_next_desc(ci_netif* ni, ef_vi* vi, int intf_i)
{
  ef_request_id di;
  oo_pkt_p pp;
  ci_ip_pkt_fmt* pkt;

  di = ef_vi_rxq_next_desc_id(vi);
  OO_PP_INIT(ni, pp, di);
  pkt = PKT_CHK(ni, pp);
  ci_prefetch_ppc(pkt->dma_start);
  ci_prefetch_ppc(pkt);
  ci_assert_equal(pkt->intf_i, intf_i);
  return pkt;
}


static void handle_rx_multi_pkts(ci_netif* ni, struct oo_rx_state* s,
                                 int prefix_bytes,
                                 ef_vi* vi, int intf_i)
{
  int full_buffer = ef_vi_receive_buffer_len(vi);
  uint16_t pkt_bytes, total_bytes, cur_bytes;
  ci_ip_pkt_fmt* pkt;


  pkt = rx_multi_get_next_desc(ni, vi, intf_i);
  ef_vi_receive_get_bytes(vi, pkt->dma_start, &pkt_bytes);
  total_bytes = pkt_bytes + prefix_bytes;

  /* if 1 pkt = 1 desc */
  if( total_bytes <= full_buffer ) {
    /* Whole packet in a single buffer. */
    pkt->pay_len = pkt_bytes;
    oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->pay_len);
    s->rx_pkt = pkt;
    return;
  }
  /* else */
  s->rx_pkt = NULL;
  /* - First fragment of packet - */
  ci_assert(s->frag_pkt == NULL);
  ci_assert_gt(total_bytes, full_buffer );

  /* The packet prefix is present in the first buffer */
  pkt->buf_len = full_buffer - prefix_bytes;
  oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->buf_len);
  s->frag_pkt = pkt;
  s->frag_bytes = pkt_bytes;
  cur_bytes = full_buffer;

  while( total_bytes - cur_bytes > full_buffer ) {
    /* - Middle fragments - */
    pkt = rx_multi_get_next_desc(ni, vi, intf_i);
    /* Middle fragments are completely filled, and don't contain a prefix */
    pkt->buf_len = full_buffer;
    oo_offbuf_init(&pkt->buf, pkt->dma_start, pkt->buf_len);
    CI_DEBUG(pkt->pay_len = -1);

    pkt->frag_next = OO_PKT_P(s->frag_pkt);
    s->frag_pkt = pkt;
    cur_bytes += full_buffer;
  }

  /* - Last fragment - */
  pkt = rx_multi_get_next_desc(ni, vi, intf_i);
  /* The first buffer contains a prefix, but all intervening buffers are
   * are filled, so this contains whatever's leftover.
   */
  pkt->buf_len = total_bytes - cur_bytes;
  oo_offbuf_init(&pkt->buf, pkt->dma_start, pkt->buf_len);
  CI_DEBUG(pkt->pay_len = -1);

  handle_rx_scatter_last_frag(ni, s, pkt);
}


static int handle_rx_csum_bad(ci_netif* ni, struct ci_netif_poll_state* ps,
                              ci_ip_pkt_fmt* pkt, int frame_len)
{
  int ip_paylen;
  int ip_proto;
  ci_uint16 ether_type;

  /* Packet reached onload -- so must be IP and must at least reach the TCP
   * or UDP header.
   */
  ci_parse_rx_vlan(pkt);
  pkt->pay_len = frame_len;
  oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->pay_len);

  /* Check that we have at least a full IP-header's-worth of data before we
   * start touching it. */
  if( pkt->pay_len < oo_pre_l3_len(pkt) + sizeof(ci_ip4_hdr) ) {
    CI_IPV4_STATS_INC_IN_HDR_ERRS(ni);
    LOG_U(log(FN_FMT "BAD frame_len=%d",
              FN_PRI_ARGS(ni), pkt->pay_len));
    goto drop;
  }
  ether_type = *((ci_uint16*)oo_l3_hdr(pkt) - 1);

  if(CI_LIKELY( ether_type == CI_ETHERTYPE_IP )) {
    ci_ip4_hdr *ip = oo_ip_hdr(pkt);
    int ip_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);
    ip_paylen = ip_len - CI_IP4_IHL(ip);
    ip_proto = ip->ip_protocol;

    if( pkt->pay_len < oo_pre_l3_len(pkt) + ip_len  ){
      CI_IPV4_STATS_INC_IN_HDR_ERRS(ni);
      LOG_U(log(FN_FMT "BAD ip_len=%d frame_len=%d",
                FN_PRI_ARGS(ni), ip_len, pkt->pay_len));
      goto drop;
    }

    if( ! ci_ip_csum_correct(ip, pkt->pay_len - oo_pre_l3_len(pkt)) ) {
      CI_IPV4_STATS_INC_IN_HDR_ERRS(ni);
      LOG_U(log(FN_FMT "IP BAD CHECKSUM", FN_PRI_ARGS(ni)));
      goto drop;
    }

  }
#if CI_CFG_IPV6
  else if( ether_type == CI_ETHERTYPE_IP6 ) {
    ci_ip6_hdr *ip = oo_ip6_hdr(pkt);
    ip_paylen = CI_BSWAP_BE16(ip->payload_len);
    ip_proto = ip->next_hdr;

    if( ip_paylen <= 0 ||
        pkt->pay_len < oo_pre_l3_len(pkt) + sizeof(ci_ip6_hdr) + ip_paylen ) {
      CI_IP_STATS_INC_IN6_HDR_ERRS(ni);
      LOG_U(log(FN_FMT "BAD frame_len=%d or IPv6 paylen=%d",
                FN_PRI_ARGS(ni), pkt->pay_len, ip_paylen));
      goto drop;
    }

    /* There is no IPv6 checksum to verify. */
  }
#endif
  else {
    LOG_U(log(FN_FMT "BAD frame ether_type=%d", FN_PRI_ARGS(ni), ether_type));
    goto drop;
  }

  if( ip_proto == IPPROTO_TCP ) {
    /* Check that we have a full-length transport-layer header,
     * with a correct checksum. */
    if( ip_paylen < sizeof(ci_tcp_hdr) ) {
      LOG_U(log(FN_FMT "BAD TCP ip_paylen=%d", FN_PRI_ARGS(ni), ip_paylen));
      goto drop;
    }
    else if( ci_tcp_csum_correct(pkt, ip_paylen) ) {
      handle_rx_pkt(ni, ps, pkt);
      return 1;
    }
    else {
      LOG_U(log(FN_FMT "BAD TCP CHECKSUM %04x "PKT_DBG_FMT, FN_PRI_ARGS(ni),
                (unsigned) PKT_IPX_TCP_HDR(oo_pkt_af(pkt), pkt)->tcp_check_be16,
                PKT_DBG_ARGS(pkt)));
      goto drop;
    }
  }
  else if( ip_proto == IPPROTO_UDP ) {
    ci_udp_hdr* udp = PKT_IPX_UDP_HDR(oo_pkt_af(pkt), pkt);
    pkt->pf.udp.pay_len = CI_BSWAP_BE16(udp->udp_len_be16) - sizeof(ci_udp_hdr);
    if( ip_paylen < sizeof(ci_udp_hdr) ) {
      LOG_U(log(FN_FMT "BAD UDP ip_paylen=%d", FN_PRI_ARGS(ni), ip_paylen));
      goto drop;
    }
    else if( ci_udp_csum_correct(pkt, udp) ) {
      handle_rx_pkt(ni, ps, pkt);
      return 1;
    }
    else {
      CI_UDP_STATS_INC_IN_ERRS(ni);
      LOG_U(log(FN_FMT "BAD UDP CHECKSUM %04x", FN_PRI_ARGS(ni),
                (unsigned) udp->udp_check_be16));
      goto drop;
    }
  }

drop:
  LOG_DU(ci_hex_dump(ci_log_fn, PKT_START(pkt), frame_len, 0));
  LOG_NR(log(LPF "DROP"));
  LOG_DR(ci_hex_dump(ci_log_fn, pkt, 40, 0));
  return 0;
}


static void handle_rx_no_desc_trunc(ci_netif* ni,
                                    struct ci_netif_poll_state* ps,
                                    int intf_i,
                                    struct oo_rx_state* s, ef_event ev)
{
  LOG_U(log(LPF "[%d] intf %d RX_NO_DESC_TRUNC "EF_EVENT_FMT,
            NI_ID(ni), intf_i, EF_EVENT_PRI_ARG(ev)));

  if( s->rx_pkt != NULL ) {
    ci_parse_rx_vlan(s->rx_pkt);
    handle_rx_pkt(ni, ps, s->rx_pkt);
    s->rx_pkt = NULL;
  }
  ci_assert(s->frag_pkt != NULL);
  if( s->frag_pkt != NULL ) {  /* belt and braces! */
    ci_netif_pkt_release_rx_1ref(ni, s->frag_pkt);
    s->frag_pkt = NULL;
  }
}


static void __handle_rx_discard(ci_netif* ni, struct ci_netif_poll_state* ps,
                                int intf_i, struct oo_rx_state* s, ef_event ev,
                                int frame_len, int discard_type, oo_pkt_p pp)
{
  int is_frag;
  ci_ip_pkt_fmt* pkt;
  int handled = 0;

  LOG_U(log(LPF "[%d] intf %d RX_DISCARD %d "EF_EVENT_FMT,
            NI_ID(ni), intf_i,
            (int) discard_type, EF_EVENT_PRI_ARG(ev)));

  if( s->rx_pkt != NULL ) {
    ci_parse_rx_vlan(s->rx_pkt);
    handle_rx_pkt(ni, ps, s->rx_pkt);
    s->rx_pkt = NULL;
  }

  /* For now bin any fragments as (i) they would only be useful in the
   * CSUM_BAD case; (ii) the hardware is probably right about the
   * checksum (especially so for packets long enough to fragment); and
   * (iii) validating the hardware's decision in the multiple
   * fragments case would require significantly more code
   *
   * By avoiding the more complex fragmented path, which differs between
   * normal and high throughput VIs, we also allow a common discard path.
   */
  if( (is_frag = (s->frag_pkt != NULL)) ) {
    ci_netif_pkt_release_rx_1ref(ni, s->frag_pkt);
    s->frag_pkt = NULL;
  }

  pkt = PKT_CHK(ni, pp);

  if( discard_type == EF_EVENT_RX_DISCARD_CSUM_BAD && !is_frag )
    handled = handle_rx_csum_bad(ni, ps, pkt, frame_len);
  
  switch( discard_type ) {
  case EF_EVENT_RX_DISCARD_CSUM_BAD:
    CITP_STATS_NETIF_INC(ni, rx_discard_csum_bad);
    break;
  case EF_EVENT_RX_DISCARD_INNER_CSUM_BAD:
    CITP_STATS_NETIF_INC(ni, rx_discard_inner_csum_bad);
    break;
  case EF_EVENT_RX_DISCARD_MCAST_MISMATCH:
    CITP_STATS_NETIF_INC(ni, rx_discard_mcast_mismatch);
    break;
  case EF_EVENT_RX_DISCARD_CRC_BAD:
    CITP_STATS_NETIF_INC(ni, rx_discard_crc_bad);
    break;
  case EF_EVENT_RX_DISCARD_TRUNC:
    CITP_STATS_NETIF_INC(ni, rx_discard_trunc);
    break;
  case EF_EVENT_RX_DISCARD_RIGHTS:
    CITP_STATS_NETIF_INC(ni, rx_discard_rights);
    break;
  case EF_EVENT_RX_DISCARD_OTHER:
    CITP_STATS_NETIF_INC(ni, rx_discard_other);
    break;
  }

  if( !handled ) {
    /* Only dump the packet if the NIC actually delivered it */
    if( (discard_type == EF_EVENT_RX_DISCARD_CSUM_BAD ||
         discard_type == EF_EVENT_RX_DISCARD_MCAST_MISMATCH ||
         discard_type == EF_EVENT_RX_DISCARD_CRC_BAD ||
         discard_type == EF_EVENT_RX_DISCARD_TRUNC ||
         discard_type == EF_EVENT_RX_DISCARD_OTHER) &&
        oo_tcpdump_check(ni, pkt, pkt->intf_i) ) {
        pkt->pay_len = frame_len;
        oo_tcpdump_dump_pkt(ni, pkt);
    }

    ci_netif_pkt_release_rx_1ref(ni, pkt);
  }
}


static void handle_rx_discard(ci_netif* ni, struct ci_netif_poll_state* ps,
                              int intf_i, struct oo_rx_state* s, ef_event ev)
{
  int discard_type = EF_EVENT_RX_DISCARD_TYPE(ev);
  int frame_len = EF_EVENT_RX_DISCARD_BYTES(ev) -
                  ni->nic_hw[intf_i].vi.rx_prefix_len;
  oo_pkt_p pp;
  OO_PP_INIT(ni, pp, EF_EVENT_RX_DISCARD_RQ_ID(ev));

  __handle_rx_discard(ni, ps, intf_i, s, ev, frame_len, discard_type, pp);
}


static void handle_rx_multi_discard(ci_netif* ni,
                                    struct ci_netif_poll_state* ps, int intf_i,
                                    struct oo_rx_state* s, ef_event ev,
                                    ef_request_id id, ef_vi* vi)
{
  int discard_type = EF_EVENT_RX_MULTI_DISCARD_TYPE(ev);
  uint16_t frame_len;
  oo_pkt_p pp;
  ci_ip_pkt_fmt* pkt;

  OO_PP_INIT(ni, pp, id);
  pkt = PKT_CHK(ni, pp);
  ef_vi_receive_get_bytes(vi, pkt->dma_start, &frame_len);

  __handle_rx_discard(ni, ps, intf_i, s, ev, frame_len, discard_type, pp);
}


static void ci_sock_put_on_reap_list(ci_netif* ni, ci_sock_cmn* s)
{
  ci_ni_dllist_remove(ni, &s->reap_link);
  ci_ni_dllist_put(ni, &ni->state->reap_list, &s->reap_link);
  s->b.sb_flags &= ~CI_SB_FLAG_RX_DELIVERED;
}


static void process_post_poll_list(ci_netif* ni)
{
  ci_ni_dllist_link* lnk;
  int i, need_wake = 0;
  citp_waitable* sb;
#if CI_CFG_EPOLL3
  int lists_need_wake = 0;
#endif

  (void) i;  /* prevent warning; effectively unused at userlevel */

  for( i = 0, lnk = ci_ni_dllist_start(ni, &ni->state->post_poll_list);
       lnk != ci_ni_dllist_end(ni, &ni->state->post_poll_list); ) {

#ifdef __KERNEL__
    if(CI_UNLIKELY( i++ > ni->ep_tbl_n )) {
      ci_netif_error_detected(ni, CI_NETIF_ERROR_POST_POLL_LIST, __FUNCTION__);
      return;
    }
#endif

    sb = CI_CONTAINER(citp_waitable, post_poll_link, lnk);
    lnk = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, lnk->next);

    if( sb->sb_flags & CI_SB_FLAG_TCP_POST_POLL )
      ci_tcp_rx_post_poll(ni, CI_CONTAINER(ci_tcp_state, s.b, sb));
    if( sb->sb_flags & CI_SB_FLAG_RX_DELIVERED )
      ci_sock_put_on_reap_list(ni, CI_CONTAINER(ci_sock_cmn, b, sb));

    if( sb->sb_flags ) {
      if( sb->sb_flags & CI_SB_FLAG_WAKE_RX )
        ++sb->sleep_seq.rw.rx;
      if( sb->sb_flags & CI_SB_FLAG_WAKE_TX )
        ++sb->sleep_seq.rw.tx;
      ci_mb();

#if CI_CFG_EPOLL3
      lists_need_wake |= sb->ready_lists_in_use;
#endif

      if( ! (sb->sb_flags & sb->wake_request) ) {
        sb->sb_flags = 0;
      }
      else {
#ifdef __KERNEL__
        /* In realtime kernel, citp_waitable_wakeup() from NAPI context is
         * harmful */
        if( !((ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT) && 
              oo_avoid_wakeup_from_dl()) ) {
          citp_waitable_wakeup(ni, sb);
        }
        else
#endif
        {
          /* Leave endpoints that need waking on the post-poll list so they can
           * be woken in the driver with a single syscall when we drop the
           * lock.
           */
          /* NB. Important to leave [sb_flags] set here, as we may run
           * process_post_poll_list() multiple times before dropping the
           * lock.  If we cleared [sb_flags] this endpoint could be dropped
           * from the list.
           */
          need_wake = 1;
          continue;
        }
      }
    }
    ci_ni_dllist_remove_safe(ni, &sb->post_poll_link);
  }

  CHECK_NI(ni);

#if CI_CFG_EPOLL3
  /* Shouldn't have had a wake for a list we don't think exists */
  ci_assert_equal(lists_need_wake & ~((1 << CI_CFG_N_READY_LISTS)-1), 0);

#ifndef __KERNEL__
  /* See if any of the ready lists need a wake.  We only bother checking if
   * we're not going to do a wake anyway.
   */
  if( need_wake == 0 && lists_need_wake != 0 ) {
    CI_READY_LIST_EACH(lists_need_wake, lists_need_wake, i) {
      if( ni->state->ready_list_flags[i] & CI_NI_READY_LIST_FLAG_WAKE ) {
        need_wake = 1;
        break;
      }
    }
  }
#endif
#endif

  if( need_wake )
    ef_eplock_holder_set_flag(&ni->state->lock, CI_EPLOCK_NETIF_NEED_WAKE);

#if CI_CFG_EPOLL3
#ifdef __KERNEL__
  /* Check whether any ready lists associated with a set need to be woken.
   */
  CI_READY_LIST_EACH(lists_need_wake, lists_need_wake, i) {
    if( (lists_need_wake & (1 << i)) &&
        (ni->state->ready_list_flags[i] & CI_NI_READY_LIST_FLAG_WAKE) )
      efab_tcp_helper_ready_list_wakeup(netif2tcp_helper_resource(ni), i);
  }
#endif
#endif
}


#define UDP_CAN_FREE(us)  ((us)->tx_count == 0)

#define CI_NETIF_TX_VI(ni, nic_i, label)  (&(ni)->nic_hw[nic_i].vi)
#define CI_NETIF_RX_VI(ni, nic_i, label)  (&(ni)->nic_hw[nic_i].vi)


static void ci_netif_tx_pkt_complete_udp(ci_netif* netif,
                                         struct ci_netif_poll_state* ps,
                                         ci_ip_pkt_fmt* pkt)
{
  ci_udp_state* us;
  oo_pkt_p frag_next;

#ifndef NDEBUG
  {
    ci_uint8 proto = TX_PKT_PROTOCOL(oo_pkt_af(pkt), pkt);
#if CI_CFG_IPV6
    ci_assert(proto == IPPROTO_UDP || proto == CI_NEXTHDR_FRAGMENT);
#else
    ci_assert_equal(proto, IPPROTO_UDP);
#endif /* CI_CFG_IPV6 */
  }
#endif /* NDEBUG */

  us = SP_TO_UDP(netif, pkt->pf.udp.tx_sock_id);

  ci_udp_dec_tx_count(us, pkt);

  if( ci_udp_tx_advertise_space(us) ) {
    if( ! (us->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN) ) {
      /* Linux wakes up with event= POLLOUT on each TX,
       * and we do the same. */
      ci_udp_wake_possibly_not_in_poll(netif, us, CI_SB_FLAG_WAKE_TX);
      ci_netif_put_on_post_poll(netif, &us->s.b);
    }
    else if( UDP_CAN_FREE(us) ) {
      ci_ni_dllist_remove_safe(netif, &us->s.b.post_poll_link);
      ci_udp_state_free(netif, us);
    }
  }

#if CI_CFG_TIMESTAMPING
  /* linux/Documentation/networking/timestamping.txt:
   * If the outgoing packet has to be fragmented, then only the first
   * fragment is time stamped and returned to the sending socket. */
  if( pkt->flags & CI_PKT_FLAG_TX_TIMESTAMPED &&
      ci_udp_timestamp_q_enqueue(netif, us, pkt) == 0 )
    return;
#endif

  /* Free this packet and all the fragments if possible. */
  while( 1 ) {
    frag_next = pkt->frag_next;

    if( ! ci_netif_pkt_release_in_poll(netif, pkt, ps) ) {
      /* If the packet is in use, then it holds ownership for all next
       * fragments. */
      break;
    }

    /* is there any next fragment? */
    if( OO_PP_IS_NULL(frag_next) )
      break;
    pkt = PKT_CHK(netif, frag_next);
  }
}



ci_inline void __ci_netif_tx_pkt_complete(ci_netif* ni,
                                          struct ci_netif_poll_state* ps,
                                          ci_ip_pkt_fmt* pkt, ef_event* ev)
{
  ci_netif_state_nic_t* nic = &ni->state->nic[pkt->intf_i];
  /* debug check - take back ownership of buffer from NIC */
  ci_assert(pkt->flags & CI_PKT_FLAG_TX_PENDING);
  nic->tx_bytes_removed += TX_PKT_LEN(pkt);
  ci_assert((int) (nic->tx_bytes_added - nic->tx_bytes_removed) >=0);
#if CI_CFG_PIO
  if( pkt->pio_addr >= 0 ) {
    ci_pio_buddy_free(ni, &nic->pio_buddy, pkt->pio_addr, pkt->pio_order);
    pkt->pio_addr = -1;
  }
#endif
#if CI_CFG_TIMESTAMPING
  if( pkt->flags & CI_PKT_FLAG_TX_TIMESTAMPED ) {
    if( ev != NULL && EF_EVENT_TYPE(*ev) == EF_EVENT_TYPE_TX_WITH_TIMESTAMP ) {
      int opt_tsf = ((NI_OPTS(ni).timestamping_reporting) &
                     CITP_TIMESTAMPING_RECORDING_FLAG_CHECK_SYNC) ?
                    EF_VI_SYNC_FLAG_CLOCK_IN_SYNC :
                    EF_VI_SYNC_FLAG_CLOCK_SET;
      int pkt_tsf = EF_EVENT_TX_WITH_TIMESTAMP_SYNC_FLAGS(*ev);

      pkt->hw_stamp.tv_sec = EF_EVENT_TX_WITH_TIMESTAMP_SEC(*ev);
      pkt->hw_stamp.tv_nsec =
                    (EF_EVENT_TX_WITH_TIMESTAMP_NSEC(*ev) &
                     (~CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC)) |
                    ((pkt_tsf & opt_tsf) ?
                     CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC : 0);
    }
    else if( ev == NULL ) {
      /* This is NIC reset. The TIMESTAMPED flag needs to stay
       * to ensure client is notified of missing timestamp -
       * important to keep TCP timestamps in sync with
       * TCP stream */
      pkt->hw_stamp.tv_sec = 0;
      pkt->hw_stamp.tv_nsec = 0;
    }
    else {
      if( CI_NETIF_TX_VI(ni, pkt->intf_i, ev->tx_timestamp.q_id)->vi_flags &
          EF_VI_TX_TIMESTAMPS ) {
        ci_log("ERROR: TX timestamp requested, but non-timestamped "
                "TX complete event received.");
      }
      pkt->flags &= ~CI_PKT_FLAG_TX_TIMESTAMPED;
    }

    /* Ensure that timestamp is written down before
     * CI_PKT_FLAG_TX_PENDING removal. */
    ci_wmb();
  }
#endif

#if CI_CFG_CTPIO
  if( pkt->flags & CI_PKT_FLAG_TX_CTPIO ) {
    /* We tried to send the packet by CTPIO.  Check whether this was
     * successful. */
    if( ! EF_EVENT_TX_CTPIO(*ev) ) {
      ci_netif_ctpio_desist(ni, pkt->intf_i);
      CITP_STATS_NETIF_INC(ni, ctpio_dma_fallbacks);
    }
    pkt->flags &= ~CI_PKT_FLAG_TX_CTPIO;
  }
#endif

  pkt->flags &=~ CI_PKT_FLAG_TX_PENDING;
  if( pkt->flags & CI_PKT_FLAG_UDP )
    ci_netif_tx_pkt_complete_udp(ni, ps, pkt);
  else
    ci_netif_pkt_release_in_poll(ni, pkt, ps);

}


void ci_netif_tx_pkt_complete(ci_netif* ni, struct ci_netif_poll_state* ps,
                              ci_ip_pkt_fmt* pkt)
{
  __ci_netif_tx_pkt_complete(ni, ps, pkt, NULL);
}


#ifdef __KERNEL__

int ci_netif_evq_poll(ci_netif* ni, int intf_i)
{
  ef_vi* evq = &ni->nic_hw[intf_i].vi;
  int n_evs;
#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
  ef_event *ev = ni->state->events;
#endif

  ci_assert_lt(intf_i, CI_CFG_MAX_INTERFACES);
  if( intf_i >= oo_stack_intf_max(ni) )
     return 0; /* for simplicity no error reported */
  /* The 4 below is empirical: with rx merging we generally see 8ish packets
   * per rx_multi; we assume that another half are tx events, hence on average
   * a VI with merging is 4 times more efficient than one without. We don't
   * want to go overboard on evs per poll for the reasons described at the
   * other ef_eventq_poll() call site below (when we're not using
   * poll_in_kernel). Note that this whole function is for poll-in-kernel
   * mode, so by default we tune evs_per_poll to be notably larger than the
   * normal default. */
  n_evs = ef_eventq_poll(evq, ni->state->events,
             CI_MIN(sizeof(ni->state->events) / sizeof(ni->state->events[0]),
                    ef_vi_flags(evq) & EF_VI_RX_EVENT_MERGE ?
                                            NI_OPTS(ni).evs_per_poll / 4 :
                                            NI_OPTS(ni).evs_per_poll));

#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
  if( NI_OPTS(ni).xdp_mode == 0 )
    return n_evs;

  {
    struct ef_vi_rvq_rx_iter ri;
    uint32_t id;
    size_t len = 0; /* placate compiler */

    ef_vi_evq_rx_iter_set(&ri, evq, ev, n_evs);

    while( (id = ef_vi_evq_rx_iter_next(&ri, &id, &len)) != 0 ) {
      oo_pkt_p pp;
      ci_ip_pkt_fmt* pkt;

      OO_PP_INIT(ni, pp, id);
      pkt = PKT_CHK(ni, pp);

      ci_prefetch_ppc(pkt->dma_start);
      ci_prefetch_ppc(pkt);
      ci_assert_equal(pkt->intf_i, intf_i);

      /* Whole packet in a single buffer. */
      if( len == 0 )
        ef_vi_receive_get_bytes(evq, pkt->dma_start,
                                (uint16_t*)&pkt->pay_len);
      else
        pkt->pay_len = len - evq->rx_prefix_len;
      oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->pay_len);
      ci_parse_rx_vlan(pkt);
      if( !efab_tcp_helper_xdp_rx_pkt(netif2tcp_helper_resource(ni), intf_i, pkt) )
        pkt->flags |= CI_PKT_FLAG_XDP_DROP; /* schedule drop */
      /* We called ci_parse_rx_vlan() above, which initialised
       * pkt_eth_payload_off.  However, the main RX loop will call that
       * function again, and it asserts at entry that the field is
       * uninitialised, so we reset it here. */
      CI_DEBUG(pkt->pkt_eth_payload_off = 0xff);
    }
  }

#endif
   return n_evs;
}
#endif

#if defined(__KERNEL__) && CI_CFG_WANT_BPF_NATIVE
#if CI_HAVE_BPF_NATIVE
ci_inline int oo_xdp_check_pkt(ci_netif* ni, int intf_i, ci_ip_pkt_fmt** pkt)
{
  if( NI_OPTS(ni).xdp_mode != 0 &&
      ! efab_tcp_helper_xdp_rx_pkt(netif2tcp_helper_resource(ni), intf_i, *pkt) ) {
    /* just drop */
    (*pkt)->flags &= ~CI_PKT_FLAG_XDP_DROP;
    ci_netif_pkt_release_rx_1ref(ni, *pkt);
    *pkt = NULL;
    return 0;
  }
  return 1;
}
#define oo_xdp_check_pkt oo_xdp_check_pkt
#endif
#endif

#ifndef oo_xdp_check_pkt
#if ! defined(__KERNEL__) && CI_CFG_WANT_BPF_NATIVE
ci_inline int oo_xdp_check_pkt(ci_netif* ni, int intf_i, ci_ip_pkt_fmt** pkt)
{
  if( NI_OPTS(ni).xdp_mode != 0 &&
      ((*pkt)->flags & CI_PKT_FLAG_XDP_DROP) ) {
    /* just drop */
    (*pkt)->flags &= ~CI_PKT_FLAG_XDP_DROP;
    ci_netif_pkt_release_rx_1ref(ni, *pkt);
    *pkt = NULL;
    return 0;
  }
  return 1;
}
#else
ci_inline int oo_xdp_check_pkt(ci_netif* ni, int intf_i, ci_ip_pkt_fmt** pkt)
{
  return 1;
}
#endif
#endif


ci_inline void __handle_rx_pkt(ci_netif* ni, struct ci_netif_poll_state* ps,
                              int intf_i, ci_ip_pkt_fmt** pkt)
{
  if( *pkt != NULL && oo_xdp_check_pkt(ni, intf_i, pkt) ) {
    ci_parse_rx_vlan(*pkt);
    handle_rx_pkt(ni, ps, *pkt);
  }
}


static int ci_netif_poll_evq(ci_netif* ni, struct ci_netif_poll_state* ps,
                             int intf_i, int n_evs)
{
  struct oo_rx_state s;
  ef_vi* evq = &ni->nic_hw[intf_i].vi;
  unsigned total_evs = 0;
  ci_ip_pkt_fmt* pkt;
  ef_event *ev = ni->state->events;
  int i;
  oo_pkt_p pp;
  int completed_tx = 0;
#ifdef OO_HAS_POLL_IN_KERNEL
  int poll_in_kernel;
#endif
  s.frag_pkt = NULL;
  s.frag_bytes = 0;  /*??*/

  if( OO_PP_NOT_NULL(ni->state->nic[intf_i].rx_frags) ) {
    pkt = PKT_CHK(ni, ni->state->nic[intf_i].rx_frags);
    ni->state->nic[intf_i].rx_frags = OO_PP_NULL;
    s.frag_pkt = pkt;
    s.frag_bytes = pkt->pay_len;
    CI_DEBUG(pkt->pay_len = -1);
  }

#ifdef OO_HAS_POLL_IN_KERNEL
  poll_in_kernel = ni->nic_hw[intf_i].poll_in_kernel;
#endif

  if( n_evs != 0 )
    goto have_events;

  do {
#ifdef OO_HAS_POLL_IN_KERNEL
    if( poll_in_kernel ) {
      n_evs = 0;
      if( ci_netif_intf_has_event(ni, intf_i) )
        n_evs = ci_netif_evq_poll_k(ni, intf_i);
    }
    else
#endif
      n_evs = ef_eventq_poll(evq, ev, 16);
    /* The 16 above is a heuristic. We want a big number for efficiency, but
     * if we go too big then we can totally drain the rxq in one go (made even
     * easier when rx merging is on). We don't refill until after this
     * function (and post-poll processing) completes, so we really don't want
     * to be spending all that time with an almost-empty rxq. There's a second
     * check at the bottom of this do..while loop, but it can't go smaller
     * than this n_evs (multiplied by rx_multis). */
    if( n_evs == 0 )
      break;

have_events:
    s.rx_pkt = NULL;
    for( i = 0; i < n_evs; ++i ) {
      /* Look for RX events first to minimise latency. */
      if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX ) {
        CITP_STATS_NETIF_INC(ni, rx_evs);
        OO_PP_INIT(ni, pp, EF_EVENT_RX_RQ_ID(ev[i]));
        pkt = PKT_CHK(ni, pp);
        ci_prefetch_ppc(pkt->dma_start);
        ci_prefetch_ppc(pkt);
        ci_assert_equal(pkt->intf_i, intf_i);
        __handle_rx_pkt(ni, ps, intf_i, &s.rx_pkt);
        if( (ev[i].rx.flags & (EF_EVENT_FLAG_SOP | EF_EVENT_FLAG_CONT))
                                                       == EF_EVENT_FLAG_SOP ) {
          /* Whole packet in a single buffer. */
          pkt->pay_len = EF_EVENT_RX_BYTES(ev[i]) - evq->rx_prefix_len;
          oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->pay_len);
          s.rx_pkt = pkt;
        }
        else {
          handle_rx_scatter(ni, &s, pkt,
                            EF_EVENT_RX_BYTES(ev[i]) - evq->rx_prefix_len,
                            ev[i].rx.flags);
        }
      }

      else if(CI_LIKELY( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_TX )) {
        ef_request_id *ids = ni->tx_events;
        int n_ids, j;
        ef_vi* vi = CI_NETIF_TX_VI(ni, intf_i, ev[i].tx.q_id);
        CITP_STATS_NETIF_INC(ni, tx_evs);
        n_ids = ef_vi_transmit_unbundle(vi, &ev[i], ids);
        ci_assert_ge(n_ids, 0);
        ci_assert_le(n_ids, sizeof(ni->tx_events) / sizeof(ids[0]));
        for( j = 0; j < n_ids; ++j ) {
          OO_PP_INIT(ni, pp, ids[j]);
          pkt = PKT_CHK(ni, pp);
          ++ni->state->nic[intf_i].tx_dmaq_done_seq;
          __ci_netif_tx_pkt_complete(ni, ps, pkt, &ev[i]);
        }
        completed_tx = 1;
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX_MULTI ) {
        ef_request_id *ids = ni->rx_events;
        int n_ids, j;
        ef_vi* vi = CI_NETIF_RX_VI(ni, intf_i, ev[i].rx.q_id);
        CITP_STATS_NETIF_INC(ni, rx_evs);
        n_ids = ef_vi_receive_unbundle(vi, &ev[i], ids);
        ci_assert_ge(n_ids, 0);
        ci_assert_le(n_ids, sizeof(ni->rx_events) / sizeof(ids[0]));
        total_evs += n_ids - 1;
        for( j = 0; j < n_ids; ++j ) {
          OO_PP_INIT(ni, pp, ids[j]);
          pkt = PKT_CHK(ni, pp);
          ci_prefetch_ppc(pkt->dma_start);
          ci_prefetch_ppc(pkt);
          ci_assert_equal(pkt->intf_i, intf_i);
          __handle_rx_pkt(ni, ps, intf_i, &s.rx_pkt);
          if( (ev[i].rx_multi.flags & (EF_EVENT_FLAG_SOP | EF_EVENT_FLAG_CONT))
               == EF_EVENT_FLAG_SOP ) {
            /* Whole packet in a single buffer. */
            ef_vi_receive_get_bytes(vi, pkt->dma_start,
                                    (uint16_t*)&pkt->pay_len);
            oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->pay_len);
            s.rx_pkt = pkt;
          }
          else {
            handle_rx_scatter_merge(ni, &s, pkt, evq->rx_prefix_len, vi,
                                    ev[i].rx_multi.flags);
          }
        }
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX_MULTI_PKTS ) {
        int j, n_pkts;
        ef_vi* vi = CI_NETIF_RX_VI(ni, intf_i, ev[i].rx_multi_pkts.q_id);
        CITP_STATS_NETIF_INC(ni, rx_evs);
        n_pkts = ev[i].rx_multi_pkts.n_pkts;
        for( j = 0; j < n_pkts; ++j ) {
          if( s.rx_pkt != NULL ) {
            ci_parse_rx_vlan(s.rx_pkt);
            handle_rx_pkt(ni, ps, s.rx_pkt);
          }
          handle_rx_multi_pkts(ni, &s, evq->rx_prefix_len, vi, intf_i);
        }
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_TX_WITH_TIMESTAMP ) {
        CITP_STATS_NETIF_INC(ni, tx_evs);
        OO_PP_INIT(ni, pp, ev[i].tx_timestamp.rq_id);
        pkt = PKT_CHK(ni, pp);
        ++ni->state->nic[intf_i].tx_dmaq_done_seq;
        __ci_netif_tx_pkt_complete(ni, ps, pkt, &ev[i]);
        completed_tx = 1;
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX_NO_DESC_TRUNC ) {
        handle_rx_no_desc_trunc(ni, ps, intf_i, &s, ev[i]);
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX_DISCARD ) {
        handle_rx_discard(ni, ps, intf_i, &s, ev[i]);
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX_MULTI_DISCARD ) {
        ef_request_id *ids = ni->rx_events;
        int n_ids, j;
        ef_vi* vi = CI_NETIF_RX_VI(ni, intf_i, ev[i].rx.q_id);
        n_ids = ef_vi_receive_unbundle(vi, &ev[i], ids);
        ci_assert_ge(n_ids, 0);
        ci_assert_le(n_ids, sizeof(ni->rx_events) / sizeof(ids[0]));
        total_evs += n_ids - 1;

        for( j = 0; j < n_ids; ++j )
          handle_rx_multi_discard(ni, ps, intf_i, &s, ev[i], ids[j], vi);
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_TX_ERROR ) {
        LOG_U(log(LPF "[%d] intf %d TX_ERROR %d "EF_EVENT_FMT,
                  NI_ID(ni), intf_i,
                  (int) EF_EVENT_TX_ERROR_TYPE(ev[i]),
                  EF_EVENT_PRI_ARG(ev[i])));
        CITP_STATS_NETIF_INC(ni, tx_error_events);
      }

      else if( EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_OFLOW ) {
        LOG_E(CI_RLLOG(1, LPF "***** EVENT QUEUE OVERFLOW *****"));
        return 0;
      }

      else {
        /* NB. If you see this for an RX event, then perhaps some code
         * which I thought was obsolete is needed. */
        ci_assert( EF_EVENT_TYPE(ev[i]) != EF_EVENT_TYPE_RX );
        LOG_E(log(LPF "***** UNKNOWN EVENT "EF_EVENT_FMT" (abstracted type:%d)"
                  " *****",
                  EF_EVENT_PRI_ARG(ev[i]), EF_EVENT_TYPE(ev[i])));
      }
    }

#ifndef NDEBUG
    {
      ef_vi* vi = CI_NETIF_TX_VI(ni, intf_i, ev[i].tx_timestamp.q_id);
      ci_assert_equiv((ef_vi_transmit_fill_level(vi) == 0 &&
                       ni->state->nic[intf_i].dmaq.num == 0),
                      (ni->state->nic[intf_i].tx_dmaq_insert_seq ==
                       ni->state->nic[intf_i].tx_dmaq_done_seq));
    }
#endif

    __handle_rx_pkt(ni, ps, intf_i, &s.rx_pkt);

    total_evs += n_evs;
  } while( total_evs < NI_OPTS(ni).evs_per_poll );

  /* If we've drained the TXQ, we can start trying CTPIO again. */
  if( completed_tx && ef_vi_transmit_fill_level(&ni->nic_hw[intf_i].vi) == 0 )
    ci_netif_ctpio_resume(ni, intf_i);

  if( s.frag_pkt != NULL ) {
    s.frag_pkt->pay_len = s.frag_bytes;
    ni->state->nic[intf_i].rx_frags = OO_PKT_P(s.frag_pkt);
  }

  return total_evs;
}


static int ci_netif_poll_intf(ci_netif* ni, int intf_i, int max_evs)
{
  struct ci_netif_poll_state ps;
  int total_evs = 0;
  int rc;

#if defined(__KERNEL__) || ! defined(NDEBUG)
  if( ! ci_netif_may_poll_in_kernel(ni, intf_i) )
    return 0;
#endif

  ci_assert(ci_netif_is_locked(ni));
  ps.tx_pkt_free_list_insert = &ps.tx_pkt_free_list;
  ps.tx_pkt_free_list_n = 0;

  do {
    rc = ci_netif_poll_evq(ni, &ps, intf_i, 0);
    if( rc > 0 ) {
      total_evs += rc;
      process_post_poll_list(ni);
    }
    else
      break;
  } while( total_evs < max_evs );

  if( ps.tx_pkt_free_list_n )
    ci_netif_poll_free_pkts(ni, &ps);

  /* The following steps probably aren't needed if we haven't handled any
   * events, but that is a rare case and so not worth testing for.
   */
  if( ci_netif_rx_vi_space(ni, ci_netif_rx_vi(ni, intf_i))
      >= CI_CFG_RX_DESC_BATCH )
    ci_netif_rx_post(ni, intf_i);

  if( ci_netif_dmaq_not_empty(ni, intf_i) )
    ci_netif_dmaq_shove1(ni, intf_i);

  return total_evs;
}


#ifndef __KERNEL__
int ci_netif_poll_intf_future(ci_netif* ni, int intf_i, ci_uint64 start_frc)
{
  int i, rc = 0, status;
  struct oo_rx_future future;
  ci_uint64 now_frc, max_spin;
  ef_vi* evq = &ni->nic_hw[intf_i].vi;
  ef_event* ev = ni->state->events;
  struct ci_netif_poll_state ps;
  ci_ip_pkt_fmt* pkt;

  ci_assert(ci_netif_is_locked(ni));
  ci_assert(ni->state->in_poll == 0);
#if CI_CFG_WANT_BPF_NATIVE
  ci_assert_equal(NI_OPTS(ni).poll_in_kernel, 0);
#endif

  pkt = ci_netif_intf_next_rx_pkt(ni, intf_i);
  if( pkt == NULL || ci_netif_rx_pkt_is_poisoned(pkt) )
    return 0;

  ci_assert_equal(pkt->intf_i, intf_i);
  ci_ip_time_update(IPTIMER_STATE(ni), start_frc);

  status = handle_rx_pre_future(ni, pkt, &future);
  if( status == FUTURE_NONE )
    return 0;

  /* From this point, the expectation is that we will receive the detected
   * packet. If that doesn't happen, then we must call rollback_rx_future,
   * which must undo any changes made here or in handle_rx_pre_future.
   */

  CITP_STATS_NETIF_INC(ni, rx_future);
  CITP_STATS_NETIF_INC(ni, rx_evs);

  ps.tx_pkt_free_list_insert = &ps.tx_pkt_free_list;
  ps.tx_pkt_free_list_n = 0;

  /* We expect the completion event within a microsecond or so. The timeout
   * of 100us is to avoid wedging the stack in the case of hardware
   * failure/removal or a bug which prevents us getting the event.
   */
  max_spin = IPTIMER_STATE(ni)->khz / 10000;
  ci_prefetch(pkt->dma_start + CI_CACHE_LINE_SIZE);
  while( (rc = ef_eventq_poll(evq, ev, EF_VI_EVENT_POLL_MIN_EVS)) == 0 ) {
    ci_frc64(&now_frc);
    if( now_frc - start_frc > max_spin ) {
      rollback_rx_future(ni, pkt, status, &future);
      return 0;
    }
  }

  /* The first and second lines should already be cached. Empirically, on some
   * platforms, there seems to be a small advantage to prefetching a couple
   * more at this point, ahead of copying the packet data.
   */
  for( i = 2; i < 5; ++i )
    ci_prefetch(pkt->dma_start + i * CI_CACHE_LINE_SIZE);

  ++ni->state->in_poll;
  if( EF_EVENT_TYPE(ev[0]) == EF_EVENT_TYPE_RX ) {
    ci_assert_equal(OO_PP_ID(OO_PKT_P(pkt)), EF_EVENT_RX_RQ_ID(ev[0]));
    if( (ev[0].rx.flags & (EF_EVENT_FLAG_SOP | EF_EVENT_FLAG_CONT))
                                                       == EF_EVENT_FLAG_SOP ) {
      pkt->pay_len = EF_EVENT_RX_BYTES(ev[0]) - evq->rx_prefix_len;
      oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->pay_len);

      handle_rx_post_future(ni, &ps, pkt, status, &future);
      if(CI_UNLIKELY( rc > 1 )) {
        /* We have handled the first event, so remove it from the array and
         * handle the rest normally. Add one to the returned count to include
         * the one handled here.
         */
        for( i = 1; i < rc; ++i )
          ev[i - 1] = ev[i];
        rc = 1 + ci_netif_poll_evq(ni, &ps, intf_i, rc - 1);
      }
      goto handled;
    }
  }
  /* maybe handle other simple events like TX? */

  rollback_rx_future(ni, pkt, status, &future);

  rc = ci_netif_poll_evq(ni, &ps, intf_i, rc);
  if( rc != 0 ) {
handled:
    process_post_poll_list(ni);
    ni->state->poll_work_outstanding = 1;
  }
  --ni->state->in_poll;
  if( ps.tx_pkt_free_list_n )
    ci_netif_poll_free_pkts(ni, &ps);
  return rc;
}
#endif


static void ci_netif_loopback_pkts_send(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p send_list = OO_PP_ID_NULL;
  ci_ipx_hdr_t* ip;
  int af;
#ifdef __KERNEL__
  int i = 0;
#endif

  CI_BUILD_ASSERT(
    CI_MEMBER_OFFSET(ci_ip_pkt_fmt_prefix, tcp_tx.lo.rx_sock) ==
    CI_MEMBER_OFFSET(ci_ip_pkt_fmt_prefix, tcp_rx.lo.rx_sock) );
  CI_BUILD_ASSERT(
    CI_MEMBER_OFFSET(ci_ip_pkt_fmt_prefix, tcp_tx.lo.tx_sock) ==
    CI_MEMBER_OFFSET(ci_ip_pkt_fmt_prefix, tcp_rx.lo.tx_sock) );

  while( OO_PP_NOT_NULL(ni->state->looppkts) ) {
#ifdef __KERNEL__
    if(CI_UNLIKELY( i++ > ni->pkt_sets_n * PKTS_PER_SET )) {
      ci_netif_error_detected(ni, CI_NETIF_ERROR_LOOP_PKTS_LIST, __FUNCTION__);
      return;
    }
#endif
    pkt = PKT_CHK(ni, ni->state->looppkts);
    ni->state->looppkts = pkt->next;
    pkt->next = send_list;
    send_list = OO_PKT_ID(pkt);
  }

  while( OO_PP_NOT_NULL(send_list) ) {
    pkt = PKT_CHK(ni, send_list);
    send_list = pkt->next;
    ni->state->n_looppkts--;

    LOG_NR(ci_log(N_FMT "loopback RX pkt %d: %d->%d", N_PRI_ARGS(ni),
                  OO_PKT_FMT(pkt),
                  OO_SP_FMT(pkt->pf.tcp_tx.lo.tx_sock),
                  OO_SP_FMT(pkt->pf.tcp_tx.lo.rx_sock)));

    oo_offbuf_init(&pkt->buf, PKT_START(pkt), pkt->buf_len);
    pkt->intf_i = OO_INTF_I_LOOPBACK;
    ci_assert_nflags(pkt->flags, CI_PKT_FLAG_RX);
    pkt->flags &= CI_PKT_FLAG_NONB_POOL;
    pkt->flags |= CI_PKT_FLAG_RX;
    ++ni->state->n_rx_pkts;
    pkt->tstamp_frc = IPTIMER_STATE(ni)->frc;
    if( oo_tcpdump_check(ni, pkt, OO_INTF_I_LOOPBACK) )
      oo_tcpdump_dump_pkt(ni, pkt);
    pkt->next = OO_PP_NULL;
#if CI_CFG_IPV6
  if( oo_pkt_ether_type(pkt) == CI_ETHERTYPE_IP6 )
    pkt->flags |= CI_PKT_FLAG_IS_IP6;
  else
    pkt->flags &=~ CI_PKT_FLAG_IS_IP6;
#endif

    ip = oo_ipx_hdr(pkt);
    af = oo_pkt_af(pkt);
    ci_tcp_handle_rx(ni, NULL, pkt, PKT_IPX_TCP_HDR(af, pkt),
                     ipx_hdr_tot_len(af, ip) - CI_IPX_IHL(af, ip));
  }
}


int ci_netif_poll_n(ci_netif* netif, int max_evs)
{
  int intf_i, n_evs_handled = 0;

#if defined(__KERNEL__) || ! defined(NDEBUG)
  if( netif->error_flags )
    return 0;
#endif

  ci_assert(ci_netif_is_locked(netif));
  CHECK_NI(netif);

#ifdef __KERNEL__
  CITP_STATS_NETIF_INC(netif, k_polls);
#else
  CITP_STATS_NETIF_INC(netif, u_polls);
#endif

  ci_ip_time_resync(IPTIMER_STATE(netif));
#if CI_CFG_UL_INTERRUPT_HELPER && ! defined(__KERNEL__)
  ci_netif_handle_actions(netif);
#endif

#if CI_CFG_HW_TIMER
  if( ci_netif_need_timer_prime(netif, IPTIMER_STATE(netif)->frc) ) {
    if( NI_OPTS(netif).timer_usec != 0 )
      OO_STACK_FOR_EACH_INTF_I(netif, intf_i)
        ef_eventq_timer_prime(&netif->nic_hw[intf_i].vi,
                              NI_OPTS(netif).timer_usec);
    netif->state->evq_last_prime = IPTIMER_STATE(netif)->frc;
  }
#endif

  ci_assert(netif->state->in_poll == 0);
  ++netif->state->in_poll;
  OO_STACK_FOR_EACH_INTF_I(netif, intf_i) {
    int n = ci_netif_poll_intf(netif, intf_i, max_evs);
    ci_assert(n >= 0);
    n_evs_handled += n;
  }

  while( OO_PP_NOT_NULL(netif->state->looppkts) ) {
    ci_netif_loopback_pkts_send(netif);
    process_post_poll_list(netif);
  }
  ci_assert_equal(netif->state->n_looppkts, 0);
  --netif->state->in_poll;

#if CI_CFG_INJECT_PACKETS
  /* If we've got packets that need to be forwarded to the kernel, and they are
   * sufficiently numerous or sufficiently old, do the forwarding when we drop
   * the lock. */
  if( ! OO_PP_IS_NULL(netif->state->kernel_packets_head) ) {
    ci_uint64 frc;
    ci_frc64(&frc);

    ci_assert_gt(netif->state->kernel_packets_pending, 0);

    if( netif->state->kernel_packets_pending >=
        NI_OPTS(netif).kernel_packets_batch_size ||
        frc - netif->state->kernel_packets_last_forwarded >=
        netif->state->kernel_packets_cycles )
      ef_eplock_holder_set_flag(&netif->state->lock,
                                CI_EPLOCK_NETIF_KERNEL_PACKETS);
  }
#endif

  /* Timer code can't use in-poll wakeup, since endpoints are out of
   * post-poll list.  So, poll timers after --in_poll. */
  ci_ip_timer_poll(netif);

  /* Timers MUST NOT send via loopback. */
  ci_assert(OO_PP_IS_NULL(netif->state->looppkts));

  if(CI_LIKELY( netif->state->rxq_low <= 1 ))
    netif->state->mem_pressure &= ~OO_MEM_PRESSURE_LOW;
  else
    netif->state->mem_pressure |= OO_MEM_PRESSURE_LOW;

  /* ?? TODO: move this into an unlock flag. */
  if(CI_UNLIKELY( netif->state->mem_pressure & OO_MEM_PRESSURE_CRITICAL ))
    if( ci_netif_mem_pressure_try_exit(netif) )
      CITP_STATS_NETIF_INC(netif, memory_pressure_exit_poll);

  netif->state->poll_work_outstanding = 0;

  /* returns the number of events handled */
  return n_evs_handled;
}

/*! \cidoxg_end */
