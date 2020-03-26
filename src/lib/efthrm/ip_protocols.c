/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  Char driver support for ICMP, IGMP
**   \date  2004/06/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_driver_efab */

#include <onload/linux_ip_protocols.h>
#include <ci/internal/ip.h>
#include <ci/tools/ipcsum_base.h>
#include <onload/debug.h>
#include <onload/tcp_helper_fns.h>

#ifndef NDEBUG
# define __ENTRY OO_DEBUG_IPP(ci_log("-> %s", __FUNCTION__))
# define __EXIT(s) OO_DEBUG_IPP(ci_log("<- %s %s", __FUNCTION__, (s) ? (s) : ""))
#else
# define __ENTRY
# define __EXIT(s)
#endif

#define DEBUGPMTU OO_DEBUG_IPP

#define VERB(x)

/* ****************************************** 
 * Packet enqueue functions
 */

ci_inline int ci_ipp_ip_csum_ok(ci_ip4_hdr* ip)
{
  unsigned csum;
  ci_uint16 pkt_csum;

  __ENTRY;
  ci_assert( ip );

  pkt_csum = ip->ip_check_be16;
  ip->ip_check_be16 = 0;
  csum = ci_ip_hdr_csum_finish(ci_ip_csum_partial(0, ip, CI_IP4_IHL(ip)));
  ip->ip_check_be16 = pkt_csum;
#ifndef NDEBUG
  if( csum != pkt_csum )
    OO_DEBUG_IPP(ci_log("%s: pkt sum:%x we get:%x", __FUNCTION__, pkt_csum, csum));
#endif
  __EXIT(0);
  return csum == pkt_csum;
}

/* Sum the ICMP hdr/payload 
 * \return 0 if csum failed
 */
int ci_ipp_icmp_csum_ok( ci_icmp_hdr* icmp, int icmp_total_len)
{
  unsigned csum;
  ci_uint16 csum_pkt;

  __ENTRY;
  ci_assert(icmp);
  ci_assert( icmp_total_len > 0 );
  ci_assert( icmp_total_len < 0x10000 );

  csum_pkt = icmp->check;
  icmp->check = 0;

  csum = ci_ip_csum_partial(0, icmp, icmp_total_len);
  csum = ci_icmp_csum_finish(csum);

  icmp->check = csum_pkt;
#ifndef NDEBUG
  if( csum != csum_pkt )
    OO_DEBUG_IPP(ci_log("%s: pkt len %d, sum:%x we get:%x", __FUNCTION__, 
		    icmp_total_len, csum_pkt, csum));
#endif
  __EXIT(0);
  return csum == csum_pkt;
}

/*! efab_ipp_icmp_parse -
 * Get the important info out of the ICMP hdr & it's payload
 *
 * If ok, the addr struct will have the addresses/ports and protocol
 * in it.
 * \param  ip  pointer to IP header - if [dta_only] != 0 then this is 
 *  the *data* IP address (i.e. the failing packet hdr)
 * \param  ip_len length of *ip
 * \param  addr   output: addressing data parsed from *[ip]
 * \param  data_only  [ip] points to data IP rather than ICMP IP hdr
 *
 * \return 1 - ok, 0 - failed.  If [data_only] != 0 then on success
 * addr->ip & addr->icmp will both be 0.  If [data_only] == 0 then
 * on success both addr->ip and addr->icmp will be valid pointers.
 */
extern int
efab_ipp_icmp_parse(const ci_ipx_hdr_t* ipx, int ip_len, efab_ipp_addr* addr,
		    int data_only )
{
  const ci_ipx_hdr_t* data_ipx;
  ci_icmp_hdr* icmp;
  ci_tcp_hdr* data_tcp;
  ci_udp_hdr* data_udp;
  int ip_paylen, af, data_ipx_af;
  ci_uint8 data_ipx_proto;

  __ENTRY;
  ci_assert( ipx );
  ci_assert( addr );

  af = ipx_hdr_af(ipx);

  ip_paylen = ipx_hdr_tot_len(af, ipx);

  if( !data_only ) {
    /* remotely generated (ICMP) errors */
    addr->ipx = ipx;
    addr->icmp = icmp = (ci_icmp_hdr*)((char*)ipx + CI_IPX_IHL(af, ipx));

    if( ip_paylen > ip_len ) {
      /* ?? how do I record this in the ICMP stats */
      OO_DEBUG_IPP(ci_log("%s: truncated packet %d %d", __FUNCTION__, 
		      ip_paylen, ip_len));
      return 0;
    }
    /* uncount the ICMP message IP hdr & ICMP hdr */
    ci_assert( sizeof(ci_icmp_hdr) == 4 );
    ip_paylen -= (int)CI_IPX_IHL(af, ipx) + sizeof(ci_icmp_hdr) + 4;
    data_ipx = (ci_ipx_hdr_t*)((char*)icmp + sizeof(ci_icmp_hdr) + 4);
  } else { 
    /* Locally generated errors */
    addr->ipx = 0;
    addr->icmp = icmp = 0;
    data_ipx = ipx;
  }

  data_ipx_af = ipx_hdr_af(data_ipx);
  data_ipx_proto = ipx_hdr_protocol(data_ipx_af, data_ipx);

  /* note that we swap the source/dest addr:port info - this means
   * that the sense of the addresses is correct for the lookup */
  if( data_ipx_proto == IPPROTO_IP || data_ipx_proto == IPPROTO_TCP ) {
    data_tcp = (ci_tcp_hdr*)((char*)data_ipx + CI_IPX_IHL(data_ipx_af, data_ipx));
    addr->protocol = IPPROTO_TCP;
    addr->sport_be16 = data_tcp->tcp_dest_be16;
    addr->dport_be16 = data_tcp->tcp_source_be16;
  } else if ( data_ipx_proto == IPPROTO_UDP ) {
    data_udp = (ci_udp_hdr*)((char*)data_ipx + CI_IPX_IHL(data_ipx_af, data_ipx));
    addr->protocol = IPPROTO_UDP;
    addr->sport_be16 = data_udp->udp_dest_be16;
    addr->dport_be16 = data_udp->udp_source_be16;
  } else {
    OO_DEBUG_IPP(ci_log("%s: Unknown protocol %d", __FUNCTION__, 
                        data_ipx_proto));
    return 0;
  }

  addr->data = (ci_uint8*)data_ipx;
  addr->data_len =  ip_paylen;
  addr->saddr = ipx_hdr_daddr(data_ipx_af, data_ipx);
  addr->daddr = ipx_hdr_saddr(data_ipx_af, data_ipx);
  __EXIT(0);
  return 1;
}

/*! efab_ipp_icmp_validate -
 * Check to see if the ICMP pkt is one we want to handle and is 
 * well-formed. We don't check the sums as there should only be one
 * copy passed-in.
 *
 * If ok, the addr struct will have the addresses/ports and protocol
 * in it.
 *
 * \return 1 - ok, 0 - failed
 */
extern int 
efab_ipp_icmp_validate( tcp_helper_resource_t* thr, ci_ip4_hdr *ip)
{
  ci_icmp_hdr* icmp;
  int ip_paylen, ip_tot_len;

  __ENTRY;
  ci_assert( thr );
  ci_assert( ip );
   
  icmp = (ci_icmp_hdr*)((char*)ip + CI_IP4_IHL(ip));
  ip_tot_len = CI_BSWAP_BE16(ip->ip_tot_len_be16);
  ip_paylen = ip_tot_len - CI_IP4_IHL(ip);

  OO_DEBUG_IPP( ci_log("%s: ip: tot len:%u, pay_len:%u", 
		   __FUNCTION__, ip_tot_len, ip_paylen ));

  /* Done in net driver */

  /* as we may be making more than one copy of this ICMP message we
   * may be saving time by doing the sum just once. Or maybe not. */
  if( CI_UNLIKELY( !ci_ipp_icmp_csum_ok( icmp, ip_paylen))) {
    __EXIT("bad ICMP sum");
    return 0;
  }

  __EXIT(0);
  return 1;
}

#if ! CI_CFG_UL_INTERRUPT_HELPER
/*!
 * Mapping of ICMP code field of destination unreachable message to errno.
 * The mapping is based on linux sources.
 */
static struct icmp_error {
  int errno;
  ci_uint8 hard;  /* Hard errors will be reported by so_error
                   * even if error queue is disabled. */
} icmp_du_code2errno[CI_ICMP_DU_CODE_MAX] = {
  { ENETUNREACH,  0 },   /* ICMP_NET_UNREACH   */
  { EHOSTUNREACH, 0 },   /* ICMP_HOST_UNREACH  */
  { ENOPROTOOPT,  1 },   /* ICMP_PROT_UNREACH  */
  { ECONNREFUSED, 1 },   /* ICMP_PORT_UNREACH  */
  { EMSGSIZE,     1 },   /* ICMP_FRAG_NEEDED   */
  { EOPNOTSUPP,   0 },   /* ICMP_SR_FAILED     */
  { ENETUNREACH,  1 },   /* ICMP_NET_UNKNOWN   */
  { EHOSTDOWN,    1 },   /* ICMP_HOST_UNKNOWN  */
  { ENONET,       1 },   /* ICMP_HOST_ISOLATED */
  { ENETUNREACH,  1 },   /* ICMP_NET_ANO       */
  { EHOSTUNREACH, 1 },   /* ICMP_HOST_ANO      */
  { ENETUNREACH,  0 },   /* ICMP_NET_UNR_TOS   */
  { EHOSTUNREACH, 0 }    /* ICMP_HOST_UNR_TOS  */
};

#if CI_CFG_IPV6
static struct icmp_error icmpv6_du_code2errno[CI_ICMPV6_DU_CODE_MAX] = {
  { ENETUNREACH,  0 },   /* NOROUTE            */
  { EACCES,       1 },   /* ADM_PROHIBITED     */
  { EHOSTUNREACH, 0 },   /* NOT_NEIGHBOUR      */
  { EHOSTUNREACH, 0 },   /* ADDR_UNREACH       */
  { ECONNREFUSED, 1 },   /* PORT_UNREACH       */
  { EACCES,       1 },   /* POLICY_FAIL        */
  { EACCES,       1 }    /* REJECT_ROUTE       */
};
#endif

/*!
 * Maps received ICMP message type and code fields to host errno value
 * according to STEVENS, section 25.7
 *
 * \param type  ICMP type
 * \param code  ICMP code
 * \param err   errno that corresponds to ICMP type/code
 * \param hard  whether the error is hard
 */
static void get_errno(int af, ci_uint8 type, ci_uint8 code,
                      int *err, ci_uint8 *hard)
{
#if CI_CFG_IPV6
  if( af == AF_INET6 ) {
    *err = EPROTO;
    *hard = 0;
    if( type == CI_ICMPV6_DEST_UNREACH ) {
      if (code < CI_ICMPV6_DU_CODE_MAX) {
        *err = icmpv6_du_code2errno[code].errno;
        *hard = icmpv6_du_code2errno[code].hard;
      }
      else {
        *hard = 1;
      }
    }
  }
  else
#endif
  {
    switch (type) {
    case CI_ICMP_DEST_UNREACH:
      if (code < CI_ICMP_DU_CODE_MAX) {
        *err = icmp_du_code2errno[code].errno;
        *hard = icmp_du_code2errno[code].hard;
      }
      else {
        *err = EHOSTUNREACH;
        *hard = 1;
      }
      break;

    case CI_ICMP_SOURCE_QUENCH:
      *err = 0;
      *hard  = 0;
      break;

    case CI_ICMP_TIME_EXCEEDED:
      *err = EHOSTUNREACH;
      *hard = 0;
      break;

    case CI_ICMP_PARAMETERPROB:
      *err = EPROTO;
      *hard = 1;
      break;

    default:
      *err = EHOSTUNREACH;
      *hard = 0;
    }
  }
}
#endif

typedef struct {
  ci_icmp_hdr hdr;
  ci_uint16   unused;
  ci_uint16   next_hop_mtu_be16;
} ci_icmp_too_big_t;


#define CI_PMTU_PRINTF_SOCKET_FORMAT IPX_PORT_FMT "->" IPX_PORT_FMT

#define CI_PMTU_PRINTF_SOCKET_ARGS(ipp_addr) \
  IPX_ARG(AF_IP(ipp_addr->saddr)),           \
  CI_BSWAP_BE16(ipp_addr->sport_be16),       \
  IPX_ARG(AF_IP(ipp_addr->daddr)),           \
  CI_BSWAP_BE16(ipp_addr->dport_be16)


#if ! CI_CFG_UL_INTERRUPT_HELPER
static void 
ci_ipp_pmtu_rx(ci_netif *netif, ci_pmtu_state_t *pmtus,
               ci_ip_cached_hdrs *ipcache,
               efab_ipp_addr* addr)
{
  const ci_uint16 plateau[] = CI_PMTU_PLATEAU_ENTRIES;
  ci_ipx_hdr_t* ipx;        /* hdr of failing packet */
  ci_uint16 len;         /* length of failing packet */
  ci_icmp_too_big_t *tb = (ci_icmp_too_big_t*)addr->icmp;
  int ctr;

  if( !CI_IPX_ADDR_EQ(ipcache_raddr(ipcache), addr->saddr) ) {
    DEBUGPMTU(ci_log("%s: "CI_PMTU_PRINTF_SOCKET_FORMAT
                     " addresses don't match",
                     __FUNCTION__, CI_PMTU_PRINTF_SOCKET_ARGS(addr)));
    return;
  }
  
  /* rfc1191 provides for this icmp message to have zero in the field
   * as defined in rfc792 */
  len = CI_BSWAP_BE16(tb->next_hop_mtu_be16);
  if( len == 0 ) {
    ci_assert( sizeof(*tb) == (sizeof(ci_icmp_hdr) + 4) );
    ipx = (ci_ipx_hdr_t*)(&tb[1]);
    len = ipx_hdr_tot_len(ipx_hdr_af(ipx), ipx);
    ctr = CI_PMTU_PLATEAU_ENTRY_MAX;
    while( ctr >= 0 && len <= plateau[ctr] )
      --ctr;
    DEBUGPMTU(ci_log("%s: (legacy icmp) pmtu=%u(%d) ip_tot_len=%d",
	             __FUNCTION__, plateau[ctr], ctr, len));
    len = plateau[ctr];
  } else {
    DEBUGPMTU(ci_log("%s: (rfc1191) next hop mtu = %d", __FUNCTION__, len));
  }
  
  /* must have been delayed as we're already below the reported len */
  if( CI_UNLIKELY(len >= pmtus->pmtu) ) {
    DEBUGPMTU(ci_log("%s: "CI_PMTU_PRINTF_SOCKET_FORMAT
                     " ignoring, current_pmtu=%d pkt_pmtu=%d", __FUNCTION__,
                     CI_PMTU_PRINTF_SOCKET_ARGS(addr), pmtus->pmtu, len));
    return;
  }
  
  /* hardly a worth-while dos attack, however ... */
  /* ... (proof that i'm not great at predictions) by april 2005 it was picked
   *  up by the media as part of a world-spanning problem :-) */
  if( CI_UNLIKELY(len < plateau[0]) ) {
    int i = CI_PMTU_PLATEAU_ENTRY_MAX;
    ci_uint16 npl;
    ci_assert_ge(ipcache->mtu, plateau[0]);
    while( plateau[i] > ipcache->mtu )
      i--;
    npl = plateau[i];
    if( ipcache->mtu == npl && i != 0 )
      npl = plateau[i-1];
    /* see bug 3667 where ANVL requires us to reduce the PMTU a bit
       from default; this matches the Linux behaviour, and also
       prevents the DoS attack */
    DEBUGPMTU(ci_log("%s: "CI_PMTU_PRINTF_SOCKET_FORMAT
                     " warning, below minimum (l:%d) dos?"
		     " using maximum plateua %d", 
		     __FUNCTION__,
                     CI_PMTU_PRINTF_SOCKET_ARGS(addr), len, npl));
    len = npl;
  }
  
  DEBUGPMTU(ci_log("%s: "CI_PMTU_PRINTF_SOCKET_FORMAT
                   " curr_pmtu=%d, pkt_pmtu=%d", __FUNCTION__,
                   CI_PMTU_PRINTF_SOCKET_ARGS(addr), pmtus->pmtu, len));

  /* if we're already at index 0 we just get out - there should be a timer
   * in the system & if we re-trigger it we may never actually get back to 
   * a sensible value (we probably won't anyway - this is probably occurring
   * because of a dos attack) */
  /*! \todo sort out a better way to handle malicious messages - for example
   * we could ignore pmtu for some time if we cannot get away from the min. */
  ci_assert_ge(pmtus->pmtu, CI_CFG_TCP_MINIMUM_MSS);
  if( CI_UNLIKELY(pmtus->pmtu == plateau[0]) ) {
    DEBUGPMTU(ci_log("%s: icmp too big and at min pmtu. dos?", __FUNCTION__));
    return;
  }

  ci_pmtu_update_slow(netif, pmtus, ipcache, len);

#if CI_CFG_FAST_RECOVER_PMTU_AT_MIN
  if( CI_UNLIKELY(s->pmtus.pmtu == plateau[0]) ) {
    DEBUGPMTU(ci_log("%s: min pmtu! (recover timer)", __FUNCTION__));
    ci_pmtu_discover_timer(&thr->netif, &s->pmtus,
                           &thr->netif.tconst_pmtu_discover_recover);
  }
#endif
}


/* ci_ipp_pmtu_rx_tcp -
 * handler for the receipt of "datagram too big" icmp messages - 
 * just extracts the most likely plateau to use.
 */
static void 
ci_ipp_pmtu_rx_tcp(tcp_helper_resource_t* thr, 
                   ci_tcp_state* ts, efab_ipp_addr* addr)
{
  ci_pmtu_state_t* pmtus;
  ci_assert( thr );
  ci_assert( ts );
  ci_assert( addr );
  ci_assert( addr->icmp );
  ci_assert( sizeof(ci_icmp_hdr) == 4 );

  if (ts->s.b.state == CI_TCP_LISTEN) {
    DEBUGPMTU(ci_log("%s: " IPX_PORT_FMT "->" IPX_PORT_FMT
                     " listening socket - aborting", __FUNCTION__,
                     IPX_ARG(AF_IP(addr->saddr)),
                     CI_BSWAP_BE16(addr->sport_be16),
                     IPX_ARG(AF_IP(addr->daddr)),
                     CI_BSWAP_BE16(addr->dport_be16)));
    return;
  }

  if( OO_PP_IS_NULL(ts->pmtus) ) {
    ts->pmtus = ci_ni_aux_alloc(&thr->netif, CI_TCP_AUX_TYPE_PMTUS);
    if( OO_PP_IS_NULL(ts->pmtus) ) {
      ci_log("%s: " IPX_PORT_FMT "->" IPX_PORT_FMT
             " out of PMTU buffers", __FUNCTION__,
             IPX_ARG(AF_IP(addr->saddr)),
             CI_BSWAP_BE16(addr->sport_be16),
             IPX_ARG(AF_IP(addr->daddr)),
             CI_BSWAP_BE16(addr->dport_be16));
    }

    pmtus = ci_ni_aux_p2pmtus(&thr->netif, ts->pmtus);
    ci_pmtu_state_init(&thr->netif, &ts->s, ts->pmtus, pmtus,
                       CI_IP_TIMER_PMTU_DISCOVER);
    ci_pmtu_set(&thr->netif, pmtus,
                CI_MIN(ts->s.pkt.mtu,
                       ts->smss + sizeof(ci_tcp_hdr) +
                       CI_IPX_HDR_SIZE(ipcache_af(&ts->s.pkt))));
  }
  else {
    pmtus = ci_ni_aux_p2pmtus(&thr->netif, ts->pmtus);
  }

  ci_ipp_pmtu_rx(&thr->netif, pmtus, &ts->s.pkt, addr);

  DEBUGPMTU(ci_log("%s: set eff_mss & change tx q to match", __FUNCTION__));
  ci_tcp_tx_change_mss(&thr->netif, ts);
}

struct ipp_pmtu_udp_work {
  struct work_struct w;

  struct cp_fwd_key key;
  struct oo_cplane_handle *cplane;
};

static void ci_ipp_pmtu_rx_udp_work(struct work_struct *data)
{
  struct ipp_pmtu_udp_work* w = container_of(data,
                                             struct ipp_pmtu_udp_work,
                                             w);

  /* This is always the stack-local cplane, so we can use its ID as the ID for
   * the fwd table. */
  oo_op_route_resolve(w->cplane, &w->key, w->cplane->cplane_id);
  kfree(w);
}

/* ci_ipp_pmtu_rx_udp -
 * handler for the receipt of "datagram too big" icmp messages
 *
 * When we finish here, this ICMP is passed back to Linux IP stack; Linux
 * stores the PMTU limitation in its route cache.  All we need to do is to
 * ask Linux about the new routing data; Linux will tell us the new PMTU
 * data and how long it is valid.
 */
static void 
ci_ipp_pmtu_rx_udp(tcp_helper_resource_t* thr, 
                   ci_udp_state* us, efab_ipp_addr* addr)
{
  struct ipp_pmtu_udp_work* w;
  struct cp_fwd_data data;
  cicp_verinfo_t verinfo;

  OO_DEBUG_IPP(ci_log("%s: ICMP route from " IPX_FMT
                      " to " IPX_FMT " ifindex %d", __FUNCTION__,
                      IPX_ARG(AF_IP(addr->daddr)), IPX_ARG(AF_IP(addr->saddr)),
                      addr->ifindex));

  if( !CI_IPX_ADDR_IS_ANY(us->s.cp.laddr) &&
      !CI_IPX_ADDR_EQ(us->s.cp.laddr, addr->daddr))
    return;
  if( us->s.cp.so_bindtodevice != 0 &&
      us->s.cp.so_bindtodevice != addr->ifindex )
    return;

  w = kmalloc(sizeof(struct ipp_pmtu_udp_work), GFP_ATOMIC);
  if( w == NULL )
    return;

  /* This is a sort of UDP-specific copy of cicp_user_retrieve().
   * Fixme: Do we need to support multicast here?  IP_TRANSPARENT? */
  memset(w, 0, sizeof(*w));
  INIT_WORK(&w->w, ci_ipp_pmtu_rx_udp_work);
  w->key.dst = CI_ADDR_SH_FROM_ADDR(addr->saddr);
  w->key.src = CI_ADDR_SH_FROM_ADDR(us->s.cp.laddr);
  w->key.ifindex = us->s.cp.so_bindtodevice;
  w->key.flag = CP_FWD_KEY_SOURCELESS | CP_FWD_KEY_REQ_REFRESH;
  if( us->s.cp.sock_cp_flags & OO_SCP_TPROXY )
    w->key.flag |= CP_FWD_KEY_TRANSPARENT;
  w->cplane = thr->netif.cplane;

  if( __oo_cp_route_resolve(w->cplane, &verinfo, &w->key, 0, &data,
                            w->cplane->cplane_id) != 0 ) {
    /* Our forward cache does not know about such a route.  Have we ever
     * sent a datagram via it, or is it an attack?  In any case let's
     * kernel handle this.
     */
    kfree(w);
    return;
  }

  /* We're going to defer to a workqueue, which relies on the property that we
   * now assert, but which can't assert it itself because it doesn't have a
   * reference to the stack. */
  ci_assert_equal(w->cplane, thr->netif.cplane);

  /* Nothing prevents us from calling oo_op_route_resolve() right now,
   * but we have a good chance to get a Linux route information before
   * this ICMP will be handled by Linux.  A workqueue does not give us
   * any guarantee as well, but we have a better chance to loose this race.
   * Otherwise we'll get another ICMP and will refresh PMTU correctly from
   * the second attempt. */
  queue_work(thr->wq, &w->w);
}
#endif

/* efab_ipp_icmp_for_thr -
 * Is this ICMP message destined for this netif 
 *
 * MUST NOT make use of addr->ip & addr->icmp fields without
 * checking as they can both be 0 
 */
ci_sock_cmn* efab_ipp_icmp_for_thr( tcp_helper_resource_t* thr, 
				    efab_ipp_addr* addr )
{
  int af_space;

  ci_assert( thr );
  ci_assert( addr );
  ci_assert( addr->data );

  af_space = (CI_IS_ADDR_IP6(addr->saddr)) ? AF_SPACE_FLAG_IP6 : AF_SPACE_FLAG_IP4;

  return  __ci_netif_filter_lookup(&thr->netif, af_space,
                                   addr->daddr, addr->dport_be16,
                                   addr->saddr, addr->sport_be16,
                                   addr->protocol);
}

/* efab_ipp_icmp_qpkt -
 * Enqueue an ICMP packet into the TCP helper's netif. 
 * This function is assumed to be called within a lock on the 
 * tcp_helper_resource's ep.
 */
extern void
efab_ipp_icmp_qpkt(tcp_helper_resource_t* thr, 
		   ci_sock_cmn* s, efab_ipp_addr* addr)
{
  ci_uint8 icmp_type, icmp_code;
#if ! CI_CFG_UL_INTERRUPT_HELPER
  ci_uint8 hard;
  int err;
  ci_netif* ni = &thr->netif;
  int af = ipx_hdr_af(addr->ipx);

  ci_assert(thr);
  ci_assert(thr->netif.state);
  ci_assert(s);
  ci_assert(addr);
  ci_assert(addr->data);
  /* If the address was created without an
   * IP/ICMP hdr then these will be 0 */
  ci_assert(addr->ipx);
  ci_assert(addr->icmp);

  ci_assert( ci_netif_is_locked(ni) );
#endif

  icmp_type = addr->icmp->type;
  icmp_code = addr->icmp->code;

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* Path MTU interception */
  if ( ( IS_AF_INET6(af) && icmp_type == CI_ICMPV6_PKT_TOOBIG ) ||
       (!IS_AF_INET6(af) && icmp_type == CI_ICMP_DEST_UNREACH &&
       icmp_code == CI_ICMP_DU_FRAG_NEEDED) )
  {
    if (addr->protocol == IPPROTO_TCP)
      ci_ipp_pmtu_rx_tcp(thr, SOCK_TO_TCP(s), addr);
    else
      ci_ipp_pmtu_rx_udp(thr, SOCK_TO_UDP(s), addr);
    return;
  }

  /* UDP is interested in PMTU only */
  if (addr->protocol == IPPROTO_UDP)
    return;
  ci_assert_equal(addr->protocol, IPPROTO_TCP);

  if( s->b.state == CI_TCP_SYN_SENT ) 
      /* \todo we should handle tsr from listening sockets as well */
  {
    ci_tcp_state* ts = SOCK_TO_TCP(s);

    CITP_STATS_NETIF(++ni->state->stats.tcp_connect_icmp);
    get_errno(af, icmp_type, icmp_code, &err, &hard);
    OO_DEBUG_IPP(ci_log("%s: TCP", __FUNCTION__));

    ci_tcp_drop(ni, ts, err);
  }
#else
  /* Todo: kick it off to onload_helper. */
  ci_log("ERROR: ICMP type %d code %d", icmp_type, icmp_code);
#endif
}

/*! \cidoxg_end */
