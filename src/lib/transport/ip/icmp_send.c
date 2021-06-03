/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  stg
**  \brief  ICMP utility functions for sending errors
**   \date  2003/12/28
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#include "ip_tx.h"

#include <ci/tools/ipcsum_base.h>

#define LPF "ci_icmp_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF


#if OO_DO_STACK_POLL

/* STATS */
/*! \todo Temporary stats in ICMP tx module need replacing */
typedef struct {
  ci_uint32 nobuf;
  ci_uint32 nospace;
  ci_uint32 sentok;
} ci_icmp_tx_stats;

static ci_icmp_tx_stats icmp_tx_stats = {0,0,0};

#define CI_ICMP_TX_STAT_NOBUF(ni) (icmp_tx_stats.nobuf++)
#define CI_ICMP_TX_STAT_NOSPACE(ni) (icmp_tx_stats.nospace++)
#define CI_ICMP_TX_STAT_SENT(ni) (icmp_tx_stats.sentok++)

/* IP header + 8 bytes is largest possible ICMP error payload */
#define CI_ICMP_MAX_PAYLOAD ( 60 + 8 )

/* Largest possible ICMP message that we're likely to send */
#define CI_ICMP_MAX_MSG_LEN \
  (sizeof(ci_ip4_hdr) + sizeof(ci_icmp_hdr) + 4 + CI_ICMP_MAX_PAYLOAD)

/**
 * Send an ICMP packet
 */
extern int
ci_icmp_send(ci_netif *ni, ci_ip_pkt_fmt *tx_pkt,
	     const ci_addr_t saddr, const ci_addr_t daddr,
	     const ci_mac_addr_t *mac_dest,
	     ci_uint8 type, ci_uint8 code, ci_uint16 data_len)
{
  struct oo_eth_hdr *tx_eth;
  ci_ipx_hdr_t *ipx;
  ci_icmp_hdr *icmp;
  unsigned csum;
  ci_uint16 payload_len;
  int af = oo_pkt_af(tx_pkt);

  ci_assert(ni);

  tx_eth = oo_ether_hdr(tx_pkt);
  ipx = oo_tx_ipx_hdr(af, tx_pkt);
  icmp = oo_tx_ipx_data(af, tx_pkt);

  /* Skip space for the IP4 hdr, ICMP hdr */
  ci_assert(sizeof(ci_icmp_hdr) == 4);
  oo_offbuf_init(&tx_pkt->buf, 
		 (char*)ipx + CI_IPX_HDR_SIZE(af) + sizeof(ci_icmp_hdr) + 4,
		 CI_ICMP_MAX_PAYLOAD);

  /* How much space free in the buffer?  */
  if (oo_offbuf_left(&tx_pkt->buf) < CI_ICMP_MAX_PAYLOAD) {
    LOG_IPP( log(LPF "send_error: Buffer too short for an ICMP msg (%d)!",
		 oo_offbuf_left(&tx_pkt->buf)));
    ci_netif_pkt_release(ni, tx_pkt);	
    CI_ICMP_TX_STAT_NOSPACE(ni);
    return -1;
  }

  /* Sort out the eth hdr, the ip_send call will deal with our MAC  */
  memcpy( tx_eth->ether_dhost, mac_dest, ETH_ALEN );
  tx_eth->ether_type = ci_af2ethertype(af);

  /* do the IP hdr, we trust the IP addresses in the rx pkt as they
   * managed to get the message thus far  */
  memset(ipx, 0, CI_IPX_HDR_SIZE(af));
  ci_ipx_hdr_init_fixed(ipx, af, IS_AF_INET6(af) ? IPPROTO_ICMPV6 :IPPROTO_ICMP,
                        CI_IPX_DFLT_TTL_HOPLIMIT(af),
                        CI_IPX_DFLT_TOS_TCLASS(af));
  if( !IS_AF_INET6(af) )
    ipx->ip4.ip_id_be16 = CI_BSWAP_BE16(NEXT_IP_ID(ni));
  ipx_hdr_set_saddr(af, ipx, saddr);
  ipx_hdr_set_daddr(af, ipx, daddr);

  payload_len = sizeof(ci_icmp_hdr) + 4 + data_len;
  ipx_hdr_set_payload_len(af, ipx, payload_len);

  /* do the ICMP hdr */
  icmp->type = type;
  icmp->code = code;
  icmp->check = 0;
  ci_assert( sizeof(ci_icmp_hdr) == 4 );
  /* set ICMP checksum */
#if CI_CFG_IPV6
  if( IS_AF_INET6(af) ) {
    icmp->check = ci_icmpv6_checksum(&ipx->ip6, icmp);
  }
  else
#endif
  {
    csum = ci_ip_csum_partial(0, icmp, sizeof(ci_icmp_hdr) + 4 + data_len );
    icmp->check = (ci_uint16)ci_icmp_csum_finish(csum);
    ipx->ip4.ip_check_be16 = (ci_uint16)ci_ip_checksum(&ipx->ip4);
  }

  tx_pkt->buf_len = tx_pkt->pay_len =
    oo_tx_ether_hdr_size(tx_pkt) + CI_IPX_HDR_SIZE(af) + payload_len;

  /* ?? FIXME: This will lookup the dest IP in the route table to choose
   * the interface to send on, but really we should reply back through the
   * same interface that we received on.
   */
  ci_ip_send_pkt(ni, NULL, tx_pkt);

  /* NB: (bug?) this will fill in the destination MAC addresses based on
         the first hop to the destination IP address (despite assigning
	 it above) - really we should send the reply back through the same
	 interface that is was received on - no matter what our routing table
	 says.
	 Note that if we do fill in a different MAC address it will
	 invalidate the ICMP checksum!
  */

  ci_netif_pkt_release(ni, tx_pkt);
  CI_ICMP_TX_STAT_SENT(ni);
  LOG_IPP(log(LPF "send_error: sent %d/%d to " IPX_FMT,
	      code, type, IPX_ARG(AF_IP(daddr))));

  return 0;
}




/**
 * Generate an ICMP error in the context of the netif and the given 
 * received packet. The outbound error will use type/code and contain
 * the IP hdr & first 8 bytes of the payload of pkt.
 */
extern int __ci_icmp_send_error(ci_netif *ni, int af,
				ci_ipx_hdr_t* ipx,
				struct oo_eth_hdr* rx_eth,
	                        ci_uint8 type, ci_uint8 code)
{
  ci_addr_t saddr, daddr;

  ci_assert(ni);
  ci_assert(ipx);
  ci_assert(rx_eth);

  saddr = ipx_hdr_saddr(af, ipx);
  daddr = ipx_hdr_daddr(af, ipx);

  /* Bug1729, Bug1731: LAND attack sets source addr=dest addr, thus our "trust"
   * mentioned below is utterly misplaced ...
   */
  if( cicp_user_is_local_addr(ni->cplane, saddr) ) {
    char buf[32];
    ci_uint8 protocol = ipx_hdr_protocol(af, ipx);
    if( protocol == IPPROTO_TCP )
      strcpy(buf, "TCP packet");
    else if ( protocol == IPPROTO_UDP )
      strcpy(buf, "UDP packet");
    else
      snprintf(buf, sizeof(buf), "packet with protocol=%u", protocol);
    if( CI_IPX_ADDR_EQ(saddr, daddr) ) {
      LOG_U(ci_log("WARNING: Unexpected receipt of a %s with source IP\n"
                   "address = dest IP address (" IPX_FMT "). Possible LAND attack.\n"
                   "Not sending ICMP type=%u code=%u", buf,
                   IPX_ARG(AF_IP(saddr)), type, code));
    } else {
      /*! \todo We could reply from here using a raw socket given that we're happy
       * that the received packet isn't some kind of vulnerability attack */
      LOG_U(ci_log("Unexpected receipt of a %s packet from a local IP\n"
                   "address (" IPX_FMT "). Not sending ICMP type=%u code=%u", buf,
                   IPX_ARG(AF_IP(saddr)), type, code));
    }
    return -1;
    
  } else
  { ci_ip_pkt_fmt *tx_pkt = ci_netif_pkt_alloc(ni, 0);
    
    if (NULL == tx_pkt) {
      LOG_IPP( log(LPF "send-error: !!No buff, yet expected at least one!!")); 
      CI_ICMP_TX_STAT_NOBUF( ni );
      return -1;
      
    } else
    { ci_uint16 data_len = CI_MIN( (int)CI_IPX_IHL(af, ipx) + 8,
                                   ipx_hdr_tot_len(af, ipx) );
      ci_icmp_hdr *icmp;

      oo_tx_pkt_layout_init(tx_pkt);
      oo_tx_ether_type_set(tx_pkt, ci_af2ethertype(af));
      oo_pkt_af_set(tx_pkt, af);
      icmp = oo_tx_ipx_data(af, tx_pkt);

      *(ci_uint32*)&icmp[1] = 0;
      memcpy( &icmp[2], ipx, data_len );

      return ci_icmp_send(ni, tx_pkt, daddr, saddr,
			  /*mac_dest*/(const ci_mac_addr_t *)
			      &rx_eth->ether_shost,
			  type, code, data_len);
    }
  }
}



#endif
/*! \cidoxg_end */
