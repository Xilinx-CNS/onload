/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  ICMP & IGMP & UDP handlers.  UDP handling is
**          for broadcasts which are not (currently) filtered by the NIC.
**          Used by linux/windows/sunos despite the filename
**   \date  2004/06/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_LINUX__IP__PROTOCOLS_H__
#define __CI_DRIVER_EFAB_LINUX__IP__PROTOCOLS_H__

#ifndef __ci_driver__
#error "This is a driver module."
#endif

#include <onload/tcp_helper.h>
#include <onload/ip_protocols.h>
#include <ci/internal/transport_config_opt.h> /* for CI_CFG_ERROR_PASS_UP */


/*! efab_handle_ipp_pkt_task -
 * ICMP, IGMP, UDP etc. delivery handler.  Called from the 
 * ARP keventd tasklet. */
extern int 
efab_handle_ipp_pkt_task(int thr_id, ci_ifid_t ifindex,
                         const void* ip_hdr, int len);

/*! efab_ipp_icmp_parse -
 * Get the important info out of the ICMP hdr & it's payload
 *
 * If ok, the addr struct will have the addresses/ports and protocol
 * in it.
 *
 * \param  data_only   0 = *[ip] points to IP/ICMP hdr + data
 *                     non-0 = *[ip] points to IP/[TCP|UDP]
 *
 * \return 1 - ok, 0 - failed
 */
extern int 
efab_ipp_icmp_parse(const ci_ipx_hdr_t*, int ip_len, efab_ipp_addr* addr,
		    int data_only );

/*! efab_ipp_icmp_validate -
 * Check to see if the ICMP pkt is well-formed.
 *
 * \return 0 - ok, else failed
 */
extern int 
efab_ipp_icmp_validate( tcp_helper_resource_t* thr, 
			ci_ip4_hdr* ip );

/* efab_ipp_icmp_for_thr -
 * Is this ICMP message destined for this netif */
extern struct ci_sock_cmn_s* 
efab_ipp_icmp_for_thr( tcp_helper_resource_t* thr, 
		       efab_ipp_addr* addr );

/*! Enqueue an ICMP packet from skb into the TCP helper's netif. 
 */
extern void efab_ipp_icmp_qpkt( tcp_helper_resource_t* thr, 
				struct ci_sock_cmn_s* s,
				efab_ipp_addr* addr );

#endif

/*! \cidoxg_end */
