/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  Linux specific ICMP & IGMP & UDP handlers.  UDP handling is
**          for broadcasts which are not (currently) filtered by the NIC.
**   \date  2004/06/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_IP__PROTOCOLS_H__
#define __CI_DRIVER_EFAB_IP__PROTOCOLS_H__

#ifndef __ci_driver__
#error "This is a driver module."
#endif

#include <ci/net/ipvx.h>


/*! struct containing ptrs into icmp data area and 
 * addressing & protocol data from an ICMP pkt */
typedef struct {
  const ci_ipx_hdr_t* ipx; /*< IP PDU holding ICMP message */
  ci_icmp_hdr *icmp;    /*< ICMP header in IP PDU */
  ci_uint8* data;       /*< ICMP reply data following header */
  ci_addr_t saddr;      /*< dest IP of IP PDU in ICMP reply data */
  ci_addr_t daddr;      /*< src IP of IP PDU in ICMP reply data */
  int data_len;         /*< ICMP len if icmp set & whole IP PDU in reply */
  ci_uint16 sport_be16; /*< dest port of TCP/UDP IP PDU in ICMP reply data */
  ci_uint16 dport_be16; /*< src port of TCP/UDP IP PDU in ICMP reply data */
  ci_uint8  protocol;   /*< protocol of IP PDU in ICMP reply data */
  ci_ifid_t ifindex;    /*< interface index we've got the ICMP message from */
} efab_ipp_addr;

#endif

/*! \cidoxg_end */
