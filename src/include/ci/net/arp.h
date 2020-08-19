/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Address resolution protocol definitions.
**   \date  2003/12/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_net  */

#ifndef __CI_NET_ARP_H__
#define __CI_NET_ARP_H__

#include <ci/net/ethernet.h>
#include <ci/net/ipv4.h>


/*! ARP header */
typedef struct ci_arp_hdr_s {
  ci_uint16  arp_hw_type_be16;
  ci_uint16  arp_prot_type_be16;
  ci_uint8   arp_hw_len;
  ci_uint8   arp_prot_len;
  ci_uint16  arp_op_be16;
} ci_arp_hdr;


#define CI_ARP_REQUEST     CI_BSWAPC_BE16(0x1)
#define CI_ARP_REPLY       CI_BSWAPC_BE16(0x2)
#define CI_ARP_RREQUEST    CI_BSWAPC_BE16(0x3)
#define CI_ARP_RREPLY      CI_BSWAPC_BE16(0x4)
#define CI_ARP_InREQUEST   CI_BSWAPC_BE16(0x8)
#define CI_ARP_InREPLY     CI_BSWAPC_BE16(0x9)


#define CI_ARP_HW_ETHER    CI_BSWAPC_BE16(0x1)
/* plus lots of others that we're not interested in */


#define CI_ARP_PROT_IP     CI_BSWAPC_BE16(0x0800)


/*! Comment? */
typedef struct ci_ether_arp_s {
  ci_arp_hdr  hdr;
  ci_uint8    arp_src_mac[6];
  ci_uint8    arp_src_ip[4];
  ci_uint8    arp_tgt_mac[6];
  ci_uint8    arp_tgt_ip[4];
} ci_ether_arp;


#define CI_ETHER_ARP_SRC_MAC_PTR(arp) \
  ((ci_uint8 *) ((ci_ether_arp*)(arp))->arp_src_mac)
#define CI_ETHER_ARP_SRC_IP_PTR(arp)  \
  ((ci_uint32*) ((ci_ether_arp*)(arp))->arp_src_ip)
#define CI_ETHER_ARP_TGT_MAC_PTR(arp) \
  ((ci_uint8 *) ((ci_ether_arp*)(arp))->arp_tgt_mac)
#define CI_ETHER_ARP_TGT_IP_PTR(arp)  \
  ((ci_uint32*) ((ci_ether_arp*)(arp))->arp_tgt_ip )


#define CI_ARP_PRINTF_FORMAT                           \
  "ARP packet type=%s, arp_hdr_ptr=%p:\n"              \
  CI_MAC_PRINTF_FORMAT ", " CI_IP_PRINTF_FORMAT " -> " \
  CI_MAC_PRINTF_FORMAT ", " CI_IP_PRINTF_FORMAT


#define CI_ARP_PRINTF_ARGS(p)                                  \
  ((p)->hdr.arp_op_be16 == CI_ARP_REQUEST) ? "request" :       \
  ((p)->hdr.arp_op_be16 == CI_ARP_REPLY)   ? "reply"   :       \
                                             "(unknown type)", \
  (p),                                                         \
  CI_MAC_PRINTF_ARGS((p)->arp_src_mac),                        \
  CI_IP_PRINTF_ARGS ((p)->arp_src_ip),                         \
  CI_MAC_PRINTF_ARGS((p)->arp_tgt_mac),                        \
  CI_IP_PRINTF_ARGS ((p)->arp_tgt_ip)


#endif  /* __CI_NET_ARP_H__ */

/*! \cidoxg_end */
