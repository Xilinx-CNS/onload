/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Utilities for dumping / analysing packet contents.
**   \date  2003/11/27
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_PKTDUMP_H__
#define __CI_TOOLS_PKTDUMP_H__


struct ci_ether_hdr_s;
struct ci_ip4_hdr_s;
struct ci_tcp_hdr_s;
struct ci_udp_hdr_s;
struct ci_arp_hdr_s;
struct ci_ether_arp_s;
struct ci_icmp_hdr_s; 

/* Convert fields to strings. */
extern const char* ci_ether_type_str(unsigned ether_type_be16) CI_HF;
extern const char* ci_ipproto_str(unsigned ip_protocol) CI_HF;
extern const char* ci_arp_op_str(unsigned arp_op_be16) CI_HF;

/* Pretty-print protocol headers. */
extern int ci_pprint_ether_hdr(const struct ci_ether_hdr_s*,int) CI_HF;
extern void ci_pprint_ip4_hdr(const struct ci_ip4_hdr_s*) CI_HF;
extern void ci_pprint_tcp_hdr(const struct ci_tcp_hdr_s*) CI_HF;
extern void ci_pprint_udp_hdr(const struct ci_udp_hdr_s*) CI_HF;
extern void ci_pprint_arp_hdr(const struct ci_arp_hdr_s*) CI_HF;
extern void ci_pprint_ether_arp(const struct ci_ether_arp_s*) CI_HF;
extern void ci_pprint_icmp_hdr(const struct ci_icmp_hdr_s* icmp) CI_HF;

/* Pretty-print protocol headers and check valid.  Return 0 if valid, or
** negative if not.
*/
extern int ci_analyse_tcp(const struct ci_ip4_hdr_s*,
		  const struct ci_tcp_hdr_s*, int bytes, int descend) CI_HF;
extern int ci_analyse_udp(const struct ci_ip4_hdr_s*,
		  const struct ci_udp_hdr_s*, int bytes, int descend) CI_HF;
extern int ci_analyse_ip4(const struct ci_ip4_hdr_s*, int bytes, int de);
extern int ci_analyse_ether_arp(const struct ci_ether_arp_s*, int) CI_HF;
extern int ci_analyse_arp(const struct ci_arp_hdr_s*, int bytes) CI_HF;
extern int ci_analyse_ether(const struct ci_ether_hdr_s*, int, int) CI_HF;
extern int ci_analyse_icmp(const struct ci_ip4_hdr_s*,
		           const struct ci_icmp_hdr_s*, int , int ) CI_HF;

extern int ci_analyse_pkt(const volatile void* pkt, int bytes) CI_HF;


#endif  /* __CI_TOOLS_PKTDUMP_H__ */

/*! \cidoxg_end */
