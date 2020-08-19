/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Initialise Internet protocol headers and packets.
**   \date  2004/01/29
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_IPPACKET_H__
#define __CI_TOOLS_IPPACKET_H__

#include <ci/net/ipv4.h>
#include <ci/net/ethernet.h>

/* ethernet headers for test apps */
#define CI_PKT_ETH_PAD 2 


/* macros to determine size of the ethernet header */
/* bit mask fields to determine what encapsulation we have */
#define CI_PKT_ENCAP_NONE 0
#define CI_PKT_ENCAP_VLAN 1
#define CI_PKT_ENCAP_SNAP 2
#define CI_PKT_ENCAP_VLAN_SNAP 3 /* not really necessary */
#define CI_PKT_ENCAP_JUMBO 4

/* Ethernet packet encapsulations */
#define CI_ETH_P_IP	0x0800	  /* Internet Protocol packet */
#define CI_ETH_P_VLAN   0x8100    /* VLAN */
#define ETH_P_JUMBO	0x8870

/* Payload generation methods */
#define CI_PKT_CONTENT_ZERO        0
#define CI_PKT_CONTENT_OCTET       1
#define CI_PKT_CONTENT_WORD        2
#define CI_PKT_CONTENT_DWORD       3
#define CI_PKT_CONTENT_CONSTANT    4
#define CI_PKT_CONTENT_PTLOOP      5  /* ptloop content format */
#define CI_PKT_CONTENT_ASCII       6

#define __CI_PKT_HAS_BITS(encap,type) ((encap & type) == type)
#define CI_PKT_ETHHDR_SIZE(encap) \
  (__CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_VLAN_SNAP) ? sizeof(ci_ethhdr_vlan_snap_t): \
   __CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_SNAP) ? sizeof(ci_ethhdr_snap_t) : \
   __CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_VLAN) ? sizeof(ci_ethhdr_vlan_t) : \
   sizeof(ci_ethhdr_t))

/* packet headers for test apps */

typedef struct ci_pkt_data_t
{
  /* A place holder for the payload. payload will overwrite this struct.
     Would like to add metadata here, but things like iscsi tests
     expect to put down an iscsi header on top of data[0] */
  char	    data[1];
} ci_pkt_data_t;

typedef struct ci_udp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_t            eh;
  ci_ip4_hdr	         ip;
  ci_udp_hdr	         udp;
  ci_pkt_data_t          data;
} ci_udp_pkt_t;

typedef struct ci_vlan_udp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_vlan_t       eh;
  ci_ip4_hdr	         ip;
  ci_udp_hdr	         udp;
  ci_pkt_data_t          data;
} ci_vlan_udp_pkt_t;

typedef struct ci_snap_udp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_snap_t       eh;
  ci_ip4_hdr	         ip;
  ci_udp_hdr	         udp;
  ci_pkt_data_t          data;
} ci_snap_udp_pkt_t;

typedef struct ci_vlan_snap_udp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_vlan_snap_t  eh;
  ci_ip4_hdr	         ip;
  ci_udp_hdr	         udp;
  ci_pkt_data_t          data;
} ci_vlan_snap_udp_pkt_t;

typedef struct ci_tcp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_t            eh;
  ci_ip4_hdr	         ip;
  ci_tcp_hdr	         tcp;
  ci_pkt_data_t          data;
} ci_tcp_pkt_t;

typedef struct ci_vlan_tcp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_vlan_t       eh;
  ci_ip4_hdr	         ip;
  ci_tcp_hdr	         tcp;
  ci_pkt_data_t          data;
} ci_vlan_tcp_pkt_t;

typedef struct ci_snap_tcp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_snap_t       eh;
  ci_ip4_hdr	         ip;
  ci_tcp_hdr	         tcp;  
  ci_pkt_data_t          data;
} ci_snap_tcp_pkt_t;

typedef struct ci_vlan_snap_tcp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_vlan_snap_t  eh;
  ci_ip4_hdr	         ip;
  ci_tcp_hdr	         tcp;
  ci_pkt_data_t          data;
} ci_vlan_snap_tcp_pkt_t;

typedef struct ci_icmp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_t            eh;
  ci_ip4_hdr	         ip;
  ci_icmp_hdr            icmp;
  ci_pkt_data_t          data;
} ci_icmp_pkt_t;

typedef struct ci_vlan_icmp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_vlan_t       eh;
  ci_ip4_hdr	         ip;
  ci_icmp_hdr            icmp;
  ci_pkt_data_t          data;
} ci_vlan_icmp_pkt_t;

typedef struct ci_snap_icmp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_snap_t       eh;
  ci_ip4_hdr	         ip;
  ci_icmp_hdr	         icmp;
  ci_pkt_data_t          data;
} ci_snap_icmp_pkt_t;

typedef struct ci_vlan_snap_icmp_pkt_s
{
  ci_uint16	         pad;
  ci_ethhdr_vlan_snap_t  eh;
  ci_ip4_hdr	         ip;
  ci_icmp_hdr            icmp;
  ci_pkt_data_t          data;
} ci_vlan_snap_icmp_pkt_t;

/* From RFC 3720 setion 10.2.1 Basic Header Section */
typedef struct ci_iscsi_bhs_s {
  ci_uint8  i_opcode;
  ci_uint8  f_opcode_be[3];
  ci_uint8  tot_ahs_len_sr2;
  ci_uint8  data_seg_len_be[3];
  ci_uint32 lun[2];
  ci_uint32 init_task_tag;
  ci_uint32 opcode[7];
} ci_iscsi_bhs_t;

/* From RFC 3720 setion 10.2 */
typedef struct ci_iscsi_pkt_s {
  ci_iscsi_bhs_t bhs;
#if defined(NDEBUG)
  ci_uint32 ahs[];
#else	/* unknown length, CTF debug info problem */
  ci_uint32 ahs[1];
#endif
  /* Followed by:
  ci_uint32 header_digest; (optional - negotiated)
  ci_uint32 data[];
  ci_uint32 data_digest; (optional - negotiated)
  */
} ci_iscsi_pkt_t;

/* unionisers and deunionisers for runtime determined encapsulations */

typedef union ci_pkt_s {
  ci_udp_pkt_t udp;
  ci_tcp_pkt_t tcp;
  ci_icmp_pkt_t icmp;

  ci_vlan_udp_pkt_t vlan_udp;
  ci_vlan_tcp_pkt_t vlan_tcp;
  ci_vlan_icmp_pkt_t vlan_icmp;

  ci_snap_udp_pkt_t snap_udp;
  ci_snap_tcp_pkt_t snap_tcp;
  ci_snap_icmp_pkt_t snap_icmp;

  ci_vlan_snap_udp_pkt_t vlan_snap_udp;
  ci_vlan_snap_tcp_pkt_t vlan_snap_tcp;
  ci_vlan_snap_icmp_pkt_t vlan_snap_icmp;
} ci_pkt_t;

#define CI_PKT_HDR_SIZE(proto) ((proto == IPPROTO_UDP) ? (sizeof(ci_ip4_hdr) + sizeof(ci_udp_hdr)) : \
				(proto == IPPROTO_TCP) ? (sizeof(ci_ip4_hdr) + sizeof(ci_tcp_hdr)) : \
				(proto == IPPROTO_ICMP) ? (sizeof(ci_ip4_hdr) + sizeof(ci_icmp_hdr)) : \
				0)


/* functions to convert payload length to frame length */
ci_inline int ci_pkt_get_frame_len(uint encap, uint proto, int payload_len)
{
  return payload_len + CI_PKT_HDR_SIZE(proto) + CI_PKT_ETHHDR_SIZE(encap);
}

ci_inline int ci_pkt_get_payload_len(uint encap, uint proto, int frame_len)
{
  return frame_len - (CI_PKT_HDR_SIZE(proto) + CI_PKT_ETHHDR_SIZE(encap));
}

/* for a given packet encapsulation member, return the appropriate
 * packet structure member for the protocol */
#define __ci_pkt_em_ptr(proto,p,encap_mem,member)		  \
  ((proto == IPPROTO_UDP) ? &(p-> encap_mem ## udp . member) :	  \
   (proto == IPPROTO_TCP) ? &(p-> encap_mem ## tcp . member) :	  \
   &(p-> encap_mem ## icmp . member))

/** for the given encapsulation and protocol, return the correct
    packet structure member */
#define __ci_pkt_ptr(encap,proto,p,member)			  \
  (__CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_VLAN_SNAP) ?		  \
   __ci_pkt_em_ptr(proto,p,vlan_snap_,member) :			  \
   __CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_VLAN) ?			  \
   __ci_pkt_em_ptr(proto,p,vlan_,member) :			  \
   __CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_SNAP) ?			  \
   __ci_pkt_em_ptr(proto,p,snap_,member) :			  \
   __ci_pkt_em_ptr(proto,p,,member))

/** same as __ci_pkt_ptr but supports snap only members */
#define __ci_snap_pkt_ptr(encap,proto,p,member)				\
  (__CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_VLAN_SNAP) ?			\
   __ci_pkt_em_ptr(proto,p,vlan_snap_,member) :				\
   __ci_pkt_em_ptr(proto,p,snap_,member))

/** same as __ci_pkt_ptr but supports vlan only members */
#define __ci_vlan_pkt_ptr(encap,proto,p,member)				\
  (__CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_SNAP) ?				\
   __ci_pkt_em_ptr(proto,p,vlan_snap_,member) :				\
   __ci_pkt_em_ptr(proto,p,vlan_,member))

/** for a given encapsulation, return the protocol specific
    member specified */
#define __ci_proto_ptr(encap,p, proto, member)				\
  (__CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_VLAN_SNAP) ? &(p->vlan_snap_ ## proto . member) : \
   __CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_VLAN) ? &(p->vlan_ ## proto . member) : \
   __CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_SNAP) ? &(p->snap_ ## proto . member) : \
   &(p-> proto . member))

ci_inline ci_tcp_hdr * ci_pkt_tcp_ptr(uint encap, ci_pkt_t *p) { 
  return __ci_proto_ptr(encap,p,tcp,tcp);
}

ci_inline ci_udp_hdr * ci_pkt_udp_ptr(uint encap, ci_pkt_t *p) { 
  return __ci_proto_ptr(encap,p,udp,udp);
}

ci_inline ci_icmp_hdr * ci_pkt_icmp_hdr_ptr(uint encap, ci_pkt_t *p) { 
  return __ci_proto_ptr(encap,p,icmp,icmp);
}

ci_inline ci_icmp_msg * ci_pkt_icmp_msg_ptr(uint encap, ci_pkt_t *p) { 
  return (ci_icmp_msg *) __ci_proto_ptr(encap,p,icmp,icmp);
}

ci_inline unsigned char * ci_pkt_eh_shost_ptr(uint encap, uint proto, ci_pkt_t *p) {
  return *__ci_pkt_ptr(encap,proto,p,eh.ether_shost);
}

ci_inline unsigned char * ci_pkt_eh_dhost_ptr(uint encap, uint proto, ci_pkt_t *p) {
  return *__ci_pkt_ptr(encap,proto,p,eh.ether_dhost);
}

ci_inline unsigned short * ci_pkt_eh_type_ptr(uint encap, uint proto, ci_pkt_t *p) {
  return __ci_pkt_ptr(encap,proto,p,eh.ether_type);
}

ci_inline ci_uint8 * ci_pkt_ip_ttl_ptr(uint encap, uint proto, ci_pkt_t* p) {
  return __ci_pkt_ptr(encap,proto,p,ip.ip_ttl);
}

/* return the start of the data, as either a char or data_t* */
ci_inline ci_pkt_data_t * ci_pkt_data_ptr(uint encap, uint proto, ci_pkt_t *p) {
  return __ci_pkt_ptr(encap, proto, p, data);
}

ci_inline char * ci_pkt_data_char(uint encap, uint proto, ci_pkt_t *p) {
  return *__ci_pkt_ptr(encap, proto, p, data.data);
}

ci_inline ci_ip4_hdr * ci_pkt_ip_ptr(uint encap, ci_pkt_t *p) {
  /* the IP header is at the same offset for all protocols */
  return __ci_pkt_ptr(encap, IPPROTO_UDP, p, ip);
}

/* return the start of the header proper. Should equal ci_pkt_eh_dhost_ptr */
ci_inline char * ci_pkt_start_ptr(ci_pkt_t *p)
{
  return (((char*) p) + CI_PKT_ETH_PAD);
}

/* packet and header initialisation routines */

extern void ci_init_eh_mac(unsigned char* shost,
			    unsigned char* dhost,
			    ci_pkt_t* pkt,
			    uint broadcast,
			    uint encap,
			    uint proto);

extern void ci_init_pkt(ci_uint32 src_ip_addr_be32,
			ci_uint32 dest_ip_addr_be32,
			ci_uint16 src_ip_port_be16,
			ci_uint16 dest_ip_port_be16,
			ci_pkt_t* pkt,
			ci_uint16 payload_id,
			int paylen,
			int payload_type,
			uint ip_opts_len,
			uint* ip_id,
			uint broadcast,
			uint encap,
			uint proto,
			uint proto_opts_len,
			uint proto_flags,
			int checksum);

ci_inline void ci_pkt_ip_checksum(uint encap, ci_pkt_t* pkt)
{
  ci_ip4_hdr* ip = ci_pkt_ip_ptr(encap, pkt);
  ip->ip_check_be16 = ci_ip_checksum(ip);
}

extern void ci_pkt_checksums(uint encap, uint proto, ci_pkt_t* pkt);

/*! Comment? */
#define CI_NO_OPTS 0
extern void ci_ip4_hdr_init(struct ci_ip4_hdr_s*, int opts_len, int tot_len_he,
			    int id_be16, int protocol, unsigned saddr_be32,
			    unsigned daddr_be32, int checksum);

/*! Comment? */
extern void ci_udp_hdr_init(struct ci_udp_hdr_s*, struct ci_ip4_hdr_s*,
			    unsigned sport_be16, unsigned dport_be16,
			    const void* payload, int payload_len,
			    int checksum);

/*! Comment? */
extern void ci_tcp_hdr_init(ci_tcp_hdr* tcp, ci_ip4_hdr* ip, int opts_len,
			    unsigned tcp_flags, unsigned sport_be16,
			    unsigned dport_be16, const void* payload,
			    int payload_len, int checksum);

/*! Comment? */
extern void ci_icmp_echo_init(ci_icmp_hdr* hdr, ci_icmp_msg* msg,
			      ci_uint16 seq);


#endif  /* __CI_TOOLS_IPPACKET_H__ */

/*! \cidoxg_end */
