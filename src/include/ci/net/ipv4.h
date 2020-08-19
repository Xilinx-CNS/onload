/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Internet protocol definitions.
**   \date  2003/01/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_net  */

#ifndef __CI_NET_IPV4_H__
#define __CI_NET_IPV4_H__

/**********************************************************************
 ** IP
 */

typedef ci_uint32 ci_ip_addr_t;

typedef struct ci_ip4_hdr_s {
  ci_uint8   ip_ihl_version;
  ci_uint8   ip_tos;
  ci_uint16  ip_tot_len_be16;
  ci_uint16  ip_id_be16;
  ci_uint16  ip_frag_off_be16;
  ci_uint8   ip_ttl;
  ci_uint8   ip_protocol;
  ci_uint16  ip_check_be16;
  ci_uint32  ip_saddr_be32;
  ci_uint32  ip_daddr_be32;
  /* ...options... */
} ci_ip4_hdr;


/* The pseudo-header used for TCP and UDP checksum calculation. */
typedef struct {
  ci_uint32  ip_saddr_be32;
  ci_uint32  ip_daddr_be32;
  ci_uint8   zero;
  ci_uint8   ip_protocol;
  ci_uint16  length_be16;  /* tcp/udp hdr + payload */
} ci_ip4_pseudo_hdr;


#define CI_IP4_IHL_VERSION(ihl)  ((4u << 4u) | ((ihl) >> 2u))
#define CI_IP4_IHL(ip)           (((ip)->ip_ihl_version & 0xf) << 2u)
#define CI_IP4_VERSION(ip)       ((ip)->ip_ihl_version >> 4u)

ci_inline void* ci_ip_data(ci_ip4_hdr* ip)
{
  return (uint8_t*) ip + CI_IP4_IHL(ip);
}

#define CI_IP4_OFFSET_MASK       CI_BSWAPC_BE16(0x1fff)
#define CI_IP4_FRAG_MORE         CI_BSWAPC_BE16(0x2000)
#define CI_IP4_FRAG_DONT         CI_BSWAPC_BE16(0x4000)
/* unused & must be 0 :          CI_BSWAPC_BE16(0x8000) */

#define CI_IP4_FRAG_OFFSET(ip)					\
  CI_BSWAP_BE16((ip)->ip_frag_off_be16 & CI_IP4_OFFSET_MASK)

#define CI_IP4_IS_FIRST_FRAG(ip)				\
  (((ip)->ip_frag_off_be16 &                                    \
    (CI_IP4_FRAG_MORE | CI_IP4_OFFSET_MASK))==CI_IP4_FRAG_MORE)

#define CI_IP4_IS_LAST_FRAG(ip)				        \
  ( !((ip)->ip_frag_off_be16 & CI_IP4_FRAG_MORE) ) 

#define CI_IP4_IS_UNFRAG(ip)					\
  (((ip)->ip_frag_off_be16 &                                    \
    (CI_IP4_FRAG_MORE | CI_IP4_OFFSET_MASK))==0)

#define CI_IP4_IS_FIRST_OR_ONLY_FRAG(ip)			\
  (CI_IP4_IS_FIRST_FRAG(ip) | CI_IP4_IS_UNFRAG(ip))	

/*! Set the fragmented flag without disturbing the offset */
#define CI_IP4_SET_FRAG_MORE(ip)                                \
  (ip)->ip_frag_off_be16 |= CI_IP4_FRAG_MORE

/*! Set the don't fragment flag without disturbing the offset */
#define CI_IP4_SET_FRAG_DONT(ip)                                \
  (ip)->ip_frag_off_be16 |= CI_IP4_FRAG_DONT

/*! Set IP4 fragment offset without disturbing the flags */
#define CI_IP4_SET_FRAG_OFFSET(ip, off) do {                    \
  (ip)->ip_frag_off_be16 =                                      \
    ((ip)->ip_frag_off_be16 & ~CI_IP4_OFFSET_MASK)              \
    | ( CI_BSWAP_BE16((off)) & CI_IP4_FRAG_OFFSET); } while(0) 

/*! Create an IP4 fragment offset  */
#define CI_IP4_MAKE_OFFSET(off)                                 \
  (CI_BSWAP_BE16((off)>>3) & CI_IP4_OFFSET_MASK)

/*! Compare two IP headers & determine if they are both fragments
 * of the same packet (ASSUMES PROTOCOL CHECKED SEPARATELY). 
 * This is a match of  source & dest addr & id */
#define CI_IP4_ARE_FROM_SAME_PKT(ip1, ip2) (	                \
  ((ip1)->ip_id_be16 == (ip2)->ip_id_be16) && 	                \
  ((ip1)->ip_saddr_be32 == (ip2)->ip_saddr_be32) && 	        \
  ((ip1)->ip_daddr_be32 == (ip2)->ip_daddr_be32))

#define CI_IP_PROTOCOL_STR(p)	((p) == IPPROTO_IP   ? "IP"   :	\
				 (p) == IPPROTO_ICMP ? "ICMP" :	\
				 (p) == IPPROTO_IGMP ? "IGMP" :	\
				 (p) == IPPROTO_TCP  ? "TCP"  :	\
				 (p) == IPPROTO_UDP  ? "UDP"  :	\
				 "<unknown-IP-protocol>")

#define CI_IP_PRINTF_FORMAT       "%d.%d.%d.%d"
#define CI_IP_PRINTF_ARGS(p_be32) ((int) ((ci_uint8*)(p_be32))[0]), \
                                  ((int) ((ci_uint8*)(p_be32))[1]), \
                                  ((int) ((ci_uint8*)(p_be32))[2]), \
                                  ((int) ((ci_uint8*)(p_be32))[3])

/** convert prefix to netmask, numbers are in host endianess */
ci_inline ci_uint32 ci_ip_prefix2mask(unsigned int prefix_he32)
{ /* warning: << <maxbits> is not defined - it leaves the value unchanged on
     some compilers */
  return prefix_he32 == 0? 0: (0xffffffffu << (32-(prefix_he32)));
}

/** convert netmask to prefix, numbers are in host endianess */
ci_inline ci_uint32 ci_ip_mask2prefix(ci_uint32 mask_he32)
{
  unsigned int prefix=0;
  for (; 0 != (mask_he32 & 0x80000000u); mask_he32 <<= 1)
    prefix++;
  return prefix;
}

/* Well-known addresses */
#define CI_IP_ALL_HOSTS     0x10000e0
#define CI_IP_ALL_BROADCAST 0xffffffff

/** check an IP address aganst a provided IP adadress and mask */
#define CI_IP_ADDR(ipa, ipb, ipc, ipd)                                \
    (((ipa) | ((ipb) << 8) | ((ipc) << 16) | ((ipd) << 24)))
#define CI_IP_ADDR_EQUAL(ipaddr_be32, ipa, ipb, ipc, ipd, mask)       \
    ( ((ipaddr_be32) & CI_BSWAP_BE32(mask)) ==                        \
      (CI_IP_ADDR(ipa, ipb, ipc, ipd) & CI_BSWAP_BE32(mask)) )   

/** is ip_be32 a multicast address? */
#define CI_IP_IS_MULTICAST(ip_be32) \
  (((ip_be32) & CI_BSWAPC_BE32(0xf0000000)) == CI_BSWAPC_BE32(0xe0000000))

/** is ip_be32 a loopback address? (127.0.0.0/8) */
#define CI_IP_IS_LOOPBACK(ip_be32) \
  (((ip_be32) & CI_BSWAPC_BE32(0xff000000)) == CI_BSWAPC_BE32(0x7f000000))

#define CI_IP_ADDR_CMP(addr1, addr2) ((addr1) != (addr2))

/* Cast struct sockaddr* to struct sockaddr_in* */
#define CI_SIN(sa) ((struct sockaddr_in *)(sa))

/* Cast struct sockaddr_in* to struct sockaddr* */
#define CI_SA(sa) ((struct sockaddr *)(sa))

/* Cast struct sockaddr* to struct sockaddr_in6* */
#define CI_SIN6(sa) ((struct sockaddr_in6 *)(sa))

/* Cast struct sockaddr_in6* to struct sockaddr* */
#define CI_SA6(sa) ((struct sockaddr *)(sa))


/** Test if IPv6 address is IPv4-mapped address. */
#define CI_IP6_IS_V4MAPPED(ip6_p) \
  (((ci_uint32 *)(ip6_p))[0] == 0 && ((ci_uint32 *)(ip6_p))[1] == 0 &&  \
   ((ci_uint32 *)(ip6_p))[2] == CI_BSWAPC_BE32(0xffff))
/** Test if IPv6 address IN6ADDR_ANY. */
#define CI_IP6_IS_ADDR_ANY(ip6_p) \
  (((ci_uint32 *)(ip6_p))[0] == 0 && ((ci_uint32 *)(ip6_p))[1] == 0 &&  \
   ((ci_uint32 *)(ip6_p))[2] == 0 && ((ci_uint32 *)(ip6_p))[3] == 0)

/** Create IPv6 address from IPv4 one. */
#define CI_IP_TO_IP6_MAPPED(ip6_p, ip_be32) \
  do {                                                              \
    ((ci_uint32 *)(ip6_p))[0] = ((ci_uint32 *)(ip6_p))[1] = 0;      \
    if (ip_be32 != 0) {                                             \
      ((ci_uint32 *)(ip6_p))[2] = CI_BSWAPC_BE32(0xffff);           \
      ((ci_uint32 *)(ip6_p))[3] = ip_be32;                          \
    } else {                                                        \
      ((ci_uint32 *)(ip6_p))[2] = ((ci_uint32 *)(ip6_p))[3] = 0;    \
    }                                                               \
  } while (0)

/*! type of service */
typedef ci_uint8 ci_ip_tos_t;


/**********************************************************************
 ** TCP
 */

typedef struct ci_tcp_hdr_s {
  ci_uint16  tcp_source_be16;
  ci_uint16  tcp_dest_be16;
  ci_uint32  tcp_seq_be32;
  ci_uint32  tcp_ack_be32;
  ci_uint8   tcp_hdr_len_sl4;
  ci_uint8   tcp_flags;
  ci_uint16  tcp_window_be16;
  ci_uint16  tcp_check_be16;
  ci_uint16  tcp_urg_ptr_be16;
  /* ...options... */
} ci_tcp_hdr;


#define CI_TCP_HDR_SET_LEN(hdr, hlen) ((hdr)->tcp_hdr_len_sl4 = (hlen) << 2u)
#define CI_TCP_HDR_LEN(hdr)           (((hdr)->tcp_hdr_len_sl4 & 0xf0) >> 2u)
#define CI_TCP_HDR_OPT_LEN(hdr)       (CI_TCP_HDR_LEN(hdr)-sizeof(ci_tcp_hdr))
#define CI_TCP_HDR_OPTS(hdr)          ((ci_uint8*)&(hdr)->tcp_urg_ptr_be16+2)
#define CI_TCP_PAYLOAD(hdr)           ((char*)(hdr) + CI_TCP_HDR_LEN(hdr))
#define CI_TCP_PAYLEN(ip, tcp)        (CI_BSWAP_BE16((ip)->ip_tot_len_be16) \
                                       - CI_IP4_IHL(ip)                     \
                                       - CI_TCP_HDR_LEN(tcp))

/* Maximum allowed length of all options. */
#define CI_TCP_MAX_OPTS_LEN             40

/* Maximum number of blocks in SACK option. */
#define CI_TCP_SACK_MAX_BLOCKS 4

#define CI_TCP_FLAG_CWR                0x80
#define CI_TCP_FLAG_ECE                0x40
#define CI_TCP_FLAG_URG                0x20
#define CI_TCP_FLAG_ACK                0x10
#define CI_TCP_FLAG_PSH                0x08
#define CI_TCP_FLAG_RST                0x04
#define CI_TCP_FLAG_SYN                0x02
#define CI_TCP_FLAG_FIN                0x01
#define CI_TCP_FLAG_MASK               0x3f  /* just the core flags */

#define CI_TCP_FLAG_SYN_BIT            1
#define CI_TCP_FLAG_FIN_BIT            0

#define CI_TCP_FLAG_STR(flags, flag, str)				\
  (((flags) & CI_TCP_FLAG_##flag) ? (str) : "")

#define CI_TCP_FLAGS_FMT		"%s%s%s%s%s%s%s%s"
#define CI_TCP_FLAGS_PRI_ARG(flg)	CI_TCP_FLAG_STR((flg), URG, "Urg"), \
					CI_TCP_FLAG_STR((flg), SYN, "Syn"), \
					CI_TCP_FLAG_STR((flg), FIN, "Fin"), \
					CI_TCP_FLAG_STR((flg), RST, "Rst"), \
					CI_TCP_FLAG_STR((flg), ACK, "Ack"), \
					CI_TCP_FLAG_STR((flg), PSH, "Psh"), \
					CI_TCP_FLAG_STR((flg), CWR, "Cwr"), \
					CI_TCP_FLAG_STR((flg), ECE, "Ece")

#define CI_TCP_HDR_FLAGS_PRI_ARG(hdr)	CI_TCP_FLAGS_PRI_ARG((hdr)->tcp_flags)

#define CI_TCP_OPT_END                 0x0
#define CI_TCP_OPT_NOP                 0x1
#define CI_TCP_OPT_MSS                 0x2
#define CI_TCP_OPT_WINSCALE            0x3
#define CI_TCP_OPT_SACK_PERM           0x4
#define CI_TCP_OPT_SACK                0x5
#define CI_TCP_OPT_TIMESTAMP           0x8


/**********************************************************************
 ** UDP
 */

typedef struct ci_udp_hdr_s {
  ci_uint16  udp_source_be16;
  ci_uint16  udp_dest_be16;
  ci_uint16  udp_len_be16;
  ci_uint16  udp_check_be16;
} ci_udp_hdr;


#define CI_UDP_PAYLOAD(hdr)	((char*) &(hdr)->udp_check_be16 + 2)
#define CI_UDP_PAYLEN(hdr)	CI_BSWAP_BE16((hdr)->udp_len_be16)


/**********************************************************************
 ** ICMP
 */

typedef struct ci_icmp_hdr_s {
  ci_uint8   type;
  ci_uint8   code;
  ci_uint16  check;
} ci_icmp_hdr;


/* Most ICMP messages consist of the header followed by one 32-bit datum. */
typedef struct {
  ci_icmp_hdr icmp;
  ci_uint32   data;
} ci_icmp_msg;


#define CI_ASSERT_ICMP_TYPES_VALID \
  ci_assert((sizeof(ci_icmp_msg) - sizeof(ci_icmp_hdr)) == 4)

enum { /* icmp type field */
  CI_ICMP_ECHOREPLY      = 0,
  CI_ICMP_DEST_UNREACH   = 3,
  CI_ICMP_SOURCE_QUENCH  = 4,
  CI_ICMP_REDIRECT       = 5,
  CI_ICMP_ECHO           = 8,
  CI_ICMP_TIME_EXCEEDED  = 11,
  CI_ICMP_PARAMETERPROB  = 12,
  CI_ICMP_TIMESTAMP      = 13,
  CI_ICMP_TIMESTAMPREPLY =  14,
  CI_ICMP_INFO_REQUEST   = 15,
  CI_ICMP_INFO_REPLY     = 16,
  CI_ICMP_ADDRESS        = 17,
  CI_ICMP_ADDRESSREPLY   = 18,
  CI_ICMP_TYPE_MAX = 19
};

enum { /* icmp code field for type = CI_ICMP_DEST_UNREACH */
  CI_ICMP_DU_NET_UNREACH   = 0,
  CI_ICMP_DU_HOST_UNREACH  = 1,
  CI_ICMP_DU_PROTO_UNREACH = 2,
  CI_ICMP_DU_PORT_UNREACH  = 3,
  CI_ICMP_DU_FRAG_NEEDED   = 4,
  CI_ICMP_DU_SRC_RT_FAIL   = 5,
  CI_ICMP_DU_DEST_NET_UNK  = 6,
  CI_ICMP_DU_DEST_HOST_UNK = 7,
  CI_ICMP_DU_SRC_HOST_ISOL = 8,
  CI_ICMP_DU_DEST_NET_PROHIB  = 9,
  CI_ICMP_DU_DEST_HOST_PROHIB = 10,
  CI_ICMP_DU_NET_UNREACH_TOS  = 11,
  CI_ICMP_DU_HOST_UNREACH_TOS = 12,
  CI_ICMP_DU_CODE_MAX = 13
};

enum { /* icmp code field for type = CI_ICMP_TIME_EXCEEDED */
  CI_ICMP_TE_TTL           = 0,
  CI_ICMP_TE_FRAG          = 1
};


/* Errno "some filters inserted, some failed".
 * The errno value which must not clash with the real errors
 * from filter code.
 * Yes, it is ugly. */
#define EFILTERSSOME EDQUOT

#endif  /* __CI_NET_IPV4_H__ */

/*! \cidoxg_end */
