/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Initialise Internet protocol headers and packets.
**   \date  2003/01/29
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */
  
#include "citools_internal.h"
#include <ci/net/ipv4.h>
#include <ci/net/ethernet.h>
#include <ci/tools/ipcsum_base.h>
#include <ci/tools/ippacket.h>

void ci_ip4_hdr_init(ci_ip4_hdr* ip, int opts_len, int tot_len, int id_be16,
		     int protocol, unsigned saddr_be32, unsigned daddr_be32,
		     int checksum)
{
  ci_assert(ip);
  ci_assert(tot_len >= sizeof(*ip));

  ip->ip_ihl_version = CI_IP4_IHL_VERSION(sizeof(*ip) + opts_len);
  ip->ip_tos = 0;
  ip->ip_tot_len_be16 = CI_BSWAP_BE16(tot_len);
  ip->ip_id_be16 = id_be16;
  ip->ip_frag_off_be16 = 0;
  ip->ip_ttl = 64;
  ip->ip_protocol = protocol;
  ip->ip_saddr_be32 = saddr_be32;
  ip->ip_daddr_be32 = daddr_be32;
  if (checksum)
    ip->ip_check_be16 = ci_ip_checksum(ip);
  else
    ip->ip_check_be16 = 0;
}


void ci_udp_hdr_init(ci_udp_hdr* udp, ci_ip4_hdr* ip,
		     unsigned sport_be16, unsigned dport_be16,
		     const void* payload, int payload_len,
		     int checksum)
{
  ci_assert(udp);
  ci_assert(ip);
  ci_assert_equal(CI_BSWAP_BE16(ip->ip_tot_len_be16),
	    payload_len + sizeof(*udp) + CI_IP4_IHL(ip));

  udp->udp_source_be16 = sport_be16;
  udp->udp_dest_be16 = dport_be16;
  udp->udp_len_be16 = payload_len + sizeof(*udp);
  udp->udp_len_be16 = CI_BSWAP_BE16(udp->udp_len_be16);
  if (checksum)  {
    ci_iovec iov;
    CI_IOVEC_BASE(&iov) = (void *)payload;
    CI_IOVEC_LEN(&iov) = payload_len;
    udp->udp_check_be16 = ci_udp_checksum(ip, udp, &iov, 1);
  }
  else
    udp->udp_check_be16 = 0;
}


void ci_tcp_hdr_init(ci_tcp_hdr* tcp, ci_ip4_hdr* ip, int opts_len,
		     unsigned tcp_flags, unsigned sport_be16,
		     unsigned dport_be16, const void* payload,
		     int payload_len, int checksum)
{
  ci_assert(tcp);
  ci_assert(ip);
  ci_assert_equal(CI_BSWAP_BE16(ip->ip_tot_len_be16),
	    payload_len + sizeof(*tcp) + opts_len + CI_IP4_IHL(ip));

  tcp->tcp_source_be16 = sport_be16; 
  tcp->tcp_dest_be16 = dport_be16;
  tcp->tcp_flags = tcp_flags;
  
  CI_TCP_HDR_SET_LEN(tcp, sizeof(*tcp) + opts_len);

  /* Fields not initialised */
  tcp->tcp_seq_be32 = 0;
  tcp->tcp_ack_be32 = 0;
  tcp->tcp_window_be16 = 0;
  tcp->tcp_urg_ptr_be16 = 0;
  if (checksum)
    tcp->tcp_check_be16 = ci_tcp_checksum(ip, tcp, payload);
  else
    tcp->tcp_check_be16 = 0;
}

struct icmp_echo_s {
  ci_uint16 id;
  ci_uint16 seq;
};
#define ICMP_ECHO 8

static ci_uint32
_ip_csum(ci_uint32 partial_sum, caddr_t in_buf, int in_bytes)
{
  ci_uint16 *buf  = (ci_uint16 *) in_buf;
  ci_uint16 bytes = (ci_uint16)   in_bytes; 

  ci_uint32 sum = partial_sum;

   while (bytes > 1) {
      sum += *buf++;
      bytes -= 2;
   }

   /* Mop up an odd byte, if necessary */
   if (bytes == 1)  sum += *(ci_uint8*) buf;

   return sum;
}

static ci_uint16 
__ip_csum(ci_uint32 sum)
{
  ci_uint16 answer;

  /*  Add back carry outs from top 16 bits to low 16 bits */
  sum =  (sum >> 16) + (sum & 0xFFFF);  
  sum += (sum >> 16);                  
  answer = ((~sum) & 0xFFFF);
  return ( !answer ? 0xFFFF : answer );
}

static ci_uint16 
ip_csum(caddr_t in_buf, int in_bytes)
{
  return __ip_csum(_ip_csum(0, in_buf, in_bytes));
}

void ci_icmp_echo_init(ci_icmp_hdr* hdr, ci_icmp_msg* msg,
		       ci_uint16 seq)
{
  /* use a union to prevent aliasing errors - compiler
     should optimise */
  union {
    ci_uint32 data;
    struct icmp_echo_s echo;
  } u;

  ci_assert( (char*) hdr == (char*) msg );

  hdr->type = ICMP_ECHO;
  hdr->code = 0;

  u.echo.id = CI_BSWAPC_BE16(0xdead);
  u.echo.seq = seq;
  msg->data = u.data;

  /* calculate checksum over the ICMP message */
  hdr->check = 0;
  hdr->check = ip_csum((caddr_t) msg, sizeof(*msg));
}

static void init_data(ci_uint8* vp, int len, int payload_type,
		      ci_uint16 id1, ci_uint16 id2)
{
  int i = 0;
  int align=1;
  ci_uint8 *va,*vf  = vp + len;
  ci_uint16* p16;
  ci_uint32* p32;

  /* do we need alignment? */
  if ((payload_type == CI_PKT_CONTENT_WORD) || (payload_type == CI_PKT_CONTENT_PTLOOP))
    align=2;
  else if (payload_type == CI_PKT_CONTENT_DWORD)
    align=4;
  /* do the alignment */
  for (va = (ci_uint8*) CI_PTR_ALIGN_FWD(vp,align); vp < CI_MIN(va,vf); *vp++ = 0, --len);
  /* reduce the length appropriate to the alignment */
  len = CI_ALIGN_BACK(len,align);

  /* fill out the packet */
  switch (payload_type) {
  case CI_PKT_CONTENT_ZERO:
    memset(vp, 0, len);
    vp += len;
    break;
  case CI_PKT_CONTENT_OCTET:
    for (i = 0; i < len; i++, vp++)
      *vp = id1 + i;
    break;
  case CI_PKT_CONTENT_WORD:
    for (p16 = (ci_uint16*) vp, i = 0; i < (len / 2); i++, vp+=2)
      *p16++ = CI_BSWAP_BE16(id1 + i);
    break;
  case CI_PKT_CONTENT_DWORD:
    for (p32 = (ci_uint32*) vp, i = 0; i < (len / 4); i++, vp+=4)
      *p32++ = (id1 << 16) | (id2 + i);
    break;
  case CI_PKT_CONTENT_CONSTANT:
    memset(vp, id1, len);
    vp += len;
    break;
  case CI_PKT_CONTENT_PTLOOP:
    for( p16 = (ci_uint16*) vp, i = 0; i < len-1; i += 2, vp+=2)
      *p16++ = ((ci_uint8) (i / 4 + 1)) | ((ci_uint8) id1 << 8u);
    break;
  case CI_PKT_CONTENT_ASCII:
    /**
     * hexdump output is 16bytes wide, so do 4x4 blocks.
     * align two bytes in at the start for UDP payload alignment.
     */
    for (i = 0, id1=0; i < len; i++, vp++) {
      *vp = 'a'+id1;
      if (((i+3) % 4) == 0)
	id1=(id1+1) % 26;
    }
    break;
  default:
    ci_assert(0);
  }
  
  /* fill any remaining bytes with non-zero value. */
  ci_assert_le(vp,vf);
  for( ; vp<vf; vp++)
    *vp = (id1 | 0x1);
}

ci_inline void fill_broadcast_mac(unsigned char* dhost)
{
  int i;
  for (i=0 ; i<ETH_ALEN ; i++) 
    dhost[i] = 0xff;
}

void ci_pkt_checksums(uint encap, uint proto, ci_pkt_t* pkt)
{
  char* data = ci_pkt_data_char(encap, proto, pkt);
  ci_tcp_hdr aligned_tcp_hdr;
  ci_ip4_hdr aligned_ip_hdr;

  ci_ip4_hdr* ip = ci_pkt_ip_ptr(encap, pkt);

  /* checksums */
  if (proto == IPPROTO_UDP) {
    ci_udp_hdr* udp = ci_pkt_udp_ptr(encap, pkt);
    ci_iovec iov;
    CI_IOVEC_BASE(&iov) = data;
    CI_IOVEC_LEN(&iov) = CI_BSWAP_BE16(ip->ip_tot_len_be16) -
        CI_IP4_IHL(ip) - sizeof(ci_udp_hdr);
    udp->udp_check_be16 = ci_udp_checksum(ip,udp,&iov,1);
  }
  else if (proto == IPPROTO_TCP) {
    /* make sure the data is aligned properly for the tcp checksum */
    ci_tcp_hdr* tcp = ci_pkt_tcp_ptr(encap, pkt);
    ci_tcp_hdr* tcp_copy = tcp;
    ci_ip4_hdr* ip_copy = ip;

    if (CI_PTR_OFFSET(tcp, 4) != 0) {
      memcpy(&aligned_tcp_hdr, tcp, sizeof(ci_tcp_hdr));
      tcp_copy = &aligned_tcp_hdr;
    }
    if (CI_PTR_OFFSET(ip, 4) != 0) {
      memcpy(&aligned_ip_hdr, ip, sizeof(ci_ip4_hdr));
      ip_copy = &aligned_ip_hdr;
    }
    tcp->tcp_check_be16 = ci_tcp_checksum(ip_copy,tcp_copy,data);
  }
  else if (proto == IPPROTO_ICMP) {
    ci_icmp_hdr* icmp = ci_pkt_icmp_hdr_ptr(encap,pkt);
    icmp->check = 0;
    icmp->check = ip_csum((caddr_t) icmp, sizeof(*icmp));
  }
  else { ci_assert(0); }

  /* calculate ip header checksum */
  ip->ip_check_be16 = ci_ip_checksum(ip);
}


/* Fills out the ethernet header MAC addresses
   using buffers (in network byte order) passed in directly */
void ci_init_eh_mac(unsigned char* smac,
		     unsigned char* dmac,
		     ci_pkt_t* pkt,
		     uint broadcast,
		     uint encap,
		     uint proto)
{
  if (broadcast) {
    fill_broadcast_mac(ci_pkt_eh_dhost_ptr(encap,proto,pkt));
  } else {
    memcpy(ci_pkt_eh_dhost_ptr(encap,proto,pkt), dmac, ETH_ALEN);
  }
  memcpy(ci_pkt_eh_shost_ptr(encap,proto,pkt), smac, ETH_ALEN);
}

/* initialize the packet. Note you must also call ci_init_eh_mac
   to intialize the MAC addresses in the ethernet header */
void ci_init_pkt(ci_uint32 src_ip_addr_be32,
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
		 int checksum)
{
  ci_uint16 ip_id_be16 = (*ip_id)++;
  ip_id_be16 = CI_BSWAP_BE16(ip_id_be16);

  /* This is the EtherII type/length field, or for SNAP packets
   * it is the LLC/SNAP type field, so it is always ETHERTYPE_IP
   */
  *(ci_pkt_eh_type_ptr(encap,proto,pkt)) = CI_ETHERTYPE_IP;
  
  ci_ip4_hdr_init(ci_pkt_ip_ptr(encap,pkt), ip_opts_len,
		  paylen + CI_PKT_HDR_SIZE(proto) + ip_opts_len,
		  ip_id_be16, proto, src_ip_addr_be32, dest_ip_addr_be32,
		  checksum);

  init_data((unsigned char*) ci_pkt_data_char(encap, proto, pkt), paylen,
	    payload_type, payload_id, src_ip_port_be16);

  if (__CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_VLAN)) {
    *__ci_vlan_pkt_ptr(encap,proto,pkt, eh.ether_vtype) = \
      CI_BSWAPC_BE16(CI_ETH_P_VLAN);
    /* vlan id = 0x1 */
    *__ci_vlan_pkt_ptr(encap,proto,pkt, eh.ether_vtag) = CI_BSWAPC_BE16(0x1);
  }

  if (__CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_SNAP)) {
    unsigned char* org = *__ci_snap_pkt_ptr(encap,proto,pkt,eh.ether_org);
    /**
     * See this draft for information on the Jumbo Encapsulation, which requires
     * an LLC header, and then a SNAP frame to store the real ethertype
     * http://www.ietf.org/proceedings/01aug/I-D/draft-ietf-isis-ext-eth-01.txt
     */
    ci_uint16 i = (__CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_JUMBO) ? ETH_P_JUMBO :
		   paylen + CI_PKT_HDR_SIZE(proto));

    ci_assert ( __CI_PKT_HAS_BITS(encap,CI_PKT_ENCAP_JUMBO) || i < 0x600 );
    
    *__ci_snap_pkt_ptr(encap,proto,pkt, eh.ether_len) = CI_BSWAP_BE16(i);
    *__ci_snap_pkt_ptr(encap,proto,pkt, eh.ether_dsap) = 0xAA; /* ?? */
    *__ci_snap_pkt_ptr(encap,proto,pkt, eh.ether_ssap) = 0xAA;
    *__ci_snap_pkt_ptr(encap,proto,pkt, eh.ether_ctrl) = 0x3;

    org[0] = 0x0;
    org[1] = 0x0;
    org[2] = 0x0;
  }

  switch (proto) {
  case IPPROTO_UDP:
    ci_udp_hdr_init(ci_pkt_udp_ptr(encap,pkt),
		    ci_pkt_ip_ptr(encap,pkt), 
		    src_ip_port_be16,
		    dest_ip_port_be16, 
		    ci_pkt_data_ptr(encap,proto,pkt),
		    paylen,checksum);
    break;
  case IPPROTO_TCP:
    ci_tcp_hdr_init(ci_pkt_tcp_ptr(encap,pkt),
		    ci_pkt_ip_ptr(encap,pkt), 
		    0,
		    proto_flags,
		    src_ip_port_be16,
		    dest_ip_port_be16, 
		    ci_pkt_data_ptr(encap,proto,pkt),
		    paylen,checksum);
    break;
  case IPPROTO_ICMP:
    ci_icmp_echo_init(ci_pkt_icmp_hdr_ptr(encap,pkt),
		      ci_pkt_icmp_msg_ptr(encap,pkt),
		      *ip_id);
    break;
  default:
    ci_assert(0);
  };
  
  (*ip_id)++;
}


/*! \cidoxg_end */
