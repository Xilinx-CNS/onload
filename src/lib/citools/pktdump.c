/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Pretty-printing and validity checking for network traffic.
**   \date  2003/12/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */

#include <ci/tools.h>
#include <ci/tools/ipcsum_base.h>
#include <ci/tools/pktdump.h>
#include <ci/tools/sysdep.h>
#include <ci/net/ethernet.h>
#include <ci/net/ipv4.h>
#include <ci/net/arp.h>


const char* ci_ether_type_str(unsigned ether_type)
{
  switch( ether_type ) {
  case CI_ETHERTYPE_IP:   return "IP";
  case CI_ETHERTYPE_ARP:  return "ARP";
  default:                return "<unknown>";
  }
}


const char* ci_ipproto_str(unsigned ip_protocol)
{
  switch( ip_protocol ) {
  case IPPROTO_IP:    return "IP";
  case IPPROTO_ICMP:  return "ICMP";
  case IPPROTO_TCP:   return "TCP";
  case IPPROTO_UDP:   return "UDP";
  default:            return "<unknown>";
  }
}


const char* ci_arp_op_str(unsigned arp_op)
{
  switch( arp_op ) {
  case CI_ARP_REQUEST:    return "REQUEST";
  case CI_ARP_REPLY:      return "REPLY";
  case CI_ARP_RREQUEST:   return "RREQUEST";
  case CI_ARP_RREPLY:     return "RREPLY";
  case CI_ARP_InREQUEST:  return "InREQUEST";
  case CI_ARP_InREPLY:    return "InREPLY";
  default:                return "<unknown>";
  }
}


int ci_pprint_ether_hdr(const ci_ether_hdr* eth, int bytes)
{
  char s[80];
  int si = 0;
  int size = ETH_HLEN;

  si += ci_sprintf(s+si, "ETH len=%d ", bytes);
  si += ci_format_eth_addr(s+si, sizeof(s)-si, eth->ether_shost, 0);
  si += ci_sprintf(s+si, "=>");
  si += ci_format_eth_addr(s+si, sizeof(s)-si, eth->ether_dhost, 0);
  si += ci_sprintf(s+si, " type=0x%04x %s", CI_BSWAP_BE16(eth->ether_type),
		ci_ether_type_str(eth->ether_type));
  if (eth->ether_type == CI_ETHERTYPE_8021Q) {
    ci_uint16 *vlan_tag = (ci_uint16 *)(eth + 1);
    si += ci_sprintf(s+si, " type=0x%04x %s %04hx",
                     CI_BSWAP_BE16(vlan_tag[0]),
                     ci_ether_type_str(vlan_tag[0]), vlan_tag[1]);
    size += ETH_VLAN_HLEN;
  }
  ci_log("%s", s);

  return size;
}


void ci_pprint_ip4_hdr(const ci_ip4_hdr* ip)
{
  char s[80];
  int si = 0;

  si += ci_sprintf(s+si, "IP4 v%u %s ", CI_IP4_VERSION(ip),
		ci_ipproto_str(ip->ip_protocol));
  si += ci_format_ip4_addr(s+si, sizeof(s)-si, ip->ip_saddr_be32);
  si += ci_sprintf(s+si, "=>");
  si += ci_format_ip4_addr(s+si, sizeof(s)-si, ip->ip_daddr_be32);
  si += ci_sprintf(s+si, " hlen=%u totlen=%d tos=%d",
		CI_IP4_IHL(ip), (int) CI_BSWAP_BE16(ip->ip_tot_len_be16),
		(int) ip->ip_tos);
  ci_log("%s", s);

  ci_sprintf(s, "IP%u id=0x%04x frag=(%s%s 0x%x) ttl=%d check=0x%04x",
	  CI_IP4_VERSION(ip), (unsigned) CI_BSWAP_BE16(ip->ip_id_be16),
	  (ip->ip_frag_off_be16 & CI_IP4_FRAG_DONT) ? "DONT" : "",
	  (ip->ip_frag_off_be16 & CI_IP4_FRAG_MORE) ? " MORE" : "",
	  (unsigned) CI_IP4_FRAG_OFFSET(ip) << 3, (int) ip->ip_ttl,
	  (unsigned) CI_BSWAP_BE16(ip->ip_check_be16));
  ci_log("%s", s);

  if( CI_IP4_IHL(ip) > sizeof(*ip) )
    ci_log("    options: present");
  /*! ?? \TODO parse ip options */
}


static int ci_pprint_tcp_hdr_options(const volatile void* p,
				     int bytes, char* s)
{
  const ci_uint8* opts = (const ci_uint8*) p;
  int n = 0;

  while( bytes ) {
    switch( opts[0] ) {
    case CI_TCP_OPT_END:
      ++opts;  --bytes;
      break;
    case CI_TCP_OPT_NOP:
      n += ci_sprintf(s + n, " nop");
      ++opts;  --bytes;
      break;
    case CI_TCP_OPT_MSS:
      if( bytes < 4 ) {
	n += ci_sprintf(s + n, " mss(truncated)");
	return -1;
      }
      if( opts[1] != 0x4 ) {
	n += ci_sprintf(s + n, " mss(bad length %d)", (int) opts[1]);
	return -1;
      }
      {
	ci_uint16 mss;
	memcpy(&mss, opts + 2, 2);
	mss = CI_BSWAP_BE16(mss);
	n += ci_sprintf(s + n, " mss(%u)", (unsigned) mss);
	opts += 4; bytes -= 4;
      }
      break;
    case CI_TCP_OPT_WINSCALE:
      if( bytes < 3 ) {
	n += ci_sprintf(s + n, " winscale(truncated)");
	return -1;
      }
      if( opts[1] != 0x3 ) {
	n += ci_sprintf(s + n, " winscale(bad length %d)", (int) opts[1]);
	return -1;
      }
      n += ci_sprintf(s + n, " winscale(%u)", 1u << opts[2]);
      opts += 3; bytes -= 3;
      break;
    case CI_TCP_OPT_SACK_PERM:
      if( bytes < 2 ) {
	n += ci_sprintf(s + n, " sackperm(truncated %d)", bytes);
	return -1;
      }
      if( opts[1] != 0x2 ) {
	n += ci_sprintf(s + n, " sackperm(bad length %d)", (int) opts[1]);
	return -1;
      }
      n += ci_sprintf(s + n, " sackperm");
      opts += 2; bytes -= 2;
      break;
    case CI_TCP_OPT_SACK:
      if( bytes < opts[1] ) {
	n += ci_sprintf(s + n, " sack(truncated %d,%d)", bytes, (int) opts[1]);
	return -1;
      }
      if( opts[1] <= 2 || CI_OFFSET(opts[1] - 2, 8) ) {
	n += ci_sprintf(s + n, " sack(bad length %d)", (int) opts[1]);
	return -1;
      }
      {
	int num = (opts[1] - 2) / 8;
	bytes -= opts[1];
	opts += 2;
	n += ci_sprintf(s + n, " sack(");
	while( num-- ) {
	  ci_uint32 sack[2];
	  memcpy(sack, opts, 8);
	  opts += 8;
	  n += ci_sprintf(s + n, "%x-%x%s", (unsigned) CI_BSWAP_BE32(sack[0]),
		       (unsigned) CI_BSWAP_BE32(sack[1]), num ? "," : "");
	}
	n += ci_sprintf(s + n, ")");
      }
      break;
    case CI_TCP_OPT_TIMESTAMP:
      if( bytes < 10 ) {
	n += ci_sprintf(s + n, " timestamp(truncated)");
	return -1;
      }
      if( opts[1] != 0xa ) {
	n += ci_sprintf(s + n, " timestamp(bad length %d)", (int) opts[1]);
	return -1;
      }
      {
	ci_uint32 t1, t2;
	memcpy(&t1, opts + 2, 4);
	memcpy(&t2, opts + 6, 4);
	n += ci_sprintf(s + n, " timestamp(0x%x,0x%x)",
		     (unsigned) CI_BSWAP_BE32(t1), 
		     (unsigned) CI_BSWAP_BE32(t2));
	opts += 10; bytes -= 10;
      }
      break;
    default:
      n += ci_sprintf(s + n, " UNKNOWN(%d,%s%d)", (int) opts[0],
		   (bytes < opts[1] || opts[1] == 0) ? "bad length " : "",
		   (int) opts[1]);
      if( bytes < opts[1] || opts[1] == 0 )  return -1;
      bytes -= opts[1];
      opts += opts[1];
      break;
    }
  }

  return 0;
}


void ci_pprint_tcp_hdr(const ci_tcp_hdr* tcp)
{
  char s[200];

  ci_sprintf(s, "TCP %d=>%d "CI_TCP_FLAGS_FMT" s=%08x a=%08x w=%d hlen=%d "
	  "ck=%x urg=%d",
	  (int) CI_BSWAP_BE16(tcp->tcp_source_be16),
	  (int) CI_BSWAP_BE16(tcp->tcp_dest_be16),
	  CI_TCP_HDR_FLAGS_PRI_ARG(tcp),
	  (unsigned) CI_BSWAP_BE32(tcp->tcp_seq_be32),
	  (unsigned) CI_BSWAP_BE32(tcp->tcp_ack_be32),
	  (int) CI_BSWAP_BE16(tcp->tcp_window_be16),
	  (int) CI_TCP_HDR_LEN(tcp),
	  (unsigned)CI_BSWAP_BE16(tcp->tcp_check_be16),
	  (int) CI_BSWAP_BE16(tcp->tcp_urg_ptr_be16));
  ci_log("%s", s);

  if( CI_TCP_HDR_LEN(tcp) > sizeof(*tcp) ) {
    int si = ci_sprintf(s, "TCP");
    ci_pprint_tcp_hdr_options(tcp + 1,
			      CI_TCP_HDR_LEN(tcp) - sizeof(*tcp), s+si);
    ci_log("%s", s);
  }
}


void ci_pprint_udp_hdr(const ci_udp_hdr* udp)
{
  char s[80];

  ci_sprintf(s, "UDP %d=>%d len=%d paylen=%d check=0x%x",
	  (int) CI_BSWAP_BE16(udp->udp_source_be16),
	  (int) CI_BSWAP_BE16(udp->udp_dest_be16),
	  (int) CI_BSWAP_BE16(udp->udp_len_be16),
	  (int) (CI_BSWAP_BE16(udp->udp_len_be16) - sizeof(*udp)),
	  (unsigned)CI_BSWAP_BE16(udp->udp_check_be16));
  ci_log("%s", s);
}


void ci_pprint_icmp_hdr(const ci_icmp_hdr* icmp)
{
  char s[80];

  ci_sprintf(s, "ICMP type=%d code=%d check=%#x bytes 4->7=%#x %#x %#x %#x",
	  (int)icmp->type, (int)icmp->code,
	  (unsigned)CI_BSWAP_BE16(icmp->check),
	  (unsigned)((char*)icmp)[4],
	  (unsigned)((char*)icmp)[5],
	  (unsigned)((char*)icmp)[6],
	  (unsigned)((char*)icmp)[7] );
  ci_log("%s", s);
}


void ci_pprint_arp_hdr(const ci_arp_hdr* arp)
{
  char s[80];

  ci_sprintf(s, "ARP op=%d %s hw=%d (len %d) prot=%04x (len %d)",
	  (int) CI_BSWAP_BE16(arp->arp_op_be16),
	  ci_arp_op_str(arp->arp_op_be16),
	  (int) CI_BSWAP_BE16(arp->arp_hw_type_be16), (int) arp->arp_hw_len,
	  (unsigned) CI_BSWAP_BE16(arp->arp_prot_type_be16),
	  (int) arp->arp_prot_len);
  ci_log("%s", s);
}


void ci_pprint_ether_arp(const ci_ether_arp* arp)
{
  char s[80];
  int si = 0;
  ci_uint32 ip;

  si += ci_sprintf(s+si, "ARP src=");
  si += ci_format_eth_addr(s+si, sizeof(s)-si, arp->arp_src_mac, 0);
  si += ci_sprintf(s+si, " ");
  memcpy(&ip, arp->arp_src_ip, 4);
  si += ci_format_ip4_addr(s+si, sizeof(s)-si, ip);
  si += ci_sprintf(s+si, "  target=");
  si += ci_format_eth_addr(s+si, sizeof(s)-si, arp->arp_tgt_mac, 0);
  si += ci_sprintf(s+si, " ");
  memcpy(&ip, arp->arp_tgt_ip, 4);
  si += ci_format_ip4_addr(s+si, sizeof(s)-si, ip);

  ci_log("%s", s);
}

/**********************************************************************
**********************************************************************/

static int
ci_analyse_check_ge(unsigned data0, unsigned data1, const char *msg) 
{
  int rc = 0;

  if (data0 < data1) {
    ci_log(msg, data0, data1);
    rc = -1;
  }
  return rc;
}


static int
ci_analyse_check_eq(unsigned data0, unsigned data1, const char *msg) 
{
  int rc = 0;

  if (data0 != data1) {
    ci_log(msg, data0, data1);
    rc = -1;
  }
  return rc;
}


int ci_analyse_tcp(const ci_ip4_hdr* ip,
		       const ci_tcp_hdr* tcp, int bytes, int descend)
{
  unsigned csum;
  int rc = 0;

  if ((rc = ci_analyse_check_ge(bytes, CI_TCP_HDR_LEN(tcp),
      "TCP ***** header doesn;t fit in frame %x (TCP hdr %x) *****")))
    return rc;

  ci_pprint_tcp_hdr(tcp);

  bytes -= CI_TCP_HDR_LEN(tcp);

  if ((rc = ci_analyse_check_ge(CI_TCP_HDR_LEN(tcp), sizeof(ci_tcp_hdr),
      "TCP ***** bad header length %x %x *****")))
    return rc;

  csum = ci_tcp_checksum(ip, tcp, CI_TCP_PAYLOAD(tcp));

  rc = ci_analyse_check_eq(tcp->tcp_check_be16, csum,
    "TCP ***** bad checksum %x (I get %x) *****");

  if( (tcp->tcp_flags & (CI_TCP_FLAG_SYN|CI_TCP_FLAG_FIN))
      == (CI_TCP_FLAG_SYN|CI_TCP_FLAG_FIN) ) {
    ci_log("TCP ***** both SYN and FIN *****");
    rc = -1;
  }
  if( (tcp->tcp_flags & (CI_TCP_FLAG_SYN|CI_TCP_FLAG_ACK)) == 0 ) {
    ci_log("TCP ***** no ACK *****");
  }
  /* ?? check for other silly flag combos etc. */

  return rc;
}


int ci_analyse_udp(const ci_ip4_hdr* ip,
		   const ci_udp_hdr* udp, int bytes, int descend)
{
  unsigned csum;
  int rc = 0;

  if( !CI_IP4_FRAG_OFFSET(ip)) { 
    
    if ((rc = ci_analyse_check_ge(bytes, sizeof(*udp),
        "UDP ***** header doesn't fit in frame %x %x *****")))
      return rc;

    ci_pprint_udp_hdr(udp);
    
    if( ~ip->ip_frag_off_be16 & CI_IP4_FRAG_MORE ) { 
      ci_iovec iov;

      rc = ci_analyse_check_eq(bytes, CI_BSWAP_BE16(udp->udp_len_be16),
	"UDP ***** datagram length doesn't match IP total length %x %x *****");

      bytes -= sizeof(*udp);      
      CI_IOVEC_BASE(&iov) = (void *)(udp + 1);
      CI_IOVEC_LEN(&iov) = CI_BSWAP_BE16(ip->ip_tot_len_be16) -
          CI_IP4_IHL(ip) - sizeof(ci_udp_hdr);
      csum = ci_udp_checksum(ip, udp, &iov, 1);

      rc = ci_analyse_check_eq(udp->udp_check_be16, csum,
        "UDP ***** bad checksum %x (I get %x) *****");

    } else {
      ci_log("UDP ***** Cannot check length/sum on fragmented datagram *****");
    }
  }
  return rc;
}


int ci_analyse_icmp(const ci_ip4_hdr* ip,
		    const ci_icmp_hdr* icmp, int bytes, int descend)
{
  unsigned csum;
  int rc = 0;

  ci_assert( sizeof(*icmp) == 4 );

  if ((rc = ci_analyse_check_ge(bytes, sizeof(*icmp) + 4,
      "ICMP ***** header doesn't fit in datagram *****")))
    return rc;

  ci_pprint_icmp_hdr(icmp);

  ci_assert( sizeof(*icmp) == 4 );
  bytes -= sizeof(*icmp) + 4;

  csum = ci_icmp_checksum(ip, icmp);

  rc = ci_analyse_check_eq(icmp->check, csum,
	"ICMP ***** bad checksum %x (I get %x) *****");

  return rc;
}


int ci_analyse_ip4(const ci_ip4_hdr* ip, int bytes, int descend)
{
  void* payload;
  unsigned csum;
  char s[256];
  int rc = 0;
  
  if ((rc = ci_analyse_check_ge(bytes, CI_IP4_IHL(ip),
      "IP4 ***** header doesn't fit in frame %x (IP header %x) *****")))
    return rc;

  /* ?? options */

  ci_pprint_ip4_hdr(ip);

  if ((rc = ci_analyse_check_ge(CI_IP4_IHL(ip), sizeof(ci_ip4_hdr),
      "IP4 ***** bad header length %x %x *****")))
    return rc;

  /* ?? FIXME: Should check by summing over whole header and checking that
   * result is zero.
   */
  csum = ci_ip_csum_partial(0, ip, CI_IP4_IHL(ip));
  csum = ci_ip_hdr_csum_finish(csum);
  rc = ci_analyse_check_eq(csum, 0,
                           "IP4 ***** bad checksum (sum=%x zero=%x) *****");

  if( bytes > ETH_ZLEN - 14 )
    ci_analyse_check_ge(CI_BSWAP_BE16(ip->ip_tot_len_be16), bytes,
              "IP4 ***** IP datagram length %u doesn't match frame %u *****");

  if ((rc = ci_analyse_check_ge(bytes, CI_BSWAP_BE16(ip->ip_tot_len_be16),
      "IP4 ***** IP datagram doesn't fit in frame (flen=%u iplen=%u) *****")))
    return rc;

  if( CI_IP4_VERSION(ip) != 4 ) {
    ci_log("IP4 ***** not version 4 *****");
    rc = -1;
  }

  if( rc || !descend )  return rc;

  if( CI_BSWAP_BE16(ip->ip_tot_len_be16) <= bytes )
    bytes = CI_BSWAP_BE16(ip->ip_tot_len_be16);
  bytes -= CI_IP4_IHL(ip);
  payload = ((char*) ip + CI_IP4_IHL(ip));

  if( CI_IP4_FRAG_OFFSET(ip) | (ip->ip_frag_off_be16 & CI_IP4_FRAG_MORE) ) {
    ci_sprintf(s, "IP4 ***** fragment: %u bytes at offset %u *****", 
	    bytes, CI_IP4_FRAG_OFFSET(ip) << 3);
    ci_log("%s", s);
    if( CI_IP4_FRAG_OFFSET(ip))
      return 0;
  }

  switch( ip->ip_protocol ) {
  case IPPROTO_ICMP:
    return ci_analyse_icmp(ip, (ci_icmp_hdr*) payload, bytes, 1);
  case IPPROTO_TCP:
    return ci_analyse_tcp(ip, (ci_tcp_hdr*) payload, bytes, 1);
  case IPPROTO_UDP:
    return ci_analyse_udp(ip, (ci_udp_hdr*) payload, bytes, 1);
  default:
    ci_log("IP4 unknown protocol");
    return 0;
  }
}


int ci_analyse_ether_arp(const ci_ether_arp* arp, int bytes)
{
  int rc = 0;

  if ((rc = ci_analyse_check_ge(bytes,sizeof(ci_ether_arp),
      "ARP ***** doesn't fit in frame ***** %x %x")))
    return rc;

  if ((rc = ci_analyse_check_eq( arp->hdr.arp_hw_len, 6,
      "ARP ***** bad hardware address length %x %x *****")))
    return rc;

  if ((rc = ci_analyse_check_eq(arp->hdr.arp_prot_len, 4,
      "ARP ***** bad protocol address length %x %x *****")))
    return rc;

  ci_pprint_ether_arp(arp);

  return rc;
}


int ci_analyse_arp(const ci_arp_hdr* arp, int bytes)
{
  int rc = 0;

  if ((rc = ci_analyse_check_ge(bytes, sizeof(ci_arp_hdr),
      "ARP ***** header doesn't fit in frame %x %x *****")))
    return rc;

  ci_pprint_arp_hdr(arp);

  if( arp->arp_hw_type_be16 == CI_ARP_HW_ETHER &&
      arp->arp_prot_type_be16 == CI_ARP_PROT_IP )
    return ci_analyse_ether_arp((const ci_ether_arp*) arp, bytes);

  return rc;
}


int ci_analyse_ether(const ci_ether_hdr* eth, int bytes,
		     int descend)
{
  int rc = 0;
  int eth_hlen;
  ci_uint16 eth_type;

  if ((rc = ci_analyse_check_ge(bytes, ETH_HLEN, 
      "ETH ***** header doesn't fit in frame %x %x *****")))
    return rc;

  eth_hlen = ci_pprint_ether_hdr(eth, bytes);
  bytes -= eth_hlen;
  eth_type = *((ci_uint16*)eth + eth_hlen/2 - 1);

  if( !descend )  return 0;

  switch( eth_type ) {
  case CI_ETHERTYPE_IP:
    return ci_analyse_ip4((ci_ip4_hdr*)((char*)eth + eth_hlen), bytes, 1);
  case CI_ETHERTYPE_ARP:
    return ci_analyse_arp((ci_arp_hdr*)((char*)eth + eth_hlen), bytes);
  default:
    ci_log("ETH ***** unknown ether_type *****");
    return rc;
  }
}


int ci_analyse_pkt(const volatile void* pkt, int bytes)
{
  return ci_analyse_ether((const ci_ether_hdr*) pkt, bytes, 1);
}

/*! \cidoxg_end */
