/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

struct ci_ip4_hdr_s;
struct ci_tcp_hdr_s;
struct ci_udp_hdr_s;
struct ci_icmp_hdr_s;
struct ci_ip6_hdr_s;

ci_inline unsigned ci_ip_hdr_csum_finish(unsigned sum) {
  sum =  (sum >> 16u) + (sum & 0xffff);
  sum += (sum >> 16u);
  return ~sum & 0xffff;
}

ci_inline unsigned ci_tcp_csum_finish(unsigned csum)
{ return ci_ip_hdr_csum_finish(csum); }

ci_inline unsigned ci_icmp_csum_finish(unsigned csum)
{ return ci_ip_hdr_csum_finish(csum); }

/*! Compute the checksum for an IP header. */
extern unsigned ci_ip_checksum(const struct ci_ip4_hdr_s* ip) CI_HF;

/*! Accumulate a partial checksum for a memory region.  [sum] and the
  **  returned value are 16+ bit partial checksums.
  */
extern unsigned ci_ip_csum_partial(unsigned sum, const volatile void* in_buf,
				   int bytes) CI_HF;
