/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Internet checksum support.
**   \date  2003/06/18
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_IPCSUM_H__
#define __CI_TOOLS_IPCSUM_H__

struct ci_ip4_hdr_s;
struct ci_tcp_hdr_s;
struct ci_udp_hdr_s;
struct ci_icmp_hdr_s;
struct ci_ip6_hdr_s;

  /*! Compute the checksum for a TCP packet. */
extern unsigned ci_tcp_checksum(const struct ci_ip4_hdr_s* ip,
				const struct ci_tcp_hdr_s* tcp,
				const void* payload) CI_HF;

extern unsigned ci_ip6_tcp_checksum(const struct ci_ip6_hdr_s* ip6,
                                    const struct ci_tcp_hdr_s* tcp,
                                    const void* payload) CI_HF;

  /*! Compute the checksum for a UDP packet. */
extern unsigned ci_udp_checksum(const struct ci_ip4_hdr_s* ip,
				const struct ci_udp_hdr_s* udp,
				const ci_iovec *iov, int iovlen) CI_HF;

extern unsigned
ci_ip6_udp_checksum(const struct ci_ip6_hdr_s* ip6,
                    const struct ci_udp_hdr_s* udp,
                    const ci_iovec *iov, int iovlen) CI_HF;

  /*! Compute the checksum for a ICMP packet. */
extern unsigned ci_icmp_checksum(const struct ci_ip4_hdr_s* ip,
				 const struct ci_icmp_hdr_s* icmp) CI_HF;

extern unsigned
ci_icmpv6_checksum(const struct ci_ip6_hdr_s* ip6,
                   const struct ci_icmp_hdr_s* icmp) CI_HF;

  /*! Compute a partial checksum for those parts of the IP header that are
  ** unlikely to change when communicating with a particular host.  ie. All
  ** except [length] and [id] fields.
  **
  ** The result is a 16+ bit partial checksum.
  */
extern unsigned ci_ip_csum_precompute(const struct ci_ip4_hdr_s* ip) CI_HF;

  /*! Compute a partial checksum for those parts of a TCP packet that are
  ** unlikely to change (for a particular connection).  Fields excluded
  ** are: [length] from the pseudo header, and [seq], [ack] and [window]
  ** from the TCP header.
  **
  ** The result is a 16+ bit partial checksum.
  */
extern unsigned ci_tcp_csum_precompute(const struct ci_ip4_hdr_s* ip,
				       const struct ci_tcp_hdr_s* tcp) CI_HF;

  /*! Compute a partial checksum for those parts of a UDP packet that are
  ** unlikely to change (for a particular 'connection').  Fields excluded
  ** are: [length] from pseudo header, and [length] from the UDP header.
  **
  ** The result is a 16+ bit partial checksum.
  */
extern unsigned ci_udp_csum_precompute(const struct ci_ip4_hdr_s* ip,
				       const struct ci_udp_hdr_s* udp) CI_HF;


  /*! Reduce the checksum to 17 bits.  This is useful if you want to add in
  ** 16 bits at a time using ordinary 32 bit arithmetic (ie. no carry).
  */
ci_inline unsigned ci_ip_csum_fold(unsigned sum)
{ return (sum >> 16u) + (sum & 0xffff); }


ci_inline unsigned ci_udp_csum_finish(unsigned sum) {
  sum =  (sum >> 16u) + (sum & 0xffff);
  sum += (sum >> 16u);
  sum = ~sum & 0xffff;
  return sum ? sum : 0xffff;
}


/****************************************************************************
 * Defines to point at C/ASM routines
 ***************************************************************************/
#define ci_ip_csum              ci_ip_csum_c
#define ci_ip_csum_copy         ci_ip_csum_copy_c
#define ci_ip_csum_aligned      ci_ip_csum_aligned_c
#define ci_ip_csum_copy_aligned ci_ip_csum_copy_aligned_c

ci_inline unsigned int
ci_ip_csum_c(const void *data, size_t n, int start_not_aligned,
             unsigned int csum);

ci_inline unsigned int
ci_ip_csum_copy_c(void *dst, const void *src, size_t n, int start_not_aligned,
                  unsigned int csum);

ci_inline unsigned
ci_ip_csum_aligned_c(const void *data, size_t n, unsigned int csum);

/****************************************************************************
 * Aligned csum and csum_copy routines. Assumes dest is half word aligned
 ***************************************************************************/
ci_inline unsigned
ci_ip_csum_aligned_c(const void *data, size_t n, unsigned int csum)
{
  const ci_uint32 *s4 = (const ci_uint32 *)data;
  const ci_uint32 *es4 = s4 + (n >> 2);
  ci_uint32        v;

  ci_assert(s4);

  /* This loop is summing (potentially unaligned) words */
  while (s4 != es4) {
    v = *s4++;
    ci_add_carry32(csum, v);
  }

  n &= 3;
  if( n == 0 )
    return csum;

  if( n & 2 ) {
    v = *(const ci_uint16 *)s4;
    ci_add_carry32(csum, v);
  }
  if( n & 1 ) {
    const ci_uint8  *s = (const ci_uint8 *)s4;

    if( n == 3 ) {
      s += 2;
    }
    v = *s;
    /* If there's a lone final byte, it needs to be treated as if it
     * was padded by an extra zero byte.  Casting to ci_uint8*
     * introduces an implicit CI_BSWAP_LE16 which needs to be
     * reversed. */
    ci_add_carry32(csum, CI_BSWAP_LE16(v));
  }

  return csum;
}


/*! Copy from [src] to [dest] whilst checksumming.  [sum] is a partial
** checksum.  Returns the final checksum.
*/
ci_inline unsigned
ci_ip_csum_copy_aligned_c(void* dest, const void* src, int n, unsigned sum)
{
  ci_uint32* d4 = (ci_uint32*) dest;
  const ci_uint32 *es4, *s4 = (const ci_uint32*) src;
  ci_uint32 v;

  ci_assert(dest || n == 0);
  ci_assert(src  || n == 0);
  ci_assert(n >= 0);

  es4 = s4 + (n >> 2);

  ci_assert(s4 == es4 || NULL != d4); /* to help Win prefast's logic */
  ci_assert(s4 == es4 || NULL != s4); /* to help Win prefast's logic */
  
  /* This loop is summing (potentially unaligned) words */
  while( s4 != es4 ) {
    *d4++ = v = *s4++;
    ci_add_carry32(sum, v);
  }

  n = n & 3;
  if( n == 0 )  return sum;

  if( n & 2 ) {
    *(ci_uint16*) d4 = v = *(const ci_uint16*) s4;
    ci_add_carry32(sum, v);
  }
  if( n & 1 ) {
    const ci_uint8* s = (const ci_uint8*) s4;
    ci_uint8* d = (ci_uint8*) d4;
    ci_uint32 w;

    if( n == 3 ) { s += 2;  d += 2; }
    w = (*d = *s);
    /* If there's a lone final byte, it needs to be treated as if it
     * was padded by an extra zero byte.  Casting to ci_uint8*
     * introduces an implicit CI_BSWAP_LE16 which needs to be
     * reversed. */
    ci_add_carry32(sum, CI_BSWAP_LE16(w));
  }

  return sum;
}



/****************************************************************************
 * Safe versions of functions that test dest alignment
 ***************************************************************************/
ci_inline unsigned int
ci_ip_csum_c(const void *data, size_t n, int start_not_aligned,
                  unsigned int csum)
{
  if (start_not_aligned && n!=0)
  {
    /* If there's a lone initial byte, it needs to be treated as if
     * there was an extra zero byte before it.  Casting to ci_uint8*
     * introduces an implicit CI_BSWAP_BE16 which needs to be
     * reversed. */
    ci_add_carry32(csum, CI_BSWAP_BE16(*(ci_uint8*)data));
    data = ((const ci_uint8 *)data) + 1;
    --n;
  }
  return ci_ip_csum_aligned_c(data, n, csum);
}


ci_inline unsigned int
ci_ip_csum_copy_c(void *dst, const void *src, size_t n, int start_not_aligned,
                  unsigned int csum)
{
  if (start_not_aligned && n != 0)
  {
    *((ci_uint8*)dst) = *((ci_uint8*)src);
    /* If there's a lone initial byte, it needs to be treated as if
     * there was an extra zero byte before it.  Casting to ci_uint8*
     * introduces an implicit CI_BSWAP_BE16 which needs to be
     * reversed. */
    ci_add_carry32(csum, CI_BSWAP_BE16(*(ci_uint8*)src));
    dst = ((ci_uint8 *)dst)       + 1;
    src = ((const ci_uint8 *)src) + 1;
    --n;
  }
  return ci_ip_csum_copy_aligned_c(dst, src, n, csum);
}



/****************************************************************************
 * ASM functions
 ***************************************************************************/

  /* Asm version.  May be worth using this one day (not much faster yet). */
extern unsigned ci_ip_csum_copy_asm(void* dest, const void* src,
				    int n, unsigned sum) CI_HF;


/****************************************************************************
 * Other functions
 ***************************************************************************/

  /*! Copy from [src] to [dest] whilst checksumming.  [n] must be a
  ** multiple of two.  [sum] is a partial checksum.  Returns the final
  ** checksum.
  */
extern unsigned ci_ip_csum_copy2(void* dest, const void* src,
				 int n, unsigned sum) CI_HF;


  /*! Copy from [src] to [dest] whilst checksumming. If [dest] is not
  ** aligned on a 2-byte boundary from start of checksum then
  ** [dest_unalign] must be set.
  ** Returns the number of bytes copied, and updates [*sum] and [*src].
  **
  ** If [src] is an odd number of bytes long, then it is padded with a zero
  ** at the end (for the purposes of the checksum).
  */
extern int ci_ip_csum_copy_iovec(void* dest, int dest_len, int dest_unalign,
				 ci_iovec_ptr* src, unsigned* sum) CI_HF;


  /*! Copy from [src] to [dest] whilst checksumming.  Returns the number of
  ** bytes copied, and updates [*sum] and [*dest].
  **
  ** If the number of bytes copied is odd, then a zero-byte is added to the
  ** end of the checksum.
  */
extern int ci_ip_csum_copy_to_iovec(ci_iovec_ptr* dest, const void* src,
				    int src_len, unsigned* sum) CI_HF;


#endif  /* __CI_TOOLS_IPCSUM_H__ */
/*! \cidoxg_end */
