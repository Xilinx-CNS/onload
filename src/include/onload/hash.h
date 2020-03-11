/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mjp
**  \brief  Hash functions for implementing lookup tables
**   \date  2017/07/14
**    \cop  (c) 2017 Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_HASH_H__
#define __ONLOAD_HASH_H__

/* Top-level file must define CI_CFG_IPV6 in some way */

#include <ci/tools.h>
#include <ci/net/ipvx.h>

/* onload_addr_xor() DOES NOT returns the same result for IPv4 address
 * in natural form (!CI_CFG_IPV6) and in IPv6-mapped form.
 * However it us harmless for all the existing use-cases:
 * - All the Onload code is compiled in the same way;
 * - All the Cplane code is always compiled with CI_CFG_IPV6.
 *
 * If you are writing more cplane code, in particular cplane library linked
 * with Onload, ensure that your code is always compiled with CI_CFG_IPV6.
 */
ci_inline unsigned onload_addr_xor(const ci_addr_t addr)
{
#if CI_CFG_IPV6
  unsigned addr_xor = 0;
  int i;
  for( i = 0; i < 4; i++ )
    addr_xor ^= addr.u32[i];
  return addr_xor;
#else
  return addr.ip4;
#endif
}


/*!
** Hashing alternatives:
**
**  linear hashing  (good cache performance, but get clustering)
**  quadratic hashing  (try positions 1, 4, 9 away...)
**  double-hashing
**  re-hashing  (resize table or use different hash fn)
**
** Double-hashing: h(k,i) = (h1(k) + i*h2(k)) mod n    for i=0,1,2...
**   Require h2(k) be relatively prime in n.  eg. n is power 2, and h2(k)
**   is odd.
**
** Note that you get better cache performance w linear hashing, so it might
** be best on the host.
**
** Resources:
**  http://www.sci.csuhayward.edu/~billard/cs3240/node23.html
**  http://ciips.ee.uwa.edu.au/~morris/Year2/PLDS210/hash_tables.html
**  http://algorithm.myrice.com/resources/technical_artile/hashing_rehashed/hashing_rehashed.htm
**  http://www.cs.nyu.edu/courses/summer03/G22.1170-001/5-Hashing.pdf
**  http://uiorean.cluj.astral.ro/cursuri/dsa/6_Sda.pdf
*/

/* These hash functions are used in several places where Onload maintains hash
 * tables.  The foremost of these is the software filter table, the design of
 * which, given its critical importance for performance, is the primary
 * dictator of the functions' characteristics.  For example, they prefer speed
 * over good mixing, while still avoiding pathological collision-cases arising
 * from likely patterns in IP addresses and ports.  In fact this limited mixing
 * turns out to be useful, giving rise to a property that we define now:
 *
 * Definition 1.  A hash function h() of an IP-tuple has the Local Port
 * Recovery Property (LPRP) if, given the value of h(t) for some tuple t, and
 * also the values of the protocol, remote address, local address and remote
 * port for t, it is possible to find the value of the local port for t.
 *
 * For the cases in which we need it, proofs are given below that particular
 * functions have the LPRP. */

ci_inline unsigned __onload_hash3(unsigned laddr, unsigned lport,
                                  unsigned raddr, unsigned rport,
                                  unsigned protocol)
{
  unsigned h = CI_BSWAP_BE32(raddr) ^ CI_BSWAP_LE32(laddr) ^
               (rport << 16 | lport) ^ protocol;
  h ^= h >> 16;
  h ^= h >> 8;
  return h;
}
ci_inline unsigned onload_hash3(const ci_addr_t laddr, unsigned lport,
                                const ci_addr_t raddr, unsigned rport,
                                unsigned protocol)
{
  return __onload_hash3(onload_addr_xor(laddr), lport,
                        onload_addr_xor(raddr), rport, protocol);
}

/* Lemma 2.  The transformation
 *
 *   h ^= h >> 16;
 *   h ^= h >> 8;
 *
 * used at the end of __onload_hash3() is a bijection.
 *
 * Proof.  It is equivalent to
 *
 *   h = h ^ (h >> 8) ^ (h >> 16) ^ (h >> 24);
 *
 * the left-hand side of which, when shifted right by 8 and XORed with itself,
 * yields h.
 *
 * Proposition 3.  __onload_hash3() has the LPRP.
 *
 * Proof.  By Lemma 2, __onload_hash3() will have the LPRP if the expression
 * for the initial value of h in that function (viewed as a function in its own
 * right) has the LPRP.  We can rewrite the construction of that expression
 * slightly as
 *
 *   tmp = CI_BSWAP_BE32(raddr) ^ CI_BSWAP_LE32(laddr) ^ (rport << 16) ^
 *         protocol;
 *   h = tmp ^ lport;
 *
 * If the preconditions of the LPRP hold, the values of h and tmp are equal for
 * both tuples, and hence the values of lport are likewise equal.
 *
 * Lemma 4.  The upper 16 bits of __onload_hash3() are independent of lport.
 *
 * Proof.  This is true of the initial value of h in that function by
 * construction.  By the expression given for the transformation applied to h
 * in the proof of Lemma 2, it is also true of the value of __onload_hash3()
 * itself. */

ci_inline unsigned __onload_hash1(unsigned size_mask,
                                  unsigned laddr, unsigned lport,
                                  unsigned raddr, unsigned rport,
                                  unsigned protocol)
{
  ci_assert(CI_IS_POW2(size_mask + 1));
  return __onload_hash3(laddr, lport, raddr, rport, protocol) & size_mask;
}
ci_inline unsigned onload_hash1(unsigned size_mask,
                                const ci_addr_t laddr, unsigned lport,
                                const ci_addr_t raddr, unsigned rport,
                                unsigned protocol)
{
  return __onload_hash1(size_mask, onload_addr_xor(laddr), lport,
                        onload_addr_xor(raddr), rport, protocol);
}

/* Proposition 5.  Suppose that the non-zero part of size_mask is at least 16
 * bits wide.  Then __onload_hash1() has the LPRP.
 *
 * Proof.  Let h be the value of __onload_hash1().  By assumption, this gives
 * us immediately at least the lowest 16 bits of __onload_hash3().  Now assume
 * the preconditions of the LPRP, so that we know all parameters of the tuple
 * other than the local port.  By Lemma 4, we have enough information to
 * construct also the upper 16 bits of __onload_hash3, and thus we know the
 * full value of that function.  But by Proposition 3, __onload_hash3() has the
 * LPRP, so we can find the value of the local port, and the result follows. */

ci_inline unsigned __onload_hash2(unsigned laddr, unsigned lport,
                                  unsigned raddr, unsigned rport,
                                  unsigned protocol)
{
  /* N.B. rport and lport are in opposite words with respect to the calculation
   * in onload_hash1. */
  return (CI_BSWAP_LE32(laddr ^ raddr)
         ^ (lport << 16 | rport) ^ protocol) | 1u;
}
ci_inline unsigned onload_hash2(const ci_addr_t laddr, unsigned lport,
                                const ci_addr_t raddr, unsigned rport,
                                unsigned protocol)
{
  return __onload_hash2(onload_addr_xor(laddr), lport,
                        onload_addr_xor(raddr), rport, protocol);
}


/* This variant of onload_hash2() has a better distribution when the
 * low bits of the addresses are zero, such as when they've been
 * masked off because the prefix length is less than 32. */
ci_inline unsigned cplane_hash2(const ci_addr_t laddr, unsigned ifindex,
                                const ci_addr_t raddr, unsigned tos,
                                unsigned iif_ifindex)
{
  unsigned laddr_xor = onload_addr_xor(laddr);
  unsigned raddr_xor = onload_addr_xor(raddr);

  /* N.B. ifindex and tos are in opposite words with respect to the
   * calculation in onload_hash1. */
  unsigned h = CI_BSWAP_LE32(raddr_xor) ^ CI_BSWAP_BE32(laddr_xor + raddr_xor) ^
               (ifindex << 16 | (iif_ifindex + tos));
  h ^= h >> 16;
  h ^= h >> 8;
  return h | 1u;
}

#endif /* __ONLOAD_HASH_H__ */
