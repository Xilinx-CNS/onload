/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  mjs
**  \brief  Toeplitz hash calculation
**   \date  2007/04/02
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_citools */

#include <ci/internal/transport_config_opt.h>

#include "citools_internal.h"

ci_uint32 ci_toeplitz_hash(const ci_uint8 *key, const ci_uint8 *input, int n)
{
  ci_uint32 key_bits;
  ci_uint32 result = 0;

  key_bits = (key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
  key += 4;

  while( --n >= 0 ) {
    ci_uint8 input_byte = *input++;
    ci_uint8 next_key_byte = *key++;
    ci_uint8 bit = 0x80;
    while (bit != 0) {
      if (input_byte & bit)  result ^= key_bits;
      key_bits <<= 1;
      if (next_key_byte & bit)  key_bits |= 1;
      bit >>= 1;
    }
  }

  return result;
}

#if !defined(__KERNEL__)

#if defined(CI_HAVE_X86INTRIN)

#include <x86intrin.h>

/* Key should be equal to original key, reversed and rotated left by 1 bit.
 * Original key should have a period of 4-bytes. Only the least significant
 * byte is accurate. Returns ci_uint32 for compatibility.
 */
__attribute__((target("pclmul,sse4.1"))) ci_inline ci_uint32
ci_toeplitz_hash_sse_finish(const ci_uint32 *key, ci_uint32 result)
{
  __m128i vkey = _mm_set_epi32(0, result, key[0], key[1]);

  result = _mm_extract_epi8(_mm_clmulepi64_si128(vkey, vkey, 0x01), 5);

  /* Perform a bit-reversal before returning */
  return ((result * 0x80200802ULL) & 0x0884422110) * 0x0101010101ULL >> 32;
}

static ci_uint32
ci_toeplitz_hash_sse_ip4(const ci_uint32 *key, const ci_uint32 *input, int size)
{
  /* This implementation is tailored to our 12-byte IP 4-tuple */
  ci_assert_equal(size, 12);

  return ci_toeplitz_hash_sse_finish(key, input[0] ^ input[1] ^ input[2]);
}

#if defined(CI_CFG_IPV6) && CI_CFG_IPV6

#define IPV6_TUPLE_SIZE 36

__attribute__((target("pclmul,sse4.1"))) static uint32_t
ci_toeplitz_hash_sse_ip6(const uint32_t *key, const uint32_t *input, int size)
{
  __m128i a, b;

  ci_assert_equal(size, IPV6_TUPLE_SIZE);

  a = _mm_xor_si128(_mm_loadu_si128((__m128i*)input),
                    _mm_loadu_si128((__m128i*)(input + 4)));
  b = _mm_xor_si128(_mm_srli_si128(a, 8), a);
  return ci_toeplitz_hash_sse_finish(key, _mm_extract_epi32(b, 0) ^
                                     _mm_extract_epi32(b, 1) ^ input[8]);
}
#endif

#endif /* CI_HAVE_X86INTRIN */

ci_uint32 ci_toeplitz_hash_ul(const ci_uint8 *key, const ci_uint8 *sse_key,
                              const ci_uint8 *input, int size)
{
#if defined(CI_HAVE_X86INTRIN)
  static int pclmul_support = -1;

  if(CI_UNLIKELY( pclmul_support < 0 ))
    pclmul_support = ci_cpu_has_feature(CI_CPU_FEATURE_PCLMULQDQ);

  if( pclmul_support ) {
#if defined(CI_CFG_IPV6) && CI_CFG_IPV6
    if( size == IPV6_TUPLE_SIZE )
      return ci_toeplitz_hash_sse_ip6((ci_uint32*) sse_key, (ci_uint32*) input,
                                      size);
    else
#endif
      return ci_toeplitz_hash_sse_ip4((ci_uint32*) sse_key, (ci_uint32*) input,
                                      size);
  }
  else
#endif /* CI_HAVE_X86INTRIN */
    return ci_toeplitz_hash(key, input, size);
}

#endif /* __KERNEL__ */

/*! \cidoxg_end */
