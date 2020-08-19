/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */
#ifndef __CI_TOOLS_UTILS_H__
#define __CI_TOOLS_UTILS_H__


/**********************************************************************
 * misc
 **********************************************************************/ 

#define CI_ZERO(p)  memset((void*) (p), 0, sizeof(*(p)))

#define CI_ZERO_ARRAY(p, howmany)  \
  memset((void*) (p), 0, (howmany) * sizeof(*(p)))

#ifdef NDEBUG
# define CI_DEBUG_ZERO(p)  do{}while(0)
#else
# define CI_DEBUG_ZERO     CI_ZERO
#endif

#ifdef NDEBUG
# define CI_DEBUG_ZERO_ARRAY(p, howmany)  do{}while(0)
#else
# define CI_DEBUG_ZERO_ARRAY              CI_ZERO_ARRAY
#endif

#ifdef CI_HAVE_FRC64
ci_inline ci_uint64 ci_frc64_get(void) {
  ci_uint64 now;
  ci_frc64(&now);
  return now;
}
#endif
#ifdef CI_HAVE_FRC32
ci_inline ci_uint32 ci_frc32_get(void) {
  ci_uint32 now;
  ci_frc32(&now);
  return now;
}
#endif


/* Convert value to signed int.  Useful in macros when you want to compare
** >= 0 but arg may sometimes be unsigned.
*/
ci_inline int ci_to_int(int v) { return v; }


/**********************************************************************
 * memory allocation helpers
 **********************************************************************/ 

#define CI_ALLOC_ARRAY(type, howmany)  \
  ((type*) ci_alloc((howmany) * sizeof(type)))
#define CI_VMALLOC_ARRAY(type, howmany)  \
  ((type*) ci_vmalloc((howmany) * sizeof(type)))


#define CI_ALLOC_OBJ(type)  \
  ((type*) ci_alloc(sizeof(type)))

#define CI_FREE_OBJ(ptr)  \
  do { CI_DEBUG_ZERO(ptr); ci_free(ptr); }while(0)


/**********************************************************************
 * CRCs, hashes
 **********************************************************************/ 

extern unsigned ci_crc16_add8(unsigned old_crc, unsigned poly,
			      unsigned data) CI_HF;
  /*!< Naive, slow algorithm.  Need table-based version if you want
   * fast.  The polynomial values are not bit reversed, so the lowest
   * order coefficient is in the least significant bit of each
   * value. */

extern unsigned ci_crc32_add8(unsigned old_crc, unsigned poly,
			      unsigned data) CI_HF;
  /*!< Naive, slow algorithm.  Need table-based version if you want
   * fast.  The polynomial values are not bit reversed, so the lowest
   * order coefficient is in the least significant bit of each
   * value. */

extern ci_uint32 ci_crc32_partial(const ci_uint8 *buf, ci_uint32 buflen,
                                  ci_uint32 crc);
  /*!< Table-based CRC32 calculation (IEEE 802.3 polynomial).  This is
   * suitable for use on an ethernet frame.  All polynomial values are
   * bit reversed, so the higest order coefficient of the input
   * polynomial is in the least significant bit of the first byte of
   * the buffer.  The highest order coefficient of the crc polynomial
   * is in the least significant bit of the crc value.
   */

extern ci_uint32 ci_crc32_partial_copy(ci_uint8 *dest, const ci_uint8 *buf,
                                       ci_uint32 buflen, ci_uint32 crc);
  /*!< Table-based CRC32 calculation and memcpy (IEEE 802.3 polynomial).
   * This is the same as ci_crc32_partial but performs a memcpy at the
   * same time. */

extern ci_uint32 ci_toeplitz_hash(const ci_uint8 *key, const ci_uint8 *input,
                                  int n);
  /*!< Toeplitz hash */

#if !defined(__KERNEL__)

extern ci_uint32
ci_toeplitz_hash_ul(const ci_uint8 *key, const ci_uint8* sse_key,
                    const ci_uint8 *input, int n);
#endif



#ifndef __KERNEL__

/**********************************************************************
 * system info
 **********************************************************************/ 

  /*! The processor speed.  This value is the number of times the free
  ** running counter (see ci_frc*()) updates per second (divided by 1000).
  ** This value is initialised by calling ci_get_cpu_khz().  Before the
  ** first call it's value is zero.
  */
extern unsigned ci_cpu_khz CI_HV;

  /*! Get the processor speed.  Returns -ve error code on failure. */
extern int ci_get_cpu_khz(unsigned* cpu_khz_out) CI_HF;


  /*! You must have called ci_get_cpu_khz() before calling this if you want
  ** a useful answer. */
ci_inline ci_uint64 ci_usec_to_cycles64(unsigned usec)
{ return (ci_uint64) usec * ci_cpu_khz / 1000; }

  /*! You really *must* have called ci_get_cpu_khz() before calling this. */
ci_inline unsigned  ci_cycles64_to_usec(ci_uint64 cycles)
{ return (unsigned) (cycles * 1000 / ci_cpu_khz); }

#endif


/**********************************************************************
 * sequence space arithmetic
 **********************************************************************/ 

#define ci_seq_eq(a, b, bits)	((((a) - (b)) & ((1u << (bits)) - 1u)) == 0u)
#define ci_seq_neq(a, b, bits)	(((a) - (b)) & ((1u << (bits)) - 1))
#define ci_seq_lt(a, b, bits)	(((a) - (b)) & (1u << ((bits) - 1)))
#define ci_seq_gt(a, b, bits)	ci_seq_lt((b), (a), (bits))
#define ci_seq_le(a, b, bits)	(!ci_seq_lt((b), (a), (bits)))
#define ci_seq_ge(a, b, bits)	(!ci_seq_lt((a), (b), (bits)))

/* Only use these if the mask uses fewer than all the available bits. */
#define ci_seqm_eq(a, b, mask)	((((a) - (b)) & (mask)) == 0u)
#define ci_seqm_neq(a, b, mask)	(((a) - (b)) & (mask))
#define ci_seqm_lt(a, b, mask)	(((a) - (b)) & (((mask) + 1u) >> 1u))
#define ci_seqm_gt(a, b, mask)	ci_seqm_lt((b), (a), (mask))
#define ci_seqm_le(a, b, mask)	(!ci_seqm_lt((b), (a), (mask)))
#define ci_seqm_ge(a, b, mask)	(!ci_seqm_lt((a), (b), (mask)))

#define ci_int32_lt(a, b)	ci_seq_lt((a), (b), 32)
#define ci_int32_gt(a, b)	ci_seq_gt((a), (b), 32)
#define ci_int32_le(a, b)	ci_seq_le((a), (b), 32)
#define ci_int32_ge(a, b)	ci_seq_ge((a), (b), 32)


/**********************************************************************
 * atomic ops that are not atomic when single-threaded
 **********************************************************************/ 

#ifndef __KERNEL__

ci_inline void ci_atomic_quick_inc (ci_atomic_t *a)
{ if( ci_is_multithreaded() )  ci_atomic_inc(a);
  else ++a->n;
}

ci_inline void ci_atomic_quick_dec(ci_atomic_t* a)
{ if( ci_is_multithreaded() )  ci_atomic_dec(a);
  else --a->n;
}

ci_inline int ci_atomic_quick_inc_and_test(ci_atomic_t* a) {
  if( ci_is_multithreaded() )  return ci_atomic_inc_and_test(a);
  else return ++a->n == 0;
}

ci_inline int ci_atomic_quick_dec_and_test(ci_atomic_t* a) {
  if( ci_is_multithreaded() ) return ci_atomic_dec_and_test(a);
  else return --a->n == 0;
}

#else

# define ci_atomic_quick_inc		ci_atomic_inc
# define ci_atomic_quick_dec		ci_atomic_dec
# define ci_atomic_quick_inc_and_test	ci_atomic_inc_and_test
# define ci_atomic_quick_dec_and_test	ci_atomic_dec_and_test

#endif


/* gcc's builtin ffs implemntations and the kernel's __ffs implementations
 * differ in their indexing of the bits, and in whether it's valid to call them
 * with a zero argument.  ci_ffs64() follow's gcc's semantics. */
#ifdef __KERNEL__
static inline int ci_ffs64(ci_uint64 x)
{
  return x == 0 ? 0 : __ffs64(x) + 1;
}
#else
# define ci_ffs64 __builtin_ffsll
#endif


#endif  /* __CI_TOOLS_UTILS_H__ */
/*! \cidoxg_end */
