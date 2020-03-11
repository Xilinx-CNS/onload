/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \Fileque
** <L5_PRIVATE L5_HEADER >
** \author
**  \brief
**   \date
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools_platform  */

#ifndef __CI_TOOLS_GCC_AARCH64_H__
#define __CI_TOOLS_GCC_AARCH64_H__
/**********************************************************************
 *
 * Free-running cycle counters.
 *
 */

/* ARM64 version based on cntvec_el0 counter running at 20MHz as no
 * x86-style FRC available at user-level, but make it look the same to
 * callers
 */

static __inline__ ci_uint64 __rdtsc(void)
{
  ci_uint64 result;

  __asm__ __volatile__ ("isb; mrs %0, cntvct_el0": "=r" (result));

  return result;
}

#define CI_HAVE_FRC64
#define CI_HAVE_FRC32

ci_inline void ci_frc32(ci_uint32* pval)
{
  *pval=(ci_uint32)__rdtsc();
}

ci_inline void ci_frc64(ci_uint64* pval)
{
  *pval=__rdtsc();
}

#define ci_frc_flush()  ci_mb()



#define CI_HAVE_COMPARE_AND_SWAP

/* We use gcc builtins for these */

/* ARM64 TODO this could be optimised by using the __sync_bool... gcc
 * builtin versions where we want a boolean output
 */

#define __cas32(_type,_p,_oldval,_newval)                               \
  {                                                                     \
    return __sync_val_compare_and_swap((_type *)_p, (_type)_oldval, (_type)_newval); \
  }

#define __cas64(_type,_p,_oldval,_newval)                               \
  { \
    return __sync_val_compare_and_swap((_type *)_p, (_type)_oldval, (_type)_newval); \
  }

ci_inline ci_int32 ci_cas32(volatile ci_int32* p, ci_int32 oldval, ci_int32 newval)
{ __cas32(ci_int32, p, oldval, newval); }

ci_inline ci_uint32 ci_cas32u(volatile ci_uint32* p, ci_uint32 oldval, ci_uint32 newval)
{ __cas32(ci_uint32, p, oldval, newval); }

ci_inline ci_int64 ci_cas64(volatile ci_int64* p, ci_int64 oldval, ci_int64 newval)
{  __cas64(ci_int64, p, oldval, newval); }

ci_inline ci_int64 ci_cas64u(volatile ci_uint64* p, ci_uint64 oldval, ci_uint64 newval)
{  __cas64(ci_uint64, p, oldval, newval); }

ci_inline int ci_cas32_succeed(volatile ci_int32* p, ci_int32 oldval,
                   ci_int32 newval)
{ return (int) (ci_cas32(p, oldval, newval) == oldval); }

ci_inline int ci_cas32_fail(volatile ci_int32* p, ci_int32 oldval,
                ci_int32 newval)
{ return (int) (ci_cas32(p, oldval, newval) != oldval); }

ci_inline int ci_cas32u_succeed(volatile ci_uint32* p, ci_uint32 oldval,
                   ci_uint32 newval)
{ return (int) (ci_cas32u(p, oldval, newval) == oldval); }

ci_inline int ci_cas32u_fail(volatile ci_uint32* p, ci_uint32 oldval,
                ci_uint32 newval)
{ return (int) (ci_cas32u(p, oldval, newval) != oldval); }

ci_inline int ci_cas64_succeed(volatile ci_int64* p, ci_int64 oldval,
                   ci_int64 newval)
{ return (int) (ci_cas64(p, oldval, newval) == oldval); }

ci_inline int ci_cas64_fail(volatile ci_int64* p, ci_int64 oldval,
                ci_int64 newval)
{ return (int) (ci_cas64(p, oldval, newval) != oldval); }

ci_inline int ci_cas64u_succeed(volatile ci_uint64* p, ci_uint64 oldval,
                   ci_uint64 newval)
{ return (int) (ci_cas64u(p, oldval, newval) == oldval); }

ci_inline int ci_cas64u_fail(volatile ci_uint64* p, ci_uint64 oldval,
                ci_uint64 newval)
{ return (int) (ci_cas64u(p, oldval, newval) != oldval); }

#define ci_cas_uintptr_succeed(p,o,n)                           \
  ci_cas64u_succeed((volatile ci_uint64*) (p), (o), (n))

# define ci_cas_uintptr_fail(p,o,n)                     \
  ci_cas64u_fail((volatile ci_uint64*) (p), (o), (n))

/**********************************************************************
 * Atomic integer.
 */

typedef struct { volatile ci_int32 n; } ci_atomic_t;

#define CI_ATOMIC_INITIALISER(i)  {(i)}

ci_inline ci_int32  ci_atomic_read(const ci_atomic_t* a)  { return a->n;    }
ci_inline void ci_atomic_set(ci_atomic_t* a, int v)       { a->n = v; ci_wmb(); }

ci_inline void ci_atomic_inc(ci_atomic_t* a)
{
  __sync_fetch_and_add(&a->n, 1);
}

ci_inline void ci_atomic_dec(ci_atomic_t* a)
{
  __sync_fetch_and_sub(&a->n, 1);
}

ci_inline int  ci_atomic_inc_and_test(ci_atomic_t* a)
{
  return __sync_add_and_fetch(&a->n, 1) == 0;
}

ci_inline int  ci_atomic_dec_and_test(ci_atomic_t* a)
{
  return __sync_sub_and_fetch(&a->n, 1) == 0;
}

ci_inline void ci_atomic_and(ci_atomic_t* a, int v)
{
   __sync_fetch_and_and(&a->n, v);
}

ci_inline void ci_atomic_or(ci_atomic_t* a, int v)
{
   __sync_fetch_and_or(&a->n, v);
}

ci_inline int ci_atomic_xadd(ci_atomic_t* a, int v)
{
  return __sync_fetch_and_add(&a->n, v);
}

ci_inline void ci_atomic32_or(volatile ci_uint32* p, ci_uint32 mask)
{
   __sync_fetch_and_or(p, mask);
}

ci_inline void ci_atomic32_and(volatile ci_uint32* p, ci_uint32 mask)
{
   __sync_fetch_and_and(p, mask);
}

ci_inline void ci_atomic32_add(volatile ci_uint32* p, ci_uint32 v)
{
   __sync_fetch_and_add(p, v);
}

ci_inline void ci_atomic32_inc(volatile ci_uint32* p)
{
   __sync_fetch_and_add(p, 1);
}

ci_inline void ci_atomic32_dec(volatile ci_uint32* p)
{
   __sync_fetch_and_sub(p, 1);
}

ci_inline int ci_atomic32_dec_and_test(volatile ci_uint32* p)
{
  return __sync_sub_and_fetch(p, 1) == 0;
}

extern int ci_glibc_uses_nptl (void) CI_HF;
extern int ci_glibc_nptl_broken(void) CI_HF;
extern int ci_glibc_gs_get_is_multihreaded_offset (void) CI_HF;
extern int ci_glibc_gs_is_multihreaded_offset CI_HV;

#define ci_is_multithreaded() 1


/**********************************************************************
 *
 * Exchange
 */

/* Use gcc builtins */

ci_inline uint32_t ci_xchg_u32(volatile uint32_t *p, uint32_t val)
{
  /* Use gcc builtin */
  return (uint32_t)__sync_lock_test_and_set(p, val);
}

ci_inline uint64_t ci_xchg_u64(volatile uint64_t *p, uint64_t val)
{
  /* Use gcc builtin */
  return (uint64_t)__sync_lock_test_and_set(p, val);
}

ci_inline ci_uint32 ci_xchg32(volatile ci_uint32* p, ci_uint32 val)
{
  return (ci_uint32) ci_xchg_u32(p, val);
}

#define ci_xchg_uintptr(p, v) (ci_uintptr_t)ci_xchg_u64((volatile uint64_t*) p, \
                                                        (uint64_t)v)
#define ci_atomic_xchg(a, v) (int)ci_xchg_u32((uint32_t*)&(a)->n, (uint32_t)v)

/**********************************************************************
 * Atomic bit field.
 */

typedef ci_uint32  ci_bits;
#define CI_BITS_N                       32u

#define CI_BITS_DECLARE(name, n)                        \
  ci_bits name[((n) + CI_BITS_N - 1u) / CI_BITS_N]

ci_inline void ci_bits_clear_all(volatile ci_bits* b, int n_bits)
{ memset((void*) b, 0, (n_bits+CI_BITS_N-1u) / CI_BITS_N * sizeof(ci_bits)); }

ci_inline void ci_bit_set(volatile ci_bits* bits, int i)
{
  // arm64 force type
  volatile ci_int32 *b = (volatile ci_int32 *)bits;
  ci_int32 mask, old, new;
  mask = 1 << ( i & 31 );
  do {
    old = b[i>>5];
    new = old | mask;
  } while (ci_cas32(b, old, new) != old);
}

ci_inline void ci_bit_clear(volatile ci_bits* bits, int i)
{
  // arm64 force type
  volatile ci_int32 *b = (volatile ci_int32 *)bits;
  ci_int32 mask, old, new;
  mask = ~(1 << ( i & 31 ));
  do {
    old = b[i>>5];
    new = old & mask;
  } while (ci_cas32(b, old, new) != old);
}

ci_inline int ci_bit_test(volatile ci_bits* b, int i)
{ return b[i >> 5] & (1<<(i & 31)); }

ci_inline int ci_bit_test_and_set(volatile ci_bits *bits, int i)
{
  // arm64 force type
  volatile ci_int32 *b = (volatile ci_int32 *)bits;
  ci_int32 mask, old, new;
  mask = 1 << ( i & 31 );
  do {
    old = b[i>>5];
    new = old | mask;
  } while (ci_cas32(b, old, new) != old);
  return (old & mask) != 0;
}

ci_inline int ci_bit_test_and_clear(volatile ci_bits *bits, int i)
{
  // arm64 force type
  volatile ci_int32 *b = (volatile ci_int32 *)bits;
  ci_int32 mask, old, new;
  mask = ~(1 << ( i & 31 ));
  do {
    old = b[i>>5];
    new = old & mask;
  } while (ci_cas32(b, old, new) != old);
  return (old & ~mask) != 0;
}

#define ci_bit_mask_set(b,m)    ci_atomic32_or((b), (m))
#define ci_bit_mask_clear(b,m)  ci_atomic32_and((b), ~(m))

/**********************************************************************
 * Misc.
 */

/* Merge the bits identified by [mask] from [val] to [*p]. */
ci_inline void ci_atomic32_merge(volatile ci_uint32* p,
                                 ci_uint32 val, ci_uint32 mask)
{
  ci_uint32 oldv, newv;
  do {
    oldv = *p;
    newv = (oldv & ~mask) | (val & mask);
  } while(CI_UNLIKELY( oldv != newv && ci_cas32u_fail(p, oldv, newv) ));
}


# define ci_spinloop_pause()  do{}while(0)

#define CI_HAVE_ADDC32
#define ci_add_carry32(sum, v)                          \
  do {                                                  \
    ci_uint64 temp;                                     \
    temp=(((ci_uint64)(sum))+((ci_uint32) (v)));        \
    sum=(unsigned int)(temp+(temp>>32));                \
  } while(0)


/* TODO */
#define ci_prefetch(addr)      do{}while(0)
#define ci_prefetch_ppc(addr)  do{}while(0)


#endif /* __CI_TOOLS_GCC_AARCH64_H__ */

/*! \codoxg_end */
