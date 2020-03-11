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

#ifndef __CI_TOOLS_GCC_PPC_H__
#define __CI_TOOLS_GCC_PPC_H__

/*
 * NOTE: These are the basic data type sizes in GNU..
 *
 *     '__powerpc64__',       '__powerpc32__'
 *
 *  char      -  8  bits          8  bits
 *  short     -  16 bits         16  bits
 *  int       -  32 bits         32  bits
 *  long      -  64 bits         32  bits
 *  pointers  -  64 bits         32  bits
 *  long long -  64 bits         64  bits
 *
 */


/*
 *  Assume all systems are going to be SMP builds for the moment ....
 */


#ifdef __powerpc64__

#		define CI_SMP_SYNC        "\n   lwsync     \n"         /* memory cache sync */
#		define CI_SMP_ISYNC       "\n   isync     \n"         /* instr cache sync */

#else	 /* for ppc32 systems */

#		define CI_SMP_SYNC        "\n   eieio     \n"
#		define CI_SMP_ISYNC       "\n   sync      \n"

#endif




/**********************************************************************
 *
 * Read Time Stamp Counter sub.
 *
 */
#ifdef __powerpc64__
static __inline__ ci_uint64 __rdtsc(void)
{
  ci_uint64 result;

  __asm__ __volatile__ (
      CI_SMP_SYNC
      "mfspr %0, 268\n"
      : "=r" (result)
  );
  return result;

}
#else
static __inline__ ci_uint64 __rdtsc(void)
{
  ci_uint64 	result=0;
  ci_uint32 	upper, lower,tmp;

   __asm__ __volatile__(
      CI_SMP_SYNC

      "1:       mfspr  %0, 269         \n"
      "         mfspr  %1, 268         \n"
      "         mfspr  %2, 269         \n"
      "         cmpw   %2,%0      \n"
      "         bne    1b         \n"

      : "=r"(upper),"=r"(lower),"=r"(tmp)
   );

  result = upper;
  result = result<<32;
  result = result|lower;

  return(result);
}
#endif


/**********************************************************************
 *
 * Free-running cycle counters.
 *
 */

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


/**********************************************************************
 *
 * Atomic integer ops.
 *
 * ci_inline void ci_atomic_add     (ci_atomic_t* a, int v)
 * ci_inline int  ci_atomic_add_ret	(ci_atomic_t* a, int v)
 * ci_inline void ci_atomic_inc     (ci_atomic_t* a)
 * ci_inline int  ci_atomic_inc_ret (ci_atomic_t* a)
 *
 * ci_inline void ci_atomic_sub     (ci_atomic_t* a, int v)
 * ci_inline int  ci_atomic_sub_ret (ci_atomic_t* a, int v)
 * ci_inline void ci_atomic_dec     (ci_atomic_t* a)
 * ci_inline int  ci_atomic_dec_ret (ci_atomic_t* a)
 *
 * ci_atomic_inc_and_test(a)	(macro)
 * ci_atomic_dec_and_test(a)	(macro)
 *
 * ci_inline   void  ci_atomic_and  (ci_atomic_t* a, int v)
 * ci_inline   void  ci_atomic_or   (ci_atomic_t* a, int v)
 *
 * ci_inline   int   ci_atomic_read (ci_atomic_t* a)
 * ci_inline   void  ci_atomic_set  (ci_atomic_t* a, int v)
 *
 */


typedef 	   struct { volatile int n; }    ci_atomic_t;

#define CI_ATOMIC_INITIALISER(i)  {(i)}


ci_inline  void  ci_atomic_add  (ci_atomic_t* a, int v)
{
	//		Perform 	a->n += v

	int	t;

   __asm__ __volatile__(

     CI_SMP_SYNC

      "1:     lwarx   %0,0,%3, 1     \n"
      "       add     %0,%2,%0    \n"
      "       stwcx.  %0,0,%3     \n"
      "       bne-    1b          \n"

     CI_SMP_ISYNC

      : "=&r" (t), "=m" (a->n)
      : "r" (v), "r" (&a->n), "m" (a->n)
      : "cc"

   );
}


ci_inline   int   ci_atomic_add_ret	  (ci_atomic_t* a, int v)
{
	// Perform  return (a->n += v)

   int t;

   __asm__ __volatile__(

      CI_SMP_SYNC

      "1:     lwarx     %0,0,%2, 1   \n"
      "       add       %0,%1,%0  \n"
      "       stwcx.    %0,0,%2   \n"
      "       bne-      1b        \n"

      CI_SMP_ISYNC

      : "=&r" (t)
      : "r" (v), "r" (&a->n)
      : "cc", "memory"
   );

   return t;
}


ci_inline void ci_atomic_inc(ci_atomic_t *a)
{
	//		Perform 	++(a->n)

	int	t;

   __asm__ __volatile__(

     CI_SMP_SYNC


      "1:     lwarx   %0,0,%2, 1     \n"
      "       addic   %0,%0,1     \n"
      "       stwcx.  %0,0,%2     \n"
      "       bne-    1b          \n"

     CI_SMP_ISYNC

      : "=&r" (t), "=m" (a->n)
      : "r" (&a->n), "m" (a->n)
      : "cc"

   );
}


ci_inline int ci_atomic_inc_ret(ci_atomic_t *a)
{
	// Perform  return (++(a->n))

   int t;

   __asm__ __volatile__(

      CI_SMP_SYNC

      "1:     lwarx   %0,0,%1, 1     \n"
      "       addic   %0,%0,1     \n"
      "       stwcx.  %0,0,%1     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      : "=&r" (t)
      : "r" (&a->n)
      : "cc", "memory"
   );

   return t;
}


ci_inline void ci_atomic_sub(ci_atomic_t *a, int v)
{
	//		Perform 	a->n -= v

	int	t;

   __asm__ __volatile__(

      "1:     lwarx   %0,0,%3, 1     \n"
      "       subf    %0,%2,%0    \n"
      "       stwcx.  %0,0,%3     \n"
      "       bne-    1b          \n"

      : "=&r" (t), "=m" (a->n)
      : "r" (v), "r" (&a->n), "m" (a->n)
      : "cc"

   );
}


ci_inline int ci_atomic_sub_ret(ci_atomic_t *a, int v)
{
	// Perform  return (a->n -= v)

   int t;

   __asm__ __volatile__(

      CI_SMP_SYNC

      "1:     lwarx   %0,0,%2, 1     \n"
      "       subf    %0,%1,%0    \n"
      "       stwcx.  %0,0,%2     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      : "=&r" (t)
      : "r" (v), "r" (&a->n)
      : "cc", "memory"
   );

   return t;
}


ci_inline void ci_atomic_dec(ci_atomic_t *a)
{
	//		Perform 	--(a->n)

	int	t;

   __asm__ __volatile__(

      "1:     lwarx     %0,0,%2, 1   \n"
      "       addic     %0,%0,-1  \n"
      "       stwcx.    %0,0,%2   \n"
      "       bne-      1b        \n"

      : "=&r" (t), "=m" (a->n)
      : "r" (&a->n), "m" (a->n)
      : "cc"

   );
}


ci_inline int ci_atomic_dec_ret(ci_atomic_t *a)
{
	// Perform  return (--(a->n))

   int t;

   __asm__ __volatile__(

      CI_SMP_SYNC

      "1:     lwarx   %0,0,%1, 1     \n"
      "       addic   %0,%0,-1    \n"
      "       stwcx.  %0,0,%1     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      : "=&r" (t)
      : "r" (&a->n)
      : "cc", "memory"
   );

   return t;
}


ci_inline void ci_atomic_and (ci_atomic_t *a, int v)
{
	// Perform   a->n &= v

	int	t;

   __asm__ __volatile__(

      "1:     lwarx   %0,0,%3, 1     \n"
      "       and     %0,%2,%0    \n"
      "       stwcx.  %0,0,%3     \n"
      "       bne-    1b          \n"

      : "=&r" (t), "=m" (a->n)
      : "r" (v), "r" (&a->n), "m" (a->n)
      : "cc"

   );
}


ci_inline void ci_atomic_or (ci_atomic_t *a, int v)
{
	// Perform   a->n |= v

   int	t;

   __asm__ __volatile__(

     CI_SMP_SYNC

      "1:     lwarx   %0,0,%3, 1     \n"
      "       or      %0,%2,%0    \n"
      "       stwcx.  %0,0,%3     \n"
      "       bne-    1b          \n"

     CI_SMP_ISYNC

      : "=&r" (t), "=m" (a->n)
      : "r" (v), "r" (&a->n), "m" (a->n)
      : "cc"

   );
}


ci_inline void ci_atomic32_and (volatile ci_uint32 *a, int v)
{
	// Perform   a &= v

	int	t;

   __asm__ __volatile__(

     CI_SMP_SYNC

       "1:     lwarx   %0,0,%2, 1     \n"
       "       and     %0,%1,%0    \n"
       "       stwcx.  %0,0,%2     \n"
       "       bne-    1b          \n"

     CI_SMP_ISYNC

      : "=&r" (t)
      : "r" (v), "r" (a)
      : "cc", "memory"

   );
}


ci_inline void ci_atomic32_or (volatile ci_uint32 *a, int v)
{
	// Perform   a->n |= v

   int	t;

   __asm__ __volatile__(

      CI_SMP_SYNC

      "1:     lwarx   %0,0,%2, 1     \n"
      "       or      %0,%1,%0    \n"
      "       stwcx.  %0,0,%2     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      : "=&r" (t)
      : "r" (v), "r" (a)
      : "cc", "memory"
   );
}


ci_inline void ci_atomic32_add (volatile ci_uint32 *a, int v)
{
   int	t;
   __asm__ __volatile__(
      CI_SMP_SYNC

      "1:     lwarx   %0,0,%2, 1     \n"
      "       add     %0,%1,%0    \n"
      "       stwcx.  %0,0,%2     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      : "=&r" (t)
      : "r" (v), "r" (a)
      : "cc", "memory"
   );
}



ci_inline   int   ci_atomic_read (ci_atomic_t* a)           { return a->n; }

ci_inline   void 	ci_atomic_set  (ci_atomic_t* a, int v)
{
	// Perform   a->n = v

   int t;

   __asm__ __volatile__(

     CI_SMP_SYNC

      "1:     lwarx   %0,0,%2, 1     \n"
      "       stwcx.  %1,0,%2     \n"
      "       bne     1b          \n"

     CI_SMP_ISYNC

      : "=&r" (t)
      : "r" (v),"r" (&a->n)
     : "cc", "memory"
   );
}


#define ci_atomic_inc_and_test(a)  (ci_atomic_inc_ret(a) == 0)
#define ci_atomic_dec_and_test(a)  (ci_atomic_dec_ret(a) == 0)


/* Copied from ci_atomic_inc above to suit the function signature. */
ci_inline void ci_atomic32_inc(volatile ci_uint32* p)
{
  int	t;
  __asm__ __volatile__(

                       CI_SMP_SYNC

                       "1:     lwarx   %0,0,%2, 1     \n"
                       "       addic   %0,%0,1     \n"
                       "       stwcx.  %0,0,%2     \n"
                       "       bne-    1b          \n"
                       CI_SMP_ISYNC
                       : "=&r" (t), "=m" (*p)
                       : "r" (p), "m" (*p)
                       : "cc"
                       );
}

/* Copied from ci_atomic_dec above to suit the function signature. */
ci_inline void ci_atomic32_dec(volatile ci_uint32* p)
{
  int	t;
  __asm__ __volatile__(
                       CI_SMP_SYNC
                       "1:     lwarx     %0,0,%2, 1   \n"
                       "       addic     %0,%0,-1  \n"
                       "       stwcx.    %0,0,%2   \n"
                       "       bne-      1b        \n"
                       CI_SMP_ISYNC
                       : "=&r" (t), "=m" (*p)
                       : "r" (p), "m" (*p)
                       : "cc"

                       );
}

/* Copied from ci_atomic_dec_ret above to suit the function signature. */
ci_inline int ci_atomic32_dec_ret(volatile ci_uint32* p)
{
  int t;
  __asm__ __volatile__(
                       CI_SMP_SYNC
                       "1:     lwarx   %0,0,%1, 1     \n"
                       "       addic   %0,%0,-1    \n"
                       "       stwcx.  %0,0,%1     \n"
                       "       bne-    1b          \n"
                       CI_SMP_ISYNC
                       : "=&r" (t)
                       : "r" (p)
                       : "cc", "memory"
                       );
  return t;
}


#define ci_atomic32_dec_and_test(p)  (ci_atomic32_dec_ret(p) == 0)


/**********************************************************************
 *
 * Exchange
 *	See <asm/system.h> for atomic ppc32/64 specific 'xchg' function.
 *
 * ci_inline   int   ci_atomic_xchg (ci_atomic_t *a, int v)
 */

ci_inline  long ci_xchg_u32(volatile int *p,  long val)
{
   long prev;

   __asm__ __volatile__ (

      CI_SMP_SYNC

      "1:     lwarx   %0,0,%2, 1     \n"
      "       stwcx.  %3,0,%2     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      : "=&r" (prev), "=m" (*p)
      : "r" (p), "r" (val), "m" (p)
      : "cc", "memory"
   );

   return prev;
}

/* This is for uniformity with the x86 layer. Implemented as an inline function
 * rather than a macro for type-safety. */
ci_inline ci_uint32 ci_xchg32(volatile ci_uint32* p, ci_uint32 val)
{
  return (ci_uint32) ci_xchg_u32((volatile int*) p, val);
}

#ifdef __powerpc64__
ci_inline  long ci_xchg_u64(volatile long *p,  long val)
{
   long prev;

   __asm__ __volatile__ (

      CI_SMP_SYNC

      "1:     ldarx   %0,0,%3     \n"
      "       stdcx.  %2,0,%3     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      : "=&r" (prev), "=m" (*p)
      : "r" (val), "r" (p)
      : "cc", "memory"
   );

   return prev;
}
#endif


static inline  long __ci_xchg( volatile void *ptr,long x, int size)
{
   switch (size)
   {
      case 4:
      return  ci_xchg_u32(ptr, x);

#ifdef __powerpc64__
     /* xchg_u64 doesn't exist on 32-bit PPC */
      case 8:
      return  ci_xchg_u64(ptr, x);
#endif

   }
   return x;
}

#ifdef __powerpc64__
#define ci_xchg_uintptr(p, v) xchg((ci_uint64*) (p), v)
#else
#define ci_xchg_uintptr(p, v) xchg((ci_uint32*) (p), v)
#endif

/*  Define this macro ONLY if it is NOT a KERNEL build because <asm/system.h> defines it otherwise */
#if !defined(__KERNEL__) || defined(__oo_standalone__)
#define xchg(ptr,x) ((__typeof__(*(ptr))) __ci_xchg((ptr),(long)(x),sizeof(*(ptr))))
#endif

ci_inline 	int	ci_atomic_xchg (ci_atomic_t *a, int v)
{
  return xchg((int *)&a->n,v);
}


/**********************************************************************
 *
 * Compare and swap.
 *	See <asm/system.h> for atomic ppc32/64 specific 'cmpxchg' function.
 *
 * ci_inline int ci_cas32_succeed	(volatile ci_int32* p, ci_int32 oldval, ci_int32 newval)
 * ci_inline int ci_cas32_fail		(volatile ci_int32* p, ci_int32 oldval, ci_int32 newval)
 * ci_inline int ci_cas32u_succeed	(volatile ci_int32* p, ci_int32 oldval, ci_int32 newval)
 * ci_inline int ci_cas32u_fail		(volatile ci_int32* p, ci_int32 oldval, ci_int32 newval)
 *
 * ci_inline int ci_cas64_succeed	(volatile ci_int64* p, ci_int64 oldval, ci_int64 newval)
 * ci_inline int ci_cas64_fail		(volatile ci_int64* p, ci_int64 oldval, ci_int64 newval)
 * ci_inline int ci_cas64u_succeed	(volatile ci_int64* p, ci_int64 oldval, ci_int64 newval)
 * ci_inline int ci_cas64u_fail		(volatile ci_int64* p, ci_int64 oldval, ci_int64 newval)
 *
 * ci_cas_uintptr_succeed(p,o,n)    (macro)
 * ci_cas_uintptr_fail(p,o,n)       (macro)
 *
 */

#define CI_HAVE_COMPARE_AND_SWAP

 
ci_inline unsigned int ci_cas32u(volatile ci_uint32 *p, ci_uint32 old, ci_uint32 new)
{	/* This is actually a cmpxchg_u32 routine */
 unsigned int prev;

   __asm__ __volatile__ (

      CI_SMP_SYNC

      "1:     lwarx   %0,0,%2, 1     \n"	
      "       cmpw    0,%0,%3     \n"
      "       bne-    2f          \n"
      "       stwcx.  %4,0,%2     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      "2:                         \n"

      : "=&r" (prev), "=m" (*p)
      : "r" (p), "r" (old), "r" (new), "m" (*p)
      : "cc", "memory"
   );
   return prev;
}


/* Copied from ci_cas32u above to silence the compiler warnings about
   pointer signedness */
ci_inline int ci_cas32(volatile ci_int32 *p, ci_int32 old, ci_int32 new)
{	/* This is actually a cmpxchg_u32 routine */
  int prev;

   __asm__ __volatile__ (

      CI_SMP_SYNC

      "1:     lwarx   %0,0,%2, 1     \n"	
      "       cmpw    0,%0,%3     \n"
      "       bne-    2f          \n"
      "       stwcx.  %4,0,%2     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      "2:                         \n"

      : "=&r" (prev), "=m" (*p)
      : "r" (p), "r" (old), "r" (new), "m" (*p)
      : "cc", "memory"
   );
   return prev;
}


ci_inline int ci_cas32_succeed(volatile ci_int32* p, ci_int32 oldval, ci_int32 newval)
{ return ci_cas32(p, oldval, newval) == oldval; }

ci_inline int ci_cas32_fail(volatile ci_int32* p, ci_int32 oldval, ci_int32 newval)
{ return ci_cas32(p, oldval, newval) != oldval; }

ci_inline int ci_cas32u_succeed(volatile ci_uint32* p, ci_uint32 oldval, ci_uint32 newval)
{ return (int)(ci_cas32u(p, oldval, newval) == oldval); }

ci_inline int ci_cas32u_fail(volatile ci_uint32* p, ci_uint32 oldval, ci_uint32 newval)
{ return (int)(ci_cas32u(p, oldval, newval) != oldval); }


#ifdef __powerpc64__
ci_inline unsigned long ci_cas64(volatile ci_uint64 *p, ci_uint64 old, ci_uint64 new)
{	/* This is actually a cmpxchg_u64 routine */
 unsigned long prev;

   __asm__ __volatile__ (

      CI_SMP_SYNC

      "1:     ldarx   %0,0,%2     \n"	
      "       cmpd    0,%0,%3     \n"
      "       bne-    2f          \n"
      "       stdcx.  %4,0,%2     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      "2:                         \n"

      : "=&r" (prev), "=m" (*p)
      : "r" (p), "r" (old), "r" (new), "m" (*p)
      : "cc", "memory"
   );
   return prev;
}

ci_inline int ci_cas64_succeed(volatile ci_uint64* p, ci_uint64 oldval, ci_uint64 newval)
{ return (int)(ci_cas64(p, oldval, newval) == oldval); }

ci_inline int ci_cas64_fail(volatile ci_uint64* p, ci_uint64 oldval, ci_uint64 newval)
{ return (int)(ci_cas64(p, oldval, newval) != oldval); }

ci_inline int ci_cas64u_succeed(volatile ci_uint64* p, ci_uint64 oldval, ci_uint64 newval)
{ return (int)(ci_cas64(p, oldval, newval) == oldval); }

ci_inline int ci_cas64u_fail(volatile ci_uint64* p, ci_uint64 oldval, ci_uint64 newval)
{ return (int)(ci_cas64(p, oldval, newval) != oldval); }

# define ci_cas_uintptr_succeed(p,o,n)    ci_cas64u_succeed((volatile ci_uint64*) (p), (o), (n))
# define ci_cas_uintptr_fail(p,o,n)       ci_cas64u_fail((volatile ci_uint64*) (p), (o), (n))

#else		/* Assume a 32bit m/c so ... */

# define ci_cas_uintptr_succeed(p,o,n)    ci_cas32u_succeed((volatile ci_uint32*) (p), (o), (n))
# define ci_cas_uintptr_fail(p,o,n)       ci_cas32u_fail((volatile ci_uint32*) (p), (o), (n))

/* This is super-hackery but it seems to work well reliably.
 * The problem here is that GCC assumes 32-bit registers when passed -m32,
 * even when CPU is 64-bit (so its registers are in fact 64-bit even in 32-bit mode).
 * Therefore if a 64-bit value is passed to __asm__, GCC insist on putting it
 * into two consecutive registers (well, that's actually what PPC 32-bit ABI spec mandates).
 * So we pass 64-bit values as two 32-bit ones and use an auxiliary register to
 * build 64-bit values and use 64-bit atomic load/stores on them
 */

ci_inline ci_uint64 ci_cas64(volatile ci_uint64 *p, ci_uint64 old, ci_uint64 new)
{  
  register volatile ci_uint32 prev0;
  register volatile ci_uint32 prev1;
  register volatile ci_uint32 old0 = (ci_uint32)old;
  register volatile ci_uint32 old1 = (ci_uint32)(old >> 32);
  register volatile ci_uint32 new0 = (ci_uint32)new;
  register volatile ci_uint32 new1 = (ci_uint32)(new >> 32);

   __asm__ __volatile__ (


      "       mr 9, %4\n"
      "       insrdi 9, %5, 32, 0\n"
      "       mr 10, %6\n"
      "       insrdi 10, %7, 32, 0\n"
      CI_SMP_SYNC

      "1:     ldarx   %0,0,%3     \n"
      "       cmpd    0,%0,9     \n"
      "       bne-    2f          \n"
      "       stdcx.  10,0,%3     \n"
      "       bne-    1b          \n"

      CI_SMP_ISYNC

      "2:                         \n"
      "       sradi %1, %0, 32    \n"

      : "=&r" (prev0), "=r" (prev1), "=m" (*p)
      : "r" (p), "r" (old0), "r" (old1), "r" (new0), "r" (new1), "m" (*p)
      : "cc", "memory", "r9", "r10"
   );
   return ((ci_uint64)prev1 << 32) | prev0;
}

ci_inline int ci_cas64_succeed(volatile ci_uint64* p, ci_uint64 oldval, ci_uint64 newval)
{ return (int)(ci_cas64(p, oldval, newval) == oldval); }

ci_inline int ci_cas64_fail(volatile ci_uint64* p, ci_uint64 oldval, ci_uint64 newval)
{ return (int)(ci_cas64(p, oldval, newval) != oldval); }

ci_inline int ci_cas64u_succeed(volatile ci_uint64* p, ci_uint64 oldval, ci_uint64 newval)
{ return (int)(ci_cas64(p, oldval, newval) == oldval); }

ci_inline int ci_cas64u_fail(volatile ci_uint64* p, ci_uint64 oldval, ci_uint64 newval)
{ return (int)(ci_cas64(p, oldval, newval) != oldval); }


#endif


/**********************************************************************
 *
 * Atomic bit field ops.
 *
 * ci_inline   void ci_bit_set               (volatile ci_bits* b, int i);
 * ci_inline   void  ci_bit_clear            (volatile ci_bits* b, int i);
 * ci_inline   int   ci_bit_test             (volatile ci_bits* b, int i);
 * ci_inline   int   ci_bit_test_and_set     (volatile ci_bits* b, int i);
 * ci_inline   int   ci_bit_test_and_clear   (volatile ci_bits* b, int i);
 *
 */

#define ci_bit_mask_set(b,m)     ci_atomic32_or((b), (m))
#define ci_bit_mask_clear(b,m)   ci_atomic32_and((b), ~(m))

typedef ci_uint32  ci_bits;
#define CI_BITS_N			32u
#define CI_BITS_DECLARE(name, n)  ci_bits name[((n) + CI_BITS_N - 1u) / CI_BITS_N]


ci_inline void ci_bits_clear_all  (volatile ci_bits* b, int n_bits)
{
   memset ( (void*) b, 0, (n_bits+CI_BITS_N-1u) / CI_BITS_N * sizeof(ci_bits));
}


ci_inline void ci_bit_set(volatile ci_bits* b, int i)
{
	// Sets bit 'i' ( 0 - 31 ) in word addressed by 'b'

     ci_bits old;
     ci_bits mask = 1 << (i & 0x1f);
     ci_bits *p = ((ci_bits *)b) + (i >> 5);

   __asm__ __volatile__(

     CI_SMP_SYNC
      "1:     lwarx   %0,0,%3, 1     \n"
      "       or      %0,%0,%2    \n"
      "       stwcx.  %0,0,%3     \n"
      "       bne-    1b          \n"
     CI_SMP_ISYNC
      : "=&r" (old), "=m" (*p)
      : "r" (mask), "r" (p), "m" (*p)
      : "cc"
   );
}

ci_inline void ci_bit_clear(volatile ci_bits* b, int i)
{
	// Clears bit 'i' ( 0 - 31 ) in word addressed by 'b'

        ci_bits old;
        ci_bits mask = 1 << (i & 0x1f);
        ci_bits *p = ((ci_bits *)b) + (i >> 5);

   __asm__ __volatile__(
     CI_SMP_SYNC
      "1:      lwarx   %0,0,%3, 1    \n"
      "        andc    %0,%0,%2   \n"
      "        stwcx.  %0,0,%3    \n"
      "        bne-    1b         \n"
     CI_SMP_ISYNC
      : "=&r" (old), "=m" (*p)
      : "r" (mask), "r" (p), "m" (*p)
      : "cc"
   );
}

ci_inline int  ci_bit_test(volatile ci_bits* b, int i)
{
	// Returns state of bit 'i' ( 0 - 31 ) in word addressed by 'b'

   return ((b[i >> 5] >> (i & 0x1f)) & 1) != 0;
}


ci_inline int ci_bit_test_and_set(volatile ci_bits* b, int i)
{
	// Return old state of a bit 'i' and set it in word addressed by 'b'

        ci_bits old, t;
        ci_bits mask = 1 << (i & 0x1f);
        volatile ci_bits *p = ((volatile ci_bits *)b) + (i >> 5);

   __asm__ __volatile__(

      CI_SMP_SYNC

       "1:      lwarx   %0,0,%4, 1   \n"
       "        or      %1,%0,%3  \n"
       "        stwcx.  %1,0,%4   \n"
       "        bne     1b        \n"

      CI_SMP_ISYNC

       : "=&r" (old), "=&r" (t), "=m" (*p)
       : "r" (mask), "r" (p), "m" (*p)
       : "cc", "memory"
   );
   return (old & mask) != 0;
}

ci_inline int ci_bit_test_and_clear(volatile ci_bits* b, int i)
{
	// Return old state of a bit 'i' and clear it in word addressed by 'b'

        ci_bits old, t;
        ci_bits mask = 1 << (i & 0x1f);
        volatile ci_bits *p = ((volatile ci_bits *)b) + (i >> 5);

   __asm__ __volatile__(

      CI_SMP_SYNC

       "1:      lwarx   %0,0,%4, 1   \n"
       "        andc    %1,%0,%3  \n"
       "        stwcx.  %1,0,%4   \n"
       "        bne     1b        \n"

      CI_SMP_ISYNC

       : "=&r" (old), "=&r" (t), "=m" (*p)
       : "r" (mask), "r" (p), "m" (*p)
       : "cc", "memory"
   );
   return (old & mask) != 0;
}



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


extern int ci_glibc_uses_nptl (void) CI_HF;
extern int ci_glibc_nptl_broken(void) CI_HF;
extern int ci_glibc_gs_get_is_multihreaded_offset (void) CI_HF;
extern int ci_glibc_gs_is_multihreaded_offset CI_HV;

#ifdef __GNUC__
/* Returns non-zero if the calling process might be mulithreaded, returns 0 if
 * it definitely isn't (i.e. if reimplementing this function for other
 * architectures and platforms, you can safely just return 1).
 */
static inline int ci_is_multithreaded (void)
{
	/*
	 * To investigate properly on ppc-linux how
	 * to determine this when time permits!!! 
	 */
	 
	return 1;	
}

static inline void ci_prefetch_ppc(const void *x)
{
	__asm__ __volatile__ ("dcbt 0,%0" : : "r" (x));
}

#else
#define ci_prefetch_ppc(addr)  do{}while(0)
#endif   /* def __GNUC__ */

#define ci_prefetch ci_prefetch_ppc

#define ci_spinloop_pause()      do{}while(0)


static inline void ci_clflush(volatile void* addr)
{
	__asm__("dcbf 0,%0" : : "r" (addr));
}


#define CI_HAVE_ADDC32
#define ci_add_carry32(sum, v)            \
  do {                                    \
    ci_uint64 temp;                       \
    temp=(((ci_uint64)sum)+v);            \
    sum=(unsigned int)(temp+(temp>>32));  \
  } while(0)


#endif  /* __CI_TOOLS_GCC_PPC_H__ */
/*! \codoxg_end */
