/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_citools */

#include "citools_internal.h"


/* Test that procesor specific instructions setup during the build match the
   CPU we're running on */

#ifdef DO
#undef DO
#endif

#ifdef IGNORE
#undef IGNORE
#endif

#define DO(x) x
#define IGNORE(x)

#define DEBUG IGNORE


/*****************************************************************************
 *
 * X86 specific code 
 *
 *****************************************************************************/

#if defined(__i386__)

#if defined(__GNUC__)
ci_inline void 
get_cpuid(int op, int *eax, int *ebx, int *ecx, int *edx)
{
  /* NB. We have to save [ebx] when building position indepent code. */
  __asm__ __volatile__ ("pushl %%ebx; cpuid; mov %%ebx, %0; popl %%ebx"
			: "=r" (*ebx), "=a" (*eax), "=c" (*ecx), "=d" (*edx)
			: "a" (op));
}
#endif

int ci_cpu_features_check(int verbose)
{	

  int eax, ebx, ecx, edx;
  int SSE, SSE2;

  get_cpuid(0, &eax, &ebx, &ecx, &edx);
  DEBUG(ci_log("0: eax %08x ebx %08x ecx %08x edx %08x", eax, ebx, ecx, edx));


  if (verbose) 
    ci_log("%c%c%c%c%c%c%c%c%c%c%c%c", 
	  ((char*)&ebx)[0],((char*)&ebx)[1],((char*)&ebx)[2],((char*)&ebx)[3],
	  ((char*)&edx)[0],((char*)&edx)[1],((char*)&edx)[2],((char*)&edx)[3],
	  ((char*)&ecx)[0],((char*)&ecx)[1],((char*)&ecx)[2],((char*)&ecx)[3]);

  if (eax < 1) {
    ci_log("Error: minimum input value for cpuid too low");
    ci_log("Probably something bad happened");
    return CI_CPU_OLD;
  }

  /* ?? do we even want to think about older processors */
  get_cpuid(1, &eax, &ebx, &ecx, &edx);

  DEBUG(ci_log("1: eax %08x ebx %08x ecx %08x edx %08x", eax, ebx, ecx, edx));

  if (verbose) {
    ci_log("Processor type: %x Family %x Model %x Stepping ID %x",
	   (eax & 0x3000) >> 12,
	   (eax & 0xf00)  >> 8,
	   (eax & 0xf0)   >> 4,
	   (eax & 0xf)    >> 0);
    ci_log("Features (edx): %x", edx);
  }

  /* First check that SSE extensions are available if we compiled them in 
     these are needed for the ci_iob() code which is defined in 
     gcc_x86.h and friends
  */
  SSE = (edx & 0x02000000);
  SSE2 = (edx & 0x04000000);

  /* flags in gcc_x86.h to indicate SSE extensions */

#if CI_CPU_HAS_SSE2 && ! CI_CPU_HAS_SSE
  if (verbose)
    ci_log("Error: SSE2 extensions built, but SSE not defined!  Dumb.");
#endif

#if CI_CPU_HAS_SSE2
  if (!SSE2) {
    if (verbose) {
      ci_log("Error: SSE2 extensions built but not implemented on this CPU");
      ci_log("Illegal instructions will be encountered");
    }
    return CI_CPU_ERROR;
  }
#else
  if (SSE2) {
    if (verbose) {
      ci_log("Warning: SSE2 extensions implemented on this CPU but not built");
      ci_log("Performance may be impacted");
    }
    return CI_CPU_WARNING;
  }
#endif

#if CI_CPU_HAS_SSE
  if (!SSE) {
    if (verbose) {
      ci_log("Error: SSE extensions built but not implemented on this CPU");
      ci_log("Illegal instructions will be encountered");
    }
    return CI_CPU_ERROR;
  }
#else
  if (SSE) {
    if (verbose) {
      ci_log("Warning: SSE extensions implemented on this CPU but not built");
      ci_log("Performance may be impacted");
    }
    return CI_CPU_WARNING;
  }
#endif

  DEBUG(ci_log("SSE extension test: passed"));
  return CI_CPU_OK;
}

#elif defined(__x86_64__)

ci_inline void
get_cpuid(int op, int *eax, int *ebx, int *ecx, int *edx)
{
  __asm__ __volatile__ ("cpuid\n\t"
                        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                        : "a" (op));
}

#else

/*****************************************************************************
 *
 * Other processor specific code
 *
 *****************************************************************************/

extern int ci_cpu_features_check(int verbose)
{	
  return CI_CPU_OK;
}

#endif

int ci_cpu_has_feature(char* feature)
{
#if defined(__x86_64__) || defined(__i386__)
  int eax, ebx, ecx, edx;

  /* Leaf 1 = CPUID feature bits */
  get_cpuid(1, &eax, &ebx, &ecx, &edx);

  if( ! strcmp(feature, "pclmul") )
    return ecx & 0x00000002;
#endif

  /* Not supported on platforms that don't implement the CPUID instruction */
  return 0;
}

/*! \cidoxg_end */
