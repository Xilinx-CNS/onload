/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  slp
**  \brief  Code to ensure the CPU has all the features required by this build.
**   \date  2003/08/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_CPU_FEATURES_H__
#define __CI_TOOLS_CPU_FEATURES_H__

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
#elif defined(__x86_64__)
ci_inline void
get_cpuid(int op, int *eax, int *ebx, int *ecx, int *edx)
{
  __asm__ __volatile__ ("cpuid\n\t"
                        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                        : "a" (op));
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

#endif  /* __CI_TOOLS_CPU_FEATURES_H__ */

/*! \cidoxg_end */
