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

/* It is perhaps possible to limit the size of the struct as the set of
 * possible values is far smaller than sizeof(int). I don't expect this
 * really has much/any benefit over this more explicit approach though. */
typedef struct ci_cpu_feature_s {
  int eax;
  int ecx;
  int output_register;
  int output_bitmask;
} ci_cpu_feature_t;

#define CI_CPU_FEATURE_REGISTER_EAX 0
#define CI_CPU_FEATURE_REGISTER_EBX 1
#define CI_CPU_FEATURE_REGISTER_ECX 2
#define CI_CPU_FEATURE_REGISTER_EDX 3
#define CI_CPU_FEATURE_REGISTER_COUNT 4

#define CI_CPU_FEATURE(eax_val, ecx_val, reg, bit) \
  ((ci_cpu_feature_t) { \
    .eax = eax_val, \
    .ecx = ecx_val, \
    .output_register = CI_CPU_FEATURE_REGISTER_##reg, \
    .output_bitmask = 1 << bit \
  })

#define CI_CPU_FEATURE_PCLMULQDQ CI_CPU_FEATURE(1, 0, ECX, 1)
#define CI_CPU_FEATURE_MOVDIR64B CI_CPU_FEATURE(7, 0, ECX, 28)

#if defined(__i386__)
#if defined(__GNUC__)
ci_inline void
get_cpuid(int in_eax, int in_ecx, int *eax, int *ebx, int *ecx, int *edx)
{
  /* NB. We have to save [ebx] when building position indepent code. */
  __asm__ __volatile__ ("pushl %%ebx; cpuid; mov %%ebx, %0; popl %%ebx"
			: "=r" (*ebx), "=a" (*eax), "=c" (*ecx), "=d" (*edx)
			: "a" (in_eax), "c" (in_ecx));
}
#endif
#elif defined(__x86_64__)
ci_inline void
get_cpuid(int in_eax, int in_ecx, int *eax, int *ebx, int *ecx, int *edx)
{
  __asm__ __volatile__ ("cpuid\n\t"
                        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                        : "a" (in_eax), "c" (in_ecx));
}
#endif

ci_inline int ci_cpu_has_feature(ci_cpu_feature_t feature)
{
#if defined(__x86_64__) || defined(__i386__)
  static int max_feature_request = -1;
  int registers[CI_CPU_FEATURE_REGISTER_COUNT];

  /* This doesn't currently support extended feature queries, for which the MSB
   * is set, though that has a separate maximum which needs checking. */
  if(CI_UNLIKELY( max_feature_request == -1 )) {
    get_cpuid(0, 0,
              &registers[CI_CPU_FEATURE_REGISTER_EAX],
              &registers[CI_CPU_FEATURE_REGISTER_EBX],
              &registers[CI_CPU_FEATURE_REGISTER_ECX],
              &registers[CI_CPU_FEATURE_REGISTER_EDX]);
    max_feature_request = registers[CI_CPU_FEATURE_REGISTER_EAX];
  }

  if( feature.eax > max_feature_request )
    return 0;

  get_cpuid(feature.eax, feature.ecx,
            &registers[CI_CPU_FEATURE_REGISTER_EAX],
            &registers[CI_CPU_FEATURE_REGISTER_EBX],
            &registers[CI_CPU_FEATURE_REGISTER_ECX],
            &registers[CI_CPU_FEATURE_REGISTER_EDX]);

  return (registers[feature.output_register] & feature.output_bitmask) ==
         feature.output_bitmask;
#else
  /* Not supported on platforms that don't implement the CPUID instruction */
  return 0;
#endif
}

#endif  /* __CI_TOOLS_CPU_FEATURES_H__ */

/*! \cidoxg_end */
