/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2019 Xilinx, Inc. */
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

/*! \cidoxg_include_ci_compat  */

#ifndef __CI_COMPAT_GCC_AARCH64_H__
#define __CI_COMPAT_GCC_AARCH64_H__

/* ARM64 TODO review these */

/*
   Barriers to enforce ordering with respect to:
   normal memory use: ci_wmb, ci_rmb, ci_wmb
*/

#define ci_mb()    __asm__ __volatile__ ("dsb sy" : : : "memory")
#define ci_wmb()   __asm__ __volatile__ ("dsb st" : : : "memory")
#define ci_rmb()   __asm__ __volatile__ ("dsb ld" : : : "memory")

/* Really these should be in  src/include/ci/driver/platform/... */
typedef unsigned long ci_phys_addr_t;
#define ci_phys_addr_fmt  "%lx"


#endif  /* __CI_COMPAT_GCC_AARCH64_H__ */

/*! \cidoxg_end */
