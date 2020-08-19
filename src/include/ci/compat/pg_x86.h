/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
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

#ifndef __CI_COMPAT_PG_X86_H__
#define __CI_COMPAT_PG_X86_H__


#define CI_HAVE_INT64
typedef unsigned long long    ci_uint64;
typedef long long             ci_int64;

#define CI_PRId64             "lld"
#define CI_PRIi64             "lli"
#define CI_PRIo64             "llo"
#define CI_PRIu64             "llu"
#define CI_PRIx64             "llx"
#define CI_PRIX64             "llX"

/* ?? need some assembler here */

#define ci_mb()   /*??*/

#define ci_wmb()  /* x86 processors store in-order */
#define ci_rmb()  ci_mb()

/* ?? double check sfence and mfence */


#endif  /* __CI_COMPAT_PG_X86_H__ */

/*! \cidoxg_end */
