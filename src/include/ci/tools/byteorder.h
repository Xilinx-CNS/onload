/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Byte-swapping etc.
**   \date  2008/05/19
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */
#ifndef __CI_TOOLS_BYTEORDER_H__
#define __CI_TOOLS_BYTEORDER_H__


/* CI_BSWAP_xx()  -- Byte-swap at runtime.  Argument must be in appropriate
 *                   domain.
 *
 * CI_BSWAPM_xx() -- Byte-swap at runtime.  Argument need not be in
 *                   appropriate domain -- high bits are truncated.
 *
 * CI_BSWAPC_xx() -- Byte-swap constants at compile-time. There used to exist
 *                   platforms on which this could be optimised better,
 *                   however all such usage is now deprecated.
 */

/* Swap runtime values. */
#define CI_BSWAP_16(v)    ci_bswap16((ci_uint16) (v))
#define CI_BSWAP_32(v)    ci_bswap32((ci_uint32) (v))
#define CI_BSWAP_64(v)    ci_bswap64(v)

#if (CI_MY_BYTE_ORDER == CI_LITTLE_ENDIAN)
# define CI_BSWAP_LE16(v)    (v)
# define CI_BSWAP_LE32(v)    (v)
# define CI_BSWAP_LE64(v)    (v)
# define CI_BSWAP_BE16(v)    CI_BSWAP_16(v)
# define CI_BSWAP_BE32(v)    CI_BSWAP_32(v)
# define CI_BSWAP_BE64(v)    CI_BSWAP_64(v)
# define CI_BSWAPM_LE16(v)   ((ci_uint16) (v))
# define CI_BSWAPM_LE32(v)   ((ci_uint32) (v))
# define CI_BSWAPM_BE16(v)   CI_BSWAP_16(v)
# define CI_BSWAPM_BE32(v)   CI_BSWAP_32(v)
# define CI_BSWAPC_BE16(v)   ci_bswapc16(v)
# define CI_BSWAPC_LE16(v)   (v)
#elif (CI_MY_BYTE_ORDER == CI_BIG_ENDIAN)
# define CI_BSWAP_BE16(v)    (v)
# define CI_BSWAP_BE32(v)    (v)
# define CI_BSWAP_BE64(v)    (v)
# define CI_BSWAP_LE16(v)    CI_BSWAP_16(v)
# define CI_BSWAP_LE32(v)    CI_BSWAP_32(v)
# define CI_BSWAP_LE64(v)    CI_BSWAP_64(v)
# define CI_BSWAPM_BE16(v)   ((ci_uint16) (v))
# define CI_BSWAPM_BE32(v)   ((ci_uint32) (v))
# define CI_BSWAPM_LE16(v)   CI_BSWAP_16(v)
# define CI_BSWAPM_LE32(v)   CI_BSWAP_32(v)
# define CI_BSWAPC_LE16(v)   ci_bswapc16(v)
# define CI_BSWAPC_BE16(v)   (v)
#else
# error Bad endian.
#endif

#define CI_BSWAPC_BE32   CI_BSWAP_BE32
#define CI_BSWAPC_LE32   CI_BSWAP_LE32
#define CI_BSWAPC_BE64   CI_BSWAP_BE64
#define CI_BSWAPC_LE64   CI_BSWAP_LE64

#endif  /* __CI_TOOLS_BYTEORDER_H__ */
/*! \cidoxg_end */
