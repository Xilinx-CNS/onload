/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2019 Xilinx, Inc. */
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
#ifndef __CI_TOOLS_CRC32C_H__
#define __CI_TOOLS_CRC32C_H__

extern ci_uint32 ci_crc32c_partial(const ci_uint8 *buf, ci_uint32 buflen,
                                   ci_uint32 crc);

extern ci_uint32 ci_crc32c_partial_copy(ci_uint8 *dest, const ci_uint8 *buf,
                                        ci_uint32 buflen, ci_uint32 crc);

ci_inline ci_uint32 ci_crc32c(const ci_uint8 *buf, ci_uint32 buflen)
{
  return ~ci_crc32c_partial(buf, buflen, 0xffffffff);
}

#endif  /* __CI_TOOLS_CRC32C_H__ */
/*! \cidoxg_end */
