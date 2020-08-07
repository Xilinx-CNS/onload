/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  IP ID allocation - values used in kernel & in UL
**   \date  2004/09/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal */

#ifndef __CI_INTERNAL_IPID_H__
#define __CI_INTERNAL_IPID_H__

/* In many cases, ipid=0 is a bad idea.  So, we avoid the first block */
# define CI_IPID_MIN 0x0400
# define CI_IPID_MAX 0xffff

/* MUST be a power of 2 */
#define CI_IPID_BLOCK_LENGTH 1024
/* must be the right number for shifts for CI_IPID_BLOCK_LENGTH */
#define CI_IPID_BLOCK_SHIFT  10

#define CI_IPID_BLOCK_MASK   (CI_IPID_BLOCK_LENGTH-1)
#define CI_IPID_BLOCK_COUNT                                             \
  (((CI_IPID_MAX+1)/CI_IPID_BLOCK_LENGTH) - (CI_IPID_MIN/CI_IPID_BLOCK_LENGTH))

#define CI_IP6ID_BLOCK_MASK 0x3ffffff

#endif

/*! \cidoxg_end */
