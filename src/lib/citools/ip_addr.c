/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
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
 
#include <ci/tools.h>
#include "citools_internal.h"


int ci_format_ip4_addr(char* buf, int len, unsigned addr_be32)
{
  const unsigned char* p;
  p = (const unsigned char*) &addr_be32;

  ci_assert(buf);

  return ci_scnprintf(buf, len, "%u.%u.%u.%u",
		 (unsigned) p[0], (unsigned) p[1],
		 (unsigned) p[2], (unsigned) p[3]);
}

/*! \cidoxg_end */
