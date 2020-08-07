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
 
#include "citools_internal.h"


int ci_format_eth_addr(char* buf, const void* eth_mac_addr, char sep)
{
  const unsigned char* p;
  p = (const unsigned char*) eth_mac_addr;

  ci_assert(buf);
  ci_assert(eth_mac_addr);

  if( sep == 0 )  sep = ':';

  return ci_sprintf(buf, "%02X%c%02X%c%02X%c%02X%c%02X%c%02X",
		 (unsigned) p[0], sep, (unsigned) p[1], sep, 
		 (unsigned) p[2], sep, (unsigned) p[3], sep,
		 (unsigned) p[4], sep, (unsigned) p[5]);
}

/*! \cidoxg_end */
