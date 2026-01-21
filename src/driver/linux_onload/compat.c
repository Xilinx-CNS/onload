/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  slp
**  \brief  Linux-specific functions used in common code
**     $Id$
**   \date  2002/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux_onload */
 
/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include <onload/fd_private.h>
#include <ci/internal/ip.h>
#include <onload/linux_onload_internal.h>
#include <onload/tcp_helper.h>


#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
/* See ci/tools/memleak_debug.h */
struct ci_alloc_entry *ci_alloc_table[CI_ALLOC_TABLE_BULKS];
unsigned int ci_alloc_table_sz = 0;
EXPORT_SYMBOL(ci_alloc_table_add);
EXPORT_SYMBOL(ci_alloc_table_del);
#endif /* CI_MEMLEAK_DEBUG_ALLOC_TABLE */


/*! \cidoxg_end */
