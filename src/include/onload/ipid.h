/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  Efab IP ID allocation mechanism
**   \date  2004/09/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_IPID_H__
#define __CI_DRIVER_EFAB_IPID_H__

#include <ci/tools/sysdep.h>
#include <ci/tools/spinlock.h>
#include <ci/internal/ipid.h>  /* symbols shared with UL */

/*! IP ID control structure - precisely one exists in each 
 * TCP Helper Resource Manager struct */
typedef struct {
  ci_irqlock_t lock;				/*! table-wide lock */
  ci_uint8 range[ CI_IPID_BLOCK_COUNT ];	/*!< in-use flag */
#ifndef NDEBUG
  int init;
# define EFAB_IPID_INIT 0x7706EE9B
#endif
  int last_block_used;
} efab_ipid_cb_t;

ci_inline void
efab_ipid_ctor( efab_ipid_cb_t* ipid )
{
  ci_assert(ipid);
  ci_irqlock_ctor( &ipid->lock );
  memset( ipid->range, 0, sizeof( ipid->range ));
  ipid->last_block_used = 0;
#ifndef NDEBUG
  ipid->init = EFAB_IPID_INIT;
#endif
}

ci_inline void
efab_ipid_dtor( efab_ipid_cb_t* ipid )
{
  ci_assert(ipid);
  ci_assert( ipid->init == EFAB_IPID_INIT );
  ci_irqlock_dtor( &ipid->lock );
#ifndef NDEBUG
  ipid->init = 0;
#endif
}

#endif


/*! \cidoxg_end */
