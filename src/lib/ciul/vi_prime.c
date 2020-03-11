/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  Akhi Singhania <asinghania@solarflare.com>
**  \brief  FD priming support
**   \date  2014/05/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include "ef_vi_internal.h"
#include "driver_access.h"


int ef_vi_prime(ef_vi* vi, ef_driver_handle dh, unsigned current_ptr)
{
  ci_resource_prime_op_t  op;
  op.crp_id = efch_make_resource_id(vi->vi_resource_id);
  op.crp_current_ptr = current_ptr;
  return ci_resource_prime(dh, &op);
}
