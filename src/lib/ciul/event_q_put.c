/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  ef_eventq_put()
**   \date  2004/05/20
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ef */
#include "ef_vi_internal.h"
#include "driver_access.h"
#include <etherfabric/vi.h>


int ef_eventq_put(unsigned evq_id, ef_driver_handle fd, unsigned ev)
{
  ci_resource_op_t  op;
  int64_t ev64;

  EF_VI_BUG_ON((ev & EF_EVENT_SW_DATA_MASK) != ev);
  ev64 = ev;

  op.op = CI_RSOP_EVENTQ_PUT;
  op.id = efch_make_resource_id(evq_id);
  op.u.evq_put.ev = cpu_to_le64(ev64);
  return ci_resource_op(fd, &op);
}
