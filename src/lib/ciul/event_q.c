/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Event queues.
**   \date  2003/03/04
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_ef */
#include <etherfabric/vi.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"


int ef_eventq_wait(ef_vi* evq, ef_driver_handle fd,
		   unsigned current_ptr, const struct timeval* timeout)
{
  /* Should we consider using absolute timeouts instead of relative ones?
  ** Or if we use relative ones, should we reduce [timeout] on return to
  ** indicate how long we waited?  (Like what select() does).
  **
  ** Also consider making [timeout] be non-optional.  Can always have an
  ** inline ciul_eventq_wait_forever() function for those that don't want
  ** to supply one.
  */
  ci_resource_op_t  op;

  op.op = CI_RSOP_EVENTQ_WAIT;
  op.id = efch_make_resource_id(evq->vi_resource_id);
  if( timeout ){
    op.u.evq_wait.timeout.tv_sec = timeout->tv_sec;
    op.u.evq_wait.timeout.tv_usec = timeout->tv_usec;
  }
  else {
    op.u.evq_wait.timeout.tv_sec = 0;
    op.u.evq_wait.timeout.tv_usec = 0;
  }
  op.u.evq_wait.current_ptr = current_ptr;
  /* This is a bit limiting, but the only callers of this function are tests
   * and disused code, so we can live with it only being able to use NIC 0. 
   * If that changes we can easily add a parameter to ef_eventq_wait */
  op.u.evq_wait.nic_index = CI_DEFAULT_NIC;

  LOGVVV(ef_log("ef_eventq_wait: current_ptr=%x next_i=%u",
		(unsigned) current_ptr,
		(unsigned) ((current_ptr & evq->evq_mask) / 8)));

  return ci_resource_op(fd, &op);
}

/*! \cidoxg_end */
