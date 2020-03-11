/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>


/**********************************************************************
 * ci_ctimer_calibrate()
 */

void ci_ctimer_calibrate(ci_ctimer_inf* i)
{
  int n = 20;
  ci_int64 min = 1000;
  ci_ctimer t;
  i->overhead = 0;

  while( n-- ) {
    ci_ctimer_start_accurate(&t);
    ci_ctimer_stop_accurate(i, &t);

    if( i == 0 || ci_ctimer_cycles(&t) < min )
      min = ci_ctimer_cycles(&t);
  }

  i->overhead = min;
}


/**********************************************************************
 * ci_ctimer_init()
 */

int ci_ctimer_init(ci_ctimer_inf* i)
{
  int rc;
  unsigned khz;

  rc = ci_get_cpu_khz(&khz);
  if( rc < 0 )  return rc;

  i->hz = (ci_int64) khz * 1000u;
  ci_ctimer_calibrate(i);

  return 0;	
}

/*! \cidoxg_end */
