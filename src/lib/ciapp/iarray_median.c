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


void ci_iarray_median(const int* start, const int* end, int* median_out)
{
  ci_iarray_assert_valid(start, end);
  ci_assert(end - start > 0);
  ci_iarray_assert_sorted(start, end);

  if( (end - start) & 1 )
    *median_out = start[(end - start) / 2];
  else
    *median_out = (start[(end-start)/2] + start[(end-start)/2-1]) / 2;
}

/*! \cidoxg_end */
