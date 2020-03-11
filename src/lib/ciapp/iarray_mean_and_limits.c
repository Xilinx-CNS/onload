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


void ci_iarray_mean_and_limits(const int* start, const int* end,
				int* mean_out, int* min_out, int* max_out)
{
  int min, max;
  ci_int64 sum;
  const int* i;

  ci_iarray_assert_valid(start, end);
  ci_assert(end - start > 0);

  sum = 0;
  min = max = *start;

  for( i = start; i != end; ++i ) {
    if( *i < min )  min = *i;
    else
    if( *i > max )  max = *i;
    sum += *i;
  }

  if( mean_out )  *mean_out = (int) (sum / (end - start));
  if( min_out  )  *min_out  = min;
  if( max_out  )  *max_out  = max;
}

/*! \cidoxg_end */
