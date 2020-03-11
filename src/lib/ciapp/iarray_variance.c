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


void ci_iarray_variance(const int* start, const int* end,
			 int mean, ci_int64* variance_out)
{
  ci_int64 sumsq, diff;
  const int* i;

  ci_iarray_assert_valid(start, end);
  ci_assert(end - start > 0);
  ci_assert(variance_out);

  if( end - start < 2 ) {
    *variance_out = 0;
    return;
  }

  sumsq = 0;

  for( i = start; i != end; ++i ) {
    diff = *i - mean;
    sumsq += diff * diff;
  }

  *variance_out = sumsq / (end - start - 1);
}

/*! \cidoxg_end */
