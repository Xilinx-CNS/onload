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


void ci_iarray_mode(const int* start, const int* end, int* mode_out)
{
  int current_v, mode, current_n, mode_n;
  const int* i;

  ci_iarray_assert_valid(start, end);
  ci_assert(end - start > 0);
  ci_assert(mode_out);

  current_v = mode = *start;
  current_n = mode_n = 1;

  for( i = start + 1; i != end; ++i ) {
    if( *i != current_v ) {
      if( current_n > mode_n ) {
	mode_n = current_n;
	mode = current_v;
      }
      current_v = *i;
      current_n = 0;
    }
    ++current_n;
  }
  if( current_n > mode_n ) {
    mode_n = current_n;
    mode = current_v;
  }

  *mode_out = mode;
}

/*! \cidoxg_end */
