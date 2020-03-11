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


#if CI_INCLUDE_ASSERT_VALID
void ci_iarray_assert_valid(const int* start, const int* end)
{
  ci_assert(start);
  ci_assert(end);
  ci_assert((((char*) end - (char*) start) & (sizeof(*start) - 1)) == 0);
}


void ci_iarray_assert_sorted(const int* start, const int* end)
{
  while( start + 1 != end )
    ci_assert(start[0] <= start[1]);
}
#endif

/*! \cidoxg_end */
