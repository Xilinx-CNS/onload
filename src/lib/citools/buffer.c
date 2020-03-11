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

/*! \cidoxg_lib_citools */

#include "citools_internal.h"


#if CI_INCLUDE_ASSERT_VALID
void ci_buffer_assert_valid(ci_buffer* b)
{
  ci_assert(b);
  ci_assert(b->ptr <= b->end);
}
#endif

/*! \cidoxg_end */
