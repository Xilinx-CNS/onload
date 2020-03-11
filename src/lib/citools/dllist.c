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
void ci_dllist_assert_valid(ci_dllist* list)
{
  ci_dllink* l;

  ci_assert(list);
  ci_assert(list->l.next);
  ci_assert(list->l.prev);

  for( l = list->l.next; l != &list->l; l = l->next ) {
    ci_assert(l);
    ci_assert(l->prev);
  }
}
#endif

/*! \cidoxg_end */
