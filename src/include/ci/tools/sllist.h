/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  Linked list.
**   \date  2002/08/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_SLLIST_H__
#define __CI_TOOLS_SLLIST_H__

#include <ci/compat/sysdep.h>

typedef struct ci_sllink_s {
  struct ci_sllink_s*  next;
} ci_sllink;


typedef struct {
  ci_sllink*  head;
} ci_sllist;

/**********************************************************************/

ci_inline int ci_sllink_busy(ci_sllink* link)
{ return link->next != NULL; }

/* It is needed to make ci_sllink_busy() works correctly if this link is
 * the last in the list.  We use even number here, so it can't accidentaly
 * match with any valid value, because all valid values are aligned.
 */
#define CI_SLLIST_TAIL ((ci_sllink*)(ci_uintptr_t)0xdeaddead)

ci_inline void ci_sllist_init(ci_sllist* list)
{ list->head = CI_SLLIST_TAIL; }


ci_inline int ci_sllist_is_empty(ci_sllist* list)
{ return list->head == CI_SLLIST_TAIL; }

ci_inline int ci_sllist_not_empty(ci_sllist* list)
{ return list->head != CI_SLLIST_TAIL; }


ci_inline void ci_sllist_push(ci_sllist* list, ci_sllink* link) {
  link->next = list->head;
  list->head = link;
}


ci_inline ci_sllink* ci_sllist_pop(ci_sllist* list) {
  ci_sllink* link;
  link = list->head;
  list->head = link->next;
  link->next = NULL;
  return link;
}


ci_inline ci_sllink* ci_sllist_try_pop(ci_sllist* list) {
  ci_sllink* link;
  link = list->head;
  if( link == CI_SLLIST_TAIL )
    return NULL;
  list->head = link->next;
  link->next = NULL; /* not busy any more */
  return link;
}

#define CI_SLLIST_TRY_POP(c_type, lnk_mbr, list)			  \
  ((list)->head ? CI_CONTAINER(c_type, lnk_mbr, ci_sllist_pop(list)) : NULL)


ci_inline void ci_sllist_insert_after(ci_sllink* before, ci_sllink* after) {
  after->next = before->next;
  before->next = after;
}

/**********************************************************************/

/*
** The following two macros implement a for(...) loop that iterates over
** the members of the list.  If the loop completes, then the iterator
** [p_lnk] or [p_c] is set to null.
*/

#define CI_SLLIST_FOR_EACH(p_lnk, p_list)				 \
  for( (p_lnk) = (p_list)->head; (p_lnk) != 0; (p_lnk) = (p_lnk)->next )

#define CI_SLLIST_FOR_EACH2(c_type, p_c, lnk_mbr, p_list)		\
  for( (p_c) = (p_list)->head ?						\
	 CI_CONTAINER(c_type, lnk_mbr, (p_list)->head) : 0;		\
       (p_c) != 0;							\
       (p_c) = ((p_c)->lnk_mbr).next ?					\
	 CI_CONTAINER(c_type, lnk_mbr, ((p_c)->lnk_mbr).next) : 0 )


#endif  /* __CI_TOOLS_SLLIST_H__ */
/*! \cidoxg_end */
