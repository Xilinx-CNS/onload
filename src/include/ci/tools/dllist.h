/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_DLLIST_H__
#define __CI_TOOLS_DLLIST_H__

typedef struct ci_dllink_s {
  struct ci_dllink_s*  prev;
  struct ci_dllink_s*  next;
} ci_dllink;


typedef struct {
  ci_dllink  l;
} ci_dllist;

/**********************************************************************/

#define CI_DLLINK_INITIALISER(prev, next)  { (prev), (next) }
#define CI_DLLIST_INITIALISER(name)  { { &(name).l, &(name).l } }

#define CI_DLLIST_DECLARE(name)      \
  ci_dllist name = CI_DLLIST_INITIALISER(name)

#define CI_DLLIST_LINK_ASSERT_VALID(l)			\
  do{							\
    ci_assert_equal((((l)->prev))->next, l);            \
    ci_assert_equal((((l)->next))->prev, l);            \
  }while(0)

ci_inline void ci_dllist_init(ci_dllist* list)
{ list->l.prev = list->l.next = &list->l; }


ci_inline int ci_dllist_is_empty(ci_dllist* list)
{ return list->l.next == &list->l; }

ci_inline int ci_dllist_not_empty(ci_dllist* list)
{ return list->l.next != &list->l; }


ci_inline void ci_dllist_insert_after(ci_dllink* before, ci_dllink* after) {
  CI_DLLIST_LINK_ASSERT_VALID(before);
  after->next = before->next;
  after->prev = before;
  before->next->prev = after;
  before->next = after;
}

ci_inline void ci_dllist_insert_before(ci_dllink* after, ci_dllink* insert) {
  CI_DLLIST_LINK_ASSERT_VALID(after);
  insert->next = after;
  insert->prev = after->prev;
  after->prev->next = insert;
  after->prev = insert;
}

ci_inline void ci_dllist_remove(ci_dllink* link) {
  CI_DLLIST_LINK_ASSERT_VALID(link);
  link->prev->next = link->next;
  link->next->prev = link->prev;
}

  /*! Removes and links to self (to further removes are okay). */
ci_inline void ci_dllist_remove_safe(ci_dllink* link) {
  CI_DLLIST_LINK_ASSERT_VALID(link);
  link->prev->next = link->next;
  link->next->prev = link->prev;
  link->next = link->prev = link;
}


ci_inline ci_dllink* ci_dllist_head(ci_dllist* list)
{ return list->l.next; }

ci_inline ci_dllink* ci_dllist_tail(ci_dllist* list)
{ return list->l.prev; }


ci_inline int ci_dllist_is_head(ci_dllist* list, ci_dllink* link)
{ return link == list->l.next; }

ci_inline int ci_dllist_is_tail(ci_dllist* list, ci_dllink* link)
{ return link == list->l.prev; }

ci_inline int ci_dllist_is_anchor(ci_dllist* list, ci_dllink* link)
{ return link == &list->l; }


ci_inline void ci_dllist_push(ci_dllist* list, ci_dllink* link) {
  CI_DLLIST_LINK_ASSERT_VALID(&list->l);
  link->next = list->l.next;
  link->prev = &list->l;
  list->l.next = link->next->prev = link;
}

ci_inline void ci_dllist_push_tail(ci_dllist* list,ci_dllink*link){
  CI_DLLIST_LINK_ASSERT_VALID(&list->l);
  link->next = &list->l;
  link->prev = list->l.prev;
  list->l.prev = link->prev->next = link;
}


ci_inline ci_dllink* ci_dllist_pop(ci_dllist* list) {
  ci_dllink* l;
  l = list->l.next;
  ci_dllist_remove(l);
  return l;
}

ci_inline ci_dllink* ci_dllist_pop_tail(ci_dllist* list) {
  ci_dllink* l;
  l = list->l.prev;
  ci_dllist_remove(l);
  return l;
}


ci_inline ci_dllink* ci_dllist_try_pop(ci_dllist* list)
{ return ci_dllist_is_empty(list) ? 0 : ci_dllist_pop(list); }

ci_inline ci_dllink* ci_dllist_try_pop_tail(ci_dllist* list)
{ return ci_dllist_is_empty(list) ? 0 : ci_dllist_pop_tail(list); }


#define ci_dllist_put       ci_dllist_push_tail
#define ci_dllist_put_back  ci_dllist_push
#define ci_dllist_get       ci_dllist_pop
#define ci_dllist_try_get   ci_dllist_try_pop


ci_inline void ci_dllist_rehome(ci_dllist* to, ci_dllist* from) {
  if( ci_dllist_is_empty(from) ) {
    ci_dllist_init(to);
  }
  else {
    to->l.next = from->l.next;
    to->l.prev = from->l.prev;
    to->l.next->prev = to->l.prev->next = &to->l;
    ci_dllist_init(from);
  }
}

ci_inline void ci_dllist_join(ci_dllist* list, ci_dllist* from) {
  if ( ci_dllist_not_empty(from) ) {
    list->l.prev->next = from->l.next;
    from->l.next->prev = list->l.prev;
    list->l.prev = from->l.prev;
    from->l.prev->next = &list->l;
    ci_dllist_init(from);
  }
}

/**********************************************************************/

ci_inline ci_dllink* ci_dllist_start(ci_dllist* list)
{ return list->l.next; }

ci_inline ci_dllink* ci_dllist_last(ci_dllist* list)
{ return list->l.prev; }

ci_inline ci_dllink* ci_dllist_end(ci_dllist* list)
{ return &list->l; }

#define ci_dllist_iter(l)  ((l) = (l)->next)

/* The following macros implement a for(...) loop that iterates over the
** members of the list.  If the loop completes, then the iterator [p_lnk]
** or [p_c] is set to null.
*/
#define CI_DLLIST_FOR_EACH(p_lnk, p_list)		\
  for( (p_lnk) = ci_dllist_start(p_list);			\
       ((p_lnk) != ci_dllist_end(p_list)) || ((p_lnk) = 0,0);	\
       ci_dllist_iter(p_lnk) )

#define CI_DLLIST_FOR_EACH2(c_type, p_c, lnk_mbr, list)			\
  for( (p_c) = CI_CONTAINER(c_type, lnk_mbr, ci_dllist_start(list));	\
       (&((p_c)->lnk_mbr) != ci_dllist_end(list)) || ((p_c) = 0,0);	\
       (p_c) = CI_CONTAINER(c_type, lnk_mbr, ((p_c)->lnk_mbr).next) )

#define CI_DLLIST_FOR_EACH_REV2(c_type, p_c, lnk_mbr, list)             \
  for( (p_c) = CI_CONTAINER(c_type, lnk_mbr, ci_dllist_last(list));     \
       (&((p_c)->lnk_mbr) != ci_dllist_end(list)) || ((p_c) = 0,0);     \
       (p_c) = CI_CONTAINER(c_type, lnk_mbr, ((p_c)->lnk_mbr).prev) )

/* Identical to CI_DLLIST_FOR_EACH(_REV)2 but a temporary of c_type is supplied
** Precalculates the next/previous entry so that the current entry can be
** trashed/removed
*/
#define CI_DLLIST_FOR_EACH3(c_type, p_c, lnk_mbr, list, temp_next)	      \
  for( (p_c) = CI_CONTAINER(c_type, lnk_mbr, ci_dllist_start(list));	      \
       ( temp_next=CI_CONTAINER(c_type, lnk_mbr, ((p_c)->lnk_mbr).next) ) &&  \
	       ((&((p_c)->lnk_mbr) != ci_dllist_end(list)) || ((p_c) = 0,0)); \
       (p_c) = temp_next )

#define CI_DLLIST_FOR_EACH_REV3(c_type, p_c, lnk_mbr, list, temp_prev)	      \
  for( (p_c) = CI_CONTAINER(c_type, lnk_mbr, ci_dllist_last(list));	      \
       ( temp_prev=CI_CONTAINER(c_type, lnk_mbr, ((p_c)->lnk_mbr).prev) ) &&  \
	       ((&((p_c)->lnk_mbr) != ci_dllist_end(list)) || ((p_c) = 0,0)); \
       (p_c) = temp_prev )


/* Identical to CI_DLLIST_FOR_EACH but a temporary is supplied
** Precalculates the next entry so that the current entry can be
** trashed/removed
*/
#define CI_DLLIST_FOR_EACH4(p_lnk, p_list, temp_next)           \
  for( ((p_lnk) = ci_dllist_start(p_list),                      \
        (temp_next) = (p_lnk), ci_dllist_iter(temp_next));      \
       ((p_lnk) != ci_dllist_end(p_list)) || ((p_lnk) = 0,0);	\
       ((p_lnk) = (temp_next), ci_dllist_iter(temp_next)) )


ci_inline int ci_dllist_count(ci_dllist* list) {
  ci_dllink* l;  
  int count = 0;
  CI_DLLIST_FOR_EACH(l, list)
    ++count;
  return count;
}

ci_inline int ci_dllist_is_member(ci_dllist* list, ci_dllink* link) {
  ci_dllink* l;
  CI_DLLIST_FOR_EACH(l, list)
    if( l == link )
      return 1;
  return 0;
}


/**********************************************************************/

  /*! After doing this you can do ci_dllist_remove() on the link, even
  ** though it is not a member of a list.  This can be useful to avoid a
  ** conditional when adding an object to a list, when the object may or
  ** may not already be a member of the list.
  */
ci_inline void ci_dllink_self_link(ci_dllink* link)
{ link->next = link->prev = link; }

ci_inline int  ci_dllink_is_self_linked(ci_dllink* link)
{ return link == link->next; }

ci_inline void ci_dllink_mark_free(ci_dllink* link)
{ link->next = 0; }

ci_inline int ci_dllink_is_free(ci_dllink* link)
{ return link->next == 0; }


#if CI_INCLUDE_ASSERT_VALID
  extern void ci_dllist_assert_valid(ci_dllist*);
#else
# define ci_dllist_assert_valid(l)
#endif


#endif  /* __CI_TOOLS_DLLIST_H__ */

/*! \cidoxg_end */
