/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  adp
**  \brief  Simple memory access checker.
**   \date  2004/07/21
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_citools */

#include <ci/tools/memchk.h>
#include "citools_internal.h"


/*
 * set this to 1 in order to cause an assert statement to be 
 * executed rather than return values of 0 on failure in the 
 * ci_memreadcheck and ci_memwritecheck functions.
 */
#define CI_MEMCHK_ASSERT_ON_FAIL 0


typedef struct extent_t {
  long start;
  long length;
  long mask;

  struct extent_t * next;
  struct extent_t * prev;
} extent;


extent * extent_list_head = NULL;

/*
 * Check whether e2 is a subset of e1, i.e.
 *
 * e1  |------|     |------|     |------|    |------|
 * e2  |--|           |--|           |--|    |------|
 *
 * Returns nonzero if e2 is a subset of e1.
 */
int ci_extent_subset(long start1, long len1, long start2, long len2)
{
  return (start2 >= start1 &&
	  start2 + len2 <= start1 + len1);
}

extent * ci_make_extent(long start, long length, long mask)
{
  extent *e = (extent *) ci_alloc(sizeof(extent));
  if (e != NULL) {
    memset((void *)e, 0, sizeof(extent));
    e->start = start;
    e->length = length;
    e->mask = mask;
  }

  return e;
}

void ci_list_addextent(extent *e)
{
  if (extent_list_head == NULL) {
    /* empty list case - insert as head: */
    extent_list_head = e;
  }
  else {
    /* non-empty list case - insert into correct place according to
     * start value
     *
     * Find the node that should be before the one that is to be 
     * inserted:
     */
    extent * listptr = extent_list_head;
    while (listptr->start < e->start && 
	   listptr->next != NULL)
      listptr = listptr->next;

    /* 
     * we can't have two extents starting at the same location -
     * how do we identify them for deletion??
     */
    ci_assert(listptr->start != e->start);

    /* mechanics of adding to the list */
    if (listptr->next) {
      listptr->next->prev = e;
      e->next = listptr->next;
    }
    e->prev = listptr;
    listptr->next = e;
  }
}


/*
 * Interface implementation
 */

/*
 * Adds an extent to the list
 *
 * start -> start of the extent
 * length -> length of the extent
 * mask -> associated data
 *
 * Returns 0 if fail, 1 if extent added successfully.
 */
int ci_extent_add(long start, long length, long mask)
{
  extent *e = ci_make_extent(start, length, mask);
  if (e != NULL) {
    ci_list_addextent(e);
    return 1;
  }
  else
    return 0;
}

/*
 * Removes an extent from the list
 *
 * start -> the start address of an extent
 * mask -> associated data
 *
 * Returns 0 if extent did not exist, 1 if the extent was removed.
 */
int ci_extent_remove(long start, long mask)
{
  extent *listptr;

  /* if empty list bail out */
  if (!extent_list_head)
    return 0;

  listptr = extent_list_head;

  while (listptr) {
    if (listptr->start == start && listptr->mask == mask) {
      /* we've found the one to remove: */
      if (listptr->next) {
	listptr->next->prev = listptr->prev;
      }
      if (listptr->prev) {
	listptr->prev->next = listptr->next;
      }
      if (listptr == extent_list_head) {
	extent_list_head = listptr->next;
      }
    
      ci_free(listptr);
      return 1;
    }

    listptr = listptr->next;
  }

  return 0;
}

/*
 * Checks if an extent passed is covered in the list of extents
 *
 * start -> Start of extent to be checked
 * length -> Length of extent to be checker
 * minmask -> Minimum set of bits that should be present in the mask field
 *   of the satisfying extent.
 *
 * Returns 0 no single extent is a subset of the extent passed, otherwise
 * non-zero to indicate a match found whose mask field is bitwise at least
 * minmask.
 */
int ci_extent_check(long start, long length, long minmask)
{
  extent * list_ptr = extent_list_head;

  while (list_ptr && list_ptr->start <= start) {
    if (ci_extent_subset(list_ptr->start, list_ptr->length,
		      start, length) &&
	(list_ptr->mask & minmask) == minmask) {
      /* we've found one that will do us */
      return 1;
    }
   
    list_ptr = list_ptr->next;
  }

  /* falls through if none found... */
  return 0;
}


/********
 * Memory check interface: implementation
 */


/*
 * Register a piece of memory with the checker
 *
 * p -> the start address of the memory
 * len -> the length in bytes of the memory
 * mask -> whether we can read or write from/to the memory
 *
 * Non-zero if no problems occurred (can generally ignore the
 * return value).
 */
int ci_memregister(void* p, long len, long mask)
{
  return ci_extent_add( (long)p, len, 0x3 );
}

/*
 * Unregister a piece of memory from the checker
 *
 * p -> the start address of the memory
 * len -> the length of the buffer (as passed before)
 *
 * Non-zero if no problems occurred (can generally ignore the
 * return value).
 */
int ci_memunregister(void* p, long mask)
{
  return ci_extent_remove( (long)p, mask );
}

/*
 * Checks that we are okay to read a range of memory.
 * This function DOES NOT check for reads across two extents.
 * 
 * p -> the start address of the memory
 * len -> the length of the buffer
 *
 * Non-zero if we are okay to read the memory, 0 otherwise.
 */
int ci_memreadcheck(void *p, long len)
{
#if CI_MEMCHK_ASSERT_ON_FAIL
  ci_assert( ci_extent_check( (long)p, len, CI_EXT_READ ));
  return 1;
#else
  return ci_extent_check( (long)p, len, CI_EXT_READ );
#endif
}

/* 
 * Checks that we are okay to write to a range of memroy.
 * This function DOES NOT check for writes across two extents.
 *
 * p -> the start address of the memory
 * len -> the length of the buffer
 *
 * None-zero if we are okay to write the memory, 0 otherwise.
 */
int ci_memwritecheck(void *p, long len)
{
#if CI_MEMCHK_ASSERT_ON_FAIL
  ci_assert( ci_extent_check( (long)p, len, CI_EXT_WRITE ));
  return 1;
#else
  return ci_extent_check( (long)p, len, CI_EXT_WRITE );
#endif
}

/*! \cidoxg_end */
