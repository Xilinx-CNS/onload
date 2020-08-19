/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  slp
**  \brief  A buddy allocator.
**   \date  2002/08/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_BUDDY_H__
#define __CI_TOOLS_BUDDY_H__


/*! Comment? */
typedef struct {
  ci_dllist*   free_lists;
  ci_dllink*   links;
  ci_uint8*    orders;
  unsigned     order;           /*!< total size == (1 << order) */
  /* ?? Consider recording largest available order + for each order the
  ** smallest available order that is big enough.
  */
} ci_buddy_allocator;


/*! Buddy ctor2 */
extern int  ci_buddy_ctor2(ci_buddy_allocator* buddy, unsigned order,
			   void* (*alloc_fn)(size_t), void (*free_fn)(void*));
/*! Buddy dtor2 */
extern void ci_buddy_dtor2(ci_buddy_allocator* buddy,
			   void (*free_fn)(void*));

/*! Buddy ctor */
ci_inline int ci_buddy_ctor(ci_buddy_allocator* buddy, unsigned order)
{ return ci_buddy_ctor2(buddy, order, ci_alloc_fn, ci_free); }

/*! Buddy dtor */
ci_inline void ci_buddy_dtor(ci_buddy_allocator* buddy)
{ ci_buddy_dtor2(buddy, ci_free); }

/*! Allocate buddy */
extern int  ci_buddy_alloc(ci_buddy_allocator*, unsigned order);
/*! free buddy */
extern void ci_buddy_free(ci_buddy_allocator*, unsigned addr, unsigned order);

  /*! Returns total size of managed space. */
ci_inline unsigned long ci_buddy_size(ci_buddy_allocator* b)
{ return ci_pow2(b->order); }

  /*! Returns log2(total size of managed space). */
ci_inline unsigned ci_buddy_log2_size(ci_buddy_allocator* b)
{ return b->order; }

void ci_buddy_reserve(ci_buddy_allocator *b, unsigned addr, unsigned size);

#if CI_INCLUDE_ASSERT_VALID
  extern void ci_buddy_assert_valid(ci_buddy_allocator*);
#else
# define ci_buddy_assert_valid(ba)
#endif


#endif  /* __CI_TOOLS_BUDDY_H__ */

/*! \cidoxg_end */
