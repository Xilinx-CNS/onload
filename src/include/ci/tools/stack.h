/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Trivial but efficient stack.
**   \date  2003/06/30
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_STACK_H__
#define __CI_TOOLS_STACK_H__

/*
** [s] is a pointer to a data structure that should have at least the
** following members (or similar):
**
**   struct int_stack {
**     elem_t*  stack_base;
**     elem_t*  stack_top;
**     elem_t*  stack_ptr;
**   };
*/

#define ci_stack_valid(s)  ((s) && (s)->stack_base &&			\
			    (s)->stack_top && (s)->stack_ptr &&		\
			    (s)->stack_ptr >= (s)->stack_base &&	\
			    (s)->stack_ptr <= (s)->stack_top)

#define ci_stack_init(s, p, capacity)		\
  do{ (s)->stack_base = (s)->stack_ptr = (p);	\
      (s)->stack_top = (p) + (capacity);	\
  }while(0)

#define ci_stack_ctor(s, capacity, prc)					      \
  do{									      \
    (s)->stack_base=ci_alloc((capacity)*sizeof((s)->stack_ptr[0])); \
    *prc = -ENOMEM;							      \
    if( (s)->stack_base ) {						      \
      *prc = 0;								      \
      ci_stack_init((s), (s)->stack_base, (capacity));			      \
    }									      \
  }while(0)

#define ci_stack_dtor(s)						 \
  do{ ci_assert(ci_stack_valid(s));  ci_free((s)->stack_base); }while(0)

#define ci_stack_is_empty(s)	((s)->stack_ptr == (s)->stack_base)
#define ci_stack_not_empty(s)	((s)->stack_ptr != (s)->stack_base)
#define ci_stack_is_full(s)	((s)->stack_ptr == (s)->stack_top)
#define ci_stack_not_full(s)	((s)->stack_ptr != (s)->stack_top)
#define ci_stack_num(s)		((s)->stack_ptr - (s)->stack_base)
#define ci_stack_space(s)	((s)->stack_top - (s)->stack_ptr)
#define ci_stack_capacity(s)	((s)->stack_top - (s)->stack_base)

#define ci_stack_push(s, v)	(*(s)->stack_ptr++ = (v))
#define ci_stack_pop(s)		(*--(s)->stack_ptr)

#define ci_stack_peek(s)	((s)->stack_ptr[-1])
#define ci_stack_peek_i(s,i)	((s)->stack_ptr[-1 - (i)])
#define ci_stack_poke(s)	(*(s)->stack_ptr)


#endif  /* __CI_TOOLS_STACK_H__ */

/*! \cidoxg_end */
