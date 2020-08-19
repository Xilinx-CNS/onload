/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
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

#ifndef __CI_TOOLS_STACKS_H__
#define __CI_TOOLS_STACKS_H__


/*! Comment? */
typedef struct {
  int*  stack_base;
  int*  stack_top;
  int*  stack_ptr;
} ci_int_stack_t;

typedef ci_int_stack_t ci_int_stack;


/*! Comment? */
typedef struct {
  void**  stack_base;
  void**  stack_top;
  void**  stack_ptr;
} ci_ptr_stack_t;

typedef ci_ptr_stack_t ci_ptr_stack;


#endif  /* __CI_TOOLS_STACKS_H__ */

/*! \cidoxg_end */
