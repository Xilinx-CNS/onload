/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
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
 
#ifndef __INTERNAL_H__
#define __INTERNAL_H__


#include <ci/tools.h>
#include <ci/tools/internal.h>


extern const char* ci_log_prefix  CI_HF;

/* Some I/O functions can be configured to emit compile-time warnings if
 * the result is ignored. Use this for low-level logging functions when there
 * is nothing useful to be done if the output fails or is incomplete. */
static inline void ci_log_ignore_result(int rc) {(void)rc;}


#endif  /* __INTERNAL_H__ */

/*! \cidoxg_end */
