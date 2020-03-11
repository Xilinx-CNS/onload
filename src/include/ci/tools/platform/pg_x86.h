/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

/*! \cidoxg_include_ci_tools_platform  */

#ifndef __CI_TOOLS_PG_X86_H__
#define __CI_TOOLS_PG_X86_H__


/**********************************************************************
 * Atomic integer.
 */

/* Minimal hack to compile stuff. */
typedef volatile ci_int32 ci_atomic_t;
#define ci_atomic_read(p)  (*(p))



#endif  /* __CI_TOOLS_PG_X86_H__ */

/*! \cidoxg_end */
