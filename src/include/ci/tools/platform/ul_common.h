/* SPDX-License-Identifier: GPL-2.0 */
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

/*! \cidoxg_include_ci_tools_platform  */

#ifndef __CI_TOOLS_PLATFORM_UL_COMMON_H__
#define __CI_TOOLS_PLATFORM_UL_COMMON_H__


/**********************************************************************
 * Memory allocation
 */
#define ci_alloc                           malloc
#define ci_atomic_alloc                    malloc
#define ci_calloc                          calloc
#define ci_realloc(ptr, oldsize, newsize)  realloc((ptr), (newsize))

#define ci_vmalloc                         malloc
#define ci_vmalloc_fn                      malloc     
#define ci_vfree                           free

#define ci_sprintf                         sprintf
#define ci_snprintf                        snprintf
#define ci_vsprintf                        vsprintf
#define ci_vsnprintf                       vsnprintf
#define ci_sscanf                          sscanf

ci_inline int
ci_vscnprintf(char* buf, size_t size, const char* fmt, va_list args)
{
  int n = ci_vsnprintf(buf, size, fmt, args);
  return n < size ? n : size - 1;
}

ci_inline int
ci_scnprintf(char* buf, size_t size, const char* fmt, ...)
{
  int n;
  va_list args;
  va_start(args, fmt);
  n = ci_vscnprintf(buf, size, fmt, args);
  va_end(args);
  return n;
}

/* ensure ci_alloc_fn and ci_free have the correct definitions so we can safely 
** pass around as function pointers. Without this, Windows user-level driver
** gets clashes of calling convention 
*/
ci_inline void *
ci_alloc_fn (size_t size)
{
  return malloc(size);
}

ci_inline void 
ci_free(void * p)
{
  free(p);
}


/*--------------------------------------------------------------------
 *
 * in_interrupt and in_atomic macros .. well portable code shouldn't
 * be using it, and definitely not for anything other than picking
 * which memory alloc routine to use
 *
 *--------------------------------------------------------------------*/

#define ci_in_interrupt() 0
#define ci_in_atomic() 0
#define ci_in_irq() 0


#endif  /* __CI_TOOLS_PLATFORM_UL_COMMON_H__ */
/*! \cidoxg_end */
