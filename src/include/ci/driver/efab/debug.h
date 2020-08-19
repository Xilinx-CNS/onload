/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  ok_sasha
**  \brief  Debug macros for the resource library. Should not be used 
**          outside of the resource driver!
**     $Id$
**   \date  2007/07
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_resource  */

#ifndef __CI_DRIVER_RESOURCE_DEBUG_H__
#define __CI_DRIVER_RESOURCE_DEBUG_H__

#include <ci/compat.h>
#include <ci/tools/log.h> /* to get ci_fail */

extern int ci_driver_debug_bits;


/*--------------------------------------------------------------------
 *
 * dynamic code inclusion macros
 *
 *--------------------------------------------------------------------*/

#define __CI_DEBUGERR__	        0x00000001    /* errors (we don't want 
                                                 customers to see)  */
#define __CI_DEBUGVM__		0x00000002    /* virtual memory mapping */
#define __CI_DEBUGNIC__		0x00000004    /* NIC operation 		*/
#define __CI_DEBUGWQ__		0x00000008    /* workqueue */
#define __CI_DEBUGRES__		0x00000010    /* resource management    */
#define __CI_DEBUGVERB__	0x00000020    /* gratuitous / verbose   */
#define __CI_DEBUGDMA__		0x00000040    /* DMA 			*/
#define __CI_DEBUGEVENT__	0x00000080    /* Events			*/
#define __CI_DEBUGMAC__		0x00000100    /* Mac 			*/
#define __CI_DEBUGVIRM__	0x00000100    /* vi_ resource 		*/
#define __CI_DEBUGIPF__		0x00400000    /* IP filters	        */

#define __CI_DEBUGLOAD__        0x40000000    /* load/unload messages   */

/* Note: we cannot use 0x80000000 as a debug flag, since we use
 * MODULE_PARM to parse arguments, and this expects a 32 bit signed
 * number.
 */

#define __CI_DEBUGALL__		0x7fffffff


#ifdef NDEBUG
# define CI_DYNAMIC_DRIVER_DEBUG( bits , str )
#else
# define CI_DYNAMIC_DRIVER_DEBUG( bits , str )  \
  do { if ( CI_UNLIKELY(ci_driver_debug_bits & (bits)) ) { str; } } while(0)
#endif

/* same as dynamic debug but also works in NDEBUG builds */
# define CI_DYNAMIC_DRIVER_LOG( bits , str )    \
  do { if ( CI_UNLIKELY(ci_driver_debug_bits & (bits)) ) { str; } } while(0)


#define DEBUGERR( str ) CI_DYNAMIC_DRIVER_DEBUG( __CI_DEBUGERR__, str)
#define DEBUGVM( str )  CI_DYNAMIC_DRIVER_DEBUG(__CI_DEBUGVM__, str)
#define DEBUGNIC( str ) CI_DYNAMIC_DRIVER_DEBUG(__CI_DEBUGNIC__, str)
#define DEBUGWQ( str ) CI_DYNAMIC_DRIVER_DEBUG(__CI_DEBUGWQ__, str)
#define DEBUGRES( str ) CI_DYNAMIC_DRIVER_DEBUG( __CI_DEBUGRES__, str)
#define DEBUGVERB( str ) CI_DYNAMIC_DRIVER_DEBUG( __CI_DEBUGVERB__, str)
#define DEBUGDMA( str ) CI_DYNAMIC_DRIVER_DEBUG( __CI_DEBUGDMA__, str)
#define DEBUGEVENT( str ) CI_DYNAMIC_DRIVER_DEBUG( __CI_DEBUGEVENT__, str)
#define DEBUGMAC( str ) CI_DYNAMIC_DRIVER_DEBUG( __CI_DEBUGMAC__, str)
#define DEBUGIPF( str ) CI_DYNAMIC_DRIVER_DEBUG( __CI_DEBUGIPF__, str)
#define DEBUGVIRM( str ) CI_DYNAMIC_DRIVER_DEBUG( __CI_DEBUGVIRM__, str)
#define DEBUGLOAD( str ) CI_DYNAMIC_DRIVER_LOG( __CI_DEBUGLOAD__, str)


#endif /* __CI_DRIVER_RESOURCE_DEBUG_H__ */
/*! \cidoxg_end */
