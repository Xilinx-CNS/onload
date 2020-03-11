/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  ok_sasha
**  \brief  Debug macros for the onload driver and efthrm library
**     $Id$
**   \date  2007/07
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_resource  */

#ifndef __ONLOAD_DEBUG_H__
#define __ONLOAD_DEBUG_H__

#include <ci/compat.h>

extern int oo_debug_bits;


/*--------------------------------------------------------------------
 *
 * dynamic code inclusion macros
 *
 *--------------------------------------------------------------------*/

#define __OO_DEBUGERR__	        0x00000001    /* errors (we don't want 
                                                 customers to see)      */
#define __OO_DEBUGVM__		0x00000002    /* virtual memory mapping */
#define __OO_DEBUGSHM__		0x00000004    /* shared kernel/userspace
                                                 memory                 */
#define __OO_DEBUGASYNC__	0x00000008    /* asyncronyous calls (poll) */
#define __OO_DEBUGRES__		0x00000010    /* resource management    */
#define __OO_DEBUGVERB__	0x00000020    /* gratuitous / verbose   */
#define __OO_DEBUGMEMSIZE__	0x00000040    /* size of shared memory  */
#define __OO_DEBUGTRAMP__       0x00000080    /* trampoline and mmap()  */
#define __OO_DEBUGARP__         0x00000100    /* ARP related messages   */
#define __OO_DEBUGOS__          0x00000400    /* OS related messages  
                                                 i.e. NDIS interaction  */
#define __OO_DEBUGIPP__         0x00001000    /* IP Protocols (ICMP...) */
#define __OO_DEBUGSTATS__       0x00002000    /* IP Statistics gathering*/
#define __OO_DEBUGDLF__		0x00004000    /* Driverlink filter	*/
#define __OO_DEBUGIPF__		0x00008000    /* IP filters	        */
#define __OO_DEBUGTCPH__	0x00010000    /* TCP helper (closedown 
                                                 for now - may remove)  */
#define __OO_DEBUGBONDING__	0x00020000    /* Bonding */
#define __OO_DEBUGLOAD__        0x00040000    /* load/unload messages   */
#define __OO_DEBUGSIGNAL__      0x00080000    /* Signal interception */
#define __OO_DEBUGCPLANE__      0x00100000    /* Control plane */

/* Note: we cannot use 0x80000000 as a debug flag, since we use
 * MODULE_PARM to parse arguments, and this expects a 32 bit signed
 * number.
 */

#define __OO_DEBUGALL__		0x7fffffff


/* Same as OO_DYNAMIC_DEBUG but included in NDEBUG builds. */
#define OO_DYNAMIC_LOG(bits, foo)                       \
  do{ if( oo_debug_bits & (bits) )  { foo; } }while(0)

#ifdef NDEBUG
# define OO_DYNAMIC_DEBUG(bits, foo)
#else
# define OO_DYNAMIC_DEBUG(bits, foo)  OO_DYNAMIC_LOG((bits), foo)
#endif


#define OO_DEBUG_ERR(foo)     OO_DYNAMIC_LOG(__OO_DEBUGERR__, foo)
#define OO_DEBUG_VM(foo)      OO_DYNAMIC_DEBUG(__OO_DEBUGVM__, foo)
#define OO_DEBUG_SHM(foo)     OO_DYNAMIC_DEBUG(__OO_DEBUGSHM__, foo)
#define OO_DEBUG_ASYNC(foo)   OO_DYNAMIC_DEBUG(__OO_DEBUGASYNC__, foo)
#define OO_DEBUG_RES(foo)     OO_DYNAMIC_DEBUG(__OO_DEBUGRES__, foo)
#define OO_DEBUG_VERB(foo)    OO_DYNAMIC_DEBUG(__OO_DEBUGVERB__, foo)
#define OO_DEBUG_MEMSIZE(foo) OO_DYNAMIC_DEBUG(__OO_DEBUGMEMSIZE__, foo)
#define OO_DEBUG_TRAMP(foo)   OO_DYNAMIC_DEBUG(__OO_DEBUGTRAMP__, foo)
#define OO_DEBUG_ARP(foo)     OO_DYNAMIC_DEBUG(__OO_DEBUGARP__, foo)
#define OO_DEBUG_OS(foo)      OO_DYNAMIC_DEBUG(__OO_DEBUGOS__, foo)
#define OO_DEBUG_IPP(foo)     OO_DYNAMIC_DEBUG(__OO_DEBUGIPP__, foo)
#define OO_DEBUG_STATS(foo)   OO_DYNAMIC_DEBUG(__OO_DEBUGSTATS__, foo)
#define OO_DEBUG_DLF(foo)     OO_DYNAMIC_DEBUG(__OO_DEBUGDLF__, foo)
#define OO_DEBUG_IPF(foo)     OO_DYNAMIC_DEBUG(__OO_DEBUGIPF__, foo)
#define OO_DEBUG_TCPH(foo)    OO_DYNAMIC_DEBUG(__OO_DEBUGTCPH__, foo)
#define OO_DEBUG_BONDING(foo) OO_DYNAMIC_DEBUG(__OO_DEBUGBONDING__, foo)
#define OO_DEBUG_LOAD(foo)    OO_DYNAMIC_LOG(__OO_DEBUGLOAD__, foo)
#define OO_DEBUG_SIGNAL(foo)  OO_DYNAMIC_DEBUG(__OO_DEBUGSIGNAL__, foo)
#define OO_DEBUG_CPLANE(foo)  OO_DYNAMIC_DEBUG(__OO_DEBUGCPLANE__, foo)


/* Also used to enable conditional test code for error provocation */ 
#ifdef NDEBUG
# define OO_DYNAMIC_CODE(bits, foo)
#else
extern int oo_debug_code_level;
# define OO_DYNAMIC_CODE(bits, foo)                             \
  do{ if( oo_debug_code_level & (bits) )  { foo; } }while(0)
#endif


#endif /* __ONLOAD_DEBUG_H__ */
/*! \cidoxg_end */
