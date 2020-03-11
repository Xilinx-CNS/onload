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

/*! \cidoxg_include_ci_driver_platform  */

#ifndef __CI_DRIVER_PLATFORM_UL_COMMON_H__
#define __CI_DRIVER_PLATFORM_UL_COMMON_H__


/*--------------------------------------------------------------------
 *
 * PCI configuration helpers
 *
 *--------------------------------------------------------------------*/

#define  PCI_BASE_ADDRESS_SPACE	0x01	/* 0 = memory, 1 = I/O */
#define  PCI_BASE_ADDRESS_SPACE_IO 0x01
#define  PCI_BASE_ADDRESS_SPACE_MEMORY 0x00
#ifndef PCI_BASE_ADDRESS_MEM_MASK /* may be defined in linux/pci_regs.h */
#define  PCI_BASE_ADDRESS_MEM_MASK	(~0x0fUL)
#endif


/*--------------------------------------------------------------------
 *
 * udelay - stalls execution for up to 50us
 *
 *--------------------------------------------------------------------*/



#endif  /* __CI_DRIVER_PLATFORM_UL_COMMON_H__ */

/*! \cidoxg_end */
