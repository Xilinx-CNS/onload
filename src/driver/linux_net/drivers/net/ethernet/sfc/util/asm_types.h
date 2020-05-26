/**************************************************************************/
/*!  \file  asm_types.h
** \author  bwh
**  \brief  Wrapper for <asm/types.h>
**   \date  2008/12/11
**    \cop  Copyright 2008 Solarflare Communications Inc.
*//************************************************************************/

#ifndef SFUTILS_ASM_TYPES_H

#include <asm/types.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
/* Some kernel headers wrongly used the in-kernel type names for user API. */
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
#endif

#endif /* !SFUTILS_ASM_TYPES_H */
