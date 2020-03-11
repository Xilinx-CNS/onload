/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  PCI defines
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver  */

#ifndef __CI_PCI_H
#define __CI_PCI_H

/*
 * Under PCI, each device has 256 bytes of configuration address space,
 * of which the first 64 bytes are standardized as follows:
 */
#define CI_PCI_VENDOR_ID          0x00    /* 16 bits */
#define CI_PCI_DEVICE_ID          0x02    /* 16 bits */
#define CI_PCI_COMMAND            0x04    /* 16 bits */
#define CI_PCI_COMMAND_IO         0x1     /* Enable response in I/O space */
#define CI_PCI_COMMAND_MEMORY     0x2     /* Enable response in Memory space */
#define CI_PCI_COMMAND_MASTER     0x4     /* Enable bus mastering */
#define CI_PCI_COMMAND_SPECIAL    0x8     /* Enable response to special cycles */
#define CI_PCI_COMMAND_INVALIDATE 0x10    /* Use memory write and invalidate */
#define CI_PCI_COMMAND_VGA_PALETTE 0x20   /* Enable palette snooping */
#define CI_PCI_COMMAND_PARITY     0x40    /* Enable parity checking */
#define CI_PCI_COMMAND_WAIT       0x80    /* Enable address/data stepping */
#define CI_PCI_COMMAND_SERR       0x100   /* Enable SERR */
#define CI_PCI_COMMAND_FAST_BACK  0x200   /* Enable back-to-back writes */

#define CI_PCI_STATUS             0x06    /* 16 bits */
#define CI_PCI_STATUS_CAP_LIST    0x10    /* Support Capability List */
#define CI_PCI_STATUS_66MHZ       0x20    /* Support 66 Mhz PCI 2.1 bus */
#define CI_PCI_STATUS_UDF         0x40    /* Support User Definable Features [obsolete] */
#define CI_PCI_STATUS_FAST_BACK   0x80    /* Accept fast-back to back */
#define CI_PCI_STATUS_PARITY      0x100   /* Detected parity error */
#define CI_PCI_STATUS_DEVSEL_MASK 0x600   /* DEVSEL timing */
#define CI_PCI_STATUS_DEVSEL_FAST 0x000
#define CI_PCI_STATUS_DEVSEL_MEDIUM    0x200
#define CI_PCI_STATUS_DEVSEL_SLOW      0x400
#define CI_PCI_STATUS_SIG_TARGET_ABORT 0x800 /* Set on target abort */
#define CI_PCI_STATUS_REC_TARGET_ABORT 0x1000 /* Master ack of " */
#define CI_PCI_STATUS_REC_MASTER_ABORT 0x2000 /* Set on master abort */
#define CI_PCI_STATUS_SIG_SYSTEM_ERROR 0x4000 /* Set when we drive SERR */
#define CI_PCI_STATUS_DETECTED_PARITY  0x8000 /* Set on parity error */

#define CI_PCI_CLASS_REVISION      0x08    /* High 24 bits are class, low 8
                                           revision */
#define CI_PCI_REVISION_ID         0x08    /* Revision ID */
#define CI_PCI_CLASS_PROG          0x09    /* Reg. Level Programming Interface */
#define CI_PCI_CLASS_DEVICE        0x0a    /* Device class */

#define CI_PCI_CACHE_LINE_SIZE     0x0c    /* 8 bits */
#define CI_PCI_LATENCY_TIMER       0x0d    /* 8 bits */
#define CI_PCI_HEADER_TYPE         0x0e    /* 8 bits */
#define CI_PCI_HEADER_TYPE_NORMAL  0
#define CI_PCI_HEADER_TYPE_BRIDGE  1
#define CI_PCI_HEADER_TYPE_CARDBUS 2

#define CI_PCI_BIST                0x0f    /* 8 bits */
#define CI_PCI_BIST_CODE_MASK      0x0f    /* Return result */
#define CI_PCI_BIST_START          0x40    /* 1 to start BIST, 2 secs or less */
#define CI_PCI_BIST_CAPABLE        0x80    /* 1 if BIST capable */

/*
 * Base addresses specify locations in memory or I/O space.
 * Decoded size can be determined by writing a value of
 * 0xffffffff to the register, and reading it back.  Only
 * 1 bits are decoded.
 */
#define CI_PCI_BASE_ADDRESS_0      0x10    /* 32 bits */
#define CI_PCI_BASE_ADDRESS_1      0x14    /* 32 bits [htype 0,1 only] */
#define CI_PCI_BASE_ADDRESS_2      0x18    /* 32 bits [htype 0 only] */
#define CI_PCI_BASE_ADDRESS_3      0x1c    /* 32 bits */
#define CI_PCI_BASE_ADDRESS_4      0x20    /* 32 bits */
#define CI_PCI_BASE_ADDRESS_5      0x24    /* 32 bits */
#define CI_PCI_BASE_ADDRESS_SPACE  0x01    /* 0 = memory, 1 = I/O */
#define CI_PCI_BASE_ADDRESS_SPACE_IO      0x01
#define CI_PCI_BASE_ADDRESS_SPACE_MEMORY  0x00
#define CI_PCI_BASE_ADDRESS_MEM_TYPE_MASK 0x06
#define CI_PCI_BASE_ADDRESS_MEM_TYPE_32   0x00    /* 32 bit address */
#define CI_PCI_BASE_ADDRESS_MEM_TYPE_1M   0x02    /* Below 1M [obsolete] */
#define CI_PCI_BASE_ADDRESS_MEM_TYPE_64   0x04    /* 64 bit address */
#define CI_PCI_BASE_ADDRESS_MEM_PREFETCH  0x08    /* prefetchable? */
#define CI_PCI_BASE_ADDRESS_MEM_MASK      (~0x0fUL)
#define CI_PCI_BASE_ADDRESS_IO_MASK       (~0x03UL)
/* bit 1 is reserved if address_space = 1 */


/* 0x35-0x3b are reserved */
#define CI_PCI_INTERRUPT_LINE      0x3c    /* 8 bits */
#define CI_PCI_INTERRUPT_PIN       0x3d    /* 8 bits */
#define CI_PCI_MIN_GNT             0x3e    /* 8 bits */
#define CI_PCI_MAX_LAT             0x3f    /* 8 bits */

#endif  /* __CI_PCI_H */

/*! \cidoxg_end */
