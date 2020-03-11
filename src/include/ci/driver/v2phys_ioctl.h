/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Test Driver for translating user addresses to physical: definitions
 *
 * Copyright 2007:      Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications <linux-net-drivers@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 2 as published 
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#ifndef EFTEST_V2P_H
#define EFTEST_V2P_H

#include <asm/ioctl.h>


struct v2p_xlate_req {
  struct {
    int pci_domain;
    int pci_bus;
    int pci_dev;
    int pci_func;
  } a;
  union {
    void *user_addr;
    unsigned long phys_addr;
    unsigned long dma_addr;
  } u;
  unsigned long len;
  unsigned dma_direction;
};


#define V2P_IOC_MAGIC	('v')
/* Translate a user virtual address in u.user_addr to a kernel virtual address */
#define V2P_XLATE_ADDR  (1)
/* As for V2P_XLATE_ADDR but overwrite the first word of address with the 
 * physical address through the corresponding kva to check the translation */
#define V2P_XTEST_ADDR	(2)
/* Map the user virtual address in u.user_addr for dma on the requested pci
 * device, and return the dma address. */
#define V2P_MAP_ADDR	(3)
/* Remap to change the IOMMU permissions */
#define V2P_REMAP_ADDR	(4)
/* Unmap the given dma_addr from the requested pci device */
#define V2P_UNMAP_ADDR  (5)
/* Cleanup all dma mappings */
#define V2P_CLEAN_ALL   (6)
/* Cleanup all dma mappings for the specified device */
#define V2P_UNMAP_ALL   (7)

#define V2P_XLATE_IOC	   _IOWR(V2P_IOC_MAGIC, V2P_XLATE_ADDR, struct v2p_xlate_req)
#define V2P_XTEST_IOC	   _IOWR(V2P_IOC_MAGIC, V2P_XTEST_ADDR, struct v2p_xlate_req)
#define V2P_MAP_IOC	   _IOWR(V2P_IOC_MAGIC, V2P_MAP_ADDR, struct v2p_xlate_req)
#define V2P_REMAP_IOC	   _IOWR(V2P_IOC_MAGIC, V2P_REMAP_ADDR, struct v2p_xlate_req)
#define V2P_UNMAP_IOC      _IOWR(V2P_IOC_MAGIC, V2P_UNMAP_ADDR, struct v2p_xlate_req)
#define V2P_CLEAN_ALL_IOC  _IOWR(V2P_IOC_MAGIC, V2P_CLEAN_ALL, struct v2p_xlate_req)
#define V2P_UNMAP_ALL_IOC  _IOWR(V2P_IOC_MAGIC, V2P_UNMAP_ALL, struct v2p_xlate_req)

#endif

