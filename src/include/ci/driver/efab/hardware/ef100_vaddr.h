/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019 Xilinx, Inc. */

#ifndef __CI_DRIVER_EFAB_HARDWARE_EF100_VADDR_H__
#define __CI_DRIVER_EFAB_HARDWARE_EF100_VADDR_H__

/*----------------------------------------------------------------------------
 *
 * Buffer virtual addresses
 *
 *---------------------------------------------------------------------------*/

#define EF100_BUF_VADDR_ORDER_SHIFT ESF_GZ_NMMU_2M_PAGE_SIZE_ID_LBN
#define EF100_BUF_VADDR_2_ID_OFFSET(vaddr) ((vaddr) & 0x7ffffffffffffffULL)
#define EF100_BUF_VADDR_2_ORDER(vaddr) ((vaddr) >> EF100_BUF_VADDR_ORDER_SHIFT)
#define EF100_BUF_ID_ORDER_2_VADDR(id, order) \
	(((uint64_t)(order) << EF100_BUF_VADDR_ORDER_SHIFT) + \
	 ((uint64_t)(id) << (order + EFHW_NIC_PAGE_SHIFT)))
#define EF100_BUF_VADDR_2_ID(vaddr) \
	(EF100_BUF_VADDR_2_ID_OFFSET(vaddr) >> \
	 (EFHW_NIC_PAGE_SHIFT + EF100_BUF_VADDR_2_ORDER(vaddr)))


#endif
