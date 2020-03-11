/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides EtherFabric NIC - EF10 specific
 * definitions.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
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

#ifndef __CI_DRIVER_EFAB_HARDWARE_EF10_H__
#define __CI_DRIVER_EFAB_HARDWARE_EF10_H__

/*----------------------------------------------------------------------------
 * Compile options
 *---------------------------------------------------------------------------*/

#include <ci/driver/efab/hardware/host_ef10_common.h>
#include <ci/driver/efab/hardware/ef10_vaddr.h>
#include <ci/driver/efab/hardware/ef10_evq.h>

#define EF10_DMA_TX_DESC_BYTES	8
#define EF10_DMA_RX_DESC_BYTES	8

/* ---- efhw_event_t helpers --- */

/*!\ TODO look at whether there is an efficiency gain to be had by
  treating the event codes to 32bit masks as is done for EF1

  These masks apply to the full 64 bits of the event to extract the
  event code - followed by the common event codes to expect
 */
#define __EF10_OPEN_MASK(WIDTH)  ((((uint64_t)1) << (WIDTH)) - 1)
#define EF10_EVENT_CODE_MASK \
	(__EF10_OPEN_MASK(ESF_DZ_EV_CODE_WIDTH) << ESF_DZ_EV_CODE_LBN)
#define EF10_EVENT_EV_Q_ID_MASK \
	(__EF10_OPEN_MASK(ESF_DZ_DRV_EVQ_ID_WIDTH) << ESF_DZ_DRV_EVQ_ID_LBN)

#define EF10_EVENT_DRV_SUBCODE_MASK \
	(__EF10_OPEN_MASK(ESF_DZ_DRV_SUB_CODE_WIDTH) << \
	 ESF_DZ_DRV_SUB_CODE_LBN)
#define EF10_EVENT_SW_SUBCODE_MASK \
	(__EF10_OPEN_MASK(MCDI_EVENT_CODE_WIDTH) << \
	 MCDI_EVENT_CODE_LBN)

#define EF10_EVENT_TX_FLUSH_Q_ID_MASK \
	(__EF10_OPEN_MASK(MCDI_EVENT_TX_FLUSH_TXQ_WIDTH) << \
	 MCDI_EVENT_TX_FLUSH_TXQ_LBN)
#define EF10_EVENT_RX_FLUSH_Q_ID_MASK \
	(__EF10_OPEN_MASK(MCDI_EVENT_RX_FLUSH_RXQ_WIDTH) << \
	 MCDI_EVENT_RX_FLUSH_RXQ_LBN)

#define EF10_EVENT_FMT         "[ev:%x:%08x:%08x]"
#define EF10_EVENT_PRI_ARG(e) \
	((unsigned)(((le64_to_cpu((e).u64) & EF10_EVENT_CODE_MASK) >> ESF_DZ_EV_CODE_LBN))), \
    ((unsigned)((le64_to_cpu((e).u64) >> 32))), ((unsigned)((e).u64 & 0xFFFFFFFF))

#define EF10_EVENT_CODE(evp)		(le64_to_cpu((evp)->u64) & EF10_EVENT_CODE_MASK)
#define EF10_EVENT_WAKE_EVQ_ID(evp) \
	((le64_to_cpu((evp)->u64) & EF10_EVENT_EV_Q_ID_MASK) >> ESF_DZ_DRV_EVQ_ID_LBN)
#define EF10_EVENT_TX_FLUSH_Q_ID(evp) \
	((le64_to_cpu((evp)->u64) & EF10_EVENT_TX_FLUSH_Q_ID_MASK) >> \
	 MCDI_EVENT_TX_FLUSH_TXQ_LBN)
#define EF10_EVENT_RX_FLUSH_Q_ID(evp) \
	((le64_to_cpu((evp)->u64) & EF10_EVENT_RX_FLUSH_Q_ID_MASK) >> \
	 MCDI_EVENT_RX_FLUSH_RXQ_LBN)
#define EF10_EVENT_RX_FLUSH_FAIL(evp) \
	((le64_to_cpu((evp)->u64) & EF10_EVENT_RX_FLUSH_FAIL_MASK) >> \
	 DRIVER_EV_RX_FLUSH_FAIL_LBN)
#define EF10_EVENT_DRIVER_SUBCODE(evp) \
	((le64_to_cpu((evp)->u64) & EF10_EVENT_DRV_SUBCODE_MASK) >> \
	 ESF_DZ_DRV_SUB_CODE_LBN)
#define EF10_EVENT_SW_SUBCODE(evp) \
	((le64_to_cpu((evp)->u64) & EF10_EVENT_SW_SUBCODE_MASK) >> \
	 MCDI_EVENT_CODE_LBN)


#define EF10_EVENT_CODE_CHAR	((uint64_t)ESE_DZ_EV_CODE_DRIVER_EV << ESF_DZ_EV_CODE_LBN)
#define EF10_EVENT_CODE_SW	((uint64_t)ESE_DZ_EV_CODE_MCDI_EV << ESF_DZ_EV_CODE_LBN)


/* we define some unique dummy values as a debug aid */
#define EF10_ATOMIC_BASE		0xdeadbeef00000000ULL
#define EF10_ATOMIC_UPD_REG		(EF10_ATOMIC_BASE | 0x1)
#define EF10_ATOMIC_PTR_TBL_REG	(EF10_ATOMIC_BASE | 0x2)
#define EF10_ATOMIC_SRPM_UDP_EVQ_REG	(EF10_ATOMIC_BASE | 0x3)
#define EF10_ATOMIC_RX_FLUSH_DESCQ	(EF10_ATOMIC_BASE | 0x4)
#define EF10_ATOMIC_TX_FLUSH_DESCQ	(EF10_ATOMIC_BASE | 0x5)
#define EF10_ATOMIC_INT_EN_REG	(EF10_ATOMIC_BASE | 0x6)
#define EF10_ATOMIC_TIMER_CMD_REG	(EF10_ATOMIC_BASE | 0x7)
#define EF10_ATOMIC_PACE_REG		(EF10_ATOMIC_BASE | 0x8)
#define EF10_ATOMIC_INT_ACK_REG	(EF10_ATOMIC_BASE | 0x9)
/* XXX It crashed with odd value in EF10_ATOMIC_INT_ADR_REG */
#define EF10_ATOMIC_INT_ADR_REG	(EF10_ATOMIC_BASE | 0xa)

/*----------------------------------------------------------------------------
 *
 * PCI control blocks for Ef10 -
 *          (P) primary is for NET
 *          (S) secondary is for CHAR *
 *---------------------------------------------------------------------------*/

#define EF10_PF_P_CTR_AP_BAR	2
#define EF10_VF_P_CTR_AP_BAR	0
#define EF10_MEDFORD2_P_CTR_AP_BAR	0
#define EF10_S_CTR_AP_BAR	0
#define EF10_S_DEVID		0x6703


/*----------------------------------------------------------------------------
 *
 * Ef10 constants
 *
 *---------------------------------------------------------------------------*/

/* Note: the following constants have moved to values in struct efhw_nic
 * because they are different between Ef10 and AF_XDP:
 *   EF10_EVQ_TBL_NUM  ->  nic->num_evqs
 *   EF10_DMAQ_NUM     ->  nic->num_dmaqs
 *   EF10_TIMERS_NUM   ->  nic->num_times
 * These replacement constants are used as sanity checks in assertions in
 * certain functions that don't have access to struct efhw_nic.  They may
 * catch some errors but do *not* guarantee a valid value for AF_XDP.
 */
#define EF10_DMAQ_NUM_SANITY          (EFHW_4K)
#define EF10_EVQ_TBL_NUM_SANITY       (EFHW_4K)
#define EF10_TIMERS_NUM_SANITY        (EFHW_4K)

/* This value is an upper limit on the total number of filter table
 * entries.  The actual size of filter table is determined at runtime, as
 * it can vary.
 */
#define EF10_FILTER_TBL_NUM		(EFHW_4K)

/* max number of buffers which can be pushed before commiting */
#define EF10_BUFFER_UPD_MAX		(128)

#define EF10_EVQ_RPTR_REG_P0		0x400

/*----------------------------------------------------------------------------
 *
 * Ef10 requires user-space descriptor pushes to be:
 *    dword[0-2]; wiob(); dword[3]
 *
 * Driver register access must be locked against other threads from
 * the same driver but can be in any order: i.e dword[0-3]; wiob()
 *
 * The following helpers ensure that valid dword orderings are exercised
 *
 *---------------------------------------------------------------------------*/

/* Ensure DW3 is written last. Outer locking cannot be relied upon to provide
 * a write barrier
 */
static inline void
ef10_write_ddd_d(volatile char __iomem *kva,
		   uint32_t d0, uint32_t d1, uint32_t d2, uint32_t d3)
{
	writel(d0, kva + 0);
	writel(d1, kva + 4);
	writel(d2, kva + 8);
	wmb();
	writel(d3, kva + 12);
	wmb();
}

/* Ensure DW3 is written last. Outer locking cannot be relied upon to provide
 * a write barrier
 */
static inline void ef10_write_q(volatile char __iomem *kva, uint64_t q)
{
	writel((uint32_t)q, kva);
	wmb();
	writel(q >> 32, kva + 4);
	wmb();
}

static inline void ef10_read_q(volatile char __iomem *addr, uint64_t *q0)
{
	/* It is essential that we read dword0 first, so that
	 * the shadow register is updated with the latest value
	 * and we get a self consistent value.
	 */
	uint32_t lo, hi;
	/* The CPU must always waits for a read to complete so locked sequences
	 * of reads cannot be interleaved. Lock is outside this function.
	 */
	lo = readl(addr);
	rmb(); /* to stop compiler/CPU re-ordering these two reads*/
	hi = readl(addr + 4);
	rmb(); /* just be safe: so ef10_read_q() can be composed */

	*q0 = ((uint64_t)hi << 32) | lo;
}

static inline void
ef10_write_qq(volatile char __iomem *kva, uint64_t q0, uint64_t q1)
{
	writeq(q0, kva + 0);
	ef10_write_q(kva + 8, q1);
}

static inline void
ef10_read_qq(volatile char __iomem *addr, uint64_t *q0, uint64_t *q1)
{
	ef10_read_q(addr, q0);
	*q1 = readq(addr + 8);
}


/*----------------------------------------------------------------------------
 *
 * DMA Queue helpers
 *
 *---------------------------------------------------------------------------*/

/*! returns an address within a bar of the TX DMA doorbell */
static inline uint ef10_tx_dma_page_addr(uint vi_stride, uint dmaq_idx)
{
    return ER_DZ_TX_DESC_UPD_REG + (dmaq_idx * vi_stride);
}

/*! returns an address within a bar of the RX DMA doorbell */
static inline uint ef10_rx_dma_page_addr(uint vi_stride, uint dmaq_idx)
{
    return ER_DZ_RX_DESC_UPD_REG + (dmaq_idx * vi_stride);
}

/*! "page"=NIC-dependent register set size */
#define EF10_DMA_PAGE_MASK  (EFHW_4K-1)

/*! returns an address within a bar of the start of the "page"
    containing the TX DMA doorbell */
static inline int ef10_tx_dma_page_base(uint vi_stride, uint dma_idx)
{
	return ef10_tx_dma_page_addr(vi_stride, dma_idx) & ~EF10_DMA_PAGE_MASK;
}

/*! returns an address within a bar of the start of the "page"
    containing the RX DMA doorbell */
static inline int ef10_rx_dma_page_base(uint vi_stride, uint dma_idx)
{
	return ef10_rx_dma_page_addr(vi_stride, dma_idx) & ~EF10_DMA_PAGE_MASK;
}

/*! returns an offset within a "page" of the TX DMA doorbell */
static inline int ef10_tx_dma_page_offset(uint vi_stride, uint dma_idx)
{
	return ef10_tx_dma_page_addr(vi_stride, dma_idx) & EF10_DMA_PAGE_MASK;
}

/*! returns an offset within a "page" of the RX DMA doorbell */
static inline int ef10_rx_dma_page_offset(uint vi_stride, uint dma_idx)
{
	return ef10_rx_dma_page_addr(vi_stride, dma_idx) & EF10_DMA_PAGE_MASK;
}


/*----------------------------------------------------------------------------
 *
 * Events
 *
 *---------------------------------------------------------------------------*/

#define EF10_A_EVQ_CHAR      (4)	/* min evq accessible via char bar */

/* default DMA-Q sizes */
#define EF10_DMA_Q_DEFAULT_TX_SIZE  512

#define EF10_DMA_Q_DEFAULT_RX_SIZE  512

#define EF10_DMA_Q_DEFAULT_MMAP \
	(EF10_DMA_Q_DEFAULT_TX_SIZE * (EF10_DMA_TX_DESC_BYTES * 2))


/*----------------------------------------------------------------------------
 *
 * DEBUG - Analyser trigger
 *
 *---------------------------------------------------------------------------*/

static inline void
ef10_deadbeef(volatile char __iomem *efhw_kva, unsigned what)
{
	writel(what, efhw_kva + 0x300);
	wmb();
}

#endif /* __CI_DRIVER_EFAB_HARDWARE_EF10_H__ */
/*! \cidoxg_end */
