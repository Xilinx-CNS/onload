/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains type definitions for VI resource.  These types
 * may be used outside of the SFC resource driver, but such use is not
 * recommended.
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

#ifndef __CI_DRIVER_EFAB_VI_RESOURCE_MANAGER_H__
#define __CI_DRIVER_EFAB_VI_RESOURCE_MANAGER_H__

#include <ci/efhw/common.h>
#include <ci/efrm/vi_resource.h>
#include <ci/efrm/vi_allocation.h>
#include <ci/efrm/buffer_table.h>


#define EFRM_VI_RM_DMA_QUEUE_COUNT 2

/* Sufficient for 32K x 8byte entry ring */
#define EFRM_VI_MAX_DMA_ADDR 64

#define EFRM_VI_TX_ALTERNATIVES_MAX  17


struct efrm_pd;


/** Numbers of bits which can be set in the evq_state member of
 * vi_resource_evq_info. */
enum {
  /** This bit is set if a wakeup has been requested on the NIC. */
	VI_RESOURCE_EVQ_STATE_WAKEUP_PENDING,
  /** This bit is set if the wakeup is valid for the sleeping
   * process. */
	VI_RESOURCE_EVQ_STATE_CALLBACK_REGISTERED,
  /** This bit is set if a wakeup or timeout event is currently being
   * processed. */
	VI_RESOURCE_EVQ_STATE_BUSY,
};
#define VI_RESOURCE_EVQ_STATE(X) \
	(((int32_t)1) << (VI_RESOURCE_EVQ_STATE_##X))


/*! Global information for the VI resource manager. */
struct vi_resource_manager {
	struct efrm_resource_manager rm;
	struct workqueue_struct *workqueue;
};


struct efrm_vi_q {
	unsigned                             flags;
	int                                  qid;
	int                                  capacity;
	int                                  bytes;
	/* Queue memory is allocated and managed in host sized pages. On some
	 * architectures the host page size and NIC page size may not be the
	 * same. For this reason we maintain both the host_pages structure
	 * containing details about the memory as host pages, and a second
	 * array dma_addrs, containing the DMA addresses of this memory in
	 * NIC sized pages.
	 */
	int                                  host_page_order;
	struct efhw_iopages                  host_pages;
	struct efrm_buffer_table_allocation  bt_alloc;
	/* DMA address per NIC page. The memory for this allocation is handled
	 * through host_pages. */
	dma_addr_t                           dma_addrs[EFRM_VI_MAX_DMA_ADDR];
	/* The following fields are used for DMA queues only. */
	int                                  tag;
	unsigned long                        flush_jiffies;
	int                                  flushing;
	struct list_head                     flush_link;
	struct list_head                     init_link;
	struct efrm_vi                      *evq_ref;
};


struct efrm_vi {
	/* Some macros make the assumption that the struct efrm_resource is
	 * the first member of a struct efrm_vi. */
	struct efrm_resource rs;
	atomic_t evq_refs;	/*!< Number of users of the event queue. */

	struct efrm_pd *pd;

	struct efrm_pio *pio; /*!< Only set if linked to a pio. */

	struct efrm_vi_allocation allocation;
	struct efhw_page_map mem_mmap;

	unsigned rx_prefix_len;

	/*! EFHW_VI_* flags or EFRM_VI_RELEASED */
	unsigned flags;
        /* Note that the EFHW_VI_* flags are stored in the same word;
         * they use all the values up to and including 0x10000000. */
#define EFRM_VI_RELEASED 0x20000000
#define EFRM_VI_OWNS_STACK_ID 0x40000000
#define EFRM_VI_STOPPING 0x80000000

	/* Sometimes a queue is shut down forcibly or never initialised,
	 * pending recovery on reset. */
	atomic_t shut_down_flags;
#define EFRM_VI_SHUT_DOWN_RXQ 0x00000001
#define EFRM_VI_SHUT_DOWN_TXQ 0x00000002
#define EFRM_VI_SHUT_DOWN_EVQ 0x00000004
#define EFRM_VI_SHUT_DOWN     (EFRM_VI_SHUT_DOWN_RXQ | \
			       EFRM_VI_SHUT_DOWN_TXQ | \
			       EFRM_VI_SHUT_DOWN_EVQ)

	/*! EFHW_VI_ effective flags */
	unsigned out_flags;

	/* Buffer size for packed stream VIs.
	 */
	int      ps_buf_size;

	int      rx_flush_outstanding;
	uint64_t flush_time;
	int      flush_count;
	void   (*flush_callback_fn)(void *);
	void    *flush_callback_arg;

	efrm_evq_callback_fn evq_callback_fn;
	void *evq_callback_arg;
	struct efrm_vi_set *vi_set;
	struct efrm_bt_manager bt_manager;
	struct efrm_vi_q q[EFHW_N_Q_TYPES];
	struct efab_efct_rxq_uk_shm *efct_shm;

	int net_drv_wakeup_channel;

	/* On EF100 we should handle IRQ in VI resource manager. */
	spinlock_t evq_callback_lock;
	uint32_t irq;                        /* IRQ vector */
	struct tasklet_struct tasklet;       /* IRQ tasklet */

	/* A memory mapping onto the IO page for this VI mapped into the
	 * kernel address space.  For EF10 this mapping is private to
	 * this efrm_vi.
	 */
	volatile char __iomem *io_page;

	/* Used by sfc_char only (NULL for Onload VIs). Mapped in to userspace and
	 * read-only to the kernel; be careful when accessing. */
	const volatile ef_vi_state *ep_state;

	unsigned tx_alt_cp;
	int      tx_alt_num;
	unsigned tx_alt_ids[EFRM_VI_TX_ALTERNATIVES_MAX];

#ifndef EFRM_IRQ_FREE_RETURNS_NAME
	const char *irq_name;
#endif
};


#undef efrm_vi
#define efrm_vi(rs1)  container_of((rs1), struct efrm_vi, rs)


#endif /* __CI_DRIVER_EFAB_VI_RESOURCE_MANAGER_H__ */
