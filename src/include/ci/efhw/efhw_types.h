/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides struct efhw_nic and some related types.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
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

#ifndef __CI_EFHW_EFAB_TYPES_H__
#define __CI_EFHW_EFAB_TYPES_H__

#include <ci/efhw/efhw_config.h>
#include <ci/efhw/hardware_sysdep.h>
#include <ci/efhw/iopage_types.h>
#include <ci/efhw/sysdep.h>
#include <ci/efhw/common.h>
#include <ci/compat.h>
#include <etherfabric/ef_vi.h>

/*--------------------------------------------------------------------
 *
 * forward type declarations
 *
 *--------------------------------------------------------------------*/

struct efhw_nic;
struct efhw_ev_handler;

typedef uint32_t efhw_btb_handle;

/*--------------------------------------------------------------------
 *
 * Buffer table management
 *
 *--------------------------------------------------------------------*/
#define EFHW_BUFFER_TABLE_BLOCK_SIZE  32

/* Block of buffer table entries.
 * If physical memory is very fragmented (and we aren't using huge pages) we
 * allocate a lot of such structures for every NIC at load time, so we mut
 * keep this structure as small as possible.
 */
struct efhw_buffer_table_block {

	/* Support linked lists. */
	struct efhw_buffer_table_block *btb_next;

	/* Buffer table virtual address of the first entry. */
	uint64_t btb_vaddr;

	/* hw-specific data */
	union {
		/* handle for Huntington */
		struct {
			efhw_btb_handle handle;
		} ef10;
	} btb_hw;

	/* Bit mask of free entries.  Free entries are set to 1. */
	uint32_t btb_free_mask;
};

#define EFHW_BT_BLOCK_FREE_ALL ((uint32_t)(-1))
#define EFHW_BT_BLOCK_RANGE(first, n) \
	((n) == EFHW_BUFFER_TABLE_BLOCK_SIZE ? EFHW_BT_BLOCK_FREE_ALL : \
	 ((1 << (n)) - 1) << (first))

#define EFHW_NIC_PAGES_IN_OS_PAGE (PAGE_SIZE / EFHW_NIC_PAGE_SIZE)
#define EFHW_GFP_ORDER_TO_NIC_ORDER(gfp_order) \
	((gfp_order) + PAGE_SHIFT - EFHW_NIC_PAGE_SHIFT)

/*--------------------------------------------------------------------
 *
 * Managed interface
 *
 *--------------------------------------------------------------------*/

enum efhw_q_type {
	EFHW_TXQ,
	EFHW_RXQ,
	EFHW_EVQ,
	EFHW_N_Q_TYPES
};


struct eventq_resource_hardware {
	/*!iobuffer allocated for eventq - can be larger than eventq */
	struct efhw_iopages iobuff;
	struct efhw_buffer_table_block *bt_block;
	int capacity;		/*!< capacity of event queue */
};


/**********************************************************************
 * Portable HW interface. ***************************************
 **********************************************************************/

/*--------------------------------------------------------------------
 *
 * EtherFabric Functional units - configuration and control
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops {

  /*-------------- Initialisation ------------ */

	/*! initialise all hardware functional units */
	int (*init_hardware) (struct efhw_nic *nic,
			      struct efhw_ev_handler *,
			      const uint8_t *mac_addr);

	/*! re-set necessary configuration after a reset */
	void (*post_reset) (struct efhw_nic *nic);

	/*! release any allocated resources */
	void (*release_hardware) (struct efhw_nic *nic);

  /*-------------- Event support  ------------ */

	/*! Enable the given event queue
	   depending on the the addressing mode selected then either a q_base_addr
	   in host memory, or a buffer base id should be provided
	 */
	int (*event_queue_enable) (struct efhw_nic *nic,
				    uint evq,	/* evnt queue index */
				    uint evq_size,	/* units of #entries */
				    dma_addr_t* dma_addr,
				    uint n_pages,
				    int interrupting, 
				    int enable_dos_p,
				    int wakeup_evq,
				    int flags,
				    int* flags_out);

	/*! Disable the given event queue (and any associated timer) */
	void (*event_queue_disable) (struct efhw_nic *nic, uint evq,
				     int time_sync_events_enabled);

	/*! request wakeup from the NIC on a given event Q */
	void (*wakeup_request) (struct efhw_nic *nic,
				volatile void __iomem* io_page, int vi_id,
				int rd_ptr);

	/*! Push a SW event on a given eventQ */
	void (*sw_event) (struct efhw_nic *nic, int data, int evq);

	/*! Handle an event from hardware, e.g. delivered via driverlink */
	int (*handle_event) (struct efhw_nic *nic, struct efhw_ev_handler *h, 
			     efhw_event_t *ev, int budget);

  /*-------------- DMA support  ------------ */

	/*! Initialise NIC state for a given TX DMAQ */
	int (*dmaq_tx_q_init) (struct efhw_nic *nic,
			       uint dmaq, uint evq, uint owner, uint tag,
			       uint dmaq_size,
			       dma_addr_t *dma_addrs, int n_dma_addrs,
			       uint vport_id, uint stack_id, uint flags);

	/*! Initialise NIC state for a given RX DMAQ */
	int (*dmaq_rx_q_init) (struct efhw_nic *nic,
			       uint dmaq, uint evq, uint owner, uint tag,
			       uint dmaq_size,
			       dma_addr_t *dma_addrs, int n_dma_addrs,
			       uint vport_id, uint stack_id, 
			       uint ps_buf_size, uint flags);

	/*! Disable a given TX DMAQ */
	void (*dmaq_tx_q_disable) (struct efhw_nic *nic, uint dmaq);

	/*! Disable a given RX DMAQ */
	void (*dmaq_rx_q_disable) (struct efhw_nic *nic, uint dmaq);

	/*! Flush a given TX DMA channel */
	int (*flush_tx_dma_channel) (struct efhw_nic *nic, uint dmaq);

	/*! Flush a given RX DMA channel */
	int (*flush_rx_dma_channel) (struct efhw_nic *nic, uint dmaq);

  /*-------------- Buffer table Support ------------ */
	/*! Find all page orders available on this NIC.
	 * order uses EFHW_NIC_PAGE_SIZE as a base (i.e. EFHW_NIC_PAGE_SIZE
	 * has order 0).
	 * orders[] is array of size EFHW_NIC_PAGE_ORDERS_NUM.
	 * The real number of available orders is returned. */
	const int *buffer_table_orders;
	int buffer_table_orders_num;

	/*! Allocate buffer table block. */
	int (*buffer_table_alloc) (struct efhw_nic *nic, int owner, int order,
				   struct efhw_buffer_table_block **block_out,
				   int reset_pending);

	/* Re-allocate buffer table block after NIC reset.
	 * In case of failure, the block should be marked as invalid;
	 * caller must free it via buffer_table_free call. */
	int (*buffer_table_realloc) (struct efhw_nic *nic,
				     int owner, int order,
				     struct efhw_buffer_table_block *block);

	/*! Free buffer table block */
	void (*buffer_table_free) (struct efhw_nic *nic,
				   struct efhw_buffer_table_block *block,
				   int reset_pending);

	/*! Set/program buffer table page entries */
	int (*buffer_table_set) (struct efhw_nic *nic,
				 struct efhw_buffer_table_block *block,
				 int first_entry, int n_entries,
				 dma_addr_t* dma_addrs);

	/*! Clear a block of buffer table pages */
	void (*buffer_table_clear) (struct efhw_nic *nic,
				    struct efhw_buffer_table_block *block,
				    int first_entry, int n_entries);

  /*-------------- Sniff Support ------------ */
	/*! Enable or disable port sniff.
	 * If rss_context_handle is -1 instance is treated as a single RX
	 * queue.  If rss_context_handle is a valid rss context handle then
	 * instance is treated as a base queue and RSS is enabled.
	 */
	int (*set_port_sniff) (struct efhw_nic *nic, int instance, int enable,
			       int promiscuous, int rss_context_handle);

	/*! Enable or disable tx port sniff.
	 * If rss_context_handle is -1 instance is treated as a single RX
	 * queue.  If rss_context_handle is a valid rss context handle then
	 * instance is treated as a base queue and RSS is enabled.
	 */
	int (*set_tx_port_sniff) (struct efhw_nic *nic, int instance,
				  int enable, int rss_context_handle);

  /*-------------- Licensing ------------------------ */
	int (*license_challenge) (struct efhw_nic *nic,
				   const uint32_t feature,
				   const uint8_t* challenge,
				   uint32_t* expiry,
				   uint8_t* signature);

	int (*license_check) (struct efhw_nic *nic, const uint32_t feature,
			      int* licensed);
	int (*v3_license_challenge) (struct efhw_nic *nic,
				   const uint64_t app_id,
				   const uint8_t* challenge,
				   uint32_t* expiry,
				   uint32_t* days,
				   uint8_t* signature,
				   uint8_t* base_mac,
				   uint8_t* v_mac);
	int (*v3_license_check) (struct efhw_nic *nic, uint64_t app_id,
			         int* licensed);

  /*-------------- Stats ------------------------ */
	int (*get_rx_error_stats) (struct efhw_nic *nic, int instance,
				   void *data, int data_len, int do_reset);

  /*-------------- TX Alternatives ------------------------ */
	int (*tx_alt_alloc)(struct efhw_nic *nic, int tx_q_id, int num_alt,
			    int num_32b_words,
			    unsigned *cp_id_out, unsigned *alt_ids_out);
	int (*tx_alt_free)(struct efhw_nic *nic, int num_alt, unsigned cp_id,
			   const unsigned *alt_ids);

  /*-------------- dynamic client IDs ------------ */

	/* Create a new dynamic client entity; see MC_CMD_CLIENT_ALLOC */
	int (*client_alloc)(struct efhw_nic *nic, uint32_t parent, uint32_t *id);
	/* Destroy something from client_alloc() */
	int (*client_free)(struct efhw_nic *nic, uint32_t id);
	/* Change the ID of the client allowed to create queues on a VI */
	int (*vi_set_user)(struct efhw_nic *nic, uint32_t vi_instance,
	                   uint32_t user);

  /*-------------- AF_XDP ------------------------ */

	/*! Provoke device to update states
	 * Relevant for software devices e.g. AF_XDP
	 */
	int (*dmaq_kick)(struct efhw_nic* nic, int instance);

	/*! Get the base address of the queue memory descriptor for a VI.
	 * This is available at any time after calling init_hardware,
	 * although the queue memory itself will not be accessible until
	 * after calling af_xdp_init. */
	void* (*af_xdp_mem) (struct efhw_nic* nic, int instance);

	/*! Initialise a VI for use with AF_XDP.
	 * This must be called after registering all buffer memory through
	 * the buffer table interface. pages_out is populated with the queue
	 * memory pages, which can be mapped into user space. */
	int (*af_xdp_init) (struct efhw_nic* nic, int instance,
	                    int chunk_size, int headroom,
	                    struct efhw_page_map* pages_out);
};


/*----------------------------------------------------------------------------
 *
 * EtherFabric NIC instance - nic.c for HW independent functions
 *
 *---------------------------------------------------------------------------*/

struct pci_dev;

/*! */
struct efhw_nic {
	/*! zero base index in efrm_nic_tablep->nic array */
	int index;

	/*! Options that can be set by user. */
	unsigned options;
# define NIC_OPT_EFTEST             0x1	/* owner is an eftest app */
# define NIC_OPT_DEFAULT            0

	struct net_device *net_dev; /*!< Network device */
	struct pci_dev *pci_dev;    /*!< pci descriptor */
	spinlock_t pci_dev_lock;    /*!< Protects access to pci_dev & net_dev */

	struct efhw_device_type devtype;

	/*! Internal flags that indicate hardware properties at runtime. */
	uint64_t flags;

	ci_uint32 resetting;	/*!< Flags indicating unavailability of HW */
# define NIC_RESETTING_FLAG_RESET       0x00000001
# define NIC_RESETTING_FLAG_UNPLUGGED   0x00000002
# define NIC_RESETTING_FLAG_VANISHED    0x00000004

	unsigned mtu;		/*!< MAC MTU (includes MAC hdr) */

	/*! Bus for hotplug purposes, as we can't rely on pci_dev->bus. */
	unsigned char bus_number;
	/*! Similarly we need the domain, as that's part of the bus state. */
	int domain;

	/* hardware resources */

	/*! Pointer to the control aperture bar. */
	volatile char __iomem *bar_ioaddr;
	/*! Pointer to the EVQ prime register, used on EF100 only. */
	volatile char __iomem *int_prime_reg;
	/*! Bar number of control aperture. */
	unsigned               ctr_ap_bar;
	/*! Length of control aperture in bytes. */
	unsigned               ctr_ap_bytes;
	/*! DMA address of the control aperture. */
	dma_addr_t             ctr_ap_dma_addr;
	/*! Stride between VIs on mem_bar */
	unsigned vi_stride;

	uint8_t mac_addr[ETH_ALEN];	/*!< mac address  */

	/*! EtherFabric Functional Units -- functions */
	const struct efhw_func_ops *efhw_func;

	int buf_commit_outstanding;	/*!< outstanding buffer commits */

	void *bt_blocks_memory;

	/*! Bit masks of the sizes of event queues and dma queues supported
	 * by this nic.
	 */
	unsigned q_sizes[EFHW_N_Q_TYPES];

	/* Number of event queues, DMA queues and timers. */
	unsigned num_evqs;
	unsigned num_dmaqs;
	unsigned num_timers;

	/* Nanoseconds for hardware timeout timer quantum */
	unsigned timer_quantum_ns;

	/* The maximum packet prefix length on this hardware type. A lower value
	 * may be selectable on specific VIs. */
	unsigned rx_prefix_len;

	/* Corrections for TX and RX timestamps. */
	int rx_ts_correction;
	int tx_ts_correction;

        /* PTP timestamp format. */
        enum ef_timestamp_format ts_format;

	/* Base offset of queues used when dealing with absolute numbers, 
	 * e.g. wakeup events.  Can change when NIC is reset.
	 */
	unsigned vi_base;
	/* Shift value used to calculate absolute VI number, non-null
	 * on Medford only;
	 */
	unsigned vi_shift;
	/* VI range to use, relative to vi_base, useful for validating
	 * wakeup event VI is in range
	 */
	unsigned vi_min;
	unsigned vi_lim;
	/* VI IRQ range to use, used on EF100 only. */
#define NIC_IRQ_MAX_RANGES 1
	unsigned vi_irq_n_ranges;
	struct vi_irq_ranges {
		unsigned base;
		unsigned range;
	} vi_irq_ranges[NIC_IRQ_MAX_RANGES];

	/* Size of PIO buffer */
	unsigned pio_size;
	/* Total number of PIO buffers */
	unsigned pio_num;

	/* Number of vFIFOs for TX alternatives */
	uint8_t tx_alts_vfifos;
	/* Number of common pool buffers for TX alternatives*/
	uint16_t tx_alts_cp_bufs;
	/* Size of common pool buffers for TX alternatives */
	uint16_t tx_alts_cp_buf_size;

        /* RX datapath firmware variant */
        uint16_t rx_variant;
        /* TX datapath firmware variant */
        uint16_t tx_variant;

        /* AF_XDP-only state */
        struct efhw_nic_af_xdp* af_xdp;
};


#define EFHW_KVA(nic)       ((nic)->bar_ioaddr)

#endif /* __CI_EFHW_EFHW_TYPES_H__ */
