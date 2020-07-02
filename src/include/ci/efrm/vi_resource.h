/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains public API for VI resource.
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

#ifndef __CI_EFRM_VI_RESOURCE_H__
#define __CI_EFRM_VI_RESOURCE_H__

#include <ci/efhw/nic.h>
#include <ci/efrm/resource.h>
#include <ci/efrm/debug.h>


struct efrm_vi;
struct efrm_vi_set;
struct efrm_pd;
struct efrm_client;


struct efrm_vi_attr {
	/* Please try to avoid changing the size of this.  We've like to
	 * preserve binary compatibility as far as possible.
	 */
	void* opaque[8];
};


struct efrm_vi_q_size {
	/** The number of "entries" in the queue. */
	int  q_len_entries;
	/** The size of the queue in bytes. */
	int  q_len_bytes;
	/** log2 of the number of 4K pages required. */
	int  q_len_page_order;
	/** Bitmask of the queue sizes supported. */
	int  q_sizes_supported;
};


enum efrm_vi_q_flags {
	/** RXQ, TXQ: Select physical addressing mode. */
	EFRM_VI_PHYS_ADDR             = 0x1,
	/** TXQ: Enable IP checksum offload. */
	EFRM_VI_IP_CSUM               = 0x2,
	/** TXQ: Enable TCP/UDP checksum offload. */
	EFRM_VI_TCP_UDP_CSUM          = 0x4,
	/** TXQ: Enable iSCSI header digest offload. */
	EFRM_VI_ISCSI_HEADER_DIGEST   = 0x8,
	/** TXQ: Enable iSCSI data digest offload. */
	EFRM_VI_ISCSI_DATA_DIGEST     = 0x10,
	/** TXQ: Outgoing packets must match an Ethernet filter. */
	EFRM_VI_ETH_FILTER            = 0x20,
	/** TXQ: Outgoing packets must match a TCP/UDP filter. */
	EFRM_VI_TCP_UDP_FILTER        = 0x40,
	/** RXQ: Contiguous buffer mode.  Only works with EFRM_VI_PHYS_ADDR. */
	EFRM_VI_CONTIGUOUS            = 0x80,
	/** RXQ: Timestamp RX packets */
	EFRM_VI_RX_TIMESTAMPS         = 0x100,
	/** TXQ: Timestamp TX packets */
	EFRM_VI_TX_TIMESTAMPS         = 0x200,
	/** TXQ: Send outgoing traffic to loopback datapath beside MAC */
	EFRM_VI_TX_LOOPBACK           = 0x400,
	/** RXQ: Enable support to receive from loopback datapath beside MAC */
	EFRM_VI_RX_LOOPBACK           = 0x800,
	/** EVQ: Disable event cut-through.
	 *  This is necessary to allow RX event merging.
	 */
	EFRM_VI_NO_EV_CUT_THROUGH     = 0x1000,
	/** RXQ: Enable packed stream mode */
	EFRM_VI_RX_PACKED_STREAM      = 0x2000,
	/** RXQ: Enable RX prefix */
	EFRM_VI_RX_PREFIX             = 0x4000,
	/** RXQ: Force events to qualify for merging */
	EFRM_VI_NO_RX_CUT_THROUGH     = 0x8000,
	/** EVQ: Enable RX event merging */
	EFRM_VI_ENABLE_RX_MERGE       = 0x10000,
	/** EVQ: Enable hardare event timer */
	EFRM_VI_ENABLE_EV_TIMER       = 0x20000,
	/** TXQ: Enable CTPIO. */
	EFRM_VI_TX_CTPIO              = 0x40000,
	/** TXQ: CTPIO: Require store-and-forward. */
	EFRM_VI_TX_CTPIO_NO_POISON    = 0x80000,
	/** RXQ: Force zerocopy with AF_XDP*/
	EFRM_VI_RX_ZEROCOPY           = 0x100000,
};


/* All the info you need to use this VI in the kernel. */
struct efrm_vi_mappings {
	void*            io_page;

	unsigned         evq_size;
	void*            evq_base;

	unsigned         timer_quantum_ns;
	int              rx_ts_correction;
	int              tx_ts_correction;
        enum ef_timestamp_format ts_format;

	unsigned         rxq_size;
	void*            rxq_descriptors;
	unsigned         rxq_prefix_len;

	unsigned         txq_size;
	void*            txq_descriptors;

	unsigned         out_flags;
};


/** Initialise an efrm_vi_attr object to default values. */
#define efrm_vi_attr_init(attr)					\
      __efrm_vi_attr_init(NULL, (attr), sizeof(struct efrm_vi_attr))
extern int __efrm_vi_attr_init(struct efrm_client *client_obsolete,
			       struct efrm_vi_attr *attr, int attr_size);

/** Set the protection domain for a VI. */
extern void efrm_vi_attr_set_pd(struct efrm_vi_attr *attr,
				struct efrm_pd *pd);

/** Allocate a VI that supports packed stream mode. */
extern void efrm_vi_attr_set_packed_stream(struct efrm_vi_attr *attr,
					   int packed_stream);

/** Set buffer size for VI allocated in packed stream mode. */
extern void efrm_vi_attr_set_ps_buffer_size(struct efrm_vi_attr *attr,
					    int ps_buffer_size);

/** Allocate VI from a VI set. */
extern void efrm_vi_attr_set_instance(struct efrm_vi_attr *attr,
				      struct efrm_vi_set *,
				      int instance_in_set);

/** The interrupt associated with the VI should be on (or close to) the
 * given core.
 */
extern void efrm_vi_attr_set_interrupt_core(struct efrm_vi_attr *, int core);

/** The VI should use the given net-driver channel for wakeups. */
extern void efrm_vi_attr_set_wakeup_channel(struct efrm_vi_attr *,
					    int channel_id);

/** Parameters required for AF_XDP buffer management */
extern void efrm_vi_attr_set_af_xdp(struct efrm_vi_attr *,
                                    long buffer_count,
                                    int buffer_size,
                                    int headroom);

extern struct efrm_vi *
efrm_vi_from_resource(struct efrm_resource *);



/**
 * Allocate a VI resource instance.
 *
 * [client] is obsolete and only remains for backwards compatibility.  You
 * should instead provide a vi_set or pd via the attributes, and set client
 * to NULL.
 *
 * [attr] may be NULL only if client is not NULL.
 */
extern int  efrm_vi_alloc(struct efrm_client *client,
			  const struct efrm_vi_attr *attr,
			  int print_resource_warnings,
			  const char *vi_name,
			  struct efrm_vi **p_virs_out);

/**
 * Tells whether rx loopback is supported by a VI.
 */
extern int efrm_vi_is_hw_rx_loopback_supported(struct efrm_vi *virs);


/**
 * Returns the pd associated with the VI
 */
extern struct efrm_pd* efrm_vi_pd_get(struct efrm_vi *virs);

#define EFRM_VI_Q_GET_SIZE_CURRENT  -123

/**
 * Returns information about the size of a DMA or event queue.
 *
 * If [n_q_entries == EFRM_VI_Q_GET_SIZE_CURRENT]: If the queue is already
 * initialised, then return the size of the existing queue.  Else return
 * -EINVAL.
 *
 * If [n_q_entries > 0]: Return the size of a queue that has the given
 * number of entries.  If [n_q_entries] is not a supported queue size, then
 * it is rounded up to the nearest supported size.  If [n_q_entries] is
 * larger than the max supported size, return -EINVAL.
 *
 * [q_size_out->q_sizes_supported] is always initialised, even if an error
 * code is returned.
 */
extern int  efrm_vi_q_get_size(struct efrm_vi *virs, enum efhw_q_type q_type,
			       int n_q_entries,
			       struct efrm_vi_q_size *q_size_out);

/**
 * Initialise a VI dma/event queue.
 *
 * [n_q_entries] must be a supported size for this NIC and [q_type], else
 * -EINVAL is returned.  Use efrm_vi_q_get_size() to choose an appropriate
 * size.
 *
 * [dma_addrs] gives the DMA address of each of the pages backing the
 * queue.
 *
 * [q_tag] is only used for RXQs and TXQs, and specifies the tag reflected
 * in completion events.
 *
 * [q_flags] takes values from [efrm_vi_q_flags].
 *
 * [evq] identifies the event queue to be used for a DMA queue.  If NULL
 * then [virs] is used.  Ignored when [q_type == EFHW_EVQ].
 */
extern int efrm_vi_q_init(struct efrm_vi *virs, enum efhw_q_type q_type,
			  int n_q_entries,
			  const dma_addr_t *dma_addrs, int dma_addrs_n,
			  int q_tag, unsigned q_flags,
			  struct efrm_vi *evq);


/* Issue flush of a VI dma/event queue.
 */
extern int
efrm_vi_q_flush(struct efrm_vi *virs, enum efhw_q_type queue_type);

/**
 * Reinitialises a VI after a NIC reset 
 */
extern void efrm_vi_qs_reinit(struct efrm_vi *virs);

/**
 * Allocate a VI dma/event queue.
 *
 * This function does everything that efrm_vi_q_init() does, but also
 * allocates and dma-maps memory for the ring.
 */
extern int efrm_vi_q_alloc(struct efrm_vi *virs, enum efhw_q_type q_type,
			   int n_q_entries, int q_tag_in, unsigned vi_flags,
			   struct efrm_vi *evq);

/**
 * Sanitize the size of the requested queue, as a precursor to allocating it.
 */
extern int
efrm_vi_q_alloc_sanitize_size(struct efrm_vi *virs, enum efhw_q_type q_type,
			      int n_q_entries);

struct pci_dev;
extern struct pci_dev *efrm_vi_get_pci_dev(struct efrm_vi *);
extern void efrm_vi_get_dev_name(struct efrm_vi *virs, char* name);

extern int efrm_vi_get_channel(struct efrm_vi *);

extern int efrm_vi_set_get_vi_instance(struct efrm_vi *);

/* Make these inline instead of macros for type checking */
static inline struct efrm_vi *
efrm_to_vi_resource(struct efrm_resource *rs)
{
	EFRM_ASSERT(rs->rs_type == EFRM_RESOURCE_VI);
	return (struct efrm_vi *) rs;
}
static inline struct
efrm_resource *efrm_from_vi_resource(struct efrm_vi *rs)
{
	return (struct efrm_resource *)rs;
}

#define EFAB_VI_RESOURCE_INSTANCE(virs) \
    (efrm_from_vi_resource(virs)->rs_instance)

#define EFAB_VI_RESOURCE_PRI_ARG(virs) \
    (efrm_from_vi_resource(virs)->rs_instance)

extern int
efrm_vi_resource_alloc(struct efrm_client *client,
		       struct efrm_vi *evq_virs,
		       struct efrm_vi_set *vi_set, int vi_set_instance,
		       struct efrm_pd *pd, const char *name,
		       unsigned vi_flags,
		       int evq_capacity, int txq_capacity, int rxq_capacity,
		       int tx_q_tag, int rx_q_tag, int wakeup_cpu_core,
		       int wakeup_channel,
		       long xdp_buffers, int xdp_buffer_size, int xdp_headroom,
		       struct efrm_vi **virs_in_out,
		       uint32_t *out_io_mmap_bytes,
		       uint32_t *out_mem_mmap_bytes,
                       uint32_t *out_ctpio_mmap_bytes,
		       uint32_t *out_txq_capacity,
		       uint32_t *out_rxq_capacity,
		       int print_resource_warnings);

extern void efrm_vi_resource_release(struct efrm_vi *);
extern void efrm_vi_resource_stop_callback(struct efrm_vi *virs);
extern void efrm_vi_resource_release_flushed(struct efrm_vi *virs);

/* Return the protection domain associated with this VI.  This function
 * returns a borrowed reference which lives as long as the VI.
 */
extern struct efrm_pd *efrm_vi_get_pd(struct efrm_vi *);

extern void efrm_vi_resource_mark_shut_down(struct efrm_vi *virs);
extern void efrm_vi_resource_shutdown(struct efrm_vi *virs);

/*--------------------------------------------------------------------
 *
 * eventq handling
 *
 *--------------------------------------------------------------------*/

/*! Callback function provided by user */
typedef int (*efrm_evq_callback_fn) (void *arg, int is_timeout,
				     struct efhw_nic *nic, int budget);

/*! Register a kernel-level handler for the event queue.  This function is
 * called whenever a timer expires, or whenever the event queue is woken
 * but no thread is blocked on it.
 *
 * This function returns -EBUSY if a callback is already installed.
 *
 * \param rs      Event-queue resource
 * \param handler Callback-handler
 * \param arg     Argument to pass to callback-handler
 * \return        Status code
 */
extern int
efrm_eventq_register_callback(struct efrm_vi *rs,
			      efrm_evq_callback_fn handler,
			      void *arg);

/*! Kill the kernel-level callback.
 *
 * This function stops the timer from running and unregisters the callback
 * function.  It waits for any running timeout handlers to complete before
 * returning.
 *
 * \param rs      Event-queue resource
 * \return        Nothing
 */
extern void efrm_eventq_kill_callback(struct efrm_vi *rs);

/*! Ask the NIC to generate a wakeup when an event is next delivered. */
extern void efrm_eventq_request_wakeup(struct efrm_vi *rs,
				       unsigned current_ptr);

/*! Register a kernel-level handler for flush completions.
 * \TODO Currently, it is unsafe to install a callback more than once.
 *
 * \param rs      VI resource being flushed.
 * \param handler Callback handler function.
 * \param arg     Argument to be passed to handler.
 */
extern void
efrm_vi_register_flush_callback(struct efrm_vi *rs,
				void (*handler)(void *),
				void *arg);

/*! Comment? */
extern void efrm_pt_flush(struct efrm_vi *);

/*! If there are flushes outstanding on this NIC wait until they have
 * completed
 */
extern void efrm_vi_wait_nic_complete_flushes(struct efhw_nic *nic);

/*!
 * Iterate the lists of pending flushes and complete any that are more
 * than 1 second old 
 */
extern void efrm_vi_check_flushes(struct work_struct *data);

/*! Set [n_entries] to -1 to get size of existing EVQ. */
extern uint32_t efrm_vi_rm_evq_bytes(struct efrm_vi *virs, int n_entries);


/*! Get the info needed to use a VI in kernel space. */
extern void efrm_vi_get_mappings(struct efrm_vi *, struct efrm_vi_mappings *);

extern int efrm_vi_get_rx_error_stats(struct efrm_vi*, void*, size_t, int);

extern int
efrm_vi_tx_alt_alloc(struct efrm_vi *virs, int num_alt, int num_32b_words);

extern int
efrm_vi_tx_alt_free(struct efrm_vi *virs);

#endif /* __CI_EFRM_VI_RESOURCE_H__ */
