/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include "net_driver.h"
#include <linux/module.h>
#include "efx.h"
#include "nic.h"
#include "rx_common.h"
#ifdef CONFIG_SFC_TRACING
#include <trace/events/sfc.h>
#endif
#include "mcdi_pcol.h"

/* This is the percentage fill level below which new RX descriptors
 * will be added to the RX descriptor ring.
 */
static unsigned int rx_refill_threshold;
module_param(rx_refill_threshold, uint, 0444);
MODULE_PARM_DESC(rx_refill_threshold,
		 "RX descriptor ring refill threshold (%)");

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
/* By default use the NIC specific calculation. This can be set to 0
 * to disable the RX recycle ring.
 */
static int rx_recycle_ring_size = -1;
module_param(rx_recycle_ring_size, uint, 0444);
MODULE_PARM_DESC(rx_recycle_ring_size,
		 "Maximum number of RX buffers to recycle pages for");
#endif

/*
 * RX maximum head room required.
 *
 * This must be at least 1 to prevent overflow, plus one packet-worth
 * to allow pipelined receives.
 */
#define EFX_RXD_HEAD_ROOM (1 + EFX_RX_MAX_FRAGS)

/* Preferred number of descriptors to fill at once */
#define EFX_RX_PREFERRED_BATCH 8U

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
static void efx_reuse_rx_buffer_zc(struct efx_rx_queue *rx_queue,
				   struct efx_rx_buffer *rx_buf_reuse);
#endif
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
void efx_recycle_rx_bufs_zc(struct efx_channel *channel,
			    struct efx_rx_buffer *rx_buf,
			    unsigned int n_frags)
{
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);

	while (n_frags) {
		rx_buf->flags |= EFX_RX_BUF_XSK_REUSE;
		rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
		--n_frags;
	}
}
#endif

static void efx_rx_slow_fill(struct work_struct *data);
static void efx_schedule_slow_fill(struct efx_rx_queue *rx_queue);
static void efx_cancel_slow_fill(struct efx_rx_queue *rx_queue);

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
/* Check the RX page recycle ring for a page that can be reused. */
static struct page *efx_reuse_page(struct efx_rx_queue *rx_queue)
{
	struct page *page;
	unsigned int index;

	/* No page recycling when queue in ZC mode */
	if (!rx_queue->page_ring)
		return NULL;
	index = rx_queue->page_remove & rx_queue->page_ptr_mask;
	rx_queue->page_remove++;

	page = rx_queue->page_ring[index];
	if (!page)
		return NULL;

	/* If page_count is 1 we hold the only reference to this page. */
	if (page_count(page) != 1) {
		++rx_queue->page_recycle_failed;
		return NULL;
	}

	++rx_queue->page_recycle_count;
	return page;
}

/* Attempt to recycle the page if there is an RX recycle ring; the page can
 * only be added if this is the final RX buffer, to prevent pages being used in
 * the descriptor ring and appearing in the recycle ring simultaneously.
 */
static void efx_recycle_rx_page(struct efx_channel *channel,
				struct efx_rx_buffer *rx_buf)
{
	struct page *page = rx_buf->page;
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);
	struct efx_nic *efx = rx_queue->efx;
	unsigned int index;

	/* Don't continue if page is already present in recycle ring.
	 * Prevents the page being added to the ring twice
	 */
	if (rx_buf->flags & EFX_RX_PAGE_IN_RECYCLE_RING)
		return;

	/* Only recycle the page after processing the final buffer. */
	if (!(rx_buf->flags & EFX_RX_BUF_LAST_IN_PAGE))
		return;

	if (rx_queue->page_ring) {
		index = rx_queue->page_add & rx_queue->page_ptr_mask;
		if (rx_queue->page_ring[index] == NULL) {
			rx_queue->page_ring[index] = page;
			++rx_queue->page_add;
			return;
		}
	}
	++rx_queue->page_recycle_full;
	efx_unmap_rx_buffer(efx, rx_buf);
	put_page(rx_buf->page);
}

/* Recycle the pages that are used by buffers that have just been received. */
void efx_recycle_rx_pages(struct efx_channel *channel,
		struct efx_rx_buffer *rx_buf,
		unsigned int n_frags)
{
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);

	do {
		efx_recycle_rx_page(channel, rx_buf);
		rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
	} while (--n_frags);
}

static void efx_init_rx_recycle_ring(struct efx_rx_queue *rx_queue)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	struct efx_channel *channel = efx_get_rx_queue_channel(rx_queue);
#endif
	unsigned int bufs_in_recycle_ring, page_ring_size;
	struct efx_nic *efx = rx_queue->efx;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	if (channel->zc) {
		rx_queue->page_ring = NULL;
		return;
	}
#endif
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	if (!rx_recycle_ring_size)
		return;
	else if (rx_recycle_ring_size == -1)
		bufs_in_recycle_ring = efx_rx_recycle_ring_size(efx);
	else
		bufs_in_recycle_ring = rx_recycle_ring_size;
#else
	bufs_in_recycle_ring = efx_rx_recycle_ring_size(efx);
#endif
	page_ring_size = roundup_pow_of_two(bufs_in_recycle_ring /
					    efx->rx_bufs_per_page);
	rx_queue->page_ring = kcalloc(page_ring_size,
				      sizeof(*rx_queue->page_ring), GFP_KERNEL);
	if (!rx_queue->page_ring)
		rx_queue->page_ptr_mask = 0;
	else
		rx_queue->page_ptr_mask = page_ring_size - 1;
}

static void efx_fini_rx_recycle_ring(struct efx_rx_queue *rx_queue)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned int i;

	if (unlikely(!rx_queue->page_ring))
		return;

	/* Unmap and release the pages in the recycle ring. Remove the ring. */
	for (i = 0; i <= rx_queue->page_ptr_mask; i++) {
		struct page *page = rx_queue->page_ring[i];
		struct efx_rx_page_state *state;

		if (page == NULL)
			continue;

		state = page_address(page);
		dma_unmap_page(&efx->pci_dev->dev, state->dma_addr,
			       PAGE_SIZE << efx->rx_buffer_order,
			       DMA_FROM_DEVICE);
		put_page(page);
	}
	kfree(rx_queue->page_ring);
	rx_queue->page_ring = NULL;
}

/* Recycle Rx buffer directly back into the rx_queue.
 * If may be done on discard only when Rx buffers do not share page.
 * There is always room to add this buffer, because pipeline is empty and
 * we've just popped a buffer.
 */
static void efx_recycle_rx_buf(struct efx_rx_queue *rx_queue,
			       struct efx_rx_buffer *rx_buf)
{
	struct efx_rx_buffer *new_buf;
	unsigned int index;

	index = rx_queue->added_count & rx_queue->ptr_mask;
	new_buf = efx_rx_buffer(rx_queue, index);

	memcpy(new_buf, rx_buf, sizeof(*new_buf));
	rx_buf->page = NULL;

	/* Page is not shared, so it is always the last */
	new_buf->flags = rx_buf->flags & EFX_RX_BUF_LAST_IN_PAGE;
	if (likely(rx_queue->page_ring)) {
		new_buf->flags |= rx_buf->flags & EFX_RX_PAGE_IN_RECYCLE_RING;
		++rx_queue->recycle_count;
	}

	/* Since removed_count is updated after packet processing the
	 * following can happen here:
	 *   added_count > removed_count + rx_queue->ptr_mask + 1
	 * efx_fast_push_rx_descriptors() asserts this is not true.
	 * efx_fast_push_rx_descriptors() is only called at the end of
	 * a NAPI poll cycle, at which point removed_count has been updated.
	 */
	++rx_queue->added_count;
}

void efx_discard_rx_packet(struct efx_channel *channel,
			   struct efx_rx_buffer *rx_buf,
			   unsigned int n_frags)
{
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	struct efx_rx_buffer *_rx_buf = rx_buf;
#endif

	do {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
		if (rx_buf->flags & EFX_RX_BUF_ZC)
			rx_buf->flags |= EFX_RX_BUF_XSK_REUSE;
		else
#endif
			efx_recycle_rx_buf(rx_queue, rx_buf);
		rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
	} while (--n_frags);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	if (channel->zc)
		efx_free_rx_buffers(efx_channel_get_rx_queue(channel), _rx_buf,
				    n_frags);
#endif
}
#else
struct page *efx_reuse_page(struct efx_rx_queue *rx_queue)
{
	(void)rx_queue;
	return NULL;
}

void efx_recycle_rx_pages(struct efx_channel *channel,
			  struct efx_rx_buffer *rx_buf,
			  unsigned int n_frags)
{
	(void) channel;
	(void) rx_buf;
	(void) n_frags;
}

void efx_discard_rx_packet(struct efx_channel *channel,
			   struct efx_rx_buffer *rx_buf,
			   unsigned int n_frags)
{
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);
	struct efx_rx_buffer *_rx_buf = rx_buf;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	if (channel->zc) {
		do {
			rx_buf->flags |= EFX_RX_BUF_XSK_REUSE;
			rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
		} while (--n_frags);
	}
#endif
	efx_free_rx_buffers(rx_queue, _rx_buf, n_frags);
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
static void efx_free_xsk_buffers(struct efx_rx_queue *rx_queue,
			 struct efx_rx_buffer *rx_buf,
			 unsigned int num_bufs)
{

	while (num_bufs) {
		xsk_buff_free(rx_buf->xsk_buf);
		rx_buf->xsk_buf = NULL;
		rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
		num_bufs--;
	}
}
#endif

static void efx_fini_rx_buffer_zc(struct efx_rx_queue *rx_queue,
				  struct efx_rx_buffer *rx_buf)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
	if (rx_buf->xsk_buf)
		efx_free_xsk_buffers(rx_queue, rx_buf, 1);
#else
	if (rx_buf->addr)
		efx_free_rx_buffers(rx_queue, rx_buf, 1);
#endif
}
#endif /* CONFIG_XDP_SOCKETS */
#endif

static void efx_fini_rx_buffer_nzc(struct efx_rx_queue *rx_queue,
				   struct efx_rx_buffer *rx_buf)
{
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	/* Release the page reference we hold for the buffer. */
	if (rx_buf->page)
		put_page(rx_buf->page);
#endif

	/* If this is the last buffer in a page, unmap and free it. */
	if (rx_buf->flags & EFX_RX_BUF_LAST_IN_PAGE) {
		efx_unmap_rx_buffer(rx_queue->efx, rx_buf);
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
		if (!(rx_buf->flags & EFX_RX_PAGE_IN_RECYCLE_RING))
#endif
			efx_free_rx_buffers(rx_queue, rx_buf, 1);
	}
	rx_buf->page = NULL;
}

static void efx_fini_rx_buffer(struct efx_rx_queue *rx_queue,
			       struct efx_rx_buffer *rx_buf)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	struct efx_channel *channel = efx_get_rx_queue_channel(rx_queue);

	if (channel->zc) {
#if defined(CONFIG_XDP_SOCKETS)
		efx_fini_rx_buffer_zc(rx_queue, rx_buf);
#endif
		return;
	}
#endif
	efx_fini_rx_buffer_nzc(rx_queue, rx_buf);
}

int efx_probe_rx_queue(struct efx_rx_queue *rx_queue)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned int entries;
	int rc;

	/* Create the smallest power-of-two aligned ring */
	entries = max(roundup_pow_of_two(efx->rxq_entries),
		      efx_min_dmaq_size(efx));
	EFX_WARN_ON_PARANOID(entries > efx_max_dmaq_size(efx));
	rx_queue->ptr_mask = entries - 1;

	netif_dbg(efx, probe, efx->net_dev,
		  "creating RX queue %d size %#x mask %#x\n",
		  efx_rx_queue_index(rx_queue), entries, rx_queue->ptr_mask);

	/* Allocate RX buffers */
	rx_queue->buffer = kcalloc(entries, sizeof(*rx_queue->buffer),
				   GFP_KERNEL);
	if (!rx_queue->buffer)
		return -ENOMEM;

	rc = efx_nic_probe_rx(rx_queue);
	if (rc) {
		kfree(rx_queue->buffer);
		rx_queue->buffer = NULL;
	}

	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_XSK_BUFFER_ALLOC)
#if defined(CONFIG_XDP_SOCKETS)
static void efx_zca_free(struct zero_copy_allocator *alloc,
			 unsigned long handle)
{
	struct efx_rx_queue *rx_queue =
		container_of(alloc, struct efx_rx_queue, zca);

	xsk_umem_fq_reuse(rx_queue->umem, handle & rx_queue->umem->chunk_mask);
}
#endif
#endif
#endif

int efx_init_rx_queue(struct efx_rx_queue *rx_queue)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
	struct efx_channel *channel = efx_get_rx_queue_channel(rx_queue);
#endif
#endif
	struct efx_nic *efx = rx_queue->efx;
	unsigned int max_fill, trigger, max_trigger;
	int rc;

	netif_dbg(rx_queue->efx, drv, rx_queue->efx->net_dev,
		  "initialising RX queue %d\n", efx_rx_queue_index(rx_queue));

	INIT_DELAYED_WORK(&rx_queue->slow_fill_work, efx_rx_slow_fill);

	/* Initialise ptr fields */
	rx_queue->added_count = 0;
	rx_queue->notified_count = 0;
	rx_queue->granted_count = 0;
	rx_queue->removed_count = 0;
	rx_queue->min_fill = -1U;
	rx_queue->failed_flush_count = 0;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	rx_queue->xsk_pool = NULL;
	if (channel->zc)
		rx_queue->xsk_pool = xsk_get_pool_from_qid(efx->net_dev,
							   rx_queue->core_index);
#else
	rx_queue->umem = NULL;
	if (channel->zc)
		rx_queue->umem = xdp_get_umem_from_qid(efx->net_dev,
						       rx_queue->core_index);
#endif
	if (channel->zc &&
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	    efx->rx_dma_len > xsk_pool_get_rx_frame_size(rx_queue->xsk_pool)) {
#else
	    efx->rx_dma_len > xsk_umem_get_rx_frame_size(rx_queue->umem)) {
#endif
#else
	    efx->rx_dma_len > (rx_queue->umem->chunk_mask + 1)) {
#endif
		netif_err(rx_queue->efx, drv, rx_queue->efx->net_dev,
			  "MTU and UMEM/POOL frame size not in sync\n. Required min. UMEM frame size = %u",
			  efx->rx_dma_len);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
#if defined(CONFIG_XDP_SOCKETS)
		rx_queue->xsk_pool = NULL;
#else
		rx_queue->umem = NULL;
#endif
#endif
		return -EINVAL;
	}
#endif /* CONFIG_XDP_SOCKETS */
#endif /*EFX_HAVE_XDP_SOCK */
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	efx_init_rx_recycle_ring(rx_queue);

	rx_queue->page_remove = 1;
	rx_queue->page_add = 0;
	rx_queue->page_recycle_count = 0;
	rx_queue->page_recycle_failed = 0;
	rx_queue->page_recycle_full = 0;
	rx_queue->page_repost_count = 0;
#endif

	/* Initialise limit fields */
	max_fill = rx_queue->ptr_mask + 1 - EFX_RXD_HEAD_ROOM;
	max_trigger =
		max_fill - efx->rx_pages_per_batch * efx->rx_bufs_per_page;
	if (rx_refill_threshold != 0) {
		trigger = max_fill * min(rx_refill_threshold, 100U) / 100U;
		if (trigger > max_trigger)
			trigger = max_trigger;
	} else {
		trigger = max_trigger;
	}

	rx_queue->max_fill = max_fill;
	rx_queue->fast_fill_trigger = trigger;
	rx_queue->refill_enabled = false;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
#if defined(CONFIG_XDP_SOCKETS)
	if (channel->zc)
		xsk_pool_set_rxq_info(rx_queue->xsk_pool,
				      &rx_queue->xdp_rxq_info);
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_RXQ_INFO)
	/* Initialise XDP queue information */
	rc = xdp_rxq_info_reg(&rx_queue->xdp_rxq_info, efx->net_dev,
			      rx_queue->core_index, 0);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
	if (!rc && channel->zc) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
		rc = xdp_rxq_info_reg_mem_model(&rx_queue->xdp_rxq_info,
						MEM_TYPE_XSK_BUFF_POOL,
						NULL);
#else
		rx_queue->zca.free = efx_zca_free;
		rc = xdp_rxq_info_reg_mem_model(&rx_queue->xdp_rxq_info,
						MEM_TYPE_ZERO_COPY,
						&rx_queue->zca);
#endif
	}
#endif
	if (rc)
		return rc;
#endif

	/* Set up RX descriptor ring */
	rc = efx_nic_init_rx(rx_queue);

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	if (!rc)
		rc = efx_ssr_init(rx_queue, efx);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_RXQ_INFO)
	if (rc)
		xdp_rxq_info_unreg(&rx_queue->xdp_rxq_info);
#endif

	return rc;
}

void efx_fini_rx_queue(struct efx_rx_queue *rx_queue)
{
	int i;
	struct efx_rx_buffer *rx_buf;

	netif_dbg(rx_queue->efx, drv, rx_queue->efx->net_dev,
		  "shutting down RX queue %d\n", efx_rx_queue_index(rx_queue));

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	efx_ssr_fini(rx_queue);
#endif

	efx_cancel_slow_fill(rx_queue);
	if (rx_queue->grant_credits)
		flush_work(&rx_queue->grant_work);

	/* Release RX buffers from the current read ptr to the write ptr */
	if (rx_queue->buffer) {
		for (i = rx_queue->removed_count; i < rx_queue->added_count;
		     i++) {
			unsigned int index = i & rx_queue->ptr_mask;

			rx_buf = efx_rx_buffer(rx_queue, index);
			efx_fini_rx_buffer(rx_queue, rx_buf);
		}
	}

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	efx_fini_rx_recycle_ring(rx_queue);
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_RXQ_INFO)
	if (xdp_rxq_info_is_reg(&rx_queue->xdp_rxq_info))
		xdp_rxq_info_unreg(&rx_queue->xdp_rxq_info);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	rx_queue->xsk_pool = NULL;
#else
	rx_queue->umem = NULL;
#endif
#endif
#endif
}

void efx_remove_rx_queue(struct efx_rx_queue *rx_queue)
{
	netif_dbg(rx_queue->efx, drv, rx_queue->efx->net_dev,
		  "removing RX queue %d\n", efx_rx_queue_index(rx_queue));

	efx_nic_remove_rx(rx_queue);
}

void efx_destroy_rx_queue(struct efx_rx_queue *rx_queue)
{
	netif_dbg(rx_queue->efx, drv, rx_queue->efx->net_dev,
		  "destroying RX queue %d\n", efx_rx_queue_index(rx_queue));

	kfree(rx_queue->buffer);
	rx_queue->buffer = NULL;
}

/* Unmap a DMA-mapped page.  This function is only called for the final RX
 * buffer in a page.
 */
void efx_unmap_rx_buffer(struct efx_nic *efx,
				struct efx_rx_buffer *rx_buf)
{
	struct page *page = rx_buf->page;

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	if (rx_buf->flags & EFX_RX_PAGE_IN_RECYCLE_RING)
		return;
#endif
	if (page) {
		struct efx_rx_page_state *state = page_address(page);

		dma_unmap_page(&efx->pci_dev->dev,
			       state->dma_addr,
			       PAGE_SIZE << efx->rx_buffer_order,
			       DMA_FROM_DEVICE);
	}
}

void efx_free_rx_buffers(struct efx_rx_queue *rx_queue,
			 struct efx_rx_buffer *rx_buf,
			 unsigned int num_bufs)
{
	while (num_bufs) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
		if (rx_buf->flags & EFX_RX_BUF_ZC) {
#if defined(CONFIG_XDP_SOCKETS)
			if (rx_buf->flags & EFX_RX_BUF_XSK_REUSE) {
				efx_reuse_rx_buffer_zc(rx_queue, rx_buf);
			} else {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
				rx_buf->xsk_buf = NULL;
#else
				rx_buf->addr = NULL;
#endif
				rx_buf->flags = 0;
			}
#endif
		} else if (rx_buf->page) {
#else
		if (rx_buf->page) {
#endif
			put_page(rx_buf->page);
			rx_buf->page = NULL;
		}
		rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
		--num_bufs;
	}
}

static void efx_rx_slow_fill(struct work_struct *data)
{
	struct efx_rx_queue *rx_queue =
		container_of(data, struct efx_rx_queue, slow_fill_work.work);

	/* Post an event to cause NAPI to run and refill the queue */
	if (efx_nic_generate_fill_event(rx_queue) != 0)
		efx_schedule_slow_fill(rx_queue);
	++rx_queue->slow_fill_count;
}

static void efx_schedule_slow_fill(struct efx_rx_queue *rx_queue)
{
	schedule_delayed_work(&rx_queue->slow_fill_work,
			      msecs_to_jiffies(1));
}

static void efx_cancel_slow_fill(struct efx_rx_queue *rx_queue)
{
	cancel_delayed_work_sync(&rx_queue->slow_fill_work);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_XSK_BUFFER_ALLOC)
static void efx_xdp_umem_discard_addr(struct xdp_umem *umem, bool slow)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_UMEM_RELEASE_ADDR)
	if (slow)
		xsk_umem_release_addr_rq(umem);
	else
		xsk_umem_release_addr(umem);
#else
	if (slow)
		xsk_umem_discard_addr_rq(umem);
	else
		xsk_umem_discard_addr(umem);
#endif
}

static bool efx_alloc_buffer_zc(struct efx_rx_queue *rx_queue,
				struct efx_rx_buffer *rx_buf, bool slow)
{
	struct xdp_umem *umem = rx_queue->umem;
	bool alloc_failed = true;
	u64 handle = 0;
	u64 hr;

	if (slow) {
		if (!xsk_umem_peek_addr_rq(umem, &handle))
			goto alloc_fail;
	} else {
		if (!xsk_umem_peek_addr(umem, &handle))
			goto alloc_fail;
	}
	alloc_failed = false;

	handle &= umem->chunk_mask;

	hr = umem->headroom + XDP_PACKET_HEADROOM;

	rx_buf->dma_addr = xdp_umem_get_dma(umem, handle);
	rx_buf->dma_addr += hr;

	rx_buf->addr = xdp_umem_get_data(umem, handle);
	rx_buf->addr += hr;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_XDP_SOCK) && defined(EFX_HAVE_XSK_OFFSET_ADJUST)
	rx_buf->handle = xsk_umem_adjust_offset(umem, handle, umem->headroom);
#endif
	efx_xdp_umem_discard_addr(umem, slow);


alloc_fail:
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_NEED_WAKEUP)
	if (xsk_umem_uses_need_wakeup(umem)) {
		if (alloc_failed)
			xsk_set_rx_need_wakeup(umem);
		else
			xsk_clear_rx_need_wakeup(umem);
	}
#endif
	return alloc_failed;
}
#else
static bool efx_alloc_buffer_zc(struct efx_rx_queue *rx_queue,
				struct efx_rx_buffer *rx_buf, bool slow)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	struct xsk_buff_pool *buff_pool = rx_queue->xsk_pool;
#else
	struct xdp_umem *buff_pool = rx_queue->umem;
#endif
	bool alloc_failed = false;
	struct xdp_buff *xsk_buf;

	xsk_buf = xsk_buff_alloc(buff_pool);
	if (!xsk_buf) {
		alloc_failed = true;
		goto alloc_fail;
	}
	rx_buf->dma_addr = xsk_buff_xdp_get_dma(xsk_buf);;
	xsk_buf->rxq = &rx_queue->xdp_rxq_info;
	rx_buf->xsk_buf = xsk_buf;

alloc_fail:
	return alloc_failed;
}
#endif

/**
 * efx_reuse_rx_buffer_zc - reuse a single zc rx_buf structure
 *
 * @rx_queue:           Efx RX queue
 * @rx_buf_reuse:       EFX RX buffer that can be reused
 * This will reuse zc buffer dma addresses.
 *
 */
static void efx_reuse_rx_buffer_zc(struct efx_rx_queue *rx_queue,
				   struct efx_rx_buffer *rx_buf_reuse)
{
	struct efx_nic *efx = rx_queue->efx;
	struct efx_rx_buffer *rx_buf;
	unsigned int index;

	index = rx_queue->added_count & rx_queue->ptr_mask;
	rx_buf = efx_rx_buffer(rx_queue, index);
	rx_buf->dma_addr = rx_buf_reuse->dma_addr;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
	rx_buf->xsk_buf = rx_buf_reuse->xsk_buf;
#else
	rx_buf->addr = rx_buf_reuse->addr;
	rx_buf->handle = rx_buf_reuse->handle;
#endif
	rx_buf_reuse->flags = 0;
	rx_buf->page_offset = 0;
	rx_buf->len = efx->rx_dma_len;
	rx_buf->flags = EFX_RX_BUF_ZC;
	rx_buf->vlan_tci = 0;
	++rx_queue->added_count;
}

/**
 * efx_init_rx_buffer_zc - inititalise a single zc rx_buf structure
 * @rx_queue:           Efx RX queue
 * @flags:              Flags field
 *
 * This will initialise a single rx_buf structure for use at the end of
 * the rx_buf array.
 *
 * WARNING: The page_offset calculated here must match with the value of
 * calculated by efx_rx_buffer_step().
 *
 * Return: a negative error code or 0 on success.
 */
static int efx_init_rx_buffer_zc(struct efx_rx_queue *rx_queue,
				 u16 flags)
{
	struct efx_rx_buffer *rx_buf;
	struct efx_nic *efx = rx_queue->efx;
	unsigned int index;
	bool slow = (rx_queue->added_count < rx_queue->ptr_mask);

	index = rx_queue->added_count & rx_queue->ptr_mask;
	rx_buf = efx_rx_buffer(rx_queue, index);
	if (rx_buf->flags & EFX_RX_BUF_XSK_REUSE)
		goto init_buf; /* can be reused at same index */
	if (!efx_alloc_buffer_zc(rx_queue, rx_buf, slow)) {
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_XSK_BUFFER_ALLOC)
		dma_sync_single_range_for_device(&efx->net_dev->dev,
						 rx_buf->dma_addr, 0,
						 efx->rx_dma_len,
						 DMA_BIDIRECTIONAL);
#endif
init_buf:
		++rx_queue->added_count;
		rx_buf->page_offset = 0;
		rx_buf->len = efx->rx_dma_len;
		rx_buf->flags = flags;
		rx_buf->vlan_tci = 0;
		return 0;
	}
	return -ENOMEM;
}
#endif /* CONFIG_XDP_SOCKETS */
#endif

/**
 * efx_init_rx_buffer - inititalise a single rx_buf structure
 *
 * @rx_queue:           Efx RX queue
 * @page:               Page to reference
 * @page_offset:        Page offset, expressed in efx->rx_page_buf_step
 *                      increments
 * @flags:              Flags field
 * This will initialise a single rx_buf structure for use at the end of
 * the rx_buf array.  It assumes the input page is initialised with the
 * efx_rx_page_state metadata necessary to correctly calculate dma addresses.
 *
 * WARNING: The page_offset calculated here must match with the value of
 * calculated by efx_rx_buffer_step().
 */
void efx_init_rx_buffer(struct efx_rx_queue *rx_queue,
				struct page *page,
				unsigned int page_offset,
				u16 flags)
{
	struct efx_rx_buffer *rx_buf;
	struct efx_nic *efx = rx_queue->efx;
	struct efx_rx_page_state *state;
	dma_addr_t dma_addr;
	unsigned int index;

	EFX_WARN_ON_ONCE_PARANOID(page_offset >
				  PAGE_SIZE << efx->rx_buffer_order);

	state = page_address(page);
	dma_addr = state->dma_addr;

	page_offset += sizeof(struct efx_rx_page_state);
	page_offset += XDP_PACKET_HEADROOM;

	index = rx_queue->added_count & rx_queue->ptr_mask;
	rx_buf = efx_rx_buffer(rx_queue, index);
	rx_buf->dma_addr = dma_addr + page_offset + efx->rx_ip_align;
	rx_buf->page = page;
	rx_buf->page_offset = ALIGN(page_offset + efx->rx_ip_align,
				    EFX_RX_BUF_ALIGNMENT);
	rx_buf->len = efx->rx_dma_len;
	rx_buf->flags = flags;
	rx_buf->vlan_tci = 0;
	++rx_queue->added_count;

	EFX_WARN_ON_PARANOID(rx_buf->page_offset + rx_buf->len >
			     PAGE_SIZE << efx->rx_buffer_order);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
/**
 * efx_init_rx_buffers_zc - create xsk_pool/umem->fq based RX buffers
 * @rx_queue:           Efx RX queue
 *
 * This allocates a buffers from xsk_pool/umem->fq using memory model alloc calls for
 * zero-copy RX, and populates struct efx_rx_buffers for each one.
 *
 * Return: a negative error code or 0 on success.
 */
static int efx_init_rx_buffers_zc(struct efx_rx_queue *rx_queue)
{
	u16 flags = 0;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	if (unlikely(!rx_queue->xsk_pool))
#else
	if (unlikely(!rx_queue->umem))
#endif
		return -EINVAL;
	if ((rx_queue->added_count - rx_queue->removed_count) <
	       rx_queue->ptr_mask) {
		flags = EFX_RX_BUF_ZC;
		return efx_init_rx_buffer_zc(rx_queue, flags);
	}

	return 0;
}
#endif /* CONFIG_XDP_SOCKETS */
#endif

/**
 * efx_init_rx_buffers_nzc - create EFX_RX_BATCH page-based RX buffers
 *
 * @rx_queue:	Efx RX queue
 * @atomic:	Perform atomic allocations
 *
 * This allocates a batch of pages, maps them for DMA, and populates struct
 * efx_rx_buffers for each one. If a single page can be used for multiple
 * buffers, then the page will either be inserted fully, or not at all.
 *
 * Return: a negative error code or 0 on success.
 */
static int efx_init_rx_buffers_nzc(struct efx_rx_queue *rx_queue, bool atomic)
{
	struct efx_nic *efx = rx_queue->efx;
	struct page *page;
	struct efx_rx_page_state *state;
	dma_addr_t dma_addr;
	unsigned int count;
	unsigned int i;
	unsigned int page_offset;
	u16 flags;

	count = 0;
	do {
		page_offset = 0;
		flags = 0;

		page = efx_reuse_page(rx_queue);

		if (!page) {
			/* GFP_ATOMIC may fail because of various reasons,
			 * and we re-schedule rx_fill from non-atomic
			 * context in such a case.  So, use __GFP_NO_WARN
			 * in case of atomic.
			 */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ALLOC_PAGES_NODE)
			struct efx_channel *channel;

			channel = efx_rx_queue_channel(rx_queue);
			page = alloc_pages_node(channel->irq_mem_node,
						__GFP_COMP |
#else
			page = alloc_pages(__GFP_COMP |
#endif
						(atomic ?
						 (GFP_ATOMIC | __GFP_NOWARN)
						 : GFP_KERNEL),
						efx->rx_buffer_order);
			if (unlikely(!page))
				return -ENOMEM;
			dma_addr =
				dma_map_page(&efx->pci_dev->dev, page, 0,
					     PAGE_SIZE << efx->rx_buffer_order,
					     DMA_FROM_DEVICE);
			if (unlikely(dma_mapping_error(&efx->pci_dev->dev,
						       dma_addr))) {
				__free_pages(page, efx->rx_buffer_order);
				return -EIO;
			}
			state = page_address(page);
			state->dma_addr = dma_addr;
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
		} else if (rx_queue->page_ring) {
			flags |= EFX_RX_PAGE_IN_RECYCLE_RING;
#endif
		}

		i = 0;
		do {
			if (i == efx->rx_bufs_per_page - 1)
				flags |= EFX_RX_BUF_LAST_IN_PAGE;
			efx_init_rx_buffer(rx_queue, page, page_offset, flags);
			page_offset += efx->rx_page_buf_step;
		} while (++i < efx->rx_bufs_per_page);
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
		/* We hold the only reference so just set to required count */
		page_ref_add(page, efx->rx_bufs_per_page);
#endif

	} while (++count < efx->rx_pages_per_batch);

	return 0;
}

static int efx_init_rx_buffers(struct efx_rx_queue *rx_queue, bool atomic)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
	struct efx_channel *channel = efx_get_rx_queue_channel(rx_queue);

	if (channel->zc)
		return efx_init_rx_buffers_zc(rx_queue);
#endif
#endif
	return efx_init_rx_buffers_nzc(rx_queue, atomic);
}

void efx_rx_config_page_split(struct efx_nic *efx)
{
	efx->rx_page_buf_step = efx_rx_buffer_step(efx);
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	efx->rx_bufs_per_page = efx->rx_buffer_order ? 1 :
		((PAGE_SIZE - sizeof(struct efx_rx_page_state)) /
		 efx->rx_page_buf_step);
#else
	efx->rx_bufs_per_page = 1;
#endif
	efx->rx_buffer_truesize = (PAGE_SIZE << efx->rx_buffer_order) /
		efx->rx_bufs_per_page;
	efx->rx_pages_per_batch = DIV_ROUND_UP(EFX_RX_PREFERRED_BATCH,
					       efx->rx_bufs_per_page);
}

/**
 * efx_fast_push_rx_descriptors - push new RX descriptors quickly
 * @rx_queue:	RX descriptor queue
 * @atomic:	Perform atomic allocations
 *
 * This will aim to fill the RX descriptor queue up to
 * @rx_queue->@max_fill. If there is insufficient atomic
 * memory to do so, a slow fill will be scheduled.
 *
 * The caller must provide serialisation (none is used here). In practise,
 * this means this function must run from the NAPI handler, or be called
 * when NAPI is disabled.
 */
void efx_fast_push_rx_descriptors(struct efx_rx_queue *rx_queue, bool atomic)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned int fill_level, batch_size;
	int space, rc = 0;

	if (!rx_queue->refill_enabled)
		return;

	/* Calculate current fill level, and exit if we don't need to fill */
	fill_level = (rx_queue->added_count - rx_queue->removed_count);
	EFX_WARN_ON_ONCE_PARANOID(fill_level > rx_queue->ptr_mask + 1);
	if (fill_level >= rx_queue->fast_fill_trigger)
		goto out;

	/* Record minimum fill level */
	if (unlikely(fill_level < rx_queue->min_fill)) {
		if (fill_level)
			rx_queue->min_fill = fill_level;
	}

	batch_size = efx->rx_pages_per_batch * efx->rx_bufs_per_page;
	space = rx_queue->max_fill - fill_level;
	EFX_WARN_ON_ONCE_PARANOID(space < batch_size);

	netif_vdbg(rx_queue->efx, rx_status, rx_queue->efx->net_dev,
		   "RX queue %d fast-filling descriptor ring from level %d to level %d\n",
		   efx_rx_queue_index(rx_queue), fill_level,
		   rx_queue->max_fill);

	while (space >= batch_size) {
		rc = efx_init_rx_buffers(rx_queue, atomic);
		if (unlikely(rc)) {
			/* Ensure that we don't leave the rx queue empty */
			efx_schedule_slow_fill(rx_queue);
			goto out;
		}
		space -= batch_size;
	}

	netif_vdbg(rx_queue->efx, rx_status, rx_queue->efx->net_dev,
		   "RX queue %d fast-filled descriptor ring to level %d\n",
		   efx_rx_queue_index(rx_queue),
		   rx_queue->added_count - rx_queue->removed_count);

out:
	if (rx_queue->notified_count != rx_queue->added_count)
		efx_nic_notify_rx_desc(rx_queue);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_GRO)

/* Pass a received packet up through GRO.  GRO can handle pages
 * regardless of checksum state and skbs with a good checksum.
 */
void
efx_rx_packet_gro(struct efx_rx_queue *rx_queue, struct efx_rx_buffer *rx_buf,
		  unsigned int n_frags, u8 *eh, __wsum csum)
{
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
#if IS_ENABLED(CONFIG_VLAN_8021Q) || defined(CONFIG_SFC_TRACING)
	struct efx_rx_buffer *head_buf = rx_buf;
#endif
	struct napi_struct *napi = &channel->napi_str;
	struct efx_nic *efx = channel->efx;
	struct sk_buff *skb;

	skb = napi_get_frags(napi);
	if (unlikely(!skb)) {
		efx_free_rx_buffers(rx_queue, rx_buf, n_frags);
		return;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RXHASH_SUPPORT)
	if (efx->net_dev->features & NETIF_F_RXHASH &&
	    efx_rx_buf_hash_valid(efx, eh))
		skb_set_hash(skb, efx_rx_buf_hash(efx, eh), PKT_HASH_TYPE_L4);
#endif
	if (csum) {
		skb->csum = csum;
		skb->ip_summed = CHECKSUM_COMPLETE;
	} else {
		skb->ip_summed = ((rx_buf->flags & EFX_RX_PKT_CSUMMED) ?
				  CHECKSUM_UNNECESSARY : CHECKSUM_NONE);
	}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CSUM_LEVEL)
	skb->csum_level = !!(rx_buf->flags & EFX_RX_PKT_CSUM_LEVEL);
#endif

	for (;;) {
		skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags,
				   rx_buf->page, rx_buf->page_offset,
				   rx_buf->len);
		rx_buf->page = NULL;
		skb->len += rx_buf->len;
		if (skb_shinfo(skb)->nr_frags == n_frags)
			break;

		rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
	}

	skb->data_len = skb->len;
	skb->truesize += n_frags * efx->rx_buffer_truesize;

	skb_record_rx_queue(skb, rx_queue->core_index);

	skb_mark_napi_id(skb, napi);

	efx_rx_skb_attach_timestamp(channel, skb,
			eh - efx->type->rx_prefix_size);
#if IS_ENABLED(CONFIG_VLAN_8021Q)
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_VLAN_RX_PATH)
	if (head_buf->flags & EFX_RX_BUF_VLAN_XTAG)
		__vlan_hwaccel_put_tag(napi->skb, htons(ETH_P_8021Q),
				       head_buf->vlan_tci);
#endif
#endif

#ifdef CONFIG_SFC_TRACING
	trace_sfc_receive(skb, true, head_buf->flags & EFX_RX_BUF_VLAN_XTAG,
			  head_buf->vlan_tci);
#endif
#if IS_ENABLED(CONFIG_VLAN_8021Q)
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_VLAN_RX_PATH)
	if (head_buf->flags & EFX_RX_BUF_VLAN_XTAG)
		vlan_gro_frags(napi, efx->vlan_group,
					    head_buf->vlan_tci);
	else
		/* fall through */
#endif
#endif
		napi_gro_frags(napi);
}

#endif /* EFX_USE_GRO */

/* RSS contexts.  We're using linked lists and crappy O(n) algorithms, because
 * (a) this is an infrequent control-plane operation and (b) n is small (max 64)
 */
struct efx_rss_context *efx_alloc_rss_context_entry(struct efx_nic *efx)
{
	struct list_head *head = &efx->rss_context.list;
	struct efx_rss_context *ctx, *new;
	u32 id = 1; /* Don't use zero, that refers to the master RSS context */

	WARN_ON(!mutex_is_locked(&efx->rss_lock));

	/* Search for first gap in the numbering */
	list_for_each_entry(ctx, head, list) {
		if (ctx->user_id != id)
			break;
		id++;
		/* Check for wrap.  If this happens, we have nearly 2^32
		 * allocated RSS contexts, which seems unlikely.
		 */
		if (WARN_ON_ONCE(!id))
			return NULL;
	}

	/* Create the new entry */
	new = kmalloc(sizeof(struct efx_rss_context), GFP_KERNEL);
	if (!new)
		return NULL;
	new->context_id = EFX_MCDI_RSS_CONTEXT_INVALID;
	new->flags = RSS_CONTEXT_FLAGS_DEFAULT;
#ifdef EFX_NOT_UPSTREAM
	new->num_queues = 0;
#endif

	/* Insert the new entry into the gap */
	new->user_id = id;
	list_add_tail(&new->list, &ctx->list);
	return new;
}

struct efx_rss_context *efx_find_rss_context_entry(struct efx_nic *efx, u32 id)
{
	struct list_head *head = &efx->rss_context.list;
	struct efx_rss_context *ctx;

	WARN_ON(!mutex_is_locked(&efx->rss_lock));

	list_for_each_entry(ctx, head, list)
		if (ctx->user_id == id)
			return ctx;
	return NULL;
}

void efx_free_rss_context_entry(struct efx_rss_context *ctx)
{
	list_del(&ctx->list);
	kfree(ctx);
}

void efx_set_default_rx_indir_table(struct efx_nic *efx,
		struct efx_rss_context *ctx)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ctx->rx_indir_table); i++)
		ctx->rx_indir_table[i] =
			ethtool_rxfh_indir_default(i, efx->rss_spread);
}

/**
 * efx_filter_is_mc_recipient - test whether spec is a multicast recipient
 * @spec: Specification to test
 *
 * Return: %true if the specification is a non-drop RX filter that
 * matches a local MAC address I/G bit value of 1 or matches a local
 * IPv4 or IPv6 address value in the respective multicast address
 * range, or is IPv4 broadcast.  Otherwise %false.
 */
bool efx_filter_is_mc_recipient(const struct efx_filter_spec *spec)
{
	if (!(spec->flags & EFX_FILTER_FLAG_RX) ||
	    spec->dmaq_id == EFX_FILTER_RX_DMAQ_ID_DROP)
		return false;

	if (spec->match_flags &
	    (EFX_FILTER_MATCH_LOC_MAC | EFX_FILTER_MATCH_LOC_MAC_IG) &&
	    is_multicast_ether_addr(spec->loc_mac))
		return true;

	if ((spec->match_flags &
	     (EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_LOC_HOST)) ==
	    (EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_LOC_HOST)) {
		if (spec->ether_type == htons(ETH_P_IP) &&
		    (ipv4_is_multicast(spec->loc_host[0]) ||
		     ipv4_is_lbcast(spec->loc_host[0])))
			return true;
		if (spec->ether_type == htons(ETH_P_IPV6) &&
		    ((const u8 *)spec->loc_host)[0] == 0xff)
			return true;
	}

	return false;
}

bool efx_filter_spec_equal(const struct efx_filter_spec *left,
			   const struct efx_filter_spec *right)
{
	if ((left->match_flags ^ right->match_flags) |
	    ((left->flags ^ right->flags) &
	     (EFX_FILTER_FLAG_RX | EFX_FILTER_FLAG_TX)))
		return false;

	return memcmp(&left->vport_id, &right->vport_id,
		      sizeof(struct efx_filter_spec) -
		      offsetof(struct efx_filter_spec, vport_id)) == 0;
}

u32 efx_filter_spec_hash(const struct efx_filter_spec *spec)
{
	BUILD_BUG_ON(offsetof(struct efx_filter_spec, vport_id) & 3);
	return jhash2((const u32 *)&spec->vport_id,
		      (sizeof(struct efx_filter_spec) -
		       offsetof(struct efx_filter_spec, vport_id)) / 4,
		      0);
}

#ifdef CONFIG_RFS_ACCEL
bool efx_rps_check_rule(struct efx_arfs_rule *rule, unsigned int filter_idx,
		bool *force)
{
	if (rule->filter_id == EFX_ARFS_FILTER_ID_PENDING) {
		/* ARFS is currently updating this entry, leave it */
		return false;
	}
	if (rule->filter_id == EFX_ARFS_FILTER_ID_ERROR) {
		/* ARFS tried and failed to update this, so it's probably out
		 * of date.  Remove the filter and the ARFS rule entry.
		 */
		rule->filter_id = EFX_ARFS_FILTER_ID_REMOVING;
		*force = true;
		return true;
	} else if (WARN_ON(rule->filter_id != filter_idx)) { /* can't happen */
		/* ARFS has moved on, so old filter is not needed.  Since we did
		 * not mark the rule with EFX_ARFS_FILTER_ID_REMOVING, it will
		 * not be removed by efx_rps_hash_del() subsequently.
		 */
		*force = true;
		return true;
	}
	/* Remove it iff ARFS wants to. */
	return true;
}

static
struct hlist_head *efx_rps_hash_bucket(struct efx_nic *efx,
				       const struct efx_filter_spec *spec)
{
	u32 hash = efx_filter_spec_hash(spec);

	WARN_ON(!spin_is_locked(&efx->rps_hash_lock));
	if (!efx->rps_hash_table)
		return NULL;
	return &efx->rps_hash_table[hash % EFX_ARFS_HASH_TABLE_SIZE];
}

struct efx_arfs_rule *efx_rps_hash_find(struct efx_nic *efx,
					const struct efx_filter_spec *spec)
{
	struct efx_arfs_rule *rule;
	struct hlist_head *head;
	struct hlist_node *node;

	head = efx_rps_hash_bucket(efx, spec);
	if (!head)
		return NULL;
	hlist_for_each(node, head) {
		rule = container_of(node, struct efx_arfs_rule, node);
		if (efx_filter_spec_equal(spec, &rule->spec))
			return rule;
	}
	return NULL;
}

struct efx_arfs_rule *efx_rps_hash_add(struct efx_nic *efx,
				       const struct efx_filter_spec *spec,
				       bool *new)
{
	struct efx_arfs_rule *rule;
	struct hlist_head *head;
	struct hlist_node *node;

	head = efx_rps_hash_bucket(efx, spec);
	if (!head)
		return NULL;
	hlist_for_each(node, head) {
		rule = container_of(node, struct efx_arfs_rule, node);
		if (efx_filter_spec_equal(spec, &rule->spec)) {
			*new = false;
			return rule;
		}
	}
	rule = kmalloc(sizeof(*rule), GFP_ATOMIC);
	*new = true;
	if (rule) {
		memcpy(&rule->spec, spec, sizeof(rule->spec));
		hlist_add_head(&rule->node, head);
	}
	return rule;
}

void efx_rps_hash_del(struct efx_nic *efx, const struct efx_filter_spec *spec)
{
	struct efx_arfs_rule *rule;
	struct hlist_head *head;
	struct hlist_node *node;

	head = efx_rps_hash_bucket(efx, spec);
	if (WARN_ON(!head))
		return;
	hlist_for_each(node, head) {
		rule = container_of(node, struct efx_arfs_rule, node);
		if (efx_filter_spec_equal(spec, &rule->spec)) {
			/* Someone already reused the entry.  We know that if
			 * this check doesn't fire (i.e. filter_id == REMOVING)
			 * then the REMOVING mark was put there by our caller,
			 * because caller is holding a lock on filter table and
			 * only holders of that lock set REMOVING.
			 */
			if (rule->filter_id != EFX_ARFS_FILTER_ID_REMOVING)
				return;
			hlist_del(node);
			kfree(rule);
			return;
		}
	}
	/* We didn't find it. */
	WARN_ON(1);
}
#endif

/* We're using linked lists and crappy O(n) algorithms, because
 * this is an infrequent control-plane operation, n is likely to be
 * small, and it gives good memory efficiency in the likely event n is
 * very small.
 */
static struct efx_ntuple_rule *efx_find_ntuple_rule(struct efx_nic *efx, u32 id)
{
	struct list_head *head = &efx->ntuple_list;
	struct efx_ntuple_rule *rule;

	list_for_each_entry(rule, head, list)
		if (rule->user_id == id)
			return rule;
	return NULL;
}

size_t efx_filter_count_ntuple(struct efx_nic *efx)
{
	struct list_head *head = &efx->ntuple_list, *l;
	size_t n = 0;

	list_for_each(l, head)
		++n;

	return n;
}

void efx_filter_get_ntuple_ids(struct efx_nic *efx, u32 *buf, u32 size)
{
	struct list_head *head = &efx->ntuple_list;
	struct efx_ntuple_rule *rule;
	size_t n = 0;

	list_for_each_entry(rule, head, list)
		if (n < size)
			buf[n++] = rule->user_id;
}

int efx_filter_ntuple_get(struct efx_nic *efx, u32 id,
			  struct efx_filter_spec *spec)
{
	struct efx_ntuple_rule *rule = efx_find_ntuple_rule(efx, id);

	if (!rule)
		return -ENOENT;

	*spec = rule->spec;

	return 0;
}

int efx_filter_ntuple_insert(struct efx_nic *efx, struct efx_filter_spec *spec)
{
	struct efx_ntuple_rule *gap = NULL, *rule, *new;
	struct list_head *head = &efx->ntuple_list;
	u32 id = 0;

	/* Search for first gap in the numbering */
	list_for_each_entry(rule, head, list) {
		/* is this rule here already? */
		if (efx_filter_spec_equal(&rule->spec, spec))
			return rule->user_id;

		/* if we haven't found a gap yet, see if there's one here */
		if (!gap) {
			if (rule->user_id != id) {
				gap = rule;
				continue;
			}

			id++;
		}
	}

	if (id >= efx_filter_get_rx_id_limit(efx))
		return -ENOSPC;

	/* Create the new entry */
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	if (efx_net_allocated(efx->state)) {
		int rc = efx->type->filter_insert(efx, spec, false);

		if (rc < 0) {
			kfree(new);
			return rc;
		}

		new->filter_id = rc;
	}

	new->spec = *spec;
	new->user_id = id;

	/* Insert the new entry into the gap (or tail if none) */
	list_add_tail(&new->list, gap ? &gap->list : head);

	return id;
}

int efx_filter_ntuple_remove(struct efx_nic *efx, u32 id)
{
	struct efx_ntuple_rule *rule = efx_find_ntuple_rule(efx, id);

	if (!rule)
		return -ENOENT;

	if (efx_net_allocated(efx->state))
		efx->type->filter_remove_safe(efx, EFX_FILTER_PRI_MANUAL,
					      rule->filter_id);

	list_del(&rule->list);
	kfree(rule);

	return 0;
}

void efx_filter_clear_ntuple(struct efx_nic *efx)
{
	struct list_head *head = &efx->ntuple_list;
	/* this only clears the structure, it doesn't remove filters,
	 * so should only be done when the interface is down
	 */
	WARN_ON(efx_net_allocated(efx->state));

	while (!list_empty(head)) {
		struct efx_ntuple_rule *rule =
			list_first_entry(head, struct efx_ntuple_rule, list);

		efx_filter_ntuple_remove(efx, rule->user_id);
	}
}

static void efx_filter_init_ntuple(struct efx_nic *efx)
{
	struct list_head *head = &efx->ntuple_list;
	struct efx_ntuple_rule *rule, *tmp;

	list_for_each_entry_safe(rule, tmp, head, list) {
		int rc = efx->type->filter_insert(efx, &rule->spec, false);

		if (rc >= 0) {
			rule->filter_id = rc;
		} else {
			/* if we couldn't insert, delete the entry */
			netif_err(efx, drv, efx->net_dev,
				  "error inserting ntuple filter ID %u\n",
				  rule->user_id);
			list_del(&rule->list);
			kfree(rule);
		}
	}
}

int efx_init_filters(struct efx_nic *efx)
{
	int rc = 0;

	mutex_lock(&efx->mac_lock);
	down_write(&efx->filter_sem);
	if (efx->type->filter_table_probe)
		rc = efx->type->filter_table_probe(efx);
	if (rc)
		goto out_unlock;

#ifdef CONFIG_RFS_ACCEL
	if (efx->net_dev->features & NETIF_F_NTUPLE) {
		struct efx_channel *channel;
		int i, success = 1;

		efx_for_each_channel(channel, efx) {
			channel->rps_flow_id =
				kcalloc(efx->type->max_rx_ip_filters,
					sizeof(*channel->rps_flow_id),
					GFP_KERNEL);
			if (!channel->rps_flow_id)
				success = 0;
			else
				for (i = 0;
				     i < efx->type->max_rx_ip_filters;
				     ++i)
					channel->rps_flow_id[i] =
						RPS_FLOW_ID_INVALID;
			channel->rfs_expire_index = 0;
			channel->rfs_filter_count = 0;
		}

		if (!success) {
			efx_for_each_channel(channel, efx) {
				kfree(channel->rps_flow_id);
				channel->rps_flow_id = NULL;
			}
			if (efx->type->filter_table_remove)
				efx->type->filter_table_remove(efx);
			rc = -ENOMEM;
			goto out_unlock;
		}
	}
#endif

out_unlock:
	up_write(&efx->filter_sem);
	mutex_unlock(&efx->mac_lock);

	if (!rc)
		efx_filter_init_ntuple(efx);

	return rc;
}

void efx_fini_filters(struct efx_nic *efx)
{
#ifdef CONFIG_RFS_ACCEL
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx) {
		cancel_delayed_work_sync(&channel->filter_work);
		kfree(channel->rps_flow_id);
		channel->rps_flow_id = NULL;
	}
#endif
	if (efx->type->filter_table_remove) {
		down_write(&efx->filter_sem);
		efx->type->filter_table_remove(efx);
		up_write(&efx->filter_sem);
	}
}

#ifdef CONFIG_RFS_ACCEL

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NEW_FLOW_KEYS)
static int efx_rfs_filter_spec(struct efx_nic *efx, const struct sk_buff *skb,
			       struct efx_filter_spec *spec)
{
	struct flow_keys fk;

	if (!skb_flow_dissect_flow_keys(skb, &fk, 0))
		return -EPROTONOSUPPORT;
	if (fk.basic.n_proto != htons(ETH_P_IP) &&
	    fk.basic.n_proto != htons(ETH_P_IPV6))
		return -EPROTONOSUPPORT;
#if !defined(EFX_USE_KCOMPAT) || defined(FLOW_DIS_IS_FRAGMENT)
	if (fk.control.flags & FLOW_DIS_IS_FRAGMENT)
		return -EPROTONOSUPPORT;
#endif

	spec->match_flags = EFX_FILTER_MATCH_FLAGS_RFS;
	spec->ether_type = fk.basic.n_proto;
	spec->ip_proto = fk.basic.ip_proto;

	if (fk.basic.n_proto == htons(ETH_P_IP)) {
		spec->rem_host[0] = fk.addrs.v4addrs.src;
		spec->loc_host[0] = fk.addrs.v4addrs.dst;
	} else {
		memcpy(spec->rem_host, &fk.addrs.v6addrs.src,
		       sizeof(struct in6_addr));
		memcpy(spec->loc_host, &fk.addrs.v6addrs.dst,
		       sizeof(struct in6_addr));
	}

	spec->rem_port = fk.ports.src;
	spec->loc_port = fk.ports.dst;
	return 0;
}

#else /* !EFX_HAVE_NEW_FLOW_KEYS */

/* The kernel flow dissector isn't up to the job, so use our own. */
static int efx_rfs_filter_spec(struct efx_nic *efx, const struct sk_buff *skb,
			       struct efx_filter_spec *spec)
{
	/* 60 octets is the maximum length of an IPv4 header (all IPv6 headers
	 * are 40 octets), and we pull 4 more to get the port numbers
	 */
	#define EFX_RFS_HEADER_LENGTH   (sizeof(struct vlan_hdr) + 60 + 4)
	unsigned char header[EFX_RFS_HEADER_LENGTH];
	int headlen = min_t(int, EFX_RFS_HEADER_LENGTH, skb->len);
	#undef EFX_RFS_HEADER_LENGTH
	void *hptr;
	const __be16 *ports;
	__be16 ether_type;
	int nhoff;

	hptr = skb_header_pointer(skb, 0, headlen, header);
	if (!hptr)
		return -EINVAL;

	if (skb->protocol == htons(ETH_P_8021Q)) {
		const struct vlan_hdr *vh = hptr;

		/* We can't filter on the IP 5-tuple and the vlan
		 * together, so just strip the vlan header and filter
		 * on the IP part.
		 */
		if (headlen < sizeof(*vh))
			return -EINVAL;
		ether_type = vh->h_vlan_encapsulated_proto;
		nhoff = sizeof(struct vlan_hdr);
	} else {
		ether_type = skb->protocol;
		nhoff = 0;
	}

	if (ether_type != htons(ETH_P_IP) && ether_type != htons(ETH_P_IPV6))
		return -EPROTONOSUPPORT;

	spec->match_flags = EFX_FILTER_MATCH_FLAGS_RFS;
	spec->ether_type = ether_type;

	if (ether_type == htons(ETH_P_IP)) {
		const struct iphdr *ip = hptr + nhoff;

		if (headlen < nhoff + sizeof(*ip))
			return -EINVAL;
		if (ip_is_fragment(ip))
			return -EPROTONOSUPPORT;
		spec->ip_proto = ip->protocol;
		spec->rem_host[0] = ip->saddr;
		spec->loc_host[0] = ip->daddr;
		if (headlen < nhoff + 4 * ip->ihl + 4)
			return -EINVAL;
		ports = (const __be16 *)(hptr + nhoff + 4 * ip->ihl);
	} else {
		const struct ipv6hdr *ip6 = (hptr + nhoff);

		if (headlen < nhoff + sizeof(*ip6) + 4)
			return -EINVAL;
		spec->ip_proto = ip6->nexthdr;
		memcpy(spec->rem_host, &ip6->saddr, sizeof(ip6->saddr));
		memcpy(spec->loc_host, &ip6->daddr, sizeof(ip6->daddr));
		ports = (const __be16 *)(ip6 + 1);
	}

	spec->rem_port = ports[0];
	spec->loc_port = ports[1];
	return 0;
}
#endif /* EFX_HAVE_NEW_FLOW_KEYS */

static void efx_filter_rfs_work(struct work_struct *data)
{
	struct efx_async_filter_insertion *req =
		container_of(data, struct efx_async_filter_insertion,
			     work);
	struct efx_nic *efx = efx_netdev_priv(req->net_dev);
	struct efx_channel *channel = efx_get_channel(efx, req->rxq_index);
	int slot_idx = req - efx->rps_slot;
	struct efx_arfs_rule *rule;
	u16 arfs_id = 0;
	int rc;

	rc = efx->type->filter_insert(efx, &req->spec, true);
	if (rc >= 0)
		/* Discard 'priority' part of EF10+ filter ID (mcdi_filters) */
		rc %= efx->type->max_rx_ip_filters;
	if (efx->rps_hash_table) {
		spin_lock_bh(&efx->rps_hash_lock);
		rule = efx_rps_hash_find(efx, &req->spec);
		/* The rule might have already gone, if someone else's request
		 * for the same spec was already worked and then expired before
		 * we got around to our work.  In that case we have nothing
		 * tying us to an arfs_id, meaning that as soon as the filter
		 * is considered for expiry it will be removed.
		 */
		if (rule) {
			if (rc < 0)
				rule->filter_id = EFX_ARFS_FILTER_ID_ERROR;
			else
				rule->filter_id = rc;
			arfs_id = rule->arfs_id;
		}
		spin_unlock_bh(&efx->rps_hash_lock);
	}
	if (rc >= 0) {
		/* Remember this so we can check whether to expire the filter
		 * later.
		 */
		mutex_lock(&efx->rps_mutex);
		if (channel->rps_flow_id[rc] == RPS_FLOW_ID_INVALID)
			channel->rfs_filter_count++;
		channel->rps_flow_id[rc] = req->flow_id;
		mutex_unlock(&efx->rps_mutex);

		if (req->spec.ether_type == htons(ETH_P_IP))
			netif_info(efx, rx_status, efx->net_dev,
				   "steering %s %pI4:%u:%pI4:%u to queue %u [flow %u filter %d id %u]\n",
				   (req->spec.ip_proto == IPPROTO_TCP) ?
					"TCP" : "UDP",
				   req->spec.rem_host,
				   ntohs(req->spec.rem_port),
				   req->spec.loc_host,
				   ntohs(req->spec.loc_port),
				   req->rxq_index, req->flow_id, rc, arfs_id);
		else
			netif_info(efx, rx_status, efx->net_dev,
				   "steering %s [%pI6]:%u:[%pI6]:%u to queue %u [flow %u filter %d id %u]\n",
				   (req->spec.ip_proto == IPPROTO_TCP) ?
					"TCP" : "UDP",
				   req->spec.rem_host,
				   ntohs(req->spec.rem_port),
				   req->spec.loc_host,
				   ntohs(req->spec.loc_port),
				   req->rxq_index, req->flow_id, rc, arfs_id);
		channel->n_rfs_succeeded++;
	} else {
		if (req->spec.ether_type == htons(ETH_P_IP))
			netif_dbg(efx, rx_status, efx->net_dev,
				  "failed to steer %s %pI4:%u:%pI4:%u to queue %u [flow %u rc %d id %u]\n",
				  (req->spec.ip_proto == IPPROTO_TCP) ? "TCP" : "UDP",
				  req->spec.rem_host, ntohs(req->spec.rem_port),
				  req->spec.loc_host, ntohs(req->spec.loc_port),
				  req->rxq_index, req->flow_id, rc, arfs_id);
		else
			netif_dbg(efx, rx_status, efx->net_dev,
				  "failed to steer %s [%pI6]:%u:[%pI6]:%u to queue %u [flow %u rc %d id %u]\n",
				  (req->spec.ip_proto == IPPROTO_TCP) ? "TCP" : "UDP",
				  req->spec.rem_host, ntohs(req->spec.rem_port),
				  req->spec.loc_host, ntohs(req->spec.loc_port),
				  req->rxq_index, req->flow_id, rc, arfs_id);
		channel->n_rfs_failed++;
		/* We're overloading the NIC's filter tables, so let's do a
		 * chunk of extra expiry work.
		 */
		__efx_filter_rfs_expire(channel, min(channel->rfs_filter_count,
						     100u));}

	/* Release references */
	clear_bit(slot_idx, &efx->rps_slot_map);
	dev_put(req->net_dev);

	return;
}

int efx_filter_rfs(struct net_device *net_dev, const struct sk_buff *skb,
		   u16 rxq_index, u32 flow_id)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	struct efx_async_filter_insertion *req;
	struct efx_arfs_rule *rule;
	int slot_idx;
	bool new;
	int rc;

	if (flow_id == RPS_FLOW_ID_INVALID)
		return -EINVAL;

	/* find a free slot */
	for (slot_idx = 0; slot_idx < EFX_RPS_MAX_IN_FLIGHT; slot_idx++)
		if (!test_and_set_bit(slot_idx, &efx->rps_slot_map))
			break;
	if (slot_idx >= EFX_RPS_MAX_IN_FLIGHT)
		return -EBUSY;

	req = efx->rps_slot + slot_idx;
	efx_filter_init_rx(&req->spec, EFX_FILTER_PRI_HINT,
			   efx->rx_scatter ? EFX_FILTER_FLAG_RX_SCATTER : 0,
			   rxq_index);
	rc = efx_rfs_filter_spec(efx, skb, &req->spec);
	if (rc < 0)
		goto out_clear;

	if (efx->rps_hash_table) {
		/* Add it to ARFS hash table */
		spin_lock(&efx->rps_hash_lock);
		rule = efx_rps_hash_add(efx, &req->spec, &new);
		if (!rule) {
			rc = -ENOMEM;
			goto out_unlock;
		}
		if (new)
			rule->arfs_id = efx->rps_next_id++ % RPS_NO_FILTER;
		rc = rule->arfs_id;
		/* Skip if existing or pending filter already does the right
		 * thing
		 */
		if (!new && rule->rxq_index == rxq_index &&
		    rule->filter_id >= EFX_ARFS_FILTER_ID_PENDING)
			goto out_unlock;
		rule->rxq_index = rxq_index;
		rule->filter_id = EFX_ARFS_FILTER_ID_PENDING;
		spin_unlock(&efx->rps_hash_lock);
	} else {
		/* Without an ARFS hash table, we just use arfs_id 0 for all
		 * filters.  This means if multiple flows hash to the same
		 * flow_id, all but the most recently touched will be eligible
		 * for expiry.
		 */
		rc = 0;
	}

	/* Queue the request */
	dev_hold(req->net_dev = net_dev);
	INIT_WORK(&req->work, efx_filter_rfs_work);
	req->rxq_index = rxq_index;
	req->flow_id = flow_id;
	schedule_work(&req->work);
	return rc;
out_unlock:
	spin_unlock(&efx->rps_hash_lock);
out_clear:
	clear_bit(slot_idx, &efx->rps_slot_map);
	return rc;
}

bool __efx_filter_rfs_expire(struct efx_channel *channel, unsigned int quota)
{
	bool (*expire_one)(struct efx_nic *efx, u32 flow_id,
			   unsigned int index);
	struct efx_nic *efx = channel->efx;
	unsigned int index, size, start;
	u32 flow_id;

	if (!mutex_trylock(&efx->rps_mutex))
		return false;
	expire_one = efx->type->filter_rfs_expire_one;
	index = channel->rfs_expire_index;
	start = index;
	size = efx->type->max_rx_ip_filters;
	while (quota) {
		flow_id = channel->rps_flow_id[index];

		if (flow_id != RPS_FLOW_ID_INVALID) {
			quota--;
			if (expire_one(efx, flow_id, index)) {
				netif_info(efx, rx_status, efx->net_dev,
					   "expired filter %d [queue %u flow %u]\n",
					   index, channel->channel, flow_id);
				channel->rps_flow_id[index] = RPS_FLOW_ID_INVALID;
				channel->rfs_filter_count--;
			}
		}
		if (++index == size)
			index = 0;
		/* If we were called with a quota that exceeds the total number
		 * of filters in the table (which shouldn't happen, but could
		 * if two callers race), ensure that we don't loop forever -
		 * stop when we've examined every row of the table.
		 */
		if (index == start)
			break;
	}
	channel->rfs_expire_index = index;

	mutex_unlock(&efx->rps_mutex);
	return true;
}

#endif /* CONFIG_RFS_ACCEL */

