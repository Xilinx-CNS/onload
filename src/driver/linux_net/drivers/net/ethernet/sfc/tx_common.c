/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include <linux/highmem.h>
#include "efx.h"
#include "nic.h"
#include "efx_common.h"
#include "tx_common.h"
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GSO_H)
#include <net/gso.h>
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
static struct sk_buff *efx_tx_vlan_sw(struct efx_tx_queue *tx_queue,
				      struct sk_buff *skb)
{
	if (skb_vlan_tag_present(skb)) {
		struct vlan_ethhdr *veth;
		int delta = 0;

		if (skb_headroom(skb) < VLAN_HLEN)
			delta = VLAN_HLEN - skb_headroom(skb);

		if (delta || skb_header_cloned(skb)) {
			int rc;

			/* pskb_expand_head will crash if skb_shared */
			if (skb_shared(skb)) {
				struct sk_buff *nskb = skb_clone(skb, GFP_ATOMIC);
				struct sock *sk = skb->sk;

				if (unlikely(!nskb))
					return ERR_PTR(-ENOMEM);

				if (sk)
					skb_set_owner_w(nskb, sk);
				consume_skb(skb);
				skb = nskb;
			}

			rc = pskb_expand_head(skb, ALIGN(delta, NET_SKB_PAD),
					      0, GFP_ATOMIC);
			if (rc) {
				dev_kfree_skb_any(skb);
				return NULL;
			}
		}

		veth = (struct vlan_ethhdr *)__skb_push(skb, VLAN_HLEN);
		/* Move the mac addresses to the beginning of the new header. */
		memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);
		veth->h_vlan_proto = htons(ETH_P_8021Q);
		veth->h_vlan_TCI = htons(skb_vlan_tag_get(skb));
		skb->protocol = htons(ETH_P_8021Q);

		skb->mac_header -= VLAN_HLEN;
		skb->vlan_tci = 0;
	}
	return skb;
}
#else
static struct sk_buff *efx_tx_vlan_noaccel(struct efx_tx_queue *tx_queue,
					   struct sk_buff *skb)
{
	if (skb_vlan_tag_present(skb)) {
		WARN_ONCE(1, "VLAN tagging requested, but no support\n");
		dev_kfree_skb_any(skb);
		return ERR_PTR(-EINVAL);
	}
	return skb;
}
#endif

static unsigned int efx_tx_cb_page_count(struct efx_tx_queue *tx_queue)
{
	return DIV_ROUND_UP(tx_queue->ptr_mask + 1, PAGE_SIZE >> tx_cb_order);
}

static bool efx_tx_cb_probe(struct efx_tx_queue *tx_queue)
{
	if (!tx_queue->efx->type->copy_break)
		return true;

	tx_queue->cb_page = kcalloc(efx_tx_cb_page_count(tx_queue),
				    sizeof(tx_queue->cb_page[0]), GFP_KERNEL);

	return !!tx_queue->cb_page;
}

static void efx_tx_cb_destroy(struct efx_tx_queue *tx_queue)
{
	unsigned int i;

	if (!tx_queue->efx->type->copy_break)
		return;

	if (tx_queue->cb_page) {
		for (i = 0; i < efx_tx_cb_page_count(tx_queue); i++)
			efx_nic_free_buffer(tx_queue->efx,
					    &tx_queue->cb_page[i]);
		kfree(tx_queue->cb_page);
		tx_queue->cb_page = NULL;
	}
}

int efx_probe_tx_queue(struct efx_tx_queue *tx_queue)
{
	struct efx_nic *efx = tx_queue->efx;
	unsigned int entries;
	int rc;

	/* Create the smallest power-of-two aligned ring */
	entries = max(roundup_pow_of_two(efx->txq_entries),
		      efx_min_dmaq_size(efx));
	EFX_WARN_ON_PARANOID(entries > efx_max_dmaq_size(efx));
	tx_queue->ptr_mask = entries - 1;

	netif_dbg(efx, probe, efx->net_dev,
		  "creating TX queue %d size %#x mask %#x\n",
		  tx_queue->queue, efx->txq_entries, tx_queue->ptr_mask);

	/* Allocate software ring */
	tx_queue->buffer = kcalloc(entries, sizeof(*tx_queue->buffer),
				   GFP_KERNEL);
	if (!tx_queue->buffer)
		return -ENOMEM;

	if (!efx_tx_cb_probe(tx_queue)) {
		rc = -ENOMEM;
		goto fail1;
	}

	/* Allocate hardware ring */
	rc = efx_nic_probe_tx(tx_queue);
	if (rc)
		goto fail2;

	return 0;

fail2:
	kfree(tx_queue->cb_page);
	tx_queue->cb_page = NULL;
fail1:
	kfree(tx_queue->buffer);
	tx_queue->buffer = NULL;
	return rc;
}

int efx_init_tx_queue(struct efx_tx_queue *tx_queue)
{
	struct efx_nic *efx = tx_queue->efx;

	netif_dbg(efx, drv, efx->net_dev,
		  "initialising TX queue %d\n", tx_queue->queue);

	/* must be the inverse of lookup in efx_get_tx_channel */
	tx_queue->core_txq =
		netdev_get_tx_queue(efx->net_dev,
				    tx_queue->channel->channel -
				    efx->tx_channel_offset);

	tx_queue->insert_count = 0;
	tx_queue->notify_count = 0;
	tx_queue->notify_jiffies = 0;
	tx_queue->write_count = 0;
	tx_queue->packet_write_count = 0;
	tx_queue->old_write_count = 0;
	tx_queue->read_count = 0;
	tx_queue->read_jiffies = 0;
	tx_queue->old_read_count = 0;
	tx_queue->empty_read_count = 0 | EFX_EMPTY_COUNT_VALID;
	tx_queue->xmit_pending = false;

	if (efx_ptp_use_mac_tx_timestamps(efx) &&
	    tx_queue->channel == efx_ptp_channel(efx))
		tx_queue->timestamping = true;
	else
		tx_queue->timestamping = false;
	tx_queue->completed_timestamp_major = 0;
	tx_queue->completed_timestamp_minor = 0;

	tx_queue->xdp_tx = efx_channel_is_xdp_tx(tx_queue->channel);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	tx_queue->xsk_pool = NULL;
	if (tx_queue->channel->zc &&
	    efx_is_xsk_tx_queue(tx_queue)) {
		tx_queue->xsk_pool =
			xsk_get_pool_from_qid(efx->net_dev,
					      tx_queue->channel->channel);
		if (!tx_queue->xsk_pool)
			return 0;
	}
#else
	tx_queue->umem = NULL;
	if (tx_queue->channel->zc &&
	    efx_is_xsk_tx_queue(tx_queue)) {
		tx_queue->umem =
			xdp_get_umem_from_qid(efx->net_dev,
					      tx_queue->channel->channel);
		if (!tx_queue->umem)
			return 0;
	}
#endif /* EFX_HAVE_XSK_POOL */
#endif /* CONFIG_XDP_SOCKETS */
#endif

	/* Set up default function pointers. These may get replaced by
	 * efx_nic_init_tx() based off NIC/queue capabilities.
	 */
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	tx_queue->handle_vlan = efx_tx_vlan_sw;
#else
	tx_queue->handle_vlan = efx_tx_vlan_noaccel;
#endif
	tx_queue->handle_tso = efx_nic_tx_tso_sw;

	/* Set up TX descriptor ring */
	return efx_nic_init_tx(tx_queue);
}

void efx_fini_tx_queue(struct efx_tx_queue *tx_queue)
{
	netif_dbg(tx_queue->efx, drv, tx_queue->efx->net_dev,
		  "shutting down TX queue %d\n", tx_queue->queue);

	if (!tx_queue->buffer)
		return;

	efx_purge_tx_queue(tx_queue);
	tx_queue->xmit_pending = false;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	tx_queue->xsk_pool = NULL;
#else
	tx_queue->umem = NULL;
#endif
	if (!efx_is_xsk_tx_queue(tx_queue))
#endif
#endif
		if (tx_queue->core_txq)
			netdev_tx_reset_queue(tx_queue->core_txq);
}

void efx_destroy_tx_queue(struct efx_tx_queue *tx_queue)
{
	netif_dbg(tx_queue->efx, drv, tx_queue->efx->net_dev,
		  "destroying TX queue %d\n", tx_queue->queue);

	efx_tx_cb_destroy(tx_queue);

	kfree(tx_queue->buffer);
	tx_queue->buffer = NULL;
}

void efx_purge_tx_queue(struct efx_tx_queue *tx_queue)
{
	while (tx_queue->read_count != tx_queue->insert_count) {
		unsigned int pkts_compl = 0, bytes_compl = 0;
		unsigned int efv_pkts_compl = 0;
		struct efx_tx_buffer *buffer =
			&tx_queue->buffer[tx_queue->read_count &
					  tx_queue->ptr_mask];

		efx_dequeue_buffer(tx_queue, buffer, &pkts_compl, &bytes_compl,
				   &efv_pkts_compl);
		++tx_queue->read_count;
	}
}

void efx_dequeue_buffer(struct efx_tx_queue *tx_queue,
			struct efx_tx_buffer *buffer,
			unsigned int *pkts_compl,
			unsigned int *bytes_compl,
			unsigned int *efv_pkts_compl)
{
	if (buffer->unmap_len) {
		struct device *dma_dev = &tx_queue->efx->pci_dev->dev;
		dma_addr_t unmap_addr = buffer->dma_addr - buffer->dma_offset;

		if (buffer->flags & EFX_TX_BUF_MAP_SINGLE)
			dma_unmap_single(dma_dev, unmap_addr, buffer->unmap_len,
					 DMA_TO_DEVICE);
		else
			dma_unmap_page(dma_dev, unmap_addr, buffer->unmap_len,
				       DMA_TO_DEVICE);
		buffer->unmap_len = 0;
	}

	if (buffer->flags & EFX_TX_BUF_SKB) {
		struct sk_buff *skb = (struct sk_buff *)buffer->skb;

		if (unlikely(buffer->flags & EFX_TX_BUF_EFV)) {
			EFX_WARN_ON_PARANOID(!efv_pkts_compl);
			(*efv_pkts_compl)++;
		} else {
			EFX_WARN_ON_PARANOID(!pkts_compl);
			EFX_WARN_ON_PARANOID(!bytes_compl);
			(*pkts_compl)++;
			(*bytes_compl) += skb->len;
		}

		if (tx_queue->timestamping &&
		    (tx_queue->completed_timestamp_major ||
		     tx_queue->completed_timestamp_minor)) {
			struct skb_shared_hwtstamps hwtstamp;

			hwtstamp.hwtstamp =
				efx_ptp_nic_to_kernel_time(tx_queue);
			skb_tstamp_tx(skb, &hwtstamp);

			tx_queue->completed_timestamp_major = 0;
			tx_queue->completed_timestamp_minor = 0;
		}

		dev_kfree_skb_any(skb);
		netif_vdbg(tx_queue->efx, tx_done, tx_queue->efx->net_dev,
			   "TX queue %d transmission id %x complete\n",
			   tx_queue->queue, tx_queue->read_count);
	} else if (buffer->flags & EFX_TX_BUF_HEAP) {
		kfree(buffer->buf);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_TX)
	} else if (buffer->flags & EFX_TX_BUF_XDP) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_FRAME_API)
		xdp_return_frame(buffer->xdpf);
#else
		page_frag_free(buffer->buf);
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
	} else if (buffer->flags & EFX_TX_BUF_XSK) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
		xsk_tx_completed(tx_queue->xsk_pool, 1);
#else
		xsk_umem_complete_tx(tx_queue->umem, 1);
#endif
#endif /* CONFIG_XDP_SOCKETS */
#endif
	}

	buffer->len = 0;
	buffer->flags = 0;
}

/* Remove packets from the TX queue
 *
 * This removes packets from the TX queue, up to and including the
 * specified index.
 */
static void efx_dequeue_buffers(struct efx_tx_queue *tx_queue,
				unsigned int index,
				unsigned int *pkts_compl,
				unsigned int *bytes_compl,
				unsigned int *efv_pkts_compl)
{
	struct efx_nic *efx = tx_queue->efx;
	unsigned int stop_index, read_ptr;

	stop_index = (index + 1) & tx_queue->ptr_mask;
	read_ptr = tx_queue->read_count & tx_queue->ptr_mask;

	while (read_ptr != stop_index) {
		struct efx_tx_buffer *buffer = &tx_queue->buffer[read_ptr];

		if (unlikely(!efx_tx_buffer_in_use(buffer))) {
			netif_err(efx, hw, efx->net_dev,
				  "TX queue %d spurious TX completion id %d\n",
				  tx_queue->queue, read_ptr);
			atomic_inc(&efx->errors.spurious_tx);
			if (efx->type->revision != EFX_REV_EF100) {
				efx_schedule_reset(efx, RESET_TYPE_TX_SKIP);
				return;
			}
		}

		efx_dequeue_buffer(tx_queue, buffer, pkts_compl, bytes_compl,
				   efv_pkts_compl);

		++tx_queue->read_count;
		tx_queue->read_jiffies = jiffies;
		read_ptr = tx_queue->read_count & tx_queue->ptr_mask;
	}
}

void efx_xmit_done_check_empty(struct efx_tx_queue *tx_queue)
{
	if ((int)(tx_queue->read_count - tx_queue->old_write_count) >= 0) {
		tx_queue->old_write_count = READ_ONCE(tx_queue->write_count);
		if (tx_queue->read_count == tx_queue->old_write_count) {
			smp_mb();
			tx_queue->empty_read_count =
				tx_queue->read_count | EFX_EMPTY_COUNT_VALID;
		}
	}
}

void efx_xmit_done(struct efx_tx_queue *tx_queue, unsigned int index)
{
	unsigned int pkts_compl = 0, efv_pkts_compl = 0, bytes_compl = 0;

	EFX_WARN_ON_ONCE_PARANOID(index > tx_queue->ptr_mask);

	efx_dequeue_buffers(tx_queue, index, &pkts_compl, &bytes_compl,
			    &efv_pkts_compl);
	tx_queue->pkts_compl += pkts_compl;
	tx_queue->bytes_compl += bytes_compl;

	if (pkts_compl + efv_pkts_compl > 1)
		++tx_queue->merge_events;
#if !defined(EFX_USE_KCOMPAT) || (defined(EFX_HAVE_XDP_SOCK) && defined(EFX_HAVE_XSK_NEED_WAKEUP))
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	if (tx_queue->xsk_pool && xsk_uses_need_wakeup(tx_queue->xsk_pool))
		xsk_set_tx_need_wakeup(tx_queue->xsk_pool);
#else
	if (tx_queue->umem && xsk_umem_uses_need_wakeup(tx_queue->umem))
		xsk_set_tx_need_wakeup(tx_queue->umem);
#endif
#endif
#endif

	efx_xmit_done_check_empty(tx_queue);
}

/* Remove buffers put into a tx_queue for the current packet.
 * None of the buffers must have an skb attached.
 */
void efx_enqueue_unwind(struct efx_tx_queue *tx_queue,unsigned int insert_count)
{
	struct efx_tx_buffer *buffer;

	/* Work backwards until we hit the original insert pointer value */
	while (tx_queue->insert_count != insert_count) {
		unsigned int pkts_compl = 0, bytes_compl = 0;
		unsigned int efv_pkts_compl = 0;

		--tx_queue->insert_count;
		buffer = __efx_tx_queue_get_insert_buffer(tx_queue);
		efx_dequeue_buffer(tx_queue, buffer, &pkts_compl, &bytes_compl,
				   &efv_pkts_compl);
	}
}

struct efx_tx_buffer *efx_tx_map_chunk(struct efx_tx_queue *tx_queue,
				       dma_addr_t dma_addr, size_t len)
{
	const struct efx_nic_type *nic_type = tx_queue->efx->type;
	struct efx_tx_buffer *buffer;
	unsigned int dma_len;

	/* Map the fragment taking account of NIC-dependent DMA limits. */
	do {
		buffer = __efx_tx_queue_get_insert_buffer(tx_queue);
#ifdef EFX_NOT_UPSTREAM
		/* In a single queue system we can get resource contention on
		 * the TX buffer array, if another thread has descheduled
		 * before incrementing the insert_count below.
		 * The IP stack should protect us from this, but on older
		 * kernels during ifdown it may not do so.
		 */
#endif
		if (unlikely(efx_tx_buffer_in_use(buffer))) {
			atomic_inc(&tx_queue->efx->errors.tx_desc_fetch);
			return NULL;
		}

		if (nic_type->tx_limit_len)
			dma_len = nic_type->tx_limit_len(tx_queue, dma_addr,
							 len);
		else
			dma_len = len;

		buffer->len = dma_len;
		buffer->dma_addr = dma_addr;
		buffer->flags = EFX_TX_BUF_CONT;
		len -= dma_len;
		dma_addr += dma_len;
		++tx_queue->insert_count;
	} while (len);

	return buffer;
}

int efx_tx_tso_header_length(struct sk_buff *skb)
{
	size_t header_len;

	if (skb->encapsulation)
		header_len = skb_inner_transport_header(skb) -
				skb->data +
				(inner_tcp_hdr(skb)->doff << 2u);
	else
		header_len = skb_transport_header(skb) - skb->data +
				(tcp_hdr(skb)->doff << 2u);
	return header_len;
}

/* Map all data from an SKB for DMA and create descriptors on the queue.
 */
int efx_tx_map_data(struct efx_tx_queue *tx_queue, struct sk_buff *skb,
		    unsigned int segment_count)
{
	struct efx_nic *efx = tx_queue->efx;
	struct device *dma_dev = &efx->pci_dev->dev;
	unsigned int frag_index, nr_frags;
	dma_addr_t dma_addr, unmap_addr;
	struct efx_tx_buffer *buffer;
	unsigned short dma_flags;
	size_t len, unmap_len;
#ifdef EFX_NOT_UPSTREAM
	/* Avoid -Wmaybe-uninitialised warning with gcc 4.8.5 */
	int header_len = 0;
#else
	int header_len;
#endif

	if (segment_count) {
		/* Ensure linear headers for TSO offload */
		header_len = efx_tx_tso_header_length(skb);

		if (header_len < 0)
			{
			/* We shouldn't have advertised encap TSO support,
			 * because this kernel doesn't have the bits we need
			 * to make it work.  So let's complain loudly.
			 */
			WARN_ON_ONCE(1);
			return -EINVAL;
		}
		if (unlikely(header_len > skb_headlen(skb))) {
			/* Pull headers into linear area */
			if (!pskb_may_pull(skb, header_len))
				return -ENOMEM;
		}
	}

	/* Map header data. */
	len = skb_headlen(skb);
	dma_addr = dma_map_single(dma_dev, skb->data, len, DMA_TO_DEVICE);
	dma_flags = EFX_TX_BUF_MAP_SINGLE;
	unmap_len = len;
	unmap_addr = dma_addr;

	if (unlikely(dma_mapping_error(dma_dev, dma_addr)))
		return -EIO;

	if (segment_count) {
		/* For TSO we need to put the header in to a separate
		 * descriptor. Map this separately if necessary.
		 */
		if (header_len != len) {
			buffer = efx_tx_map_chunk(tx_queue, dma_addr, header_len);
			if (!buffer)
				return -EBUSY;
			len -= header_len;
			dma_addr += header_len;
		}
	}

	/* Add descriptors for each fragment. */
	nr_frags = skb_shinfo(skb)->nr_frags;
	frag_index = 0;
	do {
		skb_frag_t *fragment;

		buffer = efx_tx_map_chunk(tx_queue, dma_addr, len);
		if (!buffer)
			return -EBUSY;

		/* The final descriptor for a fragment is responsible for
		 * unmapping the whole fragment.
		 */
		buffer->flags = EFX_TX_BUF_CONT | dma_flags;
		buffer->unmap_len = unmap_len;
		buffer->dma_offset = buffer->dma_addr - unmap_addr;

		if (frag_index >= nr_frags) {
			/* Store SKB details with the final buffer for
			 * the completion.
			 */
			buffer->skb = skb;
			buffer->flags = EFX_TX_BUF_SKB | dma_flags;
			return 0;
		}

		/* Move on to the next fragment. */
		fragment = &skb_shinfo(skb)->frags[frag_index++];
		len = skb_frag_size(fragment);
		dma_addr = skb_frag_dma_map(dma_dev, fragment,
				0, len, DMA_TO_DEVICE);
		dma_flags = 0;
		unmap_len = len;
		unmap_addr = dma_addr;

		if (unlikely(dma_mapping_error(dma_dev, dma_addr)))
			return -EIO;
	} while (1);

	if (netdev_xmit_more())
		/* There's another TX on the way. Prefetch next descriptor. */
		prefetchw(__efx_tx_queue_get_insert_buffer(tx_queue));
}

/*
 * Fallback to software TSO.
 *
 * This is used if we are unable to send a GSO packet through hardware TSO.
 * This should only ever happen due to per-queue restrictions - unsupported
 * packets should first be filtered by the feature flags and check_features.
 *
 * Returns 0 on success, error code otherwise.
 */
int efx_tx_tso_fallback(struct efx_tx_queue *tx_queue, struct sk_buff *skb)
{
	struct sk_buff *segments, *next;

	segments = skb_gso_segment(skb, 0);
	if (IS_ERR(segments))
		return PTR_ERR(segments);

	dev_consume_skb_any(skb);

	skb_list_walk_safe(segments, skb, next) {
		skb_mark_not_on_list(skb);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_SKB_XMIT_MORE)
		/* This explicitly sets the flag. Note that checks of this flag
		 * are buried in the netdev_xmit_more() kcompat macro.
		 */
		if (next)
			skb->xmit_more = true;
#endif
		efx_enqueue_skb(tx_queue, skb);
	}

	return 0;
}
