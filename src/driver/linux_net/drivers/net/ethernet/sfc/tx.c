/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2005-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/pci.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/slab.h>
#include <net/ipv6.h>
#include <linux/if_ether.h>
#if !defined(EFX_USE_KCOMPAT)
#include <linux/highmem.h>
#else
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/highmem.h>
#endif
#endif
#include <linux/moduleparam.h>
#include <linux/cache.h>
#include "net_driver.h"
#include "efx.h"
#include "io.h"
#include "nic.h"
#include "efx_common.h"
#include "tx.h"
#include "tx_common.h"
#include "workarounds.h"
#include "ef10_regs.h"
#ifdef CONFIG_SFC_TRACING
#include <trace/events/sfc.h>
#endif

/* Size of page-based copy buffers, used for TSO headers (normally),
 * padding and linearisation.
 *
 * Must be power-of-2 before subtracting NET_IP_ALIGN.  Values much
 * less than 128 are fairly useless; values larger than EFX_PAGE_SIZE
 * or PAGE_SIZE would be harder to support.
 */
#define TX_CB_ORDER_MIN	4
#define TX_CB_ORDER_MAX	min(12, PAGE_SHIFT)
#define TX_CB_ORDER_DEF	7
static unsigned int tx_cb_order __read_mostly = TX_CB_ORDER_DEF;
static unsigned int
tx_cb_size __read_mostly = (1 << TX_CB_ORDER_DEF) - NET_IP_ALIGN;

#if defined(EFX_NOT_UPSTREAM)
static int __init
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NON_CONST_KERNEL_PARAM)
tx_copybreak_set(const char *val, const struct kernel_param *kp)
#else
tx_copybreak_set(const char *val, struct kernel_param *kp)
#endif
{
	int rc;

	rc = param_set_uint(val, kp);
	if (rc)
		return rc;

	/* If disabled, copy buffers are still needed for VLAN tag insertion */
	if (!tx_cb_size) {
		tx_cb_order = TX_CB_ORDER_MIN;
		return 0;
	}

	tx_cb_order = order_base_2(tx_cb_size + NET_IP_ALIGN);
	if (tx_cb_order < TX_CB_ORDER_MIN)
		tx_cb_order = TX_CB_ORDER_MIN;
	else if (tx_cb_order > TX_CB_ORDER_MAX)
		tx_cb_order = TX_CB_ORDER_MAX;
	tx_cb_size = (1 << tx_cb_order) - NET_IP_ALIGN;
	return 0;
}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_KERNEL_PARAM_OPS)
static const struct kernel_param_ops tx_copybreak_ops = {
	.set = tx_copybreak_set,
	.get = param_get_uint,
};
module_param_cb(tx_copybreak, &tx_copybreak_ops, &tx_cb_size, 0444);
#else
module_param_call(tx_copybreak, tx_copybreak_set, param_get_uint,
		  &tx_cb_size, 0444);
#endif
MODULE_PARM_DESC(tx_copybreak,
		 "Maximum size of packet that may be copied to a new buffer on transmit, minimum is 16 bytes or 0 to disable (uint)");
#endif /* EFX_NOT_UPSTREAM */

#ifdef EFX_USE_PIO

#define EFX_PIOBUF_SIZE_DEF ALIGN(256, L1_CACHE_BYTES)
unsigned int efx_piobuf_size __read_mostly = EFX_PIOBUF_SIZE_DEF;

#ifdef EFX_NOT_UPSTREAM
/* The size of the on-hardware buffer should always be at least this big;
 * it might be bigger but that's ok.
 */
#define EFX_PIOBUF_SIZE_MAX ER_DZ_TX_PIOBUF_SIZE

static int __init
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_NON_CONST_KERNEL_PARAM)
efx_piobuf_size_set(const char *val, const struct kernel_param *kp)
#else
efx_piobuf_size_set(const char *val, struct kernel_param *kp)
#endif
{
	int rc;

	rc = param_set_uint(val, kp);
	if (rc)
		return rc;

	BUILD_BUG_ON(EFX_PIOBUF_SIZE_DEF > EFX_PIOBUF_SIZE_MAX);

	efx_piobuf_size = min_t(unsigned int,
				ALIGN(efx_piobuf_size, L1_CACHE_BYTES),
				EFX_PIOBUF_SIZE_MAX);
	return 0;
}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_KERNEL_PARAM_OPS)
static const struct kernel_param_ops efx_piobuf_size_ops = {
	.set = efx_piobuf_size_set,
	.get = param_get_uint,
};
module_param_cb(piobuf_size, &efx_piobuf_size_ops, &efx_piobuf_size, 0444);
#else
module_param_call(piobuf_size, efx_piobuf_size_set, param_get_uint,
		  &efx_piobuf_size, 0444);
#endif
MODULE_PARM_DESC(piobuf_size,
		 "[SFC9100-family] Maximum size of packet that may be copied to a PIO buffer on transmit (uint)");
#endif /* EFX_NOT_UPSTREAM */

#endif /* EFX_USE_PIO */

static inline u8 *efx_tx_get_copy_buffer(struct efx_tx_queue *tx_queue,
					 struct efx_tx_buffer *buffer)
{
	unsigned int index = efx_tx_queue_get_insert_index(tx_queue);
	struct efx_buffer *page_buf =
		&tx_queue->cb_page[index >> (PAGE_SHIFT - tx_cb_order)];
	unsigned int offset =
		((index << tx_cb_order) + NET_IP_ALIGN) & (PAGE_SIZE - 1);

	if (unlikely(!page_buf->addr) &&
	    efx_nic_alloc_buffer(tx_queue->efx, page_buf, PAGE_SIZE,
				 GFP_ATOMIC))
		return NULL;
	buffer->dma_addr = page_buf->dma_addr + offset;
	buffer->unmap_len = 0;
	return (u8 *)page_buf->addr + offset;
}

u8 *efx_tx_get_copy_buffer_limited(struct efx_tx_queue *tx_queue,
				   struct efx_tx_buffer *buffer, size_t len)
{
	if (len > tx_cb_size)
		return NULL;
	return efx_tx_get_copy_buffer(tx_queue, buffer);
}

static void efx_tx_maybe_stop_queue(struct efx_tx_queue *txq1)
{
	/* We need to consider both queues that the net core sees as one */
	struct efx_tx_queue *txq2;
	struct efx_nic *efx = txq1->efx;
	unsigned int fill_level;

	fill_level = efx_channel_tx_fill_level(txq1->channel);
	if (likely(fill_level < efx->txq_stop_thresh))
		return;

	/* We used the stale old_read_count above, which gives us a
	 * pessimistic estimate of the fill level (which may even
	 * validly be >= efx->txq_entries).  Now try again using
	 * read_count (more likely to be a cache miss).
	 *
	 * If we read read_count and then conditionally stop the
	 * queue, it is possible for the completion path to race with
	 * us and complete all outstanding descriptors in the middle,
	 * after which there will be no more completions to wake it.
	 * Therefore we stop the queue first, then read read_count
	 * (with a memory barrier to ensure the ordering), then
	 * restart the queue if the fill level turns out to be low
	 * enough.
	 */
	netif_tx_stop_queue(txq1->core_txq);
	smp_mb();
	efx_for_each_channel_tx_queue(txq2, txq1->channel)
		txq2->old_read_count = READ_ONCE(txq2->read_count);

	fill_level = efx_channel_tx_fill_level(txq1->channel);
	EFX_WARN_ON_ONCE_PARANOID(fill_level >= efx->txq_entries);
	if (likely(fill_level < efx->txq_stop_thresh)) {
		smp_mb();
		if (likely(!efx->loopback_selftest))
			netif_tx_start_queue(txq1->core_txq);
	}
}

static int efx_enqueue_skb_copy(struct efx_tx_queue *tx_queue,
				struct sk_buff *skb)
{
	unsigned int copy_len = skb->len;
	struct efx_tx_buffer *buffer;
	u8 *copy_buffer;
	int rc;

	EFX_WARN_ON_ONCE_PARANOID(copy_len > tx_cb_size);

	buffer = efx_tx_queue_get_insert_buffer(tx_queue);

	copy_buffer = efx_tx_get_copy_buffer(tx_queue, buffer);
	if (unlikely(!copy_buffer))
		return -ENOMEM;

	rc = skb_copy_bits(skb, 0, copy_buffer, copy_len);
	EFX_WARN_ON_PARANOID(rc);
	buffer->len = copy_len;

	buffer->skb = skb;
	buffer->flags = EFX_TX_BUF_SKB;

	++tx_queue->insert_count;
	return rc;
}

#ifdef EFX_USE_PIO

struct efx_short_copy_buffer {
	int used;
	u8 buf[L1_CACHE_BYTES];
};

/* Copy in explicit 64-bit writes. */
static void efx_memcpy_64(void __iomem *dest, void *src, size_t len)
{
	u64 *src64 = src;
	u64 __iomem *dest64 = dest;
	size_t l64 = len / 8;
	size_t i;

	WARN_ON_ONCE(len % 8 != 0);
	WARN_ON_ONCE(((u8 __iomem *) dest - (u8 __iomem *) 0) % 8 != 0);

	for(i = 0; i < l64; i++)
		writeq(src64[i], &dest64[i]);
}

/* Copy to PIO, respecting that writes to PIO buffers must be dword aligned.
 * Advances piobuf pointer. Leaves additional data in the copy buffer.
 */
static void efx_memcpy_toio_aligned(struct efx_nic *efx, u8 __iomem **piobuf,
				    u8 *data, int len,
				    struct efx_short_copy_buffer *copy_buf)
{
	int block_len = len & ~(sizeof(copy_buf->buf) - 1);

	efx_memcpy_64(*piobuf, data, block_len);
	*piobuf += block_len;
	len -= block_len;

	if (len) {
		data += block_len;
		BUG_ON(copy_buf->used);
		BUG_ON(len > sizeof(copy_buf->buf));
		memcpy(copy_buf->buf, data, len);
		copy_buf->used = len;
	}
}

/* Copy to PIO, respecting dword alignment, popping data from copy buffer first.
 * Advances piobuf pointer. Leaves additional data in the copy buffer.
 */
static void efx_memcpy_toio_aligned_cb(struct efx_nic *efx, u8 __iomem **piobuf,
				       u8 *data, int len,
				       struct efx_short_copy_buffer *copy_buf)
{
	if (copy_buf->used) {
		/* if the copy buffer is partially full, fill it up and write */
		int copy_to_buf =
			min_t(int, sizeof(copy_buf->buf) - copy_buf->used, len);

		memcpy(copy_buf->buf + copy_buf->used, data, copy_to_buf);
		copy_buf->used += copy_to_buf;

		/* if we didn't fill it up then we're done for now */
		if (copy_buf->used < sizeof(copy_buf->buf))
			return;

		efx_memcpy_64(*piobuf, copy_buf->buf, sizeof(copy_buf->buf));
		*piobuf += sizeof(copy_buf->buf);
		data += copy_to_buf;
		len -= copy_to_buf;
		copy_buf->used = 0;
	}

	efx_memcpy_toio_aligned(efx, piobuf, data, len, copy_buf);
}

static void efx_flush_copy_buffer(struct efx_nic *efx, u8 __iomem *piobuf,
				  struct efx_short_copy_buffer *copy_buf)
{
	/* if there's anything in it, write the whole buffer, including junk */
	if (copy_buf->used)
		efx_memcpy_64(piobuf, copy_buf->buf, sizeof(copy_buf->buf));
}

/* Traverse skb structure and copy fragments in to PIO buffer.
 * Advances piobuf pointer.
 */
static void efx_skb_copy_bits_to_pio(struct efx_nic *efx, struct sk_buff *skb,
				     u8 __iomem **piobuf,
				     struct efx_short_copy_buffer *copy_buf)
{
	int i;

	efx_memcpy_toio_aligned(efx, piobuf, skb->data, skb_headlen(skb),
				copy_buf);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		u8 *vaddr;

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_KMAP_ATOMIC)
#ifdef CONFIG_HIGHMEM
		BUG_ON(in_irq());
		local_bh_disable();
#endif
		vaddr = kmap_atomic(skb_frag_page(f), KM_SKB_DATA_SOFTIRQ);
#else
		vaddr = kmap_atomic(skb_frag_page(f));
#endif

		efx_memcpy_toio_aligned_cb(efx, piobuf, vaddr + skb_frag_off(f),
					   skb_frag_size(f), copy_buf);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_KMAP_ATOMIC)
		kunmap_atomic(vaddr, KM_SKB_DATA_SOFTIRQ);
#ifdef CONFIG_HIGHMEM
		local_bh_enable();
#endif
#else
		kunmap_atomic(vaddr);
#endif
	}

	EFX_WARN_ON_ONCE_PARANOID(skb_shinfo(skb)->frag_list);
}

static int efx_enqueue_skb_pio(struct efx_tx_queue *tx_queue,
			       struct sk_buff *skb)
{
	struct efx_tx_buffer *buffer =
		efx_tx_queue_get_insert_buffer(tx_queue);
	u8 __iomem *piobuf = tx_queue->piobuf;

	/* Copy to PIO buffer. Ensure the writes are padded to the end
	 * of a cache line, as this is required for write-combining to be
	 * effective on at least x86.
	 */
#ifdef EFX_USE_KCOMPAT
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0) && defined(CONFIG_SLOB)
	#error "This function doesn't work with SLOB and Linux < 3.4"
	/* SLOB is for tiny embedded systems; you probably want SLAB */
#endif
#endif

	if (skb_shinfo(skb)->nr_frags) {
		/* The size of the copy buffer will ensure all writes
		 * are the size of a cache line.
		 */
		struct efx_short_copy_buffer copy_buf;

		copy_buf.used = 0;

		efx_skb_copy_bits_to_pio(tx_queue->efx, skb,
					 &piobuf, &copy_buf);
		efx_flush_copy_buffer(tx_queue->efx, piobuf, &copy_buf);
	} else {
		/* Pad the write to the size of a cache line.
		 * We can do this because we know the skb_shared_info struct is
		 * after the source, and the destination buffer is big enough.
		 */
		BUILD_BUG_ON(L1_CACHE_BYTES >
			     SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
		efx_memcpy_64(tx_queue->piobuf, skb->data,
			      ALIGN(skb->len, L1_CACHE_BYTES));
	}

	buffer->skb = skb;
	buffer->flags = EFX_TX_BUF_SKB | EFX_TX_BUF_OPTION;

	EFX_POPULATE_QWORD_5(buffer->option,
			     ESF_DZ_TX_DESC_IS_OPT, 1,
			     ESF_DZ_TX_OPTION_TYPE, 1 /* PIO */,
			     ESF_DZ_TX_PIO_CONT, 0,
			     ESF_DZ_TX_PIO_BYTE_CNT, skb->len,
			     ESF_DZ_TX_PIO_BUF_ADDR,
			     tx_queue->piobuf_offset);
	++tx_queue->insert_count;
	return 0;
}

/* Decide whether we can use TX PIO, ie. write packet data directly into
 * a buffer on the device.  This can reduce latency at the expense of
 * throughput, so we only do this if both hardware and software TX rings
 * are empty, including all queues for the channel.  This also ensures that
 * only one packet at a time can be using the PIO buffer. If the xmit_more
 * flag is set then we don't use this - there'll be another packet along
 * shortly and we want to hold off the doorbell.
 */
static inline bool efx_tx_may_pio(struct efx_channel *channel,
				  struct efx_tx_queue *tx_queue,
				  struct sk_buff *skb)
{
	bool empty = true;

	if (!tx_queue->piobuf || (skb->len > efx_piobuf_size) ||
	    netdev_xmit_more())
		return false;

	EFX_WARN_ON_ONCE_PARANOID(!channel->efx->type->option_descriptors);

	efx_for_each_channel_tx_queue(tx_queue, channel) {
		empty = empty &&
			__efx_nic_tx_is_empty(tx_queue,
					      tx_queue->packet_write_count);
	}

	return empty;
}
#endif /* EFX_USE_PIO */

/* Send any pending traffic for a channel. xmit_more is shared across all
 * queues for a channel, so we must check all of them.
 */
static void efx_tx_send_pending(struct efx_channel *channel)
{
	struct efx_tx_queue *q;

	efx_for_each_channel_tx_queue(q, channel) {
		if (q->xmit_pending)
			efx_nic_push_buffers(q);
	}
}

/*
 * Add a socket buffer to a TX queue
 *
 * This maps all fragments of a socket buffer for DMA and adds them to
 * the TX queue.  The queue's insert pointer will be incremented by
 * the number of fragments in the socket buffer.
 *
 * If any DMA mapping fails, any mapped fragments will be unmapped,
 * the queue's insert pointer will be restored to its original value.
 *
 * This function is split out from efx_hard_start_xmit to allow the
 * loopback test to direct packets via specific TX queues.
 *
 * Returns 0 on success, error code otherwise.
 * You must hold netif_tx_lock() to call this function.
 */
int efx_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb)
{
	unsigned int old_insert_count = tx_queue->insert_count;
	bool xmit_more = netdev_xmit_more();
	struct efx_channel *channel;
	bool data_mapped = false;
	unsigned int segments;
	unsigned int skb_len;
	int rc = 0;

	channel = tx_queue->channel;

	/* We're pretty likely to want a descriptor to do this tx. */
	prefetchw(__efx_tx_queue_get_insert_buffer(tx_queue));

	EFX_WARN_ON_ONCE_PARANOID(!tx_queue->handle_vlan);
	skb = tx_queue->handle_vlan(tx_queue, skb);
	if (IS_ERR_OR_NULL(skb))
		goto err;

	/* Copy the length *after* VLAN handling, in case we've inserted a
	 * tag in software.
	 */
	skb_len = skb->len;
	segments = skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 0;
	if (segments == 1)
		segments = 0; /* Don't use TSO for a single segment. */

	/* Handle TSO first - it's *possible* (although unlikely) that we might
	 * be passed a packet to segment that's smaller than the copybreak/PIO
	 * size limit.
	 */
	if (segments) {
		EFX_WARN_ON_ONCE_PARANOID(!tx_queue->handle_tso);
		rc = tx_queue->handle_tso(tx_queue, skb, &data_mapped);
		if (rc == -EINVAL) {
			rc = efx_tx_tso_fallback(tx_queue, skb);
			tx_queue->tso_fallbacks++;
			if (rc == 0)
				return 0;
		}
		if (rc)
			goto err;
#ifdef EFX_USE_PIO
	} else if (efx_tx_may_pio(channel, tx_queue, skb)) {
		/* Use PIO for short packets with an empty queue. */
		rc = efx_enqueue_skb_pio(tx_queue, skb);
		if (rc)
			goto err;
		tx_queue->pio_packets++;
		data_mapped = true;
#endif
	} else if (skb->data_len && skb_len <= tx_cb_size) {
		/* Coalesce short fragmented packets. */
		rc = efx_enqueue_skb_copy(tx_queue, skb);
		if (rc)
			goto err;
		tx_queue->cb_packets++;
		data_mapped = true;
	}

	/* Map for DMA and create descriptors if we haven't done so already. */
	if (!data_mapped) {
		rc = efx_tx_map_data(tx_queue, skb, segments);
		if (rc)
			goto err;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_TX_TIMESTAMP)
	skb_tx_timestamp(skb);
#endif

	efx_tx_maybe_stop_queue(tx_queue);

	tx_queue->xmit_pending = true;

	/* Pass to hardware. */
	if (__netdev_tx_sent_queue(tx_queue->core_txq, skb->len, xmit_more))
		efx_tx_send_pending(channel);
	else
		/* There's another TX on the way. Prefetch next descriptor. */
		prefetchw(__efx_tx_queue_get_insert_buffer(tx_queue));

	if (segments) {
		tx_queue->tso_bursts++;
		tx_queue->tso_packets += segments;
		tx_queue->tx_packets  += segments;
	} else {
		tx_queue->tx_packets++;
	}
	tx_queue->tx_bytes += skb_len;

	return 0;

err:
	efx_enqueue_unwind(tx_queue, old_insert_count);
	if (!IS_ERR_OR_NULL(skb))
		dev_kfree_skb_any(skb);

	/* If we're not expecting another transmit and we had something to push
	 * on this queue or a partner queue then we need to push here to get the
	 * previous packets out.
	 */
	if (!xmit_more)
		efx_tx_send_pending(channel);

	return rc;
}

/* Initiate a packet transmission.  We use one channel per CPU
 * (sharing when we have more CPUs than channels).  On Falcon, the TX
 * completion events will be directed back to the CPU that transmitted
 * the packet, which should be cache-efficient.
 *
 * Context: non-blocking.
 * Note that returning anything other than NETDEV_TX_OK will cause the
 * OS to free the skb.
 */
netdev_tx_t efx_hard_start_xmit(struct sk_buff *skb,
				struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;
	int rc;

#ifdef CONFIG_SFC_TRACING
	trace_sfc_transmit(skb, net_dev);
#endif

	channel = efx_get_tx_channel(efx, skb_get_queue_mapping(skb));

#if defined(CONFIG_SFC_PTP)
	/*
	 * PTP "event" packet
	 */
	if (unlikely(efx_xmit_with_hwtstamp(skb)) &&
	    ((efx_ptp_use_mac_tx_timestamps(efx) && efx->ptp_data) ||
	     unlikely(efx_ptp_is_ptp_tx(efx, skb)))) {
		/* There may be existing transmits on the channel that are
		 * waiting for this packet to trigger the doorbell write.
		 * We need to send the packets at this point.
		 */
		efx_tx_send_pending(channel);
		return efx_ptp_tx(efx, skb);
	}
#endif

	tx_queue = efx->select_tx_queue(channel, skb);

	rc = efx_enqueue_skb(tx_queue, skb);
	return NETDEV_TX_OK;
}

void efx_xmit_done_single(struct efx_tx_queue *tx_queue)
{
	unsigned int pkts_compl = 0, bytes_compl = 0;
	unsigned int read_ptr;
	bool finished = false;

	read_ptr = tx_queue->read_count & tx_queue->ptr_mask;

	while (!finished) {
		struct efx_tx_buffer *buffer = &tx_queue->buffer[read_ptr];

		if (!efx_tx_buffer_in_use(buffer)) {
			struct efx_nic *efx = tx_queue->efx;

			netif_err(efx, hw, efx->net_dev,
				  "TX queue %d spurious single TX completion\n",
				  tx_queue->queue);
			atomic_inc(&efx->errors.spurious_tx);
			efx_schedule_reset(efx, RESET_TYPE_TX_SKIP);
			return;
		}

		/* Need to check the flag before dequeueing. */
		if (buffer->flags & EFX_TX_BUF_SKB)
			finished = true;
		efx_dequeue_buffer(tx_queue, buffer, &pkts_compl, &bytes_compl);

		++tx_queue->read_count;
		read_ptr = tx_queue->read_count & tx_queue->ptr_mask;
	}

	tx_queue->pkts_compl += pkts_compl;
	tx_queue->bytes_compl += bytes_compl;

	EFX_WARN_ON_PARANOID(pkts_compl != 1);

	efx_xmit_done_check_empty(tx_queue);
}

static unsigned int efx_tx_cb_page_count(struct efx_tx_queue *tx_queue)
{
        return DIV_ROUND_UP(tx_queue->ptr_mask + 1, PAGE_SIZE >> tx_cb_order);
}

bool efx_tx_cb_probe(struct efx_tx_queue *tx_queue)
{
        tx_queue->cb_page = kcalloc(efx_tx_cb_page_count(tx_queue),
                                    sizeof(tx_queue->cb_page[0]), GFP_KERNEL);

	return !!tx_queue->cb_page;
}

void efx_tx_cb_destroy(struct efx_tx_queue *tx_queue)
{
	unsigned int i;

       if (tx_queue->cb_page) {
                for (i = 0; i < efx_tx_cb_page_count(tx_queue); i++)
                        efx_nic_free_buffer(tx_queue->efx,
                                            &tx_queue->cb_page[i]);
                kfree(tx_queue->cb_page);
                tx_queue->cb_page = NULL;
        }
}

