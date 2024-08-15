/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2005-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/socket.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/prefetch.h>
#include <linux/moduleparam.h>
#include <linux/hash.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#ifdef EFX_NOT_UPSTREAM
#include <net/ipv6.h>
#endif
#include "net_driver.h"
#include "efx.h"
#include "rx_common.h"
#include "filter.h"
#include "nic.h"
#include "xdp.h"
#include "selftest.h"
#include "workarounds.h"
#ifdef CONFIG_SFC_TRACING
#include <trace/events/sfc.h>
#endif
#include "mcdi_pcol.h"

#ifdef EFX_NOT_UPSTREAM
static bool underreport_skb_truesize;
module_param(underreport_skb_truesize, bool, 0444);
MODULE_PARM_DESC(underreport_skb_truesize, "Give false skb truesizes. "
			"Debug option to restore previous driver behaviour.");
#endif

/* Size of headers copied into skb linear data area */
#define EFX_RX_CB_DEFAULT 192u
static unsigned int rx_cb_size = EFX_RX_CB_DEFAULT;

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
static void efx_repost_rx_page(struct efx_rx_queue *rx_queue,
			       struct efx_rx_buffer *rx_buf)
{
	struct efx_nic *efx = rx_queue->efx;
	struct page *page = rx_buf->page;
	u16 flags;
	unsigned int page_offset = 0;
	unsigned int fill_level;
	unsigned int nr_bufs;
	unsigned int space;

	/* We only repost pages that have not been pushed up the stack.
	 * These are signalled by a non-null rx_buf page field
	 */
	if (page == NULL)
		return;

	/* This indicates broken logic in packet processing functions */
	EFX_WARN_ON_ONCE_PARANOID(rx_queue->rx_pkt_n_frags > 1);
	/* Non-recycled page has ended up being marked for reposting. */
	EFX_WARN_ON_ONCE_PARANOID(!(rx_buf->flags & EFX_RX_PAGE_IN_RECYCLE_RING));

	fill_level = rx_queue->added_count - rx_queue->removed_count;

	/* Note subtle fill_level condition check. By only releasing
	 * descriptors that are above the fast_fill_trigger threshold
	 * we avoid alternating between releasing descriptors and
	 * reposting them for series of small packets.
	 */
	if (efx->rx_bufs_per_page > 2 ||
	    fill_level > rx_queue->fast_fill_trigger) {
		put_page(page);
		return;
	}

	EFX_WARN_ON_ONCE_PARANOID(efx->rx_bufs_per_page < 1);
	EFX_WARN_ON_ONCE_PARANOID(efx->rx_bufs_per_page > 2);
	/* repost the first buffer, and the second if there are no refs to it */
	nr_bufs = 1;
	if (efx->rx_bufs_per_page == 2)
		nr_bufs += page_count(page) < efx->rx_bufs_per_page + 1;

	/* Clamp nr_bufs to the minimum of the number of buffers
	 * creatable from the page and the number of free slots on the
	 * RX descriptor ring.
	 */
	space = 1 + (rx_queue->max_fill - fill_level);
	if (space < nr_bufs)
		nr_bufs = space;

	/* Page offset calculation assumes maximum 2 buffers per page */
	if (rx_buf->page_offset >= efx->rx_page_buf_step)
		page_offset = efx->rx_page_buf_step;
	flags = EFX_RX_PAGE_IN_RECYCLE_RING;
	flags |= rx_buf->flags & EFX_RX_BUF_LAST_IN_PAGE;

	do {
		efx_init_rx_buffer(rx_queue, page, page_offset, flags);
		rx_queue->page_repost_count++;

		flags ^= EFX_RX_BUF_LAST_IN_PAGE;
		page_offset ^= efx->rx_page_buf_step;

		/* We need to bump up the reference count if we're reposting
		 * two buffers onto the ring
		 */
		if (nr_bufs > 1)
			get_page(page);
	} while (--nr_bufs > 0);
}
#endif

static void efx_rx_packet__check_len(struct efx_rx_queue *rx_queue,
				     struct efx_rx_buffer *rx_buf,
				     int len)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned int max_len = rx_buf->len - efx->type->rx_buffer_padding;

	if (likely(len <= max_len))
		return;

	/* The packet must be discarded, but this is only a fatal error
	 * if the caller indicated it was
	 */
	rx_buf->flags |= EFX_RX_PKT_DISCARD;

	if (net_ratelimit())
		netif_err(efx, rx_err, efx->net_dev,
			  " RX queue %d overlength RX event "
			  "(%#x > %#x)\n",
			  efx_rx_queue_index(rx_queue), len, max_len);

	rx_queue->n_rx_overlength++;
}

/* Allocate and construct an SKB around page fragments
 *
 * Note that in the RX copybreak case the rx_buf page may be placed
 * onto the RX recycle ring, and efx_init_rx_buffer() will be called.
 * If so reset the callers rx_buf so that it is not reused.
 */
static struct sk_buff *efx_rx_mk_skb(struct efx_rx_queue *rx_queue,
				     struct efx_rx_buffer **_rx_buf,
				     unsigned int n_frags,
				     u8 **ehp, int hdr_len)
{
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	struct efx_rx_buffer *rx_buf = *_rx_buf;
	struct efx_nic *efx = rx_queue->efx;
	struct sk_buff *skb = NULL;
	unsigned int data_cp_len = efx->rx_prefix_size + hdr_len;
	unsigned int alloc_len = efx->rx_ip_align + efx->rx_prefix_size +
			hdr_len;
	u8 *new_eh;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	if (channel->zc) {
		data_cp_len = rx_buf->len + efx->rx_prefix_size;
		alloc_len = data_cp_len;
	}
#endif
	/* Allocate an SKB to store the headers */
	skb = netdev_alloc_skb(efx->net_dev, alloc_len);
	if (unlikely(skb == NULL)) {
		atomic_inc(&efx->n_rx_noskb_drops);
		return NULL;
	}

	EFX_WARN_ON_ONCE_PARANOID(rx_buf->len < hdr_len);

	memcpy(skb->data + efx->rx_ip_align, *ehp - efx->rx_prefix_size,
	       data_cp_len);
	skb_reserve(skb, efx->rx_ip_align + efx->rx_prefix_size);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	if (channel->zc) {
		__skb_put(skb, rx_buf->len);
		goto finalize_skb;
	}
#endif
	new_eh = skb->data;
	__skb_put(skb, hdr_len);

	/* Append the remaining page(s) onto the frag list */
	if (rx_buf->len > hdr_len) {
		rx_buf->page_offset += hdr_len;
		rx_buf->len -= hdr_len;

		for (;;) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB_FRAG_TRUESIZE)
			skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
					rx_buf->page, rx_buf->page_offset,
					rx_buf->len, efx->rx_buffer_truesize);
#else
			skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags,
					rx_buf->page, rx_buf->page_offset,
					rx_buf->len);
#endif
			rx_buf->page = NULL;
			if (skb_shinfo(skb)->nr_frags == n_frags)
				break;

			rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
		}
	} else {
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
		if (!(rx_buf->flags & EFX_RX_PAGE_IN_RECYCLE_RING)) {
#endif
			__free_pages(rx_buf->page, efx->rx_buffer_order);
#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
		} else {
			efx_repost_rx_page(rx_queue, rx_buf);
			*_rx_buf = NULL;
		}
#endif
		*ehp = new_eh;
		rx_buf->page = NULL;
		n_frags = 0;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
finalize_skb:
#endif
	/* Move past the ethernet header */
	skb->protocol = eth_type_trans(skb, efx->net_dev);

	skb_mark_napi_id(skb, &channel->napi_str);

	return skb;
}

void efx_rx_packet(struct efx_rx_queue *rx_queue, unsigned int index,
		   unsigned int n_frags, unsigned int len, u16 flags)
{
	struct efx_nic *efx = rx_queue->efx;
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	struct efx_rx_buffer *rx_buf;

	rx_queue->rx_packets++;

	rx_buf = efx_rx_buffer(rx_queue, index);
	rx_buf->flags |= flags;

	/* Validate the number of fragments and completed length */
	if (n_frags == 1) {
		if (!(flags & EFX_RX_PKT_PREFIX_LEN))
			efx_rx_packet__check_len(rx_queue, rx_buf, len);
	} else if (unlikely(n_frags > EFX_RX_MAX_FRAGS) ||
		   unlikely(len <= (n_frags - 1) * efx->rx_dma_len) ||
		   unlikely(len > n_frags * efx->rx_dma_len) ||
		   unlikely(!efx->rx_scatter)) {
		/* If this isn't an explicit discard request, either
		 * the hardware or the driver is broken.
		 */
		WARN_ON(!(len == 0 && rx_buf->flags & EFX_RX_PKT_DISCARD));
		rx_buf->flags |= EFX_RX_PKT_DISCARD;
	}

	netif_vdbg(efx, rx_status, efx->net_dev,
		   "RX queue %d received ids %x-%x len %d %s%s\n",
		   efx_rx_queue_index(rx_queue), index,
		   (index + n_frags - 1) & rx_queue->ptr_mask, len,
		   (rx_buf->flags & EFX_RX_PKT_CSUMMED) ? " [SUMMED]" : "",
		   (rx_buf->flags & EFX_RX_PKT_DISCARD) ? " [DISCARD]" : "");

	/* Discard packet, if instructed to do so.  Process the
	 * previous receive first.
	 */
	if (unlikely(rx_buf->flags & EFX_RX_PKT_DISCARD)) {
		efx_rx_flush_packet(rx_queue);
		efx_discard_rx_packet(channel, rx_buf, n_frags);
		return;
	}

	if (n_frags == 1 && !(flags & EFX_RX_PKT_PREFIX_LEN))
		rx_buf->len = len;

	/* Release and/or sync the DMA mapping - assumes all RX buffers
	 * consumed in-order per RX queue.
	 */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	if (channel->zc)
		dma_sync_single_for_cpu(&efx->pci_dev->dev, rx_buf->dma_addr,
					len, DMA_BIDIRECTIONAL);
	else
#endif
		efx_sync_rx_buffer(efx, rx_buf, rx_buf->len);

	/* Prefetch nice and early so data will (hopefully) be in cache by
	 * the time we look at it.
	 */
	prefetch(efx_rx_buf_va(rx_buf));

	rx_buf->page_offset += efx->rx_prefix_size;
	rx_buf->len -= efx->rx_prefix_size;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	/* XDP does not support more than 1 frag */
	if (channel->zc)
		goto skip_recycle_pages;
#endif

	if (n_frags > 1) {
		/* Release/sync DMA mapping for additional fragments.
		 * Fix length for last fragment.
		 */
		unsigned int tail_frags = n_frags - 1;

		for (;;) {
			rx_buf = efx_rx_buf_next(rx_queue, rx_buf);
			if (--tail_frags == 0)
				break;
			efx_sync_rx_buffer(efx, rx_buf, efx->rx_dma_len);
		}
		rx_buf->len = len - (n_frags - 1) * efx->rx_dma_len;
		efx_sync_rx_buffer(efx, rx_buf, rx_buf->len);
	}

	/* All fragments have been DMA-synced, so recycle pages. */
	rx_buf = efx_rx_buffer(rx_queue, index);
	efx_recycle_rx_pages(channel, rx_buf, n_frags);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
skip_recycle_pages:
#endif
	/* Pipeline receives so that we give time for packet headers to be
	 * prefetched into cache.
	 */
	efx_rx_flush_packet(rx_queue);
	rx_queue->rx_pkt_n_frags = n_frags;
	rx_queue->rx_pkt_index = index;
}

static void efx_rx_deliver(struct efx_rx_queue *rx_queue, u8 *eh,
			   struct efx_rx_buffer *rx_buf,
			   unsigned int n_frags)
{
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	u16 hdr_len = min_t(u16, rx_buf->len, rx_cb_size);
#if IS_ENABLED(CONFIG_VLAN_8021Q)
	u16 rx_buf_vlan_tci = rx_buf->vlan_tci;
#endif
	struct efx_nic *efx = rx_queue->efx;
	u16 rx_buf_flags = rx_buf->flags;
	bool free_buf_on_fail = true;
	struct sk_buff *skb;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	if (channel->zc)
		free_buf_on_fail = false;
#endif
	skb = efx_rx_mk_skb(rx_queue, &rx_buf, n_frags, &eh, hdr_len);

	if (unlikely(skb == NULL)) {
		if (free_buf_on_fail)
			efx_free_rx_buffers(rx_queue, rx_buf, n_frags);
		return;
	}
	skb_record_rx_queue(skb, rx_queue->core_index);

	/* Set the SKB flags */
	skb_checksum_none_assert(skb);
	if (likely(rx_buf_flags & EFX_RX_PKT_CSUMMED)) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
#if !defined(EFX_USE_KCOMPAT) || defined (EFX_HAVE_CSUM_LEVEL)
		skb->csum_level = !!(rx_buf_flags & EFX_RX_PKT_CSUM_LEVEL);
#endif
	}

	efx_rx_skb_attach_timestamp(channel, skb,
				    eh - efx->type->rx_prefix_size);

#if   !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RXHASH_SUPPORT)
	if (efx->net_dev->features & NETIF_F_RXHASH)
		skb_set_hash(skb, efx_rx_buf_hash(efx, eh),
			     (rx_buf_flags & EFX_RX_PKT_TCP? PKT_HASH_TYPE_L4:
			      PKT_HASH_TYPE_L3));
#endif

#if IS_ENABLED(CONFIG_VLAN_8021Q)
	if (rx_buf_flags & EFX_RX_BUF_VLAN_XTAG)
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       rx_buf_vlan_tci);
#endif

	if (rx_queue->receive_skb)
		if (rx_queue->receive_skb(rx_queue, skb))
			return;

	/* Pass the packet up */
#ifdef CONFIG_SFC_TRACING
	trace_sfc_receive(skb, false, rx_buf_flags & EFX_RX_BUF_VLAN_XTAG,
			  rx_buf_vlan_tci);
#endif
	if (channel->rx_list != NULL)
		/* Add to list, will pass up later */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
		list_add_tail(&skb->list, channel->rx_list);
#else
		__skb_queue_tail(channel->rx_list, skb);
#endif
	else
		/* No list, so pass it up now */
		netif_receive_skb(skb);
}

/* Handle a received packet.  Second half: Touches packet payload. */
void __efx_rx_packet(struct efx_rx_queue *rx_queue)
{
#if (defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL) || !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK))
	struct efx_channel *channel = efx_get_rx_queue_channel(rx_queue);
#endif
	struct efx_rx_buffer *rx_buf = efx_rx_buf_pipe(rx_queue);
	struct efx_nic *efx = rx_queue->efx;
	u8 *eh = efx_rx_buf_va(rx_buf);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	struct vlan_ethhdr *veh;
#endif
	bool rx_deliver = false;
	int rc;

	/* Read length from the prefix if necessary.  This already
	 * excludes the length of the prefix itself.
	 */
	if (rx_buf->flags & EFX_RX_PKT_PREFIX_LEN) {
		rx_buf->len = le16_to_cpup((__le16 *)
					   (eh + efx->rx_packet_len_offset));
		/* A known issue may prevent this being filled in;
		 * if that happens, just drop the packet.
		 * Must do that in the driver since passing a zero-length
		 * packet up to the stack may cause a crash.
		 */
		if (unlikely(!rx_buf->len)) {
			efx_free_rx_buffers(rx_queue, rx_buf,
					    rx_queue->rx_pkt_n_frags);
			rx_queue->n_rx_frm_trunc++;
			goto out;
		}
	}

	/* If we're in loopback test, then pass the packet directly to the
	 * loopback layer, and free the rx_buf here
	 */
	if (unlikely(efx->loopback_selftest)) {
		efx_loopback_rx_packet(efx, eh, rx_buf->len);
		efx_free_rx_buffers(rx_queue, rx_buf,
				    rx_queue->rx_pkt_n_frags);
		goto out;
	}


	rc = efx_xdp_rx(efx, rx_queue, rx_buf, &eh);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	if (channel->zc) {
		if (rc == XDP_REDIRECT || rc == XDP_TX)
			goto free_buf;
		else
			efx_recycle_rx_bufs_zc(channel, rx_buf,
					       rx_queue->rx_pkt_n_frags);
		if (rc != XDP_PASS)
			goto free_buf;
	} else if (rc != XDP_PASS) {
		goto out;
	}
#else
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	if (rc != XDP_PASS)
		goto out;
#else
	if (rc != -ENOTSUPP)
		goto out;
#endif
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	/* Fake VLAN tagging */
	veh = (struct vlan_ethhdr *) eh;
	if ((rx_buf->flags & EFX_RX_PKT_VLAN) &&
	    ((veh->h_vlan_proto == htons(ETH_P_8021Q)) ||
	     (veh->h_vlan_proto == htons(ETH_P_QINQ1)) ||
	     (veh->h_vlan_proto == htons(ETH_P_QINQ2)) ||
	     (veh->h_vlan_proto == htons(ETH_P_QINQ3)) ||
	     (veh->h_vlan_proto == htons(ETH_P_8021AD)))) {
		rx_buf->vlan_tci = ntohs(veh->h_vlan_TCI);
		memmove(eh - efx->rx_prefix_size + VLAN_HLEN,
			eh - efx->rx_prefix_size,
			2 * ETH_ALEN + efx->rx_prefix_size);
		eh += VLAN_HLEN;
		rx_buf->page_offset += VLAN_HLEN;
		rx_buf->len -= VLAN_HLEN;
		rx_buf->flags |= EFX_RX_BUF_VLAN_XTAG;
	}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	if (rx_buf->flags & EFX_RX_BUF_ZC) {
		rx_deliver = true;
		goto deliver_now;
	}
#endif
	if (unlikely(!(efx->net_dev->features & NETIF_F_RXCSUM)))
		rx_buf->flags &= ~EFX_RX_PKT_CSUMMED;

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	if ((rx_buf->flags & (EFX_RX_PKT_CSUMMED | EFX_RX_PKT_TCP)) ==
	    (EFX_RX_PKT_CSUMMED | EFX_RX_PKT_TCP) &&
	    efx_ssr_enabled(efx) &&
	    likely(rx_queue->rx_pkt_n_frags == 1))
		efx_ssr(rx_queue, rx_buf, eh);
	else
		/* fall through */
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_GRO)
	if ((rx_buf->flags & EFX_RX_PKT_TCP) &&
	    !rx_queue->receive_skb
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	    && !efx_channel_busy_polling(channel)
#endif
	   ) {
		efx_rx_packet_gro(rx_queue, rx_buf,
				  rx_queue->rx_pkt_n_frags,
				  eh, 0);
	} else {
		rx_deliver = true;
		goto deliver_now;
	}
#endif
deliver_now:
	if (rx_deliver)
		efx_rx_deliver(rx_queue, eh, rx_buf, rx_queue->rx_pkt_n_frags);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
free_buf:
	if (channel->zc)
		efx_free_rx_buffers(rx_queue, rx_buf,
				    rx_queue->rx_pkt_n_frags);
#endif
out:
	rx_queue->rx_pkt_n_frags = 0;
}

#if defined(EFX_NOT_UPSTREAM)
static int __init
efx_rx_alloc_method_set(const char *val, const struct kernel_param *kp)
{
	pr_warn("sfc: module parameter rx_alloc_method is obsolete\n");
	return 0;
}
static const struct kernel_param_ops efx_rx_alloc_method_ops = {
	.set = efx_rx_alloc_method_set
};
module_param_cb(rx_alloc_method, &efx_rx_alloc_method_ops, NULL, 0);
#endif

#if defined(EFX_NOT_UPSTREAM)
static int __init
rx_copybreak_set(const char *val, const struct kernel_param *kp)
{
	int rc = param_set_uint(val, kp);

	if (rc)
		return rc;

	if (rx_cb_size == 0) {
		/* Adjust so that ethernet headers are copied into the skb. */
		rx_cb_size = ETH_HLEN;
	} else if (rx_cb_size < ETH_ZLEN) {
		rx_cb_size = ETH_ZLEN;
		pr_warn("sfc: Invalid rx_copybreak value. Clamping to %u.\n",
			rx_cb_size);
	}

	return 0;
}

static int rx_copybreak_get(char *buffer, const struct kernel_param *kp)
{
	int rc = param_get_uint(buffer, kp);

	if (!strcmp(buffer, "14"))
		rc = scnprintf(buffer, PAGE_SIZE, "0");

	return rc;
}

static const struct kernel_param_ops rx_copybreak_ops = {
	.set = rx_copybreak_set,
	.get = rx_copybreak_get,
};
module_param_cb(rx_copybreak, &rx_copybreak_ops, &rx_cb_size, 0444);
MODULE_PARM_DESC(rx_copybreak,
		 "Size of headers copied into skb linear data area");
#endif /* EFX_NOT_UPSTREAM */


#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)

#define EFX_SSR_MAX_SKB_FRAGS	MAX_SKB_FRAGS

/* Size of the LRO hash table.  Must be a power of 2.  A larger table
 * means we can accelerate a larger number of streams.
 */
static unsigned int lro_table_size = 128;
module_param(lro_table_size, uint, 0644);
MODULE_PARM_DESC(lro_table_size,
		 "Size of the LRO hash table.  Must be a power of 2");

/* Maximum length of a hash chain.  If chains get too long then the lookup
 * time increases and may exceed the benefit of LRO.
 */
static unsigned int lro_chain_max = 20;
module_param(lro_chain_max, uint, 0644);
MODULE_PARM_DESC(lro_chain_max,
		 "Maximum length of chains in the LRO hash table");


/* Maximum time (in jiffies) that a connection can be idle before it's LRO
 * state is discarded.
 */
static unsigned int lro_idle_jiffies = HZ / 10 + 1;	/* 100ms */
module_param(lro_idle_jiffies, uint, 0644);
MODULE_PARM_DESC(lro_idle_jiffies, "Time (in jiffies) after which an"
		 " idle connection's LRO state is discarded");


/* Number of packets with payload that must arrive in-order before a
 * connection is eligible for LRO.  The idea is we should avoid coalescing
 * segments when the sender is in slow-start because reducing the ACK rate
 * can damage performance.
 */
static int lro_slow_start_packets = 2000;
module_param(lro_slow_start_packets, uint, 0644);
MODULE_PARM_DESC(lro_slow_start_packets, "Number of packets that must "
		 "pass in-order before starting LRO.");


/* Number of packets with payload that must arrive in-order following loss
 * before a connection is eligible for LRO.  The idea is we should avoid
 * coalescing segments when the sender is recovering from loss, because
 * reducing the ACK rate can damage performance.
 */
static int lro_loss_packets = 20;
module_param(lro_loss_packets, uint, 0644);
MODULE_PARM_DESC(lro_loss_packets, "Number of packets that must "
		 "pass in-order following loss before restarting LRO.");


/* Flags for efx_ssr_conn::l2_id; must not collide with VLAN tag bits */
#define EFX_SSR_L2_ID_VLAN 0x10000
#define EFX_SSR_L2_ID_IPV6 0x20000
#define EFX_SSR_CONN_IS_VLAN_ENCAP(c) ((c)->l2_id & EFX_SSR_L2_ID_VLAN)
#define EFX_SSR_CONN_IS_TCPIPV4(c) (!((c)->l2_id & EFX_SSR_L2_ID_IPV6))
#define EFX_SSR_CONN_VLAN_TCI(c) ((c)->l2_id & 0xffff)

int efx_ssr_init(struct efx_rx_queue *rx_queue, struct efx_nic *efx)
{
	struct efx_ssr_state *st = &rx_queue->ssr;
	unsigned int i;

	st->conns_mask = lro_table_size - 1;
	if (!is_power_of_2(lro_table_size)) {
		netif_err(efx, drv, efx->net_dev,
			  "lro_table_size(=%u) must be a power of 2\n",
			  lro_table_size);
		return -EINVAL;
	}
	st->efx = efx;
	st->conns = kmalloc_array((st->conns_mask + 1),
				  sizeof(st->conns[0]), GFP_KERNEL);
	if (st->conns == NULL)
		return -ENOMEM;
	st->conns_n = kmalloc_array((st->conns_mask + 1),
				    sizeof(st->conns_n[0]), GFP_KERNEL);
	if (st->conns_n == NULL) {
		kfree(st->conns);
		st->conns = NULL;
		return -ENOMEM;
	}
	for (i = 0; i <= st->conns_mask; ++i) {
		INIT_LIST_HEAD(&st->conns[i]);
		st->conns_n[i] = 0;
	}
	INIT_LIST_HEAD(&st->active_conns);
	INIT_LIST_HEAD(&st->free_conns);
	return 0;
}

static inline bool efx_rx_buffer_is_full(struct efx_rx_buffer *rx_buf)
{
	return rx_buf->page != NULL;
}

static inline void efx_rx_buffer_set_empty(struct efx_rx_buffer *rx_buf)
{
	rx_buf->page = NULL;
}

/* Drop the given connection, and add it to the free list. */
static void efx_ssr_drop(struct efx_rx_queue *rx_queue, struct efx_ssr_conn *c)
{
	unsigned int bucket;

	EFX_WARN_ON_ONCE_PARANOID(c->skb);

	if (efx_rx_buffer_is_full(&c->next_buf)) {
		efx_rx_deliver(rx_queue, c->next_eh, &c->next_buf, 1);
		list_del(&c->active_link);
	}

	bucket = c->conn_hash & rx_queue->ssr.conns_mask;
	EFX_WARN_ON_ONCE_PARANOID(rx_queue->ssr.conns_n[bucket] <= 0);
	--rx_queue->ssr.conns_n[bucket];
	list_del(&c->link);
	list_add(&c->link, &rx_queue->ssr.free_conns);
}

void efx_ssr_fini(struct efx_rx_queue *rx_queue)
{
	struct efx_ssr_state *st = &rx_queue->ssr;
	struct efx_ssr_conn *c;
	unsigned int i;

	/* Return cleanly if efx_ssr_init() has not been called. */
	if (st->conns == NULL)
		return;

	EFX_WARN_ON_ONCE_PARANOID(!list_empty(&st->active_conns));

	for (i = 0; i <= st->conns_mask; ++i) {
		while (!list_empty(&st->conns[i])) {
			c = list_entry(st->conns[i].prev,
				       struct efx_ssr_conn, link);
			efx_ssr_drop(rx_queue, c);
		}
	}

	while (!list_empty(&st->free_conns)) {
		c = list_entry(st->free_conns.prev, struct efx_ssr_conn, link);
		list_del(&c->link);
		EFX_WARN_ON_ONCE_PARANOID(c->skb);
		kfree(c);
	}

	kfree(st->conns_n);
	st->conns_n = NULL;
	kfree(st->conns);
	st->conns = NULL;
}

static inline u8 *
efx_ssr_skb_iph(struct sk_buff *skb)
{
	return skb->data;
}

/* Calc IP checksum and deliver to the OS */
static void efx_ssr_deliver(struct efx_ssr_state *st, struct efx_ssr_conn *c)
{
	struct tcphdr *c_th;

	EFX_WARN_ON_ONCE_PARANOID(!c->skb);

	++st->n_bursts;

	/* Finish off packet munging and recalculate IP header checksum. */
	if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
		struct iphdr *iph = (struct iphdr *)efx_ssr_skb_iph(c->skb);
		iph->tot_len = htons(c->sum_len);
		iph->check = 0;
#if __GNUC__+0 == 4 && __GNUC_MINOR__+0 == 5 && __GNUC_PATCHLEVEL__+0 <= 1
		/* Compiler may wrongly eliminate the preceding assignment */
		barrier();
#endif
		iph->check = ip_fast_csum((u8 *) iph, iph->ihl);
		c_th = (struct tcphdr *)(iph + 1);
	} else {
		struct ipv6hdr *iph = (struct ipv6hdr *)efx_ssr_skb_iph(c->skb);
		iph->payload_len = htons(c->sum_len);
		c_th = (struct tcphdr *)(iph + 1);
	}

#ifdef EFX_NOT_UPSTREAM
	if (underreport_skb_truesize) {
		struct ethhdr *c_eh = eth_hdr(c->skb);
		int len = c->skb->len + ((u8 *)c->skb->data - (u8 *)c_eh);
		c->skb->truesize = len + sizeof(struct sk_buff);
	} else
#endif
	c->skb->truesize += c->skb->data_len;

	c->skb->ip_summed = CHECKSUM_UNNECESSARY;

	c_th->window = c->th_last->window;
	c_th->ack_seq = c->th_last->ack_seq;
	if (c_th->doff == c->th_last->doff) {
		/* Copy TCP options (take care to avoid going negative). */
		int optlen = ((c_th->doff - 5) & 0xf) << 2u;
		memcpy(c_th + 1, c->th_last + 1, optlen);
	}

#if IS_ENABLED(CONFIG_VLAN_8021Q)
	if (EFX_SSR_CONN_IS_VLAN_ENCAP(c))
		__vlan_hwaccel_put_tag(c->skb, htons(ETH_P_8021Q),
				       EFX_SSR_CONN_VLAN_TCI(c));
#endif

#ifdef CONFIG_SFC_TRACING
	trace_sfc_receive(c->skb, false, EFX_SSR_CONN_IS_VLAN_ENCAP(c),
			  EFX_SSR_CONN_VLAN_TCI(c));
#endif
	netif_receive_skb(c->skb);

	c->skb = NULL;
	c->delivered = 1;
}

/* Stop tracking connections that have gone idle in order to keep hash
 * chains short.
 */
static void efx_ssr_purge_idle(struct efx_rx_queue *rx_queue, unsigned int now)
{
	struct efx_ssr_conn *c;
	unsigned int i;

	EFX_WARN_ON_ONCE_PARANOID(!list_empty(&rx_queue->ssr.active_conns));

	rx_queue->ssr.last_purge_jiffies = now;
	for (i = 0; i <= rx_queue->ssr.conns_mask; ++i) {
		if (list_empty(&rx_queue->ssr.conns[i]))
			continue;

		c = list_entry(rx_queue->ssr.conns[i].prev,
			       struct efx_ssr_conn, link);
		if (now - c->last_pkt_jiffies > lro_idle_jiffies) {
			++rx_queue->ssr.n_drop_idle;
			efx_ssr_drop(rx_queue, c);
		}
	}
}

/* Construct an skb Push held skbs down into network stack.
 * Only called when active list is non-empty.
 */
static int
efx_ssr_merge(struct efx_ssr_state *st, struct efx_ssr_conn *c,
	      struct tcphdr *th, int data_length)
{
	struct tcphdr *c_th;

	/* Increase lengths appropriately */
	c->skb->len += data_length;
	c->skb->data_len += data_length;

	if (data_length > skb_shinfo(c->skb)->gso_size)
		skb_shinfo(c->skb)->gso_size = data_length;

	/* Update the connection state flags */
	if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
		struct iphdr *iph = (struct iphdr *)efx_ssr_skb_iph(c->skb);
		c_th = (struct tcphdr *)(iph + 1);
	} else {
		struct ipv6hdr *iph = (struct ipv6hdr *)efx_ssr_skb_iph(c->skb);
		c_th = (struct tcphdr *)(iph + 1);
	}
	c->sum_len += data_length;
	c_th->psh |= th->psh;
	c->th_last = th;
	++st->n_merges;

	/* Pass packet up now if another segment could overflow the IP
	 * length.
	 */
	return (c->skb->len > 65536 - 9200);
}

static void
efx_ssr_start(struct efx_ssr_state *st, struct efx_ssr_conn *c,
	      struct tcphdr *th, int data_length)
{
	skb_shinfo(c->skb)->gso_size = data_length;

	if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
		struct iphdr *iph = (struct iphdr *)efx_ssr_skb_iph(c->skb);
		c->sum_len = ntohs(iph->tot_len);
		skb_shinfo(c->skb)->gso_type = SKB_GSO_TCPV4;
	} else {
		struct ipv6hdr *iph = (struct ipv6hdr *)efx_ssr_skb_iph(c->skb);
		c->sum_len = ntohs(iph->payload_len);
		skb_shinfo(c->skb)->gso_type = SKB_GSO_TCPV6;
	}
}

static int
efx_ssr_merge_page(struct efx_ssr_state *st, struct efx_ssr_conn *c,
		   struct tcphdr *th, int hdr_length, int data_length)
{
	struct efx_rx_buffer *rx_buf = &c->next_buf;
	struct efx_rx_queue *rx_queue;
	size_t rx_prefix_size;
	u8 *eh = c->next_eh;

	if (likely(c->skb)) {
		skb_fill_page_desc(c->skb, skb_shinfo(c->skb)->nr_frags,
				   rx_buf->page,
				   rx_buf->page_offset + hdr_length,
				   data_length);
		rx_buf->page = NULL;

		if (efx_ssr_merge(st, c, th, data_length) ||
		    (skb_shinfo(c->skb)->nr_frags == EFX_SSR_MAX_SKB_FRAGS))
			efx_ssr_deliver(st, c);

		return 1;
	} else {
		rx_queue = container_of(st, struct efx_rx_queue, ssr);

		c->skb = efx_rx_mk_skb(rx_queue, &rx_buf, 1, &eh, hdr_length);
		if (unlikely(c->skb == NULL))
			return 0;

		rx_prefix_size = rx_queue->efx->type->rx_prefix_size;

		efx_rx_skb_attach_timestamp(efx_get_rx_queue_channel(rx_queue),
					    c->skb, eh - rx_prefix_size);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RXHASH_SUPPORT)
		if (st->efx->net_dev->features & NETIF_F_RXHASH)
			skb_set_hash(c->skb, c->conn_hash, PKT_HASH_TYPE_L4);
#endif

		if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
			struct iphdr *iph =
				(struct iphdr *)efx_ssr_skb_iph(c->skb);
			c->th_last = (struct tcphdr *)(iph + 1);
		} else {
			struct ipv6hdr *iph =
				(struct ipv6hdr *)efx_ssr_skb_iph(c->skb);
			c->th_last = (struct tcphdr *)(iph + 1);
		}
		efx_ssr_start(st, c, th, data_length);

		return 1;
	}
}

/* Try to merge or otherwise hold or deliver (as appropriate) the
 * packet buffered for this connection (c->next_buf).  Return a flag
 * indicating whether the connection is still active for SSR purposes.
 */
static bool
efx_ssr_try_merge(struct efx_rx_queue *rx_queue, struct efx_ssr_conn *c)
{
	struct efx_rx_buffer *rx_buf = &c->next_buf;
	u8 *eh = c->next_eh;
	int data_length, hdr_length, dont_merge;
	unsigned int th_seq, pkt_length;
	struct tcphdr *th;
	unsigned int now;

	now = jiffies;
	if (now - c->last_pkt_jiffies > lro_idle_jiffies) {
		++rx_queue->ssr.n_drop_idle;
		if (c->skb)
			efx_ssr_deliver(&rx_queue->ssr, c);
		efx_ssr_drop(rx_queue, c);
		return false;
	}
	c->last_pkt_jiffies = jiffies;

	if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
		struct iphdr *iph = c->next_iph;
		th = (struct tcphdr *)(iph + 1);
		pkt_length = ntohs(iph->tot_len) + (u8 *) iph - (u8 *) eh;
	} else {
		struct ipv6hdr *iph = c->next_iph;
		th = (struct tcphdr *)(iph + 1);
		pkt_length = ntohs(iph->payload_len) + (u8 *) th - (u8 *) eh;
	}

	hdr_length = (u8 *) th + th->doff * 4 - (u8 *) eh;
	rx_buf->len = min_t(u16, pkt_length, rx_buf->len);
	data_length = rx_buf->len - hdr_length;
	th_seq = ntohl(th->seq);
	dont_merge = ((data_length <= 0)
		      | th->urg | th->syn | th->rst | th->fin);

	/* Check for options other than aligned timestamp. */
	if (th->doff != 5) {
		const __be32 *opt_ptr = (const __be32 *) (th + 1);
		if (th->doff == 8 &&
		    opt_ptr[0] == htonl((TCPOPT_NOP << 24) |
					(TCPOPT_NOP << 16) |
					(TCPOPT_TIMESTAMP << 8) |
					TCPOLEN_TIMESTAMP)) {
			/* timestamp option -- okay */
		} else {
			dont_merge = 1;
		}
	}

	if (unlikely(th_seq - c->next_seq)) {
		/* Out-of-order, so start counting again. */
		if (c->skb)
			efx_ssr_deliver(&rx_queue->ssr, c);
		c->n_in_order_pkts -= lro_loss_packets;
		c->next_seq = th_seq + data_length;
		++rx_queue->ssr.n_misorder;
		goto deliver_buf_out;
	}
	c->next_seq = th_seq + data_length;

	if (c->n_in_order_pkts < lro_slow_start_packets) {
		/* May be in slow-start, so don't merge. */
		++rx_queue->ssr.n_slow_start;
		++c->n_in_order_pkts;
		goto deliver_buf_out;
	}

	if (unlikely(dont_merge)) {
		if (c->skb)
			efx_ssr_deliver(&rx_queue->ssr, c);
		if (th->fin || th->rst) {
			++rx_queue->ssr.n_drop_closed;
			efx_ssr_drop(rx_queue, c);
			return false;
		}
		goto deliver_buf_out;
	}

	if (efx_ssr_merge_page(&rx_queue->ssr, c, th,
			       hdr_length, data_length) == 0)
		goto deliver_buf_out;

	efx_get_rx_queue_channel(rx_queue)->irq_mod_score += 2;
	return true;

 deliver_buf_out:
	efx_rx_deliver(rx_queue, eh, rx_buf, 1);
	return true;
}

static void efx_ssr_new_conn(struct efx_ssr_state *st, u32 conn_hash,
			     u32 l2_id, struct tcphdr *th)
{
	unsigned int bucket = conn_hash & st->conns_mask;
	struct efx_ssr_conn *c;

	if (st->conns_n[bucket] >= lro_chain_max) {
		++st->n_too_many;
		return;
	}

	if (!list_empty(&st->free_conns)) {
		c = list_entry(st->free_conns.next, struct efx_ssr_conn, link);
		list_del(&c->link);
	} else {
		c = kmalloc(sizeof(*c), GFP_ATOMIC);
		if (c == NULL)
			return;
		c->skb = NULL;
		efx_rx_buffer_set_empty(&c->next_buf);
	}

	/* Create the connection tracking data */
	++st->conns_n[bucket];
	list_add(&c->link, &st->conns[bucket]);
	c->l2_id = l2_id;
	c->conn_hash = conn_hash;
	c->source = th->source;
	c->dest = th->dest;
	c->n_in_order_pkts = 0;
	c->last_pkt_jiffies = jiffies;
	c->delivered = 0;
	++st->n_new_stream;
	/* NB. We don't initialise c->next_seq, and it doesn't matter what
	 * value it has.  Most likely the next packet received for this
	 * connection will not match -- no harm done.
	 */
}

/* Process SKB and decide whether to dispatch it to the stack now or
 * later.
 */
void efx_ssr(struct efx_rx_queue *rx_queue, struct efx_rx_buffer *rx_buf,
	     u8 *rx_data)
{
	struct efx_nic *efx = rx_queue->efx;
	struct ethhdr *eh = (struct ethhdr *)rx_data;
	struct efx_ssr_conn *c;
	u32 l2_id = 0;
	void *nh = eh + 1;
	struct tcphdr *th;
	u32 conn_hash;
	unsigned int bucket;

	/* Get the hardware hash if available */
#ifdef EFX_HAVE_RXHASH_SUPPORT
	if (efx->net_dev->features & NETIF_F_RXHASH)
#else
	if (efx->rx_prefix_size)
#endif
		conn_hash = efx_rx_buf_hash(efx, rx_data);
	else
		conn_hash = 0;

#if IS_ENABLED(CONFIG_VLAN_8021Q)
	if (rx_buf->flags & EFX_RX_BUF_VLAN_XTAG)
		l2_id = rx_buf->vlan_tci | EFX_SSR_L2_ID_VLAN;
#endif

	/* Check whether this is a suitable packet (unfragmented
	 * TCP/IPv4 or TCP/IPv6).  If so, find the TCP header and
	 * length, and compute a hash if necessary.  If not, return.
	 */
	if (eh->h_proto == htons(ETH_P_IP)) {
		struct iphdr *iph = nh;
		if ((iph->protocol - IPPROTO_TCP) |
		    (iph->ihl - (sizeof(*iph) >> 2u)) |
		    (__force u16)(iph->frag_off & htons(IP_MF | IP_OFFSET)))
			goto deliver_now;
		th = (struct tcphdr *)(iph + 1);
		if (conn_hash == 0)
			/* Can't use ip_fast_csum(,2) as architecture dependent
			 * implementations may assume min 5 for ihl
			 */
			conn_hash = hash_64(*((u64*)&iph->saddr), 32);
	} else if (eh->h_proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr *iph = nh;
		if (iph->nexthdr != NEXTHDR_TCP)
			goto deliver_now;
		l2_id |= EFX_SSR_L2_ID_IPV6;
		th = (struct tcphdr *)(iph + 1);
		if (conn_hash == 0)
			conn_hash = ((__force u32)ip_fast_csum(&iph->saddr, 8) ^
				     (__force u32)(th->source ^ th->dest));
	} else {
		goto deliver_now;
	}

	bucket = conn_hash & rx_queue->ssr.conns_mask;

	list_for_each_entry(c, &rx_queue->ssr.conns[bucket], link) {
		if ((c->l2_id - l2_id) | (c->conn_hash - conn_hash))
			continue;
		if ((c->source ^ th->source) | (c->dest ^ th->dest))
			continue;
		if (c->skb) {
			if (EFX_SSR_CONN_IS_TCPIPV4(c)) {
				struct iphdr *c_iph, *iph = nh;
				c_iph = (struct iphdr *)efx_ssr_skb_iph(c->skb);
				if ((c_iph->saddr ^ iph->saddr) |
				    (c_iph->daddr ^ iph->daddr))
					continue;
			} else {
				struct ipv6hdr *c_iph, *iph = nh;
				c_iph = (struct ipv6hdr *)
					efx_ssr_skb_iph(c->skb);
				if (ipv6_addr_cmp(&c_iph->saddr, &iph->saddr) |
				    ipv6_addr_cmp(&c_iph->daddr, &iph->daddr))
					continue;
			}
		}

		/* Re-insert at head of list to reduce lookup time. */
		list_del(&c->link);
		list_add(&c->link, &rx_queue->ssr.conns[bucket]);

		if (efx_rx_buffer_is_full(&c->next_buf)) {
			if (!efx_ssr_try_merge(rx_queue, c))
				goto deliver_now;
		} else {
			list_add(&c->active_link, &rx_queue->ssr.active_conns);
		}
		c->next_buf = *rx_buf;
		c->next_eh = rx_data;
		efx_rx_buffer_set_empty(rx_buf);
		c->next_iph = nh;
		return;
	}

	efx_ssr_new_conn(&rx_queue->ssr, conn_hash, l2_id, th);
 deliver_now:
	efx_rx_deliver(rx_queue, rx_data, rx_buf, 1);
}

/* Push held skbs down into network stack.
 * Only called when active list is non-empty.
 */
void __efx_ssr_end_of_burst(struct efx_rx_queue *rx_queue)
{
	struct efx_ssr_state *st = &rx_queue->ssr;
	struct efx_ssr_conn *c;
	unsigned int j;

	EFX_WARN_ON_ONCE_PARANOID(list_empty(&st->active_conns));

	do {
		c = list_entry(st->active_conns.next, struct efx_ssr_conn,
			       active_link);
		if (!c->delivered && c->skb)
			efx_ssr_deliver(st, c);
		if (efx_ssr_try_merge(rx_queue, c)) {
			if (c->skb)
				efx_ssr_deliver(st, c);
			list_del(&c->active_link);
		}
		c->delivered = 0;
	} while (!list_empty(&st->active_conns));

	j = jiffies;
	if (unlikely(j != st->last_purge_jiffies))
		efx_ssr_purge_idle(rx_queue, j);
}


#endif /* EFX_USE_SFC_LRO */

