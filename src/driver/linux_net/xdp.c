// SPDX-License-Identifier: GPL-2.0
/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include "xdp.h"
#include "nic.h"
#include "tx_common.h"
#include "rx_common.h"
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_TRACE)
#include <trace/events/xdp.h>
#endif

/* Maximum rx prefix used by any architecture. */
#define EFX_MAX_RX_PREFIX_SIZE 22

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
unsigned int efx_xdp_max_mtu(struct efx_nic *efx)
{
	/* The maximum MTU that we can fit in a single page, allowing for
	 * framing, overhead and XDP headroom.
	 */
	int overhead = EFX_MAX_FRAME_LEN(0) + sizeof(struct efx_rx_page_state) +
		       efx->rx_prefix_size + efx->type->rx_buffer_padding +
		       efx->rx_ip_align + XDP_PACKET_HEADROOM;

	return PAGE_SIZE - overhead;
}

int efx_xdp_setup_prog(struct efx_nic *efx, struct bpf_prog *prog)
{
	struct bpf_prog *old_prog;

	if (prog && efx->net_dev->mtu > efx_xdp_max_mtu(efx)) {
		netif_err(efx, drv, efx->net_dev,
			  "Unable to configure XDP with MTU of %d (max: %d)\n",
			  efx->net_dev->mtu, efx_xdp_max_mtu(efx));
		return -EINVAL;
	}

	old_prog = rtnl_dereference(efx->xdp_prog);
	rcu_assign_pointer(efx->xdp_prog, prog);
	/* Release the reference that was originally passed by the caller. */
	if (old_prog)
		bpf_prog_put(old_prog);

	return 0;
}

/* Context: process, rtnl_lock() held. */
int efx_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	struct efx_nic *efx = netdev_priv(dev);
	struct bpf_prog *xdp_prog;

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return efx_xdp_setup_prog(efx, xdp->prog);
	case XDP_QUERY_PROG:
		xdp_prog = rtnl_dereference(efx->xdp_prog);
#if defined(EFX_USE_KCOMPAT) && (defined(EFX_HAVE_XDP_PROG_ATTACHED) || defined(EFX_HAVE_XDP_OLD))
		xdp->prog_attached = !!xdp_prog;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_PROG_ID) || !defined(EFX_HAVE_XDP_OLD)
		xdp->prog_id = xdp_prog ? xdp_prog->aux->id : 0;
#endif
		return 0;
	default:
		return -EINVAL;
	}
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_REDIR)
/* Context: NAPI */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_TX_FLAGS)
int efx_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **xdpfs,
		 u32 flags)
{
	struct efx_nic *efx = netdev_priv(dev);

	if (!netif_running(dev))
		return -EINVAL;

	return efx_xdp_tx_buffers(efx, n, xdpfs, flags & XDP_XMIT_FLUSH);
}
#else
int efx_xdp_xmit(struct net_device *dev, struct xdp_frame *xdpf)
{
	struct efx_nic *efx = netdev_priv(dev);
	int rc;

	if (!netif_running(dev))
		return -EINVAL;

	rc = efx_xdp_tx_buffers(efx, 1, &xdpf, false);

	if (rc == 1)
		return 0;
	if (rc == 0)
		return -ENOSPC;
	return rc;
}
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_XDP_FLUSH)
/* Context: NAPI */
void efx_xdp_flush(struct net_device *dev)
{
	efx_xdp_tx_buffers(netdev_priv(dev), 0, NULL, true);
}
#endif /* NEED_XDP_FLUSH */
#endif /* HAVE_XDP_REDIR */
#endif /* HAVE_XDP */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_TX)
/* Transmit a packet from an XDP buffer
 *
 * Returns number of packets sent on success, error code otherwise.
 * Runs in NAPI context, either in our poll (for XDP TX) or a different NIC
 * (for XDP redirect).
 */
int efx_xdp_tx_buffers(struct efx_nic *efx, int n, struct xdp_frame **xdpfs,
		       bool flush)
{
	struct efx_tx_buffer *tx_buffer;
	struct efx_tx_queue *tx_queue;
	struct xdp_frame *xdpf;
	unsigned int total = 0;
	dma_addr_t dma_addr;
	unsigned int len;
	int space;
	int cpu;
	int i;

	cpu = raw_smp_processor_id();

	if (!efx->xdp_tx_queue_count ||
	    unlikely(cpu >= efx->xdp_tx_queue_count))
		return -EINVAL;

	tx_queue = efx->xdp_tx_queues[cpu];
	if (unlikely(!tx_queue))
		return -EINVAL;

	if (n && xdpfs) {
		/* Check for available space. We should never need multiple
		 * descriptors per frame.
		 */
		space = efx->txq_entries +
			tx_queue->read_count - tx_queue->insert_count;
		n = min(n, space);

		for (i = 0; i < n; i++) {
			xdpf = xdpfs[i];

			/* We'll want a descriptor for this tx. */
			prefetchw(__efx_tx_queue_get_insert_buffer(tx_queue));

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_FRAME_API)
			len = xdpf->len;
#else
			len = xdpf->data_end - xdpf->data;
#endif

/* Map for DMA. */
			dma_addr = dma_map_single(&efx->pci_dev->dev,
						  xdpf->data, len,
						  DMA_TO_DEVICE);
			if (dma_mapping_error(&efx->pci_dev->dev, dma_addr))
				return -EIO;

			/*  Create descriptor and set up for unmapping DMA. */
			tx_buffer = efx_tx_map_chunk(tx_queue, dma_addr, len);
			if (!tx_buffer)
				return -EBUSY;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_FRAME_API)
			tx_buffer->xdpf = xdpf;
#else
			tx_buffer->buf = xdpf->data;
#endif
			tx_buffer->flags = EFX_TX_BUF_XDP |
					   EFX_TX_BUF_MAP_SINGLE;
			tx_buffer->dma_offset = 0;
			tx_buffer->unmap_len = len;
			total += len;
		}
	}

	/* Pass to hardware. */
	if (flush)
		efx_nic_push_buffers(tx_queue);

	tx_queue->tx_packets += n;
	tx_queue->tx_bytes += total;

	return n;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
/** efx_xdp_rx: perform XDP processing on a received packet
 *
 * Returns true if packet should still be delivered.
 */
bool efx_xdp_rx(struct efx_nic *efx, struct efx_channel *channel,
		struct efx_rx_buffer *rx_buf, u8 **ehp)
{
	u8 rx_prefix[EFX_MAX_RX_PREFIX_SIZE];
	struct efx_rx_queue *rx_queue;
	struct bpf_prog *xdp_prog;
	struct xdp_frame *xdpf;
	struct xdp_buff xdp;
	u32 xdp_act;
	s16 offset;
	int rc;

	rcu_read_lock();
	xdp_prog = rcu_dereference(efx->xdp_prog);
	if (!xdp_prog) {
		rcu_read_unlock();
		return true;
	}

	rx_queue = efx_channel_get_rx_queue(channel);

	if (unlikely(channel->rx_pkt_n_frags > 1)) {
		/* We can't do XDP on fragmented packets - drop. */
		rcu_read_unlock();
		efx_free_rx_buffers(rx_queue, rx_buf,
				    channel->rx_pkt_n_frags);
		if (net_ratelimit())
			netif_err(efx, rx_err, efx->net_dev,
				  "XDP is not possible with multiple receive fragments (%d)\n",
				  channel->rx_pkt_n_frags);
		channel->n_rx_xdp_bad_drops++;
		return false;
	}

	dma_sync_single_for_cpu(&efx->pci_dev->dev, rx_buf->dma_addr,
				rx_buf->len, DMA_FROM_DEVICE);

	/* Save the rx prefix. */
	EFX_WARN_ON_PARANOID(efx->rx_prefix_size > EFX_MAX_RX_PREFIX_SIZE);
	memcpy(rx_prefix, *ehp - efx->rx_prefix_size,
	       efx->rx_prefix_size);

	xdp.data = *ehp;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_HEAD)
	xdp.data_hard_start = xdp.data - XDP_PACKET_HEADROOM;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_DATA_META)
	/* No support yet for XDP metadata */
	xdp_set_data_meta_invalid(&xdp);
#endif
	xdp.data_end = xdp.data + rx_buf->len;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_RXQ_INFO)
	xdp.rxq = &rx_queue->xdp_rxq_info;
#endif

	xdp_act = bpf_prog_run_xdp(xdp_prog, &xdp);
	rcu_read_unlock();

	offset = (u8 *)xdp.data - *ehp;

	switch (xdp_act) {
	case XDP_PASS:
		/* Fix up rx prefix. */
		if (offset) {
			*ehp += offset;
			rx_buf->page_offset += offset;
			rx_buf->len -= offset;
			memcpy(*ehp - efx->rx_prefix_size, rx_prefix,
			       efx->rx_prefix_size);
		}
		break;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_TX)
	case XDP_TX:
		/* Buffer ownership passes to tx on success. */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_FRAME_API)
		xdpf = convert_to_xdp_frame(&xdp);
#else
		xdpf = &xdp;
#endif
		rc = efx_xdp_tx_buffers(efx, 1, &xdpf, true);
		if (rc != 1) {
			efx_free_rx_buffers(rx_queue, rx_buf, 1);
			if (net_ratelimit())
				netif_err(efx, rx_err, efx->net_dev,
					  "XDP TX failed (%d)\n", rc);
			channel->n_rx_xdp_bad_drops++;
		} else {
			channel->n_rx_xdp_tx++;
		}
		break;
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_REDIR)
	case XDP_REDIRECT:
		rc = xdp_do_redirect(efx->net_dev, &xdp, xdp_prog);
		if (rc) {
			efx_free_rx_buffers(rx_queue, rx_buf, 1);
			if (net_ratelimit())
				netif_err(efx, rx_err, efx->net_dev,
					  "XDP redirect failed (%d)\n", rc);
			channel->n_rx_xdp_bad_drops++;
		} else {
			channel->n_rx_xdp_redirect++;
		}
		break;
#endif

	default:
		bpf_warn_invalid_xdp_action(xdp_act);
		/* Fall through */
	case XDP_ABORTED:
		trace_xdp_exception(efx->net_dev, xdp_prog, xdp_act);
		efx_free_rx_buffers(rx_queue, rx_buf, 1);
		channel->n_rx_xdp_bad_drops++;
		break;

	case XDP_DROP:
		efx_free_rx_buffers(rx_queue, rx_buf, 1);
		channel->n_rx_xdp_drops++;
		break;
	}

	return xdp_act == XDP_PASS;
}
#endif

