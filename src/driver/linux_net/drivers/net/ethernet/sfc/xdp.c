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
#include "efx_channels.h"
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
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
static int efx_xsk_pool_enable(struct efx_nic *efx, struct xsk_buff_pool *pool,
			       u16 qid)
{
	struct efx_channel *channel;
	bool if_running;
	int err;

	err = xsk_pool_dma_map(pool, &efx->pci_dev->dev, 0);
	if (err)
		return err;

	channel = efx_get_channel(efx, qid);
	if_running = (efx->state == STATE_NET_UP);

	if (if_running) {
		err = efx_channel_stop_xsk_queue(channel);
		if (err) {
			netif_err(efx, drv, efx->net_dev,
				  "Channel %u Stop data path failed\n",
				  qid);
			goto xsk_q_stop_fail;
		}
	}

	channel->zc = true;

	if (if_running) {
		err = efx_channel_start_xsk_queue(channel);
		if (err) {
			netif_err(efx, drv, efx->net_dev,
				  "Channel %u Start data path failed\n",
				  qid);
			goto xsk_q_start_fail;
		}
	}

	return 0;
xsk_q_start_fail: /* try to recover old configuration */
	channel->zc = false;
	efx_channel_start_xsk_queue(channel);
xsk_q_stop_fail:
	xsk_pool_dma_unmap(pool, 0);
	return err;
}

static int efx_xsk_pool_disable(struct efx_nic *efx, u16 qid)
{
	struct net_device *netdev = efx->net_dev;
	struct efx_channel *channel;
	struct xsk_buff_pool *pool;
	bool if_running;
	int rc;

	pool = xsk_get_pool_from_qid(netdev, qid);
	if (!pool)
		return -EINVAL;

	channel = efx_get_channel(efx, qid);
	if_running = (efx->state == STATE_NET_UP);

	if (if_running) {
		rc = efx_channel_stop_xsk_queue(channel);
		if (rc)
			goto xsk_q_stop_fail;
	}

	channel->zc = false;

	if (if_running)
		efx_channel_start_xsk_queue(channel);

	xsk_pool_dma_unmap(pool, 0);

	return 0;
xsk_q_stop_fail:
	channel->zc = false;
	xsk_pool_dma_unmap(pool, 0);
	return rc;
}
#else
static int efx_xsk_umem_dma_map(struct pci_dev *pci_dev, struct xdp_umem *umem)
{
	struct device *dev = &pci_dev->dev;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
	return xsk_buff_dma_map(umem, dev, 0);
#else
	unsigned int i, j;
	dma_addr_t dma;

	for (i = 0; i < umem->npgs; i++) {
		dma = dma_map_page(dev, umem->pgs[i], 0, PAGE_SIZE,
				   DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dev, dma))
			goto out_unmap;

		umem->pages[i].dma = dma;
	}
	return 0;
out_unmap:
	for (j = 0; j < i; j++) {
		dma_unmap_page(dev, umem->pages[j].dma, PAGE_SIZE,
			       DMA_BIDIRECTIONAL);
		umem->pages[j].dma = 0;
	}

	return -EINVAL;
#endif
}

static void efx_xsk_umem_dma_unmap(struct pci_dev *pci_dev,
				   struct xdp_umem *umem)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
	xsk_buff_dma_unmap(umem, 0);
#else
	struct device *dev = &pci_dev->dev;
	unsigned int i;

	for (i = 0; i < umem->npgs; i++) {
		dma_unmap_page(dev, umem->pages[i].dma, PAGE_SIZE,
			       DMA_BIDIRECTIONAL);

		umem->pages[i].dma = 0;
	}
#endif
}

static int efx_xsk_umem_enable(struct efx_nic *efx, struct xdp_umem *umem,
			       u16 qid)
{
	struct efx_channel *channel = efx_get_channel(efx, qid);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_XSK_BUFFER_ALLOC)
	struct xdp_umem_fq_reuse *reuseq;
#endif
	bool if_running;
	int err;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_XSK_BUFFER_ALLOC)
	reuseq = xsk_reuseq_prepare(channel->rx_queue.ptr_mask + 1);
	if (!reuseq)
		return -ENOMEM;

	xsk_reuseq_free(xsk_reuseq_swap(umem, reuseq));
#endif
	err = efx_xsk_umem_dma_map(efx->pci_dev, umem);
	if (err)
		return err;

	if_running = (efx->state == STATE_NET_UP);

	if (if_running) {
		err = efx_channel_stop_xsk_queue(channel);
		if (err) {
			netif_err(efx, drv, efx->net_dev,
				  "Channel %u Stop data path failed\n",
				  qid);
			goto xsk_q_stop_fail;
		}
	}

	channel->zc = true;

	if (if_running) {
		err = efx_channel_start_xsk_queue(channel);
		if (err) {
			netif_err(efx, drv, efx->net_dev,
				  "Channel %u Start data path failed\n",
				  qid);
			goto xsk_q_start_fail;
		}
	}

	return 0;
xsk_q_start_fail: /* try to recover old configuration */
	channel->zc = false;
	efx_channel_start_xsk_queue(channel);
xsk_q_stop_fail:
	efx_xsk_umem_dma_unmap(efx->pci_dev, umem);
	return err;
}

static int efx_xsk_umem_disable(struct efx_nic *efx, u16 qid)
{
	struct net_device *netdev = efx->net_dev;
	struct efx_channel *channel;
	struct xdp_umem *umem;
	bool if_running;
	int rc;

	umem = xdp_get_umem_from_qid(netdev, qid);
	if (!umem)
		return -EINVAL;

	channel = efx_get_channel(efx, qid);
	if_running = (efx->state == STATE_NET_UP);

	if (if_running) {
		rc = efx_channel_stop_xsk_queue(channel);
		if (rc)
			goto xsk_q_stop_fail;
	}

	channel->zc = false;

	if (if_running)
		efx_channel_start_xsk_queue(channel);

	efx_xsk_umem_dma_unmap(efx->pci_dev, umem);

	return 0;
xsk_q_stop_fail:
	channel->zc = false;
	efx_xsk_umem_dma_unmap(efx->pci_dev, umem);
	return rc;
}

static inline bool efx_xsk_umem_consume_tx(struct xdp_umem *umem,
					   struct xdp_desc *desc,
					   dma_addr_t *dma)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_UMEM_CONS_TX_2PARAM)
	if (xsk_umem_consume_tx(umem, desc)) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
		*dma = xsk_buff_raw_get_dma(umem, desc->addr);
#else
		*dma = xdp_umem_get_dma(umem, desc->addr);
#endif

		return true;
	}
#else
	return xsk_umem_consume_tx(umem, dma, &desc->len);
#endif
	return false;
}
#endif /* EFX_HAVE_XSK_POOL */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
static int efx_xsk_pool_setup(struct efx_nic *efx, struct xsk_buff_pool *pool,
			      u16 qid)
#else
static int efx_xsk_umem_setup(struct efx_nic *efx, struct xdp_umem *umem,
			      u16 qid)
#endif
{
	struct net_device *netdev = efx->net_dev;

	if (qid >= netdev->real_num_rx_queues ||
	    qid >= netdev->real_num_tx_queues)
		return -EINVAL;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	return pool ? efx_xsk_pool_enable(efx, pool, qid) :
		efx_xsk_pool_disable(efx, qid);
#else
	return umem ? efx_xsk_umem_enable(efx, umem, qid) :
		efx_xsk_umem_disable(efx, qid);
#endif
}

static void efx_xmit_zc(struct efx_tx_queue *tx_queue)
{
	struct efx_tx_buffer *tx_buf;
	unsigned int total_bytes = 0;
	unsigned int pkt_cnt = 0;
	struct xdp_desc desc;
	dma_addr_t dma;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	while (tx_queue->xsk_pool) {
		if (!xsk_tx_peek_desc(tx_queue->xsk_pool, &desc))
			break;
		dma = xsk_buff_raw_get_dma(tx_queue->xsk_pool, desc.addr);
#else
	while (tx_queue->umem) {
		if (!efx_xsk_umem_consume_tx(tx_queue->umem, &desc, &dma))
			break;
#endif
		prefetchw(__efx_tx_queue_get_insert_buffer(tx_queue));

		tx_buf = efx_tx_map_chunk(tx_queue, dma, desc.len);
		if (!tx_buf)
			break;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
                xsk_buff_raw_dma_sync_for_device(tx_queue->xsk_pool,
						 dma, desc.len);
#else
                xsk_buff_raw_dma_sync_for_device(tx_queue->umem, dma, desc.len);
#endif
#else
		dma_sync_single_for_device(&tx_queue->efx->net_dev->dev, dma,
					   desc.len, DMA_TO_DEVICE);
#endif
		tx_buf->flags |= EFX_TX_BUF_XSK;
		tx_buf->flags &= ~EFX_TX_BUF_CONT;
		pkt_cnt++;
		total_bytes += desc.len;
	}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	if (tx_queue->xsk_pool && pkt_cnt) {
#else
	if (tx_queue->umem && pkt_cnt) {
#endif
		efx_nic_push_buffers(tx_queue);

		tx_queue->tx_packets += pkt_cnt;
		tx_queue->tx_bytes += total_bytes;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
		xsk_tx_release(tx_queue->xsk_pool);
#else
		xsk_umem_consume_tx_done(tx_queue->umem);
#endif
	}
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_NEED_WAKEUP)
int efx_xsk_wakeup(struct net_device *dev, u32 queue_id, u32 flags)
#else
int efx_xsk_async_xmit(struct net_device *dev, u32 queue_id)
#endif
{
	struct efx_nic *efx = efx_netdev_priv(dev);
	struct efx_tx_queue *tx_queue;
	struct efx_channel *channel;

	if (!netif_running(dev))
		return -EINVAL;

	channel = efx_get_tx_channel(efx, queue_id);
	if (!channel || !channel->zc)
		return -EINVAL;
	tx_queue = efx_channel_get_xsk_tx_queue(channel);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
	if (unlikely(!tx_queue || !tx_queue->xsk_pool ||
#else
	if (unlikely(!tx_queue || !tx_queue->umem ||
#endif
		     !efx_is_xsk_tx_queue(tx_queue)))
		return -EINVAL;
	efx_xmit_zc(tx_queue);

	return 0;
}
#endif
#endif

int efx_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	struct efx_nic *efx = efx_netdev_priv(dev);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_XDP_QUERY_PROG)
	struct bpf_prog *xdp_prog;
#endif

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return efx_xdp_setup_prog(efx, xdp->prog);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_XDP_QUERY_PROG)
	case XDP_QUERY_PROG:
		xdp_prog = rtnl_dereference(efx->xdp_prog);
#if defined(EFX_USE_KCOMPAT) && (defined(EFX_HAVE_XDP_PROG_ATTACHED) || defined(EFX_HAVE_XDP_OLD))
		xdp->prog_attached = !!xdp_prog;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_PROG_ID) || !defined(EFX_HAVE_XDP_OLD)
		xdp->prog_id = xdp_prog ? xdp_prog->aux->id : 0;
#endif
		return 0;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XSK_POOL)
#if defined(CONFIG_XDP_SOCKETS)
	case XDP_SETUP_XSK_POOL:
		return efx_xsk_pool_setup(efx, xdp->xsk.pool,
					  xdp->xsk.queue_id);
#endif
#else
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
	case XDP_SETUP_XSK_UMEM:
		return efx_xsk_umem_setup(efx, xdp->xsk.umem,
					  xdp->xsk.queue_id);
#endif
#endif
#endif /* EFX_HAVE_XSK_POOL*/
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
	struct efx_nic *efx = efx_netdev_priv(dev);

	if (!netif_running(dev))
		return -EINVAL;

	return efx_xdp_tx_buffers(efx, n, xdpfs, flags & XDP_XMIT_FLUSH);
}
#else
int efx_xdp_xmit(struct net_device *dev, struct xdp_frame *xdpf)
{
	struct efx_nic *efx = efx_netdev_priv(dev);
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
	efx_xdp_tx_buffers(efx_netdev_priv(dev), 0, NULL, true);
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
int efx_xdp_rx(struct efx_nic *efx, struct efx_rx_queue *rx_queue,
	       struct efx_rx_buffer *rx_buf, u8 **ehp)
{
	u8 rx_prefix[EFX_MAX_RX_PREFIX_SIZE];
	struct xdp_buff *xdp_ptr, xdp;
	bool free_buf_on_fail = true;
	struct bpf_prog *xdp_prog;
	struct xdp_frame *xdpf;
	u32 xdp_act;

	s16 offset;
	int rc;

	rcu_read_lock();
	xdp_prog = rcu_dereference(efx->xdp_prog);
	if (!xdp_prog) {
		rcu_read_unlock();
		return XDP_PASS;
	}

	if (unlikely(rx_queue->rx_pkt_n_frags > 1)) {
		/* We can't do XDP on fragmented packets - drop. */
		rcu_read_unlock();
		efx_free_rx_buffers(rx_queue, rx_buf,
				    rx_queue->rx_pkt_n_frags);
		if (net_ratelimit())
			netif_err(efx, rx_err, efx->net_dev,
				  "XDP is not possible with multiple receive fragments (%d)\n",
				  rx_queue->rx_pkt_n_frags);
		rx_queue->n_rx_xdp_bad_drops++;
		return XDP_DROP;
	}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
	if (rx_buf->flags & EFX_RX_BUF_ZC)
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_XSK_POOL) && defined(EFX_HAVE_XSK_BUFF_DMA_SYNC_FOR_CPU_2PARAM)
		xsk_buff_dma_sync_for_cpu(rx_buf->xsk_buf, rx_queue->xsk_pool);
#else
		xsk_buff_dma_sync_for_cpu(rx_buf->xsk_buf);
#endif
	else
#endif /* EFX_USE_XSK_BUFFER_ALLOC */
#endif /* CONFIG_XDP_SOCKETS */
		dma_sync_single_for_cpu(&efx->pci_dev->dev, rx_buf->dma_addr,
					rx_buf->len, DMA_FROM_DEVICE);
#else
	dma_sync_single_for_cpu(&efx->pci_dev->dev, rx_buf->dma_addr,
				rx_buf->len, DMA_FROM_DEVICE);
#endif

	/* Save the rx prefix. */
	EFX_WARN_ON_PARANOID(efx->rx_prefix_size > EFX_MAX_RX_PREFIX_SIZE);
	memcpy(rx_prefix, *ehp - efx->rx_prefix_size,
	       efx->rx_prefix_size);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_RXQ_INFO)
	xdp_init_buff(&xdp, efx->rx_page_buf_step, &rx_queue->xdp_rxq_info);
#else
	xdp_init_buff(&xdp, efx->rx_page_buf_step);
#endif

	/* No support yet for XDP metadata */
	xdp_prepare_buff(&xdp, *ehp - XDP_PACKET_HEADROOM, XDP_PACKET_HEADROOM,
			 rx_buf->len, false);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	if (efx_rx_queue_channel(rx_queue)->zc) {
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_XDP_SOCK) && defined(EFX_HAVE_XSK_OFFSET_ADJUST)
		xdp.handle = rx_buf->handle;
#endif
		free_buf_on_fail = false;
	}
#endif
	xdp_act = bpf_prog_run_xdp(xdp_prog, &xdp);
	rcu_read_unlock();

	offset = (u8 *)xdp.data - *ehp;

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_XDP_SOCK) && defined(EFX_HAVE_XSK_OFFSET_ADJUST)
#if defined(CONFIG_XDP_SOCKETS)
	if (efx_rx_queue_channel(rx_queue)->zc)
		xdp.handle = xsk_umem_adjust_offset(rx_queue->umem, xdp.handle,
						    xdp.data -
						    xdp.data_hard_start +
						    efx->rx_prefix_size);
#endif
#endif
	xdp_ptr = &xdp;
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
#if !defined(EFX_USE_KCOMPAT) || (defined(EFX_HAVE_XDP_SOCK) && defined(EFX_USE_XSK_BUFFER_ALLOC))
#if defined(CONFIG_XDP_SOCKETS)
		if (rx_buf->flags & EFX_RX_BUF_ZC) {
			xdp_ptr = rx_buf->xsk_buf;
			xdp_ptr->data = xdp.data;
		}
#endif
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_COVERT_XDP_BUFF_FRAME_API)
		xdpf = xdp_convert_buff_to_frame(xdp_ptr);
#else
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_FRAME_API)
		xdpf = convert_to_xdp_frame(xdp_ptr);
#else
		xdpf = xdp_ptr;
#endif
#endif
		rc = efx_xdp_tx_buffers(efx, 1, &xdpf, true);
		if (rc != 1) {
			if (free_buf_on_fail)
				efx_free_rx_buffers(rx_queue, rx_buf, 1);
			if (net_ratelimit())
				netif_err(efx, rx_err, efx->net_dev,
					  "XDP TX failed (%d)\n", rc);
			rx_queue->n_rx_xdp_bad_drops++;
			xdp_act = XDP_DROP;
		} else {
			rx_queue->n_rx_xdp_tx++;
		}
		break;
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_REDIR)
	case XDP_REDIRECT:
#if !defined(EFX_USE_KCOMPAT) || (defined(EFX_HAVE_XDP_SOCK) && defined(EFX_USE_XSK_BUFFER_ALLOC))
#if defined(CONFIG_XDP_SOCKETS)
		if (rx_buf->flags & EFX_RX_BUF_ZC) {
			xdp_ptr = rx_buf->xsk_buf;
			xdp_ptr->data = xdp.data;
			xdp_ptr->data_end = xdp.data_end;
		}
#endif
#endif
		rc = xdp_do_redirect(efx->net_dev, xdp_ptr, xdp_prog);
		if (rc) {
			if (free_buf_on_fail)
				efx_free_rx_buffers(rx_queue, rx_buf, 1);
			if (net_ratelimit())
				netif_err(efx, rx_err, efx->net_dev,
					  "XDP redirect failed (%d)\n", rc);
			rx_queue->n_rx_xdp_bad_drops++;
			xdp_act = XDP_DROP;
		} else {
			rx_queue->n_rx_xdp_redirect++;
		}
		break;
#endif

	default:
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_BPF_WARN_INVALID_XDP_ACTION_3PARAM)
		bpf_warn_invalid_xdp_action(efx->net_dev, xdp_prog, xdp_act);
#else
		bpf_warn_invalid_xdp_action(xdp_act);
#endif
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(efx->net_dev, xdp_prog, xdp_act);
		if (free_buf_on_fail)
			efx_free_rx_buffers(rx_queue, rx_buf, 1);
		rx_queue->n_rx_xdp_bad_drops++;
		break;

	case XDP_DROP:
		if (free_buf_on_fail)
			efx_free_rx_buffers(rx_queue, rx_buf, 1);
		rx_queue->n_rx_xdp_drops++;
		break;
	}

	return xdp_act;
}
#endif

