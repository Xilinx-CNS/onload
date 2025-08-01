/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <net/ip6_checksum.h>

#include "net_driver.h"
#include "efx.h"
#include "nic.h"
#include "mcdi_functions.h"
#include "tx_common.h"
#include "ef100_regs.h"
#include "io.h"
#include "ef100.h"
#include "ef100_tx.h"
#include "ef100_nic.h"

#ifdef EFX_C_MODEL
#define EF100_MAX_DESC_BATCH	63	/* Bug 85534 */
#endif

int ef100_tx_probe(struct efx_tx_queue *tx_queue)
{
	/* Allocate an extra descriptor for the QMDA status completion entry */
	return efx_nic_alloc_buffer(tx_queue->efx, &tx_queue->txd,
				    (tx_queue->ptr_mask + 2) *
				    sizeof(efx_oword_t), GFP_KERNEL);
}

int ef100_tx_init(struct efx_tx_queue *tx_queue)
{
	tx_queue->tso_version = 3;	/* Not used but shown in debugfs */
	return efx_mcdi_tx_init(tx_queue, NULL);
}

unsigned int ef100_tx_max_skb_descs(struct efx_nic *efx)
{
	/* Option (PREFIX) descriptor, then header (TSO or SEND descriptor),
	 * potentially one (SEG) descriptor for the rest of the linear area,
	 * plus one (SEG) descriptor per fragment.
	 */
	return 3 + MAX_SKB_FRAGS;
}

static bool ef100_tx_can_tso(struct efx_tx_queue *tx_queue, struct sk_buff *skb)
{
	struct efx_nic *efx = tx_queue->efx;
	struct ef100_nic_data *nic_data;
	struct efx_tx_buffer *buffer;
	size_t header_len;
	u32 mss;

	nic_data = efx->nic_data;

	if (!skb_is_gso_tcp(skb))
		return false;
	if (!(efx->net_dev->features & NETIF_F_TSO))
		return false;

	mss = skb_shinfo(skb)->gso_size;
	if (unlikely(mss < 4)) {
		WARN_ONCE(1, "MSS of %u is too small for TSO\n", mss);
		return false;
	}

	header_len = efx_tx_tso_header_length(skb);
	if (header_len > nic_data->tso_max_hdr_len)
		return false;

	if (skb_shinfo(skb)->gso_segs > nic_data->tso_max_payload_num_segs) {
		/* net_dev->gso_max_segs should've caught this */
		WARN_ON_ONCE(1);
		return false;
	}

	if (skb->data_len / mss > nic_data->tso_max_frames)
		return false;

	/* net_dev->gso_max_size should've caught this */
	if (WARN_ON_ONCE(skb->data_len > nic_data->tso_max_payload_len))
		return false;

	/* Reserve an empty buffer for the TSO V3 descriptor.
	 * Convey the length of the header since we already know it.
	 */
	buffer = efx_tx_queue_get_insert_buffer(tx_queue);
	buffer->flags = EFX_TX_BUF_TSO_V3 | EFX_TX_BUF_CONT;
	buffer->len = header_len;
	buffer->unmap_len = 0;
	buffer->skb = skb;
	++tx_queue->insert_count;
	return true;
}

static inline efx_oword_t *ef100_tx_desc(struct efx_tx_queue *tx_queue,
					 unsigned int index)
{
	if (likely(tx_queue->txd.addr))
		return ((efx_oword_t *)(tx_queue->txd.addr)) + index;
	else
		return NULL;
}

void ef100_notify_tx_desc(struct efx_tx_queue *tx_queue)
{
	unsigned int write_ptr;
	efx_dword_t reg;

	tx_queue->xmit_pending = false;

	if (unlikely(tx_queue->notify_count == tx_queue->write_count))
		return;

#ifdef EF100_MAX_DESC_BATCH
	/* We can only ring the doorbell for a limited number of descriptors
	 * at a time.
	 * Each notification must be aligned to a TxQ request boundary.
	 */
	WARN_ON(tx_queue->write_count - tx_queue->notify_count >
		EF100_MAX_DESC_BATCH);
#endif

	write_ptr = tx_queue->write_count & tx_queue->ptr_mask;
	/* The write pointer goes into the high word */
	EFX_POPULATE_DWORD_1(reg, ERF_GZ_TX_RING_PIDX, write_ptr);
	efx_writed_page(tx_queue->efx, &reg,
			ER_GZ_TX_RING_DOORBELL, tx_queue->queue);
	tx_queue->notify_count = tx_queue->write_count;
	tx_queue->notify_jiffies = jiffies;
	++tx_queue->doorbell_notify_tx;
}

static void ef100_tx_push_buffers(struct efx_tx_queue *tx_queue)
{
	/* If the completion path is running and module option
	 * to enable coalescing is set we let the completion path
	 * handle the doorbell ping.
	 */
	if (!tx_queue->channel->holdoff_doorbell) {
		/* Completion handler not running so send out */
		ef100_notify_tx_desc(tx_queue);
		++tx_queue->pushes;
	}
}

static void ef100_set_tx_csum_partial(const struct sk_buff *skb,
				      struct efx_tx_buffer *buffer, efx_oword_t *txd)
{
	efx_oword_t csum;
	int csum_start;

	if (!skb || skb->ip_summed != CHECKSUM_PARTIAL)
		return;

	/* skb->csum_start has the offset from head, but we need the offset
	 * from data.
	 */
	csum_start = skb_checksum_start_offset(skb);
	EFX_POPULATE_OWORD_3(csum,
			     ESF_GZ_TX_SEND_CSO_PARTIAL_EN, 1,
			     ESF_GZ_TX_SEND_CSO_PARTIAL_START_W,
			     csum_start >> 1,
			     ESF_GZ_TX_SEND_CSO_PARTIAL_CSUM_W,
			     skb->csum_offset >> 1);
	EFX_OR_OWORD(*txd, *txd, csum);
}

static void ef100_set_tx_hw_vlan(const struct sk_buff *skb, efx_oword_t *txd)
{
	u16 vlan_tci = skb_vlan_tag_get(skb);
	efx_oword_t vlan;

	EFX_POPULATE_OWORD_2(vlan,
			     ESF_GZ_TX_SEND_VLAN_INSERT_EN, 1,
			     ESF_GZ_TX_SEND_VLAN_INSERT_TCI, vlan_tci);
	EFX_OR_OWORD(*txd, *txd, vlan);
}

static void ef100_make_send_desc(struct efx_nic *efx,
				 const struct sk_buff *skb,
				 struct efx_tx_buffer *buffer, efx_oword_t *txd,
				 unsigned int segment_count)
{
	dma_addr_t dma_addr = buffer->dma_addr;

	/* TODO: Deal with failure. */
	if (ef100_regionmap_buffer(efx, &dma_addr))
		return;

	/* TX send descriptor */
	EFX_POPULATE_OWORD_3(*txd,
			     ESF_GZ_TX_SEND_NUM_SEGS, segment_count,
			     ESF_GZ_TX_SEND_LEN, buffer->len,
			     ESF_GZ_TX_SEND_ADDR, dma_addr);

	if (likely(efx->net_dev->features & NETIF_F_HW_CSUM))
		ef100_set_tx_csum_partial(skb, buffer, txd);
	if (efx->net_dev->features & NETIF_F_HW_VLAN_CTAG_TX &&
	    skb && skb_vlan_tag_present(skb))
		ef100_set_tx_hw_vlan(skb, txd);
}

static void ef100_make_tso_desc(struct efx_nic *efx,
				const struct sk_buff *skb,
				struct efx_tx_buffer *buffer, efx_oword_t *txd,
				unsigned int segment_count)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GSO_PARTIAL)
	bool gso_partial = skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL;
#else
	bool gso_partial = false;
#endif
	unsigned int len, ip_offset, tcp_offset, payload_segs;
	u32 mangleid = ESE_GZ_TX_DESC_IP4_ID_INC_MOD16;
	unsigned int outer_ip_offset, outer_l4_offset;
	u16 vlan_tci = skb_vlan_tag_get(skb);
	u32 mss = skb_shinfo(skb)->gso_size;
	bool encap = skb->encapsulation;
	bool vlan_enable = false;
	bool udp_encap = false;
	struct tcphdr *tcp;
	bool outer_csum;
	u32 paylen;

	if (skb_shinfo(skb)->gso_type & SKB_GSO_TCP_FIXEDID)
		mangleid = ESE_GZ_TX_DESC_IP4_ID_NO_OP;
	if (efx->net_dev->features & NETIF_F_HW_VLAN_CTAG_TX)
		vlan_enable = skb_vlan_tag_present(skb);

	len = skb->len - buffer->len;
	/* We use 1 for the TSO descriptor and 1 for the header */
	payload_segs = segment_count - 2;
	if (encap) {
		outer_ip_offset = skb_network_offset(skb);
		outer_l4_offset = skb_transport_offset(skb);
		ip_offset = skb_inner_network_offset(skb);
		tcp_offset = skb_inner_transport_offset(skb);
		if (skb_shinfo(skb)->gso_type &
		    (SKB_GSO_UDP_TUNNEL | SKB_GSO_UDP_TUNNEL_CSUM))
			udp_encap = true;
	} else {
		ip_offset =  skb_network_offset(skb);
		tcp_offset = skb_transport_offset(skb);
		outer_ip_offset = outer_l4_offset = 0;
	}
	outer_csum = skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM;

	/* subtract TCP payload length from inner checksum */
	tcp = (void *)skb->data + tcp_offset;
	paylen = skb->len - tcp_offset;
	csum_replace_by_diff(&tcp->check, (__force __wsum)htonl(paylen));

	EFX_POPULATE_OWORD_19(*txd,
			      ESF_GZ_TX_DESC_TYPE, ESE_GZ_TX_DESC_TYPE_TSO,
			      ESF_GZ_TX_TSO_MSS, mss,
			      ESF_GZ_TX_TSO_HDR_NUM_SEGS, 1,
			      ESF_GZ_TX_TSO_PAYLOAD_NUM_SEGS, payload_segs,
			      ESF_GZ_TX_TSO_HDR_LEN_W, buffer->len >> 1,
			      ESF_GZ_TX_TSO_PAYLOAD_LEN, len,
			      ESF_GZ_TX_TSO_CSO_OUTER_L4, outer_csum,
			      ESF_GZ_TX_TSO_CSO_INNER_L4, 1,
			      ESF_GZ_TX_TSO_INNER_L3_OFF_W, ip_offset >> 1,
			      ESF_GZ_TX_TSO_INNER_L4_OFF_W, tcp_offset >> 1,
			      ESF_GZ_TX_TSO_ED_INNER_IP4_ID, mangleid,
			      ESF_GZ_TX_TSO_ED_INNER_IP_LEN, 1,
			      ESF_GZ_TX_TSO_OUTER_L3_OFF_W, outer_ip_offset >> 1,
			      ESF_GZ_TX_TSO_OUTER_L4_OFF_W, outer_l4_offset >> 1,
			      ESF_GZ_TX_TSO_ED_OUTER_UDP_LEN, udp_encap && !gso_partial,
			      ESF_GZ_TX_TSO_ED_OUTER_IP_LEN, encap && !gso_partial,
			      ESF_GZ_TX_TSO_ED_OUTER_IP4_ID, encap ? mangleid :
								     ESE_GZ_TX_DESC_IP4_ID_NO_OP,
			      ESF_GZ_TX_TSO_VLAN_INSERT_EN, vlan_enable,
			      ESF_GZ_TX_TSO_VLAN_INSERT_TCI, vlan_tci
		);
}

static void ef100_make_seg_desc(struct efx_nic *efx,
				struct efx_tx_buffer *buffer, efx_oword_t *txd)
{
	dma_addr_t dma_addr = buffer->dma_addr;

	/* TODO: Deal with failure. */
	if (ef100_regionmap_buffer(efx, &dma_addr))
		return;

	/* TX segment descriptor */
	EFX_POPULATE_OWORD_3(*txd,
			     ESF_GZ_TX_DESC_TYPE, ESE_GZ_TX_DESC_TYPE_SEG,
			     ESF_GZ_TX_SEG_LEN, buffer->len,
			     ESF_GZ_TX_SEG_ADDR, dma_addr);
}

static void ef100_tx_make_descriptors(struct efx_tx_queue *tx_queue,
				      const struct sk_buff *skb,
				      unsigned int segment_count,
				      struct efx_rep *efv)
{
	unsigned int old_write_count = tx_queue->write_count;
	unsigned int new_write_count = old_write_count;
	struct efx_nic *efx = tx_queue->efx;
	struct efx_tx_buffer *buffer;
	unsigned int next_desc_type;
	unsigned int write_ptr;
	efx_oword_t *txd;
	unsigned int nr_descs = tx_queue->insert_count - old_write_count;

	if (unlikely(nr_descs == 0))
		return;

#ifdef EF100_MAX_DESC_BATCH
	/* Ensure there is room for the new descriptors. */
	if (old_write_count - tx_queue->notify_count + nr_descs >
	    EF100_MAX_DESC_BATCH)
		ef100_notify_tx_desc(tx_queue);
#endif

	if (segment_count)
		next_desc_type = ESE_GZ_TX_DESC_TYPE_TSO;
	else
		next_desc_type = ESE_GZ_TX_DESC_TYPE_SEND;

	if (unlikely(efv)) {
		/* Create TX override descriptor */
		write_ptr = new_write_count & tx_queue->ptr_mask;
		txd = ef100_tx_desc(tx_queue, write_ptr);
		++new_write_count;

		tx_queue->packet_write_count = new_write_count;
		EFX_POPULATE_OWORD_3(*txd,
				     ESF_GZ_TX_DESC_TYPE, ESE_GZ_TX_DESC_TYPE_PREFIX,
				     ESF_GZ_TX_PREFIX_EGRESS_MPORT, efv->mport,
				     ESF_GZ_TX_PREFIX_EGRESS_MPORT_EN, 1);
		nr_descs--;
	}

	/* if it's a raw write (such as XDP) then always SEND single frames */
	if (!skb)
		nr_descs = 1;

	do {
		write_ptr = new_write_count & tx_queue->ptr_mask;
		buffer = &tx_queue->buffer[write_ptr];

		txd = ef100_tx_desc(tx_queue, write_ptr);
		++new_write_count;
		/* Create TX descriptor ring entry */
		tx_queue->packet_write_count = new_write_count;

		switch (next_desc_type) {
		case ESE_GZ_TX_DESC_TYPE_SEND:
			ef100_make_send_desc(efx, skb, buffer, txd, nr_descs);
			break;
		case ESE_GZ_TX_DESC_TYPE_TSO:
			/* TX TSO descriptor */
			WARN_ON_ONCE(!(buffer->flags & EFX_TX_BUF_TSO_V3));
			ef100_make_tso_desc(efx, skb, buffer, txd, nr_descs);
			break;
		default:
			ef100_make_seg_desc(efx, buffer, txd);
		}
		/* if it's a raw write (such as XDP) then always SEND */
		next_desc_type = skb ? ESE_GZ_TX_DESC_TYPE_SEG :
				       ESE_GZ_TX_DESC_TYPE_SEND;
		/* mark as an EFV buffer if applicable */
		if (unlikely(efv))
			buffer->flags |= EFX_TX_BUF_EFV;

#if 0		/* Dump the TX descriptor */
		netif_dbg(efx, tx_queued, efx->net_dev,
			  "TX desc %d: " EFX_OWORD_FMT " len %d flags 0x%x\n",
			  write_ptr, EFX_OWORD_VAL(*txd), buffer->len,
			  buffer->flags);
#endif
	} while (new_write_count != tx_queue->insert_count);

	wmb(); /* Ensure descriptors are written before they are fetched */

	tx_queue->write_count = new_write_count;

	/* The write_count above must be updated before reading
	 * channel->holdoff_doorbell to avoid a race with the
	 * completion path, so ensure these operations are not
	 * re-ordered.  This also flushes the update of write_count
	 * back into the cache.
	 */
	smp_mb();
}

void ef100_tx_write(struct efx_tx_queue *tx_queue)
{
	ef100_tx_make_descriptors(tx_queue, NULL, 0, NULL);
	ef100_tx_push_buffers(tx_queue);
}

void ef100_ev_tx(struct efx_channel *channel, const efx_qword_t *p_event)
{
	unsigned int tx_done =
		EFX_QWORD_FIELD(*p_event, ESF_GZ_EV_TXCMPL_NUM_DESC);
	unsigned int qlabel =
		EFX_QWORD_FIELD(*p_event, ESF_GZ_EV_TXCMPL_Q_LABEL);
	struct efx_tx_queue *tx_queue =
		efx_channel_get_tx_queue(channel, qlabel);
	unsigned int tx_index = (tx_queue->read_count + tx_done - 1) &
				tx_queue->ptr_mask;

	efx_xmit_done(tx_queue, tx_index);
}

/*
 * Add a socket buffer to a TX queue
 *
 * You must hold netif_tx_lock() to call this function.

 * Returns 0 on success, error code otherwise. In case of an error this
 * function will free the SKB.
 */
int ef100_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb)
{
	return __ef100_enqueue_skb(tx_queue, skb, NULL);
}

int __ef100_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb,
			struct efx_rep *efv)
{
	unsigned int old_insert_count = tx_queue->insert_count;
	struct efx_nic *efx = tx_queue->efx;
	bool xmit_more = netdev_xmit_more();
	unsigned int fill_level;
	unsigned int segments;
	int rc;

	if (!tx_queue->buffer || !tx_queue->ptr_mask) {
		netif_err(efx, tx_err, efx->net_dev,
			  "Bad TX %s, stopping queue\n",
			  tx_queue->buffer ? "ring mask" : "buffer array");
		netif_stop_queue(efx->net_dev);
		dev_kfree_skb_any(skb);
		return -ENODEV;
	}

	segments = skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 0;
	if (segments == 1)
		segments = 0;	/* Don't use TSO/GSO for a single segment. */
	if (segments && !ef100_tx_can_tso(tx_queue, skb)) {
		rc = efx_tx_tso_fallback(tx_queue, skb);
		tx_queue->tso_fallbacks++;
		if (rc)
			goto err;
		else
			return 0;
	}

	if (unlikely(efv)) {
		struct efx_tx_buffer *buffer = __efx_tx_queue_get_insert_buffer(tx_queue);

		/* Drop representor packets if the queue is stopped.
		 * We currently don't assert backoff to representors so this is
		 * to make sure representor traffic can't starve the main
		 * net device.
		 * And, of course, if there are no TX descriptors left.
		 */
		if (netif_tx_queue_stopped(tx_queue->core_txq) ||
		    unlikely(efx_tx_buffer_in_use(buffer))) {
			atomic64_inc(&efv->stats.tx_errors);
			rc = -ENOSPC;
			goto err;
		}

		/* Also drop representor traffic if it could cause us to
		 * stop the queue. If we assert backoff and we haven't
		 * received traffic on the main net device recently then the
		 * TX watchdog can go off erroneously.
		 */
		fill_level = efx_channel_tx_old_fill_level(tx_queue->channel);
		fill_level += efx->type->tx_max_skb_descs(efx);
		if (fill_level > efx->txq_stop_thresh) {
			struct efx_tx_queue *txq2;

			/* Refresh cached fill level and re-check */
			efx_for_each_channel_tx_queue(txq2, tx_queue->channel)
				txq2->old_read_count = READ_ONCE(txq2->read_count);

			fill_level = efx_channel_tx_old_fill_level(tx_queue->channel);
			fill_level += efx->type->tx_max_skb_descs(efx);
			if (fill_level > efx->txq_stop_thresh) {
				atomic64_inc(&efv->stats.tx_errors);
				rc = -ENOSPC;
				goto err;
			}
		}

		buffer->flags = EFX_TX_BUF_OPTION | EFX_TX_BUF_EFV;
		tx_queue->insert_count++;
	}

	/* Map for DMA and create descriptors */
	rc = efx_tx_map_data(tx_queue, skb, segments);
	if (rc)
		goto err;
	ef100_tx_make_descriptors(tx_queue, skb, segments, efv);

	EFX_WARN_ON_PARANOID(!tx_queue->core_txq);

	fill_level = efx_channel_tx_old_fill_level(tx_queue->channel);
	if (fill_level > efx->txq_stop_thresh) {
		struct efx_tx_queue *txq2;

		/* Because of checks above, representor traffic should
		 * not be able to stop the queue.
		 */
		WARN_ON(efv);

		netif_tx_stop_queue(tx_queue->core_txq);
		/* Re-read after a memory barrier in case we've raced with
		 * the completion path. Otherwise there's a danger we'll never
		 * restart the queue if all completions have just happened.
		 */
		smp_mb();
		efx_for_each_channel_tx_queue(txq2, tx_queue->channel)
			txq2->old_read_count = READ_ONCE(txq2->read_count);
		fill_level = efx_channel_tx_old_fill_level(tx_queue->channel);
		if (fill_level < efx->txq_stop_thresh)
			netif_tx_start_queue(tx_queue->core_txq);
	}

	if (unlikely(efv))
		/* always push for representor traffic */
		tx_queue->xmit_pending = false;
	else if (__netdev_tx_sent_queue(tx_queue->core_txq, skb->len,
					xmit_more))
		tx_queue->xmit_pending = false; /* push doorbell */
	else if (tx_queue->write_count - tx_queue->notify_count > 255)
		/* Ensure we never push more than 256 packets at once */
		tx_queue->xmit_pending = false; /* push */
	else
		tx_queue->xmit_pending = true; /* don't push yet */

	if (!tx_queue->xmit_pending)
		ef100_tx_push_buffers(tx_queue);

	if (segments) {
		tx_queue->tso_bursts++;
		tx_queue->tso_packets += segments;
		tx_queue->tx_packets  += segments;
	} else {
		tx_queue->tx_packets++;
	}
	tx_queue->tx_bytes += skb->len;
	return 0;

err:
	efx_enqueue_unwind(tx_queue, old_insert_count);
	if (!IS_ERR_OR_NULL(skb))
		dev_kfree_skb_any(skb);

	/* If we're not expecting another transmit and we had something to push
	 * on this queue then we need to push here to get the previous packets
	 * out.  We only enter this branch from before the xmit_more handling
	 * above, so xmit_pending still refers to the old state.
	 */
	if (tx_queue->xmit_pending && !xmit_more)
		ef100_tx_push_buffers(tx_queue);
	return rc;
}
