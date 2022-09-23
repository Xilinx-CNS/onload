/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include "ef100_rx.h"
#include "efx.h"
#include "nic.h"
#include "rx_common.h"
#include "xdp.h"
#include "mcdi_functions.h"
#include "ef100.h"
#include "ef100_regs.h"
#include "ef100_nic.h"
#include "ef100_rep.h"
#include "io.h"

/* Do the frame checksum on the whole frame. */
#undef BUG85159_CSUM_FRAME

/* Get the value of a field in the RX prefix */
#define PREFIX_OFFSET_W(_f)	(ESF_GZ_RX_PREFIX_ ## _f ## _LBN)/32
#define PREFIX_OFFSET_B(_f)	(ESF_GZ_RX_PREFIX_ ## _f ## _LBN)%32
#define PREFIX_WIDTH_MASK(_f)	((1UL<<(ESF_GZ_RX_PREFIX_ ## _f ## _WIDTH)) - 1)
#define PREFIX_WORD(_p,_f)	le32_to_cpu((__force __le32) (_p)[ PREFIX_OFFSET_W(_f) ])
#define PREFIX_FIELD(_p,_f)	((PREFIX_WORD(_p,_f) >>			\
				  PREFIX_OFFSET_B(_f)) & PREFIX_WIDTH_MASK(_f))

/* Get the value of a field in the classification and checksum substructure
 * of the RX prefix (rh_egres_hclass)
 */
#define PREFIX_HCLASS_OFFSET_W(_f) \
	(ESF_GZ_RX_PREFIX_CLASS_LBN + ESF_GZ_RX_PREFIX_HCLASS_ ## _f ## _LBN)/32
#define PREFIX_HCLASS_OFFSET_B(_f) \
	(ESF_GZ_RX_PREFIX_CLASS_LBN + ESF_GZ_RX_PREFIX_HCLASS_ ## _f ## _LBN)%32
#define PREFIX_HCLASS_WIDTH_MASK(_f) \
	((1UL<<(ESF_GZ_RX_PREFIX_HCLASS_ ## _f ## _WIDTH)) - 1)
#define PREFIX_HCLASS_WORD(_p,_f) \
	le32_to_cpu((__force __le32) (_p)[ PREFIX_HCLASS_OFFSET_W(_f) ])
#define PREFIX_HCLASS_FIELD(_p,_f) \
	((PREFIX_HCLASS_WORD(_p,_f) >> PREFIX_HCLASS_OFFSET_B(_f)) & \
	 PREFIX_HCLASS_WIDTH_MASK(_f))

int ef100_rx_probe(struct efx_rx_queue *rx_queue)
{
	return efx_nic_alloc_buffer(rx_queue->efx, &rx_queue->rxd,
				    (rx_queue->ptr_mask + 1) *
				    sizeof(efx_qword_t), GFP_KERNEL);
}

int ef100_rx_init(struct efx_rx_queue *rx_queue)
{
	return efx_mcdi_rx_init(rx_queue, false);
}

bool ef100_rx_buf_hash_valid(const u8 *prefix)
{
	return PREFIX_FIELD(prefix, RSS_HASH_VALID);
}

/* On older FPGA images the slice gives us the ones complement checksum of the
 * whole frame in big endian format.
 *
 * The IP stack wants the ones complement checksum starting after the
 * ethernet header in CPU endian-ness. So on older FPGA images subtract the
 * ethernet header from the original value.
 */
static __wsum get_csum(u8 *va, u32 *prefix, bool csum_frame)
{
	__sum16 ethsum, ret16;
	__u16 hw1;

	hw1 = be16_to_cpu((__force __be16) PREFIX_FIELD(prefix, CSUM_FRAME));
	WARN_ON_ONCE(!hw1);
	if (!csum_frame)
		return (__force __wsum) hw1;

	ethsum = csum_fold(csum_partial(va, sizeof(struct ethhdr), 0));
	ret16 = csum16_sub((__force __sum16) ~hw1, (__force __be16) ethsum);
	return (__force __wsum) ~ret16;
}

static bool ef100_has_fcs_error(struct efx_rx_queue *rx_queue, u32 *prefix)
{
	u16 fcsum;

	fcsum = le16_to_cpu((__force __le16) PREFIX_FIELD(prefix, CLASS));
	fcsum = PREFIX_FIELD(&fcsum, HCLASS_L2_STATUS);

	if (likely(fcsum == ESE_GZ_RH_HCLASS_L2_STATUS_OK)) {
		/* Everything is ok */
		return false;
	} else if (fcsum == ESE_GZ_RH_HCLASS_L2_STATUS_FCS_ERR) {
		rx_queue->n_rx_eth_crc_err++;
	}

	return true;
}

void __ef100_rx_packet(struct efx_rx_queue *rx_queue)
{
	struct efx_rx_buffer *rx_buf = efx_rx_buf_pipe(rx_queue);
	struct efx_nic *efx = rx_queue->efx;
	struct ef100_nic_data *nic_data;
	u8 *eh = efx_rx_buf_va(rx_buf);
	__wsum csum = 0;
	u16 ing_port;
	u32 *prefix;

	prefix = (u32 *)(eh - ESE_GZ_RX_PKT_PREFIX_LEN);
#if 0	// Dump the RX prefix
	{
		netif_dbg(efx, drv, efx->net_dev, "rx prefix data@%d: %*ph\n",
			  rx_queue->rx_pkt_index,
			  ESE_GZ_RX_PKT_PREFIX_LEN, prefix);
	}
#endif

	if (rx_queue->receive_raw) {
		u32 mark = PREFIX_FIELD(prefix, USER_MARK);

		if (rx_queue->receive_raw(rx_queue, mark))
			return; /* packet was consumed */
	}

	if (ef100_has_fcs_error(rx_queue, prefix) &&
	    unlikely(!(efx->net_dev->features & NETIF_F_RXALL)))
		goto free_rx_buffer;

	rx_buf->len = le16_to_cpu((__force __le16) PREFIX_FIELD(prefix, LENGTH));
	if (rx_buf->len <= sizeof(struct ethhdr)) {
		if (net_ratelimit())
			netif_err(efx, rx_err, efx->net_dev,
				  "RX packet too small (%d)\n", rx_buf->len);
		++rx_queue->n_rx_frm_trunc;
		goto out;
	}

	nic_data = efx->nic_data;

	ing_port = le16_to_cpu((__force __le16) PREFIX_FIELD(prefix, INGRESS_MPORT));

	if (nic_data->have_mport && ing_port != nic_data->base_mport) {
		struct net_device *rep_dev;

		rcu_read_lock();
		rep_dev = efx_ef100_find_rep_by_mport(efx, ing_port);
		if (rep_dev) {
			if (rep_dev->flags & IFF_UP)
				efx_ef100_rep_rx_packet(netdev_priv(rep_dev),
							rx_buf);
			rcu_read_unlock();
			/* Representor Rx doesn't care about PF Rx buffer
			 * ownership, it just makes a copy. So, we are done
			 * with the Rx buffer from PF point of view and should
			 * free it.
			 */
			goto free_rx_buffer;
		}
		rcu_read_unlock();
		if (net_ratelimit())
			netif_warn(efx, drv, efx->net_dev,
				   "Unrecognised ing_port %04x (base %04x), dropping\n",
				   ing_port, nic_data->base_mport);
		rx_queue->n_rx_mport_bad++;
		goto free_rx_buffer;
	}

	if (!efx_xdp_rx(efx, rx_queue, rx_buf, &eh))
		goto out;

	if (likely(efx->net_dev->features & NETIF_F_RXCSUM)) {
		if (PREFIX_HCLASS_FIELD(prefix, NT_OR_INNER_L3_CLASS) ==
		    ESE_GZ_RH_HCLASS_L3_CLASS_IP4BAD) {
			++rx_queue->n_rx_ip_hdr_chksum_err;
		}
#ifdef BUG85159_CSUM_FRAME
		csum = get_csum(eh, prefix, true);
#else
		csum = get_csum(eh, prefix, false);
#endif
		switch (PREFIX_HCLASS_FIELD(prefix, NT_OR_INNER_L4_CLASS)) {
		case ESE_GZ_RH_HCLASS_L4_CLASS_TCP:
		case ESE_GZ_RH_HCLASS_L4_CLASS_UDP:
			if (PREFIX_HCLASS_FIELD(prefix, NT_OR_INNER_L4_CSUM) ==
			    ESE_GZ_RH_HCLASS_L4_CSUM_BAD_OR_UNKNOWN)
				++rx_queue->n_rx_tcp_udp_chksum_err;
			break;
		}
	}

	if (rx_queue->receive_skb) {
		/* no support for special channels yet, so just discard */
		WARN_ON_ONCE(1);
		goto free_rx_buffer;
	}

	efx_rx_packet_gro(rx_queue, rx_buf, rx_queue->rx_pkt_n_frags, eh, csum);

#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_NET_DEVICE_LAST_RX)
	efx->net_dev->last_rx = jiffies;
#endif
	goto out;
free_rx_buffer:
	efx_free_rx_buffers(rx_queue, rx_buf, 1);
out:
	rx_queue->rx_pkt_n_frags = 0;
}

static void ef100_rx_packet(struct efx_rx_queue *rx_queue, unsigned int index)
{
	struct efx_rx_buffer *rx_buf = efx_rx_buffer(rx_queue, index);
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	struct efx_nic *efx = rx_queue->efx;

	++rx_queue->rx_packets;

	netif_vdbg(efx, rx_status, efx->net_dev,
		   "RX queue %d received id %x\n",
		   efx_rx_queue_index(rx_queue), index);

	efx_sync_rx_buffer(efx, rx_buf, efx->rx_dma_len);

	prefetch(efx_rx_buf_va(rx_buf));

	rx_buf->page_offset += efx->rx_prefix_size;

	efx_recycle_rx_pages(channel, rx_buf, 1);

	efx_rx_flush_packet(rx_queue);
	rx_queue->rx_pkt_n_frags = 1;
	rx_queue->rx_pkt_index = index;
}

int efx_ef100_ev_rx(struct efx_channel *channel, const efx_qword_t *p_event)
{
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);
	unsigned int n_packets = EFX_QWORD_FIELD(*p_event,
						 ESF_GZ_EV_RXPKTS_NUM_PKT);
	unsigned int label = EFX_QWORD_FIELD(*p_event,
					     ESF_GZ_EV_RXPKTS_Q_LABEL);
	int i;

	WARN_ON_ONCE(label != efx_rx_queue_index(rx_queue));
	WARN_ON_ONCE(!n_packets);
	if (n_packets > 1)
		++rx_queue->n_rx_merge_events;

	channel->irq_mod_score += 2 * n_packets;

	for (i = 0; i < n_packets; ++i) {
		ef100_rx_packet(rx_queue,
				rx_queue->removed_count & rx_queue->ptr_mask);
		++rx_queue->removed_count;
	}

	return n_packets;
}

void ef100_rx_write(struct efx_rx_queue *rx_queue)
{
	unsigned int notified_count = rx_queue->notified_count;
	struct efx_nic *efx = rx_queue->efx;
	struct efx_rx_buffer *rx_buf;
	dma_addr_t dma_addr;
	unsigned int idx;
	efx_qword_t *rxd;
	efx_dword_t rxdb;
	int rc;

	while (notified_count != rx_queue->added_count) {
		idx = notified_count & rx_queue->ptr_mask;
		rx_buf = efx_rx_buffer(rx_queue, idx);
		rxd = efx_rx_desc(rx_queue, idx);
		dma_addr = rx_buf->dma_addr;
		rc = ef100_regionmap_buffer(efx, &dma_addr);

		/* TODO: Deal with failure. */
		if (rc)
			break;

		EFX_POPULATE_QWORD_1(*rxd, ESF_GZ_RX_BUF_ADDR, dma_addr);

		++notified_count;
	}
	if (notified_count == rx_queue->notified_count)
		return;

	wmb();
	EFX_POPULATE_DWORD_1(rxdb, ERF_GZ_RX_RING_PIDX,
			     rx_queue->added_count & rx_queue->ptr_mask);
	efx_writed_page(rx_queue->efx, &rxdb,
			ER_GZ_RX_RING_DOORBELL, efx_rx_queue_index(rx_queue));
	if (rx_queue->grant_credits)
		wmb();
	rx_queue->notified_count = notified_count;
	if (rx_queue->grant_credits)
		schedule_work(&rx_queue->grant_work);
}

int efx_ef100_rx_defer_refill(struct efx_rx_queue *rx_queue)
{
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_DRIVER_EVENT_IN_LEN);
	efx_qword_t *event = (efx_qword_t *)MCDI_PTR(inbuf, DRIVER_EVENT_IN_DATA);
	size_t outlen;
	u32 magic;

	magic = EFX_EF100_DRVGEN_MAGIC(EFX_EF100_REFILL,
				       efx_rx_queue_index(rx_queue));
	EFX_POPULATE_QWORD_2(*event,
			     ESF_GZ_E_TYPE, ESE_GZ_EF100_EV_DRIVER,
			     ESF_GZ_DRIVER_DATA, magic);

	MCDI_SET_DWORD(inbuf, DRIVER_EVENT_IN_EVQ, channel->channel);

	return efx_mcdi_rpc(channel->efx, MC_CMD_DRIVER_EVENT,
			    inbuf, sizeof(inbuf), NULL, 0, &outlen);
}
