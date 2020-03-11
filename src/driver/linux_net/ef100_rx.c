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
#include "mcdi_functions.h"
#include "ef100_regs.h"
#include "ef100_nic.h"
#include "ef100_rep.h"
#include "io.h"
#include "mcdi_pcol_mae.h"

/* Do the frame checksum on the whole frame. */
#undef BUG85159_CSUM_FRAME

/* Get the value of a field in the RX prefix */
#define PREFIX_OFFSET_W(_f)	(ESF_GZ_RX_PREFIX_ ## _f ## _LBN)/32
#define PREFIX_OFFSET_B(_f)	(ESF_GZ_RX_PREFIX_ ## _f ## _LBN)%32
#define PREFIX_WIDTH_MASK(_f)	((1UL<<(ESF_GZ_RX_PREFIX_ ## _f ## _WIDTH)) - 1)
#define PREFIX_WORD(_p,_f)	le32_to_cpu((__force __le32) (_p)[ PREFIX_OFFSET_W(_f) ])
#define PREFIX_FIELD(_p,_f)	((PREFIX_WORD(_p,_f) >>			\
				  PREFIX_OFFSET_B(_f)) & PREFIX_WIDTH_MASK(_f))

#define ESF_GZ_RX_PREFIX_NT_OR_INNER_L3_CLASS_LBN	\
		(ESF_GZ_RX_PREFIX_CLASS_LBN + 8)
#define ESF_GZ_RX_PREFIX_NT_OR_INNER_L3_CLASS_WIDTH	2

int ef100_rx_init(struct efx_rx_queue *rx_queue)
{
	return efx_mcdi_rx_init(rx_queue, false);
}

bool efx_rx_buf_hash_valid(u8 *prefix)
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

static bool check_fcs(struct efx_channel *channel, u32 *prefix)
{
	u16 fcsum;

	fcsum = le16_to_cpu((__force __le16) PREFIX_FIELD(prefix, CLASS));
	fcsum = PREFIX_FIELD(&fcsum, HCLASS_L2_STATUS);

	if (likely(fcsum == ESE_GZ_RH_HCLASS_L2_STATUS_OK)) {
		/* Everything is ok */
		return 0;
	} else if (fcsum == ESE_GZ_RH_HCLASS_L2_STATUS_FCS_ERR) {
		channel->n_rx_eth_crc_err++;
	}

	return 1;
}

void __efx_rx_packet(struct efx_channel *channel)
{
	struct efx_rx_buffer *rx_buf =
		efx_rx_buffer(&channel->rx_queue, channel->rx_pkt_index);
	struct efx_nic *efx = channel->efx;
	struct ef100_nic_data *nic_data;
	u8 *eh = efx_rx_buf_va(rx_buf);
	__wsum csum = 0;
	u16 ing_port;
	u32 *prefix;

	prefix = (u32 *)(eh - ESE_GZ_RX_PKT_PREFIX_LEN);
#if 0	// Dump the RX prefix
	{
		netif_dbg(efx, drv, efx->net_dev, "rx prefix data: %*ph\n",
			  ESE_GZ_RX_PKT_PREFIX_LEN, prefix);
	}
#endif

	if (check_fcs(channel, prefix) &&
	    unlikely(!(efx->net_dev->features & NETIF_F_RXALL)))
		goto out;

	rx_buf->len = le16_to_cpu((__force __le16) PREFIX_FIELD(prefix, LENGTH));
	if (rx_buf->len <= sizeof(struct ethhdr)) {
		if (net_ratelimit())
			netif_err(channel->efx, rx_err, channel->efx->net_dev,
				  "RX packet too small (%d)\n", rx_buf->len);
		++channel->n_rx_frm_trunc;
		goto out;
	}

	nic_data = efx->nic_data;

	ing_port = le16_to_cpu((__force __le16) PREFIX_FIELD(prefix, INGRESS_VPORT));
	BUILD_BUG_ON(MAE_MPORT_SELECTOR_NULL);
	if (nic_data->base_mport && ing_port != nic_data->base_mport) {
		struct net_device *rep_dev = efx_ef100_find_vfrep_by_mport(efx,
							ing_port);

		if (rep_dev) {
			efx_ef100_vfrep_rx_packet(netdev_priv(rep_dev),
						  rx_buf);
			goto out;
		}
		if (net_ratelimit())
			netif_dbg(efx, drv, efx->net_dev,
				  "Unrecognised ing_port %04x (base %04x), dropping\n",
				  ing_port, nic_data->base_mport);
		/* TODO hook this up to SW stats reporting (when that's fully
		 * implemented).
		 */
		channel->n_rx_mport_bad++;
		efx_free_rx_buffers(efx_channel_get_rx_queue(channel), rx_buf, 1);
		goto out;
	}

	if (likely(efx->net_dev->features & NETIF_F_RXCSUM)) {
		if (PREFIX_FIELD(prefix, NT_OR_INNER_L3_CLASS) == 1) {
			++channel->n_rx_ip_hdr_chksum_err;
		} else {
#ifdef BUG85159_CSUM_FRAME
			csum = get_csum(eh, prefix, true);
#else
			csum = get_csum(eh, prefix, false);
#endif
		}
	}

	if (channel->type->receive_skb) {
		struct efx_rx_queue *rx_queue =
			efx_channel_get_rx_queue(channel);

		/* no support for special channels yet, so just discard */
		WARN_ON_ONCE(1);
		efx_free_rx_buffers(rx_queue, rx_buf, 1);
		goto out;
	}

	efx_rx_packet_gro(channel, rx_buf, channel->rx_pkt_n_frags, eh, csum);

#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_NET_DEVICE_LAST_RX)
	efx->net_dev->last_rx = jiffies;
#endif

out:
	channel->rx_pkt_n_frags = 0;
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

	channel->rx_pkt_n_frags = 1;
	channel->rx_pkt_index = index;
	efx_rx_flush_packet(channel);
}

void efx_ef100_ev_rx(struct efx_channel *channel, const efx_qword_t *p_event)
{
	struct efx_rx_queue *rx_queue = efx_channel_get_rx_queue(channel);
	unsigned int n_packets =
		EFX_QWORD_FIELD(*p_event, ESF_GZ_EV_RXPKTS_NUM_PKT);
	int i;

	WARN_ON_ONCE(!n_packets);
	if (n_packets > 1)
		++channel->n_rx_merge_events;

	channel->irq_mod_score += 2 * n_packets;

	for (i = 0; i < n_packets; ++i) {
		ef100_rx_packet(rx_queue,
				rx_queue->removed_count & rx_queue->ptr_mask);
		++rx_queue->removed_count;
	}
}

void ef100_rx_write(struct efx_rx_queue *rx_queue)
{
	struct efx_rx_buffer *rx_buf;
	unsigned int idx;
	efx_qword_t *rxd;
	efx_dword_t rxdb;

	while (rx_queue->notified_count != rx_queue->added_count) {
		idx = rx_queue->notified_count & rx_queue->ptr_mask;
		rx_buf = efx_rx_buffer(rx_queue, idx);
		rxd = efx_rx_desc(rx_queue, idx);

		EFX_POPULATE_QWORD_1(*rxd, ESF_GZ_RX_BUF_ADDR, rx_buf->dma_addr);

		++rx_queue->notified_count;
	}

	wmb();
	EFX_POPULATE_DWORD_1(rxdb, ERF_GZ_RX_RING_PIDX,
			     rx_queue->added_count & rx_queue->ptr_mask);
	efx_writed_page(rx_queue->efx, &rxdb,
			ER_GZ_RX_RING_DOORBELL, efx_rx_queue_index(rx_queue));
}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
int efx_ssr_init(struct efx_channel *channel, struct efx_nic *efx)
{
	return 0;
}

void efx_ssr_fini(struct efx_channel *channel)
{
}

void __efx_ssr_end_of_burst(struct efx_channel *channel)
{
}
#endif
