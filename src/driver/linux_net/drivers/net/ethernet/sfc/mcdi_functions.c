/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <linux/firmware.h>
#include <linux/crc32.h>

#include "net_driver.h"
#include "efx.h"
#include "nic.h"
#include "mcdi_functions.h"
#include "rx_common.h"
#include "mcdi.h"
#include "ef100_nic.h"

int efx_mcdi_free_vis(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF_ERR(outbuf);
	size_t outlen;
	int rc = efx_mcdi_rpc_quiet(efx, MC_CMD_FREE_VIS, NULL, 0,
				    outbuf, sizeof(outbuf), &outlen);

	/* -EALREADY means nothing to free, so ignore */
	if (rc == -EALREADY)
		rc = 0;
	if (rc)
		efx_mcdi_display_error(efx, MC_CMD_FREE_VIS, 0, outbuf, outlen,
				rc);
	return rc;
}

int efx_mcdi_alloc_vis(struct efx_nic *efx,
		       unsigned int min_vis, unsigned int max_vis,
		       unsigned int *vi_base, unsigned int *vi_shift,
		       unsigned int *allocated_vis)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_ALLOC_VIS_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_ALLOC_VIS_EXT_OUT_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, ALLOC_VIS_IN_MIN_VI_COUNT, min_vis);
	MCDI_SET_DWORD(inbuf, ALLOC_VIS_IN_MAX_VI_COUNT, max_vis);
	rc = efx_mcdi_rpc(efx, MC_CMD_ALLOC_VIS, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc != 0)
		return rc;

	if (outlen < MC_CMD_ALLOC_VIS_OUT_LEN)
		return -EIO;

	netif_dbg(efx, drv, efx->net_dev, "base VI is A%#03x\n",
		  MCDI_DWORD(outbuf, ALLOC_VIS_OUT_VI_BASE));

	if (vi_base)
		*vi_base = MCDI_DWORD(outbuf, ALLOC_VIS_OUT_VI_BASE);
	if (vi_shift)
		*vi_shift = MCDI_DWORD(outbuf, ALLOC_VIS_EXT_OUT_VI_SHIFT);
	if (allocated_vis)
		*allocated_vis = MCDI_DWORD(outbuf, ALLOC_VIS_OUT_VI_COUNT);
	return 0;
}

int efx_mcdi_ev_probe(struct efx_channel *channel)
{
	return efx_nic_alloc_buffer(channel->efx, &channel->eventq.buf,
				    (channel->eventq_mask + 1) *
				    sizeof(efx_qword_t),
				    GFP_KERNEL);
}

int efx_mcdi_ev_init(struct efx_channel *channel, bool v1_cut_thru, bool v2)
{
	MCDI_DECLARE_BUF(inbuf,
                         MC_CMD_INIT_EVQ_V2_IN_LEN(EFX_MAX_EVQ_SIZE * 8 /
                                                   EFX_BUF_SIZE));
        MCDI_DECLARE_BUF(outbuf, MC_CMD_INIT_EVQ_V2_OUT_LEN);
	size_t entries = channel->eventq.buf.len / EFX_BUF_SIZE;
	struct efx_nic *efx = channel->efx;

	size_t inlen, outlen;
	dma_addr_t dma_addr;
	int rc;
	int i;

	/* Fill event queue with all ones (i.e. empty events) */
	memset(channel->eventq.buf.addr, 0xff, channel->eventq.buf.len);

	MCDI_SET_DWORD(inbuf, INIT_EVQ_IN_SIZE, channel->eventq_mask + 1);
	MCDI_SET_DWORD(inbuf, INIT_EVQ_IN_INSTANCE, channel->channel);
	/* INIT_EVQ expects index in vector table, not absolute */
	MCDI_SET_DWORD(inbuf, INIT_EVQ_IN_IRQ_NUM, channel->channel);
	MCDI_SET_DWORD(inbuf, INIT_EVQ_IN_TMR_MODE,
			MC_CMD_INIT_EVQ_IN_TMR_MODE_DIS);
	MCDI_SET_DWORD(inbuf, INIT_EVQ_IN_TMR_LOAD, 0);
	MCDI_SET_DWORD(inbuf, INIT_EVQ_IN_TMR_RELOAD, 0);
	MCDI_SET_DWORD(inbuf, INIT_EVQ_IN_COUNT_MODE,
			MC_CMD_INIT_EVQ_IN_COUNT_MODE_DIS);
	MCDI_SET_DWORD(inbuf, INIT_EVQ_IN_COUNT_THRSHLD, 0);

	if (v2) {
		/* Use the new generic approach to specifying event queue
		 * configuration, requesting lower latency or higher throughput.
		 * The options that actually get used appear in the output.
		 */
		int unsigned perf_mode = MC_CMD_INIT_EVQ_V2_IN_FLAG_TYPE_AUTO;

#ifdef EFX_NOT_UPSTREAM
		switch (efx->performance_profile) {
		case EFX_PERFORMANCE_PROFILE_THROUGHPUT:
			perf_mode = MC_CMD_INIT_EVQ_V2_IN_FLAG_TYPE_THROUGHPUT;
			break;
		case EFX_PERFORMANCE_PROFILE_LATENCY:
			perf_mode = MC_CMD_INIT_EVQ_V2_IN_FLAG_TYPE_LOW_LATENCY;
			break;
		default:
			break;
		}
#endif
		MCDI_POPULATE_DWORD_2(inbuf, INIT_EVQ_V2_IN_FLAGS,
				      INIT_EVQ_V2_IN_FLAG_INTERRUPTING, 1,
				      INIT_EVQ_V2_IN_FLAG_TYPE, perf_mode);
	} else {
		MCDI_POPULATE_DWORD_4(inbuf, INIT_EVQ_IN_FLAGS,
				      INIT_EVQ_IN_FLAG_INTERRUPTING, 1,
				      INIT_EVQ_IN_FLAG_RX_MERGE, 1,
				      INIT_EVQ_IN_FLAG_TX_MERGE, 1,
				      INIT_EVQ_IN_FLAG_CUT_THRU, v1_cut_thru);
	}

	if (efx->type->revision == EFX_REV_EF100)
		entries = 1;	/* No need to split the memory up any more */

	dma_addr = channel->eventq.buf.dma_addr;
	for (i = 0; i < entries; ++i) {
		MCDI_SET_ARRAY_QWORD(inbuf, INIT_EVQ_IN_DMA_ADDR, i, dma_addr);
		dma_addr += EFX_BUF_SIZE;
	}

	inlen = MC_CMD_INIT_EVQ_IN_LEN(entries);

	rc = efx_mcdi_rpc(efx, MC_CMD_INIT_EVQ, inbuf, inlen,
			outbuf, sizeof(outbuf), &outlen);

	if (outlen >= MC_CMD_INIT_EVQ_V2_OUT_LEN)
		netif_dbg(efx, drv, efx->net_dev,
			  "Channel %d using event queue flags %08x\n",
			  channel->channel,
			  MCDI_DWORD(outbuf, INIT_EVQ_V2_OUT_FLAGS));

	return rc;
}

void efx_mcdi_ev_remove(struct efx_channel *channel)
{
	efx_nic_free_buffer(channel->efx, &channel->eventq.buf);
}

void efx_mcdi_ev_fini(struct efx_channel *channel)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FINI_EVQ_IN_LEN);
	MCDI_DECLARE_BUF_ERR(outbuf);
	struct efx_nic *efx = channel->efx;
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, FINI_EVQ_IN_INSTANCE, channel->channel);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_FINI_EVQ, inbuf, sizeof(inbuf),
			outbuf, sizeof(outbuf), &outlen);

	if (rc && rc != -EALREADY)
		goto fail;

	return;

fail:
	efx_mcdi_display_error(efx, MC_CMD_FINI_EVQ, MC_CMD_FINI_EVQ_IN_LEN,
			outbuf, outlen, rc);
}

int efx_mcdi_tx_init(struct efx_tx_queue *tx_queue, bool tso_v2)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_INIT_TXQ_EXT_IN_LEN);
	size_t entries = DIV_ROUND_UP(tx_queue->txd.buf.len, EFX_BUF_SIZE);
	struct efx_channel *channel = tx_queue->channel;
	struct efx_nic *efx = tx_queue->efx;
	dma_addr_t dma_addr;
	int rc;
	int i;
	bool outer_csum_offload =
		tx_queue->csum_offload & EFX_TXQ_TYPE_CSUM_OFFLOAD;
	bool inner_csum_offload =
		tx_queue->csum_offload & EFX_TXQ_TYPE_INNER_CSUM_OFFLOAD;

	BUILD_BUG_ON(MC_CMD_INIT_TXQ_OUT_LEN != 0);

	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_SIZE, tx_queue->ptr_mask + 1);
	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_TARGET_EVQ, channel->channel);
	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_LABEL, tx_queue->label);
	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_INSTANCE, tx_queue->queue);
	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_OWNER_ID, 0);
	MCDI_SET_DWORD(inbuf, INIT_TXQ_EXT_IN_PORT_ID, efx->vport.vport_id);

	dma_addr = tx_queue->txd.buf.dma_addr;
	netif_dbg(efx, hw, efx->net_dev, "pushing TXQ %d. %zu entries (%llx)\n",
		  tx_queue->queue, entries, (u64)dma_addr);

	for (i = 0; i < entries; ++i) {
		MCDI_SET_ARRAY_QWORD(inbuf, INIT_TXQ_EXT_IN_DMA_ADDR, i,
				dma_addr);
		dma_addr += EFX_BUF_SIZE;
	}

	do {
		/* TSOv2 implies IP header checksum offload for TSO frames,
		 * so we can safely disable IP header checksum offload for
		 * everything else.  If we don't have TSOv2, then we have to
		 * enable IP header checksum offload, which is strictly
		 * incorrect but better than breaking TSO.
		 */
		MCDI_POPULATE_DWORD_6(inbuf, INIT_TXQ_EXT_IN_FLAGS,
				      INIT_TXQ_EXT_IN_FLAG_TSOV2_EN,
				      tso_v2,
				      INIT_TXQ_EXT_IN_FLAG_IP_CSUM_DIS,
				      tso_v2 || !outer_csum_offload,
				      INIT_TXQ_EXT_IN_FLAG_TCP_CSUM_DIS,
				      !outer_csum_offload,
				      INIT_TXQ_EXT_IN_FLAG_INNER_IP_CSUM_EN,
				      inner_csum_offload && !tso_v2,
				      INIT_TXQ_EXT_IN_FLAG_INNER_TCP_CSUM_EN,
				      inner_csum_offload,
				      INIT_TXQ_EXT_IN_FLAG_TIMESTAMP,
				      tx_queue->timestamping);

		rc = efx_mcdi_rpc_quiet(efx, MC_CMD_INIT_TXQ,
				inbuf, sizeof(inbuf),
				NULL, 0, NULL);

		if (rc == -ENOSPC && tso_v2) {
			/* Retry without TSOv2 if we're short on contexts. */
			tso_v2 = false;
			netif_warn(efx, probe, efx->net_dev,
					"TSOv2 context not available to segment in hardware. TCP performance may be reduced.\n");
		} else if (rc) {
			efx_mcdi_display_error(efx, MC_CMD_INIT_TXQ,
					MC_CMD_INIT_TXQ_EXT_IN_LEN,
					NULL, 0, rc);
			return rc;
		}
	} while (rc);

	return 0;
}

void efx_mcdi_tx_fini(struct efx_tx_queue *tx_queue)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FINI_TXQ_IN_LEN);
	MCDI_DECLARE_BUF_ERR(outbuf);
	struct efx_nic *efx = tx_queue->efx;
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, FINI_TXQ_IN_INSTANCE, tx_queue->queue);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_FINI_TXQ, inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf), &outlen);

	if (rc && rc != -EALREADY)
		goto fail;

	return;

fail:
	efx_mcdi_display_error(efx, MC_CMD_FINI_TXQ, MC_CMD_FINI_TXQ_IN_LEN,
			       outbuf, outlen, rc);
}

int efx_mcdi_rx_probe(struct efx_rx_queue *rx_queue)
{
	return efx_nic_alloc_buffer(rx_queue->efx, &rx_queue->rxd.buf,
				    (rx_queue->ptr_mask + 1) *
				    sizeof(efx_qword_t),
				    GFP_KERNEL);
}

int efx_mcdi_rx_init(struct efx_rx_queue *rx_queue, bool want_outer_classes)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_INIT_RXQ_V4_IN_LEN);
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	size_t entries = rx_queue->rxd.buf.len / EFX_BUF_SIZE;
	struct efx_nic *efx = rx_queue->efx;
	unsigned int buffer_size;
	dma_addr_t dma_addr;
	int rc;
	int i;
	BUILD_BUG_ON(MC_CMD_INIT_RXQ_V4_OUT_LEN != 0);

	rx_queue->scatter_n = 0;
	rx_queue->scatter_len = 0;
	if (efx->type->revision == EFX_REV_EF100)
		buffer_size = efx->rx_page_buf_step;
	else
		buffer_size = 0;

	MCDI_SET_DWORD(inbuf, INIT_RXQ_IN_SIZE, rx_queue->ptr_mask + 1);
	MCDI_SET_DWORD(inbuf, INIT_RXQ_IN_TARGET_EVQ, channel->channel);
	MCDI_SET_DWORD(inbuf, INIT_RXQ_IN_LABEL, efx_rx_queue_index(rx_queue));
	MCDI_SET_DWORD(inbuf, INIT_RXQ_IN_INSTANCE,
		       efx_rx_queue_instance(rx_queue));
	MCDI_POPULATE_DWORD_3(inbuf, INIT_RXQ_IN_FLAGS,
			INIT_RXQ_IN_FLAG_PREFIX, 1,
			INIT_RXQ_IN_FLAG_TIMESTAMP, 1,
			INIT_RXQ_EXT_IN_FLAG_WANT_OUTER_CLASSES,
			want_outer_classes);
	MCDI_SET_DWORD(inbuf, INIT_RXQ_IN_OWNER_ID, 0);
	MCDI_SET_DWORD(inbuf, INIT_RXQ_IN_PORT_ID, efx->vport.vport_id);
	MCDI_SET_DWORD(inbuf, INIT_RXQ_V4_IN_BUFFER_SIZE_BYTES, buffer_size);

	dma_addr = rx_queue->rxd.buf.dma_addr;
	netif_dbg(efx, hw, efx->net_dev, "pushing RXQ %d. %zu entries (%llx)\n",
			efx_rx_queue_index(rx_queue), entries, (u64)dma_addr);

	for (i = 0; i < entries; ++i) {
		MCDI_SET_ARRAY_QWORD(inbuf, INIT_RXQ_IN_DMA_ADDR, i, dma_addr);
		dma_addr += EFX_BUF_SIZE;
	}

	rc = efx_mcdi_rpc(efx, MC_CMD_INIT_RXQ, inbuf,
			MC_CMD_INIT_RXQ_V4_IN_LEN, NULL, 0, NULL);
	if (rc && rc != -ENETDOWN && rc != -EAGAIN)
		netdev_WARN(efx->net_dev, "failed to initialise RXQ %d\n",
				efx_rx_queue_index(rx_queue));
	return rc;
}

void efx_mcdi_rx_remove(struct efx_rx_queue *rx_queue)
{
	efx_nic_free_buffer(rx_queue->efx, &rx_queue->rxd.buf);
}

void efx_mcdi_rx_fini(struct efx_rx_queue *rx_queue)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FINI_RXQ_IN_LEN);
	MCDI_DECLARE_BUF_ERR(outbuf);
	struct efx_nic *efx = rx_queue->efx;
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, FINI_RXQ_IN_INSTANCE,
		       efx_rx_queue_instance(rx_queue));

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_FINI_RXQ, inbuf, sizeof(inbuf),
			outbuf, sizeof(outbuf), &outlen);

	if (rc && rc != -EALREADY)
		goto fail;

	return;

fail:
	efx_mcdi_display_error(efx, MC_CMD_FINI_RXQ, MC_CMD_FINI_RXQ_IN_LEN,
			outbuf, outlen, rc);
}

int efx_fini_dmaq(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	int pending;

	/* Do not attempt to write to the NIC whilst unavailable */
	if (efx_nic_hw_unavailable(efx))
		return 0;

	efx_for_each_channel(channel, efx) {
		efx_for_each_channel_rx_queue(rx_queue, channel) {
			efx_mcdi_rx_fini(rx_queue);
		}
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			efx_mcdi_tx_fini(tx_queue);
		}
	}

	wait_event_timeout(efx->flush_wq,
			   atomic_read(&efx->active_queues) == 0,
			   msecs_to_jiffies(EFX_MAX_FLUSH_TIME));
	pending = atomic_read(&efx->active_queues);
	if (pending) {
		netif_err(efx, hw, efx->net_dev, "failed to flush %d queues\n",
			  pending);
		return -ETIMEDOUT;
	}
	return 0;
}

int efx_mcdi_window_mode_to_stride(struct efx_nic *efx, u8 vi_window_mode)
{
	switch (vi_window_mode) {
	case MC_CMD_GET_CAPABILITIES_V3_OUT_VI_WINDOW_MODE_8K:
		efx->vi_stride = 8192;
		break;
	case MC_CMD_GET_CAPABILITIES_V3_OUT_VI_WINDOW_MODE_16K:
		efx->vi_stride = 16384;
		break;
	case MC_CMD_GET_CAPABILITIES_V3_OUT_VI_WINDOW_MODE_64K:
		efx->vi_stride = 65536;
		break;
	default:
		netif_err(efx, probe, efx->net_dev,
			  "Unrecognised VI window mode %d\n",
			  vi_window_mode);
		return -EIO;
	}
	netif_dbg(efx, probe, efx->net_dev, "vi_stride = %u\n",
		  efx->vi_stride);
	return 0;
}

int efx_get_pf_index(struct efx_nic *efx, unsigned int *pf_index)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_FUNCTION_INFO_OUT_LEN);
	size_t outlen;
	int rc;

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_FUNCTION_INFO, NULL, 0, outbuf,
			  sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;

	*pf_index = MCDI_DWORD(outbuf, GET_FUNCTION_INFO_OUT_PF);
	return 0;
}

#ifdef EFX_FLASH_FIRMWARE
/* Some defines to correctly read the bundle reflash header .
 * Header definition can be found in SF-121352
 */
#ifndef EFX_REFLASH_HEADER
#define EFX_REFLASH_HEADER

#define EFX_REFLASH_MAGIC_VAL 0x106F1A5
#define MC_CMD_EFX_REFLASH_MAGIC_OFST 0
#define MC_CMD_EFX_REFLASH_TYPE_OFST 8
#define MC_CMD_EFX_REFLASH_BUNDLE_SIZE_OFST 16
#define MC_CMD_EFX_REFLASH_HEADER_LEN_OFST 20
#define MC_CMD_EFX_REFLASH_HEADER_LEN_LEN 4

#define EFX_REFLASH_TRAILER_LEN 4

/* This is required to look at the type as listed in the bundle,
 * as they are different from partition types return by MCDI
 */
#define FIRMWARE_TYPE_BOOTROM 0x2
#define FIRMWARE_TYPE_BUNDLE 0xd

#endif

static bool efx_check_crc_checksum(const struct firmware *fw,
				   int offset)
{
	unsigned int expected_crc, crc = 0;
	unsigned int bundle_size;
	unsigned int header_len;

	if (offset + MC_CMD_EFX_REFLASH_HEADER_LEN_OFST +
	    fw->size < MC_CMD_EFX_REFLASH_HEADER_LEN_LEN)
		return false;

	bundle_size = MCDI_DWORD((efx_dword_t *)&fw->data[offset],
				 EFX_REFLASH_BUNDLE_SIZE);

	header_len = MCDI_DWORD((efx_dword_t *)&fw->data[offset],
				EFX_REFLASH_HEADER_LEN);

	if (offset + header_len > fw->size)
		return false;

	bundle_size += header_len;

	if (bundle_size > fw->size)
		return false;

	crc = crc32_le(crc, &fw->data[offset], bundle_size);
	expected_crc = *(unsigned int *)&fw->data[offset + bundle_size];

	if (crc != expected_crc)
		return false;

	return true;
}

static int efx_check_reflash_header(const struct firmware *fw,
				    unsigned int *type,
				    unsigned int *payload_offset,
				    unsigned int *header_size)
{
	unsigned int offset = 0;
	unsigned int magic = 0;
	unsigned int fw_type;

	/* Try to find the magic value at a non zero offset, this is because
	 * signed images have the CMS header for which finding the size is a
	 * non trivial task.
	 */
	for (; offset < fw->size; offset += 4) {
		magic = MCDI_DWORD((efx_dword_t *)&fw->data[offset],
				   EFX_REFLASH_MAGIC);
		if (magic == EFX_REFLASH_MAGIC_VAL &&
		    efx_check_crc_checksum(fw, offset))
			break;
	}

	if (offset == fw->size)
		return -EINVAL;

	fw_type = MCDI_DWORD((efx_dword_t *)&fw->data[offset],
			     EFX_REFLASH_TYPE);

	/* The Partition types labelled in the bundle differ from the partition
	 * types that the MC expexts, translate them here.
	 */
	if (fw_type == FIRMWARE_TYPE_BOOTROM) {
		*type = NVRAM_PARTITION_TYPE_EXPANSION_ROM;
	} else if (fw_type == FIRMWARE_TYPE_BUNDLE) {
		*type = NVRAM_PARTITION_TYPE_BUNDLE;
	} else {
		*type = 0;
		return -EINVAL;
	}

	*payload_offset = offset;
	*header_size = MCDI_DWORD((efx_dword_t *)&fw->data[offset],
				  EFX_REFLASH_HEADER_LEN);

	return 0;
}

int efx_mcdi_flash_bundle(struct net_device *net_dev,
			  struct ethtool_flash *flash)
{
	unsigned int type, header_len = 0, payload_offset = 0;
	size_t erase_size, write_size, size, total_write_size;
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	const struct firmware *fw;
	loff_t offset = 0;
	bool protected;
	char *data;
	int rc;

	if (!net_dev || !flash || !efx)
		return -EINVAL;

	if (!efx_has_cap(efx, MCDI_BACKGROUND))
		return -EOPNOTSUPP;

	rc = request_firmware_direct(&fw, flash->data, &efx->pci_dev->dev);
	if (rc) {
		netif_warn(efx, hw, efx->net_dev,
			   "Error %d, failed to request firmware for %s\n",
			   rc, flash->data);
		return rc;
	}

	rc = efx_check_reflash_header(fw, &type, &payload_offset, &header_len);
	if (rc) {
		netif_warn(efx, hw, efx->net_dev,
			   "Reflash Header could not be read properly\n");
		rc = -EINVAL;
		goto fail1;
	}

	switch (type) {
	case NVRAM_PARTITION_TYPE_BUNDLE:
	case NVRAM_PARTITION_TYPE_EXPANSION_ROM:
		break;
	default:
		netif_warn(efx, hw, efx->net_dev,
			   "Error unsupported flash partition, supported flash partitions are {bundle: 0x%x, bootrom: 0x%x}\n",
			   NVRAM_PARTITION_TYPE_BUNDLE,
			   NVRAM_PARTITION_TYPE_EXPANSION_ROM);
		rc = -EINVAL;
		goto fail1;
	}

	rc = efx_mcdi_nvram_info(efx, type, &size, &erase_size,
				 &write_size, &protected);
	if (rc)
		goto fail1;

	if (protected) {
		rc = -EPERM;
		goto fail1;
	}

	rc = efx_mcdi_nvram_update_start(efx, type);
	if (rc) {
		netif_warn(efx, hw, efx->net_dev,
			   "failed to start nvram update with rc=%d\n", rc);
		goto fail1;
	}

	/* Erase in chunks in order to avoid the mcdi timeout */
	while (offset < size) {
		rc = efx_mcdi_nvram_erase(efx, type, offset, erase_size);
		if (rc < 0) {
			netif_warn(efx, hw, efx->net_dev,
				   "failed to erase nvram with rc=%d\n", rc);
			goto fail;
		}

		offset += erase_size;
	}

	offset = 0;
	total_write_size = fw->size;
	data = (char *)fw->data;

	if (type == NVRAM_PARTITION_TYPE_EXPANSION_ROM) {
		data += header_len + payload_offset;
		total_write_size -= header_len +
				    EFX_REFLASH_TRAILER_LEN;
	}

	/* Write in chunks in order to avoid the mcdi timeout.
	 * For some reason writing an entire image makes the mc complain.
	 */
	while (offset < total_write_size && offset < size) {
		rc = efx_mcdi_nvram_write(efx, type, offset,
					  data + offset, write_size);
		if (rc) {
			netif_warn(efx, hw, efx->net_dev,
				   "error %d, failed to write to nvram with offset %x\n",
				   rc, (int)offset);
			goto fail;
		}

		offset += write_size;
	}

fail:
	/* Don't store rc for efx-mcdi_nvram_update_finish to not
	 * overwrite potential failures
	 */
	efx_mcdi_nvram_update_finish(efx, type);

fail1:
	release_firmware(fw);

	return rc;
}
#endif
