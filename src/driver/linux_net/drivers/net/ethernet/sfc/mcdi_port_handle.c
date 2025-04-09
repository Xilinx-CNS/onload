// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Solarflare and Xilinx network controllers and boards
 * Copyright 2024 Advanced Micro Devices, Inc.
 */

#include "nic.h"
#include "mcdi_port_common.h"
#include "mcdi_port_handle.h"

int efx_mcdi_get_port_handle(struct efx_nic *efx, u32 *handle)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_ASSIGNED_PORT_HANDLE_OUT_LEN);
	size_t outlen;
	int rc;

	BUILD_BUG_ON(MC_CMD_GET_ASSIGNED_PORT_HANDLE_IN_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_ASSIGNED_PORT_HANDLE, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_GET_ASSIGNED_PORT_HANDLE_OUT_LEN)
		return -EIO;

	*handle = MCDI_DWORD(outbuf, GET_ASSIGNED_PORT_HANDLE_OUT_PORT_HANDLE);
	return 0;
}

static u32 efx_x4_mcdi_max_frame_len(struct efx_nic *efx)
{
	/* Unlike efx_calc_mac_mtu, do not use EFX_MAX_FRAME_LEN() here, as
	 * that includes an obsolete workaround for Siena hardware that is
	 * ABI for the legacy MC_CMD_SET_MAC command.
	 */
	return efx->net_dev->mtu + ETH_HLEN + VLAN_HLEN + 4 /*FCS*/;
}

int efx_x4_mcdi_mac_ctrl(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAC_CTRL_IN_LEN);
	u32 fcntl;

	BUILD_BUG_ON(MC_CMD_MAC_CTRL_OUT_LEN != 0);

	MCDI_SET_DWORD(inbuf, MAC_CTRL_IN_PORT_HANDLE, efx->port_handle);
	MCDI_SET_DWORD(inbuf, MAC_CTRL_IN_CONTROL_FLAGS,
		       BIT(MC_CMD_MAC_CONFIG_OPTIONS_CFG_MAX_FRAME_LEN) |
		       BIT(MC_CMD_MAC_CONFIG_OPTIONS_CFG_FCNTL) |
		       BIT(MC_CMD_MAC_CONFIG_OPTIONS_CFG_INCLUDE_FCS));

	fcntl = efx_mcdi_wanted_fcntl(efx);
	MCDI_SET_DWORD(inbuf, MAC_CTRL_IN_FCNTL, fcntl);

	if (efx->net_dev->features & NETIF_F_RXFCS)
		MCDI_SET_DWORD(inbuf, MAC_CTRL_IN_FLAGS,
			       BIT(MC_CMD_MAC_FLAGS_FLAG_INCLUDE_FCS));

	MCDI_SET_DWORD(inbuf, MAC_CTRL_IN_MAX_FRAME_LEN,
		       efx_x4_mcdi_max_frame_len(efx));

	return efx_mcdi_rpc(efx, MC_CMD_MAC_CTRL, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

int efx_x4_mcdi_set_mtu(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAC_CTRL_IN_LEN);

	BUILD_BUG_ON(MC_CMD_MAC_CTRL_OUT_LEN != 0);

	MCDI_SET_DWORD(inbuf, MAC_CTRL_IN_PORT_HANDLE, efx->port_handle);
	MCDI_SET_DWORD(inbuf, MAC_CTRL_IN_CONTROL_FLAGS,
		       BIT(MC_CMD_MAC_CONFIG_OPTIONS_CFG_MAX_FRAME_LEN));

	MCDI_SET_DWORD(inbuf, MAC_CTRL_IN_MAX_FRAME_LEN,
		       efx_x4_mcdi_max_frame_len(efx));

	return efx_mcdi_rpc(efx, MC_CMD_MAC_CTRL, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

/* Get flow control used by link (needed if MAC setting is AUTO) */
static int efx_x4_mcdi_get_link_fcntl(struct efx_nic *efx, u32 *fcntl)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAC_STATE_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAC_STATE_IN_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAC_STATE_IN_PORT_HANDLE, efx->port_handle);

	rc = efx_mcdi_rpc(efx, MC_CMD_MAC_STATE, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_MAC_STATE_OUT_LEN)
		return -EIO;
	*fcntl = MCDI_DWORD(outbuf, MAC_STATE_OUT_FCNTL);
	return 0;
}

/* Statistics identifiers used with MC_CMD_MAC_STATISTICS_DESCRIPTOR */
#define STAT_ID(_src, _idx)						\
	(((u32)(MC_CMD_STAT_ID_##_idx) << MC_CMD_STAT_ID_MAC_STAT_ID_LBN) | \
	 ((MC_CMD_STAT_ID_##_src) << MC_CMD_STAT_ID_SOURCE_ID_LBN))

/* For each supported statistic, MC_CMD_MAC_STATISTICS_DESCRIPTOR reports
 * the counter ID and DMA buffer offset. This map contains the counter ID
 * used to find the DMA buffer offset for each EF10_STAT_* counter.
 */
static const struct {
	u32 stat_id;
} x4_stat_id_map[EF10_STAT_COUNT] = {
#define MAC_STAT(ef10_name, mcdi_index)		\
	[EF10_STAT_ ## ef10_name] = { STAT_ID(MAC, mcdi_index) }
#define PHY_STAT(ef10_name, mcdi_index)		\
	[EF10_STAT_ ## ef10_name] = { STAT_ID(PHY, mcdi_index) }
#define PM_STAT(ef10_name, mcdi_index)		\
	[EF10_STAT_ ## ef10_name] = { STAT_ID(PM, mcdi_index) }
#define RXDP_STAT(ef10_name, mcdi_index)	\
	[EF10_STAT_ ## ef10_name] = { STAT_ID(RXDP, mcdi_index) }

	MAC_STAT(port_tx_bytes, TX_BYTES),
	MAC_STAT(port_tx_packets, TX_PKTS),
	MAC_STAT(port_tx_pause, TX_PAUSE_PKTS),
	MAC_STAT(port_tx_control, TX_CONTROL_PKTS),
	MAC_STAT(port_tx_unicast, TX_UNICAST_PKTS),
	MAC_STAT(port_tx_multicast, TX_MULTICAST_PKTS),
	MAC_STAT(port_tx_broadcast, TX_BROADCAST_PKTS),
	MAC_STAT(port_tx_lt64, TX_LT64_PKTS),
	MAC_STAT(port_tx_64, TX_64_PKTS),
	MAC_STAT(port_tx_65_to_127, TX_65_TO_127_PKTS),
	MAC_STAT(port_tx_128_to_255, TX_128_TO_255_PKTS),
	MAC_STAT(port_tx_256_to_511, TX_256_TO_511_PKTS),
	MAC_STAT(port_tx_512_to_1023, TX_512_TO_1023_PKTS),
	MAC_STAT(port_tx_1024_to_15xx, TX_1024_TO_15XX_PKTS),
	MAC_STAT(port_tx_15xx_to_jumbo, TX_15XX_TO_JUMBO_PKTS),
	MAC_STAT(port_rx_bytes, RX_BYTES),
	MAC_STAT(port_rx_bytes_minus_good_bytes, RX_BAD_BYTES),
	MAC_STAT(port_rx_packets, RX_PKTS),
	MAC_STAT(port_rx_good, RX_GOOD_PKTS),
	MAC_STAT(port_rx_bad, RX_BAD_FCS_PKTS),
	MAC_STAT(port_rx_pause, RX_PAUSE_PKTS),
	MAC_STAT(port_rx_control, RX_CONTROL_PKTS),
	MAC_STAT(port_rx_unicast, RX_UNICAST_PKTS),
	MAC_STAT(port_rx_multicast, RX_MULTICAST_PKTS),
	MAC_STAT(port_rx_broadcast, RX_BROADCAST_PKTS),
	MAC_STAT(port_rx_lt64, RX_UNDERSIZE_PKTS),
	MAC_STAT(port_rx_64, RX_64_PKTS),
	MAC_STAT(port_rx_65_to_127, RX_65_TO_127_PKTS),
	MAC_STAT(port_rx_128_to_255, RX_128_TO_255_PKTS),
	MAC_STAT(port_rx_256_to_511, RX_256_TO_511_PKTS),
	MAC_STAT(port_rx_512_to_1023, RX_512_TO_1023_PKTS),
	MAC_STAT(port_rx_1024_to_15xx, RX_1024_TO_15XX_PKTS),
	MAC_STAT(port_rx_15xx_to_jumbo, RX_15XX_TO_JUMBO_PKTS),
	MAC_STAT(port_rx_gtjumbo, RX_GTJUMBO_PKTS),
	MAC_STAT(port_rx_bad_gtjumbo, RX_JABBER_PKTS),
	MAC_STAT(port_rx_overflow, RX_OVERFLOW_PKTS),
	MAC_STAT(port_rx_align_error, RX_ALIGN_ERROR_PKTS),
	MAC_STAT(port_rx_length_error, RX_LENGTH_ERROR_PKTS),
	MAC_STAT(port_rx_nodesc_drops, RX_NODESC_DROPS),
	PM_STAT(port_rx_pm_discard_vfifo_full, PM_DISCARD_VFIFO_FULL),
	PM_STAT(port_rx_pm_discard_qbb, PM_DISCARD_QBB),
	PM_STAT(port_rx_pm_discard_mapping, PM_DISCARD_MAPPING),
	RXDP_STAT(port_rx_dp_q_disabled_packets, RXDP_Q_DISABLED_PKTS),
	RXDP_STAT(port_rx_dp_di_dropped_packets, RXDP_DI_DROPPED_PKTS),
	RXDP_STAT(port_rx_dp_streaming_packets, RXDP_STREAMING_PKTS),
	RXDP_STAT(port_rx_dp_hlb_fetch, RXDP_HLB_FETCH_CONDITIONS),
	RXDP_STAT(port_rx_dp_hlb_wait, RXDP_HLB_WAIT_CONDITIONS),
	// TODO: rx_*	      (no STAT_IDs, was MC_CMD_MAC_VADAPTER_RX_*)
	// TODO: tx_*	      (no STAT_IDs, was MC_CMD_MAC_VADAPTER_RX_*)
	PHY_STAT(fec_uncorrected_errors, FEC_UNCORRECTED_ERRORS),
	PHY_STAT(fec_corrected_errors, FEC_CORRECTED_ERRORS),
	PHY_STAT(fec_corrected_symbols_lane0, FEC_CORRECTED_SYMBOLS_LANE0),
	PHY_STAT(fec_corrected_symbols_lane1, FEC_CORRECTED_SYMBOLS_LANE1),
	PHY_STAT(fec_corrected_symbols_lane2, FEC_CORRECTED_SYMBOLS_LANE2),
	PHY_STAT(fec_corrected_symbols_lane3, FEC_CORRECTED_SYMBOLS_LANE3),
#undef MAC_STAT
#undef PHY_STAT
#undef PM_STAT
#undef RXDP_STAT
};

static bool efx_x4_lookup_ef10_stat(u32 mcdi_stat_id, u32 *ef10_stat)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(x4_stat_id_map); i++) {
		if (x4_stat_id_map[i].stat_id == mcdi_stat_id) {
			*ef10_stat = i;
			return true;
		}
	}
	return false;
}

static int efx_x4_add_hw_stat(struct efx_nic *efx, u32 stat_id, u32 dma_offset)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	u32 ef10_stat;

	if (stat_id == STAT_ID(MARKER, GENERATION_START) ||
	    stat_id == STAT_ID(MARKER, GENERATION_END))
		return 0;

	if (!efx_x4_lookup_ef10_stat(stat_id, &ef10_stat))
		return -ENOENT;

	/* Update stat_desc with DMA buffer offset */
	nic_data->x4_stat_desc[ef10_stat].offset = dma_offset;

	/* Add stat to firmware supported stats mask */
	__set_bit(ef10_stat, nic_data->x4_stats_mask);

	return 0;
}

int efx_x4_mcdi_probe_stats(struct efx_nic *efx, u16 *num_stats,
			    size_t *stats_dma_size)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAC_STATISTICS_DESCRIPTOR_IN_LEN);
	u32 total, count, stride, offset, dma_size, dma_offset;
	u32 stat_id, stat_index, generation;
	MCDI_DECLARE_STRUCT_PTR(entry);
	size_t outbuflen, outlen;
	unsigned int base, i;
	efx_dword_t *outbuf;
	int rc;

	efx_x4_init_hw_stat_desc(efx);

	outbuflen = MC_CMD_MAC_STATISTICS_DESCRIPTOR_OUT_LENMAX_MCDI2;
	outbuf = kzalloc(outbuflen, GFP_KERNEL);
	if (!outbuf)
		return -ENOMEM;

	dma_size = 0;
	total = 0;
	count = 0;
	offset = 0;
	do {
		MCDI_SET_DWORD(inbuf, MAC_STATISTICS_DESCRIPTOR_IN_PORT_HANDLE,
			       efx->port_handle);
		MCDI_SET_DWORD(inbuf, MAC_STATISTICS_DESCRIPTOR_IN_OFFSET,
			       offset);
		rc = efx_mcdi_rpc(efx, MC_CMD_MAC_STATISTICS_DESCRIPTOR,
				  inbuf, sizeof(inbuf),
				  outbuf, outbuflen, &outlen);
		if (rc)
			goto out;
		if (outlen < MC_CMD_MAC_STATISTICS_DESCRIPTOR_OUT_LENMIN) {
			rc = -EIO;
			goto out;
		}
		generation = MCDI_DWORD(outbuf,
					MAC_STATISTICS_DESCRIPTOR_OUT_GENERATION);
		if (generation) {
			/* Dynamic update of available stats not supported */
			rc = -EINVAL;
			goto out;
		}
		dma_size = MCDI_DWORD(outbuf,
				      MAC_STATISTICS_DESCRIPTOR_OUT_DMA_BUFFER_SIZE);
		stride = MCDI_DWORD(outbuf,
				    MAC_STATISTICS_DESCRIPTOR_OUT_ENTRY_SIZE);
		count = MCDI_DWORD(outbuf,
				   MAC_STATISTICS_DESCRIPTOR_OUT_ENTRY_COUNT);
		if (!count)
			continue; /* Check MORE_ENTRIES flag */

		base = MC_CMD_MAC_STATISTICS_DESCRIPTOR_OUT_ENTRIES_OFST;
		if (outlen < base + count * stride) {
			pci_dbg(efx->pci_dev, "Bad stats desc: outlen:%zu < base:%u + (count:%u * stride:%u)\n",
				outlen, base, count, stride);
			rc = -EIO;
			goto out;
		}

		/* Save DMA buffer offsets for supported stats */
		for (i = 0; i < count; i++) {
			entry =	(efx_dword_t *)_MCDI_PTR(outbuf,
							 base + i * stride);

			stat_id = MCDI_DWORD(entry, STAT_DESC_STAT_ID);
			stat_index = MCDI_WORD(entry, STAT_DESC_STAT_INDEX);

			dma_offset = stat_index * sizeof(u64);
			if (dma_offset >= dma_size) {
				pci_dbg(efx->pci_dev, "Bad stats desc: dma_offset:%u (index:%u * 8) > dma_len:%u\n",
					dma_offset, stat_index, dma_size);
				rc = -EIO;
				goto out;
			}
			efx_x4_add_hw_stat(efx, stat_id, dma_offset);
		}
		total += count;
		offset += count;
	} while (MCDI_FIELD(outbuf, MAC_STATISTICS_DESCRIPTOR_OUT,
			    MORE_ENTRIES) && !WARN_ON(!count));

	pci_dbg(efx->pci_dev, "Total stats:%u stats size:%zu dma_size:%u\n",
		total, total * sizeof(u64), dma_size);

	*num_stats = total;
	*stats_dma_size = dma_size;
out:
	kfree(outbuf);
	return rc;
}

#define TECH_MAP_VALID 0x01 /* valid map entry */
#define TECH_MAP_CAP1  0x02 /* cap1 is valid */
#define TECH_MAP_CAP2  0x04 /* cap2 is valid */

#define LANES_1lane	1
#define LANES_2lane	2
#define LANES_4lane	4
#define LANES_8lane	8

static const struct tech_map {
	u32 speed;	/* SPEED_{nnn,UNKNOWN} in Mbit/s */
	u8 duplex;	/* DUPLEX_{HALF,FULL,UNKNOWN} */
	u8 flags:4;	/* TECH_MAP_xxx */
	u8 lanes:4;	/* Number of physical lanes */
	u8 cap1;	/* Linkset bit index for link type */
	u8 cap2;	/* Linkset bit index for medium */
} tech_map[] = {
#define ETH_CAP1(_tech, _speed, _duplex, _lanes, _cap1)		\
	[MC_CMD_ETH_TECH_ ## _tech] = {				\
		.speed = SPEED_ ## _speed,			\
		.duplex = DUPLEX_ ## _duplex,			\
		.lanes = LANES_ ## _lanes,			\
		.flags = TECH_MAP_VALID | TECH_MAP_CAP1,	\
		.cap1 =	ETHTOOL_LINK_MODE_ ## _cap1 ## _BIT,	\
	}
#define ETH_CAP2(_tech, _speed, _duplex, _lanes, _cap1, _cap2)		\
	[MC_CMD_ETH_TECH_ ## _tech] = {					\
		.speed = SPEED_ ## _speed,				\
		.duplex = DUPLEX_ ## _duplex,				\
		.lanes = LANES_ ## _lanes,				\
		.flags = TECH_MAP_VALID | TECH_MAP_CAP1 | TECH_MAP_CAP2, \
		.cap1 =	ETHTOOL_LINK_MODE_ ## _cap1 ## _BIT,		\
		.cap2 =	ETHTOOL_LINK_MODE_ ## _cap2 ## _BIT,		\
	}

	ETH_CAP2(1000BASEKX, 1000, FULL, 1lane, 1000baseKX_Full, Backplane),
	ETH_CAP2(10GBASE_KR, 10000, FULL, 1lane, 10000baseKR_Full, Backplane),
	ETH_CAP2(40GBASE_KR4, 40000, FULL, 4lane, 40000baseKR4_Full, Backplane),
	ETH_CAP1(40GBASE_CR4, 40000, FULL, 4lane, 40000baseCR4_Full),
	ETH_CAP2(40GBASE_SR4, 40000, FULL, 4lane, 40000baseSR4_Full, FIBRE),
	ETH_CAP2(40GBASE_LR4, 40000, FULL, 4lane, 40000baseLR4_Full, FIBRE),
	ETH_CAP1(25GBASE_CR, 25000, FULL, 1lane, 25000baseCR_Full),
	ETH_CAP2(25GBASE_KR, 25000, FULL, 1lane, 25000baseKR_Full, Backplane),
	ETH_CAP2(25GBASE_SR, 25000, FULL, 1lane, 25000baseSR_Full, FIBRE),
	ETH_CAP2(25GBASE_LR_ER, 25000, FULL, 1lane, 25000baseSR_Full, FIBRE),
	ETH_CAP1(50GBASE_CR2, 50000, FULL, 2lane, 50000baseCR2_Full),
	ETH_CAP2(50GBASE_KR2, 50000, FULL, 2lane, 50000baseKR2_Full, Backplane),
	ETH_CAP2(100GBASE_KR4, 100000, FULL, 4lane, 100000baseKR4_Full, Backplane),
	ETH_CAP2(100GBASE_SR4, 100000, FULL, 4lane, 100000baseSR4_Full, FIBRE),
	ETH_CAP1(100GBASE_CR4, 100000, FULL, 4lane, 100000baseCR4_Full),
	ETH_CAP2(100GBASE_LR4_ER4, 100000, FULL, 4lane,
		 100000baseLR4_ER4_Full, FIBRE),
	ETH_CAP2(50GBASE_SR2, 50000, FULL, 2lane, 50000baseSR2_Full, FIBRE),
	ETH_CAP1(1000BASEX, 1000, FULL,	1lane, 1000baseX_Full),
	ETH_CAP1(10GBASE_CR, 10000, FULL, 1lane, 10000baseCR_Full),
	ETH_CAP2(10GBASE_SR, 10000, FULL, 1lane, 10000baseSR_Full, FIBRE),
	ETH_CAP2(10GBASE_LR, 10000, FULL, 1lane, 10000baseLR_Full, FIBRE),
	ETH_CAP2(10GBASE_LRM, 10000, FULL, 1lane, 10000baseLRM_Full, FIBRE),
	ETH_CAP2(10GBASE_ER, 10000, FULL, 1lane, 10000baseER_Full, FIBRE),
	ETH_CAP2(50GBASE_KR, 50000, FULL, 1lane, 50000baseKR_Full, Backplane),
	ETH_CAP2(50GBASE_SR,  50000, FULL, 1lane, 50000baseSR_Full, FIBRE),
	ETH_CAP1(50GBASE_CR, 50000, FULL, 1lane, 50000baseCR_Full),
	ETH_CAP2(50GBASE_LR_ER_FR, 50000, FULL, 1lane, 50000baseLR_ER_FR_Full, FIBRE),
	ETH_CAP2(50GBASE_DR, 50000, FULL, 1lane, 50000baseDR_Full, FIBRE),
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_LINK_MODE_400)
	ETH_CAP2(100GBASE_KR, 100000, FULL, 1lane, 100000baseKR_Full, Backplane),
#endif
	ETH_CAP2(100GBASE_KR2, 100000, FULL, 2lane, 100000baseKR2_Full, Backplane),
	ETH_CAP2(100GBASE_SR2, 100000, FULL, 2lane, 100000baseSR2_Full, FIBRE),
	ETH_CAP1(100GBASE_CR2, 100000, FULL, 2lane, 100000baseCR2_Full),
	ETH_CAP2(100GBASE_LR2_ER2_FR2, 100000, FULL, 2lane,
		 100000baseLR2_ER2_FR2_Full, FIBRE),
	ETH_CAP2(100GBASE_DR2, 100000, FULL, 2lane, 100000baseDR2_Full, FIBRE),
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_LINK_MODE_400)
	ETH_CAP2(100GBASE_SR, 100000, FULL, 1lane, 100000baseSR_Full, FIBRE),
	ETH_CAP2(100GBASE_LR_ER_FR, 100000, FULL, 1lane,
		 100000baseLR_ER_FR_Full, FIBRE),
	ETH_CAP1(100GBASE_CR,  100000, FULL, 1lane, 100000baseCR_Full),
	ETH_CAP2(100GBASE_DR, 100000, FULL, 1lane, 100000baseDR_Full, FIBRE),
#endif

#undef ETH_CAP1
#undef ETH_CAP2
};

static void ethtool_linkset_to_x4_mcdi(unsigned long *linkset,
				       unsigned long *tech_mask,
				       u8 *pause, bool *autoneg)
{
	int tech;

	/* Map from linkset to autoneg */
	*autoneg = linkmode_test_bit(ETHTOOL_LINK_MODE_Autoneg_BIT, linkset);

	/* Map from linkset to pause mode */
	*pause = 0;
	if (linkmode_test_bit(ETHTOOL_LINK_MODE_Pause_BIT, linkset))
		*pause |= BIT(MC_CMD_PAUSE_MODE_AN_PAUSE);

	if (linkmode_test_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, linkset))
		*pause |= BIT(MC_CMD_PAUSE_MODE_AN_ASYM_DIR);

	/* Map from linkset to tech */
	bitmap_zero(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);
	for (tech = 0; tech < ARRAY_SIZE(tech_map); tech++) {
		if (!(tech_map[tech].flags & TECH_MAP_VALID))
			continue;

		if (!(tech_map[tech].flags & TECH_MAP_CAP1))
			continue;

		if (linkmode_test_bit(tech_map[tech].cap1, linkset))
			__set_bit(tech, tech_mask);
	}
}

static void ethtool_to_x4_mcdi(u32 cap, unsigned long *tech_mask,
			       u8 *pause, bool *autoneg)
{
	int tech;

	/* Map from ethtool cap to autoneg */
	*autoneg = !!(cap & SUPPORTED_Autoneg);

	/* Map from ethtool cap to pause mode */
	*pause = 0;
	if (cap & SUPPORTED_Pause)
		*pause |= BIT(MC_CMD_PAUSE_MODE_AN_PAUSE);
	if (cap & SUPPORTED_Asym_Pause)
		*pause |= BIT(MC_CMD_PAUSE_MODE_AN_ASYM_DIR);

	/* Map from ethtool cap to tech */
	bitmap_zero(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);
	for (tech = 0; tech < ARRAY_SIZE(tech_map); tech++) {
		if ((tech_map[tech].flags & TECH_MAP_VALID) == 0)
			continue;

		if ((tech_map[tech].flags & TECH_MAP_CAP1) == 0)
			continue;

		if (tech_map[tech].cap1 < 32 &&
		    (cap & BIT(tech_map[tech].cap1)))
			__set_bit(tech, tech_mask);
	}
}

static void x4_mcdi_to_speed_duplex(struct efx_nic *efx, u32 tech,
				    unsigned int *speed, unsigned int *duplex)
{
	if (tech < ARRAY_SIZE(tech_map) &&
	    tech_map[tech].flags & TECH_MAP_VALID) {
		*speed = tech_map[tech].speed;
		*duplex = tech_map[tech].duplex;
	} else {
		*speed = SPEED_UNKNOWN;
		*duplex = DUPLEX_UNKNOWN;
	}
}

static void x4_mcdi_tech_to_lanes(struct efx_nic *efx, u32 tech, u32 *lanes)
{
	if (tech < ARRAY_SIZE(tech_map) &&
	    tech_map[tech].flags & TECH_MAP_VALID)
		*lanes = tech_map[tech].lanes;
	else
		*lanes = 0; /* unknown */
}

static u32 x4_mcdi_to_ethtool_cap(struct efx_nic *efx, bool autoneg,
				  const unsigned long *tech_mask, u32 pause)
{
	DECLARE_BITMAP(tech_tmp, MC_CMD_ETH_TECH_TECH_WIDTH);
	u32 cap = 0;
	int tech;

	bitmap_copy(tech_tmp, tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);

	/* Map autoneg to linkset */
	if (autoneg)
		cap |= SUPPORTED_Autoneg;

	/* Map pause modes to linkset */
	if (pause & BIT(MC_CMD_PAUSE_MODE_AN_PAUSE))
		cap |= SUPPORTED_Pause;
	if (pause & BIT(MC_CMD_PAUSE_MODE_AN_ASYM_DIR))
		cap |= SUPPORTED_Asym_Pause;

	/* Map tech to linkset */
	for (tech = 0; tech < ARRAY_SIZE(tech_map); tech++) {
		if ((tech_map[tech].flags & TECH_MAP_VALID) == 0)
			continue;

		if (__test_and_clear_bit(tech, tech_tmp) == 0)
			continue;

		if (tech_map[tech].flags & TECH_MAP_CAP1)
			cap |= BIT(tech_map[tech].cap1);

		if (tech_map[tech].flags & TECH_MAP_CAP2)
			cap |= BIT(tech_map[tech].cap2);
	}
#ifdef EFX_NOT_UPSTREAM
	if (!bitmap_empty(tech_tmp, MC_CMD_ETH_TECH_TECH_WIDTH)) {
		static bool warned;

		if (!warned) {
			pci_notice(efx->pci_dev,
				   "This NIC has %d link technologies that are not supported by your kernel: %*pbl\n",
				   bitmap_weight(tech_tmp,
						 MC_CMD_ETH_TECH_TECH_WIDTH),
				   MC_CMD_ETH_TECH_TECH_WIDTH, tech_tmp);
			warned = true;
		}
	}
#endif
	return cap;
}

static void x4_mcdi_to_ethtool_linkset(struct efx_nic *efx, bool autoneg,
				       const unsigned long *tech_mask,
				       u32 pause, unsigned long *linkset)
{
	DECLARE_BITMAP(tech_tmp, MC_CMD_ETH_TECH_TECH_WIDTH);
	int tech;

	linkmode_zero(linkset);
	bitmap_copy(tech_tmp, tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);

	/* Map autoneg to linkset */
	if (autoneg)
		linkmode_set_bit(ETHTOOL_LINK_MODE_Autoneg_BIT, linkset);

	/* Map pause modes to linkset */
	if (pause & BIT(MC_CMD_PAUSE_MODE_AN_PAUSE))
		linkmode_set_bit(ETHTOOL_LINK_MODE_Pause_BIT, linkset);

	if (pause & BIT(MC_CMD_PAUSE_MODE_AN_ASYM_DIR))
		linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, linkset);

	/* Map tech to linkset */
	for (tech = 0; tech < ARRAY_SIZE(tech_map); tech++) {
		if (!(tech_map[tech].flags & TECH_MAP_VALID))
			continue;

		if (!__test_and_clear_bit(tech, tech_tmp))
			continue;

		if (tech_map[tech].flags & TECH_MAP_CAP1)
			linkmode_set_bit(tech_map[tech].cap1, linkset);

		if (tech_map[tech].flags & TECH_MAP_CAP2)
			linkmode_set_bit(tech_map[tech].cap2, linkset);
	}
#ifdef EFX_NOT_UPSTREAM
	if (!bitmap_empty(tech_tmp, MC_CMD_ETH_TECH_TECH_WIDTH)) {
		static bool warned;

		if (!warned) {
			pci_notice(efx->pci_dev,
				   "This NIC has %d link technologies that are not supported by your kernel: %*pbl\n",
				   bitmap_weight(tech_tmp,
						 MC_CMD_ETH_TECH_TECH_WIDTH),
				   MC_CMD_ETH_TECH_TECH_WIDTH, tech_tmp);
			warned = true;
		}
	}
#endif
}

static u32 ethtool_fec_to_x4_mcdi(u32 supported_fec, u32 ethtool_fec)
{
	if (ethtool_fec & ETHTOOL_FEC_OFF)
		return MC_CMD_FEC_NONE;

	if (ethtool_fec & ETHTOOL_FEC_AUTO)
		if (supported_fec != 0)
			return MC_CMD_FEC_AUTO;

	if (ethtool_fec & ETHTOOL_FEC_RS)
		if (supported_fec & BIT(MC_CMD_FEC_RS))
			return MC_CMD_FEC_RS;

	if (ethtool_fec & ETHTOOL_FEC_BASER)
		if (supported_fec & BIT(MC_CMD_FEC_BASER))
			return MC_CMD_FEC_BASER;

	return MC_CMD_FEC_NONE;
}

static u32 x4_mcdi_fec_to_ethtool(u32 fec_mode, u32 requested_fec)
{
	bool baser_req = requested_fec & BIT(MC_CMD_FEC_BASER);
	bool rs_req = requested_fec & BIT(MC_CMD_FEC_RS);
	bool baser = fec_mode == MC_CMD_FEC_BASER;
	bool rs = fec_mode == MC_CMD_FEC_RS;
	u32 ethtool_fec = 0;

	if (fec_mode == MC_CMD_FEC_NONE)
		return ETHTOOL_FEC_OFF;

	if (rs_req)
		ethtool_fec |= ETHTOOL_FEC_RS;
	if (rs != rs_req)
		ethtool_fec |= ETHTOOL_FEC_AUTO;

	if (baser_req)
		ethtool_fec |= ETHTOOL_FEC_BASER;
	if (baser != baser_req)
		ethtool_fec |= ETHTOOL_FEC_AUTO;

	return ethtool_fec;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_LINK_MODE_FEC_BITS)
static void x4_mcdi_fec_to_ethtool_linkset(u32 fec,
					   u32 requested_fec,
					   unsigned long *linkset)
{
	if (fec & BIT(MC_CMD_FEC_BASER))
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_BASER_BIT, linkset);

	if (fec & BIT(MC_CMD_FEC_RS))
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_RS_BIT, linkset);

	if (!(requested_fec & (BIT(MC_CMD_FEC_RS) |
			       BIT(MC_CMD_FEC_BASER))))
		linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_NONE_BIT, linkset);
}
#endif

static
u64 efx_mcdi_legacy_loopback_modes(struct efx_x4_mcdi_port_data *port_data)
{
	u64 loopback = port_data->fixed_port.loopback;
	u64 legacy_modes = 0;

	if (loopback & BIT_ULL(MC_CMD_LOOPBACK_V2_NONE))
		legacy_modes |= BIT_ULL(LOOPBACK_NONE);
	if (loopback & BIT_ULL(MC_CMD_LOOPBACK_V2_AUTO))
		legacy_modes |= BIT_ULL(LOOPBACK_DATA);
	if (loopback & BIT_ULL(MC_CMD_LOOPBACK_V2_POST_PCS))
		legacy_modes |= BIT_ULL(LOOPBACK_PCS);

	// FIXME: translate other LOOPBACK_V2 modes
	return legacy_modes;
}

static int efx_mcdi_loopback_from_legacy(u32 legacy_mode)
{
	switch (legacy_mode) {
	case LOOPBACK_NONE:
		return MC_CMD_LOOPBACK_V2_NONE;
	case LOOPBACK_DATA:
		return MC_CMD_LOOPBACK_V2_AUTO;
	case LOOPBACK_PCS:
		return MC_CMD_LOOPBACK_V2_POST_PCS;
	default:
		return MC_CMD_LOOPBACK_V2_NONE;
	}
}

static void efx_x4_mcdi_tech_from_bitmap(efx_oword_t *mcdi_tech,
					 const unsigned long *bitmap)
{
	u32 bits[4];

	BUILD_BUG_ON(sizeof(bits) * BITS_PER_BYTE < MC_CMD_ETH_TECH_TECH_WIDTH);
	bitmap_to_arr32(bits, bitmap, MC_CMD_ETH_TECH_TECH_WIDTH);

	EFX_SET_OWORD_FIELD(*mcdi_tech, EFX_DWORD_0, bits[0]);
	EFX_SET_OWORD_FIELD(*mcdi_tech, EFX_DWORD_1, bits[1]);
	EFX_SET_OWORD_FIELD(*mcdi_tech, EFX_DWORD_2, bits[2]);
	EFX_SET_OWORD_FIELD(*mcdi_tech, EFX_DWORD_3, bits[3]);
}

static void efx_x4_mcdi_tech_to_bitmap(unsigned long *bitmap,
				       const efx_oword_t *mcdi_tech)
{
	u32 bits[4];

	bits[0] = EFX_OWORD_FIELD(*mcdi_tech, EFX_DWORD_0);
	bits[1] = EFX_OWORD_FIELD(*mcdi_tech, EFX_DWORD_1);
	bits[2] = EFX_OWORD_FIELD(*mcdi_tech, EFX_DWORD_2);
	bits[3] = EFX_OWORD_FIELD(*mcdi_tech, EFX_DWORD_3);

	BUILD_BUG_ON(sizeof(bits) * BITS_PER_BYTE < MC_CMD_ETH_TECH_TECH_WIDTH);
	bitmap_from_arr32(bitmap, bits, MC_CMD_ETH_TECH_TECH_WIDTH);
}

static int efx_x4_mcdi_link_ctrl(struct efx_nic *efx, u32 loopback_mode,
				 u32 flags, const unsigned long *tech_mask,
				 u32 pause, u8 fec, u32 tech, u8 module_seq)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_LINK_CTRL_IN_LEN);
	u32 loopback;
	void *caps;

	BUILD_BUG_ON(MC_CMD_LINK_CTRL_OUT_LEN != 0);

	MCDI_SET_DWORD(inbuf, LINK_CTRL_IN_PORT_HANDLE, efx->port_handle);
	MCDI_SET_DWORD(inbuf, LINK_CTRL_IN_CONTROL_FLAGS, flags);

	if (loopback_mode) {
		/* Loopback (LINK_TECHNOLOGY sets link speed) */
		loopback = efx_mcdi_loopback_from_legacy(loopback_mode);
		if (loopback == MC_CMD_LOOPBACK_V2_NONE)
			return -EINVAL;

		MCDI_SET_BYTE(inbuf, LINK_CTRL_IN_LOOPBACK, loopback);
		MCDI_SET_WORD(inbuf, LINK_CTRL_IN_LINK_TECHNOLOGY,
			      MC_CMD_ETH_TECH_AUTO); /* Auto link speed */

	} else if (flags & BIT(MC_CMD_LINK_FLAGS_AUTONEG_EN)) {
		/* Autoneg enabled (LOOPBACK and LINK_TECHNOLOGY ignored) */
		BUILD_BUG_ON(MC_CMD_ETH_TECH_TECH_WIDTH != BITS_PER_BYTE *
			     MC_CMD_LINK_CTRL_IN_ADVERTISED_TECH_ABILITIES_MASK_LEN);

		caps = MCDI_PTR(inbuf,
				LINK_CTRL_IN_ADVERTISED_TECH_ABILITIES_MASK);
		efx_x4_mcdi_tech_from_bitmap(caps, tech_mask);

		MCDI_SET_BYTE(inbuf,
			      LINK_CTRL_IN_ADVERTISED_PAUSE_ABILITIES_MASK,
			      pause);
	} else {
		/* Forced link technology (TECH_MASK ignored) */
		MCDI_SET_WORD(inbuf, LINK_CTRL_IN_LINK_TECHNOLOGY, tech);
	}
	MCDI_SET_BYTE(inbuf, LINK_CTRL_IN_FEC_MODE, fec);
	MCDI_SET_BYTE(inbuf, LINK_CTRL_IN_MODULE_SEQ, module_seq);

	return efx_mcdi_rpc(efx, MC_CMD_LINK_CTRL, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

/* Choose fixed link tech for MC_CMD_LINK_CTRL */
static u16 efx_x4_link_tech(struct efx_x4_mcdi_port_data *port_data,
			    unsigned long *tech_mask, bool autoneg)
{
	u16 tech;

	if (autoneg)
		return MC_CMD_ETH_TECH_NONE; /* Ignored */

	tech = find_first_bit(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);
	if (tech == MC_CMD_ETH_TECH_TECH_WIDTH) {
		/* Keep current mode as no link tech specified. */
		tech = port_data->link.tech;
	}
	return tech;
}

int efx_x4_mcdi_port_reconfigure(struct efx_nic *efx)
{
	DECLARE_BITMAP(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH) = {};
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	bool autoneg = false;
	u8 fec, pause = 0;
	u32 flags;
	u16 tech;

	if (!efx_nic_port_handle_supported(efx))
		return efx_mcdi_port_reconfigure(efx);

	/* Avoid using port data if unavailable (e.g. probe retry). */
	if (!port_data)
		return -ENETDOWN;

	flags = BIT(MC_CMD_LINK_FLAGS_IGNORE_MODULE_SEQ);
	ethtool_linkset_to_x4_mcdi(efx->link_advertising, tech_mask,
				   &pause, &autoneg);
	if (autoneg)
		flags |= BIT(MC_CMD_LINK_FLAGS_AUTONEG_EN);

	tech = efx_x4_link_tech(port_data, tech_mask, autoneg);
	fec = ethtool_fec_to_x4_mcdi(port_data->supported.fec,
				     efx->fec_config);

	return efx_x4_mcdi_link_ctrl(efx, efx->loopback_mode, flags,
				     tech_mask, pause, fec, tech, 0);
}

static
int efx_x4_mcdi_link_state(struct efx_nic *efx)
{
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	MCDI_DECLARE_BUF(outbuf, MC_CMD_LINK_STATE_OUT_V3_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_LINK_STATE_IN_LEN);
	void *supported, *advertised, *partner;
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, LINK_STATE_IN_PORT_HANDLE, efx->port_handle);

	rc = efx_mcdi_rpc(efx, MC_CMD_LINK_STATE, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_LINK_STATE_OUT_LEN)
		return -EIO;

	/* Link State */
	port_data->link.status =
		MCDI_QWORD(outbuf, LINK_STATE_OUT_STATUS_FLAGS);
	port_data->link.control =
		MCDI_DWORD(outbuf, LINK_STATE_OUT_CONTROL_FLAGS);
	port_data->link.tech =
		MCDI_WORD(outbuf, LINK_STATE_OUT_LINK_TECHNOLOGY);
	port_data->link.fec =
		MCDI_BYTE(outbuf, LINK_STATE_OUT_FEC_MODE);
	port_data->link.pause =
		MCDI_BYTE(outbuf, LINK_STATE_OUT_PAUSE_MASK);
	port_data->link.loopback =
		MCDI_BYTE(outbuf, LINK_STATE_OUT_LOOPBACK);
	port_data->link.module_seq =
		MCDI_BYTE(outbuf, LINK_STATE_OUT_PORT_MODULECHANGE_SEQ_NUM);

	/* Supported abilities */
	BUILD_BUG_ON(bitmap_size(MC_CMD_ETH_TECH_TECH_WIDTH) !=
		     MC_CMD_LINK_STATE_OUT_SUPPORTED_ABILITIES_TECH_MASK_LEN);

	supported = MCDI_PTR(outbuf,
			     LINK_STATE_OUT_SUPPORTED_ABILITIES_TECH_MASK);
	efx_x4_mcdi_tech_to_bitmap(port_data->supported.tech_mask, supported);

	port_data->supported.fec =
		MCDI_DWORD(outbuf,
			   LINK_STATE_OUT_SUPPORTED_ABILITIES_FEC_MASK);
	port_data->supported.requested_fec =
		MCDI_DWORD(outbuf,
			   LINK_STATE_OUT_SUPPORTED_ABILITIES_FEC_REQ);
	port_data->supported.pause =
		MCDI_BYTE(outbuf,
			  LINK_STATE_OUT_SUPPORTED_ABILITIES_PAUSE_MASK);

	/* Advertised abilities */
	BUILD_BUG_ON(bitmap_size(MC_CMD_ETH_TECH_TECH_WIDTH) !=
		MC_CMD_LINK_STATE_OUT_ADVERTISED_ABILITIES_TECH_MASK_LEN);

	advertised = MCDI_PTR(outbuf,
			      LINK_STATE_OUT_ADVERTISED_ABILITIES_TECH_MASK);
	efx_x4_mcdi_tech_to_bitmap(port_data->advertised.tech_mask, advertised);

	port_data->advertised.fec =
		MCDI_DWORD(outbuf,
			   LINK_STATE_OUT_ADVERTISED_ABILITIES_FEC_MASK);
	port_data->advertised.requested_fec =
		MCDI_DWORD(outbuf,
			   LINK_STATE_OUT_ADVERTISED_ABILITIES_FEC_REQ);
	port_data->advertised.pause =
		MCDI_BYTE(outbuf,
			  LINK_STATE_OUT_ADVERTISED_ABILITIES_PAUSE_MASK);

	/* Link partner abilities */
	BUILD_BUG_ON(bitmap_size(MC_CMD_ETH_TECH_TECH_WIDTH) !=
		MC_CMD_LINK_STATE_OUT_LINK_PARTNER_ABILITIES_TECH_MASK_LEN);

	partner = MCDI_PTR(outbuf,
			   LINK_STATE_OUT_LINK_PARTNER_ABILITIES_TECH_MASK);
	efx_x4_mcdi_tech_to_bitmap(port_data->partner.tech_mask, partner);

	port_data->partner.fec =
		MCDI_DWORD(outbuf,
			   LINK_STATE_OUT_LINK_PARTNER_ABILITIES_FEC_MASK);
	port_data->partner.requested_fec =
		MCDI_DWORD(outbuf,
			   LINK_STATE_OUT_LINK_PARTNER_ABILITIES_FEC_REQ);
	port_data->partner.pause =
		MCDI_BYTE(outbuf,
			  LINK_STATE_OUT_LINK_PARTNER_ABILITIES_PAUSE_MASK);

	/* Supported autonegotiation type */
	if (outlen < MC_CMD_LINK_STATE_OUT_V2_LEN)
		port_data->link.supported_autoneg = MC_CMD_AN_NONE;
	else
		port_data->link.supported_autoneg =
			MCDI_DWORD(outbuf, LINK_STATE_OUT_V2_LOCAL_AN_SUPPORT);

	if (outlen < MC_CMD_LINK_STATE_OUT_V3_LEN) {
		port_data->link.duplex = DUPLEX_UNKNOWN;
		port_data->link.speed = SPEED_UNKNOWN;
	} else {
		/* Link duplex and speed (Mbit/s) to use if LINK_TECHNOLOGY
		 * is not known to the driver and so cannot be translated.
		 */
		port_data->link.duplex =
			MCDI_DWORD(outbuf, LINK_STATE_OUT_V3_FULL_DUPLEX) ?
			DUPLEX_FULL : DUPLEX_HALF;
		port_data->link.speed =
			MCDI_DWORD(outbuf, LINK_STATE_OUT_V3_LINK_SPEED);
	}

	return 0;
}

static void
efx_x4_mcdi_phy_decode_link(struct efx_nic *efx,
			    struct efx_link_state *link_state,
			    const struct efx_x4_mcdi_port_data *port_data,
			    u32 fcntl)
{
	unsigned int duplex = DUPLEX_UNKNOWN;
	unsigned int speed = SPEED_UNKNOWN;

	link_state->fc = efx_mcdi_phy_decode_fcntl(fcntl);
	link_state->up = !!(port_data->link.status &
			    BIT(MC_CMD_LINK_STATUS_FLAGS_LINK_UP));

	x4_mcdi_to_speed_duplex(efx, port_data->link.tech, &speed, &duplex);
	if (speed == SPEED_UNKNOWN) {
		/* Link technology cannot be translated. Fall back to
		 * firmware reported speed/duplex if available.
		 */
		duplex = port_data->link.duplex;
		speed = port_data->link.speed;
	}
	link_state->fd = duplex == DUPLEX_FULL;
	link_state->speed = (speed == SPEED_UNKNOWN) ? 0 : speed;

	/* Not used with port handle API */
	link_state->ld_caps = 0;
	link_state->lp_caps = 0;
}

static
int efx_x4_mcdi_fixed_port_props(struct efx_nic *efx,
				 struct efx_x4_mcdi_port_data *port_data)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_FIXED_PORT_PROPERTIES_OUT_V2_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_FIXED_PORT_PROPERTIES_IN_LEN);
	size_t outlen;
	u8 *caps;
	int rc;

	MCDI_SET_DWORD(inbuf, GET_FIXED_PORT_PROPERTIES_IN_PORT_HANDLE,
		       efx->port_handle);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_FIXED_PORT_PROPERTIES, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_GET_FIXED_PORT_PROPERTIES_OUT_LEN)
		return -EIO;

	BUILD_BUG_ON(bitmap_size(MC_CMD_ETH_TECH_TECH_WIDTH) !=
		     MC_CMD_GET_FIXED_PORT_PROPERTIES_OUT_ABILITIES_TECH_MASK_LEN);

	caps = MCDI_PTR(outbuf, GET_FIXED_PORT_PROPERTIES_OUT_ABILITIES_TECH_MASK);
	efx_x4_mcdi_tech_to_bitmap(port_data->fixed_port.tech_mask,
				   (const efx_oword_t *)caps);

	port_data->fixed_port.fec =
		MCDI_DWORD(outbuf, GET_FIXED_PORT_PROPERTIES_OUT_ABILITIES_FEC_MASK);
	port_data->fixed_port.pause =
		MCDI_BYTE(outbuf, GET_FIXED_PORT_PROPERTIES_OUT_ABILITIES_PAUSE_MASK);

	port_data->fixed_port.loopback =
		(outlen < MC_CMD_GET_FIXED_PORT_PROPERTIES_OUT_V2_LEN) ?
		MCDI_BYTE(outbuf, GET_FIXED_PORT_PROPERTIES_OUT_LOOPBACK_MODES_MASK) :
		MCDI_QWORD(outbuf, GET_FIXED_PORT_PROPERTIES_OUT_V2_LOOPBACK_MODES_MASK_V2);

	return 0;
}

static
int efx_x4_mcdi_transceiver_props(struct efx_nic *efx,
				  struct efx_x4_mcdi_port_data *port_data)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_TRANSCEIVER_PROPERTIES_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_TRANSCEIVER_PROPERTIES_IN_LEN);
	size_t outlen;
	u8 *caps;
	int rc;

	BUILD_BUG_ON(bitmap_size(MC_CMD_ETH_TECH_TECH_WIDTH) !=
		     MC_CMD_GET_TRANSCEIVER_PROPERTIES_OUT_TECH_ABILITIES_MASK_LEN);

	MCDI_SET_DWORD(inbuf, GET_TRANSCEIVER_PROPERTIES_IN_PORT_HANDLE,
		       efx->port_handle);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_TRANSCEIVER_PROPERTIES, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;

	if (outlen < MC_CMD_GET_TRANSCEIVER_PROPERTIES_OUT_LEN)
		return -EIO;

	caps = MCDI_PTR(outbuf, GET_TRANSCEIVER_PROPERTIES_OUT_TECH_ABILITIES_MASK);
	efx_x4_mcdi_tech_to_bitmap(port_data->transceiver.tech_mask,
				   (const efx_oword_t *)caps);

	port_data->transceiver.preferred_fec =
		MCDI_DWORD(outbuf, GET_TRANSCEIVER_PROPERTIES_OUT_PREFERRED_FEC_MASK);
	port_data->transceiver.medium =
		MCDI_BYTE(outbuf, GET_TRANSCEIVER_PROPERTIES_OUT_MEDIUM);
	port_data->transceiver.media_subtype =
		MCDI_BYTE(outbuf, GET_TRANSCEIVER_PROPERTIES_OUT_MEDIA_SUBTYPE);
	return 0;
}

bool efx_x4_mcdi_phy_poll(struct efx_nic *efx)
{
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	struct efx_link_state old_state = efx->link_state;
	int rc, rc2;
	u32 fcntl;

	if (!efx_nic_port_handle_supported(efx))
		return efx_mcdi_phy_poll(efx);

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	rc = efx_x4_mcdi_link_state(efx);
	rc2 = efx_x4_mcdi_get_link_fcntl(efx, &fcntl);
	if (rc || rc2)
		efx->link_state.up = false;
	else
		efx_x4_mcdi_phy_decode_link(efx, &efx->link_state,
					    port_data, fcntl);

	return !efx_link_state_equal(&efx->link_state, &old_state);
}

int efx_x4_mcdi_phy_probe(struct efx_nic *efx)
{
	DECLARE_BITMAP(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH) = {};
	struct efx_x4_mcdi_port_data *port_data;
	bool autoneg;
	u32 fcntl;
	int rc;

	/* Initialise and populate port_data */
	port_data = kzalloc(sizeof(*port_data), GFP_KERNEL);
	if (!port_data)
		return -ENOMEM;

	rc = efx_x4_mcdi_fixed_port_props(efx, port_data);
	if (rc)
		goto fail;

	rc = efx_x4_mcdi_transceiver_props(efx, port_data);
	if (rc)
		goto fail;

	/* By convention, do not treat NONE as a loopback mode */
	efx->loopback_modes = efx_mcdi_legacy_loopback_modes(port_data);
	efx->loopback_modes &= ~BIT_ULL(LOOPBACK_NONE);

	/* Fill out nic state */
	efx->port_data = port_data;

	/* Read initial link advertisement */
	rc = efx_x4_mcdi_link_state(efx);
	if (rc) {
		pci_info(efx->pci_dev, "get link state failed rc=%d\n", rc);
		goto fail;
	}
	autoneg = port_data->link.control & BIT(MC_CMD_LINK_FLAGS_AUTONEG_EN);

	if (!autoneg || port_data->link.supported_autoneg == MC_CMD_AN_NONE) {
		__set_bit(port_data->link.tech, tech_mask);
		x4_mcdi_to_ethtool_linkset(efx, autoneg, tech_mask,
					   port_data->link.pause,
					   efx->link_advertising);
	} else {
		x4_mcdi_to_ethtool_linkset(efx, autoneg,
					   port_data->advertised.tech_mask,
					   port_data->advertised.pause,
					   efx->link_advertising);
	}

	rc = efx_x4_mcdi_get_link_fcntl(efx, &fcntl);
	if (rc) {
		pci_info(efx->pci_dev, "get link fcntl failed rc=%d\n", rc);
		goto fail;
	}

	/* Set the initial link mode */
	efx_x4_mcdi_phy_decode_link(efx, &efx->link_state, port_data, fcntl);

	efx->fec_config =
		x4_mcdi_fec_to_ethtool(port_data->link.fec,
				       port_data->advertised.requested_fec);

	/* Default to Autonegotiated flow control if the PHY supports it */
	efx->wanted_fc = EFX_FC_RX | EFX_FC_TX;
	if (port_data->link.supported_autoneg != MC_CMD_AN_NONE)
		efx->wanted_fc |= EFX_FC_AUTO;
	efx_link_set_wanted_fc(efx, efx->wanted_fc);

	return 0;

fail:
	pci_err(efx->pci_dev, "phy_probe failed\n");
	kfree(port_data);
	return rc;
}

void efx_x4_mcdi_phy_remove(struct efx_nic *efx)
{
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;

	efx->port_data = NULL;
	kfree(port_data);
}

static int ethtool_speed_to_x4_mcdi(unsigned long *tech_mask,
				    u32 speed, bool duplex, u32 lanes)
{
	int tech;

	for_each_set_bit(tech, tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH) {
		if (~tech_map[tech].flags & TECH_MAP_VALID)
			continue;

		if (~tech_map[tech].flags & TECH_MAP_CAP1)
			continue;

		if (tech_map[tech].speed == speed &&
		    tech_map[tech].duplex == duplex &&
		    (!lanes || tech_map[tech].lanes == lanes))
			return tech;
	}

	return MC_CMD_ETH_TECH_NONE;
}

static int efx_port_type(struct efx_nic *efx)
{
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	u8 subtype = port_data->transceiver.media_subtype;
	u8 medium = port_data->transceiver.medium;

	switch (medium) {
	case MC_CMD_GET_TRANSCEIVER_PROPERTIES_OUT_OPTICAL:
		return PORT_FIBRE;
	case MC_CMD_GET_TRANSCEIVER_PROPERTIES_OUT_COPPER:
		if (subtype == MC_CMD_GET_TRANSCEIVER_PROPERTIES_OUT_BASET)
			return PORT_TP;
		return PORT_DA;
	case MC_CMD_GET_TRANSCEIVER_PROPERTIES_OUT_BACKPLANE:
	case MC_CMD_GET_TRANSCEIVER_PROPERTIES_OUT_UNKNOWN:
	default:
		return PORT_OTHER;
	}
}

void efx_x4_mcdi_phy_get_settings(struct efx_nic *efx, struct ethtool_cmd *ecmd)
{
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	bool supported_autoneg;
	bool partner_autoneg;
	int rc;

	supported_autoneg = port_data->link.supported_autoneg != MC_CMD_AN_NONE;

	ecmd->supported = x4_mcdi_to_ethtool_cap(efx, supported_autoneg,
						 port_data->supported.tech_mask,
						 port_data->supported.pause);
	ecmd->advertising = efx->link_advertising[0];
	ethtool_cmd_speed_set(ecmd, efx->link_state.speed);
	ecmd->duplex = efx->link_state.fd;
	ecmd->port = efx_port_type(efx);
	ecmd->phy_address = 0;
	ecmd->transceiver = XCVR_INTERNAL;
	ecmd->autoneg = !!(efx->link_advertising[0] & ADVERTISED_Autoneg);

	rc = efx_x4_mcdi_link_state(efx);
	if (rc)
		return;

	partner_autoneg = port_data->link.status & BIT(MC_CMD_LINK_STATUS_FLAGS_AN_ABLE);
	ecmd->lp_advertising = x4_mcdi_to_ethtool_cap(efx, partner_autoneg,
						      port_data->partner.tech_mask,
						      port_data->partner.pause);
}

int efx_x4_mcdi_phy_set_settings(struct efx_nic *efx, struct ethtool_cmd *ecmd,
				 unsigned long *new_adv)
{
	DECLARE_BITMAP(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH) = {};
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	unsigned int advertising = ecmd->advertising;
	bool autoneg = false;
	u8 fec, pause = 0;
	u32 flags;
	u16 tech;
	int rc;

	/* Remove flow control settings that the MAC supports
	 * but that the PHY can't advertise.
	 */
	if (~port_data->supported.pause & BIT(MC_CMD_PAUSE_MODE_AN_PAUSE))
		advertising &= ~ADVERTISED_Pause;
	if (~port_data->supported.pause & BIT(MC_CMD_PAUSE_MODE_AN_ASYM_DIR))
		advertising &= ~ADVERTISED_Asym_Pause;

	if (ecmd->autoneg)
		advertising |= ADVERTISED_Autoneg;
	else
		advertising &= ~ADVERTISED_Autoneg;

	flags = BIT(MC_CMD_LINK_FLAGS_IGNORE_MODULE_SEQ);
	ethtool_to_x4_mcdi(advertising, tech_mask, &pause, &autoneg);
	if (autoneg) {
		flags |= BIT(MC_CMD_LINK_FLAGS_AUTONEG_EN);
		if (bitmap_empty(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH))
			return -EINVAL;
		tech = MC_CMD_ETH_TECH_NONE; /* Ignored */
	} else {
		tech = ethtool_speed_to_x4_mcdi(port_data->supported.tech_mask,
						ethtool_cmd_speed(ecmd),
						ecmd->duplex, 0 /*lanes*/);
		if (tech == MC_CMD_ETH_TECH_NONE)
			return -EINVAL;
	}
	fec = ethtool_fec_to_x4_mcdi(port_data->supported.fec,
				     efx->fec_config);

	rc = efx_x4_mcdi_link_ctrl(efx, efx->loopback_mode, flags,
				   tech_mask, pause, fec, tech, 0);
	if (rc) {
		if (rc == -EINVAL)
			netif_err(efx, link, efx->net_dev,
				  "invalid link settings: autoneg=%u advertising=%#x speed=%u duplex=%u\n",
				  ecmd->autoneg, ecmd->advertising,
				  ecmd->speed, ecmd->duplex);
		return rc;
	}

	/* Rather than storing the original advertising mask, we
	 * convert the capabilities we're actually using back to an
	 * advertising mask so that (1) get_settings() will report
	 * correct information (2) we can push the capabilities again
	 * after an MC reset, or recalculate them on module change.
	 */
	if (!autoneg && !efx->loopback_mode) {
		/* Replace tech mask with forced link tech */
		bitmap_zero(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);
		__set_bit(tech, tech_mask);
	}
	x4_mcdi_to_ethtool_linkset(efx, autoneg, tech_mask, pause, new_adv);

	return 1;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_LINKSETTINGS)
void efx_x4_mcdi_phy_get_ksettings(struct efx_nic *efx,
				   struct ethtool_link_ksettings *out)
{
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	struct ethtool_link_settings *base = &out->base;
	bool supported_autoneg;
	bool partner_autoneg;
	int rc;

	if (netif_carrier_ok(efx->net_dev)) {
		base->speed = efx->link_state.speed;
		base->duplex = efx->link_state.fd ? DUPLEX_FULL : DUPLEX_HALF;
	} else {
		base->speed = 0;
		base->duplex = DUPLEX_UNKNOWN;
	}
	base->port = efx_port_type(efx);
	base->phy_address = 0;

	if (linkmode_test_bit(ETHTOOL_LINK_MODE_Autoneg_BIT,
			      efx->link_advertising))
		base->autoneg = AUTONEG_ENABLE;
	else
		base->autoneg = AUTONEG_DISABLE;

	rc = efx_x4_mcdi_link_state(efx);
	if (rc)
		return;

	supported_autoneg = port_data->link.supported_autoneg != MC_CMD_AN_NONE;
	x4_mcdi_to_ethtool_linkset(efx, supported_autoneg,
				   port_data->supported.tech_mask,
				   port_data->supported.pause,
				   out->link_modes.supported);

	linkmode_copy(out->link_modes.advertising, efx->link_advertising);

	partner_autoneg = port_data->link.status & BIT(MC_CMD_LINK_STATUS_FLAGS_AN_ABLE);
	x4_mcdi_to_ethtool_linkset(efx, partner_autoneg,
				   port_data->partner.tech_mask,
				   port_data->partner.pause,
				   out->link_modes.lp_advertising);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_LINK_MODE_FEC_BITS)
	x4_mcdi_fec_to_ethtool_linkset(port_data->advertised.fec,
				       port_data->advertised.requested_fec,
				       out->link_modes.advertising);
	x4_mcdi_fec_to_ethtool_linkset(port_data->supported.fec,
				       port_data->supported.requested_fec,
				       out->link_modes.supported);
	x4_mcdi_fec_to_ethtool_linkset(port_data->partner.fec,
				       port_data->partner.requested_fec,
				       out->link_modes.lp_advertising);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_LINK_LANES)
	x4_mcdi_tech_to_lanes(efx, port_data->link.tech, &out->lanes);
#endif
}

int efx_x4_mcdi_phy_set_ksettings(struct efx_nic *efx,
				  const struct ethtool_link_ksettings *settings,
				  unsigned long *advertising)
{
	DECLARE_BITMAP(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH) = {};
	const struct ethtool_link_settings *base = &settings->base;
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	bool autoneg = false;
	u8 fec, pause = 0;
	u32 flags;
	u16 tech;
	int rc;

	linkmode_copy(advertising, settings->link_modes.advertising);

	/* Remove flow control settings that the MAC supports
	 * but that the PHY can't advertise.
	 */
	if (~port_data->supported.pause & BIT(MC_CMD_PAUSE_MODE_AN_PAUSE))
		linkmode_clear_bit(ETHTOOL_LINK_MODE_Pause_BIT, advertising);

	if (~port_data->supported.pause & BIT(MC_CMD_PAUSE_MODE_AN_ASYM_DIR))
		linkmode_clear_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT,
				   advertising);

	if (base->autoneg)
		linkmode_set_bit(ETHTOOL_LINK_MODE_Autoneg_BIT, advertising);
	else
		linkmode_clear_bit(ETHTOOL_LINK_MODE_Autoneg_BIT, advertising);

	flags = BIT(MC_CMD_LINK_FLAGS_IGNORE_MODULE_SEQ);
	ethtool_linkset_to_x4_mcdi(advertising, tech_mask, &pause, &autoneg);
	if (autoneg) {
		flags |= BIT(MC_CMD_LINK_FLAGS_AUTONEG_EN);
		if (bitmap_empty(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH))
			return -EINVAL;
		tech = MC_CMD_ETH_TECH_NONE; /* Ignored */
	} else {
		tech = ethtool_speed_to_x4_mcdi(port_data->supported.tech_mask,
						base->speed, base->duplex,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_LINK_LANES)
						settings->lanes);
#else
						0);
#endif
		if (tech == MC_CMD_ETH_TECH_NONE)
			return -EINVAL;
	}
	fec = ethtool_fec_to_x4_mcdi(port_data->supported.fec,
				     efx->fec_config);

	rc = efx_x4_mcdi_link_ctrl(efx, efx->loopback_mode, flags,
				   tech_mask, pause, fec, tech, 0);
	if (rc) {
		if (rc == -EINVAL)
			netif_err(efx, link, efx->net_dev,
				  "invalid link settings: autoneg=%u advertising=%*pb speed=%u duplex=%u\n",
				  base->autoneg, __ETHTOOL_LINK_MODE_MASK_NBITS,
				  settings->link_modes.advertising, base->speed,
				  base->duplex);
		return rc;
	}

	/* Rather than storing the original advertising mask, we
	 * convert the capabilities we're actually using back to an
	 * advertising mask so that (1) get_settings() will report
	 * correct information (2) we can push the capabilities again
	 * after an MC reset.
	 */
	if (!autoneg && !efx->loopback_mode) {
		/* Replace tech mask with forced link tech */
		bitmap_zero(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);
		__set_bit(tech, tech_mask);
	}
	x4_mcdi_to_ethtool_linkset(efx, autoneg, tech_mask, pause, advertising);

	return 1;
}
#endif

int efx_x4_mcdi_phy_get_fecparam(struct efx_nic *efx,
				 struct ethtool_fecparam *fecparam)
{
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	int rc;

	rc = efx_x4_mcdi_link_state(efx);
	if (rc)
		return rc;

	fecparam->fec =
		x4_mcdi_fec_to_ethtool(port_data->link.fec,
				       port_data->advertised.requested_fec);

	switch (port_data->link.fec) {
	case MC_CMD_FEC_NONE:
		fecparam->active_fec = ETHTOOL_FEC_OFF;
		break;
	case MC_CMD_FEC_BASER:
		fecparam->active_fec = ETHTOOL_FEC_BASER;
		break;
	case MC_CMD_FEC_RS:
		fecparam->active_fec = ETHTOOL_FEC_RS;
		break;
	default:
		netif_warn(efx, hw, efx->net_dev,
			   "Firmware reports unrecognised FEC_TYPE %u\n",
			   port_data->link.fec);
		/* We don't know what firmware has picked.  AUTO is as good a
		 * "can't happen" value as any other.
		 */
		fecparam->active_fec = ETHTOOL_FEC_AUTO;
		break;
	}
	return 0;
}

int efx_x4_mcdi_phy_set_fecparam(struct efx_nic *efx,
				 const struct ethtool_fecparam *fecparam)
{
	DECLARE_BITMAP(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH) = {};
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	bool autoneg = false;
	u8 fec, pause = 0;
	u32 flags;
	u16 tech;
	int rc;

	/* Validate new FEC mode */
	fec = ethtool_fec_to_x4_mcdi(port_data->supported.fec,
				     fecparam->fec);
	if (!(fecparam->fec & ETHTOOL_FEC_OFF) &&
	    fecparam->fec && fec == MC_CMD_FEC_NONE)
		return -EINVAL;

	flags = BIT(MC_CMD_LINK_FLAGS_IGNORE_MODULE_SEQ);
	ethtool_linkset_to_x4_mcdi(efx->link_advertising, tech_mask,
				   &pause, &autoneg);
	if (autoneg)
		flags |= BIT(MC_CMD_LINK_FLAGS_AUTONEG_EN);

	tech = efx_x4_link_tech(port_data, tech_mask, autoneg);

	rc = efx_x4_mcdi_link_ctrl(efx, efx->loopback_mode, flags,
				   tech_mask, pause, fec, tech, 0);
	if (rc)
		return rc;

	/* Record the new FEC setting for subsequent set_link calls */
	efx->fec_config = fecparam->fec;

	return 0;
}

/* Restart autonegotiation */
int efx_x4_mcdi_nway_reset(struct efx_nic *efx)
{
	DECLARE_BITMAP(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH) = {};
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	bool autoneg = false;
	u8 fec, pause = 0;
	u32 flags;
	u16 tech;
	int rc;

	flags = BIT(MC_CMD_LINK_FLAGS_IGNORE_MODULE_SEQ);
	ethtool_linkset_to_x4_mcdi(efx->link_advertising, tech_mask,
				   &pause, &autoneg);
	if (autoneg)
		flags |= BIT(MC_CMD_LINK_FLAGS_AUTONEG_EN);

	tech = efx_x4_link_tech(port_data, tech_mask, autoneg);
	fec = ethtool_fec_to_x4_mcdi(port_data->supported.fec,
				     efx->fec_config);

	flags |= BIT(MC_CMD_LINK_FLAGS_LINK_DISABLE);
	rc = efx_x4_mcdi_link_ctrl(efx, efx->loopback_mode, flags,
				   tech_mask, pause, fec, tech, 0);
	if (rc)
		return rc;

	flags &= ~BIT(MC_CMD_LINK_FLAGS_LINK_DISABLE);
	return efx_x4_mcdi_link_ctrl(efx, efx->loopback_mode, flags,
				     tech_mask, pause, fec, tech, 0);
}

int efx_x4_mcdi_enable_netport_events(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_NETPORT_EVENTS_MASK);

	BUILD_BUG_ON(MC_CMD_SET_NETPORT_EVENTS_MASK_OUT_LEN != 0);

	MCDI_SET_DWORD(inbuf, SET_NETPORT_EVENTS_MASK_IN_PORT_HANDLE,
		       efx->port_handle);
	MCDI_SET_DWORD(inbuf, SET_NETPORT_EVENTS_MASK_IN_EVENT_MASK,
		       BIT(EVENT_MASK_PORT_LINKCHANGE) |
		       BIT(EVENT_MASK_PORT_MODULECHANGE));

	return efx_mcdi_rpc(efx, MC_CMD_SET_NETPORT_EVENTS_MASK,
			    inbuf, sizeof(inbuf), NULL, 0, NULL);
}

void efx_x4_mcdi_process_link_change(struct efx_nic *efx, efx_qword_t *ev)
{
	u32 handle, seq_num, link_up;

	if (!efx_nic_port_handle_supported(efx)) {
		netif_dbg(efx, link, efx->net_dev,
			  "PORT_LINKCHANGE event ignored\n");
		return;
	}

	handle = EFX_QWORD_FIELD(*ev, MCDI_EVENT_PORT_LINKCHANGE_PORT_HANDLE);
	seq_num = EFX_QWORD_FIELD(*ev, MCDI_EVENT_PORT_LINKCHANGE_SEQ_NUM);
	link_up = EFX_QWORD_FIELD(*ev, MCDI_EVENT_PORT_LINKCHANGE_LINK_UP);

	netif_dbg(efx, link, efx->net_dev,
		  "PORT_LINKCHANGE event: handle=%d seq_num=%d link %s\n",
		  handle, seq_num, link_up ? "UP" : "DOWN");

	if (handle != efx->port_handle)
		return;

	/* Schedule work to poll for full link state details */
	schedule_work(&efx->link_change_work);
}

/* Check if changed module supports advertised abilities */
void efx_x4_check_module_caps(struct efx_nic *efx)
{
	struct efx_x4_mcdi_port_data *port_data = efx->port_data;
	DECLARE_BITMAP(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);
	u8 fec, pause;
	bool autoneg;
	u32 flags;
	u16 tech;
	int rc;

	/* Get transceiver properties (if attached) */
	rc = efx_x4_mcdi_transceiver_props(efx, port_data);
	if (rc)
		return;

	/* Check if module supports advertised abilities */
	ethtool_linkset_to_x4_mcdi(efx->link_advertising,
				   tech_mask, &pause, &autoneg);
	if (!autoneg)
		return; /* Fixed link configured */

	if (bitmap_intersects(tech_mask, port_data->supported.tech_mask,
			      MC_CMD_ETH_TECH_TECH_WIDTH))
		return; /* Supports some advertised link speeds */

	/* No overlap. Reset config to all supported speeds */
	bitmap_or(tech_mask, tech_mask, port_data->supported.tech_mask,
		  MC_CMD_ETH_TECH_TECH_WIDTH);

	/* Set new link mode */
	flags = BIT(MC_CMD_LINK_FLAGS_AUTONEG_EN);
	tech = efx_x4_link_tech(port_data, tech_mask, autoneg);
	fec = ethtool_fec_to_x4_mcdi(port_data->supported.fec,
				     efx->fec_config);
	rc = efx_x4_mcdi_link_ctrl(efx, efx->loopback_mode, flags,
				   tech_mask, pause, fec, tech,
				   port_data->link.module_seq);
	if (rc)
		return;

	/* Refresh link state again after setting new link mode */
	(void)efx_x4_mcdi_phy_poll(efx);

	/* Update advertised abilities */
	x4_mcdi_to_ethtool_linkset(efx, autoneg,
				   port_data->advertised.tech_mask,
				   port_data->advertised.pause,
				   efx->link_advertising);
}

void efx_x4_mcdi_process_module_change(struct efx_nic *efx, efx_qword_t *ev)
{
	u32 handle, seq_num, present;

	if (!efx_nic_port_handle_supported(efx)) {
		netif_dbg(efx, link, efx->net_dev,
			  "PORT_MODULECHANGE event ignored\n");
		return;
	}

	handle = EFX_QWORD_FIELD(*ev,
				 MCDI_EVENT_PORT_MODULECHANGE_PORT_HANDLE);
	seq_num = EFX_QWORD_FIELD(*ev, MCDI_EVENT_PORT_MODULECHANGE_SEQ_NUM);
	present = EFX_QWORD_FIELD(*ev,
				  MCDI_EVENT_PORT_MODULECHANGE_MDI_CONNECTED);

	netif_dbg(efx, link, efx->net_dev,
		  "Event PORT_MODULECHANGE: handle=%d seq_num=%d module %s\n",
		  handle, seq_num, present ? "INSERTED" : "REMOVED");

	/* Schedule work to poll for full module/link state details */
	atomic_set(&efx->module_changed, 1);
	schedule_work(&efx->link_change_work);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_EEPROM_BY_PAGE)
int efx_mcdi_x4_get_module_data(struct efx_nic *efx,
				const struct ethtool_module_eeprom *page,
				struct netlink_ext_ack *extack)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_MODULE_DATA_IN_V2_LEN);
	efx_dword_t *outbuf;
	size_t outlen;
	u32 datalen;
	int rc;

	outbuf = kzalloc(MC_CMD_GET_MODULE_DATA_OUT_LENMAX_MCDI2, GFP_KERNEL);
	if (!outbuf)
		return -ENOMEM;

	MCDI_SET_DWORD(inbuf, GET_MODULE_DATA_IN_V2_PORT_HANDLE,
		       efx->port_handle);
	MCDI_STRUCT_POPULATE_BYTE_1(inbuf,
				    MC_CMD_GET_MODULE_DATA_IN_V2_ADDRESSING,
				    MC_CMD_GET_MODULE_DATA_IN_V2_MODULE_ADDR,
				    page->i2c_address);
	MCDI_SET_WORD(inbuf, GET_MODULE_DATA_IN_V2_BANK, page->bank);
	MCDI_SET_WORD(inbuf, GET_MODULE_DATA_IN_V2_PAGE, page->page);
	MCDI_SET_BYTE(inbuf, GET_MODULE_DATA_IN_V2_OFFSET, page->offset);
	MCDI_SET_DWORD(inbuf, GET_MODULE_DATA_IN_V2_LENGTH, page->length);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_MODULE_DATA, inbuf, sizeof(inbuf),
			  outbuf, MC_CMD_GET_MODULE_DATA_OUT_LENMAX_MCDI2,
			  &outlen);
	if (rc)
		goto fail;
	if (outlen < MC_CMD_GET_MODULE_DATA_OUT_LENMIN) {
		rc = -EIO;
		goto fail;
	}
	datalen = MCDI_DWORD(outbuf, GET_MODULE_DATA_OUT_DATALEN);
	if (outlen < datalen + MC_CMD_GET_MODULE_DATA_OUT_DATA_OFST) {
		rc = -EIO;
		goto fail;
	}
	memcpy(page->data, MCDI_PTR(outbuf, GET_MODULE_DATA_OUT_DATA),
	       min(page->length, datalen));

fail:
	kfree(outbuf);
	return rc;
}
#endif
