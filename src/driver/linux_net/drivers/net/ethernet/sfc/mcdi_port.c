/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2009-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

/*
 * Driver for PHY related operations via MCDI.
 */

#include <linux/slab.h>
#ifdef CONFIG_SFC_DEBUGFS
#include <linux/seq_file.h>
#endif
#include "efx.h"
#include "debugfs.h"
#include "nic.h"
#include "efx_common.h"
#include "selftest.h"
#include "mcdi_port_common.h"

static void efx_mcdi_fwalert_event(struct efx_nic *efx, efx_qword_t *ev)
{
	unsigned int reason, data;

	reason = EFX_QWORD_FIELD(*ev, MCDI_EVENT_FWALERT_REASON);
	data = EFX_QWORD_FIELD(*ev, MCDI_EVENT_FWALERT_DATA);

	switch (reason) {
	case MCDI_EVENT_FWALERT_REASON_SRAM_ACCESS:
		netif_err(efx, hw, efx->net_dev,
			  "Error - controller firmware has detected a write"
			  " to an illegal SRAM address\n");
		break;
	default:
		netif_err(efx, hw, efx->net_dev,
			  "Firmware alert reason %u: 0x%x\n", reason, data);
	}
}

bool efx_mcdi_port_process_event(struct efx_channel *channel, efx_qword_t *event,
				 int *rc, int budget)
{
	struct efx_nic *efx = channel->efx;
	int code = EFX_QWORD_FIELD(*event, MCDI_EVENT_CODE);

	switch (code) {
	case MCDI_EVENT_CODE_MAC_STATS_DMA:
		/* MAC stats are gather lazily.  We can ignore this. */
		return true;
	case MCDI_EVENT_CODE_FWALERT:
		efx_mcdi_fwalert_event(efx, event);
		return true;
	case MCDI_EVENT_CODE_TX_ERR:
	case MCDI_EVENT_CODE_RX_ERR:
		netif_err(efx, hw, efx->net_dev,
			  "%s DMA error (event: "EFX_QWORD_FMT")\n",
			  code == MCDI_EVENT_CODE_TX_ERR ? "TX" : "RX",
			  EFX_QWORD_VAL(*event));
		efx_schedule_reset(efx, RESET_TYPE_DMA_ERROR);
		return true;
	case MCDI_EVENT_CODE_FLR:
		if (efx->type->sriov_flr)
			efx->type->sriov_flr(efx,
					     MCDI_EVENT_FIELD(*event, FLR_VF));
		return true;
	case MCDI_EVENT_CODE_PTP_RX:
	case MCDI_EVENT_CODE_PTP_FAULT:
	case MCDI_EVENT_CODE_PTP_PPS:
	case MCDI_EVENT_CODE_HW_PPS:
		efx_ptp_event(efx, event);
		return true;
	case MCDI_EVENT_CODE_PTP_TIME:
		efx_time_sync_event(channel, event);
		return true;
	}

	return false;
}

#ifdef CONFIG_SFC_DEBUGFS

/* DMA all of the phy statistics, and return a single statistic out of the block.
 * Means we can't view a snapshot of all the statistics, but they're not
 * populated in zero time anyway */
static int efx_mcdi_phy_stats_read(struct seq_file *file, void *data)
{
	u8 pos = *((u8 *)data);
	struct efx_mcdi_phy_data *phy_data =
		container_of(data, struct efx_mcdi_phy_data, index[pos]);
	struct efx_nic *efx = phy_data->efx;
	efx_dword_t *value;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PHY_STATS_IN_LEN);
	int rc;

	MCDI_SET_QWORD(inbuf, PHY_STATS_IN_DMA_ADDR, phy_data->stats_addr);
	BUILD_BUG_ON(MC_CMD_PHY_STATS_OUT_DMA_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_PHY_STATS, inbuf, MC_CMD_PHY_STATS_IN_LEN,
			  NULL, 0, NULL);
	if (rc)
		return rc;

	value = (efx_dword_t *)phy_data->stats + pos;

	seq_printf(file, "%d\n", EFX_DWORD_FIELD(*value, EFX_DWORD_0));
	return 0;
}

#define PHY_STAT_PARAMETER(_index, _name)				\
	[_index] = EFX_NAMED_PARAMETER(_name,				\
				       struct efx_mcdi_phy_data,	\
				       index[_index], u8,		\
				       efx_mcdi_phy_stats_read)

static struct efx_debugfs_parameter debug_entries[] = {
	PHY_STAT_PARAMETER(MC_CMD_OUI, oui),
	PHY_STAT_PARAMETER(MC_CMD_PMA_PMD_LINK_UP, pma_pmd_link_up),
	PHY_STAT_PARAMETER(MC_CMD_PMA_PMD_RX_FAULT, pma_pmd_rx_fault),
	PHY_STAT_PARAMETER(MC_CMD_PMA_PMD_TX_FAULT, pma_pmd_tx_fault),
	PHY_STAT_PARAMETER(MC_CMD_PMA_PMD_SIGNAL, pma_pmd_signal),
	PHY_STAT_PARAMETER(MC_CMD_PMA_PMD_SNR_A, pma_pmd_snr_a),
	PHY_STAT_PARAMETER(MC_CMD_PMA_PMD_SNR_B, pma_pmd_snr_b),
	PHY_STAT_PARAMETER(MC_CMD_PMA_PMD_SNR_C, pma_pmd_snr_c),
	PHY_STAT_PARAMETER(MC_CMD_PMA_PMD_SNR_D, pma_pmd_snr_d),
	PHY_STAT_PARAMETER(MC_CMD_PCS_LINK_UP, pcs_link_up),
	PHY_STAT_PARAMETER(MC_CMD_PCS_RX_FAULT, pcs_rx_fault),
	PHY_STAT_PARAMETER(MC_CMD_PCS_TX_FAULT, pcs_tx_fault),
	PHY_STAT_PARAMETER(MC_CMD_PCS_BER, pcs_ber),
	PHY_STAT_PARAMETER(MC_CMD_PCS_BLOCK_ERRORS, pcs_block_errors),
	PHY_STAT_PARAMETER(MC_CMD_PHYXS_LINK_UP, phyxs_link_up),
	PHY_STAT_PARAMETER(MC_CMD_PHYXS_RX_FAULT, phxys_rx_fault),
	PHY_STAT_PARAMETER(MC_CMD_PHYXS_TX_FAULT, phyxs_tx_fault),
	PHY_STAT_PARAMETER(MC_CMD_PHYXS_ALIGN, phyxs_align),
	PHY_STAT_PARAMETER(MC_CMD_PHYXS_SYNC, phyxs_sync),
	PHY_STAT_PARAMETER(MC_CMD_AN_LINK_UP, an_link_up),
	PHY_STAT_PARAMETER(MC_CMD_AN_COMPLETE, an_complete),
	PHY_STAT_PARAMETER(MC_CMD_AN_10GBT_STATUS, an_10gbt_status),
	PHY_STAT_PARAMETER(MC_CMD_CL22_LINK_UP, cl22_link_up),
	{NULL},
};

static int efx_mcdi_phy_stats_init(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_data = efx->phy_data;
	int pos, rc;

	/* debug_entries[] must be contiguous */
	BUILD_BUG_ON(ARRAY_SIZE(debug_entries) != MC_CMD_PHY_NSTATS + 1);

	/* Allocata a DMA buffer for phy stats */
	phy_data->stats = pci_alloc_consistent(efx->pci_dev, EFX_PAGE_SIZE,
					       &phy_data->stats_addr);
	if (phy_data->stats == NULL)
		return -ENOMEM;

	phy_data->efx = efx;
	for (pos = 0; pos < MC_CMD_PHY_NSTATS; ++pos)
		phy_data->index[pos] = pos;
	rc = efx_extend_debugfs_port(efx, phy_data, ~phy_data->stats_mask,
				     debug_entries);
	if (rc < 0)
		goto fail;

	return 0;

fail:
	pci_free_consistent(efx->pci_dev, EFX_PAGE_SIZE, phy_data->stats,
			    phy_data->stats_addr);

	return rc;
}

static void efx_mcdi_phy_stats_fini(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_data = efx->phy_data;

	efx_trim_debugfs_port(efx, debug_entries);
	if (phy_data)
		pci_free_consistent(efx->pci_dev, EFX_PAGE_SIZE,
				    phy_data->stats, phy_data->stats_addr);
}

#endif

static int efx_mcdi_mdio_read(struct net_device *net_dev,
			      int prtad, int devad, u16 addr)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MDIO_READ_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MDIO_READ_OUT_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MDIO_READ_IN_BUS, efx->mdio_bus);
	MCDI_SET_DWORD(inbuf, MDIO_READ_IN_PRTAD, prtad);
	MCDI_SET_DWORD(inbuf, MDIO_READ_IN_DEVAD, devad);
	MCDI_SET_DWORD(inbuf, MDIO_READ_IN_ADDR, addr);

	rc = efx_mcdi_rpc(efx, MC_CMD_MDIO_READ, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;

	if (MCDI_DWORD(outbuf, MDIO_READ_OUT_STATUS) !=
	    MC_CMD_MDIO_STATUS_GOOD)
		return -EIO;

	return (u16)MCDI_DWORD(outbuf, MDIO_READ_OUT_VALUE);
}

static int efx_mcdi_mdio_write(struct net_device *net_dev,
			       int prtad, int devad, u16 addr, u16 value)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MDIO_WRITE_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MDIO_WRITE_OUT_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MDIO_WRITE_IN_BUS, efx->mdio_bus);
	MCDI_SET_DWORD(inbuf, MDIO_WRITE_IN_PRTAD, prtad);
	MCDI_SET_DWORD(inbuf, MDIO_WRITE_IN_DEVAD, devad);
	MCDI_SET_DWORD(inbuf, MDIO_WRITE_IN_ADDR, addr);
	MCDI_SET_DWORD(inbuf, MDIO_WRITE_IN_VALUE, value);

	rc = efx_mcdi_rpc(efx, MC_CMD_MDIO_WRITE, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;

	if (MCDI_DWORD(outbuf, MDIO_WRITE_OUT_STATUS) !=
	    MC_CMD_MDIO_STATUS_GOOD)
		return -EIO;

	return 0;
}

static int efx_mcdi_phy_probe(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_data;
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_LINK_OUT_LEN);
	u32 caps, ld_caps, lp_caps;
	int rc;

	/* Initialise and populate phy_data */
	phy_data = kzalloc(sizeof(*phy_data), GFP_KERNEL);
	if (phy_data == NULL)
		return -ENOMEM;

	rc = efx_mcdi_get_phy_cfg(efx, phy_data);
	if (rc != 0)
		goto fail;

	/* Read initial link advertisement */
	BUILD_BUG_ON(MC_CMD_GET_LINK_IN_LEN != 0);
	rc = efx_mcdi_rpc(efx, MC_CMD_GET_LINK, NULL, 0,
			  outbuf, sizeof(outbuf), NULL);
	if (rc)
		goto fail;
	/* Fill out nic state */
	efx->phy_data = phy_data;
	efx->phy_type = phy_data->type;
	strlcpy(efx->phy_name, phy_data->name, sizeof(efx->phy_name));

	efx->mdio_bus = phy_data->channel;
	efx->mdio.prtad = phy_data->port;
	efx->mdio.mmds = phy_data->mmd_mask & ~(1 << MC_CMD_MMD_CLAUSE22);
	efx->mdio.mode_support = 0;
	if (phy_data->mmd_mask & (1 << MC_CMD_MMD_CLAUSE22))
		efx->mdio.mode_support |= MDIO_SUPPORTS_C22;
	if (phy_data->mmd_mask & ~(1 << MC_CMD_MMD_CLAUSE22))
		efx->mdio.mode_support |= MDIO_SUPPORTS_C45 | MDIO_EMULATE_C22;

	caps = ld_caps = lp_caps = MCDI_DWORD(outbuf, GET_LINK_OUT_CAP);
#ifdef EFX_NOT_UPSTREAM
	/* If the link isn't advertising any speeds this is almost certainly
	 * due to an in-distro driver bug, which can have an effect if loaded
	 * before this out-of-tree driver. It is fixed upstream in:
	 * 3497ed8c852a ("sfc: report supported link speeds on SFP connections")
	 *
	 * Unfortunately this fix is not in a number of released distro kernels.
	 * In particular:
	 *   RHEL 6.8, kernel 2.6.32-642.el6 (fixed in 2.6.32-642.13.1.el6)
	 *   SLES 12 sp2, kernel 4.4.21-68-default
	 *
	 * If no speeds are marked as supported by the link we add all those
	 * that are supported by the NIC.
	 */
	if (!(caps & MCDI_PORT_SPEED_CAPS))
		caps |= phy_data->supported_cap & MCDI_PORT_SPEED_CAPS;
#endif
	mcdi_to_ethtool_linkset(efx, phy_data->media, caps,
				efx->link_advertising);

	/* Assert that we can map efx -> mcdi loopback modes */
	BUILD_BUG_ON(LOOPBACK_NONE != MC_CMD_LOOPBACK_NONE);
	BUILD_BUG_ON(LOOPBACK_DATA != MC_CMD_LOOPBACK_DATA);
	BUILD_BUG_ON(LOOPBACK_GMAC != MC_CMD_LOOPBACK_GMAC);
	BUILD_BUG_ON(LOOPBACK_XGMII != MC_CMD_LOOPBACK_XGMII);
	BUILD_BUG_ON(LOOPBACK_XGXS != MC_CMD_LOOPBACK_XGXS);
	BUILD_BUG_ON(LOOPBACK_XAUI != MC_CMD_LOOPBACK_XAUI);
	BUILD_BUG_ON(LOOPBACK_GMII != MC_CMD_LOOPBACK_GMII);
	BUILD_BUG_ON(LOOPBACK_SGMII != MC_CMD_LOOPBACK_SGMII);
	BUILD_BUG_ON(LOOPBACK_XGBR != MC_CMD_LOOPBACK_XGBR);
	BUILD_BUG_ON(LOOPBACK_XFI != MC_CMD_LOOPBACK_XFI);
	BUILD_BUG_ON(LOOPBACK_XAUI_FAR != MC_CMD_LOOPBACK_XAUI_FAR);
	BUILD_BUG_ON(LOOPBACK_GMII_FAR != MC_CMD_LOOPBACK_GMII_FAR);
	BUILD_BUG_ON(LOOPBACK_SGMII_FAR != MC_CMD_LOOPBACK_SGMII_FAR);
	BUILD_BUG_ON(LOOPBACK_XFI_FAR != MC_CMD_LOOPBACK_XFI_FAR);
	BUILD_BUG_ON(LOOPBACK_GPHY != MC_CMD_LOOPBACK_GPHY);
	BUILD_BUG_ON(LOOPBACK_PHYXS != MC_CMD_LOOPBACK_PHYXS);
	BUILD_BUG_ON(LOOPBACK_PCS != MC_CMD_LOOPBACK_PCS);
	BUILD_BUG_ON(LOOPBACK_PMAPMD != MC_CMD_LOOPBACK_PMAPMD);
	BUILD_BUG_ON(LOOPBACK_XPORT != MC_CMD_LOOPBACK_XPORT);
	BUILD_BUG_ON(LOOPBACK_XGMII_WS != MC_CMD_LOOPBACK_XGMII_WS);
	BUILD_BUG_ON(LOOPBACK_XAUI_WS != MC_CMD_LOOPBACK_XAUI_WS);
	BUILD_BUG_ON(LOOPBACK_XAUI_WS_FAR != MC_CMD_LOOPBACK_XAUI_WS_FAR);
	BUILD_BUG_ON(LOOPBACK_XAUI_WS_NEAR != MC_CMD_LOOPBACK_XAUI_WS_NEAR);
	BUILD_BUG_ON(LOOPBACK_GMII_WS != MC_CMD_LOOPBACK_GMII_WS);
	BUILD_BUG_ON(LOOPBACK_XFI_WS != MC_CMD_LOOPBACK_XFI_WS);
	BUILD_BUG_ON(LOOPBACK_XFI_WS_FAR != MC_CMD_LOOPBACK_XFI_WS_FAR);
	BUILD_BUG_ON(LOOPBACK_PHYXS_WS != MC_CMD_LOOPBACK_PHYXS_WS);

	rc = efx_mcdi_loopback_modes(efx, &efx->loopback_modes);
	if (rc != 0)
		goto fail;
	/* The MC indicates that LOOPBACK_NONE is a valid loopback mode,
	 * but by convention we don't */
	efx->loopback_modes &= ~(1 << LOOPBACK_NONE);

	/* Set the initial link mode */
	efx_mcdi_phy_decode_link(
		efx, &efx->link_state,
		MCDI_DWORD(outbuf, GET_LINK_OUT_LINK_SPEED),
		MCDI_DWORD(outbuf, GET_LINK_OUT_FLAGS),
		MCDI_DWORD(outbuf, GET_LINK_OUT_FCNTL),
		ld_caps, lp_caps);

	efx->fec_config = mcdi_fec_caps_to_ethtool(caps,
						   efx->link_state.speed == 25000 ||
						   efx->link_state.speed == 50000);

	/* Default to Autonegotiated flow control if the PHY supports it */
	efx->wanted_fc = EFX_FC_RX | EFX_FC_TX;
	if (phy_data->supported_cap & (1 << MC_CMD_PHY_CAP_AN_LBN))
		efx->wanted_fc |= EFX_FC_AUTO;
	efx_link_set_wanted_fc(efx, efx->wanted_fc);

#ifdef CONFIG_SFC_DEBUGFS
	rc = efx_mcdi_phy_stats_init(efx);
	if (rc != 0)
		goto fail;
#endif

	return 0;

fail:
	kfree(phy_data);
	return rc;
}

static void efx_mcdi_phy_remove(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_data = efx->phy_data;

#ifdef CONFIG_SFC_DEBUGFS
	efx_mcdi_phy_stats_fini(efx);
#endif
	efx->phy_data = NULL;
	kfree(phy_data);
}

u32 efx_mcdi_phy_get_caps(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_data = efx->phy_data;

	return phy_data->supported_cap;
}

bool efx_mcdi_mac_check_fault(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_LINK_OUT_LEN);
	size_t outlength;
	int rc;

	BUILD_BUG_ON(MC_CMD_GET_LINK_IN_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_LINK, NULL, 0,
			  outbuf, sizeof(outbuf), &outlength);
	if (rc)
		return true;

	return MCDI_DWORD(outbuf, GET_LINK_OUT_MAC_FAULT) != 0;
}

int efx_mcdi_port_probe(struct efx_nic *efx)
{
	int rc;

	/* Set up MDIO structure for PHY */
	efx->mdio.mode_support = MDIO_SUPPORTS_C45 | MDIO_EMULATE_C22;
	efx->mdio.mdio_read = efx_mcdi_mdio_read;
	efx->mdio.mdio_write = efx_mcdi_mdio_write;

	/* Fill out MDIO structure, loopback modes, and initial link state */
	rc = efx_mcdi_phy_probe(efx);

	if (rc)
		return rc;

	return efx_mcdi_mac_init_stats(efx);
}

void efx_mcdi_port_remove(struct efx_nic *efx)
{
	efx_mcdi_port_reconfigure(efx);
	efx_mcdi_phy_remove(efx);
	efx_mcdi_mac_fini_stats(efx);
}
