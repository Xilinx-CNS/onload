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
#include "efx.h"
#include "mcdi_port.h"
#include "nic.h"
#include "efx_common.h"
#include "selftest.h"
#include "mcdi_port_common.h"
#include "mcdi_port_handle.h"


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

bool efx_x4_mcdi_mac_check_fault(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAC_STATE_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAC_STATE_IN_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAC_STATE_IN_PORT_HANDLE, efx->port_handle);

	rc = efx_mcdi_rpc(efx, MC_CMD_MAC_STATE, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return true;

	return MCDI_DWORD(outbuf, MAC_STATE_OUT_MAC_FAULT_FLAGS) != 0;
}

int efx_mcdi_port_probe(struct efx_nic *efx)
{
	int rc;

	/* Fill out loopback modes and initial link state */
	rc = efx_mcdi_phy_probe(efx);

	if (rc)
		return rc;

	return efx_mcdi_mac_init_stats(efx);
}

void efx_mcdi_port_remove(struct efx_nic *efx)
{
	efx->type->reconfigure_port(efx);
	efx_mcdi_phy_remove(efx);
	efx_mcdi_mac_fini_stats(efx);
}

int efx_x4_mcdi_port_probe(struct efx_nic *efx)
{
	int rc;

	if (!efx_nic_port_handle_supported(efx))
		return efx_mcdi_port_probe(efx);

	/* Fill out loopback modes and initial link state */
	rc = efx_x4_mcdi_phy_probe(efx);
	if (rc)
		return rc;

	return efx_mcdi_mac_init_stats(efx);
}

void efx_x4_mcdi_port_remove(struct efx_nic *efx)
{
	if (!efx_nic_port_handle_supported(efx))
		return efx_mcdi_port_remove(efx);

	efx_x4_mcdi_port_reconfigure(efx);
	efx_x4_mcdi_phy_remove(efx);

	efx_mcdi_mac_fini_stats(efx);
}
