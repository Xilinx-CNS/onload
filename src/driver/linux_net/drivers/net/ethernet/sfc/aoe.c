/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "aoe.h"

/* The expected reprogram time for the CPLD is about 22s
 * but allow for the board not being in turbo and add a small
 * overhead
 */
#define	CPLD_REPROGRAM_MS (60000)

/**
 * struct efx_aoe_data - AOE device node informatino
 * @read_data: Queue for handling API reads
 * @last_status: Last program status
 */
struct efx_aoe_data {
	wait_queue_head_t read_data;
	int last_status;
};

int efx_aoe_attach(struct efx_nic *efx)
{
	struct efx_aoe_data *aoe;

	aoe = kzalloc(sizeof(struct efx_aoe_data), GFP_KERNEL);
	efx->aoe_data = aoe;
	if (!efx->aoe_data)
		return -ENOMEM;

	init_waitqueue_head(&aoe->read_data);

	return	0;

}

void efx_aoe_detach(struct efx_nic *efx)
{
	kfree(efx->aoe_data);
	efx->aoe_data = NULL;
}

int efx_aoe_event(struct efx_nic *efx, efx_qword_t *event, int budget)
{
	int32_t aoe_code;
	struct efx_aoe_data *aoe = efx->aoe_data;

	if (!aoe)
		return -ENOENT;

	aoe_code = MCDI_EVENT_FIELD(*event, AOE_ERR_TYPE);
	if (aoe_code == MCDI_EVENT_AOE_CPLD_REPROGRAMMED) {

		aoe->last_status = MCDI_EVENT_FIELD(*event, AOE_ERR_DATA);
		if (waitqueue_active(&aoe->read_data))
			wake_up(&aoe->read_data);
	} else
		return efx_dl_handle_event(&efx->dl_nic, event, budget);

	return 0;
}

int efx_aoe_update_cpld(struct efx_nic *efx, struct efx_update_cpld *cpld)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_AOE_IN_CPLD_REPROGRAM_LEN);
	int rc;
	unsigned int err;
	struct efx_aoe_data *aoe = efx->aoe_data;

	if (!aoe)
		return -ENOSYS;

	MCDI_SET_DWORD(inbuf, AOE_IN_CMD, MC_CMD_AOE_OP_CPLD_REPROGRAM);
	MCDI_SET_DWORD(inbuf, AOE_IN_CPLD_REPROGRAM_OP,
			      MC_CMD_AOE_IN_CPLD_REPROGRAM_REPROGRAM_EVENT);

	aoe->last_status = -1;
	rc  = efx_mcdi_rpc(efx, MC_CMD_AOE, inbuf, sizeof(inbuf),
			NULL, 0, NULL);

	if (rc)
		return rc;

	err = wait_event_interruptible_timeout(efx->aoe_data->read_data,
				       -1 != aoe->last_status,
				       msecs_to_jiffies(CPLD_REPROGRAM_MS));
	if (err == 0)
		return -ETIMEDOUT;

	/* Check for pending signals */
	if (err == -ERESTARTSYS)
		return -EINTR;

	if (aoe->last_status != 0)
		return -EIO;

	return 0;
}

int efx_aoe_update_keys(struct efx_nic *efx,
			struct efx_update_license *key_stats)
{
	int rc;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FC_IN_LICENSE_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_FC_OUT_LICENSE_LEN);

	if (!efx->aoe_data)
		return -ENOSYS;

	/* 1. Request the FC to update the license keys */
	MCDI_SET_DWORD(inbuf, FC_IN_CMD, MC_CMD_FC_OP_LICENSE);
	MCDI_SET_DWORD(inbuf, FC_IN_LICENSE_OP,
		       MC_CMD_FC_IN_LICENSE_UPDATE_LICENSE);

	rc = efx_mcdi_rpc(efx, MC_CMD_FC, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);

	if (rc)
		return rc;

	/* 2. Obtain stats about the keys and return to the called */
	MCDI_SET_DWORD(inbuf, FC_IN_LICENSE_OP,
		       MC_CMD_FC_IN_LICENSE_GET_KEY_STATS);

	rc = efx_mcdi_rpc(efx, MC_CMD_FC, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), NULL);

	if (rc)
		return rc;

	key_stats->valid_keys = MCDI_DWORD(outbuf,
					   FC_OUT_LICENSE_VALID_KEYS);
	key_stats->invalid_keys = MCDI_DWORD(outbuf,
					     FC_OUT_LICENSE_INVALID_KEYS);
	key_stats->blacklisted_keys = MCDI_DWORD(outbuf,
						 FC_OUT_LICENSE_BLACKLISTED_KEYS);

	return 0;
}

int efx_aoe_reset_aoe(struct efx_nic *efx,
			struct efx_aoe_reset *reset_flags)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_AOE_IN_FC_LEN);
	int rc;
	struct efx_aoe_data *aoe = efx->aoe_data;

	if (!aoe)
		return -ENOSYS;

	MCDI_SET_DWORD(inbuf, AOE_IN_CMD, MC_CMD_AOE_OP_FC);

	rc  = efx_mcdi_rpc(efx, MC_CMD_AOE, inbuf, sizeof(inbuf),
			NULL, 0, NULL);

	return rc;
}

