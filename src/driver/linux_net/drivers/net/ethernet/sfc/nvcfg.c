// SPDX-License-Identifier: GPL-2.0
/****************************************************************************
 * Driver for AMD Solarflare network controllers and boards
 * Copyright 2025 Advanced Micro Devices Inc.
 */

#include "nvcfg.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_DEVLINK_HEALTH_REPORTER)
#include "mcdi.h"

int efx_nvcfg_read(struct efx_nic *efx, struct efx_nvlog_data *nvlog_data,
		   u32 type)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_READ_CONFIGURATION_IN_LEN);
	efx_dword_t *outbuf;
	u32 offset = 0, gen;
	size_t outlen;
	int rc;

	outbuf = kzalloc(MC_CMD_READ_CONFIGURATION_OUT_LENMAX_MCDI2, GFP_KERNEL);
	if (!outbuf)
		return -ENOMEM;
	MCDI_SET_DWORD(inbuf, READ_CONFIGURATION_IN_TYPE, type);
	rc = efx_mcdi_rpc(efx, MC_CMD_READ_CONFIGURATION, inbuf, sizeof(inbuf),
			  outbuf, MC_CMD_READ_CONFIGURATION_OUT_LENMAX_MCDI2,
			  &outlen);
	if (rc)
		goto out_free;
	if (outlen < MC_CMD_READ_CONFIGURATION_OUT_LEN(0)) {
		rc = -EIO;
		goto out_free;
	}
	nvlog_data->nvlog_max_len = MCDI_DWORD(outbuf, READ_CONFIGURATION_OUT_LENGTH);
	/* +1 byte for trailing NUL added in efx_nvlog_to_devlink() */
	nvlog_data->nvlog = kmalloc(nvlog_data->nvlog_max_len + 1, GFP_KERNEL);
	nvlog_data->nvlog_len = 0;
	if (!nvlog_data->nvlog) {
		rc = -ENOMEM;
		goto out_free;
	}
	gen = MCDI_DWORD(outbuf, READ_CONFIGURATION_OUT_GENERATION);

	while (true) {
		u32 bytes = MC_CMD_READ_CONFIGURATION_OUT_DATA_NUM(outlen);
		char *ptr = nvlog_data->nvlog + offset;

		if (MCDI_DWORD(outbuf, READ_CONFIGURATION_OUT_GENERATION) != gen) {
			rc = -EAGAIN;
			goto out_free;
		}
		if (!bytes)
			break;
		if (offset + bytes > nvlog_data->nvlog_max_len) {
			/* shouldn't happen */
			rc = -ENOSPC;
			goto out_free;
		}
		memcpy(ptr, MCDI_PTR(outbuf, READ_CONFIGURATION_OUT_DATA),
		       bytes);
		offset += bytes;
		if (offset == nvlog_data->nvlog_max_len)
			break;
		MCDI_SET_DWORD(inbuf, READ_CONFIGURATION_IN_START_BYTE_OFFSET,
			       offset);
		rc = efx_mcdi_rpc(efx, MC_CMD_READ_CONFIGURATION, inbuf,
				  sizeof(inbuf), outbuf,
				  MC_CMD_READ_CONFIGURATION_OUT_LENMAX_MCDI2,
				  &outlen);
		if (rc)
			goto out_free;
		if (outlen < MC_CMD_READ_CONFIGURATION_OUT_LEN(0)) {
			rc = -EIO;
			goto out_free;
		}
	}

	nvlog_data->nvlog_len = offset;
	/* claim the extra byte for trailing NUL */
	nvlog_data->nvlog_max_len++;
out_free:
	kfree(outbuf);
	return rc;
}
#endif /* EFX_HAVE_DEVLINK_HEALTH_REPORTER */
