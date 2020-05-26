/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

void efx_ioctl_mcdi_complete_reset(struct efx_nic *efx, unsigned int cmd,
				   int rc);
#ifndef EFX_FOR_UPSTREAM
/* The API below is used by sfctool */
int efx_ioctl_rxnfc(struct efx_nic *efx, void __user *useraddr);
#endif

int efx_private_ioctl_common(struct efx_nic *efx, u16 cmd,
			     union efx_ioctl_data __user *user_data);
