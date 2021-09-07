/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_WORKAROUNDS_H
#define EFX_WORKAROUNDS_H

/*
 * Hardware workarounds.
 * Bug numbers are from Solarflare's Bugzilla.
 */

#define EFX_WORKAROUND_EF10(efx) (efx_nic_rev(efx) >= EFX_REV_HUNT_A0)

/* Lockup when writing event block registers at gen2/gen3 */
#define EFX_EF10_WORKAROUND_35388(efx)					\
	((struct efx_ef10_nic_data *)efx->nic_data)->workaround_35388
#define EFX_WORKAROUND_35388(efx)					\
	(efx_nic_rev(efx) == EFX_REV_HUNT_A0 && EFX_EF10_WORKAROUND_35388(efx))

#ifdef EFX_NOT_UPSTREAM
/* RX doorbell seems to go AWOL on Stratus machines during breaker tests */
#define EFX_WORKAROUND_59975(efx) 0
/* Driverlink probe can take >1 sec to perform license challenge */
#define EFX_WORKAROUND_62649 defined
/* MTD can leave a bad usecount */
#define EFX_WORKAROUND_63680
#endif

#define EFX_WORKAROUND_87308 1

/* Moderation timer access must go through MCDI */
#define EFX_EF10_WORKAROUND_61265(efx)					\
	((struct efx_ef10_nic_data *)efx->nic_data)->workaround_61265

#endif /* EFX_WORKAROUNDS_H */
