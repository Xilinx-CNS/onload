/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Driver for Solarflare and Xilinx network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 * Copyright 2019-2020 Xilinx Inc.
 * Copyright 2020-2024, Advanced Micro Devices, Inc.
 */

#ifndef EFX_AUXBUS_INTERNAL_H
#define EFX_AUXBUS_INTERNAL_H

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_AUXILIARY_BUS
int efx_auxbus_add_dev(struct efx_client_type_data *client_type);
void efx_auxbus_del_dev(struct efx_client_type_data *client_type);
int efx_auxbus_send_events(struct efx_probe_data *pd,
			   struct efx_auxdev_event *event);
int efx_auxbus_send_poll_event(struct efx_probe_data *pd, int channel,
			       efx_qword_t *event, int budget);
#else
static inline int efx_auxbus_add_dev(struct efx_client_type_data *client_type)
{
	return 0;
}

static inline void efx_auxbus_del_dev(struct efx_client_type_data *client_type)
{
}

static inline int efx_auxbus_send_events(struct efx_probe_data *pd,
					 struct efx_auxdev_event *event)
{
	return 0;
}

static inline int efx_auxbus_send_poll_event(struct efx_probe_data *pd,
					     int channel, efx_qword_t *event,
					     int budget)
{
	return -ENODEV;
}
#endif
#endif	/* EFX_NOT_UPSTREAM */
#endif
