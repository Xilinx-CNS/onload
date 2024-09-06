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
void efx_onload_detach(struct efx_client_type_data *client_type);
void efx_onload_attach(struct efx_client_type_data *client_type);
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

static inline void efx_onload_detach(struct efx_client_type_data *client_type)
{
}

static inline void efx_onload_attach(struct efx_client_type_data *client_type)
{
}
#endif

/* These are used to delay client closure until event callbacks have completed.
 * Allow a delay up to 10 seconds.
 */
#define EFX_CLIENT_DELAY_MS	100
#define EFX_CLIENT_DELAY_COUNT	100

static inline void
efx_auxbus_wait_for_event_callbacks(struct efx_client_type_data *client_type)
{
#ifdef CONFIG_AUXILIARY_BUS
	int max_wait;

	for (max_wait = EFX_CLIENT_DELAY_COUNT;
	     max_wait && refcount_read(&client_type->in_callback) > 1;
	     max_wait--)
		msleep_interruptible(EFX_CLIENT_DELAY_MS);

	if (!max_wait)
		pci_warn(client_type->pd->pci_dev,
			 "Client close for %d was delayed\n",
			 client_type->type);
#endif
}
#endif	/* EFX_NOT_UPSTREAM */
#endif
