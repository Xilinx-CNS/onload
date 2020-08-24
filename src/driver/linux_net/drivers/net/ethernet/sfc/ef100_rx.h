/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_EF100_RX_H
#define EFX_EF100_RX_H

#include "net_driver.h"

int ef100_rx_init(struct efx_rx_queue *rx_queue);
void efx_ef100_ev_rx(struct efx_channel *channel, const efx_qword_t *p_event);
void ef100_rx_write(struct efx_rx_queue *rx_queue);

#endif
