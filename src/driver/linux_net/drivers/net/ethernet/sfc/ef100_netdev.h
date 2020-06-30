/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#ifndef EFX_EF100_NETDEV_H
#define EFX_EF100_NETDEV_H

#include <linux/netdevice.h>
#include "ef100_nic.h"
#include "ef100_rep.h"

int ef100_netdev_event(struct notifier_block *this,
		       unsigned long event, void *ptr);
int ef100_netevent_event(struct notifier_block *this,
			 unsigned long event, void *ptr);
netdev_tx_t __ef100_hard_start_xmit(struct sk_buff *skb,
				    struct net_device *net_dev,
				    struct efx_vfrep *efv);
void ef100_start_reps(struct efx_nic *efx);
void ef100_stop_reps(struct efx_nic *efx);
int ef100_probe_netdev(struct efx_probe_data *probe_data);
void ef100_remove_netdev(struct efx_probe_data *probe_data);

#endif	/* EFX_EF100_NETDEV_H */
