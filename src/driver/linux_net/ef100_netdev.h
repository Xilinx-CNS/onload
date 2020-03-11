/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/netdevice.h>
#include "ef100_rep.h"

int ef100_netdev_event(struct notifier_block *this,
		       unsigned long event, void *ptr);
int ef100_netevent_event(struct notifier_block *this,
			 unsigned long event, void *ptr);
int ef100_register_netdev(struct efx_nic *efx);
void ef100_unregister_netdev(struct efx_nic *efx);
netdev_tx_t __ef100_hard_start_xmit(struct sk_buff *skb,
				    struct net_device *net_dev,
				    struct efx_vfrep *efv);
