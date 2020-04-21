/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

/* Handling for ef100 representor netdevs */
#ifndef EF100_REP_H
#define EF100_REP_H

#include "net_driver.h"
#include "nic.h"

int efx_ef100_vfrep_create(struct efx_nic *efx, unsigned int i);
void efx_ef100_vfrep_destroy(struct efx_nic *efx, unsigned int i);

/* Returns the representor netdevice owning a dynamic m-port, or NULL */
struct net_device *efx_ef100_find_vfrep_by_mport(struct efx_nic *efx, u16 mport);

struct efx_vfrep_sw_stats {
	atomic_t rx_packets, tx_packets;
	atomic_t rx_bytes, tx_bytes;
	atomic_t rx_dropped, tx_errors;
};

/* Private data for an Efx representor */
struct efx_vfrep {
	struct efx_nic *parent;
	struct net_device *net_dev;
	u32 msg_enable;
	u32 mport_id;
	u32 mport_label;
	unsigned int vf_idx;
	unsigned int write_index, read_index;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	struct list_head rx_list;
#else
	struct sk_buff_head rx_list;
#endif
	spinlock_t rx_lock;
	struct napi_struct napi;
	struct efx_vfrep_sw_stats stats;
};

void efx_ef100_vfrep_rx_packet(struct efx_vfrep *efv, struct efx_rx_buffer *rx_buf);

extern const struct net_device_ops efx_ef100_vfrep_netdev_ops;
#endif /* EF10_REP_H */
