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

/* Forward declaration needed by nic.h for efx.h */
struct efx_rep;

#include "net_driver.h"
#include "nic.h"
#include "tc.h"

int efx_ef100_vfrep_create(struct efx_nic *efx, unsigned int i);
int efx_ef100_remote_rep_create(struct efx_nic *efx, unsigned int i,
				unsigned int mport_desc_idx);
void efx_ef100_vfrep_destroy(struct efx_nic *efx, unsigned int i);
void efx_ef100_remote_rep_destroy(struct efx_nic *efx, unsigned int i);

/* Returns the representor netdevice corresponding to a VF m-port, or NULL
 * @mport is an m-port label, *not* an m-port ID!
 */
struct net_device *efx_ef100_find_rep_by_mport(struct efx_nic *efx, u16 mport);

struct efx_rep_sw_stats {
	atomic64_t rx_packets, tx_packets;
	atomic64_t rx_bytes, tx_bytes;
	atomic64_t rx_dropped, tx_errors;
};

/* Private data for an Efx representor */
struct efx_rep {
	struct efx_nic *parent;
	struct net_device *net_dev;
	bool remote; /* flag to indicate remote rep */
	u32 msg_enable;
	u32 mport; /* m-port ID of corresponding PF/VF */
	u32 clid; /* client ID of corresponding PF/VF */
	unsigned int idx; /* rep index  */
	unsigned int write_index, read_index;
	unsigned int rx_pring_size; /* max length of RX list */
	unsigned int mport_desc_idx;
	struct efx_tc_flow_rule dflt; /* default-rule for switching */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	struct list_head rx_list;
#else
	struct sk_buff_head rx_list;
#endif
	spinlock_t rx_lock;
	struct napi_struct napi;
	struct efx_rep_sw_stats stats;
};

void efx_ef100_rep_rx_packet(struct efx_rep *efv, struct efx_rx_buffer *rx_buf);
extern const struct net_device_ops efx_ef100_rep_netdev_ops;
#endif /* EF10_REP_H */
