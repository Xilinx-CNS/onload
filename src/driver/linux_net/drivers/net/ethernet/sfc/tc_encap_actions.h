/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2022 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_TC_ENCAP_ACTIONS_H
#define EFX_TC_ENCAP_ACTIONS_H
#include "net_driver.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
#include <linux/refcount.h>
#include <net/tc_act/tc_tunnel_key.h>

/**
 * struct efx_neigh_binder - driver state for a neighbour entry
 * @net: the network namespace in which this neigh resides
 * @dst_ip: the IPv4 destination address resolved by this neigh
 * @dst_ip6: the IPv6 destination address resolved by this neigh
 * @ha: the hardware (Ethernet) address of the neighbour
 * @n_valid: true if the neighbour is in NUD_VALID state
 * @lock: protects @ha and @n_valid
 * @ttl: Time To Live associated with the route used
 * @dying: set when egdev is going away, to skip further updates
 * @egdev: egress device from the route lookup.  Holds a reference
 * @ref: counts encap actions referencing this entry
 * @used: jiffies of last time traffic hit any encap action using this.
 *      When counter reads update this, a new neighbour event is sent to
 *      indicate that the neighbour entry is still in use.
 * @users: list of &struct efx_tc_encap_action
 * @linkage: entry in efx->neigh_ht (keys are @net, @dst_ip, @dst_ip6).
 * @work: processes neighbour state changes, updates the encap actions
 * @efx: owning NIC instance.
 *
 * Associates a neighbour entry with the encap actions that are
 * interested in it, allowing the latter to be updated when the
 * neighbour details change.
 * Whichever of @dst_ip and @dst_ip6 is not in use will be all-zeroes,
 * this distinguishes IPv4 from IPv6 entries.
 */
struct efx_neigh_binder {
	struct net *net;
	__be32 dst_ip;
#ifdef CONFIG_IPV6
	struct in6_addr dst_ip6;
#endif
	char ha[ETH_ALEN];
	bool n_valid;
	rwlock_t lock;
	u8 ttl;
	bool dying;
	struct net_device *egdev;
	refcount_t ref;
	unsigned long used;
	struct list_head users;
	struct rhash_head linkage;
	struct work_struct work;
	struct efx_nic *efx;
};

#define EFX_TC_MAX_ENCAP_HDR	128 /* made-up for now, fw will decide */
struct efx_tc_encap_action {
	enum efx_encap_type type;
	struct ip_tunnel_key key; /* 52 bytes */
	u32 dest_mport; /* is copied into struct efx_tc_action_set */
	u8 encap_hdr_len;
	bool n_valid;
	u8 encap_hdr[EFX_TC_MAX_ENCAP_HDR];
	struct efx_neigh_binder *neigh;
	struct list_head list; /* entry on neigh->users list */
	struct list_head users; /* action sets using this encap_md */
	struct rhash_head linkage; /* efx->tc_encap_ht */
	refcount_t ref;
	u32 fw_id; /* index of this entry in firmware encap table */
};

/* create/uncreate/teardown hashtables */
int efx_tc_init_encap_actions(struct efx_nic *efx);
void efx_tc_destroy_encap_actions(struct efx_nic *efx);
void efx_tc_fini_encap_actions(struct efx_nic *efx);

struct efx_tc_flow_rule;
bool efx_tc_check_ready(struct efx_nic *efx, struct efx_tc_flow_rule *rule);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) || defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
void efx_tc_unregister_egdev(struct efx_nic *efx, struct net_device *net_dev);
#endif
struct efx_tc_encap_action *efx_tc_flower_create_encap_md(
			struct efx_nic *efx, const struct ip_tunnel_info *info,
			struct net_device *egdev, struct netlink_ext_ack *extack);
void efx_tc_flower_release_encap_md(struct efx_nic *efx,
				    struct efx_tc_encap_action *encap);
int efx_tc_netevent_event(struct efx_nic *efx, unsigned long event,
			  void *ptr);

#else /* EFX_TC_OFFLOAD */
static inline int efx_tc_netevent_event(struct efx_nic *efx,
					unsigned long event, void *ptr)
{
	return NOTIFY_OK;
}
#endif /* EFX_TC_OFFLOAD */

#endif /* EFX_TC_ENCAP_ACTIONS_H */
