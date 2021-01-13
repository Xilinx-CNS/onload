/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifdef EFX_USE_KCOMPAT
/* Must come before other headers */
#include "kernel_compat.h"
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_skbedit.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
#include <net/tc_act/tc_ct.h>
#endif
#include <net/vxlan.h>
#include <net/geneve.h>
#include <net/netevent.h>
#include <net/arp.h>
#include "tc.h"
#include "mae.h"
#include "mae_counter_format.h"
#include "ef100_rep.h"
#include "nic.h"
#include "rx_common.h"
#include "efx_common.h"
#include "debugfs.h"

/* Error reporting: convenience macros.  For indicating why a given filter
 * insertion is not supported; errors in internal operation or in the
 * hardware should be netif_err()s instead.
 */
/* Used when error message is constant, to ensure we get a message out even
 * if extack isn't available.
 */
#define EFX_TC_ERR_MSG(efx, extack, message)	do {			\
	if (extack)							\
		NL_SET_ERR_MSG_MOD(extack, message);			\
	if (efx->log_tc_errs || !extack)				\
		netif_info(efx, drv, efx->net_dev, "%s\n", message);	\
} while (0)
/* Used when error message is not constant; caller should also supply a
 * constant extack message with NL_SET_ERR_MSG_MOD().
 */
#define efx_tc_err(efx, fmt, args...)	do {		\
if (efx->log_tc_errs)					\
	netif_info(efx, drv, efx->net_dev, fmt, ##args);\
} while (0)

static enum efx_encap_type efx_tc_indr_netdev_type(struct net_device *net_dev)
{
	if (netif_is_vxlan(net_dev))
		return EFX_ENCAP_TYPE_VXLAN;
	if (netif_is_geneve(net_dev))
		return EFX_ENCAP_TYPE_GENEVE;

	return EFX_ENCAP_TYPE_NONE;
}

/* Lookup the (driver-internal) vport ID for a device — either the PF (us) or a
 * VF representor
 */
static int efx_tc_flower_lookup_dev(struct efx_nic *efx, struct net_device *dev)
{
	struct efx_rep *efv;

	if (!dev)
		return -EOPNOTSUPP;
	if (dev == efx->net_dev)
		return EFX_VPORT_PF;
	/* Is it an efx vfrep at all? */
	if (dev->netdev_ops != &efx_ef100_rep_netdev_ops)
		return -EOPNOTSUPP;
	/* Is it ours? */
	efv = netdev_priv(dev);
	if (efv->parent != efx)
		return -EOPNOTSUPP;
	if (!efv->remote)
		return EFX_VPORT_VF_OFFSET + efv->idx;
	return EFX_VPORT_REMOTE_OFFSET + efv->idx;
}

static long efx_tc_flower_rep_mport(struct efx_nic *efx, int vport_id)
{
	struct net_device *rep_dev;
	struct efx_rep *efv;
	u32 mport;

	if (vport_id < EFX_VPORT_VF_OFFSET) /* only repr vport_id allowed */
		return vport_id;
	if (vport_id >= EFX_VPORT_REMOTE_OFFSET)
		rep_dev = efx_get_remote_rep(efx, vport_id);
	else
		rep_dev = efx_get_vf_rep(efx, vport_id);

	efv = netdev_priv(rep_dev);
	efx_mae_mport_mport(efx, efv->mport, &mport);

	return mport;
}

/* Convert a driver-internal vport ID into an internal device (PF or VF) */
static long efx_tc_flower_internal_mport(struct efx_nic *efx, int vport_id)
{
	u32 mport;

	if (vport_id < 0) /* device isn't ours */
		return vport_id;
	if (vport_id) /* device is repr */
		mport = efx_tc_flower_rep_mport(efx, vport_id);
	else /* device is PF (us) */
		efx_mae_mport_uplink(efx, &mport);
	return mport;
}

/* Convert a driver-internal vport ID into an external device (wire or VF) */
static long efx_tc_flower_external_mport(struct efx_nic *efx, int vport_id)
{
	u32 mport;

	if (vport_id < 0) /* device isn't ours */
		return vport_id;
	if (vport_id) /* device is repr */
		mport = efx_tc_flower_rep_mport(efx, vport_id);
	else /* device is PF (us) */
		efx_mae_mport_wire(efx, &mport);
	return mport;
}

/**
 * struct efx_neigh_binder - driver state for a neighbour entry
 *
 * Associates a neighbour entry with the encap actions that are
 * interested in it, allowing the latter to be updated when the
 * neighbour details change.
 * Whichever of @dst_ip and @dst_ip6 is not in use will be all-zeroes,
 *	this distinguishes IPv4 from IPv6 entries.
 *
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
 */
struct efx_neigh_binder {
	struct net *net;
	__be32 dst_ip;
	struct in6_addr dst_ip6;
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

const static struct rhashtable_params efx_neigh_ht_params = {
	.key_len	= offsetof(struct efx_neigh_binder, ha),
	.key_offset	= 0,
	.head_offset	= offsetof(struct efx_neigh_binder, linkage),
};

const static struct rhashtable_params efx_tc_counter_id_ht_params = {
	.key_len	= offsetof(struct efx_tc_counter_index, linkage),
	.key_offset	= 0,
	.head_offset	= offsetof(struct efx_tc_counter_index, linkage),
};

const static struct rhashtable_params efx_tc_counter_ht_params = {
	.key_len	= offsetof(struct efx_tc_counter, linkage),
	.key_offset	= 0,
	.head_offset	= offsetof(struct efx_tc_counter, linkage),
};

const static struct rhashtable_params efx_tc_encap_ht_params = {
	.key_len	= offsetofend(struct efx_tc_encap_action, key),
	.key_offset	= 0,
	.head_offset	= offsetof(struct efx_tc_encap_action, linkage),
};

const static struct rhashtable_params efx_tc_encap_match_ht_params = {
	.key_len	= offsetof(struct efx_tc_encap_match, tun_type),
	.key_offset	= 0,
	.head_offset	= offsetof(struct efx_tc_encap_match, linkage),
};

const static struct rhashtable_params efx_tc_match_action_ht_params = {
	.key_len	= sizeof(unsigned long),
	.key_offset	= offsetof(struct efx_tc_flow_rule, cookie),
	.head_offset	= offsetof(struct efx_tc_flow_rule, linkage),
};

const static struct rhashtable_params efx_tc_lhs_rule_ht_params = {
	.key_len	= sizeof(unsigned long),
	.key_offset	= offsetof(struct efx_tc_lhs_rule, cookie),
	.head_offset	= offsetof(struct efx_tc_lhs_rule, linkage),
};

const static struct rhashtable_params efx_tc_ctr_agg_ht_params = {
	.key_len	= sizeof(unsigned long),
	.key_offset	= offsetof(struct efx_tc_ctr_agg, cookie),
	.head_offset	= offsetof(struct efx_tc_ctr_agg, linkage),
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
const static struct rhashtable_params efx_tc_ct_zone_ht_params = {
	.key_len	= offsetof(struct efx_tc_ct_zone, linkage),
	.key_offset	= 0,
	.head_offset	= offsetof(struct efx_tc_ct_zone, linkage),
};

const static struct rhashtable_params efx_tc_ct_ht_params = {
	.key_len	= offsetof(struct efx_tc_ct_entry, linkage),
	.key_offset	= 0,
	.head_offset	= offsetof(struct efx_tc_ct_entry, linkage),
};
#endif

const static struct rhashtable_params efx_tc_recirc_ht_params = {
	.key_len	= sizeof(u32),
	.key_offset	= offsetof(struct efx_tc_recirc_id, chain_index),
	.head_offset	= offsetof(struct efx_tc_recirc_id, linkage),
};

static void efx_tc_update_encap(struct efx_nic *efx,
				struct efx_tc_encap_action *encap);
static void efx_release_neigh(struct efx_nic *efx,
			      struct efx_tc_encap_action *encap);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) || defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
static void efx_tc_remove_neigh_users(struct efx_nic *efx, struct efx_neigh_binder *neigh)
{
	struct efx_tc_encap_action *encap, *next;

	list_for_each_entry_safe(encap, next, &neigh->users, list) {
		/* Should cause neigh usage count to fall to zero, freeing it */
		efx_release_neigh(efx, encap);
		/* The encap has lost its neigh, so it's now unready */
		efx_tc_update_encap(efx, encap);
	}
}

static void efx_tc_unregister_egdev(struct efx_nic *efx, struct net_device *net_dev)
{
	struct efx_neigh_binder *neigh;
	struct rhashtable_iter walk;

	mutex_lock(&efx->tc->mutex);
	rhashtable_walk_enter(&efx->tc->neigh_ht, &walk);
	rhashtable_walk_start(&walk);
	while ((neigh = rhashtable_walk_next(&walk)) != NULL) {
		if (IS_ERR(neigh))
			continue;
		if (neigh->egdev != net_dev)
			continue;
		neigh->dying = true;
		rhashtable_walk_stop(&walk);
		synchronize_rcu(); /* Make sure any updates see dying flag */
		efx_tc_remove_neigh_users(efx, neigh); /* might sleep */
		rhashtable_walk_start(&walk);
	}
	rhashtable_walk_stop(&walk);
	rhashtable_walk_exit(&walk);
	mutex_unlock(&efx->tc->mutex);
}
#endif

static void efx_neigh_update(struct work_struct *work);

static int efx_bind_neigh(struct efx_nic *efx,
			  struct efx_tc_encap_action *encap, struct net *net,
			  struct netlink_ext_ack *extack)
{
	struct efx_neigh_binder *neigh, *old;
	struct flowi6 flow6 = {};
	struct flowi4 flow4 = {};
	int rc;

	/* GCC stupidly thinks that only values explicitly listed in the enum
	 * definition can _possibly_ be sensible case values, so without this
	 * cast it complains about the IPv6 versions.
	 */
	switch ((int)encap->type) {
	case EFX_ENCAP_TYPE_VXLAN:
	case EFX_ENCAP_TYPE_GENEVE:
		flow4.flowi4_proto = IPPROTO_UDP;
		flow4.fl4_dport = encap->key.tp_dst;
		flow4.flowi4_tos = encap->key.tos;
		flow4.daddr = encap->key.u.ipv4.dst;
		flow4.saddr = encap->key.u.ipv4.src;
		break;
	case EFX_ENCAP_TYPE_VXLAN | EFX_ENCAP_FLAG_IPV6:
	case EFX_ENCAP_TYPE_GENEVE | EFX_ENCAP_FLAG_IPV6:
		flow6.flowi6_proto = IPPROTO_UDP;
		flow6.fl6_dport = encap->key.tp_dst;
		flow6.flowlabel = ip6_make_flowinfo(RT_TOS(encap->key.tos),
						    encap->key.label);
		flow6.daddr = encap->key.u.ipv6.dst;
		flow6.saddr = encap->key.u.ipv6.src;
		break;
	default:
		EFX_TC_ERR_MSG(efx, extack, "Unsupported encap type");
		return -EOPNOTSUPP;
	}

	neigh = kzalloc(sizeof(*neigh), GFP_USER);
	if (!neigh)
		return -ENOMEM;
	neigh->net = get_net(net);
	neigh->dst_ip = flow4.daddr;
	neigh->dst_ip6 = flow6.daddr;

	old = rhashtable_lookup_get_insert_fast(&efx->tc->neigh_ht,
						&neigh->linkage,
						efx_neigh_ht_params);
	if (old) {
		/* don't need our new entry */
		put_net(neigh->net);
		kfree(neigh);
		if (!refcount_inc_not_zero(&old->ref))
			return -EAGAIN;
		/* existing entry found, ref taken */
		neigh = old;
	} else {
		/* New entry.  We need to initiate a lookup */
		struct dst_entry *dst;
		struct neighbour *n;
		struct rtable *rt;

		if (encap->type & EFX_ENCAP_FLAG_IPV6) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_IPV6_STUBS_DST_LOOKUP_FLOW)
			dst = ipv6_stub->ipv6_dst_lookup_flow(net, NULL, &flow6,
							      NULL);
			rc = PTR_ERR_OR_ZERO(dst);
#else
			rc = ipv6_stub->ipv6_dst_lookup(net, NULL, &dst, &flow6);
#endif
			if (rc) {
				EFX_TC_ERR_MSG(efx, extack, "Failed to lookup route for encap");
				goto out_free;
			}
			dev_hold(neigh->egdev = dst->dev);
			neigh->ttl = ip6_dst_hoplimit(dst);
			n = dst_neigh_lookup(dst, &flow6.daddr);
			dst_release(dst);
		} else {
			rt = ip_route_output_key(net, &flow4);
			if (IS_ERR_OR_NULL(rt)) {
				rc = PTR_ERR(rt);
				if (!rc)
					rc = -EIO;
				EFX_TC_ERR_MSG(efx, extack, "Failed to lookup route for encap");
				goto out_free;
			}
			dev_hold(neigh->egdev = rt->dst.dev);
			neigh->ttl = ip4_dst_hoplimit(&rt->dst);
			n = dst_neigh_lookup(&rt->dst, &flow4.daddr);
			ip_rt_put(rt);
		}
		if (!n) {
			rc = -ENETUNREACH;
			EFX_TC_ERR_MSG(efx, extack, "Failed to lookup neighbour for encap");
			dev_put(neigh->egdev);
			goto out_free;
		}
		refcount_set(&neigh->ref, 1);
		INIT_LIST_HEAD(&neigh->users);
		read_lock_bh(&n->lock);
		ether_addr_copy(neigh->ha, n->ha);
		neigh->n_valid = n->nud_state & NUD_VALID;
		read_unlock_bh(&n->lock);
		rwlock_init(&neigh->lock);
		INIT_WORK(&neigh->work, efx_neigh_update);
		neigh->efx = efx;
		neigh->used = jiffies;
		if (!neigh->n_valid)
			/* Prod ARP to find us a neighbour */
			neigh_event_send(n, NULL);
		neigh_release(n);
	}
	/* Add us to this neigh */
	encap->neigh = neigh;
	list_add_tail(&encap->list, &neigh->users);
	return 0;

out_free:
	/* cleanup common to several error paths */
	rhashtable_remove_fast(&efx->tc->neigh_ht, &neigh->linkage,
			       efx_neigh_ht_params);
	synchronize_rcu();
	put_net(net);
	kfree(neigh);
	return rc;
}

static void efx_free_neigh(struct efx_neigh_binder *neigh)
{
	struct efx_nic *efx = neigh->efx;

	rhashtable_remove_fast(&efx->tc->neigh_ht, &neigh->linkage,
			       efx_neigh_ht_params);
	synchronize_rcu();
	dev_put(neigh->egdev);
	put_net(neigh->net);
	kfree(neigh);
}

static void efx_release_neigh(struct efx_nic *efx,
			      struct efx_tc_encap_action *encap)
{
	struct efx_neigh_binder *neigh = encap->neigh;

	if (!neigh)
		return;
	list_del(&encap->list);
	encap->neigh = NULL;
	if (!refcount_dec_and_test(&neigh->ref))
		return; /* still in use */
	efx_free_neigh(neigh);
}

static void efx_tc_flower_release_encap_md(struct efx_nic *efx,
					   struct efx_tc_encap_action *encap);

static void efx_neigh_update(struct work_struct *work)
{
	struct efx_neigh_binder *neigh = container_of(work, struct efx_neigh_binder, work);
	struct efx_tc_encap_action *encap;
	struct efx_nic *efx = neigh->efx;

	mutex_lock(&efx->tc->mutex);
	list_for_each_entry(encap, &neigh->users, list)
		efx_tc_update_encap(neigh->efx, encap);
	/* release ref taken in efx_neigh_event() */
	if (refcount_dec_and_test(&neigh->ref))
		efx_free_neigh(neigh);
	mutex_unlock(&efx->tc->mutex);
}

static int efx_neigh_event(struct efx_nic *efx, struct neighbour *n)
{
	struct efx_neigh_binder keys = {NULL}, *neigh;
	char ha[ETH_ALEN];
	unsigned char ipv;
	size_t keysize;
	bool n_valid;

	if (WARN_ON(!efx->tc))
		return NOTIFY_DONE;

	/* Only care about IPv4 for now */
	if (n->tbl == &arp_tbl) {
		ipv = 4;
		keysize = sizeof(keys.dst_ip);
	} else if (n->tbl == &nd_tbl) {
		ipv = 6;
		keysize = sizeof(keys.dst_ip6);
	} else {
		return NOTIFY_DONE;
	}
	if (!n->parms) {
		netif_warn(efx, drv, efx->net_dev, "neigh_event with no parms!\n");
		return NOTIFY_DONE;
	}
	keys.net = read_pnet(&n->parms->net);
	if (n->tbl->key_len != keysize) {
		netif_warn(efx, drv, efx->net_dev, "neigh_event with bad key_len %u\n",
			  n->tbl->key_len);
		return NOTIFY_DONE;
	}
	read_lock_bh(&n->lock); /* Get a consistent view */
	memcpy(ha, n->ha, ETH_ALEN);
	n_valid = (n->nud_state & NUD_VALID) && !n->dead;
	read_unlock_bh(&n->lock);
	switch(ipv) {
	case 4:
		memcpy(&keys.dst_ip, n->primary_key, n->tbl->key_len);
		break;
	case 6:
		memcpy(&keys.dst_ip6, n->primary_key, n->tbl->key_len);
		break;
	default: /* can't happen */
		return NOTIFY_DONE;
	}
	rcu_read_lock();
	neigh = rhashtable_lookup_fast(&efx->tc->neigh_ht, &keys,
				       efx_neigh_ht_params);
	if (!neigh || neigh->dying)
		/* We're not interested in this neighbour */
		goto done;
	write_lock_bh(&neigh->lock);
	if (n_valid == neigh->n_valid && !memcmp(ha, neigh->ha, ETH_ALEN)) {
		write_unlock_bh(&neigh->lock);
		/* Nothing has changed; no work to do */
		goto done;
	}
	neigh->n_valid = n_valid;
	memcpy(neigh->ha, ha, ETH_ALEN);
	write_unlock_bh(&neigh->lock);
	if (refcount_inc_not_zero(&neigh->ref)) {
		rcu_read_unlock();
		if (!schedule_work(&neigh->work))
			/* failed to schedule, release the ref we just took */
			if (refcount_dec_and_test(&neigh->ref))
				efx_free_neigh(neigh);
	} else {
done:
		rcu_read_unlock();
	}
	return NOTIFY_DONE;
}

static void efx_tc_counter_work(struct work_struct *work);

static struct efx_tc_counter *efx_tc_flower_allocate_counter(struct efx_nic *efx)
{
	struct efx_tc_counter *cnt;
	int rc, rc2;

	cnt = kzalloc(sizeof(*cnt), GFP_USER);
	if (!cnt)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&cnt->lock);
	INIT_WORK(&cnt->work, efx_tc_counter_work);
	cnt->touched = jiffies;
	cnt->tc = efx->tc;

	rc = efx_mae_allocate_counter(efx, cnt);
	if (rc)
		goto fail1;
	INIT_LIST_HEAD(&cnt->users);
	rc = rhashtable_insert_fast(&efx->tc->counter_ht, &cnt->linkage,
				    efx_tc_counter_ht_params);
	if (rc)
		goto fail2;
	return cnt;
fail2:
	/* If we get here, it implies that we couldn't insert into the table,
	 * which in turn probably means that the fw_id was already taken.
	 * In that case, it's unclear whether we really 'own' the fw_id; but
	 * the firmware seemed to think we did, so it's proper to free it.
	 */
	rc2 = efx_mae_free_counter(efx, cnt->fw_id);
	if (rc2)
		netif_warn(efx, hw, efx->net_dev,
			   "Failed to free MAE counter %u, rc %d\n",
			   cnt->fw_id, rc2);
fail1:
	kfree(cnt);
	return ERR_PTR(rc > 0 ? -EIO : rc);
}

static void efx_tc_flower_release_counter(struct efx_nic *efx,
					  struct efx_tc_counter *cnt)
{
	int rc;

	rhashtable_remove_fast(&efx->tc->counter_ht, &cnt->linkage,
			       efx_tc_counter_ht_params);
	rc = efx_mae_free_counter(efx, cnt->fw_id);
	if (rc)
		netif_warn(efx, hw, efx->net_dev,
			   "Failed to free MAE counter %u, rc %d\n",
			   cnt->fw_id, rc);
	WARN_ON(!list_empty(&cnt->users));
	/* This doesn't protect counter updates coming in arbitrarily long
	 * after we deleted the counter.  The RCU just ensures that we won't
	 * free the counter while another thread has a pointer to it.
	 * Ensuring we don't update the wrong counter if the ID gets re-used
	 * is handled by the generation count.  See SWNETLINUX-3595, and
	 * comments on CT-8026, for further discussion.
	 */
	synchronize_rcu();
	flush_work(&cnt->work);
	EFX_WARN_ON_PARANOID(spin_is_locked(&cnt->lock));
	kfree(cnt);
}

static struct efx_tc_counter *efx_tc_flower_find_counter_by_fw_id(
				struct efx_nic *efx, u32 fw_id)
{
	struct efx_tc_counter key = {};

	key.fw_id = fw_id;
	return rhashtable_lookup_fast(&efx->tc->counter_ht, &key,
				      efx_tc_counter_ht_params);
}

static void efx_tc_flower_put_counter_index(struct efx_nic *efx,
					    struct efx_tc_counter_index *ctr)
{
	if (!refcount_dec_and_test(&ctr->ref))
		return; /* still in use */
	rhashtable_remove_fast(&efx->tc->counter_id_ht, &ctr->linkage,
			       efx_tc_counter_id_ht_params);
	efx_tc_flower_release_counter(efx, ctr->cnt);
	kfree(ctr);
}

static struct efx_tc_counter_index *efx_tc_flower_get_counter_index(
				struct efx_nic *efx, unsigned long cookie)
{
	struct efx_tc_counter_index *ctr, *old;
	struct efx_tc_counter *cnt;

	ctr = kzalloc(sizeof(*ctr), GFP_USER);
	if (!ctr)
		return ERR_PTR(-ENOMEM);
	ctr->cookie = cookie;
	old = rhashtable_lookup_get_insert_fast(&efx->tc->counter_id_ht,
						&ctr->linkage,
						efx_tc_counter_id_ht_params);
	if (old) {
		/* don't need our new entry */
		kfree(ctr);
		if (!refcount_inc_not_zero(&old->ref))
			return ERR_PTR(-EAGAIN);
		/* existing entry found */
		ctr = old;
	} else {
		cnt = efx_tc_flower_allocate_counter(efx);
		if (IS_ERR(cnt)) {
			rhashtable_remove_fast(&efx->tc->counter_id_ht,
					       &ctr->linkage,
					       efx_tc_counter_id_ht_params);
			kfree(ctr);
			return (void *)cnt; /* it's an ERR_PTR */
		}
		ctr->cnt = cnt;
		refcount_set(&ctr->ref, 1);
	}
	return ctr;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_TC_ACTION_COOKIE) || defined(EFX_HAVE_TC_FLOW_OFFLOAD)
static struct efx_tc_counter_index *efx_tc_flower_find_counter_index(
				struct efx_nic *efx, unsigned long cookie)
{
	struct efx_tc_counter_index key = {};

	key.cookie = cookie;
	return rhashtable_lookup_fast(&efx->tc->counter_id_ht, &key,
				      efx_tc_counter_id_ht_params);
}
#endif

static void efx_gen_tun_header_eth(struct efx_tc_encap_action *encap, u16 proto)
{
	struct efx_neigh_binder *neigh = encap->neigh;
	struct ethhdr *eth;

	memset(encap->encap_hdr, 0, sizeof(encap->encap_hdr));
	encap->encap_hdr_len = sizeof(*eth);

	eth = (void *)encap->encap_hdr;
	if (encap->neigh->n_valid)
		ether_addr_copy(eth->h_dest, neigh->ha);
	else
		eth_zero_addr(eth->h_dest);
	ether_addr_copy(eth->h_source, neigh->egdev->dev_addr);
	eth->h_proto = htons(proto);
}

static void efx_gen_tun_header_ipv4(struct efx_tc_encap_action *encap, u8 ipproto, u8 len)
{
	struct efx_neigh_binder *neigh = encap->neigh;
	struct ip_tunnel_key *key = &encap->key;
	struct iphdr *ip;

	ip = (void *)(encap->encap_hdr + encap->encap_hdr_len);
	encap->encap_hdr_len += sizeof(*ip);

	ip->daddr = key->u.ipv4.dst;
	ip->saddr = key->u.ipv4.src;
	ip->ttl = neigh->ttl;
	ip->protocol = ipproto;
	ip->version = 0x4;
	ip->ihl = 0x5;
	ip->tot_len = cpu_to_be16(ip->ihl * 4 + len);
	ip_send_check(ip);
}

static void efx_gen_tun_header_ipv6(struct efx_tc_encap_action *encap, u8 ipproto, u8 len)
{
	struct efx_neigh_binder *neigh = encap->neigh;
	struct ip_tunnel_key *key = &encap->key;
	struct ipv6hdr *ip;

	ip = (void *)(encap->encap_hdr + encap->encap_hdr_len);
	encap->encap_hdr_len += sizeof(*ip);

	ip6_flow_hdr(ip, key->tos, key->label);
	ip->daddr = key->u.ipv6.dst;
	ip->saddr = key->u.ipv6.src;
	ip->hop_limit = neigh->ttl;
	ip->nexthdr = IPPROTO_UDP;
	ip->version = 0x6;
	ip->payload_len = cpu_to_be16(len);
}

static void efx_gen_tun_header_udp(struct efx_tc_encap_action *encap, u8 len)
{
	struct ip_tunnel_key *key = &encap->key;
	struct udphdr *udp;

	udp = (void *)(encap->encap_hdr + encap->encap_hdr_len);
	encap->encap_hdr_len += sizeof(*udp);
	udp->dest = key->tp_dst;
	udp->len = cpu_to_be16(sizeof(*udp) + len);
}

static void efx_gen_tun_header_vxlan(struct efx_tc_encap_action *encap)
{
	struct ip_tunnel_key *key = &encap->key;
	struct vxlanhdr *vxlan;

	vxlan = (void *)(encap->encap_hdr + encap->encap_hdr_len);
	encap->encap_hdr_len += sizeof(*vxlan);
	vxlan->vx_flags = VXLAN_HF_VNI;
	vxlan->vx_vni = vxlan_vni_field(tunnel_id_to_key32(key->tun_id));
}

static void efx_gen_tun_header_geneve(struct efx_tc_encap_action *encap)
{
	struct ip_tunnel_key *key = &encap->key;
	struct genevehdr *geneve;
	u32 vni;

	geneve = (void *)(encap->encap_hdr + encap->encap_hdr_len);
	encap->encap_hdr_len += sizeof(*geneve);
	geneve->proto_type = htons(ETH_P_TEB);
	/* convert tun_id to host-endian so we can use host arithmetic to
	 * extract individual bytes.
	 */
	vni = ntohl(tunnel_id_to_key32(key->tun_id));
	geneve->vni[0] = vni >> 16;
	geneve->vni[1] = vni >> 8;
	geneve->vni[2] = vni;
}

#define vxlan_header_l4_len	(sizeof(struct udphdr) + sizeof(struct vxlanhdr))
#define vxlan4_header_len	(sizeof(struct ethhdr) + sizeof(struct iphdr) + vxlan_header_l4_len)
static void efx_gen_vxlan_header_ipv4(struct efx_tc_encap_action *encap)
{
	BUILD_BUG_ON(sizeof(encap->encap_hdr) < vxlan4_header_len);
	efx_gen_tun_header_eth(encap, ETH_P_IP);
	efx_gen_tun_header_ipv4(encap, IPPROTO_UDP, vxlan_header_l4_len);
	efx_gen_tun_header_udp(encap, sizeof(struct vxlanhdr));
	efx_gen_tun_header_vxlan(encap);
}

#define geneve_header_l4_len	(sizeof(struct udphdr) + sizeof(struct genevehdr))
#define geneve4_header_len	(sizeof(struct ethhdr) + sizeof(struct iphdr) + geneve_header_l4_len)
static void efx_gen_geneve_header_ipv4(struct efx_tc_encap_action *encap)
{
	BUILD_BUG_ON(sizeof(encap->encap_hdr) < geneve4_header_len);
	efx_gen_tun_header_eth(encap, ETH_P_IP);
	efx_gen_tun_header_ipv4(encap, IPPROTO_UDP, geneve_header_l4_len);
	efx_gen_tun_header_udp(encap, sizeof(struct genevehdr));
	efx_gen_tun_header_geneve(encap);
}

#define vxlan6_header_len	(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + vxlan_header_l4_len)
static void efx_gen_vxlan_header_ipv6(struct efx_tc_encap_action *encap)
{
	BUILD_BUG_ON(sizeof(encap->encap_hdr) < vxlan6_header_len);
	efx_gen_tun_header_eth(encap, ETH_P_IPV6);
	efx_gen_tun_header_ipv6(encap, IPPROTO_UDP, vxlan_header_l4_len);
	efx_gen_tun_header_udp(encap, sizeof(struct vxlanhdr));
	efx_gen_tun_header_vxlan(encap);
}

#define geneve6_header_len	(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + geneve_header_l4_len)
static void efx_gen_geneve_header_ipv6(struct efx_tc_encap_action *encap)
{
	BUILD_BUG_ON(sizeof(encap->encap_hdr) < geneve6_header_len);
	efx_gen_tun_header_eth(encap, ETH_P_IPV6);
	efx_gen_tun_header_ipv6(encap, IPPROTO_UDP, geneve_header_l4_len);
	efx_gen_tun_header_udp(encap, sizeof(struct genevehdr));
	efx_gen_tun_header_geneve(encap);
}

static void efx_gen_encap_header(struct efx_tc_encap_action *encap)
{
	encap->n_valid = encap->neigh->n_valid;

	memset(encap->encap_hdr, 0, sizeof(encap->encap_hdr));
	/* GCC stupidly thinks that only values explicitly listed in the enum
	 * definition can _possibly_ be sensible case values, so without this
	 * cast it complains about the IPv6 versions.
	 */
	switch ((int)encap->type) {
	case EFX_ENCAP_TYPE_VXLAN:
		efx_gen_vxlan_header_ipv4(encap);
		break;
	case EFX_ENCAP_TYPE_GENEVE:
		efx_gen_geneve_header_ipv4(encap);
		break;
	case EFX_ENCAP_TYPE_VXLAN | EFX_ENCAP_FLAG_IPV6:
		efx_gen_vxlan_header_ipv6(encap);
		break;
	case EFX_ENCAP_TYPE_GENEVE | EFX_ENCAP_FLAG_IPV6:
		efx_gen_geneve_header_ipv6(encap);
		break;
	default:
		/* unhandled encap type, can't happen */
		WARN_ON(1);
		/* Make sure we don't leak arbitrary bytes on the wire;
		 * set an all-0s ethernet header.
		 */
		encap->encap_hdr_len = ETH_HLEN;
		break;
	}
}

static bool efx_tc_check_ready(struct efx_nic *efx, struct efx_tc_flow_rule *rule)
{
	struct efx_tc_action_set *act;

	/* How's our neigh? */
	list_for_each_entry(act, &rule->acts.list, list)
		if (act->encap_md && !act->encap_md->n_valid)
			return false; /* ENOHORSE */
	return true;
}

static void efx_tc_update_encap(struct efx_nic *efx,
				struct efx_tc_encap_action *encap)
{
	struct efx_tc_action_set_list *acts;
	struct efx_tc_action_set *act;
	struct efx_tc_flow_rule *rule;
	int rc;

	if (encap->neigh) {
		read_lock_bh(&encap->neigh->lock);
		efx_gen_encap_header(encap);
		read_unlock_bh(&encap->neigh->lock);
	} else {
		encap->n_valid = false;
		memset(encap->encap_hdr, 0, sizeof(encap->encap_hdr));
		encap->encap_hdr_len = ETH_HLEN;
	}

	rc = efx_mae_update_encap_md(efx, encap);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "Failed to update encap hdr %08x rc %d\n",
			  encap->fw_id, rc);
		return;
	}
	netif_dbg(efx, drv, efx->net_dev, "Updated encap hdr %08x\n",
		  encap->fw_id);
	/* Update rule users based on their (possibly now changed) readiness */
	list_for_each_entry(act, &encap->users, encap_user) {
		acts = act->user;
		if (WARN_ON(!acts)) /* can't happen */
			continue;
		rule = container_of(acts, struct efx_tc_flow_rule, acts);
		if (efx_tc_check_ready(efx, rule)) {
			rc = efx_mae_update_rule(efx, acts->fw_id, rule->fw_id);
		} else {
			struct efx_tc_flow_rule *fallback;

			if (rule->fallback < EFX_TC_DFLT__MAX)
				fallback = &efx->tc->dflt_rules[rule->fallback];
			else /* fallback fallback: deliver to PF */
				fallback = &efx->tc->dflt_rules[EFX_TC_DFLT_WIRE];
			rc = efx_mae_update_rule(efx, fallback->acts.fw_id,
						 rule->fw_id);
		}
		if (rc)
			netif_err(efx, drv, efx->net_dev,
				  "Failed to update rule %08x rc %d\n",
				  rule->fw_id, rc);
		else
			netif_dbg(efx, drv, efx->net_dev, "Updated rule %08x\n",
				  rule->fw_id);
	}
}

static struct efx_tc_encap_action *efx_tc_flower_create_encap_md(
			struct efx_nic *efx, const struct ip_tunnel_info *info,
			struct net_device *egdev, struct netlink_ext_ack *extack)
{
	enum efx_encap_type type = efx_tc_indr_netdev_type(egdev);
	struct efx_tc_encap_action *encap, *old;
	long rc;

	if (type == EFX_ENCAP_TYPE_NONE) {
		/* dest is not an encap device */
		EFX_TC_ERR_MSG(efx, extack, "Not a (supported) tunnel device but tunnel_key is set");
		return ERR_PTR(-EOPNOTSUPP);
	}
	rc = efx_mae_check_encap_type_supported(efx, type);
	if (rc < 0) {
		EFX_TC_ERR_MSG(efx, extack, "Firmware reports no support for this tunnel type");
		return ERR_PTR(rc);
	}
	encap = kzalloc(sizeof(*encap), GFP_USER);
	if (!encap)
		return ERR_PTR(-ENOMEM);
	/* No support yet for Geneve options */
	if (info->options_len) {
		EFX_TC_ERR_MSG(efx, extack, "Unsupported tunnel options");
		rc = -EOPNOTSUPP;
		goto out_free;
	}
	switch (info->mode) {
	case IP_TUNNEL_INFO_TX:
		break;
	case IP_TUNNEL_INFO_TX | IP_TUNNEL_INFO_IPV6:
		type |= EFX_ENCAP_FLAG_IPV6;
		break;
	default:
		efx_tc_err(efx, "Unsupported tunnel mode %u\n", info->mode);
		NL_SET_ERR_MSG_MOD(extack, "Unsupported tunnel mode");
		rc = -EOPNOTSUPP;
		goto out_free;
	}
	encap->type = type;
	encap->key = info->key;
	INIT_LIST_HEAD(&encap->users);
	old = rhashtable_lookup_get_insert_fast(&efx->tc->encap_ht,
						&encap->linkage,
						efx_tc_encap_ht_params);
	if (old) {
		/* don't need our new entry */
		kfree(encap);
		if (!refcount_inc_not_zero(&old->ref))
			return ERR_PTR(-EAGAIN);
		/* existing entry found, ref taken */
		return old;
	}

	rc = efx_bind_neigh(efx, encap, dev_net(egdev), extack);
	if (rc < 0)
		goto out_remove;
	rc = efx_tc_flower_lookup_dev(efx, encap->neigh->egdev);
	if (rc < 0) {
		/* neigh->egdev isn't ours */
		EFX_TC_ERR_MSG(efx, extack, "Tunnel egress device not on switch");
		goto out_release;
	}
	rc = efx_tc_flower_external_mport(efx, rc);
	if (rc < 0) {
		EFX_TC_ERR_MSG(efx, extack, "Failed to identify tunnel egress m-port");
		goto out_release;
	}
	encap->dest_mport = rc;
	read_lock_bh(&encap->neigh->lock);
	efx_gen_encap_header(encap);
	read_unlock_bh(&encap->neigh->lock);

	rc = efx_mae_allocate_encap_md(efx, encap);
	if (rc < 0) {
		EFX_TC_ERR_MSG(efx, extack, "Failed to write tunnel header to hw");
		goto out_release;
	}

	/* ref and return */
	refcount_set(&encap->ref, 1);
	return encap;
out_release:
	efx_release_neigh(efx, encap);
out_remove:
	rhashtable_remove_fast(&efx->tc->encap_ht, &encap->linkage,
			       efx_tc_encap_ht_params);
out_free:
	kfree(encap);
	return ERR_PTR(rc);
}

static void efx_tc_flower_release_encap_md(struct efx_nic *efx,
					   struct efx_tc_encap_action *encap)
{
	if (!refcount_dec_and_test(&encap->ref))
		return; /* still in use */
	efx_release_neigh(efx, encap);
	rhashtable_remove_fast(&efx->tc->encap_ht, &encap->linkage,
			       efx_tc_encap_ht_params);
	efx_mae_free_encap_md(efx, encap);
	kfree(encap);
}

static void efx_tc_free_action_set(struct efx_nic *efx,
				   struct efx_tc_action_set *act, bool in_hw)
{
	if (act->count) {
		if (!list_empty(&act->count_user))
			list_del(&act->count_user);
		efx_tc_flower_put_counter_index(efx, act->count);
	}
	if (act->encap_md) {
		list_del(&act->encap_user);
		efx_tc_flower_release_encap_md(efx, act->encap_md);
	}
	/* Failure paths calling this on the 'running action' set in_hw=false,
	 * because if the alloc had succeeded we'd've put it in acts.list and
	 * not still have it in act.
	 */
	if (in_hw)
		efx_mae_free_action_set(efx, act);
	kfree(act);
}

static void efx_tc_free_action_set_list(struct efx_nic *efx,
					struct efx_tc_action_set_list *acts,
					bool in_hw)
{
	struct efx_tc_action_set *act;

	list_for_each_entry(act, &acts->list, list)
		efx_tc_free_action_set(efx, act, true);
	/* Failure paths set in_hw=false, because usually the acts didn't get
	 * to efx_mae_alloc_action_set_list(); if they did, the failure tree
	 * has a separate efx_mae_free_action_set_list() before calling us.
	 */
	if (in_hw)
		efx_mae_free_action_set_list(efx, acts);
	/* Don't kfree, as acts is embedded inside a struct efx_tc_flow_rule */
}

static void efx_tc_flower_release_encap_match(struct efx_nic *efx,
					      struct efx_tc_encap_match *encap);

static struct efx_tc_ctr_agg *efx_tc_get_ctr_agg(struct efx_nic *efx,
						 unsigned long cookie)
{
	struct efx_tc_ctr_agg *agg, *old;

	agg = kzalloc(sizeof(*agg), GFP_USER);
	if (!agg)
		return ERR_PTR(-ENOMEM);
	agg->cookie = cookie;
	INIT_LIST_HEAD(&agg->count.users);
	refcount_set(&agg->ref, 1);
	old = rhashtable_lookup_get_insert_fast(&efx->tc->ctr_agg_ht,
						&agg->linkage,
						efx_tc_ctr_agg_ht_params);
	if (old) {
		/* don't need our new entry */
		kfree(agg);
		if (!refcount_inc_not_zero(&old->ref))
			return ERR_PTR(-EAGAIN);
		/* existing entry found */
		return old;
	}
	/* new entry was inserted, return it */
	return agg;
}

static void efx_tc_put_ctr_agg(struct efx_nic *efx, struct efx_tc_ctr_agg *agg)
{
	if (!refcount_dec_and_test(&agg->ref))
		return; /* still in use */
	rhashtable_remove_fast(&efx->tc->ctr_agg_ht, &agg->linkage,
			       efx_tc_ctr_agg_ht_params);
	/* TODO check to see what synchronisation we might need here in case of
	 * concurrent updates to the counters that feed us.
	 */
	kfree(agg);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
#if IS_ENABLED(CONFIG_NF_FLOW_TABLE)
static int efx_tc_flow_block(enum tc_setup_type type, void *type_data,
			     void *cb_priv);
#endif

static void efx_tc_ct_zone_free(void *ptr, void *arg)
{
	struct efx_tc_ct_zone *zone = ptr;
	struct efx_nic *efx = zone->efx;

	netif_err(efx, drv, efx->net_dev,
		  "tc ct_zone %u still present at teardown, removing\n",
		  zone->zone);

#if IS_ENABLED(CONFIG_NF_FLOW_TABLE)
	nf_flow_table_offload_del_cb(zone->nf_ft, efx_tc_flow_block, zone);
#endif
	kfree(zone);
}

static void efx_tc_ct_free(void *ptr, void *arg)
{
	struct efx_tc_ct_entry *conn = ptr;
	struct efx_nic *efx = arg;

	netif_err(efx, drv, efx->net_dev,
		  "tc ct_entry %lx still present at teardown, removing\n",
		  conn->cookie);

	efx_mae_remove_ct(efx, conn);
	kfree(conn);
}

static void efx_tc_ct_unregister_zone(struct efx_nic *efx,
				      struct efx_tc_ct_zone *ct_zone);
#endif

static void efx_tc_lhs_free(void *ptr, void *arg)
{
	struct efx_tc_lhs_rule *rule = ptr;
	struct efx_nic *efx = arg;

	netif_err(efx, drv, efx->net_dev,
		  "tc lhs_rule %lx still present at teardown, removing\n",
		  rule->cookie);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	if (rule->lhs_act.zone)
		efx_tc_ct_unregister_zone(efx, rule->lhs_act.zone);
#endif
	if (rule->lhs_act.count)
		efx_tc_put_ctr_agg(efx, rule->lhs_act.count);
	efx_mae_remove_lhs_rule(efx, rule);

	kfree(rule);
}

static void efx_tc_flow_free(void *ptr, void *arg)
{
	struct efx_tc_flow_rule *rule = ptr;
	struct efx_nic *efx = arg;

	netif_err(efx, drv, efx->net_dev,
		  "tc rule %lx still present at teardown, removing\n",
		  rule->cookie);

	efx_mae_delete_rule(efx, rule->fw_id);

	/* Release entries in subsidiary tables */
	efx_tc_free_action_set_list(efx, &rule->acts, true);
	if (rule->match.encap)
		efx_tc_flower_release_encap_match(efx, rule->match.encap);

	kfree(rule);
}

/* At teardown time, all TC filter rules (and thus all resources they created)
 * should already have been removed.  If we find any in our hashtables, make a
 * cursory attempt to clean up the software side.
 */
static void efx_tc_encap_free(void *ptr, void *__unused)
{
	struct efx_tc_encap_action *enc = ptr;

	WARN_ON(refcount_read(&enc->ref));
	kfree(enc);
}

static void efx_tc_encap_match_free(void *ptr, void *__unused)
{
	struct efx_tc_encap_match *encap = ptr;

	WARN_ON(refcount_read(&encap->ref));
	kfree(encap);
}

static void efx_tc_counter_free(void *ptr, void *__unused)
{
	struct efx_tc_counter *cnt = ptr;

	WARN_ON(!list_empty(&cnt->users));
	/* We'd like to synchronize_rcu() here, but unfortunately we aren't
	 * removing the element from the hashtable (it's not clear that's a
	 * safe thing to do in an rhashtable_free_and_destroy free_fn), so
	 * threads could still be obtaining new pointers to *cnt if they can
	 * race against this function at all.
	 */
	flush_work(&cnt->work);
	EFX_WARN_ON_PARANOID(spin_is_locked(&cnt->lock));
	kfree(cnt);
}

static void efx_tc_counter_id_free(void *ptr, void *__unused)
{
	struct efx_tc_counter_index *ctr = ptr;

	WARN_ON(refcount_read(&ctr->ref));
	kfree(ctr);
}

static void efx_neigh_free(void *ptr, void *__unused)
{
	struct efx_neigh_binder *neigh = ptr;

	WARN_ON(refcount_read(&neigh->ref));
	WARN_ON(!list_empty(&neigh->users));
	put_net(neigh->net);
	dev_put(neigh->egdev);
	kfree(neigh);
}

static void efx_tc_ctr_agg_free(void *ptr, void *__unused)
{
	struct efx_tc_ctr_agg *agg = ptr;

	WARN_ON(refcount_read(&agg->ref));
	WARN_ON(!list_empty(&agg->count.users)); /* shouldn't be used */
	kfree(agg);
}

static struct efx_tc_recirc_id *efx_tc_get_recirc_id(struct efx_nic *efx, u32 chain_index)
{
	struct efx_tc_recirc_id *rid, *old;
	int rc;

	rid = kzalloc(sizeof(*rid), GFP_USER);
	if (!rid)
		return ERR_PTR(-ENOMEM);
	rid->chain_index = chain_index;
	old = rhashtable_lookup_get_insert_fast(&efx->tc->recirc_ht,
						&rid->linkage,
						efx_tc_recirc_ht_params);
	if (old) {
		/* don't need our new entry */
		kfree(rid);
		if (!refcount_inc_not_zero(&old->ref))
			return ERR_PTR(-EAGAIN);
		/* existing entry found */
		rid = old;
	} else {
		rc = ida_alloc_range(&efx->tc->recirc_ida, 1, U8_MAX, GFP_USER);
		if (rc < 0) {
			rhashtable_remove_fast(&efx->tc->recirc_ht,
					       &rid->linkage,
					       efx_tc_recirc_ht_params);
			kfree(rid);
			return ERR_PTR(rc);
		}
		rid->fw_id = rc;
		refcount_set(&rid->ref, 1);
	}
	return rid;
}

static void efx_tc_put_recirc_id(struct efx_nic *efx, struct efx_tc_recirc_id *rid)
{
	if (!refcount_dec_and_test(&rid->ref))
		return; /* still in use */
	rhashtable_remove_fast(&efx->tc->recirc_ht, &rid->linkage,
			       efx_tc_recirc_ht_params);
	ida_free(&efx->tc->recirc_ida, rid->fw_id);
	kfree(rid);
}

static void efx_tc_recirc_free(void *ptr, void *arg)
{
	struct efx_tc_recirc_id *rid = ptr;
	struct efx_nic *efx = arg;

	WARN_ON(refcount_read(&rid->ref));
	ida_free(&efx->tc->recirc_ida, rid->fw_id);
	kfree(rid);
}

static void efx_tc_handle_no_channel(struct efx_nic *efx)
{
	netif_warn(efx, drv, efx->net_dev,
		   "MAE counters require MSI-X and 1 additional interrupt vector.\n");
}

static int efx_tc_probe_channel(struct efx_channel *channel)
{
	struct efx_rx_queue *rx_queue = &channel->rx_queue;

	channel->irq_moderation_us = 0;
	rx_queue->core_index = 0;

	INIT_WORK(&rx_queue->grant_work, efx_mae_counters_grant_credits);

	return 0;
}

static int efx_tc_start_channel(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;

	return efx_mae_start_counters(efx, channel);
}

static void efx_tc_stop_channel(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	int rc;

	flush_work(&channel->rx_queue.grant_work);
	rc = efx_mae_stop_counters(efx, channel);
	if (rc)
		netif_warn(efx, drv, efx->net_dev,
			   "Failed to stop MAE counters streaming, rc=%d.\n",
			   rc);
}

static void efx_tc_remove_channel(struct efx_channel *channel)
{
}

static void efx_tc_get_channel_name(struct efx_channel *channel,
				    char *buf, size_t len)
{
	snprintf(buf, len, "%s-mae", channel->efx->name);
}

static void efx_tc_counter_work(struct work_struct *work)
{
	struct efx_tc_counter *cnt = container_of(work, struct efx_tc_counter, work);
	struct efx_tc_encap_action *encap;
	struct efx_tc_action_set *act;
	unsigned long touched;
	struct neighbour *n;

	touched = READ_ONCE(cnt->touched);

	mutex_lock(&cnt->tc->mutex);
	list_for_each_entry(act, &cnt->users, count_user) {
		encap = act->encap_md;
		if (!encap)
			continue;
		if (!encap->neigh) /* can't happen */
			continue;
		if (time_after_eq(encap->neigh->used, touched))
			continue;
		encap->neigh->used = touched;
		/* We have passed traffic using this ARP entry, so
		 * indicate to the ARP cache that it's still active
		 */
		n = neigh_lookup(&arp_tbl, &encap->neigh->dst_ip,
		/* XXX is this the right device? */
				 encap->neigh->egdev);
		if (!n)
			continue;

		neigh_event_send(n, NULL);
		neigh_release(n);
	}
	mutex_unlock(&cnt->tc->mutex);
}

static void efx_tc_counter_update(struct efx_nic *efx, u32 counter_idx,
				  u64 packets, u64 bytes)
{
	struct efx_tc_counter *cnt;

	/* TODO handle 1:1 counters and feed their aggs?  How do their ids
	 * get assigned, can we identify them here?
	 */
	rcu_read_lock(); /* Protect against deletion of 'cnt' */
	cnt = efx_tc_flower_find_counter_by_fw_id(efx, counter_idx);
	if (!cnt) {
		/* This could theoretically happen due to a race where an
		 * update from the counter is generated between allocating
		 * it and adding it to the hashtable, in
		 * efx_tc_flower_allocate_counter().  But during that race
		 * window, the counter will not yet have been attached to
		 * any action, so should not have counted any packets; thus
		 * the HW should not be sending updates (zero squash).
		 */
		if (net_ratelimit())
			netif_warn(efx, drv, efx->net_dev,
				   "Got update for unwanted MAE counter %u\n",
				   counter_idx);
		goto out;
	}

	spin_lock_bh(&cnt->lock);
	cnt->packets += packets;
	cnt->bytes += bytes;
	cnt->touched = jiffies;
	spin_unlock_bh(&cnt->lock);
	schedule_work(&cnt->work);
out:
	rcu_read_unlock();
}

static void efx_tc_rx_version_1(struct efx_nic *efx, const u8 *data)
{
	u16 seq_index, n_counters, i;

	/* Header format:
	 * + |   0    |   1    |   2    |   3    |
	 * 0 |version |         reserved         |
	 * 4 |    seq_index    |   n_counters    |
	 */

	seq_index = le16_to_cpu(*(const __le16 *)(data + 4));
	n_counters = le16_to_cpu(*(const __le16 *)(data + 6));

	/* Counter update entry format:
	 * | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
	 * |  counter_idx  |     packet_count      |      byte_count       |
	 */
	for (i = 0; i < n_counters; i++) {
		const void *entry = data + 8 + 16 * i;
		u64 packet_count, byte_count;
		u32 counter_idx;

		counter_idx = le32_to_cpu(*(const __le32 *)entry);
		packet_count = le32_to_cpu(*(const __le32 *)(entry + 4)) |
			       ((u64)le16_to_cpu(*(const __le16 *)(entry + 8)) << 32);
		byte_count = le16_to_cpu(*(const __le16 *)(entry + 10)) |
			     ((u64)le32_to_cpu(*(const __le32 *)(entry + 12)) << 16);
		efx_tc_counter_update(efx, counter_idx, packet_count, byte_count);
	}
}

#define TCV2_HDR_PTR(pkt, field)						\
	((void)BUILD_BUG_ON_ZERO(ERF_SC_PACKETISER_HEADER_##field##_LBN & 7),	\
	 (pkt) + ERF_SC_PACKETISER_HEADER_##field##_LBN / 8)
#define TCV2_HDR_BYTE(pkt, field)						\
	((void)BUILD_BUG_ON_ZERO(ERF_SC_PACKETISER_HEADER_##field##_WIDTH != 8),\
	 *TCV2_HDR_PTR(pkt, field))
#define TCV2_HDR_WORD(pkt, field)						\
	((void)BUILD_BUG_ON_ZERO(ERF_SC_PACKETISER_HEADER_##field##_WIDTH != 16),\
	 (void)BUILD_BUG_ON_ZERO(ERF_SC_PACKETISER_HEADER_##field##_LBN & 15),	\
	 *(__force const __le16 *)TCV2_HDR_PTR(pkt, field))
#define TCV2_PKT_PTR(pkt, poff, i, field)					\
	((void)BUILD_BUG_ON_ZERO(ERF_SC_PACKETISER_PAYLOAD_##field##_LBN & 7),	\
	 (pkt) + ERF_SC_PACKETISER_PAYLOAD_##field##_LBN/8 + poff +		\
	 i * ER_RX_SL_PACKETISER_PAYLOAD_WORD_SIZE)

/* Read a little-endian 48-bit field with 16-bit alignment */
static u64 efx_tc_read48(const __le16 *field)
{
	u64 out = 0;
	int i;

	for (i = 0; i < 3; i++)
		out |= le16_to_cpu(field[i]) << (i * 16);
	return out;
}

static void efx_tc_rx_version_2(struct efx_nic *efx, const u8 *data)
{
	u8 payload_offset, header_offset, ident;
	u16 n_counters, i;

	ident = TCV2_HDR_BYTE(data, IDENTIFIER);
	switch (ident) {
	case ERF_SC_PACKETISER_HEADER_IDENTIFIER_AR:
		break;
	case ERF_SC_PACKETISER_HEADER_IDENTIFIER_CT:
		/* TODO handle CT counters */
		return;
	default:
		if (net_ratelimit())
			netif_err(efx, drv, efx->net_dev,
				  "ignored v2 MAE counter packet (bad identifier %u"
				  "), counters may be inaccurate\n", ident);
		return;
	}
	header_offset = TCV2_HDR_BYTE(data, HEADER_OFFSET);
	/* mae_counter_format.h implies that this offset is fixed, since it
	 * carries on with SOP-based LBNs for the fields in this header
	 */
	if (header_offset != ERF_SC_PACKETISER_HEADER_HEADER_OFFSET_DEFAULT) {
		if (net_ratelimit())
			netif_err(efx, drv, efx->net_dev,
				  "choked on v2 MAE counter packet (bad header_offset %u"
				  "), counters may be inaccurate\n", header_offset);
		return;
	}
	payload_offset = TCV2_HDR_BYTE(data, PAYLOAD_OFFSET);
	n_counters = le16_to_cpu(TCV2_HDR_WORD(data, COUNT));

	for (i = 0; i < n_counters; i++) {
		const void *counter_idx_p, *packet_count_p, *byte_count_p;
		u64 packet_count, byte_count;
		u32 counter_idx;

		/* 24-bit field with 32-bit alignment */
		counter_idx_p = TCV2_PKT_PTR(data, payload_offset, i, COUNTER_INDEX);
		BUILD_BUG_ON(ERF_SC_PACKETISER_PAYLOAD_COUNTER_INDEX_WIDTH != 24);
		BUILD_BUG_ON(ERF_SC_PACKETISER_PAYLOAD_COUNTER_INDEX_LBN & 31);
		counter_idx = le32_to_cpu(*(const __le32 *)counter_idx_p) & 0xffffff;
		/* 48-bit field with 16-bit alignment */
		packet_count_p = TCV2_PKT_PTR(data, payload_offset, i, PACKET_COUNT);
		BUILD_BUG_ON(ERF_SC_PACKETISER_PAYLOAD_PACKET_COUNT_WIDTH != 48);
		BUILD_BUG_ON(ERF_SC_PACKETISER_PAYLOAD_PACKET_COUNT_LBN & 15);
		packet_count = efx_tc_read48((const __le16 *)packet_count_p);
		/* 48-bit field with 16-bit alignment */
		byte_count_p = TCV2_PKT_PTR(data, payload_offset, i, BYTE_COUNT);
		BUILD_BUG_ON(ERF_SC_PACKETISER_PAYLOAD_BYTE_COUNT_WIDTH != 48);
		BUILD_BUG_ON(ERF_SC_PACKETISER_PAYLOAD_BYTE_COUNT_LBN & 15);
		byte_count = efx_tc_read48((const __le16 *)byte_count_p);

		efx_tc_counter_update(efx, counter_idx, packet_count, byte_count);
	}
}

/* We always swallow the packet, whether successful or not, since it's not
 * a network packet and shouldn't ever be forwarded to the stack
 */
static bool efx_tc_rx(struct efx_channel *channel)
{
	struct efx_rx_buffer *rx_buf = efx_rx_buffer(&channel->rx_queue,
						     channel->rx_pkt_index);
	const u8 *data = efx_rx_buf_va(rx_buf);
	struct efx_nic *efx = channel->efx;
	u8 version;

	/* version is always first byte of packet */
	version = *data;
	switch (version) {
	case 1:
		efx_tc_rx_version_1(efx, data);
		break;
	case ERF_SC_PACKETISER_HEADER_VERSION_VALUE: // 2
		efx_tc_rx_version_2(efx, data);
		break;
	default:
		if (net_ratelimit())
			netif_err(efx, drv, efx->net_dev,
				  "choked on MAE counter packet (bad version %u"
				  "); counters may be inaccurate\n",
				  version);
		break;
	}

	efx_free_rx_buffers(&channel->rx_queue, rx_buf, 1);
	channel->rx_pkt_n_frags = 0;
	return true;
}

static const struct efx_channel_type efx_tc_channel_type = {
	.handle_no_channel	= efx_tc_handle_no_channel,
	.pre_probe		= efx_tc_probe_channel,
	.start			= efx_tc_start_channel,
	.stop			= efx_tc_stop_channel,
	.post_remove		= efx_tc_remove_channel,
	.get_name		= efx_tc_get_channel_name,
	/* no copy operation; there is no need to reallocate this channel */
	.receive_raw		= efx_tc_rx,
	.keep_eventq		= true,
	.hide_tx		= true,
};

int efx_init_struct_tc(struct efx_nic *efx)
{
	int rc, i;

	if (efx->type->is_vf || efx->tc)
		return 0;

	efx->tc = kzalloc(sizeof(*efx->tc), GFP_KERNEL);
	if (!efx->tc)
		return -ENOMEM;
	efx->tc->caps = kzalloc(sizeof(struct mae_caps), GFP_KERNEL);
	if (!efx->tc->caps) {
		rc = -ENOMEM;
		goto fail0;
	}
	INIT_LIST_HEAD(&efx->tc->block_list);

	mutex_init(&efx->tc->mutex);

	rc = rhashtable_init(&efx->tc->neigh_ht, &efx_neigh_ht_params);
	if (rc < 0)
		goto fail1;
	rc = rhashtable_init(&efx->tc->counter_id_ht, &efx_tc_counter_id_ht_params);
	if (rc < 0)
		goto fail2;
	rc = rhashtable_init(&efx->tc->counter_ht, &efx_tc_counter_ht_params);
	if (rc < 0)
		goto fail3;
	rc = rhashtable_init(&efx->tc->encap_ht, &efx_tc_encap_ht_params);
	if (rc < 0)
		goto fail4;
	rc = rhashtable_init(&efx->tc->encap_match_ht, &efx_tc_encap_match_ht_params);
	if(rc < 0)
		goto fail5;
	rc = rhashtable_init(&efx->tc->match_action_ht, &efx_tc_match_action_ht_params);
	if (rc < 0)
		goto fail6;
	rc = rhashtable_init(&efx->tc->lhs_rule_ht, &efx_tc_lhs_rule_ht_params);
	if (rc < 0)
		goto fail7;
	rc = rhashtable_init(&efx->tc->ctr_agg_ht, &efx_tc_ctr_agg_ht_params);
	if (rc < 0)
		goto fail8;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	rc = rhashtable_init(&efx->tc->ct_zone_ht, &efx_tc_ct_zone_ht_params);
	if (rc < 0)
		goto fail9;
	rc = rhashtable_init(&efx->tc->ct_ht, &efx_tc_ct_ht_params);
	if (rc < 0)
		goto fail10;
#endif
	rc = rhashtable_init(&efx->tc->recirc_ht, &efx_tc_recirc_ht_params);
	if (rc < 0)
		goto fail11;
	ida_init(&efx->tc->recirc_ida);
	efx->tc->reps_filter_uc = -1;
	efx->tc->reps_filter_mc = -1;
	/* TODO consider making this dynamically resized, rather than always
	 * allocating space for the maximum possible # of VFs
	 */
	efx->tc->dflt_rules = kcalloc(EFX_TC_DFLT__MAX,
					 sizeof(*efx->tc->dflt_rules),
					 GFP_KERNEL);
	rc = -ENOMEM;
	if (!efx->tc->dflt_rules)
		goto fail12;
	for (i = 0; i < EFX_TC_DFLT__MAX; i++) {
		efx->tc->dflt_rules[i].fw_id = MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL;
		efx->tc->dflt_rules[i].cookie = i;
	}
	efx->extra_channel_type[EFX_EXTRA_CHANNEL_TC] = &efx_tc_channel_type;
	return 0;
fail12:
	ida_destroy(&efx->tc->recirc_ida);
	rhashtable_destroy(&efx->tc->recirc_ht);
fail11:
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	rhashtable_destroy(&efx->tc->ct_ht);
fail10:
	rhashtable_destroy(&efx->tc->ct_zone_ht);
fail9:
#endif
	rhashtable_destroy(&efx->tc->ctr_agg_ht);
fail8:
	rhashtable_destroy(&efx->tc->lhs_rule_ht);
fail7:
	rhashtable_destroy(&efx->tc->match_action_ht);
fail6:
	rhashtable_destroy(&efx->tc->encap_match_ht);
fail5:
	rhashtable_destroy(&efx->tc->encap_ht);
fail4:
	rhashtable_destroy(&efx->tc->counter_id_ht);
fail3:
	rhashtable_destroy(&efx->tc->counter_ht);
fail2:
	rhashtable_destroy(&efx->tc->neigh_ht);
fail1:
	kfree(efx->tc->caps);
fail0:
	kfree(efx->tc);
	efx->tc = NULL;
	return rc;
}

void efx_fini_struct_tc(struct efx_nic *efx)
{
	if (efx->type->is_vf)
		return;

	if (!efx->tc)
		return;

	mutex_lock(&efx->tc->mutex);
	kfree(efx->tc->dflt_rules);
	rhashtable_free_and_destroy(&efx->tc->recirc_ht, efx_tc_recirc_free, efx);
	WARN_ON(!ida_is_empty(&efx->tc->recirc_ida));
	ida_destroy(&efx->tc->recirc_ida);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	rhashtable_free_and_destroy(&efx->tc->ct_ht, efx_tc_ct_free, efx);
	rhashtable_free_and_destroy(&efx->tc->ct_zone_ht, efx_tc_ct_zone_free, NULL);
#endif
	rhashtable_free_and_destroy(&efx->tc->lhs_rule_ht, efx_tc_lhs_free, efx);
	rhashtable_free_and_destroy(&efx->tc->ctr_agg_ht, efx_tc_ctr_agg_free, NULL);
	rhashtable_free_and_destroy(&efx->tc->match_action_ht, efx_tc_flow_free,
				    efx);
	rhashtable_free_and_destroy(&efx->tc->encap_match_ht, efx_tc_encap_match_free, NULL);
	rhashtable_free_and_destroy(&efx->tc->encap_ht, efx_tc_encap_free, NULL);
	rhashtable_free_and_destroy(&efx->tc->counter_id_ht, efx_tc_counter_id_free, NULL);
	rhashtable_free_and_destroy(&efx->tc->counter_ht, efx_tc_counter_free, NULL);
	rhashtable_free_and_destroy(&efx->tc->neigh_ht, efx_neigh_free, NULL);
	mutex_unlock(&efx->tc->mutex);
	mutex_destroy(&efx->tc->mutex);
	kfree(efx->tc->caps);
	kfree(efx->tc);
	efx->tc = NULL;
}

#define IS_ALL_ONES(v)	(!(typeof (v))~(v))

/* Boilerplate for the simple 'copy a field' cases */
#define _MAP_KEY_AND_MASK(_name, _type, _tcget, _tcfield, _field)	\
if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_##_name)) {		\
	struct flow_match_##_type fm;					\
									\
	flow_rule_match_##_tcget(rule, &fm);				\
	match->value._field = fm.key->_tcfield;				\
	match->mask._field = fm.mask->_tcfield;				\
}
#define MAP_KEY_AND_MASK(_name, _type, _tcfield, _field)	\
	_MAP_KEY_AND_MASK(_name, _type, _type, _tcfield, _field)
#define MAP_ENC_KEY_AND_MASK(_name, _type, _tcget, _tcfield, _field)	\
	_MAP_KEY_AND_MASK(ENC_##_name, _type, _tcget, _tcfield, _field)

static int efx_tc_flower_parse_match(struct efx_nic *efx,
				     struct flow_rule *rule,
				     struct efx_tc_match *match,
				     struct netlink_ext_ack *extack)
{
	struct flow_dissector *dissector = rule->match.dissector;
	unsigned char ipv = 0;

	/* Owing to internal TC infelicities, the IPV6_ADDRS key might be set
	 * even on IPv4 filters; so rather than relying on dissector->used_keys
	 * we check the addr_type in the CONTROL key.  If we don't find it (or
	 * it's masked, which should never happen), we treat both IPV4_ADDRS
	 * and IPV6_ADDRS as absent.
	 */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control fm;

		flow_rule_match_control(rule, &fm);
		if (IS_ALL_ONES(fm.mask->addr_type))
			switch (fm.key->addr_type) {
			case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
				ipv = 4;
				break;
			case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
				ipv = 6;
				break;
			default:
				break;
			}

		if (fm.mask->flags & FLOW_DIS_IS_FRAGMENT) {
			match->value.ip_frag = fm.key->flags & FLOW_DIS_IS_FRAGMENT;
			match->mask.ip_frag = true;
		}
		if (fm.mask->flags & ~FLOW_DIS_IS_FRAGMENT) {
			efx_tc_err(efx, "Unsupported match on control.flags %#x\n",
				   fm.mask->flags);
			NL_SET_ERR_MSG_MOD(extack, "Unsupported match on control.flags");
			return -EOPNOTSUPP;
		}
	}

	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_DISSECTOR_KEY_CVLAN)
	      BIT(FLOW_DISSECTOR_KEY_CVLAN) |
#endif
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_ENC_CONTROL) |
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	      BIT(FLOW_DISSECTOR_KEY_CT) |
#endif
	      BIT(FLOW_DISSECTOR_KEY_TCP) |
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_DISSECTOR_KEY_ENC_IP)
	      BIT(FLOW_DISSECTOR_KEY_ENC_IP) |
#endif
	      BIT(FLOW_DISSECTOR_KEY_IP))) {
		efx_tc_err(efx, "Unsupported flower keys %#x\n", dissector->used_keys);
		NL_SET_ERR_MSG_MOD(extack, "Unsupported flower keys encountered");
		return -EOPNOTSUPP;
	}

	MAP_KEY_AND_MASK(BASIC, basic, n_proto, eth_proto);
	/* Make sure we're IP if any L3/L4 keys used. */
	if (!IS_ALL_ONES(match->mask.eth_proto) ||
	    !(match->value.eth_proto == htons(ETH_P_IP) ||
	      match->value.eth_proto == htons(ETH_P_IPV6)))
		if (dissector->used_keys &
		    (BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
		     BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
		     BIT(FLOW_DISSECTOR_KEY_PORTS) |
		     BIT(FLOW_DISSECTOR_KEY_IP) |
		     BIT(FLOW_DISSECTOR_KEY_TCP))) {
			efx_tc_err(efx, "Flower keys %#x require protocol ipv[46]\n",
				   dissector->used_keys);
			NL_SET_ERR_MSG_MOD(extack, "L3/L4 keys without L2 protocol IPv4/6");
			return -EINVAL;
		}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan fm;

		flow_rule_match_vlan(rule, &fm);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_DISSECTOR_VLAN_TPID)
		if (fm.mask->vlan_id || fm.mask->vlan_priority || fm.mask->vlan_tpid) {
			if (fm.mask->vlan_tpid && !IS_ALL_ONES(fm.mask->vlan_tpid)) {
				efx_tc_err(efx, "Unsupported masking (%#x) of VLAN ethertype\n",
					   fm.mask->vlan_tpid);
				NL_SET_ERR_MSG_MOD(extack, "VLAN ethertype masking not supported");
				return -EOPNOTSUPP;
			}
			match->value.vlan_proto[0] = fm.key->vlan_tpid;
			match->mask.vlan_proto[0] = fm.mask->vlan_tpid;
#else
		if (fm.mask->vlan_id || fm.mask->vlan_priority) {
#endif
			match->value.vlan_tci[0] = cpu_to_be16(fm.key->vlan_priority << 13 |
							       fm.key->vlan_id);
			match->mask.vlan_tci[0] = cpu_to_be16(fm.mask->vlan_priority << 13 |
							      fm.mask->vlan_id);
		}
	}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_DISSECTOR_KEY_CVLAN)
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		struct flow_match_vlan fm;

		flow_rule_match_cvlan(rule, &fm);
		if (fm.mask->vlan_id || fm.mask->vlan_priority || fm.mask->vlan_tpid) {
			if (fm.mask->vlan_tpid && !IS_ALL_ONES(fm.mask->vlan_tpid)) {
				efx_tc_err(efx, "Unsupported masking (%#x) of CVLAN ethertype\n",
					   fm.mask->vlan_tpid);
				NL_SET_ERR_MSG_MOD(extack, "CVLAN ethertype masking not supported");
				return -EOPNOTSUPP;
			}
			match->value.vlan_proto[1] = fm.key->vlan_tpid;
			match->mask.vlan_proto[1] = fm.mask->vlan_tpid;
			match->value.vlan_tci[1] = cpu_to_be16(fm.key->vlan_priority << 13 |
							       fm.key->vlan_id);
			match->mask.vlan_tci[1] = cpu_to_be16(fm.mask->vlan_priority << 13 |
							      fm.mask->vlan_id);
		}
	}
#endif
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs fm;

		flow_rule_match_eth_addrs(rule, &fm);
		ether_addr_copy(match->value.eth_saddr, fm.key->src);
		ether_addr_copy(match->value.eth_daddr, fm.key->dst);
		ether_addr_copy(match->mask.eth_saddr, fm.mask->src);
		ether_addr_copy(match->mask.eth_daddr, fm.mask->dst);
	}
	MAP_KEY_AND_MASK(BASIC, basic, ip_proto, ip_proto);
	/* Make sure we're TCP/UDP if any L4 keys used. */
	if ((match->value.ip_proto != IPPROTO_UDP &&
	     match->value.ip_proto != IPPROTO_TCP) || !IS_ALL_ONES(match->mask.ip_proto))
		if (dissector->used_keys &
		    (BIT(FLOW_DISSECTOR_KEY_PORTS) |
		     BIT(FLOW_DISSECTOR_KEY_TCP))) {
			efx_tc_err(efx, "Flower keys %#x require ipproto udp or tcp\n",
				   dissector->used_keys);
			NL_SET_ERR_MSG_MOD(extack, "L4 keys without ipproto udp/tcp");
			return -EINVAL;
		}
	MAP_KEY_AND_MASK(IP, ip, tos, ip_tos);
	MAP_KEY_AND_MASK(IP, ip, ttl, ip_ttl);
	if (ipv == 4) {
		MAP_KEY_AND_MASK(IPV4_ADDRS, ipv4_addrs, src, src_ip);
		MAP_KEY_AND_MASK(IPV4_ADDRS, ipv4_addrs, dst, dst_ip);
	} else if (ipv == 6) {
		MAP_KEY_AND_MASK(IPV6_ADDRS, ipv6_addrs, src, src_ip6);
		MAP_KEY_AND_MASK(IPV6_ADDRS, ipv6_addrs, dst, dst_ip6);
	}
	MAP_KEY_AND_MASK(PORTS, ports, src, l4_sport);
	MAP_KEY_AND_MASK(PORTS, ports, dst, l4_dport);
	MAP_KEY_AND_MASK(TCP, tcp, flags, tcp_flags);
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_CONTROL)) {
		struct flow_match_control fm;

		flow_rule_match_enc_control(rule, &fm);
		if (!IS_ALL_ONES(fm.mask->addr_type)) {
			efx_tc_err(efx, "Unsupported enc addr_type mask %u (key %u).\n",
				   fm.mask->addr_type, fm.key->addr_type);
			NL_SET_ERR_MSG_MOD(extack, "Masked enc addr_type");
			return -EOPNOTSUPP;
		}
		switch (fm.key->addr_type) {
		case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
			MAP_ENC_KEY_AND_MASK(IPV4_ADDRS, ipv4_addrs, enc_ipv4_addrs,
					     src, enc_src_ip);
			MAP_ENC_KEY_AND_MASK(IPV4_ADDRS, ipv4_addrs, enc_ipv4_addrs,
					     dst, enc_dst_ip);
			break;
		case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
			MAP_ENC_KEY_AND_MASK(IPV6_ADDRS, ipv6_addrs, enc_ipv6_addrs,
					     src, enc_src_ip6);
			MAP_ENC_KEY_AND_MASK(IPV6_ADDRS, ipv6_addrs, enc_ipv6_addrs,
					     dst, enc_dst_ip6);
			break;
		default:
			efx_tc_err(efx, "Unsupported enc addr_type %u\n",
				   fm.key->addr_type);
			NL_SET_ERR_MSG_MOD(extack, "Unsupported enc addr_type (supported are IPv4, IPv6)");
			return -EOPNOTSUPP;
		}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_DISSECTOR_KEY_ENC_IP)
		MAP_ENC_KEY_AND_MASK(IP, ip, enc_ip, tos, enc_ip_tos);
		MAP_ENC_KEY_AND_MASK(IP, ip, enc_ip, ttl, enc_ip_ttl);
#endif
		MAP_ENC_KEY_AND_MASK(PORTS, ports, enc_ports, src, enc_sport);
		MAP_ENC_KEY_AND_MASK(PORTS, ports, enc_ports, dst, enc_dport);
		MAP_ENC_KEY_AND_MASK(KEYID, enc_keyid, enc_keyid, keyid, enc_keyid);
	} else if (dissector->used_keys &
		   (BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
		    BIT(FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS) |
		    BIT(FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS) |
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_DISSECTOR_KEY_ENC_IP)
		    BIT(FLOW_DISSECTOR_KEY_ENC_IP) |
#endif
		    BIT(FLOW_DISSECTOR_KEY_ENC_PORTS))) {
		efx_tc_err(efx, "Flower enc keys require enc_control (keys: %#x)\n",
			   dissector->used_keys);
		NL_SET_ERR_MSG_MOD(extack, "Flower enc keys without enc_control");
		return -EOPNOTSUPP;
	}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CT)) {
		struct flow_match_ct fm;

		flow_rule_match_ct(rule, &fm);
#define MAP_CT_STATE(_bit, _NAME) do {					       \
	match->value.ct_state_##_bit = !!(fm.key->ct_state & TCA_FLOWER_KEY_CT_FLAGS_##_NAME);\
	match->mask.ct_state_##_bit = !!(fm.mask->ct_state & TCA_FLOWER_KEY_CT_FLAGS_##_NAME);\
} while(0)
		MAP_CT_STATE(new, NEW);
		MAP_CT_STATE(est, ESTABLISHED);
		MAP_CT_STATE(rel, RELATED);
		MAP_CT_STATE(trk, TRACKED);
#undef MAP_CT_STATE
		match->value.ct_mark = fm.key->ct_mark;
		match->mask.ct_mark = fm.mask->ct_mark;
		if (fm.mask->ct_zone) {
			EFX_TC_ERR_MSG(efx, extack, "Matching on ct_zone not supported");
			return -EOPNOTSUPP;
		}
		if (memchr_inv(fm.mask->ct_labels, 0, sizeof(fm.mask->ct_labels))) {
			EFX_TC_ERR_MSG(efx, extack, "Matching on ct_label not supported");
			return -EOPNOTSUPP;
		}
	}
#endif
	return 0;
}
#undef MAP_KEY_AND_MASK

static bool efx_ipv6_addr_all_ones(struct in6_addr *addr)
{
	return !memchr_inv(addr, 0xff, sizeof(*addr));
}

static int efx_tc_flower_record_encap_match(struct efx_nic *efx,
					    struct efx_tc_match *match,
					    enum efx_encap_type type)
{
	struct efx_tc_encap_match *encap, *old;
	unsigned char ipv;
	int rc;

	/* We require that the socket-defining fields (IP addrs and UDP dest
	 * port) are present and exact-match.  Other fields are currently not
	 * allowed.  This meets what OVS will ask for, and means that we don't
	 * need to handle difficult checks for overlapping matches as could
	 * come up if we allowed masks or varying sets of match fields.
	 */
	if (match->mask.enc_dst_ip | match->mask.enc_src_ip) {
		ipv = 4;
		if (!IS_ALL_ONES(match->mask.enc_dst_ip)) {
			efx_tc_err(efx, "Egress encap match is not exact on dst IP address\n");
			return -EOPNOTSUPP;
		}
		if (!IS_ALL_ONES(match->mask.enc_src_ip)) {
			efx_tc_err(efx, "Egress encap match is not exact on src IP address\n");
			return -EOPNOTSUPP;
		}
		if (!ipv6_addr_any(&match->mask.enc_dst_ip6) ||
		    !ipv6_addr_any(&match->mask.enc_src_ip6)) {
			efx_tc_err(efx, "Egress encap match on both IPv4 and IPv6, don't understand\n");
			return -EOPNOTSUPP;
		}
	} else {
		ipv = 6;
		if (!efx_ipv6_addr_all_ones(&match->mask.enc_dst_ip6)) {
			efx_tc_err(efx, "Egress encap match is not exact on dst IP address\n");
			return -EOPNOTSUPP;
		}
		if (!efx_ipv6_addr_all_ones(&match->mask.enc_src_ip6)) {
			efx_tc_err(efx, "Egress encap match is not exact on src IP address\n");
			return -EOPNOTSUPP;
		}
	}
	if (!IS_ALL_ONES(match->mask.enc_dport)) {
		efx_tc_err(efx, "Egress encap match is not exact on dst UDP port\n");
		return -EOPNOTSUPP;
	}
	if (match->mask.enc_sport) {
		efx_tc_err(efx, "Egress encap match on src UDP port not supported\n");
		return -EOPNOTSUPP;
	}
	if (match->mask.enc_ip_tos) {
		efx_tc_err(efx, "Egress encap match on IP ToS not supported\n");
		return -EOPNOTSUPP;
	}
	if (match->mask.enc_ip_ttl) {
		efx_tc_err(efx, "Egress encap match on IP TTL not supported\n");
		return -EOPNOTSUPP;
	}

	rc = efx_mae_check_encap_match_caps(efx, ipv);
	if (rc) {
		efx_tc_err(efx, "MAE hw reports no support for IPv%d encap matches\n", ipv);
		return rc;
	}

	encap = kzalloc(sizeof(*encap), GFP_USER);
	if (!encap)
		return -ENOMEM;
	switch (ipv) {
	case 4:
		encap->src_ip = match->value.enc_src_ip;
		encap->dst_ip = match->value.enc_dst_ip;
		break;
	case 6:
		encap->src_ip6 = match->value.enc_src_ip6;
		encap->dst_ip6 = match->value.enc_dst_ip6;
		break;
	default: /* can't happen */
		netif_err(efx, hw, efx->net_dev, "Egress encap match is IP version %d, huh?\n", ipv);
		kfree(encap);
		return -EOPNOTSUPP;
	}
	encap->udp_dport = match->value.enc_dport;
	encap->tun_type = type;
	old = rhashtable_lookup_get_insert_fast(&efx->tc->encap_match_ht,
						&encap->linkage,
						efx_tc_encap_match_ht_params);
	if (old) {
		/* don't need our new entry */
		kfree(encap);
		if (old->tun_type != type) {
			netif_err(efx, drv, efx->net_dev, "Egress encap match with conflicting tun_type\n");
			return -EEXIST;
		}
		if (!refcount_inc_not_zero(&old->ref))
			return -EAGAIN;
		/* existing entry found */
		encap = old;
	} else {
		char buf[128];

		switch (ipv) {
		case 4:
			snprintf(buf, sizeof(buf), "%pI4->%pI4",
				 &encap->src_ip, &encap->dst_ip);
			break;
		case 6:
			snprintf(buf, sizeof(buf), "%pI6c->%pI6c",
				 &encap->src_ip6, &encap->dst_ip6);
			break;
		default: /* can't happen */
			snprintf(buf, sizeof(buf), "[IP version %d, huh?]", ipv);
			break;
		}
		rc = efx_mae_register_encap_match(efx, encap);
		if (rc) {
			netif_err(efx, drv, efx->net_dev,
				  "Failed to record encap match %s:%u, rc %d\n",
				  buf, ntohs(encap->udp_dport), rc);
			goto fail;
		}
		netif_dbg(efx, drv, efx->net_dev,
			  "Recorded new encap match %s:%u\n",
			  buf, ntohs(encap->udp_dport));
		refcount_set(&encap->ref, 1);
	}
	match->encap = encap;
	return 0;
fail:
	rhashtable_remove_fast(&efx->tc->encap_match_ht, &encap->linkage,
			       efx_tc_encap_match_ht_params);
	kfree(encap);
	return rc;
}

static void efx_tc_flower_release_encap_match(struct efx_nic *efx,
					      struct efx_tc_encap_match *encap)
{
	char buf[128];
	int rc;

	if (!refcount_dec_and_test(&encap->ref))
		return; /* still in use */

	if (encap->src_ip | encap->dst_ip)
		snprintf(buf, sizeof(buf), "%pI4->%pI4",
			 &encap->src_ip, &encap->dst_ip);
	else
		snprintf(buf, sizeof(buf), "%pI6c->%pI6c",
			 &encap->src_ip6, &encap->dst_ip6);
	rc = efx_mae_unregister_encap_match(efx, encap);
	if (rc)
		/* Display message but carry on and remove entry from our
		 * SW tables, because there's not much we can do about it.
		 */
		netif_err(efx, drv, efx->net_dev,
			  "Failed to release encap match %s:%u, rc %d\n",
			  buf, ntohs(encap->udp_dport), rc);
	else
		netif_dbg(efx, drv, efx->net_dev,
			  "Released encap match %s:%u\n",
			  buf, ntohs(encap->udp_dport));
	rhashtable_remove_fast(&efx->tc->encap_match_ht, &encap->linkage,
			       efx_tc_encap_match_ht_params);
	kfree(encap);
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
static enum efx_encap_type efx_tc_egdev_udp_type(struct efx_nic *efx,
						 struct efx_tc_match *match)
{
	__be16 udp_dport;

	if (!IS_ALL_ONES(match->mask.enc_dport))
		return EFX_ENCAP_TYPE_NONE;
	udp_dport = match->value.enc_dport;
	if (efx->type->udp_tnl_lookup_port2)
		return efx->type->udp_tnl_lookup_port2(efx, udp_dport);

	return EFX_ENCAP_TYPE_NONE;
}
#endif

static const char *efx_tc_encap_type_names[] = {
	[EFX_ENCAP_TYPE_NONE] = "none",
	[EFX_ENCAP_TYPE_VXLAN] = "vxlan",
	[EFX_ENCAP_TYPE_NVGRE] = "nvgre",
	[EFX_ENCAP_TYPE_GENEVE] = "geneve",
};

enum efx_tc_action_order {
	EFX_TC_AO_DECAP,
	EFX_TC_AO_VLAN1_POP,
	EFX_TC_AO_VLAN0_POP,
	EFX_TC_AO_PEDIT,
	EFX_TC_AO_VLAN0_PUSH,
	EFX_TC_AO_VLAN1_PUSH,
	EFX_TC_AO_COUNT,
	EFX_TC_AO_ENCAP,
	EFX_TC_AO_DELIVER
};
/* Determine whether we can add @new action without violating order */
static bool efx_tc_flower_action_order_ok(const struct efx_tc_action_set *act,
					  enum efx_tc_action_order new)
{
	switch (new) {
	case EFX_TC_AO_DECAP:
		if (act->decap)
			return false;
		/* fall through */
	case EFX_TC_AO_VLAN0_POP:
		if (act->vlan_pop & 1)
			return false;
		/* fall through */
	case EFX_TC_AO_VLAN1_POP:
		if (act->vlan_pop & 2)
			return false;
		/* fall through */
	case EFX_TC_AO_PEDIT:
		if (act->pedit_md)
			return false;
		/* fall through */
	case EFX_TC_AO_VLAN0_PUSH:
		if (act->vlan_push & 1)
			return false;
		/* fall through */
	case EFX_TC_AO_VLAN1_PUSH:
		if (act->vlan_push & 2)
			return false;
		/* fall through */
	case EFX_TC_AO_COUNT:
		if (act->count)
			return false;
		/* fall through */
	case EFX_TC_AO_ENCAP:
		if (act->encap_md)
			return false;
		/* fall through */
	case EFX_TC_AO_DELIVER:
		return !act->deliver;
	default:
		/* Bad caller.  Whatever they wanted to do, say they can't. */
		WARN_ON_ONCE(1);
		return false;
	}
}

static int efx_tc_flower_replace_foreign(struct efx_nic *efx,
					 struct net_device *net_dev,
					 struct flow_cls_offload *tc)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	struct flow_rule *fr = flow_cls_offload_flow_rule(tc);
#else
	struct flow_rule *fr;
#endif
	struct efx_tc_flow_rule *rule = NULL, *old = NULL;
	struct efx_tc_action_set *act = NULL;
	bool found = false, uplinked = false;
	const struct flow_action_entry *fa;
	struct efx_tc_match match;
	long rc;
	int i;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	fr = efx_compat_flow_rule_build(tc);
	if (IS_ERR(fr)) {
		netif_err(efx, drv, efx->net_dev,
			  "Failed to convert tc cls to a flow_rule (rc %ld)\n",
			  PTR_ERR(fr));
		return PTR_ERR(fr);
	}
#endif

	flow_action_for_each(i, fa, &fr->action) {
		switch (fa->id) {
		case FLOW_ACTION_REDIRECT:
		case FLOW_ACTION_MIRRED: /* mirred means mirror here */
			rc = efx_tc_flower_lookup_dev(efx, fa->dev);
			if (rc < 0)
				continue;
			found = true;
			break;
		default:
			break;
		}
	}
	if (!found) { /* We don't care. */
		netif_dbg(efx, drv, efx->net_dev, "Ignoring foreign filter that doesn't egdev us\n");
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
		kfree(fr);
#endif
		return -EOPNOTSUPP;
	}

	/* Parse match */
	memset(&match, 0, sizeof(match));
	/* No ingress_port filtering; tunnel decap is on every port.
	 * This probably isn't the right thing, but I haven't yet figured out
	 * what is.
	 */
	rc = efx_tc_flower_parse_match(efx, fr, &match, NULL);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	if (rc)
		return rc;
#else
	if (rc) {
		kfree(fr);
		return rc;
	}
#endif
	rc = efx_mae_match_check_caps(efx, &match.mask, NULL);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	if (rc)
		return rc;
#else
	if (rc) {
		kfree(fr);
		return rc;
	}
#endif

	if (efx_tc_match_is_encap(&match.mask)) {
		enum efx_encap_type type;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) || defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
		type = efx_tc_indr_netdev_type(net_dev);
#else
		/* This is deeply unsatisfactory: we're using the UDP port to
		 * determine the tunnel type but then still inserting a full
		 * match (with IP addresses) into the encap match table in hw.
		 */
		type = efx_tc_egdev_udp_type(efx, &match);
#endif
		if (type == EFX_ENCAP_TYPE_NONE) {
			efx_tc_err(efx, "Egress encap match on unsupported tunnel device\n");
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
			kfree(fr);
#endif
			return -EOPNOTSUPP;
		}

		rc = efx_mae_check_encap_type_supported(efx, type);
		if (rc) {
			if (type < ARRAY_SIZE(efx_tc_encap_type_names))
				efx_tc_err(efx, "Firmware reports no support for %s encap match\n",
					   efx_tc_encap_type_names[type]);
			else
				efx_tc_err(efx, "Firmware reports no support for type %u encap match\n",
					   type);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
			kfree(fr);
#endif
			return rc;
		}

		rc = efx_tc_flower_record_encap_match(efx, &match, type);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_TC_FLOW_OFFLOAD)
		if (rc)
			return rc;
#else
		if (rc) {
			kfree(fr);
			return rc;
		}
#endif
	}

	rule = kzalloc(sizeof(*rule), GFP_USER);
	if (!rule) {
		rc = -ENOMEM;
		goto release;
	}
	INIT_LIST_HEAD(&rule->acts.list);
	rule->cookie = tc->cookie;
	old = rhashtable_lookup_get_insert_fast(&efx->tc->match_action_ht,
						&rule->linkage,
						efx_tc_match_action_ht_params);
	if (old) {
		netif_dbg(efx, drv, efx->net_dev,
			  "Ignoring already-offloaded rule (cookie %lx)\n",
			  tc->cookie);
		rc = -EEXIST;
		goto release;
	}

	/* Parse actions */
	act = kzalloc(sizeof(*act), GFP_USER);
	if (!act) {
		rc = -ENOMEM;
		goto release;
	}

	/* Parse actions.  For foreign rules we only support decap & redirect */
	flow_action_for_each(i, fa, &fr->action) {
		struct efx_tc_action_set save;

		switch (fa->id) {
		case FLOW_ACTION_REDIRECT:
		case FLOW_ACTION_MIRRED:
			/* See corresponding code in efx_tc_flower_replace() for
			 * long explanations of what's going on here.
			 */
			save = *act;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_HW_STATS_TYPE)
			if (fa->hw_stats) {
				if (!(fa->hw_stats & FLOW_ACTION_HW_STATS_DELAYED)) {
					efx_tc_err(efx, "hw_stats_type %u not supported (only 'delayed')\n",
						   fa->hw_stats);
					rc = -EOPNOTSUPP;
					goto release;
				}
#endif
				if (!efx_tc_flower_action_order_ok(act, EFX_TC_AO_COUNT)) {
					rc = -EOPNOTSUPP;
					goto release;
				} else {
					struct efx_tc_counter_index *ctr;

					ctr = efx_tc_flower_get_counter_index(efx,
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_TC_ACTION_COOKIE)
									      fa->cookie);
#else
									      tc->cookie);
#endif
					if (IS_ERR(ctr)) {
						rc = PTR_ERR(ctr);
						goto release;
					}
					act->count = ctr;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
					act->count_action_idx = i;
#endif
					INIT_LIST_HEAD(&act->count_user);
				}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_HW_STATS_TYPE)
			}
#endif

			if (!efx_tc_flower_action_order_ok(act, EFX_TC_AO_DELIVER)) {
				/* can't happen */
				rc = -EOPNOTSUPP;
				goto release;
			}
			rc = efx_tc_flower_lookup_dev(efx, fa->dev);
			/* PF implies egdev is us, in which case we really
			 * want to deliver to the uplink (because this is an
			 * ingress filter).  If we don't recognise the egdev
			 * at all, then we'd better trap so SW can handle it.
			 */
			if (rc < 0)
				rc = EFX_VPORT_PF;
			if (rc == EFX_VPORT_PF) {
				if (uplinked)
					break;
				uplinked = true;
			}
			rc = efx_tc_flower_internal_mport(efx, rc);
			if (rc < 0)
				goto release;
			act->dest_mport = rc;
			act->deliver = 1;
			rc = efx_mae_alloc_action_set(efx, act);
			if (rc)
				goto release;
			list_add_tail(&act->list, &rule->acts.list);
			act = NULL;
			if (fa->id == FLOW_ACTION_REDIRECT)
				break; /* end of the line */
			/* Mirror, so continue on with saved act */
			act = kzalloc(sizeof(*act), GFP_USER);
			if (!act) {
				rc = -ENOMEM;
				goto release;
			}
			*act = save;
			break;
		case FLOW_ACTION_TUNNEL_DECAP:
			if (!efx_tc_flower_action_order_ok(act, EFX_TC_AO_DECAP)) {
				rc = -EINVAL;
				goto release;
			}
			act->decap = 1;
			/* If we previously delivered/trapped to uplink, now
			 * that we've decapped we'll want another copy if we
			 * try to deliver/trap to uplink again.
			 */
			uplinked = false;
			break;
		default:
			efx_tc_err(efx, "Unhandled action %u\n", fa->id);
			rc = -EOPNOTSUPP;
			goto release;
		}
	}

	if (act) {
		if (!uplinked) {
			/* Not shot/redirected, so deliver to default dest (which is
			 * the uplink, as this is an ingress filter)
			 */
			efx_mae_mport_uplink(efx, &act->dest_mport);
			act->deliver = 1;
		}
		rc = efx_mae_alloc_action_set(efx, act);
		if (rc)
			goto release;
		list_add_tail(&act->list, &rule->acts.list);
		act = NULL; /* Prevent double-free in error path */
	}

	rule->match = match;

	netif_dbg(efx, drv, efx->net_dev,
		  "Successfully parsed foreign filter (cookie %lx)\n",
		  tc->cookie);

	if (!efx_tc_check_ready(efx, rule)) {
		/* can't happen, as foreign filters don't support encap actions */
		netif_err(efx, drv, efx->net_dev, "action not ready for hw\n");
		rc = -EOPNOTSUPP;
		goto release;
	}
	rc = efx_mae_alloc_action_set_list(efx, &rule->acts);
	if (rc)
		goto release;
	rc = efx_mae_insert_rule(efx, &rule->match, EFX_TC_PRIO_TC,
				 rule->acts.fw_id, &rule->fw_id);
	if (rc)
		goto release_act;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	kfree(fr);
#endif
	return 0;

release_act:
	efx_mae_free_action_set_list(efx, &rule->acts);
release:
	/* We failed to insert the rule, so free up any entries we created in
	 * subsidiary tables.
	 */
	if (act)
		efx_tc_free_action_set(efx, act, false);
	if (rule) {
		rhashtable_remove_fast(&efx->tc->match_action_ht,
				       &rule->linkage,
				       efx_tc_match_action_ht_params);
		efx_tc_free_action_set_list(efx, &rule->acts, false);
	}
	kfree(rule);
	if (match.encap)
		efx_tc_flower_release_encap_match(efx, match.encap);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	kfree(fr);
#endif
	return rc;
}

static bool efx_tc_rule_is_lhs_rule(struct flow_rule *fr,
				    struct efx_tc_match *match)
{
	const struct flow_action_entry *fa;
	int i;

	flow_action_for_each(i, fa, &fr->action) {
		switch (fa->id) {
		case FLOW_ACTION_GOTO:
			return true;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
		case FLOW_ACTION_CT:
			/* If rule is -trk, or doesn't mention trk at all, then
			 * a CT action implies a conntrack lookup (hence it's an
			 * LHS rule).  If rule is +trk, then a CT action could
			 * just be ct(nat) or even ct(commit) (though the latter
			 * can't be offloaded).
			 */
			if (!match->mask.ct_state_trk || !match->value.ct_state_trk)
				return true;
#endif
		default:
			break;
		}
	}
	return false;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
#if IS_ENABLED(CONFIG_NF_FLOW_TABLE)
#define EFX_NF_TCP_FLAG(flg)	cpu_to_be16(be32_to_cpu(TCP_FLAG_##flg) >> 16)

static int efx_tc_ct_parse_match(struct efx_nic *efx, struct flow_rule *fr,
				 struct efx_tc_ct_entry *conn)
{
	struct flow_dissector *dissector = fr->match.dissector;
	unsigned char ipv = 0;
	bool tcp = false;

	if (flow_rule_match_key(fr, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control fm;

		flow_rule_match_control(fr, &fm);
		if (IS_ALL_ONES(fm.mask->addr_type))
			switch (fm.key->addr_type) {
			case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
				ipv = 4;
				break;
			case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
				ipv = 6;
				break;
			default:
				break;
			}
	}

	if (!ipv) {
		efx_tc_err(efx, "Conntrack missing ipv specification\n");
		return -EOPNOTSUPP;
	}

	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_TCP) |
	      BIT(FLOW_DISSECTOR_KEY_META))) {
		efx_tc_err(efx, "Unsupported conntrack keys %#x\n", dissector->used_keys);
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(fr, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic fm;

		flow_rule_match_basic(fr, &fm);
		if (!IS_ALL_ONES(fm.mask->n_proto)) {
			efx_tc_err(efx, "Conntrack eth_proto is not exact-match; mask %04x\n",
				   ntohs(fm.mask->n_proto));
			return -EOPNOTSUPP;
		}
		conn->eth_proto = fm.key->n_proto;
		if (conn->eth_proto != (ipv == 4 ? htons(ETH_P_IP)
						 : htons(ETH_P_IPV6))) {
			efx_tc_err(efx,  "Conntrack eth_proto is not IPv%hhu, is %04x\n",
				   ipv, ntohs(conn->eth_proto));
			return -EOPNOTSUPP;
		}
		if (!IS_ALL_ONES(fm.mask->ip_proto)) {
			efx_tc_err(efx, "Conntrack ip_proto is not exact-match; mask %02x\n",
				   fm.mask->ip_proto);
			return -EOPNOTSUPP;
		}
		conn->ip_proto = fm.key->ip_proto;
		switch (conn->ip_proto) {
		case IPPROTO_TCP:
			tcp = true;
			break;
		case IPPROTO_UDP:
			break;
		default:
			efx_tc_err(efx, "Conntrack ip_proto not TCP or UDP, is %02x\n",
				   conn->ip_proto);
			return -EOPNOTSUPP;
		}
	} else {
		efx_tc_err(efx, "Conntrack missing eth_proto, ip_proto\n");
		return -EOPNOTSUPP;
	}

	if (ipv == 4 && flow_rule_match_key(fr, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		struct flow_match_ipv4_addrs fm;

		flow_rule_match_ipv4_addrs(fr, &fm);
		if (!IS_ALL_ONES(fm.mask->src)) {
			efx_tc_err(efx, "Conntrack ipv4.src is not exact-match; mask %08x\n",
				   ntohl(fm.mask->src));
			return -EOPNOTSUPP;
		}
		conn->src_ip = fm.key->src;
		if (!IS_ALL_ONES(fm.mask->dst)) {
			efx_tc_err(efx, "Conntrack ipv4.dst is not exact-match; mask %08x\n",
				   ntohl(fm.mask->dst));
			return -EOPNOTSUPP;
		}
		conn->dst_ip = fm.key->dst;
	} else if (ipv == 6 && flow_rule_match_key(fr, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
		struct flow_match_ipv6_addrs fm;

		flow_rule_match_ipv6_addrs(fr, &fm);
		if (!efx_ipv6_addr_all_ones(&fm.mask->src)) {
			efx_tc_err(efx, "Conntrack ipv6.src is not exact-match; mask %pI6\n",
				   &fm.mask->src);
			return -EOPNOTSUPP;
		}
		conn->src_ip6 = fm.key->src;
		if (!efx_ipv6_addr_all_ones(&fm.mask->dst)) {
			efx_tc_err(efx, "Conntrack ipv6.dst is not exact-match; mask %pI6\n",
				   &fm.mask->dst);
			return -EOPNOTSUPP;
		}
		conn->dst_ip6 = fm.key->dst;
	} else {
		efx_tc_err(efx, "Conntrack missing IPv%hhu addrs\n", ipv);
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(fr, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports fm;

		flow_rule_match_ports(fr, &fm);
		if (!IS_ALL_ONES(fm.mask->src)) {
			efx_tc_err(efx, "Conntrack ports.src is not exact-match; mask %04x\n",
				   ntohs(fm.mask->src));
			return -EOPNOTSUPP;
		}
		conn->l4_sport = fm.key->src;
		if (!IS_ALL_ONES(fm.mask->dst)) {
			efx_tc_err(efx, "Conntrack ports.dst is not exact-match; mask %04x\n",
				   ntohs(fm.mask->dst));
			return -EOPNOTSUPP;
		}
		conn->l4_dport = fm.key->dst;
	}
	/* TODO reject if ports not specified? */

	if (flow_rule_match_key(fr, FLOW_DISSECTOR_KEY_TCP)) {
		__be16 tcp_interesting_flags;
		struct flow_match_tcp fm;

		flow_rule_match_tcp(fr, &fm);
		tcp_interesting_flags = EFX_NF_TCP_FLAG(SYN) |
					EFX_NF_TCP_FLAG(RST) |
					EFX_NF_TCP_FLAG(FIN);
		/* If any of the tcp_interesting_flags is set, the NIC will
		 * inhibit CT lookup.
		 */
		if (fm.key->flags & tcp_interesting_flags) {
			efx_tc_err(efx, "Unsupported conntrack tcp.flags %04x/%04x\n",
				   ntohs(fm.key->flags), ntohs(fm.mask->flags));
			return -EOPNOTSUPP;
		}
		/* Other TCP flags cannot be filtered at CT */
		if (fm.mask->flags & ~tcp_interesting_flags) {
			efx_tc_err(efx, "Unsupported conntrack tcp.flags %04x/%04x\n",
				   ntohs(fm.key->flags), ntohs(fm.mask->flags));
			return -EOPNOTSUPP;
		}
	}

	if (flow_rule_match_key(fr, FLOW_DISSECTOR_KEY_META)) {
		struct flow_match_meta fm;

		flow_rule_match_meta(fr, &fm);
		/* TODO check this matches something sane? */
		efx_tc_err(efx, "Conntrack ifindex %08x/%08x\n",
			   fm.key->ingress_ifindex, fm.mask->ingress_ifindex);
	}

	return 0;
}

struct efx_tc_ct_mangler_state {
	u8 ipv4:1;
	u8 tcpudp:1;
	u8 first:1;
};

static int efx_tc_ct_mangle(struct efx_nic *efx, struct efx_tc_ct_entry *conn,
			    const struct flow_action_entry *fa,
			    struct efx_tc_ct_mangler_state *mung)
{
	bool dnat = false;

	switch (fa->mangle.htype) {
	case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
		efx_tc_err(efx, "Unsupported: mangle eth+%u %x/%x\n",
			   fa->mangle.offset, fa->mangle.val, fa->mangle.mask);
		return -EOPNOTSUPP;
	case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
		switch (fa->mangle.offset) {
		case offsetof(struct iphdr, daddr):
			dnat = true;
			/* fallthrough */
		case offsetof(struct iphdr, saddr):
			if (fa->mangle.mask) {
				efx_tc_err(efx, "Unsupported: mask (%#x) of ipv4.%s mangle\n",
					   fa->mangle.mask, dnat ? "dst" : "src");
				return -EOPNOTSUPP;
			}
			conn->nat_ip = htonl(fa->mangle.val);
			mung->ipv4 = 1;
			break;
		default:
			efx_tc_err(efx, "Unsupported: mangle ipv4+%u %x/%x\n",
				   fa->mangle.offset, fa->mangle.val,
				   fa->mangle.mask);
			return -EOPNOTSUPP;
		}
		break;
	case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
	case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
		/* Both struct tcphdr and struct udphdr start with
		 *	__be16 source;
		 *	__be16 dest;
		 * so we can use the same code for both.
		 */
		switch (fa->mangle.offset) {
		case offsetof(struct tcphdr, dest):
			BUILD_BUG_ON(offsetof(struct tcphdr, dest) !=
				     offsetof(struct udphdr, dest));
			dnat = true;
			/* fallthrough */
		case offsetof(struct tcphdr, source):
			BUILD_BUG_ON(offsetof(struct tcphdr, source) !=
				     offsetof(struct udphdr, source));
			if (~fa->mangle.mask != 0xffff) {
				efx_tc_err(efx, "Unsupported: mask (%#x) of l4+%u mangle (%x)\n",
					   fa->mangle.mask, fa->mangle.offset,
					   fa->mangle.val);
				return -EOPNOTSUPP;
			}
			conn->l4_natport = htons(fa->mangle.val);
			mung->tcpudp = 1;
			break;
		default:
			efx_tc_err(efx, "Unsupported: mangle l4+%u (%x/%x)\n",
				   fa->mangle.offset, fa->mangle.val,
				   fa->mangle.mask);
			return -EOPNOTSUPP;
		}
		break;
	default:
		efx_tc_err(efx, "Unhandled mangle htype %u for conntrack\n",
			   fa->mangle.htype);
		return -EOPNOTSUPP;
	}
	/* first mangle tells us whether this is SNAT or DNAT
	 * subsequent mangles must match that
	 */
	if (mung->first)
		conn->dnat = dnat;
	mung->first = false;
	if (conn->dnat != dnat) {
		efx_tc_err(efx, "Mixed src and dst NAT for conntrack\n");
		return -EOPNOTSUPP;
	}
	return 0;
}

static int efx_tc_ct_replace(struct efx_tc_ct_zone *ct_zone,
			     struct flow_cls_offload *tc)
{
	struct flow_rule *fr = flow_cls_offload_flow_rule(tc);
	struct efx_tc_ct_mangler_state mung = { .first = true };
	struct efx_tc_ct_entry *conn, *old;
	struct efx_nic *efx = ct_zone->efx;
	const struct flow_action_entry *fa;
	int rc, i;

	if (WARN_ON(!efx->tc))
		return -ENETDOWN;
	if (WARN_ON(!efx->tc->up))
		return -ENETDOWN;

	conn = kzalloc(sizeof(*conn), GFP_USER);
	if (!conn)
		return -ENOMEM;
	conn->cookie = tc->cookie;
	old = rhashtable_lookup_get_insert_fast(&efx->tc->ct_ht,
						&conn->linkage,
						efx_tc_ct_ht_params);
	if (old) {
		netif_dbg(efx, drv, efx->net_dev,
			  "Already offloaded conntrack (cookie %lx)\n", tc->cookie);
		rc = -EEXIST;
		goto release;
	}

	/* Parse match */
	conn->zone = ct_zone->zone;
	rc = efx_tc_ct_parse_match(efx, fr, conn);
	if (rc)
		goto release;

	/* Parse actions */
	flow_action_for_each(i, fa, &fr->action) {
		/* TODO check fa->hw_stats, figure out CT stats generally */
		switch (fa->id) {
		case FLOW_ACTION_CT_METADATA:
			conn->mark = fa->ct_metadata.mark;
			if (memchr_inv(fa->ct_metadata.labels, 0, sizeof(fa->ct_metadata.labels))) {
				efx_tc_err(efx, "Setting CT label not supported\n");
				rc = -EOPNOTSUPP;
				goto release;
			}
			break;
		case FLOW_ACTION_MANGLE:
			if (conn->eth_proto != htons(ETH_P_IP)) {
				efx_tc_err(efx, "NAT only supported for IPv4\n");
				rc = -EOPNOTSUPP;
				goto release;
			}
			rc = efx_tc_ct_mangle(efx, conn, fa, &mung);
			if (rc)
				goto release;
			break;
		default:
			efx_tc_err(efx, "Unhandled action %u for conntrack\n", fa->id);
			rc = -EOPNOTSUPP;
			goto release;
		}
	}

	/* fill in defaults for unmangled values */
	if (!mung.ipv4)
		conn->nat_ip = conn->dnat ? conn->dst_ip : conn->src_ip;
	if (!mung.tcpudp)
		conn->l4_natport = conn->dnat ? conn->l4_dport : conn->l4_sport;

	rc = efx_mae_insert_ct(efx, conn);
	if (rc) {
		efx_tc_err(efx, "Failed to insert conntrack, %d\n", rc);
		goto release;
	}

	return 0;
release:
	if (!old)
		rhashtable_remove_fast(&efx->tc->ct_ht, &conn->linkage,
				       efx_tc_ct_ht_params);
	kfree(conn);
	return rc;
}

static int efx_tc_ct_destroy(struct efx_tc_ct_zone *ct_zone,
			     struct flow_cls_offload *tc)
{
	struct efx_nic *efx = ct_zone->efx;
	struct efx_tc_ct_entry *conn;

	conn = rhashtable_lookup_fast(&efx->tc->ct_ht, &tc->cookie,
				      efx_tc_ct_ht_params);
	if (!conn) {
		netif_warn(efx, drv, efx->net_dev,
			   "Conntrack %lx not found to remove\n", tc->cookie);
		return -ENOENT;
	}

	/* Remove it from HW */
	efx_mae_remove_ct(efx, conn);
	/* Delete it from SW */
	rhashtable_remove_fast(&efx->tc->ct_ht, &conn->linkage,
			       efx_tc_ct_ht_params);
	netif_dbg(efx, drv, efx->net_dev, "Removed conntrack %lx\n", conn->cookie);
	kfree(conn);
	return 0;
}

static int efx_tc_ct_stats(struct efx_tc_ct_zone *ct_zone,
			   struct flow_cls_offload *tc)
{
	struct efx_nic *efx = ct_zone->efx;

	/* TODO handle these */
	netif_err(efx, drv, efx->net_dev, "Got a ct_stats, zone %u\n",
		  ct_zone->zone);
	return -EOPNOTSUPP;
}

static int efx_tc_flow_block(enum tc_setup_type type, void *type_data,
			     void *cb_priv)
{
	struct flow_cls_offload *tcb = type_data;
	struct efx_tc_ct_zone *ct_zone = cb_priv;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;

	switch (tcb->command) {
	case FLOW_CLS_REPLACE:
		return efx_tc_ct_replace(ct_zone, tcb);
	case FLOW_CLS_DESTROY:
		return efx_tc_ct_destroy(ct_zone, tcb);
	case FLOW_CLS_STATS:
		return efx_tc_ct_stats(ct_zone, tcb);
	default:
		break;
	};

	return -EOPNOTSUPP;
}

static struct efx_tc_ct_zone *efx_tc_ct_register_zone(struct efx_nic *efx,
						      u16 zone,
						      struct nf_flowtable *ct_ft)
{
	struct efx_tc_ct_zone *ct_zone, *old;
	int rc;

	ct_zone = kzalloc(sizeof(*ct_zone), GFP_USER);
	if (!ct_zone)
		return ERR_PTR(-ENOMEM);
	ct_zone->zone = zone;
	old = rhashtable_lookup_get_insert_fast(&efx->tc->ct_zone_ht,
						&ct_zone->linkage,
						efx_tc_ct_zone_ht_params);
	if (old) {
		/* don't need our new entry */
		kfree(ct_zone);
		if (!refcount_inc_not_zero(&old->ref))
			return ERR_PTR(-EAGAIN);
		/* existing entry found */
		WARN_ON_ONCE(old->nf_ft != ct_ft);
		netif_dbg(efx, drv, efx->net_dev, "Found existing ct_zone for %u\n", zone);
		return old;
	}
	rc = nf_flow_table_offload_add_cb(ct_ft, efx_tc_flow_block, ct_zone);
	netif_dbg(efx, drv, efx->net_dev, "Adding new ct_zone for %u, rc %d\n", zone, rc);
	if (rc < 0) {
		rhashtable_remove_fast(&efx->tc->ct_zone_ht, &ct_zone->linkage,
				       efx_tc_ct_zone_ht_params);
		kfree(ct_zone);
		return ERR_PTR(rc);
	}
	ct_zone->nf_ft = ct_ft;
	ct_zone->efx = efx;
	refcount_set(&ct_zone->ref, 1);
	return ct_zone;
}

static void efx_tc_ct_unregister_zone(struct efx_nic *efx,
				      struct efx_tc_ct_zone *ct_zone)
{
	if (!refcount_dec_and_test(&ct_zone->ref))
		return; /* still in use */
	nf_flow_table_offload_del_cb(ct_zone->nf_ft, efx_tc_flow_block, ct_zone);
	rhashtable_remove_fast(&efx->tc->ct_zone_ht, &ct_zone->linkage,
			       efx_tc_ct_zone_ht_params);
	kfree(ct_zone);
}
#else
static struct efx_tc_ct_zone *efx_tc_ct_register_zone(struct efx_nic *efx,
						      u16 zone,
						      struct nf_flowtable *ct_ft)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static void efx_tc_ct_unregister_zone(struct efx_nic *efx,
				      struct efx_tc_ct_zone *ct_zone) {}
#endif /* CONFIG_NF_FLOW_TABLE */
#endif

static int efx_tc_flower_replace_lhs(struct efx_nic *efx,
				     struct flow_cls_offload *tc,
				     struct flow_rule *fr,
				     struct efx_tc_match *match,
				     struct efx_rep *efv)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_TC_FLOW_OFFLOAD) || defined(EFX_HAVE_TCF_EXTACK)
	struct netlink_ext_ack *extack = tc->common.extack;
#else
	struct netlink_ext_ack *extack = NULL;
#endif
	struct efx_tc_lhs_rule *rule, *old;
	const struct flow_action_entry *fa;
	bool pipe = true;
	int rc, i;

	if (tc->common.chain_index) {
		EFX_TC_ERR_MSG(efx, extack, "LHS rule only allowed in chain 0");
		return -EOPNOTSUPP;
	}

	if (match->mask.ct_state_trk && match->value.ct_state_trk) {
		EFX_TC_ERR_MSG(efx, extack, "LHS rule can never match +trk");
		return -EOPNOTSUPP;
	}
	/* LHS rules are always -trk, so we don't need to match on that */
	match->mask.ct_state_trk = 0;
	match->value.ct_state_trk = 0;

	rc = efx_mae_match_check_caps_lhs(efx, &match->mask, extack);
	if (rc)
		return rc;

	rule = kzalloc(sizeof(*rule), GFP_USER);
	if (!rule)
		return -ENOMEM;
	rule->cookie = tc->cookie;
	old = rhashtable_lookup_get_insert_fast(&efx->tc->lhs_rule_ht,
						&rule->linkage,
						efx_tc_lhs_rule_ht_params);
	if (old) {
		netif_dbg(efx, drv, efx->net_dev,
			  "Already offloaded rule (cookie %lx)\n", tc->cookie);
		rc = -EEXIST;
		NL_SET_ERR_MSG_MOD(extack, "Rule already offloaded");
		goto release;
	}

	/* Parse actions */
	flow_action_for_each(i, fa, &fr->action) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
		struct efx_tc_ct_zone *ct_zone;
#endif
		struct efx_tc_recirc_id *rid;
		struct efx_tc_ctr_agg *agg;

		if (!pipe) {
			/* more actions after a non-pipe action */
			EFX_TC_ERR_MSG(efx, extack, "Action follows non-pipe action");
			rc = -EINVAL;
			goto release;
		}
		switch (fa->id) {
		case FLOW_ACTION_GOTO:
			if (!fa->chain_index) {
				EFX_TC_ERR_MSG(efx, extack, "Can't goto chain 0, no looping in hw");
				rc = -EOPNOTSUPP;
				goto release;
			}
			rid = efx_tc_get_recirc_id(efx, fa->chain_index);
			if (IS_ERR(rid)) {
				EFX_TC_ERR_MSG(efx, extack, "Failed to allocate a hardware recirculation ID for this chain_index");
				rc = PTR_ERR(rid);
				goto release;
			}
			rule->lhs_act.rid = rid;
			/* TODO check fa->hw_stats */
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_TC_ACTION_COOKIE)
			agg = efx_tc_get_ctr_agg(efx, fa->cookie);
#else
			/* No action cookies, so use rule cookie */
			agg = efx_tc_get_ctr_agg(efx, rule->cookie);
#endif
			if (IS_ERR_OR_NULL(agg)) {
				EFX_TC_ERR_MSG(efx, extack, "Failed to create counter aggregator");
				rc = PTR_ERR(agg);
				if (!rc)
					rc = -EIO;
				goto release;
			}
			rule->lhs_act.count = agg;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
			rule->lhs_act.count_action_idx = i;
#endif
			pipe = false;
			break;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
		case FLOW_ACTION_CT:
			if (rule->lhs_act.zone) {
				rc = -EOPNOTSUPP;
				EFX_TC_ERR_MSG(efx, extack, "Can't offload multiple ct actions");
				goto release;
			}
#if !defined(EFX_USE_KCOMPAT) || defined(TCA_CT_ACT_COMMIT)
			if (fa->ct.action & (TCA_CT_ACT_COMMIT |
					     TCA_CT_ACT_FORCE)) {
				rc = -EOPNOTSUPP;
				EFX_TC_ERR_MSG(efx, extack, "Can't offload ct commit/force");
				goto release;
			}
			if (fa->ct.action & TCA_CT_ACT_CLEAR) {
				rc = -EOPNOTSUPP;
				EFX_TC_ERR_MSG(efx, extack, "Can't clear ct in LHS rule");
				goto release;
			}
			if (fa->ct.action & (TCA_CT_ACT_NAT |
					     TCA_CT_ACT_NAT_SRC |
					     TCA_CT_ACT_NAT_DST)) {
				rc = -EOPNOTSUPP;
				EFX_TC_ERR_MSG(efx, extack, "Can't perform NAT in LHS rule - packet isn't conntracked yet");
				goto release;
			}
#endif
			if (fa->ct.action) {
				efx_tc_err(efx, "Unhandled ct.action %u for LHS rule\n", fa->ct.action);
				rc = -EOPNOTSUPP;
				NL_SET_ERR_MSG_MOD(extack, "Unrecognised ct.action flag");
				goto release;
			}
			ct_zone = efx_tc_ct_register_zone(efx, fa->ct.zone, fa->ct.flow_table);
			if (IS_ERR(ct_zone)) {
				rc = PTR_ERR(ct_zone);
				EFX_TC_ERR_MSG(efx, extack, "Failed to register for CT updates");
				goto release;
			}
			rule->lhs_act.zone = ct_zone;
			break;
#endif
		default:
			efx_tc_err(efx, "Unhandled action %u for LHS rule\n", fa->id);
			rc = -EOPNOTSUPP;
			NL_SET_ERR_MSG_MOD(extack, "Unsupported action for LHS rule");
			goto release;
		}
	}

	if (pipe) {
		/* TODO we might actually want to allow this */
		rc = -EOPNOTSUPP;
		EFX_TC_ERR_MSG(efx, extack, "Missing goto chain in LHS rule");
		goto release;
	}

	rule->match = *match;

	rc = efx_mae_insert_lhs_rule(efx, rule, EFX_TC_PRIO_TC);
	if (rc) {
		EFX_TC_ERR_MSG(efx, extack, "Failed to insert rule in hw");
		goto release;
	}
	netif_dbg(efx, drv, efx->net_dev,
		  "Successfully parsed lhs rule (cookie %lx)\n",
		  tc->cookie);
	return 0;

release:
	if (rule->lhs_act.rid)
		efx_tc_put_recirc_id(efx, rule->lhs_act.rid);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	if (rule->lhs_act.zone)
		efx_tc_ct_unregister_zone(efx, rule->lhs_act.zone);
#endif
	if (rule->lhs_act.count)
		efx_tc_put_ctr_agg(efx, rule->lhs_act.count);
	if (!old)
		rhashtable_remove_fast(&efx->tc->lhs_rule_ht, &rule->linkage,
				       efx_tc_lhs_rule_ht_params);
	kfree(rule);
	return rc;
}

static int efx_tc_flower_replace(struct efx_nic *efx,
				 struct net_device *net_dev,
				 struct flow_cls_offload *tc,
				 struct efx_rep *efv)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	struct flow_rule *fr = flow_cls_offload_flow_rule(tc);
#else
	struct flow_rule *fr;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_TC_FLOW_OFFLOAD) || defined(EFX_HAVE_TCF_EXTACK)
	struct netlink_ext_ack *extack = tc->common.extack;
#else
	struct netlink_ext_ack *extack = NULL;
#endif
	const struct ip_tunnel_info *encap_info = NULL;
	struct efx_tc_flow_rule *rule = NULL, *old;
	struct efx_tc_action_set *act = NULL;
	const struct flow_action_entry *fa;
	struct efx_tc_recirc_id *rid;
	struct efx_tc_match match;
	int vport_id;
	u32 acts_id;
	long rc;
	int i;

	if (!tc_can_offload_extack(efx->net_dev, extack))
		return -EOPNOTSUPP;
	if (WARN_ON(!efx->tc))
		return -ENETDOWN;
	if (WARN_ON(!efx->tc->up))
		return -ENETDOWN;

	vport_id = efx_tc_flower_lookup_dev(efx, net_dev);
	if (vport_id < 0) {
		if (tc->common.chain_index)
			return -EOPNOTSUPP;
		netif_dbg(efx, drv, efx->net_dev, "Got notification for otherdev\n");
		return efx_tc_flower_replace_foreign(efx, net_dev, tc);
	}

	if (!efv != !vport_id) {
		/* can't happen */
		efx_tc_err(efx, "for %s efv is %snull but vport_id %d\n",
			   netdev_name(net_dev), efv ? "non-" : "", vport_id);
		if (efv)
			NL_SET_ERR_MSG_MOD(extack, "vfrep filter has PF net_dev (can't happen)");
		else
			NL_SET_ERR_MSG_MOD(extack, "PF filter has vfrep net_dev (can't happen)");
		return -EINVAL;
	}

	/* Parse match */
	memset(&match, 0, sizeof(match));
	rc = efx_tc_flower_external_mport(efx, vport_id);
	if (rc < 0) {
		EFX_TC_ERR_MSG(efx, extack, "Failed to identify ingress m-port");
		return rc;
	}
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	fr = efx_compat_flow_rule_build(tc);
	if (IS_ERR(fr)) {
		EFX_TC_ERR_MSG(efx, extack, "Failed to convert tc cls to a flow_rule");
		return PTR_ERR(fr);
	}
#endif
	match.value.ingress_port = rc;
	match.mask.ingress_port = ~0;
	rc = efx_tc_flower_parse_match(efx, fr, &match, extack);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	if (rc)
		return rc;
#else
	if (rc) {
		kfree(fr);
		return rc;
	}
#endif
	if (efx_tc_match_is_encap(&match.mask)) {
		EFX_TC_ERR_MSG(efx, extack, "Ingress enc_key matches not supported");
		rc = -EOPNOTSUPP;
		goto release;
	}

	if (efx_tc_rule_is_lhs_rule(fr, &match)) {
		rc = efx_tc_flower_replace_lhs(efx, tc, fr, &match, efv);
		if (rc)
			goto release;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
		kfree(fr);
#endif
		return 0;
	}

	/* chain_index 0 is always recirc_id 0 (and does not appear in recirc_ht).
	 * Conveniently, match.rid == NULL and match.value.recirc_id == 0 owing
	 * to the initial memset(), so we don't need to do anything in that case.
	 */
	if (tc->common.chain_index) {
		rid = efx_tc_get_recirc_id(efx, tc->common.chain_index);
		if (IS_ERR(rid)) {
			EFX_TC_ERR_MSG(efx, extack, "Failed to allocate a hardware recirculation ID for this chain_index");
			rc = PTR_ERR(rid);
			goto release;
		}
		match.rid = rid;
		match.value.recirc_id = rid->fw_id;
	}
	match.mask.recirc_id = 0xff;

	/* AR table can't match on DO_CT (+trk).  But a commonly used pattern is
	 * +trk+est, which is strictly implied by +est, so rewrite it to that.
	 */
	if (match.mask.ct_state_trk && match.value.ct_state_trk &&
	    match.mask.ct_state_est && match.value.ct_state_est)
		match.mask.ct_state_trk = 0;

	rc = efx_mae_match_check_caps(efx, &match.mask, extack);
	if (rc)
		goto release;

	rule = kzalloc(sizeof(*rule), GFP_USER);
	if (!rule) {
		rc = -ENOMEM;
		goto release;
	}
	INIT_LIST_HEAD(&rule->acts.list);
	rule->cookie = tc->cookie;
	old = rhashtable_lookup_get_insert_fast(&efx->tc->match_action_ht,
						&rule->linkage,
						efx_tc_match_action_ht_params);
	if (old) {
		netif_dbg(efx, drv, efx->net_dev,
			  "Already offloaded rule (cookie %lx)\n", tc->cookie);
		rc = -EEXIST;
		NL_SET_ERR_MSG_MOD(extack, "Rule already offloaded");
		goto release;
	}

	/* Parse actions */
	act = kzalloc(sizeof(*act), GFP_USER);
	if (!act) {
		rc = -ENOMEM;
		goto release;
	}

	flow_action_for_each(i, fa, &fr->action) {
		struct efx_tc_action_set save;
		int depth;
		u16 tci;

		if (!act) {
			/* more actions after a non-pipe action */
			EFX_TC_ERR_MSG(efx, extack, "Action follows non-pipe action");
			rc = -EINVAL;
			goto release;
		}
		/* If encap_info is set, then we need a counter even if the
		 * user doesn't want stats, because we have to prod
		 * neighbouring periodically if the rule is in use.
		 */
		if ((fa->id == FLOW_ACTION_REDIRECT ||
		     fa->id == FLOW_ACTION_MIRRED ||
		     fa->id == FLOW_ACTION_DROP) &&
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_STATS_TYPE)
		    (fa->hw_stats || encap_info)) {
#else
		    true) {
#endif
			struct efx_tc_counter_index *ctr;

			/* Currently the only actions that want stats are
			 * mirred and gact (ok, shot, trap, goto-chain), which
			 * means we want stats just before delivery.  Also,
			 * note that tunnel_key set shouldn't change the length
			 * — it's only the subsequent mirred that does that,
			 * and the stats are taken _before_ the mirred action
			 * happens.
			 */
			if (!efx_tc_flower_action_order_ok(act, EFX_TC_AO_COUNT)) {
				/* All supported actions that count either steal
				 * (gact shot, mirred redirect) or clone act
				 * (mirred mirror), so we should never get two
				 * count actions on one action_set.
				 */
				EFX_TC_ERR_MSG(efx, extack, "Count-action conflict (can't happen)");
				rc = -EOPNOTSUPP;
				goto release;
			}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_STATS_TYPE)
			if (!(fa->hw_stats & FLOW_ACTION_HW_STATS_DELAYED)) {
				NL_SET_ERR_MSG_MOD(extack, "Only hw_stats_type delayed is supported");
				efx_tc_err(efx, "hw_stats_type %u not supported (only 'delayed')\n",
					   fa->hw_stats);
				rc = -EOPNOTSUPP;
				goto release;
			}
#endif

			ctr = efx_tc_flower_get_counter_index(efx,
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_TC_ACTION_COOKIE)
							      fa->cookie);
#else
							      tc->cookie);
#endif
			if (IS_ERR(ctr)) {
				rc = PTR_ERR(ctr);
				EFX_TC_ERR_MSG(efx, extack, "Failed to obtain a counter");
				goto release;
			}
			act->count = ctr;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
			act->count_action_idx = i;
#endif
			INIT_LIST_HEAD(&act->count_user);
		}

		switch (fa->id) {
		case FLOW_ACTION_DROP:
			rc = efx_mae_alloc_action_set(efx, act);
			if (rc) {
				EFX_TC_ERR_MSG(efx, extack, "Failed to write action set to hw (drop)");
				goto release;
			}
			list_add_tail(&act->list, &rule->acts.list);
			act = NULL; /* end of the line */
			break;
		case FLOW_ACTION_REDIRECT:
		case FLOW_ACTION_MIRRED:
			save = *act;

			if (encap_info) {
				struct efx_tc_encap_action *encap;

				if (!efx_tc_flower_action_order_ok(act,
								   EFX_TC_AO_ENCAP)) {
					rc = -EOPNOTSUPP;
					EFX_TC_ERR_MSG(efx, extack, "Encap action violates action order");
					goto release;
				}
				encap = efx_tc_flower_create_encap_md(
						efx, encap_info, fa->dev, extack);
				if (IS_ERR_OR_NULL(encap)) {
					rc = PTR_ERR(encap);
					if (!rc)
						rc = -EIO; /* arbitrary */
					goto release;
				}
				act->encap_md = encap;
				list_add_tail(&act->encap_user, &encap->users);
				act->dest_mport = encap->dest_mport;
				act->deliver = 1;
				if (act->count && !WARN_ON(!act->count->cnt))
					/* This counter is used by an encap
					 * action, which needs a reference back
					 * so it can prod neighbouring whenever
					 * traffic is seen.
					 */
					list_add_tail(&act->count_user,
						      &act->count->cnt->users);
				rc = efx_mae_alloc_action_set(efx, act);
				if (rc) {
					EFX_TC_ERR_MSG(efx, extack, "Failed to write action set to hw (encap)");
					goto release;
				}
				list_add_tail(&act->list, &rule->acts.list);
				act->user = &rule->acts;
				act = NULL;
				if (fa->id == FLOW_ACTION_REDIRECT)
					break; /* end of the line */
				/* Mirror, so continue on with saved act */
				save.count = NULL;
				act = kzalloc(sizeof(*act), GFP_USER);
				if (!act) {
					rc = -ENOMEM;
					goto release;
				}
				*act = save;
				break;
			}

			if (!efx_tc_flower_action_order_ok(act, EFX_TC_AO_DELIVER)) {
				/* can't happen */
				rc = -EOPNOTSUPP;
				EFX_TC_ERR_MSG(efx, extack, "Deliver action violates action order (can't happen)");
				goto release;
			}
			rc = efx_tc_flower_lookup_dev(efx, fa->dev);
			if (rc < 0) {
				EFX_TC_ERR_MSG(efx, extack, "Mirred egress device not on switch");
				goto release;
			}
			rc = efx_tc_flower_external_mport(efx, rc);
			if (rc < 0) {
				EFX_TC_ERR_MSG(efx, extack, "Failed to identify egress m-port");
				goto release;
			}
			act->dest_mport = rc;
			act->deliver = 1;
			rc = efx_mae_alloc_action_set(efx, act);
			if (rc) {
				EFX_TC_ERR_MSG(efx, extack, "Failed to write action set to hw (mirred)");
				goto release;
			}
			list_add_tail(&act->list, &rule->acts.list);
			act = NULL;
			if (fa->id == FLOW_ACTION_REDIRECT)
				break; /* end of the line */
			/* Mirror, so continue on with saved act */
			save.count = NULL;
			act = kzalloc(sizeof(*act), GFP_USER);
			if (!act) {
				rc = -ENOMEM;
				goto release;
			}
			*act = save;
			break;
		case FLOW_ACTION_VLAN_POP:
			if (act->vlan_push & 2) {
				act->vlan_push &= ~2;
			} else if (act->vlan_push & 1) {
				act->vlan_push &= ~1;
			} else if (efx_tc_flower_action_order_ok(act, EFX_TC_AO_VLAN0_POP)) {
				act->vlan_pop |= 1;
			} else if (efx_tc_flower_action_order_ok(act, EFX_TC_AO_VLAN1_POP)) {
				act->vlan_pop |= 2;
			} else {
				EFX_TC_ERR_MSG(efx, extack, "More than two VLAN pops, or action order violated");
				rc = -EINVAL;
				goto release;
			}
			break;
		case FLOW_ACTION_VLAN_PUSH:
			if (efx_tc_flower_action_order_ok(act, EFX_TC_AO_VLAN0_PUSH)) {
				depth = 0;
			} else if (efx_tc_flower_action_order_ok(act, EFX_TC_AO_VLAN1_PUSH)) {
				depth = 1;
			} else {
				/* TODO special case when we have an ENCAP rule
				 * and can stick a vlan on its encap_hdr?
				 * But we can't do the reverse, so why bother?
				 */
				rc = -EINVAL;
				EFX_TC_ERR_MSG(efx, extack, "More than two VLAN pushes, or action order violated");
				goto release;
			}
			tci = fa->vlan.vid & 0x0fff;
			tci |= fa->vlan.prio << 13;
			act->vlan_push |= (1 << depth);
			act->vlan_tci[depth] = cpu_to_be16(tci);
			act->vlan_proto[depth] = fa->vlan.proto;
			break;
		case FLOW_ACTION_TUNNEL_ENCAP:
			if (encap_info) {
				/* Can't specify encap multiple times.
				 * XXX possibly we should allow this, and just
				 * overwrite the existing encap_info?  But you
				 * can do it with a tcf_tunnel_release anyway.
				 */
				rc = -EINVAL;
				EFX_TC_ERR_MSG(efx, extack, "Tunnel key set when already set");
				goto release;
			}
			if (!fa->tunnel) {
				rc = -EOPNOTSUPP;
				EFX_TC_ERR_MSG(efx, extack, "Tunnel key set is missing key");
				goto release;
			}
			encap_info = fa->tunnel;
			break;
		case FLOW_ACTION_TUNNEL_DECAP:
			if (encap_info) {
				encap_info = NULL;
				break;
			}
			/* Actually decap it.  Since we don't support enc_key
			 * matches on ingress (and if we did there'd be no
			 * tunnel-device to give us a type), the only way for
			 * this to work is if there was a foreign filter that
			 * set up an encap_match rule that covers us.
			 * XXX if not, what will the HW/FW do with this?
			 */
			if (!efx_tc_flower_action_order_ok(act, EFX_TC_AO_DECAP)) {
				rc = -EINVAL;
				EFX_TC_ERR_MSG(efx, extack, "Multiple decaps, or action order violated");
				goto release;
			}
			act->decap = 1;
			break;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
		case FLOW_ACTION_CT:
			if (fa->ct.action != TCA_CT_ACT_NAT) {
				rc = -EOPNOTSUPP;
				efx_tc_err(efx, "Unhandled ct action=%d\n", fa->ct.action);
				NL_SET_ERR_MSG_MOD(extack, "Can only offload CT 'nat' action in RHS rules");
				goto release;
			}
			act->do_nat = 1;
			break;
#endif
		case FLOW_ACTION_GOTO:
			rc = -EOPNOTSUPP;
			efx_tc_err(efx, "goto chain_index=%u\n", fa->chain_index);
			NL_SET_ERR_MSG_MOD(extack, "Can't offload goto chain in RHS rules");
			goto release;
		default:
			efx_tc_err(efx, "Unhandled action %u\n", fa->id);
			rc = -EOPNOTSUPP;
			NL_SET_ERR_MSG_MOD(extack, "Unsupported action");
			goto release;
		}
	}
	if (act) {
		/* Not shot/redirected, so deliver to default dest */
		switch (vport_id) {
		case EFX_VPORT_PF:
			/* Rule applies to traffic from the wire,
			 * and default dest is thus the PF
			 */
			efx_mae_mport_uplink(efx, &act->dest_mport);
			break;
		default:
			/* VFrep, so rule applies to traffic from VF,
			 * and default dest is thus the VFrep (which for
			 * now uses the PF's mport)
			 */
			efx_mae_mport_uplink(efx, &act->dest_mport);
		}
		act->deliver = 1;
		rc = efx_mae_alloc_action_set(efx, act);
		if (rc) {
			EFX_TC_ERR_MSG(efx, extack, "Failed to write action set to hw (deliver)");
			goto release;
		}
		list_add_tail(&act->list, &rule->acts.list);
		act = NULL; /* Prevent double-free in error path */
	}

	netif_dbg(efx, drv, efx->net_dev,
		  "Successfully parsed filter (cookie %lx)\n",
		  tc->cookie);

	rule->match = match;

	rc = efx_mae_alloc_action_set_list(efx, &rule->acts);
	if (rc) {
		EFX_TC_ERR_MSG(efx, extack, "Failed to write action set list to hw");
		goto release;
	}
	switch (vport_id) {
	case EFX_VPORT_PF:
		rule->fallback = EFX_TC_DFLT_WIRE;
		break;
	default:
		/* rep, so rule applies to traffic from representee */
		if (efv->remote)
			rule->fallback =
				EFX_TC_DFLT_REM(vport_id -
						EFX_VPORT_REMOTE_OFFSET);
		else
			rule->fallback = EFX_TC_DFLT_VF(vport_id -
							EFX_VPORT_VF_OFFSET);
		break;
	}
	if (!efx_tc_check_ready(efx, rule)) {
		netif_dbg(efx, drv, efx->net_dev, "action not ready for hw\n");
		acts_id = efx->tc->dflt_rules[rule->fallback].acts.fw_id;
	} else {
		netif_dbg(efx, drv, efx->net_dev, "ready for hw\n");
		acts_id = rule->acts.fw_id;
	}
	rc = efx_mae_insert_rule(efx, &rule->match, EFX_TC_PRIO_TC,
				 acts_id, &rule->fw_id);
	if (rc) {
		EFX_TC_ERR_MSG(efx, extack, "Failed to insert rule in hw");
		goto release_acts;
	}
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	kfree(fr);
#endif
	return 0;

release_acts:
	efx_mae_free_action_set_list(efx, &rule->acts);
release:
	/* We failed to insert the rule, so free up any entries we created in
	 * subsidiary tables.
	 */
	if (match.rid)
		efx_tc_put_recirc_id(efx, match.rid);
	if (act)
		efx_tc_free_action_set(efx, act, false);
	if (rule) {
		rhashtable_remove_fast(&efx->tc->match_action_ht,
				       &rule->linkage,
				       efx_tc_match_action_ht_params);
		efx_tc_free_action_set_list(efx, &rule->acts, false);
	}
	kfree(rule);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	kfree(fr);
#endif
	return rc;
}

static void efx_tc_delete_rule(struct efx_nic *efx, struct efx_tc_flow_rule *rule)
{
	efx_mae_delete_rule(efx, rule->fw_id);

	/* Release entries in subsidiary tables */
	efx_tc_free_action_set_list(efx, &rule->acts, true);
	if (rule->match.rid)
		efx_tc_put_recirc_id(efx, rule->match.rid);
	if (rule->match.encap)
		efx_tc_flower_release_encap_match(efx, rule->match.encap);
	rule->fw_id = MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL;
}

static int efx_tc_flower_destroy(struct efx_nic *efx,
				 struct net_device *net_dev,
				 struct flow_cls_offload *tc)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_TC_FLOW_OFFLOAD) || defined(EFX_HAVE_TCF_EXTACK)
	struct netlink_ext_ack *extack = tc->common.extack;
#else
	struct netlink_ext_ack *extack = NULL;
#endif
	struct efx_tc_lhs_rule *lhs_rule;
	struct efx_tc_flow_rule *rule;

	lhs_rule = rhashtable_lookup_fast(&efx->tc->lhs_rule_ht, &tc->cookie,
					  efx_tc_lhs_rule_ht_params);
	if (lhs_rule) {
		/* Remove it from HW */
		if (lhs_rule->lhs_act.count)
			efx_tc_put_ctr_agg(efx, lhs_rule->lhs_act.count);
		efx_mae_remove_lhs_rule(efx, lhs_rule);
		/* Delete it from SW */
		if (lhs_rule->lhs_act.rid)
			efx_tc_put_recirc_id(efx, lhs_rule->lhs_act.rid);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
		if (lhs_rule->lhs_act.zone)
			efx_tc_ct_unregister_zone(efx, lhs_rule->lhs_act.zone);
#endif
		rhashtable_remove_fast(&efx->tc->lhs_rule_ht, &lhs_rule->linkage,
				       efx_tc_lhs_rule_ht_params);
		netif_dbg(efx, drv, efx->net_dev, "Removed (lhs) filter %lx\n",
			  lhs_rule->cookie);
		kfree(lhs_rule);
		return 0;
	}

	rule = rhashtable_lookup_fast(&efx->tc->match_action_ht, &tc->cookie,
				      efx_tc_match_action_ht_params);
	if (!rule) {
		/* Only log a message if we're the ingress device.  Otherwise
		 * it's a foreign filter and we might just not have been
		 * interested (e.g. we might not have been the egress device
		 * either).
		 */
		if (efx_tc_flower_lookup_dev(efx, net_dev) >= 0)
			netif_warn(efx, drv, efx->net_dev,
				   "Filter %lx not found to remove\n", tc->cookie);
		NL_SET_ERR_MSG_MOD(extack, "Flow cookie not found in offloaded rules");
		return -ENOENT;
	}

	/* Remove it from HW */
	efx_tc_delete_rule(efx, rule);
	/* Delete it from SW */
	rhashtable_remove_fast(&efx->tc->match_action_ht, &rule->linkage,
			       efx_tc_match_action_ht_params);
	netif_dbg(efx, drv, efx->net_dev, "Removed filter %lx\n", rule->cookie);
	kfree(rule);
	return 0;
}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_TC_ACTION_COOKIE)
static int efx_tc_action_stats(struct efx_nic *efx,
			       struct tc_action_offload *tca)
{
	struct netlink_ext_ack *extack = tc->common.extack;
	struct efx_tc_counter_index *ctr;
	struct efx_tc_ctr_agg *agg;
	struct efx_tc_counter *cnt;
	u64 packets, bytes;

	agg = efx_tc_find_ctr_agg(efx, tca->cookie);
	if (agg) {
		cnt = &agg->count;
		/* Report only new pkts/bytes since last time TC asked */
		packets = cnt->packets;
		bytes = cnt->bytes;
		flow_stats_update(&tca->stats, bytes - cnt->old_bytes,
				  packets - cnt->old_packets, cnt->touched);
		cnt->old_packets = packets;
		cnt->old_bytes = bytes;
		return 0;
	}

	ctr = efx_tc_flower_find_counter_index(efx, tca->cookie);
	if (!ctr) {
		/* See comment in efx_tc_flower_destroy() */
		if (efx_tc_flower_lookup_dev(efx, net_dev) >= 0)
			netif_warn(efx, drv, efx->net_dev,
				   "Action %lx not found for stats\n", tca->cookie);
		NL_SET_ERR_MSG_MOD(extack, "Action cookie not found in offload");
		return -ENOENT;
	}
	if (WARN_ON(!ctr->cnt)) /* can't happen */
		return -EIO;
	cnt = ctr->cnt;
	spin_lock_bh(&cnt->lock);
	/* Report only new pkts/bytes since last time TC asked */
	packets = cnt->packets;
	bytes = cnt->bytes;
	flow_stats_update(&tca->stats, bytes - cnt->old_bytes,
			  packets - cnt->old_packets, cnt->touched,
			  FLOW_ACTION_HW_STATS_DELAYED);
	cnt->old_packets = packets;
	cnt->old_bytes = bytes;
	spin_unlock_bh(&cnt->lock);
	return 0;
}
#elif defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
static int efx_tc_flower_stats(struct efx_nic *efx, struct net_device *net_dev,
			       struct tc_cls_flower_offload *tc)
{
#ifdef EFX_HAVE_TCF_EXTACK
	struct netlink_ext_ack *extack = tc->common.extack;
#else
	struct netlink_ext_ack *extack = NULL;
#endif
	struct efx_tc_lhs_rule *lhs_rule;
	struct efx_tc_flow_rule *rule;
	struct efx_tc_action_set *act;
	struct efx_tc_counter *cnt;
	u64 packets, bytes;

	lhs_rule = rhashtable_lookup_fast(&efx->tc->lhs_rule_ht, &tc->cookie,
					  efx_tc_lhs_rule_ht_params);
	if (lhs_rule) {
		if (lhs_rule->lhs_act.count) {
			struct tc_action *a;

			cnt = &lhs_rule->lhs_act.count->count;
			/* Report only new pkts/bytes since last time TC asked */
			packets = cnt->packets;
			bytes = cnt->bytes;
			a = tc->exts->actions[lhs_rule->lhs_act.count_action_idx];
			tcf_action_stats_update(a, bytes - cnt->old_bytes,
						packets - cnt->old_packets,
						cnt->touched
#ifndef EFX_HAVE_OLD_TCF_ACTION_STATS_UPDATE
						, true
#endif
						);
			cnt->old_packets = packets;
			cnt->old_bytes = bytes;
		}
		return 0;
	}
	rule = rhashtable_lookup_fast(&efx->tc->match_action_ht, &tc->cookie,
				     efx_tc_match_action_ht_params);
	if (!rule) {
		/* See comment in efx_tc_flower_destroy() */
		if (efx_tc_flower_lookup_dev(efx, net_dev) >= 0)
			netif_warn(efx, drv, efx->net_dev,
				   "Filter %lx not found for stats\n", tc->cookie);
		NL_SET_ERR_MSG_MOD(extack, "Flow cookie not found in offloaded rules");
		return -ENOENT;
	}

	/* For each COUNT action in the action-set list, update the
	 * corresponding (count_action_idx) tc action's stats
	 */
	list_for_each_entry(act, &rule->acts.list, list)
		if (act->count) {
			struct tc_action *a;

			if (WARN_ON(!act->count->cnt)) /* can't happen */
				continue;
			cnt = act->count->cnt;
			spin_lock_bh(&cnt->lock);
			/* Report only new pkts/bytes since last time TC asked */
			packets = cnt->packets;
			bytes = cnt->bytes;
			a = tc->exts->actions[act->count_action_idx];
			tcf_action_stats_update(a, bytes - cnt->old_bytes,
						packets - cnt->old_packets,
						cnt->touched
#ifndef EFX_HAVE_OLD_TCF_ACTION_STATS_UPDATE
						, true
#endif
						);
			cnt->old_packets = packets;
			cnt->old_bytes = bytes;
			spin_unlock_bh(&cnt->lock);
		}
	return 0;
}
#else
static int efx_tc_flower_stats(struct efx_nic *efx, struct net_device *net_dev,
			       struct flow_cls_offload *tc)
{
	struct netlink_ext_ack *extack = tc->common.extack;
	struct efx_tc_lhs_rule *lhs_rule;
	struct efx_tc_counter_index *ctr;
	struct efx_tc_counter *cnt;
	u64 packets, bytes;

	lhs_rule = rhashtable_lookup_fast(&efx->tc->lhs_rule_ht, &tc->cookie,
					  efx_tc_lhs_rule_ht_params);
	if (lhs_rule) {
		if (lhs_rule->lhs_act.count) {
			cnt = &lhs_rule->lhs_act.count->count;
			/* Report only new pkts/bytes since last time TC asked */
			packets = cnt->packets;
			bytes = cnt->bytes;
			flow_stats_update(&tc->stats, bytes - cnt->old_bytes,
					  packets - cnt->old_packets,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_STATS_DROPS)
					  0,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_STATS_TYPE)
					  cnt->touched, FLOW_ACTION_HW_STATS_DELAYED);
#else
					  cnt->touched);
#endif
			cnt->old_packets = packets;
			cnt->old_bytes = bytes;
		}
		return 0;
	}

	ctr = efx_tc_flower_find_counter_index(efx, tc->cookie);
	if (!ctr) {
		/* See comment in efx_tc_flower_destroy() */
		if (efx_tc_flower_lookup_dev(efx, net_dev) >= 0)
			netif_warn(efx, drv, efx->net_dev,
				   "Filter %lx not found for stats\n", tc->cookie);
		NL_SET_ERR_MSG_MOD(extack, "Flow cookie not found in offloaded rules");
		return -ENOENT;
	}
	if (WARN_ON(!ctr->cnt)) /* can't happen */
		return -EIO;
	cnt = ctr->cnt;

	spin_lock_bh(&cnt->lock);
	/* Report only new pkts/bytes since last time TC asked */
	packets = cnt->packets;
	bytes = cnt->bytes;
	flow_stats_update(&tc->stats, bytes - cnt->old_bytes,
			  packets - cnt->old_packets,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_STATS_DROPS)
			  0,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_STATS_TYPE)
			  cnt->touched, FLOW_ACTION_HW_STATS_DELAYED);
#else
			  cnt->touched);
#endif
	cnt->old_packets = packets;
	cnt->old_bytes = bytes;
	spin_unlock_bh(&cnt->lock);
	return 0;
}
#endif

int efx_tc_flower(struct efx_nic *efx, struct net_device *net_dev,
		  struct flow_cls_offload *tc, struct efx_rep *efv)
{
	int rc;

	mutex_lock(&efx->tc->mutex);
	switch (tc->command) {
	case FLOW_CLS_REPLACE:
		rc = efx_tc_flower_replace(efx, net_dev, tc, efv);
		break;
	case FLOW_CLS_DESTROY:
		rc = efx_tc_flower_destroy(efx, net_dev, tc);
		break;
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_TC_ACTION_COOKIE)
	case FLOW_CLS_STATS:
		rc = efx_tc_flower_stats(efx, net_dev, tc);
		break;
#endif
	default:
		rc = -EOPNOTSUPP;
		break;
	}
	mutex_unlock(&efx->tc->mutex);
	return rc;
}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_TC_ACTION_COOKIE)
int efx_tc_setup_action(struct efx_nic *efx, struct tc_action_offload *tca)
{
	int rc;

	mutex_lock(&efx->tc->mutex);
	switch (tca->command) {
	case TC_ACTION_STATS:
		rc = efx_tc_action_stats(efx, tca);
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}
	mutex_unlock(&efx->tc->mutex);
	return rc;
}
#endif

struct efx_tc_block_binding {
	struct list_head list;
	struct efx_nic *efx;
	struct efx_rep *efv;
	struct net_device *otherdev; /* may actually be us */
	struct flow_block *block;
};

static struct efx_tc_block_binding *efx_tc_find_binding(struct efx_nic *efx,
							struct net_device *otherdev)
{
	struct efx_tc_block_binding *binding;

	ASSERT_RTNL();
	list_for_each_entry(binding, &efx->tc->block_list, list)
		if (binding->otherdev == otherdev)
			return binding;
	return NULL;
}

int efx_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv)
{
	struct efx_tc_block_binding *binding = cb_priv;
	struct flow_cls_offload *tcf = type_data;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_TC_ACTION_COOKIE)
	struct tc_action_offload *tca = type_data;
#endif

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return efx_tc_flower(binding->efx, binding->otherdev,
				     tcf, binding->efv);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_TC_ACTION_COOKIE)
	case TC_SETUP_ACTION:
		return efx_tc_setup_action(binding->efx, tca);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_BLOCK_OFFLOAD)
static void efx_tc_block_unbind(void *cb_priv)
{
	struct efx_tc_block_binding *binding = cb_priv;

	list_del(&binding->list);
	kfree(binding);
}

static struct efx_tc_block_binding *efx_tc_create_binding(
			struct efx_nic *efx, struct efx_rep *efv,
			struct net_device *otherdev, struct flow_block *block)
{
	struct efx_tc_block_binding *binding = kmalloc(sizeof(*binding), GFP_KERNEL);

	if (!binding)
		return ERR_PTR(-ENOMEM);
	binding->efx = efx;
	binding->efv = efv;
	binding->otherdev = otherdev;
	binding->block = block;
	list_add(&binding->list, &efx->tc->block_list);
	return binding;
}

int efx_tc_setup_block(struct net_device *net_dev, struct efx_nic *efx,
		       struct flow_block_offload *tcb, struct efx_rep *efv)
{
	struct efx_tc_block_binding *binding;
	struct flow_block_cb *block_cb;
	int rc;

	if (tcb->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	if (WARN_ON(!efx->tc))
		return -ENETDOWN;

	switch (tcb->command) {
	case FLOW_BLOCK_BIND:
		binding = efx_tc_create_binding(efx, efv, net_dev, tcb->block);
		if (IS_ERR(binding))
			return PTR_ERR(binding);
		block_cb = flow_block_cb_alloc(efx_tc_block_cb, binding,
					       binding, efx_tc_block_unbind);
		rc = PTR_ERR_OR_ZERO(block_cb);
		netif_dbg(efx, drv, efx->net_dev,
			  "bind %sdirect block for device %s, rc %d\n",
			  net_dev == efx->net_dev ? "" :
			  efv ? "semi" : "in",
			  net_dev ? net_dev->name : NULL, rc);
		if (rc) {
			list_del(&binding->list);
			kfree(binding);
		} else {
			flow_block_cb_add(block_cb, tcb);
		}
		return rc;
	case FLOW_BLOCK_UNBIND:
		binding = efx_tc_find_binding(efx, net_dev);
		if (binding) {
			block_cb = flow_block_cb_lookup(tcb->block,
							efx_tc_block_cb,
							binding);
			if (block_cb) {
				flow_block_cb_remove(block_cb, tcb);
				netif_dbg(efx, drv, efx->net_dev,
					  "unbound %sdirect block for device %s\n",
					  net_dev == efx->net_dev ? "" :
					  binding->efv ? "semi" : "in",
					  net_dev ? net_dev->name : NULL);
				return 0;
			}
		}
		/* If we're in driver teardown, then we expect to have
		 * already unbound all our blocks (we did it early while
		 * we still had MCDI to remove the filters), so getting
		 * unbind callbacks now isn't a problem.
		 */
		netif_cond_dbg(efx, drv, efx->net_dev,
			       !efx->tc->up, warn,
			       "%sdirect block unbind for device %s, was never bound\n",
			       net_dev == efx->net_dev ? "" : "in",
			       net_dev ? net_dev->name : NULL);
		return -ENOENT;
	default:
		return -EOPNOTSUPP;
	}
}
#else
int efx_tc_setup_block(struct net_device *net_dev, struct efx_nic *efx,
		       struct flow_block_offload *tcb, struct efx_rep *efv)
{
	struct efx_tc_block_binding *binding;
	int rc;

	if (tcb->binder_type != TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	if (WARN_ON(!efx->tc))
		return -ENETDOWN;

	switch (tcb->command) {
	case TC_BLOCK_BIND:
		binding = kmalloc(sizeof(*binding), GFP_KERNEL);
		if (!binding)
			return -ENOMEM;
		binding->efx = efx;
		binding->efv = efv;
		binding->otherdev = net_dev;
		binding->block = tcb->block;
		list_add(&binding->list, &efx->tc->block_list);
		rc = tcf_block_cb_register(tcb->block, efx_tc_block_cb,
					   binding, binding
#ifdef EFX_HAVE_TCB_EXTACK
					   , tcb->extack
#endif
					   );
		netif_dbg(efx, drv, efx->net_dev,
			  "bind %sdirect block for device %s, rc %d\n",
			  net_dev == efx->net_dev ? "" :
			  efv ? "semi" : "in",
			  net_dev ? net_dev->name : NULL, rc);
		if (rc) {
			list_del(&binding->list);
			kfree(binding);
		}
		return rc;
	case TC_BLOCK_UNBIND:
		binding = efx_tc_find_binding(efx, net_dev);
		if (binding) {
			tcf_block_cb_unregister(binding->block, efx_tc_block_cb,
						binding);
			netif_dbg(efx, drv, efx->net_dev,
				  "unbound %sdirect block for device %s\n",
				  net_dev == efx->net_dev ? "" :
				  binding->efv ? "semi" : "in",
				  net_dev ? net_dev->name : NULL);
			list_del(&binding->list);
			kfree(binding);
		} else {
			/* If we're in driver teardown, then we expect to have
			 * already unbound all our blocks (we did it early while
			 * we still had MCDI to remove the filters), so getting
			 * unbind callbacks now isn't a problem.
			 */
			netif_cond_dbg(efx, drv, efx->net_dev,
				       !efx->tc->up, warn,
				       "%sdirect block unbind for device %s, was never bound\n",
				       net_dev == efx->net_dev ? "" : "in",
				       net_dev ? net_dev->name : NULL);
		}
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}
#endif

int efx_tc_configure_default_rule(struct efx_nic *efx,
				  enum efx_tc_default_rules dflt)
{
	struct efx_tc_flow_rule *rule = efx->tc->dflt_rules + dflt;
	struct efx_tc_action_set_list *acts = &rule->acts;
	struct efx_tc_match *match = &rule->match;
	struct efx_tc_action_set *act;
	struct net_device *rep_dev;
	struct efx_rep *efv;
	u32 ing_port, eg_port;
	int rc, idx;

	INIT_LIST_HEAD(&acts->list);
	switch (dflt) {
	case EFX_TC_DFLT_PF:
		efx_mae_mport_uplink(efx, &ing_port);
		efx_mae_mport_wire(efx, &eg_port);
		break;
	case EFX_TC_DFLT_WIRE:
		efx_mae_mport_wire(efx, &ing_port);
		efx_mae_mport_uplink(efx, &eg_port);
		break;
	default:
		if (dflt >= EFX_TC_DFLT_REMOTE_BASE) {
			idx = dflt - EFX_TC_DFLT_REMOTE_BASE;
			rep_dev = efx_get_remote_rep(efx, idx);
		} else {
			idx = dflt - EFX_TC_DFLT_VF_BASE;
			rep_dev = efx_get_vf_rep(efx, idx);
		}
		if (IS_ERR(rep_dev))
			return PTR_ERR(rep_dev);
		if (!rep_dev)
			return -EINVAL;
		efv = netdev_priv(rep_dev);
		efx_mae_mport_mport(efx, efv->mport, &ing_port);
		efx_mae_mport_mport(efx, efx->tc->reps_mport_id, &eg_port);
		break;
	}
	match->value.ingress_port = ing_port;
	match->mask.ingress_port = ~0;
	act = kzalloc(sizeof(*act), GFP_KERNEL);
	if (!act)
		return -ENOMEM;
	act->deliver = 1;
	act->dest_mport = eg_port;
	rc = efx_mae_alloc_action_set(efx, act);
	if (rc)
		goto fail1;
	list_add_tail(&act->list, &acts->list);
	rc = efx_mae_alloc_action_set_list(efx, acts);
	if (rc)
		goto fail2;
	rc = efx_mae_insert_rule(efx, match, EFX_TC_PRIO_DFLT,
				 acts->fw_id, &rule->fw_id);
	if (rc)
		goto fail3;
	return 0;
fail3:
	efx_mae_free_action_set_list(efx, acts);
fail2:
	list_del(&act->list);
	efx_mae_free_action_set(efx, act);
fail1:
	kfree(act);
	return rc;
}

void efx_tc_deconfigure_default_rule(struct efx_nic *efx,
				     enum efx_tc_default_rules dflt)
{
	struct efx_tc_flow_rule *rule = efx->tc->dflt_rules + dflt;

	if (rule->fw_id != MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL)
		efx_tc_delete_rule(efx, rule);
	rule->fw_id = MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
static int efx_tc_enumerate_mports(struct efx_nic *efx)
{
	int rc;

	rc = efx_mae_enumerate_mports(efx, 0, NULL);
	if (rc < 0)
		return rc;
	efx->tc->n_mports = rc;
	efx->tc->mports = kcalloc(efx->tc->n_mports,
				  sizeof(struct mae_mport_desc), GFP_KERNEL);
	if (!efx->tc->mports) {
		rc = -ENOMEM;
		goto fail1;
	}
	rc = efx_mae_enumerate_mports(efx, efx->tc->n_mports, efx->tc->mports);
	if (rc < 0)
		goto fail2;
	if (rc != efx->tc->n_mports) {
		/* m-port count changed, we're confused.
		 * bail out for now, TODO fix this later
		 */
		rc = -EIO;
		goto fail2;

	}
	return 0;
fail2:
	kfree(efx->tc->mports);
fail1:
	efx->tc->n_mports = 0;
	return rc;

}
#endif

#ifdef CONFIG_SFC_DEBUGFS
static void efx_tc_debugfs_dump_encap_match(struct seq_file *file,
					    struct efx_tc_encap_match *encap)
{
	seq_printf(file, "\tencap_match (%#x)\n", encap->fw_id);
	if (encap->src_ip | encap->dst_ip) {
		seq_printf(file, "\t\tsrc_ip = %pI4\n", &encap->src_ip);
		seq_printf(file, "\t\tdst_ip = %pI4\n", &encap->dst_ip);
	} else {
		seq_printf(file, "\t\tsrc_ip6 = %pI6c\n", &encap->src_ip6);
		seq_printf(file, "\t\tdst_ip6 = %pI6c\n", &encap->dst_ip6);
	}
	seq_printf(file, "\t\tudp_dport = %u\n", be16_to_cpu(encap->udp_dport));
	if (encap->tun_type < ARRAY_SIZE(efx_tc_encap_type_names))
		seq_printf(file, "\t\ttun_type = %s\n",
			   efx_tc_encap_type_names[encap->tun_type]);
	else
		seq_printf(file, "\t\ttun_type = %u\n", encap->tun_type);
}

#define efx_tc_debugfs_dump_fmt_match_item(_file, _name, _key, _mask, _fmt, _amp)\
do {									       \
	if (_mask) {							       \
		if (~_mask)						       \
			seq_printf(file, "\t%s & " _fmt " = " _fmt "\n", _name,\
				   _amp _mask, _amp _key);		       \
		else							       \
			seq_printf(file, "\t%s = " _fmt "\n", _name, _amp _key);\
	}								       \
} while (0)

static void efx_tc_debugfs_dump_fmt_ptr_match_item(struct seq_file *file,
						   const char *name, void *key,
						   void *mask, size_t len,
						   const char *fmt)
{
	char maskbuf[40], keybuf[40];

	if (!memchr_inv(mask, 0, len))
		return; /* mask is all-0s */
	snprintf(keybuf, sizeof(keybuf), fmt, key);
	if (memchr_inv(mask, 0xff, len)) { /* masked */
		snprintf(maskbuf, sizeof(maskbuf), fmt, mask);
		seq_printf(file, "\t%s & %s = %s\n", name, maskbuf, keybuf);
	} else { /* mask is all-1s */
		seq_printf(file, "\t%s = %s\n", name, keybuf);
	}
}

static void efx_tc_debugfs_dump_one_match_item(struct seq_file *file,
					       const char *name, void *key,
					       void *mask, size_t len)
{
	if (!memchr_inv(mask, 0, len))
		return; /* mask is all-0s */
	if (memchr_inv(mask, 0xff, len)) /* masked */
		seq_printf(file, "\t%s & 0x%*phN = 0x%*phN\n", name, (int)len, mask,
			   (int)len, key);
	else /* mask is all-1s */
		switch (len) {
		case 1:
			seq_printf(file, "\t%s = %#04x (%u)\n", name,
				   *(u8 *)key, *(u8 *)key);
			break;
		case 2:
			seq_printf(file, "\t%s = %#06x (%u)\n", name,
				   be16_to_cpu(*(__be16 *)key),
				   be16_to_cpu(*(__be16 *)key));
			break;
		case 4:
			seq_printf(file, "\t%s = %#010x (%u)\n", name,
				   be32_to_cpu(*(__be32 *)key),
				   be32_to_cpu(*(__be32 *)key));
			break;
		default:
			seq_printf(file, "\t%s = 0x%*phN\n", name, (int)len, key);
			break;
		}
}

static void efx_tc_debugfs_dump_ct_bits(struct seq_file *file,
					struct efx_tc_match *match)
{
	if (!(match->mask.ct_state_trk || match->mask.ct_state_est ||
	      match->mask.ct_state_rel || match->mask.ct_state_new))
		return; /* mask is all-0s */
	seq_printf(file, "\tct_state =");
#define DUMP_ONE_BIT(name)						\
	if (match->mask.ct_state_##name)				\
		seq_printf(file, " %c%s", 				\
			   match->value.ct_state_##name ? '+' : '-',	\
			   #name)
	DUMP_ONE_BIT(trk);
	DUMP_ONE_BIT(est);
	DUMP_ONE_BIT(rel);
	DUMP_ONE_BIT(new);
#undef DUMP_ONE_BIT
	seq_printf(file, "\n");
}

static void efx_tc_debugfs_dump_match(struct seq_file *file,
				      struct efx_tc_match *match)
{
	if (match->encap)
		efx_tc_debugfs_dump_encap_match(file, match->encap);
#define DUMP_ONE_MATCH(_field)						       \
	efx_tc_debugfs_dump_one_match_item(file, #_field, &match->value._field,\
					   &match->mask._field,		       \
					   sizeof(match->value._field))
#define DUMP_FMT_MATCH(_field, _fmt)					       \
	efx_tc_debugfs_dump_fmt_match_item(file, #_field, match->value._field, \
					   match->mask._field, _fmt, )
#define DUMP_FMT_AMP_MATCH(_field, _fmt)				       \
	efx_tc_debugfs_dump_fmt_match_item(file, #_field, match->value._field, \
					   match->mask._field, _fmt, &)
#define DUMP_FMT_PTR_MATCH(_field, _fmt)				       \
	efx_tc_debugfs_dump_fmt_ptr_match_item(file, #_field,		       \
					       &match->value._field,	       \
					       &match->mask._field,	       \
					       sizeof(match->value._field),    \
					       _fmt)
	DUMP_FMT_MATCH(ingress_port, "%#010x");
	DUMP_ONE_MATCH(eth_proto);
	DUMP_ONE_MATCH(vlan_tci[0]);
	DUMP_ONE_MATCH(vlan_proto[0]);
	DUMP_ONE_MATCH(vlan_tci[1]);
	DUMP_ONE_MATCH(vlan_proto[1]);
	DUMP_FMT_PTR_MATCH(eth_saddr, "%pM");
	DUMP_FMT_PTR_MATCH(eth_daddr, "%pM");
	DUMP_ONE_MATCH(ip_proto);
	DUMP_ONE_MATCH(ip_tos);
	DUMP_ONE_MATCH(ip_ttl);
	if (match->mask.ip_frag)
		seq_printf(file, "\tip_frag = %d\n", match->value.ip_frag);
	DUMP_FMT_AMP_MATCH(src_ip, "%pI4");
	DUMP_FMT_AMP_MATCH(dst_ip, "%pI4");
	DUMP_FMT_PTR_MATCH(src_ip6, "%pI6");
	DUMP_FMT_PTR_MATCH(dst_ip6, "%pI6");
	DUMP_ONE_MATCH(l4_sport);
	DUMP_ONE_MATCH(l4_dport);
	DUMP_ONE_MATCH(tcp_flags);
	DUMP_FMT_AMP_MATCH(enc_src_ip, "%pI4");
	DUMP_FMT_AMP_MATCH(enc_dst_ip, "%pI4");
	DUMP_FMT_PTR_MATCH(enc_src_ip6, "%pI6c");
	DUMP_FMT_PTR_MATCH(enc_dst_ip6, "%pI6c");
	DUMP_ONE_MATCH(enc_ip_tos);
	DUMP_ONE_MATCH(enc_ip_ttl);
	DUMP_ONE_MATCH(enc_sport);
	DUMP_ONE_MATCH(enc_dport);
	DUMP_ONE_MATCH(enc_keyid);
	efx_tc_debugfs_dump_ct_bits(file, match);
	DUMP_ONE_MATCH(ct_mark);
	DUMP_ONE_MATCH(recirc_id);
#undef DUMP_ONE_MATCH
#undef DUMP_FMT_MATCH
#undef DUMP_FMT_AMP_MATCH
#undef DUMP_FMT_PTR_MATCH
}

static void efx_tc_debugfs_dump_one_rule(struct seq_file *file,
					 struct efx_tc_flow_rule *rule)
{
	struct efx_tc_action_set *act;

	seq_printf(file, "%#lx (%#x)\n", rule->cookie, rule->fw_id);

	efx_tc_debugfs_dump_match(file, &rule->match);

	seq_printf(file, "\taction_set_list (%#x)\n", rule->acts.fw_id);
	list_for_each_entry(act, &rule->acts.list, list) {
		seq_printf(file, "\t\taction_set (%#x)\n", act->fw_id);
		if (act->decap)
			seq_printf(file, "\t\t\tdecap\n");
		if (act->vlan_pop & BIT(1))
			seq_printf(file, "\t\t\tvlan1_pop\n");
		if (act->vlan_pop & BIT(0))
			seq_printf(file, "\t\t\tvlan0_pop\n");
		if (act->pedit_md) /* TODO dump pedits when we have them */
			seq_printf(file, "\t\t\tpedit %p\n", act->pedit_md);
		if (act->vlan_push & BIT(0))
			seq_printf(file, "\t\t\tvlan0_push tci=%u proto=%x\n",
				   be16_to_cpu(act->vlan_tci[0]),
				   be16_to_cpu(act->vlan_proto[0]));
		if (act->vlan_push & BIT(1))
			seq_printf(file, "\t\t\tvlan1_push tci=%u proto=%x\n",
				   be16_to_cpu(act->vlan_tci[1]),
				   be16_to_cpu(act->vlan_proto[1]));
		if (act->do_nat)
			seq_printf(file, "\t\t\tnat\n");
		if (act->count) {
			u32 fw_id;

			if (WARN_ON(!act->count->cnt))
				fw_id = MC_CMD_MAE_COUNTER_ALLOC_OUT_COUNTER_ID_NULL;
			else
				fw_id = act->count->cnt->fw_id;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
			seq_printf(file, "\t\t\tcount (%#x) act_idx=%d\n",
				   fw_id, act->count_action_idx);
#else
			seq_printf(file, "\t\t\tcount (%#x)\n", fw_id);
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_TC_ACTION_COOKIE)
			seq_printf(file, "\t\t\t\tcookie = %#lx\n",
				   act->count->cookie);
#endif
		}
		if (act->encap_md) {
			enum efx_encap_type type = act->encap_md->type & EFX_ENCAP_TYPES_MASK;
			bool v6 = act->encap_md->type & EFX_ENCAP_FLAG_IPV6;

			seq_printf(file, "\t\t\tencap (%#x)\n", act->encap_md->fw_id);
			if (type < ARRAY_SIZE(efx_tc_encap_type_names))
				seq_printf(file, "\t\t\t\ttype = %s IPv%d\n",
					   efx_tc_encap_type_names[type],
					   v6 ? 6 : 4);
			else
				seq_printf(file, "\t\t\t\ttype = %u\n", act->encap_md->type);
			seq_printf(file, "\t\t\t\tkey\n");
			seq_printf(file, "\t\t\t\t\ttun_id = %llu\n",
				   be64_to_cpu(act->encap_md->key.tun_id));
			if (v6) {
				seq_printf(file, "\t\t\t\t\tsrc = %pI6c\n",
					   &act->encap_md->key.u.ipv6.src);
				seq_printf(file, "\t\t\t\t\tdst = %pI6c\n",
					   &act->encap_md->key.u.ipv6.dst);
			} else {
				seq_printf(file, "\t\t\t\t\tsrc = %pI4\n",
					   &act->encap_md->key.u.ipv4.src);
				seq_printf(file, "\t\t\t\t\tdst = %pI4\n",
					   &act->encap_md->key.u.ipv4.dst);
			}
			seq_printf(file, "\t\t\t\t\ttun_flags = %#x\n",
				   be16_to_cpu(act->encap_md->key.tun_flags));
			seq_printf(file, "\t\t\t\t\ttos = %#x\n",
				   act->encap_md->key.tos);
			seq_printf(file, "\t\t\t\t\tttl = %u\n",
				   act->encap_md->key.ttl);
			seq_printf(file, "\t\t\t\t\tflow_label = %#x\n",
				   be32_to_cpu(act->encap_md->key.label));
			seq_printf(file, "\t\t\t\t\ttp_src = %u\n",
				   be16_to_cpu(act->encap_md->key.tp_src));
			seq_printf(file, "\t\t\t\t\ttp_dst = %u\n",
				   be16_to_cpu(act->encap_md->key.tp_dst));
			seq_printf(file, "\t\t\t\tneigh %svalid\n",
				   act->encap_md->n_valid ? "" : "in");
		}
		if (act->deliver)
			seq_printf(file, "\t\t\tdeliver %#010x\n", act->dest_mport);
	}
}

static int efx_tc_debugfs_dump_rules(struct seq_file *file, void *data)
{
	struct efx_tc_flow_rule *rule;
	struct rhashtable_iter walk;
	struct efx_nic *efx = data;

	mutex_lock(&efx->tc->mutex);
	if (efx->tc->up) {
		rhashtable_walk_enter(&efx->tc->match_action_ht, &walk);
		rhashtable_walk_start(&walk);
		while ((rule = rhashtable_walk_next(&walk)) != NULL) {
			if (IS_ERR(rule))
				continue;
			efx_tc_debugfs_dump_one_rule(file, rule);
		}
		rhashtable_walk_stop(&walk);
		rhashtable_walk_exit(&walk);
	} else {
		seq_printf(file, "tc is down\n");
	}
	mutex_unlock(&efx->tc->mutex);

	return 0;
}

static int efx_tc_debugfs_dump_default_rules(struct seq_file *file, void *data)
{
	struct efx_nic *efx = data;
	int i;

	mutex_lock(&efx->tc->mutex);
	for (i = 0; i < EFX_TC_DFLT__MAX; i++)
		if (efx->tc->dflt_rules[i].fw_id != MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL)
			efx_tc_debugfs_dump_one_rule(file, &efx->tc->dflt_rules[i]);
	mutex_unlock(&efx->tc->mutex);

	return 0;
}

static void efx_tc_debugfs_dump_one_counter(struct seq_file *file,
					    struct efx_tc_counter *cnt)
{
	u64 packets, bytes, old_packets, old_bytes;
	unsigned long age;

	/* get a consistent view */
	spin_lock_bh(&cnt->lock);
	packets = cnt->packets;
	bytes = cnt->bytes;
	old_packets = cnt->old_packets;
	old_bytes = cnt->old_bytes;
	age = jiffies - cnt->touched;
	spin_unlock_bh(&cnt->lock);

	seq_printf(file, "%#x: %llu pkts %llu bytes (old %llu pkts %llu bytes) age %lu\n",
		   cnt->fw_id, packets, bytes, old_packets, old_bytes, age);
}

static int efx_tc_debugfs_dump_mae_counters(struct seq_file *file, void *data)
{
	struct rhashtable_iter walk;
	struct efx_nic *efx = data;
	struct efx_tc_counter *cnt;

	mutex_lock(&efx->tc->mutex);
	if (efx->tc->up) {
		rhashtable_walk_enter(&efx->tc->counter_ht, &walk);
		rhashtable_walk_start(&walk);
		while ((cnt = rhashtable_walk_next(&walk)) != NULL) {
			if (IS_ERR(cnt))
				continue;
			efx_tc_debugfs_dump_one_counter(file, cnt);
		}
		rhashtable_walk_stop(&walk);
		rhashtable_walk_exit(&walk);
	} else {
		seq_printf(file, "tc is down\n");
	}
	mutex_unlock(&efx->tc->mutex);

	return 0;
}

static int efx_tc_debugfs_dump_recirc_ids(struct seq_file *file, void *data)
{
	struct efx_tc_recirc_id *rid;
	struct rhashtable_iter walk;
	struct efx_nic *efx = data;

	mutex_lock(&efx->tc->mutex);
	if (efx->tc->up) {
		rhashtable_walk_enter(&efx->tc->recirc_ht, &walk);
		rhashtable_walk_start(&walk);
		while ((rid = rhashtable_walk_next(&walk)) != NULL) {
			if (IS_ERR(rid))
				continue;
			seq_printf(file, "%#x: %u\n", rid->fw_id, rid->chain_index);
		}
		rhashtable_walk_stop(&walk);
		rhashtable_walk_exit(&walk);
	} else {
		seq_printf(file, "tc is down\n");
	}
	mutex_unlock(&efx->tc->mutex);

	return 0;
}

static void efx_tc_debugfs_dump_lhs_rule(struct seq_file *file,
					 struct efx_tc_lhs_rule *rule)
{
	struct efx_tc_lhs_action *act = &rule->lhs_act;

	seq_printf(file, "%#lx (%#x)\n", rule->cookie, rule->fw_id);

	efx_tc_debugfs_dump_match(file, &rule->match);

	seq_printf(file, "\tlhs_action\n");
	seq_printf(file, "\t\trecirc_id %#02x\n", act->rid ? act->rid->fw_id : 0);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	if (act->zone)
		seq_printf(file, "\t\tct zone %u\n", act->zone->zone);
#endif
	if (act->count) {
		seq_printf(file, "\t\t\tcount\n");
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
		seq_printf(file, "\t\t\t\tact_idx=%d\n",
			   act->count_action_idx);
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_TC_ACTION_COOKIE)
		seq_printf(file, "\t\t\t\tcookie = %#lx\n",
			   act->count->cookie);
#else
		/* count->cookie == rule->cookie, no point printing it again */
#endif
	}
}

static int efx_tc_debugfs_dump_lhs_rules(struct seq_file *file, void *data)
{
	struct efx_tc_lhs_rule *rule;
	struct rhashtable_iter walk;
	struct efx_nic *efx = data;

	mutex_lock(&efx->tc->mutex);
	if (efx->tc->up) {
		rhashtable_walk_enter(&efx->tc->lhs_rule_ht, &walk);
		rhashtable_walk_start(&walk);
		while ((rule = rhashtable_walk_next(&walk)) != NULL) {
			if (IS_ERR(rule))
				continue;
			efx_tc_debugfs_dump_lhs_rule(file, rule);
		}
		rhashtable_walk_stop(&walk);
		rhashtable_walk_exit(&walk);
	} else {
		seq_printf(file, "tc is down\n");
	}
	mutex_unlock(&efx->tc->mutex);

	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
static void efx_tc_debugfs_dump_ct(struct seq_file *file,
				   struct efx_tc_ct_entry *conn)
{
	seq_printf(file, "%#lx (%#x)\n", conn->cookie, conn->fw_id);
	seq_printf(file, "\tzone = %u\n", conn->zone);
	seq_printf(file, "\teth_proto = %#06x\n", be16_to_cpu(conn->eth_proto));
	seq_printf(file, "\tip_proto = %#04x (%u)\n",
		   conn->ip_proto, conn->ip_proto);
	switch (conn->eth_proto) {
	case htons(ETH_P_IP):
		seq_printf(file, "\tsrc = %pI4:%u\n", &conn->src_ip,
			   be16_to_cpu(conn->l4_sport));
		seq_printf(file, "\tdst = %pI4:%u\n", &conn->dst_ip,
			   be16_to_cpu(conn->l4_dport));
		seq_printf(file, "\t%cnat = %pI4:%u\n", conn->dnat ? 'd' : 's',
			   &conn->nat_ip, be16_to_cpu(conn->l4_natport));
		break;
	case htons(ETH_P_IPV6):
		seq_printf(file, "\tsrc = %pI6c:%u\n", &conn->src_ip6,
			   be16_to_cpu(conn->l4_sport));
		seq_printf(file, "\tdst = %pI6c:%u\n", &conn->dst_ip6,
			   be16_to_cpu(conn->l4_dport));
		break;
	default:
		break;
	}
	seq_printf(file, "\tmark = %#x (%u)\n", conn->mark, conn->mark);
}

static int efx_tc_debugfs_dump_cts(struct seq_file *file, void *data)
{
	struct efx_tc_ct_entry *conn;
	struct rhashtable_iter walk;
	struct efx_nic *efx = data;

	mutex_lock(&efx->tc->mutex);
	if (efx->tc->up) {
		rhashtable_walk_enter(&efx->tc->ct_ht, &walk);
		rhashtable_walk_start(&walk);
		while ((conn = rhashtable_walk_next(&walk)) != NULL) {
			if (IS_ERR(conn))
				continue;
			efx_tc_debugfs_dump_ct(file, conn);
		}
		rhashtable_walk_stop(&walk);
		rhashtable_walk_exit(&walk);
	} else {
		seq_printf(file, "tc is down\n");
	}
	mutex_unlock(&efx->tc->mutex);

	return 0;
}
#endif

static const char *efx_mae_field_names[] = {
#define NAME(_name)	[MAE_FIELD_##_name] = #_name
	NAME(INGRESS_PORT),
	NAME(MARK),
	NAME(RECIRC_ID),
	NAME(IS_IP_FRAG),
	NAME(DO_CT),
	NAME(CT_HIT),
	NAME(CT_MARK),
	NAME(CT_DOMAIN),
	NAME(ETHER_TYPE),
	NAME(VLAN0_TCI),
	NAME(VLAN0_PROTO),
	NAME(VLAN1_TCI),
	NAME(VLAN1_PROTO),
	NAME(ETH_SADDR),
	NAME(ETH_DADDR),
	NAME(SRC_IP4),
	NAME(SRC_IP6),
	NAME(DST_IP4),
	NAME(DST_IP6),
	NAME(IP_PROTO),
	NAME(IP_TOS),
	NAME(IP_TTL),
	NAME(IP_FLAGS),
	NAME(L4_SPORT),
	NAME(L4_DPORT),
	NAME(TCP_FLAGS),
	NAME(ENCAP_TYPE),
	NAME(OUTER_RULE_ID),
	NAME(ENC_ETHER_TYPE),
	NAME(ENC_VLAN0_TCI),
	NAME(ENC_VLAN0_PROTO),
	NAME(ENC_VLAN1_TCI),
	NAME(ENC_VLAN1_PROTO),
	NAME(ENC_ETH_SADDR),
	NAME(ENC_ETH_DADDR),
	NAME(ENC_SRC_IP4),
	NAME(ENC_SRC_IP6),
	NAME(ENC_DST_IP4),
	NAME(ENC_DST_IP6),
	NAME(ENC_IP_PROTO),
	NAME(ENC_IP_TOS),
	NAME(ENC_IP_TTL),
	NAME(ENC_IP_FLAGS),
	NAME(ENC_L4_SPORT),
	NAME(ENC_L4_DPORT),
	NAME(ENC_VNET_ID),
#undef NAME
};

static const char *efx_mae_field_support_names[] = {
	[MAE_FIELD_UNSUPPORTED] = "UNSUPPORTED",
#define NAME(_name)	[MAE_FIELD_SUPPORTED_MATCH_##_name] = #_name
	NAME(NEVER),
	NAME(ALWAYS),
	NAME(OPTIONAL),
	NAME(PREFIX),
	NAME(MASK),
#undef NAME
};

static const char *efx_mae_field_support_name(unsigned int i)
{
	if (i < ARRAY_SIZE(efx_mae_field_support_names))
		return efx_mae_field_support_names[i];
	return "what is this I don't even";
}

static int efx_tc_debugfs_dump_mae_caps(struct seq_file *file, u8 *fields)
{
	int i;

	for (i = 0; i < MAE_NUM_FIELDS; i++)
		if (efx_mae_field_names[i])
			seq_printf(file, "%s\t%s\n", efx_mae_field_names[i],
				   efx_mae_field_support_name(fields[i]));
		else if(fields[i])
			seq_printf(file, "unknown-%d\t%s\n", i,
				   efx_mae_field_support_name(fields[i]));
	return 0;
}

static int efx_tc_debugfs_dump_mae_ar_caps(struct seq_file *file, void *data)
{
	struct efx_nic *efx = data;

	return efx_tc_debugfs_dump_mae_caps(file, efx->tc->caps->action_rule_fields);
}

static int efx_tc_debugfs_dump_mae_or_caps(struct seq_file *file, void *data)
{
	struct efx_nic *efx = data;

	return efx_tc_debugfs_dump_mae_caps(file, efx->tc->caps->outer_rule_fields);
}

static void efx_tc_debugfs_dump_mae_tunnel_cap(struct seq_file *file,
					      struct efx_nic *efx,
					      enum efx_encap_type encap)
{
	if (!efx_mae_check_encap_type_supported(efx, encap))
		seq_printf(file, "%s\n", efx_tc_encap_type_names[encap]);
}

static int efx_tc_debugfs_dump_mae_tunnel_caps(struct seq_file *file, void *data)
{
	struct efx_nic *efx = data;

	efx_tc_debugfs_dump_mae_tunnel_cap(file, efx, EFX_ENCAP_TYPE_VXLAN);
	efx_tc_debugfs_dump_mae_tunnel_cap(file, efx, EFX_ENCAP_TYPE_NVGRE);
	efx_tc_debugfs_dump_mae_tunnel_cap(file, efx, EFX_ENCAP_TYPE_GENEVE);
	return 0;
}

static int efx_tc_debugfs_dump_action_prios(struct seq_file *file, void *data)
{
	struct efx_nic *efx = data;

	seq_printf(file, "%u\n", efx->tc->caps->action_prios);
	return 0;
}

static int efx_tc_debugfs_dump_mae_neighs(struct seq_file *file, void *data)
{
	struct efx_neigh_binder *neigh;
	struct rhashtable_iter walk;
	struct efx_nic *efx = data;

	mutex_lock(&efx->tc->mutex);
	rhashtable_walk_enter(&efx->tc->neigh_ht, &walk);
	rhashtable_walk_start(&walk);
	while ((neigh = rhashtable_walk_next(&walk)) != NULL) {
		if (IS_ERR(neigh))
			continue;
		if (neigh->dst_ip) /* IPv4 */
			seq_printf(file, "%pI4: %svalid %pM ttl %hhu egdev %s ref %u\n",
				   &neigh->dst_ip, neigh->n_valid ? "" : "in",
				   neigh->ha, neigh->ttl, neigh->egdev->name,
				   refcount_read(&neigh->ref));
		else /* IPv6 */
			seq_printf(file, "%pI6c: %svalid %pM ttl %hhu egdev %s ref %u\n",
				   &neigh->dst_ip6, neigh->n_valid ? "" : "in",
				   neigh->ha, neigh->ttl, neigh->egdev->name,
				   refcount_read(&neigh->ref));
	}
	rhashtable_walk_stop(&walk);
	rhashtable_walk_exit(&walk);
	mutex_unlock(&efx->tc->mutex);
	return 0;
}

static int efx_tc_debugfs_dump_mports(struct seq_file *file, void *data)
{
	struct efx_nic *efx = data;
	unsigned int i;

	for (i = 0; i < efx->tc->n_mports; i++) {
		const struct mae_mport_desc *m = efx->tc->mports + i;
		char buf[100];
		size_t n;

		n = scnprintf(buf, sizeof(buf), "id %08x flags %02x cf %02x",
			      m->mport_id, m->flags, m->caller_flags);
		if (m->caller_flags & MAE_MPORT_DESC_FLAG__MASK)
			/* R = receive, T = transmit (deliver), X = delete.
			 * Avoided using 'D' for either, as that's ambiguous
			 */
			n += scnprintf(buf + n, sizeof(buf) - n,
				       " (%c%c%c)",
				       (m->caller_flags & MAE_MPORT_DESC_FLAG_CAN_RECEIVE_ON) ? 'R' : 'r',
				       (m->caller_flags & MAE_MPORT_DESC_FLAG_CAN_DELIVER_TO) ? 'T' : 't',
				       (m->caller_flags & MAE_MPORT_DESC_FLAG_CAN_DELETE) ? 'X' : 'x');
		switch (m->mport_type) {
		case MAE_MPORT_DESC_MPORT_TYPE_NET_PORT:
			n += scnprintf(buf + n, sizeof(buf) - n,
				       " type net_port idx %u", m->port_idx);
			break;
		case MAE_MPORT_DESC_MPORT_TYPE_ALIAS:
			n += scnprintf(buf + n, sizeof(buf) - n,
				       " type alias mport %u", m->alias_mport_id);
			break;
		case MAE_MPORT_DESC_MPORT_TYPE_VNIC:
			n += scnprintf(buf + n, sizeof(buf) - n, " type vnic");
			switch (m->vnic_client_type) {
			case MAE_MPORT_DESC_VNIC_CLIENT_TYPE_FUNCTION:
				n += scnprintf(buf + n, sizeof(buf) - n,
					       " ct fn if %u pf %u",
					       m->interface_idx, m->pf_idx);
				if (m->vf_idx != MAE_MPORT_DESC_VF_IDX_NULL)
					n += scnprintf(buf + n, sizeof(buf) - n,
						       " vf %u", m->vf_idx);
				break;
			case MAE_MPORT_DESC_VNIC_CLIENT_TYPE_PLUGIN:
				n += scnprintf(buf + n, sizeof(buf) - n,
					       " ct plugin");
				break;
			default:
				n += scnprintf(buf + n, sizeof(buf) - n,
					       " ct %u\n", m->vnic_client_type);
				break;

			}
			break;
		default:
			n += scnprintf(buf + n, sizeof(buf) - n,
				       " type %u", m->mport_type);
			break;

		}
		/* Trailing
		 * '.' will be absent if line truncated to fit buf */
		snprintf(buf + n, sizeof(buf) - n, ".");
		seq_printf(file, "%s\n", buf);

	}

	return 0;
}

static struct efx_debugfs_parameter efx_tc_debugfs[] = {
	_EFX_RAW_PARAMETER(mae_rules, efx_tc_debugfs_dump_rules),
	_EFX_RAW_PARAMETER(lhs_rules, efx_tc_debugfs_dump_lhs_rules),
	_EFX_RAW_PARAMETER(mae_default_rules, efx_tc_debugfs_dump_default_rules),
	_EFX_RAW_PARAMETER(mae_counters, efx_tc_debugfs_dump_mae_counters),
	_EFX_RAW_PARAMETER(mae_recirc_ids, efx_tc_debugfs_dump_recirc_ids),
	_EFX_RAW_PARAMETER(mae_action_rule_caps, efx_tc_debugfs_dump_mae_ar_caps),
	_EFX_RAW_PARAMETER(mae_outer_rule_caps, efx_tc_debugfs_dump_mae_or_caps),
	_EFX_RAW_PARAMETER(mae_tunnel_caps, efx_tc_debugfs_dump_mae_tunnel_caps),
	_EFX_RAW_PARAMETER(mae_prios, efx_tc_debugfs_dump_action_prios),
	_EFX_RAW_PARAMETER(mae_neighs, efx_tc_debugfs_dump_mae_neighs),
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	_EFX_RAW_PARAMETER(tracked_conns, efx_tc_debugfs_dump_cts),
#endif
	_EFX_RAW_PARAMETER(mae_mport_map, efx_tc_debugfs_dump_mports),
	{NULL}
};
#endif /* CONFIG_SFC_DEBUGFS */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_QDISC)
static int efx_tc_indr_setup_cb(struct net_device *net_dev, struct Qdisc *sch, void *cb_priv,
#else
static int efx_tc_indr_setup_cb(struct net_device *net_dev, void *cb_priv,
#endif
				enum tc_setup_type type, void *type_data,
				void *data, void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct flow_block_offload *tcb = type_data;
	struct efx_tc_block_binding *binding;
	struct flow_block_cb *block_cb;
	struct efx_nic *efx = cb_priv;
	int rc;

	switch (type) {
	case TC_SETUP_BLOCK:
		switch (tcb->command) {
		case FLOW_BLOCK_BIND:
			binding = efx_tc_create_binding(efx, NULL, net_dev, tcb->block);
			if (IS_ERR(binding))
				return PTR_ERR(binding);
			block_cb = flow_indr_block_cb_alloc(efx_tc_block_cb, binding,
							    binding, efx_tc_block_unbind,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_QDISC)
							    tcb, net_dev, sch, data, binding,
#else
							    tcb, net_dev, data, binding,
#endif
							    cleanup);
			rc = PTR_ERR_OR_ZERO(block_cb);
			netif_dbg(efx, drv, efx->net_dev,
				  "bind indr block for device %s, rc %d\n",
				  net_dev ? net_dev->name : NULL, rc);
			if (rc) {
				list_del(&binding->list);
				kfree(binding);
			} else {
				flow_block_cb_add(block_cb, tcb);
			}
			return rc;
		case FLOW_BLOCK_UNBIND:
			binding = efx_tc_find_binding(efx, net_dev);
			if (!binding)
				return -ENOENT;
			block_cb = flow_block_cb_lookup(tcb->block,
							efx_tc_block_cb,
							binding);
			if (!block_cb)
				return -ENOENT;
			flow_indr_block_cb_remove(block_cb, tcb);
			netif_dbg(efx, drv, efx->net_dev,
				  "unbind indr block for device %s\n",
				  net_dev ? net_dev->name : NULL);
			return 0;
		default:
			return -EOPNOTSUPP;
		}
	default:
		return -EOPNOTSUPP;
	}
}
#elif defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
static int efx_tc_indr_setup_cb(struct net_device *net_dev, void *cb_priv,
				enum tc_setup_type type, void *type_data)
{
	switch (type) {
	case TC_SETUP_BLOCK:
		return efx_tc_setup_block(net_dev, cb_priv, type_data, NULL);
	default:
		return -EOPNOTSUPP;
	}
}

#endif

static int efx_tc_configure_rep_mport(struct efx_nic *efx)
{
	struct efx_vport *rep_vport;
	u32 rep_mport_label;
	int rc;

	rc = efx_mae_allocate_mport(efx, &efx->tc->reps_mport_id, &rep_mport_label);
	if (rc)
		return rc;
	netif_dbg(efx, drv, efx->net_dev, "created rep mport 0x%08x (0x%04x)\n",
		  efx->tc->reps_mport_id, rep_mport_label);
	/* Fake up a vport ID mapping for filters */
	mutex_lock(&efx->vport_lock);
	rep_vport = efx_alloc_vport_entry(efx);
	if (rep_vport)
		/* Use mport *selector* as vport ID */
		efx_mae_mport_mport(efx, efx->tc->reps_mport_id, &rep_vport->vport_id);
	else
		rc = -ENOMEM;
	mutex_unlock(&efx->vport_lock);
	if (rc)
		return rc;
	efx->tc->reps_mport_vport_id = rep_vport->user_id;
	netif_dbg(efx, drv, efx->net_dev, "allocated rep vport 0x%04x\n",
		  efx->tc->reps_mport_vport_id);
	return 0;
}

static void efx_tc_deconfigure_rep_mport(struct efx_nic *efx)
{
	struct efx_vport *rep_vport;

	mutex_lock(&efx->vport_lock);
	rep_vport = efx_find_vport_entry(efx, efx->tc->reps_mport_vport_id);
	if (!rep_vport)
		goto out_unlock;
	efx_free_vport_entry(rep_vport);
	efx->tc->reps_mport_vport_id = 0;
out_unlock:
	mutex_unlock(&efx->vport_lock);
	efx_mae_free_mport(efx, efx->tc->reps_mport_id);
	efx->tc->reps_mport_id = MAE_MPORT_SELECTOR_NULL;
}

int efx_tc_insert_rep_filters(struct efx_nic *efx)
{
	struct efx_filter_spec promisc, allmulti;
	int rc;

	if (efx->type->is_vf)
		return 0;
	if (!efx->tc)
		return 0;
	efx_filter_init_rx(&promisc, EFX_FILTER_PRI_REQUIRED, 0, 0);
	efx_filter_set_uc_def(&promisc);
	efx_filter_set_vport_id(&promisc, efx->tc->reps_mport_vport_id);
	rc = efx_filter_insert_filter(efx, &promisc, false);
	if (rc < 0)
		return rc;
	efx->tc->reps_filter_uc = rc;
	efx_filter_init_rx(&allmulti, EFX_FILTER_PRI_REQUIRED, 0, 0);
	efx_filter_set_mc_def(&allmulti);
	efx_filter_set_vport_id(&allmulti, efx->tc->reps_mport_vport_id);
	rc = efx_filter_insert_filter(efx, &allmulti, false);
	if (rc < 0)
		return rc;
	efx->tc->reps_filter_mc = rc;
	return 0;
}

void efx_tc_remove_rep_filters(struct efx_nic *efx)
{
	if (efx->type->is_vf)
		return;
	if (!efx->tc)
		return;
	if (efx->tc->reps_filter_mc != (u32)-1)
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED, efx->tc->reps_filter_mc);
	efx->tc->reps_filter_mc = -1;
	if (efx->tc->reps_filter_uc != (u32)-1)
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED, efx->tc->reps_filter_uc);
	efx->tc->reps_filter_uc = -1;
}

int efx_init_tc(struct efx_nic *efx)
{
	int rc;

	rc = efx_mae_get_caps(efx, efx->tc->caps);
	if (rc)
		return rc;
	if (efx->tc->caps->match_field_count > MAE_NUM_FIELDS)
		/* Firmware supports some match fields the driver doesn't know
		 * about.  Not fatal, unless any of those fields are required
		 * (MAE_FIELD_SUPPORTED_MATCH_ALWAYS) but if so we don't know.
		 */
		netif_warn(efx, probe, efx->net_dev,
			   "FW reports additional match fields %u\n",
			   efx->tc->caps->match_field_count);
	if (efx->tc->caps->action_prios < EFX_TC_PRIO__NUM) {
		netif_err(efx, probe, efx->net_dev,
			  "Too few action prios supported (have %u, need %u)\n",
			  efx->tc->caps->action_prios, EFX_TC_PRIO__NUM);
		return -EIO;
	}
	rc = efx_tc_configure_rep_mport(efx);
	if (rc)
		return rc;
	rc = efx_tc_enumerate_mports(efx);
	if (rc) /* Not fatal, but means we can't create PF reps for other IFs */
		netif_warn(efx, probe, efx->net_dev,
			   "Could not enumerate mports (rc=%d), are we admin?",
			   rc);
	mutex_lock(&efx->tc->mutex);
	rc = efx_tc_configure_default_rule(efx, EFX_TC_DFLT_PF);
	if (rc)
		goto out_unlock;
	rc = efx_tc_configure_default_rule(efx, EFX_TC_DFLT_WIRE);
	if (rc)
		goto out_unlock;

#ifdef CONFIG_SFC_DEBUGFS
	efx_extend_debugfs_port(efx, efx, 0, efx_tc_debugfs);
#endif
	efx->tc->up = true;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
	rc = flow_indr_dev_register(efx_tc_indr_setup_cb, efx);
#endif

out_unlock:
	mutex_unlock(&efx->tc->mutex);
	return rc;
}

void efx_fini_tc(struct efx_nic *efx)
{
	int i;

	/* We can get called even if efx_init_struct_tc() failed */
	if (!efx->tc)
		return;
#ifdef CONFIG_SFC_DEBUGFS
	efx_trim_debugfs_port(efx, efx_tc_debugfs);
#endif
	mutex_lock(&efx->tc->mutex);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
	if (efx->tc->up)
		flow_indr_dev_unregister(efx_tc_indr_setup_cb, efx, efx_tc_block_unbind);
#endif
	for (i = 0; i < EFX_TC_DFLT__MAX; i++)
		efx_tc_deconfigure_default_rule(efx, i);
	efx_tc_deconfigure_rep_mport(efx);
	efx->tc->up = false;
	kfree(efx->tc->mports);
	efx->tc->mports = NULL;
	efx->tc->n_mports = 0;
	mutex_unlock(&efx->tc->mutex);
}

int efx_setup_tc(struct net_device *net_dev, enum tc_setup_type type,
		 void *type_data)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->is_vf)
		return -EOPNOTSUPP;

	if (type == TC_SETUP_CLSFLOWER)
		return efx_tc_flower(efx, net_dev, type_data, NULL);
	if (type == TC_SETUP_BLOCK)
		return efx_tc_setup_block(net_dev, efx, type_data, NULL);

	return -EOPNOTSUPP;
}

int efx_tc_netdev_event(struct efx_nic *efx, unsigned long event,
			struct net_device *net_dev)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) || defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
	enum efx_encap_type etyp = efx_tc_indr_netdev_type(net_dev);
	int rc;
#endif /* EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER */

	if (efx->type->is_vf)
		return NOTIFY_DONE;

	if (event == NETDEV_UNREGISTER)
		efx_tc_unregister_egdev(efx, net_dev);

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER)
	if (etyp == EFX_ENCAP_TYPE_NONE)
		return NOTIFY_OK;
	if (event == NETDEV_REGISTER) {
		rc = __flow_indr_block_cb_register(net_dev, efx,
						   efx_tc_indr_setup_cb, efx);
		if (rc)
			netif_warn(efx, drv, efx->net_dev,
				   "Indirect block reg failed %d for %s\n", rc,
				   net_dev->name);
		else
			netif_dbg(efx, drv, efx->net_dev,
				  "reg indirect block for device %s\n",
				  net_dev ? net_dev->name : NULL);
	} else if (event == NETDEV_UNREGISTER) {
		__flow_indr_block_cb_unregister(net_dev, efx_tc_indr_setup_cb,
						efx);
		netif_dbg(efx, drv, efx->net_dev,
			  "unreg indirect block for device %s\n",
			  net_dev ? net_dev->name : NULL);
	}
#endif /* EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER */
#endif

	return NOTIFY_OK;
}

int efx_tc_netevent_event(struct efx_nic *efx, unsigned long event,
			  void *ptr)
{
	if (efx->type->is_vf)
		return NOTIFY_DONE;

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		return efx_neigh_event(efx, ptr);
	case NETEVENT_DELAY_PROBE_TIME_UPDATE:
		/* TODO care about these */
	default:
		return NOTIFY_DONE;
	}
}

#else /* EFX_TC_OFFLOAD */
#include "tc.h"
#include "mae.h"

static int efx_tc_configure_default_rule(struct efx_nic *efx,
					 enum efx_tc_default_rules dflt)
{
	struct efx_tc_flow_rule *rule = efx->tc->dflt_rules + dflt;
	struct efx_tc_action_set_list *acts = &rule->acts;
	struct efx_tc_match *match = &rule->match;
	struct efx_tc_action_set *act;
	u32 ing_port, eg_port;
	int rc;

	INIT_LIST_HEAD(&acts->list);
	switch (dflt) {
	case EFX_TC_DFLT_PF:
		efx_mae_mport_uplink(efx, &ing_port);
		efx_mae_mport_wire(efx, &eg_port);
		break;
	case EFX_TC_DFLT_WIRE:
		efx_mae_mport_wire(efx, &ing_port);
		efx_mae_mport_uplink(efx, &eg_port);
		break;
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
	match->value.ingress_port = ing_port;
	match->mask.ingress_port = ~0;
	act = kzalloc(sizeof(*act), GFP_KERNEL);
	if (!act)
		return -ENOMEM;
	act->deliver = 1;
	act->dest_mport = eg_port;
	rc = efx_mae_alloc_action_set(efx, act);
	if (rc)
		goto fail1;
	list_add_tail(&act->list, &acts->list);
	rc = efx_mae_alloc_action_set_list(efx, acts);
	if (rc)
		goto fail2;
	rc = efx_mae_insert_rule(efx, match, EFX_TC_PRIO_DFLT,
				 acts->fw_id, &rule->fw_id);
	if (rc)
		goto fail3;
	return 0;
fail3:
	efx_mae_free_action_set_list(efx, acts);
fail2:
	list_del(&act->list);
	efx_mae_free_action_set(efx, act);
fail1:
	kfree(act);
	return rc;
}

static void efx_tc_delete_rule(struct efx_nic *efx, struct efx_tc_flow_rule *rule)
{
	struct efx_tc_action_set *act;

	efx_mae_delete_rule(efx, rule->fw_id);

	/* Release entries in subsidiary tables */
	list_for_each_entry(act, &rule->acts.list, list) {
		efx_mae_free_action_set(efx, act);
		kfree(act);
	}
	efx_mae_free_action_set_list(efx, &rule->acts);
	rule->fw_id = MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL;
}

static void efx_tc_deconfigure_default_rule(struct efx_nic *efx,
					    enum efx_tc_default_rules dflt)
{
	struct efx_tc_flow_rule *rule = efx->tc->dflt_rules + dflt;

	if (rule->fw_id != MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL)
		efx_tc_delete_rule(efx, rule);
}

int efx_tc_insert_rep_filters(struct efx_nic *efx)
{
	return 0;
}

void efx_tc_remove_rep_filters(struct efx_nic *efx)
{
}

int efx_init_tc(struct efx_nic *efx)
{
	int rc;

	rc = efx_mae_get_caps(efx, efx->tc->caps);
	if (rc)
		return rc;
	if (efx->tc->caps->match_field_count > MAE_NUM_FIELDS)
		/* Firmware supports some match fields the driver doesn't know
		 * about.  Not fatal, unless any of those fields are required
		 * (MAE_FIELD_SUPPORTED_MATCH_ALWAYS) but if so we don't know.
		 */
		netif_warn(efx, probe, efx->net_dev,
			   "FW reports additional match fields %u\n",
			   efx->tc->caps->match_field_count);
	if (efx->tc->caps->action_prios < EFX_TC_PRIO__NUM) {
		netif_err(efx, probe, efx->net_dev,
			  "Too few action prios supported (have %u, need %u)\n",
			  efx->tc->caps->action_prios, EFX_TC_PRIO__NUM);
		return -EIO;
	}
	rc = efx_tc_configure_default_rule(efx, EFX_TC_DFLT_PF);
	if (rc)
		return rc;
	return efx_tc_configure_default_rule(efx, EFX_TC_DFLT_WIRE);
}

void efx_fini_tc(struct efx_nic *efx)
{
	int i;

	/* We can get called even if efx_init_struct_tc() failed */
	if (!efx->tc)
		return;
	for (i = 0; i < EFX_TC_DFLT__MAX; i++)
		efx_tc_deconfigure_default_rule(efx, i);
}

int efx_init_struct_tc(struct efx_nic *efx)
{
	int rc, i;

	if (efx->type->is_vf)
		return 0;

	efx->tc = kzalloc(sizeof(*efx->tc), GFP_KERNEL);
	if (!efx->tc)
		return -ENOMEM;
	efx->tc->caps = kzalloc(sizeof(struct mae_caps), GFP_KERNEL);
	if (!efx->tc->caps) {
		rc = -ENOMEM;
		goto fail1;
	}

	efx->tc->dflt_rules = kcalloc(EFX_TC_DFLT__MAX,
				      sizeof(*efx->tc->dflt_rules),
				      GFP_KERNEL);
	rc = -ENOMEM;
	if (!efx->tc->dflt_rules)
		goto fail2;
	for (i = 0; i < EFX_TC_DFLT__MAX; i++)
		efx->tc->dflt_rules[i].fw_id = MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL;
	return 0;
fail2:
	kfree(efx->tc->caps);
fail1:
	kfree(efx->tc);
	efx->tc = NULL;
	return rc;
}

void efx_fini_struct_tc(struct efx_nic *efx)
{
	if (!efx->tc)
		return;

	kfree(efx->tc->dflt_rules);
	kfree(efx->tc->caps);
	kfree(efx->tc);
	efx->tc = NULL;
}

int efx_tc_netdev_event(struct efx_nic *efx, unsigned long event,
			struct net_device *net_dev)
{
	return NOTIFY_OK;
}

int efx_tc_netevent_event(struct efx_nic *efx, unsigned long event,
			  void *ptr)
{
	return NOTIFY_OK;
}

#endif /* EFX_TC_OFFLOAD */
