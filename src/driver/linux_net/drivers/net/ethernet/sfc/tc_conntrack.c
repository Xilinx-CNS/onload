/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2022 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifdef EFX_USE_KCOMPAT
/* Must come before other headers */
#include "kernel_compat.h"
#endif

#include "tc_conntrack.h"
#include "tc.h"
#include "mae.h"

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
#if IS_ENABLED(CONFIG_NF_FLOW_TABLE)
static int efx_tc_flow_block(enum tc_setup_type type, void *type_data,
			     void *cb_priv);
#endif

static const struct rhashtable_params efx_tc_ct_zone_ht_params = {
	.key_len	= offsetof(struct efx_tc_ct_zone, linkage),
	.key_offset	= 0,
	.head_offset	= offsetof(struct efx_tc_ct_zone, linkage),
};

static const struct rhashtable_params efx_tc_ct_ht_params = {
	.key_len	= offsetof(struct efx_tc_ct_entry, linkage),
	.key_offset	= 0,
	.head_offset	= offsetof(struct efx_tc_ct_entry, linkage),
};

static void efx_tc_ct_zone_free(void *ptr, void *arg)
{
	struct efx_tc_ct_zone *zone = ptr;
	struct efx_nic *efx = zone->efx;

	netif_err(efx, drv, efx->net_dev,
		  "tc ct_zone %u still present at teardown, removing\n",
		  zone->zone);

	ida_free(&efx->tc->domain_ida, zone->domain);
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
		  "tc ct_entry %lx still present at teardown\n",
		  conn->cookie);

	/* We can release the counter, but we can't remove the CT itself
	 * from hardware because the table meta is already gone.
	 */
	efx_tc_flower_release_counter(efx, conn->cnt);
	kfree(conn);
}

int efx_tc_init_conntrack(struct efx_nic *efx)
{
	int rc;

	rc = rhashtable_init(&efx->tc->ct_zone_ht, &efx_tc_ct_zone_ht_params);
	if (rc < 0)
		goto fail_ct_zone_ht;
	rc = rhashtable_init(&efx->tc->ct_ht, &efx_tc_ct_ht_params);
	if (rc < 0)
		goto fail_ct_ht;
	ida_init(&efx->tc->domain_ida);
	return 0;
fail_ct_ht:
	rhashtable_destroy(&efx->tc->ct_zone_ht);
fail_ct_zone_ht:
	return rc;
}

/* Only call this in init failure teardown.
 * Normal exit should fini instead as there may be entries in the table.
 */
void efx_tc_destroy_conntrack(struct efx_nic *efx)
{
	ida_destroy(&efx->tc->domain_ida);
	rhashtable_destroy(&efx->tc->ct_ht);
	rhashtable_destroy(&efx->tc->ct_zone_ht);
}

void efx_tc_fini_conntrack(struct efx_nic *efx)
{
	rhashtable_free_and_destroy(&efx->tc->ct_zone_ht, efx_tc_ct_zone_free, NULL);
	rhashtable_free_and_destroy(&efx->tc->ct_ht, efx_tc_ct_free, efx);
	WARN_ON(!ida_is_empty(&efx->tc->domain_ida));
	ida_destroy(&efx->tc->domain_ida);
}

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
	}
#ifdef CONFIG_IPV6
	else if (ipv == 6 && flow_rule_match_key(fr, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
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
	}
#endif
	else {
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

		if (!tcp) {
			efx_tc_err(efx, "Conntrack matching on TCP keys but ipproto is not tcp\n");
			return -EOPNOTSUPP;
		}
		flow_rule_match_tcp(fr, &fm);
		tcp_interesting_flags = EFX_NF_TCP_FLAG(SYN) |
					EFX_NF_TCP_FLAG(RST) |
					EFX_NF_TCP_FLAG(FIN);
		/* If any of the tcp_interesting_flags is set, we always
		 * inhibit CT lookup in LHS (so SW can update CT table).
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
			fallthrough;
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
			fallthrough;
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
	struct efx_tc_counter *cnt;
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
	conn->domain = ct_zone->domain;
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

	cnt = efx_tc_flower_allocate_counter(efx, EFX_TC_COUNTER_TYPE_CT);
	if (IS_ERR(cnt)) {
		rc = PTR_ERR(cnt);
		goto release;
	}
	conn->cnt = cnt;

	rc = efx_mae_insert_ct(efx, conn);
	if (rc) {
		efx_tc_err(efx, "Failed to insert conntrack, %d\n", rc);
		goto release;
	}
	down_write(&ct_zone->rwsem);
	list_add_tail(&conn->list, &ct_zone->cts);
	up_write(&ct_zone->rwsem);
	return 0;
release:
	if (conn->cnt)
		efx_tc_flower_release_counter(efx, conn->cnt);
	if (!old)
		rhashtable_remove_fast(&efx->tc->ct_ht, &conn->linkage,
				       efx_tc_ct_ht_params);
	kfree(conn);
	return rc;
}

/* Caller must follow with efx_tc_ct_remove_finish() after RCU grace period! */
static void efx_tc_ct_remove(struct efx_nic *efx, struct efx_tc_ct_entry *conn)
{
	int rc;

	/* Remove it from HW */
	rc = efx_mae_remove_ct(efx, conn);
	/* Delete it from SW */
	rhashtable_remove_fast(&efx->tc->ct_ht, &conn->linkage,
			       efx_tc_ct_ht_params);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "Failed to remove conntrack %lx from hw, rc %d\n",
			  conn->cookie, rc);
	} else {
		netif_dbg(efx, drv, efx->net_dev, "Removed conntrack %lx\n",
			  conn->cookie);
	}
}

static void efx_tc_ct_remove_finish(struct efx_nic *efx, struct efx_tc_ct_entry *conn)
{
	/* Remove related CT counter. This is delayed after the conn object we
	 * are working with has been succesfully removed. This is specifically
	 * for properly protecting the counter from being used inside
	 * efx_tc_ct_stats:
	 *
	 *	1) no conn, no counter reachable.
	 *	2) Conn exists, the previous synchronize_rcu precludes us from
	 *	   removing the counter here until efx_tc_ct_stats is done.
	 *
	 * Note releasing the counter through the next function call is fine
	 * with concurrent uses of the counter since that is all done through
	 * the rhastable API for the counter_ht rhashtable which takes care of
	 * the safe counter removal.
	 */
	efx_tc_flower_release_counter(efx, conn->cnt);
	kfree(conn);
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

	down_write(&ct_zone->rwsem);
	list_del(&conn->list);
	efx_tc_ct_remove(efx, conn);
	up_write(&ct_zone->rwsem);
	synchronize_rcu();
	efx_tc_ct_remove_finish(efx, conn);
	return 0;
}

static int efx_tc_ct_stats(struct efx_tc_ct_zone *ct_zone,
			   struct flow_cls_offload *tc)
{
	struct efx_nic *efx = ct_zone->efx;
	struct efx_tc_ct_entry *conn;
	struct efx_tc_counter *cnt;

	rcu_read_lock();
	conn = rhashtable_lookup_fast(&efx->tc->ct_ht, &tc->cookie,
				      efx_tc_ct_ht_params);
	if (!conn) {
		netif_warn(efx, drv, efx->net_dev,
			   "Conntrack %lx not found for stats\n", tc->cookie);
		rcu_read_unlock();
		return -ENOENT;
	}

	cnt = conn->cnt;
	spin_lock_bh(&cnt->lock);
	/* Report only last use */
	flow_stats_update(&tc->stats, 0, 0,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_STATS_DROPS)
			  0,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_FLOW_STATS_TYPE)
			  cnt->touched, FLOW_ACTION_HW_STATS_DELAYED);
#else
			  cnt->touched);
#endif
	spin_unlock_bh(&cnt->lock);
	rcu_read_unlock();

	return 0;
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

struct efx_tc_ct_zone *efx_tc_ct_register_zone(struct efx_nic *efx, u16 zone,
					       u8 vni_mode,
					       struct nf_flowtable *ct_ft)
{
	struct efx_tc_ct_zone *ct_zone, *old;
	int rc;

	ct_zone = kzalloc(sizeof(*ct_zone), GFP_USER);
	if (!ct_zone)
		return ERR_PTR(-ENOMEM);
	ct_zone->zone = zone;
	ct_zone->vni_mode = vni_mode;
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
		netif_dbg(efx, drv, efx->net_dev,
			  "Found existing ct_zone for %u@%u\n", zone, vni_mode);
		return old;
	}
	ct_zone->nf_ft = ct_ft;
	ct_zone->efx = efx;
	INIT_LIST_HEAD(&ct_zone->cts);
	init_rwsem(&ct_zone->rwsem);
	rc = ida_alloc_range(&efx->tc->domain_ida, 0, U16_MAX, GFP_USER);
	if (rc < 0) {
		if (net_ratelimit())
			netif_warn(efx, drv, efx->net_dev,
				   "Failed to allocate a domain (rc %d) for %u@%u\n",
				   rc, zone, vni_mode);
		goto fail1;
	}
	ct_zone->domain = rc;
	rc = nf_flow_table_offload_add_cb(ct_ft, efx_tc_flow_block, ct_zone);
	netif_dbg(efx, drv, efx->net_dev, "Adding new ct_zone for %u@%u, rc %d\n",
		  zone, vni_mode, rc);
	if (rc < 0)
		goto fail2;
	refcount_set(&ct_zone->ref, 1);
	return ct_zone;
fail2:
	ida_free(&efx->tc->domain_ida, ct_zone->domain);
fail1:
	rhashtable_remove_fast(&efx->tc->ct_zone_ht, &ct_zone->linkage,
				       efx_tc_ct_zone_ht_params);
	kfree(ct_zone);
	return ERR_PTR(rc);
}

void efx_tc_ct_unregister_zone(struct efx_nic *efx,
			       struct efx_tc_ct_zone *ct_zone)
{
	struct efx_tc_ct_entry *conn, *next;

	if (!refcount_dec_and_test(&ct_zone->ref))
		return; /* still in use */
	nf_flow_table_offload_del_cb(ct_zone->nf_ft, efx_tc_flow_block, ct_zone);
	rhashtable_remove_fast(&efx->tc->ct_zone_ht, &ct_zone->linkage,
			       efx_tc_ct_zone_ht_params);
	down_write(&ct_zone->rwsem);
	list_for_each_entry(conn, &ct_zone->cts, list)
		efx_tc_ct_remove(efx, conn);
	synchronize_rcu();
	/* _safe because efx_tc_ct_remove_finish() frees conn */
	list_for_each_entry_safe(conn, next, &ct_zone->cts, list)
		efx_tc_ct_remove_finish(efx, conn);
	up_write(&ct_zone->rwsem);
	ida_free(&efx->tc->domain_ida, ct_zone->domain);
	netif_dbg(efx, drv, efx->net_dev, "Removed ct_zone for %u@%u\n",
		  ct_zone->zone, ct_zone->vni_mode);
	kfree(ct_zone);
}
#else
struct efx_tc_ct_zone *efx_tc_ct_register_zone(struct efx_nic *efx, u16 zone,
					       u8 vni_mode,
					       struct nf_flowtable *ct_ft)
{
	return ERR_PTR(-EOPNOTSUPP);
}

void efx_tc_ct_unregister_zone(struct efx_nic *efx,
			       struct efx_tc_ct_zone *ct_zone) {}
#endif /* CONFIG_NF_FLOW_TABLE */

#endif /* EFX_CONNTRACK_OFFLOAD */
