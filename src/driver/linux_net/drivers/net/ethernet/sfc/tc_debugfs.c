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

#include "tc_debugfs.h"
#include "tc.h"
#include "tc_encap_actions.h"
#include "tc_conntrack.h"
#include "nic.h"

#ifdef CONFIG_SFC_DEBUGFS
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
static void efx_tc_debugfs_dump_encap_match(struct seq_file *file,
					    struct efx_tc_encap_match *encap)
{
	char errbuf[16];

	switch (encap->type) {
	case EFX_TC_EM_DIRECT:
		seq_printf(file, "\tencap_match (%#x)\n", encap->fw_id);
		break;
	case EFX_TC_EM_PSEUDO_OR:
		seq_printf(file, "\tencap_match (pseudo for OR)\n");
		break;
	case EFX_TC_EM_PSEUDO_TOS:
		seq_printf(file, "\tencap_match (pseudo for IP ToS & %#04x)\n",
			   encap->child_ip_tos_mask);
		break;
	default:
		seq_printf(file, "\tencap_match (pseudo type %d)\n",
			   encap->type);
		break;
	}
#ifdef CONFIG_IPV6
	if (encap->src_ip | encap->dst_ip) {
#endif
		seq_printf(file, "\t\tsrc_ip = %pI4\n", &encap->src_ip);
		seq_printf(file, "\t\tdst_ip = %pI4\n", &encap->dst_ip);
#ifdef CONFIG_IPV6
	} else {
		seq_printf(file, "\t\tsrc_ip6 = %pI6c\n", &encap->src_ip6);
		seq_printf(file, "\t\tdst_ip6 = %pI6c\n", &encap->dst_ip6);
	}
#endif
	seq_printf(file, "\t\tudp_dport = %u\n", be16_to_cpu(encap->udp_dport));
	if (encap->ip_tos_mask) {
		if (encap->ip_tos_mask == 0xff)
			seq_printf(file, "\t\tip_tos = %#04x (%u)\n",
				   encap->ip_tos, encap->ip_tos);
		else
			seq_printf(file, "\t\tip_tos & %#04x = %#04x\n",
				   encap->ip_tos_mask, encap->ip_tos);
	}
	seq_printf(file, "\t\ttun_type = %s\n",
		   efx_tc_encap_type_name(encap->tun_type, errbuf,
					  sizeof(errbuf)));
	seq_printf(file, "\t\tref = %u\n", refcount_read(&encap->ref));
	if (encap->pseudo) {
		seq_printf(file, "\t\thas_pseudo ::\n");
		efx_tc_debugfs_dump_encap_match(file, encap->pseudo);
	}
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
		seq_printf(file, " %c%s",				\
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
	if (match->mask.ip_firstfrag)
		seq_printf(file, "\tip_firstfrag = %d\n", match->value.ip_firstfrag);
	DUMP_FMT_AMP_MATCH(src_ip, "%pI4");
	DUMP_FMT_AMP_MATCH(dst_ip, "%pI4");
#ifdef CONFIG_IPV6
	DUMP_FMT_PTR_MATCH(src_ip6, "%pI6");
	DUMP_FMT_PTR_MATCH(dst_ip6, "%pI6");
#endif
	DUMP_ONE_MATCH(l4_sport);
	DUMP_ONE_MATCH(l4_dport);
	DUMP_ONE_MATCH(tcp_flags);
	DUMP_ONE_MATCH(tcp_syn_fin_rst);
	DUMP_FMT_AMP_MATCH(enc_src_ip, "%pI4");
	DUMP_FMT_AMP_MATCH(enc_dst_ip, "%pI4");
#ifdef CONFIG_IPV6
	DUMP_FMT_PTR_MATCH(enc_src_ip6, "%pI6c");
	DUMP_FMT_PTR_MATCH(enc_dst_ip6, "%pI6c");
#endif
	DUMP_ONE_MATCH(enc_ip_tos);
	DUMP_ONE_MATCH(enc_ip_ttl);
	DUMP_ONE_MATCH(enc_sport);
	DUMP_ONE_MATCH(enc_dport);
	DUMP_ONE_MATCH(enc_keyid);
	efx_tc_debugfs_dump_ct_bits(file, match);
	DUMP_FMT_MATCH(ct_mark, "%#010x");
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
		if (act->src_mac) {
			seq_printf(file, "\t\t\tpedit src_mac (%#x)\n",
				   act->src_mac->fw_id);
			seq_printf(file, "\t\t\t\th_addr=%pM\n",
				   act->src_mac->h_addr);
		}
		if (act->dst_mac) {
			seq_printf(file, "\t\t\tpedit dst_mac (%#x)\n",
				   act->dst_mac->fw_id);
			seq_printf(file, "\t\t\t\th_addr=%pM\n",
				   act->dst_mac->h_addr);
		}
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
			char errbuf[16];

			seq_printf(file, "\t\t\tencap (%#x)\n", act->encap_md->fw_id);
			seq_printf(file, "\t\t\t\ttype = %s IPv%d\n",
				   efx_tc_encap_type_name(type, errbuf,
							  sizeof(errbuf)),
				   v6 ? 6 : 4);
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
	struct mae_mport_desc *mport;
	struct rhashtable_iter walk;
	struct efx_nic *efx = data;
	struct net_device *rep_dev;
	struct efx_rep *efv;
	int i;

	mutex_lock(&efx->tc->mutex);
	if (efx->tc->dflt.pf.fw_id != MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL)
		efx_tc_debugfs_dump_one_rule(file, &efx->tc->dflt.pf);
	if (efx->tc->dflt.wire.fw_id != MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL)
		efx_tc_debugfs_dump_one_rule(file, &efx->tc->dflt.wire);
	for (i = 0; i < EFX_TC_VF_MAX; i++) {
		rep_dev = efx_get_vf_rep(efx, i);
		if (IS_ERR_OR_NULL(rep_dev))
			continue;
		efv = netdev_priv(rep_dev);
		if (efv->dflt.fw_id != MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL)
			efx_tc_debugfs_dump_one_rule(file, &efv->dflt);
	}
	if (!efx->mae)
		goto out_unlock;
	/* Takes RCU read lock, so entries cannot be freed under us */
	rhashtable_walk_enter(&efx->mae->mports_ht, &walk);
	rhashtable_walk_start(&walk);
	while ((mport = rhashtable_walk_next(&walk)) != NULL) {
		efv = mport->efv;
		if (!efv)
			continue;
		if (efv->dflt.fw_id != MC_CMD_MAE_ACTION_RULE_INSERT_OUT_ACTION_RULE_ID_NULL)
			efx_tc_debugfs_dump_one_rule(file, &efv->dflt);
	}
	rhashtable_walk_stop(&walk);
	rhashtable_walk_exit(&walk);
out_unlock:
	mutex_unlock(&efx->tc->mutex);
	return 0;
}

static const char *efx_mae_counter_type_name(enum efx_tc_counter_type type)
{
	switch (type) {
	case EFX_TC_COUNTER_TYPE_AR:
		return "AR";
	case EFX_TC_COUNTER_TYPE_CT:
		return "CT";
	case EFX_TC_COUNTER_TYPE_OR:
		return "OR";
	default:
		return NULL;
	}
};

static void efx_tc_debugfs_dump_one_counter(struct seq_file *file,
					    struct efx_tc_counter *cnt)
{
	u64 packets, bytes, old_packets, old_bytes;
	enum efx_tc_counter_type type;
	const char *type_name;
	unsigned long age;
	u32 gen;

	/* get a consistent view */
	spin_lock_bh(&cnt->lock);
	packets = cnt->packets;
	bytes = cnt->bytes;
	old_packets = cnt->old_packets;
	old_bytes = cnt->old_bytes;
	age = jiffies - cnt->touched;
	gen = cnt->gen;
	type = cnt->type;
	spin_unlock_bh(&cnt->lock);

	type_name = efx_mae_counter_type_name(type);
	if (type_name)
		seq_printf(file, "%s %#x: ", type_name, cnt->fw_id);
	else
		seq_printf(file, "unk-%d %#x: ", type, cnt->fw_id);
	seq_printf(file, "%llu pkts %llu bytes (old %llu, %llu) gen %u age %lu\n",
		   packets, bytes, old_packets, old_bytes, gen, age);
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

static int efx_tc_debugfs_dump_mae_macs(struct seq_file *file, void *data)
{
	struct efx_tc_mac_pedit_action *ped;
	struct rhashtable_iter walk;
	struct efx_nic *efx = data;

	mutex_lock(&efx->tc->mutex);
	if (efx->tc->up) {
		rhashtable_walk_enter(&efx->tc->mac_ht, &walk);
		rhashtable_walk_start(&walk);
		while ((ped = rhashtable_walk_next(&walk)) != NULL) {
			if (IS_ERR(ped))
				continue;
			seq_printf(file, "%#x: %pM ref %u\n", ped->fw_id,
				   ped->h_addr, refcount_read(&ped->ref));
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
			if (rid->net_dev != efx->net_dev)
				seq_printf(file, "\tnetdev %s\n",
					   netdev_name(rid->net_dev));
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
	char errbuf[16];

	seq_printf(file, "%#lx (%s %#x)\n", rule->cookie,
		   rule->is_ar ? "AR" : "OR", rule->fw_id);

	efx_tc_debugfs_dump_match(file, &rule->match);

	seq_printf(file, "\tlhs_action\n");
	if (act->tun_type) {
		seq_printf(file, "\t\ttun_type = %s\n",
			   efx_tc_encap_type_name(act->tun_type, errbuf,
						  sizeof(errbuf)));
	}
	seq_printf(file, "\t\trecirc_id %#02x\n", act->rid ? act->rid->fw_id : 0);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	if (act->zone) {
		seq_printf(file, "\t\tct domain %#x\n", act->zone->domain);
		seq_printf(file, "\t\t\tzone %u\n", act->zone->zone);
		seq_printf(file, "\t\t\tvni_mode %u\n", act->zone->vni_mode);
	}
#endif
	if (act->count) {
		seq_printf(file, "\t\tcount %#x\n", act->count->cnt->fw_id);
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
		seq_printf(file, "\t\t\tact_idx=%d\n",
			   act->count_action_idx);
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_TC_ACTION_COOKIE)
		seq_printf(file, "\t\t\tcookie = %#lx\n",
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
	seq_printf(file, "%#lx\n", conn->cookie);
	seq_printf(file, "\tdomain = %#x\n", conn->domain);
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
#ifdef CONFIG_IPV6
	case htons(ETH_P_IPV6):
		seq_printf(file, "\tsrc = %pI6c:%u\n", &conn->src_ip6,
			   be16_to_cpu(conn->l4_sport));
		seq_printf(file, "\tdst = %pI6c:%u\n", &conn->dst_ip6,
			   be16_to_cpu(conn->l4_dport));
		break;
#endif
	default:
		break;
	}
	seq_printf(file, "\tmark = %#x (%u)\n", conn->mark, conn->mark);
	if (conn->cnt)
		seq_printf(file, "\tcount %#x\n", conn->cnt->fw_id);
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
	NAME(CT_PRIVATE_FLAGS),
	NAME(IS_FROM_NETWORK),
	NAME(HAS_OVLAN),
	NAME(HAS_IVLAN),
	NAME(ENC_HAS_OVLAN),
	NAME(ENC_HAS_IVLAN),
	NAME(ENC_IP_FRAG),
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
	NAME(TCP_SYN_FIN_RST),
	NAME(IP_FIRST_FRAG),
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
	char errbuf[16];

	if (!efx_mae_check_encap_type_supported(efx, encap))
		seq_printf(file, "%s\n", efx_tc_encap_type_name(encap, errbuf,
								sizeof(errbuf)));
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
#ifdef CONFIG_IPV6
		if (neigh->dst_ip) /* IPv4 */
#endif
			seq_printf(file, "%pI4: %svalid %pM ttl %hhu egdev %s ref %u\n",
				   &neigh->dst_ip, neigh->n_valid ? "" : "in",
				   neigh->ha, neigh->ttl, neigh->egdev->name,
				   refcount_read(&neigh->ref));
#ifdef CONFIG_IPV6
		else /* IPv6 */
			seq_printf(file, "%pI6c: %svalid %pM ttl %hhu egdev %s ref %u\n",
				   &neigh->dst_ip6, neigh->n_valid ? "" : "in",
				   neigh->ha, neigh->ttl, neigh->egdev->name,
				   refcount_read(&neigh->ref));
#endif
	}
	rhashtable_walk_stop(&walk);
	rhashtable_walk_exit(&walk);
	mutex_unlock(&efx->tc->mutex);
	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RHASHTABLE)
static int efx_tc_debugfs_dump_mports(struct seq_file *file, void *data)
{
	const struct mae_mport_desc *m;
	struct rhashtable_iter walk;
	struct efx_nic *efx = data;
	struct efx_mae *mae = efx->mae;

	if (!mae)
		return 0;

	rhashtable_walk_enter(&mae->mports_ht, &walk);
	rhashtable_walk_start(&walk);
	while ((m = rhashtable_walk_next(&walk)) != NULL) {
		char buf[120];
		size_t n;

		n = scnprintf(buf, sizeof(buf), "id %08x flags %02x cf %02x",
			      m->mport_id, m->flags, m->caller_flags);
		if (m->caller_flags & MAE_MPORT_DESC_FLAG__MASK)
			/* R = receive, T = transmit (deliver), X = delete,
			 * Z = zombie.
			 * Avoided using 'D' for T or X, as that's ambiguous
			 */
			n += scnprintf(buf + n, sizeof(buf) - n,
				       " (%c%c%c%c)",
				       (m->caller_flags & MAE_MPORT_DESC_FLAG_CAN_RECEIVE_ON) ? 'R' : 'r',
				       (m->caller_flags & MAE_MPORT_DESC_FLAG_CAN_DELIVER_TO) ? 'T' : 't',
				       (m->caller_flags & MAE_MPORT_DESC_FLAG_CAN_DELETE) ? 'X' : 'x',
				       (m->caller_flags & MAE_MPORT_DESC_FLAG_IS_ZOMBIE) ? 'Z' : 'z');
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
		if (m->efv)
			n += scnprintf(buf + n, sizeof(buf) - n,
				       " rep %s", netdev_name(m->efv->net_dev));
		/* Trailing
		 * '.' will be absent if line truncated to fit buf */
		snprintf(buf + n, sizeof(buf) - n, ".");
		seq_printf(file, "%s\n", buf);

	}

	rhashtable_walk_stop(&walk);
	rhashtable_walk_exit(&walk);
	return 0;
}
#endif

static const char *efx_mae_field_id_names[] = {
#define NAME(_name)	[TABLE_FIELD_ID_##_name] = #_name
	NAME(UNUSED),
	NAME(SRC_MPORT),
	NAME(DST_MPORT),
	NAME(SRC_MGROUP_ID),
	NAME(NETWORK_PORT_ID),
	NAME(IS_FROM_NETWORK),
	NAME(CH_VC),
	NAME(CH_VC_LOW),
	NAME(USER_MARK),
	NAME(USER_FLAG),
	NAME(COUNTER_ID),
	NAME(DISCRIM),
	NAME(DST_MAC),
	NAME(SRC_MAC),
	NAME(OVLAN_TPID_COMPRESSED),
	NAME(OVLAN),
	NAME(OVLAN_VID),
	NAME(IVLAN_TPID_COMPRESSED),
	NAME(IVLAN),
	NAME(IVLAN_VID),
	NAME(ETHER_TYPE),
	NAME(SRC_IP),
	NAME(DST_IP),
	NAME(IP_TOS),
	NAME(IP_PROTO),
	NAME(SRC_PORT),
	NAME(DST_PORT),
	NAME(TCP_FLAGS),
	NAME(VNI),
	NAME(HAS_ENCAP),
	NAME(HAS_ENC_OVLAN),
	NAME(HAS_ENC_IVLAN),
	NAME(HAS_ENC_IP),
	NAME(HAS_ENC_IP4),
	NAME(HAS_ENC_UDP),
	NAME(HAS_OVLAN),
	NAME(HAS_IVLAN),
	NAME(HAS_IP),
	NAME(HAS_L4),
	NAME(IP_FRAG),
	NAME(IP_FIRST_FRAG),
	NAME(IP_TTL_LE_ONE),
	NAME(TCP_INTERESTING_FLAGS),
	NAME(RDP_PL_CHAN),
	NAME(RDP_C_PL_EN),
	NAME(RDP_C_PL),
	NAME(RDP_D_PL_EN),
	NAME(RDP_D_PL),
	NAME(RDP_OUT_HOST_CHAN_EN),
	NAME(RDP_OUT_HOST_CHAN),
	NAME(RECIRC_ID),
	NAME(DOMAIN),
	NAME(CT_VNI_MODE),
	NAME(CT_TCP_FLAGS_INHIBIT),
	NAME(DO_CT_IP4_TCP),
	NAME(DO_CT_IP4_UDP),
	NAME(DO_CT_IP6_TCP),
	NAME(DO_CT_IP6_UDP),
	NAME(OUTER_RULE_ID),
	NAME(ENCAP_TYPE),
	NAME(ENCAP_TUNNEL_ID),
	NAME(CT_ENTRY_ID),
	NAME(NAT_PORT),
	NAME(NAT_IP),
	NAME(NAT_DIR),
	NAME(CT_MARK),
	NAME(CT_PRIV_FLAGS),
	NAME(CT_HIT),
	NAME(SUPPRESS_SELF_DELIVERY),
	NAME(DO_DECAP),
	NAME(DECAP_DSCP_COPY),
	NAME(DECAP_ECN_RFC6040),
	NAME(DO_REPLACE_DSCP),
	NAME(DO_REPLACE_ECN),
	NAME(DO_DECR_IP_TTL),
	NAME(DO_SRC_MAC),
	NAME(DO_DST_MAC),
	NAME(DO_VLAN_POP),
	NAME(DO_VLAN_PUSH),
	NAME(DO_COUNT),
	NAME(DO_ENCAP),
	NAME(ENCAP_DSCP_COPY),
	NAME(ENCAP_ECN_COPY),
	NAME(DO_DELIVER),
	NAME(DO_FLAG),
	NAME(DO_MARK),
	NAME(DO_SET_NET_CHAN),
	NAME(DO_SET_SRC_MPORT),
	NAME(ENCAP_HDR_ID),
	NAME(DSCP_VALUE),
	NAME(ECN_CONTROL),
	NAME(SRC_MAC_ID),
	NAME(DST_MAC_ID),
	NAME(REPORTED_SRC_MPORT_OR_NET_CHAN),
	NAME(CHUNK64),
	NAME(CHUNK32),
	NAME(CHUNK16),
	NAME(CHUNK8),
	NAME(CHUNK4),
	NAME(CHUNK2),
	NAME(HDR_LEN_W),
	NAME(ENC_LACP_HASH_L23),
	NAME(ENC_LACP_HASH_L4),
	NAME(USE_ENC_LACP_HASHES),
	NAME(DO_CT),
	NAME(DO_NAT),
	NAME(DO_RECIRC),
	NAME(NEXT_ACTION_SET_PAYLOAD),
	NAME(NEXT_ACTION_SET_ROW),
	NAME(MC_ACTION_SET_PAYLOAD),
	NAME(MC_ACTION_SET_ROW),
	NAME(LACP_INC_L4),
	NAME(LACP_PLUGIN),
	NAME(BAL_TBL_BASE_DIV64),
	NAME(BAL_TBL_LEN_ID),
	NAME(UDP_PORT),
	NAME(RSS_ON_OUTER),
	NAME(STEER_ON_OUTER),
	NAME(DST_QID),
	NAME(DROP),
	NAME(VLAN_STRIP),
	NAME(MARK_OVERRIDE),
	NAME(FLAG_OVERRIDE),
	NAME(RSS_CTX_ID),
	NAME(RSS_EN),
	NAME(KEY),
	NAME(TCP_V4_KEY_MODE),
	NAME(TCP_V6_KEY_MODE),
	NAME(UDP_V4_KEY_MODE),
	NAME(UDP_V6_KEY_MODE),
	NAME(OTHER_V4_KEY_MODE),
	NAME(OTHER_V6_KEY_MODE),
	NAME(SPREAD_MODE),
	NAME(INDIR_TBL_BASE),
	NAME(INDIR_TBL_LEN_ID),
	NAME(INDIR_OFFSET),
#undef NAME
};

static const char *efx_mae_table_masking_names[] = {
#define NAME(_name)	[TABLE_FIELD_DESCR_MASK_##_name] = #_name
	NAME(NEVER),
	NAME(EXACT),
	NAME(TERNARY),
	NAME(WHOLE_FIELD),
	NAME(LPM),
#undef NAME
};

static void efx_tc_debugfs_dump_mae_table_field(struct seq_file *file,
						const struct efx_tc_table_field_fmt *field,
						bool resp)
{
	seq_printf(file, "\t%s ", resp ? "resp" : "key");
	if (field->field_id < ARRAY_SIZE(efx_mae_field_id_names) &&
	    efx_mae_field_id_names[field->field_id])
		seq_printf(file, "%s: ", efx_mae_field_id_names[field->field_id]);
	else
		seq_printf(file, "unknown-%#x: ", field->field_id);
	seq_printf(file, "%u @ %u; ", field->width, field->lbn);
	if (field->masking < ARRAY_SIZE(efx_mae_table_masking_names) &&
	    efx_mae_table_masking_names[field->masking])
		seq_printf(file, "mask %s ",
			   efx_mae_table_masking_names[field->masking]);
	else
		seq_printf(file, "mask unknown-%#x ", field->masking);
	seq_printf(file, "scheme %u\n", field->scheme);
}

static const char *efx_mae_table_type_names[] = {
#define NAME(_name)	[MC_CMD_TABLE_DESCRIPTOR_OUT_TYPE_##_name] = #_name
	NAME(DIRECT),
	NAME(BCAM),
	NAME(TCAM),
	NAME(STCAM),
#undef NAME
};

static void efx_tc_debugfs_dump_mae_table(struct seq_file *file,
					  const char *name,
					  const struct efx_tc_table_desc *meta,
					  bool hooked)
{
	unsigned int i;

	seq_printf(file, "%s: ", name);
	if (meta->type < ARRAY_SIZE(efx_mae_table_type_names) &&
	    efx_mae_table_type_names[meta->type])
		seq_printf(file, "type %s ",
			   efx_mae_table_type_names[meta->type]);
	else
		seq_printf(file, "type unknown-%#x ", meta->type);
	seq_printf(file, "kw %u rw %u; %u prios; flags %#x scheme %#x\n",
		   meta->key_width, meta->resp_width, meta->n_prios,
		   meta->flags, meta->scheme);
	for (i = 0; i < meta->n_keys; i++)
		efx_tc_debugfs_dump_mae_table_field(file, meta->keys + i, false);
	for (i = 0; i < meta->n_resps; i++)
		efx_tc_debugfs_dump_mae_table_field(file, meta->resps + i, true);
	if (hooked)
		seq_printf(file, "\thooked\n");
}

static int efx_tc_debugfs_dump_mae_tables(struct seq_file *file, void *data)
{
	struct efx_nic *efx = data;

	efx_tc_debugfs_dump_mae_table(file, "ct", &efx->tc->meta_ct.desc,
				      efx->tc->meta_ct.hooked);
	return 0;
}

struct efx_debugfs_parameter efx_tc_debugfs[] = {
	_EFX_RAW_PARAMETER(mae_rules, efx_tc_debugfs_dump_rules),
	_EFX_RAW_PARAMETER(lhs_rules, efx_tc_debugfs_dump_lhs_rules),
	_EFX_RAW_PARAMETER(mae_default_rules, efx_tc_debugfs_dump_default_rules),
	_EFX_RAW_PARAMETER(mae_counters, efx_tc_debugfs_dump_mae_counters),
	_EFX_RAW_PARAMETER(mae_pedit_macs, efx_tc_debugfs_dump_mae_macs),
	_EFX_RAW_PARAMETER(mae_recirc_ids, efx_tc_debugfs_dump_recirc_ids),
	_EFX_RAW_PARAMETER(mae_action_rule_caps, efx_tc_debugfs_dump_mae_ar_caps),
	_EFX_RAW_PARAMETER(mae_outer_rule_caps, efx_tc_debugfs_dump_mae_or_caps),
	_EFX_RAW_PARAMETER(mae_tunnel_caps, efx_tc_debugfs_dump_mae_tunnel_caps),
	_EFX_RAW_PARAMETER(mae_prios, efx_tc_debugfs_dump_action_prios),
	_EFX_RAW_PARAMETER(mae_neighs, efx_tc_debugfs_dump_mae_neighs),
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	_EFX_RAW_PARAMETER(tracked_conns, efx_tc_debugfs_dump_cts),
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RHASHTABLE)
	_EFX_RAW_PARAMETER(mae_mport_map, efx_tc_debugfs_dump_mports),
#endif
	_EFX_RAW_PARAMETER(mae_tables, efx_tc_debugfs_dump_mae_tables),
	{NULL}
};
#endif /* EFX_TC_OFFLOAD */
#endif /* CONFIG_SFC_DEBUGFS */
