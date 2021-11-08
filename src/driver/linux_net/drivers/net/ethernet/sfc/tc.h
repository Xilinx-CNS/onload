/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"

#ifndef EFX_TC_H
#define EFX_TC_H

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
#include <linux/mutex.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_tunnel_key.h>
#include <net/tc_act/tc_pedit.h>
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
#if defined(EFX_USE_KCOMPAT)
/* nf_flow_table.h should include this, but on deb10 it's missing */
#include <linux/netfilter.h>
#endif
#include <net/netfilter/nf_flow_table.h>
#endif
#include <linux/idr.h>
#include "mcdi_pcol.h"

enum efx_tc_counter_type {
	EFX_TC_COUNTER_TYPE_AR = MAE_COUNTER_TYPE_AR,
	EFX_TC_COUNTER_TYPE_CT = MAE_COUNTER_TYPE_CT,
	EFX_TC_COUNTER_TYPE_OR = MAE_COUNTER_TYPE_OR,
	EFX_TC_COUNTER_TYPE_MAX
};

struct efx_tc_counter {
	u32 fw_id; /* index in firmware counter table */
	enum efx_tc_counter_type type;
	struct rhash_head linkage; /* efx->tc->counter_ht */
	spinlock_t lock; /* Serialises updates to counter values */
	u32 gen; /* Generation count at which this counter is current */
	u64 packets, bytes;
	u64 old_packets, old_bytes; /* Values last time passed to userspace */
	/* jiffies of the last time we saw packets increase */
	unsigned long touched;
	struct work_struct work; /* For notifying encap actions */
	/* owners of corresponding count actions */
	struct list_head users;
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

/* MAC address edits are indirected through a table in the hardware */
struct efx_tc_mac_pedit_action {
	u8 h_addr[ETH_ALEN];
	struct rhash_head linkage;
	refcount_t ref;
	u32 fw_id; /* index of this entry in firmware MAC address table */
};

struct efx_tc_counter_index {
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_ACTION_COOKIE)
	/* cookie is rule, not action, cookie */
#endif
	unsigned long cookie;
	struct rhash_head linkage; /* efx->tc->counter_id_ht */
	refcount_t ref;
	struct efx_tc_counter *cnt;
};

/* In principle up to 255 VFs are possible; the last one is #254 */
#define EFX_TC_VF_MAX           (255)
/* TODO correct this after finding max */
#define EFX_TC_REMOTE_MAX       (16) /* including for VNIC_TYPE_PLUGIN */
/* Driver-internal numbering scheme for vports.  See efx_tc_flower_lookup_dev() */
#define EFX_VPORT_PF		0
#define EFX_VPORT_VF_OFFSET	1
#define EFX_VPORT_REMOTE_OFFSET	(EFX_VPORT_VF_OFFSET + EFX_TC_VF_MAX)

struct efx_tc_action_set {
	u16 vlan_push:2;
	u16 vlan_pop:2;
	u16 decap:1;
	u16 do_nat:1;
	u16 deliver:1;
	u16 do_ttl_dec:1;
	__be16 vlan_tci[2]; /* TCIs for vlan_push */
	__be16 vlan_proto[2]; /* Ethertypes for vlan_push */
	struct efx_tc_counter_index *count;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	int count_action_idx;
#endif
	u32 dest_mport;
	struct efx_tc_encap_action *encap_md; /* entry in tc_encap_ht table */
	struct efx_tc_mac_pedit_action *src_mac; /* entry in tc_mac_ht table */
	struct efx_tc_mac_pedit_action *dst_mac; /* entry in tc_mac_ht table */
	struct list_head encap_user; /* entry on encap_md->users list */
	struct list_head count_user; /* entry on counter->users list, if encap */
	struct efx_tc_action_set_list *user; /* Only populated if encap_md */
	u32 fw_id; /* index of this entry in firmware actions table */
	struct list_head list;
};

struct efx_tc_match_fields {
	/* L1, I guess? */
	u32 ingress_port;
	/* L2 (inner when encap) */
	__be16 eth_proto;
	__be16 vlan_tci[2], vlan_proto[2];
	u8 eth_saddr[ETH_ALEN], eth_daddr[ETH_ALEN];
	/* L3 (when IP) */
	u8 ip_proto, ip_tos, ip_ttl;
	__be32 src_ip, dst_ip;
#ifdef CONFIG_IPV6
	struct in6_addr src_ip6, dst_ip6;
#endif
	bool ip_frag, ip_firstfrag;
	/* L4 */
	__be16 l4_sport, l4_dport; /* Ports (UDP, TCP) */
	__be16 tcp_flags;
	/* Encap.  The following are *outer* fields.  Note that there are no
	 * outer eth (L2) fields; this is because TC doesn't have them.
	 */
	__be32 enc_src_ip, enc_dst_ip;
	struct in6_addr enc_src_ip6, enc_dst_ip6;
	u8 enc_ip_tos, enc_ip_ttl;
	__be16 enc_sport, enc_dport;
	__be32 enc_keyid; /* e.g. VNI, VSID */
	/* L... I don't even know any more.  Conntrack. */
	u16 ct_state_trk:1,
	    ct_state_est:1,
	    ct_state_rel:1,
	    ct_state_new:1; /* only these bits are defined in TC uapi so far */
	u32 ct_mark; /* For now we ignore ct_label, and don't indirect */
	u16 ct_zone; /* also referred to as CT domain */
	u8 recirc_id; /* mapped from (u32) TC chain_index to smaller space */
};

static inline bool efx_tc_match_is_encap(const struct efx_tc_match_fields *mask)
{
	return mask->enc_src_ip || mask->enc_dst_ip ||
	       !ipv6_addr_any(&mask->enc_src_ip6) ||
	       !ipv6_addr_any(&mask->enc_dst_ip6) || mask->enc_ip_tos ||
	       mask->enc_ip_ttl || mask->enc_sport || mask->enc_dport;
}

struct efx_tc_encap_match {
	__be32 src_ip, dst_ip;
	struct in6_addr src_ip6, dst_ip6;
	__be16 udp_dport;
	u16 tun_type; /* enum efx_encap_type */
	struct rhash_head linkage;
	refcount_t ref;
	u32 fw_id; /* index of this entry in firmware encap match table */
};

struct efx_tc_recirc_id {
	u32 chain_index;
	struct net_device *net_dev;
	struct rhash_head linkage;
	refcount_t ref;
	u8 fw_id; /* index allocated for use in the MAE */
};

struct efx_tc_match {
	struct efx_tc_match_fields value;
	struct efx_tc_match_fields mask;
	struct efx_tc_encap_match *encap;
	struct efx_tc_recirc_id *rid;
};

struct efx_tc_action_set_list {
	struct list_head list;
	u32 fw_id;
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
struct efx_tc_ct_zone {
	u16 zone;
	u8 vni_mode; /* MAE_CT_VNI_MODE enum */
	struct rhash_head linkage;
	refcount_t ref;
	struct nf_flowtable *nf_ft;
	struct efx_nic *efx;
	u16 domain; /* ID allocated for hardware use */
	struct rw_semaphore rwsem; /* protects cts list */
	struct list_head cts; /* list of efx_tc_ct_entry in this domain */
};
#endif

struct efx_tc_lhs_action {
	u16 tun_type; /* enum efx_encap_type */
	struct efx_tc_recirc_id *rid;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	struct efx_tc_ct_zone *zone;
#endif
	struct efx_tc_counter_index *count;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_TC_FLOW_OFFLOAD)
	int count_action_idx;
#endif
};

struct efx_tc_flow_rule {
	unsigned long cookie;
	struct rhash_head linkage;
	struct efx_tc_match match;
	struct efx_tc_action_set_list acts;
	struct efx_tc_action_set_list *fallback; /* what to use when unready? */
	u32 fw_id;
};

struct efx_tc_lhs_rule {
	unsigned long cookie;
	struct efx_tc_match match;
	struct efx_tc_lhs_action lhs_act;
	struct rhash_head linkage;
	u32 fw_id;
};

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
struct efx_tc_ct_entry {
	unsigned long cookie;
	struct rhash_head linkage;
	__be16 eth_proto;
	u8 ip_proto;
	bool dnat;
	__be32 src_ip, dst_ip, nat_ip;
	struct in6_addr src_ip6, dst_ip6;
	__be16 l4_sport, l4_dport, l4_natport; /* Ports (UDP, TCP) */
	u16 domain; /* we'd rather have struct efx_tc_ct_zone *zone; but that's unsafe currently */
	u32 mark;
	struct efx_tc_counter *cnt;
	struct list_head list; /* entry on zone->cts */
};
#endif

enum efx_tc_rule_prios {
	EFX_TC_PRIO_TC, /* Rule inserted by TC */
	EFX_TC_PRIO_DFLT, /* Default switch rule; one of efx_tc_default_rules */
	EFX_TC_PRIO__NUM
};

struct efx_tc_table_field_fmt {
	u16 field_id;
	u16 lbn;
	u16 width;
	u8 masking;
	u8 scheme;
};

struct efx_tc_table_desc {
	u16 type;
	u16 key_width;
	u16 resp_width;
	u16 n_keys;
	u16 n_resps;
	u16 n_prios;
	u8 flags;
	u8 scheme;
	struct efx_tc_table_field_fmt *keys;
	struct efx_tc_table_field_fmt *resps;
};

struct efx_tc_table_ct { /* TABLE_ID_CONNTRACK_TABLE */
	struct efx_tc_table_desc desc;
	bool hooked;
	struct { /* indices of named fields within @desc.keys */
		u8 eth_proto_idx;
		u8 ip_proto_idx;
		u8 src_ip_idx; /* either v4 or v6 */
		u8 dst_ip_idx;
		u8 l4_sport_idx;
		u8 l4_dport_idx;
		u8 zone_idx; /* for TABLE_FIELD_ID_DOMAIN */
	} keys;
	struct { /* indices of named fields within @desc.resps */
		u8 dnat_idx;
		u8 nat_ip_idx;
		u8 l4_natport_idx;
		u8 mark_idx;
		u8 counter_id_idx;
	} resps;
};

/**
 * struct efx_tc_state - control plane data for TC offload
 *
 * @caps: MAE capabilities reported by MCDI
 * @n_mports: length of @mports array
 * @mports: m-port descriptions from MC_CMD_MAE_MPORT_ENUMERATE
 * @block_list: List of &struct efx_tc_block_binding
 * @mutex: Used to serialise operations on TC hashtables
 * @counter_ht: Hashtable of TC counters (FW IDs and counter values)
 * @counter_id_ht: Hashtable mapping TC counter cookies to counters
 * @encap_ht: Hashtable of TC encap actions
 * @mac_ht: Hashtable of MAC address entries (for pedits)
 * @match_action_ht: Hashtable of TC match-action rules
 * @lhs_rule_ht: Hashtable of TC left-hand (act ct & goto chain) rules
 * @ct_zone_ht: Hashtable of TC conntrack flowtable bindings
 * @ct_ht: Hashtable of TC conntrack flow entries
 * @neigh_ht: Hashtable of neighbour watches (&struct efx_neigh_binder)
 * @recirc_ht: Hashtable of recirculation ID mappings (&struct efx_tc_recirc_id)
 * @recirc_ida: Recirculation ID allocator
 * @domain_ida: CT domain (zone + vni_mode) ID allocator
 * @meta_ct: MAE table layout for conntrack table
 * @reps_mport_id: MAE port allocated for representor RX
 * @reps_filter_uc: VNIC filter for representor unicast RX (promisc)
 * @reps_filter_mc: VNIC filter for representor multicast RX (allmulti)
 * @reps_mport_vport_id: vport user_id for representor RX filters
 * @flush_counters: counters have been stopped, waiting for drain
 * @flush_gen: final generation count per type array as reported by
 *             MC_CMD_MAE_COUNTERS_STREAM_STOP
 * @seen_gen: most recent generation count per type as seen by efx_tc_rx()
 * @flush_wq: wait queue used by efx_mae_stop_counters() to wait for
 *	MAE counters RXQ to finish draining
 * @dflt: Match-action rules for default switching; at priority
 *	%EFX_TC_PRIO_DFLT.  Named by *ingress* port
 * @dflt.pf: rule for traffic ingressing from PF (egresses to wire)
 * @dflt.wire: rule for traffic ingressing from wire (egresses to PF)
 * @facts: Fallback action-set-lists for unready rules.  Named by *egress* port
 * @facts.pf: action-set-list for unready rules on PF netdev, hence applying to
 *	traffic from wire, and egressing to PF
 * @facts.reps: action-set-list for unready rules on representors, hence
 *	applying to traffic from representees, and egressing to the reps mport
 * @up: have TC datastructures been set up?
 */
struct efx_tc_state {
	struct mae_caps *caps;
	unsigned int n_mports;
	struct mae_mport_desc *mports;
	struct list_head block_list;
	struct mutex mutex;
	struct rhashtable counter_ht;
	struct rhashtable counter_id_ht;
	struct rhashtable encap_ht;
	struct rhashtable mac_ht;
	struct rhashtable encap_match_ht;
	struct rhashtable match_action_ht;
	struct rhashtable lhs_rule_ht;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	struct rhashtable ct_zone_ht;
	struct rhashtable ct_ht;
#endif
	struct rhashtable neigh_ht;
	struct rhashtable recirc_ht;
	struct ida recirc_ida;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	struct ida domain_ida;
#endif
	struct efx_tc_table_ct meta_ct;
	u32 reps_mport_id;
	u32 reps_filter_uc, reps_filter_mc;
	u16 reps_mport_vport_id;
	bool flush_counters;
	u32 flush_gen[EFX_TC_COUNTER_TYPE_MAX];
	u32 seen_gen[EFX_TC_COUNTER_TYPE_MAX];
	wait_queue_head_t flush_wq;
	struct {
		struct efx_tc_flow_rule pf;
		struct efx_tc_flow_rule wire;
	} dflt;
	struct {
		struct efx_tc_action_set_list pf;
		struct efx_tc_action_set_list reps;
	} facts;
	bool up;
};

struct efx_rep;

int efx_tc_configure_default_rule_rep(struct efx_rep *efv);
void efx_tc_deconfigure_default_rule(struct efx_nic *efx,
				     struct efx_tc_flow_rule *rule);
int efx_tc_flower(struct efx_nic *efx, struct net_device *net_dev,
		  struct flow_cls_offload *tc, struct efx_rep *efv);
int efx_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv);
int efx_tc_setup_block(struct net_device *net_dev, struct efx_nic *efx,
		       struct flow_block_offload *tcb, struct efx_rep *efv);
int efx_setup_tc(struct net_device *net_dev, enum tc_setup_type type,
		 void *type_data);

#else /* EFX_TC_OFFLOAD */

struct efx_tc_action_set {
	u16 vlan_push:2;
	u16 vlan_pop:2;
	u16 decap:1;
	u16 do_nat:1;
	u16 deliver:1;
	u16 do_ttl_dec:1;
	__be16 vlan_tci[2]; /* TCIs for vlan_push */
	__be16 vlan_proto[2]; /* Ethertypes for vlan_push */
	struct efx_tc_counter_index *count;
	u32 dest_mport;
	u32 fw_id; /* index of this entry in firmware actions table */
	struct list_head list;
};

struct efx_tc_match_fields {
	/* L1, I guess? */
	u32 ingress_port;
};

struct efx_tc_encap_match {};
struct efx_tc_encap_action {};

struct efx_tc_match {
	struct efx_tc_match_fields value;
	struct efx_tc_match_fields mask;
	struct efx_tc_encap_match *encap;
};

struct efx_tc_action_set_list {
	struct list_head list;
	u32 fw_id;
};

enum efx_tc_default_rules { /* named by ingress port */
	EFX_TC_DFLT_PF,
	EFX_TC_DFLT_WIRE,
	/* No rules for VFs and vfreps; if we don't have TC offload then we
	 * just don't create them.
	 */
	EFX_TC_DFLT__MAX
};

struct efx_tc_flow_rule {
	struct efx_tc_match match;
	struct efx_tc_action_set_list acts;
	u32 fw_id;
};

enum efx_tc_rule_prios {
	EFX_TC_PRIO_DFLT, /* Default switch rule; one of efx_tc_default_rules */
	EFX_TC_PRIO__NUM
};

struct efx_tc_state {
	struct mae_caps *caps;
	struct {
		struct efx_tc_flow_rule pf;
		struct efx_tc_flow_rule wire;
	} dflt;
};

#endif /* EFX_TC_OFFLOAD */

int efx_tc_insert_rep_filters(struct efx_nic *efx);
void efx_tc_remove_rep_filters(struct efx_nic *efx);
int efx_init_tc(struct efx_nic *efx);
void efx_fini_tc(struct efx_nic *efx);

int efx_init_struct_tc(struct efx_nic *efx);
void efx_fini_struct_tc(struct efx_nic *efx);

int efx_tc_netdev_event(struct efx_nic *efx, unsigned long event,
			struct net_device *net_dev);
int efx_tc_netevent_event(struct efx_nic *efx, unsigned long event,
			  void *ptr);

#endif /* EFX_TC_H */
