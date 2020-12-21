/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "mae.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "mcdi_pcol_mae.h"
#include "ef100_rep.h"

int efx_mae_allocate_mport(struct efx_nic *efx, u32 *id, u32 *label)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_MPORT_ALLOC_ALIAS_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_MPORT_ALLOC_ALIAS_IN_LEN);
	size_t outlen;
	int rc;

	if (WARN_ON_ONCE(!id))
		return -EINVAL;
	if (WARN_ON_ONCE(!label))
		return -EINVAL;

	MCDI_SET_DWORD(inbuf, MAE_MPORT_ALLOC_ALIAS_IN_TYPE,
		       MC_CMD_MAE_MPORT_ALLOC_ALIAS_IN_MPORT_TYPE_ALIAS);
	MCDI_SET_DWORD(inbuf, MAE_MPORT_ALLOC_ALIAS_IN_DELIVER_MPORT,
		       MAE_MPORT_SELECTOR_ASSIGNED);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_MPORT_ALLOC, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	*id = MCDI_DWORD(outbuf, MAE_MPORT_ALLOC_ALIAS_OUT_MPORT_ID);
	*label = MCDI_DWORD(outbuf, MAE_MPORT_ALLOC_ALIAS_OUT_LABEL);
	return 0;
}

int efx_mae_free_mport(struct efx_nic *efx, u32 id)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_MPORT_FREE_IN_LEN);

	BUILD_BUG_ON(MC_CMD_MAE_MPORT_FREE_OUT_LEN);
	MCDI_SET_DWORD(inbuf, MAE_MPORT_FREE_IN_MPORT_ID, id);
	return efx_mcdi_rpc(efx, MC_CMD_MAE_MPORT_FREE, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

void efx_mae_mport_wire(struct efx_nic *efx, u32 *out)
{
	efx_dword_t mport;

	EFX_POPULATE_DWORD_2(mport,
			     MAE_MPORT_SELECTOR_TYPE, MAE_MPORT_SELECTOR_TYPE_PPORT,
			     MAE_MPORT_SELECTOR_PPORT_ID, efx->port_num);
	*out = EFX_DWORD_VAL(mport);
}

void efx_mae_mport_uplink(struct efx_nic *efx __always_unused, u32 *out)
{
	efx_dword_t mport;

	EFX_POPULATE_DWORD_3(mport,
			     MAE_MPORT_SELECTOR_TYPE, MAE_MPORT_SELECTOR_TYPE_FUNC,
			     MAE_MPORT_SELECTOR_FUNC_PF_ID, MAE_MPORT_SELECTOR_FUNC_PF_ID_CALLER,
			     MAE_MPORT_SELECTOR_FUNC_VF_ID, MAE_MPORT_SELECTOR_FUNC_VF_ID_NULL);
	*out = EFX_DWORD_VAL(mport);
}

void efx_mae_mport_vf(struct efx_nic *efx __always_unused, u32 vf_id, u32 *out)
{
	efx_dword_t mport;

	EFX_POPULATE_DWORD_3(mport,
			     MAE_MPORT_SELECTOR_TYPE, MAE_MPORT_SELECTOR_TYPE_FUNC,
			     MAE_MPORT_SELECTOR_FUNC_PF_ID, MAE_MPORT_SELECTOR_FUNC_PF_ID_CALLER,
			     MAE_MPORT_SELECTOR_FUNC_VF_ID, vf_id);
	*out = EFX_DWORD_VAL(mport);
}

/* Constructs an mport selector from an mport ID, because they're not the same */
void efx_mae_mport_mport(struct efx_nic *efx __always_unused, u32 mport_id, u32 *out)
{
	efx_dword_t mport;

	EFX_POPULATE_DWORD_2(mport,
			     MAE_MPORT_SELECTOR_TYPE, MAE_MPORT_SELECTOR_TYPE_MPORT_ID,
			     MAE_MPORT_SELECTOR_MPORT_ID, mport_id);
	*out = EFX_DWORD_VAL(mport);
}

/* id is really only 24 bits wide */
int efx_mae_lookup_mport(struct efx_nic *efx, u32 selector, u32 *id)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_MPORT_LOOKUP_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_MPORT_LOOKUP_IN_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAE_MPORT_LOOKUP_IN_MPORT_SELECTOR, selector);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_MPORT_LOOKUP, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	*id = MCDI_DWORD(outbuf, MAE_MPORT_LOOKUP_OUT_MPORT_ID);
	return 0;
}

int efx_mae_start_counters(struct efx_nic *efx, struct efx_channel *channel)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_COUNTERS_STREAM_START_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_COUNTERS_STREAM_START_IN_LEN);
	u32 out_flags;
	size_t outlen;
	int rc;

	MCDI_SET_WORD(inbuf, MAE_COUNTERS_STREAM_START_IN_QID, channel->channel);
	MCDI_SET_WORD(inbuf, MAE_COUNTERS_STREAM_START_IN_PACKET_SIZE,
		      efx->net_dev->mtu);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_COUNTERS_STREAM_START,
			  inbuf, sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	out_flags = MCDI_DWORD(outbuf, MAE_COUNTERS_STREAM_START_OUT_FLAGS);
	if (out_flags & BIT(MC_CMD_MAE_COUNTERS_STREAM_START_OUT_USES_CREDITS_OFST)) {
		netif_dbg(efx, drv, efx->net_dev,
			  "MAE counter stream uses credits\n");
		channel->rx_queue.grant_credits = true;
		out_flags &= ~BIT(MC_CMD_MAE_COUNTERS_STREAM_START_OUT_USES_CREDITS_OFST);
	}
	if (out_flags) {
		netif_err(efx, drv, efx->net_dev,
			  "MAE counter stream start: unrecognised flags %x\n",
			  out_flags);
		goto out_stop;
	}
	return 0;
out_stop:
	efx_mae_stop_counters(efx, channel);
	return -EOPNOTSUPP;
}

int efx_mae_stop_counters(struct efx_nic *efx, struct efx_channel *channel)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_COUNTERS_STREAM_STOP_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_COUNTERS_STREAM_STOP_OUT_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_WORD(inbuf, MAE_COUNTERS_STREAM_STOP_IN_QID, channel->channel);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_COUNTERS_STREAM_STOP,
			  inbuf, sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	/* final_generation_count = MCDI_DWORD(outbuf, MAE_COUNTERS_STREAM_STOP_OUT_GENERATION_COUNT); */
	return rc;
}

void efx_mae_counters_grant_credits(struct work_struct *work)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_COUNTERS_STREAM_GIVE_CREDITS_IN_LEN);
	struct efx_rx_queue *rx_queue = container_of(work, struct efx_rx_queue,
						     grant_work);
	struct efx_nic *efx = rx_queue->efx;
	unsigned int credits;

	BUILD_BUG_ON(MC_CMD_MAE_COUNTERS_STREAM_GIVE_CREDITS_OUT_LEN);
	credits = READ_ONCE(rx_queue->notified_count) - rx_queue->granted_count;
	MCDI_SET_DWORD(inbuf, MAE_COUNTERS_STREAM_GIVE_CREDITS_IN_NUM_CREDITS,
		       credits);
	if (!efx_mcdi_rpc(efx, MC_CMD_MAE_COUNTERS_STREAM_GIVE_CREDITS,
			  inbuf, sizeof(inbuf), NULL, 0, NULL))
		rx_queue->granted_count += credits;
}

static int efx_mae_get_basic_caps(struct efx_nic *efx, struct mae_caps *caps)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_GET_CAPS_OUT_LEN);
	size_t outlen;
	int rc;

	BUILD_BUG_ON(MC_CMD_MAE_GET_CAPS_IN_LEN);

	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_GET_CAPS, NULL, 0, outbuf,
			  sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	caps->match_field_count = MCDI_DWORD(outbuf, MAE_GET_CAPS_OUT_MATCH_FIELD_COUNT);
	caps->encap_types = MCDI_DWORD(outbuf, MAE_GET_CAPS_OUT_ENCAP_TYPES_SUPPORTED);
	caps->action_prios = MCDI_DWORD(outbuf, MAE_GET_CAPS_OUT_ACTION_PRIOS);
	return 0;
}

static int efx_mae_get_rule_fields(struct efx_nic *efx, u32 cmd,
				   u8 *field_support)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_GET_AR_CAPS_OUT_LEN(MAE_NUM_FIELDS));
	MCDI_DECLARE_STRUCT_PTR(caps);
	unsigned int count;
	size_t outlen;
	int rc, i;

	BUILD_BUG_ON(MC_CMD_MAE_GET_AR_CAPS_OUT_LEN(MAE_NUM_FIELDS) <
		     MC_CMD_MAE_GET_OR_CAPS_OUT_LEN(MAE_NUM_FIELDS));
	BUILD_BUG_ON(MC_CMD_MAE_GET_AR_CAPS_IN_LEN);
	BUILD_BUG_ON(MC_CMD_MAE_GET_OR_CAPS_IN_LEN);

	rc = efx_mcdi_rpc(efx, cmd, NULL, 0, outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	BUILD_BUG_ON(MC_CMD_MAE_GET_AR_CAPS_OUT_COUNT_OFST !=
		     MC_CMD_MAE_GET_OR_CAPS_OUT_COUNT_OFST);
	count = MCDI_DWORD(outbuf, MAE_GET_AR_CAPS_OUT_COUNT);
	memset(field_support, MAE_FIELD_UNSUPPORTED, MAE_NUM_FIELDS);
	BUILD_BUG_ON(MC_CMD_MAE_GET_AR_CAPS_OUT_FIELD_FLAGS_OFST !=
		     MC_CMD_MAE_GET_OR_CAPS_OUT_FIELD_FLAGS_OFST);
	caps = _MCDI_DWORD(outbuf, MAE_GET_AR_CAPS_OUT_FIELD_FLAGS);
	/* We're only interested in the support status enum, not any other
	 * flags, so just extract that from each entry.
	 */
	for (i = 0; i < count; i++)
		if (i * sizeof(*outbuf) + MC_CMD_MAE_GET_AR_CAPS_OUT_FIELD_FLAGS_OFST < outlen)
			field_support[i] = EFX_DWORD_FIELD(caps[i], MAE_FIELD_FLAGS_SUPPORT_STATUS);
	return 0;
}

int efx_mae_get_caps(struct efx_nic *efx, struct mae_caps *caps)
{
	int rc;

	rc = efx_mae_get_basic_caps(efx, caps);
	if (rc)
		return rc;
	rc = efx_mae_get_rule_fields(efx, MC_CMD_MAE_GET_AR_CAPS,
				     caps->action_rule_fields);
	if (rc)
		return rc;
	return efx_mae_get_rule_fields(efx, MC_CMD_MAE_GET_OR_CAPS,
				       caps->outer_rule_fields);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
/* Bit twiddling:
 * Prefix: 1...110...0
 *      ~: 0...001...1
 *    + 1: 0...010...0 is power of two
 * so (~x) & ((~x) + 1) == 0.  Converse holds also.
 */
#define is_prefix_byte(_x)	!(((_x) ^ 0xff) & (((_x) ^ 0xff) + 1))

enum mask_type { MASK_ONES, MASK_ZEROES, MASK_PREFIX, MASK_OTHER };

static const char *mask_type_name(enum mask_type typ)
{
	switch (typ) {
	case MASK_ONES:
		return "all-1s";
	case MASK_ZEROES:
		return "all-0s";
	case MASK_PREFIX:
		return "prefix";
	case MASK_OTHER:
		return "arbitrary";
	default: /* can't happen */
		return "unknown";
	}
}

/* Checks a (big-endian) bytestring is a bit prefix */
static enum mask_type classify_mask(const u8 *mask, size_t len)
{
	bool zeroes = true; /* All bits seen so far are zeroes */
	bool ones = true; /* All bits seen so far are ones */
	bool prefix = true; /* Valid prefix so far */
	size_t i;

	for (i = 0; i < len; i++) {
		if (ones) {
			if (!is_prefix_byte(mask[i]))
				prefix = false;
		} else if (mask[i]) {
			prefix = false;
		}
		if (mask[i] != 0xff)
			ones = false;
		if (mask[i])
			zeroes = false;
	}
	if (ones)
		return MASK_ONES;
	if (zeroes)
		return MASK_ZEROES;
	if (prefix)
		return MASK_PREFIX;
	return MASK_OTHER;
}

static int efx_mae_match_check_cap_typ(u8 support, enum mask_type typ)
{
	switch (support) {
	case MAE_FIELD_UNSUPPORTED:
	case MAE_FIELD_SUPPORTED_MATCH_NEVER:
		if (typ == MASK_ZEROES)
			return 0;
		return -EOPNOTSUPP;
	case MAE_FIELD_SUPPORTED_MATCH_OPTIONAL:
		if (typ == MASK_ZEROES)
			return 0;
		/* fall through */
	case MAE_FIELD_SUPPORTED_MATCH_ALWAYS:
		if (typ == MASK_ONES)
			return 0;
		return -EINVAL;
	case MAE_FIELD_SUPPORTED_MATCH_PREFIX:
		if (typ == MASK_OTHER)
			return -EOPNOTSUPP;
		return 0;
	case MAE_FIELD_SUPPORTED_MATCH_MASK:
		return 0;
	default:
		return -EIO;
	}
}

#define CHECK(_mcdi, _field)	do {					       \
	enum mask_type typ = classify_mask((const u8 *)&mask->_field,	       \
					   sizeof(mask->_field));	       \
									       \
	rc = efx_mae_match_check_cap_typ(supported_fields[MAE_FIELD_ ## _mcdi],\
					 typ);				       \
	if (rc) {							       \
		netif_err(efx, drv, efx->net_dev,			       \
			  "No support for %s mask in field %s\n",	       \
			  mask_type_name(typ), #_field);		       \
		if (typ == MASK_ONES)					       \
			NL_SET_ERR_MSG_MOD(extack, "Unsupported match field " #_field);\
		else							       \
			NL_SET_ERR_MSG_MOD(extack, "Unsupported mask type for " #_field);\
		return rc;						       \
	}								       \
} while (0)
#define UNSUPPORTED(_field)						       \
if (classify_mask((const u8 *)&mask->_field,				       \
		  sizeof(mask->_field)) != MASK_ZEROES) {		       \
	netif_err(efx, drv, efx->net_dev, "No support for field %s\n", #_field);\
	NL_SET_ERR_MSG_MOD(extack, "Unsupported match field " #_field);	       \
	return -EOPNOTSUPP;						       \
}
/* Bitfield members need special handling.  For now we only have 1-bit fields */
#define CHECK_BIT(_mcdi, _field)	do {				       \
	enum mask_type typ = mask->_field ? MASK_ONES : MASK_ZEROES;	       \
									       \
	rc = efx_mae_match_check_cap_typ(supported_fields[MAE_FIELD_ ## _mcdi],\
					 typ);				       \
	if (rc) {							       \
		netif_err(efx, drv, efx->net_dev,			       \
			  "No support for %s mask in field %s\n",	       \
			  mask_type_name(typ), #_field);		       \
		if (typ == MASK_ONES)					       \
			NL_SET_ERR_MSG_MOD(extack, "Unsupported match field " #_field);\
		else							       \
			NL_SET_ERR_MSG_MOD(extack, "Unsupported mask type for " #_field);\
		return rc;						       \
	}								       \
} while (0)
#define UNSUPPORTED_BIT(_field)						       \
if (mask->_field) {							       \
	netif_err(efx, drv, efx->net_dev, "No support for field %s\n", #_field);\
	NL_SET_ERR_MSG_MOD(extack, "Unsupported match field " #_field);	       \
	return -EOPNOTSUPP;						       \
}

int efx_mae_match_check_caps(struct efx_nic *efx,
			     const struct efx_tc_match_fields *mask,
			     struct netlink_ext_ack *extack)
{
	const u8 *supported_fields = efx->tc->caps->action_rule_fields;
	__be32 ingress_port = cpu_to_be32(mask->ingress_port);
	enum mask_type ingress_port_mask_type;
	int rc;

	/* Check for _PREFIX assumes big-endian, so we need to convert */
	ingress_port_mask_type = classify_mask((const u8 *)&ingress_port,
					       sizeof(ingress_port));
	rc = efx_mae_match_check_cap_typ(supported_fields[MAE_FIELD_INGRESS_PORT],
					 ingress_port_mask_type);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "No support for %s mask in field %s\n",
			  mask_type_name(ingress_port_mask_type), "ingress_port");
		NL_SET_ERR_MSG_MOD(extack, "Unsupported mask type for ingress_port");
		return rc;
	}
	CHECK(ETHER_TYPE, eth_proto);
	CHECK(VLAN0_TCI, vlan_tci[0]);
	CHECK(VLAN0_PROTO, vlan_proto[0]);
	CHECK(VLAN1_TCI, vlan_tci[1]);
	CHECK(VLAN1_PROTO, vlan_proto[1]);
	CHECK(ETH_SADDR, eth_saddr);
	CHECK(ETH_DADDR, eth_daddr);
	CHECK(IP_PROTO, ip_proto);
	CHECK(IP_TOS, ip_tos);
	CHECK(IP_TTL, ip_ttl);
	CHECK(SRC_IP4, src_ip);
	CHECK(DST_IP4, dst_ip);
	CHECK(SRC_IP6, src_ip6);
	CHECK(DST_IP6, dst_ip6);
	CHECK(L4_SPORT, l4_sport);
	CHECK(L4_DPORT, l4_dport);
	CHECK(TCP_FLAGS, tcp_flags);
	if (efx_tc_match_is_encap(mask)) {
		rc = efx_mae_match_check_cap_typ(
				supported_fields[MAE_FIELD_OUTER_RULE_ID],
				MASK_ONES);
		if (rc) {
			netif_err(efx, drv, efx->net_dev,
				  "No support for encap rule ID matches\n");
			NL_SET_ERR_MSG_MOD(extack, "No support for encap rule ID matches");
			return rc;
		}
		CHECK(ENC_VNET_ID, enc_keyid);
	} else if (mask->enc_keyid) {
		netif_err(efx, drv, efx->net_dev,
			  "Match on enc_keyid requires other encap fields\n");
		NL_SET_ERR_MSG_MOD(extack, "Match on enc_keyid requires other encap fields");
		return -EINVAL;
	}
	CHECK_BIT(IS_IP_FRAG, ip_frag);
	CHECK_BIT(DO_CT, ct_state_trk);
	CHECK_BIT(CT_HIT, ct_state_est);
	UNSUPPORTED_BIT(ct_state_new);
	UNSUPPORTED_BIT(ct_state_rel);
	CHECK(CT_MARK, ct_mark);
	CHECK(RECIRC_ID, recirc_id);
	return 0;
}

int efx_mae_match_check_caps_lhs(struct efx_nic *efx,
				 const struct efx_tc_match_fields *mask,
				 struct netlink_ext_ack *extack)
{
	const u8 *supported_fields = efx->tc->caps->outer_rule_fields;
	__be32 ingress_port = cpu_to_be32(mask->ingress_port);
	enum mask_type ingress_port_mask_type;
	int rc;

	/* Check for _PREFIX assumes big-endian, so we need to convert */
	ingress_port_mask_type = classify_mask((const u8 *)&ingress_port,
					       sizeof(ingress_port));
	rc = efx_mae_match_check_cap_typ(supported_fields[MAE_FIELD_INGRESS_PORT],
					 ingress_port_mask_type);
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "No support for %s mask in field %s\n",
			  mask_type_name(ingress_port_mask_type), "ingress_port");
		NL_SET_ERR_MSG_MOD(extack, "Unsupported mask type for ingress_port");
		return rc;
	}
	CHECK(ENC_ETHER_TYPE, eth_proto);
	CHECK(ENC_VLAN0_TCI, vlan_tci[0]);
	CHECK(ENC_VLAN0_PROTO, vlan_proto[0]);
	CHECK(ENC_VLAN1_TCI, vlan_tci[1]);
	CHECK(ENC_VLAN1_PROTO, vlan_proto[1]);
	CHECK(ENC_ETH_SADDR, eth_saddr);
	CHECK(ENC_ETH_DADDR, eth_daddr);
	CHECK(ENC_IP_PROTO, ip_proto);
	CHECK(ENC_IP_TOS, ip_tos);
	CHECK(ENC_IP_TTL, ip_ttl);
	CHECK(ENC_SRC_IP4, src_ip);
	CHECK(ENC_DST_IP4, dst_ip);
	CHECK(ENC_SRC_IP6, src_ip6);
	CHECK(ENC_DST_IP6, dst_ip6);
	CHECK(ENC_L4_SPORT, l4_sport);
	CHECK(ENC_L4_DPORT, l4_dport);
	UNSUPPORTED(tcp_flags);
	if (efx_tc_match_is_encap(mask) || mask->enc_keyid) {
		NL_SET_ERR_MSG_MOD(extack, "No support for encap matches in LHS rules");
		return -EOPNOTSUPP;
	}
	/* Can't filter on conntrack in LHS rules */
	UNSUPPORTED_BIT(ct_state_trk);
	UNSUPPORTED_BIT(ct_state_est);
	UNSUPPORTED_BIT(ct_state_new);
	UNSUPPORTED_BIT(ct_state_rel);
	UNSUPPORTED(ct_mark);
	UNSUPPORTED(recirc_id);
	/* Can't filter on ip_frag either (which might be a problem...) */
	UNSUPPORTED_BIT(ip_frag);
	return 0;
}
#undef CHECK
#undef UNSUPPORTED

#define CHECK(_mcdi) do {						       \
	rc = efx_mae_match_check_cap_typ(supported_fields[MAE_FIELD_ ## _mcdi],\
					 MASK_ONES);			       \
	if (rc) {							       \
		netif_err(efx, drv, efx->net_dev, "No support for field %s\n", \
			  #_mcdi);					       \
		return rc;						       \
	}								       \
} while (0)
/* Checks that the fields needed for encap-rule matches (all of which are exact)
 * are supported by the MAE.
 */
int efx_mae_check_encap_match_caps(struct efx_nic *efx, unsigned char ipv)
{
	u8 *supported_fields = efx->tc->caps->outer_rule_fields;
	int rc;

	CHECK(ENC_ETHER_TYPE);
	switch (ipv) {
	case 4:
		CHECK(ENC_SRC_IP4);
		CHECK(ENC_DST_IP4);
		break;
	case 6:
		CHECK(ENC_SRC_IP6);
		CHECK(ENC_DST_IP6);
		break;
	default: /* shouldn't happen */
		EFX_WARN_ON_PARANOID(1);
		break;
	}
	CHECK(ENC_L4_DPORT);
	CHECK(ENC_IP_PROTO);
	return 0;
}
#undef CHECK

int efx_mae_check_encap_type_supported(struct efx_nic *efx, enum efx_encap_type typ)
{
	unsigned int bit;

	switch (typ & EFX_ENCAP_TYPES_MASK) {
	case EFX_ENCAP_TYPE_VXLAN:
		bit = MC_CMD_MAE_GET_CAPS_OUT_ENCAP_TYPE_VXLAN_LBN;
		break;
	case EFX_ENCAP_TYPE_NVGRE:
		bit = MC_CMD_MAE_GET_CAPS_OUT_ENCAP_TYPE_NVGRE_LBN;
		break;
	case EFX_ENCAP_TYPE_GENEVE:
		bit = MC_CMD_MAE_GET_CAPS_OUT_ENCAP_TYPE_GENEVE_LBN;
		break;
	default:
		return -EOPNOTSUPP;
	}
	if (efx->tc->caps->encap_types & BIT(bit))
		return 0;
	return -EOPNOTSUPP;
}

int efx_mae_allocate_counter(struct efx_nic *efx, struct efx_tc_counter *cnt)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_COUNTER_ALLOC_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_COUNTER_ALLOC_IN_LEN);
	size_t outlen;
	int rc;

	if (!cnt)
		return -EINVAL;

	MCDI_SET_DWORD(inbuf, MAE_COUNTER_ALLOC_IN_REQUESTED_COUNT, 1);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_COUNTER_ALLOC, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	/* pcol says this can't happen, since count is 1 */
	if (outlen < sizeof(outbuf))
		return -EIO;
	cnt->fw_id = MCDI_DWORD(outbuf, MAE_COUNTER_ALLOC_OUT_COUNTER_ID);
	cnt->gen = MCDI_DWORD(outbuf, MAE_COUNTER_ALLOC_OUT_GENERATION_COUNT);
	return 0;
}

int efx_mae_free_counter(struct efx_nic *efx, u32 id)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_COUNTER_FREE_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_COUNTER_FREE_IN_LEN(1));
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAE_COUNTER_FREE_IN_COUNTER_ID_COUNT, 1);
	MCDI_SET_DWORD(inbuf, MAE_COUNTER_FREE_IN_FREE_COUNTER_ID, id);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_COUNTER_FREE, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	/* pcol says this can't happen, since count is 1 */
	if (outlen < sizeof(outbuf))
		return -EIO;
	/* FW freed a different ID than we asked for, should also never happen.
	 * Warn because it means we've now got a different idea to the FW of
	 * what counters exist, which could cause mayhem later.
	 */
	if (WARN_ON(MCDI_DWORD(outbuf, MAE_COUNTER_FREE_OUT_FREED_COUNTER_ID) != id))
		return -EIO;
	return 0;
}

static int efx_mae_encap_type_to_mae_type(enum efx_encap_type type)
{
	switch (type & EFX_ENCAP_TYPES_MASK) {
	case EFX_ENCAP_TYPE_NONE:
		return MAE_MCDI_ENCAP_TYPE_NONE;
	case EFX_ENCAP_TYPE_VXLAN:
		return MAE_MCDI_ENCAP_TYPE_VXLAN;
	case EFX_ENCAP_TYPE_GENEVE:
		return MAE_MCDI_ENCAP_TYPE_GENEVE;
	default:
		return -EOPNOTSUPP;
	}
}

int efx_mae_allocate_encap_md(struct efx_nic *efx,
			      struct efx_tc_encap_action *encap)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_ENCAP_HEADER_ALLOC_IN_LEN(EFX_TC_MAX_ENCAP_HDR));
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_ENCAP_HEADER_ALLOC_OUT_LEN);
	size_t inlen, outlen;
	int rc;

	rc = efx_mae_encap_type_to_mae_type(encap->type);
	if (rc < 0)
		return rc;
	MCDI_SET_DWORD(inbuf, MAE_ENCAP_HEADER_ALLOC_IN_ENCAP_TYPE, rc);
	inlen = MC_CMD_MAE_ENCAP_HEADER_ALLOC_IN_LEN(encap->encap_hdr_len);
	if (WARN_ON(inlen > sizeof(inbuf))) /* can't happen */
		return -EINVAL;
	memcpy(MCDI_PTR(inbuf, MAE_ENCAP_HEADER_ALLOC_IN_HDR_DATA),
	       encap->encap_hdr,
	       encap->encap_hdr_len);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_ENCAP_HEADER_ALLOC, inbuf,
			  inlen, outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	encap->fw_id = MCDI_DWORD(outbuf, MAE_ENCAP_HEADER_ALLOC_OUT_ENCAP_HEADER_ID);
	return 0;
}

int efx_mae_update_encap_md(struct efx_nic *efx,
			    struct efx_tc_encap_action *encap)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_ENCAP_HEADER_UPDATE_IN_LEN(EFX_TC_MAX_ENCAP_HDR));
	size_t inlen;
	int rc;

	rc = efx_mae_encap_type_to_mae_type(encap->type);
	if (rc < 0)
		return rc;
	MCDI_SET_DWORD(inbuf, MAE_ENCAP_HEADER_UPDATE_IN_ENCAP_TYPE, rc);
	MCDI_SET_DWORD(inbuf, MAE_ENCAP_HEADER_UPDATE_IN_EH_ID,
		       encap->fw_id);
	inlen = MC_CMD_MAE_ENCAP_HEADER_UPDATE_IN_LEN(encap->encap_hdr_len);
	if (WARN_ON(inlen > sizeof(inbuf))) /* can't happen */
		return -EINVAL;
	memcpy(MCDI_PTR(inbuf, MAE_ENCAP_HEADER_UPDATE_IN_HDR_DATA),
	       encap->encap_hdr,
	       encap->encap_hdr_len);

	BUILD_BUG_ON(MC_CMD_MAE_ENCAP_HEADER_UPDATE_OUT_LEN != 0);
	return efx_mcdi_rpc(efx, MC_CMD_MAE_ENCAP_HEADER_UPDATE, inbuf,
			    inlen, NULL, 0, NULL);
}

int efx_mae_free_encap_md(struct efx_nic *efx,
			  struct efx_tc_encap_action *encap)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_ENCAP_HEADER_FREE_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_ENCAP_HEADER_FREE_IN_LEN(1));
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAE_ENCAP_HEADER_FREE_IN_EH_ID, encap->fw_id);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_ENCAP_HEADER_FREE, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	/* FW freed a different ID than we asked for, should also never happen.
	 * Warn because it means we've now got a different idea to the FW of
	 * what encap_mds exist, which could cause mayhem later.
	 */
	if (WARN_ON(MCDI_DWORD(outbuf, MAE_ENCAP_HEADER_FREE_OUT_FREED_EH_ID) != encap->fw_id))
		return -EIO;
	/* We're probably about to free @encap, but let's just make sure its
	 * fw_id is blatted so that it won't look valid if it leaks out.
	 */
	encap->fw_id = MC_CMD_MAE_ENCAP_HEADER_ALLOC_OUT_ENCAP_HEADER_ID_NULL;
	return 0;
}
#endif /* EFX_TC_OFFLOAD */

int efx_mae_alloc_action_set(struct efx_nic *efx, struct efx_tc_action_set *act)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_ACTION_SET_ALLOC_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_ACTION_SET_ALLOC_IN_LEN);
	unsigned char vlan_push, vlan_pop;
	size_t outlen;
	int rc;

	/* Translate vlan actions from bitmask to count */
	switch (act->vlan_push) {
	case 0:
	case 1:
		vlan_push = act->vlan_push;
		break;
	case 2: /* can't happen */
	default:
		return -EINVAL;
	case 3:
		vlan_push = 2;
		break;
	}
	switch (act->vlan_pop) {
	case 0:
	case 1:
		vlan_pop = act->vlan_pop;
		break;
	case 2: /* can't happen */
	default:
		return -EINVAL;
	case 3:
		vlan_pop = 2;
		break;
	}

	MCDI_POPULATE_DWORD_4(inbuf, MAE_ACTION_SET_ALLOC_IN_FLAGS,
			      MAE_ACTION_SET_ALLOC_IN_VLAN_PUSH, vlan_push,
			      MAE_ACTION_SET_ALLOC_IN_VLAN_POP, vlan_pop,
			      MAE_ACTION_SET_ALLOC_IN_DECAP, act->decap,
			      MAE_ACTION_SET_ALLOC_IN_DO_NAT, act->do_nat);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	if (act->count && !WARN_ON(!act->count->cnt))
		MCDI_SET_DWORD(inbuf, MAE_ACTION_SET_ALLOC_IN_COUNTER_ID,
			       act->count->cnt->fw_id);
	else
#endif
		MCDI_SET_DWORD(inbuf, MAE_ACTION_SET_ALLOC_IN_COUNTER_ID,
			       MC_CMD_MAE_COUNTER_ALLOC_OUT_COUNTER_ID_NULL);
	MCDI_SET_DWORD(inbuf, MAE_ACTION_SET_ALLOC_IN_COUNTER_LIST_ID,
		       MC_CMD_MAE_COUNTER_LIST_ALLOC_OUT_COUNTER_LIST_ID_NULL);
	if (act->vlan_push & 1) {
		MCDI_SET_WORD_BE(inbuf, MAE_ACTION_SET_ALLOC_IN_VLAN0_TCI_BE,
				 act->vlan_tci[0]);
		MCDI_SET_WORD_BE(inbuf, MAE_ACTION_SET_ALLOC_IN_VLAN0_PROTO_BE,
				 act->vlan_proto[0]);
	}
	if (act->vlan_push & 2) {
		MCDI_SET_WORD_BE(inbuf, MAE_ACTION_SET_ALLOC_IN_VLAN1_TCI_BE,
				 act->vlan_tci[1]);
		MCDI_SET_WORD_BE(inbuf, MAE_ACTION_SET_ALLOC_IN_VLAN1_PROTO_BE,
				 act->vlan_proto[1]);
	}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	if (act->encap_md)
		MCDI_SET_DWORD(inbuf, MAE_ACTION_SET_ALLOC_IN_ENCAP_HEADER_ID,
			       act->encap_md->fw_id);
	else
#endif
		MCDI_SET_DWORD(inbuf, MAE_ACTION_SET_ALLOC_IN_ENCAP_HEADER_ID,
			       MC_CMD_MAE_ENCAP_HEADER_ALLOC_OUT_ENCAP_HEADER_ID_NULL);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	if (act->pedit_md)
		return -EOPNOTSUPP;
#endif
	if (act->deliver)
		MCDI_SET_DWORD(inbuf, MAE_ACTION_SET_ALLOC_IN_DELIVER,
			       act->dest_mport);
	BUILD_BUG_ON(MAE_MPORT_SELECTOR_NULL);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_ACTION_SET_ALLOC, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	act->fw_id = MCDI_DWORD(outbuf, MAE_ACTION_SET_ALLOC_OUT_AS_ID);
	return 0;
}

int efx_mae_free_action_set(struct efx_nic *efx, struct efx_tc_action_set *act)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_ACTION_SET_FREE_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_ACTION_SET_FREE_IN_LEN(1));
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAE_ACTION_SET_FREE_IN_AS_ID, act->fw_id);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_ACTION_SET_FREE, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	/* FW freed a different ID than we asked for, should never happen.
	 * Warn because it means we've now got a different idea to the FW of
	 * what encap_mds exist, which could cause mayhem later.
	 */
	if (WARN_ON(MCDI_DWORD(outbuf, MAE_ACTION_SET_FREE_OUT_FREED_AS_ID) != act->fw_id))
		return -EIO;
	/* We're probably about to free @act, but let's just make sure its
	 * fw_id is blatted so that it won't look valid if it leaks out.
	 */
	act->fw_id = MC_CMD_MAE_ACTION_SET_ALLOC_OUT_ACTION_SET_ID_NULL;
	return 0;
}

int efx_mae_alloc_action_set_list(struct efx_nic *efx,
				  struct efx_tc_action_set_list *acts)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_ACTION_SET_LIST_ALLOC_OUT_LEN);
	struct efx_tc_action_set *act;
	size_t inlen, outlen, i = 0;
	efx_dword_t *inbuf;
	int rc;

	list_for_each_entry(act, &acts->list, list)
		i++;
	if (i > MC_CMD_MAE_ACTION_SET_LIST_ALLOC_IN_AS_IDS_MAXNUM_MCDI2)
		return -EOPNOTSUPP; /* Too many actions */
	inlen = MC_CMD_MAE_ACTION_SET_LIST_ALLOC_IN_LEN(i);
	inbuf = kzalloc(inlen, GFP_KERNEL);
	if (!inbuf)
		return -ENOMEM;
	i = 0;
	list_for_each_entry(act, &acts->list, list) {
		MCDI_SET_ARRAY_DWORD(inbuf, MAE_ACTION_SET_LIST_ALLOC_IN_AS_IDS,
				     i, act->fw_id);
		i++;
	}
	MCDI_SET_DWORD(inbuf, MAE_ACTION_SET_LIST_ALLOC_IN_COUNT, i);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_ACTION_SET_LIST_ALLOC, inbuf, inlen,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		goto out_free;
	if (outlen < sizeof(outbuf)) {
		rc = -EIO;
		goto out_free;
	}
	acts->fw_id = MCDI_DWORD(outbuf, MAE_ACTION_SET_LIST_ALLOC_OUT_ASL_ID);
	rc = 0;
out_free:
	kfree(inbuf);
	return rc;
}

int efx_mae_free_action_set_list(struct efx_nic *efx,
				 struct efx_tc_action_set_list *acts)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_ACTION_SET_LIST_FREE_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_ACTION_SET_LIST_FREE_IN_LEN(1));
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAE_ACTION_SET_LIST_FREE_IN_ASL_ID,
		       acts->fw_id);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_ACTION_SET_LIST_FREE, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	/* FW freed a different ID than we asked for, should never happen.
	 * Warn because it means we've now got a different idea to the FW of
	 * what encap_mds exist, which could cause mayhem later.
	 */
	if (WARN_ON(MCDI_DWORD(outbuf, MAE_ACTION_SET_LIST_FREE_OUT_FREED_ASL_ID) != acts->fw_id))
		return -EIO;
	/* We're probably about to free @acts, but let's just make sure its
	 * fw_id is blatted so that it won't look valid if it leaks out.
	 */
	acts->fw_id = MC_CMD_MAE_ACTION_SET_LIST_ALLOC_OUT_ACTION_SET_LIST_ID_NULL;
	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
int efx_mae_register_encap_match(struct efx_nic *efx,
				 struct efx_tc_encap_match *encap)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_OUTER_RULE_INSERT_IN_LEN(MAE_ENC_FIELD_PAIRS_LEN));
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_OUTER_RULE_INSERT_OUT_LEN);
	MCDI_DECLARE_STRUCT_PTR(match_crit);
	size_t outlen;
	int rc;

	rc = efx_mae_encap_type_to_mae_type(encap->tun_type);
	if (rc < 0)
		return rc;
	match_crit = _MCDI_DWORD(inbuf, MAE_OUTER_RULE_INSERT_IN_FIELD_MATCH_CRITERIA);
	/* The struct contains IP src and dst, and udp dport.
	 * So we actually need to filter on IP src and dst, L4 dport, and
	 * ipproto == udp.
	 */
	MCDI_SET_DWORD(inbuf, MAE_OUTER_RULE_INSERT_IN_ENCAP_TYPE, rc);
	if (encap->src_ip | encap->dst_ip) {
		MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_SRC_IP4_BE,
					 encap->src_ip);
		MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_SRC_IP4_BE_MASK,
					 ~(__be32)0);
		MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_DST_IP4_BE,
					 encap->dst_ip);
		MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_DST_IP4_BE_MASK,
					 ~(__be32)0);
		MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_ETHER_TYPE_BE,
					htons(ETH_P_IP));
	} else {
		memcpy(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_SRC_IP6_BE),
		       &encap->src_ip6, sizeof(encap->src_ip6));
		memset(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_SRC_IP6_BE_MASK),
		       0xff, sizeof(encap->src_ip6));
		memcpy(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_DST_IP6_BE),
		       &encap->dst_ip6, sizeof(encap->dst_ip6));
		memset(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_DST_IP6_BE_MASK),
		       0xff, sizeof(encap->dst_ip6));
		MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_ETHER_TYPE_BE,
					htons(ETH_P_IPV6));
	}
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_ETHER_TYPE_BE_MASK,
				~(__be16)0);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_L4_DPORT_BE,
				encap->udp_dport);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_L4_DPORT_BE_MASK,
				~(__be16)0);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_IP_PROTO, IPPROTO_UDP);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_IP_PROTO_MASK, ~0);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_OUTER_RULE_INSERT, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	encap->fw_id = MCDI_DWORD(outbuf, MAE_OUTER_RULE_INSERT_OUT_OR_ID);
	return 0;
}

int efx_mae_unregister_encap_match(struct efx_nic *efx,
				   struct efx_tc_encap_match *encap)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_OUTER_RULE_REMOVE_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_OUTER_RULE_REMOVE_IN_LEN(1));
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAE_OUTER_RULE_REMOVE_IN_OR_ID, encap->fw_id);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_OUTER_RULE_REMOVE, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	/* FW freed a different ID than we asked for, should also never happen.
	 * Warn because it means we've now got a different idea to the FW of
	 * what encap_mds exist, which could cause mayhem later.
	 */
	if (WARN_ON(MCDI_DWORD(outbuf, MAE_OUTER_RULE_REMOVE_OUT_REMOVED_OR_ID) != encap->fw_id))
		return -EIO;
	/* We're probably about to free @encap, but let's just make sure its
	 * fw_id is blatted so that it won't look valid if it leaks out.
	 */
	encap->fw_id = MC_CMD_MAE_OUTER_RULE_INSERT_OUT_OUTER_RULE_ID_NULL;
	return 0;
}

static int efx_mae_populate_lhs_match_criteria(MCDI_DECLARE_STRUCT_PTR(match_crit),
					   const struct efx_tc_match *match)
{
	if (match->mask.ingress_port) {
		if (~match->mask.ingress_port)
			return -EOPNOTSUPP;
		MCDI_STRUCT_SET_DWORD(match_crit,
				      MAE_ENC_FIELD_PAIRS_INGRESS_MPORT_SELECTOR,
				      match->value.ingress_port);
	}
	MCDI_STRUCT_SET_DWORD(match_crit, MAE_ENC_FIELD_PAIRS_INGRESS_MPORT_SELECTOR_MASK,
			      match->mask.ingress_port);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_ETHER_TYPE_BE,
				match->value.eth_proto);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_ETHER_TYPE_BE_MASK,
				match->mask.eth_proto);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_VLAN0_TCI_BE,
				match->value.vlan_tci[0]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_VLAN0_TCI_BE_MASK,
				match->mask.vlan_tci[0]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_VLAN0_PROTO_BE,
				match->value.vlan_proto[0]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_VLAN0_PROTO_BE_MASK,
				match->mask.vlan_proto[0]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_VLAN1_TCI_BE,
				match->value.vlan_tci[1]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_VLAN1_TCI_BE_MASK,
				match->mask.vlan_tci[1]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_VLAN1_PROTO_BE,
				match->value.vlan_proto[1]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_VLAN1_PROTO_BE_MASK,
				match->mask.vlan_proto[1]);
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_ETH_SADDR_BE),
	       match->value.eth_saddr, ETH_ALEN);
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_ETH_SADDR_BE_MASK),
	       match->mask.eth_saddr, ETH_ALEN);
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_ETH_DADDR_BE),
	       match->value.eth_daddr, ETH_ALEN);
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_ETH_DADDR_BE_MASK),
	       match->mask.eth_daddr, ETH_ALEN);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_IP_PROTO,
			     match->value.ip_proto);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_IP_PROTO_MASK,
			     match->mask.ip_proto);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_IP_TOS,
			     match->value.ip_tos);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_IP_TOS_MASK,
			     match->mask.ip_tos);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_IP_TTL,
			     match->value.ip_ttl);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_IP_TTL_MASK,
			     match->mask.ip_ttl);
	MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_SRC_IP4_BE,
				 match->value.src_ip);
	MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_SRC_IP4_BE_MASK,
				 match->mask.src_ip);
	MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_DST_IP4_BE,
				 match->value.dst_ip);
	MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_DST_IP4_BE_MASK,
				 match->mask.dst_ip);
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_SRC_IP6_BE),
			       &match->value.src_ip6, sizeof(struct in6_addr));
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_SRC_IP6_BE_MASK),
			       &match->mask.src_ip6, sizeof(struct in6_addr));
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_DST_IP6_BE),
			       &match->value.dst_ip6, sizeof(struct in6_addr));
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_ENC_FIELD_PAIRS_ENC_DST_IP6_BE_MASK),
			       &match->mask.dst_ip6, sizeof(struct in6_addr));
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_L4_SPORT_BE,
				match->value.l4_sport);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_L4_SPORT_BE_MASK,
				match->mask.l4_sport);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_L4_DPORT_BE,
				match->value.l4_dport);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_ENC_FIELD_PAIRS_ENC_L4_DPORT_BE_MASK,
				match->mask.l4_dport);
	/* No enc-keys in LHS rules.  Caps check should have caught this */
	if (WARN_ON_ONCE(match->encap))
		return -EOPNOTSUPP;
	if (WARN_ON_ONCE(match->mask.enc_src_ip))
		return -EOPNOTSUPP;
	if (WARN_ON_ONCE(match->mask.enc_dst_ip))
		return -EOPNOTSUPP;
	if (WARN_ON_ONCE(!ipv6_addr_any(&match->mask.enc_src_ip6)))
		return -EOPNOTSUPP;
	if (WARN_ON_ONCE(!ipv6_addr_any(&match->mask.enc_dst_ip6)))
		return -EOPNOTSUPP;
	if (WARN_ON_ONCE(match->mask.enc_ip_tos))
		return -EOPNOTSUPP;
	if (WARN_ON_ONCE(match->mask.enc_ip_ttl))
		return -EOPNOTSUPP;
	if (WARN_ON_ONCE(match->mask.enc_sport))
		return -EOPNOTSUPP;
	if (WARN_ON_ONCE(match->mask.enc_dport))
		return -EOPNOTSUPP;
	if (WARN_ON_ONCE(match->mask.enc_keyid))
		return -EOPNOTSUPP;
	return 0;
}

int efx_mae_insert_lhs_rule(struct efx_nic *efx, struct efx_tc_lhs_rule *rule,
			    u32 prio)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_OUTER_RULE_INSERT_IN_LEN(MAE_ENC_FIELD_PAIRS_LEN));
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_OUTER_RULE_INSERT_OUT_LEN);
	MCDI_DECLARE_STRUCT_PTR(match_crit);
	const struct efx_tc_lhs_action *act;
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAE_OUTER_RULE_INSERT_IN_PRIO, prio);
	/* match */
	match_crit = _MCDI_DWORD(inbuf, MAE_OUTER_RULE_INSERT_IN_FIELD_MATCH_CRITERIA);
	rc = efx_mae_populate_lhs_match_criteria(match_crit, &rule->match);
	if (rc)
		return rc;

	/* action */
	act = &rule->lhs_act;
	rc = efx_mae_encap_type_to_mae_type(act->tun_type);
	if (rc < 0)
		return rc;
	MCDI_SET_DWORD(inbuf, MAE_OUTER_RULE_INSERT_IN_ENCAP_TYPE, rc);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
	MCDI_POPULATE_DWORD_3(inbuf, MAE_OUTER_RULE_INSERT_IN_LOOKUP_CONTROL,
			      MAE_OUTER_RULE_INSERT_IN_DO_CT, !!act->zone,
			      MAE_OUTER_RULE_INSERT_IN_CT_DOMAIN,
			      act->zone ? act->zone->zone : 0,
			      MAE_OUTER_RULE_INSERT_IN_RECIRC_ID, act->rid ? act->rid->fw_id : 0);
#else
	MCDI_POPULATE_DWORD_1(inbuf, MAE_OUTER_RULE_INSERT_IN_LOOKUP_CONTROL,
			      MAE_OUTER_RULE_INSERT_IN_RECIRC_ID, act->rid ? act->rid->fw_id : 0);
#endif
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_OUTER_RULE_INSERT, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	rule->fw_id = MCDI_DWORD(outbuf, MAE_OUTER_RULE_INSERT_OUT_OR_ID);
	return 0;
}

int efx_mae_remove_lhs_rule(struct efx_nic *efx, struct efx_tc_lhs_rule *rule)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_OUTER_RULE_REMOVE_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_OUTER_RULE_REMOVE_IN_LEN(1));
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAE_OUTER_RULE_REMOVE_IN_OR_ID, rule->fw_id);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_OUTER_RULE_REMOVE, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	/* FW freed a different ID than we asked for, should also never happen.
	 * Warn because it means we've now got a different idea to the FW of
	 * what encap_mds exist, which could cause mayhem later.
	 */
	if (WARN_ON(MCDI_DWORD(outbuf, MAE_OUTER_RULE_REMOVE_OUT_REMOVED_OR_ID) != rule->fw_id))
		return -EIO;
	/* We're probably about to free @rule, but let's just make sure its
	 * fw_id is blatted so that it won't look valid if it leaks out.
	 */
	rule->fw_id = MC_CMD_MAE_OUTER_RULE_INSERT_OUT_OUTER_RULE_ID_NULL;
	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_CONNTRACK_OFFLOAD)
int efx_mae_insert_ct(struct efx_nic *efx, struct efx_tc_ct_entry *conn)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_TRACK_CONNECTION_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_TRACK_CONNECTION_IN_LEN);
	bool ipv6 = false, udp = false;
	size_t outlen;
	int rc;

	switch (conn->eth_proto) {
	case htons(ETH_P_IP):
		break;
	case htons(ETH_P_IPV6):
		ipv6 = true;
		break;
	default:
		return -EOPNOTSUPP;
	}
	switch (conn->ip_proto) {
	case IPPROTO_TCP:
		break;
	case IPPROTO_UDP:
		udp = true;
		break;
	default:
		return -EOPNOTSUPP;
	}
	MCDI_POPULATE_DWORD_3(inbuf, MAE_TRACK_CONNECTION_IN_FLAGS,
			      MAE_TRACK_CONNECTION_IN_IS_IPV6, ipv6,
			      MAE_TRACK_CONNECTION_IN_IS_UDP, udp,
			      MAE_TRACK_CONNECTION_IN_NAT_DIR_IS_DST, conn->dnat);
	MCDI_SET_WORD(inbuf, MAE_TRACK_CONNECTION_IN_DOMAIN, conn->zone);
	if (ipv6) {
		memcpy(MCDI_PTR(inbuf, MAE_TRACK_CONNECTION_IN_SRC_ADDR),
				&conn->src_ip6, sizeof(struct in6_addr));
		memcpy(MCDI_PTR(inbuf, MAE_TRACK_CONNECTION_IN_DST_ADDR),
				&conn->dst_ip6, sizeof(struct in6_addr));
	} else {
		MCDI_SET_DWORD_BE(inbuf, MAE_TRACK_CONNECTION_IN_SRC_ADDR,
			       conn->src_ip);
		MCDI_SET_DWORD_BE(inbuf, MAE_TRACK_CONNECTION_IN_DST_ADDR,
			       conn->dst_ip);
		MCDI_SET_DWORD_BE(inbuf, MAE_TRACK_CONNECTION_IN_NAT_IP,
			       conn->nat_ip);
	}
	MCDI_SET_WORD_BE(inbuf, MAE_TRACK_CONNECTION_IN_SRC_PORT, conn->l4_sport);
	MCDI_SET_WORD_BE(inbuf, MAE_TRACK_CONNECTION_IN_DST_PORT, conn->l4_dport);
	MCDI_SET_WORD_BE(inbuf, MAE_TRACK_CONNECTION_IN_NAT_PORT, conn->l4_natport);
	MCDI_SET_DWORD(inbuf, MAE_TRACK_CONNECTION_IN_CT_MARK, conn->mark);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_TRACK_CONNECTION, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	conn->fw_id = MCDI_DWORD(outbuf, MAE_TRACK_CONNECTION_OUT_CONN_ID);
	return 0;
}

int efx_mae_remove_ct(struct efx_nic *efx, struct efx_tc_ct_entry *conn)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_FORGET_CONNECTION_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_FORGET_CONNECTION_IN_LEN(1));
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAE_FORGET_CONNECTION_IN_CONN_ID, conn->fw_id);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_FORGET_CONNECTION, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	/* FW freed a different ID than we asked for, should also never happen.
	 * Warn because it means we've now got a different idea to the FW of
	 * what rules exist, which could cause mayhem later.
	 */
	if (WARN_ON(MCDI_DWORD(outbuf, MAE_FORGET_CONNECTION_OUT_REMOVED_CONN_ID) != conn->fw_id))
		return -EIO;
	/* We're probably about to free @conn, but let's just make sure its
	 * fw_id is blatted so that it won't look valid if it leaks out.
	 */
	conn->fw_id = MC_CMD_MAE_TRACK_CONNECTION_OUT_CONN_ID_NULL;
	return 0;
}
#endif
#endif /* EFX_TC_OFFLOAD */

static int efx_mae_populate_match_criteria(MCDI_DECLARE_STRUCT_PTR(match_crit),
					   const struct efx_tc_match *match)
{
	if (match->mask.ingress_port) {
		if (~match->mask.ingress_port)
			return -EOPNOTSUPP;
		MCDI_STRUCT_SET_DWORD(match_crit,
				      MAE_FIELD_MASK_VALUE_PAIRS_V2_INGRESS_MPORT_SELECTOR,
				      match->value.ingress_port);
	}
	MCDI_STRUCT_SET_DWORD(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_INGRESS_MPORT_SELECTOR_MASK,
			      match->mask.ingress_port);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	EFX_POPULATE_DWORD_3(*_MCDI_STRUCT_DWORD(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_FLAGS),
			     MAE_FIELD_MASK_VALUE_PAIRS_V2_DO_CT,
			     match->value.ct_state_trk,
			     MAE_FIELD_MASK_VALUE_PAIRS_V2_CT_HIT,
			     match->value.ct_state_est,
			     MAE_FIELD_MASK_VALUE_PAIRS_V2_IS_IP_FRAG,
			     match->value.ip_frag);
	EFX_POPULATE_DWORD_3(*_MCDI_STRUCT_DWORD(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_FLAGS_MASK),
			     MAE_FIELD_MASK_VALUE_PAIRS_V2_DO_CT,
			     match->mask.ct_state_trk,
			     MAE_FIELD_MASK_VALUE_PAIRS_V2_CT_HIT,
			     match->mask.ct_state_est,
			     MAE_FIELD_MASK_VALUE_PAIRS_V2_IS_IP_FRAG,
			     match->mask.ip_frag);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_RECIRC_ID,
			     match->value.recirc_id);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_RECIRC_ID_MASK,
			     match->mask.recirc_id);
	MCDI_STRUCT_SET_DWORD(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_CT_MARK,
			      match->value.ct_mark);
	MCDI_STRUCT_SET_DWORD(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_CT_MARK_MASK,
			      match->mask.ct_mark);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_ETHER_TYPE_BE,
				match->value.eth_proto);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_ETHER_TYPE_BE_MASK,
				match->mask.eth_proto);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_VLAN0_TCI_BE,
				match->value.vlan_tci[0]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_VLAN0_TCI_BE_MASK,
				match->mask.vlan_tci[0]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_VLAN0_PROTO_BE,
				match->value.vlan_proto[0]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_VLAN0_PROTO_BE_MASK,
				match->mask.vlan_proto[0]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_VLAN1_TCI_BE,
				match->value.vlan_tci[1]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_VLAN1_TCI_BE_MASK,
				match->mask.vlan_tci[1]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_VLAN1_PROTO_BE,
				match->value.vlan_proto[1]);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_VLAN1_PROTO_BE_MASK,
				match->mask.vlan_proto[1]);
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_ETH_SADDR_BE),
	       match->value.eth_saddr, ETH_ALEN);
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_ETH_SADDR_BE_MASK),
	       match->mask.eth_saddr, ETH_ALEN);
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_ETH_DADDR_BE),
	       match->value.eth_daddr, ETH_ALEN);
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_ETH_DADDR_BE_MASK),
	       match->mask.eth_daddr, ETH_ALEN);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_IP_PROTO,
			     match->value.ip_proto);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_IP_PROTO_MASK,
			     match->mask.ip_proto);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_IP_TOS,
			     match->value.ip_tos);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_IP_TOS_MASK,
			     match->mask.ip_tos);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_IP_TTL,
			     match->value.ip_ttl);
	MCDI_STRUCT_SET_BYTE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_IP_TTL_MASK,
			     match->mask.ip_ttl);
	MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_SRC_IP4_BE,
				 match->value.src_ip);
	MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_SRC_IP4_BE_MASK,
				 match->mask.src_ip);
	MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_DST_IP4_BE,
				 match->value.dst_ip);
	MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_DST_IP4_BE_MASK,
				 match->mask.dst_ip);
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_SRC_IP6_BE),
			       &match->value.src_ip6, sizeof(struct in6_addr));
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_SRC_IP6_BE_MASK),
			       &match->mask.src_ip6, sizeof(struct in6_addr));
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_DST_IP6_BE),
			       &match->value.dst_ip6, sizeof(struct in6_addr));
	memcpy(MCDI_STRUCT_PTR(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_DST_IP6_BE_MASK),
			       &match->mask.dst_ip6, sizeof(struct in6_addr));
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_L4_SPORT_BE,
				match->value.l4_sport);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_L4_SPORT_BE_MASK,
				match->mask.l4_sport);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_L4_DPORT_BE,
				match->value.l4_dport);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_L4_DPORT_BE_MASK,
				match->mask.l4_dport);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_TCP_FLAGS_BE,
				match->value.tcp_flags);
	MCDI_STRUCT_SET_WORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_TCP_FLAGS_BE_MASK,
				match->mask.tcp_flags);
	/* enc-keys are handled indirectly, through encap_match ID */
	if (match->encap) {
		MCDI_STRUCT_SET_DWORD(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_OUTER_RULE_ID,
				      match->encap->fw_id);
		MCDI_STRUCT_SET_DWORD(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_OUTER_RULE_ID_MASK,
				      (u32)-1);
		/* enc_keyid (VNI/VSID) is not part of the encap_match */
		MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_ENC_VNET_ID_BE,
					 match->value.enc_keyid);
		MCDI_STRUCT_SET_DWORD_BE(match_crit, MAE_FIELD_MASK_VALUE_PAIRS_V2_ENC_VNET_ID_BE_MASK,
					 match->mask.enc_keyid);
	} else {
		/* No enc-keys should appear in a rule without an encap_match */
		if (WARN_ON_ONCE(match->mask.enc_src_ip))
			return -EOPNOTSUPP;
		if (WARN_ON_ONCE(match->mask.enc_dst_ip))
			return -EOPNOTSUPP;
		if (WARN_ON_ONCE(!ipv6_addr_any(&match->mask.enc_src_ip6)))
			return -EOPNOTSUPP;
		if (WARN_ON_ONCE(!ipv6_addr_any(&match->mask.enc_dst_ip6)))
			return -EOPNOTSUPP;
		if (WARN_ON_ONCE(match->mask.enc_ip_tos))
			return -EOPNOTSUPP;
		if (WARN_ON_ONCE(match->mask.enc_ip_ttl))
			return -EOPNOTSUPP;
		if (WARN_ON_ONCE(match->mask.enc_sport))
			return -EOPNOTSUPP;
		if (WARN_ON_ONCE(match->mask.enc_dport))
			return -EOPNOTSUPP;
		if (WARN_ON_ONCE(match->mask.enc_keyid))
			return -EOPNOTSUPP;
	}
#endif /* EFX_TC_OFFLOAD */
	return 0;
}

int efx_mae_insert_rule(struct efx_nic *efx, const struct efx_tc_match *match,
			u32 prio, u32 acts_id, u32 *id)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_ACTION_RULE_INSERT_IN_LEN(MAE_FIELD_MASK_VALUE_PAIRS_V2_LEN));
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_ACTION_RULE_INSERT_OUT_LEN);
	MCDI_DECLARE_STRUCT_PTR(match_crit);
	MCDI_DECLARE_STRUCT_PTR(response);
	size_t outlen;
	int rc;

	if (!id)
		return -EINVAL;

	match_crit = _MCDI_DWORD(inbuf, MAE_ACTION_RULE_INSERT_IN_MATCH_CRITERIA);
	response = _MCDI_DWORD(inbuf, MAE_ACTION_RULE_INSERT_IN_RESPONSE);
	MCDI_STRUCT_SET_DWORD(response, MAE_ACTION_RULE_RESPONSE_ASL_ID, acts_id);
	MCDI_STRUCT_SET_DWORD(response, MAE_ACTION_RULE_RESPONSE_AS_ID,
			      MC_CMD_MAE_ACTION_SET_ALLOC_OUT_ACTION_SET_ID_NULL);
	MCDI_SET_DWORD(inbuf, MAE_ACTION_RULE_INSERT_IN_PRIO, prio);
	rc = efx_mae_populate_match_criteria(match_crit, match);
	if (rc)
		return rc;

	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_ACTION_RULE_INSERT, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	*id = MCDI_DWORD(outbuf, MAE_ACTION_RULE_INSERT_OUT_AR_ID);
	return 0;
}

int efx_mae_update_rule(struct efx_nic *efx, u32 acts_id, u32 id)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_ACTION_RULE_UPDATE_IN_LEN);
	MCDI_DECLARE_STRUCT_PTR(response);

	BUILD_BUG_ON(MC_CMD_MAE_ACTION_RULE_UPDATE_OUT_LEN);
	response = _MCDI_DWORD(inbuf, MAE_ACTION_RULE_UPDATE_IN_RESPONSE);

	MCDI_SET_DWORD(inbuf, MAE_ACTION_RULE_UPDATE_IN_AR_ID, id);
	MCDI_STRUCT_SET_DWORD(response, MAE_ACTION_RULE_RESPONSE_ASL_ID, acts_id);
	MCDI_STRUCT_SET_DWORD(response, MAE_ACTION_RULE_RESPONSE_AS_ID,
			      MC_CMD_MAE_ACTION_SET_ALLOC_OUT_ACTION_SET_ID_NULL);
	return efx_mcdi_rpc(efx, MC_CMD_MAE_ACTION_RULE_UPDATE, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

int efx_mae_delete_rule(struct efx_nic *efx, u32 id)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_MAE_ACTION_RULE_DELETE_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAE_ACTION_RULE_DELETE_IN_LEN(1));
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, MAE_ACTION_RULE_DELETE_IN_AR_ID, id);
	rc = efx_mcdi_rpc(efx, MC_CMD_MAE_ACTION_RULE_DELETE, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	/* FW freed a different ID than we asked for, should also never happen.
	 * Warn because it means we've now got a different idea to the FW of
	 * what rules exist, which could cause mayhem later.
	 */
	if (WARN_ON(MCDI_DWORD(outbuf, MAE_ACTION_RULE_DELETE_OUT_DELETED_AR_ID) != id))
		return -EIO;
	return 0;
}
