// SPDX-License-Identifier: GPL-2.0-only
/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2018 Solarflare Communications Inc.
 * Copyright 2019-2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "mcdi_filters.h"
#include "debugfs.h"
#include "mcdi_pcol.h"
#include "mcdi.h"
#include "efx.h"
#include "rx_common.h"

/* The maximum size of a shared RSS context */
/* TODO: this should really be from the mcdi protocol export */
#define EFX_MCDI_MAX_SHARED_RSS_CONTEXT_SIZE 64UL

#define EFX_MCDI_FILTER_ID_INVALID 0xffff

#define EFX_MCDI_FILTER_DEV_UC_MAX      32
#define EFX_MCDI_FILTER_DEV_MC_MAX      512

/* An arbitrary search limit for the software hash table */
#define EFX_MCDI_FILTER_SEARCH_LIMIT 200

enum efx_mcdi_filter_default_filters {
	EFX_MCDI_BCAST,
	EFX_MCDI_UCDEF,
	EFX_MCDI_MCDEF,
	EFX_MCDI_VXLAN4_UCDEF,
	EFX_MCDI_VXLAN4_MCDEF,
	EFX_MCDI_VXLAN6_UCDEF,
	EFX_MCDI_VXLAN6_MCDEF,
	EFX_MCDI_NVGRE4_UCDEF,
	EFX_MCDI_NVGRE4_MCDEF,
	EFX_MCDI_NVGRE6_UCDEF,
	EFX_MCDI_NVGRE6_MCDEF,
	EFX_MCDI_GENEVE4_UCDEF,
	EFX_MCDI_GENEVE4_MCDEF,
	EFX_MCDI_GENEVE6_UCDEF,
	EFX_MCDI_GENEVE6_MCDEF,

	EFX_MCDI_NUM_DEFAULT_FILTERS
};

/* Per-VLAN filters information */
struct efx_mcdi_filter_vlan {
	struct list_head list;
	u16 vid;
	u16 uc[EFX_MCDI_FILTER_DEV_UC_MAX];
	u16 mc[EFX_MCDI_FILTER_DEV_MC_MAX];
	u16 default_filters[EFX_MCDI_NUM_DEFAULT_FILTERS];
	bool warn_on_zero_filters;
};

struct efx_mcdi_dev_addr {
	u8 addr[ETH_ALEN];
};

struct efx_mcdi_filter_table {
/* The MCDI match masks supported by this fw & hw, in order of priority */
	u32 rx_match_mcdi_flags[
		MC_CMD_GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES_MAXNUM * 2];
	unsigned int rx_match_count;

	struct rw_semaphore lock; /* Protects entries */
	struct {
		unsigned long spec;     /* pointer to spec plus flag bits */
/* AUTO_OLD is used to mark and sweep MAC filters for the device address lists. */
/* unused flag  1UL */
#define EFX_MCDI_FILTER_FLAG_AUTO_OLD   2UL
#define EFX_MCDI_FILTER_FLAGS	   3UL
		u64 handle;	     /* firmware handle */
	} *entry;
	/* are the filters meant to be on the NIC */
	bool push_filters;
	/* Shadow of net_device address lists, guarded by mac_lock */
	struct efx_mcdi_dev_addr dev_uc_list[EFX_MCDI_FILTER_DEV_UC_MAX];
	struct efx_mcdi_dev_addr dev_mc_list[EFX_MCDI_FILTER_DEV_MC_MAX];
	int dev_uc_count;
	int dev_mc_count;
	bool uc_promisc;
	bool mc_promisc;
	bool mc_promisc_last;
	bool mc_overflow; /* Too many MC addrs; should always imply mc_promisc */
	bool vlan_filter;
	struct list_head vlan_list;
	bool mc_chaining;
	bool encap_supported;
	bool must_restore_filters;
	bool must_restore_rss_contexts;
	bool rss_context_exclusive;
	bool additional_rss_modes;
	bool rss_limited;
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	bool kernel_blocked[EFX_DL_FILTER_BLOCK_KERNEL_MAX];
#endif
#endif
};

static void efx_mcdi_filter_remove_old(struct efx_nic *efx);

static unsigned int efx_mcdi_filter_vlan_count_filters(struct efx_nic *efx,
						       struct efx_mcdi_filter_vlan *vlan);

static struct efx_filter_spec *
efx_mcdi_filter_entry_spec(const struct efx_mcdi_filter_table *table,
			   unsigned int filter_idx)
{
	return (struct efx_filter_spec *)(table->entry[filter_idx].spec &
					  ~EFX_MCDI_FILTER_FLAGS);
}

static unsigned int
efx_mcdi_filter_entry_flags(const struct efx_mcdi_filter_table *table,
			    unsigned int filter_idx)
{
	return table->entry[filter_idx].spec & EFX_MCDI_FILTER_FLAGS;
}

static u32 efx_mcdi_filter_get_unsafe_id(struct efx_nic *efx, u32 filter_id)
{
	(void) efx;
	WARN_ON_ONCE(filter_id == EFX_MCDI_FILTER_ID_INVALID);
	return filter_id & (EFX_MCDI_FILTER_TBL_ROWS - 1);
}

static unsigned int efx_mcdi_filter_get_unsafe_pri(u32 filter_id)
{
	return filter_id / (EFX_MCDI_FILTER_TBL_ROWS * 2);
}

static u32 efx_mcdi_filter_make_filter_id(unsigned int pri, u16 idx)
{
	return pri * EFX_MCDI_FILTER_TBL_ROWS * 2 + idx;
}

#ifdef CONFIG_SFC_DEBUGFS
static void efx_debugfs_read_dev_list(struct seq_file *file,
				      struct efx_mcdi_dev_addr *dev_list,
				      size_t list_len)
{
	size_t i;
	static u8 zero[ETH_ALEN];

	for (i = 0; i < list_len; i++)
		if (!ether_addr_equal(dev_list[i].addr, zero))
			seq_printf(file, "%02x:%02x:%02x:%02x:%02x:%02x\n",
				   dev_list[i].addr[0], dev_list[i].addr[1],
				   dev_list[i].addr[2], dev_list[i].addr[3],
				   dev_list[i].addr[4], dev_list[i].addr[5]);
}

static int efx_debugfs_read_dev_uc_list(struct seq_file *file, void *data)
{
	efx_debugfs_read_dev_list(file, data,
				  EFX_MCDI_FILTER_DEV_UC_MAX);
	return 0;
}

static int efx_debugfs_read_dev_mc_list(struct seq_file *file, void *data)
{
	efx_debugfs_read_dev_list(file, data,
				  EFX_MCDI_FILTER_DEV_MC_MAX);
	return 0;
}

static int efx_debugfs_read_filter_list(struct seq_file *file, void *data)
{
	struct efx_mcdi_filter_table *table;
	struct efx_nic *efx = data;
	int i;

	down_read(&efx->filter_sem);
	table = efx->filter_state;
	if (!table || !table->entry) {
		up_read(&efx->filter_sem);
		return -ENETDOWN;
	}

	/* deliberately don't lock the table->lock, so that we can
	 * dump the table mid-operation if needed.
	 */
	for (i = 0; i < EFX_MCDI_FILTER_TBL_ROWS; ++i) {
		struct efx_filter_spec *spec =
			efx_mcdi_filter_entry_spec(table, i);
		char filter[256];

		if (spec) {
			efx_debugfs_print_filter(filter, sizeof(filter), spec);

			seq_printf(file, "%d[%#04llx],%#x = %s\n",
				   i, table->entry[i].handle & 0xffff,
				   efx_mcdi_filter_entry_flags(table, i),
				   filter);
		}
	}

	up_read(&efx->filter_sem);
	return 0;
}

static struct efx_debugfs_parameter efx_debugfs[] = {
	_EFX_RAW_PARAMETER(filters, efx_debugfs_read_filter_list),
	{NULL}
};

static struct efx_debugfs_parameter filter_debugfs[] = {
	EFX_INT_PARAMETER(struct efx_mcdi_filter_table, dev_uc_count),
	EFX_INT_PARAMETER(struct efx_mcdi_filter_table, dev_mc_count),
	_EFX_PARAMETER(struct efx_mcdi_filter_table, dev_uc_list,
		       efx_debugfs_read_dev_uc_list),
	_EFX_PARAMETER(struct efx_mcdi_filter_table, dev_mc_list,
		       efx_debugfs_read_dev_mc_list),
	EFX_BOOL_PARAMETER(struct efx_mcdi_filter_table, uc_promisc),
	EFX_BOOL_PARAMETER(struct efx_mcdi_filter_table, mc_promisc),
	EFX_BOOL_PARAMETER(struct efx_mcdi_filter_table, mc_promisc_last),
	EFX_BOOL_PARAMETER(struct efx_mcdi_filter_table, mc_overflow),
	EFX_BOOL_PARAMETER(struct efx_mcdi_filter_table, mc_chaining),
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	_EFX_PARAMETER(struct efx_mcdi_filter_table, kernel_blocked,
		       efx_debugfs_read_kernel_blocked),
#endif
#endif
	{NULL}
};
#endif

static bool efx_mcdi_filter_vlan_filter(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;

	if (WARN_ON(!table))
		return false;

	if (!(efx->net_dev->features & NETIF_F_HW_VLAN_CTAG_FILTER))
		return false;

	/* If we don't support VLAN+mismatch filters then if we
	 * want promiscuous or allmulti mode we'll need
	 * to do it without vlan filter
	 */
	if ((table->uc_promisc || table->mc_promisc) &&
	    !efx_mcdi_filter_match_supported(efx, false,
		(EFX_FILTER_MATCH_OUTER_VID | EFX_FILTER_MATCH_LOC_MAC_IG)))
		return false;

	return true;
}

/* Decide whether a filter should be exclusive or else should allow
 * delivery to additional recipients.  Currently we decide that
 * filters for specific local unicast MAC and IP addresses are
 * exclusive.
 */
static bool efx_mcdi_filter_is_exclusive(const struct efx_filter_spec *spec)
{
#ifdef EFX_NOT_UPSTREAM
	/* special case ether type and ip proto filters for onload */
	if (spec->match_flags == EFX_FILTER_MATCH_ETHER_TYPE ||
	    spec->match_flags == EFX_FILTER_MATCH_IP_PROTO ||
	    spec->match_flags ==
		     (EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_IP_PROTO))
		return true;
#endif
	if (spec->match_flags & EFX_FILTER_MATCH_LOC_MAC &&
	    !is_multicast_ether_addr(spec->loc_mac))
		return true;

	if ((spec->match_flags &
	     (EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_LOC_HOST)) ==
	    (EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_LOC_HOST)) {
		if (spec->ether_type == htons(ETH_P_IP) &&
		    !(ipv4_is_multicast(spec->loc_host[0]) ||
		      ipv4_is_lbcast(spec->loc_host[0])))
			return true;
		if (spec->ether_type == htons(ETH_P_IPV6) &&
		    ((const u8 *)spec->loc_host)[0] != 0xff)
			return true;
	}

	return false;
}

static void
efx_mcdi_filter_set_entry(struct efx_mcdi_filter_table *table,
			  unsigned int filter_idx,
			  const struct efx_filter_spec *spec,
			  unsigned int flags)
{
	table->entry[filter_idx].spec = (unsigned long)spec | flags;
}

static void
efx_mcdi_filter_push_prep_set_match_fields(struct efx_nic *efx,
					   const struct efx_filter_spec *spec,
					   efx_dword_t *inbuf)
{
	u32 match_fields = 0;
	enum efx_encap_type encap_type =
		efx_filter_get_encap_type(spec);
	unsigned uc_match, mc_match;

	MCDI_SET_DWORD(inbuf, FILTER_OP_IN_OP,
			efx_mcdi_filter_is_exclusive(spec) ?
			MC_CMD_FILTER_OP_IN_OP_INSERT :
			MC_CMD_FILTER_OP_IN_OP_SUBSCRIBE);

	/* Convert match flags and values.  Unlike almost
	 * everything else in MCDI, these fields are in
	 * network byte order.
	 */
#define COPY_FIELD(encap, gen_flag, gen_field, mcdi_field)	\
	do {							\
		if ((spec)->match_flags &			\
				EFX_FILTER_MATCH_ ## gen_flag)  \
		COPY_VALUE((encap), (spec)->gen_field,		\
				mcdi_field);			\
	} while (0)

#define COPY_VALUE(encap, value, mcdi_field)			\
	do {							\
		match_fields |= (encap) ?			\
		1 << MC_CMD_FILTER_OP_EXT_IN_MATCH_IFRM_ ##	\
			mcdi_field ## _LBN :			 \
		1 << MC_CMD_FILTER_OP_EXT_IN_MATCH_ ##		\
			mcdi_field ## _LBN;			\
		BUILD_BUG_ON(MC_CMD_FILTER_OP_EXT_IN_ ##	\
				mcdi_field ## _LEN <		\
				sizeof(value));			\
		memcpy((encap) ?				\
				MCDI_PTR(inbuf, FILTER_OP_EXT_IN_IFRM_ ## \
					mcdi_field) :		\
				MCDI_PTR(inbuf, FILTER_OP_EXT_IN_ ## \
					mcdi_field),		\
				&(value), sizeof(value));	\
	} while (0)

	/* first handle encapsulation type */
	if (encap_type) {
		__be16 ether_type =
			htons(encap_type & EFX_ENCAP_FLAG_IPV6 ?
			      ETH_P_IPV6 : ETH_P_IP);
		u8 outer_ip_proto; /* needs to be a variable for macro magic */
		/* Field in MCDI is big-endian; but MCDI_POPULATE_DWORD_* will
		 * call cpu_to_le32 on the value.  Thus by feeding it a value
		 * that's "anti-cpu-endian" we ensure that it produces a be32.
		 * We shift right after swabbing, thereby throwing away the old
		 * high byte, and effectively getting a swab24.
		 */
		u32 tni = __swab32(spec->tni) >> 8;
		bool vxlan = false;

		switch (encap_type & EFX_ENCAP_TYPES_MASK) {
		case EFX_ENCAP_TYPE_VXLAN:
			vxlan = true;
			fallthrough;
		case EFX_ENCAP_TYPE_GENEVE:
			COPY_VALUE(false, ether_type, ETHER_TYPE);
			outer_ip_proto = IPPROTO_UDP;
			COPY_VALUE(false, outer_ip_proto, IP_PROTO);
			if (spec->match_flags &
			    EFX_FILTER_MATCH_ENCAP_TNI) {
				match_fields |= 1 <<
					MC_CMD_FILTER_OP_EXT_IN_MATCH_VNI_OR_VSID_LBN;
			}
			/* We always need to set the type field, even if we're
			 * not matching on the TNI.
			 */
			MCDI_POPULATE_DWORD_2(inbuf,
				FILTER_OP_EXT_IN_VNI_OR_VSID,
				FILTER_OP_EXT_IN_VNI_TYPE,
				vxlan ? MC_CMD_FILTER_OP_EXT_IN_VNI_TYPE_VXLAN :
					MC_CMD_FILTER_OP_EXT_IN_VNI_TYPE_GENEVE,
				FILTER_OP_EXT_IN_VNI_VALUE,
				tni);
			break;
		case EFX_ENCAP_TYPE_NVGRE:
			COPY_VALUE(false, ether_type, ETHER_TYPE);
			outer_ip_proto = IPPROTO_GRE;
			COPY_VALUE(false, outer_ip_proto, IP_PROTO);
			if (spec->match_flags &
			    EFX_FILTER_MATCH_ENCAP_TNI) {
				match_fields |= 1 <<
					MC_CMD_FILTER_OP_EXT_IN_MATCH_VNI_OR_VSID_LBN;
				MCDI_POPULATE_DWORD_2(inbuf,
					FILTER_OP_EXT_IN_VNI_OR_VSID,
					FILTER_OP_EXT_IN_VSID_VALUE,
					tni,
					FILTER_OP_EXT_IN_VSID_TYPE,
					MC_CMD_FILTER_OP_EXT_IN_VSID_TYPE_NVGRE);
			}
			break;
		default:
			WARN_ON(1);
		}
		COPY_FIELD(false, OUTER_LOC_MAC, outer_loc_mac, DST_MAC);

		uc_match =
		  MC_CMD_FILTER_OP_EXT_IN_MATCH_IFRM_UNKNOWN_UCAST_DST_LBN;
		mc_match =
		  MC_CMD_FILTER_OP_EXT_IN_MATCH_IFRM_UNKNOWN_MCAST_DST_LBN;
	} else {
		uc_match = MC_CMD_FILTER_OP_EXT_IN_MATCH_UNKNOWN_UCAST_DST_LBN;
		mc_match = MC_CMD_FILTER_OP_EXT_IN_MATCH_UNKNOWN_MCAST_DST_LBN;
	}

	/* special case for mismatch */
	if (spec->match_flags & EFX_FILTER_MATCH_LOC_MAC_IG)
		match_fields |=
			is_multicast_ether_addr(spec->loc_mac) ?
			1 << mc_match :
			1 << uc_match;

	/* VLAN is always outer */
	COPY_FIELD(false, INNER_VID, inner_vid, INNER_VLAN);
	COPY_FIELD(false, OUTER_VID, outer_vid, OUTER_VLAN);
	/* outer MAC only applies if encap */
	if (encap_type)
		COPY_FIELD(false, OUTER_LOC_MAC, outer_loc_mac, DST_MAC);
	/* everything else is inner or outer based on encap type */
	COPY_FIELD(encap_type, REM_HOST, rem_host, SRC_IP);
	COPY_FIELD(encap_type, LOC_HOST, loc_host, DST_IP);
	COPY_FIELD(encap_type, REM_MAC, rem_mac, SRC_MAC);
	COPY_FIELD(encap_type, REM_PORT, rem_port, SRC_PORT);
	COPY_FIELD(encap_type, LOC_MAC, loc_mac, DST_MAC);
	COPY_FIELD(encap_type, LOC_PORT, loc_port, DST_PORT);
	COPY_FIELD(encap_type, ETHER_TYPE, ether_type, ETHER_TYPE);
	COPY_FIELD(encap_type, IP_PROTO, ip_proto, IP_PROTO);
#undef COPY_FIELD
#undef COPY_VALUE
	MCDI_SET_DWORD(inbuf, FILTER_OP_IN_MATCH_FIELDS,
			match_fields);
}

static void efx_mcdi_filter_push_prep(struct efx_nic *efx,
				      const struct efx_filter_spec *spec,
				      efx_dword_t *inbuf, u64 handle,
				      struct efx_rss_context *ctx,
				      const struct efx_vport *vpx,
				      bool replacing)
{
	unsigned int port_id;
	u32 flags = spec->flags;

	/* If RSS filter, caller better have given us an RSS context */
	if (flags & EFX_FILTER_FLAG_RX_RSS) {
		/* We don't have the ability to return an error, so we'll just
		 * log a warning and disable RSS for the filter.
		 */
		if (WARN_ON_ONCE(!ctx))
			flags &= ~EFX_FILTER_FLAG_RX_RSS;
		else if (WARN_ON_ONCE(ctx->context_id == EFX_MCDI_RSS_CONTEXT_INVALID))
			flags &= ~EFX_FILTER_FLAG_RX_RSS;
	}

	memset(inbuf, 0, MC_CMD_FILTER_OP_EXT_IN_LEN);

	if (replacing) {
		MCDI_SET_DWORD(inbuf, FILTER_OP_IN_OP,
			       MC_CMD_FILTER_OP_IN_OP_REPLACE);
		MCDI_SET_QWORD(inbuf, FILTER_OP_IN_HANDLE, handle);
	} else {
		efx_mcdi_filter_push_prep_set_match_fields(efx, spec, inbuf);
	}

	port_id = efx->vport.vport_id;
	if (flags & EFX_FILTER_FLAG_VPORT_ID) {
		/* Again, no ability to return an error.  Caller needs to catch
		 * this case for us, so log a warning if they didn't.
		 */
		if (WARN_ON_ONCE(!vpx))
			flags &= ~EFX_FILTER_FLAG_VPORT_ID;
		else if (WARN_ON_ONCE(vpx->vport_id == EVB_PORT_ID_NULL))
			flags &= ~EFX_FILTER_FLAG_VPORT_ID;
		else
			port_id = vpx->vport_id;
	}
	if (flags & EFX_FILTER_FLAG_STACK_ID)
		port_id |= EVB_STACK_ID(spec->stack_id);
	MCDI_SET_DWORD(inbuf, FILTER_OP_IN_PORT_ID, port_id );
	MCDI_SET_DWORD(inbuf, FILTER_OP_IN_RX_DEST,
		       spec->dmaq_id == EFX_FILTER_RX_DMAQ_ID_DROP ?
		       MC_CMD_FILTER_OP_IN_RX_DEST_DROP :
		       MC_CMD_FILTER_OP_IN_RX_DEST_HOST);

#ifdef EFX_NOT_UPSTREAM
	/* Onload might set this flag to request  hardware multicast loopback */
#endif
	if (spec->flags & EFX_FILTER_FLAG_TX)
		MCDI_POPULATE_DWORD_2(inbuf, FILTER_OP_IN_TX_DEST,
				      FILTER_OP_IN_TX_DEST_MAC, 1,
				      FILTER_OP_IN_TX_DEST_PM, 1);
	else if (spec->flags & EFX_FILTER_FLAG_LOOPBACK)
		MCDI_POPULATE_DWORD_1(inbuf, FILTER_OP_IN_TX_DEST,
				      FILTER_OP_IN_TX_DEST_MAC, 1);
	else
		MCDI_SET_DWORD(inbuf, FILTER_OP_IN_TX_DEST,
			       MC_CMD_FILTER_OP_IN_TX_DEST_DEFAULT);
	MCDI_SET_DWORD(inbuf, FILTER_OP_IN_TX_DOMAIN, 0);

	MCDI_SET_DWORD(inbuf, FILTER_OP_IN_RX_QUEUE,
		       spec->dmaq_id == EFX_FILTER_RX_DMAQ_ID_DROP ? 0 :
		       efx_rx_queue_id_internal(efx, spec->dmaq_id));
	MCDI_SET_DWORD(inbuf, FILTER_OP_IN_RX_MODE,
		       (flags & EFX_FILTER_FLAG_RX_RSS) ?
		       MC_CMD_FILTER_OP_IN_RX_MODE_RSS :
		       MC_CMD_FILTER_OP_IN_RX_MODE_SIMPLE);
	if (flags & EFX_FILTER_FLAG_RX_RSS)
		MCDI_SET_DWORD(inbuf, FILTER_OP_IN_RX_CONTEXT, ctx->context_id);
}

static int efx_mcdi_filter_push(struct efx_nic *efx,
				const struct efx_filter_spec *spec, u64 *handle,
				struct efx_rss_context *ctx,
				const struct efx_vport *vpx, bool replacing)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FILTER_OP_EXT_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_FILTER_OP_EXT_OUT_LEN);
	size_t outlen;
	int rc;

	if (!table->push_filters) {
		*handle = EFX_MCDI_FILTER_ID_INVALID;
		return 0;
	}

	efx_mcdi_filter_push_prep(efx, spec, inbuf, *handle, ctx, vpx, replacing);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_FILTER_OP, inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf), &outlen);
	if (rc && spec->priority != EFX_FILTER_PRI_HINT)
		efx_mcdi_display_error(efx, MC_CMD_FILTER_OP, sizeof(inbuf),
				       outbuf, outlen, rc);
	if (rc == 0)
		*handle = MCDI_QWORD(outbuf, FILTER_OP_OUT_HANDLE);
#ifdef EFX_NOT_UPSTREAM
	/* Returning EBUSY was originally done to match Falcon/Siena behaviour.
	 * This code is also called by Onload, so this is now kept to
	 * keep that ABI the same.
	 */
#endif
	if (rc == -ENOSPC)
		rc = -EBUSY;
	return rc;
}

static u32 efx_mcdi_filter_mcdi_flags_from_spec(const struct efx_filter_spec *spec)
{
	unsigned int match_flags = spec->match_flags;
	u32 mcdi_flags = 0;
	enum efx_encap_type encap_type =
		efx_filter_get_encap_type(spec);
	unsigned uc_match, mc_match;

#define MAP_FILTER_TO_MCDI_FLAG(gen_flag, mcdi_field, encap) {	\
		unsigned int  old_match_flags = match_flags;	\
		match_flags &= ~EFX_FILTER_MATCH_ ## gen_flag;	\
		if (match_flags != old_match_flags)		\
			mcdi_flags |=				\
				(1 << ((encap) ?		\
				       MC_CMD_FILTER_OP_EXT_IN_MATCH_IFRM_ ## \
				       mcdi_field ## _LBN :	\
				       MC_CMD_FILTER_OP_EXT_IN_MATCH_ ## \
				       mcdi_field ## _LBN));	\
	}
	/* inner or outer based on encap type */
	MAP_FILTER_TO_MCDI_FLAG(REM_HOST, SRC_IP, encap_type);
	MAP_FILTER_TO_MCDI_FLAG(LOC_HOST, DST_IP, encap_type);
	MAP_FILTER_TO_MCDI_FLAG(REM_MAC, SRC_MAC, encap_type);
	MAP_FILTER_TO_MCDI_FLAG(REM_PORT, SRC_PORT, encap_type);
	MAP_FILTER_TO_MCDI_FLAG(LOC_MAC, DST_MAC, encap_type);
	MAP_FILTER_TO_MCDI_FLAG(LOC_PORT, DST_PORT, encap_type);
	MAP_FILTER_TO_MCDI_FLAG(ETHER_TYPE, ETHER_TYPE, encap_type);
	MAP_FILTER_TO_MCDI_FLAG(IP_PROTO, IP_PROTO, encap_type);
	/* always outer */
	MAP_FILTER_TO_MCDI_FLAG(INNER_VID, INNER_VLAN, false);
	MAP_FILTER_TO_MCDI_FLAG(OUTER_VID, OUTER_VLAN, false);
#undef MAP_FILTER_TO_MCDI_FLAG
	/* special handling for encap type/tni, and mismatch */
	if (encap_type) {
		if (match_flags & EFX_FILTER_MATCH_ENCAP_TNI) {
			match_flags &= ~EFX_FILTER_MATCH_ENCAP_TNI;
			mcdi_flags |= (1 <<
				MC_CMD_FILTER_OP_EXT_IN_MATCH_VNI_OR_VSID_LBN);
		}
		match_flags &= ~EFX_FILTER_MATCH_ENCAP_TYPE;
		mcdi_flags |=
			(1 << MC_CMD_FILTER_OP_EXT_IN_MATCH_ETHER_TYPE_LBN);
		mcdi_flags |= (1 << MC_CMD_FILTER_OP_EXT_IN_MATCH_IP_PROTO_LBN);

		if (match_flags & EFX_FILTER_MATCH_OUTER_LOC_MAC) {
			match_flags &= ~EFX_FILTER_MATCH_OUTER_LOC_MAC;
			mcdi_flags |= (1 <<
				MC_CMD_FILTER_OP_EXT_IN_MATCH_DST_MAC_LBN);
		}

		uc_match = MC_CMD_FILTER_OP_EXT_IN_MATCH_IFRM_UNKNOWN_UCAST_DST_LBN;
		mc_match = MC_CMD_FILTER_OP_EXT_IN_MATCH_IFRM_UNKNOWN_MCAST_DST_LBN;
	} else {
		uc_match = MC_CMD_FILTER_OP_EXT_IN_MATCH_UNKNOWN_UCAST_DST_LBN;
		mc_match = MC_CMD_FILTER_OP_EXT_IN_MATCH_UNKNOWN_MCAST_DST_LBN;
	}
	if (match_flags & EFX_FILTER_MATCH_LOC_MAC_IG) {
		match_flags &= ~EFX_FILTER_MATCH_LOC_MAC_IG;
		mcdi_flags |=
			is_multicast_ether_addr(spec->loc_mac) ?
			1 << mc_match :
			1 << uc_match;
	}

	/* Did we map them all? */
	WARN_ON(match_flags);

	return mcdi_flags;
}

static int efx_mcdi_filter_pri(struct efx_mcdi_filter_table *table,
			       const struct efx_filter_spec *spec)
{
	u32 mcdi_flags = efx_mcdi_filter_mcdi_flags_from_spec(spec);
	unsigned int match_pri;

	for (match_pri = 0;
	     match_pri < table->rx_match_count;
	     match_pri++)
		if (table->rx_match_mcdi_flags[match_pri] == mcdi_flags)
			return match_pri;

	return -EPROTONOSUPPORT;
}

static int efx_filter_sanity_check(const struct efx_filter_spec *spec)
{
	/* if ipproto or hosts were specified then only allow the supported
	 * ether types
	 */
	if (((spec->match_flags & EFX_FILTER_MATCH_IP_PROTO) ||
	     (spec->match_flags & EFX_FILTER_MATCH_REM_HOST) ||
	     (spec->match_flags & EFX_FILTER_MATCH_LOC_HOST)) &&
	    (!(spec->match_flags & EFX_FILTER_MATCH_ETHER_TYPE) ||
	     ((spec->ether_type != htons(ETH_P_IP) &&
	       spec->ether_type != htons(ETH_P_IPV6)))))
		return -EINVAL;

	/* if ports were specified then only allow the supported ip protos */
	if (((spec->match_flags & EFX_FILTER_MATCH_LOC_PORT) ||
	     (spec->match_flags & EFX_FILTER_MATCH_REM_PORT)) &&
	    (!(spec->match_flags & EFX_FILTER_MATCH_IP_PROTO) ||
	     (spec->ip_proto != IPPROTO_TCP && spec->ip_proto != IPPROTO_UDP)))
		return -EINVAL;

	return 0;
}

static s32 efx_mcdi_filter_insert_locked(struct efx_nic *efx,
					 const struct efx_filter_spec *spec,
					 bool replace_equal)
{
	struct efx_mcdi_filter_table *table;
	DECLARE_BITMAP(mc_rem_map, EFX_MCDI_FILTER_SEARCH_LIMIT);
	struct efx_filter_spec *saved_spec;
	struct efx_rss_context *ctx = NULL;
	unsigned int match_pri, hash;
	struct efx_vport *vpx = NULL;
	bool vport_locked = false;
	unsigned int priv_flags;
	bool rss_locked = false;
	bool replacing = false;
	unsigned int depth, i;
	int ins_index = -1;
	DEFINE_WAIT(wait);
	bool is_mc_recip;
	s32 rc;

	WARN_ON(!rwsem_is_locked(&efx->filter_sem));
	table = efx->filter_state;
	if (!table || !table->entry)
		return -ENETDOWN;
	down_write(&table->lock);

	/* Support only RX or RX+TX filters. */
	if ((spec->flags & EFX_FILTER_FLAG_RX) == 0) {
		rc = -EINVAL;
		goto out_unlock;
	}
	/* TX and loopback are mutually exclusive */
	if ((spec->flags & EFX_FILTER_FLAG_TX) &&
	    (spec->flags & EFX_FILTER_FLAG_LOOPBACK)) {
		rc = -EINVAL;
		goto out_unlock;
	}

	rc = efx_filter_sanity_check(spec);
	if (rc)
		goto out_unlock;

	rc = efx_mcdi_filter_pri(table, spec);
	if (rc < 0)
		goto out_unlock;
	match_pri = rc;

	hash = efx_filter_spec_hash(spec);
	is_mc_recip = efx_filter_is_mc_recipient(spec);
	if (is_mc_recip)
		bitmap_zero(mc_rem_map, EFX_MCDI_FILTER_SEARCH_LIMIT);

	if (spec->flags & EFX_FILTER_FLAG_RX_RSS) {
		mutex_lock(&efx->rss_lock);
		rss_locked = true;
		if (spec->rss_context)
			ctx = efx_find_rss_context_entry(efx, spec->rss_context);
		else
			ctx = &efx->rss_context;
		if (!ctx) {
			rc = -ENOENT;
			goto out_unlock;
		}
		if (ctx->context_id == EFX_MCDI_RSS_CONTEXT_INVALID) {
			rc = -EOPNOTSUPP;
			goto out_unlock;
		}
	}

	if (spec->flags & EFX_FILTER_FLAG_VPORT_ID) {
		mutex_lock(&efx->vport_lock);
		vport_locked = true;
		if (spec->vport_id == 0)
			vpx = &efx->vport;
		else
			vpx = efx_find_vport_entry(efx, spec->vport_id);
		if (!vpx) {
			rc = -ENOENT;
			goto out_unlock;
		}
		if (vpx->vport_id == EVB_PORT_ID_NULL) {
			rc = -EOPNOTSUPP;
			goto out_unlock;
		}
	}

	/* Find any existing filters with the same match tuple or
	 * else a free slot to insert at.
	 */
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (spec->priority <= EFX_FILTER_PRI_AUTO &&
	    table->kernel_blocked[is_mc_recip ?
				  EFX_DL_FILTER_BLOCK_KERNEL_MCAST :
				  EFX_DL_FILTER_BLOCK_KERNEL_UCAST]) {
		rc = -EPERM;
		goto out_unlock;
	}
#endif
#endif

	for (depth = 1; depth < EFX_MCDI_FILTER_SEARCH_LIMIT; depth++) {
		i = (hash + depth) & (EFX_MCDI_FILTER_TBL_ROWS - 1);
		saved_spec = efx_mcdi_filter_entry_spec(table, i);

		if (!saved_spec) {
			if (ins_index < 0)
				ins_index = i;
		} else if (efx_filter_spec_equal(spec, saved_spec)) {
			if (spec->priority < saved_spec->priority &&
			    spec->priority != EFX_FILTER_PRI_AUTO) {
				rc = -EPERM;
				goto out_unlock;
			}
			if (!is_mc_recip) {
				/* This is the only one */
				if (spec->priority ==
				    saved_spec->priority &&
				    !replace_equal) {
					rc = -EEXIST;
					goto out_unlock;
				}
				ins_index = i;
				break;
			} else if (spec->priority >
				   saved_spec->priority ||
				   (spec->priority ==
				    saved_spec->priority &&
				    replace_equal) ||
				   spec->priority ==
					EFX_FILTER_PRI_AUTO) {
				if (ins_index < 0)
					ins_index = i;
				else
					__set_bit(depth, mc_rem_map);
			}
		}
	}

	/* Once we reach the maximum search depth, use the first suitable
	 * slot, or return -EBUSY if there was none
	 */
	if (ins_index < 0) {
		rc = -EBUSY;
		goto out_unlock;
	}

	/* Create a software table entry if necessary. */
	saved_spec = efx_mcdi_filter_entry_spec(table, ins_index);
	if (saved_spec) {
		if (spec->priority == EFX_FILTER_PRI_AUTO &&
		    saved_spec->priority >= EFX_FILTER_PRI_AUTO) {
			/* Just make sure it won't be removed */
			if (saved_spec->priority > EFX_FILTER_PRI_AUTO)
				saved_spec->flags |= EFX_FILTER_FLAG_RX_OVER_AUTO;
			table->entry[ins_index].spec &=
				~EFX_MCDI_FILTER_FLAG_AUTO_OLD;
			rc = ins_index;
			goto out_unlock;
		}
		replacing = true;
		priv_flags = efx_mcdi_filter_entry_flags(table, ins_index);
	} else {
		saved_spec = kmalloc(sizeof(*spec), GFP_ATOMIC);
		if (!saved_spec) {
			rc = -ENOMEM;
			goto out_unlock;
		}
		*saved_spec = *spec;
		priv_flags = 0;
	}
	efx_mcdi_filter_set_entry(table, ins_index, saved_spec, priv_flags);

	/* Actually insert the filter on the HW */
	rc = efx_mcdi_filter_push(efx, spec, &table->entry[ins_index].handle,
				  ctx, vpx, replacing);

	/* Finalise the software table entry */
	if (rc == 0) {
		if (replacing) {
			/* Update the fields that may differ */
			if (saved_spec->priority == EFX_FILTER_PRI_AUTO)
				saved_spec->flags |=
					EFX_FILTER_FLAG_RX_OVER_AUTO;
			saved_spec->priority = spec->priority;
			saved_spec->flags &= EFX_FILTER_FLAG_RX_OVER_AUTO;
			saved_spec->flags |= spec->flags;
			saved_spec->rss_context = spec->rss_context;
			saved_spec->dmaq_id = spec->dmaq_id;
			saved_spec->stack_id = spec->stack_id;
			saved_spec->vport_id = spec->vport_id;
		}
	} else if (!replacing) {
		kfree(saved_spec);
		saved_spec = NULL;
	} else {
		/* We failed to replace, so the old filter is still present.
		 * Roll back the software table to reflect this.  In fact the
		 * efx_mcdi_filter_set_entry() call below will do the right
		 * thing, so nothing extra is needed here.
		 */
	}
	efx_mcdi_filter_set_entry(table, ins_index, saved_spec, priv_flags);

	/* Remove and finalise entries for lower-priority multicast
	 * recipients
	 */
	if (is_mc_recip) {
		MCDI_DECLARE_BUF(inbuf, MC_CMD_FILTER_OP_EXT_IN_LEN);
		unsigned int depth, i;

		memset(inbuf, 0, sizeof(inbuf));

		for (depth = 0; depth < EFX_MCDI_FILTER_SEARCH_LIMIT; depth++) {
			if (!test_bit(depth, mc_rem_map))
				continue;

			i = (hash + depth) & (EFX_MCDI_FILTER_TBL_ROWS - 1);
			saved_spec = efx_mcdi_filter_entry_spec(table, i);
			priv_flags = efx_mcdi_filter_entry_flags(table, i);

			if (rc == 0) {
				MCDI_SET_DWORD(inbuf, FILTER_OP_IN_OP,
					       MC_CMD_FILTER_OP_IN_OP_UNSUBSCRIBE);
				MCDI_SET_QWORD(inbuf, FILTER_OP_IN_HANDLE,
					       table->entry[i].handle);
				rc = efx_mcdi_rpc(efx, MC_CMD_FILTER_OP,
						  inbuf, sizeof(inbuf),
						  NULL, 0, NULL);
			}

			if (rc == 0) {
				table->entry[i].handle =
					EFX_MCDI_FILTER_ID_INVALID;
				kfree(saved_spec);
				saved_spec = NULL;
				priv_flags = 0;
			}
			efx_mcdi_filter_set_entry(table, i, saved_spec,
						  priv_flags);
		}
	}

	/* If successful, return the inserted filter ID */
	if (rc == 0)
		rc = efx_mcdi_filter_make_filter_id(match_pri, ins_index);

out_unlock:
	if (vport_locked)
		mutex_unlock(&efx->vport_lock);
	if (rss_locked)
		mutex_unlock(&efx->rss_lock);
	up_write(&table->lock);
	return rc;
}

s32 efx_mcdi_filter_insert(struct efx_nic *efx,
			   const struct efx_filter_spec *spec,
			   bool replace_equal)
{
	s32 ret;

	down_read(&efx->filter_sem);
	ret = efx_mcdi_filter_insert_locked(efx, spec, replace_equal);
	up_read(&efx->filter_sem);

	return ret;
}

/* Remove a filter.
 * If !by_index, remove by ID
 * If by_index, remove by index
 * Filter ID may come from userland and must be range-checked.
 * Caller must hold efx->filter_sem for read, and efx->filter_state->lock
 * for write.
 */
static int efx_mcdi_filter_remove_internal(struct efx_nic *efx,
					   unsigned int priority_mask,
					   u32 filter_id, bool by_index)
{
	unsigned int filter_idx = efx_mcdi_filter_get_unsafe_id(efx, filter_id);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FILTER_OP_IN_LEN);
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct efx_filter_spec *spec;
	DEFINE_WAIT(wait);
	int rc = 0;

	if (!table || !table->entry)
		return -ENOENT;

	spec = efx_mcdi_filter_entry_spec(table, filter_idx);
	if (!spec ||
	    (!by_index &&
	     efx_mcdi_filter_pri(table, spec) !=
	     efx_mcdi_filter_get_unsafe_pri(filter_id)))
		return -ENOENT;

	if (spec->flags & EFX_FILTER_FLAG_RX_OVER_AUTO &&
	    priority_mask == (1U << EFX_FILTER_PRI_AUTO)) {
		/* Just remove flags */
		spec->flags &= ~EFX_FILTER_FLAG_RX_OVER_AUTO;
		table->entry[filter_idx].spec &= ~EFX_MCDI_FILTER_FLAG_AUTO_OLD;
		return 0;
	}

	if (!(priority_mask & (1U << spec->priority)))
		return -ENOENT;

	if (spec->flags & EFX_FILTER_FLAG_RX_OVER_AUTO) {
		/* Reset to an automatic filter */

		struct efx_filter_spec new_spec = *spec;

		new_spec.priority = EFX_FILTER_PRI_AUTO;
		new_spec.flags = (EFX_FILTER_FLAG_RX |
			(efx_rss_active(&efx->rss_context) ?
			 EFX_FILTER_FLAG_RX_RSS : 0));
		new_spec.dmaq_id = 0;
		new_spec.rss_context = 0;
		new_spec.vport_id = 0;
		new_spec.stack_id = 0;

		rc = efx_mcdi_filter_push(efx, &new_spec,
					  &table->entry[filter_idx].handle,
					  &efx->rss_context, &efx->vport,
					  true);

		if (rc == 0)
			*spec = new_spec;
	} else {
		/* Really remove the filter */

		MCDI_SET_DWORD(inbuf, FILTER_OP_IN_OP,
			       efx_mcdi_filter_is_exclusive(spec) ?
			       MC_CMD_FILTER_OP_IN_OP_REMOVE :
			       MC_CMD_FILTER_OP_IN_OP_UNSUBSCRIBE);
		MCDI_SET_QWORD(inbuf, FILTER_OP_IN_HANDLE,
			       table->entry[filter_idx].handle);
		if (table->push_filters)
			rc = efx_mcdi_rpc_quiet(efx, MC_CMD_FILTER_OP,
						inbuf, sizeof(inbuf), NULL, 0,
						NULL);

		if ((rc == 0) || (rc == -ENOENT) || (rc == -EIO) ||
		    (efx->reset_pending)) {
			/* Filter removed OK, it didn't actually exist, or
			 * the MC is resetting.
			 */
			kfree(spec);
			efx_mcdi_filter_set_entry(table, filter_idx, NULL, 0);
			table->entry[filter_idx].handle =
				EFX_MCDI_FILTER_ID_INVALID;
		} else {
			efx_mcdi_display_error(efx, MC_CMD_FILTER_OP,
					MC_CMD_FILTER_OP_IN_LEN, NULL, 0, rc);
		}
	}

	return rc;
}

int efx_mcdi_filter_remove_safe(struct efx_nic *efx,
				enum efx_filter_priority priority,
				u32 filter_id)
{
	struct efx_mcdi_filter_table *table;
	int rc;

	down_read(&efx->filter_sem);
	table = efx->filter_state;
	if (table) {
		down_write(&table->lock);
		rc = efx_mcdi_filter_remove_internal(efx, 1U << priority,
						     filter_id, false);
		up_write(&table->lock);
	} else {
		rc = -ENETDOWN;
	}
	up_read(&efx->filter_sem);
	return rc;
}

/* Caller must hold efx->filter_sem for read */
static int efx_mcdi_filter_remove_unsafe(struct efx_nic *efx,
					 enum efx_filter_priority priority,
					 u32 filter_id)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	int rc;

	down_write(&table->lock);
	rc = efx_mcdi_filter_remove_internal(efx, 1U << priority, filter_id,
					     true);
	up_write(&table->lock);
	return rc;
}

int efx_mcdi_filter_get_safe(struct efx_nic *efx,
			     enum efx_filter_priority priority,
			     u32 filter_id, struct efx_filter_spec *spec)
{
	unsigned int filter_idx = efx_mcdi_filter_get_unsafe_id(efx, filter_id);
	struct efx_mcdi_filter_table *table;
	const struct efx_filter_spec *saved_spec;
	int rc;

	down_read(&efx->filter_sem);
	table = efx->filter_state;
	if (!table || !table->entry) {
		up_read(&efx->filter_sem);
		return -ENETDOWN;
	}

	down_read(&table->lock);
	saved_spec = efx_mcdi_filter_entry_spec(table, filter_idx);
	if (saved_spec && saved_spec->priority == priority &&
	    efx_mcdi_filter_pri(table, saved_spec) ==
	    efx_mcdi_filter_get_unsafe_pri(filter_id)) {
		*spec = *saved_spec;
		rc = 0;
	} else {
		rc = -ENOENT;
	}
	up_read(&table->lock);
	up_read(&efx->filter_sem);
	return rc;
}

static int efx_mcdi_filter_insert_addr_list(struct efx_nic *efx,
					    struct efx_mcdi_filter_vlan *vlan,
					    bool multicast, bool rollback)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct efx_mcdi_dev_addr *addr_list;
	u16 *ids;
	enum efx_filter_flags filter_flags;
	struct efx_filter_spec spec;
	u8 baddr[ETH_ALEN];
	unsigned int i, j;
	int addr_count;
	int rc;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	if (multicast) {
		addr_list = table->dev_mc_list;
		addr_count = table->dev_mc_count;
		ids = vlan->mc;
	} else {
		addr_list = table->dev_uc_list;
		addr_count = table->dev_uc_count;
		ids = vlan->uc;
	}

	filter_flags = efx_rss_active(&efx->rss_context) ?
		       EFX_FILTER_FLAG_RX_RSS : 0;

	/* Insert/renew filters */
	for (i = 0; i < addr_count; i++) {
		EFX_WARN_ON_PARANOID(ids[i] != EFX_MCDI_FILTER_ID_INVALID);
		efx_filter_init_rx(&spec, EFX_FILTER_PRI_AUTO, filter_flags, 0);
		efx_filter_set_eth_local(&spec, vlan->vid, addr_list[i].addr);
		rc = efx_mcdi_filter_insert_locked(efx, &spec, true);
		if (rc < 0) {
			if (rollback) {
				netif_info(efx, drv, efx->net_dev,
					   "efx_mcdi_filter_insert failed rc=%d\n",
					   rc);
				/* Fall back to promiscuous */
				for (j = 0; j < i; j++) {
					if (ids[j] == EFX_MCDI_FILTER_ID_INVALID)
						continue;
					efx_mcdi_filter_remove_unsafe(
						efx, EFX_FILTER_PRI_AUTO,
						ids[j]);
					ids[j] = EFX_MCDI_FILTER_ID_INVALID;
				}
				return rc;
			}
			/* Keep invalid ID and continue */
		} else {
			ids[i] = efx_mcdi_filter_get_unsafe_id(efx, rc);
		}
	}

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (!table->kernel_blocked[EFX_DL_FILTER_BLOCK_KERNEL_MCAST])
#endif
#endif
	if (multicast && rollback) {
		/* Also need an Ethernet broadcast filter */
		EFX_WARN_ON_PARANOID(vlan->default_filters[EFX_MCDI_BCAST] !=
				    EFX_MCDI_FILTER_ID_INVALID);
		efx_filter_init_rx(&spec, EFX_FILTER_PRI_AUTO, filter_flags, 0);
		eth_broadcast_addr(baddr);
		efx_filter_set_eth_local(&spec, vlan->vid, baddr);
		rc = efx_mcdi_filter_insert_locked(efx, &spec, true);
		if (rc < 0) {
			netif_warn(efx, drv, efx->net_dev,
				   "Broadcast filter insert failed rc=%d\n", rc);
			/* Fall back to promiscuous */
			for (j = 0; j < i; j++) {
				if (ids[j] == EFX_MCDI_FILTER_ID_INVALID)
					continue;
				efx_mcdi_filter_remove_unsafe(
					efx, EFX_FILTER_PRI_AUTO,
					ids[j]);
				ids[j] = EFX_MCDI_FILTER_ID_INVALID;
			}
			return rc;
		} else {
			vlan->default_filters[EFX_MCDI_BCAST] =
				efx_mcdi_filter_get_unsafe_id(efx, rc);
		}
	}

	return 0;
}

static int efx_mcdi_filter_insert_def(struct efx_nic *efx,
				      struct efx_mcdi_filter_vlan *vlan,
				      enum efx_encap_type encap_type,
				      bool multicast, bool rollback)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	enum efx_filter_flags filter_flags;
	struct efx_filter_spec spec;
	u8 baddr[ETH_ALEN];
	int rc;
	u16 *id;

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (table->kernel_blocked[multicast ? EFX_DL_FILTER_BLOCK_KERNEL_MCAST :
					      EFX_DL_FILTER_BLOCK_KERNEL_UCAST])
		return 0;
#endif
#endif

	filter_flags = efx_rss_active(&efx->rss_context) ?
		       EFX_FILTER_FLAG_RX_RSS : 0;

	efx_filter_init_rx(&spec, EFX_FILTER_PRI_AUTO, filter_flags, 0);

	if (multicast)
		efx_filter_set_mc_def(&spec);
	else
		efx_filter_set_uc_def(&spec);

	if (encap_type) {
		if (table->encap_supported)
			efx_filter_set_encap_type(&spec, encap_type);
		else
			/* don't insert encap filters on non-supporting
			 * platforms. ID will be left as INVALID.
			 */
			return 0;
	}

	if (vlan->vid != EFX_FILTER_VID_UNSPEC)
		efx_filter_set_eth_local(&spec, vlan->vid, NULL);

	rc = efx_mcdi_filter_insert_locked(efx, &spec, true);
	if (rc < 0) {
		const char *um = multicast ? "Multicast" : "Unicast";
		const char *encap_name = "";
		const char *encap_ipv = "";

		if ((encap_type & EFX_ENCAP_TYPES_MASK) ==
		    EFX_ENCAP_TYPE_VXLAN)
			encap_name = "VXLAN ";
		else if ((encap_type & EFX_ENCAP_TYPES_MASK) ==
			 EFX_ENCAP_TYPE_NVGRE)
			encap_name = "NVGRE ";
		else if ((encap_type & EFX_ENCAP_TYPES_MASK) ==
			 EFX_ENCAP_TYPE_GENEVE)
			encap_name = "GENEVE ";
		if (encap_type & EFX_ENCAP_FLAG_IPV6)
			encap_ipv = "IPv6 ";
		else if (encap_type)
			encap_ipv = "IPv4 ";

		/* unprivileged functions can't insert mismatch filters
		 * for encapsulated or unicast traffic, so downgrade
		 * those warnings to debug.
		 */
		netif_cond_dbg(efx, drv, efx->net_dev,
			       rc == -EPERM && (encap_type || !multicast), warn,
			       "%s%s%s mismatch filter insert failed rc=%d\n",
			       encap_name, encap_ipv, um, rc);
	} else if (multicast) {
		/* mapping from encap types to default filter IDs (multicast) */
		static enum efx_mcdi_filter_default_filters map[] = {
			[EFX_ENCAP_TYPE_NONE] = EFX_MCDI_MCDEF,
			[EFX_ENCAP_TYPE_VXLAN] = EFX_MCDI_VXLAN4_MCDEF,
			[EFX_ENCAP_TYPE_NVGRE] = EFX_MCDI_NVGRE4_MCDEF,
			[EFX_ENCAP_TYPE_GENEVE] = EFX_MCDI_GENEVE4_MCDEF,
			[EFX_ENCAP_TYPE_VXLAN | EFX_ENCAP_FLAG_IPV6] =
				EFX_MCDI_VXLAN6_MCDEF,
			[EFX_ENCAP_TYPE_NVGRE | EFX_ENCAP_FLAG_IPV6] =
				EFX_MCDI_NVGRE6_MCDEF,
			[EFX_ENCAP_TYPE_GENEVE | EFX_ENCAP_FLAG_IPV6] =
				EFX_MCDI_GENEVE6_MCDEF,
		};

		/* quick bounds check (BCAST result impossible) */
		BUILD_BUG_ON(EFX_MCDI_BCAST != 0);
		if (encap_type >= ARRAY_SIZE(map) || map[encap_type] == 0) {
			WARN_ON(1);
			return -EINVAL;
		}
		/* then follow map */
		id = &vlan->default_filters[map[encap_type]];

		EFX_WARN_ON_PARANOID(*id != EFX_MCDI_FILTER_ID_INVALID);
		*id = efx_mcdi_filter_get_unsafe_id(efx, rc);
		if (!table->mc_chaining && !encap_type) {
			/* Also need an Ethernet broadcast filter */
			efx_filter_init_rx(&spec, EFX_FILTER_PRI_AUTO,
					   filter_flags, 0);
			eth_broadcast_addr(baddr);
			efx_filter_set_eth_local(&spec, vlan->vid, baddr);
			rc = efx_mcdi_filter_insert_locked(efx, &spec, true);
			if (rc < 0) {
				netif_warn(efx, drv, efx->net_dev,
					   "Broadcast filter insert failed rc=%d\n",
					   rc);
				if (rollback) {
					/* Roll back the mc_def filter */
					efx_mcdi_filter_remove_unsafe(
							efx, EFX_FILTER_PRI_AUTO,
							*id);
					*id = EFX_MCDI_FILTER_ID_INVALID;
					return rc;
				}
			} else {
				EFX_WARN_ON_PARANOID(
					vlan->default_filters[EFX_MCDI_BCAST] !=
					EFX_MCDI_FILTER_ID_INVALID);
				vlan->default_filters[EFX_MCDI_BCAST] =
					efx_mcdi_filter_get_unsafe_id(efx, rc);
			}
		}
		rc = 0;
	} else {
		/* mapping from encap types to default filter IDs (unicast) */
		static enum efx_mcdi_filter_default_filters map[] = {
			[EFX_ENCAP_TYPE_NONE] = EFX_MCDI_UCDEF,
			[EFX_ENCAP_TYPE_VXLAN] = EFX_MCDI_VXLAN4_UCDEF,
			[EFX_ENCAP_TYPE_NVGRE] = EFX_MCDI_NVGRE4_UCDEF,
			[EFX_ENCAP_TYPE_GENEVE] = EFX_MCDI_GENEVE4_UCDEF,
			[EFX_ENCAP_TYPE_VXLAN | EFX_ENCAP_FLAG_IPV6] =
				EFX_MCDI_VXLAN6_UCDEF,
			[EFX_ENCAP_TYPE_NVGRE | EFX_ENCAP_FLAG_IPV6] =
				EFX_MCDI_NVGRE6_UCDEF,
			[EFX_ENCAP_TYPE_GENEVE | EFX_ENCAP_FLAG_IPV6] =
				EFX_MCDI_GENEVE6_UCDEF,
		};

		/* quick bounds check (BCAST result impossible) */
		BUILD_BUG_ON(EFX_MCDI_BCAST != 0);
		if (encap_type >= ARRAY_SIZE(map) || map[encap_type] == 0) {
			WARN_ON(1);
			return -EINVAL;
		}
		/* then follow map */
		id = &vlan->default_filters[map[encap_type]];
		EFX_WARN_ON_PARANOID(*id != EFX_MCDI_FILTER_ID_INVALID);
		*id = rc;
		rc = 0;
	}
	return rc;
}

/* Caller must hold efx->filter_sem for read if race against
 * efx_mcdi_filter_table_down() is possible
 */
static void efx_mcdi_filter_vlan_sync_rx_mode(struct efx_nic *efx,
					      struct efx_mcdi_filter_vlan *vlan)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	unsigned int n_filters;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	/* Do not install unspecified VID if VLAN filtering is enabled.
	 * Do not install all specified VIDs if VLAN filtering is disabled.
	 */
	if ((vlan->vid == EFX_FILTER_VID_UNSPEC) == table->vlan_filter)
		return;

	/* Insert/renew unicast filters */
	if (table->uc_promisc) {
		efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_NONE,
					   false, false);
		efx_mcdi_filter_insert_addr_list(efx, vlan, false, false);
	} else {
		/* If any of the filters failed to insert, fall back to
		 * promiscuous mode - add in the uc_def filter.  But keep
		 * our individual unicast filters.
		 */
		if (efx_mcdi_filter_insert_addr_list(efx, vlan, false, false))
			efx_mcdi_filter_insert_def(efx, vlan,
						   EFX_ENCAP_TYPE_NONE,
						   false, false);
	}
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_VXLAN,
				   false, false);
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_VXLAN |
					      EFX_ENCAP_FLAG_IPV6,
				   false, false);
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_NVGRE,
				   false, false);
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_NVGRE |
					      EFX_ENCAP_FLAG_IPV6,
				   false, false);
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_GENEVE,
				   false, false);
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_GENEVE |
					      EFX_ENCAP_FLAG_IPV6,
				   false, false);

	/* Insert/renew multicast filters */
	/* If changing promiscuous state with cascaded multicast filters, remove
	 * old filters first, so that packets are dropped rather than duplicated
	 */
	if (table->mc_chaining &&
	    table->mc_promisc_last != table->mc_promisc)
		efx_mcdi_filter_remove_old(efx);
	if (table->mc_promisc) {
		if (table->mc_chaining)
		{
			/* If we failed to insert promiscuous filters, rollback and
			 * fall back to individual multicast filters
			 */
			if (efx_mcdi_filter_insert_def(efx, vlan,
						       EFX_ENCAP_TYPE_NONE,
						       true, true)) {
				/* Changing promisc state, so remove old filters */
				efx_mcdi_filter_remove_old(efx);
				efx_mcdi_filter_insert_addr_list(efx, vlan,
								 true, false);
			}
		} else {
			/* If we failed to insert promiscuous filters, don't
			 * rollback.  Regardless, also insert the mc_list,
			 * unless it's incomplete due to overflow
			 */
			efx_mcdi_filter_insert_def(efx, vlan,
						   EFX_ENCAP_TYPE_NONE,
						   true, false);
			if (!table->mc_overflow)
				efx_mcdi_filter_insert_addr_list(efx, vlan,
								 true, false);
		}
	} else {
		/* If any filters failed to insert, rollback and fall back to
		 * promiscuous mode - mc_def filter and maybe broadcast.  If
		 * that fails, roll back again and insert as many of our
		 * individual multicast filters as we can.
		 */
		if (efx_mcdi_filter_insert_addr_list(efx, vlan, true, true)) {
			/* Changing promisc state, so remove old filters */
			if (table->mc_chaining)
				efx_mcdi_filter_remove_old(efx);
			if (efx_mcdi_filter_insert_def(efx, vlan,
						       EFX_ENCAP_TYPE_NONE,
						       true, true))
				efx_mcdi_filter_insert_addr_list(efx, vlan,
								 true, false);
		}
	}
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_VXLAN,
				   true, false);
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_VXLAN |
					      EFX_ENCAP_FLAG_IPV6,
				   true, false);
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_NVGRE,
				   true, false);
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_NVGRE |
					      EFX_ENCAP_FLAG_IPV6,
				   true, false);
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_GENEVE,
				   true, false);
	efx_mcdi_filter_insert_def(efx, vlan, EFX_ENCAP_TYPE_GENEVE |
					      EFX_ENCAP_FLAG_IPV6,
				   true, false);

	n_filters = efx_mcdi_filter_vlan_count_filters(efx, vlan);
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_DRIVERLINK)
	if (n_filters == 0 && vlan->warn_on_zero_filters &&
	    !(table->kernel_blocked[EFX_DL_FILTER_BLOCK_KERNEL_UCAST] &&
	      table->kernel_blocked[EFX_DL_FILTER_BLOCK_KERNEL_MCAST])) {
#else
	if (n_filters == 0 && vlan->warn_on_zero_filters) {
#endif
		netif_warn(efx, drv, efx->net_dev,
			   "Cannot install VLAN %u filters\n",
			   vlan->vid);
		netif_warn(efx, drv, efx->net_dev,
			   "Maybe it is denied by hypervisor or network access control\n");
		vlan->warn_on_zero_filters = false;
	} else if (n_filters != 0 && !vlan->warn_on_zero_filters) {
		netif_warn(efx, drv, efx->net_dev,
			   "VLAN %u is now allowed\n",
			   vlan->vid);
		vlan->warn_on_zero_filters = true;
	}
}

int efx_mcdi_filter_clear_rx(struct efx_nic *efx,
			     enum efx_filter_priority priority)
{
	struct efx_mcdi_filter_table *table;
	unsigned int priority_mask;
	unsigned int i;
	int rc = -ENETDOWN;

	priority_mask = (((1U << (priority + 1)) - 1) &
			 ~(1U << EFX_FILTER_PRI_AUTO));

	down_read(&efx->filter_sem);
	table = efx->filter_state;
	down_write(&table->lock);

	for (i = 0; i < EFX_MCDI_FILTER_TBL_ROWS; i++) {
		rc = efx_mcdi_filter_remove_internal(efx, priority_mask,
						     i, true);
		if (rc && rc != -ENOENT)
			break;
		rc = 0;
	}

	up_write(&table->lock);
	up_read(&efx->filter_sem);
	return rc;
}

#ifdef EFX_NOT_UPSTREAM
int efx_mcdi_filter_redirect(struct efx_nic *efx, u32 filter_id,
			     u32 *rss_context, int rxq_i, int stack_id)
{
	struct efx_mcdi_filter_table *table;
	struct efx_filter_spec *spec, new_spec;
	struct efx_rss_context *ctx;
	struct efx_vport *vpx;
	unsigned int filter_idx = efx_mcdi_filter_get_unsafe_id(efx, filter_id);
	DEFINE_WAIT(wait);
	int rc;

	down_read(&efx->filter_sem);
	table = efx->filter_state;
	if (!table || !table->entry) {
		rc = -ENETDOWN;
		goto out;
	}
	down_write(&table->lock);
	/* We only need the RSS lock if this is an RSS filter, but let's just
	 * take it anyway for simplicity's sake.  Same goes for the vport lock.
	 */
	mutex_lock(&efx->rss_lock);
	mutex_lock(&efx->vport_lock);
	spec = efx_mcdi_filter_entry_spec(table, filter_idx);
	if (!spec) {
		rc = -ENOENT;
		netdev_WARN(efx->net_dev,
			    "invalid filter_id: filter_id=%#x rxq_i=%u\n",
			    filter_id, rxq_i);
		goto out_unlock;
	}

	/* Try to redirect */
	new_spec = *spec;
	new_spec.dmaq_id = rxq_i;
	new_spec.stack_id = stack_id;
	if (rss_context) {
		new_spec.rss_context = *rss_context;
		new_spec.flags |= EFX_FILTER_FLAG_RX_RSS;
	} else {
		new_spec.flags &= ~EFX_FILTER_FLAG_RX_RSS;
	}
	if (new_spec.rss_context)
		ctx = efx_find_rss_context_entry(efx, new_spec.rss_context);
	else
		ctx = &efx->rss_context;
	if (new_spec.flags & EFX_FILTER_FLAG_RX_RSS) {
		if (!ctx) {
			rc = -ENOENT;
			netdev_WARN(efx->net_dev,
				    "invalid rss_context %u: filter_id=%#x rxq_i=%u\n",
				    new_spec.rss_context, filter_id, rxq_i);
			goto out_unlock;
		}
		if (ctx->context_id == EFX_MCDI_RSS_CONTEXT_INVALID) {
			rc = -EOPNOTSUPP;
			goto out_check;
		}
	}
	if (new_spec.vport_id)
		vpx = efx_find_vport_entry(efx, new_spec.vport_id);
	else
		vpx = &efx->vport;
	if (new_spec.flags & EFX_FILTER_FLAG_VPORT_ID) {
		if (!vpx) {
			rc = -ENOENT;
			netdev_WARN(efx->net_dev,
				    "invalid vport %u: filter_id=%#x rxq_i=%u\n",
				    new_spec.vport_id, filter_id, rxq_i);
			goto out_unlock;
		}
		if (vpx->vport_id == EVB_PORT_ID_NULL) {
			rc = -EOPNOTSUPP;
			goto out_check;
		}
	}
	rc = efx_mcdi_filter_push(efx, &new_spec,
				  &table->entry[filter_idx].handle, ctx, vpx,
				  true);
out_check:
	if (rc && (rc != -ENETDOWN))
		netdev_WARN(efx->net_dev,
			    "failed to update filter: filter_id=%#x "
			    "filter_flags = %#x rxq_i=%u "
			    "stack_id = %d rc=%d \n",
			    filter_id, spec->flags, rxq_i,
			    new_spec.stack_id, rc);
	if (!rc)
		*spec = new_spec;
out_unlock:
	mutex_unlock(&efx->vport_lock);
	mutex_unlock(&efx->rss_lock);
	up_write(&table->lock);
out:
	up_read(&efx->filter_sem);
	return rc;
}
#endif /* EFX_NOT_UPSTREAM */

u32 efx_mcdi_filter_count_rx_used(struct efx_nic *efx,
				  enum efx_filter_priority priority)
{
	struct efx_mcdi_filter_table *table;
	struct efx_filter_spec *spec;
	unsigned int filter_idx;
	s32 count = 0;

	down_read(&efx->filter_sem);
	table = efx->filter_state;
	if (!table || !table->entry) {
		up_read(&efx->filter_sem);
		return -ENETDOWN;
	}

	down_read(&table->lock);

	for (filter_idx = 0;
	     filter_idx < EFX_MCDI_FILTER_TBL_ROWS;
	     filter_idx++) {
		spec = efx_mcdi_filter_entry_spec(table, filter_idx);

		if (spec && spec->priority == priority)
			++count;
	}
	up_read(&table->lock);
	up_read(&efx->filter_sem);
	return count;
}

u32 efx_mcdi_filter_get_rx_id_limit(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;

	return table->rx_match_count * EFX_MCDI_FILTER_TBL_ROWS * 2;
}

s32 efx_mcdi_filter_get_rx_ids(struct efx_nic *efx,
			       enum efx_filter_priority priority,
			       u32 *buf, u32 size)
{
	struct efx_mcdi_filter_table *table;
	struct efx_filter_spec *spec;
	unsigned int filter_idx;
	s32 count = 0;

	down_read(&efx->filter_sem);
	table = efx->filter_state;
	if (!table || !table->entry) {
		up_read(&efx->filter_sem);
		return -ENETDOWN;
	}
	down_read(&table->lock);

	for (filter_idx = 0;
	     filter_idx < EFX_MCDI_FILTER_TBL_ROWS;
	     filter_idx++) {
		spec = efx_mcdi_filter_entry_spec(table, filter_idx);
		if (spec && spec->priority == priority) {
			if (count == size) {
				count = -EMSGSIZE;
				break;
			}
			buf[count++] =
				efx_mcdi_filter_make_filter_id(
					efx_mcdi_filter_pri(table,
							    spec),
					filter_idx);
		}
	}
	up_read(&table->lock);
	up_read(&efx->filter_sem);
	return count;
}

static int efx_mcdi_filter_match_flags_from_mcdi(bool encap, u32 mcdi_flags)
{
	int match_flags = 0;

#define MAP_FLAG(gen_flag, mcdi_field) do {				\
		u32 old_mcdi_flags = mcdi_flags;			\
		mcdi_flags &= ~(1 << MC_CMD_FILTER_OP_EXT_IN_MATCH_ ##  \
				     mcdi_field ## _LBN);		\
		if (mcdi_flags != old_mcdi_flags)			\
			match_flags |= EFX_FILTER_MATCH_ ## gen_flag;	\
	} while (0)

	if (encap) {
		/* encap filters must specify encap type */
		match_flags |= EFX_FILTER_MATCH_ENCAP_TYPE;
		/* and imply ethertype and ip proto */
		mcdi_flags &=
			~(1 << MC_CMD_FILTER_OP_EXT_IN_MATCH_IP_PROTO_LBN);
		mcdi_flags &=
			~(1 << MC_CMD_FILTER_OP_EXT_IN_MATCH_ETHER_TYPE_LBN);
		/* VNI/VSID, VLAN and outer MAC refer to the outer packet */
		MAP_FLAG(ENCAP_TNI, VNI_OR_VSID);
		MAP_FLAG(INNER_VID, INNER_VLAN);
		MAP_FLAG(OUTER_VID, OUTER_VLAN);
		MAP_FLAG(OUTER_LOC_MAC, DST_MAC);
		/* everything else refers to the inner packet */
		MAP_FLAG(LOC_MAC_IG, IFRM_UNKNOWN_UCAST_DST);
		MAP_FLAG(LOC_MAC_IG, IFRM_UNKNOWN_MCAST_DST);
		MAP_FLAG(REM_HOST, IFRM_SRC_IP);
		MAP_FLAG(LOC_HOST, IFRM_DST_IP);
		MAP_FLAG(REM_MAC, IFRM_SRC_MAC);
		MAP_FLAG(REM_PORT, IFRM_SRC_PORT);
		MAP_FLAG(LOC_MAC, IFRM_DST_MAC);
		MAP_FLAG(LOC_PORT, IFRM_DST_PORT);
		MAP_FLAG(ETHER_TYPE, IFRM_ETHER_TYPE);
		MAP_FLAG(IP_PROTO, IFRM_IP_PROTO);
	} else {
		MAP_FLAG(LOC_MAC_IG, UNKNOWN_UCAST_DST);
		MAP_FLAG(LOC_MAC_IG, UNKNOWN_MCAST_DST);
		MAP_FLAG(REM_HOST, SRC_IP);
		MAP_FLAG(LOC_HOST, DST_IP);
		MAP_FLAG(REM_MAC, SRC_MAC);
		MAP_FLAG(REM_PORT, SRC_PORT);
		MAP_FLAG(LOC_MAC, DST_MAC);
		MAP_FLAG(LOC_PORT, DST_PORT);
		MAP_FLAG(ETHER_TYPE, ETHER_TYPE);
		MAP_FLAG(INNER_VID, INNER_VLAN);
		MAP_FLAG(OUTER_VID, OUTER_VLAN);
		MAP_FLAG(IP_PROTO, IP_PROTO);
	}
#undef MAP_FLAG

	/* Did we map them all? */
	if (mcdi_flags)
		return -EINVAL;

	return match_flags;
}

static struct efx_mcdi_filter_vlan *
efx_mcdi_filter_find_vlan(struct efx_nic *efx, u16 vid)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct efx_mcdi_filter_vlan *vlan;

	WARN_ON(!rwsem_is_locked(&efx->filter_sem));

	list_for_each_entry(vlan, &table->vlan_list, list)
		if (vlan->vid == vid)
			return vlan;

	return NULL;
}

int efx_mcdi_filter_add_vlan(struct efx_nic *efx, u16 vid)
{
	struct efx_mcdi_filter_table *table;
	struct efx_mcdi_filter_vlan *vlan;
	unsigned int i;
	int rc = 0;

	mutex_lock(&efx->mac_lock);
	down_write(&efx->filter_sem);

	table = efx->filter_state;
	if (!table) {
		rc = -ENETDOWN;
		goto out;
	}

	vlan = efx_mcdi_filter_find_vlan(efx, vid);
	if (vlan) {
		netif_info(efx, drv, efx->net_dev,
			   "VLAN %u already added\n", vid);
		rc = -EALREADY;
		goto out;
	}

	vlan = kzalloc(sizeof(*vlan), GFP_KERNEL);
	if (!vlan) {
		rc = -ENOMEM;
		goto out;
	}

	vlan->vid = vid;

	for (i = 0; i < ARRAY_SIZE(vlan->uc); i++)
		vlan->uc[i] = EFX_MCDI_FILTER_ID_INVALID;
	for (i = 0; i < ARRAY_SIZE(vlan->mc); i++)
		vlan->mc[i] = EFX_MCDI_FILTER_ID_INVALID;
	for (i = 0; i < EFX_MCDI_NUM_DEFAULT_FILTERS; i++)
		vlan->default_filters[i] = EFX_MCDI_FILTER_ID_INVALID;

	vlan->warn_on_zero_filters = true;

	list_add_tail(&vlan->list, &table->vlan_list);

	if (efx->datapath_started)
		efx_mcdi_filter_vlan_sync_rx_mode(efx, vlan);

out:
	up_write(&efx->filter_sem);
	mutex_unlock(&efx->mac_lock);
	return rc;
}

static void efx_mcdi_filter_down_vlan(struct efx_nic *efx,
				      struct efx_mcdi_filter_vlan *vlan)
{
	unsigned int i;

	efx_rwsem_assert_write_locked(&efx->filter_sem);

	for (i = 0; i < ARRAY_SIZE(vlan->uc); i++)
		if (vlan->uc[i] != EFX_MCDI_FILTER_ID_INVALID) {
			efx_mcdi_filter_remove_unsafe(efx, EFX_FILTER_PRI_AUTO,
						      vlan->uc[i]);
			vlan->uc[i] = EFX_MCDI_FILTER_ID_INVALID;
		}
	for (i = 0; i < ARRAY_SIZE(vlan->mc); i++)
		if (vlan->mc[i] != EFX_MCDI_FILTER_ID_INVALID) {
			efx_mcdi_filter_remove_unsafe(efx, EFX_FILTER_PRI_AUTO,
						      vlan->mc[i]);
			vlan->mc[i] = EFX_MCDI_FILTER_ID_INVALID;
		}
	for (i = 0; i < EFX_MCDI_NUM_DEFAULT_FILTERS; i++)
		if (vlan->default_filters[i] != EFX_MCDI_FILTER_ID_INVALID) {
			efx_mcdi_filter_remove_unsafe(efx, EFX_FILTER_PRI_AUTO,
						      vlan->default_filters[i]);
			vlan->default_filters[i] = EFX_MCDI_FILTER_ID_INVALID;
		}
}

static void efx_mcdi_filter_del_vlan_internal(struct efx_nic *efx,
					      struct efx_mcdi_filter_vlan *vlan)
{
	efx_rwsem_assert_write_locked(&efx->filter_sem);

	efx_mcdi_filter_down_vlan(efx, vlan);

	list_del(&vlan->list);

	kfree(vlan);
}

int efx_mcdi_filter_del_vlan(struct efx_nic *efx, u16 vid)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct efx_mcdi_filter_vlan *vlan;
	int rc = 0;

	mutex_lock(&efx->mac_lock);
	down_write(&efx->filter_sem);

	if (!table) {
		rc = -ENETDOWN;
		goto out;
	}

	vlan = efx_mcdi_filter_find_vlan(efx, vid);
	if (!vlan) {
		netif_err(efx, drv, efx->net_dev,
			  "VLAN %u not found in filter state\n", vid);
		rc = -ENOENT;
		goto out;
	}

	efx_mcdi_filter_del_vlan_internal(efx, vlan);

out:
	up_write(&efx->filter_sem);
	mutex_unlock(&efx->mac_lock);
	return rc;
}

static void efx_mcdi_filter_down_vlans(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct efx_mcdi_filter_vlan *vlan;

	efx_rwsem_assert_write_locked(&efx->filter_sem);

	list_for_each_entry(vlan, &table->vlan_list, list)
		efx_mcdi_filter_down_vlan(efx, vlan);
}

static void efx_mcdi_filter_del_vlans(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct efx_mcdi_filter_vlan *vlan, *next_vlan;

	efx_rwsem_assert_write_locked(&efx->filter_sem);

	list_for_each_entry_safe(vlan, next_vlan, &table->vlan_list, list)
		efx_mcdi_filter_del_vlan_internal(efx, vlan);
}

bool efx_mcdi_filter_match_supported(struct efx_nic *efx,
				     bool encap,
				     unsigned int match_flags)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	unsigned int match_pri;
	int mf;

	if (!table) {
		netif_warn(efx, drv, efx->net_dev,
			   "filter match support check before probe\n");
		return false;
	}

	for (match_pri = 0;
	     match_pri < table->rx_match_count;
	     match_pri++) {
		mf = efx_mcdi_filter_match_flags_from_mcdi(encap,
				table->rx_match_mcdi_flags[match_pri]);
		if (mf == match_flags)
			return true;
	}

	return false;
}

static int
efx_mcdi_filter_table_probe_matches(struct efx_nic *efx,
				    struct efx_mcdi_filter_table *table,
				    bool encap)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_PARSER_DISP_INFO_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMAX);
	unsigned int pd_match_pri, pd_match_count;
	size_t outlen;
	int rc;

	/* Find out which RX filter types are supported, and their priorities */
	MCDI_SET_DWORD(inbuf, GET_PARSER_DISP_INFO_IN_OP,
		       encap ?
		       MC_CMD_GET_PARSER_DISP_INFO_IN_OP_GET_SUPPORTED_ENCAP_RX_MATCHES :
		       MC_CMD_GET_PARSER_DISP_INFO_IN_OP_GET_SUPPORTED_RX_MATCHES);
	rc = efx_mcdi_rpc(efx, MC_CMD_GET_PARSER_DISP_INFO,
			  inbuf, sizeof(inbuf), outbuf, sizeof(outbuf),
			  &outlen);
	if (rc)
		return rc;

	pd_match_count = MCDI_VAR_ARRAY_LEN(
		outlen, GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES);

	if (pd_match_count == 0)
		netif_warn(efx, probe, efx->net_dev, "%s: pd_match_count = 0\n",
				__func__);

	for (pd_match_pri = 0; pd_match_pri < pd_match_count; pd_match_pri++) {
		u32 mcdi_flags =
			MCDI_ARRAY_DWORD(
				outbuf,
				GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES,
				pd_match_pri);
		rc = efx_mcdi_filter_match_flags_from_mcdi(encap, mcdi_flags);
		if (rc < 0) {
			netif_dbg(efx, probe, efx->net_dev,
					"%s: fw flags %#x pri %u not supported in driver\n",
					__func__, mcdi_flags, pd_match_pri);
		} else {
			netif_dbg(efx, probe, efx->net_dev,
					"%s: fw flags %#x pri %u supported as driver flags %#x pri %u\n",
					__func__, mcdi_flags, pd_match_pri,
					rc, table->rx_match_count);
			table->rx_match_mcdi_flags[table->rx_match_count++] =
				mcdi_flags;
		}
	}

	return 0;
}

int efx_mcdi_filter_probe_supported_filters(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	int rc;

	table->rx_match_count = 0;

	rc = efx_mcdi_filter_table_probe_matches(efx, table, false);

	if (!rc && table->encap_supported)
		rc = efx_mcdi_filter_table_probe_matches(efx, table, true);

	return rc;
}

int efx_mcdi_filter_table_probe(struct efx_nic *efx, bool rss_limited,
				bool additional_rss_modes)
{
	struct efx_mcdi_filter_table *table;

	if (efx->filter_state) /* already probed */
		return 0;

	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	efx->filter_state = table;

	INIT_LIST_HEAD(&table->vlan_list);

	table->rss_limited = rss_limited;
	table->additional_rss_modes = additional_rss_modes;

	table->mc_promisc_last = false;
	INIT_LIST_HEAD(&table->vlan_list);
	init_rwsem(&table->lock);

	return 0;
}

int efx_mcdi_filter_table_init(struct efx_nic *efx, bool mc_chaining,
			       bool encap)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct net_device *net_dev  = efx->net_dev;
	unsigned int filter_idx;
	int rc;

	table->mc_chaining = mc_chaining;
	table->encap_supported = encap;

	table->entry = vzalloc(array_size(EFX_MCDI_FILTER_TBL_ROWS,
					  sizeof(*table->entry)));
	if (!table->entry) {
		rc = -ENOMEM;
		goto fail;
	}

	for (filter_idx = 0;
	     filter_idx < EFX_MCDI_FILTER_TBL_ROWS;
	     filter_idx++)
		table->entry[filter_idx].handle = EFX_MCDI_FILTER_ID_INVALID;

	rc = efx_mcdi_filter_probe_supported_filters(efx);
	if (rc)
		goto fail;

#ifdef CONFIG_SFC_DEBUGFS
	efx_extend_debugfs_port(efx, efx, 0, efx_debugfs);
	efx_extend_debugfs_port(efx, efx->filter_state, 0, filter_debugfs);
#endif

	/* Ignore net_dev features for vDPA devices */
	if (efx->state == STATE_VDPA)
		return 0;

	if (!efx_mcdi_filter_match_supported(efx, false,
					     EFX_FILTER_MATCH_FLAGS_RFS)) {
		netif_info(efx, probe, net_dev,
			   "RFS filters are not supported in this firmware variant\n");
		net_dev->features &= ~NETIF_F_NTUPLE;
	}

	efx->vlan_filter_available =
		efx_mcdi_filter_match_supported(efx, false,
                (EFX_FILTER_MATCH_OUTER_VID | EFX_FILTER_MATCH_LOC_MAC));

	if ((efx_supported_features(efx) & NETIF_F_HW_VLAN_CTAG_FILTER) &&
	    !efx->vlan_filter_available) {

		netif_info(efx, probe, net_dev,
			   "VLAN filters are not supported in this firmware variant\n");
		net_dev->features &= ~NETIF_F_HW_VLAN_CTAG_FILTER;
		efx->fixed_features &= ~NETIF_F_HW_VLAN_CTAG_FILTER;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETDEV_HW_FEATURES)
		net_dev->hw_features &= ~NETIF_F_HW_VLAN_CTAG_FILTER;
#elif defined(EFX_HAVE_NETDEV_EXTENDED_HW_FEATURES)
		netdev_extended(net_dev)->hw_features &=
			~NETIF_F_HW_VLAN_CTAG_FILTER;
#else
		efx->hw_features &= ~NETIF_F_HW_VLAN_CTAG_FILTER;
#endif
	}
	table->vlan_filter = efx_mcdi_filter_vlan_filter(efx);

	return 0;

fail:
	kfree(table->entry);
	table->entry = NULL;
	return rc;
}

static void efx_mcdi_filter_invalidate_filter_id(struct efx_nic *efx,
						 unsigned int filter_idx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct efx_mcdi_filter_vlan *vlan;
	int i;

	list_for_each_entry(vlan, &table->vlan_list, list)
		for (i = 0; i < EFX_MCDI_NUM_DEFAULT_FILTERS; ++i)
			if (vlan->default_filters[i] == filter_idx)
				vlan->default_filters[i] =
					EFX_MCDI_FILTER_ID_INVALID;
	efx_mcdi_filter_set_entry(table, filter_idx, NULL, 0);
}

void efx_mcdi_filter_table_reset_mc_allocations(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;

	if (table) {
		table->must_restore_filters = true;
		table->must_restore_rss_contexts = true;
	}
}

/* Caller must hold efx->filter_sem for read if race against
 * efx_mcdi_filter_table_down() is possible
 */
int efx_mcdi_filter_table_up(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	unsigned int invalid_filters = 0;
	struct efx_filter_spec *spec;
	struct efx_rss_context *ctx;
	unsigned int filter_idx;
	struct efx_vport *vpx;
	int fail_rc = 0;
	u32 mcdi_flags;
	int match_pri;
	int rc;

	WARN_ON(!rwsem_is_locked(&efx->filter_sem));

	if (!table || !table->entry)
		return -ENETDOWN;

	if (table->push_filters)
		return 0;

	down_write(&table->lock);
	mutex_lock(&efx->rss_lock);
	mutex_lock(&efx->vport_lock);

	table->push_filters = true;

	/* remove any filters that are no longer supported */
	for (filter_idx = 0; filter_idx < EFX_MCDI_FILTER_TBL_ROWS; filter_idx++) {
		spec = efx_mcdi_filter_entry_spec(table, filter_idx);
		if (!spec)
			continue;

		mcdi_flags = efx_mcdi_filter_mcdi_flags_from_spec(spec);
		match_pri = 0;
		while (match_pri < table->rx_match_count &&
		       table->rx_match_mcdi_flags[match_pri] != mcdi_flags)
			++match_pri;
		if (match_pri < table->rx_match_count)
			continue;

		table->entry[filter_idx].handle = EFX_MCDI_FILTER_ID_INVALID;
		kfree(spec);
		efx_mcdi_filter_invalidate_filter_id(efx, filter_idx);
		++invalid_filters;
	}
	/* This can happen validly if the MC's capabilities have changed, so
	 * is not an error.
	 */
	if (invalid_filters)
		netif_dbg(efx, drv, efx->net_dev,
			  "Did not restore %u filters that are now unsupported.\n",
			  invalid_filters);
	/* re-add filters in priority order */
	for (match_pri=(table->rx_match_count)-1; match_pri >= 0; match_pri--) {
		for (filter_idx = 0; filter_idx < EFX_MCDI_FILTER_TBL_ROWS; filter_idx++) {
			spec = efx_mcdi_filter_entry_spec(table, filter_idx);
			if (!spec)
				continue;

			mcdi_flags = efx_mcdi_filter_mcdi_flags_from_spec(spec);
			if (mcdi_flags != table->rx_match_mcdi_flags[match_pri])
				continue;

			if (spec->rss_context)
				ctx = efx_find_rss_context_entry(efx, spec->rss_context);
			else
				ctx = &efx->rss_context;
			if (spec->flags & EFX_FILTER_FLAG_RX_RSS) {
				if (!ctx) {
					netif_warn(efx, drv, efx->net_dev,
						   "Warning: unable to restore a filter with nonexistent RSS context %u.\n",
						   spec->rss_context);
					rc = -EINVAL;
					goto invalid;
				}
				if (ctx->context_id == EFX_MCDI_RSS_CONTEXT_INVALID) {
					netif_warn(efx, drv, efx->net_dev,
						   "Warning: unable to restore a filter with RSS context %u as it was not created.\n",
						   spec->rss_context);
					rc = -EINVAL;
					goto invalid;
				}
			}

			if (spec->vport_id)
				vpx = efx_find_vport_entry(efx, spec->vport_id);
			else
				vpx = &efx->vport;
			if (spec->flags & EFX_FILTER_FLAG_VPORT_ID) {
				if (!vpx) {
					netif_warn(efx, drv, efx->net_dev,
						   "Warning: unable to restore a filter with nonexistent v-port %u.\n",
						   spec->vport_id);
					rc = -EINVAL;
					goto invalid;
				}
				if (vpx->vport_id == EVB_PORT_ID_NULL) {
					netif_warn(efx, drv, efx->net_dev,
						   "Warning: unable to restore a filter with v-port %u as it was not created.\n",
						   spec->vport_id);
					rc = -EINVAL;
					goto invalid;
				}
			}

			rc = efx_mcdi_filter_push(efx, spec,
						  &table->entry[filter_idx].handle,
						  ctx, vpx, false);

			if (rc) {
invalid:
				fail_rc = rc;
				kfree(spec);
				efx_mcdi_filter_invalidate_filter_id(efx, filter_idx);
			}
		}
	}

	/* if we fail to insert some filters then don't fail whatever
	 * control operation we're performing, but don't mark filters
	 * as installed so they'll be tried again later
	 */
	if (fail_rc)
		netif_err(efx, hw, efx->net_dev,
			  "unable to restore all filters, rc=%d\n",
			  fail_rc);
	else
		table->must_restore_filters = false;

	mutex_unlock(&efx->vport_lock);
	mutex_unlock(&efx->rss_lock);
	up_write(&table->lock);
	return 0;
}

void efx_mcdi_filter_table_restore(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;

	if (!table || !table->must_restore_filters)
		return;
	(void)efx_mcdi_filter_table_up(efx);
}

void efx_mcdi_filter_table_down(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FILTER_OP_IN_LEN);
	struct efx_filter_spec *spec;
	unsigned int filter_idx;
	int rc;

	if (!table || !table->entry)
		return;

	efx_rwsem_assert_write_locked(&efx->filter_sem);

	efx_mcdi_filter_down_vlans(efx);

	for (filter_idx = 0; filter_idx < EFX_MCDI_FILTER_TBL_ROWS; filter_idx++) {
		spec = efx_mcdi_filter_entry_spec(table, filter_idx);
		if (!spec)
			continue;

		MCDI_SET_DWORD(inbuf, FILTER_OP_IN_OP,
			       efx_mcdi_filter_is_exclusive(spec) ?
			       MC_CMD_FILTER_OP_IN_OP_REMOVE :
			       MC_CMD_FILTER_OP_IN_OP_UNSUBSCRIBE);
		MCDI_SET_QWORD(inbuf, FILTER_OP_IN_HANDLE,
			       table->entry[filter_idx].handle);
		rc = efx_mcdi_rpc_quiet(efx, MC_CMD_FILTER_OP, inbuf,
				sizeof(inbuf), NULL, 0, NULL);
		if (rc && (rc != -ENETDOWN))
			netif_info(efx, drv, efx->net_dev,
					"%s: filter %04x remove failed %d\n",
					__func__, filter_idx, rc);
		table->entry[filter_idx].handle = EFX_MCDI_FILTER_ID_INVALID;
	}

	table->push_filters = false;
}

void efx_mcdi_filter_table_fini(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	unsigned int filter_idx;

	if (!table)
		return;

#ifdef CONFIG_SFC_DEBUGFS
	efx_trim_debugfs_port(efx, efx_debugfs);
	efx_trim_debugfs_port(efx, filter_debugfs);
#endif

	if (!table->entry)
		return;

	for (filter_idx = 0;
	     filter_idx < EFX_MCDI_FILTER_TBL_ROWS;
	     filter_idx++)
		kfree(efx_mcdi_filter_entry_spec(table, filter_idx));
	vfree(table->entry);
	table->entry = NULL;
}

void efx_mcdi_filter_table_remove(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;

	if (!table)
		return;

	down_write(&efx->filter_sem);
	efx_mcdi_filter_del_vlans(efx);

	efx->filter_state = NULL;
	up_write(&efx->filter_sem);
	kfree(table);
}

static void efx_mcdi_filter_mark_one_old(struct efx_nic *efx, uint16_t *id)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	unsigned int filter_idx;

	efx_rwsem_assert_write_locked(&table->lock);

	if (*id != EFX_MCDI_FILTER_ID_INVALID) {
		filter_idx = efx_mcdi_filter_get_unsafe_id(efx, *id);
		if (!table->entry[filter_idx].spec)
			netif_dbg(efx, drv, efx->net_dev,
				"%s: marked null spec old %04x:%04x\n",
				__func__, *id, filter_idx);
		table->entry[filter_idx].spec |= EFX_MCDI_FILTER_FLAG_AUTO_OLD;
		*id = EFX_MCDI_FILTER_ID_INVALID;
	}
}

/* Mark old per-VLAN filters that may need to be removed */
static void _efx_mcdi_filter_vlan_mark_old(struct efx_nic *efx,
					   struct efx_mcdi_filter_vlan *vlan)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	unsigned int i;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	for (i = 0; i < table->dev_uc_count; i++)
		efx_mcdi_filter_mark_one_old(efx, &vlan->uc[i]);
	for (i = 0; i < table->dev_mc_count; i++)
		efx_mcdi_filter_mark_one_old(efx, &vlan->mc[i]);
	for (i = 0; i < EFX_MCDI_NUM_DEFAULT_FILTERS; i++)
		efx_mcdi_filter_mark_one_old(efx, &vlan->default_filters[i]);
}

/* Mark old filters that may need to be removed.
 * Caller must hold efx->filter_sem for read if race against
 * efx_mcdi_filter_table_down() is possible
 */
static void efx_mcdi_filter_mark_old(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct efx_mcdi_filter_vlan *vlan;

	down_write(&table->lock);
	list_for_each_entry(vlan, &table->vlan_list, list)
		_efx_mcdi_filter_vlan_mark_old(efx, vlan);
	up_write(&table->lock);
}

/* Remove filters that weren't renewed. */
static void efx_mcdi_filter_remove_old(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	int remove_failed = 0;
	int remove_noent = 0;
	int rc;
	int i;

	down_write(&table->lock);
	for (i = 0; i < EFX_MCDI_FILTER_TBL_ROWS; i++) {
		if (READ_ONCE(table->entry[i].spec) &
			      EFX_MCDI_FILTER_FLAG_AUTO_OLD) {
			rc = efx_mcdi_filter_remove_internal(efx,
					1U << EFX_FILTER_PRI_AUTO, i, true);
			if (rc == -ENOENT)
				remove_noent++;
			else if (rc)
				remove_failed++;
		}
	}
	up_write(&table->lock);

	if (remove_failed)
		netif_info(efx, drv, efx->net_dev,
				"%s: failed to remove %d filters\n",
				__func__, remove_failed);
	if (remove_noent)
		netif_info(efx, drv, efx->net_dev,
				"%s: failed to remove %d non-existent filters\n",
				__func__, remove_noent);
}

static void efx_mcdi_filter_uc_addr_list(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct net_device *net_dev = efx->net_dev;
	struct netdev_hw_addr *uc;
	unsigned int i;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (table->kernel_blocked[EFX_DL_FILTER_BLOCK_KERNEL_UCAST]) {
		table->dev_uc_count = 0;
		return;
	}
#endif
#endif
	table->uc_promisc = !!(net_dev->flags & IFF_PROMISC);
	ether_addr_copy(table->dev_uc_list[0].addr, net_dev->dev_addr);
	i = 1;
	netdev_for_each_uc_addr(uc, net_dev) {
		if (i >= EFX_MCDI_FILTER_DEV_UC_MAX) {
			table->uc_promisc = true;
			break;
		}
		ether_addr_copy(table->dev_uc_list[i].addr, uc->addr);
		i++;
	}
	table->dev_uc_count = i;
}

static void efx_mcdi_filter_mc_addr_list(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct net_device *net_dev = efx->net_dev;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_MC)
	struct netdev_hw_addr *mc;
#else
	struct dev_mc_list *mc;
#endif
	unsigned int i;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	table->mc_overflow = false;

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (table->kernel_blocked[EFX_DL_FILTER_BLOCK_KERNEL_MCAST]) {
		table->dev_mc_count = 0;
		return;
	}
#endif
#endif
	table->mc_promisc = !!(net_dev->flags & (IFF_PROMISC | IFF_ALLMULTI));

	i = 0;
	netdev_for_each_mc_addr(mc, net_dev) {
		if (i >= EFX_MCDI_FILTER_DEV_MC_MAX) {
			table->mc_promisc = true;
			table->mc_overflow = true;
			break;
		}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_DEVICE_MC)
		ether_addr_copy(table->dev_mc_list[i].addr, mc->addr);
#else
		ether_addr_copy(table->dev_mc_list[i].addr, mc->dmi_addr);
#endif
		i++;
	}

	table->dev_mc_count = i;
}

static unsigned int efx_mcdi_filter_vlan_count_filters(struct efx_nic *efx,
						       struct efx_mcdi_filter_vlan *vlan)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	unsigned int count = 0;
	unsigned int i;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	for (i = 0; i < table->dev_uc_count; i++)
		count += (vlan->uc[i] != EFX_MCDI_FILTER_ID_INVALID);
	for (i = 0; i < table->dev_mc_count; i++)
		count += (vlan->mc[i] != EFX_MCDI_FILTER_ID_INVALID);
	for (i = 0; i < EFX_MCDI_NUM_DEFAULT_FILTERS; i++)
		count += (vlan->default_filters[i] !=
			  EFX_MCDI_FILTER_ID_INVALID);

	return count;
}

/* Caller must hold efx->filter_sem for read if race against
 * efx_mcdi_filter_table_down() is possible
 */
void efx_mcdi_filter_sync_rx_mode(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct net_device *net_dev = efx->net_dev;
	struct efx_mcdi_filter_vlan *vlan;
	bool vlan_filter;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	if (!efx->datapath_started)
		return;

	/* If we're currently resetting, then this isn't going to go well (and
	 * we'll try it again when the reset is complete).  So skip it.
	 * This is typically triggered by adding a new UDP tunnel port and
	 * adding a multicast address (for the UDP tunnel) at the same time.
	 */
	if (!netif_device_present(net_dev))
		return;

	if (!table || !table->entry)
		return;

	efx_mcdi_filter_mark_old(efx);

	/* Copy/convert the address lists; add the primary station
	 * address and broadcast address
	 */
	netif_addr_lock_bh(net_dev);
	efx_mcdi_filter_uc_addr_list(efx);
	efx_mcdi_filter_mc_addr_list(efx);
	netif_addr_unlock_bh(net_dev);

	/* If VLAN filtering changes, all old filters are finally removed.
	 * Do it in advance to avoid conflicts for unicast untagged and
	 * VLAN 0 tagged filters.
	 */
	vlan_filter = efx_mcdi_filter_vlan_filter(efx);
	if (table->vlan_filter != vlan_filter) {
		table->vlan_filter = vlan_filter;
		efx_mcdi_filter_remove_old(efx);
	}

	list_for_each_entry(vlan, &table->vlan_list, list)
		efx_mcdi_filter_vlan_sync_rx_mode(efx, vlan);

	efx_mcdi_filter_remove_old(efx);
	table->mc_promisc_last = table->mc_promisc;
}

#ifdef CONFIG_RFS_ACCEL
bool efx_mcdi_filter_rfs_expire_one(struct efx_nic *efx, u32 flow_id,
				    unsigned int filter_idx)
{
	struct efx_filter_spec *spec, saved_spec;
	struct efx_mcdi_filter_table *table;
	struct efx_arfs_rule *rule = NULL;
	bool ret = true, force = false;
	u16 arfs_id;

	down_read(&efx->filter_sem);
	table = efx->filter_state;
	if (!table || !table->entry) {
		up_read(&efx->filter_sem);
		return false;
	}
	down_write(&table->lock);
	spec = efx_mcdi_filter_entry_spec(table, filter_idx);

	/* If it's somehow gone, or been replaced with a higher priority filter
	 * then silently expire it and move on.
	 */
	if (!spec || spec->priority != EFX_FILTER_PRI_HINT)
		goto out_unlock;

	spin_lock_bh(&efx->rps_hash_lock);
	if (!efx->rps_hash_table) {
		/* In the absence of the table, we always return 0 to ARFS. */
		arfs_id = 0;
	} else {
		rule = efx_rps_hash_find(efx, spec);
		if (!rule)
			/* ARFS table doesn't know of this filter, so remove it */
			goto expire;
		arfs_id = rule->arfs_id;
		ret = efx_rps_check_rule(rule, filter_idx, &force);
		if (force)
			goto expire;
		if (!ret) {
			spin_unlock_bh(&efx->rps_hash_lock);
			goto out_unlock;
		}
	}
	if (!rps_may_expire_flow(efx->net_dev, spec->dmaq_id, flow_id, arfs_id))
		ret = false;
	else if (rule)
		rule->filter_id = EFX_ARFS_FILTER_ID_REMOVING;
expire:
	saved_spec = *spec; /* remove operation will kfree spec */
	spin_unlock_bh(&efx->rps_hash_lock);
	/* At this point (since we dropped the lock), another thread might queue
	 * up a fresh insertion request (but the actual insertion will be held
	 * up by our possession of the filter table lock).  In that case, it
	 * will set rule->filter_id to EFX_ARFS_FILTER_ID_PENDING, meaning that
	 * the rule is not removed by efx_rps_hash_del() below.
	 */
	if (ret)
		ret = efx_mcdi_filter_remove_internal(efx, 1U << spec->priority,
						      filter_idx, true) == 0;
	/* While we can't safely dereference rule (we dropped the lock), we can
	 * still test it for NULL.
	 */
	if (ret && rule) {
		/* Expiring, so remove entry from ARFS table */
		spin_lock_bh(&efx->rps_hash_lock);
		efx_rps_hash_del(efx, &saved_spec);
		spin_unlock_bh(&efx->rps_hash_lock);
	}
out_unlock:
	up_write(&table->lock);
	up_read(&efx->filter_sem);
	return ret;
}
#endif /* CONFIG_RFS_ACCEL*/

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
int efx_mcdi_filter_block_kernel(struct efx_nic *efx,
				 enum efx_dl_filter_block_kernel_type type)
{
	struct efx_mcdi_filter_table *table;
	int rc = 0;

	mutex_lock(&efx->mac_lock);
	down_read(&efx->filter_sem);
	table = efx->filter_state;
	if (!table || !table->entry) {
		rc = -ENETDOWN;
		goto out;
	}
	down_write(&table->lock);
	table->kernel_blocked[type] = true;
	up_write(&table->lock);

	efx_mcdi_filter_sync_rx_mode(efx);

	if (type == EFX_DL_FILTER_BLOCK_KERNEL_UCAST)
		rc = efx_mcdi_filter_clear_rx(efx, EFX_FILTER_PRI_HINT);
out:
	up_read(&efx->filter_sem);
	mutex_unlock(&efx->mac_lock);
	return rc;
}

void efx_mcdi_filter_unblock_kernel(struct efx_nic *efx,
				    enum efx_dl_filter_block_kernel_type type)
{
	struct efx_mcdi_filter_table *table;

	mutex_lock(&efx->mac_lock);
	down_read(&efx->filter_sem);
	table = efx->filter_state;
	if (!table || !table->entry)
		goto out;
	down_write(&table->lock);
	table->kernel_blocked[type] = false;
	up_write(&table->lock);

	efx_mcdi_filter_sync_rx_mode(efx);
out:
	up_read(&efx->filter_sem);
	mutex_unlock(&efx->mac_lock);
}
#endif /* CONFIG_SFC_DRIVERLINK */
#endif /* EFX_NOT_UPSTREAM */

u32 efx_mcdi_get_default_rss_flags(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	u32 flags = RSS_CONTEXT_FLAGS_DEFAULT;

	if (table->additional_rss_modes)
		flags |= RSS_CONTEXT_FLAGS_DEFAULT_ADDITIONAL;
	return flags;
}

/* Firmware had a bug (sfc bug 61952) where it would not actually fill in the
 * flags field in the response to MC_CMD_RSS_CONTEXT_GET_FLAGS.
 * This meant that it would always contain whatever was previously in the MCDI
 * buffer.  Fortunately, all firmware versions with this bug have a known
 * default flags value for a newly-allocated RSS context (either 0xf or
 * 0x33f33f0f, depending on the capability flag
 * MC_CMD_GET_CAPABILITIES_OUT_ADDITIONAL_RSS_MODES), and when we allocate an
 * RSS context we're the only function that can control it; thus we can
 * maintain a shadow state in software.
 */
static void efx_mcdi_init_rss_flags(struct efx_nic *efx)
{
	efx->rss_context.flags = efx_mcdi_get_default_rss_flags(efx);
}

/* The response to MC_CMD_RSS_CONTEXT_GET_FLAGS has a 32-bit hole where the
 * context ID would be in the request, so we can use an overlength buffer in
 * the request and pre-fill the flags field with what we believe the current
 * value to be.  Thus if the firmware has the bug, it will leave our pre-filled
 * value in the flags field of the response, whereas if the firmware is fixed,
 * it will fill in the current value (which should be the same).
 */
int efx_mcdi_get_rss_context_flags(struct efx_nic *efx,
				   struct efx_rss_context *ctx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_LEN);
	size_t outlen;
	int rc;

	/* Check we have a hole for the context ID */
	BUILD_BUG_ON(MC_CMD_RSS_CONTEXT_GET_FLAGS_IN_LEN != MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_FLAGS_OFST);
	MCDI_SET_DWORD(inbuf, RSS_CONTEXT_GET_FLAGS_IN_RSS_CONTEXT_ID,
		       ctx->context_id);
	MCDI_SET_DWORD(inbuf, RSS_CONTEXT_GET_FLAGS_OUT_FLAGS, ctx->flags);
	rc = efx_mcdi_rpc(efx, MC_CMD_RSS_CONTEXT_GET_FLAGS, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc == 0) {
		if (outlen < MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_LEN)
			rc = -EIO;
		else
			ctx->flags = MCDI_DWORD(outbuf, RSS_CONTEXT_GET_FLAGS_OUT_FLAGS);
	}
	return rc;
}

int efx_mcdi_set_rss_context_flags(struct efx_nic *efx,
				   struct efx_rss_context *ctx, u32 flags)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_LEN);
	int rc;

	BUILD_BUG_ON(MC_CMD_RSS_CONTEXT_SET_FLAGS_OUT_LEN != 0);

	if (flags == ctx->flags)
		/* nothing to do */
		return 0;
	/* If we're using additional flags, check firmware supports them */
	if ((flags & RSS_CONTEXT_FLAGS_ADDITIONAL_MASK) &&
	    !table->additional_rss_modes)
		return -EOPNOTSUPP;
	MCDI_SET_DWORD(inbuf, RSS_CONTEXT_SET_FLAGS_IN_RSS_CONTEXT_ID,
		       ctx->context_id);
	MCDI_SET_DWORD(inbuf, RSS_CONTEXT_SET_FLAGS_IN_FLAGS, flags);
	rc = efx_mcdi_rpc(efx, MC_CMD_RSS_CONTEXT_SET_FLAGS, inbuf,
			  sizeof(inbuf), NULL, 0, NULL);
	if (!rc)
		ctx->flags = flags;
	return rc;
}

static int efx_mcdi_filter_alloc_rss_context(struct efx_nic *efx, bool exclusive,
					     struct efx_rss_context *ctx,
					     unsigned int *context_size)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_RSS_CONTEXT_ALLOC_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_RSS_CONTEXT_ALLOC_OUT_LEN);
	size_t outlen;
	int rc;
	u32 alloc_type = exclusive ?
				MC_CMD_RSS_CONTEXT_ALLOC_IN_TYPE_EXCLUSIVE :
				MC_CMD_RSS_CONTEXT_ALLOC_IN_TYPE_SHARED;
	unsigned int rss_spread = exclusive ?
				efx->rss_spread :
				min(rounddown_pow_of_two(efx->rss_spread),
				    EFX_MCDI_MAX_SHARED_RSS_CONTEXT_SIZE);

#ifdef EFX_NOT_UPSTREAM
	if (ctx->num_queues)
		rss_spread = ctx->num_queues;
#endif

	if (!exclusive && rss_spread == 1) {
		ctx->context_id = EFX_MCDI_RSS_CONTEXT_INVALID;
		if (context_size)
			*context_size = 1;
		return 0;
	}

	if (table->rss_limited)
		return -EOPNOTSUPP;

	MCDI_SET_DWORD(inbuf, RSS_CONTEXT_ALLOC_IN_UPSTREAM_PORT_ID,
		       efx->vport.vport_id);
	MCDI_SET_DWORD(inbuf, RSS_CONTEXT_ALLOC_IN_TYPE, alloc_type);
	MCDI_SET_DWORD(inbuf, RSS_CONTEXT_ALLOC_IN_NUM_QUEUES,
		       efx_rx_queue_id_internal(efx, rss_spread));

	rc = efx_mcdi_rpc(efx, MC_CMD_RSS_CONTEXT_ALLOC, inbuf, sizeof(inbuf),
		outbuf, sizeof(outbuf), &outlen);
	if (rc != 0)
		return rc;

	if (outlen < MC_CMD_RSS_CONTEXT_ALLOC_OUT_LEN)
		return -EIO;

	ctx->context_id = MCDI_DWORD(outbuf, RSS_CONTEXT_ALLOC_OUT_RSS_CONTEXT_ID);

	if (context_size)
		*context_size = rss_spread;

	efx_mcdi_init_rss_flags(efx);
	efx_mcdi_get_rss_context_flags(efx, ctx);

	/* Apply our default RSS hashing policy: 4-tuple for TCP and UDP,
	 * 2-tuple for other IP.
	 * If we fail, we just leave the RSS context at its default hash
	 * settings (4-tuple TCP, 2-tuple UDP and other-IP), which is safe
	 * but may slightly reduce performance.
	 */
	if (table->additional_rss_modes)
		efx_mcdi_set_rss_context_flags(efx, ctx,
			RSS_CONTEXT_FLAGS_DEFAULT | /* _EN flags */
			RSS_MODE_HASH_4TUPLE << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TCP_IPV4_RSS_MODE_LBN |
			RSS_MODE_HASH_4TUPLE << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TCP_IPV6_RSS_MODE_LBN |
			RSS_MODE_HASH_4TUPLE << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_UDP_IPV4_RSS_MODE_LBN |
			RSS_MODE_HASH_4TUPLE << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_UDP_IPV6_RSS_MODE_LBN |
			RSS_MODE_HASH_ADDRS << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_OTHER_IPV4_RSS_MODE_LBN |
			RSS_MODE_HASH_ADDRS << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_OTHER_IPV6_RSS_MODE_LBN);

	return 0;
}

static int efx_mcdi_filter_free_rss_context(struct efx_nic *efx, u32 context)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_RSS_CONTEXT_FREE_IN_LEN);

	MCDI_SET_DWORD(inbuf, RSS_CONTEXT_FREE_IN_RSS_CONTEXT_ID,
		       context);

	return efx_mcdi_rpc(efx, MC_CMD_RSS_CONTEXT_FREE, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

static int efx_mcdi_filter_populate_rss_table(struct efx_nic *efx, u32 context,
					      const u32 *rx_indir_table, const u8 *key)
{
	MCDI_DECLARE_BUF(tablebuf, MC_CMD_RSS_CONTEXT_SET_TABLE_IN_LEN);
	MCDI_DECLARE_BUF(keybuf, MC_CMD_RSS_CONTEXT_SET_KEY_IN_LEN);
	int i, rc;

	MCDI_SET_DWORD(tablebuf, RSS_CONTEXT_SET_TABLE_IN_RSS_CONTEXT_ID,
		       context);
	BUILD_BUG_ON(ARRAY_SIZE(efx->rss_context.rx_indir_table) !=
		     MC_CMD_RSS_CONTEXT_SET_TABLE_IN_INDIRECTION_TABLE_LEN);

	/* This iterates over the length of efx->rss_context.rx_indir_table, but
	 * copies bytes from rx_indir_table.  That's because the latter is a
	 * pointer rather than an array, but should have the same length.
	 * The efx->rss_context.rx_hash_key loop below is similar.
	 */
	for (i = 0; i < ARRAY_SIZE(efx->rss_context.rx_indir_table); ++i) {
		u8 q = (u8)efx_rx_queue_id_internal(efx, rx_indir_table[i]);

		MCDI_PTR(tablebuf,
			 RSS_CONTEXT_SET_TABLE_IN_INDIRECTION_TABLE)[i] = q;
	}

	rc = efx_mcdi_rpc(efx, MC_CMD_RSS_CONTEXT_SET_TABLE, tablebuf,
			  sizeof(tablebuf), NULL, 0, NULL);
	if (rc != 0)
		return rc;

	MCDI_SET_DWORD(keybuf, RSS_CONTEXT_SET_KEY_IN_RSS_CONTEXT_ID,
		       context);
	BUILD_BUG_ON(ARRAY_SIZE(efx->rss_context.rx_hash_key) !=
		     MC_CMD_RSS_CONTEXT_SET_KEY_IN_TOEPLITZ_KEY_LEN);
	for (i = 0; i < ARRAY_SIZE(efx->rss_context.rx_hash_key); ++i)
		MCDI_PTR(keybuf, RSS_CONTEXT_SET_KEY_IN_TOEPLITZ_KEY)[i] = key[i];

	return efx_mcdi_rpc(efx, MC_CMD_RSS_CONTEXT_SET_KEY, keybuf,
			    sizeof(keybuf), NULL, 0, NULL);
}

void efx_mcdi_rx_free_indir_table(struct efx_nic *efx)
{
	int rc;

	if (efx->rss_context.context_id != EFX_MCDI_RSS_CONTEXT_INVALID) {
		rc = efx_mcdi_filter_free_rss_context(efx, efx->rss_context.context_id);
		WARN_ON(rc && rc != -ENETDOWN);
	}
	efx->rss_context.context_id = EFX_MCDI_RSS_CONTEXT_INVALID;
}

static int efx_mcdi_filter_rx_push_shared_rss_config(struct efx_nic *efx,
					      unsigned int *context_size)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	int rc = efx_mcdi_filter_alloc_rss_context(efx, false,
					    &efx->rss_context, context_size);

	if (rc != 0)
		return rc;

	efx_mcdi_init_rss_flags(efx);
	efx_mcdi_get_rss_context_flags(efx, &efx->rss_context);
	table->rss_context_exclusive = false;
	efx_set_default_rx_indir_table(efx, &efx->rss_context);
	return 0;
}

static int efx_mcdi_filter_rx_push_exclusive_rss_config(struct efx_nic *efx,
							const u32 *rx_indir_table,
							const u8 *key)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	u32 old_rx_rss_context = efx->rss_context.context_id;
	int rc;

	if (efx->rss_context.context_id == EFX_MCDI_RSS_CONTEXT_INVALID ||
	    !table->rss_context_exclusive) {
		rc = efx_mcdi_filter_alloc_rss_context(efx, true, &efx->rss_context,
						NULL);
		if (rc == -EOPNOTSUPP)
			return rc;
		else if (rc != 0)
			goto fail1;
	}

	rc = efx_mcdi_filter_populate_rss_table(efx, efx->rss_context.context_id,
						rx_indir_table, key);
	if (rc)
		goto fail2;
	if (efx->rss_context.context_id != old_rx_rss_context &&
	    old_rx_rss_context != EFX_MCDI_RSS_CONTEXT_INVALID)
		WARN_ON(efx_mcdi_filter_free_rss_context(efx, old_rx_rss_context) != 0);
	table->rss_context_exclusive = true;
	if (rx_indir_table != efx->rss_context.rx_indir_table)
		memcpy(efx->rss_context.rx_indir_table, rx_indir_table,
		       sizeof(efx->rss_context.rx_indir_table));
	if (key != efx->rss_context.rx_hash_key)
		memcpy(efx->rss_context.rx_hash_key, key,
		       efx->type->rx_hash_key_size);

	return 0;

fail2:
	if (old_rx_rss_context != efx->rss_context.context_id) {
		WARN_ON(efx_mcdi_filter_free_rss_context(efx, efx->rss_context.context_id) != 0);
		efx->rss_context.context_id = old_rx_rss_context;
	}
fail1:
	netif_err(efx, hw, efx->net_dev, "%s: failed rc=%d\n", __func__, rc);
	return rc;
}

int efx_mcdi_rx_push_rss_context_config(struct efx_nic *efx,
					struct efx_rss_context *ctx,
					const u32 *rx_indir_table,
					const u8 *key)
{
	bool allocated = false;
	int rc;

	WARN_ON(!mutex_is_locked(&efx->rss_lock));

	if (ctx->context_id == EFX_MCDI_RSS_CONTEXT_INVALID) {
		rc = efx_mcdi_filter_alloc_rss_context(efx, true, ctx, NULL);
		if (rc)
			return rc;
		allocated = true;
	}

	if (!rx_indir_table) /* Delete this context */
		return efx_mcdi_filter_free_rss_context(efx, ctx->context_id);

	rc = efx_mcdi_filter_populate_rss_table(efx, ctx->context_id,
					 rx_indir_table, key);
	if (rc) {
		if (allocated)
			/* try to clean up */
			if (efx_mcdi_filter_free_rss_context(efx, ctx->context_id))
				netif_warn(efx, hw, efx->net_dev,
					   "Leaked RSS context %u (hw %u)\n",
					   ctx->user_id, ctx->context_id);
		return rc;
	}

	memcpy(ctx->rx_indir_table, rx_indir_table,
	       sizeof(efx->rss_context.rx_indir_table));
	memcpy(ctx->rx_hash_key, key, efx->type->rx_hash_key_size);

	return 0;
}

static int efx_rx_queue_id_external(struct efx_nic *efx, int rxq_id)
{
	if (efx_tx_vi_spreading(efx)) {
		WARN_ON_ONCE(rxq_id & 1);
		return rxq_id / 2;
	} else {
		return rxq_id;
	}
}

int efx_mcdi_rx_pull_rss_context_config(struct efx_nic *efx,
					struct efx_rss_context *ctx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_RSS_CONTEXT_GET_TABLE_IN_LEN);
	MCDI_DECLARE_BUF(tablebuf, MC_CMD_RSS_CONTEXT_GET_TABLE_OUT_LEN);
	MCDI_DECLARE_BUF(keybuf, MC_CMD_RSS_CONTEXT_GET_KEY_OUT_LEN);
	size_t outlen;
	int rc, i;

	WARN_ON(!mutex_is_locked(&efx->rss_lock));

	BUILD_BUG_ON(MC_CMD_RSS_CONTEXT_GET_TABLE_IN_LEN !=
		     MC_CMD_RSS_CONTEXT_GET_KEY_IN_LEN);

	if (ctx->context_id == EFX_MCDI_RSS_CONTEXT_INVALID)
		return -ENOENT;

	MCDI_SET_DWORD(inbuf, RSS_CONTEXT_GET_TABLE_IN_RSS_CONTEXT_ID,
		       ctx->context_id);
	BUILD_BUG_ON(ARRAY_SIZE(ctx->rx_indir_table) !=
		     MC_CMD_RSS_CONTEXT_GET_TABLE_OUT_INDIRECTION_TABLE_LEN);
	rc = efx_mcdi_rpc(efx, MC_CMD_RSS_CONTEXT_GET_TABLE, inbuf, sizeof(inbuf),
			  tablebuf, sizeof(tablebuf), &outlen);
	if (rc != 0)
		return rc;

	if (WARN_ON(outlen != MC_CMD_RSS_CONTEXT_GET_TABLE_OUT_LEN))
		return -EIO;

	for (i = 0; i < ARRAY_SIZE(ctx->rx_indir_table); i++) {
		u8 q = MCDI_PTR(tablebuf,
				RSS_CONTEXT_GET_TABLE_OUT_INDIRECTION_TABLE)[i];

		ctx->rx_indir_table[i] = efx_rx_queue_id_external(efx, q);
	}

	MCDI_SET_DWORD(inbuf, RSS_CONTEXT_GET_KEY_IN_RSS_CONTEXT_ID,
		       ctx->context_id);
	BUILD_BUG_ON(ARRAY_SIZE(ctx->rx_hash_key) !=
		     MC_CMD_RSS_CONTEXT_SET_KEY_IN_TOEPLITZ_KEY_LEN);
	rc = efx_mcdi_rpc(efx, MC_CMD_RSS_CONTEXT_GET_KEY, inbuf, sizeof(inbuf),
			  keybuf, sizeof(keybuf), &outlen);
	if (rc != 0)
		return rc;

	if (WARN_ON(outlen != MC_CMD_RSS_CONTEXT_GET_KEY_OUT_LEN))
		return -EIO;

	for (i = 0; i < ARRAY_SIZE(ctx->rx_hash_key); ++i)
		ctx->rx_hash_key[i] = MCDI_PTR(
				keybuf, RSS_CONTEXT_GET_KEY_OUT_TOEPLITZ_KEY)[i];

	return 0;
}

int efx_mcdi_rx_pull_rss_config(struct efx_nic *efx)
{
	int rc;

	mutex_lock(&efx->rss_lock);
	rc = efx_mcdi_rx_pull_rss_context_config(efx, &efx->rss_context);
	mutex_unlock(&efx->rss_lock);
	return rc;
}

void efx_mcdi_rx_restore_rss_contexts(struct efx_nic *efx)
{
	struct efx_mcdi_filter_table *table = efx->filter_state;
	struct efx_rss_context *ctx;
	int rc;

	WARN_ON(!mutex_is_locked(&efx->rss_lock));

	if (!table->must_restore_rss_contexts)
		return;

	list_for_each_entry(ctx, &efx->rss_context.list, list) {
		/* previous NIC RSS context is gone */
		ctx->context_id = EFX_MCDI_RSS_CONTEXT_INVALID;
		/* so try to allocate a new one */
		rc = efx_mcdi_rx_push_rss_context_config(efx, ctx,
							 ctx->rx_indir_table,
							 ctx->rx_hash_key);
		if (rc)
			netif_warn(efx, probe, efx->net_dev,
				   "failed to restore RSS context %u, rc=%d"
				   "; RSS filters may fail to be applied\n",
				   ctx->user_id, rc);
	}
	table->must_restore_rss_contexts = false;
}

int efx_mcdi_pf_rx_push_rss_config(struct efx_nic *efx, bool user,
				   const u32 *rx_indir_table,
				   const u8 *key)
{
	u32 flags = efx->rss_context.flags;
	int rc;

	if (efx->rss_spread == 1)
		return 0;

	if (!key)
		key = efx->rss_context.rx_hash_key;

	rc = efx_mcdi_filter_rx_push_exclusive_rss_config(efx, rx_indir_table, key);

	if (rc == -ENOBUFS && !user) {
		unsigned int context_size;
		bool mismatch = false;
		size_t i;

		for (i = 0;
		     i < ARRAY_SIZE(efx->rss_context.rx_indir_table) && !mismatch;
		     i++)
			mismatch = rx_indir_table[i] !=
				ethtool_rxfh_indir_default(i, efx->rss_spread);

		rc = efx_mcdi_filter_rx_push_shared_rss_config(efx, &context_size);
		if (rc == 0) {
			if (context_size != efx->rss_spread)
				netif_warn(efx, probe, efx->net_dev,
					   "Could not allocate an exclusive RSS "
					   "context; allocated a shared one of "
					   "different size. "
					   "Wanted %u, got %u.\n",
					   efx->rss_spread, context_size);
			else if (mismatch)
				netif_warn(efx, probe, efx->net_dev,
					   "Could not allocate an exclusive RSS "
					   "context; allocated a shared one but "
					   "could not apply custom "
					   "indirection.\n");
			else
				netif_info(efx, probe, efx->net_dev,
					   "Could not allocate an exclusive RSS "
					   "context; allocated a shared one.\n");
			if (flags != efx->rss_context.flags)
				netif_info(efx, probe, efx->net_dev,
					   "Could not apply custom flow-hashing; wanted "
					   "%#08x, got %#08x.\n", flags,
					   efx->rss_context.flags);
		}
	}
	return rc;
}

#ifdef CONFIG_SFC_SRIOV
int efx_mcdi_vf_rx_push_rss_config(struct efx_nic *efx, bool user,
				   const u32 *rx_indir_table
				   __attribute__ ((unused)),
				   const u8 *key
				   __attribute__ ((unused)))
{
	if (user)
		return -EOPNOTSUPP;
	if (efx->rss_context.context_id != EFX_MCDI_RSS_CONTEXT_INVALID)
		return 0;
	return efx_mcdi_filter_rx_push_shared_rss_config(efx, NULL);
}
#endif

int efx_mcdi_push_default_indir_table(struct efx_nic *efx,
				      unsigned int rss_spread)
{
	int rc = 0;

	if (efx->rss_spread == rss_spread)
		return 0;

	efx->rss_spread = rss_spread;
	if (!efx->filter_state)
		return 0;

	efx_mcdi_rx_free_indir_table(efx);
	if (rss_spread > 1) {
		efx_set_default_rx_indir_table(efx, &efx->rss_context);
		rc = efx->type->rx_push_rss_config(efx, false,
				   efx->rss_context.rx_indir_table, NULL);
	}
	return rc;
}

