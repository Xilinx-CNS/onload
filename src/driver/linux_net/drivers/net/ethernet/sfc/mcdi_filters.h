/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_MCDI_FILTERS_H
#define EFX_MCDI_FILTERS_H

#include "net_driver.h"

/* set up basic operations required for all net devices */
int efx_mcdi_filter_table_probe(struct efx_nic *efx, bool rss_limited,
				bool additional_rss);
/* enable operations we can do once we know the number of queues we have */
int efx_mcdi_filter_table_init(struct efx_nic *efx, bool mc_chaining,
			       bool encap);
/* opposite of init */
void efx_mcdi_filter_table_fini(struct efx_nic *efx);
/* opposite of probe */
void efx_mcdi_filter_table_remove(struct efx_nic *efx);
/* interface up */
int efx_mcdi_filter_table_up(struct efx_nic *efx);
/* interface down */
void efx_mcdi_filter_table_down(struct efx_nic *efx);
/* called post-reset while interface is up */
void efx_mcdi_filter_table_restore(struct efx_nic *efx);

void efx_mcdi_filter_table_reset_mc_allocations(struct efx_nic *efx);

/* The filter table(s) are managed by firmware and we have write-only
 * access.  When removing filters we must identify them to the
 * firmware by a 64-bit handle, but this is too wide for Linux kernel
 * interfaces (32-bit for RX NFC, 16-bit for RFS).  Also, we need to
 * be able to tell in advance whether a requested insertion will
 * replace an existing filter.  Therefore we maintain a software hash
 * table, which should be at least as large as the hardware hash
 * table.
 *
 * Huntington has a single 8K filter table shared between all filter
 * types and both ports.
 */
#define EFX_MCDI_FILTER_TBL_ROWS 8192

int efx_mcdi_filter_probe_supported_filters(struct efx_nic *efx);
bool efx_mcdi_filter_match_supported(struct efx_nic *efx,
				     bool encap,
				     unsigned int match_flags);

void efx_mcdi_filter_sync_rx_mode(struct efx_nic *efx);
s32 efx_mcdi_filter_insert(struct efx_nic *efx,
			   const struct efx_filter_spec *spec,
			   bool replace_equal);
int efx_mcdi_filter_redirect(struct efx_nic *efx, u32 filter_id,
			     u32 *rss_context, int rxq_i, int stack_id);
int efx_mcdi_filter_remove_safe(struct efx_nic *efx,
				enum efx_filter_priority priority,
				u32 filter_id);
int efx_mcdi_filter_get_safe(struct efx_nic *efx,
			     enum efx_filter_priority priority,
			     u32 filter_id, struct efx_filter_spec *spec);

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
int efx_mcdi_filter_block_kernel(struct efx_nic *efx,
				 enum efx_dl_filter_block_kernel_type type);
void efx_mcdi_filter_unblock_kernel(struct efx_nic *efx,
				    enum efx_dl_filter_block_kernel_type type);
#endif
#endif

u32 efx_mcdi_filter_count_rx_used(struct efx_nic *efx,
			 	  enum efx_filter_priority priority);
int efx_mcdi_filter_clear_rx(struct efx_nic *efx,
			     enum efx_filter_priority priority);
u32 efx_mcdi_filter_get_rx_id_limit(struct efx_nic *efx);
s32 efx_mcdi_filter_get_rx_ids(struct efx_nic *efx,
			       enum efx_filter_priority priority,
			       u32 *buf, u32 size);

int efx_mcdi_filter_add_vlan(struct efx_nic *efx, u16 vid);
int efx_mcdi_filter_del_vlan(struct efx_nic *efx, u16 vid);

static inline int efx_mcdi_filter_add_vid(struct efx_nic *efx,
					  __be16 proto, u16 vid)
{
	if (proto != htons(ETH_P_8021Q))
		return -EINVAL;

	return efx_mcdi_filter_add_vlan(efx, vid);
}

static inline int efx_mcdi_filter_del_vid(struct efx_nic *efx,
					  __be16 proto, u16 vid)
{
	if (proto != htons(ETH_P_8021Q))
		return -EINVAL;

	return efx_mcdi_filter_del_vlan(efx, vid);
}

void efx_mcdi_rx_free_indir_table(struct efx_nic *efx);
int efx_mcdi_rx_push_rss_context_config(struct efx_nic *efx,
				 	struct efx_rss_context *ctx,
					const u32 *rx_indir_table,
					const u8 *key);
int efx_mcdi_pf_rx_push_rss_config(struct efx_nic *efx, bool user,
				   const u32 *rx_indir_table,
				   const u8 *key);
int efx_mcdi_vf_rx_push_rss_config(struct efx_nic *efx, bool user,
				   const u32 *rx_indir_table
				   __attribute__ ((unused)),
				   const u8 *key
				   __attribute__ ((unused)));
int efx_mcdi_push_default_indir_table(struct efx_nic *efx,
				      unsigned int rss_spread);
int efx_mcdi_rx_pull_rss_config(struct efx_nic *efx);
int efx_mcdi_rx_pull_rss_context_config(struct efx_nic *efx,
					struct efx_rss_context *ctx);
u32 efx_mcdi_get_default_rss_flags(struct efx_nic *efx);
int efx_mcdi_get_rss_context_flags(struct efx_nic *efx,
				   struct efx_rss_context *ctx);
int efx_mcdi_set_rss_context_flags(struct efx_nic *efx,
				   struct efx_rss_context *ctx, u32 flags);
void efx_mcdi_rx_restore_rss_contexts(struct efx_nic *efx);

bool efx_mcdi_filter_rfs_expire_one(struct efx_nic *efx, u32 flow_id,
				    unsigned int filter_idx);

#endif
