/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#ifndef EFX_MCDI_PORT_COMMON_H
#define EFX_MCDI_PORT_COMMON_H

#include "net_driver.h"
#include "mcdi.h"
#include "mcdi_pcol.h"

#define MCDI_PORT_SPEED_CAPS   ((1 << MC_CMD_PHY_CAP_10HDX_LBN) | \
				(1 << MC_CMD_PHY_CAP_10FDX_LBN) | \
				(1 << MC_CMD_PHY_CAP_100HDX_LBN) | \
				(1 << MC_CMD_PHY_CAP_100FDX_LBN) | \
				(1 << MC_CMD_PHY_CAP_1000HDX_LBN) | \
				(1 << MC_CMD_PHY_CAP_1000FDX_LBN) | \
				(1 << MC_CMD_PHY_CAP_10000FDX_LBN) | \
				(1 << MC_CMD_PHY_CAP_40000FDX_LBN) | \
				(1 << MC_CMD_PHY_CAP_100000FDX_LBN) | \
				(1 << MC_CMD_PHY_CAP_25000FDX_LBN) | \
				(1 << MC_CMD_PHY_CAP_50000FDX_LBN))

#define SET_LINK_SEQ_IGNORE (1 << MC_CMD_SET_LINK_IN_V2_MODULE_SEQ_IGNORE_LBN)

struct efx_mcdi_phy_data {
	u32 flags;
	u32 type;
	u32 supported_cap;
	u32 channel;
	u32 port;
	u32 stats_mask;
	u8 name[20];
	u32 media;
	u32 mmd_mask;
	u8 revision[20];
#ifdef CONFIG_SFC_DEBUGFS
	struct efx_nic *efx;
	void *stats;
	dma_addr_t stats_addr;
	u8 index[MC_CMD_PHY_NSTATS];
#endif
};

void mcdi_to_ethtool_linkset(struct efx_nic *efx, u32 media, u32 cap,
			     unsigned long *linkset);
u32 mcdi_fec_caps_to_ethtool(u32 caps, bool is_25g);
u32 ethtool_linkset_to_mcdi_cap(const unsigned long *linkset);
u32 ethtool_fec_caps_to_mcdi(u32 supported_cap, u32 ethtool_cap);

u32 efx_get_mcdi_phy_flags(struct efx_nic *efx);
void efx_mcdi_phy_decode_link(struct efx_nic *efx,
			      struct efx_link_state *link_state,
			      u32 speed, u32 flags, u32 fcntl,
			      u32 ld_caps, u32 lp_caps);

int efx_mcdi_get_phy_cfg(struct efx_nic *efx, struct efx_mcdi_phy_data *cfg);
void efx_link_set_wanted_fc(struct efx_nic *efx, u8);
void efx_link_set_advertising(struct efx_nic *efx, const unsigned long *);
int efx_mcdi_set_link(struct efx_nic *efx, u32 capabilities,
		      u32 flags, u32 loopback_mode, bool async, u8 seq);
int efx_mcdi_loopback_modes(struct efx_nic *efx, u64 *loopback_modes);
void efx_mcdi_phy_check_fcntl(struct efx_nic *efx, u32 lpa);
bool efx_mcdi_phy_poll(struct efx_nic *efx);
int efx_mcdi_phy_probe(struct efx_nic *efx);
void efx_mcdi_phy_remove(struct efx_nic *efx);
void efx_mcdi_phy_get_settings(struct efx_nic *efx, struct ethtool_cmd *ecmd);
int efx_mcdi_phy_set_settings(struct efx_nic *efx, struct ethtool_cmd *ecmd,
			      unsigned long *new_adv);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_LINKSETTINGS)
int efx_mcdi_phy_set_ksettings(struct efx_nic *efx,
			       const struct ethtool_link_ksettings *settings,
			       unsigned long *advertising);
void efx_mcdi_phy_get_ksettings(struct efx_nic *efx,
				struct ethtool_link_ksettings *out);
#endif

int efx_mcdi_phy_get_fecparam(struct efx_nic *efx, struct ethtool_fecparam *fec);
int efx_mcdi_phy_set_fecparam(struct efx_nic *efx,
			      const struct ethtool_fecparam *fec);
int efx_mcdi_phy_test_alive(struct efx_nic *efx);
u32 efx_get_mcdi_caps(struct efx_nic *efx);

int efx_mcdi_set_mac(struct efx_nic *efx);
int efx_mcdi_set_mtu(struct efx_nic *efx);

void efx_mcdi_mac_update_stats_period(struct efx_nic *efx);
void efx_mcdi_mac_start_stats(struct efx_nic *efx);
void efx_mcdi_mac_stop_stats(struct efx_nic *efx);
void efx_mcdi_mac_pull_stats(struct efx_nic *efx);
int efx_mcdi_mac_init_stats(struct efx_nic *efx);
void efx_mcdi_mac_fini_stats(struct efx_nic *efx);

int efx_mcdi_port_reconfigure(struct efx_nic *efx);
int efx_mcdi_port_get_number(struct efx_nic *efx);
bool efx_mcdi_port_process_event_common(struct efx_channel *channel,
					efx_qword_t *event, int *rc,
					int budget);
void efx_mcdi_process_link_change(struct efx_nic *efx, efx_qword_t *ev);
void efx_mcdi_process_link_change_v2(struct efx_nic *efx, efx_qword_t *ev);
void efx_mcdi_process_module_change(struct efx_nic *efx, efx_qword_t *ev);

int efx_mcdi_phy_run_tests(struct efx_nic *efx, int *results,
			   unsigned int flags);
const char *efx_mcdi_phy_test_name(struct efx_nic *efx,
				   unsigned int index);

int efx_mcdi_phy_get_module_eeprom(struct efx_nic *efx,
				   struct ethtool_eeprom *ee, u8 *data);
int efx_mcdi_phy_get_module_info(struct efx_nic *efx,
				 struct ethtool_modinfo *modinfo);

#endif

