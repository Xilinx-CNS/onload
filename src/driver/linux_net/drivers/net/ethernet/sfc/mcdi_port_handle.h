/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Driver for Solarflare and Xilinx network controllers and boards
 * Copyright 2024 Advanced Micro Devices, Inc.
 */
#ifndef EFX_MCDI_PORT_HANDLE_H
#define EFX_MCDI_PORT_HANDLE_H

struct efx_x4_mcdi_port_data {
	/* Hardware properties */
	struct {
		DECLARE_BITMAP(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);
		u32 fec;
		u8 pause;
		u16 max_frame_len;
		u64 loopback;
	} fixed_port;
	struct {
		DECLARE_BITMAP(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);
		u32 preferred_fec;
		u8 medium;
		u8 media_subtype;
	} transceiver;

	/* Link properties */
	struct {
		DECLARE_BITMAP(tech_mask, MC_CMD_ETH_TECH_TECH_WIDTH);
		u32 requested_fec;
		u32 fec;
		u8 pause;
	} supported, advertised, partner;

	/* Link state */
	struct {
		u64 status;
		u32 control;
		u32 supported_autoneg;
		u16 tech;
		u8 fec;
		u8 pause;
		u8 loopback;
		u8 module_seq;
		bool duplex;
		unsigned int speed;
	} link;
};

int efx_mcdi_get_port_handle(struct efx_nic *efx, u32 *handle);

int efx_x4_mcdi_mac_ctrl(struct efx_nic *efx);
int efx_x4_mcdi_set_mtu(struct efx_nic *efx);

void efx_x4_init_hw_stat_desc(struct efx_nic *efx);
int efx_x4_mcdi_probe_stats(struct efx_nic *efx, u16 *num_stats,
			    size_t *stats_dma_size);

void efx_x4_mcdi_phy_get_settings(struct efx_nic *efx,
				  struct ethtool_cmd *ecmd);
int efx_x4_mcdi_phy_set_settings(struct efx_nic *efx,
				 struct ethtool_cmd *ecmd,
				 unsigned long *new_adv);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_LINKSETTINGS)
void efx_x4_mcdi_phy_get_ksettings(struct efx_nic *efx,
				   struct ethtool_link_ksettings *out);
int efx_x4_mcdi_phy_set_ksettings(struct efx_nic *efx,
				  const struct ethtool_link_ksettings *settings,
				  unsigned long *advertising);
#endif

int efx_x4_mcdi_phy_get_fecparam(struct efx_nic *efx,
				 struct ethtool_fecparam *fec);
int efx_x4_mcdi_phy_set_fecparam(struct efx_nic *efx,
				 const struct ethtool_fecparam *fec);

int efx_x4_mcdi_nway_reset(struct efx_nic *efx);

int efx_x4_mcdi_port_reconfigure(struct efx_nic *efx);

int efx_x4_mcdi_phy_probe(struct efx_nic *efx);
void efx_x4_mcdi_phy_remove(struct efx_nic *efx);
bool efx_x4_mcdi_phy_poll(struct efx_nic *efx);

void efx_x4_check_module_caps(struct efx_nic *efx);

int efx_x4_mcdi_enable_netport_events(struct efx_nic *efx);
void efx_x4_mcdi_process_link_change(struct efx_nic *efx, efx_qword_t *ev);
void efx_x4_mcdi_process_module_change(struct efx_nic *efx, efx_qword_t *ev);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_EEPROM_BY_PAGE)
int efx_mcdi_x4_get_module_data(struct efx_nic *efx,
				const struct ethtool_module_eeprom *page,
				struct netlink_ext_ack *extack);
#endif

#endif
