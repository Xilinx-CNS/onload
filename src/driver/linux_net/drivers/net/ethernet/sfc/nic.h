/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_NIC_H
#define EFX_NIC_H

#include "nic_common.h"
#include "efx.h"

enum {
	PHY_TYPE_NONE = 0,
	PHY_TYPE_TXC43128 = 1,
	PHY_TYPE_88E1111 = 2,
	PHY_TYPE_SFX7101 = 3,
	PHY_TYPE_QT2022C2 = 4,
	PHY_TYPE_PM8358 = 6,
	PHY_TYPE_SFT9001A = 8,
	PHY_TYPE_QT2025C = 9,
	PHY_TYPE_SFT9001B = 10,
};

enum {
	EF10_STAT_port_tx_bytes = GENERIC_STAT_COUNT,
	EF10_STAT_port_tx_packets,
	EF10_STAT_port_tx_pause,
	EF10_STAT_port_tx_control,
	EF10_STAT_port_tx_unicast,
	EF10_STAT_port_tx_multicast,
	EF10_STAT_port_tx_broadcast,
	EF10_STAT_port_tx_lt64,
	EF10_STAT_port_tx_64,
	EF10_STAT_port_tx_65_to_127,
	EF10_STAT_port_tx_128_to_255,
	EF10_STAT_port_tx_256_to_511,
	EF10_STAT_port_tx_512_to_1023,
	EF10_STAT_port_tx_1024_to_15xx,
	EF10_STAT_port_tx_15xx_to_jumbo,
	EF10_STAT_port_rx_bytes,
	EF10_STAT_port_rx_bytes_minus_good_bytes,
	EF10_STAT_port_rx_good_bytes,
	EF10_STAT_port_rx_bad_bytes,
	EF10_STAT_port_rx_packets,
	EF10_STAT_port_rx_good,
	EF10_STAT_port_rx_bad,
	EF10_STAT_port_rx_pause,
	EF10_STAT_port_rx_control,
	EF10_STAT_port_rx_unicast,
	EF10_STAT_port_rx_multicast,
	EF10_STAT_port_rx_broadcast,
	EF10_STAT_port_rx_lt64,
	EF10_STAT_port_rx_64,
	EF10_STAT_port_rx_65_to_127,
	EF10_STAT_port_rx_128_to_255,
	EF10_STAT_port_rx_256_to_511,
	EF10_STAT_port_rx_512_to_1023,
	EF10_STAT_port_rx_1024_to_15xx,
	EF10_STAT_port_rx_15xx_to_jumbo,
	EF10_STAT_port_rx_gtjumbo,
	EF10_STAT_port_rx_bad_gtjumbo,
	EF10_STAT_port_rx_overflow,
	EF10_STAT_port_rx_align_error,
	EF10_STAT_port_rx_length_error,
	EF10_STAT_port_rx_nodesc_drops,
	EF10_STAT_port_rx_pm_trunc_bb_overflow,
	EF10_STAT_port_rx_pm_discard_bb_overflow,
	EF10_STAT_port_rx_pm_trunc_vfifo_full,
	EF10_STAT_port_rx_pm_discard_vfifo_full,
	EF10_STAT_port_rx_pm_trunc_qbb,
	EF10_STAT_port_rx_pm_discard_qbb,
	EF10_STAT_port_rx_pm_discard_mapping,
	EF10_STAT_port_rx_dp_q_disabled_packets,
	EF10_STAT_port_rx_dp_di_dropped_packets,
	EF10_STAT_port_rx_dp_streaming_packets,
	EF10_STAT_port_rx_dp_hlb_fetch,
	EF10_STAT_port_rx_dp_hlb_wait,
	EF10_STAT_port_COUNT,
	EF10_STAT_rx_unicast = EF10_STAT_port_COUNT,
	EF10_STAT_rx_unicast_bytes,
	EF10_STAT_rx_multicast,
	EF10_STAT_rx_multicast_bytes,
	EF10_STAT_rx_broadcast,
	EF10_STAT_rx_broadcast_bytes,
	EF10_STAT_rx_bad,
	EF10_STAT_rx_bad_bytes,
	EF10_STAT_rx_overflow,
	EF10_STAT_tx_unicast,
	EF10_STAT_tx_unicast_bytes,
	EF10_STAT_tx_multicast,
	EF10_STAT_tx_multicast_bytes,
	EF10_STAT_tx_broadcast,
	EF10_STAT_tx_broadcast_bytes,
	EF10_STAT_tx_bad,
	EF10_STAT_tx_bad_bytes,
	EF10_STAT_tx_overflow,
	EF10_STAT_V1_COUNT,
	EF10_STAT_fec_uncorrected_errors = EF10_STAT_V1_COUNT,
	EF10_STAT_fec_corrected_errors,
	EF10_STAT_fec_corrected_symbols_lane0,
	EF10_STAT_fec_corrected_symbols_lane1,
	EF10_STAT_fec_corrected_symbols_lane2,
	EF10_STAT_fec_corrected_symbols_lane3,
	EF10_STAT_ctpio_vi_busy_fallback,
	EF10_STAT_ctpio_long_write_success,
	EF10_STAT_ctpio_missing_dbell_fail,
	EF10_STAT_ctpio_overflow_fail,
	EF10_STAT_ctpio_underflow_fail,
	EF10_STAT_ctpio_timeout_fail,
	EF10_STAT_ctpio_noncontig_wr_fail,
	EF10_STAT_ctpio_frm_clobber_fail,
	EF10_STAT_ctpio_invalid_wr_fail,
	EF10_STAT_ctpio_vi_clobber_fallback,
	EF10_STAT_ctpio_unqualified_fallback,
	EF10_STAT_ctpio_runt_fallback,
	EF10_STAT_ctpio_success,
	EF10_STAT_ctpio_fallback,
	EF10_STAT_ctpio_poison,
	EF10_STAT_ctpio_erase,
	EF10_STAT_COUNT
};

/* Maximum number of TX PIO buffers we may allocate to a function.
 * This matches the total number of buffers on each SFC9100-family
 * controller.
 */
#define EF10_TX_PIOBUF_COUNT 16

#define EF10_NUM_MCDI_BUFFERS 1

/**
 * struct efx_ef10_nic_data - EF10 architecture NIC state
 * @efx: Pointer back to main interface structure
 * @mcdi_buf: DMA buffer for MCDI
 * @mcdi_buf_use: bitmap of which MCDI buffers are used
 * @warm_boot_count: Last seen MC warm boot count
 * @bist_warm_boot_count: Value of @warm_boot_count at start of BIST
 * @n_allocated_vis: Number of VIs allocated to this function
 * @must_realloc_vis: Flag: VIs have yet to be reallocated after MC reboot
 *	MC reboot
 * @must_restore_vports: Flag: V-ports have yet to be restored after MC reboot
 * @n_piobufs: Number of PIO buffers allocated to this function
 * @wc_membase: Base address of write-combining mapping of the memory BAR
 * @pio_write_base: Base address for writing PIO buffers
 * @pio_write_vi_base: Relative VI number for @pio_write_base
 * @piobuf_handle: Handle of each PIO buffer allocated
 * @piobuf_size: size of a single PIO buffer
 * @must_restore_piobufs: Flag: PIO buffers have yet to be restored after MC
 *	reboot
 * @mc_stats: Scratch buffer for converting statistics to the kernel's format
 * @stats: Hardware statistics
 * @vf_stats_work: Work item to poll hardware statistics (VF driver only)
 * @x4_stats_mask: Netport supported statistics mask
 * @x4_stat_desc: Netport statistics descriptions
 * @workaround_35388: Flag: firmware supports workaround for bug 35388
 * @workaround_26807: Flag: firmware supports workaround for bug 26807
 * @workaround_61265: Flag: firmware supports workaround for bug 61265
 * @must_check_datapath_caps: Flag: @datapath_caps needs to be revalidated
 *	after MC reboot
 * @datapath_caps: Capabilities of datapath firmware (FLAGS1 field of
 *	%MC_CMD_GET_CAPABILITIES response)
 * @datapath_caps2: Further capabilities of datapath firmware (FLAGS2 field of
 *	%MC_CMD_GET_CAPABILITIES_V2 response)
 * @must_reprobe_sensors: Flag: sensors have yet to be reprobed after MC reboot
 * @must_probe_vswitching: Flag: vswitching has yet to be setup after MC reboot
 * @pf_index: The number for this PF, or the parent PF if this is a VF
 * @vf_index: The number for this VF, or 0xFFFF if this is a PF
 * @port_id: Physical port identity
 * @vport_mac: The MAC address on the vport, only for PFs; VFs will be zero
 * @udp_tunnels: UDP tunnel port numbers and types.
 * @licensed_features: Flags for licensed firmware features.
 */
struct efx_ef10_nic_data {
	struct efx_nic *efx;
	struct efx_buffer mcdi_buf;
	unsigned long mcdi_buf_use;
	u16 warm_boot_count;
	u16 bist_warm_boot_count;
	unsigned int n_allocated_vis;
	bool must_realloc_vis;
	bool must_restore_vports;
	unsigned int n_piobufs;
	void __iomem *wc_membase, *pio_write_base;
	unsigned int pio_write_vi_base;
	unsigned int piobuf_handle[EF10_TX_PIOBUF_COUNT];
	u16 piobuf_size;
	bool must_restore_piobufs;
	__le64 *mc_stats;
	u64 stats[EF10_STAT_COUNT];
	struct delayed_work vf_stats_work;
	DECLARE_BITMAP(x4_stats_mask, EF10_STAT_COUNT);
	struct efx_hw_stat_desc x4_stat_desc[EF10_STAT_COUNT];
	bool workaround_35388;
	bool workaround_26807;
	bool workaround_61265;
	bool must_check_datapath_caps;
	u32 datapath_caps;
	u32 datapath_caps2;
	bool must_reprobe_sensors;
	bool must_probe_vswitching;
	unsigned int pf_index;
	unsigned int vf_index;
	u8 port_id[ETH_ALEN];
#ifdef CONFIG_SFC_SRIOV
	/** @max_vfs: Number of VFs to be initialised by the driver */
	int max_vfs;
	/** @vf_count: Number of VFs intended to be enabled */
	unsigned int vf_count;
	/** @vf: Pointer to VF data structure */
	struct ef10_vf *vf;
#endif
	u8 vport_mac[ETH_ALEN];
	struct efx_udp_tunnel udp_tunnels[16];
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	/**
	 * @udp_tunnels_dirty: flag indicating a reboot occurred while
	 *	pushing @udp_tunnels to hardware and thus the push must be
	 *	re-done.
	 */
	bool udp_tunnels_dirty;
	/**
	* @udp_tunnels_lock: Serialises writes to @udp_tunnels and
	*	@udp_tunnels_dirty.
	*/
	struct mutex udp_tunnels_lock;
#else
	/**
	 * @udp_tunnels_busy: Indicates if efx_ef10_set_udp_tnl_ports()
	 *	is currently running.
	 */
	bool udp_tunnels_busy;
	/**
	* @udp_tunnels_lock: Serialises writes to @udp_tunnels and
	*	@udp_tunnels_dirty.
	*/
	spinlock_t udp_tunnels_lock;
	/**
	 * @udp_tunnel_work: workitem for pushing UDP tunnel ports to the MC.
	 */
	struct work_struct udp_tunnel_work;
#endif
	u64 licensed_features;
};

#define efx_ef10_has_cap(caps, flag) \
	(!!((caps) & BIT_ULL(MC_CMD_GET_CAPABILITIES_V4_OUT_ ## flag ## _LBN)))

#ifdef EFX_NOT_UPSTREAM
struct efx_update_license2;
int efx_ef10_update_keys(struct efx_nic *efx,
			 struct efx_update_license2 *key_stats);
struct efx_licensed_app_state;
int efx_ef10_licensed_app_state(struct efx_nic *efx,
				struct efx_licensed_app_state *app_state);
#endif

extern const struct efx_nic_type efx_hunt_a0_nic_type;
extern const struct efx_nic_type efx_hunt_a0_vf_nic_type __attribute__((weak));

extern const struct efx_nic_type efx_x4_nic_type;
extern const struct efx_nic_type efx_x4_vf_nic_type __attribute__((weak));

/* Only safe to call if protected against rep create/destroy */
static inline struct net_device *efx_get_vf_rep(struct efx_nic *efx, unsigned int vf)
{
	if (efx->type->get_vf_rep == NULL)
		return ERR_PTR(-EOPNOTSUPP);
	return efx->type->get_vf_rep(efx, vf);
}

#endif /* EFX_NIC_H */
