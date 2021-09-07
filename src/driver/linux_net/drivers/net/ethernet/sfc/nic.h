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

#ifndef EFX_USE_KCOMPAT
#include <linux/net_tstamp.h>
#endif
#include <linux/timer.h>

#include "net_driver.h"
#include "efx.h"
#include "mcdi.h"

enum {
	/* Revisions 0-3 were Falcon A0, A1, B0 and Siena respectively.
	 * They are not supported by this driver but these revision numbers
	 * form part of the ethtool API for register dumping.
	 */
	EFX_REV_HUNT_A0 = 4,
	EFX_REV_EF100 = 5,
};

static inline int efx_nic_rev(struct efx_nic *efx)
{
	return efx->type->revision;
}

/* Read the current event from the event queue */
static inline efx_qword_t *efx_event(struct efx_channel *channel,
				     unsigned int index)
{
	return ((efx_qword_t *)(channel->eventq.addr)) +
		(index & channel->eventq_mask);
}

/* See if an event is present
 *
 * We check both the high and low dword of the event for all ones.  We
 * wrote all ones when we cleared the event, and no valid event can
 * have all ones in either its high or low dwords.  This approach is
 * robust against reordering.
 *
 * Note that using a single 64-bit comparison is incorrect; even
 * though the CPU read will be atomic, the DMA write may not be.
 */
static inline int efx_event_present(efx_qword_t *event)
{
	return !(EFX_DWORD_IS_ALL_ONES(event->dword[0]) |
		  EFX_DWORD_IS_ALL_ONES(event->dword[1]));
}

/* Returns a pointer to the specified transmit descriptor in the TX
 * descriptor queue belonging to the specified channel.
 */
static inline efx_qword_t *
efx_tx_desc(struct efx_tx_queue *tx_queue, unsigned int index)
{
	return ((efx_qword_t *)(tx_queue->txd.addr)) + index;
}

/* Report whether the NIC considers this TX queue empty, given the
 * write_count used for the last doorbell push.  May return false
 * negative.
 */
static inline bool __efx_nic_tx_is_empty(struct efx_tx_queue *tx_queue,
					 unsigned int write_count)
{
	unsigned int empty_read_count = READ_ONCE(tx_queue->empty_read_count);

	if (empty_read_count == 0)
		return false;

	return ((empty_read_count ^ write_count) & ~EFX_EMPTY_COUNT_VALID) == 0;
}

/* Returns a pointer to the specified descriptor in the RX descriptor queue */
static inline efx_qword_t *
efx_rx_desc(struct efx_rx_queue *rx_queue, unsigned int index)
{
	return ((efx_qword_t *)(rx_queue->rxd.addr)) + index;
}

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

/* Alignment of PCIe DMA boundaries (4KB) */
#define EFX_PAGE_SIZE	4096
/* Size and alignment of buffer table entries (same) */
#define EFX_BUF_SIZE	EFX_PAGE_SIZE

/* NIC-generic software stats */
enum {
	GENERIC_STAT_rx_noskb_drops,
	GENERIC_STAT_rx_nodesc_trunc,
	GENERIC_STAT_COUNT
};

#define EFX_GENERIC_SW_STAT(ext_name)				\
	[GENERIC_STAT_ ## ext_name] = { #ext_name, 0, 0 }

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
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
 * @vf_stats_enabled: Marker to avoid stats work rearming if
 *	cancel_delayed_work_sync() is not availble. Serialized by stats_lock.
#endif
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
#ifdef CONFIG_SFC_SRIOV
 * @vf: Pointer to VF data structure
#endif
 * @vport_mac: The MAC address on the vport, only for PFs; VFs will be zero
 * @udp_tunnel_work: workitem for pushing UDP tunnel ports to the MC
 * @udp_tunnels: UDP tunnel port numbers and types.
 * @udp_tunnels_dirty: flag indicating a reboot occurred while pushing
 *	@udp_tunnels to hardware and thus the push must be re-done.
 * @udp_tunnels_lock: Serialises writes to @udp_tunnels and @udp_tunnels_dirty.
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
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	bool vf_stats_enabled;
#endif
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
	struct ef10_vf *vf;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
	uint32_t caps;
#endif
	u8 vport_mac[ETH_ALEN];
	struct efx_udp_tunnel udp_tunnels[16];
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	bool udp_tunnels_dirty;
	struct mutex udp_tunnels_lock;
#else
	/* Indicates whether efx_ef10_set_udp_tnl_ports() is currently running.	*/
	bool udp_tunnels_busy;
	spinlock_t udp_tunnels_lock;
	struct work_struct udp_tunnel_work;
#endif
	u64 licensed_features;
};

#define efx_ef10_has_cap(caps, flag) \
	(!!((caps) & BIT_ULL(MC_CMD_GET_CAPABILITIES_V4_OUT_ ## flag ## _LBN)))

struct ethtool_ts_info;
#ifdef CONFIG_SFC_PTP
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
struct hwtstamp_config;
struct efx_ts_read;
int efx_ptp_ts_init(struct efx_nic *efx, struct hwtstamp_config *init);
int efx_ptp_ts_read(struct efx_nic *efx, struct efx_ts_read *read);
#endif
#if defined(EFX_NOT_UPSTREAM)
struct efx_ts_settime;
struct efx_ts_adjtime;
struct efx_ts_sync;
struct efx_ts_set_sync_status;
struct efx_ts_set_vlan_filter;
struct efx_ts_set_uuid_filter;
struct efx_ts_set_domain_filter;
int efx_ptp_ts_settime(struct efx_nic *efx, struct efx_ts_settime *settime);
int efx_ptp_ts_adjtime(struct efx_nic *efx, struct efx_ts_adjtime *adjtime);
int efx_ptp_ts_sync(struct efx_nic *efx, struct efx_ts_sync *sync);
int efx_ptp_ts_set_sync_status(struct efx_nic *efx, struct efx_ts_set_sync_status *status);
#endif
void efx_ptp_remove_post_io(struct efx_nic *efx);
int efx_ptp_probe(struct efx_nic *efx, struct efx_channel *channel);
int efx_ptp_defer_probe_with_channel(struct efx_nic *efx);
struct efx_channel *efx_ptp_channel(struct efx_nic *efx);
void efx_ptp_remove(struct efx_nic *efx);
int efx_ptp_set_ts_config(struct efx_nic *efx, struct ifreq *ifr);
int efx_ptp_get_ts_config(struct efx_nic *efx, struct ifreq *ifr);
void efx_ptp_get_ts_info(struct efx_nic *efx, struct ethtool_ts_info *ts_info);
int efx_ptp_get_attributes(struct efx_nic *efx);
bool efx_ptp_uses_separate_channel(struct efx_nic *efx);
bool efx_ptp_is_ptp_tx(struct efx_nic *efx, struct sk_buff *skb);
int efx_ptp_get_mode(struct efx_nic *efx);
int efx_ptp_change_mode(struct efx_nic *efx, bool enable_wanted,
			unsigned int new_mode);
int efx_ptp_tx(struct efx_nic *efx, struct sk_buff *skb);
void efx_ptp_event(struct efx_nic *efx, efx_qword_t *ev);
size_t efx_ptp_describe_stats(struct efx_nic *efx, u8 *strings);
void efx_ptp_reset_stats(struct efx_nic *efx);
size_t efx_ptp_update_stats(struct efx_nic *efx, u64 *stats);
void efx_time_sync_event(struct efx_channel *channel, efx_qword_t *ev);
void __efx_rx_skb_attach_timestamp(struct efx_channel *channel,
				   struct sk_buff *skb,
				   const u8 *prefix);
static inline void efx_rx_skb_attach_timestamp(struct efx_channel *channel,
					       struct sk_buff *skb,
					       const u8 *prefix)
{
	__efx_rx_skb_attach_timestamp(channel, skb, prefix);
}
void efx_ptp_start_datapath(struct efx_nic *efx);
void efx_ptp_stop_datapath(struct efx_nic *efx);
bool efx_ptp_use_mac_tx_timestamps(struct efx_nic *efx);
ktime_t efx_ptp_nic_to_kernel_time(struct efx_tx_queue *tx_queue);
#else
static inline int efx_ptp_probe(struct efx_nic *efx, struct efx_channel *channel)
{ return -ENODEV; }
static inline int efx_ptp_defer_probe_with_channel(struct efx_nic *efx)
{
	return 0;
}
static inline struct efx_channel *efx_ptp_channel(struct efx_nic *efx)
{
	return NULL;
}
static inline void efx_ptp_remove(struct efx_nic *efx) {}
static inline int efx_ptp_set_ts_config(struct efx_nic *efx, struct ifreq *ifr) {return -EOPNOTSUPP; }
static inline int efx_ptp_get_ts_config(struct efx_nic *efx, struct ifreq *ifr) {return -EOPNOTSUPP; }
static inline int efx_ptp_get_ts_info(struct efx_nic *efx,
				      struct ethtool_ts_info *ts_info)
{ return -EOPNOTSUPP; }
static inline int efx_ptp_get_attributes(struct efx_nic *efx)
{ return 0; }
static inline bool efx_ptp_uses_separate_channel(struct efx_nic *efx)
{ return false; }
static inline bool efx_ptp_is_ptp_tx(struct efx_nic *efx, struct sk_buff *skb) { return false; }
static inline int efx_ptp_tx(struct efx_nic *efx, struct sk_buff *skb) { return NETDEV_TX_OK; }
static inline void efx_ptp_event(struct efx_nic *efx, efx_qword_t *ev) {}
static inline size_t efx_ptp_describe_stats(struct efx_nic *efx, u8 *strings)
{ return 0; }
static inline void efx_ptp_reset_stats(struct efx_nic *efx) {}
static inline size_t efx_ptp_update_stats(struct efx_nic *efx, u64 *stats)
{ return 0; }
static inline void efx_rx_skb_attach_timestamp(struct efx_channel *channel,
					       struct sk_buff *skb,
					       const u8 *prefix) {}
static inline void efx_time_sync_event(struct efx_channel *channel,
				       efx_qword_t *ev) {}
static inline void efx_ptp_start_datapath(struct efx_nic *efx) {}
static inline void efx_ptp_stop_datapath(struct efx_nic *efx) {}
static inline bool efx_ptp_use_mac_tx_timestamps(struct efx_nic *efx)
{
	return false;
}
static inline ktime_t efx_ptp_nic_to_kernel_time(struct efx_tx_queue *tx_queue)
{
	return (ktime_t) { 0 };
}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
struct efx_ts_get_pps;
struct efx_ts_hw_pps;
#ifdef CONFIG_SFC_PTP
int efx_ptp_pps_get_event(struct efx_nic *efx, struct efx_ts_get_pps *data);
int efx_ptp_hw_pps_enable(struct efx_nic *efx, bool enable);
#else
static inline int efx_ptp_pps_get_event(struct efx_nic *efx,
					struct efx_ts_get_pps *data)
{
	return -EOPNOTSUPP;
}
static inline int efx_ptp_hw_pps_enable(struct efx_nic *efx, bool enable)
{
	return -EOPNOTSUPP;
}
#endif
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
int efx_aoe_attach(struct efx_nic *efx);
void efx_aoe_detach(struct efx_nic *efx);
#endif

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

/* Only safe to call if protected against rep create/destroy */
static inline struct net_device *efx_get_vf_rep(struct efx_nic *efx, unsigned int vf)
{
	if (efx->type->get_vf_rep == NULL)
		return ERR_PTR(-EOPNOTSUPP);
	return efx->type->get_vf_rep(efx, vf);
}

static inline struct net_device *efx_get_remote_rep(struct efx_nic *efx,
						    unsigned int idx)
{
	if (efx->type->get_remote_rep == NULL)
		return ERR_PTR(-EOPNOTSUPP);
	return efx->type->get_remote_rep(efx, idx);
}

/**************************************************************************
 *
 * Externs
 *
 **************************************************************************
 */

/* TX data path */
static inline int efx_nic_probe_tx(struct efx_tx_queue *tx_queue)
{
	return tx_queue->efx->type->tx_probe(tx_queue);
}
static inline int efx_nic_init_tx(struct efx_tx_queue *tx_queue)
{
	return tx_queue->efx->type->tx_init(tx_queue);
}
static inline void efx_nic_push_buffers(struct efx_tx_queue *tx_queue)
{
	tx_queue->efx->type->tx_write(tx_queue);
}
static inline void efx_nic_notify_tx_desc(struct efx_tx_queue *tx_queue)
{
	tx_queue->efx->type->tx_notify(tx_queue);
}
int efx_nic_tx_tso_sw(struct efx_tx_queue *tx_queue, struct sk_buff *skb,
		      bool *data_mapped);

/* RX data path */
static inline int efx_nic_probe_rx(struct efx_rx_queue *rx_queue)
{
	return rx_queue->efx->type->rx_probe(rx_queue);
}
static inline int efx_nic_init_rx(struct efx_rx_queue *rx_queue)
{
	return rx_queue->efx->type->rx_init(rx_queue);
}
static inline void efx_nic_remove_rx(struct efx_rx_queue *rx_queue)
{
	rx_queue->efx->type->rx_remove(rx_queue);
}
static inline void efx_nic_notify_rx_desc(struct efx_rx_queue *rx_queue)
{
	rx_queue->efx->type->rx_write(rx_queue);
}
static inline int efx_nic_generate_fill_event(struct efx_rx_queue *rx_queue)
{
	return rx_queue->efx->type->rx_defer_refill(rx_queue);
}

/* Event data path */
static inline int efx_nic_probe_eventq(struct efx_channel *channel)
{
	return channel->efx->type->ev_probe(channel);
}
static inline int efx_nic_init_eventq(struct efx_channel *channel)
{
	return channel->efx->type->ev_init(channel);
}
static inline void efx_nic_fini_eventq(struct efx_channel *channel)
{
	channel->efx->type->ev_fini(channel);
}
static inline void efx_nic_remove_eventq(struct efx_channel *channel)
{
	channel->efx->type->ev_remove(channel);
}
static inline int
efx_nic_process_eventq(struct efx_channel *channel, int quota)
{
	return channel->efx->type->ev_process(channel, quota);
}
static inline bool efx_nic_mcdi_ev_pending(struct efx_channel *channel)
{
	return channel->efx->type->ev_mcdi_pending(channel);
}
static inline void efx_nic_eventq_read_ack(struct efx_channel *channel)
{
	channel->efx->type->ev_read_ack(channel);
}
static inline bool efx_nic_hw_unavailable(struct efx_nic *efx)
{
	if (efx->type->hw_unavailable)
		return efx->type->hw_unavailable(efx);
	return false;
}
static inline bool efx_nic_has_dynamic_sensors(struct efx_nic *efx)
{
	if (efx->type->has_dynamic_sensors)
		return efx->type->has_dynamic_sensors(efx);

	return false;
}
void efx_nic_event_test_start(struct efx_channel *channel);
bool efx_nic_event_present(struct efx_channel *channel);

/* Some statistics are computed as A - B where A and B each increase
 * linearly with some hardware counter(s) and the counters are read
 * asynchronously.  If the counters contributing to B are always read
 * after those contributing to A, the computed value may be lower than
 * the true value by some variable amount, and may decrease between
 * subsequent computations.
 *
 * We should never allow statistics to decrease or to exceed the true
 * value.  Since the computed value will never be greater than the
 * true value, except when the MAC stats are zeroed as a result of a NIC reset
 * we can achieve this by only storing the computed value
 * when it increases, or when it is zeroed.
 */
static inline void efx_update_diff_stat(u64 *stat, u64 diff)
{
	if (!diff || (s64)(diff - *stat) > 0)
		*stat = diff;
}

/* Interrupts */
int efx_nic_init_interrupt(struct efx_nic *efx);
int efx_nic_irq_test_start(struct efx_nic *efx);
void efx_nic_fini_interrupt(struct efx_nic *efx);

static inline int efx_nic_event_test_irq_cpu(struct efx_channel *channel)
{
	return READ_ONCE(channel->event_test_cpu);
}
static inline int efx_nic_irq_test_irq_cpu(struct efx_nic *efx)
{
	return READ_ONCE(efx->last_irq_cpu);
}

/* Global Resources */
int efx_nic_flush_queues(struct efx_nic *efx);
void efx_ef10_handle_drain_event(struct efx_nic *efx);
void efx_nic_check_pcie_link(struct efx_nic *efx,
			     unsigned int desired_bandwidth,
			     unsigned int *actual_width,
			     unsigned int *actual_speed);

int efx_nic_alloc_buffer(struct efx_nic *efx, struct efx_buffer *buffer,
			 unsigned int len, gfp_t gfp_flags);
void efx_nic_free_buffer(struct efx_nic *efx, struct efx_buffer *buffer);

size_t efx_nic_get_regs_len(struct efx_nic *efx);
void efx_nic_get_regs(struct efx_nic *efx, void *buf);

#define EFX_MC_STATS_GENERATION_INVALID ((__force __le64)(-1))

size_t efx_nic_describe_stats(const struct efx_hw_stat_desc *desc, size_t count,
			      const unsigned long *mask, u8 *names);
int efx_nic_copy_stats(struct efx_nic *efx, __le64 *dest);
static inline int efx_nic_reset_stats(struct efx_nic *efx)
{
	return efx_nic_copy_stats(efx, efx->mc_initial_stats);
}
void efx_nic_update_stats(const struct efx_hw_stat_desc *desc, size_t count,
			  const unsigned long *mask, u64 *stats,
			  const void *mc_initial_stats, const void *mc_stats);
void efx_nic_fix_nodesc_drop_stat(struct efx_nic *efx, u64 *stat);

#define EFX_MAX_FLUSH_TIME 5000

bool efx_mcdi_port_process_event(struct efx_channel *channel, efx_qword_t *event,
				 int *rc, int budget);

#endif /* EFX_NIC_H */
