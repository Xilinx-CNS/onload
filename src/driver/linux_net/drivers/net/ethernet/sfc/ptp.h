/* SPDX-License-Identifier: GPL-2.0-only */
/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2013 Solarflare Communications Inc.
 * Copyright 2019-2022 Xilinx Inc.
 */

#ifndef EFX_PTP_H
#define EFX_PTP_H

#include <linux/net_tstamp.h>
#include "net_driver.h"

struct kernel_ethtool_ts_info;
#ifdef CONFIG_SFC_PTP
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
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_HWTSTAMP_GET)
int efx_ptp_set_ts_config(struct efx_nic *efx,
			  struct kernel_hwtstamp_config *config,
			  struct netlink_ext_ack *extack);
int efx_ptp_get_ts_config(struct efx_nic *efx,
			  struct kernel_hwtstamp_config *config);
#else
int efx_ptp_set_ts_config(struct efx_nic *efx, struct ifreq *ifr);
int efx_ptp_get_ts_config(struct efx_nic *efx, struct ifreq *ifr);
#endif
void efx_ptp_get_ts_info(struct efx_nic *efx,
			 struct kernel_ethtool_ts_info *ts_info);
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
ktime_t efx_ptp_nic_to_kernel_time(struct efx_tx_queue *tx_queue);
#else
static inline int efx_ptp_probe(struct efx_nic *efx, struct efx_channel *channel)
{
	return -ENODEV;
}
static inline int efx_ptp_defer_probe_with_channel(struct efx_nic *efx)
{
	return 0;
}
static inline struct efx_channel *efx_ptp_channel(struct efx_nic *efx)
{
	return NULL;
}
static inline void efx_ptp_remove(struct efx_nic *efx) {}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_HWTSTAMP_GET)
static inline int efx_ptp_set_ts_config(struct efx_nic *efx,
					struct kernel_hwtstamp_config *config,
					struct netlink_ext_ack *extack)
#else
static inline int efx_ptp_set_ts_config(struct efx_nic *efx, struct ifreq *ifr)
#endif
{
	return -EOPNOTSUPP;
}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_HWTSTAMP_GET)
static inline int efx_ptp_get_ts_config(struct efx_nic *efx,
					struct kernel_hwtstamp_config *config)
#else
static inline int efx_ptp_get_ts_config(struct efx_nic *efx, struct ifreq *ifr)
#endif
{
	return -EOPNOTSUPP;
}
static inline int efx_ptp_get_ts_info(struct efx_nic *efx,
				      struct ethtool_ts_info *ts_info)
{
	return -EOPNOTSUPP;
}
static inline int efx_ptp_get_attributes(struct efx_nic *efx)
{
	return 0;
}
static inline bool efx_ptp_uses_separate_channel(struct efx_nic *efx)
{
	return false;
}
static inline bool efx_ptp_is_ptp_tx(struct efx_nic *efx, struct sk_buff *skb)
{
	return false;
}
static inline int efx_ptp_tx(struct efx_nic *efx, struct sk_buff *skb)
{
	return NETDEV_TX_OK;
}
static inline void efx_ptp_event(struct efx_nic *efx, efx_qword_t *ev) {}
static inline size_t efx_ptp_describe_stats(struct efx_nic *efx, u8 *strings)
{
	return 0;
}
static inline void efx_ptp_reset_stats(struct efx_nic *efx) {}
static inline size_t efx_ptp_update_stats(struct efx_nic *efx, u64 *stats)
{
	return 0;
}
static inline void efx_rx_skb_attach_timestamp(struct efx_channel *channel,
					       struct sk_buff *skb,
					       const u8 *prefix) {}
static inline void efx_time_sync_event(struct efx_channel *channel,
				       efx_qword_t *ev) {}
static inline void efx_ptp_start_datapath(struct efx_nic *efx) {}
static inline void efx_ptp_stop_datapath(struct efx_nic *efx) {}
static inline ktime_t efx_ptp_nic_to_kernel_time(struct efx_tx_queue *tx_queue)
{
	return (ktime_t) { 0 };
}
#endif

#if defined(EFX_NOT_UPSTREAM)
struct efx_ts_get_pps;
struct efx_ts_hw_pps;
#ifdef CONFIG_SFC_PTP
int efx_ptp_pps_get_event(struct efx_nic *efx, struct efx_ts_get_pps *data);
int efx_ptp_hw_pps_enable(struct efx_nic *efx, bool enable);
int efx_ptp_pps_reset(struct efx_nic *efx);
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
static inline int efx_ptp_pps_reset(struct efx_nic *efx)
{
	return -EOPNOTSUPP;
}
#endif
#endif

#endif /* EFX_PTP_H */
