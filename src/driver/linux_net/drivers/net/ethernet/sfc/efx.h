/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_EFX_H
#define EFX_EFX_H

#include "net_driver.h"
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_INDIRECT_CALL_WRAPPERS)
#include <linux/indirect_call_wrapper.h>
#endif
#include "ef100_rx.h"
#include "ef100_tx.h"
#include "filter.h"
#include "workarounds.h"
#include "efx_common.h"

/* netdevice_ops */
int efx_ioctl(struct net_device *net_dev, struct ifreq *ifr, int cmd);
int efx_net_open(struct net_device *net_dev);
int efx_net_stop(struct net_device *net_dev);
int efx_change_mtu(struct net_device *net_dev, int new_mtu);
int __efx_net_alloc(struct efx_nic *efx);
void __efx_net_dealloc(struct efx_nic *efx);

static inline int efx_net_alloc(struct efx_nic *efx)
{
	return efx->type->net_alloc(efx);
}

static inline void efx_net_dealloc(struct efx_nic *efx)
{
	efx->type->net_dealloc(efx);
}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
void efx_vlan_rx_register(struct net_device *dev, struct vlan_group *vlan_group);
#endif

int efx_pci_probe_post_io(struct efx_nic *efx,
			  int (*nic_probe)(struct efx_nic *efx));
void efx_pci_remove_post_io(struct efx_nic *efx,
			    void (*nic_remove)(struct efx_nic *efx));

/* TX */
netdev_tx_t efx_hard_start_xmit(struct sk_buff *skb,
				struct net_device *net_dev);
int __efx_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb);

static inline int efx_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb)
{
	return INDIRECT_CALL_2(tx_queue->efx->type->tx_enqueue,
			       ef100_enqueue_skb, __efx_enqueue_skb,
			       tx_queue, skb);
}

void efx_xmit_done_single(struct efx_tx_queue *tx_queue);
extern unsigned int efx_piobuf_size;
extern bool separate_tx_channels;

/* RX */
void efx_set_default_rx_indir_table(struct efx_nic *efx,
				    struct efx_rss_context *ctx);
void __efx_rx_packet(struct efx_channel *channel);
void efx_rx_packet(struct efx_rx_queue *rx_queue, unsigned int index,
		   unsigned int n_frags, unsigned int len, u16 flags);

static inline void efx_rx_flush_packet(struct efx_channel *channel)
{
	if (channel->rx_pkt_n_frags)
		if (!channel->type->receive_raw ||
		    !channel->type->receive_raw(channel))
			INDIRECT_CALL_2(channel->efx->type->rx_packet,
					__ef100_rx_packet, __efx_rx_packet,
					channel);
}

static inline bool efx_rx_buf_hash_valid(struct efx_nic *efx, const u8 *prefix)
{
	if (efx->type->rx_buf_hash_valid)
		return INDIRECT_CALL_1(efx->type->rx_buf_hash_valid,
				       ef100_rx_buf_hash_valid,
				       prefix);
	return true;
}

#define EFX_MAX_DMAQ_SIZE 4096UL
#define EFX_DEFAULT_RX_DMAQ_SIZE 1024UL
#define EFX_DEFAULT_TX_DMAQ_SIZE 1024UL
#define EFX_MIN_DMAQ_SIZE 512UL

#define EFX_MAX_EVQ_SIZE 16384UL
#define EFX_MIN_EVQ_SIZE 512UL
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
/* Additional event queue entries to add on channel zero for driverlink. */
#define EFX_EVQ_DL_EXTRA_ENTRIES 7936UL
#endif
#endif

static inline unsigned long efx_min_dmaq_size(struct efx_nic *efx)
{
	return (efx->supported_bitmap ?
		(1 << (ffs(efx->supported_bitmap) - 1)) : EFX_MIN_DMAQ_SIZE);
}

static inline unsigned long efx_max_dmaq_size(struct efx_nic *efx)
{
	return (efx->supported_bitmap ?
		(1 << (fls(efx->supported_bitmap) - 1)) : EFX_MAX_DMAQ_SIZE);
}

static inline unsigned long efx_min_evtq_size(struct efx_nic *efx)
{
	return (efx->supported_bitmap ?
		(1 << (ffs(efx->supported_bitmap) - 1)) : EFX_MIN_EVQ_SIZE);
}

static inline unsigned long efx_max_evtq_size(struct efx_nic *efx)
{
	return (efx->supported_bitmap ?
		(1 << (fls(efx->supported_bitmap) - 1)) : EFX_MAX_EVQ_SIZE);
}

/* Each packet can consume up to ceil(max_frame_len / buffer_size) buffers */
#define EFX_RX_MAX_FRAGS DIV_ROUND_UP(EFX_MAX_FRAME_LEN(EFX_MAX_MTU), \
                                      EFX_RX_USR_BUF_SIZE)

/* Maximum number of TCP segments we support for soft-TSO */
#define EFX_TSO_MAX_SEGS	100

/* The smallest rxq_entries that the driver supports. Somewhat arbitrary.
 */
#define EFX_RXQ_MIN_ENT		16U

/* All EF10 architecture NICs steal one bit of the DMAQ size for various
 * other purposes when counting TxQ entries, so we halve the queue size.
 */
#define EFX_TXQ_MAX_ENT(efx)	(EFX_WORKAROUND_EF10(efx) ? \
				 efx_max_dmaq_size(efx) / 2 : \
				 efx_max_dmaq_size(efx))

#ifdef EFX_NOT_UPSTREAM
/* PCIe link bandwidth measure:
 * bw = (width << (speed - 1))
 */
#define EFX_BW_PCIE_GEN1_X8  (8  << (1 - 1))
#define EFX_BW_PCIE_GEN2_X8  (8  << (2 - 1))
#define EFX_BW_PCIE_GEN3_X8  (8  << (3 - 1))
#define EFX_BW_PCIE_GEN3_X16 (16 << (3 - 1))
#endif

static inline bool efx_rss_enabled(struct efx_nic *efx)
{
	return efx->n_rss_channels > 1;
}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)

static inline bool efx_ssr_enabled(struct efx_nic *efx)
{
#ifdef NETIF_F_LRO
	return !!(efx->net_dev->features & NETIF_F_LRO);
#else
	return efx->lro_enabled;
#endif
}

static inline bool efx_channel_ssr_enabled(struct efx_channel *channel)
{
	return efx_ssr_enabled(channel->efx);
}

int efx_ssr_init(struct efx_channel *channel, struct efx_nic *efx);
void efx_ssr_fini(struct efx_channel *channel);
void __efx_ssr_end_of_burst(struct efx_channel *channel);
void efx_ssr(struct efx_channel *, struct efx_rx_buffer *rx_buf, u8 *eh);

static inline void efx_ssr_end_of_burst(struct efx_channel *channel)
{
	if (!list_empty(&channel->ssr.active_conns))
		__efx_ssr_end_of_burst(channel);
}

#endif /* EFX_USE_SFC_LRO */

/* Filters */
/**
 * efx_filter_insert_filter - add or replace a filter
 * @efx: NIC in which to insert the filter
 * @spec: Specification for the filter
 * @replace_equal: Flag for whether the specified filter may replace an
 *	existing filter with equal priority
 *
 * On success, return the filter ID.
 * On failure, return a negative error code.
 *
 * If existing filters have equal match values to the new filter spec,
 * then the new filter might replace them or the function might fail,
 * as follows.
 *
 * 1. If the existing filters have lower priority, or @replace_equal
 *    is set and they have equal priority, replace them.
 *
 * 2. If the existing filters have higher priority, return -%EPERM.
 *
 * 3. If !efx_filter_is_mc_recipient(@spec), or the NIC does not
 *    support delivery to multiple recipients, return -%EEXIST.
 *
 * This implies that filters for multiple multicast recipients must
 * all be inserted with the same priority and @replace_equal = %false.
 */
static inline s32 efx_filter_insert_filter(struct efx_nic *efx,
					   const struct efx_filter_spec *spec,
					   bool replace_equal)
{
	return efx->type->filter_insert(efx, spec, replace_equal);
}

/**
 * efx_filter_remove_id_safe - remove a filter by ID, carefully
 * @efx: NIC from which to remove the filter
 * @priority: Priority of filter, as passed to @efx_filter_insert_filter
 * @filter_id: ID of filter, as returned by @efx_filter_insert_filter
 *
 * This function will range-check @filter_id, so it is safe to call
 * with a value passed from userland.
 */
static inline int efx_filter_remove_id_safe(struct efx_nic *efx,
					    enum efx_filter_priority priority,
					    u32 filter_id)
{
	return efx->type->filter_remove_safe(efx, priority, filter_id);
}

/**
 * efx_filter_get_filter_safe - retrieve a filter by ID, carefully
 * @efx: NIC from which to remove the filter
 * @priority: Priority of filter, as passed to @efx_filter_insert_filter
 * @filter_id: ID of filter, as returned by @efx_filter_insert_filter
 * @spec: Buffer in which to store filter specification
 *
 * This function will range-check @filter_id, so it is safe to call
 * with a value passed from userland.
 */
static inline int
efx_filter_get_filter_safe(struct efx_nic *efx,
			   enum efx_filter_priority priority,
			   u32 filter_id, struct efx_filter_spec *spec)
{
	return efx->type->filter_get_safe(efx, priority, filter_id, spec);
}

static inline u32 efx_filter_count_rx_used(struct efx_nic *efx,
					   enum efx_filter_priority priority)
{
	return efx->type->filter_count_rx_used(efx, priority);
}
static inline u32 efx_filter_get_rx_id_limit(struct efx_nic *efx)
{
	return efx->type->filter_get_rx_id_limit(efx);
}
static inline s32 efx_filter_get_rx_ids(struct efx_nic *efx,
					enum efx_filter_priority priority,
					u32 *buf, u32 size)
{
	return efx->type->filter_get_rx_ids(efx, priority, buf, size);
}
#ifdef CONFIG_RFS_ACCEL
int efx_filter_rfs(struct net_device *net_dev, const struct sk_buff *skb,
		   u16 rxq_index, u32 flow_id);
bool __efx_filter_rfs_expire(struct efx_channel *channel, unsigned int quota);
static inline void efx_filter_rfs_expire(struct work_struct *data)
{
	struct delayed_work *dwork = to_delayed_work(data);
	struct efx_channel *channel;
	unsigned int time, quota;

	channel = container_of(dwork, struct efx_channel, filter_work);
	time = jiffies - channel->rfs_last_expiry;
	quota = channel->rfs_filter_count * time / (30 * HZ);
	if (quota >= 20 && __efx_filter_rfs_expire(channel, min(channel->rfs_filter_count, quota)))
		channel->rfs_last_expiry += time;
	/* Ensure we do more work eventually even if NAPI poll is not happening */
	schedule_delayed_work(dwork, 30 * HZ);
}
#define efx_filter_rfs_enabled() 1
#else
static inline void efx_filter_rfs_expire(struct work_struct *data) {}
#define efx_filter_rfs_enabled() 0
#endif

/* RSS contexts */
struct efx_rss_context *efx_alloc_rss_context_entry(struct efx_nic *efx);
struct efx_rss_context *efx_find_rss_context_entry(struct efx_nic *efx, u32 id);
void efx_free_rss_context_entry(struct efx_rss_context *ctx);
static inline bool efx_rss_active(struct efx_rss_context *ctx)
{
	return ctx->context_id != EFX_MCDI_RSS_CONTEXT_INVALID;
}

/* Ethtool support */
#ifdef EFX_USE_KCOMPAT
int efx_ethtool_get_rxnfc(struct net_device *net_dev,
			  struct efx_ethtool_rxnfc *info, u32 *rules);
int efx_ethtool_set_rxnfc(struct net_device *net_dev,
			  struct efx_ethtool_rxnfc *info);
#else
int efx_ethtool_set_rxnfc(struct net_device *net_dev,
			  struct ethtool_rxnfc *info);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
int efx_ethtool_old_get_rxfh_indir(struct net_device *net_dev,
				   struct ethtool_rxfh_indir *indir);
int efx_ethtool_old_set_rxfh_indir(struct net_device *net_dev,
				   const struct ethtool_rxfh_indir *indir);
#endif
#ifdef CONFIG_SFC_DUMP
struct ethtool_dump;
int efx_ethtool_get_dump_flag(struct net_device *net_dev,
			      struct ethtool_dump *dump);
int efx_ethtool_get_dump_data(struct net_device *net_dev,
			      struct ethtool_dump *dump, void *buffer);
int efx_ethtool_set_dump(struct net_device *net_dev, struct ethtool_dump *val);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_GET_TS_INFO) && !defined(EFX_HAVE_ETHTOOL_EXT_GET_TS_INFO)
int efx_ethtool_get_ts_info(struct net_device *net_dev,
			    struct ethtool_ts_info *ts_info);
#endif
extern const struct ethtool_ops efx_ethtool_ops;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_ETHTOOL_OPS_EXT)
extern const struct ethtool_ops_ext efx_ethtool_ops_ext;
#endif

/* Global */
unsigned int efx_usecs_to_ticks(struct efx_nic *efx, unsigned int usecs);
unsigned int efx_ticks_to_usecs(struct efx_nic *efx, unsigned int ticks);
int efx_init_irq_moderation(struct efx_nic *efx, unsigned int tx_usecs,
			    unsigned int rx_usecs, bool rx_adaptive,
			    bool rx_may_override_tx);
void efx_get_irq_moderation(struct efx_nic *efx, unsigned int *tx_usecs,
			    unsigned int *rx_usecs, bool *rx_adaptive);
#ifdef EFX_NOT_UPSTREAM
extern int efx_target_num_vis;
#endif

/* Update the generic software stats in the passed stats array */
void efx_update_sw_stats(struct efx_nic *efx, u64 *stats);

/* MTD */
#ifdef CONFIG_SFC_MTD
extern bool efx_allow_nvconfig_writes;
int efx_mtd_add(struct efx_nic *efx, struct efx_mtd_partition *parts,
		size_t n_parts);
static inline int efx_mtd_probe(struct efx_nic *efx)
{
	return efx->type->mtd_probe(efx);
}
int efx_mtd_init(struct efx_nic *efx);
void efx_mtd_free(struct efx_nic *efx);
void efx_mtd_rename(struct efx_nic *efx);
void efx_mtd_remove(struct efx_nic *efx);
#ifdef EFX_WORKAROUND_87308
void efx_mtd_creation_work(struct work_struct *data);
#endif
#else
static inline int efx_mtd_probe(struct efx_nic *efx) { return 0; }
static inline void efx_mtd_rename(struct efx_nic *efx) {}
static inline void efx_mtd_remove(struct efx_nic *efx) {}
#endif

#ifdef CONFIG_SFC_SRIOV
static inline unsigned int efx_vf_size(struct efx_nic *efx)
{
	return 1 << efx->vi_scale;
}
#endif

static inline void efx_schedule_channel(struct efx_channel *channel)
{
	netif_vdbg(channel->efx, intr, channel->efx->net_dev,
		   "channel %d scheduling NAPI poll on CPU%d\n",
		   channel->channel, raw_smp_processor_id());

	napi_schedule(&channel->napi_str);
}

static inline void efx_schedule_channel_irq(struct efx_channel *channel)
{
	channel->event_test_cpu = raw_smp_processor_id();
	efx_schedule_channel(channel);
}

#if defined(EFX_USE_KCOMPAT) && (!defined(EFX_USE_CANCEL_WORK_SYNC) || !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC))
extern struct workqueue_struct *efx_workqueue;
#endif

static inline void efx_reps_set_link_state(struct efx_nic *efx, bool up)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	if (efx->type->reps_set_link_state)
		efx->type->reps_set_link_state(efx, up);
#endif
}

static inline void efx_device_detach_sync(struct efx_nic *efx)
{
	struct net_device *dev = efx->net_dev;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	/* We must stop reps (which use our TX) before we stop ourselves. */
	if (efx->type->detach_reps)
		efx->type->detach_reps(efx);
#endif
	/* Lock/freeze all TX queues so that we can be sure the
	 * TX scheduler is stopped when we're done and before
	 * netif_device_present() becomes false.
	 */
	netif_tx_lock_bh(dev);
	netif_device_detach(dev);
	netif_tx_unlock_bh(dev);
}

static inline void efx_device_attach_if_not_resetting(struct efx_nic *efx)
{
	if ((efx->state != STATE_DISABLED) && !efx->reset_pending) {
		netif_device_attach(efx->net_dev);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
		if (efx->type->attach_reps && efx->state == STATE_NET_UP)
			efx->type->attach_reps(efx);
#endif
	}
}

static inline void efx_rwsem_assert_write_locked(struct rw_semaphore *sem)
{
#ifdef DEBUG
	if (down_read_trylock(sem)) {
		up_read(sem);
		WARN_ON(1);
	}
#endif
}

#endif /* EFX_EFX_H */
