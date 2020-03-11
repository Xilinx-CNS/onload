/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2011-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

/* Theory of operation:
 *
 * PTP support is assisted by firmware running on the MC, which provides
 * the hardware timestamping capabilities.  Both transmitted and received
 * PTP event packets are queued onto internal queues for subsequent processing;
 * this is because the MC operations are relatively long and would block
 * block NAPI/interrupt operation.
 *
 * Receive event processing:
 *	The event contains the packet's UUID and sequence number, together
 *	with the hardware timestamp.  The PTP receive packet queue is searched
 *	for this UUID/sequence number and, if found, put on a pending queue.
 *	Packets not matching are delivered without timestamps (MCDI events will
 *	always arrive after the actual packet).
 *	It is important for the operation of the PTP protocol that the ordering
 *	of packets between the event and general port is maintained.
 *
 * Work queue processing:
 *	If work waiting, synchronise host/hardware time
 *
 *	Transmit: send packet through MC, which returns the transmission time
 *	that is converted to an appropriate timestamp.
 *
 *	Receive: the packet's reception time is converted to an appropriate
 *	timestamp.
 */
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/time.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/ktime.h>
#endif
#include <linux/module.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/net_tstamp.h>
#include <linux/pps_kernel.h>
#include <linux/ptp_clock_kernel.h>
#endif
#include "net_driver.h"
#include "efx.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "io.h"
#include "farch_regs.h"
#include "nic.h"
#include "debugfs.h"
#ifdef EFX_USE_KCOMPAT
#include "efx_ioctl.h"
#include "kernel_compat.h"
#endif
#ifdef CONFIG_SFC_TRACING
#include <trace/events/sfc.h>
#endif

/* Maximum number of events expected to make up a PTP event */
#define	MAX_EVENT_FRAGS			3

/* Maximum delay, ms, to begin synchronisation */
#define	MAX_SYNCHRONISE_WAIT_MS		2

/* How long, at most, to spend synchronising */
#define	SYNCHRONISE_PERIOD_NS		250000

/* How often to update the shared memory time */
#define	SYNCHRONISATION_GRANULARITY_NS	200

/* Minimum permitted length of a (corrected) synchronisation time */
#define	DEFAULT_MIN_SYNCHRONISATION_NS	120

/* Maximum permitted length of a (corrected) synchronisation time */
#define	MAX_SYNCHRONISATION_NS		1000

/* How many (MC) receive events that can be queued */
#define	MAX_RECEIVE_EVENTS		8

/* Length of (modified) moving average. */
#define	AVERAGE_LENGTH			16

/* How long an unmatched event or packet can be held */
#define PKT_EVENT_LIFETIME_MS		10

/* Offsets into PTP packet for identification.  These offsets are from the
 * start of the IP header, not the MAC header.  Note that neither PTP V1 nor
 * PTP V2 permit the use of IPV4 options.
 */
#define PTP_DPORT_OFFSET	22

#define PTP_V1_VERSION_LENGTH	2
#define PTP_V1_VERSION_OFFSET	28

#define PTP_V1_UUID_LENGTH	6
#define PTP_V1_UUID_OFFSET	50

#define PTP_V1_SEQUENCE_LENGTH	2
#define PTP_V1_SEQUENCE_OFFSET	58

/* The minimum length of a PTP V1 packet for offsets, etc. to be valid:
 * includes IP header.
 */
#define	PTP_V1_MIN_LENGTH	64

#define PTP_V2_VERSION_LENGTH	1
#define PTP_V2_VERSION_OFFSET	29

#define PTP_V2_UUID_LENGTH	8
#define PTP_V2_UUID_OFFSET	48

/* Although PTP V2 UUIDs are comprised a ClockIdentity (8) and PortNumber (2),
 * the MC only captures the last six bytes of the clock identity. These values
 * reflect those, not the ones used in the standard.  The standard permits
 * mapping of V1 UUIDs to V2 UUIDs with these same values.
 */
#define PTP_V2_MC_UUID_LENGTH	6
#define PTP_V2_MC_UUID_OFFSET	50

#define PTP_V2_SEQUENCE_LENGTH	2
#define PTP_V2_SEQUENCE_OFFSET	58

/* The minimum length of a PTP V2 packet for offsets, etc. to be valid:
 * includes IP header.
 */
#define	PTP_V2_MIN_LENGTH	63

#define	PTP_MIN_LENGTH		63

#define PTP_PRIMARY_ADDRESS	0xe0000181	/* 224.0.1.129 */
#define PTP_PEER_DELAY_ADDRESS	0xe000006B	/* 224.0.0.107 */
#define PTP_EVENT_PORT		319
#define PTP_GENERAL_PORT	320

/* Annoyingly the format of the version numbers are different between
 * versions 1 and 2 so it isn't possible to simply look for 1 or 2.
 */
#define	PTP_VERSION_V1		1

#define	PTP_VERSION_V2		2
#define	PTP_VERSION_V2_MASK	0x0f

#ifdef EFX_NOT_UPSTREAM

#define PTP_V2_DOMAIN_LENGTH    1
#define PTP_V2_DOMAIN_OFFSET    32

/* Mask of VLAN tag in bytes 2 and 3 of 802.1Q header
 */
#define VLAN_TAG_MASK		0x0fff

/* Offest into the packet where PTP header starts
 */
#define PTP_LAYER2_LEN		14
#define PTP_LAYER2_VLAN_LEN	(PTP_LAYER2_LEN + VLAN_HLEN)

#endif /* EFX_NOT_UPSTREAM */

enum ptp_packet_state {
	PTP_PACKET_STATE_UNMATCHED = 0,
	PTP_PACKET_STATE_MATCHED,
	PTP_PACKET_STATE_TIMED_OUT,
	PTP_PACKET_STATE_MATCH_UNWANTED
};

/* NIC synchronised with single word of time only comprising
 * partial seconds and full nanoseconds: 10^9 ~ 2^30 so 2 bits for seconds.
 */
#define	MC_NANOSECOND_BITS	30
#define	MC_NANOSECOND_MASK	((1 << MC_NANOSECOND_BITS) - 1)
#define	MC_SECOND_MASK		((1 << (32 - MC_NANOSECOND_BITS)) - 1)

/* Maximum parts-per-billion adjustment that is acceptable */
#define MAX_PPB			100000000

/* Precalculate scale word to avoid long long division at runtime */
/* This is equivalent to 2^66 / 10^9. */
#define PPB_SCALE_WORD  ((1LL << (57)) / 1953125LL)

/* How much to shift down after scaling to convert to FP40 */
#define PPB_SHIFT_FP40		26
/* ... and FP44. */
#define PPB_SHIFT_FP44		22

#define PTP_SYNC_ATTEMPTS	4

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
/* Number of received packets to hold in timestamp queue */
#define	MAX_RX_TS_ENTRIES	16

/**
 * struct efx_ptp_rx_timestamp - Compatibility layer
 */
struct efx_ptp_rx_timestamp {
	struct skb_shared_hwtstamps ts;
	u8 uuid[PTP_V1_UUID_LENGTH];
	u8 seqid[PTP_V1_SEQUENCE_LENGTH];
};
#endif

/**
 * struct efx_ptp_match - Matching structure, stored in sk_buff's cb area.
 * @words: UUID and (partial) sequence number
 * @expiry: Time after which the packet should be delivered irrespective of
 *            event arrival.
 * @state: The state of the packet - whether it is ready for processing or
 *         whether that is of no interest.
 * @vlan_tci: VLAN tag in host byte order.
 * @vlan_tagged: Whether the match is VLAN tagged. The vlan_tci attributes is
 *	only valid if this is true.
 */
struct efx_ptp_match {
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	struct skb_shared_hwtstamps timestamps;	/* Must be first member */
#endif
	u32 words[DIV_ROUND_UP(PTP_V1_UUID_LENGTH, 4)];
	unsigned long expiry;
	enum ptp_packet_state state;
	u16 vlan_tci;
	bool vlan_tagged;
};

/**
 * struct efx_ptp_event_rx - A PTP receive event (from MC)
 * @seq0: First part of (PTP) UUID
 * @seq1: Second part of (PTP) UUID and sequence number
 * @hwtimestamp: Event timestamp
 */
struct efx_ptp_event_rx {
	struct list_head link;
	u32 seq0;
	u32 seq1;
	ktime_t hwtimestamp;
	unsigned long expiry;
};

/**
 * struct efx_ptp_timeset - Synchronisation between host and MC
 * @host_start: Host time immediately before hardware timestamp taken
 * @major: Hardware timestamp, major
 * @minor: Hardware timestamp, minor
 * @host_end: Host time immediately after hardware timestamp taken
 * @wait: Number of NIC clock ticks between hardware timestamp being read and
 *          host end time being seen
 * @window: Difference of host_end and host_start
 * @valid: Whether this timeset is valid
 */
struct efx_ptp_timeset {
	u32 host_start;
	u32 major;
	u32 minor;
	u32 host_end;
	u32 wait;
	u32 window;	/* Derived: end - start, allowing for wrap */
	s64 mc_host_diff;	/* Derived: mc_time - host_time */
};

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
/* Fordward declaration */
struct efx_ptp_data;

/**
 * struct efx_pps_data - PPS device node informatino
 * @ptp: Pointer to parent ptp structure
 * @kobj: kobject for stats handling
 * @read_data: Queue for handling API reads
 * @s_assert: sys assert time of hw_pps event
 * @n_assert: nic assert time of hw_pps event
 * @s_delta: computed delta between nic and sys clocks
 * @nic_hw_pps_enabled: Are hw_pps events enabled
 * @fd_count: Number of open fds
 * @major: device major number
 * @last_ev: Last event sequence number
 * @last_ev_taken: Last event sequence number read by API
 */
struct efx_pps_data {
	struct efx_ptp_data *ptp;
	struct kobject kobj;
	wait_queue_head_t read_data;
	struct timespec64 s_assert;
	ktime_t n_assert;
	struct timespec64 s_delta;
	bool nic_hw_pps_enabled;
	int fd_count;
	int major;
	int last_ev;
	int last_ev_taken;
};

/**
 * struct efx_pps_dev_attr - PPS device attr structure
 * @attr: attribute object
 * @pos: offset of the stat desired
 * @show: function pointer to obtain and print the stats
 */

struct efx_pps_dev_attr {
	struct attribute attr;
	u8 pos;
	ssize_t (*show)(struct efx_pps_data *, u8 pos, char *);
};
#endif

/**
 * struct efx_ptp_data - Precision Time Protocol (PTP) state
 * @efx: The NIC context
 * @channel: The PTP channel (Siena only)
 * @rx_ts_inline: Flag for whether RX timestamps are inline (else they are
 *	separate events)
 * @rxq: Receive SKB queue (awaiting timestamps)
 * @txq: Transmit SKB queue
 * @evt_list: List of MC receive events awaiting packets
 * @evt_free_list: List of free events
 * @evt_lock: Lock for manipulating evt_list and evt_free_list
 * @rx_evts: Instantiated events (on evt_list and evt_free_list)
 * @workwq: Work queue for processing pending PTP operations
 * @work: Work task
 * @kref: Reference count.
 * @reset_required: A serious error has occurred and the PTP task needs to be
 *                  reset (disable, enable).
 * @rxfilter_primary_event: Receive filter for primary address, event port
 * @rxfilter_primary_general: Receive filter for primary address, general port
 * @rxfilter_peer_delay_event: Receive filter for peer delay address,
 *	event port
 * @rxfilter_peer_delay_general: Receive filter for peer delay address,
 *	general port
 * @rxfilter_installed: Indicates if multicast filters are installed
 * @config: Current timestamp configuration
 * @enabled: PTP operation enabled. If this is disabled normal timestamping
 *	     can still work.
 * @mode: Mode in which PTP operating (PTP version)
 * @ns_to_nic_time: Function to convert from scalar nanoseconds to NIC time
 * @nic_to_kernel_time: Function to convert from NIC to kernel time
 * @nic_time.minor_max: Wrap point for NIC minor times
 * @nic_time.sync_event_diff_min: Minimum acceptable difference between time
 * in packet prefix and last MCDI time sync event i.e. how much earlier than
 * the last sync event time a packet timestamp can be.
 * @nic_time.sync_event_diff_max: Maximum acceptable difference between time
 * in packet prefix and last MCDI time sync event i.e. how much later than
 * the last sync event time a packet timestamp can be.
 * @nic_time.sync_event_minor_shift: Shift required to make minor time from
 * field in MCDI time sync event.
 * @min_synchronisation_ns: Minimum acceptable corrected sync window
 * @capabilities: Capabilities flags from the NIC
 * @ts_corrections.ptp_tx: Required driver correction of PTP packet transmit
 *                         timestamps
 * @ts_corrections.ptp_rx: Required driver correction of PTP packet receive
 *                         timestamps
 * @ts_corrections.pps_out: PPS output error (information only)
 * @ts_corrections.pps_in: Required driver correction of PPS input timestamps
 * @ts_corrections.general_tx: Required driver correction of general packet
 *                             transmit timestamps
 * @ts_corrections.general_rx: Required driver correction of general packet
 *                             receive timestamps
 * @evt_frags: Partly assembled PTP events
 * @evt_frag_idx: Current fragment number
 * @evt_code: Last event code
 * @start: Address at which MC indicates ready for synchronisation
 * @host_time_pps: Host time at last PPS
 * @adjfreq_ppb_shift: Shift required to convert scaled parts-per-billion
 * frequency adjustment into a fixed point fractional nanosecond format.
 * @max_adjfreq: Current ppb adjustment, lives here instead of phc_clock_info as
 *		 it must be accessable without PHC support, using private ioctls.
 * @current_adjfreq: Current ppb adjustment.
 * @phc_clock: Pointer to registered phc device
 * @phc_clock_info: Registration structure for phc device
 * @pps_work: pps work task for handling pps events
 * @pps_workwq: pps work queue
 * @nic_ts_enabled: Flag indicating if NIC generated TS events are handled
 * @txbuf: Buffer for use when transmitting (PTP) packets to MC (avoids
 *         allocations in main data path).
 * @good_syncs: Number of successful synchronisations.
 * @fast_syncs: Number of synchronisations requiring short delay
 * @bad_syncs: Number of failed synchronisations.
 * @sync_timeouts: Number of synchronisation timeouts
 * @no_time_syncs: Number of synchronisations with no good times.
 * @invalid_sync_windows: Number of sync windows with bad durations.
 * @undersize_sync_windows: Number of corrected sync windows that are too small
 * @oversize_sync_windows: Number of corrected sync windows that are too large
 * @rx_no_timestamp: Number of packets received without a timestamp.
 * @timeset: Last set of synchronisation statistics.
 * @xmit_skb: Transmit SKB function.
 */
struct efx_ptp_data {
	struct efx_nic *efx;
	struct efx_channel *channel;
	bool rx_ts_inline;
	struct sk_buff_head rxq;
	struct sk_buff_head txq;
	struct list_head evt_list;
	struct list_head evt_free_list;
	spinlock_t evt_lock;
	struct efx_ptp_event_rx rx_evts[MAX_RECEIVE_EVENTS];
	struct workqueue_struct *workwq;
	struct work_struct work;
	struct kref kref;
	bool reset_required;
	u32 rxfilter_primary_event;
	u32 rxfilter_primary_general;
	u32 rxfilter_peer_delay_event;
	u32 rxfilter_peer_delay_general;
	bool rxfilter_installed;
#ifdef EFX_NOT_UPSTREAM
	/* Indicates if unicast filters are installed */
	bool rxfilter_unicast_installed;
	/* Unicast address to filter on */
	__be32 rxfilter_unicast_address;
	/* Receive filter for unicast address */
	u32 rxfilter_unicast_event;
	/* Receive filter for unicast address */
	u32 rxfilter_unicast_general;

	/* Siena-based NICs only. Filtering of received PTP packets against
	 * PTP UUID, Domain Number and VLAN tags.
	 */
	struct efx_ts_set_uuid_filter uuid_filter;
	struct efx_ts_set_domain_filter domain_filter;
	struct efx_ts_set_vlan_filter vlan_filter;
#endif
	struct hwtstamp_config config;
	bool enabled;
	unsigned int mode;
	void (*ns_to_nic_time)(s64 ns, u32 *nic_major, u32 *nic_minor);
	ktime_t (*nic_to_kernel_time)(u32 nic_major, u32 nic_minor,
				      s32 correction);
	struct {
		u32 minor_max;
		u32 sync_event_diff_min;
		u32 sync_event_diff_max;
		unsigned int sync_event_minor_shift;
	} nic_time;
	unsigned int min_synchronisation_ns;
	unsigned int capabilities;
	struct {
		s32 ptp_tx;
		s32 ptp_rx;
		s32 pps_out;
		s32 pps_in;
		s32 general_tx;
		s32 general_rx;
	} ts_corrections;
	efx_qword_t evt_frags[MAX_EVENT_FRAGS];
	int evt_frag_idx;
	int evt_code;
	struct efx_buffer start;
	struct pps_event_time host_time_pps;
	unsigned int adjfreq_ppb_shift;
	s64 max_adjfreq;
	s64 current_adjfreq;
#if defined(EFX_NOT_UPSTREAM)
	/* Last measurement of delta between system and NIC clocks and
	 * associated boolean to indicate if the valud is valid.
	 */
	struct timespec64 last_delta;
	bool last_delta_valid;
#endif
	struct ptp_clock *phc_clock;
	struct ptp_clock_info phc_clock_info;
	struct work_struct pps_work;
	struct workqueue_struct *pps_workwq;
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
	/* Data associated with optional HW PPS events */
	struct efx_pps_data *pps_data;
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
	bool nic_ts_enabled;
#endif
	_MCDI_DECLARE_BUF(txbuf, MC_CMD_PTP_IN_TRANSMIT_LENMAX);

	struct {
		unsigned int good_syncs;
		unsigned int fast_syncs;
		unsigned int bad_syncs;
		unsigned int sync_timeouts;
		unsigned int no_time_syncs;
		unsigned int invalid_sync_windows;
		unsigned int undersize_sync_windows;
		unsigned int oversize_sync_windows;
		unsigned int rx_no_timestamp;
	} sw_stats;
	bool initialised_stats;
	__le16 initial_mc_stats[MC_CMD_PTP_OUT_STATUS_LEN / sizeof(__le16)];
#ifdef CONFIG_SFC_DEBUGFS
	/* Host nanoseconds at last synchronisation. */
	unsigned int last_sync_time_host;
	/* Minimum time between event and synchronisation */
	unsigned int min_sync_delta;
	/* Maximum time between event and synchronisation */
	unsigned int max_sync_delta;
	/* Average time between event and synchronisation.
	 * Modified moving average. */
	unsigned int average_sync_delta;
	/* Last time between event and synchronisation */
	unsigned int last_sync_delta;
	/* Count of appended timestamps (AOE) marked or determined to be
	 * invalid. */
	unsigned int bad_trailing_timestamps;
	int sync_window_last[PTP_SYNC_ATTEMPTS];
	int sync_window_min;
	int sync_window_max;
	int sync_window_average;
	int corrected_sync_window_last[PTP_SYNC_ATTEMPTS];
	int corrected_sync_window_min;
	int corrected_sync_window_max;
	int corrected_sync_window_average;
	/* Context value for MC statistics */
	u8 mc_stats[MC_CMD_PTP_OUT_STATUS_LEN / sizeof(u32)];
#endif
	struct efx_ptp_timeset
	timeset[MC_CMD_PTP_OUT_SYNCHRONIZE_TIMESET_MAXNUM];
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	bool tx_ts_valid;
	struct skb_shared_hwtstamps tx_ts;
	unsigned int rx_ts_head;
	unsigned int rx_ts_tail;
	struct efx_ptp_rx_timestamp rx_ts[MAX_RX_TS_ENTRIES];
#endif
	void (*xmit_skb)(struct efx_nic *efx, struct sk_buff *skb);
};

static int efx_phc_adjfreq(struct ptp_clock_info *ptp, s32 delta);
static int efx_phc_adjtime(struct ptp_clock_info *ptp, s64 delta);
static int efx_phc_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
static int efx_phc_settime(struct ptp_clock_info *ptp,
			   const struct timespec64 *e_ts);
static int efx_phc_enable(struct ptp_clock_info *ptp,
			  struct ptp_clock_request *request, int on);

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_64BIT_PHC)
static int efx_phc_gettime32(struct ptp_clock_info *ptp, struct timespec *ts);
static int efx_phc_settime32(struct ptp_clock_info *ptp,
			     const struct timespec *ts);
#endif
#endif

static LIST_HEAD(efx_all_funcs_list);
static DEFINE_SPINLOCK(ptp_all_funcs_list_lock);

bool efx_ptp_use_mac_tx_timestamps(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	return (efx_nic_rev(efx) >= EFX_REV_HUNT_A0) &&
	       efx_ef10_has_cap(nic_data->datapath_caps2, TX_MAC_TIMESTAMPING);
}

#ifdef EFX_NOT_UPSTREAM
static int efx_ptp_insert_unicast_filters(struct efx_nic *efx,
					  __be32 unicast_address);
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)

static void efx_ptp_save_rx_ts(struct efx_nic *efx, struct sk_buff *skb,
			       struct skb_shared_hwtstamps *timestamps)
{
	unsigned int new_tail;
	struct efx_ptp_data *ptp = efx->ptp_data;

	local_bh_disable();
	new_tail = ptp->rx_ts_tail + 1;
	if (new_tail >= MAX_RX_TS_ENTRIES)
		new_tail = 0;

	if (new_tail != ptp->rx_ts_head) {
		struct efx_ptp_rx_timestamp *ts;

		ts = &ptp->rx_ts[ptp->rx_ts_tail];
		ptp->rx_ts_tail = new_tail;
		ts->ts = *timestamps;

		if (ptp->mode == MC_CMD_PTP_MODE_V1) {
			memcpy(ts->uuid, &skb->data[PTP_V1_UUID_OFFSET],
			       PTP_V1_UUID_LENGTH);
		} else if (ptp->mode == MC_CMD_PTP_MODE_V2) {
			/* In the normal V2 mode, we pass bytes 2-7 of the V2
			 * UUID to the application */
			memcpy(ts->uuid, &skb->data[PTP_V2_MC_UUID_OFFSET],
			       PTP_V2_MC_UUID_LENGTH);
		} else {
			/* bug 33070 In the enhanced V2 mode, we pass bytes 0-2
			 * and 5-7 of the V2 UUID to the application */
			ts->uuid[0] = skb->data[PTP_V2_UUID_OFFSET];
			ts->uuid[1] = skb->data[PTP_V2_UUID_OFFSET + 1];
			ts->uuid[2] = skb->data[PTP_V2_UUID_OFFSET + 2];
			ts->uuid[3] = skb->data[PTP_V2_UUID_OFFSET + 5];
			ts->uuid[4] = skb->data[PTP_V2_UUID_OFFSET + 6];
			ts->uuid[5] = skb->data[PTP_V2_UUID_OFFSET + 7];
			BUG_ON(ptp->mode != MC_CMD_PTP_MODE_V2_ENHANCED);
		}

		memcpy(ts->seqid, &skb->data[PTP_V1_SEQUENCE_OFFSET],
		       PTP_V1_SEQUENCE_LENGTH);
	}
	local_bh_enable();
}
#endif

#define PTP_SW_STAT(ext_name, field_name)				\
	{ #ext_name, 0, offsetof(struct efx_ptp_data, field_name) }
#define PTP_MC_STAT(ext_name, mcdi_name)				\
	{ #ext_name, 32, MC_CMD_PTP_OUT_STATUS_STATS_ ## mcdi_name ## _OFST }
static const struct efx_hw_stat_desc efx_ptp_stat_desc[] = {
	PTP_SW_STAT(ptp_good_syncs, sw_stats.good_syncs),
	PTP_SW_STAT(ptp_fast_syncs, sw_stats.fast_syncs),
	PTP_SW_STAT(ptp_bad_syncs, sw_stats.bad_syncs),
	PTP_SW_STAT(ptp_sync_timeouts, sw_stats.sync_timeouts),
	PTP_SW_STAT(ptp_no_time_syncs, sw_stats.no_time_syncs),
	PTP_SW_STAT(ptp_invalid_sync_windows, sw_stats.invalid_sync_windows),
	PTP_SW_STAT(ptp_undersize_sync_windows, sw_stats.undersize_sync_windows),
	PTP_SW_STAT(ptp_oversize_sync_windows, sw_stats.oversize_sync_windows),
	PTP_SW_STAT(ptp_rx_no_timestamp, sw_stats.rx_no_timestamp),
	PTP_MC_STAT(ptp_tx_timestamp_packets, TX),
	PTP_MC_STAT(ptp_rx_timestamp_packets, RX),
	PTP_MC_STAT(ptp_timestamp_packets, TS),
	PTP_MC_STAT(ptp_filter_matches, FM),
	PTP_MC_STAT(ptp_non_filter_matches, NFM),
};
#define PTP_STAT_COUNT ARRAY_SIZE(efx_ptp_stat_desc)
static const unsigned long efx_ptp_stat_mask[] = {
	[0 ... BITS_TO_LONGS(PTP_STAT_COUNT) - 1] = ~0UL,
};

size_t efx_ptp_describe_stats(struct efx_nic *efx, u8 *strings)
{
	if (!efx->ptp_data)
		return 0;

	return efx_nic_describe_stats(efx_ptp_stat_desc, PTP_STAT_COUNT,
				      efx_ptp_stat_mask, strings);
}

void efx_ptp_reset_stats(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;

	if (ptp) {
		u64 temp[PTP_STAT_COUNT];

		memset(&ptp->sw_stats, 0, sizeof(ptp->sw_stats));

#ifdef CONFIG_SFC_DEBUGFS
		ptp->initialised_stats = false;
#endif
		efx_ptp_update_stats(efx, temp);
	}
}

size_t efx_ptp_update_stats(struct efx_nic *efx, u64 *stats)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_STATUS_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PTP_OUT_STATUS_LEN);
	size_t i;
	int rc;

	if (!ptp)
		return 0;

	/* Copy software statistics */
	for (i = 0; i < PTP_STAT_COUNT; i++) {
		if (efx_ptp_stat_desc[i].dma_width)
			continue;
		stats[i] = *(unsigned int *)((char *)efx->ptp_data +
					     efx_ptp_stat_desc[i].offset);
	}

	/* Fetch MC statistics.  We *must* fill in all statistics or
	 * risk leaking kernel memory to userland, so if the MCDI
	 * request fails we pretend we got zeroes.
	 */
	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_STATUS);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), NULL);
	if (rc)
		memset(outbuf, 0, sizeof(outbuf));
#ifdef CONFIG_SFC_DEBUGFS
	if (!ptp->initialised_stats) {
		memcpy(ptp->initial_mc_stats, _MCDI_PTR(outbuf, 0),
		       sizeof(ptp->initial_mc_stats));
		ptp->initialised_stats = !rc;
	}
#endif
	efx_nic_update_stats(efx_ptp_stat_desc, PTP_STAT_COUNT,
			     efx_ptp_stat_mask,
			     stats,
#ifdef CONFIG_SFC_DEBUGFS
			     ptp->initial_mc_stats,
#else
			     NULL,
#endif
			     _MCDI_PTR(outbuf, 0));

	return PTP_STAT_COUNT;
}

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
/* Read one MC PTP related statistic.  This actually gathers
 * all PTP statistics, throwing away the others.
 */
static int ptp_read_stat(struct efx_ptp_data *ptp,
			 u8 pos, efx_dword_t *value)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_STATUS_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PTP_OUT_STATUS_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_STATUS);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	rc = efx_mcdi_rpc(ptp->efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), NULL);
	if (rc) {
		*value->u32 = 0;
		return rc;
	}

	*value = outbuf[pos/sizeof(efx_dword_t)];

	return 0;
}

static ssize_t efx_pps_stats_int(struct efx_pps_data *pps, u8 pos, char *data)
{
	efx_dword_t value;

	ptp_read_stat(pps->ptp, pos, &value);

	return sprintf(data, "%d\n", EFX_DWORD_FIELD(value, EFX_DWORD_0));
}

static ssize_t efx_pps_stats_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buff)
{
	struct efx_pps_data *pps = container_of(kobj,
						struct efx_pps_data,
						kobj);

	struct efx_pps_dev_attr *efx_attr = container_of(attr,
							 struct efx_pps_dev_attr,
							 attr);
	return efx_attr->show(pps, efx_attr->pos, buff);
}

#define EFX_PPS_DEVICE_ATTR(_name, _mode, _pos) \
	static struct efx_pps_dev_attr efx_pps_attr_##_name = { \
		.attr = {.name = __stringify(_name), .mode = _mode }, \
		.pos = MC_CMD_PTP_OUT_STATUS_STATS_##_pos##_OFST, \
		.show = efx_pps_stats_int, \
	}

#define EFX_PPS_ATTR_PTR(_name) \
	&efx_pps_attr_##_name.attr

EFX_PPS_DEVICE_ATTR(pps_oflow, S_IRUGO, PPS_OFLOW);
EFX_PPS_DEVICE_ATTR(pps_bad, S_IRUGO, PPS_BAD);
EFX_PPS_DEVICE_ATTR(pps_per_min, S_IRUGO, PPS_PER_MIN);
EFX_PPS_DEVICE_ATTR(pps_per_max, S_IRUGO, PPS_PER_MAX);
EFX_PPS_DEVICE_ATTR(pps_per_last, S_IRUGO, PPS_PER_LAST);
EFX_PPS_DEVICE_ATTR(pps_per_mean, S_IRUGO, PPS_PER_MEAN);
EFX_PPS_DEVICE_ATTR(pps_off_min, S_IRUGO, PPS_OFF_MIN);
EFX_PPS_DEVICE_ATTR(pps_off_max, S_IRUGO, PPS_OFF_MAX);
EFX_PPS_DEVICE_ATTR(pps_off_last, S_IRUGO, PPS_OFF_LAST);
EFX_PPS_DEVICE_ATTR(pps_off_mean, S_IRUGO, PPS_OFF_MEAN);

static struct attribute *efx_pps_device_attrs[] = {
	EFX_PPS_ATTR_PTR(pps_oflow),
	EFX_PPS_ATTR_PTR(pps_bad),
	EFX_PPS_ATTR_PTR(pps_per_min),
	EFX_PPS_ATTR_PTR(pps_per_max),
	EFX_PPS_ATTR_PTR(pps_per_last),
	EFX_PPS_ATTR_PTR(pps_per_mean),
	EFX_PPS_ATTR_PTR(pps_off_min),
	EFX_PPS_ATTR_PTR(pps_off_max),
	EFX_PPS_ATTR_PTR(pps_off_last),
	EFX_PPS_ATTR_PTR(pps_off_mean),
	NULL,
};


/* Expose maximum PPB freq adjustment as a device attribute, allowing
 * applications to use correct freq adjustment limit per NIC */
static ssize_t show_max_adjfreq(struct device *dev,
				 struct device_attribute *attr,
				 char *buff)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct efx_nic *phc_efx = efx->phc_efx;
	s32 max_adjfreq = 0;

	if (phc_efx && phc_efx->ptp_data)
	        max_adjfreq = phc_efx->ptp_data->max_adjfreq;

	return sprintf(buff, "%d\n", max_adjfreq);
}

static DEVICE_ATTR(max_adjfreq, S_IRUGO, show_max_adjfreq, NULL);

static void efx_ptp_delete_data(struct kref *kref)
{
	struct efx_ptp_data *ptp = container_of(kref, struct efx_ptp_data,
						kref);
	struct efx_nic *efx = ptp->efx;

	if (ptp->pps_data)
		kfree(ptp->pps_data);
	kfree(ptp);
	efx->ptp_data = NULL;
}

static void ptp_boardattr_release(struct kobject *kobj)
{
	struct efx_pps_data *pps = container_of(kobj, struct efx_pps_data,
						kobj);
	struct efx_ptp_data *ptp = pps->ptp;

	kref_put(&ptp->kref, efx_ptp_delete_data);
}

static const struct sysfs_ops efx_sysfs_ops = {
	.show = efx_pps_stats_show,
	.store = NULL,
};

static struct kobj_type efx_sysfs_ktype = {
	.release = ptp_boardattr_release,
	/* May need to cast away const */
	.sysfs_ops = (struct sysfs_ops *)&efx_sysfs_ops,
	.default_attrs = efx_pps_device_attrs,
};

#endif

#ifdef CONFIG_SFC_DEBUGFS

#define EFX_PTP_UINT_PARAMETER(container_type, parameter)		\
	EFX_NAMED_PARAMETER(ptp_ ## parameter, container_type, parameter, \
			    unsigned int, efx_debugfs_read_int)

#define EFX_PTP_INT_PARAMETER(container_type, parameter)		\
	EFX_NAMED_PARAMETER(ptp_ ## parameter, container_type, parameter, \
			    int, efx_debugfs_read_int)

#define EFX_PTP_INT_ARRAY(container_type, parameter, idx)		\
	EFX_NAMED_PARAMETER(ptp_ ## parameter ## idx, container_type, \
			    parameter[idx], int, efx_debugfs_read_int)

/* PTP parameters */
static struct efx_debugfs_parameter efx_debugfs_ptp_parameters[] = {
	EFX_PTP_UINT_PARAMETER(struct efx_ptp_data, last_sync_time_host),
	EFX_PTP_UINT_PARAMETER(struct efx_ptp_data, min_sync_delta),
	EFX_PTP_UINT_PARAMETER(struct efx_ptp_data, max_sync_delta),
	EFX_PTP_UINT_PARAMETER(struct efx_ptp_data, average_sync_delta),
	EFX_PTP_UINT_PARAMETER(struct efx_ptp_data, last_sync_delta),
	EFX_PTP_UINT_PARAMETER(struct efx_ptp_data, bad_trailing_timestamps),
	EFX_PTP_INT_ARRAY(struct efx_ptp_data, sync_window_last, 0),
	EFX_PTP_INT_ARRAY(struct efx_ptp_data, sync_window_last, 1),
	EFX_PTP_INT_ARRAY(struct efx_ptp_data, sync_window_last, 2),
	EFX_PTP_INT_ARRAY(struct efx_ptp_data, sync_window_last, 3),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, sync_window_min),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, sync_window_max),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, sync_window_average),
	EFX_PTP_INT_ARRAY(struct efx_ptp_data, corrected_sync_window_last, 0),
	EFX_PTP_INT_ARRAY(struct efx_ptp_data, corrected_sync_window_last, 1),
	EFX_PTP_INT_ARRAY(struct efx_ptp_data, corrected_sync_window_last, 2),
	EFX_PTP_INT_ARRAY(struct efx_ptp_data, corrected_sync_window_last, 3),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, corrected_sync_window_min),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, corrected_sync_window_max),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, corrected_sync_window_average),
	{NULL},
};

static ssize_t set_ptp_stats(struct device *dev,
			     struct device_attribute *attr, const char *buf, size_t count)
{
	bool clear = count > 0 && *buf != '0';

	if (clear) {
		struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
		MCDI_DECLARE_BUF(in_rst_stats, MC_CMD_PTP_IN_RESET_STATS_LEN);
		int rc;

		MCDI_SET_DWORD(in_rst_stats, PTP_IN_OP, MC_CMD_PTP_OP_RESET_STATS);
		MCDI_SET_DWORD(in_rst_stats, PTP_IN_PERIPH_ID, 0);

		rc = efx_mcdi_rpc(efx, MC_CMD_PTP, in_rst_stats, sizeof(in_rst_stats),
				  NULL, 0, NULL);
		if (rc < 0)
			count = (size_t) rc;
	}

	return count;
}

static DEVICE_ATTR(ptp_stats, S_IWUSR, NULL, set_ptp_stats);

#endif

/* For Siena platforms NIC time is s and ns */
static void efx_ptp_ns_to_s_ns(s64 ns, u32 *nic_major, u32 *nic_minor)
{
	struct timespec64 ts = ns_to_timespec64(ns);
	*nic_major = (u32)ts.tv_sec;
	*nic_minor = ts.tv_nsec;
}

static ktime_t efx_ptp_s_ns_to_ktime_correction(u32 nic_major, u32 nic_minor,
						s32 correction)
{
	ktime_t kt = ktime_set(nic_major, nic_minor);
	if (correction >= 0)
		kt = ktime_add_ns(kt, (u64)correction);
	else
		kt = ktime_sub_ns(kt, (u64)-correction);
	return kt;
}

/* To convert from s27 format to ns we multiply then divide by a power of 2.
 * For the conversion from ns to s27, the operation is also converted to a
 * multiply and shift.
 */
#define S27_TO_NS_SHIFT	(27)
#define NS_TO_S27_MULT	(((1ULL << 63) + NSEC_PER_SEC / 2) / NSEC_PER_SEC)
#define NS_TO_S27_SHIFT	(63 - S27_TO_NS_SHIFT)
#define S27_MINOR_MAX	(1 << S27_TO_NS_SHIFT)

/* For Huntington platforms NIC time is in seconds and fractions of a second
 * where the minor register only uses 27 bits in units of 2^-27s.
 */
static void efx_ptp_ns_to_s27(s64 ns, u32 *nic_major, u32 *nic_minor)
{
	struct timespec64 ts = ns_to_timespec64(ns);
	u32 maj = (u32)ts.tv_sec;
	u32 min = (u32)(((u64)ts.tv_nsec * NS_TO_S27_MULT +
			 (1ULL << (NS_TO_S27_SHIFT - 1))) >> NS_TO_S27_SHIFT);

	/* The conversion can result in the minor value exceeding the maximum.
	 * In this case, round up to the next second.
	 */
	if (min >= S27_MINOR_MAX) {
		min -= S27_MINOR_MAX;
		maj++;
	}

	*nic_major = maj;
	*nic_minor = min;
}

static inline ktime_t efx_ptp_s27_to_ktime(u32 nic_major, u32 nic_minor)
{
	u32 ns = (u32)(((u64)nic_minor * NSEC_PER_SEC +
			(1ULL << (S27_TO_NS_SHIFT - 1))) >> S27_TO_NS_SHIFT);
	return ktime_set(nic_major, ns);
}

static ktime_t efx_ptp_s27_to_ktime_correction(u32 nic_major, u32 nic_minor,
					       s32 correction)
{
	/* Apply the correction and deal with carry */
	nic_minor += correction;
	if ((s32)nic_minor < 0) {
		nic_minor += S27_MINOR_MAX;
		nic_major--;
	} else if (nic_minor >= S27_MINOR_MAX) {
		nic_minor -= S27_MINOR_MAX;
		nic_major++;
	}

	return efx_ptp_s27_to_ktime(nic_major, nic_minor);
}

/* For Medford2 platforms the time is in seconds and quarter nanoseconds. */
static void efx_ptp_ns_to_s_qns(s64 ns, u32 *nic_major, u32 *nic_minor)
{
	struct timespec64 ts = ns_to_timespec64(ns);

	*nic_major = (u32)ts.tv_sec;
	*nic_minor = ts.tv_nsec * 4;
}

static ktime_t efx_ptp_s_qns_to_ktime_correction(u32 nic_major, u32 nic_minor,
						 s32 correction)
{
	ktime_t kt;

	nic_minor = DIV_ROUND_CLOSEST(nic_minor, 4);
	correction = DIV_ROUND_CLOSEST(correction, 4);

	kt = ktime_set(nic_major, nic_minor);

	if (correction >= 0)
		kt = ktime_add_ns(kt, (u64)correction);
	else
		kt = ktime_sub_ns(kt, (u64)-correction);
	return kt;
}


struct efx_channel *efx_ptp_channel(struct efx_nic *efx)
{
	return efx->ptp_data ? efx->ptp_data->channel : NULL;
}

static u32 last_sync_timestamp_major(struct efx_nic *efx)
{
	struct efx_channel *channel = efx_ptp_channel(efx);
	u32 major = 0;

	if (channel)
		major = channel->sync_timestamp_major;
	return major;
}

/* The 8XXX series and later can provide the time from the MAC, which is only
 * 48 bits long and provides meta-information in the top 2 bits.
 * See SFC bug 57928.
 */
static ktime_t
efx_ptp_mac_nic_to_ktime_correction(struct efx_nic *efx,
				    struct efx_ptp_data *ptp,
				    u32 nic_major, u32 nic_minor,
				    s32 correction)
{
	ktime_t kt = { 0 };

	if (!(nic_major & 0x80000000)) {
		WARN_ON_ONCE(nic_major >> 16);
		/* Use the top bits from the latest sync event. */
		nic_major &= 0xffff;
		nic_major |= (last_sync_timestamp_major(efx) & 0xffff0000);

		kt = ptp->nic_to_kernel_time(nic_major, nic_minor,
					     correction);
	}
	return kt;
}

ktime_t efx_ptp_nic_to_kernel_time(struct efx_tx_queue *tx_queue)
{
	struct efx_nic *efx = tx_queue->efx;
	struct efx_ptp_data *ptp = efx->ptp_data;
	ktime_t kt;

	if (efx_ptp_use_mac_tx_timestamps(efx))
		kt = efx_ptp_mac_nic_to_ktime_correction(efx, ptp,
				tx_queue->completed_timestamp_major,
				tx_queue->completed_timestamp_minor,
				ptp->ts_corrections.general_tx);
	else
		kt = ptp->nic_to_kernel_time(
				tx_queue->completed_timestamp_major,
				tx_queue->completed_timestamp_minor,
				ptp->ts_corrections.general_tx);
	return kt;
}

/* Get PTP attributes and set up time conversions */
int efx_ptp_get_attributes(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_GET_ATTRIBUTES_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PTP_OUT_GET_ATTRIBUTES_LEN);
	struct efx_ptp_data *ptp = efx->ptp_data;
	int rc;
	u32 fmt;
	size_t out_len;

	/* Get the PTP attributes. If the NIC doesn't support the operation we
	 * use the default format for compatibility with older NICs i.e.
	 * seconds and nanoseconds.
	 */
	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_GET_ATTRIBUTES);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf), &out_len);
	if (ptp) {
		if (rc == 0) {
			fmt = MCDI_DWORD(outbuf, PTP_OUT_GET_ATTRIBUTES_TIME_FORMAT);
		} else if (rc == -EINVAL) {
			fmt = MC_CMD_PTP_OUT_GET_ATTRIBUTES_SECONDS_NANOSECONDS;
		} else if (rc == -EPERM) {
			netif_info(efx, probe, efx->net_dev, "no PTP support\n");
			return rc;
		} else {
			efx_mcdi_display_error(efx, MC_CMD_PTP, sizeof(inbuf),
					       outbuf, sizeof(outbuf), rc);
			return rc;
		}

		switch (fmt) {
		case MC_CMD_PTP_OUT_GET_ATTRIBUTES_SECONDS_27FRACTION:
			ptp->ns_to_nic_time = efx_ptp_ns_to_s27;
			ptp->nic_to_kernel_time = efx_ptp_s27_to_ktime_correction;
			ptp->nic_time.minor_max = (1<<27);
			ptp->nic_time.sync_event_minor_shift = 19;
			break;
		case MC_CMD_PTP_OUT_GET_ATTRIBUTES_SECONDS_NANOSECONDS:
			ptp->ns_to_nic_time = efx_ptp_ns_to_s_ns;
			ptp->nic_to_kernel_time = efx_ptp_s_ns_to_ktime_correction;
			ptp->nic_time.minor_max = 1000000000;
			ptp->nic_time.sync_event_minor_shift = 22;
			break;
		case MC_CMD_PTP_OUT_GET_ATTRIBUTES_SECONDS_QTR_NANOSECONDS:
			ptp->ns_to_nic_time = efx_ptp_ns_to_s_qns;
			ptp->nic_to_kernel_time = efx_ptp_s_qns_to_ktime_correction;
			ptp->nic_time.minor_max = 4000000000UL;
			ptp->nic_time.sync_event_minor_shift = 24;
			break;
		default:
			return -ERANGE;
		}

		/* Precalculate acceptable difference between the minor time in the
		 * packet prefix and the last MCDI time sync event. We expect the
		 * packet prefix timestamp to be after of sync event by up to one
		 * sync event interval (0.25s) but we allow it to exceed this by a
		 * fuzz factor of (0.1s)
		 */
		ptp->nic_time.sync_event_diff_min = ptp->nic_time.minor_max
			- (ptp->nic_time.minor_max / 10);
		ptp->nic_time.sync_event_diff_max = (ptp->nic_time.minor_max / 4)
			+ (ptp->nic_time.minor_max / 10);

		/* MC_CMD_PTP_OP_GET_ATTRIBUTES has been extended twice from an older
		* operation MC_CMD_PTP_OP_GET_TIME_FORMAT. The function now may return
		* a value to use for the minimum acceptable corrected synchronization
		* window and may return further capabilities.
		* If we have the extra information store it. For older firmware that
		* does not implement the extended command use the default value.
		*/
		if (rc == 0 &&
		    out_len >= MC_CMD_PTP_OUT_GET_ATTRIBUTES_CAPABILITIES_OFST)
			ptp->min_synchronisation_ns =
				MCDI_DWORD(outbuf,
					   PTP_OUT_GET_ATTRIBUTES_SYNC_WINDOW_MIN);
		else
			ptp->min_synchronisation_ns = DEFAULT_MIN_SYNCHRONISATION_NS;
	}

	if (rc == 0 &&
	    out_len >= MC_CMD_PTP_OUT_GET_ATTRIBUTES_LEN)
		efx->ptp_capability =
			MCDI_DWORD(outbuf,
				   PTP_OUT_GET_ATTRIBUTES_CAPABILITIES);
	else
		efx->ptp_capability = 0;

	if (ptp) {
		ptp->capabilities = efx->ptp_capability;

		/* Set up the shift for conversion between frequency
		 * adjustments in parts-per-billion and the fixed-point
		 * fractional ns format that the adapter uses.
		 */
		if (ptp->capabilities & (1 << MC_CMD_PTP_OUT_GET_ATTRIBUTES_FP44_FREQ_ADJ_LBN))
			ptp->adjfreq_ppb_shift = PPB_SHIFT_FP44;
		else
			ptp->adjfreq_ppb_shift = PPB_SHIFT_FP40;
	}

	return 0;
}

/* Get PTP timestamp corrections */
static int efx_ptp_get_timestamp_corrections(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_GET_TIMESTAMP_CORRECTIONS_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PTP_OUT_GET_TIMESTAMP_CORRECTIONS_V2_LEN);
	int rc;
	size_t out_len;

	/* Get the timestamp corrections from the NIC. If this operation is
	 * not supported (older NICs) then no correction is required.
	 */
	MCDI_SET_DWORD(inbuf, PTP_IN_OP,
		       MC_CMD_PTP_OP_GET_TIMESTAMP_CORRECTIONS);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf), &out_len);
	if (rc == 0) {
		efx->ptp_data->ts_corrections.ptp_tx = MCDI_DWORD(outbuf,
			PTP_OUT_GET_TIMESTAMP_CORRECTIONS_TRANSMIT);
		efx->ptp_data->ts_corrections.ptp_rx = MCDI_DWORD(outbuf,
			PTP_OUT_GET_TIMESTAMP_CORRECTIONS_RECEIVE);
		efx->ptp_data->ts_corrections.pps_out = MCDI_DWORD(outbuf,
			PTP_OUT_GET_TIMESTAMP_CORRECTIONS_PPS_OUT);
		efx->ptp_data->ts_corrections.pps_in = MCDI_DWORD(outbuf,
			PTP_OUT_GET_TIMESTAMP_CORRECTIONS_PPS_IN);

		if (out_len >= MC_CMD_PTP_OUT_GET_TIMESTAMP_CORRECTIONS_V2_LEN) {
			efx->ptp_data->ts_corrections.general_tx = MCDI_DWORD(
				outbuf,
				PTP_OUT_GET_TIMESTAMP_CORRECTIONS_V2_GENERAL_TX);
			efx->ptp_data->ts_corrections.general_rx = MCDI_DWORD(
				outbuf,
				PTP_OUT_GET_TIMESTAMP_CORRECTIONS_V2_GENERAL_RX);
		} else {
			efx->ptp_data->ts_corrections.general_tx =
				efx->ptp_data->ts_corrections.ptp_tx;
			efx->ptp_data->ts_corrections.general_rx =
				efx->ptp_data->ts_corrections.ptp_rx;
		}
	} else if (rc == -EINVAL) {
		efx->ptp_data->ts_corrections.ptp_tx = 0;
		efx->ptp_data->ts_corrections.ptp_rx = 0;
		efx->ptp_data->ts_corrections.pps_out = 0;
		efx->ptp_data->ts_corrections.pps_in = 0;
		efx->ptp_data->ts_corrections.general_tx = 0;
		efx->ptp_data->ts_corrections.general_rx = 0;
	} else {
		efx_mcdi_display_error(efx, MC_CMD_PTP, sizeof(inbuf), outbuf,
				       sizeof(outbuf), rc);
		return rc;
	}

	return 0;
}

static int efx_ptp_adapter_has_support(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_READ_NIC_TIME_LEN);
	MCDI_DECLARE_BUF_ERR(outbuf);
	int rc;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_READ_NIC_TIME);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf), NULL);
	/* ENOSYS => the NIC doesn't support PTP.
	 * EPERM => the NIC doesn't have a PTP license.
	 */
	if (rc == -ENOSYS || rc == -EPERM)
		netif_info(efx, probe, efx->net_dev, "no PTP support (rc=%d)\n",
			rc);
	else if (rc)
		efx_mcdi_display_error(efx, MC_CMD_PTP,
				       MC_CMD_PTP_IN_READ_NIC_TIME_LEN,
				       outbuf, sizeof(outbuf), rc);
	return rc == 0;
}

/* Enable MCDI PTP support. */
static int efx_ptp_enable(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_ENABLE_LEN);
	MCDI_DECLARE_BUF_ERR(outbuf);
	int rc;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_ENABLE);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	MCDI_SET_DWORD(inbuf, PTP_IN_ENABLE_QUEUE,
		       efx->ptp_data->channel ?
		       efx->ptp_data->channel->channel : 0);
	MCDI_SET_DWORD(inbuf, PTP_IN_ENABLE_MODE, efx->ptp_data->mode);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf), NULL);
	rc = (rc == -EALREADY) ? 0 : rc;
	if (rc)
		efx_mcdi_display_error(efx, MC_CMD_PTP,
				       MC_CMD_PTP_IN_ENABLE_LEN,
				       outbuf, sizeof(outbuf), rc);
	return rc;
}

/* Disable MCDI PTP support.
 */
static int efx_ptp_disable(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_DISABLE_LEN);
	MCDI_DECLARE_BUF_ERR(outbuf);
	int rc;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_DISABLE);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf), NULL);
	rc = (rc == -EALREADY) ? 0 : rc;
	if (rc)
		efx_mcdi_display_error(efx, MC_CMD_PTP,
				       MC_CMD_PTP_IN_DISABLE_LEN,
				       outbuf, sizeof(outbuf), rc);
	return rc;
}

static void efx_ptp_deliver_rx_queue(struct efx_nic *efx)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&efx->ptp_data->rxq))) {
#if IS_ENABLED(CONFIG_VLAN_8021Q) || defined(CONFIG_SFC_TRACING)
		struct efx_ptp_match *match = (struct efx_ptp_match *)skb->cb;
#endif

		local_bh_disable();
#ifdef CONFIG_SFC_TRACING
		trace_sfc_receive(skb, false, match->vlan_tagged,
				  match->vlan_tci);
#endif
#if IS_ENABLED(CONFIG_VLAN_8021Q)
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
		if (match->vlan_tagged)
			vlan_hwaccel_receive_skb(skb, efx->vlan_group,
						 match->vlan_tci);
		else
			/* fall through */
#else
		if (match->vlan_tagged)
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       match->vlan_tci);
#endif
#endif
		netif_receive_skb(skb);
		local_bh_enable();
	}
}

static void efx_ptp_handle_no_channel(struct efx_nic *efx)
{
	netif_err(efx, drv, efx->net_dev,
		  "ERROR: PTP requires MSI-X and 1 additional interrupt"
		  "vector. PTP disabled\n");
}

/* Repeatedly send the host time to the MC which will capture the hardware
 * time.
 */
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_PPS_EVENT_TIME_TIMESPEC) && defined(EFX_HAVE_TIMESPEC64)
/* struct pps_event_time is old-style struct timespec, so map timespec64 to the
 * old names, just for this function.
 */
#define timespec64 timespec
#define timespec64_add_ns timespec_add_ns
#define timespec64_compare timespec_compare
#endif

struct efx_ptp_mcdi_data {
	struct kref ref;
	bool done;
	spinlock_t done_lock;
	wait_queue_head_t wq;
	int rc;
	size_t resplen;
	efx_dword_t *outbuf;
};

static void efx_ptp_mcdi_data_release(struct kref *ref)
{
	kfree(container_of(ref, struct efx_ptp_mcdi_data, ref));
}

static void efx_ptp_send_times(struct efx_nic *efx,
			       struct pps_event_time *last_time,
			       struct efx_ptp_mcdi_data *mcdi_data)
{
	struct pps_event_time now;
	struct timespec64 limit;
	struct efx_ptp_data *ptp = efx->ptp_data;
	int *mc_running = ptp->start.addr;

	pps_get_ts(&now);
	limit = now.ts_real;
	timespec64_add_ns(&limit, SYNCHRONISE_PERIOD_NS);

	/* Write host time for specified period or until MC is done */
	while ((timespec64_compare(&now.ts_real, &limit) < 0) &&
	       READ_ONCE(*mc_running) && !READ_ONCE(mcdi_data->done)) {
		struct timespec64 update_time;
		unsigned int host_time;

		/* Don't update continuously to avoid saturating the PCIe bus */
		update_time = now.ts_real;
		timespec64_add_ns(&update_time, SYNCHRONISATION_GRANULARITY_NS);
		do {
			pps_get_ts(&now);
		} while ((timespec64_compare(&now.ts_real, &update_time) < 0) &&
			 READ_ONCE(*mc_running));

		/* Synchronize against the MCDI completion to ensure we don't
		 * trash the MC doorbell on EF10 if the command completes and
		 * another is issued.
		 */
		spin_lock_bh(&mcdi_data->done_lock);

		/* Read time again to make sure we're as up-to-date as possible */
		pps_get_ts(&now);

		/* Synchronise NIC with single word of time only */
		host_time = (now.ts_real.tv_sec << MC_NANOSECOND_BITS |
			     now.ts_real.tv_nsec);

		/* Update host time in NIC memory */
		if (!mcdi_data->done)
			efx->type->ptp_write_host_time(efx, host_time);

		spin_unlock_bh(&mcdi_data->done_lock);
	}
	*last_time = now;
#ifdef CONFIG_SFC_DEBUGFS
	ptp->last_sync_time_host = (unsigned int) now.ts_real.tv_nsec;
#endif
}
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_PPS_EVENT_TIME_TIMESPEC) && defined(EFX_HAVE_TIMESPEC64)
/* Remove name mappings. */
#undef timespec64
#undef timespec64_add_ns
#undef timespec64_compare
#endif

/* Read a timeset from the MC's results and partial process. */
static void efx_ptp_read_timeset(MCDI_DECLARE_STRUCT_PTR(data),
				 struct efx_ptp_timeset *timeset)
{
	unsigned int start_ns, end_ns;

	timeset->host_start = MCDI_DWORD(data, PTP_OUT_SYNCHRONIZE_HOSTSTART);
	timeset->major = MCDI_DWORD(data, PTP_OUT_SYNCHRONIZE_MAJOR);
	timeset->minor = MCDI_DWORD(data, PTP_OUT_SYNCHRONIZE_MINOR);
	timeset->host_end = MCDI_DWORD(data, PTP_OUT_SYNCHRONIZE_HOSTEND),
	timeset->wait = MCDI_DWORD(data, PTP_OUT_SYNCHRONIZE_WAITNS);

	/* Ignore seconds */
	start_ns = timeset->host_start & MC_NANOSECOND_MASK;
	end_ns = timeset->host_end & MC_NANOSECOND_MASK;
	/* Allow for rollover */
	if (end_ns < start_ns)
		end_ns += NSEC_PER_SEC;
	/* Determine duration of operation */
	timeset->window = end_ns - start_ns;
}

#ifdef CONFIG_SFC_DEBUGFS
/* Calculate synchronisation window statistics */
static void efx_ptp_sync_stats_update_window(struct efx_ptp_data *ptp,
					     unsigned int idx, s32 window,
					     s32 corrected)
{
	if (idx < PTP_SYNC_ATTEMPTS)
		ptp->sync_window_last[idx] = window;
	if (window < ptp->sync_window_min)
		ptp->sync_window_min = window;
	if (window > ptp->sync_window_max)
		ptp->sync_window_max = window;

	/* This will underestimate the average because of the truncating
	 * integer calculations.  Attempt to correct by pseudo rounding up.
	 */
	ptp->sync_window_average = DIV_ROUND_UP(
		(AVERAGE_LENGTH - 1) * ptp->sync_window_average + window,
		AVERAGE_LENGTH);

	if (idx < PTP_SYNC_ATTEMPTS)
		ptp->corrected_sync_window_last[idx] = corrected;
	if (corrected < ptp->corrected_sync_window_min)
		ptp->corrected_sync_window_min = corrected;
	if (corrected > ptp->corrected_sync_window_max)
		ptp->corrected_sync_window_max = corrected;

	/* This will underestimate the average because of the truncating
	 * integer calculations.  Attempt to correct by pseudo rounding up.
	 */
	ptp->corrected_sync_window_average = DIV_ROUND_UP(
		(AVERAGE_LENGTH - 1) * ptp->corrected_sync_window_average +
		corrected, AVERAGE_LENGTH);
}
#endif

/* Process times received from MC.
 *
 * Extract times from returned results, and establish the minimum value
 * seen.  The minimum value represents the "best" possible time and events
 * too much greater than this are rejected - the machine is, perhaps, too
 * busy. A number of readings are taken so that, hopefully, at least one good
 * synchronisation will be seen in the results.
 */
static int
efx_ptp_process_times(struct efx_nic *efx, MCDI_DECLARE_STRUCT_PTR(synch_buf),
		      size_t response_length,
		      const struct pps_event_time *last_time)
{
	unsigned int number_readings =
		MCDI_VAR_ARRAY_LEN(response_length,
				   PTP_OUT_SYNCHRONIZE_TIMESET);
	unsigned int i;
	s32 ngood = 0;
	unsigned int last_good = 0;
	struct efx_ptp_data *ptp = efx->ptp_data;
	u32 last_sec;
	u32 start_sec;
	struct timespec64 delta;
	struct timespec64 mc_time;
	struct timespec64 diff;
	s64 diff_min = LONG_MAX;
	s64 diff_avg = 0;
	unsigned int good_mask = 0;

	if (number_readings == 0)
		return -EAGAIN;

	/* Read the set of results and find the last good host-MC
	 * synchronization result. The MC times when it finishes reading the
	 * host time so the corrected window time should be fairly constant
	 * for a given platform. Increment stats for any results that appear
	 * to be erroneous.
	 */
	for (i = 0; i < number_readings; i++) {
		s32 window, corrected;
		struct timespec64 wait;

		efx_ptp_read_timeset(
			MCDI_ARRAY_STRUCT_PTR(synch_buf,
					      PTP_OUT_SYNCHRONIZE_TIMESET, i),
			&ptp->timeset[i]);

		wait = ktime_to_timespec64(
			ptp->nic_to_kernel_time(0, ptp->timeset[i].wait, 0));
		window = ptp->timeset[i].window;
		corrected = window - wait.tv_nsec;

		/* We expect the uncorrected synchronization window to be at
		 * least as large as the interval between host start and end
		 * times. If it is smaller than this then this is mostly likely
		 * to be a consequence of the host's time being adjusted.
		 * Check that the corrected sync window is in a reasonable
		 * range. If it is out of range it is likely to be because an
		 * interrupt or other delay occurred between reading the system
		 * time and writing it to MC memory.
		 */
		if (window < SYNCHRONISATION_GRANULARITY_NS) {
			++ptp->sw_stats.invalid_sync_windows;
		} else if (corrected >= MAX_SYNCHRONISATION_NS) {
			++ptp->sw_stats.oversize_sync_windows;
		} else if (corrected < ptp->min_synchronisation_ns) {
			++ptp->sw_stats.undersize_sync_windows;
		} else {
			ngood++;
			last_good = i;

			/* Compute the average, marking this sample as good */
			good_mask |= 1 << i;
			mc_time = ktime_to_timespec64(ptp->nic_to_kernel_time(
				ptp->timeset[i].major, ptp->timeset[i].minor, 0));
			mc_time.tv_sec &= MC_SECOND_MASK;

			delta.tv_sec = ptp->timeset[i].host_start >> MC_NANOSECOND_BITS;
			delta.tv_nsec = ptp->timeset[i].host_start & MC_NANOSECOND_MASK;

			diff = timespec64_sub(mc_time, delta);
			ptp->timeset[i].mc_host_diff = timespec64_to_ns(&diff);
			diff_avg += ptp->timeset[i].mc_host_diff; /* Avg normalised below */
		}
#ifdef CONFIG_SFC_DEBUGFS
		efx_ptp_sync_stats_update_window(ptp, i, window, corrected);
#endif
	}

	if (ngood == 0)
		return -EAGAIN;

	if (ngood > 2) { /* No point doing this if only 1-2 valid samples */
		diff_avg = div_s64(diff_avg, ngood);
		/* Find the sample which is closest to the average */
		for (i = 0; i < number_readings; i++) {
			if (good_mask & (1 << i)) {
				s64 d = abs(ptp->timeset[i].mc_host_diff - diff_avg);
				if (d < diff_min) {
					diff_min = d;
					last_good = i;
				}
			}
		}
	}

	/* Calculate delay from last good sync (host time) to last_time.
	 * It is possible that the seconds rolled over between taking
	 * the start reading and the last value written by the host.  The
	 * timescales are such that a gap of more than one second is never
	 * expected.  delta is *not* normalised.
	 */
	start_sec = ptp->timeset[last_good].host_start >> MC_NANOSECOND_BITS;
	last_sec = last_time->ts_real.tv_sec & MC_SECOND_MASK;
	if (start_sec != last_sec &&
	    ((start_sec + 1) & MC_SECOND_MASK) != last_sec) {
		netif_warn(efx, hw, efx->net_dev,
			   "PTP bad synchronisation seconds\n");
		return -EAGAIN;
	}
	delta.tv_sec = (last_sec - start_sec) & 1;
	delta.tv_nsec =
		last_time->ts_real.tv_nsec -
		(ptp->timeset[last_good].host_start & MC_NANOSECOND_MASK);

	/* Convert the NIC time at last good sync into kernel time.
	 * No correction is required - this time is the output of a
	 * firmware process.
	 */
	mc_time = ktime_to_timespec64(ptp->nic_to_kernel_time(
				ptp->timeset[last_good].major,
				ptp->timeset[last_good].minor, 0));

#if defined(EFX_NOT_UPSTREAM)
	{
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_PPS_EVENT_TIME_TIMESPEC)
		struct timespec64 host_time =
			timespec64_sub(timespec_to_timespec64(last_time->ts_real), delta);
#else
		struct timespec64 host_time =
			timespec64_sub(last_time->ts_real, delta);
#endif
		struct timespec64 last_delta =
			timespec64_sub(mc_time, host_time);

		/* Don't let compiler treat last_delta as an alias for
		 * ptp->last_delta, which would exacerbate bug 41339
		 */
		barrier();

		ptp->last_delta = last_delta;
		ptp->last_delta_valid = true;
	}
#endif

	/* Calculate delay from NIC top of second to last_time */
	delta.tv_nsec += mc_time.tv_nsec;

	/* Set PPS timestamp to match NIC top of second */
	ptp->host_time_pps = *last_time;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_PPS_EVENT_TIME_TIMESPEC)
	pps_sub_ts(&ptp->host_time_pps, timespec64_to_timespec(delta));
#else
	pps_sub_ts(&ptp->host_time_pps, delta);
#endif

	return 0;
}

static void efx_ptp_cmd_complete(struct efx_nic *efx, unsigned long cookie,
				 int rc, efx_dword_t *outbuf,
				 size_t outlen_actual)
{
	struct efx_ptp_mcdi_data *data = (struct efx_ptp_mcdi_data *) cookie;

	data->resplen = min_t(size_t, outlen_actual,
			      MC_CMD_PTP_OUT_SYNCHRONIZE_LENMAX);
	memcpy(data->outbuf, outbuf, data->resplen);
	data->rc = rc;
	spin_lock_bh(&data->done_lock);
	data->done = true;
	spin_unlock_bh(&data->done_lock);
	wake_up(&data->wq);
	kref_put(&data->ref, efx_ptp_mcdi_data_release);
}

/* Synchronize times between the host and the MC */
static int efx_ptp_synchronize(struct efx_nic *efx, unsigned int num_readings)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct efx_ptp_mcdi_data *mcdi_data;
	unsigned int mcdi_handle;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_SYNCHRONIZE_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PTP_OUT_SYNCHRONIZE_LENMAX);
	int rc;
	unsigned long timeout;
	struct pps_event_time last_time = {};
	unsigned int loops = 0;
	int *start = ptp->start.addr;
	static const unsigned int PTP_SYNC_TIMEOUT = 10 * HZ;
	static const unsigned int PTP_START_TIMEOUT = PTP_SYNC_TIMEOUT * 4;
	unsigned long started;

	mcdi_data = kmalloc(sizeof(*mcdi_data), GFP_KERNEL);
	if (!mcdi_data)
		return -ENOMEM;

	kref_init(&mcdi_data->ref);
	mcdi_data->done = false;
	init_waitqueue_head(&mcdi_data->wq);
	spin_lock_init(&mcdi_data->done_lock);
	mcdi_data->outbuf = outbuf;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_SYNCHRONIZE);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	MCDI_SET_DWORD(inbuf, PTP_IN_SYNCHRONIZE_NUMTIMESETS,
		       num_readings);
	MCDI_SET_QWORD(inbuf, PTP_IN_SYNCHRONIZE_START_ADDR,
		       ptp->start.dma_addr);

	/* Clear flag that signals MC ready */
	WRITE_ONCE(*start, 0);
	started = jiffies;
	timeout = started + PTP_START_TIMEOUT;
	/* Get an additional reference - if efx_mcdi_rpc_async_ext returns
	 * successfully then the reference is no longer owned by us.:w
	 */
	kref_get(&mcdi_data->ref);
	while ((rc = efx_mcdi_rpc_async_ext(efx, MC_CMD_PTP,
				    inbuf, MC_CMD_PTP_IN_SYNCHRONIZE_LEN,
				    efx_ptp_cmd_complete,
				    NULL,
				    (unsigned long) mcdi_data,
				    false, true, &mcdi_handle)) == -EAGAIN &&
	       time_before(jiffies, timeout))
		efx_mcdi_wait_for_quiescence(efx, PTP_START_TIMEOUT);

	if (rc)
		/* Completer won't be called. */
		kref_put(&mcdi_data->ref, efx_ptp_mcdi_data_release);

	if (rc == -EAGAIN) {
		netif_err(efx, drv, efx->net_dev,
			  "MC PTP_OP command timed out trying to send after %u ms\n",
			  jiffies_to_msecs(jiffies - started));
		rc = -ETIMEDOUT;
	}

	if (rc == 0) {
		/* Wait for start from MC (or timeout) */
		timeout = jiffies + msecs_to_jiffies(MAX_SYNCHRONISE_WAIT_MS);
		while (!READ_ONCE(mcdi_data->done) && !READ_ONCE(*start) &&
		       (time_before(jiffies, timeout))) {
			udelay(20); /* Usually start MCDI execution quickly */
			loops++;
		}

		if (mcdi_data->done || !READ_ONCE(*start))
			++ptp->sw_stats.sync_timeouts;
		else if (loops <= 1)
			++ptp->sw_stats.fast_syncs;

		if (!mcdi_data->done && READ_ONCE(*start))
			efx_ptp_send_times(efx, &last_time, mcdi_data);

		if (!wait_event_timeout(mcdi_data->wq, mcdi_data->done,
					PTP_SYNC_TIMEOUT) &&
		    !mcdi_data->done) {
			efx_mcdi_cancel_cmd(efx, mcdi_handle);
			rc = -ETIMEDOUT;
		} else {
			rc = mcdi_data->rc;
		}
	}

	if (rc == 0) {
		rc = efx_ptp_process_times(efx, mcdi_data->outbuf,
					   mcdi_data->resplen, &last_time);
		if (rc == 0)
			++ptp->sw_stats.good_syncs;
		else
			++ptp->sw_stats.no_time_syncs;
	}

	kref_put(&mcdi_data->ref, efx_ptp_mcdi_data_release);

	/* Increment the bad syncs counter if the synchronize fails, whatever
	 * the reason.
	 */
	if (rc != 0)
		++ptp->sw_stats.bad_syncs;

	return rc;
}

#ifdef EFX_NOT_UPSTREAM
/* Get the host time from a given hardware time */
static bool efx_ptp_get_host_time(struct efx_nic *efx,
				  struct skb_shared_hwtstamps *timestamps)
{
#ifdef EFX_HAVE_SKB_SYSTSTAMP
	if (efx->ptp_data->last_delta_valid) {
		ktime_t diff = timespec64_to_ktime(efx->ptp_data->last_delta);
		timestamps->syststamp = ktime_sub(timestamps->hwtstamp, diff);
	} else {
		timestamps->syststamp = ktime_set(0, 0);
	}

	return efx->ptp_data->last_delta_valid;
#else
	return false;
#endif
}
#endif


/* Transmit a PTP packet via the dedicated hardware timestamped queue. */
static void efx_ptp_xmit_skb_queue(struct efx_nic *efx, struct sk_buff *skb)
{
	struct efx_ptp_data *ptp_data = efx->ptp_data;
	struct efx_tx_queue *tx_queue;

	tx_queue = efx->select_tx_queue(ptp_data->channel, skb);
	if (tx_queue && tx_queue->timestamping) {
		efx_enqueue_skb(tx_queue, skb);
		/* If netdev_xmit_more() was true in enqueue_skb() then our
		 * queue will be waiting for the next packet to push the
		 * doorbell. Since the next packet might not be coming this
		 * way (if it doesn't need a timestamp) we need to push it
		 * directly.
		 */
		efx_nic_push_buffers(tx_queue);
	} else {
		WARN_ONCE(1, "PTP channel has no timestamped tx queue\n");
		dev_kfree_skb_any(skb);
	}
}

/* Transmit a PTP packet, via the MCDI interface, to the wire. */
static void efx_ptp_xmit_skb_mc(struct efx_nic *efx, struct sk_buff *skb)
{
	struct efx_ptp_data *ptp_data = efx->ptp_data;
	struct skb_shared_hwtstamps timestamps;
	int rc = -EIO;
	MCDI_DECLARE_BUF(txtime, MC_CMD_PTP_OUT_TRANSMIT_LEN);
	size_t len;

	MCDI_SET_DWORD(ptp_data->txbuf, PTP_IN_OP, MC_CMD_PTP_OP_TRANSMIT);
	MCDI_SET_DWORD(ptp_data->txbuf, PTP_IN_PERIPH_ID, 0);

#ifdef EFX_NOT_UPSTREAM
	/* Get the UDP source IP address and use it to set up a unicast receive
	 * filter for received PTP packets. This enables PTP hybrid mode to
	 * work. */
	efx_ptp_insert_unicast_filters(efx, ip_hdr(skb)->saddr);
#endif

	if (skb_shinfo(skb)->nr_frags != 0) {
		rc = skb_linearize(skb);
		if (rc != 0)
			goto fail;
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		rc = skb_checksum_help(skb);
		if (rc != 0)
			goto fail;
	}
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	if (skb_vlan_tag_present(skb)) {
		skb = vlan_insert_tag_set_proto(skb, htons(ETH_P_8021Q),
				     skb_vlan_tag_get(skb));
		if (unlikely(!skb))
			return;
	}
#endif
	skb_copy_from_linear_data(skb,
				  MCDI_PTR(ptp_data->txbuf,
					   PTP_IN_TRANSMIT_PACKET),
				  skb->len);
	MCDI_SET_DWORD(ptp_data->txbuf, PTP_IN_TRANSMIT_LENGTH, skb->len);

	rc = efx_mcdi_rpc(efx, MC_CMD_PTP,
			  ptp_data->txbuf, MC_CMD_PTP_IN_TRANSMIT_LEN(skb->len),
			  txtime, sizeof(txtime), &len);
	if (rc != 0)
		goto fail;

	memset(&timestamps, 0, sizeof(timestamps));
	timestamps.hwtstamp = ptp_data->nic_to_kernel_time(
		MCDI_DWORD(txtime, PTP_OUT_TRANSMIT_MAJOR),
		MCDI_DWORD(txtime, PTP_OUT_TRANSMIT_MINOR),
		ptp_data->ts_corrections.ptp_tx);

#if defined(EFX_NOT_UPSTREAM) || (defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_PHC_SUPPORT))
	/* Failure to get the system timestamp is non-fatal */
	(void)efx_ptp_get_host_time(efx, &timestamps);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	efx->ptp_data->tx_ts_valid = 1;
	efx->ptp_data->tx_ts = timestamps;
#else
	skb_tstamp_tx(skb, &timestamps);
#endif

	rc = 0;

fail:
	dev_kfree_skb_any(skb);

	return;
}

static void efx_ptp_drop_time_expired_events(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct list_head *cursor;
	struct list_head *next;

	if (ptp->rx_ts_inline)
		return;

	/* Drop time-expired events */
	spin_lock_bh(&ptp->evt_lock);
	if (!list_empty(&ptp->evt_list)) {
		list_for_each_safe(cursor, next, &ptp->evt_list) {
			struct efx_ptp_event_rx *evt;

			evt = list_entry(cursor, struct efx_ptp_event_rx,
					 link);
			if (time_after(jiffies, evt->expiry)) {
				list_move(&evt->link, &ptp->evt_free_list);
				netif_warn(efx, hw, efx->net_dev,
					   "PTP rx event dropped\n");
			}
		}
	}
	spin_unlock_bh(&ptp->evt_lock);
}

static enum ptp_packet_state efx_ptp_match_rx(struct efx_nic *efx,
					      struct sk_buff *skb)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	bool evts_waiting;
	struct list_head *cursor;
	struct list_head *next;
	struct efx_ptp_match *match = (struct efx_ptp_match *)skb->cb;
	enum ptp_packet_state rc = PTP_PACKET_STATE_UNMATCHED;

#ifndef EFX_USE_KCOMPAT
	WARN_ON_ONCE(ptp->rx_ts_inline);
#else
	if (ptp->rx_ts_inline) {
		match->state = PTP_PACKET_STATE_MATCHED;
		return PTP_PACKET_STATE_MATCHED;
	}
#endif

	spin_lock_bh(&ptp->evt_lock);
	evts_waiting = !list_empty(&ptp->evt_list);
	spin_unlock_bh(&ptp->evt_lock);

	if (!evts_waiting)
		return PTP_PACKET_STATE_UNMATCHED;

	/* Look for a matching timestamp in the event queue */
	spin_lock_bh(&ptp->evt_lock);
	list_for_each_safe(cursor, next, &ptp->evt_list) {
		struct efx_ptp_event_rx *evt;

		evt = list_entry(cursor, struct efx_ptp_event_rx, link);
		if ((evt->seq0 == match->words[0]) &&
		    (evt->seq1 == match->words[1])) {
			struct skb_shared_hwtstamps *timestamps;

			/* Match - add in hardware timestamp */
			timestamps = skb_hwtstamps(skb);
			timestamps->hwtstamp = evt->hwtimestamp;

			match->state = PTP_PACKET_STATE_MATCHED;
			rc = PTP_PACKET_STATE_MATCHED;
			list_move(&evt->link, &ptp->evt_free_list);
			break;
		}
	}
	spin_unlock_bh(&ptp->evt_lock);

	return rc;
}

/* Process any queued receive events and corresponding packets
 *
 * q is returned with all the packets that are ready for delivery.
 */
static void efx_ptp_process_events(struct efx_nic *efx, struct sk_buff_head *q)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&ptp->rxq))) {
		struct efx_ptp_match *match;

		match = (struct efx_ptp_match *)skb->cb;
		if (match->state == PTP_PACKET_STATE_MATCH_UNWANTED) {
			__skb_queue_tail(q, skb);
		} else if (efx_ptp_match_rx(efx, skb) ==
			   PTP_PACKET_STATE_MATCHED) {
			__skb_queue_tail(q, skb);
		} else if (time_after(jiffies, match->expiry)) {
			match->state = PTP_PACKET_STATE_TIMED_OUT;
			++ptp->sw_stats.rx_no_timestamp;
			__skb_queue_tail(q, skb);
		} else {
			/* Replace unprocessed entry and stop */
			skb_queue_head(&ptp->rxq, skb);
			break;
		}
	}
}

#ifdef CONFIG_SFC_DEBUGFS
/* Calculate synchronisation delta statistics */
static void efx_ptp_update_delta_stats(struct efx_nic *efx,
				       struct skb_shared_hwtstamps *timestamps)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	ktime_t diff;
	ktime_t delta = timespec64_to_ktime(ptp->last_delta);

	diff = ktime_sub(timestamps->hwtstamp, delta);
	ptp->last_sync_delta = ktime_to_ns(diff);
	if (ptp->last_sync_delta < ptp->min_sync_delta)
		ptp->min_sync_delta = ptp->last_sync_delta;

	if (ptp->last_sync_delta > ptp->max_sync_delta)
		ptp->max_sync_delta = ptp->last_sync_delta;

	/* This will underestimate the average because of the
	 * truncating integer calculations.  Attempt to correct by
	 * pseudo rounding up.
	 */
	ptp->average_sync_delta = DIV_ROUND_UP(
		(AVERAGE_LENGTH - 1) * ptp->average_sync_delta +
		ptp->last_sync_delta, AVERAGE_LENGTH);
}
#endif

/* Complete processing of a received packet */
static inline void efx_ptp_process_rx(struct efx_nic *efx, struct sk_buff *skb)
{
#if defined(CONFIG_SFC_TRACING) || IS_ENABLED(CONFIG_VLAN_8021Q) || \
	defined(EFX_NOT_UPSTREAM)
	struct efx_ptp_match *match = (struct efx_ptp_match *)skb->cb;
#endif
#ifdef EFX_NOT_UPSTREAM
	struct skb_shared_hwtstamps *timestamps = skb_hwtstamps(skb);

	/* Translate timestamps, as required */
	if (match->state == PTP_PACKET_STATE_MATCHED &&
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_KTIME_UNION)
	    timestamps->hwtstamp) {
#else
	    timestamps->hwtstamp.tv64) {
#endif
		efx_ptp_get_host_time(efx, timestamps);
#ifdef CONFIG_SFC_DEBUGFS
		efx_ptp_update_delta_stats(efx, timestamps);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
		efx_ptp_save_rx_ts(efx, skb, timestamps);
#endif
	}

#endif
	local_bh_disable();
#ifdef CONFIG_SFC_TRACING
	trace_sfc_receive(skb, false, match->vlan_tagged, match->vlan_tci);
#endif
#if IS_ENABLED(CONFIG_VLAN_8021Q)
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_VLAN_RX_PATH)
	if (match->vlan_tagged)
		vlan_hwaccel_receive_skb(skb, efx->vlan_group,
				match->vlan_tci);
	else
		/* fall through */
#else
	if (match->vlan_tagged)
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       match->vlan_tci);
#endif
#endif
	netif_receive_skb(skb);
	local_bh_enable();
}

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
/* Size of timestamp appended to packets for PTP on AOE */
#define PTP_AOE_TIMESTAMP_LENGTH 8
#define PTP_AOE_TIMESTAMP_INVALID (1 << 31)
#define PTP_AOE_TIMESTAMP_NS_MASK ((1 << 30) - 1)

static void
efx_ptp_aoe_attach_timestamp(struct efx_nic *efx, struct sk_buff *skb)
{
	struct skb_shared_hwtstamps *timestamps = skb_hwtstamps(skb);
	u8 *data = skb->data;
	struct iphdr *ip_hdr;
	struct udphdr *udp_hdr;
	unsigned int offset = 0;

#if !defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	if (((struct efx_ptp_match *)skb->cb)->vlan_tagged)
		offset = VLAN_HLEN;
#endif

	ip_hdr = (struct iphdr *)&data[offset];
	udp_hdr = (struct udphdr *)&data[offset + ip_hdr->ihl * sizeof(u32)];

	/* If the packet is a PTP event packet, then look for a timestamp */
	if (likely(skb->protocol == htons(ETH_P_IP)) &&
	   ip_hdr->protocol == IPPROTO_UDP &&
	   udp_hdr->dest == htons(PTP_EVENT_PORT)) {
		/* Work out where the IP packet ends i.e. the size of the
		 * ethernet header plus the total length of the IP packet plus
		 * the vlan header if present. If there is a timestamp present
		 * it will be the last few bytes of the packet and so there
		 * should be enough space between the end of the ip packet and
		 * the end of the skb.
		 */
		offset += ntohs(ip_hdr->tot_len);

		/* Is there sufficient space for the timestamp? */
		if (offset + PTP_AOE_TIMESTAMP_LENGTH <= skb->len) {
			__be32 ts[2];
			u32 seconds, nanoseconds;

			BUILD_BUG_ON(sizeof(ts) != PTP_AOE_TIMESTAMP_LENGTH);

			skb_copy_bits(skb, skb->len - PTP_AOE_TIMESTAMP_LENGTH,
				      ts, PTP_AOE_TIMESTAMP_LENGTH);
			seconds = ntohl(ts[0]);
			nanoseconds = ntohl(ts[1]);

			/* If the invalid timestamp bit is clear and the
			 * timestamp is not zero, use it */
			if (!(nanoseconds & PTP_AOE_TIMESTAMP_INVALID) &&
			    ((seconds != 0) || (nanoseconds != 0))) {
				nanoseconds &= PTP_AOE_TIMESTAMP_NS_MASK;
				timestamps->hwtstamp = ktime_set(seconds,
								 nanoseconds);
				/* Trim the socket buffer to remove the
				 * timestamp.  pskb_trim() can't fail as
				 * the skb is not cloned.
				 */
				WARN_ON(pskb_trim(skb, skb->len -
						  PTP_AOE_TIMESTAMP_LENGTH));
			}
#ifdef CONFIG_SFC_DEBUGFS
			else {
				struct efx_ptp_data *ptp = efx->ptp_data;
				++ptp->bad_trailing_timestamps;
			}
#endif
		}
	}
}
#endif

static void efx_ptp_remove_multicast_filters(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;

	if (ptp->rxfilter_installed) {
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter_primary_general);
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter_primary_event);
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter_peer_delay_general);
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter_peer_delay_event);
		ptp->rxfilter_installed = false;
	}
}

static int efx_ptp_insert_multicast_filters(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct efx_filter_spec rxfilter;
	int rc;

	if (!ptp->channel || ptp->rxfilter_installed)
		return 0;

	/* Must filter on both event and general ports to ensure
	 * that there is no packet re-ordering.
	 */
	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				   efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       htonl(PTP_PRIMARY_ADDRESS),
				       htons(PTP_EVENT_PORT));
	if (rc != 0)
		return rc;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		return rc;
	ptp->rxfilter_primary_event = rc;

	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				   efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       htonl(PTP_PRIMARY_ADDRESS),
				       htons(PTP_GENERAL_PORT));
	if (rc != 0)
		goto fail;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		goto fail;
	ptp->rxfilter_primary_general = rc;

	/* Filtering of event and general port on peer delay address */
	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				   efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       htonl(PTP_PEER_DELAY_ADDRESS),
				       htons(PTP_EVENT_PORT));
	if (rc != 0)
		goto fail2;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		goto fail2;
	ptp->rxfilter_peer_delay_event = rc;

	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				   efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       htonl(PTP_PEER_DELAY_ADDRESS),
				       htons(PTP_GENERAL_PORT));
	if (rc != 0)
		goto fail3;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		goto fail3;
	ptp->rxfilter_peer_delay_general = rc;

	ptp->rxfilter_installed = true;
	return 0;

fail3:
	efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
				  ptp->rxfilter_peer_delay_event);
fail2:
	efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
				  ptp->rxfilter_primary_general);
fail:
	efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
				  ptp->rxfilter_primary_event);
	return rc;
}

#ifdef EFX_NOT_UPSTREAM

static void efx_ptp_remove_unicast_filters(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;

	if (ptp->rxfilter_unicast_installed) {
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter_unicast_event);
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter_unicast_general);
		ptp->rxfilter_unicast_installed = false;
	}
}

static int efx_ptp_insert_unicast_filters(struct efx_nic *efx,
					  __be32 unicast_address)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct efx_filter_spec rxfilter;
	int rc;

	if (!ptp->channel ||
	    (ptp->rxfilter_unicast_installed &&
	     (ptp->rxfilter_unicast_address == unicast_address)))
		return 0;

	/* Remove the existing unicast filter. This has no effect if
	 * the filters are not installed */
	efx_ptp_remove_unicast_filters(efx);

	/* Filtering of event and general port on unicast address */
	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       unicast_address,
				       htons(PTP_EVENT_PORT));
	if (rc != 0)
		return rc;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		return rc;
	ptp->rxfilter_unicast_event = rc;

	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       unicast_address,
				       htons(PTP_GENERAL_PORT));
	if (rc != 0)
		goto fail;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		goto fail;

	ptp->rxfilter_unicast_general = rc;
	ptp->rxfilter_unicast_address = unicast_address;
	ptp->rxfilter_unicast_installed = true;

	netif_warn(efx, hw, efx->net_dev,
		   "PTP set up unicast filter on %#x\n", unicast_address);

	return 0;

fail:
	efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
				  ptp->rxfilter_unicast_event);
	return rc;
}

#endif /* EFX_NOT_UPSTREAM */

static int efx_ptp_start(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	int rc;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	ptp->rx_ts_tail = 0;
	ptp->rx_ts_head = 0;
	ptp->tx_ts_valid = 0;
#endif
	ptp->reset_required = false;

	rc = efx_ptp_insert_multicast_filters(efx);
	if (rc)
		return rc;

	rc = efx_ptp_enable(efx);
	if (rc != 0)
		goto fail;

	ptp->evt_frag_idx = 0;
	ptp->current_adjfreq = 0;

	return 0;

fail:
	efx_ptp_remove_multicast_filters(efx);
	return rc;
}

static int efx_ptp_stop(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct list_head *cursor;
	struct list_head *next;
	int rc;

	if (ptp == NULL)
		return 0;

	rc = efx_ptp_disable(efx);

	efx_ptp_remove_multicast_filters(efx);
#ifdef EFX_NOT_UPSTREAM
	efx_ptp_remove_unicast_filters(efx);
#endif

	/* Make sure RX packets are really delivered */
	efx_ptp_deliver_rx_queue(efx);
	skb_queue_purge(&efx->ptp_data->txq);

	/* Drop any pending receive events */
	spin_lock_bh(&efx->ptp_data->evt_lock);
	list_for_each_safe(cursor, next, &efx->ptp_data->evt_list) {
		list_move(cursor, &efx->ptp_data->evt_free_list);
	}
#if defined(EFX_NOT_UPSTREAM)
	ptp->last_delta_valid = false;
#endif
	spin_unlock_bh(&efx->ptp_data->evt_lock);

	return rc;
}

static int efx_ptp_restart(struct efx_nic *efx)
{
	if (efx->ptp_data && efx->ptp_data->enabled)
#ifndef EFX_NOT_UPSTREAM
		return efx_ptp_start(efx);
#else
	{
		int rc = efx_ptp_start(efx);
		if (!rc)
		       rc = efx_ptp_synchronize(efx, PTP_SYNC_ATTEMPTS);
		return rc;
	}
#endif
	return 0;
}

static void efx_ptp_pps_worker(struct work_struct *work)
{
	struct efx_ptp_data *ptp =
		container_of(work, struct efx_ptp_data, pps_work);
	struct efx_nic *efx = ptp->efx;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
	struct ptp_clock_event ptp_evt;
#endif

	if (efx_ptp_synchronize(efx, PTP_SYNC_ATTEMPTS))
		return;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
#ifdef EFX_NOT_UPSTREAM
	if (!ptp->nic_ts_enabled)
		return;
#endif
	ptp_evt.type = PTP_CLOCK_PPSUSR;
	ptp_evt.pps_times = ptp->host_time_pps;
	ptp_clock_event(ptp->phc_clock, &ptp_evt);
#endif
}

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
int efx_ptp_pps_get_event(struct efx_nic *efx, struct efx_ts_get_pps *event)
{
	struct timespec64 nic_time;
	struct efx_pps_data *pps_data;
	unsigned int ev;
	unsigned int err;
	unsigned int timeout;

	if (!efx->ptp_data)
		return -ENOTTY;

	if (!efx->ptp_data->pps_data)
		return -ENOTTY;

	pps_data = efx->ptp_data->pps_data;
	timeout = msecs_to_jiffies(event->timeout);

	ev = pps_data->last_ev_taken;

	if (ev == pps_data->last_ev) {
		err = wait_event_interruptible_timeout(pps_data->read_data,
						       ev != pps_data->last_ev,
						       timeout);
		if (err == 0)
			return -ETIMEDOUT;

		/* Check for pending signals */
		if (err == -ERESTARTSYS)
			return -EINTR;
	}

	/* Return the fetched timestamp */
	nic_time = ktime_to_timespec64(pps_data->n_assert);
	event->nic_assert.tv_sec = nic_time.tv_sec;
	event->nic_assert.tv_nsec = nic_time.tv_nsec;

	event->sys_assert.tv_sec = pps_data->s_assert.tv_sec;
	event->sys_assert.tv_nsec = pps_data->s_assert.tv_nsec;

	event->delta.tv_sec = pps_data->s_delta.tv_sec;
	event->delta.tv_nsec = pps_data->s_delta.tv_nsec;
	event->sequence = pps_data->last_ev;

	pps_data->last_ev_taken = pps_data->last_ev;

	return 0;
}

int efx_ptp_hw_pps_enable(struct efx_nic *efx, struct efx_ts_hw_pps *data)
{
	struct efx_pps_data *pps_data;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_PPS_ENABLE_LEN);
	int rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	if (!efx->ptp_data->pps_data)
		return -ENOTTY;

	if (!data) {
		return -EINVAL;
	}

	pps_data = efx->ptp_data->pps_data;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_PPS_ENABLE);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	MCDI_SET_DWORD(inbuf, PTP_IN_PPS_ENABLE_OP,
		       data->enable ? MC_CMD_PTP_ENABLE_PPS :
				      MC_CMD_PTP_DISABLE_PPS);
	MCDI_SET_DWORD(inbuf, PTP_IN_PPS_ENABLE_QUEUE_ID,
		       efx->ptp_data->channel ?
		       efx->ptp_data->channel->channel : 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);

	if (rc)
		return rc;

	if (data->enable) {
		pps_data->last_ev = 0;
		pps_data->last_ev_taken = 0;
		memset(&pps_data->s_delta, 0x0, sizeof(pps_data->s_delta));
		memset(&pps_data->s_assert, 0x0, sizeof(pps_data->s_assert));
		memset(&pps_data->n_assert, 0x0, sizeof(pps_data->n_assert));
	}

	pps_data->nic_hw_pps_enabled = data->enable;

	return 0;
}
#endif

static void efx_ptp_worker(struct work_struct *work)
{
	struct efx_ptp_data *ptp_data =
		container_of(work, struct efx_ptp_data, work);
	struct efx_nic *efx = ptp_data->efx;
	struct sk_buff *skb;
	struct sk_buff_head tempq;

	if (ptp_data->reset_required) {
		efx_ptp_stop(efx);
		efx_ptp_start(efx);
		return;
	}

	efx_ptp_drop_time_expired_events(efx);

	__skb_queue_head_init(&tempq);
	efx_ptp_process_events(efx, &tempq);

	while ((skb = skb_dequeue(&ptp_data->txq)))
		ptp_data->xmit_skb(efx, skb);

	while ((skb = __skb_dequeue(&tempq)))
		efx_ptp_process_rx(efx, skb);
}

#ifdef EFX_NOT_UPSTREAM
static ssize_t siena_show_ptp(struct device *dev,
			      struct device_attribute *attr,
			      char *buff)
{
	return sprintf(buff, "HW clock\nPTP TS\n");
}

static DEVICE_ATTR(ptp_caps, S_IRUGO, siena_show_ptp, NULL);
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
static int efx_ptp_create_pps(struct efx_ptp_data *ptp)
{
	struct efx_pps_data *pps;

	pps = kzalloc(sizeof(*pps), GFP_ATOMIC);
	if (!pps)
		return -ENOMEM;

	init_waitqueue_head(&pps->read_data);
	pps->nic_hw_pps_enabled = false;

	if (kobject_init_and_add(&pps->kobj,
				 &efx_sysfs_ktype,
				 &ptp->efx->pci_dev->dev.kobj,
				 "pps_stats"))
		goto fail1;

	pps->ptp = ptp;
	ptp->pps_data = pps;
	kref_get(&ptp->kref);

	return 0;
fail1:
	kfree(pps);
	ptp->pps_data = NULL;

	return -ENOMEM;
}

static void efx_ptp_destroy_pps(struct efx_ptp_data *ptp)
{
	if (!ptp->pps_data)
		return;

	kobject_del(&ptp->pps_data->kobj);
	kobject_put(&ptp->pps_data->kobj);
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
static const struct ptp_clock_info efx_phc_clock_info = {
	.owner		= THIS_MODULE,
	.name		= "sfc",
	.max_adj	= MAX_PPB, /* unused, ptp_data->max_adjfreq used instead */
	.n_alarm	= 0,
	.n_ext_ts	= 0,
	.n_per_out	= 0,
	.pps		= 1,
	.adjfreq	= efx_phc_adjfreq,
	.adjtime	= efx_phc_adjtime,
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_64BIT_PHC)
	.gettime	= efx_phc_gettime32,
	.settime	= efx_phc_settime32,
#else
	.gettime64	= efx_phc_gettime,
	.settime64	= efx_phc_settime,
#endif
	.enable		= efx_phc_enable,
};
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT) || defined(EFX_NOT_UPSTREAM)
static int efx_create_pps_worker(struct efx_ptp_data *ptp)
{
	char busdevice[11];

	snprintf(busdevice, sizeof(busdevice), "%04x:%02x:%02x",
		 pci_domain_nr(ptp->efx->pci_dev->bus),
		 ptp->efx->pci_dev->bus->number,
		 ptp->efx->pci_dev->devfn);

	INIT_WORK(&ptp->pps_work, efx_ptp_pps_worker);
#if defined(EFX_NOT_UPSTREAM)
	ptp->pps_workwq = efx_alloc_workqueue("sfc_pps_%s", WQ_UNBOUND |
					      WQ_MEM_RECLAIM | WQ_SYSFS, 1,
					      busdevice);
#else
	ptp->pps_workwq = alloc_workqueue("sfc_pps_%s", WQ_UNBOUND |
					  WQ_MEM_RECLAIM | WQ_SYSFS, 1,
					  busdevice);
#endif
	if (!ptp->pps_workwq)
		return -ENOMEM;
	return 0;
}
#endif
bool efx_ptp_uses_separate_channel(struct efx_nic *efx)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_TSTAMP)
	  return efx->ptp_capability & (1 << MC_CMD_PTP_OUT_GET_ATTRIBUTES_RX_TSTAMP_OOB_LBN);
#else
	  return true;
#endif
}

/* Find interface on the same physical adapter (by port0 MAC address) and setup
 * efx->phc_efx. This cannot be merged with efx_associate() as efx_phc_exposed()
 * is required at probe time.
 */
static void efx_associate_phc(struct efx_nic *efx)
{
	struct efx_nic *other, *next;

	EFX_WARN_ON_PARANOID(efx->phc_efx);
	spin_lock(&ptp_all_funcs_list_lock);

	list_for_each_entry_safe(other, next, &efx_all_funcs_list,
				 node_ptp_all_funcs) {
		EFX_WARN_ON_PARANOID(other == efx);
		if (other->phc_efx == other &&
		    ether_addr_equal(other->adapter_base_addr,
				     efx->adapter_base_addr)) {
			efx->phc_efx = other;
			goto out;
		}
	}

	efx->phc_efx = efx;
out:
	list_add(&efx->node_ptp_all_funcs, &efx_all_funcs_list);
	spin_unlock(&ptp_all_funcs_list_lock);
}

/* Clear efx->phc_efx for any interface that points to this one.
*/
static void efx_dissociate_phc(struct efx_nic *efx)
{
	struct efx_nic *other, *next;

	spin_lock(&ptp_all_funcs_list_lock);

	list_del(&efx->node_ptp_all_funcs);
	list_for_each_entry_safe(other, next, &efx_all_funcs_list,
		node_ptp_all_funcs) {
		EFX_WARN_ON_PARANOID(other == efx);
		if (other->phc_efx == efx)
			other->phc_efx = NULL;
	}
	efx->phc_efx = NULL;

	spin_unlock(&ptp_all_funcs_list_lock);
}

static inline bool efx_phc_exposed(struct efx_nic *efx)
{
	return efx->phc_efx == efx;
}

/* Initialise PTP state. */
int efx_ptp_probe(struct efx_nic *efx, struct efx_channel *channel)
{
	struct efx_ptp_data *ptp;
	int rc = 0;
	unsigned int pos;

	ptp = kzalloc(sizeof(struct efx_ptp_data), GFP_KERNEL);
	efx->ptp_data = ptp;
	if (!efx->ptp_data)
		return -ENOMEM;

	rc = efx_mcdi_get_board_cfg(efx, 0, efx->adapter_base_addr, NULL,
				    NULL);
	if (rc < 0)
		return rc;

	efx_associate_phc(efx);

	ptp->efx = efx;
	ptp->channel = channel;
	ptp->rx_ts_inline = efx_nic_rev(efx) >= EFX_REV_HUNT_A0;
	kref_init(&ptp->kref);
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
	if (efx->aoe_data) {
		ptp->rx_ts_inline = true;
		/* no sync events required */
		if (channel)
			channel->sync_events_state = SYNC_EVENTS_DISABLED;
	}
#endif

#ifdef CONFIG_SFC_DEBUGFS
	for (pos = 0; pos < (MC_CMD_PTP_OUT_STATUS_LEN / sizeof(u32)); pos++)
		efx->ptp_data->mc_stats[pos] = pos;

	rc = efx_extend_debugfs_port(efx, efx->ptp_data, 0,
				     efx_debugfs_ptp_parameters);
	if (rc < 0)
		goto fail;
#endif

	rc = efx_nic_alloc_buffer(efx, &ptp->start, sizeof(int), GFP_KERNEL);
	if (rc != 0)
		goto fail1;

	skb_queue_head_init(&ptp->rxq);
	skb_queue_head_init(&ptp->txq);
	ptp->workwq = create_singlethread_workqueue("sfc_ptp");
	if (!ptp->workwq) {
		rc = -ENOMEM;
		goto fail2;
	}

	if (efx_ptp_use_mac_tx_timestamps(efx)) {
		ptp->xmit_skb = efx_ptp_xmit_skb_queue;
		/* Request sync events on this channel. */
		channel->sync_events_state = SYNC_EVENTS_QUIESCENT;
	} else {
		ptp->xmit_skb = efx_ptp_xmit_skb_mc;
	}

	INIT_WORK(&ptp->work, efx_ptp_worker);
	ptp->config.flags = 0;
	ptp->config.tx_type = HWTSTAMP_TX_OFF;
	ptp->config.rx_filter = HWTSTAMP_FILTER_NONE;
	INIT_LIST_HEAD(&ptp->evt_list);
	INIT_LIST_HEAD(&ptp->evt_free_list);
	spin_lock_init(&ptp->evt_lock);
	for (pos = 0; pos < MAX_RECEIVE_EVENTS; pos++)
		list_add(&ptp->rx_evts[pos].link, &ptp->evt_free_list);

	/* Get the NIC PTP attributes and set up time conversions */
	rc = efx_ptp_get_attributes(efx);
	if (rc < 0)
		goto fail3;

	/* Get the timestamp corrections */
	rc = efx_ptp_get_timestamp_corrections(efx);
	if (rc < 0)
		goto fail3;

	/* Set the NIC clock maximum frequency adjustment */
	/* TODO: add MCDI call to get this value from the NIC */
	ptp->max_adjfreq = MAX_PPB;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
	if (efx_phc_exposed(efx)) {
		ptp->phc_clock_info = efx_phc_clock_info;
		ptp->phc_clock_info.max_adj = ptp->max_adjfreq;
		ptp->phc_clock = ptp_clock_register(&ptp->phc_clock_info,
						    &efx->pci_dev->dev);
		if (IS_ERR(ptp->phc_clock)) {
			rc = PTR_ERR(ptp->phc_clock);
			goto fail3;
		}
		kref_get(&ptp->kref);
		rc = efx_create_pps_worker(ptp);
		if (rc < 0)
			goto fail4;

	}
	ptp->nic_ts_enabled = false;
#elif defined(EFX_NOT_UPSTREAM)
	rc = efx_create_pps_worker(ptp);
	if (rc < 0)
		goto fail3;
#endif

#ifdef EFX_NOT_UPSTREAM

#ifdef CONFIG_SFC_PPS
	rc = efx_ptp_create_pps(ptp);
	if (rc < 0)
		goto fail5;
#endif

#ifdef CONFIG_SFC_DEBUGFS
	ptp->min_sync_delta = UINT_MAX;
	ptp->sync_window_min = INT_MAX;
	ptp->sync_window_max = INT_MIN;
	ptp->corrected_sync_window_min = INT_MAX;
	ptp->corrected_sync_window_max = INT_MIN;

	rc = device_create_file(&efx->pci_dev->dev,
				&dev_attr_ptp_stats);
	if (rc < 0)
		goto fail6;
#endif

	/* Only advertise ptp_caps when a clock was exposed, otherwise
	 * older versions of sfptpd will try to synchronise multiple
	 * net devices that share a clock.
	 */
	if (efx_phc_exposed(efx)) {
		rc = device_create_file(&efx->pci_dev->dev,
					&dev_attr_ptp_caps);
		if (rc < 0)
			goto fail7;
	}

	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_max_adjfreq);
	if (rc < 0)
		goto fail8;

#endif /* EFX_NOT_UPSTREAM */

	return 0;

#ifdef EFX_NOT_UPSTREAM
fail8:
	if (efx_phc_exposed(efx))
		device_remove_file(&efx->pci_dev->dev, &dev_attr_ptp_caps);
fail7:
#ifdef CONFIG_SFC_DEBUGFS
	device_remove_file(&efx->pci_dev->dev, &dev_attr_ptp_stats);
fail6:
#endif
#ifdef CONFIG_SFC_PPS
	efx_ptp_destroy_pps(efx->ptp_data);
fail5:
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
	if (ptp->phc_clock)
		destroy_workqueue(ptp->pps_workwq);
#endif
#endif /* EFX_NOT_UPSTREAM */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
fail4:
#ifdef EFX_NOT_UPSTREAM
	kref_put(&ptp->kref, efx_ptp_delete_data);
#endif
	if (ptp->phc_clock)
		ptp_clock_unregister(ptp->phc_clock);
#endif

fail3:
	destroy_workqueue(efx->ptp_data->workwq);

fail2:
	efx_nic_free_buffer(efx, &ptp->start);

fail1:
#ifdef CONFIG_SFC_DEBUGFS
	efx_trim_debugfs_port(efx, efx_debugfs_ptp_parameters);

fail:
#endif
#ifdef EFX_NOT_UPSTREAM
	kref_put(&ptp->kref, efx_ptp_delete_data);
#endif
	efx_dissociate_phc(efx);

	return rc;
}

/* Initialise PTP channel.
 *
 * Setting core_index to zero causes the queue to be initialised and doesn't
 * overlap with 'rxq0' because ptp.c doesn't use skb_record_rx_queue.
 */
static int efx_ptp_probe_channel(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;

	channel->irq_moderation_us = 0;
	channel->rx_queue.core_index = 0;

	return efx_ptp_probe(efx, channel);
}

void efx_ptp_remove(struct efx_nic *efx)
{
	/* ensure that the work queues are canceled and destroyed only once.
	 * Use the workwq pointer to track this.
	 */
	if (!efx->ptp_data || !efx->ptp_data->workwq)
		return;

	(void)efx_ptp_disable(efx);

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
	efx_ptp_destroy_pps(efx->ptp_data);
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
	cancel_work_sync(&efx->ptp_data->work);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
	if (efx->ptp_data->pps_workwq)
		cancel_work_sync(&efx->ptp_data->pps_work);
#endif
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_CANCEL_WORK_SYNC)
	flush_workqueue(efx->ptp_data->workwq);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
	if (ptp->phc_clock)
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT) || defined(EFX_NOT_UPSTREAM)
		flush_workqueue(efx->ptp_data->pps_workwq);
#endif
#endif

	skb_queue_purge(&efx->ptp_data->rxq);
	skb_queue_purge(&efx->ptp_data->txq);

#ifdef EFX_NOT_UPSTREAM
	if (efx_phc_exposed(efx) || efx->ptp_data->phc_clock)
		device_remove_file(&efx->pci_dev->dev, &dev_attr_ptp_caps);
	device_remove_file(&efx->pci_dev->dev, &dev_attr_max_adjfreq);
#endif
#ifdef CONFIG_SFC_DEBUGFS
	device_remove_file(&efx->pci_dev->dev, &dev_attr_ptp_stats);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
	if (efx->ptp_data->phc_clock)
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT) || defined(EFX_NOT_UPSTREAM)
		destroy_workqueue(efx->ptp_data->pps_workwq);
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
	if (efx->ptp_data->phc_clock) {
		ptp_clock_unregister(efx->ptp_data->phc_clock);
#ifdef EFX_NOT_UPSTREAM
		kref_put(&efx->ptp_data->kref, efx_ptp_delete_data);
#endif
	}
#endif

	destroy_workqueue(efx->ptp_data->workwq);
	efx->ptp_data->workwq = NULL;

	efx_nic_free_buffer(efx, &efx->ptp_data->start);
#ifdef CONFIG_SFC_DEBUGFS
	efx_trim_debugfs_port(efx, efx_debugfs_ptp_parameters);
#endif
#ifdef EFX_NOT_UPSTREAM
	kref_put(&efx->ptp_data->kref, efx_ptp_delete_data);
#endif
	efx_dissociate_phc(efx);
}

static void efx_ptp_remove_channel(struct efx_channel *channel)
{
	efx_ptp_remove(channel->efx);
}

static void efx_ptp_get_channel_name(struct efx_channel *channel,
				     char *buf, size_t len)
{
	snprintf(buf, len, "%s-ptp", channel->efx->name);
}

/* Determine whether this packet should be processed by the PTP module
 * or transmitted conventionally.
 */
bool efx_ptp_is_ptp_tx(struct efx_nic *efx, struct sk_buff *skb)
{
	return efx->ptp_data &&
		efx->ptp_data->enabled &&
		skb->len >= PTP_MIN_LENGTH &&
		skb->len <= MC_CMD_PTP_IN_TRANSMIT_PACKET_MAXNUM &&
		likely(skb->protocol == htons(ETH_P_IP)) &&
		skb_transport_header_was_set(skb) &&
		skb_network_header_len(skb) >= sizeof(struct iphdr) &&
		ip_hdr(skb)->protocol == IPPROTO_UDP &&
		skb_headlen(skb) >=
		skb_transport_offset(skb) + sizeof(struct udphdr) &&
		udp_hdr(skb)->dest == htons(PTP_EVENT_PORT);
}

/* Receive a PTP packet.  Packets are queued until the arrival of
 * the receive timestamp from the MC - this will probably occur after the
 * packet arrival because of the processing in the MC.
 */
static bool efx_ptp_rx(struct efx_channel *channel, struct sk_buff *skb)
{
	struct efx_nic *efx = channel->efx;
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct efx_ptp_match *match = (struct efx_ptp_match *)skb->cb;
	u8 *match_data_012, *match_data_345;
	unsigned int version;
#if defined(EFX_NOT_UPSTREAM)
	unsigned int uuid_len;
	u8 domain, *uuid;
#endif
	u8 *data = skb->data;

	match->expiry = jiffies + msecs_to_jiffies(PKT_EVENT_LIFETIME_MS);

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	/* All vlan info is provided by the "hardware" in this case. */
	match->vlan_tagged = !vlan_get_tag(skb, &match->vlan_tci);
#else
	/* In this case, software accounts for lack of receive vlan acceleration */
	if (skb->dev->features & NETIF_F_HW_VLAN_CTAG_RX)
		match->vlan_tagged = !vlan_get_tag(skb, &match->vlan_tci);
	else if ((skb->protocol == htons(ETH_P_8021Q) ||
		  skb->protocol == htons(ETH_P_8021AD)) && pskb_may_pull(skb, VLAN_HLEN)) {
#ifdef EFX_NOT_UPSTREAM
		/* VLAN tag has to be stripped away for Siena */
		if (ptp->vlan_filter.num_vlan_tags != 0) {
			match->vlan_tagged = 1;
			match->vlan_tci = skb->vlan_tci = ntohs(*((__be16 *)skb->data));
			skb->protocol = *((__be16 *)(skb->data + 2));
			skb_pull(skb, VLAN_HLEN);
		} else {
			/* required because of the fixed offsets used below */
			data += VLAN_HLEN;
		}
#else
		/* required because of the fixed offsets used below */
		data += VLAN_HLEN;
#endif
	}
#endif

	/* catch up with skb->data if there's a VLAN tag present */
	if (match->vlan_tagged)
		data += VLAN_HLEN;

	/* Correct version? */
	if (ptp->mode == MC_CMD_PTP_MODE_V1) {
		if (!pskb_may_pull(skb, PTP_V1_MIN_LENGTH))
			return false;
		version = ntohs(*(__be16 *)&data[PTP_V1_VERSION_OFFSET]);
		if (version != PTP_VERSION_V1) {
			return false;
		}

		/* PTP V1 uses all six bytes of the UUID to match the packet
		 * to the timestamp
		 */
		match_data_012 = data + PTP_V1_UUID_OFFSET;
		match_data_345 = data + PTP_V1_UUID_OFFSET + 3;
	} else {
		if (!pskb_may_pull(skb, PTP_V2_MIN_LENGTH))
			return false;
		version = data[PTP_V2_VERSION_OFFSET];
		if ((version & PTP_VERSION_V2_MASK) != PTP_VERSION_V2) {
			return false;
		}

		/* The original V2 implementation uses bytes 2-7 of
		 * the UUID to match the packet to the timestamp. This
		 * discards two of the bytes of the MAC address used
		 * to create the UUID (SF bug 33070).  The PTP V2
		 * enhanced mode fixes this issue and uses bytes 0-2
		 * and byte 5-7 of the UUID.
		 */
		match_data_345 = data + PTP_V2_UUID_OFFSET + 5;
		if (ptp->mode == MC_CMD_PTP_MODE_V2) {
			match_data_012 = data + PTP_V2_UUID_OFFSET + 2;
		} else {
			match_data_012 = data + PTP_V2_UUID_OFFSET + 0;
			BUG_ON(ptp->mode != MC_CMD_PTP_MODE_V2_ENHANCED);
		}
	}

	/* Does this packet require timestamping? */
	if (ntohs(*(__be16 *)&data[PTP_DPORT_OFFSET]) == PTP_EVENT_PORT) {
#if defined(EFX_NOT_UPSTREAM)
		if (ptp->mode == MC_CMD_PTP_MODE_V1) {
			uuid = &data[PTP_V1_UUID_OFFSET];
			uuid_len = PTP_V1_UUID_LENGTH;
		} else {
			uuid = &data[PTP_V2_UUID_OFFSET];
			uuid_len = PTP_V2_UUID_LENGTH;

			domain = data[PTP_V2_DOMAIN_OFFSET];
			if (ptp->domain_filter.enable &&
			    (ptp->domain_filter.domain != domain)) {
				return false;
			}
		}

		if (ptp->uuid_filter.enable &&
		    (memcmp(ptp->uuid_filter.uuid, uuid, uuid_len) != 0)) {
			return false;
		}

		/* bug 33071 only singly tagged VLAN packets are currently
		 * supported for PTP. */
		if (!match->vlan_tagged &&
		    (ptp->vlan_filter.num_vlan_tags != 0)) {
			return false;
		}

		if (match->vlan_tagged &&
		    ((ptp->vlan_filter.num_vlan_tags == 0) ||
		     (ptp->vlan_filter.vlan_tags[0] !=
		      (match->vlan_tci & VLAN_TAG_MASK)))) {
			return false;
		}

#endif
		match->state = PTP_PACKET_STATE_UNMATCHED;

		/* We expect the sequence number to be in the same position in
		 * the packet for PTP V1 and V2
		 */
		BUILD_BUG_ON(PTP_V1_SEQUENCE_OFFSET != PTP_V2_SEQUENCE_OFFSET);
		BUILD_BUG_ON(PTP_V1_SEQUENCE_LENGTH != PTP_V2_SEQUENCE_LENGTH);

		/* Extract UUID/Sequence information */
		match->words[0] = (match_data_012[0]         |
				   (match_data_012[1] << 8)  |
				   (match_data_012[2] << 16) |
				   (match_data_345[0] << 24));
		match->words[1] = (match_data_345[1]         |
				   (match_data_345[2] << 8)  |
				   (data[PTP_V1_SEQUENCE_OFFSET +
					 PTP_V1_SEQUENCE_LENGTH - 1] <<
				    16));
	} else {
		match->state = PTP_PACKET_STATE_MATCH_UNWANTED;
	}

	skb_queue_tail(&ptp->rxq, skb);
	queue_work(ptp->workwq, &ptp->work);

	return true;
}

/* Transmit a PTP packet.  This has to be transmitted by the MC
 * itself, through an MCDI call.  MCDI calls aren't permitted
 * in the transmit path so defer the actual transmission to a suitable worker.
 */
int efx_ptp_tx(struct efx_nic *efx, struct sk_buff *skb)
{
	struct efx_ptp_data *ptp = efx->ptp_data;

	skb_queue_tail(&ptp->txq, skb);
	efx_xmit_hwtstamp_pending(skb);
	queue_work(ptp->workwq, &ptp->work);

	return NETDEV_TX_OK;
}

int efx_ptp_get_mode(struct efx_nic *efx)
{
	return efx->ptp_data->mode;
}

int efx_ptp_change_mode(struct efx_nic *efx, bool enable_wanted,
			unsigned int new_mode)
{
	int rc = 0;

	/* If we are being asked to disable PTP we always disable it.
	 * Otherwise, carry out the enable request unless we are already
	 * enabled and the mode isn't changing.
	 */
	if (!enable_wanted) {
		rc = efx_ptp_stop(efx);
	} else if (!efx->ptp_data->enabled ||
		   (efx->ptp_data->mode != new_mode)) {
		/* We need to disable PTP to change modes */
		if (efx->ptp_data->enabled) {
			efx->ptp_data->enabled = false;
			rc = efx_ptp_stop(efx);
			if (rc != 0)
				return rc;
		}

		/* Set new operating mode and establish baseline
		 * synchronisation, which must succeed.
		 */
		efx->ptp_data->mode = new_mode;
		if (netif_running(efx->net_dev))
			rc = efx_ptp_start(efx);
		if (rc == 0) {
			rc = efx_ptp_synchronize(efx, PTP_SYNC_ATTEMPTS * 2);
			if (rc != 0)
				efx_ptp_stop(efx);
		}
	}

	if (rc != 0)
		return rc;

	efx->ptp_data->enabled = enable_wanted;
	return 0;
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
int efx_ptp_ts_init(struct efx_nic *efx, struct hwtstamp_config *init)
#else
static int efx_ptp_ts_init(struct efx_nic *efx, struct hwtstamp_config *init)
#endif
{
	int rc;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	if (!efx->ptp_data)
		return -ENOTTY;
#endif

	if (init->flags)
		return -EINVAL;

	if ((init->tx_type != HWTSTAMP_TX_OFF) &&
	    (init->tx_type != HWTSTAMP_TX_ON))
		return -ERANGE;

	rc = efx->type->ptp_set_ts_config(efx, init);
	if (rc)
		return rc;

	efx->ptp_data->config = *init;
	return 0;
}

void efx_ptp_get_ts_info(struct efx_nic *efx, struct ethtool_ts_info *ts_info)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct efx_nic *phc_efx = efx->phc_efx;

	ASSERT_RTNL();

	if (!ptp)
		return;

	ts_info->so_timestamping |= (SOF_TIMESTAMPING_TX_HARDWARE |
				     SOF_TIMESTAMPING_RX_HARDWARE |
				     SOF_TIMESTAMPING_RAW_HARDWARE);
#ifdef EFX_NOT_UPSTREAM
	ts_info->so_timestamping |= SOF_TIMESTAMPING_SYS_HARDWARE;
#endif
	/* Check licensed features. */
	if (efx_ptp_use_mac_tx_timestamps(efx)) {
		struct efx_ef10_nic_data *nic_data = efx->nic_data;

		if (!(nic_data->licensed_features &
		      (1 << LICENSED_V3_FEATURES_TX_TIMESTAMPS_LBN)))
			ts_info->so_timestamping &=
				~SOF_TIMESTAMPING_TX_HARDWARE;
	}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
	if (ptp->phc_clock)
		ts_info->phc_index = ptp_clock_index(ptp->phc_clock);
	else if (phc_efx && phc_efx->ptp_data && phc_efx->ptp_data->phc_clock)
		ts_info->phc_index =
			ptp_clock_index(phc_efx->ptp_data->phc_clock);
#else
	/* Use phc_efx's ifindex as a fake clock index */
	if (phc_efx && phc_efx->ptp_data)
		ts_info->phc_index = phc_efx->net_dev->ifindex;
#endif
	ts_info->tx_types = 1 << HWTSTAMP_TX_OFF | 1 << HWTSTAMP_TX_ON;
	ts_info->rx_filters = ptp->efx->type->hwtstamp_filters;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_TSTAMP)

int efx_ptp_set_ts_config(struct efx_nic *efx, struct ifreq *ifr)
{
	struct hwtstamp_config config;
	int rc;

	/* Not a PTP enabled port */
	if (!efx->ptp_data)
		return -EOPNOTSUPP;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	rc = efx_ptp_ts_init(efx, &config);
	if (rc != 0)
		return rc;

	return copy_to_user(ifr->ifr_data, &config, sizeof(config))
		? -EFAULT : 0;
}

#else /* EFX_USE_KCOMPAT && !EFX_HAVE_NET_TSTAMP */

int efx_ptp_ts_read(struct efx_nic *efx, struct efx_ts_read *read)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct timespec64 uts;

	if (!ptp)
		return -ENOTTY;

	local_bh_disable();
	read->tx_valid = ptp->tx_ts_valid;
	if (ptp->tx_ts_valid) {
		ptp->tx_ts_valid = 0;
		uts = ktime_to_timespec64(ptp->tx_ts.syststamp);
		read->tx_ts.tv_sec = uts.tv_sec;
		read->tx_ts.tv_nsec = uts.tv_nsec;
		uts = ktime_to_timespec64(ptp->tx_ts.hwtstamp);
		read->tx_ts_hw.tv_sec = uts.tv_sec;
		read->tx_ts_hw.tv_nsec = uts.tv_nsec;
	}
	read->rx_valid = 0;
	if (ptp->rx_ts_head != ptp->rx_ts_tail) {
		struct efx_ptp_rx_timestamp *ts;

		ts = &ptp->rx_ts[ptp->rx_ts_head];
		uts = ktime_to_timespec64(ts->ts.syststamp);
		read->rx_ts.tv_sec = uts.tv_sec;
		read->rx_ts.tv_nsec = uts.tv_nsec;
		uts = ktime_to_timespec64(ts->ts.hwtstamp);
		read->rx_ts_hw.tv_sec = uts.tv_sec;
		read->rx_ts_hw.tv_nsec = uts.tv_nsec;
		memcpy(read->uuid, ts->uuid, sizeof(read->uuid));
		memcpy(read->seqid, ts->seqid, sizeof(read->seqid));
		read->rx_valid = 1;

		ptp->rx_ts_head++;
		if (ptp->rx_ts_head >= MAX_RX_TS_ENTRIES)
			ptp->rx_ts_head = 0;
	}
	local_bh_enable();

	return 0;
}

#endif /* !EFX_USE_KCOMPAT || EFX_HAVE_NET_TSTAMP */

int efx_ptp_get_ts_config(struct efx_nic *efx, struct ifreq *ifr)
{
	if (!efx->ptp_data)
		return -EOPNOTSUPP;

	return copy_to_user(ifr->ifr_data, &efx->ptp_data->config,
			    sizeof(efx->ptp_data->config)) ? -EFAULT : 0;
}

#if defined(EFX_NOT_UPSTREAM)
static struct ptp_clock_info *efx_ptp_clock_info(struct efx_nic *efx)
{
	struct ptp_clock_info *phc_clock_info;

	if (!efx->ptp_data)
		return NULL;

	phc_clock_info = &efx->ptp_data->phc_clock_info;
	if (!phc_clock_info && efx->phc_efx && efx->phc_efx->ptp_data)
		phc_clock_info = &efx->phc_efx->ptp_data->phc_clock_info;

	return phc_clock_info;
}

int efx_ptp_ts_settime(struct efx_nic *efx, struct efx_ts_settime *settime)
{
	struct ptp_clock_info *phc_clock_info = efx_ptp_clock_info(efx);
	int ret;
	struct timespec64 ts;
	s64 delta;

	if (!phc_clock_info)
		return -ENOTTY;

	ts.tv_sec = settime->ts.tv_sec;
	ts.tv_nsec = settime->ts.tv_nsec;

	if (settime->iswrite) {
		delta = timespec64_to_ns(&ts);

		return efx_phc_adjtime(phc_clock_info, delta);
	} else {
		ret = efx_phc_gettime(phc_clock_info, &ts);
		if (!ret) {
			settime->ts.tv_sec = ts.tv_sec;
			settime->ts.tv_nsec = ts.tv_nsec;
		}
		return ret;
	}
}

int efx_ptp_ts_adjtime(struct efx_nic *efx, struct efx_ts_adjtime *adjtime)
{
	struct ptp_clock_info *phc_clock_info = efx_ptp_clock_info(efx);

	if (!phc_clock_info)
		return -ENOTTY;

	if (adjtime->adjustment > MAX_PPB)
		adjtime->adjustment = MAX_PPB;
	else if (adjtime->adjustment < -MAX_PPB)
		adjtime->adjustment = -MAX_PPB;

	return efx_phc_adjfreq(phc_clock_info, adjtime->adjustment);
}

int efx_ptp_ts_sync(struct efx_nic *efx, struct efx_ts_sync *sync)
{
	int rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	rc = efx_ptp_synchronize(efx, PTP_SYNC_ATTEMPTS);
	if (rc == 0) {
		sync->ts.tv_sec = efx->ptp_data->last_delta.tv_sec;
		sync->ts.tv_nsec = efx->ptp_data->last_delta.tv_nsec;
	}
	return rc;
}

int efx_ptp_ts_set_sync_status(struct efx_nic *efx,
			       struct efx_ts_set_sync_status *status)
{
	MCDI_DECLARE_BUF(mcdi_req, MC_CMD_PTP_IN_SET_SYNC_STATUS_LEN);
	u32 flag;
	int rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	if (!(efx->ptp_data->capabilities &
		(1 << MC_CMD_PTP_OUT_GET_ATTRIBUTES_REPORT_SYNC_STATUS_LBN)))
		return -EOPNOTSUPP;

	if (status->in_sync != 0)
		flag = MC_CMD_PTP_IN_SET_SYNC_STATUS_IN_SYNC;
	else
		flag = MC_CMD_PTP_IN_SET_SYNC_STATUS_NOT_IN_SYNC;

	MCDI_SET_DWORD(mcdi_req, PTP_IN_OP, MC_CMD_PTP_OP_SET_SYNC_STATUS);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_PERIPH_ID, 0);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_SET_SYNC_STATUS_STATUS, flag);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_SET_SYNC_STATUS_TIMEOUT,
		       status->timeout);

	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, mcdi_req, sizeof(mcdi_req),
			  NULL, 0, NULL);
	return rc;
}

int efx_ptp_ts_set_vlan_filter(struct efx_nic *efx,
			       struct efx_ts_set_vlan_filter *vlan_filter)
{
	MCDI_DECLARE_BUF(mcdi_req, MC_CMD_PTP_IN_RX_SET_VLAN_FILTER_LEN);
	u32 *tag;
	int i, rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	if (vlan_filter->num_vlan_tags > TS_MAX_VLAN_TAGS)
		return -ERANGE;

	MCDI_SET_DWORD(mcdi_req, PTP_IN_OP, MC_CMD_PTP_OP_RX_SET_VLAN_FILTER);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_PERIPH_ID, 0);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_RX_SET_VLAN_FILTER_NUM_VLAN_TAGS,
		       vlan_filter->num_vlan_tags);
	tag = (u32 *)MCDI_PTR(mcdi_req, PTP_IN_RX_SET_VLAN_FILTER_VLAN_TAG);
	for (i = 0; i < vlan_filter->num_vlan_tags; i++)
		tag[i] = vlan_filter->vlan_tags[i];

	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, mcdi_req, sizeof(mcdi_req),
			  NULL, 0, NULL);
	if (rc == 0)
		efx->ptp_data->vlan_filter = *vlan_filter;

	return rc;
}

int efx_ptp_ts_set_uuid_filter(struct efx_nic *efx,
			       struct efx_ts_set_uuid_filter *uuid_filter)
{
	MCDI_DECLARE_BUF(mcdi_req, MC_CMD_PTP_IN_RX_SET_UUID_FILTER_LEN);
	u8 *uuid;
	int rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	MCDI_SET_DWORD(mcdi_req, PTP_IN_OP, MC_CMD_PTP_OP_RX_SET_UUID_FILTER);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_PERIPH_ID, 0);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_RX_SET_UUID_FILTER_ENABLE,
		       uuid_filter->enable);
	uuid = (u8 *)MCDI_PTR(mcdi_req, PTP_IN_RX_SET_UUID_FILTER_UUID);
	memcpy(uuid, uuid_filter->uuid,
	       MC_CMD_PTP_IN_RX_SET_UUID_FILTER_UUID_LEN);

	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, mcdi_req, sizeof(mcdi_req),
			  NULL, 0, NULL);
	if (rc == 0)
		efx->ptp_data->uuid_filter = *uuid_filter;

	return rc;
}

int efx_ptp_ts_set_domain_filter(struct efx_nic *efx,
				 struct efx_ts_set_domain_filter *domain_filter)
{
	MCDI_DECLARE_BUF(mcdi_req, MC_CMD_PTP_IN_RX_SET_DOMAIN_FILTER_LEN);
	int rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	MCDI_SET_DWORD(mcdi_req, PTP_IN_OP,
		       MC_CMD_PTP_OP_RX_SET_DOMAIN_FILTER);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_PERIPH_ID, 0);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_RX_SET_DOMAIN_FILTER_ENABLE,
		       domain_filter->enable);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_RX_SET_DOMAIN_FILTER_DOMAIN,
		       domain_filter->domain);

	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, mcdi_req, sizeof(mcdi_req),
			  NULL, 0, NULL);
	if (rc == 0)
		efx->ptp_data->domain_filter = *domain_filter;

	return rc;
}
#endif

static void ptp_event_failure(struct efx_nic *efx, int expected_frag_len)
{
	struct efx_ptp_data *ptp = efx->ptp_data;

	netif_err(efx, hw, efx->net_dev,
		"PTP unexpected event length: got %d expected %d\n",
		ptp->evt_frag_idx, expected_frag_len);
	ptp->reset_required = true;
	queue_work(ptp->workwq, &ptp->work);
}

/* Process a completed receive event.  Put it on the event queue and
 * start worker thread.  This is required because event and their
 * correspoding packets may come in either order.
 */
static void ptp_event_rx(struct efx_nic *efx, struct efx_ptp_data *ptp)
{
	struct efx_ptp_event_rx *evt = NULL;

	if (WARN_ON_ONCE(ptp->rx_ts_inline))
		return;

	if (ptp->evt_frag_idx != 3) {
		ptp_event_failure(efx, 3);
		return;
	}

	spin_lock_bh(&ptp->evt_lock);
	if (!list_empty(&ptp->evt_free_list)) {
		evt = list_first_entry(&ptp->evt_free_list,
				       struct efx_ptp_event_rx, link);
		list_del(&evt->link);

		evt->seq0 = EFX_QWORD_FIELD(ptp->evt_frags[2], MCDI_EVENT_DATA);
		evt->seq1 = (EFX_QWORD_FIELD(ptp->evt_frags[2],
					     MCDI_EVENT_SRC)        |
			     (EFX_QWORD_FIELD(ptp->evt_frags[1],
					      MCDI_EVENT_SRC) << 8) |
			     (EFX_QWORD_FIELD(ptp->evt_frags[0],
					      MCDI_EVENT_SRC) << 16));
		evt->hwtimestamp = efx->ptp_data->nic_to_kernel_time(
			EFX_QWORD_FIELD(ptp->evt_frags[0], MCDI_EVENT_DATA),
			EFX_QWORD_FIELD(ptp->evt_frags[1], MCDI_EVENT_DATA),
			ptp->ts_corrections.ptp_rx);
		evt->expiry = jiffies + msecs_to_jiffies(PKT_EVENT_LIFETIME_MS);
		list_add_tail(&evt->link, &ptp->evt_list);

		queue_work(ptp->workwq, &ptp->work);
	} else if (net_ratelimit()) {
		/* Log a rate-limited warning message. */
		netif_err(efx, rx_err, efx->net_dev, "PTP event queue overflow\n");
	}
	spin_unlock_bh(&ptp->evt_lock);
}

static void ptp_event_fault(struct efx_nic *efx, struct efx_ptp_data *ptp)
{
	int code = EFX_QWORD_FIELD(ptp->evt_frags[0], MCDI_EVENT_DATA);
	if (ptp->evt_frag_idx != 1) {
		ptp_event_failure(efx, 1);
		return;
	}

	netif_err(efx, hw, efx->net_dev, "PTP error %d\n", code);
}

static void ptp_event_pps(struct efx_nic *efx, struct efx_ptp_data *ptp)
{
	if (efx && ptp->pps_workwq)
		queue_work(ptp->pps_workwq, &ptp->pps_work);
}

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
static void hw_pps_event_pps(struct efx_nic *efx, struct efx_ptp_data *ptp)
{
	struct efx_pps_data *pps = efx->ptp_data->pps_data;

	pps->n_assert = ptp->nic_to_kernel_time(
		EFX_QWORD_FIELD(ptp->evt_frags[0], MCDI_EVENT_DATA),
		EFX_QWORD_FIELD(ptp->evt_frags[1], MCDI_EVENT_DATA),
		ptp->ts_corrections.pps_in);

	if (pps->nic_hw_pps_enabled) {
		pps->s_assert = timespec64_sub(
			ktime_to_timespec64(pps->n_assert),
			pps->ptp->last_delta);
		pps->s_delta = pps->ptp->last_delta;
		pps->last_ev++;

		if (waitqueue_active(&pps->read_data))
			wake_up(&pps->read_data);
	}
}
#endif

static bool efx_ptp_warn_once(struct efx_nic *efx)
{
	if (efx->ptp_unavailable_warned)
		return false;
	efx->ptp_unavailable_warned = true;
	return true;
}

void efx_ptp_event(struct efx_nic *efx, efx_qword_t *ev)
{
	struct efx_ptp_data *ptp;
	struct efx_nic *phc_efx;
	int code = EFX_QWORD_FIELD(*ev, MCDI_EVENT_CODE);

	phc_efx = efx->phc_efx;
	ptp = phc_efx ? phc_efx->ptp_data : NULL;

	if (!ptp) {
		if (efx_ptp_warn_once(efx))
			netif_warn(efx, drv, efx->net_dev,
				   "Received PTP event (code %d) but PTP not set up\n",
				   code);
		return;
	}

	if (ptp->evt_frag_idx == 0) {
		ptp->evt_code = code;
	} else if (ptp->evt_code != code) {
		netif_err(efx, hw, efx->net_dev,
			  "PTP out of sequence event %d\n", code);
		ptp->evt_frag_idx = 0;
	}
	/* Relay all events to the PF that administers the hardware */
	efx = phc_efx;

	ptp->evt_frags[ptp->evt_frag_idx++] = *ev;
	if (!MCDI_EVENT_FIELD(*ev, CONT)) {
		/* Process resulting event */
		switch (code) {
		case MCDI_EVENT_CODE_PTP_RX:
			ptp_event_rx(efx, ptp);
			break;
		case MCDI_EVENT_CODE_PTP_FAULT:
			ptp_event_fault(efx, ptp);
			break;
		case MCDI_EVENT_CODE_PTP_PPS:
			ptp_event_pps(efx, ptp);
			break;
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
		case MCDI_EVENT_CODE_HW_PPS:
			hw_pps_event_pps(efx, ptp);
			break;
#endif
		default:
			netif_err(efx, hw, efx->net_dev,
				  "PTP unknown event %d\n", code);
			break;
		}
		ptp->evt_frag_idx = 0;
	} else if (MAX_EVENT_FRAGS == ptp->evt_frag_idx) {
		netif_err(efx, hw, efx->net_dev,
			  "PTP too many event fragments\n");
		ptp->evt_frag_idx = 0;
	}
}

void efx_time_sync_event(struct efx_channel *channel, efx_qword_t *ev)
{
	struct efx_nic *efx = channel->efx;
	struct efx_ptp_data *ptp = efx->ptp_data;

	// TODO test ptp null?

	/* When extracting the sync timestamp minor value, we should discard
	 * the least significant two bits. These are not required in order
	 * to reconstruct full-range timestamps and they are optionally used
	 * to report status depending on the options supplied when subscribing
	 * for sync events.
	 */
	channel->sync_timestamp_major = MCDI_EVENT_FIELD(*ev, PTP_TIME_MAJOR);
	channel->sync_timestamp_minor =
		(MCDI_EVENT_FIELD(*ev, PTP_TIME_MINOR_MS_8BITS) & 0xFC)
			<< ptp->nic_time.sync_event_minor_shift;

	/* if sync events have been disabled then we want to silently ignore
	 * this event, so throw away result.
	 */
	(void) cmpxchg(&channel->sync_events_state, SYNC_EVENTS_REQUESTED,
		       SYNC_EVENTS_VALID);
}

static inline u32 efx_rx_buf_timestamp_minor(struct efx_nic *efx,
					     const u8 *prefix)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	return __le32_to_cpup((const __le32 *)(prefix +
					       efx->type->rx_ts_offset));
#else
	const u8 *data = prefix + efx->type->rx_ts_offset;
	return (u32)data[0]       |
	       (u32)data[1] << 8  |
	       (u32)data[2] << 16 |
	       (u32)data[3] << 24;
#endif
}

void __efx_rx_skb_attach_timestamp(struct efx_channel *channel,
				   struct sk_buff *skb,
				   const u8 *prefix)
{
	struct efx_nic *efx = channel->efx;
	struct efx_ptp_data *ptp = efx->ptp_data;
	u32 pkt_timestamp_major, pkt_timestamp_minor;
	u32 diff, carry;
	struct skb_shared_hwtstamps *timestamps;

	// TODO do we need to check if ptp is null?

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
	if (efx->aoe_data) {
		efx_ptp_aoe_attach_timestamp(efx, skb);
		return;
	}
#endif
	if (channel->sync_events_state != SYNC_EVENTS_VALID)
		return;

	pkt_timestamp_minor = efx_rx_buf_timestamp_minor(efx, prefix);

	/* get the difference between the packet and sync timestamps,
	 * modulo one second
	 */
	diff = pkt_timestamp_minor - channel->sync_timestamp_minor;
	if (pkt_timestamp_minor < channel->sync_timestamp_minor)
		diff += ptp->nic_time.minor_max;

	/* do we roll over a second boundary and need to carry the one? */
	carry = (channel->sync_timestamp_minor >= ptp->nic_time.minor_max - diff) ?
		1 : 0;

	if (diff <= ptp->nic_time.sync_event_diff_max) {
		/* packet is ahead of the sync event by a quarter of a second or
		 * less (allowing for fuzz)
		 */
		pkt_timestamp_major = channel->sync_timestamp_major + carry;
	} else if (diff >= ptp->nic_time.sync_event_diff_min) {
		/* packet is behind the sync event but within the fuzz factor.
		 * This means the RX packet and sync event crossed as they were
		 * placed on the event queue, which can sometimes happen.
		 */
		pkt_timestamp_major = channel->sync_timestamp_major - 1 + carry;
	} else {
		/* it's outside tolerance in both directions. this might be
		 * indicative of us missing sync events for some reason, so
		 * we'll call it an error rather than risk giving a bogus
		 * timestamp.
		 */
		netif_vdbg(efx, drv, efx->net_dev,
			  "packet timestamp %x too far from sync event %x:%x\n",
			  pkt_timestamp_minor, channel->sync_timestamp_major,
			  channel->sync_timestamp_minor);
		return;
	}

	/* attach the timestamps to the skb */
	timestamps = skb_hwtstamps(skb);
	timestamps->hwtstamp =
		ptp->nic_to_kernel_time(pkt_timestamp_major,
					pkt_timestamp_minor,
					ptp->ts_corrections.general_rx);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_HAVE_NET_TSTAMP)
	/* Note the unusual preprocessor condition:
	 * - setting syststamp is deprecated, so this is EFX_NOT_UPSTREAM
	 * - this will be done in efx_ptp_process_rx() if !EFX_HAVE_NET_TSTAMP
	 */
	efx_ptp_get_host_time(efx, timestamps);
#endif
}

static int efx_phc_adjfreq(struct ptp_clock_info *ptp, s32 delta)
{
	struct efx_ptp_data *ptp_data = container_of(ptp,
						     struct efx_ptp_data,
						     phc_clock_info);
	struct efx_nic *efx = ptp_data->efx;
	s64 max_adjfreq = ptp_data->max_adjfreq;
	MCDI_DECLARE_BUF(inadj, MC_CMD_PTP_IN_ADJUST_LEN);
	s64 adjustment_ns;
	int rc;

	if (delta > (s32)max_adjfreq)
		delta = max_adjfreq;
	else if (delta < -((s32)max_adjfreq))
		delta = -max_adjfreq;

	/* Convert ppb to fixed point ns taking care to round correctly. */
	adjustment_ns =
		((s64)delta * PPB_SCALE_WORD + (1 << (ptp_data->adjfreq_ppb_shift-1)))
			 >> ptp_data->adjfreq_ppb_shift;

	MCDI_SET_DWORD(inadj, PTP_IN_OP, MC_CMD_PTP_OP_ADJUST);
	MCDI_SET_DWORD(inadj, PTP_IN_PERIPH_ID, 0);
	MCDI_SET_QWORD(inadj, PTP_IN_ADJUST_FREQ, adjustment_ns);
	MCDI_SET_DWORD(inadj, PTP_IN_ADJUST_SECONDS, 0);
	MCDI_SET_DWORD(inadj, PTP_IN_ADJUST_NANOSECONDS, 0);
	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, inadj, sizeof(inadj),
			  NULL, 0, NULL);
	if (rc != 0)
		return rc;

	ptp_data->current_adjfreq = adjustment_ns;
	return 0;
}

static int efx_phc_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	u32 nic_major, nic_minor;
	struct efx_ptp_data *ptp_data = container_of(ptp,
						     struct efx_ptp_data,
						     phc_clock_info);
	struct efx_nic *efx = ptp_data->efx;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_ADJUST_LEN);
#if defined(EFX_NOT_UPSTREAM)
	int rc;

	ptp_data->last_delta_valid = false;
#endif

	efx->ptp_data->ns_to_nic_time(delta, &nic_major, &nic_minor);

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_ADJUST);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	MCDI_SET_QWORD(inbuf, PTP_IN_ADJUST_FREQ, ptp_data->current_adjfreq);
	MCDI_SET_DWORD(inbuf, PTP_IN_ADJUST_MAJOR, nic_major);
	MCDI_SET_DWORD(inbuf, PTP_IN_ADJUST_MINOR, nic_minor);
#if defined(EFX_NOT_UPSTREAM)
	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, inbuf, sizeof(inbuf), NULL, 0, NULL);

	if (!rc)
		return rc;
	return efx_ptp_synchronize(efx, PTP_SYNC_ATTEMPTS);
#else
	return efx_mcdi_rpc(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
#endif
}

static int efx_phc_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct efx_ptp_data *ptp_data = container_of(ptp,
						     struct efx_ptp_data,
						     phc_clock_info);
	struct efx_nic *efx = ptp_data->efx;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_READ_NIC_TIME_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PTP_OUT_READ_NIC_TIME_LEN);
	int rc;
	ktime_t kt;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_READ_NIC_TIME);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), NULL);
	if (rc != 0)
		return rc;

	kt = ptp_data->nic_to_kernel_time(
		MCDI_DWORD(outbuf, PTP_OUT_READ_NIC_TIME_MAJOR),
		MCDI_DWORD(outbuf, PTP_OUT_READ_NIC_TIME_MINOR), 0);
	*ts = ktime_to_timespec64(kt);
	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
static int efx_phc_settime(struct ptp_clock_info *ptp,
			   const struct timespec64 *e_ts)
{
	/* Get the current NIC time, efx_phc_gettime.
	 * Subtract from the desired time to get the offset
	 * call efx_phc_adjtime with the offset
	 */
	int rc;
	struct timespec64 time_now;
	struct timespec64 delta;

	rc = efx_phc_gettime(ptp, &time_now);
	if (rc != 0)
		return rc;

	delta = timespec64_sub(*e_ts, time_now);

	rc = efx_phc_adjtime(ptp, timespec64_to_ns(&delta));
	if (rc != 0)
		return rc;

	return 0;
}

static int efx_phc_enable(struct ptp_clock_info *ptp,
			  struct ptp_clock_request *request,
			  int enable)
{
	struct efx_ptp_data *ptp_data = container_of(ptp,
						     struct efx_ptp_data,
						     phc_clock_info);
	if (request->type != PTP_CLK_REQ_PPS)
		return -EOPNOTSUPP;

	ptp_data->nic_ts_enabled = !!enable;
	return 0;
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_64BIT_PHC)
static int efx_phc_settime32(struct ptp_clock_info *ptp,
			     const struct timespec *ts)
{
	struct timespec64 ts64 = timespec_to_timespec64(*ts);

	return efx_phc_settime(ptp, &ts64);
}

static int efx_phc_gettime32(struct ptp_clock_info *ptp,
			     struct timespec *ts)
{
	struct timespec64 ts64 = timespec_to_timespec64(*ts);
	int rc;

	rc = efx_phc_gettime(ptp, &ts64);
	if (rc == 0)
		*ts = timespec64_to_timespec(ts64);

	return rc;
}
#endif
#endif

static const struct efx_channel_type efx_ptp_channel_type = {
	.handle_no_channel	= efx_ptp_handle_no_channel,
	.pre_probe		= efx_ptp_probe_channel,
	.post_remove		= efx_ptp_remove_channel,
	.get_name		= efx_ptp_get_channel_name,
	/* no copy operation; there is no need to reallocate this channel */
	.receive_skb		= efx_ptp_rx,
	.keep_eventq		= false,
};

void efx_ptp_defer_probe_with_channel(struct efx_nic *efx)
{
	if (efx_ptp_adapter_has_support(efx) &&
	    !separate_tx_channels) {
		efx->extra_channel_type[EFX_EXTRA_CHANNEL_PTP] =
			&efx_ptp_channel_type;
		/* Create an extra TX queue */
		if (efx_ptp_use_mac_tx_timestamps(efx) &&
		    efx_channels(efx) < efx->max_channels) {
			++efx->n_combined_channels;
			++efx->xdp_channel_offset;
		}
	}
}

void efx_ptp_start_datapath(struct efx_nic *efx)
{
	if (efx_ptp_restart(efx))
		netif_err(efx, drv, efx->net_dev, "Failed to restart PTP.\n");
	/* re-enable timestamping if it was previously enabled */
	if (efx->type->ptp_set_ts_sync_events)
		efx->type->ptp_set_ts_sync_events(efx, true, true);
}

void efx_ptp_stop_datapath(struct efx_nic *efx)
{
	/* temporarily disable timestamping */
	if (efx->type->ptp_set_ts_sync_events)
		efx->type->ptp_set_ts_sync_events(efx, false, true);
	efx_ptp_stop(efx);
}
