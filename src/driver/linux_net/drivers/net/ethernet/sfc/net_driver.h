/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2005-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

/* Common definitions for all Efx net driver code */

#ifndef EFX_NET_DRIVER_H
#define EFX_NET_DRIVER_H

/* Uncomment this to enable output from netif_vdbg
#define VERBOSE_DEBUG 1
 */

#ifdef EFX_NOT_UPSTREAM
#define SFC_NAPI_DEBUG 1
#endif

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/mii.h>
#include <linux/pci.h>
#include <linux/device.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/highmem.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#endif
#include <linux/rwsem.h>
#include <linux/vmalloc.h>
#include <linux/mtd/mtd.h>
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEVLINK)
#include <net/devlink.h>
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_RXQ_INFO)
#include <net/xdp.h>
#endif
#include <net/netevent.h>
#if !defined(EFX_USE_KCOMPAT)
#if defined(CONFIG_XDP_SOCKETS)
#include <net/xdp_sock_drv.h>
#endif
#endif

#ifdef EFX_NOT_UPSTREAM
#include "config.h"
#endif

#ifdef EFX_USE_KCOMPAT
/* Must come before other headers */
#include "kernel_compat.h"
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_BUSY_POLL)
#include <net/busy_poll.h>
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
#include <linux/bpf.h>
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_RHASHTABLE)
#include <linux/rhashtable.h>
#endif

#include "enum.h"
#include "bitfield.h"
#ifdef EFX_NOT_UPSTREAM
#include "sfctool.h" /* Provides missing 'struct ethtool_*' declarations */
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
#define EFX_DRIVERLINK_API_VERSION_MINOR EFX_DRIVERLINK_API_VERSION_MINOR_MAX
#include "driverlink_api.h" /* Indirectly includes filter.h */
#endif
#endif
#include "filter.h"

#include "workarounds.h"

/**************************************************************************
 *
 * Build definitions
 *
 **************************************************************************/

#ifdef EFX_NOT_UPSTREAM
#define EFX_DRIVER_VERSION	"5.3.19.1023"
#endif

#ifdef DEBUG
#define EFX_WARN_ON_ONCE_PARANOID(x) WARN_ON_ONCE(x)
#define EFX_WARN_ON_PARANOID(x) WARN_ON(x)
#else
#define EFX_WARN_ON_ONCE_PARANOID(x) do {} while (0)
#define EFX_WARN_ON_PARANOID(x) do {} while (0)
#endif

#if defined(EFX_NOT_UPSTREAM)
#define EFX_RX_PAGE_SHARE	1
#if IS_ENABLED(CONFIG_VLAN_8021Q)
#ifndef EFX_HAVE_CSUM_LEVEL
#define EFX_USE_FAKE_VLAN_RX_ACCEL 1
#endif
#define EFX_USE_FAKE_VLAN_TX_ACCEL 1
#endif
#endif

/**************************************************************************
 *
 * Efx data structures
 *
 **************************************************************************/

/* This limit is arbitrary, it only exists to impose a testing limit and
 * to avoid large memory allocations in case of a bug.
 */
#define EFX_MAX_CHANNELS 255U
#define EFX_MAX_RX_QUEUES EFX_MAX_CHANNELS
#define EFX_EXTRA_CHANNEL_PTP	0
#define EFX_EXTRA_CHANNEL_TC	1
#define EFX_MAX_EXTRA_CHANNELS	2U

/* Checksum generation is a per-queue option in hardware, so each
 * queue visible to the networking core is backed by two hardware TX
 * queues. */
#define EFX_MAX_CORE_TX_QUEUES	EFX_MAX_CHANNELS
#define EFX_TXQ_TYPE_NO_OFFLOAD		0
#define EFX_TXQ_TYPE_CSUM_OFFLOAD	1
#define EFX_TXQ_TYPE_INNER_CSUM_OFFLOAD	2
#define EFX_TXQ_TYPE_BOTH_CSUM_OFFLOAD  3
#define EFX_TXQ_TYPES			3
#define EFX_MAX_TX_QUEUES	(EFX_TXQ_TYPES * EFX_MAX_CORE_TX_QUEUES)

/* Maximum possible MTU the driver supports */
#define EFX_MAX_MTU (9 * 1024)
#define EFX_100_MAX_MTU 9600

/* Minimum MTU, from RFC791 (IP) */
#define EFX_MIN_MTU 68

/* Maximum total header length for TSOv2 */
#define EFX_TSO2_MAX_HDRLEN	208

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
/* Size of an RX scatter buffer.  Small enough to pack 2 into a 4K page,
 * and should be a multiple of the cache line size.
 */
#define EFX_RX_USR_BUF_SIZE	(2048 - 256 - XDP_PACKET_HEADROOM)
#else
/* Size of an RX scatter buffer. */
#define EFX_RX_USR_BUF_SIZE	(PAGE_SIZE - L1_CACHE_BYTES)
#endif

/* If possible, we should ensure cache line alignment at start and end
 * of every buffer.  Otherwise, we just need to ensure 4-byte
 * alignment of the network header.
 */
#if NET_IP_ALIGN == 0
#define EFX_RX_BUF_ALIGNMENT	L1_CACHE_BYTES
#else
#define EFX_RX_BUF_ALIGNMENT	4
#endif

/* Forward declare Precision Time Protocol (PTP) support structure. */
struct efx_ptp_data;
struct kernel_hwtstamp_config;

struct efx_self_tests;

enum efx_rss_mode {
	EFX_RSS_PACKAGES,
	EFX_RSS_CORES,
	EFX_RSS_HYPERTHREADS,
	EFX_RSS_NUMA_LOCAL_CORES,
	EFX_RSS_NUMA_LOCAL_HYPERTHREADS,
	EFX_RSS_CUSTOM,
};

#ifdef EFX_NOT_UPSTREAM
enum efx_performance_profile {
	EFX_PERFORMANCE_PROFILE_AUTO,
	EFX_PERFORMANCE_PROFILE_THROUGHPUT,
	EFX_PERFORMANCE_PROFILE_LATENCY,
};
#endif

/**
 * struct efx_buffer - A general-purpose DMA buffer
 * @addr: host base address of the buffer
 * @dma_addr: DMA base address of the buffer
 * @len: Buffer length, in bytes
 *
 * The NIC uses these buffers for its interrupt status registers and
 * MAC stats dumps.
 */
struct efx_buffer {
	void *addr;
	dma_addr_t dma_addr;
	unsigned int len;
};

/**
 * struct efx_tx_buffer - buffer state for a TX descriptor
 * @skb: When @flags & %EFX_TX_BUF_SKB, the associated socket buffer to be
 *	freed when descriptor completes
 * @buf: When @flags & %EFX_TX_BUF_HEAP, the associated heap buffer to be
 *	freed when descriptor completes.
 * @xdpf: When @flags & %EFX_TX_BUF_XDP, the XDP frame information; its @data
 *	member is the associated buffer to drop a page reference on.  If the
 *	kernel does not support this (i.e. ifndef EFX_HAVE_XDP_FRAME_API), then
 *	instead @buf is used, and holds the buffer to drop a page reference on.
 * @option: When @flags & %EFX_TX_BUF_OPTION, an EF10-specific option descriptor.
 * @dma_addr: DMA address of the fragment.
 * @flags: Flags for allocation and DMA mapping type
 * @len: Length of this fragment.
 *	This field is zero when the queue slot is empty.
 * @unmap_len: Length of this fragment to unmap
 * @dma_offset: Offset of @dma_addr from the address of the backing DMA mapping.
 * Only valid if @unmap_len != 0.
 */
struct efx_tx_buffer {
	union {
		const struct sk_buff *skb;
		void *buf;
		struct xdp_frame *xdpf;
	};
	union {
		efx_qword_t option;	/* EF10 */
		dma_addr_t dma_addr;
	};
	unsigned short flags;
	unsigned short len;
	unsigned short unmap_len;
	unsigned short dma_offset;
};
#define EFX_TX_BUF_CONT		1	/* not last descriptor of packet */
#define EFX_TX_BUF_SKB		2	/* buffer is last part of skb */
#define EFX_TX_BUF_HEAP		4	/* buffer was allocated with kmalloc() */
#define EFX_TX_BUF_MAP_SINGLE	8	/* buffer was mapped with dma_map_single() */
#define EFX_TX_BUF_OPTION	0x10	/* empty buffer for option descriptor */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_TX)
#define EFX_TX_BUF_XDP		0x20	/* buffer was sent with XDP */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#define EFX_TX_BUF_XSK		0x80	/* buffer was sent for XSK */
#endif
#endif
#define EFX_TX_BUF_TSO_V3	0x40	/* empty buffer for a TSO_V3 descriptor */
#define EFX_TX_BUF_EFV		0x100	/* buffer was sent from representor */

/**
 * struct efx_tx_queue - An Efx TX queue
 * @efx: The associated Efx NIC
 * @queue: DMA queue number
 * @label: Queue label - distinguishes this queue from others sharing evq. Used
 *	as an index in to %efx_channel->tx_queues
 * @csum_offload: Is checksum offloading enabled for this queue?
 * @tso_version: Version of TSO in use for this queue.
 * @tso_wanted_version: Version of TSO wanted for this queue
 * @tso_encap: Is encapsulated TSO supported? Supported in TSOv2 on 8000 series.
 * @channel: The associated channel
 * @core_txq: The networking core TX queue structure
 * @buffer: The software buffer ring
 * @cb_page: Array of pages of copy buffers
 * @txd: The hardware descriptor ring
 * @ptr_mask: The size of the ring minus 1.
 * @piobuf: PIO buffer region for this TX queue (shared with its partner).
 *	Size of the region is efx_piobuf_size.
 * @piobuf_offset: Buffer offset to be specified in PIO descriptors
 * @timestamping: Is timestamping enabled for this channel?
 * @xdp_tx: Is this an XDP tx queue?
 * @xsk_pool: reference to xsk_buff_pool assigned to this queue
 * @handle_vlan: VLAN insertion offload handler.
 * @handle_tso: TSO offload handler.
 * @read_count: Current read pointer.
 *	This is the number of buffers that have been removed from both rings.
 * @read_jiffies: Time that @read_count was last updated.
 * @old_write_count: The value of @write_count when last checked.
 *	This is here for performance reasons.  The xmit path will
 *	only get the up-to-date value of @write_count if this
 *	variable indicates that the queue is empty.  This is to
 *	avoid cache-line ping-pong between the xmit path and the
 *	completion path.
 * @merge_events: Number of TX merged completion events
 * @doorbell_notify_comp: Number of doorbell updates from the completion path.
 * @bytes_compl: Number of bytes completed to report to BQL
 * @pkts_compl: Number of packets completed to report to BQL
 * @completed_timestamp_major: Top part of the most recent tx timestamp.
 * @completed_timestamp_minor: Low part of the most recent tx timestamp.
 * @completion_remainder: The number of outstanding descriptors left over after
 *	the last TX completion event.
 * @insert_count: Current insert pointer
 *	This is the number of buffers that have been added to the
 *	software ring.
 * @write_count: Current write pointer
 *	This is the number of buffers that have been added to the
 *	hardware ring.
 * @packet_write_count: Completable write pointer
 *	This is the write pointer of the last packet written.
 *	Normally this will equal @write_count, but as option descriptors
 *	don't produce completion events, they won't update this.
 *	Filled in iff @efx->type->option_descriptors; only used for PIO.
 *	Thus, this is written and used on EF10, and neither on farch.
 * @old_read_count: The value of read_count when last checked.
 *	This is here for performance reasons.  The xmit path will
 *	only get the up-to-date value of read_count if this
 *	variable indicates that the queue is full.  This is to
 *	avoid cache-line ping-pong between the xmit path and the
 *	completion path.
 * @tso_bursts: Number of times TSO xmit invoked by kernel
 * @tso_long_headers: Number of packets with headers too long for standard
 *	blocks
 * @tso_packets: Number of packets via the TSO xmit path
 * @tso_fallbacks: Number of times TSO fallback used
 * @pushes: Number of times the TX push feature has been used
 * @pio_packets: Number of times the TX PIO feature has been used
 * @cb_packets: Number of times the TX copybreak feature has been used
 * @doorbell_notify_tx: Number of doorbell updates from the xmit path.
 * @notify_count: Count of notified descriptors to the NIC
 * @notify_jiffies: Time when @notify_count was last updated.
 * @tx_bytes: Number of bytes sent.
 * @tx_packets: Number of packets sent.
 * @xmit_pending: Are any packets waiting to be pushed to the NIC
 * @empty_read_count: If the completion path has seen the queue as empty
 *	and the transmission path has not yet checked this, the value of
 *	@read_count bitwise-added to %EFX_EMPTY_COUNT_VALID; otherwise 0.
 * @flush_outstanding: non-zero if TX queue flush is pending.
 *
 * This is a ring buffer of TX fragments.
 * Since the TX completion path always executes on the same
 * CPU and the xmit path can operate on different CPUs,
 * performance is increased by ensuring that the completion
 * path and the xmit path operate on different cache lines.
 * This is particularly important if the xmit path is always
 * executing on one CPU which is different from the completion
 * path.  There is also a cache line for members which are
 * read but not written on the fast path.
 */
struct efx_tx_queue {
	/* Members which don't change on the fast path */
	struct efx_nic *efx ____cacheline_aligned_in_smp;
	unsigned int queue;
	unsigned int label;
	unsigned int csum_offload;
	unsigned int tso_version;
	unsigned int tso_wanted_version;
	bool tso_encap;
	struct efx_channel *channel;
	struct netdev_queue *core_txq;
	struct efx_tx_buffer *buffer;
	struct efx_buffer *cb_page;
	struct efx_buffer txd;
	unsigned int ptr_mask;
	void __iomem *piobuf;
	unsigned int piobuf_offset;
	bool timestamping;
	bool xdp_tx;
#if !defined(EFX_USE_KCOMPAT) ||  defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) ||  defined(EFX_HAVE_XSK_POOL)
	struct xsk_buff_pool *xsk_pool;
#else
	/** @umem: umem assigned to this queue */
	struct xdp_umem *umem;
#endif
#endif
#endif
#ifdef CONFIG_DEBUG_FS
	/** @debug_dir: debugfs directory for this queue */
	struct dentry *debug_dir;
#endif

	/* Function pointers used in the fast path. */
	struct sk_buff* (*handle_vlan)(struct efx_tx_queue*, struct sk_buff*);
	int (*handle_tso)(struct efx_tx_queue*, struct sk_buff*, bool *);

	/* Members used mainly on the completion path */
	unsigned int read_count ____cacheline_aligned_in_smp;
	unsigned long read_jiffies;
	unsigned int old_write_count;
	unsigned int merge_events;
	unsigned int doorbell_notify_comp;
	unsigned int bytes_compl;
	unsigned int pkts_compl;
	u32 completed_timestamp_major;
	u32 completed_timestamp_minor;
	unsigned int completion_remainder;

	/* Members used only on the xmit path */
	unsigned int insert_count ____cacheline_aligned_in_smp;
	unsigned int write_count;
	unsigned int packet_write_count;
	unsigned int old_read_count;
	unsigned int tso_bursts;
	unsigned int tso_long_headers;
	unsigned int tso_packets;
	unsigned int tso_fallbacks;
	unsigned int pushes;
	unsigned int pio_packets;
	unsigned int cb_packets;
	unsigned int doorbell_notify_tx;
	unsigned int notify_count;
	unsigned long notify_jiffies;
	/* Statistics to supplement MAC stats */
	u64 tx_bytes;
	unsigned long tx_packets;

	bool xmit_pending;

	/* Members shared between paths and sometimes updated */
	unsigned int empty_read_count ____cacheline_aligned_in_smp;
#define EFX_EMPTY_COUNT_VALID 0x80000000
	atomic_t flush_outstanding;
};

/**
 * struct efx_rx_buffer - An Efx RX data buffer
 * @dma_addr: DMA base address of the buffer
 * @page: The associated page buffer.
 *	Will be %NULL if the buffer slot is currently free.
 * @addr: virtual address of buffer
 * @handle: hande to the umem buffer
 * @xsk_buf: umem buffer
 * @page_offset: If pending this is the offset in @page of the DMA base address.
 *	If completed this is the offset in @page of the Ethernet header.
 * @len: If pending this is the length of a DMA descriptor.
 *	If completed this is the received length, excluding hash prefix.
 * @flags: Flags for buffer and packet state.  These are only set on the
 *	first buffer of a scattered packet.
 * @vlan_tci: VLAN tag in host byte order. If the EFX_RX_PKT_VLAN_XTAG
 *	flag is set, the tag has been moved here.
 */
struct efx_rx_buffer {
	dma_addr_t dma_addr;
	union {
		struct page *page;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_XSK_BUFFER_ALLOC)
		struct xdp_buff *xsk_buf;
#else
		struct {
			void *addr;
			u64 handle;
		};
#endif
#endif
#endif
	};

	u16 page_offset;
	u16 len;
	u16 flags;
	u16 vlan_tci;
};
#define EFX_RX_BUF_LAST_IN_PAGE		0x0001
#define EFX_RX_PKT_CSUMMED		0x0002
#define EFX_RX_PKT_DISCARD		0x0004
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
#define EFX_RX_PKT_VLAN                 0x0008
#endif
#define EFX_RX_PKT_IPV4			0x0010
#define EFX_RX_PKT_IPV6			0x0020
#define EFX_RX_PKT_TCP			0x0040
#define EFX_RX_PKT_PREFIX_LEN		0x0080	/* length is in prefix only */
#define EFX_RX_PAGE_IN_RECYCLE_RING	0x0100
#define EFX_RX_PKT_CSUM_LEVEL		0x0200
#define EFX_RX_BUF_VLAN_XTAG		0x8000
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#define EFX_RX_BUF_ZC			0x0400
#define EFX_RX_BUF_XSK_REUSE		0x0800
#endif

/**
 * struct efx_rx_page_state - Page-based rx buffer state
 * @dma_addr: The dma address of this page.
 *
 * Inserted at the start of every page allocated for receive buffers.
 * Used to facilitate sharing dma mappings between recycled rx buffers
 * and those passed up to the kernel.
 */
struct efx_rx_page_state {
	dma_addr_t dma_addr;
/* private: */
	unsigned int __pad[0] ____cacheline_aligned;
};

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)

/**
 * struct efx_ssr_conn - Connection state for Soft Segment Reassembly (SSR) aka LRO
 * @link: Link for hash table and free list.
 * @active_link: Link for active_conns list
 * @l2_id: Identifying information from layer 2
 * @conn_hash: Hash of connection 4-tuple
 * @source: Source TCP port number
 * @dest: Destination TCP port number
 * @n_in_order_pkts: Number of in-order packets with payload.
 * @next_seq: Next in-order sequence number.
 * @last_pkt_jiffies: Time we last saw a packet on this connection.
 * @skb: The SKB we are currently holding.
 *	If %NULL, then all following fields are undefined.
 * @skb_tail: The tail of the frag_list of SKBs we're holding.
 *	Only valid after at least one merge (and when not in page-mode).
 * @th_last: The TCP header of the last packet merged.
 * @next_buf: The next RX buffer to process.
 * @next_eh: Ethernet header of the next buffer.
 * @next_iph: IP header of the next buffer.
 * @delivered: True if we've delivered a payload packet up this interrupt.
 * @sum_len: IPv4 tot_len or IPv6 payload_len for @skb.
 */
struct efx_ssr_conn {
	struct list_head link;
	struct list_head active_link;
	u32 l2_id;
	u32 conn_hash;
	__be16 source, dest;
	int n_in_order_pkts;
	unsigned int next_seq;
	unsigned int last_pkt_jiffies;
	struct sk_buff *skb;
	struct sk_buff *skb_tail;
	struct tcphdr *th_last;
	struct efx_rx_buffer next_buf;
	char *next_eh;
	void *next_iph;
	int delivered;
	u16 sum_len;
};

/**
 * struct efx_ssr_state - Port state for Soft Segment Reassembly (SSR) aka LRO
 * @efx: The associated NIC.
 * @conns_mask: Number of hash buckets - 1.
 * @conns: Hash buckets for tracked connections.
 * @conns_n: Length of linked list for each hash bucket.
 * @active_conns: Connections that are holding a packet.
 *	Connections are self-linked when not in this list.
 * @free_conns: Free efx_ssr_conn instances.
 * @last_purge_jiffies: The value of jiffies last time we purged idle
 *	connections.
 * @n_merges: Number of packets absorbed by SSR.
 * @n_bursts: Number of bursts spotted by SSR.
 * @n_slow_start: Number of packets not merged because connection may be in
 *	slow-start.
 * @n_misorder: Number of out-of-order packets seen in tracked streams.
 * @n_too_many: Incremented when we're trying to track too many streams.
 * @n_new_stream: Number of distinct streams we've tracked.
 * @n_drop_idle: Number of streams discarded because they went idle.
 * @n_drop_closed: Number of streams that have seen a FIN or RST.
 */
struct efx_ssr_state {
	struct efx_nic *efx;
	unsigned int conns_mask;
	struct list_head *conns;
	unsigned int *conns_n;
	struct list_head active_conns;
	struct list_head free_conns;
	unsigned int last_purge_jiffies;
	unsigned int n_merges;
	unsigned int n_bursts;
	unsigned int n_slow_start;
	unsigned int n_misorder;
	unsigned int n_too_many;
	unsigned int n_new_stream;
	unsigned int n_drop_idle;
	unsigned int n_drop_closed;
};

#endif

/**
 * struct efx_rx_queue - An Efx RX queue
 * @efx: The associated Efx NIC
 * @buffer: The software buffer ring
 * @rxd: The hardware descriptor ring
 * @queue: Hardware RXQ instance number
 * @label: Hardware RXQ label
 * @core_index: Index of network core RX queue.  Will be >= 0 iff this
 *	is associated with a real RX queue.
 * @ptr_mask: The size of the ring minus 1.
 * @refill_enabled: Enable refill whenever fill level is low
 * @flush_pending: Set when a RX flush is pending. Has the same lifetime as
 *	@rxq_flush_pending.
 * @grant_credits: Posted RX descriptors need to be granted to the MAE with
 *	%MC_CMD_MAE_COUNTERS_STREAM_GIVE_CREDITS.  For %EFX_EXTRA_CHANNEL_TC,
 *	and only supported on EF100.
 * @added_count: Number of buffers added to the receive queue.
 * @notified_count: Number of buffers given to NIC (<= @added_count).
 * @granted_count: Number of buffers granted to the MAE (<= @notified_count).
 * @removed_count: Number of buffers removed from the receive queue.
 * @scatter_n: Used by NIC specific receive code.
 * @scatter_len: Used by NIC specific receive code.
 * @rx_pkt_n_frags: Number of fragments in next packet to be delivered by
 *	__efx_rx_packet(), or zero if there is none
 * @rx_pkt_index: Ring index of first buffer for next packet to be delivered
 *	by __efx_rx_packet(), if @rx_pkt_n_frags != 0
 * @page_ring: The ring to store DMA mapped pages for reuse.
 * @page_add: Counter to calculate the write pointer for the recycle ring.
 * @page_remove: Counter to calculate the read pointer for the recycle ring.
 * @page_recycle_count: The number of pages that have been recycled.
 * @page_recycle_failed: The number of pages that couldn't be recycled because
 *      the kernel still held a reference to them.
 * @page_recycle_full: The number of pages that were released because the
 *      recycle ring was full.
 * @page_repost_count: The number of pages that were reposted to the RX queue.
 * @page_ptr_mask: The number of pages in the RX recycle ring minus 1.
 * @max_fill: RX descriptor maximum fill level (<= ring size)
 * @fast_fill_trigger: RX descriptor fill level that will trigger a fast fill
 *	(<= @max_fill)
 * @min_fill: RX descriptor minimum non-zero fill level.
 *	This records the minimum fill level observed when a ring
 *	refill was triggered.
 * @recycle_count: RX buffer recycle counter.
 * @slow_fill_count: Number of slow fill events sent.
 * @slow_fill_work: workitem used to defer ring refill to process context.
 * @grant_work: workitem used to grant credits to the MAE if @grant_credits
 * @rx_packets: Count of RX packets
 * @n_rx_tobe_disc: Count of RX_TOBE_DISC errors
 * @n_rx_ip_hdr_chksum_err: Count of RX IP header checksum errors
 * @n_rx_tcp_udp_chksum_err: Count of RX TCP and UDP checksum errors
 * @n_rx_outer_ip_hdr_chksum_err: Count of RX outer IP header checksum errors
 * @n_rx_outer_tcp_udp_chksum_err: Count of RX outer TCP and UDP checksum errors
 * @n_rx_inner_ip_hdr_chksum_err: Count of RX inner IP header checksum errors
 * @n_rx_inner_tcp_udp_chksum_err: Count of RX inner TCP and UDP checksum errors
 * @n_rx_eth_crc_err: Count of RX CRC errors
 * @n_rx_mcast_mismatch: Count of unmatched multicast frames
 * @n_rx_frm_trunc: Count of RX_FRM_TRUNC errors
 * @n_rx_overlength: Count of RX_OVERLENGTH errors
 * @n_rx_nodesc_trunc: Number of RX packets truncated and then dropped due to
 *	lack of descriptors
 * @n_rx_merge_events: Number of RX merged completion events
 * @n_rx_merge_packets: Number of RX packets completed by merged events
 * @n_rx_xdp_drops: Count of RX packets intentionally dropped due to XDP
 * @n_rx_xdp_bad_drops: Count of RX packets dropped due to XDP errors
 * @n_rx_xdp_tx: Count of RX packets retransmitted due to XDP
 * @n_rx_xdp_redirect: Count of RX packets redirected to a different NIC by XDP
 * @n_rx_mport_bad: Count of RX packets dropped because their ingress mport was
 *	not recognised
 * @failed_flush_count: Count of failed queue flush attempts.
 * @debug_dir: debugfs directory for this queue
 * @xsk_pool: reference to xsk_buff_pool assigned to this queue
 * @xdp_rxq_info: XDP specific RX queue information.
 * @receive_skb: Handle an skb ready to be passed to netif_receive_skb()
 * @receive_raw: Handle an RX buffer ready to be passed to __efx_rx_packet().
 *	Also takes the value of the USER_MARK extracted from the prefix.
 */
struct efx_rx_queue {
	struct efx_nic *efx;
	struct efx_rx_buffer *buffer;
	struct efx_buffer rxd;
	int queue;
	int label;
	int core_index;
	unsigned int ptr_mask;
	bool refill_enabled;
	bool flush_pending;
	bool grant_credits;
	unsigned int added_count;
	unsigned int notified_count;
	unsigned int granted_count;
	unsigned int removed_count;
	unsigned int scatter_n;
	unsigned int scatter_len;

	unsigned int rx_pkt_n_frags;
	unsigned int rx_pkt_index;

#if !defined(EFX_NOT_UPSTREAM) || defined(EFX_RX_PAGE_SHARE)
	struct page **page_ring;
	unsigned int page_add;
	unsigned int page_remove;
	unsigned int page_recycle_count;
	unsigned int page_recycle_failed;
	unsigned int page_recycle_full;
	unsigned int page_repost_count;
	unsigned int page_ptr_mask;
#endif
	unsigned int max_fill;
	unsigned int fast_fill_trigger;
	unsigned int min_fill;
	unsigned int recycle_count;
	unsigned int slow_fill_count;
	struct delayed_work slow_fill_work;
	struct work_struct grant_work;
	/* Statistics to supplement MAC stats */
	unsigned long rx_packets;
	unsigned int n_rx_tobe_disc;
	unsigned int n_rx_ip_hdr_chksum_err;
	unsigned int n_rx_tcp_udp_chksum_err;
	unsigned int n_rx_outer_ip_hdr_chksum_err;
	unsigned int n_rx_outer_tcp_udp_chksum_err;
	unsigned int n_rx_inner_ip_hdr_chksum_err;
	unsigned int n_rx_inner_tcp_udp_chksum_err;
	unsigned int n_rx_eth_crc_err;
	unsigned int n_rx_mcast_mismatch;
	unsigned int n_rx_frm_trunc;
	unsigned int n_rx_overlength;
	unsigned int n_rx_nodesc_trunc;
	unsigned int n_rx_merge_events;
	unsigned int n_rx_merge_packets;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	unsigned int n_rx_xdp_drops;
	unsigned int n_rx_xdp_bad_drops;
	unsigned int n_rx_xdp_tx;
	unsigned int n_rx_xdp_redirect;
#endif
	unsigned int n_rx_mport_bad;
	unsigned int failed_flush_count;

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	/** @ssr: state for Soft Segment Reassembly (LRO) */
	struct efx_ssr_state ssr;
#endif

#ifdef CONFIG_DEBUG_FS
	struct dentry *debug_dir;
#endif

#if !defined(EFX_USE_KCOMPAT) ||  defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
#if !defined(EFX_USE_KCOMPAT) ||  defined(EFX_HAVE_XSK_POOL)
	struct xsk_buff_pool *xsk_pool;
#else
	/** @umem: umem assigned to this queue. */
	struct xdp_umem *umem;
#endif
#endif
#endif /* EFX_HAVE_XSK_POOL */

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_XSK_BUFFER_ALLOC)
#if defined(CONFIG_XDP_SOCKETS)
	/** @zca: zero copy allocator for rx_queue */
	struct zero_copy_allocator zca;
#endif
#endif /* EFX_HAVE_XDP_SOCK */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_RXQ_INFO)
	struct xdp_rxq_info xdp_rxq_info;
#endif /* EFX_HAVE_XDP_RXQ_INFO */

	/* Special RX handlers (normally %NULL) */
	bool (*receive_skb)(struct efx_rx_queue *, struct sk_buff *);
	bool (*receive_raw)(struct efx_rx_queue *, u32);
};

#ifdef CONFIG_SFC_PTP
enum efx_sync_events_state {
	SYNC_EVENTS_DISABLED = 0,
	SYNC_EVENTS_QUIESCENT,
	SYNC_EVENTS_REQUESTED,
	SYNC_EVENTS_VALID,
};
#endif

/* The reserved RSS context value */
#define EFX_MCDI_RSS_CONTEXT_INVALID	0xffffffff
/**
 * struct efx_rss_context - A user-defined RSS context for filtering
 * @list: node of linked list on which this struct is stored
 * @context_id: the RSS_CONTEXT_ID returned by MC firmware, or
 *	%EFX_MCDI_RSS_CONTEXT_INVALID if this context is not present on the NIC.
 *	For Siena, 0 if RSS is active, else %EFX_MCDI_RSS_CONTEXT_INVALID.
 * @user_id: the rss_context ID exposed to userspace over ethtool.
 * @flags: Hashing flags for this RSS context
 * @rx_hash_key: Toeplitz hash key for this RSS context
 * @rx_indir_table: Indirection table for this RSS context
 */
struct efx_rss_context {
	struct list_head list;
	u32 context_id;
	u32 user_id;
	u32 flags;
#ifdef EFX_NOT_UPSTREAM
	/**
	 * @num_queues: Number of queues targeted by this context
	 *	(set at alloc time).
	 */
	u8 num_queues;
#endif
	u8 rx_hash_key[40];
	u32 rx_indir_table[128];
};

/**
 * struct efx_channel - An Efx channel
 * @efx: Associated Efx NIC
 * @channel: Channel instance number
 * @type: Channel type definition
 * @list: Link to the previous and next channel.
 * @eventq_init: Event queue initialised flag
 * @enabled: Channel enabled indicator
 * @tx_coalesce_doorbell: Coalescing of doorbell notifications enabled
 *      for this channel
 * @holdoff_doorbell: Flag indicating that the channel is being processed
 * @irq: IRQ number (MSI and MSI-X only)
 * @irq_moderation_us: IRQ moderation value (in microseconds)
 * @napi_dev: Net device used with NAPI
 * @napi_str: NAPI control structure
 * @eventq: Event queue buffer
 * @eventq_mask: Event queue pointer mask
 * @eventq_read_ptr: Event queue read pointer
 * @event_test_cpu: Last CPU to handle interrupt or test event for this channel
 * @irq_count: Number of IRQs since last adaptive moderation decision
 * @irq_mod_score: IRQ moderation score
 * @rfs_filter_count: number of accelerated RFS filters currently in place;
 *	equals the count of @rps_flow_id slots filled
 * @rfs_last_expiry: value of jiffies last time some accelerated RFS filters
 *	were checked for expiry
 * @rfs_expire_index: next accelerated RFS filter ID to check for expiry
 * @n_rfs_succeeded: number of successful accelerated RFS filter insertions
 * @n_rfs_failed: number of failed accelerated RFS filter insertions
 * @filter_work: Work item for efx_filter_rfs_expire()
 * @rps_flow_id: Flow IDs of filters allocated for accelerated RFS,
 *      indexed by filter ID
 * @debug_dir: debugfs directory for this channel
 * @rx_list: list of SKBs from current RX, awaiting processing
 * @zc: zero-copy enabled on channel
 * @rx_queue: RX queue for this channel
 * @tx_queue_count: Number of TX queues pointed to by %tx_queues
 * @tx_queues: Pointer to TX queues for this channel
 * @sync_events_state: Current state of sync events on this channel
 * @sync_timestamp_major: Major part of the last ptp sync event
 * @sync_timestamp_minor: Minor part of the last ptp sync event
 * @irq_mem_node: Memory NUMA node of interrupt
 *
 * A channel comprises an event queue, at least one TX queue, at least
 * one RX queue, and an associated tasklet for processing the event
 * queue.
 */
struct efx_channel {
	struct efx_nic *efx;
	int channel;
	const struct efx_channel_type *type;
	struct list_head list;
	bool eventq_init;
	bool enabled;
	bool tx_coalesce_doorbell;
	bool holdoff_doorbell;
	int irq;
	unsigned int irq_moderation_us;
	struct net_device *napi_dev;
	struct napi_struct napi_str;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
	/** @busy_poll_state: busy poll state */
	unsigned long busy_poll_state;
	/** @poll_lock: Protect against concurrent busy poll and NAPI */
	spinlock_t poll_lock;
#endif
#endif
	struct efx_buffer eventq;
	unsigned int eventq_mask;
	unsigned int eventq_read_ptr;
	int event_test_cpu;

#ifdef EFX_NOT_UPSTREAM
#ifdef SFC_NAPI_DEBUG
	/** @last_irq_jiffies: time of last hardware interrupt */
	int last_irq_jiffies;
	/** @last_napi_poll_jiffies: time of last NAPI poll start */
	int last_napi_poll_jiffies;
	/** @last_napi_poll_end_jiffies: time of last NAPI poll end */
	int last_napi_poll_end_jiffies;
	/** @last_budget: budget for last NAPI poll */
	int last_budget;
	/** @last_spent: budget consumed in last NAPI poll */
	int last_spent;
	/** @last_complete_done: time of last completed NAPI poll */
	bool last_complete_done;
	/** @last_irq_reprime_jiffies: Time of last interrupt reprime */
	int last_irq_reprime_jiffies;
#endif
#endif

	unsigned int irq_count;
	unsigned int irq_mod_score;
#ifdef CONFIG_RFS_ACCEL
	unsigned int rfs_filter_count;
	unsigned int rfs_last_expiry;
	unsigned int rfs_expire_index;
	unsigned int n_rfs_succeeded;
	unsigned int n_rfs_failed;
	struct delayed_work filter_work;
#define RPS_FLOW_ID_INVALID 0xFFFFFFFF
	u32 *rps_flow_id;
#endif

#ifdef CONFIG_DEBUG_FS
	struct dentry *debug_dir;
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	struct list_head *rx_list;
#else
	struct sk_buff_head *rx_list;
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
	bool zc;
#endif
	struct efx_rx_queue rx_queue;
	unsigned int tx_queue_count;
	struct efx_tx_queue *tx_queues;

#ifdef CONFIG_SFC_PTP
	enum efx_sync_events_state sync_events_state;
	u32 sync_timestamp_major;
	u32 sync_timestamp_minor;
#endif

	int irq_mem_node;
};

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_NDO_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
enum efx_channel_busy_poll_state {
	EFX_CHANNEL_STATE_IDLE = 0,
	EFX_CHANNEL_STATE_POLL_BIT = 1,
	EFX_CHANNEL_STATE_POLL = BIT(1),
	EFX_CHANNEL_STATE_DISABLE_BIT = 2,
};

static inline void efx_channel_busy_poll_init(struct efx_channel *channel)
{
	WRITE_ONCE(channel->busy_poll_state, EFX_CHANNEL_STATE_IDLE);
	spin_lock_init(&channel->poll_lock);
}

/* Called from efx_busy_poll(). */
static inline bool efx_channel_try_lock_poll(struct efx_channel *channel)
{
	return cmpxchg(&channel->busy_poll_state, EFX_CHANNEL_STATE_IDLE,
			EFX_CHANNEL_STATE_POLL) == EFX_CHANNEL_STATE_IDLE;
}

static inline void efx_channel_unlock_poll(struct efx_channel *channel)
{
	clear_bit_unlock(EFX_CHANNEL_STATE_POLL_BIT, &channel->busy_poll_state);
}

static inline bool efx_channel_busy_polling(struct efx_channel *channel)
{
	return test_bit(EFX_CHANNEL_STATE_POLL_BIT, &channel->busy_poll_state);
}

static inline void efx_channel_enable(struct efx_channel *channel)
{
	clear_bit_unlock(EFX_CHANNEL_STATE_DISABLE_BIT,
			&channel->busy_poll_state);
}

/* Stop further polling or napi access.
 * Returns false if the channel is currently busy polling.
 */
static inline bool efx_channel_disable(struct efx_channel *channel)
{
	set_bit(EFX_CHANNEL_STATE_DISABLE_BIT, &channel->busy_poll_state);
	/* Implicit barrier in efx_channel_busy_polling() */
	return !efx_channel_busy_polling(channel);
}

#else /* CONFIG_NET_RX_BUSY_POLL */

static inline void efx_channel_busy_poll_init(struct efx_channel *channel)
{
}

static inline bool efx_channel_lock_napi(struct efx_channel *channel)
{
	return true;
}

static inline void efx_channel_unlock_napi(struct efx_channel *channel)
{
}

static inline bool efx_channel_try_lock_poll(struct efx_channel *channel)
{
	return false;
}

static inline void efx_channel_unlock_poll(struct efx_channel *channel)
{
}

static inline bool efx_channel_busy_polling(struct efx_channel *channel)
{
	return false;
}

static inline void efx_channel_enable(struct efx_channel *channel)
{
}

static inline bool efx_channel_disable(struct efx_channel *channel)
{
	return true;
}
#endif /* CONFIG_NET_RX_BUSY_POLL */
#endif /* EFX_HAVE_NDO_BUSY_POLL */

/**
 * struct efx_msi_context - Context for each MSI
 * @efx: The associated NIC
 * @index: Index of the channel/IRQ
 * @name: Name of the channel/IRQ
 *
 * Unlike &struct efx_channel, this is never reallocated and is always
 * safe for the IRQ handler to access.
 */
struct efx_msi_context {
	struct efx_nic *efx;
	unsigned int index;
	char name[IFNAMSIZ + 6];
};

/**
 * struct efx_channel_type - distinguishes traffic and extra channels
 * @handle_no_channel: Handle failure to allocate an extra channel
 * @pre_probe: Set up extra state prior to initialisation
 * @start: called early in efx_start_channels()
 * @stop: called early in efx_stop_channels()
 * @post_remove: Tear down extra state after finalisation, if allocated.
 *	May be called on channels that have not been probed.
 * @get_name: Generate the channel's name (used for its IRQ handler)
 * @receive_skb: Handle an skb ready to be passed to netif_receive_skb()
 * @receive_raw: Handle an RX buffer ready to be passed to __efx_rx_packet()
 * @keep_eventq: Flag for whether event queue should be kept initialised
 *	while the device is stopped
 * @hide_tx: Flag set the TX queue is used for internal driver purposes
 *	and is not exposed to the kernel.
 * @get_queue_name: Get channel RX/TX queue name
 */
struct efx_channel_type {
	void (*handle_no_channel)(struct efx_nic *);
	int (*pre_probe)(struct efx_channel *);
	int (*start)(struct efx_channel *);
	void (*stop)(struct efx_channel *);
	void (*post_remove)(struct efx_channel *);
	void (*get_name)(struct efx_channel *, char *buf, size_t len);
	bool (*receive_skb)(struct efx_rx_queue *, struct sk_buff *);
	bool (*receive_raw)(struct efx_rx_queue *, u32);
	bool keep_eventq;
	bool hide_tx;
	const char *(*get_queue_name)(struct efx_channel *, bool tx);
};

enum efx_led_mode {
	EFX_LED_OFF	= 0,
	EFX_LED_ON	= 1,
	EFX_LED_DEFAULT	= 2
};

#define STRING_TABLE_LOOKUP(val, member) \
	((val) < member ## _max) && member ## _names[val] ? member ## _names[val] : "(invalid)"

extern const char *const efx_loopback_mode_names[];
extern const unsigned int efx_loopback_mode_max;
#define LOOPBACK_MODE(efx) \
	STRING_TABLE_LOOKUP((efx)->loopback_mode, efx_loopback_mode)

extern const char *const efx_interrupt_mode_names[];
extern const unsigned int efx_interrupt_mode_max;
#define INT_MODE(efx) \
	STRING_TABLE_LOOKUP(efx->interrupt_mode, efx_interrupt_mode)

void efx_get_udp_tunnel_type_name(u16 type, char *buf, size_t buflen);

enum efx_int_mode {
	/* Be careful if altering to correct macro below */
	EFX_INT_MODE_MSIX = 0,
	EFX_INT_MODE_MSI = 1,
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
	EFX_INT_MODE_POLLED = 2,
#endif
	EFX_INT_MODE_MAX	/* Insert any new items before this */
};

enum nic_state {
	STATE_UNINIT = 0,	/* device being probed/removed */
	STATE_PROBED,		/* hardware probed */
	STATE_NET_DOWN,		/* netdev registered */
	STATE_NET_ALLOCATED,	/* resources allocated but no traffic */
	STATE_NET_UP,		/* ready for traffic */
	STATE_DISABLED,		/* device disabled due to hardware errors */
	STATE_VDPA,		/* device bar_config changed to vDPA */

	STATE_RECOVERY = 0x100,/* recovering from PCI error */
	STATE_FROZEN = 0x200,	/* frozen by power management */
};

static inline bool efx_net_active(enum nic_state state)
{
	return state == STATE_NET_DOWN ||
	       state == STATE_NET_UP ||
	       state == STATE_NET_ALLOCATED;
}

static inline bool efx_net_allocated(enum nic_state state)
{
	return state ==  STATE_NET_UP ||
	       state == STATE_NET_ALLOCATED;
}

static inline bool efx_frozen(enum nic_state state)
{
	return state & STATE_FROZEN;
}

static inline bool efx_recovering(enum nic_state state)
{
	return state & STATE_RECOVERY;
}

static inline enum nic_state efx_freeze(enum nic_state state)
{
	WARN_ON(!efx_net_active(state));
	return state | STATE_FROZEN;
}

static inline enum nic_state efx_thaw(enum nic_state state)
{
	WARN_ON(!efx_frozen(state));
	return state & ~STATE_FROZEN;
}

static inline enum nic_state efx_begin_recovery(enum nic_state state)
{
	WARN_ON(!efx_net_active(state));
	return state | STATE_RECOVERY;
}

static inline enum nic_state efx_end_recovery(enum nic_state state)
{
	WARN_ON(!efx_recovering(state));
	return state & ~STATE_RECOVERY;
}

/* Forward declaration */
struct efx_nic;

/* Pseudo bit-mask flow control field */
#define EFX_FC_RX	FLOW_CTRL_RX
#define EFX_FC_TX	FLOW_CTRL_TX
#define EFX_FC_AUTO	4

/**
 * struct efx_link_state - Current state of the link
 * @up: Link is up
 * @fd: Link is full-duplex
 * @fc: Actual flow control flags
 * @speed: Link speed (Mbps)
 * @ld_caps: Local device capabilities
 * @lp_caps: Link partner capabilities
 */
struct efx_link_state {
	bool up;
	bool fd;
	u8 fc;
	unsigned int speed;
	u32 ld_caps;
	u32 lp_caps;
};

static inline bool efx_link_state_equal(const struct efx_link_state *left,
					const struct efx_link_state *right)
{
	return left->up == right->up && left->fd == right->fd &&
		left->fc == right->fc && left->speed == right->speed;
}

/**
 * enum efx_phy_mode - PHY operating mode flags
 * @PHY_MODE_NORMAL: on and should pass traffic
 * @PHY_MODE_TX_DISABLED: on with TX disabled
 * @PHY_MODE_LOW_POWER: set to low power through ethtool
 * @PHY_MODE_OFF: switched off through external control
 * @PHY_MODE_SPECIAL: on but will not pass traffic
 */
enum efx_phy_mode {
	PHY_MODE_NORMAL		= 0,
	PHY_MODE_TX_DISABLED	= 1,
	PHY_MODE_LOW_POWER	= 2,
	PHY_MODE_OFF		= 4,
	PHY_MODE_SPECIAL	= 8,
};

static inline bool efx_phy_mode_disabled(enum efx_phy_mode mode)
{
	return !!(mode & ~PHY_MODE_TX_DISABLED);
}

/**
 * struct efx_hw_stat_desc - Description of a hardware statistic
 * @name: Name of the statistic as visible through ethtool, or %NULL if
 *	it should not be exposed
 * @dma_width: Width in bits (0 for non-DMA statistics)
 * @offset: Offset within stats (ignored for non-DMA statistics)
 */
struct efx_hw_stat_desc {
	const char *name;
	u16 dma_width;
	u16 offset;
};

/* Efx Error condition statistics */
struct efx_nic_errors {
	atomic_t missing_event;
	atomic_t rx_reset;
	atomic_t rx_desc_fetch;
	atomic_t tx_desc_fetch;
	atomic_t spurious_tx;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debug_dir;
#endif
};

struct vfdi_status;
struct sfc_rdma_dev;

/* Useful collections of RSS flags.  Caller needs mcdi_pcol.h. */
#define RSS_CONTEXT_FLAGS_DEFAULT	(1 << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TOEPLITZ_IPV4_EN_LBN |\
					 1 << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TOEPLITZ_TCPV4_EN_LBN |\
					 1 << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TOEPLITZ_IPV6_EN_LBN |\
					 1 << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TOEPLITZ_TCPV6_EN_LBN)
#define RSS_CONTEXT_FLAGS_ADDITIONAL_MASK	~0xff
#define RSS_MODE_HASH_ADDRS	(1 << RSS_MODE_HASH_SRC_ADDR_LBN |\
				 1 << RSS_MODE_HASH_DST_ADDR_LBN)
#define RSS_MODE_HASH_PORTS	(1 << RSS_MODE_HASH_SRC_PORT_LBN |\
				 1 << RSS_MODE_HASH_DST_PORT_LBN)
#define RSS_MODE_HASH_4TUPLE	(RSS_MODE_HASH_ADDRS | RSS_MODE_HASH_PORTS)
#define RSS_CONTEXT_FLAGS_DEFAULT_ADDITIONAL	(\
		RSS_MODE_HASH_4TUPLE << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TCP_IPV4_RSS_MODE_LBN |\
		RSS_MODE_HASH_ADDRS << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_UDP_IPV4_RSS_MODE_LBN |\
		RSS_MODE_HASH_ADDRS << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_OTHER_IPV4_RSS_MODE_LBN |\
		RSS_MODE_HASH_4TUPLE << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TCP_IPV6_RSS_MODE_LBN |\
		RSS_MODE_HASH_ADDRS << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_UDP_IPV6_RSS_MODE_LBN |\
		RSS_MODE_HASH_ADDRS << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_OTHER_IPV6_RSS_MODE_LBN)

#ifdef CONFIG_RFS_ACCEL
/* Order of these is important, since filter_id >= %EFX_ARFS_FILTER_ID_PENDING
 * is used to test if filter does or will exist.
 */
#define EFX_ARFS_FILTER_ID_PENDING	-1
#define EFX_ARFS_FILTER_ID_ERROR	-2
#define EFX_ARFS_FILTER_ID_REMOVING	-3
/**
 * struct efx_arfs_rule - record of an ARFS filter and its IDs
 * @node: linkage into hash table
 * @spec: details of the filter (used as key for hash table).  Use efx->type to
 *	determine which member to use.
 * @rxq_index: channel to which the filter will steer traffic.
 * @arfs_id: filter ID which was returned to ARFS
 * @filter_id: index in software filter table.  May be
 *	%EFX_ARFS_FILTER_ID_PENDING if filter was not inserted yet,
 *	%EFX_ARFS_FILTER_ID_ERROR if filter insertion failed, or
 *	%EFX_ARFS_FILTER_ID_REMOVING if expiry is currently removing the filter.
 */
struct efx_arfs_rule {
	struct hlist_node node;
	struct efx_filter_spec spec;
	u16 rxq_index;
	u16 arfs_id;
	s32 filter_id;
};

/* Size chosen so that the table is one page (4kB) */
#define EFX_ARFS_HASH_TABLE_SIZE	512

/**
 * struct efx_async_filter_insertion - Request to asynchronously insert a filter
 * @net_dev: Reference to the netdevice
 * @spec: The filter to insert
 * @work: Workitem for this request
 * @rxq_index: Identifies the channel for which this request was made
 * @flow_id: Identifies the kernel-side flow for which this request was made
 */
struct efx_async_filter_insertion {
	struct net_device *net_dev;
	struct efx_filter_spec spec;
	struct work_struct work;
	u16 rxq_index;
	u32 flow_id;
};

/* Maximum number of ARFS workitems that may be in flight on an efx_nic */
#define EFX_RPS_MAX_IN_FLIGHT	8
#endif /* CONFIG_RFS_ACCEL */

/**
 * struct efx_ntuple_rule - record of an ntuple filter and its IDs
 * @list: linked list node in the ntuple_list
 * @spec: details of the filter.
 * @user_id: filter ID which was returned to ethtool
 * @filter_id: index in software filter table.
 *	Only valid if efx_net_allocated(efx->state).
 */
struct efx_ntuple_rule {
	struct list_head list;
	struct efx_filter_spec spec;
	u32 user_id;
	s32 filter_id;
};

/**
 * struct efx_vport - A driver-managed virtual port
 * @list: node of linked list on which this struct is stored
 * @vport_id: the VPORT_ID returned by MC firmware, or %EVB_PORT_ID_NULL if this
 *	vport is not present on the NIC
 * @user_id: the port_id exposed to the user
 * @vlan: VID of this vport's VLAN, or %EFX_FILTER_VID_UNSPEC for none
 * @vlan_restrict: as per %MC_CMD_VPORT_ALLOC_IN_FLAG_VLAN_RESTRICT
 */
struct efx_vport {
#ifdef EFX_NOT_UPSTREAM
	/* These are used by Driverlink (and no-one else currently). */
#endif
	struct list_head list;
	u32 vport_id;
	u16 user_id;
	u16 vlan;
	bool vlan_restrict;
};


#ifdef CONFIG_SFC_MTD
/**
 * struct efx_mtd - Struct to holds mtd list and krer for deletion without efx
 * @efx: The associated efx_nic
 * @list: List of MTDs attached to the NIC
 * @parts: Memory allocated for MTD data
 * @parts_kref: kref object for @parts
 */
struct efx_mtd {
	struct efx_nic *efx;
	struct list_head list;
	void *parts;
	struct kref parts_kref;
#if defined(EFX_WORKAROUND_87308)
	/** @probed_flag: Flag set when netdev is registered or renamed */
	atomic_t probed_flag;
	/** @creation_work: Delay MTD creation to avoid naming conflicts */
	struct delayed_work creation_work;
};
#endif
#endif


/**
 * enum efx_buf_alloc_mode - buffer allocation mode
 * @EFX_BUF_MODE_EF100: buffer setup in ef100 mode
 * @EFX_BUF_MODE_VDPA: buffer setup in vdpa mode
 */
enum efx_buf_alloc_mode {
	EFX_BUF_MODE_EF100,
	EFX_BUF_MODE_VDPA
};

struct efx_mae;

/**
 * struct efx_nic - an Efx NIC
 * @name: Device name (net device name or bus id before net device registered)
 * @pci_dev: The PCI device
 * @type: Controller type attributes
 * @mgmt_dev: vDPA Management device
 * @port_num: Port number as reported by MCDI
 * @client_id: client ID of this PCIe function
 * @adapter_base_addr: MAC address of port0 (used as unique identifier)
 * @reset_work: Scheduled reset workitem
 * @membase_phys: Memory BAR value as physical address
 * @membase: Memory BAR value
 * @rdev: Device information for the virtual bus
 * @vi_stride: step between per-VI registers / memory regions
 * @interrupt_mode: Interrupt mode
 * @timer_quantum_ns: Interrupt timer quantum, in nanoseconds
 * @timer_max_ns: Interrupt timer maximum value, in nanoseconds
 * @tc_match_ignore_ttl: Flag for whether TC match should ignore IP TTL value
 * @irq_rx_adaptive: Adaptive IRQ moderation enabled for RX event queues
 * @xdp_tx: Flag for whether XDP TX queues are supported
 * @irqs_hooked: Channel interrupts are hooked
 * @log_tc_errs: Error logging for TC filter insertion is enabled
 * @irq_mod_step_us: Adaptive IRQ moderation time step for RX event queues
 * @irq_rx_moderation_us: IRQ moderation time for RX event queues
 * @rss_mode: RSS spreading mode
 * @msg_enable: Log message enable flags
 * @state: Device state number (%STATE_*). Serialised by the rtnl_lock.
 * @max_irqs: Maximum number if interrupts the device supports.
 * @reset_pending: Bitmask for pending resets
 * @last_reset: Time of previous reset (jiffies)
 * @current_reset: Time of current reset (jiffies)
 * @reset_count: Count of resets to rate limit reset rescheduling
 * @channel_list: Channels used by a PCI function.
 * @msi_context: Context for each MSI
 * @extra_channel_type: Types of extra (non-traffic) channels that
 *	should be allocated for this NIC
 * @mae: Details of the Match Action Engine
 * @xdp_tx_queue_count: Number of entries in %xdp_tx_queues.
 * @xdp_tx_queues: Array of pointers to tx queues used for XDP transmit.
 * @rxq_entries: Size of receive queues requested by user.
 * @txq_entries: Size of transmit queues requested by user.
 * @txq_stop_thresh: TX queue fill level at or above which we stop it.
 * @txq_wake_thresh: TX queue fill level at or below which we wake it.
 * @txq_min_entries: Minimum valid number of TX queue entries.
 * @tx_dc_entries: Number of entries in each TX queue descriptor cache
 * @rx_dc_entries: Number of entries in each RX queue descriptor cache
 * @tx_dc_base: Base qword address in SRAM of TX queue descriptor caches
 * @rx_dc_base: Base qword address in SRAM of RX queue descriptor caches
 * @sram_lim_qw: Qword address limit of SRAM
 * @max_channels: Max available channels
 * @max_vis: Max available VI resources
 * @max_tx_channels: Max available TX channels
 * @supported_bitmap: Bitmap of supported ring sizes (EF100)
 * @guaranteed_bitmap: Bitmap of guaranteed ring sizes (EF100)
 * @n_combined_channels: Number of combined RX/TX channels
 * @n_extra_channels: Number of extra channels (for driver-internal uses)
 * @n_rx_only_channels: Number of channels used only for RX (after combined)
 * @n_rss_channels: Number of rx channels available for RSS.
 * @rss_spread: Number of event queues to spread traffic over.
 * @n_tx_only_channels: Number of channels used only for TX (after RX)
 * @tx_channel_offset: Offset of zeroth channel used for TX.
 * @tx_queues_per_channel: Number of TX queues on a normal (non-XDP) TX channel.
 * @n_xdp_channels: Number of channels used for XDP TX (after TX)
 * @xdp_tx_per_channel: Max number of TX queues on an XDP TX channel.
 * @rx_ip_align: RX DMA address offset to have IP header aligned in
 *	in accordance with NET_IP_ALIGN
 * @rx_dma_len: Current maximum RX DMA length
 * @rx_buffer_order: Order (log2) of number of pages for each RX buffer
 * @rx_buffer_truesize: Amortised allocation size of an RX buffer,
 *	for use in &struct sk_buff.truesize
 * @rx_page_buf_step: Stride between adjacent RX buffers, in bytes
 * @rx_bufs_per_page: Number of RX buffers per memory page
 * @rx_pages_per_batch: Preferred number of descriptors to fill at once
 * @rx_prefix_size: Size of RX prefix before packet data
 * @rx_packet_hash_offset: Offset of RX flow hash from start of packet data
 *	(valid only if @rx_prefix_size != 0; always negative)
 * @rx_packet_len_offset: Offset of RX packet length from start of packet data
 *	(valid only for NICs that set %EFX_RX_PKT_PREFIX_LEN; always negative)
 * @rx_packet_ts_offset: Offset of timestamp from start of packet data
 *	(valid only if channel->sync_timestamps_enabled; always negative)
 * @rx_scatter: Scatter mode enabled for receives
 * @rss_context: Main RSS context.  Its @list member is the head of the list of
 *	RSS contexts created by user requests
 * @rss_lock: Protects custom RSS context software state in @rss_context.list
 * @vport: Main virtual port.  Its @list member is the head of a list of vports.
 * @vport_lock: Protects extra virtual port state in @vport.list
 * @select_tx_queue: select appropriate TX queue for packet
 * @errors: Error condition stats
 * @int_error_count: Number of internal errors seen recently
 * @int_error_expire: Time at which error count will be expired
 * @irq_soft_enabled: Are IRQs soft-enabled? If not, IRQ handler will
 *	acknowledge but do nothing else.
 * @irq_status: Interrupt status buffer
 * @irq_level: IRQ level/index for IRQs not triggered by an event queue
 * @selftest_work: Work item for asynchronous self-test
 * @mtd_struct: A struct for holding combined mtd data for freeing
 *	independently
 * @nic_data: Hardware dependent state
 * @mcdi: Management-Controller-to-Driver Interface state
 * @mac_lock: MAC access lock. Protects @port_enabled, @link_up, @phy_mode,
 *	efx_monitor() and efx_mac_work()
 * @mac_work: Work item for changing MAC promiscuity and multicast hash
 * @port_enabled: Port enabled indicator.
 *	Serialises efx_stop_all(), efx_start_all(), efx_monitor() and
 *	efx_mac_work() with kernel interfaces. Safe to read under any
 *	one of the rtnl_lock, mac_lock, or netif_tx_lock, but all three must
 *	be held to modify it.
 * @datapath_started: Is the datapath running ?
 * @mc_bist_for_other_fn: Is NIC unavailable due to BIST on another function ?
 * @port_initialized: Port initialized?
 * @net_dev: Operating system network device. Consider holding the rtnl lock
 * @vlan_filter_available: are VLAN filters available ?
 * @fixed_features: Features which cannot be turned off
 * @stats_enabled: Is periodic statistics collection enabled ?
 * @stats_initialised: Have initial stats counters been fetched ?
 * @num_mac_stats: Number of MAC stats reported by firmware (MAC_STATS_NUM_STATS
 *	field of %MC_CMD_GET_CAPABILITIES_V4 response, or %MC_CMD_MAC_NSTATS)
 * @stats_period_ms: Interval between statistic updates in milliseconds.
 *	Set from ethtool -C parameter stats-block-usecs.
 * @stats_monitor_work: Work item to monitor periodic statistics updates
 * @stats_monitor_generation: Periodic stats most recent generation count
 * @stats_buffer: DMA buffer for statistics
 * @mc_initial_stats: Buffer for statistics as they were when probing the device
 * @rx_nodesc_drops_total: Count packets dropped when no RX descriptor is
 *	available on the NIC.
 * @rx_nodesc_drops_while_down: Count packets dropped when no RX descriptor is
 *	available on the NIC and the interface is down.
 * @rx_nodesc_drops_prev_state: Was interface up when nodesc drops last updated ?
 * @phy_type: PHY type
 * @phy_name: PHY name
 * @phy_data: PHY data
 * @phy_mode: PHY operating mode. Serialised by @mac_lock.
 * @link_down_on_reset: force link down on reset
 * @phy_power_follows_link: PHY powers off when link is taken down.
 * @phy_power_force_off: PHY always powered off - only useful for test.
 * @link_advertising: Autonegotiation advertising flags
 * @fec_config: Forward Error Correction configuration flags.  For bit positions
 *	see &enum ethtool_fec_config_bits.
 * @link_state: Current state of the link
 * @n_link_state_changes: Number of times the link has changed state
 * @wanted_fc: Wanted flow control flags
 * @fc_disable: When non-zero flow control is disabled. Typically used to
 *	ensure that network back pressure doesn't delay dma queue flushes.
 *	Serialised by the rtnl lock.
 * @loopback_mode: Loopback status
 * @loopback_modes: Supported loopback mode bitmask
 * @loopback_selftest: Offline self-test private state
 * @xdp_prog: Current XDP program for this interface
 * @filter_sem: Filter table rw_semaphore, protects existence of @filter_state
 * @filter_state: Architecture-dependent filter table state
 * @rps_mutex: Protects RPS state of all channels
 * @rps_slot_map: bitmap of in-flight entries in @rps_slot
 * @rps_slot: array of ARFS insertion requests for efx_filter_rfs_work()
 * @rps_hash_lock: Protects ARFS filter mapping state (@rps_hash_table and
 *	@rps_next_id).
 * @rps_hash_table: Mapping between ARFS filters and their various IDs
 * @rps_next_id: next arfs_id for an ARFS filter
 * @ntuple_list: List of ntuple filters
 * @active_queues: Count of RX and TX queues that haven't been flushed and drained.
 * @rxq_flush_pending: Count of number of receive queues that need to be flushed.
 *	Decremented when the efx_flush_rx_queue() is called.
 * @rxq_flush_outstanding: Count of number of RX flushes started but not yet
 *	completed (either success or failure). Not used when MCDI is used to
 *	flush receive queues.
 * @flush_wq: wait queue used by efx_nic_flush_queues() to wait for flush completions.
 * @ptp_data: PTP state data
 * @phc_ptp_data: PTP state data of the adapter exposing the PHC clock.
 * @node_ptp_all_funcs: List node for maintaining list of all functions.
 *	Serialised by ptp_all_funcs_list_lock
 * @ptp_unavailable_warned: If PTP is unavailable has a warning been issued ?
 * @ptp_capability: PTP capability flags
 * @dump_data: state for NIC state dumping support
 * @netdev_notifier: Netdevice notifier.
 * @netevent_notifier: Netevent notifier (for neighbour updates).
 * @tc: state for TC offload (EF100).
 * @mem_bar: The BAR that is mapped into membase.
 * @reg_base: Offset from the start of the bar to the function control window.
 * @mcdi_buf_mode: mcdi buffer allocation mode
 * @vdpa_nic: State when operating as a VDPA device (EF100)
 * @reflash_mutex: Mutex for serialising firmware reflash operations.
 * @monitor_work: Hardware monitor workitem
 * @biu_lock: BIU (bus interface unit) lock
 * @last_irq_cpu: Last CPU to handle a possible test interrupt.  This
 *	field is used by efx_test_interrupts() to verify that an
 *	interrupt has occurred.
 * @stats_lock: Statistics update lock. Used to serialize access to
 *	statistics-related NIC data. Obtained in efx_nic_type::update_stats
 *	and must be released by caller after statistics processing/copying
 *	if required.
 * @n_rx_noskb_drops: Count of RX packets dropped due to failure to allocate an skb
 *
 * This is stored in the private area of the &struct net_device.
 */
struct efx_nic {

	/* The following fields should be written very rarely */
	char name[IFNAMSIZ];
	struct pci_dev *pci_dev;
	const struct efx_nic_type *type;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VDPA_MGMT_INTERFACE)
	struct vdpa_mgmt_dev *mgmt_dev;
#endif
	unsigned int port_num;
	u32 client_id;
	/* Aligned for efx_mcdi_get_board_cfg()+ether_addr_copy() */
	u8 adapter_base_addr[ETH_ALEN] __aligned(2);
	struct work_struct reset_work;
#ifdef EFX_NOT_UPSTREAM
	/**
	 * @schedule_all_channels_work: work item to schedule NAPI on all
	 *	channels
	 */
	struct work_struct schedule_all_channels_work;
#endif
	resource_size_t membase_phys;
	void __iomem *membase;
	struct sfc_rdma_dev *rdev;

	unsigned int vi_stride;

	enum efx_int_mode interrupt_mode;
	unsigned int timer_quantum_ns;
	unsigned int timer_max_ns;
	bool tc_match_ignore_ttl;
	bool irq_rx_adaptive;
	bool xdp_tx;
	bool irqs_hooked;
	bool log_tc_errs;
	unsigned int irq_mod_step_us;
	unsigned int irq_rx_moderation_us;
#if !defined(EFX_NOT_UPSTREAM)
	enum efx_rss_mode rss_mode;
#endif
	u32 msg_enable;
#ifdef EFX_NOT_UPSTREAM
	/** @performance_profile: Performance tuning profile */
	enum efx_performance_profile performance_profile;
#endif

	enum nic_state state;
	u16 max_irqs;
	unsigned long reset_pending;
	unsigned long last_reset;
	unsigned long current_reset;
	unsigned int reset_count;

	struct list_head channel_list;
	struct efx_msi_context *msi_context;
	const struct efx_channel_type *
		extra_channel_type[EFX_MAX_EXTRA_CHANNELS];
	struct efx_mae *mae;

	unsigned int xdp_tx_queue_count;
	struct efx_tx_queue **xdp_tx_queues;

	unsigned int rxq_entries;
	unsigned int txq_entries;
	unsigned int txq_stop_thresh;
	unsigned int txq_wake_thresh;
	unsigned int txq_min_entries;

	unsigned int tx_dc_entries;
	unsigned int rx_dc_entries;
	unsigned int tx_dc_base;
	unsigned int rx_dc_base;
	unsigned int sram_lim_qw;
#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	/** @n_dl_irqs: Number of IRQs to reserve for driverlink */
	int n_dl_irqs;
	/** @ef10_resources: EF10 driverlink parameters */
	struct efx_dl_ef10_resources ef10_resources;
	/** @irq_resources: IRQ driverlink parameters */
	struct efx_dl_irq_resources *irq_resources;
#endif
#endif

	u16 max_channels;
	u16 max_vis;
	unsigned int max_tx_channels;
	unsigned long supported_bitmap;
	unsigned long guaranteed_bitmap;

	/* RX and TX channel ranges must be contiguous.
	 * other channels are always combined channels.
	 * combined channels are first, followed by other channels OR
	 *   TX-only channels OR RX-only channels.
	 * OR we can have RX-only then TX-only, but no combined or other.
	 * XDP is a special set of TX channels that go on the end and can
	 * coexist with anything.
	 * So we can have:
	 * combined and other
	 * combined and RX-only
	 * combined and TX-only
	 * RX-only and TX-only
	 */
	unsigned int n_combined_channels;
	unsigned int n_extra_channels;
	unsigned int n_rx_only_channels;
	unsigned int n_rss_channels;
	unsigned int rss_spread;
	unsigned int n_tx_only_channels;
	unsigned int tx_channel_offset;
	unsigned int tx_queues_per_channel;
	unsigned int n_xdp_channels;
	unsigned int xdp_tx_per_channel;
	unsigned int rx_ip_align;
	unsigned int rx_dma_len;
	unsigned int rx_buffer_order;
	unsigned int rx_buffer_truesize;
	unsigned int rx_page_buf_step;
	unsigned int rx_bufs_per_page;
	unsigned int rx_pages_per_batch;
	unsigned int rx_prefix_size;
	int rx_packet_hash_offset;
	int rx_packet_len_offset;
	int rx_packet_ts_offset;
	bool rx_scatter;
	struct efx_rss_context rss_context;
	struct mutex rss_lock;

	struct efx_vport vport;
	struct mutex vport_lock;

	struct efx_tx_queue *(*select_tx_queue)(struct efx_channel *channel,
						struct sk_buff *skb);

	struct efx_nic_errors errors;
	unsigned int_error_count;
	unsigned long int_error_expire;

	bool irq_soft_enabled;
	struct efx_buffer irq_status;
	unsigned long irq_level;
	struct delayed_work selftest_work;

#ifdef CONFIG_SFC_MTD
	struct efx_mtd *mtd_struct;
#endif

	void *nic_data;
	struct efx_mcdi_data *mcdi;

	struct mutex mac_lock;
	struct work_struct mac_work;
#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	/** @open_count: Count netdev opens */
	u16 open_count;
#endif
#endif
	bool port_enabled;
	bool datapath_started;

	bool mc_bist_for_other_fn;
	bool port_initialized;
	struct net_device *net_dev;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	/** @lro_available: Is LRO supported ? */
	bool lro_available;
#ifndef NETIF_F_LRO
	/** @lro_enabled: Is LRO enabled ? */
	bool lro_enabled;
#endif
#endif
	bool vlan_filter_available;

	netdev_features_t fixed_features;

	bool stats_enabled;
	bool stats_initialised;
	u16 num_mac_stats;
	unsigned int stats_period_ms;

	struct delayed_work stats_monitor_work;
	__le64 stats_monitor_generation;

	struct efx_buffer stats_buffer;
	__le64 *mc_initial_stats;
	u64 rx_nodesc_drops_total;
	u64 rx_nodesc_drops_while_down;
	bool rx_nodesc_drops_prev_state;

	unsigned int phy_type;
	char phy_name[20];
	void *phy_data;
	enum efx_phy_mode phy_mode;
	bool link_down_on_reset;
	bool phy_power_follows_link;
	bool phy_power_force_off;

	__ETHTOOL_DECLARE_LINK_MODE_MASK(link_advertising);
	u32 fec_config;
	struct efx_link_state link_state;
	unsigned int n_link_state_changes;

	u8 wanted_fc;
	unsigned int fc_disable;

	enum efx_loopback_mode loopback_mode;
	u64 loopback_modes;
	void *loopback_selftest;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	/* We access loopback_selftest immediately before running XDP,
	 * so we want them next to each other.
	 */
	struct bpf_prog __rcu *xdp_prog;
#endif

	struct rw_semaphore filter_sem;
	void *filter_state;
#ifdef CONFIG_RFS_ACCEL
	struct mutex rps_mutex;
	unsigned long rps_slot_map;
	struct efx_async_filter_insertion rps_slot[EFX_RPS_MAX_IN_FLIGHT];
	spinlock_t rps_hash_lock;
	struct hlist_head *rps_hash_table;
	u32 rps_next_id;
#endif
	struct list_head ntuple_list;

#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	/** @dl_nic: Efx driverlink nic */
	struct efx_dl_nic dl_nic;
	/**
	 * @dl_block_kernel_mutex: Mutex protecting @dl_block_kernel_count
	 *	and corresponding per-client state
	 */
	struct mutex dl_block_kernel_mutex;
	/**
	 * @dl_block_kernel_count: Number of times Driverlink clients are
	 *	blocking the kernel stack from receiving packets
	 */
	unsigned int dl_block_kernel_count[EFX_DL_FILTER_BLOCK_KERNEL_MAX];
#endif
#endif

#ifdef CONFIG_DEBUG_FS
	/** @debug_dir: NIC debugfs directory */
	struct dentry *debug_dir;
	/** @debug_symlink: NIC debugfs symlink (``nic_eth%d``) */
	struct dentry *debug_symlink;
	/** @debug_port_dir: Port debugfs directory */
	struct dentry *debug_port_dir;
	/** @debug_port_symlink: Port debugfs symlink (``if_eth%d``) */
	struct dentry *debug_port_symlink;
#endif

	atomic_t active_queues;
	atomic_t rxq_flush_pending;
	atomic_t rxq_flush_outstanding;
	wait_queue_head_t flush_wq;

#ifdef CONFIG_SFC_PTP
	struct efx_ptp_data *ptp_data;
	struct efx_ptp_data *phc_ptp_data;
	struct list_head node_ptp_all_funcs;
	bool ptp_unavailable_warned;
#endif
	unsigned int ptp_capability;

#ifdef CONFIG_SFC_DUMP
	struct efx_dump_data *dump_data;
#endif
	struct notifier_block netdev_notifier;
	struct notifier_block netevent_notifier;
	struct efx_tc_state *tc;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEVLINK)
	/** @devlink: Devlink instance */
	struct devlink *devlink;
	/** @devlink_port: Devlink port instance */
	struct devlink_port *devlink_port;
#endif
	unsigned int mem_bar;
	u32 reg_base;
	enum efx_buf_alloc_mode mcdi_buf_mode;
#ifdef CONFIG_SFC_VDPA
	struct ef100_vdpa_nic *vdpa_nic;
#endif
	struct mutex reflash_mutex;

	/* The following fields may be written more often */

	struct delayed_work monitor_work ____cacheline_aligned_in_smp;
	spinlock_t biu_lock;
	int last_irq_cpu;
	spinlock_t stats_lock;
	atomic_t n_rx_noskb_drops;

#ifdef CONFIG_DEBUG_FS
	/**
	 * @debugfs_symlink_mutex: Protect debugfs @debug_symlink and
	 *	@debug_port_symlink
	 */
	struct mutex debugfs_symlink_mutex;
#endif
};

/**
 * struct efx_probe_data - State after hardware probe
 * @pci_dev: The PCI device
 * @efx: Efx NIC details
 */
struct efx_probe_data {
	struct pci_dev *pci_dev;
	struct efx_nic efx;
};

static inline struct efx_nic *efx_netdev_priv(struct net_device *dev)
{
	struct efx_probe_data **probe_ptr = netdev_priv(dev);
	struct efx_probe_data *probe_data = *probe_ptr;

	return &probe_data->efx;
}

static inline unsigned int efx_xdp_channels(struct efx_nic *efx)
{
	return efx->xdp_tx ? efx->n_xdp_channels : 0;
}

static inline unsigned int efx_channels(struct efx_nic *efx)
{
	return efx->n_combined_channels + efx->n_extra_channels +
	       efx->n_rx_only_channels + efx->n_tx_only_channels +
	       efx_xdp_channels(efx);
}

static inline unsigned int efx_rx_channels(struct efx_nic *efx)
{
	return efx->n_combined_channels + efx->n_rx_only_channels +
	       efx->n_extra_channels;
}

static inline unsigned int efx_tx_channels(struct efx_nic *efx)
{
	return efx->n_combined_channels + efx->n_tx_only_channels +
	       efx->n_extra_channels;
}

static inline unsigned int efx_extra_channel_offset(struct efx_nic *efx)
{
	if (efx->n_rx_only_channels && efx->n_tx_only_channels)
		return efx->n_rx_only_channels + efx->n_tx_only_channels;
	else
		return efx->n_combined_channels;
}

static inline unsigned int efx_xdp_channel_offset(struct efx_nic *efx)
{
	return efx->tx_channel_offset + efx_tx_channels(efx);
}

static inline int efx_dev_registered(struct efx_nic *efx)
{
	return efx->net_dev->reg_state == NETREG_REGISTERED;
}

static inline unsigned int efx_port_num(struct efx_nic *efx)
{
	return efx->port_num;
}

#ifdef CONFIG_SFC_MTD
struct efx_mtd_partition {
	struct list_head node;
	struct efx_mtd *mtd_struct;
	struct mtd_info mtd;
	const char *dev_type_name;
	const char *type_name;
	char name[IFNAMSIZ + 40];
	/* MCDI related attributes */
	bool updating;
	u32 nvram_type;
	u32 fw_subtype;
};
#endif

struct efx_udp_tunnel {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
#define TUNNEL_ENCAP_UDP_PORT_ENTRY_INVALID	0xffff
#endif
	u16 type; /* TUNNEL_ENCAP_UDP_PORT_ENTRY_foo, see mcdi_pcol.h */
	__be16 port;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	/* Current state of slot.  Used only inside the list, not in request
	 * arguments.
	 */
	u16 adding:1, removing:1, count:14;
#endif
};
#define	EFX_UDP_TUNNEL_COUNT_WARN	0x2000 /* top bit of 14-bit field */
#define EFX_UDP_TUNNEL_COUNT_MAX	0x3fff /* saturate at this value */

#if defined(EFX_USE_KCOMPAT) && defined(EFX_TC_OFFLOAD) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
struct ef100_udp_tunnel {
	enum efx_encap_type type;
	__be16 port;
	struct list_head list;
};
#endif

struct mae_mport_desc;

/**
 * struct efx_nic_type - Efx device type definition
 * @is_vf: Tells whether the function is a VF or PF
 * @mem_bar: Get the memory BAR
 * @mem_map_size: Get memory BAR mapped size
 * @probe: Probe the controller
 * @dimension_resources: Dimension controller resources (buffer table,
 *	and VIs once the available interrupt resources are clear)
 * @free_resources: Free resources allocated by dimension_resources
 * @net_alloc: Bringup shared by netdriver and driverlink clients
 * @net_dealloc: Teardown corresponding to @net_alloc()
 * @remove: Free resources allocated by probe()
 * @init: Initialise the controller
 * @fini: Shut down the controller
 * @monitor: Periodic function for polling link state and hardware monitor
 * @hw_unavailable: Check for uninitialised or disabled hardware
 * @map_reset_reason: Map ethtool reset reason to a reset method
 * @map_reset_flags: Map ethtool reset flags to a reset method, if possible
 * @reset: Reset the controller hardware and possibly the PHY.  This will
 *	be called while the controller is uninitialised.
 * @probe_port: Probe the MAC and PHY
 * @remove_port: Free resources allocated by probe_port()
 * @handle_global_event: Handle a "global" event (may be %NULL)
 * @fini_dmaq: Flush and finalise DMA queues (RX and TX queues)
 * @prepare_flr: Prepare for an FLR
 * @finish_flr: Clean up after an FLR
 * @describe_stats: Describe statistics for ethtool
 * @update_stats: Update statistics not provided by event handling.
 *	Must obtain and hold efx_nic::stats_lock on return.
 *	Either argument may be %NULL.
 * @start_stats: Start the regular fetching of statistics
 * @pull_stats: Pull stats from the NIC and wait until they arrive.
 * @stop_stats: Stop the regular fetching of statistics
 * @update_stats_period: Set interval for periodic stats fetching.
 * @push_irq_moderation: Apply interrupt moderation value
 * @reconfigure_port: Push loopback/power/txdis changes to the MAC and PHY
 * @reconfigure_mac: Push MAC address, MTU, flow control and filter settings
 *	to the hardware.  Serialised by the mac_lock.
 *	Only change MTU if mtu_only is set.
 * @check_mac_fault: Check MAC fault state. True if fault present.
 * @get_wol: Get WoL configuration from driver state
 * @set_wol: Push WoL configuration to the NIC
 * @resume_wol: Synchronise WoL state between driver and MC (e.g. after resume)
 * @check_caps: Check firmware capability flags
 * @test_chip: Test registers and memory. This is expected to reset
 *	the NIC.
 * @test_memory: Test read/write functionality of memory blocks, using
 *	the given test pattern generator
 * @test_nvram: Test validity of NVRAM contents
 * @mcdi_request: Send an MCDI request with the given header and SDU.
 *	The SDU length may be any value from 0 up to the protocol-
 *	defined maximum, but its buffer will be padded to a multiple
 *	of 4 bytes.
 * @mcdi_poll_response: Test whether an MCDI response is available.
 * @mcdi_read_response: Read the MCDI response PDU.  The offset will
 *	be a multiple of 4.  The length may not be, but the buffer
 *	will be padded so it is safe to round up.
 * @mcdi_poll_reboot: Test whether the MCDI has rebooted.  If so,
 *	return an appropriate error code for aborting any current
 *	request; otherwise return 0.
 * @mcdi_record_bist_event: Record warm boot count at start of BIST
 * @mcdi_poll_bist_end: Record warm boot count at end of BIST
 * @mcdi_reboot_detected: Called when the MCDI module detects an MC reboot
 * @mcdi_get_buf: Get a free buffer for MCDI
 * @mcdi_put_buf: Return a buffer from MCDI
 * @irq_enable_master: Enable IRQs on the NIC.  Each event queue must
 *	be separately enabled after this.
 * @irq_test_generate: Generate a test IRQ
 * @irq_disable_non_ev: Disable non-event IRQs on the NIC.  Each event
 *	queue must be separately disabled before this.
 * @irq_handle_msi: Handle MSI for a channel.  The @dev_id argument is
 *	a pointer to the &struct efx_msi_context for the channel.
 * @tx_probe: Allocate resources for TX queue
 * @tx_init: Initialise TX queue on the NIC
 * @tx_write: Write TX descriptors and doorbell
 * @tx_notify: Write TX doorbell
 * @tx_enqueue: Add an SKB to TX queue
 * @tx_limit_len: Max available data length for TX descriptor
 * @tx_max_skb_descs: Max descriptors required for a single SKB
 * @rx_push_rss_config: Write RSS hash key and indirection table to the NIC
 * @rx_pull_rss_config: Read RSS hash key and indirection table back from the NIC
 * @rx_push_rss_context_config: Write RSS hash key and indirection table for
 *	user RSS context to the NIC
 * @rx_pull_rss_context_config: Read RSS hash key and indirection table for user
 *	RSS context back from the NIC
 * @rx_restore_rss_contexts: Restore user RSS contexts removed from hardware
 * @rx_get_default_rss_flags: Get default RSS flags
 * @rx_set_rss_flags: Write RSS flow-hashing flags to the NIC
 * @rx_get_rss_flags: Read RSS flow-hashing flags back from the NIC
 * @rx_probe: Allocate resources for RX queue
 * @rx_init: Initialise RX queue on the NIC
 * @rx_remove: Free resources for RX queue
 * @rx_write: Write RX descriptors and doorbell
 * @rx_defer_refill: Generate a refill reminder event
 * @rx_packet: Receive the queued RX buffer on a channel
 * @rx_buf_hash_valid: Determine whether the RX prefix contains a valid hash
 * @ev_probe: Allocate resources for event queue
 * @ev_init: Initialise event queue on the NIC
 * @ev_fini: Deinitialise event queue on the NIC
 * @ev_remove: Free resources for event queue
 * @ev_process: Process events for a queue, up to the given NAPI quota
 * @ev_mcdi_pending: Peek at event queue, return whether MCDI event is pending
 * @ev_read_ack: Acknowledge read events on a queue, rearming its IRQ
 * @ev_test_generate: Generate a test event
 * @max_rx_ip_filters: Max receive filters for IP
 * @filter_table_probe: Probe filter capabilities and set up filter software state
 * @filter_table_up: Insert filters due to interface up
 * @filter_table_restore: Restore filters removed from hardware
 * @filter_table_down: Remove filters due to interface down
 * @filter_table_remove: Remove filters from hardware and tear down software state
 * @filter_match_supported: Check if specified filter match supported
 * @filter_update_rx_scatter: Update filters after change to rx scatter setting
 * @filter_insert: add or replace a filter
 * @filter_remove_safe: remove a filter by ID, carefully
 * @filter_get_safe: retrieve a filter by ID, carefully
 * @filter_clear_rx: Remove all RX filters whose priority is less than or
 *	equal to the given priority and is not %EFX_FILTER_PRI_AUTO
 * @filter_count_rx_used: Get the number of filters in use at a given priority
 * @filter_get_rx_id_limit: Get maximum value of a filter id, plus 1
 * @filter_get_rx_ids: Get list of RX filters at a given priority
 * @filter_rfs_expire_one: Consider expiring a filter inserted for RFS.
 *	This must check whether the specified table entry is used by RFS
 *	and that rps_may_expire_flow() returns true for it.
 * @mtd_probe: Probe and add MTD partitions associated with this net device,
 *	 using efx_mtd_add()
 * @mtd_rename: Set an MTD partition name using the net device name
 * @mtd_read: Read from an MTD partition
 * @mtd_erase: Erase part of an MTD partition
 * @mtd_write: Write to an MTD partition
 * @mtd_sync: Wait for write-back to complete on MTD partition.  This
 *	also notifies the driver that a writer has finished using this
 *	partition.
 * @ptp_write_host_time: Send host time to MC as part of sync protocol
 * @ptp_set_ts_sync_events: Enable or disable sync events for inline RX
 *	timestamping, possibly only temporarily for the purposes of a reset.
 * @ptp_set_ts_config: Set hardware timestamp configuration.  The flags
 *	and tx_type will already have been validated but this operation
 *	must validate and update rx_filter.
 * @pps_reset: Re-enable PPS if nic_hw_pps_enabled
 * @vlan_rx_add_vid: Add RX VLAN filter
 * @vlan_rx_kill_vid: Delete RX VLAN filter
 * @get_phys_port_id: Get the underlying physical port id.
 * @vport_add: Add a vport with specified VLAN parameters.  Returns an MCDI id.
 * @vport_del: Destroy a vport specified by MCDI id.
 * @sriov_init: Initialise VFs when vf-count is set via module parameter.
 * @sriov_fini: Disable sriov
 * @sriov_wanted: Check that max_vf > 0.
 * @sriov_configure: Enable VFs.
 * @sriov_set_vf_mac: Performs MCDI commands to delete and add back a new
 *       vport with new mac address.
 * @sriov_set_vf_vlan: Set up VF vlan.
 * @sriov_set_vf_spoofchk: Checks if sppokcheck is supported.
 * @sriov_get_vf_config: Gets VF config
 * @sriov_set_vf_link_state: Set VF Link state
 * @vswitching_probe: Allocate vswitches and vports.
 * @vswitching_restore: Restore vswitching following a reset.
 * @vswitching_remove: Free the vports and vswitches.
 * @get_mac_address: Get mac address from underlying vport/pport.
 * @set_mac_address: Set the MAC address of the device
 * @mcdi_rpc_timeout: Select MCDI timeout for command
 * @udp_tnl_has_port: Check if a port has been added as UDP tunnel
 * @udp_tnl_push_ports: Push the list of UDP tunnel ports to the NIC if required.
 * @udp_tnl_add_port: Add a UDP tunnel port
 * @udp_tnl_del_port: Remove a UDP tunnel port
 * @get_vf_rep: get the VF representor netdevice for given VF index
 * @detach_reps: detach (stop TX on) all representors
 * @attach_reps: attach (restart TX on) all representors
 * @add_mport: process the addition of a new MAE port (e.g. create a repr)
 * @remove_mport: process the deletion of an existing MAE port
 * @has_dynamic_sensors: check if dynamic sensor capability is set
 * @rx_recycle_ring_size: Size of the RX recycle ring
 * @revision: Hardware architecture revision
 * @txd_ptr_tbl_base: TX descriptor ring base address
 * @rxd_ptr_tbl_base: RX descriptor ring base address
 * @buf_tbl_base: Buffer table base address
 * @evq_ptr_tbl_base: Event queue pointer table base address
 * @evq_rptr_tbl_base: Event queue read-pointer table base address
 * @max_dma_mask: Maximum possible DMA mask
 * @rx_prefix_size: Size of RX prefix before packet data
 * @rx_hash_offset: Offset of RX flow hash within prefix
 * @rx_ts_offset: Offset of timestamp within prefix
 * @rx_buffer_padding: Size of padding at end of RX packet
 * @can_rx_scatter: NIC is able to scatter packets to multiple buffers
 * @always_rx_scatter: NIC will always scatter packets to multiple buffers
 * @option_descriptors: NIC supports TX option descriptors
 * @copy_break: driver datapath may perform TX copy break
 * @supported_interrupt_modes: A set of flags denoting which interrupt
 *	modes are supported, denoted by a bitshift by values in &enum
 *	efx_init_mode.
 * @timer_period_max: Maximum period of interrupt timer (in ticks)
 * @offload_features: net_device feature flags for protocol offload
 *	features implemented in hardware
 * @mcdi_max_ver: Maximum MCDI version supported
 * @hwtstamp_filters: Mask of hardware timestamp filter types supported
 * @rx_hash_key_size: Size of RSS hash key in bytes
 */
struct efx_nic_type {
	bool is_vf;
	unsigned int (*mem_bar)(struct efx_nic *efx);
	unsigned int (*mem_map_size)(struct efx_nic *efx);
	int (*probe)(struct efx_nic *efx);
	int (*dimension_resources)(struct efx_nic *efx);
	void (*free_resources)(struct efx_nic *efx);
	int (*net_alloc)(struct efx_nic *efx);
	void (*net_dealloc)(struct efx_nic *efx);
	void (*remove)(struct efx_nic *efx);
	int (*init)(struct efx_nic *efx);
	void (*fini)(struct efx_nic *efx);
	void (*monitor)(struct efx_nic *efx);
	bool (*hw_unavailable)(struct efx_nic *efx);
	enum reset_type (*map_reset_reason)(enum reset_type reason);
	int (*map_reset_flags)(u32 *flags);
	int (*reset)(struct efx_nic *efx, enum reset_type method);
	int (*probe_port)(struct efx_nic *efx);
	void (*remove_port)(struct efx_nic *efx);
	bool (*handle_global_event)(struct efx_channel *channel, efx_qword_t *);
	int (*fini_dmaq)(struct efx_nic *efx);
	void (*prepare_flr)(struct efx_nic *efx);
	void (*finish_flr)(struct efx_nic *efx);
	size_t (*describe_stats)(struct efx_nic *efx, u8 *names);
	size_t (*update_stats)(struct efx_nic *efx, u64 *full_stats,
			       struct rtnl_link_stats64 *core_stats)
		__acquires(efx->stats_lock);
	void (*start_stats)(struct efx_nic *efx);
	void (*pull_stats)(struct efx_nic *efx);
	void (*stop_stats)(struct efx_nic *efx);
	void (*update_stats_period)(struct efx_nic *efx);
	void (*push_irq_moderation)(struct efx_channel *channel);
	int (*reconfigure_port)(struct efx_nic *efx);
	int (*reconfigure_mac)(struct efx_nic *efx, bool mtu_only);
	bool (*check_mac_fault)(struct efx_nic *efx);
	void (*get_wol)(struct efx_nic *efx, struct ethtool_wolinfo *wol);
	int (*set_wol)(struct efx_nic *efx, u32 type);
	void (*resume_wol)(struct efx_nic *efx);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_FECSTATS)
	/** @get_fec_stats: Report FEC block statistics. */
	void (*get_fec_stats)(struct efx_nic *efx,
			      struct ethtool_fec_stats *fec_stats);
#endif
	unsigned int (*check_caps)(const struct efx_nic *efx,
				   u8 flag,
				   u32 offset);
	int (*test_chip)(struct efx_nic *efx, struct efx_self_tests *tests);
	int (*test_memory)(struct efx_nic *efx,
			void (*pattern)(unsigned int, efx_qword_t *, int, int),
			int a, int b);
	int (*test_nvram)(struct efx_nic *efx);
	void (*mcdi_request)(struct efx_nic *efx, u8 bufid,
			     const efx_dword_t *hdr, size_t hdr_len,
			     const efx_dword_t *sdu, size_t sdu_len);
	bool (*mcdi_poll_response)(struct efx_nic *efx, u8 bufid);
	void (*mcdi_read_response)(struct efx_nic *efx, u8 bufid,
				   efx_dword_t *pdu, size_t pdu_offset,
				   size_t pdu_len);
	int (*mcdi_poll_reboot)(struct efx_nic *efx);
	void (*mcdi_record_bist_event)(struct efx_nic *efx);
	int (*mcdi_poll_bist_end)(struct efx_nic *efx);
	void (*mcdi_reboot_detected)(struct efx_nic *efx);
	bool (*mcdi_get_buf)(struct efx_nic *efx, u8 *bufid);
	void (*mcdi_put_buf)(struct efx_nic *efx, u8 bufid);
	void (*irq_enable_master)(struct efx_nic *efx);
	int (*irq_test_generate)(struct efx_nic *efx);
	void (*irq_disable_non_ev)(struct efx_nic *efx);
	irqreturn_t (*irq_handle_msi)(int irq, void *dev_id);
	int (*tx_probe)(struct efx_tx_queue *tx_queue);
	int (*tx_init)(struct efx_tx_queue *tx_queue);
	void (*tx_write)(struct efx_tx_queue *tx_queue);
	void (*tx_notify)(struct efx_tx_queue *tx_queue);
	int (*tx_enqueue)(struct efx_tx_queue *tx_queue, struct sk_buff *skb);
	unsigned int (*tx_limit_len)(struct efx_tx_queue *tx_queue,
				     dma_addr_t dma_addr, unsigned int len);
	unsigned int (*tx_max_skb_descs)(struct efx_nic *efx);
	int (*rx_push_rss_config)(struct efx_nic *efx, bool user,
				  const u32 *rx_indir_table, const u8 *key);
	int (*rx_pull_rss_config)(struct efx_nic *efx);
	int (*rx_push_rss_context_config)(struct efx_nic *efx,
					  struct efx_rss_context *ctx,
					  const u32 *rx_indir_table,
					  const u8 *key);
	int (*rx_pull_rss_context_config)(struct efx_nic *efx,
					  struct efx_rss_context *ctx);
	void (*rx_restore_rss_contexts)(struct efx_nic *efx);
	u32 (*rx_get_default_rss_flags)(struct efx_nic *efx);
	int (*rx_set_rss_flags)(struct efx_nic *efx, struct efx_rss_context *ctx,
				u32 flags);
	int (*rx_get_rss_flags)(struct efx_nic *efx, struct efx_rss_context *ctx);
	int (*rx_probe)(struct efx_rx_queue *rx_queue);
	int (*rx_init)(struct efx_rx_queue *rx_queue);
	void (*rx_remove)(struct efx_rx_queue *rx_queue);
	void (*rx_write)(struct efx_rx_queue *rx_queue);
	int (*rx_defer_refill)(struct efx_rx_queue *rx_queue);
	void (*rx_packet)(struct efx_rx_queue *rx_queue);
	bool (*rx_buf_hash_valid)(const u8 *prefix);
	int (*ev_probe)(struct efx_channel *channel);
	int (*ev_init)(struct efx_channel *channel);
	void (*ev_fini)(struct efx_channel *channel);
	void (*ev_remove)(struct efx_channel *channel);
	int (*ev_process)(struct efx_channel *channel, int quota);
	bool (*ev_mcdi_pending)(struct efx_channel *channel);
	void (*ev_read_ack)(struct efx_channel *channel);
	void (*ev_test_generate)(struct efx_channel *channel);
	unsigned int max_rx_ip_filters;
	int (*filter_table_probe)(struct efx_nic *efx);
	int (*filter_table_up)(struct efx_nic *efx);
	void (*filter_table_restore)(struct efx_nic *efx);
	void (*filter_table_down)(struct efx_nic *efx);
	void (*filter_table_remove)(struct efx_nic *efx);
	bool (*filter_match_supported)(struct efx_nic *efx, bool encap,
				       unsigned int match_flags);
	void (*filter_update_rx_scatter)(struct efx_nic *efx);
	s32 (*filter_insert)(struct efx_nic *efx,
			     const struct efx_filter_spec *spec, bool replace);
	int (*filter_remove_safe)(struct efx_nic *efx,
				  enum efx_filter_priority priority,
				  u32 filter_id);
	int (*filter_get_safe)(struct efx_nic *efx,
			       enum efx_filter_priority priority,
			       u32 filter_id, struct efx_filter_spec *);
	int (*filter_clear_rx)(struct efx_nic *efx,
			       enum efx_filter_priority priority);
	u32 (*filter_count_rx_used)(struct efx_nic *efx,
				    enum efx_filter_priority priority);
	u32 (*filter_get_rx_id_limit)(struct efx_nic *efx);
	s32 (*filter_get_rx_ids)(struct efx_nic *efx,
				 enum efx_filter_priority priority,
				 u32 *buf, u32 size);
#ifdef CONFIG_RFS_ACCEL
	bool (*filter_rfs_expire_one)(struct efx_nic *efx, u32 flow_id,
				      unsigned int index);
#endif
#ifdef EFX_NOT_UPSTREAM
	/**
	 * @filter_redirect: update the queue (and RSS context if not NULL)
	 *	for an existing RX filter
	 */
	int (*filter_redirect)(struct efx_nic *efx, u32 filter_id,
			       u32 *rss_context, int rxq_i, int stack_id);
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	/**
	 * @filter_block_kernel: Block kernel from receiving packets except
	 *	through explicit configuration, i.e. remove and disable
	 *	filters with priority < MANUAL
	 */
	int (*filter_block_kernel)(struct efx_nic *efx,
				   enum efx_dl_filter_block_kernel_type type);
	/**
	 * @filter_unblock_kernel: Unblock kernel, i.e. enable automatic
	 *	and hint filters
	 */
	void (*filter_unblock_kernel)(struct efx_nic *efx, enum
				      efx_dl_filter_block_kernel_type type);
#endif
#endif
	/** @regionmap_buffer: Check if buffer is in accessible region */
	int (*regionmap_buffer)(struct efx_nic *efx, dma_addr_t *dma_addr);
#ifdef CONFIG_SFC_MTD
	int (*mtd_probe)(struct efx_nic *efx);
	void (*mtd_rename)(struct efx_mtd_partition *part);
	int (*mtd_read)(struct mtd_info *mtd, loff_t start, size_t len,
			size_t *retlen, u8 *buffer);
	int (*mtd_erase)(struct mtd_info *mtd, loff_t start, size_t len);
	int (*mtd_write)(struct mtd_info *mtd, loff_t start, size_t len,
			 size_t *retlen, const u8 *buffer);
	int (*mtd_sync)(struct mtd_info *mtd);
#endif
#ifdef CONFIG_SFC_PTP
	void (*ptp_write_host_time)(struct efx_nic *efx, u32 host_time);
	int (*ptp_set_ts_sync_events)(struct efx_nic *efx, bool en, bool temp);
	int (*ptp_set_ts_config)(struct efx_nic *efx,
				 struct kernel_hwtstamp_config *init);
	int (*pps_reset)(struct efx_nic *efx);
#endif
	int (*vlan_rx_add_vid)(struct efx_nic *efx, __be16 proto, u16 vid);
	int (*vlan_rx_kill_vid)(struct efx_nic *efx, __be16 proto, u16 vid);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID)
	int (*get_phys_port_id)(struct efx_nic *efx,
				struct netdev_phys_item_id *ppid);
#endif
	int (*vport_add)(struct efx_nic *efx, u16 vlan, bool vlan_restrict,
			 unsigned int *port_id_out);
	int (*vport_del)(struct efx_nic *efx, unsigned int port_id);
	int (*sriov_init)(struct efx_nic *efx);
	void (*sriov_fini)(struct efx_nic *efx);
	bool (*sriov_wanted)(struct efx_nic *efx);
	int (*sriov_configure)(struct efx_nic *efx, int num_vfs);
	int (*sriov_set_vf_mac)(struct efx_nic *efx, int vf_i, const u8 *mac,
				bool *reset);
	int (*sriov_set_vf_vlan)(struct efx_nic *efx, int vf_i, u16 vlan,
				 u8 qos);
	int (*sriov_set_vf_spoofchk)(struct efx_nic *efx, int vf_i,
				     bool spoofchk);
	int (*sriov_get_vf_config)(struct efx_nic *efx, int vf_i,
				   struct ifla_vf_info *ivi);
	int (*sriov_set_vf_link_state)(struct efx_nic *efx, int vf_i,
				       int link_state);
	int (*vswitching_probe)(struct efx_nic *efx);
	int (*vswitching_restore)(struct efx_nic *efx);
	void (*vswitching_remove)(struct efx_nic *efx);
	int (*get_mac_address)(struct efx_nic *efx, unsigned char *perm_addr);
	int (*set_mac_address)(struct efx_nic *efx);
	unsigned int (*mcdi_rpc_timeout)(struct efx_nic *efx, unsigned int cmd);
	bool (*udp_tnl_has_port)(struct efx_nic *efx, __be16 port);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	int (*udp_tnl_push_ports)(struct efx_nic *efx);
#else
	void (*udp_tnl_push_ports)(struct efx_nic *efx);
	void (*udp_tnl_add_port)(struct efx_nic *efx, struct efx_udp_tunnel tnl);
	void (*udp_tnl_del_port)(struct efx_nic *efx, struct efx_udp_tunnel tnl);
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_TC_OFFLOAD) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
	/** @udp_tnl_add_port2: Add tunnel offload UDP port (EF100) */
	void (*udp_tnl_add_port2)(struct efx_nic *efx, struct ef100_udp_tunnel tnl);
	/** @udp_tnl_lookup_port2: Lookup tunnel offload UDP port (EF100) */
	enum efx_encap_type (*udp_tnl_lookup_port2)(struct efx_nic *efx, __be16 port);
	/** @udp_tnl_del_port2: Delete tunnel offload port (EF100) */
	void (*udp_tnl_del_port2)(struct efx_nic *efx, struct ef100_udp_tunnel tnl);
#endif
	struct net_device *(*get_vf_rep)(struct efx_nic *efx, unsigned int vf);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	void (*detach_reps)(struct efx_nic *efx);
	void (*attach_reps)(struct efx_nic *efx);
#endif
	int (*add_mport)(struct efx_nic *efx, struct mae_mport_desc *mport);
	void (*remove_mport)(struct efx_nic *efx, struct mae_mport_desc *mport);
	bool (*has_dynamic_sensors)(struct efx_nic *efx);
	unsigned int (*rx_recycle_ring_size)(const struct efx_nic *efx);

	int revision;
	unsigned int txd_ptr_tbl_base;
	unsigned int rxd_ptr_tbl_base;
	unsigned int buf_tbl_base;
	unsigned int evq_ptr_tbl_base;
	unsigned int evq_rptr_tbl_base;
	u64 max_dma_mask;
	unsigned int rx_prefix_size;
	unsigned int rx_hash_offset;
	unsigned int rx_ts_offset;
	unsigned int rx_buffer_padding;
	bool can_rx_scatter;
	bool always_rx_scatter;
	bool option_descriptors;
	bool copy_break;
	unsigned int supported_interrupt_modes;
	unsigned int timer_period_max;
#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	/**
	 * @ef10_resources: Resources to be shared via driverlink (copied
	 * and updated as struct efx_nic.ef10_resources).
	 */
	struct efx_dl_ef10_resources ef10_resources;
	/** @dl_hash_insertion: RX hash insertion details for driverlink */
	struct efx_dl_hash_insertion dl_hash_insertion;
#endif
#endif
	netdev_features_t offload_features;
	int mcdi_max_ver;
	u32 hwtstamp_filters;
	unsigned int rx_hash_key_size;
};

/**************************************************************************
 *
 * Prototypes and inline functions
 *
 *************************************************************************/

struct efx_channel *efx_get_channel(struct efx_nic *efx, unsigned int index);

/* Iterate over all used channels */
#define efx_for_each_channel(_channel, _efx)				\
	list_for_each_entry(_channel, &_efx->channel_list, list)

/* Iterate over all used channels in reverse */
#define efx_for_each_channel_rev(_channel, _efx)			\
	list_for_each_entry_reverse(_channel, &_efx->channel_list, list)

static inline struct efx_channel *
efx_get_tx_channel(struct efx_nic *efx, unsigned int index)
{
	EFX_WARN_ON_ONCE_PARANOID(index >= efx_tx_channels(efx));
	return efx_get_channel(efx, efx->tx_channel_offset + index);
}

static inline struct efx_channel *
efx_get_xdp_channel(struct efx_nic *efx, unsigned int index)
{
	EFX_WARN_ON_ONCE_PARANOID(index >= efx->n_xdp_channels);
	return efx_get_channel(efx, efx_xdp_channel_offset(efx) + index);
}

static inline struct efx_channel *
efx_get_rx_queue_channel(struct efx_rx_queue *rx_queue)
{
	struct efx_channel *channel = container_of(rx_queue,
						   struct efx_channel,
						   rx_queue);
	return channel;
}

static inline bool efx_channel_has_tx_queues(struct efx_channel *channel)
{
	return channel->channel - channel->efx->tx_channel_offset <
	       efx_tx_channels(channel->efx);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
static inline struct efx_tx_queue *
efx_channel_get_xsk_tx_queue(struct efx_channel *channel)
{
	if (unlikely(channel->tx_queue_count <= 1))
		return NULL;

	/* The Last TX queue is used for XSK Transmits */
	return channel->tx_queues + (channel->tx_queue_count - 1);
}

static inline bool efx_is_xsk_tx_queue(struct efx_tx_queue *tx_queue)
{
	return (tx_queue->channel->tx_queue_count > 1 &&
		tx_queue->label == (tx_queue->channel->tx_queue_count - 1));
}
#endif
#endif

static inline struct efx_tx_queue *
efx_channel_get_tx_queue(struct efx_channel *channel, unsigned int label)
{
	if (unlikely(label > channel->tx_queue_count)) {
		netif_err(channel->efx, drv, channel->efx->net_dev,
			  "Queue label %d out of range on channel %d (max %d)\n",
			  label, channel->channel, channel->tx_queue_count);
		return NULL;
	}

	return channel->tx_queues + label;
}

static inline struct efx_tx_queue *
efx_get_tx_queue_from_index(struct efx_nic *efx, unsigned int index)
{
	struct efx_channel *channel;

	if (index < efx_tx_channels(efx) * efx->tx_queues_per_channel) {
		channel = efx_get_tx_channel(efx,
					     index / efx->tx_queues_per_channel);
		index %= efx->tx_queues_per_channel;
		return efx_channel_get_tx_queue(channel, index);
	}

	index -= efx_tx_channels(efx) * efx->tx_queues_per_channel;
	if (index < efx->n_xdp_channels * efx->xdp_tx_per_channel) {
		channel = efx_get_xdp_channel(efx,
					      index / efx->xdp_tx_per_channel);
		index %= efx->xdp_tx_per_channel;
		return efx_channel_get_tx_queue(channel, index);
	}

	return NULL;
}

/* Iterate over all TX queues belonging to a channel */
#define efx_for_each_channel_tx_queue(_tx_queue, _channel)		 \
	if (!_channel || !(_channel)->tx_queues)			 \
		;							 \
	else								 \
		for (_tx_queue = (_channel)->tx_queues;			 \
		     _tx_queue < (_channel)->tx_queues +		 \
				 (_channel)->tx_queue_count;	 \
		     _tx_queue++)

static inline bool efx_channel_has_rx_queue(struct efx_channel *channel)
{
	return channel && channel->rx_queue.core_index >= 0;
}

static inline struct efx_rx_queue *
efx_channel_get_rx_queue(struct efx_channel *channel)
{
	EFX_WARN_ON_ONCE_PARANOID(!efx_channel_has_rx_queue(channel));
	return &channel->rx_queue;
}

/* Iterate over all RX queues belonging to a channel */
#define efx_for_each_channel_rx_queue(_rx_queue, _channel)		\
	if (!efx_channel_has_rx_queue(_channel))			\
		;							\
	else								\
		for (_rx_queue = &(_channel)->rx_queue;			\
		     _rx_queue;						\
		     _rx_queue = NULL)

static inline bool efx_channel_is_xdp_tx(struct efx_channel *channel)
{
	return channel->channel - efx_xdp_channel_offset(channel->efx) <
	       efx_xdp_channels(channel->efx);
}

/* Name formats */
#define EFX_CHANNEL_NAME(_channel) "chan%d", (_channel)->channel
#define EFX_TX_QUEUE_NAME(_tx_queue) "txq%d", (_tx_queue)->queue
#define EFX_RX_QUEUE_NAME(_rx_queue) "rxq%d", efx_rx_queue_index(_rx_queue)

static inline struct efx_channel *
efx_rx_queue_channel(struct efx_rx_queue *rx_queue)
{
	return container_of(rx_queue, struct efx_channel, rx_queue);
}

/* Software index of the RX queue, meaningful to the driver.
 * Not necessarily related to hardware RXQ number in any way.
 */
static inline int efx_rx_queue_index(struct efx_rx_queue *rx_queue)
{
	return rx_queue->label;
}

/* Hardware RXQ instance number.  Relative VI number of the VI backing
 * this RX queue.
 */
static inline int efx_rx_queue_instance(struct efx_rx_queue *rx_queue)
{
	return rx_queue->queue;
}

/* Returns a pointer to the specified receive buffer in the RX
 * descriptor queue.
 */
static inline struct efx_rx_buffer *efx_rx_buffer(struct efx_rx_queue *rx_queue,
						  unsigned int index)
{
	return &rx_queue->buffer[index];
}

/* Returns a pointer to the receive buffer waiting in the RX pipeline */
static inline struct efx_rx_buffer *efx_rx_buf_pipe(struct efx_rx_queue *rx_queue)
{
	return efx_rx_buffer(rx_queue, rx_queue->rx_pkt_index);
}

static inline struct efx_rx_buffer *
efx_rx_buf_next(struct efx_rx_queue *rx_queue, struct efx_rx_buffer *rx_buf)
{
        if (unlikely(rx_buf == efx_rx_buffer(rx_queue, rx_queue->ptr_mask)))
                return efx_rx_buffer(rx_queue, 0);
        else
                return rx_buf + 1;
}

/**
 * EFX_MAX_FRAME_LEN - calculate maximum frame length
 * @mtu: maximum transmission unit (ethernet frame payload size).
 *
 * This calculates the maximum frame length that will be used for a
 * given MTU.  The frame length will be equal to the MTU plus a
 * constant amount of header space and padding.  This is the quantity
 * that the net driver will program into the MAC as the maximum frame
 * length.
 *
 * The 10G MAC requires 8-byte alignment on the frame
 * length, so we round up to the nearest 8.
 *
 * Re-clocking by the XGXS on RX can reduce an IPG to 32 bits (half an
 * XGMII cycle).  If the frame length reaches the maximum value in the
 * same cycle, the XMAC can miss the IPG altogether.  We work around
 * this by adding a further 16 bytes.
 */
#define EFX_MAX_FRAME_LEN(mtu) \
	((((mtu) + ETH_HLEN + VLAN_HLEN + 4/* FCS */ + 7) & ~7) + 16)

/*
 * WARNING: This calculation must match with the value of page_offset
 * calculated in efx_init_rx_buffer().
 */
static inline size_t efx_rx_buffer_step(struct efx_nic *efx)
{
	return ALIGN(sizeof(struct efx_rx_page_state) + XDP_PACKET_HEADROOM +
		     efx->rx_dma_len + efx->rx_ip_align, EFX_RX_BUF_ALIGNMENT);
}

static inline bool efx_xmit_with_hwtstamp(struct sk_buff *skb)
{
	return skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP;
}
static inline void efx_xmit_hwtstamp_pending(struct sk_buff *skb)
{
	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
}

/* Get the max fill level of the TX queues on this channel */
static inline unsigned int
efx_channel_tx_fill_level(struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	unsigned int fill_level = 0;

	efx_for_each_channel_tx_queue(tx_queue, channel)
		fill_level = max(fill_level,
				 tx_queue->insert_count - tx_queue->read_count);

	return fill_level;
}

/* Conservative approximation of efx_channel_tx_fill_level using cached value */
static inline unsigned int
efx_channel_tx_old_fill_level(struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	unsigned int fill_level = 0;

	efx_for_each_channel_tx_queue(tx_queue, channel)
		fill_level = max(fill_level,
				 tx_queue->insert_count - tx_queue->old_read_count);

	return fill_level;
}

/* Get all supported features.
 * If a feature is not fixed, it is present in hw_features.
 * If a feature is fixed, it does not present in hw_features, but
 * always in features.
 */
static inline netdev_features_t efx_supported_features(const struct efx_nic *efx)
{
	const struct net_device *net_dev = efx->net_dev;

	return net_dev->features | net_dev->hw_features;
}

/* Get the current TX queue insert index. */
static inline unsigned int
efx_tx_queue_get_insert_index(const struct efx_tx_queue *tx_queue)
{
	return tx_queue->insert_count & tx_queue->ptr_mask;
}

/* Get a TX buffer. */
static inline struct efx_tx_buffer *
__efx_tx_queue_get_insert_buffer(const struct efx_tx_queue *tx_queue)
{
	return &tx_queue->buffer[efx_tx_queue_get_insert_index(tx_queue)];
}

/* Get a TX buffer, checking it's not currently in use. */
static inline struct efx_tx_buffer *
efx_tx_queue_get_insert_buffer(const struct efx_tx_queue *tx_queue)
{
	struct efx_tx_buffer *buffer =
		__efx_tx_queue_get_insert_buffer(tx_queue);

	EFX_WARN_ON_ONCE_PARANOID(buffer->len);
	EFX_WARN_ON_ONCE_PARANOID(buffer->flags);
	EFX_WARN_ON_ONCE_PARANOID(buffer->unmap_len);

	return buffer;
}

#endif /* EFX_NET_DRIVER_H */
