/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides API of the efhw library which may be used both from
 * the kernel and from the user-space code.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#ifndef __CI_EFHW_COMMON_H__
#define __CI_EFHW_COMMON_H__

#include <ci/efhw/common_sysdep.h>
#include <ci/efhw/device.h>

typedef uint32_t efhw_buffer_addr_t;
#define EFHW_BUFFER_ADDR_FMT	"[ba:%"PRIx32"]"

/* Below event structure is in NIC bytes order. When using either field for
 * something other then check against 0xffff one should convert the event
 * into CPU byte order.  Normally this is done in the HW-specific macros */

/*! Comment? */
typedef union {
	uint64_t u64;
	struct {
		uint32_t a;
		uint32_t b;
	} opaque;
} efhw_event_t;

/* Flags for TX/RX queues */
#define EFHW_VI_JUMBO_EN           0x01    /*! scatter RX over multiple desc */
#define EFHW_VI_RX_ZEROCOPY        0x02    /*! Zerocopy for AF_XDP */
#define EFHW_VI_ENABLE_TPH         0x08    /*! PCIe TPH steering hints */
#define EFHW_VI_TX_PHYS_ADDR_EN    0x20    /*! TX physical address mode */
#define EFHW_VI_RX_PHYS_ADDR_EN    0x40    /*! RX physical address mode */
#define EFHW_VI_TX_IP_CSUM_DIS     0x100   /*! enable ip checksum generation */
#define EFHW_VI_TX_TCPUDP_CSUM_DIS 0x200   /*! enable tcp/udp checksum
					       generation */
#define EFHW_VI_TX_TCPUDP_ONLY     0x400   /*! drop non-tcp/udp packets */
#define EFHW_VI_TX_IP_FILTER_EN    0x800   /*! TX IP filtering */
#define EFHW_VI_TX_ETH_FILTER_EN   0x1000  /*! TX MAC filtering */
#define EFHW_VI_TX_Q_MASK_WIDTH_0  0x2000  /*! TX filter q_mask_width bit 0 */
#define EFHW_VI_TX_Q_MASK_WIDTH_1  0x4000  /*! TX filter q_mask_width bit 1 */
#define EFHW_VI_RX_HDR_SPLIT       0x8000  /*! RX header split */
#define EFHW_VI_RX_PREFIX          0x10000  /*! RX prefix */
#define EFHW_VI_RX_TIMESTAMPS      0x20000  /*! RX timestamping */
#define EFHW_VI_TX_TIMESTAMPS      0x40000  /*! TX timestamping */
#define EFHW_VI_TX_LOOPBACK        0x80000  /*! loopback outgoing traffic */
#define EFHW_VI_RX_LOOPBACK        0x100000  /*! receive loopback traffic */
/* Event cut through must be disabled for RX merging to occur.
 * Event cut through must be enabled for the best latency.
 */
#define EFHW_VI_NO_EV_CUT_THROUGH  0x200000  /*! Disable event cut-through */
#define EFHW_VI_RX_PACKED_STREAM   0x400000  /*! Packed stream mode */
/* For RX merging to occur received packets must be processed in store and
 * forward mode, to enable the length to be added to the packet prefix.  This
 * setting forces processing as store and forward, even in cases where it
 * would not otherwise happen.
 */
#define EFHW_VI_NO_RX_CUT_THROUGH  0x800000  /*! Disable RX cut-through */
/* This enables multiple RX packets to be completed via a single RX event.
 * Whether this actually occurs depends on what happens on the RX datapath
 * (see EFHW_VI_NO_RX_CUT_THROUGH).
 */
#define EFHW_VI_ENABLE_RX_MERGE    0x1000000  /*! Enable RX event merging */
#define EFHW_VI_ENABLE_EV_TIMER    0x2000000  /*! Enable hardware event timer */
#define EFHW_VI_TX_ALT             0x4000000  /*! Provision for alternatives */
#define EFHW_VI_TX_CTPIO           0x8000000  /*! Cut-through PIO */
#define EFHW_VI_TX_CTPIO_NO_POISON 0x10000000 /*! Prevent CTPIO poisoning */

/* Note that the EFRM_VI_* flags (0x20000000 and above) are stored in
 * the same word and so no more bits are available for use as new
 * EFHW_VI_* flags. */

#define HIGH_THROUGHPUT_EFHW_VI_FLAGS (EFHW_VI_RX_PREFIX | \
				       EFHW_VI_NO_EV_CUT_THROUGH | \
				       EFHW_VI_NO_RX_CUT_THROUGH | \
				       EFHW_VI_ENABLE_RX_MERGE)

/* Flags indicating effective setings determined at queue
 * allocation/enabling.  Unfortunately these flags are exposed through the
 * userlevel/char interface, so there are flags here that really should not
 * be...
 */
#define EFHW_VI_CLOCK_SYNC_STATUS  0x01  /*! sync status reporting */
#define EFHW_VI_PS_BUF_SIZE_SET    0x02  /*! ps_buf_size field is set */
#define EFHW_VI_ABS_IDX_SET        0x04  /*! abs idx field is valid */
#define EFHW_VI_POST_BUF_SIZE_SET  0x08  /*! rx_post_buffer_mmap_bytes is set */

/* Flags for hw features */
#define EFHW_VI_NIC_BUG35388_WORKAROUND 0x01  /*! workaround for bug35388 */
#define EFHW_VI_NIC_CTPIO_ONLY          0x02  /*! TX only using CTPIO */
#define EFHW_VI_NIC_RX_SHARED           0x04  /*! RX filters are lower bound */
#define EFHW_VI_NIC_RX_MCAST_REPLICATION 0x08 /*! RX mcast replication */
#define EFHW_VI_NIC_IRQ                 0x10  /*! onload IRQ */

/* Types of hardware filter */
/* Each of these values implicitly selects scatter filters on B0 - or in
   EFHW_IP_FILTER_TYPE_NOSCAT_B0_MASK if a non-scatter filter is required */
#define EFHW_IP_FILTER_TYPE_UDP_WILDCARD  (0)	/* dest host only */
#define EFHW_IP_FILTER_TYPE_UDP_FULL      (1)	/* dest host and port */
#define EFHW_IP_FILTER_TYPE_TCP_WILDCARD  (2)	/* dest based filter */
#define EFHW_IP_FILTER_TYPE_TCP_FULL      (3)	/* src  filter */
/* Same again, but with RSS (for B0 only) */
#define EFHW_IP_FILTER_TYPE_UDP_WILDCARD_RSS_B0  (4)
#define EFHW_IP_FILTER_TYPE_UDP_FULL_RSS_B0      (5)
#define EFHW_IP_FILTER_TYPE_TCP_WILDCARD_RSS_B0  (6)
#define EFHW_IP_FILTER_TYPE_TCP_FULL_RSS_B0      (7)

#define EFHW_IP_FILTER_TYPE_FULL_MASK      (0x1) /* Mask for full / wildcard */
#define EFHW_IP_FILTER_TYPE_TCP_MASK       (0x2) /* Mask for TCP type */
#define EFHW_IP_FILTER_TYPE_RSS_B0_MASK    (0x4) /* Mask for B0 RSS enable */
#define EFHW_IP_FILTER_TYPE_NOSCAT_B0_MASK (0x8) /* Mask for B0 SCATTER dsbl */

#define EFHW_IP_FILTER_TYPE_MASK	(0xffff) /* Mask of types above */

#define EFHW_IP_FILTER_BROADCAST	(0x10000) /* driverlink filter
						     support */

/* RSS context hash flags - Huntington */

#define EFHW_RSS_FLAG_SRC_ADDR 0x1
#define EFHW_RSS_FLAG_DST_ADDR 0x2
#define EFHW_RSS_FLAG_SRC_PORT 0x4
#define EFHW_RSS_FLAG_DST_PORT 0x8

/* NIC's page size information */

#define EFHW_1K		0x00000400u
#define EFHW_2K		0x00000800u
#define EFHW_4K		0x00001000u
#define EFHW_8K		0x00002000u
#define EFHW_16K	0x00004000u
#define EFHW_32K	0x00008000u
#define EFHW_64K	0x00010000u
#define EFHW_128K	0x00020000u
#define EFHW_256K	0x00040000u
#define EFHW_512K	0x00080000u
#define EFHW_1M		0x00100000u
#define EFHW_2M		0x00200000u
#define EFHW_4M		0x00400000u
#define EFHW_8M		0x00800000u
#define EFHW_16M	0x01000000u
#define EFHW_32M	0x02000000u
#define EFHW_48M	0x03000000u
#define EFHW_64M	0x04000000u
#define EFHW_128M	0x08000000u
#define EFHW_256M	0x10000000u
#define EFHW_512M	0x20000000u
#define EFHW_1G 	0x40000000u
#define EFHW_2G		0x80000000u
#define EFHW_4G		0x100000000ULL
#define EFHW_8G		0x200000000ULL

/* --- DMA --- */
#define EFHW_DMA_ADDRMASK		(0xffffffffffffffffULL)

#define EFHW_IP_FILTER_NUM		8192

#define EFHW_NIC_PAGE_SIZE  EFHW_4K
#define EFHW_NIC_PAGE_SHIFT 12

#define EFHW_NIC_PAGE_MASK (~(EFHW_NIC_PAGE_SIZE-1))


/* --- NIC-feature flags --- */
#define NIC_FLAG_BUG35388_WORKAROUND 0x80
#define NIC_FLAG_MCAST_LOOP_HW 0x100
#define NIC_FLAG_14BYTE_PREFIX 0x200
#define NIC_FLAG_PACKED_STREAM 0x400
#define NIC_FLAG_RX_RSS_LIMITED 0x800
#define NIC_FLAG_VAR_PACKED_STREAM 0x1000
#define NIC_FLAG_ADDITIONAL_RSS_MODES 0x2000
#define NIC_FLAG_PIO 0x4000
#define NIC_FLAG_HW_MULTICAST_REPLICATION 0x8000
#define NIC_FLAG_HW_RX_TIMESTAMPING 0x10000
#define NIC_FLAG_HW_TX_TIMESTAMPING 0x20000
#define NIC_FLAG_VPORTS 0x40000
#define NIC_FLAG_PHYS_MODE 0x80000
#define NIC_FLAG_BUFFER_MODE 0x100000
#define NIC_FLAG_MULTICAST_FILTER_CHAINING 0x200000
#define NIC_FLAG_MAC_SPOOFING 0x400000
#define NIC_FLAG_ZERO_RX_PREFIX 0x1000000000LL
#define NIC_FLAG_NIC_PACE 0x2000000000LL
#define NIC_FLAG_RX_MERGE 0x4000000000LL
#define NIC_FLAG_TX_ALTERNATIVES 0x8000000000LL
#define NIC_FLAG_EVQ_V2 0x10000000000LL
#define NIC_FLAG_TX_CTPIO 0x20000000000LL
#define NIC_FLAG_RX_FORCE_EVENT_MERGING 0x40000000000LL
#define NIC_FLAG_EVENT_CUT_THROUGH 0x80000000000LL
#define NIC_FLAG_RX_CUT_THROUGH 0x100000000000LL
#define NIC_FLAG_RX_ZEROCOPY 0x200000000000LL
#define NIC_FLAG_PHYS_CONTIG_EVQ 0x400000000000LL
#define NIC_FLAG_PHYS_CONTIG_TXQ 0x800000000000LL
#define NIC_FLAG_PHYS_CONTIG_RXQ 0x1000000000000LL
/* Use a dedicated irq rather than wakeups on this NIC
 * This reflects what we do rather than the underlying HW capabilities as
 * currently we have no arch where we sometimes use wakeups and sometimes use
 * irqs. */
#define NIC_FLAG_EVQ_IRQ 0x2000000000000LL
/* The only supported TX mode is CTPIO */
#define NIC_FLAG_CTPIO_ONLY 0x4000000000000LL
/* A physical RX queue might be shared with other entities e.g. kernel stack or VIs of other apps.
 * The implications are that applications should:
 *  * expect traffic that has not been requested through their explicit HW filter installation,
 *  * ignore such unsolicited traffic as it is handled by other parties.
 */
#define NIC_FLAG_RX_SHARED 0x8000000000000LL
/* Multicast replication of incoming packets is implemented in the NIC */
#define NIC_FLAG_RX_MCAST_REPLICATION 0x10000000000000LL
/*! ef_vi_prime() runs entirely in userspace */
#define NIC_FLAG_USERSPACE_PRIME 0x20000000000000LL
/* A protection domain and associated buffer allocation can be shared between
   vis. */
#define NIC_FLAG_SHARED_PD 0x40000000000000LL
#define NIC_FLAG_LLCT 0x100000000000000LL

/* Filter type flags */
#define NIC_FILTER_FLAG_RX_TYPE_IP_LOCAL 0x1
#define NIC_FILTER_FLAG_RX_TYPE_IP_FULL 0x2
#define NIC_FILTER_FLAG_RX_TYPE_IP6 0x4
#define NIC_FILTER_FLAG_RX_TYPE_ETH_LOCAL 0x10
#define NIC_FILTER_FLAG_RX_TYPE_ETH_LOCAL_VLAN 0x20
#define NIC_FILTER_FLAG_RX_TYPE_UCAST_ALL 0x40
#define NIC_FILTER_FLAG_RX_TYPE_MCAST_ALL 0x80
#define NIC_FILTER_FLAG_RX_TYPE_UCAST_MISMATCH 0x100
#define NIC_FILTER_FLAG_RX_TYPE_MCAST_MISMATCH 0x200
#define NIC_FILTER_FLAG_RX_TYPE_SNIFF 0x400
#define NIC_FILTER_FLAG_TX_TYPE_SNIFF 0x800
#define NIC_FILTER_FLAG_RX_IP4_PROTO 0x1000
#define NIC_FILTER_FLAG_RX_ETHERTYPE 0x2000
#define NIC_FILTER_FLAG_RX_MAC_IP4_PROTO 0x4000
#define NIC_FILTER_FLAG_IPX_VLAN_HW 0x8000
/* The SW filter flags indicate capabilities that are replicated in SW in the
 * efhw layer rather than provided in HW by the NIC. */
#define NIC_FILTER_FLAG_IPX_VLAN_SW 0x10000
#define NIC_FILTER_FLAG_IP_FULL_SW 0x20000

/* Reserved space in evq for a reasonable number of time sync events.
 * They arrive at a rate of 4 per second.  This allows app to get
 * 25s behind...
 */
#define CI_CFG_TIME_SYNC_EVENT_EVQ_CAPACITY (4 * 25)

#endif /* __CI_EFHW_COMMON_H__ */
