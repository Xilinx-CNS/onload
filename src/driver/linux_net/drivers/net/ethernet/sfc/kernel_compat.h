/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_KERNEL_COMPAT_H
#define EFX_KERNEL_COMPAT_H

#include <linux/version.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/sysfs.h>
#include <linux/stringify.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/cpumask.h>
#include <linux/topology.h>
#include <linux/ethtool.h>
#include <linux/vmalloc.h>
#include <linux/if_vlan.h>
#include <linux/time.h>
#include <linux/bitops.h>
#include <linux/jhash.h>
#include <linux/ktime.h>
#include <linux/ctype.h>
#include <linux/aer.h>
#ifdef CONFIG_SFC_MTD
/* This is conditional because it's fairly disgusting */
#include "linux_mtd_mtd.h"
#endif
#include <asm/byteorder.h>
#include <net/ip.h>

/**************************************************************************
 *
 * Autoconf compatability
 *
 **************************************************************************/

#include "autocompat.h"

#ifdef KMP_RELEASE
#include "kabi_compat.h"
#endif

/**************************************************************************
 *
 * Resolve conflicts between feature switches and compatibility flags
 *
 **************************************************************************/

#ifndef EFX_HAVE_GRO
	#undef EFX_USE_GRO
#endif

#ifdef CONFIG_SFC_PRIVATE_MDIO
	#undef EFX_HAVE_LINUX_MDIO_H
#endif

/**************************************************************************
 *
 * Version/config/architecture compatability.
 *
 **************************************************************************
 *
 * The preferred kernel compatability mechanism is through the autoconf
 * layer above. The following definitions are all deprecated
 */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
	#error "This kernel version is now unsupported"
#endif

/* netif_device_{detach,attach}() were missed in multiqueue transition */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
	#define EFX_NEED_NETIF_DEVICE_DETACH_ATTACH_MQ yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33) && defined(EFX_HAVE_LINUX_MDIO_H)
	/* mdio module lacks pause frame advertising */
	#define EFX_NEED_MDIO45_FLOW_CONTROL_HACKS yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36) && \
	!defined(EFX_NEED_UNMASK_MSIX_VECTORS)
	/* Fixing that bug introduced a different one, fixed in 2.6.36 */
	#define EFX_NEED_SAVE_MSIX_MESSAGES yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20) && defined(CONFIG_PPC_ISERIES)
	/* __raw_writel and friends were broken on iSeries */
	#define EFX_NEED_RAW_READ_AND_WRITE_FIX yes
#endif

/**************************************************************************
 *
 * Definitions of missing constants, types, functions and macros
 *
 **************************************************************************
 *
 */

#ifndef spin_trylock_irqsave
	#define spin_trylock_irqsave(lock, flags)	\
	({						\
		local_irq_save(flags);			\
		spin_trylock(lock) ?			\
		1 : ({local_irq_restore(flags); 0;});	\
	})
#endif

#ifndef raw_smp_processor_id
	#define raw_smp_processor_id() (current_thread_info()->cpu)
#endif

#ifndef fallthrough
#ifdef __has_attribute
#ifndef __GCC4_has_attribute___fallthrough__
#define __GCC4_has_attribute___fallthrough__	0
#endif
#if __has_attribute(__fallthrough__)
# define fallthrough                    __attribute__((__fallthrough__))
#else
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif
#else
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif
#endif

#ifndef NETIF_F_CSUM_MASK
#ifdef NETIF_F_IPV6_CSUM
	#define NETIF_F_CSUM_MASK \
		(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_HW_CSUM)
#else
	#define NETIF_F_CSUM_MASK \
		(NETIF_F_IP_CSUM | NETIF_F_HW_CSUM)
#endif
#endif

#ifdef NETIF_F_RXHASH
	#define EFX_HAVE_RXHASH_SUPPORT yes
#else
	/* This reduces the need for #ifdefs */
	#define NETIF_F_RXHASH 0
	#define ETH_FLAG_RXHASH 0
#endif

/* Older kernel versions assume that a device with the NETIF_F_NTUPLE
 * feature implements ethtool_ops::set_rx_ntuple, which is not the
 * case in this driver.  If we enable this feature on those kernel
 * versions, 'ethtool -U' will crash.  Therefore we prevent the
 * feature from being set even if it is defined, unless this is a safe
 * version: Linux 3.0+ or RHEL 6 with backported RX NFC and ARFS
 * support.
 */
#if !defined(NETIF_F_NTUPLE) || (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0) && !(defined(RHEL_MAJOR) && RHEL_MAJOR == 6))
	#undef NETIF_F_NTUPLE
	#define NETIF_F_NTUPLE 0
	#undef ETH_FLAG_NTUPLE
	#define ETH_FLAG_NTUPLE 0
#endif

#ifndef NETIF_F_RXCSUM
	/* This reduces the need for #ifdefs */
	#define NETIF_F_RXCSUM 0
#endif

/* This reduces the need for #ifdefs */
#ifndef NETIF_F_TSO6
	#define NETIF_F_TSO6 0
#endif
#ifndef NETIF_F_TSO_ECN
	#define NETIF_F_TSO_ECN 0
#endif
#ifndef NETIF_F_ALL_TSO
	#define NETIF_F_ALL_TSO (NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_TSO_ECN)
#endif

#ifndef NETIF_F_GSO_GRE
	#define NETIF_F_GSO_GRE 0
#endif
#ifndef NETIF_F_GSO_GRE_CSUM
	#define NETIF_F_GSO_GRE_CSUM 0
#endif
#ifndef NETIF_F_GSO_UDP_TUNNEL
	#define NETIF_F_GSO_UDP_TUNNEL 0
#endif
#ifndef NETIF_F_GSO_UDP_TUNNEL_CSUM
	#define NETIF_F_GSO_UDP_TUNNEL_CSUM 0
#endif
#ifndef EFX_HAVE_GSO_UDP_TUNNEL
	#define SKB_GSO_UDP_TUNNEL	0
#endif
#ifndef EFX_HAVE_GSO_UDP_TUNNEL_CSUM
	#define SKB_GSO_UDP_TUNNEL_CSUM	0
#endif

#ifndef NETIF_F_RXFCS
	#define NETIF_F_RXFCS 0
#endif
#ifndef NETIF_F_RXALL
	#define NETIF_F_RXALL 0
#endif

/* RHEL 6.2 introduced XPS support but didn't add it under CONFIG_XPS.
 * Instead the code was simply included directly, so it's enabled in all
 * configurations. We check for the presence of CONFIG_XPS in other code.
 */
#if (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)) && \
    defined(RHEL_MAJOR) && (RHEL_MAJOR == 6) &&  \
    defined(RHEL_MINOR) && (RHEL_MINOR >= 2)
# define CONFIG_XPS
#endif

/* Cope with small changes in PCI constants between minor kernel revisions */
#if PCI_X_STATUS != 4
	#undef PCI_X_STATUS
	#define PCI_X_STATUS 4
	#undef PCI_X_STATUS_MAX_SPLIT
	#define PCI_X_STATUS_MAX_SPLIT 0x03800000
#endif

#ifndef __GFP_COMP
	#define __GFP_COMP 0
#endif

#ifndef __iomem
	#define __iomem
#endif

#ifndef PCI_EXP_FLAGS
	#define PCI_EXP_FLAGS		2	/* Capabilities register */
	#define PCI_EXP_FLAGS_TYPE	0x00f0	/* Device/Port type */
	#define  PCI_EXP_TYPE_ENDPOINT	0x0	/* Express Endpoint */
	#define  PCI_EXP_TYPE_LEG_END	0x1	/* Legacy Endpoint */
	#define  PCI_EXP_TYPE_ROOT_PORT 0x4	/* Root Port */
#endif

#ifndef PCI_EXP_DEVCAP
	#define PCI_EXP_DEVCAP		4	/* Device capabilities */
	#define  PCI_EXP_DEVCAP_PAYLOAD	0x07	/* Max_Payload_Size */
	#define  PCI_EXP_DEVCAP_PWR_VAL	0x3fc0000 /* Slot Power Limit Value */
	#define  PCI_EXP_DEVCAP_PWR_SCL	0xc000000 /* Slot Power Limit Scale */
#endif

#ifndef PCI_EXP_DEVCTL
	#define PCI_EXP_DEVCTL		8	/* Device Control */
	#define  PCI_EXP_DEVCTL_PAYLOAD	0x00e0	/* Max_Payload_Size */
	#define  PCI_EXP_DEVCTL_READRQ	0x7000	/* Max_Read_Request_Size */
#endif

#ifndef PCI_EXP_LNKSTA
	#define PCI_EXP_LNKSTA		18	/* Link Status */
#endif
#ifndef PCI_EXP_LNKSTA_CLS
	#define  PCI_EXP_LNKSTA_CLS	0x000f	/* Current Link Speed */
#endif
#ifndef PCI_EXP_LNKSTA_NLW
	#define  PCI_EXP_LNKSTA_NLW	0x03f0	/* Nogotiated Link Width */
#endif
#ifndef PCI_EXP_LNKCAP_MLW
	#define  PCI_EXP_LNKCAP_MLW     0x000003f0 /* Maximum Link Width */
#endif
#ifndef PCI_EXP_LNKCAP_SLS_5_0GB
	#define  PCI_EXP_LNKCAP_SLS_5_0GB 0x00000002 /* LNKCAP2 SLS bit 1 */
#endif
#ifndef PCI_EXP_LNKCAP2
	#define PCI_EXP_LNKCAP2         44      /* Link Capabilities 2 */
#endif
#ifndef PCI_EXP_LNKCAP2_SLS_8_0GB
	#define  PCI_EXP_LNKCAP2_SLS_8_0GB  0x00000008 /* Supported 8.0GT/s */
#endif

#ifndef PCI_VENDOR_ID_SOLARFLARE
	#define PCI_VENDOR_ID_SOLARFLARE	0x1924
	#define PCI_DEVICE_ID_SOLARFLARE_SFC4000A_0	0x0703
	#define PCI_DEVICE_ID_SOLARFLARE_SFC4000A_1	0x6703
	#define PCI_DEVICE_ID_SOLARFLARE_SFC4000B	0x0710
#endif

#ifndef PCI_EXT_CAP_ID_VNDR
	#define PCI_EXT_CAP_ID_VNDR 0x0B
#endif

#ifndef __force
	#define __force
#endif

#if !defined(for_each_cpu_mask) && !defined(CONFIG_SMP)
	#define for_each_cpu_mask(cpu, mask)            \
		for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#endif

#ifndef IRQF_SHARED
	#define IRQF_SHARED	   SA_SHIRQ
#endif

#ifndef CHECKSUM_PARTIAL
	#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif

#ifndef DMA_BIT_MASK
	#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

#if defined(__GNUC__) && !defined(inline)
	#define inline inline __attribute__ ((always_inline))
#endif

#if defined(__GNUC__) && !defined(__packed)
	#define __packed __attribute__((packed))
#endif

#if defined(__GNUC__) && !defined(__aligned)
	#define __aligned(x) __attribute__((aligned(x)))
#endif

#ifndef DIV_ROUND_UP
	#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#if !defined(round_up) && !defined(round_down) && !defined(__round_mask)
/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#endif

#ifndef __ATTR
	#define __ATTR(_name, _mode, _show, _store) {			\
		.attr = {.name = __stringify(_name), .mode = _mode },	\
		.show   = _show,					\
		.store  = _store,					\
	}
#endif

#ifndef DEVICE_ATTR
	#define DEVICE_ATTR(_name, _mode, _show, _store)		\
		struct device_attribute dev_attr_ ## _name =		\
			__ATTR(_name, _mode, _show, _store)
#endif

#ifndef DEVICE_ATTR_RO
#define DEVICE_ATTR_RO(_name)  DEVICE_ATTR(_name, 0444, _name##_show, NULL)
#endif
#ifndef DEVICE_ATTR_RW
#define DEVICE_ATTR_RW(_name)  DEVICE_ATTR(_name, 0644, _name##_show, \
					   _name##_store)
#endif

#ifndef sysfs_attr_init
	#define sysfs_attr_init(attr) do {} while (0)
#endif

#if defined(CONFIG_X86) && !defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#endif

#ifndef BUILD_BUG_ON_ZERO
	#define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)
#endif

#ifndef __bitwise
	#define __bitwise
#endif

#ifndef VLAN_PRIO_MASK
	#define VLAN_PRIO_MASK          0xe000
#endif
#ifndef VLAN_PRIO_SHIFT
	#define VLAN_PRIO_SHIFT         13
#endif

#ifndef SIOCGHWTSTAMP
	#define SIOCGHWTSTAMP	0x89b1
#endif

#ifdef EFX_NEED_UINTPTR_T
    typedef unsigned long uintptr_t;
#endif

#ifdef EFX_NEED_IPV6_NFC
	/**
	 * struct ethtool_tcpip6_spec - flow specification for TCP/IPv6 etc.
	 * @ip6src: Source host
	 * @ip6dst: Destination host
	 * @psrc: Source port
	 * @pdst: Destination port
	 * @tclass: Traffic Class
	 *
	 * This can be used to specify a TCP/IPv6, UDP/IPv6 or SCTP/IPv6 flow.
	 */
	struct ethtool_tcpip6_spec {
		__be32	ip6src[4];
		__be32	ip6dst[4];
		__be16	psrc;
		__be16	pdst;
		__u8    tclass;
	};

	/**
	 * struct ethtool_ah_espip6_spec - flow specification for IPsec/IPv6
	 * @ip6src: Source host
	 * @ip6dst: Destination host
	 * @spi: Security parameters index
	 * @tclass: Traffic Class
	 *
	 * This can be used to specify an IPsec transport or tunnel over IPv6.
	 */
	struct ethtool_ah_espip6_spec {
		__be32	ip6src[4];
		__be32	ip6dst[4];
		__be32	spi;
		__u8    tclass;
	};

	/**
	 * struct ethtool_usrip6_spec - general flow specification for IPv6
	 * @ip6src: Source host
	 * @ip6dst: Destination host
	 * @l4_4_bytes: First 4 bytes of transport (layer 4) header
	 * @tclass: Traffic Class
	 * @l4_proto: Transport protocol number (nexthdr after any Extension Headers)
	 */
	struct ethtool_usrip6_spec {
		__be32	ip6src[4];
		__be32	ip6dst[4];
		__be32	l4_4_bytes;
		__u8    tclass;
		__u8    l4_proto;
	};

	#ifndef IPV6_USER_FLOW
		#define	IPV6_USER_FLOW	0x0e	/* spec only (usr_ip6_spec; nfc only) */
	#endif
#endif

/**************************************************************************/

#ifdef EFX_NEED_BYTEORDER_TYPES
	typedef __u16 __be16;
	typedef __u32 __be32;
	typedef __u64 __be64;
	typedef __u16 __le16;
	typedef __u32 __le32;
	typedef __u64 __le64;
#endif

#ifdef EFX_HAVE_LINUX_MDIO_H
	#include <linux/mdio.h>
#else
	#include "linux_mdio.h"
#endif

#ifndef ETH_RESET_SHARED_SHIFT
	enum ethtool_reset_flags {
		/* These flags represent components dedicated to the interface
		 * the command is addressed to.  Shift any flag left by
		 * ETH_RESET_SHARED_SHIFT to reset a shared component of the
		 * same type.
		 */
		ETH_RESET_MGMT		= 1 << 0,	/* Management processor */
		ETH_RESET_IRQ		= 1 << 1,	/* Interrupt requester */
		ETH_RESET_DMA		= 1 << 2,	/* DMA engine */
		ETH_RESET_FILTER	= 1 << 3,	/* Filtering/flow direction */
		ETH_RESET_OFFLOAD	= 1 << 4,	/* Protocol offload */
		ETH_RESET_MAC		= 1 << 5,	/* Media access controller */
		ETH_RESET_PHY		= 1 << 6,	/* Transceiver/PHY */
		ETH_RESET_RAM		= 1 << 7,	/* RAM shared between
							 * multiple components */

		ETH_RESET_DEDICATED	= 0x0000ffff,	/* All components dedicated to
							 * this interface */
		ETH_RESET_ALL		= 0xffffffff,	/* All components used by this
							 * interface, even if shared */
	};
	#define ETH_RESET_SHARED_SHIFT	16
	#define ETHTOOL_RESET		0x00000034
#endif

#ifndef ETHTOOL_GRXFH
	#define ETHTOOL_GRXFH		0x00000029
#endif

#ifdef ETHTOOL_GRXRINGS
	#define EFX_HAVE_ETHTOOL_RXNFC yes
#else
	#define ETHTOOL_GRXRINGS	0x0000002d
#endif

#ifndef TCP_V4_FLOW
	#define	TCP_V4_FLOW	0x01
	#define	UDP_V4_FLOW	0x02
	#define	SCTP_V4_FLOW	0x03
	#define	AH_ESP_V4_FLOW	0x04
	#define	TCP_V6_FLOW	0x05
	#define	UDP_V6_FLOW	0x06
	#define	SCTP_V6_FLOW	0x07
	#define	AH_ESP_V6_FLOW	0x08
#endif
#ifndef AH_V4_FLOW
	#define	AH_V4_FLOW	0x09
	#define	ESP_V4_FLOW	0x0a
	#define	AH_V6_FLOW	0x0b
	#define	ESP_V6_FLOW	0x0c
	#define	IP_USER_FLOW	0x0d
#endif
#ifndef IPV4_FLOW
	#define	IPV4_FLOW	0x10
	#define	IPV6_FLOW	0x11
#endif
#ifndef ETHER_FLOW
	#define ETHER_FLOW	0x12
#endif
#ifndef FLOW_EXT
	#define	FLOW_EXT	0x80000000
#endif
#ifndef FLOW_RSS
	#define	FLOW_RSS	0x20000000
#endif
#ifndef RXH_L2DA
	#define	RXH_L2DA	(1 << 1)
	#define	RXH_VLAN	(1 << 2)
	#define	RXH_L3_PROTO	(1 << 3)
	#define	RXH_IP_SRC	(1 << 4)
	#define	RXH_IP_DST	(1 << 5)
	#define	RXH_L4_B_0_1	(1 << 6)
	#define	RXH_L4_B_2_3	(1 << 7)
	#define	RXH_DISCARD	(1 << 31)
#endif

#ifndef ETHTOOL_GRXCLSRULE
	struct ethtool_tcpip4_spec {
		__be32	ip4src;
		__be32	ip4dst;
		__be16	psrc;
		__be16	pdst;
		__u8    tos;
	};

	struct ethtool_usrip4_spec {
		__be32  ip4src;
		__be32  ip4dst;
		__be32  l4_4_bytes;
		__u8    tos;
		__u8    ip_ver;
		__u8    proto;
	};

	#define RX_CLS_FLOW_DISC	0xffffffffffffffffULL

	#define ETH_RX_NFC_IP4  1

	#define ETHTOOL_GRXCLSRLCNT	0x0000002e
	#define ETHTOOL_GRXCLSRULE	0x0000002f
	#define ETHTOOL_GRXCLSRLALL	0x00000030
	#define ETHTOOL_SRXCLSRLDEL     0x00000031
	#define ETHTOOL_SRXCLSRLINS	0x00000032
#endif

/* We want to use the latest definition of ethtool_rxnfc, even if the
 * kernel headers don't define all the fields in it.  Use our own name
 * and cast as necessary.
 */
#ifndef EFX_HAVE_EFX_ETHTOOL_RXNFC
	union efx_ethtool_flow_union {
		struct ethtool_tcpip4_spec		tcp_ip4_spec;
		struct ethtool_tcpip4_spec		udp_ip4_spec;
		struct ethtool_tcpip4_spec		sctp_ip4_spec;
		struct ethtool_usrip4_spec		usr_ip4_spec;
		struct ethtool_tcpip6_spec		tcp_ip6_spec;
		struct ethtool_tcpip6_spec		udp_ip6_spec;
		struct ethtool_tcpip6_spec		sctp_ip6_spec;
		struct ethtool_usrip6_spec		usr_ip6_spec;
		struct ethhdr				ether_spec;
		/* unneeded members omitted... */
		__u8					hdata[60];
	};
	struct efx_ethtool_flow_ext {
		__be16	vlan_etype;
		__be16	vlan_tci;
		__be32	data[2];
	};
	struct efx_ethtool_rx_flow_spec {
		__u32		flow_type;
		union efx_ethtool_flow_union h_u;
		struct efx_ethtool_flow_ext h_ext;
		union efx_ethtool_flow_union m_u;
		struct efx_ethtool_flow_ext m_ext;
		__u64		ring_cookie;
		__u32		location;
	};
	struct efx_ethtool_rxnfc {
		__u32				cmd;
		__u32				flow_type;
		__u64				data;
		struct efx_ethtool_rx_flow_spec	fs;
		union {
			__u32			rule_cnt;
			__u32			rss_context;
		};
		__u32				rule_locs[0];
	};
	#define EFX_HAVE_EFX_ETHTOOL_RXNFC yes
#endif

#ifndef RX_CLS_LOC_SPECIAL
	#define RX_CLS_LOC_SPECIAL	0x80000000
	#define RX_CLS_LOC_ANY		0xffffffff
	#define RX_CLS_LOC_FIRST	0xfffffffe
	#define RX_CLS_LOC_LAST		0xfffffffd
#endif

#ifdef ETHTOOL_GRXFHINDIR
	#define EFX_HAVE_ETHTOOL_RXFH_INDIR yes
#else
	struct ethtool_rxfh_indir {
		__u32	cmd;
		/* On entry, this is the array size of the user buffer.  On
		 * return from ETHTOOL_GRXFHINDIR, this is the array size of
		 * the hardware indirection table. */
		__u32	size;
		__u32	ring_index[0];	/* ring/queue index for each hash value */
	};
	#define ETHTOOL_GRXFHINDIR	0x00000038
	#define ETHTOOL_SRXFHINDIR	0x00000039
#endif

#ifdef EFX_NEED_ETHTOOL_RXFH_INDIR_DEFAULT
	static inline u32 ethtool_rxfh_indir_default(u32 index, u32 n_rx_rings)
	{
		return index % n_rx_rings;
	}
#endif

#ifndef EFX_HAVE_ETHTOOL_SET_PHYS_ID
	enum ethtool_phys_id_state {
		ETHTOOL_ID_INACTIVE,
		ETHTOOL_ID_ACTIVE,
		ETHTOOL_ID_ON,
		ETHTOOL_ID_OFF
	};
#endif

#ifdef EFX_NEED_ETHTOOL_CMD_SPEED
	static inline void ethtool_cmd_speed_set(struct ethtool_cmd *ep,
						 u32 speed)
	{
		ep->speed = speed;
		/* speed_hi is at offset 28 (architecture-independent) */
		((u16 *)ep)[14] = speed >> 16;
	}

	static inline u32 ethtool_cmd_speed(const struct ethtool_cmd *ep)
	{
		return ((u16 *)ep)[14] << 16 | ep->speed;
	}
#endif

#ifdef ETHTOOL_GMODULEEEPROM
	#define EFX_HAVE_ETHTOOL_GMODULEEEPROM yes
	#ifndef ETH_MODULE_SFF_8436
	#define ETH_MODULE_SFF_8436     0x3
	#define ETH_MODULE_SFF_8436_LEN 640
	#endif
#else
	struct ethtool_modinfo {
		__u32   cmd;
		__u32   type;
		__u32   eeprom_len;
		__u32   reserved[8];
	};

	#define ETH_MODULE_SFF_8079     0x1
	#define ETH_MODULE_SFF_8079_LEN 256
	#define ETH_MODULE_SFF_8472     0x2
	#define ETH_MODULE_SFF_8472_LEN 512
	#define ETH_MODULE_SFF_8436     0x3
	#define ETH_MODULE_SFF_8436_LEN 640

	#define ETHTOOL_GMODULEINFO     0x00000042
	#define ETHTOOL_GMODULEEEPROM   0x00000043
#endif

#ifndef ETHTOOL_GET_TS_INFO
	struct ethtool_ts_info {
		__u32	cmd;
		__u32	so_timestamping;
		__s32	phc_index;
		__u32	tx_types;
		__u32	tx_reserved[3];
		__u32	rx_filters;
		__u32	rx_reserved[3];
	};
	#define ETHTOOL_GET_TS_INFO	0x00000041 /* Get time stamping and PHC info */
#endif

#ifndef FLOW_CTRL_TX
	#define FLOW_CTRL_TX		0x01
	#define FLOW_CTRL_RX		0x02
#endif

#ifdef EFX_NEED_MII_RESOLVE_FLOWCTRL_FDX
	/**
	 * mii_resolve_flowctrl_fdx
	 * @lcladv: value of MII ADVERTISE register
	 * @rmtadv: value of MII LPA register
	 *
	 * Resolve full duplex flow control as per IEEE 802.3-2005 table 28B-3
	 */
	static inline u8 mii_resolve_flowctrl_fdx(u16 lcladv, u16 rmtadv)
	{
		u8 cap = 0;

		if (lcladv & rmtadv & ADVERTISE_PAUSE_CAP) {
			cap = FLOW_CTRL_TX | FLOW_CTRL_RX;
		} else if (lcladv & rmtadv & ADVERTISE_PAUSE_ASYM) {
			if (lcladv & ADVERTISE_PAUSE_CAP)
				cap = FLOW_CTRL_RX;
			else if (rmtadv & ADVERTISE_PAUSE_CAP)
				cap = FLOW_CTRL_TX;
		}

		return cap;
	}
#endif

#ifdef EFX_NEED_MII_ADVERTISE_FLOWCTRL
	/**
	 * mii_advertise_flowctrl - get flow control advertisement flags
	 * @cap: Flow control capabilities (FLOW_CTRL_RX, FLOW_CTRL_TX or both)
	 */
	static inline u16 mii_advertise_flowctrl(int cap)
	{
		u16 adv = 0;

		if (cap & FLOW_CTRL_RX)
			adv = ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;
		if (cap & FLOW_CTRL_TX)
			adv ^= ADVERTISE_PAUSE_ASYM;

		return adv;
	}
#endif

#ifndef PORT_DA
	#define PORT_DA			0x05
#endif

#ifndef PORT_OTHER
	#define PORT_OTHER		0xff
#endif

#ifndef SUPPORTED_Pause
	#define SUPPORTED_Pause			(1 << 13)
	#define SUPPORTED_Asym_Pause		(1 << 14)
#endif

#ifndef SUPPORTED_Backplane
	#define SUPPORTED_Backplane		(1 << 16)
	#define SUPPORTED_1000baseKX_Full	(1 << 17)
	#define SUPPORTED_10000baseKX4_Full	(1 << 18)
	#define SUPPORTED_10000baseKR_Full	(1 << 19)
	#define SUPPORTED_10000baseR_FEC	(1 << 20)
#endif
#ifndef SUPPORTED_40000baseKR4_Full
	#define SUPPORTED_40000baseKR4_Full	(1 << 23)
	#define SUPPORTED_40000baseCR4_Full	(1 << 24)
#endif

#ifdef EFX_NEED_SKB_HEADER_MACROS
	#define skb_mac_header(skb)	((skb)->mac.raw)
	#define skb_network_header(skb) ((skb)->nh.raw)
	#define skb_tail_pointer(skb)   ((skb)->tail)
	#define skb_set_mac_header(skb, offset)			\
		((skb)->mac.raw = (skb)->data + (offset))
	#define skb_transport_header(skb) ((skb)->h.raw)

	static inline int skb_transport_offset(const struct sk_buff *skb)
	{
		return skb->h.raw - skb->data;
	}
#endif

#ifdef EFX_NEED_SKB_NETWORK_HEADER_LEN
	static inline u32 skb_network_header_len(const struct sk_buff *skb)
	{
		return skb->h.raw - skb->nh.raw;
	}
#endif

#ifdef EFX_NEED_SKB_RECORD_RX_QUEUE
	#define skb_record_rx_queue(_skb, _channel)
#endif

#ifdef EFX_NEED_TCP_HDR
	#define tcp_hdr(skb)		((skb)->h.th)
#endif

#ifdef EFX_NEED_UDP_HDR
	#define udp_hdr(skb)		((skb)->h.uh)
#endif

#ifdef EFX_NEED_IP_HDR
	#define ip_hdr(skb)		((skb)->nh.iph)
#endif

#ifdef EFX_NEED_IPV6_HDR
	#define ipv6_hdr(skb)		((skb)->nh.ipv6h)
#endif

#ifdef EFX_NEED_RAW_READ_AND_WRITE_FIX
	#include <asm/io.h>
	static inline void
	efx_raw_writeb(u8 value, volatile void __iomem *addr)
	{
		writeb(value, addr);
	}
	static inline void
	efx_raw_writew(u16 value, volatile void __iomem *addr)
	{
		writew(le16_to_cpu(value), addr);
	}
	static inline void
	efx_raw_writel(u32 value, volatile void __iomem *addr)
	{
		writel(le32_to_cpu(value), addr);
	}
	static inline void
	efx_raw_writeq(u64 value, volatile void __iomem *addr)
	{
		writeq(le64_to_cpu(value), addr);
	}
	static inline u8
	efx_raw_readb(const volatile void __iomem *addr)
	{
		return readb(addr);
	}
	static inline u16
	efx_raw_readw(const volatile void __iomem *addr)
	{
		return cpu_to_le16(readw(addr));
	}
	static inline u32
	efx_raw_readl(const volatile void __iomem *addr)
	{
		return cpu_to_le32(readl(addr));
	}
	static inline u64
	efx_raw_readq(const volatile void __iomem *addr)
	{
		return cpu_to_le64(readq(addr));
	}

	#undef __raw_writeb
	#undef __raw_writew
	#undef __raw_writel
	#undef __raw_writeq
	#undef __raw_readb
	#undef __raw_readw
	#undef __raw_readl
	#undef __raw_readq
	#define __raw_writeb efx_raw_writeb
	#define __raw_writew efx_raw_writew
	#define __raw_writel efx_raw_writel
	#define __raw_writeq efx_raw_writeq
	#define __raw_readb efx_raw_readb
	#define __raw_readw efx_raw_readw
	#define __raw_readl efx_raw_readl
	#define __raw_readq efx_raw_readq
#endif

#ifdef EFX_NEED_VZALLOC
	static inline void *vzalloc(unsigned long size)
	{
		void *buf = vmalloc(size);
		if (buf)
			memset(buf, 0, size);
		return buf;
	}
#endif

#ifndef NETIF_F_GSO
	#define efx_gso_size tso_size
	#undef gso_size
	#define gso_size efx_gso_size
	#define efx_gso_segs tso_segs
	#undef gso_segs
	#define gso_segs efx_gso_segs
#endif

#ifndef GSO_MAX_SIZE
	#define GSO_MAX_SIZE 65536
#endif

#ifdef EFX_NEED_NETDEV_ALLOC_SKB
	#ifndef NET_SKB_PAD
		#define NET_SKB_PAD 16
	#endif

	static inline
	struct sk_buff *netdev_alloc_skb(struct net_device *dev,
					 unsigned int length)
	{
		struct sk_buff *skb = alloc_skb(length + NET_SKB_PAD,
						GFP_ATOMIC);
		if (likely(skb)) {
			skb_reserve(skb, NET_SKB_PAD);
			skb->dev = dev;
		}
		return skb;
	}
#endif

#ifdef EFX_NEED_NETDEV_TX_T
	typedef int netdev_tx_t;
	#ifndef NETDEV_TX_OK
		#define NETDEV_TX_OK 0
	#endif
	#ifndef NETDEV_TX_BUSY
		#define NETDEV_TX_BUSY 1
	#endif
#endif

#ifndef netdev_for_each_uc_addr
	#if defined(EFX_HAVE_NET_DEVICE_UC)
		#define netdev_for_each_uc_addr(uclist, dev)		\
			list_for_each_entry(uclist, &(dev)->uc.list, list)
		#define netdev_uc_count(dev) (dev)->uc.count
	#elif defined(EFX_HAVE_NET_DEVICE_UC_LIST)
		#define netdev_for_each_uc_addr(uclist, dev)		\
			for (uclist = (dev)->uc_list;			\
			     uclist;					\
			     uclist = uclist->next)
		#define netdev_uc_count(dev) (dev)->uc_count
	#else
		struct dev_addr_list { void *da_addr; struct dev_addr_list *next; };
		#define netdev_for_each_uc_addr(uclist, dev) while ((void)uclist,(void)dev,0)
		#define netdev_uc_count(dev) ((void)dev,0)
	#endif
#endif

#ifndef netdev_for_each_mc_addr
	#define netdev_for_each_mc_addr(mclist, dev) \
		for (mclist = (dev)->mc_list; mclist; mclist = mclist->next)
#endif

#ifndef netdev_mc_count
	#define netdev_mc_count(dev) (dev)->mc_count
#endif

#ifdef EFX_NEED_ALLOC_ETHERDEV_MQ
	#define alloc_etherdev_mq(sizeof_priv, queue_count)		\
		({							\
			BUILD_BUG_ON((queue_count) != 1);		\
			alloc_etherdev(sizeof_priv);			\
		})
#endif

#ifdef EFX_NEED_NETIF_SET_REAL_NUM_TX_QUEUES
	static inline void
	netif_set_real_num_tx_queues(struct net_device *dev, unsigned int txq)
	{
		dev->real_num_tx_queues = txq;
	}
#endif

#ifdef EFX_NEED_NETIF_SET_REAL_NUM_RX_QUEUES
	static inline void
	netif_set_real_num_rx_queues(struct net_device *dev, unsigned int rxq)
	{
#ifdef CONFIG_RPS
		dev->num_rx_queues = rxq;
#endif
	}
#endif

#ifdef EFX_NEED_RTNL_TRYLOCK
	static inline int rtnl_trylock(void) {
		return !rtnl_shlock_nowait();
	}
#endif

#ifdef EFX_NEED_NETIF_TX_LOCK
	static inline void netif_tx_lock(struct net_device *dev)
	{
		spin_lock(&dev->xmit_lock);
		dev->xmit_lock_owner = smp_processor_id();
	}
	static inline void netif_tx_lock_bh(struct net_device *dev)
	{
		spin_lock_bh(&dev->xmit_lock);
		dev->xmit_lock_owner = smp_processor_id();
	}
	static inline void netif_tx_unlock_bh(struct net_device *dev)
	{
		dev->xmit_lock_owner = -1;
		spin_unlock_bh(&dev->xmit_lock);
	}
	static inline void netif_tx_unlock(struct net_device *dev)
	{
		dev->xmit_lock_owner = -1;
		spin_unlock(&dev->xmit_lock);
	}
#endif

#ifdef EFX_NEED_NETIF_ADDR_LOCK
	static inline void netif_addr_lock(struct net_device *dev)
	{
		netif_tx_lock(dev);
	}
	static inline void netif_addr_lock_bh(struct net_device *dev)
	{
		netif_tx_lock_bh(dev);
	}
	static inline void netif_addr_unlock_bh(struct net_device *dev)
	{
		netif_tx_unlock_bh(dev);
	}
	static inline void netif_addr_unlock(struct net_device *dev)
	{
		netif_tx_unlock(dev);
	}
#endif

#ifdef EFX_NEED_HEX_DUMP
	enum {
		DUMP_PREFIX_NONE,
		DUMP_PREFIX_ADDRESS,
		DUMP_PREFIX_OFFSET
	};
#endif

#ifdef EFX_NEED_RESOURCE_SIZE_T
	typedef unsigned long resource_size_t;
#endif

#ifdef EFX_NEED_RESOURCE_SIZE
	static inline resource_size_t resource_size(struct resource *res)
	{
		return res->end - res->start + 1;
	}
#endif

#ifdef EFX_HAVE_OLD_DMA_MAPPING_ERROR
	static inline int
	efx_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
	{
		return dma_mapping_error(dma_addr);
	}
	#undef dma_mapping_error
	#define dma_mapping_error efx_dma_mapping_error
#endif

#ifdef EFX_NEED_DMA_SET_COHERENT_MASK
	static inline int dma_set_coherent_mask(struct device *dev, u64 mask)
	{
		return pci_set_consistent_dma_mask(to_pci_dev(dev), mask);
	}
#endif

#ifdef EFX_NEED_DMA_SET_MASK_AND_COHERENT
	static inline int dma_set_mask_and_coherent(struct device *dev, u64 mask)
	{
		int rc = dma_set_mask(dev, mask);
		if (rc == 0)
			dma_set_coherent_mask(dev, mask);
		return rc;
	}
#endif

/*
 * Recent mainline kernels can be configured so that the resulting
 * image will run both on 'bare metal' and in a Xen domU.
 * xen_domain() or xen_start_info tells us which is the case at
 * run-time.  If neither is defined, assume that CONFIG_XEN tells us
 * at compile-time.
 */
#if defined(EFX_HAVE_XEN_XEN_H)
	#include <xen/xen.h>
#elif defined(CONFIG_XEN) && defined(EFX_HAVE_XEN_START_INFO)
	/* We should be able to include <asm/xen/hypervisor.h> but that
	 * is broken (#includes other headers that are not installed) in
	 * Fedora 10. */
	extern struct start_info *xen_start_info;
	#define xen_domain() (xen_start_info ? 1 : 0)
#endif
#ifndef xen_domain
	#ifdef CONFIG_XEN
		#define xen_domain() 1
	#else
		#define xen_domain() 0
	#endif
#endif

#ifndef IS_ALIGNED
	#define IS_ALIGNED(x, a) (((x) & ((typeof(x))(a) - 1)) == 0)
#endif

#ifndef netif_printk

	/* A counterpart to SET_NETDEV_DEV */
	#ifdef EFX_USE_NETDEV_DEV
		#define EFX_GET_NETDEV_DEV(netdev) ((netdev)->dev.parent)
	#else
		#define EFX_GET_NETDEV_DEV(netdev) ((netdev)->class_dev.dev)
	#endif

	static inline const char *netdev_name(const struct net_device *dev)
	{
		if (dev->reg_state != NETREG_REGISTERED)
			return "(unregistered net_device)";
		return dev->name;
	}

	#define netdev_printk(level, netdev, format, args...)		\
		dev_printk(level, EFX_GET_NETDEV_DEV(netdev),		\
			   "%s: " format,				\
			   netdev_name(netdev), ##args)

	#define netif_printk(priv, type, level, dev, fmt, args...)	\
	do {								\
		if (netif_msg_##type(priv))				\
			netdev_printk(level, (dev), fmt, ##args);	\
	} while (0)

	#define netif_emerg(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_EMERG, dev, fmt, ##args)
	#define netif_alert(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_ALERT, dev, fmt, ##args)
	#define netif_crit(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_CRIT, dev, fmt, ##args)
	#define netif_err(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_ERR, dev, fmt, ##args)
	#define netif_warn(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_WARNING, dev, fmt, ##args)
	#define netif_notice(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_NOTICE, dev, fmt, ##args)
	#define netif_info(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_INFO, (dev), fmt, ##args)

	#if defined(DEBUG)
	#define netif_dbg(priv, type, dev, format, args...)		\
		netif_printk(priv, type, KERN_DEBUG, dev, format, ##args)
	#elif defined(CONFIG_DYNAMIC_DEBUG)
	#define netif_dbg(priv, type, netdev, format, args...)		\
	do {								\
		if (netif_msg_##type(priv))				\
			dynamic_dev_dbg((netdev)->dev.parent,		\
					"%s: " format,			\
					netdev_name(netdev), ##args);	\
	} while (0)
	#else
	#define netif_dbg(priv, type, dev, format, args...)		\
	({								\
		if (0)							\
			netif_printk(priv, type, KERN_DEBUG, dev,	\
				     format, ##args);			\
		0;							\
	})
	#endif

#endif

/* netif_vdbg may be defined wrongly */
#undef netif_vdbg
#if defined(VERBOSE_DEBUG)
#define netif_vdbg	netif_dbg
#else
#define netif_vdbg(priv, type, dev, format, args...)		\
({								\
	if (0)							\
		netif_printk(priv, type, KERN_DEBUG, dev,	\
			     format, ##args);			\
	0;							\
})
#endif

/* netdev_WARN may be defined wrongly (with a trailing semi-colon) */
#undef netdev_WARN
#define netdev_WARN(dev, format, args...)			\
	WARN(1, "netdevice: %s\n" format, netdev_name(dev), ##args)

#ifndef pr_err
	#define pr_err(fmt, arg...) \
		printk(KERN_ERR fmt, ##arg)
#endif
#ifndef pr_warning
	#define pr_warning(fmt, arg...) \
		printk(KERN_WARNING fmt, ##arg)
#endif

#ifndef netif_cond_dbg
/* if @cond then downgrade to debug, else print at @level */
#define netif_cond_dbg(priv, type, netdev, cond, level, fmt, args...)     \
	do {                                                              \
		if (cond)                                                 \
			netif_dbg(priv, type, netdev, fmt, ##args);       \
		else                                                      \
			netif_ ## level(priv, type, netdev, fmt, ##args); \
	} while (0)
#endif

/* __maybe_unused may be defined wrongly */
#undef __maybe_unused
#define __maybe_unused __attribute__((unused))

#ifndef __always_unused
	#define __always_unused __attribute__((unused))
#endif

#ifdef EFX_NEED_ETHER_ADDR_COPY
	static inline void ether_addr_copy(u8 *dst, const u8 *src)
	{
		u16 *a = (u16 *)dst;
		const u16 *b = (const u16 *)src;

		a[0] = b[0];
		a[1] = b[1];
		a[2] = b[2];
	}
#endif

#ifdef EFX_NEED_ETHER_ADDR_EQUAL
	static inline bool ether_addr_equal(const u8 *addr1, const u8 *addr2)
	{
		return !compare_ether_addr(addr1, addr2);
	}
#endif

#ifdef EFX_NEED_ETH_ZERO_ADDR
	static inline void eth_zero_addr(u8 *addr)
	{
		memset(addr, 0x00, ETH_ALEN);
	}
#endif

#ifdef EFX_NEED_ETH_BROADCAST_ADDR
	static inline void eth_broadcast_addr(u8 *addr)
	{
		memset(addr, 0xff, ETH_ALEN);
	}
#endif

#ifdef EFX_NEED_ETH_RANDOM_ADDR
/* random_ether_addr was renamed in:
 *  0a4dd594982a ("etherdevice: Rename random_ether_addr to eth_random_addr")
 */
#define eth_random_addr	random_ether_addr
#endif

#ifdef EFX_NEED_MAC_PTON
	#ifndef EFX_HAVE_HEX_TO_BIN
		static inline int hex_to_bin(char ch)
		{
			if ((ch >= '0') && (ch <= '9'))
				return ch - '0';
			ch = tolower(ch);
			if ((ch >= 'a') && (ch <= 'f'))
				return ch - 'a' + 10;
			return -1;
		}
	#endif

	static inline int mac_pton(const char *s, u8 *mac)
	{
		int i;
		if (strlen(s) < 3 * ETH_ALEN - 1)
			return 0;
		for (i = 0; i < ETH_ALEN; i++) {
			if (!isxdigit(s[i * 3]) || !isxdigit(s[i * 3 + 1]))
				return 0;
			if (i != ETH_ALEN - 1 && s[i * 3 + 2] != ':')
				return 0;
			}
		for (i = 0; i < ETH_ALEN; i++)
			mac[i] = (hex_to_bin(s[i * 3]) << 4) |
				  hex_to_bin(s[i * 3 + 1]);
		return 1;
	}
#endif

#ifdef EFX_NEED_IPV4_IS_MULTICAST
	static inline bool ipv4_is_multicast(__be32 addr)
	{
		return (addr & htonl(0xf0000000)) == htonl(0xe0000000);
	}
#endif

#ifdef EFX_NEED_IPV4_IS_LBCAST
	static inline bool ipv4_is_lbcast(__be32 addr)
	{
		return addr == htonl(INADDR_BROADCAST);
	}
#endif

#ifdef EFX_NEED_IP_IS_FRAGMENT
	static inline bool ip_is_fragment(const struct iphdr *iph)
	{
		return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
	}
#endif

#ifdef EFX_NEED_NETDEV_FEATURES_T
	typedef u32 netdev_features_t;
#endif

#ifdef EFX_NEED_NETDEV_NOTIFIER_INFO_TO_DEV
static inline struct net_device *
netdev_notifier_info_to_dev(const void *info)
{
	return (struct net_device *) info;
}
#endif

#ifdef EFX_NEED_SKB_FILL_PAGE_DESC
	static inline void
	skb_fill_page_desc(struct sk_buff *skb, int i, struct page *page,
			   int off, int size)
	{
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		frag->page = page;
		frag->page_offset = off;
		frag->size = size;
		skb_shinfo(skb)->nr_frags = i+1;
	}
#endif

#ifdef EFX_NEED_SKB_FRAG_DMA_MAP
	static inline dma_addr_t skb_frag_dma_map(struct device *dev,
						  const skb_frag_t *frag,
						  size_t offset, size_t size,
						  enum dma_data_direction dir)
	{
		return dma_map_page(dev, frag->page,
				    frag->page_offset + offset, size, dir);
	}
#endif

#ifdef EFX_NEED_SKB_FRAG_ADDRESS
	static inline void *skb_frag_address(const skb_frag_t *frag)
	{
		return page_address(frag->page) + frag->page_offset;
	}
#endif

#ifdef EFX_NEED_SKB_FRAG_SIZE
	static inline unsigned int skb_frag_size(const skb_frag_t *frag)
	{
		return frag->size;
	}
#endif

#ifdef EFX_NEED_SKB_FRAG_PAGE
	static inline struct page *skb_frag_page(const skb_frag_t *frag)
	{
		return frag->page;
	}
#endif

#ifdef EFX_NEED_SKB_FRAG_OFF
/**
 * skb_frag_off() - Returns the offset of a skb fragment
 * @frag: the paged fragment
 */
static inline unsigned int skb_frag_off(const skb_frag_t *frag)
{
	/* This later got renamed bv_offset (because skb_frag_t is now really
	 * a struct bio_vec), but the page_offset name should work in any
	 * kernel that doesn't already have skb_frag_off defined.
	 */
	return frag->page_offset;
}
#endif

#if defined(CONFIG_COMPAT) && defined(EFX_NEED_COMPAT_U64)
	#if defined(CONFIG_X86_64) || defined(CONFIG_IA64)
		typedef u64 __attribute__((aligned(4))) compat_u64;
	#else
		typedef u64 compat_u64;
	#endif
#endif

#ifdef EFX_NEED_BYTE_QUEUE_LIMITS
static inline void netdev_tx_sent_queue(struct netdev_queue *dev_queue,
					unsigned int bytes)
{}
static inline void netdev_tx_completed_queue(struct netdev_queue *dev_queue,
					     unsigned int pkts,
					     unsigned int bytes)
{}
static inline void netdev_tx_reset_queue(struct netdev_queue *q) {}
#endif

#ifdef EFX_NEED___BQL
/* Variant of netdev_tx_sent_queue() for drivers that are aware
 * that they should not test BQL status themselves.
 * We do want to change __QUEUE_STATE_STACK_XOFF only for the last
 * skb of a batch.
 * Returns true if the doorbell must be used to kick the NIC.
 */
static inline bool __netdev_tx_sent_queue(struct netdev_queue *dev_queue,
					  unsigned int bytes,
					  bool xmit_more)
{
	if (xmit_more) {
#ifdef CONFIG_BQL
		dql_queued(&dev_queue->dql, bytes);
#endif
		return netif_tx_queue_stopped(dev_queue);
	}
	netdev_tx_sent_queue(dev_queue, bytes);
	return true;
}
#endif

#ifdef EFX_NEED_IS_COMPAT_TASK
	static inline int is_compat_task(void)
	{
	#if !defined(CONFIG_COMPAT)
		return 0;
	#elif defined(CONFIG_X86_64)
		#if defined(EFX_HAVE_TIF_ADDR32)
		return test_thread_flag(TIF_ADDR32);
		#else
		return test_thread_flag(TIF_IA32);
		#endif
	#elif defined(CONFIG_PPC64)
		return test_thread_flag(TIF_32BIT);
	#else
	#error "cannot define is_compat_task() for this architecture"
	#endif
	}
#endif

#ifdef EFX_NEED_SKB_CHECKSUM_NONE_ASSERT
static inline void skb_checksum_none_assert(const struct sk_buff *skb)
{
#ifdef DEBUG
	BUG_ON(skb->ip_summed != CHECKSUM_NONE);
#endif
}
#endif

#ifndef NETIF_F_TSO_MANGLEID
	#define NETIF_F_TSO_MANGLEID 0
#endif
#ifndef SKB_GSO_TCP_FIXEDID
	#define SKB_GSO_TCP_FIXEDID 0
#endif

#ifndef __read_mostly
	#define __read_mostly
#endif

#ifndef NETIF_F_HW_VLAN_CTAG_TX
	#define NETIF_F_HW_VLAN_CTAG_TX NETIF_F_HW_VLAN_TX
#endif

#ifndef NETIF_F_HW_VLAN_CTAG_RX
       #define NETIF_F_HW_VLAN_CTAG_RX NETIF_F_HW_VLAN_RX
#endif

#ifdef EFX_HAVE_OLD___VLAN_HWACCEL_PUT_TAG
static inline struct sk_buff *
	efx___vlan_hwaccel_put_tag(struct sk_buff *skb, __be16 vlan_proto,
				   u16 vlan_tci)
	{
		WARN_ON(vlan_proto != htons(ETH_P_8021Q));
		return __vlan_hwaccel_put_tag(skb, vlan_tci);
	}
	#define __vlan_hwaccel_put_tag efx___vlan_hwaccel_put_tag
#endif
#ifndef NETIF_F_HW_VLAN_CTAG_FILTER
	#define NETIF_F_HW_VLAN_CTAG_FILTER NETIF_F_HW_VLAN_FILTER
#endif

#ifdef EFX_NEED___SET_BIT_LE
	/* Depending on kernel version, BITOP_LE_SWIZZLE may be
	 * defined the way we want or unconditionally as the
	 * big-endian value (or not at all).  Use our own name.
	 */
	#if defined(__LITTLE_ENDIAN)
	#define EFX_BITOP_LE_SWIZZLE        0
	#elif defined(__BIG_ENDIAN)
	#define EFX_BITOP_LE_SWIZZLE        ((BITS_PER_LONG-1) & ~0x7)
	#endif

	/* __set_bit_le() and __clear_bit_le() may already be defined
	 * as macros with the wrong effective parameter type (volatile
	 * unsigned long *), so use brute force to replace them.
	 */

	static inline void efx__set_bit_le(int nr, void *addr)
	{
		__set_bit(nr ^ EFX_BITOP_LE_SWIZZLE, addr);
	}
	#undef __set_bit_le
	#define __set_bit_le efx__set_bit_le

	static inline void efx__clear_bit_le(int nr, void *addr)
	{
		__clear_bit(nr ^ EFX_BITOP_LE_SWIZZLE, addr);
	}
	#undef __clear_bit_le
	#define __clear_bit_le efx__clear_bit_le
#endif

#ifdef CONFIG_SFC_MTD
#ifdef EFX_NEED_MTD_DEVICE_REGISTER
	struct mtd_partition;

	static inline int
	mtd_device_register(struct mtd_info *master,
			    const struct mtd_partition *parts,
			    int nr_parts)
	{
		BUG_ON(parts);
		return add_mtd_device(master);
	}

	static inline int mtd_device_unregister(struct mtd_info *master)
	{
		return del_mtd_device(master);
	}
#endif
#endif

#ifndef for_each_set_bit
	#define for_each_set_bit(bit, addr, size)			\
		for ((bit) = find_first_bit((addr), (size));		\
		     (bit) < (size);					\
		     (bit) = find_next_bit((addr), (size), (bit) + 1))
#endif

#ifndef EFX_HAVE_IOREMAP_WC
	/* This should never be called */
	static inline void *
	ioremap_wc(resource_size_t offset, resource_size_t size)
	{
		WARN_ON(1);
		return NULL;
	}
#endif

#ifdef EFX_HAVE_IOREMAP_NOCACHE
	/* On old kernels ioremap_nocache() differs from ioremap() */
	#define efx_ioremap(phys,size)	ioremap_nocache(phys,size)
#else
	#define efx_ioremap(phys,size)	ioremap(phys,size)
#endif

#ifdef EFX_NEED_SKB_TRANSPORT_HEADER_WAS_SET
	#ifdef EFX_HAVE_OLD_SKB_HEADER_FIELDS
		#define skb_transport_header_was_set(skb) (!!(skb)->h.raw)
	#else
		#define skb_transport_header_was_set(skb)	\
			(!!(skb)->transport_header)
	#endif
#endif

#ifndef EFX_HAVE_NAPI_STRUCT
/* We use a napi_struct pointer as context in some compat functions even if the
 * kernel doesn't use this structure at all.
 */
struct efx_napi_dummy {};
#define napi_struct efx_napi_dummy
#endif

#ifdef EFX_HAVE_RXHASH_SUPPORT
#ifdef EFX_NEED_SKB_SET_HASH
enum pkt_hash_types {
	PKT_HASH_TYPE_NONE,
	PKT_HASH_TYPE_L2,
	PKT_HASH_TYPE_L3,
	PKT_HASH_TYPE_L4,
};

static inline void skb_set_hash(struct sk_buff *skb, __u32 hash,
				enum pkt_hash_types type)
{
#ifdef EFX_HAVE_SKB_L4HASH
	skb->l4_rxhash = (type == PKT_HASH_TYPE_L4);
#endif
	skb->rxhash = hash;
}
#endif
#endif

#ifndef EFX_HAVE_BUSY_POLL
static inline void skb_mark_napi_id(struct sk_buff *skb,
				    struct napi_struct *napi) {}
#endif

#ifdef EFX_NEED_USLEEP_RANGE
void usleep_range(unsigned long min, unsigned long max);
#endif

#ifndef EFX_HAVE_PCI_RESET_FUNCTION
	static inline int pci_reset_function(struct pci_dev *dev)
	{
		/* If it doesn't have pci_reset_function, it probably doesn't
		 * have all the things we need to implement it either.
		 * So just return ENOSYS and don't have FLR recovery.
		 */
		return -ENOSYS;
	}
#endif

#ifdef EFX_NEED_SKB_VLAN_TAG_GET
#define skb_vlan_tag_get	vlan_tx_tag_get
#define skb_vlan_tag_present	vlan_tx_tag_present
#endif

#ifdef EFX_NEED_PAGE_REF_ADD
static inline void page_ref_add(struct page *page, int nr)
{
	atomic_add(nr, &page->_count);
}
#endif

#ifdef EFX_HAVE_SKB_ENCAPSULATION
#ifdef EFX_SKB_HAS_INNER_NETWORK_HEADER
#define EFX_CAN_SUPPORT_ENCAP_TSO
#ifndef EFX_HAVE_SKB_INNER_NETWORK_HEADER
static inline unsigned char *skb_inner_network_header(const struct sk_buff *skb)
{
	return skb->head + skb->inner_network_header;
}
#endif

#ifndef EFX_HAVE_INNER_IP_HDR
static inline struct iphdr *inner_ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_inner_network_header(skb);
}
#endif
#endif /* EFX_SKB_HAS_INNER_NETWORK_HEADER */

#ifdef EFX_SKB_HAS_INNER_TRANSPORT_HEADER
#ifndef EFX_HAVE_SKB_INNER_TRANSPORT_HEADER
static inline unsigned char *skb_inner_transport_header(const struct sk_buff *skb)
{
	return skb->head + skb->inner_transport_header;
}
#endif

#ifndef EFX_HAVE_INNER_TCP_HDR
static inline struct tcphdr *inner_tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_inner_transport_header(skb);
}
#endif
#else /* !EFX_SKB_HAS_INNER_TRANSPORT_HEADER */
#undef EFX_CAN_SUPPORT_ENCAP_TSO
#endif /* EFX_SKB_HAS_INNER_TRANSPORT_HEADER */
#ifndef NETIF_F_GSO_GRE
#undef EFX_CAN_SUPPORT_ENCAP_TSO
#endif /* !NETIF_F_GSO_GRE */
#endif /* EFX_HAVE_SKB_ENCAPSULATION */

#ifndef EFX_HAVE_PCI_CHANNEL_STATE_T
#define	pci_channel_state_t	enum pci_channel_state
#endif

#ifndef EFX_HAVE_INDIRECT_CALL_WRAPPERS
#ifdef CONFIG_RETPOLINE

/*
 * INDIRECT_CALL_$NR - wrapper for indirect calls with $NR known builtin
 *  @f: function pointer
 *  @f$NR: builtin functions names, up to $NR of them
 *  @__VA_ARGS__: arguments for @f
 *
 * Avoid retpoline overhead for known builtin, checking @f vs each of them and
 * eventually invoking directly the builtin function. The functions are check
 * in the given order. Fallback to the indirect call.
 */
#define INDIRECT_CALL_1(f, f1, ...)					\
	({								\
		likely(f == f1) ? f1(__VA_ARGS__) : f(__VA_ARGS__);	\
	})
#define INDIRECT_CALL_2(f, f2, f1, ...)					\
	({								\
		likely(f == f2) ? f2(__VA_ARGS__) :			\
				  INDIRECT_CALL_1(f, f1, __VA_ARGS__);	\
	})

#else
#define INDIRECT_CALL_1(f, f1, ...) f(__VA_ARGS__)
#define INDIRECT_CALL_2(f, f2, f1, ...) f(__VA_ARGS__)
#endif
#endif /* EFX_HAVE_INDIRECT_CALL_WRAPPERS */

#ifndef EFX_HAVE_ETHTOOL_LINKSETTINGS
/* We use an array of size 1 so that legacy code using index [0] will
 * work with both this and a real link_mode_mask.
 */
#define __ETHTOOL_DECLARE_LINK_MODE_MASK(name)  unsigned long name[1]
#endif

#ifdef EFX_HAVE_XDP_TX
#ifndef EFX_HAVE_XDP_FRAME_API
#define xdp_frame	xdp_buff
#endif
#endif

#if !defined(EFX_USE_NETDEV_STATS64)
#define rtnl_link_stats64	net_device_stats
#endif

#ifdef EFX_NEED_MOD_DELAYED_WORK
static inline bool mod_delayed_work(struct workqueue_struct *wq,
				    struct delayed_work *dwork,
				    unsigned long delay)
{
	cancel_delayed_work(dwork);
	queue_delayed_work(wq, dwork, delay);
	return true;
}
#endif

#ifdef EFX_NEED_PCI_AER_CLEAR_NONFATAL_STATUS
static inline int pci_aer_clear_nonfatal_status(struct pci_dev *dev)
{
	return pci_cleanup_aer_uncorrect_error_status(dev);
}
#endif

#ifndef pci_info
#define pci_info(pdev, fmt, arg...)	dev_info(&(pdev)->dev, fmt, ##arg)
#endif
#ifndef pci_warn
#define pci_warn(pdev, fmt, arg...)	dev_warn(&(pdev)->dev, fmt, ##arg)
#endif
#ifndef pci_err
#define pci_err(pdev, fmt, arg...)	dev_err(&(pdev)->dev, fmt, ##arg)
#endif
#ifndef pci_dbg
#define pci_dbg(pdev, fmt, arg...)	dev_dbg(&(pdev)->dev, fmt, ##arg)
#endif

/**************************************************************************
 *
 * Missing functions provided by kernel_compat.c
 *
 **************************************************************************
 *
 */

#ifdef EFX_NEED_HEX_DUMP
	extern void
	print_hex_dump(const char *level, const char *prefix_str,
		       int prefix_type, int rowsize, int groupsize,
		       const void *buf, size_t len, int ascii);
#endif

#ifdef EFX_NEED_PCI_CLEAR_MASTER
	void pci_clear_master(struct pci_dev *dev);
#endif

#ifdef EFX_NEED_PCI_WAKE_FROM_D3
	int pci_wake_from_d3(struct pci_dev *dev, bool enable);
#endif

#if defined(EFX_NEED_UNMASK_MSIX_VECTORS) || \
    defined(EFX_NEED_SAVE_MSIX_MESSAGES)

	#if defined(EFX_NEED_SAVE_MSIX_MESSAGES)
		#include <linux/msi.h>
	#endif

	int efx_pci_save_state(struct pci_dev *dev);
	#define pci_save_state efx_pci_save_state

	void efx_pci_restore_state(struct pci_dev *dev);
	#define pci_restore_state efx_pci_restore_state

#endif

#if defined(EFX_NEED_NEW_CPUMASK_API)

	#define cpumask_clear efx_cpumask_clear
	static inline void efx_cpumask_clear(cpumask_t *dstp)
	{
		cpus_clear(*dstp);
	}

	#define cpumask_copy efx_cpumask_copy
	static inline void efx_cpumask_copy(cpumask_t *dstp, const cpumask_t *srcp)
	{
		*dstp = *srcp;
	}

	#undef cpumask_test_cpu
	#define cpumask_test_cpu(cpu, mask) cpu_isset(cpu, *(mask))

	#undef cpumask_set_cpu
	#define cpumask_set_cpu(cpu, mask) cpu_set(cpu, *(mask))

	#define cpumask_or efx_cpumask_or
	static inline void efx_cpumask_or(cpumask_t *dstp, const cpumask_t *src1p,
				      const cpumask_t *src2p)
	{
		cpus_or(*dstp, *src1p, *src2p);
	}

	#define cpumask_and efx_cpumask_and
	static inline void efx_cpumask_and(cpumask_t *dstp, const cpumask_t *src1p,
				      const cpumask_t *src2p)
	{
		cpus_and(*dstp, *src1p, *src2p);
	}

	#define cpumask_weight efx_cpumask_weight
	static inline unsigned int efx_cpumask_weight(const cpumask_t *srcp)
	{
		return cpus_weight(*srcp);
	}

	#undef for_each_cpu
	#define for_each_cpu(cpu, mask) for_each_cpu_mask(cpu, *(mask))

	#undef for_each_possible_cpu
	#define for_each_possible_cpu(CPU)			\
		for_each_cpu_mask((CPU), cpu_possible_map)

	#define cpumask_var_t efx_cpumask_var_t
	typedef cpumask_t efx_cpumask_var_t[1];

	#define alloc_cpumask_var efx_alloc_cpumask_var
	static inline bool efx_alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
	{
		return true;
	}

	#define zalloc_cpumask_var efx_zalloc_cpumask_var
	static inline bool efx_zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
	{
		cpumask_clear(*mask);
		return true;
	}

	#define free_cpumask_var efx_free_cpumask_var
	static inline void efx_free_cpumask_var(cpumask_t *mask) {}

	#ifdef topology_core_siblings
		#define topology_core_cpumask(cpu)		\
			(&(topology_core_siblings(cpu)))
	#endif

	#ifdef topology_thread_siblings
		#define topology_sibling_cpumask(cpu)		\
			(&(topology_thread_siblings(cpu)))
	#endif

	#if defined(cpumask_parse)
		#define cpumask_parse_user(ubuf, ulen, src)	 \
			__cpumask_parse(ubuf, ulen, src, NR_CPUS)
	#elif defined(cpumask_parse_user)
		#undef cpumask_parse_user
		#define cpumask_parse_user(ubuf, ulen, src)	\
			__cpumask_parse_user(ubuf, ulen, src, NR_CPUS)
	#endif

#elif defined(EFX_NEED_ZALLOC_CPUMASK_VAR)

	#ifdef CONFIG_CPUMASK_OFFSTACK
		static inline bool
		zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
		{
			return alloc_cpumask_var(mask, flags | __GFP_ZERO);
		}
	#else
		static inline bool
		zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
		{
			cpumask_clear(*mask);
			return true;
		}
	#endif

#else
	#if !defined(topology_sibling_cpumask) && defined(topology_thread_cpumask)
		#define topology_sibling_cpumask topology_thread_cpumask
	#endif
#endif

#ifndef EFX_HAVE_CPUMASK_OF_NODE
# ifdef node_to_cpumask_ptr
#  define cpumask_of_node(NODE)				\
	({						\
		node_to_cpumask_ptr(result, NODE);	\
		result;					\
	})
#  define EFX_HAVE_CPUMASK_OF_NODE yes
# elif LINUX_VERSION_CODE != KERNEL_VERSION(2,6,25)
#  define cpumask_of_node(NODE) &(node_to_cpumask(NODE))
#  define EFX_HAVE_CPUMASK_OF_NODE yes
# endif
#endif

#if defined(EFX_NEED_SET_CPUS_ALLOWED_PTR) && !defined(set_cpus_allowed_ptr)
	/* kernel_compat.sh uses nexport for set_cpus_allowed_ptr() because of
	 * redhat backport madness, but on !SMP machines it's a macro */
	#define set_cpus_allowed_ptr efx_set_cpus_allowed_ptr
	static inline int efx_set_cpus_allowed_ptr(struct task_struct *p,
						   const cpumask_t *new_mask)
	{
	#if !defined(CONFIG_SMP)
		/* Don't use set_cpus_allowed() if present, because 2.6.11-2.6.15
		 * define it using an unexported symbol */
		if (!cpu_isset(0, *new_mask))
			return -EINVAL;
		return 0;
	#else
		return set_cpus_allowed(p, *new_mask);
	#endif
	}
#endif

#ifdef EFX_NEED_KOBJECT_INIT_AND_ADD
	#define kobject_init_and_add efx_kobject_init_and_add
	extern int
	efx_kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
				 struct kobject *parent, const char *fmt, ...);
#endif

#ifdef EFX_NEED_KOBJECT_SET_NAME_VARGS
	#define kobject_set_name_vargs efx_kobject_set_name_vargs
	extern int
	efx_kobject_set_name_vargs(struct kobject *kobj, const char *fmt, va_list vargs);
#endif


#ifdef EFX_NEED_CPUMASK_LOCAL_SPREAD
#if NR_CPUS == 1
static inline unsigned int cpumask_local_spread(unsigned int i, int node)
{
	return 0;
}
#else
unsigned int cpumask_local_spread(unsigned int i, int node);
#endif
#endif

/**************************************************************************
 *
 * Wrappers to fix bugs and parameter changes
 *
 **************************************************************************
 *
 */
#ifdef EFX_NEED_WORK_API_WRAPPERS
	#define delayed_work work_struct
	#undef INIT_DELAYED_WORK
	#define INIT_DELAYED_WORK INIT_WORK
	#undef EFX_USE_CANCEL_DELAYED_WORK_SYNC /* we can't */

	/**
	 * The old and new work-function prototypes just differ
	 * in the type of the pointer returned, so it's safe
	 * to cast between the prototypes.
	 */
	typedef void (*efx_old_work_func_t)(void *p);

	#undef INIT_WORK
	#define INIT_WORK(_work, _func)					\
		do {							\
			INIT_LIST_HEAD(&(_work)->entry);		\
			(_work)->pending = 0;				\
			PREPARE_WORK((_work),				\
				     (efx_old_work_func_t) (_func),	\
				     (_work));				\
			init_timer(&(_work)->timer);                    \
		} while (0)
#endif

#ifdef EFX_NEED_WQ_SYSFS
	#define WQ_SYSFS	0
#endif
#ifndef WQ_MEM_RECLAIM
	#define WQ_MEM_RECLAIM	0
#endif

#ifdef EFX_HAVE_ALLOC_WORKQUEUE
#ifndef EFX_HAVE_NEW_ALLOC_WORKQUEUE
	#define efx_alloc_workqueue(_fmt, _flags, _max, _name)	\
		alloc_workqueue(_name, _flags, _max)
#else
	#define efx_alloc_workqueue(_fmt, _flags, _max, _name)	\
		alloc_workqueue(_fmt, _flags, _max, _name)
#endif
#else
	#define efx_alloc_workqueue(_fmt, _flags, _max, _name)	\
		create_singlethread_workqueue(_name)
#endif

#if defined(EFX_NEED_NETIF_NAPI_DEL)
	static inline void netif_napi_del(struct napi_struct *napi)
	{
	#ifdef CONFIG_NETPOLL
		list_del(&napi->dev_list);
	#endif
	}
#endif

#if defined(EFX_USE_GRO) && defined(EFX_HAVE_NAPI_GRO_RECEIVE_GR)
	/* Redhat backports of functions returning gro_result_t */
	#define napi_gro_frags napi_gro_frags_gr
	#define napi_gro_receive napi_gro_receive_gr
#elif defined(EFX_USE_GRO) && defined(EFX_NEED_GRO_RESULT_T)
	typedef int gro_result_t;

	#define napi_gro_frags(_napi)				\
		({ napi_gro_frags(_napi);			\
		   GRO_MERGED; })
	#define napi_gro_receive(_napi, _skb)			\
		({ napi_gro_receive(_napi, _skb);		\
		   GRO_MERGED; })
#endif
#if defined(EFX_USE_GRO) && (defined(EFX_HAVE_NAPI_GRO_RECEIVE_GR) || defined(EFX_NEED_GRO_RESULT_T))
	/* vlan_gro_{frags,receive} won't return gro_result_t in
	 * either of the above cases.
	 */
	#define vlan_gro_frags(_napi, _group, _tag)		\
		({ vlan_gro_frags(_napi, _group, _tag);		\
		   GRO_MERGED; })
	#define vlan_gro_receive(_napi, _group, _tag, _skb)	\
		({ vlan_gro_receive(_napi, _group, _tag, _skb);	\
		   GRO_MERGED; })
#endif

#ifdef EFX_NEED_HEX_DUMP_CONST_FIX
	#define print_hex_dump(v, s, t, r, g, b, l, a) \
		print_hex_dump((v), (s), (t), (r), (g), (void *)(b), (l), (a))
#endif

#ifdef EFX_NEED_SCSI_SGLIST
	#include <scsi/scsi.h>
	#include <scsi/scsi_cmnd.h>
	#define scsi_sglist(sc)    ((struct scatterlist *)((sc)->request_buffer))
	#define scsi_bufflen(sc)   ((sc)->request_bufflen)
	#define scsi_sg_count(sc)  ((sc)->use_sg)
	static inline void scsi_set_resid(struct scsi_cmnd *sc, int resid)
	{
		sc->resid = resid;
	}
	static inline int scsi_get_resid(struct scsi_cmnd *sc)
	{
		return sc->resid;
	}
#endif


#ifdef EFX_NEED_SG_NEXT
	#define sg_page(sg) ((sg)->page)
	#define sg_next(sg) ((sg) + 1)
	#define for_each_sg(sglist, sg, nr, __i) \
	  for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
#endif

#ifdef EFX_NEED_VMALLOC_NODE
	static inline void *vmalloc_node(unsigned long size, int node)
	{
		return vmalloc(size);
	}
#endif

#ifdef EFX_NEED_VMALLOC_TO_PFN
	static inline unsigned long vmalloc_to_pfn(const void *addr)
	{
		return page_to_pfn(vmalloc_to_page((void *)addr));
	}
#endif

#ifdef EFX_NEED_KVEC
	struct kvec {
		struct iovec iov;
	};
#endif

#ifdef EFX_NEED_KERNEL_SENDMSG
	static inline int kernel_sendmsg(struct socket *sock,
					 struct msghdr *msg,
					 struct kvec *vec, size_t num,
					 size_t size)
	{
		mm_segment_t oldfs = get_fs();
		int result;

		set_fs(KERNEL_DS);
		/* the following is safe, since for compiler definitions of
		 * kvec and iovec are identical, yielding the same in-core
		 * layout and alignment. */
		msg->msg_iov = (struct iovec *)vec;
		msg->msg_iovlen = num;
		result = sock_sendmsg(sock, msg, size);
		set_fs(oldfs);
		return result;
	}
#endif

#ifdef EFX_NEED_ROUNDDOWN_POW_OF_TWO
static inline unsigned long __attribute_const__ rounddown_pow_of_two(unsigned long x)
{
	return 1UL << (fls(x) - 1);
}
#endif

#ifndef order_base_2
#define order_base_2(x) fls((x) - 1)
#endif

#ifndef EFX_HAVE_LIST_SPLICE_TAIL_INIT
	static inline void list_splice_tail_init(struct list_head *list,
						 struct list_head *head)
	{
		if (!list_empty(list)) {
			struct list_head *first = list->next;
			struct list_head *last = list->prev;
			struct list_head *prev = head->prev;

			first->prev = prev;
			prev->next = first;
			last->next = head;
			head->prev = last;

			INIT_LIST_HEAD(list);
		}
	}
#endif

#ifdef EFX_NEED_NETIF_DEVICE_DETACH_ATTACH_MQ
	static inline void efx_netif_device_detach(struct net_device *dev)
	{
		if (test_and_clear_bit(__LINK_STATE_PRESENT, &dev->state) &&
		    netif_running(dev)) {
			netif_tx_stop_all_queues(dev);
		}
	}
	#define netif_device_detach efx_netif_device_detach

	static inline void efx_netif_device_attach(struct net_device *dev)
	{
		/* __netdev_watchdog_up() is not exported, so we have
		 * to call the broken implementation and then start
		 * the remaining queues.
		 */
		if (!test_bit(__LINK_STATE_PRESENT, &dev->state) &&
		    netif_running(dev)) {
			netif_device_attach(dev);
			netif_tx_wake_all_queues(dev);
		}
	}
	#define netif_device_attach efx_netif_device_attach
#endif

#ifdef EFX_NEED___SKB_QUEUE_HEAD_INIT
	static inline void __skb_queue_head_init(struct sk_buff_head *list)
	{
		list->prev = list->next = (struct sk_buff *)list;
		list->qlen = 0;
	}
#endif

#ifdef EFX_NEED_LIST_FIRST_ENTRY
	#define list_first_entry(ptr, type, member) \
		list_entry((ptr)->next, type, member)
#endif

#ifndef list_first_entry_or_null
	#define list_first_entry_or_null(ptr, type, member) \
		(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
#endif

#ifdef EFX_NEED_SKB_COPY_FROM_LINEAR_DATA
	static inline void skb_copy_from_linear_data(const struct sk_buff *skb,
			void *to, const unsigned int len)
		{
			memcpy(to, skb->data, len);
		}
#endif

#ifdef EFX_NEED_NS_TO_TIMESPEC
	struct timespec ns_to_timespec(const s64 nsec);
#endif

#ifdef EFX_NEED_RTC_TIME64_TO_TM
	#include <linux/rtc.h>
	static inline void rtc_time64_to_tm(unsigned long time, struct rtc_time *tm)
	{
		rtc_time_to_tm(time, tm);
	}
#endif

#ifdef EFX_NEED_KTIME_SUB_NS
	#if BITS_PER_LONG == 64 || defined(CONFIG_KTIME_SCALAR)
		#define ktime_sub_ns(kt, nsval) \
				({ (ktime_t){ .tv64 = (kt).tv64 - (nsval) }; })
	#else
		ktime_t ktime_sub_ns(const ktime_t kt, u64 nsec);
	#endif
#endif

#ifdef EFX_HAVE_NET_TSTAMP
	#include <linux/net_tstamp.h>
#else
	#include <linux/in.h>
	#include <linux/ip.h>
	#include <linux/udp.h>
	/**
	 * struct efx_ptp_timestamp - Time stamps of received packets.
	 * @hwtstamp: Hardware (NIC) timestamp
	 * @syststamp: System timestamp
	 */
	struct skb_shared_hwtstamps {
		ktime_t	hwtstamp;
		ktime_t	syststamp;
	};

	static inline struct skb_shared_hwtstamps *skb_hwtstamps(struct sk_buff *skb)
	{
		return (struct skb_shared_hwtstamps *) skb->cb;
	}

	enum {
		SOF_TIMESTAMPING_TX_HARDWARE = (1<<0),
		SOF_TIMESTAMPING_TX_SOFTWARE = (1<<1),
		SOF_TIMESTAMPING_RX_HARDWARE = (1<<2),
		SOF_TIMESTAMPING_RX_SOFTWARE = (1<<3),
		SOF_TIMESTAMPING_SOFTWARE = (1<<4),
		SOF_TIMESTAMPING_SYS_HARDWARE = (1<<5),
		SOF_TIMESTAMPING_RAW_HARDWARE = (1<<6),
		SOF_TIMESTAMPING_MASK =
		(SOF_TIMESTAMPING_RAW_HARDWARE - 1) |
		SOF_TIMESTAMPING_RAW_HARDWARE
	};

	enum hwtstamp_tx_types {
		HWTSTAMP_TX_OFF,
		HWTSTAMP_TX_ON,
		HWTSTAMP_TX_ONESTEP_SYNC,
	};

	enum hwtstamp_rx_filters {
		HWTSTAMP_FILTER_NONE,
		HWTSTAMP_FILTER_ALL,
		HWTSTAMP_FILTER_SOME,
		HWTSTAMP_FILTER_PTP_V1_L4_EVENT,
		HWTSTAMP_FILTER_PTP_V1_L4_SYNC,
		HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ,
		HWTSTAMP_FILTER_PTP_V2_L4_EVENT,
		HWTSTAMP_FILTER_PTP_V2_L4_SYNC,
		HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ,
		HWTSTAMP_FILTER_PTP_V2_L2_EVENT,
		HWTSTAMP_FILTER_PTP_V2_L2_SYNC,
		HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ,
		HWTSTAMP_FILTER_PTP_V2_EVENT,
		HWTSTAMP_FILTER_PTP_V2_SYNC,
		HWTSTAMP_FILTER_PTP_V2_DELAY_REQ,
	};

	struct hwtstamp_config {
		int flags;
		int tx_type;
		int rx_filter;
	};
#endif

#ifndef EFX_HAVE_TIMESPEC64
#ifdef EFX_NEED_TIMESPEC_ADD_NS
	static inline void timespec_add_ns(struct timespec *a, u64 ns)
	{
		ns += a->tv_nsec;
		while (unlikely(ns >= NSEC_PER_SEC)) {
			ns -= NSEC_PER_SEC;
			a->tv_sec++;
		}
		a->tv_nsec = ns;
	}
#endif

#ifdef EFX_NEED_SET_NORMALIZED_TIMESPEC
	/* set_normalized_timespec() might be defined by the kernel
	 * but not exported.  Define it under our own name.
	 */
	static inline void
	efx_set_normalized_timespec(struct timespec *ts, time_t sec, long nsec)
	{
		while (nsec >= NSEC_PER_SEC) {
			nsec -= NSEC_PER_SEC;
			++sec;
		}
		while (nsec < 0) {
			nsec += NSEC_PER_SEC;
			--sec;
		}
		ts->tv_sec = sec;
		ts->tv_nsec = nsec;
	}
	#define set_normalized_timespec efx_set_normalized_timespec
#endif

#ifdef EFX_NEED_SET_NORMALIZED_TIMESPEC
	/* timespec_sub() may need to be redefined because of
	 * set_normalized_timespec() not being exported.  Define it
	 * under our own name.
	 */
	static inline struct timespec efx_timespec_sub(struct timespec lhs,
		struct timespec rhs)
	{
		struct timespec ts_delta;
		set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec,
		lhs.tv_nsec - rhs.tv_nsec);
		return ts_delta;
	}
	#define timespec_sub efx_timespec_sub
#endif


	#define timespec64		timespec
	#define timespec64_compare	timespec_compare
	#define timespec64_add_ns	timespec_add_ns
	#define timespec64_sub		timespec_sub
	#define ns_to_timespec64	ns_to_timespec
	#define timespec64_to_ns	timespec_to_ns
	#define ktime_to_timespec64	ktime_to_timespec
	#define timespec64_to_ktime	timespec_to_ktime
	#define timespec_to_timespec64(t) (t)
	#define timespec64_to_timespec(t) (t)
#endif // EFX_HAVE_TIMESPEC64
#ifdef EFX_NEED_KTIME_GET_REAL_TS64
	static inline void efx_ktime_get_real_ts64(struct timespec64 *ts64)
	{
		struct timespec ts;
		ktime_get_real_ts(&ts);
		*ts64 = timespec_to_timespec64(ts);
	}

	#define ktime_get_real_ts64 efx_ktime_get_real_ts64
#endif // EFX_NEED_KTIME_GET_REAL_TS64

#ifdef EFX_HAVE_OLD_SKB_LINEARIZE
	static inline int efx_skb_linearize(struct sk_buff *skb)
	{
		return skb_linearize(skb, GFP_ATOMIC);
	}
	#define skb_linearize efx_skb_linearize
#endif

#ifdef EFX_HAVE_OLD_SKB_CHECKSUM_HELP
	static inline int efx_skb_checksum_help(struct sk_buff *skb)
	{
		return skb_checksum_help(skb, 0);
	}
	#define skb_checksum_help efx_skb_checksum_help
#endif

#ifdef EFX_HAVE_OLDER_SKB_CHECKSUM_HELP
	static inline int efx_skb_checksum_help(struct sk_buff *skb)
	{
		return skb_checksum_help(&skb, 0);
	}
	#define skb_checksum_help efx_skb_checksum_help
#endif

#if defined(CONFIG_X86) && NET_IP_ALIGN != 0
	#undef NET_IP_ALIGN
	#define NET_IP_ALIGN 0
#endif

#ifndef EFX_HAVE_FDTABLE
#define fdtable files_struct
#define files_fdtable(files) (files)
#endif

#ifndef EFX_HAVE_REMAP_PFN_RANGE
#define remap_pfn_range remap_page_range
#endif

#if defined(EFX_HAVE_OLD___VLAN_PUT_TAG)
	static inline struct sk_buff *
	efx___vlan_put_tag(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)
	{
		WARN_ON(vlan_proto != htons(ETH_P_8021Q));
		return __vlan_put_tag(skb, vlan_tci);
	}
	#define vlan_insert_tag_set_proto efx___vlan_put_tag
#elif !defined(EFX_HAVE_VLAN_INSERT_TAG_SET_PROTO)
	static inline struct sk_buff *
	vlan_insert_tag_set_proto(struct sk_buff *skb, __be16 vlan_proto,
			u16 vlan_tci)
	{
		return __vlan_put_tag(skb, vlan_proto, vlan_tci);
	}
#endif

#if defined(EFX_HAVE_FDTABLE_PARTIAL_ACCESSORS) && !defined(EFX_HAVE_FDTABLE_FULL_ACCESSORS)
#include <linux/fdtable.h>
static inline void efx_set_close_on_exec(int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->close_on_exec);
}

static inline void efx_clear_close_on_exec(int fd, struct fdtable *fdt)
{
	__clear_bit(fd, fdt->close_on_exec);
}

static inline bool efx_close_on_exec(int fd, const struct fdtable *fdt)
{
	return close_on_exec(fd, fdt);
}

static inline void efx_set_open_fd(int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->open_fds);
}

static inline void efx_clear_open_fd(int fd, struct fdtable *fdt)
{
	__clear_bit(fd, fdt->open_fds);
}

static inline bool efx_fd_is_open(int fd, const struct fdtable *fdt)
{
	return fd_is_open(fd, fdt);
}

static inline unsigned long efx_get_open_fds(int fd, const struct fdtable *fdt)
{
	return fdt->open_fds[fd];
}
#elif defined(EFX_HAVE_FDTABLE_FULL_ACCESSORS)
#include <linux/fdtable.h>
static inline void efx_set_close_on_exec(int fd, struct fdtable *fdt)
{
	__set_close_on_exec(fd, fdt);
}

static inline void efx_clear_close_on_exec(int fd, struct fdtable *fdt)
{
	__clear_close_on_exec(fd, fdt);
}

static inline bool efx_close_on_exec(int fd, const struct fdtable *fdt)
{
	return close_on_exec(fd, fdt);
}

static inline void efx_set_open_fd(int fd, struct fdtable *fdt)
{
	__set_open_fd(fd, fdt);
}

static inline void efx_clear_open_fd(int fd, struct fdtable *fdt)
{
	__clear_open_fd(fd, fdt);
}

static inline bool efx_fd_is_open(int fd, const struct fdtable *fdt)
{
	return fd_is_open(fd, fdt);
}

static inline unsigned long efx_get_open_fds(int fd, const struct fdtable *fdt)
{
	return fdt->open_fds[fd];
}
#else
#ifdef EFX_HAVE_FDTABLE_H
#include <linux/fdtable.h>
#else
#include <linux/file.h>
#endif
static inline void efx_set_close_on_exec(unsigned long fd, struct fdtable *fdt)
{
	FD_SET(fd, fdt->close_on_exec);
}

static inline void efx_clear_close_on_exec(unsigned long fd, struct fdtable *fdt)
{
	FD_CLR(fd, fdt->close_on_exec);
}

static inline bool efx_close_on_exec(unsigned long fd, const struct fdtable *fdt)
{
	return FD_ISSET(fd, fdt->close_on_exec);
}

static inline void efx_set_open_fd(unsigned long fd, struct fdtable *fdt)
{
	FD_SET(fd, fdt->open_fds);
}

static inline void efx_clear_open_fd(unsigned long fd, struct fdtable *fdt)
{
	FD_CLR(fd, fdt->open_fds);
}

static inline bool efx_fd_is_open(unsigned long fd, const struct fdtable *fdt)
{
	return FD_ISSET(fd, fdt->open_fds);
}

static inline unsigned long efx_get_open_fds(unsigned long fd, const struct fdtable *fdt)
{
	return fdt->open_fds->fds_bits[fd];
}
#endif

#ifdef EFX_HAVE_ASM_SYSTEM_H
#include <asm/system.h>
#endif

#ifdef EFX_HAVE_PPS_KERNEL
	#include <linux/pps_kernel.h>
#endif

#ifdef EFX_NEED_PPS_EVENT_TIME
	struct pps_event_time {
	#ifdef CONFIG_NTP_PPS
		struct timespec ts_raw;
	#endif /* CONFIG_NTP_PPS */
		struct timespec ts_real;
	};
#endif

#ifdef EFX_NEED_PPS_GET_TS
#ifdef CONFIG_NTP_PPS
	static inline void pps_get_ts(struct pps_event_time *ts)
	{
		getnstime_raw_and_real(&ts->ts_raw, &ts->ts_real);
	}
#else /* CONFIG_NTP_PPS */
	static inline void pps_get_ts(struct pps_event_time *ts)
	{
		getnstimeofday(&ts->ts_real);
	}
#endif /* CONFIG_NTP_PPS */
#endif

#ifdef EFX_NEED_PPS_SUB_TS
	static inline void pps_sub_ts(struct pps_event_time *ts, struct timespec delta)
	{
		ts->ts_real = timespec_sub(ts->ts_real, delta);
	#ifdef CONFIG_NTP_PPS
		ts->ts_raw = timespec_sub(ts->ts_raw, delta);
	#endif
	}
#endif

#ifndef EFX_HAVE_PHC_SUPPORT
	struct ptp_clock_time {
		__s64 sec;
		__u32 nsec;
		__u32 reserved;
	};

	struct ptp_extts_request {
		unsigned int index;
		unsigned int flags;
		unsigned int rsv[2];
	};

	struct ptp_perout_request {
		struct ptp_clock_time start;
		struct ptp_clock_time period;
		unsigned int index;
		unsigned int flags;
		unsigned int rsv[4];
	};

	struct ptp_clock_request {
		enum {
			PTP_CLK_REQ_EXTTS,
			PTP_CLK_REQ_PEROUT,
			PTP_CLK_REQ_PPS,
		} type;
		union {
			struct ptp_extts_request extts;
			struct ptp_perout_request perout;
		};
	};

	struct ptp_clock_info {
	};
#else
#include <linux/ptp_clock_kernel.h>
#endif

#ifdef EFX_NEED_PTP_CLOCK_PPSUSR
#define PTP_CLOCK_PPSUSR (PTP_CLOCK_PPS + 1)
#endif

#ifdef EFX_HAVE_NON_CONST_JHASH2
	static inline u32 efx_jhash2(const u32 *k, u32 length, u32 initval)
	{
		return jhash2((u32 *)k, length, initval);
	}
	#define jhash2 efx_jhash2
#endif

#ifdef EFX_NEED_RCU_ACCESS_POINTER
#define rcu_access_pointer rcu_dereference
#endif

#ifdef EFX_NEED_CPU_ONLINE_MASK
#define cpu_online_mask (&cpu_online_map)
#endif

#ifndef EFX_HAVE_PCI_VFS_ASSIGNED
int pci_vfs_assigned(struct pci_dev *dev);
#endif

#ifdef EFX_NEED_PCI_ENABLE_MSIX_RANGE
/**
 * pci_enable_msix_range - configure device's MSI-X capability structure
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * @entries: pointer to an array of MSI-X entries
 * @minvec: minimum number of MSI-X irqs requested
 * @maxvec: maximum number of MSI-X irqs requested
 *
 * Setup the MSI-X capability structure of device function with a maximum
 * possible number of interrupts in the range between @minvec and @maxvec
 * upon its software driver call to request for MSI-X mode enabled on its
 * hardware device function. It returns a negative errno if an error occurs.
 * If it succeeds, it returns the actual number of interrupts allocated and
 * indicates the successful configuration of MSI-X capability structure
 * with new allocated MSI-X interrupts.
 *
 * NOTE: This is implemented inline here since it is also used by onload.
 **/
static inline int pci_enable_msix_range(struct pci_dev *dev,
					struct msix_entry *entries,
					int minvec, int maxvec)
{
	int nvec = maxvec;
	int rc;

	if (maxvec < minvec)
		return -ERANGE;

	do {
		rc = pci_enable_msix(dev, entries, nvec);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			if (rc < minvec)
				return -ENOSPC;
			nvec = rc;
		}
	} while (rc);

	return nvec;
}
#endif
#ifdef EFX_NEED_PCI_MSIX_VEC_COUNT
int pci_msix_vec_count(struct pci_dev *dev);
#endif

#ifdef EFX_NEED_KMALLOC_ARRAY
#define kmalloc_array(n,s,f) kcalloc(n,s,f)
#endif

/* 3.19 renamed netdev_phys_port_id to netdev_phys_item_id */
#ifndef MAX_PHYS_ITEM_ID_LEN
#define MAX_PHYS_ITEM_ID_LEN MAX_PHYS_PORT_ID_LEN
#define netdev_phys_item_id netdev_phys_port_id
#endif

#ifdef ETH_RSS_HASH_TOP
#define EFX_HAVE_CONFIGURABLE_RSS_HASH
#else
#define ETH_RSS_HASH_NO_CHANGE 0
#define ETH_RSS_HASH_TOP       1
#endif

/* Some functions appear in either net_device_ops or in net_device_ops_ext. The
 * latter is used in RHEL for backported features. To simplify conditionals
 * elsewhere, we merge them here.
 */
#if defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID) || defined(EFX_HAVE_NET_DEVICE_OPS_EXT_GET_PHYS_PORT_ID)
#define EFX_NEED_GET_PHYS_PORT_ID
#endif

#ifdef EFX_NEED_SKB_GSO_TCPV6
#define SKB_GSO_TCPV6 0
#endif

#ifdef EFX_NEED_SKB_IS_GSO_TCP
static inline bool skb_is_gso_tcp(const struct sk_buff *skb)
{
	return skb_is_gso(skb) &&
	       skb_shinfo(skb)->gso_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6);
}
#endif

#ifdef EFX_NEED_IS_ERR_OR_NULL
static inline bool __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}
#endif

#ifdef EFX_NEED_NETDEV_RSS_KEY_FILL
#define netdev_rss_key_fill get_random_bytes
#endif

#ifndef smp_mb__before_atomic
#ifdef CONFIG_X86
/* As in arch/x86/include/asm/barrier.h */
#define smp_mb__before_atomic() barrier()
#else
/* As in include/asm-generic/barrier.h and arch/powerpc/include/asm/barrier.h */
#define smp_mb__before_atomic() smp_mb()
#endif
#endif

#ifndef READ_ONCE
#define READ_ONCE(x) ACCESS_ONCE((x))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v) (ACCESS_ONCE((x)) = (v))
#endif

#ifndef NUMA_NO_NODE
#define NUMA_NO_NODE (-1)
#endif

#if !defined(CONFIG_HAVE_MEMORYLESS_NODES) && !defined(cpu_to_mem)
#define cpu_to_mem(cpu) cpu_to_node(cpu)
#endif

#ifndef IS_ENABLED
/* As in include/linux/kconfig.h */
#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg) _config_enabled(cfg)
#define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
#define ___config_enabled(__ignored, val, ...) val

#define IS_ENABLED(option)	(config_enabled(option) ||	\
				 config_enabled(option##_MODULE))
#endif

#ifndef EFX_HAVE_NETIF_XMIT_STOPPED
#define netif_xmit_stopped netif_tx_queue_stopped
#endif

#ifdef EFX_HAVE_HW_ENC_FEATURES
#ifdef EFX_NEED_SKB_INNER_TRANSPORT_OFFSET
static inline int skb_inner_transport_offset(const struct sk_buff *skb)
{
	return skb_inner_transport_header(skb) - skb->data;
}
#endif
#endif

#ifndef QSTR_INIT
#define QSTR_INIT(n,l) { .len = l, .name = n }
#endif

#ifdef EFX_HAVE_NETDEV_REGISTER_RH
/* The _rh versions of these appear in RHEL7.3.
 * Wrap them to make the calling code simpler.
 */
static inline int efx_register_netdevice_notifier(struct notifier_block *b)
{
	return register_netdevice_notifier_rh(b);
}

static inline int efx_unregister_netdevice_notifier(struct notifier_block *b)
{
	return unregister_netdevice_notifier_rh(b);
}

#define register_netdevice_notifier efx_register_netdevice_notifier
#define unregister_netdevice_notifier efx_unregister_netdevice_notifier
#endif

#ifdef EFX_HAVE_NAPI_HASH_ADD
/* napi_hash_add appeared in 3.11 and is no longer exported as of 4.10.
 *
 * Although newer versions of netif_napi_add call napi_hash_add we can still
 * call napi_hash_add here regardless, since there is a state bit to avoid
 * double adds.
 */
static inline void efx_netif_napi_add(struct net_device *dev,
				      struct napi_struct *napi,
				      int (*poll)(struct napi_struct *, int),
				      int weight)
{
	netif_napi_add(dev, napi, poll, weight);
	napi_hash_add(napi);
}
#ifdef netif_napi_add
/* RHEL7.3 defines netif_napi_add as _netif_napi_add for KABI compat. */
#define _netif_napi_add efx_netif_napi_add
#else
#define netif_napi_add efx_netif_napi_add
#endif

/* napi_hash_del still exists as of 4.10, even though napi_hash_add has gone.
 * This is because it returns whether an RCU grace period is needed, allowing
 * drivers to coalesce them. We don't do this.
 *
 * Although newer versions of netif_napi_del() call napi_hash_del() already
 * this is safe - it uses a state bit to determine if it needs deleting.
 */
static inline void efx_netif_napi_del(struct napi_struct *napi)
{
	might_sleep();
#ifndef EFX_HAVE_NAPI_HASH_DEL_RETURN
	napi_hash_del(napi);
	if (1) /* Always call synchronize_net */
#else
	if (napi_hash_del(napi))
#endif
		synchronize_net();
	netif_napi_del(napi);
}
#define netif_napi_del efx_netif_napi_del
#endif

#ifndef tcp_flag_byte
#define tcp_flag_byte(th) (((u_int8_t *)th)[13])
#endif

#ifndef TCPHDR_FIN
#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80
#endif

#if defined(EFX_HAVE_NDO_BUSY_POLL) || defined(EFX_HAVE_NDO_EXT_BUSY_POLL)
/* Combined define for driver-based busy poll. Later kernels (4.11+) implement
 * busy polling in the core.
 */
#define EFX_WANT_DRIVER_BUSY_POLL
#endif

#if defined(EFX_NEED_BOOL_NAPI_COMPLETE_DONE)
static inline bool efx_napi_complete_done(struct napi_struct *napi,
					  int spent __always_unused)
{
	napi_complete(napi);
	return true;
}
#define napi_complete_done efx_napi_complete_done
#endif

#if defined(EFX_NEED_HWMON_DEVICE_REGISTER_WITH_INFO)
struct hwmon_chip_info;
struct attribute_group;

enum hwmon_sensor_types {
	hwmon_chip,
	hwmon_temp,
	hwmon_in,
	hwmon_curr,
	hwmon_power,
	hwmon_energy,
	hwmon_humidity,
	hwmon_fan,
	hwmon_pwm,
};

#ifdef EFX_HAVE_HWMON_CLASS_DEVICE
#define EFX_HWMON_DEVICE_REGISTER_TYPE class_device
#else
#define EFX_HWMON_DEVICE_REGISTER_TYPE device
#endif

struct EFX_HWMON_DEVICE_REGISTER_TYPE *hwmon_device_register_with_info(
	struct device *dev,
	const char *name __always_unused,
	void *drvdata __always_unused,
	const struct hwmon_chip_info *info __always_unused,
	const struct attribute_group **extra_groups __always_unused);
#else
#if defined(EFX_NEED_HWMON_T_ALARM)
#define HWMON_T_ALARM	BIT(hwmon_temp_alarm)
#endif
#endif
/* For RHEL 6 and 7 the above takes care of hwmon_device_register_with_info(),
 * but they are missing the read_string() API in struct hwmon_ops.
 */
#if defined(HWMON_T_MIN) && (defined(EFX_HAVE_HWMON_READ_STRING) ||	\
			     defined(EFX_HAVE_HWMON_READ_STRING_CONST))
#define EFX_HAVE_HWMON_DEVICE_REGISTER_WITH_INFO
#endif

#if defined(EFX_HAVE_XDP_EXT)
/* RHEL 7 adds the XDP related NDOs in the net_device_ops_extended area.
 * The XDP interfaces in RHEL 7 are merely stubs intended to make Red Hat's
 * backporting easier, and XDP is not functional. So we can just not build
 * XDP in this case.
 * It's unlikely that anybody else will have a net_device_ops_extended in
 * this way.
 */
#undef EFX_HAVE_XDP
#undef EFX_HAVE_XDP_HEAD
#undef EFX_HAVE_XDP_OLD
#undef EFX_HAVE_XDP_REDIR
#undef EFX_HAVE_XDP_TX
#endif

#ifdef EFX_HAVE_XDP_TX
#ifndef EFX_HAVE_XDP_FRAME_API
#define xdp_frame	xdp_buff
#endif
#endif

#if defined(EFX_HAVE_XDP_OLD)
/* ndo_xdp and netdev_xdp were renamed in 4.15 */
#define ndo_bpf	ndo_xdp
#define netdev_bpf netdev_xdp
#define EFX_HAVE_XDP
#endif

#if defined(EFX_HAVE_XDP) && !defined(EFX_HAVE_XDP_TRACE)
#define trace_xdp_exception(dev, prog, act)
#endif

#if !defined(EFX_HAVE_XDP_HEAD) && !defined(XDP_PACKET_HEADROOM)
#define XDP_PACKET_HEADROOM 0
#endif

#ifndef EFX_HAVE_XDP_RXQ_INFO_NAPI_ID
#define xdp_rxq_info_reg(_i,_d,_q,_n)	xdp_rxq_info_reg(_i,_d,_q)
#endif

#ifdef EFX_NEED_VOID_SKB_PUT
static inline void *efx_skb_put(struct sk_buff *skb, unsigned int len)
{
	return skb_put(skb, len);
}
#define skb_put efx_skb_put
#endif

#ifndef DEFINE_RATELIMIT_STATE
/* No rate limitation */
#define DEFINE_RATELIMIT_STATE(var, i, b)	int var = 1
#define __ratelimit(varp)			(*varp)
#endif

#if defined(EFX_NEED_PAGE_FRAG_FREE)
#if defined(EFX_HAVE_FREE_PAGE_FRAG)
/* Renamed in v4.10 */
#define page_frag_free __free_page_frag
#else
static inline void page_frag_free(void *p)
{
	put_page(virt_to_head_page(p));
}
#endif
#endif

#ifndef BIT_ULL
#define BIT_ULL(nr)		(1ULL << (nr))
#endif

#ifdef EFX_NEED_PCI_DEV_TO_EEH_DEV
#define pci_dev_to_eeh_dev(pci_dev) \
	of_node_to_eeh_dev(pci_device_to_OF_node((pci_dev)))
#endif

#ifndef USER_TICK_USEC
#define USER_TICK_USEC TICK_USEC
#endif

#ifdef EFX_HAVE_NETIF_SET_XPS_QUEUE_NON_CONST
static inline int efx_netif_set_xps_queue(struct net_device *netdev,
					  const struct cpumask *mask, u16 index)
{
	/* De-constify the mask */
	return netif_set_xps_queue(netdev, (struct cpumask*)mask, index);
}
#define netif_set_xps_queue efx_netif_set_xps_queue
#endif

#ifdef EFX_HAVE_OLD_DEV_OPEN
static inline int efx_dev_open(struct net_device *netdev,
			       void *unused __always_unused)
{
	return dev_open(netdev);
}
#define dev_open efx_dev_open
#endif

#ifdef EFX_NEED_CONSUME_SKB_ANY
#define dev_consume_skb_any(skb) dev_kfree_skb_any(skb)
#endif

#ifdef EFX_NEED_SKB_CHECKSUM_START_OFFSET
static inline int skb_checksum_start_offset(const struct sk_buff *skb)
{
	return skb->csum_start - skb_headroom(skb);
}
#endif

#ifdef EFX_NEED_CSUM16_SUB
static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	u16 res = (__force u16)csum;

	res += (__force u16)addend;
	return (__force __sum16)(res + (res < (__force u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}
#endif

#ifdef EFX_NEED_CSUM_REPLACE_BY_DIFF
static inline void csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
	*sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}
#endif

#ifndef EFX_HAVE_STRUCT_SIZE
/* upstream version of this checks for overflow, but that's too much machinery
 * to replicate for older kernels.
 */
#define struct_size(p, member, n)	(sizeof(*(p)) + n * sizeof(*(p)->member))
#endif

/* Several kernel features are needed for TC offload to work.  Only enable it
 * if we have all of them.
 */
#ifdef EFX_HAVE_NEW_NDO_SETUP_TC
#if defined(EFX_HAVE_TC_BLOCK_OFFLOAD) || defined(EFX_HAVE_FLOW_BLOCK_OFFLOAD)
#if !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER) || defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_ALLOC)
#define EFX_TC_OFFLOAD	yes
/* Further features needed for conntrack offload */
#if defined(EFX_HAVE_NF_FLOW_TABLE_OFFLOAD) && defined(EFX_HAVE_TC_ACT_CT)
#define EFX_CONNTRACK_OFFLOAD	yes
#endif
#endif
#endif
#endif

/* We only need netif_is_{vxlan,geneve} & flow_rule_match_cvlan if we have TC offload support */
#ifdef EFX_TC_OFFLOAD
#ifndef EFX_HAVE_FLOW_BLOCK_OFFLOAD
/* Old names of structs... */
#define	flow_block_offload	tc_block_offload
#define flow_block		tcf_block
#define flow_cls_offload	tc_cls_flower_offload
/* ... accessors... */
#define flow_cls_offload_flow_rule	tc_cls_flower_offload_flow_rule
/* ... and enumerators */
#define FLOW_CLS_REPLACE	TC_CLSFLOWER_REPLACE
#define FLOW_CLS_DESTROY	TC_CLSFLOWER_DESTROY
#define FLOW_CLS_STATS		TC_CLSFLOWER_STATS
#endif
#ifndef EFX_HAVE_TC_CAN_EXTACK
#include <net/pkt_cls.h>
static inline bool tc_can_offload_extack(const struct net_device *dev,
					 struct netlink_ext_ack *extack)
{
	bool can = tc_can_offload(dev);

	if (!can)
		NL_SET_ERR_MSG(extack, "TC offload is disabled on net device");

	return can;
}
#endif
#ifdef EFX_HAVE_TC_INDR_BLOCK_CB_REGISTER
#define __flow_indr_block_cb_register	__tc_indr_block_cb_register
#define __flow_indr_block_cb_unregister	__tc_indr_block_cb_unregister
#define EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER	yes
#endif
#ifndef EFX_HAVE_NETIF_IS_VXLAN
static inline bool netif_is_vxlan(const struct net_device *dev)
{
	return dev->rtnl_link_ops &&
	       !strcmp(dev->rtnl_link_ops->kind, "vxlan");
}
#endif
#ifndef EFX_HAVE_NETIF_IS_GENEVE
static inline bool netif_is_geneve(const struct net_device *dev)
{
	return dev->rtnl_link_ops &&
	       !strcmp(dev->rtnl_link_ops->kind, "geneve");
}
#endif
#ifdef EFX_NEED_IDA_ALLOC_RANGE
#define ida_alloc_range	ida_simple_get
#define ida_free	ida_simple_remove
#endif
#ifdef EFX_HAVE_TC_FLOW_OFFLOAD
#ifdef EFX_NEED_FLOW_RULE_MATCH_CVLAN
#include <net/flow_offload.h>
static inline void flow_rule_match_cvlan(const struct flow_rule *rule,
					 struct flow_match_vlan *out)
{
	const struct flow_match *m = &rule->match;
	struct flow_dissector *d = m->dissector;

	out->key = skb_flow_dissector_target(d, FLOW_DISSECTOR_KEY_CVLAN, m->key);
	out->mask = skb_flow_dissector_target(d, FLOW_DISSECTOR_KEY_CVLAN, m->mask);
}
#endif
#if defined(EFX_NEED_FLOW_RULE_MATCH_CT) && defined(EFX_CONNTRACK_OFFLOAD)
#include <net/flow_offload.h>
struct flow_match_ct {
	struct flow_dissector_key_ct *key, *mask;
};
static inline void flow_rule_match_ct(const struct flow_rule *rule,
				      struct flow_match_ct *out)
{
	const struct flow_match *m = &rule->match;
	struct flow_dissector *d = m->dissector;

	out->key = skb_flow_dissector_target(d, FLOW_DISSECTOR_KEY_CT, m->key);
	out->mask = skb_flow_dissector_target(d, FLOW_DISSECTOR_KEY_CT, m->mask);
}
#endif
#else /* EFX_HAVE_TC_FLOW_OFFLOAD */
#include <net/flow_dissector.h>
#include <net/pkt_cls.h>

struct flow_match {
	struct flow_dissector	*dissector;
	void			*mask;
	void			*key;
};

struct flow_match_basic {
	struct flow_dissector_key_basic *key, *mask;
};

struct flow_match_control {
	struct flow_dissector_key_control *key, *mask;
};

struct flow_match_eth_addrs {
	struct flow_dissector_key_eth_addrs *key, *mask;
};

struct flow_match_vlan {
	struct flow_dissector_key_vlan *key, *mask;
};

struct flow_match_ipv4_addrs {
	struct flow_dissector_key_ipv4_addrs *key, *mask;
};

struct flow_match_ipv6_addrs {
	struct flow_dissector_key_ipv6_addrs *key, *mask;
};

struct flow_match_ip {
	struct flow_dissector_key_ip *key, *mask;
};

struct flow_match_ports {
	struct flow_dissector_key_ports *key, *mask;
};

struct flow_match_icmp {
	struct flow_dissector_key_icmp *key, *mask;
};

struct flow_match_tcp {
	struct flow_dissector_key_tcp *key, *mask;
};

struct flow_match_mpls {
	struct flow_dissector_key_mpls *key, *mask;
};

struct flow_match_enc_keyid {
	struct flow_dissector_key_keyid *key, *mask;
};

struct flow_rule;

void flow_rule_match_basic(const struct flow_rule *rule,
			   struct flow_match_basic *out);
void flow_rule_match_control(const struct flow_rule *rule,
			     struct flow_match_control *out);
void flow_rule_match_eth_addrs(const struct flow_rule *rule,
			       struct flow_match_eth_addrs *out);
void flow_rule_match_vlan(const struct flow_rule *rule,
			  struct flow_match_vlan *out);
#ifdef EFX_HAVE_FLOW_DISSECTOR_KEY_CVLAN
void flow_rule_match_cvlan(const struct flow_rule *rule,
			   struct flow_match_vlan *out);
#endif
void flow_rule_match_ipv4_addrs(const struct flow_rule *rule,
				struct flow_match_ipv4_addrs *out);
void flow_rule_match_ipv6_addrs(const struct flow_rule *rule,
				struct flow_match_ipv6_addrs *out);
void flow_rule_match_ip(const struct flow_rule *rule,
			struct flow_match_ip *out);
void flow_rule_match_ports(const struct flow_rule *rule,
			   struct flow_match_ports *out);
void flow_rule_match_tcp(const struct flow_rule *rule,
			 struct flow_match_tcp *out);
void flow_rule_match_icmp(const struct flow_rule *rule,
			  struct flow_match_icmp *out);
void flow_rule_match_mpls(const struct flow_rule *rule,
			  struct flow_match_mpls *out);
void flow_rule_match_enc_control(const struct flow_rule *rule,
				 struct flow_match_control *out);
void flow_rule_match_enc_ipv4_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv4_addrs *out);
void flow_rule_match_enc_ipv6_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv6_addrs *out);
#ifdef EFX_HAVE_FLOW_DISSECTOR_KEY_ENC_IP
void flow_rule_match_enc_ip(const struct flow_rule *rule,
			    struct flow_match_ip *out);
#endif
void flow_rule_match_enc_ports(const struct flow_rule *rule,
			       struct flow_match_ports *out);
void flow_rule_match_enc_keyid(const struct flow_rule *rule,
			       struct flow_match_enc_keyid *out);

enum flow_action_id {
	FLOW_ACTION_ACCEPT		= 0,
	FLOW_ACTION_DROP,
	FLOW_ACTION_TRAP,
	FLOW_ACTION_GOTO,
	FLOW_ACTION_REDIRECT,
	FLOW_ACTION_MIRRED,
	FLOW_ACTION_VLAN_PUSH,
	FLOW_ACTION_VLAN_POP,
	FLOW_ACTION_VLAN_MANGLE,
	FLOW_ACTION_TUNNEL_ENCAP,
	FLOW_ACTION_TUNNEL_DECAP,
	FLOW_ACTION_MANGLE,
	FLOW_ACTION_ADD,
	FLOW_ACTION_CSUM,
	FLOW_ACTION_MARK,
	FLOW_ACTION_WAKE,
	FLOW_ACTION_QUEUE,
	FLOW_ACTION_SAMPLE,
	FLOW_ACTION_POLICE,
};

/* This is mirroring enum pedit_header_type definition for easy mapping between
 * tc pedit action. Legacy TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK is mapped to
 * FLOW_ACT_MANGLE_UNSPEC, which is supported by no driver.
 */
enum flow_action_mangle_base {
	FLOW_ACT_MANGLE_UNSPEC		= 0,
	FLOW_ACT_MANGLE_HDR_TYPE_ETH,
	FLOW_ACT_MANGLE_HDR_TYPE_IP4,
	FLOW_ACT_MANGLE_HDR_TYPE_IP6,
	FLOW_ACT_MANGLE_HDR_TYPE_TCP,
	FLOW_ACT_MANGLE_HDR_TYPE_UDP,
};

struct flow_action_entry {
	enum flow_action_id		id;
	union {
		u32			chain_index;	/* FLOW_ACTION_GOTO */
		struct net_device	*dev;		/* FLOW_ACTION_REDIRECT */
		struct {				/* FLOW_ACTION_VLAN */
			u16		vid;
			__be16		proto;
			u8		prio;
		} vlan;
		struct {				/* FLOW_ACTION_PACKET_EDIT */
			enum flow_action_mangle_base htype;
			u32		offset;
			u32		mask;
			u32		val;
		} mangle;
		const struct ip_tunnel_info *tunnel;	/* FLOW_ACTION_TUNNEL_ENCAP */
		u32			csum_flags;	/* FLOW_ACTION_CSUM */
		u32			mark;		/* FLOW_ACTION_MARK */
		struct {				/* FLOW_ACTION_QUEUE */
			u32		ctx;
			u32		index;
			u8		vf;
		} queue;
		struct {				/* FLOW_ACTION_SAMPLE */
			struct psample_group	*psample_group;
			u32			rate;
			u32			trunc_size;
			bool			truncate;
		} sample;
		struct {				/* FLOW_ACTION_POLICE */
			s64			burst;
			u64			rate_bytes_ps;
		} police;
	};
};

struct flow_action {
	unsigned int			num_entries;
	struct flow_action_entry 	entries[0];
};

#define flow_action_for_each(__i, __act, __actions)			\
        for (__i = 0, __act = &(__actions)->entries[0]; __i < (__actions)->num_entries; __act = &(__actions)->entries[++__i])

struct flow_rule {
	struct flow_match	match;
	struct flow_action	action;
};

static inline bool flow_rule_match_key(const struct flow_rule *rule,
				       enum flow_dissector_key_id key)
{
	return dissector_uses_key(rule->match.dissector, key);
}

struct flow_rule *efx_compat_flow_rule_build(struct tc_cls_flower_offload *tc);
#endif /* EFX_HAVE_TC_FLOW_OFFLOAD */
#endif /* EFX_TC_OFFLOAD */

#ifndef EFX_HAVE_NETDEV_XMIT_MORE
#ifdef EFX_HAVE_SKB_XMIT_MORE
/* This relies on places that use netdev_xmit_more having an SKB structure
 * called skb.
 */
#define netdev_xmit_more()  (skb->xmit_more)
#else
#define netdev_xmit_more()  (0)
#endif
#endif

#ifndef EFX_HAVE_RECEIVE_SKB_LIST
#ifdef EFX_HAVE_SKB__LIST
#ifdef EFX_NEED_SKB_LIST_DEL_INIT
static inline void skb_list_del_init(struct sk_buff *skb)
{
	__list_del_entry(&skb->list);
	skb->next = NULL;
}
#endif

static inline void netif_receive_skb_list(struct list_head *head)
{
	struct sk_buff *skb, *next;

	list_for_each_entry_safe(skb, next, head, list) {
		skb_list_del_init(skb);
		netif_receive_skb(skb);
	}
}
#else
static inline void netif_receive_skb_list(struct sk_buff_head *head)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(head)))
		netif_receive_skb(skb);
}
#endif
#endif

#ifdef EFX_NEED_SKB_MARK_NOT_ON_LIST
static inline void skb_mark_not_on_list(struct sk_buff *skb)
{
	skb->next = NULL;
}
#endif

#ifndef skb_list_walk_safe
/* Iterate through singly-linked GSO fragments of an skb. */
#define skb_list_walk_safe(first, skb, next_skb)                               \
	for ((skb) = (first), (next_skb) = (skb) ? (skb)->next : NULL; (skb);  \
	     (skb) = (next_skb), (next_skb) = (skb) ? (skb)->next : NULL)
#endif

#if !defined(EFX_HAVE_PCI_FIND_NEXT_EXT_CAPABILITY)
int pci_find_next_ext_capability(struct pci_dev *dev, int pos, int cap);
#endif

/* XDP_SOCK check on latest kernels */
#if defined(EFX_HAVE_XSK_POOL)
#define EFX_HAVE_XDP_SOCK_DRV yes
#define EFX_HAVE_XSK_NEED_WAKEUP yes
#endif
#if defined(EFX_HAVE_XDP_SOCK_DRV)
#undef EFX_HAVE_XDP_SOCK_DRV
#define EFX_USE_XSK_BUFFER_ALLOC yes
#ifndef EFX_HAVE_XDP_SOCK
#define EFX_HAVE_XDP_SOCK
#endif
#ifndef EFX_HAVE_XSK_UMEM_CONS_TX_2PARAM
#define EFX_HAVE_XSK_UMEM_CONS_TX_2PARAM yes
#endif
#include <net/xdp_sock_drv.h>
#elif defined(EFX_HAVE_XDP_SOCK)
#include <net/xdp_sock.h>
#endif /* EFX_HAVE_XDP_SOCK_DRV */

/* Virtio feature bit number 35 is not defined in
 * include/uapi/linux/virtio_config.h
 */
#ifndef EFX_HAVE_VIRTIO_F_IN_ORDER
#define VIRTIO_F_IN_ORDER 35
#endif

#if defined(VIRTIO_F_IOMMU_PLATFORM) && !defined(VIRTIO_F_ACCESS_PLATFORM)
#define VIRTIO_F_ACCESS_PLATFORM VIRTIO_F_IOMMU_PLATFORM
#endif

#ifndef VIRTIO_NET_F_HASH_REPORT
#define VIRTIO_NET_F_HASH_REPORT 57
#endif

#ifndef VIRTIO_NET_F_RSS
#define VIRTIO_NET_F_RSS 60
#endif

#ifndef VIRTIO_NET_F_RSC_EXT
#define VIRTIO_NET_F_RSC_EXT 61
#endif

#if defined(EFX_HAVE_NET_DEVLINK_H) && defined(EFX_HAVE_NDO_GET_DEVLINK) && defined(EFX_HAVE_DEVLINK_INFO) && defined(CONFIG_NET_DEVLINK)
/* Minimum requirements met to use the kernel's devlink suppport */
#include <net/devlink.h>

/* devlink is available, augment the provided support with wrappers and stubs
 * for newer APIs as appropriate.
 */
#define EFX_USE_DEVLINK

#ifdef EFX_NEED_DEVLINK_INFO_BOARD_SERIAL_NUMBER_PUT
static inline int devlink_info_board_serial_number_put(struct devlink_info_req *req,
						       const char *bsn)
{
	/* Do nothing */
	return 0;
}
#endif
#ifdef EFX_NEED_DEVLINK_FLASH_UPDATE_STATUS_NOTIFY
static inline void devlink_flash_update_status_notify(struct devlink *devlink,
						      const char *status_msg,
						      const char *component,
						      unsigned long done,
						      unsigned long total)
{
	/* Do nothing */
}
#endif
#ifdef EFX_NEED_DEVLINK_FLASH_UPDATE_TIMEOUT_NOTIFY
void devlink_flash_update_timeout_notify(struct devlink *devlink,
					 const char *status_msg,
					 const char *component,
					 unsigned long timeout);
#endif
#else

/* devlink is not available, provide a 'fake' devlink info request structure
 * and functions to expose the version information via a file in sysfs.
 */

struct devlink_info_req {
	char *buf;
	size_t bufsize;
};

int devlink_info_serial_number_put(struct devlink_info_req *req, const char *sn);
int devlink_info_driver_name_put(struct devlink_info_req *req, const char *name);
int devlink_info_board_serial_number_put(struct devlink_info_req *req,
					 const char *bsn);
int devlink_info_version_fixed_put(struct devlink_info_req *req,
				   const char *version_name,
				   const char *version_value);
int devlink_info_version_stored_put(struct devlink_info_req *req,
				    const char *version_name,
				    const char *version_value);
int devlink_info_version_running_put(struct devlink_info_req *req,
				     const char *version_name,
				     const char *version_value);

/* Provide a do-nothing stubs for the flash update status notifications */

struct devlink;

static inline void devlink_flash_update_status_notify(struct devlink *devlink,
						      const char *status_msg,
						      const char *component,
						      unsigned long done,
						      unsigned long total)
{
	/* Do nothing */
}

static inline void devlink_flash_update_timeout_notify(struct devlink *devlink,
						       const char *status_msg,
						       const char *component,
						       unsigned long timeout)
{
	/* Do nothing */
}

#endif	/* EFX_HAVE_NET_DEVLINK_H && EFX_HAVE_NDO_GET_DEVLINK && EFX_HAVE_DEVLINK_INFO && CONFIG_NET_DEVLINK */

/* Irrespective of whether devlink is available, use the generic devlink info
 * version object names where possible.  Many of these definitions were added
 * to net/devlink.h over time so augment whatever is provided.
 */
#ifndef DEVLINK_INFO_VERSION_GENERIC_BOARD_ID
#define DEVLINK_INFO_VERSION_GENERIC_BOARD_ID		"board.id"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_BOARD_REV
#define DEVLINK_INFO_VERSION_GENERIC_BOARD_REV		"board.rev"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_BOARD_MANUFACTURE
#define DEVLINK_INFO_VERSION_GENERIC_BOARD_MANUFACTURE	"board.manufacture"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_ASIC_ID
#define DEVLINK_INFO_VERSION_GENERIC_ASIC_ID		"asic.id"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_ASIC_REV
#define DEVLINK_INFO_VERSION_GENERIC_ASIC_REV		"asic.rev"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_FW
#define DEVLINK_INFO_VERSION_GENERIC_FW			"fw"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_FW_MGMT
#define DEVLINK_INFO_VERSION_GENERIC_FW_MGMT		"fw.mgmt"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_FW_MGMT_API
#define DEVLINK_INFO_VERSION_GENERIC_FW_MGMT_API	"fw.mgmt.api"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_FW_APP
#define DEVLINK_INFO_VERSION_GENERIC_FW_APP		"fw.app"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_FW_UNDI
#define DEVLINK_INFO_VERSION_GENERIC_FW_UNDI		"fw.undi"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_FW_NCSI
#define DEVLINK_INFO_VERSION_GENERIC_FW_NCSI		"fw.ncsi"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_FW_PSID
#define DEVLINK_INFO_VERSION_GENERIC_FW_PSID		"fw.psid"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_FW_ROCE
#define DEVLINK_INFO_VERSION_GENERIC_FW_ROCE		"fw.roce"
#endif
#ifndef DEVLINK_INFO_VERSION_GENERIC_FW_BUNDLE_ID
#define DEVLINK_INFO_VERSION_GENERIC_FW_BUNDLE_ID	"fw.bundle_id"
#endif

#ifdef EFX_NEED_ARRAY_SIZE
/**
* array_size() - Calculate size of 2-dimensional array.
*
* @a: dimension one
* @b: dimension two
*
* Calculates size of 2-dimensional array: @a * @b.
*
* Returns: number of bytes needed to represent the array.
*/
static inline __must_check size_t array_size(size_t a, size_t b)
{
	return(a * b);
}
#else
/* On RHEL7.6 nothing includes this yet */
#include <linux/overflow.h>
#endif

#endif /* EFX_KERNEL_COMPAT_H */
