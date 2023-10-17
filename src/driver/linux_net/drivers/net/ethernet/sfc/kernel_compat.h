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
#include <linux/iommu.h>
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

/**************************************************************************
 *
 * Version/config/architecture compatability.
 *
 **************************************************************************
 *
 * The preferred kernel compatability mechanism is through the autoconf
 * layer above. The following definitions are all deprecated
 */


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	#error "This kernel version is now unsupported"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	/* Fixing MSI-X masking introduced another bug, fixed in 2.6.36 */
	#define EFX_NEED_SAVE_MSIX_MESSAGES yes
#endif

/**************************************************************************
 *
 * Definitions of missing constants, types, functions and macros
 *
 **************************************************************************
 *
 */
#ifndef READ_ONCE
#define READ_ONCE(x) ACCESS_ONCE((x))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v) (ACCESS_ONCE((x)) = (v))
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
	#define NETIF_F_CSUM_MASK \
		(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_HW_CSUM)
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

#if defined(__GNUC__) && !defined(inline)
	#define inline inline __attribute__ ((always_inline))
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

#ifndef VLAN_PRIO_MASK
	#define VLAN_PRIO_MASK          0xe000
#endif
#ifndef VLAN_PRIO_SHIFT
	#define VLAN_PRIO_SHIFT         13
#endif

#ifndef SIOCGHWTSTAMP
	#define SIOCGHWTSTAMP	0x89b1
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

#ifdef ETHTOOL_GMODULEEEPROM
	#define EFX_HAVE_ETHTOOL_GMODULEEEPROM yes
	#ifndef ETH_MODULE_SFF_8436
	#define ETH_MODULE_SFF_8436     0x3
	#define ETH_MODULE_SFF_8436_LEN 256
	#endif
	#ifndef ETH_MODULE_SFF_8436_MAX_LEN
	#define ETH_MODULE_SFF_8436_MAX_LEN 640
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
	#define ETH_MODULE_SFF_8436_LEN 256
	#define ETH_MODULE_SFF_8436_MAX_LEN 640

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

#ifndef PORT_DA
	#define PORT_DA			0x05
#endif

#ifndef SUPPORTED_40000baseKR4_Full
	#define SUPPORTED_40000baseKR4_Full	(1 << 23)
	#define SUPPORTED_40000baseCR4_Full	(1 << 24)
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

#ifndef GSO_LEGACY_MAX_SIZE
	#define GSO_LEGACY_MAX_SIZE	65536u
#endif

#ifndef netdev_for_each_uc_addr
	#define netdev_for_each_uc_addr(uclist, dev)		\
		list_for_each_entry(uclist, &(dev)->uc.list, list)
	#define netdev_uc_count(dev) (dev)->uc.count
#endif

#ifndef netdev_for_each_mc_addr
	#define netdev_for_each_mc_addr(mclist, dev) \
		for (mclist = (dev)->mc_list; mclist; mclist = mclist->next)
#endif

#ifndef netdev_mc_count
	#define netdev_mc_count(dev) (dev)->mc_count
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

#ifdef EFX_NEED_DMA_SET_COHERENT_MASK
	static inline int dma_set_coherent_mask(struct device *dev, u64 mask)
	{
		return pci_set_consistent_dma_mask(to_pci_dev(dev), mask);
	}
#endif

#ifdef EFX_NEED_DMA_SET_MASK_AND_COHERENT
	static inline int dma_set_mask_and_coherent(struct device *dev, u64 mask)
	{
		int rc;

		/*
		 * Truncate the mask to the actually supported dma_addr_t
		 * width to avoid generating unsupportable addresses.
		 */
		mask = (dma_addr_t)mask;

		rc = dma_set_mask(dev, mask);
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

#ifndef netif_printk

	static inline const char *netdev_name(const struct net_device *dev)
	{
		if (dev->reg_state != NETREG_REGISTERED)
			return "(unregistered net_device)";
		return dev->name;
	}

	#define netdev_printk(level, netdev, format, args...)		\
		dev_printk(level, (netdev)->dev.parent,			\
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

#ifdef EFX_NEED_ETH_HW_ADDR_SET
	static inline void eth_hw_addr_set(struct net_device *dev, const u8 *addr)
	{
		ether_addr_copy(dev->dev_addr, addr);
	}
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

#ifdef EFX_NEED_BITMAP_ZALLOC
#define bitmap_zalloc(count, gfp)	kzalloc(BITS_TO_LONGS(count), gfp)
#define bitmap_free(ptr)		kfree(ptr)
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
	#define skb_transport_header_was_set(skb)		\
		(!!(skb)->transport_header)
#endif

#ifndef EFX_HAVE_NAPI_STRUCT
/* We use a napi_struct pointer as context in some compat functions even if the
 * kernel doesn't use this structure at all.
 */
struct efx_napi_dummy {};
#define napi_struct efx_napi_dummy
#endif

#ifndef NAPI_POLL_WEIGHT
#define NAPI_POLL_WEIGHT	64
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
#ifndef pci_notice
#define pci_notice(pdev, fmt, arg...)	dev_notice(&(pdev)->dev, fmt, ##arg)
#endif

#if defined(EFX_HAVE_RHASHTABLE) && defined(EFX_HAVE_RHASHTABLE_LOOKUP_FAST)
#ifdef EFX_NEED_RHASHTABLE_WALK_ENTER
#include <linux/rhashtable.h>

static inline void rhashtable_walk_enter(struct rhashtable *ht,
					 struct rhashtable_iter *iter)
{
	int rc;

	rc = rhashtable_walk_init(ht, iter
#ifdef EFX_HAVE_RHASHTABLE_WALK_INIT_GFP
				  , GFP_KERNEL
#endif
				  );
	WARN_ON_ONCE(rc);
}
#endif
#endif

#ifdef EFX_NEED_STRSCPY
#define strscpy(dest, src, count)	strlcpy(dest, src, count)
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

#ifdef EFX_NEED_KREALLOC_ARRAY
#ifndef SIZE_MAX
#define SIZE_MAX (~(size_t)0)
#endif

static __must_check inline void *
krealloc_array(void *p, size_t new_n, size_t new_size, gfp_t flags)
{
	size_t bytes = array_size(new_n, new_size);

	return (bytes == SIZE_MAX ? NULL : krealloc(p, bytes, flags));
}
#endif

#ifndef struct_group
#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
	union { \
		struct { MEMBERS } ATTRS; \
		struct TAG { MEMBERS } ATTRS NAME; \
	}
#define struct_group(NAME, MEMBERS...)	\
	__struct_group(/* no tag */, NAME, /* no attrs */, MEMBERS)
#endif

#ifdef EFX_NEED_NETDEV_HOLD
#ifdef EFX_HAVE_DEV_HOLD_TRACK
/* Commit d62607c3fe45 ("net: rename reference+tracking helpers")
 * renamed these.
 */
#define netdev_hold(_n, _t, _g)	dev_hold_track(_n, _t, _g)
#define netdev_put(_n, _t)	dev_put_track(_n, _t)
#else
/* This was introduced in the same commit that adds dev_hold_track */
typedef struct {} netdevice_tracker;

static inline void netdev_hold(struct net_device *dev,
			       netdevice_tracker *tracker __always_unused,
			       gfp_t gfp __always_unused)
{
	dev_hold(dev);
}

static inline void netdev_put(struct net_device *dev,
			      netdevice_tracker *tracker __always_unused)
{
	dev_put(dev);
}
#endif
#endif

#ifdef EFX_NEED_DEBUGFS_LOOKUP_AND_REMOVE
#ifdef CONFIG_DEBUG_FS
void debugfs_lookup_and_remove(const char *name, struct dentry *parent);
#else
static inline void debugfs_lookup_and_remove(const char *name,
					     struct dentry *parent)
{ }
#endif
#endif

/**************************************************************************
 *
 * Missing functions provided by kernel_compat.c
 *
 **************************************************************************
 *
 */

#if defined(EFX_NEED_SAVE_MSIX_MESSAGES)

	#include <linux/msi.h>

	int efx_pci_save_state(struct pci_dev *dev);
	#define pci_save_state efx_pci_save_state

	void efx_pci_restore_state(struct pci_dev *dev);
	#define pci_restore_state efx_pci_restore_state

#endif

#if !defined(topology_sibling_cpumask) && defined(topology_thread_cpumask)
	#define topology_sibling_cpumask topology_thread_cpumask
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

#ifndef list_first_entry_or_null
	#define list_first_entry_or_null(ptr, type, member) \
		(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
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

#ifdef EFX_NEED_KTIME_COMPARE
	static inline int ktime_compare(const ktime_t cmp1, const ktime_t cmp2)
	{
	       if (cmp1.tv64 < cmp2.tv64)
	               return -1;
	       if (cmp1.tv64 > cmp2.tv64)
	               return 1;
	       return 0;
	}
#endif

#include <linux/net_tstamp.h>

#ifndef EFX_HAVE_TIMESPEC64
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
#else
/* RHEL 9.0 has commit cb47755725da ("time: Prevent undefined behaviour
 * in timespec64_to_ns()") but not commit 39ff83f2f6cc ("time: Handle
 * negative seconds correctly in timespec64_to_ns()") which fixes it.
 * This pulls in that patch.
 */
#ifdef EFX_NEED_TIMESPEC64_TO_NS_SIGNED
	#define KTIME_MIN	(-KTIME_MAX - 1)
	#define KTIME_SEC_MIN	(KTIME_MIN / NSEC_PER_SEC)

	static inline s64 efx_timespec64_to_ns(const struct timespec64 *ts)
	{
		/* Prevent multiplication overflow / underflow */
		if (ts->tv_sec >= KTIME_SEC_MAX)
			return KTIME_MAX;

		if (ts->tv_sec <= KTIME_SEC_MIN)
			return KTIME_MIN;

		return ((s64) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
	}
	#define timespec64_to_ns efx_timespec64_to_ns
#endif
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

#if defined(CONFIG_X86) && NET_IP_ALIGN != 0
	#undef NET_IP_ALIGN
	#define NET_IP_ALIGN 0
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

#ifdef EFX_HAVE_ASM_SYSTEM_H
#include <asm/system.h>
#endif

#include <linux/pps_kernel.h>

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


#ifdef EFX_NEED_KTIME_GET_SNAPSHOT
/* simplified structure for systems which don't have a kernel definition
 * we only need a couple of fields and layout doesn't matter for this usage */
struct system_time_snapshot {
	ktime_t			real;
	ktime_t			raw;
};

static inline void ktime_get_snapshot(struct system_time_snapshot *systime_snapshot)
{
	struct timespec64 ts_real;
	struct timespec64 ts_raw = {};

#ifdef CONFIG_NTP_PPS
	getnstime_raw_and_real(&ts_raw, &ts_real);
#else
	getnstimeofday(&ts_real);
#endif

	systime_snapshot->real = timespec64_to_ktime(ts_real);
	systime_snapshot->raw = timespec64_to_ktime(ts_raw);
}
#else
#include <linux/timekeeping.h>
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

#ifdef EFX_NEED_SCALED_PPM_TO_PPB
/**
 * scaled_ppm_to_ppb() - convert scaled ppm to ppb
 *
 * @ppm:    Parts per million, but with a 16 bit binary fractional field
 */
static inline long scaled_ppm_to_ppb(long ppm)
{
	/*
	 * The 'freq' field in the 'struct timex' is in parts per
	 * million, but with a 16 bit binary fractional field.
	 *
	 * We want to calculate
	 *
	 *    ppb = scaled_ppm * 1000 / 2^16
	 *
	 * which simplifies to
	 *
	 *    ppb = scaled_ppm * 125 / 2^13
	 */
	s64 ppb = 1 + ppm;

	ppb *= 125;
	ppb >>= 13;
	return (long)ppb;
}
#endif

#ifdef EFX_NEED_RCU_ACCESS_POINTER
#define rcu_access_pointer rcu_dereference
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

#ifdef EFX_NEED_SET_TSO_MAX_SIZE
static inline void netif_set_tso_max_size(struct net_device *dev,
					  unsigned int size)
{
	/* dev->gso_max_size is read locklessly from sk_setup_caps() */
	WRITE_ONCE(dev->gso_max_size, size);
}
#endif

#ifdef EFX_NEED_SET_TSO_MAX_SEGS
static inline void netif_set_tso_max_segs(struct net_device *dev,
					  unsigned int segs)
{
#ifdef EFX_HAVE_GSO_MAX_SEGS
	/* dev->gso_max_segs is read locklessly from sk_setup_caps() */
	WRITE_ONCE(dev->gso_max_segs, segs);
#endif
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

#ifndef NUMA_NO_NODE
#define NUMA_NO_NODE (-1)
#endif

#if !defined(CONFIG_HAVE_MEMORYLESS_NODES) && !defined(cpu_to_mem)
#define cpu_to_mem(cpu) cpu_to_node(cpu)
#endif

/* As in include/linux/kconfig.h */
#ifndef __take_second_arg
#define __take_second_arg(__ignored, val, ...) val
#endif
#ifndef __and
#define __ARG_PLACEHOLDER_1 0,

#define __and(x, y)			___and(x, y)
#define ___and(x, y)			____and(__ARG_PLACEHOLDER_##x, y)
#define ____and(arg1_or_junk, y)	__take_second_arg(arg1_or_junk y, 0)

#define __or(x, y)			___or(x, y)
#define ___or(x, y)			____or(__ARG_PLACEHOLDER_##x, y)
#define ____or(arg1_or_junk, y)		__take_second_arg(arg1_or_junk 1, y)
#endif

#if !defined(IS_ENABLED) || LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
#undef IS_ENABLED
#undef IS_BUILTIN
#undef IS_MODULE
#undef IS_REACHABLE

#define __is_defined(x)			___is_defined(x)
#define ___is_defined(val)		____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk)	__take_second_arg(arg1_or_junk 1, 0)

#define IS_BUILTIN(option) __is_defined(option)
#define IS_MODULE(option) __is_defined(option##_MODULE)
#define IS_REACHABLE(option) __or(IS_BUILTIN(option), \
				__and(IS_MODULE(option), __is_defined(MODULE)))
#define IS_ENABLED(option) __or(IS_BUILTIN(option), IS_MODULE(option))
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

#ifdef EFX_NEED_NETIF_NAPI_ADD_WEIGHT
static inline void netif_napi_add_weight(struct net_device *dev,
					 struct napi_struct *napi,
					 int (*poll)(struct napi_struct *, int),
					 int weight)
{
	netif_napi_add(dev, napi, poll, weight);
}
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

struct device *hwmon_device_register_with_info(
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

#ifndef EFX_HAVE_XDP_RXQ_INFO_NAPI_ID
#define xdp_rxq_info_reg(_i,_d,_q,_n)	xdp_rxq_info_reg(_i,_d,_q)
#endif

#if defined(EFX_HAVE_XDP) && defined(EFX_NEED_XDP_INIT_BUFF)
static __always_inline void
xdp_init_buff(struct xdp_buff *xdp, u32 frame_sz
#ifdef EFX_HAVE_XDP_RXQ_INFO
	      , struct xdp_rxq_info *rxq
#endif
	      )
{
#ifdef EFX_HAVE_XDP_FRAME_SZ
	xdp->frame_sz = frame_sz;
#endif
#ifdef EFX_HAVE_XDP_RXQ_INFO
	xdp->rxq = rxq;
#endif
}
#endif

#if defined(EFX_HAVE_XDP) && defined(EFX_NEED_XDP_PREPARE_BUFF)
static __always_inline void
xdp_prepare_buff(struct xdp_buff *xdp, unsigned char *hard_start,
		 int headroom, int data_len, const bool meta_valid)
{
	unsigned char *data = hard_start + headroom;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_HEAD)
	xdp->data_hard_start = hard_start;
#endif
	xdp->data = data;
	xdp->data_end = data + data_len;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_DATA_META)
	xdp->data_meta = meta_valid ? data : data + 1;
#endif
}
#endif

#ifdef EFX_NEED_VOID_SKB_PUT
static inline void *efx_skb_put(struct sk_buff *skb, unsigned int len)
{
	return skb_put(skb, len);
}
#define skb_put efx_skb_put
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
#if defined(CONFIG_NET_CLS_ACT) || defined(EFX_HAVE_TC_FLOW_OFFLOAD)
#define EFX_TC_OFFLOAD	yes
/* Further features needed for conntrack offload */
#if defined(EFX_HAVE_NF_FLOW_TABLE_OFFLOAD) && defined(EFX_HAVE_TC_ACT_CT)
#define EFX_CONNTRACK_OFFLOAD	yes
#endif
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

#if !defined(EFX_HAVE_XDP_HEAD) && !defined(XDP_PACKET_HEADROOM)
#define XDP_PACKET_HEADROOM 0
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

#ifndef VIRTIO_F_IN_ORDER
/* Virtio feature bit number 35 is not defined in
 * include/uapi/linux/virtio_config.h for kernel versions < 5.18.
 * So make it available for the out-of-tree builds. VIRTIO_F_IN_ORDER
 * is defined in section 6 (Reserved Feature Bits) of the VirtIO v1.1 spec
 */
#define VIRTIO_F_IN_ORDER 35
#endif

#if defined(EFX_HAVE_NET_DEVLINK_H) && defined(EFX_HAVE_DEVLINK_INFO) && defined(CONFIG_NET_DEVLINK)
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

#endif	/* EFX_HAVE_NET_DEVLINK_H && EFX_HAVE_DEVLINK_INFO && CONFIG_NET_DEVLINK */

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

#ifdef EFX_NEED_REFCOUNT_T
typedef atomic_t refcount_t;

#define refcount_set	atomic_set
#define refcount_inc_not_zero	atomic_inc_not_zero
#define refcount_dec_and_test	atomic_dec_and_test
#endif

#ifdef EFX_NEED_DEVICE_IOMMU_CAPABLE
#ifndef EFX_HAVE_IOMMU_CAPABLE
enum iommu_cap { IOMMU_CAP_DUMMY, };
#endif

static inline bool device_iommu_capable(struct device *dev, enum iommu_cap cap)
{
#ifdef EFX_HAVE_IOMMU_CAPABLE
	return iommu_capable(dev->bus, cap);
#else
	return false;
#endif
}
#endif

#ifndef EFX_HAVE_IOMMU_MAP_GFP_PARAM
static inline int efx_iommu_map(struct iommu_domain *domain,
				unsigned long iova, phys_addr_t paddr,
				size_t size, int prot, gfp_t gfp)
{
	return iommu_map(domain, iova, paddr, size, prot);
}
#undef iommu_map
#define iommu_map efx_iommu_map
#endif

#ifndef EFX_HAVE_SK_BUFF_LIST
static inline void efx__skb_queue_tail(struct sk_buff_head *list,
				       struct sk_buff *newsk)
{
        // This calls __skb_queue_before(list, (struct sk_buff *)list, newsk)
	__skb_insert(newsk, list->prev, (struct sk_buff *)list, list);
}
#undef __skb_queue_tail
#define __skb_queue_tail efx__skb_queue_tail
#endif

/* xdp_do_flush_map has been renamed xdp_do_flush */
#ifdef EFX_NEED_XDP_DO_FLUSH
#define xdp_do_flush xdp_do_flush_map
#endif

#endif /* EFX_KERNEL_COMPAT_H */
