#!/bin/bash -eu

######################################################################
#
# Driver for Solarflare network controllers and boards
# Copyright 2019 Solarflare Communications Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation, incorporated herein by reference.
#
######################################################################

me=$(basename "$0")

######################################################################
# Symbol definition map

function generate_kompat_symbols() {
    echo "
EFX_HAVE_MTD_TABLE			kver	<	2.6.35
EFX_HAVE_VMALLOC_REG_DUMP_BUF		kver	>=	2.6.37
EFX_USE_ETHTOOL_OP_GET_LINK		kver	>=	2.6.38
EFX_WANT_NDO_POLL_CONTROLLER		kver	<	4.19
EFX_FLASH_FIRMWARE		symbol request_firmware_direct	include/linux/firmware.h
EFX_NEED_ROOT_DEVICE_REGISTER		nsymbol root_device_register	include/linux/device.h
EFX_HAVE_GRO				custom
EFX_NEED_GRO_RESULT_T			nsymbol	gro_result_t		include/linux/netdevice.h
EFX_HAVE_NAPI_GRO_RECEIVE_GR		symbol	napi_gro_receive_gr	include/linux/netdevice.h
EFX_HAVE_NAPI_GRO_BITMASK		member	struct_napi_struct	gro_bitmask	include/linux/netdevice.h
EFX_NEED_HEX_DUMP			nexport	print_hex_dump		include/linux/kernel.h include/linux/printk.h lib/hexdump.c
EFX_NEED_HEX_DUMP_CONST_FIX 		symtype	print_hex_dump		include/linux/kernel.h void(const char *, const char *, int, int, int, void *, size_t, bool)
EFX_NEED_VZALLOC			nsymbol	vzalloc			include/linux/vmalloc.h
EFX_NEED_MII_ADVERTISE_FLOWCTRL		nsymbol	mii_advertise_flowctrl	include/linux/mii.h
EFX_NEED_MII_RESOLVE_FLOWCTRL_FDX	nsymbol	mii_resolve_flowctrl_fdx include/linux/mii.h
EFX_HAVE_LINUX_MDIO_H			file				include/linux/mdio.h
EFX_NEED_MTD_DEVICE_REGISTER		nsymbol	mtd_device_register	include/linux/mtd/mtd.h
EFX_HAVE_MTD_DIRECT_ACCESS              custom
EFX_NEED_NETDEV_ALLOC_SKB		nsymbol	netdev_alloc_skb	include/linux/skbuff.h
EFX_NEED_SKB_COPY_FROM_LINEAR_DATA	nsymbol skb_copy_from_linear_data	include/linux/skbuff.h
EFX_NEED___SKB_QUEUE_HEAD_INIT		nsymbol __skb_queue_head_init	include/linux/skbuff.h
EFX_NEED_NETDEV_TX_T			nsymbol	netdev_tx_t		include/linux/netdevice.h
EFX_NEED_NETIF_NAPI_DEL			nsymbol	netif_napi_del		include/linux/netdevice.h
EFX_NEED_NETIF_TX_LOCK			nsymbol	netif_tx_lock		include/linux/netdevice.h
EFX_NEED_NETIF_ADDR_LOCK		nsymbol	netif_addr_lock		include/linux/netdevice.h
EFX_NEED_ALLOC_ETHERDEV_MQ		nsymbol	alloc_etherdev_mq	include/linux/etherdevice.h
EFX_NEED_NETIF_SET_REAL_NUM_TX_QUEUES	nsymbol	netif_set_real_num_tx_queues include/linux/netdevice.h
EFX_NEED_NETIF_SET_REAL_NUM_RX_QUEUES	nsymbol	netif_set_real_num_rx_queues include/linux/netdevice.h
EFX_NEED_PCI_CLEAR_MASTER		nsymbol	pci_clear_master	include/linux/pci.h
EFX_HAVE_PCI_RESET_FUNCTION		symbol	pci_reset_function	include/linux/pci.h
EFX_NEED_RESOURCE_SIZE_T		nsymbol resource_size_t		include/linux/types.h
EFX_NEED_RESOURCE_SIZE			nsymbol	resource_size		include/linux/ioport.h
EFX_NEED_RTNL_TRYLOCK			nsymbol	rtnl_trylock		include/linux/rtnetlink.h
EFX_HAVE_ROUND_JIFFIES_UP		symbol	round_jiffies_up	include/linux/timer.h
EFX_NEED_SKB_HEADER_MACROS		nsymbol	skb_mac_header		include/linux/skbuff.h
EFX_NEED_SKB_NETWORK_HEADER_LEN		nsymbol	skb_network_header_len	include/linux/skbuff.h
EFX_NEED_SKB_CHECKSUM_START_OFFSET	nsymbol	skb_checksum_start_offset	include/linux/skbuff.h
EFX_HAVE_CSUM_LEVEL			symbol	csum_level		include/linux/skbuff.h
EFX_HAVE_SKB_SET_TRANSPORT_HEADER	symbol	skb_set_transport_header	include/linux/skbuff.h
EFX_HAVE_OLD_SKB_HEADER_FIELDS		member	struct_sk_buff		h	include/linux/skbuff.h
EFX_HAVE_OLD_SKB_LINEARIZE		nsymtype skb_linearize		include/linux/skbuff.h int(struct sk_buff *)
EFX_HAVE_SKBTX_HW_TSTAMP		symbol	SKBTX_HW_TSTAMP		include/linux/skbuff.h
EFX_HAVE_SKB_SYSTSTAMP			member	struct_skb_shared_hwtstamps	syststamp	include/linux/skbuff.h
EFX_HAVE_SKB_TSTAMP_TX			symbol	skb_tstamp_tx		include/linux/skbuff.h
EFX_HAVE_SKB_TX_TIMESTAMP		symbol	skb_tx_timestamp	include/linux/skbuff.h
EFX_NEED_TCP_HDR			nsymbol	tcp_hdr			include/linux/tcp.h
EFX_NEED_UDP_HDR			nsymbol	udp_hdr			include/linux/udp.h
EFX_NEED_IP_HDR				nsymbol	ip_hdr			include/linux/ip.h
EFX_NEED_IPV6_HDR			nsymbol	ipv6_hdr		include/linux/ipv6.h
EFX_NEED_WORK_API_WRAPPERS		nmember	struct_delayed_work	timer	include/linux/workqueue.h
EFX_USE_CANCEL_DELAYED_WORK_SYNC	symbol	cancel_delayed_work_sync		include/linux/workqueue.h
EFX_USE_CANCEL_WORK_SYNC		symbol	cancel_work_sync	include/linux/workqueue.h
EFX_NEED_WQ_SYSFS			nsymbol	WQ_SYSFS		include/linux/workqueue.h
EFX_HAVE_ALLOC_WORKQUEUE		symbol	alloc_workqueue		include/linux/workqueue.h
EFX_HAVE_NEW_ALLOC_WORKQUEUE		custom
EFX_NEED_MOD_DELAYED_WORK		nsymbol	mod_delayed_work	include/linux/workqueue.h
EFX_USE_ETHTOOL_ETH_TP_MDIX		symbol	eth_tp_mdix		include/linux/ethtool.h
EFX_USE_ETHTOOL_GET_PERM_ADDR		symbol	get_perm_addr		include/linux/ethtool.h
EFX_USE_ETHTOOL_FLAGS			symbol	get_flags		include/linux/ethtool.h
EFX_USE_ETHTOOL_LP_ADVERTISING		symbol	lp_advertising		include/linux/ethtool.h
EFX_USE_ETHTOOL_MDIO_SUPPORT		symbol	mdio_support		include/linux/ethtool.h
EFX_USE_LINUX_UACCESS_H			file				include/linux/uaccess.h
EFX_USE_MTD_WRITESIZE			symbol	writesize		include/linux/mtd/mtd.h
EFX_HAVE_MTD_NVMEM			member	struct_mtd_info	nvmem	include/linux/mtd/mtd.h
EFX_USE_NETDEV_DEV			member	struct_net_device	dev	include/linux/netdevice.h
EFX_USE_NETDEV_STATS			custom
EFX_USE_NETDEV_STATS64			member	struct_net_device_ops	ndo_get_stats64 include/linux/netdevice.h
EFX_HAVE_NETDEV_STATS64_VOID		memtype	struct_net_device_ops	ndo_get_stats64	include/linux/netdevice.h	void(*)(struct net_device *, struct rtnl_link_stats64 *)
EFX_USE_NETDEV_VLAN_FEATURES		symbol	vlan_features		include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_UC			memtype	struct_net_device	uc	include/linux/netdevice.h	struct netdev_hw_addr_list
EFX_HAVE_NET_DEVICE_UC_LIST		symbol	uc_list			include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_MC			memtype	struct_net_device	mc	include/linux/netdevice.h	struct netdev_hw_addr_list
EFX_HAVE_OLD_SKB_CHECKSUM_HELP		symtype	skb_checksum_help	include/linux/netdevice.h int(struct sk_buff *, int)
EFX_HAVE_HWMON_CLASS_DEVICE		symtype	hwmon_device_register	include/linux/hwmon.h struct class_device *(struct device *)
EFX_NEED_HWMON_T_ALARM			nsymbol	HWMON_T_ALARM		include/linux/hwmon.h
EFX_HAVE_HWMON_READ_STRING		member	struct_hwmon_ops	read_string	include/linux/hwmon.h
EFX_HAVE_HWMON_READ_STRING_CONST	memtype	struct_hwmon_ops	read_string	include/linux/hwmon.h	int(*)(struct device *, enum hwmon_sensor_types, u32, int, const char **)
EFX_HAVE_BIN_ATTRIBUTE_OP_FILE_PARAM	custom
EFX_USE_ETHTOOL_GET_SSET_COUNT		symbol	get_sset_count		include/linux/ethtool.h
# Do not use struct ethtool_ops_ext due to RH BZ 1008678 (SF bug 39031)
EFX_HAVE_ETHTOOL_RESET			member	struct_ethtool_ops reset include/linux/ethtool.h
EFX_HAVE_ETHTOOL_SET_PHYS_ID		symbol	set_phys_id		include/linux/ethtool.h
EFX_NEED_ETHTOOL_CMD_SPEED		nsymbol	ethtool_cmd_speed	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GMODULEEEPROM		symbol	get_module_eeprom	include/linux/ethtool.h
EFX_HAVE_OLD_DMA_MAPPING_ERROR		custom
EFX_NEED_DMA_SET_COHERENT_MASK		nsymbol	dma_set_coherent_mask	include/linux/dma-mapping.h
EFX_NEED_DMA_SET_MASK_AND_COHERENT		nsymbol	dma_set_mask_and_coherent	include/linux/dma-mapping.h
EFX_HAVE_LINUX_SEMAPHORE_H		file				include/linux/semaphore.h
EFX_HAVE_PRINTF_BITMAPS			symbol	cpumask_pr_args		include/linux/cpumask.h
EFX_HAVE_OLD_CPUMASK_SCNPRINTF		nsymtype cpumask_scnprintf	include/linux/cpumask.h int(char *, int, const struct cpumask *)
EFX_NEED_NEW_CPUMASK_API		nsymbol	cpumask_var_t		include/linux/cpumask.h
EFX_NEED_ZALLOC_CPUMASK_VAR		nsymbol zalloc_cpumask_var	include/linux/cpumask.h
EFX_USE_PM_EXT_OPS			symbol	pm_ext_ops		include/linux/pm.h
EFX_USE_DEV_PM_OPS			symbol	dev_pm_ops		include/linux/pm.h
EFX_NEED_PCI_WAKE_FROM_D3		nsymbol pci_wake_from_d3        include/linux/pci.h
EFX_HAVE_DEV_DISABLE_LRO		export	dev_disable_lro		include/linux/netdevice.h	net/core/dev.c
EFX_NEED_UNMASK_MSIX_VECTORS		nsymbol	masked			include/linux/msi.h
EFX_HAVE_PM_IDLE			export	pm_idle			include/linux/pm.h arch/$SRCARCH/kernel/process.c
EFX_NEED_SKB_RECORD_RX_QUEUE		nsymbol	skb_record_rx_queue	include/linux/skbuff.h
EFX_HAVE_XEN_XEN_H			file				include/xen/xen.h
EFX_HAVE_SYSDEV_H			file				include/linux/sysdev.h
EFX_HAVE_ASM_SYSTEM_H			file				asm/system.h
EFX_HAVE_XEN_START_INFO			custom
EFX_HAVE_CPUMASK_OF_NODE		symbol	cpumask_of_node		include/asm-generic/topology.h
EFX_HAVE_CPUMASK_OF_PCIBUS		symbol	cpumask_of_pcibus	include/asm-generic/topology.h
EFX_NEED_SET_CPUS_ALLOWED_PTR		nsymbol set_cpus_allowed_ptr	include/linux/sched.h
EFX_HAVE_EXPORTED_CPU_SIBLING_MAP	export	(per_cpu__)?cpu_sibling_map	include/asm/smp.h	arch/$SRCARCH/include/asm/smp.h	arch/$SRCARCH/kernel/smpboot.c	drivers/xen/core/smpboot.c
EFX_NEED_ROUNDDOWN_POW_OF_TWO		nsymbol	rounddown_pow_of_two	include/linux/log2.h include/linux/kernel.h
EFX_HAVE_SRIOV				export	pci_enable_sriov	include/linux/pci.h	drivers/pci/iov.c
EFX_HAVE_PCI_NUM_VF			export	pci_num_vf		include/linux/pci.h	drivers/pci/iov.c
EFX_HAVE_SRIOV_CONFIGURE                member  struct_pci_driver       sriov_configure        include/linux/pci.h
EFX_HAVE_PCI_DRIVER_RH                  member  struct_pci_driver_rh    sriov_configure        include/linux/pci.h
EFX_HAVE_PHYSFN                         member  struct_pci_dev          physfn                 include/linux/pci.h
EFX_HAVE_NDO_SIZE			member	struct_net_device_ops	ndo_size		include/linux/netdevice.h
EFX_HAVE_NDO_SIZE_RH			member	struct_net_device_ops	ndo_size_rh		include/linux/netdevice.h
EFX_HAVE_NDO_SET_VF_MAC 		member	struct_net_device_ops	ndo_set_vf_mac		include/linux/netdevice.h
EFX_HAVE_NDO_SET_VF_VLAN_PROTO		memtype	struct_net_device_ops	ndo_set_vf_vlan		include/linux/netdevice.h	int (*)(struct net_device *, int, u16, u8, __be16)
EFX_HAVE_NDO_EXT_SET_VF_VLAN_PROTO		memtype struct_net_device_ops_extended	ndo_set_vf_vlan	include/linux/netdevice.h	int (*)(struct net_device *, int, u16, u8, __be16)
EFX_HAVE_NDO_SET_VF_SPOOFCHK		member	struct_net_device_ops	ndo_set_vf_spoofchk	include/linux/netdevice.h
EFX_HAVE_NDO_SET_FEATURES		member	struct_net_device_ops	ndo_set_features	include/linux/netdevice.h
EFX_HAVE_NDO_FEATURES_CHECK		member	struct_net_device_ops	ndo_features_check	include/linux/netdevice.h
EFX_HAVE_EXT_NDO_SET_FEATURES           member  struct_net_device_ops_ext ndo_set_features      include/linux/netdevice.h
EFX_HAVE_VF_LINK_STATE			member	struct_net_device_ops	ndo_set_vf_link_state	include/linux/netdevice.h
EFX_HAVE_NDO_SET_MULTICAST_LIST		member	struct_net_device_ops	ndo_set_multicast_list	include/linux/netdevice.h
EFX_HAVE_NDO_BUSY_POLL			member	struct_net_device_ops	ndo_busy_poll	        include/linux/netdevice.h
EFX_HAVE_NDO_GET_PHYS_PORT_ID		member	struct_net_device_ops	ndo_get_phys_port_id	include/linux/netdevice.h
EFX_HAVE_NDO_GET_PHYS_PORT_NAME		member	struct_net_device_ops	ndo_get_phys_port_name	include/linux/netdevice.h
EFX_HAVE_NDO_GET_PORT_PARENT_ID		member	struct_net_device_ops	ndo_get_port_parent_id	include/linux/netdevice.h
EFX_HAVE_NDO_VLAN_RX_ADD_VID		member	struct_net_device_ops	ndo_vlan_rx_add_vid	include/linux/netdevice.h
EFX_HAVE_NDO_VLAN_RX_ADD_VID_PROTO	memtype	struct_net_device_ops	ndo_vlan_rx_add_vid	include/linux/netdevice.h	int (*)(struct net_device *, __be16, u16)
EFX_HAVE_NDO_VLAN_RX_ADD_VID_RC		memtype	struct_net_device_ops	ndo_vlan_rx_add_vid	include/linux/netdevice.h	int (*)(struct net_device *, u16)
EFX_NEED_ETHER_ADDR_COPY		nsymbol ether_addr_copy		include/linux/etherdevice.h
EFX_NEED_ETHER_ADDR_EQUAL		nsymbol	ether_addr_equal	include/linux/etherdevice.h
EFX_NEED_ETH_ZERO_ADDR			nsymbol eth_zero_addr		include/linux/etherdevice.h
EFX_NEED_ETH_BROADCAST_ADDR		nsymbol	eth_broadcast_addr	include/linux/etherdevice.h
EFX_NEED_ETH_RANDOM_ADDR		nsymbol	eth_random_addr		include/linux/etherdevice.h
EFX_NEED_MAC_PTON			nsymbol mac_pton		include/linux/kernel.h	include/linux/if_ether.h
EFX_HAVE_HEX_TO_BIN			symbol hex_to_bin		include/linux/kernel.h
EFX_NEED_IPV4_IS_MULTICAST		nsymbol	ipv4_is_multicast	include/linux/in.h
EFX_NEED_IPV4_IS_LBCAST			nsymbol	ipv4_is_lbcast		include/linux/in.h
EFX_HAVE_LIST_SPLICE_TAIL_INIT		symbol	list_splice_tail_init	include/linux/list.h
EFX_NEED_LIST_FIRST_ENTRY		nsymbol	list_first_entry	include/linux/list.h
EFX_NEED_TIMESPEC_ADD_NS		nsymbol	timespec_add_ns		include/linux/time.h	include/linux/time32.h
EFX_NEED_NS_TO_TIMESPEC			nexport ns_to_timespec		include/linux/time.h	kernel/time.c
EFX_HAVE_TIMESPEC64			symbol	timespec64		include/linux/time64.h	include/linux/time.h
EFX_NEED_KTIME_GET_REAL_TS64		nsymbol	ktime_get_real_ts64	include/linux/timekeeping.h	include/linux/ktime.h
EFX_NEED_RTC_TIME64_TO_TM		nsymbol	rtc_time64_to_tm	include/linux/rtc.h
EFX_HAVE_FDTABLE_FULL_ACCESSORS		symbol	__set_close_on_exec	include/linux/fdtable.h
EFX_HAVE_FDTABLE_PARTIAL_ACCESSORS	symbol	fd_is_open		include/linux/fdtable.h
EFX_HAVE_FDTABLE_H			file				include/linux/fdtable.h
EFX_NEED_SET_NORMALIZED_TIMESPEC	custom
EFX_HAVE_VLAN_RX_PATH			symbol	vlan_hwaccel_receive_skb include/linux/if_vlan.h
EFX_HAVE_OLD_ETHTOOL_GET_RXNFC		memtype	struct_ethtool_ops	get_rxnfc	include/linux/ethtool.h int (*)(struct net_device *, struct ethtool_rxnfc *, void *)
EFX_HAVE_CPU_RMAP			file				include/linux/cpu_rmap.h
EFX_NEED_KTIME_SUB_NS			nsymbol	ktime_sub_ns		include/linux/ktime.h
EFX_HAVE_NET_TSTAMP			file				include/linux/net_tstamp.h include/uapi/linux/net_tstamp.h
EFX_NEED_PTP_CLOCK_PPSUSR		custom
EFX_USE_64BIT_PHC			member	struct_ptp_clock_info gettime64	include/linux/ptp_clock_kernel.h
EFX_HAVE_PHC_SUPPORT			custom
EFX_NEED_PPS_SUB_TS			nsymbol pps_sub_ts		include/linux/pps_kernel.h
EFX_NEED_PPS_EVENT_TIME			nsymbol	pps_event_time		include/linux/pps_kernel.h
EFX_HAVE_PPS_EVENT_TIME_TIMESPEC	nmemtype	struct_pps_event_time	ts_real	include/linux/pps_kernel.h	struct timespec64
EFX_NEED_PPS_GET_TS			nsymbol	pps_get_ts		include/linux/pps_kernel.h
EFX_HAVE_PPS_KERNEL			file				include/linux/pps_kernel.h
EFX_HAVE_DIV_S64_REM			symbol	div_s64_rem		include/linux/math64.h
EFX_NEED_IP_IS_FRAGMENT			nsymbol	ip_is_fragment		include/net/ip.h
EFX_NEED_NETDEV_FEATURES_T		nsymbol	netdev_features_t	include/linux/netdevice.h
EFX_NEED_SKB_FILL_PAGE_DESC		nsymbol	skb_fill_page_desc	include/linux/skbuff.h
EFX_NEED_SKB_FRAG_DMA_MAP		nsymbol	skb_frag_dma_map	include/linux/skbuff.h
EFX_NEED_SKB_FRAG_ADDRESS		nsymbol skb_frag_address	include/linux/skbuff.h
EFX_NEED_SKB_FRAG_SIZE			nsymbol	skb_frag_size		include/linux/skbuff.h
EFX_NEED_SKB_FRAG_PAGE			nsymbol	skb_frag_page		include/linux/skbuff.h
EFX_NEED_SKB_FRAG_OFF			nsymbol	skb_frag_off		include/linux/skbuff.h
EFX_HAVE_ETHTOOL_GET_RXFH_INDIR	symbol	get_rxfh_indir	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_RXFH_INDIR_SIZE	symbol	get_rxfh_indir_size	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_RXFH		symbol	get_rxfh	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_RXFH_KEY_SIZE		symbol	get_rxfh_key_size	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_SET_RXFH_NOCONST	custom
EFX_HAVE_OLD_ETHTOOL_RXFH_INDIR		custom
EFX_NEED_ETHTOOL_RXFH_INDIR_DEFAULT	nsymbol	ethtool_rxfh_indir_default	include/linux/ethtool.h
EFX_NEED_IS_COMPAT_TASK			custom
EFX_NEED_COMPAT_U64			nsymbol	compat_u64		include/asm/compat.h arch/$SRCARCH/include/asm/compat.h include/asm-$SRCARCH/compat.h
EFX_HAVE_IRQ_NOTIFIERS			symbol  irq_affinity_notify	include/linux/interrupt.h
EFX_HAVE_GSO_MAX_SEGS			member	struct_net_device	gso_max_segs		include/linux/netdevice.h
EFX_NEED_BYTE_QUEUE_LIMITS		nsymbol	netdev_tx_sent_queue	include/linux/netdevice.h
EFX_NEED___BQL				nsymbol __netdev_tx_sent_queue	include/linux/netdevice.h
EFX_NEED_SKB_CHECKSUM_NONE_ASSERT	nsymbol	skb_checksum_none_assert	include/linux/skbuff.h
EFX_HAVE_NON_CONST_KERNEL_PARAM		symtype	param_set_uint		include/linux/moduleparam.h	int (const char *, struct kernel_param *)
EFX_HAVE_KERNEL_PARAM_OPS		symbol kernel_param_ops		include/linux/moduleparam.h
EFX_NEED___SET_BIT_LE			nsymtype __set_bit_le		include/asm-generic/bitops/le.h	void (int, void *)
EFX_NEED_KOBJECT_INIT_AND_ADD		nsymbol	kobject_init_and_add	include/linux/kobject.h
EFX_HAVE_NON_CONST_JHASH2		symtype	jhash2			include/linux/jhash.h		u32 (u32 *, u32, u32)
EFX_NEED_KOBJECT_SET_NAME_VARGS		nsymbol kobject_set_name_vargs	include/linux/kobject.h
EFX_USE_ETHTOOL_OPS_EXT			symbol	ethtool_ops_ext		include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_DUMP_FLAG		member	struct_ethtool_ops get_dump_flag	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_DUMP_DATA		member	struct_ethtool_ops get_dump_data	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_SET_DUMP		member	struct_ethtool_ops set_dump	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_TS_INFO		member	struct_ethtool_ops get_ts_info	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_EXT_GET_TS_INFO	member	struct_ethtool_ops_ext get_ts_info	include/linux/ethtool.h
EFX_HAVE_OLD___VLAN_PUT_TAG		symtype	__vlan_put_tag		include/linux/if_vlan.h	struct sk_buff *(struct sk_buff *, u16)
EFX_HAVE_VLAN_INSERT_TAG_SET_PROTO	symbol vlan_insert_tag_set_proto	include/linux/if_vlan.h
EFX_NEED_NETDEV_NOTIFIER_INFO_TO_DEV	nsymbol	netdev_notifier_info_to_dev	include/linux/netdevice.h
EFX_HAVE_NETDEV_REGISTER_RH		symbol	register_netdevice_notifier_rh	include/linux/netdevice.h
EFX_HAVE_NETDEV_RFS_INFO		symbol	netdev_rfs_info		include/linux/netdevice.h
EFX_HAVE_PCI_AER			file				include/linux/aer.h
EFX_NEED_PCI_AER_CLEAR_NONFATAL_STATUS	nsymbol pci_aer_clear_nonfatal_status	include/linux/aer.h
EFX_HAVE_EEH_DEV_CHECK_FAILURE		symbol	eeh_dev_check_failure	arch/powerpc/include/asm/eeh.h
EFX_NEED_PCI_DEV_TO_EEH_DEV		nsymbol	pci_dev_to_eeh_dev	include/linux/pci.h
EFX_HAVE_IOREMAP_WC			symbol	ioremap_wc		arch/$SRCARCH/include/asm/io.h include/asm-$SRCARCH/io.h include/asm-generic/io.h
EFX_HAVE_IOREMAP_NOCACHE		symbol	ioremap_nocache		include/asm-generic/io.h
EFX_NEED_SKB_TRANSPORT_HEADER_WAS_SET	nsymbol	skb_transport_header_was_set include/linux/skbuff.h
EFX_HAVE_OLD_KMAP_ATOMIC		custom
EFX_HAVE_DEBUGFS_CREATE_SYMLINK		symbol	debugfs_create_symlink	include/linux/debugfs.h
EFX_HAVE_INODE_U_GENERIC_IP		symbol	generic_ip		include/linux/fs.h
EFX_HAVE_NAPI_STRUCT			symbol	napi_struct		include/linux/netdevice.h
EFX_HAVE_NAPI_STRUCT_NAPI_ID		member	struct_napi_struct	napi_id	include/linux/netdevice.h
EFX_HAVE_NAPI_HASH_ADD			symbol	napi_hash_add		include/linux/netdevice.h
EFX_HAVE_NAPI_HASH_DEL_RETURN		symtype	napi_hash_del		include/linux/netdevice.h	int (struct napi_struct *)
EFX_NEED_SKB_SET_HASH			nsymbol skb_set_hash		include/linux/skbuff.h
EFX_HAVE_SKB_L4HASH			member	struct_sk_buff l4_rxhash	include/linux/skbuff.h
EFX_HAVE_SKB_VLANTCI                     member    struct_sk_buff vlan_tci        include/linux/skbuff.h
EFX_HAVE_BUSY_POLL			file				include/net/busy_poll.h
EFX_NEED_USLEEP_RANGE			nsymbol	usleep_range		include/linux/delay.h
EFX_HAVE_SRIOV_GET_TOTALVFS		symbol	pci_sriov_get_totalvfs	include/linux/pci.h
EFX_NEED_SKB_VLAN_TAG_GET		nsymbol	skb_vlan_tag_get	include/linux/if_vlan.h
EFX_HAVE_OLD___VLAN_HWACCEL_PUT_TAG	symtype	__vlan_hwaccel_put_tag	include/linux/if_vlan.h	struct sk_buff *(struct sk_buff *, u16)
EFX_HAVE_ETHTOOL_CHANNELS		member	struct_ethtool_ops get_channels	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_EXT_CHANNELS		member	struct_ethtool_ops_ext get_channels	include/linux/ethtool.h
EFX_NEED_UINTPTR_T			nsymbol	uintptr_t		include/linux/types.h
EFX_NEED_IPV6_NFC			nsymbol	ethtool_tcpip6_spec	include/uapi/linux/ethtool.h
EFX_HAVE_SKB_HASH			member	struct_sk_buff hash	include/linux/skbuff.h
EFX_HAVE_SKB_INNER_NETWORK_HEADER	symbol	skb_inner_network_header	include/linux/skbuff.h
EFX_SKB_HAS_INNER_NETWORK_HEADER	member	struct_sk_buff	inner_network_header	include/linux/skbuff.h
EFX_HAVE_SKB_INNER_TRANSPORT_HEADER	symbol	skb_inner_transport_header	include/linux/skbuff.h
EFX_SKB_HAS_INNER_TRANSPORT_HEADER	member	struct_sk_buff	inner_transport_header	include/linux/skbuff.h
EFX_HAVE_SKB_FRAG_TRUESIZE		symtype	skb_add_rx_frag		include/linux/skbuff.h	void (struct sk_buff *, int, struct page *, int, int, unsigned int)
EFX_HAVE_INNER_IP_HDR			symbol	inner_ip_hdr		include/linux/ip.h
EFX_HAVE_INNER_TCP_HDR			symbol	inner_tcp_hdr		include/linux/tcp.h

# Stuff needed in code other than the linux net driver
EFX_NEED_SCSI_SGLIST			nsymbol scsi_sglist		include/scsi/scsi_cmnd.h
EFX_NEED_SG_NEXT			nsymbol sg_next			include/linux/scatterlist.h
EFX_HAVE_NEW_KFIFO			symbol kfifo_out		include/linux/kfifo.h
EFX_NEED_VMALLOC_NODE			nsymbol vmalloc_node		include/linux/vmalloc.h
EFX_NEED_VMALLOC_TO_PFN			nsymbol vmalloc_to_pfn		include/linux/mm.h
EFX_NEED_KVEC				nsymbol	kvec			include/linux/uio.h
EFX_NEED_KERNEL_SENDMSG			nsymbol kernel_sendmsg		include/linux/net.h
EFX_HAVE_NETFILTER_INDIRECT_SKB		memtype	struct_nf_hook_ops	hook	include/linux/netfilter.h	unsigned int(*)(unsigned int, struct sk_buff **, const struct net_device *, const struct net_device *, int (*)(struct sk_buff *))
EFX_HAVE_NFPROTO_CONSTANTS		symbol	NFPROTO_NUMPROTO	include/linux/netfilter.h
EFX_HAVE_FDTABLE			symbol	files_fdtable		include/linux/file.h include/linux/fdtable.h
EFX_HAVE_REMAP_PFN_RANGE		symbol	remap_pfn_range		include/linux/mm.h
EFX_HAVE___REGISTER_CHRDEV		symbol __register_chrdev	include/linux/fs.h
EFX_HAVE_MSIX_CAP			symbol	msix_cap		include/linux/pci.h
EFX_NEED_PCI_ENABLE_MSIX_RANGE          nsymbol pci_enable_msix_range include/linux/pci.h
EFX_NEED_PCI_MSIX_VEC_COUNT		nsymbol	pci_msix_vec_count	include/linux/pci.h
EFX_HAVE_SKB_OOO_OKAY			member	struct_sk_buff ooo_okay	include/linux/skbuff.h
EFX_HAVE_SKB_TX_HASH			symbol	skb_tx_hash	include/linux/netdevice.h include/linux/skbuff.h
EFX_HAVE_SK_SET_TX_QUEUE		symbol	sk_tx_queue_set	include/net/sock.h
EFX_HAVE_SKB_GET_RX_QUEUE		symbol	skb_get_rx_queue	include/linux/skbuff.h
EFX_NEED_RCU_ACCESS_POINTER		nsymbol	rcu_access_pointer	include/linux/rcupdate.h
EFX_NEED_CPU_ONLINE_MASK		nsymbol	cpu_online_mask		include/linux/cpumask.h
EFX_HAVE_VF_INFO_MIN_TX_RATE		member	struct_ifla_vf_info min_tx_rate	include/linux/if_link.h
EFX_HAVE_NETDEV_HW_FEATURES		member	struct_net_device	hw_features	include/linux/netdevice.h
EFX_HAVE_NETDEV_EXTENDED_HW_FEATURES    member  struct_net_device_extended hw_features  include/linux/netdevice.h
EFX_HAVE_NETDEV_FEATURES_CHANGE	symbol	netdev_features_change	include/linux/netdevice.h
EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED		symbol	PCI_DEV_FLAGS_ASSIGNED	include/linux/pci.h
EFX_HAVE_PCI_VFS_ASSIGNED		symbol	pci_vfs_assigned	include/linux/pci.h
EFX_HAVE_LINUX_EXPORT_H			file				include/linux/export.h
EFX_NEED_KMALLOC_ARRAY			nsymbol	kmalloc_array	include/linux/slab.h
EFX_HAVE_VOID_DYNAMIC_NETDEV_DBG	symtype	__dynamic_netdev_dbg	include/linux/dynamic_debug.h void (struct _ddebug *, const struct net_device *, const char *, ...)
EFX_HAVE_NDO_EXT_BUSY_POLL		member	struct_net_device_extended	ndo_busy_poll	        include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_OPS_EXT	member struct_net_device_extended	netdev_ops_ext	include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_OPS_EXT_GET_PHYS_PORT_ID	member struct_net_device_ops_ext	ndo_get_phys_port_id	include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_OPS_EXT_SET_VF_SPOOFCHK	member struct_net_device_ops_ext	ndo_set_vf_spoofchk	include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_OPS_EXT_SET_VF_LINK_STATE	member struct_net_device_ops_ext	ndo_set_vf_link_state	include/linux/netdevice.h
EFX_NEED_SKB_GSO_TCPV6			nsymbol	SKB_GSO_TCPV6		include/linux/skbuff.h
EFX_HAVE_GSO_PARTIAL			symbol	SKB_GSO_PARTIAL		include/linux/skbuff.h
EFX_HAVE_GSO_UDP_TUNNEL_CSUM		symbol	SKB_GSO_UDP_TUNNEL_CSUM	include/linux/skbuff.h
EFX_NEED_SKB_IS_GSO_TCP		nsymbol	skb_is_gso_tcp	include/linux/skbuff.h
EFX_NEED_IS_ERR_OR_NULL		nsymbol IS_ERR_OR_NULL	include/linux/err.h
EFX_NEED_NETDEV_RSS_KEY_FILL	nsymbol	netdev_rss_key_fill	include/linux/netdevice.h
EFX_HAVE_NETIF_SET_XPS_QUEUE	symbol	netif_set_xps_queue	include/linux/netdevice.h
EFX_HAVE_NETIF_SET_XPS_QUEUE_NON_CONST	symtype	netif_set_xps_queue include/linux/netdevice.h	int (struct net_device *, struct cpumask *, u16)
EFX_HAVE_ALLOC_PAGES_NODE	symbol	alloc_pages_node	include/linux/gfp.h
EFX_HAVE_NETIF_XMIT_STOPPED	symbol	netif_xmit_stopped	include/linux/netdevice.h
EFX_NEED_CPUMASK_LOCAL_SPREAD	nsymbol	cpumask_local_spread	include/linux/cpumask.h
EFX_HAVE_CONST_PCI_ERR_HANDLER	memtype	struct_pci_driver err_handler	include/linux/pci.h	const struct pci_error_handlers *
EFX_HAVE_HW_ENC_FEATURES	member	struct_net_device	hw_enc_features	include/linux/netdevice.h
EFX_NEED_SKB_INNER_TRANSPORT_OFFSET	nsymbol	skb_inner_transport_offset	include/linux/skbuff.h
EFX_HAVE_SKB_XMIT_MORE	bitfield	struct_sk_buff	xmit_more	include/linux/skbuff.h
EFX_HAVE_NETDEV_XMIT_MORE	symbol	netdev_xmit_more	include/linux/netdevice.h
EFX_HAVE_NDO_ADD_VXLAN_PORT	member	struct_net_device_ops	ndo_add_vxlan_port	include/linux/netdevice.h
EFX_NEED_PAGE_REF_ADD		nfile				include/linux/page_ref.h
EFX_NEED_D_HASH_AND_LOOKUP	nexport	d_hash_and_lookup	include/linux/dcache.h fs/dcache.c
EFX_HAVE_KTIME_UNION		custom
EFX_NEED_HWMON_DEVICE_REGISTER_WITH_INFO	nsymbol	hwmon_device_register_with_info	include/linux/hwmon.h
EFX_HAVE_NDO_UDP_TUNNEL_ADD	member	struct_net_device_ops	ndo_udp_tunnel_add	include/linux/netdevice.h
EFX_HAVE_NEW_FLOW_KEYS		member	struct_flow_keys	basic		include/net/flow_dissector.h
EFX_HAVE_SKB_ENCAPSULATION	bitfield	struct_sk_buff	encapsulation	include/linux/skbuff.h
EFX_HAVE_NDO_ADD_GENEVE_PORT	member	struct_net_device_ops	ndo_add_geneve_port	include/linux/netdevice.h
EFX_HAVE_NETDEV_MTU_LIMITS	member	struct_net_device	max_mtu	include/linux/netdevice.h
EFX_NEED_BOOL_NAPI_COMPLETE_DONE	nsymtype	napi_complete_done	include/linux/netdevice.h	bool (struct napi_struct *, int)
EFX_HAVE_XDP	symbol	netdev_bpf	include/linux/netdevice.h
EFX_HAVE_XDP_OLD	symbol	netdev_xdp	include/linux/netdevice.h
EFX_HAVE_XDP_TRACE	file	include/trace/events/xdp.h
EFX_HAVE_XDP_HEAD	member	struct_xdp_buff	data_hard_start	include/linux/filter.h
EFX_HAVE_XDP_TX		symbol	XDP_TX		include/uapi/linux/bpf.h
EFX_HAVE_XDP_TX_FLAGS	memtype	struct_net_device_ops	ndo_xdp_xmit	include/linux/netdevice.h	int (*)(struct net_device *, int, struct xdp_frame **, u32)
EFX_HAVE_XDP_REDIR	symbol	XDP_REDIRECT	include/uapi/linux/bpf.h
EFX_HAVE_XDP_RXQ_INFO	symbol	xdp_rxq_info	include/net/xdp.h
EFX_HAVE_XDP_EXT	member	struct_net_device_ops_extended	ndo_xdp	include/linux/netdevice.h
EFX_NEED_XDP_FLUSH	member	struct_net_device_ops	ndo_xdp_flush	include/linux/netdevice.h
EFX_HAVE_XDP_PROG_ATTACHED	member	struct_netdev_bpf	prog_attached	include/linux/netdevice.h
EFX_HAVE_XDP_PROG_ID	member	struct_netdev_bpf	prog_id	include/linux/netdevice.h
EFX_NEED_PAGE_FRAG_FREE	nsymbol	page_frag_free	include/linux/gfp.h
EFX_HAVE_FREE_PAGE_FRAG	symbol	__free_page_frag	include/linux/gfp.h
EFX_NEED_VOID_SKB_PUT	nsymtype	skb_put	include/linux/skbuff.h	void *(struct sk_buff *, unsigned int)
EFX_HAVE_ETHTOOL_FCS	symbol	NETIF_F_RXALL	include/linux/netdev_features.h
EFX_HAVE_ETHTOOL_LINKSETTINGS	symbol	ethtool_link_ksettings	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_LEGACY	symbol	__ethtool_get_settings	include/linux/ethtool.h
EFX_HAVE_LINK_MODE_25_50_100	symbol	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT	include/uapi/linux/ethtool.h
EFX_HAVE_LINK_MODE_FEC_BITS	symbol	ETHTOOL_LINK_MODE_FEC_BASER_BIT	include/uapi/linux/ethtool.h
EFX_HAVE_NETDEV_EXT_MTU_LIMITS	member	struct_net_device_extended	max_mtu	include/linux/netdevice.h
EFX_HAVE_NDO_EXT_CHANGE_MTU	memtype	struct_net_device_ops_extended	ndo_change_mtu	include/linux/netdevice.h	int (*)(struct net_device *, int)
EFX_HAVE_NDO_TX_TIMEOUT_TXQUEUE	memtype	struct_net_device_ops	ndo_tx_timeout	include/linux/netdevice.h	void (*)(struct net_device *, unsigned int)
EFX_HAVE_ETHTOOL_FECPARAM	member	struct_ethtool_ops	get_fecparam	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_RXFH_CONTEXT	member	struct_ethtool_ops	get_rxfh_context	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_RXNFC_CONTEXT	member	struct_ethtool_rxnfc	rss_context	include/linux/ethtool.h
EFX_NEED_HASH_64		nsymbol	hash_64	include/linux/hash.h
EFX_HAVE_XDP_FRAME_API		symbol	xdp_frame	include/net/xdp.h
EFX_HAVE_XDP_DATA_META		member	struct_xdp_buff	data_meta	include/linux/filter.h
EFX_HAVE_OLD_DEV_OPEN	symtype	dev_open	include/linux/netdevice.h	int (struct net_device *)
EFX_NEED_CONSUME_SKB_ANY	nsymbol	dev_consume_skb_any	include/linux/netdevice.h
EFX_NEED_CSUM16_SUB	nsymbol	csum16_sub	include/net/checksum.h
EFX_HAVE_NEW_NDO_SETUP_TC		memtype	struct_net_device_ops	ndo_setup_tc	include/linux/netdevice.h	int (*)(struct net_device *, enum tc_setup_type, void *)
EFX_HAVE_TC_BLOCK_OFFLOAD		symbol	tc_block_offload	include/net/pkt_cls.h
EFX_HAVE_FLOW_BLOCK_OFFLOAD		symbol	flow_block_offload	include/net/flow_offload.h
EFX_HAVE_TC_INDR_BLOCK_CB_REGISTER	symbol	__tc_indr_block_cb_register	include/net/pkt_cls.h
EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER	symbol	__flow_indr_block_cb_register	include/net/flow_offload.h
EFX_HAVE_TC_ACTION_COOKIE		custom
EFX_HAVE_TC_FLOW_OFFLOAD		file	include/net/flow_offload.h
EFX_NEED_TCF_MIRRED_DEV			nsymbol	tcf_mirred_dev	include/net/tc_act/tc_mirred.h
EFX_HAVE_STRUCT_SIZE			symbol	struct_size	include/linux/overflow.h
EFX_NEED_FLOW_RULE_MATCH_CVLAN		nsymbol	flow_rule_match_cvlan	include/net/flow_offload.h
EFX_HAVE_FLOW_DISSECTOR_KEY_CVLAN	symbol	FLOW_DISSECTOR_KEY_CVLAN	include/net/flow_dissector.h
EFX_HAVE_FLOW_DISSECTOR_KEY_ENC_IP	symbol	FLOW_DISSECTOR_KEY_ENC_IP	include/net/flow_dissector.h
EFX_HAVE_FLOW_DISSECTOR_VLAN_TPID	member	struct_flow_dissector_key_vlan	vlan_tpid	include/net/flow_dissector.h
EFX_HAVE_OLD_TCF_ACTION_STATS_UPDATE	symtype	tcf_action_stats_update	include/net/act_api.h	void(struct tc_action *a, u64 bytes, u64 packets, u64 lastuse)
EFX_HAVE_FLOW_STATS_TYPE		symbol	flow_action_hw_stats	include/net/flow_offload.h
EFX_HAVE_TCB_EXTACK			member	struct_tc_block_offload	extack	include/net/pkt_cls.h
EFX_HAVE_NETIF_IS_VXLAN			symbol	netif_is_vxlan	include/net/vxlan.h
EFX_HAVE_NETIF_IS_GENEVE		symbol	netif_is_geneve	include/net/geneve.h
EFX_HAVE_IPV6_STUBS_DST_LOOKUP_FLOW	member	struct_ipv6_stub	ipv6_dst_lookup_flow	include/net/ipv6_stubs.h
EFX_HAVE_IPV6_STUBS_DST_LOOKUP_FLOW	member	struct_ipv6_stub	ipv6_dst_lookup_flow	include/net/addrconf.h
EFX_HAVE_SKB__LIST			member	struct_sk_buff	list	include/linux/skbuff.h
EFX_HAVE_RECEIVE_SKB_LIST		symbol	netif_receive_skb_list	include/linux/netdevice.h
EFX_NEED_SKB_LIST_DEL_INIT		nsymbol	skb_list_del_init	include/linux/skbuff.h
EFX_NEED_SKB_MARK_NOT_ON_LIST		nsymbol	skb_mark_not_on_list	include/linux/skbuff.h
EFX_HAVE_MMIOWB				symbol	mmiowb	include/asm-generic/io.h
EFX_HAVE_NDO_GET_DEVLINK	member	struct_net_device_ops	ndo_get_devlink_port	include/linux/netdevice.h
EFX_HAVE_DEVLINK_INFO		symbol	devlink_info_version_running_put	include/net/devlink.h
EFX_HAVE_PCI_FIND_NEXT_EXT_CAPABILITY	symbol	pci_find_next_ext_capability	include/linux/pci.h
EFX_HAVE_XDP_SOCK			export	xdp_get_umem_from_qid	include/net/xdp_sock.h net/xdp/xdp_umem.c
EFX_HAVE_XSK_OFFSET_ADJUST             symbol  xsk_umem_adjust_offset  include/net/xdp_sock.h
EFX_HAVE_XDP_UMEM_RELEASE_ADDR         symbol  xsk_umem_release_addr  include/net/xdp_sock.h
EFX_HAVE_XSK_UMEM_CONS_TX_2PARAM 	symtype xsk_umem_consume_tx	include/net/xdp_sock.h bool(struct xdp_umem *umem, struct xdp_desc *)
EFX_HAVE_XSK_NEED_WAKEUP		symbol	xsk_umem_uses_need_wakeup	include/net/xdp_sock.h
" | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

######################################################################
# Implementation for more tricky types

function do_EFX_HAVE_MTD_DIRECT_ACCESS()
{
    # RHEL 4 is missing <mtd/mtd-abi.h>; assume old operation names
    # in this case
    # kernels post 3.5 changed to use _<operator> for function pointers
    # kernels post 3.7 changed the location of mtd-abi.h to uapi/..
    (! test -f $KBUILD_SRC/include/mtd/mtd-abi.h && \
    ! test -f $KBUILD_SRC/include/uapi/mtd/mtd-abi.h ) || \
	 defer_test_memtype pos struct_mtd_info erase include/linux/mtd/mtd.h void
}

function do_EFX_USE_NETDEV_STATS()
{
    local source="
#include <linux/netdevice.h>
struct net_device_stats *stats;
void test(struct net_device *net_dev) { stats = &net_dev->stats; }"
    defer_test_compile pos "$source"
}

function do_EFX_HAVE_BIN_ATTRIBUTE_OP_FILE_PARAM()
{
    defer_test_compile pos "
#include <linux/list.h>
#include <linux/sysfs.h>
ssize_t f(struct file *, struct kobject *, struct bin_attribute *,
          char *, loff_t, size_t);
struct bin_attribute attr = { .read = f };
"
}

function do_EFX_HAVE_OLD_DMA_MAPPING_ERROR()
{
    # We should be able to use symtype for this, but dma_mapping_error
    # used to be defined as a macro on some architectures.
    defer_test_compile pos "
#include <linux/dma-mapping.h>
int f(void) { return dma_mapping_error(0); }
"
}

function do_EFX_HAVE_XEN_START_INFO()
{
    case $SRCARCH in
	i386 | x86)
	    test_export xen_start_info arch/$SRCARCH/xen/enlighten.c || return
	    ;;
	ia64)
	    test_export xen_start_info arch/ia64/xen/hypervisor.c || return
	    ;;
	*)
	    return 1
	    ;;
    esac

    test_symbol xen_start_info \
	include/asm/xen/hypervisor.h \
	arch/$SRCARCH/include/asm/xen/hypervisor.h
}

function do_EFX_HAVE_EXPORTED_CPU_DATA()
{
    # cpu_data gets exported in lots of places in various kernels
    test_export cpu_data \
        arch/x86_64/kernel/x8664_ksyms.c \
        arch/i386/kernel/i386_ksyms.c \
        arch/$SRCARCH/kernel/smpboot.c \
        drivers/xen/core/smpboot.c && \
	defer_test_symtype pos cpu_data include/asm/processor.h 'struct cpuinfo_x86[]'
}

function do_EFX_HAVE_GRO()
{
    # We check symbol types here because in Linux 2.6.29 and 2.6.30
    # napi_gro_frags() took an extra parameter.  We don't bother to
    # support GRO on those versions; no major distribution used them.
    if test_symbol napi_gro_receive_gr include/linux/netdevice.h; then
	true
    elif test_symbol gro_result_t include/linux/netdevice.h; then
	defer_test_symtype pos napi_gro_frags include/linux/netdevice.h "gro_result_t(struct napi_struct *)"
    else
	defer_test_symtype pos napi_gro_frags include/linux/netdevice.h "int(struct napi_struct *)"
    fi
}

function do_EFX_NEED_SET_NORMALIZED_TIMESPEC
{
    ! test_inline_symbol set_normalized_timespec include/linux/time.h && \
	! test_export set_normalized_timespec include/linux/time.h kernel/time.c
}

function do_EFX_HAVE_OLD_ETHTOOL_RXFH_INDIR
{
    test_symbol ETHTOOL_GRXFHINDIR include/linux/ethtool.h && \
	! test_symbol get_rxfh_indir_size include/linux/ethtool.h
}

function do_EFX_HAVE_ETHTOOL_SET_RXFH_NOCONST
{
	defer_test_compile pos "
#include <linux/ethtool.h>
static int test_func(struct net_device *a, u32  *b, u8 *c)
{
	return 0;
}
struct ethtool_ops_ext test = {
	.set_rxfh = test_func
};
"
}

function do_EFX_NEED_IS_COMPAT_TASK
{
    defer_test_compile neg "
#include <linux/compat.h>
int test(void) { return is_compat_task(); }
"
}

function do_EFX_NEED_PTP_CLOCK_PPSUSR
{
    # If the enum is not complete
    test_symbol PTP_CLOCK_PPS include/linux/ptp_clock_kernel.h && \
      ! test_symbol PTP_CLOCK_PPSUSR include/linux/ptp_clock_kernel.h
}

function do_EFX_HAVE_PHC_SUPPORT
{
    if [ "${CONFIG_PTP_1588_CLOCK:-}" = "y" ] || [ "${CONFIG_PTP_1588_CLOCK:-}" = "m" ]; then
        # Ideally this would use this (but it is a deferred test)
        #   test_member struct ptp_clock_event ptp_evt pps_times
        # NB pps_times is needed for the PTP_CLOCK_PPSUSR event
        test_export ptp_clock_register && \
          test_symbol pps_times include/linux/ptp_clock_kernel.h
    else
        return 1
    fi
}

function do_EFX_HAVE_PHYS_ADDR_T
{
    local source="
#include <linux/types.h>
#include <asm/page.h>
phys_addr_t paddr;"
    test_compile "$source"
}

function do_EFX_HAVE_OLD_KMAP_ATOMIC
{
    # This is a negative test because the new implementation of
    # kmap_atomic() was a macro that accepts and ignores extra
    # arguments.
    defer_test_compile neg "
#include <linux/highmem.h>

void *f(struct page *p)
{
	return kmap_atomic(p);
}
"
}

function do_EFX_HAVE_KTIME_UNION
{
	defer_test_compile pos "
#include <linux/ktime.h>

void f(void)
{
	ktime_t t;
	t.tv64 = 0;
}
"
}

function do_EFX_HAVE_NEW_ALLOC_WORKQUEUE
{
    # The old macro only accepts 3 arguments.
    defer_test_compile pos '
#include <linux/workqueue.h>

void f(void)
{
	alloc_workqueue("%s", 0, 0, "test");
}
'
}

function do_EFX_HAVE_TC_ACTION_COOKIE
{
    # TC action cookie isn't upstream yet.  When it is, we expect something
    # like the following compat rule to work:
    #		member	struct_flow_action_entry	cookie	include/net/flow_offload.h
    # In the meantime, we keep around our code to support it but make the
    # compat symbol always false, in case the eventually merged version is
    # different to that against which our current code was developed.
    return 1
}

TOPDIR=$(dirname "$0")/../../../..
source $TOPDIR/scripts/kernel_compat_funcs.sh
