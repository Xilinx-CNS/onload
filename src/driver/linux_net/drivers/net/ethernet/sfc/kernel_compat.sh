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
EFX_WANT_NDO_POLL_CONTROLLER		kver	<	4.19
EFX_HAVE_PCI_TPH			file				include/linux/pci-tph.h
EFX_HAVE_PCIE_ENABLE_TPH		symbol	pcie_enable_tph		include/linux/pci-tph.h
EFX_HAVE_PCIE_TPH_GET_CPU_ST		symbol	pcie_tph_get_cpu_st	include/linux/pci-tph.h
EFX_HAVE_NET_GRO_H			file				include/net/gro.h
EFX_NEED_SKB_GRO_MAY_PULL              nsymbol  skb_gro_may_pull    include/net/gro.h
EFX_HAVE_CSUM_LEVEL			symbol	csum_level		include/linux/skbuff.h
EFX_HAVE_HWTSTAMP_FLAGS         symbol	hwtstamp_flags		include/uapi/linux/net_tstamp.h
EFX_HAVE_KERNEL_HWTSTAMP_CONFIG         symbol kernel_hwtstamp_config include/linux/net_tstamp.h
EFX_HAVE_KERNEL_HWTSTAMP_CONFIG_IFR     member struct_kernel_hwtstamp_config ifr include/linux/net_tstamp.h
EFX_HAVE_NDO_HWTSTAMP_GET               member  struct_net_device_ops ndo_hwtstamp_get include/linux/netdevice.h
EFX_HAVE_HWTSTAMP_CONFIG_TO_KERNEL      symbol hwtstamp_config_to_kernel    include/linux/net_tstamp.h
EFX_HAVE_HWTSTAMP_CONFIG_FROM_KERNEL    symbol hwtstamp_config_from_kernel  include/linux/net_tstamp.h
EFX_HAVE_MTD_USECOUNT			member  struct_mtd_info	usecount		include/linux/mtd/mtd.h
EFX_HAVE_NETDEV_STATS64_VOID		memtype	struct_net_device_ops	ndo_get_stats64	include/linux/netdevice.h	void(*)(struct net_device *, struct rtnl_link_stats64 *)
EFX_NEED_HWMON_T_ALARM			nsymbol	HWMON_T_ALARM		include/linux/hwmon.h
EFX_HAVE_HWMON_READ_STRING		member	struct_hwmon_ops	read_string	include/linux/hwmon.h
EFX_HAVE_HWMON_READ_STRING_CONST	memtype	struct_hwmon_ops	read_string	include/linux/hwmon.h	int(*)(struct device *, enum hwmon_sensor_types, u32, int, const char **)
EFX_HAVE_ETHTOOL_SET_PHYS_ID		symbol	set_phys_id		include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GMODULEEEPROM		symbol	get_module_eeprom	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_EEPROM_BY_PAGE		symbol	get_module_eeprom_by_page	include/linux/ethtool.h
EFX_NEED_DMA_SET_MASK_AND_COHERENT		nsymbol	dma_set_mask_and_coherent	include/linux/dma-mapping.h
EFX_NEED_BITMAP_ZALLOC			nsymbol	bitmap_zalloc		include/linux/bitmap.h
EFX_HAVE_ASM_SYSTEM_H			file				asm/system.h
EFX_HAVE_EXPORTED_CPU_SIBLING_MAP	export	(per_cpu__)?cpu_sibling_map	include/asm/smp.h	arch/$SRCARCH/include/asm/smp.h	arch/$SRCARCH/kernel/smpboot.c	drivers/xen/core/smpboot.c
EFX_HAVE_NDO_SIZE			member	struct_net_device_ops	ndo_size		include/linux/netdevice.h
EFX_HAVE_NDO_SIZE_RH			member	struct_net_device_ops	ndo_size_rh		include/linux/netdevice.h
EFX_HAVE_NDO_SET_VF_VLAN_PROTO		memtype	struct_net_device_ops	ndo_set_vf_vlan		include/linux/netdevice.h	int (*)(struct net_device *, int, u16, u8, __be16)
EFX_HAVE_NDO_EXT_SET_VF_VLAN_PROTO		memtype struct_net_device_ops_extended	ndo_set_vf_vlan	include/linux/netdevice.h	int (*)(struct net_device *, int, u16, u8, __be16)
EFX_HAVE_NDO_FEATURES_CHECK		member	struct_net_device_ops	ndo_features_check	include/linux/netdevice.h
EFX_HAVE_VF_LINK_STATE			member	struct_net_device_ops	ndo_set_vf_link_state	include/linux/netdevice.h
EFX_HAVE_NDO_BUSY_POLL			member	struct_net_device_ops	ndo_busy_poll	        include/linux/netdevice.h
EFX_HAVE_NDO_GET_PHYS_PORT_ID		member	struct_net_device_ops	ndo_get_phys_port_id	include/linux/netdevice.h
EFX_HAVE_NDO_GET_PHYS_PORT_NAME		member	struct_net_device_ops	ndo_get_phys_port_name	include/linux/netdevice.h
EFX_HAVE_NDO_GET_PORT_PARENT_ID		member	struct_net_device_ops	ndo_get_port_parent_id	include/linux/netdevice.h
EFX_HAVE_NDO_VLAN_RX_ADD_VID_PROTO	memtype	struct_net_device_ops	ndo_vlan_rx_add_vid	include/linux/netdevice.h	int (*)(struct net_device *, __be16, u16)
EFX_HAVE_NDO_VLAN_RX_ADD_VID_RC		memtype	struct_net_device_ops	ndo_vlan_rx_add_vid	include/linux/netdevice.h	int (*)(struct net_device *, u16)
EFX_NEED_ETHER_ADDR_COPY		nsymbol ether_addr_copy		include/linux/etherdevice.h
EFX_NEED_ETH_HW_ADDR_SET		nsymbol	eth_hw_addr_set		include/linux/etherdevice.h
EFX_NEED_NS_TO_TIMESPEC			nexport ns_to_timespec		include/linux/time.h	kernel/time.c
EFX_HAVE_TIMESPEC64			symbol	timespec64		include/linux/time64.h	include/linux/time.h
EFX_NEED_KTIME_GET_REAL_TS64		nsymbol	ktime_get_real_ts64	include/linux/timekeeping.h	include/linux/ktime.h
EFX_NEED_KTIME_COMPARE			nsymbol	ktime_compare		include/linux/ktime.h
EFX_NEED_RTC_TIME64_TO_TM		nsymbol	rtc_time64_to_tm	include/linux/rtc.h
EFX_NEED_SET_NORMALIZED_TIMESPEC	custom
EFX_HAVE_OLD_ETHTOOL_GET_RXNFC		memtype	struct_ethtool_ops	get_rxnfc	include/linux/ethtool.h int (*)(struct net_device *, struct ethtool_rxnfc *, void *)
EFX_HAVE_CPU_RMAP			file				include/linux/cpu_rmap.h
EFX_NEED_PTP_CLOCK_PPSUSR		custom
EFX_NEED_KTIME_GET_SNAPSHOT		nsymbol	ktime_get_snapshot	include/linux/timekeeping.h
EFX_HAVE_PTP_CLOCK_GETTIMEX64		member	struct_ptp_clock_info gettimex64	include/linux/ptp_clock_kernel.h
EFX_NEED_SCALED_PPM_TO_PPB		nsymbol scaled_ppm_to_ppb		include/linux/ptp_clock_kernel.h
EFX_NEED_SKB_FRAG_OFF			nsymbol	skb_frag_off		include/linux/skbuff.h
EFX_HAVE_ETHTOOL_GET_RXFH_INDIR	symbol	get_rxfh_indir	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_RXFH_INDIR_SIZE	symbol	get_rxfh_indir_size	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_RXFH		symbol	get_rxfh	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_RXFH_KEY_SIZE		symbol	get_rxfh_key_size	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_SET_RXFH_NOCONST	custom
EFX_NEED_IS_COMPAT_TASK			custom
EFX_NEED_COMPAT_U64			nsymbol	compat_u64		include/asm/compat.h arch/$SRCARCH/include/asm/compat.h include/asm-$SRCARCH/compat.h
EFX_HAVE_IRQ_NOTIFIERS			symbol  irq_affinity_notify	include/linux/interrupt.h
EFX_NEED_SET_TSO_MAX_SIZE		nsymbol netif_set_tso_max_size	include/linux/netdevice.h
EFX_NEED_SET_TSO_MAX_SEGS		nsymbol netif_set_tso_max_segs	include/linux/netdevice.h
EFX_NEED___BQL				nsymbol __netdev_tx_sent_queue	include/linux/netdevice.h
EFX_NEED_KERNEL_ETHTOOL_TS_INFO		nsymbol	kernel_ethtool_ts_info	include/linux/ethtool.h
EFX_HAVE_OLD___VLAN_PUT_TAG		symtype	__vlan_put_tag		include/linux/if_vlan.h	struct sk_buff *(struct sk_buff *, u16)
EFX_HAVE_VLAN_INSERT_TAG_SET_PROTO	symbol vlan_insert_tag_set_proto	include/linux/if_vlan.h
EFX_NEED_NETDEV_NOTIFIER_INFO_TO_DEV	nsymbol	netdev_notifier_info_to_dev	include/linux/netdevice.h
EFX_HAVE_NETDEV_REGISTER_RH		symbol	register_netdevice_notifier_rh	include/linux/netdevice.h
EFX_NEED_PCI_AER_CLEAR_NONFATAL_STATUS	nsymbol pci_aer_clear_nonfatal_status	include/linux/aer.h
EFX_HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING	symbol	pci_enable_pcie_error_reporting	include/linux/aer.h
EFX_HAVE_EEH_DEV_CHECK_FAILURE		symbol	eeh_dev_check_failure	arch/powerpc/include/asm/eeh.h
EFX_NEED_PCI_DEV_TO_EEH_DEV		nsymbol	pci_dev_to_eeh_dev	include/linux/pci.h
EFX_HAVE_IOREMAP_WC			symbol	ioremap_wc		arch/$SRCARCH/include/asm/io.h include/asm-$SRCARCH/io.h include/asm-generic/io.h
EFX_HAVE_IOREMAP_NOCACHE		symbol	ioremap_nocache		include/asm-generic/io.h
EFX_HAVE_OLD_KMAP_ATOMIC		custom
EFX_HAVE_NAPI_STRUCT_NAPI_ID		member	struct_napi_struct	napi_id	include/linux/netdevice.h
EFX_HAVE_NAPI_HASH_ADD			symbol	napi_hash_add		include/linux/netdevice.h
EFX_HAVE_NAPI_HASH_DEL_RETURN		symtype	napi_hash_del		include/linux/netdevice.h	int (struct napi_struct *)
EFX_NEED_NETIF_NAPI_ADD_WEIGHT		nsymbol	netif_napi_add_weight	include/linux/netdevice.h
EFX_HAVE_OLD_NETIF_NAPI_ADD		symtype	netif_napi_add		include/linux/netdevice.h	void (struct net_device *, struct napi_struct *, int (*)(struct napi_struct *, int), int)
EFX_NEED_SKB_SET_HASH			nsymbol skb_set_hash		include/linux/skbuff.h
EFX_HAVE_SKB_L4HASH			member	struct_sk_buff l4_rxhash	include/linux/skbuff.h
EFX_HAVE_BUSY_POLL			file				include/net/busy_poll.h
EFX_NEED_SKB_VLAN_TAG_GET		nsymbol	skb_vlan_tag_get	include/linux/if_vlan.h
EFX_NEED_IPV6_NFC			nsymbol	ethtool_tcpip6_spec	include/uapi/linux/ethtool.h
EFX_HAVE_SKB_HASH			member	struct_sk_buff hash	include/linux/skbuff.h
EFX_HAVE_INDIRECT_CALL_WRAPPERS		file				include/linux/indirect_call_wrapper.h
EFX_HAVE_QUEUE_TRANS_TIMEOUT_ATOMIC	memtype	struct_netdev_queue trans_timeout	include/linux/netdevice.h	atomic_long_t

# Stuff needed in code other than the linux net driver
EFX_NEED_PCI_ENABLE_MSIX_RANGE          nsymbol pci_enable_msix_range include/linux/pci.h
EFX_NEED_PCI_MSIX_VEC_COUNT		nsymbol	pci_msix_vec_count	include/linux/pci.h
EFX_HAVE_VF_INFO_MIN_TX_RATE		member	struct_ifla_vf_info min_tx_rate	include/linux/if_link.h
EFX_HAVE_VOID_DYNAMIC_NETDEV_DBG	symtype	__dynamic_netdev_dbg	include/linux/dynamic_debug.h void (struct _ddebug *, const struct net_device *, const char *, ...)
EFX_HAVE_GSO_PARTIAL			symbol	SKB_GSO_PARTIAL		include/linux/skbuff.h
EFX_HAVE_GSO_UDP_TUNNEL_CSUM		symbol	SKB_GSO_UDP_TUNNEL_CSUM	include/linux/skbuff.h
EFX_NEED_SKB_IS_GSO_TCP		nsymbol	skb_is_gso_tcp	include/linux/skbuff.h
EFX_HAVE_GSO_H				file	include/net/gso.h
EFX_NEED_NETDEV_RSS_KEY_FILL	nsymbol	netdev_rss_key_fill	include/linux/netdevice.h
EFX_HAVE_NETIF_SET_XPS_QUEUE_NON_CONST	symtype	netif_set_xps_queue include/linux/netdevice.h	int (struct net_device *, struct cpumask *, u16)
EFX_NEED_CPUMASK_LOCAL_SPREAD	nsymbol	cpumask_local_spread	include/linux/cpumask.h
EFX_NEED_SKB_INNER_TRANSPORT_OFFSET	nsymbol	skb_inner_transport_offset	include/linux/skbuff.h
EFX_HAVE_SKB_XMIT_MORE	bitfield	struct_sk_buff	xmit_more	include/linux/skbuff.h
EFX_HAVE_SK_BUFF_LIST          symbol  sk_buff_list            include/linux/skbuff.h
EFX_HAVE_NETDEV_XMIT_MORE	symbol	netdev_xmit_more	include/linux/netdevice.h
EFX_HAVE_NDO_ADD_VXLAN_PORT	member	struct_net_device_ops	ndo_add_vxlan_port	include/linux/netdevice.h
EFX_NEED_PAGE_REF_ADD		nfile				include/linux/page_ref.h
EFX_NEED_HWMON_DEVICE_REGISTER_WITH_INFO	nsymbol	hwmon_device_register_with_info	include/linux/hwmon.h
EFX_HAVE_NDO_UDP_TUNNEL_ADD	member	struct_net_device_ops	ndo_udp_tunnel_add	include/linux/netdevice.h
EFX_HAVE_UDP_TUNNEL_NIC_INFO	symbol	udp_tunnel_nic_info	include/net/udp_tunnel.h
EFX_HAVE_NEW_FLOW_KEYS		member	struct_flow_keys	basic		include/net/flow_dissector.h
EFX_HAVE_NDO_ADD_GENEVE_PORT	member	struct_net_device_ops	ndo_add_geneve_port	include/linux/netdevice.h
EFX_HAVE_NETDEV_LLTX		nsymbol	NETIF_F_LLTX	include/linux/netdev_features.h
EFX_HAVE_NETDEV_MTU_LIMITS	member	struct_net_device	max_mtu	include/linux/netdevice.h
EFX_NEED_BOOL_NAPI_COMPLETE_DONE	nsymtype	napi_complete_done	include/linux/netdevice.h	bool (struct napi_struct *, int)
EFX_HAVE_NETDEV_XDP_FEATURES	member	struct_net_device	xdp_features	include/linux/netdevice.h
EFX_HAVE_XDP	symbol	netdev_bpf	include/linux/netdevice.h
EFX_HAVE_XDP_OLD	symbol	netdev_xdp	include/linux/netdevice.h
EFX_HAVE_XDP_TRACE	file	include/trace/events/xdp.h
EFX_HAVE_XDP_HEAD	member	struct_xdp_buff	data_hard_start	include/linux/filter.h
EFX_HAVE_XDP_PACKET_HEADROOM	symbol	XDP_PACKET_HEADROOM	include/uapi/linux/bpf.h
EFX_HAVE_XDP_TX		symbol	XDP_TX		include/uapi/linux/bpf.h
EFX_HAVE_XDP_TX_FLAGS	memtype	struct_net_device_ops	ndo_xdp_xmit	include/linux/netdevice.h	int (*)(struct net_device *, int, struct xdp_frame **, u32)
EFX_HAVE_XDP_REDIR	symbol	XDP_REDIRECT	include/uapi/linux/bpf.h
EFX_HAVE_XDP_RXQ_INFO	symbol	xdp_rxq_info	include/net/xdp.h
EFX_HAVE_XDP_RXQ_INFO_NAPI_ID	symtype	xdp_rxq_info_reg	include/net/xdp.h	int(struct xdp_rxq_info *, struct net_device *, u32, unsigned int)
EFX_HAVE_XDP_EXT	member	struct_net_device_ops_extended	ndo_xdp	include/linux/netdevice.h
EFX_NEED_XDP_FLUSH	member	struct_net_device_ops	ndo_xdp_flush	include/linux/netdevice.h
EFX_HAVE_XDP_PROG_ATTACHED	member	struct_netdev_bpf	prog_attached	include/linux/netdevice.h
EFX_HAVE_XDP_PROG_ID	member	struct_netdev_bpf	prog_id	include/linux/netdevice.h
EFX_HAVE_BPF_WARN_INVALID_XDP_ACTION_3PARAM	symtype	bpf_warn_invalid_xdp_action	include/linux/filter.h void(struct net_device *, struct bpf_prog *, u32)
EFX_HAVE_BPF_WARN_INVALID_XDP_ACTION_CONST	symtype	bpf_warn_invalid_xdp_action	include/linux/filter.h void(const struct net_device *, const struct bpf_prog *, u32)
EFX_NEED_PAGE_FRAG_FREE	nsymbol	page_frag_free	include/linux/gfp.h include/linux/page_frag_cache.h
EFX_HAVE_FREE_PAGE_FRAG	symbol	__free_page_frag	include/linux/gfp.h
EFX_NEED_VOID_SKB_PUT	nsymtype	skb_put	include/linux/skbuff.h	void *(struct sk_buff *, unsigned int)
EFX_HAVE_ETHTOOL_LINKSETTINGS	symbol	ethtool_link_ksettings	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_LEGACY	symbol	__ethtool_get_settings	include/linux/ethtool.h
EFX_HAVE_LINK_MODE_1000X	symbol	ETHTOOL_LINK_MODE_1000baseX_Full_BIT	include/uapi/linux/ethtool.h
EFX_HAVE_LINK_MODE_25_50_100	symbol	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT	include/uapi/linux/ethtool.h
EFX_HAVE_LINK_MODE_400		symbol	ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT include/uapi/linux/ethtool.h
EFX_HAVE_LINK_MODE_FEC_BITS	symbol	ETHTOOL_LINK_MODE_FEC_BASER_BIT	include/uapi/linux/ethtool.h
EFX_HAVE_NETDEV_EXT_MTU_LIMITS	member	struct_net_device_extended	max_mtu	include/linux/netdevice.h
EFX_HAVE_NDO_EXT_CHANGE_MTU	memtype	struct_net_device_ops_extended	ndo_change_mtu	include/linux/netdevice.h	int (*)(struct net_device *, int)
EFX_HAVE_NDO_TX_TIMEOUT_TXQUEUE	memtype	struct_net_device_ops	ndo_tx_timeout	include/linux/netdevice.h	void (*)(struct net_device *, unsigned int)
EFX_HAVE_ETHTOOL_LINK_LANES	bitfield struct_ethtool_ops	cap_link_lanes_supported	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_FECSTATS	member	struct_ethtool_ops	get_fec_stats	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_FECPARAM	member	struct_ethtool_ops	get_fecparam	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_RXFH_CONTEXT	member	struct_ethtool_ops	get_rxfh_context	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_RXNFC_CONTEXT	member	struct_ethtool_rxnfc	rss_context	include/linux/ethtool.h
EFX_HAVE_XDP_FRAME_API		symbol	xdp_frame	include/net/xdp.h
EFX_HAVE_XDP_COVERT_XDP_BUFF_FRAME_API	symbol	xdp_convert_buff_to_frame include/net/xdp.h
EFX_HAVE_XDP_DATA_META		member	struct_xdp_buff	data_meta	include/linux/filter.h
EFX_HAVE_OLD_DEV_OPEN	symtype	dev_open	include/linux/netdevice.h	int (struct net_device *)
EFX_NEED_CONSUME_SKB_ANY	nsymbol	dev_consume_skb_any	include/linux/netdevice.h
EFX_NEED_CSUM16_SUB	nsymbol	csum16_sub	include/net/checksum.h
EFX_NEED_CSUM_REPLACE_BY_DIFF	nsymbol	csum_replace_by_diff	include/net/checksum.h
EFX_HAVE_NEW_NDO_SETUP_TC		memtype	struct_net_device_ops	ndo_setup_tc	include/linux/netdevice.h	int (*)(struct net_device *, enum tc_setup_type, void *)
EFX_HAVE_TC_BLOCK_OFFLOAD		symbol	tc_block_offload	include/net/pkt_cls.h
EFX_HAVE_FLOW_BLOCK_OFFLOAD		symbol	flow_block_offload	include/net/flow_offload.h
EFX_HAVE_TC_INDR_BLOCK_CB_REGISTER	symbol	__tc_indr_block_cb_register	include/net/pkt_cls.h
EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER	symbol	__flow_indr_block_cb_register	include/net/flow_offload.h
EFX_HAVE_FLOW_INDR_BLOCK_CB_ALLOC	symbol	flow_indr_block_cb_alloc	include/net/flow_offload.h
EFX_HAVE_FLOW_INDR_DEV_REGISTER		symbol	flow_indr_dev_register	include/net/flow_offload.h
EFX_HAVE_FLOW_INDR_QDISC		member	struct_flow_block_indr	sch	include/net/flow_offload.h
EFX_HAVE_TC_ACTION_COOKIE		custom
EFX_HAVE_TC_FLOW_OFFLOAD		file	include/net/flow_offload.h
EFX_NEED_TCF_MIRRED_DEV			nsymbol	tcf_mirred_dev	include/net/tc_act/tc_mirred.h
EFX_HAVE_STRUCT_SIZE			symbol	struct_size	include/linux/overflow.h
EFX_NEED_ARRAY_SIZE			nsymbol	array_size	include/linux/overflow.h
EFX_NEED_FLOW_RULE_MATCH_CVLAN		nsymbol	flow_rule_match_cvlan	include/net/flow_offload.h
EFX_NEED_FLOW_RULE_MATCH_CT		nsymbol	flow_rule_match_ct	include/net/flow_offload.h
EFX_HAVE_FLOW_DISSECTOR_KEY_CVLAN	symbol	FLOW_DISSECTOR_KEY_CVLAN	include/net/flow_dissector.h
EFX_HAVE_FLOW_DISSECTOR_KEY_ENC_IP	symbol	FLOW_DISSECTOR_KEY_ENC_IP	include/net/flow_dissector.h
EFX_HAVE_FLOW_DISSECTOR_64BIT_USED_KEYS memtype struct_flow_dissector   used_keys   include/net/flow_dissector.h unsigned long long
EFX_HAVE_FLOW_DISSECTOR_VLAN_TPID	member	struct_flow_dissector_key_vlan	vlan_tpid	include/net/flow_dissector.h
EFX_HAVE_OLD_TCF_ACTION_STATS_UPDATE	symtype	tcf_action_stats_update	include/net/act_api.h	void(struct tc_action *a, u64 bytes, u64 packets, u64 lastuse)
EFX_HAVE_FLOW_STATS_TYPE		symbol	flow_action_hw_stats	include/net/flow_offload.h
EFX_HAVE_FLOW_STATS_DROPS		member	struct_flow_stats	drops	include/net/flow_offload.h
EFX_HAVE_NF_FLOW_TABLE_OFFLOAD		symbol	nf_flow_table_offload_add_cb	include/net/netfilter/nf_flow_table.h
EFX_HAVE_TC_ACT_CT			file	include/net/tc_act/tc_ct.h
EFX_HAVE_TCB_EXTACK			member	struct_tc_block_offload	extack	include/net/pkt_cls.h
EFX_HAVE_TCF_EXTACK			member	struct_tc_cls_common_offload	extack	include/net/pkt_cls.h
EFX_HAVE_TC_CAN_EXTACK			symbol	tc_can_offload_extack	include/net/pkt_cls.h
EFX_HAVE_NETIF_IS_VXLAN			symbol	netif_is_vxlan	include/net/vxlan.h
EFX_HAVE_NETIF_IS_GENEVE		symbol	netif_is_geneve	include/net/geneve.h
EFX_NEED_IDA_ALLOC_RANGE		nsymbol	ida_alloc_range		include/linux/idr.h
EFX_HAVE_IPV6_STUBS_DST_LOOKUP_FLOW	custom
EFX_HAVE_SKB__LIST			member	struct_sk_buff	list	include/linux/skbuff.h
EFX_HAVE_RECEIVE_SKB_LIST		symbol	netif_receive_skb_list	include/linux/netdevice.h
EFX_NEED_SKB_LIST_DEL_INIT		nsymbol	skb_list_del_init	include/linux/skbuff.h
EFX_NEED_SKB_MARK_NOT_ON_LIST		nsymbol	skb_mark_not_on_list	include/linux/skbuff.h
EFX_HAVE_MMIOWB				symbol	mmiowb	include/asm-generic/io.h
EFX_HAVE_NET_DEVLINK_H			file				include/net/devlink.h
EFX_HAVE_NDO_GET_DEVLINK_PORT	member	struct_net_device_ops	ndo_get_devlink_port	include/linux/netdevice.h
EFX_HAVE_SET_NETDEV_DEVLINK_PORT	symbol	SET_NETDEV_DEVLINK_PORT	include/linux/netdevice.h
EFX_HAVE_DEVLINK_INFO		symbol	devlink_info_version_running_put	include/net/devlink.h
EFX_NEED_DEVLINK_INFO_BOARD_SERIAL_NUMBER_PUT	nsymbol	devlink_info_board_serial_number_put	include/net/devlink.h
EFX_HAVE_DEVLINK_INFO_DRIVER_NAME_PUT	symbol devlink_info_driver_name_put	include/net/devlink.h
EFX_HAVE_DEVLINK_OPS_SUPPORTED_FLASH_UPDATE_PARAMS	member	devlink_ops	supported_flash_update_params	include/net/devlink.h
EFX_HAVE_DEVLINK_FLASH_UPDATE_PARAMS	symbol devlink_flash_update_params	include/net/devlink.h
EFX_HAVE_DEVLINK_FLASH_UPDATE_PARAMS_FW	member	struct_devlink_flash_update_params	fw	include/net/devlink.h
EFX_HAVE_DEVLINK_FLASH_UPDATE_BEGIN_NOTIFY	symbol	devlink_flash_update_begin_notify	include/net/devlink.h
EFX_NEED_DEVLINK_FLASH_UPDATE_STATUS_NOTIFY	nsymbol	devlink_flash_update_status_notify	include/net/devlink.h
EFX_NEED_DEVLINK_FLASH_UPDATE_TIMEOUT_NOTIFY	nsymbol	devlink_flash_update_timeout_notify	include/net/devlink.h
EFX_HAVE_DEVLINK_ALLOC_DEV		symtype	devlink_alloc		include/net/devlink.h	struct devlink *(const struct devlink_ops *, size_t, struct device *)
EFX_HAVE_VOID_DEVLINK_REGISTER		symtype	devlink_register	include/net/devlink.h	void(struct devlink *)
EFX_NEED_ETHTOOL_FLASH_DEVICE		nsymbol devlink_compat_flash_update	include/net/devlink.h
EFX_HAVE_DEVLINK_HEALTH_REPORTER	symtype	devlink_health_reporter_create	include/net/devlink.h	struct devlink_health_reporter *(struct devlink *, const struct devlink_health_reporter_ops *, u64, void *)
EFX_HAVE_VOID_DEVLINK_FMSG_STRING_PUT   symtype devlink_fmsg_string_put include/net/devlink.h void(struct devlink_fmsg *, const char *)
EFX_HAVE_DEVLINK_HEALTH_REPORTER_OPS_EXTACK memtype struct_devlink_health_reporter_ops diagnose include/net/devlink.h int(*)(struct devlink_health_reporter *, struct devlink_fmsg *,	struct netlink_ext_ack *)
EFX_HAVE_ETHTOOL_COALESCE_CQE		memtype	struct_ethtool_ops	get_coalesce	include/linux/ethtool.h	int (*)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *)
EFX_HAVE_ETHTOOL_GET_RINGPARAM_EXTACK	memtype	struct_ethtool_ops	get_ringparam	include/linux/ethtool.h	void (*)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *)
EFX_HAVE_ETHTOOL_SET_RINGPARAM_EXTACK	memtype	struct_ethtool_ops	set_ringparam	include/linux/ethtool.h	int (*)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *)

EFX_HAVE_PCI_ALLOC_DYN			symbol	pci_msix_can_alloc_dyn	include/linux/pci.h
EFX_HAVE_XDP_SOCK			export	xdp_get_umem_from_qid	include/net/xdp_sock.h
EFX_HAVE_XDP_SOCK_DRV			export	xdp_get_umem_from_qid	include/net/xdp_sock_drv.h
EFX_HAVE_XSK_POOL			export	xsk_get_pool_from_qid	include/net/xdp_sock_drv.h
EFX_HAVE_XSK_OFFSET_ADJUST             symbol  xsk_umem_adjust_offset  include/net/xdp_sock.h
EFX_HAVE_XDP_UMEM_RELEASE_ADDR         symbol  xsk_umem_release_addr  include/net/xdp_sock.h
EFX_HAVE_XSK_UMEM_CONS_TX_2PARAM	symtype xsk_umem_consume_tx	include/net/xdp_sock.h bool(struct xdp_umem *umem, struct xdp_desc *)
EFX_HAVE_XSK_BUFF_DMA_SYNC_FOR_CPU_2PARAM	symtype xsk_buff_dma_sync_for_cpu	include/net/xdp_sock_drv.h void(struct xdp_buff *, struct xsk_buff_pool *)
EFX_HAVE_XSK_NEED_WAKEUP		symbol	xsk_umem_uses_need_wakeup	include/net/xdp_sock.h include/net/xdp_sock_drv.h
EFX_HAVE_COALESCE_PARAMS		member struct_ethtool_ops supported_coalesce_params include/linux/ethtool.h
EFX_NEED_NETLINK_EXT_ACK		nsymbol	netlink_ext_ack	include/linux/netlink.h
EFX_HAVE_ETHTOOL_RXFH_PARAM		symbol	ethtool_rxfh_param	include/linux/ethtool.h
EFX_HAVE_XDP_QUERY_PROG			symbol XDP_QUERY_PROG	include/linux/netdevice.h
EFX_HAVE_XDP_FRAME_SZ			member struct_xdp_buff	frame_sz	include/net/xdp.h
EFX_NEED_XDP_INIT_BUFF			nsymbol	xdp_init_buff	include/net/xdp.h
EFX_NEED_XDP_PREPARE_BUFF		nsymbol	xdp_prepare_buff	include/net/xdp.h
EFX_NEED_XDP_DO_FLUSH                   nsymbol xdp_do_flush    include/linux/filter.h
EFX_HAVE_VDPA_VQ_STATE			symbol vdpa_vq_state		include/linux/vdpa.h
EFX_HAVE_VDPA_VQ_STATE_SPLIT		symbol vdpa_vq_state_split	include/linux/vdpa.h
EFX_HAVE_GET_VQ_IRQ			member struct_vdpa_config_ops get_vq_irq include/linux/vdpa.h
EFX_HAVE_GET_VQ_NOTIFY			member struct_vdpa_config_ops get_vq_notification include/linux/vdpa.h
EFX_HAVE_GET_DEVICE_FEATURES		member struct_vdpa_config_ops get_device_features include/linux/vdpa.h
EFX_HAVE_VDPA_RESET                     member struct_vdpa_config_ops reset include/linux/vdpa.h
EFX_HAVE_GET_CONFIG_SIZE		member struct_vdpa_config_ops get_config_size include/linux/vdpa.h
EFX_HAVE_VDPA_ALLOC_NVQS_PARAM		symtype __vdpa_alloc_device	include/linux/vdpa.h struct vdpa_device *(struct device *, const struct vdpa_config_ops *, int, size_t)
EFX_HAVE_VDPA_ALLOC_NAME_PARAM          symtype __vdpa_alloc_device     include/linux/vdpa.h struct vdpa_device *(struct device *, const struct vdpa_config_ops *, size_t, const char *)
EFX_HAVE_VDPA_ALLOC_NAME_USEVA_PARAMS	symtype __vdpa_alloc_device	include/linux/vdpa.h struct vdpa_device *(struct device *, const struct vdpa_config_ops *, size_t, const char *, bool)
EFX_HAVE_VDPA_ALLOC_ASID_NAME_USEVA_PARAMS     symtype __vdpa_alloc_device     include/linux/vdpa.h struct vdpa_device *(struct device *, const struct vdpa_config_ops *, unsigned int, unsigned int, size_t, const char *, bool)
EFX_HAVE_VDPA_REGISTER_NVQS_PARAM       symtype _vdpa_register_device   include/linux/vdpa.h int(struct vdpa_device *, int )
EFX_HAVE_VDPA_DMA_MAP_OPAQUE_PARAM	memtype	struct_vdpa_config_ops	dma_map	include/linux/vdpa.h int (*)(struct vdpa_device *, u64, u64, u64, u32, void *)
EFX_HAVE_VDPA_CONFIG_OP_SUSPEND		member struct_vdpa_config_ops  suspend include/linux/vdpa.h
EFX_HAVE_RHASHTABLE			file	include/linux/rhashtable.h
EFX_HAVE_RHASHTABLE_LOOKUP_FAST		symbol	rhashtable_lookup_fast	include/linux/rhashtable.h
EFX_NEED_RHASHTABLE_WALK_ENTER		nsymbol	rhashtable_walk_enter	include/linux/rhashtable.h
EFX_HAVE_RHASHTABLE_WALK_INIT_GFP	symtype	rhashtable_walk_init	include/linux/rhashtable.h	int(struct rhashtable *, struct rhashtable_iter *, gfp_t)
EFX_NEED_STRSCPY			nsymbol	strscpy			include/linux/fortify-string.h include/linux/string.h
EFX_HAVE_NDO_SIOCDEVPRIVATE		member	struct_net_device_ops	ndo_siocdevprivate	include/linux/netdevice.h
EFX_HAVE_NDO_ETH_IOCTL			member	struct_net_device_ops	ndo_eth_ioctl		include/linux/netdevice.h
EFX_NEED_NETDEV_HOLD			nsymbol	netdev_hold		include/linux/netdevice.h
EFX_HAVE_DEV_HOLD_TRACK			symbol	dev_hold_track		include/linux/netdevice.h
EFX_NEED_KREALLOC_ARRAY			nsymbol	krealloc_array		include/linux/slab.h
EFX_HAVE_VDPA_MGMT_INTERFACE		symbol	vdpa_mgmtdev_register	include/linux/vdpa.h
EFX_HAVE_IOMMU_CAPABLE			symbol	iommu_capable		include/linux/iommu.h
EFX_NEED_DEVICE_IOMMU_CAPABLE		nsymbol	device_iommu_capable	include/linux/iommu.h
EFX_HAVE_IOMMU_MAP_GFP_PARAM		symtype iommu_map		include/linux/iommu.h int(struct iommu_domain *, unsigned long iova, phys_addr_t paddr, size_t, int, gfp_t)
EFX_HAVE_VDPA_MGMT_OPS_CONFIG_PARAM	memtype	struct_vdpa_mgmtdev_ops	dev_add	include/linux/vdpa.h int (*)(struct vdpa_mgmt_dev *, const char *, const struct vdpa_dev_set_config *)
EFX_HAVE_VDPA_SUPPORTED_FEATURES	member	struct_vdpa_mgmt_dev	supported_features	include/linux/vdpa.h
EFX_HAVE_VDPA_MAX_SUPPORTED_VQS		member	struct_vdpa_mgmt_dev	max_supported_vqs	include/linux/vdpa.h
EFX_HAVE_VIRTIO_NET_SPEED_LE32		memtype struct_virtio_net_config speed include/uapi/linux/virtio_net.h __le32
EFX_NEED_TIMESPEC64_TO_NS_SIGNED	custom
EFX_HAVE_KOBJECT_DEFAULT_GROUPS		member	struct_kobj_type	default_groups	include/linux/kobject.h
EFX_NEED_REFCOUNT_T			nsymbol	refcount_t		include/linux/refcount.h
EFX_HAVE_XARRAY				symbol	xa_limit		include/linux/xarray.h
EFX_HAVE_AUXILIARY_BUS			file	include/linux/auxiliary_bus.h
EFX_HAVE_NET_RPS_H                     file       include/net/rps.h
EFX_HAVE_IP_TUNNEL_FLAGS_TO_BE16	symbol	ip_tunnel_flags_to_be16	include/net/ip_tunnels.h
EFX_NEED_TIME64_TO_TM			nsymbol	time64_to_tm		include/linux/time.h
EFX_HAVE_ASSIGN_STR_NO_SRC_ARG      custom
" | grep -E -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

######################################################################
# Implementation for more tricky types

function do_EFX_NEED_SET_NORMALIZED_TIMESPEC
{
    ! test_inline_symbol set_normalized_timespec include/linux/time.h && \
	! test_export set_normalized_timespec include/linux/time.h kernel/time.c
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

int test(void);
int test(void) { return is_compat_task(); }
"
}

function do_EFX_NEED_PTP_CLOCK_PPSUSR
{
    # If the enum is not complete
    test_symbol PTP_CLOCK_PPS include/linux/ptp_clock_kernel.h && \
      ! test_symbol PTP_CLOCK_PPSUSR include/linux/ptp_clock_kernel.h
}

function do_EFX_HAVE_OLD_KMAP_ATOMIC
{
    # This is a negative test because the new implementation of
    # kmap_atomic() was a macro that accepts and ignores extra
    # arguments.
    defer_test_compile neg "
#include <linux/highmem.h>

void *f(struct page *p);
void *f(struct page *p)
{
	return kmap_atomic(p);
}
"
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

function do_EFX_HAVE_IPV6_STUBS_DST_LOOKUP_FLOW
{
    if test_symbol ipv6_dst_lookup_flow include/net/addrconf.h; then
	defer_test_memtype pos struct_ipv6_stub	ipv6_dst_lookup_flow	include/net/addrconf.h void
    else
	defer_test_memtype pos struct_ipv6_stub	ipv6_dst_lookup_flow	include/net/ipv6_stubs.h void
    fi
}

function do_EFX_NEED_TIMESPEC64_TO_NS_SIGNED
{
    test -f $KBUILD_SRC/include/linux/time64.h &&
	grep -q 'Prevent multiplication overflow ./' $KBUILD_SRC/include/linux/time64.h
}

function do_EFX_HAVE_ASSIGN_STR_NO_SRC_ARG
{
    test -f $KBUILD_SRC/include/trace/stages/stage6_event_callback.h &&
    grep -q '#define __assign_str(dst)' $KBUILD_SRC/include/trace/stages/stage6_event_callback.h
}

TOPDIR=$(dirname "$0")/../../../..
source $TOPDIR/scripts/kernel_compat_funcs.sh
