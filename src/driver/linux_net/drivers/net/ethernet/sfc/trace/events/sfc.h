/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2013 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM sfc

#if !defined(TRACE_EVENTS_SFC_H) || defined(TRACE_HEADER_MULTI_READ)
#define TRACE_EVENTS_SFC_H

#include <linux/tracepoint.h>
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NET_GRO_H)
#include <net/gro.h>
#endif

TRACE_EVENT(sfc_receive,

	TP_PROTO(const struct sk_buff *skb, bool gro, bool vlan_tagged, u16 vlan_tci),

	TP_ARGS(skb, gro, vlan_tagged, vlan_tci),

	TP_STRUCT__entry(
		__string(	dev_name,		skb->dev->name	)
		__field(	unsigned int,		napi_id		)
		__field(	u16,			queue_mapping	)
		__field(	const void *,		skbaddr		)
		__field(	bool,			gro		)
		__field(	bool,			vlan_tagged	)
		__field(	u16,			vlan_proto	)
		__field(	u16,			vlan_tci	)
		__field(	u16,			protocol	)
		__field(	u8,			ip_summed	)
		__field(	u32,			rxhash		)
		__field(	bool,			l4_rxhash	)
		__field(	unsigned int,		len		)
		__field(	unsigned int,		data_len	)
		__field(	unsigned int,		truesize	)
		__field(	bool,			mac_header_valid)
		__field(	int,			mac_header	)
		__field(	unsigned char,		nr_frags	)
		__field(	u16,			gso_size	)
		__field(	u16,			gso_type	)
	),

	TP_fast_assign(
		__assign_str(dev_name, skb->dev->name);
#ifdef CONFIG_NET_LL_RX_POLL
		__entry->napi_id = skb->napi_id;
#else
		__entry->napi_id = 0;
#endif
		__entry->queue_mapping = skb->queue_mapping;
		__entry->skbaddr = skb;
		__entry->gro = gro;
#ifndef EFX_HAVE_VLAN_RX_PATH
		/* Ignore vlan arguments and look at the skb, as the
		 * vlan arguments are *not* being passed separately
		 * to the kernel
		 */
		__entry->vlan_tagged = skb_vlan_tag_present(skb);
#ifndef EFX_HAVE_OLD___VLAN_PUT_TAG
		__entry->vlan_proto = ntohs(skb->vlan_proto);
#else
		__entry->vlan_proto = ETH_P_8021Q;
#endif
		__entry->vlan_tci = skb_vlan_tag_get(skb);
#else
		__entry->vlan_tagged = vlan_tagged;
		__entry->vlan_proto = ETH_P_8021Q;
		__entry->vlan_tci = vlan_tci;
#endif
		{
			const struct ethhdr* eth;
			unsigned int hlen;
			unsigned int off;

			off = skb_gro_offset(skb);
			hlen = off + sizeof(*eth);
			eth = skb_gro_header_hard((struct sk_buff *) skb, hlen) ?
			      skb_gro_header_slow((struct sk_buff *) skb, hlen, off) :
			      skb_gro_header_fast((struct sk_buff *) skb, off);
			__entry->protocol = gro && eth ?
				ntohs(eth->h_proto) :
				ntohs(skb->protocol);
		};
		__entry->ip_summed = skb->ip_summed;
#ifdef EFX_HAVE_SKB_HASH
		__entry->rxhash = skb->hash;
		__entry->l4_rxhash = skb->l4_hash;
#else
	#ifdef EFX_HAVE_RXHASH_SUPPORT
		__entry->rxhash = skb->rxhash;
	#else
		__entry->rxhash = 0;
	#endif
	#ifdef EFX_HAVE_L4_RXHASH
		__entry->l4_rxhash = skb->l4_rxhash;
	#else
		__entry->l4_rxhash = false;
	#endif
#endif
		__entry->len = skb->len;
		__entry->data_len = skb->data_len;
		__entry->truesize = skb->truesize;
		__entry->mac_header_valid = skb_mac_header_was_set(skb);
		__entry->mac_header = skb_mac_header(skb) - skb->data;
		__entry->nr_frags = skb_shinfo(skb)->nr_frags;
		__entry->gso_size = skb_shinfo(skb)->gso_size;
		__entry->gso_type = skb_shinfo(skb)->gso_type;
	),

	TP_printk("dev_name=%s napi_id=%#x queue_mapping=%u skbaddr=%p gro=%d vlan_tagged=%d vlan_proto=0x%04x vlan_tci=0x%04x protocol=0x%04x ip_summed=%d rxhash=0x%08x l4_rxhash=%d len=%u data_len=%u truesize=%u mac_header_valid=%d mac_header=%d nr_frags=%d gso_size=%d gso_type=%#x",
		  __get_str(dev_name), __entry->napi_id, __entry->queue_mapping,
		  __entry->skbaddr, __entry->gro, __entry->vlan_tagged,
		  __entry->vlan_proto, __entry->vlan_tci, __entry->protocol,
		  __entry->ip_summed, __entry->rxhash, __entry->l4_rxhash,
		  __entry->len, __entry->data_len, __entry->truesize,
		  __entry->mac_header_valid, __entry->mac_header,
		  __entry->nr_frags, __entry->gso_size, __entry->gso_type)
);

TRACE_EVENT(sfc_transmit,

	TP_PROTO(const struct sk_buff *skb, const struct net_device *net_dev),

	TP_ARGS(skb, net_dev),

	TP_STRUCT__entry(
		__string(	dev_name,		net_dev->name	)
		__field(	u16,			queue_mapping	)
		__field(	const void *,		skbaddr		)
		__field(	bool,			vlan_tagged	)
		__field(	u16,			vlan_proto	)
		__field(	u16,			vlan_tci	)
		__field(	u16,			protocol	)
		__field(	u8,			ip_summed	)
		__field(	unsigned int,		len		)
		__field(	unsigned int,		data_len	)
		__field(	int,			network_offset	)
		__field(	bool,			transport_offset_valid)
		__field(	int,			transport_offset)
		__field(	u8,			tx_flags	)
		__field(	u16,			gso_size	)
		__field(	u16,			gso_segs	)
		__field(	u16,			gso_type	)
	),

	TP_fast_assign(
		__assign_str(dev_name, net_dev->name);
		__entry->queue_mapping = skb->queue_mapping;
		__entry->skbaddr = skb;
		__entry->vlan_tagged = skb_vlan_tag_present(skb);
#ifndef EFX_HAVE_OLD___VLAN_PUT_TAG
		__entry->vlan_proto = ntohs(skb->vlan_proto);
#else
		__entry->vlan_proto = ETH_P_8021Q;
#endif
		__entry->vlan_tci = skb_vlan_tag_get(skb);
		__entry->protocol = ntohs(skb->protocol);
		__entry->ip_summed = skb->ip_summed;
		__entry->len = skb->len;
		__entry->data_len = skb->data_len;
		__entry->network_offset = skb_network_offset(skb);
		__entry->transport_offset_valid =
			skb_transport_header_was_set(skb);
		__entry->transport_offset = skb_transport_offset(skb);
#if defined(EFX_HAVE_SKBTX_HW_TSTAMP)
		__entry->tx_flags = skb_shinfo(skb)->tx_flags;
#else
		__entry->tx_flags = skb_shinfo(skb)->tx_flags.flags;
#endif
		__entry->gso_size = skb_shinfo(skb)->gso_size;
		__entry->gso_segs = skb_shinfo(skb)->gso_segs;
		__entry->gso_type = skb_shinfo(skb)->gso_type;
	),

	TP_printk("dev_name=%s queue_mapping=%u skbaddr=%p vlan_tagged=%d vlan_proto=0x%04x vlan_tci=0x%04x protocol=0x%04x ip_summed=%d len=%u data_len=%u network_offset=%d transport_offset_valid=%d transport_offset=%d tx_flags=%d gso_size=%d gso_segs=%d gso_type=%#x",
		  __get_str(dev_name), __entry->queue_mapping, __entry->skbaddr,
		  __entry->vlan_tagged, __entry->vlan_proto, __entry->vlan_tci,
		  __entry->protocol, __entry->ip_summed, __entry->len, __entry->data_len, 
		  __entry->network_offset, __entry->transport_offset_valid,
		  __entry->transport_offset, __entry->tx_flags,
		  __entry->gso_size, __entry->gso_segs, __entry->gso_type)
);

#endif /* TRACE_EVENTS_SFC_H */

#include <trace/define_trace.h>
