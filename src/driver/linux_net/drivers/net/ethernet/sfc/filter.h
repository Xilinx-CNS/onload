/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_FILTER_H
#define EFX_FILTER_H

#include <linux/types.h>
#include <linux/if_ether.h>
#if !defined(EFX_NOT_UPSTREAM) || defined(__KERNEL__)
#include <linux/in6.h>
#include <linux/etherdevice.h>
#else
/* Use userland definition of struct in6_addr */
#include <netinet/in.h>
#endif
#include <asm/byteorder.h>

#if !defined(EFX_USE_KCOMPAT) && defined(EFX_NOT_UPSTREAM) && defined(EFX_NEED_ETHER_ADDR_COPY)
/* Standalone KCOMPAT for driverlink headers */
static inline void efx_ether_addr_copy(u8 *dst, const u8 *src)
{
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
}
#define ether_addr_copy efx_ether_addr_copy
#endif

/**
 * enum efx_filter_match_flags - Flags for hardware filter match type
 * @EFX_FILTER_MATCH_REM_HOST: Match by remote IP host address
 * @EFX_FILTER_MATCH_LOC_HOST: Match by local IP host address
 * @EFX_FILTER_MATCH_REM_MAC: Match by remote MAC address
 * @EFX_FILTER_MATCH_REM_PORT: Match by remote TCP/UDP port
 * @EFX_FILTER_MATCH_LOC_MAC: Match by local MAC address
 * @EFX_FILTER_MATCH_LOC_PORT: Match by local TCP/UDP port
 * @EFX_FILTER_MATCH_ETHER_TYPE: Match by Ether-type
 * @EFX_FILTER_MATCH_INNER_VID: Match by inner VLAN ID
 * @EFX_FILTER_MATCH_OUTER_VID: Match by outer VLAN ID
 * @EFX_FILTER_MATCH_IP_PROTO: Match by IP transport protocol
 * @EFX_FILTER_MATCH_LOC_MAC_IG: Match by local MAC address I/G bit.
 *	Used for RX default unicast and multicast/broadcast filters.
 * @EFX_FILTER_MATCH_ENCAP_TYPE: Match by encapsulation type.
 * @EFX_FILTER_MATCH_ENCAP_TNI: Match by Tenant Network ID.
 *	Only applicable for filters with an encapsulation type set.
 * @EFX_FILTER_MATCH_OUTER_LOC_MAC: Match by outer MAC for encapsulated packets
 *	Only applicable for filters with an encapsulation type set.
 *
 * Only some combinations are supported, depending on NIC type:
 *
 * - Falcon supports RX filters matching by {TCP,UDP}/IPv4 4-tuple or
 *   local 2-tuple (only implemented for Falcon B0)
 *
 * - Siena supports RX and TX filters matching by {TCP,UDP}/IPv4 4-tuple
 *   or local 2-tuple, or local MAC with or without outer VID, and RX
 *   default filters
 *
 * - Huntington supports filter matching controlled by firmware, potentially
 *   using {TCP,UDP}/IPv{4,6} 4-tuple or local 2-tuple, local MAC or I/G bit,
 *   with or without outer and inner VID
 */
enum efx_filter_match_flags {
	EFX_FILTER_MATCH_REM_HOST =	0x0001,
	EFX_FILTER_MATCH_LOC_HOST =	0x0002,
	EFX_FILTER_MATCH_REM_MAC =	0x0004,
	EFX_FILTER_MATCH_REM_PORT =	0x0008,
	EFX_FILTER_MATCH_LOC_MAC =	0x0010,
	EFX_FILTER_MATCH_LOC_PORT =	0x0020,
	EFX_FILTER_MATCH_ETHER_TYPE =	0x0040,
	EFX_FILTER_MATCH_INNER_VID =	0x0080,
	EFX_FILTER_MATCH_OUTER_VID =	0x0100,
	EFX_FILTER_MATCH_IP_PROTO =	0x0200,
	EFX_FILTER_MATCH_LOC_MAC_IG =	0x0400,
	EFX_FILTER_MATCH_ENCAP_TYPE =	0x0800,
	EFX_FILTER_MATCH_ENCAP_TNI =	0x1000,
	EFX_FILTER_MATCH_OUTER_LOC_MAC =0x2000,
};

#define EFX_FILTER_MATCH_FLAGS_RFS (EFX_FILTER_MATCH_ETHER_TYPE | \
				    EFX_FILTER_MATCH_IP_PROTO |	  \
				    EFX_FILTER_MATCH_LOC_HOST |	  \
				    EFX_FILTER_MATCH_LOC_PORT |	  \
				    EFX_FILTER_MATCH_REM_HOST |	  \
				    EFX_FILTER_MATCH_REM_PORT)

#define EFX_FILTER_MATCH_FLAGS_RFS_DEST_ONLY (EFX_FILTER_MATCH_ETHER_TYPE | \
				    EFX_FILTER_MATCH_IP_PROTO |   \
				    EFX_FILTER_MATCH_LOC_HOST |   \
				    EFX_FILTER_MATCH_LOC_PORT)

/**
 * enum efx_filter_priority - priority of a hardware filter specification
 * @EFX_FILTER_PRI_HINT: Performance hint
 * @EFX_FILTER_PRI_AUTO: Automatic filter based on device address list
 *	or hardware requirements.  This may only be used by the filter
 *	implementation for each NIC type.
 * @EFX_FILTER_PRI_MANUAL: Manually configured filter
 * @EFX_FILTER_PRI_REQUIRED: Required for correct behaviour (user-level
 *	networking and SR-IOV)
 */
enum efx_filter_priority {
	EFX_FILTER_PRI_HINT = 1,
	EFX_FILTER_PRI_AUTO,
	EFX_FILTER_PRI_MANUAL,
	EFX_FILTER_PRI_REQUIRED,
};

/**
 * enum efx_filter_flags - flags for hardware filter specifications
 * @EFX_FILTER_FLAG_RX_RSS: Use RSS to spread across multiple queues.
 *	By default, matching packets will be delivered only to the
 *	specified queue. If this flag is set, they will be delivered
 *	to a range of queues offset from the specified queue number
 *	according to the indirection table.
 * @EFX_FILTER_FLAG_RX_SCATTER: Enable DMA scatter on the receiving
 *	queue.  Note that this cannot be enabled independently for
 *	unicast and multicast default filters; it will only be enabled
 *	if both have this flag set.
 * @EFX_FILTER_FLAG_RX_OVER_AUTO: Indicates a filter that is
 *	overriding an automatic filter (priority
 *	%EFX_FILTER_PRI_AUTO).  This may only be set by the filter
 *	implementation for each type.  A removal request will restore
 *	the automatic filter in its place.
 * @EFX_FILTER_FLAG_RX: Filter is for RX
 * @EFX_FILTER_FLAG_TX: Filter is for TX
 * @EFX_FILTER_FLAG_STACK_ID: Stack ID value for self loopback supression.
 * @EFX_FILTER_FLAG_VPORT_ID: Virtual port ID for adapter switching.
 * @EFX_FILTER_FLAG_LOOPBACK: Filter is for loopback testing.
 */
enum efx_filter_flags {
	EFX_FILTER_FLAG_RX_RSS = 0x01,
	EFX_FILTER_FLAG_RX_SCATTER = 0x02,
	EFX_FILTER_FLAG_RX_OVER_AUTO = 0x04,
	EFX_FILTER_FLAG_RX = 0x08,
	EFX_FILTER_FLAG_TX = 0x10,
	EFX_FILTER_FLAG_STACK_ID = 0x20,
	EFX_FILTER_FLAG_VPORT_ID = 0x40,
	EFX_FILTER_FLAG_LOOPBACK = 0x80,
};

/* user_id of the driver-default RSS context */
#define EFX_FILTER_RSS_CONTEXT_DEFAULT	0

/** enum efx_encap_type - types of encapsulation
 * @EFX_ENCAP_TYPE_NONE: no encapsulation
 * @EFX_ENCAP_TYPE_VXLAN: VXLAN encapsulation
 * @EFX_ENCAP_TYPE_NVGRE: NVGRE encapsulation
 * @EFX_ENCAP_TYPE_GENEVE: GENEVE encapsulation
 * @EFX_ENCAP_FLAG_IPV6: indicates IPv6 outer frame
 *
 * Contains both enumerated types and flags.
 * To get just the type, OR with @EFX_ENCAP_TYPES_MASK.
 */
enum efx_encap_type {
	EFX_ENCAP_TYPE_NONE = 0,
	EFX_ENCAP_TYPE_VXLAN = 1,
	EFX_ENCAP_TYPE_NVGRE = 2,
	EFX_ENCAP_TYPE_GENEVE = 3,

	EFX_ENCAP_TYPES_MASK = 7,
	EFX_ENCAP_FLAG_IPV6 = 8,
};

/**
 * struct efx_filter_spec - specification for a hardware filter
 * @match_flags: Match type flags, from &enum efx_filter_match_flags
 * @priority: Priority of the filter, from &enum efx_filter_priority
 * @flags: Miscellaneous flags, from &enum efx_filter_flags
 * @rss_context: RSS context to use, if %EFX_FILTER_FLAG_RX_RSS is set.  This
 *	is a user_id (with %EFX_FILTER_RSS_CONTEXT_DEFAULT meaning the
 *	driver/default RSS context), not an MCFW context_id.
 * @dmaq_id: Source/target queue index, or %EFX_FILTER_RX_DMAQ_ID_DROP for
 *	an RX drop filter
 * @stack_id: Stack id associated with RX queue, used for
 *	multicast loopback suppression
 * @vport_id: Virtual port user_id associated with RX queue, for adapter
 *	switching  This is a user_id, with 0 meaning the main driver vport, not
 *	an MCFW vport_id.
 * @outer_vid: Outer VLAN ID to match, if %EFX_FILTER_MATCH_OUTER_VID is set
 * @inner_vid: Inner VLAN ID to match, if %EFX_FILTER_MATCH_INNER_VID is set
 * @loc_mac: Local MAC address to match, if %EFX_FILTER_MATCH_LOC_MAC or
 *	%EFX_FILTER_MATCH_LOC_MAC_IG is set
 * @rem_mac: Remote MAC address to match, if %EFX_FILTER_MATCH_REM_MAC is set
 * @ether_type: Ether-type to match, if %EFX_FILTER_MATCH_ETHER_TYPE is set
 * @ip_proto: IP transport protocol to match, if %EFX_FILTER_MATCH_IP_PROTO
 *	is set
 * @loc_host: Local IP host to match, if %EFX_FILTER_MATCH_LOC_HOST is set
 * @rem_host: Remote IP host to match, if %EFX_FILTER_MATCH_REM_HOST is set
 * @loc_port: Local TCP/UDP port to match, if %EFX_FILTER_MATCH_LOC_PORT is set
 * @rem_port: Remote TCP/UDP port to match, if %EFX_FILTER_MATCH_REM_PORT is set
 * @tni: VXLAN Tenant Network ID.
 * @encap_type: Type of encapsulation, see efx_encap_type above.
 * @outer_loc_mac: Outer local MAC address to match, if
 *	%EFX_FILTER_MATCH_OUTER_LOC_MAC is set
 *
 * The efx_filter_init_rx() or efx_filter_init_tx() function *must* be
 * used to initialise the structure.  The efx_filter_set_*() functions
 * may then be used to set @rss_context, @match_flags and related
 * fields.
 *
 * The @priority field is used by software to determine whether a new
 * filter may replace an old one.  The hardware priority of a filter
 * depends on which fields are matched.
 */
struct efx_filter_spec {
	u32	match_flags:16;
	u32	priority:8;
	u32	flags:8;
	u32	dmaq_id:16;
	u32	stack_id:16;
	u32	rss_context;
	struct_group(match_key,
		u32	vport_id;
		__be16	outer_vid;
		__be16	inner_vid;
		u8	loc_mac[ETH_ALEN];
		u8	rem_mac[ETH_ALEN];
		__be16	ether_type;
		u8	ip_proto;
		__be32	loc_host[4];
		__be32	rem_host[4];
		__be16	loc_port;
		__be16	rem_port;
		u32	tni:24;
		u32     encap_type:4;
		u8	outer_loc_mac[ETH_ALEN];
	);
	/* total 82 bytes */
};

enum {
	EFX_FILTER_RX_DMAQ_ID_DROP = 0xfff
};

static inline void efx_filter_init_rx(struct efx_filter_spec *spec,
				      enum efx_filter_priority priority,
				      enum efx_filter_flags flags,
				      unsigned int rxq_id)
{
	memset(spec, 0, sizeof(*spec));
	spec->priority = priority;
	spec->flags = EFX_FILTER_FLAG_RX | flags;
	spec->rss_context = 0;
	spec->dmaq_id = rxq_id;
}

static inline void efx_filter_init_tx(struct efx_filter_spec *spec,
				      unsigned int txq_id)
{
	memset(spec, 0, sizeof(*spec));
	spec->priority = EFX_FILTER_PRI_REQUIRED;
	spec->flags = EFX_FILTER_FLAG_TX;
	spec->dmaq_id = txq_id;
}

/**
 * efx_filter_set_ipv4_local - specify IPv4 host, transport protocol and port
 * @spec: Specification to initialise
 * @proto: Transport layer protocol number
 * @host: Local host address (network byte order)
 * @port: Local port (network byte order)
 *
 * Return: a negative error code or 0 on success.
 */
static inline int
efx_filter_set_ipv4_local(struct efx_filter_spec *spec, u8 proto,
			  __be32 host, __be16 port)
{
	spec->match_flags |=
		EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_IP_PROTO |
		EFX_FILTER_MATCH_LOC_HOST | EFX_FILTER_MATCH_LOC_PORT;
	spec->ether_type = htons(ETH_P_IP);
	spec->ip_proto = proto;
	spec->loc_host[0] = host;
	spec->loc_port = port;
	return 0;
}

/**
 * efx_filter_set_ipv4_full - specify IPv4 hosts, transport protocol and ports
 * @spec: Specification to initialise
 * @proto: Transport layer protocol number
 * @lhost: Local host address (network byte order)
 * @lport: Local port (network byte order)
 * @rhost: Remote host address (network byte order)
 * @rport: Remote port (network byte order)
 *
 * Return: a negative error code or 0 on success.
 */
static inline int
efx_filter_set_ipv4_full(struct efx_filter_spec *spec, u8 proto,
			 __be32 lhost, __be16 lport,
			 __be32 rhost, __be16 rport)
{
	spec->match_flags |=
		EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_IP_PROTO |
		EFX_FILTER_MATCH_LOC_HOST | EFX_FILTER_MATCH_LOC_PORT |
		EFX_FILTER_MATCH_REM_HOST | EFX_FILTER_MATCH_REM_PORT;
	spec->ether_type = htons(ETH_P_IP);
	spec->ip_proto = proto;
	spec->loc_host[0] = lhost;
	spec->loc_port = lport;
	spec->rem_host[0] = rhost;
	spec->rem_port = rport;
	return 0;
}

/**
 * efx_filter_set_ipv6_local - specify IPv6 host, transport protocol and port
 * @spec: Specification to initialise
 * @proto: Transport layer protocol number
 * @host: Local host address (network byte order)
 * @port: Local port (network byte order)
 *
 * Return: a negative error code or 0 on success.
 */
static inline int
efx_filter_set_ipv6_local(struct efx_filter_spec *spec, u8 proto,
			  const struct in6_addr *host, __be16 port)
{
	spec->match_flags |=
		EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_IP_PROTO |
		EFX_FILTER_MATCH_LOC_HOST | EFX_FILTER_MATCH_LOC_PORT;
	spec->ether_type = htons(ETH_P_IPV6);
	spec->ip_proto = proto;
	memcpy(spec->loc_host, host->s6_addr32, sizeof(spec->loc_host));
	spec->loc_port = port;
	return 0;
}

/**
 * efx_filter_set_ipv6_full - specify IPv6 hosts, transport protocol and ports
 * @spec: Specification to initialise
 * @proto: Transport layer protocol number
 * @lhost: Local host address (network byte order)
 * @lport: Local port (network byte order)
 * @rhost: Remote host address (network byte order)
 * @rport: Remote port (network byte order)
 *
 * Return: a negative error code or 0 on success.
 */
static inline int
efx_filter_set_ipv6_full(struct efx_filter_spec *spec, u8 proto,
			 struct in6_addr lhost, __be16 lport,
			 struct in6_addr rhost, __be16 rport)
{
	spec->match_flags |=
		EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_IP_PROTO |
		EFX_FILTER_MATCH_LOC_HOST | EFX_FILTER_MATCH_LOC_PORT |
		EFX_FILTER_MATCH_REM_HOST | EFX_FILTER_MATCH_REM_PORT;
	spec->ether_type = htons(ETH_P_IPV6);
	spec->ip_proto = proto;
	memcpy(spec->loc_host, lhost.s6_addr32, sizeof(spec->loc_host));
	spec->loc_port = lport;
	memcpy(spec->rem_host, rhost.s6_addr32, sizeof(spec->rem_host));
	spec->rem_port = rport;
	return 0;
}

enum {
	EFX_FILTER_VID_UNSPEC = 0xffff,
};

/**
 * efx_filter_set_eth_local - specify local Ethernet address and/or VID
 * @spec: Specification to initialise
 * @vid: Outer VLAN ID to match, or %EFX_FILTER_VID_UNSPEC
 * @addr: Local Ethernet MAC address, or %NULL
 *
 * Return: a negative error code or 0 on success.
 */
static inline int efx_filter_set_eth_local(struct efx_filter_spec *spec,
					   u16 vid, const u8 *addr)
{
	if (vid == EFX_FILTER_VID_UNSPEC && addr == NULL)
		return -EINVAL;

	if (vid != EFX_FILTER_VID_UNSPEC) {
		spec->match_flags |= EFX_FILTER_MATCH_OUTER_VID;
		spec->outer_vid = htons(vid);
	}
	if (addr != NULL) {
		spec->match_flags |= EFX_FILTER_MATCH_LOC_MAC;
		ether_addr_copy(spec->loc_mac, addr);
	}
	return 0;
}

/**
 * efx_filter_set_uc_def - specify matching otherwise-unmatched unicast
 * @spec: Specification to initialise
 *
 * Return: a negative error code or 0 on success.
 */
static inline int efx_filter_set_uc_def(struct efx_filter_spec *spec)
{
	spec->match_flags |= EFX_FILTER_MATCH_LOC_MAC_IG;
	return 0;
}

/**
 * efx_filter_set_mc_def - specify matching otherwise-unmatched multicast
 * @spec: Specification to initialise
 *
 * Return: a negative error code or 0 on success.
 */
static inline int efx_filter_set_mc_def(struct efx_filter_spec *spec)
{
	spec->match_flags |= EFX_FILTER_MATCH_LOC_MAC_IG;
	spec->loc_mac[0] = 1;
	return 0;
}

/**
 * efx_filter_set_stack_id - set stack id relating to filter
 * @spec: Specification to initialise
 * @stack_id: ID of the stack used to suppress stack's own traffic on loopback.
 */
static inline void efx_filter_set_stack_id(struct efx_filter_spec *spec,
				      unsigned int stack_id)
{
	spec->flags |= EFX_FILTER_FLAG_STACK_ID;
	spec->stack_id = stack_id;
}

/**
 * efx_filter_set_vport_id - override virtual port user_id relating to filter
 * @spec: Specification to initialise
 * @vport_id: user_id of the virtual port
 */
static inline void efx_filter_set_vport_id(struct efx_filter_spec *spec,
					   unsigned int vport_id)
{
	spec->flags |= EFX_FILTER_FLAG_VPORT_ID;
	spec->vport_id = vport_id;
}

/**
 * efx_filter_set_ethertype - add or override ethertype relating to filter
 * @spec: Specification to set
 * @ether_type: Ethernet protocol ID to match
 */
static inline void efx_filter_set_ethertype(struct efx_filter_spec *spec,
					    u16 ether_type)
{
	spec->flags |= EFX_FILTER_MATCH_ETHER_TYPE;
	spec->ether_type = htons(ether_type);
}

/**
 * efx_filter_set_ipproto - add or override ip protocol relating to filter
 * @spec: Specification to set
 * @ip_proto: IP protocol ID to match
 */
static inline void efx_filter_set_ipproto(struct efx_filter_spec *spec,
					  u8 ip_proto)
{
	spec->flags |= EFX_FILTER_MATCH_IP_PROTO;
	spec->ip_proto = ip_proto;
}

static inline void efx_filter_set_encap_type(struct efx_filter_spec *spec,
					     enum efx_encap_type encap_type)
{
	spec->match_flags |= EFX_FILTER_MATCH_ENCAP_TYPE;
	spec->encap_type = encap_type;
}

static inline enum efx_encap_type efx_filter_get_encap_type(
		const struct efx_filter_spec *spec)
{
	if (spec->match_flags & EFX_FILTER_MATCH_ENCAP_TYPE)
		return spec->encap_type;
	return EFX_ENCAP_TYPE_NONE;
}

static inline void efx_filter_set_encap_tni(struct efx_filter_spec *spec,
		u32 tni)
{
	spec->match_flags |= EFX_FILTER_MATCH_ENCAP_TNI;
	spec->tni = tni;
}

/**
 * efx_filter_set_encap_outer_loc_mac - specify outer Ethernet address for an
 *   encapsulated filter
 * @spec: Specification to initialise
 * @addr: Local Ethernet MAC address, or %NULL
 */
static inline
void efx_filter_set_encap_outer_loc_mac(struct efx_filter_spec *spec,
					const u8 *addr)
{
	spec->match_flags |= EFX_FILTER_MATCH_OUTER_LOC_MAC;
	ether_addr_copy(spec->outer_loc_mac, addr);
}

#endif /* EFX_FILTER_H */
