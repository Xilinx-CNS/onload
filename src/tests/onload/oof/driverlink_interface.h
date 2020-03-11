#ifndef __OOF_TEST_DRIVERLINK_INTERFACE_H__
#define __OOF_TEST_DRIVERLINK_INTERFACE_H__

#include <linux/if_ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#define EFX_DRIVERLINK_API_VERSION 23

#define EFX_DLFILTER_HANDLE_BAD -1

struct efx_filter_spec {
        u32     match_flags:16;
        u32     priority:8;
        u32     flags:8;
        u32     dmaq_id:16;
        u32     stack_id:16;
        u32     vport_id;
        u32     rss_context;
        __be16  outer_vid; /* allow jhash2() of match values */
        __be16  inner_vid;
        u8      loc_mac[ETH_ALEN];
        u8      rem_mac[ETH_ALEN];
        __be16  ether_type;
        u8      ip_proto;
        __be32  loc_host[4];
        __be32  rem_host[4];
        __be16  loc_port;
        __be16  rem_port;
        u32     tni:24;
        u32     encap_type:4;
        u8      outer_loc_mac[ETH_ALEN];
        /* total 82 bytes */
};

enum {
        EFX_FILTER_RSS_CONTEXT_DEFAULT = 0xffffffff,
        EFX_FILTER_RX_DMAQ_ID_DROP = 0xfff
};


enum {
        EFX_FILTER_VID_UNSPEC = 0xffff,
};

enum efx_filter_match_flags {
        EFX_FILTER_MATCH_REM_HOST =     0x0001,
        EFX_FILTER_MATCH_LOC_HOST =     0x0002,
        EFX_FILTER_MATCH_REM_MAC =      0x0004,
        EFX_FILTER_MATCH_REM_PORT =     0x0008,
        EFX_FILTER_MATCH_LOC_MAC =      0x0010,
        EFX_FILTER_MATCH_LOC_PORT =     0x0020,
        EFX_FILTER_MATCH_ETHER_TYPE =   0x0040,
        EFX_FILTER_MATCH_INNER_VID =    0x0080,
        EFX_FILTER_MATCH_OUTER_VID =    0x0100,
        EFX_FILTER_MATCH_IP_PROTO =     0x0200,
        EFX_FILTER_MATCH_LOC_MAC_IG =   0x0400,
        EFX_FILTER_MATCH_ENCAP_TYPE =   0x0800,
        EFX_FILTER_MATCH_ENCAP_TNI =    0x1000,
        EFX_FILTER_MATCH_OUTER_LOC_MAC =0x2000,
};

enum efx_filter_priority {
        EFX_FILTER_PRI_SARFS = 0,
        EFX_FILTER_PRI_HINT,
        EFX_FILTER_PRI_AUTO,
        EFX_FILTER_PRI_MANUAL,
        EFX_FILTER_PRI_REQUIRED,
};


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


static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
        u16 *a = (u16 *)dst;
        const u16 *b = (const u16 *)src;

        a[0] = b[0];
        a[1] = b[1];
        a[2] = b[2];
}


static inline void efx_filter_init_rx(struct efx_filter_spec *spec,
                                      enum efx_filter_priority priority,
                                      enum efx_filter_flags flags,
                                      unsigned int rxq_id)
{
        memset(spec, 0, sizeof(*spec));
        spec->priority = priority;
        spec->flags = EFX_FILTER_FLAG_RX | flags;
        spec->rss_context = EFX_FILTER_RSS_CONTEXT_DEFAULT;
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
 */
static inline int
efx_filter_set_ipv6_local(struct efx_filter_spec *spec, u8 proto,
			  struct in6_addr host, __be16 port)
{
	spec->match_flags |=
		EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_IP_PROTO |
		EFX_FILTER_MATCH_LOC_HOST | EFX_FILTER_MATCH_LOC_PORT;
	spec->ether_type = htons(ETH_P_IPV6);
	spec->ip_proto = proto;
	memcpy(spec->loc_host, host.s6_addr32, sizeof(spec->loc_host));
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

/**
 * efx_filter_set_eth_local - specify local Ethernet address and/or VID
 * @spec: Specification to initialise
 * @vid: Outer VLAN ID to match, or %EFX_FILTER_VID_UNSPEC
 * @addr: Local Ethernet MAC address, or %NULL
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


#endif /* __OOF_TEST_DRIVERLINK_INTERFACE_H__ */

