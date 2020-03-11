/* SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This header describes the interface between the open source parts
 * of Onload and the binary-only control plane server.
 *
 * We use an md5sum over certain headers to ensure that userland and
 * kernel drivers are built against a compatible interface. The
 * control plane server and its clients will verify this hash against
 * the kernel module and refuse to start if there is a version
 * mismatch.
 *
 * Users should therefore not modify these headers because the
 * supplied control plane server will refuse to operate with the
 * resulting module.
 */

/* Public API for UL Control plane.  This header is:
 * (a) sourceful for the customers;
 * (b) compilable in both UL and kernel.
 */
#ifndef __TOOLS_CPLANE_PUBLIC_H__
#define __TOOLS_CPLANE_PUBLIC_H__

#include <ci/compat.h>
#include <ci/tools/sysdep.h>
#include <ci/tools/byteorder.h>
#include <ci/net/ipvx_sh.h>
#include <linux/neighbour.h>
#include "mib_dllist_tmpl_instantiate.h"

/* At user level, net/if.h and linux/if.h cannot both be #included.  However,
 * there are files that #include this one requiring each of those.  As a
 * workaround, do the #include only if neither has yet been included. */
#if ! defined(IFNAMSIZ)
# ifndef __KERNEL__
#  include <sys/socket.h>
#  include <net/if.h> /* for IFNAMSIZ */
# else
#  include <linux/if.h> /* for IFNAMSIZ */
# endif
#endif



/*
 *** Primary data types ***
 */

typedef ci_int16 cicp_rowid_t;
#define CICP_ROWID_BAD          ((cicp_rowid_t)(-1))
#define CICP_ROWID_IS_VALID(id) ((cicp_rowid_t)(id) >= 0)
#define CICP_ROWID_MAX 0x7fff

/* Row id for MAC and FWD cache tables. */
typedef ci_int32 cicp_mac_rowid_t;
#define CICP_MAC_ROWID_BAD          ((cicp_mac_rowid_t)(-1))
#define CICP_MAC_ROWID_UNUSED       ((cicp_mac_rowid_t)(-3))
#define CICP_MAC_ROWID_ERROR        ((cicp_mac_rowid_t)(-8))
#define CICP_MAC_ROWID_IS_VALID(id) ((cicp_mac_rowid_t)(id) >= 0)
#define CICP_MAC_ROWID_MAX 0x7fffffff

typedef ci_uint8 ci_hwport_id_t;
#define CI_HWPORT_ID_BAD          ((ci_hwport_id_t) -1)
#define CI_HWPORT_ID_BAD_LICENSED ((ci_hwport_id_t) -2)
typedef ci_uint16 ci_ifid_t;
#define CI_IFID_BAD  0
#define CI_IFID_LOOP 1

typedef ci_uint8 cicp_prefixlen_t;
#define CI_IP_PREFIXLEN_BAD 0xff

typedef ci_uint8 ci_mac_addr_t[6];
typedef ci_uint16 ci_mtu_t;


/*! flags for types of encapsulation supported by the NIC */
enum {
  CICP_LLAP_TYPE_NONE                = 0x00000000,
  CICP_LLAP_TYPE_VLAN                = 0x00000001,
  CICP_LLAP_TYPE_BOND                = 0x00000002,
  CICP_LLAP_TYPE_SLAVE               = 0x00000004,
  CICP_LLAP_TYPE_XMIT_HASH_LAYER2    = 0x00000008,
  CICP_LLAP_TYPE_XMIT_HASH_LAYER34   = 0x00000010,
  CICP_LLAP_TYPE_XMIT_HASH_LAYER23   = 0x00000020,
  CICP_LLAP_TYPE_LOOP                = 0x00000040,
  CICP_LLAP_TYPE_MACVLAN             = 0x00000080,
  CICP_LLAP_TYPE_VETH                = 0x00000100,
  CICP_LLAP_TYPE_ROUTE_ACROSS_NS     = 0x00000200,
  CICP_LLAP_TYPE_IPVLAN              = 0x00000400,
};
#define CICP_LLAP_TYPE_USES_HASH \
  (CICP_LLAP_TYPE_XMIT_HASH_LAYER34 | \
   CICP_LLAP_TYPE_XMIT_HASH_LAYER2 | \
   CICP_LLAP_TYPE_XMIT_HASH_LAYER23 )
#define CICP_LLAP_TYPE_XMIT_HASH_LAYER4 CICP_LLAP_TYPE_XMIT_HASH_LAYER34

/* enum is always int, so no typedef for enum */
typedef ci_uint32 cicp_llap_type_t;


/*
 *** Local Link Access Point table ***
 */

typedef struct {
  cicp_llap_type_t type;
  ci_uint16 vlan_id;
  ci_ifid_t link_ifindex;     /*< ifindex for VLAN master, veth-peer, etc. */
} cicp_encap_t;


#define CICP_ENCAP_NAME_FMT "%s%s%s%s%s%s%s%s%s%s%s"
#define cicp_encap_name(encap)                                  \
    (encap & CICP_LLAP_TYPE_VLAN ? "VLAN " : ""),               \
    (encap & CICP_LLAP_TYPE_MACVLAN ? "MACVLAN " : ""),         \
    (encap & CICP_LLAP_TYPE_IPVLAN ? "IPVLAN " : ""),           \
    (encap & CICP_LLAP_TYPE_VETH ? "VETH " : ""),               \
    (encap & CICP_LLAP_TYPE_LOOP ? "LOOP " : ""),               \
    (encap & CICP_LLAP_TYPE_BOND ? "BOND " : ""),               \
    (encap & CICP_LLAP_TYPE_USES_HASH ? "HASH " : ""),          \
    (encap & CICP_LLAP_TYPE_XMIT_HASH_LAYER34 ? "L34 " : ""),   \
    (encap & CICP_LLAP_TYPE_XMIT_HASH_LAYER2 ? "L2 " : ""),     \
    (encap & CICP_LLAP_TYPE_XMIT_HASH_LAYER23 ? "L23 " : ""),   \
    (encap & CICP_LLAP_TYPE_ROUTE_ACROSS_NS ? "XNS " : "")      \

typedef ci_uint16 cicp_hwport_mask_t;

#define CICP_ALL_HWPORTS ((cicp_hwport_mask_t) -1)

static inline ci_hwport_id_t cp_hwport_mask_first(cicp_hwport_mask_t mask)
{
  /* if mask == 0 then it results in CI_HWPORT_ID_BAD */
  return ffs(mask) - 1;
}
static inline cicp_hwport_mask_t cp_hwport_make_mask(ci_hwport_id_t hwport)
{
  /* Address potential shif overflow when:
   *  * hwport == dim->hwports_max == bits(ci_hwport_id_t)
   *  * CI_HWPORT_ID_BAD is passed*/
  if( hwport >= sizeof(cicp_hwport_mask_t) * 8 )
    return 0;
  return ((cicp_hwport_mask_t) 1) << hwport;
}

#define CP_MAX_INSTANCES 4096u
#define CP_FWD_TABLE_ID_INVALID CP_MAX_INSTANCES
CI_BUILD_ASSERT(CP_FWD_TABLE_ID_INVALID >= CP_MAX_INSTANCES);
typedef uint32_t cp_fwd_table_id;

typedef ci_uint32 cp_hwport_flags_t;
typedef cp_hwport_flags_t cp_llap_flags_t;

typedef struct cicp_llap_row_s {
  ci_ifid_t ifindex;

  ci_mtu_t mtu;               /*< IP Maximum Transmit Unit for this i/f */

  /* N.B. Some flags may be set either on an LLAP or on an hwport. */
  cp_llap_flags_t flags;      /*< various flags */
/* Interface is up. */
#define CP_LLAP_UP                     0x00000001u
/* Interface is not acceleratable. */
#define CP_LLAP_ALIEN                  0x00000002u
/* Interface was verified to have some (may be 0)
 * license features below */
#define CP_LLAP_LICENSED_VERIFIED      0x00000004u

/* "Ultra-low latency". */
#define CP_LLAP_LICENSED_ONLOAD_ULL    0x00000040u

/* lower iface is in some other (main) namespace */
#define CP_LLAP_IMPORTED               0x00000100u
/* Hwport row is non-empty. */
#define CP_HWPORT_ROW_IN_USE           0x00000200u

  char name[IFNAMSIZ+1];
  ci_mac_addr_t mac;          /*< MAC address of access point */
  cicp_encap_t encap;         /*< encapsulation used on this i/f */

  /* the following fields are only valid in SFC interfaces */

  /* Hardware ports under this interface.
   *
   * tx_hwports are used for transmit.  Everything except LACP team/bond
   * (+vlan/macvlan over LACP) has one bit set tx_hwports mask only.
   *
   * rx_hwports are used for receive.  For all team/bond types, all ports
   * in aggregation must be included into rx_hwports mask, to ensure that
   * appropriate TCP filters are inserted for any TCP connection, and OS
   * will not receive any TCP packets with Onload destination.  Otherwise
   * OS may reply with RST. */
  cicp_hwport_mask_t tx_hwports;
  cicp_hwport_mask_t rx_hwports;

  /* If we make a routing request specifying this interface in RTA_IIF, use the
   * fwd table specified in this field to store the result. */
  cp_fwd_table_id iif_fwd_table_id;
} cicp_llap_row_t;


struct cp_hwport_row {
/* we reuse CP_LLAP flags here */
  cp_hwport_flags_t flags;
};


static inline int
cicp_llap_row_is_free(cicp_llap_row_t *row)
{
  return row->ifindex == CI_IFID_BAD;
}


static inline int
cicp_hwport_row_is_free(struct cp_hwport_row* row)
{
  return (row->flags & CP_HWPORT_ROW_IN_USE) == 0;
}

/*
 *** IP address on network InterFace table ***
 */

typedef struct
{
  /* keys: */
  ci_ip_addr_t     net_ip;    /*< network own address */
  cicp_prefixlen_t net_ipset; /*< network IP address set specification */
  ci_ifid_t        ifindex;   /*< O/S index of link layer interface */

  /* data: */
  ci_ip_addr_t     bcast_ip;  /*< broadcast IP address, 0 if not set */
  ci_uint8         scope;     /*< RT_SCOPE_UNIVERSE=0, more is worse */
  /* XXX store flag: primary or secondary (see IFA_F_SECONDARY) */
} cicp_ipif_row_t;

typedef struct
{
  /* keys: */
  ci_ip6_addr_t    net_ip6;
  cicp_prefixlen_t net_ipset;
  ci_ifid_t        ifindex;

  /* data: */
  ci_uint8         scope;
} cicp_ip6if_row_t;

static inline int
cicp_ipif_row_is_free(cicp_ipif_row_t *row)
{
  return row->net_ipset == CI_IP_PREFIXLEN_BAD;
}

static inline int
cicp_ip6if_row_is_free(cicp_ip6if_row_t *row)
{
  return row->net_ipset == CI_IP_PREFIXLEN_BAD;
}

/*
 *** Route Cache table ***
 */
typedef ci_uint8 cicp_ip_tos_t;

/* Keys for forward cache table. */
struct cp_fwd_key {
  ci_addr_sh_t  src;
  ci_addr_sh_t  dst;
  ci_ifid_t     ifindex;
  cicp_ip_tos_t tos;
  /* This is the ifindex of the origin interface in the case where we are
   * simulating the forwarding of packets. */
  ci_ifid_t     iif_ifindex;

  ci_uint8      flag;
#define CP_FWD_KEY_REQ_REFRESH  0x80
#define CP_FWD_KEY_REQ_WAIT     0x40
#define CP_FWD_KEY_TRANSPARENT  0x20
#define CP_FWD_KEY_SOURCELESS   0x08
  /* Smaller values are used (after shifting) for flags in netlink sequence
   * numbers, so don't use them here. */
};
#ifdef CI_ADDR_SH_IS_TYPEDEF
#define CP_FWD_KEY_FMT \
  "from "IPX_FMT" to "IPX_FMT" from %d via %d tos %d"
#define CP_FWD_KEY_ARGS(key) \
  IPX_ARG(AF_IP_L3((key)->src)), IPX_ARG(AF_IP_L3((key)->dst)), \
  (key)->iif_ifindex, (key)->ifindex, (key)->tos
#else
/* We do not have good macros to print IPv6 ci_addr_sh_t in this case, so
 * let's print IPv4 only. */
#define CP_FWD_KEY_FMT \
  "from "CI_IP_PRINTF_FORMAT" to "CI_IP_PRINTF_FORMAT" from %d via %d tos %d"
#define CP_FWD_KEY_ARGS(key) \
  CI_IP_PRINTF_ARGS(&(key)->src.ip4), CI_IP_PRINTF_ARGS(&(key)->dst.ip4), \
  (key)->iif_ifindex, (key)->ifindex, (key)->tos
#endif

ci_inline int
fwd_key2af(const struct cp_fwd_key* key)
{
  /* Fixme: When we know any such use-cases, we may want to check address
   * family of both source and desrination */
  return CI_IS_ADDR_SH_IP6(key->dst) ? AF_INET6 : AF_INET;
}

struct cp_fwd_key_ext {
  /* This is part of "key", but only ever stored in fwd_row */
  cicp_prefixlen_t src_prefix;
  cicp_prefixlen_t dst_prefix;
};
#ifdef CI_ADDR_SH_IS_TYPEDEF
#define CP_ADDR_PREFIX_FMT IPX_FMT"/%d"
#define CP_ADDR_PREFIX_ARG(addr, prefix) \
  AF_IP_L3(addr), (prefix) - (CI_IS_ADDR_IP6(addr) ? 0 : 96)
#else
#define CP_ADDR_PREFIX_FMT CI_IP_PRINTF_FORMAT"/%d"
#define CP_ADDR_PREFIX_ARG(addr, prefix) \
  CI_IP_PRINTF_ARGS(&addr), prefix - 96
#endif

/* Basic routing data, obtained from the routing table */
struct cp_fwd_data_base {
  ci_addr_sh_t      src;
  ci_addr_sh_t      next_hop;
  ci_mtu_t          mtu;
  ci_ifid_t         ifindex;
  /* Stores RTAX_HOPLIMIT attribute value. It would contain IPv4 TTL or
   * IPv6 Hop Limit after parsing NETLINK route message. */
  ci_uint8          hop_limit;
};

/* Multipath weights.
 * User selects a random weight.  This weight is serviced by this path
 * iff end - val <= weight < end.
 * Random weight is selected from
 * [0 - <end value from CP_FWD_MULTIPATH_WEIGHT_LAST path>).
 */
struct cp_fwd_multipath_weight {
  ci_uint32 end;  /* End of weight range serviced by this entry */
  ci_uint16 val;  /* Weight of this path: range 1:0x100 */
  ci_uint16 flag;
  /* This entry has the maximum end value among the paths for this route */
#define CP_FWD_MULTIPATH_FLAG_LAST 1
};
#define CP_FWD_MULTIPATH_WEIGHT_FMT "multipath %d/%d%s"
#define CP_FWD_MULTIPATH_WEIGHT_ARG(w_) \
  (w_)->val, (w_)->end, \
  ((w_)->flag & CP_FWD_MULTIPATH_FLAG_LAST) ? " LAST" : ""

#define CP_FWD_MULTIPATH_WEIGHT_NONE ((ci_uint32)-1)
static inline int
cp_fwd_weight_match(ci_uint32 val, struct cp_fwd_multipath_weight* w)
{
  if( val == CP_FWD_MULTIPATH_WEIGHT_NONE )
    return w->end == 0 || (w->flag & CP_FWD_MULTIPATH_FLAG_LAST);
  else
    return val < w->end && val >= w->end - w->val;
}

/* Routing info in the forward cache table. */
struct cp_fwd_data {
  struct cp_fwd_data_base base;

  /* Unlike flags in cp_fwd_row, this field is versioned. */
  ci_uint8          flags;
#define CICP_FWD_DATA_FLAG_ARP_VALID  0x1
#define CICP_FWD_DATA_FLAG_ARP_FAILED 0x2
/* Currently we do not have non-ARP flags, but we write the code in a way
 * so they can be easily added, so let's define this mask: */
#define CICP_FWD_DATA_FLAG_ARP_MASK   0x3
#define CICP_FWD_DATA_FLAG_FMT "arp %s"
#define CICP_FWD_DATA_FLAG_ARG(flags) \
  ((flags) & CICP_FWD_DATA_FLAG_ARP_VALID) ? "valid" : \
  ((flags) & CICP_FWD_DATA_FLAG_ARP_FAILED) ? "failed" : "invalid"

  ci_mac_addr_t     src_mac;
  cicp_hwport_mask_t hwports;
  ci_mac_addr_t     dst_mac;
  cicp_encap_t      encap;

  struct cp_fwd_multipath_weight weight;
};

static inline ci_ip_addr_t cp_prefixlen2bitmask(cicp_prefixlen_t len)
{
  return CI_BSWAP_BE32(~(len == 0 ? 0xffffffff : (1 << (32 - len)) - 1));
}

static inline int /*bool*/
cp_ip_prefix_match(ci_ip_addr_t ip1, ci_ip_addr_t ip2, cicp_prefixlen_t len)
{
  return ((ip1 ^ ip2) & cp_prefixlen2bitmask(len)) == 0;
}

static inline ci_addr_sh_t
cp_ip6_pfx2mask(cicp_prefixlen_t pfx)
{
  ci_addr_sh_t m = {};
  int i = 0;
  ci_assert_le(pfx, 128);
  while ( pfx > 64 ) {
    m.u64[i++] = 0xffffffffffffffffull;
    pfx -= 64;
  }
  if( pfx != 0 )
    m.u64[i] = CI_BSWAP_BE64(0xffffffffffffffffull << (64 - pfx));
  return m;
}

static inline void
cp_addr_apply_pfx(ci_addr_sh_t* a, cicp_prefixlen_t pfx)
{
  ci_addr_sh_t m = cp_ip6_pfx2mask(pfx);
  a->u64[0] &= m.u64[0];
  a->u64[1] &= m.u64[1];
}

static inline int
cp_ip6_pfx_match(const ci_addr_sh_t* a, const ci_addr_sh_t* b,
                 cicp_prefixlen_t pfx)
{
  ci_addr_sh_t m = cp_ip6_pfx2mask(pfx);
  return ci_ipx_addr_sh_masked_eq(a, b, &m);
}

typedef uint32_t cp_version_t;

/* fwd table has the following properties:
 *
 * 1. Each fwd entry has prefix sizes associated allowing the entry to match
 *    requests ignoring the respective least significant bits of both
 *    src and dst ip addresses
 * 2. There is only one entry that can handle any given ip address.
 *  * if there is an entry for 1.1.1.0/24 then there is no entry 1.1.0.0/16
 *  * if with existing route 1.1.0.0/16, a new route 1.1.1.0/24 is added
 *    then the fwd table entry 1.1.0.0/16 gets deleted and entries
 *    1.1.1.0/24 1.1.2/24 etc are added as needed
 * 3. best effort tendency to adding the widest fwd table entries
 *    (entries are created as widest but after route change widening occurs
 *     when needed)
 *
 * Following (2) for a given request with full fwd table scan of given table
 * would produce at most single result.
 * In practice, full scan is avoided by using hash probing.
 * It may take several probes though to find the matching row. Each probe uses
 * key modified to address increase of prefix. e.g. for address 1.1.1.1
 * the search could be 1.1.1.1, then 1.1.1.0, and 1.1.0.0.
 * (It is possible for probe of 1.1.1.1 to return 1.1.0.0 if the probe sequence
 *  went over it by chance).
 *
 * Note: examples above used one dimension of ip address prefix range for
 * simplicity.
 */
struct cp_fwd_row {
  /* the key and data fields are 0 padded */
  struct cp_fwd_key     key;
  struct cp_fwd_key_ext key_ext;
  struct cp_fwd_data    data[2]; /* two snapshots of data */

  /* Version is the "data" version. Even version means that snapshot of data
   * at index 0 is to be read by clients, odd that the data under index 1.
   *
   * When data changes, both copies are updated, one-after another.
   * The version may be updated without any data change, for example for
   * CICP_FWD_FLAG_STALE flag.
   */
  cp_version_t version;
  uint32_t use; /* in how many probe sequences record is used */
  uint8_t flags;

/* flags used by server */
/* fwd row is at least half ttl old and frc_used needs refreshing */
#define CICP_FWD_FLAG_STALE           0x1
/* changes have been started */
#define CICP_FWD_FLAG_CHANGES_STARTED 0x2
/* row contains modification of MTU */
#define CICP_FWD_FLAG_MTU             0x4
/* MTU is a result of Path MTU discovery and will expire */
#define CICP_FWD_FLAG_MTU_EXPIRES     0x8
/* This route has a gateway */
#define CICP_FWD_FLAG_HAS_GATEWAY     0x10
/* Multicast - does not need ARP */
#define CICP_FWD_FLAG_FIXED_MAC       0x20
/* This route is a result of NLMSG_ERROR message */
#define CICP_FWD_FLAG_ERROR           0x100

/* flags used by client: */
/* row is used and the key is valid */
#define CICP_FWD_FLAG_OCCUPIED        0x80
/* data field has been filled once */
#define CICP_FWD_FLAG_DATA_VALID      0x40
};

static inline int/*bool*/
cp_fwd_key_match(const struct cp_fwd_row* fwd,
                 const struct cp_fwd_key* key)
{
  int addr_match;
  ci_addr_sh_t src_mask = cp_ip6_pfx2mask(fwd->key_ext.src_prefix);
  ci_addr_sh_t dst_mask = cp_ip6_pfx2mask(fwd->key_ext.dst_prefix);
  addr_match =
      (ci_ipx_addr_sh_masked_eq(&fwd->key.src, &key->src, &src_mask) &&
       ci_ipx_addr_sh_masked_eq(&fwd->key.dst, &key->dst, &dst_mask));
  return (fwd->flags & CICP_FWD_FLAG_OCCUPIED) != 0 && addr_match &&
         fwd->key.ifindex == key->ifindex && fwd->key.tos == key->tos &&
         fwd->key.iif_ifindex == key->iif_ifindex &&
         ((fwd->key.flag ^ key->flag) & CP_FWD_KEY_TRANSPARENT) == 0;
}


/*
 *** Read-only cplane memory ***
 */

/* Read-only cplane memory is structured as following:
 * struct cp_tables_dim dim;
 * struct cp_hwport_row hwport[hwport_max];
 * cicp_llap_row_t llap[llap_max];
 * cicp_bond_row_t bond[bond_max];
 * cicp_ipif_row_t ipif[ipif_max];
 * struct cp_fwd_row fwd[fwd_max+1];
 */

struct cp_tables_dim {
  /* N.B. dim members specifying table sizes must be ci_int32, as
   * process_mib_layout() constructs pointers to those elements and makes that
   * assumption about the type. */

  /* Number of hwport rows */
  ci_int32 hwport_max;

  /* Number of llap rows */
  ci_int32 llap_max;

  /* Number of ipif rows */
  ci_int32 ipif_max;
  ci_int32 ip6if_max;

  /* Number of k8s dnat backend arrays to allocate of services to use */
  ci_int32 svc_arrays_max;
  /* Number of k8s service endpoints (front and back end) */
  ci_int32 svc_ep_max;

  /* Number of fwd cache rows, must be 2^n */
  ci_uint8 fwd_ln2;
  ci_uint32 fwd_mask; /* 2^fwd_ln2 - 1 */

  /* RT signal used to notify about new oof instances */
  ci_int32 oof_req_sig;
  /* signal used to notify about update of main cp server */
  ci_int32 llap_update_sig;
  /* signal to request sync with OS */
  ci_int32 os_sync_sig;

  /* PID of the server process */
  ci_uint32 server_pid;

#ifdef CP_SYSUNIT
  ci_uint32 sub_server_pid;
#endif
};

enum {
  CP_FWD_PREFIX_SRC,
  CP_FWD_PREFIX_DST,
  CP_FWD_PREFIX_NUM
};

/*
 *** Read-write cplane memory ***
 */

/* This structure is writable for all Onloaded processes.
 * It allows to say:
 * - "I'm using this route, don't move it out of the cache and resolve ARP"
 */
struct cp_fwd_rw_row {
  /* Last time this row was used. */
  ci_uint64 frc_used CI_ALIGN(8);

  /* Use ci_atomic32_* operations to modify flags: */
  ci_uint32 flags;
/* ARP entry is almost-stale and should be confirmed when possible */
#define CICP_FWD_RW_FLAG_ARP_NEED_REFRESH 0x1
};

/* Array for IPv6 prefix mask. IPv6 mask requires 129 bits.*/
typedef ci_uint64 ci_ip6_pfx_t[3];

typedef union ci_ipx_pfx {
  ci_ip6_pfx_t ip6;
} ci_ipx_pfx_t;

/* Structure to hold the fwd table and related fields */
struct cp_fwd_table {
  /* bitmask for indexes into rows, rw_rows */
  cicp_mac_rowid_t mask; /* 2^fwd_ln2 - 1 */
  /* Read-only fwd data, array size fwd_max */
  struct cp_fwd_row* rows;
  /* bitmap (set) of prefix values in table rows, see CP_FWD_PREFIX_*. */
  ci_ipx_pfx_t *prefix;
  /* Read-write fwd data, array size fwd_max */
  struct cp_fwd_rw_row* rw_rows;
};


/* TCP endpoint comprising IP address and port. */
struct cp_svc_endpoint {
  ci_addr_sh_t addr;
  ci_uint16 port;
};


/* DL list element containing an frontend or backend endpoint in a k8s service.
 * Frontend elements point to a linked list of all backend elements in the
 * service. */
struct cp_svc_ep_dllist {

  /* The endpoint value. */
  struct cp_svc_endpoint ep;

  /* Use count of element in hash table */
  ci_uint32 use;

  enum {CP_SVC_EMPTY = 0, CP_SVC_SERVICE, CP_SVC_BACKEND} row_type;

  /* The union member depends on whether this element is a service front or
   * back end.  For frontends it contains the head of the backend list, for
   * backends it contains the link including that backend in the list. */
  union {
    struct {
      /* Head of backend list */
      ci_mib_dllist_t backends;
      /* Index of backend arrays in mib svc_arrays field */
      cicp_rowid_t head_array_id;
      cicp_rowid_t tail_array_id;
      /* Number of backends in linked list and array */
      size_t n_backends;
    } service;

    struct {
      /* Link connecting this backend to rest of list */
      ci_mib_dllist_link link;
      /* Index in hash table of frontend for service this backend belongs to */
      cicp_mac_rowid_t svc_id;
      /* Index of this backend in the service's backend array */
      cicp_rowid_t element_id;
    } backend;
  } u;
};

#define CP_SVC_BACKEND_FROM_LINK(link_ptr) \
  CI_CONTAINER(struct cp_svc_ep_dllist, u.backend.link, link_ptr)


/* Number of backends per service array. */
#define CP_SVC_BACKENDS_PER_ARRAY 128

/* An array of k8s service backend endpoints to be used for quick indexing.
 * Arrays can be chained together using next, service must always point to
 * head array.  All arrays other than the tail must be full. */
struct cp_svc_ep_array {
  /* Doubly link list of array_ids, both direction end in CICP_ROWID_BAD */
  cicp_rowid_t next;
  cicp_rowid_t prev;
  struct cp_svc_endpoint eps[CP_SVC_BACKENDS_PER_ARRAY];
};

#define CP_STRING_LEN 256

typedef struct cp_string { char value[CP_STRING_LEN]; } cp_string_t;


/* The main cplane object, used by both Cplane Process and Cplane users */

struct cp_mibs {
  /* Read-only data: */
  struct cp_tables_dim* dim;

  /* Version of the hwport, ipif, llap tables */
  cp_version_t* version;

  /* Version of the llap tables. Not used in selecting which table to index,
   * but rather a finer heuristic to detect stale llap rows. */
  cp_version_t* llap_version;

  /* Version of "dump from OS" point of view: odd means "dump in progress".
   * It is increased when dump is started and when it finishes
   * successfully. */
  cp_version_t* dump_version;

  /* Number of times when the cplane server have nothing to do (blocked in
   * epoll) multiplied by 2.  As with dump_version, an odd value means that
   * cplane is updating something right now.
   */
  cp_version_t* idle_version;

  /* Version exposed to oof subsystem. */
  cp_version_t* oof_version;

  struct cp_hwport_row* hwport;
  cicp_llap_row_t* llap;
  cicp_ipif_row_t* ipif;
  cicp_ip6if_row_t* ip6if;

#ifndef __KERNEL__
  /* Struct containing fwd table rows and prefix bitmap.
   * There is a single copy of each fwd_table prefix bitmap
   * shared between both MIB frames.  It is not protected by any lock, as each
   * bit is independent of each other bit, and the only consistency requirement
   * is that the presence of a prefix-length in the fwd table implies that the
   * corresponding bit in the appropriate prefix entry is set.  As such,
   * normal non-atomic writes are sufficient for updating the prefix.  Barriers
   * are not even required between changes to the prefix and the table itself,
   * as there is no harm in the race between look-ups by clients and changes to
   * the table.
   * N.B. This field is valid in client handles only, and only exists at UL.
   * The control plane server and the driver must refer to tables explictly by
   * ID, even for the local table. */
  struct cp_fwd_table fwd_table;
#endif

  /* Hash table of all k8s service endpoints.  Each item may be a service
   * frontend or backend endpoint.  Backends form a doubly linked list of all
   * backends in that service, frontends point to the head of that list. */
  struct cp_svc_ep_dllist* svc_ep_table;

  /* Table of k8s service backends organised by service.
   * Logically an array of arrays, each of length CP_SVC_BACKENDS_PER_ARRAY. */
  struct cp_svc_ep_array* svc_arrays;
};


typedef struct
{
  cicp_mac_rowid_t id;
  cp_version_t     version;
} cicp_verinfo_t;


static inline size_t cp_calc_fwd_size(const struct cp_tables_dim* m)
{
  return sizeof(struct cp_fwd_row) * (m->fwd_mask + 1);
}

static inline size_t cp_calc_fwd_blob_size(const struct cp_tables_dim* m)
{
  /* blob starts with fwd table, then fwd_prefix */
  return cp_calc_fwd_size(m) + sizeof(ci_ipx_pfx_t) * CP_FWD_PREFIX_NUM;
}

static inline size_t cp_calc_fwd_rw_size(const struct cp_tables_dim* m)
{
  return sizeof(struct cp_fwd_rw_row) * (m->fwd_mask + 1);
}


/* The "fwd blob" is a chunk of memory that starts with a fwd table and is
 * followed by the prefix table.  These two functions give the addresses of
 * those two tables within the blob. */
static inline struct cp_fwd_row* cp_fwd_table_within_blob(void* fwd_blob)
{
  return (struct cp_fwd_row*) fwd_blob;
}
static inline ci_ipx_pfx_t*
cp_fwd_prefix_within_blob(void* fwd_blob, const struct cp_tables_dim* dim)
{
  return (ci_ipx_pfx_t*) ((char*) fwd_blob + cp_calc_fwd_size(dim));
}


static inline struct cp_fwd_row*
cp_get_fwd_by_id(struct cp_fwd_table* fwd_table, cicp_mac_rowid_t id)
{
  ci_assert_nequal(fwd_table, NULL);
  ci_assert_nequal(id, CICP_MAC_ROWID_BAD);
  ci_assert(CICP_MAC_ROWID_IS_VALID(id));
  ci_assert_le(id, fwd_table->mask);
  return &fwd_table->rows[id];
}


static inline struct cp_fwd_row*
cp_get_fwd(struct cp_fwd_table* fwd_table, cicp_verinfo_t* ver)
{
  return cp_get_fwd_by_id(fwd_table, ver->id);
}

static inline struct cp_fwd_data*
cp_get_fwd_data(struct cp_fwd_table* fwd_table, cicp_verinfo_t* ver)
{
  return &cp_get_fwd(fwd_table, ver)->data[ver->version & 1];
}

static inline cp_version_t*
cp_fwd_version(struct cp_fwd_row* r)
{
  return &r->version;
}

static inline struct cp_fwd_data*
cp_get_fwd_data_current(struct cp_fwd_row* r)
{
  return &r->data[*cp_fwd_version(r) & 1];
}

static inline int
cp_fwd_version_matches(struct cp_fwd_table* fwd_table, cicp_verinfo_t* ver)
{
  ci_assert_nequal(ver->id, CICP_ROWID_BAD);
  ci_assert(CICP_ROWID_IS_VALID(ver->id));
  return ver->version == *cp_fwd_version(cp_get_fwd(fwd_table, ver));
}


static inline struct cp_fwd_rw_row*
cp_get_fwd_rw(struct cp_fwd_table* fwd_table, cicp_verinfo_t* ver)
{
  ci_assert_nequal(fwd_table, NULL);
  ci_assert_nequal(ver->id, CICP_ROWID_BAD);
  ci_assert(CICP_ROWID_IS_VALID(ver->id));
  ci_assert_le(ver->id, fwd_table->mask);
  return &fwd_table->rw_rows[ver->id];
}

static inline int /*bool*/
cp_get_fwd_pfx_cmp(const ci_ipx_pfx_t* a, const ci_ipx_pfx_t* b)
{
  return memcmp(&a->ip6, &b->ip6, sizeof(a->ip6));
}

/* Set up cp_mibs structure from the mmaped memory;
 * caller must set mibs->dim before.
 * Return the size of memory used by MIBs. */
size_t cp_init_mibs(void* mem, struct cp_mibs* mibs);

extern size_t cp_calc_mib_size(const struct cp_tables_dim* dim);
extern off_t cp_find_public_mib_end(const struct cp_tables_dim* dim);

/* Set up fwd table and associated fields from the mmaped memory. */
void cp_init_mibs_fwd_blob(void* romem, struct cp_mibs* mibs);

/* The caller is responsible for version check before and after this
 * function is called. */
static inline cicp_rowid_t
cp_llap_find_row(struct cp_mibs* mib, ci_ifid_t ifindex)
{
  cicp_rowid_t i;

  ci_assert_nequal(ifindex, CI_IFID_BAD);

  for( i = 0; i < mib->dim->llap_max; i++ ) {
    if( mib->llap[i].ifindex == ifindex )
      return i;
    if( cicp_llap_row_is_free(&mib->llap[i]) )
      return CICP_ROWID_BAD;
  }
  return CICP_ROWID_BAD;
}

/* The caller is responsible for version check before and after this
 * function is called. */
static inline cicp_rowid_t
cp_llap_by_ifname(struct cp_mibs* mib, const char* ifname)
{
  cicp_rowid_t i;

  for( i = 0; i < mib->dim->llap_max; i++ ) {
    if( strcmp(mib->llap[i].name, ifname) == 0 )
      return i;
    if( cicp_llap_row_is_free(&mib->llap[i]) )
      return CICP_ROWID_BAD;
  }
  return CICP_ROWID_BAD;
}

/* The caller is responsible for version check before and after this
 * function is called. */
static inline cicp_rowid_t
cp_ipif_any_row_by_ifindex(struct cp_mibs* mib, ci_ifid_t ifindex)
{
  cicp_rowid_t i;

  for( i = 0; i < mib->dim->ipif_max; i++ ) {
    if( mib->ipif[i].ifindex == ifindex )
      return i;
    if( cicp_ipif_row_is_free(&mib->ipif[i]) )
      return CICP_ROWID_BAD;
  }
  return CICP_ROWID_BAD;
}


static inline cicp_hwport_mask_t
cp_get_hwports(struct cp_mibs* mib, cicp_hwport_mask_t hwports)
{
  cicp_hwport_mask_t all_hwports = 0;

  for( ; hwports; hwports &= (hwports - 1) ) {
    ci_hwport_id_t id = cp_hwport_mask_first(hwports);
    if( cicp_hwport_row_is_free(&mib->hwport[id]) )
      continue;
    all_hwports |= cp_hwport_make_mask(id);
  }

  return all_hwports;
}


extern int cp_get_acceleratable_llap_count(struct cp_mibs*);
extern int cp_get_acceleratable_ifindices(struct cp_mibs*,
                                          ci_ifid_t* ifindices, int max_count);
extern ci_ifid_t cp_get_hwport_ifindex(struct cp_mibs*, ci_hwport_id_t);


/* This is an arbitrary limit of re-hashing when searching or adding
 * destination in MAC or FWD tables. */
#define CP_REHASH_LIMIT(mask) ((mask) >> 2)

/* Iterator; returns true to stop iterating */
typedef int/*bool*/
(*cp_fwd_find_hook_fn)(struct cp_fwd_table* fwd_table,
                       cicp_mac_rowid_t fwd_id, void* arg);
cicp_mac_rowid_t
cp_fwd_find_row_iterate(struct cp_fwd_table* fwd_table,
                        struct cp_fwd_key* key,
                        struct cp_fwd_key* match,
                        cp_fwd_find_hook_fn hook, void* hook_arg);

cicp_mac_rowid_t
__cp_fwd_find_row(struct cp_fwd_table* fwd_table, struct cp_fwd_key* key,
                  struct cp_fwd_key* match, ci_uint32 weight);

static inline cicp_mac_rowid_t
cp_fwd_find_row(struct cp_fwd_table* fwd_table, struct cp_fwd_key* key)
{
  return __cp_fwd_find_row(fwd_table, key, key, 0);
}

extern cicp_mac_rowid_t
__cp_fwd_find_match(struct cp_fwd_table* fwd_table, struct cp_fwd_key* key,
                    ci_uint32 weight,
                    ci_ipx_pfx_t src_prefs, ci_ipx_pfx_t dst_prefs);
static inline cicp_mac_rowid_t
cp_fwd_find_match(struct cp_fwd_table* fwd_table,
                  struct cp_fwd_key* key, int weight)
{
  return __cp_fwd_find_match(fwd_table, key, weight,
                             fwd_table->prefix[CP_FWD_PREFIX_SRC],
                             fwd_table->prefix[CP_FWD_PREFIX_DST]);
}


static inline int ci_frc64_after(uint64_t old_frc, uint64_t new_frc)
{
  return (int64_t)(new_frc - old_frc) > 0;
}


/* Some route properties (currently, whether the request was originated by a
 * UDP socket) are not significant for lookup but should be checked when
 * deciding whether to issue a new request for the route.  This function
 * further checks the result of cp_fwd_find_row() for satisfaction of these
 * properties. */
static inline int /*bool*/
cp_fwd_find_row_found_perfect_match(struct cp_fwd_table* fwd_table,
                                    cicp_mac_rowid_t id, struct cp_fwd_key* key)
{
  return id != CICP_MAC_ROWID_BAD;
}


typedef int /*bool*/
(*cp_svc_iterator_callback_t)(const struct cp_mibs*, cicp_mac_rowid_t,
                              void* opaque);

extern cicp_mac_rowid_t
cp_svc_iterate_matches(const struct cp_mibs* mib, const ci_addr_sh_t addr,
                       ci_uint16 port, cp_svc_iterator_callback_t callback,
                       void* opaque);

extern cicp_mac_rowid_t
cp_svc_find_match(const struct cp_mibs* mib, const ci_addr_sh_t dst_addr,
                  ci_uint16 dst_port);

extern void
cp_svc_walk_array_chain(const struct cp_mibs* mib,
                        cicp_rowid_t array_id, cicp_rowid_t element_id,
                        struct cp_svc_ep_array** arr, cicp_rowid_t* index);


static inline void
bw_not_192(uint64_t* x)
{
  int i;
  for( i = 0; i < 3; i++ )
    x[i] = ~x[i];
}

static inline void
bw_and_192(uint64_t* x, uint64_t* y)
{
  int i;
  for( i = 0; i < 3; i++ )
    x[i] &= y[i];
}

static inline void
bw_or_192(uint64_t* x, uint64_t* y)
{
  int i;
  for( i = 0; i < 3; i++ )
    x[i] |= y[i];
}

static inline void
bw_shift_bit_192(uint64_t* x, uint8_t shift)
{
  memset(x, 0, sizeof(uint64_t) * 3);
  x[ 2 - shift / 64] = 1ull << (shift % 64);
}

static inline int
ci_clz192(ci_uint64* x)
{
  int i, res = 0;
  for( i = 0; i < 3; i++ ) {
    ci_uint64 val = x[i];
    if(val == 0) {
      res += 64;
      continue;
    }
    return res + __builtin_clzll(val);
  }
  return 191;
}

static inline ci_uint8 cp_ip6_get_largest_prefix(ci_uint64* prefix_bitmask)
{
  return 191 - ci_clz192(prefix_bitmask);
}

static inline ci_uint8 cp_get_largest_prefix(ci_ipx_pfx_t prefix_bitmask)
{
  return cp_ip6_get_largest_prefix(prefix_bitmask.ip6);
}

#endif /* __TOOLS_CPLANE_PUBLIC_H__ */
