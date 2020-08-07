/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#ifndef __TOOLS_CPLANE_PRIVATE_H__
#define __TOOLS_CPLANE_PRIVATE_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/fib_rules.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include <ci/compat.h>
#include <ci/tools.h>

#include <etherfabric/base.h>


/*
 * cplane server should support IPv6 addresses regardless of CI_CFG_IPV6
 * defined in transport_config_opt.h
 */
#define CI_CFG_IPV6 1
#ifdef __CI_NET_IPVX_SH_H__
#error "Do not include non-typedef'ed version of ci/net/ipvx_sh.h " \
       "into cplane server and tests"
#endif

#include <ci/net/ipvx.h>


#include <onload/hash.h>
#include <cplane/hash.h>
#include <cplane/mib.h>
#include <cplane/ioctl.h>
#include "mask.h"
#include "ip_prefix_list.h"

/* CP_FWD_FLAG_* flags
 * Definitions are in:
 * - CP_FWD_KEY_* are defined in include/cplane/mib.h, together with
 *   struct cp_fwd_key.
 * - CP_FWD_FLAG_REQ & CP_FWD_FLAG_REQ_MASK are defined in
 *   include/cplane/server.h, to make them available when building a route
 *   resolution request.
 * - The rest of the flags are defined below.
 *
 * 0. CP_FWD_FLAG_REQ is set in cp_fwd_req_do(), or'ed with the request id.
 *
 * 1. CP_FWD_KEY_* flags are used in cp_fwd_key->flags.
 * 1a. When cp_fwd_key is used to request a route resolution from the
 *     Control Plane server, following flags are used:
 *     REQ_REFRESH, REQ_WAIT, TRANSPARENT, UDP, SOURCELESS
 * 1b. When cp_fwd_key is used to store a route in the fwd table,
 *     following flgas are used:
 *     TRANSPARENT, UDP
 *
 * TODO: REQ_REFRESH, REQ_WAIT, SOURCELESS are better moved from
 *   cp_fwd_key->flags to si_code and nlmsg_seq, but it means change in the
 *   cplane server interface.  We probably will change the interface when
 *   adding IPv6, but let's avoid such a change when it is not strictly
 *   necessary.
 *
 * 2. CP_FWD_FLAG_*: CP_FWD_KEY_* flags are moved to the upper bytes and
 *    are used in the netlink message sequence number.
 * 2a. When a route resolution is requested, its sequence number always has
 *     CP_FWD_FLAG_REQ and may have REQ_WAIT, TRANSPARENT, UDP, SOURCELESS
 *     flags (see 1a above).
 *     In this case, we also use CP_FWD_FLAG_IFINDEX.
 *     Lower bytes are used for request id, see (0) above.
 * NB CP_FWD_FLAG_REQ clashes with REQ_REFRESH, but they have distinct use
 *    areas.
 * 2b. When the Control Plane server updates an already known route,
 *     the sequence number does NOT have CP_FWD_FLAG_REQ set.
 *     May have TRANSPARENT, UDP, IFINDEX flags.
 *     All other bytes are the fwd entry number.
 * 2c. Dump netlink messages use CP_FWD_FLAG_DUMP sequence number.
 */
#define CP_FWD_FLAG_REQ      0x80000000

#define CP_FWD_FLAG_KEY2NL_SHIFT 24

/* Flag to use with RTM_GETROUTE when resolving a particular route by
 * request, used together with CP_FWD_FLAG_REQ. */
#define CP_FWD_FLAG_REQ_WAIT    (CP_FWD_KEY_REQ_WAIT << \
                                 CP_FWD_FLAG_KEY2NL_SHIFT)
#define CP_FWD_FLAG_TRANSPARENT (CP_FWD_KEY_TRANSPARENT << \
                                 CP_FWD_FLAG_KEY2NL_SHIFT)
#define CP_FWD_FLAG_SOURCELESS  (CP_FWD_KEY_SOURCELESS << \
                                 CP_FWD_FLAG_KEY2NL_SHIFT)

/* The following values are at least as large as 1 << CP_FWD_FLAG_KEY2NL_SHIFT,
 * so care is required not to clash wih flags that are defined with respect to
 * that shift. */

/* The key was remembered in the list of outstanding fwd requests.  Only valid
 * when CP_FWD_FLAG_REQ is not set, as the key is always remembered for
 * requests that have that flag. */
#define CP_FWD_FLAG_KEY_REMEMBERED    0x02000000

/* The route request specifies ifindex (e.g. for SO_BINDTODEVICE). */
#define CP_FWD_FLAG_IFINDEX           0x04000000

/* Adding further flags here requires changes to CP_FWD_FLAG_REQ_MASK. */


/* Mask of the flags we transfer from key->flag to nlmsg_seq */
#define CP_FWD_KEY2SEQ_MASK          CP_FWD_KEY_TRANSPARENT

/* nl_seq value when requesting full table dump.  It MUST have
 * CP_FWD_FLAG_REQ unset.  It also is counted in the maximum possible value
 * for fwd_ln2. */
#define CP_FWD_FLAG_DUMP            0x01000000
#define CP_FWD_FLAG_REFRESH_MASK    0x00ffffff

#ifdef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__
#error "don't include ci/internal/transport_config_opt.h from cplane code"
#endif


struct cp_timer {
  enum {
    CP_TIMER_NET,
    CP_TIMER_FWD,
  } type;
  timer_t t;
};

/* NETLINK_GENERIC groups we'd like to listen on. */
enum cp_genl_group {
  /* nlctrl/notify: */
  CP_GENL_GROUP_CTRL= 0,
  /* TEAM_GENL_NAME/TEAM_GENL_CHANGE_EVENT_MC_GRP_NAME: */
  CP_GENL_GROUP_TEAM = 1,
  CP_GENL_GROUP_MAX = 2
};

enum cp_dump_state {
  CP_DUMP_IDLE,
  CP_DUMP_GENL,
  CP_DUMP_LLAP,
  CP_DUMP_IPIF,
  CP_DUMP_IP6IF,
  CP_DUMP_RULE,
  CP_DUMP_RULE6,
  CP_DUMP_ROUTE,
  CP_DUMP_ROUTE6,
  CP_DUMP_MAC,
  CP_DUMP_MAC6,
  CP_DUMP_COMPLETED,
};

struct cp_team_dump {
  struct cp_team_dump* next;
  ci_ifid_t ifindex;
  enum {
    CP_TEAM_DUMP_OPTS,
    CP_TEAM_DUMP_PORTS,
    CP_TEAM_DUMP_DONE
  } state;
  cp_row_mask_t seen;
};

/* Used to accumulate bond info from netlink attributes, before being applied
 * wholesale. */
struct cp_bond_netlink_state {
  /* Bitmap of netlink attributes seen, and hence also of fields that are valid
   * in this structure. */
#define CP_BOND_NETLINK_SEEN_MODE              0x00000001u
#define CP_BOND_NETLINK_SEEN_ACTIVE_SLAVE      0x00000002u
#define CP_BOND_NETLINK_SEEN_HASH_POLICY       0x00000004u
#define CP_BOND_NETLINK_SEEN_AGGREGATOR        0x00000008u
  uint32_t    attributes_seen;

  int         mode;               /* Bond mode. */
  ci_ifid_t   active_slave;       /* Ifindex of active slave. */
  int         hash_policy;        /* Hash policy to use for xmit */
  uint16_t    aggregator_id;      /* Aggregator id, bond_3ad */
};

/*
 *** BOND table ***
 */

#define CICP_BOND_ROW_TYPE_FREE 0
#define CICP_BOND_ROW_TYPE_MASTER 1
#define CICP_BOND_ROW_TYPE_SLAVE 2

#define CICP_BOND_ROW_NEXT_BAD CICP_ROWID_BAD

/* Slave flags:
 * In case of teaming, FLAG_UP is TEAM_ATTR_PORT_LINKUP attribute,
 * and FLAG_ENABLED is the "enabled" per-port option.  The port is in
 * operation iff both are true.
 * In case of bonding lacp, FLAG_ENABLED is used when aggregator id matches.
 * Bonding active backup always sets FLAG_ENABLED.
 *
 * FLAG_ACTIVE means this port is really used for transmit:
 * - load balance: FLAG_UP & FLAG_ENABLED
 * - active backup: the active port, specified via a special option.
 */
#define CICP_BOND_ROW_FLAG_UP          1
#define CICP_BOND_ROW_FLAG_ENABLED     2
#define CICP_BOND_ROW_FLAG_ACTIVE      4
#define CICP_BOND_ROW_FLAG_UNSUPPORTED 8

/* XOR mode is currently unsupported due to difficulty getting link
 * status for XOR bonds - see Bug21239
 */
#define CICP_BOND_MODE_ACTIVE_BACKUP 1
#define CICP_BOND_MODE_802_3AD       2
#define CICP_BOND_MODE_UNSUPPORTED   3

typedef struct {
  cicp_rowid_t next;
  ci_ifid_t ifid;
  ci_uint8 type;
  ci_uint16 agg_id; /* used by bond_3ad only */
  union{
    struct {
      ci_hwport_id_t hwport;
      cicp_rowid_t master;
      ci_uint8 flags;
    } slave;
    struct {
      ci_int8 n_active_slaves;
      ci_int8 mode;
      cicp_llap_type_t hash_policy; /* CICP_LLAP_TYPE_XMIT_HASH_* flags only */
    } master;
  };
} cicp_bond_row_t;

static inline int
cicp_bond_row_is_free(cicp_bond_row_t *row)
{
  return row->type == CICP_BOND_ROW_TYPE_FREE;
}


/*
 *** ARP table ***
 */
/* entry is occupied when ifindex != 0 */
typedef struct {
    ci_addr_t     addr;     /*< the entry's ip address */
    ci_mac_addr_t mac;      /*< the ip address's MAC address */
    ci_ifid_t     ifindex;  /*< access point on which the MAC addr is valid */
    ci_uint16     use;      /*< hash chain use count */
    ci_uint16     state;    /*< NUD_REACHABLE, etc */

    ci_uint16     flags;
/* Onload should set EHOSTUNREACH */
#define CP_MAC_ROW_FLAG_FAILED     1
/* Some fwd entry uses it.  This flag is not reliable, because we have no
 * method to maintain it.  It can be used as a hint that this MAC entry was
 * unused for some time, and its FAILED state need reconfirmation.
 *
 * Think of it as a sort of heuristic. */
#define CP_MAC_ROW_FLAG_REFERENCED 2

    /* frc when this MAC entry must be re-confirmed if possible;
     * valid in NUD_REACHABLE state only. */
    ci_uint64     frc_reconfirm;
} cicp_mac_row_t;

#define CP_MAC_ROW_FLAGS_FMT "%s%s"
#define CP_MAC_ROW_FLAGS_ARGS(flags) \
  ((flags) & CP_MAC_ROW_FLAG_FAILED) ? "FAILED " : "", \
  ((flags) & CP_MAC_ROW_FLAG_REFERENCED) ? "referenced " : ""

#ifndef NUD_VALID
/* Linux defines this in net/neighbour.h for in-kernel code, but we need it
 * in UL. */
#define NUD_VALID \
  (NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
#endif

/*
 *** Private part of a FWD table row ***
 */
struct cp_fwd_priv {
  /* mirror of fwd_table.rw_rows.frc_used containing values we've
   * really applied */
  uint64_t frc_used;
  cicp_mac_rowid_t macid;
  /* ifindex for the route
   * note: for ALIEN routes ifindex is not stored in fwd_data */
  ci_ifid_t ifindex;
  uint32_t table_id; /* routing table this fwd entry originates from */
};

/*
 *** FWD state containing public and private fields for one net namespace ***
 */
struct cp_fwd_state {
  /* Public FWD table */
  struct cp_fwd_table fwd_table;
  /* Which FWD table rows are in use? */
  cp_row_mask_t fwd_used;
  /* Array of private per-row data */
  struct cp_fwd_priv* priv_rows;
};

/*
 *** Private dump of a route table
 */
struct cp_route {
  /* Keys.  See fib_table_insert(): linux sort of guarantees that there
   * is no more than one route with any given key.
   * However we have bug bug 43318: 2 different routes to the same
   * destination.  I can easily add them with "route" tool, but can not
   * with "ip route" tool. */
  struct cp_ip_with_prefix dst;
  uint32_t metric;
  cicp_ip_tos_t tos;
  uint8_t scope;

  /* Data. */
  uint8_t type;
  struct cp_fwd_data_base data;

  /* Multipath data */
  struct cp_fwd_multipath_weight weight;
};
#define ROUTE_TABLE_HASH_SIZE 256 /* == FIB_TABLE_HASHSZ */
struct cp_route_table {
  uint32_t id;
  struct cp_ip_prefix_list routes;
  struct cp_route_table* next;
};

/*
 *** Private part of LLAP table ***
 */
struct cp_llap_priv {
  /* The immediate type of this link */
  cicp_llap_type_t immediate_type;

  /* /proc/sys/net/ipv4/neigh/<ifname>/base_reachable_time_ms, in ms  */
  ci_uint32 arp_base_reachable;
};


/*
 *** Server statistics ***
 */
struct cp_stats {
#define CP_STAT_GROUP_START(desc, name)     struct {
#define CP_STAT(desc, type, name)             type name;
#define CP_STAT_GROUP_END(name)             } name;
  #include "stats.h"
#undef CP_STAT_GROUP_START
#undef CP_STAT
#undef CP_STAT_GROUP_END
};


/*
 *** The main server structure ***
 */
struct cp_session {
  /* Globally-unique ID for this control plane instance. */
  cp_fwd_table_id cplane_id;

  /* Timers:
   * - Netlink timer "timer_net" is seldom because we listen on netlink update.
   *   This timer is not needed at all if no netlink message is lost (but
   *   we can't guarantee this).
   * - Bond timer is frequent because it is the only way to find out about bond
   *   updates on distros that don't publish bond state via netlink.  If we
   *   receive netlink bond attributes, we stop this timer.
   * - Forwarch cache timer should fire at least every 5 seconds to
   *   re-confirm ARP entries which are going to become stale.
   */
  struct cp_timer timer_net;
  struct cp_timer timer_bond;
  struct cp_timer timer_bond_3ad;
  struct cp_timer timer_fwd;

  int epoll_fd;

  /* Netlink sockets: NETLINK_ROUTE and NETLINK_GENERIC. */
  int sock_net;
  int sock_gen[CP_GENL_GROUP_MAX];

  /* AF_UNIX socket to communicate with mibdump */
  int mibdump_sock;

  /* AF_UNIX socket to receive updates from external agents */
  int agent_sock;

  /* File descriptor to print internal states. */
  int cp_print_fd;

  /* Buffer to read netlink messages */
  size_t buf_size;
  void* buf;

  /* Netlink socket name */
  struct sockaddr_nl sock_net_name;

  /* Pipe to get the results of license check */
  int pipe[2];

  /* AF_INET SOCK_DGRAM socket, to be used with SIOCETHTOOL */
  int sock;

  /* /dev/onload */
  int oo_fd;

#ifdef CP_SYSUNIT
  /* Named pipe /tmp/onload_cp_server.<pid> */
  int comm_pipe;
#endif

#ifdef CP_UNIT
  /* Next hwport to synthesise when mocking up Onloadable interfaces. */
  int next_hwport;
#endif

  /* Sequence number for netlink messages. */
  uint32_t nl_seq;

  /* Flags to set and get while processing something in sequence. */
  uint32_t flags;
/* We are ready to serve clients iff both NETLINK_DUMPED and HWPORT_DUMPED. */
/* We've dumped all the netlink data. */
#define CP_SESSION_NETLINK_DUMPED          0x1
/* We've got hwport info from the kernel module */
#define CP_SESSION_HWPORT_DUMPED           0x2
/* Need to re-resolve routes for all entries in fwd table. */
#define CP_SESSION_FLAG_FWD_REFRESH_NEEDED 0x4
#define CP_SESSION_FLAG_FWD_REFRESHED      0x8
/* See cp_mibs_.*under_change(), cp_mibs_change_done(). */
#define CP_SESSION_FLAG_CHANGES_STARTED   0x10
#define CP_SESSION_FLAG_LLAP_CHANGES_STARTED 0x20
/* Debug mode: do not listen for netlink updates, rely on periodic table
 * dump. */
#define CP_SESSION_NO_LISTEN              0x40
/* At next refresh of the fwd table, remove any entries whose prefix lengths do
 * not match those implied by the route tables. */
#define CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED 0x100
/* User asked for dump and is waiting for notification */
#define CP_SESSION_USER_DUMP             0x200
/* User asked for dump when another dump is in progress;
 * we should re-dump everything when we have a chance. */
#define CP_SESSION_USER_DUMP_REFRESH     0x400
/* User asked for lightweight sync with OS */
#define CP_SESSION_USER_OS_SYNC          0x800
/* disable IPv6 support */
#define CP_SESSION_NO_IPV6               0x2000
/* Kernel compiled without CONFIG_IPV6_SUBTREES - no source address
 * for IPv6 */
#define CP_SESSION_IPV6_NO_SOURCE        0x4000
/* Some routes are multipath routes */
#define CP_SESSION_DO_MULTIPATH          0x8000
/* Seen some multipath routes during this route dump */
#define CP_SESSION_SEEN_MULTIPATH       0x10000
/* Verify that resolving routes via routing tables results in the same
 * data as questioning via netlink */
#define CP_SESSION_VERIFY_ROUTES        0x20000
/* Kernel reports RTA_IIF. */
#define CP_SESSION_OS_REPORTS_RTA_IIF   0x40000
/* Need to refresh the list of local addresses laddr */
#define CP_SESSION_LADDR_REFRESH_NEEDED 0x80000
/* Account preferred source addresses in laddr */
#define CP_SESSION_LADDR_USE_PREF_SRC  0x100000
  
  /* Netlink is dumping a table: */
  enum cp_dump_state state;
  enum cp_dump_state prev_state;
  bool dump_one_only; /* dump one table only */

  /* Which rows we've seen when dumping the current table? */
  cp_row_mask_t seen;

  /* Bond & MAC MIBs are not visible to users, so they are not a part of
   * cp_mibs structure. */
  cicp_bond_row_t* bond;
  cicp_rowid_t bond_max;

  /* Number of ARP rows must be 2^n */
  cicp_mac_row_t* mac;
  ci_uint8 mac_max_ln2;
  cicp_mac_rowid_t mac_mask; /* 2^mac_max_ln2 - 1 */

  cicp_mac_row_t* ip6_mac;

  /* The list of teaming interfaces we are dumping now.  The team interface
   * parameters are dumped in CP_DUMP_LLAP state. */
  struct cp_team_dump* team_dump;

  /* We sort out versioning of the mibs in the following way.
   * We have two frames/snapshots of mibs.
   * One is coherent and active, the other is inactive or under update.
   * Active frame is identified with by this expression:
   *  (*version) & 1,
   * by having always a coherent available version there is no need to spin on
   * verlock waiting for pending update to complete.  Especially important for
   * accessing verlock from interrupt context */

  struct cp_mibs mib[2];

  int main_cp_fd;
  struct oo_cplane_handle* main_cp_handle;

  /* sysconf(_SC_CLK_TCK) to decode ndm_confirmed field */
  unsigned user_hz;
  /* frc = msec * kz */
  uint64_t khz;

  /* Which MAC entries are in use? */
  cp_row_mask_t mac_used;
  cp_row_mask_t ip6_mac_used;

  /* How long to we keep fwd entries in cache? */
  uint64_t frc_fwd_cache_ttl;

  /* Private per-fwd-table data.  These are initialised lazily in
   * cp_get_fwd_state(), which should ordinarily be used to access this array.
   */
  struct cp_fwd_state __fwd_state[CP_MAX_INSTANCES];

  /* Which service backend arrays are in use? */
  cp_row_mask_t service_used;

  /* Private per-llap-entry data */
  struct cp_llap_priv* llap_priv;

  uint32_t genl_family[CP_GENL_GROUP_MAX];
  uint32_t genl_group[CP_GENL_GROUP_MAX];

  /* Full dump of all routes and rules tables.  Only IP/prefix destination is
   * stored here.  Ordered by prefix (/32 first). */
  struct cp_ip_prefix_list route_dst;
  /* List of all source-routing rules. */
  struct cp_ip_prefix_list rule_src;

  struct cp_ip_prefix_list ip6_route_dst;
  struct cp_ip_prefix_list ip6_rule_src;

  /* List of all possible preferred source addresses for accelerated routes.
   * It includes
   * (1) ipif and ip6if tables;
   * (2) preferred source for any route going via onloadable interface.
   * The list is used for oof notifications.
   */
  struct cp_ip_prefix_list laddr;

  /* Copy of all the route tables */
  struct cp_route_table* rt_table[ROUTE_TABLE_HASH_SIZE];
  struct cp_route_table* rt6_table[ROUTE_TABLE_HASH_SIZE];

#define CICP_LLAP_TYPE_CHILD (CICP_LLAP_TYPE_MACVLAN | \
                              CICP_LLAP_TYPE_IPVLAN  | \
                              CICP_LLAP_TYPE_VLAN)
#define LLAP_TYPE_OS_MASK_DEFAULT (CICP_LLAP_TYPE_CHILD| \
                                   CICP_LLAP_TYPE_BOND | \
                                   CICP_LLAP_TYPE_LOOP | \
                                   CICP_LLAP_TYPE_VETH | \
                                   CICP_LLAP_TYPE_ROUTE_ACROSS_NS)
  /* LLAP types specified in this mask are set in response to RTM_GETLINK
   * messages from the OS; others are determined via other ways. */
  cicp_llap_type_t llap_type_os_mask;

  struct cp_stats stats;

  /* Outstanding route requests.  This is analogous to the fwd_req list in the
   * kernel. */
  ci_dllist fwd_req_ul;

  /* Things added to epoll. Stored solely so we can free them at exit to get
   * clean results from leak checkers */
  struct cp_epoll_state* ep_net;
  struct cp_epoll_state* ep_gen_ctrl;
  struct cp_epoll_state* ep_gen_team;
  struct cp_epoll_state* ep_pipe;
  struct cp_epoll_state* ep_mibdump;
  struct cp_epoll_state* ep_agent;
  struct cp_epoll_state* ep_oo;
};


/* Outstanding route request.  This allows us to recover the key for a route
 * request, as in general the kernel does not provide us with sufficient
 * information to reconstruct it from the route response. */
struct cp_fwd_req {
  struct cp_fwd_key key;
  uint32_t nl_seq;
  ci_dllink link;
};


static inline struct cp_mibs* cp_get_active_mib(struct cp_session* s)
{
  int i = *s->mib->version & 1;
  return &s->mib[i];
}


static inline struct cp_mibs* cp_get_scratch_mib(struct cp_session* s)
{
  int i = !(*s->mib->version & 1);
  return &s->mib[i];
}

#ifndef NDEBUG
extern void cp_mibs_verify_identical(struct cp_session* s, bool llap_only);
extern void cp_fwd_verify_identical(struct cp_fwd_row* s);
#else
static inline void cp_mibs_verify_identical(struct cp_session* s, bool llap_only)
{}
static inline void cp_fwd_verify_identical(struct cp_fwd_row* s)
{}
#endif

static inline struct cp_ip_prefix_list*
cp_get_route_dst_p(struct cp_session* s, int af)
{
  return (af == AF_INET6) ? &s->ip6_route_dst : &s->route_dst;
}

static inline struct cp_ip_prefix_list*
cp_get_rule_src_p(struct cp_session* s, int af)
{
  return (af == AF_INET6) ? &s->ip6_rule_src : &s->rule_src;
}

static inline cicp_mac_row_t*
cp_get_mac_p(struct cp_session* s, int af)
{
  return (af == AF_INET6) ? s->ip6_mac : s->mac;
}

static inline cp_row_mask_t
cp_get_mac_used(struct cp_session* s, int af)
{
  return (af == AF_INET6) ? s->ip6_mac_used : s->mac_used;
}

/* cp_mibs_under_change() and cp_mibs_change_done() are idempotent.
 * I.e. the first marks the MIB as "under change"; it does nothing if the
 * MIBs are already under change.
 * The second one exits the critical section if the critical section was
 * entered; i.e. it is safe to call it even the critical section was not
 * entered. */
static inline void cp_mibs_under_change(struct cp_session* s)
{
  s->flags |= CP_SESSION_FLAG_CHANGES_STARTED;
}
/* cp_mibs_llap_under_change() marks "MIB under change"
 * (as cp_mibs_under_change() does) and also
 * marks llap table within mib to be undergoing change.
 * should be called instead of cp_mibs_under_change() when changes
 * to MIB affect llap table.  Calling this function will cause
 * increase of mib->llap_version - this is the only effect
 * and the only consumer of llap_version is tcp_direct bonding. */
static inline void cp_mibs_llap_under_change(struct cp_session* s)
{
  s->flags |= CP_SESSION_FLAG_CHANGES_STARTED |
              CP_SESSION_FLAG_LLAP_CHANGES_STARTED;
}
static inline bool cp_mibs_change_done(struct cp_session* s)
{
  if( ! (s->flags & CP_SESSION_FLAG_CHANGES_STARTED) )
    return false;
  struct cp_mibs* mib = cp_get_scratch_mib(s);
  int flags = s->flags;
  s->flags &= ~(CP_SESSION_FLAG_CHANGES_STARTED |
                CP_SESSION_FLAG_LLAP_CHANGES_STARTED);
  if( flags & CP_SESSION_FLAG_LLAP_CHANGES_STARTED )
    (*mib->llap_version)++;
  ci_wmb();
  (*mib->version)++;

  if( ~flags & CP_SESSION_FLAG_LLAP_CHANGES_STARTED )
    cp_mibs_verify_identical(s, true);
  return true;
}



/* Macros defining loop constructs for updating each MIB.  They can be used
 * in conjuction with "continue" if the same changes should be applied to
 * both MIB copies (if any), and with MIB_UPDATE_LOOP_UNCHANGED() for
 * early exit from the loop. */
#define MIB_UPDATE_LOOP(mib_, cp_, mib_i_) \
  { \
    ci_assert_nflags((cp_)->flags, CP_SESSION_FLAG_CHANGES_STARTED | \
                                   CP_SESSION_FLAG_LLAP_CHANGES_STARTED ); \
    cp_mibs_verify_identical((cp_), false); \
    for( (mib_i_) = 0; (mib_i_) < 2; ++(mib_i_) ) { \
      (mib_) = cp_get_scratch_mib((cp_)); \
      do {

#define MIB_UPDATE_LOOP_END(mib_,cp_) \
      } while(0); /* catch continue for cp_mibs_change_done and tests */ \
      if( ! cp_mibs_change_done((cp_)) ) \
        break; \
    } \
    cp_mibs_verify_identical((cp_), false); \
  }

/* Macro to use for early exit from the MIB_UPDATE_LOOP-MIB_UPDATE_LOOP_END
 * loop when we know that MIBs have not been changed.
 * The _code is typically "return" or "goto fail".
 * Beware: "connect" or "break" will not work in a way you expect. */
#define MIB_UPDATE_LOOP_UNCHANGED(mib_, cp_, code_) \
  do { \
    ci_assert_equal((mib_), cp_get_scratch_mib((cp_))); \
    ci_assert_nflags((cp_)->flags, CP_SESSION_FLAG_CHANGES_STARTED | \
                                   CP_SESSION_FLAG_LLAP_CHANGES_STARTED); \
    cp_mibs_verify_identical((cp_), false); \
    code_; \
  } while(0)


static inline void cp_fwd_under_change(struct cp_fwd_row* s)
{
  s->flags |= CICP_FWD_FLAG_CHANGES_STARTED;
}

static inline int cp_fwd_change_done(struct cp_fwd_row* s)
{
  if( ! (s->flags & CICP_FWD_FLAG_CHANGES_STARTED) )
    return 0;
  s->flags &= ~CICP_FWD_FLAG_CHANGES_STARTED;
  if( s->flags & CICP_FWD_FLAG_OCCUPIED )
    /* assume that after first update the data is valid.
     * The flag is removed on removal of row in fwd_row_del(). */
    s->flags |= CICP_FWD_FLAG_DATA_VALID;
  ci_wmb();
  ++s->version;
  return 1;
}

static inline struct cp_fwd_data*
cp_get_fwd_data_scratch(struct cp_fwd_row* r)
{
  return &r->data[(*cp_fwd_version(r) & 1) ^ 1];
}

#define FWD_UPDATE_LOOP(fwd_data_, fwd_, ver_i_) \
  { \
    cp_fwd_verify_identical((fwd_)); \
    ci_assert_nflags((fwd_)->flags, CICP_FWD_FLAG_CHANGES_STARTED); \
    for( (ver_i_) = 0; (ver_i_) < 2; ++(ver_i_) ) { \
      (fwd_data_) = cp_get_fwd_data_scratch((fwd_)); \
      do {

#define FWD_UPDATE_LOOP_END(fwd_) \
      } while(0); \
      if( ! cp_fwd_change_done((fwd_)) ) \
        break; /* no work has been done */ \
    } \
    cp_fwd_verify_identical((fwd_)); \
  }


/* Symbols defined as CP_UNIT_EXTERN are extern only in the build of the unit
 * tests. */
#if defined(CP_UNIT) || defined(CP_SYSUNIT)
# define CP_ANYUNIT
# define CP_UNIT_EXTERN
# define ONLOAD_IOCTL cp_unit_ioctl
  extern int cplane_ioctl(int, long unsigned int, ...);
  int cp_session_init_memory(struct cp_session*, struct cp_tables_dim*,
                              void* mib_mem);
  void cp_nl_net_handle_msg(struct cp_session*, struct nlmsghdr*,
                            ssize_t bytes);
  void init_ipp_list(struct cp_ip_prefix_list*, cicp_rowid_t size);
  ci_uint64 cp_frc64_get(void);
  void cp_nl_dump_all_done(struct cp_session*);
  struct cp_fwd_state* cp_fwd_state_get(struct cp_session* s,
                                        cp_fwd_table_id fwd_table_id);

#else
# define CP_UNIT_EXTERN static
# define cp_frc64_get ci_frc64_get
# define cplane_ioctl ioctl
#endif

CI_NORETURN init_failed(const char* msg, ...);


struct cp_epoll_state;

/* NOTE: The callback function takes the entire epoll state as this
 * is required to unregister the fd. */
typedef void (cp_epoll_callback)(struct cp_session*, struct cp_epoll_state*);

struct cp_epoll_state {
  int fd;                      /* An fd that we've added to the epoll set */
  cp_epoll_callback* callback; /* The function to call when fd becomes ready */
  void* private;               /* Pointer to private data (size specified
                                * at register time) */
};

struct cp_epoll_state* cp_epoll_register(struct cp_session* s, int fd,
                                         cp_epoll_callback* callback,
                                         unsigned private_bytes);
int cp_epoll_unregister(struct cp_session* s, struct cp_epoll_state* state);


ssize_t cp_sock_recv(struct cp_session* s, int sock);
void nl_net_handle(struct cp_session*, struct cp_epoll_state*);
void nl_gen_handle(struct cp_session*);
void nl_gen_ctrl_handle(struct cp_session*, struct cp_epoll_state*);
void nl_gen_team_handle(struct cp_session*, struct cp_epoll_state*);

void cp_dump_init(struct cp_session* s);
void cp_dump_start(struct cp_session* s);
void cp_do_dump(struct cp_session*);
void cp_periodic_dump(struct cp_session* s);
int cp_nl_send_dump_req(struct cp_session* s, int sock,
                        struct nlmsghdr* nlh, int nlmsg_type,
                        int nlmsg_flags, size_t bytes);
void cp_llap_dump_done(struct cp_session* s);
void cp_ipif_dump_done(struct cp_session* s);
void cp_ip6if_dump_done(struct cp_session* s);
void cp_mac_dump_done(struct cp_session* s, int af);
int cp_genl_dump_start(struct cp_session* s);
void cp_genl_dump_done(struct cp_session* s);
void cp_team_dump_one(struct cp_session* s, ci_ifid_t ifindex);

void cp_mibdump_sock_init(struct cp_session* s);
void cp_mibdump_sock_handle(struct cp_session* s, struct cp_epoll_state*);

void cp_agent_sock_init(struct cp_session* s);
void cp_agent_sock_handle(struct cp_session* s, struct cp_epoll_state*);

void cp_populate_llap_hwports(struct cp_session* s, ci_ifid_t ifindex,
                              ci_hwport_id_t hwport, cp_nic_flags_t nic_flags);

#define RTA_GET(ptr) \
  ((struct rtattr*)(((char*)(ptr)) + NLMSG_ALIGN(sizeof(typeof(*ptr)))))
#define RTA_LOOP(upper, attr, bytes) \
  struct rtattr *attr;                  \
  for( attr = RTA_GET(upper);           \
       RTA_OK(attr, bytes);             \
       attr = RTA_NEXT(attr, bytes) )

/* The "upper" may be of various type, and it MUST NOT be casted to
 * (struct rtattr*) before this macro, because RTA_GET() needs the real
 * type and the real sizeof. */
#define RTA_NESTED_LOOP(upper, attr, bytes) \
  struct rtattr *attr;                                                      \
  size_t bytes;                                                             \
  for( attr = RTA_GET(upper), bytes = RTA_PAYLOAD((struct rtattr*)(upper)); \
       RTA_OK(attr, bytes);                                                 \
       attr = RTA_NEXT(attr, bytes) )

/* alignment for a value of rtattr */
#define CP_RTA_PACKED   __attribute__((__packed__, __aligned__(RTA_ALIGNTO)))
/* alignment for payload following nlmsg header */
#define CP_NLMSG_PACKED __attribute__((__packed__, __aligned__(NLMSG_ALIGNTO)))

/* GCC complains on applying packed attribute to char */
#pragma GCC diagnostic ignored "-Wattributes"

struct nlmsghdr;
struct rtmsg;
void
cp_nl_route_handle(struct cp_session* s, struct nlmsghdr* nlhdr,
                   struct rtmsg* rtm, size_t bytes);
void
cp_nl_route_table_update(struct cp_session* s, struct nlmsghdr* nlhdr,
                         struct rtmsg* rtm, size_t bytes);

void cp_fwd_req_do(struct cp_session* s, int req_id,
                   struct cp_fwd_key* key);
void cp_fwd_cache_refresh(struct cp_session*);
void cp_fwd_llap_update(struct cp_session* s, struct cp_mibs* mib,
                        cicp_rowid_t llap_id,
                        cicp_hwport_mask_t old_rx_hwports);

void cp_laddr_refresh(struct cp_session*);

#define CP_FWD_MAC_UPDATE_FLAG_NEED_UPDATE      0x1
#define CP_FWD_MAC_UPDATE_FLAG_NEED_UPDATE_ONLY 0x2
void cp_fwd_mac_update(struct cp_session* s, int af,
                       ci_addr_t addr, ci_ifid_t ifindex,
                       cicp_mac_rowid_t macid, int flags);
void cp_fwd_mac_is_stale(struct cp_session* s, int af, cicp_mac_rowid_t macid);
void cp_fwd_timer(struct cp_session*);

extern void cp_oof_req_do(struct cp_session* s);

static inline void
cicp_ipif_row_free(cicp_ipif_row_t *row)
{
  row->net_ipset = CI_IP_PREFIXLEN_BAD;
}

static inline void
cicp_ip6if_row_free(cicp_ip6if_row_t *row)
{
  row->net_ipset = CI_IP_PREFIXLEN_BAD;
}

static inline void
cicp_llap_row_free(cicp_llap_row_t *row)
{
  row->ifindex = CI_IFID_BAD;
}

void cp_llap_notify_oof(struct cp_session* s, cicp_llap_row_t* llap);

void __cp_ipif_notify_oof(struct cp_session* s, int af,
                          struct cp_ip_with_prefix* laddr, bool add);
void cp_laddr_add(struct cp_session* s, int af,
                  ci_addr_sh_t addr, ci_ifid_t ifindex);
void cp_ipif_notify_oof(struct cp_session* s, struct cp_mibs* mib, int af,
                        cicp_rowid_t row_id);
void cp_llap_notify_oof_of_removal(struct cp_session* s, ci_ifid_t ifindex);

void cp_nl_error_route_handle(struct cp_session* s,
                              struct nlmsgerr* err, size_t bytes);
void cp_llap_set_hwports(struct cp_session* s, struct cp_mibs* mib,
                         cicp_rowid_t llap_id,
                         cicp_hwport_mask_t rx_hwport,
                         cicp_hwport_mask_t tx_hwport,
                         cicp_llap_type_t type, bool notify);

extern bool
cp_llap_can_accelerate_veth(struct cp_session* s, ci_ifid_t ifindex);

extern void
cp_veth_fwd_table_id_do(struct cp_session* s, ci_ifid_t veth_ifindex,
                        cp_fwd_table_id fwd_table_id);

extern void cp_llap_fix_upper_layers(struct cp_session* s);

extern void
cp_set_hwport_flags(struct cp_session* s, struct cp_mibs* mib,
                    ci_hwport_id_t hwport, int flags);

/* teaming & bonding primitives */

static inline cicp_rowid_t
cp_bond_find_master(struct cp_session* s, ci_ifid_t ifindex)
{
  cicp_rowid_t id;

  for( id = 0; id < s->bond_max; id++ ) {
    /* Since masters are compressed, we can exit as soon as we see a free
     * entry. */
    if( cicp_bond_row_is_free(&s->bond[id]) )
      return CICP_ROWID_BAD;
    else if( s->bond[id].ifid == ifindex &&
             s->bond[id].type == CICP_BOND_ROW_TYPE_MASTER )
      return id;
  }

  return CICP_ROWID_BAD;
}

static inline cicp_rowid_t
cp_team_find_row(struct cp_session* s, ci_ifid_t ifindex)
{
  /* Although masters are compressed, slaves are not, and so a linear search
   * would have to iterate over the whole table.  Instead, iterate over the
   * masters, and iterate in turn over their slave lists. */

  cicp_rowid_t master_id;

  for( master_id = 0; master_id < s->bond_max; ++master_id ) {
    if( cicp_bond_row_is_free(&s->bond[master_id]) )
      return CICP_ROWID_BAD;
    if( s->bond[master_id].ifid == ifindex )
      return master_id;

    cicp_rowid_t slave_id;
    for( slave_id = s->bond[master_id].next;
         CICP_ROWID_IS_VALID(slave_id);
         slave_id = s->bond[slave_id].next ) {
      ci_assert(! cicp_bond_row_is_free(&s->bond[slave_id]));
      if( s->bond[slave_id].ifid == ifindex )
        return slave_id;
    }
  }

  return CICP_ROWID_BAD;
}

static inline cicp_rowid_t
cp_bond_find_slave(struct cp_session* s, ci_ifid_t ifindex)
{
  /* Bonds-on-bonds are not supported, so it's legitimate to do a generic
   * lookup and check that the result is a slave. */
  cicp_rowid_t id = cp_team_find_row(s, ifindex);
  if( id == CICP_ROWID_BAD || s->bond[id].type != CICP_BOND_ROW_TYPE_SLAVE )
    return CICP_ROWID_BAD;
  return id;
}

cicp_rowid_t cp_team_find_or_add(struct cp_session* s, ci_ifid_t ifindex);

void cp_team_update_hwports(struct cp_session* s, struct cp_mibs* mib,
                           cicp_rowid_t team_id, bool notify);
void cp_team_update_hwports_bothmibs(struct cp_session*, cicp_rowid_t team_id);

cicp_rowid_t cp_team_port_add(struct cp_session* s,
                              ci_ifid_t team, ci_ifid_t port);
void cp_team_slave_update_flags(struct cp_session* s, cicp_rowid_t port_id,
                                ci_uint8 mask, ci_uint8 flags);
void cp_team_slave_del(struct cp_session* s,
                       ci_ifid_t team, ci_ifid_t port);
void cp_team_set_mode(struct cp_session* s, ci_ifid_t team, ci_int8 mode,
                      cicp_llap_type_t hash_policy);
void cp_team_activebackup_set_active(struct cp_session* s,
                                     ci_ifid_t team, ci_ifid_t port);
void cp_team_no_ports(struct cp_session* s, ci_ifid_t team);
void cp_team_remove_master(struct cp_session* s, ci_ifid_t team);
void ci_team_purge_unseen(struct cp_session* s, ci_ifid_t team,
                          cp_row_mask_t seen);
void cp_team_purge_unknown(struct cp_session* s, struct cp_mibs* mib);

void cp_bond_handle_netlink_info(struct cp_session* s, ci_ifid_t bond_ifindex,
                                 struct rtattr *attr,
                                 struct cp_bond_netlink_state* state);
void cp_bond_master_update(struct cp_session* s, ci_ifid_t bond_ifindex,
                           const struct cp_bond_netlink_state* state);
void cp_bond_slave_update(struct cp_session* s, ci_ifid_t master_ifindex,
                          ci_ifid_t slave_ifindex, bool slave_up,
                          int16_t aggregator_id);


/* IFLA_IPVLAN_MODE exists in linux>=3.19 */
#if !defined(IFLA_IPVLAN_MAX)
#define IFLA_IPVLAN_MODE 1
#define IPVLAN_MODE_L2 0
#else
  CI_BUILD_ASSERT(IFLA_IPVLAN_MODE == 1);
  CI_BUILD_ASSERT(IPVLAN_MODE_L2 == 0);
#endif
 
/* RTM_F_LOOKUP_TABLE exists in linux>=4.4 */
#ifndef RTM_F_LOOKUP_TABLE
# define RTM_F_LOOKUP_TABLE 0x1000
#else
  CI_BUILD_ASSERT(RTM_F_LOOKUP_TABLE == 0x1000);
#endif


void cp_ipif_dump_start(struct cp_session* s, int af);
void cp_rule_dump_start(struct cp_session* s, int af);
void cp_route_dump_start(struct cp_session* s, int af);
void cp_rule_dump_done(struct cp_session* s, int af);
void cp_route_dump_done(struct cp_session* s, int af);
void cp_newrule_handle(struct cp_session* s, uint16_t nlmsg_type,
                       struct fib_rule_hdr* rule, size_t bytes);
void cp_routes_update_laddr(struct cp_session* s,
                            struct cp_route_table** tables, int af);

void cp_verify_hwport_flags(struct cp_session* s);

static inline bool cp_mac_need_refresh(cicp_mac_row_t* mrow, ci_uint64 now)
{
  return mrow->state == NUD_REACHABLE &&
         ci_frc64_after(mrow->frc_reconfirm, now);
}


static inline void
cp_calc_mac_hash(struct cp_session* s, ci_addr_t const *addr, unsigned ifindex,
                 cicp_mac_rowid_t* hash1, cicp_mac_rowid_t* hash2)
{
  cp_calc_hash(s->mac_mask, &addr_any, addr, ifindex, 0, 0, hash1, hash2);
}


static inline cicp_mac_rowid_t
cp_mac_find_row(struct cp_session* s, int af, ci_addr_t addr, ci_ifid_t ifindex)
{
  cicp_mac_rowid_t hash1, hash2, hash;
  int iter = 0;

  cp_calc_mac_hash(s, &addr, ifindex, &hash1, &hash2);
  hash = hash1;

  do {
    cicp_mac_row_t* mac = (af == AF_INET6) ? &s->ip6_mac[hash] : &s->mac[hash];
    if( mac->use == 0 )
      return CICP_MAC_ROWID_BAD;
    if( CI_IPX_ADDR_EQ(mac->addr, addr) && mac->ifindex == ifindex )
      return hash;
    hash = (hash + hash2) & s->mac_mask;
  } while( ++iter < CP_REHASH_LIMIT(s->mac_mask) );

  return CICP_MAC_ROWID_BAD;
}

static inline void
cp_bond_slave_set_hwport(cicp_bond_row_t* bond, const cicp_llap_row_t* llap)
{
  bond->slave.hwport = cp_hwport_mask_first(llap->tx_hwports);
  if( (llap->encap.type & (CICP_LLAP_TYPE_VLAN | CICP_LLAP_TYPE_BOND)) ||
      bond->slave.hwport == CI_HWPORT_ID_BAD ) {
    bond->slave.flags |= CICP_BOND_ROW_FLAG_UNSUPPORTED;
  }
  else {
    bond->slave.flags &=~ CICP_BOND_ROW_FLAG_UNSUPPORTED;
  }
}

static inline bool
cp_ready_usable(struct cp_session* s)
{
  cplane_ioctl(s->oo_fd, OO_IOC_CP_READY, NULL);
  s->stats.notify.ready++;
  return true;
}


/* Iterates over all fwd states that have been mapped in.  The function returns
 * the next table given prev, which is the previous table returned.  If prev is
 * NULL, the first table is returned.  When there are no further mapped tables,
 * the function returns NULL. */
static inline struct cp_fwd_state*
cp_fwd_state_iterate_mapped(struct cp_session* s, struct cp_fwd_state* prev)
{
  struct cp_fwd_state* fwd_state;

  if( prev == NULL )
    fwd_state = &s->__fwd_state[0];
  else
    fwd_state = prev + 1;

  /* TODO: Track the highest allocated table to give a better upper bound. */
  for( ; fwd_state - s->__fwd_state < CP_MAX_INSTANCES; ++fwd_state )
    if( fwd_state->fwd_table.rows != NULL )
      return fwd_state;

  return NULL;
}

static inline cp_fwd_table_id
cp_fwd_state_id(struct cp_session* s, struct cp_fwd_state* fwd_state)
{
  return fwd_state - &s->__fwd_state[0];
}


extern cicp_mac_rowid_t
cp_svc_add(struct cp_session* s,
           const ci_addr_sh_t addr, const ci_uint16 port);

extern cicp_mac_rowid_t
cp_svc_backend_add(struct cp_session* s, const cicp_mac_rowid_t svc_id,
                   const ci_addr_sh_t addr, const ci_uint16 port);

extern cicp_mac_rowid_t
cp_svc_del(struct cp_session* s, const cicp_mac_rowid_t rowid);

extern int
cp_svc_backend_del(struct cp_session* s, cicp_mac_rowid_t svc_id,
                   const ci_addr_sh_t ep_addr, ci_uint16 ep_port);

extern void cp_svc_erase_all(struct cp_session* s);

#endif /* __TOOLS_CPLANE_PRIVATE_H__ */
