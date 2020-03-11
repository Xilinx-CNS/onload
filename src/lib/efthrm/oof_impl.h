/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __OOF_IMPL_H__
#define __OOF_IMPL_H__

#include <ci/tools.h>
#include <ci/internal/transport_config_opt.h>
#include <ci/net/ipvx.h>
#include <onload/oof_hw_filter.h>
#include <onload/oof_interface.h>

#include "oof_tproxy_ipproto.h"

#define OOF_LOCAL_PORT_TBL_SIZE      16
#define OOF_LOCAL_PORT_TBL_MASK      (OOF_LOCAL_PORT_TBL_SIZE - 1)

struct tcp_helper_resource_s;
struct oo_hw_filter;


/* State per protocol/local-ip/local-port triple. */
struct oof_local_port_addr {

  /* Wildcard H/W filters that demux to this addr/port/protocol, or NULL.
   *
   * If [lpa_semi_wild_socks] is non-empty, this will filter to the stack
   * of the socket at the head of the list.  If [lpa_semi_wild_socks] is
   * empty, then this will filter to the stack at the head of
   * [lp_wild_socks].
   *
   * If [lpa_semi_wild_socks] and [lp_wild_socks] are both empty then this
   * filter will be disabled.
   *
   * EXCEPT: Sometimes this h/w filter will point at the wrong stack
   * because we weren't able to (or chose not to) insert full match filters
   * for full-match sockets sharing the filter.  This should only be true
   * if [lpa_n_full_sharers > 0].
   */
  struct oo_hw_filter lpa_filter;

  /* List of [oof_socket]s that would like to receive packets from
   * [wild_filter] only.  i.e. Sockets receiving packets addressed to
   * [laddr:lport] for a single [laddr] (no those receiving to any IP).
   */
  ci_dllist lpa_semi_wild_socks;

  /* Full-match sockets bound to this local address and [lp_lport].
   * Includes sockets with their own full-match H/W filter, and ones
   * sharing [lpa_filter].
   */
  ci_dllist lpa_full_socks;

  /* List of [oof_nat_filter]s for this addr/port/protocol. */
  ci_dllist lpa_nat_filters;

  /* Number of full-match sockets sharing [lpa_filter].
   * When flag OOF_LPA_REMOVED is set no hw/sw filter insertions
   * or filter sharing is allowed. */
  int32_t lpa_n_full_sharers;
#define OOF_LPA_FLAG_REMOVED 0x1
  uint32_t lpa_flags;
};


/* There is one of these per protocol/local-port pair.  Used to coordinate
 * and manage h/w and s/w filters.
 *
 * Every socket that needs to have packets delivered to it is associated
 * with one of these.  Each oof_local_port may be associated with multiple
 * sockets, all using the same local port number (and protocol).
 */
struct oof_local_port {

  ci_uint16 lp_lport;
  ci_uint16 lp_protocol;
  ci_dllink lp_manager_link;

  /* Ref count includes all users and transient references. */
  int       lp_refs;

  /* [oof_socket]s that would like to receive any packet addressed to
   * [lp_lport].
   */
  ci_dllist lp_wild_socks;

  ci_dllist lp_mcast_filters;

  /* Per-local-address state.  Entries in this table correspond to entries
   * in [oof_manager::local_addrs].
   */
  struct oof_local_port_addr *lp_addr;
};


struct oof_local_interface {

  ci_dllink li_active_ifs_link;

  unsigned  li_ifindex;
};


struct oof_local_interface_details {

  ci_dllink lid_link;

  ci_uint16 lid_ifindex;
  ci_uint16 lid_flags; /* for now 0x1 is for interface up */
  ci_uint32 lid_hwport_mask;
  ci_uint16 lid_vlan_id;
  ci_mac_addr_t lid_mac;
};


struct oof_local_addr {
  ci_addr_t la_laddr;

  /* Number of sockets explicitly using this address (i.e. full match and
   * semi-wild).
   */
  int      la_sockets;

  /* List of ifindexes that have added this address */
  ci_dllist la_active_ifs;
};


/* Tproxy per ifindex */
struct oof_tproxy {
  struct oo_hw_filter ft_filter; /* mac filter */
  struct oo_hw_filter ft_filter_arp;
  struct oo_hw_filter ft_filter_ipproto[OOF_TPROXY_IPPROTO_FILTER_COUNT];
  int ft_ifindex;
  unsigned ft_hwport_mask;
  unsigned short ft_vlan_id;
  ci_uint8 ft_mac[6];

  ci_dllink ft_manager_link;
};


struct oof_manager {

  /* Pointer to state belonging to the code module using this module. */
  void*        fm_owner_private;

  /* Protects all state not protected by fm_cplane_updates_lock. */
  spinlock_t   fm_inner_lock;

  /* Used together with [fm_inner_lock] to ensure that calls to modify
   * hardware filters are serialised with respect to everything else.
   *
   * Hardware filter updates cannot be done in atomic context (hence
   * mutex).  But other state in this module does need to be accessed in
   * atomic context (hence spinlock).
   */
  struct mutex fm_outer_lock;

  /* The name is misleading - it really protects fm_hwports_* fields */
  spinlock_t   fm_cplane_updates_lock;

  int          fm_local_addr_n;

  /* Size of fm_local_addrs array */
  int          fm_local_addr_max;

  ci_dllist    fm_local_ports[OOF_LOCAL_PORT_TBL_SIZE];

  struct oof_local_addr* fm_local_addrs;

  /* list of local_interface_details */
  ci_dllist    fm_local_interfaces;

  ci_dllist    fm_mcast_laddr_socks;

  /* List of scalable-filter-manager structures, or "tproxies" for short. */
  ci_dllist    fm_tproxies;

  /* Track which ports we've requested tproxy global filters on.  For each
   * filter type we need to know which hwports we have a filter installed on.
   * We store this as a bitmask.
   */
  unsigned     fm_tproxy_global_filters[OOF_TPROXY_GLOBAL_FILTER_COUNT];

  /* This mask tracks which hwports are up.  Unicast filters are usually
   * installed on all interfaces that are up and mapped into the
   * corresponding stack and not unavailable (see below).
   */
  unsigned     fm_hwports_up;
  unsigned     fm_hwports_down;

  /* This mask tracks which hwports are unavailable because of various
   * reasons.
   */
  unsigned     fm_hwports_avail_per_tag[OOF_HWPORT_AVAIL_TAG_NUM];
  unsigned     fm_hwports_available;

  /* This mask tracks which hwports are capable of multicast replication.
   */
  unsigned     fm_hwports_mcast_replicate_capable;

  /* This mask tracks which hwports can by used with filters specifying a
   * VLAN.
   */
  unsigned     fm_hwports_vlan_filters;

  /* This mask tracks which hwports have been handled by
   * __oof_mcast_update_filters().
   */
  unsigned     fm_hwports_mcast_update_seen;

  /* New values of the above masks, staged here in order to resolve the
   * lock order requirements.
   *
   * Protected by [fm_cplane_updates_lock].
   */
  unsigned     fm_hwports_up_new;
  unsigned     fm_hwports_down_new;
  unsigned     fm_hwports_removed;
  unsigned     fm_hwports_avail_per_tag_new[OOF_HWPORT_AVAIL_TAG_NUM];
  unsigned     fm_hwports_mcast_replicate_capable_new;
  unsigned     fm_hwports_vlan_filters_new;

  /* Queue of oof_cplane_update objects representing changes to control
   * plane.  They are queued temporarily to be applied in a workitem in
   * order to get locking order right.
   *
   * Protected by [fm_cplane_updates_lock].
   */
  ci_dllist    fm_cplane_updates;

};


/* A multicast filter.  Shared by all sockets in a stack that have
 * subscribed to a particular {maddr, port, vlan}.
 */
struct oof_mcast_filter {

  struct oo_hw_filter mf_filter;

  unsigned            mf_maddr;

  /* Union of the physical interfaces wanted by the [mf_memberships]. */
  unsigned            mf_hwport_mask;

  /* Link for [oof_local_port::lp_mcast_filters]. */
  ci_dllink           mf_lp_link;

  ci_dllist           mf_memberships;

  ci_uint16           mf_vlan_id;

};


/* A multicast group membership (or subscription if you like).  A
 * bi-directional link between oof_socket and oof_mcast_filter.
 */
struct oof_mcast_member {

  /* The filter, or NULL if the socket does not yet have filters installed. */
  struct oof_mcast_filter* mm_filter;

  /* The owning socket. */
  struct oof_socket*       mm_socket;

  /* Multicast address.  (Needed here for when [mm_filter] is NULL). */
  unsigned                 mm_maddr;

  /* Master ifindex that uses this filter. In case of bonds, VLANs etc
   * it will be the master interface rather than any of the slaves 
   */
  int                      mm_ifindex;

  /* The physical interfaces underlying [mm_ifindex]. */
  unsigned                 mm_hwport_mask;

  /* Link for [struct oof_socket::sf_mcast_memberships]. */
  ci_dllink                mm_socket_link;

  /* Link for [struct oof_mcast_filter::mf_memberships]. */
  ci_dllink                mm_filter_link;

  /* The vlan id of [mm_ifindex]. */
  ci_uint16                mm_vlan_id;

};


struct oof_nat_table {
  ci_uint32    nattbl_size;
  ci_dllist*   nattbl_buckets;
  spinlock_t   nattbl_lock;

  /* This is the logical number of entries in the table: that is, even NAT
   * mappings that require two insertions in the table (which is the common
   * case) are counted as one. */
  int          nattbl_entries;

  /* To avoid having to allocate memory in atomic context, we allocate storage
   * for an oof_nat_filter at the point at which an entry is added to the NAT
   * table, and stash it in this list.  When an OOF instance decides it needs
   * to install a filter for a NAT entry, it grabs an entry from the list. */
  ci_dllist    nattbl_filter_storage_list;
  int          nattbl_filter_storage_count;
};


struct oof_nat_table_entry {
  ci_dllink link;
  ci_addr_t orig_addr;
  ci_addr_t xlated_addr;
  ci_uint16 orig_port;
  ci_uint16 xlated_port;
  /* Each logical entry is added to (at most) two buckets.  This is a link to
   * the entry in the other bucket, or is NULL in the case where the entry is
   * in one bucket only. */
  struct oof_nat_table_entry* dual_entry;
};


/* Arbitrary limit for the number of NAT results that we will report for a
 * given address:port query. */
#define OOF_NAT_LOOKUP_RESULTS_MAX 256

struct oof_nat_lookup_result_entry {
  ci_addr_t orig_addr;
  ci_uint16 orig_port;
};

struct oof_nat_lookup_result {
  /* The idea here is to avoid kmalloc() calls in atomic context.  We embed a
   * little bit of scratch space in the structure itself, which we expect
   * callers to have allocated on the stack.  The results member can point
   * either to scratch_space to a kmalloc()ed blob.  oof_nat_table_lookup()
   * will try to use the scratch space first, and will fall back to dynamic
   * allocation if there's not enough room.  In practice, we almost always
   * expect at most one result, so the size of 4 for the scratch space should
   * only be exceeded in deliberately perverse configurations. */
  struct oof_nat_lookup_result_entry scratch_space[4], *results;
  int n_results;
};


struct oof_nat_filter {
  ci_dllink link;
  struct oo_hw_filter natf_hwfilter;
  ci_addr_t orig_addr;
  ci_uint16 orig_port;
};


#endif  /* __OOF_IMPL_H__ */
