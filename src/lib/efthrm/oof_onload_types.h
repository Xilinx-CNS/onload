/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __OOF_ONLOAD_TYPES_H__
#define __OOF_ONLOAD_TYPES_H__


#include <onload/oof_interface.h>
#include <onload/oof_hw_filter.h>
#include <onload/drv/dump_to_user.h>
#include <ci/tools.h>

#include "oof_tproxy_ipproto.h"

struct efab_tcp_driver_s;
struct net;
struct oof_manager;
struct seq_file;
struct oo_filter_ns_manager;
struct oof_nat_table;


struct oo_filter_ns {
  /* Filter handling for this net namespace */
  struct oof_manager* ofn_filter_manager;
  struct work_struct ofn_filter_work_item;

  /* Which netns this is */
  struct net* ofn_netns;

  int ofn_refcount;

  /* For use of the oo_filter_ns_manager */
  ci_dllink ofn_ofnm_link;

  /* Our parent, for when we need arbitration */
  struct oo_filter_ns_manager* ofn_ns_manager;
};


struct oo_tproxy_filter {
  struct oo_hw_filter otf_filter;
  int otf_filter_refs[CI_CFG_MAX_HWPORTS];
};


struct oo_filter_ns_manager {
  /* We maintain a list of oo_filter_ns, one per-namespace, allocated on an
   * on demand basis.  Protected by ofnm_ns_lock for reading from atomic
   * context. */
  ci_dllist ofnm_ns_list;
  spinlock_t ofnm_ns_lock;

  /* This lock protects manipulation of onm_ns_list, and changes to
   * the om_hwports_* values.
   */
  struct mutex ofnm_lock;

  /* In some circumstances, tproxies need to install protocol filters that are
   * not MAC-qualified and are required for the lifetime of any tproxy and are
   * system-global.  Because hwports may be present in more than one netns
   * we need to arbitrate between the different users of these global filters.o   *
   * We protect this list with its own mutex.  We can't use ofnm_lock, as its
   * possible for the oof_managers to want to update their tproxy filters in
   * the context of an update made while we're already holding that.
   */
  struct oo_tproxy_filter ofnm_tproxy_filters[OOF_TPROXY_GLOBAL_FILTER_COUNT];
  struct mutex ofnm_tproxy_lock;

  /* We maintain global state of hwports so that we can propogate the info
   * when new namespaces appear.
   */
  unsigned ofnm_hwports_up;
  unsigned ofnm_hwports_down;
  unsigned ofnm_hwports_avail_per_tag[OOF_HWPORT_AVAIL_TAG_NUM];
  unsigned ofnm_hwports_available;
  unsigned ofnm_hwports_mcast_replicate_capable;
  unsigned ofnm_hwports_vlan_filters;

  struct oof_nat_table* ofnm_nat_table;
};


#endif  /* __OOF_ONLOAD_TYPES_H__ */
