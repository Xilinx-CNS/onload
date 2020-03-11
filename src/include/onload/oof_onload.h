/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_OOF_ONLOAD_H__
#define __ONLOAD_OOF_ONLOAD_H__


#include <onload/oof_interface.h>
#include <onload/drv/dump_to_user.h>
#include <ci/tools.h>
#include <ci/net/ipvx.h>


struct efab_tcp_driver_s;
struct net;
struct oof_manager;
struct seq_file;


extern int oo_filter_ns_manager_ctor(struct efab_tcp_driver_s*);
extern void oo_filter_ns_manager_dtor(struct efab_tcp_driver_s*);


extern struct oo_filter_ns* oo_filter_ns_get(struct efab_tcp_driver_s*,
                                             struct net*, int* oof_preexisted);
extern void oo_filter_ns_put(struct efab_tcp_driver_s*,
                             struct oo_filter_ns* ofn);

/* atomic context safe functions */
extern void __oo_filter_ns_get(struct efab_tcp_driver_s*, struct oo_filter_ns* fns);
extern struct oo_filter_ns* oo_filter_ns_lookup(struct efab_tcp_driver_s*,
                                                struct net*);
extern void oo_filter_ns_put_atomic(struct efab_tcp_driver_s* drv,
                                    struct oo_filter_ns* fns);

extern void oof_onload_on_cplane_ipadd(int af, ci_addr_t net_ip, ci_ifid_t ifindex,
                                       struct net* netns, void* arg);
extern void oof_onload_on_cplane_ipdel(int af, ci_addr_t net_ip, ci_ifid_t ifindex,
                                       struct net* netns, void* arg);
extern void
oof_onload_mcast_update_interface(ci_ifid_t ifindex, ci_uint16 flags,
                                  ci_uint32 hwport_mask,
                                  ci_uint16 vlan_id, ci_mac_addr_t mac,
                                  struct net* netns, void *arg);
extern void oof_onload_mcast_update_filters(ci_ifid_t ifindex,
                                            struct net* netns, void *arg);
extern void oof_onload_hwport_removed(struct efab_tcp_driver_s*, int hwport);
extern void oof_onload_hwport_up_down(struct efab_tcp_driver_s*, int hwport,
                                      int up, int mcast_replicate_capable,
                                      int vlan_filters, int sync);

extern int
oof_onload_dnat_add(struct efab_tcp_driver_s*, const ci_addr_t orig_addr,
                    ci_uint16 orig_port, const ci_addr_t xlated_addr,
                    ci_uint16 xlated_port);

extern void
oof_onload_dnat_del(struct efab_tcp_driver_s*, const ci_addr_t orig_addr,
                    ci_uint16 orig_port);

extern void oof_onload_dnat_reset(struct efab_tcp_driver_s*);

extern void oof_onload_manager_dump(struct efab_tcp_driver_s*,
                                    oo_dump_log_fn_t log, void* log_arg);
extern void oof_onload_socket_dump(struct efab_tcp_driver_s*,
                         struct oof_socket*,
                         void (*dump_fn)(void* opaque, const char* fmt, ...),
                         void* opaque);
extern int oof_onload_hwports_list(struct efab_tcp_driver_s*,
                                   struct seq_file* seq);
extern int oof_onload_ipaddrs_list(struct efab_tcp_driver_s*,
                                   struct seq_file* seq);

extern struct oof_manager* oo_filter_ns_to_manager(struct oo_filter_ns* ofn);
extern struct net* oo_filter_ns_to_netns(struct oo_filter_ns* ofn);

extern int oo_filter_ns_add_global_tproxy_filter(struct oo_filter_ns* ofn,
                                              struct oo_hw_filter_spec* filter,
                                              int proto, unsigned hwport_mask,
                                              unsigned* installed_hwport_mask);
extern int oo_filter_ns_remove_global_tproxy_filter(struct oo_filter_ns* ofn,
                                              int proto, unsigned hwport_mask,
                                              unsigned* installed_hwport_mask);

#endif  /* __ONLOAD_OOF_ONLOAD_H__ */
