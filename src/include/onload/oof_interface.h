/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_OOF_INTERFACE_H__
#define __ONLOAD_OOF_INTERFACE_H__

#include <ci/internal/transport_config_opt.h>
#include <cplane/mib.h> /* for ci_hwport_id_t */
#include <ci/net/ipvx.h>

struct tcp_helper_resource_s;
struct oof_socket;
struct oof_manager;
struct oo_hw_filter;
struct tcp_helper_cluster_s;
struct oo_hw_filter_spec;


#define OO_IFID_ALL (-2)

enum {
  /* Members of an unacceleratable bond.  ie. Filters should not be used
   * with unavailable hwports because traffic arriving on them goes via the
   * kernel stack. */
  OOF_HWPORT_AVAIL_TAG_BOND,
  /* Hwports in the network namespace of this oof_manager. */
  OOF_HWPORT_AVAIL_TAG_NAMESPACE,
  /* Number of tags */
  OOF_HWPORT_AVAIL_TAG_NUM,
};


/**********************************************************************
 * The oof module interface.
 */

extern int oof_shared_keep_thresh;
extern int oof_shared_steal_thresh;
extern int oof_all_ports_required;
extern int oof_use_all_local_ip_addresses;

extern struct oof_manager*
oof_manager_alloc(unsigned local_addr_max, void* owner_private);

extern void
oof_manager_free(struct oof_manager*);

extern void
oof_manager_addr_add(struct oof_manager*, int af, ci_addr_t laddr,
                     unsigned ifindex);

extern void
oof_manager_addr_del(struct oof_manager*, int af, ci_addr_t laddr,
                     unsigned ifindex);

extern int
oof_manager_dnat_add(struct oof_manager* fm, int af, ci_uint16 lp_protocol,
                     const ci_addr_t orig_addr, ci_uint16 orig_port,
                     const ci_addr_t xlated_addr, ci_uint16 xlated_port);

extern void
oof_manager_dnat_del(struct oof_manager* fm, ci_uint16 lp_protocol,
                     const ci_addr_t orig_addr, ci_uint16 orig_port);

extern void
oof_manager_dnat_reset(struct oof_manager* fm, ci_uint16 lp_protocol);

extern void
oof_hwport_up_down(struct oof_manager* fm, int hwport, int up,
                   int mcast_replicate_capable, int vlan_filters, int sync);

extern void
oof_hwport_removed(struct oof_manager* fm, int hwport);

extern void
oof_hwport_un_available(ci_hwport_id_t hwport, int available, int tag,
                        void *arg);

extern void
oof_do_deferred_work(struct oof_manager*);

extern void
oof_socket_ctor(struct oof_socket*);

extern void
oof_socket_dtor(struct oof_socket*);


extern int
oof_socket_is_armed(struct oof_socket* skf);

#define OOF_SOCKET_ADD_FLAG_CLUSTERED 0x1
#define OOF_SOCKET_ADD_FLAG_DUMMY     0x2
#define OOF_SOCKET_ADD_FLAG_NO_STACK  0x4
#define OOF_SOCKET_ADD_FLAG_NO_UCAST  0x8
extern int
oof_socket_add(struct oof_manager*, struct oof_socket*,
               int flags, int protocol, int af_space,
               ci_addr_t laddr, int lport,
               ci_addr_t raddr, int rport,
               struct tcp_helper_cluster_s** thc_out);

extern int
oof_socket_replace(struct oof_manager* fm,
                   struct oof_socket* old_skf, struct oof_socket* skf);

extern int
oof_socket_can_update_stack(struct oof_manager* fm, struct oof_socket* skf,
                            struct tcp_helper_resource_s* thr);

extern void
oof_socket_update_sharer_details(struct oof_manager*, struct oof_socket*,
                                 ci_addr_t raddr, int rport);

extern int
oof_socket_share(struct oof_manager*, struct oof_socket* skf,
                 struct oof_socket* listen_skf, int af_space,
                 ci_addr_t laddr, ci_addr_t raddr, int lport, int rport);

extern void
oof_socket_del(struct oof_manager*, struct oof_socket*);

extern int
oof_socket_del_sw(struct oof_manager*, struct oof_socket*);

extern int
oof_udp_connect(struct oof_manager*, struct oof_socket*, int af_space,
                ci_addr_t laddr, ci_addr_t raddr, int rport);

extern int
oof_socket_mcast_add(struct oof_manager*, struct oof_socket*,
                     unsigned maddr, int ifindex);

extern void
oof_socket_mcast_del(struct oof_manager*, struct oof_socket*,
                     unsigned maddr, int ifindex);

extern void
oof_socket_mcast_del_all(struct oof_manager*, struct oof_socket*);

extern void
oof_mcast_update_interface(ci_ifid_t ifindex,  ci_uint16 flags,
                           cicp_hwport_mask_t hwport_mask,
                           ci_uint16 vlan_id, ci_mac_addr_t mac, void *arg);

extern void
oof_mcast_update_filters(ci_ifid_t ifindex, void *arg);

extern int
oof_tproxy_install(struct oof_manager* fm,
                   struct tcp_helper_resource_s* trs,
                   struct tcp_helper_cluster_s* thc, int ifindex);

extern int
oof_tproxy_free(struct oof_manager* fm,
                struct tcp_helper_resource_s* trs,
                struct tcp_helper_cluster_s* thc,
                int ifindex);

extern int
oof_tproxy_update_filters(struct oof_manager* fm, int ifindex);

extern void
oof_socket_dump(struct oof_manager*, struct oof_socket*,
                void (*dump_fn)(void* opaque, const char* fmt, ...),
                void* opaque);

extern void
oof_manager_dump(struct oof_manager*,
                 void (*dump_fn)(void* opaque, const char* fmt, ...),
                 void* opaque);

extern int
oof_is_onloaded(struct oof_manager* fm, int ifindex);
/**********************************************************************
 * Callbacks.  These are invoked by the oof module.
 */

extern struct tcp_helper_resource_s*
oof_cb_socket_stack(struct oof_socket* skf);

extern struct tcp_helper_cluster_s*
oof_cb_stack_thc(struct tcp_helper_resource_s* skf_stack);

extern void
oof_cb_thc_ref(struct tcp_helper_cluster_s* thc);

extern const char*
oof_cb_thc_name(struct tcp_helper_cluster_s* thc);

extern int
oof_cb_socket_id(struct oof_socket* skf);

extern int
oof_cb_stack_id(struct tcp_helper_resource_s*);

extern void
oof_cb_callback_set_filter(struct oof_socket* skf);

extern int
oof_cb_sw_filter_insert(struct oof_socket* skf, int af,
                        const ci_addr_t laddr, int lport,
                        const ci_addr_t raddr, int rport,
                        int protocol, int stack_locked);


extern void
oof_cb_sw_filter_remove(struct oof_socket* skf, int af,
                        const ci_addr_t laddr, int lport,
                        const ci_addr_t raddr, int rport,
                        int protocol, int stack_locked);

struct ci_netif_s;
extern void oof_cb_sw_filter_apply(struct ci_netif_s* ni);

extern void
oof_dl_filter_set(struct oo_hw_filter* filter, int stack_id, int protocol,
                  ci_addr_t saddr, int sport, ci_addr_t daddr, int dport);

extern void
oof_dl_filter_del(struct oo_hw_filter* filter);

extern int 
oof_cb_get_hwport_mask(int ifindex, cicp_hwport_mask_t *hwport_mask, void* owner_priv);

extern int 
oof_cb_get_vlan_id(int ifindex, unsigned short *vlan_id, void* owner_priv);

extern int
oof_cb_get_mac(int ifindex, unsigned char mac[6], void* owner_priv);

extern void
oof_cb_defer_work(void* owner_private);

#ifdef EFRM_NET_HAS_USER_NS
extern struct user_namespace*
oof_cb_user_ns(void* owner_private);
#endif

extern struct oof_nat_table* oof_cb_nat_table(void* owner_private);

extern int
oof_hwports_list(struct oof_manager* fm, struct seq_file* seq);
extern int
oof_ipaddrs_list(struct oof_manager* fm, struct seq_file* seq);

extern int
oof_cb_add_global_tproxy_filter(struct oo_hw_filter_spec* filter, int proto,
                                unsigned hwport_mask,
                                unsigned* installed_hwport_mask,
                                void* owner_priv);
extern int
oof_cb_remove_global_tproxy_filter(int proto, unsigned hwport_mask,
                                   unsigned* installed_hwport_mask,
                                   void* owner_priv);

#endif  /* __ONLOAD_OOF_INTERFACE_H__ */
