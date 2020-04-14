/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* Driver-specific cplane interface. */
#ifndef __ONLOAD_CPLANE_DRIVER_H__
#define __ONLOAD_CPLANE_DRIVER_H__

#include <linux/mm.h>
#include <linux/poll.h>

#define DEFAULT_CPLANE_SERVER_PATH "/sbin/onload_cp_server"

extern int oo_cplane_mmap(struct file* file, struct vm_area_struct* vma);
extern ssize_t cp_fop_read(struct file *filp, char __user *buf,
                           size_t len, loff_t *off);
extern unsigned cp_fop_poll(struct file* filp, poll_table* wait);

struct ci_private_s;
struct oo_cplane_handle;
extern int oo_cp_get_mib_size(struct ci_private_s *priv, void *arg);
extern int oo_cp_fwd_resolve_rsop(struct ci_private_s *priv, void *arg);
extern int oo_cp_fwd_resolve_complete(struct ci_private_s *priv, void *arg);
extern int oo_cp_arp_resolve_rsop(struct ci_private_s *priv, void *arg);
extern int oo_cp_arp_confirm_rsop(struct ci_private_s *priv, void *arg);
extern int oo_cp_get_active_hwport_mask(struct oo_cplane_handle* cp,
                                        ci_ifid_t ifindex,
                                        cicp_hwport_mask_t *hwport_mask);
extern int oo_cp_driver_ctor(void);
extern int oo_cp_driver_dtor(void);

enum cp_sync_mode;
extern struct oo_cplane_handle*
cp_acquire_and_sync(struct net* netns, enum cp_sync_mode mode);
extern struct oo_cplane_handle*
cp_acquire_from_netns_if_exists(const struct net* netns);
extern void cp_release(struct oo_cplane_handle* cp);

extern int
cp_acquire_from_priv_if_server(struct ci_private_s* priv,
                               struct oo_cplane_handle** out);

struct cicppl_instance;
extern int /* rc */
cicpplos_ctor(struct cicppl_instance* cppl);
extern void
cicpplos_dtor(struct cicppl_instance *cppl);

enum cp_sync_mode;
extern int oo_cp_wait_for_server(struct oo_cplane_handle* cp,
                                 enum cp_sync_mode mode);
extern int oo_cp_wait_for_server_rsop(struct ci_private_s*, void* arg);
extern int oo_cp_link_rsop(struct ci_private_s*, void* arg);
extern int oo_cp_ready(struct ci_private_s*, void* version);
extern int oo_cp_check_version(struct ci_private_s*, void* arg);


extern int oo_cp_get_server_pid(struct oo_cplane_handle* cp);
extern int oo_cp_llap_change_notify_all(struct oo_cplane_handle* main_cp);
extern int oo_cp_oof_sync(struct oo_cplane_handle* cp);
extern int
oo_cp_check_veth_acceleration(struct oo_cplane_handle* cp, ci_ifid_t ifindex);
extern int
oo_cp_select_instance(struct ci_private_s* priv,
                      enum oo_op_cp_select_instance inst);
extern int oo_cp_init_kernel_mibs(struct oo_cplane_handle* cp,
                                  cp_fwd_table_id* fwd_table_id_out);

struct ci_netif_s;
extern void
cicp_kernel_resolve(struct ci_netif_s* ni, struct oo_cplane_handle* cp,
                    struct cp_fwd_key* key,
                    struct cp_fwd_data* data);

extern int
__cp_announce_hwport(struct oo_cplane_handle* cp, ci_ifid_t ifindex,
                     ci_hwport_id_t hwport, ci_uint64 nic_flags);
struct efhw_nic;
extern int
cp_announce_hwport(const struct efhw_nic* nic, ci_hwport_id_t hwport);

extern int oo_nic_announce(struct oo_cplane_handle* cp, ci_ifid_t);

#endif /* __ONLOAD_CPLANE_DRIVER_H__ */
