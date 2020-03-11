/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* Stuff that connects the oof module and the rest of onload. */

#include <onload/tcp_driver.h>
#include <onload/oof_onload.h>
#include <onload/oof_nat.h>

#include "oof_onload_types.h"
#include "oo_hw_filter.h"

#define skf_to_ep(skf)  CI_CONTAINER(tcp_helper_endpoint_t, oofilter, (skf))
#define skf_to_ni(skf)  (&skf_to_ep(skf)->thr->netif)

void oof_onload_on_cplane_ipadd(int af, ci_addr_t net_ip, ci_ifid_t ifindex,
                                struct net* netns, void* arg)
{
  struct oo_filter_ns* fns = oo_filter_ns_lookup(arg, netns);

  ci_assert(memcmp(&net_ip, &addr_any, sizeof(net_ip)));

  if( fns ) {
    oof_manager_addr_add(fns->ofn_filter_manager, af, net_ip, ifindex);
    oo_filter_ns_put(arg, fns);
  }
}


void oof_onload_on_cplane_ipdel(int af, ci_addr_t net_ip, ci_ifid_t ifindex,
                                struct net* netns, void* arg)
{
  struct oo_filter_ns* fns = oo_filter_ns_lookup(arg, netns);

  ci_assert(memcmp(&net_ip, &addr_any, sizeof(net_ip)));

  if( fns ) {
    oof_manager_addr_del(fns->ofn_filter_manager, af, net_ip, ifindex);
    oo_filter_ns_put(arg, fns);
  }
}


extern void
oof_onload_mcast_update_interface(ci_ifid_t ifindex, ci_uint16 flags,
                                  ci_uint32 hwport_mask,
                                  ci_uint16 vlan_id, ci_mac_addr_t mac,
                                  struct net* netns, void *arg)
{
  struct efab_tcp_driver_s* drv = (struct efab_tcp_driver_s*)arg;
  struct oo_filter_ns* fns = oo_filter_ns_lookup(drv, netns);

  if( fns ) {
    oof_mcast_update_interface(ifindex, flags, hwport_mask, vlan_id, mac,
                               fns->ofn_filter_manager);
    oo_filter_ns_put(arg, fns);
  }
}


extern void
oof_onload_mcast_update_filters(ci_ifid_t ifindex, struct net* netns,
                                void *arg)
{
  struct efab_tcp_driver_s* drv = (struct efab_tcp_driver_s*)arg;
  struct oo_filter_ns* fns = oo_filter_ns_lookup(drv, netns);

  if( fns ) {
    oof_mcast_update_filters(ifindex, fns->ofn_filter_manager);
    oo_filter_ns_put(arg, fns);
  }
}


void oof_onload_hwport_removed(efab_tcp_driver_t* drv, int hwport)
{
  struct oo_filter_ns* fns;
  ci_dllink* link;

  mutex_lock(&drv->filter_ns_manager->ofnm_lock);

  drv->filter_ns_manager->ofnm_hwports_up &= ~(1 << hwport);
  drv->filter_ns_manager->ofnm_hwports_down |= 1 << hwport;

  CI_DLLIST_FOR_EACH(link, &drv->filter_ns_manager->ofnm_ns_list) {
    fns = CI_CONTAINER(struct oo_filter_ns, ofn_ofnm_link, link);
    oof_hwport_removed(fns->ofn_filter_manager, hwport);
  }
  mutex_unlock(&drv->filter_ns_manager->ofnm_lock);
}


void oof_onload_hwport_up_down(efab_tcp_driver_t* drv, int hwport, int up,
                               int mcast_replicate_capable, int vlan_filters,
                               int sync)
{
  struct oo_filter_ns* fns;
  struct oo_filter_ns_manager* manager = drv->filter_ns_manager;
  ci_dllink* link;

  mutex_lock(&manager->ofnm_lock);

  mcast_replicate_capable = !! mcast_replicate_capable;
  vlan_filters = !! vlan_filters;

  if( up ) {
    /* Reset hwport capabilities when bringing it up */
    manager->ofnm_hwports_mcast_replicate_capable &= ~(1 << hwport);
    manager->ofnm_hwports_vlan_filters &= ~(1 << hwport);

    /* Now mark it up and set capabilities based on new information */
    manager->ofnm_hwports_up |= 1 << hwport;
    manager->ofnm_hwports_down &= ~(1 << hwport);
    manager->ofnm_hwports_mcast_replicate_capable |=
                                           mcast_replicate_capable << hwport;
    manager->ofnm_hwports_vlan_filters |= vlan_filters << hwport;
  }
  else {
    manager->ofnm_hwports_up &= ~(1 << hwport);
    manager->ofnm_hwports_down |= 1 << hwport;
  }

  CI_DLLIST_FOR_EACH(link, &manager->ofnm_ns_list) {
    fns = CI_CONTAINER(struct oo_filter_ns, ofn_ofnm_link, link);
    oof_hwport_up_down(fns->ofn_filter_manager, hwport, up,
                       mcast_replicate_capable, vlan_filters, sync);
  }
  mutex_unlock(&manager->ofnm_lock);
}


int oof_onload_dnat_add(efab_tcp_driver_t* drv, const ci_addr_t orig_addr,
                        ci_uint16 orig_port, const ci_addr_t xlated_addr,
                        ci_uint16 xlated_port)
{
  struct oo_filter_ns* fns;
  int rc, af;

  rc = oof_nat_table_add(drv->filter_ns_manager->ofnm_nat_table, orig_addr,
                         orig_port, xlated_addr, xlated_port);
  if( rc != 0)
    return rc;

  af = CI_IS_ADDR_IP6(xlated_addr) ? AF_INET6 : AF_INET;
  mutex_lock(&drv->filter_ns_manager->ofnm_lock);
  CI_DLLIST_FOR_EACH2(struct oo_filter_ns, fns, ofn_ofnm_link,
                      &drv->filter_ns_manager->ofnm_ns_list) {
    rc = oof_manager_dnat_add(fns->ofn_filter_manager, af, IPPROTO_TCP,
                              orig_addr, orig_port,
                              xlated_addr, xlated_port);
    if( rc != 0 )
      break;
  }
  mutex_unlock(&drv->filter_ns_manager->ofnm_lock);

  if( rc != 0 )
    oof_onload_dnat_del(drv, orig_addr, orig_port);

  return rc;
}


void oof_onload_dnat_del(efab_tcp_driver_t* drv, const ci_addr_t orig_addr,
                         ci_uint16 orig_port)
{
  struct oo_filter_ns* fns;

  oof_nat_table_del(drv->filter_ns_manager->ofnm_nat_table, orig_addr,
                    orig_port);

  mutex_lock(&drv->filter_ns_manager->ofnm_lock);
  CI_DLLIST_FOR_EACH2(struct oo_filter_ns, fns, ofn_ofnm_link,
                      &drv->filter_ns_manager->ofnm_ns_list) {
    oof_manager_dnat_del(fns->ofn_filter_manager, IPPROTO_TCP,
                         orig_addr, orig_port);
  }
  mutex_unlock(&drv->filter_ns_manager->ofnm_lock);
}


void oof_onload_dnat_reset(efab_tcp_driver_t* drv)
{
  struct oo_filter_ns* fns;

  oof_nat_table_reset(drv->filter_ns_manager->ofnm_nat_table);

  mutex_lock(&drv->filter_ns_manager->ofnm_lock);
  CI_DLLIST_FOR_EACH2(struct oo_filter_ns, fns, ofn_ofnm_link,
                      &drv->filter_ns_manager->ofnm_ns_list) {
    oof_manager_dnat_reset(fns->ofn_filter_manager, IPPROTO_TCP);
  }
  mutex_unlock(&drv->filter_ns_manager->ofnm_lock);
}


static void oof_do_deferred_work_fn(struct work_struct *data)
{
  struct oo_filter_ns* fns = container_of(data, struct oo_filter_ns,
                                          ofn_filter_work_item);
  oof_do_deferred_work(fns->ofn_filter_manager);
  /* XXX: This is a layer violation: Other callers of oo_filter_ns_put() take
   * an argument specifying the driver, but that's not straightforward on the
   * workqueue. */
  oo_filter_ns_put(&efab_tcp_driver, fns);
}


void oof_onload_manager_dump(struct efab_tcp_driver_s* drv,
                             oo_dump_log_fn_t log, void* log_arg)
{
  struct oo_filter_ns* fns;
  ci_dllink* link;

  mutex_lock(&drv->filter_ns_manager->ofnm_lock);
  CI_DLLIST_FOR_EACH(link, &drv->filter_ns_manager->ofnm_ns_list) {
    fns = CI_CONTAINER(struct oo_filter_ns, ofn_ofnm_link, link);
    oof_manager_dump(fns->ofn_filter_manager, log, log_arg);
  }
  oof_nat_table_dump(drv->filter_ns_manager->ofnm_nat_table, log, log_arg);
  mutex_unlock(&drv->filter_ns_manager->ofnm_lock);
}


void oof_onload_socket_dump(struct efab_tcp_driver_s* drv,
                            struct oof_socket* skf,
                            void (*dump_fn)(void* opaque,const char* fmt,...),
                            void* opaque)
{
  struct oo_filter_ns* fns;
  ci_dllink* link;

  mutex_lock(&drv->filter_ns_manager->ofnm_lock);
  CI_DLLIST_FOR_EACH(link, &drv->filter_ns_manager->ofnm_ns_list) {
    fns = CI_CONTAINER(struct oo_filter_ns, ofn_ofnm_link, link);
    oof_socket_dump(fns->ofn_filter_manager, skf, dump_fn, opaque);
  }
  mutex_unlock(&drv->filter_ns_manager->ofnm_lock);
}


int oof_onload_hwports_list(struct efab_tcp_driver_s* drv,
                            struct seq_file* seq)
{
  struct oo_filter_ns* fns;
  ci_dllink* link;

  mutex_lock(&drv->filter_ns_manager->ofnm_lock);
  CI_DLLIST_FOR_EACH(link, &drv->filter_ns_manager->ofnm_ns_list) {
    fns = CI_CONTAINER(struct oo_filter_ns, ofn_ofnm_link, link);
    oof_hwports_list(fns->ofn_filter_manager, seq);
  }
  mutex_unlock(&drv->filter_ns_manager->ofnm_lock);

  return 0;
}



int oof_onload_ipaddrs_list(struct efab_tcp_driver_s* drv,
                            struct seq_file* seq)
{
/* FIXME SCJ OOF fix return */
  struct oo_filter_ns* fns;
  ci_dllink* link;

  mutex_lock(&drv->filter_ns_manager->ofnm_lock);
  CI_DLLIST_FOR_EACH(link, &drv->filter_ns_manager->ofnm_ns_list) {
    fns = CI_CONTAINER(struct oo_filter_ns, ofn_ofnm_link, link);
    oof_ipaddrs_list(fns->ofn_filter_manager, seq);
  }
  mutex_unlock(&drv->filter_ns_manager->ofnm_lock);

  return 0;
}


static void
oof_onload_init_hwport_state_locked(struct oo_filter_ns_manager* manager,
                                    struct oo_filter_ns* fns)
{
  int i;

  ci_assert_equal(manager->ofnm_hwports_up & manager->ofnm_hwports_down, 0);

  for( i = 0; i < (sizeof(manager->ofnm_hwports_up) * 8); i++ ) {
    if( manager->ofnm_hwports_up & (1 << i) ) {
      oof_hwport_up_down(fns->ofn_filter_manager, i, 1,
                      manager->ofnm_hwports_mcast_replicate_capable & (1 << i),
                      manager->ofnm_hwports_vlan_filters & (1 << i), 1);
    }
    else if( manager->ofnm_hwports_down & (1 << i) ) {
      oof_hwport_up_down(fns->ofn_filter_manager, i, 0,
                      manager->ofnm_hwports_mcast_replicate_capable & (1 << i),
                      manager->ofnm_hwports_vlan_filters & (1 << i), 1);
    }
  }
}


static struct oo_filter_ns* oo_filter_ns_ctor_locked(efab_tcp_driver_t* drv,
                                                     struct net* netns)
{
  struct oo_filter_ns* fns = CI_ALLOC_OBJ(struct oo_filter_ns);
  if( !fns )
    return NULL;

  fns->ofn_filter_manager = oof_manager_alloc(CI_CFG_MAX_LOCAL_IPADDRS, fns);
  if( fns->ofn_filter_manager == NULL ) {
    CI_FREE_OBJ(fns);
    return NULL;
  }

  fns->ofn_ns_manager = drv->filter_ns_manager;
  INIT_WORK(&fns->ofn_filter_work_item, oof_do_deferred_work_fn);
  fns->ofn_netns = netns;
  get_net(fns->ofn_netns);
  fns->ofn_refcount = 1;
  spin_lock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
  ci_dllist_push_tail(&drv->filter_ns_manager->ofnm_ns_list,
                      &fns->ofn_ofnm_link);
  spin_unlock_bh(&drv->filter_ns_manager->ofnm_ns_lock);

  oof_onload_init_hwport_state_locked(drv->filter_ns_manager, fns);

  return fns;
}


/* [ofnm_ns_lock, efnm_ns_lock] must be held at entry, and is never held at exit. */
static void oo_filter_ns_dtor(efab_tcp_driver_t* drv,
                              struct oo_filter_ns* fns)
{
  ci_assert_equal(fns->ofn_refcount, 0);
  ci_assert(spin_is_locked(&drv->filter_ns_manager->ofnm_ns_lock));
  ci_assert(mutex_is_locked(&drv->filter_ns_manager->ofnm_lock));

  ci_dllist_remove(&fns->ofn_ofnm_link);

  /* Now that we've removed [fns] from the list, we can drop the locks. */
  spin_unlock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
  mutex_unlock(&drv->filter_ns_manager->ofnm_lock);

  oof_manager_free(fns->ofn_filter_manager);
  put_net(fns->ofn_netns);
  CI_FREE_OBJ(fns);

  /* Exit without the lock. */
}


int oo_filter_ns_manager_ctor(efab_tcp_driver_t* drv)
{
  /* This is the size of the NAT table, which is a hash table with chaining.
   * In practice it's used for Kubernetes services with exactly one local
   * pod, so 1024 is more than large enough. */
  const ci_uint32 NAT_TABLE_SIZE = 1024;

  int rc = -ENOMEM;
  int i;
  ci_assert(!drv->filter_ns_manager);
  drv->filter_ns_manager = CI_ALLOC_OBJ(struct oo_filter_ns_manager);

  if( !drv->filter_ns_manager )
    goto fail1;

  CI_ZERO(drv->filter_ns_manager);

  ci_dllist_init(&drv->filter_ns_manager->ofnm_ns_list);
  mutex_init(&drv->filter_ns_manager->ofnm_lock);
  mutex_init(&drv->filter_ns_manager->ofnm_tproxy_lock);
  spin_lock_init(&drv->filter_ns_manager->ofnm_ns_lock);

  for( i = 0; i < OOF_TPROXY_GLOBAL_FILTER_COUNT; ++i ) {
    struct oo_tproxy_filter* otp;
    otp = &drv->filter_ns_manager->ofnm_tproxy_filters[i];

    oo_hw_filter_init(&otp->otf_filter);
    memset(otp->otf_filter_refs, 0, sizeof(otp->otf_filter_refs));
  }

  drv->filter_ns_manager->ofnm_nat_table = oof_nat_table_alloc(NAT_TABLE_SIZE);
  if( drv->filter_ns_manager->ofnm_nat_table == NULL )
    goto fail2;

  return 0;

 fail2:
  CI_FREE_OBJ(drv->filter_ns_manager);
 fail1:
  return rc;
}


void oo_filter_ns_manager_dtor(efab_tcp_driver_t* drv)
{
  if( drv->filter_ns_manager == NULL )
    return;

  ci_assert(ci_dllist_is_empty(&drv->filter_ns_manager->ofnm_ns_list));

  oof_nat_table_free(drv->filter_ns_manager->ofnm_nat_table);
  mutex_destroy(&drv->filter_ns_manager->ofnm_tproxy_lock);
  mutex_destroy(&drv->filter_ns_manager->ofnm_lock);
  CI_FREE_OBJ(drv->filter_ns_manager);
}


extern void __oo_filter_ns_get(efab_tcp_driver_t* drv, struct oo_filter_ns* fns)
{
  spin_lock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
  fns->ofn_refcount++;
  spin_unlock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
}


struct oo_filter_ns* oo_filter_ns_lookup(efab_tcp_driver_t* drv,
                                         struct net* netns)
{
  ci_dllink* link;
  spin_lock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
  CI_DLLIST_FOR_EACH(link, &drv->filter_ns_manager->ofnm_ns_list) {
    struct oo_filter_ns* fns =
        CI_CONTAINER(struct oo_filter_ns, ofn_ofnm_link, link);
    if( fns->ofn_netns == netns && fns->ofn_refcount > 0 ) {
      fns->ofn_refcount++;
      spin_unlock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
      return fns;
    }
  }
  spin_unlock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
  return NULL;
}


struct oo_filter_ns* oo_filter_ns_get(efab_tcp_driver_t* drv,
                                      struct net* netns, int* oof_preexisted)
{
  struct oo_filter_ns* fns;

  mutex_lock(&drv->filter_ns_manager->ofnm_lock);
  fns = oo_filter_ns_lookup(drv, netns);

  *oof_preexisted = fns != NULL;
  if( fns == NULL )
    fns = oo_filter_ns_ctor_locked(drv, netns);
  mutex_unlock(&drv->filter_ns_manager->ofnm_lock);

  return fns;
}


void oo_filter_ns_put(efab_tcp_driver_t* drv, struct oo_filter_ns* fns)
{
  mutex_lock(&drv->filter_ns_manager->ofnm_lock);
  spin_lock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
  ci_assert(ci_dllist_is_member(&drv->filter_ns_manager->ofnm_ns_list,
                                &fns->ofn_ofnm_link));
  ci_assert_gt(fns->ofn_refcount, 0);
  fns->ofn_refcount--;
  if( fns->ofn_refcount == 0 ) {
    oo_filter_ns_dtor(drv, fns);
  }
  else {
    spin_unlock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
    mutex_unlock(&drv->filter_ns_manager->ofnm_lock);
  }
  /* oo_filter_ns_dtor() drops the locks itself. */
}


#ifdef __KERNEL__
void oo_filter_ns_put_atomic(efab_tcp_driver_t* drv, struct oo_filter_ns* fns)
{
  spin_lock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
  if( fns->ofn_refcount == 1 ) {
    /* Queue some work passing the last refcount
     * The filter_ns will be destroyed when handler drops the ref. */
    int rc = queue_work(CI_GLOBAL_WORKQUEUE, &fns->ofn_filter_work_item);
    (void) rc;
    ci_assert_nequal(rc, 0);
  }
  else {
    fns->ofn_refcount--;
  }
  ci_assert_gt(fns->ofn_refcount, 0);
  spin_unlock_bh(&drv->filter_ns_manager->ofnm_ns_lock);
}
#endif

struct oof_manager* oo_filter_ns_to_manager(struct oo_filter_ns* ofn)
{
  return ofn->ofn_filter_manager;
}

struct net* oo_filter_ns_to_netns(struct oo_filter_ns* ofn)
{
  return ofn->ofn_netns;
}

int oo_filter_ns_add_global_tproxy_filter(struct oo_filter_ns* fns,
                                          struct oo_hw_filter_spec* filter,
                                          int proto, unsigned hwport_mask,
                                          unsigned* installed_hwport_mask)
{
  int rc = 0;
  int i;
  unsigned hwports_got = 0;
  unsigned hwports_want;
  struct oo_filter_ns_manager* ofnm = fns->ofn_ns_manager;

  /* As an arbitrator we don't really care what the actual proto is.  What
   * matters is that a) all oof_managers are in agreement and b) they don't
   * use more than we expect, so we can track them correctly.
   */
  ci_assert_lt(proto, OOF_TPROXY_GLOBAL_FILTER_COUNT);

  /* Asking us to install on a hwport that this caller has already got a
   * filter on is just asking for trouble.
   */
  ci_assert_equal(hwport_mask & *installed_hwport_mask, 0);

  mutex_lock(&ofnm->ofnm_tproxy_lock);

  /* The interface to oo_hw_filter_update requires us to provide a mask of
   * all ports that should have filters on.  That means we need to ensure we
   * include any existing filters in our passed mask.
   */
  for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
    if( ofnm->ofnm_tproxy_filters[proto].otf_filter.filter_id[i] >= 0 )
      hwports_got |= 1 << i;
  }

  /* We need filters on any port that is either being requested, or we've
   * already got a filter for.
   */
  hwports_want = hwport_mask | hwports_got;
  rc = oo_hw_filter_update(&ofnm->ofnm_tproxy_filters[proto].otf_filter,
                           NULL, filter, hwports_want, hwports_want, 0,
                           OO_HW_SRC_FLAG_KERNEL_REDIRECT);

  /* Update ref counts for all ports we're reporting we've got to the caller */
  for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
    if( (hwport_mask & (1 << i)) &&
        (ofnm->ofnm_tproxy_filters[proto].otf_filter.filter_id[i] >= 0) ) {
      ofnm->ofnm_tproxy_filters[proto].otf_filter_refs[i]++;
      *installed_hwport_mask |= 1 << i;
    }
  }

  mutex_unlock(&ofnm->ofnm_tproxy_lock);

  return rc;
}

int oo_filter_ns_remove_global_tproxy_filter(struct oo_filter_ns* fns,
                                             int proto, unsigned hwport_mask,
                                             unsigned* installed_hwport_mask)
{
  struct oo_filter_ns_manager* ofnm = fns->ofn_ns_manager;
  struct oo_tproxy_filter* otp = &ofnm->ofnm_tproxy_filters[proto];
  unsigned hwports_clear = 0;
  int i;

  mutex_lock(&ofnm->ofnm_tproxy_lock);

  for( i = 0; i < CI_CFG_MAX_HWPORTS; i++ ) {
    if( hwport_mask & (1 << i) ) {
      /* If the caller is expecting us to clear a filter from this port, then
       * we better have one to be clearing, and have references to it.  If
       * not, someone's state is out of sync.
       */
      ci_assert_ge(otp->otf_filter.filter_id[i], 0);
      ci_assert_gt(otp->otf_filter_refs[i], 0);

      /* Reduce the ref count */
      otp->otf_filter_refs[i]--;
      *installed_hwport_mask &= ~(1 << i);

      /* If there's no-one left we can clear this filter */
      if( otp->otf_filter_refs[i] == 0 ) {
        hwports_clear |= 1 << i;
      }
    }
  }

  oo_hw_filter_clear_hwports(&otp->otf_filter, hwports_clear, 1);

  mutex_unlock(&ofnm->ofnm_tproxy_lock);

  return 0;
}


struct oof_nat_table* oof_cb_nat_table(void* owner_private)
{
  struct oo_filter_ns* fns = owner_private;
  struct oo_filter_ns_manager* ofnm = fns->ofn_ns_manager;
  return ofnm->ofnm_nat_table;
}

