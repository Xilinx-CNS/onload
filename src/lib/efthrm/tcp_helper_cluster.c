/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: as
**     Started: 2014/03/14
** Description: TCP helper cluster
** </L5_PRIVATE>
\**************************************************************************/


#include <onload/tcp_helper_fns.h>
#include <onload/version.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/oof_onload.h>
#include <onload/oof_interface.h>

#include <ci/efrm/pd.h>
#include <ci/efrm/vi_set.h>
#include <onload/nic.h>
#include <onload/drv/dump_to_user.h>


#if CI_CFG_ENDPOINT_MOVE
/* Clustering is not supported wuthout endpoint move. */

#define FMT_PROTOCOL(p)    ((p) == IPPROTO_TCP ? "TCP":         \
                            (p) == IPPROTO_UDP ? "UDP" : "???")

#define FMT_PORT(p)        ((int) CI_BSWAP_BE16(p))

#define IP_FMT             CI_IP_PRINTF_FORMAT
#define IP_ARG(ip)         CI_IP_PRINTF_ARGS(&(ip))

#define IPPORT_FMT         IP_FMT":%d"
#define IPPORT_ARG(ip,p)   IP_ARG(ip), FMT_PORT(p)

/* Head of global linked list of clusters.
 * The list is protected by thc_mutex.
 */
/* TODO: As all clusters are associated with a oof_local_port, we
 * could iterate over oof_local_port's to get a list of clusters and
 * not need to maintain this list here. */
static tcp_helper_cluster_t* thc_head;

/* Mutex for protecting any thc_head list and thc state as well
 * thc creation and destruction, thr creation, allocation and destruction */
static DEFINE_MUTEX(thc_mutex);

/* This mutex serializes cluster creation and allocation of thcs and their thrs.
 * Not to be taken for destructions of clusters and their objects.
 * Cannot be taken with thc_mutex held already. */
static DEFINE_MUTEX(thc_init_mutex);


static void thc_cluster_free(tcp_helper_cluster_t* thc);


static int thc_get_sock_protocol(ci_sock_cmn* sock)
{
  return sock->b.state == CI_TCP_STATE_UDP ? IPPROTO_UDP : IPPROTO_TCP;
}


void tcp_helper_cluster_ref(tcp_helper_cluster_t* thc)
{
  ci_assert_gt(oo_atomic_read(&thc->thc_ref_count), 0);
  oo_atomic_inc(&thc->thc_ref_count);
}


static int thc_is_thr_name_taken(tcp_helper_cluster_t* thc, char* name)
{
  int i = 0;
  ci_dllink* link;

  ci_assert(mutex_is_locked(&thc_mutex));

  CI_DLLIST_FOR_EACH(link, &thc->thc_thr_list) {
    tcp_helper_resource_t* thr_walk = CI_CONTAINER(tcp_helper_resource_t,
                                                   thc_thr_link, link);
    if( strncmp(name, thr_walk->name, CI_CFG_STACK_NAME_LEN) == 0 )
      return 1;
    ++i;
  }
  ci_assert_le(i, thc->thc_cluster_size);
  return 0;
}


/* Note: thc_mutex is needed to ensure the name is not taken by the time
 * the function returns */
static int thc_get_next_thr_name(tcp_helper_cluster_t* thc, char* name_out)
{
  int i = 0;
  while( i < thc->thc_cluster_size ) {
    snprintf(name_out, CI_CFG_STACK_NAME_LEN, "%s-c%d", thc->thc_name, i);
    if( thc_is_thr_name_taken(thc, name_out) == 0 )
      return 0;
    ++i;
  }
  return -ENOSPC;
}


/* If the thc has any orphan stacks, return one of them with a kernel reference.
 * Returns
 *  * -EBUSY - if a stack is being destructed (no need to kill)
 *  * -ENOENT - no stack present
 *  * 0 on success and gives thr with extra kernel ref
 */
static int thc_get_an_orphan(tcp_helper_cluster_t* thc,
                             tcp_helper_resource_t** thr_out)
{
  ci_dllink* link;
  int rc = -ENOENT;
  ci_irqlock_state_t lock_flags;

  ci_assert(mutex_is_locked(&thc_mutex));
  /* Iterating over list of stacks, make sure they don't change. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &thc->thc_thr_list) {
    tcp_helper_resource_t* thr_walk = CI_CONTAINER(tcp_helper_resource_t,
                                                   thc_thr_link, link);
    if( thr_walk->ref[OO_THR_REF_APP] == 0 ) {
      rc = oo_thr_ref_get(thr_walk->ref, OO_THR_REF_BASE);
      *thr_out = thr_walk;
      break;
    }
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  return rc;
}


static int thc_is_scalable(int thc_flags)
{
  return !! (thc_flags & THC_FLAG_SCALABLE);
}


static int /*bool*/ thc_has_live_stacks(tcp_helper_cluster_t* thc)
{
  ci_dllink* link;
  int rc = 0;
  ci_irqlock_state_t lock_flags;

  ci_assert(mutex_is_locked(&thc_mutex));
  /* Iterating over list of stacks, make sure they don't change. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &thc->thc_thr_list) {
    tcp_helper_resource_t* thr_walk = CI_CONTAINER(tcp_helper_resource_t,
                                                   thc_thr_link, link);
    if( thr_walk->ref[OO_THR_REF_APP] != 0 ) {
      rc = 1;
      break;
    }
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  return rc;
}


/* Allocate a new cluster.
 *
 * On success returns cluster with single reference */
static int thc_alloc(const char* cluster_name, int protocol, int port_be16,
                     uid_t euid, int cluster_size, int ephemeral_port_count,
                     unsigned ephem_table_entries, unsigned flags,
                     struct net* netns, tcp_helper_cluster_t** thc_out)
{
  int rc, i;
  int rss_flags;
  struct efrm_pd* pd;
  int packet_buffer_mode = flags & THC_FLAG_PACKET_BUFFER_MODE;
  int tproxy = flags & THC_FLAG_TPROXY;
  int hw_loopback_enable = flags & THC_FLAG_HW_LOOPBACK_ENABLE;
  tcp_helper_cluster_t* thc;

  ci_assert(mutex_is_locked(&thc_init_mutex));
  ci_assert(mutex_is_locked(&thc_mutex));

  thc = kmalloc(sizeof(*thc), GFP_KERNEL);
  if( thc == NULL )
    return -ENOMEM;
  memset(thc, 0, sizeof(*thc));
  ci_dllist_init(&thc->thc_tlos);
  ci_dllist_init(&thc->thc_thr_list);

  thc->thc_thr_rrobin = kmalloc(sizeof(tcp_helper_resource_t*) * cluster_size,
                                GFP_KERNEL);
  if( thc->thc_thr_rrobin == NULL ) {
    kfree(thc);
    return -ENOMEM;
  }
  memset(thc->thc_thr_rrobin, 0, sizeof(tcp_helper_resource_t*) * cluster_size);

  if( ephem_table_entries > 0 ) {
    thc->thc_ephem_table =
      tcp_helper_alloc_ephem_table(ephem_table_entries, &ephem_table_entries);
    thc->thc_ephem_table_entries = ephem_table_entries;
    if( thc->thc_ephem_table == NULL ) {
      kfree(thc->thc_thr_rrobin);
      kfree(thc);
      return -ENOMEM;
    }
  }

  if( (rc = tcp_helper_get_ns_components(&thc->thc_cplane,
                                         &thc->thc_filter_ns)) < 0) {
    tcp_helper_free_ephemeral_ports(thc->thc_ephem_table,
                                    thc->thc_ephem_table_entries);
    kfree(thc->thc_thr_rrobin);
    kfree(thc);
    return rc;
  }

  strcpy(thc->thc_name, cluster_name);
  thc->thc_cluster_size       = cluster_size;
  thc->thc_keuid              = euid;
  thc->thc_flags              = flags;
  thc->thc_thr_rrobin_index   = 0;
  thc->thc_reheat_flags       = THC_REHEAT_FLAG_USE_SWITCH_PORT;
  oo_atomic_set(&thc->thc_ref_count, 1);
  init_waitqueue_head(&thc->thr_release_done);
  thc->thc_switch_port        = 0;
  thc->thc_switch_addr        = addr_any;

  if( flags & THC_FLAG_PREALLOC_LPORTS ) {
    /* We know on this path that shared local ports are not per-IP, so pass
     * an address of zero here, and likewise pass NULL for the global table. */
    struct efab_ephemeral_port_head* ephemeral_ports;
    tcp_helper_get_ephemeral_port_list(thc->thc_ephem_table, addr_any,
                                       thc->thc_ephem_table_entries,
                                       &ephemeral_ports);
    if( (rc = tcp_helper_alloc_ephemeral_ports(ephemeral_ports, NULL, addr_any,
                                               ephemeral_port_count)) < 0 ) {
      tcp_helper_free_ephemeral_ports(thc->thc_ephem_table,
                                      thc->thc_ephem_table_entries);
      kfree(thc->thc_thr_rrobin);
      kfree(thc);
      return rc;
    }
  }

  /* Needed to protect against oo_nics changes */
  rtnl_lock();

  for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i ) {
    if( oo_nics[i].efrm_client == NULL ||
        ! oo_check_nic_suitable_for_onload(&(oo_nics[i])) )
      continue;
    if( (rc = efrm_pd_alloc(&pd, oo_nics[i].efrm_client,
                (packet_buffer_mode ? EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE : 0) |
                (hw_loopback_enable ? EFRM_PD_ALLOC_FLAG_HW_LOOPBACK : 0))) )
      goto fail;
    /*
     * Currently we move on if we fail to get special tproxy RSS_MODE on
     * interface(s) (expect Huntington old fw, run out of rss contexts).
     */
    rss_flags = tproxy ? EFRM_RSS_MODE_DST | EFRM_RSS_MODE_SRC :
                         EFRM_RSS_MODE_DEFAULT;
redo:
    rc = efrm_vi_set_alloc(pd, thc->thc_cluster_size,
                           rss_flags, &thc->thc_vi_set[i]);
    if( rc != 0 && (rss_flags != EFRM_RSS_MODE_DEFAULT) ) {
      LOG_E(ci_log("Installing special RSS mode filter failed on hwport %d, "
                   "falling back to default mode.  Transparent proxy will not "
                   "work with this interface.", i));
      rss_flags = EFRM_RSS_MODE_DEFAULT;
      goto redo;
    }

    efrm_pd_release(pd);
    if( rc != 0 )
      goto fail;
  }

  rtnl_unlock();

  thc->thc_next = thc_head;
  thc_head = thc;

  *thc_out = thc;
  return 0;

 fail:
  rtnl_unlock();
  thc_cluster_free(thc);
  return rc;
}


/* Searches for an existing cluster by name, returning a reference to that
 * cluster in [thc_out] if it exists.
 *
 * The cluster name is specified in [user_cluster_name] in the form that is
 * used by users in the EF_CLUSTER_NAME environment variable.  In particular,
 * if this is the empty string, the search falls back to the "default" cluster,
 * which means different things in different contexts:
 *  - If [thc_default] is NULL, the default cluster is the process cluster.
 *  - Otherwise, the default cluster is [thc_default], in which case [*thc_out]
 *    will be set to (a new reference to) [thc_default].
 *
 * The actual cluster name is returned in [actual_cluster_name_out].  This is
 * true even when the cluster does not exist, which is useful for the case
 * where we fall back to generating a name for a non-existent process cluster.
 * The buffer pointed to by [actual_cluster_name_out] must be at least
 * CI_CFG_CLUSTER_NAME_LEN + 1 bytes long.
 *
 * Returns zero on success or a negative error code on failure.
 */
static int
__thc_search_by_name(const char* user_cluster_name, struct net* netns,
                     int protocol, int port_be16, uid_t euid,
                     char* actual_cluster_name_out,
                     tcp_helper_cluster_t* thc_default,
                     tcp_helper_cluster_t** thc_out)
{
  tcp_helper_cluster_t* thc_walk;

  ci_assert(mutex_is_locked(&thc_mutex));

  actual_cluster_name_out[CI_CFG_CLUSTER_NAME_LEN] = '\0';

  if( strlen(user_cluster_name) > 0 ) {
    strncpy(actual_cluster_name_out, user_cluster_name,
            CI_CFG_CLUSTER_NAME_LEN);
  }
  else {
    /* A named cluster was not requested.  If we have an explicit default
     * cluster, we can just use that. */
    if( thc_default != NULL ) {
      tcp_helper_cluster_ref(thc_default);
      *thc_out = thc_default;
      strncpy(actual_cluster_name_out, thc_default->thc_name,
              CI_CFG_CLUSTER_NAME_LEN);
      return 0;
    }
    /* If the default cluster is the process cluster, we have to generate its
     * name and then go looking for it. */
    snprintf(actual_cluster_name_out, CI_CFG_CLUSTER_NAME_LEN + 1, "c%d",
             current->tgid);
  }

  thc_walk = thc_head;
  while( thc_walk != NULL ) {
    if( thc_walk->thc_cplane->cp_netns == netns &&
        strcmp(actual_cluster_name_out, thc_walk->thc_name) == 0 ) {
      if( thc_walk->thc_keuid != euid )
        return -EPERM;
      tcp_helper_cluster_ref(thc_walk);
      *thc_out = thc_walk;
      return 0;
    }
    thc_walk = thc_walk->thc_next;
  }
  return -ENOENT;
}


/* Tests whether a cluster contains a specified stack.  It is allowed to pass
 * in a pointer to a stack that might have been destroyed, so to reinforce this
 * point, the pointer to the stack is passed in opaquely. */
static int /*bool*/
thc_contains_thr(tcp_helper_cluster_t* thc, void* thr_opaque)
{
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, &thc->thc_thr_list) {
    tcp_helper_resource_t* thr_walk = CI_CONTAINER(tcp_helper_resource_t,
                                                   thc_thr_link, link);
    if( (uintptr_t) thr_walk == (uintptr_t) thr_opaque )
      return 1;
  }

  return 0;
}


static void
thc_uninstall_tproxy(tcp_helper_cluster_t* thc)
{
  if( thc->thc_tproxy_ifindex != NULL ) {
    tcp_helper_install_tproxy(0, NULL, thc, NULL, thc->thc_tproxy_ifindex,
                              thc->thc_tproxy_ifindex_count);
    kfree(thc->thc_tproxy_ifindex);
    thc->thc_tproxy_ifindex = NULL;
  }
}


static void thc_cluster_remove(tcp_helper_cluster_t* thc)
{
  tcp_helper_cluster_t *thc_walk, *thc_prev;

  ci_assert(mutex_is_locked(&thc_mutex));

  /* Remove from the thc_head list */
  thc_walk = thc_head;
  thc_prev = NULL;
  while( thc_walk != NULL ) {
    if( thc_walk == thc ) {
      if( thc_walk == thc_head ) {
        ci_assert_equal(thc_prev, NULL);
        thc_head = thc_walk->thc_next;
      }
      else {
        thc_prev->thc_next = thc_walk->thc_next;
      }
      return;
    }
    thc_prev = thc_walk;
    thc_walk = thc_walk->thc_next;
  }
  ci_assert(0);
}


/* Free a thc.
 * No need for lock.
 */
static void thc_cluster_free(tcp_helper_cluster_t* thc)
{
  int i;

  if( thc->thc_ephem_table != NULL )
    tcp_helper_free_ephemeral_ports(thc->thc_ephem_table,
                                    thc->thc_ephem_table_entries);

  thc_uninstall_tproxy(thc);

  /* Free up resources within the thc */
  oo_filter_ns_put(&efab_tcp_driver, thc->thc_filter_ns);
  cp_release(thc->thc_cplane);
  for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i )
    if( thc->thc_vi_set[i] != NULL )
      efrm_vi_set_release(thc->thc_vi_set[i]);
  kfree(thc->thc_thr_rrobin);
  ci_assert(ci_dllist_is_empty(&thc->thc_tlos));
  kfree(thc);
}


/* Remove the thr from the list of stacks tracked by the thc.
 * Remove the thr from the round robin array of stack pointers tracked by the thc.
 *
 * requires thc_mutex
 */
static void thc_remove_thr(tcp_helper_cluster_t* thc,
                           tcp_helper_resource_t* thr)
{
  ci_dllink* link;
  int rrobin_i;

  for( rrobin_i = 0; rrobin_i < thc->thc_cluster_size; ++rrobin_i ) {
    if( thc->thc_thr_rrobin[rrobin_i] != NULL &&
        thc->thc_thr_rrobin[rrobin_i]->id == thr->id ) {
      thc->thc_thr_rrobin[rrobin_i] = NULL;
      break;
    }
  }

  ci_assert(mutex_is_locked(&thc_mutex));

  CI_DLLIST_FOR_EACH(link, &thc->thc_thr_list) {
    tcp_helper_resource_t* thr_walk = CI_CONTAINER(tcp_helper_resource_t,
                                                   thc_thr_link, link);
    if( thr_walk == thr ) {
      ci_dllist_remove(link);
      thr->thc = NULL;
      oo_atomic_dec_and_test(&thc->thc_thr_count);
      ci_assert_ge(oo_atomic_read(&thc->thc_thr_count), 0);
      return;
    }
  }
  ci_assert(0);
}


/* From given cluster remove thr with its reference or reference alone if
 * thr not given. Signal thc_release_done waiter when thr is removed.
 * Free cluster when no references left, in which case the return value is
 * true; otherwise, it is false.
 */
static int /*bool*/
tcp_helper_cluster_release_locked(tcp_helper_cluster_t* thc,
                                  tcp_helper_resource_t* thr)
{
  int do_free_cluster = 0;
  ci_assert(mutex_is_locked(&thc_mutex));

  /* Make sure that removing thr from thc and thc from thc_head is atomic */
  if( thr != NULL )
    /* Remove thr as it no longer holds cluster resources */
    thc_remove_thr(thc, thr);
  do_free_cluster = oo_atomic_dec_and_test(&thc->thc_ref_count);
  if( do_free_cluster )
    thc_cluster_remove(thc);

  /* thc is detached from thc_head list and technically thc_mutex is
   * not required.
   * However having resources freed now might reduce clash with
   * concurrent cluster creation (especially tproxy one).
   * TODO: consider adding EF_CLUSTER_REUSE analogue
   * for entire clusters.
   */
  if( do_free_cluster )
    thc_cluster_free(thc);

  if( ! do_free_cluster && thr != NULL )
    /* there might be some waiter around - wake him up */
    wake_up_all(&thc->thr_release_done);

  return do_free_cluster;
}


/* Kill an orphan stack in the thc */
static int thc_kill_an_orphan(tcp_helper_cluster_t* thc)
{
  tcp_helper_resource_t* thr = NULL;
  int rc;

  ci_assert(mutex_is_locked(&thc_init_mutex));
  ci_assert(mutex_is_locked(&thc_mutex));

  rc = thc_get_an_orphan(thc, &thr);
  if( rc == -ENOENT )
    return rc;

  /* -EBUSY means the stack is dying already - no need to kill */
  ci_assert_impl(rc != 0, rc == -EBUSY);

  if( rc == 0 ) {
    /* This is generally called when the stack is being freed.  But as
     * we are holding the thc_mutex, we will deadlock if we took that
     * path.  So we remove thr from the thc now. */
    LOG_U(ci_log("Clustering: Killing orphan stack %d", thr->id));

    tcp_helper_kill_stack(thr);
  }
  else {
    LOG_U(ci_log("%s: a suitable stack is dying - waiting\n", __FUNCTION__));
  }

  /* Drop mutex so the stack cleanup can proceed,
   *  * We have got thc refernce so thc cannot go away.
   *  * We have got thc_init_mutex, so no concurrent cluster or stack creation
   *    work can proceed - only destruction.
   */
  mutex_unlock(&thc_mutex);

  if( rc == 0 )
    /* remove reference taken by thc_get_an_orphan()
     * Note: this will likely trigger stack destruction
     */
    oo_thr_ref_drop(thr->ref, OO_THR_REF_BASE);

  rc = wait_event_interruptible_timeout(thc->thr_release_done,
                                        ! thc_contains_thr(thc, thr), 10 * HZ);
  if( rc == 0 ) {
    LOG_E(ci_log("%s: stack did not die within 10s\n", __FUNCTION__));
    rc = -ETIMEDOUT;
  }
  else if( rc > 0 ) {
    /* A strictly positive return value indicates success, which this function
     * in turn indicates with a return value of zero. */
    rc = 0;
  }

  mutex_lock(&thc_mutex);

  return rc;
}


/* This function searches for a cluster by name.  If so instructed by
 * [custer_restart_opt], clusters containing only orphaned stacks that would
 * otherwise satisfy the search will be destroyed.  Please see
 * __thc_search_by_name() for the behaviour of the search itself. */
static int
thc_search_by_name(const char* user_cluster_name, struct net* netns,
                   int protocol, int port_be16, uid_t euid,
                   char* actual_cluster_name_out,
                   int cluster_restart_opt,
                   tcp_helper_cluster_t* thc_default,
                   tcp_helper_cluster_t** thc_out)
{
  int rc;
  tcp_helper_cluster_t* thc = NULL;

  ci_assert(mutex_is_locked(&thc_mutex));

  rc = __thc_search_by_name(user_cluster_name, netns, protocol, port_be16,
                            euid, actual_cluster_name_out, thc_default, &thc);

  if( rc == 0 && cluster_restart_opt && ! thc_has_live_stacks(thc) ) {
    /* We found a cluster, but it doesn't have any non-orphaned stacks.
     * Destroy the cluster so that the caller can create a new one with the
     * desired properties. */

    /* Start by clearing out any stacks.  Caveat: killing a stack drops and
     * retakes [thc_mutex]. */
    while( thc_kill_an_orphan(thc) == 0 );

    /* All stacks were orphans, and we succeeded in clearing all of the
     * orphaned stacks, so now there should be no stacks at all. */
    ci_assert(ci_dllist_is_empty(&thc->thc_thr_list));

    /* Now that the stacks have gone, our reference to the cluster ought to
     * be the last one... unless, that is, that we used the default cluster,
     * to which the caller will have a reference. */
    ci_assert_equal(oo_atomic_read(&thc->thc_ref_count),
                    thc == thc_default ? 2 : 1);

    /* Drop our reference to the cluster. */
    tcp_helper_cluster_release_locked(thc, NULL);

    if( thc != thc_default ) {
      /* If the cluster is not the default cluster, it will have been
       * destroyed by now, and so repeating the search will not find it but
       * instead will fall back to the default cluster (whether that be the
       * explicit default or the process cluster).  We call the double-
       * underscore variant directly, as we don't want to kill the next
       * cluster that we find. */
      rc = __thc_search_by_name(user_cluster_name, netns, protocol,
                                port_be16, euid, actual_cluster_name_out,
                                thc_default, &thc);
    }
    else {
      /* On the other hand, if we did clean out the default cluster, it won't
       * quite be dead yet, and so we don't want to repeat the search, or
       * we'll just find it again. */
      rc = -ENOENT;
      thc = NULL;
    }
  }

  *thc_out = thc;
  return rc;
}


static int thc_get_prior_round_robin_index(const tcp_helper_cluster_t* thc)
{
  int index = thc->thc_thr_rrobin_index;
  if( --index < 0 )
    index = thc->thc_cluster_size - 1;
  return index;
}


/* Look for a suitable stack within the cluster.
 *
 * You need to oo_thr_ref_drop(OO_THR_REF_APP) the stack returned by this
 * function if you fail to install it for a user application.
 *
 * You must hold the thc_mutex before calling this function.
 */
static int thc_get_thr(tcp_helper_cluster_t* thc,
                       struct oof_socket* oofilter,
                       tcp_helper_resource_t** thr_out)
{
  ci_irqlock_state_t lock_flags;
  ci_dllink* link;

  ci_assert(mutex_is_locked(&thc_mutex));
  /* Search for a suitable stack within the thc.  A suitable stack has
   * the same tid as current and we could associate our filter with it.
   * Or in other words does not have a socket filter installed
   * (dummy or not) with the same protocol:port_be16[:addr_be32]
   */
  /* Iterating over list of stacks, make sure they don't change. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);

  CI_DLLIST_FOR_EACH(link, &thc->thc_thr_list) {
    tcp_helper_resource_t* thr_walk = CI_CONTAINER(tcp_helper_resource_t,
                                                   thc_thr_link, link);
    if( thr_walk->thc_tid == current->pid &&
       oof_socket_can_update_stack(oo_filter_ns_to_manager(thc->thc_filter_ns),
                                   oofilter, thr_walk) &&
       oo_thr_ref_get(thr_walk->ref, OO_THR_REF_APP) == 0 ) {
      *thr_out = thr_walk;
      ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
      return 0;
    }
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  return 1;
}


/* Performs stack selection and ensures stickiness properties
 * suitable for a cluster in hot restart mode.
 *
 * Returns 0 if successful and stack exists,
 * 1 if successful except that stack needs to be allocated,
 * -EADDRINUSE if no more spaces available for reheating.
 *
 * If a stack is found for reheating, the stack owner will be updated to
 * the current pid/tid.
 *
 * You need to oo_thr_ref_drop(OO_THR_REF_APP) the stack returned by this
 * function when done.
 *
 * You must hold the thc_mutex before calling this function.
 *
 * You cannot hold the THR_TABLE.lock when calling this function.
 */
static int thc_get_thr_reheat(tcp_helper_cluster_t* thc,
                              ci_addr_t addr,
                              uint16_t port,
                              int* backup_index,
                              pid_t* backup_tid_effective,
                              tcp_helper_resource_t** thr_out)
{
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t* thr = NULL;
  tcp_helper_resource_t* thr_prior = NULL;
  int i;
  int rc = 1;

  ci_assert_nequal(thc->thc_thr_rrobin, NULL);

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);

  /* Try to set prior_stack; sticky binds explicitly unset it. */
  for( i = 0; i < thc->thc_cluster_size; ++i ) {
    if( NULL == thc->thc_thr_rrobin[i] )
      continue;
    if( thc->thc_thr_rrobin[i]->thc_tid_effective == current->pid ) {
      thr_prior = thc->thc_thr_rrobin[i];
      break;
    }
  }

  if( thc->thc_reheat_flags & THC_REHEAT_FLAG_USE_SWITCH_PORT ) {
    /* If both ports and addrs match we need to instead switch stack. */
    /* Note addr == 0 is valid (wild filter), so this condition could fail if
     * switch_port == port and switch_addr == 0 by default (hasn't been set)
     * and addr == 0, although this should be a valid case to enter this code.
     * This case can never happen as ports are compared first, 0 is invalid for
     * a port, and if switch_port has been set, switch_addr was set at the
     * same time (possibly to 0).
     */
    if( thc->thc_switch_port != port ||
        !CI_IPX_ADDR_EQ(thc->thc_switch_addr, addr) ) {
      if( 0 != thc->thc_switch_port ) {
        thc->thc_reheat_flags |= THC_REHEAT_FLAG_STICKY_MODE;
      }
      /* Try to find a stack this worker already uses. */
      thr = thr_prior;
      thr_prior = NULL;
    }
  }
  if( NULL == thr ) {
    thr = thc->thc_thr_rrobin[thc->thc_thr_rrobin_index];
    if( thr_prior == NULL ) {
      /* Reheat or multi-worker, else tids would match. */
      thc->thc_switch_port = port;
      thc->thc_switch_addr = addr;
      thc->thc_reheat_flags |= THC_REHEAT_FLAG_USE_SWITCH_PORT;
      thc->thc_reheat_flags &= ~THC_REHEAT_FLAG_STICKY_MODE;
    }
    else {
      *backup_index = i;
      *backup_tid_effective = thr_prior->thc_tid_effective;
      thr_prior->thc_tid_effective = 0;
      if( ! (thc->thc_reheat_flags & THC_REHEAT_FLAG_STICKY_MODE) )
        thc->thc_reheat_flags &= ~THC_REHEAT_FLAG_USE_SWITCH_PORT;
    }
    if( thr != NULL )
      thr->thc_tid_effective = current->pid;
    if( ++thc->thc_thr_rrobin_index >= thc->thc_cluster_size )
      thc->thc_thr_rrobin_index = 0;
  }
  if( thr != NULL ) {
    if( (rc = oo_thr_ref_get(thr->ref, OO_THR_REF_APP)) != 0 ) {
      /* Stack is dying; let thc_alloc_thr() kill an orphan. */
      thr = NULL;
      rc = 1;
    }
  }
  *thr_out = thr;

  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  return rc;
}


/* Adds an entry in this cluster's round robin table,
 * at a position determined using the cluster's round robin index.
 *
 * You must hold the thc_mutex before calling this function.
 *
 * This function only expects to be called if there is a free space at the
 * determined position; this and thc_mutex being held are guaranteed via
 * thc_alloc_thr().
 */
static void thc_round_robin_add(tcp_helper_cluster_t*   thc,
                                tcp_helper_resource_t*  thr_new)
{
  tcp_helper_resource_t** stacks = thc->thc_thr_rrobin;
  int index = thc_get_prior_round_robin_index(thc);

  /* The round robin pointer should have been init'd during cluster alloc */
  ci_assert_nequal(stacks, NULL);
  /* Not the space I asked for. I want to talk to the manager! */
  /* If the thc_mutex is held, nobody else can modify round robin table while
   * we are looking for a free space in it.
   *    During bind, thc_alloc_thr() is only called if the stack at the
   * index is NULL, in which case the index gets incremented mod cluster size,
   * hence the need for thc_get_prior_round_robin_index() here. This index
   * should still be for a NULL pointer.
   */
  ci_assert_equal(stacks[index], NULL);

  stacks[index] = thr_new;
}


/* Allocates a new stack in thc.
 *
 * You need to oo_thr_ref_drop(OO_THR_REF_APP) the stack returned by this
 * function when done.
 */
static int thc_alloc_thr(tcp_helper_cluster_t* thc,
                         int cluster_restart_opt,
                         int cluster_hot_restart_opt,
                         const ci_netif_config_opts* ni_opts,
                         int ni_flags,
                         tcp_helper_resource_t** thr_out)
{
  int rc;
  tcp_helper_resource_t* thr_walk;
  ci_resource_onload_alloc_t roa;
  ci_netif_config_opts* opts;
  ci_netif* netif;

  ci_assert(mutex_is_locked(&thc_init_mutex));
  ci_assert(mutex_is_locked(&thc_mutex));

  memset(&roa, 0, sizeof(roa));

  if( (rc = thc_get_next_thr_name(thc, roa.in_name)) != 0 ) {
    /* All stack names taken i.e. cluster is full.  Based on setting
     * of cluster_restart_opt, either kill a orphan or return error. */
    if( cluster_restart_opt == 1 ) {
      rc = thc_kill_an_orphan(thc);

      /* thc_kill_an_orphan() can return ENOENT if there are no
       * orphan stacks. It means that all instances in cluster already
       * allocated, so proper(ENOSPC) return code should be set. */
      if( rc == 0 )
        rc = thc_get_next_thr_name(thc, roa.in_name);
      else if( rc == -ENOENT )
        rc = -ENOSPC;

      if( rc != 0 ) {
        LOG_E(ci_log("%s: Stack creation failed because all instances in "
                     "cluster already allocated.", __FUNCTION__));
        return rc;
      }
    }
    else {
      LOG_E(ci_log("%s: Clustered stack creation failed because of "
                   "orphans.  Either try again later or use "
                   "EF_CLUSTER_RESTART", __FUNCTION__));
      return rc;
    }
  }
  roa.in_flags = ni_flags & ~(CI_NETIF_FLAG_DO_DROP_SHARED_LOCAL_PORTS |
                              CI_NETIF_FLAG_IN_DL_CONTEXT);
  strncpy(roa.in_version, ONLOAD_VERSION, sizeof(roa.in_version));
  strncpy(roa.in_uk_intf_ver, oo_uk_intf_ver, sizeof(roa.in_uk_intf_ver));
  if( (opts = kmalloc(sizeof(*opts), GFP_KERNEL)) == NULL )
    return -ENOMEM;
  memcpy(opts, ni_opts, sizeof(*opts));
  if( ni_flags & CI_NETIF_FLAG_DO_DROP_SHARED_LOCAL_PORTS ) {
    /* disabling tcp shared ports on passive socket clustered stacks */
    opts->tcp_shared_local_ports = 0;
    opts->tcp_shared_local_ports_max = 0;
  }

  if( opts->scalable_filter_enable == CITP_SCALABLE_FILTERS_ENABLE_WORKER )
     /* Original stack postponed creation of active scalable filter to
      * clustered stack.  New stack will have scalable filter and the flag
      * reset accordingly. */
     opts->scalable_filter_enable = CITP_SCALABLE_FILTERS_ENABLE;

  rc = tcp_helper_rm_alloc(&roa, opts, -1, thc, &thr_walk);
  kfree(opts);
  if( rc != 0 )
    return rc;

  if( 0 != cluster_hot_restart_opt )
    thc_round_robin_add(thc, thr_walk);

  /* Do not allow clustered stacks to do TCP loopback apart same stack loopback
   * Note: same stack loopback will only be attempted in active scalable clustered
   * stack */
  netif = &thr_walk->netif;
  if( (NI_OPTS(netif).tcp_server_loopback != CITP_TCP_LOOPBACK_OFF) &&
      (NI_OPTS(netif).tcp_server_loopback != CITP_TCP_LOOPBACK_SAMESTACK) ) {
    ci_log("%s: Disabling Unsupported TCP loopback on clustered stack.",
           __FUNCTION__);
    NI_OPTS(netif).tcp_server_loopback = CITP_TCP_LOOPBACK_SAMESTACK;
  }
  if( (NI_OPTS(netif).tcp_client_loopback != CITP_TCP_LOOPBACK_OFF) &&
      (NI_OPTS(netif).tcp_client_loopback != CITP_TCP_LOOPBACK_SAMESTACK) ) {
    ci_log("%s: Disabling Unsupported TCP loopback on clustered stack.",
           __FUNCTION__);
    NI_OPTS(netif).tcp_client_loopback = CITP_TCP_LOOPBACK_SAMESTACK;
  }

  thr_walk->thc_tid           = current->pid;
  thr_walk->thc_tid_effective = current->pid;
  thr_walk->thc               = thc;
  if( thc_is_scalable(thr_walk->thc->thc_flags) )
    netif->state->flags |= CI_NETIF_FLAG_SCALABLE_FILTERS_RSS;

  tcp_helper_cluster_ref(thc);
  ci_dllist_push_tail(&thc->thc_thr_list, &thr_walk->thc_thr_link);

  oo_atomic_inc(&thc->thc_thr_count);

  *thr_out = thr_walk;
  return 0;
}
#endif /* CI_CFG_ENDPOINT_MOVE */


/* This function returns an upper bound on the number of interfaces on which
 * the user has requested that scalable interfaces be created. */
int ci_netif_requested_scalable_intf_count(struct oo_cplane_handle* cp,
                                           const ci_netif_config_opts* ni_opts)
{
  ci_assert_equiv(ni_opts->scalable_filter_ifindex_active ==
                  CITP_SCALABLE_FILTERS_ALL,
                  ni_opts->scalable_filter_ifindex_passive ==
                  CITP_SCALABLE_FILTERS_ALL);

  if( ni_opts->scalable_filter_ifindex_passive == CITP_SCALABLE_FILTERS_ALL )
    return oo_cp_get_acceleratable_llap_count(cp);

  /* When specifying interfaces explicitly, we support at most one passive and
   * one active. */
  return 2;
}

static int
ci_netif_requested_scalable_interfaces(struct oo_cplane_handle* cp,
                                       const ci_netif_config_opts* ni_opts,
                                       ci_ifid_t* ifindices, int max_count)
{
  int count;

  ci_assert_equiv(ni_opts->scalable_filter_ifindex_active ==
                  CITP_SCALABLE_FILTERS_ALL,
                  ni_opts->scalable_filter_ifindex_passive ==
                  CITP_SCALABLE_FILTERS_ALL);

  if( ni_opts->scalable_filter_ifindex_passive == CITP_SCALABLE_FILTERS_ALL )
    return oo_cp_get_acceleratable_ifindices(cp, ifindices, max_count);

  /* Report the passive and active scalable interfaces if they are specified.
   */
  count = 0;
  if( count < max_count && ni_opts->scalable_filter_ifindex_active > 0 )
    ifindices[count++] = ni_opts->scalable_filter_ifindex_active;
  if( count < max_count && ni_opts->scalable_filter_ifindex_passive > 0 )
    ifindices[count++] = ni_opts->scalable_filter_ifindex_passive;

  return count;
}


int
tcp_helper_install_tproxy(int install,
                          tcp_helper_resource_t* thr,
                          tcp_helper_cluster_t* thc,
                          const ci_netif_config_opts* ni_opts,
                          uint16_t* ifindexes_out, int out_count)
{
  int rc = 0;
  int i, k;
  int ifindex = 0;
  struct oof_manager* ofm;
  ci_ifid_t* ifindexes_in = NULL;
  int in_count;
  struct oo_cplane_handle* cplane;

  if( thr ) {
    ofm = oo_filter_ns_to_manager(thr->filter_ns);
    cplane = thr->netif.cplane;
  }
  else {
#if CI_CFG_ENDPOINT_MOVE
    ofm = oo_filter_ns_to_manager(thc->thc_filter_ns);
    cplane = thc->thc_cplane;
#else
    ci_assert(0);
    return -EINVAL;
#endif
  }

  ci_assert(ofm);

  if( ! install ) {
    k = out_count;
    goto cleanup;
  }

  ifindexes_in = kmalloc(out_count * sizeof(ci_ifid_t), GFP_KERNEL);
  if( ifindexes_in == NULL )
    return -ENOMEM;

  in_count = ci_netif_requested_scalable_interfaces(cplane, ni_opts,
                                                    ifindexes_in, out_count);

  ci_assert_le(in_count, out_count);
  ci_assert_ge(in_count, 0);

  for( i = 0, k = 0; i < in_count; ++i ) { /* for each input ifindex */

    ifindex = ifindexes_in[i];

    {
      /* check duplicates */
      int j;
      for( j = 0 ; j < k ; ++j ) /* for each tproxy installed so far */
        if( ifindexes_out[j] == ifindex )
          break;
      /* ignore duplicates */
      if( j != k )
        continue;
    }

    rc = oof_tproxy_install(ofm, thr, thc, ifindex);
    if( rc != 0 )
      goto cleanup;

    ci_assert_equal(ifindexes_out[k] , 0);
    ifindexes_out[k++] = ifindex;
  }

out:
  kfree(ifindexes_in);
  return rc;

cleanup:
  for( --k; k >= 0; --k) {
    if( ifindexes_out[k] > 0 ) {
      oof_tproxy_free(ofm, thr, thc, ifindexes_out[k]);
      ifindexes_out[k] = 0;
    }
  }
  goto out;
}


#if CI_CFG_ENDPOINT_MOVE
static int
thc_install_tproxy(tcp_helper_cluster_t* thc,
                   const ci_netif_config_opts* ni_opts)
{
  int ifindex_buf_size;

  thc->thc_tproxy_ifindex_count =
    ci_netif_requested_scalable_intf_count(thc->thc_cplane, ni_opts);
  ifindex_buf_size = sizeof(*thc->thc_tproxy_ifindex) *
                     thc->thc_tproxy_ifindex_count;

  ci_assert_equal(thc->thc_tproxy_ifindex, NULL);
  thc->thc_tproxy_ifindex = kmalloc(ifindex_buf_size, GFP_KERNEL);
  if( thc->thc_tproxy_ifindex == NULL )
    return -ENOMEM;
  memset(thc->thc_tproxy_ifindex, 0, ifindex_buf_size);
  return tcp_helper_install_tproxy(1, NULL, thc, ni_opts,
                                   thc->thc_tproxy_ifindex,
                                   thc->thc_tproxy_ifindex_count);
}


void tcp_helper_cluster_release(tcp_helper_cluster_t* thc,
                                tcp_helper_resource_t* thr)
{
  mutex_lock(&thc_mutex);
  tcp_helper_cluster_release_locked(thc, thr);
  mutex_unlock(&thc_mutex);
}


/* Returns 1 if the stack belongs to a cluster or else 0.
 */
int tcp_helper_cluster_from_cluster(tcp_helper_resource_t* thr)
{
  return thr->thc != NULL;
}


static int tcp_helper_cluster_thc_flags(const ci_netif_config_opts* ni_opts)
{
  int flags =
    (ni_opts->packet_buffer_mode ?
     THC_FLAG_PACKET_BUFFER_MODE : 0) |
    (ni_opts->mcast_send & CITP_MCAST_SEND_FLAG_EXT ?
     THC_FLAG_HW_LOOPBACK_ENABLE : 0);
  int maybe_prealloc_lports = ni_opts->tcp_shared_local_ports_per_ip ?
    0 : THC_FLAG_PREALLOC_LPORTS;

  /* The remaining flags are only applicable to scalable clusters, i.e. to
   * those that have a MAC filter pointing at their VI set.  If scalable
   * filters are disabled, or if they're not in one of the "rss" modes, then
   * the cluster is not scalable. */
  if( ni_opts->scalable_filter_enable == CITP_SCALABLE_FILTERS_DISABLE )
    return flags;
  if( ! (ni_opts->scalable_filter_mode & CITP_SCALABLE_MODE_RSS) )
    return flags;

  /* If we get this far, we're in an "rss:<something>" mode, and the cluster is
   * scalable. */
  flags |= THC_FLAG_SCALABLE;

  /* According to the exact scalable filter mode, we might need to tweak the
   * behaviour slightly with some extra flags. */
  switch( ni_opts->scalable_filter_mode ) {
  case CITP_SCALABLE_MODE_PASSIVE_RSS:
    /* Scalable on passive-open only.  No extra flags here. */
    break;
  case CITP_SCALABLE_MODE_ACTIVE_RSS:
  case CITP_SCALABLE_MODE_PASSIVE_RSS | CITP_SCALABLE_MODE_ACTIVE_RSS:
    /* Scalable on non-IP_TRANSPARENT active-open sockets (and maybe on
     * passive-open).  This has interactions with shared local ports. */
    flags |= maybe_prealloc_lports;
    break;
  case CITP_SCALABLE_MODE_TPROXY_ACTIVE_RSS:
  case CITP_SCALABLE_MODE_PASSIVE_RSS | CITP_SCALABLE_MODE_TPROXY_ACTIVE_RSS:
    /* Scalable on IP_TRANSPARENT active-open sockets (and maybe on
     * passive-open).  This was the original use case for MAC filters in
     * Onload.  Multiple RSS contexts are required in these modes, so we set a
     * flag that we will check when creating those.
     * As all active RSS scalable filter modes, rss transparent active can be
     * combined with shared local ports feature. */
    flags |= THC_FLAG_TPROXY | maybe_prealloc_lports;
    break;
  default:
    ci_assert(0);
    break;
  }
  return flags;
}


int tcp_helper_cluster_alloc_thr(const char* cname,
                                 int cluster_size,
                                 int cluster_restart,
                                 int ni_flags,
                                 const ci_netif_config_opts* ni_opts,
                                 tcp_helper_resource_t** thr_out)
{
  tcp_helper_cluster_t* thc = NULL;
  tcp_helper_resource_t* thr = NULL;
  int thc_alloced = 0, thc_found = 0;
  int rc;
  int thc_flags = tcp_helper_cluster_thc_flags(ni_opts);
  char name[CI_CFG_CLUSTER_NAME_LEN + 1];


  mutex_lock(&thc_init_mutex);
  mutex_lock(&thc_mutex);

  /* Caveat: this call can drop and retake [thc_mutex]. */
  rc = thc_search_by_name(cname, current->nsproxy->net_ns, 0, 0,
                          ci_geteuid(), name, cluster_restart, NULL, &thc);
  if( rc == 0 ) {
    thc_found = 1;
  }
  else if( rc == -ENOENT ) {
    /* This is the scalable filter path, where we need to allocate a cluster
     * at stack creation.  We use the namespace that we're currently in to
     * select the appropriate filter manager.
     */
    rc = thc_alloc(name, 0, 0, ci_geteuid(), cluster_size,
                   ni_opts->tcp_shared_local_ports,
                   CI_MAX(ni_opts->tcp_shared_local_ports,
                          ni_opts->tcp_shared_local_ports_max), thc_flags,
                   current->nsproxy->net_ns, &thc);
    if( rc < 0 )
      goto fail;
    thc_alloced = 1;
  }
  else {
    goto fail;
  }

  rc = thc_alloc_thr(thc, cluster_restart, 0, ni_opts, ni_flags, &thr);

 fail:
  mutex_unlock(&thc_mutex);
  if( rc == 0 && thc_alloced && thc_is_scalable(thc_flags) ) {
    /* TODO: wait for resources if another's cluster destruction is in progress */
    rc = thc_install_tproxy(thc, ni_opts);
    if( rc != 0 )
      oo_thr_ref_drop(thr->ref, OO_THR_REF_APP);
  }
  if( thc_alloced || thc_found )
    /* free the reference we have taken in thc_alloc() or thc_search_by_name() */
    /* unless thr has not been allocated (error), it will get thc freed as well */
    tcp_helper_cluster_release(thc, NULL);
  mutex_unlock(&thc_init_mutex);
  if( rc == 0 )
   *thr_out = thr;
  return rc;
}


/* This function must be called with netif lock not held and it always
 * returns with the netif lock not held.
 */
int efab_tcp_helper_reuseport_bind(ci_private_t *priv, void *arg)
{
  oo_tcp_reuseport_bind_t* trb = arg;
  ci_netif* ni = &priv->thr->netif;
  tcp_helper_cluster_t* thc = NULL;
  tcp_helper_resource_t* thr = NULL;
  citp_waitable* waitable;
  ci_sock_cmn* sock;
  /* We need to try and find an appropriate existing cluster.  To do that
   * we use the netns and filter manager associated with this socket, which
   * reflect the namespace the socket was created in.  If we need to create
   * a new cluster we'll use the netns to get our own reference to an
   * appropriate filter manager.
   */
  struct oof_manager* fm = oo_filter_ns_to_manager(priv->thr->filter_ns);
  struct net* netns = oo_filter_ns_to_netns(priv->thr->filter_ns);
  struct oof_socket* oofilter;
  struct oof_socket dummy_oofilter;
  int protocol;
  char name[CI_CFG_CLUSTER_NAME_LEN + 1];
  int rc;
  int flags = 0;
  tcp_helper_cluster_t* ported_thc;
  int alloced = 0;
  int do_sock_unlock = 1;
  oo_sp new_sock_id;
  int scalable;
  ci_addr_t laddr, raddr;

  tcp_helper_reheat_state_t reheat_state = {
    .thr_prior_index    = -1,
    .thc_tid_effective  = -1,
    .thc_reheat_flags   =  0,
    .thc_switch_port    =  0,
    .thc_switch_addr    =  addr_any,
  };

  if( NI_OPTS(ni).cluster_ignore == 1 ) {
    LOG_NV(ci_log("%s: Ignored attempt to use clusters due to "
                  "EF_CLUSTER_SIZE set to 0 or EF_CLUSTER_IGNORE option."
                  "EF_CLUSTER_IGNORE is deprecated", __FUNCTION__));
    return 0;
  }

  if( trb->port_be16 == 0 ) {
    ci_log("%s: Reuseport on port=0 is not supported", __FUNCTION__);
    return -EINVAL;
  }

  if( trb->cluster_size < 1 ) {
    ci_log("%s: Cluster size needs to be a positive number", __FUNCTION__);
    return -EINVAL;
  }

  waitable = SP_TO_WAITABLE(ni, priv->sock_id);
  rc = ci_sock_lock(ni, waitable);
  if( rc != 0 )
    return rc;

  sock = SP_TO_SOCK(ni, priv->sock_id);
  protocol = thc_get_sock_protocol(sock);

  scalable = ci_tcp_use_mac_filter_listen(ni, sock, sock->cp.so_bindtodevice);

  /* No clustering on sockets bound to alien addresses */
  if( sock->s_flags & CI_SOCK_FLAG_BOUND_ALIEN && ! scalable ) {
    rc = 0;
    goto unlock_sock;
  }

  if( sock->s_flags & (CI_SOCK_FLAGS_SCALABLE | CI_SOCK_FLAG_STACK_FILTER) ) {
    /* This is not quite the contradiction that it seems: we certainly support
     * clustered scalable sockets, but the prohibition here is against
     * clustering of sockets that are _already_ using a MAC filter. */
    ci_log("%s: Scalable filter sockets cannot be clustered", __FUNCTION__);
    rc = -EINVAL;
    goto unlock_sock;
  }

  if( scalable && NI_OPTS(ni).scalable_filter_enable !=
                  CITP_SCALABLE_FILTERS_ENABLE_WORKER) {
    rc = 0;
    /* We assume this socket will become listen scalable passive.  There's
     * nothing to do as we already have a cluster, since we're not in the
     * ENABLE_WORKER case. */
    goto unlock_sock;
  }

  oofilter = &ci_trs_ep_get(priv->thr, priv->sock_id)->oofilter;

  if( oofilter->sf_local_port != NULL ) {
    ci_log("%s: Socket that already have filter cannot be clustered",
           __FUNCTION__);
    rc = -EINVAL;
    goto unlock_sock;
  }

  laddr = trb->addr;
  raddr = addr_any;

  if( priv->thr->thc ) {
    /* Reserve proto:port[:ip] until bind (or close)*/
    rc = oof_socket_add(fm, oofilter,
                       OOF_SOCKET_ADD_FLAG_CLUSTERED |
                       OOF_SOCKET_ADD_FLAG_DUMMY,
                       protocol, sock_af_space(sock),
                       laddr, trb->port_be16, raddr, 0,
                       &ported_thc);
    if( rc > 0 )
      rc = 0;
    if( rc == 0 )
      sock->s_flags |= CI_SOCK_FLAG_FILTER;
    goto unlock_sock;
  }

  mutex_lock(&thc_init_mutex);
  /* We are going to be iterating over clusters, make sure they don't
   * change.
   */
  mutex_lock(&thc_mutex);

  /* Lookup a suitable cluster to use */

  /* We try to add dummy filter to oof to reserve proto:port[:ip] tuple,
   * if there is already a cluster at the tuple we will get reference to it,
   */
  oof_socket_ctor(&dummy_oofilter);
  rc = oof_socket_add(fm, &dummy_oofilter,
                      OOF_SOCKET_ADD_FLAG_CLUSTERED |
                      OOF_SOCKET_ADD_FLAG_DUMMY |
                      OOF_SOCKET_ADD_FLAG_NO_STACK,
                      protocol, sock_af_space(sock),
                      laddr, trb->port_be16, raddr, 0,
                      &ported_thc);
  if( rc < 0 ) /* non-clustered socket on the tuple */
    goto alloc_fail0;
  /* if ported_thc != NULL, oof_socket_add added reference to the cluster */

  /* Caveat: this call can drop and retake [thc_mutex]. */
  rc = thc_search_by_name(trb->cluster_name, ni->cplane->cp_netns, protocol,
                          trb->port_be16, ci_geteuid(), name,
                          trb->cluster_restart_opt, ported_thc, &thc);

  if( ported_thc != NULL )
    /* We do not need the reference from oof_socket_add() as we have second
     * one from thc_search_by_name() if ported_thc == thc, or ported_thc is
     * unusable.  If the reference that we free is not the last one, then we
     * can continue to dereference ported_thc as there must be at least one
     * other reference, and we hold the cluster locks. */
    if( tcp_helper_cluster_release_locked(ported_thc, NULL) )
      ported_thc = NULL;

  if( rc < 0 && rc != -ENOENT )
    goto alloc_fail;

  if( strlen(trb->cluster_name) > 0 ) {
    /* user requested a cluster by name.  But we need to make sure
     * that the oof_local_port that the user is interested in is not
     * being used by another cluster.  We search for cluster by name
     * and use results of prior protp:port[:ip] search oof_local_port
     * to then do some sanity checking.
     */

    /* If search by port and by name were both successful, and match,
     * user would be trying to add to a cluster they know about,
     * which probably means this is genuine clustering behaviour.
     * If a port is in use but the name isn't found, some other
     * cluster/socket is already on the port.
     * If name is found but there's no port, suggests cluster is in
     * use on different port(s).
     * If neither search is successful, then no cluster exists and
     * nobody has claimed the port yet, so go ahead and allocate a
     * stack to claim it.
     */
    if( rc == -ENOENT ) {
      if( ported_thc != NULL ) {
        /* search by oof_local_port found a cluster which search by
         * name didn't find. */
        LOG_E(ci_log("Error: Cluster with requested name %s already "
                     "bound to %s", name, ported_thc->thc_name));
        rc = -EEXIST;
        goto alloc_fail;
      }
      else {
        /* Neither searches found a cluster.  So allocate one below.
         */
      }
    }
    else {
      if( ported_thc != NULL ) {
        /* Both searches found clusters.  Fine if they are the same or
         * else error. */
        if( thc != ported_thc ) {
          LOG_E(ci_log("Error: Cluster %s does not handle socket %s:%d.  "
                       "Cluster %s does", name, FMT_PROTOCOL(protocol),
                       trb->port_be16, thc->thc_name));
          /* release outstanding thc_search_by_name() reference */
          tcp_helper_cluster_release_locked(thc, NULL);
          rc = -EEXIST;
          goto alloc_fail;
        }
      }
      /* Search by name found a cluster no conflict with search by tuple
       * (the ported cluster is either none or the same as named)*/
      goto cont;
    }
  }
  else {
    /* No cluster name requested.  We have already looked for a cluster handling
     * the tuple.  If none found, then try to use an existing
     * cluster this process created.  If none found, then allocate one.
     */
    /* If ported_thc == NULL, then no cluster found - try to allocate one.
     * If ported_thc != NULL, we found cluster - make sure that euids match and
     * continue.  The latter includes the case of hot restarts.
     */
    if( ported_thc != NULL ) {
      /* We know that the caller didn't specify a cluster name, so we should
       * have fallen back to [ported_thc]. */
      ci_assert_equal(rc, 0);
      ci_assert_equal(thc, ported_thc);
      if( thc->thc_keuid != ci_geteuid() ) {
        /* release the reference from thc_search_by_name() */
        tcp_helper_cluster_release_locked(thc, NULL);
        rc = -EADDRINUSE;
        goto alloc_fail;
      }
    }
    if( rc == 0 )
      goto cont; /* move on with thc reference from thc_search_by_name() */
  }
  /* When an interface is in tproxy mode, all clustered listening socket
   * are assumed to be part of tproxy passive side.  This requires
   * rss context to use altered rss hashing based solely on src ip:port.
   */
  flags = tcp_helper_cluster_thc_flags(&NI_OPTS(ni));

  if( (rc = thc_alloc(name, protocol, trb->port_be16, ci_geteuid(),
                      trb->cluster_size, NI_OPTS(ni).tcp_shared_local_ports,
                      CI_MAX(NI_OPTS(ni).tcp_shared_local_ports,
                             NI_OPTS(ni).tcp_shared_local_ports_max),
                      flags, netns, &thc)) != 0 )
      goto alloc_fail;

  alloced = 1;

 cont:
  /* At this point we have our cluster with one additional reference */
  /* We should be using a cluster in the correct namespace for this socket */
  ci_assert_equal(netns, oo_filter_ns_to_netns(thc->thc_filter_ns));

  if( trb->cluster_hot_restart_opt != 0 ) {
    /* Record state in case alloc fails in reheat mode. */
    reheat_state.thc_reheat_flags   = thc->thc_reheat_flags;
    reheat_state.thc_switch_port    = thc->thc_switch_port;
    reheat_state.thc_switch_addr    = thc->thc_switch_addr;
    reheat_state.thr_prior_index    = -1;
    reheat_state.thc_tid_effective  = -1;
  }

  /* Find a suitable stack within the cluster to use */
  rc = trb->cluster_hot_restart_opt == 0 ?
    thc_get_thr(thc, &dummy_oofilter, &thr) :
    thc_get_thr_reheat(thc, trb->addr, trb->port_be16,
                       &reheat_state.thr_prior_index,
                       &reheat_state.thc_tid_effective, &thr);
  if( rc != 0 ) {
    int drop_flags = CI_NETIF_FLAG_DO_DROP_SHARED_LOCAL_PORTS;
    /* For scalable active we want shared local ports.  This doesn't work for
     * tproxy because the RSS hashing used by the NIC doesn't match that
     * expected by the shared local ports code. */
    if( thc_is_scalable(thc->thc_flags) &&
        ! (thc->thc_flags & THC_FLAG_TPROXY) )
      drop_flags = 0;
    rc = thc_alloc_thr(thc, trb->cluster_restart_opt,
                       trb->cluster_hot_restart_opt,
                       &ni->opts,
                       ni->flags | drop_flags,
                       &thr);
  }

  /* Both the above failed, meaning every stack in the cluster is in use,
   * and there are no free stacks slots left.
   *
   * If in hot restart mode, roll back.
   */
  if( rc < 0 ) {
    if( trb->cluster_hot_restart_opt != 0 ) {
      /* Restore state after alloc failure in reheat mode. */
      thc->thc_reheat_flags = reheat_state.thc_reheat_flags;
      thc->thc_switch_port  = reheat_state.thc_switch_port;
      thc->thc_switch_addr  = reheat_state.thc_switch_addr;
      if( reheat_state.thr_prior_index != -1 )
        thc->thc_thr_rrobin[reheat_state.thr_prior_index]->thc_tid_effective =
          reheat_state.thc_tid_effective;
      thc->thc_thr_rrobin_index = thc_get_prior_round_robin_index(thc);
      thc->thc_thr_rrobin[thc->thc_thr_rrobin_index] = NULL;
    }
    else if( (-EBUSY == rc) || (-ENOSPC == rc) ) {
      LOG_TC(ci_log("Unable to bind to port %d. "
                    "If you need hot/seamless restarts, please use "
                    "EF_CLUSTER_HOT_RESTART=1.",
                    trb->port_be16
                   ));
    }
  }

  /* If get, alloc, or reheat succeeded, thr holds reference to the cluster,
   * so the cluster cannot go away.  We'll drop our reference and also
   * will not be accessing state within the cluster anymore so we can
   * drop the lock. */
  mutex_unlock(&thc_mutex);

  if( alloced && rc == 0 && thc_is_scalable(flags) ) {
    /* Tproxy filter is allocated as late as here,
     * the reason is that this needs to be preceded by stack allocation
     * (firmware needs initialized vi) */
    rc = thc_install_tproxy(thc, &NI_OPTS(ni));
    if( rc != 0 )
      oo_thr_ref_drop(thr->ref, OO_THR_REF_APP);
  }

  tcp_helper_cluster_release(thc, NULL);

  if( rc != 0 ) {
    oof_socket_del(fm, &dummy_oofilter);
    goto alloc_fail_unlocked;
  }

  /* We have thr and we hold single reference to it. */

  /* Move the socket into the new stack */
  if( (rc = ci_netif_lock(ni)) != 0 )
    goto drop_and_done;

  /* we hold:
   * * lock on the old socket,
   * * lock on the old stack,
   * * reference to the destination stack (thr) */

  /* thr referencing scheme comes from efab_file_move_to_alien_stack_rsop */
  rc = oo_thr_ref_get(thr->ref, OO_THR_REF_APP);
  if( rc != 0 ) {
    ci_netif_unlock(ni);
    goto drop_and_done;
  }
  rc = efab_file_move_to_alien_stack(priv, &thr->netif, 0, &new_sock_id);
  if( rc != 0 ) {
    oo_thr_ref_drop(thr->ref, OO_THR_REF_APP);
    do_sock_unlock = 0;
    /* both sockets are unlocked, and there is still single reference to thr */
  }
  else {
    /* both the new socket and the destination stack are locked */
    /* beside us, socket now holds its own reference to thr */
    waitable = SP_TO_WAITABLE(&thr->netif, new_sock_id);
    oofilter = &ci_trs_ep_get(thr, new_sock_id)->oofilter;
    oof_socket_replace(fm, &dummy_oofilter, oofilter);
    SP_TO_SOCK(&thr->netif, new_sock_id)->s_flags |= CI_SOCK_FLAG_FILTER;
    ci_netif_unlock(&thr->netif);

    /* we hold:
     * * two references to thr, of which one belongs to the new socket
     * * lock on the new socket
     * we have just unlocked thr */
  }

 drop_and_done:
  if( rc != 0 )
    oof_socket_del(fm, &dummy_oofilter);
  /* Drop the reference we got from thc_get_thr or thc_alloc_thr().
   * If things went wrong both stack and cluster might disappear. */
  oo_thr_ref_drop(thr->ref, OO_THR_REF_APP);
  oof_socket_dtor(&dummy_oofilter);
  mutex_unlock(&thc_init_mutex);
unlock_sock:
  /* Only unlock if the socket was locked in the first place */
  if( do_sock_unlock != 0 )
    ci_sock_unlock(ni, waitable);
  return rc;

 alloc_fail:
  oof_socket_del(fm, &dummy_oofilter);
 alloc_fail0:
  mutex_unlock(&thc_mutex);
 alloc_fail_unlocked:
  oof_socket_dtor(&dummy_oofilter);
  mutex_unlock(&thc_init_mutex);
  ci_sock_unlock(ni, waitable);
  return rc;
}



/****************************************************************
Cluster dump functions
*****************************************************************/


static void thc_dump_sockets(ci_netif* netif, oo_dump_log_fn_t log,
                             void* log_arg)
{
  unsigned id;
  for( id = 0; id < netif->state->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, id);
    if( wo->waitable.state != CI_TCP_STATE_FREE ) {
      citp_waitable* w = &wo->waitable;
      ci_sock_cmn* s = CI_CONTAINER(ci_sock_cmn, b, w);
      log(log_arg, "    %s lcl="OOF_IPXPORT" rmt="OOF_IPXPORT,
          citp_waitable_type_str(w),
          OOFA_IPXPORT(sock_ipx_laddr(s), sock_lport_be16(s)),
          OOFA_IPXPORT(sock_ipx_raddr(s), sock_rport_be16(s)));
    }
  }
}


static void thc_dump_thrs(tcp_helper_cluster_t* thc, oo_dump_log_fn_t log,
                          void* log_arg)
{
  ci_dllink* link;

  log(log_arg, "stacks:");
  CI_DLLIST_FOR_EACH(link, &thc->thc_thr_list) {
    tcp_helper_resource_t* walk = CI_CONTAINER(tcp_helper_resource_t,
                                               thc_thr_link, link);
    log(log_arg, "  name=%s  id=%d  tid=%d", walk->name, walk->id,
        walk->thc_tid);
    thc_dump_sockets(&walk->netif, log, log_arg);
  }
}


static void thc_dump_fn(void* not_used, oo_dump_log_fn_t log, void* log_arg)
{
  ci_irqlock_state_t lock_flags;
  tcp_helper_cluster_t* walk;
  int cnt = 0;

  /* Iterating over list of stacks, make sure they don't change. */
  mutex_lock(&thc_mutex);
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);

  walk = thc_head;
  while( walk != NULL ) {
    int hwports = 0;
    int i;
    for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i )
      if( walk->thc_vi_set[i] != NULL )
        hwports |= (1 << i);
    log(log_arg, "--------------------------------------------------------");
    log(log_arg, "%d: name=%s  size=%d  euid=%d flags=%d hwports=0x%x", cnt++,
        walk->thc_name, walk->thc_cluster_size,
        ci_current_from_kuid_munged(walk->thc_keuid),
        walk->thc_flags, hwports);
    thc_dump_thrs(walk, log, log_arg);
    walk = walk->thc_next;
  }

  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  mutex_unlock(&thc_mutex);
}


int tcp_helper_cluster_dump(tcp_helper_resource_t* thr, void* buf, int buf_len)
{
  return oo_dump_to_user(thc_dump_fn, NULL, buf, buf_len);
}
#endif
