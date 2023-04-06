/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: ctk
**     Started: 2004/03/15
** Description: TCP helper resource
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_driver_efab */
#include <ci/internal/transport_config_opt.h>
#include <onload_kernel_compat.h>
#include <onload/linux_onload_internal.h>
#include <onload/linux_onload.h>
#include <onload/linux_ip_protocols.h>
#include <ci/driver/kernel_compat.h>
#include <ci/efch/mmap.h>
#include <onload/mmap.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/driverlink_filter.h>
#include <onload/version.h>
#include <onload/version_check.h>

#include <etherfabric/timer.h>
#include <etherfabric/internal/internal.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/efhw/nic.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/vi_set.h>
#include <ci/efrm/slice_ext.h>
#include <ci/efrm/efct_rxq.h>
#include <ci/driver/efab/hardware.h>
#include <onload/oof_onload.h>
#include <onload/oof_interface.h>
#include <onload/nic.h>
#include <onload/cplane_modparam.h>
#include <onload/netif_dtor.h>
#include <ci/internal/pio_buddy.h>
#include <onload/tmpl.h>
#include <onload/dshm.h>
#include <ci/net/ipv4.h>
#include <ci/internal/more_stats.h>
#include <ci/internal/crc_offload_prefix.h>
#include "tcp_helper_resource.h"
#include "tcp_helper_stats_dump.h"
#include <onload/tcp-ceph.h>
#include <onload/tx_plugin.h>

#ifdef NDEBUG
# define DEBUG_STR  ""
#else
# define DEBUG_STR  " debug"
#endif

#if CI_CFG_PKT_BUF_SIZE == EFHW_NIC_PAGE_SIZE
#define HW_PAGES_PER_SET_S CI_CFG_PKTS_PER_SET_S
#define PKTS_PER_HW_PAGE 1
#elif CI_CFG_PKT_BUF_SIZE * 2 == EFHW_NIC_PAGE_SIZE
#define HW_PAGES_PER_SET_S (CI_CFG_PKTS_PER_SET_S - 1)
#define PKTS_PER_HW_PAGE 2
#elif CI_CFG_PKT_BUF_SIZE * 4 == EFHW_NIC_PAGE_SIZE
#define HW_PAGES_PER_SET_S (CI_CFG_PKTS_PER_SET_S - 2)
#define PKTS_PER_HW_PAGE 4
#else
#error "Unknown value for CI_CFG_PKT_BUF_SIZE"
#endif

/* Sentinel value indicating that an entry in the table of lists of ephemeral
 * ports is empty.  We can't use laddr field, because it may be IPv6, which
 * is unwieldy.  We use port_count field instead. */
#define EPHEMERAL_PORT_LIST_NO_PORT ((uint32_t) -1)


#define EFAB_THR_MAX_NUM_INSTANCES  0x00010000

static const unsigned EFCT_HUGEPAGES_PER_RXQ = 2;  /* EFCT TODO: un-hardcode */

/* Provides upper limit to EF_MAX_PACKETS. default is 512K packets,
 * which equates to roughly 1GB of memory 
 */
static unsigned max_packets_per_stack = 0x80000;
module_param(max_packets_per_stack, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(max_packets_per_stack,
                 "Limit the number of packet buffers that each Onload stack "
                 "can allocate.  This module option places an upper limit "
                 "on the EF_MAX_PACKETS option.  Changes to this module "
                 "option are not applied retrospectively to stacks already "
                 "existing before the change.");

static int allow_insecure_setuid_sharing;
module_param(allow_insecure_setuid_sharing, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(allow_insecure_setuid_sharing,
                 "Override default security rules and allow setuid processes "
                 "to map Onload stacks created by other users.");

#ifdef CONFIG_PREEMPT
unsigned long oo_avoid_wakeup_under_pressure = 1;
#else
unsigned long oo_avoid_wakeup_under_pressure = 0;
#endif
module_param(oo_avoid_wakeup_under_pressure, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_avoid_wakeup_under_pressure,
                 "Avoid endpoint wakeups for this number of jiffies after "
                 "NAPI budget limited interrupt handler.  This is typically "
                 "needed on realtime kernels, where you can see "
                 "\"stall on CPU\" messages when this value is set to 0.");
DEFINE_PER_CPU(unsigned long, oo_budget_limit_last_ts);

#if HZ < 100
# error FIXME: Not able to cope with low HZ at the moment.
#endif
  /* Periodic timer fires roughly 10 times per sec. */
#define CI_TCP_HELPER_PERIODIC_BASE_T  ((unsigned long)(HZ*9/100))
#define CI_TCP_HELPER_PERIODIC_FLOAT_T ((unsigned long)(HZ*1/100))
unsigned long periodic_poll = CI_TCP_HELPER_PERIODIC_BASE_T;
unsigned long periodic_poll_skew = CI_TCP_HELPER_PERIODIC_FLOAT_T;
module_param(periodic_poll, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(periodic_poll,
                 "Number of jiffies between periodic polls of "
                 "any Onload stack.  Defaults to 90ms.");
module_param(periodic_poll_skew, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(periodic_poll_skew,
                 "Allowed time skew for periodic polls.  "
                 "Defaults to 10ms.");


/* Global structure for onload driver */
efab_tcp_driver_t efab_tcp_driver;


static void
efab_tcp_helper_rm_free_locked(tcp_helper_resource_t*);
#if ! CI_CFG_UL_INTERRUPT_HELPER
static void
efab_tcp_helper_rm_schedule_free(tcp_helper_resource_t*);
#endif


#if ! CI_CFG_UL_INTERRUPT_HELPER
static int
oo_handle_wakeup_int_driven(void*, int is_timeout,
                            struct efhw_nic*, int budget);
static int
oo_handle_wakeup_or_timeout(void*, int is_timeout,
                            struct efhw_nic*, int budget);
static void
tcp_helper_initialize_and_start_periodic_timer(tcp_helper_resource_t*);
static void
tcp_helper_stop_periodic_work(tcp_helper_resource_t*);

static void
tcp_helper_close_pending_endpoints(tcp_helper_resource_t*);
#endif

#if CI_CFG_NIC_RESET_SUPPORT
static void
tcp_helper_purge_txq_work(struct work_struct *data);

static void
tcp_helper_reset_stack_work(struct work_struct *data);
#endif

#if CI_CFG_EPOLL3
static void
get_os_ready_list(tcp_helper_resource_t* thr, int ready_list);
#endif

static void
efab_tcp_helper_drop_os_socket(tcp_helper_resource_t* trs,
                               tcp_helper_endpoint_t* ep);

/* Allocate a block of IDs from the pool of ID blocks */
static int efab_ipid_alloc(efab_ipid_cb_t* ipid);

/* Release a block of IDs previosuly allocated through efab_ipid_alloc().
 * Base MUST be the base address returned by efab_ipid_alloc(). */
static int efab_ipid_free(efab_ipid_cb_t* ipid, int base);

#if ! CI_CFG_UL_INTERRUPT_HELPER
/*----------------------------------------------------------------------------
 *
 * oo_trusted_lock
 *
 *---------------------------------------------------------------------------*/

ci_inline int
oo_trusted_lock_is_locked(tcp_helper_resource_t* trs)
{
  return trs->trusted_lock & OO_TRUSTED_LOCK_LOCKED;
}


static int
oo_trusted_lock_try_lock(tcp_helper_resource_t* trs)
{
  return trs->trusted_lock == OO_TRUSTED_LOCK_UNLOCKED &&
         ci_cas32u_succeed(&trs->trusted_lock, OO_TRUSTED_LOCK_UNLOCKED, 
                           OO_TRUSTED_LOCK_LOCKED);
}


/* Returns true if flags were set, or false if the lock was not locked.
 * NB. We ignore flags if AWAITING_FREE.
 */
static int
oo_trusted_lock_set_flags_if_locked(tcp_helper_resource_t* trs, unsigned flags)
{
  unsigned l;

  do {
    l = trs->trusted_lock;
    if( ! (l & OO_TRUSTED_LOCK_LOCKED) )
      return 0;
    if( l & OO_TRUSTED_LOCK_AWAITING_FREE )
      /* We must not set flags when AWAITING_FREE. */
      return 1;
  } while( ci_cas32_fail(&trs->trusted_lock, l, l | flags) );

  return 1;
}


/* returns 0 if unlocked,
 *         1 if unlock has been deferred
 * If has_shared is set both locks would get deferred.
 */
static int
oo_trusted_lock_drop(tcp_helper_resource_t* trs,
                     int in_dl_context, int has_shared)
{
  unsigned l;
  ci_uint64 sl_flags;
  ci_netif* ni = &trs->netif;

 again:
  l = trs->trusted_lock;
  ci_assert_flags(l, OO_TRUSTED_LOCK_LOCKED);

  if(CI_UNLIKELY( l & OO_TRUSTED_LOCK_AWAITING_FREE )) {
    /* We may be called from the stack workqueue, so postpone destruction
     * to the point where wq may be flushed */
    /* rm_free_locked expects trusted lock only
     * it is OK to defer shared lock to stack wq as rm free work
     * is run from global wq and flushes stack wq */
    if( has_shared )
      tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_UNLOCK_UNTRUSTED);
    efab_tcp_helper_rm_schedule_free(trs);
    return 1;
  }

  if( l == OO_TRUSTED_LOCK_LOCKED ) {
    if( ci_cas32_fail(&trs->trusted_lock, l, OO_TRUSTED_LOCK_UNLOCKED) ) {
      goto again;
    }
    return 0;
  }

#if ! CI_CFG_UL_INTERRUPT_HELPER
  if( l & OO_TRUSTED_LOCK_CLOSE_ENDPOINT ) {
    unsigned new_l = l & ~OO_TRUSTED_LOCK_CLOSE_ENDPOINT;
    if( ci_cas32_fail(&trs->trusted_lock, l, new_l) )
      goto again;

    if( has_shared ||
        ef_eplock_lock_or_set_flag(&trs->netif.state->lock,
                                   CI_EPLOCK_NETIF_CLOSE_ENDPOINT) ) {
      /* let's reset the shared lock flag to avoid flag ping pong */
      ef_eplock_clear_flags(&trs->netif.state->lock, CI_EPLOCK_NETIF_CLOSE_ENDPOINT);

      /* We've got both locks.  If in non-dl context, do the work, else
       * defer work and locks to workitem.
       */
      if( in_dl_context ) {
        /* the flag needs to be reinstated for atomic work to undertake the work */
        oo_trusted_lock_set_flags_if_locked(trs, OO_TRUSTED_LOCK_CLOSE_ENDPOINT);
        trs->netif.flags |= CI_NETIF_FLAG_IN_DL_CONTEXT;
        OO_DEBUG_TCPH(ci_log("%s: [%u] defer CLOSE_ENDPOINT to workitem",
                             __FUNCTION__, trs->id));
        tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_UNLOCK_TRUSTED);
        return 1;
      }
      OO_DEBUG_TCPH(ci_log("%s: [%u] CLOSE_ENDPOINT now",
                           __FUNCTION__, trs->id));
      tcp_helper_close_pending_endpoints(trs);
      if( ! has_shared )
        efab_eplock_unlock_and_wake(ni, in_dl_context);
    }
    else {
      /* Untrusted lock holder now responsible for invoking non-atomic work. */
      OO_DEBUG_TCPH(ci_log("%s: [%u] defer CLOSE_ENDPOINT to untrusted lock",
                           __FUNCTION__, trs->id));
    }
    goto again;
  }

  if( l & OO_TRUSTED_LOCK_OS_READY ) {
#if CI_CFG_EPOLL3
    int i, tmp;
#endif
    unsigned new_l = l & ~OO_TRUSTED_LOCK_OS_READY;
    if( ci_cas32_fail(&trs->trusted_lock, l, new_l) )
      goto again;
    if( has_shared ||
       ef_eplock_lock_or_set_flag(&trs->netif.state->lock,
                                   CI_EPLOCK_NETIF_NEED_WAKE) ) {
      /* We've got both locks, do the work now. */
      OO_DEBUG_TCPH(ci_log("%s: [%u] OS READY now",
                           __FUNCTION__, trs->id));

#if CI_CFG_EPOLL3
      CI_READY_LIST_EACH(trs->netif.state->ready_lists_in_use, tmp, i) {
        get_os_ready_list(trs, i);
        if( ! oo_p_dllink_is_empty(&trs->netif,
                oo_p_dllink_ptr(&trs->netif,
                                &trs->netif.state->ready_lists[i])) )
          ci_waitable_wakeup_all(&trs->ready_list_waitqs[i]);
      }
#endif

      if( ! has_shared )
        efab_eplock_unlock_and_wake(ni, in_dl_context);
    }
    else {
      /* Untrusted lock holder now responsible for invoking work. */
      OO_DEBUG_TCPH(ci_log("%s: [%u] defer OS READY WAKE to trusted lock",
                           __FUNCTION__, trs->id));
    }
    goto again;
  }
#endif

  sl_flags = 0;
  if( l & OO_TRUSTED_LOCK_NEED_POLL )
    sl_flags |= CI_EPLOCK_NETIF_NEED_POLL;
  if( l & OO_TRUSTED_LOCK_NEED_PRIME )
    sl_flags |= CI_EPLOCK_NETIF_NEED_PRIME;
  if( l & OO_TRUSTED_LOCK_SWF_UPDATE )
    sl_flags |= CI_EPLOCK_NETIF_SWF_UPDATE;
  if( l & OO_TRUSTED_LOCK_PURGE_TXQS )
    sl_flags |= CI_EPLOCK_NETIF_PURGE_TXQS;
#if CI_CFG_HANDLE_ICMP
  if( l & OO_TRUSTED_LOCK_HANDLE_ICMP )
    sl_flags |= CI_EPLOCK_NETIF_HANDLE_ICMP;
#endif
  if( l & OO_TRUSTED_LOCK_PRIME_IF_IDLE )
    sl_flags |= CI_EPLOCK_NETIF_PRIME_IF_IDLE;
  ci_assert(sl_flags != 0);
  if( ci_cas32_succeed(&trs->trusted_lock, l, OO_TRUSTED_LOCK_LOCKED) ) {
    if( has_shared )
      ef_eplock_holder_set_flags(&trs->netif.state->lock, sl_flags);
    else if ( ef_eplock_trylock_and_set_flags(&trs->netif.state->lock, sl_flags) )
      efab_eplock_unlock_and_wake(ni, in_dl_context);
  }
  goto again;
}


#if ! CI_CFG_UL_INTERRUPT_HELPER
/* Returns true if the lock is obtained, or false otherwise.
 * The flags will be set (unless AWAITING_FREE).
 */
static int
oo_trusted_lock_lock_and_set_flags(tcp_helper_resource_t* trs, unsigned flags)
{
  unsigned l, new_l;

  do {
    l = trs->trusted_lock;
    if( l == OO_TRUSTED_LOCK_UNLOCKED )
      new_l = OO_TRUSTED_LOCK_LOCKED | flags;
    else if( l & OO_TRUSTED_LOCK_AWAITING_FREE )
      return 0;
    else
      new_l = l | flags;
  } while( ci_cas32_fail(&trs->trusted_lock, l, new_l) );

  return l == OO_TRUSTED_LOCK_UNLOCKED;
}
#endif


/*----------------------------------------------------------------------------
 *
 * efab_tcp_helper_netif_try_lock() etc.
 *
 *---------------------------------------------------------------------------*/

int
efab_tcp_helper_netif_try_lock(tcp_helper_resource_t* trs, int in_dl_context)
{
  if( oo_trusted_lock_try_lock(trs) ) {
    ci_netif* ni = &trs->netif;
    if( ci_netif_trylock(&trs->netif) ) {
      ci_assert( ! (ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT) );
      if( in_dl_context )
        ni->flags |= CI_NETIF_FLAG_IN_DL_CONTEXT;
      return 1;
    }
    oo_trusted_lock_drop(trs, in_dl_context, 0 /* has_shared */);
  }
  return 0;
}


void
efab_tcp_helper_netif_unlock(tcp_helper_resource_t* trs, int in_dl_context)
{
  ci_assert_equiv(in_dl_context, trs->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT);
#if 0
  /* See ON-13698 & ON-13099: we want it to be true, but it fires for now. */
  ci_assert_impl(trs->netif.flags & CI_NETIF_FLAGS_AVOID_ATOMIC, !in_dl_context);
#endif

  if( in_dl_context )
    trs->netif.flags &= ~CI_NETIF_FLAG_IN_DL_CONTEXT;
  /* We drop trusted lock first as this allow to drain trusted lock work
   * and pass flags to shared lock without lock/flag flipping
   * also in case atomic work is inevitable - it will quickly schedule the work
   * with both locks held.
   */
  if( oo_trusted_lock_drop(trs, in_dl_context, 1 /* has_shared */) == 0 )
    efab_eplock_unlock_and_wake(&trs->netif, in_dl_context);
}


/* Returns 1 if the locks are held, or 0 if not and the flags are set. 
 *   
 * NB if trusted lock has OO_TRUSTED_LOCK_AWAITING_FREE this function
 * will return 0, but the flags will not be set 
 */
int
efab_tcp_helper_netif_lock_or_set_flags(tcp_helper_resource_t* trs, 
                                        unsigned trusted_flags,
                                        ci_uint64 untrusted_flags,
                                        int in_dl_context)
{
  do {
    if( efab_tcp_helper_netif_try_lock(trs, in_dl_context) )
      return 1;
    if( ef_eplock_set_flags_if_locked(&trs->netif.state->lock, 
                                      untrusted_flags) )
      return 0;
    if( oo_trusted_lock_set_flags_if_locked(trs, trusted_flags) )
       return 0;
  } while( 1 );
}
#endif /* CI_CFG_UL_INTERRUPT_HELPER */


/*----------------------------------------------------------------------------
 *
 * tcp helpers table implementation
 *
 *---------------------------------------------------------------------------*/

static int thr_table_ctor(tcp_helpers_table_t *table)
{
  ci_dllist_init(&table->all_stacks);
  ci_dllist_init(&table->started_stacks);
  table->stack_count = 0;
  ci_irqlock_ctor(&table->lock);
  ci_id_pool_ctor(&table->instances, EFAB_THR_MAX_NUM_INSTANCES,
                  /* initial size */ 8);
  return 0;
}


#if ! CI_CFG_UL_INTERRUPT_HELPER
void tcp_helper_kill_stack(tcp_helper_resource_t *thr)
{
  ci_uint32 n_ep_orphaned;
  ci_netif* netif = &thr->netif;
  unsigned int timeout = 500;

  /* Timeout to lock netif should be increased for debug builds.
   * This is due to the fact that lock can be held for a long time
   * to print various log messages.
   */
#ifndef NDEBUG
  timeout = 2000;
#endif

  ci_assert_equal(thr->ref[OO_THR_REF_FILE], 0);

  /* Fixme: timeout is not appropriate here.  We should not leak OS socket
   * and filters.
   * And as all the UL have gone, it can't prevent us from taking the lock.
   */
  if( efab_eplock_lock_timeout(netif, msecs_to_jiffies(timeout)) == 0 ) {
    int id;
    for( id = 0; id < netif->state->n_ep_bufs; ++id ) {
      citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, id);
      if( wo->waitable.state == CI_TCP_TIME_WAIT ||
          ci_tcp_is_timeout_orphan(&wo->tcp) )
        wo->tcp.t_last_sent = ci_ip_time_now(netif);
    }
    ci_ip_timer_clear(netif, &netif->state->timeout_tid);
#if CI_CFG_TCP_OFFLOAD_RECYCLER
    ci_ip_timer_clear(netif, &netif->state->recycle_tid);
#endif
    ci_netif_timeout_state(netif);
    ci_netif_unlock(netif);
  }

  /* Atomically replace n_ep_orphaned by 0: the code which sets 0 is
   * responsible for decrementing refcount. */
  do {
    n_ep_orphaned = netif->n_ep_orphaned;
    if( n_ep_orphaned == 0 )
      break;
  } while( ci_cas32u_fail(&netif->n_ep_orphaned, n_ep_orphaned, 0) );

  if( n_ep_orphaned > 0 ) {
    ci_log("%s: ERROR: force-kill stack [%d]: "
           "leaking %d OS sockets and filters",
           __func__, thr->id, n_ep_orphaned);
#ifndef NDEBUG
    dump_stack_to_logger(&thr->netif, ci_log_dump_fn, NULL);
#endif
    oo_thr_ref_drop(thr->ref, OO_THR_REF_BASE);
  }
}
#endif


static void thr_table_dtor(tcp_helpers_table_t *table)
{
  /* Onload is going away, so kill off any remaining stacks. */

  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t* thr;
  ci_dllink* link;
  int rc;

  ci_irqlock_lock(&table->lock, &lock_flags);

  /* Gracefully shutdown all time-wait sockets */
  while( ci_dllist_not_empty(&table->all_stacks) ) {
    link = ci_dllist_pop(&table->all_stacks);
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    ci_dllink_mark_free(&thr->all_stacks_link);

    /* Get a ref to avoid races: thr should not disappear */
    rc = oo_thr_ref_get(thr->ref, OO_THR_REF_BASE);
    if( rc != 0 )
      continue;
    ci_irqlock_unlock(&table->lock, &lock_flags);

    if( thr->ref[OO_THR_REF_FILE] != 0 )
      ci_log("%s: ERROR: non-orphaned stack=%u ref "OO_THR_REF_FMT,
             __FUNCTION__, thr->id, OO_THR_REF_ARG(thr->ref));

#if ! CI_CFG_UL_INTERRUPT_HELPER
    OO_DEBUG_TCPH(ci_log("%s: killing stack %d", __FUNCTION__, thr->id));
    tcp_helper_kill_stack(thr);
#endif

    /* The only ref is ours.  Instead of releasing the ref, call dtor
     * directly. */
    tcp_helper_dtor(thr);
    ci_irqlock_lock(&table->lock, &lock_flags);
  }

  ci_irqlock_unlock(&table->lock, &lock_flags);
}



static
int efab_thr_table_check_name(const char* name, struct net* netns)
{
  /* Check that there is no name collision with already-existing stacks.
   */
  tcp_helpers_table_t* table = &THR_TABLE;
  tcp_helper_resource_t *thr2;
  ci_dllink *link;

  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr2 = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    if( netns == thr2->netif.cplane->cp_netns &&
        strncmp(thr2->netif.state->name, name, CI_CFG_STACK_NAME_LEN) == 0 &&
        thr2->ref[OO_THR_REF_APP] != 0 )
      return -EEXIST;
  }
  return 0;
}


int efab_thr_get_inaccessible_stack_info(unsigned id, uid_t* uid, uid_t* euid,
                                         ci_int32* share_with, char* name)
{
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t *thr;
  ci_dllink *link;
  int match;

  ci_irqlock_lock(&table->lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);

    match = thr->id == id;

    if( match ) {
      if( NI_OPTS(&thr->netif).share_with > 0 ) {
        /* Translate the share_with uid from the target stack's user_ns
         * to the kernel space.
         */
        uid_t kshare_with = ci_make_kuid(tcp_helper_get_user_ns(thr),
                                         NI_OPTS(&thr->netif).share_with);
        /* Then translate that into the user_ns of the requestor */
        *share_with = ci_current_from_kuid_munged(kshare_with);
      }
      else {
        /* Special value indicating either none (0) or all (-1) doesn't need
         * translation.
         */
        *share_with = NI_OPTS(&thr->netif).share_with;
      }
      *uid = ci_current_from_kuid_munged(thr->netif.kuid);
      *euid = ci_current_from_kuid_munged(thr->netif.keuid);
      memcpy(name, thr->name, sizeof(thr->name));
      ci_irqlock_unlock(&table->lock, &lock_flags);
      return 0;
    }
  }
  ci_irqlock_unlock(&table->lock, &lock_flags);
  return -ENODEV;
}


int efab_thr_user_can_access_stack(uid_t uid, uid_t euid,
                                   tcp_helper_resource_t* thr)
{
  uid_t kshare_with;

  if( /* bob and setuid-bob can access stacks created by bob or setuid-bob. */
      euid == thr->netif.keuid ||
      /* root can map any stack. */
      uid == 0 )
    return 1;

  kshare_with = ci_make_kuid(tcp_helper_get_user_ns(thr),
                             NI_OPTS(&thr->netif).share_with);
  if( /* Owner does not allow other users to map this stack. */
      kshare_with == 0 ||
      /* Stack can be shared with another user, but not this user. */
      (NI_OPTS(&thr->netif).share_with > 0 && euid != kshare_with) )
    return 0;

  /* By default we don't allow setuid processes to map other users' stacks,
   * because the setuid process could then be compromised.
   */
  return euid == uid || allow_insecure_setuid_sharing;
}

int efab_thr_can_access_stack(tcp_helper_resource_t* thr, int check_user)
{
  /* On entry, [check_user] tells us whether the calling code path requires
   * the user to be checked.  Some paths do not because the call is not
   * being made on behalf of a user.
   */

  if( /* We're not about to give a user access to the stack. */
     ! (check_user & EFAB_THR_TABLE_LOOKUP_CHECK_USER) )
    return 1;

  return efab_thr_user_can_access_stack(ci_getuid(), ci_geteuid(), thr);
}

/* 
 * If this returns 0 it will have taken a reference either through:
 * - efab_thr_ref(); or
 * - efab_tcp_helper_k_ref_count_inc() if it is an orphan;
 * 
 * It is up to the caller to drop the appropriate reference when safe
 * to do so.
 *
 * If you call without the EFAB_THR_TABLE_LOOKUP_NO_UL then
 * you only need to consider the efab_thr_ref() as you won't see
 * orphan stacks.  If you call with the EFAB_THR_TABLE_LOOKUP_NO_UL
 * flag then you only need to consider the
 * efab_tcp_helper_k_ref_count_inc() case as you won't see parented
 * stacks.
 */
int efab_thr_table_lookup(const char* name, struct net* netns,
                          unsigned id, int flags,
                          enum oo_thr_ref_type ref_type,
                          tcp_helper_resource_t** thr_p)
{
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t *thr;
  ci_dllink *link;
  int match, rc = -ENODEV;

  ci_assert(thr_p != NULL);
  ci_assert(flags == EFAB_THR_TABLE_LOOKUP_NO_CHECK_USER ||
            (flags & EFAB_THR_TABLE_LOOKUP_CHECK_USER));
  if( ref_type >= OO_THR_REF_FILE )
    ci_assert_flags(flags, EFAB_THR_TABLE_LOOKUP_CHECK_USER);

  ci_irqlock_lock(&table->lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);

    if( name ) {
      match = (strcmp(thr->name, name) == 0) &&
              (thr->netif.cplane->cp_netns == netns);
    }
    else {
      match = thr->id == id;
    }

    if( match ) {
      if( ! efab_thr_can_access_stack(thr, flags) ) {
        if( ! (flags & EFAB_THR_TABLE_LOOKUP_NO_WARN) ) {
          /* If we're in a context that stack access can fail, that implies
           * we're in a context where we have a current user namespace
           * (if user namespaces are supported).
           */
          uid_t kshare_with = ci_make_kuid(tcp_helper_get_user_ns(thr),
                                           NI_OPTS(&thr->netif).share_with);

          ci_log("User %d:%d can't share stack %d(%s) owned by %d:%d "
                 "share_with=%d",
                 ci_current_from_kuid_munged(ci_getuid()),
                 ci_current_from_kuid_munged(ci_geteuid()),
                 thr->id, thr->name,
                 ci_current_from_kuid_munged(thr->netif.kuid),
                 ci_current_from_kuid_munged(thr->netif.keuid),
                 NI_OPTS(&thr->netif).share_with > 0 ?
                 ci_current_from_kuid_munged(kshare_with) :
                 NI_OPTS(&thr->netif).share_with);
        }
        rc = -EACCES;
      }
      else if( (thr->ref[OO_THR_REF_FILE] != 0) !=
               ! (flags & EFAB_THR_TABLE_LOOKUP_NO_UL) ) {
        /* Orphan stacks flag does not match  */
        rc = -EBUSY;
      }
      else {
        /* Success */
        rc = oo_thr_ref_get(thr->ref, ref_type);
        *thr_p = thr;
      }
      break;
    }
  }
  ci_irqlock_unlock(&table->lock, &lock_flags);
  return rc;
}

static unsigned rescale(unsigned v, unsigned new_scale, unsigned old_scale)
{
  /* What we want:
   *   return (v * new_scale) / old_scale;
   *
   * Unfortunately we can overflow 32-bits, and 64-bit division is not
   * available in 32-bit x86 kernels.
   */
  while( fls(v) + fls(new_scale) > 32 ) {
    new_scale /= 2;
    old_scale /= 2;
  }
  if( old_scale == 0 )
    /* Breaks assumptions, so don't care that result is dumb. */
    old_scale = 1;
  return v * new_scale / old_scale;
}


static void tcp_helper_reduce_max_packets(ci_netif* ni, int new_max_packets)
{
  ci_assert_lt(new_max_packets, NI_OPTS(ni).max_packets);
  NI_OPTS(ni).max_rx_packets = rescale(NI_OPTS(ni).max_rx_packets,
                                     new_max_packets, NI_OPTS(ni).max_packets);
  NI_OPTS(ni).max_tx_packets = rescale(NI_OPTS(ni).max_tx_packets,
                                     new_max_packets, NI_OPTS(ni).max_packets);
  NI_OPTS(ni).max_packets = new_max_packets;
  if( ni->state != NULL ) {
    ni->state->opts.max_packets = NI_OPTS(ni).max_packets;
    ni->state->opts.max_rx_packets = NI_OPTS(ni).max_rx_packets;
    ni->state->opts.max_tx_packets = NI_OPTS(ni).max_tx_packets;
  }
}


#if ! CI_CFG_UL_INTERRUPT_HELPER
static int
__tcp_helper_kill_stack_by_id(unsigned id, unsigned ignore_id)
{
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t *thr = NULL;
  ci_dllink *link;
  int rc = -ENODEV;

  ci_irqlock_lock(&table->lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    if( ignore_id || thr->id == id ) {
      OO_DEBUG_TCPH(ci_log("Stack to release [%d]", thr->id));
      if( thr->ref[OO_THR_REF_APP] != 0 )
        break;
      rc = oo_thr_ref_get(thr->ref, OO_THR_REF_BASE);
      break;
    }
  }
  ci_irqlock_unlock(&table->lock, &lock_flags);

  if( rc == 0 ) {
    tcp_helper_kill_stack(thr);

    if( ignore_id )
      OO_DEBUG_TCPH(ci_log("Orphaned stack %d(%s) owned by %d:%d has been "
                           "released.",
                           thr->id, thr->name,
                           ci_current_from_kuid_munged(thr->netif.kuid),
                           ci_current_from_kuid_munged(thr->netif.keuid)));

    /* Remove reference we took in this function */
    oo_thr_ref_drop(thr->ref, OO_THR_REF_BASE);
  }

  return rc;
}

int tcp_helper_kill_stack_by_id(unsigned id)
{
  return __tcp_helper_kill_stack_by_id(id, 0);
}
#endif


void
tcp_helper_resource_assert_valid(tcp_helper_resource_t* thr, int no_ul,
                                 const char *file, int line)
{
  _ci_assert(thr, file, line);
  _ci_assert_nequal(thr->id, CI_ID_POOL_ID_NONE, file, line);
  _ci_assert_equal(thr->id, thr->netif.state->stack_id, file, line);

  if (no_ul >=0) {
    if ((no_ul && thr->ref[OO_THR_REF_FILE] > 0) ||
        (!no_ul && thr->ref[OO_THR_REF_FILE] == 0)) {
      ci_log("%s %d: %s check %u for %szero ul ref=%d", file, line,
             __FUNCTION__, thr->id, no_ul ? "" : "non-",
             thr->ref[OO_THR_REF_FILE]);
    }
    _ci_assert(no_ul || thr->ref[OO_THR_REF_FILE], file, line);
  }
}


int tcp_helper_rx_vi_id(tcp_helper_resource_t* trs, int hwport)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_HWPORTS);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 )
    return EFAB_VI_RESOURCE_INSTANCE(tcp_helper_vi(trs, intf_i));
  else
    return -1;
}


int tcp_helper_plugin_vi_id(tcp_helper_resource_t* trs, int hwport, int subvi)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_HWPORTS);
  ci_assert_lt((unsigned) subvi, ci_netif_num_vis(&trs->netif));
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 )
    return EFAB_VI_RESOURCE_INSTANCE(trs->nic[intf_i].thn_vi_rs[subvi]);
  else
    return -1;
}


int tcp_helper_vi_hw_stack_id(tcp_helper_resource_t* trs, int hwport)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_HWPORTS);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 ) {
    struct efrm_vi* vi = tcp_helper_vi(trs, intf_i);
    struct efrm_pd* pd = efrm_vi_get_pd(vi);
    return efrm_pd_stack_id_get(pd);
  }
  else
    return -1;
}


int tcp_helper_cluster_vi_hw_stack_id(tcp_helper_cluster_t* thc, int hwport)
{
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_HWPORTS);
  if( thc->thc_vi_set[hwport] != NULL ) {
    struct efrm_pd* pd = efrm_vi_set_get_pd(thc->thc_vi_set[hwport]);
    return efrm_pd_stack_id_get(pd);
  }
  else
    return -1;
}


int tcp_helper_cluster_vi_base(tcp_helper_cluster_t* thc, int hwport)
{
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_HWPORTS);
  if( thc->thc_vi_set[hwport] != NULL )
    return efrm_vi_set_get_base(thc->thc_vi_set[hwport]);
  else
    return -1;
}


int tcp_helper_vi_hw_rx_loopback_supported(tcp_helper_resource_t* trs,
                                           int hwport)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_HWPORTS);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 )
    return efrm_vi_is_hw_rx_loopback_supported(tcp_helper_vi(trs, intf_i));
  else
    return -1;
}


int tcp_helper_vi_hw_drop_filter_supported(tcp_helper_resource_t* trs,
                                           int hwport)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_HWPORTS);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 )
    return efrm_vi_is_hw_drop_filter_supported(tcp_helper_vi(trs, intf_i));
  else
    return -1;
}


void tcp_helper_get_filter_params(tcp_helper_resource_t* trs, int hwport,
                                  int* vi_id, int* rxq, unsigned *flags)
{
  int intf_i;
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_HWPORTS);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) >= 0 ) {
    ef_vi* vi = &trs->netif.nic_hw[intf_i].vis[0];
    *vi_id = EFAB_VI_RESOURCE_INSTANCE(tcp_helper_vi(trs, intf_i));
    if( NI_OPTS_TRS(trs).shared_rxq_num >= 0 ) {
      *rxq = NI_OPTS_TRS(trs).shared_rxq_num;
      *flags |= EFHW_FILTER_F_PREF_RXQ;
    }
    else if( vi->efct_shm ) {
      if( vi->efct_shm->q[0].superbuf_pkts ) {
        *rxq = vi->efct_shm->q[0].qid;
        *flags |= EFHW_FILTER_F_PREF_RXQ;
      }
      else {
        *flags |= EFHW_FILTER_F_ANY_RXQ;
      }
    }
  }
}


int tcp_helper_post_filter_add(tcp_helper_resource_t* trs, int hwport,
                               const struct efx_filter_spec* spec, int rxq,
                               bool replace)
{
  int intf_i;
  struct efhw_nic* nic;

  int hugepages = max(1, DIV_ROUND_UP(NI_OPTS_TRS(trs).rxq_size * EFCT_PKT_STRIDE, CI_HUGEPAGE_SIZE));
  ci_assert_lt((unsigned) hwport, CI_CFG_MAX_HWPORTS);
  if( (intf_i = trs->netif.hwport_to_intf_i[hwport]) < 0 )
    return 0;

  nic = efrm_client_get_nic(trs->nic[intf_i].thn_oo_nic->efrm_client);
  if( efhw_nic_max_shared_rxqs(nic) ) {
    struct efrm_vi* vi_rs = tcp_helper_vi(trs, intf_i);
    ef_vi* vi = ci_netif_vi(&trs->netif, intf_i);
    int qix;
    int rc;

    if( vi_rs->q[EFHW_RXQ].capacity == 0 )   /* e.g. EF_RXQ_SIZE=0 */
      return 0;

    ci_assert_ge(rxq, 0);
    /* We can be here either with or without the stack lock, depending on what
     * triggered the filter update. However, we are always called from oof
     * with fm_outer_lock held, which protects our qix between looking it up
     * and using it in the alloc. */
    qix = efct_vi_find_free_rxq(vi, rxq);
    if( qix == -EALREADY )
      return 0;

    rc = efrm_rxq_alloc(vi_rs, rxq, qix, true, hugepages,
                        trs->thc_efct_memfd, &trs->thc_efct_memfd_off,
                        &trs->nic[intf_i].thn_efct_rxq[qix]);
    if( rc < 0 ) {
      ci_log("%s: ERROR: efrm_rxq_alloc failed (%d)", __func__, rc);
      return rc;
    }
    efct_vi_start_rxq(vi, qix);

#if ! CI_CFG_UL_INTERRUPT_HELPER
    if( NI_OPTS(&trs->netif).int_driven ) {
      ci_bit_set(&trs->netif.state->evq_prime_deferred, intf_i);
      if( efab_tcp_helper_netif_lock_or_set_flags(trs,
               OO_TRUSTED_LOCK_NEED_POLL | OO_TRUSTED_LOCK_NEED_PRIME,
               CI_EPLOCK_NETIF_NEED_POLL | CI_EPLOCK_NETIF_NEED_PRIME, 0) ) {
        ef_eplock_holder_set_flag(&trs->netif.state->lock,
                                  CI_EPLOCK_NETIF_NEED_POLL |
                                  CI_EPLOCK_NETIF_NEED_PRIME);
        efab_tcp_helper_netif_unlock(trs, 0);
      }
    }
#endif
  }
  return 0;
}


#if CI_CFG_PIO

static int allocate_pio(tcp_helper_resource_t* trs, int intf_i, 
                        struct efrm_pd *pd, struct efhw_nic* nic,
                        unsigned *pio_buf_offset)
{
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  ci_netif_state_nic_t* nsn = &ns->nic[intf_i];
  ci_netif_nic_t *netif_nic = &trs->netif.nic_hw[intf_i];
  struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
  int rc = 0;

  if( nic->pio_num == 0 )
      return 0;

  if( trs_nic->thn_pio_rs == NULL ) {
    rc = efrm_pio_alloc(pd, &trs_nic->thn_pio_rs);
    if( rc < 0 ) {
      if( NI_OPTS(ni).pio == 1 ) {
        if( rc == -ENOSPC ) {
          NI_LOG(ni, RESOURCE_WARNINGS,
                 "[%s]: WARNING: all PIO bufs allocated to other stacks. "
                 "Continuing without PIO.  Use EF_PIO to control this.",
                 ns->pretty_name);
          return 0;
        }
        else {
          CI_NDEBUG( if( rc != -ENETDOWN && rc != -EPERM ) )
            /* ENETDOWN means absent hardware, so this failure is
             * expected, and we should not warn about it in NDEBUG
             * builds.  EPERM is expected on NICs that don't
             * support PIO.
             */
            NI_LOG(ni, RESOURCE_WARNINGS,
                   "[%s]: Unable to alloc PIO (%d), will continue without it",
                   ns->pretty_name, rc);
          return 0;
        }
      }
      else {
        OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_pio_alloc(%d) failed %d",
                             __FUNCTION__, intf_i, rc));
        return rc;
      }
    }
  }

  /* efrm_pio_alloc() success */
  rc = efrm_pio_link_vi(trs_nic->thn_pio_rs, tcp_helper_vi(trs, intf_i));
  if( rc < 0 ) {
    efrm_pio_release(trs_nic->thn_pio_rs, true);
    trs_nic->thn_pio_rs = NULL;
    if( NI_OPTS(ni).pio == 1 ) {
      NI_LOG(ni, RESOURCE_WARNINGS,
             "[%s]: Unable to link PIO (%d), will continue without it",
             ns->pretty_name, rc);
      return 0;
    }
    else {
      OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_pio_link_vi(%d) failed %d",
                           __FUNCTION__, intf_i, rc));
      return rc;
    }
  }
   
  /* efrm_pio_link_vi() success */
  rc = efrm_pio_map_kernel(tcp_helper_vi(trs, intf_i),
                           (void**) &netif_nic->pio.pio_io);
  if( rc < 0 ) {
    efrm_pio_unlink_vi(trs_nic->thn_pio_rs, tcp_helper_vi(trs, intf_i), NULL);
    efrm_pio_release(trs_nic->thn_pio_rs, true);
    trs_nic->thn_pio_rs = NULL;
    if( NI_OPTS(ni).pio == 1 ) {
      NI_LOG(ni, RESOURCE_WARNINGS,
             "[%s]: Unable to kmap PIO (%d), will continue without it",
             ns->pretty_name, rc);
      return 0;
    }
    else {
      OO_DEBUG_VM(ci_log("%s: ERROR: efrm_pio_map_kernel(%d) failed %d",
                         __FUNCTION__, intf_i, rc));
      return rc;
    }
  } 

  /* efrm_pio_map_kernel() success */
  /* Set up the pio struct so we can call ef_vi_pio_memcpy */
  netif_nic->pio.pio_buffer = 
    (uint8_t*)ns + ns->pio_bufs_ofs + *pio_buf_offset;
  netif_nic->pio.pio_len = efrm_pio_get_size(trs_nic->thn_pio_rs);
  /* Advertise that PIO can be used on this VI */
  nsn->oo_vi_flags |= OO_VI_FLAGS_PIO_EN;
  /* Advertise how should be mapped for this VI */
  ci_assert_le(netif_nic->pio.pio_len, CI_PAGE_SIZE);
  nsn->pio_io_mmap_bytes = CI_PAGE_SIZE;
  /* and how much of that mapping is usable */
  nsn->pio_io_len = netif_nic->pio.pio_len;
  /* and record a copy that UL can't modify */
  trs_nic->thn_pio_io_mmap_bytes = nsn->pio_io_mmap_bytes;
  netif_nic->vis[CI_Q_ID_NORMAL].linked_pio = &netif_nic->pio;
  trs->pio_mmap_bytes += CI_PAGE_SIZE;
  *pio_buf_offset += efrm_pio_get_size(trs_nic->thn_pio_rs);
  /* Drop original ref to PIO region as linked VI now holds it */ 
  efrm_pio_release(trs_nic->thn_pio_rs, true);
  /* Initialise the buddy allocator for the PIO region. */
  ci_pio_buddy_ctor(ni, &nsn->pio_buddy, nsn->pio_io_len);

  return 0;
}

#endif /* CI_CFG_PIO */


static void get_if_name(ci_netif* ni, int intf_i, char* buf_out)
{
  struct net_device* ndev = NULL;
  ci_hwport_id_t hwport = ni->intf_i_to_hwport[intf_i];
  int ifindex;

  memset(buf_out, 0, IFNAMSIZ);

  ifindex = oo_cp_hwport_vlan_to_ifindex(ni->cplane, hwport, 0, NULL);
  if( ifindex == 0 )
    goto no_dev;
  ndev = dev_get_by_index(&init_net, ifindex);
  if( !ndev )
    goto no_dev;

  memcpy(buf_out, ndev->name, IFNAMSIZ);
  dev_put(ndev);

  return;
 no_dev:

  /* cannot identify the device, let's produce a name */
  snprintf(buf_out, IFNAMSIZ, "noif/hwp0x%x", hwport);
}

/* Evaluates whether timestamping is to be enabled
 * based on respective netif options and NIC architecture.
 */
static int
check_timestamping_support(const char* stack_name, const char* dir,
                           int user_val, int device_supports_ts,
                           const char* if_name,
                           int* out_try_ts, int* out_retry_without)
{
  *out_try_ts = (user_val != 0);
  *out_retry_without = 0;
  if( ! device_supports_ts && (user_val == 3) ) {
    ci_log(
        "[%s]: %s timestamping not supported on given interface (%s)",
        stack_name, dir, if_name);
    return -ENOENT;
  }
  if( ! device_supports_ts && (user_val == 2) ) {
    ci_log(
      "[%s]: %s timestamping not supported on given interface (%s), "
      "continuing with timestamping disabled on this particular interface",
      stack_name, dir, if_name);
    *out_try_ts = 0;
  }
  if( user_val == 1 ) {
    *out_retry_without = 1; /* in case alloc fails do retry without ts*/
  }
  return 0;
}


static int allocate_pd(ci_netif* ni, struct vi_allocate_info* info,
                       struct efhw_nic* nic)
{
  int rc = 0;

  switch( NI_OPTS(ni).packet_buffer_mode ) {
  case 0:
    break;

  case CITP_PKTBUF_MODE_PHYS:
    info->ef_vi_flags |= EF_VI_RX_PHYS_ADDR | EF_VI_TX_PHYS_ADDR;
    break;

  default:
    rc = -EINVAL;
    return rc;
  }

  if( info->cluster == NULL ) {
    rc = efrm_pd_alloc(&info->pd, info->client,
        ((info->ef_vi_flags & EF_VI_RX_PHYS_ADDR) ?
            EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE : 0) |
        ((info->oo_vi_flags & OO_VI_FLAGS_TX_HW_LOOPBACK_EN) ?
            EFRM_PD_ALLOC_FLAG_HW_LOOPBACK : 0) );
    if( rc != 0 ) {
      OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_pd_alloc(%d) failed %d",
                         __FUNCTION__, info->intf_i, rc));
      return rc;
    }
    ci_assert(info->pd);
    info->release_pd = 1;
    info->vi_set = NULL;
  }
  else {
    int hwport = ni->intf_i_to_hwport[info->intf_i];
    ci_assert_ge(hwport, 0);
    info->vi_set = info->cluster->thc_vi_set[hwport];
    info->release_pd = 0;
    info->pd = efrm_vi_set_get_pd(info->vi_set);
  }

  return rc;
}

#if CI_CFG_CTPIO
static int /*bool*/ should_try_ctpio(ci_netif* ni, struct efhw_nic* nic,
                                     struct vi_allocate_info* info)
{
  return
    nic->flags & NIC_FLAG_CTPIO_ONLY ||
    /* Stack configured to use CTPIO. */
    (NI_OPTS(ni).ctpio > 0 &&
     /* NIC claims support for CTPIO. */
     (nic->flags & NIC_FLAG_TX_CTPIO) != 0 &&
     /* CTPIO bypasses the NIC's switch.  When the switch is enabled, don't use
      * CTPIO unless we've been told to do so explicitly. */
     (~nic->flags & NIC_FLAG_MCAST_LOOP_HW ||
      NI_OPTS(ni).ctpio_switch_bypass));
}
#endif

static int
get_vi_settings(ci_netif* ni, struct efhw_nic* nic,
                struct vi_allocate_info* info)
{
  char if_name[IFNAMSIZ];
  int rc;

  info->wakeup_cpu_core = NI_OPTS(ni).irq_core;
  info->log_resource_warnings = NI_OPTS(ni).log_category &
                              (1 << (EF_LOG_RESOURCE_WARNINGS));
  if( NI_OPTS(ni).irq_core < 0 && NI_OPTS(ni).irq_channel < 0 ) {
    info->wakeup_cpu_core = raw_smp_processor_id();
    info->log_resource_warnings = 0;
  }
  /* NICs that do not have the low-latency licensed feature (e.g. those with
   * a ScaleOut key) claim incorrectly that they support event cut-through.
   * They report correctly, however, that they do not support RX cut-through,
   * so we check for this here.
   * EF100 has different Rx merging mechanism and hasn't RX cut-through. */
  if( NI_OPTS(ni).rx_merge_mode ||
      (nic->devtype.arch != EFHW_ARCH_EF100 &&
       nic->devtype.arch != EFHW_ARCH_EFCT &&
       ! (nic->flags & NIC_FLAG_RX_CUT_THROUGH)) ) {
    info->efhw_flags |= HIGH_THROUGHPUT_EFHW_VI_FLAGS;
    info->ef_vi_flags |= EF_VI_RX_EVENT_MERGE;
  }

  if( nic->flags & NIC_FLAG_CTPIO_ONLY )
    info->oo_vi_flags |= OO_VI_FLAGS_TX_CTPIO_ONLY;
  else
    info->oo_vi_flags &=~ OO_VI_FLAGS_TX_CTPIO_ONLY;

  if( nic->flags & NIC_FLAG_RX_SHARED )
    info->oo_vi_flags |= OO_VI_FLAGS_RX_SHARED;
  else
    info->oo_vi_flags &=~ OO_VI_FLAGS_RX_SHARED;

  if( nic->flags & NIC_FLAG_HW_MULTICAST_REPLICATION )
    info->oo_vi_flags |= OO_VI_FLAGS_HW_MULTICAST_REPLICATION;
  else
    info->oo_vi_flags &=~ OO_VI_FLAGS_HW_MULTICAST_REPLICATION;

  if( (nic->flags & NIC_FLAG_MCAST_LOOP_HW) &&
      (NI_OPTS(ni).mcast_recv_hw_loop) ) {
    info->efhw_flags |= EFHW_VI_RX_LOOPBACK;
  } else {
    info->efhw_flags &= ~EFHW_VI_RX_LOOPBACK;
  }
  if( (nic->flags & NIC_FLAG_MCAST_LOOP_HW) &&
      (NI_OPTS(ni).mcast_send & CITP_MCAST_SEND_FLAG_EXT) ) {
    info->efhw_flags |= EFHW_VI_TX_LOOPBACK;
    info->oo_vi_flags |= OO_VI_FLAGS_TX_HW_LOOPBACK_EN;
#if CI_CFG_CTPIO
    if( should_try_ctpio(ni, nic, info) )
      NI_LOG(ni, CONFIG_WARNINGS,
             "[%s]: WARNING: Packets sent by CTPIO will not be looped back.",
             ni->state->pretty_name);
#endif
  } else {
    info->efhw_flags &= ~EFHW_VI_TX_LOOPBACK;
    info->oo_vi_flags &= ~OO_VI_FLAGS_TX_HW_LOOPBACK_EN;
  }

  info->try_ctpio = 0;
  info->retry_without_ctpio = 0;

  if( NI_OPTS(ni).af_xdp_zerocopy ) {
    if (nic->flags & NIC_FLAG_RX_ZEROCOPY) {
      info->ef_vi_flags |= EF_VI_RX_ZEROCOPY;
      info->efhw_flags |= EFHW_VI_RX_ZEROCOPY;
    } else {
      NI_LOG(ni, CONFIG_WARNINGS,
             "[%s]: WARNING: Zerocopy is required but NIC does not support it",
             ni->state->pretty_name);
    }
  }

#if CI_CFG_CTPIO
  if( should_try_ctpio(ni, nic, info) ) {
    info->try_ctpio = 1;
    info->retry_without_ctpio = NI_OPTS(ni).ctpio < 2 &&
                                ! (nic->flags & NIC_FLAG_CTPIO_ONLY);

    if( NI_OPTS(ni).ctpio_mode == EF_CTPIO_MODE_SF_NP ) {
      info->ef_vi_flags |= EF_VI_TX_CTPIO_NO_POISON;
      info->efhw_flags |= EFHW_VI_TX_CTPIO_NO_POISON;
    }
    if( NI_OPTS(ni).ctpio_mode == EF_CTPIO_MODE_CT )
      info->ctpio_threshold = NI_OPTS(ni).ctpio_ct_thresh;
    else
      info->ctpio_threshold = EF_VI_CTPIO_CT_THRESHOLD_SNF;
  }
  else {
    info->vi_ctpio_mmap_bytes = 0;
    if( NI_OPTS(ni).ctpio == 2 ) {
      char if_name[IFNAMSIZ];
      get_if_name(ni, info->intf_i, if_name);
      ci_log("[%s]: CTPIO is required, but interface %s does not support it.",
             ni->state->pretty_name, if_name);
      return -EINVAL;
    }
  }
#endif

  get_if_name(ni, info->intf_i, if_name);

  rc = check_timestamping_support(ni->state->pretty_name, "RX",
                                  NI_OPTS(ni).rx_timestamping,
                                  (nic->flags & NIC_FLAG_HW_RX_TIMESTAMPING) != 0,
                                  if_name,
                                  &info->try_rx_ts,
                                  &info->retry_without_rx_ts);

  if( rc == 0 )
    rc = check_timestamping_support(ni->state->pretty_name, "TX",
                                    NI_OPTS(ni).tx_timestamping,
                                    (nic->flags & NIC_FLAG_HW_TX_TIMESTAMPING) != 0,
                                    if_name,
                                    &info->try_tx_ts,
                                    &info->retry_without_tx_ts);

  return rc;
}


/* Function to find the orphaned stacks and release the resources
 * occupied by the this stack by kiling it so that it can be used
 * for allocation of new stack.
 * \return  Zero when stack has been released ENODEV otherwise */
static int find_and_release_orphaned_stack(void)
{
  int rc = -ENODEV;
#if ! CI_CFG_UL_INTERRUPT_HELPER
  rc = __tcp_helper_kill_stack_by_id(0, 1);

  if( rc == 0 ) {
    flush_workqueue(CI_GLOBAL_WORKQUEUE);
  }
#else
  /* TODO We should try to kill all the services which use some app-orphaned
   * stack */
#endif
  return rc;
}


static int allocate_vi(ci_netif* ni, struct vi_allocate_info* info,
                       struct efrm_vi *evq_virs, int q_tag)
{
  int rc = -EDOM;  /* Placate compiler. */
  unsigned evq_min;

  /* There are various VI flags that can be requested by the caller, and we
   * need to retry all combinations in the event of failure.  We achieve this
   * by building a table of all features, and then iterating over it using a
   * bitmap to indicate which set of features to attempt. */
  struct {
    int attempt;
    int retry_without;
    const char* description;
    enum ef_vi_flags ef_vi_flags;
    ci_uint32 efhw_flags;
    int oo_vi_flags;
  } features[] = {
    {
      .attempt = info->try_rx_ts,
      .retry_without = info->retry_without_rx_ts,
      .description = "RX timestamping",
      .ef_vi_flags = EF_VI_RX_TIMESTAMPS,
      .efhw_flags = EFHW_VI_RX_TIMESTAMPS | EFHW_VI_RX_PREFIX,
      .oo_vi_flags = OO_VI_FLAGS_RX_HW_TS_EN,
    },
    {
      .attempt = info->try_tx_ts,
      .retry_without = info->retry_without_tx_ts,
      .description = "TX timestamping",
      .ef_vi_flags = EF_VI_TX_TIMESTAMPS,
      .efhw_flags = EFHW_VI_TX_TIMESTAMPS,
      .oo_vi_flags = OO_VI_FLAGS_TX_HW_TS_EN,
    },
    {
      .attempt = info->try_ctpio,
      .retry_without = info->retry_without_ctpio,
      .description = "CTPIO",
      .ef_vi_flags = EF_VI_TX_CTPIO,
      .efhw_flags = EFHW_VI_TX_CTPIO,
      .oo_vi_flags = OO_VI_FLAGS_CTPIO_EN,
    },
  };
  const int feature_count = sizeof(features) / sizeof(features[0]);
  ci_uint32 feature_mask;
  ci_uint32 requested_feature_mask;
  ci_uint32 required_feature_mask;
  struct vi_allocate_info info_base;
  int i;
  size_t n_shm_rxqs;

  /* Choose DMA queue sizes, and calculate suitable size for EVQ. */
  evq_min = info->txq_capacity;
  if( ! (info->oo_vi_flags & OO_VI_FLAGS_RX_SHARED) )
    evq_min += info->rxq_capacity;
  for( info->evq_capacity = 512; info->evq_capacity <= evq_min;
       info->evq_capacity *= 2 )
    ;

  /* Build masks of the features that are required or requested. */
  requested_feature_mask = 0;
  required_feature_mask = 0;
  for( i = 0; i < feature_count; ++i )
    if( features[i].attempt ) {
      requested_feature_mask |= 1 << i;
      if( ! features[i].retry_without )
        required_feature_mask |= 1 << i;
    }
  ci_assert_equal(required_feature_mask & ~requested_feature_mask, 0);

  info_base = *info;
  feature_mask = requested_feature_mask;
  do {
    /* Skip any iterations that would attempt to enable a feature that was not
     * requested, or would not attempt a feature that was required. */
    if( feature_mask & ~requested_feature_mask ||
        ~feature_mask & required_feature_mask )
      continue;

    /* Build the flag fields from the mask of features. */
    *info = info_base;
    for( i = 0; i < feature_count; ++i )
      if( feature_mask & (1 << i) ) {
        info->ef_vi_flags |= features[i].ef_vi_flags;
        info->efhw_flags  |= features[i].efhw_flags;
        info->oo_vi_flags |= features[i].oo_vi_flags;
      }

    /* This is a loop to try double allocation. If it fails initialy an attempt
     * is made to find and release orphaned stack and try allocation again.  */
    for( i = 0; i < 2; ++i ) {
      rc = efrm_vi_resource_alloc(info->client, evq_virs, info->vi_set, -1,
                                  info->pd, info->name,
                                  info->efhw_flags,
                                  info->evq_capacity, info->txq_capacity,
                                  info->rxq_capacity, q_tag, q_tag,
                                  info->wakeup_cpu_core,
                                  info->wakeup_channel,
                                  info->virs,
                                  &info->vi_io_mmap_bytes,
                                  &info->vi_ctpio_mmap_bytes, NULL, NULL,
                                  info->log_resource_warnings);
      /* If we succeeded, there is no need to find and release orphan stack. */
      if( rc != -EBUSY )
        break;

      /* If first allocation returned EBUSY there is try to search and release
       * orphaned stack. If it succeed another allocation will be attempted.  */
      if( i == 0 && find_and_release_orphaned_stack() != 0 )
        break;
    }

    /* If we succeeded, we can break from the retry loop. */
    if( rc == 0 )
      break;

    if( feature_mask == required_feature_mask &&
        info_base.wakeup_cpu_core != NI_OPTS(ni).irq_core ) {
      /* Special case: if we've cut out all possible requested features and
       * still failed, our last-ditch effort is to stop trying to be clever
       * about the interrupt affinity.  In this case, and only in this case, do
       * we enable the warnings in the innards of the allocation functions. */
      info_base.wakeup_cpu_core = NI_OPTS(ni).irq_core;
      info_base.log_resource_warnings = NI_OPTS(ni).log_category &
                                        (1 << (EF_LOG_RESOURCE_WARNINGS));
      /* Fake out the loop counter to give us one more shot. */
      ++feature_mask;
    }
    /* Loop until we've tried the least-featureful permissible allocation,
     * taking care that we don't underflow. */
  } while( feature_mask && feature_mask-- >= required_feature_mask );

  n_shm_rxqs = efhw_nic_max_shared_rxqs(efrm_client_get_nic(info->client));
  info->vi_efct_shm_mmap_bytes =
        n_shm_rxqs ? CI_ROUND_UP(CI_EFCT_SHM_BYTES(n_shm_rxqs), PAGE_SIZE) : 0;

  if( rc < 0 ) {
    OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_vi_resource_alloc(%d) failed %d",
                         __FUNCTION__, info->intf_i, rc));
    if( info->release_pd )
      efrm_pd_release(info->pd);
  }
  else {
    /* Warn about any requested features that we didn't get. */
    for( i = 0; i < feature_count; ++i )
      if( features[i].attempt && ! (feature_mask & (1 << i)) ) {
        char if_name[IFNAMSIZ];
        get_if_name(ni, info->intf_i, if_name);
        ci_log("[%s]: enabling %s on interface %s failed, "
               "continuing with it disabled on this interface",
               ni->state->pretty_name, features[i].description, if_name);
      }
  }

  return rc;
}


static int tcp_helper_superbuf_config_refresh(ef_vi* vi, int qid)
{
  return efrm_rxq_refresh_kernel(vi->dh, vi->efct_shm->q[qid].qid,
                                 vi->efct_rxq[qid].superbufs);
}


static int initialise_vi(ci_netif* ni, struct ef_vi* vi, struct efrm_vi* vi_rs,
                         struct efrm_vi_mappings* vm, void* vi_state,
                         int vi_arch, int vi_variant, int vi_revision,
                         unsigned char vi_nic_flags,
                         struct vi_allocate_info* alloc_info,
                         unsigned* vi_out_flags, ef_vi_stats* vi_stats)
{
  uint32_t* vi_ids = (void*) ((ef_vi_state*) vi_state + 1);

  efrm_vi_get_mappings(vi_rs, vm);

  ef_vi_init(vi, vi_arch, vi_variant, vi_revision, alloc_info->ef_vi_flags,
             vi_nic_flags, (ef_vi_state*) vi_state);
  *vi_out_flags = (vm->out_flags & EFHW_VI_CLOCK_SYNC_STATUS) ?
                        EF_VI_OUT_CLOCK_SYNC_STATUS : 0;

  ef_vi_init_out_flags( vi, *vi_out_flags);
  ef_vi_init_io(vi, vm->io_page);
  ef_vi_init_timer(vi, vm->timer_quantum_ns);
  ef_vi_init_evq(vi, vm->evq_size, vm->evq_base);
  if( vm->rxq_size > 0 ) {
    ef_vi_init_rxq(vi, vm->rxq_size, vm->rxq_descriptors, vi_ids,
                   vm->rxq_prefix_len);
    vi_ids += vm->rxq_size;
  }
  else {
    /* efct_poll_rx() will crash if called when rx hasn't been inited, so
     * guarantee that it never will be even if somebody corrupts the shared
     * memory */
    vi->max_efct_rxq = 0;
  }
  if( vm->txq_size > 0 )
    ef_vi_init_txq(vi, vm->txq_size, vm->txq_descriptors, vi_ids);
  vi->vi_i = EFAB_VI_RESOURCE_INSTANCE(vi_rs);
  vi->dh = efrm_client_get_nic(vi_rs->rs.rs_client);
  if( vi->max_efct_rxq ) {
    int i;
    int rc = efct_vi_mmap_init_internal(vi, vi_rs->efct_shm);
    if( rc < 0 )
      return rc;
    for( i = 0; i < vi->max_efct_rxq; ++i )
      efct_vi_attach_rxq_internal(vi, i, -1 /* resource ID not needed */,
                                  tcp_helper_superbuf_config_refresh);
  }
  ef_vi_init_state(vi);
  ef_vi_set_stats_buf(vi, vi_stats);
  if( vm->txq_size || vm->rxq_size )
    ef_vi_add_queue(vi, vi);

  if( NI_OPTS(ni).tx_push )
    ef_vi_set_tx_push_threshold(vi, NI_OPTS(ni).tx_push_thresh);
  ef_vi_set_ts_format(vi, vm->ts_format);
  ef_vi_init_rx_timestamping(vi, vm->rx_ts_correction);
  ef_vi_init_tx_timestamping(vi, vm->tx_ts_correction);
  ef_vi_receive_set_discards(vi,
      EF_VI_DISCARD_RX_L4_CSUM_ERR |
      EF_VI_DISCARD_RX_L3_CSUM_ERR |
      EF_VI_DISCARD_RX_ETH_FCS_ERR |
      EF_VI_DISCARD_RX_ETH_LEN_ERR |
      EF_VI_DISCARD_RX_INNER_L3_CSUM_ERR |
      EF_VI_DISCARD_RX_INNER_L4_CSUM_ERR |
      EF_VI_DISCARD_RX_L2_CLASS_OTHER |
      EF_VI_DISCARD_RX_L3_CLASS_OTHER |
      EF_VI_DISCARD_RX_L4_CLASS_OTHER 
  );
  return 0;
}

/* callback from ef_vi->ops */
static int af_xdp_kick(ef_vi* vi)
{
  return efrm_vi_af_xdp_kick(vi->xdp_kick_context);
}

static int allocate_vis(tcp_helper_resource_t* trs,
                        ci_resource_onload_alloc_t* alloc,
                        void* vi_state, tcp_helper_cluster_t* thc)
{
  /* Format is "onload:pretty_name-intf_i"
   * Do not use slash in this name! */
  char vf_name[7 + CI_CFG_STACK_NAME_LEN+8 + 3];
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  int rc, intf_i;
#if CI_CFG_PIO
  unsigned pio_buf_offset = 0;
#endif
  /* vi allocation is done in several stages.  We build up the information
   * needed in this structure, and pass it to helper functions that use and
   * update the information as needed.
   */
  struct vi_allocate_info alloc_info;
  unsigned base_efhw_flags, base_ef_vi_flags;

  /* The user level netif build function calculates mapping offsets based on
   * the vi information.  If these values are non-zero here, that implies
   * something before vi creation is adding to these mappings, so the
   * netif build function will need updating.
   */
  ci_assert_equal(trs->buf_mmap_bytes, 0);
  ci_assert_equal(trs->io_mmap_bytes, 0);
#if CI_CFG_PIO
  ci_assert_equal(trs->pio_mmap_bytes, 0);
#endif
#if CI_CFG_CTPIO
  ci_assert_equal(trs->ctpio_mmap_bytes, 0);
#endif
  ci_assert_equal(trs->efct_shm_mmap_bytes, 0);

  /* Outside the per-interface loop we initialise some values that are common
   * across all interfaces.
   */
  alloc_info.wakeup_channel = NI_OPTS(ni).irq_channel,
  alloc_info.name = vf_name;
  alloc_info.cluster = thc;
  alloc_info.rxq_capacity = NI_OPTS(ni).rxq_size;

  /* The flags are slightly more complicated as they might be tweaked per-
   * interface.  These are the base values. */
  base_ef_vi_flags = EF_VI_ENABLE_EV_TIMER;
  base_efhw_flags = EFHW_VI_JUMBO_EN | EFHW_VI_ENABLE_EV_TIMER;

  if( ! NI_OPTS(ni).tx_push )
    base_ef_vi_flags |= EF_VI_TX_PUSH_DISABLE;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    int vi_i;
    for( vi_i = 0; vi_i < CI_MAX_VIS_PER_INTF; ++vi_i ) {
      trs->nic[intf_i].thn_vi_rs[vi_i] = NULL;
      trs->nic[intf_i].thn_vi_mmap_bytes[vi_i] = 0;
      ni->nic_hw[intf_i].vis[vi_i].efct_rxq[0].superbufs = NULL;
    }
#if CI_CFG_PIO
    trs->nic[intf_i].thn_pio_rs = NULL;
    trs->nic[intf_i].thn_pio_io_mmap_bytes = 0;
#endif
    memset(trs->nic[intf_i].thn_efct_rxq, 0,
           sizeof(trs->nic[intf_i].thn_efct_rxq));
  }

  /* This loop does the work of allocating a vi, using the information built
   * up in the alloc_info structure.  It then updates the nsn structure with
   * the resultant resource information.
   */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    ci_netif_state_nic_t* nsn = &ns->nic[intf_i];
    struct efhw_nic* nic =
      efrm_client_get_nic(trs_nic->thn_oo_nic->efrm_client);
    struct efrm_vi_mappings* vm = (void*) ni->vi_data;
    unsigned vi_out_flags = 0;
    struct device* dev;
    struct efrm_vi* vi_rs;
    ef_vi* vi;

    BUILD_BUG_ON(sizeof(ni->vi_data) < sizeof(struct efrm_vi_mappings));

    alloc_info.hwport_flags = 0;        /* Placate compiler. */

    /* Get interface properties. */
    rc = oo_cp_get_hwport_properties(ni->cplane, ns->intf_i_to_hwport[intf_i],
                                     &alloc_info.hwport_flags, NULL);
    if( rc < 0 )
      goto error_out;

    alloc_info.client = trs_nic->thn_oo_nic->efrm_client;
    alloc_info.pd = NULL;
    alloc_info.vi_set = NULL;
    alloc_info.release_pd = 0;
    alloc_info.intf_i = intf_i;
    alloc_info.oo_vi_flags = 0;
    alloc_info.efhw_flags = base_efhw_flags;
    alloc_info.ef_vi_flags = base_ef_vi_flags;

    ci_assert_equal(tcp_helper_vi(trs, intf_i), NULL);
    ci_assert(trs_nic->thn_oo_nic != NULL);
    ci_assert(alloc_info.client != NULL);

    snprintf(vf_name, sizeof(vf_name), "onload:%s-%d",
             ns->pretty_name, intf_i);

    rc = get_vi_settings(ni, nic, &alloc_info);
    if( rc != 0 )
      goto error_out;

    rc = allocate_pd(ni, &alloc_info, nic);
    if( rc != 0 )
      goto error_out;
    nsn->pd_owner = efrm_pd_owner_id(alloc_info.pd);

    alloc_info.virs = &trs_nic->thn_vi_rs[CI_Q_ID_NORMAL];
    alloc_info.txq_capacity = NI_OPTS(ni).txq_size;
    rc = allocate_vi(ni, &alloc_info, NULL, 0);
    if( rc != 0 )
      goto error_out;

    vi_rs = tcp_helper_vi(trs, intf_i);
    /* FIXME we should impose vi_set instance top down */
    if( thc ) {
      trs->thc_rss_instance = efrm_vi_set_get_vi_instance(vi_rs);
      ns->rss_instance = trs->thc_rss_instance;
      ns->cluster_size = thc->thc_cluster_size;
    }
    else {
      ns->cluster_size = 1;
    }

    vi = ci_netif_vi(ni, intf_i);
    rc = initialise_vi(ni, vi, tcp_helper_vi(trs, intf_i), vm,
                       vi_state, nic->devtype.arch, nic->devtype.variant,
                       nic->devtype.revision, efhw_vi_nic_flags(nic),
                       &alloc_info, &vi_out_flags, &ni->state->vi_stats);
    if( rc < 0 )
      goto error_out;

    vi->xdp_kick = af_xdp_kick;
    vi->xdp_kick_context = vi_rs;

    nsn->oo_vi_flags = alloc_info.oo_vi_flags;
    nsn->vi_io_mmap_bytes = alloc_info.vi_io_mmap_bytes;
    nsn->vi_efct_shm_mmap_bytes = alloc_info.vi_efct_shm_mmap_bytes;
#if CI_CFG_CTPIO
    nsn->ctpio_ct_threshold = alloc_info.ctpio_threshold;
    nsn->ctpio_max_frame_len = nsn->ctpio_frame_len_check =
      nsn->oo_vi_flags & OO_VI_FLAGS_CTPIO_EN ?
      NI_OPTS(ni).ctpio_max_frame_len : 0;
#endif
    dev = efrm_vi_get_dev(vi_rs);
    strncpy(nsn->dev_name, dev ? dev_name(dev) : "?", sizeof(nsn->dev_name));
    if( dev )
      put_device(dev);
    nsn->dev_name[sizeof(nsn->dev_name) - 1] = '\0';
    nsn->vi_instance[0] =
        (ci_uint16) EFAB_VI_RESOURCE_INSTANCE(vi_rs);
    nsn->vi_abs_idx[0] = efhw_nic_rel_to_abs_idx(nic, nsn->vi_instance[0]);
    nsn->vi_arch = (ci_uint8) nic->devtype.arch;
    nsn->vi_variant = (ci_uint8) nic->devtype.variant;
    nsn->vi_revision = (ci_uint8) nic->devtype.revision;
    nsn->vi_nic_flags = efhw_vi_nic_flags(nic);
    nsn->vi_channel = (ci_uint8)efrm_vi_get_channel(vi_rs);
    nsn->vi_flags = alloc_info.ef_vi_flags;
    nsn->vi_out_flags = vi_out_flags;
    nsn->vi_evq_bytes = efrm_vi_rm_evq_bytes(vi_rs, -1);
    nsn->vi_rxq_size = vm->rxq_size;
    nsn->vi_txq_size = vm->txq_size;
    nsn->timer_quantum_ns = vm->timer_quantum_ns;
    nsn->rx_prefix_len = vm->rxq_prefix_len;
    nsn->rx_ts_correction = vm->rx_ts_correction;
    nsn->tx_ts_correction = vm->tx_ts_correction;
    nsn->ts_format = vm->ts_format;
    if( ! (nic->flags & NIC_FLAG_USERSPACE_PRIME) )
      ni->state->flags |= CI_NETIF_FLAG_EVQ_KERNEL_PRIME_ONLY;

    trs->io_mmap_bytes += alloc_info.vi_io_mmap_bytes;
    trs->efct_shm_mmap_bytes += alloc_info.vi_efct_shm_mmap_bytes;
    vi_state = (char*) vi_state +
               ef_vi_calc_state_bytes(vm->rxq_size, vm->txq_size);

#if CI_CFG_CTPIO
    trs_nic->thn_ctpio_io_mmap_bytes = alloc_info.vi_ctpio_mmap_bytes;
    trs_nic->thn_ctpio_io_mmap = NULL;
    trs->ctpio_mmap_bytes += alloc_info.vi_ctpio_mmap_bytes;

    if( nsn->oo_vi_flags & OO_VI_FLAGS_CTPIO_EN ) {
      rc = efrm_ctpio_map_kernel(vi_rs, &(trs_nic->thn_ctpio_io_mmap));
      if( rc < 0 ) {
        ci_log("%s: ERROR: efrm_ctpio_map_kernel failed (%d)\n", __func__, rc);
        efrm_pd_release(alloc_info.pd);
        goto error_out;
      }
      vi->vi_ctpio_mmap_ptr = trs_nic->thn_ctpio_io_mmap;
    }
#endif

#if CI_CFG_PIO
    if( NI_OPTS(ni).pio && (nic->devtype.arch == EFHW_ARCH_EF10) ) {
      rc = allocate_pio(trs, intf_i, alloc_info.pd, nic, &pio_buf_offset);
      if( rc < 0 ) {
        efrm_pd_release(alloc_info.pd);
        goto error_out;
      }
    }
#endif

#if CI_CFG_TCP_OFFLOAD_RECYCLER
    /* The TCP plugin uses multiple VIs per intf to distinguish various types
     * of traffic.
     *  - The 'normal' VI (CI_Q_ID_NORMAL) isn't used at all by the plugin; it
     *    exists to keep non-pluginized traffic clearly delineated
     *  - CI_Q_ID_TCP_RECYCLER is used by the core of the TCP plugin. The
     *    plugin sends headers-only and to-recycle payloads to Onload over
     *    this VI, and Onload sends the to-recycle packets back again when
     *    it's their time
     *  - Subsequent VIs (CI_Q_ID_TCP_APP..+inf) are owned by the TCP
     *    processing plugin, i.e. the protocol-specific part of the plugin. In
     *    Ceph's case there's only one of these additional VIs and it's used
     *    for sending in-order TCP payloads from plugin to Onload, where the
     *    payloads are in a structure of their own which allows some parts to
     *    be inline while other parts are pointers to remote memory which must
     *    be mem2mem-copied to get at it.
     * All of this is discussed in detail in the design doc: SF-123622 */
    if( NI_OPTS(ni).tcp_offload_plugin ) {
      int release_pd = alloc_info.release_pd;
      int vi_i;
      int num_vis = ci_netif_num_vis(ni);

      /* The TCP plugin is a throughput-oriented feature - tweak the alloc
       * to be the best for that */
      alloc_info.try_ctpio = false;

      for( vi_i = 1; vi_i < num_vis; ++vi_i) {
        struct efrm_vi *vi_rs;
        int qid = ef_vi_add_queue(ci_netif_vi(ni, intf_i),
                                  &ni->nic_hw[intf_i].vis[vi_i]);
        ci_assert_equal(qid, vi_i);
        alloc_info.virs = &trs_nic->thn_vi_rs[vi_i];
        rc = allocate_vi(ni, &alloc_info, tcp_helper_vi(trs, intf_i), qid);
        if( rc ) {
          if( release_pd )
            efrm_pd_release(alloc_info.pd); /* vi keeps a ref to pd */
          goto error_out;
        }
        vi_rs = trs_nic->thn_vi_rs[vi_i];
        rc = initialise_vi(ni, &ni->nic_hw[intf_i].vis[vi_i],
                           vi_rs, vm,
                           vi_state, nic->devtype.arch, nic->devtype.variant,
                           nic->devtype.revision, efhw_vi_nic_flags(nic),
                           &alloc_info, &vi_out_flags, &ni->state->vi_stats);
        if( rc < 0 ) {
          if( release_pd )
            efrm_pd_release(alloc_info.pd); /* vi keeps a ref to pd */
          goto error_out;
        }

        nsn->vi_instance[vi_i] =
                  (ci_uint16) EFAB_VI_RESOURCE_INSTANCE(vi_rs);
        nsn->vi_abs_idx[vi_i] =
                  efhw_nic_rel_to_abs_idx(nic, nsn->vi_instance[vi_i]);
        trs->io_mmap_bytes += alloc_info.vi_io_mmap_bytes;
        vi_state = (char*) vi_state +
                   ef_vi_calc_state_bytes(vm->rxq_size, vm->txq_size);
      }
    }
    else
#endif
      ci_assert_equal(ci_netif_num_vis(ni), 1);

    if( alloc_info.release_pd )
      efrm_pd_release(alloc_info.pd); /* vi keeps a ref to pd */
  }

  OO_DEBUG_RES(ci_log("%s: done", __FUNCTION__));

  return 0;

error_out:
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    int vi_i;
    for( vi_i = ci_netif_num_vis(ni) - 1; vi_i >= 0; --vi_i ) {
      if( trs->nic[intf_i].thn_vi_rs[vi_i] ) {
        ef_vi* vi = &ni->nic_hw[intf_i].vis[vi_i];
        if( vi->efct_rxq[0].superbufs )
          efct_vi_munmap_internal(vi);
        efrm_vi_resource_release(trs->nic[intf_i].thn_vi_rs[vi_i]);
        trs->nic[intf_i].thn_vi_rs[vi_i] = NULL;
      }
    }
  }
  return rc;
}


static int deferred_vis(tcp_helper_resource_t* trs)
{
  int rc, intf_i;
  ci_netif* ni = &trs->netif;

  if( ni->flags & CI_NETIF_FLAG_AF_XDP ) {
    /* hugetlbfs pages are incompatible with AF_XDP */
    if( NI_OPTS(ni).huge_pages != 0 ) {
      NI_LOG(ni, RESOURCE_WARNINGS,
             "[%s]: WARNING: huge pages are incompatible with AF_XDP. "
             "Disabling hugepage support.",
             ni->state->pretty_name);

      NI_OPTS(ni).huge_pages = 0;
    }

    /* All buffers need to be allocated before AF_XDP sockets are usable. */
    while( (rc = efab_tcp_helper_more_bufs(trs)) == 0 );
    if( rc != -ENOSPC )
      return rc;
  }

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    int vi_i;

    for( vi_i = 0; vi_i < ci_netif_num_vis(&trs->netif); ++vi_i ) {
      uint32_t mmap_bytes;

      rc = efrm_vi_resource_deferred(trs_nic->thn_vi_rs[vi_i],
                                     CI_CFG_PKT_BUF_SIZE,
                                     offsetof(ci_ip_pkt_fmt, dma_start),
                                     &mmap_bytes);
      if( rc < 0 )
        return rc;

      trs->buf_mmap_bytes += mmap_bytes;
      trs_nic->thn_vi_mmap_bytes[vi_i] = mmap_bytes;

      /* We used the info we were told - check that's consistent with what
       * someone else would get if they checked separately.
       */
      ci_assert_equal(ni->state->nic[intf_i].vi_io_mmap_bytes,
                     efab_vi_resource_mmap_bytes(trs_nic->thn_vi_rs[vi_i], 0));
      ci_assert_equal(trs_nic->thn_vi_mmap_bytes[vi_i],
                     efab_vi_resource_mmap_bytes(trs_nic->thn_vi_rs[vi_i], 1));

      ci_assert_equal(
                    efab_vi_resource_mmap_bytes(tcp_helper_vi(trs, intf_i), 0),
                    efab_vi_resource_mmap_bytes(trs_nic->thn_vi_rs[vi_i], 0));
    }
  }

  ni->state->buf_mmap_bytes = trs->buf_mmap_bytes;
  return 0;
}


static void vi_complete(void *completion_void)
{
  complete((struct completion *)completion_void);
}

#if CI_CFG_NIC_RESET_SUPPORT
#define intfs_suspended(trs) ((trs)->intfs_suspended)
#else
#define intfs_suspended(trs) 0
#endif

static void release_pkts(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  unsigned i;
  int intf_i;
#ifndef NDEBUG
  int n_free = 0;
#endif

  for (i = 0; i < ni->pkt_sets_n; i++) {
    ci_assert(ni->pkt_bufs[i]);
#ifndef NDEBUG
    n_free += ni->packets->set[i].n_free;
#endif
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      oo_iobufset_resource_release(ni->nic_hw[intf_i].pkt_rs[i],
                                   intfs_suspended(trs) & (1 << intf_i));
  }
#ifndef NDEBUG
  if( ~trs->netif.flags & CI_NETIF_FLAG_WEDGED )
    ci_assert_equal(ni->packets->n_free, n_free);
#endif

  /* Now release everything allocated in allocate_netif_hw_resources. */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_free(ni->nic_hw[intf_i].pkt_rs);

  for (i = 0; i < ni->pkt_sets_n; i++)
    oo_iobufset_pages_release(ni->pkt_bufs[i]);
  vfree(ni->pkt_bufs);
}


static void detach_efct_rxqs(tcp_helper_resource_t* trs)
{
  int intf_i;
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    int num_vis = ci_netif_num_vis(&trs->netif);
    int vi_i;
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    for( vi_i = num_vis - 1; vi_i >= 0; --vi_i ) {
      size_t rxq_i;
      for( rxq_i = 0; rxq_i < ARRAY_SIZE(trs_nic->thn_efct_rxq); ++rxq_i ) {
        if( trs_nic->thn_efct_rxq[rxq_i] ) {
          efrm_rxq_release(trs_nic->thn_efct_rxq[rxq_i]);
          trs_nic->thn_efct_rxq[rxq_i] = NULL;
        }
      }
    }
  }
}


static void release_vi(tcp_helper_resource_t* trs)
{
  int intf_i;

  /* Flush vis first to ensure our bufs won't be used any more */
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    int vi_i;
    for( vi_i = ci_netif_num_vis(&trs->netif) - 1; vi_i >= 0; --vi_i ) {
      struct efrm_vi *vi_rs = trs->nic[intf_i].thn_vi_rs[vi_i];
      reinit_completion(&trs->complete);
      efrm_vi_register_flush_callback(vi_rs, &vi_complete, &trs->complete);
      efrm_vi_resource_stop_callback(vi_rs);
      wait_for_completion(&trs->complete);
    }
  }

  /* Now do the rest of vi release */
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    int num_vis = ci_netif_num_vis(&trs->netif);
    int vi_i;
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    ci_netif_nic_t *netif_nic = &trs->netif.nic_hw[intf_i];
#if CI_CFG_PIO || (CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE)
    struct efhw_nic* nic =
      efrm_client_get_nic(trs_nic->thn_oo_nic->efrm_client);
#endif
#if CI_CFG_PIO
    if( NI_OPTS(&trs->netif).pio &&
        (nic->devtype.arch == EFHW_ARCH_EF10) &&
        (trs_nic->thn_pio_io_mmap_bytes != 0) ) {
      efrm_pio_unmap_kernel(tcp_helper_vi(trs, intf_i),
                            (void*)netif_nic->pio.pio_io);
      ci_pio_buddy_dtor(&trs->netif,
                        &trs->netif.state->nic[intf_i].pio_buddy);
    }
#endif
#if CI_CFG_CTPIO
    if( trs_nic->thn_ctpio_io_mmap != NULL )
      efrm_ctpio_unmap_kernel(tcp_helper_vi(trs, intf_i),
                              trs_nic->thn_ctpio_io_mmap);
#endif
    for( vi_i = num_vis - 1; vi_i >= 0; --vi_i ) {
      ef_vi* vi = &trs->netif.nic_hw[intf_i].vis[vi_i];
      if( vi->efct_rxq[0].superbufs )
        efct_vi_munmap_internal(vi);
      efrm_vi_resource_release_flushed(trs_nic->thn_vi_rs[vi_i]);
      trs_nic->thn_vi_rs[vi_i] = NULL;
      CI_DEBUG_ZERO(&trs->netif.nic_hw[intf_i].vis[vi_i]);
    }
  }
  /* On the normal path we've already done this, but it's convenient to have
   * it here to catch the various failure paths */
  detach_efct_rxqs(trs);

#if CI_CFG_ENDPOINT_MOVE
  if( trs->thc != NULL )
    tcp_helper_cluster_release(trs->thc, trs);
#endif
}


#if ! CI_CFG_UL_INTERRUPT_HELPER
/* This leak check should be moved to UL in CI_CFG_UL_INTERRUPT_HELPER mode */

static void tcp_helper_leak_check(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  int i;
  ci_uint32 table_n_entries;

  /* Check that all aux buffers have been freed before the stack
   * destruction. */
  for( i = 0; i < CI_TCP_AUX_TYPE_NUM; i++ ) {
    ci_assert_equal(ni->state->n_aux_bufs[i], 0);
    if( ni->state->n_aux_bufs[i] != 0 ) {
      ci_log("%s[%d]: aux_bufs[%s]: leaked %d out of %d",
             __func__, NI_ID(ni), ci_tcp_aux_type2str(i),
             ni->state->n_aux_bufs[i], ni->state->max_aux_bufs[i]);
    }
  }

  /* Check for sw filters leak.
   *
   * To check for the leak, we should ensure that all pending sw filter
   * operations are applied.  In debug build we just apply them all
   * by calling oof_cb_sw_filter_apply().
   *
   * In ndebug build we disable the leak check if there are any pending sw
   * filter operations, by checking OO_TRUSTED_LOCK_SWF_UPDATE and
   * CI_EPLOCK_NETIF_SWF_UPDATE flags.
   */
  table_n_entries = ni->state->stats.table_n_entries
#if CI_CFG_IPV6
                  + ni->state->stats.ipv6_table_n_entries
#endif
                  ;

#ifndef NDEBUG
  oof_cb_sw_filter_apply(&trs->netif);
  if( table_n_entries != 0 )
    ci_netif_filter_dump(&trs->netif);
  ci_assert_equal(table_n_entries, 0);
#endif
  if( table_n_entries != 0 &&
      ! (trs->trusted_lock & OO_TRUSTED_LOCK_SWF_UPDATE) &&
      ! (trs->netif.state->lock.lock & CI_EPLOCK_NETIF_SWF_UPDATE) )
    ci_log("%s[%d]: leaked %d software filters", __func__, NI_ID(ni),
           table_n_entries);

  ci_assert_equal(ni->state->reserved_pktbufs, 0);
}
#endif


/* Set-up the IPIDs for netif [ni] */
static void ci_ipid_ctor(ci_netif* ni)
{
  ci_netif_ipid_cb_t* ipid;
  int range;

  ci_assert(ni);

  ipid = NI_IPID(ni);
  memset( ipid, 0, sizeof(*ipid));

  if( (range = efab_ipid_alloc(&efab_tcp_driver.ipid)) < 0 ) {
    ipid->no_free = 1; /* skip range release in dtor */
    range = CI_IPID_MIN; /* just use range 0 anyway */
  }

  ci_assert( (range + CI_IPID_BLOCK_MASK) < 0x10000);
  ipid->base = (ci_uint16)range;
  ipid->next = 0;
#if CI_CFG_IPV6
  ipid->ip6_base = range << 16;
  ipid->ip6_next = 0;
#endif
}


static void ci_ipid_dtor(ci_netif* ni)
{
  ci_netif_ipid_cb_t* ipid;

  ci_assert(ni);

  ipid = NI_IPID(ni);

  /* Skip range relese if allocation failed in ctor */
  if( ipid->no_free )
    return;
  ci_assert( ipid->base <= (ci_uint16)(0x10000 - CI_IPID_BLOCK_LENGTH) );
  ci_assert( !(ipid->base & CI_IPID_BLOCK_MASK));
  efab_ipid_free(&efab_tcp_driver.ipid, (ci_int32)ipid->base);
}


static int
allocate_netif_resources(ci_resource_onload_alloc_t* alloc,
                         tcp_helper_resource_t* trs, int cluster_size)
{
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns;
  int i, sz, rc, no_table_entries;
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  int no_active_wild_pools, no_active_wild_table_entries;
#endif
  int no_seq_table_entries;
  unsigned vi_state_bytes;
  unsigned dma_addrs_bytes;
#if CI_CFG_PIO
  unsigned pio_bufs_ofs = 0;
#endif
  ci_uint32 filter_table_size;
  ci_uint32 filter_table_ext_size;
#if CI_CFG_IPV6
  ci_uint32 ip6_filter_table_size;
#endif
  ci_uint32 ns_ofs;

  OO_DEBUG_SHM(ci_log("%s:", __func__));

  trs->mem_mmap_bytes = 0;
  trs->io_mmap_bytes = 0;
#if CI_CFG_PIO
  trs->pio_mmap_bytes = 0;
#endif
#if CI_CFG_CTPIO
  trs->ctpio_mmap_bytes = 0;
#endif
  trs->buf_mmap_bytes = 0;
  trs->efct_shm_mmap_bytes = 0;

  no_table_entries = ci_netif_filter_table_size(ni);

  if( NI_OPTS(ni).tcp_isn_mode == 1 ) {
    /* FIXME: Reconsider the size of this table. */
    ci_uint32 entries = NI_OPTS(ni).tcp_isn_cache_size;
    if( entries == 0 )
      /* FIXME: Reconsider the size of this table. */
      entries = NI_OPTS(ni).max_ep_bufs * 2;
    no_seq_table_entries = 1u << ci_log2_ge(entries, 1);
  }
  else {
    no_seq_table_entries = 0;
  }

  /* pkt_sets_n should be zeroed before possible NIC reset */
  if( NI_OPTS(ni).max_packets > max_packets_per_stack ) {
    OO_DEBUG_ERR(ci_log("WARNING: EF_MAX_PACKETS reduced from %d to %d due to "
                        "max_packets_per_stack module option",
                        NI_OPTS(ni).max_packets, max_packets_per_stack));
    ni->state = NULL;
    tcp_helper_reduce_max_packets(ni, max_packets_per_stack);
  }
  ni->pkt_sets_n = 0;
  ni->pkt_sets_max =
    (NI_OPTS(ni).max_packets + PKTS_PER_SET - 1) >> CI_CFG_PKTS_PER_SET_S;


  /* Find size of netif state to allocate. */
  vi_state_bytes = ef_vi_calc_state_bytes(NI_OPTS(ni).rxq_size,
                                          NI_OPTS(ni).txq_size);
  vi_state_bytes *= ci_netif_num_vis(ni);

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  if( ci_netif_should_allocate_tcp_shared_local_ports(ni) ) {
    no_active_wild_pools = is_power_of_2(cluster_size) ? cluster_size :
                                                         RSS_HASH_SIZE;
    /* Max active wilds is bounded by the number of local IPs and
     * shared local ports. */
    no_active_wild_table_entries =
      CI_MIN((ci_uint32)CI_CFG_MAX_LOCAL_IPADDRS,
             CI_MAX(NI_OPTS(ni).tcp_shared_local_ports,
                    NI_OPTS(ni).tcp_shared_local_ports_max));
    /* Quadruple the size to ensure the hash table does not get too full. */
    no_active_wild_table_entries <<= 2;
    /* Round up to a power of two. */
    if( no_active_wild_table_entries > 1 )
      no_active_wild_table_entries =
        1u << (__fls(no_active_wild_table_entries - 1) + 1);
  }
  else {
    no_active_wild_pools = 0;
    no_active_wild_table_entries = 0;
  }
#endif

  filter_table_size = sizeof(ci_netif_filter_table) +
    sizeof(ci_netif_filter_table_entry_fast) * (no_table_entries - 1);
  filter_table_ext_size = sizeof(ci_netif_filter_table_entry_ext) *
                          no_table_entries;
#if CI_CFG_IPV6
  ip6_filter_table_size = sizeof(ci_ip6_netif_filter_table) +
    sizeof(ci_ip6_netif_filter_table_entry) * (no_table_entries - 1);
#endif

  /* Allocate shmbuf for netif state.  When calculating the size, it's
   * important that the sizes of the sub-buffers are accumulated in the order
   * in which they will be laid out in memory, or else the alignment
   * calculations will be invalid. */
  ci_assert_le(NI_OPTS(ni).max_ep_bufs, CI_CFG_NETIF_MAX_ENDPOINTS_MAX);
  sz = sizeof(ci_netif_state);
  sz = CI_ROUND_UP(sz, __alignof__(ef_vi_state));
  sz += vi_state_bytes * trs->netif.nic_n;
  sz = CI_ROUND_UP(sz, __alignof__(oo_pktbuf_manager));
  sz += sizeof(oo_pktbuf_manager);
  sz = CI_ROUND_UP(sz, __alignof__(oo_pktbuf_set));
  sz += sizeof(oo_pktbuf_set) * ni->pkt_sets_max;
  sz = CI_ROUND_UP(sz, CI_CACHE_LINE_SIZE);
  /* This is the worst-case amount of space needed for DMA addrs, i.e. when
   * we're never able to find any higher-order pages. It's extremely likely
   * that only a fraction of this space will ever be used: */
  dma_addrs_bytes = ni->pkt_sets_max * CI_CFG_MAX_INTERFACES *
                    PKTS_PER_SET / (PAGE_SIZE / CI_CFG_PKT_BUF_SIZE) *
                    sizeof(ef_addr);
  sz += dma_addrs_bytes;
  sz = CI_ROUND_UP(sz, __alignof__(struct oo_p_dllink));
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  sz += sizeof(struct oo_p_dllink) * no_active_wild_table_entries *
        no_active_wild_pools;
#endif
  sz = CI_ROUND_UP(sz, __alignof__(ci_tcp_prev_seq_t));
  sz += sizeof(ci_tcp_prev_seq_t) * no_seq_table_entries;
  sz = CI_ROUND_UP(sz, __alignof__(struct oo_deferred_pkt));
  sz += sizeof(struct oo_deferred_pkt) * NI_OPTS(ni).defer_arp_pkts;
  sz = CI_ROUND_UP(sz, __alignof__(ci_netif_filter_table));
  sz += filter_table_size;
  sz = CI_ROUND_UP(sz, __alignof__(ci_netif_filter_table_entry_ext));
  sz += filter_table_ext_size;

#if CI_CFG_IPV6
  sz = CI_ROUND_UP(sz, __alignof__(ci_ip6_netif_filter_table));
  sz += ip6_filter_table_size;
#endif

#if CI_CFG_UL_INTERRUPT_HELPER
  sz = CI_ROUND_UP(sz, __alignof__(oo_sp));
  sz += sizeof(oo_sp) * OO_CLOSED_EPS_RING_SIZE;
  sz = CI_ROUND_UP(sz, __alignof__(struct oo_sw_filter_op));
  sz += sizeof(struct oo_sw_filter_op) * OO_SW_FILTER_OPS_SIZE;
#endif

#if CI_CFG_PIO
  /* Allocate shmbuf for pio regions.  We haven't tried to allocate
   * PIOs yet and we don't know how many ef10s we have.  So just
   * reserve space for each available interface and waste the
   * remainder of the memory.
   */
  if( NI_OPTS(ni).pio ) {
    const int pio_max_buf_size = 4096;
    sz = CI_ROUND_UP(sz, pio_max_buf_size);
    pio_bufs_ofs = sz;
    sz += pio_max_buf_size * oo_stack_intf_max(ni);
  }
#endif

  sz = CI_ROUND_UP(sz, OO_SHARED_BUFFER_CHUNK_SIZE);

  /* [shmbuf] backs the shared stack state and the socket buffers.  First,
   * count the pages required for the latter. */
  i = (NI_OPTS(ni).max_ep_bufs / EP_BUF_PER_PAGE) >>
                                    OO_SHARED_BUFFER_CHUNK_ORDER;
  /* Now add in the pages for the shared state. */
  i += sz / OO_SHARED_BUFFER_CHUNK_SIZE;

  /* Allocate the shmbuf, and fault in the pages for the shared state (but not
   * for the sockets).  These pages get zeroed, so all fields in the shared
   * state can be assumed to have been zero-initialised. */
  rc = oo_shmbuf_alloc(&ni->shmbuf, OO_SHARED_BUFFER_CHUNK_ORDER, i,
                       sz / OO_SHARED_BUFFER_CHUNK_SIZE);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("%s: failed to alloc shmbuf for shared state and "
                        "socket buffers (%d)", __FUNCTION__, rc));
    goto fail1;
  }

  ns = ni->state = (ci_netif_state*) oo_shmbuf_off2ptr(&ni->shmbuf, 0);

  CI_DEBUG(ns->flags |= CI_NETIF_FLAG_DEBUG);

  ns->netif_mmap_bytes = oo_shmbuf_size(&ni->shmbuf);

  ns->stack_id = trs->id;
  ns->ep_ofs = ni->ep_ofs = sz;
#if CI_CFG_PIO
  ns->pio_bufs_ofs = pio_bufs_ofs;
#endif
  ns->n_ep_bufs = 0;
  ns->nic_n = trs->netif.nic_n;

#if CI_CFG_UL_INTERRUPT_HELPER
  ns->n_ep_orphaned = OO_N_EP_ORPHANED_INIT;
#else
  ni->n_ep_orphaned = OO_N_EP_ORPHANED_INIT;
#endif

  /* An entry in intf_i_to_hwport should not be touched if the intf does
   * not exist.  Belt-and-braces: initialise to 0.
   */
  ns->hwport_mask = ni->hwport_mask;
  memset(ns->intf_i_to_hwport, 0, sizeof(ns->intf_i_to_hwport));
  memcpy(ns->hwport_to_intf_i, ni->hwport_to_intf_i,
         sizeof(ns->hwport_to_intf_i));
  for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i )
    if( ns->hwport_to_intf_i[i] >= 0 )
      ns->intf_i_to_hwport[(int) ns->hwport_to_intf_i[i]] = i;

  ns_ofs = sizeof(ci_netif_state);
  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(ef_vi_state));
  ns_ofs += vi_state_bytes * trs->netif.nic_n;

  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(oo_pktbuf_manager));
  ns->buf_ofs = ns_ofs;
  ns_ofs += sizeof(oo_pktbuf_manager);
  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(oo_pktbuf_set));
  ns_ofs += sizeof(oo_pktbuf_set) * ni->pkt_sets_max;

  ns_ofs = CI_ROUND_UP(ns_ofs, CI_CACHE_LINE_SIZE);
  ns->dma_ofs = ns_ofs;
  ns_ofs += dma_addrs_bytes;

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(struct oo_p_dllink));
  ns->active_wild_ofs = ns_ofs;
  ns->active_wild_table_entries_n = no_active_wild_table_entries;
  ns->active_wild_pools_n = no_active_wild_pools;

  ns_ofs += (sizeof(struct oo_p_dllink) * ns->active_wild_table_entries_n *
            ns->active_wild_pools_n);
#endif

  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(ci_tcp_prev_seq_t));
  ns->seq_table_ofs = ns_ofs;
  ns->seq_table_entries_n = no_seq_table_entries;
  ns_ofs += sizeof(ci_tcp_prev_seq_t) * ns->seq_table_entries_n;

  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(struct oo_deferred_pkt));
  ns->deferred_pkts_ofs = ns_ofs;
  ns_ofs += sizeof(struct oo_deferred_pkt) * NI_OPTS(ni).defer_arp_pkts;

  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(ci_netif_filter_table));
  ns->table_ofs = ns_ofs;
  ns_ofs += filter_table_size;

  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(ci_netif_filter_table_entry_ext));
  ns->table_ext_ofs = ns_ofs;
  ns_ofs += filter_table_ext_size;

#if CI_CFG_IPV6
  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(ci_ip6_netif_filter_table));
  ns->ip6_table_ofs = ns_ofs;
  ns_ofs += ip6_filter_table_size;
#endif

#if CI_CFG_UL_INTERRUPT_HELPER
  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(oo_sp));
  ns->closed_eps_ofs = ns_ofs;
  ns_ofs += sizeof(oo_sp) * OO_CLOSED_EPS_RING_SIZE;

  ns_ofs = CI_ROUND_UP(ns_ofs, __alignof__(struct oo_sw_filter_op));
  ns->sw_filter_ofs = ns_ofs;
  ns_ofs += sizeof(struct oo_sw_filter_op) * OO_SW_FILTER_OPS_SIZE;
#endif

  /* The last addition to ns_ofs is not really used */
  (void)ns_ofs;

  ns->vi_state_bytes = vi_state_bytes;

  ni->packets = (void*) ((char*) ns + ns->buf_ofs);
  ni->dma_addrs = (void*) ((char*) ns + ns->dma_ofs);
  ni->dma_addr_next = 0;
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  ni->active_wild_table = (void*) ((char*) ns + ns->active_wild_ofs);
#endif
  ni->seq_table = (void*) ((char*) ns + ns->seq_table_ofs);
  ni->deferred_pkts = (void*) ((char*) ns + ns->deferred_pkts_ofs);
  ni->filter_table = (void*) ((char*) ns + ns->table_ofs);
  ni->filter_table_ext = (void*) ((char*) ns + ns->table_ext_ofs);

#if CI_CFG_IPV6
  ni->ip6_filter_table = (void*) ((char*) ns + ns->ip6_table_ofs);
#endif

#if CI_CFG_UL_INTERRUPT_HELPER
  oo_ringbuffer_state_init(&ns->closed_eps, OO_CLOSED_EPS_RING_SIZE,
                           sizeof(oo_sp));
  oo_ringbuffer_init(&ni->closed_eps, &ns->closed_eps,
                     (void*)((char*) ns + ns->closed_eps_ofs));

  oo_ringbuffer_state_init(&ns->sw_filter_ops, OO_SW_FILTER_OPS_SIZE,
                           sizeof(struct oo_sw_filter_op));
  oo_ringbuffer_init(&ni->sw_filter_ops, &ns->sw_filter_ops,
                     (void*)((char*) ns + ns->sw_filter_ofs));
#endif

  ni->packets->sets_max = ni->pkt_sets_max;
  ni->packets->sets_n = 0;
  ni->packets->n_pkts_allocated = 0;

  /* Initialize the free list of synrecv/aux bufs */
  oo_p_dllink_init(ni, oo_p_dllink_ptr(ni, &ni->state->free_aux_mem));
  ni->state->n_free_aux_bufs = 0;
  memset(ni->state->n_aux_bufs, 0, sizeof(ni->state->n_aux_bufs));
  ns->max_aux_bufs[CI_TCP_AUX_TYPE_SYNRECV] = ni->opts.tcp_synrecv_max;
  ns->max_aux_bufs[CI_TCP_AUX_TYPE_BUCKET] = ni->opts.max_ep_bufs;
  ns->max_aux_bufs[CI_TCP_AUX_TYPE_EPOLL] = ni->opts.max_ep_bufs;
  ns->max_aux_bufs[CI_TCP_AUX_TYPE_PMTUS] = ni->opts.max_ep_bufs;

  /* The shared netif-state buffer and EP buffers are part of the mem mmap */
  trs->mem_mmap_bytes += ns->netif_mmap_bytes;
  OO_DEBUG_MEMSIZE(ci_log(
        "added %d (0x%x) bytes for shared netif state and ep buffers, "
        "reached %d (0x%x)", ns->netif_mmap_bytes, ns->netif_mmap_bytes,
        trs->mem_mmap_bytes, trs->mem_mmap_bytes));

  if( trs->name[0] == '\0' )
    snprintf(ns->pretty_name, sizeof(ns->pretty_name), "%d", ns->stack_id);
  else
    snprintf(ns->pretty_name, sizeof(ns->pretty_name), "%d,%s",
             ns->stack_id, trs->name);

  /* Allocate an eplock resource. */
  rc = eplock_ctor(ni);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to allocate EPLOCK (%d)", rc));
    goto fail2;
  }
  ni->state->lock.lock = CI_EPLOCK_LOCKED;

  ci_ipid_ctor(ni);

  ci_waitq_ctor(&trs->pkt_waitq);

#if CI_CFG_UL_INTERRUPT_HELPER
  init_waitqueue_head(&trs->ulh_waitq);
  trs->ulh_flags = 0;

  { CI_BUILD_ASSERT(CI_CFG_MAX_INTERFACES<=32); }
  ci_atomic_set(&trs->intr_intfs, 0);
  if( NI_OPTS(&trs->netif).int_driven )
    ci_atomic_set(&trs->wake_intfs,
                  (1ull << oo_stack_intf_max(&trs->netif)) - 1);
  else
    ci_atomic_set(&trs->wake_intfs, 0);
#endif

  for( i = 0; i < CI_CFG_N_READY_LISTS; i++ ) {
    ci_dllist_init(&trs->os_ready_lists[i]);
    ci_waitable_ctor(&trs->ready_list_waitqs[i]);
  }
  spin_lock_init(&trs->os_ready_list_lock);

  return 0;

 fail2:
  oo_shmbuf_free(&ni->shmbuf);
 fail1:
  LOG_NC(ci_log("failed to allocate tcp_helper resources (%d)", rc));
  return rc;
}

#if CI_CFG_TCP_OFFLOAD_RECYCLER
static void destroy_ceph_app(struct efrm_ext* plugin, uint32_t app_id)
{
  struct xsn_ceph_destroy_app param = {.in_app_id = cpu_to_le32(app_id)};
  int rc = efrm_ext_msg(plugin, XSN_CEPH_DESTROY_APP, &param, sizeof(param));
  if( rc ) {
    OO_DEBUG_ERR(ci_log("%s: Destroy Ceph app failed (%d)", __FUNCTION__, rc));
    /* Nothing we can do about it */
  }
}
#endif

static int
create_plugin_rx_app(tcp_helper_resource_t* trs)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  ci_netif* ni = &trs->netif;
  bool got_nic = false;
  int intf_i;

  ni->state->plugin_mmap_bytes = 0;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ni->nic_hw[intf_i].plugin_rx = NULL;

  if( NI_OPTS(ni).tcp_offload_plugin != CITP_TCP_OFFLOAD_CEPH )
    return 0;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct efrm_pd* pd = efrm_vi_get_pd(tcp_helper_vi(trs, intf_i));
    struct xsn_ceph_create_app create;
    struct ef_vi* tcp_vi;
    struct ef_vi* ceph_vi;
    struct efrm_ext* plugin;
    struct efhw_nic* nic;
    ci_uint32 app_id;
    struct efrm_ext_svc_meta meta;
    int rc;

    nic = efrm_client_get_nic(trs->nic[intf_i].thn_oo_nic->efrm_client);
    if( nic->devtype.arch != EFHW_ARCH_EF100 )
      continue;
    rc = efrm_ext_alloc_rs(pd, XSN_TCP_CEPH_PLUGIN, &plugin);
    if( rc ) {
      /* We don't immediately fail here because we don't want to require
       * that every EF100 in the system be provisioned identically. We only
       * fail if no NICs are capable */
      continue;
    }

    rc = efrm_ext_get_meta_global(plugin, &meta);
    if( rc ) {
      OO_DEBUG_ERR(ci_log("%s: Failed to get plugin metadata (%d, %d)",
                          __FUNCTION__, intf_i, rc));
      goto fail_plugin_1;
    }

    tcp_vi = &ni->nic_hw[intf_i].vis[CI_Q_ID_TCP_RECYCLER];
    ceph_vi = &ni->nic_hw[intf_i].vis[CI_Q_ID_TCP_APP];
    create = (struct xsn_ceph_create_app){
      .tcp.in_vi_id = cpu_to_le16(ef_vi_instance(tcp_vi)),
      .in_meta_vi_id = cpu_to_le16(ef_vi_instance(ceph_vi)),
      .in_meta_buflen = cpu_to_le16(ef_vi_receive_buffer_len(ceph_vi) -
                                    ef_vi_receive_prefix_len(ceph_vi)),
    };
    rc = efrm_ext_msg(plugin, XSN_CEPH_CREATE_APP, &create, sizeof(create));
    if( rc ) {
      OO_DEBUG_ERR(ci_log("%s: CEPH_CREATE_APP failed (%d, %d)",
                          __FUNCTION__, intf_i, rc));
      goto fail_plugin_1;
    }
    app_id = le32_to_cpu(create.tcp.out_app_id);

    ni->nic_hw[intf_i].plugin_io = NULL;
    if( meta.mapped_csr_size ) {
      size_t bar_off = ef10_tx_dma_page_base(nic->vi_stride,
                            trs->nic[intf_i].thn_vi_rs[CI_Q_ID_TCP_APP]->
                                    rs.rs_instance);
      bar_off += meta.mapped_csr_offset;
      ni->nic_hw[intf_i].plugin_io = ci_ioremap(nic->ctr_ap_addr +
                                                (bar_off & PAGE_MASK),
                                                meta.mapped_csr_size);
      if( ! ni->nic_hw[intf_i].plugin_io ) {
        OO_DEBUG_ERR(ci_log("%s: Ceph app failed to map VI window (%d)",
                            __FUNCTION__, intf_i));
        destroy_ceph_app(plugin, app_id);
      fail_plugin_1:
        efrm_ext_release(plugin);
        continue;
      }
      ni->state->nic[intf_i].oo_vi_flags |= OO_VI_FLAGS_PLUGIN_IO_EN;
      trs->nic[intf_i].thn_plugin_mapped_csr_offset = meta.mapped_csr_offset;
      ni->state->plugin_mmap_bytes += meta.mapped_csr_size;
    }
    ni->nic_hw[intf_i].plugin_rx = plugin;
    ni->nic_hw[intf_i].plugin_rx_app_id = app_id;
    got_nic = true;
  }
  if( ! got_nic ) {
    OO_DEBUG_ERR(ci_log("%s: no EF100 NICs have the requested plugin",
                        __FUNCTION__));
    return -ENOTSUPP;
  }
#endif
  return 0;
}


static void
destroy_plugin_rx_app(tcp_helper_resource_t* trs)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  ci_netif* ni = &trs->netif;
  int intf_i;
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct efrm_ext* plugin = ni->nic_hw[intf_i].plugin_rx;
    if( ! plugin )
      continue;
    destroy_ceph_app(plugin, ni->nic_hw[intf_i].plugin_rx_app_id);
    efrm_ext_release(plugin);
    ni->nic_hw[intf_i].plugin_rx = NULL;
  }
#endif
}


#if CI_CFG_TX_CRC_OFFLOAD
static ci_uint32
get_plugin_tx_crc_table_region(struct oo_nic* nic)
{
  ci_uint32 region_id;
  ci_uint8 first_set_bit;
  ci_irqlock_state_t lock_flags;

  /* The regions will eventually be managed by plugin control messages,
   * so the stack table lock will go away */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  first_set_bit = ffs(nic->crc_id_pools_mask);
  if( ! first_set_bit ) {
    ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
    return -ENOSPC;
  }
  nic->crc_id_pools_mask &= ~(1 << (first_set_bit - 1));
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  region_id = (first_set_bit - 1) << ZC_NVME_CRC_IDP_CAP;
  return region_id;
}

static void
release_plugin_tx_crc_table_region(struct oo_nic* nic, ci_uint32 region_id)
{
  ci_irqlock_state_t lock_flags;

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  nic->crc_id_pools_mask |= 1 << (region_id >> ZC_NVME_CRC_IDP_CAP);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
}
#endif

static int
create_plugin_tx_app(tcp_helper_resource_t* trs)
{
#if CI_CFG_TX_CRC_OFFLOAD
  ci_netif* ni = &trs->netif;
  int intf_i;
  bool got_nic = false;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ni->nic_hw[intf_i].plugin_tx = NULL;

  if( NI_OPTS(ni).tcp_offload_plugin != CITP_TCP_OFFLOAD_NVME )
    return 0;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    ci_uint32 region_id;
#if ! CI_CFG_NVME_LOCAL_CRC_MODE
    struct efhw_nic* nic;
    struct efrm_pd* pd;
    struct efrm_ext* plugin;
    struct xsn_storage_tx_create_app create;
    struct ef_vi* tx_vi;
    int rc;

    nic = efrm_client_get_nic(trs->nic[intf_i].thn_oo_nic->efrm_client);
    if( nic->devtype.arch != EFHW_ARCH_EF100 )
      continue;

    pd = efrm_vi_get_pd(tcp_helper_vi(trs, intf_i));
    rc = efrm_ext_alloc_rs(pd, XSN_STORAGE_TX, &plugin);
    if( rc )
      continue;

    tx_vi = &ni->nic_hw[intf_i].vis[CI_Q_ID_NORMAL];
    create = (struct xsn_storage_tx_create_app) {
      .vi_id = cpu_to_le16(ef_vi_instance(tx_vi))
    };
    rc = efrm_ext_msg(plugin, XSN_STORAGE_TX_CREATE_APP, &create, sizeof(create));
    if( rc ) {
      OO_DEBUG_ERR(ci_log("%s: TX_CREATE_APP failed (%d, %d)",
                          __FUNCTION__, intf_i, rc));
      efrm_ext_release(plugin);
      continue;
    }

    ni->nic_hw[intf_i].plugin_tx = plugin;
#endif

    region_id = get_plugin_tx_crc_table_region(trs->nic[intf_i].thn_oo_nic);
    ni->nic_hw[intf_i].plugin_tx_region_id = region_id;
    got_nic = true;
  }
  if( ! got_nic ) {
    OO_DEBUG_ERR(ci_log("%s: no EF100 NICs have the requested plugin",
                        __FUNCTION__));
    return -ENOTSUPP;
  }
#endif
 return 0;
}


static void
destroy_plugin_tx_app(tcp_helper_resource_t* trs)
{
#if CI_CFG_TX_CRC_OFFLOAD
  ci_netif* ni = &trs->netif;
  int intf_i;

  if( NI_OPTS(ni).tcp_offload_plugin != CITP_TCP_OFFLOAD_NVME )
    return;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
#if ! CI_CFG_NVME_LOCAL_CRC_MODE
    struct efrm_ext* plugin = ni->nic_hw[intf_i].plugin_tx;
    if( ! plugin )
      continue;
    efrm_ext_release(plugin);
    ni->nic_hw[intf_i].plugin_tx = NULL;
#endif
    release_plugin_tx_crc_table_region(trs->nic[intf_i].thn_oo_nic,
                                       ni->nic_hw[intf_i].plugin_tx_region_id);
  }
#endif
}


static int
allocate_netif_hw_resources(ci_resource_onload_alloc_t* alloc,
                            tcp_helper_cluster_t* thc,
                            tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  int sz, rc;
  int intf_i;

  OO_DEBUG_SHM(ci_log("%s:", __func__));

  if( NI_OPTS(ni).prealloc_packets && trs->thc_efct_memfd ) {
    int n_rxqs = 0;
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
      struct efhw_nic* nic =
                efrm_client_get_nic(trs->nic[intf_i].thn_oo_nic->efrm_client);
      n_rxqs += efhw_nic_max_shared_rxqs(nic);
    }
    if( n_rxqs ) {
      off_t bytes = CI_HUGEPAGE_SIZE * EFCT_HUGEPAGES_PER_RXQ * n_rxqs;
      rc = vfs_fallocate(trs->thc_efct_memfd, 0, 0, bytes);
      if( rc < 0 ) {
        if( rc == -ENOSPC )
          OO_DEBUG_ERR(ci_log("tcp_helper_alloc: fallocate hugepage memory "
                              "for EF_PREALLOC_PACKETS failed (%d queues): "
                              "ENOSPC. Check /proc/sys/vm/nr_hugepages",
                              n_rxqs));
        else
          OO_DEBUG_ERR(ci_log("tcp_helper_alloc: fallocate hugepage memory "
                              "for EF_PREALLOC_PACKETS failed (%d queues): %d",
                              n_rxqs, rc));
        goto fail0;
      }
    }
  }

  rc = allocate_vis(trs, alloc, ns + 1, thc);
  if( rc < 0 )  goto fail1;

  sz = sizeof(ci_pkt_bufs) * ni->pkt_sets_max;
  if( (ni->pkt_bufs = vmalloc(sz)) == NULL ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to allocate iobufset table"));
    rc = -ENOMEM;
    goto fail4;
  }
  memset(ni->pkt_bufs, 0, sz);

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ni->nic_hw[intf_i].pkt_rs = NULL;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    if( (ni->nic_hw[intf_i].pkt_rs = ci_alloc(sz)) == NULL ) {
      OO_DEBUG_ERR(ci_log("%s: failed to allocate iobufset tables",
                          __FUNCTION__));
      rc = -ENOMEM;
      goto fail5;
    }
    memset(ni->nic_hw[intf_i].pkt_rs, 0, sz);
  }

  /* Advertise the size of the IO and buf mmap that needs to be performed.
   * The queue map size (buf_mmap_bytes) is not known yet, as queue creation
   * might be deferred until after buffer memory allocation. */
  ns->io_mmap_bytes = trs->io_mmap_bytes;
#if CI_CFG_PIO
  ns->pio_mmap_bytes = trs->pio_mmap_bytes;
#endif
#if CI_CFG_CTPIO
  ns->ctpio_mmap_bytes = trs->ctpio_mmap_bytes;
#endif
  ns->efct_shm_mmap_bytes = trs->efct_shm_mmap_bytes;
  ns->timesync_bytes = PAGE_SIZE;

  OO_DEBUG_MEMSIZE(ci_log("helper=%u map_bytes=%u (0x%x)",
                          trs->id,
                          trs->mem_mmap_bytes, trs->mem_mmap_bytes));
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    int i;
    for( i = 0; i < ci_netif_num_vis(ni); ++i )
      LOG_NC(ci_log("VI[%d]=%d", i,
                    ef_vi_instance(&ni->nic_hw[intf_i].vis[i])));
  }

  rc = create_plugin_rx_app(trs);
  if( rc )
    goto fail5;

  rc = create_plugin_tx_app(trs);
  if( rc )
    goto fail6;

  /* This is needed because release_netif_hw_resources() tries to free the ep
  ** table. */
  ni->ep_tbl = 0;

  return 0;

 fail6:
   destroy_plugin_rx_app(trs);
 fail5:
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    if( ni->nic_hw[intf_i].pkt_rs )
      ci_free(ni->nic_hw[intf_i].pkt_rs);
  vfree(ni->pkt_bufs);
 fail4:
  release_vi(trs);
 fail1:
 fail0:
  return rc;
}


static void
release_ep_tbl(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  int i;

  if( ni->ep_tbl != NULL ) {
    for( i = 0; i < ni->ep_tbl_n; ++i ) {
      ci_assert(ni->ep_tbl[i]);
      tcp_helper_endpoint_dtor(ni->ep_tbl[i]);
    }

    /* Ensure that all filter removals have been finished properly
     * before we free ep->oofilter. */
    oof_do_deferred_work(oo_filter_ns_to_manager(trs->filter_ns));

    for( i = 0; i < ni->ep_tbl_n; ++i ) {
      ci_assert(ni->ep_tbl[i]);
      ci_free(ni->ep_tbl[i]);
      CI_DEBUG(ni->ep_tbl[i] = 0);
    }
    ci_vfree(ni->ep_tbl);
    ni->ep_tbl = NULL;
  }

}

static void
release_netif_resources(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  int i;

  OO_DEBUG_SHM(ci_log("%s:", __func__));

  ci_waitq_dtor(&trs->pkt_waitq);
  ci_ipid_dtor(ni);
  eplock_dtor(ni);
  for( i = 0; i < CI_CFG_N_READY_LISTS; i++ )
    ci_waitable_dtor(&trs->ready_list_waitqs[i]);

  oo_shmbuf_free(&ni->shmbuf);
}
static void
release_netif_hw_resources(tcp_helper_resource_t* trs)
{

  OO_DEBUG_SHM(ci_log("%s:", __func__));

  destroy_plugin_rx_app(trs);
  destroy_plugin_tx_app(trs);
  release_vi(trs);

  /* Once all vis are flushed we can release pkt memory */
  release_pkts(trs);
}


int
oo_version_check(const char* version, const char* uk_intf_ver, int debug_lib)
{
  return oo_version_check_impl(version, uk_intf_ver, debug_lib,
                               oo_uk_intf_ver);
}


static int /* bool */ oo_nic_is_vf(const struct oo_nic* onic)
{
  return efrm_client_get_nic(onic->efrm_client)->devtype.function ==
         EFHW_FUNCTION_VF;
}


ci_inline int oo_dev_get_by_name(tcp_helper_resource_t* trs, const char* name)
{
  struct net_device *nd;
  int ifindex;
#ifdef EFRM_DEV_GET_BY_NAME_TAKES_NS
  nd = dev_get_by_name(trs->netif.cplane->cp_netns, name);
#else
  nd = dev_get_by_name(name);
#endif
  if( nd == NULL )
    return 0;
  ifindex = nd->ifindex;
  dev_put(nd);
  return ifindex;
}

static const char IFACELIST_DELIM[] = " \t\n\v\f\r"; /* inspired by isspace() */
static int oo_get_listed_hwports(tcp_helper_resource_t* trs, const char* list,
                                 cicp_hwport_mask_t* hwports_out, const char* tag)
{
  ci_netif* ni = &trs->netif;
  cicp_hwport_mask_t listed_hwports = 0;
  char *token, *running, *dup;
  int found_iface = 0;

  if( *list == '\0' )
    return 1;
  running = dup = kstrdup(list, GFP_KERNEL);
  if( dup == NULL ) {
    ci_log("%s: WARNING no memory to parse interface %s, assuming empty\n",
           __FUNCTION__, tag);
    return 1;
  }

  while( 1 ) {
    int ifindex;
    
    token = strsep(&running, IFACELIST_DELIM);
    if( token == NULL )
      break;
    if( *token == '\0' )
      continue;
    found_iface = 1;
    ifindex = oo_dev_get_by_name(trs, token);
    if( ifindex ) {
      cicp_hwport_mask_t hwport_mask = 0;
      int rc;
      rc = oo_cp_find_llap(ni->cplane, ifindex, NULL, NULL,
                           &hwport_mask /* rx_hwports */, NULL, NULL);
      if( rc == 0 && hwport_mask != 0 ) {
        listed_hwports |= hwport_mask;
      }
      else {
        ci_log("%s: WARNING interface %s constains %s, which "
               " is not identified as Solarflare interface",
               __FUNCTION__, tag, token);
      }
    }
    else {
      ci_log("%s: WARNING interface %s contains %s, which "
             "is not known an interface",
             __FUNCTION__, tag, token);
    }
  }
  *hwports_out = listed_hwports;
  kfree(dup);
  return found_iface ? 0 : 1;
}

/* This function is used to retrive the list of currently active SF
 * interfaces.
 *
 * If ifindices_len > 0, the function is not implemented and returns
 * error.
 *
 * If ifindices_len == 0, then the function performs some
 * initialisation and debug checks.  This is useful for creating
 * stacks without HW (e.g. TCP loopback).
 *
 * If ifindices_len < 0, then the function will autodetect all
 * available SF interfaces based on the cplane information.
 */
static int oo_get_nics(tcp_helper_resource_t* trs, int ifindices_len)
{
  ci_netif* ni = &trs->netif;
  struct oo_nic* onic;
  int rc, i, intf_i;
  ci_hwport_id_t hwport;
  cicp_hwport_mask_t hwport_mask, whitelist_mask;

  efrm_nic_set_clear(&ni->nic_set);
  trs->netif.nic_n = 0;

  if( ifindices_len > CI_CFG_MAX_INTERFACES )
    return -E2BIG;

  for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i )
    ni->hwport_to_intf_i[i] = (ci_int8) -1;
  
  for( i = 0; i < CI_CFG_MAX_INTERFACES; ++i )
    ni->intf_i_to_hwport[i] = (ci_int8) -1;

  hwport_mask = oo_cp_get_hwports(ni->cplane);

  if( oo_get_listed_hwports(trs, NI_OPTS(ni).iface_whitelist,
                            &whitelist_mask, "whitelist") == 0 )
  {
    if( (whitelist_mask & ~hwport_mask) != 0 ) {
      ci_log("%s: WARNING: interface whitelist specifies unlicensed NICs",
             __FUNCTION__);
    }
    /* We only allow whitelist to specify subset of licensed hwports
     * present in current namespace. */
    hwport_mask &= whitelist_mask;
  }

  if( oo_get_listed_hwports(trs, NI_OPTS(ni).iface_blacklist,
                            &whitelist_mask, "blacklist") == 0 )
  {
    if( (whitelist_mask & ~hwport_mask) != 0 ) {
      ci_log("%s: WARNING: interface blacklist specifies unlicensed NICs",
             __FUNCTION__);
    }
    hwport_mask &= ~whitelist_mask;
  }

  if( ifindices_len < 0 ) {
    /* Needed to protect against oo_nics changes */
    rtnl_lock();

    hwport = 0;
    for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i ) {
      for( ; hwport < CI_CFG_MAX_HWPORTS; ++hwport ) {
        if( ~hwport_mask & cp_hwport_make_mask(hwport) )
          continue;
        onic = &oo_nics[hwport];
        if( onic->efrm_client != NULL &&
            /* VIs are created whether the interface is up, down or unplugged.
             * The latter results in "ghost VIs".  As a temporary workaround
             * for bug56347, we avoid creating ghost VIs on VFs. */
            ! (onic->oo_nic_flags & OO_NIC_UNPLUGGED && oo_nic_is_vf(onic)) &&
            oo_check_nic_suitable_for_onload(onic) )
          break;
      }
      if( hwport >= CI_CFG_MAX_HWPORTS )
        break;
      efrm_nic_set_write(&ni->nic_set, intf_i, CI_TRUE);
      trs->nic[intf_i].thn_intf_i = intf_i;
      trs->nic[intf_i].thn_oo_nic = onic;
      ni->hwport_to_intf_i[onic - oo_nics] = intf_i;
      ni->intf_i_to_hwport[intf_i] = hwport;
      ++trs->netif.nic_n;
      ++hwport;
    }

    rtnl_unlock();
  }
  else if( ifindices_len == 0 ) {
    ci_assert_equal(trs->netif.nic_n, 0);
  }
  else {
    /* This code path is not used yet, but this error message will make it
     * obvious what needs doing if we decide to use it in future...
     */
    ci_log("%s: TODO", __FUNCTION__);
    rc = -EINVAL;
    goto fail;
  }

  if( trs->netif.nic_n == 0 && ifindices_len != 0 ) {
    ci_log("%s: ERROR: No Solarflare network interfaces are active/UP,\n"
           "or they are configured with packed stream firmware, disabled,\n"
           "or unlicensed for Onload. Please check your configuration.",
           __FUNCTION__);
    return -ENODEV;
  }
  ni->hwport_mask = hwport_mask;
  return 0;

 fail:
  return rc;
}


ci_inline void efab_notify_stacklist_change(tcp_helper_resource_t *thr)
{
  /* here we should notify tcpdump process that the stack list have
   * changed */
  /*ci_log("add/remove stack %d(%s), refcount %d", thr->id, thr->name,
         oo_atomic_read(&thr->ref_count));*/
  efab_tcp_driver.stack_list_seq++;
  ci_rmb();
  ci_waitq_wakeup(&efab_tcp_driver.stack_list_wq);
}


#if ! CI_CFG_UL_INTERRUPT_HELPER
static int tcp_helper_reprime_is_needed(ci_netif* ni)
{
  ci_assert_equal( NI_OPTS(ni).int_driven, 0);

  if( ci_netif_is_spinner(ni) )
    /* Don't reprime if someone is spinning -- let them poll the stack. */
    return 0;
  if( ni->state->last_spin_poll_frc > ni->state->last_sleep_frc )
    /* A spinning thread has polled the stack more recently than a thread
     * has gone to sleep.  We assume the spinning thread will handle
     * network events (or enable interrupts at some point), so no need to
     * enable interrupts here.
     */
    return 0;
  return 1;
}


/* Defer some task from a driverlink context to non-atomic work item.
 * The caller should hold the shared lock in case of
 * OO_THR_AFLAG_UNLOCK_UNTRUSTED and both shared and trusted locks
 * otherwise.  The caller should not assume that it has the locks after
 * this function is called, because non-atomic work item might be already
 * running and using the locks.
 */
void
tcp_helper_defer_dl2work(tcp_helper_resource_t* trs, ci_uint32 flag)
{
  OO_DEBUG_TCPH(ci_log("%s: [%u] defer locks with flag=%x",
                       __FUNCTION__, trs->id, flag));
  ci_assert(ci_netif_is_locked(&trs->netif));
  CITP_STATS_NETIF_INC(&trs->netif, stack_locks_deferred);
  trs->netif.flags &=~ CI_NETIF_FLAG_IN_DL_CONTEXT;
  /* We need write memory barrier here.  However, both x86 and ppc
   * implementations of ci_atomic32_or() include  a sort of write memory
   * barrier at the beginning.
   * On the flip side, ci_wmb+ci_atomic32_or on ppc result in 2 lwsync
   * instructions one afther another, which is harmful for performance. */
  ci_atomic32_or(&trs->trs_aflags, flag);
  /* And we really need write memory barrier here.  It is harmless on x86:
   * ci_atomic32_or-x86 implementation provides such a barrier but
   * ci_atomic32_or+ci_wmb do not create any additional barrier in the
   * asm code.  But this barrier is really needed on ppc. */
  ci_wmb();
  queue_work(trs->wq, &trs->non_atomic_work);
}

static void
oo_inject_packets_kernel_force(ci_netif* ni)
{
  ci_assert(ci_netif_is_locked(ni));
  if( kernel_packets_pending(ni->state) == 0 )
    return;
  ef_eplock_holder_set_flag(&ni->state->lock,
                            CI_EPLOCK_NETIF_KERNEL_PACKETS);
}


static void tcp_helper_do_non_atomic(struct work_struct *data)
{
  tcp_helper_resource_t* trs = container_of(data, tcp_helper_resource_t,
                                            non_atomic_work);
  const unsigned handled_aflags = (OO_THR_EP_AFLAG_CLEAR_FILTERS |
                                   OO_THR_EP_AFLAG_NEED_FREE |
                                   OO_THR_EP_AFLAG_TCP_OFFLOAD_ISN);
  ci_irqlock_state_t lock_flags;
  tcp_helper_endpoint_t* ep;
  unsigned ep_aflags, new_aflags;
  ci_sllist list;
  ci_sllink* link;
  int need_unlock_shared = 0;

  OO_DEBUG_TCPH(ci_log("%s: [%u]", __FUNCTION__, trs->id));
  ci_assert(! in_atomic());

  /* Handle endpoints that have work queued. */
  ci_irqlock_lock(&trs->lock, &lock_flags);
  list = trs->non_atomic_list;
  ci_sllist_init(&trs->non_atomic_list);
  ci_irqlock_unlock(&trs->lock, &lock_flags);
  while( (link = ci_sllist_try_pop(&list)) != NULL ) {
    ep = CI_CONTAINER(tcp_helper_endpoint_t, non_atomic_link , link);
  again:
    do {  /* grab and clear flags telling us what to do */
      ep_aflags = ep->ep_aflags;
      new_aflags = ep_aflags & ~handled_aflags;
    } while( ci_cas32_fail(&ep->ep_aflags, ep_aflags, new_aflags) );
    OO_DEBUG_TCPH(ci_log("%s: [%u:%d] aflags=%x", __FUNCTION__, trs->id,
                         OO_SP_FMT(ep->id), ep_aflags));
    if( ep_aflags & OO_THR_EP_AFLAG_CLEAR_FILTERS )
      tcp_helper_endpoint_clear_filters(ep, 0);
    if( ep_aflags & OO_THR_EP_AFLAG_NEED_FREE ) {
      /* make sure that the filters are released: */
      tcp_helper_endpoint_clear_filters(ep, 0);
      citp_waitable_obj_free_nnl(&trs->netif,
                                 SP_TO_WAITABLE(&trs->netif, ep->id));
    }
#if CI_CFG_TCP_OFFLOAD_RECYCLER
    if( ep_aflags & OO_THR_EP_AFLAG_TCP_OFFLOAD_ISN ) {
      ci_tcp_state* ts = SP_TO_TCP(&trs->netif, ep->id);
      if( ts->s.b.state == CI_TCP_ESTABLISHED )
        efab_tcp_helper_tcp_offload_set_isn(trs, ep->id, tcp_rcv_nxt(ts));
    }
#endif
    /* Clear the NON_ATOMIC flag while checking to see if more work has
     * been requested.  (Done this way to avoid race with
     * citp_waitable_obj_free().
     */
    do {
      if( (ep_aflags = ep->ep_aflags) & handled_aflags )
        goto again;
      new_aflags = ep_aflags & ~OO_THR_EP_AFLAG_NON_ATOMIC;
    } while( ci_cas32_fail(&ep->ep_aflags, ep_aflags, new_aflags) );
  }

  /* Handle the deferred actions with stolen locks: shared lock. */
  if( trs->trs_aflags & OO_THR_AFLAG_UNLOCK_UNTRUSTED ) {
    ci_atomic32_and(&trs->trs_aflags, ~OO_THR_AFLAG_UNLOCK_UNTRUSTED);
    need_unlock_shared = 1;
  }

  /* Handle the deferred actions with stolen locks: both shared and trusted
   * lock. */
  if( trs->trs_aflags & OO_THR_AFLAG_DEFERRED_TRUSTED ) {
    ci_uint32 trs_aflags;
    OO_DEBUG_TCPH(ci_log("%s: [%u] deferred locks trs_aflags=%d",
                         __FUNCTION__, trs->id, trs->trs_aflags));
    ci_assert(ci_netif_is_locked(&trs->netif));
    ci_assert(oo_trusted_lock_is_locked(trs));

    /* We have the trusted lock, so no one could set new
     * OO_THR_AFLAG_DEFERRED_TRUSTED flags before we handle them.
     * So, it is safe to remove them all at once.
     *
     * From the other hand, we should remove POLL_AND_PRIME flag
     * before it is handled, because event callbacks check for the presence
     * of this flag.  If POLL_AND_PRIME is present, event callbacks assume
     * that poll-and-prime is going to happen soon. */
    trs_aflags = trs->trs_aflags;
    ci_atomic32_and(&trs->trs_aflags, ~OO_THR_AFLAG_DEFERRED_TRUSTED);

    if( trs_aflags & OO_THR_AFLAG_POLL_AND_PRIME ) {
      int intf_i;

      OO_DEBUG_TCPH(ci_log("%s: [%u] deferred POLL_AND_PRIME",
                           __FUNCTION__, trs->id));
      trs->netif.state->poll_did_wake = 0;
      ci_netif_poll(&trs->netif);
      if( NI_OPTS(&trs->netif).int_driven ) {
        ci_netif* ni = &trs->netif;
        OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
          if( ci_bit_test_and_clear(&ni->state->evq_prime_deferred, intf_i) )
            tcp_helper_request_wakeup_nic(trs, intf_i);
      }
      else if( ! trs->netif.state->poll_did_wake &&
               tcp_helper_reprime_is_needed(&trs->netif) ) {
        tcp_helper_request_wakeup(trs);
        CITP_STATS_NETIF_INC(&trs->netif, interrupt_primes);
      }
    }

    efab_tcp_helper_netif_unlock(trs, 0);
  }
  else if( need_unlock_shared )
    efab_eplock_unlock_and_wake(&trs->netif, 0);
}


void tcp_helper_endpoint_queue_non_atomic(tcp_helper_endpoint_t* ep,
                                          unsigned why_aflag)
{
  ci_irqlock_state_t lock_flags;
  unsigned prev_aflags;

  why_aflag |= OO_THR_EP_AFLAG_NON_ATOMIC;
  ci_irqlock_lock(&ep->thr->lock, &lock_flags);
  prev_aflags = tcp_helper_endpoint_set_aflags(ep, why_aflag);
  if( ! (prev_aflags & OO_THR_EP_AFLAG_NON_ATOMIC) ) {
    ci_sllist_push(&ep->thr->non_atomic_list, &ep->non_atomic_link);
    queue_work(ep->thr->wq, &ep->thr->non_atomic_work);
  }
  ci_irqlock_unlock(&ep->thr->lock, &lock_flags);
}

/* Woritem routine to handle postponed stack destruction.
 * Should be run in global workqueue only, not in the stack workqueue
 * because these functions flush and destroy the stack workqueue. */
static void
tcp_helper_destroy_work(struct work_struct *data)
{
  tcp_helper_resource_t* trs = container_of(data, tcp_helper_resource_t,
                                            work_item_dtor);

  if( trs->ref[OO_THR_REF_BASE] == 0 ) {
    tcp_helper_dtor(trs);
    return;
  }

  efab_tcp_helper_rm_free_locked(trs);
}
#endif


ci_inline void tcp_helper_init_max_mss(tcp_helper_resource_t* rs)
{
  /* EF100 uses 22, EF10 uses shorter prefixes */
  const int max_prefix = 22;
  ci_netif* ni = &rs->netif;

  ni->state->max_mss = CI_CFG_PKT_BUF_SIZE - 256 - max_prefix - ETH_HLEN - 
                  ETH_VLAN_HLEN - sizeof(ci_ip4_hdr) - sizeof(ci_tcp_hdr);
}


static int
tcp_helper_rm_alloc_proxy(ci_resource_onload_alloc_t* alloc,
                          const ci_netif_config_opts* opts,
                          int ifindices_len,
                          tcp_helper_resource_t** rs_out)
{
  int rc;

  ci_assert(alloc);
  ci_assert(rs_out);
  ci_assert(ifindices_len <= 0);

  rc = oo_version_check(alloc->in_version, alloc->in_uk_intf_ver, -1);
  if( rc < 0 )
    return rc;

  oo_timesync_wait_for_cpu_khz_to_stabilize();

#if CI_CFG_ENDPOINT_MOVE
  if( alloc->in_flags & CI_NETIF_FLAG_DO_ALLOCATE_SCALABLE_FILTERS_RSS ) {
    tcp_helper_resource_t* rs;
    ci_netif* ni;
    /* Create stack that will be part of a cluster,
     * Cluster will be created if needed.
     */
    ci_uint16 in_flags =
      alloc->in_flags & ~CI_NETIF_FLAG_DO_ALLOCATE_SCALABLE_FILTERS_RSS;
    rc = tcp_helper_cluster_alloc_thr(alloc->in_name,
                                      alloc->in_cluster_size,
                                      alloc->in_cluster_restart,
                                      in_flags,
                                      opts,
                                      &rs);
    if ( rc != 0 )
      return rc;
    ni = &rs->netif;
    ci_assert_equal(rs->id, rs->netif.state->stack_id);
    alloc->out_netif_mmap_bytes = rs->mem_mmap_bytes;
    alloc->out_nic_set = ni->nic_set;
    *rs_out = rs;
    return 0;
  }
  else
#endif
  {
    return tcp_helper_rm_alloc(alloc, opts, ifindices_len,
                               NULL, rs_out);
  }
}


void
tcp_helper_free_ephemeral_ports(struct efab_ephemeral_port_head* table,
                                ci_uint32 entries)
{
  ci_uint32 i;
  for( i = 0; i < entries; ++i ) {
    struct efab_ephemeral_port_keeper* keeper = table[i].head;

    /* Special case: when EF_TCP_SHARED_LOCAL_PORTS_PER_IP is set, the global
     * list of ephemeral ports is kept at the INADDR_ANY entry in the table.
     * These entries are also kept at the locations for their respective IP
     * addresses, so to avoid double-freeing, we detect the global list by
     * checking for an IP-address mismatch. */
    if( keeper != NULL && !CI_IPX_ADDR_EQ(keeper->laddr, table[i].laddr) ) {
      ci_assert(CI_IPX_ADDR_IS_ANY(table[i].laddr));
      continue;
    }

    while( keeper != NULL ) {
      struct efab_ephemeral_port_keeper* next = keeper->next;
      ci_assert(CI_IPX_ADDR_EQ(table[i].laddr, keeper->laddr));
      efab_free_ephemeral_port(keeper);
      keeper = next;
    }
  }
  vfree(table);
}


/* Turns
 *     list_head -> LIST
 * and
 *     new_head -> ... -> new_tail
 * into
 *     list_head -> LIST -> new_head -> ... -> new_tail
 * in a thread-safe manner. */
static void
donate_ephemeral_ports(struct efab_ephemeral_port_head* list_head,
                       struct efab_ephemeral_port_keeper* new_head,
                       struct efab_ephemeral_port_keeper** new_tail_link)
{
  ci_uintptr_t ptr = (ci_uintptr_t) &list_head->head;
  ci_uintptr_t new = (ci_uintptr_t) new_head;

  ci_assert_equal(*new_tail_link, NULL);

  do {
    /* [tail_next_ptr] can change under our feet, which is OK -- the CAS
     * operation later will protect us against this -- but we need
     * OO_ACCESS_ONCE() to force a re-read each time around the loop. */
    ptr = (ci_uintptr_t) OO_ACCESS_ONCE(list_head->tail_next_ptr);
    if( ptr == (ci_uintptr_t) NULL )
      ptr = (ci_uintptr_t) &list_head->head;
  } while( ci_cas_uintptr_fail(ptr, (ci_uintptr_t) NULL, new) );

  ci_wmb();

  /* We have attached our new list-portion to the end of the old list.  We now
   * need to remember the new tail.  There is no need for this to be atomic
   * with respect to the write in the above loop: if another thread sees the
   * intermediate state between that write and the one that we're about to do,
   * it will see a non-NULL old value in its CAS operation and will sit in the
   * loop.  For the same reason, we cannot race with another thread in either
   * of the writes.
   */
  list_head->tail_next_ptr = new_tail_link;
}


void
tcp_helper_donate_ephemeral_ports(struct efab_ephemeral_port_head* list_head,
                                  struct efab_ephemeral_port_keeper* new_head,
                                  struct efab_ephemeral_port_keeper* new_tail,
                                  int count)
{
  /* The addresses of all ports on the list should be equal. */
  ci_assert(CI_IPX_ADDR_EQ(list_head->laddr, new_head->laddr));
  ci_assert(CI_IPX_ADDR_EQ(list_head->laddr, new_tail->laddr));

  donate_ephemeral_ports(list_head, new_head, &new_tail->next);

  ci_atomic32_add(&list_head->port_count, count);
}


/* Add some ephemeral ports to the list of all ephemeral ports (as opposed to
 * an IP-specific list). */
static void
tcp_helper_donate_global_ephemeral_ports(
                                  struct efab_ephemeral_port_head* list_head,
                                  struct efab_ephemeral_port_keeper* new_head,
                                  struct efab_ephemeral_port_keeper* new_tail)
{
  /* This is the global list, which is headed at the INADDR_ANY entry in the
   * table, as that entry is otherwise unused when shared local ports are
   * per-IP. */
  ci_assert(CI_IPX_ADDR_IS_ANY(list_head->laddr));

  donate_ephemeral_ports(list_head, new_head, &new_tail->global_next);
}


int
tcp_helper_alloc_ephemeral_ports(struct efab_ephemeral_port_head* list_head,
                                 struct efab_ephemeral_port_head* global_head,
                                 ci_addr_t laddr, int count)
{
  struct efab_ephemeral_port_keeper* new_head = NULL;
  struct efab_ephemeral_port_keeper* new_global_head = NULL;
  struct efab_ephemeral_port_keeper* new_tail = NULL;
  struct efab_ephemeral_port_keeper* new_global_tail = NULL;
  struct efab_ephemeral_port_keeper* existing = NULL;
  int rc = 0;
  int i;
  OO_DEBUG_TCPH(ci_log("%s count %d", __FUNCTION__, count));

  if( global_head != NULL ) {
    existing = OO_ACCESS_ONCE(list_head->global_consumed);
    if( existing == NULL )
      existing = global_head->head;
  }

  for( i = 0; i < count; ++i ) {
    struct efab_ephemeral_port_keeper* keeper = NULL;
    struct efab_ephemeral_port_keeper* existing_prev = NULL;

    /* In order to keep the set of ephemeral ports as small as possible (where
     * "port" is understood in the strict sense: that is, not an addr:port
     * pair, but merely the port), we first try to get a port for this IP
     * address by binding to one of the ports already used by another IP
     * address. */
    for( rc = -ENODATA; rc != 0 && existing != NULL;
         existing = existing->global_next ) {
      existing_prev = existing;
      rc = efab_alloc_ephemeral_port(laddr, existing->port_be16, &keeper);
      if( rc != 0 && rc != -EADDRINUSE )
        OO_DEBUG_ERR(CI_RLLOG(10, "%s: unexpected failure reusing "
                              CI_IP_PRINTF_FORMAT":%u for %d-th ephemeral "
                              "port: rc=%d", __FUNCTION__,
                              CI_IP_PRINTF_ARGS(&existing->laddr),
                              CI_BSWAP_BE16(existing->port_be16), i, rc));
    }

    /* Remember where we got to in the global list.  We can race against other
     * threads when writing here, but it's benign: the worst that can happen is
     * that the value that's eventually written is earlier in the list than
     * the latest that has been consumed, but this just means that we'll
     * reconsider some ports unnecessarily next time around. */
    if( existing_prev != NULL )
      list_head->global_consumed = existing_prev;

    /* If we didn't manage to allocate an ephemeral port already used by
     * another IP address, get a brand new ephemeral port from the kernel on
     * this IP address. */
    if( keeper == NULL ) {
      if( (rc = efab_alloc_ephemeral_port(laddr, 0, &keeper)) != 0 ) {
        OO_DEBUG_ERR(ci_log("%s: failed to allocate %d-th ephemeral port: "
                            "rc=%d", __FUNCTION__, i, rc));
        break;
      }

      /* This is a genuinely new ephemeral port, so, if we have a global list,
       * add the new port to the chain of elements that we will add to the
       * global list at the end of the function.
       */
      if( global_head != NULL ) {
        if( new_global_tail == NULL )
          new_global_tail = keeper;
        keeper->global_next = new_global_head;
        new_global_head = keeper;
      }
    }

    /* Add the port to the chain of elements that will be added to the per-IP
     * list. */
    if( new_tail == NULL )
      new_tail = keeper;
    keeper->next = new_head;
    new_head = keeper;
  }

  if( i == 0 )
    return rc;

  ci_assert(new_head);
  ci_assert(new_tail);

  /* Append the newly-allocated ports to the caller's list. */
  tcp_helper_donate_ephemeral_ports(list_head, new_head, new_tail, i);

  /* Add genuinely new ephemeral ports to the global list. */
  if( new_global_head != NULL ) {
    ci_assert(global_head);
    ci_assert(new_global_tail);
    tcp_helper_donate_global_ephemeral_ports(global_head, new_global_head,
                                             new_global_tail);
  }

  return i;
}

static int
__efab_create_os_socket(tcp_helper_resource_t* trs, tcp_helper_endpoint_t* ep,
                        struct file* os_file, ci_int32 domain);

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
static
ci_active_wild* tcp_helper_alloc_active_wild(
                                    tcp_helper_resource_t* rs,
                                    struct efab_ephemeral_port_keeper* keeper)
{
  ci_active_wild* aw;
  ci_netif* netif = &rs->netif;
  tcp_helper_endpoint_t* ep;
  ci_uint16 source_be16 = 0;
  int rc;

  /* Get a sock buf */
  aw = ci_active_wild_get_state_buf(netif);
  if( !aw )
    goto fail;

  /* Give it an OS backing socket */
  ep = ci_trs_get_valid_ep(rs, SC_SP(&aw->s));

  /* grab reference to pass to __efab_create_os_socket(),
   * the reference is always consumed (error or not) */
  get_file(keeper->os_file);
  rc = __efab_create_os_socket(rs, ep, keeper->os_file, AF_INET);
  if( rc != 0 )
    goto fail_ep;

  source_be16 = keeper->port_be16;
  ci_sock_set_laddr_port(&aw->s, keeper->laddr, source_be16);

  /* Install filters */
  if( NI_OPTS(&rs->netif).scalable_active_wilds_need_filter )
    rc = tcp_helper_endpoint_set_filters(ep, CI_IFID_BAD, OO_SP_NULL);
  else
    rc = ci_tcp_sock_set_stack_filter(netif, &aw->s);
  if( rc != 0 )
    goto fail_ep;

  return aw;

 fail_ep:
  /* We are already under stack lock, this ensures that we can
   * immediately and safely close the endpoint in
   * efab_tcp_helper_close_endpoint() function.
   * It helps to avoid problems in out-of-resources situation.
   * If we do not close ep immediately, then we got a bad situation
   * when the ep will have multiple entries in the filter table with
   * the same local address. It happens only when we try to allocate
   * active wild for the port which was already used but failed due to
   * out-of-resources.
   */
  efab_tcp_helper_close_endpoint(rs, ep->id, 1);
 fail:
  return NULL;
}


/* Allocate active wild for the port [port]. */
static int
tcp_helper_alloc_to_aw_pool(tcp_helper_resource_t* rs,
                            ci_addr_t laddr,
                            struct efab_ephemeral_port_keeper* port)
{
  ci_netif* ni = &rs->netif;
  int idx;
  ci_active_wild* aw = tcp_helper_alloc_active_wild(rs, port);
  struct oo_p_dllink_state list;

  OO_DEBUG_TCPH(ci_log("%s [%u]", __FUNCTION__, rs->id));

  if( aw == NULL )
    return -ENOBUFS;

  /* The number of pools that are maintained depends on the cluster size.
   * If clustering is not in use then all active wilds are placed on the
   * same pool.
   * If the cluster size is power of two sized then we have cluster_size
   * pools.  We then directly select an appropriate pool for the 3-tuple
   * that's requested, such that the resulting 4-tuple rss hashes to this
   * stack.
   * If the cluster size is not power of two sized then we have a pool for
   * each entry in the RSS indirection table.  That means that there will
   * be multiple possible pools that match for a given 3-tuple.  We will
   * use any of the pools that give us a match for the resulting 4-tuple.
   */

  idx = ni->state->active_wild_pools_n > 1 ?
        ci_netif_active_wild_nic_hash(ni, addr_any, port->port_be16,
                                      addr_any, 0) : 0;
  idx &= ni->state->active_wild_pools_n - 1;

  list = ci_netif_get_active_wild_list(ni, idx, laddr);
  if( list.p == OO_P_NULL ) {
    aw->s.b.sb_aflags |= CI_SB_AFLAG_ORPHAN;
    efab_tcp_helper_drop_os_socket(rs, ci_netif_ep_get(ni, W_SP(&aw->s.b)));
    citp_waitable_obj_free(ni, &aw->s.b);
    return -ENOSPC;
  }

  oo_p_dllink_add(ni, list, oo_p_dllink_sb(ni, &aw->s.b, &aw->pool_link));
  ni->state->active_wild_n++;

  return 0;
}


/* Allocate active wilds for all ports in the list [ports]. */
static int
tcp_helper_alloc_list_to_aw_pool(tcp_helper_resource_t* rs,
                                 ci_addr_t laddr,
                                 struct efab_ephemeral_port_head* ports)
{
  ci_netif* ni = &rs->netif;
  int i = 0;
  int rc;
  struct efab_ephemeral_port_keeper* port = OO_ACCESS_ONCE(ports->head);
  struct efab_ephemeral_port_head* consumed;

  OO_DEBUG_TCPH(ci_log("%s [%u]", __FUNCTION__, rs->id));

  /* Future allocations to the pool, in tcp_helper_alloc_aw_for_ephem_ports(),
   * need to know that we've consumed these ports.  We mark them as consumed
   * even if we fail to allocate the active wilds: in that case, we have
   * bigger problems. */
  rc = tcp_helper_get_ephemeral_port_list(rs->trs_ephem_table_consumed,
                                          laddr,
                                          rs->trs_ephem_table_entries,
                                          &consumed);
  /* If we're calling this function, we must have a list of ephemeral ports for
   * the local address.  This means that we should also succeed in finding
   * (storage for) the "consumed" pointer for that address. */
  ci_assert_ge(rc, 0);
  if( rc < 0 )
    return rc;

  for( ; port != NULL; port = port->next ) {
    int rc = tcp_helper_alloc_to_aw_pool(rs, laddr, port);
    if( rc < 0 ) {
      /* Treat the active wild pool as best effort - we can carry on
       * without it.
       */
      NI_LOG(&rs->netif, RESOURCE_WARNINGS, "%s: Only alloced %d of active"
             " shared", __FUNCTION__, CI_MAX(0, i - 1));
      return -ENOBUFS;
    }
    consumed->head = port;
    ++i;
  }

  if( ! NI_OPTS(ni).tcp_shared_local_ports_per_ip )
    for( i = 0; i < ni->state->active_wild_pools_n; i++ ) {
      struct oo_p_dllink_state list =
                    ci_netif_get_active_wild_list(ni, i, addr_any);
      if( list.p != OO_P_NULL && oo_p_dllink_is_empty(ni, list) ) {
        NI_LOG(&rs->netif, RESOURCE_WARNINGS, "%s: Current shared local ports "
               "don't provide coverage of all possible connections.  Allocate "
               "more to improve coverage.", __FUNCTION__);
        break;
      }
    }

  return 0;
}
#endif


/* These hashing functions are the same as for the per-stack active-wild table,
 * but there's no reason why they have to be, and so in the interests of
 * keeping separate things separate, the implementations are duplicated. */


/* Returns the list of ephemeral ports owned by the cluster for the specified
 * local address.  If such a list does not exist, an empty list is returned,
 * into which new ephemeral ports for that IP address may be inserted.  Unlike
 * the similar function ci_netif_get_active_wild_list(), when creating a new
 * list in this way, that list _is_ immediately and permanently associated with
 * the specified IP address.
 *     This function requires no locks and uses atomic operations to ensure
 * thread-safety.
 */
int
tcp_helper_get_ephemeral_port_list(struct efab_ephemeral_port_head* table,
                                   ci_addr_t laddr, ci_uint32 table_entries,
                                   struct efab_ephemeral_port_head** list_out)
{
  uint32_t bucket, hash1, hash2;

  ci_addr_simple_hash(laddr, table_entries, &hash1, &hash2);
  bucket = hash1;

  do {
    *list_out = &table[bucket];

    /* If the list is non-empty, check the local address. */
    if( CI_IPX_ADDR_EQ((*list_out)->laddr, laddr) )
      return 0;

    /* If we've found an empty list, it means there was no entry in the table
     * for the specified IP address.  We'd like to use this entry to hold a new
     * list, but we have to guard against another concurrent instance of this
     * function trying to do the same thing. */
    if( (*list_out)->port_count == EPHEMERAL_PORT_LIST_NO_PORT &&
        ci_cas32_succeed(&(*list_out)->port_count,
                         EPHEMERAL_PORT_LIST_NO_PORT, 0) ) {
      (*list_out)->laddr = laddr;
      return 0;
    }

    /* The address in this entry wasn't the one we were looking for when we
     * first checked, and it wasn't the magic empty value, either.  So it's
     * probably something else... unless we're racing against another instance
     * of this function with the same value of [laddr].  Check again,
     * relying on the intervening CAS operation to have forced a re-read.  We
     * don't need to check again for emptiness, because entries can only ever
     * transition _away_ from being empty. */
    if( CI_IPX_ADDR_EQ((*list_out)->laddr, laddr) )
      return 0;

    /* This list is for the wrong IP address, so advance to the next bucket. */
    bucket = (bucket + hash2) & (table_entries - 1);
  } while( bucket != hash1 );

  CI_RLLOG(1, "%s: No space in ephemeral port table for local address "
           IPX_FMT, __FUNCTION__, IPX_ARG(AF_IP(laddr)));

  return -ENOSPC;
}


#if CI_CFG_TCP_SHARED_LOCAL_PORTS
/* Allocates active wilds for ephemeral ports on the list [list_head].  The
 * traversal of the list will terminate when a port is reached for which we
 * have previously allocated an active wild. */
static int
tcp_helper_alloc_aw_for_ephem_ports(tcp_helper_resource_t* rs,
                                    struct efab_ephemeral_port_head* list_head,
                                    ci_addr_t laddr)
{
  int rc;
  int count = 0;
  struct efab_ephemeral_port_head* consumed;
  struct efab_ephemeral_port_keeper* port;

  ci_assert(ci_netif_is_locked(&rs->netif));

  rc = tcp_helper_get_ephemeral_port_list(rs->trs_ephem_table_consumed,
                                          laddr,
                                          rs->trs_ephem_table_entries,
                                          &consumed);
  /* If we're calling this function, we must have a list of ephemeral ports
   * for the local address.  This means that we should also succeed in
   * finding (storage for) the "consumed" pointer for that address. */
  ci_assert_ge(rc, 0);
  if( rc < 0 )
    return rc;

  /* If we haven't consumed any yet, start from the beginning of the list. */
  port = consumed->head != NULL ? consumed->head->next : list_head->head;

  for( ; port != NULL; port = port->next ) {
    /* Try to allocate an active wild on this port. */
    if( tcp_helper_alloc_to_aw_pool(rs, laddr, port) == 0 ) {
      consumed->head = port;
      ++count;
    }
  }

  if( count > 0 )
    return count;

  return -ENOENT;
}


int tcp_helper_increase_active_wild_pool(tcp_helper_resource_t* rs,
                                         ci_addr_t laddr)
{
  struct efab_ephemeral_port_head* list_head;
  struct efab_ephemeral_port_head* global_head = NULL;
  const ci_netif_config_opts* ni_opts = &NI_OPTS(&rs->netif);
  int rc;
  const int BATCH_SIZE = 32;
  int to_alloc = ni_opts->tcp_shared_local_ports_step;

  ci_assert(ci_netif_is_locked(&rs->netif));

  /* We can come in here from an ioctl, which should only be made on a stack
   * with shared local ports. */
  ci_assert(rs->trs_ephem_table);
  if( rs->trs_ephem_table == NULL )
    return -EINVAL;

  rc = tcp_helper_get_ephemeral_port_list(rs->trs_ephem_table, laddr,
                                          rs->trs_ephem_table_entries,
                                          &list_head);

  if( rc < 0 )
    return rc;

  /* If we're IP-specific, we also need to get the global list. */
  if( !CI_IPX_ADDR_IS_ANY(laddr) ) {
    rc = tcp_helper_get_ephemeral_port_list(rs->trs_ephem_table, addr_any,
                                            rs->trs_ephem_table_entries,
                                            &global_head);

    if( rc < 0 )
      return rc;
  }

  if( NI_OPTS(&rs->netif).tcp_shared_local_ports_per_ip_max &&
      list_head->port_count >=
      NI_OPTS(&rs->netif).tcp_shared_local_ports_per_ip_max )
    return -ENOBUFS;

  /* Consume any ephemeral ports that were allocated since the last time we
   * increased the active-wild pool. */
  rc = tcp_helper_alloc_aw_for_ephem_ports(rs, list_head, laddr);
  if( rc > 0 )
    to_alloc -= rc;

  while( to_alloc > 0 ) {
    /* Allocate a few more ephemeral ports. */
    rc = tcp_helper_alloc_ephemeral_ports(list_head, global_head, laddr,
                                          CI_MIN(to_alloc, BATCH_SIZE));
    if( rc < 0 )
      goto out;

    /* Try again now that we've allocated some ephemeral ports. */
    rc = tcp_helper_alloc_aw_for_ephem_ports(rs, list_head, laddr);
    if( rc <= 0 )
      goto out;
    to_alloc -= rc;
  }

 out:
  /* We succeeded as long as we increased the pool at all. */
  if( to_alloc < ni_opts->tcp_shared_local_ports_step )
    return 0;
  return rc;
}
#endif


static int
thr_install_tproxy(tcp_helper_resource_t* thr)
{
  int ifindex_buf_size;
  const ci_netif_config_opts* ni_opts = &NI_OPTS(&thr->netif);
  thr->tproxy_ifindex_count =
    ci_netif_requested_scalable_intf_count(thr->netif.cplane, ni_opts);
  ifindex_buf_size = sizeof(*thr->tproxy_ifindex) * thr->tproxy_ifindex_count;

  ci_assert_equal(thr->tproxy_ifindex, NULL);
  thr->tproxy_ifindex = kmalloc(ifindex_buf_size, GFP_KERNEL);
  if( thr->tproxy_ifindex == NULL )
    return -ENOMEM;
  memset(thr->tproxy_ifindex, 0, ifindex_buf_size);
  return tcp_helper_install_tproxy(1, thr, NULL, ni_opts, thr->tproxy_ifindex,
                                   thr->tproxy_ifindex_count);
}


static void
thr_uninstall_tproxy(tcp_helper_resource_t* thr)
{
  if( thr->tproxy_ifindex != NULL ) {
    tcp_helper_install_tproxy(0, thr, NULL, NULL, thr->tproxy_ifindex,
                              thr->tproxy_ifindex_count);
    kfree(thr->tproxy_ifindex);
    thr->tproxy_ifindex = NULL;
  }
}



static inline void netns_get_identifiers(ci_netif_state* state,
                                         const struct net* ns)
{
  struct oo_cplane_handle* cp = cp_acquire_from_netns_if_exists(ns);

  state->netns_id = get_netns_id(ns);

  if( cp != NULL ) {
    state->cplane_pid = oo_cp_get_server_pid(cp);
    cp_release(cp);
  }
  else {
    state->cplane_pid = 0;
  }
}


void tcp_helper_put_ns_components(struct oo_cplane_handle* cplane,
                                  struct oo_filter_ns* filter_ns)
{
  oo_filter_ns_put(&efab_tcp_driver, filter_ns);
  cp_release(cplane);
}


int tcp_helper_get_ns_components(struct oo_cplane_handle** cplane,
                                 struct oo_filter_ns**  filter_ns)
{
  int oof_preexisted;
  int rc;

  /* Kernel uses current->nsproxy->net_ns without any additional locks (for
   * the "current" task only!), so we believe it is safe. */
  *cplane = cp_acquire_from_netns_if_exists(current->nsproxy->net_ns);
  if( *cplane == NULL ) {
    OO_DEBUG_ERR(ci_log("ERROR: cplane server not running"));
    return -ENOMEM;
  }

  /* oof requires respective cplane to be always present
   * Although cplane does not hold reference to oof the fact that the stack
   * does allocates and frees in appropriate order is expected to ensure
   * the condition is met */
  *filter_ns = oo_filter_ns_get(&efab_tcp_driver,
                                current->nsproxy->net_ns, &oof_preexisted);
  if( *filter_ns == NULL ) {
    OO_DEBUG_ERR(ci_log("%s: failed to allocated filter_ns", __func__));
    cp_release(*cplane);
    *cplane = NULL;
    return -ENOMEM;
  }

  /* Sync the just-created oof with the cplane. */
  if( ! oof_preexisted ) {
    rc = oo_cp_oof_sync(*cplane);
    if( rc != 0 )
      goto error;
  }

  return 0;

 error:
  tcp_helper_put_ns_components(*cplane, *filter_ns);
  return rc;
}


struct user_namespace* tcp_helper_get_user_ns(tcp_helper_resource_t* trs)
{
#ifdef EFRM_DO_USER_NS
  return trs->user_ns;
#else
  return NULL;
#endif
}


struct efab_ephemeral_port_head*
tcp_helper_alloc_ephem_table(ci_uint32 min_entries, ci_uint32* entries_out)
{
  struct efab_ephemeral_port_head* table;
  ci_uint32 i;
  ci_uint32 entries;

  ci_assert_gt(min_entries, 0);

  /* Round up to a power of two. */
  if( min_entries > 1 )
    entries = 1u << (__fls(min_entries - 1) + 1);
  else
    entries = 1;

  /* Report the actual number of entries.  If the caller didn't request to be
   * told the number of entries, it had better be sure that the number that it
   * asked for is really the number that it gets. */
  if( entries_out != NULL )
    *entries_out = entries;
  else
    ci_assert_equal(entries, min_entries);

  table = CI_VMALLOC_ARRAY(struct efab_ephemeral_port_head, entries);
  if( table == NULL )
    return NULL;

  for( i = 0; i < entries; ++i ) {
    table[i].port_count = EPHEMERAL_PORT_LIST_NO_PORT;
    table[i].head = NULL;
    table[i].tail_next_ptr = NULL;
    table[i].global_consumed = NULL;
  }

  return table;
}


#if CI_CFG_UL_INTERRUPT_HELPER
static bool
stack_has_events(ci_netif* ni, ci_uint32 intfs)
{
  for( ; intfs != 0 ; intfs &= (intfs - 1) ) {
    int intf = ffs(intfs) - 1;
    if( ci_netif_intf_has_event(ni, intf) )
      return true;
  }
  return false;
}

static bool
stack_has_ul_job(tcp_helper_resource_t* trs, ci_uint32* intfs, ci_uint32* flags)
{
  *intfs = ci_atomic_xchg(&trs->intr_intfs, 0);
  do {
    *flags = trs->ulh_flags;
    if( *flags == 0 )
      break;
  } while( ci_cas32u_fail(&trs->ulh_flags, *flags, 0) );
  
  return *intfs != 0 || *flags != 0;
}

static void
request_pending_wakeups(tcp_helper_resource_t* trs)
{
  ci_uint32 intfs = ci_atomic_xchg(&trs->wake_intfs, 0);
  for( ; intfs != 0; intfs &= intfs - 1 ) {
    int intf_i = ffs(intfs) - 1;
    ci_assert_lt(intf_i, oo_stack_intf_max(&trs->netif));
    tcp_helper_request_wakeup_nic(trs, intf_i);
  }
}

int oo_wait_for_interrupt(ci_private_t* priv, void* argp)
{
  struct oo_ulh_waiter* arg = argp;
  tcp_helper_resource_t* trs = priv->thr;
  int rc = 0;
  bool first = true;
  unsigned long timeout = msecs_to_jiffies(arg->timeout_ms);
  ci_uint32 intfs;

  if( timeout == 0 || timeout > periodic_poll )
    timeout = periodic_poll;

  /* Wait for the next interrupt or timeout */
  while(1) {
    /* Request wakeups before sleeping.  */
    request_pending_wakeups(trs);

    ci_assert_ge(timeout, 1);
    rc = wait_event_interruptible_timeout(
                  trs->ulh_waitq,
                  stack_has_ul_job(trs, &intfs, &arg->flags),
                  timeout);
    if( NI_OPTS(&trs->netif).int_driven && intfs != 0 )
      ci_atomic_or(&trs->wake_intfs, intfs);
    if( rc < 0 )
      return rc;

    /* the helper is the last user */
    if( (arg->rs_ref_count = trs->ref[OO_THR_REF_APP]) > 1 )
      break;
    /* interrupts were not handled by the app, do it by the helper */
    if( stack_has_events(&trs->netif, intfs) || arg->flags != 0 )
      break;
    /* No interrupts, but the stack was not touched for too long.
     * Fixme: Ideally, we'd like to ensure there are no pending ip timers,
     * see stack_next_timer_ms(). */
    if( intfs == 0 &&
        ci_frc64_get() - trs->netif.state->evq_last_prime >
        trs->netif.state->timer_prime_cycles * 5 )
      break;

    if( first ) {
      first = false;
      timeout = periodic_poll + get_random_long() % periodic_poll_skew;
    }
  }

  return 0;
}

static int oo_handle_wakeup_in_ul(void* context, int is_timeout,
                                  struct efhw_nic* nic, int budget)
{
  struct tcp_helper_nic* tcph_nic = context;
  tcp_helper_resource_t* trs;
  ci_uint64 l;

  trs = CI_CONTAINER(tcp_helper_resource_t, nic[tcph_nic->thn_intf_i],
                     tcph_nic);

  ci_atomic_or(&trs->intr_intfs, 1 << tcph_nic->thn_intf_i);

  /* Request prime if no spinner is not spinning now. */
  if( ! NI_OPTS(&trs->netif).int_driven && is_timeout &&
      ! ci_netif_is_spinner(&trs->netif)) {
    ci_atomic_or(&trs->wake_intfs, 1 << tcph_nic->thn_intf_i);
  }

  wake_up(&trs->ulh_waitq);

  /* Ask for poll if anybody is holding the stack lock.
   * Do it after wakeup, because we want to wake the ulhelper up as soon as
   * possible. */
  do {
    l = trs->netif.state->lock.lock;
    if( l & CI_EPLOCK_NETIF_NEED_POLL )
      break;
  } while( ci_cas64u_fail(&trs->netif.state->lock.lock,
                          l, l | CI_EPLOCK_NETIF_NEED_POLL) );

  return 1;
}
#endif

#if defined(EFRM_DO_NAMESPACES) && defined(EFRM_HAVE_NEW_KALLSYMS)
#include <linux/ipc_namespace.h>
/* put_ipc_ns() is not exported */
static void (*my_put_ipc_ns)(struct ipc_namespace *ns);
#endif
static void put_namespaces(tcp_helper_resource_t* rs)
{
#ifdef EFRM_DO_USER_NS
  put_user_ns(rs->user_ns);
#endif
#ifdef EFRM_DO_NAMESPACES
#ifdef OO_HAS_IPC_NS
  if( my_put_ipc_ns != NULL )
    my_put_ipc_ns(rs->ipc_ns);
#endif
  put_pid_ns(rs->pid_ns);
  put_net(rs->net_ns);
#endif
}

static void generate_efct_filter_irqmask(cpumask_t* result)
{
  /* The goal here is to maintain NUMA-locality, but avoid contention between
   * app and IRQs. */
  int cpu;
#ifdef EFRM_TASK_HAS_CPUMASK
/* >= 5.3, backported to RHEL8 */
  cpumask_t* current_cpus = &current->cpus_mask;
#else
  cpumask_t* current_cpus = &current->cpus_allowed;
#endif

  cpumask_clear(result);
  for_each_cpu(cpu, current_cpus)
    cpumask_or(result, result, cpumask_of_node(cpu_to_node(cpu)));
  /* If the app is spanned across every CPU on its node(s) then it's better
   * to have potential contention than to do cross-NUMA stuff. Also covers the
   * degenerate case of an app being unaffinitised. */
  if( ! cpumask_equal(result, current_cpus) )
    cpumask_andnot(result, result, current_cpus);
}

int tcp_helper_rm_alloc(ci_resource_onload_alloc_t* alloc,
                        const ci_netif_config_opts* opts,
                        int ifindices_len, tcp_helper_cluster_t* thc,
                        tcp_helper_resource_t** rs_out)
{
  tcp_helper_resource_t* rs;
  ci_irqlock_state_t lock_flags;
  struct efhw_nic *nic;
  int rc, intf_i;
  ci_netif* ni;
  int hw_resources_allocated = 0;
#ifdef EFRM_DO_NAMESPACES
  struct nsproxy* nsproxy;
#endif

  ci_assert(alloc);
  ci_assert(rs_out);
  ci_assert(ifindices_len <= 0);

  alloc->in_name[CI_CFG_STACK_NAME_LEN] = '\0';

  if( (opts->packet_buffer_mode & CITP_PKTBUF_MODE_PHYS) &&
      !ci_in_egroup(phys_mode_gid) ) {
    OO_DEBUG_ERR(ci_log("%s: ERROR: EF_PACKET_BUFFER_MODE=%d not permitted "
                        "(phys_mode_gid=%d egid=%d pid=%d)", __FUNCTION__,
                        opts->packet_buffer_mode, phys_mode_gid, ci_getegid(),
                        current->tgid);
                 ci_log("%s: HINT: See the phys_mode_gid onload module "
                        "option.", __FUNCTION__));
    rc = -EPERM;
    goto fail1;
  }

  if( opts->packet_buffer_mode & ~CITP_PKTBUF_MODE_PHYS ) {
    OO_DEBUG_ERR(ci_log("%s: ERROR: EF_PACKET_BUFFER_MODE=%d not supported. It "
                        "was used on 6000 series NICs only.", __FUNCTION__,
                        opts->packet_buffer_mode);
                 ci_log("%s: HINT: Use EF_PACKET_BUFFER_MODE=0/2 instead.",
                        __FUNCTION__));
    rc = -ENOTSUPP;
    goto fail1;
  }

#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
  if( opts->xdp_mode == EF_XDP_MODE_COMPATIBLE && ! cplane_track_xdp ) {
    OO_DEBUG_ERR(ci_log("%s: ERROR: EF_XDP_MODE=compatible but "
                        "cplane_track_xdp module parameter is off.",
                        __func__);
                 ci_log("%s: HINT: enable cplane_track_xdp module "
                        "parameter.", __func__));
    rc = -ENOTSUPP;
    goto fail1;
  }
#endif

  rs = CI_ALLOC_OBJ(tcp_helper_resource_t);
  if( !rs ) {
    rc = -ENOMEM;
    goto fail1;
  }

  /* We're attaching to a user app: take all the refcounts
   * for user.
   *
   * We also get an additional refcount of each level to serialize dtor.
   * Destruction functions can be deferred to workqueue, so it is important
   * that lower-level dtor does not start until the previous one has
   * finished.  To archive this, each dtor level drops next-level refcount
   * when done.
   */
  rs->ref[OO_THR_REF_BASE] = 3;
  rs->ref[OO_THR_REF_FILE] = 2;
  rs->ref[OO_THR_REF_APP] = 1;
#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* And another additional BASE reference is for non-zero n_ep_orphaned
   * (in case of non-ulhelper). */
  rs->ref[OO_THR_REF_BASE]++;
#endif

  ni = &rs->netif;

  ni->opts = *opts;
  ci_netif_config_opts_rangecheck(&ni->opts);

  rc = tcp_helper_get_ns_components(&ni->cplane, &rs->filter_ns);
  if( rc != 0 )
    goto fail1a;

  if( oo_accelerate_veth ) {
    ni->cplane_init_net = cp_acquire_from_netns_if_exists(&init_net);
    if( ni->cplane_init_net == NULL ) {
      /* We can tolerate failure to speak to init_net's control plane.  Compare
       * the equivalent case at UL in ci_netif_init(). */
      OO_DEBUG_ERR(ci_log("%s: failed to get init_net control plane handle",
                          __FUNCTION__));
      OO_DEBUG_ERR(ci_log("%s: support for containers will be limited",
                          __FUNCTION__));
    }
  }
  else {
    ni->cplane_init_net = NULL;
  }

  /* Mark that there is a stack present.
   * This will prevent interfaces going down. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ++THR_TABLE.stack_count;
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  rc = oo_get_nics(rs, ifindices_len);
  if( rc < 0 )
    goto fail2;

  /* Allocate an instance number. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  rs->id = ci_id_pool_alloc(&THR_TABLE.instances);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  if (rs->id == CI_ID_POOL_ID_NONE) {
    OO_DEBUG_ERR(ci_log("%s: out of instances", __FUNCTION__));
    rc = -EBUSY;
    goto fail3;
  }

#if ! CI_CFG_UL_INTERRUPT_HELPER
  rs->trusted_lock = OO_TRUSTED_LOCK_LOCKED;
  atomic_set(&rs->timer_running, 0);
#endif
#if CI_CFG_NIC_RESET_SUPPORT
  rs->intfs_to_reset = 0;
  rs->intfs_suspended = 0;
#endif
#if CI_CFG_ENDPOINT_MOVE
  rs->thc = NULL;
#endif
  strcpy(rs->name, alloc->in_name);
  generate_efct_filter_irqmask(&rs->filter_irqmask);

  mutex_init(&rs->usermem_mutex);
  rs->usermem_prev_id = 0;
  rs->usermem = NULL;

  spin_lock_init(&ni->swf_update_lock);
  ni->swf_update_last =  ni->swf_update_first = NULL;

  /* Allocate buffers for shared state, etc. */
  rc = allocate_netif_resources(alloc, rs, thc ? thc->thc_cluster_size : 1);
  if( rc < 0 ) goto fail4;

  /* Initialise work items.
   * Some of them are used in reset handler and in error path. */
#if CI_CFG_NIC_RESET_SUPPORT
  INIT_DELAYED_WORK(&rs->purge_txq_work, tcp_helper_purge_txq_work);
  INIT_WORK(&rs->reset_work, tcp_helper_reset_stack_work);
#endif
#if ! CI_CFG_UL_INTERRUPT_HELPER
  INIT_WORK(&rs->work_item_dtor, tcp_helper_destroy_work);
  INIT_WORK(&rs->non_atomic_work, tcp_helper_do_non_atomic);
  ci_sllist_init(&rs->non_atomic_list);
  ci_sllist_init(&rs->ep_tobe_closed);
#endif
  ci_irqlock_ctor(&rs->lock);
  init_completion(&rs->complete);
#if CI_CFG_HANDLE_ICMP
  rs->icmp_msg = NULL;
  rs->icmp_msg_n = 0;
#endif

#ifdef EFRM_DO_NAMESPACES
  /* Initialise namespaces */
  nsproxy = task_nsproxy_start(current);
  ci_assert(nsproxy);
  rs->net_ns = get_net(nsproxy->net_ns);
  rs->pid_ns = get_pid_ns(ci_get_pid_ns(nsproxy));
#ifdef OO_HAS_IPC_NS
  if( my_put_ipc_ns != NULL )
    rs->ipc_ns = get_ipc_ns(nsproxy->ipc_ns);
#endif
  task_nsproxy_done(current);
  netns_get_identifiers(rs->netif.state, rs->net_ns);
#endif

#ifdef EFRM_DO_USER_NS
  rs->user_ns = current_user_ns();
  get_user_ns(rs->user_ns);
#endif

#if ! CI_CFG_UL_INTERRUPT_HELPER
  rs->periodic_timer_cpu = NI_OPTS(ni).periodic_timer_cpu;
  if( rs->periodic_timer_cpu < 0 )
    rs->periodic_timer_cpu = WORK_CPU_UNBOUND;

  /* "onload-wq:pretty_name workqueue for non-atomic works */
  snprintf(rs->wq_name, sizeof(rs->wq_name), ONLOAD_WQ_NAME,
           ni->state->pretty_name);
  /* This workqueue is used to poll NIC => WQ_CPU_INTENSIVE
   * This workqueue is used to postpone IRQ hanlder when we are out of NAPI
   * budget => WQ_HIGHPRI
   * EF10 postpones packet allocation => WQ_HIGHPRI
   * Users want to set cpu affinity => WQ_SYSFS
   * Long running CPU intensive workloads which can be better
   * managed by the system scheduler => WQ_UNBOUND
   */
  rs->wq = alloc_workqueue(rs->wq_name,
                           WQ_UNBOUND | WQ_CPU_INTENSIVE |
                           WQ_HIGHPRI | WQ_SYSFS, 0);
  if( rs->wq == NULL ) {
    OO_DEBUG_ERR(ci_log("%s: [%d] Failed to allocate stack due to workqueue "
                        "allocation failure", __func__, NI_ID(ni)));
    rc = -ENOMEM;
    goto fail5;
  }
#endif

#if CI_CFG_NIC_RESET_SUPPORT
  /* "onload-wq-reset:pretty_name workqueue for handling resets */
  snprintf(rs->reset_wq_name, sizeof(rs->reset_wq_name), ONLOAD_RESET_WQ_NAME,
           ni->state->pretty_name);
  /* Until we've handled a reset, other activities are pointless => WQ_HIGHPRI
   * Users may want to set cpu affinity => WQ_SYSFS
   */
  rs->reset_wq = alloc_workqueue(rs->reset_wq_name, WQ_UNBOUND |
                                 WQ_HIGHPRI | WQ_SYSFS, 0);
  if( rs->reset_wq == NULL ) {
    OO_DEBUG_ERR(ci_log("%s: [%d] Failed to allocate stack due to reset workqueue "
                        "allocation failure", __func__, NI_ID(ni)));
    rc = - ENOMEM;
    goto fail5a;
  }
#endif

  /* Ready for possible reset: after workqueue is ready, but before any hw
   * resources are allocated. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_dllist_push(&THR_TABLE.started_stacks, &rs->all_stacks_link);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  rs->thc_efct_memfd = NULL;
  rs->thc_efct_memfd_off = 0;
  if( alloc->in_memfd >= 0 ) {
    rs->thc_efct_memfd = fget(alloc->in_memfd);
    if( ! rs->thc_efct_memfd ) {
      rc = -EBADF;
      OO_DEBUG_ERR(ci_log("%s: [%d] Bad fd for efct (%d).",
                  __func__, NI_ID(ni), alloc->in_memfd));
      goto fail_memfd;
    }
  }

  /* Allocate hardware resources */
  ni->ep_tbl = NULL;
  ni->flags = alloc->in_flags;
  ci_assert( ! (alloc->in_flags & CI_NETIF_FLAG_IN_DL_CONTEXT) );
  rc = allocate_netif_hw_resources(alloc, thc, rs);
  if( rc < 0 ) goto fail6;

  if( ci_in_egroup(inject_kernel_gid) ) {
    ni->flags |= CI_NETIF_FLAG_MAY_INJECT_TO_KERNEL;
    ni->state->flags |= CI_NETIF_FLAG_DO_INJECT_TO_KERNEL;
  }

  /* Prepare per-socket data structures, and allocate the first few socket
  ** buffers. */
  ni->ep_tbl_max = NI_OPTS(ni).max_ep_bufs;
  ni->ep_tbl_n = 0;
  ni->ep_tbl = CI_VMALLOC_ARRAY(tcp_helper_endpoint_t*, ni->ep_tbl_max);
  if( ni->ep_tbl == 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_rm_alloc: failed to allocate ep_tbl"));
    rc = -ENOMEM;
    goto fail7;
  }

  rs->trs_aflags = 0;
  ni->kuid = ci_getuid();
  ni->keuid = ci_geteuid();
  ni->error_flags = 0;
  ci_netif_state_init(&rs->netif, oo_timesync_cpu_khz, alloc->in_name);
  OO_STACK_FOR_EACH_INTF_I(&rs->netif, intf_i) {
    nic = efrm_client_get_nic(rs->nic[intf_i].thn_oo_nic->efrm_client);
    if( nic->devtype.arch == EFHW_ARCH_AF_XDP )
      ni->flags |= CI_NETIF_FLAG_AF_XDP;
    if( nic->devtype.arch == EFHW_ARCH_EFCT )
      ni->flags |= CI_NETIF_FLAG_EFCT;
    if( nic->flags & NIC_FLAG_ONLOAD_UNSUPPORTED )
      ni->state->flags |= CI_NETIF_FLAG_ONLOAD_UNSUPPORTED;
#if CI_CFG_NIC_RESET_SUPPORT
    if( nic->resetting )
      tcp_helper_suspend_interface(ni, intf_i);
#endif
  }
  if( oof_use_all_local_ip_addresses || cplane_use_prefsrc_as_local )
    ni->state->flags |= CI_NETIF_FLAG_USE_ALIEN_LADDRS;

  tcp_helper_init_max_mss(rs);

  efab_tcp_helper_more_socks(rs);

  rc = deferred_vis(rs);
  if( rc < 0 )
    goto fail9;

  CI_MAGIC_SET(ni, NETIF_MAGIC);

  if( (rc = ci_netif_init_fill_rx_rings(ni)) != 0 )
    goto fail9;

  rs->tproxy_ifindex = NULL;
  /* When requested set up tproxy mode on selected interface(s) */
  if( (NI_OPTS(ni).scalable_filter_enable != CITP_SCALABLE_FILTERS_DISABLE) &&
      ((NI_OPTS(ni).scalable_filter_mode & CITP_SCALABLE_MODE_RSS) == 0) &&
      thc == NULL ) {
    rc = thr_install_tproxy(rs);
    if( rc != 0 ) {
      OO_DEBUG_ERR(ci_log("%s: [%d] Failed to set scalable filters rc=%d.",
                          __func__, NI_ID(ni), rc));
      goto fail10;
    }
  }

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  /* Create or get the table used to hold the ephemeral ports that are used for
   * active wilds.  If we are clustered then we get this from the cluster;
   * otherwise, we create it ourselves. */
  if( thc != NULL ) {
    rs->trs_ephem_table = thc->thc_ephem_table;
    rs->trs_ephem_table_entries =
      thc->thc_ephem_table_entries;
  }
  else if( ci_netif_should_allocate_tcp_shared_local_ports(ni) ) {
    ci_uint32 entries = CI_MAX(NI_OPTS(ni).tcp_shared_local_ports,
                               NI_OPTS(ni).tcp_shared_local_ports_max);
    rs->trs_ephem_table =
      tcp_helper_alloc_ephem_table(entries, &rs->trs_ephem_table_entries);
    if( rs->trs_ephem_table == NULL ) {
      OO_DEBUG_ERR(ci_log("%s: [%d] Failed to allocate ephemeral port table.",
                          __func__, NI_ID(ni)));
      goto fail11;
    }
  }
  else {
    rs->trs_ephem_table = NULL;
  }

  if( rs->trs_ephem_table != NULL ) {
    /* Now allocate the hash table that tracks the portion of each list that
     * has already been consumed.  This is always particular to the current
     * stack, even if the table of ephemeral ports is shared. */
    rs->trs_ephem_table_consumed =
      tcp_helper_alloc_ephem_table(rs->trs_ephem_table_entries, NULL);
    if( rs->trs_ephem_table_consumed == NULL ) {
      OO_DEBUG_ERR(ci_log("%s: [%d] Failed to allocate table of consumed "
                          "ephemeral ports.", __func__, NI_ID(ni)));
      goto fail12;
    }
  }
  else {
    rs->trs_ephem_table_consumed = NULL;
  }
#endif

  /* We're about to expose this stack to other people.  so we should be
   * sufficiently initialised here that other people don't get upset.
   */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_dllist_remove_safe(&rs->all_stacks_link);
  if( alloc->in_name[0] ) {
    rc = efab_thr_table_check_name(alloc->in_name, rs->netif.cplane->cp_netns);
    if( rc != 0 ) {
      ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
      goto fail13;
    }
  }
  /* This must be set when we are guaranteed that stack creation
   * cannot fail (because stack creation failure calls into stack
   * freeing code which frees the reference to the thc leading us to
   * deadlock with thc creation code).
   */
#if CI_CFG_ENDPOINT_MOVE
  rs->thc = thc;
#endif
  ci_dllist_push(&THR_TABLE.all_stacks, &rs->all_stacks_link);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  /* This must be done after setting rs->thc, as active-wild behaviour depends
   * on the scalable-filter mode, and in particular on whether the scalable
   * filter is clustered.  Doing this after adding the stack to the global list
   * is safe, because all active-wild consumers require the stack lock, which
   * we still hold.
   *     If scalable filters are requested to be created for workers, so are
   * shared local ports.  Also, if we're reserving shared local ports by
   * binding to specific ip addresses, we can't reserve any up-front. */
  if( ci_netif_should_allocate_tcp_shared_local_ports(ni) &&
      ! NI_OPTS(ni).tcp_shared_local_ports_per_ip ) {
    struct efab_ephemeral_port_head* ephemeral_ports;
    /* We know on this path that shared local ports are not per-IP, so we use
     * an address of zero here where appropriate, and we don't need to pass in
     * a separate global table. */
    if( thc == NULL ) {
      tcp_helper_get_ephemeral_port_list(rs->trs_ephem_table, addr_any,
                                         rs->trs_ephem_table_entries,
                                         &ephemeral_ports);
      tcp_helper_alloc_ephemeral_ports(ephemeral_ports, NULL, addr_any,
                                       NI_OPTS(ni).tcp_shared_local_ports);
      /* In the event that tcp_helper_alloc_ephemeral_ports() returns an error,
       * there's nothing to do here: a warning will have been printed, and we
       * can continue with an empty list of ephemeral ports. */
    }
    else {
      tcp_helper_get_ephemeral_port_list(thc->thc_ephem_table, addr_any,
                                         thc->thc_ephem_table_entries,
                                         &ephemeral_ports);
    }
    tcp_helper_alloc_list_to_aw_pool(rs, addr_any, ephemeral_ports);
  }
#endif

  /* We deliberately avoid starting periodic timer and callback until now,
   * so we don't have to worry about stopping them if we bomb out early.
   *
   * Although the stack is visible before this point, it's only once we unlock
   * it that other users can start to do things that require these to have
   * been initialised.
   */
  OO_STACK_FOR_EACH_INTF_I(&rs->netif, intf_i) {
#if CI_CFG_UL_INTERRUPT_HELPER
      efrm_eventq_register_callback(tcp_helper_vi(rs, intf_i),
                                    &oo_handle_wakeup_in_ul,
                                    &rs->nic[intf_i]);
#else
    if( NI_OPTS(ni).int_driven )
      efrm_eventq_register_callback(tcp_helper_vi(rs, intf_i),
                                    &oo_handle_wakeup_int_driven,
                                    &rs->nic[intf_i]);
    else
      efrm_eventq_register_callback(tcp_helper_vi(rs, intf_i),
                                    &oo_handle_wakeup_or_timeout,
                                    &rs->nic[intf_i]);
#endif
  }
#if ! CI_CFG_UL_INTERRUPT_HELPER
  tcp_helper_initialize_and_start_periodic_timer(rs);
  if( NI_OPTS(ni).int_driven )
    tcp_helper_request_wakeup(netif2tcp_helper_resource(ni));
  efab_tcp_helper_netif_unlock(rs, 0);
#else
  ni->state->lock.lock = 0;
#endif


  efab_notify_stacklist_change(rs);

  alloc->out_netif_mmap_bytes = rs->mem_mmap_bytes;
  alloc->out_nic_set = ni->nic_set;
  *rs_out = rs;
  OO_DEBUG_RES(ci_log("tcp_helper_rm_alloc: allocated %u", rs->id));
  return 0;

 fail13:
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  vfree(rs->trs_ephem_table_consumed);
 fail12:
  /* Free the table of ephemeral ports unless we share it with the cluster. */
  if( thc == NULL )
    vfree(rs->trs_ephem_table);
 fail11:
#endif
 fail10:
 fail9:
  release_ep_tbl(rs);
 fail7:
  /* Do not call release_netif_hw_resources() now - do it later, after
   * we're out of THR_TABLE. */
  hw_resources_allocated = 1;
 fail6:

  /* Remove from the THR_TABLE and handle possible reset
   * before trying to remove VIs. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_dllist_remove(&rs->all_stacks_link);
  ci_dllink_mark_free(&rs->all_stacks_link);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

#if CI_CFG_NIC_RESET_SUPPORT
  /* We might have been reset, so provide a lock for potential waiter.  We
   * don't want to (and can't safely) run any unlock hooks.  Ignoring them is
   * safe since the only other possible user of this stack is reset work, which
   * doesn't require that we handle any of the flags. */
  ef_eplock_clear_flags(&ni->state->lock, CI_EPLOCK_NETIF_UNLOCK_FLAGS);
  efab_tcp_helper_netif_unlock(rs, 0);
  flush_workqueue(rs->reset_wq);
  efab_tcp_helper_netif_try_lock(rs, 0);
#endif

  if( hw_resources_allocated )
    release_netif_hw_resources(rs);

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* tcp_helper_stop_periodic_work() has the side-effect of flushing the
   * workqueue. */
  tcp_helper_stop_periodic_work(rs);
#endif

  if( rs->thc_efct_memfd )
    fput(rs->thc_efct_memfd);
 fail_memfd:
#if CI_CFG_NIC_RESET_SUPPORT
  destroy_workqueue(rs->reset_wq);
 fail5a:
#endif
#if ! CI_CFG_UL_INTERRUPT_HELPER
  destroy_workqueue(rs->wq);
 fail5:
#endif
  put_namespaces(rs);
  release_netif_resources(rs);
 fail4:
  ci_id_pool_free(&THR_TABLE.instances, rs->id, &THR_TABLE.lock);
 fail3:
 fail2:
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_assert(THR_TABLE.stack_count > 0);
  --THR_TABLE.stack_count;
  /* EEXIST has a special significance: it means that the requested stackname
   * was already taken, meaning that UL should (re)try to map in the stack of
   * that name rather than to create a new one.  Races that can result in
   * such stackname clashes can also break stack-creation in other ways --
   * scalable filters are a case in point -- and in such cases we would prefer
   * to report EEXIST rather than the other arbitrary error so that UL can
   * recover. */
  if( rc != -EEXIST && alloc->in_name[0] ) {
    int rc1 = efab_thr_table_check_name(alloc->in_name,
                                        rs->netif.cplane->cp_netns);
    if( rc1 == -EEXIST )
      rc = rc1;
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  if( ni->cplane_init_net != NULL )
    cp_release(ni->cplane_init_net);
  tcp_helper_put_ns_components(ni->cplane, rs->filter_ns);
 fail1a:
  CI_FREE_OBJ(rs);
 fail1:
  return rc;
}

int tcp_helper_alloc_ul(ci_resource_onload_alloc_t* alloc,
                        int ifindices_len, tcp_helper_resource_t** rs_out)
{
  ci_netif_config_opts* opts;
  int rc;

  if( (opts = kmalloc(sizeof(*opts), GFP_KERNEL)) == NULL )
    return -ENOMEM;
  rc = -EFAULT;
  if( copy_from_user(opts, CI_USER_PTR_GET(alloc->in_opts), sizeof(*opts)) )
    goto out;

  rc = tcp_helper_rm_alloc_proxy(alloc, opts, ifindices_len, rs_out);
 out:
  kfree(opts);
  return rc;
}


int tcp_helper_alloc_kernel(ci_resource_onload_alloc_t* alloc,
                            const ci_netif_config_opts* opts,
                            int ifindices_len, tcp_helper_resource_t** rs_out)
{
  return tcp_helper_rm_alloc_proxy(alloc, opts, ifindices_len, rs_out);
}


#if CI_CFG_NIC_RESET_SUPPORT
static void thr_reset_stack_rx_cb(ef_request_id id, void* arg)
{
  tcp_helper_resource_t* thr = (tcp_helper_resource_t*)arg;
  ci_netif* ni = &thr->netif;
  oo_pkt_p pp;
  ci_ip_pkt_fmt* pkt;
  OO_PP_INIT(ni, pp, id);
  pkt = PKT_CHK(ni, pp);
  ci_netif_pkt_release(ni, pkt);
}


struct thr_reset_stack_tx_cb_state {
  int intf_i;
  struct ci_netif_poll_state ps;
  tcp_helper_resource_t* thr;
};

static void
thr_reset_stack_tx_cb_state_init(struct thr_reset_stack_tx_cb_state* cb_state,
                                 tcp_helper_resource_t* thr, int intf_i)
{
  cb_state->intf_i = intf_i;
  cb_state->thr = thr;
  cb_state->ps.tx_pkt_free_list_insert = &cb_state->ps.tx_pkt_free_list;
  cb_state->ps.tx_pkt_free_list_n = 0;
}

static void thr_reset_stack_tx_cb(ef_request_id id, void* arg)
{
  struct thr_reset_stack_tx_cb_state* cb_state =
    (struct thr_reset_stack_tx_cb_state*)arg;
  ci_netif* ni = &cb_state->thr->netif;
  oo_pkt_p pp;
  ci_ip_pkt_fmt* pkt;

  OO_PP_INIT(ni, pp, id);
  pkt = PKT_CHK(ni, pp);
  ++ni->state->nic[cb_state->intf_i].tx_dmaq_done_seq;
  ci_netif_tx_pkt_complete(ni, &cb_state->ps, pkt);
}
#endif

#if ! CI_CFG_UL_INTERRUPT_HELPER
/* All delayed work is now run on the periodic workqueue. */
static inline int thr_queue_delayed_work(tcp_helper_resource_t* thr,
                                         struct delayed_work *dwork,
                                         unsigned long delay)
{
  return queue_delayed_work_on(thr->periodic_timer_cpu, thr->wq,
                               dwork, delay);
}
#endif

#if CI_CFG_NIC_RESET_SUPPORT
#define TXQ_PURGE_PERIOD (HZ / 10)
static void tcp_helper_purge_txq_locked(tcp_helper_resource_t* thr)
{
  /* We want to purge the TXQs of any interfaces which have been unplugged but
   * have not returned yet.  This is only safe if the hardware is actually
   * gone, as opposed merely to having been suspended in anticipation of a
   * reset.  The former implies that the suspension has also happened, though,
   * so for now we record the mask of suspended interfaces and will check later
   * whether in fact the hardware has gone. */
  unsigned intfs_suspended = OO_ACCESS_ONCE(thr->intfs_suspended);
  ci_netif* ni = &thr->netif;
  int intf_i;
  int reschedule = 0;

  OO_DEBUG_VERB(ci_log("%s: [%d] Purging TXQs for suspended interfaces %08x",
                       __FUNCTION__, thr->id, intfs_suspended));

  ci_assert(ci_netif_is_locked(ni));

  for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i )
    if( intfs_suspended & (1 << intf_i) ) {
      struct efhw_nic* nic;
      nic = efrm_client_get_nic(thr->nic[intf_i].thn_oo_nic->efrm_client);
      /* Purge the TXQ only if the hardware has been removed, to avoid races
       * against subsequent TX completions.  The flag that we check can change
       * asynchronously, but races against such changes are harmless; the full
       * reset work will always be done precisely once and after any purging
       * that we do here, and that's what matters. */
      if( nic->resetting & NIC_RESETTING_FLAG_UNPLUGGED ) {
        struct thr_reset_stack_tx_cb_state cb_state;
        ef_vi* vi = ci_netif_vi(ni, intf_i);
        thr_reset_stack_tx_cb_state_init(&cb_state, thr, intf_i);
        ef_vi_txq_reinit(vi, thr_reset_stack_tx_cb, &cb_state);
        /* Purge the eventq as well, to get rid of any references to TX
         * descriptors that we just purged. */
        ef_vi_evq_reinit(vi);

        /* We will continue to reschedule this work item for as long as there
         * are defunct queues to purge. */
        reschedule = 1;
      }
    }

  if( reschedule )
    thr_queue_delayed_work(thr, &thr->purge_txq_work, TXQ_PURGE_PERIOD);
}
#endif


static void set_pkt_bufset_hwaddrs(ci_netif* ni, int bufset_id, int intf_i,
                                   const ci_uint64* hw_addrs)
{
  int i;
  int page_order = ni->packets->set[bufset_id].page_order;
  ef_addr* addr = ni->dma_addrs +
                  ni->packets->set[bufset_id].dma_addr_base +
                  intf_i * (PKTS_PER_SET >> page_order);

  for( i = 0; i < PKTS_PER_SET >> page_order; i++ ) {
    int pkti = i << page_order;
    ci_uint64 pkt_addr = hw_addrs[pkti / PKTS_PER_HW_PAGE];
    addr[i] = pkt_addr + CI_MEMBER_OFFSET(ci_ip_pkt_fmt, dma_start);
  }
}


#if CI_CFG_NIC_RESET_SUPPORT
static void tcp_helper_reset_stack_locked(tcp_helper_resource_t* thr)
{
  ci_irqlock_state_t lock_flags;
  unsigned intfs_to_reset;
  int intf_i, i, pkt_sets_n;
  ci_netif* ni = &thr->netif;
  ef_vi* vi;
  struct thr_reset_stack_tx_cb_state cb_state;
  uint64_t *hw_addrs;
#if CI_CFG_PIO
  struct efhw_nic* nic;
  int rc;
#endif

  ci_assert(ci_netif_is_locked(ni));

  /* We walked this link to find this stack to reset in the first place, but
   * it might have been invalidated while we were waiting for the lock. */
  if( ci_dllink_is_free(&thr->all_stacks_link) ) {
    OO_DEBUG_TCPH(ci_log("%s: [%d] Stack is being destroyed; not resetting",
                         __FUNCTION__, thr->id));
    return;
  }

  ci_irqlock_lock(&thr->lock, &lock_flags);
  intfs_to_reset = thr->intfs_to_reset;
  thr->intfs_to_reset = 0;
  /* Prevent any further periodic TXQ-purges, since we're about to bring the
   * TXQ back up. */
  thr->intfs_suspended &=~ intfs_to_reset;
  ci_irqlock_unlock(&thr->lock, &lock_flags);

#if CI_CFG_ENDPOINT_MOVE
  if( thr->thc != NULL ) {
    /* This warning can be removed once Bug43452 is properly addressed */
    ci_log("Stack %s:%d in cluster %s can't restore filters post-NIC-reset.\n"
           "This stack will no longer receive packets",
           thr->name, thr->id, thr->thc->thc_name);
  }
#endif

  pkt_sets_n = ni->pkt_sets_n;

  hw_addrs = ci_alloc(sizeof(uint64_t) * (1 << HW_PAGES_PER_SET_S));
  if( hw_addrs == NULL ) {
    ci_log("%s: [%d] out of memory", __func__, thr->id);
    return;
  }

  for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i ) {
    if( intfs_to_reset & (1 << intf_i) ) {
      ci_netif_state_nic_t* nsn = &ni->state->nic[intf_i];
      ci_uint32 old_errors = nsn->nic_error_flags;
      vi = ci_netif_vi(ni, intf_i);

      EFRM_WARN_LIMITED("%s: reset stack %d intf %d (0x%x)",
                        __FUNCTION__, thr->id, intf_i, intfs_to_reset);

#if CI_CFG_PIO
      nic = efrm_client_get_nic(thr->nic[intf_i].thn_oo_nic->efrm_client);
      if( NI_OPTS(ni).pio &&
          (nic->devtype.arch == EFHW_ARCH_EF10) && 
          (thr->nic[intf_i].thn_pio_io_mmap_bytes != 0) ) {
        struct efrm_pd *pd = efrm_vi_get_pd(tcp_helper_vi(thr, intf_i));
        OO_DEBUG_TCPH(ci_log("%s: realloc PIO", __FUNCTION__));
        /* Now try to recreate and link the PIO region */
        rc = efrm_pio_realloc(pd, thr->nic[intf_i].thn_pio_rs, 
                              tcp_helper_vi(thr, intf_i));
        if( rc < 0 ) {
          OO_DEBUG_TCPH(ci_log("%s: [%d:%d] pio_realloc failed %d, "
                               "removing PIO capability", 
                               __FUNCTION__, thr->id, intf_i, rc));
          thr->pio_mmap_bytes -= thr->nic[intf_i].thn_pio_io_mmap_bytes;
          /* Expose failure to user-level */
          ni->state->pio_mmap_bytes -= thr->nic[intf_i].thn_pio_io_mmap_bytes;
          thr->nic[intf_i].thn_pio_io_mmap_bytes = 0;
          thr->netif.nic_hw[intf_i].pio.pio_buffer = NULL;
          thr->netif.nic_hw[intf_i].pio.pio_len = 0;
          nsn->oo_vi_flags &=~ OO_VI_FLAGS_PIO_EN;
          nsn->pio_io_mmap_bytes = 0;
          nsn->pio_io_len = 0;
          ci_pio_buddy_dtor(ni, &nsn->pio_buddy);
          /* Leave efrm references in place as we can't remove them
           * now - they will get removed as normal when stack
           * destroyed
           */
        }
      }
#endif

      /* Remap packets before using them in RX q */
      nsn->nic_error_flags &=~ CI_NETIF_NIC_ERROR_REMAP;
      for( i = 0; i < pkt_sets_n; ++i ) {
        int rc;

        rc = oo_iobufset_resource_remap_bt(ni->nic_hw[intf_i].pkt_rs[i],
                                          hw_addrs);
        if( rc == -ENOSYS ) {
          /* This PD does not use buffer table; do not update anything and
           * go away. */
          ci_assert_equal(i, 0);
          break;
        }

        if( rc != 0 ) {
          /* The stack is running, but packet mapping is invalidated.  We have
           * no good solution.  Just let's reset all hardware addresses and
           * wait for user to kill the app, or for another reset to attempt
           * to recover things. */
          ci_log("ERROR [%d]: failed to remap packet set %d after NIC reset",
                 thr->id, i);
          memset(hw_addrs, 0, sizeof(uint64_t) * (1 << HW_PAGES_PER_SET_S));
          nsn->nic_error_flags |= CI_NETIF_NIC_ERROR_REMAP;
        }

        set_pkt_bufset_hwaddrs(ni, i, intf_i, hw_addrs);
      }
      if( ~nsn->nic_error_flags & CI_NETIF_NIC_ERROR_REMAP ) {
        if( old_errors & CI_NETIF_NIC_ERROR_REMAP )
          ci_log("[%d]: packets remapped successfully on intf %d", thr->id,
                 intf_i);
      }

      /* Reset sw queues */
      ef_vi_evq_reinit(vi);
      ef_vi_rxq_reinit(vi, thr_reset_stack_rx_cb, thr);

      thr_reset_stack_tx_cb_state_init(&cb_state, thr, intf_i);
      ef_vi_txq_reinit(vi, thr_reset_stack_tx_cb, &cb_state);

      /* Reset hw queues.  This must be done after resetting the sw
         queues as the hw will start delivering events after being reset.  If
         we failed to map packet buffers, we don't bring the hw queues back up
         to ensure that we don't attempt to DMA to an invalid address. */
      if( ~nsn->nic_error_flags & CI_NETIF_NIC_ERROR_REMAP )
        efrm_vi_qs_reinit(tcp_helper_vi(thr, intf_i));
      else
        efrm_vi_resource_mark_shut_down(tcp_helper_vi(thr, intf_i));

      if( cb_state.ps.tx_pkt_free_list_n )
        ci_netif_poll_free_pkts(ni, &cb_state.ps);

      if( OO_PP_NOT_NULL(nsn->rx_frags) ) {
        ci_ip_pkt_fmt* pkt = PKT_CHK(ni, nsn->rx_frags);
        nsn->rx_frags = OO_PP_NULL;
        ci_netif_pkt_release(ni, pkt);
      }

      if( NI_OPTS(ni).timer_usec != 0 ) 
        ef_eventq_timer_prime(vi, NI_OPTS(ni).timer_usec);

      ci_bit_test_and_set(&ni->state->evq_primed, intf_i);
      tcp_helper_request_wakeup_nic(thr, intf_i);
    }
  }

#if CI_CFG_PIO
  /* This should only be done after we have tried to reacquire PIO
   * regions. */
  ci_tcp_tmpl_handle_nic_reset(ni);
#endif

  ci_free(hw_addrs);
}


void tcp_helper_suspend_interface(ci_netif* ni, int intf_i)
{
  tcp_helper_resource_t* thr;
  ci_irqlock_state_t lock_flags;

  thr = CI_CONTAINER(tcp_helper_resource_t, netif, ni);

  ci_irqlock_lock(&thr->lock, &lock_flags);
  thr->intfs_suspended |= (1 << intf_i);
  ci_irqlock_unlock(&thr->lock, &lock_flags);

  /* If a bonded interface is hot-unplugged, we fail over to another slave.
   * There is potentially a considerable interval between an interface going
   * away and the failover actually happening, during which time Onload will
   * merrily post packets to the defunct NIC's TXQ.  Naturally no completion
   * will be generated for such packets, and so they are not eligible for
   * retransmission.  If these packets are left there, any TCP connections to
   * which they belong will stall, and will be reset if the hardware does not
   * reappear quickly enough.  To avoid this problem, we purge defunct TXQs
   * periodically.  (In non-bonded scenarios there is no benefit to this, but
   * no harm either).
   */
  thr_queue_delayed_work(thr, &thr->purge_txq_work, 0);
}

void tcp_helper_reset_stack(ci_netif* ni, int intf_i)
{
  tcp_helper_resource_t* thr = CI_CONTAINER(tcp_helper_resource_t, netif, ni);
  ci_irqlock_state_t lock_flags;

  ci_irqlock_lock(&thr->lock, &lock_flags);
  /* We would like to assert that the corresponding bit in thr->intfs_suspended
   * is already set, but a race against stack-allocation means that's not quite
   * necessarily true. */
  thr->intfs_to_reset |= (1 << intf_i);
  ci_irqlock_unlock(&thr->lock, &lock_flags);

  /* Call tcp_helper_reset_stack_locked from non-dl context only.
   * todo: net driver should tell us if it is dl context */
  queue_work(thr->reset_wq, &thr->reset_work);
}
#endif


#if CI_CFG_NIC_RESET_SUPPORT
static void tcp_helper_purge_txq_work(struct work_struct *data)
{
  tcp_helper_resource_t* trs;

#ifdef EFX_NEED_WORK_API_WRAPPERS
  trs = container_of(data, tcp_helper_resource_t, purge_txq_work);
#else
  trs = container_of(data, tcp_helper_resource_t, purge_txq_work.work);
#endif

  /* If we can get the lock, we purge the queues now; if not, we defer to the
   * lock-holder. */
  if( efab_tcp_helper_netif_lock_or_set_flags(trs, OO_TRUSTED_LOCK_PURGE_TXQS,
                                              CI_EPLOCK_NETIF_PURGE_TXQS, 0) ) {
    tcp_helper_purge_txq_locked(trs);
    efab_tcp_helper_netif_unlock(trs, 0);
  }
}

static void tcp_helper_reset_stack_work(struct work_struct *data)
{
  tcp_helper_resource_t* trs = container_of(data, tcp_helper_resource_t,
                                            reset_work);

  /* Before tcp_helper_reset_stack_locked is called,
   * any stack activity is just silly.  So we agressively wait for
   * the stack lock to reset the stack as early as possible.
   *
   * However, we have to cope with the possibility that we're blocked waiting
   * for a wedged lock.  If we know the lock may already be wedged we can
   * just trylock here.  Otherwise block, but allow interruption by a wakeup.
   */
  while (! (trs->trs_aflags & OO_THR_AFLAG_DONT_BLOCK_SHARED) ) {
    int rc = ci_netif_lock_maybe_wedged(&trs->netif);
    if( rc == 0 ) {
      goto locked;
    }
    if( rc == -ECANCELED ) {
      /* In the wedged case, we'll get OO_THR_AFLAG_DONT_BLOCK_SHARED flag
       * sooner or later.  Otherwise it does not harm to try again. */
      continue;
    }
    else {
      /* Workqueue was interrupted by a signal - give up */
      break;
    }
  }

  /* I believe we can get here if the stack is going to be destroyed only.
   * However I can't find a good ci_assert() sentence to verify that the
   * stack is under destruction.  OO_TRUSTED_LOCK_AWAITING_FREE is not an
   * option, because it is set too late. */
  if( ! ci_netif_trylock(&trs->netif) ) {
    /* It is probably OK, but let's print a warning. */
    ci_log("[%d]: unable to process NIC reset before destroying stack",
           trs->id);
    return;
  }
 locked:
  ci_assert(ci_netif_is_locked(&trs->netif));
  tcp_helper_reset_stack_locked(trs);
  ci_netif_unlock(&trs->netif);
}
#endif


#if ! CI_CFG_UL_INTERRUPT_HELPER || ! defined(NDEBUG)
static bool
current_is_proper_ul_context(void)
{
  return ! in_interrupt() &&
      (current->flags & (PF_KTHREAD | PF_WQ_WORKER)) == 0;
}
#endif

/*--------------------------------------------------------------------
 *!
 * Called when reference count on a TCP helper resource reaches zero.
 * The code is arranged so that this happens when the user-mode closes
 * the last efab file - irrespective of whether any TCP connections
 * need to live on
 *
 * At this stage we need to recover from corruption of the shared eplock
 * state - for exmaple, user application may have crashed whilst holding
 * this lock. However, we need to be race free against valid kernel users
 * of this lock - therefore, we proceed only once we have obtained the
 * kernel netif lock
 *
 * \param trs             Efab resource
 *
 *--------------------------------------------------------------------*/

static void
tcp_helper_rm_free(tcp_helper_resource_t* trs)
{
#if ! CI_CFG_UL_INTERRUPT_HELPER
  unsigned l, new_l;
#endif

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 1);

  OO_DEBUG_TCPH(ci_log("%s: [%u]", __FUNCTION__, trs->id));

#if ! CI_CFG_UL_INTERRUPT_HELPER
  do {
    l = trs->trusted_lock;
    /* NB. We clear other flags when setting AWAITING_FREE.
     * tcp_helper_rm_free_locked() will close pending sockets, and other
     * flags are not critical.
     */
    new_l = OO_TRUSTED_LOCK_LOCKED | OO_TRUSTED_LOCK_AWAITING_FREE;
  } while( ci_cas32u_fail(&trs->trusted_lock, l, new_l) );

  if( l & OO_TRUSTED_LOCK_LOCKED )
    /* Lock holder will call efab_tcp_helper_rm_free_locked(). */
    return;
#endif

#if CI_CFG_UL_INTERRUPT_HELPER
  ci_assert(current_is_proper_ul_context());
#else
  if( trs->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT ||
      ! current_is_proper_ul_context() )
    efab_tcp_helper_rm_schedule_free(trs);
  else
#endif
    efab_tcp_helper_rm_free_locked(trs);
  OO_DEBUG_TCPH(ci_log("%s: [%u] done", __FUNCTION__, trs->id));
}


#if ! CI_CFG_UL_INTERRUPT_HELPER
/*--------------------------------------------------------------------
 *!
 * Enqueues a work-item to call tcp_helper_dtor() at a safe time.
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

static void
tcp_helper_dtor_schedule(tcp_helper_resource_t * trs)
{
  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));
  ci_verify( queue_work(CI_GLOBAL_WORKQUEUE, &trs->work_item_dtor) != 0);
}
#endif

/*--------------------------------------------------------------------
 * Called when [trs->k_ref_count] goes to zero.  This can only happen
 * after all references to the resource have gone, and all sockets have
 * reached closed.
 *
 * \param trs               TCP helper resource
 *--------------------------------------------------------------------*/

static void
efab_tcp_helper_k_ref_count_is_zero(tcp_helper_resource_t* trs)
{
  /* although we have atomically got to zero we still have to contend
   * with a possible race from the resource manager destruction
   * (which needs the ability to force destruction of orphaned resources)
   * Therefore, we still have to test whether resource is in the list
   */
  ci_irqlock_state_t lock_flags;

  ci_assert(trs);
  ci_assert_equal(trs->ref[OO_THR_REF_BASE], 0);
  ci_assert_equal(trs->ref[OO_THR_REF_FILE], 0);
  ci_assert_equal(trs->ref[OO_THR_REF_APP], 0);

  OO_DEBUG_TCPH(ci_log("%s: [%u] ref "OO_THR_REF_FMT,
                       __FUNCTION__, trs->id, OO_THR_REF_ARG(trs->ref)));

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  if( !ci_dllink_is_free(&trs->all_stacks_link) ) {
    ci_dllist_remove(&trs->all_stacks_link);
    ci_dllink_mark_free(&trs->all_stacks_link);
  }
  else
    trs = 0;
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  if( trs ) {
#if CI_CFG_UL_INTERRUPT_HELPER
    ci_assert(current_is_proper_ul_context());
#else
    if( ! current_is_proper_ul_context() )
      tcp_helper_dtor_schedule(trs);
    else
#endif
      tcp_helper_dtor(trs);
  }
  OO_DEBUG_TCPH(ci_log("%s: finished", __FUNCTION__));
}


static void
tcp_helper_close_cleanup_ep(tcp_helper_resource_t* trs,
                            tcp_helper_endpoint_t* ep)
{
    tcp_helper_endpoint_clear_aflags(ep, OO_THR_EP_AFLAG_PEER_CLOSED);
    if( ep->alien_ref != NULL ) {
      fput(ep->alien_ref->_filp);
      ep->alien_ref = NULL;
    }
}

#if ! CI_CFG_UL_INTERRUPT_HELPER
/*! Close sockets.  Called with netif lock held.  Kernel netif lock may or
 * may not be held.
 */
static void
tcp_helper_close_pending_endpoints(tcp_helper_resource_t* trs)
{
  ci_irqlock_state_t lock_flags;
  tcp_helper_endpoint_t* ep;
  ci_sllink* link;

  OO_DEBUG_TCPH(ci_log("%s: [%d]", __FUNCTION__, trs->id));

  ci_assert(ci_netif_is_locked(&trs->netif));
  ci_assert(! in_atomic());
  ci_assert( ~trs->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT );

  /* Ensure we're up-to-date so we get an ordered response to all packets.
  ** (eg. ANVL tcp_core 9.18).  Do it once here rather than per-socket.
  ** Also ensure all local packets are delivered before endpoint release.
  */
  ci_netif_poll(&trs->netif);

  while( ci_sllist_not_empty(&trs->ep_tobe_closed) ) {
    ci_irqlock_lock(&trs->lock, &lock_flags);

    /* DEBUG build: we are protected by netif lock, so the ep_tobe_closed
     * list can't be empty.
     * NDEBUG build: we are not protected by kernel netif lock, so
     * we should re-check that ep_tobe_closed is non-empty for security
     * reasons. */
    ci_assert( ci_sllist_not_empty(&trs->ep_tobe_closed) );
    if( ci_sllist_is_empty(&trs->ep_tobe_closed) ) {
      ci_irqlock_unlock(&trs->lock, &lock_flags);
      ci_log("%s: [%d] ERROR: stack lock corrupted", __func__, trs->id);
      break;
    }
    link = ci_sllist_pop(&trs->ep_tobe_closed);
    ci_irqlock_unlock(&trs->lock, &lock_flags);

    ep = CI_CONTAINER(tcp_helper_endpoint_t, tobe_closed , link);
    OO_DEBUG_TCPH(ci_log("%s: [%u:%d] closing",
                         __FUNCTION__, trs->id, OO_SP_FMT(ep->id)));
    tcp_helper_close_cleanup_ep(trs, ep);
    citp_waitable_all_fds_gone(&trs->netif, ep->id);
  }
}
#else

int oo_wakeup_waiters(ci_private_t* priv, void* arg)
{
  struct oo_wakeup_eps* op = arg;
  tcp_helper_resource_t* thr = priv->thr;
  oo_sp ep_id[16];
  oo_sp __user * user_ptr = CI_USER_PTR_GET(op->eps);
  int n, i;

  if( thr == NULL )
    return -EINVAL;

  while( op->eps_num > 0 ) {
    n = CI_MIN(op->eps_num, (ci_uint32)(sizeof(ep_id) / sizeof(ep_id[0])));
    if( copy_from_user(ep_id, user_ptr, n * sizeof(ep_id[0])) )
      return -EFAULT;
    user_ptr += n;
    op->eps_num -= n;

    for( i = 0; i < n; i++ ) {
      tcp_helper_endpoint_t* ep;
      ep = ci_netif_get_valid_ep(&thr->netif, ep_id[i]);
      tcp_helper_endpoint_wakeup(thr, ep);
    }
  }

  return 0;
}
#endif /* CI_CFG_UL_INTERRUPT_HELPER */


#if ! CI_CFG_UL_INTERRUPT_HELPER
static void
efab_tcp_helper_rm_reset_untrusted(tcp_helper_resource_t* trs)
{
  /* Called when closing a stack and the lock is wedged.  Assume that
   * shared state is borked.
   */
  ci_netif *netif = &trs->netif;
  int i;

  for( i = 0; i < netif->ep_tbl_n; ++i ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, i);

    if( (wo->waitable.state & CI_TCP_STATE_TCP_CONN) &&
        wo->waitable.state != CI_TCP_TIME_WAIT ) {
      ci_tcp_reset_untrusted(netif, &wo->tcp);
    }
#if CI_CFG_TCP_SHARED_LOCAL_PORTS
    else if( wo->waitable.state == CI_TCP_STATE_ACTIVE_WILD ) {
      /* In the case of normal endpoints they are associated with a file
       * descriptor, so even with a wedged netif they will have come through
       * efab_tcp_helper_close_endpoint() resulting in the os socket being
       * dropped.  Active wilds aren't associated with an fd so we drop the
       * os socket explicitly here.
       */
      efab_tcp_helper_drop_os_socket(trs, netif->ep_tbl[i]);
    }
#endif
  }
}

static void
efab_tcp_helper_rm_schedule_free(tcp_helper_resource_t* trs)
{
  OO_DEBUG_TCPH(ci_log("%s [%u]: defer", __FUNCTION__, trs->id));
  queue_work(CI_GLOBAL_WORKQUEUE, &trs->work_item_dtor);
}
#endif /* CI_CFG_UL_INTERRUPT_HELPER */

/*--------------------------------------------------------------------
 *!
 * Called when reference count on a TCP helper resource reaches zero
 * AND we have the kernel netif lock. At this point we are safe to
 * correct any coruption of the netif lock. We either then
 * continue destroying the TCP helper resource OR we leave it around
 * so that it exists for connections that need to close gracefully
 * post application exit
 *
 * \param trs               TCP helper resource
 * \param safe_destroy_now  is it OK to destroy the resource now or
 *                          do we need to schedule for later
 *
 *--------------------------------------------------------------------*/


#if CI_CFG_NIC_RESET_SUPPORT
static void
efab_tcp_helper_flush_reset_wq(tcp_helper_resource_t* trs)
{
  /* There may be both work running and work pending.  We can wake up the
   * work currently blocked on the lock, but we don't want a queued
   * work item to block subsequently so set a flag.
   */
  ci_atomic32_or(&trs->trs_aflags, OO_THR_AFLAG_DONT_BLOCK_SHARED);
  wake_up_interruptible(&trs->netif.eplock_helper.wq);
  flush_workqueue(trs->reset_wq);
  ci_atomic32_and(&trs->trs_aflags, ~OO_THR_AFLAG_DONT_BLOCK_SHARED);
}

void tcp_helper_flush_resets(ci_netif* ni)
{
  tcp_helper_resource_t* thr = CI_CONTAINER(tcp_helper_resource_t, netif, ni);
  efab_tcp_helper_flush_reset_wq(thr);
}
#endif


static void
efab_tcp_helper_rm_free_locked(tcp_helper_resource_t* trs)
{
  ci_netif* netif;
#if ! CI_CFG_UL_INTERRUPT_HELPER
  ci_uint32 n_orphaned = 0;
#endif

  ci_assert(NULL != trs);
#if ! CI_CFG_UL_INTERRUPT_HELPER
  ci_assert(trs->trusted_lock == (OO_TRUSTED_LOCK_LOCKED |
                                  OO_TRUSTED_LOCK_AWAITING_FREE));
#endif

  netif = &trs->netif;
#if ! CI_CFG_UL_INTERRUPT_HELPER
  ci_assert(!in_atomic());
  /* Make sure all postponed actions are done and endpoints freed */
  flush_workqueue(trs->wq);
#endif


  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* At this point we need to determine the state of the shared lock.  There
   * is still potentially reset work running, which also uses the lock.
   *
   * The following are the possible cases:
   *
   * 1. Wedged with reset work pending
   * 2. Wedged without reset work pending
   * 3. Not wedged with reset work ongoing
   * 4. Not wedged with no reset work
   *
   * We must ensure that the reset work is not running before we continue.
   * That means that we need to hold the lock.  We get to this state in the
   * same way in cases 1, 2 and 3, by dinging the lock waitqueue then waiting
   * for the reset-wq to flush.
   *
   * In case 1 the ding wakes the reset work, which simply returns, leaving
   * the lock locked.
   *
   * In case 2 there's no work pending, so the lock is still locked.
   *
   * In case 3 the ding doesn't achieve anything because there are no waiters,
   * but the reset work carries on and releases the lock on completion.
   *
   * In case 4 we can aquire the lock.
   *
   * This allows us to distinguish all cases, and so appropriately set the
   * CI_NETIF_FLAG_WEDGED flag to handle the rest of the cleanup appropriately.
   */
  if( ! ci_netif_trylock(&trs->netif) ) {
    /* Cases 1, 2 and 3 */
    efab_tcp_helper_flush_reset_wq(trs);

    /* There's a potential race here.  We're still on the all stacks list
     * at this point so additional reset work could potentially be queued
     * and take the lock between the flush and this trylock.  This leads us
     * to think that the stack is wedged, and perform an ungraceful
     * stack release, but we shouldn't encounter more serious consequences.
     * As we deem the stack wedged we won't be touching the shared state,
     * and we'll wait for the work to complete as we flush the workqueue
     * again on tcp_helper_stop.
     */
    if( !ci_netif_trylock(&trs->netif) ) {
      /* Cases 1 and 2 */
      OO_DEBUG_ERR(ci_log("Stack [%d] released with lock stuck (0x%llx)",
                   trs->id,
                   (unsigned long long)trs->netif.state->lock.lock));
      netif->flags |= CI_NETIF_FLAG_WEDGED;
    }
  }
  /* else case 4 */

  /* Validate shared netif state before we continue
   *  \TODO: for now just clear in_poll flag
   */
  netif->state->in_poll = 0;

  /* If netif is wedged then for now instead of getting netif in
   * a valid state we instead try never to touch it again.  For most of our
   * resources this is fine, they'll just be released gracelessly.  In the
   * case of socket caching we potentially have fds which won't be.  However,
   * socket caching doesn't play nicely with stack sharing, so it's likely
   * that if this stack is going away it means the process has died and so
   * the fds will be released.
   */
#if CI_CFG_DESTROY_WEDGED
  if( ! (netif->flags & CI_NETIF_FLAG_WEDGED) )
#endif
  {

#if CI_CFG_FD_CACHING
    ci_tcp_active_cache_drop_cache(netif);
    ci_tcp_passive_scalable_cache_drop_cache(netif);
#endif

    /* purge list of connections waiting to be closed
     *   - ones where we couldn't continue in fop_close because
     *     we didn't have the netif lock
     */
    tcp_helper_close_pending_endpoints(trs);

    /* Do we have any endpoints which can't be dropped yet? */
    n_orphaned = oo_netif_apps_gone(netif);
  }

  /* Who sets n_ep_orphaned to zero, the same code should drop the
   * associated BASE refcount. */
  if( ci_cas32u_succeed(&netif->n_ep_orphaned, OO_N_EP_ORPHANED_INIT,
                        n_orphaned) && n_orphaned == 0 )
    oo_thr_ref_drop(trs->ref, OO_THR_REF_BASE);

  /* Drop lock so that sockets can proceed towards close. */
#if CI_CFG_DESTROY_WEDGED
  if( ! (netif->flags & CI_NETIF_FLAG_WEDGED) )
#endif
    efab_eplock_unlock_and_wake(netif, 0 /* in_dl_context */);


  /* Don't need atomics here, because only we are permitted to touch
   * [trusted_lock] when AWAITING_FREE is set.
   */
  ci_assert(trs->trusted_lock == (OO_TRUSTED_LOCK_LOCKED |
                                  OO_TRUSTED_LOCK_AWAITING_FREE));
  trs->trusted_lock = OO_TRUSTED_LOCK_UNLOCKED;
#endif /* CI_CFG_UL_INTERRUPT_HELPER*/
  oo_thr_ref_drop(trs->ref, OO_THR_REF_BASE);
  OO_DEBUG_TCPH(ci_log("%s: finished", __FUNCTION__));
}


/*--------------------------------------------------------------------
 *!
 * This function stops any async callbacks into the TCP helper resource
 * (waiting for any running callbacks to complete)
 *
 * Split into a separate function from tcp_helper_dtor only to make the
 * protection against potentail race conditions clearer
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

ci_inline void
tcp_helper_stop(tcp_helper_resource_t* trs)
{
  int intf_i;

  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* stop the periodic timer callbacks and TXQ-purges. */
  tcp_helper_stop_periodic_work(trs);
#endif

  /* stop callbacks from the event queue
        - wait for any running callback to complete */
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    ef_eventq_timer_clear(ci_netif_vi(&trs->netif, intf_i));
    efrm_eventq_kill_callback(tcp_helper_vi(trs, intf_i));
  }

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* stop postponed packet allocations: we are the only thread using this
   * thr, so nobody can scedule anything new */
  flush_workqueue(trs->wq);
#endif
#if CI_CFG_NIC_RESET_SUPPORT
  efab_tcp_helper_flush_reset_wq(trs);
#endif

  OO_DEBUG_TCPH(ci_log("%s [%d]: finished --- all async processes finished",
                       __FUNCTION__, trs->id));
}


/*--------------------------------------------------------------------
 *!
 * This is the code that was previously called directly when the TCP
 * helper resource ref count reaches zero to destruct the resource.
 * The call is now delayed until all endpoints have closed, or
 * forced when the TCP helper resource manager destructs.
 *
 * By the time we get here all attempts at graceful shutdown of sockets are
 * over.  This function is about releasing resources, and nothing else.  Do
 * not put any code that depends on the shared state in here!
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

void tcp_helper_dtor(tcp_helper_resource_t* trs)
{
  int rc;
  ci_irqlock_state_t lock_flags;

  ci_assert(NULL != trs);

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 1);

  OO_DEBUG_TCPH(ci_log("%s [%u]: starting %s", __FUNCTION__, trs->id,
                       trs->netif.flags & CI_NETIF_FLAG_WEDGED ?
                       "wedged" : "gracious"));

#if ! CI_CFG_UL_INTERRUPT_HELPER
  if( trs->netif.flags & CI_NETIF_FLAG_WEDGED ) {
    /* We're doing this here because we need to be in a context that allows
     * us to block.
     */
    efab_tcp_helper_rm_reset_untrusted(trs);
  }
#endif

  /* stop any async callbacks from kernel mode (waiting if necessary)
   *  - as these callbacks are the only events that can take the kernel
   *    netif lock, we know that once these callbacks are stopped the kernel
   *    lock will have been dropped
   *      => tcp_helper_rm_free_locked must have run to completion
   */
  tcp_helper_stop(trs);

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* oo_netif_dtor_pkts() is going to wait until there's nothing more coming,
   * but that might never happen on X3 rxqs, so detech from them now */
  detach_efct_rxqs(trs);

  /* Get the stack lock; it is needed for filter removal and leak check. */
  if( ~trs->netif.flags & CI_NETIF_FLAG_WEDGED ) {
    if( efab_tcp_helper_netif_try_lock(trs, 0) ) {
      oo_netif_dtor_pkts(&trs->netif);
    }
    else {
      /* Pretend to be wedged and do not check for leaks */
      trs->netif.flags |= CI_NETIF_FLAG_WEDGED;
      OO_DEBUG_ERR(ci_log("Stack [%d] destroyed with lock stuck (0x%llx)",
                   trs->id,
                   (unsigned long long)trs->netif.state->lock.lock));
      /* I believe that after tcp_helper_stop() there are no legitimate
       * lock holders, so assert() in debug build.  See bug 67856 comment 2
       * for details why it was not so in the past. */
      ci_assert(0);
    }
  }
#elif ! defined(NDEBUG)
  /* Appease dtor code, pretend to be locked */
  trs->netif.state->lock.lock = CI_EPLOCK_LOCKED;
#endif

  /* Remove all filters - and make sure we do not send anything, while
   * closing socket or as a reply to a network packet. */
  release_ep_tbl(trs);

#if CI_CFG_HANDLE_ICMP
  /* dlfilters have been removed.  Let's process (and free) all icmp
   * messages */
  oo_icmp_handle(trs);
#endif

#if ! CI_CFG_UL_INTERRUPT_HELPER
  if( ~trs->netif.flags & CI_NETIF_FLAG_WEDGED )
    tcp_helper_leak_check(trs);
#endif

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  /* Free the table of ephemeral ports unless we share it with the cluster. */
  if(
#if CI_CFG_ENDPOINT_MOVE
      trs->thc == NULL &&
#endif
      trs->trs_ephem_table != NULL )
    tcp_helper_free_ephemeral_ports(trs->trs_ephem_table,
                                    trs->trs_ephem_table_entries);

  /* We just vfree() the consumed table, as the pointers that it contains point
   * straight into the the table of ephemeral ports itself. */
  vfree(trs->trs_ephem_table_consumed);
#endif

  thr_uninstall_tproxy(trs);

  oo_filter_ns_put(&efab_tcp_driver, trs->filter_ns);

  release_netif_hw_resources(trs);
  release_netif_resources(trs);
  if( trs->thc_efct_memfd )
    fput(trs->thc_efct_memfd);

#if ! CI_CFG_UL_INTERRUPT_HELPER
  destroy_workqueue(trs->wq);
#endif
#if CI_CFG_NIC_RESET_SUPPORT
  destroy_workqueue(trs->reset_wq);
#endif

  while( trs->usermem ) {
    struct tcp_helper_usermem* next = trs->usermem->next;
    efab_tcp_helper_unmap_usermem(trs, &trs->usermem->um);
    kfree(trs->usermem);
    trs->usermem = next;
  }

  if( trs->netif.cplane_init_net != NULL )
    cp_release(trs->netif.cplane_init_net);
  cp_release(trs->netif.cplane);
  put_namespaces(trs);

  rc = ci_id_pool_free(&THR_TABLE.instances, trs->id, &THR_TABLE.lock);
  OO_DEBUG_ERR(if (rc)
        ci_log("%s [%u]: failed to free instance number",
               __FUNCTION__, trs->id));

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_assert(THR_TABLE.stack_count > 0);
  --THR_TABLE.stack_count;
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  OO_DEBUG_TCPH(ci_log("%s [%u]: finished", __FUNCTION__, trs->id));  
  CI_FREE_OBJ(trs);
}



/*--------------------------------------------------------------------
 *!
 * TCP driver management -- here for now while it needs a NIC to be around
 *
 * TODO: move somewhere more appropriate
 *
 *--------------------------------------------------------------------*/

#if CI_CFG_HANDLE_ICMP
static int efab_is_onloaded(void* ctx, struct net* netns, ci_ifid_t ifindex)
{
  struct oo_filter_ns* ns;
  int v;

  ci_assert_equal(ctx, &efab_tcp_driver);
  ns = oo_filter_ns_lookup(&efab_tcp_driver, netns);
  if( ns == NULL )
    return 0;

  v = oof_is_onloaded(oo_filter_ns_to_manager(ns), ifindex);

  oo_filter_ns_put_atomic(&efab_tcp_driver, ns);
  return v;
}
#endif


int
efab_tcp_driver_ctor()
{
  int rc = 0;

#if defined(EFRM_DO_NAMESPACES) && defined(OO_HAS_IPC_NS)
  my_put_ipc_ns = efrm_find_ksym("put_ipc_ns");
  if( my_put_ipc_ns == NULL )
    ci_log("Failed to find put_ipc_ns(), proceeding without.");
#endif

  CI_ZERO(&efab_tcp_driver);


  /* Create work queue */
  /* This work queue is used for deferred stack destruction (and it is
   * natural to run such a work item on the same cpu it was queued),
   * for oof and cplane delayed destructors (to escape from atomic
   * context).
   * So, we use bound work queue without any additional flags.
   */
  CI_GLOBAL_WORKQUEUE = alloc_workqueue("onload-wqueue", WQ_SYSFS, 0);
  if (CI_GLOBAL_WORKQUEUE == NULL) {
    rc = -ENOMEM;
    goto fail_wq;
  }
  
  /* Create TCP helpers table */
  if ((rc = thr_table_ctor(&efab_tcp_driver.thr_table)) < 0)
    goto fail_thr_table;

  if( (rc = oo_filter_ns_manager_ctor(&efab_tcp_driver)) < 0 )
    goto fail_filter_ns_manager;

#if CI_CFG_HANDLE_ICMP
  /* Create driverlink filter. */
  efab_tcp_driver.dlfilter =
      efx_dlfilter_ctor(&efab_tcp_driver, efab_is_onloaded);
  if( efab_tcp_driver.dlfilter == NULL ) {
    rc = -ENOMEM;
    goto fail_dlf;
  }
#endif

  efab_tcp_driver.timesync_page = alloc_page(GFP_KERNEL);
  if( efab_tcp_driver.timesync_page == NULL )
    goto fail_timesync_alloc;

  efab_tcp_driver.timesync = vmap(&efab_tcp_driver.timesync_page, 1,
                                  VM_USERMAP, PAGE_KERNEL);

  if( (rc = oo_timesync_ctor(efab_tcp_driver.timesync)) < 0 )
    goto fail_timesync;

  /* Construct the IP ID allocator */
  efab_ipid_ctor(&efab_tcp_driver.ipid);

  ci_atomic_set(&efab_tcp_driver.sendpage_pinpages_n, 0);
  /* This is was (EFHW_BUFFER_TBL_NUM >> 1), but the size is no longer
  ** known at compile time.  But the pinned-page stuff is on its way out,
  ** so no need to fix properly. */
  efab_tcp_driver.sendpage_pinpages_max = 4096;

  efab_tcp_driver.stack_list_seq = 0;
  ci_waitq_ctor(&efab_tcp_driver.stack_list_wq);

  oo_dshm_init();

  efab_tcp_driver.load_numa_node = numa_node_id();

  return 0;

fail_timesync:
  __free_page(efab_tcp_driver.timesync_page);
fail_timesync_alloc:
#if CI_CFG_HANDLE_ICMP
  efx_dlfilter_dtor(efab_tcp_driver.dlfilter);
fail_dlf:
#endif
  oo_filter_ns_manager_dtor(&efab_tcp_driver);
fail_filter_ns_manager:
  thr_table_dtor(&efab_tcp_driver.thr_table);
fail_thr_table:
  destroy_workqueue(CI_GLOBAL_WORKQUEUE);
fail_wq:
  OO_DEBUG_ERR(ci_log("%s: failed rc=%d", __FUNCTION__, rc));
  return rc;
}

/* Destroy all existing stacks. */
void
efab_tcp_driver_stop(void)
{
  OO_DEBUG_TCPH(ci_log("%s: kill stacks", __FUNCTION__));

  thr_table_dtor(&efab_tcp_driver.thr_table);

  flush_workqueue(CI_GLOBAL_WORKQUEUE);
}

void
efab_tcp_driver_dtor(void)
{
  OO_DEBUG_TCPH(ci_log("%s: free resources", __FUNCTION__));

  oo_dshm_fini();

  ci_id_pool_dtor(&efab_tcp_driver.thr_table.instances);

#ifndef NDEBUG
  if (ci_atomic_read(&efab_tcp_driver.sendpage_pinpages_n) != 0) {
    ci_log("%s: ERROR: sendpage_pinpages_n is %d at destruction",
           __FUNCTION__, ci_atomic_read(&efab_tcp_driver.sendpage_pinpages_n));
  }
#endif

  efab_ipid_dtor(&efab_tcp_driver.ipid);

  oo_timesync_dtor(efab_tcp_driver.timesync);
  efab_tcp_driver.timesync = NULL;
  __free_page(efab_tcp_driver.timesync_page);

  destroy_workqueue(CI_GLOBAL_WORKQUEUE);
#if CI_CFG_HANDLE_ICMP
  efx_dlfilter_dtor(efab_tcp_driver.dlfilter);
#endif
  oo_filter_ns_manager_dtor(&efab_tcp_driver);

  ci_waitq_dtor(&efab_tcp_driver.stack_list_wq);
}


static int
add_ep(tcp_helper_resource_t* trs, unsigned id, tcp_helper_endpoint_t* ep)
{
  ci_netif* ni = &trs->netif;
  citp_waitable_obj* wo;

  if( id < ni->ep_tbl_n )  return -1;
  ci_assert_equal(id, ni->ep_tbl_n);

  tcp_helper_endpoint_ctor(ep, trs, id);
  ni->ep_tbl[id] = ep;

  /* Only update [ep_tbl_n] once ep is installed. */
  ci_wmb();
  ni->state->n_ep_bufs = ++ni->ep_tbl_n;

  wo = SP_TO_WAITABLE_OBJ(ni, ep->id);
  CI_ZERO(wo);  /* ??fixme */
  citp_waitable_init(ni, &wo->waitable, id);
  wo->waitable.state = CI_TCP_STATE_FREE;
  citp_waitable_add_free_list(ni, &wo->waitable);
  return 0;
}

static int
install_socks(tcp_helper_resource_t* trs, unsigned id, int num)
{
  tcp_helper_endpoint_t** eps;
  ci_irqlock_state_t lock_flags;
  int i;

  eps = vmalloc(sizeof(void*) * num);
  if( eps == NULL )
    return -ENOMEM;

  /* Allocate the kernel state for each socket. */
  for( i = 0; i < num; ++i ) {
    eps[i] = CI_ALLOC_OBJ(tcp_helper_endpoint_t);
    if( ! eps[i] ) {
      OO_DEBUG_ERR(ci_log("%s: allocation failed", __FUNCTION__));
      while( i-- )  ci_free(eps[i]);
      vfree(eps);
      return -ENOMEM;
    }
  }

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  for( i = 0; i < num; ++i, ++id ){
    OO_DEBUG_SHM(ci_log("%s: add ep %d", __FUNCTION__, id));
    if( add_ep(trs, id, eps[i]) == 0 )
      eps[i] = NULL;
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  /* Prevents leaks! */
  for( i = 0; i < num; ++i )
    if( eps[i] )
      ci_free(eps[i]);
  vfree(eps);

  trs->netif.state->sock_alloc_numa_nodes |= 1 << numa_node_id();
  return 0;
}


int efab_tcp_helper_more_socks(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  int rc;

  if( ni->ep_tbl_n >= ni->ep_tbl_max )  return -ENOSPC;

  if( ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT ) {
    ef_eplock_holder_set_flag(&ni->state->lock,
                              CI_EPLOCK_NETIF_NEED_SOCK_BUFS);
    return -EBUSY;
  }

  rc = oo_shmbuf_add(&ni->shmbuf);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("%s: demand failed (%d)", __FUNCTION__, rc));
    return rc;
  }

  return install_socks(trs, ni->ep_tbl_n,
                       EP_BUF_PER_PAGE << OO_SHARED_BUFFER_CHUNK_ORDER);
}


#if CI_CFG_FD_CACHING
int efab_tcp_helper_clear_epcache(tcp_helper_resource_t* trs)
{
  ci_tcp_epcache_drop_cache(&trs->netif);
  return 0;
}
#endif


static void
efab_tcp_helper_no_more_bufs(tcp_helper_resource_t* trs)
{
  /* We've failed to allocate more packet buffers -- we're out of resources
   * (probably buffer table).  We don't want to keep trying to allocate and
   * failing -- that just makes performance yet worse.  So reset the
   * various packet limits, preserving relative sizes.
   */
  ci_netif* ni = &trs->netif;
  int new_max_packets = ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S;
  ni->pkt_sets_max = ni->pkt_sets_n;
  ni->packets->sets_max = ni->pkt_sets_max;
  tcp_helper_reduce_max_packets(&trs->netif, new_max_packets);
  ci_netif_set_rxq_limit(ni);

  if( ++ni->state->stats.bufset_alloc_nospace == 1 )
    OO_DEBUG_ERR(ci_log(FN_FMT "Failed to allocate packet buffers: "
                        "no more buffer table entries. ",
                        FN_PRI_ARGS(&trs->netif));
                 ci_log(FN_FMT "New limits: max_packets=%d rx=%d tx=%d "
                        "rxq_limit=%d", FN_PRI_ARGS(ni),
                        NI_OPTS(ni).max_packets, NI_OPTS(ni).max_rx_packets,
                        NI_OPTS(ni).max_tx_packets, NI_OPTS(ni).rxq_limit));
}


/* hw_addrs below is structured as following:
 *      hw_addrs[n_page + intf_i * n_hw_pages]
 */
static int
efab_tcp_helper_iobufset_map(tcp_helper_resource_t* trs,
                             struct oo_buffer_pages* pages,
                             int n_hw_pages,
                             struct oo_iobufset** all_out,
                             uint64_t* hw_addrs, int* page_order)
{
  ci_netif* ni = &trs->netif;
  int rc, intf_i;
  int map_order = INT_MAX;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct efrm_pd *pd = efrm_vi_get_pd(tcp_helper_vi(trs, intf_i));
    struct oo_iobufset *iobuf;
    int cur_map_order;

    rc = oo_iobufset_resource_alloc(pages, pd, &iobuf,
                                    &hw_addrs[intf_i * n_hw_pages],
                                    intfs_suspended(trs) & (1 << intf_i),
                                    &cur_map_order);
    if( rc < 0 ) {
      while( --intf_i >= 0 )
        oo_iobufset_resource_release(all_out[intf_i], 0);
      return rc;
    }
    map_order = CI_MIN(map_order, cur_map_order);
    all_out[intf_i] = iobuf;
  }
  if( page_order )
    *page_order = map_order;
  return 0;
}


static int
efab_tcp_helper_min_nics_order(tcp_helper_resource_t* trs)
{
  int i, intf_i;
  int min_nic_order;
  int min_nics_order = 0;

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    struct efhw_nic *nic =
      efrm_client_get_nic(trs->nic[intf_i].thn_oo_nic->efrm_client);
    /* If we allocate pages in buffer mode with order less than minimum NIC
     * page order then we cannot find acceptable NIC buffer table.
     * Minimum NIC page order in EF10 and production Riverhead is 0. */
    min_nic_order = HW_PAGES_PER_SET_S;
    if( NI_OPTS(&trs->netif).packet_buffer_mode == 0 ) {
      for (i = 0; i < efhw_nic_buffer_table_orders_num(nic); i++)
        min_nic_order = min(min_nic_order, efhw_nic_buffer_table_orders(nic)[i]);
    }
    else {
      min_nic_order = 0;
    }

    /* The minimum supported page size order of all NICs is maximum among all
     * NICs values. */
    min_nics_order = max(min_nics_order, min_nic_order);
  }
  return min_nics_order;
}


static int
efab_tcp_helper_iobufset_alloc(tcp_helper_resource_t* trs,
                               struct oo_iobufset** all_out,
                               struct oo_buffer_pages** pages_out,
                               uint64_t* hw_addrs,
                               int* page_order)
{
  ci_netif* ni = &trs->netif;
  int rc, intf_i;
  struct oo_buffer_pages *pages;
  int flags;
  int min_nics_order = efab_tcp_helper_min_nics_order(trs);

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    all_out[intf_i] = NULL;
  *pages_out = NULL;

#ifdef OO_DO_HUGE_PAGES
  BUILD_BUG_ON(HW_PAGES_PER_SET_S != HPAGE_SHIFT - PAGE_SHIFT);
#endif

  flags = NI_OPTS(ni).compound_pages << OO_IOBUFSET_FLAG_COMPOUND_SHIFT;
#if CI_CFG_PKTS_AS_HUGE_PAGES
  /* If there is a possibility to get huge pages, copy the flags.
   * Otherwise, we'll avoid them. */
  if( ni->flags & CI_NETIF_FLAG_HUGE_PAGES_FAILED )
    flags |= OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED;
  if( !in_atomic() && current->mm != NULL ) {
#ifdef EFRM_DO_NAMESPACES
    struct nsproxy *ns;
    ns = task_nsproxy_start(current);
    /* Use huge pages if we are in the same namespace only.
     * ipc_ns has a pointer to user_ns, so we may compare uids
     * if ipc namespaces match. */
    if( ns != NULL
#ifdef OO_HAS_IPC_NS
        && (ns->ipc_ns == trs->ipc_ns || my_put_ipc_ns == NULL)
#elif defined(EFRM_DO_USER_NS)
        && current_user_ns() == trs->user_ns
#endif
        && ci_geteuid() == ni->keuid ) {
      flags |= NI_OPTS(ni).huge_pages;
    }
    task_nsproxy_done(current);
#else
    if( ci_geteuid() == ni->keuid )
      flags |= NI_OPTS(ni).huge_pages;
#endif
  }
#endif
  rc = oo_iobufset_pages_alloc(HW_PAGES_PER_SET_S, min_nics_order, &flags,
                               &pages);
  if( rc != 0 )
    return rc;
#if CI_CFG_PKTS_AS_HUGE_PAGES
    if( (flags & OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED) &&
        !(ni->flags & CI_NETIF_FLAG_HUGE_PAGES_FAILED) ) {
      NI_LOG(ni, RESOURCE_WARNINGS,
             "[%s]: unable to allocate huge page, using standard pages instead",
             ni->state->pretty_name);
      ni->flags |= CI_NETIF_FLAG_HUGE_PAGES_FAILED;
    }
#endif

  rc = efab_tcp_helper_iobufset_map(trs, pages, 1 << HW_PAGES_PER_SET_S,
                                    all_out, hw_addrs, page_order);
  if( rc < 0 ) {
    oo_iobufset_pages_release(pages);
    return rc;
  }

  *pages_out = pages;
  return 0;
}


static void efab_put_pages(struct page** pages, size_t n)
{
  size_t i;
  for( i = 0; i < n; ++i )
    unpin_user_page(pages[i]);
}


static long efab_get_all_user_pages(unsigned long base, long max_pages,
                                    struct page** pages, unsigned gup_flags)
{
  long n;
  long rc;

  mmap_read_lock(current->mm);
  for( n = 0; n < max_pages; n += rc ) {
    rc = pin_user_pages(base + n * PAGE_SIZE, max_pages - n, gup_flags,
                        pages + n, NULL);
    if (rc <= 0) {
      efab_put_pages(pages, n);
      mmap_read_unlock(current->mm);
      return rc ? rc : -EFAULT;
    }
  }
  mmap_read_unlock(current->mm);
  return n;
}


/* Same as efab_get_all_user_pages(), but guarantees that the returned page
 * range neither starts nor ends with a partial-hugepage. map_usermem has
 * three options for what to do in that circumstance:
 *  1) Fail the registration. This was tried and got tricky because of
 *     transparent hugepages making it difficult for the user to be sure that
 *     they'd done an allocation which is going to work.
 *  2) Extend the registered area to encompass the full size of the huge pages
 *     at the beginning and end. This seems like a bad idea for the same
 *     hugepage reason: the user could be unaware that they've got straddling
 *     and be surprised at the implicit extension.
 *  3) (This implementation) Split the hugepages down to normal pages to make
 *     the registration unstraddled. This causes least functional surprise to
 *     users, and if (as they normally would) users pass in correctly mmapped
 *     and aligned hugepages then no splitting happens and they never notice
 *     this fixup code. */
static long efab_get_unstraddled_user_pages(unsigned long base, long max_pages,
                                            struct page** pages)
{
  long rc;
#ifdef FOLL_SPLIT
  long count;
#endif
  ci_assert_gt(max_pages, 0);

  rc = efab_get_all_user_pages(base, max_pages, pages, FOLL_WRITE);
  if( rc < 0 )
    return rc;

#ifdef FOLL_SPLIT
  /*
   * From experiments:
   * It is not needed for linux<=4.9, and it is not needed for linux>=5.4.
   * It is definitely needed for linux-4.18 (RHEL 8) and linux-4.19 (Debain 10).
   *
   * However let's be on the safe side: FOLL_SPLIT is defined for
   * 2.6.38 <= linux <= 5.12.
   */
  if( PageTail(pages[0]) ) {
    /* Beginning of the region straddles a hugepage. Put those pages and
     * re-get them with FOLL_SPLIT */
    for( count = 1; count < max_pages; ++count)
      if( ! PageTail(pages[count]) )
        break;
    efab_put_pages(pages, count);
    rc = efab_get_all_user_pages(base, count, pages, FOLL_WRITE | FOLL_SPLIT);
    if( rc < 0 ) {
      efab_put_pages(pages + count, max_pages - count);
      return rc;
    }
    if( PageTail(pages[0]) ) {
      /* If we hit an already-mlocked page then it silently fails to split,
       * hence this extra check. */
      efab_put_pages(pages, max_pages);
      return -EBUSY;
    }
  }

  /* Check that the last chunk doesn't straddle a hugepage */
  count = max_pages;
  while( --count && PageTail(pages[count]) )
    ;
  ci_assert(!PageTail(pages[count]));
  if( count + (1L << compound_order(pages[count])) != max_pages ) {
    efab_put_pages(pages + count, max_pages - count);
    rc = efab_get_all_user_pages(base + count * PAGE_SIZE, max_pages - count,
                                 pages + count, FOLL_WRITE | FOLL_SPLIT);
    if( rc < 0 ) {
      efab_put_pages(pages, count);
      return rc;
    }
    if( PageCompound(pages[max_pages - 1]) ) {
      /* Already-mlocked, failed to split. */
      efab_put_pages(pages, max_pages);
      return -EBUSY;
    }
  }
#endif

  return 0;
}


int efab_tcp_helper_map_usermem(tcp_helper_resource_t* trs,
                                struct oo_iobufs_usermem* ioum,
                                unsigned long user_base, int n_pages,
                                uint64_t** hw_addrs_out)
{
#if PAGE_SIZE != EFHW_NIC_PAGE_SIZE
  /* Not implemented, solely for simplicity */
  return -EOPNOTSUPP;
#else
  ci_netif* ni = &trs->netif;
  long rc;
  uint64_t* hw_addrs = NULL;
  uint64_t* tmp_hw_addrs = NULL;
  struct page** pages;
  int last_order = -1;
  int i;
  int group_i;
  int min_nics_order = efab_tcp_helper_min_nics_order(trs);

  if( user_base & (PAGE_SIZE - 1) || n_pages == 0 )
    return -EINVAL;

  pages = kmalloc_array(n_pages, sizeof(*pages), GFP_KERNEL);
  if( ! pages )
    return -ENOMEM;

  mmap_read_lock(current->mm);
  rc = efab_get_unstraddled_user_pages(user_base, n_pages, pages);
  mmap_read_unlock(current->mm);
  if( rc < 0 ) {
    NI_LOG(ni, RESOURCE_WARNINGS, "[%s]: pin_user_pages(%d) returned %ld",
           __FUNCTION__, n_pages, rc);
    goto fail1;
  }

  /* The user's chunk of address space may cover all sorts of different
   * allocations, but our iobufset requires homogeneity. Split it all up in to
   * groups which have the same order */
  ioum->n_groups = 0;
  for( i = 0; i < n_pages; ) {
    int order = compound_order(pages[i]);
    ci_assert(!PageTail(pages[i]));
    if( order != last_order )
      ++ioum->n_groups;
    last_order = order;
    i += 1 << order;
  }
#ifdef FOLL_SPLIT
  ci_assert_equal(i, n_pages);
#else
  ci_assert_ge(i, n_pages);
#endif

  ioum->groups = kmalloc_array(ioum->n_groups, sizeof(*ioum->groups),
                               GFP_KERNEL);
  hw_addrs = kmalloc(sizeof(hw_addrs[0]) * n_pages * oo_stack_intf_max(ni),
                     GFP_KERNEL);
  if( ioum->n_groups > 1 )
    tmp_hw_addrs = kmalloc(sizeof(hw_addrs[0]) * n_pages *
                           oo_stack_intf_max(ni),
                           GFP_KERNEL);
  else
    tmp_hw_addrs = hw_addrs;
  if( ioum->groups == NULL || hw_addrs == NULL || tmp_hw_addrs == NULL ) {
    rc = -ENOMEM;
    goto fail3;
  }

  for( i = 0, group_i = 0; group_i < ioum->n_groups; ++group_i ) {
    struct oo_iobufs_usermem_group* g = &ioum->groups[group_i];
    int order = compound_order(pages[i]);
    int j;
    int group_pages = 1 << order;
    int intf_i;

    if( EFHW_GFP_ORDER_TO_NIC_ORDER(order) < min_nics_order ) {
      rc = -EMSGSIZE;   /* Same as oo_bufpage_alloc() */
      goto fail4;
    }

    while( i + group_pages < n_pages &&
           compound_order(pages[i + group_pages]) == order )
      group_pages += 1 << order;

    rc = oo_iobufset_init(&g->pages, group_pages >> order);
    if( rc < 0 )
      goto fail4;

    for( j = 0; j < group_pages >> order; ++j )
      g->pages->pages[j] = pages[i + (j << order)];

    rc = efab_tcp_helper_iobufset_map(trs, g->pages, group_pages,
                                      g->all, tmp_hw_addrs, NULL);
    if( rc < 0 ) {
      oo_iobufset_kfree(g->pages);
      goto fail4;
    }

    if( tmp_hw_addrs != hw_addrs ) {
      OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
        memcpy(hw_addrs + i + intf_i * n_pages,
               tmp_hw_addrs + intf_i * group_pages,
               sizeof(hw_addrs[0]) * CI_MIN(group_pages, n_pages - i));
      }
    }

    i += group_pages;
  }
#ifdef FOLL_SPLIT
  ci_assert_equal(i, n_pages);
#else
  ci_assert_ge(i, n_pages);
#endif

  /* For compound pages we only store the head page and we're about to lose
   * the struct page* for all the tail pages. Decref all those tail pages
   * here. The lock we keep on the head page is sufficient to keep the whole
   * compound page locked. We could have resurrected the struct page* pointers
   * from the head page later on, but that involves unnecessary poking at
   * Linux internals.
   * No jumping to the 'fail' labels allowed after this point. */
  for( i = 0, group_i = 0; group_i < ioum->n_groups; ++group_i ) {
    struct oo_iobufs_usermem_group* g = &ioum->groups[group_i];
    int order = compound_order(g->pages->pages[0]);
    int group_pages = g->pages->n_bufs << order;

    if (order) {
        /* The 2 CI_MIN()s below are needed for ! FOLL_SPLIT case only,
         * i.e. for linux >= 5.13. */
      int i_max = CI_MIN(n_pages, i + group_pages);
      while( i < i_max ) {
        efab_put_pages(pages + i + 1,
                       CI_MIN(1 << order, i_max - i) - 1);
        i += 1 << order;
      }
    }
    else {
      i += group_pages;
    }
  }
#ifdef FOLL_SPLIT
  ci_assert_equal(i, n_pages);
#else
  ci_assert_ge(i, n_pages);
#endif
  kfree(pages);
  if( tmp_hw_addrs != hw_addrs )
    kfree(tmp_hw_addrs);

  *hw_addrs_out = hw_addrs;
  return 0;

 fail4:
  while( --group_i >= 0 ) {
    struct oo_iobufs_usermem_group* g = &ioum->groups[group_i];
    OO_STACK_FOR_EACH_INTF_I(ni, i)
      if( g->all[i] )
        oo_iobufset_resource_release(g->all[i], 0);
    oo_iobufset_kfree(g->pages);
  }
 fail3:
  /* kfree() handles NULL, so we do not care to create fail2 */
  kfree(hw_addrs);
  if( tmp_hw_addrs != hw_addrs )
    kfree(tmp_hw_addrs);
  kfree(ioum->groups);
  efab_put_pages(pages, n_pages);
 fail1:
  kfree(pages);
  return rc;
#endif
}


void efab_tcp_helper_unmap_usermem(tcp_helper_resource_t* trs,
                                   struct oo_iobufs_usermem* ioum)
{
  ci_netif* ni = &trs->netif;
  int group_i;
  int intf_i;

  for( group_i = 0; group_i < ioum->n_groups; ++group_i ) {
    struct oo_iobufs_usermem_group* g = &ioum->groups[group_i];
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      if( g->all[intf_i] )
        oo_iobufset_resource_release(g->all[intf_i], 0);
    efab_put_pages(g->pages->pages, g->pages->n_bufs);
    oo_iobufset_kfree(g->pages);
  }
  kfree(ioum->groups);
}


int
efab_tcp_helper_more_bufs(tcp_helper_resource_t* trs)
{
  struct oo_iobufset* iobrs[CI_CFG_MAX_INTERFACES];
  struct oo_buffer_pages* pages;
  uint64_t *hw_addrs;
  ci_irqlock_state_t lock_flags;
  ci_netif* ni = &trs->netif;
  int i, rc, bufset_id, intf_i, page_order;

  ci_assert(ci_netif_is_locked(ni));

  /* efab_tcp_helper_iobufset_alloc() checks for pkt_sets_max, but we do
   * not want to go in efab_tcp_helper_no_more_bufs() in this case, so
   * let's exit early. */
  if( ni->pkt_sets_n == ni->pkt_sets_max )
    return -ENOSPC;

  if( ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT ) {
    ef_eplock_holder_set_flag(&ni->state->lock,
                              CI_EPLOCK_NETIF_NEED_PKT_SET);
    return -EBUSY;
  }

  hw_addrs = ci_vmalloc(sizeof(uint64_t) * (1 << HW_PAGES_PER_SET_S) *
                        CI_CFG_MAX_INTERFACES);
  if( hw_addrs == NULL ) {
    ci_log("%s: [%d] out of memory", __func__, trs->id);
    return -ENOMEM;
  }

  rc = efab_tcp_helper_iobufset_alloc(trs, iobrs, &pages, hw_addrs,
                                      &page_order);
  if(CI_UNLIKELY( rc < 0 )) {
    /* With highly fragmented memory, iobufset_alloc may fail in
     * atomic context but succeed later in non-atomic context.
     * We should somehow differentiate temporary failures (atomic
     * allocation failure) and permanent failure (out of buffer table
     * entries).
     */
    if( rc == -ENOSPC )
      efab_tcp_helper_no_more_bufs(trs);
    else {
      ++ni->state->stats.bufset_alloc_fails;
      NI_LOG(ni, RESOURCE_WARNINGS,
             FN_FMT "Failed to allocate packet buffers (%d)",
             FN_PRI_ARGS(&trs->netif), rc);
    }
    ci_vfree(hw_addrs);
    return rc;
  }
  /* check we get the size we are expecting */
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_assert(iobrs[intf_i] != NULL);
  ci_assert(pages != NULL);

  /* Install the new buffer allocation, protecting against multi-threads. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  ci_assert_le(ni->pkt_sets_n, ni->pkt_sets_max);
  ci_assert_ge(ni->pkt_sets_n, 0);
  if( ni->pkt_sets_n == ni->pkt_sets_max ) {
    ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      oo_iobufset_resource_release(iobrs[intf_i], 0);
    oo_iobufset_pages_release(pages);
    ci_vfree(hw_addrs);
    return -ENOSPC;
  }
  bufset_id = ni->pkt_sets_n;
  ci_assert_ge(bufset_id, 0);

  ++ni->pkt_sets_n;
  ni->pkt_bufs[bufset_id] = pages;
#ifdef OO_DO_HUGE_PAGES
  if( oo_iobufset_get_shmid(pages) >= 0 )
    CITP_STATS_NETIF_INC(ni, pkt_huge_pages);
#endif
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ni->nic_hw[intf_i].pkt_rs[bufset_id] = iobrs[intf_i];
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  OO_DEBUG_SHM({
    int i;
    ci_log("[%d] allocated new bufset id %d, current=%d n_freepkts=%d",
           NI_ID(ni), bufset_id, ni->packets->id,
           ni->packets->n_free);
    for( i = 0; i < bufset_id; i++ )
      ci_log("\tpkt_set[%i]: n_free=%d", i, ni->packets->set[i].n_free);
  });

  ni->packets->sets_n = ni->pkt_sets_n;
  ni->packets->n_pkts_allocated = ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S;

  ni->packets->set[bufset_id].free = OO_PP_NULL;
  ni->packets->set[bufset_id].n_free = PKTS_PER_SET;
#ifdef OO_DO_HUGE_PAGES
  ni->packets->set[bufset_id].shm_id = oo_iobufset_get_shmid(pages);
#else
  ni->packets->set[bufset_id].shm_id = -1;
#endif
  ni->packets->set[bufset_id].dma_addr_base = ni->dma_addr_next;
  if( page_order > CI_CFG_PKTS_PER_SET_S ) {
    /* page_order=INT_MAX means that there are no hardware interfaces associated
     * with this stack. */
    ci_assert_equal(page_order, INT_MAX);
    page_order = CI_CFG_PKTS_PER_SET_S;
  }
  else
    page_order += ci_log2_ge(PAGE_SIZE / CI_CFG_PKT_BUF_SIZE, 0);
  ni->packets->set[bufset_id].page_order = page_order;
  ni->dma_addr_next += (PKTS_PER_SET >> page_order) * CI_CFG_MAX_INTERFACES;
  ni->packets->n_free += PKTS_PER_SET;

  /* Initialise the new buffers. */
  for( i = 0; i < PKTS_PER_SET; i++ ) {
    ci_ip_pkt_fmt* pkt;
    int id = (bufset_id * PKTS_PER_SET) + i;
    oo_pkt_p pp;

    OO_PP_INIT(ni, pp, id);
    pkt = __PKT(ni, pp);
    OO_PKT_PP_INIT(pkt, id);

    pkt->flags = 0;
    __ci_netif_pkt_clean(pkt);
    pkt->refcount = 0;
    pkt->stack_id = trs->id;
    pkt->pio_addr = -1;
    pkt->next = ni->packets->set[bufset_id].free;
    ni->packets->set[bufset_id].free = OO_PKT_P(pkt);
  }
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    set_pkt_bufset_hwaddrs(ni, bufset_id, intf_i,
                           hw_addrs + intf_i * (1 << HW_PAGES_PER_SET_S));
  }
  ci_vfree(hw_addrs);

  trs->netif.state->packet_alloc_numa_nodes |= 1 << numa_node_id();
  CHECK_FREEPKTS(ni);
  return 0;
}


#if ! CI_CFG_UL_INTERRUPT_HELPER
void
tcp_helper_rm_dump(oo_fd_flags fd_flags, oo_sp sock_id,
                   tcp_helper_resource_t* trs, const char *line_prefix) 
{
  ci_netif* ni;
  int intf_i;
  unsigned i;

  if( trs == NULL ) {
    ci_dllink *link;
    CI_DLLIST_FOR_EACH(link, &THR_TABLE.all_stacks) {
      trs = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
      tcp_helper_rm_dump(OO_FDFLAG_STACK, OO_SP_NULL, trs, line_prefix);
      for( i = 0; i < trs->netif.ep_tbl_n; ++i )
        if (trs->netif.ep_tbl[i]) {
          ci_sock_cmn *s = ID_TO_SOCK(&trs->netif, i);
          if (s->b.state == CI_TCP_STATE_FREE || s->b.state == CI_TCP_CLOSED)
            continue;
          tcp_helper_rm_dump(s->b.state == CI_TCP_STATE_UDP ?
                             OO_FDFLAG_EP_UDP : OO_FDFLAG_EP_TCP,
                             OO_SP_FROM_INT(&trs->netif, i), trs, line_prefix);
        }
    }
    return;
  }

  ni = &trs->netif;

  ci_log("%sfd "OO_FDFLAG_FMT, line_prefix, OO_FDFLAG_ARG(fd_flags));
  if( fd_flags & OO_FDFLAG_STACK ) {
    ci_log("%smmap_bytes=%x", line_prefix, trs->mem_mmap_bytes);
  }
  else if( fd_flags & OO_FDFLAG_EP_MASK ) {
    ci_log("%sendpoint with id=%u", line_prefix, OO_SP_FMT(sock_id));
    citp_waitable_dump(ni, SP_TO_WAITABLE(ni, sock_id), line_prefix);
  }

  ci_log("%sref "OO_THR_REF_FMT, line_prefix, OO_THR_REF_ARG(trs->ref));

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_log("%svi[%d]: %d", line_prefix, intf_i,
           ef_vi_instance(ci_netif_vi(ni, intf_i)));
}
#endif


/**********************************************************************
 * Callbacks (timers, interrupts)
 */

/*--------------------------------------------------------------------
 *!
 * Eventq callback
 *    - call OS dependent code to try and poll the stack
 *    - reprime timer and/of request wakeup if needed
 *
 *--------------------------------------------------------------------*/

#if ! CI_CFG_UL_INTERRUPT_HELPER
static void defer_poll_and_prime(tcp_helper_resource_t* trs)
{
  if( efab_tcp_helper_netif_lock_or_set_flags(trs,
            OO_TRUSTED_LOCK_NEED_POLL | OO_TRUSTED_LOCK_PRIME_IF_IDLE,
            CI_EPLOCK_NETIF_NEED_POLL | CI_EPLOCK_NETIF_PRIME_IF_IDLE, 1) )
      tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_POLL_AND_PRIME);
}


static int tcp_helper_wakeup(tcp_helper_resource_t* trs, int intf_i, int budget)
{
  ci_netif* ni = &trs->netif;
  int n = 0, prime_async;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, -1);
  OO_DEBUG_RES(ci_log(FN_FMT, FN_PRI_ARGS(ni)));
  CITP_STATS_NETIF_INC(ni, interrupts);

  /* Must clear this before the poll rather than waiting till later */
  ci_bit_clear(&ni->state->evq_primed, intf_i);

  if( budget <= 0 ) {
    defer_poll_and_prime(trs);
    return 0;
  }

  /* Don't reprime if someone is spinning -- let them poll the stack. */
  prime_async = ! ci_netif_is_spinner(ni);

  if( ci_netif_intf_has_event(ni, intf_i) ) {
    if( efab_tcp_helper_netif_try_lock(trs, 1) ) {
      CITP_STATS_NETIF(++ni->state->stats.interrupt_polls);

      if( ni->flags & CI_NETIF_FLAGS_AVOID_ATOMIC ) {
        /* Steal the locks and exit: don't attempt AF_XDP in atomic context */
        tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_POLL_AND_PRIME);
        return 0;
      }

      ni->state->poll_did_wake = 0;
      n = ci_netif_poll_n(ni, budget);
      CITP_STATS_NETIF_ADD(ni, interrupt_evs, n);
      trs->netif.state->interrupt_numa_nodes |= 1 << numa_node_id();

      budget -= n;
      /* If we've exceeded budget, and have woken up user - we trust to user
       * to poll the rest of events.  But if there is no such a user - we
       * defer the poll-and-prime action to workqueue. */
      if( budget <= 0 && ! ni->state->poll_did_wake &&
          ci_netif_intf_has_event(ni, intf_i) ) {
        CITP_STATS_NETIF_INC(&trs->netif, interrupt_budget_limited);
        raw_cpu_write(oo_budget_limit_last_ts, jiffies);
        /* Steal the locks and exit */
        tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_POLL_AND_PRIME);
        return n;
      }

      if( ni->state->poll_did_wake ) {
        prime_async = 0;
        CITP_STATS_NETIF_INC(ni, interrupt_wakes);
      }
      else {
        oo_inject_packets_kernel_force(ni);
      }

      efab_tcp_helper_netif_unlock(trs, 1);
    }
    else {
      /* Couldn't get the lock.  We take this as evidence that another thread
       * is alive and doing stuff, so no need to re-enable interrupts.  The
       * EF_INT_REPRIME option overrides.
       *
       * There are three potential classes of entity which could be holding
       * the lock:
       *  1) Userspace doing stuff
       "  2) Some other userspace process
       *  3) Periodic poll in kernel
       * In case (1) the process will almost certainly re-prime whatever it
       * needs while it has the lock, however cases (2) and (3) likely won't.
       * On EF10 this isn't generally a problem because a) the majority of
       * time packets received on a VI are 'interesting' and thus will trigger
       * a userspace wakeup, and b) if that didn't happen then we'll pick them
       * up at the next periodic poll and recover.
       * Neither (a) nor (b) are true on X3: we can be attached to 'somebody
       * elses' rxq and that receives a vast number of packets, sufficiently
       * quickly that the tiny number of packets for this stack have wrapped
       * out of the superbufs by the time periodic polls happen. We therefore
       * reprime interrupts much more eagerly on X3 so that these holes
       * cannot happen, at the cost of consuming more CPU time on semi-idle
       * processes. The classic example of an app which encounters this
       * problem is a multi-process network server, which has a process
       * listening for connections (a few SYNs occasionally) forking off
       * processes handling those connections (many packets).
       */
      CITP_STATS_NETIF_INC(ni, interrupt_lock_contends);
      if( ! NI_OPTS(ni).int_reprime &&
          ! (ni->state->nic[intf_i].oo_vi_flags & OO_VI_FLAGS_RX_SHARED) )
        prime_async = 0;
    }
  }
  else {
    CITP_STATS_NETIF_INC(ni, interrupt_no_events);
  }

  if( prime_async && tcp_helper_reprime_is_needed(ni) &&
      tcp_helper_start_request_wakeup(trs, intf_i) ) {
    int rc = tcp_helper_request_wakeup_nic_from_wakeup(trs, intf_i);
    if( rc == -EAGAIN )
      defer_poll_and_prime(trs);
    else
      CITP_STATS_NETIF_INC(ni, interrupt_primes);
  }

  return n;
}


static int tcp_helper_timeout(tcp_helper_resource_t* trs, int intf_i, int budget)
{
  int n = 0;
#if CI_CFG_HW_TIMER
  ci_netif* ni = &trs->netif;
  int i;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, -1);
  OO_DEBUG_RES(ci_log(FN_FMT, FN_PRI_ARGS(ni)));
  CITP_STATS_NETIF_INC(ni, timeout_interrupts);

  /* We do not expect evq_primed to be set, but it may happen if we fail to
   * serve a non-timout interrupt in time.
   */
  i = ci_bit_test_and_clear(&ni->state->evq_primed, intf_i);
  if( i )
    CITP_STATS_NETIF(++ni->state->stats.timeout_interrupt_when_primed);

  /* Re-prime the timer here to ensure it is re-primed even if we don't
   * call ci_netif_poll() below.  Updating [evq_last_prime] ensures we
   * won't re-prime it again in ci_netif_poll().
   */
  ci_frc64(&ni->state->evq_last_prime);
  if( NI_OPTS(ni).timer_usec != 0 )
    OO_STACK_FOR_EACH_INTF_I(ni, i)
      ef_eventq_timer_prime(ci_netif_vi(ni, i), NI_OPTS(ni).timer_usec);

  if( ci_netif_intf_has_event(ni, intf_i) ) {
    if( efab_tcp_helper_netif_try_lock(trs, 1) ) {
      CITP_STATS_NETIF(++ni->state->stats.timeout_interrupt_polls);

      if( ni->flags & CI_NETIF_FLAGS_AVOID_ATOMIC || budget <= 0 ) {
        /* Steal the locks and exit: don't attempt AF_XDP in atomic context */
        tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_POLL_AND_PRIME);
        return 0;
      }

      ni->state->poll_did_wake = 0;
      trs->netif.state->interrupt_numa_nodes |= 1 << numa_node_id();
      if( (n = ci_netif_poll_n(ni, budget)) ) {
        CITP_STATS_NETIF(ni->state->stats.timeout_interrupt_evs += n;
                         ni->state->stats.timeout_interrupt_wakes +=
                         ni->state->poll_did_wake);
        if( n >= budget && ci_netif_intf_has_event(ni, intf_i) ) {
          ni->state->poll_did_wake = 1; /* avoid re-priming */
          CITP_STATS_NETIF_INC(&trs->netif, interrupt_budget_limited);
          raw_cpu_write(oo_budget_limit_last_ts, jiffies);
          /* Steal the locks and exit */
          tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_POLL_AND_PRIME);
          return n;
        }
      }
      oo_inject_packets_kernel_force(ni);
      efab_tcp_helper_netif_unlock(trs, 1);
    }
    else {
      CITP_STATS_NETIF_INC(ni, timeout_interrupt_lock_contends);
    }
  }
  else {
    CITP_STATS_NETIF_INC(ni, timeout_interrupt_no_events);
  }
#endif
  return n;
}

static int oo_handle_wakeup_or_timeout(void* context, int is_timeout,
                                        struct efhw_nic* nic, int budget)
{
  struct tcp_helper_nic* tcph_nic = context;
  tcp_helper_resource_t* trs;
  trs = CI_CONTAINER(tcp_helper_resource_t, nic[tcph_nic->thn_intf_i],
                     tcph_nic);
  if( trs->trs_aflags & OO_THR_AFLAG_POLL_AND_PRIME ) {
    /* OO_THR_AFLAG_POLL_AND_PRIME is set - i.e. in some sense the
     * previous interrupt handler is already running.
     * Workqueue will handle new events if any and will prime if needed. */
    ci_bit_clear(&trs->netif.state->evq_primed, tcph_nic->thn_intf_i);
    return 0;
  }

  if( ! CI_CFG_HW_TIMER || ! is_timeout )
    return tcp_helper_wakeup(trs, tcph_nic->thn_intf_i, budget);
  else
    return tcp_helper_timeout(trs, tcph_nic->thn_intf_i, budget);
}


static int oo_handle_wakeup_int_driven(void* context, int is_timeout,
                                        struct efhw_nic* nic_, int budget)
{
  struct tcp_helper_nic* tcph_nic = context;
  tcp_helper_resource_t* trs;
  ci_netif* ni;
  int n = 0;

  trs = CI_CONTAINER(tcp_helper_resource_t, nic[tcph_nic->thn_intf_i],
                     tcph_nic);
  ni = &trs->netif;

  if( trs->trs_aflags & OO_THR_AFLAG_POLL_AND_PRIME ) {
    /* OO_THR_AFLAG_POLL_AND_PRIME is set - i.e. in some sense the
     * previous interrupt handler is already running.
     * Workqueue will handle new events if any and will prime if needed. */
    ci_bit_set(&ni->state->evq_prime_deferred, tcph_nic->thn_intf_i);
    if( trs->trs_aflags & OO_THR_AFLAG_POLL_AND_PRIME ||
        ! ci_bit_test_and_clear(&ni->state->evq_prime_deferred,
                                tcph_nic->thn_intf_i) )
      return 0;
    /* otherwise continue as though POLL_AND_PRIME wasn't initially set */
  }

  ci_assert( ! is_timeout );
  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, -1);
  CITP_STATS_NETIF_INC(ni, interrupts);

  /* Grab lock and poll, or set bit so that lock holder will poll.  (Or if
   * stack is being destroyed, do nothing).
   */
  while( 1 ) {
    if( ci_netif_intf_has_event(ni, tcph_nic->thn_intf_i) ) {
      if( efab_tcp_helper_netif_try_lock(trs, 1) ) {
        CITP_STATS_NETIF(++ni->state->stats.interrupt_polls);
        ci_assert( ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT);

        if( ni->flags & CI_NETIF_FLAGS_AVOID_ATOMIC || budget <= 0 ) {
          /* Steal the locks and exit: don't attempt AF_XDP in atomic context */
          ci_bit_set(&ni->state->evq_prime_deferred, tcph_nic->thn_intf_i);
          tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_POLL_AND_PRIME);
          return 0;
        }

        ni->state->poll_did_wake = 0;
        n = ci_netif_poll_n(ni, budget);
        CITP_STATS_NETIF_ADD(ni, interrupt_evs, n);
        if( ni->state->poll_did_wake )
          CITP_STATS_NETIF_INC(ni, interrupt_wakes);
        trs->netif.state->interrupt_numa_nodes |= 1 << numa_node_id();

        if( n >= budget &&
            ci_netif_intf_has_event(ni, tcph_nic->thn_intf_i) ) {
          CITP_STATS_NETIF_INC(&trs->netif, interrupt_budget_limited);
          raw_cpu_write(oo_budget_limit_last_ts, jiffies);
          /* Steal the locks and exit */
          ci_bit_set(&ni->state->evq_prime_deferred, tcph_nic->thn_intf_i);
          tcp_helper_defer_dl2work(trs, OO_THR_AFLAG_POLL_AND_PRIME);
          return n;
        }

        if( ! ni->state->poll_did_wake )
          oo_inject_packets_kernel_force(ni);

        /* Make sure the deferred prime bit is clear, in case it was set by an
         * earlier iteration through the loop when the lock couldn't be taken.
         * Test it first to avoid unnecessarily locking the bus on this path.
         */
        if( ci_bit_test(&ni->state->evq_prime_deferred, tcph_nic->thn_intf_i) )
          ci_bit_clear(&ni->state->evq_prime_deferred, tcph_nic->thn_intf_i);
        tcp_helper_request_wakeup_nic(trs, tcph_nic->thn_intf_i);
        efab_tcp_helper_netif_unlock(trs, 1);
        break;
      }
      else {
        CITP_STATS_NETIF_INC(ni, interrupt_lock_contends);
        /* Drop through to set lock flags or try again... */
      }
    }
    else {
      CITP_STATS_NETIF_INC(ni, interrupt_no_events);

      /* Requesting wakeup is tricky here.  Don't want to take the
       * lock if avoidable as results in user-level seeing lock
       * contention, but need an accurate value of the evq_ptr to
       * write to request the wakeup.
       * 
       * First attempt to set the flags to request lock holder request
       * wakeup.  If this fails, then lock is not held, so evq_ptr is
       * likely consistent.  In case where we get it wrong it will
       * result in immediate wakeup and we'll try again, but won't get
       * into the feedback loop of repeated wakeups seen in bug42745.
       */
      ci_bit_set(&ni->state->evq_prime_deferred, tcph_nic->thn_intf_i);
      if( ef_eplock_set_flag_if_locked(&ni->state->lock,
                                       CI_EPLOCK_NETIF_NEED_PRIME) ) {
        break;
      }
      else if( oo_trusted_lock_set_flags_if_locked
               (trs, OO_TRUSTED_LOCK_NEED_PRIME) ) {
        break;
      }
      if( ! ci_bit_test_and_clear(&ni->state->evq_prime_deferred,
                                  tcph_nic->thn_intf_i) )
        break;
      if( tcp_helper_request_wakeup_nic_from_wakeup(trs,
                                                    tcph_nic->thn_intf_i) == 0 )
        break;
    }

    ci_bit_set(&ni->state->evq_prime_deferred, tcph_nic->thn_intf_i);
    if( ef_eplock_set_flags_if_locked(&ni->state->lock,
                                      CI_EPLOCK_NETIF_NEED_POLL |
                                      CI_EPLOCK_NETIF_NEED_PRIME) ) {
      break;
    }
    else if( oo_trusted_lock_set_flags_if_locked(trs,
                                        OO_TRUSTED_LOCK_NEED_POLL |
                                        OO_TRUSTED_LOCK_NEED_PRIME) ) {
      break;
    }
  }
  return n;
}
#endif


/*--------------------------------------------------------------------
 *!
 * TCP helper timer implementation 
 *
 *--------------------------------------------------------------------*/

#if ! CI_CFG_UL_INTERRUPT_HELPER
static void
linux_set_periodic_timer_restart(tcp_helper_resource_t* rs,
                                 unsigned long timeout)
{
  if (atomic_read(&rs->timer_running) == 0) 
    return;

  /* The timeout is calculated from IP ticks, which are ususally smaller
   * than jiffies, so the timeout can occur to be 0.
   * linux_tcp_timer_do() adds 1, but even 1-jiffie timout is ususally
   * unwelcome, so we use periodic_poll_skew as a minimum. */
  if( timeout < periodic_poll_skew )
    timeout = periodic_poll_skew;
  if( timeout >= periodic_poll )
    timeout = periodic_poll + get_random_long() % periodic_poll_skew;

  thr_queue_delayed_work(rs, &rs->timer, timeout);
}

/* Find the delay before the next IP timer will fire, in jiffies.
 * Can be unreliable if the stack is not locked. */
static unsigned long
tcp_helper_next_ip_timer(ci_netif* ni)
{
  unsigned long delay = periodic_poll;
  ci_ip_timer_state* ipts = IPTIMER_STATE(ni);
  ci_iptime_t ticks_delay = ipts->closest_timer - ipts->sched_ticks;

  /* 1 tick is roughly equal to 1ms; we do not care about delay > 1s.
   * Non-positive delta probably means that something is going on under
   * our feet, so we ignore it. */
  if( ticks_delay > 1000 || ticks_delay < 1)
    return delay;

  /* We have the next IP timer closer than 1s.  Let's find the time
   * in jiffies. */
  delay = usecs_to_jiffies(
        (ci_uint64)ticks_delay <<
        (ipts->ci_ip_time_frc2tick - ipts->ci_ip_time_frc2us));
  /* The calculations above are imprecise.  Imprecision is OK, as long
   * as the periodic timer fires **after** the IP timer should be
   * run, otherwise the IP timer subsystem refuses to run the IP
   * timer.  So we add 1 jiffie.
   */
  return delay + 1;
}

void
tcp_helper_request_timer(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  unsigned long timer_delay;

  timer_delay = tcp_helper_next_ip_timer(ni);
  /* If the current periodic timer expiration is too far from
   * jiffies + timer_delay, then we want to re-schedule the timer. */
  if( TIME_GT(trs->timer.timer.expires,
              jiffies + timer_delay + periodic_poll_skew) ) {
    /* re-schedule the periodic timer to match the delay */
    /* RHEL6 fixme:
     * We'd better run mod_delayed_work(), but it exists for
     * linux>=3.7 only.  So we cancel the old work and run a new one.
     */
    cancel_delayed_work(&trs->timer);
    thr_queue_delayed_work(trs, &trs->timer, timer_delay);
  }
}

static void
ci_netif_collect_periodic_metrics(ci_netif* ni)
{
  /* We have no lock here however, we are the only modifier
   * of lowest_free_pkts count */
  uint32_t free_pkts =
    ((ni->pkt_sets_max - ni->pkt_sets_n) << CI_CFG_PKTS_PER_SET_S) +
    ni->packets->n_free;

  if( free_pkts <= 0 )
    free_pkts = 1; /* cannot allow it to be set to 0 */

  if( free_pkts < ni->state->stats.lowest_free_pkts ||
      ni->state->stats.lowest_free_pkts == 0 )
    ni->state->stats.lowest_free_pkts = free_pkts;
}

static void
linux_tcp_timer_do(tcp_helper_resource_t* rs, unsigned long* next_timer)
{
  ci_netif* ni = &rs->netif;
  ci_uint64 now_frc;
  int rc;

  TCP_HELPER_RESOURCE_ASSERT_VALID(rs, -1);
  OO_DEBUG_VERB(ci_log("%s: running", __FUNCTION__));

  oo_timesync_update(efab_tcp_driver.timesync);

  /* Avoid interfering if stack has been active recently.  This code path
   * is only for handling time-related events that have not been handled in
   * the normal course of things because we've not had any network events.
   */
  ci_frc64(&now_frc);
  if( now_frc - ni->state->evq_last_prime >
      ni->state->timer_prime_cycles * 5 ) {
    if( efab_tcp_helper_netif_try_lock(rs, 0) ) {

      rc = ci_netif_poll(ni);
      oo_inject_packets_kernel_force(ni);
      *next_timer = tcp_helper_next_ip_timer(ni);
      efab_tcp_helper_netif_unlock(rs, 0);
      CITP_STATS_NETIF_INC(ni, periodic_polls);
      if( rc > 0 )
        CITP_STATS_NETIF_ADD(ni, periodic_evs, rc);
    }
    else {
      CITP_STATS_NETIF_INC(ni, periodic_lock_contends);
    }
    ci_netif_collect_periodic_metrics(ni);
  }
}

static void
linux_tcp_helper_periodic_timer(struct work_struct *work)
{
  tcp_helper_resource_t* rs = container_of(work, tcp_helper_resource_t,
                                           timer
#ifndef EFX_NEED_WORK_API_WRAPPERS
                                                .work
#endif
                                          );
  unsigned long next_timer = periodic_poll;

  ci_assert(NULL != rs);

  OO_DEBUG_VERB(ci_log("linux_tcp_helper_periodic_timer: fired"));

  linux_tcp_timer_do(rs, &next_timer);
  linux_set_periodic_timer_restart(rs, next_timer);
}

static void
tcp_helper_initialize_and_start_periodic_timer(tcp_helper_resource_t* rs)
{
  atomic_set(&rs->timer_running, 1);

  INIT_DELAYED_WORK(&rs->timer, linux_tcp_helper_periodic_timer);

  linux_set_periodic_timer_restart(rs, periodic_poll);
}


/* This function is used when stopping a stack, and also on error paths when
 * creating a stack fails.  The workqueue and the purge_txq_work work item
 * must be initialised, but the periodic timer need not be initialised. */
static void
tcp_helper_stop_periodic_work(tcp_helper_resource_t* rs)
{
  ci_irqlock_state_t lock_flags;
  int timer_was_running = atomic_read(&rs->timer_running);

  /* Prevent timers from rescheduling themselves. */
  atomic_set(&rs->timer_running, 0);

  /* Prevent TXQ-purge for rescheduling itself. */
  ci_irqlock_lock(&rs->lock, &lock_flags);
  rs->intfs_suspended = 0;
  ci_irqlock_unlock(&rs->lock, &lock_flags);

  /* cancel already-scheduled workitems */
  if( timer_was_running )
    cancel_delayed_work(&rs->timer);
  cancel_delayed_work(&rs->purge_txq_work);
  /* wait for running timer workqitem */
  flush_workqueue(rs->wq);
  /* the running workitems might haved kicked off some more before the flags
   * were cleared earlier - let's cancel them. */
  if( timer_was_running )
    cancel_delayed_work(&rs->timer);
  cancel_delayed_work(&rs->purge_txq_work);
  /* and flush, just in case the second workitem have started
   * before we cancelled it */
  flush_workqueue(rs->wq);
}
#endif

/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------
 *!
 * End of TCP helper timer implementation
 *
 *--------------------------------------------------------------------*/

static void
efab_tcp_helper_drop_os_socket(tcp_helper_resource_t* trs,
                               tcp_helper_endpoint_t* ep)
{
  unsigned long lock_flags;
  struct file* os_socket;

  spin_lock_irqsave(&ep->lock, lock_flags);
  os_socket = ep->os_socket;
  ep->os_socket = NULL;
  spin_unlock_irqrestore(&ep->lock, lock_flags);
  oo_os_sock_poll_register(&ep->os_sock_poll, NULL);
  if( os_socket != NULL )
    fput(os_socket);
}

/* efab_tcp_helper_close_endpoint() must be called in non-atomic
 * non-driverlink context.
 * (1) There might be postponed works for this ep, and we must process
 *     them before closing.
 * (2) tcp_helper_endpoint_clear_filters() will postpone hw filter removal.
 *     See (1) for the result.
 */
void
efab_tcp_helper_close_endpoint(tcp_helper_resource_t* trs, oo_sp ep_id,
                               int already_locked)
{
  ci_netif* ni;
  tcp_helper_endpoint_t* tep_p;
  ci_irqlock_state_t lock_flags;
  citp_waitable* w;
  citp_waitable_obj* wo;

  ni = &trs->netif;
  tep_p = ci_trs_ep_get(trs, ep_id);

  w = SP_TO_WAITABLE(ni, ep_id);
  wo = SP_TO_WAITABLE_OBJ(&trs->netif, tep_p->id);

  OO_DEBUG_TCPH(ci_log("%s: [%d:%d] ref "OO_THR_REF_FMT" %s", __FUNCTION__,
                       trs->id, OO_SP_FMT(ep_id), OO_THR_REF_ARG(trs->ref),
                       ci_tcp_state_str(wo->waitable.state)));

  ci_assert_impl(already_locked, ci_netif_is_locked(ni));
  ci_assert(!(w->sb_aflags & CI_SB_AFLAG_ORPHAN));
  ci_assert(! in_atomic());

  /* Drop ref to the OS socket.  Won't necessarily be the last reference to it;
   * there may also be one from the filter, and others from dup'd or forked
   * processes.  This needs to be done here rather since fput can block.
   */
  if( tep_p->os_socket != NULL ) {
    ci_assert( !(w->sb_flags & CI_SB_FLAG_MOVED) );

    /* Shutdown() the os_socket.  This needs to be done in a blocking
     * context.
     */
    if( w->state == CI_TCP_LISTEN )
      efab_tcp_helper_shutdown_os_sock(tep_p, SHUT_RDWR);

    efab_tcp_helper_drop_os_socket(trs, tep_p);

  }

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* SO_LINGER should be handled
   * (i) when we close the last reference to the file;
   * (ii) not postponed to any lock holder;
   * (iii) not under the trusted lock.
   *
   * Do not handle linger in the CLOSED state:
   * (A) It is useless, we are already CLOSED.
   * (B) When handing socket over, we get here with the stack locked from
   * the UL, so ci_netif_lock() results in deadlock.
   */
  if( ! (current->flags & PF_EXITING) &&
      (w->state & CI_TCP_STATE_TCP) &&
      w->state !=  CI_TCP_LISTEN && w->state !=  CI_TCP_CLOSED &&
      (wo->sock.s_flags & CI_SOCK_FLAG_LINGER) && wo->sock.so.linger != 0 &&
      ci_netif_lock(&trs->netif) == 0 ) {
    ci_assert( !already_locked );
    __ci_tcp_shutdown(&trs->netif, &wo->tcp, SHUT_WR);
    ci_tcp_linger(&trs->netif, &wo->tcp);
    /* ci_tcp_linger exits unlocked */
  }
#endif

#if CI_CFG_FD_CACHING
  if( SP_TO_WAITABLE(ni, ep_id)->state == CI_TCP_LISTEN )
    ci_tcp_listen_uncache_fds(ni, SP_TO_TCP_LISTEN(ni, ep_id));
#endif

  /*! Add ep to the list in tcp_helper_resource_t for closing
    *   - we don't increment the ref count - as we need it to reach 0 when
    * the application exits i.e. crashes (even if its holding the netif lock)
    */
  ci_irqlock_lock(&trs->lock, &lock_flags);
#if ! CI_CFG_UL_INTERRUPT_HELPER
  if( ! ci_sllink_busy(&tep_p->tobe_closed) )
    ci_sllist_push(&trs->ep_tobe_closed, &tep_p->tobe_closed);
  else {
    ci_irqlock_unlock(&trs->lock, &lock_flags);
    ci_log("%s: [%d:%d] is already closing", __FUNCTION__,
           trs->id, OO_SP_FMT(ep_id));
    return;
  }
#else
  tcp_helper_close_cleanup_ep(trs, tep_p);
  oo_ringbuffer_write(&trs->netif.closed_eps, &tep_p->id);
#endif
  ci_irqlock_unlock(&trs->lock, &lock_flags);

#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* Close pending endpoints if we are already under lock or
   * set flag in eplock to signify callback needed when netif unlocked
   *
   * It is fine to pass 0 value as in_dl_context parameter to the function
   * for in the driverlink context the trusted lock is already held and
   * effectively the following clause only sets a flag, no lock
   * gets obtained and the inner clause is skipped.
   */


  if( (already_locked && (~trs->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT)) ||
      efab_tcp_helper_netif_lock_or_set_flags(trs,
                                             OO_TRUSTED_LOCK_CLOSE_ENDPOINT,
                                             CI_EPLOCK_NETIF_CLOSE_ENDPOINT,
                                             0) ) {
    OO_DEBUG_TCPH(ci_log("%s: [%d:%d] closing now",
                         __FUNCTION__, trs->id, OO_SP_FMT(ep_id)));
    tcp_helper_close_pending_endpoints(trs);
    if( !already_locked )
      efab_tcp_helper_netif_unlock(trs, 0);
  }
  else {
    OO_DEBUG_TCPH(ci_log("%s: [%d:%d] closing deferred to lock holder",
                         __FUNCTION__, trs->id, OO_SP_FMT(ep_id)));
  }
#else
  ci_atomic_or(&trs->netif.state->action_flags, OO_ACTION_CLOSE_EP);
#endif
}


void generic_tcp_helper_close(ci_private_t* priv)
{
  tcp_helper_resource_t* trs;
  tcp_helper_endpoint_t* ep;
#if CI_CFG_FD_CACHING
  citp_waitable_obj* wo;
#endif

  ci_assert(priv->fd_flags & OO_FDFLAG_EP_MASK);
  if( priv->sock_id < 0 ) {
    LOG_EP(ci_log("%s: closing detached fd", __FUNCTION__));
    return;
  }

  trs = efab_priv_to_thr(priv);
  ep = ci_trs_ep_get(trs, priv->sock_id);
#if CI_CFG_FD_CACHING
  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);
#endif

  if (ep->fasync_queue) {
    OO_DEBUG_SHM(ci_log("generic_tcp_helper_close removing fasync helper"));
    linux_tcp_helper_fop_fasync(-1, priv->_filp, 0);
  }

 if( priv->fd_flags & OO_FDFLAG_EP_ALIEN )
    fput(priv->_filp);

#if CI_CFG_FD_CACHING
  /* We don't close the endpoint for something in the cache.  The socket will
   * either be accepted, then freed as normal, or freed on removal from the
   * cache or acceptq on listening socket shutdown.
   *
   * The IN_CACHE flag is set with the netif lock held before adding to the
   * pending cache queue when deciding to cache.  At that point we still have
   * an fdtable entry preventing any close from the app getting here. This
   * means we should be safe to assume that responsibility for endpoint free
   * has been passed to the listening socket as long as Onload prevents
   * termination of threads that are holding the stack lock.  If this is not
   * the case there is the potential to leak the endpoint if the thread is
   * killed between setting the flag and adding the socket to the pending
   * queue.
   *
   * The NO_FD flag is required to be accurate when a socket is being pulled
   * off the acceptq.  This can be done by the app on accept, or on listen
   * socket shutdown.  It is also required to be accurate if the socket is
   * freed directly from cache on listen socket shutdown.
   *
   * There is some peril here if the app does a dup2/3 onto the cached fd
   * before we've put an entry in the fdtable.  The code at user level is
   * responsible for avoiding this.
   *
   * This is tricky on listening socket shutdown.  The fd can have changed
   * identity, but we might not know about it yet.  At the moment we don't
   * cope properly with this, just logging that it occurred.
   */
  if( (priv->fd_flags & OO_FDFLAG_EP_TCP) &&
      (wo->waitable.sb_aflags & CI_SB_AFLAG_IN_CACHE) )  {
    /* Clear file_ptr before NO_FD flag to ensure correct behaviour of
     * efab_tcp_helper_detach_file */
    ep->file_ptr = NULL;
    ci_wmb();
    ci_atomic32_or(&wo->waitable.sb_aflags, CI_SB_AFLAG_IN_CACHE_NO_FD);
    LOG_EP(ci_log("%s: %d:%d fd close while cached - not freeing endpoint",
                  __FUNCTION__, ep->thr->id, OO_SP_FMT(ep->id)));
  }
  else
#endif
  {
    ep->file_ptr = NULL;
    efab_tcp_helper_close_endpoint(trs, ep->id, 0);
  }
}


/**********************************************************************
 * CI_RESOURCE_OPs.
 */

int
efab_attach_os_socket(tcp_helper_endpoint_t* ep, struct file* os_file)
{
  struct file* old_os_socket;
  struct file* new_os_socket;
  unsigned long lock_flags;

  ci_assert(ep);
  ci_assert(os_file);
  ci_assert_equal(ep->os_socket, NULL);

  new_os_socket = os_file;

  /* Check that this os_socket is really a socket. */
  if( !S_ISSOCK(os_file->f_path.dentry->d_inode->i_mode) ||
      SOCKET_I(os_file->f_path.dentry->d_inode)->file != os_file) {
    fput(new_os_socket);
    OO_DEBUG_ERR(ci_log("%s: %d:%d os_file=%p is not a socket",
                        __FUNCTION__, ep->thr->id, OO_SP_FMT(ep->id),
                        os_file));
    return -EBUSY;
  }
  
  spin_lock_irqsave(&ep->lock, lock_flags);
  old_os_socket = oo_file_xchg(&ep->os_socket, new_os_socket);
  new_os_socket = get_file(new_os_socket);
  spin_unlock_irqrestore(&ep->lock, lock_flags);

  if( SP_TO_WAITABLE(&ep->thr->netif, ep->id)->state == CI_TCP_STATE_UDP )
    oo_os_sock_poll_register(&ep->os_sock_poll, new_os_socket);
  else
    oo_os_sock_poll_register(&ep->os_sock_poll, NULL);

  fput(new_os_socket);
  if( old_os_socket != NULL )
    fput(old_os_socket);

  return 0;
}


int
__efab_create_os_socket(tcp_helper_resource_t* trs, tcp_helper_endpoint_t* ep,
                        struct file* os_file, ci_int32 domain)
{
  int rc;
  citp_waitable_obj* wo;

  rc = efab_attach_os_socket(ep, os_file);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ERROR: efab_attach_os_socket failed (%d)",
                 __FUNCTION__, rc));
    /* NB. efab_attach_os_socket() consumes [os_file] even on error. */
    return rc;
  }

  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);
  wo->sock.domain = domain;
  wo->sock.uuid = ci_from_kuid_munged(tcp_helper_get_user_ns(trs),
                  __kuid_val(ep->os_socket->f_path.dentry->d_inode->i_uid));

  /* Advertise the existence of the backing socket to user-level. */
  ci_atomic32_or(&wo->waitable.sb_aflags, CI_SB_AFLAG_OS_BACKED);

  return 0;
}


int
efab_create_os_socket(tcp_helper_resource_t* trs, tcp_helper_endpoint_t* ep,
                      ci_int32 domain, ci_int32 type, int flags)
{
  int rc;
  struct socket *sock;
  struct file *os_file;

  rc = sock_create(domain, type, 0, &sock);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ERROR: pid %d: sock_create(%d, %d, 0) failed (%d)",
                 __FUNCTION__, current->pid, domain, type, rc));
    return rc;
  }
  os_file = sock_alloc_file(sock, flags, NULL);
  if( IS_ERR(os_file) ) {
    LOG_E(ci_log("%s: ERROR: sock_alloc_file failed (%ld)",
                 __FUNCTION__, PTR_ERR(os_file)));
    /* sock_alloc_file() releases the socket in case of failure */
    return PTR_ERR(os_file);
  }
  /* sock is consumed by os_file */
  rc = __efab_create_os_socket(trs, ep, os_file, domain);
  /* on error os_file is consumed by __efab_create_os_socket(), and
   * so is the sock. */
  return rc;
}

/**********************************************************************
***************** Wakeups, callbacks, signals, events. ****************
**********************************************************************/

void tcp_helper_endpoint_wakeup(tcp_helper_resource_t* thr,
                                tcp_helper_endpoint_t* ep)
{
  citp_waitable* w = SP_TO_WAITABLE(&thr->netif, ep->id);
  int wq_active;
  w->wake_request = 0;
  wq_active = ci_waitable_active(&ep->waitq);
  ci_waitable_wakeup_all(&ep->waitq);
  if( wq_active ) {
    thr->netif.state->poll_did_wake = 1;
    if( w->sb_flags & CI_SB_FLAG_WAKE_RX )
      CITP_STATS_NETIF_INC(&thr->netif, sock_wakes_rx);
    if( w->sb_flags & CI_SB_FLAG_WAKE_TX )
      CITP_STATS_NETIF_INC(&thr->netif, sock_wakes_tx);
  }
  w->sb_flags = 0;
  /* Check to see if application has requested ASYNC notification */
  if( ep->fasync_queue ) {
    LOG_TV(ci_log(NWS_FMT "async notification sigown=%d",
                  NWS_PRI_ARGS(&thr->netif, w), w->sigown));
    kill_fasync(&ep->fasync_queue, SIGIO, POLL_IN);
    CITP_STATS_NETIF_INC(&thr->netif, sock_wakes_signal);
    if( w->sigown )
      /* Ensure we keep getting notified. */
      ci_bit_set(&w->wake_request, CI_SB_FLAG_WAKE_RX_B);
  }
}


#if CI_CFG_EPOLL3
static void
get_os_ready_list(tcp_helper_resource_t* thr, int ready_list)
{
  ci_netif* ni = &thr->netif;
  tcp_helper_endpoint_t* ep;
  ci_dllink* lnk;
  citp_waitable* w;
  unsigned long lock_flags;

  spin_lock_irqsave(&thr->os_ready_list_lock, lock_flags);
  while( ci_dllist_not_empty(&thr->os_ready_lists[ready_list]) ) {
    struct oo_p_dllink_state ready_link;
    ci_sb_epoll_state* epoll;

    lnk = ci_dllist_head(&thr->os_ready_lists[ready_list]);
    ep = CI_CONTAINER(tcp_helper_endpoint_t,
                      epoll[ready_list].os_ready_link, lnk);
    ci_dllist_remove_safe(&ep->epoll[ready_list].os_ready_link);

    w = SP_TO_WAITABLE(ni, ep->id);
    /* The waitable was put to the os_ready_list without the stack lock,
     * and the epoll membership can be abandoned now. */
    if( OO_PP_IS_NULL(w->epoll) ||
        ! (w->ready_lists_in_use & 1 << ready_list) )
      continue;

    epoll = ci_ni_aux_p2epoll(ni, w->epoll);
    ready_link = ci_sb_epoll_ready_link(ni, epoll, ready_list);
    oo_p_dllink_del(ni, ready_link);
    oo_p_dllink_add_tail(ni,
                oo_p_dllink_ptr(ni, &ni->state->ready_lists[ready_list]),
                ready_link);
  }
  spin_unlock_irqrestore(&thr->os_ready_list_lock, lock_flags);
}
#endif


#if ! CI_CFG_UL_INTERRUPT_HELPER
static void
wakeup_post_poll_list(tcp_helper_resource_t* thr)
{
  ci_netif* ni = &thr->netif;
  tcp_helper_endpoint_t* ep;
  int n = ni->ep_tbl_n;
  struct oo_p_dllink_state post_poll_list =
                           oo_p_dllink_ptr(ni, &ni->state->post_poll_list);
  citp_waitable* w;
#if CI_CFG_EPOLL3
  int tmp;
#endif

  LOG_TV(if( oo_p_dllink_is_empty(ni, post_poll_list) )
           ci_log("netif_lock_callback: need_wake but empty"));

  /* [n] ensures the loop will terminate in reasonable time no matter how
  ** badly u/l behaves.
  */
  while( n-- > 0 && ! oo_p_dllink_is_empty(ni, post_poll_list) ) {
    struct oo_p_dllink_state lnk =
                            oo_p_dllink_statep(ni, post_poll_list.l->next);
    oo_p_dllink_del_init(ni, lnk);
    w = CI_CONTAINER(citp_waitable, post_poll_link, lnk.l);

    ep = ci_netif_get_valid_ep(ni, W_SP(w));
    tcp_helper_endpoint_wakeup(thr, ep);
  }

#if CI_CFG_EPOLL3
  CI_READY_LIST_EACH(ni->state->ready_lists_in_use, tmp, n) {
    get_os_ready_list(thr, n);
    if( ! oo_p_dllink_is_empty(ni, oo_p_dllink_ptr(ni,
                                        &ni->state->ready_lists[n])) )
      efab_tcp_helper_ready_list_wakeup(thr, n);
  }
#endif
}
#endif

static inline void
tcp_helper_unlock_prime(tcp_helper_resource_t* thr)
{
  ci_netif *ni = &thr->netif;
  int intf_i;

  CITP_STATS_NETIF_INC(ni, unlock_slow_need_prime);
  if( NI_OPTS(ni).int_driven ) {
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      if( ci_bit_test_and_clear(&ni->state->evq_prime_deferred, intf_i) )
        tcp_helper_request_wakeup_nic(thr, intf_i);
  }
  else {
    tcp_helper_request_wakeup(thr);
  }
}

#if ! CI_CFG_UL_INTERRUPT_HELPER
/*--------------------------------------------------------------------
 *!
 * Callback installed with the netif (kernel/user mode shared) eplock
 * so we can get notified when the lock is dropped
 *
 * This code is either called with the kernel netif lock held (if the
 * common eplock is dropped from kernel mode). It can also be called
 * when user mode drops the eplock with the kernel lock not held.
 * However in this case we know the user mode still exists and has a
 * file open on efab. Therefore, we know that this cannot race with
 * efab_tcp_helper_rm_free_locked which is called whilst holding the kernel
 * lock once user mode has closed all efab file handles
 *
 * \param arg             TCP helper resource
 * \param lock_val        lock value
 *
 * \return                final lock value just before unlock
 *
 *--------------------------------------------------------------------*/

ci_uint64
efab_tcp_helper_netif_lock_callback(eplock_helper_t* epl, ci_uint64 lock_val,
                                    int in_dl_context)
{
  tcp_helper_resource_t* thr = CI_CONTAINER(tcp_helper_resource_t,
                                            netif.eplock_helper, epl);
  const ci_uint64 all_after_unlock_flags = (CI_EPLOCK_NETIF_NEED_PRIME |
                                           CI_EPLOCK_NETIF_PKT_WAKE);
  ci_uint64 all_handled_flags =
      CI_EPLOCK_NETIF_UNLOCK_FLAGS |
      CI_EPLOCK_NETIF_SOCKET_LIST |
      CI_EPLOCK_NETIF_UL_COMMON_MASK; /* adds PKT_WAITER | DEFERRED_PKTS */
  ci_netif* ni = &thr->netif;
  ci_uint64 flags_set;
  ci_uint64 after_unlock_flags = 0;
  ci_uint64 defer_flags = 0;
  int/*bool*/ pkt_waiter_retried = 0;
  bool orphaned;

  ci_assert(ci_netif_is_locked(ni));

  /* from dl context we can only run a subset of work, for other work we need to defer.
   * defer_flags contains all work items that will cause us to defer to non-atomic */
  if( in_dl_context ) {
    defer_flags = CI_EPLOCK_NETIF_DL_CONTEXT_DEFER_MASK;
    if(! oo_avoid_wakeup_from_dl() )
      defer_flags &=~ CI_EPLOCK_NETIF_NEED_WAKE;
  }

  do {
    if( in_dl_context )
      ni->flags |= CI_NETIF_FLAG_IN_DL_CONTEXT;

 again:
    /* We expect this to sort out CI_EPLOCK_NETIF_UL_COMMON flags and clear
    * all_handled_flags. Note the flags might have re-emerged. */
    lock_val = ci_netif_unlock_slow_common(ni, lock_val, all_handled_flags & ~defer_flags);

    orphaned = (thr->ref[OO_THR_REF_APP] == 0);

    /* Get flags set.  NB. Its possible no flags were set
    ** e.g. we tried to unlock the eplock (bottom of loop) but found
    ** someone had tried to lock it and therefore set the "need wake" bit.
    */
    flags_set = lock_val & CI_EPLOCK_NETIF_UNLOCK_FLAGS &~ CI_EPLOCK_NETIF_UL_COMMON_MASK;
    after_unlock_flags |= flags_set & all_after_unlock_flags;

    /* All code between here and the bottom of the loop should use
    ** [flags_set], and must not touch [lock_val].  If any flags
    ** subsequently get re-set, then we'll come round the loop again.
    */

#if ! CI_CFG_UL_INTERRUPT_HELPER
    /* This work comes first as DL-context wise this job is special as it
     * would either pass the work: to trusted lock (meaning no work now), or
     * to atomic work item.
     */
    if( flags_set & CI_EPLOCK_NETIF_CLOSE_ENDPOINT ) {
      /* prevent flag ping pong */
      ef_eplock_clear_flags(&ni->state->lock, CI_EPLOCK_NETIF_CLOSE_ENDPOINT);
      flags_set &=~ CI_EPLOCK_NETIF_CLOSE_ENDPOINT;
      if( oo_trusted_lock_lock_and_set_flags(thr,
                                             OO_TRUSTED_LOCK_CLOSE_ENDPOINT) ) {
        /* We've got both locks.  If in non-atomic context, do the work,
         * else defer work and locks to workitem.
         */
        OO_DEBUG_TCPH(ci_log("%s: [%u] CLOSE_ENDPOINT now",
                             __FUNCTION__, thr->id));

        /* set flags in case we get deferred */
        ef_eplock_holder_set_flags(&ni->state->lock, flags_set);

        /* lets clear IN_DL_CONTEXT flag as expected by oo_trusted_lock_drop */
        if( in_dl_context )
          ni->flags &= ~CI_NETIF_FLAG_IN_DL_CONTEXT;
        /* unlock will take care of CLOSE_ENDPOINT work */
        if( oo_trusted_lock_drop(thr, in_dl_context, 1/*has_shared=1*/) )
          return 0; /* unlock has been deferred with both locks */
        CITP_STATS_NETIF(++ni->state->stats.unlock_slow_close);
        /* best to go around to refresh flags_set */
        continue;
      }
      else {
        /* Trusted lock holder now responsible for non-atomic work. */
        OO_DEBUG_TCPH(ci_log("%s: [%u] defer CLOSE_ENDPOINT to trusted lock",
                             __FUNCTION__, thr->id));
      }
    }
#endif

    /* we test lock_val to include into consideration COMMON_MASK
     * flags. Canonically, it would suit to run this check before
     * ci_netif_unlock_slow_common. However, we consider doing some
     * of its work early (in DL context) a good thing. */
    if( lock_val & defer_flags ) {
      ci_assert(in_dl_context);
      /* We cannot finish this work in DL context, let's defer to work item
       * immediately without any partial work */
      OO_DEBUG_TCPH(ci_log("%s: [%u] defer to workitem, flags %llx",
                           __FUNCTION__, thr->id, lock_val));
      /* set flags so work item can pick up the work */
      ef_eplock_holder_set_flags(&ni->state->lock, flags_set);
      tcp_helper_defer_dl2work(thr, OO_THR_AFLAG_UNLOCK_UNTRUSTED);
      return 0;
    }

#if ! CI_CFG_UL_INTERRUPT_HELPER
    if( flags_set & CI_EPLOCK_NETIF_SWF_UPDATE ) {
      oof_cb_sw_filter_apply(ni);
      CITP_STATS_NETIF(++ni->state->stats.unlock_slow_swf_update);
      flags_set &=~ CI_EPLOCK_NETIF_SWF_UPDATE;
    }

    if( flags_set & CI_EPLOCK_NETIF_NEED_WAKE ) {
      OO_DEBUG_TCPH(ci_log("%s: [%u] wake up endpoints",
                           __FUNCTION__, thr->id));
      wakeup_post_poll_list(thr);
      CITP_STATS_NETIF(++ni->state->stats.unlock_slow_wake);
      flags_set &=~ CI_EPLOCK_NETIF_NEED_WAKE;
    }

    /* Monitor the number of free packets: pretend that
    ** CI_EPLOCK_NETIF_NEED_PKT_SET was set if non-current packet sets are
    ** short of packets.
    */
    if( (flags_set & CI_EPLOCK_NETIF_NEED_PKT_SET) ||
        (!orphaned && oo_want_proactive_packet_allocation(ni)) ) {
      OO_DEBUG_TCPH(ci_log("%s: [%u] NEED_PKT_SET now",
                           __FUNCTION__, thr->id));
      efab_tcp_helper_more_bufs(thr);
      flags_set &=~ CI_EPLOCK_NETIF_NEED_PKT_SET;
    }

    /* Monitor the number of socket buffers.
     */
    if( (flags_set & CI_EPLOCK_NETIF_NEED_SOCK_BUFS) ||
        (!orphaned && oo_want_proactive_socket_allocation(ni)) ) {
      OO_DEBUG_TCPH(ci_log("%s: [%u] NEED_SOCK_BUFS now",
                           __FUNCTION__, thr->id));
      efab_tcp_helper_more_socks(thr);
      flags_set &=~ CI_EPLOCK_NETIF_NEED_SOCK_BUFS;

    }
#endif

#if CI_CFG_NIC_RESET_SUPPORT
    if( flags_set & CI_EPLOCK_NETIF_PURGE_TXQS ) {
      tcp_helper_purge_txq_locked(thr);
      flags_set &= ~CI_EPLOCK_NETIF_PURGE_TXQS;
    }
#endif

    if( flags_set & CI_EPLOCK_NETIF_KERNEL_PACKETS ) {
      OO_DEBUG_TCPH(ci_log("%s: [%u] forward %u packets to kernel",
                           __FUNCTION__, thr->id,
                           kernel_packets_pending(ni->state)));
      oo_inject_packets_kernel(thr, 0);
      flags_set &= ~CI_EPLOCK_NETIF_KERNEL_PACKETS;
    }

#if CI_CFG_EPOLL3
    if( flags_set & CI_EPLOCK_NETIF_FREE_READY_LIST ) {
      ci_netif_free_ready_lists(ni);
      flags_set &= ~CI_EPLOCK_NETIF_FREE_READY_LIST;
    }
#endif

#if CI_CFG_HANDLE_ICMP
    if( flags_set & CI_EPLOCK_NETIF_HANDLE_ICMP ) {
      CITP_STATS_NETIF(++ni->state->stats.rx_icmp_hooked);
      oo_icmp_handle(thr);
      flags_set &= ~CI_EPLOCK_NETIF_HANDLE_ICMP;
    }
#endif


    /* we have handled all the flags (that get handled before unlock) */
    ci_assert_nflags(flags_set, ~all_after_unlock_flags);

    /* We can free some packets while closing endpoints, etc.  Check this
     * condition again, but do it only once. */
    if( ! pkt_waiter_retried &&
        (ni->state->lock.lock & CI_EPLOCK_NETIF_IS_PKT_WAITER) &&
        ci_netif_pkt_tx_can_alloc_now(ni) ) {
      /* Call ci_netif_unlock_slow_common() again to handle PKT_WAITER
       * flag.  */
      pkt_waiter_retried = 1;
      goto again;
    }

    /* IN_DL_CONTEXT flag should be removed under the stack lock - so we
     * remove it inside the "while" loop here and set back if necessary at
     * the beginning of the loop. */
    if( in_dl_context )
      ni->flags &= ~CI_NETIF_FLAG_IN_DL_CONTEXT;

  } while ( !ef_eplock_try_unlock(&ni->state->lock, &lock_val,
                                  CI_EPLOCK_NETIF_UNLOCK_FLAGS |
                                  CI_EPLOCK_NETIF_SOCKET_LIST) );

  if( after_unlock_flags & CI_EPLOCK_NETIF_NEED_PRIME )
    tcp_helper_unlock_prime(thr);

  if( after_unlock_flags & CI_EPLOCK_NETIF_PKT_WAKE ) {
    CITP_STATS_NETIF_INC(&thr->netif, pkt_wakes);
    ci_waitq_wakeup(&thr->pkt_waitq);
  }

  /* ALERT!  If [after_unlock_flags] is used for any more flags, they must
   * be included in all_after_unlock_flags above!
   */
  ci_assert_nflags(after_unlock_flags, ~all_after_unlock_flags);

  return lock_val;
}
#else /* CI_CFG_UL_INTERRUPT_HELPER */
int
efab_eplock_wake_and_do(ci_netif *ni, ci_uint64 l)
{
  tcp_helper_resource_t* thr = netif2tcp_helper_resource(ni);

  /* First of all, request wakeup for EF100 */
  if( l & CI_EPLOCK_NETIF_NEED_PRIME )
    tcp_helper_unlock_prime(thr);

  if( l & CI_EPLOCK_NETIF_PKT_WAKE ) {
    CITP_STATS_NETIF_INC(&thr->netif, pkt_wakes);
    ci_waitq_wakeup(&thr->pkt_waitq);
  }

  if( l & CI_EPLOCK_FL_NEED_WAKE )
    efab_eplock_wake(ni);

  return 0;
}
#endif /* CI_CFG_UL_INTERRUPT_HELPER */

/**********************************************************************
***************** Iterators to find netifs ***************************
**********************************************************************/

/*--------------------------------------------------------------------
 *!
 * Called to iterate through all the various netifs, where we feel
 * safe to continue with an unlocked netif. This function guareetees
 * the netif pointer will remain valid BUT callees need to be aware
 * that other contexts could be changing the netif state.
 *
 * If the caller wants to stop iteration before the function returns
 * non-zero, he should drop the netif reference by calling
 * iterate_netifs_unlocked_dropref().
 *
 * Usage:
 *   netif = NULL;
 *   while (iterate_netifs_unlocked(&netif) == 0) {
 *     do_something_useful_with_each_netif;
 *     if (going_to_stop) {
 *       iterate_netifs_unlocked_dropref(netif);
 *       break;
 *     }
 *     do_something;
 *   }
 *
 * \param p_ni       IN: previous netif (NULL to start)
 *                   OUT: next netif
 * \param ref_type: take refcount of this type
 *                  (and skip the stack if it fails)
 * \param ref_zero: require that this refcount type is zero
 *                  (i.e. there is no UL, no app)
 *
 * \return either an unlocked netif or NULL if no more netifs
 *
 *--------------------------------------------------------------------*/

extern int
iterate_netifs_unlocked(ci_netif **p_ni, enum oo_thr_ref_type ref_type,
                        enum oo_thr_ref_type ref_zero)
{
  ci_netif *ni_prev = *p_ni;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t * thr_prev = NULL;
  ci_dllink *link = NULL;
  int rc = -ENOENT;

  ci_assert_lt(ref_type, ref_zero);

  if (ni_prev) {
    thr_prev = CI_CONTAINER(tcp_helper_resource_t, netif, ni_prev);
    TCP_HELPER_RESOURCE_ASSERT_VALID(thr_prev, -1);
  }

  /* We need a lock to protect the link and thr from removing 
   * after we've got the link and before taking refcount */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);

  if (ni_prev != NULL) {
    link = thr_prev->all_stacks_link.next;
    if (ci_dllist_end(&THR_TABLE.all_stacks) == link)
      link = NULL;
  } else if (ci_dllist_not_empty(&THR_TABLE.all_stacks))
    link = ci_dllist_start(&THR_TABLE.all_stacks);

  if (link) {
    tcp_helper_resource_t * thr;

    /* Skip dead thr's */
again:
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);

    if( ! oo_thr_ref_is_zero(thr->ref, ref_zero) ||
        oo_thr_ref_get(thr->ref, ref_type) != 0 ) {
      link = link->next;
      if (ci_dllist_end(&THR_TABLE.all_stacks) == link) {
        *p_ni = NULL;
        goto out;
      }
      goto again;
    }

    rc = 0;
    *p_ni = &thr->netif;
  }

out:
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  if (ni_prev != NULL)
    iterate_netifs_unlocked_dropref(&thr_prev->netif, ref_type);
  return rc;
}



static int efab_ipid_alloc(efab_ipid_cb_t* ipid)
{
  int i;
  int rv;
  ci_irqlock_state_t lock_flags;

  ci_assert( ipid->init == EFAB_IPID_INIT );
  ci_irqlock_lock( &ipid->lock, &lock_flags );

  /* go find an unused block */
  i = ipid->last_block_used;
  do {
    i = (i + 1) % CI_IPID_BLOCK_COUNT;
    if( i == ipid->last_block_used )
      break;
    if( !ipid->range[i] ) {
      ipid->range[i]++;
      rv = CI_IPID_MIN + (i << CI_IPID_BLOCK_SHIFT);
      ci_assert((rv >= CI_IPID_MIN) && 
                (rv <= CI_IPID_MAX - CI_IPID_BLOCK_LENGTH + 1));
      ipid->last_block_used = i;
      goto alloc_exit;
    } else {
      ci_assert( ipid->range[i] == 1 );
    }
  } while(1);
  /* !!Out of blocks!! */
  rv = -ENOMEM;

 alloc_exit:
  ci_irqlock_unlock( &ipid->lock, &lock_flags );
  return rv;
}


static int efab_ipid_free(efab_ipid_cb_t* ipid, int base)
{
  int i;
  ci_irqlock_state_t lock_flags;

  ci_assert( ipid->init == EFAB_IPID_INIT );

  if(  (base & CI_IPID_BLOCK_MASK) != 0 )
    return -EINVAL;  /* not actually on a block boundary */

  ci_assert((base >= CI_IPID_MIN) && 
            (base <= CI_IPID_MAX - CI_IPID_BLOCK_LENGTH + 1));

  ci_irqlock_lock( &ipid->lock, &lock_flags );
  i = (base - CI_IPID_MIN) >> CI_IPID_BLOCK_SHIFT;
  ci_assert( ipid->range[i] == 1 );
  ipid->range[i] = 0;
  ci_irqlock_unlock( &ipid->lock, &lock_flags );
  return 0;
}


int
efab_tcp_helper_vi_stats_query(tcp_helper_resource_t* trs, unsigned int intf_i,
                               void* data, size_t data_len, int do_reset)
{
  struct efrm_vi* virs;

  if( intf_i >= CI_CFG_MAX_INTERFACES )
    return -EINVAL;

  virs = tcp_helper_vi(trs, intf_i);
  return efrm_vi_get_rx_error_stats(virs, data, data_len, do_reset);
}


#if CI_CFG_INJECT_PACKETS
static int oo_inject_packet_kernel(ci_netif* ni, ci_ip_pkt_fmt* pkt)
{
  struct net_device* dev;
  struct sk_buff* skb;
  ci_hwport_id_t hwport;
  ci_ip_pkt_fmt* frag;
  ci_uint32 pay_len;
  int len;

  if( pkt->intf_i < 0 || pkt->intf_i >= CI_CFG_MAX_INTERFACES ) {
    /* We should have checked this before adding the packet to the list. */
    ci_assert(0);
    return -ENODEV;
  }

  hwport = ni->state->intf_i_to_hwport[pkt->intf_i];

  dev = efhw_nic_get_net_dev(efrm_client_get_nic(oo_nics[hwport].efrm_client));
  if( dev == NULL ) {
    /* There is a race against unplugging */
    CITP_STATS_NETIF_INC(ni, no_match_bad_netdev);
    return -ENODEV;
  }

  /* Allocate an skb for the kernel's consumption. */
  /* pkt is in the shared memory and may be modified from UL.  So we store
   * the values, check them and then use for memcpy to ensure they do not
   * change under our feet. */
  pay_len = OO_ACCESS_ONCE(pkt->pay_len);
  skb = netdev_alloc_skb(dev, pay_len);
  if( skb == NULL ) {
    CITP_STATS_NETIF_INC(ni, no_match_oom);
    dev_put(dev);
    return -ENOMEM;
  }
  skb_put(skb, pay_len);

  /* Copy the Ethernet payload into the skb. */
  frag = pkt;
  len = 0;
  do {
    int offbuf_off = OO_ACCESS_ONCE(frag->buf.off);
    int offbuf_end = OO_ACCESS_ONCE(frag->buf.end);

    if( offbuf_end - offbuf_off > pay_len - len ||
        offbuf_end + offsetof(typeof(*frag), buf) > CI_CFG_PKT_BUF_SIZE )
      goto corrupted;

    memcpy(skb->data + len,
           (void*)((uintptr_t)(&frag->buf) + offbuf_off),
           offbuf_end - offbuf_off);
    len += offbuf_end - offbuf_off;

    if( OO_PP_IS_NULL(frag->frag_next) )
      break;
    frag = PKT_CHK_NNL(ni, frag->frag_next);
  } while( 1 );

  ci_assert_equal(pay_len, len);
  if( pay_len != len )
    goto corrupted;

  /* Infer the protocol from the Ethernet payload. */
  skb->protocol = eth_type_trans(skb, dev);

  /* Inject the skb into the kernel.  The return value indicates whether the
   * kernel decided to drop the packet, but we don't need to check that. */
  ci_netif_rx_non_irq(skb);

  dev_put(dev);
  return 0;

corrupted:
  CITP_STATS_NETIF_INC(ni, no_match_corrupted);
  kfree_skb(skb);
  dev_put(dev);
  return -EINVAL;
}


struct oo_inject_packets_work_data {
  struct work_struct work;
  tcp_helper_resource_t* trs;
  oo_pkt_p pkt_head;
};

static void oo_inject_packets_work(struct work_struct* work)
{
  struct oo_inject_packets_work_data* data =
            container_of(work, struct oo_inject_packets_work_data, work);
  ci_netif* ni = &data->trs->netif;
  ci_ip_pkt_fmt* pkt;
  int netif_is_locked;

  /* Part one: inject all packets to the kernel */
  for( pkt = PKT_CHK(ni, data->pkt_head); ; pkt = PKT_CHK(ni, pkt->next) ) {
    /* No need to check the return value here.  If the function fails, the
     * packet is dropped, and a counter is incremented. */
    oo_inject_packet_kernel(ni, pkt);

    if( OO_PP_IS_NULL(pkt->next) )
      break;
  }

  /* Part two: free Onload packets */
  netif_is_locked = 0;
  for( pkt = PKT_CHK(ni, data->pkt_head); ; pkt = PKT_CHK(ni, data->pkt_head)) {
    data->pkt_head = pkt->next;
    ci_netif_pkt_release_mnl(ni, pkt, &netif_is_locked);
    if( OO_PP_IS_NULL(data->pkt_head) )
      break;
  }
  if( netif_is_locked )
    ci_netif_unlock(ni);

  kfree(data);
}
#endif

#if CI_CFG_INJECT_PACKETS
/* Injects all pending kernel packets into the kernel's network stack. */
void oo_inject_packets_kernel(tcp_helper_resource_t* trs, int sync)
{
  ci_netif* ni = &trs->netif;
  struct oo_inject_packets_work_data* data;

  ci_assert(ci_netif_is_locked(ni));

  /* We can't avoid this when handling CI_EPLOCK_NETIF_KERNEL_PACKETS
   * because of the complicated nature of the netif unlock function.
   * efab_tcp_helper_netif_lock_callback() can set this flag again under
   * some conditions. */
  if( ni->state->kernel_packets_pending == 0 )
    return;

  ci_assert( ! OO_PP_IS_NULL(ni->state->kernel_packets_head) );

  /* Are we allowed to inject any packets? */
  if( ! (ni->flags & CI_NETIF_FLAG_MAY_INJECT_TO_KERNEL) ) {
    CITP_STATS_NETIF_INC(ni, no_match_dropped);
    while( ! OO_PP_IS_NULL(ni->state->kernel_packets_head) ) {
      ci_ip_pkt_fmt* pkt = PKT_CHK(ni, ni->state->kernel_packets_head);
      ni->state->kernel_packets_head = pkt->next;
      ci_netif_pkt_release(ni, pkt);
    }
    ci_assert_equal(ni->state->kernel_packets_head, OO_PP_NULL);
    ni->state->kernel_packets_tail = OO_PP_NULL;
    ni->state->kernel_packets_pending = 0;
    return;
  }

  data = kmalloc(sizeof(*data), GFP_ATOMIC);
  if( data == NULL )
    return;

  INIT_WORK(&data->work, oo_inject_packets_work);
  data->trs = trs;
  data->pkt_head = ni->state->kernel_packets_head;

  if( sync ) {
    oo_inject_packets_work(&data->work);
  }
  else {
    /* Push data to kernel without holding the stack lock */
    queue_work(trs->wq, &data->work);
  }

  CITP_STATS_NETIF_INC(ni, no_match_pass_to_kernel_batches);

  ni->state->kernel_packets_head = OO_PP_NULL;
  ni->state->kernel_packets_tail = OO_PP_NULL;
  ni->state->kernel_packets_pending = 0;
  ci_frc64(&ni->state->kernel_packets_last_forwarded);
}
#endif /* CI_CFG_INJECT_PACKETS */


#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
#include <linux/syscalls.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>


ci_inline int oo_xdp_rx_pkt_locked(ci_netif* ni,
                                   struct net_device* dev,
                                   ci_ip_pkt_fmt* pkt)
{
  /* TODO: ensure that packet:
   *  * is linear
   *  * has enough headroom (256 bytes)
   *  see netif_receive_generic_xdp in kernel */
  struct bpf_prog* xdp_prog = rcu_dereference(
                    oo_nics[ni->intf_i_to_hwport[pkt->intf_i] ].prog);
  struct xdp_buff _xdp;
  struct xdp_buff* xdp = &_xdp;
  void *orig_data, *orig_data_end;
  struct xdp_rxq_info xdp_rx_queue = {
    .dev = dev,
  };
  int act;

  if( xdp_prog == NULL )
      return XDP_PASS;

  /* The XDP program wants to see the packet starting at the MAC
   * header.
   */
  xdp->data = oo_ether_hdr(pkt);
  xdp->data_meta = xdp->data; /* note: netdriver does not support metadata at all, we could do the same */

  /* There are two commonly-discussed behaviours for jumbograms:
   * 1) Drop the packet here (it would be bad to bypass XDP without dropping
   *    because that's a firewall bypass)
   * 2) Pass only the first fragment to the XDP
   * This code implements option (2), which is not what most kernel drivers
   * do at time of writing but is likely to be the future. See discussion at
   * https://github.com/xdp-project/xdp-project/blob/master/areas/core/xdp-multi-buffer01-design.org
   */
  xdp->data_end = xdp->data + oo_offbuf_left(&pkt->buf);
  xdp->data_hard_start = xdp->data; /* no headroom, should be 256 bytes at least */
  orig_data_end = xdp->data_end;
  orig_data = xdp->data;

  xdp->rxq = &xdp_rx_queue; /* TODO: would that do? */

  act = bpf_prog_run_xdp(xdp_prog, xdp);

  return act;
}


/* bool */ int
efab_tcp_helper_xdp_rx_pkt(tcp_helper_resource_t* trs, ci_ip_pkt_fmt* pkt)
{
  int ret = XDP_PASS;
  struct tcp_helper_nic* trs_nic = &trs->nic[pkt->intf_i];
  struct efhw_nic* nic;
  struct net_device* dev;
  ci_netif* ni = &trs->netif;

  /* Early exit if nothing to do.  We'll re-read it after RCU lock later. */
  if( oo_nics[ni->intf_i_to_hwport[pkt->intf_i]].prog == NULL )
    return 1;

  nic = efrm_client_get_nic(trs_nic->thn_oo_nic->efrm_client);
  dev = efhw_nic_get_net_dev(nic);
  if( ! dev ) {
    /* We can't let a NULL value into bpf_run() because some helper functions
     * can crash the kernel with that. We don't really want to accept these
     * packets blindly either, so I suppose this will have to do */
    CITP_STATS_NETIF_INC(ni, rx_xdp_aborted);
    return 0;
  }

  /* As kernel stack disable preemption and start read lock critical section
   * seperately for each pkt */
  preempt_disable();
  rcu_read_lock();
  ret = oo_xdp_rx_pkt_locked(ni, dev, pkt);
  rcu_read_unlock();
  preempt_enable();

  dev_put(dev);

  switch( ret ) {
    case XDP_PASS:
      CITP_STATS_NETIF_INC(ni, rx_xdp_pass);
      break;
    case XDP_DROP:
      CITP_STATS_NETIF_INC(ni, rx_xdp_drop);
      break;
    case XDP_TX:
      CITP_STATS_NETIF_INC(ni, rx_xdp_tx);
      break;
    case XDP_REDIRECT:
      CITP_STATS_NETIF_INC(ni, rx_xdp_redirect);
      break;
    case XDP_ABORTED:
      CITP_STATS_NETIF_INC(ni, rx_xdp_aborted);
      break;
    default:
      CITP_STATS_NETIF_INC(ni, rx_xdp_unknown);
      /* drop */
      break;
  };
  return ret == XDP_PASS;
}
#endif

int efab_tcp_helper_tcp_offload_set_isn(tcp_helper_resource_t* trs,
                                        oo_sp ep_id, ci_uint32 isn)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  ci_netif* ni = &trs->netif;
  int intf_i;
  tcp_helper_endpoint_t* tep_p = ci_trs_get_valid_ep(trs, ep_id);

  ci_assert(! in_atomic());

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    if( ni->nic_hw[intf_i].plugin_rx &&
        tep_p->plugin_stream_id[intf_i] != INVALID_PLUGIN_HANDLE ) {
      struct xsn_tcp_sync_stream sync = {
        .in_conn_id = tep_p->plugin_stream_id[intf_i],
        .in_seq = isn,
      };
      int rc = efrm_ext_msg(ni->nic_hw[intf_i].plugin_rx,
                            XSN_CEPH_SYNC_STREAM, &sync, sizeof(sync));
      if( rc < 0 )
        return rc;
    }
  }
  return 0;
#else
  return -ENOTSUPP;
#endif
}

int efab_tcp_helper_tcp_offload_get_stream_id(tcp_helper_resource_t* trs,
                                              oo_sp ep_id, ci_int32 intf_i,
                                              ci_uint32* stream_id,
                                              ci_uint64* ddr_base,
                                              ci_uint64* ddr_size)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  ci_netif* ni = &trs->netif;
  tcp_helper_endpoint_t* tep_p = ci_trs_get_valid_ep(trs, ep_id);
  ci_tcp_state* ts = SP_TO_TCP(ni, ep_id);

  if( intf_i < 0 || intf_i >= oo_stack_intf_max(ni) )
    return -EINVAL;

  /* With the non-P2H design, we only created a stream on the interface over
   * which the stream routes.  That might not be the same as the interface on
   * which traffic is received. */
  if( ! ci_netif_tcp_plugin_uses_p2h(ni, intf_i) )
    intf_i = ts->s.pkt.intf_i;

  if( stream_id )
    *stream_id = tep_p->plugin_stream_id[intf_i];
  if( ddr_base )
    *ddr_base = tep_p->plugin_ddr_base[intf_i];
  if( ddr_size )
    *ddr_size = tep_p->plugin_ddr_size[intf_i];
  return 0;
#else
  return -ENOTSUPP;
#endif
}

int efab_tcp_helper_efct_superbuf_config_refresh(
                                        tcp_helper_resource_t* trs,
                                        oo_efct_superbuf_config_refresh_t* op)
{
  struct tcp_helper_nic* nic;
  if( op->intf_i >= oo_stack_intf_max(&trs->netif) )
    return -EINVAL;
  nic = &trs->nic[op->intf_i];
  if( op->qid >= ARRAY_SIZE(nic->thn_efct_rxq) ||
      ! nic->thn_efct_rxq[op->qid] )
    return -EINVAL;
  return efrm_rxq_refresh(nic->thn_efct_rxq[op->qid],
                          (unsigned long)CI_USER_PTR_GET(op->superbufs),
                          CI_USER_PTR_GET(op->current_mappings),
                          op->max_superbufs);
}

static tcp_helper_resource_t*
thr_ref2thr(oo_thr_ref_t ref)
{
  return CI_CONTAINER(tcp_helper_resource_t, ref[0], &ref[0]);
}

static void thr_release_base(oo_thr_ref_t ref)
{
  tcp_helper_resource_t* thr = thr_ref2thr(ref);
  OO_DEBUG_TCPH(ci_log("%s [%d] "OO_THR_REF_FMT, __func__, thr->id,
                       OO_THR_REF_ARG(ref)));
  efab_tcp_helper_k_ref_count_is_zero(thr);
}

static void thr_release_file(oo_thr_ref_t ref)
{
  tcp_helper_resource_t* thr = thr_ref2thr(ref);
  OO_DEBUG_TCPH(ci_log("%s [%d] "OO_THR_REF_FMT, __func__, thr->id,
                       OO_THR_REF_ARG(ref)));
  tcp_helper_rm_free(thr);
}

static void thr_release_app(oo_thr_ref_t ref)
{
  tcp_helper_resource_t* thr = thr_ref2thr(ref);
  OO_DEBUG_TCPH(ci_log("%s [%d] "OO_THR_REF_FMT, __func__, thr->id,
                       OO_THR_REF_ARG(ref)));
  efab_notify_stacklist_change(thr);
  /* We could run the most part of efab_tcp_helper_rm_free_locked() here.
   * But as we don't trust the "services" running in UL, we'll have to
   * re-do this at thr_release_file() above.  So it does not worth the
   * hassle.
   *
   * However it may result in slightly different behaviour when
   * onload_tcpdump is present in somewhat broken cases like ON-2108.
   */
  oo_thr_ref_drop(ref, OO_THR_REF_FILE);
}

oo_thr_ref_release_fn oo_thr_ref_release[OO_THR_REF_INFTY] =
{
  thr_release_base,
  thr_release_file,
  thr_release_app
};

/*! \cidoxg_end */
