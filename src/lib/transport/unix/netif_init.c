/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file netif_init.c
** <L5_PRIVATE L5_SOURCE>
** \author  stg
**  \brief  Common functionality used by TCP & UDP
**   \date  2004/06/09
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_unix */

#include <signal.h>
#include <internal.h>
#include <ci/internal/transport_config_opt.h>
#include <ci/tools/sllist.h>
#include <onload/dup2_lock.h>
#include <cplane/cplane.h>
#include <onload/ul/tcp_helper.h>


#define LPF "citp_netif_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF


int citp_netif_init_ctor(void)
{
  Log_S(ci_log("%s()", __FUNCTION__));

  citp_cmn_netif_init_ctor(CITP_OPTS.netif_dtor);

  return 0;
}

/* Storage for stackname context across fork() */
static struct oo_stackname_state stackname_config_across_fork;

/* Storage for library context across fork() */
static citp_lib_context_t citp_lib_context_across_fork;

/*! Handles user-level netif internals pre fork() */
static void citp_netif_pre_fork_hook(void);
/*! Handles user-level netif internals post fork() in the parent */
static void citp_netif_parent_fork_hook(void);
/* Handles user-level netif internals post fork() in the child */
static void citp_netif_child_fork_hook(void);

/* I do not understand why, but __register_atfork seems to work better than
 * __libc_atfork */
extern int __register_atfork(void (*prepare)(void), void (*parent)(void), 
                             void (*child)(void), void *dso);

int ci_setup_fork(void)
{
    Log_CALL(ci_log("%s()", __FUNCTION__));
    return __register_atfork(citp_netif_pre_fork_hook,
                             citp_netif_parent_fork_hook, 
                             citp_netif_child_fork_hook, NULL);
}


/* Handles user-level netif internals pre fork() */
static void citp_netif_pre_fork_hook(void)
{
  struct oo_stackname_state *stackname_state;

  /* If we have not inited fork hook, how can we get here in the first
   * place? */
  if( citp.init_level < CITP_INIT_FORK_HOOKS) {
    ci_assert(0);
    return;
  }

  Log_CALL(ci_log("%s()", __FUNCTION__));

  /* Lock to protect citp_lib_context_across_fork across fork(). */
  pthread_mutex_lock(&citp_dup_lock);

  if( citp.init_level < CITP_INIT_FDTABLE )
    return;

  citp_enter_lib(&citp_lib_context_across_fork);

  CITP_FDTABLE_LOCK();

#if CI_CFG_FD_CACHING
  /* citp_netif_cache_warn_on_fork takes netif lock
   * so should be called before taking dup2 lock so lock
   * ordering is consistent with ci_tcp_ep_ctor
   */
  if( citp.init_level >= CITP_INIT_NETIF )
    citp_netif_cache_warn_on_fork();
#endif

  oo_rwlock_lock_write(&citp_dup2_lock);
  pthread_mutex_lock(&citp_pkt_map_lock);

  if( citp.init_level < CITP_INIT_NETIF )
    return;

  stackname_state = oo_stackname_thread_get();
  memcpy(&stackname_config_across_fork, stackname_state, 
         sizeof(stackname_config_across_fork));
  
  /* If the call to _fork() subsequently fails we potentially have
   * marked all of our netifs as shared when ideally we shouldn't
   * have.  However, this is non-fatal and is probably the least of
   * our worries if the system can't fork!
   */
  __citp_netif_mark_all_shared();
  if( CITP_OPTS.fork_netif == CI_UNIX_FORK_NETIF_BOTH )
    __citp_netif_mark_all_dont_use();
}

/* Handles user-level netif internals post fork() in the parent */
static void citp_netif_parent_fork_hook(void)
{
  /* If we have not inited fork hook, how can we get here in the first
   * place? */
  if( citp.init_level < CITP_INIT_FORK_HOOKS) {
    ci_assert(0);
    return;
  }

  Log_CALL(ci_log("%s()", __FUNCTION__));
  pthread_mutex_unlock(&citp_pkt_map_lock);
  oo_rwlock_unlock_write(&citp_dup2_lock);

  if( citp.init_level < CITP_INIT_FDTABLE)
    goto unlock_fork;
  else if( citp.init_level < CITP_INIT_NETIF)
    goto unlock;

  if( CITP_OPTS.fork_netif == CI_UNIX_FORK_NETIF_PARENT ) 
    __citp_netif_mark_all_dont_use();

unlock:
  CITP_FDTABLE_UNLOCK();
  citp_exit_lib(&citp_lib_context_across_fork, 0);
unlock_fork:
  pthread_mutex_unlock(&citp_dup_lock);
}

/* Handles user-level netif internals post fork() in the child */
static void citp_netif_child_fork_hook(void)
{
  /* If we have not inited fork hook, how can we get here in the first
   * place? */
  if( citp.init_level < CITP_INIT_FORK_HOOKS) {
    ci_assert(0);
    return;
  }
#if CI_CFG_FD_CACHING
  citp.pid = getpid();
#endif

  /* We can't just use CITP_UNLOCK since we are not allowed to call
   * non-async-safe functions from the child hook.
   * For now we are the only thread so we may re-init all locks.
   *
   * Formally, we are not allowed to do this: these are not async-safe
   * functions.  However, "The GNU C Library Reference Manual" tells us in
   * "POSIX Threads" -> "Threads and Fork":
   * "... install handlers with pthread_atfork as follows: have the prepare
   * handler lock the mutexes (in locking order), and the parent handler
   * unlock the mutexes. The child handler should reset the mutexes using
   * pthread_mutex_init, as well as any other synchronization objects such
   * as condition variables."
   * So, we just follow this book recommendation.
   */
  pthread_mutex_init(&citp_dup_lock, NULL);
  oo_rwlock_ctor(&citp_ul_lock);
  oo_rwlock_ctor(&citp_dup2_lock);
  pthread_mutex_init(&citp_pkt_map_lock, NULL);

  if( citp.init_level < CITP_INIT_FDTABLE)
    return;

  pthread_mutex_lock(&citp_dup_lock);
  CITP_FDTABLE_LOCK();

  if( citp.init_level < CITP_INIT_NETIF)
    goto setup_fdtable;

  citp_setup_logging_prefix();
  Log_CALL(ci_log("%s()", __FUNCTION__));

  oo_stackname_update(&stackname_config_across_fork);

  if( CITP_OPTS.fork_netif == CI_UNIX_FORK_NETIF_CHILD ) 
    __citp_netif_mark_all_dont_use();

setup_fdtable:
  /* Allow the fdtable to make itself safe across the fork(). */
  citp_fdtable_fork_hook();

  CITP_FDTABLE_UNLOCK();
  citp_exit_lib(&citp_lib_context_across_fork, 0);
  pthread_mutex_unlock(&citp_dup_lock);
}

/* Should be called in child branch after vfork syscall */
void** citp_netif_child_vfork_hook(void)
{
  Log_CALL(ci_log("%s()", __func__));
  oo_per_thread_get()->in_vfork_child = 1;
  return oo_per_thread_get()->vfork_scratch;
}

/* Should be called in parent branch after vfork syscall */
void** citp_netif_parent_vfork_hook(void)
{
  Log_CALL(ci_log("%s()", __func__));
  oo_per_thread_get()->in_vfork_child = 0;
  return oo_per_thread_get()->vfork_scratch;
}

/* Handles user-level netif internals pre bproc_move() */
void citp_netif_pre_bproc_move_hook(void)
{
  CITP_FDTABLE_LOCK();

  /* Remove any user-level destruct protection from the active netifs,
   * also remove the reference given to each netif if netif
   * destruction has been disabled (EF_NETIF_DTOR=0).  We want no open
   * endpoints, sockets or references to EtherFabric devices at the
   * time of the bproc_move().
   */
  __citp_netif_unprotect_all();
  
  CITP_FDTABLE_UNLOCK();
}


/* Checks that the stack config is sane, given the process config.
 *
 * Stack only config should already be checked in ci_netif_sanity_checks()
 * on stack creation.
 */
static void ci_netif_check_process_config(ci_netif* ni)
{
#if CI_CFG_FD_CACHING
  if( ni->state->opts.sock_cache_max > 0 ) {
    if( citp_fdtable_not_mt_safe() ) {
      NI_LOG(ni, CONFIG_WARNINGS, "Socket caching is not supported when "
                                  "EF_FDS_MT_SAFE=0, and has been disabled");
      citp_netif_cache_disable();
    }
    else if( CITP_OPTS.ul_epoll != 3 )
      NI_LOG(ni, CONFIG_WARNINGS, "Sockets that are added to an epoll set can "
                                  "only be cached if EF_UL_EPOLL=3");
  }
  if( (NI_OPTS(ni).scalable_filter_enable) &&
      (CITP_OPTS.ul_epoll != 1) && (CITP_OPTS.ul_epoll != 3) ) {
    NI_LOG(ni, CONFIG_WARNINGS, "When using a scalable filters mode handover "
                                "of TCP sockets in an epoll set is only "
                                "supported if EF_UL_EPOLL=1 or 3.");
  }
#endif
  if( NI_OPTS(ni).scalable_filter_enable && CITP_OPTS.stack_per_thread ) {
    NI_LOG(ni, CONFIG_WARNINGS, "EF_STACK_PER_THREAD=1 cannot be used in "
                                "scalable filters mode as a single filter "
                                "configuration can only be used by one stack.");
  }
  if( NI_OPTS(ni).shared_rxq_num > 15) {
    NI_LOG(ni, CONFIG_WARNINGS, "EF_SHARED_RXQ_NUM is outside expected range. "
                                "Sockets may be handed over if EF_NO_FAIL=0 "
                                "is not set.");
  }
}


/* Platform specific code, called after netif construction */
void  citp_netif_ctor_hook(ci_netif* ni, int realloc)
{

  if (!realloc)
    /* Protect the netif's FD table entry */
    __citp_fdtable_reserve(ci_netif_get_driver_handle(ni), 1);

  ci_netif_check_process_config(ni);
}


/* Platform specific code, called proir to netif destruction */
void  citp_netif_free_hook(ci_netif* ni)
{
#if CI_CFG_FD_CACHING
  citp_uncache_fds_ul(ni);
#endif
  /* Unprotect the netif's FD table entry */
  __citp_fdtable_reserve(ci_netif_get_driver_handle(ni), 0);
}

/*! \cidoxg_end */
