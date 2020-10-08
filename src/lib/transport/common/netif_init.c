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

#include <ci/internal/ip.h>
#include <ci/internal/transport_config_opt.h>
#include <ci/internal/transport_common.h>
#include <ci/internal/banner.h>

/* This breaks the "common" code separation by including stuff from
 * unix directly with no windows equivalent implemented */
#include <onload/ul/stackname.h>

#include <onload/ul/tcp_helper.h>
#include <onload/ul.h>
#include <onload/version.h>

#include <../unix/internal.h>

#define LPF "citp_netif_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF


#define VERB(x)

/*
 * Support for n netif per lib. 
 * 
 * There is one pool of netifs - "general" (each call to socket()
 * results in an allocation from this pool)
 *
 * Netifs from the pool are constructed on demand.  A netif from the
 * general pool is allocated each time citp_netif_alloc_and_init() is
 * called.  Currently there's 1 netif in this pool.  The general pool
 * is the one that's checked for logging etc.
 */

/* ***************************
 * Local vars
 */

/* All known netifs  */
static ci_dllist citp_active_netifs;

/* set after first call to citp_netif_startup */
static int citp_netifs_inited=0;

/* The netif destructor mode of operation */
static unsigned citp_netif_dtor_mode = CITP_NETIF_DTOR_ONLY_SHARED;


/* ***************************
 *  Local Functions
 */

ci_inline void __citp_add_netif( ci_netif* ni )
{
  /* Requires that the FD table write lock has been taken */
  ci_dllink* prev = &citp_active_netifs.l;
  ci_dllink* next;

  ci_assert( ni );
  CI_MAGIC_CHECK(ni, NETIF_MAGIC);
  ci_assert( citp_netifs_inited );
  CITP_FDTABLE_ASSERT_LOCKED(1);

  /* Add to the list of active netifs; keep the list sorted.
   *
   * It is needed when we want to lock all the stacks at exit.
   * Ordering allows to avoid deadlock.
   */
  CI_DLLIST_FOR_EACH(next, &citp_active_netifs ) {
    ci_netif* ni_next = CI_CONTAINER(ci_netif, link, next);
    if( NI_ID(ni_next) > NI_ID(ni) )
      break;
    prev = next;
  }
  ci_dllist_insert_after(prev, &ni->link);
}

ci_inline void __citp_remove_netif(ci_netif* ni)
{
  /* Requires that the FD table write lock has been taken */

  ci_assert( ni );
  CI_MAGIC_CHECK(ni, NETIF_MAGIC);
  ci_assert( citp_netifs_inited );
  CITP_FDTABLE_ASSERT_LOCKED(1);
  ci_assert( ci_dllist_not_empty(&citp_active_netifs) );

  /* Remove from the list of active netifs */
  ci_dllist_remove(&ni->link);
}


static int __citp_netif_alloc(ef_driver_handle* fd, const char *name,
                              int flags,
                              ci_netif** out_ni)
{
  int rc;
  ci_netif* ni;
  int realloc = 0;

  CITP_FDTABLE_ASSERT_LOCKED(1);

  /* Allocate netif from the heap */
  ni = CI_ALLOC_OBJ(ci_netif);
  if( !ni ) {
    Log_E(ci_log("%s: OS failure (memory low!)", __FUNCTION__ ));
    rc = -ENOMEM;
    goto fail1;
  }
  oo_atomic_set(&ni->ref_count, 0);

  rc = ef_onload_driver_open(fd, OO_STACK_DEV, 1);
  if( rc < 0 ) {
    Log_E(ci_log("%s: failed to open driver (%d)", __FUNCTION__, -rc));
    goto fail2;
  }

  while( 1 ) {
    if( name[0] != '\0' ) {
      rc = ci_netif_restore_name(ni, name);
      if( rc == 0 ) {
        ef_onload_driver_close(*fd);
        break;
      }
      else if( rc == -EACCES)
        goto fail3;
    }

    rc = ci_netif_ctor(ni, *fd, name, flags);
    if( rc == 0 ) {
      break;
    }
    else if( rc != -EEXIST ) {
      Log_E(ci_log("%s: failed to construct netif (%d)", __FUNCTION__, -rc));
      goto fail3;
    }
    /* Stack with given name exists -- try again to restore. */
  }

  __citp_add_netif(ni);

  /* Call the platform specifc netif ctor hook */
  citp_netif_ctor_hook(ni, realloc);

  *out_ni = ni;
  *fd = ci_netif_get_driver_handle(ni);	/* UNIX may change FD in
					   citp_netif_ctor_hook() */
  return 0;

 fail3:
  ef_onload_driver_close(*fd);
 fail2:
  CI_FREE_OBJ(ni);
 fail1:
  errno = -rc;

  return rc;
}

static void oo_exit_hook__on_exit(int status, void* arg)
{
  oo_exit_hook();
}

/* ***************************
 * Interface
 */

int citp_netif_by_id(ci_uint32 stack_id, ci_netif** out_ni, int locked)
{
  ci_netif *ni;
  int rc;


  ni = citp_find_ul_netif(stack_id, locked);
  if( ni != NULL ) {
    citp_netif_add_ref(ni);
    *out_ni = ni;
    return 0;
  }

  ni = CI_ALLOC_OBJ(ci_netif);
  if( ni == NULL ) {
    return -ENOMEM;
  }

  if( ! locked )
    CITP_FDTABLE_LOCK();
  rc = ci_netif_restore_id(ni, stack_id, false);
  if( rc < 0 ) {
    if( ! locked )
      CITP_FDTABLE_UNLOCK();
    CI_FREE_OBJ(ni);
    return rc;
  }
  __citp_add_netif(ni);
  ni->flags |= CI_NETIF_FLAGS_SHARED;
  citp_netif_init_ref(ni);
  citp_netif_ctor_hook(ni, 0);

  if( ! locked )
    CITP_FDTABLE_UNLOCK();

  ci_netif_log_startup_banner(ni, "Importing");

  *out_ni = ni;
  return 0;
}

/* Check the active netifs to look for one with
 * a matching ID
 * \param id          ID to look for (as returned by NI_ID())
 * \param fdt_locked  0 if the fd table lock is NOT held
 *                    or != 0 if the fd table lock IS held.
 * \return     ptr to UL netif or NULL if not found
 */
ci_netif* citp_find_ul_netif( int id, int locked )
{
  ci_netif* ni;

  ci_assert( citp_netifs_inited );

  /* Although we're not modifying the fdtable we take the write lock here.
   * This is because we want this to be usable on paths that are trying to
   * clear the busy status of an fd.  The existence of any busy waiters will
   * prevent the read lock from being taken, but we are still able to take
   * the write lock.
   */
  if( !locked )
    CITP_FDTABLE_LOCK();
    
  CI_DLLIST_FOR_EACH2( ci_netif, ni, link, &citp_active_netifs )
    if( NI_ID(ni) == id )
      goto exit_find;

  ni = NULL;

 exit_find:
  if( !locked )
    CITP_FDTABLE_UNLOCK();
  return ni;
}


void citp_cmn_netif_init_ctor(unsigned netif_dtor_mode)
{
  Log_S(ci_log("%s()", __FUNCTION__));

  if( citp_netifs_inited ) {
    Log_U(ci_log("%s: citp_netifs_inited = %d", 
		 __FUNCTION__, citp_netifs_inited));
  }

  citp_netifs_inited=1;
  
  /* Remember configuration parameters */
  citp_netif_dtor_mode = netif_dtor_mode;

  /* no asserts about signal state yet - do not call CITP_FDTABLE_LOCK */
  __CITP_LOCK(&citp_ul_lock);

  /* Initialise the active netif list */
  ci_dllist_init(&citp_active_netifs);

  __CITP_UNLOCK(&citp_ul_lock);

  /* Install the exit hook */
  /* It is recommended to use atexit(), but linker complains, because
   * atexit() resides in ld-linux.so instead of libc.so.  We can play games
   * with linker script and libc_nonshared.a, or use on_exit(). */
  on_exit(oo_exit_hook__on_exit, NULL);
}


static int /*bool*/
citp_netif_use_scalable_clustered_stack(const char* stackname)
{
  return
    ci_cfg_opts.netif_opts.scalable_filter_enable ==
      CITP_SCALABLE_FILTERS_ENABLE &&
    (ci_cfg_opts.netif_opts.scalable_filter_mode & CITP_SCALABLE_MODE_RSS) &&
    stackname[0] == '\0' && ci_cfg_opts.netif_opts.cluster_ignore != 1;
}


int citp_netif_get_process_stack(ci_netif** out_ni, const char* stackname)
{
  /* Look through the active netifs for a stack with a name that
   * matches.  If it has no name, ignore it if DONT_USE_ANON netif
   * flag is set
   */
  if( ci_dllist_not_empty(&citp_active_netifs) ) {
    CI_DLLIST_FOR_EACH2(ci_netif, *out_ni, link, &citp_active_netifs)
      if( ! citp_netif_use_scalable_clustered_stack(stackname) ) {
        if( strncmp((*out_ni)->state->name, stackname,
                    CI_CFG_STACK_NAME_LEN) == 0 )
          if( strlen((*out_ni)->state->name) != 0 ||
              ((*out_ni)->flags & CI_NETIF_FLAGS_DONT_USE_ANON) == 0 )
            return 0;
      }
      else if( (*out_ni)->state->flags & CI_NETIF_FLAG_SCALABLE_FILTERS_RSS &&
               (*out_ni)->state->pid == getpid() ) {
        /* We pick the stack that is marked with the above flag.
         * A process is expected to have access only to one of these. */
        return 0;
     }
  }

  return -ENOENT;
}


/* Common netif initialiser.  
 * \param IN fd file descriptor
 * \param OUT netif constructed
 * \return 0 - ok else -1 & errno set
 */
int citp_netif_alloc_and_init(ef_driver_handle* fd, ci_netif** out_ni)
{
  ci_netif* ni = NULL;
  char* stackname;
  int rc;

  ci_assert( citp_netifs_inited );
  ci_assert( fd );
  ci_assert( out_ni );

  CITP_FDTABLE_LOCK();

  /* Ensure that the onload_fd is created for close trampolining. */
  if( citp.onload_fd < 0 )
    __oo_service_fd(true);

  oo_stackname_get(&stackname);
  if( stackname == NULL ) {
    /* This implies EF_DONT_ACCELERATE is set */
    CITP_FDTABLE_UNLOCK();
    return CI_SOCKET_HANDOVER;
  }

  rc = citp_netif_get_process_stack(&ni, stackname);
  if( rc == -ENOENT ) {
    /* Allocate a new netif */
    int flags = citp_netif_use_scalable_clustered_stack(stackname) ?
                CI_NETIF_FLAG_DO_ALLOCATE_SCALABLE_FILTERS_RSS : 0;
    rc = __citp_netif_alloc(fd, stackname, flags, &ni);
    if( rc < 0 ) {
      Log_E(ci_log("%s: failed to create netif (%d)", __FUNCTION__, -rc));
      goto fail;
    } 

    /* If we shouldn't destruct private netifs at user-level add an extra
    ** 'destruct protect' reference to prevent it happening.
    */
    if( citp_netif_dtor_mode == CITP_NETIF_DTOR_ONLY_SHARED ) {
      citp_netif_add_ref(ni);
      ni->flags |= CI_NETIF_FLAGS_DTOR_PROTECTED;
    }
    else if( citp_netif_dtor_mode == CITP_NETIF_DTOR_NONE )
      citp_netif_add_ref(ni);

    VERB(ci_log("%s: constructed NI %d", __FUNCTION__, NI_ID(ni)));
  }
  else {
    ci_assert_equal(rc, 0);
    ci_assert(ni);
  }

  /* We wouldn't be recreating this unless we had an endpoint to attach.
  ** We add the reference for the endpoint here to prevent a race
  ** condition with short-lived endpoints.
  */
  citp_netif_add_ref(ni);
  CITP_FDTABLE_UNLOCK();
  CI_MAGIC_CHECK(ni, NETIF_MAGIC);
  *out_ni = ni;
  return 0;
  
 fail:
  CITP_FDTABLE_UNLOCK();
  errno = -rc;

  return rc;
}


/* Recreate a netif for a 'probed' user-level endpoint, must already hold
** the writer lock to the FD table. caller_fd is the fd of the ep that is
** associated with the netif to be recreated.
*/
int citp_netif_recreate_probed(ci_fd_t ul_sock_fd, 
                               ef_driver_handle* ni_fd_out,
                               ci_netif** ni_out)
{
  int rc;
  ci_netif* ni;
  ci_uint32 map_size;

  ci_assert( citp_netifs_inited );
  ci_assert( ni_fd_out );
  ci_assert( ni_out );
  CITP_FDTABLE_ASSERT_LOCKED(1);

  /* Allocate netif from the heap */
  ni = CI_ALLOC_OBJ(ci_netif);
  if( !ni ) {		
    Log_E(ci_log("%s: OS failure (memory low!)", __FUNCTION__ ));
    rc = -ENOMEM;
    goto fail1;
  }

  CI_ZERO(ni);  /* bc: need to zero-out the UL netif */
  
  /* Create a new file descriptor that maps to the netif. */
  rc = ci_tcp_helper_stack_attach(ul_sock_fd, &ni->nic_set, &map_size);
  if( rc < 0 ) {
    Log_E(ci_log("%s: FAILED: ci_tcp_helper_stack_attach %d", __FUNCTION__, rc));
    goto fail2;
  }

  if( rc < CITP_OPTS.fd_base )
    ef_onload_handle_move_and_do_cloexec(&rc, 1);

  /* Restore the netif mmaps and user-level state */
  CI_TRY_RET(ci_netif_restore(ni, (ci_fd_t)rc, map_size));

  CI_MAGIC_CHECK(ni, NETIF_MAGIC);

  /* Remember the netif */
  __citp_add_netif( ni );

  /* Setup flags, restored netifs are definitely shared with another
  ** process.  If they weren't shared they wouldn't exist to be restored.
  */
  ni->flags |= CI_NETIF_FLAGS_SHARED;

  /* We wouldn't be recreating this unless we had an endpoint to attach.
  ** We add the reference for the endpoint here to prevent a race
  ** condition.
  */
  citp_netif_init_ref(ni);

  /* If we shouldn't destruct netifs at user-level add an extra 'destruct
  ** protect' reference to prevent it ever happening.
  **
  ** Since we're never deleting any netifs in this case we avoid setting
  ** the CI_NETIF_FLAGS_DTOR_PROTECTED flag.
  */
  if( citp_netif_dtor_mode == CITP_NETIF_DTOR_NONE )
    citp_netif_add_ref(ni);

  /* Call the platform specifc netif ctor hook */
  citp_netif_ctor_hook(ni, 0);

  *ni_out = ni;
  *ni_fd_out = ci_netif_get_driver_handle(ni); /* UNIX may change FD in
						  citp_netif_ctor_hook() */
  return 0;

 fail2:
  CI_FREE_OBJ(ni);
 fail1:
  return rc;
}


/* Returns any active netif (used when all you need is a netif to
** do a resource operation or similar)
*/
ci_netif* __citp_get_any_netif(void)
{
  ci_netif* ni = 0;
  
  CITP_FDTABLE_ASSERT_LOCKED(1);
  
  if( ci_dllist_not_empty(&citp_active_netifs) )
    ni = CI_CONTAINER(ci_netif, link, ci_dllist_start(&citp_active_netifs));

  return ni;
}


#if CI_CFG_FD_CACHING

void citp_netif_cache_disable(void)
{
  ci_netif* ni;
  /* Disable caching on every netif. */
  if( ci_dllist_not_empty(&citp_active_netifs) )
    CI_DLLIST_FOR_EACH2(ci_netif, ni, link, &citp_active_netifs) {
      ci_netif_lock(ni);
      ci_assert_le(ni->state->passive_cache_avail_stack,
                   ni->state->opts.sock_cache_max);
      if( ni->state->passive_cache_avail_stack !=
          ni->state->opts.sock_cache_max ) {
        /* ioctl to drop the cache lists. */
        int rc = ci_tcp_helper_clear_epcache(ni);
        /* Silence unused-but-set warning for NDEBUG builds. */
        (void)rc;
        ci_assert_equal(rc, 0);
      }
      ni->state->passive_cache_avail_stack = 0;
      ci_netif_unlock(ni);
    }
}


void citp_netif_cache_warn_on_fork(void)
{
  ci_netif* ni;

  /* Disable caching on every netif. */
  if( ci_dllist_not_empty(&citp_active_netifs) )
    CI_DLLIST_FOR_EACH2(ci_netif, ni, link, &citp_active_netifs) {
      if( ni->state->opts.sock_cache_max > 0 &&
          ~ni->state->flags & CI_NETIF_FLAG_SOCKCACHE_FORKED ) {
        ci_atomic32_or(&ni->state->flags, CI_NETIF_FLAG_SOCKCACHE_FORKED);
        NI_LOG(ni, CONFIG_WARNINGS,
               "WARNING: Socket caching is not supported after fork().");
      }
    }
}
#endif /* CI_CFG_FD_CACHING */


int citp_get_active_netifs(ci_netif **array, int array_size)
{
  ci_netif* ni = 0;
  int n = 0;
  CITP_FDTABLE_ASSERT_LOCKED_RD;
  
  if( ci_dllist_not_empty(&citp_active_netifs) ) {
    CI_DLLIST_FOR_EACH2(ci_netif, ni, link, &citp_active_netifs) {
      if (n >= array_size) {
        ci_log("***%s: cannot return all active netifs! Array too small.",
               __FUNCTION__);
        break;
      }
      citp_netif_add_ref(ni);
      array[n] = ni;
      n++;
    }
  }

  return n;
}

int citp_netif_exists(void)
{
    ci_assert( citp_netifs_inited );

    return ci_dllist_not_empty(&citp_active_netifs);
}


/* Mark all active netifs as shared */
void __citp_netif_mark_all_shared(void)
{
  ci_netif* ni;
  ci_netif* next_ni;

  CITP_FDTABLE_ASSERT_LOCKED(1);

  /* Remove any 'destruct protect' references, if we are in
  ** CITP_NETIF_DTOR_NONE mode the CI_NETIF_FLAGS_DTOR_PROTECTED
  ** flag isn't set if the first place, so this will still work as
  ** intended.
  */
  CI_DLLIST_FOR_EACH3(ci_netif, ni, link, &citp_active_netifs, next_ni) {
    if( ni->flags & CI_NETIF_FLAGS_DTOR_PROTECTED ) {
      ni->flags &= ~CI_NETIF_FLAGS_DTOR_PROTECTED;
      citp_netif_release_ref(ni, 1);
    }
  }

  /* Set shared flag on any netifs that haven't destructed above */
  CI_DLLIST_FOR_EACH2(ci_netif, ni, link, &citp_active_netifs)
    ni->flags |= CI_NETIF_FLAGS_SHARED;
}


/* Mark all netifs as "don't use for new sockets unless compelled to
 * do so by the stack name configuration 
 */
void __citp_netif_mark_all_dont_use(void)
{
  ci_netif* ni;

  CITP_FDTABLE_ASSERT_LOCKED(1);

  CI_DLLIST_FOR_EACH2(ci_netif, ni, link, &citp_active_netifs)
    ni->flags |= CI_NETIF_FLAGS_DONT_USE_ANON;
}


/* Unprotect all netifs, allowing them to disappear when they have no sockets.
 */
void __citp_netif_unprotect_all(void)
{
  ci_netif* ni;
  ci_netif* next_ni;

  CITP_FDTABLE_ASSERT_LOCKED(1);

  CI_DLLIST_FOR_EACH3(ci_netif, ni, link, &citp_active_netifs, next_ni) {
    if( ni->flags & CI_NETIF_FLAGS_DTOR_PROTECTED ) {
      ni->flags &= ~CI_NETIF_FLAGS_DTOR_PROTECTED;
      citp_netif_release_ref(ni, 1);
    }
    if( citp_netif_dtor_mode == CITP_NETIF_DTOR_NONE )
      citp_netif_release_ref(ni, 1);
  }
}


void __citp_netif_ref_count_zero( ci_netif* ni, int locked )
{
  ci_assert( ni );
  CI_MAGIC_CHECK(ni, NETIF_MAGIC);
  ci_assert( oo_atomic_read(&ni->ref_count) == 0 );

  Log_V(ci_log("%s: Last ref removed from NI %d (fd:%d ni:%p driver)",
               __FUNCTION__, NI_ID(ni), ci_netif_get_driver_handle(ni), ni));

  if( !locked )
    CITP_FDTABLE_LOCK();

  CITP_FDTABLE_ASSERT_LOCKED(1);

  /* Forget about the netif */
  __citp_remove_netif(ni);

  __citp_netif_free(ni);

  if( !locked )
    CITP_FDTABLE_UNLOCK();
}


/* Free and destruct a netif
**
** Requires that the FD table write lock has been taken
*/
void __citp_netif_free(ci_netif* ni)
{
  ef_driver_handle fd;
  
  ci_assert( ni );
  CI_MAGIC_CHECK(ni, NETIF_MAGIC);
  ci_assert( oo_atomic_read(&ni->ref_count) == 0 );
  CITP_FDTABLE_ASSERT_LOCKED(1);

  Log_V(ci_log("%s: Freeing NI %d (fd:%d ni:%p)", __FUNCTION__,
               NI_ID(ni), ci_netif_get_driver_handle(ni), ni));

  /* Call the platform specifc netif free hook */
  citp_netif_free_hook(ni);

  /* Destruct the netif...
  **
  ** This will zap ci_netif_get_driver_handle(ni) so we remember it
  ** first, it also needs ci_netif_get_driver_handle(ni) to be valid
  ** and still open so we can't close it first
  */
  fd = ci_netif_get_driver_handle(ni);
  ci_netif_dtor(ni);

  /* Close the netif's FD */
  ef_onload_driver_close(fd);

  /* ...and free it */
  CI_FREE_OBJ(ni);
}


#if CI_CFG_FD_CACHING
void uncache_active_netifs(void)
{
  ci_netif* ni;
  citp_lib_context_t lib_context;
  citp_enter_lib(&lib_context);

  Log_V(ci_log("%s:", __FUNCTION__));
  CITP_FDTABLE_LOCK_RD();
  CITP_FDTABLE_ASSERT_LOCKED(1);
  // citp_netif_cache_disable();
  /* Disable caching on every netif. */
  if( ci_dllist_not_empty(&citp_active_netifs) ) {
    CI_DLLIST_FOR_EACH2(ci_netif, ni, link, &citp_active_netifs) {
      citp_uncache_fds_ul(ni);
    }
  }
  CITP_FDTABLE_UNLOCK_RD();
  citp_exit_lib(&lib_context, 1);
}
#endif


void oo_exit_hook(void)
{
  citp_lib_context_t lib_context;

  Log_CALL(ci_log("%s()", __func__));

  if( ci_dllist_is_empty(&citp_active_netifs) )
    return;

  citp_enter_lib(&lib_context);
  CITP_FDTABLE_LOCK();

  /* Lock all the stacks of this process. */

  CITP_FDTABLE_UNLOCK();
  citp_exit_lib(&lib_context, 1);
}

