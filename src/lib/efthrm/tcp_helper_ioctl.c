/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2008/02/20
** Description: Implementation of "ops" invoked by user-level.
** </L5_PRIVATE>
\**************************************************************************/

#include <ci/internal/transport_config_opt.h>
#include <onload/linux_onload_internal.h>
#include <onload/linux_onload.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/oof_onload.h>
#include <onload/oof_interface.h>
#include <onload/cplane_ops.h>
#include <onload/version.h>
#include <onload/dshm.h>
#include <onload/nic.h>
#include "onload_kernel_compat.h"
#include <onload/cplane_driver.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/efrm_client.h>
#include "oof_impl.h"
#include "tcp_helper_resource.h"
#include "tcp_helper_stats_dump.h"

#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
#include <linux/bpf.h>
#endif

int
efab_ioctl_get_ep(ci_private_t* priv, oo_sp sockp,
                  tcp_helper_endpoint_t** ep_out)
{
  ci_assert(ep_out != NULL);
  if( priv->thr == NULL || ! IS_VALID_SOCK_P(&priv->thr->netif, sockp) )
    return -EINVAL;
  *ep_out = ci_trs_ep_get(priv->thr, sockp);
  ci_assert(*ep_out != NULL);
  return 0;
}


static int
oo_priv_set_stack(ci_private_t* priv, tcp_helper_resource_t* trs)
{
  ci_uintptr_t* p = (ci_uintptr_t*) &priv->thr;
  ci_uintptr_t old, new = (ci_uintptr_t) trs;

  do {
    if( (old = *p) != 0 ) {
      LOG_E(ci_log("%s: ERROR: stack already attached", __FUNCTION__));
      return -EINVAL;
    }
  } while( ci_cas_uintptr_fail(p, old, new) );

  return 0;
}


static int
oo_priv_lookup_and_attach_stack(ci_private_t* priv, const char* name,
                                unsigned id, bool is_service)
{
  tcp_helper_resource_t* trs;
  int rc;
  enum oo_thr_ref_type ref_type = is_service ? OO_THR_REF_FILE : OO_THR_REF_APP;

  if( (rc = efab_thr_table_lookup(name, current->nsproxy->net_ns, id,
                                  EFAB_THR_TABLE_LOOKUP_CHECK_USER,
                                  ref_type, &trs)) == 0 ) {
    if( (rc = oo_priv_set_stack(priv, trs)) == 0 ) {
      priv->fd_flags = OO_FDFLAG_STACK |
                       (is_service ? OO_FDFLAG_SERVICE : 0);
      priv->sock_id = OO_SP_NULL;
    }
    else {
      oo_thr_ref_drop(trs->ref, ref_type);
    }
  }
  return rc;
}

static int
efab_tcp_helper_lookup_and_attach_stack(ci_private_t* priv, void *arg)
{
  oo_stack_lookup_and_attach_t* op = arg;
  return oo_priv_lookup_and_attach_stack(priv, NULL,
                                         op->stack_id, op->is_service);
}

static int
efab_tcp_helper_stack_attach(ci_private_t* priv, void *arg)
{
  oo_stack_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  int rc;

  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }
  OO_DEBUG_TCPH(ci_log("%s: [%d]", __FUNCTION__, NI_ID(&trs->netif)));

  rc = oo_create_stack_fd(trs, op->is_service ? OO_FDFLAG_SERVICE : 0);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("%s: oo_create_stack_fd failed (%d)",
                        __FUNCTION__, rc));
    return rc;
  }
  op->fd = rc;

  /* Re-read the OS socket buffer size settings.  This ensures we'll use
   * up-to-date values for this new socket.
   */
  efab_get_os_settings(trs);
  op->out_nic_set = trs->netif.nic_set;
  op->out_map_size = trs->mem_mmap_bytes;
  return 0;
}


static int
efab_tcp_helper_sock_attach_setup_flags(int* sock_type_in_out)
{
  int flags;

  BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
  flags = *sock_type_in_out & (SOCK_CLOEXEC | SOCK_NONBLOCK);
  *sock_type_in_out &= SOCK_TYPE_MASK;
  if( SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK) )
    flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

  return flags;
}


static int
efab_tcp_helper_sock_attach_common(tcp_helper_resource_t* trs,
                                   tcp_helper_endpoint_t* ep,
                                   ci_int32 sock_type, int fd_type, int flags)
{
  int rc;
  citp_waitable_obj *wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);
  (void) wo;

  /* Create a new file descriptor to attach the socket to. */
  rc = oo_create_ep_fd(ep, flags, fd_type);
  if( fd_type == -1 ) {
    /* FIXME: perhaps we should check flag compatibility ? */
  }
  else if( rc >= 0 ) {
    if( sock_type & SOCK_NONBLOCK )
      ci_bit_mask_set(&wo->waitable.sb_aflags, CI_SB_AFLAG_O_NONBLOCK);
    if( sock_type & SOCK_CLOEXEC )
      ci_bit_mask_set(&wo->waitable.sb_aflags, CI_SB_AFLAG_O_CLOEXEC);

    /* Re-read the OS socket buffer size settings.  This ensures we'll use
     * up-to-date values for this new socket.
     */
    efab_get_os_settings(trs);
  }
  else {
    CITP_STATS_NETIF_INC(&trs->netif, sock_attach_fd_alloc_fail);
  }

  return rc;
}

/* We always need an OS socket for UDP endpoints.
 * We don't want a backing socket for TCP endpoints in the next cases:
 * - sockets will be cached.
 * - sockets with local shared ports and IP_TRANSPARENT set, as we can't
 * tell that yet, unless we're in a stack configuration that doesn't
 * support IP_TRANSPARENT.
 *
 * We could always defer creation of OS sockets for TCP, as we have to
 * support that for the IP_TRANSPARENT case, but until this feature has
 * matured a bit we'll err on the side of caution and only use it where it
 * might actually be needed.
 * Note: in scalable active (non transparent mode) we always create OS backing
 * socket to reserve their own local ip/port
 */
static int /*bool*/
efab_tcp_helper_os_sock_is_needed(ci_netif* netif, oo_fd_flags fd_flags)
{
  if( ((NI_OPTS(netif).scalable_filter_enable !=
       CITP_SCALABLE_FILTERS_ENABLE)
#if CI_CFG_FD_CACHING
      && (NI_OPTS(netif).sock_cache_max == 0 )
#endif
      ) || (fd_flags & OO_FDFLAG_EP_UDP) )
    return 1;

  return 0;
}

/* This ioctl may be entered with or without the stack lock.  This has two
 * immediate implications:
 *  - it must not rely on the consistency of nor make atomically inconsistent
 *    modifications to the state protected by the stack lock; and
 *  - it must not block on the stack lock.
 * Trylocks are safe, however.  Also, the caller provides a guarantee that the
 * endpoint whose ep_id is passed in will not change under the ioctl's feet
 * and that the ioctl may modify it freely. */
static int
efab_tcp_helper_sock_attach(ci_private_t* priv, void *arg)
{
  oo_sock_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  citp_waitable_obj *wo;
  int rc;
  int flags;
  int sock_type = op->type;
  oo_fd_flags fd_flags;

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, op->ep_id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  /* Validate and find the endpoint. */
  if( ! IS_VALID_SOCK_P(&trs->netif, op->ep_id) )
    return -EINVAL;

  ep = ci_trs_get_valid_ep(trs, op->ep_id);
  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);

  ci_assert( (wo->waitable.state == CI_TCP_STATE_UDP) ||
             (wo->waitable.state & CI_TCP_STATE_TCP) );
  fd_flags = (wo->waitable.state & CI_TCP_STATE_TCP) ?
             OO_FDFLAG_EP_TCP : OO_FDFLAG_EP_UDP;

  ci_atomic32_and(&wo-> waitable.sb_aflags,
                  ~(CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ));
  wo->sock.domain = op->domain;

  flags = efab_tcp_helper_sock_attach_setup_flags(&sock_type);

  /* We always need an OS socket for UDP endpoints.
   * Creation of the OS socket may be deferred for all TCP cases.
   */
  if( efab_tcp_helper_os_sock_is_needed(&trs->netif, fd_flags) ) {
    rc = efab_create_os_socket(trs, ep, op->domain, sock_type, flags);
    if( rc < 0 ) {
      efab_tcp_helper_close_endpoint(trs, ep->id, 0);
      return rc;
    }
  }
  else {
#if CI_CFG_FD_CACHING
    /* There are ways that a cached socket may have had its fd closed.  If
     * that happens we come through this ioctl to get a new one, so update the
     * state to reflect that.
     */
    if( wo->waitable.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD ) {
      ci_assert_flags(wo->waitable.sb_aflags, CI_SB_AFLAG_IN_CACHE);
      ci_assert_flags(wo->waitable.state, CI_TCP_STATE_TCP);

      ci_atomic32_and(&wo->waitable.sb_aflags, ~CI_SB_AFLAG_CACHE_PRESERVE);
      wo->tcp.cached_on_fd = -1;
      wo->tcp.cached_on_pid = -1;
    }
#endif
  }

  rc = efab_tcp_helper_sock_attach_common(trs, ep, op->type, fd_flags, flags);
  /* File should have not existed */
  ci_assert_nequal(rc, -ENOANO);
  if( rc < 0 ) {
    efab_tcp_helper_close_endpoint(trs, ep->id, 0);
    return rc;
  }

  op->fd = rc;
  return 0;
}


#if CI_CFG_FD_CACHING
/* Endpoint must have IN_CACHE flag set to avoid side effects
 * (e.g. dropping endpoint).
 *
 * The detaching of the foreign FD can only work for FDs
 * that are coming out of endpoint cache (no user or onload stack references)
 * and is technically an orhpan.
 * The only concurrent operation expected is FD close when the process
 * owning the FD is about to die or dying.
 * In presence of IN_CACHE flag the concurrent generic_tcp_helper_close()
 * can perform only:
 *   {ep->file_ptr = NULL; ep->sb_aflags |= NO_FD}.
 * The following function performs effectively:
 *   {load file_ptr , load sb_aflags}
 * and needs to deal with the following three outcomes:
 *  * file_ptr == NULL and sb_aflags[NO_FD] == 1 - FD already freed
 *  * file_ptr == NULL and sb_aflags[NO_FD] == 0 - definitely in the
 *    middle of the generic_tcp_helper_close()
 *  * file_ptr == &foreign_file and sb_aflags[NO_FD] == 0 - file close not
 *    called yet at all or in deferred/in-progress depending on the outcome
 *    of get_file_rcu(file_ptr).
 *    And if close() has not been called yet detaching of the FD is performed.
 */
static int
efab_tcp_helper_detach_file(tcp_helper_endpoint_t* ep,
                            citp_waitable_obj *wo)
{
  /* in cache and with some fd, we only expect of different process here */
  /* could there be some races here */
  int pid = wo->tcp.cached_on_pid;
  int fd = wo->tcp.cached_on_fd;
  /* keep IN_CACHE flag while closing the foreign file */
  ci_private_t* priv = NULL;
  struct file* filp;
  int rc = 0;
  tcp_helper_resource_t* trs = ep->thr;

  ci_assert_flags(wo->waitable.sb_aflags, CI_SB_AFLAG_IN_CACHE);
  ci_assert_nflags(wo->waitable.sb_aflags, CI_SB_AFLAG_ORPHAN);

#ifdef EFRM_DO_NAMESPACES
  ci_assert_nequal(pid, task_pid_nr_ns(current, trs->pid_ns));
#endif
  ci_assert_ge(fd, 0);

  rcu_read_lock();
  /* Once again check NO_FD flag
   * We need to perform this check after taking rcu_read_lock
   * which prevents weakly referenced filp object from being freed */
  if( wo->waitable.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD ) {
    /* cleaned NO_FD flag means that the filp close operation finished
     * and EP can be reused */
    goto rcu_unlock;
  }
  filp = ep->file_ptr;
  /* filp might be NULL if we raced with FD close, other than that
   * filp is still valid even if close completed concurrently thanks to rcu_lock */
  if( filp == NULL || ! get_file_rcu(filp) ) {
    /* filp is being freed concurrently, best to back off until it is completed */
    OO_DEBUG_TCPH(ci_log("%s: pid=%d fd=%d => is being freed", __FUNCTION__, pid, fd));
    CITP_STATS_NETIF_INC(&trs->netif, sock_attach_fd_detach_fail_soft);
    rc = -EINVAL;
    goto rcu_unlock;
  }
  if( filp->f_op != &linux_tcp_helper_fops_tcp ) {
    LOG_E(ci_log("%s: pid=%d fd=%d => non TCP", __FUNCTION__, pid, fd));
    CITP_STATS_NETIF_INC(&trs->netif, sock_attach_fd_detach_fail_hard);
    rc = -EINVAL;
    goto file_put;
  }
  priv = (ci_private_t*) filp->private_data;
  if( priv == NULL ) {
    rc = -EINVAL;
    LOG_E(ci_log("%s: pid=%d fd=%d => no TCP priv", __FUNCTION__, pid, fd));
    CITP_STATS_NETIF_INC(&trs->netif, sock_attach_fd_detach_fail_hard);
    goto file_put;
  }
  if( ! (priv->fd_flags & OO_FDFLAG_EP_TCP) ) {
    rc = -EINVAL;
    LOG_E(ci_log("%s: pid=%d fd=%d => fd priv type not TCP: "OO_FDFLAG_FMT,
          __FUNCTION__, pid, fd, OO_FDFLAG_ARG(priv->fd_flags)));
    CITP_STATS_NETIF_INC(&trs->netif, sock_attach_fd_detach_fail_hard);
    goto file_put;
  }
  if( priv->thr != trs ) {
    rc = -EINVAL;
    LOG_E(ci_log("%s: [%d] file refers to stack %d",
                 __FUNCTION__, trs->id, priv->thr->id));
    CITP_STATS_NETIF_INC(&trs->netif, sock_attach_fd_detach_fail_hard);
    goto file_put;
  }
  if( priv->sock_id != ep->id ) {
    rc = -EINVAL;
    LOG_E(ci_log("%s: wrong ep expected %d:%d while file refers to %d",
          __FUNCTION__, trs->id, ep->id, priv->sock_id));
    CITP_STATS_NETIF_INC(&trs->netif, sock_attach_fd_detach_fail_hard);
    goto file_put;
  }

/* redirect foreign file to magic sock_id */
  {
    //ci_tcp_state* s = ci_tcp_get_state_buf(&trs->netif);
    priv->sock_id = -1; // s->s.b.bufid;
    ep->file_ptr = NULL;
    CITP_STATS_NETIF_INC(&trs->netif, sock_attach_fd_detach);
  }

 file_put:
  fput(filp);
 rcu_unlock:
  rcu_read_unlock();
  return rc;
}


static int
efab_tcp_helper_sock_detach_file(ci_private_t* priv, void *arg)
{
  oo_tcp_accept_sock_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  citp_waitable_obj *wo;
  int rc;

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, op->ep_id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  /* Validate and find the endpoint. */
  if( ! IS_VALID_SOCK_P(&trs->netif, op->ep_id) ) {
    LOG_E(ci_log("%s: invalid endp", __FUNCTION__));
    return -EINVAL;
  }

  ep = ci_trs_get_valid_ep(trs, op->ep_id);
  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);
  ci_assert_flags(wo->waitable.state, CI_TCP_STATE_TCP);
  ci_assert_nflags(wo->waitable.sb_aflags,
                   CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ);
  if( (~wo->waitable.state & CI_TCP_STATE_TCP) ||
      (wo->waitable.sb_aflags &
       (CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ)) )
    return -ENOTSUPP;

  rc = efab_tcp_helper_detach_file(ep, wo);
  if( rc == 0 ) {
    ci_atomic32_and(&wo->waitable.sb_aflags, ~CI_SB_AFLAG_IN_CACHE_NO_FD);
    wo->tcp.cached_on_fd = -1;
    wo->tcp.cached_on_pid = -1;
    op->fd = 0;
  }
  return rc;
}


static int
efab_tcp_helper_sock_attach_to_existing_file(ci_private_t* priv, void *arg)
{
  oo_tcp_accept_sock_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  citp_waitable_obj *wo;
  int rc;

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, op->ep_id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  /* Validate and find the endpoint. */
  if( ! IS_VALID_SOCK_P(&trs->netif, op->ep_id) ) {
    LOG_E(ci_log("%s: invalid endp", __FUNCTION__));
    return -EINVAL;
  }

  ep = ci_trs_get_valid_ep(trs, op->ep_id);
  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);

  /* expected on EP cache path (thus TCP) from ci_tcp_ep_ctor (no passive/orphan)*/
  ci_assert_flags(wo->waitable.state, CI_TCP_STATE_TCP);
  ci_assert_nflags(wo->waitable.sb_aflags,
                   CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ);
  if( (~wo->waitable.state & CI_TCP_STATE_TCP) ||
      (wo->waitable.sb_aflags &
       (CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ)) )
    return -ENOTSUPP;

  /* Fail if there is no existing file attached to this EP */
  if( ep->file_ptr == NULL )
    return -EINVAL;

  rc = efab_tcp_helper_sock_attach_common(trs, ep, 0,
                                          -1 /* clone only */, 0);
  if( rc < 0 )
    return rc;

  op->fd = rc;
  return 0;
}
#endif


static int
efab_tcp_helper_tcp_accept_sock_attach(ci_private_t* priv, void *arg)
{
  oo_tcp_accept_sock_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  citp_waitable_obj *wo;
  int rc;
  int flags;
  int sock_type = op->type;
  int aflags_saved;

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, op->ep_id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  /* Validate and find the endpoint. */
  if( ! IS_VALID_SOCK_P(&trs->netif, op->ep_id) ) {
    LOG_E(ci_log("%s: invalid endp", __FUNCTION__));
    return -EINVAL;
  }

  ep = ci_trs_get_valid_ep(trs, op->ep_id);
  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);
  ci_assert(wo->waitable.state & CI_TCP_STATE_TCP);

  aflags_saved = wo->waitable.sb_aflags &
                 (CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ);

  /* clear NONBLOCK/CLOEXEC flag as these will be set according to
   * sock_type in efab_tcp_helper_sock_attach_common() */
  ci_atomic32_and(&wo-> waitable.sb_aflags,
                  ~(CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ |
                    CI_SB_AFLAG_O_CLOEXEC | CI_SB_AFLAG_O_NONBLOCK));

  flags = efab_tcp_helper_sock_attach_setup_flags(&sock_type);
  rc = efab_tcp_helper_sock_attach_common(trs, ep, op->type,
                                          OO_FDFLAG_EP_TCP, flags);
  if( rc < 0 )
    goto on_error;

#if CI_CFG_FD_CACHING
  /* There are ways that a cached socket may have had its fd closed.  If
   * that happens we come through this ioctl to get a new one, so update the
   * state to reflect that.
   */
  if( wo->waitable.sb_aflags & (CI_SB_AFLAG_IN_CACHE_NO_FD |
                                CI_SB_AFLAG_IN_CACHE) ) {
    ci_assert_impl(wo->waitable.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD,
                   wo->waitable.sb_aflags & CI_SB_AFLAG_IN_CACHE);
    /* we clear the relevant flags apart from O_CLOEXEC and O_NONBLOCK as
     * they have been set as needed in efab_tcp_helper_sock_attach_common()
     * along with the FD's counterpart */
    ci_atomic32_and(&wo->waitable.sb_aflags, (~CI_SB_AFLAG_CACHE_PRESERVE) |
                                             CI_SB_AFLAG_O_CLOEXEC |
                                             CI_SB_AFLAG_O_NONBLOCK);
    wo->tcp.cached_on_fd = -1;
    wo->tcp.cached_on_pid = -1;
  }
#endif

  op->fd = rc;
  return 0;

 on_error:
  /* - accept() does not touch the ep - no need to clear it up;
   * - accept() needs the tcp state survive
   * Note: we can lose O_NONBLOCK and O_CLOEXEC - they will be reapplied on
   * another attempt.
   */
  ci_atomic32_or(&wo->waitable.sb_aflags, aflags_saved);
  return rc;
}


static int
efab_tcp_helper_pipe_attach(ci_private_t* priv, void *arg)
{
  oo_pipe_attach_t* op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  citp_waitable_obj *wo;
  int rc;

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, op->ep_id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  /* Validate and find the endpoint. */
  if( ! IS_VALID_SOCK_P(&trs->netif, op->ep_id) )
    return -EINVAL;
  ep = ci_trs_get_valid_ep(trs, op->ep_id);

  wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);
  ci_atomic32_and(&wo->waitable.sb_aflags,
                  ~(CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ));

  rc = oo_create_ep_fd(ep, op->flags, OO_FDFLAG_EP_PIPE_READ);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ERROR: failed to bind reader [%d:%d] to fd",
                 __func__, trs->id, ep->id));
    tcp_helper_endpoint_set_aflags(ep, OO_THR_EP_AFLAG_PEER_CLOSED);
    efab_tcp_helper_close_endpoint(trs, ep->id, 0);
    return rc;
  }
  op->rfd = rc;

  rc = oo_create_ep_fd(ep, op->flags, OO_FDFLAG_EP_PIPE_WRITE);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ERROR: failed to bind writer [%d:%d] to fd",
                 __func__, trs->id, ep->id));
    tcp_helper_endpoint_set_aflags(ep, OO_THR_EP_AFLAG_PEER_CLOSED);
    ci_close_fd(op->rfd);
    return rc;
  }
  op->wfd = rc;

  return 0;
}

/*--------------------------------------------------------------------
 *!
 * Entry point from user-mode when the TCP/IP stack requests
 * filtering of a TCP/UDP endpoint
 *
 * \param trs             tcp helper resource
 * \param op              structure filled in by application
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

static int
efab_ep_filter_set(ci_private_t *priv, void *arg)
{
  oo_tcp_filter_set_t *op = arg;
  tcp_helper_endpoint_t* ep;
  int rc = efab_ioctl_get_ep(priv, op->tcp_id, &ep);
  if (rc != 0)
    return rc;

  return tcp_helper_endpoint_set_filters(ep, op->bindto_ifindex,
                                         op->from_tcp_id);
}
static int
efab_ep_filter_clear(ci_private_t *priv, void *arg)
{
  oo_tcp_filter_clear_t *op = arg;
  tcp_helper_endpoint_t* ep;
  int rc = efab_ioctl_get_ep(priv, op->tcp_id, &ep);
  if (rc != 0)
    return rc;
  return tcp_helper_endpoint_clear_filters(
            ep, op->need_update ? EP_CLEAR_FILTERS_FLAG_NEED_UPDATE : 0);
}
static int
efab_ep_filter_mcast_add(ci_private_t *priv, void *arg)
{
  oo_tcp_filter_mcast_t *op = arg;
  tcp_helper_endpoint_t* ep;
  int rc = efab_ioctl_get_ep(priv, op->tcp_id, &ep);
  if( rc == 0 )
    rc = oof_socket_mcast_add(oo_filter_ns_to_manager(ep->thr->filter_ns),
                              &ep->oofilter, op->addr, op->ifindex);
  return rc;
}
static int
efab_ep_filter_mcast_del(ci_private_t *priv, void *arg)
{
  oo_tcp_filter_mcast_t *op = arg;
  tcp_helper_endpoint_t* ep;
  int rc = efab_ioctl_get_ep(priv, op->tcp_id, &ep);
  if( rc == 0 )
    oof_socket_mcast_del(oo_filter_ns_to_manager(ep->thr->filter_ns),
                         &ep->oofilter, op->addr, op->ifindex);
  return rc;
}
static int
efab_ep_filter_dump(ci_private_t *priv, void *arg)
{
  oo_tcp_filter_dump_t *op = arg;
  return tcp_helper_endpoint_filter_dump(priv->thr, op->sock_id,
                                         CI_USER_PTR_GET(op->buf),
                                         op->buf_len);
}

#if CI_CFG_ENDPOINT_MOVE
static int
efab_cluster_dump(ci_private_t *priv, void *arg)
{
  oo_cluster_dump_t *op = arg;
  return tcp_helper_cluster_dump(priv->thr, CI_USER_PTR_GET(op->buf),
                                 op->buf_len);
}
#endif


/*--------------------------------------------------------------------
 *!
 * Debug function to get information about netids in the driver
 *
 * \param info            copy of user structure
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

static int
efab_tcp_helper_get_info(ci_private_t *unused, void *arg)
{
  ci_netif_info_t *info = arg;
  int index, rc=0;
  tcp_helper_resource_t* thr = NULL;
  ci_netif* ni = NULL;
  int flags = EFAB_THR_TABLE_LOOKUP_CHECK_USER | EFAB_THR_TABLE_LOOKUP_NO_WARN; 

#if CI_CFG_EFAB_EPLOCK_RECORD_CONTENTIONS
  int j;
  eplock_resource_t* eplock_rs;
#endif

  info->ni_exists = 0;
  info->ni_no_perms_exists = 0;
  if( info->ni_orphan ) {
    flags |= EFAB_THR_TABLE_LOOKUP_NO_UL;
    info->ni_orphan = 0;
  }
  rc = efab_thr_table_lookup(NULL, NULL, info->ni_index, flags,
                             OO_THR_REF_BASE, &thr);
  if( rc == 0 ) {
    info->ni_exists = 1;
    info->ni_orphan = (thr->ref[OO_THR_REF_FILE] == 0);
    ni = &thr->netif;
    info->mmap_bytes = thr->mem_mmap_bytes;
    info->rs_ref_count = thr->ref[OO_THR_REF_APP];
    memcpy(info->ni_name, ni->state->name, sizeof(ni->state->name));
  } else if( rc == -EACCES ) {
    info->ni_no_perms_id = info->ni_index;
    if( efab_thr_get_inaccessible_stack_info(info->ni_index, 
                                             &info->ni_no_perms_uid,
                                             &info->ni_no_perms_euid,
                                             &info->ni_no_perms_share_with,
                                             info->ni_no_perms_name) == 0 )
      info->ni_no_perms_exists = 1;
  }

  /* sub-ops that do not need the netif to exist */
  if( info->ni_subop == CI_DBG_NETIF_INFO_GET_NEXT_NETIF ) {
    tcp_helper_resource_t* next_thr;

    info->u.ni_next_ni.index = -1;
    for( index = info->ni_index + 1;
         index < 10000 /* FIXME: magic! */;
         ++index ) {
      rc = efab_thr_table_lookup(NULL, NULL, index, flags, OO_THR_REF_BASE,
                                 &next_thr);
      if( rc == 0 ) {
        oo_thr_ref_drop(next_thr->ref, OO_THR_REF_BASE);
        info->u.ni_next_ni.index = index;
        break;
      }
      if( rc == -EACCES ) {
        info->u.ni_next_ni.index = index;
        break;
      }
    }
    rc = 0;
  }
  else if( info->ni_subop == CI_DBG_NETIF_INFO_NOOP ) {
    rc = 0;
  }

  if (!info->ni_exists)
    return 0;

  /* sub-ops that need the netif to exist */
  switch (info->ni_subop)
  {

    case CI_DBG_NETIF_INFO_GET_ENDPOINT_STATE:
      index = info->u.ni_endpoint.index;
      info->u.ni_endpoint.max = thr->netif.ep_tbl_n;
      if ((index < 0) || (index >= (int)thr->netif.ep_tbl_n)) {
        info->u.ni_endpoint.state = CI_TCP_STATE_FREE;
      }
      else {
        citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, index);

        info->u.ni_endpoint.state = wo->waitable.state;

        if( wo->waitable.state == CI_TCP_STATE_UDP ) {
          ci_udp_state* us = &wo->udp;
          info->u.ni_endpoint.udpstate = us->udpflags;
          info->u.ni_endpoint.rx_pkt_ul = us->recv_q.pkts_delivered;
          info->u.ni_endpoint.rx_pkt_kn = us->stats.n_rx_os;
        }
        else if( wo->waitable.state & CI_TCP_STATE_TCP_CONN ) {
          ci_tcp_state* ts = &wo->tcp;
          info->u.ni_endpoint.tx_pkts_max = ts->so_sndbuf_pkts;
          info->u.ni_endpoint.tx_pkts_num = ts->send.num;
        }
        if( CI_TCP_STATE_IS_SOCKET(wo->waitable.state) ) {
          ci_sock_cmn* s = &wo->sock;
          info->u.ni_endpoint.protocol = (int) sock_protocol(s);
          info->u.ni_endpoint.laddr = sock_laddr_be32(s);
          info->u.ni_endpoint.lport = (int) sock_lport_be16(s);
          info->u.ni_endpoint.raddr = sock_raddr_be32(s);
          info->u.ni_endpoint.rport = (int) sock_rport_be16(s);
        }
      }
      break;

    case CI_DBG_NETIF_INFO_GET_NEXT_NETIF:
      /* If the current netif is found, we need to succeed */
      break;

    case CI_DBG_NETIF_INFO_NOOP:
      /* Always succeeds, rc already set */
      break;

    default:
      rc = -EINVAL;
      break;
  }
  if( thr )
    oo_thr_ref_drop(thr->ref, OO_THR_REF_BASE);
  return rc;
}

static int
efab_tcp_helper_wait_stack_list_update(ci_private_t* priv, void *arg)
{
  struct oo_stacklist_update *param = arg;
  ci_waitq_waiter_t waiter;
  ci_waitq_timeout_t timeout = param->timeout;

  if( param->timeout != 0 ) {
    ci_waitq_waiter_pre(&waiter, &efab_tcp_driver.stack_list_wq);
    while( efab_tcp_driver.stack_list_seq == param->seq &&
           ! ci_waitq_waiter_signalled(&q, &efab_tcp_driver.stack_list_wq) ) {
      ci_waitq_waiter_timedwait(&waiter, &efab_tcp_driver.stack_list_wq,
                                0, &timeout);
    }
    ci_waitq_waiter_post(&waiter, &efab_tcp_driver.stack_list_wq);
  }
  param->seq = efab_tcp_driver.stack_list_seq;
  return 0;
}

static int
efab_tcp_helper_sock_sleep_rsop(ci_private_t* priv, void *op)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_sock_sleep(priv->thr, (oo_tcp_sock_sleep_t *)op);
}

static int
efab_tcp_helper_waitable_wake_rsop(ci_private_t* priv, void* arg)
{
  oo_waitable_wake_t* op = arg;
  if( priv->thr == NULL )
    return -EINVAL;
  tcp_helper_endpoint_wakeup(priv->thr,
                             ci_trs_get_valid_ep(priv->thr, op->sock_id));
  return 0;
}

/* This resource op must be called with the stack lock held.  This ensures
 * that we sync a consistent set of state to the OS socket when it is created.
 * All operations that can affect what we sync (setsockopt, ioctl, fcntl) are
 * protected by the stack lock so we know they won't change under our feet.
 */
static int
efab_tcp_helper_os_sock_create_and_set_rsop(ci_private_t* priv, void* arg)
{
  oo_tcp_create_set_t *op = arg;
  tcp_helper_resource_t* trs = priv->thr;
  tcp_helper_endpoint_t* ep = NULL;
  int rc;

  ci_assert(priv);
  ci_assert(op);

  if( ! (priv->fd_flags & OO_FDFLAG_EP_MASK) )
    return -EINVAL;

  ci_assert(priv->thr);
  ci_assert_flags(priv->fd_flags, OO_FDFLAG_EP_TCP);
  ep = efab_priv_to_ep(priv);

  OO_DEBUG_TCPH(ci_log("%s: ep_id=%d", __FUNCTION__, ep->id));
  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  rc = efab_tcp_helper_create_os_sock(priv);
  if( rc < 0 )
    return rc;

  /* If we've been given a socket option to sync, do it now */
  if( op->level >= 0 )
    rc = efab_tcp_helper_setsockopt(trs, ep->id, op->level, op->optname,
                                    CI_USER_PTR_GET(op->optval), op->optlen);

  return rc;
}
static int
tcp_helper_endpoint_shutdown_rsop(ci_private_t* priv, void *arg)
{
  oo_tcp_endpoint_shutdown_t *op = arg;
  return tcp_helper_endpoint_shutdown(priv->thr, op->sock_id,
                                      op->how, op->old_state);
}
static int
efab_tcp_helper_set_tcp_close_os_sock_rsop(ci_private_t* priv, void *arg)
{
  oo_sp *sock_id_p = arg;
  return efab_tcp_helper_set_tcp_close_os_sock(priv->thr, *sock_id_p);
}
static int
efab_tcp_helper_os_pollerr_clear(ci_private_t* priv, void *arg)
{
  oo_sp *sock_id_p = arg;
  tcp_helper_endpoint_t *ep = ci_trs_get_valid_ep(priv->thr, *sock_id_p);
  struct file *os_file;
  int rc = oo_os_sock_get_from_ep(ep, &os_file);

  if( rc != 0 )
    return 0;
  oo_os_sock_status_bit_clear_handled(ep, os_file, OO_OS_STATUS_ERR);
  oo_os_sock_put(os_file);
  return 0;
}

static int
efab_tcp_helper_sock_lock_slow_rsop(ci_private_t* priv, void *p_sock_id)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_sock_lock_slow(priv->thr, *(oo_sp *)p_sock_id);
}
static int
efab_tcp_helper_sock_unlock_slow_rsop(ci_private_t* priv, void *p_sock_id)
{
  if (priv->thr == NULL)
    return -EINVAL;
  efab_tcp_helper_sock_unlock_slow(priv->thr, *(oo_sp *)p_sock_id);
  return 0;
}
static int
efab_tcp_helper_pkt_wait_rsop(ci_private_t* priv, void *lock_flags)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_pkt_wait(priv->thr, (int *)lock_flags);
}
static int
efab_tcp_helper_more_bufs_rsop(ci_private_t* priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_more_bufs(priv->thr);
}
static int
efab_tcp_helper_more_socks_rsop(ci_private_t* priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_more_socks(priv->thr);
}
#if CI_CFG_FD_CACHING
static int
efab_tcp_helper_clear_epcache_rsop(ci_private_t* priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_clear_epcache(priv->thr);
}
#endif
#if ! CI_CFG_UL_INTERRUPT_HELPER
static int
efab_eplock_unlock_and_wake_rsop(ci_private_t *priv, void *unused)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_eplock_unlock_and_wake(&priv->thr->netif, 0);
}
#else
static int
efab_eplock_wake_and_do_rsop(ci_private_t *priv, void *arg)
{
  ci_uint64 l = *(ci_uint64*)arg;
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_eplock_wake_and_do(&priv->thr->netif, l);
}
#endif
static int
oo_efct_superbuf_config_refresh_rsop(ci_private_t *priv, void *op)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_efct_superbuf_config_refresh(priv->thr, op);
}

static int
oo_pkt_buf_map_rsop(ci_private_t* priv, void *arg)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_pkt_buf_map(priv->thr, arg);
}

static int
oo_design_parameters_rsop(ci_private_t* priv, void *arg)
{
  if (priv->thr == NULL)
    return -EINVAL;
  return efab_tcp_helper_design_parameters(priv->thr, arg);
}

static int
oo_eplock_lock_rsop(ci_private_t* priv, void* arg)
{
  long timeout_jiffies = MAX_SCHEDULE_TIMEOUT;
  bool has_timeout = false;
  ci_int32* timeout_ms_p = (ci_uint32*)arg;
  int rc;

  if (priv->thr == NULL)
    return -EINVAL;
  if(CI_UNLIKELY( *timeout_ms_p >= 0 )) {
    timeout_jiffies = msecs_to_jiffies(*timeout_ms_p);
    has_timeout = true;
  }

  rc = oo_eplock_lock(&priv->thr->netif, &timeout_jiffies, 0);

  if( has_timeout )
    *timeout_ms_p = jiffies_to_msecs(timeout_jiffies);
  return rc;
}

static int
efab_install_stack(ci_private_t *priv, void *arg)
{
  struct oo_op_install_stack* op = arg;
  op->in_name[CI_CFG_STACK_NAME_LEN] = '\0';
  return oo_priv_lookup_and_attach_stack(priv, op->in_name, -1, 0);
}
#if ! CI_CFG_UL_INTERRUPT_HELPER
static int
thr_priv_dump(ci_private_t *priv, void *unused)
{
  ci_log("OO_IOC_RSOP_DUMP:");
  THR_PRIV_DUMP(priv, "");
  ci_log("OO_IOC_RSOP_DUMP: done");
  return 0;
}
static int
oo_ioctl_debug_op(ci_private_t *priv, void *arg)
{
  ci_debug_onload_op_t *op = arg;
  int rc;

  if( !ci_is_sysadmin() )  return -EPERM;

  switch( op->what ) {
  case __CI_DEBUG_OP_KILL_STACK__:
    rc = tcp_helper_kill_stack_by_id(op->u.stack_id);
    break;
  case __CI_DEBUG_OP_DUMP_STACK__:
  case __CI_DEBUG_OP_NETSTAT_STACK__:
  case __CI_DEBUG_OP_NETIF_DUMP__:
  case __CI_DEBUG_OP_NETIF_DUMP_EXTRA__:
  case __CI_DEBUG_OP_DUMP_SOCKETS__:
  case __CI_DEBUG_OP_STACK_STATS__:
  case __CI_DEBUG_OP_STACK_MORE_STATS__:
  case __CI_DEBUG_OP_IP_STATS__:
  case __CI_DEBUG_OP_TCP_STATS__:
  case __CI_DEBUG_OP_TCP_EXT_STATS__:
  case __CI_DEBUG_OP_UDP_STATS__:
  case __CI_DEBUG_OP_NETIF_CONFIG_OPTS_DUMP__:
  case __CI_DEBUG_OP_STACK_TIME__:
  case __CI_DEBUG_OP_VI_INFO__:
    rc = tcp_helper_dump_stack(op->u.dump_stack.stack_id,
                               op->u.dump_stack.orphan_only,
                               CI_USER_PTR_GET(op->u.dump_stack.user_buf),
                               op->u.dump_stack.user_buf_len,
                               op->what);
    break;
  default:
    rc = -EINVAL;
    break;
  }
  return rc;
}
#endif
static int
ioctl_printk(ci_private_t *priv, void *arg)
{
  char *msg = arg;
  size_t  lvl_len = sizeof KERN_INFO - 1;
  memmove (msg+lvl_len, msg, CI_LOG_MAX_LINE-lvl_len);
  memmove (msg, KERN_INFO, lvl_len);
  msg[CI_LOG_MAX_LINE-1] = 0;
  printk("%s\n", msg);
  return 0;
}
static int
tcp_helper_alloc_rsop(ci_private_t *priv, void *arg)
{
  /* Using lock to serialize multiple processes trying to create
   * stacks with same name.
   */
static DEFINE_MUTEX(ctor_mutex);

  ci_resource_onload_alloc_t *alloc = arg;
  tcp_helper_resource_t* trs;
  int rc;

  mutex_lock(&ctor_mutex);
  rc = tcp_helper_alloc_ul(alloc, -1, &trs);
  if( rc == 0 ) {
    rc = oo_priv_set_stack(priv, trs);
    if( rc == 0 ) {
      priv->fd_flags = OO_FDFLAG_STACK;
      priv->sock_id = OO_SP_NULL;
    }
    else
      oo_thr_ref_drop(trs->ref, OO_THR_REF_APP);
  }
  mutex_unlock(&ctor_mutex);
  return rc;
}
static int
ioctl_ep_info(ci_private_t *priv, void *arg)
{
  ci_ep_info_t *ep_info = arg;
  ep_info->fd_flags = priv->fd_flags;
  if (priv->thr != NULL) {
    ep_info->resource_id = priv->thr->id;
    ep_info->sock_id = priv->sock_id;
    ep_info->mem_mmap_bytes = priv->thr->mem_mmap_bytes;
  } else
    ep_info->resource_id = CI_ID_POOL_ID_NONE;

  return 0;
}
static int
ioctl_vi_stats_query(ci_private_t *priv, void *arg)
{
  ci_vi_stats_query_t* vi_stats_query = (ci_vi_stats_query_t*) arg;
  void __user* user_data = CI_USER_PTR_GET(vi_stats_query->stats_data);
  void* data;
  int rc;
  size_t data_len = vi_stats_query->data_len;

  if( priv->thr == NULL)
    return -EINVAL;
  if( data_len > PAGE_SIZE )
    return -EINVAL;

  data = kmalloc(data_len, GFP_KERNEL);
  if( data == NULL )
    return -ENOMEM;

  rc = efab_tcp_helper_vi_stats_query(priv->thr, vi_stats_query->intf_i, data,
                                      data_len, vi_stats_query->do_reset);
  if( rc == 0 ) {
    if( copy_to_user(user_data, data, data_len) )
      rc = -EFAULT;
  }
  kfree(data);
  return rc;
}
static int
ioctl_clone_fd(ci_private_t *priv, void *arg)
{
  ci_clone_fd_t *op = arg;
  op->fd = oo_clone_fd (priv->_filp, op->do_cloexec);
  if (op->fd < 0) {
    ci_log("clone fd ioctl: get_unused_fd() failed, errno=%d",
           -(int)(op->fd)); 
    return op->fd;
  }
  return 0;
}
static int
ioctl_kill_self(ci_private_t *priv, void *unused)
{
  return send_sig(SIGPIPE, current, 0);
}

#if CI_CFG_ENDPOINT_MOVE
extern int efab_file_move_to_alien_stack_rsop(ci_private_t *priv, void *arg);
extern int efab_tcp_loopback_connect(ci_private_t *priv, void *arg);
extern int efab_tcp_helper_reuseport_bind(ci_private_t *priv, void *arg);
#endif


static int oo_get_cpu_khz_rsop(ci_private_t *priv, void *arg)
{
  ci_uint32* cpu_khz = arg;
  oo_timesync_wait_for_cpu_khz_to_stabilize();
  *cpu_khz = oo_timesync_cpu_khz;
  return 0;
}

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
static int efab_tcp_helper_alloc_active_wild_rsop(ci_private_t *priv,
                                                  void *arg)
{
  tcp_helper_resource_t* trs = priv->thr;
  oo_alloc_active_wild_t* aaw = arg;

  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  if( trs->netif.state->active_wild_n <
      NI_OPTS(&trs->netif).tcp_shared_local_ports_max )
    return tcp_helper_increase_active_wild_pool(trs, aaw->laddr);

  return -ENOBUFS;
}
#endif


#if CI_CFG_WANT_BPF_NATIVE
static int efab_tcp_helper_evq_poll_rsop(ci_private_t *priv, void* arg)
{
  tcp_helper_resource_t* trs = priv->thr;
  ci_uint32 *vp = arg;

  if( trs == NULL ) {
    LOG_E(ci_log("%s: ERROR: not attached to a stack", __FUNCTION__));
    return -EINVAL;
  }

  return ci_netif_evq_poll(&trs->netif, *vp);
}
#endif


/* "Donation" shared memory ioctls. */

static int oo_dshm_register_rsop(ci_private_t *priv, void *arg)
{
  oo_dshm_register_t* params = arg;
  return oo_dshm_register_impl(params->shm_class, params->buffer,
                               params->length, &params->buffer_id,
                               &priv->dshm_list);
}

static int oo_dshm_list_rsop(ci_private_t *priv, void *arg)
{
  oo_dshm_list_t* params = arg;
  return oo_dshm_list_impl(params->shm_class, params->buffer_ids,
                           &params->count);
}

static int
oo_cp_dump_hwports(ci_private_t *priv, void *arg)
{
  ci_ifid_t ifindex = *(ci_ifid_t*)arg;
  struct oo_cplane_handle* cp;
  int rc = cp_acquire_from_priv_if_server(priv, &cp);

  if( rc < 0 )
    return rc;

  rtnl_lock();
  rc = oo_nic_announce(cp, ifindex);
  rtnl_unlock();

  cp_release(cp);
  return rc;
}

static int
oo_version_check_rsop(ci_private_t *priv, void *arg)
{
  oo_version_check_t *ver = arg;
  return oo_version_check(ver->in_version, ver->in_uk_intf_ver, ver->debug);
}

static int oo_cplane_ipmod(ci_private_t *priv, void *arg)
{
  struct oo_op_cplane_ipmod* op = arg;
  int rc = cp_acquire_from_priv_if_server(priv, NULL);

  if( rc < 0 )
    return rc;

  if( op->add )
    oof_onload_on_cplane_ipadd(op->af, CI_ADDR_FROM_ADDR_SH(op->addr),
                               op->ifindex,
                               priv->priv_cp->cp_netns, &efab_tcp_driver);
  else
    oof_onload_on_cplane_ipdel(op->af, CI_ADDR_FROM_ADDR_SH(op->addr),
                               op->ifindex,
                               priv->priv_cp->cp_netns, &efab_tcp_driver);
  return 0;
}


static int oo_cplane_llapmod(ci_private_t *priv, void *arg)
{
  struct oo_op_cplane_llapmod* op = arg;
  int rc = cp_acquire_from_priv_if_server(priv, NULL);
  if( rc < 0 )
    return rc;

  oof_onload_mcast_update_interface(op->ifindex,  op->flags, op->hwport_mask,
                                    op->vlan_id, op->mac, priv->priv_cp->cp_netns,
                                    &efab_tcp_driver);

  return 0;
}


static int oo_cplane_llap_update_filters(ci_private_t *priv, void *arg)
{
  struct oo_op_cplane_llapmod* op = arg;
  int rc = cp_acquire_from_priv_if_server(priv, NULL);
  if( rc < 0 )
    return rc;

  oof_onload_mcast_update_filters(op->ifindex, priv->priv_cp->cp_netns,
                                  &efab_tcp_driver);

  return 0;
}


static int oo_cplane_dnat_add(ci_private_t *priv, void *arg)
{
  struct oo_op_cplane_dnat_add* op = arg;
  int rc = cp_acquire_from_priv_if_server(priv, NULL);
  if( rc != 0 )
    return rc;

  rc = oof_onload_dnat_add(&efab_tcp_driver,
                           CI_ADDR_FROM_ADDR_SH(op->orig_addr), op->orig_port,
                           CI_ADDR_FROM_ADDR_SH(op->xlated_addr),
                           op->xlated_port);

  return rc;
}


static int oo_cplane_dnat_del(ci_private_t *priv, void *arg)
{
  struct oo_op_cplane_dnat_del* op = arg;
  int rc = cp_acquire_from_priv_if_server(priv, NULL);
  if( rc != 0 )
    return rc;

  oof_onload_dnat_del(&efab_tcp_driver, CI_ADDR_FROM_ADDR_SH(op->orig_addr),
                      op->orig_port);

  return 0;
}


static int oo_cplane_dnat_reset(ci_private_t *priv, void *arg)
{
  int rc = cp_acquire_from_priv_if_server(priv, NULL);
  if( rc != 0 )
    return rc;

  oof_onload_dnat_reset(&efab_tcp_driver);

  return 0;
}


int oo_cp_notify_llap_monitors_rsop(ci_private_t *priv, void *arg)
{
  struct oo_cplane_handle* cp;
  int rc = cp_acquire_from_priv_if_server(priv, &cp);
  if( rc )
    return rc;

  rc = oo_cp_llap_change_notify_all(cp);
  cp_release(cp);
  return rc;
}


static int oo_cp_check_veth_acceleration_rsop(ci_private_t *priv, void *arg)
{
  ci_ifid_t ifindex = *(ci_ifid_t*) arg;
  struct oo_cplane_handle* cp;

  int rc = cp_acquire_from_priv_if_server(priv, &cp);
  if( rc != 0 )
    return rc;

  rc = oo_cp_check_veth_acceleration(cp, ifindex);
  cp_release(cp);
  return rc;
}


static int oo_cp_select_instance_rsop(ci_private_t *priv, void *arg)
{
  return oo_cp_select_instance(priv, *(ci_uint32*) arg);
}


static int oo_veth_acceleration_enabled_rsop(ci_private_t *priv, void *arg)
{
  return oo_accelerate_veth;
}


static int oo_cp_init_kernel_mibs_rsop(ci_private_t *priv, void *arg)
{
  cp_fwd_table_id* fwd_table_id = (cp_fwd_table_id*) arg;
  struct oo_cplane_handle* cp;

  int rc = cp_acquire_from_priv_if_server(priv, &cp);
  if( rc != 0 )
    return rc;

  rc = oo_cp_init_kernel_mibs(cp, fwd_table_id);
  cp_release(cp);
  return rc;
}

static int oo_cp_xdp_prog_change(ci_private_t *priv, void *arg)
{
#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
  struct oo_cp_xdp_change* param = arg;
  struct oo_nic* nic;
  struct bpf_prog* new_prog = NULL;
  struct bpf_prog* old_prog;

  if( param->hwport < 0 || param->hwport >= CI_CFG_MAX_HWPORTS )
    return -EINVAL;
  nic = &oo_nics[param->hwport];

  if( param->fd >= 0 ) {
    new_prog = bpf_prog_get_type_dev(param->fd, BPF_PROG_TYPE_XDP, 1);
    if( IS_ERR(new_prog) )
      new_prog = NULL;
  }
  do {
    old_prog = nic->prog;
  } while( ci_cas_uintptr_fail(&nic->prog, (ci_uintptr_t)old_prog,
                               (ci_uintptr_t)new_prog) );

  if( old_prog != NULL ) {
    /* Release the bpf prog after RCU is not using it.
     * __bpf_prog_put() cares about RCU, so we don't need to.
     */
    bpf_prog_put(old_prog);
  }
#endif
  return 0;
}


static int oo_af_xdp_kick_rsop(ci_private_t *priv, void *arg)
{
  int intf_i = *(int32_t*)arg;
  return efrm_vi_af_xdp_kick(tcp_helper_vi(priv->thr, intf_i));
}


/*************************************************************************
 * ATTENTION! ACHTUNG! ATENCION!                                         *
 * This table MUST be synchronised with enum of OO_OP_* operations!      *
 *************************************************************************/
/*! Table of all supported ioctl handlers */
oo_operations_table_t oo_operations[] = {
#if ! OO_OPS_TABLE_HAS_NAME
# define op(ioc, fn)  { (ioc), (fn) }
#else
# define op(ioc, fn)  { (ioc), (fn), #ioc }
#endif

  /* include/cplane/ioctl.h: */
  op(OO_IOC_GET_CPU_KHZ, oo_get_cpu_khz_rsop),

  op(OO_IOC_CP_DUMP_HWPORTS,   oo_cp_dump_hwports),
  op(OO_IOC_CP_MIB_SIZE,       oo_cp_get_mib_size),
  op(OO_IOC_CP_FWD_RESOLVE,    oo_cp_fwd_resolve_rsop),
  op(OO_IOC_CP_FWD_RESOLVE_COMPLETE,    oo_cp_fwd_resolve_complete),
  op(OO_IOC_CP_ARP_RESOLVE,    oo_cp_arp_resolve_rsop),
  op(OO_IOC_CP_ARP_CONFIRM,    oo_cp_arp_confirm_rsop),
  op(OO_IOC_CP_WAIT_FOR_SERVER, oo_cp_wait_for_server_rsop),
  op(OO_IOC_CP_LINK,           oo_cp_link_rsop),
  op(OO_IOC_CP_READY,          oo_cp_ready),
  op(OO_IOC_CP_CHECK_VERSION,  oo_cp_check_version),

  op(OO_IOC_OOF_CP_IP_MOD,     oo_cplane_ipmod),
  op(OO_IOC_OOF_CP_LLAP_MOD,   oo_cplane_llapmod),
  op(OO_IOC_OOF_CP_LLAP_UPDATE_FILTERS, oo_cplane_llap_update_filters),
  op(OO_IOC_OOF_CP_DNAT_ADD,   oo_cplane_dnat_add),
  op(OO_IOC_OOF_CP_DNAT_DEL,   oo_cplane_dnat_del),
  op(OO_IOC_OOF_CP_DNAT_RESET, oo_cplane_dnat_reset),
  op(OO_IOC_CP_NOTIFY_LLAP_MONITORS,   oo_cp_notify_llap_monitors_rsop),
  op(OO_IOC_CP_CHECK_VETH_ACCELERATION, oo_cp_check_veth_acceleration_rsop),
  op(OO_IOC_CP_SELECT_INSTANCE, oo_cp_select_instance_rsop),
  op(OO_IOC_CP_INIT_KERNEL_MIBS, oo_cp_init_kernel_mibs_rsop),
  op(OO_IOC_CP_XDP_PROG_CHANGE, oo_cp_xdp_prog_change),

  /* include/onload/ioctl-dshm.h: */
  op(OO_IOC_DSHM_REGISTER, oo_dshm_register_rsop),
  op(OO_IOC_DSHM_LIST,     oo_dshm_list_rsop),

  /* include/onload/ioctl.h: */
  op(OO_IOC_DBG_GET_STACK_INFO, efab_tcp_helper_get_info),
  op(OO_IOC_DBG_WAIT_STACKLIST_UPDATE, efab_tcp_helper_wait_stack_list_update),

#if ! CI_CFG_UL_INTERRUPT_HELPER
  op(OO_IOC_DEBUG_OP, oo_ioctl_debug_op),
#endif

  op(OO_IOC_PRINTK, ioctl_printk),

  op(OO_IOC_RESOURCE_ONLOAD_ALLOC, tcp_helper_alloc_rsop),
  op(OO_IOC_EP_INFO,               ioctl_ep_info),
  op(OO_IOC_VI_STATS_QUERY,        ioctl_vi_stats_query),
  op(OO_IOC_CLONE_FD,              ioctl_clone_fd),
  op(OO_IOC_KILL_SELF_SIGPIPE,     ioctl_kill_self),

  op(OO_IOC_TCP_SOCK_SLEEP,   efab_tcp_helper_sock_sleep_rsop),
  op(OO_IOC_WAITABLE_WAKE,    efab_tcp_helper_waitable_wake_rsop),

  op(OO_IOC_EP_FILTER_SET,       efab_ep_filter_set),
  op(OO_IOC_EP_FILTER_CLEAR,     efab_ep_filter_clear),
  op(OO_IOC_EP_FILTER_MCAST_ADD, efab_ep_filter_mcast_add),
  op(OO_IOC_EP_FILTER_MCAST_DEL, efab_ep_filter_mcast_del),
  op(OO_IOC_EP_FILTER_DUMP,      efab_ep_filter_dump),

  op(OO_IOC_TCP_SOCK_LOCK,      efab_tcp_helper_sock_lock_slow_rsop),
  op(OO_IOC_TCP_SOCK_UNLOCK,    efab_tcp_helper_sock_unlock_slow_rsop),
  op(OO_IOC_TCP_PKT_WAIT,       efab_tcp_helper_pkt_wait_rsop),
  op(OO_IOC_TCP_MORE_BUFS,      efab_tcp_helper_more_bufs_rsop),
  op(OO_IOC_TCP_MORE_SOCKS,     efab_tcp_helper_more_socks_rsop),
#if CI_CFG_FD_CACHING
  op(OO_IOC_TCP_CLEAR_EPCACHE,  efab_tcp_helper_clear_epcache_rsop),
#endif

  op(OO_IOC_STACK_ATTACH,      efab_tcp_helper_stack_attach ),
  op(OO_IOC_INSTALL_STACK_BY_ID, efab_tcp_helper_lookup_and_attach_stack),
  op(OO_IOC_SOCK_ATTACH,           efab_tcp_helper_sock_attach ),
  op(OO_IOC_TCP_ACCEPT_SOCK_ATTACH,efab_tcp_helper_tcp_accept_sock_attach ),
  op(OO_IOC_PIPE_ATTACH,       efab_tcp_helper_pipe_attach ),
#if CI_CFG_FD_CACHING
  op(OO_IOC_SOCK_DETACH,       efab_tcp_helper_sock_detach_file),
  op(OO_IOC_SOCK_ATTACH_TO_EXISTING, efab_tcp_helper_sock_attach_to_existing_file),
#endif

  op(OO_IOC_OS_SOCK_CREATE_AND_SET,efab_tcp_helper_os_sock_create_and_set_rsop),
  op(OO_IOC_OS_SOCK_FD_GET,        efab_tcp_helper_get_sock_fd),
  op(OO_IOC_OS_SOCK_SENDMSG,       efab_tcp_helper_os_sock_sendmsg),
  op(OO_IOC_OS_SOCK_RECVMSG,       efab_tcp_helper_os_sock_recvmsg),
  op(OO_IOC_OS_SOCK_ACCEPT,        efab_tcp_helper_os_sock_accept),
  op(OO_IOC_TCP_ENDPOINT_SHUTDOWN, tcp_helper_endpoint_shutdown_rsop),
  op(OO_IOC_TCP_BIND_OS_SOCK,      efab_tcp_helper_bind_os_sock_rsop),
  op(OO_IOC_TCP_LISTEN_OS_SOCK,    efab_tcp_helper_listen_os_sock),
  op(OO_IOC_TCP_HANDOVER,          efab_tcp_helper_handover),
  op(OO_IOC_FILE_MOVED,            oo_file_moved_rsop),
  op(OO_IOC_TCP_CLOSE_OS_SOCK,     efab_tcp_helper_set_tcp_close_os_sock_rsop),
  op(OO_IOC_OS_POLLERR_CLEAR,      efab_tcp_helper_os_pollerr_clear),

#if ! CI_CFG_UL_INTERRUPT_HELPER
  op(OO_IOC_EPLOCK_WAKE,      efab_eplock_unlock_and_wake_rsop),
#else
  op(OO_IOC_EPLOCK_WAKE_AND_DO, efab_eplock_wake_and_do_rsop),
#endif
  op(OO_IOC_EPLOCK_LOCK, oo_eplock_lock_rsop),

  op(OO_IOC_INSTALL_STACK,    efab_install_stack),
#if ! CI_CFG_UL_INTERRUPT_HELPER
  op(OO_IOC_RSOP_DUMP, thr_priv_dump),
#endif
  op(OO_IOC_GET_ONLOADFS_DEV, onloadfs_get_dev_t),
#if CI_CFG_ENDPOINT_MOVE
  op(OO_IOC_TCP_LOOPBACK_CONNECT, efab_tcp_loopback_connect),
  op(OO_IOC_MOVE_FD, efab_file_move_to_alien_stack_rsop),
  op(OO_IOC_EP_REUSEPORT_BIND, efab_tcp_helper_reuseport_bind),
  op(OO_IOC_CLUSTER_DUMP,      efab_cluster_dump),
#endif

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
  op(OO_IOC_ALLOC_ACTIVE_WILD, efab_tcp_helper_alloc_active_wild_rsop),
#endif

  op(OO_IOC_VETH_ACCELERATION_ENABLED, oo_veth_acceleration_enabled_rsop),

#if CI_CFG_WANT_BPF_NATIVE
  op(OO_IOC_EVQ_POLL, efab_tcp_helper_evq_poll_rsop),
#endif

#if CI_CFG_UL_INTERRUPT_HELPER
  op(OO_IOC_WAIT_FOR_INTERRUPT, oo_wait_for_interrupt),
  op(OO_IOC_WAKEUP_WAITERS,     oo_wakeup_waiters),
#endif

  op(OO_IOC_AF_XDP_KICK, oo_af_xdp_kick_rsop),
  op(OO_IOC_EFCT_SUPERBUF_CONFIG_REFRESH,oo_efct_superbuf_config_refresh_rsop),
  op(OO_IOC_PKT_BUF_MMAP, oo_pkt_buf_map_rsop),
  op(OO_IOC_DESIGN_PARAMETERS, oo_design_parameters_rsop),

/* Here come non contigous operations only, their position need to match
 * index according to their placeholder */
  op(OO_IOC_CHECK_VERSION, oo_version_check_rsop),
#undef op
};

#define OO_OP_TABLE_SIZE (sizeof(oo_operations) / sizeof(oo_operations[0]))

CI_BUILD_ASSERT(OO_OP_TABLE_SIZE == OO_OP_END);

