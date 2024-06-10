/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2010-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file epoll_fd_b.c
** <L5_PRIVATE L5_HEADER >
** \author  oktet sasha
**  \brief  epoll implementation - first approach
**   \date  2010/03/04
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */

#include <ci/internal/transport_config_opt.h>


#define LPF      "citp_epoll:"

#include <ci/internal/transport_common.h>
#include <onload/ul/tcp_helper.h>
#include <onload/extensions.h>
#include "ul_epoll.h"


/***************************************************************
                       Epoll implementation details
                       ----------------------------

There is no /dev/onload fd associated with epoll fd.  All the
implementation is userspace-only.  After exec(), user receives just
normal kernel epoll fd, loosing all userspace acceleration.

Known problems:

Edge-triggering & EPOLLONESHOT
==============================
With EPOLLET, every event is reported no more than twice.
For OO socket, it is polled via oo_sockets list and via the main epfd.
For kernel fd, it is polled via epfd_os and via the main epfd.
Each of them reports each event only once, so it is possible that
the entire epoll_wait() call reports the same event twice regardless
on EPOLLET.
Similar problem exists with EPOLLONESHOT

2 types of fds
==============
We have 3 types of fds: kernel and onload.

fork()+exec() bug in epoll
==========================
User has onload epfd in app1.  Using fork+exec, he gets the same epfd in
non-accelerated app2 (even if app2 is really accelerated, epfd is
non-accelerated).  From proc2, user calls epoll_ctl().  As proc1 knows
nothing about it, oo_sockets list and epfd_os are not changed.  Now, app2
receives incorrect results for epoll_wait().
- If app2 have added new fd to the polling set, app1 will receive these
events only when it blocks.  Not so bad.
- If app2 have modified fd parameters (events or data), app1 will receive
incorrect events.
- If app2 have removed fd from the polling set, app1 will receive events
for this fd even after removal.
I do not think the scenarios above can really happen with any real-world
applications, so I'm not going to fix it.  See also some discussions about
epoll+exec() in LKML: http://www.mail-archive.com/search?q=epoll (exec OR
shared)&l=linux-kernel@vger.kernel.org



Missing features:

exec()
======
Restore onload epoll fd after exec.  Currently, we get kernel epoll fd
in the exec'ed app.

epoll_pwait()
=============
epoll_pwait(), ppoll() and pselect() are not accelerated.

multi-level poll
================
If an application uses poll/epoll/select on onload epoll fd, we can
accelerate it.  Currently, onload epoll fd will be used as kernel fd.

Unification of poll/epoll/select code
=====================================
We have 3 copy of more-or-less the same code.  May be, it is good, as
the code is not identical.

Lazy update of the main epoll fd
================================
Waiting on the main epoll fd is rare thing, especially with EF_POLL_SPIN.
We can avoid calling epoll_ctl(main fd, ...) as long as it is not really
necessary.  It is not clear if such approach makes things faster.


 ***************************************************************/


#define EITEM_FROM_DLLINK(lnk)                          \
  CI_CONTAINER(struct citp_epoll_member, dllink, (lnk))
#define EITEM_FROM_DEADLINK(lnk)                          \
  CI_CONTAINER(struct citp_epoll_member, dead_stack_link, (lnk))


#define EP_NOT_REGISTERED  ((unsigned) -1)


/* In the same namespace as EPOLLIN etc.  Assumed not to collide with any
 * useful events!
 */
#define OO_EPOLL_FORCE_SYNC  (1 << 27)


#define EPOLL_CTL_FMT  "%d, %s, %d, %x, %llx"
#define EPOLL_CTL_ARGS(epoll_fd, op, fd, event)                 \
  (epoll_fd), citp_epoll_op_str(op), (fd),                      \
  (event) ? (event)->events : -1,                               \
    (unsigned long long) ((event) ? (event)->data.u64 : 0llu)


#define CITP_EPOLL_EP_LOCK(ep)                  \
  do {                                          \
    if( (ep)->not_mt_safe )                     \
      oo_wqlock_lock(&(ep)->lock);              \
  } while( 0 )

#define CITP_EPOLL_EP_UNLOCK(ep, fdt_locked)                            \
  do {                                                                  \
    if( (ep)->not_mt_safe )                                             \
      oo_wqlock_unlock(&(ep)->lock, (void*)(uintptr_t) (fdt_locked));   \
  } while( 0 )


#ifndef NDEBUG
static const char* citp_epoll_op_str(int op)
{
  switch( op ) {
  case EPOLL_CTL_ADD:  return "ADD";
  case EPOLL_CTL_MOD:  return "MOD";
  case EPOLL_CTL_DEL:  return "DEL";
  default:             return "BAD_OP";
  }
}
#endif


static inline citp_fdinfo_p
citp_ul_epoll_member_to_fdip(struct citp_epoll_member* eitem)
{
  ci_assert_lt(eitem->fd, citp_fdtable.inited_count);
  return citp_fdtable.table[eitem->fd].fdip;
}

static inline citp_fdinfo * 
citp_ul_epoll_member_to_fdi(struct citp_epoll_member* eitem)
{
  citp_fdinfo* fdi = NULL;
  do {
    citp_fdinfo_p fdip = citp_ul_epoll_member_to_fdip(eitem);
    if( fdip_is_busy(fdip) ) {
      /* Wait: We cannot draw any conclusion about a busy entry.  (NB. We
       * cannot call citp_fdtable_busy_wait() because we're holding the
       * fdtable lock).
       */
      ci_spinloop_pause();
      continue;
    }
    if( !fdip_is_normal(fdip) )
      return NULL;
    fdi = fdip_to_fdi(fdip);
    if( fdi->seq != eitem->fdi_seq )
      return NULL;
    break;
  } while(1);
  return fdi;
}


#if CI_CFG_EPOLL3
static void
citp_epoll_set_home_stack(struct citp_epoll_fd* ep, ci_netif* ni)
{
  struct oo_epoll1_set_home_arg op;
  int rc;

  ep->ready_list = ci_netif_get_ready_list(ni);
  if( ep->ready_list < 0 )
    return;

  Log_POLL(ci_log("%s: Set home stack using ready list %d "
                  "stack %s",
                  __FUNCTION__, ep->ready_list, ni->state->pretty_name));

  op.sockfd = ci_netif_get_driver_handle(ni);
  op.ready_list = ep->ready_list;
  rc = ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_SET_HOME_STACK, &op);
  if( rc == 0 ) {
    citp_netif_add_ref(ni);
    ep->home_stack = ni;
  }
  else {
    ci_netif_put_ready_list(ni, ep->ready_list);
    ep->ready_list = -1;
  }
}

static int citp_epoll_sb_state_alloc(citp_socket* sock)
{
  oo_p sp;
  ci_sb_epoll_state* epoll;
  int i;

  ci_netif_lock(sock->netif);
  if( OO_PP_NOT_NULL(sock->s->b.epoll) ) {
    ci_netif_unlock(sock->netif);
    return 0;
  }

  sp = ci_ni_aux_alloc(sock->netif, CI_TCP_AUX_TYPE_EPOLL);
  if( OO_PP_NOT_NULL(sp) ) {
    sock->s->b.epoll = sp;
    epoll = ci_ni_aux_p2epoll(sock->netif, sp);
    epoll->sock_id = sock->s->b.bufid;
    for( i = 0; i < CI_EPOLL_SETS_PER_AUX_BUF; i++ ) {
      oo_p_dllink_init(sock->netif,
                       ci_sb_epoll_ready_link(sock->netif, epoll, i));
    }
  }
  ci_netif_unlock(sock->netif);
  if( OO_PP_IS_NULL(sp) ) {
    Log_POLL(ci_log("%s: failed to allocate epoll state for [%d:%d]", __func__,
                    NI_ID(sock->netif), sock->s->b.bufid));
    CITP_STATS_NETIF_INC(sock->netif, epoll_sb_state_alloc_failed);
    return -1;
  }
  return 0;
}

static void citp_epoll_sb_state_set(struct citp_epoll_member* eitem,
                                    struct citp_epoll_fd* ep,
                                    citp_socket* sock)
{
  ci_sb_epoll_state* epoll;
  struct oo_p_dllink_state link;

  ci_assert(OO_PP_NOT_NULL(sock->s->b.epoll));

  epoll = ci_ni_aux_p2epoll(sock->netif, sock->s->b.epoll);
  link = ci_sb_epoll_ready_link(ep->home_stack, epoll, ep->ready_list);

  /* This epoll set owns the ready list id, so it must be free in the
   * socket */
  ci_assert_nflags(sock->s->b.ready_lists_in_use, 1 << ep->ready_list);
  OO_P_DLLINK_ASSERT_EMPTY(ep->home_stack, link);

  CI_USER_PTR_SET(epoll->e[ep->ready_list].eitem, eitem);

  /* Tell others that we are in the list */
  ci_netif_lock(ep->home_stack);
  sock->s->b.ready_lists_in_use |= 1 << ep->ready_list;
  oo_p_dllink_add_tail(ep->home_stack,
                       oo_p_dllink_ptr(ep->home_stack,
                                       &ep->home_stack->state->
                                            unready_lists[ep->ready_list]),
                       link);
  ci_netif_unlock(ep->home_stack);
}


static void
citp_epoll_promote_to_home(struct citp_epoll_member* eitem, citp_fdinfo* fd_fdi,
                           citp_socket* sock, struct citp_epoll_fd* ep)
{
  Log_POLL(ci_log("%s:  fd %d", __FUNCTION__, eitem->fd));
  /* Sockets from the oo_sockets list are added to the OS epoll set.
   * We'll handle it when deleting them, see citp_epoll_ctl_onload_del().
   */
  ci_dllist_remove_safe(&eitem->dllink);
  ep->oo_sockets_n--;
  eitem->item_list = &ep->oo_stack_sockets;
  eitem->ready_list_id = ep->ready_list;
  eitem->flags &=~ CITP_EITEM_FLAG_POLL_END;
  ep->oo_stack_sockets_n++;

  ci_dllist_push(&ep->oo_stack_sockets, &eitem->dllink);

  citp_epoll_sb_state_set(eitem, ep, sock);
}

static void
citp_epoll_try_promote_to_home(struct citp_epoll_member* eitem,
                               struct citp_epoll_fd* ep, citp_fdinfo* fdi)
{
  citp_socket* sock;

  ci_assert_equal(CITP_OPTS.ul_epoll, 3);
  if( ! citp_fdinfo_is_socket(fdi) )
    return;

  sock = fdi_to_socket(fdi);
  if( citp_epoll_sb_state_alloc(sock) != 0 )
    return;
  if( ep->home_stack == NULL )
    citp_epoll_set_home_stack(ep, sock->netif);
  if( sock->netif == ep->home_stack )
    citp_epoll_promote_to_home(eitem, fdi, sock, ep);
}


static void citp_epoll_last_stack_socket_gone(struct citp_epoll_fd* epoll_fd,
                                              int fdt_locked)
{
  struct citp_epoll_member* e;
  struct citp_epoll_member* enext;

  /* Release the ready list.  We don't bother to sync this to the kernel. */
  ci_assert(ci_dllist_is_empty(&epoll_fd->oo_stack_sockets));
  ci_assert(ci_dllist_is_empty(&epoll_fd->oo_stack_not_ready_sockets));
  ci_assert(ci_dllist_is_empty(&epoll_fd->dead_stack_sockets));
  ci_sys_ioctl(epoll_fd->epfd_os, OO_EPOLL1_IOC_REMOVE_HOME_STACK);
  ci_netif_put_ready_list(epoll_fd->home_stack, epoll_fd->ready_list);

  citp_netif_release_ref(epoll_fd->home_stack, fdt_locked);

  epoll_fd->home_stack = NULL;
  epoll_fd->ready_list = -1;
  if( epoll_fd->closing )
    return;

  CI_DLLIST_FOR_EACH3(struct citp_epoll_member, e,
                      dllink, &epoll_fd->oo_sockets, enext) {
    citp_fdinfo* fdi = citp_ul_epoll_member_to_fdi(e);
    if( fdi != NULL )
      citp_epoll_try_promote_to_home(e, epoll_fd, fdi);
  }
}


/* This function does the full monty cleanup.  It assumes that:
 * - a reference to fd_fdi is held
 * - the epoll lock is held (or we know we don't need it)
 * - the home stack netif lock is not held
 * For cases where we can't guarantee the above
 *
 * It tidies up all state, but does not free the eitem.
 */
static void citp_remove_home_member(struct citp_epoll_fd* epoll_fd,
                                    struct citp_epoll_member* eitem,
                                    citp_fdinfo* fd_fdi, int fdt_locked)
{
  ci_netif* ni;
  citp_socket* sock;

  ci_assert(eitem);
  ci_assert_ge(eitem->ready_list_id, 0);
  ci_assert(epoll_fd->home_stack);

  ci_dllist_remove_safe(&eitem->dllink);
  epoll_fd->oo_stack_sockets_n--;

  sock = fdi_to_socket(fd_fdi);
  ni = sock->netif;
  fd_fdi->epoll_fd = -1;

  /* It is possible that we've already removed this epoll state; in this
   * case no cleanup in the shared state is needed. */
  if( sock->s->b.ready_lists_in_use & (1 << eitem->ready_list_id) ) {
    ci_netif_lock(ni);
    if( sock->s->b.ready_lists_in_use & (1 << eitem->ready_list_id) ) {
      ci_sb_epoll_state* epoll = ci_ni_aux_p2epoll(ni, sock->s->b.epoll);
      struct oo_p_dllink_state link =
              ci_sb_epoll_ready_link(ni, epoll, eitem->ready_list_id);

      sock->s->b.ready_lists_in_use &=~ (1 << eitem->ready_list_id);
      oo_p_dllink_del(ni, link);
      oo_p_dllink_init(ni, link);
    }
    ci_netif_unlock(ni);
  }

  if( epoll_fd->oo_stack_sockets_n == 0 )
    citp_epoll_last_stack_socket_gone(epoll_fd, fdt_locked);
}


/* This function requires that the epoll lock is held, or we know that we
 * don't need it.
 */
static void citp_epoll_cleanup_dead_home_socks(struct citp_epoll_fd* ep,
                                               int fdt_locked)
{
  struct citp_epoll_member* eitem;

  oo_wqlock_lock(&ep->dead_stack_lock);
  while( ci_dllist_not_empty(&ep->dead_stack_sockets) ) {
    eitem = EITEM_FROM_DEADLINK(ci_dllist_head(&ep->dead_stack_sockets));

    /* For dead sockets the associated socket state has (potentiall) been
     * freed, so we have nothing to do (and can't touch) the associated fdinfo
     * or socket buffer.
     *
     * We just need to remove this eitem from any other queue it's on, and
     * free it.
     */
    ci_dllist_remove(&eitem->dllink);
    ci_dllist_remove(&eitem->dead_stack_link);
    CI_FREE_OBJ(eitem);
    ci_assert_gt(ep->oo_stack_sockets_n, 0);
    if( --ep->oo_stack_sockets_n == 0 )
      citp_epoll_last_stack_socket_gone(ep, fdt_locked);
  }
  oo_wqlock_unlock(&ep->dead_stack_lock, NULL);
}


static void citp_epoll_cleanup_home_sock_list(struct citp_epoll_fd* ep,
                                              ci_dllist* list,
                                              int fdt_locked)
{
  struct citp_epoll_member* eitem;
  citp_fdinfo* fd_fdi;
  /* Can only call this for lists that use the dllink field */
  ci_assert((list == &ep->oo_stack_sockets) ||
            (list == &ep->oo_stack_not_ready_sockets));

  while( ci_dllist_not_empty(list) ) {
    eitem = EITEM_FROM_DLLINK(ci_dllist_head(list));
    oo_wqlock_lock(&ep->dead_stack_lock);
    /* The socket could be being closed at the same time as we are, so need
     * to take dead_stack_lock and check whether it's on the list.
     */
    if( ci_dllink_is_self_linked(&eitem->dead_stack_link) ) {
      ci_assert( ci_dllink_is_self_linked(&eitem->dead_stack_link) );
  
      /* Last reference to this epoll_fd is about to go => we don't need to
       * take epoll lock here.
       */
      fd_fdi = citp_ul_epoll_member_to_fdi(eitem);
      if( fd_fdi != NULL ) {
        citp_remove_home_member(ep, eitem, fd_fdi, fdt_locked);
      }
      else {
        /* Fixme: bug78046: we leak the netif refcount here */
        ci_dllist_remove_safe(&eitem->dllink);
      }
      CI_FREE_OBJ(eitem);
    }
    oo_wqlock_unlock(&ep->dead_stack_lock, NULL);
  }
}

static void citp_epoll_update_eitems_epoll_fd(ci_dllist *list, int epoll_fd,
                                              int new_epoll_fd,
                                              int new_epoll_fd_seq)
{
  struct citp_epoll_member* eitem;
  citp_fdinfo *fd_fdi;

  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem, dllink, list) {
    fd_fdi = citp_ul_epoll_member_to_fdi(eitem);
    if( fd_fdi && fd_fdi->epoll_fd == epoll_fd ) {
      fd_fdi->epoll_fd = new_epoll_fd;
      fd_fdi->epoll_fd_seq = new_epoll_fd_seq;
    }
  }
}
#endif

static void citp_epoll_purge_other_socks(struct citp_epoll_fd* ep)
{
  struct citp_epoll_member* eitem;
  struct citp_epoll_member* next_eitem;
  CI_DLLIST_FOR_EACH3(struct citp_epoll_member, eitem,
                      dllink, &ep->oo_sockets, next_eitem) {
    CI_FREE_OBJ(eitem);
  }
}

static void citp_epoll_dtor(citp_fdinfo* fdi, int fdt_locked)
{
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);

#if CI_CFG_EPOLL3
  ci_dllist_remove(&fdi_to_epoll_fdi(fdi)->dllink);
#endif

  if (!oo_atomic_dec_and_test(&ep->refcount)) {
#if CI_CFG_EPOLL3
    /* We're closing epoll fd but there are still more open fds associated with
     * this epoll set. Find all the sockets referring to this epoll fd and
     * change it to the next valid fd from epi_list. */
    citp_epoll_fdi *next_epi = CI_CONTAINER(citp_epoll_fdi, dllink,
                                            ci_dllist_start(&ep->epi_list));

    citp_epoll_update_eitems_epoll_fd(&ep->oo_stack_sockets, fdi->fd,
                                      next_epi->fdinfo.fd, next_epi->fdinfo.seq);
    citp_epoll_update_eitems_epoll_fd(&ep->oo_stack_not_ready_sockets, fdi->fd,
                                      next_epi->fdinfo.fd, next_epi->fdinfo.seq);
#endif
    return;
  }

  ep->closing = 1;

#if CI_CFG_EPOLL3
  if( ep->home_stack ) {
    /* Cleaning up the dead sockets must be done first, to ensure that they're
     * removed from the other lists before we process them.
     */
    citp_epoll_cleanup_dead_home_socks(ep, fdt_locked);
    citp_epoll_cleanup_home_sock_list(ep, &ep->oo_stack_sockets, fdt_locked);
    citp_epoll_cleanup_home_sock_list(ep, &ep->oo_stack_not_ready_sockets,
                                      fdt_locked);
    citp_epoll_cleanup_dead_home_socks(ep, fdt_locked);
  }
  ci_assert(ci_dllist_is_empty(&ep->oo_stack_sockets));
  ci_assert(ci_dllist_is_empty(&ep->oo_stack_not_ready_sockets));
  ci_assert(ci_dllist_is_empty(&ep->dead_stack_sockets));
#endif

  citp_epoll_purge_other_socks(ep);

  if( ! fdt_locked )  CITP_FDTABLE_LOCK();
  ci_tcp_helper_close_no_trampoline(ep->shared->epfd);
  __citp_fdtable_reserve(ep->shared->epfd, 0);
  munmap(ep->shared, sizeof(*ep->shared));

  ci_tcp_helper_close_no_trampoline(ep->epfd_os);
  __citp_fdtable_reserve(ep->epfd_os, 0);
  if( ! fdt_locked )  CITP_FDTABLE_UNLOCK();

#if CI_CFG_TIMESTAMPING
  ci_free(ep->ordering_info);
  ci_free(ep->wait_events);
#endif

  CI_FREE_OBJ(ep);
}


static citp_fdinfo* citp_epoll_dup(citp_fdinfo* orig_fdi)
{
  citp_fdinfo    *fdi;
  citp_epoll_fdi *epi;
  struct citp_epoll_fd* ep = fdi_to_epoll(orig_fdi);

  epi = CI_ALLOC_OBJ(citp_epoll_fdi);
  if (!epi)
    return NULL;

  fdi = &epi->fdinfo;
  citp_fdinfo_init(fdi, &citp_epoll_protocol_impl);
  epi->epoll = ep;
#if CI_CFG_EPOLL3
  ci_dllist_push(&ep->epi_list, &epi->dllink);
#endif
  oo_atomic_inc(&ep->refcount);
  return fdi;
}

static int citp_epoll_ioctl(citp_fdinfo *fdi, int cmd, void *arg)
{
  return ci_sys_ioctl(fdi->fd, cmd, arg);
}


citp_protocol_impl citp_epoll_protocol_impl = {
  .type     = CITP_EPOLL_FD,
  .ops      = {
    /* Important members -- users will realy call it. */
    .dup         = citp_epoll_dup,
    .dtor        = citp_epoll_dtor,
    .ioctl       = citp_epoll_ioctl,

    /* Poll/select for epollfd is done via kernel. */
    .select      = citp_passthrough_select,
    .poll        = citp_passthrough_poll,
    .fcntl       = citp_passthrough_fcntl,

    /* "Invalid" members; normal user should not call it and should not
     * expect good behaviour */
    .socket      = NULL,        /* nobody should ever call this */
    .recv        = citp_nonsock_recv,
    .send        = citp_nonsock_send,
    .bind        = citp_nonsock_bind,
    .listen      = citp_nonsock_listen,
    .accept      = citp_nonsock_accept,
    .connect     = citp_nonsock_connect,
    .shutdown    = citp_nonsock_shutdown,
    .getsockname = citp_nonsock_getsockname,
    .getpeername = citp_nonsock_getpeername,
    .getsockopt  = citp_nonsock_getsockopt,
    .setsockopt  = citp_nonsock_setsockopt,
    .recvmmsg    = citp_nonsock_recvmmsg,
    .sendmmsg    = citp_nonsock_sendmmsg,
    .zc_send     = citp_nonsock_zc_send,
    .zc_recv     = citp_nonsock_zc_recv,
    .zc_recv_filter = citp_nonsock_zc_recv_filter,
    .recvmsg_kernel = citp_nonsock_recvmsg_kernel,
    .tmpl_alloc     = citp_nonsock_tmpl_alloc,
    .tmpl_update    = citp_nonsock_tmpl_update,
    .tmpl_abort     = citp_nonsock_tmpl_abort,
#if CI_CFG_TIMESTAMPING
    .ordered_data   = citp_nonsock_ordered_data,
#endif
    .is_spinning    = citp_nonsock_is_spinning,
#if CI_CFG_FD_CACHING
    .cache          = citp_nonsock_cache,
#endif
  }
};


int citp_epoll_create(int size, int flags)
{
  citp_fdinfo    *fdi;
  citp_epoll_fdi *epi;
  struct citp_epoll_fd* ep;
  int            fd;
  int            shared_fd;
  int            rc;

  if( (epi = CI_ALLOC_OBJ(citp_epoll_fdi)) == NULL )
    goto fail0;
  if( (ep = CI_ALLOC_OBJ(struct citp_epoll_fd)) == NULL )
    goto fail1;
  fdi = &epi->fdinfo;
  citp_fdinfo_init(fdi, &citp_epoll_protocol_impl);

  /* Create the epoll fd. */
  CITP_FDTABLE_LOCK();
  if( (fd = ci_sys_epoll_create_compat(size, flags, 0)) < 0 )
    goto fail2;
  citp_fdtable_new_fd_set(fd, fdip_busy, TRUE);

  /* Init epfd_os */
  if( ef_onload_driver_open(&ep->epfd_os, OO_EPOLL_DEV, 1) < 0 ) {
    Log_E(ci_log("%s: ERROR: failed to open(%s) errno=%d",
                 __FUNCTION__, oo_device_name[OO_EPOLL_DEV], errno));
    goto fail3;
  }
  __citp_fdtable_reserve(ep->epfd_os, 1);
  rc = ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_INIT, NULL);
  if( rc == 0 ) {
    ep->shared = mmap(NULL, sizeof(*ep->shared), PROT_READ, MAP_SHARED,
                       ep->epfd_os, 0);
  }
  if( rc != 0 || ep->shared == MAP_FAILED ) {
    Log_E(ci_log("%s: ERROR: failed to mmap shared segment errno=%d",
                 __FUNCTION__, errno));
    goto fail4;
  }
  if( ep->shared->epfd < CITP_OPTS.fd_base ) {
    ci_sys_epoll_move_fd(ep->shared->epfd, &shared_fd);
    ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_MOVE_FD, &shared_fd);
  }
  __citp_fdtable_reserve(ep->shared->epfd, 1);
  CITP_FDTABLE_UNLOCK();

  epi->epoll = ep;
  ep->size = size;
  oo_wqlock_init(&ep->lock);
  ep->not_mt_safe = ! CITP_OPTS.ul_epoll_mt_safe;
#if CI_CFG_EPOLL3
  oo_wqlock_init(&ep->dead_stack_lock);
  ci_dllist_init(&ep->oo_stack_sockets);
  ep->oo_stack_sockets_n = 0;
  ci_dllist_init(&ep->oo_stack_not_ready_sockets);
  ci_dllist_init(&ep->dead_stack_sockets);
  ep->home_stack = NULL;
  ep->ready_list = -1;
  ci_dllist_init(&ep->epi_list);
  ci_dllist_push(&ep->epi_list, &epi->dllink);
#endif
  ci_dllist_init(&ep->oo_sockets);
  ep->oo_sockets_n = 0;
  ci_dllist_init(&ep->dead_sockets);
  oo_atomic_set(&ep->refcount, 1);
  ep->epfd_syncs_needed = 0;
  ep->blocking = 0;
#if CI_CFG_TIMESTAMPING
  ep->ordering_info = NULL;
  ep->wait_events = NULL;
  ep->n_woda_events = 0;
#endif
  ep->avoid_spin_once = 0;
  ep->closing = 0;
  ep->phase = 0;
  citp_fdtable_insert(fdi, fd, 0);
  Log_POLL(ci_log("%s: fd=%d driver_fd=%d epfd=%d", __FUNCTION__,
                  fd, ep->epfd_os, (int) ep->shared->epfd));
  return fd;

 fail4:
  __citp_fdtable_reserve(ep->epfd_os, 0);
  ci_tcp_helper_close_no_trampoline(ep->epfd_os);
 fail3:
  ci_tcp_helper_close_no_trampoline(fd);
  citp_fdtable_busy_clear(fd, fdip_unknown, 1);
 fail2:
  CITP_FDTABLE_UNLOCK();
  CI_FREE_OBJ(ep);
 fail1:
  CI_FREE_OBJ(epi);
 fail0:
  return -2;
}


/* Reset edge-triggering status of the eitem */
ci_inline void citp_eitem_reset_epollet(struct citp_epoll_member* eitem,
                                        citp_fdinfo* fd_fdi)
{
  if( eitem->epoll_data.events & (EPOLLET | EPOLLONESHOT) ) {
    /* Only needed for EPOLLET and harmless otherwise.
     */
    eitem->reported_sleep_seq.all =
                        citp_fdinfo_get_ops(fd_fdi)->sleep_seq(fd_fdi);
    eitem->reported_sleep_seq.rw.rx--;
    eitem->reported_sleep_seq.rw.tx--;
    /* User is arming or re-arming ET or ONESHOT.  If not adding, we have
     * no idea whether these are still armed in the kernel set, so we must
     * re-sync before doing a wait.
     */
    eitem->epoll_data.events |= OO_EPOLL_FORCE_SYNC;
  }
}


ci_inline int epoll_event_eq(const struct epoll_event*__restrict__ a,
                             const struct epoll_event*__restrict__ b)
{
  return memcmp(a, b, sizeof(*a)) == 0;
}


/* Return true if kernel has up-to-date state for this eitem. */
ci_inline int citp_eitem_is_synced(const struct citp_epoll_member* eitem)
{
  return epoll_event_eq(&eitem->epoll_data, &eitem->epfd_event);
}


ci_inline int
citp_epoll_find(struct citp_epoll_fd* ep, const citp_fdinfo* fd_fdi,
                struct citp_epoll_member** eitem_out, int epoll_fd)
{
  struct citp_epoll_member* eitem_next;
#if CI_CFG_EPOLL3
  citp_socket* sock;
  ci_sb_epoll_state* epoll;

  /* We don't know how long ago the fdi was aquired - although we know it's
   * still valid because we hold a reference.  All sorts of things could have
   * happened to it in the meantime.
   *
   * Firstly we check to see if it's a home socket.  In this case the referred
   * to socket will have it's eitem field set, and the fd_fdi->epoll_fd will
   * provide us with the required epoll information.  These would have been
   * unset
   */

  if( ! citp_fdinfo_is_socket(fd_fdi) )
    goto out;

  sock = fdi_to_socket((citp_fdinfo*)fd_fdi);

  /* We need to get a consistent view of fd_fdi - it might be in the process
   * of being closed.
   *
   * We also need to be certain that we actually own this eitem.
   */
  if( ep->home_stack != sock->netif )
    goto out;
  if( OO_PP_IS_NULL(sock->s->b.epoll) )
    goto out;
  epoll = ci_ni_aux_p2epoll(sock->netif, sock->s->b.epoll);
  if( (sock->s->b.ready_lists_in_use & (1 << ep->ready_list)) == 0 )
    goto out;

  oo_wqlock_lock(&ep->dead_stack_lock);
  *eitem_out = CI_USER_PTR_GET(epoll->e[ep->ready_list].eitem);
  oo_wqlock_unlock(&ep->dead_stack_lock, NULL);
  ci_assert(eitem_out);

  /* This epoll set owns the ready list.  So, any socket from this ready
   * list belongs to this set. */
  ci_assert_equal(fd_fdi->seq, (*eitem_out)->fdi_seq);
  return EPOLL_STACK_EITEM;

out:
#endif
  CI_DLLIST_FOR_EACH3(struct citp_epoll_member, *eitem_out,
                      dllink, &ep->oo_sockets, eitem_next) {
    if( (*eitem_out)->fd == fd_fdi->fd && (*eitem_out)->fdi_seq == fd_fdi->seq )
      return EPOLL_NON_STACK_EITEM;
  }
  *eitem_out = NULL;
  return -1;
}


ci_inline struct citp_epoll_member*
citp_epoll_find_dead(struct citp_epoll_fd* ep, const citp_fdinfo* fd_fdi)
{
  struct citp_epoll_member* eitem;
  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem,
                      dllink, &ep->dead_sockets)
    if( eitem->fd == fd_fdi->fd && eitem->fdi_seq == fd_fdi->seq )
      break;
  return eitem;
}


static void citp_eitem_init(struct citp_epoll_member* eitem,
                            citp_fdinfo* fd_fdi, struct epoll_event* event)
{
  eitem->epoll_data = *event;
  eitem->epoll_data.events |= EPOLLERR | EPOLLHUP;
  citp_eitem_reset_epollet(eitem, fd_fdi);
  eitem->fd = fd_fdi->fd;
  eitem->fdi_seq = fd_fdi->seq;
#if CI_CFG_EPOLL3
  eitem->ready_list_id = -1;
  ci_dllink_self_link(&eitem->dead_stack_link);
#endif
  eitem->flags = 0;
}

#if CI_CFG_EPOLL3
static void citp_epoll_ctl_onload_add_home(struct citp_epoll_member* eitem,
                                           struct citp_epoll_fd* ep,
                                           citp_socket* sock,
                                           citp_fdinfo* fd_fdi, int epoll_fd,
                                           ci_uint64 epoll_fd_seq)
{
  eitem->item_list = &ep->oo_stack_sockets;
  eitem->ready_list_id = ep->ready_list;
  eitem->flags &=~ (CITP_EITEM_FLAG_POLL_END | CITP_EITEM_FLAG_OS_SYNC);
  ep->oo_stack_sockets_n++;

  /* We start it out on the ready list - if it's already ready it won't be
   * on the stack ready list.
   */
  ci_dllist_push(&ep->oo_stack_sockets, &eitem->dllink);

  fd_fdi->epoll_fd = epoll_fd;
  fd_fdi->epoll_fd_seq = epoll_fd_seq;

  citp_epoll_sb_state_set(eitem, ep, sock);
}
#endif


static void citp_epoll_ctl_onload_add_other(struct citp_epoll_member* eitem,
                                            struct citp_epoll_fd* ep,
                                            int* sync_kernel,
                                            citp_fdinfo* fd_fdi, int epoll_fd,
                                            ci_uint64 epoll_fd_seq)
{
  eitem->item_list = &ep->oo_sockets;
  eitem->flags &=~ CITP_EITEM_FLAG_POLL_END;
  ci_dllist_push(&ep->oo_sockets, &eitem->dllink);
  ep->oo_sockets_n++;

#if CI_CFG_FD_CACHING
  /* We need to be able to autopop at user level if we want to cache, and that
   * means we can only cache stuff added as home sockets.
   */
  /* FIXME SCJ want a stat to pick this up - probably want to be more
   * specific about why uncacheable - set flags?
   */
  fd_fdi->can_cache = 0;
#endif

  if( ! *sync_kernel ) {
    eitem->epfd_event.events = EP_NOT_REGISTERED;
    ++ep->epfd_syncs_needed;
  }

  /* At the moment only one epoll set can be associated with an fdinfo.  This
   * is used on handover, stack move, and in the home stack case it's also
   * needed on close.  Because everything gets closed, but move or handover
   * are more unusual I'm making the non-broken set the home stack set.
   * FIXME SCJ this is skanky anyway - maybe we should just prohibit adding to
   * more than one set with epoll1 - it works ok with epoll2.
   */
  if( ci_cas32_succeed(&fd_fdi->epoll_fd, -1, epoll_fd) )
    fd_fdi->epoll_fd_seq = epoll_fd_seq;
}

#if CI_CFG_EPOLL3
static int citp_epoll_can_rehome_on_scalable(ci_netif* ni)
{
  return
    ci_cfg_opts.netif_opts.scalable_filter_enable ==
      CITP_SCALABLE_FILTERS_ENABLE_WORKER &&
    NI_OPTS(ni).scalable_filter_enable == CITP_SCALABLE_FILTERS_ENABLE &&
    /* Fixme, Sasha2Maciej: it was
     *      s_f_mode & (ACTIVE | TPROXY_ACTIVE)) != -1
     * which is always true */
    (NI_OPTS(ni).scalable_filter_mode & CITP_SCALABLE_MODE_RSS) != 0;
}
#endif


static int citp_epoll_ctl_onload_add_new(struct citp_epoll_member** eitem_out,
                                         struct citp_epoll_fd* ep,
                                         citp_fdinfo* fd_fdi, int* sync_kernel,
                                         struct epoll_event* event,
                                         int epoll_fd, ci_uint64 epoll_fd_seq)
{
  citp_socket* sock = NULL;
  ci_netif* ni;

  *eitem_out = CI_ALLOC_OBJ(struct citp_epoll_member);
  if( *eitem_out == NULL ) {
    errno = ENOMEM;
    return -1;
  }

  citp_eitem_init(*eitem_out, fd_fdi, event);

  if( ! citp_fdinfo_is_socket(fd_fdi) ) {
    citp_epoll_ctl_onload_add_other(*eitem_out, ep, sync_kernel, fd_fdi,
                                    epoll_fd, epoll_fd_seq);
    return 0;
  }

  sock = fdi_to_socket(fd_fdi);
  ni = sock->netif;

#if CI_CFG_EPOLL3
  if( (CITP_OPTS.ul_epoll == 3) && CI_UNLIKELY(!ep->home_stack) && sock &&
       citp_epoll_can_rehome_on_scalable(ni) ) {
    char* name;
    int empty;
    int rc;

    CITP_FDTABLE_LOCK();
    oo_stackname_get(&name);
    empty = name[0] == 0;
    CITP_FDTABLE_UNLOCK();
    if( empty ) {
      /* With CITP_SCALABLE_FILTERS_ENABLE_WORKER we have encountered
       * a socket in a suitable stack in rss:*active scalable mode.
       * We make this stack a process stack and current context will benefit
       * from (tproxy_)active open acceleration */
      rc = onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL,
                                ni->state->name);
      (void) rc; /* Keep ndebug build happy that rc is used */
      ci_assert_equal(rc, 0);
      Log_POLL(ci_log("%s: name %s %p rc %d", __func__, name, name, rc));
    }
  }

  /* If we don't already have a home stack, then see if we can get a ready
   * list for this socket's stack, and if so use that.
   *
   * There's a gap here between deciding to use this socket's stack for our
   * home stack, and actually claiming this socket as ours, but I'm deeming
   * the chance of this socket being added to another socket in parallel
   * sufficiently low that the cost of locking more widely to avoid it isn't
   * worth it.  Things will work fine, we just potentially won't end up with
   * any sockets in our home stack, but currently home stack selection is not
   * guaranteed to be in any way optimal anyway.
   */
  if( (CITP_OPTS.ul_epoll == 3) && CI_UNLIKELY(!ep->home_stack) && sock &&
       citp_epoll_sb_state_alloc(sock) == 0 ) {
    citp_epoll_set_home_stack(ep, ni);
  }

  /* If we have a home stack then need to check if this fd lives there.
   * If so we can add it to our cool sockets list, if not we'll do it the old
   * school way.
   */
  if( ep->home_stack == ni && citp_epoll_sb_state_alloc(sock) == 0 ) {
    citp_epoll_ctl_onload_add_home(*eitem_out, ep, sock, fd_fdi, epoll_fd,
                                   epoll_fd_seq);
    *sync_kernel = 0;
  }
  else
#endif
  {
    citp_epoll_ctl_onload_add_other(*eitem_out, ep, sync_kernel, fd_fdi,
                                    epoll_fd, epoll_fd_seq);
    CITP_STATS_NETIF_INC(ni, epoll_add_non_home);
  }

  return 0;
}


static void citp_epoll_ctl_onload_readd(struct citp_epoll_member* eitem,
                                        struct citp_epoll_fd* ep,
                                        int* sync_kernel, int* sync_op,
                                        struct epoll_event* event,
                                        citp_fdinfo* fd_fdi, int epoll_fd,
                                        ci_uint64 epoll_fd_seq)
{
#if CI_CFG_EPOLL3
  /* Sockets in the home stack don't hang around after EPOLL_CTL_DEL */
  ci_assert_equal(eitem->ready_list_id, -1);
#endif

  /* Re-added having previously been deleted (but delete did not
   * yet make it as far as the kernel).
   */
  eitem->epoll_data = *event;
  eitem->epoll_data.events |= EPOLLERR | EPOLLHUP;
  citp_eitem_reset_epollet(eitem, fd_fdi);
  if( *sync_kernel )
    *sync_op = EPOLL_CTL_MOD;
  else if( ! citp_eitem_is_synced(eitem) )
    ++ep->epfd_syncs_needed;
  ci_dllist_remove(&eitem->dllink);

  ci_dllist_push(&ep->oo_sockets, &eitem->dllink);
  ep->oo_sockets_n++;

  if( ci_cas32_succeed(&fd_fdi->epoll_fd, -1, epoll_fd) )
    fd_fdi->epoll_fd_seq = epoll_fd_seq;
}


static int citp_epoll_ctl_onload_add(struct citp_epoll_member** eitem_out,
                                     struct citp_epoll_fd* ep,
                                     citp_fdinfo* fd_fdi, int* sync_kernel,
                                     int* sync_op, struct epoll_event* event,
                                     int epoll_fd, ci_uint64 epoll_fd_seq)
{
  int rc = 0;
  if( *eitem_out == NULL ) {
    *eitem_out = citp_epoll_find_dead(ep, fd_fdi);
    if( *eitem_out == NULL ) {
      rc = citp_epoll_ctl_onload_add_new(eitem_out, ep, fd_fdi, sync_kernel,
                                         event, epoll_fd, epoll_fd_seq);
    }
    else {
      citp_epoll_ctl_onload_readd(*eitem_out, ep, sync_kernel, sync_op, event,
                                  fd_fdi, epoll_fd, epoll_fd_seq);
    }
  }
  else {
    errno = EEXIST;
    rc = -1;
  }
  return rc;
}


static int citp_epoll_ctl_onload_mod(struct citp_epoll_member* eitem,
                                     struct citp_epoll_fd* ep,
                                     int* sync_kernel, int* sync_op,
                                     struct epoll_event* event,
                                     citp_fdinfo* fd_fdi)
{
  int rc = 0;
  if(CI_LIKELY( eitem != NULL )) {
    eitem->epoll_data = *event;
    eitem->epoll_data.events |= EPOLLERR | EPOLLHUP;
    citp_eitem_reset_epollet(eitem, fd_fdi);
    if( eitem->flags & CITP_EITEM_FLAG_OS_SYNC )
      *sync_kernel = 1;
    if( *sync_kernel ) {
      if( eitem->epfd_event.events == EP_NOT_REGISTERED ) {
        *sync_op = EPOLL_CTL_ADD;
      }
#if CI_CFG_EPOLL3
      else if( eitem->ready_list_id >= 0 ) {
        ci_assert_flags(eitem->flags, CITP_EITEM_FLAG_OS_SYNC);
        *sync_op = EPOLL_CTL_DEL;
        eitem->flags &=~ CITP_EITEM_FLAG_OS_SYNC;
      }
#endif
    }
    else if(
#if CI_CFG_EPOLL3
            (eitem->ready_list_id < 0) &&
#endif
            !citp_eitem_is_synced(eitem) )
      ++ep->epfd_syncs_needed;

    /* Reinsert at front to exploit locality of reference if there
     * are many sockets and EPOLL_CTL_MOD is frequent.
     */
    ci_dllist_remove(&eitem->dllink);
    ci_dllist_push(eitem->item_list, &eitem->dllink);
  }
  else {
    errno = ENOENT;
    rc = -1;
  }
  return rc;
}

static int citp_epoll_ctl_onload_del(struct citp_epoll_member* eitem,
                                     struct citp_epoll_fd* ep,
                                     int* sync_kernel, citp_fdinfo* fd_fdi,
                                     int epoll_fd, int fdt_locked)
{
  int rc = 0;
  if(CI_LIKELY( eitem != NULL )) {
#if CI_CFG_EPOLL3
    if( eitem->ready_list_id >= 0 ) {
      /* Once upon a time, it was a non-home member, so we have to sync to
       * kernel.  See the comment in citp_epoll_promote_to_home(). */
      if( eitem->flags & CITP_EITEM_FLAG_OS_SYNC )
        *sync_kernel = 1;

      /* This may already be being, or have been, removed via close of the
       * socket, so need to check.
       */
      oo_wqlock_lock(&ep->dead_stack_lock);
      if( ci_dllink_is_self_linked(&eitem->dead_stack_link) ) {
        /* Not been closed yet, can cleanup now. */
        citp_remove_home_member(ep, eitem, fd_fdi, fdt_locked);
        if( ! *sync_kernel )
          CI_FREE_OBJ(eitem);
        /* else the eitem will be freed after syncing */
      }
      ci_assert_equal(fd_fdi->epoll_fd, -1);
      oo_wqlock_unlock(&ep->dead_stack_lock, NULL);
    }
    else
#endif
    {
      ci_dllist_remove(&eitem->dllink);
      ep->oo_sockets_n--;
      if( eitem->epfd_event.events == EP_NOT_REGISTERED ) {
        *sync_kernel = 0;
        CI_FREE_OBJ(eitem);
      }
      else if( ! *sync_kernel ) {
        ci_dllist_push(&ep->dead_sockets, &eitem->dllink);
        ++ep->epfd_syncs_needed;
      }
      /* else in case of sync_kernel we'll free the eitem
       * shortly after sync */
      ci_cas32_succeed(&fd_fdi->epoll_fd, epoll_fd, -1);
    }
  }
  else {
    errno = ENOENT;
    rc = -1;
  }
  return rc;
}


static int citp_epoll_ctl_onload2(struct citp_epoll_fd* ep, int op,
                                  struct epoll_event* event,
                                  citp_fdinfo* fd_fdi, int epoll_fd,
                                  ci_uint64 epoll_fd_seq, int fdt_locked)
{
  struct citp_epoll_member* eitem;
  int sync_kernel, rc = 0;
  int sync_op = op;
  int type = citp_epoll_find(ep, fd_fdi, &eitem, epoll_fd);

  /* Should we sync this op to the kernel?
   *
   * We try defer this step when EF_EPOLL_CTL_FAST=1 because we hope to
   * avoid a sys-call, or at least delay the sys-call until we're about to
   * block.
   *
   * If a thread is blocking in epoll_wait(), then we must sync to kernel
   * now, as this op may wake the epoll_wait().
   *
   * If the relevant eitem is in our home stack we don't have any kernel
   * state to be kept in sync.
   */
  sync_kernel = (type != EPOLL_STACK_EITEM) &&
                (! CITP_OPTS.ul_epoll_ctl_fast || ep->blocking);


  switch( op ) {
  case EPOLL_CTL_ADD:
    rc = citp_epoll_ctl_onload_add(&eitem, ep, fd_fdi, &sync_kernel, &sync_op,
                                   event, epoll_fd, epoll_fd_seq);
    break;
  case EPOLL_CTL_MOD:
    rc = citp_epoll_ctl_onload_mod(eitem, ep, &sync_kernel, &sync_op, event,
                                   fd_fdi);
    break;
  case EPOLL_CTL_DEL:
    rc = citp_epoll_ctl_onload_del(eitem, ep, &sync_kernel, fd_fdi,
                                   epoll_fd, fdt_locked);
    break;
  default:
    errno = EINVAL;
    rc = -1;
    break;
  }

  /* Apply epoll_ctl() to the kernel. */
  if( sync_kernel && rc == 0 ) {
    Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): SYNC_KERNEL", __FUNCTION__,
                    EPOLL_CTL_ARGS(epoll_fd, op, fd_fdi->fd, event)));
    if( sync_op == EPOLL_CTL_ADD ) {
      ci_fixed_descriptor_t fd = fd_fdi->fd;
      int saved_errno = errno;
      ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_ADD_STACK, &fd);
      /* We ignore rc: we do not care if ioctl failed.
       * So, we should restore errno. */
      errno = saved_errno;
      eitem->flags |= CITP_EITEM_FLAG_OS_SYNC;
    }
    rc = ci_sys_epoll_ctl(epoll_fd, sync_op, fd_fdi->fd, event);
    if( rc < 0 )
      Log_E(ci_log("%s("EPOLL_CTL_FMT"): ERROR: sys_epoll_ctl(%s) failed (%d)",
                   __FUNCTION__,
                   EPOLL_CTL_ARGS(epoll_fd, op, fd_fdi->fd, event),
                   citp_epoll_op_str(sync_op), errno));
    if( op != EPOLL_CTL_DEL ) {
      eitem->epoll_data.events &= ~OO_EPOLL_FORCE_SYNC;
      eitem->epfd_event = eitem->epoll_data;
    }
    else {
      CI_FREE_OBJ(eitem);
    }
  }
  else {
    Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): %s rc=%d errno=%d", __FUNCTION__,
                    EPOLL_CTL_ARGS(epoll_fd, op, fd_fdi->fd, event),
#if CI_CFG_EPOLL3
                    eitem && eitem->ready_list_id >= 0 ? "HOME":
#endif
                    "OTHER",
                    rc, errno));
  }

#if CI_CFG_EPOLL3
  if( ci_dllist_not_empty(&ep->dead_stack_sockets) )
    citp_epoll_cleanup_dead_home_socks(ep, fdt_locked);
#endif

  return rc;
}


struct deferred_epoll_ctl {
  struct oo_wqlock_work work;
  struct citp_epoll_fd* ep;
  int op;
  struct epoll_event event;
  citp_fdinfo* fd_fdi;
  int epoll_fd;
  ci_uint64 epoll_fd_seq;
};


static void citp_epoll_deferred_do(struct oo_wqlock_work* work,
                                   void* unlock_param)
{
  struct deferred_epoll_ctl* dec = CI_CONTAINER(struct deferred_epoll_ctl,
                                                work, work);
  int fdt_locked = (int)(uintptr_t) unlock_param;
  int rc;

  Log_POLL(ci_log("%s:", __FUNCTION__));

  Log_POLL(ci_log("%s: epoll_ctl("EPOLL_CTL_FMT")", __FUNCTION__,
                  EPOLL_CTL_ARGS(dec->epoll_fd, dec->op, dec->fd_fdi->fd,
                                 &dec->event)));
  rc = citp_epoll_ctl_onload2(dec->ep, dec->op, &dec->event, dec->fd_fdi,
                              dec->epoll_fd, dec->epoll_fd_seq, fdt_locked);
  if( rc != 0 ) {
    /* If you see this error message then the optimisation that passes an
     * epoll_ctl() call from one thread to another has hidden an error
     * return from the application.  This may or may not be a problem.
     * Set EF_EPOLL_CTL_FAST=0 to prevent this from happening.
     */
    Log_E(ci_log("%s: ERROR: epoll_ctl("EPOLL_CTL_FMT") returned (%d,%d)",
                 __FUNCTION__,
                 EPOLL_CTL_ARGS(dec->epoll_fd, dec->op, dec->fd_fdi->fd,
                                &dec->event), rc, errno));
  }
  citp_fdinfo_release_ref(dec->fd_fdi, fdt_locked);
  free(dec);

  Log_POLL(ci_log("%s: done", __FUNCTION__));
}


static int
citp_epoll_ctl_try_defer_to_lock_holder(struct citp_epoll_fd* ep, int op,
                                        const struct epoll_event* event,
                                        citp_fdinfo* fd_fdi, int epoll_fd,
                                        ci_uint64 epoll_fd_seq)
{
  struct deferred_epoll_ctl* dec;

  if( (dec = malloc(sizeof(*dec))) == NULL ) {
    oo_wqlock_lock(&ep->lock);
    return 0;
  }
  dec->work.fn = citp_epoll_deferred_do;
  dec->ep = ep;
  dec->op = op;
  if( event != NULL )  /* NB. We've already checked op... */
    dec->event = *event;
  dec->fd_fdi = fd_fdi;
  citp_fdinfo_ref(fd_fdi);
  dec->epoll_fd = epoll_fd;
  dec->epoll_fd_seq = epoll_fd_seq;
  if( oo_wqlock_lock_or_queue(&ep->lock, &dec->work) ) {
    /* We got the lock after all. */
    citp_fdinfo_release_ref(fd_fdi, 0);
    free(dec);
    return 0;
  }
  else {
    return 1;
  }
}


static int citp_epoll_ctl_onload(citp_fdinfo* fdi, int op,
                                 struct epoll_event* event,
                                 citp_fdinfo* fd_fdi)
{
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);
  int rc;

  if( event == NULL && (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) ) {
    errno = EFAULT;
    return -1;
  }

  if( ep->not_mt_safe ) {
    if( CITP_OPTS.ul_epoll_ctl_handoff ) {
      /* We need the lock, but epoll_wait() holds it while spinning.  We
       * don't want to do a blocking lock, as we could be held-up
       * indefinitely, and even deadlock the app.  So if the lock is held
       * we pass the epoll_ctl() op to the lock holder.
       */
      if( ! oo_wqlock_try_lock(&ep->lock) &&
          citp_epoll_ctl_try_defer_to_lock_holder(ep, op, event, fd_fdi,
                                                  fdi->fd, fdi->seq) ) {
        /* The thread holding [ep->lock] will apply this op for us.  We just
         * hope it doesn't fail!
         */
        Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): QUEUED", __FUNCTION__,
                        EPOLL_CTL_ARGS(fdi->fd, op, fd_fdi->fd, event)));
        return 0;
      }
    }
    else {
      CITP_EPOLL_EP_LOCK(ep);
    }
  }

  rc = citp_epoll_ctl_onload2(ep, op, event, fd_fdi, fdi->fd, fdi->seq, 0);
  CITP_EPOLL_EP_UNLOCK(ep, 0);
  return rc;
}


static int citp_epoll_ctl_os(citp_fdinfo* fdi, int op, int fd,
                             struct epoll_event *event)
{
  /* Apply this epoll_ctl() to both epoll fds (the one containing
   * everything, and the one containing just non-accelerated fds).
   *
   * To avoid doing two syscalls, we do this via an internal ioctl().
   */
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);
  struct oo_epoll1_ctl_arg oop;
  struct oo_epoll_item ev;
  int rc;

  ev.op = op;
  ev.fd = fd;
  if( event == NULL ) {
    if(CI_UNLIKELY( op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD )) {
      errno = EFAULT;
      return -1;
    }
  }
  else if( op != EPOLL_CTL_DEL ) {
    ev.event = *event;
  }
  oop.fd = ev.fd;
  CI_USER_PTR_SET(oop.event, &ev.event);
  oop.op = ev.op;
  oop.epfd = fdi->fd;
  rc = ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_CTL, &oop);
  Log_POLL(ci_log("%s("EPOLL_CTL_FMT"): rc=%d errno=%d", __FUNCTION__,
                  EPOLL_CTL_ARGS(fdi->fd, op, fd, event), rc, errno));
  return rc;
}


int citp_epoll_ctl(citp_fdinfo* fdi, int op, int fd, struct epoll_event *event)
{
  citp_fdinfo* fd_fdi;

  if( (fd_fdi = citp_fdtable_lookup(fd)) != NULL ) {
    int rc = CITP_NOT_HANDLED;
    if( citp_fdinfo_get_ops(fd_fdi)->epoll != NULL )
      rc = citp_epoll_ctl_onload(fdi, op, event, fd_fdi);
    citp_fdinfo_release_ref(fd_fdi, 0);
    if( rc != CITP_NOT_HANDLED )
      return rc;
  }

  return citp_epoll_ctl_os(fdi, op, fd, event);
}


static void citp_ul_epoll_ctl_sync_fd(int epfd, struct citp_epoll_fd* ep,
                                      struct citp_epoll_member* eitem)
{
  int rc, op;

  if( eitem->epfd_event.events == EP_NOT_REGISTERED ) {
    if( (eitem->epfd_event.events & OO_EPOLL_ALL_EVENTS) == 0 )
      /* No events to register, so don't bother to sync for now.  (In
       * EPOLLONESHOT case this is important, else kernel could report one
       * of the always-on events).
       */
      return;
    op = EPOLL_CTL_ADD;
  }
  else {
    op = EPOLL_CTL_MOD;
  }
  Log_POLL(ci_log("%s: sys_epoll_ctl("EPOLL_CTL_FMT") old_evs=%x",
                  __FUNCTION__,
                  EPOLL_CTL_ARGS(epfd, op, eitem->fd, &eitem->epoll_data),
                  eitem->epfd_event.events));
  eitem->epoll_data.events &= ~OO_EPOLL_FORCE_SYNC;
  eitem->epfd_event = eitem->epoll_data;
  if( op == EPOLL_CTL_ADD ) {
    ci_fixed_descriptor_t fd = eitem->fd;
    int saved_errno = errno;
    ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_ADD_STACK, &fd);
    /* We ignore rc: we do not care if ioctl failed.
     * So, we should restore errno. */
    errno = saved_errno;
  }
  rc = ci_sys_epoll_ctl(epfd, op, eitem->fd, &eitem->epoll_data);
  if( rc < 0 )
    Log_E(ci_log("%s: ERROR: sys_epoll_ctl("EPOLL_CTL_FMT") failed (%d,%d)",
                 __FUNCTION__,
                 EPOLL_CTL_ARGS(epfd, op, eitem->fd, &eitem->epoll_data),
                 rc, errno));
}

static void citp_ul_epoll_ctl_sync(struct citp_epoll_fd* ep, int epfd)
{
  struct citp_epoll_member* eitem;
  struct citp_epoll_member* eitem_tmp;
  int rc;

  Log_POLL(ci_log("%s(%d): epfd_syncs_needed=%d", __FUNCTION__, epfd,
                  ep->epfd_syncs_needed));

  while( ci_dllist_not_empty(&ep->dead_sockets) ) {
    eitem = EITEM_FROM_DLLINK(ci_dllist_pop(&ep->dead_sockets));
#if CI_CFG_EPOLL3
    ci_assert_equal(eitem->ready_list_id, -1);
#endif

    /* Check that this fd was not replaced by another file */
    if( citp_ul_epoll_member_to_fdi(eitem) ) {
      Log_POLL(ci_log("%s(%d): DEL %d", __FUNCTION__, epfd, eitem->fd));
      rc = ci_sys_epoll_ctl(epfd, EPOLL_CTL_DEL,
                            eitem->fd, &eitem->epoll_data);
      if( rc < 0 )
        Log_E(ci_log("%s: ERROR: sys_epoll_ctl(%d, DEL, %d) failed (%d,%d)",
                     __FUNCTION__, epfd, eitem->fd, rc, errno));
    }
    CI_FREE_OBJ(eitem);
  }

  CI_DLLIST_FOR_EACH3(struct citp_epoll_member, eitem,
                      dllink, &ep->oo_sockets, eitem_tmp)
    if( ! citp_eitem_is_synced(eitem) ) {
      if( citp_ul_epoll_member_to_fdi(eitem) ) {
        Log_POLL(ci_log("%s(): sync %d", __func__, eitem->fd));
        citp_ul_epoll_ctl_sync_fd(epfd, ep, eitem);
        eitem->flags |= CITP_EITEM_FLAG_OS_SYNC;
      }
      else {
        ci_dllist_remove(&eitem->dllink);
        ep->oo_sockets_n--;
        CI_FREE_OBJ(eitem);
      }
      if( --ep->epfd_syncs_needed == 0 )
        /* This early exit may help us avoid iterating over the whole list. */
        break;
    }

  /* epfd_syncs_needed can be an overestimate, because changes can cancel
   * and members can be removed.
   */
  ep->epfd_syncs_needed = 0;
}


/* Number of retries: avoid false edge-triggered events if the sleep
 * sequence number is changing while the event is processed. */
#define OO_EPOLLET_SLEEP_SEQ_MISMATCH_RETRIES 3

static int citp_ul_epoll_one(struct oo_ul_epoll_state*__restrict__ eps,
                             struct citp_epoll_member*__restrict__ eitem)
{
  citp_fdinfo* fdi = NULL;
  int stored_event = 0;

  ci_assert_lt(eitem->fd, citp_fdtable.inited_count);

  if(CI_LIKELY( (fdi = citp_ul_epoll_member_to_fdi(eitem)) != NULL )) {
    if( (eitem->epoll_data.events & OO_EPOLL_ALL_EVENTS) != 0 ) {
      int i = 0;

      /* If SO_BUSY_POLL behaviour requested need to check if there is
       * a spinning socket in the set, and remove flag to enable spinning
       * if it is found */
      if( ( eps->ul_epoll_spin & (1 << ONLOAD_SPIN_SO_BUSY_POLL) ) &&
          citp_fdinfo_get_ops(fdi)->is_spinning(fdi) ) {
        eps->ul_epoll_spin &= ~(1 << ONLOAD_SPIN_SO_BUSY_POLL);
      }

      /* In most cases, it is not a loop - ->epoll() usually returns 0.
       * ->epoll() returns non-zero if user asked for EPOLLET and
       * the sequence number is changing under our feet.
       * In such a case, we retry a few times. */
      while( citp_fdinfo_get_ops(fdi)->epoll(fdi, eitem, eps, &stored_event) &&
             i++ < OO_EPOLLET_SLEEP_SEQ_MISMATCH_RETRIES )
        ;
    }
    return stored_event;
  }

  /* [fdip] is special, or the seq check failed, so this fd has changed
   * identity.  Best we can do at userlevel is assume the file descriptor
   * was closed, and remove it from the set.  We have to ensure that
   * all the hooks (on_handover, on_close) have been properly processed,
   * so we ignore it all if something has been queued to the epoll lock.
   *
   *   Home sockets are cleaned up via the close hook, and so must not be
   * cleaned up here.  If the fdi we've looked up is closing, then we can't
   * currently tell whether this is a home socket, so don't do anything yet.
   * If it's not closing then we should be able to tell by looking at whether
   * it's on the dead list - home sockets are bunged here when they're closed.
   */
  if( ! (eps->ep->lock.lock & OO_WQLOCK_WORK_BITS)
#if CI_CFG_EPOLL3
      &&
      ci_dllink_is_self_linked(&eitem->dead_stack_link) &&
      eitem->ready_list_id < 0
#endif
      ) {
    Log_POLL(ci_log("%s: auto remove fd %d from epoll set",
                    __FUNCTION__, eitem->fd));

    ci_dllist_remove(&eitem->dllink);
    eps->ep->oo_sockets_n--;
    CI_FREE_OBJ(eitem);
  }

  return stored_event;
}


#if CI_CFG_EPOLL3
static void citp_epoll_get_ready_list(struct oo_ul_epoll_state*
                                      __restrict__ eps)
{
  ci_netif* ni = eps->ep->home_stack;
  struct oo_p_dllink_state ready_list =
      oo_p_dllink_ptr(ni, &ni->state->ready_lists[eps->ep->ready_list]);
  struct oo_p_dllink_state unready_list =
      oo_p_dllink_ptr(ni, &ni->state->unready_lists[eps->ep->ready_list]);
  struct oo_p_dllink_state lnk, tmp;
  struct citp_epoll_member* eitem = NULL;
  int stack_locked = 0;

  /* If we're ordering then we've only just done a poll to determine the
   * limiting timestamp, so avoid doing another one here.
   */
  if( !eps->ordering_info )
    stack_locked = __citp_poll_if_needed(ni, eps->this_poll_frc,
                                         eps->ul_epoll_spin);

  if( ! stack_locked )
    ci_netif_lock(ni);
  oo_p_dllink_for_each_safe(ni, lnk, tmp, ready_list) {
    ci_sb_epoll_state* epoll;
    epoll = CI_CONTAINER(ci_sb_epoll_state,
                         e[eps->ep->ready_list].ready_link, lnk.l);

    eitem = CI_USER_PTR_GET(epoll->e[eps->ep->ready_list].eitem);
    oo_p_dllink_del(ni, lnk);
    oo_p_dllink_add_tail(ni, unready_list, lnk);
    ci_assert(eitem);
    ci_dllist_remove(&((struct citp_epoll_member*)eitem)->dllink);
    /* This means that we'll be processing sockets in the order that they got
     * added to the ready list, so can mean we're close to ordered.  This
     * provides a noticeable benefit when we're doing WODA with a large
     * number of sockets.
     */
    eitem->flags &=~ CITP_EITEM_FLAG_POLL_END;
    ci_dllist_push_tail(&eps->ep->oo_stack_sockets,
                        &((struct citp_epoll_member*)eitem)->dllink);
  }
  if( eitem ) {
    /* mark that when we remove this item from ready list we shall poll
     * other as well as os fds */
    eitem->flags |= CITP_EITEM_FLAG_POLL_END;
  }
  ci_netif_unlock(ni);
}


static void citp_epoll_poll_home_socks(struct oo_ul_epoll_state*
                                       __restrict__ eps)
{
  struct citp_epoll_member* eitem;
  ci_dllink *next, *last;
  int stored_event;

  if( ci_dllist_not_empty(&eps->ep->oo_stack_sockets) ) {
    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_LOCK_RD();

    last = ci_dllist_last(&eps->ep->oo_stack_sockets);
    next = ci_dllist_start(&eps->ep->oo_stack_sockets);

    do {
      eitem = CI_CONTAINER(struct citp_epoll_member, dllink, next);
      if( eitem->flags & CITP_EITEM_FLAG_POLL_END )
        eps->phase |= EPOLL_PHASE_DONE_ACCELERATED;
      next = next->next;
      stored_event = citp_ul_epoll_one(eps, eitem);
      if( !stored_event ) {
        ci_dllist_remove(&eitem->dllink);
        ci_dllist_push(&eps->ep->oo_stack_not_ready_sockets, &eitem->dllink);
      }
    } while( eps->events < eps->events_top && &eitem->dllink != last );

    if( &eitem->dllink == last )
      eps->phase = EPOLL_PHASE_DONE_ACCELERATED;

    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_UNLOCK_RD();
  }
  else
    eps->phase = EPOLL_PHASE_DONE_ACCELERATED;
  FDTABLE_ASSERT_VALID();
}


static void citp_epoll_poll_ul_home_stack(struct oo_ul_epoll_state*
                                          __restrict__ eps)
{
  ci_assert( eps->events < eps->events_top );

  /* Move all potentially ready socks onto our internal potential ready list.
   * If they turn out not to be ready later on, then they'll go onto the not
   * ready list then.
   *
   * We always get the ready list, so that we don't need to remember what socks
   * we've already got events for.  We could be cleverer here, and avoid a poll
   * and stack lock grab.
   */
  citp_epoll_get_ready_list(eps);

  citp_epoll_poll_home_socks(eps);
}
#endif


static void citp_epoll_poll_ul_other(struct oo_ul_epoll_state* __restrict__ eps)
{
  struct citp_epoll_member* eitem;
  ci_dllink *next, *last;

  ci_assert( eps->events < eps->events_top );

  if( ci_dllist_not_empty(&eps->ep->oo_sockets) ) {
    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_LOCK_RD();

    last = ci_dllist_last(&eps->ep->oo_sockets);
    next = ci_dllist_start(&eps->ep->oo_sockets);
    CI_CONTAINER(struct citp_epoll_member, dllink, last)->flags |=
                                                CITP_EITEM_FLAG_POLL_END;
    do {
      eitem = CI_CONTAINER(struct citp_epoll_member, dllink, next);
      if( eitem->flags & CITP_EITEM_FLAG_POLL_END )
        eps->phase |= EPOLL_PHASE_DONE_OTHER;
      next = next->next;
      citp_ul_epoll_one(eps, eitem);
    } while( eps->events < eps->events_top && &eitem->dllink != last );

    if( &eitem->dllink == last )
      eps->phase = EPOLL_PHASE_DONE_OTHER;

    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_UNLOCK_RD();
  }
  else
    eps->phase = EPOLL_PHASE_DONE_OTHER;
  FDTABLE_ASSERT_VALID();
}


static void citp_epoll_poll_ul(struct oo_ul_epoll_state*__restrict__ eps)
{
#if CI_CFG_EPOLL3
  /* First check any sockets in our home stack */
  if( eps->ep->home_stack )
    citp_epoll_poll_ul_home_stack(eps);
#endif

  /* Then check any other accelerated sockets if we still have space */
  if( eps->events < eps->events_top ) {
#if CI_CFG_EPOLL3
    if( eps->ep->home_stack )
      ci_assert_flags(eps->phase, EPOLL_PHASE_DONE_ACCELERATED);
#endif
    citp_epoll_poll_ul_other(eps);
  }

  /* If we'd like to spin for spinning socket only, and we've failed to
   * find any - remove spinning flags. */
  if( eps->ul_epoll_spin & (1 << ONLOAD_SPIN_SO_BUSY_POLL) )
    eps->ul_epoll_spin = 0;
}


ci_inline int citp_epoll_os_fds(citp_epoll_fdi *efdi,
                                struct epoll_event* events,
                                struct citp_ordering_info* ordering_info,
                                int maxevents)
{
  struct oo_epoll1_wait_arg op;
  struct citp_epoll_fd* ep = efdi->epoll;
  int rc;

  ci_assert(__oo_per_thread_get()->sig.c.inside_lib);

  if( (ep->shared->flag & OO_EPOLL1_FLAG_EVENT) == 0 )
    return 0;

  Log_VVPOLL(ci_log("%s(%d): poll os fds", __FUNCTION__, efdi->fdinfo.fd));

  op.epfd = efdi->fdinfo.fd;
  op.maxevents = maxevents;
  CI_USER_PTR_SET(op.events, events);
  rc = ci_sys_ioctl(efdi->epoll->epfd_os, OO_EPOLL1_IOC_WAIT, &op);

  /* We don't have valid timestamps for events grabbed via the kernel, so
   * we need to ensure that the ordering info shows that.
   */
  if( ordering_info && (rc >= 0) )
    memset(ordering_info, 0, (sizeof(struct citp_ordering_info)) * op.rc);

  return rc < 0 ? rc : op.rc;
}



static inline void
citp_epoll_find_timeout(ci_int64* timeout_hr, ci_uint64* poll_start_frc)
{
  ci_uint64 now_frc;

  ci_frc64(&now_frc);
  *timeout_hr -= now_frc - *poll_start_frc;
  *poll_start_frc = now_frc;
  *timeout_hr = CI_MAX(*timeout_hr, 0);
}


/* Synchronise state to kernel if:
   - EF_EPOLL_CTL_FAST=0;
   - or we are going to block (timeout != 0 && rc == 0) */
ci_inline void
citp_epoll_ctl_try_sync(struct citp_epoll_fd* ep, citp_fdinfo* fdi,
                        ci_int64 timeout_hr, int rc)
{
  if( ep->epfd_syncs_needed &&
      ( ! CITP_OPTS.ul_epoll_ctl_fast || (rc == 0 && timeout_hr != 0) ) )
    citp_ul_epoll_ctl_sync(ep, fdi->fd);
}


int citp_epoll_wait(citp_fdinfo* fdi, struct epoll_event*__restrict__ events,
                    struct citp_ordered_wait* ordering, int maxevents,
                    ci_int64 timeout_hr, const sigset_t *sigmask,
                    const struct timespec *ts, citp_lib_context_t *lib_context)
{
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);
  struct oo_ul_epoll_state eps;
  ci_uint64 base_poll_start_frc, poll_start_frc;
  int rc = 0, rc_os = 0;
  sigset_t sigsaved;
  int pwait_was_spinning = 0;
  int have_spin = 0;

  ci_assert_ge(timeout_hr, 0);
  ci_assert_le(timeout_hr, OO_EPOLL_MAX_TIMEOUT_FRC);

  /* Because we may spin or block while polling we need to report back to
   * onload_ordered_epoll_wait() on the timeout it should use if it polls
   * again, as some of the initial timout may have been used up.  Start out
   * with the full time available.
   *
   * Note that onload_ordered_epoll_wait() may need to poll again even if
   * we return without blocking, as the stack may be polled from another
   * context after the ordering limit was determined, so the interface that
   * we offer to it must always initialise this value.
   */
  if( ordering )
    ordering->next_timeout_hr = timeout_hr;

  Log_VPOLL(ci_log("%s(%d, max_ev=%d, timeout=%" CI_PRId64 ") ul=%d dead=%d "
                   "syncs=%d",
                   __FUNCTION__, fdi->fd, maxevents, timeout_hr,
                   ! ci_dllist_is_empty(&ep->oo_sockets),
                   ! ci_dllist_is_empty(&ep->dead_sockets),
                   ep->epfd_syncs_needed));

  CITP_EPOLL_EP_LOCK(ep);

  if( ((CITP_OPTS.ul_epoll == 1 || ! ep->not_mt_safe) &&
#if CI_CFG_EPOLL3
       ci_dllist_is_empty(&ep->oo_stack_sockets) &&
       ci_dllist_is_empty(&ep->oo_stack_not_ready_sockets) &&
#endif
       ci_dllist_is_empty(&ep->oo_sockets)) ||
      maxevents <= 0 || events == NULL ) {
    /* No accelerated fds or invalid parameters). */
    if( ep->epfd_syncs_needed )
      citp_ul_epoll_ctl_sync(ep, fdi->fd);
    CITP_EPOLL_EP_UNLOCK(ep, 0);
    citp_exit_lib(lib_context, FALSE);
    Log_VPOLL(ci_log("%s(%d, ..): passthrough", __FUNCTION__, fdi->fd));
#if CI_LIBC_HAS_epoll_pwait2
    if( ts != NULL ) {
      if( ts->tv_sec > 0 || ts->tv_nsec > 0 )
        ep->blocking = 1;
      rc = ci_sys_epoll_pwait2(fdi->fd, events, maxevents, ts, sigmask);
    }
    else
#endif /* CI_LIBC_HAS_epoll_pwait2 */
    {
      int timeout_ms = oo_epoll_frc_to_ms(timeout_hr);
      if( timeout_ms )
        ep->blocking = 1;
      rc = ci_sys_epoll_pwait(fdi->fd, events, maxevents, timeout_ms, sigmask);
    }

    /* We don't have valid timestamps for events grabbed via the kernel, so
     * we need to ensure that the ordering info shows that.
     */
    if( ordering && (rc > 0) )
      memset(ordering->ordering_info, 0,
            (sizeof(struct citp_ordering_info)) * rc);

    ep->blocking = 0;
    return rc;
  }

  /* Set up epoll state */
  ci_frc64(&base_poll_start_frc);
  /* base_poll_start_frc keeps the base timestamp of poll start and
   * poll_start_frc keeps the updated value because we should to update it
   * both with timeout_hr re-calculation. See citp_epoll_find_timeout().*/
  eps.this_poll_frc = poll_start_frc = base_poll_start_frc;
  eps.ep = ep;
  eps.events = events;
  eps.events_top = events + maxevents;
  eps.ordering_info = ordering ? ordering->ordering_info : NULL;
  eps.has_epollet = 0;
  eps.phase = ep->phase;
  /* NB. We do need to call oo_per_thread_get() here (despite having
   * [lib_context] in scope) to ensure [spinstate] is initialised.
   */
  eps.ul_epoll_spin = 
    oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_EPOLL_WAIT);
  if( eps.ul_epoll_spin ) {
    eps.ul_epoll_spin |=
      oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_SO_BUSY_POLL);
  }

  if(CI_UNLIKELY( eps.phase )) {
    /* In last epoll_wait we have not managed to obtain all the
     * non-home-stack events as the event count surpassed maxevents.
     * Let's resume where we stopped obtaining events - either other
     * or os sockets. This is to avoid unfair suppression of other/os
     * events in case server is saturated.
     * we need to go over (other, [os, [home]]) events, or
     * (os, [home, [other]]) sequence.
     */
    int need_to_process_other = 0;
    /* get ready list anyway and tag its end */
#if CI_CFG_EPOLL3
    if( eps.ep->home_stack )
      citp_epoll_get_ready_list(&eps);
#endif
    if( ~eps.phase & EPOLL_PHASE_DONE_OTHER ) {
      /* Time for other socket priority round */
      ci_assert_equal(eps.phase, EPOLL_PHASE_DONE_ACCELERATED);
      citp_epoll_poll_ul_other(&eps);
      rc = eps.events - events;
      if( rc == maxevents ) {
        ep->phase = eps.phase;
        goto unlock_release_exit_ret;
      }
    }
    else {
      /*FIXME consider taggin end of oo_sockets list */
      need_to_process_other = 1;
    }
    if( eps.phase & EPOLL_PHASE_DONE_OTHER ) {
      /* Time for os socket priority round */
      if(CI_UNLIKELY( ep->shared->flag & OO_EPOLL1_FLAG_EVENT )) {
        rc_os = citp_epoll_os_fds(fdi_to_epoll_fdi(fdi),
                                  events + rc,
                                  ordering ? ordering->ordering_info+rc : NULL,
                                  maxevents - rc);
        if( rc_os > 0 ) {
          rc += rc_os;
          eps.events += rc_os;
        }
        else {
          rc_os = 0; /* ignore errors */
        }
        if( rc == maxevents ) {
          ep->phase = 0;
          goto unlock_release_exit_ret;
        }
      }
      /* We can only be certain that we have done with os sockets
       * when polling os sockets has not filled all the events.
       * However, when os sockets saturate server the accelerated sockets
       * might get starved.
       * FIXME: consider stopping polling os fds if polling them time
       * after time fills all the events.
       */
    }
    ep->phase = 0; /* clear it for all the blocking/non-event paths */
    eps.phase = 0;
#if CI_CFG_EPOLL3
    /* no need to check presence of home_stack */
    citp_epoll_poll_home_socks(&eps);
#endif
    rc = eps.events - events;
    if( rc == maxevents ) {
      ep->phase = eps.phase;
      goto unlock_release_exit_ret;
    }
    if( need_to_process_other
#if CI_CFG_EPOLL3
        && (eps.phase & EPOLL_PHASE_DONE_ACCELERATED)
#endif
        ) {
      citp_epoll_poll_ul_other(&eps);
      rc = eps.events - events;
    }
    if( rc == 0 )
      goto no_events;
    ep->phase = eps.phase;
    goto unlock_release_exit_ret;
  }

 poll_again:
#if CI_CFG_SPIN_STATS
  eps.stat_incremented = 0;
#endif
  ci_assert_equal(eps.events_top - eps.events, maxevents);
  citp_epoll_poll_ul(&eps);

  if( eps.events != events ) {
    /* We have either:
     *  * exclusively userlevel sockets ready just need to do a non-blocking
     *    poll of kernel sockets (at most) and we're done, or
     *  * we have some os sockets from os socket priority round,
     *    no need to repeat querying os.
     */
    rc = eps.events - events;
    ci_assert_le(rc, maxevents);
    ci_assert_impl(rc < maxevents, eps.phase & EPOLL_PHASE_DONE_OTHER);
    if(CI_UNLIKELY( ep->shared->flag & OO_EPOLL1_FLAG_EVENT )) {
      if(CI_LIKELY( rc < maxevents )) {
        rc_os = citp_epoll_os_fds(fdi_to_epoll_fdi(fdi),
                                  events + rc,
                                  ordering ? ordering->ordering_info+rc : NULL,
                                  maxevents - rc);
        if( rc_os > 0 ) {
          rc += rc_os;
          if( rc == maxevents )
            eps.phase = EPOLL_PHASE_DONE_OTHER;
        }
      }
    }

    if( rc == maxevents )
      ep->phase = eps.phase;

    /* If we've been spinning for some time before getting events, then any
     * events are probably past the limit being used for ordering.  Tell caller
     * that it would be worth polling again.
     */
    if( have_spin && ordering ) {
      ordering->poll_again = 1;
      citp_epoll_find_timeout(&timeout_hr, &poll_start_frc);
      ordering->next_timeout_hr = timeout_hr;
    }

    Log_VPOLL(ci_log("%s(%d): return %d ul + %d kernel",
                     __FUNCTION__, fdi->fd, rc, rc_os));
    goto unlock_release_exit_ret;
  }
  /* eps.events == events */
no_events:
  /* poll OS fds: */
  rc = citp_epoll_os_fds(fdi_to_epoll_fdi(fdi), events,
                         ordering ?  ordering->ordering_info : NULL, maxevents);
  if( rc != 0 || timeout_hr == 0 ) {
    Log_VPOLL(ci_log("%s(%d): %d kernel events", __FUNCTION__, fdi->fd, rc));
    goto unlock_release_exit_ret;
  }

  /* Blocking.  Shall we spin? */
  if( KEEP_POLLING(eps.ul_epoll_spin, eps.this_poll_frc, base_poll_start_frc) ) {
    if( !pwait_was_spinning && sigmask != NULL) {
      if( ep->avoid_spin_once ) {
        eps.ul_epoll_spin = 0;
        ep->avoid_spin_once = 0;
        goto unlock_release_exit_ret;
      }
      rc = citp_ul_pwait_spin_pre(lib_context, sigmask, &sigsaved);
      if( rc != 0 ) {
        CITP_EPOLL_EP_UNLOCK(ep, 0);
        citp_exit_lib(lib_context, CI_FALSE);
        return rc;
      }
      pwait_was_spinning = 1;
    }

    /* Has another thread queued any epoll_ctl requests or
     * blocking on the lock?  See citp_epoll_ctl_onload(). */
    if( CITP_OPTS.ul_epoll_ctl_handoff ) {
      oo_wqlock_try_drain_work(&ep->lock, (void*)(uintptr_t) 0);
    }
    else {
      /* epoll_ctl() may be blocking on this lock.
       * Let's give it a chance. */
      CITP_EPOLL_EP_UNLOCK(ep, 0);
      CITP_EPOLL_EP_LOCK(ep);
    }

    /* Timeout while spinning? */
    if( timeout_hr > 0 &&
        (eps.this_poll_frc - poll_start_frc >= timeout_hr) ) {
      Log_VPOLL(ci_log("%s(%d): timeout during spin", __FUNCTION__, fdi->fd));
      rc = 0;
      timeout_hr = 0;
      goto unlock_release_exit_ret;
    }

    if(CI_UNLIKELY( lib_context->thread->sig.c.aflags &
                    OO_SIGNAL_FLAG_HAVE_PENDING )) {
      errno = EINTR;
      rc = -1;
      goto unlock_release_exit_ret;
    }

    have_spin = 1;

    /* When we're WODAing we can't return anything we find with later polls,
     * so we don't poll on individual sockets.  However, we do need to ensure
     * that the stack continues to be polled, so if we've looked at everything
     * and nothing's ready yet then poll now.
     */
    if( ordering && ordering->ordering_stack)
      citp_poll_if_needed(ordering->ordering_stack, eps.this_poll_frc,
                          eps.ul_epoll_spin);
    if( CITP_OPTS.sleep_spin_usec ) {
      struct oo_epoll1_spin_on_arg op = {};
      op.epoll_fd = fdi->fd;
      op.timeout_ns = oo_epoll_frc_to_ns(timeout_hr);
      op.sleep_iter_ns = CITP_OPTS.sleep_spin_usec * 1000;

      citp_epoll_ctl_try_sync(ep, fdi, timeout_hr, 0);

      rc = ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_SPIN_ON, &op);
      citp_epoll_find_timeout(&timeout_hr, &poll_start_frc);
      Log_VVPOLL(ci_log("%s(%d): SPIN ON", __FUNCTION__, fdi->fd));
    }
    goto poll_again;
  } /* endif ul_epoll_spin spinning*/

  /* Re-calculate timeout.  We should do it if we were spinning a lot. */
  if( eps.ul_epoll_spin && timeout_hr > 0 ) {
    timeout_hr -= eps.this_poll_frc - poll_start_frc;
    poll_start_frc = eps.this_poll_frc;
    timeout_hr = CI_MAX(timeout_hr, 0);
    Log_VVPOLL(ci_log("%s: blocking timeout reduced to %" CI_PRId64,
                      __FUNCTION__, timeout_hr));
  }

 unlock_release_exit_ret:
  /* Synchronise state to kernel (if necessary) and block. */
  citp_epoll_ctl_try_sync(ep, fdi, timeout_hr, rc);

  CITP_EPOLL_EP_UNLOCK(ep, 0);
  Log_VPOLL(ci_log("%s(%d): to kernel", __FUNCTION__, fdi->fd));

  if( pwait_was_spinning) {
    Log_VPOLL(ci_log("%s(%d): pwait_was_spinning", __FUNCTION__, fdi->fd));
    /* Fixme:
     * if we've got both signal and event, we can't return both to user.
     * As signal will be processed anyway (in exit_lib), we MUST
     * tell the user about it with -1(EINTR).  User will get events with
     * the next epoll_pwait call.
     *
     * The problem is, if some events are with EPOLLET or EPOLLONESHOT,
     * they are lost.  Ideally, we should un-mark them as "reported" in our
     * internal oo_sockets list.
     *
     * Workaround is to disable spinning for one next epoll_pwait call,
     * because we report EPOLLET events twice in such a way.
     */
    citp_ul_pwait_spin_done(lib_context, &sigsaved, &rc);
    if( rc < 0 ) {
      if( eps.has_epollet )
        ep->avoid_spin_once = 1;
      return rc;
    }
  }
  else
    citp_exit_lib(lib_context, FALSE);

  if( rc != 0 || timeout_hr == 0 )
    return rc;

  Log_VPOLL(ci_log("%s(%d): rc=0 timeout=%" CI_PRId64 " sigmask=%p",
                   __FUNCTION__, fdi->fd, timeout_hr, sigmask));
  ci_assert( eps.events_top == (eps.events + maxevents) );

  ep->blocking = 1;

  {
    struct oo_epoll1_block_on_arg op;

    op.flags = 0;
    op.epoll_fd = fdi->fd;
    if( sigmask != NULL ) {
      op.flags = OO_EPOLL1_HAS_SIGMASK;
      op.sigmask = *(ci_uint64*)sigmask;
    }
   block_again:
    /* Unlike when we fall back to normal epoll_wait(), we can block for a
     * precise nanosecond amount in this epoll3 case. This avoids the whole
     * function call blocking for slightly longer than expected when we have
     * already spun for a bit. */
    op.timeout_ns = oo_epoll_frc_to_ns(timeout_hr);
    rc = ci_sys_ioctl(ep->epfd_os, OO_EPOLL1_IOC_BLOCK_ON, &op);

    ep->blocking = 0;
    Log_VPOLL(ci_log("%s(%d): BLOCK_ON rc=%d op.flags=%d", __FUNCTION__,
                    fdi->fd, rc, op.flags));

    if( rc == 0 && !ordering ) {
      /* We've got some events.  We MUST call epoll_wait to get the real
       * events - it is the only way to reset EPOLLET event. */
      if( op.flags & OO_EPOLL1_EVENT_ON_OTHER ) {
        rc = ci_sys_epoll_wait(fdi->fd, events, maxevents, 0);
        if( rc < 0 )
          return rc;
        eps.events += rc;
      }

#if CI_CFG_EPOLL3
      /* Are there any events in the home stack? */
      if( op.flags & OO_EPOLL1_EVENT_ON_HOME ) {
        citp_reenter_lib(lib_context);

        CITP_EPOLL_EP_LOCK(ep);
        /* We MUST check that home stack has not disappeared while we were
         * waiting. */
        if( eps.ep->home_stack )
          citp_epoll_poll_ul_home_stack(&eps);
        CITP_EPOLL_EP_UNLOCK(ep, 0);

        citp_exit_lib(lib_context, FALSE);
        rc = eps.events - events;
      }
#endif

      if( rc == 0 ) {
        /* False alarm. Let's block again.  */
        citp_epoll_find_timeout(&timeout_hr, &poll_start_frc);
        if( timeout_hr > 0 ) {
          ep->blocking = 1;
          op.flags &= ~(OO_EPOLL1_EVENT_ON_HOME | OO_EPOLL1_EVENT_ON_OTHER);
          goto block_again;
        }
      }
    }
    else if( rc == 0 ) {
      ci_assert(ordering);
      rc = op.flags & (OO_EPOLL1_EVENT_ON_HOME | OO_EPOLL1_EVENT_ON_OTHER);
    }
  }

  if( rc && ordering ) {
    ordering->poll_again = 1;
    citp_epoll_find_timeout(&timeout_hr, &poll_start_frc);
    ordering->next_timeout_hr = timeout_hr;
  }

  Log_VPOLL(ci_log("%s(%d): to kernel => %d (%d)", __FUNCTION__, fdi->fd,
                   rc, errno));
  return rc;
}

/* Caller must lock ep */
static struct citp_epoll_member*
citp_epoll_hook_start(struct citp_epoll_fd* ep, citp_fdinfo* fd_fdi,
                      int fdt_locked)
{
  struct citp_epoll_member* eitem;

#if CI_CFG_EPOLL3
  /* This hook may be called after a completed handover, ie after the socket
   * buffer has been released, so we need to search through our list, rather
   * than going through the fdi.
   */
  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem,
                      dllink, &ep->oo_stack_sockets) {
    if( eitem->fd == fd_fdi->fd && eitem->fdi_seq == fd_fdi->seq )
      return eitem;
  }
  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem,
                      dllink, &ep->oo_stack_not_ready_sockets) {
    if( eitem->fd == fd_fdi->fd && eitem->fdi_seq == fd_fdi->seq )
      return eitem;
  }
#endif

  CI_DLLIST_FOR_EACH2(struct citp_epoll_member, eitem,
                      dllink, &ep->oo_sockets) {
    if( eitem->fd == fd_fdi->fd && eitem->fdi_seq == fd_fdi->seq )
      return eitem;
  }

  Log_POLL(ci_log("%s: epoll_fd=%d fd=%d not in epoll u/l set",
                  __FUNCTION__, fd_fdi->epoll_fd, fd_fdi->fd));
  return NULL;
}

struct deferred_on_handover {
  struct oo_wqlock_work work;
  citp_fdinfo* epoll_fdi;
  citp_fdinfo* fd_fdi; 
  citp_fdinfo* new_fdi; /* NULL for handover, non-NULL for move */
};

void citp_epoll_on_move_do(citp_fdinfo* epoll_fdi, citp_fdinfo* fd_fdi,
                           citp_fdinfo* new_fdi,
                           struct citp_epoll_member* eitem,
                           int fdt_locked)
{
#if CI_CFG_EPOLL3
  struct citp_epoll_fd* ep = fdi_to_epoll(epoll_fdi);
#endif

  Log_POLL(ci_log("%s: epoll_fd=%d fd=%d %s", __FUNCTION__, fd_fdi->epoll_fd,
                  fd_fdi->fd,
#if CI_CFG_EPOLL3
                  eitem->ready_list_id > 0 ? "HOME":
#endif
                  "OTHER"));

#if CI_CFG_EPOLL3
  if( eitem->ready_list_id < 0 )
#endif
  {
    /* Would be nice to move into the home stack if that's where we're moved
     * to, but not bothering for now.
     */
    eitem->fdi_seq = new_fdi->seq;
  }
#if CI_CFG_EPOLL3
  else {
    /* This was in our home stack, but now isn't.  Need to update the eitem
     * state to be appropriate for a non-home sock.
     */
    ci_dllist_remove(&eitem->dllink);
    ep->oo_stack_sockets_n--;
    eitem->ready_list_id = -1;
    if( ep->oo_stack_sockets_n == 0 )
      citp_epoll_last_stack_socket_gone(ep, fdt_locked);

    eitem->item_list = &ep->oo_sockets;
    ci_dllist_push(&ep->oo_sockets, &eitem->dllink);
    ep->oo_sockets_n++;

    eitem->fdi_seq = new_fdi->seq;
    eitem->epfd_event.events = EP_NOT_REGISTERED;
    ++ep->epfd_syncs_needed;
  }
#endif

  citp_fdinfo_release_ref(fd_fdi, fdt_locked);
  citp_fdinfo_release_ref(new_fdi, fdt_locked);
}

static void citp_epoll_on_handover_do(citp_fdinfo* epoll_fdi,
                                      citp_fdinfo* fd_fdi,
                                      struct citp_epoll_member* eitem,
                                      int fdt_locked)
{
  /* We've handed [fd_fdi->fd] over to the kernel, but it may be registered
   * in an epoll set.  The handover (probably) caused the underlying file
   * object in the kernel to be freed, which will have removed this fd from
   * the epoll set.  We need to add it back.
   */
  struct citp_epoll_fd* ep = fdi_to_epoll(epoll_fdi);
  int rc;

  Log_POLL(ci_log("%s: epoll_fd=%d fd=%d events=%x data=%llx",
                  __FUNCTION__, fd_fdi->epoll_fd, fd_fdi->fd,
                  eitem->epoll_data.events,
                  (unsigned long long) eitem->epoll_data.data.u64));

#if CI_CFG_EPOLL3
  if( eitem->ready_list_id >= 0 ) {
    citp_remove_home_member(ep, eitem, fd_fdi, fdt_locked);
  }
  else
#endif
  {
    ep->oo_sockets_n--;
    ci_dllist_remove(&eitem->dllink);
  }

  if( fd_fdi->protocol->type == CITP_PASSTHROUGH_FD )
    rc = citp_epoll_ctl(epoll_fdi, EPOLL_CTL_ADD,
                        fdi_to_alien_fdi(fd_fdi)->os_socket,
                        &eitem->epoll_data);
  else
    rc = citp_epoll_ctl(epoll_fdi, EPOLL_CTL_ADD, fd_fdi->fd,
                        &eitem->epoll_data);
  /* Error is OK: it means this fd is already in the kernel epoll set,
   * and kernel workaround is used */
  if( rc != 0 )
    Log_E(ci_log("%s: ERROR: epoll_ctl(%d, ADD, %d, ev) failed (%d)",
                 __FUNCTION__, epoll_fdi->fd, fd_fdi->fd, errno));
  CI_FREE_OBJ(eitem);

  if( ep->epfd_syncs_needed )
    citp_ul_epoll_ctl_sync(ep, epoll_fdi->fd);

  /* Now we can free fd_fdi */
  citp_fdinfo_free(fd_fdi);
}

static void citp_epoll_on_handover_work(struct oo_wqlock_work* work,
                                      void* unlock_param)
{
  struct deferred_on_handover* deh = CI_CONTAINER(struct deferred_on_handover,
                                                  work, work);
  int fdt_locked = (int)(uintptr_t) unlock_param;
  struct citp_epoll_fd* ep = fdi_to_epoll(deh->epoll_fdi);
  struct citp_epoll_member* eitem;

  eitem = citp_epoll_hook_start(ep, deh->fd_fdi, fdt_locked);
  if( eitem == NULL ) {
    free(deh);
    return;
  }

  if( deh->new_fdi == NULL ) {
    citp_epoll_on_handover_do(deh->epoll_fdi, deh->fd_fdi, eitem,
                              fdt_locked);
  }
  else {
    citp_epoll_on_move_do(deh->epoll_fdi, deh->fd_fdi, deh->new_fdi,
                          eitem, fdt_locked);
  }

  citp_fdinfo_release_ref(deh->epoll_fdi, fdt_locked);
  free(deh);
}

static void __citp_epoll_on_smth(citp_fdinfo* epoll_fdi, citp_fdinfo* fd_fdi,
                                 citp_fdinfo* new_fdi, int fdt_locked)
{
  struct citp_epoll_fd* ep = fdi_to_epoll(epoll_fdi);;
  struct deferred_on_handover* deh;

  if( (deh = malloc(sizeof(*deh))) == NULL ) {
    /* malloc never fails; and we do not have a good fallback here. */
    ci_log("%s: malloc unexpectedly fails", __func__);
    ci_assert(0);
    return;
  }
  deh->work.fn = citp_epoll_on_handover_work;
  deh->epoll_fdi = epoll_fdi;
  deh->fd_fdi = fd_fdi;
  deh->new_fdi = new_fdi;

  if( oo_wqlock_lock_or_queue(&ep->lock, &deh->work) ) {
    deh->work.fn(&deh->work, (void*)(uintptr_t)fdt_locked);
    /* deh->work.fn have just freed deh */
    oo_wqlock_unlock(&ep->lock, (void*)(uintptr_t)fdt_locked);
  }
}

/* See citp_epoll_on_move_do which does the real work. */
void citp_epoll_on_move(citp_fdinfo* epoll_fdi, citp_fdinfo* fd_fdi,
                        citp_fdinfo* new_fdi, int fdt_locked)
{
  citp_fdinfo_ref(fd_fdi);
  citp_fdinfo_ref(new_fdi);
  __citp_epoll_on_smth(epoll_fdi, fd_fdi, new_fdi, fdt_locked);

}

/* See citp_epoll_on_handover_do which does the real work. */
void citp_epoll_on_handover(citp_fdinfo* epoll_fdi, citp_fdinfo* fd_fdi,
                            int fdt_locked)
{
  __citp_epoll_on_smth(epoll_fdi, fd_fdi, NULL, fdt_locked);
}

#if CI_CFG_EPOLL3
void citp_epoll_on_close(citp_fdinfo* epoll_fdi, citp_fdinfo* fd_fdi,
                         int fdt_locked)
{
  struct citp_epoll_member* eitem = NULL;
  struct citp_epoll_fd* ep = fdi_to_epoll(epoll_fdi);
  citp_socket* sock;
  ci_sb_epoll_state* epoll;
  ci_netif* ni;

  if( ! citp_fdinfo_is_socket(fd_fdi) )
    return;

  sock = fdi_to_socket(fd_fdi);
  ni = sock->netif;

  if( OO_PP_IS_NULL(sock->s->b.epoll) )
    return;

  oo_wqlock_lock(&ep->dead_stack_lock);
  if( ni != ep->home_stack )
    goto unlock;
  if( (sock->s->b.ready_lists_in_use & (1 << ep->ready_list)) == 0 )
    goto unlock;

  epoll = ci_ni_aux_p2epoll(ni, sock->s->b.epoll);
  eitem = CI_USER_PTR_GET(epoll->e[ep->ready_list].eitem);


  /* Only remove home members from the set here, because this hook is only
   * guaranteed to be called for home sockets as we only remember one epoll
   * set we've been added to.
   */
  if( eitem && (eitem->ready_list_id == ep->ready_list) ) {
    struct oo_p_dllink_state link = ci_sb_epoll_ready_link(ni, epoll,
                                                           ep->ready_list);
    Log_POLL(ci_log("%s: epoll_fd=%d fd=%d",
                    __FUNCTION__, fd_fdi->epoll_fd, fd_fdi->fd));
    /* At this point any of the eitem, sock buf, or fdinfo may still be in
     * use. As such we just add the socket to the dead sockets list here.
     * We can only free the eitem at a point where we hold the epoll lock,
     * if needed.  For now we just bung this on the dead list, to be
     * processed later.
     */
    fd_fdi->epoll_fd = -1;

    ci_netif_lock(ni);
    sock->s->b.ready_lists_in_use &=~ (1 << ep->ready_list);
    oo_p_dllink_del(ni, link);
    oo_p_dllink_init(ni, link);
    ci_netif_unlock(ni);

    ci_dllist_push(&ep->dead_stack_sockets, &eitem->dead_stack_link);
  }
unlock:
  oo_wqlock_unlock(&ep->dead_stack_lock, NULL);
}
#endif


ci_inline void
citp_ul_epoll_store_event(struct oo_ul_epoll_state*__restrict__ eps,
                          struct citp_epoll_member*__restrict__ eitem,
                          unsigned events)
{
  Log_VVPOLL(ci_log("%s: member=%llx events=%x", __FUNCTION__,
                    (long long) eitem->epoll_data.data.u64, events));

  ci_assert(eps->events_top - eps->events > 0);
  eps->events[0].events = events;
  eps->events[0].data = eitem->epoll_data.data;
  ++eps->events;
#if CI_CFG_TIMESTAMPING
  if( eps->ordering_info ) {
    citp_fdinfo* fdi = citp_ul_epoll_member_to_fdi(eitem);
    struct timespec zero = {0, 0};
    eps->ordering_info[0].oo_event.ts.tv_sec = 0;
    eps->ordering_info[0].oo_event.ts.tv_nsec = 0;
    ci_assert(fdi);
    eps->ordering_info[0].fdi = fdi;
    if( events & EPOLLIN )
      /* Grab the timestamp of the first data available. */
      citp_fdinfo_get_ops(fdi)->ordered_data(fdi, &zero,
                                        &eps->ordering_info[0].oo_event.ts,
                                        &eps->ordering_info[0].oo_event.bytes);
    ++eps->ordering_info;
  }
#endif

  ci_assert(eitem->item_list == &eps->ep->oo_sockets
#if CI_CFG_EPOLL3
            || eitem->item_list == &eps->ep->oo_stack_sockets
#endif
            );
  ci_dllist_remove_safe(&eitem->dllink);
  ci_assert_lt(eitem->fd, citp_fdtable.inited_count);
  if( eitem->epoll_data.events & (EPOLLONESHOT | EPOLLET) )
    eps->has_epollet = 1;
  if( eitem->epoll_data.events & EPOLLONESHOT ) {
    eitem->epoll_data.events = 0;
    if( ! citp_eitem_is_synced(eitem) )
      ++(eps->ep->epfd_syncs_needed);
  }
  ci_dllist_push_tail(eitem->item_list, &eitem->dllink);
}


int
citp_ul_epoll_find_events(struct oo_ul_epoll_state*__restrict__ eps,
                          struct citp_epoll_member*__restrict__ eitem,
                          unsigned events, ci_uint64 sleep_seq,
                          volatile ci_uint64* sleep_seq_p,
                          int* seq_mismatch)
{
  unsigned report = events;

  if( eitem->epoll_data.events & EPOLLET ) {
    ci_sleep_seq_t polled_sleep_seq;
    if( sleep_seq != *sleep_seq_p ) {
      *seq_mismatch = 1;
      return 0;
    }
    polled_sleep_seq.all = sleep_seq;
    Log_VVPOLL(ci_log("%s: EPOLLET fd=%d rx_seq=%d,%d tx_seq=%d,%d",
                      __FUNCTION__, eitem->fd,
                      eitem->reported_sleep_seq.rw.rx, polled_sleep_seq.rw.rx,
                      eitem->reported_sleep_seq.rw.tx, polled_sleep_seq.rw.tx));
    if( polled_sleep_seq.all == eitem->reported_sleep_seq.all )
      report = 0;
    else if( polled_sleep_seq.rw.rx == eitem->reported_sleep_seq.rw.rx )
      report &=~ OO_EPOLL_READ_EVENTS;
    else if( polled_sleep_seq.rw.tx == eitem->reported_sleep_seq.rw.tx )
      report &=~ OO_EPOLL_WRITE_EVENTS;
    eitem->reported_sleep_seq = polled_sleep_seq;
  }

  /* If we have some events to report, we should always report
   * the full mask of events. */
  if( report != 0 ) {
    citp_ul_epoll_store_event(eps, eitem, events);
    return 1;
  }
  else {
    return 0;
  }
}


#if CI_CFG_TIMESTAMPING
/* Gets the limiting timestamp for a netif, the earliest if the earliest
 * parameter is true, else the latest.
 */
static void citp_epoll_netif_limit(ci_netif* ni, struct timespec* ts_out,
                                   int earliest)
{
  ci_netif_state_nic_t* nsn = &ni->state->nic[0];
  int intf_i;
  int check = earliest ? -1 : 1;

  ts_out->tv_sec = nsn->last_rx_timestamp.tv_sec;
  ts_out->tv_nsec = nsn->last_rx_timestamp.tv_nsec;
  for( intf_i = 1; intf_i < oo_stack_intf_max(ni); ++intf_i ) {
    nsn = &ni->state->nic[intf_i];

    if( citp_oo_timespec_compare(&nsn->last_rx_timestamp, ts_out) == check ) {
      ts_out->tv_sec = nsn->last_rx_timestamp.tv_sec;
      ts_out->tv_nsec = nsn->last_rx_timestamp.tv_nsec;
    }
  }
}


static void citp_epoll_latest_rx(ci_netif* ni, struct timespec* ts_out)
{
  citp_epoll_netif_limit(ni, ts_out, 0);
}

static void citp_epoll_earliest_rx(ci_netif* ni, struct timespec* ts_out)
{
  citp_epoll_netif_limit(ni, ts_out, 1);
}


static void citp_epoll_get_ordering_limit(ci_netif* ni,
                                          struct timespec* limit_out)
{
  struct timespec base_ts;

  if( ni ) {
    if( CITP_OPTS.woda_single_if == 0 ) {
      ci_netif_lock(ni);
      citp_epoll_latest_rx(ni, &base_ts);
      ci_netif_poll_n(ni, 0x7fffffff);
      citp_epoll_earliest_rx(ni, limit_out);
      ci_netif_unlock(ni);

      /* It's always the case that the earliest RX across all interfaces
       * provides a safe limit. However, if we have one or more interfaces
       * that aren't receiving traffic our earliest RX stamp may be from a
       * very long time ago. To deal with that possibility we have a fallback
       * base_ts. Because we've done a full poll after that stamp we know that
       * it's safe too, so fall back to using base_ts if it's more recent than
       * limit. */
      if( citp_timespec_compare(&base_ts, limit_out) > 0 ) {
        limit_out->tv_sec = base_ts.tv_sec;
        limit_out->tv_nsec = base_ts.tv_nsec;
      }
    }
    else {
      /* In single interface WODA mode we don't need to ensure that all
       * interfaces have been polled, as ordering is only relative to other
       * traffic on the same interface.  This means that we just need to find
       * the latest timestamp after our poll, which is done before we start
       * putting together the ordered events list. This is necessary to ensure
       * that if a poll happens in another context we don't consider any data
       * that it finds, as we may have already finished processing some of our
       * sockets by that point.
       */
      ci_netif_lock(ni);
      ci_netif_poll(ni);
      citp_epoll_latest_rx(ni, limit_out);
      ci_netif_unlock(ni);
    }

    Log_VPOLL(ci_log("%s: %s poll limit %ld:%09lu", __FUNCTION__,
                     ni->state->pretty_name,
                     limit_out->tv_sec, limit_out->tv_nsec));
  }
}


static int citp_epoll_ordering_compare(const void* a, const void* b)
{
  return citp_timespec_compare(
                          &((const struct citp_ordering_info*)a)->oo_event.ts,
                          &((const struct citp_ordering_info*)b)->oo_event.ts);
}


static int
citp_epoll_sort_results(struct epoll_event*__restrict__ events,
                        struct epoll_event*__restrict__ wait_events,
                        struct onload_ordered_epoll_event* oo_events,
                        struct citp_ordering_info* ordering_info,
                        int ready_socks, int maxevents,
                        struct timespec* limit)
{
  int i;
  int ordered_events = 0;
  struct timespec next;
  struct timespec* next_data_limit;
  if( ready_socks < maxevents )
    maxevents = ready_socks;

  /* Update ordering info to point at the corresponding event, so that we know
   * which event it corresponds to after sorting.
   */
  for( i = 0; i < ready_socks; i++ )
    ordering_info[i].event = &wait_events[i];

  /* Sort list of ready sockets based on timestamp of next available data. */
  qsort(ordering_info, ready_socks, sizeof(*ordering_info),
        citp_epoll_ordering_compare);

  /* Working from head of list, copy ordered data into output array, stopping
   * when any of the following conditions are true:
   * - we have filled the output event array (i == maxevents)
   * - the timestamp for the current event is after the limit
   * - a ready socket has additional data that is earlier than the next socket's
   *
   * If a socket has additional data that is after the next socket's, but
   * still earlier than the limit, then reduce the limit to that timestamp.
   */
  Log_VPOLL(ci_log("%s: maxevents=%d limit %lus %dns", __func__, maxevents,
                   (unsigned long)limit->tv_sec, (int)limit->tv_nsec));
  for( i = 0; i < maxevents; i++ ) {
    /* If this event has a valid timestamp, then get ordering data for it. */
    if( ordering_info[i].oo_event.ts.tv_sec != 0 ) {
      Log_VPOLL(ci_log("%s: ev=%d ts %lus %dns", __func__, i,
                       (unsigned long)ordering_info[i].oo_event.ts.tv_sec,
                       (int)ordering_info[i].oo_event.ts.tv_nsec));
      /* If this event is after the limit, stop here. */
      if( citp_timespec_compare(limit, &ordering_info[i].oo_event.ts) < 0 )
        break;

      /* If there is another ready socket then use the start of their data
       * to bound the amount we claim as available from this socket.
       */
      if( (i + 1) < ready_socks && ordering_info[i + 1].oo_event.ts.tv_sec &&
          citp_timespec_compare(&ordering_info[i + 1].oo_event.ts, limit) < 0 )
        next_data_limit = &ordering_info[i + 1].oo_event.ts;
      else
        next_data_limit = limit;

      /* Get the number of bytes available in order, and the timestamp of the
       * first data that is after that.
       */
      if( ordering_info[i].fdi )
        citp_fdinfo_get_ops(ordering_info[i].fdi)->ordered_data(
                                       ordering_info[i].fdi, next_data_limit,
                                       &next, &ordering_info[i].oo_event.bytes);

      /* If we have more data then don't let us return anything beyond that. */
      if( next.tv_sec && citp_timespec_compare(&next, limit) < 0 )
        *limit = next;
    }

    memcpy(&events[i], ordering_info[i].event, sizeof(struct epoll_event));
    memcpy(&oo_events[i], &ordering_info[i].oo_event,
           sizeof(struct onload_ordered_epoll_event));
    ordered_events++;
  }
  Log_VPOLL(ci_log("%s: got %d ordered events", __FUNCTION__, ordered_events));

  return ordered_events;
}

int citp_epoll_ordered_wait(citp_fdinfo* fdi,
                            struct epoll_event*__restrict__ events,
                            struct onload_ordered_epoll_event* oo_events,
                            int maxevents, int timeout, const sigset_t *sigmask,
                            citp_lib_context_t *lib_context)
{
  int rc;
  struct citp_epoll_fd* ep = fdi_to_epoll(fdi);
  struct citp_epoll_member* eitem;
  citp_fdinfo* sock_fdi = NULL;
  citp_sock_fdi* sock_epi;
  ci_netif* ni;
  struct timespec limit_ts = {0, 0};
  struct citp_ordered_wait wait;
  int n_socks;
  ci_int64 timeout_hr = oo_epoll_ms_to_frc(timeout);

  Log_VPOLL(ci_log("%s(%d, max_ev=%d, timeout=%d) ul=%d dead=%d syncs=%d",
                   __FUNCTION__, fdi->fd, maxevents, timeout,
                   ! ci_dllist_is_empty(&ep->oo_sockets),
                   ! ci_dllist_is_empty(&ep->dead_sockets),
                   ep->epfd_syncs_needed));

 new_stack:
  ni = NULL;

  CITP_EPOLL_EP_LOCK(ep);

  /* We need to consider all accelerated sockets in the set.  We drop the lock
   * before polling the sockets, so it's possible to increase the size of the
   * set during this call, and not have all sockets considered.
   *
   * It's possible that the set also contains un-accelerated fds, so if
   * maxevents is bigger than the number of accelerated fds then we'll use
   * that value.
   *
   * If there are large numbers of sockets this can require a lot of memory,
   * perhaps resulting in the need for the process heap size to be increased.
   * When a large enough chunk of memory is freed glibc appears to reduce the
   * process heap size again.  When this happens it is very expensive,
   * resulting in pages being mapped and unmapped, and TLB flushes on each call
   * to onload_ordered_epoll_wait.  To avoid this we cache any memory allocated
   * for this purpose, and only realloc in cases where the size of the set has
   * grown.
   */
  n_socks = CI_MAX(maxevents,
#if CI_CFG_EPOLL3
                   ep->home_stack ? ep->oo_stack_sockets_n :
#endif
                   ep->oo_sockets_n);

  if( n_socks > ep->n_woda_events ) {
    ci_free(ep->ordering_info);
    ci_free(ep->wait_events);

    ep->ordering_info = ci_alloc(n_socks * sizeof(*ep->ordering_info));
    ep->wait_events = ci_alloc(n_socks * sizeof(*ep->wait_events));

    ep->n_woda_events = n_socks;
  }

  if( !ep->ordering_info || !ep->wait_events ) {
    CITP_EPOLL_EP_UNLOCK(ep, 0);
    citp_exit_lib(lib_context, FALSE);
    ci_free(ep->ordering_info);
    ep->ordering_info = NULL;
    ci_free(ep->wait_events);
    ep->wait_events = NULL;
    ep->n_woda_events = 0;
    errno = ENOMEM;
    return -1;
  }

#if CI_CFG_EPOLL3
  if( ep->home_stack ) {
    ni = ep->home_stack;
    citp_netif_add_ref(ni);
  }
  else
#endif
  if( ci_dllist_not_empty(&ep->oo_sockets) ) {
    ci_dllink *link;
    ci_assert(ep->oo_sockets_n);

    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_LOCK_RD();

    CI_DLLIST_FOR_EACH(link, &ep->oo_sockets) {
      eitem = CI_CONTAINER(struct citp_epoll_member, dllink, link);

      ci_assert_lt(eitem->fd, citp_fdtable.inited_count);

      /* Use the first orderable socket we find to select the netif to use
       * for ordering.
       */
      if(CI_LIKELY( (sock_fdi = citp_ul_epoll_member_to_fdi(eitem)) != NULL )) {
        if( citp_fdinfo_is_socket(sock_fdi) ) {
          sock_epi = fdi_to_sock_fdi(sock_fdi);
          ni = sock_epi->sock.netif;
          citp_netif_add_ref(ni);
          break;
        }
      }
    }

    if( citp_fdtable_not_mt_safe() )
      CITP_FDTABLE_UNLOCK_RD();
  }
  FDTABLE_ASSERT_VALID();

  CITP_EPOLL_EP_UNLOCK(ep, 0);

 again:
  citp_epoll_get_ordering_limit(ni, &limit_ts);

  wait.ordering_info = ep->ordering_info;
  wait.poll_again = 0;
  wait.ordering_stack = ni;
  /* citp_epoll_wait will do citp_exit_lib */
  rc = citp_epoll_wait(fdi, ep->wait_events, &wait,
                       n_socks, timeout_hr, sigmask, NULL, lib_context);
  if( rc < 0 )
    goto out;

  /* If we ended up going via the kernel we won't have the info we need for
   * the ordering - but the fds will be ready next time the user does a wait.
   */
  if( wait.poll_again ) {
    ci_int64 old_timeout_hr = wait.next_timeout_hr;
    ci_assert_gt(rc, 0);
    Log_VPOLL(ci_log("%s: need repoll at user level", __FUNCTION__));
    citp_reenter_lib(lib_context);
    if( ni == NULL )
      goto new_stack;
    citp_epoll_get_ordering_limit(ni, &limit_ts);

    rc = citp_epoll_wait(fdi, ep->wait_events, &wait, n_socks,
                         0, sigmask, NULL, lib_context);
    /* We've just called citp_epoll_wait() with timeout=0, and it may
     * have rewritten the wait.next_timeout_hr value.  Rewrite it back. */
    wait.next_timeout_hr = old_timeout_hr;
    if( rc == 0 && old_timeout_hr != 0 ) {
      citp_reenter_lib(lib_context);
      timeout_hr = wait.next_timeout_hr;
      Log_VPOLL(ci_log("%s: start over", __FUNCTION__));
      goto again;
    }
  }

  if( rc > 0 ) {
    /* ordering_info should be protected by the ep lock */
    CITP_EPOLL_EP_LOCK(ep);
    rc = citp_epoll_sort_results(events, ep->wait_events, oo_events,
                                 ep->ordering_info, rc, maxevents, &limit_ts);
    CITP_EPOLL_EP_UNLOCK(ep, 0);
    if( rc == 0 && wait.next_timeout_hr != 0 ) {
      citp_reenter_lib(lib_context);
      timeout_hr = wait.next_timeout_hr;
      Log_VPOLL(ci_log("%s: all events vanished.  Stack change?", __FUNCTION__));
      if( ni )
        citp_netif_release_ref(ni, 0);
      goto new_stack;
    }
  }

out:
  if( ni )
    citp_netif_release_ref(ni, 0);
  return rc;
}
#endif /* CI_CFG_TIMESTAMPING */

