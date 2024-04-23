/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file epoll_fd_b.c
** <L5_PRIVATE L5_HEADER >
** \author  oktet sasha
**  \brief  epoll implementation - B approach
**   \date  2011/02/14
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */

#include <ci/internal/transport_config_opt.h>


#define LPF      "citp_epollb:"

#include <ci/internal/transport_common.h>

#if CI_CFG_EPOLL2
#include <onload/ul/tcp_helper.h>
#include <onload/epoll.h>
#include "ul_epoll.h"

void oo_epollb_ctor(citp_epollb_fdi *epi)
{
  int i;
  epi->is_accel = 1;
  epi->kepfd = -1;

  epi->have_postponed = 0;
  for(i = 0; i < CI_CFG_EPOLL_MAX_POSTPONED; i++ )
    epi->postponed[i].fd = -1;
  epi->not_mt_safe = ! CITP_OPTS.ul_epoll_mt_safe;
  if( epi->not_mt_safe )
    pthread_mutex_init(&epi->lock_postponed, NULL);
}

static void citp_epollb_install_kepfd(citp_epollb_fdi *epi, int kepfd)
{
  ci_assert_equal(epi->kepfd, -1);
  epi->kepfd = kepfd;
  CITP_FDTABLE_LOCK();
  __citp_fdtable_reserve(epi->kepfd, 1);
  CITP_FDTABLE_UNLOCK();
}

static int
citp_epollb_postpone_syscall_pre(citp_epollb_fdi *epi,
                                 struct oo_epoll2_action_arg *op,
                                 citp_fdinfo *fd_fdi_using)
{
  if( epi->not_mt_safe )
    pthread_mutex_lock(&epi->lock_postponed);

  if( CI_LIKELY( epi->have_postponed ) ) { /* Recheck inside lock */
    int i;
    int max_i_used = -1;

    /* We are checking that the fds in the postponed list are correct.
     * But kernel will get them later, and we should protect these fds
     * from disappearing. not_mt_safe does not help - EF_EPOLL_MT_SAFE
     * description tells about "epoll calls are concurrency safe" */
    for( i = 0; i < CI_CFG_EPOLL_MAX_POSTPONED; i++ ) {
      int fd = epi->postponed[i].fd;
      citp_fdinfo *fd_fdi;
      if( fd == -1 ) continue;
      if( fd_fdi_using && fd == fd_fdi_using->fd )
        fd_fdi = fd_fdi_using;
      else {
        fd_fdi = citp_fdtable_lookup_noprobe(fd, 0);
        if( fd_fdi_using )
          ci_assert_nequal(fd_fdi, fd_fdi_using);
      }
      if( fd_fdi == NULL || fd_fdi->seq != epi->postponed[i].fdi_seq )
        epi->postponed[i].fd = -1;
      else {
        max_i_used = i;
        fd_fdi->epoll_fd = -1;
        fd_fdi->epoll_fd_seq = 0;
      }
      if( fd_fdi && fd_fdi != fd_fdi_using)
        citp_fdinfo_release_ref(fd_fdi, 0);
    }
    if( max_i_used >= 0 ) {
      CI_USER_PTR_SET(op->epoll_ctl, epi->postponed);
      op->epoll_ctl_n = max_i_used + 1;
      return 1; /* hold the lock, to be released after _post() */
    }
  }

  if( epi->not_mt_safe )
    pthread_mutex_unlock(&epi->lock_postponed);
  return 0;
}
static void citp_epollb_postpone_syscall_post(citp_epollb_fdi *epi, int rc)
{
  int i;
  if( rc == 0 ) {
    for( i = 0; i < CI_CFG_EPOLL_MAX_POSTPONED; i++ )
      epi->postponed[i].fd = -1;
    epi->have_postponed = 0;
  }
}

static void citp_epollb_do_postponed_ctl(citp_epollb_fdi *epi,
                                         citp_fdinfo *fd_fdi_using)
{
  struct oo_epoll2_action_arg op;
  int have_postponed;
  int rc;

  if( !epi->have_postponed )
    return;
  have_postponed = citp_epollb_postpone_syscall_pre(epi, &op, fd_fdi_using);
  if( !have_postponed)
    return;

  /* We really have postponed operations.  Push them. */
  op.kepfd = epi->kepfd;
  op.maxevents = 0;
  rc = ci_sys_ioctl(epi->fdinfo.fd, OO_EPOLL2_IOC_ACTION, &op);
  citp_epollb_postpone_syscall_post(epi, rc);
  if( epi->not_mt_safe )
    pthread_mutex_unlock(&epi->lock_postponed);

  if( CI_UNLIKELY( epi->kepfd == -1 && rc == 0 ) )
    citp_epollb_install_kepfd(epi, op.kepfd);
  return;
}

static citp_fdinfo* citp_epollb_dup(citp_fdinfo* orig_fdi)
{
  citp_epollb_fdi *old_epi = fdi_to_epollb_fdi(orig_fdi);
  citp_epollb_fdi *new_epi = CI_ALLOC_OBJ(citp_epollb_fdi);
  if( new_epi ) {
    /* It helps in case of dup2, but does not really help if both old_epi
     * and new_epi survive. */
    if( old_epi->have_postponed )
      citp_epollb_do_postponed_ctl(old_epi, NULL);

    citp_fdinfo_init(&new_epi->fdinfo, &citp_epollb_protocol_impl);
    oo_epollb_ctor(new_epi);

    return &new_epi->fdinfo;
  }
  return 0;
}

static void citp_epollb_dtor(citp_fdinfo* fdi, int fdt_locked)
{
  citp_epollb_fdi *epi = fdi_to_epollb_fdi(fdi);


  if( epi->not_mt_safe )
    pthread_mutex_destroy(&epi->lock_postponed);
  if( epi->kepfd != -1 ) {
    if( ! fdt_locked )
      CITP_FDTABLE_LOCK();
    ci_tcp_helper_close_no_trampoline(epi->kepfd);
    __citp_fdtable_reserve(epi->kepfd, 0);
    if( ! fdt_locked )
      CITP_FDTABLE_UNLOCK();
  }
}

int citp_epollb_ioctl(citp_fdinfo *fdi, int cmd, void *arg)
{
  citp_epollb_fdi *epi = fdi_to_epollb_fdi(fdi);
  /* Silly, but let's return the correct error */
  if( epi->kepfd != -1 )
    return ci_sys_ioctl(epi->kepfd, cmd, arg);
  errno = ENOTTY;
  return -1;
}

citp_protocol_impl citp_epollb_protocol_impl = {
  .type     = CITP_EPOLLB_FD,
  .ops      = {
    /* Important members -- users will realy call it. */
    .dup         = citp_epollb_dup,
    .dtor        = citp_epollb_dtor,
    .ioctl       = citp_epollb_ioctl,

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

int citp_epollb_create(int size, int flags)
{
  citp_epollb_fdi *epi;
  citp_fdinfo *fdi;
  int fd = -1;
  int kepfd;
  int rc = -1;

  Log_V(log(LPF "epollb_create()"));

  epi = CI_ALLOC_OBJ(citp_epollb_fdi);
  if( ! epi ) {
    Log_U(ci_log(LPF "%s: failed to allocate epi", __func__));
    errno = ENOMEM;
    goto fail1;
  }
  fdi = &epi->fdinfo;
  citp_fdinfo_init(fdi, &citp_epollb_protocol_impl);
  
  if( fdtable_strict() )  CITP_FDTABLE_LOCK();

  /* get new file descriptor */
  if( ef_onload_driver_open(&fd, OO_EPOLL_DEV,
                            flags & EPOLL_CLOEXEC) < 0 ) {
    Log_E(ci_log("%s: ERROR: failed to open onload epoll device errno=%d",
                 __FUNCTION__, errno));
    rc = fd;
    ci_log("%s: failed to open(%s) errno=%d", __func__,
           oo_device_name[OO_EPOLL_DEV], errno);
    if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
    goto fail2;
  }

  /* Protect the fdtable entry until we're done initialising. */
  citp_fdtable_new_fd_set(fd, fdip_busy, fdtable_strict());

  /* Create kernel epoll fd */
  kepfd = ci_sys_epoll_create_compat(size, flags, 1/*cloexec*/);
  if( kepfd < 0 ) {
    rc = kepfd;
    Log_E(ci_log(LPF "%s: ci_sys_epoll_create_compat(%d, %d, 1) "
                 "failed errno=%d", __func__, size, flags, errno));
    if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
    goto fail3;
  }
  if( ! fdtable_strict() ) CITP_FDTABLE_LOCK();
  __citp_fdtable_reserve(kepfd, 1);
  CITP_FDTABLE_UNLOCK();

  oo_epollb_ctor(epi);
  epi->kepfd = kepfd;
  {
    ci_fixed_descriptor_t fixed_kepfd = kepfd;
    rc = ci_sys_ioctl(fd, OO_EPOLL2_IOC_INIT, &fixed_kepfd);
    if( rc < 0 )
      goto fail4;
  }
  epi->is_accel = 0;

  /* We're ready.  Unleash us onto the world! */
  citp_fdtable_insert(fdi, fd, 0);

  Log_VSS(ci_log(LPF "%s(%d, %d) = %d  (kepfd=%d)", __func__,
                 size, flags, fd, kepfd));
  return fd;

fail4:
  CITP_FDTABLE_LOCK();
  __citp_fdtable_reserve(kepfd, 0);
  CITP_FDTABLE_UNLOCK();
  ci_sys_close(kepfd);
fail3:
  ci_tcp_helper_close_no_trampoline(fd);
  citp_fdtable_busy_clear(fd, fdip_unknown, 0);
fail2:
  CI_FREE_OBJ(epi);
fail1:
  return -2;
}


/* Return -errno; -ENOMEM meand that there are no space for postponed
 * operation and caller should do syscall.
 *
 * If op != NULL, we are going to pass this to kernel NOW.  It means:
 * - update op->epoll_ctl_n;
 * - no sanity checks: kernel will handle it;
 * - fd_fdi may be NULL.
 */
static int citp_epollb_postpone(citp_epollb_fdi *epi, citp_fdinfo *fd_fdi,
                                int eop, int fd, struct epoll_event *event,
                                struct oo_epoll2_action_arg *op)
{
  int i;
  int empty_idx = -1;

  if( op == NULL ) {
    /* Sanity check: do not add self, provide non-null events, correct op */
    if( fd < 0 )
      return -EINVAL;
    if( fd_fdi && (fd_fdi == &epi->fdinfo || fd_fdi->fd == epi->kepfd) )
      return -EINVAL;
    if( eop != EPOLL_CTL_ADD && eop != EPOLL_CTL_MOD && eop != EPOLL_CTL_DEL )
      return -EINVAL;
  }

  for( i = 0; i < CI_CFG_EPOLL_MAX_POSTPONED; i++ ) {
    if( epi->postponed[i].fd == fd ) {
      if( fd_fdi == NULL || epi->postponed[i].fdi_seq != fd_fdi->seq) {
        if( fd_fdi )
          epi->postponed[i].fdi_seq = fd_fdi->seq;
        epi->postponed[i].op = eop;
        if( eop != EPOLL_CTL_DEL )
          epi->postponed[i].event = *event;
        return 0;
      }
      if( eop == EPOLL_CTL_ADD ) {
        if( epi->postponed[i].op == EPOLL_CTL_DEL ) {
          epi->postponed[i].op = EPOLL_CTL_MOD;
          epi->postponed[i].event = *event;
          return 0;
        }
        else
          return -EEXIST;
      }
      else if( eop == EPOLL_CTL_MOD ) {
        if( epi->postponed[i].op == EPOLL_CTL_DEL )
          return -ENOENT;
        else {
          epi->postponed[i].event = *event;
          return 0;
        }
      }
      else if (eop == EPOLL_CTL_DEL ) {
        if( epi->postponed[i].op == EPOLL_CTL_ADD ) {
          epi->postponed[i].fd = -1;
          return 0;
        }
        else if (epi->postponed[i].op == EPOLL_CTL_MOD ) {
          epi->postponed[i].op = EPOLL_CTL_DEL;
          return 0;
        }
        else {
          return -ENOENT;
        }
      }
    }
    else if( epi->postponed[i].fd == -1 && empty_idx == -1 )
      empty_idx = i;
  }

  /* empty_idx is the index of empty slot. */
  if( empty_idx != -1 ) {
    if( fd_fdi && eop == EPOLL_CTL_ADD ) {
      /* Remember that this fd has been added to this epoll set.  This
       * is needed to handle accelerated fds being handed over to
       * kernel.
       */
      if( fd_fdi->epoll_fd == -1 ) {
        fd_fdi->epoll_fd = epi->fdinfo.fd;
        fd_fdi->epoll_fd_seq = epi->fdinfo.seq;
      }
      else {
        /* Already have a postponed add for this fd on another set, need to
         * push this straight to the kernel.
         */
        return -ENOMEM;
      }
    }
    epi->postponed[empty_idx].fd = fd;
    if( fd_fdi )
      epi->postponed[empty_idx].fdi_seq = fd_fdi->seq;
    epi->postponed[empty_idx].op = eop;
    if( eop != EPOLL_CTL_DEL )
      epi->postponed[empty_idx].event = *event;
    epi->have_postponed = 1;
    if( op && empty_idx >= op->epoll_ctl_n )
      op->epoll_ctl_n = empty_idx + 1;
    return 0;
  }

  /* No empty slots. Go push things to kernel */
  return -ENOMEM;
}

static int citp_epollb_ctl_do(citp_fdinfo* fdi, citp_fdinfo *fd_fdi,
                              int eop, int fd,
                              struct epoll_event *event)
{
  citp_epollb_fdi *epi = fdi_to_epollb_fdi(fdi);
  struct oo_epoll2_action_arg op;
  int rc;

  op.kepfd = epi->kepfd;
  op.maxevents = 0;

  if( epi->have_postponed &&
      citp_epollb_postpone_syscall_pre(epi, &op, fd_fdi) ) {
    /* If we have something postponed:
     * - we've already got the lock;
     * - we should add this fd to the list is possible */
    int rc2 = citp_epollb_postpone(epi, fd_fdi, eop, fd, event, &op);
    rc = ci_sys_ioctl(fdi->fd, OO_EPOLL2_IOC_ACTION, &op);
    citp_epollb_postpone_syscall_post(epi, epi->kepfd == -1 ? rc : 0);
    if( rc2 == -ENOMEM ) {
      /* Postponing went awry.  We've already pushed all previouly
       * postponed operations.  Let's push this one as well. */
      if( op.kepfd ) {
        op.rc = ci_sys_epoll_ctl(op.kepfd, eop, fd, event);
      }
      else {
        /* We hadn't got kepfd, and our ioctl didn't get us one, not a lot
         * we can do here.
         */
        ci_assert_le(rc, 0);
        op.rc = -ENOENT;
      }
    }
    else {
      op.rc = rc2;
    }
    if( epi->not_mt_safe )
      pthread_mutex_unlock(&epi->lock_postponed);
  }
  else {
    struct oo_epoll_item item;
    item.fd = fd;
    item.op = eop;
    if( eop != EPOLL_CTL_DEL )
      item.event = *event;
    CI_USER_PTR_SET(op.epoll_ctl, &item);
    op.epoll_ctl_n = 1;
    rc = ci_sys_ioctl(fdi->fd, OO_EPOLL2_IOC_ACTION, &op);
  }

  if( rc < 0 )
    return rc;

  if( epi->kepfd == -1 )
    citp_epollb_install_kepfd(epi, op.kepfd);

  /* ioctl returned 0 to copy op.kepfd back.  Now, we should check the
   * real errno and set it up. */
  if( op.rc < 0 ) {
    errno = -op.rc;
    return -1;
  }
  return 0;
}

int citp_epollb_ctl(citp_fdinfo* fdi, int eop, int fd,
                    struct epoll_event *event)
{
  citp_fdinfo *fd_fdi;
  citp_epollb_fdi *epi = fdi_to_epollb_fdi(fdi);

  /* With NULL events, return -EFAULT instead of crash */
  if( event == NULL && eop != EPOLL_CTL_DEL ) {
    errno = EFAULT;
    return -1;
  }

  /* OS fd - pass it through */
  fd_fdi = citp_fdtable_lookup(fd);
  if( fd_fdi == NULL ) {
    /* If we have some tasks to do, call our ioctl. */
    if( epi->have_postponed || epi->kepfd == -1 )
      return citp_epollb_ctl_do(fdi, NULL, eop, fd, event);
    else
      return ci_sys_epoll_ctl(epi->kepfd, eop, fd, event);
  }

  /* Reserved fd should not be added */
  if( fd_fdi == &citp_the_reserved_fd ) {
    citp_fdinfo_release_ref(fd_fdi, 0);
    errno = EBADF;
    return -1;
  }

  if( fd_fdi->protocol->type == CITP_EPOLLB_FD ) {
    citp_epollb_fdi *epi_low = fdi_to_epollb_fdi(fd_fdi);
    int low_fd = epi_low->kepfd;
    citp_fdinfo_release_ref(fd_fdi, 0);
    return ci_sys_epoll_ctl(epi->kepfd, eop, low_fd, event);
  }

  /* This is onload fd now. */
  epi->is_accel = 1;

#if CI_CFG_FD_CACHING
  /* fd_fdi->can_cache is only checked when all references to this fdi have
   * gone away, and only transitions to 0, so no need to worry about other
   * people fiddling with it as well.
   */
  if( eop == EPOLL_CTL_ADD )
    fd_fdi->can_cache = 0;
#endif

  /* If we postpone epoll_ctl calls, do it and exit */
  if( CITP_OPTS.ul_epoll_ctl_fast &&
      ( ! epi->not_mt_safe ||
        pthread_mutex_trylock(&epi->lock_postponed) == 0 ) ) {
    /* We call trylock here, since _lock() may get us to sleep.  And if we
     * are going to kernel, there is nothing time-critical: just do the
     * epoll_ctl in real. */
    int rc = citp_epollb_postpone(epi, fd_fdi, eop, fd, event, NULL);
    if( epi->not_mt_safe )
      pthread_mutex_unlock(&epi->lock_postponed);
    if( rc == 0 ) {
      citp_fdinfo_release_ref(fd_fdi, 0);
      return 0;
    }
    else if( rc != -ENOMEM ) {
      citp_fdinfo_release_ref(fd_fdi, 0);
      errno = -rc;
      return -1;
    }
    /* In case of ENOMEM, go forward */
  }

  if( eop == EPOLL_CTL_ADD || epi->have_postponed || epi->kepfd == -1 ) {
    int rc = citp_epollb_ctl_do(fdi, fd_fdi, eop, fd, event);
    citp_fdinfo_release_ref(fd_fdi, 0);
    return rc;
  }
  else {
    citp_fdinfo_release_ref(fd_fdi, 0);
    return ci_sys_epoll_ctl(epi->kepfd, eop, fd, event);
  }
}


int citp_epollb_wait(citp_fdinfo* fdi, struct epoll_event *events,
                     int maxevents, ci_int64 timeout_hr,
                     const sigset_t *sigmask, const struct timespec *ts,
                     citp_lib_context_t* lib_context)
{
  citp_epollb_fdi *epi = fdi_to_epollb_fdi(fdi);
  struct oo_epoll2_action_arg op;
  int rc;
  int have_postponed = 0;

  if( maxevents <= 0 ) {
    errno = EINVAL;
    return -1;
  }

  op.epoll_ctl_n = 0;
  if( epi->have_postponed )
    have_postponed = citp_epollb_postpone_syscall_pre(epi, &op, NULL);

  if( epi->kepfd != -1 && !epi->is_accel && !have_postponed) {

#if CI_LIBC_HAS_epoll_pwait2
    if( ts != NULL ) {
      return ci_sys_epoll_pwait2(fdi->fd, events, maxevents, ts, sigmask);
    }
    else
#endif /* CI_LIBC_HAS_epoll_pwait2 */
    {
      /* We can always call ci_sys_epoll_pwait, but not every kernel has it.
       * And from UL, there is no way to find the truth, since libc may know
       * about epoll_pwait(). */
      int timeout_ms = timeout_hr_to_ms(timeout_hr);
      if( sigmask )
        return ci_sys_epoll_pwait(epi->kepfd, events, maxevents, timeout_ms,
                                  sigmask);
      else
         return ci_sys_epoll_wait(epi->kepfd, events, maxevents, timeout_ms);
    }
  }

  op.kepfd = epi->kepfd;
  CI_USER_PTR_SET(op.events, events);
  op.maxevents = maxevents;
  op.timeout_hr = timeout_hr;
  CI_USER_PTR_SET(op.sigmask, sigmask);

  /* Set up spin_cycles. */
  if( oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_EPOLL_WAIT) )
    op.spin_cycles = citp.spin_cycles;
  else
    op.spin_cycles = 0;

  if( have_postponed || timeout_hr == 0 ) {
    /* If we are going to apply postponed epoll_ctls, we do it holding
     * the lock_postponed and fdtable lock.  So, we should not block.
     * From the other side, there is no need to exit the library when
     * non-blocking. */
    op.timeout_hr = 0;
    rc = ci_sys_ioctl(fdi->fd, OO_EPOLL2_IOC_ACTION, &op);
    if( have_postponed ) {
      citp_epollb_postpone_syscall_post(epi, epi->kepfd == -1 ? rc : 0);
      if( epi->not_mt_safe )
        pthread_mutex_unlock(&epi->lock_postponed);
    }
    if( timeout_hr == 0 || rc < 0 || op.rc != 0 )
      goto out;
    /* If timeout!=0 && op.rc==0, fall through to blocking syscall */
    op.timeout_hr = timeout_hr;
  }

  citp_exit_lib(lib_context, FALSE);
  rc = ci_sys_ioctl(fdi->fd, OO_EPOLL2_IOC_ACTION, &op);
  citp_reenter_lib(lib_context);

out:
  if( rc < 0 )
    return rc;
  if( epi->kepfd == -1 )
    citp_epollb_install_kepfd(epi, op.kepfd);
  if( op.rc < 0 ) {
    errno = -op.rc;
    return -1;
  }

  return op.rc;
}

void citp_epollb_on_handover(citp_fdinfo* epoll_fdi, citp_fdinfo* fd_fdi)
{
  /* We've handed [fd_fdi->fd] over to the kernel, but it may be registered
   * in an epoll set.  We have a workaroung in-kernel, but before we should
   * push all postponed epoll_ctls.
   */
  citp_epollb_do_postponed_ctl(fdi_to_epollb_fdi(epoll_fdi), fd_fdi);
}
#endif
