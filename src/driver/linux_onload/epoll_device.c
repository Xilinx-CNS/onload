/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file epoll_device.c
** <L5_PRIVATE L5_HEADER >
** \author  oktet sasha
**  \brief  /dev/onload_epoll char device implementation
**   \date  2011/03/07
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <ci/internal/transport_config_opt.h>

#include "onload_kernel_compat.h"
#include <onload/linux_onload_internal.h>
#include <onload/linux_onload.h>
#include <onload/tcp_helper_fns.h>
#include <onload/epoll.h>
#include <ci/driver/chrdev.h>
#include <linux/eventpoll.h>
#include <linux/poll.h>
#include <linux/unistd.h> /* for __NR_epoll_pwait */
#include "onload_internal.h"

/* This is needed for RHEL4 and similar vintage kernels */
#ifndef __MODULE_PARM_TYPE
#define __MODULE_PARM_TYPE(name, _type)                 \
  __MODULE_INFO(parmtype, name##type, #name ":" _type)
#endif

static int set_max_stacks(const char *val, 
                          const struct kernel_param *kp);
static unsigned epoll_max_stacks = CI_CFG_EPOLL_MAX_STACKS;
static const struct kernel_param_ops epoll_max_stacks_ops = {
  .set = set_max_stacks,
  .get = param_get_uint,
};
module_param_cb(epoll_max_stacks, &epoll_max_stacks_ops, 
                &epoll_max_stacks, S_IRUGO | S_IWUSR);
__MODULE_PARM_TYPE(epoll_max_stacks, "uint");
MODULE_PARM_DESC(epoll_max_stacks,
"Maximum number of onload stacks handled by single epoll object.");


#if CI_CFG_EPOLL2
/*************************************************************
 * EPOLL2 private file data
 *************************************************************/
struct oo_epoll2_private {
  struct file  *kepo;
  int           do_spin;
};
#endif


/*************************************************************
 * EPOLL1 private file data
 *************************************************************/
struct oo_epoll1_private {
  /* Shared memory */
  struct oo_epoll1_shared *sh;
  struct page *page; /*!< shared page used for shared memory */

  /* Poll table and workqueue, used in callback */
  poll_table pt;
  wait_queue_entry_t wait;
  wait_queue_head_t *whead;

  /* kernel epoll file */
  struct file *os_file;

#if CI_CFG_EPOLL3
  /* home stack support */
  tcp_helper_resource_t* home_stack;
  int ready_list;
  ci_uint32 flags;
#define OO_EPOLL1_FLAG_HOME_STACK_CHANGED 1
  ci_waitable_t home_w;
#endif
};

/*************************************************************
 * EPOLL common private file data
 *************************************************************/
struct oo_epoll_private {
  int type;
#define OO_EPOLL_TYPE_UNKNOWN   0
#define OO_EPOLL_TYPE_1         1
#if CI_CFG_EPOLL2
#define OO_EPOLL_TYPE_2         2
#endif

  spinlock_t    lock;
  tcp_helper_resource_t** stacks;

  union {
    struct oo_epoll1_private p1;
#if CI_CFG_EPOLL2
    struct oo_epoll2_private p2;
#endif
  } p;
};


static int oo_epoll_init_common(struct oo_epoll_private *priv)
{
  int size = sizeof(priv->stacks[0]) * epoll_max_stacks;

  priv->stacks = kmalloc(size, GFP_KERNEL);
  if( priv->stacks == NULL )
    return -ENOMEM;
  memset(priv->stacks, 0, size);
  spin_lock_init(&priv->lock);
  return 0;
}

static int oo_epoll_add_stack(struct oo_epoll_private* priv,
                              tcp_helper_resource_t* fd_thr)
{
  unsigned i;
  int rc;

  /* Common case is that we already know about this stack, so make that
   * fast.
   */
  for( i = 0; i < epoll_max_stacks; ++i )
    if( priv->stacks[i] == fd_thr )
      return 1;
    else if(unlikely( priv->stacks[i] == NULL ))
      break;

  /* Try to add stack.  NB. May already be added by concurrent thread. */
  spin_lock(&priv->lock);
  for( i = 0; i < epoll_max_stacks; ++i ) {
    if( priv->stacks[i] == fd_thr )
      break;
    if( priv->stacks[i] != NULL )
      continue;
    priv->stacks[i] = fd_thr;
    rc = oo_thr_ref_get(fd_thr->ref, OO_THR_REF_BASE);
    spin_unlock(&priv->lock);
    return rc == 0;
  }
  spin_unlock(&priv->lock);
  return 0;
}

static void oo_epoll_release_common(struct oo_epoll_private* priv)
{
  int i;

  /* Release references to all stacks */
  for( i = 0; i < epoll_max_stacks; i++ ) {
    if( priv->stacks[i] == NULL )
      break;
    oo_thr_ref_drop(priv->stacks[i]->ref, OO_THR_REF_BASE);
    priv->stacks[i] = NULL;
  }
  kfree(priv->stacks);
}

static int set_max_stacks(const char *val, 
                          const struct kernel_param *kp)
{
  int rc = param_set_uint(val, kp);
  if( rc != 0 )
    return rc;

  /* do not accept 0 value: use default instead */
  if( epoll_max_stacks == 0 )
    epoll_max_stacks = CI_CFG_EPOLL_MAX_STACKS;

  return 0;
}

#define OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni)      \
  for( i = 0; i < epoll_max_stacks; ++i )              \
    if( (thr = (priv)->stacks[i]) == NULL )            \
      break;                                           \
    else if(unlikely( thr->ref[OO_THR_REF_APP] == 0 )) \
      continue;                                        \
    else if( (ni = &thr->netif) || 1 )


#if CI_CFG_EPOLL2
/*************************************************************
 * EPOLL2-specific code
 *************************************************************/
static int oo_epoll2_init(struct oo_epoll_private *priv,
                         ci_fixed_descriptor_t kepfd)
{
  struct file  *kepo = fget(kepfd);
  int rc;

  if( kepo == NULL )
    return -EBADF;

  rc = oo_epoll_init_common(priv);
  if( rc != 0 )
    return rc;

  priv->p.p2.kepo = kepo;

  priv->type = OO_EPOLL_TYPE_2;
  return 0;
}


static int oo_epoll2_ctl(struct oo_epoll_private *priv, int op_kepfd,
                         int op_op, int op_fd, struct epoll_event *op_event)
{
  tcp_helper_resource_t *fd_thr;
  struct file *file;
  int rc;
  ci_uint32 fd_sock_id;
  citp_waitable *fd_w;

  /* We are interested in ADD only */
  if( op_op != EPOLL_CTL_ADD )
    return efab_linux_sys_epoll_ctl(op_kepfd, op_op, op_fd, op_event);

  /* system poll() and friends use fget_light(), which is cheap.
   * But they do not export fget_light to us, so we have to use fget(). */
  file = fget(op_fd);
  if(unlikely( file == NULL ))
    return -EBADF;

  /* Check for the dead circle.
   * We should check that we are not adding ourself. */
  if(unlikely( file->private_data == priv )) {
    fput(file);
    return -EINVAL;
  }

  /* Is op->fd ours and if yes, which netif it has? */
  /* Fixme: epoll fd - do we want to accelerate something? */
  if( file->f_op != &linux_tcp_helper_fops_udp &&
      file->f_op != &linux_tcp_helper_fops_tcp ) {
    if( ( file->f_op == &linux_tcp_helper_fops_pipe_reader ||
          file->f_op == &linux_tcp_helper_fops_pipe_writer ) ) {
      priv->p.p2.do_spin = 1;
    }
#if CI_CFG_EPOLL2
    else
    if( file->f_op == &oo_epoll_fops &&
        ((struct oo_epoll_private *)file->private_data)->type ==
        OO_EPOLL_TYPE_2 ) {
      /* Protect from the loops.  Kernel does it.  Our UL must provide
       * the OS epoll fd in such a case. */
      fput(file);
      return -ELOOP;
    }
#endif

    fput(file);
    return efab_linux_sys_epoll_ctl(op_kepfd, op_op, op_fd, op_event);
  }

  /* Onload socket here! */
  fd_thr = ((ci_private_t *)file->private_data)->thr;
  fd_sock_id = ((ci_private_t *)file->private_data)->sock_id;
  priv->p.p2.do_spin = 1;

  if(unlikely( ! oo_epoll_add_stack(priv, fd_thr) )) {
    static int printed;
    if( !printed )
      ci_log("Can't add stack %d to epoll set: consider "
             "increasing epoll_max_stacks module option", fd_thr->id);
    /* fall through to sys_epoll_ctl() without interrupt */
  }

  /* Let kernel add fd to the epoll set, but ask endpoint to avoid enabling
   * interrupts.
   * And we keep file ref while using fd_w to avoid nasty things. */
  fd_w = SP_TO_WAITABLE(&fd_thr->netif, fd_sock_id);
  ci_bit_set(&fd_w->sb_aflags, CI_SB_AFLAG_AVOID_INTERRUPTS_BIT);
  rc = efab_linux_sys_epoll_ctl(op_kepfd, op_op, op_fd, op_event);
  ci_bit_clear(&fd_w->sb_aflags, CI_SB_AFLAG_AVOID_INTERRUPTS_BIT);
  fput(file);

  return rc;
}

/* Apply all postponed epoll_ctl and ignore the results (just print
 * a message), since there is nothing to do now. */
static int oo_epoll2_apply_ctl(struct oo_epoll_private *priv,
                               struct oo_epoll2_action_arg *op)
{
  struct oo_epoll_item postponed_k[CI_CFG_EPOLL_MAX_POSTPONED];
  struct oo_epoll_item *postponed_u = CI_USER_PTR_GET(op->epoll_ctl);
  int i;
  int rc = 0;

  if( op->epoll_ctl_n > CI_CFG_EPOLL_MAX_POSTPONED )
    return -EFAULT;
  if( copy_from_user(postponed_k, postponed_u,
                     sizeof(struct oo_epoll_item) * op->epoll_ctl_n) )
    return -EFAULT;

  for( i = 0; i < op->epoll_ctl_n; i++ ) {
    if(  postponed_k[i].fd != -1 ) {
      rc = oo_epoll2_ctl(priv, op->kepfd, postponed_k[i].op,
                         postponed_k[i].fd, &postponed_u[i].event);
      if( rc && (i != op->epoll_ctl_n - 1 || op->maxevents != 0) ) {
        ci_log("postponed epoll_ctl(fd=%d) returned error %d; ignoring",
               (int)postponed_k[i].fd, rc);
        ci_log("consider disabling EF_EPOLL_CTL_FAST to get "
               "the correct behaviour");
      }
    }
  }

  /* Return the last rc */
  return rc;
}


static void oo_epoll2_wait(struct oo_epoll_private *priv,
                           struct oo_epoll2_action_arg *op)
{
  /* This function uses oo_timesync_cpu_khz but we do not want to
   * block here for it to stabilize.  So we already blocked in
   * oo_epoll_fop_open().
   */

  ci_uint64 start_frc = 0, now_frc = 0; /* =0 to make gcc happy */
  tcp_helper_resource_t* thr;
  ci_netif* ni;
  unsigned i;
  ci_int32 timeout = op->timeout;

  /* Get the start of time. */
  if( timeout > 0 || ( timeout < 0 && op->spin_cycles ) )
    ci_frc64(&start_frc);

  /* Declare that we are spinning - even if we are just polling */
  OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni)
    ci_atomic32_inc(&ni->state->n_spinners);

  /* Poll each stack for events */
  op->rc = -ENOEXEC; /* impossible value */
  OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni) {
    if( ci_netif_may_poll(ni) && ci_netif_has_event(ni) &&
        ci_netif_trylock(ni) ) {
      int did_wake;
      ni->state->poll_did_wake = 0;
      ci_netif_poll(ni);
      did_wake = ni->state->poll_did_wake;
      ci_netif_unlock(ni);

      /* Possibly, we've got necessary event.  If true, exit */
      if( did_wake ) {
        op->rc = efab_linux_sys_epoll_wait(op->kepfd,
                                           CI_USER_PTR_GET(op->events),
                                           op->maxevents, 0);
        if( op->rc != 0 )
          goto do_exit;
      }
    }
  }

  /* Do we have anything to do? */
  if( op->rc == -ENOEXEC ) {
    /* never called sys_epoll_wait() - do it! */

    op->rc = efab_linux_sys_epoll_wait(op->kepfd, CI_USER_PTR_GET(op->events),
                                       op->maxevents, 0);
  }
  if( op->rc != 0 || timeout == 0 )
    goto do_exit;

  /* Fixme: eventually, remove NO_USERLAND stacks from this list.
   * Here is a good moment: we are going to spin or block, so there are
   * a lot of time.  But avoid locking! */

  /* Spin for a while. */
  if( op->spin_cycles ) {
    ci_uint64 schedule_frc;
    ci_uint64 max_spin = op->spin_cycles;
    int spin_limited_by_timeout = 0;
    ci_assert(start_frc);

    if( timeout > 0) {
      ci_uint64 max_timeout_spin = (ci_uint64)timeout * oo_timesync_cpu_khz;
      if( max_timeout_spin <= max_spin ) {
        max_spin = max_timeout_spin;
        spin_limited_by_timeout = 1;
      }
    }

    /* spin */
    now_frc = schedule_frc = start_frc;
    do {
      if(unlikely( signal_pending(current) )) {
        op->rc = -EINTR; /* epoll_wait returns EINTR, not ERESTARTSYS! */
        goto do_exit;
      }

      OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni) {
#if CI_CFG_SPIN_STATS
        ni->state->stats.spin_epoll_kernel++;
#endif
        if( ci_netif_may_poll(ni) &&
            ci_netif_need_poll_spinning(ni, now_frc) &&
            ci_netif_trylock(ni) ) {
          ci_netif_poll(ni);
          ci_netif_unlock(ni);
        }
      }

      op->rc = efab_linux_sys_epoll_wait(op->kepfd, CI_USER_PTR_GET(op->events),
                                         op->maxevents, 0);
      if( op->rc != 0 )
        goto do_exit;

      ci_frc64(&now_frc);
      if(unlikely( now_frc - schedule_frc > oo_timesync_cpu_khz )) {
        schedule(); /* schedule() every 1ms */
        schedule_frc = now_frc;
      }
      else
        ci_spinloop_pause();
    } while( now_frc - start_frc < max_spin );

    if( spin_limited_by_timeout )
      goto do_exit;
  }

  /* Even without spinning, netif_poll for 4 netifs takes some time.
   * Count it. */
  if( timeout > 0 ) {
    ci_uint64 spend_ms;
    if( ! op->spin_cycles )
      ci_frc64(&now_frc); /* In spin case, re-use now_frc value */
    spend_ms = now_frc - start_frc;
    do_div(spend_ms, oo_timesync_cpu_khz);
    ci_assert_ge((int)spend_ms, 0);
    if( timeout > (int)spend_ms ) {
      timeout -= spend_ms;
    }
    else
      goto do_exit;
  }

  /* Going to block: enable interrupts; reset spinner flag */
  OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni) {
    ci_atomic32_dec(&ni->state->n_spinners);
    tcp_helper_request_wakeup(thr);
    CITP_STATS_NETIF_INC(&thr->netif, muxer_primes);
  }

  /* Block */

  op->rc = efab_linux_sys_epoll_wait(op->kepfd, CI_USER_PTR_GET(op->events),
                                     op->maxevents, timeout);
  return;

do_exit:
  OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni)
    ci_atomic32_dec(&ni->state->n_spinners);
  return;
}


static int oo_epoll2_action(struct oo_epoll_private *priv,
                            struct oo_epoll2_action_arg *op)
{
  sigset_t ksigmask, sigsaved;
  int return_zero = false;

  op->rc = 0;

  /* Restore kepfd if necessary */
  if(unlikely( op->kepfd == -1 )) {
    op->kepfd = get_unused_fd_flags(O_CLOEXEC);
    if( op->kepfd < 0 )
      return op->kepfd;
    /* We've restored kepfd.  Now we should return 0! */
    return_zero = true;

    get_file(priv->p.p2.kepo);
    fd_install(op->kepfd, priv->p.p2.kepo);
  }

  /* Call all postponed epoll_ctl calls; ignore rc. */
  if( op->epoll_ctl_n )
    op->rc = oo_epoll2_apply_ctl(priv, op);

  if( op->maxevents ) {
    if( CI_USER_PTR_GET(op->sigmask) ) {
      if (copy_from_user(&ksigmask, CI_USER_PTR_GET(op->sigmask),
                         sizeof(ksigmask))) {
        if( return_zero ) {
          op->rc = -EFAULT;
          return 0;
        }
        else
          return -EFAULT;
      }
      sigdelsetmask(&ksigmask, sigmask(SIGKILL) | sigmask(SIGSTOP));
      sigprocmask(SIG_SETMASK, &ksigmask, &sigsaved);
    }

    if( priv->p.p2.do_spin )
      oo_epoll2_wait(priv, op);
    else {
      op->rc = efab_linux_sys_epoll_wait(op->kepfd,
                                         CI_USER_PTR_GET(op->events),
                                         op->maxevents, op->timeout);
    }

    if( CI_USER_PTR_GET(op->sigmask) ) {
      if (op->rc == -EINTR) {
        memcpy(&current->saved_sigmask, &sigsaved, sizeof(sigsaved));
/* Must check for both symbols: see def'n of EFRM_HAVE_SET_RESTORE_SIGMASK. */
#if defined(HAVE_SET_RESTORE_SIGMASK) || \
    defined(EFRM_HAVE_SET_RESTORE_SIGMASK) || \
    defined(EFRM_HAVE_SET_RESTORE_SIGMASK1)
        set_restore_sigmask();
#else
        set_thread_flag(TIF_RESTORE_SIGMASK);
#endif
      }
      else {
        sigprocmask(SIG_SETMASK, &sigsaved, NULL);
      }
    }
  }

  if( return_zero || op->rc >= 0 )
    return 0;
  else
    return op->rc;
}

static void oo_epoll2_release(struct oo_epoll_private *priv)
{
  ci_assert(priv);

  /* Release KEPO */
  if( priv->p.p2.kepo )
    fput(priv->p.p2.kepo);

  oo_epoll_release_common(priv);

}

static unsigned oo_epoll2_poll(struct oo_epoll_private* priv,
                               poll_table* wait)
{
  /* Fixme: poll all netifs? */
  return priv->p.p2.kepo->f_op->poll(priv->p.p2.kepo, wait);
}
#endif


/*************************************************************
 * EPOLL1-specific code
 *************************************************************/
static void oo_epoll1_set_shared_flag(struct oo_epoll1_private* priv, int set)
{
  ci_uint32 tmp, new;
  do {
    tmp = priv->sh->flag;
    if( set )
      new = (tmp + (1 << OO_EPOLL1_FLAG_SEQ_SHIFT)) | OO_EPOLL1_FLAG_EVENT;
    else
      new = tmp & ~OO_EPOLL1_FLAG_EVENT;
  } while( ci_cas32u_fail(&priv->sh->flag, tmp, new) );
}

static int oo_epoll1_callback(wait_queue_entry_t *wait, unsigned mode,
                              int sync, void *key)
{
  struct oo_epoll1_private* priv = container_of(wait,
                                                struct oo_epoll1_private,
                                                wait);
  oo_epoll1_set_shared_flag(priv, 1/*set*/);
  return 0;
}
static void oo_epoll1_queue_proc(struct file *file,
                                 wait_queue_head_t *whead,
                                 poll_table *pt)
{
  struct oo_epoll1_private* priv = container_of(pt,
                                                struct oo_epoll1_private,
                                                pt);
  init_waitqueue_func_entry(&priv->wait, oo_epoll1_callback);
  priv->whead = whead;
  add_wait_queue(whead, &priv->wait);
}

/* Allocate the shared memory to notify UL about OS socket events */
static int oo_epoll1_setup_shared(struct oo_epoll1_private* priv)
{
  int rc;

#ifdef __GFP_ZERO
  priv->page = alloc_page(GFP_KERNEL|__GFP_ZERO);
#else
  priv->page = alloc_page(GFP_KERNEL);
#endif
  if( priv->page == NULL )
    return -ENOMEM;
  priv->sh = page_address(priv->page);
#ifndef __GFP_ZERO
  memset(priv->sh, 0, PAGE_SIZE);
#endif

  /* Create epoll fd */

  priv->sh->epfd = efab_linux_sys_epoll_create1(EPOLL_CLOEXEC);
  if( (int)priv->sh->epfd < 0 ) {
    rc = priv->sh->epfd;
    goto fail1;
  }
  priv->os_file = fget(priv->sh->epfd);
  if( priv->os_file == NULL ) {
    rc = -EINVAL;
    goto fail2;
  }

  /* Install callback */
  init_poll_funcptr(&priv->pt, oo_epoll1_queue_proc);
  priv->os_file->f_op->poll(priv->os_file, &priv->pt);

  return 0;

fail2:
  efab_linux_sys_close(priv->sh->epfd);
fail1:
  priv->sh = NULL;
  __free_page(priv->page);
  return rc;
}

static int oo_epoll1_mmap(struct oo_epoll1_private* priv,
                          struct vm_area_struct* vma)
{
  if (vma->vm_end - vma->vm_start != PAGE_SIZE)
    return -EINVAL;
  if (vma->vm_flags & VM_WRITE)
    return -EPERM;

  /* Map memory to user */
  if( priv->page == NULL ||
      remap_pfn_range(vma, vma->vm_start, page_to_pfn(priv->page),
                      PAGE_SIZE, vma->vm_page_prot) < 0) {
    return -EIO;
  }

  return 0;
}

static int oo_epoll1_release(struct oo_epoll_private* priv)
{
  struct oo_epoll1_private* priv1 = &priv->p.p1;

  ci_assert(priv1->whead);
  remove_wait_queue(priv1->whead, &priv1->wait);

  fput(priv1->os_file);

  __free_page(priv1->page);

#if CI_CFG_EPOLL3
  if( priv1->home_stack )
    ci_netif_put_ready_list(&priv1->home_stack->netif, priv1->ready_list);
#endif

  oo_epoll_release_common(priv);

  return 0;
}

static int oo_epoll1_ctl(struct oo_epoll1_private *priv,
                           struct oo_epoll1_ctl_arg *op)
{
  int rc = efab_linux_sys_epoll_ctl(op->epfd, op->op,
                                    op->fd, CI_USER_PTR_GET(op->event));
  /* It's valid to have already added the fd to the os epoll set. */
  if( rc == 0 || rc == -EEXIST )
    return efab_linux_sys_epoll_ctl(priv->sh->epfd, op->op,
                                    op->fd, CI_USER_PTR_GET(op->event));
  return rc;
}

static int oo_epoll1_wait(struct oo_epoll1_private *priv,
                          struct oo_epoll1_wait_arg *op)
{
  int rc = 0;

  /* We are going to handle all EPOLLET and EPOLLONESHOT events -
   * remove OO_EPOLL1_FLAG_EVENT flag from the shared page. */
  oo_epoll1_set_shared_flag(priv, 0/*unset*/);

  op->rc = efab_linux_sys_epoll_wait(priv->sh->epfd,
                                     CI_USER_PTR_GET(op->events),
                                     op->maxevents, 0/*timeout*/);
  if( op->rc < 0 )
    rc = op->rc;

  /* We have not handled all events because they are level-triggered or
   * because maxevents valus is too small. Set the OO_EPOLL1_FLAG_EVENT
   * flag back. */
  if( priv->os_file->f_op->poll(priv->os_file, NULL) )
    oo_epoll1_set_shared_flag(priv, 1/*set*/);

  return rc;
}

#if CI_CFG_EPOLL3
static void oo_epoll1_set_home_stack(struct oo_epoll1_private* priv,
                                     tcp_helper_resource_t* thr, int ready_list)
{
  tcp_helper_resource_t* old_thr = priv->home_stack;
  int old_ready_list = priv->ready_list;

  /* We do not lock home_stack field.  It UL corrupts it - is is too bad
   * for this UL, because we'll malfunction but never crash.
   * Behaving UL has epoll lock to protect it from simultaneous changes of
   * the home stack. */
  priv->home_stack = thr;
  priv->ready_list = ready_list;

  priv->flags = OO_EPOLL1_FLAG_HOME_STACK_CHANGED;
  /* We never release stacks after oo_epoll_add_stack(), so we definitely
   * keep a reference to old_thr. */
  if( old_thr != NULL )
    ci_waitable_wakeup_all(&old_thr->ready_list_waitqs[old_ready_list]);
  else
    ci_waitable_wakeup_all(&priv->home_w);
}
#endif

static void oo_epoll_prime_all_stacks(struct oo_epoll_private* priv)
{
  int i;
  tcp_helper_resource_t* thr;
  ci_netif* ni;
  
  OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni) {
    tcp_helper_request_wakeup(thr);
    ci_frc64(&thr->netif.state->last_sleep_frc);
    CITP_STATS_NETIF_INC(&thr->netif, muxer_primes);
  }
}

#if CI_CFG_EPOLL3
/* It is a f_op->poll() like function, but we poll from oo_epoll1_block_on()
 * only, so there is no need to propogate it as such. */
/* Fixme: get rid of f_op->poll() prototype, and call
 * add_wait_queue(this_wq, ept.wq[0]) directly. */
static unsigned oo_epoll1_poll(struct file* filp, poll_table* wait)
{
  struct oo_epoll_private *priv = filp->private_data;
  tcp_helper_resource_t* thr = priv->p.p1.home_stack;
  int ready_list = priv->p.p1.ready_list;
  unsigned mask = 0;

  if( thr ) {
    ci_atomic32_or(&thr->netif.state->ready_list_flags[ready_list],
                   CI_NI_READY_LIST_FLAG_WAKE);
    poll_wait(filp, &thr->ready_list_waitqs[ready_list].wq, wait);

    mask = efab_tcp_helper_ready_list_events(thr, ready_list);
    /* no need to prime the stack - it is done
     * from oo_epoll_prime_all_stacks() */
  }
  else
    poll_wait(filp, &priv->p.p1.home_w.wq, wait);

  return mask;
}
#endif

struct oo_epoll_poll_table {
  poll_table pt;
  wait_queue_entry_t wq[2];
  wait_queue_head_t* w[2];
  struct task_struct* task;
  struct file* filp;
  int rc;
};

static void oo_epoll1_block_on_callback(struct file* filp,
                                        wait_queue_head_t* w,
                                        poll_table* pt)
{
  struct oo_epoll_poll_table* ept;
  int i = 0;

  ept = container_of(pt, struct oo_epoll_poll_table, pt);
  if( filp != ept->filp )
    i = 1;

  ept->w[i] = w;
  add_wait_queue(w, &ept->wq[i]);
}

static inline int oo_epoll1_wake_home_callback(wait_queue_entry_t* wait,
                                               unsigned mode, int sync,
                                               void* key)
{
  struct oo_epoll_poll_table* ept;

  ept = container_of(wait, struct oo_epoll_poll_table, wq[0]);
  ept->rc |= OO_EPOLL1_EVENT_ON_HOME;
  return wake_up_process(ept->task);
}
static inline int oo_epoll1_wake_other_callback(wait_queue_entry_t* wait,
                                                unsigned mode, int sync,
                                                void* key)
{
  struct oo_epoll_poll_table* ept;

  ept = container_of(wait, struct oo_epoll_poll_table, wq[1]);
  ept->rc |= OO_EPOLL1_EVENT_ON_OTHER;
  return wake_up_process(ept->task);
}

/* this is essentially sys_poll([home_filp,other_filp], timeout_ms) */
static int oo_epoll1_block_on(struct file* home_filp,
                              struct file* other_filp,
                              ci_uint64 timeout_us)
{
  struct oo_epoll_poll_table ept;
  int rc, ret = 0;

  ept.rc = 0;
  ept.filp = home_filp;
  ept.task = current;
  ept.w[0] = ept.w[1] = NULL;
  init_poll_funcptr(&ept.pt, oo_epoll1_block_on_callback);
#if CI_CFG_EPOLL3
  init_waitqueue_func_entry(&ept.wq[0], oo_epoll1_wake_home_callback);

  rc = oo_epoll1_poll(home_filp, &ept.pt);

  if( rc != 0 ) {
    ret = OO_EPOLL1_EVENT_ON_HOME;
    rc = other_filp->f_op->poll(other_filp, NULL);
    if( rc )
      ret |= OO_EPOLL1_EVENT_ON_OTHER;
  }
  else
#endif
  {
    init_waitqueue_func_entry(&ept.wq[1], oo_epoll1_wake_other_callback);
    rc = other_filp->f_op->poll(other_filp, &ept.pt);
    if( rc )
      ret = OO_EPOLL1_EVENT_ON_OTHER;
    else {
      oo_epoll_prime_all_stacks(home_filp->private_data);
      set_current_state(TASK_INTERRUPTIBLE);
      if( ept.rc == 0 ) {
        ktime_t kt;
        /* Totally arbitrary heuristic for slack, based on the guess that
         * applications waiting for a short amount of time want more accurate
         * timing. This is equivalent to select_estimate_accuracy() in the
         * kernel but much less sophisticated - we assume that all apps using
         * Onload want pretty good timing. Note that Linux will tend to wait
         * for the total timeout+slack if there's no other reason for it to
         * wake. */
        int slack_ns = timeout_us < 10000 ? 0 : 10000;
        kt = ktime_set(0, timeout_us * 1000);
        schedule_hrtimeout_range(&kt, slack_ns, HRTIMER_MODE_REL);
      }
      __set_current_state(TASK_RUNNING);
      ret = ept.rc;
    }
  }

  if( ept.w[0] != NULL )
    remove_wait_queue(ept.w[0], &ept.wq[0]);
  if( ept.w[1] != NULL )
    remove_wait_queue(ept.w[1], &ept.wq[1]);

  return ret;
}

#if CI_CFG_EPOLL3
static int oo_epoll_has_event(struct file* filp)
{
  struct oo_epoll_private *priv = filp->private_data;
  int i;
  tcp_helper_resource_t* thr;
  ci_netif* ni;

  OO_EPOLL_FOR_EACH_STACK(priv, i, thr, ni) {
    if( ci_netif_has_event(ni) )
      return OO_EPOLL1_EVENT_ON_EVQ | (
             (thr == priv->p.p1.home_stack) ?
               OO_EPOLL1_EVENT_ON_HOME :
               OO_EPOLL1_EVENT_ON_OTHER);
  }
  return 0;
}


static int oo_epoll1_spin_on(struct file* home_filp,
                             struct file* other_filp,
                             ci_uint64 timeout_us, int sleep_iter_us)
{
  struct oo_epoll_poll_table ept;
  int rc, ret = 0;
  struct oo_epoll_private *priv = home_filp->private_data;
  tcp_helper_resource_t* thr = priv->p.p1.home_stack;
  s64 end;

  if( ! thr )
    return 0;

  ept.rc = 0;
  ept.filp = home_filp;
  ept.task = current;
  end = ktime_to_ns(ktime_add_us(ktime_get(), timeout_us));

again:
  ept.w[0] = ept.w[1] = NULL;

  init_poll_funcptr(&ept.pt, oo_epoll1_block_on_callback);
  init_waitqueue_func_entry(&ept.wq[0], oo_epoll1_wake_home_callback);

  if( (ret = oo_epoll_has_event(home_filp)) != 0 )
    goto out;

  if(  oo_epoll1_poll(home_filp, &ept.pt) != 0 ) {
    ret = OO_EPOLL1_EVENT_ON_HOME;
    goto out;
  }

  rc = other_filp->f_op->poll(other_filp, NULL);
  if( rc ) {
    ret =  OO_EPOLL1_EVENT_ON_OTHER;
    goto out;
  }

  init_waitqueue_func_entry(&ept.wq[1], oo_epoll1_wake_other_callback);
  rc = other_filp->f_op->poll(other_filp, &ept.pt);
  if( rc ) {
    ret = OO_EPOLL1_EVENT_ON_OTHER;
    goto out;
  }
  /* We are spinning here on eventq of the home and other stacks
   * We have events armed to wake us in case stacks are polled by
   * other context. */
  set_current_state(TASK_INTERRUPTIBLE);
  if( ept.rc != 0 ) {
    /* Callback might have tried waking up us before us entering TASK_INTERRUPTIBLE
     * state.  To address this case the state is reset. */
    __set_current_state(TASK_RUNNING);
  }
  else {
    ktime_t kt;
    /* sleep up to between iter_usec and 2 * iter_usec */
    kt = ktime_set(0, sleep_iter_us * 1000);
    ret = schedule_hrtimeout_range(&kt, sleep_iter_us * 1000, HRTIMER_MODE_REL);
    if( ret != 0 ) {
      /* We have been woken up by relevant event or a signal,
       * either of these is good to terminate the loop. */
      end = 0;
    }
  }
  /* task is always in TASK_RUNNING state here */

  ret = ept.rc;
out:
  if( ept.w[0] != NULL )
    remove_wait_queue(ept.w[0], &ept.wq[0]);
  if( ept.w[1] != NULL )
    remove_wait_queue(ept.w[1], &ept.wq[1]);
  /* FIXME optimize use of wqs */
  if( ret == 0 && ktime_to_ns(ktime_get()) < end )
    goto again;

  return ret;
}
#endif


static int oo_epoll_move_fd(struct oo_epoll1_private* priv, int epoll_fd)
{
  struct file* epoll_file = fget(epoll_fd);

  /* We expect that os_file is non-NULL, but we can't rely on it because
   * we do not trust UL.  In a "good" case, we just check that the new
   * epoll_fd points to the same underlying os_file.  In the "bad" case we
   * just avoid crashing; misbehaving UL should be happy with any result
   * from this ioctl. */
  if( epoll_file != priv->os_file ) {
    if( epoll_file != NULL )
      fput(epoll_file);
    return -EINVAL;
  }
  if( epoll_file != NULL )
    fput(epoll_file);

  priv->sh->epfd = epoll_fd;
  return 0;
}

/*************************************************************
 * Common /dev/onload_epoll code
 *************************************************************/
static long oo_epoll_fop_unlocked_ioctl(struct file* filp,
                                        unsigned cmd, unsigned long arg)
{
  struct oo_epoll_private *priv = filp->private_data;
  void __user* argp = (void __user*) arg;
  int rc;

  switch( cmd ) {
#if CI_CFG_EPOLL2
  case OO_EPOLL2_IOC_ACTION: {
    struct oo_epoll2_action_arg local_arg;

    ci_assert_equal(_IOC_SIZE(cmd), sizeof(local_arg));
    if( priv->type != OO_EPOLL_TYPE_2 )
      return -EINVAL;
    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;

    rc = oo_epoll2_action(priv, &local_arg);

    if( rc == 0 && copy_to_user(argp, &local_arg, _IOC_SIZE(cmd)) )
      return -EFAULT;
    break;
  }

  case OO_EPOLL2_IOC_INIT: {
    ci_fixed_descriptor_t local_arg;
    ci_assert_equal(_IOC_SIZE(cmd), sizeof(local_arg));
    if( priv->type != OO_EPOLL_TYPE_UNKNOWN )
      return -EINVAL;
    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;

    rc = oo_epoll2_init(priv, local_arg);
    break;
  }
#endif

  case OO_EPOLL1_IOC_CTL: {
    struct oo_epoll1_ctl_arg local_arg;
    ci_assert_equal(_IOC_SIZE(cmd), sizeof(local_arg));
    if( priv->type != OO_EPOLL_TYPE_1 )
      return -EINVAL;
    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) ) {
      return -EFAULT;
    }

    rc = oo_epoll1_ctl(&priv->p.p1, &local_arg);
    break;
  }

  case OO_EPOLL1_IOC_WAIT: {
    struct oo_epoll1_wait_arg local_arg;
    ci_assert_equal(_IOC_SIZE(cmd), sizeof(local_arg));
    if( priv->type != OO_EPOLL_TYPE_1 )
      return -EINVAL;
    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;

    rc = oo_epoll1_wait(&priv->p.p1, &local_arg);
    if( rc == 0 && copy_to_user(argp, &local_arg, _IOC_SIZE(cmd)) )
      return -EFAULT;
    break;
  }

  case OO_EPOLL1_IOC_ADD_STACK: {
    ci_fixed_descriptor_t sock_fd;
    struct file *sock_file;
    ci_private_t *sock_priv;
    ci_assert_equal(_IOC_SIZE(cmd), sizeof(sock_fd));
    if( priv->type != OO_EPOLL_TYPE_1 )
      return -EINVAL;
    if( copy_from_user(&sock_fd, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;

    sock_file = fget(sock_fd);
    if( sock_file == NULL )
      return -EINVAL;
    if( sock_file->f_op != &linux_tcp_helper_fops_udp &&
        sock_file->f_op != &linux_tcp_helper_fops_tcp ) {
      fput(sock_file);
      return -EINVAL;
    }
    sock_priv = sock_file->private_data;

    rc = 0;
    if( ! oo_epoll_add_stack(priv, sock_priv->thr) )
      rc = -ENOSPC;
    
    fput(sock_file);
    break;
  }

#if CI_CFG_EPOLL3
  case OO_EPOLL1_IOC_SET_HOME_STACK: {
    struct oo_epoll1_set_home_arg local_arg;
    struct file *stack_file;
    ci_private_t *stack_priv;

    ci_assert_equal(_IOC_SIZE(cmd), sizeof(local_arg));
    if( priv->type != OO_EPOLL_TYPE_1 )
      return -EINVAL;
    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;

    stack_file = fget(local_arg.sockfd);
    if( stack_file == NULL )
      return -EINVAL;
    if( stack_file->f_op != &oo_fops ) {
      fput(stack_file);
      return -EINVAL;
    }
    stack_priv = stack_file->private_data;

    rc = 0;
    if( oo_epoll_add_stack(priv, stack_priv->thr) )
      oo_epoll1_set_home_stack(&priv->p.p1, stack_priv->thr,
                               local_arg.ready_list);
    else
      rc = -ENOSPC;

    fput(stack_file);
    break;
  }

  case OO_EPOLL1_IOC_REMOVE_HOME_STACK:
    if( priv->type != OO_EPOLL_TYPE_1 )
      return -EINVAL;
    oo_epoll1_set_home_stack(&priv->p.p1, NULL, 0);
    rc = 0;
    break;
#endif

  case OO_EPOLL1_IOC_SPIN_ON:
  case OO_EPOLL1_IOC_BLOCK_ON: {
    struct oo_epoll1_block_on_arg local_arg;
    sigset_t sigmask, sigsaved;
    struct file* other_filp;

    ci_assert_equal(_IOC_SIZE(cmd), sizeof(local_arg));
    if( priv->type != OO_EPOLL_TYPE_1 )
      return -EINVAL;
    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;

    other_filp = fget(local_arg.epoll_fd);
    if( other_filp == NULL )
      return -EINVAL;

    if( local_arg.flags & OO_EPOLL1_HAS_SIGMASK ) {
      ci_assert_equal(sizeof(sigset_t), sizeof(local_arg.sigmask));
      memcpy(&sigmask, &local_arg.sigmask, sizeof(sigset_t));
      sigdelsetmask(&sigmask, sigmask(SIGKILL)|sigmask(SIGSTOP));
      sigprocmask(SIG_SETMASK, &sigmask, &sigsaved);
    }

#if CI_CFG_EPOLL3
    /* drop OO_EPOLL1_FLAG_HOME_STACK_CHANGED flag */
    priv->p.p1.flags = 0;
#endif

#if CI_CFG_EPOLL3
    if( cmd == OO_EPOLL1_IOC_SPIN_ON )
      rc = oo_epoll1_spin_on(filp, other_filp, local_arg.timeout_us,
                                               local_arg.sleep_iter_us);
    else
#endif
      rc = oo_epoll1_block_on(filp, other_filp, local_arg.timeout_us);

    if( signal_pending(current) )
      rc = -EINTR;

    if( local_arg.flags & OO_EPOLL1_HAS_SIGMASK ) {
      if( signal_pending(current) ) {
        memcpy(&current->saved_sigmask, &sigsaved, sizeof(sigsaved));
/* Must check for both symbols: see def'n of EFRM_HAVE_SET_RESTORE_SIGMASK. */
#if defined(HAVE_SET_RESTORE_SIGMASK) || \
    defined(EFRM_HAVE_SET_RESTORE_SIGMASK) || \
    defined(EFRM_HAVE_SET_RESTORE_SIGMASK1)
        set_restore_sigmask();
#else
        set_thread_flag(TIF_RESTORE_SIGMASK);
#endif
      }
      else
        sigprocmask(SIG_SETMASK, &sigsaved, NULL);
    }

    /* no guarantee if stupid user have called us with wrong flags: */
    ci_assert_equal(local_arg.flags &
                    (OO_EPOLL1_EVENT_ON_HOME | OO_EPOLL1_EVENT_ON_OTHER |
                     OO_EPOLL1_EVENT_ON_EVQ), 0);
    if( rc > 0 ) {
      local_arg.flags |= rc;
      rc = 0;
    }

    if( copy_to_user(argp, &local_arg, _IOC_SIZE(cmd)) )
      return -EFAULT;
    break;
  }

  case OO_EPOLL1_IOC_PRIME: {
    oo_epoll_prime_all_stacks(priv);
    rc = 0;
    break;
  }

  case OO_EPOLL_IOC_CLONE: {
    ci_clone_fd_t local_arg;

    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;
    local_arg.fd = oo_clone_fd(filp, local_arg.do_cloexec);

    if( local_arg.fd < 0 )
      return local_arg.fd;
    if( copy_to_user(argp, &local_arg, _IOC_SIZE(cmd)) )
      return -EFAULT;
    return 0;
  }

  case OO_EPOLL1_IOC_MOVE_FD: {
    ci_fixed_descriptor_t epoll_fd;
    ci_assert_equal(_IOC_SIZE(cmd), sizeof(epoll_fd));
    if( priv->type != OO_EPOLL_TYPE_1 )
      return -EINVAL;
    if( copy_from_user(&epoll_fd, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;

    rc = oo_epoll_move_fd(&priv->p.p1, epoll_fd);
    break;
  }

  case OO_EPOLL1_IOC_INIT:
    rc = oo_epoll1_setup_shared(&priv->p.p1);
    break;

  default:
    /* If libc is used on our sockets, sometimes it may call TCGETS ioctl to
     * determine whether the file is a tty.
     * tc* functions (tcgetpgrp, tcflush, etc) use direct ioctl syscalls,
     * so TIOC* ioctl go around onload library even if it is used.
     * So, we do not print scary warning for 0x5401(TCGETS)
     * - 0x541A(TIOCSSOFTCAR).
     * Next is FIONREAD(0x541B), which we can support, but do not do this.
     * The only ioctl which was really seen in the real life is TIOCGPGRP.
     */
#if ! defined (__PPC__)
    BUILD_BUG_ON(_IOC_TYPE(TIOCSSOFTCAR) != _IOC_TYPE(TCGETS));
    if( _IOC_TYPE(cmd) != _IOC_TYPE(TCGETS) ||
        _IOC_NR(cmd) > _IOC_NR(TIOCSSOFTCAR) ) {
#else
    /* On PPC TTY ioctls are organized in a complicated way, so for now
     * we just shut up warnings for a few known ioctl codes
     */
    if( cmd != TCGETS && cmd != TIOCGPGRP) {
#endif
      ci_log("unknown epoll device ioctl: 0x%x", cmd);
    }

    rc = -EINVAL;
  }
  return rc;
}

static int oo_epoll_fop_open(struct inode* inode, struct file* filp)
{
  struct oo_epoll_private *priv = kmalloc(sizeof(*priv), GFP_KERNEL);

  /* oo_epoll2_wait() uses the definition of oo_timesync_cpu_khz.  We
     don't want to block on it to stablize there on the fast path so
     we block here. */
  oo_timesync_wait_for_cpu_khz_to_stabilize();

  if(unlikely( priv == NULL ))
    return -ENOMEM;
  memset(priv, 0, sizeof(*priv));

  filp->private_data = (void*) priv;
  filp->f_op = &oo_epoll_fops;

  return 0;
}

static int oo_epoll_fop_release(struct inode* inode, struct file* filp)
{
  struct oo_epoll_private *priv = filp->private_data;

  ci_assert(priv);

  /* Type-specific cleanup */
  switch( priv->type ) {
    case OO_EPOLL_TYPE_1: oo_epoll1_release(priv); break;
#if CI_CFG_EPOLL2
    case OO_EPOLL_TYPE_2: oo_epoll2_release(priv); break;
#endif
    default: ci_assert_equal(priv->type, OO_EPOLL_TYPE_UNKNOWN);
  }

  /* Free priv data */
  kfree(priv);

  return 0;
}

static unsigned oo_epoll_fop_poll(struct file* filp, poll_table* wait)
{
#if CI_CFG_EPOLL2
  struct oo_epoll_private *priv = filp->private_data;

  ci_assert(priv);
  if( priv->type == OO_EPOLL_TYPE_2 )
    return oo_epoll2_poll(priv, wait);
  else
#endif
    return POLLNVAL;
}

static int oo_epoll_fop_mmap(struct file* filp, struct vm_area_struct* vma)
{
  struct oo_epoll_private *priv = filp->private_data;
  int rc;

  ci_assert(priv);
  if( priv->type != OO_EPOLL_TYPE_UNKNOWN)
    return -EINVAL;

  rc = oo_epoll_init_common(priv);
  if( rc != 0 )
    return rc;

  rc = oo_epoll1_mmap(&priv->p.p1, vma);
  if( rc != 0 ) {
    oo_epoll_release_common(priv);
    return rc;
  }

#if CI_CFG_EPOLL3
  ci_waitable_ctor(&priv->p.p1.home_w);
  priv->p.p1.flags = 0;
#endif

  priv->type = OO_EPOLL_TYPE_1;
  return rc;
}

struct file_operations oo_epoll_fops =
{
  CI_STRUCT_MBR(owner, THIS_MODULE),
  CI_STRUCT_MBR(poll, oo_epoll_fop_poll),
  CI_STRUCT_MBR(unlocked_ioctl, oo_epoll_fop_unlocked_ioctl),
  CI_STRUCT_MBR(compat_ioctl, oo_epoll_fop_unlocked_ioctl),
  CI_STRUCT_MBR(open, oo_epoll_fop_open),
  CI_STRUCT_MBR(release,  oo_epoll_fop_release),
  CI_STRUCT_MBR(mmap,  oo_epoll_fop_mmap),
};

static struct ci_chrdev_registration* oo_epoll_chrdev;


/* the only external symbol here: init /dev/onload_epoll */
int __init oo_epoll_chrdev_ctor(void)
{
  return create_one_chrdev_and_mknod(0, OO_EPOLL_DEV_NAME, &oo_epoll_fops,
                                     &oo_epoll_chrdev);
}

void oo_epoll_chrdev_dtor(void)
{
  destroy_chrdev_and_mknod(oo_epoll_chrdev);
}

