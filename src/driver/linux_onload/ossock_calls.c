/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: gel
**     Started: 2005/01/05
** Description: TCP helper resource OS socket calls (linux specific)
** </L5_PRIVATE>
\**************************************************************************/

#include <ci/internal/ip.h>
#include <onload/tcp_helper.h>
#include <onload/debug.h>
#include <onload/fd_private.h>
#include <onload/common.h>

#include <net/tcp.h>
#include <linux/compat.h>

#include <onload/tcp_helper_fns.h>
#include <onload/linux_onload.h>
#include <onload/linux_onload_internal.h>
#include <onload/tcp_helper_endpoint.h>

#include "onload_kernel_compat.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define OO_SOCK_OPS_GETNAME(sock, addr, peer) \
  sock->ops->getname(sock, addr, peer)
#else
static inline int OO_SOCK_OPS_GETNAME(struct socket* sock,
                                      struct sockaddr* addr, int peer)
{
  int addrlen, rc;
  rc = sock->ops->getname(sock, addr, &addrlen, peer);
  if( rc < 0 )
    return rc;
  return addrlen;
}
#endif
  

static void efab_ep_handover_setup(ci_private_t* priv, int* in_epoll_p)
{
  citp_waitable_obj* w = SP_TO_WAITABLE_OBJ(&priv->thr->netif, priv->sock_id);

  /*
   * 1. Mark this "struct file" as alien.  Userland will know what to do
   * with it.
   * 2. If we are in epoll list, mark endpoint.  We should not close this
   * endpoint until the OS file is alive.
   * 3. Do dup() but preserver flags.  This fd is now OK; other fd
   * referencing this file will reprobe the state.
   */

  /* First, be sure that OO_FDFLAG_EP_TCP does not meet anything
   * unexpected in the shared state: */
  priv->fd_flags = (priv->fd_flags & ~OO_FDFLAG_EP_MASK) |
                   OO_FDFLAG_EP_PASSTHROUGH;
  priv->_filp->f_op = &linux_tcp_helper_fops_passthrough;
  ci_wmb();

  /* Second, update the shared state: */
  ci_bit_set(&w->waitable.sb_aflags, CI_SB_AFLAG_MOVED_AWAY_BIT);
#if CI_CFG_ENDPOINT_MOVE
  w->waitable.moved_to_stack_id = OO_STACK_ID_INVALID;
#endif

  *in_epoll_p = 0;
  if( ! list_empty(&priv->_filp->f_ep_links) ) {
    ci_bit_set(&w->waitable.sb_aflags, CI_SB_AFLAG_MOVED_AWAY_IN_EPOLL_BIT);
    *in_epoll_p = 1;
  }
}

/*! Replace [old_filp] with [new_filp] in the current process's fdtable.
** Fails if [fd] is bad, or doesn't currently resolve to [old_filp].
*/
static int
oo_fd_replace_file(struct file* old_filp, struct file* new_filp,
                   int old_fd, int* new_fd_p)
{
  task_lock(current);
  if( atomic_read(&current->files->count) != 1 ) {
    /* This is a multithreaded application, and someone can be already
     * calling into this endpoint.  We should not remove the ep from under
     * other thread's feet.  UL library will call dup2().
     * 
     * See also __fget_light() comments, because sys_ioctl() uses
     * it to obtain the struct file.
     */
    int new_fd;

    task_unlock(current);
    rcu_read_lock(); /* for files_fdtable() */
    new_fd = get_unused_fd_flags(
                close_on_exec(old_fd, files_fdtable(current->files)) ?
                O_CLOEXEC : 0);
    rcu_read_unlock();
    if( new_fd < 0 ) {
      return new_fd;
    }
    get_file(new_filp);
    fd_install(new_fd, new_filp);

    /* UL library will examine the returned fd, and call dup2() if it is !=
     * old_fd. */
    *new_fd_p = new_fd;
    return 0;
  }

  rcu_read_lock();
  if( fcheck(old_fd) != old_filp ) {
    rcu_read_unlock();
    spin_unlock(&current->files->file_lock);
    return -EINVAL;
  }

  get_file(new_filp);
  rcu_assign_pointer(files_fdtable(current->files)->fd[old_fd], new_filp);
  rcu_read_unlock();
  task_unlock(current);

  /* No synchronize_rcu() is needed here.  See do_dup2() for an example,
   * and file_free() for the reason. */
  fput(old_filp);

  *new_fd_p = old_fd;
  return 0;
}

int oo_file_moved_rsop(ci_private_t* priv, void *p_fd)
{
  tcp_helper_endpoint_t* ep;
  int fd = *(ci_int32*) p_fd;
  int rc;
  int new_fd;

  if( ! (priv->fd_flags & (OO_FDFLAG_EP_PASSTHROUGH | OO_FDFLAG_EP_ALIEN)) )
    return -EINVAL;

  ci_assert(priv->thr);

  ep = ci_trs_ep_get(priv->thr, priv->sock_id);

  if( priv->fd_flags & OO_FDFLAG_EP_PASSTHROUGH ) {
    struct file* os_file;

    ci_assert_equal(priv->_filp->f_op, &linux_tcp_helper_fops_passthrough);
    rc = oo_os_sock_get_from_ep(ep, &os_file);
    if( rc != 0 )
      return rc;
    rc = oo_fd_replace_file(priv->_filp, os_file, fd, &new_fd);
    oo_os_sock_put(os_file);
  }
  else {
    ci_assert(ep->alien_ref);
    ci_assert_equal(priv->_filp->f_op, &linux_tcp_helper_fops_alien);
    rc = oo_fd_replace_file(priv->_filp, ep->alien_ref->_filp, fd, &new_fd);
  }
  if( rc != 0 )
    return rc;
  *(ci_int32*) p_fd = new_fd;
  return 0;
}

/* Handover the user-level socket to the OS one.  This means that the FD
** that previously pointed at a ul socket will now point at the OS socket
** that backed it.  This gets called when we connect through a non-l5
** interface, or bind to a non-l5 interface.
*/
int efab_tcp_helper_handover(ci_private_t* priv, void *p_fd)
{
  tcp_helper_endpoint_t* ep;
  int fd = *(ci_int32*) p_fd;
  struct file *oo_file = priv->_filp;
  int rc, line, in_epoll, new_fd;
  struct file* os_file;

  if( ! (priv->fd_flags & (OO_FDFLAG_EP_TCP | OO_FDFLAG_EP_UDP)) ) {
    line = __LINE__;
    goto unexpected_error;
  }
  ep = ci_trs_ep_get(priv->thr, priv->sock_id);
  rc = oo_os_sock_get_from_ep(ep, &os_file);
  if( rc != 0 ) {
    line = __LINE__;
    goto unexpected_error;
  }

  /* Caller must have taken the stack lock */
  ci_assert(ci_netif_is_locked(&priv->thr->netif));

  /* shut down fasync */
  if( ep->fasync_queue )
    fasync_helper(-1, oo_file, 0, &ep->fasync_queue);

  efab_ep_handover_setup(priv, &in_epoll);

  if( in_epoll ) {
    oo_os_sock_put(os_file);
    return -EBUSY;
  }

  rc = oo_fd_replace_file(oo_file, os_file, fd, &new_fd);
  oo_os_sock_put(os_file);
  if( rc != 0 )
    return rc;

  *(ci_int32*) p_fd = new_fd;

  /* exit from ioctl drops the last reference to the onload file */
  return 0;


 unexpected_error:
  OO_DEBUG_ERR(ci_log("%s: ERROR: unexpected error in HANDOVER at line %d",
                      __FUNCTION__, line));
  return -EINVAL;
}


#ifdef CONFIG_COMPAT

static int copy_compat_iovec_from_user(struct iovec* iovec,
                                       struct compat_iovec __user* uiovec,
                                       int iovlen)
{
  compat_uptr_t iov_base;
  compat_size_t iov_len;
  int i;

  for( i = 0; i < iovlen; ++i ) {
    if( get_user(iov_len, &uiovec[i].iov_len) ||
        get_user(iov_base, &uiovec[i].iov_base) )
      return -EFAULT;
    iovec[i].iov_base = compat_ptr(iov_base);
    iovec[i].iov_len = (__kernel_size_t) iov_len;
  }
  return 0;
}

#endif


int sock_map_fd(struct socket *sock, int flags)
{
  struct file *file;
  int fd;

  if( (fd = get_unused_fd_flags(flags)) < 0 )
    return fd;
  if( IS_ERR(file = sock_alloc_file(sock, flags, NULL)) ) {
    put_unused_fd(fd);
    return PTR_ERR(file);
  }
  fd_install(fd, file);
  return fd;
}


static int get_os_fd_from_ep(tcp_helper_endpoint_t *ep)
{
  int fd = get_unused_fd_flags(O_CLOEXEC);
  struct file *os_file;

  if( fd < 0 )
    return fd;

  if( oo_os_sock_get_from_ep(ep, &os_file) != 0 ) {
    put_unused_fd(fd);
    return -EINVAL;
  }

  fd_install(fd, os_file);

  return fd;
}

/* This really sucks, but sometimes we can't get at the kernel state that we
 * need to from a module.  So, what we do is to return a temporary FD for the
 * OS socket that backs a user-level socket.  Intention is for the user-level
 * code to do the necessary operation(s) using the FD, then close it.
 */
int efab_tcp_helper_get_sock_fd(ci_private_t* priv, void *arg)
{
  oo_os_sock_fd_get_t *op = arg;
  tcp_helper_endpoint_t *ep;
  ci_int32 sock_id = op->sock_id;

  if( op->sock_id < 0 )
    sock_id = OO_SP_TO_INT(priv->sock_id);
  ep = ci_trs_get_valid_ep(priv->thr, sock_id);

  op->fd_out = get_os_fd_from_ep(ep);

  return op->fd_out >= 0 ? 0 : op->fd_out;
}


/* Get at the OS socket backing the u/l socket for fd.  NB. No need to
** get_file() here, since if the os_socket exists it is guaranteed to
** remain referenced until the u/l socket's [struct file] goes away.  And
** it can't go away while we're in this ioctl!.
*/
static struct socket *
get_linux_socket(tcp_helper_endpoint_t* ep)
{
  ci_os_file socketp;
  struct inode *inode;
  struct socket *sock;
  int rc;

  rc = oo_os_sock_get_from_ep(ep, &socketp);
  if( rc != 0 )
    return NULL;
  inode = socketp->f_path.dentry->d_inode;
  if( inode == NULL )
    return NULL;

  ci_assert(S_ISSOCK(inode->i_mode));
  sock = SOCKET_I(inode);
  ci_assert_equal(sock->file, socketp);
  return sock;
}

static void put_linux_socket(struct socket *sock)
{
  fput(sock->file);
}

int efab_tcp_helper_os_sock_sendmsg(ci_private_t* priv, void *arg)
{
  oo_os_sock_sendmsg_t *op = arg;
  /* To make life a little simpler, we've packaged up the msghdr
   * in a 32/64 agnostic format.  But we still need to worry about
   * the iovec and cmsg.
   *
   * However, we do not handle cmsg compat case: user should call _raw
   * version of this ioctl.
   */
  tcp_helper_endpoint_t *ep;
  struct socket* sock;
  struct iovec local_iovec[UIO_FASTIOV];
  struct iovec *p_iovec = local_iovec;
  int iovec_bytes = 0, total_bytes;
  struct sockaddr_storage addr;
  struct msghdr msg;
  int i, rc;
  unsigned char local_ctl[sizeof(struct cmsghdr) + 20]
      __attribute__ ((aligned(sizeof(__kernel_size_t))));
  unsigned char *ctl_buf = local_ctl;

  ep = ci_trs_get_valid_ep(priv->thr, op->sock_id); 
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return  -EINVAL;

  rc = -EMSGSIZE;
  if( op->msg_iovlen > UIO_MAXIOV )
    goto out;

  iovec_bytes = op->msg_iovlen * sizeof(local_iovec[0]);
  rc = -ENOMEM;
  if( op->msg_iovlen > UIO_FASTIOV ) {
    p_iovec = sock_kmalloc(sock->sk, iovec_bytes, GFP_KERNEL);
    if( p_iovec == NULL )
      goto out;
  }

  rc = -EFAULT;
#ifdef CONFIG_COMPAT
  if( op->sizeof_ptr != sizeof(void*) ) {
    if( copy_compat_iovec_from_user(p_iovec, CI_USER_PTR_GET(op->msg_iov),
                                    op->msg_iovlen) != 0 )
      goto out;
  }
  else
#endif
    if( copy_from_user(p_iovec, CI_USER_PTR_GET(op->msg_iov),
                       op->msg_iovlen * sizeof(p_iovec[0])) != 0 )
      goto out;

  total_bytes = 0;
  for( i = 0; i < op->msg_iovlen; ++i )
    total_bytes += p_iovec[i].iov_len;
  rc = -EMSGSIZE;
  if( total_bytes < 0 )
    goto out;

  oo_msg_iov_init(&msg, WRITE, p_iovec, op->msg_iovlen, total_bytes);

  if( op->msg_controllen ) {
#ifdef CONFIG_COMPAT
    /* do not handle compat; use _raw version instead */
    ci_assert_equal(op->sizeof_ptr, sizeof(void*));
#endif

    if( op->msg_controllen > INT_MAX ) {
      rc = -ENOBUFS;
      goto out;
    }
    if( op->msg_controllen > sizeof(local_ctl) ) {
      ctl_buf = sock_kmalloc(sock->sk, op->msg_controllen, GFP_KERNEL);
      if( ctl_buf == NULL )
        goto out;
    }
    if( copy_from_user(ctl_buf, CI_USER_PTR_GET(op->msg_control),
                       op->msg_controllen) ) {
      rc = -EFAULT;
      goto out;
    }
    msg.msg_control = ctl_buf;
    msg.msg_controllen = op->msg_controllen;
  }
  else {
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
  }

  msg.msg_namelen = op->msg_namelen;
  if( op->msg_namelen == 0 )
    msg.msg_name = NULL;
  else if( op->msg_namelen < 0 ||
           op->msg_namelen > sizeof(struct sockaddr_storage) ) {
    rc = -EINVAL;
    goto out;
  }
  else if( copy_from_user(&addr, CI_USER_PTR_GET(op->msg_name),
                          op->msg_namelen) ) {
    rc = -EFAULT;
    goto out;
  }
  else
    msg.msg_name = &addr;

  msg.msg_flags = op->flags;

  rc = sock_sendmsg(sock, &msg);
  /* Clear OS TX flag if necessary  */
  oo_os_sock_status_bit_clear_handled(ep, sock->file, OO_OS_STATUS_TX);

 out:
  if( p_iovec != local_iovec && p_iovec != NULL)
    sock_kfree_s(sock->sk, p_iovec, iovec_bytes);
  if( ctl_buf != local_ctl && ctl_buf != NULL)
    sock_kfree_s(sock->sk, ctl_buf, op->msg_controllen);
  put_linux_socket(sock);
  return rc;
}

int efab_tcp_helper_os_sock_sendmsg_raw(ci_private_t* priv, void *arg)
{
  oo_os_sock_sendmsg_raw_t *op = arg;
  tcp_helper_endpoint_t *ep = ci_trs_get_valid_ep(priv->thr, op->sock_id);
  int fd, rc;
  unsigned flags = op->flags;
  struct socket* sock;

  ep = ci_trs_get_valid_ep(priv->thr, op->sock_id);
  fd = get_os_fd_from_ep(ep);
  if( fd < 0 )
    return -EINVAL;

#ifdef CONFIG_COMPAT
  if( op->sizeof_ptr != sizeof(void*) )
    rc = efab_linux_sys_sendmsg32(fd, CI_USER_PTR_GET(op->msg),
                                  CI_USER_PTR_GET(op->socketcall_args),
                                  flags);
  else
#endif
  rc = efab_linux_sys_sendmsg(fd, CI_USER_PTR_GET(op->msg),
                              CI_USER_PTR_GET(op->socketcall_args), flags);

  /* Clear OS TX flag if necessary  */
  sock = get_linux_socket(ep);
  if( sock != NULL ) {
    oo_os_sock_status_bit_clear_handled(ep, sock->file, OO_OS_STATUS_TX);
    put_linux_socket(sock);
  }
  efab_linux_sys_close(fd);
  return rc;
}


int efab_tcp_helper_os_sock_recvmsg(ci_private_t* priv, void *arg)
{
  oo_os_sock_recvmsg_t *op = arg;
  /*
   * To make life a little simpler, we've packaged up the msghdr in a 32/64
   * agnostic format.  But we still need to worry about the iovec etc.
   */
  tcp_helper_endpoint_t *ep;
  struct socket *sock;
  char sockaddr[sizeof(struct sockaddr_in6)];
  struct iovec local_iovec[UIO_FASTIOV];
  struct iovec *p_iovec = local_iovec;
  int iovec_bytes = 0, total_bytes;
  struct msghdr msg;
  int i, rc;

  ep = ci_trs_get_valid_ep(priv->thr, op->sock_id); 
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return 0;

  rc = -EMSGSIZE;
  if( op->msg_iovlen > UIO_MAXIOV )
    goto out;

  iovec_bytes = op->msg_iovlen * sizeof(local_iovec[0]);
  rc = -ENOMEM;
  if( op->msg_iovlen > UIO_FASTIOV ) {
    p_iovec = sock_kmalloc(sock->sk, iovec_bytes, GFP_KERNEL);
    if( p_iovec == NULL )
      goto out;
  }

  rc = -EFAULT;
#ifdef CONFIG_COMPAT
  if( op->sizeof_ptr != sizeof(void*) ) {
    if( copy_compat_iovec_from_user(p_iovec, CI_USER_PTR_GET(op->msg_iov),
                                    op->msg_iovlen) != 0 )
      goto out;
  }
  else
#endif
    if( copy_from_user(p_iovec, CI_USER_PTR_GET(op->msg_iov),
                       op->msg_iovlen * sizeof(p_iovec[0])) != 0 )
      goto out;

  total_bytes = 0;
  for( i = 0; i < op->msg_iovlen; ++i )
    total_bytes += p_iovec[i].iov_len;
  rc = -EMSGSIZE;
  if( total_bytes < 0 )
    goto out;

  oo_msg_iov_init(&msg, READ, p_iovec, op->msg_iovlen, total_bytes);

  if(  CI_USER_PTR_GET(op->msg_name) ) {
    msg.msg_name = sockaddr;
    msg.msg_namelen = sizeof(sockaddr);
  }
  else {
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
  }

  if( op->msg_controllen ) {
    msg.msg_control = CI_USER_PTR_GET(op->msg_control);
    msg.msg_controllen = op->msg_controllen;
  }
  else {
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
  }

  msg.msg_flags = 0;
  if( op->sizeof_ptr != sizeof(void*) )
    msg.msg_flags = MSG_CMSG_COMPAT;
#ifdef MSG_CMSG_CLOEXEC
  msg.msg_flags |= op->flags & MSG_CMSG_CLOEXEC;
#endif

  if( sock->file->f_flags & O_NONBLOCK )
    op->flags |= MSG_DONTWAIT;
  rc = sock_recvmsg(sock, &msg, op->flags);
  /* Clear OS RX flag if we've got everything  */
  oo_os_sock_status_bit_clear_handled(ep, sock->file,
            OO_OS_STATUS_RX | (op->msg_controllen ? OO_OS_STATUS_ERR : 0));
  if( rc < 0 )
    goto out;

  if( CI_USER_PTR_GET(op->msg_name) &&
      copy_to_user(CI_USER_PTR_GET(op->msg_name),
                   sockaddr, CI_MIN(op->msg_namelen, msg.msg_namelen)) != 0 )
    rc = -EFAULT;
  if( CI_USER_PTR_GET(op->msg_name) || op->msg_namelen )
    op->msg_namelen = msg.msg_namelen;
  if( CI_USER_PTR_GET(op->msg_control) ) {
    op->msg_controllen = (unsigned long)msg.msg_control -
        (unsigned long)CI_USER_PTR_GET(op->msg_control);
    if( msg.msg_flags & MSG_ERRQUEUE ) {
      /* If errqueue is non-empty, we've already got correct so_error via
       * callback.  If errqueue is empty, we should clear SO_ERROR value. */
      spin_lock_bh(&sock->sk->sk_error_queue.lock);
      if( skb_queue_empty(&sock->sk->sk_error_queue) )
        SP_TO_SOCK_CMN(&ep->thr->netif, ep->id)->so_error = 0;
      spin_unlock_bh(&sock->sk->sk_error_queue.lock);
    }
  }
  op->flags = msg.msg_flags &~ MSG_CMSG_COMPAT;

 out:
  if( p_iovec != local_iovec && p_iovec != NULL)
    sock_kfree_s(sock->sk, p_iovec, iovec_bytes);
  put_linux_socket(sock);
  op->rc = rc;
  return rc > 0 ? 0 : rc;
}


/* X-SPDX-Source-URL: * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git */
/* X-SPDX-Source-Tag: 6a9ab7a8b1d2c5059752a9147c2f0fd1aea4f44d */
/* X-SPDX-Source-File: net/socket.c */
/* X-SPDX-License-Identifier: GPL-2.0-or-later */
/* X-SPDX-Comment: The function move_addr_to_kernel() used to be exported in
 *                 older linux versions.  Copied verbatim, because the idea
 *                 is too trivial to implement in another way */
static int
efab_move_addr_to_kernel(void __user *uaddr, int ulen,
                         struct sockaddr_storage *kaddr)
{
	if (ulen < 0 || ulen > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (ulen == 0)
		return 0;
	if (copy_from_user(kaddr, uaddr, ulen))
		return -EFAULT;
	return 0;
}


static int __efab_tcp_helper_destroy_os_sock(tcp_helper_endpoint_t* ep)
{
  struct file* os_socket;
  unsigned long lock_flags;
  citp_waitable *w = SP_TO_WAITABLE(&ep->thr->netif, ep->id);

  ci_atomic32_and(&w->sb_aflags, ~CI_SB_AFLAG_OS_BACKED);
  spin_lock_irqsave(&ep->lock, lock_flags);
  os_socket = ep->os_socket;
  ep->os_socket = NULL;
  spin_unlock_irqrestore(&ep->lock, lock_flags);
  if( os_socket != NULL ) {
    fput(os_socket);
  }
  return 0;
}
/* X-SPDX-Restore: */


int efab_tcp_helper_destroy_os_sock(ci_private_t *priv)
{
  return __efab_tcp_helper_destroy_os_sock(efab_priv_to_ep(priv));
}

int efab_tcp_helper_create_os_sock(ci_private_t *priv)
{
  struct socket *sock;
  int flags = 0;
  int rc;
  ci_netif *ni = &priv->thr->netif;
  citp_waitable *w = SP_TO_WAITABLE(ni, priv->sock_id);
  tcp_helper_endpoint_t *ep = efab_priv_to_ep(priv);

  /* It's always valid to set the O_ flag rather than the SOCK_ flag,
   * as either they're the same, or the O_ flag is what we want.
   */
  if( w->sb_aflags & CI_SB_AFLAG_O_NONBLOCK)
    flags |= O_NONBLOCK;
  if( w->sb_aflags & CI_SB_AFLAG_O_CLOEXEC)
    flags |= O_CLOEXEC;
  rc = efab_create_os_socket(priv->thr, ep,
                             SP_TO_SOCK(ni, priv->sock_id)->domain,
                             SOCK_STREAM, flags);
  if( rc < 0 )
    return rc;

  /* At this point we are marked as OS_BACKED, so any new options that get
   * set will get synced directly as needed.  We need to sync anything that
   * has been set before now and we need to ensure we don't undo anything
   * that is happening concurrently with this.
   */
  sock = get_linux_socket(ep);

  /* Copy F_SETOWN_EX, F_SETSIG to the new file */
#ifdef F_SETOWN_EX
  if(priv->_filp->f_owner.pid != 0) {
    rcu_read_lock();
    __f_setown(sock->file, priv->_filp->f_owner.pid,
               priv->_filp->f_owner.pid_type, 1);
    rcu_read_unlock();
  }
#endif
  sock->file->f_owner.signum = priv->_filp->f_owner.signum;

  rc = ci_tcp_sync_sockopts_to_os_sock(ni, ep->id, sock);
  put_linux_socket(sock);

  if( rc < 0 ) {
    /* Drop the OS socket to leave this endpoint in a consistent state. */
    efab_tcp_helper_destroy_os_sock(priv);
  }

  return rc;
}

/* This function does a 'bind' and a getname on the OS socket.  It is the
 * common functionality between kernel and user (via ioctl) bind.
 */
int efab_tcp_helper_bind_os_sock_common(struct socket* sock,
                                        struct sockaddr *addr, int addrlen,
                                        ci_uint16 *out_port)
{
  int rc;

  rc = sock->ops->bind(sock, addr, addrlen);
  LOG_TV(ci_log("%s: rc=%d", __FUNCTION__, rc));

  if (rc >= 0) {
    /* We also return the port bound to
     * (which might be different to asked for if asked for 0)
     * This is the getsockname, as mentioned in description above
     */
    OO_SOCK_OPS_GETNAME(sock, addr, 0);

    *out_port = ((struct sockaddr_in*)addr)->sin_port;
  }

  return rc;
}


void efab_free_ephemeral_port(struct efab_ephemeral_port_keeper* keeper)
{
  if( keeper->os_file )
    fput(keeper->os_file); /* socket released implicitely */
  kfree(keeper);
}


/* Reserve a port by creating a TCP socket and binding it.  The idea in
 * principle here is that we're allocating an ephemeral ports for use in
 * backing an active wild, hence the "ephemeral" in the name of the function,
 * but sometimes we will prefer to use an explicit port, so when [lport_be16]
 * is non-zero we will bind to that port, and "ephemeral" becomes something of
 * a misnomer. */
int
efab_alloc_ephemeral_port(ci_addr_t laddr, ci_uint16 lport_be16,
                          struct efab_ephemeral_port_keeper** keeper_out)
{
  struct efab_ephemeral_port_keeper* keeper;
  struct sockaddr_storage addr;
  int rc;

  addr = ci_make_sockaddr_storage_from_addr(lport_be16, laddr);

  keeper = kmalloc(sizeof(*keeper), GFP_KERNEL);
  keeper->laddr = laddr;
  keeper->next = NULL;
  keeper->global_next = NULL;

  rc = sock_create(addr.ss_family, SOCK_STREAM, 0, &keeper->sock);
  if( rc != 0 ) {
    LOG_TC(ci_log("%s: Failed to create socket: rc=%d", __FUNCTION__, rc));
    goto fail1;
  }
  rc = efab_tcp_helper_bind_os_sock_common(keeper->sock,
                                             (struct sockaddr*) &addr,
                                             sizeof(addr), &keeper->port_be16);
  if( rc != 0 ) {
    LOG_TC(ci_log("%s: Failed to bind socket: rc=%d", __FUNCTION__, rc));
    goto fail2;
  }

  keeper->os_file = sock_alloc_file(keeper->sock, 0, NULL);
  if( IS_ERR(keeper->os_file) ) {
    rc = PTR_ERR(keeper->os_file);
    LOG_TC(ci_log("%s: Failed to allocate file: rc=%d", __FUNCTION__, rc));
    goto fail2;
  }

  *keeper_out = keeper;
  return 0;

 fail2:
  sock_release(keeper->sock);
 fail1:
  kfree(keeper);
  return rc;
}



/* This function handles the OS socket bind when done from the kernel.  In
 * this case we are already expected to have an OS socket.
 */
extern int efab_tcp_helper_bind_os_sock_kernel(tcp_helper_resource_t *trs,
                                               oo_sp sock_id,
                                               struct sockaddr *addr,
                                               int addrlen, ci_uint16 *out_port)
{
  int rc;
  tcp_helper_endpoint_t *ep;
  struct socket *sock;
  struct sockaddr_storage orig_addr;

  ci_assert(trs);

  memcpy(&orig_addr, addr, addrlen);

  ep = ci_trs_get_valid_ep(trs, sock_id);
  if( ep == NULL )
    return -EINVAL;

  sock = get_linux_socket(ep);

  if( sock == NULL )
    return -EINVAL;

  rc = efab_tcp_helper_bind_os_sock_common(sock, addr, addrlen, out_port);
  put_linux_socket(sock);

  return rc;
}


/* This function handles the OS socket bind when done via ioctl.  If there's
 * no OS socket then it will attempt to create one before performing the bind.
 */
extern int efab_tcp_helper_bind_os_sock_rsop(ci_private_t *priv, void *arg)
{
  oo_tcp_bind_os_sock_t *op = arg;
  struct sockaddr_storage k_address_buf;
  int addrlen = op->addrlen;
  ci_uint16 port;
  int rc;
  tcp_helper_endpoint_t *ep;
  struct socket *sock;

  ci_assert(priv);
  ci_assert(op);
  if( ! (priv->fd_flags & OO_FDFLAG_EP_MASK) )
    return -EINVAL;
  ci_assert(priv->thr);

  rc = efab_move_addr_to_kernel(CI_USER_PTR_GET(op->address), addrlen,
                                (struct sockaddr_storage *)&k_address_buf);
  if( rc < 0 )
    return rc;

  ep = efab_priv_to_ep(priv);
  if( ep == NULL )
    return -EINVAL;

  sock = get_linux_socket(ep);

  /* For tcp sockets we delay creation of the os socket until we know whether
   * we need one or not.  We don't create OS sockets for sockets with
   * IP_TRANSPARENT set, which we require to be set before bind time to be
   * accelerated.
   */
  if( (sock == NULL) && (priv->fd_flags & OO_FDFLAG_EP_TCP) ) {
    rc = efab_tcp_helper_create_os_sock(priv);
    if( rc < 0 )
      return rc;
    sock = get_linux_socket(ep);
    ci_assert(sock);
  }

  if( sock == NULL )
    return -EINVAL;

  rc = efab_tcp_helper_bind_os_sock_common(sock,
                                           (struct sockaddr *)&k_address_buf,
                                           addrlen, &port);
  put_linux_socket(sock);

  if( rc < 0 )
    return rc;

  op->addrlen = port;
  return 0;
}


int efab_tcp_helper_listen_os_sock(ci_private_t* priv, void* p_backlog)
{
  int rc = -EINVAL;
  tcp_helper_endpoint_t *ep;
  struct socket *sock;
  int backlog;

  if( ! (priv->fd_flags & OO_FDFLAG_EP_MASK) )
    return -EINVAL;
  ci_assert(priv->thr);

  backlog = *(ci_uint32*)p_backlog;
  ep = efab_priv_to_ep(priv);

  sock = get_linux_socket(ep);
  /* They only way we come here without binding the OS socket (and hence
   * ensuring it exists) is if we directly handover a socket on listen.
   */
  if( sock == NULL ) {
    rc = efab_tcp_helper_create_os_sock(priv);
    if( rc < 0 )
      return rc;
    sock = get_linux_socket(ep);
  }

  if( sock == NULL )
    return -EINVAL;

  oo_os_sock_poll_register(&ep->os_sock_poll, sock->file);

  rc = sock->ops->listen (sock, backlog);
  put_linux_socket(sock);

  LOG_TV(ci_log("%s: rc=%d", __FUNCTION__, rc));

  return rc;
}

extern int efab_tcp_helper_shutdown_os_sock (tcp_helper_endpoint_t *ep,
                                             ci_int32 how)
{
  int rc = -EINVAL;
  struct socket *sock;

  ci_assert (ep);

  sock = get_linux_socket(ep);
  if( sock == NULL )
    return -EINVAL;

  rc = sock->ops->shutdown (sock, how);
  put_linux_socket(sock);
  LOG_TV(ci_log("%s: shutdown(%d) rc=%d", __FUNCTION__, how, rc));

  return rc;
}

extern int
efab_tcp_helper_os_sock_accept(ci_private_t* priv, void *arg)
{
  oo_os_sock_accept_t *op = arg;
  tcp_helper_endpoint_t *ep = ci_trs_get_valid_ep(priv->thr, op->sock_id);
  ci_sock_cmn *s = SP_TO_SOCK(&ep->thr->netif, ep->id);
  struct socket *sock = get_linux_socket(ep);
  struct socket *newsock;
  int rc;
  short socktype;

  if( sock == NULL )
    return -EINVAL;
  socktype = sock->type;
  /* Blocking in the accept call is determined by the flags passed in, not
   * the flags set on the socket.  We don't do anything to prevent multiple
   * threads racing to pick up the same incoming OS connection, so we always
   * do non-blocking accepts, no matter what other flags user level has
   * provided.
   */
  rc = kernel_accept(sock, &newsock, op->flags | O_NONBLOCK);

  /* Clear OS RX flag if we've got everything  */
  oo_os_sock_status_bit_clear_handled(ep, sock->file, OO_OS_STATUS_RX);
  put_linux_socket(sock);

  if( rc != 0 )
    return rc;
  newsock->type = socktype;

  if( CI_USER_PTR_GET(op->addr) != NULL ) {
    char address[sizeof(struct sockaddr_in6)];
    int len, ulen;

    len = OO_SOCK_OPS_GETNAME(newsock, (struct sockaddr *)address, 2);
    if( len < 0 )
      return -ECONNABORTED;
    rc = get_user(ulen, (int *)CI_USER_PTR_GET(op->addrlen));
    if( rc != 0 )
      return rc;
    if( ulen < 0 )
      return -EINVAL;
    if( ulen ) {
      if( copy_to_user(CI_USER_PTR_GET(op->addr), address,
                       min(ulen, len)) )
        return -EFAULT;
    }

    __put_user(len, (int *)CI_USER_PTR_GET(op->addrlen));
  }

#ifdef SOCK_TYPE_MASK
  /* This is 'off' on linux, unless set via environment */
  if( NI_OPTS(&ep->thr->netif).accept_inherit_nonblock && op->flags == 0 &&
      s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK)
    op->flags |= SOCK_NONBLOCK;
  op->rc = sock_map_fd(newsock, op->flags);
#else
  op->rc = sock_map_fd(newsock);
#endif
  if( op->rc < 0 ) {
    sock_release(newsock);
    return op->rc;
  }

#ifndef SOCK_TYPE_MASK
  /* This is 'off' on linux, unless set via environment */
  if( NI_OPTS(&ep->thr->netif).accept_inherit_nonblock) {
    /* We can not use newsock, because it may be already closed by another
     * thread. */
    struct file *file = fget(op->rc);
    if( file == NULL )
      return 0;
    lock_kernel();
    if( s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK )
      file->f_flags |= O_NONBLOCK;
    if( s->b.sb_aflags & CI_SB_AFLAG_O_NDELAY )
      file->f_flags |= O_NDELAY;
    unlock_kernel();
  }
#endif

  return 0;
}



int efab_tcp_helper_set_tcp_close_os_sock(tcp_helper_resource_t *thr,
                                          oo_sp sock_id)
{
  tcp_helper_endpoint_t* ep;
  struct socket* sock;

  ep = ci_trs_get_valid_ep(thr, sock_id);
  if( ep == NULL )
    return -EINVAL;
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return  -EINVAL;
  tcp_set_state(sock->sk, TCP_CLOSE);
  put_linux_socket(sock);
  return 0;
}


int efab_tcp_helper_setsockopt(tcp_helper_resource_t* trs, oo_sp sock_id,
                               int level, int optname, char* user_optval,
                               int optlen)
{
  tcp_helper_endpoint_t* ep;
  struct socket* sock;
  int rc = -EINVAL;

  /* Get at the OS socket backing the u/l socket for fd.  NB. No need to
  ** get_file() here, since if the os_socket exists it is guaranteed to
  ** remain referenced until the u/l socket's [struct file] goes away.  And
  ** it can't go away while we're in this ioctl.
  */
  ep = ci_trs_get_valid_ep(trs, sock_id);
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return  -EINVAL;
  if( level == SOL_SOCKET )
    rc = sock_setsockopt(sock, level, optname, user_optval, optlen);
  else
    rc = sock->ops->setsockopt(sock, level, optname, user_optval, optlen);
  put_linux_socket(sock);
  LOG_SV(ci_log("%s: rc=%d", __FUNCTION__, rc));

  return rc;
}


/*--------------------------------------------------------------------
 *
 * oo_clone_fd()
 *
 *--------------------------------------------------------------------*/

/* Clone filp to a new fd.  As long as filp is one of ours, this is like
** doing open ("/dev/efab0"), except you don't need access to /dev/efab0
** (i.e. works independently of NIC, and works if you've been chroot-ed to
** a place where you can't see /dev/).
**
** Returns a new fd that references the same kind of file object as filp
** (though a distinct 'instance'), or negative error code on failure.
** New file is marked with CLOEXEC.
*/
int oo_clone_fd(struct file* filp, int do_cloexec)
{
  /* dentry_open() will construct a new struct file given an appropriate
  ** struct dentry and struct vfsmount: all we need to do is grab a
  ** reference to the entries that the original filp points to.
  */
  int new_fd = get_unused_fd_flags(do_cloexec ? O_CLOEXEC : 0);

  if( new_fd >= 0 ) {
    struct file *new_filp;
    new_filp = dentry_open(&filp->f_path, filp->f_flags, current_cred());
    if( ! IS_ERR(new_filp) ) {
      fd_install(new_fd, new_filp);
    }
    else {
      put_unused_fd(new_fd);
      new_fd = -ENOMEM;
    }
  }

  return new_fd;
}

