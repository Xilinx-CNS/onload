/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2010-2019 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Solarflare Communications Inc.
**      Author: djr
**     Started: 2008/11/10
** Description: Operations on OS sockets.
** </L5_PRIVATE>
\**************************************************************************/

#include "ip_internal.h"
#include <onload/common.h>
#include <onload/osfile.h>
#ifndef __KERNEL__
# include <onload/dup2_lock.h>
#endif


/**********************************************************************
 * oo_os_sock_get() and oo_os_sock_release().
 */

#ifdef __KERNEL__

/* Caller must call oo_os_sock_put() to release the os_sock*/
int oo_os_sock_get_from_ep(tcp_helper_endpoint_t* ep, oo_os_file* os_sock_out)
{
  unsigned long lock_flags;

  spin_lock_irqsave(&ep->lock, lock_flags);
  if( ep->os_socket != NULL ) {
    *os_sock_out = ep->os_socket;
    get_file(*os_sock_out);
    spin_unlock_irqrestore(&ep->lock, lock_flags);
    ci_assert(*os_sock_out != NULL);
    return 0;
  }
  spin_unlock_irqrestore(&ep->lock, lock_flags);
  *os_sock_out = NULL;
  return -EINVAL;
}

/* Caller must call oo_os_sock_put() to release the os_sock */
int oo_os_sock_get(ci_netif* ni, oo_sp sock_p, oo_os_file* os_sock_out)
{
  int sock_id = OO_SP_TO_INT(sock_p);
  tcp_helper_endpoint_t* ep;

  if( sock_id != TRUSTED_SOCK_ID(ni, sock_id) ) {
    LOG_E(ci_log("%s: ERROR: %d:%d bad sock_id",
                 __FUNCTION__, NI_ID(ni), sock_id));
    return -EINVAL;
  }
  ep = ci_netif_ep_get(ni, sock_p);
  if( oo_os_sock_get_from_ep(ep, os_sock_out) == 0 )
    return 0;

  LOG_E(ci_log("%s: ERROR: %d:%d has no O/S socket",
               __FUNCTION__, NI_ID(ni), sock_id));
  return -ENOENT;
}

#else

int oo_os_sock_get(ci_netif* ni, oo_sp sock_p, oo_os_file* os_sock_out)
{
  oo_os_sock_fd_get_t op;
  int rc;

  oo_rwlock_lock_read(&citp_dup2_lock);
  op.sock_id = OO_SP_TO_INT(sock_p);
  rc = oo_resource_op(ci_netif_get_driver_handle(ni),
                      OO_IOC_OS_SOCK_FD_GET, &op);
  if( rc == 0 )
    *os_sock_out = op.fd_out;
  else
    oo_rwlock_unlock_read (&citp_dup2_lock);
  return rc;
}


static void oo_os_sock_release(ci_netif* ni, oo_os_file fd)
{
  int rc = ci_sys_close(fd);
  oo_rwlock_unlock_read(&citp_dup2_lock);
  if( rc != 0 )
    LOG_E(ci_log("%s: [%d] ci_sys_close returned %d (errno=%d)",
                 __FUNCTION__, NI_ID(ni), rc, errno));
}



/**********************************************************************
 * oo_os_sock_ioctl().
 */

int oo_os_sock_ioctl(ci_netif* ni, oo_sp sock_p, int request, void* arg,
                     int* ioctl_rc)
{
  oo_os_file os_sock_fd;
  int rc;
  if( (rc = oo_os_sock_get(ni, sock_p, &os_sock_fd)) == 0 ) {
    rc = ci_sys_ioctl(os_sock_fd, request, arg);
    if( rc < 0 )
      rc = -errno;
    oo_os_sock_release(ni, os_sock_fd);
    if( ioctl_rc != NULL ) {
      *ioctl_rc = rc;
      rc = 0;
    }
  }
  else {
    LOG_E(ci_log("%s: [%d:%d] ERROR: failed to get kernel sock fd "
                 "(rc=%d req=%d)", __FUNCTION__, NI_ID(ni), OO_SP_FMT(sock_p),
                 rc, request));
  }
  return rc;
}



int oo_os_sock_sendmsg(ci_netif* ni, oo_sp sock_p,
                       const struct msghdr* msg, int flags)
{
  oo_os_sock_sendmsg_t op;

  op.sock_id = OO_SP_TO_INT(sock_p);
  op.sizeof_ptr = sizeof(void*);
  op.flags = flags;
  CI_USER_PTR_SET(op.msg_iov, msg->msg_iov);
  op.msg_iovlen = msg->msg_iovlen;
  CI_USER_PTR_SET(op.msg_name, msg->msg_name);
  op.msg_namelen = msg->msg_namelen;
#ifdef __i386__
  /* compat cmsg is not handled in this function */
  ci_assert_equal(msg->msg_controllen, 0);
  op.msg_controllen = 0;
  CI_USER_PTR_SET(op.msg_control, NULL);
#else
  CI_USER_PTR_SET(op.msg_control, msg->msg_control);
  op.msg_controllen = msg->msg_controllen;
#endif
  return oo_resource_op(ci_netif_get_driver_handle(ni),
                        OO_IOC_OS_SOCK_SENDMSG, &op);
}

int oo_os_sock_sendmsg_raw(ci_netif* ni, oo_sp sock_p,
                           const struct msghdr* msg, int flags)
{
  unsigned long socketcall_args[8];
  oo_os_sock_sendmsg_raw_t op;
  int rc;

  op.sock_id = OO_SP_TO_INT(sock_p);
  op.sizeof_ptr = sizeof(void*);
  op.flags = flags;
  CI_USER_PTR_SET(op.msg, msg);
  CI_USER_PTR_SET(op.socketcall_args, socketcall_args);

  oo_rwlock_lock_read(&citp_dup2_lock);
  rc = oo_resource_op(ci_netif_get_driver_handle(ni),
                      OO_IOC_OS_SOCK_SENDMSG_RAW, &op);
  oo_rwlock_unlock_read (&citp_dup2_lock);

  return rc;
}


int oo_os_sock_recvmsg(ci_netif* ni, oo_sp sock_p,
                       struct msghdr* msg, int flags)
{
  oo_os_sock_recvmsg_t op;
  int rc;

  op.sock_id = OO_SP_TO_INT(sock_p);
  op.sizeof_ptr = sizeof(void*);
  op.flags = flags;
  CI_USER_PTR_SET(op.msg_iov, msg->msg_iov);
  op.msg_iovlen = msg->msg_iovlen;
  CI_USER_PTR_SET(op.msg_name, msg->msg_name);
  op.msg_namelen = msg->msg_namelen;
  CI_USER_PTR_SET(op.msg_control, msg->msg_control);
  op.msg_controllen = msg->msg_controllen;
  rc = oo_resource_op(ci_netif_get_driver_handle(ni),
                      OO_IOC_OS_SOCK_RECVMSG, &op);
  ci_assert(op.rc >= 0 || rc < 0);
  if( rc == 0 ) {
    msg->msg_flags = op.flags;
    msg->msg_namelen = op.msg_namelen;
    if( msg->msg_controllen )
      msg->msg_controllen = op.msg_controllen;
    return op.rc;
  }
  return rc;
}

int oo_os_sock_accept(ci_netif* ni, oo_sp sock_p, struct sockaddr *addr,
                      socklen_t *addrlen, int flags)
{
  oo_os_sock_accept_t op;
  int rc;

  op.sock_id = OO_SP_TO_INT(sock_p);
  CI_USER_PTR_SET(op.addr, addr);
  CI_USER_PTR_SET(op.addrlen, addrlen);
  op.flags = flags;

  rc = oo_resource_op(ci_netif_get_driver_handle(ni),
                      OO_IOC_OS_SOCK_ACCEPT, &op);

  return rc == 0 ? op.rc : rc;
}
#endif
