/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Exported functions from linux onload driver.
**   \date  2005/04/25
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __CI_DRIVER_EFAB_LINUX_ONLOAD__
#define __CI_DRIVER_EFAB_LINUX_ONLOAD__

#ifndef __KERNEL__
# error Silly
#endif

#include <linux/linkage.h>
#include <ci/internal/transport_config_opt.h>
#include <linux/socket.h>
#include <linux/signal.h>
#include <linux/version.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#include <net/compat.h>
#endif
#include <linux/poll.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/eventpoll.h>
#include <linux/fcntl.h>
#include <linux/net.h>

#include <ci/driver/kernel_compat.h>

#ifndef EFRM_HAVE_MSG_ITER
static inline void __msg_iov_init(struct msghdr *msg, struct iovec *iov,
                                  unsigned long iovlen)
{
  msg->msg_iov = iov;
  msg->msg_iovlen = iovlen;
}
#define oo_msg_iov_init(msg, dir, iov, iovlen, bytes) \
  __msg_iov_init(msg, iov, iovlen)
#else
#define oo_msg_iov_init(msg, dir, iov, iovlen, bytes) \
  iov_iter_init(&(msg)->msg_iter, dir, iov, iovlen, bytes)
#endif


#ifdef EFRM_SOCK_SENDMSG_NEEDS_LEN
static inline int oo_sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
  size_t bytes = 0;

#ifdef EFRM_HAVE_MSG_ITER
  bytes = msg->msg_iter.count;
#else
  int i;
  for( i = 0; i < msg->msg_iovlen; ++i )
    bytes += msg->msg_iov[i].iov_len;
#endif
  return sock_sendmsg(sock, msg, bytes);
}
#define sock_sendmsg oo_sock_sendmsg
#endif


#ifdef EFRM_SOCK_RECVMSG_NEEDS_BYTES
static inline int oo_sock_recvmsg(struct socket *sock, struct msghdr *msg,
                                  int flags)
{
  size_t bytes = 0;

#ifdef EFRM_HAVE_MSG_ITER
  bytes = msg->msg_iter.count;
#else
  int i;
  for( i = 0; i < msg->msg_iovlen; ++i )
    bytes += msg->msg_iov[i].iov_len;
#endif
  return sock_recvmsg(sock, msg, bytes, flags);

}
#define sock_recvmsg oo_sock_recvmsg
#endif

/*--------------------------------------------------------------------
 *
 * System calls
 *
 *--------------------------------------------------------------------*/

extern asmlinkage int efab_linux_sys_epoll_create1(int flags);
extern asmlinkage int efab_linux_sys_epoll_ctl(int epfd, int op, int fd,
                                               struct epoll_event *event);
extern asmlinkage int efab_linux_sys_epoll_wait(int epfd,
                                                struct epoll_event *events,
                                                int maxevents, int timeout);


#if defined(CONFIG_HUGETLB_PAGE) && CI_CFG_PKTS_AS_HUGE_PAGES && \
   (defined(__x86_64__) || defined(__aarch64__))
#define OO_DO_HUGE_PAGES
#endif

#ifdef CONFIG_NAMESPACES
#include <linux/nsproxy.h>
#ifdef EFRM_HAVE_TASK_NSPROXY
static inline struct nsproxy *
task_nsproxy_start(struct task_struct *tsk)
{
  rcu_read_lock();
  return task_nsproxy(tsk);
}
static inline void
task_nsproxy_done(struct task_struct *tsk)
{
  rcu_read_unlock();
}
#else
#ifdef EFRM_HAVE_SCHED_TASK_H
#include <linux/sched/task.h>
#endif
static inline struct nsproxy *
task_nsproxy_start(struct task_struct *tsk)
{
  task_lock(tsk);
  return tsk->nsproxy;
}
static inline void
task_nsproxy_done(struct task_struct *tsk)
{
  task_unlock(tsk);
}
#endif
#endif


DECLARE_PER_CPU(unsigned long, oo_budget_limit_last_ts);
extern unsigned long oo_avoid_wakeup_under_pressure;
static inline int/*bool*/ oo_avoid_wakeup_from_dl(void)
{
  if( oo_avoid_wakeup_under_pressure == 0 )
    return 0;
  return raw_cpu_read(oo_budget_limit_last_ts) +
    oo_avoid_wakeup_under_pressure >= jiffies;
}

#endif  /* __CI_DRIVER_EFAB_LINUX_ONLOAD__ */
