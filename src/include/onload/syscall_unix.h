/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  Tom Kelly
**  \brief  Unix syscall interface
**   \date  2003/12/18
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_ul */

#ifndef __CI_UL_SYSCALL_UNIX_H__
#define __CI_UL_SYSCALL_UNIX_H__

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <signal.h>

#include "libc_compat.h"
#include <ci/internal/transport_config_opt.h>



extern ssize_t __read_chk (int fd, void *buf, size_t nbytes, size_t buflen);
extern ssize_t __recv_chk (int fd, void *buf, size_t nbytes, size_t buflen,
                           int flags);
extern ssize_t __recvfrom_chk (int fd, void *buf, size_t nbytes, size_t buflen,
                              int flags, struct sockaddr*, socklen_t*);
extern int __poll_chk (struct pollfd *__fds, nfds_t __nfds, int __timeout,
                       size_t __fdslen);
extern int __ppoll_chk (struct pollfd *__fds, nfds_t __nfds,
                        const struct timespec *, const sigset_t *,
                       size_t __fdslen);
extern __sighandler_t bsd_signal(int signum, __sighandler_t handler);
extern __sighandler_t sysv_signal(int signum, __sighandler_t handler);


/*! Generate declarations of pointers to the system calls */
#define CI_MK_DECL(ret,fn,args)  extern ret (*ci_sys_##fn) args CI_HV
# include <onload/declare_syscalls.h.tmpl>


#ifdef _STAT_VER
#define ci_sys_fstat(__fd, __statbuf)                          \
         ci_sys___fxstat(_STAT_VER, (__fd), (__statbuf))
#ifdef __USE_LARGEFILE64
# define ci_sys_fstat64(__fd, __statbuf)                       \
          ci_sys___fxstat64(_STAT_VER, (__fd), (__statbuf))
#endif
#endif


#endif  /* __CI_UL_SYSCALL_UNIX_H__ */
