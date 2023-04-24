/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/*
** Copyright 2005-2012  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/**************************************************************************\
*//*! \file linux_trampoline.c System call trampolines for Linux
** <L5_PRIVATE L5_SOURCE>
** \author  gel,mjs
**  \brief  Package - driver/linux	Linux driver support
**   \date  2005/03/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */
 
/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include <ci/efrm/syscall.h>
#include <linux/unistd.h>
#include <onload/linux_onload.h>

/*--------------------------------------------------------------------
 *
 * Platform-specific stuff
 *
 *--------------------------------------------------------------------*/

#include <asm/processor.h>
#ifdef __x86_64__
#include <asm/msr.h>
#endif
#ifdef __aarch64__
#include <asm/sysreg.h>
#include <asm/esr.h>
#endif
#include <asm/insn.h>
#include <asm/percpu.h>



/* A way to call the original sys_close, exported to other parts of the code.
 */
asmlinkage int efab_linux_sys_close(int fd)
{
  return (int)SYSCALL_DISPATCHn(1, close, (int), fd);
}


asmlinkage int efab_linux_sys_epoll_create1(int flags)
{
  return (int)SYSCALL_DISPATCHn(1, epoll_create1, (int), flags);
}

asmlinkage int efab_linux_sys_epoll_ctl(int epfd, int op, int fd,
                                        struct epoll_event *event)
{
  return (int)SYSCALL_DISPATCHn(4, epoll_ctl,
                                (int, int, int, struct epoll_event*),
                                epfd, op, fd, event);
}

asmlinkage int efab_linux_sys_epoll_wait(int epfd, struct epoll_event *events,
                                         int maxevents, int timeout)
{
#ifdef __aarch64__
  return (int)SYSCALL_DISPATCHn(6, epoll_pwait,
                                (int, struct epoll_event*, int, int,
                                 const sigset_t*, size_t),
                                epfd, events, maxevents,
                                timeout, NULL, sizeof(sigset_t));
#else
  return (int)SYSCALL_DISPATCHn(4, epoll_wait,
                                (int, struct epoll_event*, int, int),
                                epfd, events, maxevents, timeout);
#endif
}

