/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  David Riddoch
**  \brief  Declare the onload entry-points.
**   \date  2011/01/06
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_SYSCALLS_H__
#define __ONLOAD_SYSCALLS_H__

/*
 * This head declares the public interface for linking directly to the
 * Onload library.
 *
 */

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <signal.h>
#include <sys/sendfile.h>

/*! Generate declarations of pointers to the system calls */
#define CI_MK_DECL(ret, fn, args)  extern ret onload_##fn args
#include <onload/declare_syscalls.h.tmpl>


#endif  /* __ONLOAD_SYSCALLS_H__ */
