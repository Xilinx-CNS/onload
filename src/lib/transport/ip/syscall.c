/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  stg
**  \brief  Access to sys calls
**   \date  2007/05/16
**    \cop  (c) Solarflare Communications Inc
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ef */


/* This is required to get pread() and pwrite() defined in <unistd.h> */
#define _GNU_SOURCE
#include <aio.h>
#include <resolv.h>
#include <netdb.h>

#include <ci/tools.h>
#include <ci/internal/transport_config_opt.h>

#include <onload/syscall_unix.h>

/* We are not interested whether siginterrupt() and friends are deprected.
 * We do not use the following functions, we need them to intercept is
 * a user application happened to use them. */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/* define the ci_sys_ pointers */
#define CI_MK_DECL(ret, fn, args)  ret (*ci_sys_##fn) args = fn
#include <onload/declare_syscalls.h.tmpl>


/*! \cidoxg_end */
