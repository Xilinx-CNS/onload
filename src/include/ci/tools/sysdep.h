/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_SYSDEP_H__
#define __CI_TOOLS_SYSDEP_H__


/* Make this header self-sufficient */
#include <ci/compat.h>


/**********************************************************************
 * Platform dependencies.
 */

#if defined(__KERNEL__)

# if defined(__oo_standalone__)

#  include <string.h> /* for memset */
#  define INADDR_ANY 0

   /* We need errno values, but we do not need errno variable: */
#  define _ERRNO_H
#    include <bits/errno.h>
#  undef _ERRNO_H

# else
#  include <ci/tools/platform/linux_kernel.h>
# endif

#else
# include <ci/tools/platform/unix.h>
#endif

typedef ci_int32 ci_uerr_t; /* range of OS user-mode return codes */
typedef ci_int32 ci_kerr_t; /* range of OS kernel-mode return codes */

#define CI_DECLARE_FLEX_ARRAY(type, name)          \
	struct {                                        \
		struct { } __empty_ ## name;                 \
		type name[];                                 \
	}

#define CI_MAX_ERRNO 1024
#define IS_ERR(ptr) \
  CI_UNLIKELY((uintptr_t)(ptr) >= (uintptr_t)-CI_MAX_ERRNO)
#define PTR_ERR(ptr) ((long)((uintptr_t)(ptr)))
#define PTR_ERR_OR_ZERO(ptr) (IS_ERR(ptr) ? PTR_ERR(ptr) : 0)
#define ERR_PTR(err) ((void*)(uintptr_t)(long)(err))

/**********************************************************************
 * Compiler and processor dependencies.
 */

#if defined(__GNUC__)

#if defined(__i386__) || defined(__x86_64__)
# include <ci/tools/platform/gcc_x86.h>
#elif defined(__PPC__)
#  include <ci/tools/platform/gcc_ppc.h>
#elif defined(__aarch64__)
#  include <ci/tools/platform/gcc_aarch64.h>
#else
# error Unknown processor.
#endif

#elif defined(__PGI)

# include <ci/tools/platform/pg_x86.h>

#elif defined(__INTEL_COMPILER)

/* Intel compilers v7 claim to be very gcc compatible. */
# include <ci/tools/platform/gcc_x86.h>

#else
# error Unknown compiler.
#endif


#endif  /* __CI_TOOLS_SYSDEP_H__ */

/*! \cidoxg_end */
