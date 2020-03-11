/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

/*! \cidoxg_include_ci_compat  */

#ifndef __CI_COMPAT_SYSDEP_H__
#define __CI_COMPAT_SYSDEP_H__


/**********************************************************************
 * Platform definition fixups.
 */

#if defined(__ci_ul_driver__) && !defined(__ci_driver__)
# define __ci_driver__
#endif

/**********************************************************************
 * Sanity checks (no cheating!)
 */

#if defined(__KERNEL__) && !defined(__ci_driver__)
# error Insane.
#endif

#if defined(__KERNEL__) && defined(__ci_ul_driver__)
# error Madness.
#endif

/**********************************************************************
 * Compiler and processor dependencies.
 */

#if defined(__GNUC__)

# include <ci/compat/gcc.h>

# if defined(__i386__)
#  include <ci/compat/x86.h>
#  include <ci/compat/gcc_x86.h>
# elif defined(__x86_64__)
#  include <ci/compat/x86_64.h>
#  include <ci/compat/gcc_x86.h>
# elif defined(__PPC__)
#  include <ci/compat/ppc.h>
#  include <ci/compat/gcc_ppc.h>
# elif defined(__aarch64__)
#  include <ci/compat/aarch64.h>
#  include <ci/compat/gcc_aarch64.h>
# elif defined(__mips__)
#  include <ci/compat/mips.h>
#  include <ci/compat/gcc_mips.h>
# else
#  error Unknown processor - GNU C
# endif

#elif defined(__PGI)

# include <ci/compat/x86.h>
# include <ci/compat/pg_x86.h>

#elif defined(__INTEL_COMPILER)

/* Intel compilers v7 claim to be very gcc compatible. */
# if __INTEL_COMPILER >= 700
#  include <ci/compat/gcc.h>
#  include <ci/compat/x86.h>
#  include <ci/compat/gcc_x86.h>
# else
#  error Old Intel compiler not supported.  Yet.
# endif

#else
# error Unknown compiler.
#endif


/**********************************************************************
 * Defaults for anything left undefined.
 */

#ifndef  CI_LIKELY
# define CI_LIKELY(t)    (t)
# define CI_UNLIKELY(t)  (t)
#endif

#ifndef  ci_restrict
# define ci_restrict
#endif

#ifndef  ci_inline
# define ci_inline  static inline
#endif

#ifndef  ci_noinline
# define ci_noinline  static
#endif

#endif  /* __CI_COMPAT_SYSDEP_H__ */

/*! \cidoxg_end */
