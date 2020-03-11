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

#ifndef __CI_COMPAT_PRIMITIVE_H__
#define __CI_COMPAT_PRIMITIVE_H__


/**********************************************************************
 * Primitive types.
 */

typedef unsigned char                   ci_uint8;
typedef signed char                            ci_int8;

typedef unsigned short                  ci_uint16;
typedef short                           ci_int16;

typedef unsigned int                    ci_uint32;
typedef int                             ci_int32;

/* 64-bit support is platform dependent. */


/**********************************************************************
 * Other fancy types.
 */

typedef ci_uint8                        ci_octet;

typedef enum {
  CI_FALSE = 0,
  CI_TRUE
} ci_boolean_t;


typedef char                            ci_string256[256];

/**********************************************************************
 * Some nice types you'd always assumed were standards.
 * (Really, they are SYSV "standards".)
 */

#if defined(__oo_standalone__)
#include <stddef.h>
#include <stdint.h>
typedef char*                           caddr_t;
#elif defined(__KERNEL__)
#include <linux/types.h>
#else
#include <sys/types.h>
#endif


#endif  /* __CI_COMPAT_PRIMITIVE_H__ */

/*! \cidoxg_end */
