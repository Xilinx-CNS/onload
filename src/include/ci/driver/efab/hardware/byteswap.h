/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2019 Xilinx, Inc. */
/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2012: Solarflare Communications Inc,
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

/* The file is a partial copy-paste from sysdep_unix.h */

#ifndef __CI_DRIVER_EFAB_HARDWARE_BYTESWAP_H__
#define __CI_DRIVER_EFAB_HARDWARE_BYTESWAP_H__

#include <endian.h>
#include <byteswap.h>


#if defined(__i386__) || defined(__x86_64__)
# define EF_VI_LITTLE_ENDIAN   1
#elif defined(__BYTE_ORDER)
# define EF_VI_LITTLE_ENDIAN   (__BYTE_ORDER == __LITTLE_ENDIAN)
#elif defined(__LITTLE_ENDIAN)
# define EF_VI_LITTLE_ENDIAN   1
#elif defined(__BIG_ENDIAN)
# define EF_VI_LITTLE_ENDIAN   0
#else
# error "EF_VI_LITTLE_ENDIAN needs fixing"
#endif


#if EF_VI_LITTLE_ENDIAN
# define cpu_to_le16(v)   (v)
# define le16_to_cpu(v)   (v)
# define cpu_to_le32(v)   (v)
# define le32_to_cpu(v)   (v)
# define cpu_to_le64(v)   (v)
# define le64_to_cpu(v)   (v)
#else
# define cpu_to_le16(v)   bswap_16(v)
# define le16_to_cpu(v)   bswap_16(v)
# define cpu_to_le32(v)   bswap_32(v)
# define le32_to_cpu(v)   bswap_32(v)
# define cpu_to_le64(v)   bswap_64(v)
# define le64_to_cpu(v)   bswap_64(v)
#endif


#endif /* __CI_DRIVER_EFAB_HARDWARE_BYTESWAP_H__ */
