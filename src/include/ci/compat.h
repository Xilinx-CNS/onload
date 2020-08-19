/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
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

/*
 * \author  djr
 *  \brief  Compatability layer.  Provides definitions of fundamental
 *          types and definitions that are used throughout CI source
 *          code.  It does not introduce any link time dependencies,
 *          or include any unnecessary system headers.
 */
/*! \cidoxg_include_ci */

#ifndef __CI_COMPAT_H__
#define __CI_COMPAT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <ci/compat/primitive.h>
#include <ci/compat/sysdep.h>
#include <ci/compat/utils.h>


#ifdef __cplusplus
}
#endif

#endif  /* __CI_COMPAT_H__ */

/*! \cidoxg_end */
