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

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_CONFIG_H__
#define __CI_TOOLS_CONFIG_H__


/**********************************************************************
 * Debugging.
 */

#define CI_INCLUDE_ASSERT_VALID           0

/* Set non-zero to allow info about who has allocated what to appear in
 * /proc/drivers/level5/mem.
 * However - Note that doing so can lead to segfault when you unload the
 * driver, and other weirdness.  i.e. I don't think the code for is quite
 * right (written by Oktet, hacked by gel), but it does work well enough to be
 * useful.
 */
#define CI_MEMLEAK_DEBUG_ALLOC_TABLE	  0


#endif  /* __CI_TOOLS_CONFIG_H__ */
/*! \cidoxg_end */
