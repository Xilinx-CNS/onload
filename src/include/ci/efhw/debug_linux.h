/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides debug-related API for efhw library using Linux kernel
 * primitives.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
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

#ifndef __CI_EFHW_DEBUG_LINUX_H__
#define __CI_EFHW_DEBUG_LINUX_H__

#define EFHW_PRINTK_PREFIX "[sfc efhw] "

#ifndef printk_nl
#define printk_nl "\n"
#endif

#define EFHW_PRINTK(level, fmt, ...) \
	printk(level EFHW_PRINTK_PREFIX fmt printk_nl, __VA_ARGS__)

/* This macro will do <x> no more than (approximately) once per second.  In
 * other words, <x> is rate-limited.
 */
#define EFHW_LIMITED(x) do {                    \
	static uint64_t last_jiffy;		\
	if (jiffies - last_jiffy > HZ) { x; }	\
	last_jiffy = jiffies;			\
} while(0)

/* Following macros should be used with non-zero format parameters
 * due to __VA_ARGS__ limitations.  Use "%s" with __FUNCTION__ if you can't
 * find better parameters. */
#define EFHW_ERR(fmt, ...)     EFHW_PRINTK(KERN_ERR, fmt, __VA_ARGS__)
#define EFHW_WARN(fmt, ...)    EFHW_PRINTK(KERN_WARNING, fmt, __VA_ARGS__)
#define EFHW_NOTICE(fmt, ...)  EFHW_PRINTK(KERN_NOTICE, fmt, __VA_ARGS__)
#if 0 && !defined(NDEBUG)
#define EFHW_TRACE(fmt, ...) EFHW_PRINTK(KERN_DEBUG, fmt, __VA_ARGS__)
#else
#define EFHW_TRACE(fmt, ...)
#endif

/* Defined for messaging that may be high rate in normal operation */
#define EFHW_ERR_LIMITED(fmt, ...)    EFHW_LIMITED(EFHW_ERR(fmt, __VA_ARGS__))
#define EFHW_WARN_LIMITED(fmt, ...)   EFHW_LIMITED(EFHW_WARN(fmt, __VA_ARGS__))
#define EFHW_NOTICE_LIMITED(fmt, ...) EFHW_LIMITED(EFHW_NOTICE(fmt, __VA_ARGS__))

#ifndef NDEBUG
#define EFHW_ASSERT(cond)  BUG_ON((cond) == 0)
#define EFHW_DO_DEBUG(expr) expr
#else
#define EFHW_ASSERT(cond)
#define EFHW_DO_DEBUG(expr)
#endif

#define EFHW_TEST(expr)			\
	do {				\
		if (unlikely(!(expr)))	\
		BUG();			\
	} while (0)

/* Build time asserts. We paste the line number into the type name
 * so that the macro can be used more than once per file even if the
 * compiler objects to multiple identical typedefs. Collisions
 * between use in different header files is still possible. */
#ifndef EFHW_BUILD_ASSERT
#define __EFHW_BUILD_ASSERT_NAME(_x) __EFHW_BUILD_ASSERT_ILOATHECPP(_x)
#define __EFHW_BUILD_ASSERT_ILOATHECPP(_x)  __EFHW_BUILD_ASSERT__ ##_x
#define EFHW_BUILD_ASSERT(e) \
	{ typedef char __EFHW_BUILD_ASSERT_NAME(__LINE__)[(e) ? 1 : -1] \
		__attribute__((unused)); }
#endif

#endif /* __CI_EFHW_DEBUG_LINUX_H__ */
