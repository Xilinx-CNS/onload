/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides debug-related API for efrm library using Linux kernel
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

#ifndef __CI_EFRM_DEBUG_LINUX_H__
#define __CI_EFRM_DEBUG_LINUX_H__

#define EFRM_PRINTK_PREFIX "[sfc efrm] "

#define EFRM_PRINTK(level, fmt, ...) \
	printk(level EFRM_PRINTK_PREFIX fmt "\n", __VA_ARGS__)


/* This macro will do <x> no more than (approximately) once per second.  In
 * other words, <x> is rate-limited.
 */
#define EFRM_LIMITED(x) do {				     \
	static uint64_t last_jiffy;			     \
	static int suppressed;				     \
	if (jiffies - last_jiffy > HZ) {		     \
		if (suppressed) {					\
			EFRM_PRINTK(KERN_WARNING,			\
				    "Rate limiting suppressed %d msgs",	\
				    suppressed);			\
		}							\
		x;						     \
		suppressed = 0;					     \
		last_jiffy = jiffies;				     \
	}							     \
	else {							     \
		++suppressed;					     \
	}							     \
} while(0)


/* Following macros should be used with non-zero format parameters
 * due to __VA_ARGS__ limitations.  Use "%s" with __FUNCTION__ if you can't
 * find better parameters. */
#define EFRM_ERR(fmt, ...)     EFRM_PRINTK(KERN_ERR, fmt, __VA_ARGS__)
#define EFRM_WARN(fmt, ...)    EFRM_PRINTK(KERN_WARNING, fmt, __VA_ARGS__)
#define EFRM_NOTICE(fmt, ...)  EFRM_PRINTK(KERN_NOTICE, fmt, __VA_ARGS__)
#if !defined(NDEBUG)
#define EFRM_TRACE(fmt, ...) EFRM_PRINTK(KERN_DEBUG, fmt, __VA_ARGS__)
#else
#define EFRM_TRACE(fmt, ...)
#endif

#define EFRM_WARN_ONCE(fmt, ...) do {                        \
	static bool warned = false;                          \
	if (!warned)                                         \
		EFRM_PRINTK(KERN_WARNING, fmt, __VA_ARGS__); \
	warned = true;                                       \
} while(0)

/* Defined for messaging that may be high rate in normal operation */
#define EFRM_ERR_LIMITED(fmt, ...)    EFRM_LIMITED(EFRM_ERR(fmt, __VA_ARGS__))
#define EFRM_WARN_LIMITED(fmt, ...)   EFRM_LIMITED(EFRM_WARN(fmt, __VA_ARGS__))
#define EFRM_NOTICE_LIMITED(fmt, ...) EFRM_LIMITED(EFRM_NOTICE(fmt, __VA_ARGS__))

#ifndef NDEBUG
#define EFRM_ASSERT(cond)  BUG_ON((cond) == 0)
#define _EFRM_ASSERT(cond, file, line) \
	do {								\
		if (unlikely(!(cond))) {				\
			EFRM_ERR("assertion \"%s\" failed at %s %d",	\
				 #cond, file, line);			\
			BUG();						\
		}							\
	} while (0)

#define EFRM_DO_DEBUG(expr) expr
#define EFRM_VERIFY_EQ(expr, val) EFRM_ASSERT((expr) == (val))
#else
#define EFRM_ASSERT(cond)
#define EFRM_DO_DEBUG(expr)
#define EFRM_VERIFY_EQ(expr, val) expr
#endif

/* Build time asserts. We paste the line number into the type name
 * so that the macro can be used more than once per file even if the
 * compiler objects to multiple identical typedefs. Collisions
 * between use in different header files is still possible. */
#ifndef EFRM_BUILD_ASSERT
#define __EFRM_BUILD_ASSERT_NAME(_x) __EFRM_BUILD_ASSERT_ILOATHECPP(_x)
#define __EFRM_BUILD_ASSERT_ILOATHECPP(_x)  __EFRM_BUILD_ASSERT__ ##_x
#define EFRM_BUILD_ASSERT(e) \
	{ typedef char __EFRM_BUILD_ASSERT_NAME(__LINE__)[(e) ? 1 : -1] \
		__attribute__((unused)); }
#endif

#endif /* __CI_EFRM_DEBUG_LINUX_H__ */
