/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2019 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides some event-related macros.  This file is designed for
 * use from kernel and from the userland contexts.
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

#ifndef __CI_EFHW_EVENTQ_MACROS_H__
#define __CI_EFHW_EVENTQ_MACROS_H__

#include <ci/efhw/common.h>

/*--------------------------------------------------------------------
 *
 * Event Queue manipulation
 *
 *--------------------------------------------------------------------*/

#define EFHW_EVENT_OFFSET(q, s, i)					\
	(((s)->evq_ptr - (i) * (int32_t)sizeof(efhw_event_t))		\
	 & (q)->evq_mask)

#define EFHW_EVENT_PTR(q, s, i)						\
	((efhw_event_t *)((q)->evq_base + EFHW_EVENT_OFFSET(q, s, i)))

#define EFHW_EVENTQ_NEXT(s)						\
	do { ((s)->evq_ptr += sizeof(efhw_event_t)); } while (0)

#define EFHW_EVENTQ_PREV(s)						\
	do { ((s)->evq_ptr -= sizeof(efhw_event_t)); } while (0)

  /* Due to crazy chipsets, we see the event words being written in
   * arbitrary order (bug4539).  So test for presence of event must ensure
   * that both halves have changed from the null.
   */
	#define EFHW_IS_EVENT(evp)			\
		(((evp)->opaque.a != (uint32_t)-1) &&	\
		 ((evp)->opaque.b != (uint32_t)-1))
	#define EFHW_CLEAR_EVENT(evp)       ((evp)->u64 = (uint64_t)-1)
	#define EFHW_CLEAR_EVENT_VALUE      0xff


#define EFHW_EVENT_OVERFLOW(evq, s)			\
	(EFHW_IS_EVENT(EFHW_EVENT_PTR(evq, s, 1)))

#endif /* __CI_EFHW_EVENTQ_MACROS_H__ */
