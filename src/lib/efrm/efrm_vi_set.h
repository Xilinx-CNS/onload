/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides internal API for VI-set resources.
 *
 * Copyright 2012-2012: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
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

#ifndef __EFRM_VI_SET_H__
#define __EFRM_VI_SET_H__

#include <ci/efrm/resource.h>
#include <ci/efrm/vi_allocation.h>
#include <ci/efrm/efrm_filter.h>

/* EFRM_RSS_MODE_ID_MAX needs to be large engough
 * to accomodate all modes.
 * See EFRM_RSS_MODE_ID in vi_set.h
 */
#define EFRM_RSS_MODE_ID_MAX 1

struct efrm_rss_context {
	/* Driverlink ID for this RSS context. */
	uint32_t rss_context_id;
	/* An EFRM_RSS_MODE_ID_* constant indicating the intended purpose of
	 * this RSS context. */
	uint32_t rss_mode;
	/* Bitmap indicating the VIs in the set that are referenced by the
	 * indirection table. */
	uint64_t indirected_vis;
	/* The indirection table programmed to the NIC for this RSS context. */
	uint32_t indirection_table[EFRM_RSS_INDIRECTION_TABLE_LEN];
	/* The hash key programmed to the NIC for this RSS context. */
	uint8_t rss_hash_key[EFRM_RSS_KEY_LEN];
};

struct efrm_vi_set {
	struct efrm_resource      rs;
	struct efrm_vi_allocation allocation;
	struct efrm_pd           *pd;
	spinlock_t                allocation_lock;
	struct completion         allocation_completion;
	uint64_t                  free;
	struct efrm_rss_context   rss_context[EFRM_RSS_MODE_ID_MAX + 1];
	int                       n_vis;
	int                       n_vis_flushing;
	int                       n_flushing_waiters;
};


extern int
efrm_create_vi_set_resource_manager(struct efrm_resource_manager **);

extern void
efrm_vi_set_free(struct efrm_vi_set *);


#endif  /* __EFRM_VI_SET_H__ */
