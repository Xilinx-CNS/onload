/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides public API for vi_set resource.
 *
 * Copyright 2011-2011: Solarflare Communications Inc,
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

#ifndef __CI_EFRM_VI_SET_H__
#define __CI_EFRM_VI_SET_H__

#include <ci/efrm/resource.h>
#include <ci/efhw/common.h>
#include <ci/efrm/debug.h>
#include <ci/efrm/efrm_filter.h> /* for EFRM_RSS_* */


struct efrm_vi_set;
struct efrm_vi;
struct efrm_pd;


extern int
efrm_vi_set_alloc(struct efrm_pd *, int n_vis,
		  int efhw_rss_mode,
		  struct efrm_vi_set **vi_set_out);

extern int
efrm_vi_set_redistribute_queue(struct efrm_vi_set*, uint32_t q_id);

extern void
efrm_vi_set_release(struct efrm_vi_set *);

extern int
efrm_vi_set_num_vis(struct efrm_vi_set *);

extern int
efrm_vi_set_get_base(struct efrm_vi_set *);

#define EFRM_RSS_MODE_ID_DEFAULT 0
#define EFRM_RSS_MODE_ID_SRC     0
#define EFRM_RSS_MODE_ID_DST     1
extern int
efrm_vi_set_get_rss_context(struct efrm_vi_set *, unsigned rss_id);

extern struct efrm_resource *
efrm_vi_set_to_resource(struct efrm_vi_set *);

extern struct efrm_vi_set *
efrm_vi_set_from_resource(struct efrm_resource *);

extern struct efrm_pd *
efrm_vi_set_get_pd(struct efrm_vi_set *);


#endif /* __CI_EFRM_VI_SET_H__ */
