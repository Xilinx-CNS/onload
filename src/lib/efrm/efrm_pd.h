/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides internal API for protection domain resources.
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

#ifndef __EFRM_PD_H__
#define __EFRM_PD_H__


#define OWNER_ID_PHYS_MODE       0

struct efrm_pd;
struct efrm_resource_manager;


extern int
efrm_create_pd_resource_manager(struct efrm_resource_manager **);

extern void
efrm_pd_free(struct efrm_pd *);


/* API to OS-dependent part (proc files in Linux case) */

void *
efrm_pd_os_stats_ctor(struct efrm_pd *pd);

void
efrm_pd_os_stats_dtor(struct efrm_pd *pd, void *os_data);

struct efrm_bt_manager *
efrm_pd_bt_manager_next(struct efrm_pd *pd, struct efrm_bt_manager *prev);

#endif  /* __EFRM_PD_H__ */
