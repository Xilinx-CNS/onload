/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides public API for protection domain resource.
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

#ifndef __CI_EFRM_PIO_H__
#define __CI_EFRM_PIO_H__


struct efrm_pio;
struct efrm_pd;
struct efrm_vi;
struct efrm_resource;

extern int 
efrm_pio_realloc(struct efrm_pd *pd, struct efrm_pio *pio, struct efrm_vi *vi);

extern int
efrm_pio_alloc(struct efrm_pd *, struct efrm_pio **);

extern bool
efrm_pio_release(struct efrm_pio *, bool);

extern struct efrm_resource *
efrm_pio_to_resource(struct efrm_pio *);

extern struct efrm_pio *
efrm_pio_from_resource(struct efrm_resource *);

extern int
efrm_pio_link_vi(struct efrm_pio *, struct efrm_vi *);

extern int
efrm_pio_unlink_vi(struct efrm_pio *, struct efrm_vi *,
		   bool* freed_resource_out);

extern int
efrm_pio_map_kernel(struct efrm_vi *, void **);

extern void
efrm_pio_unmap_kernel(struct efrm_vi *, void *);

extern int 
efrm_pio_get_size(struct efrm_pio *);

extern int
efrm_ctpio_map_kernel(struct efrm_vi *, void **);

extern void
efrm_ctpio_unmap_kernel(struct efrm_vi *, void *);


#endif /* __CI_EFRM_PIO_H__ */
