/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          sfc_affinity: flow steering
 *
 * This file defines the interface exported by the sfc_affinity driver to
 * other drivers.
 *
 * Copyright 2009-2011: Solarflare Communications, Inc.,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <onload-dev@solarflare.com>
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

#ifndef __CI_AFFINITY_K_DRV_INTF_H__
#define __CI_AFFINITY_K_DRV_INTF_H__


#ifndef __KERNEL__
# error "This is a kernel interface."
#endif


struct net_device;

/* Access core-to-queue mapping from other drivers.  Returns -1 if cpu is
 * out of range, or if the ifindex is not known to sfc_affinity, or if the
 * core-to-queue mapping has not been initialised.
 */
extern int sfc_affinity_cpu_to_channel_dev(const struct net_device* dev,
                                           int cpu);


#endif  /* __CI_AFFINITY_K_DRV_INTF_H__ */
