/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides private API of efrm library -- resource handling.
 * This API is not designed for use outside of SFC resource driver.
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

#ifndef __CI_EFRM_PRIVATE_H__
#define __CI_EFRM_PRIVATE_H__

#include <ci/efrm/resource.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/sysdep.h>
#include <ci/efrm/debug.h>
#include "kernel_compat.h"


/*! Initialize the fields in the provided resource manager memory area
 *   \param rm         The area of memory to be initialized
 *   \param dtor       A method to destroy the resource manager
 *   \param name       A Textual name for the resource manager
 *   \param type       The type of resource managed
 *   \param initial_table_size Initial size of the ID table
 *   \param auto_destroy Destroy resource manager on driver onload iff true
 *
 * A default table size is provided if the value 0 is provided.
 */
extern int
efrm_resource_manager_ctor(struct efrm_resource_manager *rm,
			   void (*dtor)(struct efrm_resource_manager *),
			   const char *name, unsigned type);

extern void efrm_resource_manager_dtor(struct efrm_resource_manager *rm);


#endif /* __CI_EFRM_PRIVATE_H__ */
