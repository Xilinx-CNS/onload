/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains functions to assert validness of resources and
 * resource manager in DEBUG build of the resource driver.
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

#include <ci/efrm/sysdep.h>
#include <ci/efrm/private.h>
#include "efrm_internal.h"


#ifndef NDEBUG
#include <ci/efrm/resource.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/debug.h>


void
efrm_resource_manager_assert_valid(struct efrm_resource_manager *rm,
				   const char *file, int line)
{
	_EFRM_ASSERT(rm, file, line);
	_EFRM_ASSERT(rm->rm_name, file, line);
	_EFRM_ASSERT(rm->rm_type < EFRM_RESOURCE_NUM, file, line);
	_EFRM_ASSERT(rm->rm_dtor, file, line);
}
EXPORT_SYMBOL(efrm_resource_manager_assert_valid);

/*
 * \param rs                    resource to validate
 * \param ref_count_is_zero     One of 3 values
 *                                > 0  - check ref count is zero
 *                                = 0  - check ref count is non-zero
 *                                < 0  - ref count could be any value
 */
void
efrm_resource_assert_valid(struct efrm_resource *rs, int ref_count_is_zero,
			   const char *file, int line)
{
	struct efrm_resource_manager *rm;

	_EFRM_ASSERT(rs, file, line);

	if (ref_count_is_zero >= 0) {
		if (!(ref_count_is_zero || rs->rs_ref_count > 0)
		    || !(!ref_count_is_zero || rs->rs_ref_count == 0))
			EFRM_WARN("%s: check %szero ref=%d " EFRM_RESOURCE_FMT,
				  __FUNCTION__,
				  ref_count_is_zero == 0 ? "non-" : "",
				  rs->rs_ref_count,
				  EFRM_RESOURCE_PRI_ARG(rs));

		_EFRM_ASSERT(!(ref_count_is_zero == 0) ||
			     rs->rs_ref_count != 0, file, line);
		_EFRM_ASSERT(!(ref_count_is_zero > 0) ||
			     rs->rs_ref_count == 0, file, line);
	}

	rm = efrm_rm_table[rs->rs_type];
	efrm_resource_manager_assert_valid(rm, file, line);
}
EXPORT_SYMBOL(efrm_resource_assert_valid);

#endif
