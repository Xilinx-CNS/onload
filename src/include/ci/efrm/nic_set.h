/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides public API for NIC sets.
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

#ifndef __CI_EFRM_NIC_SET_H__
#define __CI_EFRM_NIC_SET_H__

#include <ci/compat.h>
#include <ci/efrm/debug.h>
#include <ci/efhw/common_sysdep.h>
#include <ci/efhw/efhw_config.h>

/*--------------------------------------------------------------------
 *
 * efrm_nic_set_t - tracks which NICs something has been done on
 *
 *--------------------------------------------------------------------*/

/* Internal suructure of efrm_nic_set_t should not be referenced outside of
 * this file.  Add a new accessor if you should do it. */
typedef struct {
	uint64_t nics CI_ALIGN(8);
} efrm_nic_set_t;

#if EFHW_MAX_NR_DEVS > 64
#error change efrm_nic_set to handle EFHW_MAX_NR_DEVS number of devices
#endif

static inline bool
efrm_nic_set_read(const efrm_nic_set_t *nic_set, unsigned index)
{
	EFRM_ASSERT(nic_set);
	EFRM_ASSERT(index < EFHW_MAX_NR_DEVS && index < 64);
	return (nic_set->nics & (1 << index)) ? true : false;
}

static inline void
efrm_nic_set_write(efrm_nic_set_t *nic_set, unsigned index, bool value)
{
	EFRM_ASSERT(nic_set);
	EFRM_ASSERT(index < EFHW_MAX_NR_DEVS && index < 64);
	EFRM_ASSERT(value == false || value == true);
	nic_set->nics = (nic_set->nics & (~(1 << index))) + (value << index);
}

static inline void efrm_nic_set_clear(efrm_nic_set_t *nic_set)
{
	nic_set->nics = 0;
}

static inline void efrm_nic_set_all(efrm_nic_set_t *nic_set)
{
	nic_set->nics = (uint64_t)-1;
}

static inline bool efrm_nic_set_is_all_clear(efrm_nic_set_t *nic_set)
{
	return nic_set->nics == 0 ? true : false;
}

#define EFRM_NIC_SET_FMT CI_PRIx64

static inline uint64_t efrm_nic_set_pri_arg(efrm_nic_set_t *nic_set)
{
	return nic_set->nics;
}


#endif /* __CI_EFRM_NIC_SET_H__ */
