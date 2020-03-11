/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides public API for NIC table.
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

#ifndef __CI_EFRM_NIC_TABLE_H__
#define __CI_EFRM_NIC_TABLE_H__

#include <ci/efhw/efhw_types.h>
#include <ci/efrm/sysdep.h>

/*--------------------------------------------------------------------
 *
 * struct efrm_nic_table - top level driver object keeping all NICs -
 * implemented in driver_object.c
 *
 *--------------------------------------------------------------------*/

/*! Comment? */
struct efrm_nic_table {
	/*! nics attached to this driver */
	struct efhw_nic *nic[EFHW_MAX_NR_DEVS];
	spinlock_t lock;	/*!< lock for table modifications */
	atomic_t ref_count;	/*!< refcount for users of nic table */
	int down;		/*!< used on the stop()/fini() path */
};

/* Resource driver structures used by other drivers as well */
extern struct efrm_nic_table *efrm_nic_tablep;

static inline void efrm_nic_table_hold(void)
{
	atomic_inc(&efrm_nic_tablep->ref_count);
        /* Ensure ordering between ref_cnt and down */
        smp_rmb();
}

static inline void efrm_nic_table_rele(void)
{
	atomic_dec(&efrm_nic_tablep->ref_count);
}

static inline int efrm_nic_table_held(void)
{
	return atomic_read(&efrm_nic_tablep->ref_count) != 0;
}

static inline int efrm_nic_table_down(void)
{
	return efrm_nic_tablep->down != 0;
}

/* Run code block _x multiple times with variable nic set to each
 * registered NIC in turn.
 *
 * DO NOT "break" out of this loop early
 */
#define EFRM_FOR_EACH_NIC(_nic_i, _nic)					\
	for ((_nic_i) = (efrm_nic_table_hold(), 0);	       		\
	     (_nic_i) < EFHW_MAX_NR_DEVS || (efrm_nic_table_rele(), 0);	\
	     (_nic_i)++)						\
		if (efrm_nic_table_down() ||				\
		    ((_nic) = efrm_nic_tablep->nic[_nic_i]) == NULL)	\
			continue;					\
		else


#endif /* __CI_EFRM_NIC_TABLE_H__ */
