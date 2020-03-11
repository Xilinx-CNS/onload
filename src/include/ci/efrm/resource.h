/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides public interface of efrm library -- resource handling.
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

#ifndef __CI_EFRM_RESOURCE_H__
#define __CI_EFRM_RESOURCE_H__

/*--------------------------------------------------------------------
 *
 * headers for type dependencies
 *
 *--------------------------------------------------------------------*/

#include <ci/efhw/efhw_types.h>
#include <ci/efrm/resource_id.h>
#include <ci/efrm/sysdep.h>
#include <ci/efhw/common_sysdep.h>

#ifndef __ci_driver__
#error "Driver-only file"
#endif

/*--------------------------------------------------------------------
 *
 * struct efrm_resource - represents an allocated resource
 *                   (eg. pinned pages of memory, or resource on a NIC)
 *
 *--------------------------------------------------------------------*/

/*! Representation of an allocated resource */
struct efrm_resource {
	int rs_ref_count;
	int rs_instance;
	int rs_type;
	struct efrm_client *rs_client;
	struct list_head rs_client_link;
	struct list_head rs_manager_link;
};


#define EFRM_RESOURCE_FMT          "[rs:%d,%p]"
#define EFRM_RESOURCE_PRI_ARG(rs)  (rs)->rs_instance, (rs)


/*--------------------------------------------------------------------
 *
 * managed resource abstraction
 *
 *--------------------------------------------------------------------*/

/*! Factory for resources of a specific type */
struct efrm_resource_manager {
	const char *rm_name;	/*!< human readable only */
	/** 
	 * This lock exists to protect the linked lists (including
	 * some in other data structures such as the flush-related
	 * lists) and associated state
	 */
	spinlock_t rm_lock;
#ifndef NDEBUG
	unsigned rm_type;
#endif
	int rm_resources;
	int rm_resources_hiwat;
        int rm_resources_total; /* or -1 for no specified limit */
	struct list_head rm_resources_list;
	/**
	 * Destructor for the resource manager. Other resource managers
	 * might be already dead, although the system guarantees that
	 * managers are destructed in the order by which they were created
	 */
	void (*rm_dtor)(struct efrm_resource_manager *);
};

#ifdef NDEBUG
# define EFRM_RESOURCE_ASSERT_VALID(rs, rc_mbz)
# define EFRM_RESOURCE_MANAGER_ASSERT_VALID(rm)
#else
/*! Check validity of resource and report on failure */
extern void efrm_resource_assert_valid(struct efrm_resource *,
				       int rc_may_be_zero,
				       const char *file, int line);
# define EFRM_RESOURCE_ASSERT_VALID(rs, rc_mbz) \
	efrm_resource_assert_valid((rs), (rc_mbz), __FILE__, __LINE__)

/*! Check validity of resource manager and report on failure */
extern void efrm_resource_manager_assert_valid(struct efrm_resource_manager *,
					       const char *file, int line);
# define EFRM_RESOURCE_MANAGER_ASSERT_VALID(rm) \
	efrm_resource_manager_assert_valid((rm), __FILE__, __LINE__)
#endif


extern void efrm_resource_ref(struct efrm_resource *rs);
extern void efrm_resource_release(struct efrm_resource *);
extern int  __efrm_resource_release(struct efrm_resource *);

extern void efrm_resource_manager_add_total(int rs_type,
                                            int n_avail);
extern void efrm_resource_manager_del_total(int rs_type,
                                            int n_avail);

#endif /* __CI_EFRM_RESOURCE_H__ */
