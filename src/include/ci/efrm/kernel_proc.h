/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides public API for managing /proc/ files.
 *
 * Copyright 2005-2012: Solarflare Communications Inc,
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

#ifndef __CI_EFRM_KERNEL_PROC_H__
#define __CI_EFRM_KERNEL_PROC_H__

/* For file_operations */
#include <linux/fs.h>
#include <linux/if.h>

#include <ci/tools/debug.h>

#include <driver/linux_affinity/kernel_compat.h>

/* This must be at least long enough to store a PCI domain:bus:slot.fn address.
 * The kernel uses a hard-coded value of 32 in lots of places for this. */
#define EFRM_PROC_NAME_LEN 32

/* We use interface names as filenames, too. */
CI_BUILD_ASSERT(EFRM_PROC_NAME_LEN >= IFNAMSIZ);

typedef void* efrm_pd_handle;

extern int
efrm_proc_dir_update_symlink(char const* dirname, const char* symlink_name);

extern efrm_pd_handle efrm_proc_device_dir_get(const char* device_name);
extern efrm_pd_handle efrm_proc_intf_dir_get(const char* intf_name);

extern int efrm_proc_device_dir_put(efrm_pd_handle handle);
extern int efrm_proc_intf_dir_put(efrm_pd_handle handle);

efrm_pd_handle
efrm_proc_create_file( char const* name, mode_t mode, efrm_pd_handle parent,
                       const struct proc_ops *fops, void* context );
extern void efrm_proc_remove_file( efrm_pd_handle handle );


#endif /* __CI_EFRM_KERNEL_PROC_H__ */
