/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains /proc/driver/sfc_resource/ implementation.
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

#include <ci/driver/internal.h>
#include <ci/efrm/debug.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/kernel_proc.h>
#include <linux/proc_fs.h>
#include <ci/driver/kernel_compat.h>

/** Top level directory for sfc specific stats **/
static struct proc_dir_entry *efrm_proc_root = NULL;
static struct proc_dir_entry *efrm_proc_nic_dir = NULL;
static struct proc_dir_entry *efrm_proc_resources = NULL;

/** Subdirectories (interfaces) **/
struct efrm_procdir_s {
	char efrm_pd_name[EFRM_PROC_NAME_LEN];
	int efrm_pd_refcount;
	struct efrm_procdir_s* efrm_pd_next;
/*	int efrm_pd_access_mode; */
	struct efrm_file_s* efrm_pd_child;
	struct proc_dir_entry* efrm_pd_dir;
};
struct efrm_file_s {
	struct efrm_procdir_s* efrm_pf_parent;
	char efrm_pf_name[EFRM_PROC_NAME_LEN];
	struct efrm_file_s* efrm_pf_next;
	struct proc_dir_entry* efrm_pf_file;
};
static struct efrm_procdir_s* efrm_pd_device_list = NULL;
static struct efrm_procdir_s* efrm_pd_intf_list = NULL;
static DEFINE_MUTEX(efrm_pd_mutex);

/****************************************************************************
 *
 * /proc/drivers/sfc_resource/devices/<PCI bus address>/
 * /proc/drivers/sfc_resource/<interface name>/
 *
 ****************************************************************************/

#define EFRM_PROC_DEVICES_NAME "devices"


static efrm_pd_handle
efrm_proc_dir_get(char const* dirname, struct proc_dir_entry* parent,
		  struct efrm_procdir_s** entry_list_head)
{
	/* Acquire a handle to a directory; creates the directory if needed */
	struct efrm_procdir_s* rval = NULL;
	struct efrm_procdir_s* procdir;
	if( !parent ) {
		EFRM_ERR( "%s: Creating subdirectory %s before parent.\n",
		          __func__, dirname );
		return NULL;
	}
	
	if ( !dirname )
		return 0;
	
	mutex_lock( &efrm_pd_mutex );
	procdir = *entry_list_head;
	
	/* Does it already exist? If so, increment the refcount */
	while ( procdir ) {
		if ( procdir->efrm_pd_name
		     && !strcmp(procdir->efrm_pd_name, dirname) ) {
			procdir->efrm_pd_refcount++;
			rval = procdir;
			break;
		}
		procdir = procdir->efrm_pd_next;
	}
	
	/* Entry doesn't exist?  Create it */
	if ( !rval ) {
		rval = (struct efrm_procdir_s*) kmalloc(
				sizeof(struct efrm_procdir_s), GFP_KERNEL );

		if( rval == NULL )
			goto out;

		/* Create the directory */
		rval->efrm_pd_dir = proc_mkdir(dirname, parent);
		if( rval->efrm_pd_dir == NULL ) {
			/* Failed to create actual directory, don't leave the
			 * table hanging around */
			kfree(rval);
			rval = NULL;
			goto out;
		}

		rval->efrm_pd_refcount = 1;
		rval->efrm_pd_next = *entry_list_head;
		rval->efrm_pd_child = NULL;
		*entry_list_head = rval;
		strlcpy(rval->efrm_pd_name, dirname, EFRM_PROC_NAME_LEN);
	}

out:
	mutex_unlock( &efrm_pd_mutex );
	return (efrm_pd_handle) rval;
}


efrm_pd_handle
efrm_proc_device_dir_get(char const* device_name)
{
	return efrm_proc_dir_get(device_name, efrm_proc_nic_dir,
				 &efrm_pd_device_list);
}


efrm_pd_handle
efrm_proc_intf_dir_get(char const* intf_name)
{
	return efrm_proc_dir_get(intf_name, efrm_proc_root,
				 &efrm_pd_intf_list);
}


static int
efrm_proc_dir_put(efrm_pd_handle pd_handle, struct proc_dir_entry* parent,
		  struct efrm_procdir_s** entry_list_head)
{
	/* Release handle to directory, removes directory if not in use. */
	struct efrm_procdir_s* handle = (struct efrm_procdir_s*) pd_handle;
	struct efrm_procdir_s* procdir;
	struct efrm_procdir_s* prev = NULL;
	int rval = -EINVAL;
	
	if ( !pd_handle ) return rval;
	
	mutex_lock( &efrm_pd_mutex );
	procdir = *entry_list_head;
	
	/* Check provided procdir actually exists */
	while ( procdir ) {
		if ( procdir == handle ) {
			/* Decrement refcount, and remove if zero */
			procdir->efrm_pd_refcount--;
			if ( !procdir->efrm_pd_refcount ) {
				if ( prev ) {
					prev->efrm_pd_next =
							procdir->efrm_pd_next;
				}
				else {
					*entry_list_head =
						procdir->efrm_pd_next;
				}
				/* Delete the directory and the table entry*/
				/* TODO: Warn if it still has files in it */
				remove_proc_entry(procdir->efrm_pd_name,
						  parent);
				kfree( procdir );
			}
			rval = 0;
			break;
		} else {
			prev = procdir;
			procdir = procdir->efrm_pd_next;
		}
	}
	
	mutex_unlock( &efrm_pd_mutex );
	return rval;
}


int efrm_proc_device_dir_put(efrm_pd_handle handle)
{
	return efrm_proc_dir_put(handle, efrm_proc_nic_dir,
				 &efrm_pd_device_list);
}


int efrm_proc_intf_dir_put(efrm_pd_handle handle)
{
	return efrm_proc_dir_put(handle, efrm_proc_root, &efrm_pd_intf_list);
}


efrm_pd_handle
efrm_proc_create_file( char const* name, mode_t mode, efrm_pd_handle parent,
                       const struct proc_ops *fops, void* context )
{
	/* Tracking the files within a /proc/ directory. */
	struct proc_dir_entry* entry;
	struct efrm_procdir_s* handle = (struct efrm_procdir_s*) parent;
	struct proc_dir_entry* root;
	struct efrm_file_s* rval = NULL;
	
	mutex_lock( &efrm_pd_mutex );
	
	root = handle ? handle->efrm_pd_dir : efrm_proc_root;
	if ( !root ) {
		EFRM_WARN("%s: Creating %s before init.", __func__, name );
		goto done_create_file;
	}
	
	rval = kmalloc( sizeof(struct efrm_file_s), GFP_KERNEL );
	if ( !rval ) {
		EFRM_WARN("%s: Out of memory", __func__);
		goto done_create_file;
	}
	rval->efrm_pf_parent = handle;
	strlcpy( rval->efrm_pf_name, name, EFRM_PROC_NAME_LEN );
	rval->efrm_pf_next = handle ? handle->efrm_pd_child : NULL;
	
	entry = proc_create_data( name, mode, root, fops, context );
	if ( !entry ) {
		EFRM_WARN("%s: Unable to create procfile %s", __func__, name);
		kfree( rval );
		rval = NULL;
	}
	else {
		rval->efrm_pf_file = entry;
		if ( handle ) {
			rval->efrm_pf_next = handle->efrm_pd_child;
			handle->efrm_pd_child = rval;
		}
	}

done_create_file:
	mutex_unlock( &efrm_pd_mutex );
	return rval;
}

void
efrm_proc_remove_file( efrm_pd_handle handle )
{
	/* Tracking the files within a /proc/ directory. */
	struct efrm_file_s* entry = (struct efrm_file_s*) handle;
	struct efrm_procdir_s* parent;

	mutex_lock( &efrm_pd_mutex );

	if ( entry && entry->efrm_pf_file ) {
		remove_proc_entry( entry->efrm_pf_name,
				   entry->efrm_pf_parent ?
				   entry->efrm_pf_parent->efrm_pd_dir :
				   efrm_proc_root);
		parent = entry->efrm_pf_parent;
		if ( parent ) {
			/* remove ourselves from the list of children */
			struct efrm_file_s* prev = parent->efrm_pd_child;
			struct efrm_file_s* after = entry->efrm_pf_next;
			if ( prev == entry ) {
				parent->efrm_pd_child = entry->efrm_pf_next;
			}
			else {
				while ( prev ) {
					if ( prev->efrm_pf_next == entry ) {
						prev->efrm_pf_next = after;
						break;
					}
					prev = prev->efrm_pf_next;
				}
			}
		}
	}
	if ( entry )
		kfree( entry );
	
	mutex_unlock( &efrm_pd_mutex );
}

static int
efrm_proc_dir_check_all_removed(struct proc_dir_entry* parent,
				struct efrm_procdir_s** entry_list_head)
{
	/* Check there are no directories hanging around. */
	int rval = 1;
	struct efrm_procdir_s* procdir;
	mutex_lock( &efrm_pd_mutex );
	
	procdir = *entry_list_head;
	
	while ( procdir ) {
		/* If it's better to remove them */
		struct efrm_procdir_s* next = procdir->efrm_pd_next;
		rval = 0;

		/* Which is worse, to leak these, or to destroy them while
		   somthing is holding a handle? */
		remove_proc_entry(procdir->efrm_pd_name, parent);

		/* Delete the table entry*/
		kfree( procdir );
		procdir = next;
	}
	
	*entry_list_head = NULL;
	mutex_unlock( &efrm_pd_mutex );
	return rval;
}

/****************************************************************************
 *
 * /proc/drivers/sfc/resources
 *
 ****************************************************************************/


static const struct proc_ops efrm_resource_fops_proc;

int efrm_install_proc_entries(void)
{
	int rc = 0;
	mutex_lock( &efrm_pd_mutex );
	if ( !efrm_proc_root ) {
		/* create the top-level directory for etherfabric specific stuff */
		efrm_proc_root = proc_mkdir("driver/sfc_resource", NULL);
		if (!efrm_proc_root) {
			rc = -ENOMEM;
			goto out;
		}

		/* Create the parent directory for per-NIC stats. */
		efrm_proc_nic_dir = proc_mkdir(EFRM_PROC_DEVICES_NAME,
					       efrm_proc_root);
		if ( !efrm_proc_nic_dir ) {
			EFRM_WARN("%s: Unable to create /proc/drivers/"
				  "sfc_resources/" EFRM_PROC_DEVICES_NAME,
				  __func__);
		}

		efrm_proc_resources = proc_create("resources", 0,
						  efrm_proc_root,
						  &efrm_resource_fops_proc);
		if ( !efrm_proc_resources ) {
			EFRM_WARN("%s: Unable to create /proc/drivers/"
				  "sfc_resource/resources", __func__);
		}
	}
out:
	mutex_unlock( &efrm_pd_mutex );
	return rc;
}

int efrm_uninstall_proc_entries(void)
{
	int rc = 0;
	
	if ( ! efrm_proc_dir_check_all_removed(efrm_proc_nic_dir,
					       &efrm_pd_device_list) ||
	     ! efrm_proc_dir_check_all_removed(efrm_proc_root,
					       &efrm_pd_intf_list)) {
		return -EPERM;
	}

	mutex_lock( &efrm_pd_mutex );

	if ( !efrm_proc_root ) {
		rc = -EPERM;
		goto done_efrm_uninstall_proc_entries;
	}

	if ( efrm_proc_resources )
		remove_proc_entry("resources", efrm_proc_root);
	efrm_proc_resources = NULL;
	if ( efrm_proc_nic_dir )
		remove_proc_entry(EFRM_PROC_DEVICES_NAME, efrm_proc_root);
	efrm_proc_nic_dir = NULL;
	if ( efrm_proc_root )
		remove_proc_entry("driver/sfc_resource", NULL);
	efrm_proc_root = NULL;

done_efrm_uninstall_proc_entries:
	mutex_unlock( &efrm_pd_mutex );
	return rc;
}

/****************************************************************************
 *
 * /proc/drivers/sfc/resources
 *
 ****************************************************************************/

static int
efrm_resource_read_proc(struct seq_file *seq, void *s)
{
	int type;
	struct efrm_resource_manager *rm;

	for (type = 0; type < EFRM_RESOURCE_NUM; type++) {
		rm = efrm_rm_table[type];
		if (rm == NULL)
			continue;

		seq_printf(seq, "*** %s ***\n", rm->rm_name);

		spin_lock_bh(&rm->rm_lock);
                if( rm->rm_resources_total != -1 )
                        seq_printf(seq, "  total = %u\n", rm->rm_resources_total);
		seq_printf(seq, "current = %u\n", rm->rm_resources);
		seq_printf(seq, "    max = %u\n\n",
				 rm->rm_resources_hiwat);
		spin_unlock_bh(&rm->rm_lock);
	}

	return 0;
}
static int efrm_resource_open_proc(struct inode *inode, struct file *file)
{
	return single_open(file, efrm_resource_read_proc, PDE_DATA(inode));
}
static const struct proc_ops efrm_resource_fops_proc = {
	PROC_OPS_SET_OWNER
	.proc_open		= efrm_resource_open_proc,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release	= single_release,
};

