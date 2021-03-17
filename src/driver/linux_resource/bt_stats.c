/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains part /proc/driver/sfc_resource/ implementation:
 * buffer table statistics.
 *
 * Copyright      2013: Solarflare Communications Inc,
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
#include <ci/efrm/kernel_proc.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/driver_private.h>
#include <ci/efhw/nic.h>
#include "efrm_internal.h"
#include "efrm_pd.h"
#include <ci/driver/kernel_compat.h>


/* ************************************ */
/* buffer table proc file format        */
/* ************************************ */

static inline void
efrm_bt_proc_header(struct seq_file *seq)
{
	seq_printf(seq, "order	blocks	entries\n");
}

static inline void
efrm_bt_proc_show(struct seq_file *seq, struct efrm_bt_manager *manager)
{
	seq_printf(seq, "%d	%d	%d\n", manager->order,
		   atomic_read(&manager->btm_blocks),
		   atomic_read(&manager->btm_entries));
}

/* ************************************ */
/* /proc/driver/sfc_resource/ethX/pd:%d */
/* ************************************ */

struct efrm_pd_proc {
	efrm_pd_handle parent;
	efrm_pd_handle stats;
};

static int
efrm_read_pd_stats(struct seq_file *seq, void *s)
{
	struct efrm_pd *pd = seq->private;
	struct efrm_bt_manager *manager = NULL;

	efrm_bt_proc_header(seq);
	while ((manager = efrm_pd_bt_manager_next(pd, manager)) != NULL)
		efrm_bt_proc_show(seq, manager);
	return 0;
}
static int efrm_open_pd_stats(struct inode *inode, struct file *file)
{
	return single_open(file, efrm_read_pd_stats, PDE_DATA(inode));
}
static const struct proc_ops efrm_fops_pd_stats = {
	PROC_OPS_SET_OWNER
	.proc_open	= efrm_open_pd_stats,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

void *
efrm_pd_os_stats_ctor(struct efrm_pd *pd)
{
	struct efrm_pd_proc *ret;
	char name[EFRM_PROC_NAME_LEN];
	int owner = efrm_pd_owner_id(pd);
	struct device* dev;
	struct efhw_nic* nic;

	/* Phys mode: no buffer table */
	if (owner == OWNER_ID_PHYS_MODE)
		return NULL;

	ret = kmalloc(sizeof(*ret), GFP_KERNEL);
	if (ret == NULL)
		return NULL;

	nic = efrm_pd_to_resource(pd)->rs_client->nic;

	dev = efhw_nic_get_dev(efrm_pd_to_resource(pd)->rs_client->nic);
	if (dev == NULL)
		return NULL;

	ret->parent = efrm_proc_device_dir_get(dev_name(dev));
	put_device(dev);
	if (ret->parent == NULL)
		goto fail1;

	snprintf(name, sizeof(name), "pd%d", owner);
	ret->stats = efrm_proc_create_file(name, 0444, ret->parent,
					   &efrm_fops_pd_stats, pd);
	if (ret->stats == NULL)
		goto fail2;

	return ret;

fail2:
	efrm_proc_device_dir_put(ret->parent);
fail1:
	kfree(ret);
	return NULL;
}

void
efrm_pd_os_stats_dtor(struct efrm_pd *pd, void *os_data)
{
	struct efrm_pd_proc *data = os_data;

	if (data == NULL)
		return;

	efrm_proc_remove_file(data->stats);
	efrm_proc_device_dir_put(data->parent);
	kfree(data);
}
