// SPDX-License-Identifier: GPL-2.0
/* Driver for Xilinx network controllers and boards
 * Copyright 2021 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/vdpa.h>
#include <linux/virtio_ids.h>
#include <linux/pci_ids.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include "ef100_iova.h"

#if defined(CONFIG_SFC_VDPA)

#define vdpa_log(vdpa_nic, fmt, ...)		\
({									\
	struct vdpa_device *vdev = &vdpa_nic->vdpa_dev;			\
	dev_info(&vdev->dev, fmt, ##__VA_ARGS__);			\
})

static void update_free_list_node(struct ef100_vdpa_iova_node *target_node,
				  struct ef100_vdpa_iova_node *next_node,
				  struct ef100_vdpa_nic *vdpa_nic)
{
	unsigned long free_area;
	bool in_list;

	free_area = next_node->iova - IOVA_NODE_END(target_node);
	in_list = !(list_empty(&target_node->free_node));

	if (!in_list && free_area >= MCDI_BUF_LEN) {
		list_add(&target_node->free_node,
			 &vdpa_nic->free_list);
#ifdef EFX_NOT_UPSTREAM
		vdpa_log(vdpa_nic,
			 "%s node_add: iova: %lx free_area: %lx\n",
			 __func__, target_node->iova, free_area);
#endif
	} else if (in_list && free_area < MCDI_BUF_LEN) {
		list_del_init(&target_node->free_node);
#ifdef EFX_NOT_UPSTREAM
		vdpa_log(vdpa_nic,
			 "%s node_del: iova: %lx free_area: %lx\n",
			 __func__, target_node->iova, free_area);
#endif
	}
}

static void update_free_list(struct ef100_vdpa_iova_node *iova_node,
			     struct ef100_vdpa_nic *vdpa_nic,
			     bool add_node)
{
	struct ef100_vdpa_iova_node *prev_in = NULL;
	struct ef100_vdpa_iova_node *next_in = NULL;
	struct rb_node *prev_node;
	struct rb_node *next_node;

	prev_node = rb_prev(&iova_node->node);
	next_node = rb_next(&iova_node->node);

	if (prev_node)
		prev_in = rb_entry(prev_node,
				   struct ef100_vdpa_iova_node, node);
	if (next_node)
		next_in = rb_entry(next_node,
				   struct ef100_vdpa_iova_node, node);

	if (add_node) {
		if (prev_in)
			update_free_list_node(prev_in, iova_node, vdpa_nic);

		if (next_in)
			update_free_list_node(iova_node, next_in, vdpa_nic);
	} else {
		if (next_in && prev_in)
			update_free_list_node(prev_in, next_in, vdpa_nic);
		if (!list_empty(&iova_node->free_node))
			list_del_init(&iova_node->free_node);
	}
}

int efx_ef100_insert_iova_node(struct ef100_vdpa_nic *vdpa_nic,
			       u64 iova, u64 size)
{
	struct ef100_vdpa_iova_node *iova_node;
	struct ef100_vdpa_iova_node *new_node;
	struct rb_node *parent;
	struct rb_node **link;
	struct rb_root *root;
	int rc = 0;

	mutex_lock(&vdpa_nic->iova_lock);

	root = &vdpa_nic->iova_root;
	link = &root->rb_node;
	parent = *link;
	/* Go to the bottom of the tree */
	while (*link) {
		parent = *link;
		iova_node = rb_entry(parent, struct ef100_vdpa_iova_node, node);

		/* handle duplicate node */
		if (iova_node->iova == iova) {
			rc = -EEXIST;
			goto out_unlock;
		}

		if (iova_node->iova > iova)
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}

	new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	new_node->iova = iova;
	new_node->size = size;
	INIT_LIST_HEAD(&new_node->free_node);

	/* Put the new node here */
#ifdef EFX_NOT_UPSTREAM
	vdpa_log(vdpa_nic,
		 "%s: Inserting node iova: %lx, size: %lx\n",
		 __func__, new_node->iova, new_node->size);
#endif
	rb_link_node(&new_node->node, parent, link);
	rb_insert_color(&new_node->node, root);

	update_free_list(new_node, vdpa_nic, true);

out_unlock:
	mutex_unlock(&vdpa_nic->iova_lock);
	return rc;
}

static struct ef100_vdpa_iova_node*
ef100_rbt_search_node(struct ef100_vdpa_nic *vdpa_nic,
		      unsigned long iova)
{
	struct ef100_vdpa_iova_node *iova_node;
	struct rb_node *rb_node;
	struct rb_root *root;

	root = &vdpa_nic->iova_root;
	if (!root)
		return NULL;

	rb_node = root->rb_node;

	while (rb_node) {
		iova_node = rb_entry(rb_node, struct ef100_vdpa_iova_node,
				     node);
		if (iova_node->iova > iova)
			rb_node = rb_node->rb_left;
		else if (iova_node->iova < iova)
			rb_node = rb_node->rb_right;
		else
			return iova_node;
	}

	return NULL;
}

void efx_ef100_remove_iova_node(struct ef100_vdpa_nic *vdpa_nic,
				unsigned long iova)
{
	struct ef100_vdpa_iova_node *iova_node;

	mutex_lock(&vdpa_nic->iova_lock);
	iova_node = ef100_rbt_search_node(vdpa_nic, iova);
	if (!iova_node)
		goto exit;

#ifdef EFX_NOT_UPSTREAM
	vdpa_log(vdpa_nic,
		 "%s: Removing node iova: %lx, size: %lx\n",
		 __func__, iova_node->iova, iova_node->size);
#endif
	update_free_list(iova_node, vdpa_nic, false);

	rb_erase(&iova_node->node, &vdpa_nic->iova_root);
	kfree(iova_node);
exit:
	mutex_unlock(&vdpa_nic->iova_lock);
}

void efx_ef100_delete_iova_tree(struct ef100_vdpa_nic *vdpa_nic)
{
	struct ef100_vdpa_iova_node *iova_node;
	struct rb_root *iova_root;
	struct rb_node *node;

	mutex_lock(&vdpa_nic->iova_lock);

	iova_root = &vdpa_nic->iova_root;
	while (!RB_EMPTY_ROOT(iova_root)) {
		node = rb_first(iova_root);
		iova_node = rb_entry(node, struct ef100_vdpa_iova_node, node);
#ifdef EFX_NOT_UPSTREAM
		vdpa_log(vdpa_nic,
			 "%s: Removing node iova: %lx, size: %lx\n",
			 __func__, iova_node->iova, iova_node->size);
#endif
		if (!list_empty(&iova_node->free_node)) {
			list_del_init(&iova_node->free_node);
#ifdef EFX_NOT_UPSTREAM
			vdpa_log(vdpa_nic,
				 "%s iova %lx removed from freelist",
				 __func__, iova_node->iova);
#endif
		}
		rb_erase(node, iova_root);
		kfree(iova_node);
	}

	mutex_unlock(&vdpa_nic->iova_lock);
}

int efx_ef100_find_new_iova(struct ef100_vdpa_nic *vdpa_nic,
			    unsigned int buf_len,
			    u64 *new_iova)
{
	struct ef100_vdpa_iova_node *iova_node;

	/* pick the first node from freelist */
	iova_node = list_first_entry_or_null(&vdpa_nic->free_list,
					     struct ef100_vdpa_iova_node,
					     free_node);
	if (!iova_node) {
		vdpa_log(vdpa_nic, "freelist is empty\n");
		return -ENOENT;
	};

#ifdef EFX_NOT_UPSTREAM
	vdpa_log(vdpa_nic, "new free node iova: %lx, size: %lx\n",
		 iova_node->iova, iova_node->size);
#endif
	*new_iova = iova_node->iova + iova_node->size;
#ifdef EFX_NOT_UPSTREAM
	vdpa_log(vdpa_nic, "Returning mcdi iova: %llx\n", *new_iova);
#endif

	return 0;
}
#endif
