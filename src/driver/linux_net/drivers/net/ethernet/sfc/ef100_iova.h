/* SPDX-License-Identifier: GPL-2.0 */
/* Driver for Xilinx network controllers and boards
 * Copyright 2021 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#ifndef EFX_EF100_IOVA_H
#define EFX_EF100_IOVA_H

#include "ef100_nic.h"
#include "ef100_vdpa.h"

#if defined(CONFIG_SFC_VDPA)
/* struct ef100_vdpa_iova_node - guest buffer iova entry
 * @node: red black tree node
 * @iova: mapping's IO virtual address
 * @size: length of mapped region in bytes
 * @free_node: free list node
 */
struct ef100_vdpa_iova_node {
	struct rb_node node;
	unsigned long iova;
	size_t size;
	struct list_head free_node;
};

#define IOVA_NODE_END(node) (node->iova + node->size)

int efx_ef100_insert_iova_node(struct ef100_vdpa_nic *vdpa_nic,
			       u64 iova, u64 size);
void efx_ef100_remove_iova_node(struct ef100_vdpa_nic *vdpa_nic,
				unsigned long iova);
void efx_ef100_delete_iova_tree(struct ef100_vdpa_nic *vdpa_nic);

int efx_ef100_find_new_iova(struct ef100_vdpa_nic *vdpa_nic,
			    unsigned int buf_len,
			    u64 *new_iova);
#endif  /* CONFIG_SFC_VDPA */
#endif	/* EFX_EF100_IOVA_H */
