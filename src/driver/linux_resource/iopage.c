/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides Linux-specific implementation for iopage API used
 * from efhw library.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
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

#include <ci/driver/resource/linux_efhw_nic.h>
#include "kernel_compat.h"
#include <ci/efhw/common_sysdep.h> /* for dma_addr_t */
#include <ci/efrm/debug.h>



static int
efhw_iopages_alloc_phys_cont(struct device *dev, struct efhw_iopages *p,
			     unsigned order, int gfp_flag)
{
	int i = 0;
	dma_addr_t base_dma_addr;
	struct page *page;

	page = alloc_pages_node(numa_node_id(), gfp_flag, order);
	if (page == NULL)
		goto fail1;

	p->ptr = page_address(page);
	base_dma_addr = dma_map_page(dev, page, 0, PAGE_SIZE << order,
				     DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, base_dma_addr)) {
		EFHW_ERR("%s: ERROR dma_map_page failed",
			 __FUNCTION__);
		goto fail2;
	}
	for (i = 0; i < p->n_pages; ++i)
		p->dma_addrs[i] = base_dma_addr + (i << PAGE_SHIFT);

	p->phys_cont = 1;
	return 0;

fail2:
	__free_pages(page, compound_order(page));
fail1:
	return -ENOMEM;
}

static int
efhw_iopages_alloc_kernel_cont(struct device *dev, struct efhw_iopages *p,
			       unsigned order)
{
	int i = 0;

	p->ptr = vmalloc_node(p->n_pages << PAGE_SHIFT, -1);
	if (p->ptr == NULL)
		goto fail1;
	for (i = 0; i < p->n_pages; ++i) {
		struct page *page;
		page = vmalloc_to_page(p->ptr + (i << PAGE_SHIFT));

		if( dev ) {
			p->dma_addrs[i] = dma_map_page(dev, page, 0, PAGE_SIZE,
						       DMA_BIDIRECTIONAL);

			if (dma_mapping_error(dev, p->dma_addrs[i])) {
				EFHW_ERR("%s: ERROR dma_map_page failed",
					 __FUNCTION__);
				goto fail2;
			}
		}
		else {
			p->dma_addrs[i] = page_to_phys(page);
		}
	}

	p->phys_cont = 0;
	return 0;

fail2:
	while (i-- > 0) {
		dma_unmap_page(dev, p->dma_addrs[i],
			       PAGE_SIZE, DMA_BIDIRECTIONAL);
	}
fail1:
	return -ENOMEM;
}

int
efhw_iopages_alloc(struct pci_dev *pci_dev, struct efhw_iopages *p,
		   unsigned order, int phys_cont_only,
		   unsigned long iova_base)
{
	/* dma_alloc_coherent() is really the right interface to use here.
	 * However, it allocates memory "close" to the device, but we want
	 * memory on the current numa node.  Also we need the memory to be
	 * contiguous in the kernel, but not necessarily in physical
	 * memory.
	 * But we try to allocate contiguous physical memory first.
	 */
	struct device *dev = pci_dev ? &pci_dev->dev : NULL;
	int rc = 0;
	int gfp_flag = __GFP_COMP;

	p->n_pages = 1 << order;
	p->dma_addrs = kmalloc(p->n_pages * sizeof(p->dma_addrs[0]), 0);
	if (p->dma_addrs == NULL) {
		rc = -ENOMEM;
		goto fail1;
	}

	/* __GFP_NOWARN is necessary in case when we handle high-order page
	 * allocation failure by allocating pages one-by-one. */
	if( dev ) {
		if (!phys_cont_only && order > 0)
			gfp_flag |= __GFP_NOWARN;
		rc = efhw_iopages_alloc_phys_cont(dev, p, order, gfp_flag);
		if (rc == 0)
			return 0;
		else if (rc != 0 && (phys_cont_only || order == 0))
			goto fail2;
	}
	/* If allocation of contiguous physical memory is failed and
	 * non-contiguous physical memory could be used then try to allocate it.
	 */
	rc = efhw_iopages_alloc_kernel_cont(dev, p, order);
	if (rc != 0)
		goto fail2;

	return 0;

fail2:
	kfree(p->dma_addrs);
fail1:
	return rc;
}

void efhw_iopages_free(struct pci_dev *pci_dev, struct efhw_iopages *p)
{
	if( pci_dev == NULL) {
		vfree(p->ptr);
	}
	else if (p->phys_cont) {
		struct device *dev = &pci_dev->dev;
		unsigned order = __ffs64(p->n_pages);
		dma_unmap_page(dev, p->dma_addrs[0], PAGE_SIZE << order,
			DMA_BIDIRECTIONAL);

		free_pages((unsigned long)p->ptr, order);
	} else {
		struct device *dev = &pci_dev->dev;
		int i;
		for (i = 0; i < p->n_pages; ++i)
			dma_unmap_page(dev, p->dma_addrs[i],
				PAGE_SIZE, DMA_BIDIRECTIONAL);
#ifdef CONFIG_SUSE_KERNEL
		/* bug 56168 */
		schedule();
#endif
		vfree(p->ptr);
	}
	kfree(p->dma_addrs);
}
