/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
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
#include <ci/driver/kernel_compat.h>
#include <ci/efhw/nic.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/debug.h>


static int
efhw_iopages_map_page(struct efhw_nic *nic, struct device *dev,
		      struct efhw_iopages *p, struct page *page, int page_i,
		      size_t size)
{
	dma_addr_t addr;

	switch( efhw_nic_queue_map_type(nic) ) {
	case EFHW_PAGE_MAP_DMA:
		if( !dev ) {
			EFHW_ERR("%s: ERROR nic %d: no device for dma map",
				 __FUNCTION__, nic->index);
			return -ENODEV;
		}
		addr = dma_map_page(dev, page, 0, size, DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dev, addr)) {
			EFHW_ERR("%s: ERROR dma_map_page failed",
				 __FUNCTION__);
			return -ENOMEM;
		}
		p->dma_addrs[page_i] = addr;
		break;
	case EFHW_PAGE_MAP_PHYS:
		p->dma_addrs[page_i] = virt_to_phys(page_address(page));
		break;
	default:
		/* All known NIC types use DMA or PHYS mapping for queues */
		EFRM_ASSERT(false);
		return -ENOMEM;
	}

	return 0;
}

static void
efhw_iopages_unmap_page(struct efhw_nic *nic, struct device *dev,
			dma_addr_t addr, size_t size)
{
	if( efhw_nic_queue_map_type(nic) == EFHW_PAGE_MAP_DMA ) {
		if( !dev )
			EFHW_ERR("%s: ERROR nic %d: no device for dma ummap",
				 __FUNCTION__, nic->index);
		else
			dma_unmap_page(dev, addr, size, DMA_BIDIRECTIONAL);
	}
}


static int
efhw_iopages_alloc_phys_cont(struct efhw_nic *nic, struct device *dev,
			     struct efhw_iopages *p, unsigned order,
			     int gfp_flag)
{
	int i = 0;
	int rc;
	struct page *page;

	page = alloc_pages_node(numa_node_id(), gfp_flag, order);
	if (page == NULL)
		goto fail1;
	p->ptr = page_address(page);

	rc = efhw_iopages_map_page(nic, dev, p, page, 0, PAGE_SIZE << order);
	if( rc < 0 )
		goto fail2;

	for (i = 1; i < p->n_pages; ++i)
		p->dma_addrs[i] = p->dma_addrs[0] + (i << PAGE_SHIFT);

	return 0;

fail2:
	__free_pages(page, compound_order(page));
fail1:
	return -ENOMEM;
}

static int
efhw_iopages_alloc_kernel_cont(struct efhw_nic *nic, struct device *dev,
			       struct efhw_iopages *p, unsigned order)
{
	int i = 0;
	int rc;

	p->ptr = vmalloc_node(p->n_pages << PAGE_SHIFT, -1);
	if (p->ptr == NULL)
		goto fail1;
	for (i = 0; i < p->n_pages; ++i) {
		struct page *page;
		page = vmalloc_to_page(p->ptr + (i << PAGE_SHIFT));

		rc = efhw_iopages_map_page(nic, dev, p, page, i, PAGE_SIZE);
		if( rc < 0 )
			goto fail2;
	}

	return 0;

fail2:
	while (i-- > 0)
		efhw_iopages_unmap_page(nic, dev, p->dma_addrs[i], PAGE_SIZE);
fail1:
	return -ENOMEM;
}

int
efhw_iopages_alloc(struct efhw_nic *nic, struct efhw_iopages *p,
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
	struct pci_dev *pci_dev = efhw_nic_get_pci_dev(nic);
	struct device *dev = pci_dev ? &pci_dev->dev : NULL;
	int rc = -ENOMEM;
	int gfp_flag = __GFP_COMP | GFP_KERNEL | __GFP_ZERO;

	p->n_pages = 1 << order;
	p->dma_addrs = kmalloc(p->n_pages * sizeof(p->dma_addrs[0]), GFP_KERNEL);
	if (p->dma_addrs == NULL) {
		rc = -ENOMEM;
		goto fail1;
	}

	/* __GFP_NOWARN is necessary in case when we handle high-order page
	 * allocation failure by allocating pages one-by-one. */
	if (!phys_cont_only && order > 0)
		gfp_flag |= __GFP_NOWARN;
	rc = efhw_iopages_alloc_phys_cont(nic, dev, p, order, gfp_flag);
	if (rc) {
		if (phys_cont_only || order == 0)
			goto fail2;
	}

	/* If allocation of contiguous physical memory failed or we never tried
	 * to allocate any, then non-contiguous physical memory could be used
	 * to try to allocate it.
	 */
	if (rc < 0) {
		EFRM_ASSERT(!phys_cont_only);
		rc = efhw_iopages_alloc_kernel_cont(nic, dev, p, order);
		if (rc != 0)
			goto fail2;
	}

	return 0;

fail2:
	kfree(p->dma_addrs);
fail1:
	if (pci_dev)
		pci_dev_put(pci_dev);
	return rc;
}

void efhw_iopages_free(struct efhw_nic *nic, struct efhw_iopages *p)
{
	struct pci_dev *pci_dev = efhw_nic_get_pci_dev(nic);
	struct device *dev = pci_dev ? &pci_dev->dev : NULL;

	if (is_vmalloc_addr(p->ptr)) {
		int i;
		for (i = 0; i < p->n_pages; ++i)
			efhw_iopages_unmap_page(nic, dev, p->dma_addrs[i],
						PAGE_SIZE);
#ifdef CONFIG_SUSE_KERNEL
		/* bug 56168 */
		schedule();
#endif
		vfree(p->ptr);
	} else {
		unsigned order = __ffs64(p->n_pages);
		efhw_iopages_unmap_page(nic, dev, p->dma_addrs[0],
					PAGE_SIZE << order);

		free_pages((unsigned long)p->ptr, order);
	}
	kfree(p->dma_addrs);
	if (pci_dev)
		pci_dev_put(pci_dev);
}
