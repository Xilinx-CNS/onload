/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/cpu_rmap.h>
#endif
#include "net_driver.h"
#ifdef CONFIG_SFC_TPH
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCIE_ENABLE_TPH)
#include <linux/pci-tph.h>
#endif
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_CPU_RMAP)
#include <linux/cpu_rmap.h>
#endif
#include "bitfield.h"
#include "efx.h"
#include "nic.h"
#include "ef10_regs.h"
#include "ef100_nic.h"
#include "io.h"
#include "workarounds.h"
#include "mcdi_pcol.h"

extern unsigned int efx_interrupt_mode;

/**************************************************************************
 *
 * Generic buffer handling
 * These buffers are used for interrupt status, MAC stats, etc.
 *
 **************************************************************************/

int efx_nic_alloc_buffer(struct efx_nic *efx, struct efx_buffer *buffer,
			 unsigned int len, gfp_t gfp_flags)
{
	buffer->addr = dma_alloc_coherent(&efx->pci_dev->dev, len,
					  &buffer->dma_addr, gfp_flags);
	if (!buffer->addr)
		return -ENOMEM;
	buffer->len = len;
	memset(buffer->addr, 0, len);
	return 0;
}

void efx_nic_free_buffer(struct efx_nic *efx, struct efx_buffer *buffer)
{
	if (buffer->addr) {
		dma_free_coherent(&efx->pci_dev->dev, buffer->len,
				  buffer->addr, buffer->dma_addr);
		buffer->addr = NULL;
	}
}

/* Check whether an event is present in the eventq at the current
 * read pointer.  Only useful for self-test.
 */
bool efx_nic_event_present(struct efx_channel *channel)
{
	return efx_event_present(efx_event(channel, channel->eventq_read_ptr));
}

void efx_nic_event_test_start(struct efx_channel *channel)
{
	if (!channel->efx->type->ev_test_generate)
		return;

	channel->event_test_cpu = -1;
	smp_wmb();
	channel->efx->type->ev_test_generate(channel);
}

int efx_nic_irq_test_start(struct efx_nic *efx)
{
	if (!efx->type->irq_test_generate)
		return -EOPNOTSUPP;

	efx->last_irq_cpu = -1;
	smp_wmb();
	return efx->type->irq_test_generate(efx);
}

/* Hook interrupt handler(s)
 * Try MSI and then legacy interrupts.
 */
int efx_nic_init_interrupt(struct efx_nic *efx)
{
	struct efx_probe_data *pd = efx_nic_to_probe_data(efx);
	struct cpu_rmap *cpu_rmap __maybe_unused = NULL;
	struct efx_msi_context *msi_context;
	struct efx_channel *channel;
	unsigned int n_irqs;
	int rc;

#ifdef CONFIG_SFC_TPH
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCIE_ENABLE_TPH)
	rc = pcie_enable_tph(efx->pci_dev, PCI_TPH_ST_DS_MODE);
	if (rc)
		netif_dbg(efx, drv, efx->net_dev,
			  "failed enabling TPH support\n");
#endif
#endif

#ifdef CONFIG_RFS_ACCEL
	if (efx->interrupt_mode == EFX_INT_MODE_MSIX) {
		cpu_rmap = alloc_irq_cpu_rmap(efx_channels(efx));
		if (!cpu_rmap) {
			rc = -ENOMEM;
			goto fail1;
		}
	}
#endif

	/* Hook MSI or MSI-X interrupt */
	n_irqs = 0;
	efx_for_each_channel(channel, efx) {
		if (!channel->irq || channel->irq_index < 0)
			continue;

		msi_context = xa_load(&pd->irq_pool, channel->irq_index);
		if (!msi_context)
			continue;

		msi_context->efx = efx;
		msi_context->channel = channel->channel;
		rc = request_irq(channel->irq, efx->type->irq_handle_msi, 0,
				 msi_context->name, msi_context);
		if (rc) {
			netif_err(efx, drv, efx->net_dev,
				  "failed to hook IRQ %d\n", channel->irq);
			goto fail2;
		}
		++n_irqs;

#ifdef CONFIG_RFS_ACCEL
		if (efx->interrupt_mode == EFX_INT_MODE_MSIX &&
		    channel->channel < efx_rx_channels(efx)) {
			rc = irq_cpu_rmap_add(cpu_rmap, channel->irq);
			if (rc)
				goto fail2;
		}
#endif
	}

#ifdef CONFIG_RFS_ACCEL
	efx->net_dev->rx_cpu_rmap = cpu_rmap;
#endif
	efx->irqs_hooked = true;
	return 0;

 fail2:
#ifdef CONFIG_RFS_ACCEL
	free_irq_cpu_rmap(cpu_rmap);
#endif
	efx_for_each_channel(channel, efx) {
		if (!channel->irq || channel->irq_index < 0)
			continue;
		if (n_irqs-- == 0)
			break;
		msi_context = xa_load(&pd->irq_pool, channel->irq_index);
		if (!msi_context)
			continue;
		msi_context->efx = NULL;
		free_irq(channel->irq, msi_context);
	}
#ifdef CONFIG_RFS_ACCEL
 fail1:
#endif
	return rc;
}

void efx_nic_fini_interrupt(struct efx_nic *efx)
{
	struct efx_probe_data *pd = efx_nic_to_probe_data(efx);
	struct efx_msi_context *msi_context;
	struct efx_channel *channel;

#ifdef CONFIG_RFS_ACCEL
	if (efx->net_dev->rx_cpu_rmap)
		free_irq_cpu_rmap(efx->net_dev->rx_cpu_rmap);
	efx->net_dev->rx_cpu_rmap = NULL;
#endif

	if (efx->irqs_hooked)
		/* Disable MSI/MSI-X interrupts */
		efx_for_each_channel(channel, efx) {
			if (!channel->irq || channel->irq_index < 0)
				continue;

			msi_context = xa_load(&pd->irq_pool,
					      channel->irq_index);
			if (!msi_context)
				continue;
			msi_context->efx = NULL;
			msi_context->channel = 0;
			free_irq(channel->irq, msi_context);
		}
	efx->irqs_hooked = false;

#ifdef CONFIG_SFC_TPH
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCIE_ENABLE_TPH)
	pcie_disable_tph(efx->pci_dev);
#endif
#endif
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_PCI_ALLOC_DYN)
static int efx_alloc_irq_vectors(struct efx_probe_data *pd, unsigned int n_irqs)
{
	struct msix_entry *xentries;
	unsigned int i;
	int rc;

	xentries = kmalloc_array(n_irqs, sizeof(*xentries), GFP_KERNEL);
	if (!xentries)
		return -ENOMEM;
	for (i = 0; i < n_irqs; i++)
		xentries[i].entry = i;
	rc = pci_enable_msix_range(pd->pci_dev, xentries, 1, n_irqs);
	if (rc <= 0)
		kfree(xentries);
	else
		pd->xentries = xentries;
	return rc;
}
#endif

void efx_nic_fini_irq_pool(struct efx_probe_data *pd)
{
	unsigned long index;
	bool warned = false;
	void *entry;

	xa_lock(&pd->irq_pool);

	pd->max_irqs = 0;
	pd->irqs_left = 0;
	xa_for_each(&pd->irq_pool, index, entry) {
		if (!entry)
			continue;
		if (!warned)
			pci_err(pd->pci_dev,
				"Interrupt at index %u freed late\n",
				(unsigned int)index);
		warned = true;
		kfree(entry);
		__xa_erase(&pd->irq_pool, index);
	}
	xa_unlock(&pd->irq_pool);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_ALLOC_DYN)
	pci_free_irq_vectors(pd->pci_dev);
#else
	kfree(pd->xentries);
	pd->xentries = NULL;
	pci_disable_msix(pd->pci_dev);
#endif
}

int efx_nic_init_irq_pool(struct efx_probe_data *pd)
{
	struct efx_nic *efx = &pd->efx;
	unsigned int n_irqs;
	int rc;

	if (WARN_ON(efx->type->supported_interrupt_modes == 0)) {
		pci_err(pd->pci_dev, "no interrupt modes supported\n");
		return -EOPNOTSUPP;
	}
	pd->max_irqs = 1;	/* For MSI mode */
	if (BIT(efx_interrupt_mode) & efx->type->supported_interrupt_modes)
		efx->interrupt_mode = efx_interrupt_mode;
	else
		efx->interrupt_mode = ffs(efx->type->supported_interrupt_modes) - 1;

	if (efx_interrupt_mode == EFX_INT_MODE_MSI ||
	    !(efx->type->supported_interrupt_modes & BIT(EFX_INT_MODE_MSIX))) {
		rc = pci_alloc_irq_vectors(pd->pci_dev, 1, 1, PCI_IRQ_MSI);
		if (rc)
			pci_err(pd->pci_dev, "Error %d allocating an MSI vector\n",
				rc);
		return rc;
	}
	/* MSI-X mode */
	rc = pci_msix_vec_count(pd->pci_dev);
	if (rc <= 0)
		rc = efx_wanted_parallelism(efx);

	/* Determine how many interrupts we need */
	n_irqs = min_t(u16, rc, efx->max_channels);
	pci_dbg(pd->pci_dev, "Allocating %u interrupts\n", n_irqs);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_ALLOC_DYN)
	rc = pci_alloc_irq_vectors(pd->pci_dev, 1, n_irqs, PCI_IRQ_MSIX);
#else
	rc = efx_alloc_irq_vectors(pd, n_irqs);
#endif
	if (rc <= 0) {
		pci_err(pd->pci_dev, "could not enable interrupts (%d)\n", rc);
		pd->max_irqs = 0;
	} else {
		pd->max_irqs = rc;
		rc = 0;
	}
	pd->irqs_left = pd->max_irqs;
	return rc;
}

struct efx_msi_context *efx_nic_alloc_irq(struct efx_probe_data *pd,
					  int *os_vector)
{
	struct efx_msi_context *msi_context;
	struct xa_limit irq_limit;
	int rc, irq;

	msi_context = kzalloc(sizeof(*msi_context), GFP_KERNEL);
	if (!msi_context)
		return ERR_PTR(-ENOMEM);

	xa_lock(&pd->irq_pool);

	if (!pd->irqs_left) {
		rc = -ENOSPC;
		goto out_free;
	}

	irq_limit.min = 0;
	irq_limit.max = pd->max_irqs;

	/* Find a free slot for the interrupt */
	rc = __xa_alloc(&pd->irq_pool, &msi_context->index, msi_context,
			irq_limit, GFP_KERNEL);
	if (rc == -EBUSY)
		rc = -ENOSPC;
	if (rc)
		goto out_free;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_ALLOC_DYN)
	irq = pci_irq_vector(pd->pci_dev, msi_context->index);
#else
	irq = pd->xentries[msi_context->index].vector;
#endif
	pd->irqs_left--;
	xa_unlock(&pd->irq_pool);
	*os_vector = irq;
	return msi_context;

out_free:
	kfree(msi_context);
	xa_unlock(&pd->irq_pool);
	return ERR_PTR(rc);
}

void efx_nic_free_irq(struct efx_probe_data *pd, int irq_index)
{
	struct efx_msi_context *msi_context;

	xa_lock(&pd->irq_pool);

	if (irq_index < 0 || irq_index >= pd->max_irqs)
		goto out_unlock;

	msi_context = __xa_erase(&pd->irq_pool, irq_index);
	EFX_WARN_ON_ONCE_PARANOID(!msi_context);
	kfree(msi_context);
	pd->irqs_left++;

out_unlock:
	xa_unlock(&pd->irq_pool);
}

#ifdef EFX_NOT_UPSTREAM
static unsigned int
efx_device_check_pcie_link(struct pci_dev *pdev, unsigned int *actual_width,
			   unsigned int *max_width, unsigned int *actual_speed,
			   unsigned int *nic_bandwidth)
{
	int cap = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	unsigned int nic_speed;
	u16 lnksta;
	u16 lnkcap;

	*actual_speed = 0;
	*actual_width = 0;
	*max_width = 0;
	*nic_bandwidth = 0;

	if (!cap ||
	    pci_read_config_word(pdev, cap + PCI_EXP_LNKSTA, &lnksta) ||
	    pci_read_config_word(pdev, cap + PCI_EXP_LNKCAP, &lnkcap))
		return 0;

	*actual_width = (lnksta & PCI_EXP_LNKSTA_NLW) >>
			__ffs(PCI_EXP_LNKSTA_NLW);

	*max_width = (lnkcap & PCI_EXP_LNKCAP_MLW) >> __ffs(PCI_EXP_LNKCAP_MLW);
	*actual_speed = (lnksta & PCI_EXP_LNKSTA_CLS);

	nic_speed = 1;
	if (lnkcap & PCI_EXP_LNKCAP_SLS_5_0GB)
		nic_speed = 2;
	/* PCIe Gen3 capabilities are in a different config word. */
	if (!pci_read_config_word(pdev, cap + PCI_EXP_LNKCAP2, &lnkcap)) {
		if (lnkcap & PCI_EXP_LNKCAP2_SLS_8_0GB)
			nic_speed = 3;
	}

	*nic_bandwidth = *max_width << (nic_speed - 1);

	return nic_speed;
}

/* Return the embedded PCI bridge device if it exists. If the PCI device has
 * been assigned to a virtual machine, the bridge will not be found so the
 * pcie link check is done with the NIC PCI device.
 */
static struct pci_dev *efx_get_bridge_device(struct pci_dev *nic)
{
	struct pci_dev *pdev = NULL;
	struct pci_dev *p = NULL;

	/* Find PCI device bridging the NIC PCI bus.
	 * First the bridge downstream port device.
	 */
	for_each_pci_dev(p) {
		if (p->subordinate == nic->bus) {
			/* Is this the EF100 embedded bridge downstream
			 * port?
			 */
			if ((p->vendor != PCI_VENDOR_ID_XILINX) ||
			    (p->device != EF100_BRIDGE_DOWNSTREAM_PCI_DEVICE))
				return nic;
			/* We got the downstream port. */
			pdev = p;
		}
	}

	/* This should never happen. */
	if (!pdev)
		return nic;

	/* We got the embedded bridge downstream port. Let's get the upstream
	 * port now which is the physical PCI link to the Host.
	 */
	p = NULL;
	for_each_pci_dev(p) {
		if (p->subordinate == pdev->bus) {
			if ((p->vendor != PCI_VENDOR_ID_XILINX) ||
			    (p->device != EF100_BRIDGE_UPSTREAM_PCI_DEVICE)) {
				WARN_ON(1);
				return nic;
			}
			/* We got the upstream port. This is the device we are
			 * interested in.
			 */
			return p;
		}
	}
	return nic;
}

void
efx_nic_check_pcie_link(struct efx_nic *efx, unsigned int desired_bandwidth,
			unsigned int *actual_width, unsigned int *actual_speed)
{
	struct pci_dev *pdev = efx->pci_dev;
	unsigned int nic_bandwidth;
	unsigned int bandwidth;
	unsigned int nic_width;
	unsigned int nic_speed;
	unsigned int width;
	unsigned int speed;

	if (efx_nic_rev(efx) == EFX_REV_EF100)
		pdev = efx_get_bridge_device(efx->pci_dev);

	nic_speed = efx_device_check_pcie_link(pdev, &width, &nic_width, &speed,
					       &nic_bandwidth);

	if(!nic_speed)
		goto out;

	if (width > nic_width)
		netif_dbg(efx, drv, efx->net_dev,
			  "PCI Express width is %d, with maximum expected %d. "
			  "If running on a virtualized platform this is fine, "
			  "otherwise it indicates a PCI problem.\n",
			  width, nic_width);

	bandwidth = width << (speed - 1);

	if (desired_bandwidth > nic_bandwidth)
		/* You can desire all you want, it ain't gonna happen. */
		desired_bandwidth = nic_bandwidth;

	if (desired_bandwidth && (bandwidth < desired_bandwidth))
		netif_warn(efx, drv, efx->net_dev,
			   "This Solarflare Network Adapter requires the "
			   "equivalent of %d lanes at PCI Express %d speed for "
			   "full throughput, but is currently limited to %d "
			   "lanes at PCI Express %d speed.  Consult your "
			   "motherboard documentation to find a more "
			   "suitable slot\n",
			   desired_bandwidth > EFX_BW_PCIE_GEN3_X8 ? 16 : 8,
			   nic_speed, width, speed);
	else if (bandwidth < nic_bandwidth)
		netif_warn(efx, drv, efx->net_dev,
			   "This Solarflare Network Adapter requires a "
			   "slot with %d lanes at PCI Express %d speed for "
			   "optimal latency, but is currently limited to "
			   "%d lanes at PCI Express %d speed\n",
			   nic_width, nic_speed, width, speed);

out:
	if (actual_width)
		*actual_width = width;

	if (actual_speed)
		*actual_speed = speed;
}
#endif

/* Register dump */

#define REGISTER_REVISION_ED	4
#define REGISTER_REVISION_EZ	4	/* latest EF10 revision */

struct efx_nic_reg {
	u32 offset:24;
	u32 min_revision:3, max_revision:3;
};

#define REGISTER(name, arch, min_rev, max_rev) {			\
	arch ## R_ ## min_rev ## max_rev ## _ ## name,			\
	REGISTER_REVISION_ ## arch ## min_rev,				\
	REGISTER_REVISION_ ## arch ## max_rev				\
}
#define REGISTER_DZ(name) REGISTER(name, E, D, Z)

static const struct efx_nic_reg efx_nic_regs[] = {
	REGISTER_DZ(BIU_HW_REV_ID),
	REGISTER_DZ(MC_DB_LWRD),
	REGISTER_DZ(MC_DB_HWRD),
};

struct efx_nic_reg_table {
	u32 offset:24;
	u32 min_revision:3, max_revision:3;
	u32 step:6, rows:21;
};

#define REGISTER_TABLE_DIMENSIONS(_, offset, arch, min_rev, max_rev, step, rows) { \
	offset,								\
	REGISTER_REVISION_ ## arch ## min_rev,				\
	REGISTER_REVISION_ ## arch ## max_rev,				\
	step, rows							\
}
#define REGISTER_TABLE(name, arch, min_rev, max_rev)			\
	REGISTER_TABLE_DIMENSIONS(					\
		name, arch ## R_ ## min_rev ## max_rev ## _ ## name,	\
		arch, min_rev, max_rev,					\
		arch ## R_ ## min_rev ## max_rev ## _ ## name ## _STEP,	\
		arch ## R_ ## min_rev ## max_rev ## _ ## name ## _ROWS)
#define REGISTER_TABLE_DZ(name) REGISTER_TABLE(name, E, D, Z)

static const struct efx_nic_reg_table efx_nic_reg_tables[] = {
	REGISTER_TABLE_DZ(BIU_MC_SFT_STATUS),
};

size_t efx_nic_get_regs_len(struct efx_nic *efx)
{
	const struct efx_nic_reg *reg;
	const struct efx_nic_reg_table *table;
	size_t len = 0;

	for (reg = efx_nic_regs;
	     reg < efx_nic_regs + ARRAY_SIZE(efx_nic_regs);
	     reg++)
		if (efx->type->revision >= reg->min_revision &&
		    efx->type->revision <= reg->max_revision)
			len += sizeof(efx_oword_t);

	for (table = efx_nic_reg_tables;
	     table < efx_nic_reg_tables + ARRAY_SIZE(efx_nic_reg_tables);
	     table++)
		if (efx->type->revision >= table->min_revision &&
		    efx->type->revision <= table->max_revision)
			len += table->rows * min_t(size_t, table->step, 16);

	return len;
}

void efx_nic_get_regs(struct efx_nic *efx, void *buf)
{
	const struct efx_nic_reg *reg;
	const struct efx_nic_reg_table *table;

	for (reg = efx_nic_regs;
	     reg < efx_nic_regs + ARRAY_SIZE(efx_nic_regs);
	     reg++) {
		if (efx->type->revision >= reg->min_revision &&
		    efx->type->revision <= reg->max_revision) {
			efx_reado(efx, (efx_oword_t *)buf, reg->offset);
			buf += sizeof(efx_oword_t);
		}
	}

	for (table = efx_nic_reg_tables;
	     table < efx_nic_reg_tables + ARRAY_SIZE(efx_nic_reg_tables);
	     table++) {
		size_t size, i;

		if (!(efx->type->revision >= table->min_revision &&
		      efx->type->revision <= table->max_revision))
			continue;

		size = min_t(size_t, table->step, 16);

		for (i = 0; i < table->rows; i++) {
			switch (table->step) {
			case 4: /* 32-bit SRAM */
				efx_readd(efx, buf, table->offset + 4 * i);
				break;
			case 16: /* 128-bit-readable register */
				efx_reado_table(efx, buf, table->offset, i);
				break;
			case 32: /* 128-bit register, interleaved */
				efx_reado_table(efx, buf, table->offset, 2 * i);
				break;
			default:
				WARN_ON(1);
				return;
			}
			buf += size;
		}
	}
}

/**
 * efx_nic_describe_stats - Describe supported statistics for ethtool
 * @desc: Array of &struct efx_hw_stat_desc describing the statistics
 * @count: Length of the @desc array
 * @mask: Bitmask of which elements of @desc are enabled
 * @names: Buffer to copy names to, or %NULL.  The names are copied
 *	starting at intervals of %ETH_GSTRING_LEN bytes.
 *
 * Return: the number of visible statistics, i.e. the number of set
 * bits in the first @count bits of @mask for which a name is defined.
 */
size_t efx_nic_describe_stats(const struct efx_hw_stat_desc *desc, size_t count,
			      const unsigned long *mask, u8 *names)
{
	size_t visible = 0;
	size_t index;

	for_each_set_bit(index, mask, count) {
		if (desc[index].name) {
			if (names) {
				strscpy(names, desc[index].name,
					ETH_GSTRING_LEN);
				names += ETH_GSTRING_LEN;
			}
			++visible;
		}
	}

	return visible;
}

/**
 * efx_nic_copy_stats - Copy stats from the DMA buffer
 * @efx: The associated NIC.
 * @dest: Destination buffer. Must be the same size as the DMA buffer.
 *
 * Copy stats from the DMA buffer in to an intermediate buffer. This is
 * used to get a consistent set of stats while the DMA buffer can be
 * written at any time by the NIC.
 *
 * Return: a negative error code or 0 on success.
 */
int efx_nic_copy_stats(struct efx_nic *efx, __le64 *dest)
{
	int retry;
	__le64 generation_start, generation_end;
	__le64 *dma_stats = efx->stats_buffer.addr;
	int rc = 0;

	if (!dest)
		return 0;

	if (!dma_stats)
		goto return_zeroes;

	for (retry = 0; retry < 100; ++retry) {
		generation_end = dma_stats[efx->num_mac_stats - 1];
		if (generation_end == EFX_MC_STATS_GENERATION_INVALID)
			goto return_zeroes;
		rmb();
		memcpy(dest, dma_stats, efx->num_mac_stats * sizeof(__le64));
		rmb();
		generation_start = dma_stats[MC_CMD_MAC_GENERATION_START];
		if (generation_end == generation_start)
			return 0; /* return good data */
		udelay(100);
	}

	rc = -EIO;

return_zeroes:
	memset(dest, 0, efx->num_mac_stats * sizeof(u64));
	return rc;
}

/**
 * efx_nic_update_stats - Convert statistics DMA buffer to array of u64
 * @desc: Array of &struct efx_hw_stat_desc describing the DMA buffer
 *	layout.  DMA widths of 0, 16, 32 and 64 are supported; where
 *	the width is specified as 0 the corresponding element of
 *	@stats is not updated.
 * @count: Length of the @desc array
 * @mask: Bitmask of which elements of @desc are enabled
 * @stats: Buffer to update with the converted statistics.  The length
 *	of this array must be at least @count.
 * @mc_initial_stats: Copy of DMA buffer containing initial stats. Subtracted
 *	from the stats in mc_stats.
 * @mc_stats: DMA buffer containing hardware statistics
 */
void efx_nic_update_stats(const struct efx_hw_stat_desc *desc, size_t count,
			  const unsigned long *mask, u64 *stats,
			  const void *mc_initial_stats, const void *mc_stats)
{
	size_t index;
	__le64 zero = 0;

	for_each_set_bit(index, mask, count) {
		if (desc[index].dma_width) {
			const void *addr =
				mc_stats ?
				mc_stats + desc[index].offset :
				&zero;
			const void *init =
				mc_initial_stats && mc_stats ?
				mc_initial_stats + desc[index].offset :
				&zero;

			switch (desc[index].dma_width) {
			case 16:
				stats[index] = le16_to_cpup((__le16 *)addr) -
					       le16_to_cpup((__le16 *)init);
				break;
			case 32:
				stats[index] = le32_to_cpup((__le32 *)addr) -
					       le32_to_cpup((__le32 *)init);
				break;
			case 64:
				stats[index] = le64_to_cpup((__le64 *)addr) -
					       le64_to_cpup((__le64 *)init);
				break;
			default:
				WARN_ON_ONCE(1);
				stats[index] = 0;
				break;
			}
		}
	}
}

void efx_nic_fix_nodesc_drop_stat(struct efx_nic *efx, u64 *rx_nodesc_drops)
{
	/* if down, or this is the first update after coming up */
	if (!(efx->net_dev->flags & IFF_UP) || !efx->rx_nodesc_drops_prev_state)
		efx->rx_nodesc_drops_while_down +=
			*rx_nodesc_drops - efx->rx_nodesc_drops_total;
	efx->rx_nodesc_drops_total = *rx_nodesc_drops;
	efx->rx_nodesc_drops_prev_state = !!(efx->net_dev->flags & IFF_UP);
	*rx_nodesc_drops -= efx->rx_nodesc_drops_while_down;
}
