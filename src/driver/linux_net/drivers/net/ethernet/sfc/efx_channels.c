/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include <linux/module.h>
#ifndef EFX_USE_KCOMPAT
#include <xen/xen.h>
#endif
#include "efx_channels.h"
#include "efx.h"
#include "efx_common.h"
#include "rx_common.h"
#include "tx_common.h"
#include "nic.h"
#include "sriov.h"
#include "mcdi_functions.h"
#include "mcdi_filters.h"
#include "debugfs.h"

/* Interrupt mode names (see INT_MODE())) */
const unsigned int efx_interrupt_mode_max = EFX_INT_MODE_MAX;
const char *const efx_interrupt_mode_names[] = {
	[EFX_INT_MODE_MSIX]   = "MSI-X",
	[EFX_INT_MODE_MSI]    = "MSI",
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
	[EFX_INT_MODE_POLLED] = "busy-poll",
#endif
};

#if !defined(EFX_USE_KCOMPAT) || (defined(topology_core_cpumask))
#define HAVE_EFX_NUM_PACKAGES
#endif
#if !defined(EFX_USE_KCOMPAT) || (defined(topology_sibling_cpumask) && defined(EFX_HAVE_EXPORTED_CPU_SIBLING_MAP))
#define HAVE_EFX_NUM_CORES
#endif

/* This is the requested number of CPUs to use for Receive-Side Scaling
 * (RSS), i.e. the number of CPUs among which we may distribute
 * simultaneous interrupt handling.  Or alternatively it may be set to
 * "packages", "cores", "hyperthreads", "numa_local_cores" or
 * "numa_local_hyperthreads" to get one receive channel per package, core,
 * hyperthread, numa local core or numa local hyperthread.  The default
 * is "cores".
 *
 * Systems without MSI-X will only target one CPU via legacy or MSI
 * interrupt.
 */
static char *rss_cpus;
module_param(rss_cpus, charp, 0444);
MODULE_PARM_DESC(rss_cpus, "Number of CPUs to use for Receive-Side Scaling, or 'packages', 'cores', 'hyperthreads', 'numa_local_cores' or 'numa_local_hyperthreads'");

#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)) && defined(HAVE_EFX_NUM_PACKAGES)
static bool rss_numa_local = true;
module_param(rss_numa_local, bool, 0444);
MODULE_PARM_DESC(rss_numa_local, "Restrict RSS to CPUs on the local NUMA node");
#endif

/*
 * Use separate channels for TX and RX events
 *
 * Set this to 1 to use separate channels for TX and RX. It allows us
 * to control interrupt affinity separately for TX and RX.
 *
 * This is only used by sfc.ko in MSI-X interrupt mode
 */
bool separate_tx_channels;

/* This is the first interrupt mode to try out of:
 * 0 => MSI-X
 * 1 => MSI
 */
unsigned int interrupt_mode;

static unsigned int irq_adapt_low_thresh = 8000;
module_param(irq_adapt_low_thresh, uint, 0644);
MODULE_PARM_DESC(irq_adapt_low_thresh,
		 "Threshold score for reducing IRQ moderation");

static unsigned int irq_adapt_high_thresh = 16000;
module_param(irq_adapt_high_thresh, uint, 0644);
MODULE_PARM_DESC(irq_adapt_high_thresh,
		 "Threshold score for increasing IRQ moderation");

static unsigned int irq_adapt_irqs = 1000;
module_param(irq_adapt_irqs, uint, 0644);
MODULE_PARM_DESC(irq_adapt_irqs,
		 "Number of IRQs per IRQ moderation adaptation");

/* This is the weight assigned to each of the (per-channel) virtual
 * NAPI devices.
 */
static int napi_weight = 64;
#ifdef EFX_NOT_UPSTREAM
module_param(napi_weight, int, 0444);
MODULE_PARM_DESC(napi_weight, "NAPI weighting");
#endif

static const struct efx_channel_type efx_default_channel_type;
static void efx_remove_channel(struct efx_channel *channel);
#ifdef EFX_NOT_UPSTREAM
static void efx_schedule_all_channels(struct work_struct *data);
#endif
static int efx_soft_enable_interrupts(struct efx_nic *efx);
static void efx_soft_disable_interrupts(struct efx_nic *efx);
static int efx_init_napi_channel(struct efx_channel *channel);
static void efx_fini_napi_channel(struct efx_channel *channel);

/*************
 * INTERRUPTS
 *************/

#ifdef HAVE_EFX_NUM_CORES
/* Count the number of unique cores in the given cpumask */
static unsigned int efx_num_cores(const cpumask_t *in)
{
	cpumask_var_t core_mask;
	unsigned int count;
	int cpu;

	if (unlikely(!zalloc_cpumask_var(&core_mask, GFP_KERNEL))) {
		printk(KERN_WARNING
		       "sfc: RSS disabled due to allocation failure\n");
		return 1;
	}

	count = 0;
	for_each_cpu(cpu, in) {
		if (!cpumask_test_cpu(cpu, core_mask)) {
			++count;
			cpumask_or(core_mask, core_mask,
				   topology_sibling_cpumask(cpu));
		}
	}

	free_cpumask_var(core_mask);
	return count;
}
#endif

#ifdef HAVE_EFX_NUM_PACKAGES
/* Count the number of unique packages in the given cpumask */
static unsigned int efx_num_packages(const cpumask_t *in)
{
	cpumask_var_t core_mask;
	unsigned int count;
	int cpu, cpu2;

	if (unlikely(!zalloc_cpumask_var(&core_mask, GFP_KERNEL))) {
		printk(KERN_WARNING
		       "sfc: RSS disabled due to allocation failure\n");
		return 1;
	}

	count = 0;
	for_each_cpu(cpu, in) {
		if (!cpumask_test_cpu(cpu, core_mask)) {
			++count;

			/* Treat each numa node as a separate package */
			for_each_cpu(cpu2, topology_core_cpumask(cpu)) {
				if (cpu_to_node(cpu) == cpu_to_node(cpu2))
					cpumask_set_cpu(cpu2, core_mask);
			}
		}
	}

	free_cpumask_var(core_mask);

	return count;
}
#endif

static unsigned int efx_wanted_parallelism(struct efx_nic *efx)
{
	bool selected = false;
	unsigned int n_rxq;
	struct net_device *net_dev = efx->net_dev;

	efx->rss_mode = EFX_RSS_CORES;

	if (!rss_cpus) {
		/* Leave at default. */
	} else if (strcmp(rss_cpus, "packages") == 0) {
		efx->rss_mode = EFX_RSS_PACKAGES;
		selected = true;
	} else if (strcmp(rss_cpus, "cores") == 0) {
		efx->rss_mode = EFX_RSS_CORES;
		selected = true;
	} else if (strcmp(rss_cpus, "hyperthreads") == 0) {
		efx->rss_mode = EFX_RSS_HYPERTHREADS;
		selected = true;
	} else if (strcmp(rss_cpus, "numa_local_cores") == 0) {
		efx->rss_mode = EFX_RSS_NUMA_LOCAL_CORES;
		selected = true;
	} else if (strcmp(rss_cpus, "numa_local_hyperthreads") == 0) {
		efx->rss_mode = EFX_RSS_NUMA_LOCAL_HYPERTHREADS;
		selected = true;
	} else if (sscanf(rss_cpus, "%u", &n_rxq) == 1 && n_rxq > 0) {
		efx->rss_mode = EFX_RSS_CUSTOM;
		selected = true;
	} else {
		netif_err(efx, drv, net_dev,
			  "Bad value for module parameter rss_cpus='%s'\n",
			  rss_cpus);
	}

	switch (efx->rss_mode) {
#if defined(HAVE_EFX_NUM_PACKAGES)
	case EFX_RSS_PACKAGES:
		if (xen_domain()) {
			netif_warn(efx, drv, net_dev,
				   "Unable to determine CPU topology on Xen reliably. Using 4 rss channels.\n");
			n_rxq = 4;
		} else {
			netif_dbg(efx,  drv, net_dev,
				  "using efx_num_packages()\n");
			n_rxq = efx_num_packages(cpu_online_mask);
			/* Create two RSS queues even with a single package */
			if (n_rxq == 1)
				n_rxq = 2;
		}
		break;
#endif
#if defined(HAVE_EFX_NUM_CORES)
	case EFX_RSS_CORES:
		if (xen_domain()) {
			netif_warn(efx, drv, net_dev,
				   "Unable to determine CPU topology on Xen reliably. Assuming hyperthreading enabled.\n");
			n_rxq = max_t(int, 1, num_online_cpus() / 2);
		} else {
			netif_dbg(efx, drv, net_dev,
				  "using efx_num_cores()\n");
			n_rxq = efx_num_cores(cpu_online_mask);
		}
		break;
#endif
	case EFX_RSS_HYPERTHREADS:
		n_rxq = num_online_cpus();
		break;
#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)) && defined(HAVE_EFX_NUM_CORES)
	case EFX_RSS_NUMA_LOCAL_CORES:
		if (xen_domain()) {
			netif_warn(efx, drv, net_dev,
				   "Unable to determine CPU topology on Xen reliably. Creating rss channels for half of cores/hyperthreads.\n");
			n_rxq = max_t(int, 1, num_online_cpus() / 2);
		} else {
			n_rxq = min(efx_num_cores(cpu_online_mask),
			            efx_num_cores(cpumask_of_pcibus(efx->pci_dev->bus)));
		}
		break;
#endif
#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS))
	case EFX_RSS_NUMA_LOCAL_HYPERTHREADS:
		if (xen_domain()) {
			netif_warn(efx, drv, net_dev,
				   "Unable to determine CPU topology on Xen reliably. Creating rss channels for all cores/hyperthreads.\n");
			n_rxq = num_online_cpus();
		} else {
			n_rxq = min(num_online_cpus(),
			            cpumask_weight(cpumask_of_pcibus(efx->pci_dev->bus)));
		}
		break;
#endif
	case EFX_RSS_CUSTOM:
		break;
	default:
		if (selected)
			netif_err(efx, drv, net_dev,
				  "Selected rss mode '%s' not available\n",
				  rss_cpus);
		efx->rss_mode = EFX_RSS_HYPERTHREADS;
		n_rxq = num_online_cpus();
		break;
	}

	if (n_rxq > EFX_MAX_RX_QUEUES) {
		netif_warn(efx, drv, net_dev,
			   "Reducing number of rss channels from %u to %u.\n",
			   n_rxq, EFX_MAX_RX_QUEUES);
		n_rxq = EFX_MAX_RX_QUEUES;
	}

#ifdef CONFIG_SFC_SRIOV
	/* If RSS is requested for the PF *and* VFs then we can't write RSS
	 * table entries that are inaccessible to VFs
	 */
	if (efx_sriov_wanted(efx) && efx_vf_size(efx) > 1 &&
	    n_rxq > efx_vf_size(efx)) {
		netif_warn(efx, drv, net_dev,
			   "Reducing number of RSS channels from %u to %u for VF support. Increase vf-msix-limit to use more channels on the PF.\n",
			   n_rxq, efx_vf_size(efx));
		n_rxq = efx_vf_size(efx);
	}
#endif

	return n_rxq;
}

static unsigned int efx_num_rss_channels(struct efx_nic *efx)
{
	/* do not RSS to extra_channels, such as PTP */
	unsigned int rss_channels = efx_rx_channels(efx) -
				    efx->n_extra_channels;

#if (!defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)) && defined(HAVE_EFX_NUM_PACKAGES)
	if (rss_numa_local) {
		cpumask_var_t local_online_cpus;

		if (unlikely(!zalloc_cpumask_var(&local_online_cpus,
						 GFP_KERNEL))) {
			netif_err(efx, drv, efx->net_dev,
				  "Not enough temporary memory to determine local CPUs - using all CPUs for RSS.\n");
			rss_numa_local = false;
			return rss_channels;
		}

		cpumask_and(local_online_cpus, cpu_online_mask,
			    cpumask_of_pcibus(efx->pci_dev->bus));

		if (unlikely(!cpumask_weight(local_online_cpus))) {
			netif_info(efx, drv, efx->net_dev, "No local CPUs online - using all CPUs for RSS.\n");
			rss_numa_local = false;
			free_cpumask_var(local_online_cpus);
			return rss_channels;
		}

		if (efx->rss_mode == EFX_RSS_PACKAGES)
			rss_channels = min(rss_channels,
					   efx_num_packages(local_online_cpus));
#ifdef HAVE_EFX_NUM_CORES
		else if (efx->rss_mode == EFX_RSS_CORES)
			rss_channels = min(rss_channels,
					   efx_num_cores(local_online_cpus));
#endif
		else
			rss_channels = min(rss_channels,
					   cpumask_weight(local_online_cpus));
		free_cpumask_var(local_online_cpus);
	}
#endif

	return rss_channels;
}

static void efx_allocate_xdp_channels(struct efx_nic *efx,
				      unsigned int max_channels,
				      unsigned int n_channels)
{
	/* To allow XDP transmit to happen from arbitrary NAPI contexts
	 * we allocate a TX queue per CPU. We share event queues across
	 * multiple tx queues, assuming tx and ev queues are both
	 * maximum size.
	 */
	int tx_per_ev = EFX_MAX_EVQ_SIZE / EFX_TXQ_MAX_ENT(efx);
	int n_xdp_tx;
	int n_xdp_ev;

	n_xdp_tx = num_possible_cpus();
	n_xdp_ev = DIV_ROUND_UP(n_xdp_tx, tx_per_ev);

	/* Check resources.
	 * We need a channel per event queue, plus a VI per tx queue.
	 * This may be more pessimistic than it needs to be.
	 */
	if (n_channels + n_xdp_ev > max_channels) {
		netif_err(efx, drv, efx->net_dev,
			   "Insufficient resources for %d XDP event queues (%d current channels, max %d)\n",
			   n_xdp_ev, n_channels, max_channels);
		efx->n_xdp_channels = 0;
		efx->xdp_tx_per_channel = 0;
		efx->xdp_tx_queue_count = 0;
	} else if (n_channels + n_xdp_tx > efx->max_vis) {
		netif_err(efx, drv, efx->net_dev,
			  "Insufficient resources for %d XDP TX queues (%d current channels, max VIs %d)\n",
			  n_xdp_tx, n_channels, efx->max_vis);
		efx->n_xdp_channels = 0;
		efx->xdp_tx_per_channel = 0;
		efx->xdp_tx_queue_count = 0;
	} else {
		efx->n_xdp_channels = n_xdp_ev;
		efx->xdp_tx_per_channel = tx_per_ev;
		efx->xdp_tx_queue_count = n_xdp_tx;
		netif_dbg(efx, drv, efx->net_dev,
			  "Allocating %d TX and %d event queues for XDP\n",
			  n_xdp_tx, n_xdp_ev);
	}
}

static int efx_allocate_msix_channels(struct efx_nic *efx,
				      unsigned int max_channels,
				      unsigned int parallelism)
{
	unsigned int n_channels = parallelism;
	unsigned int extra_channel_type;
#ifdef EFX_HAVE_MSIX_CAP
	int vec_count;
#endif
	unsigned int min_channels = 1;

	if (separate_tx_channels) {
		n_channels *= 2;
		min_channels = 2;
	}

	if (max_channels < min_channels) {
		netif_err(efx, drv, efx->net_dev,
			  "Unable to satisfy minimum channel requirements\n");
		return -ENOSPC;
	}

	for (extra_channel_type = 0;
	     extra_channel_type < EFX_MAX_EXTRA_CHANNELS &&
	     !separate_tx_channels && n_channels < max_channels;
	     extra_channel_type++)
		n_channels += !!efx->extra_channel_type[extra_channel_type];

	efx_allocate_xdp_channels(efx, max_channels, n_channels);
	n_channels += efx->n_xdp_channels;

#ifdef EFX_HAVE_MSIX_CAP
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	/* dl IRQs don't need VIs, so no need to clamp to max_channels */
	n_channels += efx->n_dl_irqs;
#endif
#endif

	vec_count = pci_msix_vec_count(efx->pci_dev);
	if (vec_count < 0)
		return vec_count;
	if (vec_count < min_channels) {
		netif_err(efx, drv, efx->net_dev,
			  "Unable to satisfy minimum channel requirements\n");
		return -ENOSPC;
	}
	if (vec_count < n_channels) {
		netif_err(efx, drv, efx->net_dev,
			  "WARNING: Insufficient MSI-X vectors available (%d < %u).\n",
			  vec_count, n_channels);
		netif_err(efx, drv, efx->net_dev,
			  "WARNING: Performance may be reduced.\n");

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
		/* reduce driverlink allocated IRQs first, to a minimum of 1 */
		n_channels -= efx->n_dl_irqs;
		efx->n_dl_irqs = vec_count == min_channels ? 0 :
				 max(vec_count - (int)n_channels, 1);
		/* Make driverlink-consumed IRQ vectors unavailable for net
		 * driver use.
		 */
		vec_count -= efx->n_dl_irqs;
#endif
#endif
		/* reduce XDP channels */
		n_channels -= efx->n_xdp_channels;
		efx->n_xdp_channels = max(vec_count - (int)n_channels, 0);

		n_channels = vec_count;
	}
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	else {
		/* driverlink IRQs don't have a channel in the net driver, so
		 * remove them from further calculations.
		 */
		n_channels -= efx->n_dl_irqs;
	}
#endif
#endif
#endif

	/* Ignore XDP tx channels when creating rx channels. */
	n_channels -= efx->n_xdp_channels;

	if (separate_tx_channels) {
		efx->n_extra_channels = 0;
		efx->n_combined_channels = 0;
		efx->n_tx_only_channels =
			min(max(n_channels / 2, 1U),
			    efx->max_tx_channels);
		efx->tx_channel_offset =
			n_channels - efx->n_tx_only_channels;
		efx->n_rx_only_channels =
			max(n_channels -
			    efx->n_tx_only_channels, 1U);
	} else {
		efx->n_extra_channels = 0;
		/* allocate other channels, leaving at least one channel */
		for (extra_channel_type = 0;
		     extra_channel_type < EFX_MAX_EXTRA_CHANNELS &&
		     n_channels > 1 &&
		     efx->n_extra_channels + 1 < efx->max_tx_channels;
		     extra_channel_type++)
			efx->n_extra_channels += !!efx->extra_channel_type[extra_channel_type];
		n_channels -= efx->n_extra_channels;

		efx->n_combined_channels = min(n_channels,
					       efx->max_tx_channels);
		efx->n_tx_only_channels = 0;
		efx->tx_channel_offset = 0;
		/* if we have other channels then don't use RX only channels */
		efx->n_rx_only_channels = efx->n_extra_channels ? 0 :
			n_channels - efx->n_combined_channels;
	}
	efx->n_rss_channels = efx_num_rss_channels(efx);

	EFX_WARN_ON_PARANOID(efx->n_rx_only_channels &&
			     efx->n_tx_only_channels &&
			     (efx->n_combined_channels ||
			      efx->n_extra_channels));

	return 0;
}

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
static u16 efx_dl_make_irq_resources_(struct efx_dl_irq_resources *res,
				      size_t entries,
				      struct msix_entry *xentries)
{
	u16 n_ranges = 0;
	size_t i = 0, j;

	while (i < entries) {
		j = i + 1;

		while (j < entries &&
		       xentries[j - 1].vector + 1 == xentries[j].vector)
			++j;

		if (res) {
			res->irq_ranges[n_ranges].vector = xentries[i].vector;
			res->irq_ranges[n_ranges].range = j - i;
		}
		n_ranges++;
		i = j;
	}

	return n_ranges;
}

static void efx_dl_make_irq_resources(struct efx_nic *efx, size_t entries,
				      struct msix_entry *xentries)
{
	u16 n_ranges = efx_dl_make_irq_resources_(NULL, entries, xentries);

	if (n_ranges) {
		efx->irq_resources =
			kzalloc(sizeof(struct efx_dl_irq_resources) -
				sizeof(struct efx_dl_irq_range) +
				sizeof(struct efx_dl_irq_range) * n_ranges,
				GFP_KERNEL);
		if (!efx->irq_resources)
			netif_warn(efx, drv, efx->net_dev,
				   "Out of memory exporting interrupts to driverlink\n");
	}
	if (efx->irq_resources) {
		efx->irq_resources->hdr.type = EFX_DL_IRQ_RESOURCES;
		efx->irq_resources->channel_base = xentries[0].entry;
		efx->irq_resources->n_ranges = n_ranges;
		efx_dl_make_irq_resources_(efx->irq_resources,
					   entries, xentries);

		netif_dbg(efx, drv, efx->net_dev,
			  "Exporting %d IRQ range(s) to driverlink for channels %d-%zu. IRQ[0]=%d.\n",
			  efx->irq_resources->n_ranges,
			  efx->irq_resources->channel_base,
			  efx->irq_resources->channel_base + entries - 1,
			  efx->irq_resources->irq_ranges[0].vector);
	}
}
#endif
#endif

/* Probe the number and type of interrupts we are able to obtain, and
 * the resulting numbers of channels and RX queues.
 */
int efx_probe_interrupts(struct efx_nic *efx)
{
	unsigned int i;
	int rc;

	if (efx->interrupt_mode == EFX_INT_MODE_MSIX) {
		struct msix_entry *xentries;
		unsigned int n_channels = efx_channels(efx);

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
		n_channels += efx->n_dl_irqs;
#endif
#endif
		netif_dbg(efx, drv, efx->net_dev,
			  "Allocating %u interrupts\n", n_channels);

		xentries = kmalloc(n_channels * sizeof(*xentries), GFP_KERNEL);
		if (!xentries) {
			rc = -ENOMEM;
		} else {
			for (i = 0; i < n_channels; i++)
				xentries[i].entry = i;
			rc = pci_enable_msix_range(efx->pci_dev, xentries,
						   1, n_channels);
		}
		if (rc < 0) {
			/* Fall back to single channel MSI */
			netif_err(efx, drv, efx->net_dev,
				  "could not enable MSI-X (%d)\n", rc);
			if (efx->type->supported_interrupt_modes & BIT(EFX_INT_MODE_MSI))
				efx->interrupt_mode = EFX_INT_MODE_MSI;
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
			else if (efx->type->supported_interrupt_modes & BIT(EFX_INT_MODE_POLLED))
				efx->interrupt_mode = EFX_INT_MODE_POLLED;
#endif
			else {
				kfree(xentries);
				return rc;
			}
#ifndef EFX_HAVE_MSIX_CAP
		} else if (rc < n_channels) {
			unsigned int parallelism = efx_wanted_parallelism(efx);
			int rc2;

			netif_err(efx, drv, efx->net_dev,
				  "WARNING: Insufficient MSI-X vectors"
				  " available (%d < %u).\n", rc, n_channels);
			netif_err(efx, drv, efx->net_dev,
				  "WARNING: Performance may be reduced.\n");
			n_channels = rc;
			rc2 = efx_allocate_msix_channels(efx, n_channels,
							 parallelism);
			if (rc2)
				rc = rc2;
#endif
		}

		if (rc > 0) {
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
			n_channels -= efx->n_dl_irqs;
			efx_dl_make_irq_resources(efx, efx->n_dl_irqs,
						  xentries + n_channels);
#endif
#endif
			for (i = 0; i < n_channels; i++)
				efx_get_channel(efx, i)->irq =
					xentries[i].vector;
		}

		kfree(xentries);
	}

	/* Try single interrupt MSI */
	if (efx->interrupt_mode == EFX_INT_MODE_MSI) {
		efx->n_extra_channels = 0;
		efx->n_combined_channels = 1;
		efx->n_rx_only_channels = 0;
		efx->n_rss_channels = 1;
		efx->rss_spread = 1;
		efx->n_tx_only_channels = 0;
		efx->tx_channel_offset = 0;
		efx->n_xdp_channels = 0;
		rc = pci_enable_msi(efx->pci_dev);
		if (rc == 0) {
			efx_get_channel(efx, 0)->irq = efx->pci_dev->irq;
		} else {
			netif_err(efx, drv, efx->net_dev,
				  "could not enable MSI\n");
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
			if (efx->type->supported_interrupt_modes & BIT(EFX_INT_MODE_POLLED))
				efx->interrupt_mode = EFX_INT_MODE_POLLED;
			else
#endif
				return rc;
		}
	}

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
    if (efx->interrupt_mode == EFX_INT_MODE_POLLED) ;
        /* Do nothing */
#endif

	/* RSS on the PF might now be impossible due to interrupt allocation
	 * failure
	 */
#ifdef CONFIG_SFC_SRIOV
	if (efx_sriov_wanted(efx) && efx->rss_spread == 1)
		efx->rss_spread = efx_vf_size(efx);
#endif

	return 0;
}

void efx_remove_interrupts(struct efx_nic *efx)
{
	struct efx_channel *channel;

	/* Remove MSI/MSI-X interrupts */
	efx_for_each_channel(channel, efx)
		channel->irq = 0;
	pci_disable_msi(efx->pci_dev);
	pci_disable_msix(efx->pci_dev);
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	kfree(efx->irq_resources);
	efx->irq_resources = NULL;
#endif
#endif
}

#if !defined(CONFIG_SMP)
void efx_set_interrupt_affinity(struct efx_nic *efx __always_unused,
				bool rtnl_held __always_unused)
{
}

void efx_clear_interrupt_affinity(struct efx_nic *efx __always_unused)
{
}
#else
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NETIF_SET_XPS_QUEUE)
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_XPS)
static bool auto_config_xps = true;
module_param(auto_config_xps, bool, 0644);
MODULE_PARM_DESC(auto_config_xps,
		"Toggle automatic XPS configuration (default is enabled).");
#endif /* EFX_NOT_UPSTREAM && CONFIG_XPS */

static void efx_set_xps_queue(struct efx_channel *channel,
			     const cpumask_t *mask)
{
       if (!efx_channel_has_tx_queues(channel) ||
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_XPS)
	   !auto_config_xps ||
#endif
	   efx_channel_is_xdp_tx(channel) ||
	   channel == efx_ptp_channel(channel->efx))
		return;

       netif_set_xps_queue(channel->efx->net_dev, mask,
			   channel->channel - channel->efx->tx_channel_offset);
}
#else
static void efx_set_xps_queue(struct efx_channel *channel,
			     const cpumask_t *mask)
{
}
#endif

#if !defined(EFX_NOT_UPSTREAM)
void efx_set_interrupt_affinity(struct efx_nic *efx,
				bool rtnl_held __always_unused)
{
	struct efx_channel *channel;
	unsigned int cpu;

	efx_for_each_channel(channel, efx) {
		cpu = cpumask_local_spread(channel->channel,
					   pcibus_to_node(efx->pci_dev->bus));

		irq_set_affinity_hint(channel->irq, cpumask_of(cpu));
		channel->irq_mem_node = cpu_to_mem(cpu);
		efx_set_xps_queue(channel, cpumask_of(cpu));
	}
}

void efx_clear_interrupt_affinity(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		irq_set_affinity_hint(channel->irq, NULL);
}
#else
static bool efx_irq_set_affinity = true;
module_param_named(irq_set_affinity, efx_irq_set_affinity, bool, 0444);
MODULE_PARM_DESC(irq_set_affinity,
		  "Set SMP affinity of IRQs to support RSS (N=>disabled Y=>enabled (default))");

static int efx_set_cpu_affinity(struct efx_channel *channel, int cpu)
{
	int rc;

	if (!efx_irq_set_affinity)
		return 0;

        rc = irq_set_affinity_hint(channel->irq, cpumask_of(cpu));
        if (rc) {
                netif_err(channel->efx, drv, channel->efx->net_dev,
                          "Unable to set affinity hint for channel %d"
                          " interrupt %d\n", channel->channel, channel->irq);
                return rc;
        }
        efx_set_xps_queue(channel, cpumask_of(cpu));
        return rc;
}

/* Count of number of RSS channels allocated to each CPU
 * in the system. Protected by the rtnl lock
 */
static u16 *rss_cpu_usage;

#ifdef HAVE_EFX_NUM_PACKAGES
/* Select the package_set with the lowest usage count */
static void efx_rss_choose_package(cpumask_t *set, cpumask_t *package_set,
				   cpumask_t *used_set,
				   const cpumask_t *global_set)
{
	unsigned int thresh, count;
	int cpu, cpu2, sibling;

	thresh = 1;
	for_each_cpu(cpu, global_set)
		thresh += rss_cpu_usage[cpu];

	cpumask_clear(used_set);
	for_each_cpu(cpu, global_set) {
		if (!cpumask_test_cpu(cpu, used_set)) {
			cpumask_clear(package_set);
			/* Treat each numa node as a separate package */
			for_each_cpu(cpu2, topology_core_cpumask(cpu)) {
				if (cpu_to_node(cpu) == cpu_to_node(cpu2))
					cpumask_set_cpu(cpu2, package_set);
			}
			cpumask_and(package_set, package_set, global_set);
			cpumask_or(used_set, used_set, package_set);

			count = 0;
			for_each_cpu(sibling, package_set)
				count += rss_cpu_usage[sibling];

			if (count < thresh) {
				cpumask_copy(set, package_set);
				thresh = count;
			}
		}
	}
}
#endif

#ifdef HAVE_EFX_NUM_CORES
/* Select the thread siblings within the package with the lowest usage count */
static void efx_rss_choose_core(cpumask_t *set, const cpumask_t *package_set,
				cpumask_t *core_set, cpumask_t *used_set)
{
	unsigned int thresh, count;
	int cpu, sibling;

	thresh = 1;
	for_each_cpu(cpu, package_set)
		thresh += rss_cpu_usage[cpu];

	cpumask_clear(used_set);
	for_each_cpu(cpu, package_set) {
		if (!cpumask_test_cpu(cpu, used_set)) {
			cpumask_copy(core_set, topology_sibling_cpumask(cpu));
			cpumask_or(used_set, used_set, core_set);

			count = 0;
			for_each_cpu(sibling, core_set)
				count += rss_cpu_usage[sibling];

			if (count < thresh) {
				cpumask_copy(set, core_set);
				thresh = count;
			}
		}
	}
}
#endif

/* Select the thread within the mask with the lowest usage count */
static int efx_rss_choose_thread(const cpumask_t *set)
{
	int cpu, chosen;
	unsigned int thresh;

	thresh = 1;
	for_each_cpu(cpu, set)
		thresh += rss_cpu_usage[cpu];

	chosen = 0;
	for_each_cpu(cpu, set) {
		if (rss_cpu_usage[cpu] < thresh) {
			chosen = cpu;
			thresh = rss_cpu_usage[cpu];
		}
	}

	return chosen;
}

/* Stripe the RSS vectors across the CPUs. */
void efx_set_interrupt_affinity(struct efx_nic *efx, bool rtnl_held)
{
	enum {PACKAGE, CORE, TEMP1, TEMP2, LOCAL, SETS_MAX};
	struct efx_channel *channel;
	struct cpumask *sets;
	int cpu;

	/* Only do this for RSS/MSI-X */
	if (efx->interrupt_mode != EFX_INT_MODE_MSIX)
		return;

	sets = kcalloc(SETS_MAX, sizeof(*sets), GFP_KERNEL);
	if (!sets) {
		netif_err(efx, drv, efx->net_dev,
			  "Not enough temporary memory to set IRQ affinity\n");
		return;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)
	cpumask_and(&sets[LOCAL], cpu_online_mask,
		    cpumask_of_pcibus(efx->pci_dev->bus));
#endif

	/* Serialise access to rss_cpu_usage. On EF100 this is called from
	 * ef100_net_open(), which already has the RTNL lock.
	 */
	if (!rtnl_held)
		rtnl_lock();

	/* Assign each channel a CPU */
	efx_for_each_channel(channel, efx) {
#ifdef HAVE_EFX_NUM_PACKAGES
		/* Force channels 0-RSS to the local package, otherwise select
		 * the package with the lowest usage count
		 */
		efx_rss_choose_package(&sets[PACKAGE], &sets[TEMP1],
				       &sets[TEMP2],
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_CPUMASK_OF_PCIBUS)
				       rss_numa_local &&
				       channel->channel < efx->n_rss_channels ?
				       &sets[LOCAL] :
#endif
				       cpu_online_mask);
		WARN_ON(!cpumask_weight(&sets[PACKAGE]));
#else
		cpumask_copy(&sets[PACKAGE], &cpu_online_map);
#endif

		/* Select the thread siblings within this package with the
		 * lowest usage count
		 */
#ifdef HAVE_EFX_NUM_CORES
		efx_rss_choose_core(&sets[CORE], &sets[PACKAGE], &sets[TEMP1],
				    &sets[TEMP2]);
		WARN_ON(!cpumask_weight(&sets[CORE]));
#else
		cpumask_copy(&sets[CORE], &sets[PACKAGE]);
#endif
		/* Select the thread within this set with the lowest usage
		 * count
		 */
		cpu = efx_rss_choose_thread(&sets[CORE]);
		++rss_cpu_usage[cpu];
		efx_set_cpu_affinity(channel, cpu);
		channel->irq_mem_node = cpu_to_mem(cpu);
	}

	if (!rtnl_held)
		rtnl_unlock();

	kfree(sets);
}

void efx_clear_interrupt_affinity(struct efx_nic *efx)
{
        struct efx_channel *channel;

        efx_for_each_channel(channel, efx)
                (void)irq_set_affinity_hint(channel->irq, NULL);
}

#endif /* EFX_NOT_UPSTREAM */
#endif /* CONFIG_SMP */

#ifdef EFX_USE_IRQ_NOTIFIERS
static void efx_irq_release(struct kref *ref)
{
	struct efx_channel *channel = container_of(ref, struct efx_channel,
						   irq_affinity.notifier.kref);

	complete(&channel->irq_affinity.complete);
}

static void efx_irq_notify(struct irq_affinity_notify *this,
			   const cpumask_t *mask)
{
	struct efx_channel *channel = container_of(this, struct efx_channel,
						   irq_affinity.notifier);

	efx_set_xps_queue(channel, mask);
}

static void efx_set_affinity_notifier(struct efx_channel *channel)
{
	int rc;

	init_completion(&channel->irq_affinity.complete);
	channel->irq_affinity.notifier.notify = efx_irq_notify;
	channel->irq_affinity.notifier.release = efx_irq_release;
	rc = irq_set_affinity_notifier(channel->irq,
				       &channel->irq_affinity.notifier);
	if (rc)
		netif_warn(channel->efx, probe, channel->efx->net_dev,
			   "Failed to set irq notifier for IRQ %d\n",
			   channel->irq);
}

static void efx_clear_affinity_notifier(struct efx_channel *channel)
{
	/* Don't clear if it hasn't been set */
	if (!channel->irq_affinity.notifier.notify)
		return;
	irq_set_affinity_notifier(channel->irq, NULL);
	wait_for_completion(&channel->irq_affinity.complete);
	channel->irq_affinity.notifier.notify = NULL;
}

void efx_register_irq_notifiers(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		efx_set_affinity_notifier(channel);
}

void efx_unregister_irq_notifiers(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		efx_clear_affinity_notifier(channel);
}
#endif

/***************
 * EVENT QUEUES
 ***************/

/* Create event queue
 * Event queue memory allocations are done only once.  If the channel
 * is reset, the memory buffer will be reused; this guards against
 * errors during channel reset and also simplifies interrupt handling.
 */
static int efx_probe_eventq(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	struct efx_tx_queue *txq;
	unsigned long entries;

	/* When sizing our event queue we need to allow for:
	 *  - one entry per rxq entry.
	 *  - one entry per txq entry - or three if we're using timestamping.
	 *  - some capacity for MCDI and other events. This is mostly on
	 *    channel zero.
	 */
	if (efx_channel_has_rx_queue(channel))
		entries = efx->rxq_entries;
	else
		entries = 0;

	efx_for_each_channel_tx_queue(txq, channel) {
		entries += txq->timestamping ?
			   efx->txq_entries * 3 :
			   efx->txq_entries;
	}

	entries += channel->channel == 0 ? 256 : 128;

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	/* Add additional event queue entries for driverlink activity on
	 * channel zero.
	 */
	if (channel->channel == 0 && efx_dl_supported(efx))
		entries += EFX_EVQ_DL_EXTRA_ENTRIES;
#endif
#endif

	if (entries > EFX_MAX_EVQ_SIZE) {
		netif_warn(efx, probe, efx->net_dev,
			   "chan %d ev queue too large at %lu, capped at %lu\n",
			   channel->channel, entries, EFX_MAX_EVQ_SIZE);
		entries = EFX_MAX_EVQ_SIZE;
	} else {
		entries = roundup_pow_of_two(entries);
		netif_dbg(efx, probe, efx->net_dev,
			  "chan %d ev queue created with %lu entries\n",
			  channel->channel, entries);
	}
	channel->eventq_mask = max(entries, EFX_MIN_EVQ_SIZE) - 1;

	return efx_nic_probe_eventq(channel);
}

/* Prepare channel's event queue */
static int efx_init_eventq(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	int rc;

	EFX_WARN_ON_PARANOID(channel->eventq_init);

	netif_dbg(efx, drv, efx->net_dev,
		  "chan %d init event queue\n", channel->channel);

	rc = efx_nic_init_eventq(channel);
	if (rc == 0) {
		efx->type->push_irq_moderation(channel);
		channel->eventq_read_ptr = 0;
		channel->eventq_init = true;
	}
	return rc;
}

/* Enable event queue processing and NAPI */
void efx_start_eventq(struct efx_channel *channel)
{
	netif_dbg(channel->efx, ifup, channel->efx->net_dev,
		  "chan %d start event queue\n", channel->channel);

	/* Make sure the NAPI handler sees the enabled flag set */
	channel->enabled = true;
	smp_wmb();

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	efx_channel_enable(channel);
#endif
	napi_enable(&channel->napi_str);

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
	if (channel->efx->type->revision == EFX_REV_EF100 && channel->efx->interrupt_mode == EFX_INT_MODE_POLLED)
		napi_schedule(&channel->napi_str);
#endif

	efx_nic_eventq_read_ack(channel);
}

/* Disable event queue processing and NAPI */
void efx_stop_eventq(struct efx_channel *channel)
{
	if (!channel->enabled)
		return;

	netif_dbg(channel->efx, drv, channel->efx->net_dev,
		  "chan %d stop event queue\n", channel->channel);

	napi_disable(&channel->napi_str);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	while (!efx_channel_disable(channel))
		usleep_range(1000, 20000);
	efx_channel_unlock_napi(channel);

#ifdef CONFIG_NET_RX_BUSY_POLL
	if (channel->busy_poll_state != (1 << EFX_CHANNEL_STATE_DISABLE_BIT))
		netif_err(channel->efx, drv, channel->efx->net_dev,
			  "chan %d bad state %#lx\n", channel->channel,
			  channel->busy_poll_state);
#endif
#endif
	channel->enabled = false;
}

static void efx_fini_eventq(struct efx_channel *channel)
{
	if (!channel->eventq_init || efx_nic_hw_unavailable(channel->efx))
		return;

	netif_dbg(channel->efx, drv, channel->efx->net_dev,
		  "chan %d fini event queue\n", channel->channel);

	efx_nic_fini_eventq(channel);
	channel->eventq_init = false;
}

static void efx_remove_eventq(struct efx_channel *channel)
{
	netif_dbg(channel->efx, drv, channel->efx->net_dev,
		  "chan %d remove event queue\n", channel->channel);

	efx_nic_remove_eventq(channel);
}

/* Configure a normal TX channel - add TX queues */
static int efx_set_channel_tx(struct efx_nic *efx, struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	int queue_base;
	int j;

	EFX_WARN_ON_PARANOID(channel->tx_queues);
	channel->tx_queues = kcalloc(efx->tx_queues_per_channel,
				     sizeof(*tx_queue),
				     GFP_KERNEL);
	if (!channel->tx_queues)
		return -ENOMEM;

	channel->tx_queue_count = efx->tx_queues_per_channel;
	queue_base = efx->tx_queues_per_channel *
		     (channel->channel - efx->tx_channel_offset);

	for (j = 0; j < channel->tx_queue_count; ++j) {
		tx_queue = &channel->tx_queues[j];
		tx_queue->efx = efx;
		tx_queue->channel = channel;
		tx_queue->csum_offload = j;
		tx_queue->label = j;
		tx_queue->queue = queue_base + j;
		/* When using an even number of queues, for even numbered
		 * channels alternate the queues. This stripes events across
		 * the NIC resources more effectively.
		 */
		if (efx->tx_queues_per_channel % 2 == 0)
			tx_queue->queue ^= channel->channel & 1;
	}

	return 0;
}

/* Configure an XDP TX channel - add TX queues */
static int efx_set_channel_xdp(struct efx_nic *efx, struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	int xdp_zero_base;
	int xdp_base;
	int j;

	/* TX queue index for first XDP queue overall. */
	xdp_zero_base = efx->tx_queues_per_channel * efx_tx_channels(efx);
	/* TX queue index for first queue on this channel. */
	xdp_base = channel->channel - efx_xdp_channel_offset(efx);
	xdp_base *= efx->xdp_tx_per_channel;

	/* Do we need the full allowance of XDP tx queues for this channel?
	 * If the total number of queues required is not a multiple of
	 * xdp_tx_per_channel we omit the surplus queues.
	 */
	if (xdp_base + efx->xdp_tx_per_channel > efx->xdp_tx_queue_count) {
		channel->tx_queue_count = efx->xdp_tx_queue_count %
					  efx->xdp_tx_per_channel;
	} else {
		channel->tx_queue_count = efx->xdp_tx_per_channel;
	}
	EFX_WARN_ON_PARANOID(channel->tx_queue_count == 0);

	EFX_WARN_ON_PARANOID(channel->tx_queues);
	channel->tx_queues = kcalloc(channel->tx_queue_count,
				     sizeof(*tx_queue),
				     GFP_KERNEL);
	if (!channel->tx_queues) {
		channel->tx_queue_count = 0;
		return -ENOMEM;
	}

	for (j = 0; j < channel->tx_queue_count; ++j) {
		tx_queue = &channel->tx_queues[j];
		tx_queue->efx = efx;
		tx_queue->channel = channel;
		tx_queue->csum_offload = EFX_TXQ_TYPE_NO_OFFLOAD;
		tx_queue->label = j;
		tx_queue->queue = xdp_zero_base + xdp_base + j;

		/* Stash pointer for use by XDP TX */
		efx->xdp_tx_queues[xdp_base + j] = tx_queue;
	}

	return 0;
}

/* Allocate and initialise a channel structure. */
static struct efx_channel *
efx_alloc_channel(struct efx_nic *efx, int i, struct efx_channel *old_channel)
{
	struct efx_channel *channel;

	channel = kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel)
		return NULL;

	channel->efx = efx;
	channel->channel = i;
	channel->type = &efx_default_channel_type;
	channel->holdoff_doorbell = false;
	channel->tx_coalesce_doorbell = false;
	channel->irq_mem_node = NUMA_NO_NODE;
#ifdef CONFIG_RFS_ACCEL
	INIT_DELAYED_WORK(&channel->filter_work, efx_filter_rfs_expire);
#endif

	channel->rx_queue.efx = efx;

	return channel;
}

void efx_fini_channels(struct efx_nic *efx)
{
	unsigned int i;

	for (i = 0; i < EFX_MAX_CHANNELS; ++i) {
		kfree(efx->channel[i]);
		efx->channel[i] = NULL;
	}
}

int efx_init_channels(struct efx_nic *efx)
{
	unsigned int i;
	int rc = 0;

	if (WARN_ON(efx->type->supported_interrupt_modes == 0))
		return false;

	if (BIT(interrupt_mode) & efx->type->supported_interrupt_modes)
		efx->interrupt_mode = interrupt_mode;
	else
		efx->interrupt_mode = ffs(efx->type->supported_interrupt_modes) - 1;

#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_DUMMY_MSIX)
	if (efx->interrupt_mode == EFX_INT_MODE_MSIX)
		efx->interrupt_mode = EFX_INT_MODE_MSI;
#endif

	if (efx->interrupt_mode == EFX_INT_MODE_MSIX) {
		unsigned int parallelism = efx_wanted_parallelism(efx);

#ifdef EFX_HAVE_MSIX_CAP
		i = pci_msix_vec_count(efx->pci_dev);
		if (i > 0) {
			efx->max_channels =
				min(efx->max_channels, (u16)i);
			efx->max_tx_channels = efx->max_channels;
		}
#endif

		rc = efx_allocate_msix_channels(efx, efx->max_channels,
						parallelism);
		if (rc)
			return rc;
	}

	for (i = 0; i < EFX_MAX_CHANNELS; i++) {
		efx->channel[i] = efx_alloc_channel(efx, i, NULL);
		if (!efx->channel[i]) {
			netif_err(efx, drv, efx->net_dev,
				  "out of memory allocating channel\n");
			rc = -ENOMEM;
		}
		efx->msi_context[i].efx = efx;
		efx->msi_context[i].index = i;
	}

	return rc;
}

/* Allocate and initialise a channel structure, copying parameters
 * (but not resources) from an old channel structure.
 */
static struct efx_channel *
efx_copy_channel(struct efx_channel *old_channel)
{
	struct efx_tx_queue *new_tx_queues;
	struct efx_rx_queue *rx_queue;
	struct efx_tx_queue *tx_queue;
	struct efx_channel *channel;

	channel = kmalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel)
		return NULL;

	if (old_channel->tx_queue_count) {
		new_tx_queues = kcalloc(old_channel->tx_queue_count,
					sizeof(*new_tx_queues), GFP_KERNEL);
		if (!new_tx_queues) {
			kfree(channel);
			return NULL;
		}
	} else {
		new_tx_queues = NULL;
	}

#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_clear_affinity_notifier(old_channel);
#endif

	*channel = *old_channel;

	channel->napi_dev = NULL;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NAPI_STRUCT_NAPI_ID)
	INIT_HLIST_NODE(&channel->napi_str.napi_hash_node);
	channel->napi_str.napi_id = 0;
	channel->napi_str.state = 0;
#endif
	memset(&channel->eventq, 0, sizeof(channel->eventq));

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	/* Invalidate SSR state */
	channel->ssr.conns = NULL;
#endif

	if (channel->tx_queue_count) {
		channel->tx_queues = new_tx_queues;
		memcpy(channel->tx_queues, old_channel->tx_queues,
		       channel->tx_queue_count * sizeof(*tx_queue));

		efx_for_each_channel_tx_queue(tx_queue, channel) {
			if (tx_queue->channel)
				tx_queue->channel = channel;
			tx_queue->buffer = NULL;
			tx_queue->cb_page = NULL;
			memset(&tx_queue->txd, 0, sizeof(tx_queue->txd));
		}
	} else {
		channel->tx_queues = NULL;
	}

	rx_queue = &channel->rx_queue;
	rx_queue->buffer = NULL;
	memset(&rx_queue->rxd, 0, sizeof(rx_queue->rxd));

#ifdef EFX_USE_IRQ_NOTIFIERS
	efx_set_affinity_notifier(channel);
#endif
#ifdef CONFIG_RFS_ACCEL
	INIT_DELAYED_WORK(&channel->filter_work, efx_filter_rfs_expire);
#endif

	return channel;
}

static int efx_probe_channel(struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	struct efx_nic *efx;
	int rc;

	efx = channel->efx;

	netif_dbg(efx, probe, efx->net_dev,
		  "creating channel %d\n", channel->channel);

	rc = channel->type->pre_probe(channel);
	if (rc)
		goto fail;

	rc = efx_probe_eventq(channel);
	if (rc)
		goto fail;

	efx_for_each_channel_tx_queue(tx_queue, channel) {
		rc = efx_probe_tx_queue(tx_queue);
		if (rc)
			goto fail;
	}

	efx_for_each_channel_rx_queue(rx_queue, channel) {
		rc = efx_probe_rx_queue(rx_queue);
		if (rc)
			goto fail;
	}

	channel->rx_list = NULL;

	return 0;

fail:
	efx_remove_channel(channel);
	return rc;
}

static void
efx_get_channel_name(struct efx_channel *channel, char *buf, size_t len)
{
	struct efx_nic *efx = channel->efx;
	const char *type;
	int number;

	number = channel->channel;

	if (efx->n_xdp_channels && number >= efx_xdp_channel_offset(efx)) {
		type = "-xdp";
		number -= efx_xdp_channel_offset(efx);
	} else if (efx->tx_channel_offset == 0) {
		type = "";
	} else if (number < efx->tx_channel_offset) {
		type = "-rx";
	} else {
		type = "-tx";
		number -= efx->tx_channel_offset;
	}
	snprintf(buf, len, "%s%s-%d", efx->name, type, number);
}

void efx_set_channel_names(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		channel->type->get_name(channel,
					efx->msi_context[channel->channel].name,
					sizeof(efx->msi_context[0].name));
}

int efx_probe_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;
	int rc;

#ifdef EFX_NOT_UPSTREAM
	INIT_WORK(&efx->schedule_all_channels_work, efx_schedule_all_channels);
#endif

	/* Restart buffer table allocation */
	efx->next_buffer_table = 0;

	/* Probe channels in reverse, so that any 'extra' channels
	 * use the start of the buffer table. This allows the traffic
	 * channels to be resized without moving them or wasting the
	 * entries before them.
	 */
	efx_for_each_channel_rev(channel, efx) {
		rc = efx_probe_channel(channel);
		if (rc) {
			netif_err(efx, probe, efx->net_dev,
				  "failed to create channel %d\n",
				  channel->channel);
			return rc;
		}
	}
	efx_set_channel_names(efx);

	return efx_init_debugfs_channels(efx);
}

static void efx_remove_channel(struct efx_channel *channel)
{
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;

	netif_dbg(channel->efx, drv, channel->efx->net_dev,
		  "destroy chan %d\n", channel->channel);

	efx_for_each_channel_rx_queue(rx_queue, channel) {
		efx_remove_rx_queue(rx_queue);
		efx_destroy_rx_queue(rx_queue);
	}
	efx_for_each_channel_tx_queue(tx_queue, channel) {
		efx_remove_tx_queue(tx_queue);
		efx_destroy_tx_queue(tx_queue);
	}
	efx_remove_eventq(channel);
	channel->type->post_remove(channel);
}

void efx_remove_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_fini_debugfs_channels(efx);

#if defined(EFX_NOT_UPSTREAM) && (!defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC))
	cancel_work_sync(&efx->schedule_all_channels_work);
#endif

	efx_for_each_channel(channel, efx)
		efx_remove_channel(channel);
}

int
efx_realloc_channels(struct efx_nic *efx, u32 rxq_entries, u32 txq_entries)
{
	struct efx_channel *other_channel[EFX_MAX_CHANNELS], *channel;
	u32 old_rxq_entries, old_txq_entries;
	unsigned int i, next_buffer_table = 0;
	int rc, rc2;

	rc = efx_check_disabled(efx);
	if (rc)
		return rc;

	/* Not all channels should be reallocated. We must avoid
	 * reallocating their buffer table entries.
	 */
	efx_for_each_channel(channel, efx) {
		struct efx_rx_queue *rx_queue;
		struct efx_tx_queue *tx_queue;

		if (channel->type->copy)
			continue;
		next_buffer_table = max(next_buffer_table,
					channel->eventq.index +
					channel->eventq.entries);
		efx_for_each_channel_rx_queue(rx_queue, channel)
			next_buffer_table = max(next_buffer_table,
						rx_queue->rxd.index +
						rx_queue->rxd.entries);
		efx_for_each_channel_tx_queue(tx_queue, channel)
			next_buffer_table = max(next_buffer_table,
						tx_queue->txd.index +
						tx_queue->txd.entries);
	}

	efx_device_detach_sync(efx);
	efx_stop_all(efx);
	efx_soft_disable_interrupts(efx);

	/* Clone channels (where possible) */
	memset(other_channel, 0, sizeof(other_channel));
	for (i = 0; i < efx_channels(efx); i++) {
		channel = efx->channel[i];
		if (channel->type->copy)
			channel = channel->type->copy(channel);
		if (!channel) {
			rc = -ENOMEM;
			goto out;
		}
		other_channel[i] = channel;
	}

	/* Swap entry counts and channel pointers */
	old_rxq_entries = efx->rxq_entries;
	old_txq_entries = efx->txq_entries;
	efx->rxq_entries = rxq_entries;
	efx->txq_entries = txq_entries;
	for (i = 0; i < efx_channels(efx); i++) {
		channel = efx->channel[i];
		efx->channel[i] = other_channel[i];
		other_channel[i] = channel;
	}

	/* Restart buffer table allocation */
	efx->next_buffer_table = next_buffer_table;

	for (i = 0; i < efx_channels(efx); i++) {
		channel = efx->channel[i];
		if (!channel->type->copy)
			continue;
		rc = efx_probe_channel(channel);
		if (rc)
			goto rollback;
		rc = efx_init_napi_channel(efx->channel[i]);
		if (rc)
			goto rollback;
	}

out:
	/* Destroy unused channel structures */
	for (i = 0; i < efx_channels(efx); i++) {
		channel = other_channel[i];
		if (channel && channel->type->copy) {
			efx_fini_napi_channel(channel);
			efx_remove_channel(channel);
			kfree(channel->tx_queues);
			kfree(channel);
		}
	}

	rc2 = efx_soft_enable_interrupts(efx);
	if (rc2) {
		rc = rc ? rc : rc2;
		netif_err(efx, drv, efx->net_dev,
			  "unable to restart interrupts on channel reallocation\n");
		efx_schedule_reset(efx, RESET_TYPE_DISABLE);
	} else {
		efx_start_all(efx);
		efx_device_attach_if_not_resetting(efx);
	}
	return rc;

rollback:
	/* Swap back */
	efx->rxq_entries = old_rxq_entries;
	efx->txq_entries = old_txq_entries;
	for (i = 0; i < efx_channels(efx); i++) {
		channel = efx->channel[i];
		efx->channel[i] = other_channel[i];
		other_channel[i] = channel;
#ifdef EFX_USE_IRQ_NOTIFIERS
		efx_set_affinity_notifier(efx->channel[i]);
#endif
	}
	goto out;
}

int efx_set_channels(struct efx_nic *efx)
{
	unsigned int i, j, hidden_tx_channels = 0;
	struct efx_channel *channel;
	int rc = 0;

	if (efx->xdp_tx_queue_count) {
		EFX_WARN_ON_PARANOID(efx->xdp_tx_queues);

		/* Allocate array for XDP TX queue lookup. */
		efx->xdp_tx_queues = kcalloc(efx->xdp_tx_queue_count,
					     sizeof(*efx->xdp_tx_queues),
					     GFP_KERNEL);
		if (!efx->xdp_tx_queues)
			return -ENOMEM;
	}

	/* set all channels to default type.
	 * will be overridden for extra_channels
	 */
	efx_for_each_channel(channel, efx)
		channel->type = &efx_default_channel_type;

	/* Assign extra channels if possible in to extra_channel range */
	for (i = 0, j = efx_extra_channel_offset(efx);
	     i < EFX_MAX_EXTRA_CHANNELS; i++) {
		if (!efx->extra_channel_type[i])
			continue;

		if (j < efx_extra_channel_offset(efx) + efx->n_extra_channels) {
			efx_get_channel(efx, j++)->type =
				efx->extra_channel_type[i];
			/* Other TX channels exposed to the kernel must be
			 * before hidden ones in the extra_channel_type array.
			 */
			WARN_ON(hidden_tx_channels &&
				!efx->extra_channel_type[i]->hide_tx);
			hidden_tx_channels +=
				efx->extra_channel_type[i]->hide_tx ||
				hidden_tx_channels != 0;
		} else {
			efx->extra_channel_type[i]->handle_no_channel(efx);
		}
	}

	/* We need to mark which channels really have RX and TX
	 * queues, and adjust the TX queue numbers if we have separate
	 * RX-only and TX-only channels.
	 */
	efx_for_each_channel(channel, efx) {
		if (channel->channel < efx_rx_channels(efx))
			channel->rx_queue.core_index = channel->channel;
		else
			channel->rx_queue.core_index = -1;

		if (efx_channel_is_xdp_tx(channel))
			rc = efx_set_channel_xdp(efx, channel);
		else if (efx_channel_has_tx_queues(channel))
			rc = efx_set_channel_tx(efx, channel);

		if (rc)
			return rc;
	}

	netif_set_real_num_tx_queues(efx->net_dev, efx_tx_channels(efx) -
						   hidden_tx_channels);
	netif_set_real_num_rx_queues(efx->net_dev, efx_rx_channels(efx));

	return 0;
}

void efx_unset_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;

	kfree(efx->xdp_tx_queues);
	efx->xdp_tx_queues = NULL;

	efx_for_each_channel(channel, efx) {
		channel->tx_queue_count = 0;
		kfree(channel->tx_queues);
		channel->tx_queues = NULL;
	}
}

/*************
 * START/STOP
 *************/
static int efx_soft_enable_interrupts(struct efx_nic *efx)
{
	struct efx_channel *channel, *end_channel;
	int rc;

	if (efx->state == STATE_DISABLED)
		return -ENETDOWN;

	efx->irq_soft_enabled = true;
	smp_wmb();

	efx_for_each_channel(channel, efx) {
		if (!channel->type->keep_eventq) {
			rc = efx_init_eventq(channel);
			if (rc)
				goto fail;
		}
		efx_start_eventq(channel);
	}

	efx_mcdi_mode_event(efx);

	return 0;
fail:
	end_channel = channel;
	efx_for_each_channel(channel, efx) {
		if (channel == end_channel)
			break;
		efx_stop_eventq(channel);
		if (!channel->type->keep_eventq)
			efx_fini_eventq(channel);
	}

	return rc;
}

static void efx_soft_disable_interrupts(struct efx_nic *efx)
{
	struct efx_channel *channel;

	if (efx->state == STATE_DISABLED)
		return;

	efx_mcdi_mode_poll(efx);

	efx->irq_soft_enabled = false;
	smp_wmb();

	efx_for_each_channel(channel, efx) {
		if (channel->irq)
			synchronize_irq(channel->irq);

		efx_stop_eventq(channel);
		if (!channel->type->keep_eventq)
			efx_fini_eventq(channel);
	}
}

int efx_enable_interrupts(struct efx_nic *efx)
{
	struct efx_channel *channel, *end_channel;
	int rc;

	if (efx->state == STATE_DISABLED)
		return -ENETDOWN;

	efx->type->irq_enable_master(efx);

	efx_for_each_channel(channel, efx) {
		if (channel->type->keep_eventq) {
			rc = efx_init_eventq(channel);
			if (rc)
				goto fail;
		}
	}

	rc = efx_soft_enable_interrupts(efx);
	if (rc)
		goto fail;

	return 0;

fail:
	end_channel = channel;
	efx_for_each_channel(channel, efx) {
		if (channel == end_channel)
			break;
		if (channel->type->keep_eventq)
			efx_fini_eventq(channel);
	}

	efx->type->irq_disable_non_ev(efx);

	return rc;
}

void efx_disable_interrupts(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_soft_disable_interrupts(efx);

	efx_for_each_channel(channel, efx) {
		if (channel->type->keep_eventq)
			efx_fini_eventq(channel);
	}

	efx->type->irq_disable_non_ev(efx);
}

int efx_start_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	int rc;

	efx_for_each_channel(channel, efx) {
		if (channel->type->start) {
			rc = channel->type->start(channel);
			if (rc)
				return rc;
		}
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			rc = efx_init_tx_queue(tx_queue);
			if (rc)
				return rc;
			atomic_inc(&efx->active_queues);
		}

		efx_for_each_channel_rx_queue(rx_queue, channel) {
			rc = efx_init_rx_queue(rx_queue);
			if (rc)
				return rc;
			atomic_inc(&efx->active_queues);
			efx_stop_eventq(channel);
			rx_queue->refill_enabled = true;
			efx_fast_push_rx_descriptors(rx_queue, false);
			efx_start_eventq(channel);
		}
	}

	return 0;
}

void efx_stop_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	struct efx_mcdi_iface *mcdi = NULL;
	int rc = 0;

	/* Stop RX refill */
	efx_for_each_channel(channel, efx) {
		efx_for_each_channel_rx_queue(rx_queue, channel)
			rx_queue->refill_enabled = false;
	}

	efx_for_each_channel(channel, efx) {
		if (channel->type->stop)
			channel->type->stop(channel);
		/* RX packet processing is pipelined, so wait for the
		 * NAPI handler to complete.  At least event queue 0
		 * might be kept active by non-data events, so don't
		 * use napi_synchronize() but actually disable NAPI
		 * temporarily.
		 */
		if (efx_channel_has_rx_queue(channel)) {
			efx_stop_eventq(channel);
			efx_start_eventq(channel);
		}
	}

	if (efx->type->fini_dmaq)
		rc = efx->type->fini_dmaq(efx);
	else
		rc = efx_fini_dmaq(efx);
	if (rc) {
		if (efx->mcdi)
			mcdi = efx_mcdi(efx);
		if (mcdi && mcdi->mode == MCDI_MODE_FAIL) {
			netif_info(efx, drv, efx->net_dev,
				   "Ignoring flush queue failure as we're in MCDI_MODE_FAIL\n");
		} else {
			netif_err(efx, drv, efx->net_dev,
				  "Recover or disable due to flush queue failure\n");
			efx_schedule_reset(efx, RESET_TYPE_RECOVER_OR_DISABLE);
		}
	} else {
		netif_dbg(efx, drv, efx->net_dev,
			  "successfully flushed all queues\n");
	}

#if defined(EFX_NOT_UPSTREAM) && (!defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC))
	cancel_work_sync(&efx->schedule_all_channels_work);
#endif

	efx_for_each_channel(channel, efx) {
		efx_for_each_channel_rx_queue(rx_queue, channel)
			efx_fini_rx_queue(rx_queue);
		efx_for_each_channel_tx_queue(tx_queue, channel)
			efx_fini_tx_queue(tx_queue);
	}
}

/**************************************************************************
 *
 * NAPI interface
 *
 **************************************************************************/
/* Process channel's event queue
 *
 * This function is responsible for processing the event queue of a
 * single channel.  The caller must guarantee that this function will
 * never be concurrently called more than once on the same channel,
 * though different channels may be being processed concurrently.
 */
static int efx_process_channel(struct efx_channel *channel, int budget)
{
	int spent;
	struct efx_nic *efx = channel->efx;
	struct efx_tx_queue *tx_queue;
	struct netdev_queue *core_txq;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	struct list_head rx_list;
#else
	struct sk_buff_head rx_list;
#endif
	unsigned int fill_level;

	if (unlikely(!channel->enabled))
		return 0;

	/* Notify the TX path that we are going to ping
	 * doorbell, do this early to maximise benefit
	 */
	channel->holdoff_doorbell = channel->tx_coalesce_doorbell;

	efx_for_each_channel_tx_queue(tx_queue, channel) {
		tx_queue->pkts_compl = 0;
		tx_queue->bytes_compl = 0;
	}

	/* Prepare the batch receive list */
	EFX_WARN_ON_PARANOID(channel->rx_list != NULL);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_SKB__LIST)
	INIT_LIST_HEAD(&rx_list);
#else
	__skb_queue_head_init(&rx_list);
#endif
	channel->rx_list = &rx_list;

	spent = efx_nic_process_eventq(channel, budget);
	if (spent && efx_channel_has_rx_queue(channel)) {
		struct efx_rx_queue *rx_queue =
			efx_channel_get_rx_queue(channel);

		efx_rx_flush_packet(channel);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
		efx_ssr_end_of_burst(channel);
#endif
		efx_fast_push_rx_descriptors(rx_queue, true);
	}

	/* Receive any packets we queued up */
	netif_receive_skb_list(channel->rx_list);
	channel->rx_list = NULL;

	/* See if we need to ping doorbell if there is
	 * anything on the send queue that NIC has not been
	 * informed of.
	 */
	while (unlikely(channel->holdoff_doorbell)) {
		unsigned int unsent = 0;

		/* write_count and notify_count can be updated on the Tx path
		 * so use READ_ONCE() in this loop to avoid optimizations that
		 * would avoid reading the latest values from memory.
		 */

		/* There are unsent packets, for this to be set
		 * the xmit thread knows we are running
		 */
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			if (READ_ONCE(tx_queue->notify_count) !=
			    READ_ONCE(tx_queue->write_count)) {
				efx_nic_notify_tx_desc(tx_queue);
				++tx_queue->doorbell_notify_comp;
			}
		}
		channel->holdoff_doorbell = false;
		smp_mb();
		efx_for_each_channel_tx_queue(tx_queue, channel)
			unsent += READ_ONCE(tx_queue->write_count) -
				  READ_ONCE(tx_queue->notify_count);
		if (unsent) {
			channel->holdoff_doorbell = true;

			/* Ensure that all reads and writes are complete to
			 * allow the latest values to be read in the next
			 * iteration, and that the Tx path sees holdoff_doorbell
			 * true so there are no further updates at this point.
			 */
			smp_mb();
		}
	}

	/* Update BQL */
	smp_rmb(); /* ensure netdev_tx_sent updates are seen */
	efx_for_each_channel_tx_queue(tx_queue, channel)
		if (tx_queue->bytes_compl && tx_queue->core_txq)
			netdev_tx_completed_queue(tx_queue->core_txq,
						  tx_queue->pkts_compl,
						  tx_queue->bytes_compl);

	if (channel->tx_queues) {
		core_txq = channel->tx_queues[0].core_txq;
		fill_level = efx_channel_tx_fill_level(channel);

		/* See if we need to restart the netif queue. */
		if (fill_level <= efx->txq_wake_thresh &&
		    likely(core_txq) &&
		    unlikely(netif_tx_queue_stopped(core_txq)) &&
		    likely(efx->port_enabled) &&
		    likely(netif_device_present(efx->net_dev)))
			netif_tx_wake_queue(core_txq);
	}

	return spent;
}

static void efx_update_irq_mod(struct efx_nic *efx, struct efx_channel *channel)
{
	int step = efx->irq_mod_step_us;

	if (channel->irq_mod_score < irq_adapt_low_thresh) {
		if (channel->irq_moderation_us > step) {
			channel->irq_moderation_us -= step;
			efx->type->push_irq_moderation(channel);
		}
	} else if (channel->irq_mod_score > irq_adapt_high_thresh) {
		if (channel->irq_moderation_us <
		    efx->irq_rx_moderation_us) {
			channel->irq_moderation_us += step;
			efx->type->push_irq_moderation(channel);
		}
	}

	channel->irq_count = 0;
	channel->irq_mod_score = 0;
}

/* NAPI poll handler
 *
 * NAPI guarantees serialisation of polls of the same device, which
 * provides the guarantee required by efx_process_channel().
 */
static int efx_poll(struct napi_struct *napi, int budget)
{
	struct efx_channel *channel =
		container_of(napi, struct efx_channel, napi_str);
	struct efx_nic *efx = channel->efx;
#ifdef CONFIG_RFS_ACCEL
	unsigned int time;
#endif
	int spent;

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	if (!efx_channel_lock_napi(channel))
		return budget;
#endif

	netif_vdbg(efx, intr, efx->net_dev,
		   "channel %d NAPI poll executing on CPU %d\n",
		   channel->channel, raw_smp_processor_id());

	spent = efx_process_channel(channel, budget);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_REDIR)
	xdp_do_flush_map();
#endif

	if (spent < budget) {
		if (efx_channel_has_rx_queue(channel) &&
		    efx->irq_rx_adaptive &&
		    unlikely(++channel->irq_count == irq_adapt_irqs)) {
			efx_update_irq_mod(efx, channel);
		}

#ifdef CONFIG_RFS_ACCEL
		/* Perhaps expire some ARFS filters */
		time = jiffies - channel->rfs_last_expiry;
		/* Would our quota be >= 20? */
		if (channel->rfs_filter_count * time >= 600 * HZ)
			mod_delayed_work(system_wq, &channel->filter_work, 0);
#endif

		/* There is no race here; although napi_disable() will
		 * only wait for napi_complete(), this isn't a problem
		 * since efx_nic_eventq_read_ack() will have no effect if
		 * interrupts have already been disabled.
		 */
		if (napi_complete_done(napi, spent))
			efx_nic_eventq_read_ack(channel);
	}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	efx_channel_unlock_napi(channel);
#endif
	return spent;
}

static int efx_init_napi_channel(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;

	channel->napi_dev = efx->net_dev;
	netif_napi_add(channel->napi_dev, &channel->napi_str,
		       efx_poll, napi_weight);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	{
		int rc = efx_ssr_init(channel, efx);

		if (rc) {
			efx_fini_napi(efx);
			return rc;
		}
	}
#endif
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
	efx_channel_busy_poll_init(channel);
#endif

	return 0;
}

int efx_init_napi(struct efx_nic *efx)
{
	struct efx_channel *channel;
	int rc;

	efx_for_each_channel(channel, efx) {
		rc = efx_init_napi_channel(channel);
		if (rc)
			return rc;
	}

	return 0;
}

static void efx_fini_napi_channel(struct efx_channel *channel)
{
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SFC_LRO)
	efx_ssr_fini(channel);
#endif
	if (channel->napi_dev)
		netif_napi_del(&channel->napi_str);
	channel->napi_dev = NULL;
}

void efx_fini_napi(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		efx_fini_napi_channel(channel);
}

#ifdef EFX_NOT_UPSTREAM
static void efx_schedule_all_channels(struct work_struct *data)
{
	struct efx_nic *efx = container_of(data, struct efx_nic,
			schedule_all_channels_work);
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx) {
		local_bh_disable();
		efx_schedule_channel(channel);
		local_bh_enable();
	}
}

void efx_pause_napi(struct efx_nic *efx)
{
	struct efx_channel *channel;

	if (efx->state != STATE_NET_UP)
		return;

	ASSERT_RTNL();
	netif_dbg(efx, drv, efx->net_dev, "Pausing NAPI\n");

	efx_for_each_channel(channel, efx) {
		napi_disable(&channel->napi_str);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
		while (!efx_channel_disable(channel))
			usleep_range(1000, 20000);
		efx_channel_unlock_napi(channel);

#ifdef CONFIG_NET_RX_BUSY_POLL
		if (channel->busy_poll_state !=
		    (1 << EFX_CHANNEL_STATE_DISABLE_BIT))
			netif_err(channel->efx, drv, channel->efx->net_dev,
				  "chan %d bad state %#lx in %s\n",
				  channel->channel,
				  channel->busy_poll_state, __func__);
#endif
#endif
	}
}

int efx_resume_napi(struct efx_nic *efx)
{
	struct efx_channel *channel;

	if (efx->state != STATE_NET_UP)
		return 0;

	ASSERT_RTNL();
	netif_dbg(efx, drv, efx->net_dev, "Resuming NAPI\n");

	efx_for_each_channel(channel, efx) {
#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
		efx_channel_enable(channel);
#endif
		napi_enable(&channel->napi_str);
	}

	/* Schedule all channels in case we've
	 * missed something whilst paused.
	 */
	schedule_work(&efx->schedule_all_channels_work);

	return 0;
}
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_NDO_POLL_CONTROLLER)
#ifdef CONFIG_NET_POLL_CONTROLLER

/* Although in the common case interrupts will be disabled, this is not
 * guaranteed. However, all our work happens inside the NAPI callback,
 * so no locking is required.
 */
void efx_netpoll(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		efx_schedule_channel(channel);
}

#endif
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_WANT_DRIVER_BUSY_POLL)
#ifdef CONFIG_NET_RX_BUSY_POLL
int efx_busy_poll(struct napi_struct *napi)
{
	struct efx_channel *channel =
		container_of(napi, struct efx_channel, napi_str);
	struct efx_nic *efx = channel->efx;
	int budget = 4;
	int old_rx_packets, rx_packets;

	if (!netif_running(efx->net_dev))
		return LL_FLUSH_FAILED;

	if (!efx_channel_try_lock_poll(channel))
		return LL_FLUSH_BUSY;

	old_rx_packets = channel->rx_queue.rx_packets;
	efx_process_channel(channel, budget);

	rx_packets = channel->rx_queue.rx_packets - old_rx_packets;

	/* There is no race condition with NAPI here.
	 * NAPI will automatically be rescheduled if it yielded during busy
	 * polling, because it was not able to take the lock and thus returned
	 * the full budget.
	 */
	efx_channel_unlock_poll(channel);

	return rx_packets;
}
#endif
#endif

/***************
 * Housekeeping
 ***************/

int efx_channel_dummy_op_int(struct efx_channel *channel)
{
	return 0;
}

void efx_channel_dummy_op_void(struct efx_channel *channel)
{
}

static const struct efx_channel_type efx_default_channel_type = {
	.pre_probe              = efx_channel_dummy_op_int,
	.post_remove            = efx_channel_dummy_op_void,
	.get_name               = efx_get_channel_name,
	.copy                   = efx_copy_channel,
	.keep_eventq            = false,
};

int efx_channels_init_module(void)
{
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP)
	rss_cpu_usage = kzalloc(NR_CPUS * sizeof(rss_cpu_usage[0]), GFP_KERNEL);
	if (!rss_cpu_usage)
		return -ENOMEM;
#endif
	return 0;
}

void efx_channels_fini_module(void)
{
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SMP)
	kfree(rss_cpu_usage);
	rss_cpu_usage = NULL;
#endif
}

