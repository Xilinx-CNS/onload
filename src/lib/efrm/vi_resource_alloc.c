/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains allocation of VI resources.
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

#include <ci/efrm/nic_table.h>
#include <ci/efhw/iopage.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/mc_driver_pcol.h>
#include <ci/efhw/efct.h>
#include <ci/efrm/private.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/vi_set.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/pio.h>
#include <ci/tools/utils.h>
#include <ci/tools/debug.h>
#include <etherfabric/vi.h>
#include <etherfabric/internal/internal.h>
#include <linux/file.h>
#include "efrm_internal.h"
#include "efrm_vi_set.h"
#include "efrm_pd.h"
#include "bt_manager.h"
#include "sfcaffinity.h"
#include "debugfs_rs.h"
#include <ci/driver/resource/linux_efhw_nic.h>
#include <onload/tcp_helper.h>
#include <onload/tcp_helper_fns.h>


struct vi_attr {
	struct efrm_pd     *pd;
	struct efrm_vi_set *vi_set;
	int16_t             interrupt_core;
	int16_t             channel;
	uint8_t             want_interrupt;
	uint8_t             vi_set_instance;
	int8_t              packed_stream;
	int32_t             ps_buffer_size;
	bool                want_rxq;
	bool                want_txq;
};

CI_BUILD_ASSERT(sizeof(struct vi_attr) <= sizeof(struct efrm_vi_attr));

union vi_attr_u {
	struct vi_attr      vi_attr;
	struct efrm_vi_attr efrm_vi_attr;
};


#define VI_ATTR_FROM_O_ATTR(attr)					\
  (&(container_of((attr), union vi_attr_u, efrm_vi_attr)->vi_attr))

/* Linux 4.6 introduced a specific define for this */
#ifndef IRQ_NOTCONNECTED
#define IRQ_NOTCONNECTED        (1U << 31)
#endif


/*** Data definitions ****************************************************/

static const char *q_names[EFHW_N_Q_TYPES] = { "TXQ", "RXQ", "EVQ" };
static const char default_irq_name[] = "Onload";

struct vi_resource_manager *efrm_vi_manager;


/*** Forward references **************************************************/

static void
__efrm_vi_resource_free(struct efrm_vi *virs);


/*** Reference count handling ********************************************/

static void efrm_vi_rm_get_ref(struct efrm_vi *virs)
{
	atomic_inc(&virs->evq_refs);
}

static void efrm_vi_rm_drop_ref(struct efrm_vi *virs)
{
	EFRM_ASSERT(atomic_read(&virs->evq_refs) != 0);
	if (atomic_dec_and_test(&virs->evq_refs))
		__efrm_vi_resource_free(virs);
}


static inline void efrm_atomic_or(int i, atomic_t *v)
{
	int old, new;
	do {
		old = atomic_read(v);
		new = old | i;
	} while (atomic_cmpxchg(v, old, new) != old);
}

static irqreturn_t
vi_interrupt(int irq, void *dev_id)
{
	struct efrm_interrupt_vector *vec = dev_id;

	/* efrm_eventq_do_interrupt_callbacks() assumes its calls are
	 * serialised.  request_threaded_irq() creates exactly one thread
	 * for each IRQ, so we don't need any additional locking here. */

	/* Fixme: callback with is_timeout=true? */
	efrm_eventq_do_interrupt_callbacks(vec, false, INT_MAX);
	return IRQ_HANDLED;
}


#ifndef IRQF_SAMPLE_RANDOM
#define IRQF_SAMPLE_RANDOM 0
#endif


static int
efrm_vi_irq_setup(struct efrm_interrupt_vector *vec)
{
	char name_local[80];
	int rc;
	const char *name;
	unsigned flags = IRQF_SAMPLE_RANDOM;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0) && \
    (!defined RHEL_MAJOR || RHEL_MAJOR < 8)
	/* This flag is safe to use for all kernels (per commentary surrounding
	 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=923aa4c378f9 )
	 * however it does come with a performance cost ("For !ONESHOT irqs the
	 * thread mask is 0 so we can avoid a conditional in irq_wake_thread()" in
	 * kernel/irq/manage.c). The above ifdefs, then, are a minimal attempt at
	 * avoiding that extra cost on systems where we've manually verified that
	 * we don't need it. Ubuntu's 4.15.0 has been verified to be 'old'. If
	 * that condition is imperfect then it just means a system might be a
	 * little slower than it could be. */
	flags |= IRQF_ONESHOT;
#endif

	snprintf(name_local, sizeof(name_local), "onld-%d",
		 vec->nic->index);
	name_local[sizeof(name_local) - 1] = '\0';

	/* Enable interrupts */
	name = kstrdup(name_local, GFP_KERNEL);
	if (!name)
		name = default_irq_name;
	rc = request_threaded_irq(vec->irq, NULL, vi_interrupt, flags, name, vec);
	if (rc != 0) {
		EFRM_ERR("failed to request IRQ %d for NIC %d", vec->irq,
			 vec->nic->index);
		if (name != default_irq_name)
			kfree(name);
	}
#ifndef EFRM_IRQ_FREE_RETURNS_NAME
	vec->irq_name = name;
#endif

	return rc;
}


static void
efrm_vi_irq_free(struct efrm_interrupt_vector *vec)
{
	const char *name;
	EFRM_ASSERT(vec);

	/* If the underlying hardware has gone away we'll already have
	 * freed the irq at device remove time. */
	if( vec->irq == IRQ_NOTCONNECTED )
		return;

	/* linux>=4.13: free_irq() returns name */
#ifdef EFRM_IRQ_FREE_RETURNS_NAME
	name = free_irq(vec->irq, &vec->tasklet);
#else
	free_irq(vec->irq, vec);
	name = vec->irq_name;
	vec->irq_name = NULL;
#endif
	EFRM_ASSERT(name);
	if (name != default_irq_name)
		kfree(name);

	efhw_nic_irq_free(vec->nic, vec->channel, vec->irq);
	vec->channel = IRQ_NOTCONNECTED;
	vec->irq = IRQ_NOTCONNECTED;
}


static int efrm_interrupt_vector_acquire(struct efrm_interrupt_vector *vec)
{
	int rc = 0;

	mutex_lock(&vec->vec_acquire_lock);
	if (vec->num_vis == 0)
		rc = efrm_vi_irq_setup(vec);
	if (rc == 0)
		++vec->num_vis;
	mutex_unlock(&vec->vec_acquire_lock);

	return rc;
}


static void efrm_interrupt_vector_release(struct efrm_interrupt_vector *vec)
{
	mutex_lock(&vec->vec_acquire_lock);
	--vec->num_vis;
	if (vec->num_vis == 0)
		efrm_vi_irq_free(vec);
	mutex_unlock(&vec->vec_acquire_lock);
}


static int
efrm_interrupt_vector_choose(struct efrm_nic *nic, struct efrm_vi *virs)
{
	struct efrm_interrupt_vector *current_vec = NULL, *selected_vec = NULL;
	uint32_t irq, channel;
	int rc;

	mutex_lock(&nic->irq_list_lock);
	rc = efhw_nic_irq_alloc(&nic->efhw_nic, &channel, &irq);
	if (rc < 0) {
		/* IRQ allocation failed. Find the least used vector of those
		 * that have already been allocated.*/
		struct efrm_interrupt_vector *least_used_vec = NULL;
		list_for_each_entry(current_vec, &nic->irq_list, link) {
			/* The num_vis could be changing under our feet, but
			 * it's not worth locking each vector to prevent this.
			 */
			if (least_used_vec == NULL ||
				current_vec->num_vis < least_used_vec->num_vis)
				least_used_vec = current_vec;
			if (current_vec->num_vis == 0)
				break;
		}
		selected_vec = least_used_vec;
	} else {
		/* IRQ allocation succeeded. Find an unconnected vector and
		 * update it with the new irq and channel values. */
		list_for_each_entry(current_vec, &nic->irq_list, link) {
			if (current_vec->irq == IRQ_NOTCONNECTED) {
				selected_vec = current_vec;
				selected_vec->irq = irq;
				selected_vec->channel = channel;
				break;
			}
		}
	}
	mutex_unlock(&nic->irq_list_lock);

	EFRM_ASSERT(selected_vec);

	rc = efrm_interrupt_vector_acquire(selected_vec);

	if (rc >= 0) {
		virs->vec = selected_vec;
		spin_lock(&selected_vec->vi_irq_lock);
		list_add(&virs->irq_link, &selected_vec->vi_list);
		spin_unlock(&selected_vec->vi_irq_lock);
		/* Move the vector to the end of the list in order to
		 * discourage re-use. */
		mutex_lock(&nic->irq_list_lock);
		list_move_tail(&selected_vec->link, &nic->irq_list);
		mutex_unlock(&nic->irq_list_lock);
	}

	return rc;
}


int efrm_interrupt_vectors_ctor(struct efrm_nic *nic,
				const struct vi_resource_dimensions *res_dim)
{
	int range, index, count;
	uint32_t channel;
	struct efrm_interrupt_vector *vec;

	count = 0;
	for (range = 0; range < res_dim->irq_n_ranges; ++range)
		count += res_dim->irq_ranges[range].irq_range;

	if (count == 0) {
		nic->irq_vectors_buffer = NULL;
	}
	else {
		nic->irq_vectors_buffer = vmalloc(count * sizeof(*vec));
		if (nic->irq_vectors_buffer == NULL)
			return -ENOMEM;
	}

	vec = nic->irq_vectors_buffer;
	INIT_LIST_HEAD(&nic->irq_list);
	channel = res_dim->vi_min;
	for (range = 0; range < res_dim->irq_n_ranges; ++range) {
		for (index = 0; index < res_dim->irq_ranges[range].irq_range;
		     ++index) {
			spin_lock_init(&vec->vi_irq_lock);
			mutex_init(&vec->vec_acquire_lock);
			INIT_LIST_HEAD(&vec->vi_list);
			/* irq/channel are provided by efhw_nic_irq_alloc */
			vec->irq = IRQ_NOTCONNECTED;
			vec->channel = IRQ_NOTCONNECTED;
			vec->nic = &nic->efhw_nic;
			vec->num_vis = 0;
			list_add_tail(&vec->link, &nic->irq_list);
			++vec;
			++channel;
		}
	}

	mutex_init(&nic->irq_list_lock);

	return 0;
}


void efrm_interrupt_vectors_dtor(struct efrm_nic *nic)
{
	struct efrm_interrupt_vector *vec;
	list_for_each_entry(vec, &nic->irq_list, link)
		mutex_destroy(&vec->vec_acquire_lock);
	mutex_destroy(&nic->irq_list_lock);
	vfree(nic->irq_vectors_buffer);
}


void efrm_interrupt_vectors_release(struct efrm_nic *nic)
{
	struct efrm_interrupt_vector *vec = NULL;

	mutex_lock(&nic->irq_list_lock);
	list_for_each_entry(vec, &nic->irq_list, link) {
		mutex_lock(&vec->vec_acquire_lock);
		if (vec->num_vis > 0)
			efrm_vi_irq_free(vec);
		vec->irq = IRQ_NOTCONNECTED;
		mutex_unlock(&vec->vec_acquire_lock);
	}
	mutex_unlock(&nic->irq_list_lock);
}


static int efrm_vi_request_irq(struct efhw_nic *nic, struct efrm_vi *virs)
{
	int rc;

	rc = efrm_interrupt_vector_choose(efrm_nic(nic), virs);
	if (rc != 0) {
		EFRM_ERR("%s: Failed to assign IRQ: %d\n", __FUNCTION__, rc);
		return rc;
	}

	return 0;
}


/*** Instance numbers ****************************************************/


/* Returns -ve code on error and 0 on success. */
static int efrm_vi_set_alloc_instance_try(struct efrm_vi *virs,
					  struct efrm_vi_set* vi_set,
					  int instance)
{
	assert_spin_locked(&vi_set->allocation_lock);
	if (instance != 0xff) {
		if (instance >= vi_set->allocation.n_vis) {
			EFRM_ERR("%s: ERROR: vi_set instance=%d out-of-range "
				 "(size=%d)", __FUNCTION__, instance,
				 vi_set->allocation.n_vis);
			return -EDOM;
		}
	} else {
		if ((instance = ci_ffs64(vi_set->free) - 1) < 0) {
			EFRM_TRACE("%s: ERROR: vi_set no free members",
				  __FUNCTION__);
			return -ENOSPC;
		}
	}

	if(! (vi_set->free & ((uint64_t)1 << instance))) {
		EFRM_TRACE("%s: instance %d already allocated.", __FUNCTION__,
			   instance);
		return -EEXIST;
	}

	EFRM_ASSERT(vi_set->free & (1ULL << instance));
	vi_set->free &= ~(1ULL << instance);

	virs->allocation.instance = vi_set->allocation.instance + instance;
	virs->vi_set = vi_set;
	efrm_resource_ref(efrm_vi_set_to_resource(vi_set));
	return 0;
}


int efrm_vi_set_get_vi_instance(struct efrm_vi *virs)
{
	if( virs->vi_set == NULL )
		return -1;
	return virs->allocation.instance - virs->vi_set->allocation.instance;
}
EXPORT_SYMBOL(efrm_vi_set_get_vi_instance);


int efrm_vi_af_xdp_kick(struct efrm_vi *virs)
{
	return efhw_nic_dmaq_kick(virs->rs.rs_client->nic, virs->rs.rs_instance);
}
EXPORT_SYMBOL(efrm_vi_af_xdp_kick);


/* Try to allocate an instance out of the VIset.  If no free instances
 * and some instances are flushing, block.  Else return error.
 */
static int efrm_vi_set_alloc_instance(struct efrm_vi *virs,
				      struct efrm_vi_set* vi_set, int instance)
{
	int rc;
	while (1) {
		spin_lock(&vi_set->allocation_lock);
		rc = efrm_vi_set_alloc_instance_try(virs, vi_set, instance);
		EFRM_ASSERT(rc <= 0);
		if ((rc == -ENOSPC || rc == -EEXIST) &&
		    vi_set->n_vis_flushing > 0) {
			++vi_set->n_flushing_waiters;
			rc = 1;
		}
		spin_unlock(&vi_set->allocation_lock);
		if (rc != 1)
			return rc;
		EFRM_TRACE("%s: %d waiting for flush", __FUNCTION__,
			   current->pid);
		rc = wait_for_completion_interruptible(
			&vi_set->allocation_completion);
		spin_lock(&vi_set->allocation_lock);
		--vi_set->n_flushing_waiters;
		spin_unlock(&vi_set->allocation_lock);
		if (rc != 0)
			return rc;
	}
}


int efrm_vi_rm_alloc_instance(struct efrm_pd *pd,
                              struct efrm_vi *virs,
                              const struct vi_attr *vi_attr,
                              int print_resource_warnings)
{
	struct efrm_nic *efrm_nic;
	struct efhw_nic *efhw_nic;
	struct efrm_alloc_vi_constraints avc = {
		.channel = vi_attr->channel,
		.min_vis_in_set = 1,
		.has_rss_context = 0,
		.want_txq = vi_attr->want_txq,
	};

	efhw_nic = efrm_client_get_nic(efrm_pd_to_resource(pd)->rs_client);
	avc.efhw_nic = efhw_nic;
	efrm_nic = efrm_nic(efhw_nic);
	if (vi_attr->interrupt_core >= 0) {
		struct net_device *dev = efhw_nic_get_net_dev(&efrm_nic->efhw_nic);
		if (!dev) {
			if (print_resource_warnings) {
				EFRM_ERR("%s: ERROR: NIC was removed since pd allocation",
				         __FUNCTION__);
				return -ENETDOWN;
			}
			avc.channel = -1;
		}
		else {
			int ifindex = dev->ifindex;
			avc.channel = efrm_affinity_cpu_to_channel_dev(linux_efhw_nic(efhw_nic),
			                                          vi_attr->interrupt_core);
			dev_put(dev);
			if (avc.channel < 0 && print_resource_warnings) {
				EFRM_ERR("%s: ERROR: could not map core_id=%d using "
					"ifindex=%d", __FUNCTION__,
					(int) vi_attr->interrupt_core, ifindex);
				EFRM_ERR("%s: ERROR: Perhaps sfc_affinity is not "
					"configured?", __FUNCTION__);
				return -EINVAL;
			}
		}
	}
	virs->net_drv_wakeup_channel = avc.channel;

	if (vi_attr->vi_set != NULL)
		return efrm_vi_set_alloc_instance(virs, vi_attr->vi_set,
						  vi_attr->vi_set_instance);

	return efrm_vi_allocator_alloc_set(efrm_nic, &avc, &virs->allocation);
}


static void efrm_vi_rm_free_instance(struct efrm_client * client,
				     struct efrm_vi *virs)
{
	struct efrm_nic *nic = efrm_nic(efrm_client_get_nic(client));

	if (virs->vec != NULL) {
		struct efrm_interrupt_vector *first;

		efrm_interrupt_vector_release(virs->vec);

		spin_lock(&virs->vec->vi_irq_lock);
		list_del(&virs->irq_link);
		spin_unlock(&virs->vec->vi_irq_lock);

		mutex_lock(&nic->irq_list_lock);
		first = list_first_entry(&nic->irq_list,
					 struct efrm_interrupt_vector,
					 link);
		/* As a heuristic to promote the selection of
		 * under-utilised IRQs for subsequent VIs, move the
		 * just-released IRQ to the front of the list if and
		 * only if it is now no more heavily subscribed than
		 * the current first entry.
		 *     The num_vis fields of both vectors could be
		 * changing under our feet, but the worst that can
		 * happen as a result of that is that we make the wrong
		 * heuristic decision. */
		if (virs->vec->num_vis <= first->num_vis)
			list_move(&virs->vec->link, &nic->irq_list);
		mutex_unlock(&nic->irq_list_lock);
	}

	if (virs->vi_set != NULL) {
		struct efrm_vi_set* vi_set = virs->vi_set;
		int si = virs->allocation.instance -
			vi_set->allocation.instance;
		int need_complete;
		spin_lock(&vi_set->allocation_lock);
		EFRM_ASSERT((vi_set->free & (1ULL << si)) == 0);
		vi_set->free |= 1ULL << si;
		--vi_set->n_vis_flushing;
		need_complete = vi_set->n_flushing_waiters > 0;
		spin_unlock(&vi_set->allocation_lock);
		efrm_vi_set_release(vi_set);
		if (need_complete)
			complete(&vi_set->allocation_completion);
	}
	else {
		efrm_vi_allocator_free_set(nic, &virs->allocation);
	}
}

int efrm_vi_qid(struct efrm_vi* virs, enum efhw_q_type type)
{
	return virs->q[type].qid;
}
EXPORT_SYMBOL(efrm_vi_qid);

/*** Queue sizes *********************************************************/

static int efrm_vi_is_phys(const struct efrm_vi* virs)
{
	return efrm_pd_owner_id(virs->pd) == 0;
}


uint32_t efrm_vi_rm_evq_bytes(struct efrm_vi *virs, int n_entries)
{
	if (n_entries < 0)
		n_entries = virs->q[EFHW_EVQ].capacity;
	return n_entries * sizeof(efhw_event_t);
}
EXPORT_SYMBOL(efrm_vi_rm_evq_bytes);


static uint32_t efrm_vi_rm_txq_bytes(struct efrm_vi *virs, int n_entries)
{
	struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);
	if (nic->devtype.arch == EFHW_ARCH_EF10)
		return n_entries * EF10_DMA_TX_DESC_BYTES;
	else if (nic->devtype.arch == EFHW_ARCH_AF_XDP)
		return n_entries * EFAB_AF_XDP_DESC_BYTES;
	else if (nic->devtype.arch == EFHW_ARCH_EFCT)
		return n_entries * EFCT_TX_DESCRIPTOR_BYTES;
	else if (nic->devtype.arch == EFHW_ARCH_EF10CT)
		return n_entries * EFCT_TX_DESCRIPTOR_BYTES;
	else {
		EFRM_ASSERT(0);
		return -EINVAL;
	}
}


static uint32_t efrm_vi_rm_rxq_bytes(struct efrm_vi *virs, int n_entries)
{
	uint32_t bytes_per_desc;
	struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);

	if (nic->devtype.arch == EFHW_ARCH_EF10)
		bytes_per_desc = EF10_DMA_RX_DESC_BYTES;
	else if (nic->devtype.arch == EFHW_ARCH_AF_XDP)
		bytes_per_desc = EFAB_AF_XDP_DESC_BYTES;
	else if (nic->devtype.arch == EFHW_ARCH_EFCT)
		return EFCT_RX_DESCRIPTOR_BYTES * CI_EFCT_MAX_SUPERBUFS *
		       EF_VI_MAX_EFCT_RXQS;
	else if (nic->devtype.arch == EFHW_ARCH_EF10CT)
		return EFCT_RX_DESCRIPTOR_BYTES * CI_EFCT_MAX_SUPERBUFS *
		       EF_VI_MAX_EFCT_RXQS;
	else {
		EFRM_ASSERT(0);	
		return -EINVAL;
	}
	return n_entries * bytes_per_desc;
}


static int efrm_vi_q_bytes(struct efrm_vi *virs, enum efhw_q_type q_type,
			   int n_entries)
{
	switch (q_type) {
	case EFHW_TXQ:
		return efrm_vi_rm_txq_bytes(virs, n_entries);
	case EFHW_RXQ:
		return efrm_vi_rm_rxq_bytes(virs, n_entries);
	case EFHW_EVQ:
		return efrm_vi_rm_evq_bytes(virs, n_entries);
	default:
		return -EINVAL;
	}
}


int efrm_vi_n_q_entries(int size_rq, unsigned sizes)
{
	int size;

	/* size_rq < 0 means default, but we interpret this as 'minimum'. */

	for (size = 256;; size <<= 1)
		if ((size & sizes) && size >= size_rq)
			return size;
		else if ((sizes & ~((size - 1) | size)) == 0)
			return -1;
		else if (size == 1 << 30)
			return -1;
}
EXPORT_SYMBOL(efrm_vi_n_q_entries);


/*************************************************************************/

static void efrm_vi_attach_evq(struct efrm_vi *virs, enum efhw_q_type q_type,
			       struct efrm_vi *evq)
{
	EFRM_ASSERT(evq != NULL);
	EFRM_ASSERT(atomic_read(&evq->evq_refs) != 0);
	EFRM_ASSERT(virs->q[q_type].evq_ref == NULL);
	virs->q[q_type].evq_ref = evq;
	if (evq != virs)
		efrm_vi_rm_get_ref(evq);
}


static void efrm_vi_detach_evq(struct efrm_vi *virs, enum efhw_q_type q_type)
{
	struct efrm_vi *evq = virs->q[q_type].evq_ref;
	virs->q[q_type].evq_ref = NULL;
	if (evq != NULL && evq != virs)
		efrm_vi_rm_drop_ref(evq);
}


/*************************************************************************/

static unsigned q_flags_to_vi_flags(unsigned q_flags, enum efhw_q_type q_type)
{
	unsigned vi_flags = 0;

	switch (q_type) {
	case EFHW_TXQ:
		if (!(q_flags & EFRM_VI_IP_CSUM))
			vi_flags |= EFHW_VI_TX_IP_CSUM_DIS;
		if (!(q_flags & EFRM_VI_TCP_UDP_CSUM))
			vi_flags |= EFHW_VI_TX_TCPUDP_CSUM_DIS;
		if (q_flags & EFRM_VI_ETH_FILTER)
			vi_flags |= EFHW_VI_TX_ETH_FILTER_EN;
		if (q_flags & EFRM_VI_TCP_UDP_FILTER)
			vi_flags |= EFHW_VI_TX_IP_FILTER_EN;
		if (q_flags & EFRM_VI_TX_TIMESTAMPS)
			vi_flags |= EFHW_VI_TX_TIMESTAMPS;
		if (q_flags & EFRM_VI_TX_LOOPBACK)
			vi_flags |= EFHW_VI_TX_LOOPBACK;
		if (q_flags & EFRM_VI_TX_CTPIO)
			vi_flags |= EFHW_VI_TX_CTPIO;
		if (q_flags & EFRM_VI_TX_CTPIO_NO_POISON)
			vi_flags |= EFHW_VI_TX_CTPIO_NO_POISON;
		break;
	case EFHW_RXQ:
		if (!(q_flags & EFRM_VI_CONTIGUOUS))
			vi_flags |= EFHW_VI_JUMBO_EN;
		if (q_flags & EFRM_VI_RX_TIMESTAMPS)
			vi_flags |= EFHW_VI_RX_PREFIX | EFHW_VI_RX_TIMESTAMPS;
		if (q_flags & EFRM_VI_RX_LOOPBACK)
			vi_flags |= EFHW_VI_RX_LOOPBACK;
		if (q_flags & EFRM_VI_RX_PACKED_STREAM)
			vi_flags |= EFHW_VI_RX_PACKED_STREAM;
		if (q_flags & EFRM_VI_RX_PREFIX)
			vi_flags |= EFHW_VI_RX_PREFIX;
		if (q_flags & EFRM_VI_NO_RX_CUT_THROUGH)
			vi_flags |= EFHW_VI_NO_RX_CUT_THROUGH;
		if (q_flags & EFRM_VI_RX_ZEROCOPY)
			vi_flags |= EFHW_VI_RX_ZEROCOPY;
		if (q_flags & EFRM_VI_ENABLE_TPH)
			vi_flags |= EFHW_VI_ENABLE_TPH;
		if (q_flags & EFRM_VI_TPH_TAG_MODE)
			vi_flags |= EFHW_VI_TPH_TAG_MODE;
		break;
	case EFHW_EVQ:
		if (q_flags & EFRM_VI_RX_TIMESTAMPS)
			vi_flags |= EFHW_VI_RX_TIMESTAMPS;
		if (q_flags & EFRM_VI_TX_TIMESTAMPS)
			vi_flags |= EFHW_VI_TX_TIMESTAMPS;
		if (q_flags & EFRM_VI_NO_EV_CUT_THROUGH)
			vi_flags |= EFHW_VI_NO_EV_CUT_THROUGH;
		if (q_flags & EFRM_VI_RX_PACKED_STREAM)
			vi_flags |= EFHW_VI_RX_PACKED_STREAM;
		if (q_flags & EFRM_VI_ENABLE_RX_MERGE)
			vi_flags |= EFHW_VI_ENABLE_RX_MERGE;
		if (q_flags & EFRM_VI_ENABLE_EV_TIMER)
			vi_flags |= EFHW_VI_ENABLE_EV_TIMER;
		break;
	default:
		break;
	}

	return vi_flags;
}


static unsigned vi_flags_to_q_flags(unsigned vi_flags, enum efhw_q_type q_type)
{
	unsigned q_flags = 0;

	switch (q_type) {
	case EFHW_TXQ:
		if (!(vi_flags & EFHW_VI_TX_IP_CSUM_DIS))
			q_flags |= EFRM_VI_IP_CSUM;
		if (!(vi_flags & EFHW_VI_TX_TCPUDP_CSUM_DIS))
			q_flags |= EFRM_VI_TCP_UDP_CSUM;
		if (vi_flags & EFHW_VI_TX_ETH_FILTER_EN)
			q_flags |= EFRM_VI_ETH_FILTER;
		if (vi_flags & EFHW_VI_TX_IP_FILTER_EN)
			q_flags |= EFRM_VI_TCP_UDP_FILTER;
		if (vi_flags & EFHW_VI_TX_TIMESTAMPS)
			q_flags |= EFRM_VI_TX_TIMESTAMPS;
		if (vi_flags & EFHW_VI_TX_LOOPBACK)
			q_flags |= EFRM_VI_TX_LOOPBACK;
		if (vi_flags & EFHW_VI_TX_CTPIO)
			q_flags |= EFRM_VI_TX_CTPIO;
		if (vi_flags & EFHW_VI_TX_CTPIO_NO_POISON)
			q_flags |= EFRM_VI_TX_CTPIO_NO_POISON;
		break;
	case EFHW_RXQ:
		if (!(vi_flags & EFHW_VI_JUMBO_EN))
			q_flags |= EFRM_VI_CONTIGUOUS;
		if (vi_flags & EFHW_VI_RX_TIMESTAMPS)
			q_flags |= EFRM_VI_RX_TIMESTAMPS;
		if (vi_flags & EFHW_VI_RX_LOOPBACK)
			q_flags |= EFRM_VI_RX_LOOPBACK;
		if (vi_flags & EFHW_VI_RX_PACKED_STREAM)
			q_flags |= EFRM_VI_RX_PACKED_STREAM;
		if (vi_flags & EFHW_VI_RX_PREFIX)
			q_flags |= EFRM_VI_RX_PREFIX;
		if (vi_flags & EFHW_VI_NO_RX_CUT_THROUGH)
			q_flags |= EFRM_VI_NO_RX_CUT_THROUGH;
		if (vi_flags & EFHW_VI_RX_ZEROCOPY)
			q_flags |= EFRM_VI_RX_ZEROCOPY;
		if (vi_flags & EFHW_VI_ENABLE_TPH)
			q_flags |= EFRM_VI_ENABLE_TPH;
		if (vi_flags & EFHW_VI_TPH_TAG_MODE)
			q_flags |= EFRM_VI_TPH_TAG_MODE;
		break;
	case EFHW_EVQ:
		if (vi_flags & EFHW_VI_RX_TIMESTAMPS)
			q_flags |= EFRM_VI_RX_TIMESTAMPS;
		if (vi_flags & EFHW_VI_TX_TIMESTAMPS)
			q_flags |= EFRM_VI_TX_TIMESTAMPS;
		if (vi_flags & EFHW_VI_NO_EV_CUT_THROUGH)
			q_flags |= EFRM_VI_NO_EV_CUT_THROUGH;
		if (vi_flags & EFHW_VI_RX_PACKED_STREAM)
			q_flags |= EFRM_VI_RX_PACKED_STREAM;
		if (vi_flags & EFHW_VI_ENABLE_RX_MERGE)
			q_flags |= EFRM_VI_ENABLE_RX_MERGE;
		if (vi_flags & EFHW_VI_ENABLE_EV_TIMER)
			q_flags |= EFRM_VI_ENABLE_EV_TIMER;
		break;
	default:
		break;
	}

	return q_flags;
}


/*** Per-NIC allocations *************************************************/

int
efrm_vi_rm_init_dmaq(struct efrm_vi *virs, enum efhw_q_type queue_type,
		     struct efhw_nic *nic)
{
	int rc = 0;
	struct efrm_vi_q *q = virs->q + queue_type;
	struct efrm_nic* efrm_nic;
	int instance, evq_instance = -1;
	uint qid = -1;
	unsigned flags = virs->flags;
	unsigned vport_id;
	struct efhw_evq_params evq_params = {};
	struct efhw_dmaq_params q_params = {};

	vport_id = efrm_pd_get_vport_id(virs->pd);

	efrm_nic = efrm_nic(nic);

	mutex_lock(&efrm_nic->dmaq_state.lock);

	if( efrm_nic->dmaq_state.unplugging ) {
		mutex_unlock(&efrm_nic->dmaq_state.lock);
		return -ENETDOWN;
	}

	instance = virs->rs.rs_instance;

	if (efrm_vi_is_phys(virs))
		flags |= EFHW_VI_TX_PHYS_ADDR_EN | EFHW_VI_RX_PHYS_ADDR_EN;

	if (queue_type == EFHW_TXQ || queue_type == EFHW_RXQ) {
		evq_instance = q->evq_ref->rs.rs_instance;
		q_params.dmaq = instance;
		q_params.evq = evq_instance;
		q_params.owner = efrm_pd_owner_id(virs->pd);
		q_params.tag = virs->q[queue_type].tag;
		q_params.dmaq_size = q->capacity;
		q_params.dma_addrs = q->dma_addrs;
		q_params.n_dma_addrs =
			(1 << q->host_page_order) * EFHW_NIC_PAGES_IN_OS_PAGE;
		q_params.vport_id = vport_id;
		q_params.stack_id = efrm_pd_stack_id_get(virs->pd);
		q_params.flags = flags;
	}

	switch (queue_type) {
	case EFHW_TXQ:
		rc = efhw_nic_dmaq_tx_q_init(nic, &q_params);
		qid = q_params.qid_out;
		break;
	case EFHW_RXQ:
		q_params.rx.ps_buf_size = virs->ps_buf_size;
		/* TODO: How do we determine this? */
		q_params.rx.suppress_events = true;
		rc = efhw_nic_dmaq_rx_q_init(nic, &q_params);
		if( rc >= 0 ) {
			virs->rx_prefix_len = rc;
			rc = 0;
		}
		qid = q_params.qid_out;
		break;
	case EFHW_EVQ:
		qid = instance;
		evq_params.evq = instance;
		evq_params.evq_size = q->capacity;
		evq_params.dma_addrs = q->dma_addrs;
		evq_params.virt_base = q->host_pages.ptr;
		evq_params.n_pages = (1 << q->host_page_order) *
					EFHW_NIC_PAGES_IN_OS_PAGE;
		evq_params.flags = flags;

		evq_params.wakeup_channel = efrm_vi_get_channel(virs);
		EFRM_ASSERT(!!(nic->flags & NIC_FLAG_EVQ_IRQ) ==
			    !!(virs->vec != NULL));

		rc = efhw_nic_event_queue_enable(nic, &evq_params);
		if( rc == 0 )
			virs->out_flags = evq_params.flags_out;
		break;
	default:
		EFRM_ASSERT(0);
		break;
	}

	/* Here we violate the usual principle that we should not change our
	 * behaviour as a direct consequence of the resetting state.  However,
	 * we need to detect failure to allocate a queue, and, since some of
	 * the MCDI operations have an outlen of zero, they will appear to
	 * succeed even while a reset is pending.  We check this *after*
	 * attempting the MCDI call to avoid a race against the flag being set
	 * between the check and the call. */
	if (nic->resetting)
		rc = -ENETDOWN;

	if( ! list_empty(&q->init_link) ) {
		/* TODO assertion instead */
		EFRM_WARN("Double initialized queue "
			  "nic %d type %d 0x%x (evq 0x%x) rc %d",
			  nic->index, queue_type, instance, evq_instance, rc);
	} else {
		if( rc == 0 ) {
			q->qid = qid;
			list_add_tail(&q->init_link,
				      &efrm_nic->dmaq_state.q[queue_type]);
		}
	}

	mutex_unlock(&efrm_nic->dmaq_state.lock);

	return rc;
}


static void
efrm_vi_rm_fini_dmaq(struct efrm_vi *virs, enum efhw_q_type queue_type)
{
	struct efrm_vi_q *q = &virs->q[queue_type];

	if (q->capacity == 0)
		return;

	switch (queue_type) {
	case EFHW_EVQ:
		if (~atomic_read(&virs->shut_down_flags) & EFRM_VI_SHUT_DOWN_EVQ)
                        efrm_vi_q_flush(virs, queue_type);
		break;
	default:
		break;
	}

	/* NB. No need to disable DMA queues here.  Nobody is using it
	 * anyway.
	 */
	if (efhw_iopages_n_pages(&q->host_pages)) {
		struct efhw_nic* nic = virs->rs.rs_client->nic;
		efhw_iopages_free(nic, &q->host_pages);
	}
}


static int
efrm_vi_io_map(struct efrm_vi* virs, struct efhw_nic *nic, int instance)
{
	resource_size_t addr;
	size_t io_size;

	int rc = efhw_nic_vi_io_region(nic, instance, &io_size, &addr);
	if (rc == 0 && io_size > 0)  {
		virs->io_page = ci_ioremap(addr, io_size);
		if (virs->io_page == NULL)
			return -ENOMEM;
	}

	return rc;
}


static void
efrm_vi_io_unmap(struct efrm_vi* virs, struct efhw_nic* nic)
{
	if (virs->io_page)
		iounmap(virs->io_page);
}


/* Marks all queues as having been shut down. */
void
efrm_vi_resource_mark_shut_down(struct efrm_vi *virs)
{
	struct efhw_nic* nic = virs->rs.rs_client->nic;
	struct efrm_nic* efrm_nic = efrm_nic(nic);
	int type;

	mutex_lock(&efrm_nic->dmaq_state.lock);

	/* We should not attempt to flush these queues, so remove them from the
	 * requiring-flush lists. */
	for (type = 0; type < EFHW_N_Q_TYPES; ++type) {
		struct efrm_vi_q *q = &virs->q[type];
		if (! list_empty(&q->init_link) ) {
			list_del(&q->init_link);
			INIT_LIST_HEAD(&q->init_link);
		}
	}

	efrm_atomic_or(EFRM_VI_SHUT_DOWN, &virs->shut_down_flags);

	mutex_unlock(&efrm_nic->dmaq_state.lock);
}
EXPORT_SYMBOL(efrm_vi_resource_mark_shut_down);


static int
efrm_vi_evq_id(struct efrm_vi *virs, enum efhw_q_type queue_type)
{
	struct efrm_vi *evq;

	if( queue_type != EFHW_EVQ )
		evq = virs->q[queue_type].evq_ref;
	else
		evq = virs;

	return evq->q[EFHW_EVQ].qid;
}


static void efrm_init_debugfs_vi(struct efrm_vi *virs)
{
#ifdef CONFIG_DEBUG_FS
	/* Currently only need vi debugfs folders to hold efct queues
	 * Avoid creating others to avoid empty folder clutter */
	if (virs->efct_shm) {
		struct efrm_resource *rs = &virs->rs;
		efrm_debugfs_add_rs(rs, NULL, rs->rs_instance);
	}
	/* VI resource doesn't currently have debugfs files */
#endif
}


static void efrm_fini_debugfs_vi(struct efrm_vi *virs)
{
#ifdef CONFIG_DEBUG_FS
	efrm_debugfs_remove_rs(&virs->rs);
#endif
}


static int
__efrm_vi_q_flush(struct efhw_nic* nic, struct efrm_vi* virs,
		  enum efhw_q_type queue_type)
{
	int rc;
	struct efrm_vi_q *q = &virs->q[queue_type];
	int evq = efrm_vi_evq_id(virs, queue_type);

	switch (queue_type) {
	case EFHW_RXQ:
		rc = efhw_nic_flush_rx_dma_channel(nic, q->qid);
		break;
	case EFHW_TXQ:
		rc = efhw_nic_flush_tx_dma_channel(nic, q->qid, evq);
		break;
	case EFHW_EVQ:
		{
			int time_sync_events_enabled =
				efhw_nic_evq_requires_time_sync(nic,
								virs->flags);
			/* flushing EVQ is as good as disabling it */
			efhw_nic_event_queue_disable(nic, q->qid,
						     time_sync_events_enabled);
		}
		rc = 0;
		break;
	default:
		EFRM_ASSERT(0);
		rc = -EINVAL;
	};
	return rc;
}


static int
efrm_vi_q_flush_state(struct efrm_vi *virs, enum efhw_q_type queue_type)
{
	struct efrm_vi_q *q = &virs->q[queue_type];
#ifndef NDEBUG
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	struct efrm_nic* efrm_nic = efrm_nic(nic);
#endif

	EFRM_ASSERT(mutex_is_locked(&efrm_nic->dmaq_state.lock));

	if( list_empty(&q->init_link) ) {
		EFRM_TRACE("Queue already flushed nic %d type %d 0x%x(0x%x)",
			   nic->index, queue_type, virs->rs.rs_instance,
			   q->qid);
		return -EALREADY;
	} else {
		list_del(&q->init_link);
		INIT_LIST_HEAD(&q->init_link);
	}

	return 0;
}


int
efrm_vi_q_flush(struct efrm_vi *virs, enum efhw_q_type queue_type)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
#ifndef NDEBUG
	struct efrm_vi_q *q = &virs->q[queue_type];
#endif
	struct efrm_nic* efrm_nic = efrm_nic(nic);
	int rc = 0;

	mutex_lock(&efrm_nic->dmaq_state.lock);

	rc = efrm_vi_q_flush_state(virs, queue_type);
	if( rc < 0 )
		goto unlock_out;

	rc = __efrm_vi_q_flush(nic, virs, queue_type);
	EFRM_TRACE("Flushed queue nic %d type %d 0x%x(0x%x) rc %d",
		  nic->index, queue_type, virs->rs.rs_instance, q->qid, rc);

unlock_out:
	mutex_unlock(&efrm_nic->dmaq_state.lock);
	return rc;
}
EXPORT_SYMBOL(efrm_vi_q_flush);


static void
__efrm_vi_resource_free(struct efrm_vi *virs)
{
	struct efrm_nic *efrm_nic;
	int instance;
	int rc;

	EFRM_ASSERT(efrm_vi_manager);
	EFRM_RESOURCE_MANAGER_ASSERT_VALID(&efrm_vi_manager->rm);
	EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 1);

	efrm_nic = efrm_nic(virs->rs.rs_client->nic);
	instance = virs->rs.rs_instance;

	EFRM_TRACE("%s: Freeing %d", __FUNCTION__, instance);
	EFRM_ASSERT(atomic_read(&virs->evq_refs) == 0);
	EFRM_ASSERT(virs->evq_callback_fn == NULL);
	EFRM_ASSERT(virs->q[EFHW_TXQ].evq_ref == NULL);
	EFRM_ASSERT(virs->q[EFHW_RXQ].evq_ref == NULL);

	if (virs->tx_alt_num) {
		struct efhw_nic *nic = &(efrm_nic->efhw_nic);
		nic->efhw_func->tx_alt_free(nic, virs->tx_alt_num,
					    virs->tx_alt_cp, virs->tx_alt_ids);
	}
	if (virs->pio != NULL) {
		/* Unlink also manages reference accounting.  We don't need to
		 * worry about whether this actually freed the buffer: other
		 * callers need to clean up the resource-table if so, to
		 * prevent double-frees, but the fact that the VI is going away
		 * is sufficient to guarantee this anyway, so we can pass NULL
		 * for the last parameter. */
		rc = efrm_pio_unlink_vi(virs->pio, virs, NULL);
		if (rc < 0)
			/* If txq has been flushed already, this can
			 * fail benignly */
			if (rc != -EALREADY)
				EFRM_ERR("%s: efrm_pio_unlink_vi failed: %d.\n",
					 __FUNCTION__, rc);
	}
	efrm_vi_rm_fini_dmaq(virs, EFHW_RXQ);
	efrm_vi_rm_fini_dmaq(virs, EFHW_TXQ);
	efrm_vi_rm_fini_dmaq(virs, EFHW_EVQ);
	efrm_vi_detach_evq(virs, EFHW_RXQ);
	efrm_vi_detach_evq(virs, EFHW_TXQ);
	efrm_vi_io_unmap(virs, &efrm_nic->efhw_nic);
	vfree(virs->efct_shm);
	efrm_vi_rm_free_instance(virs->rs.rs_client, virs);
	efrm_pd_release(virs->pd);
	efrm_fini_debugfs_vi(virs);
	efrm_client_put(virs->rs.rs_client);
	EFRM_DO_DEBUG(memset(virs, 0, sizeof(*virs)));
	kfree(virs);
}


void efrm_nic_flush_all_queues(struct efhw_nic *nic, int flags)
{
	int type;
	struct efrm_nic *efrm_nic = efrm_nic_from_efhw_nic(nic);

	mutex_lock(&efrm_nic->dmaq_state.lock);
	if (!(flags & EFRM_FLUSH_QUEUES_F_NO_HW))
		efrm_nic->dmaq_state.unplugging = 1;
	EFRM_TRACE(" Flushing all queues for nic %d flags %x", nic->index, flags);
	for (type = 0; type < EFHW_N_Q_TYPES; ++type) {
		while (!list_empty(&efrm_nic->dmaq_state.q[type])) {
			struct list_head *h = list_pop(&efrm_nic->dmaq_state.q[type]);
			struct efrm_vi *virs;
			int rc;
			virs = list_entry(h, struct efrm_vi, q[type].init_link);
			INIT_LIST_HEAD(&virs->q[type].init_link);
			if (flags & EFRM_FLUSH_QUEUES_F_INJECT_EV && type == EFHW_EVQ &&
			    virs->ep_state) {
				rc = efhw_nic_inject_reset_ev(nic,
				                             virs->q[EFHW_EVQ].host_pages.ptr,
				                             virs->q[EFHW_EVQ].capacity,
				                             &virs->ep_state->evq.evq_ptr);
				if( rc )
					EFRM_ERR(" nic %d 0x%x ef_vi reset not supported (%d)",
					         nic->index, virs->rs.rs_instance, rc);
			}
			if (flags & EFRM_FLUSH_QUEUES_F_NO_HW)
				continue;
			efrm_atomic_or(efrm_vi_shut_down_flag(type), &virs->shut_down_flags);
			rc = __efrm_vi_q_flush(virs->rs.rs_client->nic,
					       virs, type);
			(void) rc;
			EFRM_TRACE(" nic %d type %d 0x%x rc %d",
				nic->index, type, virs->rs.rs_instance, rc);
		}
	}
	mutex_unlock(&efrm_nic->dmaq_state.lock);
}
EXPORT_SYMBOL(efrm_nic_flush_all_queues);


/*** Resource object  ****************************************************/

int
efrm_vi_q_alloc_sanitize_size(struct efrm_vi *virs, enum efhw_q_type q_type,
			      int n_q_entries)
{
	struct efrm_vi_q_size qsize;
	if (n_q_entries == 0)
		return 0;
	if (n_q_entries < 0)
		n_q_entries = 1;
	if (efrm_vi_q_get_size(virs, q_type, n_q_entries, &qsize) < 0) {
		EFRM_ERR("%s: ERROR: bad %s size %d (supported=%x)",
			 __FUNCTION__, q_names[q_type], n_q_entries,
			 virs->rs.rs_client->nic->q_sizes[q_type]);
		return -EINVAL;
	}
	return qsize.q_len_entries;
}
EXPORT_SYMBOL(efrm_vi_q_alloc_sanitize_size);


int
efrm_vi_q_alloc(struct efrm_vi *virs, enum efhw_q_type q_type,
		int n_q_entries, int q_tag_in, unsigned vi_flags,
		struct efrm_vi *evq)
{
	struct efrm_vi_q *q = &virs->q[q_type];
	struct efrm_vi_q_size qsize;
	int rc, q_flags;
	unsigned long iova_base = 0;
	struct efhw_nic* nic = virs->rs.rs_client->nic;

	if (n_q_entries == 0)
		return 0;
	if (n_q_entries < 0)
		n_q_entries = 1;
	if (efrm_vi_q_get_size(virs, q_type, n_q_entries, &qsize) < 0) {
		EFRM_ERR("%s: ERROR: bad %s size %d (supported=%x)",
			 __FUNCTION__, q_names[q_type], n_q_entries,
			 virs->rs.rs_client->nic->q_sizes[q_type]);
		return -EINVAL;
	}
	if (evq != NULL) {
		if (virs->rs.rs_client != evq->rs.rs_client) {
			EFRM_ERR("%s: ERROR: %s on %d but EVQ on %d",
				 __FUNCTION__, q_names[q_type],
				 efrm_client_get_ifindex(virs->rs.rs_client),
				 efrm_client_get_ifindex(evq->rs.rs_client));
			return -EINVAL;
		}
	}

	/* AF_XDP interfaces provide their own queue memory.
	 * We will acquire it later, after initialising the packet
	 * buffer memory.
	 */
	if (nic->devtype.arch != EFHW_ARCH_AF_XDP) {
		rc = efhw_iopages_alloc(nic, &q->host_pages,
					qsize.q_len_page_order,
					efhw_nic_phys_contig_queue(nic, q_type),
					iova_base);
		if (rc < 0) {
			EFRM_ERR("%s: Failed to allocate %s DMA buffer",
				 __FUNCTION__, q_names[q_type]);
			return rc;
		}
		q->host_page_order = qsize.q_len_page_order;
		if (q_type == EFHW_EVQ)
			memset(efhw_iopages_ptr(&q->host_pages), EFHW_CLEAR_EVENT_VALUE,
			       qsize.q_len_bytes);

		rc = efhw_page_map_add_pages(&virs->mem_mmap, &q->host_pages);
		if (rc < 0)
			goto fail;
	}

	q_flags = vi_flags_to_q_flags(vi_flags, q_type);

	INIT_LIST_HEAD(&q->init_link);
	rc = efrm_vi_q_init(virs, q_type, qsize.q_len_entries, q_tag_in,
			    q_flags, evq);
	if (rc < 0)
		goto fail;

	return rc;

fail:
	efhw_iopages_free(nic, &q->host_pages);
	return rc;
}
EXPORT_SYMBOL(efrm_vi_q_alloc);


/* This function must always be called with pd != NULL.
 *
 * If this function is called with vi_set != NULL, then pd must be
 * what is returned from efrm_vi_set_get_pd().
 */
int
efrm_vi_resource_alloc(struct efrm_client *client,
		       struct efrm_vi *evq_virs,
		       struct efrm_vi_set *vi_set, int vi_set_instance,
		       struct efrm_pd *pd, const char *name,
		       unsigned vi_flags,
		       int evq_capacity, int txq_capacity, int rxq_capacity,
		       int tx_q_tag, int rx_q_tag, int wakeup_cpu_core,
		       int wakeup_channel,
		       struct efrm_vi **virs_out,
		       uint32_t *out_io_mmap_bytes,
		       uint32_t *out_ctpio_mmap_bytes,
		       uint32_t *out_txq_capacity,
		       uint32_t *out_rxq_capacity,
		       int print_resource_warnings)
{
	struct efrm_vi_attr attr;
	struct efrm_vi *virs;
	unsigned ctpio_mmap_bytes = 0;
	int rc;
	size_t io_size;
	resource_size_t io_addr;

	EFRM_ASSERT(pd != NULL);
	efrm_vi_attr_init(&attr);
	if (vi_set != NULL)
		efrm_vi_attr_set_instance(&attr, vi_set, vi_set_instance);
	efrm_vi_attr_set_pd(&attr, pd);
	if (wakeup_cpu_core >= 0)
		efrm_vi_attr_set_interrupt_core(&attr, wakeup_cpu_core);
	if (wakeup_channel >= 0)
		efrm_vi_attr_set_wakeup_channel(&attr, wakeup_channel);
	if (evq_virs == NULL)
		efrm_vi_attr_set_want_interrupt(&attr);
	efrm_vi_attr_set_queue_types(&attr, rxq_capacity != 0,
	                             txq_capacity != 0);

	if ((rc = efrm_vi_alloc(client, &attr, print_resource_warnings,
				name, &virs)) < 0)
		goto fail_vi_alloc;

	/* We have to jump through some hoops here:
	 * - EF10 needs the event queue allocated before rx and tx queues
	 * - Event queue needs to know the size of the rx and tx queues
	 *
	 * So we first work out the sizes, then create the evq, then create
	 * the rx and tx queues.
	 */

	rc = efrm_vi_q_alloc_sanitize_size(virs, EFHW_TXQ, txq_capacity);
	if (rc < 0)
		goto fail_q_alloc;
	txq_capacity = rc;

	rc = efrm_vi_q_alloc_sanitize_size(virs, EFHW_RXQ, rxq_capacity);
	if (rc < 0)
		goto fail_q_alloc;
	rxq_capacity = rc;

	if (evq_virs == NULL) {
		if (evq_capacity < 0)
			evq_capacity = rxq_capacity + txq_capacity;

		/* TODO AF_XDP: allocation order must match the order that
	 	* ef_vi expects the queues to be mapped into user memory. */
		if ((rc = efrm_vi_q_alloc(virs, EFHW_EVQ, evq_capacity,
				  	  0, vi_flags, NULL)) < 0)
			goto fail_q_alloc;
	}
	if ((rc = efrm_vi_q_alloc(virs, EFHW_RXQ, rxq_capacity,
				  rx_q_tag, vi_flags, evq_virs)) < 0)
		goto fail_q_alloc;
	if ((rc = efrm_vi_q_alloc(virs, EFHW_TXQ, txq_capacity,
				  tx_q_tag, vi_flags, evq_virs)) < 0)
		goto fail_q_alloc;

	if( vi_flags & EFHW_VI_TX_CTPIO )
		ctpio_mmap_bytes = EF_VI_CTPIO_APERTURE_SIZE;

	if (out_io_mmap_bytes != NULL) {
		rc = efhw_nic_vi_io_region(client->nic,
					evq_virs ? evq_virs->rs.rs_instance :
						   virs->rs.rs_instance,
					&io_size, &io_addr);
		if (rc == 0)
			*out_io_mmap_bytes = io_size;
		else
			goto fail_q_alloc;
	}
	if (out_ctpio_mmap_bytes != NULL)
		*out_ctpio_mmap_bytes = ctpio_mmap_bytes;
	if (out_txq_capacity != NULL)
		*out_txq_capacity = virs->q[EFHW_TXQ].capacity;
	if (out_rxq_capacity != NULL)
		*out_rxq_capacity = virs->q[EFHW_RXQ].capacity;

	*virs_out = virs;
	return 0;


fail_q_alloc:
	efrm_vi_resource_release(virs);
fail_vi_alloc:
	return rc;
}
EXPORT_SYMBOL(efrm_vi_resource_alloc);


int
efrm_vi_resource_deferred(struct efrm_vi *virs, int chunk_size, int headroom,
                          uint32_t *out_mem_mmap_bytes)
{
	int rc;
	struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);

	rc = efhw_nic_af_xdp_init(nic, virs->allocation.instance,
	                          chunk_size, headroom, &virs->mem_mmap);
	if (rc < 0)
		return rc;

	if (out_mem_mmap_bytes != NULL)
		*out_mem_mmap_bytes = efhw_page_map_bytes(&virs->mem_mmap);

	return 0;
}
EXPORT_SYMBOL(efrm_vi_resource_deferred);


void efrm_vi_rm_free_flushed_resource(struct efrm_vi *virs)
{
	EFRM_ASSERT(virs != NULL);
	EFRM_ASSERT(virs->rs.rs_ref_count == 0);

	EFRM_TRACE("%s: " EFRM_RESOURCE_FMT, __FUNCTION__,
		   EFRM_RESOURCE_PRI_ARG(&virs->rs));
	/* release the associated event queue then drop our own reference
	 * count */
	efrm_vi_detach_evq(virs, EFHW_RXQ);
	efrm_vi_detach_evq(virs, EFHW_TXQ);
	efrm_vi_rm_drop_ref(virs);
}


/**********************************************************************
 * The new interface...
 */

int __efrm_vi_attr_init(struct efrm_client *client_obsolete,
			struct efrm_vi_attr *attr, int attr_size)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	if (attr_size < sizeof(struct vi_attr)) {
		EFRM_ERR("efrm_vi_attr_init: Interface mismatch (%d %d)",
			 attr_size, (int) sizeof(struct vi_attr));
		return -EINVAL;
	}
	a->pd = NULL;
	a->vi_set = NULL;
	a->interrupt_core = -1;
	a->channel = -1;
	a->want_interrupt = false;
	a->packed_stream = 0;
	a->want_rxq = true;
	a->want_txq = true;
	return 0;
}
EXPORT_SYMBOL(__efrm_vi_attr_init);


void efrm_vi_attr_set_pd(struct efrm_vi_attr *attr, struct efrm_pd *pd)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->pd = pd;
}
EXPORT_SYMBOL(efrm_vi_attr_set_pd);


void efrm_vi_attr_set_packed_stream(struct efrm_vi_attr *attr,
				    int packed_stream)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->packed_stream = packed_stream;
}
EXPORT_SYMBOL(efrm_vi_attr_set_packed_stream);


void efrm_vi_attr_set_ps_buffer_size(struct efrm_vi_attr *attr,
				     int ps_buffer_size)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->ps_buffer_size = ps_buffer_size;
}
EXPORT_SYMBOL(efrm_vi_attr_set_ps_buffer_size);


void efrm_vi_attr_set_instance(struct efrm_vi_attr *attr,
			       struct efrm_vi_set *vi_set,
			       int instance_in_set)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->vi_set = vi_set;
	if (instance_in_set < 0)
		a->vi_set_instance = 0xff;
	else if (instance_in_set <= 0xfe)
		a->vi_set_instance = instance_in_set;
	else
		/* Ensure we provoke EDOM when we attempt to allocate.
		 * This field is a u8, and 0xff means "any".  So 0xfe is
		 * largest value interpreted as an instance num.
		 */
		a->vi_set_instance = 0xfe;
}
EXPORT_SYMBOL(efrm_vi_attr_set_instance);


void efrm_vi_attr_set_interrupt_core(struct efrm_vi_attr *attr, int core_id)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->interrupt_core = core_id;
}
EXPORT_SYMBOL(efrm_vi_attr_set_interrupt_core);


void efrm_vi_attr_set_wakeup_channel(struct efrm_vi_attr *attr, int channel_id)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->channel = channel_id;
}
EXPORT_SYMBOL(efrm_vi_attr_set_wakeup_channel);


void efrm_vi_attr_set_want_interrupt(struct efrm_vi_attr *attr)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->want_interrupt = true;
}
EXPORT_SYMBOL(efrm_vi_attr_set_want_interrupt);


void efrm_vi_attr_set_queue_types(struct efrm_vi_attr *attr, bool want_rxq,
                                  bool want_txq)
{
	struct vi_attr *a = VI_ATTR_FROM_O_ATTR(attr);
	a->want_rxq = want_rxq;
	a->want_txq = want_txq;
}
EXPORT_SYMBOL(efrm_vi_attr_set_queue_types);


static size_t efrm_vi_get_efct_shm_bytes_nrxq(struct efrm_vi *vi,
                                              size_t n_shm_rxqs)
{
	return CI_ROUND_UP(CI_EFCT_SHM_BYTES(n_shm_rxqs), PAGE_SIZE);
}


size_t efrm_vi_get_efct_shm_bytes(struct efrm_vi *vi)
{
	size_t n_shm_rxqs = efhw_nic_max_shared_rxqs(
	                                    efrm_client_get_nic(vi->rs.rs_client));
	return efrm_vi_get_efct_shm_bytes_nrxq(vi, n_shm_rxqs);
}
EXPORT_SYMBOL(efrm_vi_get_efct_shm_bytes);


int  efrm_vi_alloc(struct efrm_client *client,
		   const struct efrm_vi_attr *o_attr,
		   int print_resource_warnings,
		   const char *vi_name,
		   struct efrm_vi **p_virs_out)
{
	struct efrm_vi_attr s_attr;
	struct efrm_vi *virs;
	struct vi_attr *attr;
	int rc;
	struct efrm_pd *pd;
	size_t n_shm_rxqs;
	struct efrm_client *set_client;

	if (o_attr == NULL) {
		efrm_vi_attr_init(&s_attr);
		o_attr = &s_attr;
	}
	attr = VI_ATTR_FROM_O_ATTR(o_attr);

	pd = NULL;
	if (attr->pd != NULL)
		pd = attr->pd;
	if (attr->vi_set != NULL) {
		EFRM_ASSERT(attr->vi_set->pd);
		set_client = client ?
			client :
			efrm_pd_to_resource(attr->vi_set->pd)->rs_client;

		EFRM_ASSERT(set_client);
		if (set_client->nic->flags & NIC_FLAG_SHARED_PD)
			pd = attr->vi_set->pd;
	}
	if (pd == NULL) {
		/* Legacy compatibility.  Create a [pd] from [client]. */
		if (client == NULL) {
			EFRM_ERR("%s: ERROR: no PD or CLIENT\n", __func__);
			return -EINVAL;
		}
		rc = efrm_pd_alloc(&pd, client, 0);
		if (rc < 0) {
			EFRM_ERR("%s: ERROR: failed to alloc PD (rc=%d)\n",
				 __func__, rc);
			goto fail_alloc_pd;
		}
	} else {
		efrm_resource_ref(efrm_pd_to_resource(pd));
		client = efrm_pd_to_resource(pd)->rs_client;
	}

	/* At this point we definitely have a valid [client] and a [pd]. */

	rc = -EINVAL;
	if (attr->packed_stream &&
	    (efrm_pd_get_min_align(pd) <
	     EFRM_PD_RX_PACKED_STREAM_MEMORY_ALIGNMENT)) {
		EFRM_ERR("%s: ERROR: Packed stream VI requested on non-packed "
			 "stream PD", __FUNCTION__);
		goto fail_checks;
	}
	if (attr->vi_set != NULL) {
		struct efrm_resource *rs;
		rs = efrm_vi_set_to_resource(attr->vi_set);
		if (client != rs->rs_client) {
			EFRM_ERR("%s: ERROR: vi_set ifindex=%d client "
				 "ifindex=%d", __func__,
				 efrm_client_get_ifindex(rs->rs_client),
				 efrm_client_get_ifindex(client));
			goto fail_checks;
		}
	}

	virs = kmalloc(sizeof(*virs), GFP_KERNEL);
	if (virs == NULL) {
		EFRM_ERR("%s: Out of memory", __FUNCTION__);
		rc = -ENOMEM;
		goto fail_alloc;
	}
	memset(virs, 0, sizeof(*virs));
	EFRM_ASSERT(&virs->rs == (struct efrm_resource *) (virs));

	efrm_vi_rm_salvage_flushed_vis(client->nic);
	rc = efrm_vi_rm_alloc_instance(pd, virs, attr,
				       print_resource_warnings);
	if (rc < 0) {
		if (print_resource_warnings) {
			EFRM_ERR("%s: Out of VI instances with given "
			 	 "attributes (%d)", __FUNCTION__, rc);
		}
		goto fail_alloc_id;
	}
	EFRM_ASSERT(virs->allocation.instance >= 0);

	n_shm_rxqs = efhw_nic_max_shared_rxqs(efrm_client_get_nic(client));
	if( n_shm_rxqs ) {
		size_t i;
		virs->efct_shm = vmalloc_user(efrm_vi_get_efct_shm_bytes_nrxq(virs,
		                                                          n_shm_rxqs));
		if (!virs->efct_shm) {
			EFRM_ERR("%s: ERROR: OOM for efct rxq (%zu+%zu*%zu)",
						__func__, sizeof(*virs->efct_shm),
						sizeof(virs->efct_shm->q[0]), n_shm_rxqs);
			goto fail_efct_rxq;
		}
		for (i = 0; i < n_shm_rxqs; ++i) {
			virs->efct_shm->q[i].qid = -1;
			virs->efct_shm->q[i].config_generation = 1;
		}
	}

	INIT_LIST_HEAD(&virs->efct_rxq_list);

	rc = efrm_vi_io_map(virs, client->nic,
			    virs->allocation.instance);
	if (rc < 0) {
		EFRM_ERR("%s: failed to I/O map id=%d (rc=%d)\n",
		  	 __FUNCTION__, virs->rs.rs_instance, rc);
		goto fail_mmap;
	}

	/* Some NICs don't support wakeup events, so only interrupting
	 * is supported. Net driver provides range of interrupts
	 * and register to prime EVQ. Resource manager setups IRQ for VI,
	 * one VI has one IRQ.
	 * See ON-10914.
	 */
	if ((client->nic->flags & NIC_FLAG_EVQ_IRQ) && attr->want_interrupt) {
		rc = efrm_vi_request_irq(client->nic, virs);
		if (rc != 0)
			goto fail_irq;
	}

	efrm_resource_init(&virs->rs, EFRM_RESOURCE_VI,
			   virs->allocation.instance);

	/* Start with one reference.  Any external VIs using the EVQ of
	 * this resource will increment this reference rather than the
	 * resource reference to avoid DMAQ flushes from waiting for other
	 * DMAQ flushes to complete.  When the resource reference goes to
	 * zero, the DMAQ flush happens.  When the flush completes, this
	 * reference is decremented.  When this reference reaches zero, the
	 * instance is freed.
	 */
	atomic_set(&virs->evq_refs, 1);
	virs->flags = 0;
	virs->pd = pd;

#ifdef __PPC__
	/* On PPC it is impossible to get DMA addresses that are aligned on
	 * boundaries greater than 64K, so we cannot use buffers any larger
	 * than this.
	 */
	virs->ps_buf_size = 1 << 16;
#else
	if (client->nic->flags & NIC_FLAG_VAR_PACKED_STREAM) {
		virs->ps_buf_size = 1 << 16;
		while (virs->ps_buf_size < attr->ps_buffer_size &&
		       virs->ps_buf_size < 1 << 20)
			virs->ps_buf_size <<= 1;
	} else {
		virs->ps_buf_size = 1 << 20;
	}
#endif

	efrm_client_add_resource(client, &virs->rs);
	efrm_init_debugfs_vi(virs);
	*p_virs_out = virs;
	return 0;


fail_irq:
	efrm_vi_io_unmap(virs, client->nic);
fail_mmap:
	vfree(virs->efct_shm);
fail_efct_rxq:
	efrm_vi_rm_free_instance(client, virs);
fail_alloc_id:
	kfree(virs);
fail_alloc:
fail_checks:
	efrm_pd_release(pd);
fail_alloc_pd:
	return rc;
}
EXPORT_SYMBOL(efrm_vi_alloc);


int efrm_vi_is_hw_rx_loopback_supported(struct efrm_vi *virs)
{
	return (virs->flags & EFHW_VI_RX_LOOPBACK);
}
EXPORT_SYMBOL(efrm_vi_is_hw_rx_loopback_supported);


int efrm_vi_is_hw_drop_filter_supported(struct efrm_vi *virs)
{
	struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);
	return ! (nic->devtype.arch == EFHW_ARCH_AF_XDP);
}
EXPORT_SYMBOL(efrm_vi_is_hw_drop_filter_supported);


int  efrm_vi_q_get_size(struct efrm_vi *virs, enum efhw_q_type q_type,
			int n_q_entries, struct efrm_vi_q_size *qso)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;

	n_q_entries = efrm_vi_n_q_entries(n_q_entries, nic->q_sizes[q_type]);
	if (n_q_entries <= 0)
		return -EINVAL;

	qso->q_len_entries = n_q_entries;
	qso->q_len_bytes = efrm_vi_q_bytes(virs, q_type, n_q_entries);

	/* This value should always be positive, but if we don't check for this
	 * explicitly, some compilers will assume that undefined logarithms
	 * can be taken in get_order() and will generate code that won't link.
	 * See bug63982. */
	EFRM_ASSERT(qso->q_len_bytes > 0);
	if (qso->q_len_bytes <= 0)
		return -EINVAL;

	qso->q_len_page_order = get_order(qso->q_len_bytes);
	return 0;
}
EXPORT_SYMBOL(efrm_vi_q_get_size);


int
efrm_vi_q_init_common(struct efrm_vi *virs, enum efhw_q_type q_type,
		      int n_q_entries, int q_tag, unsigned q_flags)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	struct efrm_vi_q *q = &virs->q[q_type];
	struct efrm_vi_q_size qsize;
	int n_pages, i, j;
	int mask;

	if (q->capacity != 0)
		return -EBUSY;

	switch (q_type) {
	case EFHW_TXQ:
		mask = (1 << MC_CMD_INIT_TXQ_EXT_IN_LABEL_LEN) - 1;
		if (q_tag != (q_tag & mask))
			return -EINVAL;
		break;
	case EFHW_RXQ:
		mask = (1 << MC_CMD_INIT_RXQ_EXT_IN_LABEL_LEN) - 1;
		if (q_tag != (q_tag & mask))
			return -EINVAL;
		break;
	case EFHW_EVQ:
		break;
	default:
		return -EINVAL;
	}

	if (n_q_entries != efrm_vi_n_q_entries(n_q_entries, nic->q_sizes[q_type]))
		return -EINVAL;
	efrm_vi_q_get_size(virs, q_type, n_q_entries, &qsize);

	if (efhw_iopages_n_pages(&q->host_pages) > 0) {
		n_pages = 1 << qsize.q_len_page_order;
		EFRM_ASSERT(n_pages == efhw_iopages_n_pages(&q->host_pages));
		/* Ensure we don't write past `q->dma_addrs` in the loop below. */
		EFRM_ASSERT(n_pages*EFHW_NIC_PAGES_IN_OS_PAGE <= EFRM_VI_MAX_DMA_ADDR);

		for (i = 0; i < n_pages; ++i) {
			for (j = 0; j < EFHW_NIC_PAGES_IN_OS_PAGE; ++j) {
				q->dma_addrs[i * EFHW_NIC_PAGES_IN_OS_PAGE + j] =
					efhw_iopages_dma_addr(&q->host_pages, i) + EFHW_NIC_PAGE_SIZE * j;
			}
		}
	}

	q->tag = q_tag;
	q->flags = q_flags;
	q->capacity = qsize.q_len_entries;
	q->bytes = qsize.q_len_bytes;
	virs->flags |= q_flags_to_vi_flags(q_flags, q_type);

	return 0;
}

unsigned
efrm_vi_shut_down_flag(enum efhw_q_type queue)
{
	switch (queue) {
		default:
			EFRM_ASSERT(0);
			ci_fallthrough;
		case EFHW_TXQ:
			return EFRM_VI_SHUT_DOWN_TXQ;
		case EFHW_RXQ:
			return EFRM_VI_SHUT_DOWN_RXQ;
		case EFHW_EVQ:
			return EFRM_VI_SHUT_DOWN_EVQ;
	}

	/* Unreachable. */
}



static int efrm_vi_q_init_pf(struct efrm_vi *virs, enum efhw_q_type q_type,
			     int q_tag, struct efrm_vi *evq)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	struct efrm_vi_q *q = &virs->q[q_type];
	int rc;

	if (evq == NULL)
		evq = virs;

	q->bt_alloc.bta_size = 0;

	if (q_type != EFHW_EVQ)
		efrm_vi_attach_evq(virs, q_type, evq);
	rc = efrm_vi_rm_init_dmaq(virs, q_type, nic);
	/* ENETDOWN indicates absent hardware, in which case we should not
	 * report failure as we wish to preserve all software state in
	 * anticipation of the hardware's reappearance. */
	if (rc == -ENETDOWN) {
		efrm_atomic_or(efrm_vi_shut_down_flag(q_type), &virs->shut_down_flags);
		rc = 0;
	}
	return rc;
}


int efrm_vi_q_init(struct efrm_vi *virs, enum efhw_q_type q_type,
		   int n_q_entries, int q_tag, unsigned q_flags,
		   struct efrm_vi *evq)
{
	struct efrm_vi_q *q = &virs->q[q_type];
	int rc;

	rc = efrm_vi_q_init_common(virs, q_type, n_q_entries, q_tag, q_flags);
	if (rc != 0)
		return rc;
	rc = efrm_vi_q_init_pf(virs, q_type, q_tag, evq);
	if (rc != 0)
		q->capacity = 0;
	return rc;
}


static int efrm_vi_q_reinit(struct efrm_vi *virs, enum efhw_q_type q_type)
{
	struct efrm_vi_q *q;
	struct efhw_nic *nic;

	EFRM_TRACE("%s: %p %d", __FUNCTION__, virs, q_type);

	q = &virs->q[q_type];
	nic = virs->rs.rs_client->nic;

	if (q->capacity == 0) 
		return -EINVAL;

	return efrm_vi_rm_init_dmaq(virs, q_type, nic);
}


int efrm_vi_reinit_txq(struct efrm_vi *virs)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	struct efrm_nic* efrm_nic = efrm_nic(nic);
	struct efrm_vi_q *q = &virs->q[EFHW_TXQ];
	int rc;

	EFRM_TRACE("%s: %p", __FUNCTION__, virs);

	if( q->capacity == 0 )
		return -EINVAL;

	if( (virs->flags & (EFRM_VI_RELEASED | EFRM_VI_STOPPING)) != 0 )
		return -EINVAL;

	if( ! list_empty(&q->init_link) ) {
		mutex_lock(&efrm_nic->dmaq_state.lock);
		rc = efrm_vi_q_flush_state(virs, EFHW_TXQ);
		mutex_unlock(&efrm_nic->dmaq_state.lock);
		if( rc < 0 )
			return rc;
	}

	rc = efhw_nic_post_tx_error(nic, q->qid);
	if( rc < 0 )
		return rc;

	return efrm_vi_rm_init_dmaq(virs, EFHW_TXQ, nic);
}
EXPORT_SYMBOL(efrm_vi_reinit_txq);


void efrm_vi_qs_reinit(struct efrm_vi *virs)
{
	atomic_set(&virs->shut_down_flags, 0);
	efrm_vi_q_reinit(virs, EFHW_EVQ);
	efrm_vi_q_reinit(virs, EFHW_TXQ);
	efrm_vi_q_reinit(virs, EFHW_RXQ);
}
EXPORT_SYMBOL(efrm_vi_qs_reinit);


extern struct efrm_vi *
efrm_vi_from_resource(struct efrm_resource *rs)
{
	return efrm_vi(rs);
}
EXPORT_SYMBOL(efrm_vi_from_resource);


int efrm_vi_tx_alt_alloc(struct efrm_vi *virs, int num_alt, int num_32b_words)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	int rc;

	if ((num_alt <= 0) || (num_32b_words <= 0))
		return -EINVAL;

	if (virs->tx_alt_num > 0)
		return -EALREADY;

	rc = efhw_nic_tx_alt_alloc(nic, virs->rs.rs_instance, num_alt,
				   num_32b_words, &(virs->tx_alt_cp),
				   virs->tx_alt_ids);
	if (rc == 0)
		virs->tx_alt_num = num_alt;
	return rc;
}
EXPORT_SYMBOL(efrm_vi_tx_alt_alloc);

int efrm_vi_tx_alt_free(struct efrm_vi *virs)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	int rc;

	if (virs->tx_alt_num == 0)
		return 0;

	rc = efhw_nic_tx_alt_free(nic, virs->tx_alt_num, virs->tx_alt_cp,
				  virs->tx_alt_ids);
	if (rc == 0)
		virs->tx_alt_num = 0;
	return rc;
}
EXPORT_SYMBOL(efrm_vi_tx_alt_free);
