/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
#include <ci/efhw/public.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/mc_driver_pcol.h>
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


struct vi_attr {
	struct efrm_pd     *pd;
	struct efrm_vi_set *vi_set;
	int16_t             interrupt_core;
	int16_t             channel;
	uint8_t             vi_set_instance;
	int8_t              packed_stream;
	int32_t             ps_buffer_size;
};

CI_BUILD_ASSERT(sizeof(struct vi_attr) <= sizeof(struct efrm_vi_attr));

union vi_attr_u {
	struct vi_attr      vi_attr;
	struct efrm_vi_attr efrm_vi_attr;
};


#define VI_ATTR_FROM_O_ATTR(attr)					\
  (&(container_of((attr), union vi_attr_u, efrm_vi_attr)->vi_attr))


/*** Data definitions ****************************************************/

static const char *q_names[EFHW_N_Q_TYPES] = { "TXQ", "RXQ", "EVQ" };

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

/*** Instance numbers ****************************************************/


/* Returns -ve code on error and 0 on success. */
static int efrm_vi_set_alloc_instance_try(struct efrm_vi *virs,
					  struct efrm_vi_set* vi_set,
					  int instance)
{
	assert_spin_locked(&vi_set->allocation_lock);
	if (instance != 0xff) {
		if (instance >= (1 << vi_set->allocation.order) ) {
			EFRM_ERR("%s: ERROR: vi_set instance=%d out-of-range "
				 "(size=%d)", __FUNCTION__, instance,
				 1 << vi_set->allocation.order);
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


int efrm_vi_af_xdp_kick(struct efrm_vi *vi)
{
  struct msghdr msg = {.msg_flags = MSG_DONTWAIT};
  return kernel_sendmsg(vi->af_xdp_sock, &msg, NULL, 0, 0);
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
	int channel;

	efhw_nic = efrm_client_get_nic(efrm_pd_to_resource(pd)->rs_client);
	efrm_nic = efrm_nic(efhw_nic);
	channel = vi_attr->channel;
	if (vi_attr->interrupt_core >= 0) {
		struct net_device *dev = efhw_nic_get_net_dev(&efrm_nic->efhw_nic);
		if (!dev) {
			if (print_resource_warnings) {
				EFRM_ERR("%s: ERROR: NIC was removed since pd allocation",
				         __FUNCTION__);
				return -ENETDOWN;
			}
			channel = -1;
		}
		else {
			int ifindex = dev->ifindex;
			channel = efrm_affinity_cpu_to_channel_dev(dev,
			                                          vi_attr->interrupt_core);
			dev_put(dev);
			if (channel < 0 && print_resource_warnings) {
				EFRM_ERR("%s: ERROR: could not map core_id=%d using "
					"ifindex=%d", __FUNCTION__,
					(int) vi_attr->interrupt_core, ifindex);
				EFRM_ERR("%s: ERROR: Perhaps sfc_affinity is not "
					"configured?", __FUNCTION__);
				return -EINVAL;
			}
		}
	}
	virs->net_drv_wakeup_channel = channel;

	if (vi_attr->vi_set != NULL)
		return efrm_vi_set_alloc_instance(virs, vi_attr->vi_set,
						  vi_attr->vi_set_instance);

	return efrm_vi_allocator_alloc_set(efrm_nic, 1, 0,
					   channel, &virs->allocation);
}


static void
efrm_vi_irq_free(struct efrm_vi *vi)
{
	EFRM_ASSERT(vi);

	free_irq(vi->irq, vi);
	tasklet_kill(&vi->tasklet);
}


static void efrm_vi_rm_free_instance(struct efrm_vi *virs)
{
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
		struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);

		if (virs->irq != 0)
			efrm_vi_irq_free(virs);

		efrm_vi_allocator_free_set(efrm_nic(nic), &virs->allocation);
	}
}

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
	else if (nic->devtype.arch == EFHW_ARCH_EF100)
		return n_entries * EF100_DMA_TX_DESC_BYTES;
	else if (nic->devtype.arch == EFHW_ARCH_AF_XDP)
		return n_entries * 8; /* TODO AF_XDP sizeof struct xdp_desc */
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
	else if (nic->devtype.arch == EFHW_ARCH_EF100)
		bytes_per_desc = EF100_DMA_RX_DESC_BYTES;
	else if (nic->devtype.arch == EFHW_ARCH_AF_XDP)
		return n_entries * 8; /* TODO AF_XDP sizeof struct xdp_desc */
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


static int choose_size(int size_rq, unsigned sizes)
{
	int size;

	/* size_rq < 0 means default, but we interpret this as 'minimum'. */

	for (size = 256;; size <<= 1)
		if ((size & sizes) && size >= size_rq)
			return size;
		else if ((sizes & ~((size - 1) | size)) == 0)
			return -1;
}


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
	struct efrm_vi_q *q = &virs->q[queue_type];
	struct efrm_nic* efrm_nic;
	int instance, evq_instance = -1, interrupting, wakeup_evq;
	unsigned flags = virs->flags;
	unsigned vport_id;

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

	switch (queue_type) {
	case EFHW_TXQ:
		evq_instance = q->evq_ref->rs.rs_instance;
		rc = efhw_nic_dmaq_tx_q_init
			(nic, instance, evq_instance,
			 efrm_pd_owner_id(virs->pd),
			 virs->q[queue_type].tag, q->capacity,
			 q->dma_addrs,
			 (1 << q->page_order) * EFHW_NIC_PAGES_IN_OS_PAGE,
			 vport_id,
			 efrm_pd_stack_id_get(virs->pd), flags);
		break;
	case EFHW_RXQ:
		evq_instance = q->evq_ref->rs.rs_instance;
                rc = efhw_nic_dmaq_rx_q_init
                       (nic, instance, evq_instance,
                        efrm_pd_owner_id(virs->pd),
                        virs->q[queue_type].tag, q->capacity,
                        q->dma_addrs,
                        (1 << q->page_order) * EFHW_NIC_PAGES_IN_OS_PAGE,
                        vport_id,
                        efrm_pd_stack_id_get(virs->pd), virs->ps_buf_size,
                        flags);
                if( rc >= 0 ) {
                  virs->rx_prefix_len = rc;
                  rc = 0;
                }
		break;
	case EFHW_EVQ:
		if (nic->devtype.arch == EFHW_ARCH_EF10)
			interrupting = 0;
		/* EF100 hasn't wakeup events, so only interrupting
		 * is supported. Every VI has only one IRQ.
		 * See ON-10914.
		 */
		else if (nic->devtype.arch == EFHW_ARCH_EF100)
			interrupting = 1;
		else if (nic->devtype.arch == EFHW_ARCH_AF_XDP)
			interrupting = 0;
		else {
			EFRM_ASSERT(0);
			interrupting = 0;
		}
	
		if (nic->devtype.arch == EFHW_ARCH_EF100) {
			wakeup_evq = instance;
		}
		else {
			wakeup_evq = virs->net_drv_wakeup_channel >= 0?
				virs->net_drv_wakeup_channel:
				efrm_nic->rss_channel_count == 0?
				0:
				instance % efrm_nic->rss_channel_count;
		}

		/* NB. We do not enable DOS protection because of bug12916. */
		rc = efhw_nic_event_queue_enable
			(nic, instance, q->capacity,
			 q->dma_addrs,
			 (1 << q->page_order) * EFHW_NIC_PAGES_IN_OS_PAGE,
			 interrupting, 0 /* DOS protection */,
			 wakeup_evq, flags, &virs->out_flags);
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
		if( rc == 0 )
			list_add_tail(&q->init_link,
				      &efrm_nic->dmaq_state.q[queue_type]);
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
	if (efhw_iopages_n_pages(&q->pages)) {
		struct pci_dev* dev = efrm_vi_get_pci_dev(virs);
		efhw_iopages_free(dev, &q->pages);
		if (dev)
			pci_dev_put(dev);
	}
}


static int
efrm_vi_io_map(struct efrm_vi* virs, struct efhw_nic *nic, int instance)
{
	int offset;
	switch (nic->devtype.arch) {
	case EFHW_ARCH_EF10:
	case EFHW_ARCH_EF100:
		offset = instance * nic->vi_stride;
		virs->io_page = ci_ioremap(nic->ctr_ap_dma_addr + offset,
                                           PAGE_SIZE);
		if (virs->io_page == NULL)
			return -ENOMEM;
		break;
	case EFHW_ARCH_AF_XDP:
		break;
	default:
		EFRM_ASSERT(0);
		break;
	}
	return 0;
}


static void
efrm_vi_io_unmap(struct efrm_vi* virs)
{
	struct efhw_nic* nic = virs->rs.rs_client->nic;
	switch (nic->devtype.arch) {
	case EFHW_ARCH_EF10:
	case EFHW_ARCH_EF100:
		iounmap(virs->io_page);
		break;
	case EFHW_ARCH_AF_XDP:
		break;
	default:
		EFRM_ASSERT(0);
		break;
	}
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
__efrm_vi_q_flush(struct efhw_nic* nic, enum efhw_q_type queue_type,
		  int instance, int time_sync_events_enabled)
{
	int rc;

	switch (queue_type) {
	case EFHW_RXQ:
		rc = efhw_nic_flush_rx_dma_channel(nic, instance);
		break;
	case EFHW_TXQ:
		rc = efhw_nic_flush_tx_dma_channel(nic, instance);
		break;
	case EFHW_EVQ:
		/* flushing EVQ is as good as disabling it */
		efhw_nic_event_queue_disable(nic, instance,
					     time_sync_events_enabled);
		rc = 0;
		break;
	default:
		EFRM_ASSERT(0);
		rc = -EINVAL;
	};
	return rc;
}


int
efrm_vi_q_flush(struct efrm_vi *virs, enum efhw_q_type queue_type)
{
	struct efrm_vi_q *q = &virs->q[queue_type];
	int instance = virs->rs.rs_instance;
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	struct efrm_nic* efrm_nic = efrm_nic(nic);

	int rc = 0;

	mutex_lock(&efrm_nic->dmaq_state.lock);

	if( list_empty(&q->init_link) ) {
		EFRM_TRACE("Queue already flushed nic %d type %d 0x%x",
			  nic->index, queue_type, instance);
		/* we should not issue MCDI now */
		rc = -EALREADY;
		mutex_unlock(&efrm_nic->dmaq_state.lock);
		return rc;
	} else {
		list_del(&q->init_link);
		INIT_LIST_HEAD(&q->init_link);
	}

	rc = __efrm_vi_q_flush(nic, queue_type, instance,
			       (virs->flags & (EFHW_VI_RX_TIMESTAMPS |
					       EFHW_VI_TX_TIMESTAMPS)) != 0);
	EFRM_TRACE("Flushed queue nic %d type %d 0x%x rc %d",
		  nic->index, queue_type, instance, rc);
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
	efrm_vi_io_unmap(virs);
	efrm_vi_rm_free_instance(virs);
	efrm_pd_release(virs->pd);
	efrm_client_put(virs->rs.rs_client);
	EFRM_DO_DEBUG(memset(virs, 0, sizeof(*virs)));
	kfree(virs);
}


/* dummy parameter indicates only sw state needs to be updated
 * e.g. after impolite unplug we assume all queues are gone */
void efrm_nic_flush_all_queues(struct efhw_nic *nic, int dummy)
{
	int type;
	struct efrm_nic *efrm_nic = efrm_nic_from_efhw_nic(nic);

	mutex_lock(&efrm_nic->dmaq_state.lock);
	if (!dummy)
		efrm_nic->dmaq_state.unplugging = 1;
	EFRM_TRACE(" Flushing all queues for nic %d nohw %d", nic->index, dummy);
	for (type = 0; type < EFHW_N_Q_TYPES; ++type) {
		while (!list_empty(&efrm_nic->dmaq_state.q[type])) {
			struct list_head *h = list_pop(&efrm_nic->dmaq_state.q[type]);
			struct efrm_vi *virs;
			int rc;
			virs = list_entry(h, struct efrm_vi, q[type].init_link);
			INIT_LIST_HEAD(&virs->q[type].init_link);
			if (dummy)
				continue;
			efrm_atomic_or(efrm_vi_shut_down_flag(type), &virs->shut_down_flags);
			rc = __efrm_vi_q_flush(virs->rs.rs_client->nic, type,
				virs->rs.rs_instance,
				(virs->flags & EFHW_VI_RX_TIMESTAMPS) != 0);
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
			 __FUNCTION__, q_names[q_type],
			 virs->q[q_type].capacity,
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
	dma_addr_t *dma_addrs;
	int dma_addrs_size, mmap_bytes;
	struct efrm_vi_q *q = &virs->q[q_type];
	struct efrm_vi_q_size qsize;
	int i, rc, q_flags;
	unsigned long iova_base = 0;
	struct pci_dev* dev;
	struct efhw_nic* nic = virs->rs.rs_client->nic;

	if (n_q_entries == 0)
		return 0;
	if (n_q_entries < 0)
		n_q_entries = 1;
	if (efrm_vi_q_get_size(virs, q_type, n_q_entries, &qsize) < 0) {
		EFRM_ERR("%s: ERROR: bad %s size %d (supported=%x)",
			 __FUNCTION__, q_names[q_type],
			 virs->q[q_type].capacity,
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

	if (nic->devtype.arch == EFHW_ARCH_AF_XDP) {
		/* AF_XDP interfaces have provide their own queue memory.
		 * We will acquire it later, after initialising the packet
		 * buffer memory.
		 */
		dma_addrs = NULL;
		dma_addrs_size = 0;
	}
	else {
		dev = efrm_vi_get_pci_dev(virs);
		rc = efhw_iopages_alloc(dev, &q->pages, qsize.q_len_page_order,
		                        nic->devtype.arch == EFHW_ARCH_EF100, iova_base);
		if (dev)
			pci_dev_put(dev);
		if (rc < 0) {
			EFRM_ERR("%s: Failed to allocate %s DMA buffer",
				 __FUNCTION__, q_names[q_type]);
			return rc;
		}
		if (q_type == EFHW_EVQ)
			memset(efhw_iopages_ptr(&q->pages), EFHW_CLEAR_EVENT_VALUE,
			       qsize.q_len_bytes);

		rc = efhw_page_map_add_pages(&virs->mem_mmap, &q->pages);
		if (rc < 0)
			goto fail;

		dma_addrs_size = 1 << EFHW_GFP_ORDER_TO_NIC_ORDER(qsize.q_len_page_order);
		EFRM_ASSERT(dma_addrs_size <= EFRM_VI_MAX_DMA_ADDR);
		dma_addrs = kmalloc(sizeof(*dma_addrs) * dma_addrs_size, GFP_KERNEL);
		if (dma_addrs == NULL) {
			rc = -ENOMEM;
			goto fail;
		}

		for (i = 0; i < dma_addrs_size; ++i)
			dma_addrs[i] = efhw_iopages_dma_addr(&q->pages, i);

		mmap_bytes = PAGE_SIZE * (1 << qsize.q_len_page_order);

		/* TODO why is this different to the value for kmalloc above? */
		dma_addrs_size = efhw_iopages_n_pages(&q->pages) *
		                   EFHW_NIC_PAGES_IN_OS_PAGE;
	}

	q_flags = vi_flags_to_q_flags(vi_flags, q_type);

	INIT_LIST_HEAD(&q->init_link);
	rc = efrm_vi_q_init(virs, q_type, qsize.q_len_entries,
			    dma_addrs, dma_addrs_size,
			    q_tag_in, q_flags, evq);

	if (dma_addrs != NULL) {
		kfree(dma_addrs);
		if (rc < 0)
			goto fail;
	}

	return rc;

fail:
	dev = efrm_vi_get_pci_dev(virs);
	efhw_iopages_free(dev, &q->pages);
	if (dev)
		pci_dev_put(dev);
	return rc;
}
EXPORT_SYMBOL(efrm_vi_q_alloc);


static void
vi_call_evq_callback(struct efrm_vi *vi)
{
	efrm_evq_callback_fn handler;
	void *arg;

	spin_lock_bh(&vi->evq_callback_lock);

	handler = vi->evq_callback_fn;
	rmb();
	arg = vi->evq_callback_arg;

	if (handler == NULL) {
		/* This is seen at VI creation time, so we should not cry
		 * too loud.  It will be nice to see this at other times,
		 * but it is not easy. */
		EFRM_TRACE("VI %d/%d interrupt IRQ %d but no handler",
			   vi->rs.rs_instance, vi->allocation.instance, vi->irq);
	}
	else {
		/* Fixme: callback with is_timeout=true? */
		handler(arg, false, vi->rs.rs_client->nic,
			INT_MAX);
	}

	spin_unlock_bh(&vi->evq_callback_lock);
}


static void
efrm_vi_tasklet(unsigned long l)
{
	struct efrm_vi *vi = (void *)l;
	vi_call_evq_callback(vi);
}


static irqreturn_t
vi_interrupt(int irq, void *dev_id
#if defined(EFX_HAVE_IRQ_HANDLER_REGS)
	, struct pt_regs *regs __attribute__ ((unused))
#endif
	)
{
	struct efrm_vi *vi = dev_id;

	/* Processing of hardware interrupt should be done in 2 steps: top-half
	 * and bottom-half. Top-half is a handler function that is performed in
	 * the context of the disabled interrupts. So it should performs only
	 * the most minimal work that cannot be postponed for later.
	 * Bottom-half is the deferred processing of interrupts is performed in
	 * the kernel context with enabled interrupts. It can be done with
	 * tasklet, workqueue and request_threaded_irq().
	 * Tasklet is used here because it has better latency performance.
	 */
	tasklet_schedule(&vi->tasklet);
	return IRQ_HANDLED;
}


#ifndef IRQF_SAMPLE_RANDOM
#define IRQF_SAMPLE_RANDOM 0
#endif


static int
efrm_vi_irq_setup(struct efrm_vi *vi, const char *vi_name, unsigned int irq)
{
	int rc;

	spin_lock_init(&vi->evq_callback_lock);

	/* Enable interrupts */
	tasklet_init(&vi->tasklet, &efrm_vi_tasklet, (unsigned long)vi);
	rc = request_irq(irq, vi_interrupt,
			 IRQF_SAMPLE_RANDOM, vi_name, vi);
	if (rc != 0) {
		EFRM_ERR("failed to request IRQ %d for VI %d",
			 irq, vi->rs.rs_instance);
	}

	return rc;
}


static int
efrm_vi_request_irq(struct efrm_vi *virs, const char *vi_name)
{
	char name[80];
	unsigned vi_index;
	unsigned irq = 0;
	unsigned i;
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	int rc;

	if (vi_name == NULL) {
		snprintf(name, sizeof(name),
			 "SolarFlare NIC %d VI %d pid %d",
			 nic->index,
			 virs->rs.rs_instance,
			 current ? current->tgid : -1);
		name[sizeof(name)-1] = '\0';
		vi_name = name;
	}

	vi_index = virs->rs.rs_instance - nic->vi_min;
	for (i = 0; i < nic->vi_irq_n_ranges; i++) {
		if (vi_index < nic->vi_irq_ranges[i].range) {
			irq = nic->vi_irq_ranges[i].base + vi_index;
			break;
		} else {
			vi_index -= nic->vi_irq_ranges[i].range;
		}
	}

	if (irq == 0) {
		EFRM_ERR("%s: VI number is out of range IRQs\n",
			 __FUNCTION__);
		return -EINVAL;
	}

	rc = efrm_vi_irq_setup(virs, vi_name, irq);
	if (rc != 0)
		return rc;

	virs->irq = irq;
	return 0;
}


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

	EFRM_ASSERT(pd != NULL);
	efrm_vi_attr_init(&attr);
	if (vi_set != NULL)
		efrm_vi_attr_set_instance(&attr, vi_set, vi_set_instance);
	efrm_vi_attr_set_pd(&attr, pd);
	if (wakeup_cpu_core >= 0)
		efrm_vi_attr_set_interrupt_core(&attr, wakeup_cpu_core);
	if (wakeup_channel >= 0)
		efrm_vi_attr_set_wakeup_channel(&attr, wakeup_channel);

	if ((rc = efrm_vi_alloc(client, &attr, print_resource_warnings,
				name, &virs)) < 0)
		goto fail_vi_alloc;

	/* EF100 hasn't wakeup events, so only interrupting
	 * is supported. Net driver via driverlink provides range of interrupts
	 * and register to prime EVQ. Resource manager setups IRQ for VI,
	 * one VI has one IRQ.
	 * See ON-10914.
	 */
	if (client->nic->devtype.arch == EFHW_ARCH_EF100) {
		rc = efrm_vi_request_irq(virs, name);
		if (rc != 0)
			goto fail_irq;
	}

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

	if (evq_virs == NULL && evq_capacity < 0)
		evq_capacity = rxq_capacity + txq_capacity;

	if ((rc = efrm_vi_q_alloc(virs, EFHW_EVQ, evq_capacity,
				  0, vi_flags, NULL)) < 0)
		goto fail_q_alloc;
	if ((rc = efrm_vi_q_alloc(virs, EFHW_RXQ, rxq_capacity,
				  rx_q_tag, vi_flags, evq_virs)) < 0)
		goto fail_q_alloc;
	if ((rc = efrm_vi_q_alloc(virs, EFHW_TXQ, txq_capacity,
				  tx_q_tag, vi_flags, evq_virs)) < 0)
		goto fail_q_alloc;

	if( vi_flags & EFHW_VI_TX_CTPIO )
		ctpio_mmap_bytes = EF_VI_CTPIO_APERTURE_SIZE;

	if (out_io_mmap_bytes != NULL) {
		if (client->nic->devtype.arch == EFHW_ARCH_AF_XDP)
			*out_io_mmap_bytes = 0;
		else
			*out_io_mmap_bytes = PAGE_SIZE;
	}
	if (out_ctpio_mmap_bytes != NULL)
		*out_ctpio_mmap_bytes = ctpio_mmap_bytes;
	if (out_txq_capacity != NULL)
		*out_txq_capacity = virs->q[EFHW_TXQ].capacity;
	if (out_rxq_capacity != NULL)
		*out_rxq_capacity = virs->q[EFHW_RXQ].capacity;

	*virs_out = virs;
	return 0;


fail_irq:
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

	rc = nic->efhw_func->af_xdp_init(nic, virs->allocation.instance,
	                                 chunk_size, headroom,
	                                 &virs->af_xdp_sock, &virs->mem_mmap);
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
	a->packed_stream = 0;
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

	if (o_attr == NULL) {
		efrm_vi_attr_init(&s_attr);
		o_attr = &s_attr;
	}
	attr = VI_ATTR_FROM_O_ATTR(o_attr);

	pd = NULL;
	if (attr->pd != NULL)
		pd = attr->pd;
	if (attr->vi_set != NULL)
		pd = attr->vi_set->pd;
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
	rc = efrm_vi_io_map(virs, client->nic,
			    virs->allocation.instance);
	if (rc < 0) {
		EFRM_ERR("%s: failed to I/O map id=%d (rc=%d)\n",
		  	 __FUNCTION__, virs->rs.rs_instance, rc);
		goto fail_mmap;
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
	*p_virs_out = virs;
	return 0;


fail_mmap:
	efrm_vi_rm_free_instance(virs);
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


int  efrm_vi_q_get_size(struct efrm_vi *virs, enum efhw_q_type q_type,
			int n_q_entries, struct efrm_vi_q_size *qso)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;

	/* We return [q_sizes_supported] even if we fail. */
	qso->q_sizes_supported = nic->q_sizes[q_type];
	if (n_q_entries == EFRM_VI_Q_GET_SIZE_CURRENT)
		n_q_entries = virs->q[q_type].capacity;
	else
		n_q_entries = choose_size(n_q_entries, nic->q_sizes[q_type]);
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
		      int n_q_entries,
		      const dma_addr_t *dma_addrs, int dma_addrs_n,
		      int q_tag, unsigned q_flags)
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

	if (n_q_entries != choose_size(n_q_entries, nic->q_sizes[q_type]))
		return -EINVAL;
	efrm_vi_q_get_size(virs, q_type, n_q_entries, &qsize);

	if (dma_addrs != NULL) {
		n_pages = 1 << qsize.q_len_page_order;
		if (n_pages > dma_addrs_n)
			return -EINVAL;
		for (i = 0; i < n_pages; ++i) {
			for (j = 0; j < EFHW_NIC_PAGES_IN_OS_PAGE; ++j) {
				q->dma_addrs[i * EFHW_NIC_PAGES_IN_OS_PAGE + j] =
					dma_addrs[i] + EFHW_NIC_PAGE_SIZE * j;
			}
		}
	}

	q->page_order = qsize.q_len_page_order;
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
			/* Fall through. */
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
		   int n_q_entries,
		   const dma_addr_t *dma_addrs, int dma_addrs_n,
		   int q_tag, unsigned q_flags, struct efrm_vi *evq)
{
	struct efrm_vi_q *q = &virs->q[q_type];
	int rc;

	rc = efrm_vi_q_init_common(virs, q_type, n_q_entries,
				   dma_addrs, dma_addrs_n, q_tag, q_flags);
	if (rc != 0)
		return rc;
	rc = efrm_vi_q_init_pf(virs, q_type, q_tag, evq);
	if (rc != 0)
		q->capacity = 0;
	return rc;
}
EXPORT_SYMBOL(efrm_vi_q_init);



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

	rc = nic->efhw_func->tx_alt_alloc(nic, virs->rs.rs_instance,
					  num_alt, num_32b_words,
					  &(virs->tx_alt_cp), virs->tx_alt_ids);
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

	rc = nic->efhw_func->tx_alt_free(nic, virs->tx_alt_num,
					 virs->tx_alt_cp, virs->tx_alt_ids);
	if (rc == 0)
                virs->tx_alt_num = 0;
	return rc;
}
EXPORT_SYMBOL(efrm_vi_tx_alt_free);
