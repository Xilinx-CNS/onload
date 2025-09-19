/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains event handling for VI resource.
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
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/eventq.h>
#include <ci/efrm/private.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/buffer_table.h>
#include "efrm_internal.h"


static DEFINE_MUTEX(register_evq_cb_mutex);


static inline efhw_event_t *
efrm_eventq_base(struct efrm_vi *virs)
{
	return (efhw_event_t *) efhw_iopages_ptr(&virs->q[EFHW_EVQ].host_pages);
}


void efrm_eventq_request_wakeup(struct efrm_vi *virs, unsigned current_ptr)
{
	struct efhw_nic *nic = virs->rs.rs_client->nic;
	int next_i;

	/* If the NIC is under reset we should avoid touching hardware
	 * resources. In the onload case we won't request wakeups once we've
	 * been informed of the reset, but ef_vi doesn't know. */
	if( nic->resetting )
		return;

	next_i = current_ptr & (virs->q[EFHW_EVQ].capacity - 1);
	efhw_nic_wakeup_request(nic, virs->io_page, virs->rs.rs_instance,
				next_i);
}
EXPORT_SYMBOL(efrm_eventq_request_wakeup);


/* Registers a callback function for an event queue.  This must not be called
 * on an event queue that already has a registered callback.  To change the
 * callback, first call efrm_eventq_kill_callback(), and then this function. */
int
efrm_eventq_register_callback(struct efrm_vi *virs,
			      efrm_evq_callback_fn handler, void *arg)
{
	struct efrm_nic_per_vi *cb_info;
	struct efrm_nic *rm_nic;
	int instance;
	int bit;
	int rc = 0;

	EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 0);
	EFRM_ASSERT(virs->q[EFHW_EVQ].capacity != 0);
	EFRM_ASSERT(handler != NULL);

	mutex_lock(&register_evq_cb_mutex);
	if (virs->evq_callback_fn != NULL) {
		rc = -EBUSY;
		goto unlock_and_out;
	}

	virs->evq_callback_arg = arg;
	virs->evq_callback_fn = handler;

	rm_nic = efrm_nic(virs->rs.rs_client->nic);
	instance = virs->rs.rs_instance;
	EFRM_ASSERT(instance < rm_nic->max_vis);
	cb_info = &rm_nic->vis[instance];

	cb_info->vi = virs;
	bit = atomic_fetch_or(VI_RESOURCE_EVQ_STATE_CALLBACK_REGISTERED,
			       &cb_info->state);
	EFRM_ASSERT((bit & VI_RESOURCE_EVQ_STATE_CALLBACK_REGISTERED) == 0);
unlock_and_out:
	mutex_unlock(&register_evq_cb_mutex);
	return rc;
}
EXPORT_SYMBOL(efrm_eventq_register_callback);

void efrm_eventq_kill_callback(struct efrm_vi *virs)
{
	struct efrm_nic_per_vi *cb_info;
	struct efrm_nic *rm_nic;
	int32_t evq_state;
	int instance;
	int bit;

	EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 0);
	EFRM_ASSERT(virs->q[EFHW_EVQ].capacity != 0);
	EFRM_ASSERT(virs->rs.rs_client != NULL);

	mutex_lock(&register_evq_cb_mutex);

	rm_nic = efrm_nic(virs->rs.rs_client->nic);
	instance = virs->rs.rs_instance;
	EFRM_ASSERT(instance < rm_nic->max_vis);
	cb_info = &rm_nic->vis[instance];

	/* Disable the callback. */
	bit = atomic_fetch_and(~VI_RESOURCE_EVQ_STATE_CALLBACK_REGISTERED,
				 &cb_info->state);
	EFRM_ASSERT(bit & VI_RESOURCE_EVQ_STATE_CALLBACK_REGISTERED);	/* do not call me twice! */

	/* Spin until the callback is complete. */
	do {
		rmb();

		udelay(1);
		evq_state = atomic_read(&cb_info->state);
	} while (evq_state >> VI_RESOURCE_EVQ_STATE_BUSY_BITSHIFT);

	wmb();
	atomic_fetch_and(~VI_RESOURCE_EVQ_STATE_WAKEUP_PENDING, &cb_info->state);
	cb_info->vi = NULL;
	virs->evq_callback_fn = NULL;
	mutex_unlock(&register_evq_cb_mutex);
}
EXPORT_SYMBOL(efrm_eventq_kill_callback);


/* This is in effect a spinlock on an event queue that ensures that it's safe
 * to run that queue's callback.  We will only succeed in taking this lock if
 * there's a callback registered, and no-one will be able to unregister the
 * callback (nor continue to free the queue) while we hold the lock. */
static struct efrm_vi*
eventq_mark_callback_busy(struct efrm_nic *rnic, unsigned instance,
			  bool is_timeout, bool* contended)
{
	struct efrm_nic_per_vi *cb_info = &rnic->vis[instance];

	/* Set the BUSY bit and clear WAKEUP_PENDING.  Do this before waking up
	 * the sleeper to avoid races. */
	while (1) {
		int32_t evq_state = atomic_read(&cb_info->state);
		int32_t new_evq_state = evq_state;
		bool was_busy = (evq_state >> VI_RESOURCE_EVQ_STATE_BUSY_BITSHIFT) != 0;

		if (was_busy) {
			/* Races are expected here with AF_XDP (since the kernel decides
			 * how much parallelism to use) and X3 (since a single wakeup
			 * request is broadcast to multiple rxqs and an evq).  EF10-style
			 * wakeups and EF100-style interrupts on a given queue are
			 * serialised by the lower-level mechanisms that despatch them. */
			if (rnic->efhw_nic.devtype.arch != EFHW_ARCH_AF_XDP &&
			    rnic->efhw_nic.devtype.arch != EFHW_ARCH_EFCT &&
			    rnic->efhw_nic.devtype.arch != EFHW_ARCH_EF10CT ) {
				EFRM_ERR("%s:%d: evq_state[%d] corrupted!",
					 __FUNCTION__, __LINE__, instance);
				EFRM_ASSERT(0);
			}
		}

		if (!is_timeout)
			new_evq_state &= ~VI_RESOURCE_EVQ_STATE_WAKEUP_PENDING;

		if (evq_state & VI_RESOURCE_EVQ_STATE_CALLBACK_REGISTERED) {
			new_evq_state += 1 << VI_RESOURCE_EVQ_STATE_BUSY_BITSHIFT;
			if (atomic_cmpxchg(&cb_info->state, evq_state,
				    new_evq_state) == evq_state) {
				EFRM_ASSERT(cb_info->vi);
				*contended = was_busy;
				return cb_info->vi;
			}
		}
		else {
			/* Just update the state if necessary. */
			if (new_evq_state == evq_state ||
			    atomic_cmpxchg(&cb_info->state, evq_state,
				    new_evq_state) == evq_state)
				return NULL;
		}
	}
}


/* Run an event queue's callback.  The event queue must be marked as BUSY: see
 * eventq_mark_callback_busy(). */
static int eventq_do_callback(struct efhw_nic *nic, struct efrm_vi *virs,
			      bool is_timeout, int budget, bool contended)
{
	efrm_evq_callback_fn handler = virs->evq_callback_fn;
	void *arg = virs->evq_callback_arg;
	EFRM_ASSERT(handler != NULL);
	/* there's no need for an explicit flag on the callback to deal with the
	 * contended case, since there's no way for the callbacks to do any less
	 * work than they should do with a zero budget */
	return handler(arg, is_timeout, nic, contended ? 0 : budget);
}


static void
eventq_unmark_callback_busy(struct efrm_nic *rnic, unsigned instance)
{
	struct efrm_nic_per_vi *cb_info = &rnic->vis[instance];
	int old = atomic_fetch_sub(
	               1 << VI_RESOURCE_EVQ_STATE_BUSY_BITSHIFT, &cb_info->state);

	if ((old >> VI_RESOURCE_EVQ_STATE_BUSY_BITSHIFT) == 0) {
		EFRM_ERR("%s:%d: evq_state corrupted!",
			 __FUNCTION__, __LINE__);
		EFRM_ASSERT(0);
	}
}


static int
efrm_eventq_do_callback(struct efhw_nic *nic, unsigned instance,
			bool is_timeout, int budget)
{
	struct efrm_nic *rnic = efrm_nic(nic);
	struct efrm_vi *virs;
	int rc = 0;
	bool contended;

	EFRM_ASSERT(efrm_vi_manager);

	virs = eventq_mark_callback_busy(rnic, instance, is_timeout, &contended);
	if (virs) {
		rc = eventq_do_callback(nic, virs, is_timeout, budget, contended);
		eventq_unmark_callback_busy(rnic, instance);
	}

	return rc;
}


int efrm_eventq_do_interrupt_callbacks(struct efrm_interrupt_vector *vec,
				       bool is_timeout, int budget)
{
	struct efrm_vi *virs, *next;
	struct list_head vis;
	struct efrm_nic *rnic = efrm_nic(vec->nic);
	int rc = 0;
	bool contended;
	int64_t contended_seq = ~(uint64_t)0 << 63;
	int num_vis = 0;

	INIT_LIST_HEAD(&vis);

	/* This function is called from a threaded IRQ handler, and is therefore
	 * serialised with respect to itself. */

	/* With the list locked, mark the VIs as busy.  This will prevent
	 * anyone from freeing them. */
	spin_lock(&vec->vi_irq_lock);
	list_for_each_entry_safe(virs, next, &vec->vi_list, irq_link) {
		if (eventq_mark_callback_busy(rnic, virs->rs.rs_instance,
					      is_timeout, &contended)) {
			++num_vis;
			/* Mildly sneaky: just to make the code smaller we only keep track
			 * of 63 VIs' contention status on the vis list. Any more than
			 * that and we assume that they're all contended by exploiting
			 * arithmetic right shift. Assuming contention when there isn't
			 * will only make the callbacks unnecessarily defer all their
			 * work, it won't cause any functional harm. */
			if (contended && num_vis < 63)
				contended_seq |= (uint64_t)1 << num_vis;
			list_move_tail(&virs->irq_link, &vis);
		}
	}
	spin_unlock(&vec->vi_irq_lock);

	/* Now that we've dropped the lock, call the handlers. */
	list_for_each_entry(virs, &vis, irq_link) {
		int rc1 = eventq_do_callback(vec->nic, virs, is_timeout,
					     budget, contended_seq & 1);
		contended_seq >>= 1;
		if (rc1 >= 0) {
			EFRM_ASSERT(rc1 <= budget);
			budget -= rc;
			if (rc >= 0)
				rc += rc1;
		}
		else {
			/* We've hit a failure.  Poll any remaining EVQs with
			 * a budget of zero so that they can schedule deferred
			 * polling. */
			budget = 0;
			if (rc == 0)
				rc = rc1;
			else
				EFRM_TRACE("%s: EVQ %d callback failed (%d), "
					   "but can't propagate error",
					   __FUNCTION__, virs->rs.rs_instance,
					   rc1);
		}
	}

	/* Unmark the VIs as busy and return them to the list.  The busy-marker
	 * means that nobody can have attempted to free them, so returning them
	 * to the list is legitimate. */
	spin_lock(&vec->vi_irq_lock);
	list_for_each_entry(virs, &vis, irq_link)
		eventq_unmark_callback_busy(rnic, virs->rs.rs_instance);
	list_splice(&vis, &vec->vi_list);
	spin_unlock(&vec->vi_irq_lock);

	return rc;
}


int efrm_handle_wakeup_event(struct efhw_nic *nic, unsigned instance,
			     int budget)
{
	return efrm_eventq_do_callback(nic, instance, false, budget);
}

int efrm_handle_timeout_event(struct efhw_nic *nic, unsigned instance,
			      int budget)
{
	return efrm_eventq_do_callback(nic, instance, true, budget);
}

