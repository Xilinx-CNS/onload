/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides public API for vi_set resource.
 *
 * Copyright 2011-2011: Solarflare Communications Inc,
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

#include <ci/efrm/nic_table.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/private.h>
#include <ci/efrm/vi_set.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efrm/pd.h>
#include <ci/tools/log2.h>
#include "efrm_internal.h"
#include "efrm_vi_set.h"


#define efrm_vi_set(rs1)  container_of((rs1), struct efrm_vi_set, rs)


static int
efrm_rss_context_alloc_and_init(struct efrm_pd *pd,
				struct efrm_client *client,
				int num_qs,
				int rss_mode,
				struct efrm_rss_context* rss_context)
{
	int rc;
	int shared = 0;
	int index;
	/* Copied from efx_rss_fixed_key from linux_net/efx.c.
	 * FIXME: maintain consistency with net driver and tests. */
	static const uint8_t rx_hash_key_default[EFRM_RSS_KEY_LEN] = {
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	};
        /* With some hardware and/or firmware variants only
         * default mode is supported.  If any other mode is
         * asked for - fail. */
	if (num_qs > 1 && rss_mode != EFHW_RSS_MODE_DEFAULT &&
	    (!(efrm_client_get_nic(client)->flags & NIC_FLAG_ADDITIONAL_RSS_MODES) ||
	     (efrm_client_get_nic(client)->flags & NIC_FLAG_RX_RSS_LIMITED)))
		return -EOPNOTSUPP;

	rss_context->rss_mode = rss_mode;

	/* If the number of queues needed is a power of 2 we can simply use
	 * one of the shared contexts.
	 * If nic reports RX_RSS_LIMITED, shared rss contexts do not exist,
	 * so we must allocate an exclusive one.
	 * Alternative RSS hashes require individual RSS context.
	 */
	if (CI_IS_POW2(num_qs) &&
	    !(efrm_client_get_nic(client)->flags & NIC_FLAG_RX_RSS_LIMITED) &&
	    rss_mode == EFHW_RSS_MODE_DEFAULT) {
		shared = 1;
	}

	/* TODO: I've disabled use of shared RSS contexts because the
	 * firmware generates random hash keys by default.  This may give
	 * poor spreading, and won't be symmetric.  Once firmware has been
	 * fixed for a while we can re-enable shared contexts (or provide
	 * an option).
	 */
	shared = 0;

	/* Set up the indirection table to stripe evenly(ish) across VIs. */
	for (index = 0; index < EFRM_RSS_INDIRECTION_TABLE_LEN; index++)
		rss_context->indirection_table[index] = index % num_qs;

	/* Currently we always use the same key for the RSS hash. */
	EFRM_BUILD_ASSERT(sizeof(rss_context->rss_hash_key) ==
			  sizeof(rx_hash_key_default));
	memcpy(rss_context->rss_hash_key, rx_hash_key_default,
	       sizeof(rss_context->rss_hash_key));

	/* The maximum number of queues can't be larger than 64 */
	EFRM_ASSERT(num_qs <= 64);

	/* All queues in the set are used in the table initially. */
	rss_context->indirected_vis = (( num_qs < 64 ) ? (1ull << num_qs) : 0) - 1;

	/* If we have an exclusive context we need to set up the key and
	 * indirection table.
	 *
	 * We use fixed key, that:
	 * 1. has been tested and found to provide
	 * good spreading behaviour (random keys do not give such warranty).
	 *
	 * 2. matches net driver's rss key, meaning
	 * guarantees the same spreading regardless whether net driver's or private
	 * rss context is used (applies to 7000 series devices only).
	 * NOTE1: netdriver might be configured to use random key.
	 * NOTE2: shared keys currently are set with random keys by fw.
	 *
	 * The same key accross devices will ensure the identical spreading,
	 * which is important for maintaining proper opration after bond
	 * reconfiguration or fallover.
	 * Also Transparent proxy requires identical rss key on its devices.
	 */

	rc = efrm_rss_context_alloc(client, efrm_pd_get_vport_id(pd),
				    shared, rss_context->indirection_table,
				    rss_context->rss_hash_key, rss_mode,
				    num_qs, &rss_context->rss_context_id);
	return rc;
}


int efrm_vi_set_alloc(struct efrm_pd *pd, int n_vis,
		      int rss_modes,
		      struct efrm_vi_set **vi_set_out)
{
	struct efrm_client *client;
	struct efrm_vi_set *vi_set;
	struct efrm_nic *efrm_nic;
	int i, j, rc;
	int rss_limited;
	struct efrm_alloc_vi_constraints avc = {
		.channel = -1,
		.min_vis_in_set = n_vis,
		.has_rss_context = 0,
		/* We don't know the details of individual vis when allocating
		 * a set, so assume we may want a txq. */
		.want_txq = true,
	};
	EFRM_ASSERT(0 == (rss_modes &
		  ~(EFHW_RSS_MODE_DEFAULT|EFHW_RSS_MODE_SRC|EFHW_RSS_MODE_DST)));
	EFRM_ASSERT(rss_modes & (EFHW_RSS_MODE_DEFAULT|EFHW_RSS_MODE_SRC));
	/* mode default and src are exclusive */
	EFRM_ASSERT(~rss_modes & (EFHW_RSS_MODE_DEFAULT|EFHW_RSS_MODE_SRC));
	if (n_vis < 1 || n_vis > 64) {
		EFRM_ERR("%s: ERROR: set size=%d out of range (max=64)",
			 __FUNCTION__, n_vis);
		return -EINVAL;
	}

	if ((vi_set = kmalloc(sizeof(*vi_set), GFP_KERNEL)) == NULL)
		return -ENOMEM;

	client = efrm_pd_to_resource(pd)->rs_client;
	efrm_nic = container_of(client->nic, struct efrm_nic, efhw_nic);
	avc.efhw_nic = &efrm_nic->efhw_nic;
	rss_limited =
		efrm_client_get_nic(client)->flags & NIC_FLAG_RX_RSS_LIMITED;

	for (i = 0; i <= EFRM_RSS_MODE_ID_MAX; ++i)
		vi_set->rss_context[i].rss_context_id = -1;

	if (!(n_vis > 1 || rss_limited)) {
		/* Don't bother allocating a context of size 1, just use
		 * the netdriver's context.
		 */
		goto skip_context_alloc;
	}
	for (j = 0; rss_modes; j++) {
		/* least significant bit of rss_modes */
		int rss_mode = rss_modes ^ (rss_modes & (rss_modes -1));
		rss_modes &= ~rss_mode;
		rc = efrm_rss_context_alloc_and_init(pd, client, n_vis,
						     rss_mode,
						     &vi_set->rss_context[j]);
		/* If we failed to allocate an RSS context fall back to
		* using the netdriver's default context.
		*
		* This can occur if the FW does not support allocating an
		* RSS context, or if it's out of contexts.
		*/
		if (rc != 0) {
			/* If RX_RSS_LIMITED is set, the netdriver will not
			 * have allocated a default context.
			 */
			if (rss_limited)
				goto fail1;

			if (rc != -EOPNOTSUPP)
				EFRM_ERR("%s: WARNING: Failed to allocate RSS "
					 "context of size %d (rc %d), falling "
					 "back to default context.",
					 __FUNCTION__, n_vis, rc);
		}
		else {
			avc.has_rss_context = 1;
		}
	}

 skip_context_alloc:
	rc = efrm_vi_allocator_alloc_set(efrm_nic, &avc, &vi_set->allocation);
	if (rc != 0)
		goto fail1;
	efrm_resource_init(&vi_set->rs, EFRM_RESOURCE_VI_SET,
			vi_set->allocation.instance);
	efrm_client_add_resource(client, &vi_set->rs);
	vi_set->pd = pd;
	efrm_resource_ref(efrm_pd_to_resource(pd));
	vi_set->free = 0;
	for (i = 0; i < n_vis; ++i )
		vi_set->free |= 1ULL << i;
	spin_lock_init(&vi_set->allocation_lock);
	vi_set->n_vis = n_vis;
	init_completion(&vi_set->allocation_completion);
	vi_set->n_vis_flushing = 0;
	vi_set->n_flushing_waiters = 0;
	*vi_set_out = vi_set;

	return 0;
 fail1:
	for (i = 0; i <= EFRM_RSS_MODE_ID_MAX; ++i) {
		struct efrm_rss_context* context = &vi_set->rss_context[i];
		if (context->rss_context_id != -1)
			efrm_rss_context_free(client, context->rss_context_id);
	}

	return rc;
}
EXPORT_SYMBOL(efrm_vi_set_alloc);


static void iterate_queue(int num_queues, uint64_t* bitmap, uint32_t* index)
{
	uint32_t rotations = 0;

	EFRM_ASSERT(*bitmap);
	EFRM_ASSERT(*index < num_queues);
	EFRM_ASSERT(num_queues <= sizeof(*bitmap) * 8);

	/* The idea here is to rotate the queue bitmap to the right until the
	 * next non-zero bit has made its way to the bottom bit. */
	do {
		uint64_t low_bit = *bitmap & 1;
		*bitmap >>= 1;
		*bitmap |= low_bit << (num_queues - 1);
		++rotations;
	} while (~*bitmap & 1);

	/* Bump the returned index by the number of rotations that we made. */
	*index = (*index + rotations) % num_queues;
}


/* This function rewrites the indirection table such that all traffic currently
 * sent to the queue with ID [q_id] (relative to the start of the VI set)
 * will be sent instead to other queues in the set. */
static int
__efrm_vi_set_redistribute_queue(struct efrm_vi_set* vi_set,
				 int vi_set_rss_context, uint32_t q_id)
{
	struct efrm_rss_context* rss_context =
		&vi_set->rss_context[vi_set_rss_context];
	uint32_t indir_table_copy[EFRM_RSS_INDIRECTION_TABLE_LEN];
	uint32_t new_q;
	int new_q_relative;
	uint64_t rotated_queues;
	int index;
	int rotated_q_id_index;
	int rc;

	/* Queue already not receiving traffic? */
	if (~rss_context->indirected_vis & (1ull << q_id))
		return -EALREADY;

	/* No other queues available to replace it? */
	if (CI_IS_POW2(rss_context->indirected_vis))
		return -EBUSY;

	/* Work on a copy of the initial state of the indirection table in case
	 * we get a failure from driverlink. */
	EFRM_BUILD_ASSERT(sizeof(indir_table_copy) ==
			  sizeof(rss_context->indirection_table));
	memcpy(indir_table_copy, rss_context->indirection_table,
	       sizeof(indir_table_copy));

	EFRM_ASSERT(vi_set->n_vis > 0);
	EFRM_ASSERT(hweight64(rss_context->indirected_vis) <= vi_set->n_vis);

	/* The initial value of [new_q] determines the first queue that will be
	 * substituted in place of the old one.  Thereafter, we round-robin
	 * amongst the queues that are still in the set.  We pick the initial
	 * value here to be biased in favour of queues that are disadvantaged
	 * by the initial state of the indirection table.  The calculation
	 * involves first finding [new_q_relative], which is the index within
	 * the set of queues previously in [indirected_vis], and then
	 * converting this to the value actually used in the RSS table by using
	 * iterate_queue(). */
	rotated_queues = rss_context->indirected_vis;
	new_q = 0;
	if (! (rotated_queues & 1) )
		iterate_queue(vi_set->n_vis, &rotated_queues, &new_q);
	/* [new_q] is now equal to the first queue referenced by the RSS table
	 * at entry to this function, which would correspond to a value of zero
	 * for [new_q_relative]. */
	new_q_relative = 128 % hweight64(rotated_queues);
	for (index = 0; index < new_q_relative; ++index)
		iterate_queue(vi_set->n_vis, &rotated_queues, &new_q);
	/* [new_q] is now equal to the next queue in the set after that in the
	 * final bucket, and this is the first value with which we should
	 * replace table-entries for the queue that we're removing... unless,
	 * that is, that this is itself the queue to be removed, in which case
	 * we should bump it on to the next one. */
	if (new_q == q_id)
		iterate_queue(vi_set->n_vis, &rotated_queues, &new_q);
	/* Finally, remove queue [q_id] from the set over which we iterate.  In
	 * doing so, we have to account for the rotation that we've already
	 * applied to [rotated_queues]. */
	rotated_q_id_index = (q_id - new_q + vi_set->n_vis) % vi_set->n_vis;
	rotated_queues &= ~(1ull << rotated_q_id_index);

	for (index = 0; index < EFRM_RSS_INDIRECTION_TABLE_LEN; index++)
		if (rss_context->indirection_table[index] == q_id) {
			iterate_queue(vi_set->n_vis, &rotated_queues, &new_q);
			EFRM_ASSERT(new_q != q_id);
			EFRM_ASSERT(rss_context->indirected_vis &
				    (1ull << new_q));
			indir_table_copy[index] = new_q;
		}

	/* Push the changes to the NIC. */
	rc = efrm_rss_context_update(vi_set->rs.rs_client,
				     rss_context->rss_context_id,
				     indir_table_copy,
				     rss_context->rss_hash_key,
				     rss_context->rss_mode);
	if (rc == 0) {
		/* Now that we've successfully reprogrammed the NIC, update
		 * our record of the indirection table. */
		memcpy(rss_context->indirection_table, indir_table_copy,
		       sizeof(indir_table_copy));
		/* Remember the fact that the queue is no longer receiving
		 * traffic. */
		rss_context->indirected_vis &= ~(1ull << q_id);

	}

	return rc;
}


int efrm_vi_set_redistribute_queue(struct efrm_vi_set* vi_set, uint32_t q_id)
{
	int i;
	int rc = 0;

	for (i = 0; i <= EFRM_RSS_MODE_ID_MAX; ++i) {
		if (vi_set->rss_context[i].rss_context_id != -1) {
			int rc1 = __efrm_vi_set_redistribute_queue(vi_set, i,
								   q_id);
			if (rc1 < 0) {
				rc = rc1;
				EFRM_ERR("%s: Failed to remove queue %u from "
					 "VI set: rc1=%d", __FUNCTION__, q_id,
					 rc1);
			}
		}
	}

	return rc;
}
EXPORT_SYMBOL(efrm_vi_set_redistribute_queue);


void efrm_vi_set_release(struct efrm_vi_set *vi_set)
{
	if (__efrm_resource_release(&vi_set->rs))
		efrm_vi_set_free(vi_set);
}
EXPORT_SYMBOL(efrm_vi_set_release);


void efrm_vi_set_free(struct efrm_vi_set *vi_set)
{
	struct efrm_nic *efrm_nic;
	int n_free;
	uint64_t free = vi_set->free;
	int i;
	efrm_nic = container_of(vi_set->rs.rs_client->nic,
				struct efrm_nic, efhw_nic);

	for (i = 0; i <= EFRM_RSS_MODE_ID_MAX; ++i) {
		struct efrm_rss_context* context = &vi_set->rss_context[i];
		if (context->rss_context_id != -1)
			efrm_rss_context_free(vi_set->rs.rs_client,
					      context->rss_context_id);
	}
	efrm_vi_allocator_free_set(efrm_nic, &vi_set->allocation);
	efrm_pd_release(vi_set->pd);
	efrm_client_put(vi_set->rs.rs_client);

	for (n_free = 0; free; ++n_free)
		free &= free - 1;
	EFRM_ASSERT(n_free == vi_set->n_vis);
	kfree(vi_set);
}


int efrm_vi_set_num_vis(struct efrm_vi_set *vi_set)
{
	return vi_set->n_vis;
}
EXPORT_SYMBOL(efrm_vi_set_num_vis);


int efrm_vi_set_get_base(struct efrm_vi_set *vi_set)
{
	return vi_set->allocation.instance;
}
EXPORT_SYMBOL(efrm_vi_set_get_base);


int efrm_vi_set_get_rss_context(struct efrm_vi_set *vi_set, unsigned rss_id)
{
	EFRM_ASSERT(rss_id <= EFRM_RSS_MODE_ID_MAX);
	return vi_set->rss_context[rss_id].rss_context_id;
}
EXPORT_SYMBOL(efrm_vi_set_get_rss_context);


struct efrm_resource * efrm_vi_set_to_resource(struct efrm_vi_set *vi_set)
{
	return &vi_set->rs;
}
EXPORT_SYMBOL(efrm_vi_set_to_resource);


struct efrm_vi_set * efrm_vi_set_from_resource(struct efrm_resource *rs)
{
	return efrm_vi_set(rs);
}
EXPORT_SYMBOL(efrm_vi_set_from_resource);


struct efrm_pd* efrm_vi_set_get_pd(struct efrm_vi_set *vi_set)
{
	return vi_set->pd;
}
EXPORT_SYMBOL(efrm_vi_set_get_pd);


static void efrm_vi_set_rm_dtor(struct efrm_resource_manager *rm)
{
}


int
efrm_create_vi_set_resource_manager(struct efrm_resource_manager **rm_out)
{
	struct efrm_resource_manager *rm;
	int rc;

	rm = kmalloc(sizeof(*rm), GFP_KERNEL);
	if (rm == NULL)
		return -ENOMEM;
	memset(rm, 0, sizeof(*rm));

	rc = efrm_resource_manager_ctor(rm, efrm_vi_set_rm_dtor, "VI_SET",
					EFRM_RESOURCE_VI_SET);
	if (rc < 0)
		goto fail1;

	*rm_out = rm;
	return 0;

fail1:
	kfree(rm);
	return rc;
}
