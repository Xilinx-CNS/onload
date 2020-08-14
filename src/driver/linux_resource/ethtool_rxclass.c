/* X-SPDX-Source-URL: https://git.kernel.org/pub/scm/network/ethtool/ethtool.git */
/* X-SPDX-Source-Tag: beeb50531786f64d1f78953a362941c0b1a4219b */
/* X-SPDX-Source-File: rxclass.c */
/* SPDX-License-Identifier: GPL-2.0-only */
/* X-SPDX-Comment: This file has minor modifications to enable it to be built
 *                 in the onload kernel environment as well as removing
 *                 functionality not used by onload. */

/*
 * Copyright (C) 2008 Sun Microsystems, Inc. All rights reserved.
 */


#include <linux/ethtool.h>
#include "linux_resource_internal.h"


static int send_ioctl(struct cmd_context *ctx, void* cmd)
{
	struct ethtool_rxnfc *info = (struct ethtool_rxnfc*)cmd;
	const struct ethtool_ops *ops = ctx->netdev->ethtool_ops;

	if (!ops->get_rxnfc)
		return -EOPNOTSUPP;

	EFRM_ASSERT((info->cmd == ETHTOOL_GRXCLSRLCNT) ||
		    (info->cmd == ETHTOOL_GRXCLSRLALL));

	return ops->get_rxnfc(ctx->netdev, info, info->rule_locs);
}

static int rxclass_get_dev_info(struct cmd_context *ctx, __u32 *count,
				int *driver_select)
{
	struct ethtool_rxnfc nfccmd;
	int err;

	nfccmd.cmd = ETHTOOL_GRXCLSRLCNT;
	nfccmd.data = 0;
	nfccmd.rule_cnt = 0;
	err = send_ioctl(ctx, &nfccmd);
	*count = nfccmd.rule_cnt;
	if (driver_select)
		*driver_select = !!(nfccmd.data & RX_CLS_LOC_SPECIAL);
	if (err < 0)
		EFRM_WARN("%s: rxclass: Cannot get RX class rule count",
			  __FUNCTION__);

	return err;
}

/*
 * This is a simple rule manager implementation for ordering rx flow
 * classification rules based on newest rules being first in the list.
 * The assumption is that this rule manager is the only one adding rules to
 * the device's hardware classifier.
 */

struct rmgr_ctrl {
	/* flag for device/driver that can select locations itself */
	int			driver_select;
	/* slot contains a bitmap indicating which filters are valid */
	unsigned long		*slot;
	__u32			n_rules;
	__u32			size;
};

static int rmgr_ins(struct rmgr_ctrl *rmgr, __u32 loc)
{
	/* verify location is in rule manager range */
	if (loc >= rmgr->size) {
		EFRM_WARN("%s: rmgr: Location out of range\n", __FUNCTION__);
		return -1;
	}

	/* set bit for the rule */
	set_bit(loc, rmgr->slot);

	return 0;
}

static int rmgr_find_empty_slot(struct rmgr_ctrl *rmgr,
				struct ethtool_rx_flow_spec *fsp)
{
	__u32 loc;
	__u32 slot_num;

	/* leave this to the driver if possible */
	if (rmgr->driver_select)
		return 0;

	/* start at the end of the list since it is lowest priority */
	loc = rmgr->size - 1;

	/* locate the first slot a rule can be placed in */
	slot_num = loc / BITS_PER_LONG;

	/*
	 * Avoid testing individual bits by inverting the word and checking
	 * to see if any bits are left set, if so there are empty spots.  By
	 * moving 1 + loc % BITS_PER_LONG we align ourselves to the last bit
	 * in the previous word.
	 *
	 * If loc rolls over it should be greater than or equal to rmgr->size
	 * and as such we know we have reached the end of the list.
	 */
	if (!~(rmgr->slot[slot_num] | (~1UL << rmgr->size % BITS_PER_LONG))) {
		loc -= 1 + (loc % BITS_PER_LONG);
		slot_num--;
	}

	/*
	 * Now that we are aligned with the last bit in each long we can just
	 * go though and eliminate all the longs with no free bits
	 */
	while (loc < rmgr->size && !~(rmgr->slot[slot_num])) {
		loc -= BITS_PER_LONG;
		slot_num--;
	}

	/*
	 * If we still are inside the range, test individual bits as one is
	 * likely available for our use.
	 */
	while (loc < rmgr->size && test_bit(loc, rmgr->slot))
		loc--;

	/* location found, insert rule */
	if (loc < rmgr->size) {
		fsp->location = loc;
		return rmgr_ins(rmgr, loc);
	}

	/* No space to add this rule */
	EFRM_WARN("%s: rmgr: Cannot find appropriate slot to insert rule\n",
		  __FUNCTION__);

	return -1;
}

static int rmgr_init(struct cmd_context *ctx, struct rmgr_ctrl *rmgr)
{
	struct ethtool_rxnfc *nfccmd;
	int err, i;
	__u32 *rule_locs;

	/* clear rule manager settings */
	memset(rmgr, 0, sizeof(*rmgr));

	/* request device/driver information */
	err = rxclass_get_dev_info(ctx, &rmgr->n_rules, &rmgr->driver_select);
	if (err < 0)
		return err;

	/* do not get the table if the device/driver can select locations */
	if (rmgr->driver_select)
		return 0;

	/* alloc memory for request of location list */
	nfccmd = kzalloc(sizeof(*nfccmd) + (rmgr->n_rules * sizeof(__u32)),
			 GFP_KERNEL);
	if (!nfccmd) {
		EFRM_WARN("%s: rmgr: Cannot allocate memory for"
			  " RX class rule locations", __FUNCTION__);
		return -1;
	}

	/* request location list */
	nfccmd->cmd = ETHTOOL_GRXCLSRLALL;
	nfccmd->rule_cnt = rmgr->n_rules;
	err = send_ioctl(ctx, nfccmd);
	if (err < 0) {
		EFRM_WARN("%s: rmgr: Cannot get RX class rules", __FUNCTION__);
		kfree(nfccmd);
		return err;
	}

	/* make certain the table size is valid */
	rmgr->size = nfccmd->data;
	if (rmgr->size == 0 || rmgr->size < rmgr->n_rules) {
		EFRM_WARN("%s: rmgr: Invalid RX class rules table size",
			  __FUNCTION__);
		return -1;
	}

	/* initialize bitmap for storage of valid locations */
	rmgr->slot = kzalloc(BITS_TO_LONGS(rmgr->size) * sizeof(long),
			     GFP_KERNEL);
	if (!rmgr->slot) {
		EFRM_WARN("%s: rmgr: Cannot allocate memory for RX class rules",
			  __FUNCTION__);
		return -1;
	}

	/* write locations to bitmap */
	rule_locs = nfccmd->rule_locs;
	for (i = 0; i < rmgr->n_rules; i++) {
		err = rmgr_ins(rmgr, rule_locs[i]);
		if (err < 0)
			break;
	}

	kfree(nfccmd);

	return err;
}

static void rmgr_cleanup(struct rmgr_ctrl *rmgr)
{
	kfree(rmgr->slot);
	rmgr->slot = NULL;
	rmgr->size = 0;
}

int rmgr_set_location(struct cmd_context *ctx,
			     struct ethtool_rx_flow_spec *fsp)
{
	struct rmgr_ctrl rmgr;
	int err;

	/* init table of available rules */
	err = rmgr_init(ctx, &rmgr);
	if (err < 0)
		goto out;

	/* verify rule location */
	err = rmgr_find_empty_slot(&rmgr, fsp);

out:
	/* cleanup table and free resources */
	rmgr_cleanup(&rmgr);

	return err;
}

