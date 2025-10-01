/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */
#include <ci/efrm/private.h>
#include <ci/efrm/efct_rxq.h>
#include <ci/efrm/vi_resource.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/efct.h>
#include <linux/file.h>
#include <ci/driver/ci_efct.h>
#include "efrm_internal.h"
#include "debugfs_rs.h"


struct efrm_efct_rxq {
	struct efrm_resource rs;
	struct efrm_vi *vi;
	struct efhw_efct_rxq hw;
	struct work_struct free_work;

	struct list_head flush_link;
	struct list_head vi_link;
};

#if CI_HAVE_EFCT_COMMON
static bool check_efct(const struct efrm_resource *rs)
{
	if ((rs->rs_client->nic->devtype.arch != EFHW_ARCH_EFCT) &&
	    (rs->rs_client->nic->devtype.arch != EFHW_ARCH_EF10CT)) {
		EFRM_TRACE("%s: Only EFCT NIC supports rxq resources."
		           " Expected arch=%d or %d but got %d\n",
			   __FUNCTION__, EFHW_ARCH_EFCT, EFHW_ARCH_EF10CT,
			   rs->rs_client->nic->devtype.arch);
		return false;
	}
	return true;
}
#endif

extern struct efrm_resource* efrm_rxq_to_resource(struct efrm_efct_rxq *rxq)
{
	return &rxq->rs;
}
EXPORT_SYMBOL(efrm_rxq_to_resource);


extern struct efrm_efct_rxq* efrm_rxq_from_resource(struct efrm_resource *rs)
{
	return container_of(rs, struct efrm_efct_rxq, rs);
}
EXPORT_SYMBOL(efrm_rxq_from_resource);

#if CI_HAVE_EFCT_COMMON

#ifdef CONFIG_DEBUG_FS
static int efrm_debugfs_read_inq_size(struct seq_file *file,
	                              const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.krxq.shm;
	uint32_t val = CI_ARRAY_SIZE(shm->rxq.q);
	return efrm_debugfs_read_u32(file, &val);
}

static int efrm_debugfs_read_inq_level(struct seq_file *file,
	                               const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.krxq.shm;
	uint32_t val = shm->rxq.added - shm->rxq.removed;
	return efrm_debugfs_read_u32(file, &val);

}

static int efrm_debugfs_read_inq_full(struct seq_file *file,
	                              const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.krxq.shm;
	return efrm_debugfs_read_u32(file, &shm->stats.no_rxq_space);
}

static int efrm_debugfs_read_inq_empty(struct seq_file *file,
	                               const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.krxq.shm;
	return efrm_debugfs_read_u32(file, &shm->stats.no_bufs);
}


static int efrm_debugfs_read_outq_level(struct seq_file *file,
	                                const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.krxq.shm;
	uint32_t val = CI_ARRAY_SIZE(shm->freeq.q);
	return efrm_debugfs_read_u32(file, &val);
}

static int efrm_debugfs_read_outq_size(struct seq_file *file,
	                               const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.krxq.shm;
	uint32_t val = shm->freeq.added - shm->freeq.removed;
	return efrm_debugfs_read_u32(file, &val);
}

static int efrm_debugfs_read_sbufs_allowed(struct seq_file *file,
	                                   const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efhw_efct_rxq *app = &rxq->hw;
	return efrm_debugfs_read_u32(file, &app->krxq.max_allowed_superbufs);
}

static int efrm_debugfs_read_sbufs_owned(struct seq_file *file,
	                                 const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efhw_efct_rxq *app = &rxq->hw;
	return efrm_debugfs_read_u32(file, &app->krxq.current_owned_superbufs);
}

static int efrm_debugfs_read_sbufs_limited(struct seq_file *file,
	                                   const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.krxq.shm;
	return efrm_debugfs_read_u32(file, &shm->stats.too_many_owned);
}

static int efrm_debugfs_read_sbufs_skipped(struct seq_file *file,
	                                   const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.krxq.shm;
	return efrm_debugfs_read_u32(file, &shm->stats.skipped_bufs);
}

static int efrm_debugfs_read_sbufs_pkts_max(struct seq_file *file,
	                                    const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efhw_efct_rxq *app = &rxq->hw;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.krxq.shm;
	uint32_t val = app->krxq.max_allowed_superbufs * shm->superbuf_pkts;
	return efrm_debugfs_read_u32(file, &val);
}

static int efrm_debugfs_read_qix(struct seq_file *file, const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	uint32_t val = rxq->hw.qix;
	return efrm_debugfs_read_x32(file, &val);
}

static int efrm_debugfs_read_wake_at(struct seq_file *file, const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	uint32_t val = rxq->hw.wake_at_seqno;
	return efrm_debugfs_read_x32(file, &val);
}

static int efrm_debugfs_read_shared_evq(struct seq_file *file,
					const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	uint32_t val = rxq->hw.shared_evq;
	return efrm_debugfs_read_x32(file, &val);
}

static int efrm_debugfs_read_instance(struct seq_file *file, const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	uint32_t val = rxq->hw.wakeup_instance;
	return efrm_debugfs_read_u32(file, &val);
}

static int efrm_debugfs_read_last_req_seqno(struct seq_file *file,
					    const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	uint32_t val = rxq->hw.last_req_seqno;
	return efrm_debugfs_read_x32(file, &val);
}

static int efrm_debugfs_read_last_req_now(struct seq_file *file,
					  const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	uint32_t val = rxq->hw.last_req_now;
	return efrm_debugfs_read_x32(file, &val);
}

static const struct efrm_debugfs_parameter efrm_debugfs_efct_krxq_params[] = {
	_EFRM_RAW_PARAMETER(inq_size, efrm_debugfs_read_inq_size),
	_EFRM_RAW_PARAMETER(inq_level, efrm_debugfs_read_inq_level),
	_EFRM_RAW_PARAMETER(inq_full, efrm_debugfs_read_inq_full),
	_EFRM_RAW_PARAMETER(inq_empty, efrm_debugfs_read_inq_empty),
	_EFRM_RAW_PARAMETER(outq_size, efrm_debugfs_read_outq_size),
	_EFRM_RAW_PARAMETER(outq_level, efrm_debugfs_read_outq_level),
	_EFRM_RAW_PARAMETER(sbufs_allowed, efrm_debugfs_read_sbufs_allowed),
	_EFRM_RAW_PARAMETER(sbufs_owned, efrm_debugfs_read_sbufs_owned),
	_EFRM_RAW_PARAMETER(sbufs_limited, efrm_debugfs_read_sbufs_limited),
	_EFRM_RAW_PARAMETER(sbufs_skipped, efrm_debugfs_read_sbufs_skipped),
	_EFRM_RAW_PARAMETER(sbufs_pkts_max, efrm_debugfs_read_sbufs_pkts_max),
	{NULL},
};

static const struct efrm_debugfs_parameter efrm_debugfs_efct_urxq_params[] = {
	_EFRM_RAW_PARAMETER(qix, efrm_debugfs_read_qix),
	_EFRM_RAW_PARAMETER(wake_at_seqno, efrm_debugfs_read_wake_at),
	_EFRM_RAW_PARAMETER(wakeup_instance, efrm_debugfs_read_instance),
	_EFRM_RAW_PARAMETER(shared_evq, efrm_debugfs_read_shared_evq),
	_EFRM_RAW_PARAMETER(last_req_seqno, efrm_debugfs_read_last_req_seqno),
	_EFRM_RAW_PARAMETER(last_req_now, efrm_debugfs_read_last_req_now),
	{NULL},
};

#endif

static void efrm_init_debugfs_efct_rxq(struct efrm_efct_rxq *rxq, bool krxq)
{
#ifdef CONFIG_DEBUG_FS
	struct efrm_resource *rs = efrm_rxq_to_resource(rxq);
	struct efrm_resource *vi_rs = efrm_from_vi_resource(rxq->vi);
	efrm_debugfs_add_rs(rs, vi_rs, rxq->hw.qid);
	if( krxq )
		efrm_debugfs_add_rs_files(rs, efrm_debugfs_efct_krxq_params,
					  rxq);
	else
		efrm_debugfs_add_rs_files(rs, efrm_debugfs_efct_urxq_params,
					  rxq);
#endif
}

static void efrm_fini_debugfs_efct_rxq(struct efrm_efct_rxq *rxq)
{
#ifdef CONFIG_DEBUG_FS
	efrm_debugfs_remove_rs(&rxq->rs);
#endif
}

#endif

#if CI_HAVE_EFCT_COMMON
static void free_rxq_work(struct work_struct *data)
{
	struct efrm_efct_rxq *rmrxq = container_of(data, struct efrm_efct_rxq,
	                                           free_work);
	efrm_vi_resource_release(rmrxq->vi);
	kfree(rmrxq);
}

static void free_rxq(struct efhw_efct_rxq *rxq)
{
	struct efrm_efct_rxq *rmrxq = container_of(rxq, struct efrm_efct_rxq, hw);
	INIT_WORK(&rmrxq->free_work, free_rxq_work);
	queue_work(efrm_vi_manager->workqueue, &rmrxq->free_work);
}
#endif

int efrm_rxq_alloc(struct efrm_vi *vi, int qid, int shm_ix, bool timestamp_req,
                   bool interrupt_req, size_t n_hugepages,
                   struct oo_hugetlb_allocator *hugetlb_alloc,
                   struct efrm_efct_rxq **rxq_out)
{
#if CI_HAVE_EFCT_COMMON
	int rc;
	struct efrm_efct_rxq *rxq;
	struct efrm_resource *vi_rs = efrm_from_vi_resource(vi);
	struct efhw_shared_bind_params params = {
		.qid = qid,
		.timestamp_req = timestamp_req,
		.interrupt_req = interrupt_req,
		.n_hugepages = n_hugepages,
		.hugetlb_alloc = hugetlb_alloc,
		.shm = NULL,
		.wakeup_instance = vi->rs.rs_instance,
		.flags = vi->flags,
	};
	struct efhw_nic *nic;

	if (!check_efct(vi_rs))
		return -EOPNOTSUPP;

	nic = vi_rs->rs_client->nic;

	if (shm_ix >= 0 &&
	    shm_ix >= efhw_nic_max_shared_rxqs(nic))
		return -EINVAL;

	if (shm_ix >= 0 && !hugetlb_alloc)
		return -EINVAL;

	rxq = kzalloc(sizeof(struct efrm_efct_rxq), GFP_KERNEL);
	if (!rxq)
		return -ENOMEM;
	params.rxq = &rxq->hw;
	params.rxq->qix = shm_ix;

	if (shm_ix >= 0)
		params.shm = &vi->efct_shm->q[shm_ix];

	rxq->vi = vi;
	rc = efhw_nic_shared_rxq_bind(nic, &params);
	if (rc < 0)
		goto fail_bind;
	if( shm_ix >= 0 )
	  vi->efct_shm->active_qs |= 1ull << shm_ix;
	if( shm_ix < 0 ) {
		resource_size_t io_addr;
		rc = efhw_nic_rxq_window(nic, rxq->hw.qid, &io_addr);
		if( rc < 0 )
			goto fail_rxq_window;

		rxq->hw.urxq.rx_buffer_post_register = io_addr;
	}
	efrm_resource_init(&rxq->rs, EFRM_RESOURCE_EFCT_RXQ, 0);
	efrm_client_add_resource(vi_rs->rs_client, &rxq->rs);
	efrm_resource_ref(vi_rs);
	list_add_tail(&rxq->vi_link, &vi->efct_rxq_list);
	efrm_init_debugfs_efct_rxq(rxq, shm_ix >= 0);
	*rxq_out = rxq;
	return 0;

fail_rxq_window:
	efhw_nic_shared_rxq_unbind(nic, &rxq->hw, free_rxq);
fail_bind:
	kfree(rxq);
	return rc;
#else
	return -EOPNOTSUPP;
#endif
}
EXPORT_SYMBOL(efrm_rxq_alloc);

resource_size_t efrm_rxq_superbuf_window(struct efrm_efct_rxq *rxq)
{
	return rxq->hw.urxq.rx_buffer_post_register;
}
EXPORT_SYMBOL(efrm_rxq_superbuf_window);

struct efhw_efct_rxq *efrm_rxq_get_hw(struct efrm_efct_rxq *rxq)
{
	return &rxq->hw;
}
EXPORT_SYMBOL(efrm_rxq_get_hw);

static void dummy_freer(struct efhw_efct_rxq *rxq)
{
}

void efrm_rxq_flush(struct efrm_efct_rxq *rxq)
{
	int shm_ix = rxq->hw.qix;

	efhw_nic_shared_rxq_unbind(rxq->rs.rs_client->nic, &rxq->hw,
	                           dummy_freer);
	efrm_fini_debugfs_efct_rxq(rxq);
	if (shm_ix >= 0)
		rxq->vi->efct_shm->active_qs &= ~(1ull << shm_ix);
}
EXPORT_SYMBOL(efrm_rxq_flush);

void efrm_rxq_free(struct efrm_efct_rxq *rxq)
{
	if (__efrm_resource_release(&rxq->rs)) {
		struct efrm_client *rs_client = rxq->rs.rs_client;

		list_del(&rxq->vi_link);
		efrm_vi_resource_release(rxq->vi);
		kfree(rxq);
		efrm_client_put(rs_client);
	}
}
EXPORT_SYMBOL(efrm_rxq_free);

struct list_head *efrm_rxq_get_flush_list(struct efrm_efct_rxq *rxq)
{
	return &rxq->flush_link;
}
EXPORT_SYMBOL(efrm_rxq_get_flush_list);

struct efrm_efct_rxq *efrm_rxq_from_flush_list(struct list_head *list)
{
	return container_of(list, struct efrm_efct_rxq, flush_link);
}
EXPORT_SYMBOL(efrm_rxq_from_flush_list);

struct efrm_efct_rxq *efrm_rxq_from_vi_list(struct list_head *list)
{
	return container_of(list, struct efrm_efct_rxq, vi_link);
}
EXPORT_SYMBOL(efrm_rxq_from_vi_list);

struct efrm_vi *efrm_rxq_get_vi(struct efrm_efct_rxq *rxq)
{
	return rxq->vi;
}
EXPORT_SYMBOL(efrm_rxq_get_vi);

void efrm_rxq_release(struct efrm_efct_rxq *rxq)
{
#if CI_HAVE_EFCT_COMMON
	if (__efrm_resource_release(&rxq->rs)) {
		struct efrm_client* rs_client = rxq->rs.rs_client;
		int shm_ix = rxq->hw.qix;
		efrm_fini_debugfs_efct_rxq(rxq);
		if (shm_ix >= 0)
			rxq->vi->efct_shm->active_qs &= ~(1ull << shm_ix);
		list_del(&rxq->vi_link);
		efhw_nic_shared_rxq_unbind(rxq->rs.rs_client->nic, &rxq->hw,
					   free_rxq);
		/* caution! rxq may have been freed now */
		efrm_client_put(rs_client);
	}
#endif
}
EXPORT_SYMBOL(efrm_rxq_release);

int efrm_rxq_refresh(struct efrm_efct_rxq *rxq, unsigned long superbufs,
                     uint64_t __user *user_current, unsigned max_superbufs)
{
	return efhw_nic_shared_rxq_refresh(rxq->rs.rs_client->nic,
					   rxq->hw.qid, superbufs,
					   user_current, max_superbufs);
}
EXPORT_SYMBOL(efrm_rxq_refresh);


/* This function is identical to efrm_rxq_refresh(), except with the output
 * being pointers to kernelspace rather than userspace */
int efrm_rxq_refresh_kernel(struct efhw_nic *nic, int hwqid,
						    const char** superbufs)
{
  return efhw_nic_shared_rxq_refresh_kernel(nic, hwqid, superbufs);
}
EXPORT_SYMBOL(efrm_rxq_refresh_kernel);


int efrm_rxq_request_wakeup(struct efrm_efct_rxq *rxq, unsigned sbseq,
                            unsigned pktix, bool allow_recursion)
{
	struct efhw_nic *nic = rxq->vi->rs.rs_client->nic;
	return efhw_nic_shared_rxq_request_wakeup(nic, &rxq->hw, sbseq, pktix,
						  allow_recursion);
}
EXPORT_SYMBOL(efrm_rxq_request_wakeup);



static void efrm_rxq_rm_dtor(struct efrm_resource_manager *rm)
{
	/* NOP */
}


int efrm_create_rxq_resource_manager(struct efrm_resource_manager **rm_out)
{
	struct efrm_resource_manager *rm;
	int rc;

	rm = kzalloc(sizeof(*rm), GFP_KERNEL);
	if (rm == NULL)
		return -ENOMEM;

	rc = efrm_resource_manager_ctor(rm, efrm_rxq_rm_dtor, "RXQ",
	                                EFRM_RESOURCE_EFCT_RXQ);
	if (rc < 0)
		goto fail;

	*rm_out = rm;
	return 0;

fail:
	kfree(rm);
	return rc;
}
