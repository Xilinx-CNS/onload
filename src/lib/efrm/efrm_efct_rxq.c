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
#include <kernel_utils/hugetlb.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <ci/driver/ci_efct.h>
#include "efrm_internal.h"
#include "debugfs_rs.h"


#ifndef page_to_virt
/* Needed for RHEL7 only */
#define page_to_virt(page) __va(page_to_pfn(page) << PAGE_SHIFT)
#endif

struct efrm_efct_rxq {
	struct efrm_resource rs;
	struct efrm_vi *vi;
	struct efhw_efct_rxq hw;
	struct work_struct free_work;
};

#if CI_HAVE_EFCT_AUX
static bool check_efct(const struct efrm_resource *rs)
{
	if (rs->rs_client->nic->devtype.arch != EFHW_ARCH_EFCT) {
		EFRM_TRACE("%s: Only EFCT NIC supports rxq resources."
		           " Expected arch=%d but got %d\n", __FUNCTION__,
		           EFHW_ARCH_EFCT, rs->rs_client->nic->devtype.arch);
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

#if CI_HAVE_EFCT_AUX

#ifdef CONFIG_DEBUG_FS
static int efrm_debugfs_read_inq_size(struct seq_file *file,
	                              const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.shm;
	uint32_t val = CI_ARRAY_SIZE(shm->rxq.q);
	return efrm_debugfs_read_u32(file, &val);
}

static int efrm_debugfs_read_inq_level(struct seq_file *file,
	                               const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.shm;
	uint32_t val = shm->rxq.added - shm->rxq.removed;
	return efrm_debugfs_read_u32(file, &val);

}

static int efrm_debugfs_read_inq_full(struct seq_file *file,
	                              const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.shm;
	return efrm_debugfs_read_u32(file, &shm->stats.no_rxq_space);
}

static int efrm_debugfs_read_inq_empty(struct seq_file *file,
	                               const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.shm;
	return efrm_debugfs_read_u32(file, &shm->stats.no_bufs);
}


static int efrm_debugfs_read_outq_level(struct seq_file *file,
	                                const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.shm;
	uint32_t val = CI_ARRAY_SIZE(shm->freeq.q);
	return efrm_debugfs_read_u32(file, &val);
}

static int efrm_debugfs_read_outq_size(struct seq_file *file,
	                               const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.shm;
	uint32_t val = shm->freeq.added - shm->freeq.removed;
	return efrm_debugfs_read_u32(file, &val);
}

static int efrm_debugfs_read_sbufs_allowed(struct seq_file *file,
	                                   const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efhw_efct_rxq *app = &rxq->hw;
	return efrm_debugfs_read_u32(file, &app->max_allowed_superbufs);
}

static int efrm_debugfs_read_sbufs_owned(struct seq_file *file,
	                                 const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efhw_efct_rxq *app = &rxq->hw;
	return efrm_debugfs_read_u32(file, &app->current_owned_superbufs);
}

static int efrm_debugfs_read_sbufs_limited(struct seq_file *file,
	                                   const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.shm;
	return efrm_debugfs_read_u32(file, &shm->stats.too_many_owned);
}

static int efrm_debugfs_read_sbufs_skipped(struct seq_file *file,
	                                   const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.shm;
	return efrm_debugfs_read_u32(file, &shm->stats.skipped_bufs);
}

static int efrm_debugfs_read_sbufs_pkts_max(struct seq_file *file,
	                                    const void *data)
{
	struct efrm_efct_rxq *rxq = (struct efrm_efct_rxq *)data;
	struct efhw_efct_rxq *app = &rxq->hw;
	struct efab_efct_rxq_uk_shm_q *shm = rxq->hw.shm;
	uint32_t val = app->max_allowed_superbufs * shm->superbuf_pkts;
	return efrm_debugfs_read_u32(file, &val);
}

static const struct efrm_debugfs_parameter efrm_debugfs_efct_rxq_parameters[] = {
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
#endif

static void efrm_init_debugfs_efct_rxq(struct efrm_efct_rxq *rxq)
{
#ifdef CONFIG_DEBUG_FS
	struct efrm_resource *rs = efrm_rxq_to_resource(rxq);
	struct efrm_resource *vi_rs = efrm_from_vi_resource(rxq->vi);
	efrm_debugfs_add_rs(rs, vi_rs, rxq->hw.qid);
	efrm_debugfs_add_rs_files(rs, efrm_debugfs_efct_rxq_parameters, rxq);
#endif
}

static void efrm_fini_debugfs_efct_rxq(struct efrm_efct_rxq *rxq)
{
#ifdef CONFIG_DEBUG_FS
	efrm_debugfs_remove_rs(&rxq->rs);
#endif
}

#endif

int efrm_rxq_alloc(struct efrm_vi *vi, int qid, int shm_ix, bool timestamp_req,
                   size_t n_hugepages,
                   struct oo_hugetlb_allocator *hugetlb_alloc,
                   struct efrm_efct_rxq **rxq_out)
{
#if CI_HAVE_EFCT_AUX
	int rc;
	struct efrm_efct_rxq *rxq;
	struct efrm_resource *vi_rs = efrm_from_vi_resource(vi);

	if (!check_efct(vi_rs))
		return -EOPNOTSUPP;

	if (shm_ix < 0 ||
	    shm_ix >= efhw_nic_max_shared_rxqs(vi_rs->rs_client->nic) ||
	    !hugetlb_alloc)
		return -EINVAL;

	rxq = kzalloc(sizeof(struct efrm_efct_rxq), GFP_KERNEL);
	if (!rxq)
		return -ENOMEM;

	rxq->vi = vi;
	rc = efct_nic_rxq_bind(vi_rs->rs_client->nic, qid, timestamp_req,
	                       n_hugepages, hugetlb_alloc,
	                       &vi->efct_shm->q[shm_ix], vi->rs.rs_instance,
	                       &rxq->hw);
	if (rc < 0) {
		kfree(rxq);
		return rc;
	}
	vi->efct_shm->active_qs |= 1ull << shm_ix;
	efrm_resource_init(&rxq->rs, EFRM_RESOURCE_EFCT_RXQ, 0);
	efrm_client_add_resource(vi_rs->rs_client, &rxq->rs);
	efrm_resource_ref(vi_rs);
	efrm_init_debugfs_efct_rxq(rxq);
	*rxq_out = rxq;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}
EXPORT_SYMBOL(efrm_rxq_alloc);


#if CI_HAVE_EFCT_AUX
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

void efrm_rxq_release(struct efrm_efct_rxq *rxq)
{
#if CI_HAVE_EFCT_AUX
	if (__efrm_resource_release(&rxq->rs)) {
		int shm_ix = rxq->hw.shm - rxq->vi->efct_shm->q;
		struct efrm_client* rs_client = rxq->rs.rs_client;
		efrm_fini_debugfs_efct_rxq(rxq);
		rxq->vi->efct_shm->active_qs &= ~(1ull << shm_ix);
		efct_nic_rxq_free(rxq->rs.rs_client->nic, &rxq->hw, free_rxq);
		/* caution! rxq may have been freed now */
		efrm_client_put(rs_client);
	}
#endif
}
EXPORT_SYMBOL(efrm_rxq_release);


#if CI_HAVE_EFCT_AUX

#define REFRESH_BATCH_SIZE  8
#define EFCT_INVALID_PFN   (~0ull)

static int map_one_superbuf(unsigned long addr,
                            const struct xlnx_efct_hugepage *kern)
{
	unsigned long rc;
	rc = vm_mmap(kern->file, addr, CI_HUGEPAGE_SIZE, PROT_READ,
	             MAP_FIXED | MAP_SHARED | MAP_POPULATE |
	                 MAP_HUGETLB | MAP_HUGE_2MB,
	             oo_hugetlb_page_offset(kern->page));
	if (IS_ERR((void*)rc))
		return PTR_ERR((void*)rc);
	return 0;
}

static int fixup_superbuf_mapping(unsigned long addr,
                                  uint64_t *user,
                                  const struct xlnx_efct_hugepage *kern,
                                  const struct xlnx_efct_hugepage *spare_page)
{
	uint64_t pfn = kern->page ? __pa(kern->page) : EFCT_INVALID_PFN;
	if (*user == pfn)
		return 0;

	if (pfn == EFCT_INVALID_PFN) {
		/* Rather than actually unmapping the memory, we prefer to map in some
		 * random other valid page instead. Ideally we'd use the huge zero
		 * page, but we can't get at that so we pick a random other one of our
		 * pages instead.
		 * The reason for all this is that we promise that
		 * ef_eventq_has_event() is safe to call concurrently with
		 * ef_eventq_poll(). The latter might call in to this function to
		 * unmap the exact page that the former is just about to look at. */
		if (!spare_page->page ||
		    map_one_superbuf(addr, spare_page))
			vm_munmap(addr, CI_HUGEPAGE_SIZE);
	}
	else {
		int rc = map_one_superbuf(addr, kern);
		if (rc)
			return rc;
	}
	*user = pfn;
	return 1;
}

#endif /* CI_HAVE_EFCT_AUX */

int efrm_rxq_refresh(struct efrm_efct_rxq *rxq, unsigned long superbufs,
                     uint64_t __user *user_current, unsigned max_superbufs)
{
#if CI_HAVE_EFCT_AUX
	struct xlnx_efct_hugepage *pages;
	struct xlnx_efct_hugepage spare_page = {};
	size_t i;
	int rc = 0;
	bool is_sbuf_err_logged = false;
	unsigned n_hugepages = CI_MIN(max_superbufs, (unsigned)CI_EFCT_MAX_SUPERBUFS) /
	                       CI_EFCT_SUPERBUFS_PER_PAGE;

	if (max_superbufs < CI_EFCT_MAX_SUPERBUFS) {
		EFRM_TRACE("max_superbufs: %u passed in by user less than kernel's: %u. "
		           "Ensure you do not create enough apps to donate more than %u "
		           "superbufs! Alternatively, applications should be compiled with"
							 "a newer userspace.", max_superbufs, CI_EFCT_MAX_SUPERBUFS,
		           n_hugepages * CI_EFCT_SUPERBUFS_PER_PAGE);
	}

	pages = kmalloc_array(CI_EFCT_MAX_HUGEPAGES, sizeof(pages[0]), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	rc = efct_get_hugepages(rxq->rs.rs_client->nic,
	                        rxq->hw.qid, pages, CI_EFCT_MAX_HUGEPAGES);
	if (rc < 0) {
		kfree(pages);
		return rc;
	}
	for (i = 0; i < CI_EFCT_MAX_HUGEPAGES; ++i) {
		if (pages[i].page) {
			/* See commentary in fixup_superbuf_mapping(). It'd be possible to
			 * have extensive debates about which is the least-worst page to
			 * use for this purpose, but any decision would be crystal ball
			 * work: we're trying to avoid wasting memory by having a page
			 * mapped which is used for no other purpose other than as our
			 * free page filler. */
			spare_page = pages[i];
			break;
		}
	}
	for (i = 0; i < n_hugepages; i += REFRESH_BATCH_SIZE) {
		uint64_t local_current[REFRESH_BATCH_SIZE];
		size_t j;
		size_t n = min((size_t)REFRESH_BATCH_SIZE,
		               n_hugepages - i);
		bool changes = false;

		if (copy_from_user(local_current, user_current + i,
		                   n * sizeof(*local_current))) {
			rc = -EFAULT;
			break;
		}

		for (j = 0; j < n; ++j) {
			rc = fixup_superbuf_mapping(
					superbufs + CI_HUGEPAGE_SIZE * (i + j),
					&local_current[j], &pages[i + j], &spare_page);
			if (rc < 0)
				break;
			if (rc)
				changes = true;
		}

		if (changes)
			if (copy_to_user(user_current + i, local_current,
			                 n * sizeof(*local_current)))
				rc = -EFAULT;

		if (rc < 0)
			break;
	}

	for (i = 0; i < CI_EFCT_MAX_HUGEPAGES; i++) {
		if (pages[i].page != NULL) {
			put_page(pages[i].page);
			fput(pages[i].file);
			if (i > n_hugepages && !is_sbuf_err_logged) {
				EFRM_ERR("More than %d superbufs have been donated. User max: %u, "
				         "kernel max: %u. Applications should be recompiled with a newer"
				         "userspace.",
				         n_hugepages * CI_EFCT_SUPERBUFS_PER_PAGE, max_superbufs,
				         CI_EFCT_MAX_SUPERBUFS);
				is_sbuf_err_logged = true;
			}
		}
	}

	kfree(pages);
	return rc;
#else
	return -EOPNOTSUPP;
#endif /* CI_HAVE_EFCT_AUX */
}
EXPORT_SYMBOL(efrm_rxq_refresh);


/* This function is identical to efrm_rxq_refresh(), except with the output
 * being pointers to kernelspace rather than userspace */
int efrm_rxq_refresh_kernel(struct efhw_nic *nic, int hwqid,
						    const char** superbufs)
{
#if CI_HAVE_EFCT_AUX
	struct xlnx_efct_hugepage *pages;
	size_t i;
	int rc = 0;

	pages = kmalloc_array(CI_EFCT_MAX_HUGEPAGES, sizeof(pages[0]), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	rc = efct_get_hugepages(nic, hwqid, pages, CI_EFCT_MAX_HUGEPAGES);
	if (rc < 0) {
		kfree(pages);
		return rc;
	}
	for (i = 0; i < CI_EFCT_MAX_SUPERBUFS; ++i) {
		struct page* page = pages[i / CI_EFCT_SUPERBUFS_PER_PAGE].page;
		superbufs[i] = page_to_virt(page) +
		              EFCT_RX_SUPERBUF_BYTES * (i % CI_EFCT_SUPERBUFS_PER_PAGE);
	}

	for (i = 0; i < CI_EFCT_MAX_HUGEPAGES; ++i) {
		if (pages[i].page != NULL) {
			put_page(pages[i].page);
			fput(pages[i].file);
		}
	}

	kfree(pages);
	return rc;
#else
	return -EOPNOTSUPP;
#endif /* CI_HAVE_EFCT_AUX */
}
EXPORT_SYMBOL(efrm_rxq_refresh_kernel);


int efrm_rxq_request_wakeup(struct efrm_efct_rxq *rxq, unsigned sbseq,
                            unsigned pktix, bool allow_recursion)
{
#if CI_HAVE_EFCT_AUX
	struct efhw_nic *nic = rxq->vi->rs.rs_client->nic;
	return efct_request_wakeup(nic->arch_extra, &rxq->hw, sbseq, pktix,
	                    allow_recursion);
#else
	return -ENOSYS;
#endif
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
