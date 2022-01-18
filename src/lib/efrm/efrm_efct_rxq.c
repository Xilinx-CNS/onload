/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */
#include <ci/efrm/private.h>
#include <ci/efrm/efct_rxq.h>
#include <ci/efrm/vi_resource.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/efct.h>
#include <linux/mman.h>
#include <ci/driver/ci_efct.h>
#include "efrm_internal.h"


#ifndef page_to_virt
/* Needed for RHEL7 only */
#define page_to_virt(page) __va(page_to_pfn(page) << PAGE_SHIFT)
#endif

struct efrm_efct_rxq {
	struct efrm_resource rs;
	struct efrm_vi *vi;
	struct efhw_efct_rxq hw;
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


int efrm_rxq_alloc(struct efrm_vi *vi, int qid, int shm_ix,
                   const struct cpumask *mask, bool timestamp_req,
                   size_t n_hugepages, struct file* memfd, off_t* memfd_off,
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
	    memfd_off < 0 )
		return -EINVAL;

	rxq = kzalloc(sizeof(struct efrm_efct_rxq), GFP_KERNEL);
	if (!rxq)
		return -ENOMEM;

	rxq->vi = vi;
	rc = efct_nic_rxq_bind(vi_rs->rs_client->nic, qid, mask, timestamp_req,
	                       n_hugepages, memfd, memfd_off,
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
	*rxq_out = rxq;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}
EXPORT_SYMBOL(efrm_rxq_alloc);


#if CI_HAVE_EFCT_AUX
static void free_rxq(struct efhw_efct_rxq *rxq)
{
	kfree(container_of(rxq, struct efrm_efct_rxq, hw));
}
#endif

void efrm_rxq_release(struct efrm_efct_rxq *rxq)
{
#if CI_HAVE_EFCT_AUX
	if (__efrm_resource_release(&rxq->rs)) {
		int shm_ix = rxq->hw.shm - rxq->vi->efct_shm->q;
		rxq->vi->efct_shm->active_qs &= ~(1ull << shm_ix);
		efct_nic_rxq_free(rxq->rs.rs_client->nic, &rxq->hw, free_rxq);
		efrm_vi_resource_release(rxq->vi);
		efrm_client_put(rxq->rs.rs_client);
	}
#endif
}
EXPORT_SYMBOL(efrm_rxq_release);


#if CI_HAVE_EFCT_AUX

#define REFRESH_BATCH_SIZE  8
#define EFCT_INVALID_PFN   (~0ull)

static int fixup_superbuf_mapping(unsigned long addr,
                                  uint64_t *user,
                                  const struct xlnx_efct_hugepage *kern)
{
	uint64_t pfn = kern->page ? __pa(kern->page) : EFCT_INVALID_PFN;
	if (*user == pfn)
		return 0;

	if (pfn == EFCT_INVALID_PFN) {
		vm_munmap(addr, CI_HUGEPAGE_SIZE);
	}
	else {
		unsigned long rc;
		rc = vm_mmap(kern->file, addr, CI_HUGEPAGE_SIZE,
		             PROT_READ,
		             MAP_FIXED | MAP_SHARED | MAP_POPULATE |
		                     MAP_HUGETLB | MAP_HUGE_2MB,
		             kern->page->index * CI_HUGEPAGE_SIZE);
		if (IS_ERR((void*)rc))
			return PTR_ERR((void*)rc);
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
	size_t i;
	int rc = 0;

	if (max_superbufs != CI_EFCT_MAX_SUPERBUFS) {
		/* Could be supported without much difficulty, but no need for now */
		return -EINVAL;
	}

	pages = kmalloc_array(sizeof(pages[0]), CI_EFCT_MAX_HUGEPAGES,
	                      GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	rc = efct_get_hugepages(rxq->rs.rs_client->nic,
	                        rxq->hw.qid, pages, CI_EFCT_MAX_HUGEPAGES);
	if (rc < 0) {
		kfree(pages);
		return rc;
	}
	for (i = 0; i < CI_EFCT_MAX_HUGEPAGES; i += REFRESH_BATCH_SIZE) {
		uint64_t local_current[REFRESH_BATCH_SIZE];
		size_t j;
		size_t n = min((size_t)REFRESH_BATCH_SIZE,
		               CI_EFCT_MAX_HUGEPAGES - i);
		bool changes = false;

		if (copy_from_user(local_current, user_current + i,
		                   n * sizeof(*local_current))) {
			rc = -EFAULT;
			break;
		}

		for (j = 0; j < n; ++j) {
			rc = fixup_superbuf_mapping(
					superbufs + CI_HUGEPAGE_SIZE * (i + j),
					&local_current[j], &pages[i + j]);
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

#if XLNX_EFCT_AUX_VERSION >= KERNEL_VERSION(5,0,0)
	for (i = 0; i < CI_EFCT_MAX_HUGEPAGES; i++) {
		if (pages[i].page != NULL) {
			put_page(pages[i].page);
			fput(pages[i].file);
		}
	}
#endif

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

	pages = kmalloc_array(sizeof(pages[0]), CI_EFCT_MAX_HUGEPAGES, GFP_KERNEL);
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
		
#if XLNX_EFCT_AUX_VERSION >= KERNEL_VERSION(5,0,0)
		if (pages[i].page != NULL) {
			put_page(pages[i].page);
			fput(pages[i].file);
		}
#endif
	}

	kfree(pages);
	return rc;
#else
	return -EOPNOTSUPP;
#endif /* CI_HAVE_EFCT_AUX */
}
EXPORT_SYMBOL(efrm_rxq_refresh_kernel);


void efrm_rxq_request_wakeup(struct efrm_efct_rxq *rxq, unsigned sbseq,
                             unsigned pktix)
{
#if CI_HAVE_EFCT_AUX
	struct efhw_nic *nic = rxq->vi->rs.rs_client->nic;
	efct_request_wakeup(nic->arch_extra, &rxq->hw, sbseq, pktix);
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
