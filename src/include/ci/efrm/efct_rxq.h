/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */
#ifndef __CI_EFRM_EFCT_RXQ_H__
#define __CI_EFRM_EFCT_RXQ_H__
#include <linux/cpumask.h>

struct efrm_resource;
struct efrm_resource_manager;
struct efrm_vi;
struct efrm_efct_rxq;
struct oo_hugetlb_allocator;

int efrm_create_rxq_resource_manager(struct efrm_resource_manager **rm_out);

extern struct efrm_resource* efrm_rxq_to_resource(struct efrm_efct_rxq *ext);
extern struct efrm_efct_rxq* efrm_rxq_from_resource(struct efrm_resource *rs);

extern int efrm_rxq_alloc(struct efrm_vi *vi, int qid, int shm_ix,
                          bool timestamp_req, bool interrupt_req,
                          size_t n_hugepages,
                          struct oo_hugetlb_allocator *hugetlb_alloc,
                          struct efrm_efct_rxq **rxq_out);

/** Flush and release rxq resource. To be used with shared queues */
extern void efrm_rxq_release(struct efrm_efct_rxq *rxq);
/** Flush queue associated with resource - to be used with non-shared queues */
void efrm_rxq_flush(struct efrm_efct_rxq *rxq);
/** Release resource - to be used with non-shared queues after flush complete */
void efrm_rxq_free(struct efrm_efct_rxq *rxq);
int efrm_rxq_refresh(struct efrm_efct_rxq *rxq,
                     unsigned long superbufs, uint64_t __user *user_current,
                     unsigned max_superbufs);
int efrm_rxq_refresh_kernel(struct efhw_nic *nic, int hwqid,
                            const char** superbufs);
int efrm_rxq_request_wakeup(struct efrm_efct_rxq *rxq, unsigned sbseq,
                            unsigned pktix, bool allow_recursion);
resource_size_t efrm_rxq_superbuf_window(struct efrm_efct_rxq *rxq);
struct efhw_efct_rxq *efrm_rxq_get_hw(struct efrm_efct_rxq *rxq);
struct efrm_vi *efrm_rxq_get_vi(struct efrm_efct_rxq *rxq);
struct list_head *efrm_rxq_get_flush_list(struct efrm_efct_rxq *rxq);
struct efrm_efct_rxq *efrm_rxq_from_flush_list(struct list_head *);
struct efrm_efct_rxq *efrm_rxq_from_vi_list(struct list_head *);


#endif
