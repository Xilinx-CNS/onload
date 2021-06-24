/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */
#ifndef __CI_EFRM_EFCT_RXQ_H__
#define __CI_EFRM_EFCT_RXQ_H__
#include <linux/cpumask.h>

struct efrm_resource;
struct efrm_resource_manager;
struct efrm_pd;
struct efrm_efct_rxq;

int efrm_create_rxq_resource_manager(struct efrm_resource_manager **rm_out);

extern struct efrm_resource* efrm_rxq_to_resource(struct efrm_efct_rxq *ext);
extern struct efrm_efct_rxq* efrm_rxq_from_resource(struct efrm_resource *rs);

extern int efrm_rxq_alloc(struct efrm_pd *pd, int qid,
                          const struct cpumask *mask, bool timestamp_req,
                          size_t n_hugepages, struct efrm_efct_rxq **rxq_out);

extern void efrm_rxq_release(struct efrm_efct_rxq *rxq);
int efrm_rxq_mmap(struct efrm_efct_rxq* rxq, struct vm_area_struct *vma,
                  unsigned long *bytes);
int efrm_rxq_refresh(struct efrm_efct_rxq *rxq,
                     unsigned long superbufs, uint64_t __user *user_current,
                     unsigned max_superbufs);


#endif
