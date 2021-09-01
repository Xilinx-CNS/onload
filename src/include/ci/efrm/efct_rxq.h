/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */
#ifndef __CI_EFRM_EFCT_RXQ_H__
#define __CI_EFRM_EFCT_RXQ_H__
#include <linux/cpumask.h>

struct efrm_resource;
struct efrm_resource_manager;
struct efrm_vi;
struct efrm_efct_rxq;

int efrm_create_rxq_resource_manager(struct efrm_resource_manager **rm_out);

extern struct efrm_resource* efrm_rxq_to_resource(struct efrm_efct_rxq *ext);
extern struct efrm_efct_rxq* efrm_rxq_from_resource(struct efrm_resource *rs);

extern int efrm_rxq_alloc(struct efrm_vi *vi, int qid, int shm_ix,
                          const struct cpumask *mask, bool timestamp_req,
                          size_t n_hugepages, struct file* memfd,
                          off_t memfd_off, struct efrm_efct_rxq **rxq_out);

extern void efrm_rxq_release(struct efrm_efct_rxq *rxq);
int efrm_rxq_refresh(struct efrm_efct_rxq *rxq,
                     unsigned long superbufs, uint64_t __user *user_current,
                     unsigned max_superbufs);
int efrm_rxq_refresh_kernel(struct efhw_nic *nic, int hwqid,
                            const char** superbufs);


#endif
