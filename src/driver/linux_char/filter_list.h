/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2019 Xilinx, Inc. */
#ifndef __FILTER_LIST_H__
#define __FILTER_LIST_H__


extern void efch_filter_list_init(struct efch_filter_list *);

extern void efch_filter_list_free(struct efrm_resource *, struct efrm_pd *,
                                  struct efch_filter_list *);

extern int efch_filter_list_del(struct efrm_resource *, struct efrm_pd *,
                                struct efch_filter_list *, int filter_id);

extern int efch_filter_list_op_add(struct efrm_resource *, struct efrm_pd *,
                                   struct efch_filter_list *,
                                   ci_resource_op_t *, int *copy_out,
                                   unsigned efx_filter_flags, int rss_context);

extern int efch_filter_list_op_del(struct efrm_resource *rs, struct efrm_pd *,
                                   struct efch_filter_list *fl,
                                   ci_resource_op_t *op);

extern int efch_filter_list_op_query(struct efrm_resource *rs, struct efrm_pd *,
                                     struct efch_filter_list *fl,
                                     ci_resource_op_t *op);

extern int efch_filter_list_op(struct efrm_resource *rs,
                               struct efch_filter_list *fl,
                               ci_resource_op_t *op);

extern int efch_filter_list_op_block(struct efrm_resource *rs, struct efrm_pd*,
                                     struct efch_filter_list *fl,
                                     ci_resource_op_t *op);

extern int efch_filter_list_add(struct efrm_resource* rs, struct efrm_pd* pd,
                                struct efch_filter_list* fl,
                                ci_filter_add_t* filter_add, int* copy_out);

#endif  /* __FILTER_LIST_H__ */
