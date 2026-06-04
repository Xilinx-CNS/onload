/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017 Xilinx, Inc. */

#ifndef __OOF_TEST_EFRM_INTERFACE_H__
#define __OOF_TEST_EFRM_INTERFACE_H__

#define EFRM_RSS_MODE_ID_DEFAULT 0
#define EFRM_RSS_MODE_ID_SRC     0
#define EFRM_RSS_MODE_ID_DST     1

struct efrm_vi_set {
};

extern int
efrm_vi_set_get_rss_context(struct efrm_vi_set *, unsigned rss_id);

extern int efrm_filter_insert_fail_count;
extern int efrm_filter_insert_fail_after;
extern int efrm_filter_insert_fail_proto_mac;
extern int efrm_filter_insert_fail_rc;
extern int efrm_filter_redirect_fail_count;
extern int efrm_filter_redirect_fail_rc;
extern int efrm_filter_rollback_remove_count;

#endif /* __OOF_TEST_EFRM_INTERFACE_H__ */
