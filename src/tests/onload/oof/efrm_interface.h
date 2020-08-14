/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017 Xilinx, Inc. */

#ifndef __OOF_TEST_EFRM_INTERFACE_H__
#define __OOF_TEST_EFRM_INTERFACE_H__

/* note mode default and src are mutually exclusive */
#define EFRM_RSS_MODE_DEFAULT 0x1 /* standard non-tproxy mode */
#define EFRM_RSS_MODE_SRC     0x2 /* semi transparent proxy passive side */
#define EFRM_RSS_MODE_DST     0x4 /* transparent proxy active side */

#define EFRM_RSS_MODE_ID_DEFAULT 0
#define EFRM_RSS_MODE_ID_SRC     0
#define EFRM_RSS_MODE_ID_DST     1

struct efrm_vi_set {
};

extern int
efrm_vi_set_get_rss_context(struct efrm_vi_set *, unsigned rss_id);

#endif /* __OOF_TEST_EFRM_INTERFACE_H__ */
