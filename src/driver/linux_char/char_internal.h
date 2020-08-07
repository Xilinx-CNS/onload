/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2019 Xilinx, Inc. */
#ifndef __CHAR_INTERNAL_H__
#define __CHAR_INTERNAL_H__

#include <ci/efch/resource_id.h>


struct ci_timeval_s;
struct efrm_vi;
struct efch_resource_ops_s;


extern struct efch_resource_ops_s efch_vi_ops;
extern struct efch_resource_ops_s efch_vi_set_ops;
extern struct efch_resource_ops_s efch_memreg_ops;
extern struct efch_resource_ops_s efch_pd_ops;
extern struct efch_resource_ops_s efch_pio_ops;

extern struct file_operations ci_char_fops;
extern int phys_mode_gid;

extern struct efch_resource_ops_s *efch_ops_table[EFRM_RESOURCE_NUM];


extern int
efab_vi_rm_eventq_wait(struct efrm_vi* virs, unsigned current_ptr,
                       struct ci_timeval_s* timeout_tv);

extern int efch_lookup_rs(int fd, efch_resource_id_t rs_id, int rs_type,
                          struct efrm_resource **rs_out);


#define EFCH_PRINTK(level, fmt, ...) \
	printk(level "[sfc_char]" fmt "\n", __VA_ARGS__)

#define EFCH_ERR(fmt, ...)     EFCH_PRINTK(KERN_ERR, fmt, __VA_ARGS__)
#define EFCH_WARN(fmt, ...)    EFCH_PRINTK(KERN_WARNING, fmt, __VA_ARGS__)
#define EFCH_NOTICE(fmt, ...)  EFCH_PRINTK(KERN_NOTICE, fmt, __VA_ARGS__)
#ifndef NDEBUG
#define EFCH_TRACE(fmt, ...)   EFCH_PRINTK(KERN_DEBUG, fmt, __VA_ARGS__)
#else
#define EFCH_TRACE(fmt, ...)   do{}while(0)
#endif


#endif  /* __CHAR_INTERNAL_H__ */
