/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
#ifndef __CI_EFCH_MMAP_H__
#define __CI_EFCH_MMAP_H__

#include <ci/efch/mmap_id.h>

struct efrm_vi;


extern int
efab_vi_resource_mmap(struct efrm_vi *virs, unsigned long *bytes,
                      struct vm_area_struct *vma,
                      int *map_num, unsigned long *offset, int map_type);

extern int
efab_vi_resource_mmap_bytes(struct efrm_vi* virs, int map_type);

extern struct page*
efab_vi_resource_nopage(struct efrm_vi *virs, struct vm_area_struct *vma,
                        unsigned long offset, unsigned long map_size);


#endif /* __CI_EFCH_MMAP_H__ */
