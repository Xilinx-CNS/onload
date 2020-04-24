/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __CI_EFCH_MMAP_H__
#define __CI_EFCH_MMAP_H__

#include <ci/efch/mmap_id.h>

struct efrm_vi;


extern int
efab_vi_resource_mmap(struct efrm_vi *virs, unsigned long *bytes, void *opaque,
                      int *map_num, unsigned long *offset, int map_type);

extern int
efab_vi_resource_mmap_bytes(struct efrm_vi* virs, int map_type);

extern struct page*
efab_vi_resource_nopage(struct efrm_vi *virs, void *opaque,
                        unsigned long offset, unsigned long map_size);


#endif /* __CI_EFCH_MMAP_H__ */
