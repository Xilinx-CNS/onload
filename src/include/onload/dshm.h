/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**
 * \file Kernel interface to "donation" shared memory.
 */

#ifndef __OO_DSHM_H__
#define __OO_DSHM_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <onload/mmap_base.h>
#include <ci/tools/dllist.h>

enum {
  OO_DSHM_CLASS_ZF_STACK,
  OO_DSHM_CLASS_ZF_PACKETS,
  OO_DSHM_CLASS_COUNT,
};


/* "Donation" shared memory ioctl structures. */

typedef struct {
  ci_int32       shm_class;
  ci_user_ptr_t  buffer;
  ci_uint32      length;
  ci_int32       buffer_id;
} oo_dshm_register_t;

typedef struct {
  ci_int32       shm_class;
  ci_user_ptr_t  buffer_ids;
  ci_uint32      count;
} oo_dshm_list_t;

#ifdef __KERNEL__

extern int
oo_dshm_register_impl(ci_int32 shm_class, ci_user_ptr_t user_addr,
                      ci_uint32 length, ci_int32* buffer_id_out,
                      ci_dllist* handle_list);

extern int
oo_dshm_list_impl(ci_int32 shm_class, ci_user_ptr_t buffer_ids,
                  ci_uint32* count_in_out);

extern void
oo_dshm_init(void);

extern void
oo_dshm_fini(void);

extern int
oo_dshm_free_handle_list(ci_dllist*);

#ifdef OO_MMAP_TYPE_DSHM
extern int
oo_dshm_mmap_impl(struct vm_area_struct*);
#endif

#endif


#ifdef __cplusplus
}
#endif

#endif /* ! defined(__OO_DSHM_H__) */

