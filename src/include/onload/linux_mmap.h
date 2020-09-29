/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  ok_sasha
**  \brief  Linux driver mmap internal interfaces
**   \date  2007/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal */

#ifndef __ONLOAD_LINUX_MMAP_H__
#define __ONLOAD_LINUX_MMAP_H__

#include <ci/tools.h>
#include <onload/tcp_helper.h>


struct mm_hash {
  ci_dllink         link;
  struct mm_struct *mm;

  unsigned          ref;
  unsigned          magic;
};

/* A lock to protect the hash-table.  If we really wanted to go mad we could
 * have one lock per entry in the table.  But the hash-table is infrequently
 * updated, so a single r/w lock should suffice.
 */
extern rwlock_t oo_mm_tbl_lock;

extern void oo_mm_tbl_init(void);

extern struct mm_hash* oo_mm_tbl_lookup(struct mm_struct*);
extern int efab_put_mm_hash_locked(struct mm_hash *p);
static inline void efab_get_mm_hash_locked(struct mm_hash *p)
{ p->ref++; }
extern void efab_free_mm_hash(struct mm_hash *p);

int oo_fop_mmap(struct file* file, struct vm_area_struct* vma);


#endif /* __ONLOAD_LINUX_MMAP_H__ */
