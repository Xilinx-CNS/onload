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
#include <onload/signals.h>

/* Trampolining requires us to maintain per-process state for each app using us
 * -- the address of the trampoline handler that we need to return to.  We do
 * this by maintaining a hash-table for MMs that are mapped onto our resources
 * (if a process is using our stack, if must have mapped the mm)
 */
struct mm_signal_data {
  __sighandler_t    handler_postpone;
  void             *sarestorer;
  __sighandler_t    handlers[OO_SIGHANGLER_DFL_MAX+1];
  ci_uint32/*bool*/ sa_onstack_intercept;
  ci_user_ptr_t     user_data;
  void             *kernel_sighand; /* used as opaque pointer only */
  struct oo_sigaction signal_data[_NSIG];
};


struct mm_hash {
  ci_dllink         link;
  struct mm_struct *mm;

  ci_user_ptr_t     trampoline_entry;

  /* Used on PPC (and others) to restore the TOC pointer; unnecessary 
   *  for x86 and x64
   */
  ci_user_ptr_t   trampoline_toc;
  ci_user_ptr_t trampoline_user_fixup;

  CI_DEBUG(ci_user_ptr_t trampoline_ul_fail;)

  struct mm_signal_data signal_data;

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
