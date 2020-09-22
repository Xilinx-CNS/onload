/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file linux_trampoline.c System call trampolines for Linux - common to all architectures
** <L5_PRIVATE L5_SOURCE>
** \author  gel,mjs
**  \brief  Package - driver/linux	Linux driver support
**   \date  2005/03/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */
 
/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include "onload_kernel_compat.h"

#include <onload/linux_onload_internal.h>
#include <onload/linux_trampoline.h>
#include <onload/linux_mmap.h>
#include <onload/linux_onload.h>
#include <linux/unistd.h>

/*--------------------------------------------------------------------
 *
 * Tracing / debugging
 *
 *--------------------------------------------------------------------*/

/* Debugging for internal use only */
#if 0
#  define TRAMP_DEBUG(x...) ci_log(x)
#else
#  define TRAMP_DEBUG(x...) (void)0
#endif

/* Function to insert the current process's MM into the hash-table --
 * necessary to trampoline syscalls back into the user library.  The
 * trampoline_entry parameter is the address in the library we'll
 * trampoline to.
 *
 * Returns zero on success, or -ve error code on failure. 
 */
int
efab_linux_trampoline_register (ci_private_t *priv, void *arg)
{
  const ci_tramp_reg_args_t *args = arg;
  int rc = 0;
  struct mm_hash *p;

  TRAMP_DEBUG ("Register entry-point 0x%"CI_PRIx64" for mm %p (pid %d)",
               args->trampoline_entry.ptr, current->mm, current->pid);

  write_lock (&oo_mm_tbl_lock);

  p = oo_mm_tbl_lookup(current->mm);
  /* Either we found the entry on the hash table already, or we just created
   * one.  Either way, update the trampoline entry-point
   */
  if (!p) {
    /* This means current mm is not in the hash, implying that client
     * hasn't mmapped anything yet.  Fail the request since we have no
     * way of cleaning up.
     */
    ci_log("Unexpected trampoline registration with no maps");
    rc = -ENOENT;
    goto exit;
  }
  ci_assert (p);
  ci_assert (p->mm == current->mm);
  p->trampoline_entry = args->trampoline_entry;
  p->trampoline_toc = args->trampoline_toc;
  p->trampoline_user_fixup = args->trampoline_user_fixup;
  CI_DEBUG(p->trampoline_ul_fail = args->trampoline_ul_fail;)

  rc = efab_signal_mm_init(args, p);

  TRAMP_DEBUG("mm %p registered trampoline entry %"CI_PRIx64,
              p->mm, args->trampoline_entry.ptr);

exit:
  if( rc == 0 && safe_signals_and_exit )
    efab_get_mm_hash_locked(p);
  write_unlock (&oo_mm_tbl_lock);

  if( rc == 0 && safe_signals_and_exit ) {
    efab_signal_process_init(&p->signal_data);
    efab_signal_put_tramp_data(&p->signal_data);
  }
  return rc;
}
