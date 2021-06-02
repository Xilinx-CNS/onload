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

#ifndef __LINUX_CHAR_INTERNAL_H__
#define __LINUX_CHAR_INTERNAL_H__

#include "efch.h"
#include <linux/mm.h>
#include <linux/fs.h>


/* Name of the char device */
#define EFAB_CHAR_NAME "sfc_char"


/*--------------------------------------------------------------------
 *
 * ci_private_char_t - holds the per file descriptor private state
 *
 *--------------------------------------------------------------------*/

typedef struct ci_private_char_s {
  ci_resource_table_t  rt;
  struct efrm_vi*      cpcp_vi;
  int                  cpcp_readable;
  wait_queue_head_t    cpcp_poll_queue;
} ci_private_char_t;


extern int ci_char_fop_mmap(struct file* file, struct vm_area_struct* vma);

extern int
ci_mmap_bar(struct efhw_nic* nic, off_t base, size_t len, void* opaque,
            int* map_num, unsigned long* offset, int set_wc);

#endif /* __LINUX_CHAR_INTERNAL_H__ */
