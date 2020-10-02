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


int oo_fop_mmap(struct file* file, struct vm_area_struct* vma);


#endif /* __ONLOAD_LINUX_MMAP_H__ */
