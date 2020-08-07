/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#ifndef __ONLOAD_IOCTL__DSHM_H__
#define __ONLOAD_IOCTL__DSHM_H__

#include <onload/ioctl_base.h>
#include <cplane/ioctl.h>

enum {
  OO_OP_DSHM_REGISTER  = OO_OP_CP_END,
#define OO_IOC_DSHM_REGISTER      OO_IOC_RW(DSHM_REGISTER, oo_dshm_register_t)

  OO_OP_DSHM_LIST,
#define OO_IOC_DSHM_LIST          OO_IOC_RW(DSHM_LIST, oo_dshm_list_t)

  OO_OP_DSHM_END  /* This had better be last! */
};

#endif /* __ONLOAD_IOCTL__DSHM_H__ */
