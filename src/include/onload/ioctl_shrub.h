/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#ifndef __ONLOAD_IOCTL__SHRUB_H__
#define __ONLOAD_IOCTL__SHRUB_H__

#include <onload/ioctl_base.h>
#include <onload/ioctl_dshm.h>

enum {
  OO_OP_SHRUB_SPAWN_SERVER = OO_OP_DSHM_END,
#define OO_IOC_SHRUB_SPAWN_SERVER OO_IOC_W(SHRUB_SPAWN_SERVER, shrub_ioctl_data_t)

  OO_OP_SHRUB_SET_SOCKETS,
#define OO_IOC_SHRUB_SET_SOCKETS OO_IOC_W(SHRUB_SET_SOCKETS, shrub_socket_ioctl_data_t)

  OO_OP_SHRUB_SET_TOKEN,
#define OO_IOC_SHRUB_SET_TOKEN OO_IOC_W(SHRUB_SET_TOKEN, shrub_socket_ioctl_data_t)

  OO_OP_SHRUB_END  /* This had better be last! */
};

#endif /* __ONLOAD_IOCTL__SHRUB_H__ */
