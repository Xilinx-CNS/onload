/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
#ifndef __ONLOAD_IOCTL_BASE_H__
#define __ONLOAD_IOCTL_BASE_H__

#include <linux/version.h>

/* Worth changing this base whenever you change an ioctl in an incompatible
** way, so we can catch the error more easily...
*/
# define OO_LINUX_IOC_BASE  90
# if OO_LINUX_IOC_BASE > 254
# error "OO_LINUX_IOC_BASE should be one byte"
# endif

# define OO_IOC_NONE(XXX)   _IO(OO_LINUX_IOC_BASE, OO_OP_##XXX)
# define OO_IOC_R(XXX, t)   _IOR(OO_LINUX_IOC_BASE, OO_OP_##XXX, t)
# define OO_IOC_W(XXX, t)   _IOW(OO_LINUX_IOC_BASE, OO_OP_##XXX, t)
# define OO_IOC_RW(XXX, t)  _IOWR(OO_LINUX_IOC_BASE, OO_OP_##XXX, t)

#endif  /* __ONLOAD_IOCTL_BASE_H__ */
