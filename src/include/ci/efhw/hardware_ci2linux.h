/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */

#ifndef __CI_EFHW_HARDWARE_CI2LINUX_H__
#define __CI_EFHW_HARDWARE_CI2LINUX_H__

#include <ci/compat.h>

#define __iomem

#if CI_MY_BYTE_ORDER == CI_LITTLE_ENDIAN
#define EFHW_IS_LITTLE_ENDIAN
#else
#define EFHW_IS_BIG_ENDIAN
#endif


#ifndef PAGE_SIZE
#define PAGE_SIZE CI_PAGE_SIZE
#endif
#ifndef PAGE_SHIFT
#define PAGE_SHIFT CI_PAGE_SHIFT
#endif


#define mmiowb()
#define rmb ci_rmb
#define wmb ci_wmb


#endif /* __CI_EFHW_HARDWARE_CI2LINUX_H__ */
