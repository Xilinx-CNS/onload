/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2020 Xilinx, Inc. */
#ifndef __CI_EFHW_DEVICE_H__
#define __CI_EFHW_DEVICE_H__

/* NB: this enum must be aligned with enum ef_vi_arch */
enum efhw_arch {
	EFHW_ARCH_EF10 = 1,
	EFHW_ARCH_EF100,
	EFHW_ARCH_AF_XDP,
};

/*----------------------------------------------------------------------------
 *
 * NIC type
 *
 *---------------------------------------------------------------------------*/

enum efhw_function {
	EFHW_FUNCTION_PF,
	EFHW_FUNCTION_VF,
};

struct efhw_device_type {
	int  arch;            /* enum efhw_arch */
	char variant;         /* 'A', 'B', ... */
	int  revision;        /* 0, 1, ... */
	int  function;        /* enum efhw_function */
};

#endif
