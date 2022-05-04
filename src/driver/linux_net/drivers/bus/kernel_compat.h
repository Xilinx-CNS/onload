/* SPDX-License-Identifier: GPL-2.0 */
/****************************************************************************
 * Driver for Solarflare and Xilinx network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 * Copyright 2019-2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef BUS_KERNEL_COMPAT_H
#define BUS_KERNEL_COMPAT_H
#include <linux/idr.h>
#include "autocompat.h"

#ifndef EFX_HAVE_DEV_PM_DOMAIN_ATTACH
static inline int dev_pm_domain_attach(struct device *dev, bool power_on)
{
	return 0;
}

static inline void dev_pm_domain_detach(struct device *dev, bool power_off) {}
#endif

#ifdef EFX_NEED_IDA
static inline int ida_simple_get(struct ida *ida, unsigned int min,
				 unsigned int max, gfp_t gfp)
{
	static bool first = true;
	int ret, id;

	if (first && !ida_pre_get(ida, GFP_KERNEL))
		return -ENOMEM;
	first = false;

	ret = ida_get_new(ida, &id);
	if (ret)
		return ret;
	return id;
}

#define ida_simple_remove(ida, id)	ida_remove(ida, id)
#endif

#endif
