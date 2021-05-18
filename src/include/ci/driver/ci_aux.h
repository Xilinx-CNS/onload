/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef CI_DRIVER_CI_AUX_H
#define CI_DRIVER_CI_AUX_H

#ifdef CONFIG_AUXILIARY_BUS
#include <linux/auxiliary_bus.h>
#elif CI_HAVE_CNS_AUX
#include CI_AUX_MOD_HEADER
#include CI_AUX_HEADER
#endif

#endif /* CI_DRIVER_CI_AUX_H */

