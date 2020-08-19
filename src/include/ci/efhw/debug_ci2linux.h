/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */

#ifndef __CI_EFHW_DEBUG_CI2LINUX_H__
#define __CI_EFHW_DEBUG_CI2LINUX_H__

#include <ci/compat.h>
#include <ci/tools/log.h>
#include <ci/tools/debug.h>

#define printk    ci_log
#define printk_nl ""

#define KERN_ERR        "ERR>"
#define KERN_WARNING    "WARN>"
#define KERN_NOTICE     "NOTICE>"
#define KERN_DEBUG      "DBG>"

#define BUG_ON(cond) ci_assert((cond) == 0)
#define BUG() ci_assert(0)

#endif /* __CI_EFHW_DEBUG_CI2LINUX_H__ */
