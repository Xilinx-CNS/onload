/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017 Xilinx, Inc. */

#ifndef __OOF_TEST_TCP_FILTERS_DEPS_H__
#define __OOF_TEST_TCP_FILTERS_DEPS_H__

#include <stdlib.h>

#include "onload_kernel_compat.h"

struct tcp_helper_cluster_s;
struct efhw_nic;
#define EFHW_FILTER_F_REPLACE  0x0001
#define EFHW_PD_NON_EXC_TOKEN 0xFFFFFFFF

#include <onload/oof_hw_filter.h>
#include <onload/nic.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/net/ethernet.h>

#include "oo_hw_filter.h"

#include "driverlink_interface.h"
#include "efrm_interface.h"
#include "stack_interface.h"

#define EFRM_WARN(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
#define EFRM_ERR(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)

static inline bool ipv4_is_multicast(__be32 addr)
{
  return (addr & htonl(0xf0000000)) == htonl(0xe0000000);
}

#endif /* __OOF_TEST_TCP_FILTERS_DEPS_H__ */
