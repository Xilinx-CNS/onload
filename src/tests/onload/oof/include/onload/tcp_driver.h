/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017 Xilinx, Inc. */

#ifndef __OOF_TEST_TCP_DRIVER_H__
#define __OOF_TEST_TCP_DRIVER_H__

#include "onload_kernel_compat.h"
#include "oof_test.h"
#include <ci/internal/transport_config_opt.h>

struct oo_filter_ns_manager;
typedef struct efab_tcp_driver_s {
  struct oo_filter_ns_manager *filter_ns_manager;
} efab_tcp_driver_t;

#endif /* __OOF_TEST_TCP_DRIVER_H__ */
