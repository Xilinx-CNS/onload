/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2022 Xilinx, Inc. */

#include "../oof_test.h"
#include "../cplane.h"
#include <onload/oof_interface.h>

int test_sanity_no5tuple()
{
  return __test_sanity(OOFT_NIC_AFXDP, OOFT_RX_FF);
}
