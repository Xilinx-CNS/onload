/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include "../oof_test.h"
#include "../cplane.h"
#include <onload/oof_interface.h>

int test_llct_sanity_ff()
{
  /* This differs from test_sanity() even though it's only using the FF path
   * because the test is performed in a config where the extra datapath is
   * available. */
  return __test_sanity(OOFT_NIC_X4_FF, OOFT_RX_FF);
}
