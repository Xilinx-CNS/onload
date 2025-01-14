/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include "../oof_test.h"
#include "../cplane.h"
#include <onload/oof_interface.h>

int test_llct_sanity()
{
  /* This is the default configuration, where the stack can use both paths */
  return __test_sanity(OOFT_NIC_X4_FF, OOFT_RX_BOTH);
}
