/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

/*
 * Simple linking test for libciul.
 *
 * This test verifies that we can successfully link against libciul
 * and call basic functions. It's designed to catch issues like
 * undefined symbols that occur when the library has missing
 * dependencies.
 *
 * This test should be linked against the full libciul library
 * (either static or dynamic) rather than individual object files.
 */

#include <stdio.h>
#include <stdbool.h>

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>

/* Test infrastructure */
#include "unit_test.h"

static void test_linking_basic(void)
{
  /*
   * Call ef_vi_version_str() to verify that the library is linked
   * correctly and we can call a basic function.
   */
  const char* version = ef_vi_version_str();

  /* Version string should not be NULL */
  CHECK_TRUE(version != NULL);

  /* Version string should not be empty */
  if( version != NULL )
    CHECK_TRUE(version[0] != '\0');
}

int main(void)
{
  TEST_RUN(test_linking_basic);
  TEST_END();
}
