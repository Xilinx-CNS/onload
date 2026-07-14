/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "oo_nics_test.h"

struct {
  const char* name;
  int (*fn)(void);
} tests[] = {
  { "basic",                test_basic },
  { "multiarch_datapath",   test_multiarch_datapath },
  { "whitelist_blacklist",  test_whitelist_blacklist },
};

int main(int argc, char** argv)
{
  unsigned i;
  const char* test_name;

  if( argc != 2 ) {
    fprintf(stderr, "Usage: %s <test_name|all>\n", argv[0]);
    return 1;
  }
  test_name = argv[1];

  if( strcmp(test_name, "all") == 0 ) {
    int rc = 0;
    for( i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i )
      rc |= tests[i].fn();
    return rc;
  }

  for( i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i ) {
    if( strcmp(test_name, tests[i].name) == 0 )
      return tests[i].fn();
  }

  fprintf(stderr, "Unknown test: %s\n", test_name);
  return 1;
}
