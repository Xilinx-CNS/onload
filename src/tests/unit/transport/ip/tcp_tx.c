/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2022 AMD, Inc. */

#include <stdio.h>

int main(int argc, char* argv[])
{
  /* For now, this is a dummy test to demonstrate that:
   *  - the framework can handle multiple tests
   *  - test failures are handled properly (uncomment the return to check)
   */
  printf("*** simulating test %s\n", argv[0]);
  //return 1;
}
