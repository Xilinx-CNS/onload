/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Xilinx, Inc. */

#include "dtor_lib.hpp"

int main(int argc, char const* argv[])
{
  /* Re-instantiate Foo with the accelerated socket. */
  foo = Foo();
  return 0;
}
