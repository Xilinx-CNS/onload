/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Xilinx, Inc. */

#include <sys/socket.h>
#include "dtor_lib.hpp"

Foo::Foo()
{
  fd = socket(AF_INET, SOCK_STREAM, 0);
}

Foo::~Foo()
{
  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&opt, sizeof(opt));
}

/* The runtime creates @foo in the library constructor, possibly before Onload,
 * and thus make it operate on a non-accelerated socket. Later in main() we
 * re-instantiate @foo to ensure its socket is accelerated when the app exits.
 *
 * When application exits, the runtime runs ~Foo() and here we check that
 * Onload is still in good shape and handles interception as expected.
 */
Foo foo;
