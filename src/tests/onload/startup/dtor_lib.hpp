/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Xilinx, Inc. */

#ifndef __STARTUP_TEST_DTOR_LIB_H__
#define __STARTUP_TEST_DTOR_LIB_H__

class Foo {
public:
  Foo();
  ~Foo();

private:
  int fd;
};

extern Foo foo;

#endif /* __STARTUP_TEST_DTOR_LIB_H__ */
