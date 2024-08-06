/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2024 Advanced Micro Devices, Inc. */

#include <stdio.h>
#include <stdbool.h>

/* Functions under test */
#include <etherfabric/checksum.h>

/* Test infrastructure */
#include "unit_test.h"

static void test_ef_tcp_checksum_ffff(void)
{
  /* A real IPv4 packet grabbed from interface. */
  char ipdata[] = {
    0x45, 0x00, 0x00, 0x3c,
    0x73, 0x63, 0x40, 0x00,
    0x40, 0x06, 0x9e, 0x66,
    0x0a, 0x78, 0x0a, 0x02,
    0x0a, 0x78, 0x0a, 0x01
  };
  char tcpdata[] = {
    0xa9, 0xf6, 0x52, 0x13,
    0x08, 0x15, 0xf7, 0x44,
    0x00, 0x00, 0x00, 0x00,
    0xa0, 0x02, 0xfa, 0xf0, /* flags - 0x2 (SYN) */
    0xff, 0xff, 0x00, 0x00, /* checksum - 0xffff */
    0x02, 0x04, 0x05, 0xb4,
    0x04, 0x02, 0x08, 0x0a,
    0x7f, 0xd1, 0xa8, 0xe7,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x03, 0x03, 0x07
  };
  struct iphdr *ip = (struct iphdr *)ipdata;
  struct tcphdr *tcp = (struct tcphdr *)tcpdata;

  CHECK_TRUE(ef_tcp_checksum_is_correct(ip, tcp, NULL, 0));

  /* Check that we still consider the checksum correct if it is 0. */
  tcp->check = 0;
  CHECK_TRUE(ef_tcp_checksum_is_correct(ip, tcp, NULL, 0));

  /* Check that we compute the checksum of the above packet as 0xffff. */
  CHECK(ef_tcp_checksum(ip, tcp, NULL, 0), ==, 0xffff);
}

int main(void)
{
  TEST_RUN(test_ef_tcp_checksum_ffff);
  TEST_END();
}
