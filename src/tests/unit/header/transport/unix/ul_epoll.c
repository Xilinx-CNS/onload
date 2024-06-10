/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */
#include <time.h>
#include <limits.h>
#include <stdlib.h>

/* 9.765432GHz */

static const unsigned cpu_khz_vals[] = { 10000000, 9765432, 500000, 100000, 12345, 2};

__attribute__ ((weak)) unsigned oo_timesync_cpu_khz;

/* Modules under test. Define UNIT_TEST_EPOLL to compile in oo_epoll_frc_to_ts
 * despite it being a kernel module function. */
#define UNIT_TEST_EPOLL
#include <transport/unix/ul_epoll.h>
#include <onload/epoll.h>

#include "unit_test.h"

__attribute__ ((weak)) citp_globals_t citp;

static void test_oo_epoll_ms_to_frc(void)
{
  CHECK(oo_epoll_ms_to_frc(-1), ==, OO_EPOLL_MAX_TIMEOUT_FRC);
  CHECK(oo_epoll_ms_to_frc(0), ==, 0);
  CHECK(oo_epoll_ms_to_frc(19), ==, 19 * oo_timesync_cpu_khz);
  CHECK(oo_epoll_ms_to_frc(INT_MAX), ==, (uint64_t)INT_MAX *
                           oo_timesync_cpu_khz);
}

static void test_oo_epoll_ts_to_frc_null(void)
{
  CHECK(oo_epoll_ts_to_frc(NULL), ==, OO_EPOLL_MAX_TIMEOUT_FRC);
}

static void test_oo_epoll_ts_to_frc_max(void)
{
  struct timespec ts = {
    .tv_sec = OO_EPOLL_MAX_TV_SEC,
    .tv_nsec = 999999999
  };
  CHECK(oo_epoll_ts_to_frc(&ts), <, OO_EPOLL_MAX_TIMEOUT_FRC);
}

static void test_oo_epoll_ts_to_frc_max2(void)
{
  struct timespec ts = {
    .tv_sec = OO_EPOLL_MAX_TV_SEC + 1,
    .tv_nsec = 0
  };
  ci_int64 timeout = oo_epoll_ts_to_frc(&ts);
  CHECK(timeout, ==, OO_EPOLL_MAX_TIMEOUT_FRC);
}

static void test_oo_epoll_ts_to_frc(void)
{
  struct timespec ts;
  ts.tv_sec = 2134;
  ts.tv_nsec = 123456789;
  CHECK(oo_epoll_ts_to_frc(&ts), ==,
        ts.tv_sec * oo_timesync_cpu_khz * 1000ULL +
        (ts.tv_nsec * oo_timesync_cpu_khz) / 1000000);

  ts.tv_sec = OO_EPOLL_MAX_TV_SEC;
  ts.tv_nsec = 123456789;
  CHECK(oo_epoll_ts_to_frc(&ts), ==,
        ts.tv_sec * oo_timesync_cpu_khz * 1000ULL +
        (ts.tv_nsec * oo_timesync_cpu_khz) / 1000000);
}

static void test_oo_epoll_frc_to_ts(void)
{
  struct __kernel_timespec ts;
  uint64_t nanos;
  oo_epoll_frc_to_ts(0, &ts);
  CHECK(ts.tv_sec, ==, 0);
  CHECK(ts.tv_nsec, ==, 0);

  oo_epoll_frc_to_ts(INT64_MAX, &ts);
  nanos = ((ci_uint128)INT64_MAX * 1000000) / oo_timesync_cpu_khz;
  CHECK(ts.tv_sec, ==, nanos / 1000000000);
  CHECK(ts.tv_nsec, ==, nanos % 1000000000);
}

static void test_oo_epoll_frc_to_ms(void)
{
  CHECK(oo_epoll_frc_to_ms(0), ==, 0);
  /* Timout should always round up due to the coarseness of millis */
  CHECK(oo_epoll_frc_to_ms(1), ==, 1);
  CHECK(oo_epoll_frc_to_ms(oo_timesync_cpu_khz - 1), ==, 1);
  CHECK(oo_epoll_frc_to_ms(INT64_MAX), ==, 0x7fffffff);
  /* Testing rounding up - Does not work at 1KHz */
  CHECK(oo_epoll_frc_to_ms(oo_timesync_cpu_khz * 0xBEEFULL +
        (oo_timesync_cpu_khz >> 1)), ==, 0xBEF0);
}

/* Accept a 0.001% error in frc_to_ns calculation. Even this is a bit harsh. */
#define FRC_TO_NS_ERROR_RECIPROCAL 100000

static void test_frc_to_ns(uint64_t val)
{
  uint64_t nanos = oo_epoll_frc_to_ns(val);
  ci_uint128 expected_ns = ((ci_uint128)val * 1000000) / oo_timesync_cpu_khz;
  uint64_t expected_ns64 = (expected_ns > OO_EPOLL_MAX_TIMEOUT_NS) ?
                            OO_EPOLL_MAX_TIMEOUT_NS : (uint64_t)expected_ns;

  CHECK(nanos, >=, expected_ns64 - expected_ns64 / FRC_TO_NS_ERROR_RECIPROCAL);
  CHECK(nanos, <=, expected_ns64 + expected_ns64 / FRC_TO_NS_ERROR_RECIPROCAL);
}

static void test_oo_epoll_frc_to_ns(void)
{
  int i;
  CHECK(oo_epoll_frc_to_ns(0), ==, 0);

  test_frc_to_ns(INT64_MAX);
  test_frc_to_ns(1345);
  for(i = 0; i < 5; i++) {
    test_frc_to_ns(rand());
  }
}

static void run_tests(unsigned cpu_khz)
{
  oo_timesync_cpu_khz = cpu_khz;
  citp.cpu_khz = cpu_khz;
  citp.epoll_frc_to_ns_magic = ((uint64_t)1ull << 44) * 1000000 / citp.cpu_khz;

  TEST_RUN(test_oo_epoll_ms_to_frc);
  TEST_RUN(test_oo_epoll_ts_to_frc_null);
  TEST_RUN(test_oo_epoll_ts_to_frc_max);
  TEST_RUN(test_oo_epoll_ts_to_frc_max2);
  TEST_RUN(test_oo_epoll_ts_to_frc);
  TEST_RUN(test_oo_epoll_frc_to_ts);
  TEST_RUN(test_oo_epoll_frc_to_ms);
  TEST_RUN(test_oo_epoll_frc_to_ns);
}

int main(void)
{
  unsigned seed = time(NULL);
  int i;
  fprintf(stderr, "Running unit test ul_epoll.c with random seed: %u\n", seed);
  srand(seed);

  for(i = 0; i < sizeof(cpu_khz_vals) / sizeof(cpu_khz_vals[0]); i++) {
    run_tests(cpu_khz_vals[i]);
  }

  /* Test arbitrary frequencies > 2HZ */
  for(i = 0; i < 5; i++) {
    run_tests(rand() % 10000000 + 2);
  }
  TEST_END();
}
