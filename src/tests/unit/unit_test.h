/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2022 Xilinx, Inc. */

/* Unit test infrastructure */
#ifndef ONLOAD_UNIT_TEST_H
#define ONLOAD_UNIT_TEST_H

#include <stdlib.h>


/* Running test suites
 *
 * A test suite is an executable program, defining one or more test cases. Each
 * test case is typically a function which:
 *  - establishes initial state and input
 *  - calls function(s) to exercise the unit under test
 *  - checks final state and output
 *
 * The suite should provide a "main" entry point for the program, which invokes
 * all of its test cases using TEST_RUN, then reports the result using TEST_END.
 */

/* Run a single test case defined by a function */
#define TEST_RUN(TEST_FN) \
  ut_test_run(#TEST_FN, TEST_FN)

/* End a test suite, exiting the program with 0 for success, 1 for failure */
#define TEST_END() \
  return ut_test_end()


/* Checking values within tests
 *
 * All checks which affect the test results should be performed using these
 * macros. They report individual failures as they occur, and record failures
 * to report the overall test result.
 */

/* Check that two values satisfy an equality or inequality comparison, reporting
 * the observed values on failure. */
#define CHECK(LHS, CMP, RHS) \
  ut_check(__FILE__, __LINE__, (LHS) CMP (RHS), #LHS, #CMP, #RHS, \
           (long long)LHS, (long long)RHS)

/* Check that an expression is true/non-zero */
#define CHECK_TRUE(EXPR) \
  ut_check_true(__FILE__, __LINE__, (EXPR), #EXPR)

/* Check that an expression is false/zero */
#define CHECK_FALSE(EXPR) \
  CHECK_TRUE(!(EXPR))

/* Check that two blocks of memory match, reporting the offset and byte values
 * of the first mismatch on failure. */
#define CHECK_MEM(LHS, RHS, BYTES) \
  ut_check_mem(__FILE__, __LINE__, #LHS, #RHS, (void*)(LHS), (void*)(RHS), BYTES)


/* Testing changes to structures passed by pointer.
 *
 * A typical C function has four kinds of parameters:
 *  - "state" pointers, to something which might be read and updated
 *  - "input" pointers, to something which it should not change
 *  - "output" pointers, to something which it will write but not read
 *  - "values" passed by value
 *
 * We would like set up states and inputs before testing, and verify that:
 *  - specific fields of a state are updated, nothing else changed
 *  - inputs are unchanged
 *  - outputs have specific values set
 *
 * These macros help with this, using the following workflow:
 *  - allocate two objects ("live" and "stash")
 *  - populate live states and inputs to establish the test's preconditions
 *  - copy the live objects to their stash
 *  - run the test
 *  - check postconditions in states and outputs
 *  - restore checked values to their stashed values
 *  - compare with stashed values to trap unexpected changes before freeing
 */

/* Allocate two copies of an object, declaring a pointer to the live copy.
 * They are zero-initialised. TODO: maybe fill with a sentinel value instead? */
#define STATE_ALLOC(TYPE, NAME) \
  TYPE *NAME = calloc(2, sizeof(TYPE))

/* Stash the live copy of an object, after establishing its pre-test state */
#define STATE_STASH(NAME) \
  memcpy(NAME + 1, NAME, sizeof(*NAME))

/* Check the value of a field of an object, restoring the stashed value */
#define STATE_CHECK(NAME, FIELD, EXPECTED) \
  do { \
    CHECK(NAME->FIELD, ==, EXPECTED);   \
    NAME->FIELD = (NAME + 1)->FIELD; \
  } while (0)

/* Check there are no unchecked changes before freeing the objects.
 * TIP: it can be useful to run the tests with a memory validator
 * (e.g. valgrind) to make sure these aren't omitted. */
#define STATE_FREE(NAME) \
  do { \
    const void* stash = NAME + 1; \
    CHECK_MEM(NAME, stash, sizeof(*NAME)); \
    free(NAME); \
  } while (0)


/* Implementation details. Functions are usually called via macros */
static int checks_total;
static int checks_failed;
static const char* current_test = "<UNDEFINED>";

static inline void ut_test_run(const char* name, void (*fn)(void))
{
  current_test = name;
  fn();
}

static inline int ut_test_end(void)
{
  if( checks_failed == 0 ) {
    fprintf(stderr, "Passed %d checks\n", checks_total);
    return 0;
  }
  else {
    fprintf(stderr, "FAILED %d/%d checks\n", checks_failed, checks_total);
    return 1;
  }
}

static inline void
ut_check(const char* file, int line, bool pass,
         const char* lstr, const char* cstr, const char* rstr,
         long long lval, long long rval)
{
  ++checks_total;
  if( ! pass ) {
    ++checks_failed;
    fprintf(stderr,
        "%s:%d: %s failed '%s %s %s'\n  %s = %lld\n  %s = %lld\n",
        file, line, current_test, lstr, cstr, rstr, lstr, lval, rstr, rval);
  }
}

static inline void
ut_check_true(const char* file, int line, bool pass, const char* expr)
{
  ++checks_total;
  if( ! pass ) {
    ++checks_failed;
    fprintf(stderr, "%s:%d: %s failed '%s'\n", file, line, current_test, expr);
  }
}

static inline void
ut_check_mem(const char* file, int line,
             const char* lstr, const char* rstr,
             const unsigned char* lptr, const unsigned char* rptr,
             long long bytes)
{
  long long i;
  ++checks_total;
  for( i = 0; i < bytes; ++i ) {
    if( lptr[i] != rptr[i] ) {
      ++checks_failed;
      fprintf(stderr,
          "%s:%d: %s failed %s == %s\n  %s[%lld] = %02x\n  %s[%lld] = %02x\n",
          __FILE__, __LINE__, current_test, lstr, rstr,
          lstr, i, lptr[i], rstr, i, rptr[i]);
      break;
    }
  }
}

#endif
