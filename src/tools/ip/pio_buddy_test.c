/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2016 Xilinx, Inc. */

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author
**  \brief
**   \date
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tools_ip */

#include "libstack.h"
#include <ci/internal/pio_buddy.h>
#include <ci/app.h>


#define CHK_PT()  ci_log("%d", __LINE__)

#if CI_CFG_PIO

static void usage(const char* msg)
{
  if( msg ) {
    ci_log("%s", msg);
    ci_log(" ");
  }

  ci_log("usage:");
  ci_log("  %s [stack-index]", ci_appname);
  ci_log(" ");

  exit(-1);
}
#define N_CFG_OPTS 0


static void atexit_fn(void)
{
  libstack_end();
}


#define CI_PIO_BUDDY_TEST_MAX_ORDER (CI_CFG_MIN_PIO_BLOCK_ORDER + \
                                     CI_PIO_BUDDY_MAX_ORDER)
#define CI_PIO_BUDDY_TEST_LEN (1 << CI_PIO_BUF_ORDER)
#define OFFSET_TO_ADDR(o) (o / (1u << CI_CFG_MIN_PIO_BLOCK_ORDER))
#define ADDR_TO_OFFSET(a) (a * (1u << CI_CFG_MIN_PIO_BLOCK_ORDER))


void test_buddy_0(ci_netif* ni)
{
  ci_pio_buddy_allocator* b = &ni->state->nic[0].pio_buddy;
  int a1;

  CHK_PT();
  ci_pio_buddy_ctor(ni, b, CI_PIO_BUDDY_TEST_LEN);
  ci_pio_buddy_dtor(ni, b);

  CHK_PT();
  ci_pio_buddy_ctor(ni, b, CI_PIO_BUDDY_TEST_LEN);

  CHK_PT();
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER));
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER);

  CHK_PT();
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER));
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER);
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER));
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER);

  CHK_PT();
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER));
  CI_TEST(ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER) < 0);
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER);
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER));
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER);

  CHK_PT();
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER));
  CI_TEST(ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER) < 0);
  CI_TEST(ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER) < 0);
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER);
}


void test_buddy_1(ci_netif* ni)
{
  ci_pio_buddy_allocator* b = &ni->state->nic[0].pio_buddy;
  int a1, a2;

  CHK_PT();
  ci_pio_buddy_ctor(ni, b, CI_PIO_BUDDY_TEST_LEN);
  ci_pio_buddy_dtor(ni, b);

  CHK_PT();
  ci_pio_buddy_ctor(ni, b, CI_PIO_BUDDY_TEST_LEN);

  CHK_PT();
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER-1));
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER-1);

  CHK_PT();
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER-1));
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER-1);
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER-1));
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER-1);

  CHK_PT();
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER-1));
  CI_TRY(a2 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER-1));
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER-1);
  ci_pio_buddy_free(ni, b, a2, CI_PIO_BUDDY_TEST_MAX_ORDER-1);

  CHK_PT();
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER));
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER);

  CHK_PT();
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER));
  CI_TEST(ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER-1) < 0);
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER);

  CHK_PT();
  CI_TRY(a1 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER-1));
  CI_TRY(a2 = ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER-1));
  CI_TEST(ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER-1) < 0);
  CI_TEST(ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER) < 0);
  CI_TEST(ci_pio_buddy_alloc(ni, b, CI_PIO_BUDDY_TEST_MAX_ORDER+1) < 0);
  ci_pio_buddy_free(ni, b, a1, CI_PIO_BUDDY_TEST_MAX_ORDER-1);
  ci_pio_buddy_free(ni, b, a2, CI_PIO_BUDDY_TEST_MAX_ORDER-1);
}


void test_buddy_2(ci_netif* ni)
{
  ci_pio_buddy_allocator* b = &ni->state->nic[0].pio_buddy;
  int order = CI_PIO_BUDDY_TEST_MAX_ORDER;
  char* allocated;
  int n_allocated = 0;

  CHK_PT();

  allocated = (char*) malloc(ci_pow2(order));
  CI_TEST(allocated);
  memset(allocated, 0, ci_pow2(order));

  ci_pio_buddy_ctor(ni, b, CI_PIO_BUDDY_TEST_LEN);

  while( n_allocated < (1u << CI_PIO_BUDDY_MAX_ORDER) ) {
    int i, offset;
    int order = (rand() % CI_PIO_BUDDY_MAX_ORDER/2)+CI_CFG_MIN_PIO_BLOCK_ORDER;
    offset = ci_pio_buddy_alloc(ni, b, order);
    if( offset >= 0 ) {
      for( i = 0; i < (int)ci_pow2(order); ++i ) {
	CI_TEST(allocated[OFFSET_TO_ADDR(offset) + i] == 0);
	allocated[OFFSET_TO_ADDR(offset)  + i] = 1;
	++n_allocated;
      }
    }
  }

  ci_pio_buddy_dtor(ni, b);
  free(allocated);
}


void test_buddy_3(ci_netif* ni)
{
  ci_pio_buddy_allocator* b = &ni->state->nic[0].pio_buddy;
  int n_blocks = 1u << CI_PIO_BUDDY_MAX_ORDER;

  int i, j, a1, a2, a3, a4;

  CHK_PT();

  ci_pio_buddy_ctor(ni, b, CI_PIO_BUDDY_TEST_LEN);

  for( i = 0; i < n_blocks / 4; ++i ) {

    int this_order = ci_log2_ge(i, 0) + CI_CFG_MIN_PIO_BLOCK_ORDER;

    a1 = ci_pio_buddy_alloc(ni, b, this_order);

    for(j = 0; j < n_blocks; ++j) {

      a2 = ci_pio_buddy_alloc(ni, b, this_order);
      a3 = ci_pio_buddy_alloc(ni, b, this_order);
      a4 = ci_pio_buddy_alloc(ni, b, this_order);

      ci_pio_buddy_free(ni, b, a2, this_order);
      ci_pio_buddy_free(ni, b, a3, this_order);
      ci_pio_buddy_free(ni, b, a4, this_order);

      a2 = ci_pio_buddy_alloc(ni, b, this_order);
      a3 = ci_pio_buddy_alloc(ni, b, this_order);
      a4 = ci_pio_buddy_alloc(ni, b, this_order);
      ci_pio_buddy_free(ni, b, a4, this_order);
      ci_pio_buddy_free(ni, b, a3, this_order);
      ci_pio_buddy_free(ni, b, a2, this_order);

      a2 = ci_pio_buddy_alloc(ni, b, this_order);
      a3 = ci_pio_buddy_alloc(ni, b, this_order);
      a4 = ci_pio_buddy_alloc(ni, b, this_order);

      ci_pio_buddy_free(ni, b, a3, this_order);
      ci_pio_buddy_free(ni, b, a2, this_order);
      ci_pio_buddy_free(ni, b, a4, this_order);
    }
    ci_pio_buddy_free(ni, b, a1, this_order);

  }
  ci_pio_buddy_dtor(ni, b);
}


void test_buddy_4(ci_netif* ni)
{
#define B4_N (1u << CI_PIO_BUDDY_MAX_ORDER)
  ci_pio_buddy_allocator* b = &ni->state->nic[0].pio_buddy;
  int n_blocks = B4_N;
  int i, j, a1[B4_N], a2[B4_N], a3[B4_N], a4[B4_N];

  CHK_PT();

 
  ci_pio_buddy_ctor(ni, b, CI_PIO_BUDDY_TEST_LEN);

  for( i = 0;  i < (n_blocks << 1); ++i ) {

    for(j = 0; j < (n_blocks >> 1); ++j)
      CI_TRY(a1[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));

    for(j = 0;  j < (n_blocks >> 1); ++j)
      CI_TRY(a2[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));

    for(j = 0;  j < (n_blocks >> 1); ++j)
      ci_pio_buddy_free(ni, b, a1[j], CI_CFG_MIN_PIO_BLOCK_ORDER);

    for(j = 0;  j < (n_blocks >> 1); ++j)
      ci_pio_buddy_free(ni, b, a2[j], CI_CFG_MIN_PIO_BLOCK_ORDER);

    for(j = 0; j < (n_blocks >> 1); ++j)
      CI_TRY(a1[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));

    for(j = 0;  j < (n_blocks >> 1); ++j)
      CI_TRY(a2[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));

    for(j = 0;  j < (n_blocks >> 1); ++j)
      ci_pio_buddy_free(ni, b, a2[j], CI_CFG_MIN_PIO_BLOCK_ORDER);

    for(j = 0;  j < (n_blocks >> 1); ++j)
      ci_pio_buddy_free(ni, b, a1[j], CI_CFG_MIN_PIO_BLOCK_ORDER);

    for(j = 0; j < (n_blocks >> 1); ++j) {
      CI_TRY(a1[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));
      CI_TRY(a2[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));
    }

    for(j = 0; j < (n_blocks >> 1); ++j) {
      ci_pio_buddy_free(ni, b, a2[j], CI_CFG_MIN_PIO_BLOCK_ORDER);
      ci_pio_buddy_free(ni, b, a1[j], CI_CFG_MIN_PIO_BLOCK_ORDER);
    }

    for(j = 0; j < (n_blocks >> 1); ++j) {
      CI_TRY(a1[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));
      CI_TRY(a2[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));
    }

    for(j = 0; j < (n_blocks >> 1); ++j) {
      ci_pio_buddy_free(ni, b, a1[j], CI_CFG_MIN_PIO_BLOCK_ORDER);
      ci_pio_buddy_free(ni, b, a2[j], CI_CFG_MIN_PIO_BLOCK_ORDER);
    }

    for(j = 0; j < (n_blocks >> 2); ++j) {
      CI_TRY(a2[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));
      CI_TRY(a1[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));
    }

    for(j = 0; j < (n_blocks >> 2); ++j) {
      CI_TRY(a3[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));
      ci_pio_buddy_free(ni, b, a1[j], CI_CFG_MIN_PIO_BLOCK_ORDER);
      CI_TRY(a4[j] = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER));
      ci_pio_buddy_free(ni, b, a2[j], CI_CFG_MIN_PIO_BLOCK_ORDER);
    }

    for(j = 0;  j < (n_blocks >> 2); ++j) {
      ci_pio_buddy_free(ni, b, a3[j], CI_CFG_MIN_PIO_BLOCK_ORDER);
      ci_pio_buddy_free(ni, b, a4[j], CI_CFG_MIN_PIO_BLOCK_ORDER);
    }

  }
  ci_pio_buddy_dtor(ni, b);
}


void test_buddy_5(ci_netif* ni)
{
  ci_pio_buddy_allocator* b = &ni->state->nic[0].pio_buddy;

  int i, ns, ne;
  int n_blocks = 1u << CI_PIO_BUDDY_MAX_ORDER;
  char allocated[1u << CI_PIO_BUDDY_MAX_ORDER];
  int o, high, a1, a2;

  CHK_PT();

  for( ns = 0; ns <= n_blocks; ++ns )
    for( ne = 0; ne <= n_blocks - ns; ++ne ) {
      high = n_blocks - ne;
      ci_pio_buddy_ctor(ni, b, CI_PIO_BUDDY_TEST_LEN);
      /* Allocate the lot. */
      for( i = 0; i < n_blocks; ++i ) {
        CI_TEST(a1 = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER)>=0);
      }
      CI_TEST(ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER) < 0);
      /* Release back the range that "exists". */
      for( i = ns; i < high; ++i ) {
        ci_pio_buddy_free(ni, b, ADDR_TO_OFFSET(i), CI_CFG_MIN_PIO_BLOCK_ORDER);
      }
      /* Determine size of largest block. */
      for( o = CI_PIO_BUDDY_MAX_ORDER; o >= 0; --o )
        if( CI_ROUND_UP(ns, 1 << o) + (1 << o) <= high )
          break;
      /* Verify that largest block can be allocated, and is where we expect
       * is to be.  There can be at most two blocks of this size. */
      if( o >= 0 ) {
        o += CI_CFG_MIN_PIO_BLOCK_ORDER;
        CI_TEST(ci_pio_buddy_alloc(ni, b, o + 1) < 0);
        a1 = ci_pio_buddy_alloc(ni, b, o);

        o -= CI_CFG_MIN_PIO_BLOCK_ORDER;
        CI_TEST(OFFSET_TO_ADDR(a1) >= ns);
        if(! (OFFSET_TO_ADDR(a1) == CI_ROUND_UP(ns, 1 << o) ||
                OFFSET_TO_ADDR(a1) == CI_ROUND_UP(ns, 1 << o) + (1 << o)) )
        CI_TEST(OFFSET_TO_ADDR(a1) == CI_ROUND_UP(ns, 1 << o) ||
                OFFSET_TO_ADDR(a1) == CI_ROUND_UP(ns, 1 << o) + (1 << o));

        o += CI_CFG_MIN_PIO_BLOCK_ORDER;
        a2 = ci_pio_buddy_alloc(ni, b, o);
        CI_TEST(ci_pio_buddy_alloc(ni, b, o) < 0);
        ci_pio_buddy_free(ni, b, a1, o);
        if( a2 >= 0 )
          ci_pio_buddy_free(ni, b, a2, o);
      }
      else
        CI_TEST(ci_pio_buddy_alloc(ni, b, 0) < 0);
      /* Verify that we can allocate the rest of the entries, and that they
      ** don't lie within the reserved region.
      */
      memset(allocated, 0, sizeof(allocated));
      for( i = 0; i < n_blocks - ns - ne; ++i ) {
        int a = ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER);
        CI_TEST(OFFSET_TO_ADDR(a) >= ns);
        CI_TEST(OFFSET_TO_ADDR(a) < high);
        CI_TEST(allocated[OFFSET_TO_ADDR(a)] == 0);
        allocated[OFFSET_TO_ADDR(a)] = 1;
      }
      CI_TEST(ci_pio_buddy_alloc(ni, b, CI_CFG_MIN_PIO_BLOCK_ORDER) < 0);
      ci_pio_buddy_dtor(ni, b);
    }

  CHK_PT();
}


int main(int argc, char* argv[])
{
  netif_t* netif;
  unsigned stack_id;

  ci_app_usage = usage;
  ci_app_getopt("[stack-index]", &argc, argv, 0, 0);
  --argc; ++argv;

  if( argc != 1 )
    usage(NULL);

  CI_TRY(libstack_init(NULL));
  atexit(atexit_fn);

  if( sscanf(argv[0], "%u", &stack_id) == 1 ) {
    if( ! stack_attach(stack_id) ) {
      ci_log("No such stack id: %d", stack_id);
      usage(NULL);
    }
  }

  netif = stack_attached(stack_id);

  test_buddy_0(&netif->ni);
  test_buddy_1(&netif->ni);
  test_buddy_2(&netif->ni);
  test_buddy_3(&netif->ni);
  test_buddy_4(&netif->ni);
  test_buddy_5(&netif->ni);

  return 0;
}

#else /* CI_CFG_PIO */

int main(int argc, char* argv[])
{
  return 0;
}

#endif /* CI_CFG_PIO */
/*! \cidoxg_end */
