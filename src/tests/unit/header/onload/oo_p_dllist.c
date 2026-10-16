/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

/* Dependencies */
#include <stdbool.h>
#include <ci/tools.h>
#include <onload/state_p.h>
#define OO_P_DLLIST_NO_CODE
#include <onload/oo_p_dllist.h>

typedef struct undefined citp_waitable;

typedef struct
{
  size_t bytes;
  char* memory;
} ci_netif;

#define CI_NETIF_PTR(ni, p) (ni->memory + OO_P_OFF(p))

static oo_p oo_state_ptr_to_statep(ci_netif* ni, const void* ptr)
{
  oo_p p;
  OO_P_INIT(p, ni, (char*)ptr - ni->memory);
  return p;
}

/* Functions under test */
#include <onload/oo_p_dllist.h>

/* Test infrastructure */
#include "unit_test.h"

struct list_node
{
  struct oo_p_dllink link;
  char label;
};

static oo_p state_alloc(ci_netif* ni, size_t bytes)
{
  /* This will invalidate pointers (but not oo_p's) from previous allocations */
  oo_p p;
  OO_P_INIT(p, ni, ni->bytes);
  ni->bytes += bytes;
  ni->memory = realloc(ni->memory, ni->bytes);
  return p;
}

static struct list_node*
node_from_link(ci_netif* ni, struct oo_p_dllink_state link)
{
  return CI_CONTAINER(struct list_node, link, link.l);
}

static struct oo_p_dllink_state
make_list(ci_netif* ni, const char* labels)
{
  oo_p list_p = state_alloc(ni, sizeof(struct oo_p_dllink));
  oo_p_dllink_init(ni, oo_p_dllink_statep(ni, list_p));

  while( *labels != 0 ) {
    oo_p node_p = state_alloc(ni, sizeof(struct list_node));
    struct list_node* node = (struct list_node*)CI_NETIF_PTR(ni, node_p);
    struct oo_p_dllink_state link = oo_p_dllink_ptr(ni, &node->link);

    node->label = *labels++;
    oo_p_dllink_add_tail(ni, oo_p_dllink_statep(ni, list_p), link);
  }

  return oo_p_dllink_statep(ni, list_p);
}

#define CHECK_LIST(ni, list, labels) { \
  const char* label = labels; \
  struct oo_p_dllink_state link; \
  oo_p_dllink_for_each(ni, link, list) { \
    CHECK(node_from_link(ni, link)->label, ==, *label); \
    if( *label != 0 ) ++label; \
  } \
  CHECK(*label, ==, 0); \
}

/* Test cases */
static void test_oo_p_dllist(void)
{
  ci_netif netif = {};
  ci_netif* ni = &netif;
  struct oo_p_dllink_state list;

  list = make_list(ni, "");
  CHECK_LIST(ni, list, "");

  list = make_list(ni, "x");
  CHECK_LIST(ni, list, "x");

  list = make_list(ni, "12345");
  CHECK_LIST(ni, list, "12345");
}

static void test_oo_p_dllist_validate_links(void)
{
  ci_netif netif = {};
  ci_netif* ni = &netif;
  struct oo_p_dllink_state list, link;

  list = make_list(ni, "");
  CHECK_TRUE(oo_p_dllink_validate_links(ni, list));

  list = make_list(ni, "x");
  CHECK_TRUE(oo_p_dllink_validate_links(ni, list));
  list.l->next = list.p;
  CHECK_FALSE(oo_p_dllink_validate_links(ni, list));
  CHECK_TRUE(oo_p_dllink_validate_links(ni, list));
  CHECK_LIST(ni, list, "");

  list = make_list(ni, "x");
  link = oo_p_dllink_statep(ni, list.l->next);
  link.l->next = link.p;
  CHECK_FALSE(oo_p_dllink_validate_links(ni, list));
  CHECK_TRUE(oo_p_dllink_validate_links(ni, list));
  CHECK_LIST(ni, list, "x");

  list = make_list(ni, "x");
  list.l->prev = list.p;
  CHECK_FALSE(oo_p_dllink_validate_links(ni, list));
  CHECK_TRUE(oo_p_dllink_validate_links(ni, list));
  CHECK_LIST(ni, list, "x");

  list = make_list(ni, "12345");
  CHECK_TRUE(oo_p_dllink_validate_links(ni, list));
  link = oo_p_dllink_statep(ni, list.l->next);
  link = oo_p_dllink_statep(ni, link.l->next);
  link.l->next = list.p;
  CHECK_FALSE(oo_p_dllink_validate_links(ni, list));
  CHECK_TRUE(oo_p_dllink_validate_links(ni, list));
  CHECK_LIST(ni, list, "12");

  list = make_list(ni, "12345");
  list.l->prev = list.p;
  CHECK_FALSE(oo_p_dllink_validate_links(ni, list));
  CHECK_TRUE(oo_p_dllink_validate_links(ni, list));
  CHECK_LIST(ni, list, "12345");
}

int main(void)
{
  TEST_RUN(test_oo_p_dllist);
  TEST_RUN(test_oo_p_dllist_validate_links);
  TEST_END();
}
