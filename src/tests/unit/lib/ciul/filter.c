/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2026 Advanced Micro Devices, Inc. */

/* Functions under test */
#include <etherfabric/vi.h>

/* Test infrastructure */
#include "unit_test.h"

/* Dependencies */
#include <ci/efch/op_types.h>
#include <ef_vi_internal.h>
#include <stdarg.h>
#include <netinet/ether.h>

struct ioctl_args
{
  int fd;
  int request;
  ci_filter_add_t filter;

  int filter_id;
  int rxq;
  int err;
};

struct ioctl_calls
{
  int expected;
  int received;
  struct ioctl_args** args;
};

struct add_filter_state
{
  ef_vi vi;
  ef_vi_state vi_state;
  ef_filter_spec spec;
  ef_filter_cookie cookie;
  struct ioctl_calls ioc;
};

static struct ioctl_calls* s_ioctl_calls;

int ioctl(int fd, unsigned long request, ...)
{
  va_list va;
  ci_filter_add_t* filter;
  int args_idx;
  struct ioctl_args* args;

  args_idx = s_ioctl_calls->received++;
  if( args_idx >= s_ioctl_calls->expected ) {
    errno = ENOSPC;
    return -1;
  }

  va_start(va, request);
  filter = va_arg(va, ci_filter_add_t*);
  va_end(va);

  args = s_ioctl_calls->args[args_idx];
  args->fd = fd;
  args->request = request;
  args->filter = *filter;

  if( args->err != 0 ) {
    errno = args->err;
    return -1;
  }

  filter->out.out_len = sizeof(filter->out);
  filter->out.filter_id = args->filter_id;
  filter->out.rxq = args->rxq;

  return 0;
}

static struct add_filter_state* alloc_add_filter_state(int ioctl_calls)
{
  int i;

  STATE_ALLOC(struct add_filter_state, s);
  s->vi.ep_state = &s->vi_state;

  s->ioc.expected = ioctl_calls;
  s->ioc.args = calloc(ioctl_calls, sizeof(struct ioctl_args*));
  for( i = 0; i < ioctl_calls; ++i ) {
    STATE_ALLOC(struct ioctl_args, args);
    s->ioc.args[i] = args;
  }

  s_ioctl_calls = &s->ioc;
  return s;
}

static void stash_add_filter_state(struct add_filter_state* s)
{
  int i;
  for( i = 0; i < s->ioc.expected; ++i )
    STATE_STASH(s->ioc.args[i]);

  STATE_STASH(s);
}

static void free_add_filter_state(struct add_filter_state* s)
{
  int i;
  for( i = 0; i < s->ioc.expected; ++i )
    STATE_FREE(s->ioc.args[i]);

  free(s->ioc.args);
  STATE_FREE(s);
}

/* Filter types are private, but we want to check how cookies are set */
#define EF_FILTER_IP4 2

/* Test cases */
void test_ef_vi_add_filter(void)
{
  struct add_filter_state* s = alloc_add_filter_state(1);
  struct ioctl_args* args = s->ioc.args[0];

  ef_filter_spec_init(&s->spec, EF_FILTER_FLAG_EXCLUSIVE_RXQ);
  ef_filter_spec_set_ip4_local(&s->spec, 53, 0x12345678, 0xabcd);

  args->filter_id = 3;
  args->rxq = 4;
  args->err = 0;
  stash_add_filter_state(s);

  CHECK(ef_vi_filter_add(&s->vi, 42, &s->spec, &s->cookie), ==, 0);

  STATE_CHECK(s, ioc.received, 1);

  STATE_CHECK(args, fd, 42);
  STATE_CHECK(args, request, CI_FILTER_ADD);
  STATE_CHECK(args, filter.in.in_len, sizeof(args->filter.in));
  STATE_CHECK(args, filter.in.out_size, sizeof(args->filter.out));
  STATE_CHECK(args, filter.in.flags, CI_FILTER_FLAG_EXCLUSIVE_RXQ |
                                     CI_FILTER_FLAG_ANY_RXQ);
  STATE_CHECK(args, filter.in.fields, CI_FILTER_FIELD_LOC_HOST |
                                      CI_FILTER_FIELD_LOC_PORT);
  STATE_CHECK(args, filter.in.spec.l2.type, htons(ETH_P_IP));
  STATE_CHECK(args, filter.in.spec.l3.protocol, 53);
  STATE_CHECK(args, filter.in.spec.l3.u.ipv4.daddr, 0x12345678);
  STATE_CHECK(args, filter.in.spec.l4.ports.dest, 0xabcd);

  STATE_CHECK(s, cookie.filter_id, 3);
  STATE_CHECK(s, cookie.filter_type, EF_FILTER_IP4);

  free_add_filter_state(s);
}

void test_ef_vi_add_second_filter(void)
{
  struct add_filter_state* s = alloc_add_filter_state(1);
  struct ioctl_args* args = s->ioc.args[0];
  uint64_t active_qs = 1;

  s->vi.efct_rxqs.active_qs = &active_qs;
  efct_get_rxq_state(&s->vi, 0)->qid = 4;

  ef_filter_spec_init(&s->spec, EF_FILTER_FLAG_EXCLUSIVE_RXQ);
  ef_filter_spec_set_ip4_local(&s->spec, 53, 0x12345678, 0xabcd);

  args->filter_id = 3;
  args->rxq = 4;
  args->err = 0;
  stash_add_filter_state(s);

  CHECK(ef_vi_filter_add(&s->vi, 42, &s->spec, &s->cookie), ==, 0);

  STATE_CHECK(s, ioc.received, 1);

  STATE_CHECK(args, fd, 42);
  STATE_CHECK(args, request, CI_FILTER_ADD);
  STATE_CHECK(args, filter.in.in_len, sizeof(args->filter.in));
  STATE_CHECK(args, filter.in.out_size, sizeof(args->filter.out));
  STATE_CHECK(args, filter.in.flags, CI_FILTER_FLAG_EXCLUSIVE_RXQ |
                                     CI_FILTER_FLAG_PREF_RXQ);
  STATE_CHECK(args, filter.in.fields, CI_FILTER_FIELD_LOC_HOST |
                                      CI_FILTER_FIELD_LOC_PORT |
                                      CI_FILTER_FIELD_RXQ);
  STATE_CHECK(args, filter.in.rxq_no, 4);
  STATE_CHECK(args, filter.in.spec.l2.type, htons(ETH_P_IP));
  STATE_CHECK(args, filter.in.spec.l3.protocol, 53);
  STATE_CHECK(args, filter.in.spec.l3.u.ipv4.daddr, 0x12345678);
  STATE_CHECK(args, filter.in.spec.l4.ports.dest, 0xabcd);

  STATE_CHECK(s, cookie.filter_id, 3);
  STATE_CHECK(s, cookie.filter_type, EF_FILTER_IP4);

  free_add_filter_state(s);
}

void test_ef_vi_add_third_filter_fails(void)
{
  struct add_filter_state* s = alloc_add_filter_state(3);
  uint64_t active_qs = 5; /* two queues and a gap */
  int i;

  s->vi.efct_rxqs.active_qs = &active_qs;
  efct_get_rxq_state(&s->vi, 0)->qid = 4;
  efct_get_rxq_state(&s->vi, 2)->qid = 5;

  ef_filter_spec_init(&s->spec, EF_FILTER_FLAG_EXCLUSIVE_RXQ);
  ef_filter_spec_set_ip4_local(&s->spec, 53, 0x12345678, 0xabcd);

  /* Attempts to join both queues fail, so we request a new one */
  s->ioc.args[0]->filter_id = -1;
  s->ioc.args[0]->rxq = -1;
  s->ioc.args[0]->err = EPERM;

  s->ioc.args[1]->filter_id = -1;
  s->ioc.args[1]->rxq = -1;
  s->ioc.args[1]->err = EPERM;

  s->ioc.args[2]->filter_id = 67;
  s->ioc.args[2]->rxq = 6;
  s->ioc.args[2]->err = 0;
  stash_add_filter_state(s);

  CHECK(ef_vi_filter_add(&s->vi, 42, &s->spec, &s->cookie), ==, 0);

  STATE_UPDATE(s, ioc.received, 3);

  for( i = 0; i < s->ioc.received; ++i ) {
    struct ioctl_args* args = s->ioc.args[i];
    unsigned qflag = i == 2 ? CI_FILTER_FLAG_ANY_RXQ : CI_FILTER_FLAG_PREF_RXQ;
    unsigned qfield = i == 2 ? 0 : CI_FILTER_FIELD_RXQ;
    int qno = i == 2 ? 0 : i + 4;

    STATE_CHECK(args, fd, 42);
    STATE_CHECK(args, request, CI_FILTER_ADD);
    STATE_CHECK(args, filter.in.in_len, sizeof(args->filter.in));
    STATE_CHECK(args, filter.in.out_size, sizeof(args->filter.out));
    STATE_CHECK(args, filter.in.flags, CI_FILTER_FLAG_EXCLUSIVE_RXQ | qflag);
    STATE_CHECK(args, filter.in.fields, CI_FILTER_FIELD_LOC_HOST |
                                        CI_FILTER_FIELD_LOC_PORT | qfield);
    STATE_CHECK(args, filter.in.rxq_no, qno);
    STATE_CHECK(args, filter.in.spec.l2.type, htons(ETH_P_IP));
    STATE_CHECK(args, filter.in.spec.l3.protocol, 53);
    STATE_CHECK(args, filter.in.spec.l3.u.ipv4.daddr, 0x12345678);
    STATE_CHECK(args, filter.in.spec.l4.ports.dest, 0xabcd);
  }

  STATE_CHECK(s, cookie.filter_id, 67);
  STATE_CHECK(s, cookie.filter_type, EF_FILTER_IP4);

  free_add_filter_state(s);
}

int main(void)
{
  TEST_RUN(test_ef_vi_add_filter);
  TEST_RUN(test_ef_vi_add_second_filter);
  TEST_RUN(test_ef_vi_add_third_filter_fails);
  TEST_END();
}

