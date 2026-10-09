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

struct add_filter_state
{
  ef_vi vi;
  ef_vi_state vi_state;
  ef_filter_spec spec;
  ef_filter_cookie cookie;
  struct ioctl_args ioc;
};

static struct ioctl_args* s_ioctl_args;

int ioctl(int fd, unsigned long request, ...)
{
  va_list va;
  ci_filter_add_t* filter;

  va_start(va, request);
  filter = va_arg(va, ci_filter_add_t*);
  va_end(va);

  s_ioctl_args->fd = fd;
  s_ioctl_args->request = request;
  s_ioctl_args->filter = *filter;

  filter->out.out_len = sizeof(filter->out);
  filter->out.filter_id = s_ioctl_args->filter_id;
  filter->out.rxq = s_ioctl_args->rxq;

  if( s_ioctl_args->err == 0 )
    return 0;

  errno = s_ioctl_args->err;
  return -1;
}

static struct add_filter_state* alloc_add_filter_state(void)
{
  STATE_ALLOC(struct add_filter_state, s);
  s->vi.ep_state = &s->vi_state;
  s_ioctl_args = &s->ioc;
  return s;
}

/* Filter types are private, but we want to check how cookies are set */
#define EF_FILTER_IP4 2

/* Test cases */
void test_ef_vi_add_filter(void)
{
  struct add_filter_state* s = alloc_add_filter_state();

  ef_filter_spec_init(&s->spec, EF_FILTER_FLAG_EXCLUSIVE_RXQ);
  ef_filter_spec_set_ip4_local(&s->spec, 53, 0x12345678, 0xabcd);

  s->ioc.filter_id = 3;
  s->ioc.rxq = 4;
  s->ioc.err = 0;
  STATE_STASH(s);

  CHECK(ef_vi_filter_add(&s->vi, 42, &s->spec, &s->cookie), ==, 0);

  STATE_CHECK(s, ioc.fd, 42);
  STATE_CHECK(s, ioc.request, CI_FILTER_ADD);
  STATE_CHECK(s, ioc.filter.in.in_len, sizeof(s->ioc.filter.in));
  STATE_CHECK(s, ioc.filter.in.out_size, sizeof(s->ioc.filter.out));
  STATE_CHECK(s, ioc.filter.in.flags, CI_FILTER_FLAG_EXCLUSIVE_RXQ);
  STATE_CHECK(s, ioc.filter.in.fields, CI_FILTER_FIELD_LOC_HOST |
                                       CI_FILTER_FIELD_LOC_PORT);
  STATE_CHECK(s, ioc.filter.in.spec.l2.type, htons(ETH_P_IP));
  STATE_CHECK(s, ioc.filter.in.spec.l3.protocol, 53);
  STATE_CHECK(s, ioc.filter.in.spec.l3.u.ipv4.daddr, 0x12345678);
  STATE_CHECK(s, ioc.filter.in.spec.l4.ports.dest, 0xabcd);

  STATE_CHECK(s, cookie.filter_id, 3);
  STATE_CHECK(s, cookie.filter_type, EF_FILTER_IP4);

  STATE_FREE(s);
}

void test_ef_vi_add_second_filter(void)
{
  struct add_filter_state* s = alloc_add_filter_state();
  uint64_t active_qs = 1;

  s->vi.efct_rxqs.active_qs = &active_qs;
  efct_get_rxq_state(&s->vi, 0)->qid = 4;

  ef_filter_spec_init(&s->spec, EF_FILTER_FLAG_EXCLUSIVE_RXQ);
  ef_filter_spec_set_ip4_local(&s->spec, 53, 0x12345678, 0xabcd);

  s->ioc.filter_id = 3;
  s->ioc.rxq = 4;
  s->ioc.err = 0;
  STATE_STASH(s);

  CHECK(ef_vi_filter_add(&s->vi, 42, &s->spec, &s->cookie), ==, 0);

  STATE_CHECK(s, ioc.fd, 42);
  STATE_CHECK(s, ioc.request, CI_FILTER_ADD);
  STATE_CHECK(s, ioc.filter.in.in_len, sizeof(s->ioc.filter.in));
  STATE_CHECK(s, ioc.filter.in.out_size, sizeof(s->ioc.filter.out));
  STATE_CHECK(s, ioc.filter.in.flags, CI_FILTER_FLAG_EXCLUSIVE_RXQ |
                                      CI_FILTER_FLAG_PREF_RXQ);
  STATE_CHECK(s, ioc.filter.in.fields, CI_FILTER_FIELD_LOC_HOST |
                                       CI_FILTER_FIELD_LOC_PORT |
                                       CI_FILTER_FIELD_RXQ);
  STATE_CHECK(s, ioc.filter.in.rxq_no, 4);
  STATE_CHECK(s, ioc.filter.in.spec.l2.type, htons(ETH_P_IP));
  STATE_CHECK(s, ioc.filter.in.spec.l3.protocol, 53);
  STATE_CHECK(s, ioc.filter.in.spec.l3.u.ipv4.daddr, 0x12345678);
  STATE_CHECK(s, ioc.filter.in.spec.l4.ports.dest, 0xabcd);

  STATE_CHECK(s, cookie.filter_id, 3);
  STATE_CHECK(s, cookie.filter_type, EF_FILTER_IP4);

  STATE_FREE(s);
}

void test_ef_vi_add_second_filter_fails(void)
{
  struct add_filter_state* s = alloc_add_filter_state();
  uint64_t active_qs = 1;

  s->vi.efct_rxqs.active_qs = &active_qs;
  efct_get_rxq_state(&s->vi, 0)->qid = 4;

  ef_filter_spec_init(&s->spec, EF_FILTER_FLAG_EXCLUSIVE_RXQ);
  ef_filter_spec_set_ip4_local(&s->spec, 53, 0x12345678, 0xabcd);

  s->ioc.filter_id = -1;
  s->ioc.rxq = -1;
  s->ioc.err = EPERM;
  STATE_STASH(s);

  CHECK(ef_vi_filter_add(&s->vi, 42, &s->spec, &s->cookie), ==, -EPERM);

  STATE_CHECK(s, ioc.fd, 42);
  STATE_CHECK(s, ioc.request, CI_FILTER_ADD);
  STATE_CHECK(s, ioc.filter.in.in_len, sizeof(s->ioc.filter.in));
  STATE_CHECK(s, ioc.filter.in.out_size, sizeof(s->ioc.filter.out));
  STATE_CHECK(s, ioc.filter.in.flags, CI_FILTER_FLAG_EXCLUSIVE_RXQ |
                                      CI_FILTER_FLAG_PREF_RXQ);
  STATE_CHECK(s, ioc.filter.in.fields, CI_FILTER_FIELD_LOC_HOST |
                                       CI_FILTER_FIELD_LOC_PORT |
                                       CI_FILTER_FIELD_RXQ);
  STATE_CHECK(s, ioc.filter.in.rxq_no, 4);
  STATE_CHECK(s, ioc.filter.in.spec.l2.type, htons(ETH_P_IP));
  STATE_CHECK(s, ioc.filter.in.spec.l3.protocol, 53);
  STATE_CHECK(s, ioc.filter.in.spec.l3.u.ipv4.daddr, 0x12345678);
  STATE_CHECK(s, ioc.filter.in.spec.l4.ports.dest, 0xabcd);

  /* TODO should retry without PREF_RXQ, requesting a new queue */

  STATE_FREE(s);
}

int main(void)
{
  TEST_RUN(test_ef_vi_add_filter);
  TEST_RUN(test_ef_vi_add_second_filter);
  TEST_RUN(test_ef_vi_add_second_filter_fails);
  TEST_END();
}

