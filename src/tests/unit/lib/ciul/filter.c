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

struct pre_filter_args
{
  int calls;

  ef_vi* vi;
  bool shared;
  bool interrupts;

  int rc;
};

struct post_filter_args
{
  int calls;

  ef_vi* vi;
  const ef_filter_spec* spec;
  ef_filter_cookie cookie;
  int rxq;
  bool shared;

  int rc;
};

struct add_filter_state
{
  ef_vi vi;
  ef_vi_state vi_state;
  ef_filter_spec spec;
  ef_filter_cookie cookie;
  struct pre_filter_args pre_filter_args;
  struct ioctl_calls ioctl_calls;
  struct post_filter_args post_filter_args;
};

static struct add_filter_state* state;

int ioctl(int fd, unsigned long request, ...)
{
  va_list va;
  ci_filter_add_t* filter;
  int args_idx;
  struct ioctl_args* args;

  args_idx = state->ioctl_calls.received++;
  if( args_idx >= state->ioctl_calls.expected ) {
    errno = ENOSPC;
    return -1;
  }

  va_start(va, request);
  filter = va_arg(va, ci_filter_add_t*);
  va_end(va);

  args = state->ioctl_calls.args[args_idx];
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

static int pre_filter_add(ef_vi* vi, bool shared, bool interrupts)
{
  struct pre_filter_args* args = &state->pre_filter_args;

  if( state->ioctl_calls.received != 0 )
    return -EPROTO;

  args->calls++;

  args->vi = vi;
  args->shared = shared;
  args->interrupts = interrupts;

  return args->rc;
}

static int post_filter_add(ef_vi* vi, const ef_filter_spec* spec,
                           const ef_filter_cookie* cookie, int rxq, bool shared)
{
  struct post_filter_args* args = &state->post_filter_args;

  if( state->ioctl_calls.received != state->ioctl_calls.expected )
    return -EPROTO;

  args->calls++;

  args->vi = vi;
  args->spec = spec;
  args->cookie = *cookie;
  args->rxq = rxq;
  args->shared = shared;

  return args->rc;
}

static struct add_filter_state* alloc_add_filter_state(int ioctl_calls)
{
  int i;

  STATE_ALLOC(struct add_filter_state, s);
  s->vi.ep_state = &s->vi_state;
  s->vi.internal_ops.pre_filter_add = pre_filter_add;
  s->vi.internal_ops.post_filter_add = post_filter_add;

  s->ioctl_calls.expected = ioctl_calls;
  s->ioctl_calls.args = calloc(ioctl_calls, sizeof(struct ioctl_args*));
  for( i = 0; i < ioctl_calls; ++i ) {
    STATE_ALLOC(struct ioctl_args, args);
    s->ioctl_calls.args[i] = args;
  }

  state = s;
  return s;
}

static void stash_add_filter_state(struct add_filter_state* s)
{
  int i;
  for( i = 0; i < s->ioctl_calls.expected; ++i )
    STATE_STASH(s->ioctl_calls.args[i]);

  STATE_STASH(s);
}

static void free_add_filter_state(struct add_filter_state* s)
{
  int i;
  for( i = 0; i < s->ioctl_calls.expected; ++i )
    STATE_FREE(s->ioctl_calls.args[i]);

  free(s->ioctl_calls.args);
  STATE_FREE(s);
}

/* Filter types are private, but we want to check how cookies are set */
#define EF_FILTER_IP4 2

/* Test cases */
void test_ef_vi_add_filter(void)
{
  struct add_filter_state* s = alloc_add_filter_state(1);
  struct ioctl_args* args = s->ioctl_calls.args[0];

  ef_filter_spec_init(&s->spec, EF_FILTER_FLAG_EXCLUSIVE_RXQ);
  ef_filter_spec_set_ip4_local(&s->spec, 53, 0x12345678, 0xabcd);

  args->filter_id = 3;
  args->rxq = 4;
  args->err = 0;
  stash_add_filter_state(s);

  CHECK(ef_vi_filter_add(&s->vi, 42, &s->spec, &s->cookie), ==, 0);

  STATE_CHECK(s, pre_filter_args.calls, 1);
  STATE_CHECK(s, pre_filter_args.vi, &s->vi);
  STATE_CHECK(s, pre_filter_args.shared, false);
  STATE_CHECK(s, pre_filter_args.interrupts, false);

  STATE_CHECK(s, ioctl_calls.received, 1);

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

  STATE_CHECK(s, post_filter_args.calls, 1);
  STATE_CHECK(s, post_filter_args.vi, &s->vi);
  STATE_CHECK(s, post_filter_args.spec, &s->spec);
  STATE_CHECK(s, post_filter_args.cookie.filter_id, s->cookie.filter_id);
  STATE_CHECK(s, post_filter_args.cookie.filter_type, s->cookie.filter_type);
  STATE_CHECK(s, post_filter_args.rxq, 4);
  STATE_CHECK(s, post_filter_args.shared, false);

  STATE_CHECK(s, cookie.filter_id, 3);
  STATE_CHECK(s, cookie.filter_type, EF_FILTER_IP4);

  free_add_filter_state(s);
}

void test_ef_vi_add_filter_existing_queue(void)
{
  struct add_filter_state* s = alloc_add_filter_state(1);
  struct ioctl_args* args = s->ioctl_calls.args[0];
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

  STATE_CHECK(s, pre_filter_args.calls, 1);
  STATE_CHECK(s, pre_filter_args.vi, &s->vi);
  STATE_CHECK(s, pre_filter_args.shared, false);
  STATE_CHECK(s, pre_filter_args.interrupts, false);

  STATE_CHECK(s, ioctl_calls.received, 1);

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

  STATE_CHECK(s, post_filter_args.calls, 1);
  STATE_CHECK(s, post_filter_args.vi, &s->vi);
  STATE_CHECK(s, post_filter_args.spec, &s->spec);
  STATE_CHECK(s, post_filter_args.cookie.filter_id, s->cookie.filter_id);
  STATE_CHECK(s, post_filter_args.cookie.filter_type, s->cookie.filter_type);
  STATE_CHECK(s, post_filter_args.rxq, 4);
  STATE_CHECK(s, post_filter_args.shared, false);

  STATE_CHECK(s, cookie.filter_id, 3);
  STATE_CHECK(s, cookie.filter_type, EF_FILTER_IP4);

  free_add_filter_state(s);
}

void test_ef_vi_add_filter_second_existing_queue(void)
{
  struct add_filter_state* s = alloc_add_filter_state(2);
  uint64_t active_qs = 5; /* two queues and a gap */
  int i;

  s->vi.efct_rxqs.active_qs = &active_qs;
  efct_get_rxq_state(&s->vi, 0)->qid = 4;
  efct_get_rxq_state(&s->vi, 2)->qid = 5;

  ef_filter_spec_init(&s->spec, EF_FILTER_FLAG_EXCLUSIVE_RXQ);
  ef_filter_spec_set_ip4_local(&s->spec, 53, 0x12345678, 0xabcd);

  /* Attempt to join first queue fails, second succeeds */
  s->ioctl_calls.args[0]->filter_id = -1;
  s->ioctl_calls.args[0]->rxq = -1;
  s->ioctl_calls.args[0]->err = EPERM;

  s->ioctl_calls.args[1]->filter_id = 67;
  s->ioctl_calls.args[1]->rxq = 5;
  s->ioctl_calls.args[1]->err = 0;
  stash_add_filter_state(s);

  CHECK(ef_vi_filter_add(&s->vi, 42, &s->spec, &s->cookie), ==, 0);

  STATE_CHECK(s, pre_filter_args.calls, 1);
  STATE_CHECK(s, pre_filter_args.vi, &s->vi);
  STATE_CHECK(s, pre_filter_args.shared, false);
  STATE_CHECK(s, pre_filter_args.interrupts, false);

  STATE_UPDATE(s, ioctl_calls.received, 2);

  for( i = 0; i < s->ioctl_calls.received; ++i ) {
    struct ioctl_args* args = s->ioctl_calls.args[i];

    STATE_CHECK(args, fd, 42);
    STATE_CHECK(args, request, CI_FILTER_ADD);
    STATE_CHECK(args, filter.in.in_len, sizeof(args->filter.in));
    STATE_CHECK(args, filter.in.out_size, sizeof(args->filter.out));
    STATE_CHECK(args, filter.in.flags, CI_FILTER_FLAG_EXCLUSIVE_RXQ |
                                       CI_FILTER_FLAG_PREF_RXQ);
    STATE_CHECK(args, filter.in.fields, CI_FILTER_FIELD_LOC_HOST |
                                        CI_FILTER_FIELD_LOC_PORT |
                                        CI_FILTER_FIELD_RXQ);
    STATE_CHECK(args, filter.in.rxq_no, i + 4);
    STATE_CHECK(args, filter.in.spec.l2.type, htons(ETH_P_IP));
    STATE_CHECK(args, filter.in.spec.l3.protocol, 53);
    STATE_CHECK(args, filter.in.spec.l3.u.ipv4.daddr, 0x12345678);
    STATE_CHECK(args, filter.in.spec.l4.ports.dest, 0xabcd);
  }

  STATE_CHECK(s, post_filter_args.calls, 1);
  STATE_CHECK(s, post_filter_args.vi, &s->vi);
  STATE_CHECK(s, post_filter_args.spec, &s->spec);
  STATE_CHECK(s, post_filter_args.cookie.filter_id, s->cookie.filter_id);
  STATE_CHECK(s, post_filter_args.cookie.filter_type, s->cookie.filter_type);
  STATE_CHECK(s, post_filter_args.rxq, 5);
  STATE_CHECK(s, post_filter_args.shared, false);

  STATE_CHECK(s, cookie.filter_id, 67);
  STATE_CHECK(s, cookie.filter_type, EF_FILTER_IP4);

  free_add_filter_state(s);
}

void test_ef_vi_add_filter_new_queue(void)
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
  s->ioctl_calls.args[0]->filter_id = -1;
  s->ioctl_calls.args[0]->rxq = -1;
  s->ioctl_calls.args[0]->err = EPERM;

  s->ioctl_calls.args[1]->filter_id = -1;
  s->ioctl_calls.args[1]->rxq = -1;
  s->ioctl_calls.args[1]->err = EPERM;

  s->ioctl_calls.args[2]->filter_id = 67;
  s->ioctl_calls.args[2]->rxq = 6;
  s->ioctl_calls.args[2]->err = 0;
  stash_add_filter_state(s);

  CHECK(ef_vi_filter_add(&s->vi, 42, &s->spec, &s->cookie), ==, 0);

  STATE_CHECK(s, pre_filter_args.calls, 1);
  STATE_CHECK(s, pre_filter_args.vi, &s->vi);
  STATE_CHECK(s, pre_filter_args.shared, false);
  STATE_CHECK(s, pre_filter_args.interrupts, false);

  STATE_UPDATE(s, ioctl_calls.received, 3);

  for( i = 0; i < s->ioctl_calls.received; ++i ) {
    struct ioctl_args* args = s->ioctl_calls.args[i];
    unsigned qflag = i == 2 ? CI_FILTER_FLAG_ANY_RXQ : CI_FILTER_FLAG_PREF_RXQ;
    unsigned qfield = i == 2 ? 0 : CI_FILTER_FIELD_RXQ;
    int qid = i == 2 ? 0 : i + 4;

    STATE_CHECK(args, fd, 42);
    STATE_CHECK(args, request, CI_FILTER_ADD);
    STATE_CHECK(args, filter.in.in_len, sizeof(args->filter.in));
    STATE_CHECK(args, filter.in.out_size, sizeof(args->filter.out));
    STATE_CHECK(args, filter.in.flags, CI_FILTER_FLAG_EXCLUSIVE_RXQ | qflag);
    STATE_CHECK(args, filter.in.fields, CI_FILTER_FIELD_LOC_HOST |
                                        CI_FILTER_FIELD_LOC_PORT | qfield);
    STATE_CHECK(args, filter.in.rxq_no, qid);
    STATE_CHECK(args, filter.in.spec.l2.type, htons(ETH_P_IP));
    STATE_CHECK(args, filter.in.spec.l3.protocol, 53);
    STATE_CHECK(args, filter.in.spec.l3.u.ipv4.daddr, 0x12345678);
    STATE_CHECK(args, filter.in.spec.l4.ports.dest, 0xabcd);
  }

  STATE_CHECK(s, post_filter_args.calls, 1);
  STATE_CHECK(s, post_filter_args.vi, &s->vi);
  STATE_CHECK(s, post_filter_args.spec, &s->spec);
  STATE_CHECK(s, post_filter_args.cookie.filter_id, s->cookie.filter_id);
  STATE_CHECK(s, post_filter_args.cookie.filter_type, s->cookie.filter_type);
  STATE_CHECK(s, post_filter_args.rxq, 6);
  STATE_CHECK(s, post_filter_args.shared, false);

  STATE_CHECK(s, cookie.filter_id, 67);
  STATE_CHECK(s, cookie.filter_type, EF_FILTER_IP4);

  free_add_filter_state(s);
}

void test_ef_vi_add_filter_fails(void)
{
  struct add_filter_state* s = alloc_add_filter_state(3);
  uint64_t active_qs = 5; /* two queues and a gap */
  int i;

  s->vi.efct_rxqs.active_qs = &active_qs;
  efct_get_rxq_state(&s->vi, 0)->qid = 4;
  efct_get_rxq_state(&s->vi, 2)->qid = 5;

  ef_filter_spec_init(&s->spec, EF_FILTER_FLAG_EXCLUSIVE_RXQ);
  ef_filter_spec_set_ip4_local(&s->spec, 53, 0x12345678, 0xabcd);

  /* Attempts to join both queues fail, so does request for a new one */
  s->ioctl_calls.args[0]->filter_id = -1;
  s->ioctl_calls.args[0]->rxq = -1;
  s->ioctl_calls.args[0]->err = EPERM;

  s->ioctl_calls.args[1]->filter_id = -1;
  s->ioctl_calls.args[1]->rxq = -1;
  s->ioctl_calls.args[1]->err = EPERM;

  s->ioctl_calls.args[2]->filter_id = -1;
  s->ioctl_calls.args[2]->rxq = -1;
  s->ioctl_calls.args[2]->err = EOPNOTSUPP;
  stash_add_filter_state(s);

  CHECK(ef_vi_filter_add(&s->vi, 42, &s->spec, &s->cookie), ==, -EOPNOTSUPP);

  STATE_CHECK(s, pre_filter_args.calls, 1);
  STATE_CHECK(s, pre_filter_args.vi, &s->vi);
  STATE_CHECK(s, pre_filter_args.shared, false);
  STATE_CHECK(s, pre_filter_args.interrupts, false);

  STATE_UPDATE(s, ioctl_calls.received, 3);

  for( i = 0; i < s->ioctl_calls.received; ++i ) {
    struct ioctl_args* args = s->ioctl_calls.args[i];
    unsigned qflag = i == 2 ? CI_FILTER_FLAG_ANY_RXQ : CI_FILTER_FLAG_PREF_RXQ;
    unsigned qfield = i == 2 ? 0 : CI_FILTER_FIELD_RXQ;
    int qid = i == 2 ? 0 : i + 4;

    STATE_CHECK(args, fd, 42);
    STATE_CHECK(args, request, CI_FILTER_ADD);
    STATE_CHECK(args, filter.in.in_len, sizeof(args->filter.in));
    STATE_CHECK(args, filter.in.out_size, sizeof(args->filter.out));
    STATE_CHECK(args, filter.in.flags, CI_FILTER_FLAG_EXCLUSIVE_RXQ | qflag);
    STATE_CHECK(args, filter.in.fields, CI_FILTER_FIELD_LOC_HOST |
                                        CI_FILTER_FIELD_LOC_PORT | qfield);
    STATE_CHECK(args, filter.in.rxq_no, qid);
    STATE_CHECK(args, filter.in.spec.l2.type, htons(ETH_P_IP));
    STATE_CHECK(args, filter.in.spec.l3.protocol, 53);
    STATE_CHECK(args, filter.in.spec.l3.u.ipv4.daddr, 0x12345678);
    STATE_CHECK(args, filter.in.spec.l4.ports.dest, 0xabcd);
  }

  STATE_CHECK(s, post_filter_args.calls, 0);

  free_add_filter_state(s);
}

int main(void)
{
  TEST_RUN(test_ef_vi_add_filter);
  TEST_RUN(test_ef_vi_add_filter_existing_queue);
  TEST_RUN(test_ef_vi_add_filter_second_existing_queue);
  TEST_RUN(test_ef_vi_add_filter_new_queue);
  TEST_RUN(test_ef_vi_add_filter_fails);
  TEST_END();
}

