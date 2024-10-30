/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */

#define _GNU_SOURCE

/* Functions under test */
#include <etherfabric/ef_vi.h>

#include <etherfabric/memreg.h>
#include <ci/efhw/common.h>
#include <etherfabric/internal/efct_uk_api.h>
#include "ef_vi_internal.h"

/* Test infrastructure */
#include "unit_test.h"

/* Dependencies */
int efct_vi_find_free_rxq(ef_vi* vi, int qid) { return qid; }
void efct_vi_start_rxq(ef_vi* vi, int ix, int qid) {}

#include <dlfcn.h>
#include <sys/mman.h>
void* mmap(void* p, size_t l, int pr, int fl, int fd, off_t off)
{
  void* (*real_mmap)(void*, size_t, int, int, int, int) =
    dlsym(RTLD_NEXT, "mmap");
  fl &= ~MAP_HUGETLB;
  return real_mmap(p, l, pr, fl, fd, off);
}

/* Used for ci_resource_alloc */
int ioctl (int __fd, unsigned long int __request, ...)
{
  return 0;
}

static const size_t sbufs_per_rxq = CI_EFCT_MAX_SUPERBUFS;
static const size_t sbuf_bytes_per_rxq = sbufs_per_rxq * EFCT_RX_SUPERBUF_BYTES;

int efct_superbufs_reserve(ef_vi* vi, void* space)
{
  int i;

  CHECK(space, ==, NULL);
  vi->efct_rxqs.max_qs = EF_VI_MAX_EFCT_RXQS;
  space = mmap(NULL, sbuf_bytes_per_rxq * vi->efct_rxqs.max_qs, PROT_NONE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  madvise(space, sbuf_bytes_per_rxq * vi->efct_rxqs.max_qs, MADV_DONTDUMP);
  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i )
    vi->efct_rxqs.q[i].superbuf = (const char*)space + i * sbuf_bytes_per_rxq;
  return 0;
}

void efct_superbufs_cleanup(ef_vi* vi)
{
  munmap((void*)vi->efct_rxqs.q[0].superbuf,
         sbuf_bytes_per_rxq * vi->efct_rxqs.max_qs);
}

int ef_memreg_alloc_flags(ef_memreg* mr, ef_driver_handle mr_dh,
                          struct ef_pd* pd, ef_driver_handle pd_dh,
                          void* p_mem, size_t len_bytes, unsigned flags)
{
  return 0;
}

int ef_memreg_alloc(ef_memreg* mr, ef_driver_handle mr_dh,
                    struct ef_pd* pd, ef_driver_handle pd_dh,
                    void* p_mem, size_t len_bytes)
{
  return ef_memreg_alloc_flags(mr, mr_dh, pd, pd_dh, p_mem, len_bytes,
                               ef_pd_mr_flags(pd));
}

int ef_memreg_free(ef_memreg* mr, ef_driver_handle mr_dh)
{
  return 0;
}

#define SUPERBUF_COUNT 16
static int sb_free_next[EF_VI_MAX_EFCT_RXQS][SUPERBUF_COUNT];

void efct_rx_sb_free_push(ef_vi* vi, uint32_t qid, uint32_t sbid)
{
  int16_t* head;

  assert(qid < EF_VI_MAX_EFCT_RXQS);
  assert(sbid < SUPERBUF_COUNT);

  head = &vi->ep_state->rxq.sb_desc_free_head[qid];
  sb_free_next[qid][sbid] = *head;
  *head = sbid;
}

int16_t efct_rx_sb_free_next(ef_vi* vi, uint32_t qid, uint32_t sbid)
{
  assert(qid < EF_VI_MAX_EFCT_RXQS);
  assert(sbid < SUPERBUF_COUNT);
  return sb_free_next[qid][sbid];
}

static const void* get_superbuf(ef_vi* vi, int qid, int sbid)
{
  return vi->efct_rxqs.q[qid].superbuf + sbid * EFCT_RX_SUPERBUF_BYTES;
}

static bool get_sentinel(ef_vi* vi, int qid, int sbid)
{
  const ci_qword_t* header = get_superbuf(vi, qid, sbid);
  return CI_QWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL);
}

static void set_sentinel(ef_vi* vi, int qid, int sbid, bool sentinel)
{
  ci_qword_t* header = (void*)get_superbuf(vi, qid, sbid);
  CI_SET_QWORD_FIELD(*header, EFCT_RX_HEADER_SENTINEL, sentinel);
}

static int posted_buffers[SUPERBUF_COUNT];
static unsigned posted_added, posted_removed;

static void mock_post(ef_vi* vi, int qid, int sbid, bool sentinel)
{
  CHECK(qid, ==, 0); // Only testing one queue for now
  CHECK(posted_added - posted_removed, <=, SUPERBUF_COUNT);
  CHECK(sentinel, !=, get_sentinel(vi, qid, sbid));
  posted_buffers[posted_added++ % SUPERBUF_COUNT] = sbid;
}

static int get_posted(void)
{
  CHECK(posted_added - posted_removed, >, 0);
  return posted_buffers[posted_removed++ % SUPERBUF_COUNT];
}

static void check_poison(char *sbuf) {
  char *pkt = sbuf + EFCT_RX_HEADER_NEXT_FRAME_LOC_1 - 2;
  int i;

  CHECK((uintptr_t)pkt % sizeof(uint64_t), ==, 0);
  for(i = 0; i < EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE; i++) {
    CHECK(*(uint64_t *)pkt, ==, CI_EFCT_DEFAULT_POISON);
    pkt += EFCT_PKT_STRIDE;
  }
}

static ef_vi* alloc_vi(void)
{
  int i;

  STATE_ALLOC(ef_vi, vi);
  STATE_ALLOC(ef_vi_state, state);
  vi->ep_state = state;
  for( i = 0; i < EF_VI_MAX_EFCT_RXQS; ++i )
    state->rxq.sb_desc_free_head[i] = -1;
  CHECK(efct_ubufs_init(vi, NULL, 0), ==, 0);
  STATE_STASH(vi);
  STATE_STASH(state);

  vi->efct_rxqs.ops->post = mock_post;
  return vi;
}

static void free_vi(ef_vi* vi)
{
  vi->efct_rxqs.ops->cleanup(vi);
  STATE_FREE(vi->ep_state);
  STATE_FREE(vi);
}

/* Test cases */
static void test_efct_ubufs(void)
{
  int i, rep;
  int bufs[SUPERBUF_COUNT];
  bool sentinel;
  unsigned sbseq, expect_seq=0;

  ef_vi* vi = alloc_vi();
  ef_vi_efct_rxq_ops* ops = vi->efct_rxqs.ops;

  CHECK(ops->attach(vi, 0, -1, SUPERBUF_COUNT, false), ==, 0);

  for( rep = 0; rep < 3; ++rep ) {
    for( i = 0; i < SUPERBUF_COUNT; ++i ) {
      CHECK(ops->available(vi, 0), ==, true);
      bufs[i] = ops->next(vi, 0, &sentinel, &sbseq);
      CHECK(bufs[i], >=, 0);
      CHECK(bufs[i], ==, get_posted());
      CHECK(sbseq, ==, expect_seq++);
    }

    CHECK(ops->available(vi, 0), ==, false);
    CHECK(ops->next(vi, 0, &sentinel, &sbseq), ==, -EAGAIN);

    ops->free(vi, 0, bufs[0]);
    CHECK(ops->available(vi, 0), ==, true);
    bufs[0] = ops->next(vi, 0, &sentinel, &sbseq);
    CHECK(bufs[0], >=, 0);
    CHECK(bufs[0], ==, get_posted());
    CHECK(sbseq, ==, expect_seq++);

    CHECK(ops->available(vi, 0), ==, false);
    CHECK(ops->next(vi, 0, &sentinel, &sbseq), ==, -EAGAIN);

    for( i = 0; i < SUPERBUF_COUNT; ++i ) {
      ops->free(vi, 0, bufs[i]);
    }
  }

  free_vi(vi);
}

static void test_sentinel(void)
{
  bool sentinel;
  unsigned sbseq;
  int buf;

  ef_vi* vi = alloc_vi();
  ef_vi_efct_rxq_ops* ops = vi->efct_rxqs.ops;

  CHECK(ops->attach(vi, 0, -1, 1, false), ==, 0);

  buf = ops->next(vi, 0, &sentinel, &sbseq);
  CHECK(buf, >=, 0);
  CHECK(get_posted(), ==, buf);
  CHECK(get_sentinel(vi, 0, buf), ==, false);
  CHECK(sentinel, ==, true);

  ops->free(vi, 0, buf);
  CHECK(ops->next(vi, 0, &sentinel, &sbseq), ==, buf);
  CHECK(get_posted(), ==, buf);
  CHECK(get_sentinel(vi, 0, buf), ==, false);
  CHECK(sentinel, ==, true);

  set_sentinel(vi, 0, buf, true);
  ops->free(vi, 0, buf);
  CHECK(ops->next(vi, 0, &sentinel, &sbseq), ==, buf);
  CHECK(get_posted(), ==, buf);
  CHECK(get_sentinel(vi, 0, buf), ==, true);
  CHECK(sentinel, ==, false);

  set_sentinel(vi, 0, buf, false);
  ops->free(vi, 0, buf);
  CHECK(ops->next(vi, 0, &sentinel, &sbseq), ==, buf);
  CHECK(get_posted(), ==, buf);
  CHECK(get_sentinel(vi, 0, buf), ==, false);
  CHECK(sentinel, ==, true);

  free_vi(vi);
}

static void test_poison(void)
{
  bool sentinel;
  unsigned sbseq;
  int buf;

  ef_vi* vi = alloc_vi();
  ef_vi_efct_rxq_ops* ops = vi->efct_rxqs.ops;

  ops = vi->efct_rxqs.ops;
  CHECK(ops->attach(vi, 0, -1, 1, false), ==, 0);

  buf = ops->next(vi, 0, &sentinel, &sbseq);
  CHECK(buf, >=, 0);
  CHECK(get_posted(), ==, buf);
  check_poison((void *)get_superbuf(vi, 0, buf));
  ops->free(vi, 0, buf);

  free_vi(vi);
}

int main(void)
{
  TEST_RUN(test_efct_ubufs);
  TEST_RUN(test_sentinel);
  TEST_RUN(test_poison);
  TEST_END();
}
