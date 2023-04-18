/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#ifndef CI_EFHW_EFCT_H
#define CI_EFHW_EFCT_H
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/driver/ci_efct.h>
#include <ci/tools/sysdep.h>

extern struct efhw_func_ops efct_char_functional_units;

struct efhw_efct_rxq;
struct efct_client_hugepage;
struct efct_client_rxq_params;
struct oo_hugetlb_allocator;
typedef void efhw_efct_rxq_free_func_t(struct efhw_efct_rxq*);
typedef void efhw_efct_rxq_int_wake_func_t(struct efhw_efct_rxq*);

/* Packet sequences are defined as (superbuf_seqno << 16) | pkt_index_in_sb,
 * therefore -1 is an impossible value because we'll never have 65535 packets
 * in a single superbuf */
#define EFCT_INVALID_PKT_SEQNO (~0u)

struct efhw_efct_rxq {
  struct efhw_efct_rxq *next;
  struct efab_efct_rxq_uk_shm_q *shm;
  unsigned qid;
  bool destroy;
  uint32_t next_sbuf_seq;
  size_t n_hugepages;
  uint32_t wake_at_seqno;
  uint32_t current_owned_superbufs;
  uint32_t max_allowed_superbufs;
  CI_BITS_DECLARE(owns_superbuf, CI_EFCT_MAX_SUPERBUFS);
  efhw_efct_rxq_free_func_t *freer;
  unsigned wakeup_instance;
};

/* TODO EFCT find somewhere better to put this */
#define CI_EFCT_EVQ_DUMMY_MAX 1024

struct efhw_nic_efct_rxq {
  struct efhw_efct_rxq *new_apps;  /* Owned by process context */
  struct efhw_efct_rxq *live_apps; /* Owned by NAPI context */
  struct efhw_efct_rxq *destroy_apps; /* Owned by NAPI context */
  uint32_t superbuf_refcount[CI_EFCT_MAX_SUPERBUFS];
  /* Tracks buffers passed to us from the driver in order they are going
   * to be filled by HW. We need to do this to:
   *  * progressively refill client app superbuf queues,
   *    as x3net can refill RX ring with more superbufs than an app can hold
   *    (or if queues are equal there is a race)
   *  * resume a stopped app (subset of the above really),
   *  * start new app (without rollover)
   */
  struct {
    struct efab_efct_rxq_uk_shm_rxq_entry q[16];
    uint32_t added;
    uint32_t removed;
  } sbufs;
  struct work_struct destruct_wq;
  uint32_t now;
  uint32_t awaiters;
  uint64_t time_sync;
};

#define EFCT_EVQ_NO_TXQ -1
struct efhw_nic_efct_evq {
  struct efhw_nic *nic;
  atomic_t queues_flushing;
  struct delayed_work check_flushes;
  void *base;
  unsigned capacity;
  int txq;
};

#define EFCT_ETHERTYPE_IG_FILTER 0xFFFF

#define EFCT_PROTO_UCAST_IG_FILTER 0x1
#define EFCT_PROTO_MCAST_IG_FILTER 0x2

/* Key type for all the efct_filter_set members. Careful of ordering of
 * members here: this struct is rigged so that prefix subsets are useful. When
 * adding new match types, the only things which it should be necessary to
 * update are the definitions from here to FOR_EACH_FILTER_CLASS, and the
 * implementations of efct_filter_insert() and efct_filter_match(). */
struct efct_filter_node {
  struct hlist_node node;
  struct rcu_head free_list;
  int filter_id;
  int hw_filter;  /* index into hw_filters, or -1 */
  unsigned refcount;
  /* All fields from here on are big-endian */
  union {
    u32 key_start;   /* marker for 'this is the beginning of the key' */
    int32_t vlan;   /* -1 for any (i.e. don't care if it has a VLAN tag) */
  };
  uint16_t ethertype;
  uint8_t proto;
  uint16_t rport;
  uint16_t lport;
  union {
    struct {
      uint32_t lip;
      uint32_t rip;
    } ip4;
    struct {
      uint32_t lip[4];
      uint32_t rip[4];
    } ip6;
  } u;
};

/* Defines the software filters supported for the net driver. There's no need
 * for the software filters to be in any way related to hardware filtering,
 * we merely need some kind of rule engine to define what packets the net
 * driver should ignore (presumably because some ef_vi app is going to
 * consume them). We choose here to implement essentially the same filtering
 * as EF10's low-latency firmware. This gets us out-of-the-box support for
 * Onload and TCPDirect, and there's plenty of room for being smarter later.
 *
 * We nominally expect ef_vi applications to implement the same filtering as
 * that here (so that userspace and kernelspace reach identical conclusions
 * about who should be handling each packet) however there are significant
 * advantages to keeping divergent implementations. The most obvious is
 * performance: an ef_vi app probably knows precisely what packet flavours it
 * wants, so can use a highly specialised parser. As long as the parser here
 * is a superset, i.e. is capable of describing the same packets as the
 * user's algorithm, then coherence will be achieved.
 *
 * It is intended to be somewhat-easy to add new types of matching to this
 * file by updating FOR_EACH_FILTER_CLASS() (and fixing all the compiler
 * errors that result), adding efx_filter_spec-to-efct_filter_node conversion
 * to efct_filter_insert(), and adding real-packet-to-efct_filter_node
 * conversion to efct_filter_match(). */
struct efct_filter_set {
  struct hlist_head full_match[16384];
  size_t full_match_n;
  struct hlist_head semi_wild[16384];
  size_t semi_wild_n;
  struct hlist_head ethertype[64];
  size_t ethertype_n;
};

/* Totally arbitrary numbers: */
static const size_t MAX_ALLOWED_full_match = 32768;
static const size_t MAX_ALLOWED_semi_wild = 32768;
static const size_t MAX_ALLOWED_ethertype = 128;

#define FOR_EACH_FILTER_CLASS(action) \
  action(full_match) \
  action(semi_wild) \
  action(ethertype)

struct efct_hw_filter {
  int drv_id;
  unsigned refcount;
  uint8_t rxq;
  uint8_t proto;
  uint16_t port;
  uint32_t ip;
};

#define EFCT_NIC_BLOCK_KERNEL_UNICAST 0x1
#define EFCT_NIC_BLOCK_KERNEL_MULTICAST 0x2

struct efhw_nic_efct {
  uint32_t rxq_n;
  uint32_t evq_n;
  struct efhw_nic_efct_rxq *rxq;
  struct efhw_nic_efct_evq *evq;
  struct efct_client_device *edev;
  struct efct_client *client;
  struct efhw_nic *nic;
#ifdef __KERNEL__
  /* ZF emu includes this file from UL */
  /* We could have one filter set per rxq, effectively adding a few more bits
   * to the hash key. Let's not for now: the memory trade-off doesn't seem
   * worth it */
  struct efct_filter_set filters;
  uint32_t hw_filters_n;
  struct efct_hw_filter *hw_filters;
  struct mutex driver_filters_mtx;
  uint8_t block_kernel;
#endif
};

#if CI_HAVE_EFCT_AUX
int efct_nic_rxq_bind(struct efhw_nic *nic, int qid, bool timestamp_req,
                      size_t n_hugepages,
                      struct oo_hugetlb_allocator *hugetlb_alloc,
                      struct efab_efct_rxq_uk_shm_q *shm,
                      unsigned wakeup_instance, struct efhw_efct_rxq *rxq);
void efct_nic_rxq_free(struct efhw_nic *nic, struct efhw_efct_rxq *rxq,
                       efhw_efct_rxq_free_func_t *freer);
int efct_get_hugepages(struct efhw_nic *nic, int hwqid,
                       struct efct_client_hugepage *pages, size_t n_pages);
int efct_request_wakeup(struct efhw_nic_efct *efct, struct efhw_efct_rxq *app,
                        unsigned sbseq, unsigned pktix, bool allow_recursion);
void efct_nic_filter_init(struct efhw_nic_efct *efct);
bool efct_packet_handled(void *driver_data, int rxq, bool flow_lookup,
                         const void* meta, const void* payload);
#endif

static inline void efct_app_list_push(struct efhw_efct_rxq **head,
                                      struct efhw_efct_rxq *app)
{
  struct efhw_efct_rxq *next;
  do {
    app->next = next = *head;
  } while( ci_cas_uintptr_fail(head, (uintptr_t) next, (uintptr_t)app) );
}

#endif /* CI_EFHW_EFCT_H */
