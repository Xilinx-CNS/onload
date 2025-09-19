/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#ifndef LIB_EFHW_EFCT_FILTERS_INTERNAL_H
#define LIB_EFHW_EFCT_FILTERS_INTERNAL_H

#include <ci/efhw/mc_driver_pcol.h>
#include "mcdi_common.h"

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
  uint8_t loc_mac[ETH_ALEN];
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
  struct hlist_head ipproto[64];
  size_t ipproto_n;
  struct hlist_head ipproto_vlan[64];
  size_t ipproto_vlan_n;
  struct hlist_head ethertype[64];
  size_t ethertype_n;
  struct hlist_head mac[64];
  size_t mac_n;
  struct hlist_head mac_vlan[64];
  size_t mac_vlan_n;
};

/* Totally arbitrary numbers: */
static const size_t MAX_ALLOWED_full_match = 32768;
static const size_t MAX_ALLOWED_semi_wild = 32768;
static const size_t MAX_ALLOWED_ipproto = 128;
static const size_t MAX_ALLOWED_ipproto_vlan = 128;
static const size_t MAX_ALLOWED_ethertype = 128;
static const size_t MAX_ALLOWED_mac = 128;
static const size_t MAX_ALLOWED_mac_vlan = 128;

static const uint32_t MCDI_MATCH_FLAGS_full_match =
                          EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE) |
                          EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO) |
                          EFHW_MCDI_MATCH_FIELD_BIT(DST_IP) |
                          EFHW_MCDI_MATCH_FIELD_BIT(DST_PORT) |
                          EFHW_MCDI_MATCH_FIELD_BIT(SRC_IP) |
                          EFHW_MCDI_MATCH_FIELD_BIT(SRC_PORT);
static const uint32_t MCDI_MATCH_FLAGS_semi_wild =
                          EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE) |
                          EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO) |
                          EFHW_MCDI_MATCH_FIELD_BIT(DST_IP) |
                          EFHW_MCDI_MATCH_FIELD_BIT(DST_PORT);
static const uint32_t MCDI_MATCH_FLAGS_ipproto =
                          EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE) |
                          EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO);
static const uint32_t MCDI_MATCH_FLAGS_ipproto_vlan =
                          EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE) |
                          EFHW_MCDI_MATCH_FIELD_BIT(IP_PROTO) |
                          EFHW_MCDI_MATCH_FIELD_BIT(OUTER_VLAN);
static const uint32_t MCDI_MATCH_FLAGS_ethertype =
                          EFHW_MCDI_MATCH_FIELD_BIT(ETHER_TYPE);
static const uint32_t MCDI_MATCH_FLAGS_mac =
                          EFHW_MCDI_MATCH_FIELD_BIT(DST_MAC);
static const uint32_t MCDI_MATCH_FLAGS_mac_vlan =
                          EFHW_MCDI_MATCH_FIELD_BIT(DST_MAC) |
                          EFHW_MCDI_MATCH_FIELD_BIT(OUTER_VLAN);

#define FOR_EACH_FILTER_CLASS(action) \
  action(full_match) \
  action(semi_wild) \
  action(ipproto) \
  action(ipproto_vlan) \
  action(ethertype) \
  action(mac) \
  action(mac_vlan)

struct efct_hw_filter {
  uint64_t drv_id;
  unsigned refcount;
  unsigned flags;
  uint32_t hw_id;
  uint8_t rxq;
  uint16_t ethertype;
  uint8_t ip_proto;
  uint16_t local_port;
  uint32_t local_ip;
  uint8_t loc_mac[ETH_ALEN];
  /* Although the VLAN field is 16 bits, we use an int32_t so we can use -1
   * mean unset. We use this for comparisons with the vlan field in
   * efct_filter_node, so keeping the types aligned avoids unpleasant
   * size/signedness shenanigans in those cases. */
  int32_t outer_vlan;
  uint16_t remote_port;
  uint32_t remote_ip;
};

#define EFCT_NIC_BLOCK_KERNEL_UNICAST 0x1
#define EFCT_NIC_BLOCK_KERNEL_MULTICAST 0x2

#ifdef __KERNEL__
struct efct_filter_state {
  /* This array is used for marking whether a given hw_qid is exclusively owned.
   * The index represents the hardware_queue, and the value should correspond to
   * a token representing exclusive ownership of the rxq. In this case, a token_id
   * of 0 indicates the rxq is not being used. Otherwise the queue is owned and
   * in-use.  */
  uint32_t* exclusive_rxq_mapping;
  int rxq_n;

  /* We could have one filter set per rxq, effectively adding a few more bits
   * to the hash key. Let's not for now: the memory trade-off doesn't seem
   * worth it */
  struct efct_filter_set filters;
  uint32_t hw_filters_n;
  struct efct_hw_filter *hw_filters;
  struct mutex driver_filters_mtx;
  uint8_t block_kernel;
};
#endif


#endif /* LIB_EFHW_EFCT_FILTERS_INTERNAL_H */
