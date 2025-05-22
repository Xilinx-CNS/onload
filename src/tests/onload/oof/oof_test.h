/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017 Xilinx, Inc. */

#ifndef __OOF_TEST_H__
#define __OOF_TEST_H__


struct ooft_cplane;
struct efab_tcp_driver_s;
struct ootf_task;
struct net;
struct cpumask {};

extern struct ooft_cplane* cp;
extern struct efab_tcp_driver_s efab_tcp_driver;
extern struct ooft_task* current;

#define TEST_DEBUG(x)
#define LOG_FILTER_OP(x) x

extern void dump(void* opaque, const char* fmt, ...);
extern void test_alloc(int max_addrs);
extern void test_cleanup(void);

extern struct net* current_ns(void);
extern struct ooft_task* context_alloc(struct net* ns);
extern void context_free(struct ooft_task* task);

extern int oo_debug_bits;
extern int scalable_filter_gid;

enum ooft_rx_mode {
  OOFT_RX_FF,
  OOFT_RX_LL,
  OOFT_RX_BOTH,
  OOFT_RX_NONE,
};

/* There's a separate nic and hwport enum to allow tests to request a nic,
 * then just get the appropriate set of hwports. */
enum ooft_nic_type {
  OOFT_NIC_X2_FF, /* X2 with FF FW */
  OOFT_NIC_X2_LL, /* X2 with ULL FW */
  OOFT_NIC_X4_FF, /* X4 with FF FW */
  OOFT_NIC_X4_LL, /* X4 with ULL FW */
  OOFT_NIC_AFXDP, /* Generic NIC using kernel AF_XDP */
};

extern int __test_sanity(enum ooft_nic_type type, enum ooft_rx_mode mode);
extern int test_sanity(void);
extern int test_sanity_no5tuple(void);
extern int test_multicast_sanity(void);
extern int test_replication_sanity(void);
extern int test_multipath_replication(void);
extern int test_multicast_local_addr(void);
extern int test_namespace_sanity(void);
extern int test_namespace_macvlan_move(void);
extern int test_llct_sanity(void);
extern int test_llct_sanity_ff(void);
extern int test_llct_sanity_ll(void);

#endif /* __OOF_TEST_H__ */
