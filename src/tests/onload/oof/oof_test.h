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

/* SW-filter insert fault injection (mock oof_cb_sw_filter_insert).
 * While oof_sw_filter_insert_fail_count != 0, a matching insert returns
 * oof_sw_filter_insert_fail_rc instead of installing the filter, and the
 * count is decremented (if > 0).  oof_sw_filter_insert_fail_laddr, when
 * non-zero, restricts injection to inserts for that local address (BE).
 * An injected failure is NOT recorded as a bad add, so it models a
 * genuine insertion failure rather than an unexpected insert. */
extern int oof_sw_filter_insert_fail_count;
extern int oof_sw_filter_insert_fail_rc;
extern unsigned oof_sw_filter_insert_fail_laddr;

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
extern int test_hidden_socket(void);
extern int test_del_sw(void);
extern int test_addr_lifecycle(void);
extern int test_filter_redirect(void);
extern int test_mcast_input_validation(void);
extern int test_cluster_compat(void);
extern int test_threshold_sharing(void);
extern int test_mcast_hw_errors(void);
extern int test_mcast_del(void);
extern int test_mcast_del_sw(void);
extern int test_mcast_interface_update(void);
extern int test_hwport_lifecycle(void);
extern int test_addr_reactivate(void);

#endif /* __OOF_TEST_H__ */
