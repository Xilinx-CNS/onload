/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017 Xilinx, Inc. */

#ifndef __OOF_TEST_H__
#define __OOF_TEST_H__


struct ooft_cplane;
struct efab_tcp_driver_s;
struct ootf_task;
struct net;
struct cpumask;

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

extern int test_sanity(void);
extern int test_multicast_sanity(void);
extern int test_namespace_sanity(void);
extern int test_namespace_macvlan_move(void);

#endif /* __OOF_TEST_H__ */
