/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <etherfabric/ef_vi.h>
#include <etherfabric/efct_vi.h>

#include <etherfabric/vi.h>
#include <ci/efhw/common.h>

#include <ci/tools/debug.h>

#include <ci/efch/op_types.h>


CI_BUILD_ASSERT(sizeof(struct efch_timeval) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_timeval, tv_sec) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_timeval, tv_usec) == 4);

CI_BUILD_ASSERT(sizeof(struct efch_vi_alloc_in) == 44);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, ifindex) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, pd_or_vi_set_fd) == 4);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, pd_or_vi_set_rs_id) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, vi_set_instance) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, evq_fd) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, evq_rs_id) == 20);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, evq_capacity) == 24);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, txq_capacity) == 28);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, rxq_capacity) == 32);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, flags) == 36);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, tx_q_tag) == 40);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, rx_q_tag) == 41);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_in, ps_buf_size_kb) == 42);

CI_BUILD_ASSERT(sizeof(struct efch_vi_alloc_out) == 44);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, evq_capacity) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, txq_capacity) == 4);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, rxq_capacity) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, nic_arch) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, nic_variant) == 13);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, nic_revision) == 14);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, nic_flags) == 15);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, mem_mmap_bytes) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, io_mmap_bytes) == 20);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, instance) == 24);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, rx_prefix_len) == 28);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, out_flags) == 32);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, ps_buf_size) == 36);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_alloc_out, abs_idx) == 40);

CI_BUILD_ASSERT(sizeof(struct efch_vi_set_alloc) == 20);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_set_alloc, in_ifindex) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_set_alloc, in_n_vis) == 4);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_set_alloc, in_flags) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_set_alloc, in_pd_fd) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_vi_set_alloc, in_pd_rs_id) == 16);

CI_BUILD_ASSERT(sizeof(struct efch_memreg_alloc) == 48);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_memreg_alloc, in_vi_or_pd_fd) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_memreg_alloc, in_vi_or_pd_id) == 4);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_memreg_alloc, in_mem_ptr) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_memreg_alloc, in_mem_bytes) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_memreg_alloc, in_addrs_out_ptr) == 24);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_memreg_alloc, in_addrs_out_stride) == 32);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_memreg_alloc, in_flags) == 40);

CI_BUILD_ASSERT(sizeof(struct efch_pio_alloc) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_pio_alloc, in_pd_fd) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_pio_alloc, in_pd_id) == 4);

CI_BUILD_ASSERT(sizeof(struct efch_pd_alloc) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_pd_alloc, in_ifindex) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_pd_alloc, in_flags) == 4);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_pd_alloc, in_vlan_id) == 8);

CI_BUILD_ASSERT(sizeof(struct efch_efct_rxq_alloc) == 24);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_efct_rxq_alloc, in_vi_rs_id) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_efct_rxq_alloc, in_flags) == 4);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_efct_rxq_alloc, in_abi_version) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_efct_rxq_alloc, in_qid) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_efct_rxq_alloc, in_shm_ix) == 13);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_efct_rxq_alloc, in_timestamp_req) == 14);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_efct_rxq_alloc, in_n_hugepages) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_efct_rxq_alloc, in_memfd) == 20);

CI_BUILD_ASSERT(sizeof(struct ci_resource_alloc_s) == 88);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_alloc_s, intf_ver) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_alloc_s, ra_type) == 32);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_alloc_s, out_id) == 36);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_alloc_s, u.vi_in) == 40);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_alloc_s, u.vi_out) == 40);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_alloc_s, u.vi_set) == 40);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_alloc_s, u.memreg) == 40);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_alloc_s, u.pd) == 40);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_alloc_s, u.pio) == 40);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_alloc_s, u.rxq) == 40);

CI_BUILD_ASSERT(sizeof(struct ci_resource_op_s) == 40);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, id) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, op) == 4);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.evq_wait.current_ptr) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.evq_wait.timeout) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.evq_wait.nic_index) == 20);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.evq_put.ev) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_get_mtu.out_mtu) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_get_mac.out_mac) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.pt.pace) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.pio_link_vi.in_vi_fd) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.pio_link_vi.in_vi_id) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.pio_unlink_vi.in_vi_fd) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.pio_unlink_vi.in_vi_id) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.ip4.protocol) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.ip4.port_be16) == 10);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.ip4.rport_be16) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.ip4.host_be32) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.ip4.rhost_be32) == 20);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.mac.vlan_id) == 24);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.mac.mac) == 26);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.u.in.flags) == 32);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.u.in.ether_type_be16) == 36);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.u.out.rxq) == 32);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_add.u.out.filter_id) == 36);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_del.filter_id) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_query.filter_id) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_query.out_rxq) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_query.out_hw_id) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.filter_query.out_flags) == 20);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_rx_ts_correction.out_rx_ts_correction) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_ts_correction.out_rx_ts_correction) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_ts_correction.out_tx_ts_correction) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.pt_sniff.enable) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.pt_sniff.promiscuous) == 9);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.tx_pt_sniff.enable) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.block_kernel.block) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_stats.data_ptr) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_stats.data_len) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_stats.do_reset) == 20);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_tx_alt_alloc_in.num_alts) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_tx_alt_alloc_in.buf_space_32b) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_tx_alt_alloc_out.alt_ids) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.vi_ts_format.out_ts_format) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.rxq_refresh.superbufs) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.rxq_refresh.current_mappings) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.rxq_refresh.max_superbufs) == 24);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.pd_excl_rxq_tok_get.token) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_op_s, u.shared_rxq_tok_set.token) == 8);

CI_BUILD_ASSERT(sizeof(union ci_filter_add_u) == 120);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.in_len) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.out_size) == 2);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.res_id) == 4);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.fields) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.opt_fields) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.flags) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l2.dhost) == 20);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l2.shost) == 26);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l2.type) == 32);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l2.vid) == 34);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l2.reserved) == 36);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l3.protocol) == 40);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l3.reserved) == 41);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l3.u.ipv4.saddr) == 44);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l3.u.ipv4.daddr) == 48);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l3.u.ipv4.reserved) == 52);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l3.u.ipv6.saddr) == 44);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l3.u.ipv6.daddr) == 60);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l3.u.ipv6.reserved) == 76);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l4.ports.source) == 84);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l4.ports.dest) == 86);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.spec.l4.pad.pad) == 84);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, in.rxq_no) == 116);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, out.out_len) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, out.rxq) == 2);
CI_BUILD_ASSERT(__builtin_offsetof(union ci_filter_add_u, out.filter_id) == 8);

CI_BUILD_ASSERT(sizeof(struct efch_capabilities_in) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_capabilities_in, cap) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_capabilities_in, ifindex) == 4);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_capabilities_in, pd_fd) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_capabilities_in, pd_id) == 12);

CI_BUILD_ASSERT(sizeof(struct efch_capabilities_out) == 16);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_capabilities_out, support_rc) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct efch_capabilities_out, val) == 8);

CI_BUILD_ASSERT(sizeof(struct ci_resource_prime_op_s) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_prime_op_s, crp_id) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_prime_op_s, crp_current_ptr) == 4);

CI_BUILD_ASSERT(sizeof(struct ci_resource_prime_qs_op_s) == 112);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_prime_qs_op_s, crp_id) == 0);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_prime_qs_op_s, n_rxqs) == 4);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_prime_qs_op_s, n_txqs) == 8);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_prime_qs_op_s, rxq_current) == 12);
CI_BUILD_ASSERT(__builtin_offsetof(struct ci_resource_prime_qs_op_s, txq_current) == 108);

CI_BUILD_ASSERT(sizeof(struct ci_capabilities_op_s) == 16);
