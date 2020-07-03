/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef CI_EFHW_AF_XDP_H
#define CI_EFHW_AF_XDP_H

extern struct efhw_func_ops af_xdp_char_functional_units;

struct socket;
struct efhw_nic;
struct efhw_page_map;

extern void* efhw_nic_bodge_af_xdp_mem(struct efhw_nic* nic, int stack_id);
extern int efhw_nic_bodge_af_xdp_ready(struct efhw_nic* nic, int stack_id,
                                       int chunk_size, int headroom,
                                       struct socket** sock_out,
                                       struct efhw_page_map* pages_out);
extern void efhw_nic_bodge_af_xdp_dtor(struct efhw_nic* nic);

#endif /* CI_EFHW_AF_XDP_H */
