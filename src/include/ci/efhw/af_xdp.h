/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef CI_EFHW_AF_XDP_H
#define CI_EFHW_AF_XDP_H

extern struct efhw_func_ops af_xdp_char_functional_units;

struct socket;
struct efhw_nic;
struct efhw_page_map;

extern int efhw_nic_bodge_af_xdp_socket(struct efhw_nic* nic, int stack_id,
                                        long buffers, int size, int headroom,
                                        struct socket** sock_out,
                                        void** mem_base_out);
extern int efhw_nic_bodge_af_xdp_ready(struct efhw_nic* nic, int stack_id,
                                       struct efhw_page_map* pages_out);
extern void efhw_nic_bodge_af_xdp_dtor(struct efhw_nic* nic);

#endif /* CI_EFHW_AF_XDP_H */
