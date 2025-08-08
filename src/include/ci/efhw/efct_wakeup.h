/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#ifndef LIB_EFHW_EFCT_WAKEUP_H
#define LIB_EFHW_EFCT_WAKEUP_H

int efct_request_wakeup(struct efhw_nic *nic,
                        struct efhw_nic_efct_rxq_wakeup_bits *bits,
                        struct efhw_efct_rxq *app,
                        unsigned sbseq, unsigned pktix, bool allow_recursion);

int efct_handle_wakeup(struct efhw_nic *nic,
                       struct efhw_nic_efct_rxq_wakeup_bits *bits,
                       unsigned sbseq, unsigned pktix, int budget);

#endif /* LIB_EFHW_EFCT_WAKEUP_H */
