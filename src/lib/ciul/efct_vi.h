/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#ifndef __CIUL_EFCT_VI_H__
#define __CIUL_EFCT_VI_H__

/* generic tx header */
uint64_t efct_tx_header(unsigned packet_length, unsigned ct_thresh,
                        unsigned timestamp_flag, unsigned warm_flag,
                        unsigned action);

/* Operations */

int efct_ef_vi_transmit(ef_vi* vi, ef_addr base, int len,
                        ef_request_id dma_id);

int efct_ef_vi_transmitv(ef_vi* vi, const ef_iovec* iov, int iov_len,
                         ef_request_id dma_id);


void efct_ef_vi_transmit_push(ef_vi* vi);

#endif  /* __CIUL_EFCT_VI_H__ */
