/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */
#include "ef_vi_internal.h"

#include "efct_vi.h"

/* For various EFCT macro definitions */
#include <etherfabric/internal/efct_uk_api.h>

#ifndef __KERNEL__
/* Needed for `offsetof` in expansion of macro EFAB_NIC_DP_GET */
#include <stddef.h>
#endif

/* Stolen from ef100 */
ef_vi_inline void
ef10ct_unsupported_msg(const char *func_name)
{
  ef_log("ERROR: %s is not supported", func_name);
#ifndef __KERNEL__
  abort();
#endif
}

int ef10ct_transmit_pio(struct ef_vi * vi, int offset, int len,
                        ef_request_id id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_transmit_copy_pio(struct ef_vi *vi, int pio_offset,
                             const void *src_buff, int len, ef_request_id id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

void ef10ct_transmit_pio_warm(struct ef_vi *vi) {
    ef10ct_unsupported_msg(__func__);
}

void ef10ct_transmit_copy_pio_warm(struct ef_vi *vi, int pio_offset,
                                   const void *src_buf, int len) {
    ef10ct_unsupported_msg(__func__);
}

void ef10ct_transmitv_ctpio(struct ef_vi *vi, size_t frame_len,
                            const struct iovec *iov, int iov_len,
                            unsigned threshold) {
    ef10ct_unsupported_msg(__func__);
}

void ef10ct_transmitv_ctpio_copy(struct ef_vi *vi, size_t frame_len,
                                 const struct iovec *iov, int iov_len,
                                 unsigned threshold, void *fallback) {
    ef10ct_unsupported_msg(__func__);
}

int ef10ct_transmit_alt_select(struct ef_vi *vi, unsigned alt_id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_transmit_alt_select_default(struct ef_vi *vi) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_transmit_alt_stop(struct ef_vi *vi, unsigned alt_id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_transmit_alt_go(struct ef_vi *vi, unsigned alt_id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_receive_set_discards(struct ef_vi *vi, unsigned discard_err_flags) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

uint64_t ef10ct_receive_get_discards(struct ef_vi *vi) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_transmit_alt_discard(struct ef_vi *vi, unsigned alt_id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_receive_init(struct ef_vi *vi, ef_addr addr, ef_request_id id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

void ef10ct_receive_push(struct ef_vi *vi) {
    ef10ct_unsupported_msg(__func__);
}

int ef10ct_eventq_poll(struct ef_vi *vi, ef_event *evs, int evs_len) {
    int n = 0;
    /* TODO EF10CT poll receive queue(s) */
    if( vi->vi_txq.mask )
        n += efct_poll_tx(vi, evs + n, evs_len - n);
    return n;
}

void ef10ct_eventq_prime(struct ef_vi *vi) {
    ef10ct_unsupported_msg(__func__);
}

void ef10ct_eventq_timer_prime(struct ef_vi *vi, unsigned v) {
    ef10ct_unsupported_msg(__func__);
}

void ef10ct_eventq_timer_run(struct ef_vi *vi, unsigned v) {
    ef10ct_unsupported_msg(__func__);
}

void ef10ct_eventq_timer_clear(struct ef_vi *vi) {
    ef10ct_unsupported_msg(__func__);
}

void ef10ct_eventq_timer_zero(struct ef_vi *vi) {
    ef10ct_unsupported_msg(__func__);
}

int ef10ct_transmitv_init_extra(struct ef_vi *vi,
                                const struct ef_vi_tx_extra *extra,
                                const ef_remote_iovec *iov, int iov_len,
                                ef_request_id id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

ssize_t ef10ct_transmit_memcpy(struct ef_vi *vi,
                               const ef_remote_iovec *dst_iov, int dst_iov_len,
                               const ef_remote_iovec* src_iov, int src_iov_len
                               ) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_transmit_memcpy_sync(struct ef_vi *vi, ef_request_id dma_id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_transmit_ctpio_fallback(struct ef_vi *vi, ef_addr dma_addr,
                                   size_t len, ef_request_id dma_id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_transmitv_ctpio_fallback(struct ef_vi *vi,
                                    const ef_iovec *dma_iov, int dma_iov_len,
                                    ef_request_id dma_id) {
    ef10ct_unsupported_msg(__func__);
    return -EOPNOTSUPP;
}

int ef10ct_design_parameters(struct ef_vi *vi,
                             struct efab_nic_design_parameters *dp) {
#define GET(PARAM) EFAB_NIC_DP_GET(*dp, PARAM)

    /* When writing to the aperture we use a bitmask to keep within range. This
     * requires the size a power of two, and we shift by 3 because we write
     * a uint64_t (8 bytes) at a time.
     */
    if( ! EF_VI_IS_POW2(GET(tx_aperture_bytes)) ) {
    LOG(ef_log("%s: unsupported tx_aperture_bytes, %ld not a power of 2",
                __FUNCTION__, (long)GET(tx_aperture_bytes)));
    return -EOPNOTSUPP;
    }
    vi->vi_txq.efct_aperture_mask = (GET(tx_aperture_bytes) - 1) >> 3;

    /* FIFO size, reduced by 8 bytes for the TX header. Hardware reduces this
     * by one cache line to make their overflow tracking easier */
    vi->vi_txq.ct_fifo_bytes = GET(tx_fifo_bytes) -
                             EFCT_TX_ALIGNMENT - EFCT_TX_HEADER_BYTES;

    return 0;
}

static void ef10ct_initialise_ops(ef_vi *vi) {
    vi->ops.transmit                    = efct_ef_vi_transmit;
    vi->ops.transmitv                   = efct_ef_vi_transmitv;
    vi->ops.transmitv_init              = efct_ef_vi_transmitv;
    vi->ops.transmit_push               = efct_ef_vi_transmit_push;
    vi->ops.transmit_pio                = ef10ct_transmit_pio;
    vi->ops.transmit_copy_pio           = ef10ct_transmit_copy_pio;
    vi->ops.transmit_pio_warm           = ef10ct_transmit_pio_warm;
    vi->ops.transmit_copy_pio_warm      = ef10ct_transmit_copy_pio_warm;
    vi->ops.transmitv_ctpio             = ef10ct_transmitv_ctpio;
    vi->ops.transmitv_ctpio_copy        = ef10ct_transmitv_ctpio_copy;
    vi->ops.transmit_alt_select         = ef10ct_transmit_alt_select;
    vi->ops.transmit_alt_select_default = ef10ct_transmit_alt_select_default;
    vi->ops.transmit_alt_stop           = ef10ct_transmit_alt_stop;
    vi->ops.transmit_alt_go             = ef10ct_transmit_alt_go;
    vi->ops.receive_set_discards        = ef10ct_receive_set_discards;
    vi->ops.receive_get_discards        = ef10ct_receive_get_discards;
    vi->ops.transmit_alt_discard        = ef10ct_transmit_alt_discard;
    vi->ops.receive_init                = ef10ct_receive_init;
    vi->ops.receive_push                = ef10ct_receive_push;
    vi->ops.eventq_poll                 = ef10ct_eventq_poll;
    vi->ops.eventq_prime                = ef10ct_eventq_prime;
    vi->ops.eventq_timer_prime          = ef10ct_eventq_timer_prime;
    vi->ops.eventq_timer_run            = ef10ct_eventq_timer_run;
    vi->ops.eventq_timer_clear          = ef10ct_eventq_timer_clear;
    vi->ops.eventq_timer_zero           = ef10ct_eventq_timer_zero;
    vi->ops.transmitv_init_extra        = ef10ct_transmitv_init_extra;
    vi->ops.transmit_memcpy             = ef10ct_transmit_memcpy;
    vi->ops.transmit_memcpy_sync        = ef10ct_transmit_memcpy_sync;
    vi->ops.transmit_ctpio_fallback     = ef10ct_transmit_ctpio_fallback;
    vi->ops.transmitv_ctpio_fallback    = ef10ct_transmitv_ctpio_fallback;

    vi->internal_ops.design_parameters = ef10ct_design_parameters;
}

void ef10ct_vi_init(ef_vi* vi) {
    ef10ct_initialise_ops(vi);

    vi->max_efct_rxq = EF_VI_MAX_EFCT_RXQS;
    vi->evq_phase_bits = 1;

    vi->rx_discard_mask = (
        EF_VI_DISCARD_RX_L4_CSUM_ERR |
        EF_VI_DISCARD_RX_L3_CSUM_ERR |
        EF_VI_DISCARD_RX_ETH_FCS_ERR |
        EF_VI_DISCARD_RX_ETH_LEN_ERR
    );

    vi->vi_txq.efct_fixed_header = efct_tx_header(0, 0,
                            (vi->vi_flags & EF_VI_TX_TIMESTAMPS) ? 1 : 0, 0, 0);
}
