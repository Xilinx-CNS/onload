/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* ct_rx.h
 *
 * Copyright 2019 Solarflare Communications Inc.
 * Author: David Riddoch, Matthew Robinson
 *
 * This is a sample to demonstrate usage of EF_VI cut-though receive.
 * See trader_tcpdirect_ds_efvi for example usage.
 */

#ifndef __CT_RX_H__
#define __CT_RX_H__

typedef struct {
  uint64_t  sentinel_val;
  unsigned  first_sentinel_offset;
  unsigned  sentinel_stride;
  unsigned  num_sentinels;
} ef_rx_sentinel_cfg;


typedef struct {
  volatile uint64_t* p_sentinel;
  unsigned           sentinel_i;
  unsigned           sentinel_max;
} ef_rx_sentinel;


/* ef_rx_sentinel_cfg_init is used to setup configuration for a set of sentinels
 *
 * sentinel_val :          the value we check for.
 *                         ideally pick a value which is unlikely to be in the
 *                         real packets
 * first_sentinel_offset : size in bytes of the region of the packet buffer
 *                         which is tested by the first sentinel
 *                         (must be 8-byte aligned)
 * sentinel_stride :       offset in bytes of each subsequent sentinel
 *                         (must be 8-byte aligned)
 * num_sentinels :         maximum number of sentinels to be used
 */
static inline void ef_rx_sentinel_cfg_init(ef_rx_sentinel_cfg* rxsc,
                                           uint64_t sentinel_val,
                                           unsigned first_sentinel_offset,
                                           unsigned sentinel_stride,
                                           unsigned num_sentinels)
{
  assert( first_sentinel_offset % sizeof(uint64_t) == 0 );
  assert( sentinel_stride % sizeof(uint64_t) == 0 );
  assert( first_sentinel_offset > 0 );

  rxsc->sentinel_val = sentinel_val;
  rxsc->first_sentinel_offset = first_sentinel_offset - sizeof(uint64_t);
  rxsc->sentinel_stride = sentinel_stride;
  rxsc->num_sentinels = num_sentinels;
}


/* Initialise an (empty) packet buffer, by setting all sentinel locations to
 * the known value sentinel_val.
 */
static inline void ef_rx_sentinel_init_buf(const ef_rx_sentinel_cfg* rxsc,
                                           void* dma_buf_start)
{
  char* p = (char*) dma_buf_start + rxsc->first_sentinel_offset;
  unsigned i;
  for( i = 0; i < rxsc->num_sentinels; ++i ) {
    *(volatile uint64_t*) p = rxsc->sentinel_val;
    p += rxsc->sentinel_stride;
  }
}


/* Call this to setup rxs, before trying to read a new packet buffer. */
static inline void ef_rx_sentinel_init(ef_rx_sentinel* rxs,
                                       const ef_rx_sentinel_cfg* rxsc,
                                       const void* dma_buf_start)
{
  rxs->p_sentinel =
    (void*) ((char*) dma_buf_start + rxsc->first_sentinel_offset);
  rxs->sentinel_i = 0;
  rxs->sentinel_max = rxsc->num_sentinels - 1; /* max index */
}


/* Adjust the number of sentinels that we will test for this packet.
 * Use when actual packet is shorter than the configured number of sentinels.
 * Avoids wasting time checking sentinels which will never change.
 */
static inline void ef_rx_sentinel_adjust_num(ef_rx_sentinel* rxs,
                                             const ef_rx_sentinel_cfg* rxsc,
                                             unsigned num_sentinels)
{
  assert( num_sentinels > 0 );
  rxs->sentinel_max = num_sentinels - 1;
  if( rxs->sentinel_max >= rxsc->num_sentinels )
    rxs->sentinel_max = rxsc->num_sentinels - 1;
}


/* Test whether the value at the sentinel location is different from the
 * initial value i.e. has data arrived.
 */
static inline int ef_rx_sentinel_is_ready(const ef_rx_sentinel* rxs,
                                          const ef_rx_sentinel_cfg* rxsc)
{
  return *(rxs->p_sentinel) != rxsc->sentinel_val;
}


/* Wait for sentinel to detect data, checking up to loops times.
 * Returns positive value (remaining times) when the sentinel becomes ready.
 * Returns zero if the sentinel has not changed.
 */
static inline int ef_rx_sentinel_wait(const ef_rx_sentinel* rxs,
                                      const ef_rx_sentinel_cfg* rxsc,
                                      unsigned loops)
{
  unsigned i;
  for( i = 0; i < loops; ++i )
    if( ef_rx_sentinel_is_ready(rxs, rxsc) )
      return loops - i;
  return 0;
}


/* Return a pointer to the location directly after the sentinel */
static inline void* ef_rx_sentinel_ready_end(const ef_rx_sentinel* rxs)
{
  return (void*) (rxs->p_sentinel + 1);
}


/* Move onto the next sentinel */
static inline void ef_rx_sentinel_next(ef_rx_sentinel* rxs,
                                       const ef_rx_sentinel_cfg* rxsc)
{
  rxs->p_sentinel = (void*) (((char*) rxs->p_sentinel) + rxsc->sentinel_stride);
  ++(rxs->sentinel_i);
  assert(rxs->sentinel_i < rxsc->num_sentinels);
}


/* Is this the last sentinel in the sequence ? */
static inline int ef_rx_sentinel_is_last(const ef_rx_sentinel* rxs)
{
  return rxs->sentinel_i == rxs->sentinel_max;
}

#endif  /* __CT_RX_H__ */
