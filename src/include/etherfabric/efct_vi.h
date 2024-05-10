/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2022 Xilinx, Inc. */

#ifndef __EFAB_EFCT_VI_H__
#define __EFAB_EFCT_VI_H__

/*! \file
**  \brief Extended \a ef_vi API for EFCT architectures
**
** EFCT architectures have significant differences from other architectures,
** affecting how the \a ef_vi abstraction can be used. In particular, the
** application is not responsible for buffer allocation.
**
** The transmit path is by CTPIO only, so there are no DMA buffers. Transmission
** can be performed using \a ef_vi functions, with some caveats:
**  \li \a base address arguments must be obtained from registered memory
**    regions via \a ef_memreg_dma_addr, as for the DMA buffers used by other
**    architectures.
**  \li Protocol headers must contain valid checksums: this architecture does
**    not support transmit checksum offload.
**  \li Transmission can fail (returning -EAGAIN) if there is not enough space
**    in the adapter's FIFO to write the packet data. This differs from other
**    architectures, which limit the number of packet buffers which can be
**    enqueued. You can use \a ef_vi_transmit_space_bytes to check the available
**    space.
**  \li PIO functions (e.g. \a ef_vi_transmit_pio) are not supported.
**  \li Most functions perform store-and-forward: all data is written to the
**    adapter's FIFO before transmission begins.
**  \li \a ef_vi_transmit_ctpio allows cut-through mode, with \a ct_threshold
**    specifying how many bytes to write before transmission begins. This
**    allows transmission from arbitrary user memory.
**  \li \a ef_vi_transmit_ctpio should be followed up with
**    \a ef_vi_transmit_ctpio_fallback, providing packet data in registered
**    memory, to check for failure, retry if needed, and assign a \a dma_id.
**    This step can be omitted, in which case failure due to insufficient space
**    will not be reported, and completion will report an arbitrary non-zero
**    \a dma_id.
**
** The receive path uses buffers managed by the kernel, which might be shared
** with other processes. An alternative API is provided to access and manage
** these buffers. On completion of a received packet, an event of type RX_REF
** or RX_REF_DISCARD transfers ownership of the buffer to the application, via
** a \a pkt_id identifier. This identifier can be used to access packet data.
**
** The packet buffer must be released after use; after release, the identifier
** and any pointers to packet data must be considered invalid. The buffer should
** be released promptly, as it is managed as part of a larger shared buffer.
** Retaining a reference will prevent reuse of the entire buffer and may cause
** the system to run out of buffers and drop incoming packets. If the packet
** data needs to be retained after handling the completion event, then copy it
** to a user buffer before releasing the packet buffer.
**/

#include <etherfabric/ef_vi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Receive buffer management */

/*! \brief Access the data of a received packet.
**
** \param vi     The virtual interface which received the packet.
** \param pkt_id A valid packet identifier.
**
** \return a pointer to the packet data, typically the first byte of the
**         Ethernet header.
**
** \a pkt_id must come from a RX_REF or RX_REF_DISCARD event for this \a vi,
** and must not have been released. Behaviour is undefined otherwise.
**/
extern const void* efct_vi_rxpkt_get(struct ef_vi* vi, uint32_t pkt_id);

/*! \brief _Deprecated:_ use ef_vi_receive_get_precise_timestamp()
 *         with the packet pointer obtained from efct_vi_rxpkt_get() instead.
**
** \param vi        The virtual interface that received the packet.
** \param pkt_id    A valid packet identifier.
** \param ts_out    Pointer to a timespec, that is updated on return with
**                  the UTC timestamp for the packet.
** \param flags_out Pointer to an unsigned, that is updated on return with
**                  the sync flags for the packet.
**
** \return 0 on success, or a negative error code:
**    \li ENODATA - Packet does not have a timestamp. This should only happen
**                  if timestamps are disabled for this adapter.
**
** \deprecated _This function is now deprecated._ Use
** ef_vi_receive_get_precise_timestamp() with the packet pointer obtained from
** efct_vi_rxpkt_get() instead.
**
** On success the ts_out and flags_out fields are updated, and a value of
** zero is returned. The flags_out field contains the following flags:
** - EF_VI_SYNC_FLAG_CLOCK_SET is set if the adapter clock has ever been
**   set (in sync with system)
** - EF_VI_SYNC_FLAG_CLOCK_IN_SYNC is set if the adapter clock is in sync
**   with the external clock (PTP).
**
** \a pkt_id must come from a RX_REF or RX_REF_DISCARD event for this \a vi,
** and must not have been released. Behaviour is undefined otherwise.
**/
__attribute__ ((deprecated("ef_vi_receive_get_precise_timestamp")))
ef_vi_inline int
efct_vi_rxpkt_get_timestamp(struct ef_vi* vi, uint32_t pkt_id,
                            ef_timespec* ts_out, unsigned* flags_out)
{
  ef_precisetime ts;
  const void* pkt;
  int rc;

  pkt = efct_vi_rxpkt_get(vi, pkt_id);
  rc = ef_vi_receive_get_precise_timestamp(vi, pkt, &ts);
  ts_out->tv_sec = ts.tv_sec;
  ts_out->tv_nsec = ts.tv_nsec;
  *flags_out = ts.tv_flags;
  return rc;
}


/*! \brief Release a received packet's buffer after use
**
** \param vi     The virtual interface which received the packet.
** \param pkt_id A valid packet identifier.
**
** This must be called for each packet for which a RX_REF or RX_REF_DISCARD
** event was received, to prevent resource leaks. Once released, the packet
** identifier and any pointers to the packet data must be considered invalid.
**
** \a pkt_id must come from a RX_REF or RX_REF_DISCARD event for this \a vi,
** and must not have been released. Behaviour is undefined otherwise.
**/
extern void efct_vi_rxpkt_release(struct ef_vi* vi, uint32_t pkt_id);

/*! \brief Detect incoming packets before completion
**
** \param vi    The virtual interface to check for incoming packets.
**
** \return a pointer to partial packet data, typically the first byte of the
**         Ethernet header, or NULL if no packet was detected.
**
** To busy-wait for an incoming packet, call this function repeatedly until it
** returns a non-NULL pointer. This will give access to a small number of bytes
** at the start of the packet (\see EFCT_FUTURE_VALID_BYTES) which will
** typically be enough for the network protocol headers.
**
** This allows some work (e.g. protocol handling) to be carried out while
** waiting for the completion event indicating that the full packet has arrived.
** Any work done may need to be reverted if the packet turns out to be invalid.
**
** To await the specific completion event related to this packet use
** \a efct_vi_rx_future_poll rather than \a ef_eventq_poll.
**
** \note The ef_vi library must occasionally perform non-packet related work.
** If such work is pending this function will always return NULL. The caller
** must sometimes call \a ef_eventq_has_event in their busy-wait loop and
** process events using \a ef_eventq_poll if any are indicated as waiting.
**
** \note An outline code structure for a busy-wait loop using
** \a efct_vi_rx_future_peek is suggested below.
** ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
** for ( ; ; ) {
**   if ( (p = efct_vi_rx_future_peek(vi)) ) {
**     // Process partial packet data here
**     // ...
**
**     // Wait for full packet to arrive. rx_evs[0] will relate to
**     // packet data just processed.
**     while ( !(n_evs = efct_vi_rx_future_poll(vi, rx_evs, max_rx_evs)) )
**       // Add timeout processing in this loop to cover rare event such as
**       // hardware failure.
**       ;
**
**     // Handle RX events returned. If rx_evs[0] is EF_EVENT_TYPE_RX_REF_DISCARD
**     // undo packet processing.  Also undo packet processing if above loop
**     // exited with no events.
**     // ...
**   }
**   if (ef_eventq_has_event(vi)) {
**     n_evs = ef_eventq_poll(vi, evs, max_evs);
**     // Handle events returned.
**     // ...
**   }
** }
** ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
**
** \par
** \note \a efct_vi_rx_future_peek can be called concurrently with other APIs.
** However, \a efct_vi_rx_future_poll and \a ef_eventq_poll cannot be.
*/
extern const void* efct_vi_rx_future_peek(struct ef_vi* vi);

/*! \brief Poll for an incoming packet after \a efct_vi_rx_future_peek
**
** \param vi      The virtual interface to poll
** \param evs     Array in which to return polled events
** \param evs_len Length of the evs array
**
** \return The number of events retrieved
**
** Poll only the receive queue corresponding to an incoming packet detected
** by \efct_vi_rx_future_peek. The first event is expected to relate to that
** packet, of type EF_EVENT_TYPE_RX_REF or EF_EVENT_TYPE_RX_REF_DISCARD.
**
** This may only be called after a call to \a efct_vi_rx_future_peek returning
** a non-NULL pointer, and will not poll for transmit events or packets received
** on other queues.
*/
int efct_vi_rx_future_poll(ef_vi* vi, ef_event* evs, int evs_len);

/*! \brief Number of bytes available in an incoming packet
**
** This is the number of bytes guaranteed to be valid when accessed via a
** pointer obtained from \a efct_vi_rx_future_peek before the corresponding
** completion event has been received. Accessing packet data beyond this limit
** gives undefined behaviour.
*/
#define EFCT_FUTURE_VALID_BYTES 62

/*! \brief _Deprecated:_ Start transmit warming for this VI
**
** \deprecated
** This function is now deprecated in favour of using the generic function:
**  - ef_vi_start_transmit_warm()
**
** Calling transmit functions during warming will exercise the code path but
** will not send any data on the wire. This can potentially improve transmit
** performance for packets sent in shortly after warming.
**
** Each warming transmit will generate a completion event of type
** EF_EVENT_TYPE_TX with an invalid dma_id field of EF_REQUEST_ID_MASK.
** There will be no timestamp whether or not transmit timestamping is
** enabled for this VI.
*/
void efct_vi_start_transmit_warm(ef_vi* vi);

/*! \brief _Deprecated:_ Stop transmit warming for this VI
**
** \deprecated
** This function is now deprecated in favour of using the generic function:
**  - ef_vi_stop_transmit_warm()
**
** Transmit functions will behave normally, attempting to send data on the
** wire, after warming has been stopped.
*/
void efct_vi_stop_transmit_warm(ef_vi* vi);

#ifdef __cplusplus
}
#endif

#endif /* __EFAB_EFCT_VI_H__ */

