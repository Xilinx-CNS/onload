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

/*! \brief Retrieve the UTC timestamp associated with a received packet,
**         and the clock sync status flags
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
extern int
efct_vi_rxpkt_get_timestamp(struct ef_vi* vi, uint32_t pkt_id,
                            ef_timespec* ts_out, unsigned* flags_out);

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
** Be aware that the packet might not match the next completion event, if the VI
** is using multiple receive queues. You can check whether the completion event
** matches this packet by comparing with the pointer obtained from
** \a efct_vi_rxpkt_get. You can avoid polling other queues by using
** \a efct_vi_rx_future_poll rather than \a ef_eventq_poll while waiting for
** this packet.
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

#ifdef __cplusplus
}
#endif

#endif /* __EFAB_EFCT_VI_H__ */

