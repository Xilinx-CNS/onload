/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Virtual packet / DMA interface for EtherFabric Virtual
**            Interface HAL.
** \date      2018/11/06
** \copyright Copyright &copy; 2018 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_VI_H__
#define __EFAB_VI_H__

#include <etherfabric/ef_vi.h>
#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ef_pd;
struct in6_addr;


/**********************************************************************
 * ef_vi **************************************************************
 **********************************************************************/

/*! \brief Allocate a virtual interface from a protection domain.
**
** \param vi           Memory for the allocated virtual interface.
** \param vi_dh        The ef_driver_handle to associate with the virtual
**                     interface.
** \param pd           The protection domain from which to allocate the
**                     virtual interface.
** \param pd_dh        The ef_driver_handle to associate with the
**                     protection domain.
** \param evq_capacity The capacity of the event queue, or:\n
**                     - 0 for no event queue\n
**                     - -1 for the default size (EF_VI_EVQ_SIZE if set, 
**                     otherwise it is rxq_capacity + txq_capacity +
**                     extra bytes if timestamps are enabled).
** \param rxq_capacity The number of slots in the RX descriptor ring, or:\n
**                     - 0 for no event queue\n
**                     - -1 for the default size (EF_VI_RXQ_SIZE if
**                       set, otherwise 512).
** \param txq_capacity The number of slots in the TX descriptor ring, or:\n
**                     - 0 for no TX descriptor ring\n
**                     - -1 for the default size (EF_VI_TXQ_SIZE if
**                       set, otherwise 512).
** \param evq_opt      event queue to use if evq_capacity=0.
** \param evq_dh       The ef_driver_handle of the evq_opt event queue.
** \param flags        Flags to select hardware attributes of the virtual
**                     interface.
**
** \return >= 0 on success (value is Q_ID), or a negative error code.
**
** Allocate a virtual interface from a protection domain.
**
** This allocates an RX and TX descriptor ring, an event queue, timers and
** interrupt etc. on the card. It also initializes the (opaque) structures
** needed to access them in software.
**
** An existing virtual interface can be specified, to resize its descriptor
** rings and event queue.
**
** When setting the sizes of the descriptor rings and event queue for a new
** or existing virtual interface:
** - the event queue should be left at its default size unless extra rings
**   are added
** - if extra descriptor rings are added, the event queue should also be
**   made correspondingly larger
** - the maximum size of the event queue effectively limits how many
**   descriptor ring slots can be supported without risking the event queue
**   overflowing.
*/
extern int ef_vi_alloc_from_pd(ef_vi* vi, ef_driver_handle vi_dh,
                               struct ef_pd* pd, ef_driver_handle pd_dh,
                               int evq_capacity, int rxq_capacity,
                               int txq_capacity,
                               ef_vi* evq_opt, ef_driver_handle evq_dh,
                               enum ef_vi_flags flags);


/*! \brief Free a virtual interface
**
** \param vi  The virtual interface to free.
** \param nic The ef_driver_handle for the NIC hosting the interface.
**
** \return  0 on success, or a negative error code.
**
** Free a virtual interface.
**
** This should be called when a virtual interface is no longer needed.
**
** To free up all resources, you must also close the associated driver
** handle using ef_driver_close and free up memory from the protection domain
** ef_pd_free. See \ref using_freeing
**
** If successful:
** - the memory for state provided for this virtual interface is no longer
**   required
** - no further events from this virtual interface will be delivered to its
**   event queue.
*/
extern int ef_vi_free(ef_vi* vi, ef_driver_handle nic);


/*! \brief Allocate a set of TX alternatives
**
** \param vi         The virtual interface that is to use the
**                   TX alternatives.
** \param vi_dh      The ef_driver_handle for the NIC hosting the interface.
** \param num_alts   The number of TX alternatives for which to allocate
**                   space.
** \param buf_space  The buffer space required for the set of TX alternatives,
**                   in bytes.
**
** \return 0         Success.
**
** \return -EINVAL   The num_alts or buf_space parameters are invalid, or
**                   the VI was allocated without EF_VI_TX_ALT set.
**
** \return -EALREADY A set of TX alternatives has already been allocated
**                   for use with this VI.
**
** \return -EBUSY   Insufficient memory was available (either host memory
**                  or packet buffers on the adapter); or
**                  too many alternatives requested, or alternatives
**                  requested on too many distinct VIs.
**
** Allocate a set of TX alternatives for use with a virtual interface. The
** virtual interface must have been allocated with the EF_VI_TX_ALT flag.
**
** The space remains allocated until ef_vi_transmit_alt_free() is
** called or the virtual interface is freed.
**
** TX alternatives provide a mechanism to send with very low latency.  They
** work by pre-loading packets into the adapter in advance, and then
** calling ef_vi_transmit_alt_go() to transmit the packets.
**
** Packets are pre-loaded into the adapter using normal send calls such as
** ef_vi_transmit().  Use ef_vi_transmit_alt_select() to select which
** "alternative" to load the packet into.
**
** Each alternative has three states: STOP, GO and DISCARD.  The
** ef_vi_transmit_alt_stop(), ef_vi_transmit_alt_go() and
** ef_vi_transmit_alt_discard() calls transition between the states.
** Typically an alternative is placed in the STOP state, selected,
** pre-loaded with one or more packets, and then later on the critical path
** placed in the GO state.
**
** When packets are transmitted via TX alternatives, events of type
** EF_EVENT_TYPE_TX_ALT are returned to the application.  The application
** is responsible for ensuring that all of the packets in an alternative
** have been sent before transitioning from GO or DISCARD to the STOP
** state.
**
** The @p buf_space parameter gives the amount of buffering to allocate for
** this set of TX alternatives, in bytes.  Note that if this buffering is
** exceeded then packets sent to TX alternatives may be truncated or
** dropped, and no error is reported in this case.
*/
extern int ef_vi_transmit_alt_alloc(struct ef_vi* vi, ef_driver_handle vi_dh,
                                    int num_alts, size_t buf_space);

/*! \brief Free a set of TX alternatives
**
** \param vi         The virtual interface whose alternatives are to be freed.
** \param vi_dh      The ef_driver_handle for the NIC hosting the interface.
**
** \return  0 on success, or a negative error code.
**
** Release the set of TX alternatives allocated by ef_vi_transmit_alt_alloc().
*/
extern int ef_vi_transmit_alt_free(struct ef_vi* vi, ef_driver_handle vi_dh);

/*! \brief Query available buffering
**
** \param vi          Interface to be queried
** \param ifindex     The index of the interface that you wish to query. You
**                    can use if_nametoindex() to obtain this. This should be
**                    the underlying physical interface, rather than a bond,
**                    VLAN, or similar.
** \param vi_dh       The ef_driver_handle for the NIC hosting the interface.
** \param n_alts      Intended number of alternatives
**
** \return -EINVAL if this VI doesn't support alternatives, else the
** number of bytes available
**
** Owing to per-packet and other overheads, the amount of data which
** can be stored in TX alternatives is generally slightly less than
** the amount of memory available on the hardware.
**
** This function allows the caller to find out how much user-visible
** buffering will be available if the given number of alternatives are
** allocated on the given VI.
*/
extern int
ef_vi_transmit_alt_query_buffering(struct ef_vi* vi,
                                   int ifindex,
                                   ef_driver_handle vi_dh,
                                   int n_alts);

/*! \brief Flush the virtual interface
**
** \param vi  The virtual interface to flush.
** \param nic The ef_driver_handle for the NIC hosting the interface.
**
** \return 0 on success, or a negative error code.
**
** Flush the virtual interface.
**
** After this function returns, it is safe to reuse all buffers which have
** been pushed onto the NIC.
*/
extern int ef_vi_flush(ef_vi* vi, ef_driver_handle nic);


/*! \brief Pace the virtual interface
**
** \param vi  The virtual interface to pace.
** \param nic The ef_driver_handle for the NIC hosting the interface.
** \param val The minimum inter-packet gap for the TXQ.
**
** \return 0 on success, or a negative error code.
**
** Pace the virtual interface.
**
** This sets a minimum inter-packet gap for the TXQ:
** - if val is -1 then the TXQ is put into the "pacing" bin, but no gap is
**   enforced
** - otherwise, the gap is (2^val)*100ns.
**
** This can be used to give priority to latency sensitive traffic over bulk
** traffic.
*/
extern int ef_vi_pace(ef_vi* vi, ef_driver_handle nic, int val);


/*! \brief Return the virtual interface MTU
**
** \param vi    The virtual interface to query.
** \param vi_dh The ef_driver_handle for the NIC hosting the interface.
**
** \return The virtual interface Maximum Transmission Unit.
**
** Return the virtual interface MTU. (This is the maximum size of Ethernet
** frames that can be transmitted through, and received by the interface).
**
** The returned value is the total frame size, including all headers, but
** not including the Ethernet frame check.
*/
extern unsigned ef_vi_mtu(ef_vi* vi, ef_driver_handle vi_dh);


/*! \brief Get the Ethernet MAC address for the virtual interface
**
** \param vi      The virtual interface to query.
** \param vi_dh   The ef_driver_handle for the NIC hosting the interface.
** \param mac_out Pointer to a six-byte buffer, that is updated on return
**                with the Ethernet MAC address.
**
** \return 0 on success, or a negative error code.
**
** Get the Ethernet MAC address for the virtual interface.
**
** This is not a cheap call, so cache the result if you care about
** performance.
*/
extern int ef_vi_get_mac(ef_vi* vi, ef_driver_handle vi_dh, void* mac_out);


/*! \brief Send a software-generated event to an event queue
**
** \param resource_id The ID of the event queue.
** \param evq_dh      The ef_driver_handle for the event queue.
** \param ev_bits     Data for the event. The lowest 16 bits only are used,
**                    and all other bits must be clear.
**
** \return 0 on success, or a negative error code.
**
** Send a software-generated event to an event queue.
**
** An application can use this feature to put its own signals onto the
** event queue. For example, a thread might block waiting for events. An
** application could use a software-generated event to wake up the thread,
** so the thread could then process some non-ef_vi resources.
*/
extern int ef_eventq_put(unsigned resource_id,
                         ef_driver_handle evq_dh , unsigned ev_bits);


/**********************************************************************
 * ef_vi_set **********************************************************
 **********************************************************************/

/*! \brief A virtual interface set within a protection domain */
typedef struct {
  /** Resource ID for the virtual interface set */
  unsigned      vis_res_id;
  /** Protection domain from which the virtual interface set is allocated */
  struct ef_pd* vis_pd;
} ef_vi_set;


/*! \brief Allocate a virtual interface set within a protection domain
**
** \param vi_set    Memory for the allocated virtual interface set.
** \param vi_set_dh The ef_driver_handle to associate with the virtual
**                  interface set.
** \param pd        The protection domain from which to allocate the
**                  virtual interface set.
** \param pd_dh     The ef_driver_handle of the associated protection
**                  domain.
** \param n_vis     The number of virtual interfaces in the virtual
**                  interface set.
**
** \return 0 on success, or a negative error code.
**
** Allocate a virtual interface set within a protection domain.
**
** A virtual interface set is usually used to spread the load of handling
** received packets. This is sometimes called receive-side scaling, or RSS.
*/
extern int ef_vi_set_alloc_from_pd(ef_vi_set* vi_set,
                                   ef_driver_handle vi_set_dh,
                                   struct ef_pd* pd, ef_driver_handle pd_dh,
                                   int n_vis);


/*! \brief Free a virtual interface set
**
** \param vi_set    Memory for the allocated virtual interface set.
** \param vi_set_dh The ef_driver_handle to associate with the virtual
**                  interface set.
**
** \return 0 on success, or a negative error code.
**
** Free a virtual interface set.
**
** To free up all resources, you must also close the associated driver
** handle.
*/
extern int ef_vi_set_free(ef_vi_set* vi_set, ef_driver_handle vi_set_dh);


/*! \brief Allocate a virtual interface from a virtual interface set
**
** \param vi              Memory for the allocated virtual interface.
** \param vi_dh           The ef_driver_handle to associate with the
**                        virtual interface.
** \param vi_set          The virtual interface set from which to allocate
**                        the virtual interface.
** \param vi_set_dh       The ef_driver_handle to associate with the
**                        virtual interface set.
** \param index_in_vi_set Index of the virtual interface within the set to
**                        allocate, or -1 for any.
** \param evq_capacity    The number of events in the event queue (maximum
**                        32768), or:\n
**                        - 0 for no event queue\n
**                        - -1 for the default size.
** \param rxq_capacity    The number of slots in the RX descriptor ring,
**                        or:\n
**                        - 0 for no RX queue\n
**                        - -1 for the default size (EF_VI_RXQ_SIZE if
**                        set, otherwise 512).
** \param txq_capacity    The number of slots in the TX descriptor ring,
**                        or:\n
**                        - 0 for no TX queue\n
**                        - -1 for the default size (EF_VI_TXQ_SIZE if
**                        set, otherwise 512).
** \param evq_opt         event queue to use if evq_capacity=0.
** \param evq_dh          The ef_driver_handle of the evq_opt event queue.
** \param flags           Flags to select hardware attributes of the
**                        virtual interface.
**
** \return >= 0 on success (value is Q_ID), or a negative error code.
**
** Allocate a virtual interface from a virtual interface set.
**
** This allocates an RX and TX descriptor ring, an event queue, timers and
** interrupt etc. on the card. It also initializes the (opaque) structures
** needed to access them in software.
**
** An existing virtual interface can be specified, to resize its descriptor
** rings and event queue.
**
** When setting the sizes of the descriptor rings and event queue for a new
** or existing virtual interface:
** - the event queue should be left at its default size unless extra rings
**   are added
** - if extra descriptor rings are added, the event queue should also be
**   made correspondingly larger
** - the maximum size of the event queue effectively limits how many
**   descriptor ring slots can be supported without risking the event queue
**   overflowing.
*/
extern int ef_vi_alloc_from_set(ef_vi* vi, ef_driver_handle vi_dh,
                                ef_vi_set* vi_set, ef_driver_handle vi_set_dh,
                                int index_in_vi_set, int evq_capacity,
                                int rxq_capacity, int txq_capacity,
                                ef_vi* evq_opt, ef_driver_handle evq_dh,
                                enum ef_vi_flags flags);


/*! \brief Prime a virtual interface
**
** \param vi          The virtual interface to prime.
** \param dh          The ef_driver_handle to associate with the virtual
**                    interface.
** \param current_ptr Value returned from ef_eventq_current().
**
** \return 0 on success, or a negative error code.
**
** Prime a virtual interface. This enables interrupts so you can block on
** the file descriptor associated with the ef_driver_handle using
** select/poll/epoll, etc.
**
** Passing the current event queue pointer ensures correct handling of any
** events that occur between this prime and the epoll_wait call.
*/
extern int ef_vi_prime(ef_vi* vi, ef_driver_handle dh, unsigned current_ptr);


/**********************************************************************
 * ef_filter **********************************************************
 **********************************************************************/

/*! \brief Flags for a filter */
enum ef_filter_flags {
  /** No flags */
  EF_FILTER_FLAG_NONE           = 0x0,
  /** If set, the filter will receive looped back packets for matching (see
  ** ef_filter_spec_set_tx_port_sniff()) */
  EF_FILTER_FLAG_MCAST_LOOP_RECEIVE     = 0x2,
};

/*! \brief Specification of a filter */
typedef struct {
  /** Type of filter */
  unsigned type;
  /** Flags for filter */
  unsigned flags;
  /** Data for filter */
  unsigned data[12];
} ef_filter_spec;

/*! \brief Virtual LANs for a filter */
enum {
  /** Any Virtual LAN */
  EF_FILTER_VLAN_ID_ANY = -1,
};

/*! \brief Cookie identifying a filter */
typedef struct {
  /** ID of the filter */
  int filter_id;
  /** Type of the filter */
  int filter_type;
} ef_filter_cookie;


/*! \brief Initialize an ef_filter_spec
**
** \param filter_spec  The ef_filter_spec to initialize.
** \param flags        The flags to set in the ef_filter_spec.
**
** \return None.
**
** Initialize an ef_filter_spec.
**
** This function must be called to initialize a filter before calling the
** other filter functions.
**
**  The EF_FILTER_FLAG_MCAST_LOOP_RECEIVE flag does the following:
** - if set, the filter will receive looped back packets for matching (see
**   ef_filter_spec_set_tx_port_sniff())
** - otherwise, the filter will not receive looped back packets.
*/
extern void ef_filter_spec_init(ef_filter_spec* filter_spec,
                                enum ef_filter_flags flags);

/*! Set various types of filters on the filter spec */

/*! \brief Set an IP4 Local filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
** \param protocol    The protocol on which to filter (IPPROTO_UDP or
**                    IPPROTO_TCP).
** \param host_be32   The local host address on which to filter, as a
**                    32-bit big-endian value (e.g. the output of htonl()).
** \param port_be16   The local port on which to filter, as a 16-bit
**                    big-endian value (e.g. the output of htons()).
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set an IP4 Local filter on the filter specification.
**
** This filter intercepts all packets that match the given protocol and
** host/port combination.
**
** \note You cannot specify a range, or a wildcard, for any parameter.
*/
extern int ef_filter_spec_set_ip4_local(ef_filter_spec* filter_spec,
                                        int protocol,
                                        unsigned host_be32, int port_be16);


/*! \brief Set an IP4 Full filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
** \param protocol    The protocol on which to filter (IPPROTO_UDP or
**                    IPPROTO_TCP).
** \param host_be32   The local host address on which to filter, as a
**                    32-bit big-endian value (e.g. the output of htonl()).
** \param port_be16   The local port on which to filter, as a 16-bit
**                    big-endian value (e.g. the output of htons()).
** \param rhost_be32  The remote host address on which to filter, as a
**                    32-bit big-endian value (e.g. the output of htonl()).
** \param rport_be16  The remote port on which to filter, as a 16-bit
**                    big-endian value (e.g. the output of htons()).
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set an IP4 Full filter on the filter specification.
**
** This filter intercepts all packets that match the given protocol and
** host/port combinations.
**
** \note You cannot specify a range, or a wildcard, for any parameter.
*/
extern int ef_filter_spec_set_ip4_full(ef_filter_spec* filter_spec,
                                       int protocol,
                                       unsigned host_be32, int port_be16,
                                       unsigned rhost_be32, int rport_be16);


/*! \brief Set an IP6 Local filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
** \param protocol    The protocol on which to filter (IPPROTO_UDP or
**                    IPPROTO_TCP).
** \param host        The local host address on which to filter, as a
**                    pointer to a struct in6_addr.
** \param port_be16   The local port on which to filter, as a 16-bit
**                    big-endian value (e.g. the output of htons()).
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set an IP6 Local filter on the filter specification.
**
** This filter intercepts all packets that match the given protocol and
** host/port combination.
**
** \note You cannot specify a range, or a wildcard, for any parameter.
*/
extern int ef_filter_spec_set_ip6_local(ef_filter_spec* filter_spec,
                                        int protocol,
                                        const struct in6_addr* host,
                                        int port_be16);


/*! \brief Set an IP6 Full filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
** \param protocol    The protocol on which to filter (IPPROTO_UDP or
**                    IPPROTO_TCP).
** \param host        The local host address on which to filter, as a
**                    pointer to a struct in6_addr.
** \param port_be16   The local port on which to filter, as a 16-bit
**                    big-endian value (e.g. the output of htons()).
** \param rhost       The remote host address on which to filter, as a
**                    pointer to a struct in6_addr.
** \param rport_be16  The remote port on which to filter, as a 16-bit
**                    big-endian value (e.g. the output of htons()).
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set an IP6 Full filter on the filter specification.
**
** This filter intercepts all packets that match the given protocol and
** host/port combinations.
**
** \note You cannot specify a range, or a wildcard, for any parameter.
*/
extern int ef_filter_spec_set_ip6_full(ef_filter_spec* filter_spec,
                                       int protocol,
                                       const struct in6_addr* host,
                                       int port_be16,
                                       const struct in6_addr* rhost,
                                       int rport_be16);


/*! \brief Add a Virtual LAN filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
** \param vlan_id     The ID of the virtual LAN on which to filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Add a Virtual LAN filter on the filter specification.
**
** The Virtual LAN filter can be combined with other filters as follows:
** - Ethernet MAC Address filters: supported.
**   See ef_filter_spec_set_eth_local().
** - EtherType filters: supported.
** - IP protocol filters: supported.
** - IP4 filters:
**   - 7000-series adapter with full feature firmware: supported.
**     Packets that match the IP4 filter will be received only if they also
**     match the VLAN.
**   - Otherwise: not supported.
**     Packets that match the IP4 filter will always be received, whatever
**     the VLAN.
** - Other filters: not supported, -EPROTONOSUPPORT is returned.
*/
extern int ef_filter_spec_set_vlan(ef_filter_spec* filter_spec,
                                   int vlan_id);


/*! \brief Set an Ethernet MAC Address filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
** \param vlan_id     The ID of the virtual LAN on which to filter, or
**                    EF_FILTER_VLAN_ID_ANY to match all VLANs.
** \param mac         The MAC address on which to filter, as a six-byte
**                    array.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set an Ethernet MAC Address filter on the filter specification.
**
** This filter intercepts all packets that match the given MAC address and
** VLAN.
*/
extern int ef_filter_spec_set_eth_local(ef_filter_spec* filter_spec,
                                        int vlan_id, const void* mac);


/*! \brief Set a Unicast All filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set a Unicast All filter on the filter specification.
**
** This filter must be used with caution. It intercepts all unicast packets
** that arrive, including ARP resolutions, which must normally be handled
** by the kernel for routing to work.
*/
extern int ef_filter_spec_set_unicast_all(ef_filter_spec* filter_spec);


/*! \brief Set a Multicast All filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set a Multicast All filter on the filter specification.
**
** This filter must be used with caution. It intercepts all multicast
** packets that arrive, including IGMP group membership queries, which must
** normally be handled by the kernel to avoid any membership lapses.
*/
extern int ef_filter_spec_set_multicast_all(ef_filter_spec* filter_spec);


/*! \brief Set a Unicast Mismatch filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set a Unicast Mismatch filter on the filter specification.
**
** This filter intercepts all unicast traffic that would otherwise be
** discarded; that is, all traffic that does not match either an existing
** unicast filter or a kernel subscription.
**
** This filter is not supported by 5000-series and 6000-series adapters.
*/
extern int ef_filter_spec_set_unicast_mismatch(ef_filter_spec* filter_spec);


/*! \brief Set a Multicast Mismatch filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set a Multicast Mismatch filter on the filter specification.
**
** This filter intercepts all multicast traffic that would otherwise be
** discarded; that is, all traffic that does not match either an existing
** multicast filter or a kernel subscription.
**
** This filter is not supported by 5000-series and 6000-series adapters.
*/
extern int ef_filter_spec_set_multicast_mismatch(ef_filter_spec* filter_spec);


/*! \brief Set a Port Sniff filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
** \param promiscuous True to enable promiscuous mode on any virtual
**                    interface using this filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set a Port Sniff filter on the filter specification.
**
** This filter enables sniff mode for the virtual interface. All filtering
** on that interface then copies packets instead of intercepting them.
** Consequently, the kernel receives the filtered packets; otherwise it
** would not.
**
** If promiscuous mode is enabled, this filter copies all packets, instead
** of only those matched by other filters.
**
** This filter is not supported by 5000-series and 6000-series adapters.
*/
extern int ef_filter_spec_set_port_sniff(ef_filter_spec* filter_spec,
                                         int promiscuous);


/*! \brief Set a TX Port Sniff filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set a TX Port Sniff filter on the filter specification.
**
** This filter loops back a copy of all outgoing packets, so that your
** application can process them.
**
** This filter is not supported by 5000-series and 6000-series adapters.
*/
extern int ef_filter_spec_set_tx_port_sniff(ef_filter_spec* filter_spec);


/*! \brief Set a Block Kernel filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set a Block Kernel filter on the filter specification.
**
** This filter blocks all packets from reaching the kernel.
**
** This filter is not supported by 5000-series and 6000-series adapters.
*/
extern int ef_filter_spec_set_block_kernel(ef_filter_spec* filter_spec);


/*! \brief Set a Block Kernel Multicast filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set a Block Kernel Multicast filter on the filter specification.
**
** This filter blocks all multicast packets from reaching the kernel.
**
** This filter is not supported by 5000-series and 6000-series adapters.
*/
extern int
ef_filter_spec_set_block_kernel_multicast(ef_filter_spec* filter_spec);


/*! \brief Add an EtherType filter on the filter specification
**
** \param filter_spec       The ef_filter_spec on which to set the filter.
** \param ether_type_be16   The EtherType on which to filter, in network order.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Add an EtherType filter on the filter specification
**
** The EtherType filter can be combined with other filters as follows:
** - Ethernet MAC Address filters: supported.
**   See ef_filter_spec_set_eth_local().
** - Other filters: not supported, -EPROTONOSUPPORT is returned.
**
** This filter is not supported by 5000-series and 6000-series adapters.
** 7000-series adapters require a firmware version of at least v4.6 for full
** support for these filters.  v4.5 firmware supports such filters only
** when not combined with a MAC address.  Insertion of such filters on firmware
** versions that do not support them will fail.
**
** Due to a current firmware limitation, this method does not support ether_type 
** IP or IPv6 and will return no error if these values are specified.
*/
extern int
ef_filter_spec_set_eth_type(ef_filter_spec *filter_spec,
			    uint16_t ether_type_be16);


/*! \brief Add an IP protocol filter on the filter specification
**
** \param filter_spec   The ef_filter_spec on which to set the filter.
** \param ip_proto      The IP protocol on which to filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Add an IP protocol filter on the filter specification
**
** The IP protocol filter can be combined with other filters as follows:
** - Ethernet MAC Address filters: supported.
**   See ef_filter_spec_set_eth_local().
** - Other filters: not supported, -EPROTONOSUPPORT is returned.
**
** This filter is not supported by 5000-series and 6000-series adapters.
** Other adapters require a firmware version of at least v4.5.  Insertion
** of such filters on firmware versions that do not support them will fail.
**
** Due to a current firmware limitation, this method does not support ip_proto=6 (TCP)
** or ip_proto=17 (UDP) and will return no error if these values are used.  
*/
extern int
ef_filter_spec_set_ip_proto(ef_filter_spec *filter_spec, uint8_t ip_proto);


/*! \brief Set a Block Kernel Unicast filter on the filter specification
**
** \param filter_spec The ef_filter_spec on which to set the filter.
**
** \return 0 on success, or a negative error code:\n
**         -EPROTONOSUPPORT indicates that a filter is already set that is
**         incompatible with the new filter.
**
** Set a Block Kernel Unicast filter on the filter specification.
**
** This filter blocks all unicast packets from reaching the kernel.
**
** This filter is not supported by 5000-series and 6000-series adapters.
*/
extern int ef_filter_spec_set_block_kernel_unicast(ef_filter_spec* filter_spec);


/*! \brief Add a filter to a virtual interface.
**
** \param vi                The virtual interface on which to add the
**                          filter.
** \param vi_dh             The ef_driver_handle for the virtual interface.
** \param filter_spec       The filter to add.
** \param filter_cookie_out Optional pointer to an ef_filter_cookie, that
**                          is updated on return with a cookie for the
**                          filter.
**
** \return 0 on success, or a negative error code.
**
** Add a filter to a virtual interface.
**
** filter_cookie_out can be NULL. If not null, then the returned value can
** be used in ef_vi_filter_del() to remove this filter.
**
** After calling this function, any local copy of the filter can be
** deleted.
*/
extern int ef_vi_filter_add(ef_vi* vi, ef_driver_handle vi_dh,
                            const ef_filter_spec* filter_spec,
                            ef_filter_cookie* filter_cookie_out);


/*! \brief Delete a filter from a virtual interface
**
** \param vi            The virtual interface from which to delete the
**                      filter.
** \param vi_dh         The ef_driver_handle for the virtual interface.
** \param filter_cookie The filter cookie for the filter to delete, as set
**                      on return from ef_vi_filter_add().
**
** \return 0 on success, or a negative error code.
**
** Delete a filter from a virtual interface.
*/
extern int ef_vi_filter_del(ef_vi* vi, ef_driver_handle vi_dh,
                            ef_filter_cookie* filter_cookie);


/*! \brief Add a filter to a virtual interface set.
**
** \param vi_set            The virtual interface set on which to add the
**                          filter.
** \param vi_set_dh         The ef_driver_handle for the virtual interface
**                          set.
** \param filter_spec       The filter to add.
** \param filter_cookie_out Optional pointer to an ef_filter_cookie, that
**                          is updated on return with a cookie for the
**                          filter.
**
** \return 0 on success, or a negative error code:\n
**
** Add a filter to a virtual interface set.
**
** filter_cookie_out can be NULL. If not null, then the returned value can
** be used in ef_vi_filter_del() to delete this filter.
**
** After calling this function, any local copy of the filter can be
** deleted.
*/
extern int ef_vi_set_filter_add(ef_vi_set* vi_set, ef_driver_handle vi_set_dh,
                                const ef_filter_spec* filter_spec,
                                ef_filter_cookie* filter_cookie_out);


/*! \brief Delete a filter from a virtual interface set
**
** \param vi_set        The virtual interface set from which to delete the
**                      filter.
** \param vi_set_dh     The ef_driver_handle for the virtual interface set.
** \param filter_cookie The filter cookie for the filter to delete.
**
** \return 0 on success, or a negative error code.
**
** Delete a filter from a virtual interface set.
*/
extern int ef_vi_set_filter_del(ef_vi_set* vi_set, ef_driver_handle vi_set_dh,
                                ef_filter_cookie* filter_cookie);


/**********************************************************************
 * Get VI stats *******************************************************
 **********************************************************************/

/*! \brief Layout for a field of statistics */
typedef struct {
  /** Name of statistics field */
  char* evsfl_name;
  /** Offset of statistics fiel, in bytesd */
  int   evsfl_offset;
  /** Size of statistics field, in bytes */
  int   evsfl_size;
} ef_vi_stats_field_layout;

/*! \brief Layout for statistics */
typedef struct {
  /** Size of data for statistics */
  int                      evsl_data_size;
  /** Number of fields of statistics */
  int                      evsl_fields_num;
  /** Array of fields of statistics */
  ef_vi_stats_field_layout evsl_fields[];
} ef_vi_stats_layout;


/*! \brief Retrieve layout for available statistics
**
** \param vi         The virtual interface to query.
** \param layout_out Pointer to an ef_vi_stats_layout*, that is updated on
**                   return with the layout for available statistics.
**
** \return 0 on success, or a negative error code.
**
** Retrieve layout for available statistics.
*/
extern int
ef_vi_stats_query_layout(ef_vi* vi,
                         const ef_vi_stats_layout**const layout_out);


/*! \brief Retrieve a set of statistic values
**
** \param vi       The virtual interface to query.
** \param vi_dh    The ef_driver_handle for the virtual interface.
** \param data     Pointer to a buffer, into which the statistics are
**                 retrieved.\n
**                 The size of this buffer should be equal to the
**                 evsl_data_bytes field of the layout description, that
**                 can be fetched using ef_vi_stats_query_layout().
** \param do_reset True to reset the statistics after retrieving them.
**
** \return 0 on success, or a negative error code.
**
** Retrieve a set of statistic values.
**
** If do_reset is true, the statistics are reset after reading.
**
** \note This requires full feature firmware. If used with low-latency
** firmware, no error is given, and the statistics are invalid (typically
** all zeroes).
*/
extern int
ef_vi_stats_query(ef_vi* vi, ef_driver_handle vi_dh,
                  void* data, int do_reset);


#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_VI_H__ */
