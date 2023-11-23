/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Virtual Interface definitions for EtherFabric Virtual
**            Interface HAL.
** \date      2018/11/06
** \copyright Copyright &copy; 2018 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_EF_VI_H__
#define __EFAB_EF_VI_H__


/**********************************************************************
 * Primitive types ****************************************************
 **********************************************************************/

/* We standardize on the types from stdint.h and synthesize these types
 * for compilers/platforms that don't provide them */

#if defined(__GNUC__)
# ifdef __KERNEL__
#  include <linux/types.h>
#  include <linux/time.h>
#  include <asm/errno.h>
#  include <linux/uio.h>
# else
#  include <stdint.h>
#  ifndef __STDC_FORMAT_MACROS
#   define __STDC_FORMAT_MACROS
#  endif
#  include <inttypes.h>
#  include <time.h>
#  include <sys/types.h>
#  include <sys/uio.h>
#  include <errno.h>
# endif
# define EF_VI_ALIGN(x) __attribute__ ((aligned (x)))
# define ef_vi_inline static inline
# define ef_vi_pure __attribute__ ((pure))
# define ef_vi_cold __attribute__ ((cold))

/* Expect noinline to be defined in kernel */
# if defined(__KERNEL__) && defined (noinline)
#  define ef_vi_noinline noinline
# else
#  define ef_vi_noinline __attribute__ ((noinline))
# endif

#else
# error Unknown compiler
#endif


/*! \brief Cache line sizes for alignment purposes */
#if defined(__powerpc64__) || defined(__powerpc__)
# define EF_VI_DMA_ALIGN  128
#else
# define EF_VI_DMA_ALIGN  64
#endif


#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************************
 * Types **************************************************************
 **********************************************************************/

/*! \brief An ef_driver_handle is needed to allocate resources. */
#ifdef __KERNEL__
typedef struct efhw_nic*   ef_driver_handle;
#else
typedef int                ef_driver_handle;
#endif

/*! \brief A pointer to an event queue */
typedef uint32_t                ef_eventq_ptr;

/*! \brief An address */
typedef uint64_t                ef_addr;
/*! \brief An address of an I/O area for a virtual interface */
typedef char*                   ef_vi_ioaddr_t;

/*! \brief Reference to a non-local address space */
typedef uint64_t ef_addrspace;

#define EF_ADDRSPACE_LOCAL ((uint64_t)-1)

struct ef_vi;
struct ef_filter_spec;
struct ef_filter_cookie;

/**********************************************************************
 * Dimensions *********************************************************
 **********************************************************************/

/*! \brief The maximum number of queues per virtual interface */
#define EF_VI_MAX_QS              32
/*! \brief The minimum size of array to pass when polling the event queue */
#define EF_VI_EVENT_POLL_MIN_EVS  2
/*! \brief The maximum number of efct receive queues per virtual interface */
#define EF_VI_MAX_EFCT_RXQS       8


/**********************************************************************
 * ef_event ***********************************************************
 **********************************************************************/

/*! \brief A DMA request identifier.
**
** This is an integer token specified by the transport and associated
** with a DMA request.  It is returned to the VI user with DMA completion
** events.  It is typically used to identify the buffer associated with
** the transfer.
*/
typedef int			ef_request_id;


/*! \brief Mask to use with an ef_request_id. */
#define EF_REQUEST_ID_MASK      0xffffffff


/*! \brief A token that identifies something that has happened.
**
** Examples include packets received, packets transmitted, and errors.
**
** Users should not access this structure, but should instead use the
** macros provided.
*/
typedef union {
  /** A generic event, to query the type when it is unknown */
  struct {
    unsigned       type       :16;
  } generic;
  /** An event of type EF_EVENT_TYPE_RX */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :8;
    unsigned       __reserved :8;
    unsigned       rq_id      :32;
    unsigned       len        :16;
    unsigned       flags      :16;
    unsigned       ofs        :16; /* AF_XDP specific */
  } rx;
  /** An event of type EF_EVENT_TYPE_RX_DISCARD */
  struct {  /* This *must* have same initial layout as [rx]. */
    unsigned       type       :16;
    unsigned       q_id       :8;
    unsigned       __reserved :8;
    unsigned       rq_id      :32;
    unsigned       len        :16;
    unsigned       flags      :16;
    unsigned       subtype    :16;
  } rx_discard;
  /** An event of type EF_EVENT_TYPE_TX */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :8;
    unsigned       flags      :8;
    unsigned       desc_id    :16;
  } tx;
  /** An event of type EF_EVENT_TYPE_TX_ERROR */
  struct {  /* This *must* have same layout as [tx]. */
    unsigned       type       :16;
    unsigned       q_id       :8;
    unsigned       flags      :8;
    unsigned       desc_id    :16;
    unsigned       subtype    :16;
  } tx_error;
  /** An event of type EF_EVENT_TYPE_TX_WITH_TIMESTAMP */
  struct {  /* This *must* have same layout as [tx] up to [flags]. */
    unsigned       type       :16;
    unsigned       q_id       :8;
    unsigned       flags      :8;
    unsigned       rq_id      :32;
    unsigned       ts_sec     :32;
    unsigned       ts_nsec    :32;
  } tx_timestamp;
  /** An event of type EF_EVENT_TYPE_TX_ALT */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :8;
    unsigned       __reserved :8;
    unsigned       alt_id     :16;
  } tx_alt;
  /** An event of type EF_EVENT_TYPE_RX_NO_DESC_TRUNC */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :8;
  } rx_no_desc_trunc;
  /** An event of type EF_EVENT_TYPE_RX_PACKED_STREAM */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :8;
    unsigned       __reserved :8;
    unsigned       flags      :16;
    unsigned       n_pkts     :16;
    unsigned       ps_flags   :8;
  } rx_packed_stream;
  /** An event of type EF_EVENT_TYPE_SW */
  struct {
    unsigned       type       :16;
    unsigned       data;
  } sw;
  /** An event of type EF_EVENT_TYPE_RX_MULTI */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :8;
    unsigned       __reserved :8;
    unsigned       n_descs    :16;
    unsigned       flags      :16;
  } rx_multi;
  /** An event of type EF_EVENT_TYPE_RX_MULTI_DISCARD */
  struct {  /* Common layout with rx_multi. */
    unsigned       type       :16;
    unsigned       q_id       :8;
    unsigned       __reserved :8;
    unsigned       n_descs    :16;
    unsigned       flags      :16;
    unsigned       subtype    :16;
  } rx_multi_discard;
  /** An event of type EF_EVENT_TYPE_RX_MULTI_PKTS */
  struct {
    unsigned       type       :16;
    unsigned       q_id       :8;
    unsigned       __reserved :8;
    unsigned       n_pkts     :16;
    unsigned       flags      :16;
  } rx_multi_pkts;
  /** An event of type EF_EVENT_TYPE_MEMCPY */
  struct {
    unsigned       type       :16;
    unsigned       __reserved :16;
    unsigned       dma_id     :32;
  } memcpy;
  /** An event of type EF_EVENT_TYPE_RX_REF */
  struct {
    unsigned       type       :16;
    unsigned       len        :16;
    unsigned       pkt_id     :32;
    unsigned       q_id       :8;
    unsigned       filter_id  :16;
    unsigned       user       :8;
  } rx_ref;
  /** An event of type EF_EVENT_TYPE_RX_REF_DISCARD */
  struct {
    unsigned       type       :16;
    unsigned       len        :16;
    unsigned       pkt_id     :32;
    unsigned       q_id       :8;
    unsigned       filter_id  :16;
    unsigned       user       :8;
    unsigned       flags      :16;
  } rx_ref_discard;
} ef_event;


/*! \brief Type of event in an ef_event e */
#define EF_EVENT_TYPE(e)        ((e).generic.type)


/*! \brief Possible types of events */
enum {
  /** Good data was received. */
  EF_EVENT_TYPE_RX,
  /** Packets have been sent. */
  EF_EVENT_TYPE_TX,
  /** Data received and buffer consumed, but something is wrong. */
  EF_EVENT_TYPE_RX_DISCARD,
  /** Transmit of packet failed. */
  EF_EVENT_TYPE_TX_ERROR,
  /** Received packet was truncated due to a lack of descriptors. */
  EF_EVENT_TYPE_RX_NO_DESC_TRUNC,
  /** Software generated event. */
  EF_EVENT_TYPE_SW,
  /** Event queue overflow. */
  EF_EVENT_TYPE_OFLOW,
  /** TX timestamp event. */
  EF_EVENT_TYPE_TX_WITH_TIMESTAMP,
  /** A batch of packets was received in a packed stream. */
  EF_EVENT_TYPE_RX_PACKED_STREAM,
  /** A batch of packets was received on a RX event merge vi. */
  EF_EVENT_TYPE_RX_MULTI,
  /** Packet has been transmitted via a "TX alternative". */
  EF_EVENT_TYPE_TX_ALT,
  /** A batch of packets was received with error condition set. */
  EF_EVENT_TYPE_RX_MULTI_DISCARD,
  /** Event queue has been forcibly halted (hotplug, reset, etc.) */
  EF_EVENT_TYPE_RESET,
  /** A ef_vi_transmit_memcpy_sync() request has completed. */
  EF_EVENT_TYPE_MEMCPY,
  /** A batch of packets was received. */
  EF_EVENT_TYPE_RX_MULTI_PKTS,
  /** Good packets have been received on an efct adapter */
  EF_EVENT_TYPE_RX_REF,
  /** Packets with a bad checksum have been received on an efct adapter */
  EF_EVENT_TYPE_RX_REF_DISCARD,
};


/* Macros to look up various information per event */

/*! \brief Get the number of bytes received */
#define EF_EVENT_RX_BYTES(e)            ((e).rx.len)
/*! \brief Get the RX descriptor ring ID used for a received packet. */
#define EF_EVENT_RX_Q_ID(e)             ((e).rx.q_id)
/*! \brief Get the dma_id used for a received packet. */
#define EF_EVENT_RX_RQ_ID(e)            ((e).rx.rq_id)
/*! \brief True if the CONTinuation Of Packet flag is set for an RX event */
#define EF_EVENT_RX_CONT(e)             ((e).rx.flags & EF_EVENT_FLAG_CONT)
/*! \brief True if the Start Of Packet flag is set for an RX event */
#define EF_EVENT_RX_SOP(e)              ((e).rx.flags & EF_EVENT_FLAG_SOP)
/*! \brief True if the next buffer flag is set for a packed stream event */
#define EF_EVENT_RX_PS_NEXT_BUFFER(e)   ((e).rx_packed_stream.flags &	\
                                         EF_EVENT_FLAG_PS_NEXT_BUFFER)
/*! \brief True if the iSCSIOK flag is set for an RX event */
#define EF_EVENT_RX_ISCSI_OKAY(e)       ((e).rx.flags & EF_EVENT_FLAG_ISCSI_OK)

/* RX-event flags. */

/*! \brief Start Of Packet flag. */
#define EF_EVENT_FLAG_SOP             0x1
/*! \brief CONTinuation Of Packet flag. */
#define EF_EVENT_FLAG_CONT            0x2
/*! \brief iSCSI CRC validated OK flag. */
#define EF_EVENT_FLAG_ISCSI_OK        0x4
/*! \brief Multicast flag. */
#define EF_EVENT_FLAG_MULTICAST       0x8
/*! \brief Packed Stream Next Buffer flag. */
#define EF_EVENT_FLAG_PS_NEXT_BUFFER  0x10

/* TX-event flags. */

/*! \brief Packets were sent successfully with CTPIO. */
#define EF_EVENT_FLAG_CTPIO           0x1

/*! \brief Get the TX descriptor ring ID used for a transmitted packet. */
#define EF_EVENT_TX_Q_ID(e)     ((e).tx.q_id)

/*! \brief True if packets were sent successfully with CTPIO. */
#define EF_EVENT_TX_CTPIO(e)    ((e).tx.flags & EF_EVENT_FLAG_CTPIO)

/*! \brief Get the RX descriptor ring ID used for a discarded packet. */
#define EF_EVENT_RX_DISCARD_Q_ID(e)  ((e).rx_discard.q_id)
/*! \brief Get the dma_id used for a discarded packet. */
#define EF_EVENT_RX_DISCARD_RQ_ID(e) ((e).rx_discard.rq_id)
/*! \brief True if the CONTinuation Of Packet flag is set for an RX_DISCARD
** event */
#define EF_EVENT_RX_DISCARD_CONT(e)  ((e).rx_discard.flags&EF_EVENT_FLAG_CONT)
/*! \brief True if the Start Of Packet flag is set for an RX_DISCARD event */
#define EF_EVENT_RX_DISCARD_SOP(e)   ((e).rx_discard.flags&EF_EVENT_FLAG_SOP)
/*! \brief Get the reason for an EF_EVENT_TYPE_RX_DISCARD event */
#define EF_EVENT_RX_DISCARD_TYPE(e)  ((e).rx_discard.subtype)
/*! \brief Get the length of a discarded packet */
#define EF_EVENT_RX_DISCARD_BYTES(e) ((e).rx_discard.len)

/*! \brief Get the RX descriptor ring ID used for a received packet. */
#define EF_EVENT_RX_MULTI_Q_ID(e)             ((e).rx_multi.q_id)
/*! \brief True if the CONTinuation Of Packet flag is set for an RX HT event */
#define EF_EVENT_RX_MULTI_CONT(e)             ((e).rx_multi.flags & \
                                               EF_EVENT_FLAG_CONT)
/*! \brief True if the Start Of Packet flag is set for an RX HT event */
#define EF_EVENT_RX_MULTI_SOP(e)              ((e).rx_multi.flags & \
                                               EF_EVENT_FLAG_SOP)
/*! \brief Get the reason for an EF_EVENT_TYPE_RX_MULTI_DISCARD event */
#define EF_EVENT_RX_MULTI_DISCARD_TYPE(e)     ((e).rx_multi_discard.subtype)

/*! \brief The reason for an EF_EVENT_TYPE_RX_DISCARD event */
enum {
  /** IP header or TCP/UDP checksum error */
  EF_EVENT_RX_DISCARD_CSUM_BAD,
  /** Hash mismatch in a multicast packet */
  EF_EVENT_RX_DISCARD_MCAST_MISMATCH,
  /** Ethernet CRC error */
  EF_EVENT_RX_DISCARD_CRC_BAD,
  /** Frame was truncated */
  EF_EVENT_RX_DISCARD_TRUNC,
  /** No ownership rights for the packet */
  EF_EVENT_RX_DISCARD_RIGHTS,
  /** Event queue error, previous RX event has been lost */
  EF_EVENT_RX_DISCARD_EV_ERROR,
  /** Other unspecified reason */
  EF_EVENT_RX_DISCARD_OTHER,
  /** Inner IP header or TCP/UDP checksum error */
  EF_EVENT_RX_DISCARD_INNER_CSUM_BAD,
  /** Maximum value of this enumeration */
  EF_EVENT_RX_DISCARD_MAX, /* Keep this last */
};

/*! \brief Get the TX descriptor ring ID used for a transmit error */
#define EF_EVENT_TX_ERROR_Q_ID(e)              ((e).tx_error.q_id)
/*! \brief Get the reason for a TX_ERROR event */
#define EF_EVENT_TX_ERROR_TYPE(e)              ((e).tx_error.subtype)

/*! \brief The adapter clock has previously been set in sync with the
** system */
#define EF_VI_SYNC_FLAG_CLOCK_SET 1
/*! \brief The adapter clock is in sync with the external clock (PTP) */
#define EF_VI_SYNC_FLAG_CLOCK_IN_SYNC 2

/*! \brief Get the TX descriptor ring ID used for a timestamped packet. */
#define EF_EVENT_TX_WITH_TIMESTAMP_Q_ID(e)     ((e).tx_timestamp.q_id)
/*! \brief Get the dma_id used for a timestamped packet. */
#define EF_EVENT_TX_WITH_TIMESTAMP_RQ_ID(e)    ((e).tx_timestamp.rq_id)
/*! \brief Get the number of seconds from the timestamp of a transmitted
** packet */
#define EF_EVENT_TX_WITH_TIMESTAMP_SEC(e)      ((e).tx_timestamp.ts_sec)
/*! \brief Get the number of nanoseconds from the timestamp of a transmitted
** packet */
#define EF_EVENT_TX_WITH_TIMESTAMP_NSEC(e)     ((e).tx_timestamp.ts_nsec)
/*! \brief Mask for the sync flags in the timestamp of a transmitted packet */
#define EF_EVENT_TX_WITH_TIMESTAMP_SYNC_MASK \
  (EF_VI_SYNC_FLAG_CLOCK_SET | EF_VI_SYNC_FLAG_CLOCK_IN_SYNC)
/*! \brief Get the sync flags from the timestamp of a transmitted packet */
#define EF_EVENT_TX_WITH_TIMESTAMP_SYNC_FLAGS(e) \
  ((e).tx_timestamp.ts_nsec & EF_EVENT_TX_WITH_TIMESTAMP_SYNC_MASK)

/*! \brief Get the TX descriptor ring ID used for a TX alternative packet. */
#define EF_EVENT_TX_ALT_Q_ID(e)                ((e).tx_alt.q_id)
/*! \brief Get the TX alternative ID used for a TX alternative packet. */
#define EF_EVENT_TX_ALT_ALT_ID(e)              ((e).tx_alt.alt_id)

/*! \brief The reason for an EF_EVENT_TYPE_TX_ERROR event */
enum {
  /** No ownership rights for the packet */
  EF_EVENT_TX_ERROR_RIGHTS,
  /** TX pacing engine work queue was full */
  EF_EVENT_TX_ERROR_OFLOW,
  /** Oversized transfer has been indicated by the descriptor */
  EF_EVENT_TX_ERROR_2BIG,
  /** Bus or descriptor protocol error occurred when attempting to read the
  ** memory referenced by the descriptor */
  EF_EVENT_TX_ERROR_BUS,
};

/*! \brief Get the RX descriptor ring ID used for a received packet that
** was truncated due to a lack of descriptors. */
#define EF_EVENT_RX_NO_DESC_TRUNC_Q_ID(e)  ((e).rx_no_desc_trunc.q_id)

/*! \brief Mask for the data in a software generated event */
#define EF_EVENT_SW_DATA_MASK   0xffff
/*! \brief  Get the data for an EF_EVENT_TYPE_SW event */
#define EF_EVENT_SW_DATA(e)     ((e).sw.data)

/*! \brief Output format for an ef_event */
#define EF_EVENT_FMT            "[ev:%x]"
/*! \brief Get the type of an event */
#define EF_EVENT_PRI_ARG(e)     (unsigned) (e).generic.type


/* ***************** */


/*! \brief ef_iovec is similar to the standard struct iovec.  An array of
** these is used to designate a scatter/gather list of I/O buffers.
*/
typedef struct {
  /** base address of the buffer */
  ef_addr  iov_base EF_VI_ALIGN(8);
  /** length of the buffer */
  unsigned iov_len;
} ef_iovec;

#define EF_RIOV_FLAG_TRANSLATE_ADDR 0x1

/*! \brief ef_remote_iovec describes a scatter/gather list of I/O
**  buffers that can optionally be located in another address space
**  that is not directly accessible by the host CPU.
*/
typedef struct {
  /** base address of the buffer */
  ef_addr  iov_base EF_VI_ALIGN(8);
  /** length of the buffer */
  unsigned iov_len;
  uint32_t flags; /* EF_RIOV_FLAG_* */
  ef_addrspace addrspace;
} ef_remote_iovec;


/*! \brief ef_timespec is equal to struct timespec (for now),
** but may change in future for 2038Y.
*/
#ifdef __KERNEL__
typedef struct {
  long tv_sec;
  long tv_nsec;
} ef_timespec;
#else
#define ef_timespec struct timespec
#endif

/**********************************************************************
 * ef_vi **************************************************************
 **********************************************************************/

/*! \brief Flags that can be requested when allocating an ef_vi */
enum ef_vi_flags {
  /** Default setting */
  EF_VI_FLAGS_DEFAULT     = 0x0,
  /** Receive iSCSI header digest enable: hardware verifies header digest
   ** (CRC) when packet is iSCSI */
  EF_VI_ISCSI_RX_HDIG     = 0x2,
  /** Transmit iSCSI header digest enable: hardware calculates and inserts
   ** header digest (CRC) when packet is iSCSI */
  EF_VI_ISCSI_TX_HDIG     = 0x4,
  /** Receive iSCSI data digest enable: hardware verifies data digest (CRC)
   ** when packet is iSCSI */
  EF_VI_ISCSI_RX_DDIG     = 0x8,
  /** Transmit iSCSI data digest enable: hardware calculates and inserts
   ** data digest (CRC) when packet is iSCSI */
  EF_VI_ISCSI_TX_DDIG     = 0x10,
  /** Use physically addressed TX descriptor ring */
  EF_VI_TX_PHYS_ADDR      = 0x20,
  /** Use physically addressed RX descriptor ring */
  EF_VI_RX_PHYS_ADDR      = 0x40,
  /** IP checksum calculation and replacement is disabled */
  EF_VI_TX_IP_CSUM_DIS    = 0x80,
  /** TCP/UDP checksum calculation and replacement is disabled */
  EF_VI_TX_TCPUDP_CSUM_DIS= 0x100,
  /** Drop transmit packets that are not TCP or UDP */
  EF_VI_TX_TCPUDP_ONLY    = 0x200,
  /** Drop packets with a mismatched IP source address
  ** (5000 and 6000 series only) */
  EF_VI_TX_FILTER_IP      = 0x400,              /* Siena only */
  /** Drop packets with a mismatched MAC source address
   ** (5000 and 6000 series only) */
  EF_VI_TX_FILTER_MAC     = 0x800,              /* Siena only */
  /** Set lowest bit of queue ID to 0 when matching within filter block
   ** (5000 and 6000 series only) */
  EF_VI_TX_FILTER_MASK_1  = 0x1000,             /* Siena only */
  /** Set lowest 2 bits of queue ID to 0 when matching within filter block
   ** (5000 and 6000 series only) */
  EF_VI_TX_FILTER_MASK_2  = 0x2000,             /* Siena only */
  /** Set lowest 3 bits of queue ID to 0 when matching within filter block
  ** (5000 and 6000 series only) */
  EF_VI_TX_FILTER_MASK_3  = (0x1000 | 0x2000),  /* Siena only */
  /** Disable using TX descriptor push, so always use doorbell for transmit */
  EF_VI_TX_PUSH_DISABLE   = 0x4000,
  /** Always use TX descriptor push, so never use doorbell for transmit
   ** (7000 series and newer) */
  EF_VI_TX_PUSH_ALWAYS    = 0x8000,             /* ef10 only */
  /** Add timestamp to received packets (7000 series and newer) */
  EF_VI_RX_TIMESTAMPS     = 0x10000,            /* ef10 only */
  /** Add timestamp to transmitted packets (7000 series and newer),
   ** cannot be combined with EF_VI_TX_ALT */
  EF_VI_TX_TIMESTAMPS     = 0x20000,            /* ef10 only */
  /* Flag EF_VI_TX_LOOPBACK (0x40000) has been removed. Similar
   * functionality can now be achieved with protection domain and
   * EF_PD_MCAST_LOOP flag.
   * Flag value 0x40000 is not to be reused. */
  /** Enable packed stream mode for received packets (7000 series and newer) */
  EF_VI_RX_PACKED_STREAM  = 0x80000,            /* ef10 only */
  /** Use 64KiB packed stream buffers, instead of the 1024KiB default (7000
   *  series and newer) */
  EF_VI_RX_PS_BUF_SIZE_64K = 0x100000,          /* ef10 only */
  /** Enable RX event merging mode for received packets;
   ** see ef_vi_receive_unbundle() and ef_vi_receive_get_bytes() for more
   ** details on using RX event merging mode */
  EF_VI_RX_EVENT_MERGE = 0x200000,          /* ef10 only */
  /** Enable the "TX alternatives" feature (8000 series and newer),
   ** cannot be combined with EF_VI_TX_TIMESTAMPS */
  EF_VI_TX_ALT             = 0x400000,
  /** Controls whether the hardware event timer is enabled (8000 series and
   ** newer) */
  EF_VI_ENABLE_EV_TIMER = 0x800000,
  /** Enable the "cut-through PIO" feature (X2000 series and newer). */
  EF_VI_TX_CTPIO           = 0x1000000,
  /** When using CTPIO, prevent poisoned frames from reaching the wire (X2000
   ** series and newer). */
  EF_VI_TX_CTPIO_NO_POISON = 0x2000000,
  /** Zerocopy - relevant for AF_XDP */
  EF_VI_RX_ZEROCOPY = 0x4000000,
  /** Support ef_vi_transmit_memcpy() (SN1000 series and newer). */
  EF_VI_ALLOW_MEMCPY = 0x8000000,
  /** DEPRECATED FLAG */
  EF_VI_EFCT_UNIQUEUE = 0x10000000,
  /** DEPRECATED FLAG */
  EF_VI_RX_EXCLUSIVE = 0x20000000,
};

/*! \brief Flags that can be returned when an ef_vi has been allocated */
enum ef_vi_out_flags {
  /** Clock sync status */
  EF_VI_OUT_CLOCK_SYNC_STATUS = 0x1,            /* ef10 only */
};


/*! \brief Flags that define which errors will cause either:
** - RX_DISCARD events; or
** - EF_EVENT_TYPE_RX_REF_DISCARD; or
** - reporting of errors in EF_EVENT_TYPE_RX_MULTI_PKTS events.
*/
enum ef_vi_rx_discard_err_flags {
  /** TCP or UDP checksum error */
  EF_VI_DISCARD_RX_L4_CSUM_ERR       = 0x1,
  /** IP checksum error */
  EF_VI_DISCARD_RX_L3_CSUM_ERR       = 0x2,
  /** Ethernet FCS error */
  EF_VI_DISCARD_RX_ETH_FCS_ERR       = 0x4,
  /** Ethernet frame length error */
  EF_VI_DISCARD_RX_ETH_LEN_ERR       = 0x8,
  /** DEPRECATED FLAG */
  EF_VI_DISCARD_RX_TOBE_DISC         = 0x10,
  /** Inner TCP or UDP checksum error */
  EF_VI_DISCARD_RX_INNER_L4_CSUM_ERR = 0x20,
  /** Inner IP checksum error */
  EF_VI_DISCARD_RX_INNER_L3_CSUM_ERR = 0x40,
  /** Error flags ending with OTHER are only supported on NIC
   ** architectures that support shared RXQs. Their purpose is 
   ** for scenarios where the layer N header is corrupt and the packet
   ** may not be successfully classed as that protocol, so may appear
   ** as LN_other instead. In this case any layer N checksum validation
   ** will not have been performed. By marking packets that are not the
   ** expected protocol as discards the application can ensure that it
   ** can distinguish correctly checksummed packets. For example,
   ** if an application is expecting only TCP or UDP packets,
   ** it can set EF_VI_DISCARD_RX_L4_CLASS_OTHER as part of the discard mask 
   ** (along with the various _ERR discard types), and anything that didn't 
   ** have its checksum validated, as it wasn't recognised as TCP or UDP, 
   ** will be marked as a discard. */
  /** Matches unrecognised ethernet frames or traffic containing more than 1 vlan tag. */
  EF_VI_DISCARD_RX_L2_CLASS_OTHER    = 0x80,
  /** Matches traffic that doesn't parse as IPv4 or IPv6. */
  EF_VI_DISCARD_RX_L3_CLASS_OTHER    = 0x100,
  /** Matches protocols other than TCP/UDP/fragmented traffic. */
  EF_VI_DISCARD_RX_L4_CLASS_OTHER    = 0x200
};


/*! \brief Timestamp formats supported by various cards. */
enum ef_timestamp_format {
        TS_FORMAT_SECONDS_27FRACTION = 0,
        TS_FORMAT_SECONDS_QTR_NANOSECONDS = 1
};


/**********************************************************************
 * ef_vi data structure ***********************************************
 **********************************************************************/

/*! \brief NIC architectures that are supported */
enum ef_vi_arch {
  /** 5000 and 6000-series NICs */
  EF_VI_ARCH_FALCON,
  /** 7000, 8000 and X2-series NICs */
  EF_VI_ARCH_EF10,
  /** SN1000-series NICs */
  EF_VI_ARCH_EF100,
  /** X3-series NICs (low latency persona) */
  EF_VI_ARCH_EFCT,
  /** Arbitrary NICs using AF_XDP */
  EF_VI_ARCH_AF_XDP,
};

/*! \brief State of TX descriptor ring
**
** Users should not access this structure.
*/
typedef struct {
  /** Previous slot that has been handled */
  uint32_t  previous;
  /** Descriptors added to the ring */
  uint32_t  added;
  /** Descriptors removed from the ring */
  uint32_t  removed;
  /** Bytes added to the cut-through FIFO */
  uint32_t  ct_added;
  /** Bytes removed from the cut-through FIFO */
  uint32_t  ct_removed;
  /** Timestamp in nanoseconds */
  uint32_t  ts_nsec;
} ef_vi_txq_state;

/*! \brief State of efct receive queue
**
** Users should not access this structure.
*/
typedef struct {
  /** Prior value of 'next', however without bit 31 abused (i.e. it's always
   * 0). Usually next-1, but not if there was a rollover. This is effectively
   * the pointer to the packet payload. */
  uint32_t prev;
  /** Combi-value of (sbseq << 32) | next.
   * 'next' is the next pkt_id, with bit 31 abused to contain the expected
   * sentinel of the pointed-to superbuf (this is duplicated info, but
   * improves locality). This is effectively the pointer to the packet
   * metadata
   * sbseq is the global sequence number of the current superbuf; used for
   * primes/wakeups.
   * The two disparate values are munged together so that they can be read
   * atomically in order to allow wakeups to be primed without holding a lock
   * on the VI. */
  uint64_t next;
} ef_vi_efct_rxq_ptr;

/*! \brief State of RX descriptor ring
**
** Users should not access this structure.
*/
typedef struct {
  /** Descriptors posted to the nic */
  uint32_t  posted;
  /** Descriptors added to the ring */
  uint32_t  added;
  /** Descriptors removed from the ring */
  uint32_t  removed;
  /** Packets received as part of a jumbo (7000-series only) */
  uint32_t  in_jumbo;                           /* ef10 only */
  /** Bytes received as part of a jumbo (7000-series only) */
  uint32_t  bytes_acc;                          /* ef10 only */
  /** Last descriptor index completed (7000-series only) */
  uint16_t  last_desc_i;                        /* ef10 only */
  /** Credit for packed stream handling (7000-series only) */
  uint16_t  rx_ps_credit_avail;                 /* ef10 only */
  ef_vi_efct_rxq_ptr rxq_ptr[EF_VI_MAX_EFCT_RXQS]; /* efct only */
  int16_t sb_desc_free_head[EF_VI_MAX_EFCT_RXQS]; /* efct only */
} ef_vi_rxq_state;

/*! \brief State of event queue
**
** Users should not access this structure.
*/
typedef struct {
  /** Event queue pointer */
  ef_eventq_ptr evq_ptr;
  /** For internal use only */
  int32_t       evq_clear_stride;
  /** Timestamp (major part) */
  uint32_t      sync_timestamp_major;
  /** Timestamp (minor part) */
  uint32_t      sync_timestamp_minor;
  /** Smallest possible seconds value for given sync_timestamp_major */
  uint32_t      sync_timestamp_minimum;
  /** Timestamp synchronized with adapter */
  uint32_t      sync_timestamp_synchronised; /* with adapter */
  /** Unsolicited credit sequence */
  uint32_t      unsol_credit_seq;
  /** Time synchronization flags */
  uint32_t      sync_flags;
} ef_eventq_state;

/*! \brief TX descriptor ring
**
** Users should not access this structure.
*/
typedef struct {
  /** Mask for indexes within ring, to wrap around */
  uint32_t         mask;
  /** Maximum space in the cut-through FIFO, reduced to account for header */
  uint32_t         ct_fifo_bytes;
  /** EFCT header bytes that do not usually change between packets */
  uint64_t         efct_fixed_header;
  /** Pointer to descriptors */
  void*            descriptors;
  /** Pointer to IDs */
  uint32_t*        ids;
} ef_vi_txq;

/*! \brief RX descriptor ring
**
** Users should not access this structure.
*/
typedef struct {
  /** Mask for indexes within ring, to wrap around */
  uint32_t         mask;
  /** Pointer to descriptors */
  void*            descriptors;
  /** Pointer to IDs */
  uint32_t*        ids;
} ef_vi_rxq;

typedef int ef_vi_efct_superbuf_refresh_t(struct ef_vi*, int);

/*! \brief EFCT RX buffer memory and metadata
**
** Users should not access this structure.
*/
typedef struct {
  unsigned resource_id;
#ifdef __KERNEL__
  /** array of CI_EFCT_MAX_SUPERBUFS elements */
  const char** superbufs;
#else
  /** contiguous area of superbuf memory */
  const char* superbuf;
  uint64_t* current_mappings;
#endif
  uint32_t config_generation;
  ef_vi_efct_superbuf_refresh_t* refresh_func;
} ef_vi_efct_rxq;

/*! \brief State of a virtual interface
**
** Users should not access this structure.
*/
typedef struct {
  /** Event queue state */
  ef_eventq_state evq;
  /** TX descriptor ring state */
  ef_vi_txq_state txq;
  /** RX descriptor ring state */
  ef_vi_rxq_state rxq;
  /* Followed by request id fifos. */
} ef_vi_state;

/*! \brief Statistics for a virtual interface
**
** Users should not access this structure.
*/
typedef struct {
  /** RX events lost */
  uint32_t rx_ev_lost;
  /** RX events with a bad descriptor */
  uint32_t rx_ev_bad_desc_i;
  /** RX events with a bad queue label */
  uint32_t rx_ev_bad_q_label;
  /** Gaps in the event queue (empty slot followed by event) */
  uint32_t evq_gap;
} ef_vi_stats;

/*! \brief The type of NIC in use
**
** Users should not access this structure.
*/
struct ef_vi_nic_type {
  /** Architecture of the NIC */
  unsigned char  arch;
  /** Variant of the NIC */
  char           variant;
  /** Revision of the NIC */
  unsigned char  revision;
  /** Flags indicating hardware features */
  unsigned char  nic_flags;
};

/*! \brief Per-packet overhead information
**
** This structure is used by ef_vi_transmit_alt_usage() to calculate
** the amount of buffering needed to store a packet. It should be
** filled in by ef_vi_transmit_alt_query_overhead() or similar. Its
** members are not intended to be meaningful to the application and
** should not be obtained or interpreted in any other way.
*/
struct ef_vi_transmit_alt_overhead {
  /** Bytes to add before rounding */
  uint32_t pre_round;
  /** Rounding mask */
  uint32_t mask;
  /** Bytes to add after rounding */
  uint32_t post_round;
};


struct ef_pio;


/*! \brief Flags that can be passed to ef_vi_transmitv_init_extra()
**  via the 'struct ef_vi_tx_extra' structure.
*/
enum ef_vi_tx_extra_flags {
  /** Enable use of the mark field. */
  EF_VI_TX_EXTRA_MARK = 0x1,
  /** True to enable use of the ingress_mport field. */
  EF_VI_TX_EXTRA_INGRESS_MPORT = 0x2,
  /** True to enable use of the egress_mport field. */
  EF_VI_TX_EXTRA_EGRESS_MPORT = 0x4,
  /** Capsule metadata is present as prefix to frame data. */
  EF_VI_TX_EXTRA_CAPSULE_METADATA = 0x8,
};

/*! \brief TX extra options */
struct ef_vi_tx_extra {
  /** Flags indicating which options to apply. */
  enum ef_vi_tx_extra_flags flags;
  /** Packet mark value. */
  uint32_t mark;
  /** Port used to enter virtual switch. */
  uint16_t ingress_mport;
  /** Port used to leave virtual switch. */
  uint16_t egress_mport;
};

/*! \brief A virtual interface.
**
** An ef_vi represents a virtual interface on a specific NIC.  A virtual
** interface is a collection of an event queue and two DMA queues used to
** pass Ethernet frames between the transport implementation and the
** network.
**
** Users should not access this structure.
*/
typedef struct ef_vi {
  /** True if the virtual interface has been initialized */
  unsigned                      inited;
  /** The resource ID of the virtual interface */
  unsigned                      vi_resource_id;
  /** The instance ID of the virtual interface */
  unsigned                      vi_i;
  /** NIC-global ID of this virtual interface, or -1 */
  unsigned                      abs_idx;
  /** fd used for original initialisation */
  ef_driver_handle              dh;

  /** The length of a receive buffer */
  unsigned                      rx_buffer_len;
  /** The length of the prefix at the start of a received packet */
  unsigned                      rx_prefix_len;
  /** efct: The last call to transmit_ctpio didn't have space; remember this
   * for the call to ctpio_fallback */
  uint8_t                       last_ctpio_failed;
  /** The mask to select which errors cause a discard event */
  uint64_t                      rx_discard_mask;
  /** The timestamp correction (ticks) for received packets */
  int                           rx_ts_correction;
  /** The offset to packet length in receive buffer */
  unsigned                      rx_pkt_len_offset;
  /** The mask of packet length in receive buffer */
  unsigned                      rx_pkt_len_mask;
  /** The timestamp correction (ns) for transmitted packets */
  int                           tx_ts_correction_ns;
  /** The timestamp format used by the hardware */
  enum ef_timestamp_format      ts_format;
  /** Pointer to virtual interface memory */
  char*                         vi_mem_mmap_ptr;
  /** Length of virtual interface memory */
  int                           vi_mem_mmap_bytes;
  /** Pointer to virtual interface I/O region */
  char*                         vi_io_mmap_ptr;
  /** Length of virtual interface I/O region */
  int                           vi_io_mmap_bytes;
  /** Pointer to CTPIO region */
  char*                         vi_ctpio_mmap_ptr;
  /** Controls rate of writes into CTPIO aperture */
  uint32_t                      vi_ctpio_wb_ticks;
  /** Length of region allocated at ep_state */
  int                           ep_state_bytes;
  /** True if the virtual interface is in a cluster */
  int                           vi_clustered;
  /** True if packed stream mode is enabled for the virtual interface */
  int                           vi_is_packed_stream;
  /** True if no special mode is enabled for the virtual interface */
  int                           vi_is_normal;
  /** The packed stream buffer size for the virtual interface */
  unsigned                      vi_ps_buf_size;

  /** I/O address for the virtual interface */
  ef_vi_ioaddr_t                io;

  /** Programmed I/O region linked to the virtual interface */
  struct ef_pio*                linked_pio;

  /** Base of the event queue for the virtual interface */
  char*                         evq_base;
  /** Mask for offsets within the event queue for the virtual interface */
  unsigned                      evq_mask;
  /** True if the event queue uses phase bits */
  int                           evq_phase_bits;
  /** The timer quantum for the virtual interface, in nanoseconds */
  unsigned                      timer_quantum_ns;

  /** The threshold at which to switch from using TX descriptor push to
  ** using a doorbell */
  unsigned                      tx_push_thresh;

  /** The TX descriptor ring for the virtual interface */
  ef_vi_txq                     vi_txq;
  /** The RX descriptor ring for the virtual interface */
  ef_vi_rxq                     vi_rxq;
  /** The state of the virtual interface */
  ef_vi_state*                  ep_state;
  /** The flags for the virtual interface */
  enum ef_vi_flags              vi_flags;
  /** Flags returned when the virtual interface is allocated */
  enum ef_vi_out_flags          vi_out_flags;
  /** Statistics for the virtual interface */
  ef_vi_stats*                  vi_stats;

  /** Virtual queues for the virtual interface */
  struct ef_vi*                 vi_qs[EF_VI_MAX_QS];
  /** Number of virtual queues for the virtual interface */
  int                           vi_qs_n;
  /** Id of queue a pending PFTF packet belongs to */
  uint8_t                       future_qid;
  /** Attached rxqs for efct VIs (NB: not necessarily in rxq order) */
  ef_vi_efct_rxq                efct_rxq[EF_VI_MAX_EFCT_RXQS];
  /** efct kernel/userspace shared queue area. */
  struct efab_efct_rxq_uk_shm_base* efct_shm;
  /** 1 + highest allowed index of a used element in efct_rxq */
  int                           max_efct_rxq;

  /** Number of TX alternatives for the virtual interface */
  unsigned                      tx_alt_num;
  /** Mapping from end-user TX alternative IDs to hardware IDs  */
  unsigned*                     tx_alt_id2hw;
  /** Mapping from hardware TX alternative IDs to end-user IDs  */
  unsigned*                     tx_alt_hw2id;

  /** The type of NIC hosting the virtual interface */
  struct ef_vi_nic_type	        nic_type;

  /** Callback to invoke AF_XDP send operations */
  int                         (*xdp_kick)(struct ef_vi*);
  void*                         xdp_kick_context;

  /*! \brief Driver-dependent operations. */
  /* Doxygen comment above is the detailed description of ef_vi::ops */
  struct ops {
    /** Transmit a packet from a single packet buffer */
    int (*transmit)(struct ef_vi*, ef_addr base, int len,
                    ef_request_id);
    /** Transmit a packet from a vector of packet buffers */
    int (*transmitv)(struct ef_vi*, const ef_iovec*, int iov_len,
                     ef_request_id);
    /** Initialize TX descriptors on the TX descriptor ring, for a vector
    **  of packet buffers */
    int (*transmitv_init)(struct ef_vi*, const ef_iovec*,
                          int iov_len, ef_request_id);
    /** Submit newly initialized TX descriptors to the NIC */
    void (*transmit_push)(struct ef_vi*);
    /** Transmit a packet already resident in Programmed I/O */
    int (*transmit_pio)(struct ef_vi*, int offset, int len,
                        ef_request_id dma_id);
    /** Copy a packet to Programmed I/O region and transmit it */
    int (*transmit_copy_pio)(struct ef_vi*, int pio_offset,
                             const void* src_buf, int len,
                             ef_request_id dma_id);
    /** Warm Programmed I/O transmit path for subsequent transmit */
    void (*transmit_pio_warm)(struct ef_vi*);
    /** Copy a packet to Programmed I/O region and warm transmit path */
    void (*transmit_copy_pio_warm)(struct ef_vi*, int pio_offset,
                                   const void* src_buf, int len);
    /** Transmit a vector of packet buffers using CTPIO */
    void (*transmitv_ctpio)(struct ef_vi*, size_t frame_len,
                            const struct iovec* iov,
                            int iov_len, unsigned threshold);
    /** Transmit a vector of packet buffers using CTPIO and copy to fallback */
    void (*transmitv_ctpio_copy)(struct ef_vi*, size_t frame_len,
                                 const struct iovec* iov,
                                 int iov_len, unsigned threshold,
                                 void* fallback);
    /** Select a TX alternative as the destination for future sends */
    int (*transmit_alt_select)(struct ef_vi*, unsigned alt_id);
    /** Select the "normal" data path as the destination for future sends */
    int (*transmit_alt_select_default)(struct ef_vi*);
    /** Transition a TX alternative to the STOP state */
    int (*transmit_alt_stop)(struct ef_vi*, unsigned alt_id);
    /** Transition a TX alternative to the GO state */
    int (*transmit_alt_go)(struct ef_vi*, unsigned alt_id);
    /** Specify vi_discard behaviour */
    int (*receive_set_discards)(struct ef_vi* vi, unsigned discard_err_flags);
    /** Retrieve vi_discard behaviour */
    uint64_t (*receive_get_discards)(struct ef_vi* vi);
    /** Transition a TX alternative to the DISCARD state */
    int (*transmit_alt_discard)(struct ef_vi*, unsigned alt_id);
    /** Initialize an RX descriptor on the RX descriptor ring */
    int (*receive_init)(struct ef_vi*, ef_addr, ef_request_id);
    /** Submit newly initialized RX descriptors to the NIC */
    void (*receive_push)(struct ef_vi*);
    /** Poll an event queue */
    int (*eventq_poll)(struct ef_vi*, ef_event*, int evs_len);
    /** Prime a virtual interface allowing you to go to sleep blocking on it */
    void (*eventq_prime)(struct ef_vi*);
    /** Prime an event queue timer with a new timeout */
    void (*eventq_timer_prime)(struct ef_vi*, unsigned v);
    /** Start an event queue timer running */
    void (*eventq_timer_run)(struct ef_vi*, unsigned v);
    /** Stop an event-queue timer */
    void (*eventq_timer_clear)(struct ef_vi*);
    /** Prime an event queue timer to expire immediately */
    void (*eventq_timer_zero)(struct ef_vi*);
    /** Initialize TX descriptors on the TX descriptor ring, using
     * extra options and (optionally) remote buffers */
    int (*transmitv_init_extra)(struct ef_vi*, const struct ef_vi_tx_extra*,
                                const ef_remote_iovec*, int iov_len,
                                ef_request_id);
    ssize_t (*transmit_memcpy)(struct ef_vi*, const ef_remote_iovec* dst_iov,
                               int dst_iov_len, const ef_remote_iovec* src_iov,
                               int src_iov_len);
    int (*transmit_memcpy_sync)(struct ef_vi*, ef_request_id dma_id);
    int (*transmit_ctpio_fallback)(struct ef_vi* vi, ef_addr dma_addr,
                                   size_t len, ef_request_id dma_id);
    int (*transmitv_ctpio_fallback)(struct ef_vi* vi, const ef_iovec* dma_iov,
                                    int dma_iov_len, ef_request_id dma_id);
  } ops;  /**< Driver-dependent operations. */
  /* Doxygen comment above is documentation for the ops member of ef_vi */

  /*! \brief Driver-dependent operations not corresponding to a public API. */
  /** The difference between this and ops is purely documentational. Functions
   * here may be NULL if the driver doesn't need the feature. */
  struct internal_ops {
    /** A filter has just been added to the given VI */
    int (*post_filter_add)(struct ef_vi*, const struct ef_filter_spec* fs,
                           const struct ef_filter_cookie* cookie, int rxq);
  } internal_ops;
} ef_vi;


/*! \brief Return the resource ID of the virtual interface
**
** \param vi The virtual interface to query.
**
** \return The resource ID of the virtual interface.
**
** Return the resource ID of the virtual interface.
*/
ef_vi_inline unsigned ef_vi_resource_id(ef_vi* vi)
{
  return vi->vi_resource_id;
}


/*! \brief Return the flags of the virtual interface
**
** \param vi The virtual interface to query.
**
** \return The flags of the virtual interface.
**
** Return the flags of the virtual interface.
*/
ef_vi_inline enum ef_vi_flags ef_vi_flags(ef_vi* vi)
{
  return vi->vi_flags;
}



/*! \brief Return the instance ID of the virtual interface
**
** \param vi The virtual interface to query.
**
** \return The instance ID of the virtual interface.
**
** Return the instance ID of the virtual interface.
*/
ef_vi_inline unsigned ef_vi_instance(ef_vi* vi)
{
  return vi->vi_i;
}


/*! \brief Return a string that identifies the version of ef_vi
**
** \return A string that identifies the version of ef_vi.
**
** Return a string that identifies the version of ef_vi. This should be
** treated as an unstructured string. At time of writing it is the version
** of OpenOnload or EnterpriseOnload in which ef_vi is distributed.
**
** Note that Onload will check this is a version that it recognizes. It
** recognizes the version strings generated by itself, and those generated
** by older official releases of Onload (when the API hasn't changed), but
** not those generated by older patched releases of Onload. Consequently,
** ef_vi applications built against patched versions of Onload will not be
** supported by future versions of Onload.
*/
extern const char* ef_vi_version_str(void);


/*! \brief Returns a string that identifies the char driver interface
**         required
**
** \return A string that identifies the char driver interface required by
**         this build of ef_vi.
**
** Returns a string that identifies the char driver interface required by
** this build of ef_vi.
**
** Returns the current version of the drivers that are running - useful to
** check that it is new enough.
*/
extern const char* ef_vi_driver_interface_str(void);


/**********************************************************************
 * Receive interface **************************************************
 **********************************************************************/

/*! \brief Returns the length of the prefix at the start of a received
**         packet
**
** \param vi The virtual interface to query.
**
** \return The length of the prefix at the start of a received packet.
**
** Returns the length of the prefix at the start of a received packet.
**
** The NIC may be configured to deliver meta-data in a prefix before the
** packet payload data. This call returns the size of the prefix.
**
** When a large packet is received that is scattered over multiple packet
** buffers, the prefix is only present in the first buffer.
*/
ef_vi_inline int ef_vi_receive_prefix_len(const ef_vi* vi)
{
  return vi->rx_prefix_len;
}


/*! \brief Returns the length of a receive buffer
**
** \param vi The virtual interface to query.
**
** \return The length of a receive buffer.
**
** Returns the length of a receive buffer.
**
** When a packet arrives that does not fit within a single receive buffer,
** it is spread over multiple buffers.
**
** The application must ensure that receive buffers are at least as large
** as the value returned by this function, else there is a risk that a DMA
** may overrun the buffer. This must include room for the prefix as returned
** by ef_vi_receive_prefix_len().
**
** For AF_XDP, this is the total chunk size, including any user metadata stored
** before the packet data. The prefix length indicates the offset of the packet
** data.
*/
ef_vi_inline int ef_vi_receive_buffer_len(const ef_vi* vi)
{
  return vi->rx_buffer_len;
}


/*! \brief Sets the length of receive buffers.
**
** \param vi      The virtual interface for which to set the length of
**                receive buffers.
** \param buf_len The length of receive buffers.
**
** Sets the length of receive buffers for this VI. The new length is used
** for subsequent calls to ef_vi_receive_init() and ef_vi_receive_post().
**
** This call has no effect for 5000 and 6000-series (Falcon) adapters.
**
** For AF_XDP, this must be called before registering user memory with the VI,
** and will have no effect if called later.
*/
ef_vi_inline void ef_vi_receive_set_buffer_len(ef_vi* vi, unsigned buf_len)
{
  vi->rx_buffer_len = buf_len;
}


/*! \brief Returns the amount of free space in the RX descriptor ring.
**
** \param vi The virtual interface to query.
**
** \return The amount of free space in the RX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the amount of free space in the RX descriptor ring. This is the
** number of slots that are available for pushing a new descriptor (and an
** associated unfilled packet buffer).
*/
ef_vi_inline int ef_vi_receive_space(const ef_vi* vi)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  return vi->vi_rxq.mask - (qs->added - qs->removed);
}


/*! \brief Returns the fill level of the RX descriptor ring
**
** \param vi The virtual interface to query.
**
** \return The fill level of the RX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the fill level of the RX descriptor ring. This is the number of
** slots that hold a descriptor (and an associated packet buffer).
** The fill level should be kept as high as possible, so there are enough
** slots available to handle a burst of incoming packets.
*/
ef_vi_inline int ef_vi_receive_fill_level(const ef_vi* vi)
{
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  return qs->added - qs->removed;
}


/*! \brief Returns the total capacity of the RX descriptor ring
**
** \param vi The virtual interface to query.
**
** \return The total capacity of the RX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the total capacity of the RX descriptor ring.
*/
ef_vi_inline int ef_vi_receive_capacity(const ef_vi* vi)
{
  return vi->vi_rxq.mask;
}


/*! \brief Initialize an RX descriptor on the RX descriptor ring
**
** \param vi     The virtual interface for which to initialize an RX
**               descriptor.
** \param addr   DMA address of the packet buffer to associate with the
**               descriptor, as obtained from ef_memreg_dma_addr().
** \param dma_id DMA id to associate with the descriptor. This is
**               completely arbitrary, and can be used for subsequent
**               tracking of buffers.
**
** \return 0 on success, or a negative error code.
**
** Initialize an RX descriptor on the RX descriptor ring, and prepare the
** associated packet buffer (identified by its DMA address) to receive
** packets. This function only writes a few bytes into host memory, and is
** very fast.
*/
#define ef_vi_receive_init(vi, addr, dma_id)            \
  (vi)->ops.receive_init((vi), (addr), (dma_id))


/*! \brief Submit newly initialized RX descriptors to the NIC
**
** \param vi The virtual interface for which to push descriptors.
**
** \return None.
**
** Submit newly initialized RX descriptors to the NIC. The NIC can then
** receive packets into the associated packet buffers.
**
** For Solarflare 7000-series NICs, this function submits RX descriptors
** only in multiples of 8. This is to conform with hardware requirements.
** If the number of newly initialized RX descriptors is not exactly
** divisible by 8, this function does not submit any remaining descriptors
** (up to 7 of them).
*/
#define ef_vi_receive_push(vi) (vi)->ops.receive_push((vi))


/*! \brief Initialize an RX descriptor on the RX descriptor ring, and
**         submit it to the NIC
**
** \param vi     The virtual interface for which to initialize and push an
**               RX descriptor.
** \param addr   DMA address of the packet buffer to associate with the
**               descriptor, as obtained from ef_memreg_dma_addr().
** \param dma_id DMA id to associate with the descriptor. This is
**               completely arbitrary, and can be used for subsequent
**               tracking of buffers.
**
** \return 0 on success, or a negative error code.
**
** Initialize an RX descriptor on the RX descriptor ring, and submit it to
** the NIC. The NIC can then receive a packet into the associated packet
** buffer.
**
** This function simply wraps ef_vi_receive_init() and
** ef_vi_receive_push(). It is provided as a convenience, but is less
** efficient than submitting the descriptors in batches by calling the
** functions separately.
**
** Note that for Solarflare 7000-series NICs, this function submits RX
** descriptors only in multiples of 8. This is to conform with hardware
** requirements. If the number of newly initialized RX descriptors is not
** exactly divisible by 8, this function does not submit any remaining
** descriptors (including, potentially, the RX descriptor initialized in
** this call).
*/
extern int ef_vi_receive_post(ef_vi* vi, ef_addr addr, ef_request_id dma_id);


/*! \brief _Deprecated:_ use ef_vi_receive_get_timestamp_with_sync_flags()
** instead.
**
** \param vi     The virtual interface that received the packet.
** \param pkt    The received packet.
** \param ts_out Pointer to a timespec, that is updated on return with the
**               UTC timestamp for the packet.
**
** \return 0 on success, or a negative error code.
**
** _This function is now deprecated._ Use
** ef_vi_receive_get_timestamp_with_sync_flags() instead.
**
** Retrieve the UTC timestamp associated with a received packet.
**
** This function must be called after retrieving the associated RX event
** via ef_eventq_poll(), and before calling ef_eventq_poll() again.
**
** If the virtual interface does not have RX timestamps enabled, the
** behavior of this function is undefined.
**
** Note: ef_eventq_poll(), efct_vi_rx_future_poll() and efct_vi_rx_future_peek()
**       invalidate timestamps retrieved by previous poll function.
*/
extern int ef_vi_receive_get_timestamp(ef_vi* vi, const void* pkt,
                                       ef_timespec* ts_out);


/*! \brief Retrieve the UTC timestamp associated with a received packet,
**         and the clock sync status flags
**
** \param vi        The virtual interface that received the packet.
** \param pkt       The first packet buffer for the received packet.
** \param ts_out    Pointer to a timespec, that is updated on return with
**                  the UTC timestamp for the packet.
** \param flags_out Pointer to an unsigned, that is updated on return with
**                  the sync flags for the packet.
**
** \return 0 on success, or a negative error code:\n
**         - ENOMSG - Synchronization with adapter has not yet been
**           achieved.\n
**           This only happens with old firmware.\n
**         - ENODATA - Packet does not have a timestamp.\n
**           On current Solarflare adapters, packets that are switched from
**           TX to RX do not get timestamped.\n
**         - EL2NSYNC - Synchronization with adapter has been lost.\n
**           This should never happen!
**
** Retrieve the UTC timestamp associated with a received packet, and the
** clock sync status flags.
**
** This function:
** - must be called after retrieving the associated RX event via
**   ef_eventq_poll(), and before calling ef_eventq_poll() again
** - must only be called for the first segment of a jumbo packet
** - must not be called for any events other than RX.
**
** If the virtual interface does not have RX timestamps enabled, the
** behavior of this function is undefined.
**
** This function will also fail if the virtual interface has not yet
** synchronized with the adapter clock. This can take from a few hundred
** milliseconds up to several seconds from when the virtual interface is
** allocated.
**
** On success the ts_out and flags_out fields are updated, and a value of
** zero is returned. The flags_out field contains the following flags:
** - EF_VI_SYNC_FLAG_CLOCK_SET is set if the adapter clock has ever been
**   set (in sync with system)
** - EF_VI_SYNC_FLAG_CLOCK_IN_SYNC is set if the adapter clock is in sync
**   with the external clock (PTP).
**
** In case of error the timestamp result (*ts_out) is set to zero, and a
** non-zero error code is returned (see Return value above).
*/
extern int
ef_vi_receive_get_timestamp_with_sync_flags(ef_vi* vi, const void* pkt,
                                            ef_timespec* ts_out,
                                            unsigned* flags_out);


/*! \brief Retrieve the number of bytes in a received packet in RX event
**         merge mode
**
** \param vi        The virtual interface that received the packet.
** \param pkt       The first packet buffer for the received packet.
** \param bytes_out Pointer to a uint16_t, that is updated on return with the
**                  number of bytes in the packet.
**
** Note that this function returns the number of bytes in a received packet,
** not received into a single buffer, ie it must only be called for the first
** buffer in a packet.  For jumbos it will return the full length of the jumbo.
** Buffers prior to the last buffer in the packet will be filled completely.
**
** The length does not include the length of the packet prefix.
**
** \return 0 on success, or a negative error code
*/
extern int
ef_vi_receive_get_bytes(ef_vi* vi, const void* pkt, uint16_t* bytes_out);


/*! \brief Retrieve the user_mark and user_flag fields in a received packet
**
** \param vi        The virtual interface that received the packet.
** \param pkt       The first packet buffer for the received packet.
** \param user_mark On return, set to the 32-bit value assigned by the NIC
** \param user_flag On return, set to the 1-bit value assigned by the NIC
**
** These fields are available on SN1000-series and later adapters, and only
** when using the full rx prefix. Use of this function in other configurations
** will return nonsense data, or assert in a debug build.
**
** The value of the mark and flag may be set by filter rules assigned to the
** VI or by datapath extensions (see ef_extension_open()).
**
** \return 0 on success, or a negative error code
*/
extern int
ef_vi_receive_get_user_data(ef_vi* vi, const void* pkt, uint32_t* user_mark,
                            uint8_t* user_flag);


/*! \brief Maximum number of receive completions per receive event. */
#define EF_VI_RECEIVE_BATCH 15


/*! \brief Unbundle an event of type EF_EVENT_TYPE_RX_MULTI or
**         EF_EVENT_TYPE_RX_MULTI_DISCARD
**
** \param ep    The virtual interface that has raised the event.
** \param event The event, of type EF_EVENT_TYPE_RX_MULTI or
**              EF_EVENT_TYPE_RX_MULTI_DISCARD.
** \param ids   Array of size EF_VI_RECEIVE_BATCH, that is updated on return
**              with the DMA ids that were used in the original
**              ef_vi_receive_init() call.
**
** \return The number of valid ef_request_ids (can be zero).
**
** Unbundle an event of type EF_EVENT_TYPE_RX_MULTI or
** EF_EVENT_TYPE_RX_MULTI_DISCARD.
**
** In RX event merge mode the NIC will coalesce multiple packet receptions
** into a single RX event.  This reduces PCIe load, enabling higher potential
** throughput at the cost of latency.
**
** This function returns the number of descriptors whose reception has
** completed, and updates the ids array with the ef_request_ids for each
** completed DMA request.
**
** After calling this function, the RX descriptors for the completed RX event
** are ready to be re-used.
**
** In order to determine the length of each packet ef_vi_receive_get_bytes()
** must be called, or the length examined in the packet prefix (see
** ef_vi_receive_query_layout()).
*/
extern int ef_vi_receive_unbundle(ef_vi* ep, const ef_event* event,
                                  ef_request_id* ids);

extern ef_request_id ef_vi_rxq_next_desc_id(ef_vi* vi);


/*! \brief Set which errors cause an EF_EVENT_TYPE_RX_DISCARD event
**
** \param vi                The virtual interface to configure.
** \param discard_err_flags Flags which indicate which errors will cause
**                          discard events
**
** \return 0 on success, or a negative error code.
**
** Set which errors cause an EF_EVENT_TYPE_RX_DISCARD event. Not all flags
** are supported on all NIC versions. To query which flags have been set
** successfully use the ef_vi_receive_get_discards() function.
*/
#define ef_vi_receive_set_discards(vi, discard_err_flags)          \
  (vi)->ops.receive_set_discards((vi), discard_err_flags)

/*! \brief Retrieve which errors cause an EF_EVENT_TYPE_RX_[REF_]DISCARD event
**
** \param vi                The virtual interface to query.
**
** \return mask of set ef_vi_rx_discard_err_flags
**
** Retrieve which errors cause an EF_EVENT_TYPE_RX_[REF_]DISCARD event
*/
#define ef_vi_receive_get_discards(vi)          \
  (vi)->ops.receive_get_discards((vi))

/**********************************************************************
 * Transmit interface *************************************************
 **********************************************************************/

/*! \brief Returns the amount of free space in the TX descriptor ring.
**
** \param vi The virtual interface to query.
**
** \return The amount of free space in the TX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the amount of free space in the TX descriptor ring. This is the
** number of slots that are available for pushing a new descriptor (and an
** associated filled packet buffer).
*/
ef_vi_inline int ef_vi_transmit_space(const ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  return vi->vi_txq.mask - (qs->added - qs->removed);
}


/*! \brief Returns the fill level of the TX descriptor ring
**
** \param vi The virtual interface to query.
**
** \return The fill level of the TX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the fill level of the TX descriptor ring. This is the number of
** slots that hold a descriptor (and an associated filled packet buffer).
** The fill level should be low or 0, unless a large number of packets have
** recently been posted for transmission. A consistently high fill level
** should be investigated.
*/
ef_vi_inline int ef_vi_transmit_fill_level(const ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  return qs->added - qs->removed;
}


/*! \brief Returns the amount of free space in the TX cut-through FIFO
**
** \param vi The virtual interface to query.
**
** \return The amount of free space in the TX cut-through FIFO, in bytes
**
** For architectures with a TX FIFO, returns the the space available for the
** next packet. The function accounts for any extra overhead required by the
** architecture (e.g. headers), so the value returned is the maximum number of
** payload bytes that can be sent in a single packet.
**
** To simplify the calculation, the value can be negative if the FIFO is full.
**
** For architectures without a TX FIFO, returns a large value to indicate that
** there is no limit on the number of bytes which may be sent.
*/
ef_vi_inline int ef_vi_transmit_space_bytes(const ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  return vi->vi_txq.ct_fifo_bytes - (qs->ct_added - qs->ct_removed);
}


/*! \brief Returns the fill level of the TX cut-through FIFO
**
** \param vi The virtual interface to query.
**
** \return The fill level of the TX cut-through FIFO, in bytes
*/
ef_vi_inline int ef_vi_transmit_fill_level_bytes(const ef_vi* vi)
{
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  return qs->ct_added - qs->ct_removed;
}


/*! \brief Returns the total capacity of the TX descriptor ring
**
** \param vi The virtual interface to query.
**
** \return The total capacity of the TX descriptor ring, as slots for
**         descriptor entries.
**
** Returns the total capacity of the TX descriptor ring.
*/
ef_vi_inline int ef_vi_transmit_capacity(const ef_vi* vi)
{
  return vi->vi_txq.mask;
}


/*! \brief Initialize a TX descriptor on the TX descriptor ring, for a
**         single packet buffer
**
** \param vi     The virtual interface for which to initialize a TX
**               descriptor.
** \param addr   DMA address of the packet buffer to associate with the
**               descriptor, as obtained from ef_memreg_dma_addr().
** \param bytes  The size of the packet to transmit.
** \param dma_id DMA id to associate with the descriptor. This is
**               completely arbitrary, and can be used for subsequent
**               tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Initialize a TX descriptor on the TX descriptor ring, for a single
** packet buffer. The associated packet buffer (identified by its DMA
** address) must contain the packet to transmit. This function only writes
** a few bytes into host memory, and is very fast.
*/
extern int ef_vi_transmit_init(ef_vi* vi, ef_addr addr, int bytes,
                               ef_request_id dma_id);


/*! \brief Initialize TX descriptors on the TX descriptor ring, for a
**         vector of packet buffers
**
** \param vi      The virtual interface for which to initialize a TX
**                descriptor.
** \param iov     Start of the iovec array describing the packet buffers.
** \param iov_len Length of the iovec array.
** \param dma_id  DMA id to associate with the descriptor. This is
**                completely arbitrary, and can be used for subsequent
**                tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Initialize TX descriptors on the TX descriptor ring, for a vector of
** packet buffers. The associated packet buffers (identified in the iov
** vector) must contain the packet to transmit. This function only writes a
** few bytes into host memory, and is very fast.
**
** Building a packet by concatenating a vector of buffers allows:
** - sending a packet that is larger than a packet buffer
**   - the packet is split across multiple buffers in a vector
** - optimizing sending packets with only small differences:
**   - the packet is split into those parts that are constant, and those
**     that vary between transmits
**   - each part is written into its own buffer
**   - after each transmit, the buffers containing varying data must be
**     updated, but the buffers containing constant data are re-used
**   - this minimizes the amount of data written between transmits.
*/
#define ef_vi_transmitv_init(vi, iov, iov_len, dma_id)          \
  (vi)->ops.transmitv_init((vi), (iov), (iov_len), (dma_id))

/*! \brief Initialize TX descriptors on the TX descriptor ring, with
**         extra options and a vector of optionally remote packet
**         buffers
**
** \param extra Pointer to extra options to apply to this packet.
**              May be NULL.
**
** Refer to ef_vi_transmitv_init() for details.
**
** Note that the first iovec in the array must be in the local address
** space (EF_ADDRSPACE_LOCAL) and cannot be translated; this is a
** limitation of the hardware. It can, however, be zero length.
*/
#define ef_vi_transmitv_init_extra(vi, extra, iov, iov_len, dma_id)     \
  (vi)->ops.transmitv_init_extra((vi), (extra), (iov),                  \
                                 (iov_len), (dma_id))

/*! \brief Submit newly initialized TX descriptors to the NIC
**
** \param vi The virtual interface for which to push descriptors.
**
** \return None.
**
** Submit newly initialized TX descriptors to the NIC. The NIC can then
** transmit packets from the associated packet buffers.
**
** New TX descriptors must have been initialized using ef_vi_transmit_init()
** or ef_vi_transmitv_init() before calling this function, and so in particular
** it is not legal to call this function more than once without initializing
** new descriptors in between those calls.
*/
#define ef_vi_transmit_push(vi) (vi)->ops.transmit_push((vi))


/*! \brief Transmit a packet from a single packet buffer
**
** \param vi     The virtual interface for which to initialize and push a
**               TX descriptor.
** \param base   DMA address of the packet buffer to associate with the
**               descriptor, as obtained from ef_memreg_dma_addr().
** \param len    The size of the packet to transmit.
** \param dma_id DMA id to associate with the descriptor. This is
**               completely arbitrary, and can be used for subsequent
**               tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Transmit a packet from a single packet buffer. This Initializes a TX
** descriptor on the TX descriptor ring, and submits it to the NIC. The NIC
** can then transmit a packet from the associated packet buffer.
**
** This function simply wraps ef_vi_transmit_init() and
** ef_vi_transmit_push(). It is provided as a convenience. It is less
** efficient than submitting the descriptors in batches by calling the
** functions separately, but unless there is a batch of packets to
** transmit, calling this function is often the right thing to do.
*/
#define ef_vi_transmit(vi, base, len, dma_id)           \
  (vi)->ops.transmit((vi), (base), (len), (dma_id))


/*! \brief Transmit a packet from a vector of packet buffers
**
** \param vi      The virtual interface for which to initialize a TX
**                descriptor.
** \param iov     Start of the iovec array describing the packet buffers.
** \param iov_len Length of the iovec array.
** \param dma_id  DMA id to associate with the descriptor. This is
**                completely arbitrary, and can be used for subsequent
**                tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Transmit a packet from a vector of packet buffers. This initializes a TX
** descriptor on the TX descriptor ring, and submits it to the NIC. The NIC
** can then transmit a packet from the associated packet buffers.
**
** This function simply wraps ef_vi_transmitv_init() and
** ef_vi_transmit_push(). It is provided as a convenience. It is less
** efficient than submitting the descriptors in batches by calling the
** functions separately, but unless there is a batch of packets to
** transmit, calling this function is often the right thing to do.
**
** Building a packet by concatenating a vector of buffers allows:
** - sending a packet that is larger than a packet buffer
**   - the packet is split across multiple buffers in a vector
** - optimizing sending packets with only small differences:
**   - the packet is split into those parts that are constant, and those
**     that vary between transmits
**   - each part is written into its own buffer
**   - after each transmit, the buffers containing varying data must be
**     updated, but the buffers containing constant data are re-used
**   - this minimizes the amount of data written between transmits.
*/
#define ef_vi_transmitv(vi, iov, iov_len, dma_id)       \
  (vi)->ops.transmitv((vi), (iov), (iov_len), (dma_id))


/*! \brief Transmit a packet already resident in Programmed I/O
**
** \param vi     The virtual interface from which to transmit.
** \param offset The offset within its Programmed I/O region to the start
**               of the packet. This must be aligned to at least a 64-byte
**               boundary.
** \param len    Length of the packet to transmit. This must be at
**               least 16 bytes.
** \param dma_id DMA id to associate with the descriptor. This is
**               completely arbitrary, and can be used for subsequent
**               tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Transmit a packet already resident in Programmed I/O.
**
** The Programmed I/O region used by this call must not be reused until an
** event indicating TX completion is handled (see \ref using_transmit), thus
** completing the transmit operation for the packet. Failure to do so might
** corrupt an ongoing transmit.
**
** The Programmed I/O region can hold multiple packets, referenced by
** different offset parameters. All other constraints must still be
** observed, including:
** - alignment
** - minimum size
** - maximum size
** - avoiding reuse until transmission is complete.
*/
#define ef_vi_transmit_pio(vi, offset, len, dma_id)             \
  (vi)->ops.transmit_pio((vi), (offset), (len), (dma_id))


/*! \brief Transmit a packet by copying it into the Programmed I/O region
**
** \param vi         The virtual interface from which to transmit.
** \param pio_offset The offset within its Programmed I/O region to the
**                   start of the packet. This must be aligned to at least
**                   a 64-byte boundary.
** \param src_buf    The source buffer from which to read the packet.
** \param len        Length of the packet to transmit. This must be at
**                   least 16 bytes.
** \param dma_id     DMA id to associate with the descriptor. This is
**                   completely arbitrary, and can be used for subsequent
**                   tracking of buffers.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** Transmit a packet by copying it into the Programmed I/O region.
**
** The src_buf parameter must point at a complete packet that is copied to
** the adapter and transmitted. The source buffer need not be registered,
** and is available for re-use immediately after this call returns.
**
** This call does not copy the packet data into the local copy of the
** adapter's Programmed I/O buffer. As a result it is slightly faster than
** calling ef_pio_memcpy() followed by ef_vi_transmit_pio().
**
** The Programmed I/O region used by this call must not be reused until an
** event indicating TX completion is handled (see \ref using_transmit), thus
** completing the transmit operation for the packet. Failure to do so might
** corrupt an ongoing transmit.
**
** The Programmed I/O region can hold multiple smaller packets, referenced
** by different offset parameters. All other constraints must still be
** observed, including:
** - alignment
** - minimum size
** - maximum size
** - avoiding reuse until transmission is complete.
*/
#define ef_vi_transmit_copy_pio(vi, pio_offset, src_buf, len, dma_id)	\
  (vi)->ops.transmit_copy_pio((vi), (pio_offset), (src_buf),            \
                              (len), (dma_id))


/*! \brief Warm Programmed I/O transmit path for subsequent transmit
**
** \param vi     The virtual interface from which transmit is planned.
**
** \return None
**
** Warm Programmed I/O transmit path for a subsequent transmit.
**
** The application can call this function in advance of calls to
** ef_vi_transmit_pio() to reduce latency jitter caused by code and state
** being evicted from cache during delays between transmits. This is also
** effective before the first transmit using Programmed I/O.
**
** While this may also benefit a subsequent call to ef_vi_transmit_copy_pio(),
** it follows a different code path. See ef_vi_transmit_copy_pio_warm() for
** a warming function designed to warm for ef_vi_transmit_copy_pio().
*/
#define ef_vi_transmit_pio_warm(vi)   \
  (vi)->ops.transmit_pio_warm((vi))


/*! \brief Copy a packet to Programmed I/O region and warm transmit path
**
** \param vi         The virtual interface from which transmit is planned.
** \param pio_offset The offset within its Programmed I/O region to the
**                   start of the packet. This must be aligned to at least
**                   a 64-byte boundary.
** \param src_buf    The source buffer from which to read the packet.
** \param len        Length of the packet to transmit. This must be at
**                   least 16 bytes.
**
** \return None
**
** Copy a packet to Programmed I/O region and warm transmit path
**
** The application can call this function in advance of calls to
** ef_vi_transmit_copy_pio() to reduce latency jitter caused by code and state
** being evicted from cache during delays between transmits.  This is also
** effective before the first transmit using Programmed I/O.
**
** No data is sent but this function will copy data to the Programmed I/O
** region. Therefore all constraints regarding copying to the
** Programmed I/O region must be met. This includes not reusing a region
** previously transmitted from until the corresponding TX completion has
** been handled. See ef_vi_transmit_copy_pio() for full details of the
** constraints.
**
** While this may also benefit a subsequent call to ef_vi_transmit_pio(),
** it follows a different code path. See ef_vi_transmit_pio_warm() for
** a warming function designed to warm for ef_vi_transmit_pio().
*/
#define ef_vi_transmit_copy_pio_warm(vi, pio_offset, src_buf, len)        \
  (vi)->ops.transmit_copy_pio_warm((vi), (pio_offset), (src_buf), (len))


/*! \brief Remove all TX descriptors from the TX descriptor ring that have
**         been initialized since last transmit.
**
** \param vi     The virtual interface for which to remove initialized TX
**               descriptors from the TX descriptor ring.
**
** \return None
**
** Remove all TX descriptors from the TX descriptor ring that have been
** initialized since last transmit.  This will undo the effects of calls
** made to ef_vi_transmit_init or ef_vi_transmitv_init since the last
** "push".
**
** Initializing and then removing descriptors can have a warming effect
** on the transmit code path for subsequent transmits.  This can reduce
** latency jitter caused by code and state being evicted from cache during
** delays between transmitting packets.  This technique is also effective
** before the first transmit.
*/
extern void ef_vi_transmit_init_undo(ef_vi* vi);


/*! \brief Maximum number of transmit completions per transmit event. */
#define EF_VI_TRANSMIT_BATCH  64


/*! \brief Unbundle an event of type of type EF_EVENT_TYPE_TX or
**         EF_EVENT_TYPE_TX_ERROR
**
** \param ep    The virtual interface that has raised the event.
** \param event The event, of type EF_EVENT_TYPE_TX or
**              EF_EVENT_TYPE_TX_ERROR
** \param ids   Array of size EF_VI_TRANSMIT_BATCH, that is updated on
**              return with the DMA ids that were used in the originating
**              ef_vi_transmit_*() calls.
**
** \return The number of valid ef_request_ids (can be zero).
**
** Unbundle an event of type of type EF_EVENT_TYPE_TX or
** EF_EVENT_TYPE_TX_ERROR.
**
** The NIC might coalesce multiple packet transmissions into a single TX
** event in the event queue. This function returns the number of descriptors
** whose transmission has completed, and updates the ids array with the
** ef_request_ids for each completed DMA request.
**
** After calling this function, the TX descriptors for the completed TX
** event are ready to be re-initialized. The associated packet buffers are
** no longer in use by ef_vi. Each buffer can then be freed, or can be
** re-used (for example as a packet buffer for a descriptor on the TX ring,
** or on the RX ring).
*/
extern int ef_vi_transmit_unbundle(ef_vi* ep, const ef_event* event,
                                   ef_request_id* ids);


/*! \brief Return the number of TX alternatives allocated for a virtual
** interface.
**
** \param vi     The virtual interface to query.
**
** \return The number of TX alternatives, or a negative error code.
**
** Gets the number of TX alternatives for the given virtual interface.
*/
extern unsigned ef_vi_transmit_alt_num_ids(ef_vi* vi);



/*! \brief Select a TX alternative as the destination for future sends
**
** \param vi     The virtual interface associated with the TX alternative.
** \param alt_id The TX alternative to select.
**
** \return 0 on success, or a negative error code.
**
** Selects a TX alternative as the destination for future sends. Packets
** can be sent to it using normal send calls such as ef_vi_transmit().
** The action then taken depends on the state of the TX alternative:
** - if the TX alternative is in the STOP state, the packet is buffered for
**   possible future transmission
** - if the TX alternative is in the GO state, the packet is immediately
**   transmitted.
*/
#define ef_vi_transmit_alt_select(vi, alt_id)	\
  (vi)->ops.transmit_alt_select((vi), (alt_id))


/*! \brief Select the "normal" data path as the destination for future
** sends.
**
** \param vi        A virtual interface associated with a TX alternative.
**
** Selects the "normal" data path as the destination for future sends.
** The virtual interface then transmits packets to the network
** immediately, in the normal way. This call undoes the effect of
** ef_vi_transmit_alt_select().
*/
#define ef_vi_transmit_alt_select_normal(vi)	\
  (vi)->ops.transmit_alt_select_default((vi))


/*! \brief Transition a TX alternative to the STOP state.
**
** \param vi        The virtual interface associated with the TX alternative.
** \param alt_id    The TX alternative to transition to the STOP state.
**
** Transitions a TX alternative to the STOP state.  Packets that are sent
** to a TX alternative in the STOP state are buffered on the adapter.
*/
#define ef_vi_transmit_alt_stop(vi, alt_id)     \
  (vi)->ops.transmit_alt_stop((vi), (alt_id))


/*! \brief Transition a TX alternative to the GO state.
**
** \param vi     The virtual interface associated with the TX alternative.
** \param alt_id The TX alternative to transition to the GO state.
**
** \return 0 on success, or a negative error code.
**
** Transitions a TX alternative to the GO state. Packets buffered in the
** alternative are transmitted to the network.
**
** As packets are transmitted events of type EF_EVENT_TYPE_TX_ALT are
** returned to the application. The application should normally wait until
** all packets have been sent before transitioning to a different state.
*/
#define ef_vi_transmit_alt_go(vi, alt_id)	\
  (vi)->ops.transmit_alt_go((vi), (alt_id))


/*! \brief Transition a TX alternative to the DISCARD state.
**
** \param vi     The virtual interface associated with the TX alternative.
** \param alt_id The TX alternative to transition to the DISCARD state.
**
** \return 0 on success, or a negative error code.
**
** Transitions a TX alternative to the DISCARD state. Packets buffered in
** the alternative are discarded.
**
** As packets are discarded, events of type EF_EVENT_TYPE_TX_ALT are
** returned to the application. The application should normally wait until
** all packets have been discarded before transitioning to a different state.
**
** Memory for the TX alternative remains allocated, and is not freed until
** the virtual interface is freed.
*/
#define ef_vi_transmit_alt_discard(vi, alt_id)          \
  (vi)->ops.transmit_alt_discard((vi), (alt_id))


/*! \brief Query per-packet overhead parameters
**
** \param vi          Interface to be queried
** \param params      Returned overhead parameters
**
** \return 0 on success or -EINVAL if this VI doesn't support
** alternatives.
**
** This function returns parameters which are needed by the
** ef_vi_transmit_alt_usage() function below.
*/
extern int ef_vi_transmit_alt_query_overhead(ef_vi* vi,
                                             struct ef_vi_transmit_alt_overhead* params);


/*! \brief Calculate a packet's buffer usage
**
** \param params      Parameters returned by
**                    ef_vi_transmit_alt_query_overhead
**
** \param pkt_len     Packet length in bytes
**
** \return Packet buffer usage in bytes including per-packet overhead
**
** This function calculates the number of bytes of buffering which
** will be used by the NIC to store a packet with the given length.
**
** The returned value includes per-packet overheads, but does not
** include any other overhead which may be incurred by the hardware.
** Note that if the application has successfully requested N bytes of
** buffering using ef_vi_transmit_alt_alloc() then it is guaranteed to
** be able to store at least N bytes of packet data + per-packet
** overhead as calculated by this function.
**
** It is possible that the application may be able to use more space
** in some situations if the non-per-packet overheads are low enough.
**
** It is important that callers do not use ef_vi_capabilities_get() to
** query the available buffering. That function does not take into
** account non-per-packet overheads and so is likely to return more
** space than can actually be used by the application.  This function
** is provided instead to allow applications to calculate their buffer
** usage accurately.
*/
ef_vi_inline ef_vi_pure uint32_t
ef_vi_transmit_alt_usage(const struct ef_vi_transmit_alt_overhead* params,
                         uint32_t pkt_len)
{
  pkt_len += params->pre_round;
  pkt_len &= params->mask;
  pkt_len += params->post_round;
  return pkt_len;
}


/*! \brief Set the threshold at which to switch from using TX descriptor
**         push to using a doorbell
**
** \param vi        The virtual interface for which to set the threshold.
** \param threshold The threshold to set, as the number of outstanding
**                  transmits at which to switch.
**
** \return 0 on success, or a negative error code.
**
** Set the threshold at which to switch from using TX descriptor push to
** using a doorbell. TX descriptor push has better latency, but a doorbell
** is more efficient.
**
** The default value for this is controlled using the EF_VI_TX_PUSH_DISABLE
** and EF_VI_TX_PUSH_ALWAYS flags to ef_vi_init().
**
** This is not supported by all Solarflare NICs. At the time of writing,
** 7000-series NICs support this, but it is ignored by earlier NICs.
*/
extern void ef_vi_set_tx_push_threshold(ef_vi* vi, unsigned threshold);


/*! \brief Transmit a packet using CTPIO from an array of buffers
**
** \param vi            The virtual interface on which to transmit.
** \param frame_len     Frame length in bytes.
** \param frame_iov     Buffers containing the frame to transmit.
** \param frame_iov_len Length of frame_iov.
** \param ct_threshold  Number of bytes of the packet to buffer before
**                      starting to cut-through to the wire.
**
** Transmit a packet using the CTPIO datapath.  The CTPIO interface gives
** the lowest latency in most cases, and can be used by any number of VIs.
**
** This function implements the latency critical part of a CTPIO send.  It
** should be followed by a call to ef_vi_transmit_ctpio_fallback() or
** similar before doing any further send calls on the same VI.
** ef_vi_transmit_ctpio_fallback() provides a fallback frame which is sent
** in cases where the CTPIO send fails.
**
** It is possible for a CTPIO send to fail for a number of reasons,
** including contention for adapter resources, and timeout due to the whole
** frame not being written to the adapter sufficiently quickly.
**
** The @p ct_threshold indicates how many bytes of the packet should be
** buffered by the adapter before starting to emit the packet.  To disable
** cut-through behavior this must be at least as large as the frame
** length.  To disable cut-through across all packet sizes, use
** EF_VI_CTPIO_CT_THRESHOLD_SNF.
**
** The CTPIO path bypasses the adapter's normal transmit path, including
** checksum offloads, and so the packet is transmitted unmodified.  The
** Ethernet FCS is appended as normal.
**
** The caller must ensure that @p frame_len is equal to the sum of the
** lengths in @p frame_iov.
**
** The buffers referenced by @p frame_iov can be reused as soon as this
** call returns.
*/
#define ef_vi_transmitv_ctpio(vi, frame_len, frame_iov,         \
                              frame_iov_len, ct_threshold)      \
  (vi)->ops.transmitv_ctpio((vi), (frame_len), (frame_iov),     \
                            (frame_iov_len), (ct_threshold))


/*! \brief Transmit a packet using CTPIO from an array of buffers,
**         simultaneously copying the data into a fallback buffer
**
** \param vi            The virtual interface on which to transmit.
** \param frame_len     Frame length in bytes.
** \param frame_iov     Buffers containing the frame to transmit.
** \param frame_iov_len Length of frame_iov.
** \param ct_threshold  Number of bytes of the packet to buffer before
**                      starting to cut-through to the wire.
** \param fallback      Fallback buffer to copy the data into
**
** This function is identical to ef_vi_transmitv_cptio, but additionally
** copies the data into a fallback buffer ready to provide to
** ef_vi_transmit_ctpio_fallback. This is an optimisation to avoid the need
** to copy the data in a separate step.
*/
#define ef_vi_transmitv_ctpio_copy(vi, frame_len, frame_iov,         \
                                   frame_iov_len, ct_threshold,      \
                                   fallback)                         \
  (vi)->ops.transmitv_ctpio_copy((vi), (frame_len), (frame_iov),     \
                                 (frame_iov_len), (ct_threshold),    \
                                 (fallback))

/*! \brief Transmit a packet using CTPIO
**
** \param vi            The virtual interface on which to transmit.
** \param frame_buf     Buffer containing the frame to transmit.
** \param frame_len     Frame length in bytes.
** \param ct_threshold  Number of bytes of the packet to buffer before
**                      starting to cut-through to the wire.
**
** Transmit a packet using the CTPIO datapath.  The CTPIO interface gives
** the lowest latency in most cases, and can be used by any number of VIs.
**
** This function implements the latency critical part of a CTPIO send.  It
** should be followed by a call to ef_vi_transmit_ctpio_fallback() or
** similar before doing any further send calls on the same VI.
** ef_vi_transmit_ctpio_fallback() provides a fallback frame which is sent
** in cases where the CTPIO send fails.
**
** It is possible for a CTPIO send to fail for a number of reasons,
** including contention for adapter resources, and timeout due to the whole
** frame not being written to the adapter sufficiently quickly.
**
** The @p ct_threshold indicates how many bytes of the packet should be
** buffered by the adapter before starting to emit the packet.  To disable
** cut-through behavior this must be at least as large as the frame
** length.  To disable cut-through across all packet sizes, use
** EF_VI_CTPIO_CT_THRESHOLD_SNF.
**
** The CTPIO path bypasses the adapter's normal transmit path, including
** checksum offloads, and so the packet is transmitted unmodified.  The
** Ethernet FCS is appended as normal.
**
** The buffer @p frame_buf can be reused as soon as this call returns.
*/
ef_vi_inline void
ef_vi_transmit_ctpio(ef_vi* vi, const void* frame_buf, size_t frame_len,
                     unsigned ct_threshold)
{
  struct iovec iov = { (void*) frame_buf, frame_len };
  ef_vi_transmitv_ctpio(vi, frame_len, &iov, 1, ct_threshold);
}


/*! \brief Post fallback frame for a CTPIO transmit
**
** \param vi            The virtual interface on which to transmit.
** \param dma_addr      DMA address of frame.
** \param len           Frame length in bytes.
** \param dma_id        DMA ID to be returned on completion.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** This should be called after ef_vi_transmit_ctpio() or similar.  It
** provides the fallback frame which is sent in the event that a CTPIO
** transmit fails.
**
** Ordinarily the fallback frame will be the same as the CTPIO frame, but
** it doesn't have to be.
*/
#define ef_vi_transmit_ctpio_fallback(vi, dma_addr, len, dma_id) \
  (vi)->ops.transmit_ctpio_fallback((vi), (dma_addr), (len), (dma_id))


/*! \brief Post fallback frame for a CTPIO transmit
**
** \param vi            The virtual interface on which to transmit.
** \param dma_iov       Array of source buffer DMA addresses.
** \param dma_iov_len   Length of dma_iov.
** \param dma_id        DMA ID to be returned on completion.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**
** This should be called after ef_vi_transmit_ctpio() or similar.  It
** provides the fallback frame which is sent in the event that a CTPIO
** transmit fails.
**
** Ordinarily the fallback frame will be the same as the CTPIO frame, but
** it doesn't have to be.
*/
#define ef_vi_transmitv_ctpio_fallback(vi, dma_iov, dma_iov_len, dma_id) \
  (vi)->ops.transmitv_ctpio_fallback((vi), (dma_iov), (dma_iov_len), (dma_id))


/*! Cut-through threshold to use if store-and-forward behavior is wanted
** for all packet sizes.  For use with ef_vi_transmit_ctpio() and
** ef_vi_transmitv_ctpio().
*/
#define EF_VI_CTPIO_CT_THRESHOLD_SNF  0xffff


/*! \brief Request the NIC copy data from one place to another
**
** \param vi          A virtual interface on which to request the send. In
**                    general this has no functional effect on the copy, but
**                    space is required on the VI's queues to perform the copy
**                    and the permissions of the VI will apply.
** \param dst_iov     An array of ef_remote_iovec instances indicating where
**                    to copy the data to.
** \param dst_iov_len Number of elements in the dst_iov array.
** \param src_iov     An array of ef_remote_iovec instances indicating the
**                    source of the data to copy.
** \param src_iov_len Number of elements in the src_iov array.
**
** After this call, ef_vi_transmit_push() must be used to send the request to
** the NIC. There is no automatic notification of completion of the copy; see
** ef_vi_transmit_memcpy_sync().
**
** src_iov and dst_iov may add up to different total amounts of data to copy;
** in this case the copy stops after one or the other is complete, i.e. it
** uses the minimum of the total lengths.
**
** \return The number of bytes actually enqueued to be copied, which may be
**         less than the input length if the queue is full. Returns a negative
**         error code on failure:
**         -EAGAIN if the descriptor ring is full.\n
**         -EINVAL if \p src_iov or \p dst_iov have bad values.
**         -EOPNOTSUPP the VI was created without EF_VI_ALLOW_MEMCPY.
*/
#define ef_vi_transmit_memcpy(vi, dst_iov, dst_iov_len, src_iov, src_iov_len) \
  (vi)->ops.transmit_memcpy((vi), (dst_iov), (dst_iov_len), (src_iov), \
                            (src_iov_len))


/*! \brief Require a completion event for all preceding ef_vi_transmit_memcpy()
**         calls on the given VI.
**
** \param vi     The virtual interface which has had previous
**               ef_vi_transmit_memcpy() calls which must be completed.
** \param dma_id DMA id to associate with the descriptor. This is completely
**               arbitrary, and can be used for tracking of requests.
**
** After this call, ef_vi_transmit_push() must be used to send the request to
** the NIC. The completion will be delivered to the application as an
** EF_EVENT_TYPE_MEMCPY event, with the given \p dma_id.
**
** \return 0 on success, or a negative error code:\n
**         -EAGAIN if the descriptor ring is full.
**         -EOPNOTSUPP the VI was created without EF_VI_ALLOW_MEMCPY.
*/
#define ef_vi_transmit_memcpy_sync(vi, dma_id)   \
  (vi)->ops.transmit_memcpy_sync((vi), (dma_id))


/**********************************************************************
 * Eventq interface ***************************************************
 **********************************************************************/

/*! \brief Returns true if there is event in eventq.
**
** \param vi          The virtual interface to query.
** \param look_ahead  Number of event relative to the current event.
**
** \return True if there is event in eventq.
**
** Returns true if there is event in eventq.
*/
extern int ef_eventq_check_event(const ef_vi* vi, int look_ahead);


/*! \brief Returns true if there is event in eventq by checking phase bit.
**
** \param vi          The virtual interface to query.
** \param look_ahead  Number of event relative to the current event.
**
** \return True if there is event in eventq.
**
** Returns true if there is event in eventq.
*/
extern int ef_eventq_check_event_phase_bit(const ef_vi* vi, int look_ahead);

extern int efxdp_ef_eventq_check_event(const ef_vi* vi, int look_ahead);
extern int efct_ef_eventq_check_event(const ef_vi* vi);


/*! \brief Returns true if ef_eventq_poll() will return event(s)
**
** \param vi The virtual interface to query.
**
** \return True if ef_eventq_poll() will return event(s).
**
** Returns true if ef_eventq_poll() will return event(s).
*/
ef_vi_inline int
ef_eventq_has_event(const ef_vi* vi)
{
  if( ! vi->evq_phase_bits )
    return ef_eventq_check_event(vi, 0);

  switch( vi->nic_type.arch ) {
    case EF_VI_ARCH_AF_XDP:
      return efxdp_ef_eventq_check_event(vi, 0);
    case EF_VI_ARCH_EFCT:
      return efct_ef_eventq_check_event(vi);
    default:
      return ef_eventq_check_event_phase_bit(vi, 0);
  }
}


/*! \brief Returns true if there are a given number of events in the event
**         queue.
**
** \param evq      The event queue to query.
** \param n_events Number of events to check.
**
** \return True if the event queue contains at least `n_events` events.
**
** Returns true if there are a given number of events in the event queue.
**
** This looks ahead in the event queue, so has the property that it will
** not ping-pong a cache-line when it is called concurrently with events
** being delivered.
**
** This function returns quickly. It is useful for an application to
** determine whether it is falling behind in its event processing.
*/
ef_vi_inline int
ef_eventq_has_many_events(const ef_vi* evq, int n_events)
{
  if( evq->evq_phase_bits )
    return ef_eventq_check_event_phase_bit(evq, n_events);
  else
    return ef_eventq_check_event(evq, n_events);
}


/*! \brief Prime a virtual interface allowing you to go to sleep blocking
**         on it
**
** \param vi The virtual interface to prime.
**
** \return None.
**
** Prime a virtual interface allowing you to go to sleep blocking on it.
*/
#define ef_eventq_prime(vi) (vi)->ops.eventq_prime((vi))


/*! \brief Poll an event queue
**
** \param evq     The event queue to poll.
** \param evs     Array in which to return polled events.
** \param evs_len Length of the evs array, must be >=
**                EF_VI_EVENT_POLL_MIN_EVS.
**
** \return The number of events retrieved.
**
** Poll an event queue. Any events that have been raised are added to the
** given array. Most events correspond to packets arriving, or packet
** transmission completing. This function is critical to latency, and must
** be called as often as possible.
**
** This function returns immediately, even if there are no outstanding
** events. The array might not be full on return.
*/
#define ef_eventq_poll(evq, evs, evs_len)               \
  (evq)->ops.eventq_poll((evq), (evs), (evs_len))


/*! \brief Returns the capacity of an event queue
**
** \param vi The event queue to query.
**
** \return The capacity of an event queue.
**
** Returns the capacity of an event queue.  This is the maximum number of
** events that can be stored into the event queue before overflow.
**
** It is up to the application to avoid event queue overflow by ensuring
** that the maximum number of events that can be delivered into an event
** queue is limited to its capacity.  In general each RX descriptor and TX
** descriptor posted can cause an event to be generated.
**
** In addition, when time-stamping is enabled time-sync events are
** generated at a rate of 4 per second.  When TX timestamps are enabled you
** may get up to one event for each descriptor plus two further events per
** packet.
*/
extern int ef_eventq_capacity(ef_vi* vi);


/*! \brief Get the current offset into the event queue.
**
** \param evq The event queue to query.
**
** \return The current offset into the eventq.
**
** Get the current offset into the event queue.
*/
ef_vi_inline unsigned ef_eventq_current(ef_vi* evq)
{
  return (unsigned) evq->ep_state->evq.evq_ptr;
}


/**********************************************************************
 * ef_vi layout *******************************************************
 **********************************************************************/

/*! \brief Types of layout that are used for receive buffers. */
enum ef_vi_layout_type {
  /** An Ethernet frameo */
  EF_VI_LAYOUT_FRAME,
  /** Hardware timestamp (minor ticks) - 32 bits */
  EF_VI_LAYOUT_MINOR_TICKS,
  /** Packet length - 16 bits */
  EF_VI_LAYOUT_PACKET_LENGTH,
};


/*! \brief Layout of the data that is delivered into receive buffers. */
typedef struct {
  /** The type of layout */
  enum ef_vi_layout_type   evle_type;
  /** Offset to the data */
  int                      evle_offset;
  /** Description of the layout */
  const char*              evle_description;
} ef_vi_layout_entry;


/*! \brief Gets the layout of the data that the adapter delivers into
**         receive buffers
**
** \param vi             The virtual interface to query.
** \param layout_out     Pointer to an ef_vi_layout_entry*, that is updated
**                       on return with a reference to the layout table.
** \param layout_len_out Pointer to an int, that is updated on return with
**                       the length of the layout table.
**
** \return 0 on success, or a negative error code.
**
** Gets the layout of the data that the adapter delivers into receive
** buffers. Depending on the adapter type and options selected, there can
** be a meta-data prefix in front of each packet delivered into memory.  Note
** that this prefix is per-packet, not per buffer, ie for jumbos the prefix
** will only be present in the first buffer of the packet.
**
** The first entry is always of type EF_VI_LAYOUT_FRAME, and the offset is
** the same as the value returned by ef_vi_receive_prefix_len().
*/
extern int
ef_vi_receive_query_layout(ef_vi* vi,
                           const ef_vi_layout_entry**const layout_out,
                           int* layout_len_out);


/*! \brief Retrieve the discard flags associated with a received packet.
**
** \param vi             The virtual interface to query.
** \param pkt            The received packet.
** \param discard_flags  Pointer to an unsigned, that is updated on return with
**                       the discard flags for the packet.
**
** \return 0 on success, or a negative error code
**
** For EF_EVENT_TYPE_RX_MULTI_PKTS events an information about Rx offload
** classification is contained in the prefix of received packet.
** The EF_EVENT_TYPE_RX_MULTI_PKTS events and prefix type are EF100 specific.
**
** Read CLASS field from the prefix of received packet and return discard flags
** about packet length, CRC or checksum validation errors.
** 
*/
extern int
ef_vi_receive_get_discard_flags(ef_vi* vi, const void* pkt,
                                unsigned* discard_flags);

#ifdef __cplusplus
}
#endif

#endif /* __EFAB_EF_VI_H__ */
