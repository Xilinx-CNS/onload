/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  kjm
**  \brief  Onload zero-copy API
**   \date  2011/05/31
**    \cop  (c) Solarflare Communications Ltd.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_ZC_H__
#define __ONLOAD_ZC_H__

#include <sys/uio.h>    // for struct iovec
#include <sys/socket.h> // for struct msghdr
#include <stdint.h>

#include <etherfabric/ef_vi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TODO :
 *  - Zero-copy UDP-TX
 *  - allow application to signal that fd table checks aren't necessary
 *  - forwarding: zero-copy receive into a buffer, app can then do a
 *    zero-copy send on the same buffer.
 */
 

/******************************************************************************
 * Data structures
 ******************************************************************************/

/* Opaque pointer to the zc buffer metadata */
struct oo_zc_buf;
typedef struct oo_zc_buf* onload_zc_handle;

#define ONLOAD_ZC_HANDLE_NONZC ((onload_zc_handle)(uintptr_t)(-1))

/* A zc_iovec describes a single buffer */
struct onload_zc_iovec {
  union {
    void* iov_base;        /* Address within buffer */
    uint64_t iov_ptr;      /* 'buf' may refer to an external address space */
  };
  union {
    size_t iov_len;        /* Length of data */
    uint64_t iov_len64;    /* To allow large external address space buffers */
  };
  onload_zc_handle buf;    /* Corresponding (opaque) buffer handle or
                              ONLOAD_ZC_HANDLE_NONZC */

  /* When using EF_TCP_OFFLOAD, these flags can be set on an onload_zc_iovec
   * passed to onload_zc_send. They instruct the offload engine to calculate
   * and inject a CRC into an outgoing packet.
   *
   * The ONLOAD_ZC_SEND_FLAG_ACCUM_CRC flag indicates that the iovec's
   * payload should contribute to the CRC. It can be specified on multiple
   * iovecs to arrange for a CRC covering multiple regions of payload.
   *
   * The ONLOAD_ZC_SEND_FLAG_INSERT_CRC flag indicates that the calculated
   * CRC should be placed at the end of the iov's payload, replacing the
   * last 4 bytes.
   *
   * Once an INSERT flag has been seen on a connection, a subsequent ACCUM
   * flag will start a new CRC.
   *
   * These flags must not be set if EF_TCP_OFFLOAD is not set, or is set
   * to a mode that does not support TX CRC offload.
   */
  #define ONLOAD_ZC_SEND_FLAG_ACCUM_CRC       0x1
  #define ONLOAD_ZC_SEND_FLAG_INSERT_CRC      0x2
  unsigned iov_flags;      /* Flags */
  int rx_memreg_idx;       /* Index into the array returned from
                              onload_zc_query_rx_memregs() of the region
                              containing 'buf'. Populated by the recv
                              functions */
  union {
    void* app_cookie;      /* Arbitrary data passed back to the application
                              after send completion through the MSG_ERRQUEUE */
    ef_addrspace addr_space; /* Populated by onload_zc_query_rx_memregs and the
                                recv functions */
  };
};

/* A msg describes an array of iovecs that make up a datagram */
struct onload_zc_msg {
  struct onload_zc_iovec* iov; /* Array of buffers, len zc_msg.msghdr.msg_iovlen */
  struct msghdr msghdr;        /* Message metadata */
};

/* An mmsg describes a message, the socket, and its result such that
 * many can be sent in one go.
 */
struct onload_zc_mmsg {
  struct onload_zc_msg msg;    /* Message */
  int rc;                      /* Result of send/recv operation */
  int fd;                      /* socket to send on */
};


/* onload_zc_await_stack_sync will block until a stack's transmit queues
 * have cycled completely.
 *
 * fd indicates the stack that will be examined. Any accelerated socket on
 * the stack of interest may be used.
 *
 * This call allows an application to synchronise with a stack to ensure that
 * zero-copy application buffers are not being used at the time that they are
 * being changed. It is typically called immediately before
 * onload_zc_unregister_buffers().
 *
 * This synchronisation check examines only the NICs' transmit queues. It is
 * the application's responsibility to ensure that socket send queues are
 * empty as well. This function will usually block for at most a few
 * microseconds.
 *
 * Returns zero on success, or <0 to indicate an error
 */
extern int onload_zc_await_stack_sync(int fd);


/******************************************************************************
 * Buffer management
 ******************************************************************************/

enum onload_zc_buffer_type_flags {
  ONLOAD_ZC_BUFFER_HDR_NONE = 0x0,
  ONLOAD_ZC_BUFFER_HDR_UDP = 0x1,
  ONLOAD_ZC_BUFFER_HDR_TCP = 0x2,
};

/* onload_zc_alloc_buffers will allocate 1 or more buffers and return
 * details in the supplied iovecs array.
 * 
 * fd needed to indicate stack that these buffers will be used on.
 * The buffers can be used on any socket that shares the same stack as
 * the allocating fd.
 * 
 * flags can be used to indicate what type of socket this buffer will
 * be used on.  This allows space for the relevant headers to be
 * reserved resulting in more efficient sends. With no space reserved
 * (flags=0) headers will be inserted as necessary by onload with a
 * separate buffer; this is also true if insufficient space is
 * reserved (e.g. requested UDP, but actually used for TCP).
 *
 * Returns zero on success, or <0 to indicate an error
 *
 * These functions can only be used with accelerated sockets (those
 * being handled by Onload).  If a socket has been handed over to the
 * kernel stack (e.g. because it has been bound to an address that is
 * not routed over a SFC interface) it will return -ESOCKTNOSUPPORT
 */

extern int onload_zc_alloc_buffers(int fd, struct onload_zc_iovec* iovecs,
                                   int iovecs_len, 
                                   enum onload_zc_buffer_type_flags flags);

/* onload_zc_release_buffers will release 1 or more previously
 * allocated buffers supplied in the bufs array.
 * 
 * This can also be used to free buffers retained by setting
 * ONLOAD_ZC_KEEP in a receive callback.  Only the first buffer from
 * each received datagram needs to be freed this way; the rest are
 * freed automatically as they are internally chained from the first.
 *
 * Returns zero on success, or <0 to indicate an error
 */

extern int onload_zc_release_buffers(int fd, onload_zc_handle* bufs, 
                                     int bufs_len);


/* Increments the user-owned reference count for a zc handle. The application
 * is free to use this additional reference count for anything that may be
 * required. Packets are initially obtained with a user reference count of 1
 * (e.g. from onload_zc_alloc_buffers or onload_zc_recv). This function
 * accesses the reference count in a thread-safe manner.
 *
 * Other ZC functions which deal with onload_zc_handle instances do not use
 * this reference count: onload_zc_release_buffers() will always release a
 * buffer (see onload_zc_buffer_decref()), and onload_zc_send() will always
 * take full ownership of (and then release) a buffer. Applications must not
 * continue to use these incref/decref functions after those events.
 *
 * Returns 0 on success, or <0 to indicate an error
 */
extern int onload_zc_buffer_incref(int fd, onload_zc_handle buf);

/* Decrements the user-owned reference count for a zc handle. When this
 * additional reference count is decremented to zero then
 * onload_zc_release_buffers is automatically called. This function
 * accesses the reference count in a thread-safe manner.
 *
 * Returns 0 on success, or <0 to indicate an error
 */
extern int onload_zc_buffer_decref(int fd, onload_zc_handle buf);


/* onload_zc_register_buffers fixes an area of memory for use with the Onload
 * zero-copy APIs.
 *
 * The buffer must be page-aligned at minimum (both base and length). Any
 * memory may be used, however huge pages are more efficient. If huge pages
 * are used then the buffer must be huge page-aligned. Failure to meet this
 * requirement will cause the function to return -ERANGE.
 *
 * This function locks the regions of memory. The caller's RLIMIT_MEMLOCK must
 * permit this.
 *
 * This function is not available when an AF_XDP or X3 adaptor is registered
 * for use by Onload.
 *
 * fd indicates the stack on which to register the buffers. It can be any
 * socket allocated on that stack.
 *
 * addr_space must be EF_ADDRSPACE_LOCAL (to send from the process's
 * local address space) or a value obtained from elsewhere. flags must
 * be 0.
 *
 * Returns zero on success, or <0 to indicate an error.
 *
 * The returned 'handle' value must be used in the onload_zc_iovec::buf field
 * when this registered region is to be used, and can be passed to
 * onload_zc_unregister_buffers() to unregister the buffers.
 */
extern int onload_zc_register_buffers(int fd,
                                      ef_addrspace addr_space,
                                      uint64_t base_ptr, uint64_t len,
                                      int flags, onload_zc_handle* handle);


/* onload_zc_unregister_buffers undoes the effect of
 * onload_zc_register_buffers(). This function does not guarantee to perform
 * consistency checking: if the memory is still in use by Onload at the time
 * then this may cause an application crash or termination of the VI. The
 * onload_zc_await_stack_sync() function can help with this synchronisation.
 *
 * Returns zero on success, or <0 to indicate an error.
 */
extern int onload_zc_unregister_buffers(int fd,
                                        onload_zc_handle handle, int flags);

/* Reports the location of Onload's rx packet buffers
 *
 * The intended use is to allow a client to preregister Onload's packet
 * buffer memory with other devices belonging to the zero copy chain.
 *
 * fd indicates the stack from which to query the buffers. It can be any
 * socket allocated on that stack.
 *
 * flags must be 0.
 *
 * When called a value of *iovecs_len which is too small (or zero), the
 * function will set *iovecs_len to contain required number of iovecs
 * and returns -ENOSPC.
 *
 * On success the iov array gets filled with memory region details. Each
 * region is guaranteed to have address and size at least page-size
 * aligned and contigous. The iov_ptr, iov_len, iov_flags and addr_space
 * fields are populated. No flags are currently defined for iov_flags.
 *
 * Subsequently, additional info will be shared by onload_zc_recv* APIs in
 * order to indicate which memreg each packet belongs to: the value of
 * onload_zc_iovec::rx_memreg_idx will match the index within the iov array
 * returned by this function.
 *
 * Calling this function will cause all packet buffers space to be allocated,
 * if it is not already. See also EF_PREALLOC_PACKETS.
 *
 * The lifetime of buffers is tied to that of the stack. A process
 * using this function should keep a file descriptor to the stack or at
 * least one of its socket as long as they keep references to the buffers
 * and the memory regions.
 *
 * Returns zero on success, or <0 to indicate an error.
 */
extern int onload_zc_query_rx_memregs(int fd, struct onload_zc_iovec* iov,
                                      int* iovecs_len, int flags);

/* 
 * TODO buffer re-use:
 *  - recv then send, care needed as can cross stacks
 *  - send same buffer multiple times, care needed as state could change
 */


/******************************************************************************
 * Zero-copy send/receive
 ******************************************************************************/

/* onload_zc_recv will call the supplied callback for each message
 * received. On onload_zc_recv_args should have the following fields
 * set:
 * 
 *  - cb set to the callback function pointer
 *  - user_ptr set to point to application state; this is not touched
 *  by onload
 *  - msg.msghdr.msg_control set to an appropriate buffer (if required)
 *  - msg.msghdr.msg_controllen let to length of msg_control
 *  - msg.msghdr.msg_name & msg_namelen set as you would for recvmsg
 *  - flags set to indicate behavior (e.g. ONLOAD_MSG_DONTWAIT)
 *
 * Onload makes only limited checks for validity on the arguments
 * passed in, so care should be taken to ensure they are correct.
 * Cases such as NULL args pointer, etc. may result in incorrect
 * application behaviour.
 *
 * The supplied onload_zc_recv_args structure is passed through to
 * the callback every time the callback is called.
 *
 * Before calling the callback onload will fill in the args.msg.iov
 * with details of the received data, and args.msg.msghdr with the
 * relevant metadata.  args.msg.msghdr.msg_iov is not set by onload
 * and should not be used.
 *
 * When called, the callback should deal with the received data
 * (stored in onload_zc_recv_args.msg.iov) and can indicate the
 * following by setting flags on its return code:
 *
 * - onload should stop processing this set of messages and return
 * from onload_zc_recv() (rc & ONLOAD_ZC_TERMINATE).  - onload should
 * transfer ownership of the buffer(s) to the application, as the
 * application wishes to keep them for now and will release or reuse
 * them later (rc & ONLOAD_ZC_KEEP).  See onload_zc_release_buffers().
 * Use of ONLOAD_ZC_KEEP with MSG_PEEK is forbidden, due to the
 * ambiguous packet buffer ownership that it implies.
 *
 * The iov passed to the callback may have multiple elements. In this
 * case they are all fragments of the same packet, so when ONLOAD_ZC_KEEP
 * is used the application must pass only the first (iov[0].buf) to
 * onload_zc_release_buffers().
 *
 * As the return code is flags-based the application is free to set
 * any combination of these.  If no flags are set onload will continue
 * to process the next message and ownership of the buffer(s) remains
 * with onload.
 * 
 * The callback can access valid cmsg data (if requested by setting
 * socket options and providing a msg_control buffer in the
 * onload_zc_recv_args) in the onload_zc_recv_args.msghdr structure.
 * 
 * args.flags can take ONLOAD_MSG_DONTWAIT to indicate that the call
 * shouldn't block.
 *
 * For UDP, there are two options for handling data received via the
 * kernel rather than through Onload:
 * 1) Set ONLOAD_MSG_RECV_OS_INLINE in args.flags.  This will result
 * in Onload copying kernel data into oo_zc_bufs and delivering it to
 * the callback as if it had been received via Onload.
 * 2) Do not set ONLOAD_MSG_RECV_OS_INLINE in args.flags.  This will
 * result in Onload return -ENOTEMPTY from the call to
 * onload_zc_recv() if kernel traffic is present.  The caller can then
 * use onload_recvmsg_kernel() to access the kernel traffic.
 *
 * TCP urgent data is not supported by this API. Applications using
 * protocols which may include urgent data should use standard recv
 * calls.
 *
 * The callbacks are called in the same context that invoked
 * onload_zc_recv().
 * 
 * The callback's flags field will be set to ONLOAD_ZC_MSG_SHARED if
 * the msg is shared with other sockets and the caller should take
 * care not to modify the contents of the iovec.
 *
 * Timeouts are handled by setting the socket SO_RCVTIMEO value.
 * 
 * Returns 0 success or <0 to indicate an error.
 *
 * This function can only be used with accelerated sockets (those
 * being handled by Onload).  If a socket has been handed over to the
 * kernel stack (e.g. because it has been bound to an address that is
 * not routed over a SFC interface) it will return -ESOCKTNOSUPPORT
 */

enum onload_zc_callback_rc {
  ONLOAD_ZC_CONTINUE  = 0x0,
  ONLOAD_ZC_TERMINATE = 0x1,
  ONLOAD_ZC_KEEP      = 0x2, /* Receive callback only */
  ONLOAD_ZC_MODIFIED  = 0x4, /* Filter callback only */
};

/* Flags that can be set in onload_zc_recv_args.flags */
/* The value 0x40000000 overlaps with MSG_CMSG_CLOEXEC, so we're free to
 * subvert it because it can never be meaningful on UDP or TCP */
#define ONLOAD_MSG_RECV_OS_INLINE 0x40000000
#define ONLOAD_MSG_DONTWAIT MSG_DONTWAIT

/* Mask for supported onload_zc_recv_args.flags */
#define ONLOAD_ZC_RECV_FLAGS_MASK (ONLOAD_MSG_DONTWAIT | \
                                   ONLOAD_MSG_RECV_OS_INLINE)

/* Subset of onload_zc_recv_args.flags that are passed through to the
 * kernel when handling non-onloaded datagrams
 */
#define ONLOAD_ZC_RECV_FLAGS_PTHRU_MASK (ONLOAD_MSG_DONTWAIT)

/* Flags that can be set in the callback flags argument
 * 
 * If set then this buffer may be shared with other sockets and the
 * caller should take care not to modify the contents of the iovec
 */
#define ONLOAD_ZC_MSG_SHARED 0x1
#define ONLOAD_ZC_END_OF_BURST 0x2

struct onload_zc_recv_args;

typedef enum onload_zc_callback_rc 
(*onload_zc_recv_callback)(struct onload_zc_recv_args *args, int flags);

struct onload_zc_recv_args {
  struct onload_zc_msg msg;
  onload_zc_recv_callback cb;
  void* user_ptr;
  int flags;
};


extern int onload_zc_recv(int fd, struct onload_zc_recv_args *args);


/* Use onload_recvmsg_kernel() to access packets delivered by
 * kernel/OS rather than Onload, when onload_zc_recv() returns
 * -ENOTEMPTY
 */
extern int onload_recvmsg_kernel(int fd, struct msghdr *msg, int flags);


/* onload_zc_send will send each of the messages supplied in the msgs
 * array using the fd from struct onload_zc_mmsg.  Each message
 * consists of an array of buffers (msgs[i].msg.iov[j].iov_base,
 * buffer length msgs[i].msg.iov[j].iov_len), and the array is of
 * length msgs[i].msg.msghdr.msg_iovlen.  For UDP this array is sent
 * as a single datagram.
 *
 * ONLOAD_ZC_HANDLE_NONZC is not currently supported by this function.
 *
 * Onload makes only limited checks for validity on the arguments
 * passed in, so care should be taken to ensure they are correct.
 * Cases such as NULL msgs pointer, zero mlen, or zero iov_len,
 * etc. may result in incorrect application behaviour.
 *
 * TODO flags can take a value that indicates that the send path
 * should be exercised to keep it warm, but no data actually sent.  In
 * this case the application retains ownership of the buffers.
 * 
 * Returns number of messages processed, with the status (e.g. bytes
 * sent or error) of each processed message stored in msgs[i].rc
 * Caller should check each valid msgs[i].rc and compare to expected
 * number of bytes to check how much has been done.
 *
 * The 'buf' element of onload_zc_iovec may refer to either a packet
 * buffer allocated by onload_zc_alloc_buffers() or a region of pinned
 * memory defined by onload_zc_register_buffers().
 *
 * For any buffer successfully sent which was allocated by
 * onload_zc_alloc_buffers(), ownership of the corresponding
 * onload_zc_handle buffer is transferred to Onload and it must not be
 * subsequently used by the application.  For any messages that are
 * not sent (e.g. due to error) ownership of the buffers remains with
 * the application and it must either re-use or free them.
 *
 * If an iovec refers to (a subset of) a region of memory defined by
 * onload_zc_register_buffers() then the application must not modify
 * or release the buffers until Onload has finished with them; the
 * completion notification mechanism is described below. This feature is
 * incompatible with loopback acceleration (EF_TCP_CLIENT_LOOPBACK != 0)
 * and will set msgs.rc to -EINVAL.
 *
 * This function can only be used with accelerated sockets (those
 * being handled by Onload).  If a socket has been handed over to the
 * kernel stack (e.g. because it has been bound to an address that is
 * not routed over a SFC interface) it will set msgs.rc to
 * -ESOCKTNOSUPPORT
 *
 * This function copies behaviour of normal send() functions when possible,
 * which includes sleep in case when the TCP socket has not established
 * connection yet.
 */

#define ONLOAD_MSG_DONTWAIT MSG_DONTWAIT
#define ONLOAD_MSG_MORE MSG_MORE
#define ONLOAD_MSG_NOSIGNAL MSG_NOSIGNAL

/* Mask for supported flags */
#define ONLOAD_ZC_SEND_FLAGS_MASK (ONLOAD_MSG_MORE | ONLOAD_MSG_NOSIGNAL | \
                                   ONLOAD_MSG_WARM | ONLOAD_MSG_DONTWAIT)

/* Subset of flags that are passed through to the kernel when
 * handling non-onloaded datagrams
 */ 
#define ONLOAD_ZC_SEND_FLAGS_PTHRU_MASK (ONLOAD_MSG_MORE | \
                                         ONLOAD_MSG_NOSIGNAL | \
                                         ONLOAD_MSG_DONTWAIT)

extern int onload_zc_send(struct onload_zc_mmsg* msgs, int mlen, int flags);


/* This is a randomly-generated number - hopefully nobody else uses the
 * same number */
#define ONLOAD_SO_ONLOADZC_COMPLETE   8902

/* Completion notifications for onload_zc_send
 *
 * Notifications are sent only for sends of buffer regions allocated
 * by onload_zc_register_buffers(). Sends involving buffers from
 * onload_zc_alloc_buffers() have no signal that the buffers have been
 * freed back to Onload.
 *
 * This notification scheme is modelled on that of the Linux MSG_ZEROCOPY
 * feature, however the specific format of the completion event differs.
 *
 * Completion notifications are sent through the socket's error queue.
 * This can be retrieved by passing MSG_ERRQUEUE as a flag to recvmsg()
 * on the socket, with a msg_control buffer to retrieve the data.
 * Testing for availability of data on the errqueue is implicit in
 * poll(), select(), epoll, etc. - see the documentation of POLLERR.
 *
 * The completions are delivered with a cmsg_level=SOL_IP and
 * cmsg_type=ONLOAD_SO_ONLOADZC_COMPLETE. The body is a single
 * void* containing the onload_zc_iovec::app_cookie field originally
 * passed in the onload_zc_send() call. Multiple completions may be
 * delivered in a single recvmsg() call, as multiple cmsgs.
 *
 * Applications are required to track incomplete buffers themselves. At
 * any close() (even after correct use of shutdown()) it cannot be
 * guaranteed that all completion events have been delivered, so the
 * application must have (and use) a mechanism for reclaiming incomplete
 * buffers after they have lost access to the socket's error queue. On
 * abortive socket close the application must be aware that Onload may be
 * concurrently transmitting from any incomplete buffers; if those
 * buffers are rapidly reused then it is possible that modified data may
 * be sent on the wire.
 *
 * Applications should also be aware of the implicit POLLERR behaviour,
 * and ensure that all polling loops try to consume the socket's
 * errqueue before resuming.
 */


/******************************************************************************
 * Receive filtering 
 ******************************************************************************/

/*
 * onload_set_recv_filter() will install a callback that can intercept
 * data received through the normal recv/recvmsg/recvmmsg API.
 * This should not be used in conjunction with onload_zc_recv()
 *
 * The callback is invoked once per message and the cb_arg value is
 * passed to the callback along with the message.  The callback's
 * flags argument will be set to ONLOAD_ZC_MSG_SHARED if the msg is
 * shared with other sockets and the caller should take care not to
 * modify the contents of the iovec.
 *
 * The message can be found in msg->iov[], and the iovec is of length
 * msg->msghdr.msg_iovlen.
 *
 * The callback must return ONLOAD_ZC_CONTINUE to allow the message to
 * be delivered to the application. Other return codes such as
 * ONLOAD_ZC_TERMINATE and ONLOAD_ZC_MODIFIED are deprecated and no
 * longer supported.
 *
 * This function can only be used with accelerated sockets (those
 * being handled by Onload).  If a socket has been handed over to the
 * kernel stack (e.g. because it has been bound to an address that is
 * not routed over a SFC interface) it will return -ESOCKTNOSUPPORT
 */

typedef enum onload_zc_callback_rc 
(*onload_zc_recv_filter_callback)(struct onload_zc_msg *msg, void* arg, 
                                  int flags);

extern int onload_set_recv_filter(int fd, 
                                  onload_zc_recv_filter_callback filter,
                                  void* cb_arg, int flags);



/******************************************************************************
 * Send templates 
 ******************************************************************************/

/* onload_msg_template_*
 * 
 * This set of functions allows the user to specify the bulk of a
 * packet in advance (the send template), then update it and send it
 * when the complete packet contents are known.  If the updates are
 * relatively small this should result in a lower latency send.
 *
 * onload_msg_template_alloc takes an array of iovecs to specify the
 * initial bulk of the packet data. On success, the
 * onload_template_handle pointer is updated to contain the (opaque)
 * handle used to refer to this template in subsequent operations.
 *
 * onload_msg_template_update takes an array of
 * onload_template_msg_update_iovec to describe changes to the base
 * packet given in onload_msg_template_alloc.  Each of the update
 * iovec should describe a single change, and contain:
 *
 *  - otmu_base set to the start of the new data.
 *
 *  - otmu_len set to the length of the update.
 *
 *  - otmu_offset set to the offset within the template to update
 *
 * ulen is the length of the updates array (i.e. the number of changes)
 *
 * Currently, the only supported operations with
 * onload_msg_template_update is to either overwrite existing contents
 * or to send by using ONLOAD_TEMPLATE_FLAGS_SEND_NOW flag.
 *
 * To send without overwriting, simply call onload_msg_template_update
 * with updates=NULL, ulen=0, and flags=ONLOAD_TEMPLATE_FLAGS_SEND_NOW.
 *
 * After onload_msg_template_update has been called with
 * flags=ONLOAD_TEMPLATE_FLAGS_SEND_NOW, the ownership of the template
 * passes to Onload.
 *
 * Templated sends will still respect the TCP state machinery and do a
 * normal send if the state machinery does not allow it (e.g. the send
 * queue is not empty).  In such scenarios, it is possible that the
 * converted normal send can block.  ONLOAD_TEMPLATE_FLAGS_DONTWAIT
 * flag provides the same behavior as MSG_DONTWAIT in such scenarios.
 *
 * By default, if PIO allocation fails, then
 * onload_msg_template_alloc() will fail.  Setting
 * ONLOAD_TEMPLATE_FLAGS_PIO_RETRY will cause it to continue without a
 * PIO AND trying to allocate the PIO in later calls to
 * onload_msg_template_update().
 *
 * onload_msg_template_update can be called multiple times and updates
 * are cumulative.
 *
 * onload_msg_template_abort can be used to abort a templated send
 * without sending.
 * 
 * All functions return zero on success, or <0 to indicate an error.
 *
 * If the associated socket with allocated templates is shutdown or
 * closed, then the allocated templates are freed.  Subsequent calls
 * to access them will return an error.
 *
 * Currently, when the NIC is reset, any socket with some allocated
 * templated sends will get marked as not being able to do any further
 * templated sends.  This is a limitation of the current
 * implementation and will be removed in future.
 *
 * This implementation has known functional and performance
 * limitations that will be resolved in future releases.
 *
 * These functions can only be used with accelerated sockets (those
 * being handled by Onload).  If a socket has been handed over to the
 * kernel stack (e.g. because it has been bound to an address that is
 * not routed over a SFC interface) it will return -ESOCKTNOSUPPORT
 *
 * PIO, and therefore templated send, is not available on SmartNIC
 * (SN1000 and later series) or X3 architectures. Normal send
 * operations provide the lowest possible latency on those devices.
 */

/* Opaque pointer to the template metadata */
struct oo_msg_template;
typedef struct oo_msg_template* onload_template_handle;

/* An update_iovec describes a single template update */
struct onload_template_msg_update_iovec {
  void*    otmu_base;         /* Pointer to new data */
  size_t   otmu_len;          /* Length of new data */
  off_t    otmu_offset;       /* Offset within template to update */ 
  unsigned otmu_flags;        /* For future use.  Must be set to 0. */
};

/* Flags for use with onload_msg_template_alloc() and
 * onload_msg_template_update()
 */
enum onload_template_flags {
  ONLOAD_TEMPLATE_FLAGS_SEND_NOW  = 0x1, /* Send the packet now */
  ONLOAD_TEMPLATE_FLAGS_PIO_RETRY = 0x2, /* Retry acquiring PIO */
  ONLOAD_TEMPLATE_FLAGS_DONTWAIT = MSG_DONTWAIT, /* Don't block (0x40) */
};

/* Valid options for flags are: ONLOAD_TEMPLATE_FLAGS_PIO_RETRY */
extern int onload_msg_template_alloc(int fd, const struct iovec* initial_msg,
                                     int mlen, onload_template_handle* handle,
                                     unsigned flags);


/* Valid options for flags are: ONLOAD_TEMPLATE_FLAGS_SEND_NOW,
 * ONLOAD_TEMPLATE_FLAGS_DONTWAIT
 */
extern int
onload_msg_template_update(int fd, onload_template_handle handle,
                           const struct onload_template_msg_update_iovec*,
                           int ulen, unsigned flags);

extern int onload_msg_template_abort(int fd, onload_template_handle handle);


/******************************************************************************
 * High-level receive API (hlrx)
 ******************************************************************************/

/* This API is a high-level wrapper, using onload_zc_recv_full() and
 * onload_zc_buffer_incref() underneath. It is provided to ease the
 * implementation of applications which need to alternate between copy
 * receives and zero-copy receives arbitrarily. It is implemented
 * entirely in terms of the other APIs: if applications need more
 * fine-grained control than is provided here then they can
 * reimplement functionality entirely equivalent to this API without
 * additional knowledge of Onload internals.
 *
 * Use onload_zc_hlrx_alloc() to create an object to manage the state
 * of a single socket, then onload_zc_hlrx_recv_copy() and
 * onload_zc_hlrx_recv_zc() may be freely called.
 */

struct onload_zc_hlrx;

/* Create a new hlrx state on the given socket, returning the instance
 * in the 'hlrx' out parameter. Use onload_zc_hlrx_free() to deallocate.
 *
 * An hlrx state maintains an internal buffer of data received on the socket,
 * so there can be at most one instance per socket.
 *
 * flags must be 0
 *
 * Returns zero on success, or <0 to indicate an error
 */
extern int onload_zc_hlrx_alloc(int fd, int flags,
                                struct onload_zc_hlrx** hlrx);

/* Frees an hlrx state created by onload_zc_hlrx_alloc()
 *
 * Returns zero on success, or <0 to indicate an error. A notable error
 * is -EBUSY if non-local (i.e. addr_space != EF_ADDRSPACE_LOCAL)
 * onload_zc_iovec blocks have been given out by onload_zc_hlrx_recv_zc()
 * but not yet freed with onload_zc_hlrx_buffer_release(); the
 * memory referenced by those iovecs would be freed by closing the
 * fd backing this hlrx instance, so this function fails instead.
 */
extern int onload_zc_hlrx_free(struct onload_zc_hlrx* hlrx);

/* Frees a zc handle which was returned by onload_zc_hlrx_recv_zc in
 * the onload_zc_iovec::buf field.
 *
 * fd must be any socket on the same stack as the socket inside the
 * hlrx instance which returned the buf. Buffers are permitted to
 * outlive the hlrx instance which created them.
 *
 * Returns 0 on success, or <0 to indicate an error
 */
extern int onload_zc_hlrx_buffer_release(int fd, onload_zc_handle buf);

/* Performs a copying receive on an hlrx state. This function operates
 * identically to recvmsg(), however it returns errors by return code
 * rather than by errno.
 *
 * The MSG_PEEK and MSG_TRUNC flags are not supported.
 *
 * Returns the total number of bytes received on success, or <0 to
 * indicate an error. In addition to typical errno values, the error
 * -EREMOTEIO may be returned when the next data in the receive queue
 * is in a remote address space; in this case onload_zc_hlrx_recv_zc()
 * must be used to obtain the pointer.
 */
extern ssize_t onload_zc_hlrx_recv_copy(struct onload_zc_hlrx* hlrx,
                                        struct msghdr* msg, int flags);

/* Performs a zero-copy receive on an hlrx state. This function will
 * return with as many of msg->iov populated with received segments as will
 * fit or are available, i.e. whichever of msg->msghdr.msg_iovlen or
 * max_bytes is reached first. There is no guarantee about where the
 * boundaries between packets will be placed.
 *
 * The caller must release all packets returned by this function
 * using onload_zc_hlrx_buffer_release(). The onload_zc_iovec::buf may
 * refer to a metaobject instead of a real packet, so the non-hlrx
 * functions must not be used with it.
 *
 * On input, msg->msghdr.msg_iovlen is the size of the msg->iov array. On
 * output it is the number of elements populated with buffers; this is the
 * minimum of the input count and the number of iovs required to cover
 * max_bytes.
 *
 * The MSG_PEEK, MSG_TRUNC and MSG_ERRQUEUE flags are not supported.
 *
 * Returns the total number of bytes of data obtained, i.e.
 * sum(msg->iov[*].iov_len), on success, or a negative error number on
 * failure.
 */
extern ssize_t onload_zc_hlrx_recv_zc(struct onload_zc_hlrx* hlrx,
                                      struct onload_zc_msg* msg,
                                      size_t max_bytes, int flags);


/******************************************************************************
 * TCP processing offload
 ******************************************************************************/

/* A socket option for use with setsockopt/getsockopt with the IPPROTO_TCP
 * level. Takes an int for the optval: 0 to disable offload (default), a
 * nonzero value to enable it using the engine for a particular protocol. The
 * set of nonzero values which are available is dependent on what plugins are
 * loaded in to the NIC; the policy is to use the IANA port number
 * registration for the protocol being used.
 *
 * Offloading must be enabled before the socket is connected or bound. Setting
 * the option on a listening socket will apply it to all accepted sockets: the
 * listen itself is not offloaded. Requires EF_TCP_OFFLOAD set to a value
 * other than 'off' and which allows for the protocol which is requested.
 *
 * Protocol offloads typically involve some amount of data being modified on
 * the NIC and/or being delivered through an alternative route. These
 * applications must use the Onload zero-copy receive extension API,
 * onload_zc_recv(). */
#define ONLOAD_TCP_OFFLOAD  47429

/* ioctl request to mark remote memory as available on this socket. Remote
 * memory is handed to the app from onload_zc_recv() with
 * onload_zc_iovec::addr_space != EF_ADDRSPACE_LOCAL. Once the memory is
 * finished with (typically by completion of a mem2mem transfer), this ioctl
 * must be called to release the memory back to the plugin.
 *
 * The ioctl argp is a pointer to a single uint64_t, being the pointer to the
 * byte immediately after the region to be freed. This must be a value in the
 * range (iov_ptr, iov_ptr+iov_len64] for some iov which has been obtained
 * from onload_zc_recv().
 *
 * Plugin memory is freed in order, i.e. passing a pointer from iov[n] will
 * cause all outstanding memory from iov[k] for all k < n to be freed as well;
 * all iovs are included in this range, regardless of whether they came from
 * one or multiple calls to onload_zc_recv(). If the app may cause memory
 * regions to become available in an arbitrary order then it is the app's
 * responsibility to sort the completions so that this ordering contraint is
 * obeyed. This requirement exists because plugin memory operates as a ring
 * buffer: this ioctl is directly assigning to the 'tail' pointer of the ring
 * buffer - there is no sophisticated heap manager, */
#define ONLOAD_SIOC_CEPH_REMOTE_CONSUME  0x654182d9

#ifdef __cplusplus
}
#endif

#endif /* __ONLOAD_ZC_H__ */
