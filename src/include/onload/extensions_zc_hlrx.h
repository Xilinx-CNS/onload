/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  rch maciejj
**  \brief  Onload zero-copy API
**   \date  2022/08/01
**    \cop  (c) Solarflare Communications Ltd.
** </L5_PRIVATE>
**
** Contains zerocopy APIs for use of alternate/mixed address spaces.
** Support is experimental and limited to ef100 series adapters.
*//*
\**************************************************************************/

#ifndef __ONLOAD_ZC_HLRX_H__
#define __ONLOAD_ZC_HLRX_H__

#include <onload/extensions_zc.h>
#include <stdint.h>

#include <etherfabric/ef_vi.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 * Zero-copy send/receive extensions for alternate/mixed address spaces
 ******************************************************************************/

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
/* Flags in the ONLOAD_ZC_RECV_FLAG_OFFLOAD_RESERVED set are reserved for use
 * by zero-copy offload implementations.  The 'hlrx' high-level receive API
 * is a convenient mechanism for consuming such flags. */
#define ONLOAD_ZC_RECV_FLAG_OFFLOAD_RESERVED   0xff00u


/******************************************************************************
 * Buffer management
 ******************************************************************************/

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
 * aligned and contiguous. The iov_ptr, iov_len, iov_flags and addr_space
 * fields are populated.
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


/******************************************************************************
 * Zero-copy send/receive
 ******************************************************************************/

/* onload_zc_send has now additional capabilities,
 * specifically use of registered buffers.
 *
 * There is an important distiction when it comes to use of registered buffers:
 *
 * If an iovec refers to (a subset of) a region of memory defined by
 * onload_zc_register_buffers() then the application must not modify
 * or release the buffers until Onload has finished with them; the
 * completion notification mechanism is described below. This feature is
 * incompatible with loopback acceleration (EF_TCP_CLIENT_LOOPBACK != 0)
 * and will set msgs.rc to -EINVAL.
 */


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

/* Returns out-of-band data associated with a buffer returned by a previous
 * onload_zc_hlrx_recv_zc() call.  This function will return with as many of
 * msg->iov populated with out-of-band buffers corresponding to the
 * previously-returned buffer inband.
 *
 * inband must be the very iovec populated by onload_zc_hlrx_recv_zc() rather
 * than a copy thereof.  The application must not drop its reference to inband
 * (i.e. must not call onload_zc_hlrx_buffer_release() on inband->buf) before
 * passing inband to this function.
 *
 * In the current implementation, inband must be the most recently-returned
 * buffer from onload_zc_hlrx_recv_zc().
 *
 * Up to len bytes of out-of-band data are copied into buf.
 *
 * No input flags are supported at present.  On return, *flags will have
 * MSG_TRUNC set if only part of the data was returned, either because the
 * provided buffer was too small or because the data was truncated internally.
 * flags may be NULL if this information is not required by the caller.
 *
 * Returns the total number of bytes of data obtained on success, or a negative
 * error number on failure.
 */
extern ssize_t
onload_zc_hlrx_recv_oob(struct onload_zc_hlrx* hlrx,
                        const struct onload_zc_iovec* inband,
                        void* buf, size_t len, int *flags);


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
 * range (iov_ptr, iov_ptr+iov_len] for some iov which has been obtained
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

/* On onload_zc_iovec::iov_flags, indicates that the iovec describes not in-
 * band stream data, but instead contains out-of-band data generated by the
 * offload engine.  The significance of this out-of-band data is opaque to the
 * Onload zero-copy framework and is determined solely by the semantics of the
 * enabled offload. */
#define ONLOAD_ZC_RECV_FLAG_OFFLOAD_OOB 0x0100u

#ifdef __cplusplus
}
#endif

#endif /* __ONLOAD_ZC_HLRX_H__ */
