/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  kjm
**  \brief  Onload extension API
**   \date  2010/12/20
**    \cop  (c) Solarflare Communications Ltd.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_EXTENSIONS_H__
#define __ONLOAD_EXTENSIONS_H__

#include <sys/types.h>
#include <stdint.h>
#include <onload/extensions_timestamping.h>

#ifdef __cplusplus
extern "C" {
#endif


/* Use ONLOAD_MSG_WARM in the flags field of send(), sendto(), sendmsg(),
 * and onload_zc_send() to do 'fake' sends to keep the send path warm.
 *
 * This is advantageous because code paths that have not run recently
 * execute slowly.  ie. A send() call will take much longer if the previous
 * send was 1s ago than if it was 1ms ago, and the reason is because cached
 * state in the processor is lost over time.  This flag exercises Onload's
 * send path so that a subsequent performance critical send() will be
 * faster.
 *
 * WARNING!!! Note that if you use this flag with unaccelerated sockets,
 * then the message may actually be transmitted.  Therefore, we recommend
 * that before using this flag on a socket, you verify that the socket is
 * indeed accelerated by using onload_fd_stat() or onload_fd_check_feature()
 * You should check this for each socket, after you call bind() or connect()
 * on it; as these functions can cause the socket to be handed to the kernel.
 *
 * This flag corresponds to MSG_SYN in the kernel sources, which appears to
 * not be used.
 */
#define ONLOAD_MSG_WARM 0x400

/* Use ONLOAD_MSG_ONEPKT in the flags field of recv(), recvfrom() and
 * recvmsg() to receive data only up to the next packet boundary.  This
 * is not compatible with MSG_WAITALL, so that combination of flags will
 * be rejected as invalid.
 *
 * The flag value 0x20000 is not used in header bits/socket.h.
 */
#define ONLOAD_MSG_ONEPKT 0x20000

/* Use ONLOAD_SOF_TIMESTAMPING_STREAM with SO_TIMESTAMPING on TCP sockets.
 *
 * The timestamp information is returned via MSG_ERRQUEUE using
 * onload_scm_timestamping_stream structure.
 * The only valid TX flag combination is
 * (SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_SYS_HARDWARE |
 *  ONLOAD_SOF_TIMESTAMPING_STREAM).
 *
 * Onload sometimes sends packets via OS.  If it happens, the corresponding
 * timestamp is 0.
 *
 * If a segment was not retransmitted, last_sent is 0.
 */
#define ONLOAD_SOF_TIMESTAMPING_STREAM (1 << 23)

/* Use ONLOAD_SCM_TIMESTAMPING_STREAM when decoding error queue from TCP
 * socket.
 */
#define ONLOAD_SCM_TIMESTAMPING_STREAM ONLOAD_SOF_TIMESTAMPING_STREAM

struct onload_scm_timestamping_stream {
  struct timespec  first_sent; /* Time segment was first sent. */
  struct timespec  last_sent;  /* Time segment was last sent. */
  size_t           len; /* Number of bytes of message payload. */
};

extern int onload_is_present(void);


/* Describes the namespace for searching for matching stack names */
enum onload_stackname_scope {
  ONLOAD_SCOPE_NOCHANGE,
  ONLOAD_SCOPE_THREAD,
  ONLOAD_SCOPE_PROCESS,
  ONLOAD_SCOPE_USER,
  ONLOAD_SCOPE_GLOBAL
};

/* Describes who the stack name will apply to */
enum onload_stackname_who {
  ONLOAD_THIS_THREAD, /* just this thread */
  ONLOAD_ALL_THREADS  /* all threads in this process */
};

#define ONLOAD_DONT_ACCELERATE NULL

extern int onload_set_stackname(enum onload_stackname_who who,
                                enum onload_stackname_scope scope, 
                                const char* stackname);

extern int onload_stackname_save(void);

extern int onload_stackname_restore(void);

extern int onload_stack_opt_set_int(const char* opt, int64_t val);

extern int onload_stack_opt_get_int(const char* opt, int64_t* val);

extern int onload_stack_opt_set_str(const char* opt, const char* val);

/* When buffer is too small -ENOSPC is returned and required buffer size is
 * stored in val_out_len */
extern int
onload_stack_opt_get_str(const char* opt, char* val_out, size_t* val_out_len);

extern int onload_stack_opt_reset(void);


/**********************************************************************
 * onload_fd_stat: return internal details of a file descriptor
 *
 * This call returns some details that can be useful for debugging and
 * combining application-state with Onload state such as the output of
 * onload_stackdump.  It returns 1 if the file descriptor is
 * accelerated (and the details below are completed) or 0 if it is not
 * accelerated by Onload.
 * 
 * stack_id :    the numeric ID of the stack that this file descriptor
 *               belongs to.
 * stack_name :  the string name of the stack that this file descriptor
 *               belongs to.
 * endpoint_id : the numeric ID of the file descritor within its stack
 * endpoint_state : an integer that describes the current internal 
 *                  state of this file descriptor.  This can not be 
 *                  easily decoded by an application, and any 
 *                  significance of the value may change between Onload
 *                  releases.
 * 
 * The caller must free stack_name (when it is set).
 */

struct onload_stat {
  int32_t   stack_id;
  char*     stack_name;
  int32_t   endpoint_id;
  int32_t   endpoint_state;
};

extern int onload_fd_stat(int fd, struct onload_stat* stat);


/**********************************************************************
 * onload_thread_set_spin: Per-thread control of spinning.
 *
 * By default each thread uses the spinning options as specified by the
 * Onload configuration options.  This call can be used to override those
 * settings on a per-thread basis.
 *
 * The companion function onload_thread_get_spin allows querying of
 * current thread settings
 *
 * Unlike all other parts of Onload extention API, ONLOAD_SPIN_MAX value is
 * not guaranteed to be stable across Onload releases.  New enum entries
 * could be added, and ONLOAD_SPIN_MAX will be changed accordingly.
 */

enum onload_spin_type {
  ONLOAD_SPIN_ALL,        /* enable or disable all spin options */
  ONLOAD_SPIN_UDP_RECV,
  ONLOAD_SPIN_UDP_SEND,
  ONLOAD_SPIN_TCP_RECV,
  ONLOAD_SPIN_TCP_SEND,
  ONLOAD_SPIN_TCP_ACCEPT,
  ONLOAD_SPIN_PIPE_RECV,
  ONLOAD_SPIN_PIPE_SEND,
  ONLOAD_SPIN_SELECT,
  ONLOAD_SPIN_POLL,
  ONLOAD_SPIN_PKT_WAIT,
  ONLOAD_SPIN_EPOLL_WAIT,
  ONLOAD_SPIN_STACK_LOCK,
  ONLOAD_SPIN_SOCK_LOCK,
  ONLOAD_SPIN_SO_BUSY_POLL,
  ONLOAD_SPIN_TCP_CONNECT,
  ONLOAD_SPIN_MIMIC_EF_POLL, /* thread spin configuration which mimics
                              * spin settings in EF_POLL_USEC. Note that
                              * this has no effect on the usec-setting
                              * part of EF_POLL_USEC. This needs to be
                              * set separately
                              */
  ONLOAD_SPIN_MAX /* special value to mark largest valid input */
};

/* Enable or disable spinning for the current thread. */
extern int onload_thread_set_spin(enum onload_spin_type type, int spin);

/* Query thread spin settings. The state parameter will be set as a
 *  bitmask of the spin settings */
extern int onload_thread_get_spin(unsigned* state);

/**********************************************************************
 * onload_fd_check_feature : Check whether or not a feature is supported
 *
 * Will return >0 if the feature is supported, or 0 if not.
 * It will return -EOPNOTSUP if this version of Onload does not know how
 * to check for that particular feature, even if the feature itself may
 * be available; or -ENOSYS if onload_fd_check_feature() itself is not
 * supported.
 */

enum onload_fd_feature {
  /* Check whether this fd supports ONLOAD_MSG_WARM or not */
  ONLOAD_FD_FEAT_MSG_WARM = 0,
  /* Check whether this Onload returns headers with transmit
   * timestamps on UDP sockets
   */
  ONLOAD_FD_FEAT_UDP_TX_TS_HDR = 1,
};

extern int onload_fd_check_feature(int fd, enum onload_fd_feature feature);

/**********************************************************************
 * onload_move_fd: Move the file descriptor to the current stack.
 *
 * Move Onload file descriptor to the current stack, set by
 * onload_set_stackname() or other tools.  Useful for descriptors obtained
 * by accept(), to move the client connection to per-thread stack out of
 * the listening one.
 *
 * Not all kinds of Onload file descriptors are supported. Currently, it
 * works only with TCP closed sockets and TCP accepted sockets with some
 * limitations.
 * Current limitations for accepted sockets:
 * a) empty send queue and retransmit queue (i.e. send() was never called
 *    on this socket);
 * b) simple receive queue: do not read() before move, no urgent data.
 *
 * Returns 0 f moved successfully, -1 otherwise.
 * In any case, fd is a good accelerated socket after this call.
 */
extern int onload_move_fd(int fd);


/**********************************************************************
 * onload_ordered_epoll_wait: Wire order delivery via epoll
 *
 * Where an epoll set contains accelerated sockets in only one stack this
 * function can be used as a replacement for epoll_wait, but where the returned
 * EPOLLIN events are ordered.
 *
 * This function can only be used if EF_UL_EPOLL=1, which is the default, or
 * EF_UL_EPOLL=3.
 *
 * Hardware timestamping is required for correct operation.
 *
 * Any file descriptors that are returned as ready without a valid timestamp
 * (tv_sec is 0) should be considered un-ordered, with respect to each other
 * and the rest of the set.  This will occur where data is received via the
 * kernel, or without a hardware timestamp, for example on a pipe, or on an
 * interface that does not provide hardware timestamps.
 *
 * This does not support use of EPOLLET or EPOLLONESHOT.
 */

struct onload_ordered_epoll_event {
  /* The hardware timestamp of the first readable data. */
  struct timespec ts;
  /* Number of bytes that may be read to respect ordering. */
  int bytes;
};

struct epoll_event;
int onload_ordered_epoll_wait(int epfd, struct epoll_event *events,
                              struct onload_ordered_epoll_event *oo_events,
                              int maxevents, int timeout);


/**********************************************************************
 * onload_delegated_send: send via EF_VI to the Onload-managed TCP connection
 *
 * onload_delegated_send_prepare: prepare to send up to "size" bytes.
 * Allocates "headers" and fill them in with Ethernet-IP-TCP header data.
 * Returns:
 * ONLOAD_DELEGATED_SEND_RC_OK=0 in case of success;
 * ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET: invalid socket
 *     (non-Onloaded, non-TCP, non-connected or write-shutdowned);
 * ONLOAD_DELEGATED_SEND_RC_SMALL_HEADER: too small headers_len value
 *     (headers_len is set to the correct size);
 * ONLOAD_DELEGATED_SEND_RC_SENDQ_BUSY: send queue is not empty;
 * ONLOAD_DELEGATED_SEND_RC_NOARP: failed to find the destination MAC
 *      address;
 * ONLOAD_DELEGATED_SEND_RC_NOWIN: send window is closed, the peer is
 *      unable to receive more data.
 * ONLOAD_DELEGATED_SEND_RC_NOCWIN: congestion window
 *      is closed.  It is a violation of the TCP protocol to send anything.
 *      However, all the headers are filled in and the caller may use them
 *      for sending.
 *
 * ARP resolution in onload_delegated_send_prepare():
 * default (flags=0):
 *   Ask kernel for ARP information if necessary;
 *   fail if such information is not available.
 *   It is recommended to use a normal send() for the first part of the
 *   data if onload_delegated_send_prepare() returns
 *   ONLOAD_DELEGATED_SEND_RC_NOARP.
 * flags=ONLOAD_DELEGATED_SEND_FLAG_IGNORE_ARP:
 *   Do not look for correct ARP.  The caller will fill in
 *   the destination MAC address.
 * flags=ONLOAD_DELEGATED_SEND_FLAG_RESOLVE_ARP:
 *   If ARP information is not available, send a speculative TCP ACK
 *   to provoke kernel into ARP resolution.  Wait up to 1ms for ARP
 *   information to appear.
 * 
 *
 * onload_delegated_send_prepare() can be called speculatively.
 *
 *
 * onload_delegated_send_tcp_update: update packet headers with data length
 * and push flag details.
 * TCP PUSH flag: The flag is expected to be set on the last packet when
 * sending a large data chunk.  In the most cases, contemporary OSes ignore
 * TCP PUSH flag on receive.  However, you probably want to set it
 * correcctly if your TCP stream is received by an older OS.
 * Length: onload_delegated_send_prepare() assumes that the packet length
 * is equal to mss.  If it is a correct assumption, there is no need to
 * call onload_delegated_send_tcp_update().
 *
 *
 * onload_delegated_send_tcp_advance: advance headers after sending
 * one TCP packet via EF_VI.
 *
 *
 * onload_delegated_send_complete: tell this TCP connection that
 * some data was sent via EF_VI.  This function can be thought as send() or
 * sendmsg() replacement.
 * Most of the flags are ignored, except: MSG_DONTWAIT, MSG_NOSIGNAL.
 *
 * If the call is successful, Onload takes care about any further issues
 * with the data: retransmit in case of packet loss, PMTU changes, etc.
 * This function can block because of SO_SNDBUF limitation.  When blocked,
 * the function call can be interrupted by signal and return the number of
 * bytes already processed (added to retransmit queue).
 * This function ignores SO_SNDTIMEO value.
 * You can pass your data to onload via multiple _complete() calls after
 * one _prepare() call.
 *
 *
 * onload_delegated_send_cancel: No more delegated send is planned.
 * Normal send(), shutdown() or close() can be called after this call.
 * This call is necessary if you need to close the connection graciously
 * when the file descriptor is closed via close() or exit().
 * 
 * There is no need to call _cancel() before _prepare().  There is no
 * need to call _cancel if all the bytes specified in _prepare were
 * sent. If some (but not all) of the bytes specified in _prepare were
 * sent, you must call _complete() for the sent bytes and _cancel()
 * for the remaining reserved-but-not-sent bytes.  This is true even
 * if the reason for not sending is that you've reached the window
 * limits retured by the _prepare() call.
 *
 *
 * Note 1, serialization.
 * User is responsible for serialization of onload_delegated_send_*()
 * calls.  I.e. user should call onload_delegated_send_prepare() first,
 * and onload_delegated_send_cancel() later.  Normal send(), write(),
 * sendfile() function MUST NOT be called in between or in parallel with
 * these calls.  Misbehaving applications might crash.
 *
 *
 * Note 2, latency/performance.
 * If you need the best latency in the worst case, you must call
 * _complete() as soon as possible.  If you are using EF_VI to send the
 * real packets, do not wait for TX complete events - call _complete() at
 * once.  It will allow TCP machinery to retransmit packet if any of them
 * are lost.
 * If you want to save some CPU cycles at cost of making TCP retransmits
 * a bit slower (i.e. at the cost of worse latency in case of packet loss):
 * call _complete() later, to allow the network peer to acknowledge your data.
 * With the late _complete() call, you'll avoid copying of your data into TCP
 * retransmit queue (if there are no packet loss).
 *
 *
 * Sample code0: Try to send via delegated sends API and if not enough space
   fall back to normal send.

 start:
  onload_delegated_send_prepare(fd, size, flags, &ds);
  bytes = min(ds.send_wnd, ds->cong_wnd, ds.user_size, ds.mss);
  if( bytes != ds.user_size ) {
    onload_delegated_send_cancel(fd);
    send(fd, buf, size);
  }
  else {
    if( bytes != ods.mss )
      onload_delegated_send_tcp_update(&ds, bytes, 1);
    // Send via ef_vi
    onload_delegated_send_complete(fd, iovec pointing to data, 0);
  }

 * Sample code1: More involved.  Here, we will only send via delegated sends
   API.  If there isn't enough space to send, we use multiple delegated sends
   to send the entire payload.
 
 start:
  onload_delegated_send_prepare(fd, size, &ds,
                                ONLOAD_DELEGATED_SEND_FLAG_RESOLVE_ARP);
  sent = 0;
  while( (bytes = min(ds->send_wnd, ds->cong_wnd,
                      ds->user_size, ds->mss)) > 0 ) {
    uint8_t packet[1500];
 
    // set correct length and push for the last packet
    if( bytes != ds->mss ||
        bytes == min(ds->send_wnd, ds->cong_wnd, ds->user_size) )
      onload_delegated_send_tcp_update(ds, bytes, true);
 
    // compose and send the packet
    memcpy(packet, ds->headers, ds->headers_len);
    memcpy(packet + ds->headers_len, my_data, bytes);
    send "packet" via EF_VI;
 
    // increment everything
    onload_delegated_send_tcp_advance(ds, bytes);
    sent += bytes;
    my_data += bytes;
    if( something is wrong )
      break; // no need to send all the "size" bytes
  }
  assert(sent <= size);
  if( sent > 0 )
    onload_delegated_send_complete(fd, msg pointing to "my_data", 0);
  if( have more data to send )
    goto start;
  if( sent != size )
    onload_delegated_send_cancel(fd);
  close(fd);
 
 */
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

struct onload_delegated_send {
  void* headers;
  int   headers_len; /* buffer len on input, headers len on output */

  int   mss;         /* one packet payload may not exceed this */
  int   send_wnd;    /* send window */
  int   cong_wnd;    /* congestion window */
  int   user_size;   /* the "size" value from send_prepare() call */

  /* User should not look under the hood of those: */
  int   tcp_seq_offset;
  int   ip_len_offset;
  int   ip_tcp_hdr_len;
  int   reserved[5];
};

enum onload_delegated_send_rc {
  ONLOAD_DELEGATED_SEND_RC_OK = 0,
  ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET,
  ONLOAD_DELEGATED_SEND_RC_SMALL_HEADER,
  ONLOAD_DELEGATED_SEND_RC_SENDQ_BUSY,
  ONLOAD_DELEGATED_SEND_RC_NOWIN,
  ONLOAD_DELEGATED_SEND_RC_NOARP,
  ONLOAD_DELEGATED_SEND_RC_NOCWIN,
};

/* Do not try to find the destination MAC address -
 * user will fill it in the packet */
#define ONLOAD_DELEGATED_SEND_FLAG_IGNORE_ARP  0x1
/* Resolve ARP if necessary - it might take some time */
#define ONLOAD_DELEGATED_SEND_FLAG_RESOLVE_ARP 0x2

#ifndef ONLOAD_INCLUDE_DS_DATA_ONLY
/* Prepare to make a delegated send.  
 *
 * This function reserves up to "size" bytes for future delegated
 * sends, allocates headers and fills them in with current
 * Ethernet-IP-TCP header data.
 *
 * See the notes above for more details on usage.
 *
 * Returns:
 * ONLOAD_DELEGATED_SEND_RC_OK=0 in case of success;
 * ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET: invalid socket
 *     (non-Onloaded, non-TCP, non-connected or write-shutdowned);
 * ONLOAD_DELEGATED_SEND_RC_SMALL_HEADER: too small headers_len value
 *     (headers_len is set to the correct size);
 * ONLOAD_DELEGATED_SEND_RC_SENDQ_BUSY: send queue is not empty;
 * ONLOAD_DELEGATED_SEND_RC_NOARP: failed to find the destination MAC
 *      address;
 * ONLOAD_DELEGATED_SEND_RC_NOWIN: send window or congestion window
 *      is closed.  send_wnd and cong_wnd fields are filled in,
 *      so the caller can find out which window is closed.
 */

extern enum onload_delegated_send_rc
onload_delegated_send_prepare(int fd, int size, unsigned flags,
                              struct onload_delegated_send* out);


/* Update packet headers created by onload_delegated_send_prepare()
 * with correct data length and push flag details.
 * 
 * onload_delegated_send_prepare() assumes that the delegated send
 * will be the maximum segment size, and that no PUSH flag will be set
 * in the TCP header.  If this assumption is correct there is no need
 * to call onload_delegated_send_tcp_update().
 *
 * See the notes above for more details on usage.
 */

static inline void
onload_delegated_send_tcp_update(struct onload_delegated_send* ds, int bytes,
                                 int/*bool*/ push)
{
  uint16_t* ip_len_p;
  uint8_t* tcp_flags_p;

  ip_len_p = (uint16_t*) ((uintptr_t) ds->headers + ds->ip_len_offset);
  *ip_len_p = htons(bytes + ds->ip_tcp_hdr_len);

#define TCP_OFFSET_SEQ_TO_FLAGS   9
#define TCP_FLAG_PSH            0x8
  tcp_flags_p = (uint8_t*)((uintptr_t) ds->headers + ds->tcp_seq_offset +
                           TCP_OFFSET_SEQ_TO_FLAGS);
  if( push )
    *tcp_flags_p |= TCP_FLAG_PSH;
  else
    *tcp_flags_p &= ~TCP_FLAG_PSH;
#undef TCP_OFFSET_SEQ_TO_FLAGS
#undef TCP_FLAG_PSH
}

/* Update packet headers created by onload_delegated_send_prepare() to
 * reflect that a packet of length "bytes" has been sent.
 * 
 * onload_delegated_send_prepare() reserves a potentially long area
 * for delegated sends.  If these bytes are sent in multiple packets,
 * this function must be used in between each delegated send to update
 * the TCP headers appropriately.
 *
 * See the notes above for more details on usage.
 */

static inline void
onload_delegated_send_tcp_advance(struct onload_delegated_send* ds, int bytes)
{
  uint32_t seq;
  uint32_t* seq_p;

  ds->send_wnd -= bytes;
  ds->cong_wnd -= bytes;
  ds->user_size -= bytes;

  seq_p = (uint32_t*) ((uintptr_t) ds->headers + ds->tcp_seq_offset);
  seq = ntohl(*seq_p);
  seq += bytes;
  *seq_p = htonl(seq);
}


/* Notify Onload that some data have been sent via delegated sends.
 * If successful, Onload will handle all further aspects of the TCP
 * protocol (e.g. acknowledgements, retransmissions) for those bytes.
 *
 * See the notes above for more details on usage.
 *
 * Returns 0 on success, or -1 with errno set in case of error.
 */

extern int
onload_delegated_send_complete(int fd, const struct iovec* iov, int iovlen,
                               int flags);

/* Notify Onload that a previously reserved set of bytes (obtained
 * using onload_delegated_send_prepare()) are no longer required.
 *
 * This must be used if the caller has not called
 * onload_delegated_send_complete() for all the bytes reserved.  After
 * successful return, the caller can use standard sockets API calls,
 * or start another delegated send operation with
 * onload_delegated_send_prepare().
 * 
 * See the notes above for more details on usage.
 *
 * Returns 0 on success, or -1 with errno set in case of error.
 */

extern int
onload_delegated_send_cancel(int fd);


/**********************************************************************
 * onload_get_tcp_info: Onload-specific call similar to Linux TCP_INFO
 *
 * Returns -1 with errno EINVAL for a file descriptor which is not an
 * Onload TCP connection.
 *
 *
 *
 *
 */
struct onload_tcp_info {
  /* Receive buffer and its current use:
   * so_recvbuf ~= rcvbuf_used + rcv_window.
   *
   * - so_recvbuf is also available via getsockopt(SO_RCVBUF);
   * - rcvbuf_used is also available via ioctl(FIONREAD), but ignoring
   *    SO_OOBINLINE complexity (i.e. just the number of bytes in receive
   *    queue, urgent or not);
   * - rcv_window is also available via getsockopt(TCP_INFO), tcpi_rcv_space.
   */
  int so_recvbuf;
  int rcvbuf_used;
  int rcv_window;

  /* Send buffer and its current use:
   * so_sndbuf_pkts * snd_mss ~= so_sndbuf.
   *
   * - so_sndbuf is also available via getsockopt(SO_SNDBUF);
   * - so_sndbuf_pkts is the packet limit used for send queue by Onload
   *    internally, calculated from user-supplied SO_SNDBUF value;
   * - sndbuf_pkts_avail is the number of packets could be added to send
   *    queue just now;
   * - snd_mss is also available as getsockopt(TCP_INFO), tcpi_snd_mss
   */
  int so_sndbuf;
  int so_sndbuf_pkts;
  int sndbuf_pkts_avail;
  int snd_mss;

  /* Send windows:
   * - snd_window is the window size we've got from the network peer;
   *    it is the same as send_wnd value in onload_delegated_send.
   * - cong_window is the current congestion window, i.e. the size of data
   *    we are allowed to send to network by TCP congestion control
   *    protocol in use; it is the same as cong_wnd value in
   *    onload_delegated_send.
   */
  int snd_window;
  int cong_window;
};

/* Get onload_tcp_info structure defined above if the fd refers to
 * accelerated TCP connection.
 * Return 0 on success, -1 with errno=EINVAL on failure.
 *
 * len_in_out: user passes the size of memory available for the info
 * pointer; the function call returns the length of onload_tcp_info that
 * was really filled in.  len_in_out parameter is supposed to be used as
 * a sort of version number, to allow onload_tcp_info structure to be
 * extened in future.
 */
extern int
onload_get_tcp_info(int fd, struct onload_tcp_info* info, int* len_in_out);


/**********************************************************************
 * onload_socket_nonaccel: create a non-accelerated socket
 *
 * This function creates a socket that is not accelerated by Onload.
 * It is possible to do the same, more flexibly, using the Onload
 * stackname API.  This can be useful when attempting to reserve a
 * port for an ephemeral ef_vi instance without installing Onload
 * filters.
 *
 * This function takes arguments and returns values that correspond
 * exactly to the standard socket() function call.  In addition, it
 * will return -1 with errno ENOSYS if the onload extensions library
 * is not in use.
 */
extern int
onload_socket_nonaccel(int domain, int type, int protocol);


/**********************************************************************
 * onload_socket_unicast_nonaccel: create a socket where unicast is
 *                                 non-accelerated
 *
 * This function creates a socket where only multicast traffic is
 * accelerated by onload.  If this socket is not able to receive multicast,
 * for example because it's bound to a unicast local address, or it's a TCP
 * socket, then it will be handed over to the kernel.
 *
 * This can be useful in cases where a socket will be used solely for
 * multicast traffic to avoid consuming limited filter table resource.  This
 * does not prevent unicast traffic from arriving at the socket, as if
 * appropriate traffic is received it will still be delivered via the
 * un-accelerated path.  It is most useful for sockets that are bound to
 * INADDR_ANY, as for these onload must install a filter per IP address that
 * is configured on an accelerated interface, on each accelerated hardware
 * port.
 *
 * If a socket is bound to a multicast local address then no unicast filters
 * will be installed, so there is no need for this function.
 */
extern int
onload_socket_unicast_nonaccel(int domain, int type, int protocol);

#endif /* ONLOAD_INCLUDE_DS_DATA_ONLY */

#ifdef __cplusplus
}
#endif
#endif /* __ONLOAD_EXTENSIONS_H__ */
