/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */
#ifndef __ONLOAD_TCP_POLL_H__
#define __ONLOAD_TCP_POLL_H__


/* Find events to return by poll() for a given TCP socket. 
 * These functions do not wait for events, but just report them. 
 *
 * ATTENTION! These functions should be kept is sync with
 * citp_tcp_select().  (Or better still, citp_tcp_select() should use
 * these).
 */

/* This function should be used for listening sockets only. */
ci_inline short
ci_tcp_poll_events_listen(ci_netif *ni, ci_tcp_socket_listen *tls)
{
  if( ci_tcp_acceptq_n(tls) || (tls->s.os_sock_status & OO_OS_STATUS_RX) ||
      tls->s.so_error )
    return  POLLIN | POLLRDNORM;
  return 0;
}

/* The timestamp_q is subtly managed to ensure that tx_pending packets do not
 * appear to be visible. See doc at ci_tcp_state::timestamp_q */
ci_inline bool
ci_tcp_poll_timestamp_q_nonempty(ci_netif *ni, ci_tcp_state *ts)
{
#if CI_CFG_TIMESTAMPING
  return ! ci_udp_recv_q_is_empty(&ts->timestamp_q);
#else
  return 0;
#endif
}

ci_inline int/*bool*/
ci_tcp_poll_events_nolisten_haspri(ci_netif *ni, ci_tcp_state *ts)
{
  return ( tcp_urg_data(ts) & CI_TCP_URG_IS_HERE )
         || ( (ts->s.s_aflags & CI_SOCK_AFLAG_SELECT_ERR_QUEUE)
              && ci_tcp_poll_timestamp_q_nonempty(ni, ts) );
}

/* This function should not be used for listening sockets.
 * Once upon a time, this function simulated both Linux and Solaris.
 * Linux behaviour changed in 2.6.32, and this function was reworked.
 * See history for Solaris behaviour if you need it. */
ci_inline short
ci_tcp_poll_events_nolisten(ci_netif *ni, ci_tcp_state *ts)
{
  short revents = 0;

  /* Shutdown: */
  if( ts->s.tx_errno )
    revents |= POLLOUT;
  if( (TCP_RX_DONE(ts) & CI_SHUT_RD) )
    revents |= POLLIN | POLLRDHUP; /* SHUT_RD */
  if( ts->s.tx_errno && TCP_RX_DONE(ts) )
    revents |= POLLHUP; /* SHUT_RDWR */
  /* Errors */
  if( ts->s.so_error || ci_tcp_poll_timestamp_q_nonempty(ni, ts) )
    revents |= POLLERR;

  /* synchronised: !CLOSED !SYN_SENT */
  if( ts->s.b.state & CI_TCP_STATE_SYNCHRONISED ) {
    /* normal send: */
    if( ! ts->s.tx_errno && ci_tcp_tx_advertise_space(ni, ts) )
      revents |= POLLOUT | POLLWRNORM;

    /* urg */
    if( ci_tcp_poll_events_nolisten_haspri(ni, ts) )
      revents |= POLLPRI;

    /* normal recv or nothing to recv forever */
    if( (ts->s.b.state & CI_TCP_STATE_NOT_CONNECTED) ||
        ci_tcp_recv_not_blocked(ts) )
      revents |= POLLIN | POLLRDNORM;

  }
  else if( ts->s.b.state == CI_TCP_SYN_SENT )
    revents = 0;

  return revents;
}

/* Call ci_tcp_poll_events_listen() or ci_tcp_poll_events_nolisten
 * in accordance with the current state.  All state transitions are
 * implemented using CI_TCP_INVALID state:
 *   set state to CI_TCP_INVALID;
 *   write barrier;
 *   re-init the waitable object to the new structure;
 *   write barrier;
 *   set state to CI_TCP_whatever.
 * These transitions happen when listen() or
 * shutdown(listen_sock) are called.
 *
 * We use __SOCK_TO_TCP_LISTEN and __SOCK_TO_TCP to avoid assertions that
 * the socket is in the correct state.  Such assertions can fail, because
 * we have no way to guarantee that the state have not changed under our
 * feet.  See the paragraph above for the state transition machinery.
 * If we detect the state change after the mask is calculated, we drop this
 * mask and return 0.
 * 
 * poll_events() returns 0 if it is called in a transitional state.
 */
ci_inline short ci_tcp_poll_events(ci_netif* ni, ci_sock_cmn* s)
{
  short mask;
  if( s->b.state == CI_TCP_LISTEN ) {
    mask = ci_tcp_poll_events_listen(ni, __SOCK_TO_TCP_LISTEN(s));
    if( OO_ACCESS_ONCE(s->b.state) != CI_TCP_LISTEN )
      mask = 0;
  }
  else if( s->b.state == CI_TCP_INVALID ) {
    mask = 0;
  }
  else {
    ci_uint32 state;
    mask = ci_tcp_poll_events_nolisten(ni, __SOCK_TO_TCP(s));
    state = OO_ACCESS_ONCE(s->b.state);
    if( state == CI_TCP_INVALID || state == CI_TCP_LISTEN )
      mask = 0;
  }
  return mask;
}


ci_inline unsigned
ci_udp_poll_events(ci_netif* ni, ci_udp_state* us)
{
  unsigned events = 0;

  /* TX errno set by shutdown(SHUT_WR) must not set POLLERR. */
  if( us->s.so_error || UDP_RX_ERRNO(us) ||
      (UDP_TX_ERRNO(us) && ! UDP_IS_SHUT_WR(us)) )
    events |= POLLERR;

  if( UDP_IS_SHUT_RD(us) ) {
    events |= POLLRDHUP | POLLIN;
    if( UDP_IS_SHUT_RDWR(us) )
      events |= POLLHUP;
  }

  if( UDP_RX_ERRNO(us) | ci_udp_recv_q_not_empty(&us->recv_q) )
    events |= POLLIN | POLLRDNORM;

  if( us->s.os_sock_status & OO_OS_STATUS_RX )
    events |= POLLIN | POLLRDNORM;

  if(
#if CI_CFG_TIMESTAMPING
     ci_udp_recv_q_not_empty(&us->timestamp_q) ||
#endif
      (us->s.os_sock_status & OO_OS_STATUS_ERR) ) {
    events |= POLLERR;
    if( us->s.s_aflags & CI_SOCK_AFLAG_SELECT_ERR_QUEUE )
      events |= POLLPRI;
  }

  if( ci_udp_tx_advertise_space(us) &&
      (us->s.os_sock_status & OO_OS_STATUS_TX) )
    events |= POLLOUT | POLLWRNORM | POLLWRBAND;

  return events;
}

#include <onload/oo_pipe.h>

ci_inline unsigned
oo_pipe_poll_read_events(struct oo_pipe* p)
{
  unsigned events = 0;

  if( oo_pipe_data_len(p) )
    events |= POLLIN | POLLRDNORM;
  if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_WRITER_SHIFT) )
    events |= POLLHUP;

  return events;
}

ci_inline unsigned
oo_pipe_poll_write_events(struct oo_pipe* p)
{
  unsigned events = 0;

  if( oo_pipe_is_writable(p) )
    events |= POLLOUT | POLLWRNORM | POLLWRBAND;
  if( p->aflags & (CI_PFD_AFLAG_CLOSED << CI_PFD_AFLAG_READER_SHIFT) )
    events |= POLLERR;

  return events;
}


#endif  /* __ONLOAD_TCP_POLL_H__ */
