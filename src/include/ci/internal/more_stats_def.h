/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2019 Xilinx, Inc. */

#define MORE_STATS_DERIVED_DESC "derived statistic"

/* TCP states need to come first to match more_stats_t
 * and in the following order to match CI_TCP_STATE_NUM(state) index */
OO_STAT("Number of TCP sockets in the CLOSED state.",
        unsigned, TCP_CLOSED, val)
OO_STAT("Number of TCP listen sockets.",
        unsigned, TCP_LISTEN, val)
OO_STAT("Number of TCP sockets that have sent the intial SYN but are not "
        "fully connected yet.",
        unsigned, TCP_SYN_SENT, val)
OO_STAT("Number of fully established TCP sockets.",
        unsigned, TCP_ESTABLISHED, val)
OO_STAT("Number of TCP sockets currently in the CLOSE_WAIT state.",
        unsigned, TCP_CLOSE_WAIT, val)
OO_STAT("Number of TCP sockets currently in the LAST_ACK state.",
        unsigned, TCP_LAST_ACK, val)
OO_STAT("Number of TCP sockets currently in the FIN_WAIT1 state.",
        unsigned, TCP_FIN_WAIT1, val)
OO_STAT("Number of TCP sockets currently in the FIN_WAIT2 state.",
        unsigned, TCP_FIN_WAIT2, val)
OO_STAT("Number of TCP sockets currently in the CLOSING state.",
        unsigned, TCP_CLOSING, val)
OO_STAT("Number of TCP sockets currently in the TIME_WAIT state.",
        unsigned, TCP_TIME_WAIT, val)
OO_STAT("Number of endpoints allocated but not currently used",
        unsigned, TCP_STATE_FREE, val)
OO_STAT("Number of UDP sockets",
        unsigned, TCP_STATE_UDP, val)
/* PIPE needs to be kept even for
 * non-PIPE builds */
OO_STAT("Number of pipes",
        unsigned, TCP_STATE_PIPE, val)
OO_STAT("Aux buffers are used to store half-open TCP socket information.",
        unsigned, TCP_STATE_AUXBUF, val)
OO_STAT("Used for EF_TCP_SHARED_LOCAL_PORTS",
        unsigned, TCP_STATE_ACTIVE_WILD, val)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, BAD_STATE, val)

OO_STAT("An orphan socket is one that does not have an associated "
        "fd.  e.g. not yet accepted, or recently closed but still waiting to "
        "be finalised.",
        unsigned, sock_orphans, val)
OO_STAT("A thread tried to receive; couldn't do so immediately, and slept.  "
        "This count is for it getting woken up again.  This can mean there "
        "was no data available, and spin timed out.",
        unsigned, sock_wake_needed_rx, val)
OO_STAT("A thread tried to transmit; couldn't do so immediately, and slept.  "
        "This count is for it getting woken up again.  This usually means "
        "TCP sends are being held off by window or cwnd.",
        unsigned, sock_wake_needed_tx, val)
OO_STAT("The number of TCP sockets that currently have data in a receive "
        "queue.",
        unsigned, tcp_has_recvq, val)
OO_STAT("The number of bytes currently waiting in TCP receive "
        "queues.",
        unsigned, tcp_recvq_bytes, val)
OO_STAT("The number of packets currently waiting in TCP receive queues.",
        unsigned, tcp_recvq_pkts, val)
OO_STAT("The number of sockets with packets in the re-ordering queue.  "
        "Re-ordering usually (though not always) indicates loss.  We hold on "
        "to the future packets until the intervening ones arrive, then push "
        "them to the receive queue.  So unless Onload is currently waiting "
        "for some retransmits; this counter will be zero.  It is not a "
        "historical log.",
        unsigned, tcp_has_recv_reorder, val)
OO_STAT("The number of packets currently in re-ordering queues.  Re-ordering "
        "usually (though not always) indicates loss.  We hold on to the "
        "future packets until the intervening ones arrive, then push them "
        "to the receive queue.  So unless Onload is currently waiting for "
        "some retransmits; this counter will be zero.  It is not a "
        "historical log.",
        unsigned, tcp_recv_reorder_pkts, val)
OO_STAT("The number of TCP sockets with packets in the send queue; see also "
        "'send+pre=' in the per-socket counts.  This counter will usually be "
        "zero; unless something is preventing Onload from sending "
        "immediately (e.g. congestion window)",
        unsigned, tcp_has_sendq, val)
OO_STAT("The count of bytes in TCP send queues; see also 'send+pre=' in the "
        "per-socket counts.  This counter will usually be zero; unless "
        "something is preventing Onload from sending immediately (e.g. "
        "congestion window)",
        unsigned, tcp_sendq_bytes, val)
OO_STAT("The number of packets in TCP send queues; see also 'send+pre=' in "
        "the per-socket counts.  This counter will usually be zero; unless "
        "something is preventing Onload from sending immediately (e.g. "
        "congestion window)",
        unsigned, tcp_sendq_pkts, val)
OO_STAT("The number of sockets that have packets 'in-flight' - i.e. sent "
        "but Onload has not yet received an ACK for.  See also 'inflight=' "
        "in the per-socket stats.",
        unsigned, tcp_has_inflight, val)
OO_STAT("The number of bytes that are 'in-flight' - i.e. sent but Onload has "
        "not yet received an ACK for.  See also 'inflight=' in the "
        "per-socket stats.",
        unsigned, tcp_inflight_bytes, val)
OO_STAT("The number of packets 'in-flight' - i.e. sent but Onload has not "
        "yet received an ACK for.  See also 'inflight=' in the "
        "per-socket stats.",
        unsigned, tcp_inflight_pkts, val)
OO_STAT("Number of sockets in SYN-RECEIVED state.  The size of the listen "
        "queue is limited by EF_TCP_BACKLOG_MAX",
        unsigned, tcp_n_in_listenq, val)
OO_STAT("Number of sockets that have reached ESTABLISHED state, that the "
        "application has not yet called accept() for.",
        unsigned, tcp_n_in_acceptq, val)
OO_STAT("The number of UDP sockets that have data waiting in the receive "
        "queue.  See also 'rcv: q_pkts' in the per-socket statistics.",
        unsigned, udp_has_recvq, val)
OO_STAT("The number of packets waiting in UDP receive queues.  See also "
        "'rcv: q_pkts' in the per-socket statistics.",
        unsigned, udp_recvq_pkts, val)
OO_STAT("The number of UDP sockets that have data waiting in the send queue.",
        unsigned, udp_has_sendq, val)
OO_STAT("The number of bytes currently waiting in UDP send queues.",
        unsigned, udp_sendq_bytes, val)
OO_STAT("The total number of UDP packets received at user level.",
        unsigned, udp_tot_recv_pkts_ul, count)
OO_STAT("The total number of UDP packets dropped at user level - e.g. due "
        "to queue overflow, or memory pressure.  This is not an exhaustive "
        "counter; drops can still occur at other levels of the system.",
        unsigned, udp_tot_recv_drops_ul, count)
OO_STAT("The total number of UDP packets received via the kernel.  This "
        "count is also available per socket (tot_pkts minus ul)",
        unsigned, udp_tot_recv_pkts_os, count)
OO_STAT("The total number of UDP packets sent from user level.  This count "
        "is also available per socket (ul=)",
        unsigned, udp_tot_send_pkts_ul, count)
OO_STAT("The total number of UDP packets sent via the kernel.  A small "
        "count is normal, for route resolution purposes.  This count is "
        "also available per socket (os=).",
        unsigned, udp_tot_send_pkts_os, count)
OO_STAT("Only applicable to older cards; internal error.",
        unsigned, ef_vi_rx_ev_lost, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_rx_ev_bad_desc_i, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_rx_ev_bad_q_label, count)
OO_STAT(MORE_STATS_DERIVED_DESC,
        unsigned, ef_vi_evq_gap, count)
