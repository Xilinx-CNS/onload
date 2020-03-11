/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
OO_STAT("Number of SYN/ACKs sent with ISN chosen according to SYN "
        "cookie technique.",
        CI_IP_STATS_TYPE, syncookies_sent, count)
OO_STAT("Number of times syncookie in incoming ACK segments are accessed.",
        CI_IP_STATS_TYPE, syncookies_recv, count)
OO_STAT("Number of times syncookie in incoming ACK segments fail "
        "validation.",
        CI_IP_STATS_TYPE, syncookies_failed, count)
OO_STAT("Number of times connection estatblishment procedure was aborted in "
        "SYN-RECEIVED state.",
        CI_IP_STATS_TYPE, embrionic_rsts, count)
OO_STAT("Number of times procedure for finding an additional memory for "
        "RX buffer is calle.",
        CI_IP_STATS_TYPE, prune_called, count)
OO_STAT("Number of times procedure fails to find an additional room for "
        "incoming data.",
        CI_IP_STATS_TYPE, rcv_pruned, count)
OO_STAT("Number of times out-of-order queue was destructed to liberate an "
        "additional memory for incoming data.",
        CI_IP_STATS_TYPE, ofo_pruned, count)
OO_STAT("Number of ICMP messages received in response to a TCP segment whose "
        "sequence number is out of the current window.",
        CI_IP_STATS_TYPE, out_of_window_icmps, count)
OO_STAT("Number of dropped ICMP messages due to connection is busy and "
        "cannot process it.",
        CI_IP_STATS_TYPE, lock_dropped_icmps, count)
OO_STAT("it is not obvious what it meant, currently it is set to zero.",
        CI_IP_STATS_TYPE, arp_filter, count_zero)
OO_STAT("Number of sockets that passed from TIME-WAIT to CLOSED state by "
        "timeout specified for TIME-WAIT state.",
        CI_IP_STATS_TYPE, time_waited, count)
OO_STAT("Number of connections that were recycled in TIME-WAIT queue before "
        "the timeout expires.",
        CI_IP_STATS_TYPE, time_wait_recycled, count)
OO_STAT("Number of connections that were killed in TIME-WAIT queue before "
        "the timeout expires.",
        CI_IP_STATS_TYPE, time_wait_killed, count)
OO_STAT("Number of SYN segments destined to a socket in LISTENING state "
        "that were rejected due to PAWS checking fails.",
        CI_IP_STATS_TYPE, paws_passive_rejected, count)
OO_STAT("Number of ACK segments destined to a socket in SYN-SEND state "
        "that were rejected due to the failure of checking against 'TSecr' "
        "field of timestamp option.",
        CI_IP_STATS_TYPE, paws_active_rejected, count)
OO_STAT("Number of segments rejected due to PAWS checking fails.",
        CI_IP_STATS_TYPE, paws_estab_rejected, count)
OO_STAT("Number of segments allowed despite missing timestamp option.",
        CI_IP_STATS_TYPE, tso_missing, count)
OO_STAT("Number of ACKs sent in delayed manner.",
        CI_IP_STATS_TYPE, delayed_ack, count)
OO_STAT("Number of times procedure of sending delayed ACK was "
        "initiated on locked socket.",
        CI_IP_STATS_TYPE, delayed_ack_locked, count)
OO_STAT("Number of segments whose end sequence number is less than RCV.NXT "
        "value.",
        CI_IP_STATS_TYPE, delayed_ack_lost, count)
OO_STAT("Number of times established connection was dropped due to the lack "
        "of room in accept queue of listening socket.",
        CI_IP_STATS_TYPE, listen_overflows, count)
OO_STAT("Number of times listening socket drops established connections after "
        "receiving ACK from the peer due to lack of packet buffers to reserve.",
        CI_IP_STATS_TYPE, listen_no_pkts, count)
OO_STAT("Number of times listening socket drops established connections after "
        "receiving ACK from the peer due to some reason.",
        CI_IP_STATS_TYPE, listen_drops, count)

#define TCP_EXT_STATS_COUNT_LINUX_BUF \
        "not relevant to Onload stack"
/* the following set of counters deals with linux-specific buffering "
 * scheme, Onload stack does not use these way of buffering */
OO_STAT(TCP_EXT_STATS_COUNT_LINUX_BUF,
        CI_IP_STATS_TYPE, tcp_prequeued, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_LINUX_BUF,
        CI_IP_STATS_TYPE, tcp_direct_copy_from_backlog, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_LINUX_BUF,
        CI_IP_STATS_TYPE, tcp_direct_copy_from_prequeue, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_LINUX_BUF,
        CI_IP_STATS_TYPE, tcp_prequeue_dropped, count_zero)
#undef TCP_EXT_STATS_COUNT_LINUX_BUF

OO_STAT("Number of times data segment passed through 'header prediction' "
        "mechanism and its data put into receive queue.",
        CI_IP_STATS_TYPE, tcp_hp_hits, count)
OO_STAT("Number of times data segment passes through 'header prediction' "
        "mechanism and the data is put directly into user_prepared buffer instead "
        "of receive queue.",
        CI_IP_STATS_TYPE, tcp_hp_hits_to_user, count)
OO_STAT("Number of pure ACKs received - segments with only ACK bit set and "
        "without any data.",
        CI_IP_STATS_TYPE, tcp_pure_acks, count)
OO_STAT("Number of received ACK segments that force shifting unacknowledged "
        "sequence number and processed over fast path.",
        CI_IP_STATS_TYPE, tcp_hp_acks, count)
OO_STAT("Number of times connections entered in recovery state with SACK "
        "disabled.",
        CI_IP_STATS_TYPE, tcp_reno_recovery, count)
OO_STAT("Number of times connections entered in recovery state with SACK "
        "enabled.",
        CI_IP_STATS_TYPE, tcp_sack_recovery, count)
OO_STAT("Number of times we receiber ACK segments that acknowledges sequence "
        "number inside the interval of SACKed sequence numbers.",
        CI_IP_STATS_TYPE, tcp_sack_reneging, count)

#define TCP_EXT_STATS_COUNT_REORDER \
"each counter in the following group is responsible for the number of " \
"reorders detected basing on a particular type of detection"
OO_STAT(TCP_EXT_STATS_COUNT_REORDER,
        CI_IP_STATS_TYPE, tcp_fack_reorder, count)
OO_STAT(TCP_EXT_STATS_COUNT_REORDER,
        CI_IP_STATS_TYPE, tcp_sack_reorder, count)
OO_STAT(TCP_EXT_STATS_COUNT_REORDER,
        CI_IP_STATS_TYPE, tcp_reno_reorder, count)
OO_STAT(TCP_EXT_STATS_COUNT_REORDER,
        CI_IP_STATS_TYPE, tcp_ts_reorder, count)
#undef TCP_EXT_STATS_COUNT_REORDER

OO_STAT("Number of acknowledgements received for the last SN sent, "
        "but not acknowledged yet when the connection was not in the LOSS state.",
        CI_IP_STATS_TYPE, tcp_full_undo, count)
OO_STAT("Number of acknowledgements we receive from the range "
        "( the last SN acknowledged by ACK; the last SN sent, but not ackn. yet ), "
        "after which we leaved recovery state.",
        CI_IP_STATS_TYPE, tcp_partial_undo, count)
OO_STAT("Number of acknowledgements received for the last SN sent, "
        "but not acknowledged yet when the connection was in the LOSS state.",
        CI_IP_STATS_TYPE, tcp_loss_undo, count)
OO_STAT("this counter deals with DSACK and linux-specific state machine, so in "
        "Onload stack it should be set to zero.",
        CI_IP_STATS_TYPE, tcp_sack_undo, count_zero)
OO_STAT("Number of data loss detected by SACK.",
        CI_IP_STATS_TYPE, tcp_loss, count)
OO_STAT("Number of retransmitted segments that were lost as it was "
        "discovered by SACK.",
        CI_IP_STATS_TYPE, tcp_lost_retransmit, count)

  /** the following set of counters is incremented depending of
   * the state of NewReno/SCK/FACK/ECN state machine (linux-specific)
   * **************************************************************
   * * State    *           SACK         *        Not SACK        *
   * **************************************************************
   * * Recovery * tcp_sack_recovery_fail * tcp_reno_recovery_fail *
   * **************************************************************
   * * Disorder *    tcp_sack_failures   *    tcp_reno_failures   *
   * **************************************************************
   * * Loss     *    tcp_loss_failures   *    tcp_loss_failures   *
   * **************************************************************
   * * Other    *       tcp_timeouts     *       tcp_timeouts     *
   * **************************************************************
   */

#define TCP_EXT_STATS_COUNT_RENO \
  "NewReno/SCK/FACK/ECN state machine specific - in Onload stack it should be zero"
OO_STAT(TCP_EXT_STATS_COUNT_RENO,
        CI_IP_STATS_TYPE, tcp_reno_failures, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_RENO,
        CI_IP_STATS_TYPE, tcp_sack_failures, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_RENO,
        CI_IP_STATS_TYPE, tcp_loss_failures, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_RENO,
        CI_IP_STATS_TYPE, tcp_timeouts, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_RENO,
        CI_IP_STATS_TYPE, tcp_reno_recovery_fail, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_RENO,
        CI_IP_STATS_TYPE, tcp_sack_recovery_fail, count_zero)
#undef TCP_EXT_STATS_COUNT_RENO

OO_STAT("Number of retransmitis made in recovery state (fast retransmits).",
        CI_IP_STATS_TYPE, tcp_fast_retrans, count)
OO_STAT("Number of retransmits made while the connection runs slow start "
        "algorithm.",
        CI_IP_STATS_TYPE, tcp_forward_retrans, count)
OO_STAT("not tcp_fast_retrans nor tcp_forward_retrans.",
        CI_IP_STATS_TYPE, tcp_slow_start_retrans, count)

OO_STAT("this counter deals with scheduler of delayed ACKs and so far, "
        "in Onload stack it should be zero.",
        CI_IP_STATS_TYPE, tcp_scheduler_failures, count_zero)
OO_STAT("Number of received segments collapsed for some reason from "
        "out-of-order or receive queues.",
        CI_IP_STATS_TYPE, tcp_rcv_collapsed, count)
/* Onload stack does not support DSACK extendion of TCP, so the following set "
 * of counters in it should be set to zero */
#define TCP_EXT_STATS_COUNT_DSACK_EXT_NOT_SUPPORTED \
  "DSACK extension specific - in Onload stack it should be zero"
OO_STAT(TCP_EXT_STATS_COUNT_DSACK_EXT_NOT_SUPPORTED,
        CI_IP_STATS_TYPE, tcp_dsack_old_sent, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_DSACK_EXT_NOT_SUPPORTED,
        CI_IP_STATS_TYPE, tcp_dsack_ofo_sent, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_DSACK_EXT_NOT_SUPPORTED,
        CI_IP_STATS_TYPE, tcp_dsack_recv, count_zero)
OO_STAT(TCP_EXT_STATS_COUNT_DSACK_EXT_NOT_SUPPORTED,
        CI_IP_STATS_TYPE, tcp_dsack_ofo_recv, count_zero)
#undef TCP_EXT_STATS_COUNT_DSACK_EXT_NOT_SUPPORTED

OO_STAT("Number of SYN segments that caused a connection to be aborted "
        "( [RFC1213] page 71).",
        CI_IP_STATS_TYPE, tcp_abort_on_syn, count)
OO_STAT("Number of times socket was destroyed due to one of the following: "
        "(1) on closing the socket has no unread data in its receive queue and it "
        "also has SO_LINGER option set with l_linger field equals to zero; "
        "(2) data segment arrives on socket being in FIN-WAIT-1 or FIN_WAIT-2 "
        "state.",
        CI_IP_STATS_TYPE, tcp_abort_on_data, count)
OO_STAT("Number of times socket was closed remaining unread data in its "
        "receive queue.",
        CI_IP_STATS_TYPE, tcp_abort_on_close, count)
OO_STAT("Number of times orphan socket was destroyed due to the lack "
        "of resources.",
        CI_IP_STATS_TYPE, tcp_abort_on_memory, count)
OO_STAT("Number of times socket was destroyed due to some retransmission "
        "timer expires.",
        CI_IP_STATS_TYPE, tcp_abort_on_timeout, count)
OO_STAT("Number of times socket was destroyed just after close operation due "
        "to the value of TCP_LINGER2 socket option is set to some negative "
        "value.",
        CI_IP_STATS_TYPE, tcp_abort_on_linger, count)
OO_STAT("Number of times socket was destroyed just after close operation due "
        "to incomplete onload_delegated_send operation.",
        CI_IP_STATS_TYPE, tcp_abort_on_delegated_send, count)
OO_STAT("Number of times sending RST segment from a socket being terminated "
        "fails.",
        CI_IP_STATS_TYPE, tcp_abort_failed, count)
OO_STAT("some value related to memory management in linx TCP/IP stack.",
        CI_IP_STATS_TYPE, tcp_memory_pressures, count)
