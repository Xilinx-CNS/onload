/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Definition of stack statistics
**   \date  2008/04/25
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <ci/internal/transport_config_opt.h>

/*
 * OO_STAT(description, datatype, name, kind)
 */

#define MEMORY_PRESSURE_DESCRIPTION \
  "Memory pressure means Onload is out of packet buffers; and will "      \
  "drop packets until it recovers.  However, it only counts as memory "   \
  "pressure if we are unable to fill the RX ring.  Running out of "       \
  "memory for other purposes (e.g. transmit) will not necessarily "       \
  "trigger these counters; if receive is still functioning normally.  "

#define HANDOVER_DESCRIPTION(_x) \
  "All of the handover statistics represent sockets that have been handed "   \
  "to the kernel; and the call that was made that caused this."               \
  "  (In this case " #_x "with a TCP socket)  "                               \
  "Most often, this is caused by routing over a non-accelerated interface "   \
  "(including loopback; see EF_TCP_SERVER_LOOPBACK and "                      \
  "EF_TCP_CLIENT_LOOPBACK); but unsupported socket options and resource "     \
  "limitations can also cause this."

#define HANDOVER_DESCRIPTION_UDP(_x) \
  "All of the handover statistics represent sockets that have been handed "   \
  "to the kernel; and the call that was made that caused this."               \
  "  (In this case " #_x " with a UDP socket)  "                              \
  "Most often, this is caused by routing over a non-accelerated interface "   \
  "(including loopback); but unsupported socket options and resource "        \
  "limitations can also cause this."                                          \
  "Also check per-socket os= counts, as UDP sockets can receive and send "    \
  "via multiple interfaces, and so might not be handed over, but might not "  \
  "actually be accelerating traffic)"

OO_STAT("Number of times event queue was polled from kernel.  Expected to "
        "continually increment if interrupt driven, or using EF_UL_EPOLL=2",
        ci_uint32, k_polls, count)
OO_STAT("Number of times event queue was polled from user-level.",
        ci_uint32, u_polls, count)
OO_STAT("Number of times event queue was polled from user-level with ioctl.",
        ci_uint32, ioctl_evq_polls, count)
OO_STAT("Number of RX events handled.  Not always 1:1 with number of "
        "packets received, an event can cover a batch of packets in "
        "high-throughput mode.",
        ci_uint32, rx_evs, count)
OO_STAT("Number of TX events handled.  Not always 1:1 with number of "
        "packets sent - batching is done at higher rates.",
        ci_uint32, tx_evs, count)
OO_STAT("Number of times periodic timer has polled for events.  Indicates "
        "your application has not made accelerated calls for a long period.",
        ci_uint32, periodic_polls, count)
OO_STAT("Number of network events handled by periodic timer.  Indicates your "
        "application stopped making accelerated networking calls for a time, "
        "while the network was active.",
        ci_uint32, periodic_evs, count)
OO_STAT("Number of times periodic timer could not get the stack lock.  "
        "Not severe.",
        ci_uint32, periodic_lock_contends, count)
OO_STAT("Number of interrupts.  Expected if interrupt driven; otherwise "
        "suggests timeout of one kind or another.",
        ci_uint32, interrupts, count)
OO_STAT("Number of times an interrupt polled for network events.  If "
        "significantly less than number of interrutps, usually indicates "
        "user mode and the interrupt were active nearly simultaneously.",
        ci_uint32, interrupt_polls, count)
OO_STAT("Number of network events handled in interrupts.  Roughly "
        "proportional to traffic levels.",
        ci_uint32, interrupt_evs, count)
OO_STAT("Number of times an interrupt woke one or more processes.  i.e. "
        "threads were sleeping (not spinning) waiting for this data.",
        ci_uint32, interrupt_wakes, count)
OO_STAT("Number of times interrupts were re-enabled from another interrupt.  "
        "See also muxer_primes.",
        ci_uint32, interrupt_primes, count)
OO_STAT("Number of times an interrupt found no network events.  Indicates "
        "that user mode was racing, and got to them first.",
        ci_uint32, interrupt_no_events, count)
OO_STAT("Number of times an interrupt could not lock the stack.  Usually "
        "indicates that user mode was racing, and it was a photo-finish, "
        "with user mode in front.",
        ci_uint32, interrupt_lock_contends, count)
OO_STAT("Number of times an interrupt handler was limited by NAPI budget.  "
        "This potentially leads to drops if there's a microburst.",
        ci_uint32, interrupt_budget_limited, count)
OO_STAT("Number of times poll has been deferred to lock holder.  i.e. There "
        "was contention, and this reader thread gave way.",
        ci_uint32, deferred_polls, count)
OO_STAT("Number of timeout interrupts.  Timeout interrupts mean no "
        "accelerated networking call was made for at least "
        "EF_HELPER_PRIME_USEC.  Some at start-up are normal, otherwise this "
        "risks nodesc drops.",
        ci_uint32, timeout_interrupts, count)
OO_STAT("Number of times timeout interrupts polled for network events.  "
        "Timeout interrupts mean no networking call was made for at least "
        "EF_HELPER_PRIME_USEC.  Some at start-up are normal, otherwise "
        "risks nodesc drops.",
        ci_uint32, timeout_interrupt_polls, count)
OO_STAT("Number of network events handled in timeout interrupts.  Some "
        "during start-up are normal, but incrementing while the application "
        "is active likely indicates a problem.  Ensure that "
        "your application makes network calls to each stack frequently; and "
        "is not being descheduled.  The time this is not a problem is "
        "acknowledging transmit-complete, so also check rx_evs vs tx_evs.",
        ci_uint32, timeout_interrupt_evs, count)
OO_STAT("Number of times a timeout interrupt woke one or more processes.  "
        "This is an indication of a problem - a process was sleeping for the "
        "data, but normal interrupts had not been enabled.  Possibly you "
        "have EF_INT_DRIVEN disabled, but have not enabled spinning instead?",
        ci_uint32, timeout_interrupt_wakes, count)
OO_STAT("Number of times timeout interrupts found no network events.  Much "
        "less severe than timeout_interrupt_evs; though it still indicates "
        "the application is not making network calls promptly.",
        ci_uint32, timeout_interrupt_no_events, count)
OO_STAT("Number of times timeout interrupts could not lock the stack.  This "
        "usually indicates that your application got descheduled while it was "
        "in the middle of a networking call.",
        ci_uint32, timeout_interrupt_lock_contends, count)
OO_STAT("Number of times select/poll/epoll enabled interrupts.  i.e. reached "
        "the spin timeout without returning data.",
        ci_uint32, muxer_primes, count)
OO_STAT("Number of times Onload needed to enable interrupts to wait for a "
        "packet allocation to be available.",
        ci_uint32, pkt_wait_primes, count)
OO_STAT("Times a thread has blocked on a single socket.",
        ci_uint32, sock_sleeps, count)
OO_STAT("Times a thread has enabled interrupts before blocking on a socket.",
        ci_uint32, sock_sleep_primes, count)
OO_STAT("Times Onload has woken threads waiting on a socket for receive.",
        ci_uint32, sock_wakes_rx, count)
OO_STAT("Times Onload has woken threads waiting on a socket for transmit.",
        ci_uint32, sock_wakes_tx, count)
OO_STAT("Times OS has woken threads waiting on an Onload socket for receive.",
        ci_uint32, sock_wakes_rx_os, count)
OO_STAT("Times OS has woken threads waiting on an Onload socket for transmit.",
        ci_uint32, sock_wakes_tx_os, count)
OO_STAT("Times Onload has potentially sent a signal due to O_ASYNC.",
        ci_uint32, sock_wakes_signal, count)
#if CI_CFG_PKTS_AS_HUGE_PAGES
OO_STAT("Number of huge pages allocated for packet sets.",
        ci_uint32, pkt_huge_pages, count)
#endif
OO_STAT("Usually an indication of contention (and thus jitter) - the "
        "(slower, but threadsafe) nonb pool is used when a send is unable to "
        "take the stack lock.  But it has other uses too; "
        "see EF_UDP_SEND_UNLOCK_THRESH.",
        ci_uint32, pkt_nonb, count)
OO_STAT("Indicates that we've reclaimed from the pkt_nonb (e.g. due to "
        "memory pressure; but may be just contention with the ring refill "
        "path).  Check for memory_pressure.",
        ci_uint32, pkt_nonb_steal, count)
OO_STAT("Times we've woken threads waiting for free packet buffers.  Can "
        "occur during memory_pressure.",
        ci_uint32, pkt_wakes, count)
OO_STAT("Number of times we've scrambled (l0) to find free buffers.  "
        "Indication of severe memory_pressure.",
        ci_uint32, pkt_scramble0, count)
OO_STAT("Number of times we've scrambled (l1) to find free buffers.  "
        "Indication of severe memory_pressure.",
        ci_uint32, pkt_scramble1, count)
OO_STAT("Number of times we've scrambled (l2) to find free buffers.  "
        "Indication of severe memory_pressure.",
        ci_uint32, pkt_scramble2, count)
OO_STAT("Number of times something tried to allocate memory, and "
        "span, waiting to do so.",
        ci_uint32, pkt_wait_spin, count)
OO_STAT("Number of times we came to release the lock; but then found more "
        "work to do.  The various unlock_slow_ counts contribute to this.",
        ci_uint32, unlock_slow, count)
OO_STAT("We came to release the lock - and something was waiting for more "
        "packet memory to be available, and it now is, so we inform it.",
        ci_uint32, unlock_slow_pkt_waiter, count)
OO_STAT("We came to release the lock and some sockets had deferred work onto "
        "the thread that was the stack-lock holder.",
        ci_uint32, unlock_slow_socket_list, count)
OO_STAT("We came to release the lock and we needed to enable interrupts.",
        ci_uint32, unlock_slow_need_prime, count)
OO_STAT("We primed interrupts at user level when releasing the stack lock.",
        ci_uint32, unlock_slow_prime_ul, count)
OO_STAT("We came to release the lock and we needed to wake some other "
        "threads up.  (e.g. data it was waiting for is now available, or to "
        "give it a chance to take the lock.)",
        ci_uint32, unlock_slow_wake, count)
OO_STAT("We came to release the lock and needed to update software filters.",
        ci_uint32, unlock_slow_swf_update, count)
OO_STAT("We came to release the lock and needed to close sockets/pipes.",
        ci_uint32, unlock_slow_close, count)
#if CI_CFG_WANT_BPF_NATIVE
OO_STAT("We came to release the lock and needed to handle change in XDP prog",
        ci_uint32, unlock_slow_xdp_change, count)
#endif
OO_STAT("We came to release the lock and had to make a system call - usually "
        "this will be to wake up another thread.",
        ci_uint32, unlock_slow_syscall, count)
OO_STAT("A thread blocked trying to take the stack lock it could not defer "
        "its work to the stack-lock holding thread) and had to be woken up "
        "now that the lock is available.",
        ci_uint32, lock_wakes, count)
OO_STAT("Times a thread has spun waiting for the stack lock.  Indication of "
        "contention (not high) wanted to take the lock; smoething else had "
        "it, so it retried for a while.  See  EF_BUZZ_USEC.",
        ci_uint32, stack_lock_buzz, count)
OO_STAT("Times work has been done by the lock holder for another thread.  "
        "This is a mitigation mechanism for contention - which means that "
        "multiple threads are accessing this stack simultaneously.",
        ci_uint32, deferred_work, count)
OO_STAT("Times a thread has slept waiting for a socket lock.",
        ci_uint32, sock_lock_sleeps, count)
OO_STAT("Times a thread has spun waiting for a socket lock.",
        ci_uint32, sock_lock_buzz, count)
OO_STAT("Number of times TCP sendmsg() found the non-blocking pool empty.",
        ci_uint32, tcp_send_nonb_pool_empty, count)
OO_STAT("Number of times TCP sendmsg() contended the stack lock.",
        ci_uint32, tcp_send_ni_lock_contends, count)
OO_STAT("Number of times TCP sendmsg() failed to find an acceleratable route.",
        ci_uint32, tcp_send_fail_noroute, count)
OO_STAT("Number of times UDP sendmsg() contended the stack lock.",
        ci_uint32, udp_send_ni_lock_contends, count)
OO_STAT("Number of times getsockopt() contended the stack lock.",
        ci_uint32, getsockopt_ni_lock_contends, count)
OO_STAT("Number of times setsockopt() contended the stack lock.",
        ci_uint32, setsockopt_ni_lock_contends, count)
OO_STAT("Multicast loop-back sends.",
        ci_uint32, udp_send_mcast_loop, count)
OO_STAT("Multicast loop-back send was dropped due to RX packet buffer limit.",
        ci_uint32, udp_send_mcast_loop_drop, count)
OO_STAT("Number of active opens that reached established.",
        ci_uint32, active_opens, count)
OO_STAT(HANDOVER_DESCRIPTION(socket),
        ci_uint32, tcp_handover_socket, count)
OO_STAT(HANDOVER_DESCRIPTION(bind) 
        "  If attempting loopback, see EF_TCP_SERVER_LOOPBACK",
        ci_uint32, tcp_handover_bind, count)
OO_STAT(HANDOVER_DESCRIPTION(listen),
        ci_uint32, tcp_handover_listen, count)
OO_STAT("This indicates that a connection came in from a non-accelerated "
        "interface.",
        ci_uint32, tcp_accept_os, count)
OO_STAT(HANDOVER_DESCRIPTION(connect),
        ci_uint32, tcp_handover_connect, count)
OO_STAT(HANDOVER_DESCRIPTION(setsockopt),
        ci_uint32, tcp_handover_setsockopt, count)
OO_STAT(HANDOVER_DESCRIPTION_UDP(socket),
        ci_uint32, udp_handover_socket, count)
OO_STAT(HANDOVER_DESCRIPTION_UDP(bind),
        ci_uint32, udp_handover_bind, count)
OO_STAT(HANDOVER_DESCRIPTION_UDP(connect),
        ci_uint32, udp_handover_connect, count)
OO_STAT(HANDOVER_DESCRIPTION_UDP(setsockopt),
        ci_uint32, udp_handover_setsockopt, count)
OO_STAT("Bind() on a UDP socket found that we had insufficient filters "
        "available, so the socket was handed to the kernel.",
        ci_uint32, udp_bind_no_filter, count)
OO_STAT("Connect() on a UDP socket found that we had insufficient filters "
        "available, so the socket was handed to the kernel.",
        ci_uint32, udp_connect_no_filter, count)
OO_STAT("Onload was short of socket buffers, and reclaimed sockets that were "
        "closing, but not yet fully closed.  This can cause resets to be "
        "sent; if the remote side later finalises the close sequence.",
        ci_uint32, timewait_reap, count)
#if CI_CFG_IPV6
OO_STAT("Connect() on TCP socket detected source and destination address"
        "family mismatch and handed socket to the kernel.",
        ci_uint32, tcp_connect_af_mismatch, count)
#endif
OO_STAT("Onload was short of filters, and reclaimed sockets that were "
        "closing, but not yet fully closed.  This can cause resets to be "
        "sent; if the remote side later finalises the close sequence.",
        ci_uint32, timewait_reap_filter, count)
OO_STAT("Max hops in the software-filter hash table lookup.",
        ci_uint32, table_max_hops, val)
OO_STAT("Rolling mean of number of hops in recent inserts to the software "
        "filter-table.",
        ci_uint32, table_mean_hops, val)
OO_STAT("Number of entries in software-filter hash table.",
        ci_uint32, table_n_entries, val)
OO_STAT("Number of slots occupied in software-filter hash table.",
        ci_uint32, table_n_slots, val)
#if CI_CFG_IPV6
OO_STAT("Max hops in the IPv6 software-filter hash table lookup.",
        ci_uint32, ipv6_table_max_hops, val)
OO_STAT("Rolling mean of number of hops in recent inserts to the "
        "IPv6 software filter-table.",
        ci_uint32, ipv6_table_mean_hops, val)
OO_STAT("Number of entries in IPv6 software-filter hash table.",
        ci_uint32, ipv6_table_n_entries, val)
OO_STAT("Number of slots occupied in IPv6 software-filter hash table.",
        ci_uint32, ipv6_table_n_slots, val)
#endif
OO_STAT("Number of retransmit timeouts, across all TCP sockets that stack "
        "has had.",
        ci_uint32, tcp_rtos, count)
#if CI_CFG_TAIL_DROP_PROBE
OO_STAT("Number of tail-drop probes sent from retransmit queue.",
        ci_uint32, tail_drop_probe_retrans, count)
OO_STAT("Number of tail-drop probes sent from send queue.",
        ci_uint32, tail_drop_probe_sendq, count)
OO_STAT("Number of tail-drop probes that were probably unnecessary.",
        ci_uint32, tail_drop_probe_unnecessary, count)
OO_STAT("Number of tail-drop probes that probably recovered loss.",
        ci_uint32, tail_drop_probe_success, count)
#endif
OO_STAT("Number of times a connection has been reset while in accept queue; "
        "not yet a fully-connected socket.",
        ci_uint32, rst_recv_acceptq, count)
OO_STAT("Number of times a connection has been reset while in the listen "
        "queue; not yet a fully-connected socket.",
        ci_uint32, rst_recv_synrecv, count)
OO_STAT("Number of RST packets destined to a socket in SYN-RECEIVED state "
        "that were rejected due to PAWS checking fails.",
        ci_uint32, rst_recv_synrecv_paws_rejected, count)
OO_STAT("Number of MacOS X style RST packets: after FIN, with the same "
        "sequence number as that FIN.  Such packets are accepted despite "
        "having \"unacceptable\" sequence numbers.",
        ci_uint32, rst_recv_after_fin, count)
OO_STAT("Number of connections reset with data still in the receive queue, "
        "waiting for the local application to consume it.",
        ci_uint32, rst_recv_has_recvq, count)
OO_STAT("Number of connections reset with data in the send queue.  (So there "
        "is likely to be data that we have told the application was accepted "
        "for send which the other side never sees)",
        ci_uint32, rst_recv_has_sendq, count)
OO_STAT("Number of connections reset with unacknowledged data.  So there "
        "was data on the wire which the other side may or may not have "
        "received.",
        ci_uint32, rst_recv_has_unack, count)
OO_STAT("We got sent a RST but it doesn't match up with anything.  "
        "We cannot match it to any current half-connected socket, or we "
        "could not understand its sequence number.  So we just ignore it.",
        ci_uint32, rst_recv_unacceptable, count)

OO_STAT("Onload has sent a RST packet because we got an ACKs we could not "
        "understand (e.g. ACKing a packet we didn't yet send).  Note: If "
        "rst_sent counts are all zero, but other side sees a reset, check "
        "whether the kernel sent it.",
        ci_uint32, rst_sent_unacceptable_ack, count)
OO_STAT("Number of RSTs sent due to a SYN that Onload does not understand.",
        ci_uint32, rst_sent_synrecv_bad_syn, count)
OO_STAT("Number of RSTs sent due to an ACK that Onload cannot see as valid, "
        "on a half-open socket in the SYNRECV state.",
        ci_uint32, rst_sent_synrecv_bad_ack, count)
OO_STAT("Number of RSTs sent because an ACK got sent to a listen socket.  "
        "We don't do anything special with this, window hosts do it "
        "fairly often.",
        ci_uint32, rst_sent_listen_got_ack, count)
OO_STAT("Number of RSTs sent due to remote side requesting TCP options we "
        "don't support.",
        ci_uint32, rst_sent_bad_options, count)
OO_STAT("Number of RSTs sent due to remote side sending a sequence number "
        "far too far away from normal for us to accept.  (i.e. it's not just "
        "some lost packets).",
        ci_uint32, rst_sent_bad_seq, count)
OO_STAT("We got a packet, but we didn't have a socket to match and decided not "
        "to forward it to the kernel, so we replied with a RST.",
        ci_uint32, rst_sent_no_match, count)
OO_STAT("Number of times that we forwarded a batch of packets to the kernel.",
        ci_uint32, no_match_pass_to_kernel_batches, count)
OO_STAT("We got a TCP packet, but we didn't have a socket to match, so we "
        "decided to forward it to the kernel.",
        ci_uint32, no_match_pass_to_kernel_tcp, count)
OO_STAT("We got a UDP packet, but we didn't have a socket to match, so we "
        "decided to forward it to the kernel.",
        ci_uint32, no_match_pass_to_kernel_udp, count)
OO_STAT("We got a non-TCP-non-UDP IP packet, so we decided to forward it to "
        "the kernel.",
        ci_uint32, no_match_pass_to_kernel_ip_other, count)
#if CI_CFG_IPV6
OO_STAT("We got a non-TCP-non-UDP IPv6 packet, so we decided to forward it to "
        "the kernel.",
        ci_uint32, no_match_pass_to_kernel_ip6_other, count)
#endif
OO_STAT("We got a non-IP packet, so we decided to forward it to the kernel.",
        ci_uint32, no_match_pass_to_kernel_non_ip, count)
OO_STAT("We got a packet, but we didn't have a socket to match, and we didn't "
        "forward it to the kernel because it didn't come via the network.",
        ci_uint32, no_match_bad_intf_i, count)
OO_STAT("We got a packet, but we didn't have a socket to match, and we didn't "
        "forward it to the kernel because we couldn't find the net device.",
        ci_uint32, no_match_bad_netdev, count)
OO_STAT("We got a packet, but we didn't have a socket to match, and we didn't "
        "forward it to the kernel because we couldn't allocate memory.",
        ci_uint32, no_match_oom, count)
OO_STAT("We got a packet, but we didn't have a socket to match, and it looks "
        "corrupted, so we do not forward it to the kernel",
        ci_uint32, no_match_corrupted, count)
OO_STAT("We got a packet, but we didn't have a socket to match, and we do "
        "not not have permission to forward it to the kernel (see "
        "inject_kernel_gid onload module parameter).",
        ci_uint32, no_match_dropped, count)
OO_STAT("We got a packet, but we didn't have a socket to match, but we "
        "have a matching ACTIVE_WILD endpoint "
        "(see EF_TCP_SHARED_LOCAL_PORTS enviroment variable).",
        ci_uint32, no_match_in_active_wild, count)


OO_STAT("Number of unacceptable (out of range) ACKs received.",
        ci_uint32, unacceptable_acks, count)
OO_STAT("Socket is closing, but we are unable to send the FIN (usually this "
        "means EF_MAX_TX_PACKETS has been reached) so we defer this FIN.",
        ci_uint32, tcp_cant_fin, count)
OO_STAT("We failed to send FIN at least ones, but have finally managed to "
        "send the FIN out.",
        ci_uint32, tcp_cant_fin_resolved, count)
OO_STAT("We failed to send FIN many times, and finally had dropped the "
        "connection in a way similar to retransmit timeout.",
        ci_uint32, tcp_cant_fin_dropped, count)
OO_STAT("Socket is in SYNRECV; and send retransmits the SYN-ACK handshake.",
        ci_uint32, synrecv_retransmits, count)
OO_STAT("Number of sends from SYNRECV state that failed.  (Out of memory?)",
        ci_uint32, synrecv_send_fails, count)
OO_STAT("Number of times half-open socket has been dropped due to timeout.",
        ci_uint32, synrecv_timeouts, count)
OO_STAT("Times a synrecv has been purged to make room for a new one - this "
        "may indicate a DOS attack; consider enabling SYN cookies to "
        "alleviate this.",
        ci_uint32, synrecv_purge, count)
OO_STAT("We received a SYN packet, but the accept queue was full, so we drop "
        "it rather than sending a SYN-ACK.  If it's a legitimate connection "
        "attempt, the remote side should re-transmit the SYN later; when "
        "hopefully the application will have processed the accept queue to "
        "make space for it.",
        ci_uint32, syn_drop_busy, count)
OO_STAT("We received a SYN, but we don't have an accelerated outgoing route "
        "for the SYN-ACK.  So we drop the connection attempt.",
        ci_uint32, syn_drop_no_return_route, count)
OO_STAT("Number of times a LISTEN socket has started a new half-open socket"
        "(in the listen queue; the SYN-RECV state)",
        ci_uint32, listen2synrecv, count)
OO_STAT("Number of times a socket has moved from the SYN-RECV state to the "
        "fully ESTABLISHED state.",
        ci_uint32, synrecv2established, count)
OO_STAT("Number of times accept() was accelerated.",
        ci_uint32, ul_accepts, count)
OO_STAT("Number of times accept() returned EAGAIN.",
        ci_uint32, accept_eagain, count)
OO_STAT("Number of failed aux-buffer allocations.",
        ci_uint32, aux_alloc_fails, count)
OO_STAT("Number of failed bucket-aux-buffer allocations.",
        ci_uint32, aux_bucket_alloc_fails, count)
OO_STAT("Times that accept() was called, but as a result of the "
        "TCP_DEFER_ACCEPT socket option (on the listening socket), we do not "
        "promote a half-opened connection from listen to accept queue until "
        "some data arrives from the client (or it reaches the timeout)",
        ci_uint32, accepts_deferred, count)
OO_STAT("Number of times we have sent a pure ACK packet.  Indicates that we "
        "are receiving data substantially more often than we are sending any.",
        ci_uint32, acks_sent, count)
OO_STAT("Number of TCP window updates sent.",
        ci_uint32, wnd_updates_sent, count)
OO_STAT("This means that Onload received a packet, and had to do something "
        "other than just put it onto the receive queue.  Usually just "
        "(indicates TCP where we have to update state machinery, reset "
        "timers, update windows, send out ACKs etc.)",
        ci_uint32, rx_slow, count)
OO_STAT("Packets arrived out of the expected sequence.  This could indicate "
        "loss or re-ordering in the network.",
        ci_uint32, rx_out_of_order, count)
OO_STAT("Number of TCP segments received in-order when ROB is non-empty.  "
        "This could indicate loss of our return selective-ACK; or it could "
        "indicate a higher latency connection where packets had already "
        "been sent ahead of the re-ordering being detected.",
        ci_uint32, rx_rob_non_empty, count)
OO_STAT("Number of TCP segments retransmited.",
        ci_uint32, retransmits, count)
OO_STAT("Number of ACK packets not sent in response of invalid incoming TCP "
        "packets because of rate limiting.",
        ci_uint32, invalid_ack_limited, count)
OO_STAT("Number of challenge ACKs sent (RFC 5961).",
        ci_uint32, challenge_ack_sent, count)
OO_STAT("Number of challenge ACKs not sent because of packet allocation "
        "failure.",
        ci_uint32, challenge_ack_out_of_pkts, count)
OO_STAT("Number of challenge ACKs not sent because of rate-limiting.",
        ci_uint32, challenge_ack_limited, count)
OO_STAT("Number of deferred packets when next hop MAC address is not known.",
        ci_uint32, tx_defer_pkt, count)
OO_STAT("Number of deferred packets sent without any real delay.",
        ci_uint32, tx_defer_pkt_fast, count)
OO_STAT("Number of deferred packets sent.",
        ci_uint32, tx_defer_pkt_sent, count)
OO_STAT("Number of deferred packets which were dropped because Onload failed "
        "to resolve the MAC address.",
        ci_uint32, tx_defer_pkt_drop_failed, count)
OO_STAT("Number of deferred packets which were dropped because the OS failed "
        "to resolve the MAC address.",
        ci_uint32, tx_defer_pkt_drop_arp_failed, count)
OO_STAT("Number of deferred packets which were dropped because of "
        "EF_DEFER_ARP_TIMEOUT timeout.",
        ci_uint32, tx_defer_pkt_drop_timeout, count)
OO_STAT("Number of dropped packets because of EF_DEFER_ARP_MAX limitation.",
        ci_uint32, tx_defer_pkt_drop_limited, count)
OO_STAT("Number of EF_EVENT_TYPE_TX_ERROR events.  A transmit failed.",
        ci_uint32, tx_error_events, count)
OO_STAT("Number of RX discards (checksum bad).",
        ci_uint32, rx_discard_csum_bad, count)
OO_STAT("Number of RX discards (inner checksum bad).",
        ci_uint32, rx_discard_inner_csum_bad, count)
OO_STAT("Number of RX discards (multicast mismatch).  On 7000 and newer, "
        "these will usually be discarded by the hardware; but some can get "
        "through if the socket was recently closed.",
        ci_uint32, rx_discard_mcast_mismatch, count)
OO_STAT("Number of RX discards (crc bad).",
        ci_uint32, rx_discard_crc_bad, count)
OO_STAT("Number of RX discards (frame truncated).  i.e. space was available "
        "for part, but not all, of a Jumbo frame.",
        ci_uint32, rx_discard_trunc, count)
OO_STAT("Number of RX discards (buffer ownership error).",
        ci_uint32, rx_discard_rights, count)
OO_STAT("Number of RX discards ( bad IP options;"
        "ie. Source routing or unknown option) ",
        ci_uint32, rx_discard_ip_options_bad, count)
OO_STAT("Number of RX discards (other).",
        ci_uint32, rx_discard_other, count)
OO_STAT("Number of times we have refilled RX ring from recv() path.  This is "
        "a short-cut path used when in a low-memory situation.",
        ci_uint32, rx_refill_recv, count)
OO_STAT("Number of RX packets detected from the future.",
        ci_uint32, rx_future, count)
OO_STAT("Number of RX packets detected from the future which did not complete.",
        ci_uint32, rx_future_rollback, count)
OO_STAT("Number of times we've tried to free packet-buffers by reaping.  "
        "Indicates that we are very close to a memory_pressure situation.",
        ci_uint32, reap_rx_limited, count)
OO_STAT("Entering the low-memory state that will cause rx_refill_recv.",
        ci_uint32, reap_buf_limited, count)
OO_STAT("Number of packet buffers reclaimed by reaping.",
        ci_uint32, pkts_reaped, count)
OO_STAT("We wanted to refill the RX ring, but lacked available buffers to "
        "do so.  This is likely to lead to nodesc drops at the interface.",
        ci_uint32, refill_rx_limited, count)
OO_STAT("Number of times we could not refill RX ring due to lack of buffers.",
        ci_uint32, refill_buf_limited, count)
OO_STAT("Deferred work is used to mitigate jitter due to contention.  But "
        "to prevent a thread monopolising the lock completely, there is a "
        "cap - which has been reached.  See EF_DEFER_WORK_LIMIT.",
        ci_uint32, defer_work_limited, count)
OO_STAT("Deferred work is used to mitigate jitter due to contention.  But "
        "if 2 threads try to defer work on the same socket, we sometimes "
        "fail to do the right thing.",
        ci_uint32, defer_work_contended_unsafe, count)
OO_STAT("Indicates that you're sending faster than we can push packets on to "
        "the wire; and the TX ring (default size 512, controlled via "
        "EF_TXQ_SIZE) has filled.  So we've has to hold packets in a queue.  "
        "And the maximum size that queue has reached, so sends will start to "
        "block or return EAGAIN.",
        ci_uint32, tx_dma_max, val)
OO_STAT("Number of TX DMA doorbells.",
        ci_uint32, tx_dma_doorbells, count)
OO_STAT("Unable to allocate more packet buffers.  It's possible that this is "
        "transient; or due to needing memory in a context where allocating "
        "is forbidden.  It's also posisble we're about to enter "
        "memory_pressure.  Expect to see a message 'Failed to allocate "
        "packet buffers' in the system log; giving more details as to the "
        "cause (commonly ENOSPC - indicating that the card buffer table "
        "is full) - see also bufset_alloc_nospace.",
        ci_uint32, bufset_alloc_fails, count)
OO_STAT("Number of attempts to allocate packet buffer set which have failed "
        "because of buffer table number limitation.  Note that when this "
        "is hit, we reduce EF_MAX_PACKETS to match the current allocation; "
        "in order to avoid printing a message repeatedly.  So it would be "
        "unlikely for this to increment multiple times.  To resolve this, "
        "make huge pages available, or look into EF_PACKET_BUFFER_MODE.",
        ci_uint32, bufset_alloc_nospace, count)
OO_STAT("Something has requested a larger MSS than we can support in a "
        "single packet buffer; so we've reduced it.  The maximum mss has "
        "multiple possibilities depending on card version.  "
        "It should be at least 1700 though.",
        ci_uint32, mss_limitations, count)
OO_STAT("Number of times stack has entered 'memory pressure' state.  "
        MEMORY_PRESSURE_DESCRIPTION
        "memory_pressure_enter counts how many times we've gone into this "
        "critical state",
        ci_uint32, memory_pressure_enter, count)
OO_STAT("Number of times stack has exited 'memory pressure' state via poll."
        MEMORY_PRESSURE_DESCRIPTION
        "If the total of the two exit counts is less than enter - we're "
        "still in it - also indicated by CRITICAL at the top of the stack.",
        ci_uint32, memory_pressure_exit_poll, count)
OO_STAT("Number of times stack has exited 'memory pressure' state via recv."
        MEMORY_PRESSURE_DESCRIPTION
        "If the total of the two exit counts is less than enter - we're "
        "still in it - also indicated by CRITICAL at the top of the stack.",
        ci_uint32, memory_pressure_exit_recv, count)
OO_STAT("Number of packets dropped due to 'memory pressure'."
        MEMORY_PRESSURE_DESCRIPTION
        "There will, very likely, also be additional nodesc drops - "
        "since we know that the RX ring is not being fully filled.",
        ci_uint32, memory_pressure_drops, count)
OO_STAT("A UDP packet has arrived into the Onload stack, but it doesn't "
        "actually match any of our sockets.  Could be it arrived from a "
        "different interface or vlan (and the socket has bind_to_device set); "
        "or the socket just closed (and there were already matching packets"
        "in the RX ring).",
        ci_uint32, udp_rx_no_match_drops, count)
OO_STAT("We've been asked to free up a UDP socket (i.e. nothing references "
        "that fd any more) - but there are still some transmits waiting to "
        "complete.  The socket will be freed up once those transmits complete.",
        ci_uint32, udp_free_with_tx_active, count)
OO_STAT("We've run out of space in the filter table; on the host.  "
        "Try increasing EF_MAX_ENDPOINTS",
        ci_uint32, sw_filter_insert_table_full, count)
#if CI_CFG_PIO
OO_STAT("Number of times PIO has been used to send a packet",
        ci_uint32, pio_pkts, count)
# ifndef NDEBUG
OO_STAT("Number of times PIO was not used due to packet length",
        ci_uint32, no_pio_too_long, count)
OO_STAT("Number of times PIO was not used due to flags",
        ci_uint32, no_pio_busy, count)
# endif
OO_STAT("Number of times PIO was not used due to an error",
        ci_uint32, no_pio_err, count)
#endif
#if CI_CFG_CTPIO
OO_STAT("Number of times CTPIO has been used to send a packet",
        ci_uint32, ctpio_pkts, count)
OO_STAT("Number of times CTPIO transmits have fallen back to DMA",
        ci_uint32, ctpio_dma_fallbacks, count)
#endif
OO_STAT("Number of calls to sendpage() for a connected TCP socket.",
        ci_uint32, tcp_sendpages, count)
OO_STAT("TCP wants to reply; (e.g. sending an ACK) was not able to re-use "
        "the packet buffer (e.g. because it contains data that the "
        "application has not yet consumed) and was further unable to "
        "allocate a fresh packet buffer.  Maybe increase EF_MAX_TX_PACKETS?",
        ci_uint32, poll_no_pkt, count)
#if CI_CFG_SPIN_STATS
OO_STAT("Number of loops spent in TCP recv() code while busy-waiting",
        ci_uint64, spin_tcp_recv, count)
OO_STAT("Number of loops spent in TCP send() code while busy-waiting",
        ci_uint64, spin_tcp_send, count)
OO_STAT("Number of loops spent in UDP send() code while busy-waiting",
        ci_uint64, spin_udp_send, count)
OO_STAT("Number of loops spent in UDP recv() code while busy-waiting",
        ci_uint64, spin_udp_recv, count)
OO_STAT("Number of loops spent in pipe read() code while busy-waiting",
        ci_uint64, spin_pipe_read, count)
OO_STAT("Number of loops spent in pipe write() code while busy-waiting",
        ci_uint64, spin_pipe_write, count)
OO_STAT("Number of loops spent in TCP accept() code while busy-waiting",
        ci_uint64, spin_tcp_accept, count)
OO_STAT("Number of loops spent in TCP connect() code while busy-waiting",
        ci_uint64, spin_tcp_connect, count)
OO_STAT("Number of loops spent in waiting for a free packet while busy-waiting",
        ci_uint64, spin_pkt_wait, count)
OO_STAT("Number of loops x sockets spent in select() busy-waiting",
        ci_uint64, spin_select, count)
OO_STAT("Number of loops x sockets spent in poll() busy-waiting",
        ci_uint64, spin_poll, count)
OO_STAT("Number of loops x sockets spent in epoll_wait() busy-waiting, "
        "with EF_UL_EPOLL=1",
        ci_uint64, spin_epoll, count)
OO_STAT("Number of loops x sockets spent in epoll_wait() busy-waiting, "
        "with EF_UL_EPOLL=2",
        ci_uint64, spin_epoll_kernel, count)
#endif
#if CI_CFG_FD_CACHING
OO_STAT("Number of sockets cached over lifetime of the stack",
        ci_uint32, sockcache_cached, count)
OO_STAT("Number of sockets not cached owing to lock contention",
        ci_uint32, sockcache_contention, count)
OO_STAT("Number of passive sockets not cached owing to stack limit.  "
        "See EF_SOCKET_CACHE_MAX",
        ci_uint32, passive_sockcache_stacklim, count)
OO_STAT("Number of active sockets not cached owing to stack limit  "
        "See EF_SOCKET_CACHE_MAX",
        ci_uint32, active_sockcache_stacklim, count)
#if ! CI_CFG_IPV6
OO_STAT("Number of active sockets not cached as being non-IPv4",
        ci_uint32, active_sockcache_non_ip4, count)
#endif
OO_STAT("Number of times active cached sockets had their fd attached to "
        "existing file",
        ci_uint32, active_attach_fd, count)
OO_STAT("Number of times active cached sockets had their fd already present",
        ci_uint32, active_attach_fd_reuse, count)
OO_STAT("Number of times active cached sockets couldn't have their fd attached "
         "to existing file",
        ci_uint32, active_attach_fd_fail, count)
OO_STAT("Number of sockets not cached owing to per-socket limit  "
        "See EF_SOCKET_CACHE_MAX",
        ci_uint32, sockcache_socklim, count)
OO_STAT("Number of times socket caching was successful.",
        ci_uint32, sockcache_hit, count)
OO_STAT("Socket cache failed due to lack of resources, reclaimed some, "
        "and then succeeded.",
        ci_uint32, sockcache_hit_reap, count)
OO_STAT("Number of socket-cache misses due to mismatched interfaces",
        ci_uint32, sockcache_miss_intmismatch, count)
OO_STAT("Number of active sockets cached over lifetime of the stack",
        ci_uint32, activecache_cached, count)
OO_STAT("Number of sockets not cached owing to stack limit",
        ci_uint32, activecache_stacklim, count)
OO_STAT("Number of active-cache hits",
        ci_uint32, activecache_hit, count)
OO_STAT("Number of active-cache hits after reaping",
        ci_uint32, activecache_hit_reap, count)
#endif
OO_STAT("Number of times that cached endpoint had its fd forcecully detached.",
        ci_uint32, sock_attach_fd_detach, count)
OO_STAT("Number of times fd detach failed legitimately. ",
        ci_uint32, sock_attach_fd_detach_fail_soft, count)
OO_STAT("Number of times fd detach failed unexpectedly. ",
        ci_uint32, sock_attach_fd_detach_fail_hard, count)
OO_STAT("Number of times that cached endpoint had more than one fd attached.",
        ci_uint32, sock_attach_fd_more, count)
OO_STAT("Number of times that attaching subsequent fd to endpoint failed. ",
        ci_uint32, sock_attach_fd_more_fail, count)
OO_STAT("Number of times fd got uncached. ",
        ci_uint32, epoll_fd_uncache, count)
OO_STAT("Number of times attach fd required retry in accept. ",
        ci_uint32, accept_attach_fd_retry, count)
OO_STAT("Number of times when TCP SO_RCVBUF value was found to be abused "
        "by too small incoming segments",
        ci_uint32, tcp_rcvbuf_abused, count)
OO_STAT("Number of times when TCP reorder buffer used too many packets "
        "compared to SO_RCVBUF value",
        ci_uint32, tcp_rcvbuf_abused_rob_guilty, count)
OO_STAT("Number of times when TCP receive queue was coalesced while "
        "fighting with SO_RCVBUF abusement",
        ci_uint32, tcp_rcvbuf_abused_recv_coalesced, count)
OO_STAT("Number of times when TCP receive queue used too many packets "
        "compared to SO_RCVBUF value",
        ci_uint32, tcp_rcvbuf_abused_recv_guilty, count)
OO_STAT("Number of times when TCP reorder buffer was dropped in a "
        "desperate attempt to fight with SO_RCVBUF abusement",
        ci_uint32, tcp_rcvbuf_abused_rob_desperate, count)
OO_STAT("Number of times when TCP SO_RCVBUF value was found to be abused "
        "by too small incoming segments even after taking measures "
        "against it",
        ci_uint32, tcp_rcvbuf_abused_badly, count)
OO_STAT("Number of times when TCP listening socket failed to retransmit "
        "SYNACK because it failed to allocate more packet buffers "
        "(probably postponing packet buffers allocation).",
        ci_uint32, tcp_listen_synack_retrans_no_buffer, count)
OO_STAT("Number of proactive packet buffers allocations because of "
        "EF_FREE_PACKETS_LOW_WATERMARK or fragmentation of free packets "
        "between packet sets.",
        ci_uint32, proactive_packet_allocation, count)
OO_STAT("Number of times the stack lock was deferred from driverlink "
        "context to workqueue.",
        ci_uint32, stack_locks_deferred, count)
OO_STAT("Number of TCP active-open sockets that used a shared local port",
        ci_uint32, tcp_shared_local_ports_used, count)
OO_STAT("Number of times a TIME_WAIT was reused to use a shared local port",
        ci_uint32, tcp_shared_local_ports_reused_tw, count)
OO_STAT("Number of times the shared local port pool was grown",
        ci_uint32, tcp_shared_local_ports_grow, count)
OO_STAT("Number of times an attempt to grow the shared local port pool failed",
        ci_uint32, tcp_shared_local_ports_grow_failed, count)
OO_STAT("Number of times no active wild filter was available",
        ci_uint32, tcp_shared_local_ports_exhausted, count)
OO_STAT("Number of times a socket from this stack was added to an epoll set "
        "with a different home stack.",
        ci_uint32, epoll_add_non_home, count)
OO_STAT("Number of times a socket could be added to a epoll set with "
        "a matching home stack, but epoll state allocation failed.  "
        "You probably want to increase EF_MAX_ENDPOINTS if this count "
        "is non-zero.",
        ci_uint32, epoll_sb_state_alloc_failed, count)
OO_STAT("Number of times that fd allocation failed for a socket in this stack.",
        ci_uint32, sock_attach_fd_alloc_fail, count)
OO_STAT("Number of times that a socket has used a MAC filter.",
        ci_uint32, mac_filter_shares, count)
OO_STAT("Number of times that we rejected a shared local port for any reason.",
        ci_uint32, tcp_shared_local_ports_skipped, count)
OO_STAT("Number of times that we rejected a shared local port because it "
        "would have resulted in a duplicate four-tuple.",
        ci_uint32, tcp_shared_local_ports_skipped_in_use, count)
OO_STAT("Number of active-opened connections which require at least one "
        "SYN retransmission.",
        ci_uint32, tcp_syn_retrans_once, count)
OO_STAT("Number of active-opened connections which require at least two "
        "SYN retransmissions.",
        ci_uint32, tcp_syn_retrans_twice, count)
OO_STAT("Number of active-opened connections which require at least three "
        "SYN retransmissions.",
        ci_uint32, tcp_syn_retrans_thrice, count)
OO_STAT("Number of SYN retransmissions.",
        ci_uint32, tcp_syn_retrans, count)
OO_STAT("Number of active-opened connections which failed because of "
        "retransmit timeout.",
        ci_uint32, tcp_connect_timedout, count)
OO_STAT("Number of active-opened connections dropped with ETIMEDOUT error.  "
        "In the most cases, this value is equal to tcp_connect_timedout.",
        ci_uint32, tcp_connect_etimedout, count)
OO_STAT("Number of active-opened connections which failed because of "
        "ICMP packet received.",
        ci_uint32, tcp_connect_icmp, count)
OO_STAT("Number of active-opened connections dropped with EHOSTUNREACH error.  "
        "In the most cases, this occurrences are also counted "
        "in tcp_connect_icmp.",
        ci_uint32, tcp_connect_ehostunreach, count)
OO_STAT("Number of active-opened connections dropped with ENETUNREACH error.  "
        "This condition can come from tcp_connect_icmp, or from route "
        "table misconfiguration.",
        ci_uint32, tcp_connect_enetunreach, count)
OO_STAT("Number of active-opened connections dropped with ENETDOWN error.  "
        "This condition can come from various misconfigurations.",
        ci_uint32, tcp_connect_enetdown, count)
OO_STAT("Number of active-opened connections which failed because of "
        "RST packet received.",
        ci_uint32, tcp_connect_refused, count)
OO_STAT("Number of active-opened connections dropped with ECONNREFUSED error.  "
        "In most cases, this value is equal to tcp_connect_refused.",
        ci_uint32, tcp_connect_econnrefused, count)

OO_STAT("Number of active-opened connections dropped with an error "
        "not mentioned above.",
        ci_uint32, tcp_connect_eother, count)
OO_STAT("The last errno value in use when tcp_connect_eother counter "
        "was incremented for the last time.",
        ci_uint32, tcp_connect_eother_val, val)

OO_STAT("Number of times that an active-open connection has used an initial "
        "sequence number from the table of remembered sequence numbers.",
        ci_uint32, tcp_seq_table_hits, count)
OO_STAT("Number of insertions made to sequence number table.",
        ci_uint32, tcp_seq_table_insertions, count)
OO_STAT("Number of sequence-table entries expired by ISN clock.",
        ci_uint32, tcp_seq_table_expiries, count)
OO_STAT("Number of sequence-table entries purged as oldest in set.",
        ci_uint32, tcp_seq_table_purgations, count)
OO_STAT("Number of all steps made across entries in all insertions.",
        ci_uint32, tcp_seq_table_steps, count)
OO_STAT("Number of insertions with short expiry.",
        ci_uint32, tcp_seq_table_short_expiry, count)
OO_STAT("Number of times there was no need to create entry.",
        ci_uint32, tcp_seq_table_avoided, count)

OO_STAT("Number of times the urgent flag was ignored in received packets",
        ci_uint32, tcp_urgent_ignore_rx, count)
OO_STAT("Number of times the urgent flag was processed in received packets",
        ci_uint32, tcp_urgent_process_rx, count)

OO_STAT("Number of packets received that contained IP options.",
        ci_uint32, ip_options, count)

#if CI_CFG_TCPDUMP
OO_STAT("Number of packets not captured by onload_tcpdump because the "
        "dump ring was full.",
        ci_uint32, tcpdump_missed, count)
#endif

OO_STAT("Lowest recorded number of free packets",
        ci_uint32, lowest_free_pkts, val)
#if CI_CFG_WANT_BPF_NATIVE
OO_STAT("Number of rx packets accepted by XDP program",
        ci_uint32, rx_xdp_pass, count)
OO_STAT("Number of rx packets rejected by XDP program with DROP code",
        ci_uint32, rx_xdp_drop, count)
OO_STAT("Number of rx packets rejected due to XDP program returning TX code",
        ci_uint32, rx_xdp_tx, count)
OO_STAT("Number of rx packets rejected due to XDP program returning REDIRECT code",
        ci_uint32, rx_xdp_redirect, count)
OO_STAT("Number of rx packets rejected due to XDP program returning ABORTED code",
        ci_uint32, rx_xdp_aborted, count)
OO_STAT("Number of rx packets rejected due to XDP program returning unknown code",
        ci_uint32, rx_xdp_unknown, count)
#endif

#if CI_CFG_HANDLE_ICMP
OO_STAT("Number of ICMP messages handled",
        ci_uint32, rx_icmp, count)
OO_STAT("Number of ICMP messages dropped",
        ci_uint32, rx_icmp_dropped, count)
OO_STAT("Number of ICMP messages dropped because of no memory",
        ci_uint32, rx_icmp_enomem, count)
OO_STAT("Number of batches when ICMP messages were handled",
        ci_uint32, rx_icmp_handler_batches, count)
OO_STAT("Number of ICMP messages handled from lock hook",
        ci_uint32, rx_icmp_hooked, count)

#endif
