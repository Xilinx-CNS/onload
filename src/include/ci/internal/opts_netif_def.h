/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Definition of configuration options held in a netif
**   \date  2005/11/30
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/


/* This file is included in a number of different environments to obtain a
   representation of configuration options.  It must contain ONLY C
   pre-procesor symbols.

   It must include one instance of the macro
   
       CI_CFG_OPTFILE_VERSION(version) - version of this option set
       
   This version number should be incremented if the meaning of current or
   former option names changes.

   It then has an arbitrary number of
   
       CI_CFG_OPT(env, name, type, doc, type_modifier, group, default,
                  min, max, presentation)

   option definitions:

       env           - a string giving the enviornment variable used to control
                       this option.
       name          - the C name of this option
       type          - an integer C type used to hold the option in
       doc           - a user-facing documentation documentation string
                       describing the option
       type_modifier - an integer giving size of the bitfield it is in or
                       an alignment requirement A<n> for aligning on an
		       <n>-byte boundary
       group         - a name for the option group this option belongs to,
                       by default (if nothing is placed in this field)
		       the name (above) is used
                       option groups define sets of options all of which must
		       be defined if any are
       default       - the value to which the option should be initialized
                       the values MIN, MAX, SMIN, SMAX can be used to refer to
		       the unsigned and signed minimum and maximum values that
		       fit in the field
       min           - the integer minimum value the option can hold
                       the values MIN, MAX, SMIN, SMAX can be used to refer to
		       the unsigned and signed minimum and maximum values that
		       fit in the field
       max           - the integer maximum value the option can hold
                       the values MIN, MAX, SMIN, SMAX can be used to refer to
		       the unsigned and signed minimum and maximum values that
		       fit in the field
		       Note: currently MAX is unlikely to be treated properly
		       in an unsigned 64-bit field - you should use SMAX
       presentation  - a name for the presentation type used to determine the
                       way this value should be presented to a user currently
		       one of:
		           count	- number of elements in something
		           countln2	- " as a power of two
			   bincount     - number of binary things, e.g. bytes
			   level        - one of a set of relative levels
			   time:sec     - time in seconds
			   time:msec    - time in milliseconds
			   time:usec    - time in microseconds
			   time:tick    - time in host-specific units
			   invcount     - a rate/probability of 1 in this many
			   bitmask      - bit mask
			   bitset:<S1>;..<Sn>
			                - bit set composed of bit 0==S1 |
					  bit 1=S2 ... | <bit n-1=Sn
			   ipaddress    - IP address
			   ipmask       - IP address mask
			   oneof:<S1>;..;<Sn>
			                - enumeration where minimum==S1
			   yesno        - same as oneof:no;yes
			   filename     - name of a file
                      

   Finally it can contain an arbitrary number of
   
       CI_CFG_OPTGROUP(group, category, expertise)

   option group definitions:

       group         - name of the option group (as used in CI_CFG_OPT)
       category      - name for the category of option these options belong to
                       options from the same category may be presented to
		       a user for modification grouped together
		       by default (if nothing is placed in this field)
		       the name of the group is used
       expertise     - an integer giving the expertise level associated with
                       these options
		       options with expertise level greater than that of the
		       user may not be presented to him for modification
		       by default the value 100 should be used

   Option groups generated implicitly by CI_CFG_OPT macros, which are
   unmodified by a CI_CFG_OPTGROUP macro should be considered to have a
   category with the same name as the option group and an expertise level
   equal to 100
*/


/* Please think carefully about packing when adding fields to this data
** structure.  Small fields should be next to each other to avoid wasting
** space.
**
** Please do not remove the sequence  0, MIN, MAX  on every option on the
** grounds that it is common text - they are there as in invitation to
** consider more correct values.
*/
#ifdef CI_CFG_OPTFILE_VERSION
CI_CFG_OPTFILE_VERSION(100)
#endif

/************************* FLAGS SECTION *************************/

CI_CFG_OPT("EF_URG_RFC", urg_rfc, ci_uint32,
"Choose between compliance with RFC1122 (1) or BSD behaviour (0) regarding "
"the location of the urgent point in TCP packet headers.",
           1, , 0, 0, 1, yesno)

#define EF_TCP_URG_MODE_ALLOW 0
#define EF_TCP_URG_MODE_IGNORE 1
CI_CFG_OPT("EF_TCP_URG_MODE", urg_mode, ci_uint32,
"allow  - process urgent flag and pointer.\n"
"ignore - ignore the urgent flag and pointer in received packets.\n"
"         WARNING: applications actually using urgent data will see "
"corrupt streams",
           1, , EF_TCP_URG_MODE_IGNORE, 0, 1, oneof:allow;ignore)


CI_CFG_OPT("EF_TX_PUSH", tx_push, ci_uint32,
"Enable low-latency transmit.",
           1, , 1, 0, 1, yesno)

/* Takes its value from EF_ACCEPT_INHERIT_NONBLOCK in opts_citp_def.  Do
 * not document this one here.
 */
CI_CFG_OPT("", accept_inherit_nonblock, ci_uint32,
           "", 1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_POLL_ON_DEMAND", poll_on_demand, ci_uint32,
"Poll for network events in the context of the application calls into the "
"network stack.  This option is enabled by default."
"\n"
"This option can improve performance in multi-threaded applications where "
"the Onload stack is interrupt-driven (EF_INT_DRIVEN=1), because it can "
"reduce lock contention.  Setting EF_POLL_ON_DEMAND=0 ensures that network "
"events are (mostly) processed in response to interrupts.",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_INT_DRIVEN", int_driven, ci_uint32,
"Put the stack into an 'interrupt driven' mode of operation.  When this "
"option is not enabled Onload uses heuristics to decide when to enable "
"interrupts, and this can cause latency jitter in some applications.  So "
"enabling this option can help avoid latency outliers."
"\n"
"This option is enabled by default except when spinning is enabled."
"\n"
"This option can be used in conjunction with spinning to prevent outliers "
"caused when the spin timeout is exceeded and the application blocks, or when "
"the application is descheduled.  In this case we recommend that interrupt "
"moderation be set to a reasonably high value (eg. 100us) to prevent too high "
"a rate of interrupts.",
           1, , 1, 0, 1, yesno)
#if CI_CFG_WANT_BPF_NATIVE
CI_CFG_OPT("EF_POLL_IN_KERNEL", poll_in_kernel, ci_uint32,
"Do polling of eventq in kernel.  This introduces cost of additional syscall(s) "
"per poll.",
           1, , 0, 0, 1, count)
#define EF_XDP_MODE_DISABLED 0
#define EF_XDP_MODE_COMPATIBLE 1
CI_CFG_OPT("EF_XDP_MODE", xdp_mode, ci_uint32,
"disabled    - disable running XDP programs "
"compatible  - enable running XDP programs on packets received by Onload. "
"Onload will use XDP programs attached to Solaflare devices. "
"\n"
"Enabling the feature implicitly enables in-kernel polling - see EF_POLL_IN_KERNEL.",
           1, , EF_XDP_MODE_DISABLED, 0, EF_XDP_MODE_COMPATIBLE, oneof:disabled;compatible)
#endif

CI_CFG_OPT("EF_INT_REPRIME", int_reprime, ci_uint32,
"Enable interrupts more aggressively than the default.",
           1, , 0, 0, 1, yesno)

#define MULTICAST_LIMITATIONS_NOTE                                      \
    "\nSee the OpenOnload manual for further details on multicast operation."

CI_CFG_OPT("EF_MCAST_RECV", mcast_recv, ci_uint32,
"Controls whether or not to accelerate multicast receives.  When set to zero, "
"multicast receives are not accelerated, but the socket continues to be "
"managed by Onload."
"\n"
"See also EF_MCAST_JOIN_HANDOVER."
MULTICAST_LIMITATIONS_NOTE,
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_FORCE_SEND_MULTICAST", force_send_multicast, ci_uint32,
"This option causes all multicast sends to be accelerated.  When disabled, "
"multicast sends are only accelerated for sockets that have cleared the "
"IP_MULTICAST_LOOP flag."
"\n"
"This option disables loopback of multicast traffic to receivers on the same "
"host, unless\n"
"(a) those receivers are sharing an OpenOnload stack with the sender "
"(see EF_NAME) and EF_MCAST_SEND is set to 1 or 3, or\n"
"(b) prerequisites to support loopback to other OpenOnload stacks are met "
"(see EF_MCAST_SEND)."
MULTICAST_LIMITATIONS_NOTE,
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_MULTICAST_LOOP_OFF", multicast_loop_off, ci_uint32,
"EF_MULTICAST_LOOP_OFF is deprecated in favour of EF_MCAST_SEND\n"
"When set, disables loopback of multicast traffic to receivers in the same "
"OpenOnload stack.\n"
"This option only takes effect when EF_MCAST_SEND is not set and is "
"equivalent to EF_MCAST_SEND=1 or EF_MCAST_SEND=0 "
"for values of 0 and 1 respectively."
MULTICAST_LIMITATIONS_NOTE,
           1, , 1, 0, 1, yesno)

#define CITP_MCAST_SEND_FLAG_LOCAL 1
#define CITP_MCAST_SEND_FLAG_EXT 2

CI_CFG_OPT("EF_MCAST_SEND", mcast_send, ci_uint32,
"Controls loopback of multicast traffic to receivers in the same and other "
"OpenOnload stacks.\n"
"When set to 0 (default) disables loopback within the same stack as well as to "
"other OpenOnload stacks.\n"
"When set to 1 enables loopback to the same stack\n"
"When set to 2 enables loopback to other OpenOnload stacks.\n"
"When set to 3 enables loopback to the same as well as other OpenOnload "
"stacks.\n"
"In respect to loopback to other OpenOnload stacks the options is just a hint "
"and the feature requires: (a) 7000-series or newer device, and "
"(b) selecting firmware variant with loopback support."
MULTICAST_LIMITATIONS_NOTE,
           2, , 0, 0, 3, oneof:none;local;ext;all;)

CI_CFG_OPT("EF_MCAST_RECV_HW_LOOP", mcast_recv_hw_loop, ci_uint32,
"When enabled allows udp sockets to receive multicast traffic that "
"originates from other OpenOnload stacks."
MULTICAST_LIMITATIONS_NOTE,
           1, , 1, 0, 1, yesno)


CI_CFG_OPT("EF_TCP_LISTEN_HANDOVER", tcp_listen_handover, ci_uint32,
"When an accelerated TCP socket calls listen(), hand it over to the kernel "
"stack.  This option disables acceleration of TCP listening sockets and "
"passively opened TCP connections.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_CONNECT_HANDOVER", tcp_connect_handover, ci_uint32,
"When an accelerated TCP socket calls connect(), hand it over to the kernel "
"stack.  This option disables acceleration of active-open TCP connections.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_UDP_CONNECT_HANDOVER", udp_connect_handover, ci_uint32,
"When set to 1, if a UDP socket is connected to an IP address that cannot be "
"accelerated by OpenOnload, or resource restrictions prevent RX acceleration, "
"hand the socket over to the kernel stack.\n"

"When this option is disabled the socket remains under the control of "
"OpenOnload.  This may be worthwhile because the socket may subsequently be "
"re-connected to an IP address that can be accelerated, or the socket may be"
"intended for TX use only.\n"

"When set to 2, hand the socket over on connect() even if the address could "
"have been accelerated.",
           2, , 1, 0, 2, level)

CI_CFG_OPT("EF_FORCE_TCP_NODELAY", tcp_force_nodelay, ci_uint32,
"This option allows the user to override the use of TCP_NODELAY. "
"This may be useful in cases where 3rd-party software is (not) "
"setting this value and the user would like to control its "
"behaviour:\n"
"  0 - do not override"
"  1 - always set TCP_NODELAY"
"  2 - never set TCP_NODELAY",
           2, , 0, 0, 2, level)

CI_CFG_OPT("EF_UDP_SEND_UNLOCKED", udp_send_unlocked, ci_uint32,
"Enables the 'unlocked' UDP send path.  When enabled this option improves "
"concurrency when multiple threads are performing UDP sends.",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_UNCONFINE_SYN", unconfine_syn, ci_uint32,
"Accept TCP connections that cross into or out-of a private network.",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_BINDTODEVICE_HANDOVER", bindtodevice_handover, ci_uint32,
"Hand sockets over to the kernel stack that have the SO_BINDTODEVICE socket "
"option enabled.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_MCAST_JOIN_BINDTODEVICE", mcast_join_bindtodevice, ci_uint32,
"When a UDP socket joins a multicast group (using IP_ADD_MEMBERSHIP or "
"similar), this option causes the socket to be bound to the interface that "
"the join was on.  The benefit of this is that it ensures the socket will "
"not accidentally receive packets from other interfaces that happen to match "
"the same group and port.  This can sometimes happen if another socket joins "
"the same multicast group on a different interface, or if the switch is "
"not filtering multicast traffic effectively."
"\n"
"If the socket joins multicast groups on more than one interface, then the "
"binding is automatically removed.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_RX_CHECKS", tcp_rx_checks, ci_uint32,
"Internal/debugging use only: perform extra debugging/consistency checks "
"on received packets.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_USE_DSACK", use_dsack, ci_uint32,
"Whether or not to use DSACK (duplicate SACK).\n"
"The value from /proc/sys/net/ipv4/tcp_dsack is used by default.",
           1, , CI_CFG_TCP_DSACK, 0, 1, yesno)

#define CITP_TIMESTAMPING_RECORDING_FLAG_CHECK_SYNC 1
CI_CFG_OPT("EF_TIMESTAMPING_REPORTING", timestamping_reporting, ci_uint32,
"Controls timestamp reporting, possible values:\n"
" 0: report translated timestamps only when the NIC clock has been set;\n"
" 1: report translated timestamps only when the system clock and the NIC "
"clock are in sync (e.g. using ptpd)\n"
"If the above conditions are not met Onload will only report raw "
"(not translated) timestamps.\n",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_RX_TIMESTAMPING", rx_timestamping, ci_uint32,
"Control of hardware timestamping of received packets, possible values:\n"
"  0 - do not do timestamping (default);\n"
"  1 - request timestamping but continue if hardware is not capable or it"
" does not succeed;\n"
"  2 - request timestamping and fail if hardware is capable and it does"
" not succeed;\n"
"  3 - request timestamping and fail if hardware is not capable or it"
" does not succeed;\n",
           2, , 0, 0, 3, count)

#define CITP_RX_TIMESTAMPING_SOURCE_NIC 0
#define CITP_RX_TIMESTAMPING_SOURCE_TRAILER 1
CI_CFG_OPT("EF_RX_TIMESTAMPING_ORDERING", rx_timestamping_ordering, ci_uint32,
"Select the source of timestamps to use to order received packets.\n"
"  nic - use hardware timestamps generated by the NIC\n"
"  trailer - use trailer timestamps on received packets\n"
"  cPacket - synonym for trailer (legacy)\n",
           1, , 0, 0, 2, oneof:nic;trailer;cpacket)

#define CITP_RX_TIMESTAMPING_TRAILER_FORMAT_CPACKET 0
#define CITP_RX_TIMESTAMPING_TRAILER_FORMAT_TTAG 1
#define CITP_RX_TIMESTAMPING_TRAILER_FORMAT_BRCM 2
CI_CFG_OPT("EF_RX_TIMESTAMPING_TRAILER_FORMAT", rx_timestamping_trailer_fmt, ci_uint32,
"Select the format of timestamps received as a packet trailer.\n"
"  cpacket - use cPacket trailer timestamp format\n"
"  ttag - use TTAG trailer timestamp format\n"
"  brcm - use Broadcom trailer timestamp format\n",
           2, , 0, 0, 2, oneof:nic;cpacket;ttag;brcm)

CI_CFG_OPT("EF_TX_TIMESTAMPING", tx_timestamping, ci_uint32,
"Control of hardware timestamping of transmitted packets, possible values:\n"
"  0 - do not do timestamping (default);\n"
"  1 - request timestamping but continue if hardware is not capable or it"
" does not succeed;\n"
"  2 - request timestamping and fail if hardware is capable and it does"
" not succeed;\n"
"  3 - request timestamping and fail if hardware is not capable or it"
" does not succeed;\n",
           2, , 0, 0, 3, count)

CI_CFG_OPT("EF_TCP_TSOPT_MODE", tcp_tsopt_mode, ci_uint32,
"Enable or disable per-stack TCP header timestamps (as defined in RFC 1323).  "
"Overrides system setting ipv4.tcp_timestamps and EF_TCP_SYN_OPTS.  "
"Possible values are:\n"
"  0  -  Disable TCP header timestamps\n"
"  1  -  Enable TCP header timestamps\n"
"  2  -  Use system settings (default)\n",
        2, , 2, 0, 2, count)

CI_CFG_OPT("EF_CLUSTER_IGNORE", cluster_ignore, ci_uint32,
"EF_CLUSTER_IGNORE is deprecated, use EF_CLUSTER_SIZE=0 to disable clustering. "
"When set, this option instructs Onload to ignore attempts to use clusters and "
"effectively ignore attempts to set SO_REUSEPORT.",
           1, , 0, 0, 1, count)

CI_CFG_OPT("EF_VALIDATE_ENV", validate_env, ci_uint32,
"When set this option validates Onload related environment "
"variables (starting with EF_).",
           1, , 1, 0, 1, level)

#if CI_CFG_TAIL_DROP_PROBE
CI_CFG_OPT("EF_TAIL_DROP_PROBE", tail_drop_probe, ci_uint32,
"Whether to probe if the tail of a TCP burst isn't ACKed quickly.\n"
"The value from /proc/sys/net/ipv4/tcp_early_retrans is used to derive "
"the default.",
           , , 1, 0, 1, yesno)
#endif

CI_CFG_OPT("EF_TCP_RST_DELAYED_CONN", rst_delayed_conn, ci_uint32,
"This option tells Onload to reset TCP connections rather than allow data to "
"be transmitted late.  Specifically, TCP connections are reset if the "
"retransmit timeout fires.  (This usually happens when data is lost, and "
"normally triggers a retransmit which results in data being delivered "
"hundreds of milliseconds late)."
"\n"
"WARNING: This option is likely to cause connections to be reset spuriously "
"if ACK packets are dropped in the network.",
          1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_SNDBUF_MODE", tcp_sndbuf_mode, ci_uint32,
           "This option controls how the SO_SNDBUF limit is applied to TCP "
           "sockets.  In the default mode the limit applies to the "
           "size of the send queue and retransmit queue combined.  "
           "When this option is set to 0 the limit applies to the "
           "the send queue only."
           "When this option is set to 2, the SNDBUF size is automatically "
           "adjusted for each TCP socket to match the window advertised by "
           "the peer (limited by EF_TCP_SOCKBUF_MAX_FRACTION). If the "
           "application sets SO_SNDBUF explictly then automatic adjustment is "
           "not used for that socket. The limit is applied to the size of the "
           "send queue and retransmit queue combined. You may also want to set "
           "EF_TCP_RCVBUF_MODE to give automatic adjustment of RCVBUF.",
           2, , 1, 0, 2, oneof:no;yes;auto)

CI_CFG_OPT("EF_TCP_COMBINE_SENDS_MODE", tcp_combine_sends_mode, ci_uint32,
           "This option controls how Onload fills packets in the TCP send "
           "buffer. In the default mode (set to 0) Onload will prefer to use "
           "all the space at the end of a previous packet before allocating a "
           "new one.  When set to 1, Onload will prefer to allocate a new "
           "packet for each new send.  In all cases this is a hint rather than "
           "guaranteed behaviour: there are conditions where the preference "
           "indicated by this option will not be possible, e.g. memory "
           "pressure may cause packets in the send queue to be combined.  "
           "MSG_MORE and TCP_CORK can override this option when set.  The "
           "zero-copy sends API may also use the segmentation provided by the "
           "caller's buffers.  For full control of message segmentation the "
           "delegated sends API can be used."
           "Setting this option can affect the capacity of send buffers "
           "belonging to sockets in this stack and increase packet buffer usage.  "
           "It can also reduce efficiency as packets will be allocated for each "
           "send call rather than being able to reuse one that is already "
           "available.  Setting it is only recommended for those who have an "
           "explicit need to avoid combined or split sends.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_SOCKBUF_MAX_FRACTION", tcp_sockbuf_max_fraction, ci_uint32,
           "This option controls the maximum fraction of the TX buffers "
           "that may be allocated to a single socket with EF_TCP_SNDBUF_MODE=2.  "
           "It also controls the maximum fraction of the RX buffers that may "
           "be allocated to a single socket with EF_TCP_RCVBUF_MODE=1.  "
           "The maximum allocation for a socket is EF_MAX_TX_PACKETS/(2^N) "
           "for TX and EF_MAX_RX_PACKETS/(2^N) for RX, where N is specified "
           "here.",
           4, , 1, 1, 10, count)

CI_CFG_OPT("EF_TCP_SYNCOOKIES", tcp_syncookies, ci_uint32,
"Use TCP syncookies to protect from SYN flood attack",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_SEND_NONBLOCK_NO_PACKETS_MODE", 
           tcp_nonblock_no_pkts_mode, ci_uint32,
           "This option controls how a non-blocking TCP send() call should "
           "behave if it is unable to allocate sufficient packet buffers.  By "
           "default Onload will mimic Linux kernel stack behaviour and block "
           "for packet buffers to be available.  If set to 1, this option will "
           "cause Onload to return error ENOBUFS.  Note this option can cause "
           "some applications (that assume that a socket that is writeable is "
           "able to send without error) to malfunction.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_RCVBUF_STRICT", tcp_rcvbuf_strict, ci_uint32,
"This option prevents TCP small segment attack.  With this option set, "
"Onload limits the number of packets inside TCP receive queue and "
"TCP reorder buffer.  In some cases, this option causes performance "
"penalty.  You probably want this option if your application is "
"connecting to unrtusted partner or over untrusted network.\n"
"Off by default.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_UDP_SEND_NONBLOCK_NO_PACKETS_MODE", 
           udp_nonblock_no_pkts_mode, ci_uint32,
           "This option controls how a non-blocking UDP send() call should "
           "behave if it is unable to allocate sufficient packet buffers.  By "
           "default Onload will mimic Linux kernel stack behaviour and block "
           "for packet buffers to be available.  If set to 1, this option will "
           "cause Onload to return error ENOBUFS.  Note this option can cause "
           "some applications (that assume that a socket that is writeable is "
           "able to send without error) to malfunction.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_RCVBUF_MODE", tcp_rcvbuf_mode, ci_uint32,
"This option controls how the RCVBUF is set for TCP "
"Mode 0 (default) gives fixed size RCVBUF."
"Mode 1 will enable automatic tuning of RCVBUF using Dynamic Right Sizing."
"       If SO_RCVBUF is explictly set by the application this value will be"
"       used. EF_TCP_SOCKBUF_MAX_FRACTION can be used to control the maximum"
"       size of the buffer for an individual socket."
"The effect of EF_TCP_RCVBUF_STRICT is independent of this setting.",
	   1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_HIGH_THROUGHPUT_MODE", rx_merge_mode, ci_uint32,
"This option causes onload to optimise for throughput at the cost of latency.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_TIME_WAIT_ASSASSINATION", time_wait_assassinate, ci_uint32,
"Allow TCP TIME-WAIT state assassination, as with "
"/proc/sys/net/ipv4/tcp_rfc1337 set to  0",
           1, , CI_CFG_TIME_WAIT_ASSASSINATE, 0, 1, yesno)


/**********************************************************************
 * Narrow fields (few bits).
 */

CI_CFG_OPT("EF_TPH_MODE", tph_mode, ci_uint32,
"Enable use of SDCI PCIe TPH steering hints."
"0 means off, 1 means no-steering-tag mode, 2 means use steering tags",
           2, , 0, 0, 2, oneof:off;nostmode;stmode )

CI_CFG_OPT("EF_MCAST_JOIN_HANDOVER", mcast_join_handover, ci_uint32,
"When this option is set to 1, and a UDP socket joins a multicast group on an "
"interface that is not accelerated, the UDP socket is handed-over to the "
"kernel stack.  This can be a good idea because it prevents that socket from "
"consuming Onload resources, and may also help avoid spinning when it is not "
"wanted."
"\n"
"When set to 2, UDP sockets that join multicast groups are always handed-over "
"to the kernel stack.",
           2, , 0, 0, 2, oneof:off;kernel;always)

#if CI_CFG_POISON_BUFS
CI_CFG_OPT("EF_POISON_RX_BUF", poison_rx_buf, ci_uint32,
"1=hdrs 2=payload also.",
           2, , 0, 0, 2, oneof:no;headers;headersandpayload)
#endif

/* packet_buffer_mode bits to be ORed: */
/* bit 0 was the former SR-IOV VF mode */
#define CITP_PKTBUF_MODE_PHYS    2
CI_CFG_OPT("EF_PACKET_BUFFER_MODE", packet_buffer_mode, ci_uint32,
"This option affects how DMA buffers are managed.  The default packet buffer "
"mode uses a limited hardware resource, and so restricts the total amount "
"of memory that can be used by Onload for DMA."
"\n"
"Setting EF_PACKET_BUFFER_MODE!=0 enables 'scalable packet buffer mode' which "
"removes that limit.  See details for each mode below."
"\n"
"  2  -  Physical address mode.  Inherently unsafe; no address space "
"separation between different stacks or net driver packets."
"\n"
"Mode 1 was relevant only to adapters which are no longer supported."
"\n"
"For unsafe physical address mode (2), you should tune "
"phys_mode_gid module parameter of the onload module.",
           2, , 0, 0, 3, oneof:buf_table;sriov_iommu;phys;sriov_phys)

#if CI_CFG_ENDPOINT_MOVE
#define CITP_TCP_LOOPBACK_OFF           0
#define CITP_TCP_LOOPBACK_SAMESTACK     1
#define CITP_TCP_LOOPBACK_TO_CONNSTACK  2
#define CITP_TCP_LOOPBACK_ALLOW_ALIEN_IN_ACCEPTQ 2
#define CITP_TCP_LOOPBACK_TO_LISTSTACK  3
#define CITP_TCP_LOOPBACK_TO_NEWSTACK   4

CI_CFG_OPT("EF_TCP_SERVER_LOOPBACK", tcp_server_loopback, ci_uint32,
"Enable acceleration of TCP loopback connections on the listening (server) "
"side:\n"
"  0  -  not accelerated (default);\n"
"  1  -  accelerate if the connecting socket is in the same stack (you "
"should also set EF_TCP_CLIENT_LOOPBACK!=0);\n"
"  2  -  accelerate and allow accepted socket to be in another stack "
"(this is necessary for clients with EF_TCP_CLIENT_LOOPBACK=2,4).",
           2, , CITP_TCP_LOOPBACK_OFF, 0,
           CITP_TCP_LOOPBACK_ALLOW_ALIEN_IN_ACCEPTQ,
           oneof:no;samestack;allowalien)

CI_CFG_OPT("EF_TCP_CLIENT_LOOPBACK", tcp_client_loopback, ci_uint32,
"Enable acceleration of TCP loopback connections on the connecting (client) "
"side:\n"
"  0  -  not accelerated (default);\n"
"  1  -  accelerate if the listening socket is in the same stack "
"(you should also set EF_TCP_SERVER_LOOPBACK!=0);\n"
"  2  -  accelerate and move accepted socket to the stack of the connecting "
"socket (server should allow this via EF_TCP_SERVER_LOOPBACK=2);\n"
"  3  -  accelerate and move the connecting socket to the stack of the "
"listening socket (server should allow this via EF_TCP_SERVER_LOOPBACK!=0).\n"
"  4  -  accelerate and move both connecting and accepted  sockets to the "
"new stack (server should allow this via EF_TCP_SERVER_LOOPBACK=2).\n"
"\n"
"NOTES:\nOptions 3 and 4 break some applications using epoll, fork and "
"dup calls.\n"
"Options 2 and 4 makes accept() to misbehave if the client exist "
"too early.\n"
"Option 4 is not recommended on 32-bit systems because it can create "
"a lot of additional Onload stacks eating a lot of low memory.",
           3, , CITP_TCP_LOOPBACK_OFF, 0, CITP_TCP_LOOPBACK_TO_NEWSTACK,
           oneof:no;samestack;toconn;tolist;nonew)
#endif

#if CI_CFG_PKTS_AS_HUGE_PAGES
CI_CFG_OPT("EF_USE_HUGE_PAGES", huge_pages, ci_uint32,
"Control of whether huge pages are used for packet buffers:\n"
"  0 - no;\n"
"  1 - use huge pages if available (default);\n"
"  2 - always use huge pages and fail if huge pages are not available.\n"
"Mode 1 prints syslog message if there is not enough huge pages "
"in the system.\n"
"Mode 2 guarantees only initially-allocated packets to be in huge pages.  "
"It is recommended to use this mode together with EF_MIN_FREE_PACKETS, "
"to control the number of such guaranteed huge pages.  All non-initial "
"packets are allocated in huge pages when possible; syslog message is "
"printed if the system is out of huge pages.\n"
"Non-initial packets may be allocated in non-huge pages without "
"any warning in syslog for both mode 1 and 2 even if the system has "
"free huge pages.",
           2, , 1, 0, 2, oneof:no;try;always)
#endif

CI_CFG_OPT("EF_COMPOUND_PAGES_MODE", compound_pages, ci_uint32,
"Debug option, not suitable for normal use.\n"
"For packet buffers, allocate system pages in the following way:\n"
"  0 - try to use compound pages if possible (default);\n"
"  1 - obsolete, same behaviour as 0;\n"
"  2 - do not use compound pages at all.\n",
          2, , 0, 0, 2, oneof:always;small;never)

#if CI_CFG_PIO
CI_CFG_OPT("EF_PIO", pio, ci_uint32,
"Control of whether Programmed I/O is used instead of DMA for small packets:\n"
"  0 - no (use DMA);\n"
"  1 - use PIO for small packets if available (default);\n"
"  2 - use PIO for small packets and fail if PIO is not available.\n"
"Mode 1 will fall back to DMA if PIO is not currently available.\n"
"Mode 2 will fail to create the stack if the hardware supports PIO but "
"PIO is not currently available.  On hardware that does not support PIO "
"there is no difference between mode 1 and mode 2.\n"
"In all cases, PIO will only be used for small packets (see EF_PIO_THRESHOLD) "
"and if the VI's transmit queue is currently empty.  If these conditions are "
"not met DMA will be used, even in mode 2.\n"
"Note: PIO is currently only available on x86_64 systems\n"
"Note: Mode 2 will not prevent a stack from operating without PIO in the\n"
"      event that PIO allocation is originally successful but then fails\n"
"      after an adapter is rebooted or hotplugged while that stack exists.",
           2, , 1, 0, 2, oneof:no;try;always)
#endif

#if CI_CFG_CTPIO
CI_CFG_OPT("EF_CTPIO", ctpio, ci_uint32,
"Controls whether the CTPIO low-latency transmit mechanism is enabled:\n"
"  0 - no (use DMA and/or PIO);\n"
"  1 - enable CTPIO if available (default);\n"
"  2 - enable CTPIO and fail stack creation if not available.\n"
"Mode 1 will fall back to DMA or PIO if CTPIO is not currently available.  "
"Mode 2 will fail to create the stack if the hardware supports CTPIO but "
"CTPIO is not currently available.  On hardware that does not support CTPIO "
"there is no difference between mode 1 and mode 2.\n"
"In all cases, CTPIO is only be used for packets if length <= "
"EF_CTPIO_MAX_FRAME_LEN and when the VI's transmit queue is empty.  If these "
"conditions are not met DMA or PIO is used, even in mode 2.\n"
"Note: CTPIO is currently only available on x86_64 systems.\n"
"Note: Mode 2 will not prevent a stack from operating without CTPIO in the\n"
"      event that CTPIO allocation is originally successful but then fails\n"
"      after an adapter is rebooted or hotplugged while that stack exists.",
           2, , 1, 0, 2, oneof:no;try;always)

#define EF_CTPIO_MODE_SF 0
#define EF_CTPIO_MODE_SF_NP 1
#define EF_CTPIO_MODE_CT 2
CI_CFG_OPT("EF_CTPIO_MODE", ctpio_mode, ci_uint16,
"CTPIO transmission mode: \n"
"  sf    - store and forward - the NIC will buffer the entire packet before\n"
"          starting to send it on the wire.\n"
"  sf-np - store and forward, no poison - similar to mode 0 but the NIC will\n"
"          guarantee never to emit a poisoned frame under any circumstances.\n"
"          This will force store-and-forward semantics for all users of CTPIO\n"
"          on the same port.\n"
"  ct    - cut-through - the NIC will start to send the outgoing packet onto\n"
"          the wire before it has been fully received, improving latency at\n"
"          the cost of occasionally transmitting a poisoned frame under some\n"
"          circumstances (such as the process being descheduled before it\n"
"          has finished writing the packet to the NIC).\n",
           2, , EF_CTPIO_MODE_SF_NP, 0, 2, oneof:sf;sf-np;ct)
#endif

CI_CFG_OPT("EF_TCP_SYN_OPTS", syn_opts, ci_uint32,
"A bitmask specifying the TCP options to advertise in SYN segments.\n"
"bit 0 (0x1) is set to 1 to enable PAWS and RTTM timestamps (RFC1323),\n"
"bit 1 (0x2) is set to 1 to enable window scaling (RFC1323),\n"
"bit 2 (0x4) is set to 1 to enable SACK (RFC2018),\n"
"bit 3 (0x8) is set to 1 to enable ECN (RFC3128).\n"
"The values from /proc/sys/net/ipv4/tcp_{sack,timestamp,window_scaling} "
"are used to find the default.",
           4, , CI_TCPT_SYN_FLAGS, MIN, MAX, bitmask)

CI_CFG_OPT("EF_TCP_ADV_WIN_SCALE_MAX", tcp_adv_win_scale_max, ci_uint32,
"Maximum value for TCP window scaling that will be advertised.  Set it "
"to 0 to turn window scaling off.\n"
"The value from /proc/sys/net/ipv4/tcp_window_scaling is used by default.",
           4, , CI_TCP_WSCL_MAX, 0, 14, bincount)

CI_CFG_OPT("EF_TCP_TCONST_MSL", msl_seconds, ci_uint32,
"The Maximum Segment Lifetime (as defined by the TCP RFC).  A smaller value "
"causes connections to spend less time in the TIME_WAIT state.",
           8, , CI_CFG_TCP_TCONST_MSL, MIN, MAX, time:sec)

CI_CFG_OPT("EF_TCP_FIN_TIMEOUT", fin_timeout, ci_uint32,
"Time in seconds to wait for an orphaned connection to be closed properly "
"by the network partner (e.g. FIN in the TCP FIN_WAIT2 state; zero window "
"opening to send our FIN, etc).\n"
"The value from /proc/sys/net/ipv4/tcp_fin_timeout is used by default.",
           8, , CI_CFG_TCP_FIN_TIMEOUT, MIN, MAX, time:sec)

CI_CFG_OPT("EF_TCP_RX_LOG_FLAGS", tcp_rx_log_flags, ci_uint32,
"Log received packets that have any of these flags set in the TCP header.  "
"Only active when EF_TCP_RX_CHECKS is set.",
           8, ,  0, MIN, MAX, bitmask)

#if CI_CFG_PORT_STRIPING
CI_CFG_OPT("EF_STRIPE_DUPACK_THRESHOLD", stripe_dupack_threshold, ci_uint16,
"For connections using port striping: Sets the number of duplicate ACKs that "
"must be received before initiating fast retransmit.",
           8, , CI_CFG_STRIPE_DEFAULT_DUPACK_THRESHOLD, MIN, MAX, count/*?*/)

CI_CFG_OPT("EF_STRIPE_TCP_OPT", stripe_tcp_opt, ci_uint32,
"The TCP option number to use when negotiating port striping.",
           8, , CI_CFG_STRIPE_DEFAULT_TCP_OPT, MIN, MAX, bitmask)
#endif

CI_CFG_OPT("EF_RETRANSMIT_THRESHOLD", retransmit_threshold, ci_int32,
"Number of retransmit timeouts before a TCP connection is aborted.\n"
"The value from /proc/sys/net/ipv4/tcp_retries2 is used by default.",
           8,  retransmit_threshold, CI_TCP_RETRANSMIT_THRESHOLD,
           0, SMAX, count)

CI_CFG_OPT("EF_RETRANSMIT_THRESHOLD_ORPHAN", retransmit_threshold_orphan, ci_int32,
"Number of retransmit timeouts before a TCP connection is aborted "
"in case of orphaned connection.\n"
"The value from /proc/sys/net/ipv4/tcp_orphan_retries is used by default.",
           8,  retransmit_threshold, CI_TCP_RETRANSMIT_THRESHOLD_ORPHAN,
           0, SMAX, count)

CI_CFG_OPT("EF_RETRANSMIT_THRESHOLD_SYN", retransmit_threshold_syn, ci_int32,
"Number of times a SYN will be retransmitted before a connect() attempt will "
"be aborted.\n"
"The value from /proc/sys/net/ipv4/tcp_syn_retries is used by default.",
           8,  retransmit_threshold, CI_TCP_RETRANSMIT_THRESHOLD_SYN,
           0, SMAX, count)

#define CI_TCP_LISTEN_SYNACK_RETRIES 5   /* send 5 synacks by default */
CI_CFG_OPT("EF_RETRANSMIT_THRESHOLD_SYNACK", retransmit_threshold_synack,
           ci_int32,
"Number of times a SYN-ACK will be retransmitted before an embryonic "
"connection will be aborted.\n"
"The value from /proc/sys/net/ipv4/tcp_synack_retries is used by default.",
           8,  retransmit_threshold, CI_TCP_LISTEN_SYNACK_RETRIES, 0,
           CI_CFG_TCP_SYNACK_RETRANS_MAX, count)

/*****************************************************************/

CI_CFG_OPT("EF_SHARE_WITH", share_with, ci_int32,
"Set this option to allow a stack to be accessed by processes owned by "
"another user.  Set it to the UID of a user that should be permitted to share "
"this stack, or set it to -1 to allow any user to share the stack.  By "
"default stacks are not accessible by users other than root."
"\n"
"Processes invoked by root can access any stack.  Setuid processes can only "
"access stacks created by the effective user, not the real user.  This "
"restriction can be relaxed by setting the onload kernel module option "
"allow_insecure_setuid_sharing=1."
"\n"
"WARNING: A user that is permitted to access a stack is able to: Snoop on any "
"data transmitted or received via the stack; Inject or modify data "
"transmitted or received via the stack; damage the stack and any sockets or "
"connections in it; cause misbehaviour and crashes in any application using "
"the stack.",
           , , 0, -1, SMAX, count)

/* TODO ON-16706 allow 0 ring size for now for development purposes */
CI_CFG_OPT("EF_RXQ_SIZE", rxq_size, ci_uint16,
"Set the size of the receive descriptor ring.  Must be a power of two.  "
"Valid values are architecture dependent.  For EF10: 512, 1024, 2048 "
"or 4096.\n"

"A larger ring size can absorb larger packet bursts without drops, but may "
"reduce efficiency because the working set size is increased.\n"

"If the value is lower than is supported by the hardware this will be rounded "
"up. Set EF_LOG to include more_config_warnings to log if this occurs.",
           , , 512, 0, 32768, bincount)

CI_CFG_OPT("EF_TXQ_SIZE", txq_size, ci_uint16,
"Set the size of the transmit descriptor ring.  Valid values: 512, 1024, 2048 "
"or 4096.",
           , , 512, 512, 4096, bincount)

CI_CFG_OPT("EF_SEND_POLL_THRESH", send_poll_thresh, ci_uint16,
"Poll for network events after sending this many packets."
"\n"
"Setting this to a larger value may improve transmit throughput for small "
"messages by allowing batching.  However, such batching may cause sends to be "
"delayed leading to increased jitter.",
           , , 64, 0, 65535, count)

CI_CFG_OPT("EF_SEND_POLL_MAX_EVS", send_poll_max_events, ci_uint16,
"When polling for network events after sending, this places a limit on the "
"number of events handled.",
           , , 96, 1, 65535, count)

CI_CFG_OPT("EF_UDP_SEND_UNLOCK_THRESH", udp_send_unlock_thresh, ci_uint16,
"UDP message size below which we attempt to take the stack lock early.  "
"Taking the lock early reduces overhead and latency slightly, but may "
"increase lock contention in multi-threaded applications.",
           , , 1500, MIN, MAX, count)

CI_CFG_OPT("EF_UDP_PORT_HANDOVER_MIN", udp_port_handover_min, ci_uint16,
"When set (together with EF_UDP_PORT_HANDOVER_MAX), this causes UDP sockets "
"explicitly bound to a port in the given range to be handed over to the "
"kernel stack.  The range is inclusive.",
           , , 2, MIN, MAX, count)

CI_CFG_OPT("EF_UDP_PORT_HANDOVER_MAX", udp_port_handover_max, ci_uint16,
"When set (together with EF_UDP_PORT_HANDOVER_MIN), this causes UDP sockets "
"explicitly bound to a port in the given range to be handed over to the "
"kernel stack.  The range is inclusive.",
           , , 1, MIN, MAX, count)

CI_CFG_OPT("EF_UDP_PORT_HANDOVER2_MIN", udp_port_handover2_min, ci_uint16,
"When set (together with EF_UDP_PORT_HANDOVER2_MAX), this causes UDP sockets "
"explicitly bound to a port in the given range to be handed over to the "
"kernel stack.  The range is inclusive.",
           , , 2, MIN, MAX, count)

CI_CFG_OPT("EF_UDP_PORT_HANDOVER2_MAX", udp_port_handover2_max, ci_uint16,
"When set (together with EF_UDP_PORT_HANDOVER2_MIN), this causes UDP sockets "
"explicitly bound to a port in the given range to be handed over to the "
"kernel stack.  The range is inclusive.",
           , , 1, MIN, MAX, count)

CI_CFG_OPT("EF_UDP_PORT_HANDOVER3_MIN", udp_port_handover3_min, ci_uint16,
"When set (together with EF_UDP_PORT_HANDOVER3_MAX), this causes UDP sockets "
"explicitly bound to a port in the given range to be handed over to the "
"kernel stack.  The range is inclusive.",
           , , 2, MIN, MAX, count)

CI_CFG_OPT("EF_UDP_PORT_HANDOVER3_MAX", udp_port_handover3_max, ci_uint16,
"When set (together with EF_UDP_PORT_HANDOVER3_MIN), this causes UDP sockets "
"explicitly bound to a port in the given range to be handed over to the "
"kernel stack.  The range is inclusive.",
           , , 1, MIN, MAX, count)

CI_CFG_OPT("EF_DELACK_THRESH", delack_thresh, ci_uint16,
"This option controls the delayed acknowledgement algorithm.  A socket may "
"receive up to the specified number of TCP segments without generating an "
"ACK.  Setting this option to 0 disables delayed acknowledgements."
"\n"
"NB. This option is overridden by EF_DYNAMIC_ACK_THRESH, so both options need "
"to be set to 0 to disable delayed acknowledgements.",
           , , 1, 0, 65535, count)
           
#if CI_CFG_DYNAMIC_ACK_RATE
CI_CFG_OPT("EF_DYNAMIC_ACK_THRESH", dynack_thresh, ci_uint16,
"If set to >0 this will turn on dynamic adapation of the ACK rate to "
"increase efficiency by avoiding ACKs when they would reduce "
"throughput.  The value is used as the threshold for number of pending "
"ACKs before an ACK is forced.  If set to zero then the standard "
"delayed-ack algorithm is used.",
           , , 16, 0, 65535, count)
#endif

CI_CFG_OPT("EF_INVALID_ACK_RATELIMIT", oow_ack_ratelimit, ci_uint32,
"Limit the rate of ACKs sent because of invalid incoming TCP packet, "
"in milliseconds.  The limitation is applied per-socket.  "
"The value from /proc/sys/net/ipv4/tcp_invalid_ratelimit "
"is used by default.",
          , , CI_CFG_TCP_OUT_OF_WINDOW_ACK_RATELIMIT, 0, 65535, time:msec)

#if CI_CFG_FD_CACHING
CI_CFG_OPT("EF_SOCKET_CACHE_MAX", sock_cache_max, ci_uint32,
"Sets the maximum number of TCP sockets to cache for this stack.  When "
"set > 0, OpenOnload will cache resources associated with sockets in order "
"to improve connection set-up and tear-down performance.  This improves "
"performance for applications that make new TCP connections at a high rate.",
           , , 0, MIN, SMAX, count)

CI_CFG_OPT("EF_PER_SOCKET_CACHE_MAX", per_sock_cache_max, ci_int32,
"When socket caching is enabled, (i.e. when EF_SOCKET_CACHE_MAX > 0), this "
"sets a further limit on the size of the cache for each socket. If set to "
"-1, no limit is set beyond the global limit specified by "
"EF_SOCKET_CACHE_MAX.",
           , , -1, -1, SMAX, count)
#endif

CI_CFG_OPT("EF_ACCEPTQ_MIN_BACKLOG", acceptq_min_backlog, ci_uint16,
"Sets a minimum value to use for the 'backlog' argument to the listen() "
"call.  If the application requests a smaller value, use this value instead.",
           , , 1, MIN, MAX, count)

CI_CFG_OPT("EF_ACCEPTQ_MAX_BACKLOG", acceptq_max_backlog, ci_uint32,
"Maximum value of 'backlog' argument in listen() call (accept queue maximum "
"size). The value from /proc/sys/core/somaxconn is used by default.",
           , , SOMAXCONN, MIN, MAX, count)

CI_CFG_OPT("EF_NONAGLE_INFLIGHT_MAX", nonagle_inflight_max, ci_uint16,
"This option affects the behaviour of TCP sockets with the TCP_NODELAY socket "
"option.  Nagle's algorithm is enabled when the number of packets in-flight "
"(sent but not acknowledged) exceeds the value of this option.  This improves "
"efficiency when sending many small messages, while preserving low latency.\n"

"Set this option to -1 to ensure that Nagle's algorithm never delays sending "
"of TCP messages on sockets with TCP_NODELAY enabled.",
	   , , 50, 1, MAX, count)

CI_CFG_OPT("EF_DEFER_WORK_LIMIT", defer_work_limit, ci_uint16,
"The maximum number of times that work can be deferred to the lock holder "
"before we force the unlocked thread to block and wait for the lock",
           , , 32, MIN, MAX, count)

CI_CFG_OPT("EF_IRQ_CORE", irq_core, ci_int16,
"Specify which CPU core interrupts for this stack should be handled on."
"\n"
"Onload interrupts are handled via net driver receive channel interrupts.  "
"The sfc_affinity driver is normally used to choose which net-driver receive "
"channel is used, however this value may be used to override that "
"mechanism.  It is only possible for interrupts to be handled on the "
"requested core if a net driver interrupt is assigned to the selected core.  "
"Otherwise a nearby core will be selected."
"\n"
"Note that if the IRQ balancer service is enabled it may redirect interrupts "
"to other cores.",
	   , , -1, -1, SMAX, count)

CI_CFG_OPT("EF_IRQ_CHANNEL", irq_channel, ci_int16,
"Set the net-driver receive channel that will be used to handle interrupts "
"for this stack.  The core that receives interrupts for this stack will be "
"whichever core is configured to handle interrupts for the specified net "
"driver receive channel.",
	   , , -1, -1, SMAX, count)

CI_CFG_OPT("EF_RXQ_LIMIT", rxq_limit, ci_int32,
"Maximum fill level for the receive descriptor ring.  This has no effect "
"when it has a value larger than the ring size (EF_RXQ_SIZE).",
           , , 65535, CI_CFG_RX_DESC_BATCH, 65535, level)

CI_CFG_OPT("EF_SHARED_RXQ_NUM", shared_rxq_num, ci_int32,
"Experimental option: this option may be changed or removed in future "
"releases. For adapters using shared receive queues for their traffic (X3), "
"the queue number to use for the next filter required. Subsequent filters "
"will share the same queue number (if possible), in order to minimize the "
"number of queues needing to be polled. In some cases (e.g. multicast "
"replication, IPv6, etc.) Onload may be required to choose a different "
"receive queue to that preferred by this option. "
"If this option is not used, the default is to spread out stacks amongst "
"available queues.\n"
"If the queue specified cannot be used then operations that result in filter "
"insertion, such as bind() and connect(), can fail, resulting in the socket "
"being handed over to the kernel, with an error output to the kernel log. "
"To fail the socket operation in this condition and prevent handover the "
"option EF_NO_FAIL=0 can be set. ",
           , , -1, -1, SMAX, count)

CI_CFG_OPT("EF_EVS_PER_POLL", evs_per_poll, ci_uint32,
"Sets the number of hardware network events to handle before performing other "
"work.  This is a hint for internal tuning, and the actual number handled "
"might differ.  The value chosen represents a trade-off: Larger values "
"increase batching (which typically improves efficiency) but may also "
"increase the working set size (which harms cache efficiency). When "
"EF_POLL_IN_KERNEL is set (either explicitly or implicitly) then the default "
"value is 192, to increasing batching efficiency.",
           , , 64, 0, 0x7fffffff, level)

#if CI_CFG_PORT_STRIPING
CI_CFG_OPT("EF_STRIPE_NETMASK", stripe_netmask_be32, ci_uint32,
"Port striping is only negotiated with hosts whose IP address is on the same "
"subnet as the local IP, where the subnet mask is defined by this option.",
           , , CI_CFG_STRIPE_DEFAULT_NETMASK, MIN, MAX, ipmask)
#endif

#if CI_CFG_RANDOM_DROP
CI_CFG_OPT("EF_RX_DROP_RATE", rx_drop_rate, ci_uint32,
"Testing use only.  Drop 1 in N packets at random.",
           , ,        0, MIN, MAX, invcount)
#endif

CI_CFG_OPT("EF_SPIN_USEC", spin_usec, ci_uint32,
           "" /* documented in opts_citp_def.h */,
           ,  poll_cycles, 0, MIN, MAX, time:usec)

CI_CFG_OPT("EF_BUZZ_USEC", buzz_usec, ci_uint32,
"Sets the timeout in microseconds for lock buzzing options.  Set to zero to "
"disable lock buzzing (spinning).  Will buzz forever if set to -1.  Also set "
"by the EF_POLL_USEC option.",
           ,  poll_cycles, 0, MIN, MAX, time:usec)

CI_CFG_OPT("EF_HELPER_USEC", timer_usec, ci_uint32,
"Timeout in microseconds for the count-down interrupt timer.  This timer "
"generates an interrupt if network events are not handled by the application "
"within the given time.  It ensures that network events are handled promptly "
"when the application is not invoking the network, or is descheduled."
"\n"
"Set this to 0 to disable the count-down interrupt timer.  It is disabled by "
"default for stacks that are interrupt driven.",
           ,  helper_timer, 500, MIN, MAX, time:usec)

CI_CFG_OPT("EF_HELPER_PRIME_USEC", timer_prime_usec, ci_uint32,
"Sets the frequency with which software should reset the count-down timer.  "
"Usually set to a value that is significantly smaller than EF_HELPER_USEC "
"to prevent the count-down timer from firing unless needed.  Defaults to "
"(EF_HELPER_USEC / 2).",
           ,  helper_timer, 250, MIN, MAX, time:usec)

CI_CFG_OPT("EF_MAX_PACKETS", max_packets, ci_uint32,
"Upper limit on number of packet buffers in each OpenOnload stack.  Packet "
"buffers require hardware resources which may become a limiting factor if "
"many stacks are each using many packet buffers.  This option can be used to "
"limit how much hardware resource and memory a stack uses.  This option "
"has an upper limit determined by the max_packets_per_stack onload "
"module option."
"\n"
"Note: When 'scalable packet buffer mode' is not enabled (see "
"EF_PACKET_BUFFER_MODE) the total number of packet buffers possible in "
"aggregate is limited by a hardware resource.  The SFN5x series adapters "
"support approximately 120,000 packet buffers.",
           , , 32768, 1024, MAX, count)

CI_CFG_OPT("EF_MAX_RX_PACKETS", max_rx_packets, ci_int32,
"The maximum number of packet buffers in a stack that can be used by the "
"receive data path.  This should be set to a value smaller than "
"EF_MAX_PACKETS to ensure that some packet buffers are reserved for the "
"transmit path.",
           , , 24576, 0, 1000000000, count)

CI_CFG_OPT("EF_MAX_TX_PACKETS", max_tx_packets, ci_int32,
"The maximum number of packet buffers in a stack that can be used by the "
"transmit data path.  This should be set to a value smaller than "
"EF_MAX_PACKETS to ensure that some packet buffers are reserved for the "
"receive path.",
           , , 24576, 0, 1000000000, count)

/* TODO ON-16706 allow 0 ring size for now for development purposes */
CI_CFG_OPT("EF_RXQ_MIN", rxq_min, ci_uint16,
"Minimum initial fill level for each RX ring.  If Onload is not able to "
"allocate sufficient packet buffers to fill each RX ring to this level, then "
"creation of the stack will fail.",
           , , 256, 0, MAX, count)

CI_CFG_OPT("EF_MIN_FREE_PACKETS", min_free_packets, ci_int32,
"Minimum number of free packets to reserve for each stack at initialisation.  "
"If Onload is not able to allocate sufficient packet buffers to fill the "
"RX rings and fill the free pool with the given number of buffers, then "
"creation of the stack will fail.",
           , , 100, 0, 1000000000, count)

CI_CFG_OPT("EF_PREFAULT_PACKETS", prefault_packets, ci_int32,
"When set, this option causes the process to 'touch' the specified number of "
"packet buffers when the Onload stack is created.  This causes memory for "
"the packet buffers to be pre-allocated, and also causes them to be memory-"
"mapped into the process address space.  This can prevent latency jitter "
"caused by allocation and memory-mapping overheads."
"\n"
"The number of packets requested is in addition to the packet buffers that "
"are allocated to fill the RX rings.  There is no guarantee that it will be "
"possible to allocate the number of packet buffers requested."
"\n"
"The default setting causes all packet buffers to be mapped into the "
"user-level address space, but does not cause any extra buffers to be "
"reserved.  Set to 0 to prevent prefaulting.",
           , , 1, 0, 1000000000, count)

CI_CFG_OPT("EF_PREALLOC_PACKETS", prealloc_packets, ci_int32,
"If set ensures all packet buffers (EF_MAX_PACKETS) get allocated during "
"stack creation or the stack creation fails.  Also when set "
"EF_MIN_FREE_PACKETS option is not taken into account.",
           , , 0, 0, 1, yesno)

/* Max is currently 2^21 EPs.
 * We allocate ep in pages, EP_BUF_PER_PAGE=4 ep per page, so min is 4.
 * 7 synrecv states consume one endpoint, but we also use aux buffers for
 * listening buckets, so the real ratio is 3,5 synrecv state consumes on
 * endpoint. */
CI_CFG_OPT("EF_MAX_ENDPOINTS", max_ep_bufs, ci_uint32,
"This option places an upper limit on the number of accelerated endpoints "
"(sockets, pipes etc.) in an Onload stack.  This option should be set to a "
"power of two between 4 and 2^21."
"\n"
"When this limit is reached listening sockets are not able to accept new "
"connections over accelerated interfaces.  New sockets and pipes created via "
"socket() and pipe() etc. are handed over to the kernel stack and so are not "
"accelerated."
"\n"
"Note: ~4 syn-receive states consume one endpoint, see also "
"EF_TCP_SYNRECV_MAX.",
           , , CI_CFG_NETIF_MAX_ENDPOINTS, 4, CI_CFG_NETIF_MAX_ENDPOINTS_MAX,
           count)


CI_CFG_OPT("EF_ENDPOINT_PACKET_RESERVE", endpoint_packet_reserve, ci_uint16,
"This option enables reservation of packets per endpoint.  No other endpoints"
"would be able to use that reserved quota.  Furthermore, "
"new endpoints will only be created if there are enough free packets to reserve.  "
"Currently, this option is limited to TCP sockets and enforced on incoming "
"TCP connections.",
          , , 0, 0, 1024, count)


CI_CFG_OPT("EF_DEFER_ARP_MAX", defer_arp_pkts, ci_uint16,
"Maximum number of packets to keep while resolving MAC address "
"(via ARP protocol for IPv4 or Neighbor Discovery for IPv6).",
          , , 128, 0, 4096, count)

CI_CFG_OPT("EF_DEFER_ARP_TIMEOUT", defer_arp_timeout, ci_uint16,
"Time to in seconds keep packets and try to resolve MAC address "
"(via ARP protocol for IPv4 or Neighbor Discovery for IPv6).",
          , , 60, 1, 600, time:sec)


CI_CFG_OPT("EF_TCP_SNDBUF_ESTABLISHED_DEFAULT", tcp_sndbuf_est_def, ci_uint32,
"Overrides the OS default SO_SNDBUF value for TCP sockets in the ESTABLISHED "
"state if the OS default SO_SNDBUF value falls outside bounds set with this "
"option. This value is used when the TCP connection transitions to "
"ESTABLISHED state, to avoid confusion of some applications like netperf.\n"
"The lower bound is set to this value and the upper bound is set to 4 * this "
"value. If the OS default SO_SNDBUF value is less than the lower bound, then "
"the lower bound is used. If the OS default SO_SNDBUF value is more than the "
"upper bound, then the upper bound is used.\n"
"This variable overrides OS default SO_SNDBUF value only, it does not "
"change SO_SNDBUF if the application explicitly sets it "
"(see EF_TCP_SNDBUF variable which overrides application-supplied value).",
           ,  , 128 * 1024, 0, SMAX/4, bincount)

CI_CFG_OPT("EF_TCP_RCVBUF_ESTABLISHED_DEFAULT", tcp_rcvbuf_est_def, ci_uint32,
"Overrides the OS default SO_RCVBUF value for TCP sockets in the ESTABLISHED "
"state if the OS default SO_RCVBUF value falls outside bounds set with this "
"option. This value is used when the TCP connection transitions to "
"ESTABLISHED state, to avoid confusion of some applications like netperf.\n"
"The lower bound is set to this value and the upper bound is set to 4 * this "
"value. If the OS default SO_RCVBUF value is less than the lower bound, then "
"the lower bound is used. If the OS default SO_RCVBUF value is more than the "
"upper bound, then the upper bound is used.\n"
"This variable overrides OS default SO_RCVBUF value only, it does not "
"change SO_RCVBUF if the application explicitly sets it "
"(see EF_TCP_RCVBUF variable which overrides application-supplied value).",
           ,  , 128 * 1024, 0, SMAX/4, bincount)

CI_CFG_OPT("", tcp_sndbuf_min, ci_uint32,
"Minimum value for SO_SNDBUF for TCP sockets.  Set via O/S interface.",
           ,  tcp_sndbuf, CI_CFG_TCP_SNDBUF_MIN, MIN, MAX, bincount)

CI_CFG_OPT("", tcp_sndbuf_def, ci_uint32,
"Default value for SO_SNDBUF for TCP sockets.  Set via O/S interface.",
           ,  tcp_sndbuf,      CI_CFG_TCP_SNDBUF_DEFAULT, MIN, MAX, bincount)

CI_CFG_OPT("", tcp_sndbuf_max, ci_uint32,
"Maximum value for SO_SNDBUF for TCP sockets.  Set via O/S interface.",
           ,  tcp_sndbuf,      CI_CFG_TCP_SNDBUF_MAX, MIN, MAX, bincount)

CI_CFG_OPT("", tcp_rcvbuf_min, ci_uint32,
"Minimum value for SO_RCVBUF for TCP sockets.  Set via O/S interface.",
           ,  tcp_rcvbuf, CI_CFG_TCP_RCVBUF_MIN, MIN, MAX, bincount)

CI_CFG_OPT("", tcp_rcvbuf_def, ci_uint32,
"Default value for SO_RCVBUF for TCP sockets.  Set via O/S interface.",
           ,  tcp_rcvbuf, CI_CFG_TCP_RCVBUF_DEFAULT, MIN, MAX, bincount)

CI_CFG_OPT("", tcp_rcvbuf_max, ci_uint32,
"Maximum value for SO_RCVBUF for TCP sockets.  Set via O/S interface.",
           ,  tcp_rcvbuf,     CI_CFG_TCP_RCVBUF_MAX, MIN, MAX, bincount)

CI_CFG_OPT("", udp_sndbuf_min, ci_uint32,
"Minimum value for SO_SNDBUF for UDP sockets.  Set via O/S interface.",
           ,  udp_sndbuf, CI_CFG_UDP_SNDBUF_MIN, MIN, MAX, bincount)

CI_CFG_OPT("", udp_sndbuf_def, ci_uint32,
"Default value for SO_SNDBUF for UDP sockets.  Set via O/S interface.",
           ,  udp_sndbuf, CI_CFG_UDP_SNDBUF_DEFAULT, MIN, MAX, bincount)

CI_CFG_OPT("", udp_sndbuf_max, ci_uint32,
"Maximum value for SO_SNDBUF for UDP sockets.  Set via O/S interface.",
           ,  udp_sndbuf, CI_CFG_UDP_SNDBUF_MAX, MIN, MAX, bincount)

CI_CFG_OPT("", udp_rcvbuf_min, ci_uint32,
"Minimum value for SO_RCVBUF for UDP sockets.  Set via O/S interface.",
           ,  udp_rcvbuf, CI_CFG_UDP_RCVBUF_MIN, MIN, MAX, bincount)

CI_CFG_OPT("", udp_rcvbuf_def, ci_uint32,
"Default value for SO_RCVBUF for UDP sockets.  Set via O/S interface.",
           ,  udp_rcvbuf, CI_CFG_UDP_RCVBUF_DEFAULT, MIN, MAX, bincount)

CI_CFG_OPT("", udp_rcvbuf_max, ci_uint32,
"Maximum value for SO_RCVBUF for UDP sockets.  Set via O/S interface.",
           ,  udp_rcvbuf, CI_CFG_UDP_RCVBUF_MAX, MIN, MAX, bincount)

CI_CFG_OPT("EF_TCP_SNDBUF", tcp_sndbuf_user, ci_uint32,
"Override SO_SNDBUF for TCP sockets (Note: the actual size of the buffer is "
"double the amount requested, mimicking the behavior of the Linux kernel.)",
           ,  tcp_sndbuf,     0, 0, SMAX/2, bincount)

CI_CFG_OPT("EF_TCP_RCVBUF", tcp_rcvbuf_user, ci_uint32,
"Override SO_RCVBUF for TCP sockets. (Note: the actual size of the buffer is "
"double the amount requested, mimicking the behavior of the Linux kernel.)",
           ,  tcp_rcvbuf, 0, 0, SMAX/2, bincount)

CI_CFG_OPT("EF_UDP_SNDBUF", udp_sndbuf_user, ci_uint32,
"Override SO_SNDBUF for UDP sockets. (Note: the actual size of the buffer is "
"double the amount requested, mimicking the behavior of the Linux kernel.)",
           ,  udp_sndbuf, 0, 0, SMAX/2, bincount)

CI_CFG_OPT("EF_UDP_RCVBUF", udp_rcvbuf_user, ci_uint32,
"Override SO_RCVBUF for UDP sockets. (Note: the actual size of the buffer is "
"double the amount requested, mimicking the behavior of the Linux kernel.)",
           ,  udp_rcvbuf, 0, 0, SMAX/2, bincount)

CI_CFG_OPT("EF_TCP_BACKLOG_MAX", tcp_backlog_max, ci_uint32,
"Places an upper limit on the number of embryonic (half-open) connections for "
"one listening socket; see also EF_TCP_SYNRECV_MAX.\n"
"The value from /proc/sys/net/ipv4/tcp_max_syn_backlog is used by default.",
           , , CI_TCP_LISTENQ_MAX, MIN, MAX, bincount)

/* The number we really use is tcp_synrecv_max*2 - it is the maximum
 * number of aux buffers, assuming that synrrecv state can use one half of
 * them and listening bucktes use another half. */
CI_CFG_OPT("EF_TCP_SYNRECV_MAX", tcp_synrecv_max, ci_uint32,
"Places an upper limit on the number of embryonic (half-open) connections in "
"an Onload stack; see also EF_TCP_BACKLOG_MAX.  By default, "
"EF_TCP_SYNRECV_MAX = 4 * EF_TCP_BACKLOG_MAX.",
           , , CI_TCP_LISTENQ_MAX * CI_CFG_ASSUME_LISTEN_SOCKS,
           MIN, CI_CFG_NETIF_MAX_ENDPOINTS_MAX, bincount)

CI_CFG_OPT("EF_TCP_INITIAL_CWND", initial_cwnd, ci_uint32,
"Sets the initial size of the congestion window (in bytes) for TCP "
"connections. Some care is needed as, for example, setting smaller than the "
"segment size may result in Onload being unable to send traffic. "
"\n"
"WARNING: Modifying this option may violate the TCP protocol.",
           ,  , 0, 0, SMAX, count)

CI_CFG_OPT("EF_TCP_LOSS_MIN_CWND", loss_min_cwnd, ci_uint32,
"Sets the minimum size of the congestion window for TCP connections following "
"loss."
"\n"
"WARNING: Modifying this option may violate the TCP protocol."
"\n"
"Deprecated.  Please use EF_TCP_MIN_CWND instead."
,
           ,  , 0, 0, SMAX, count)

CI_CFG_OPT("EF_TCP_MIN_CWND", min_cwnd, ci_uint32,
"Sets the minimum size of the congestion window for TCP connections. "
"This value is used for any congestion window changes: connection start, "
"packet loss, connection being idle, etc."
"\n"
"WARNING: Modifying this option may violate the TCP protocol.",
           ,  , 0, 0, SMAX, count)

#if CI_CFG_TCP_FASTSTART
CI_CFG_OPT("EF_TCP_FASTSTART_INIT", tcp_faststart_init, ci_uint32,
"The FASTSTART feature prevents Onload from delaying ACKs during times when "
"doing so may reduce performance.  FASTSTART is enabled when a connection is "
"new, following loss and after the connection has been idle for a while."
"\n"
"This option sets the number of bytes that must be ACKed by the receiver "
"before the connection exits FASTSTART.  Set to zero to disable FASTSTART "
"on new connections.",
           ,  , 64*1024, 0, MAX, count)

CI_CFG_OPT("EF_TCP_FASTSTART_IDLE", tcp_faststart_idle, ci_uint32,
"The FASTSTART feature prevents Onload from delaying ACKs during times when "
"doing so may reduce performance.  FASTSTART is enabled when a connection is "
"new, following loss and after the connection has been idle for a while."
"\n"
"This option sets the number of bytes that must be ACKed by the receiver "
"before the connection exits FASTSTART.  Set to zero to prevent a connection "
"entering FASTSTART after an idle period.",
           ,  , 64*1024, 0, MAX, count)

CI_CFG_OPT("EF_TCP_FASTSTART_LOSS", tcp_faststart_loss, ci_uint32,
"The FASTSTART feature prevents Onload from delaying ACKs during times when "
"doing so may reduce performance.  FASTSTART is enabled when a connection is "
"new, following loss and after the connection has been idle for a while."
"\n"
"This option sets the number of bytes that must be ACKed by the receiver "
"before the connection exits FASTSTART following loss.  Set to zero to "
"disable FASTSTART after loss.",
           ,  , 64*1024, 0, MAX, count)
#endif

CI_CFG_OPT("EF_TCP_EARLY_RETRANSMIT", tcp_early_retransmit, ci_uint32,
"Enables the Early Retransmit (RFC 5827) algorithm for TCP, and also the "
"Limited Transmit (RFC 3042) algorithm, on which Early Retransmit depends.\n"
"The value from /proc/sys/net/ipv4/tcp_early_retrans is used to derive "
"the default.",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_RFC_RTO_INITIAL", rto_initial, ci_iptime_t,
"Initial retransmit timeout in milliseconds.  i.e. The number of "
"milliseconds to wait for an ACK before retransmitting packets.",
           ,  rto, CI_TCP_TCONST_RTO_INITIAL, MIN, MAX, time:msec)

CI_CFG_OPT("EF_RFC_RTO_MIN", rto_min, ci_iptime_t,
"Minimum retransmit timeout in milliseconds.",
           ,  rto, CI_TCP_TCONST_RTO_MIN, MIN, MAX, time:msec)

CI_CFG_OPT("EF_RFC_RTO_MAX", rto_max, ci_iptime_t,
"Maximum retransmit timeout in milliseconds.",
           ,  rto, CI_TCP_TCONST_RTO_MAX, MIN, MAX, time:msec)

CI_CFG_OPT("EF_KEEPALIVE_TIME", keepalive_time, ci_iptime_t,
"Default idle time before keepalive probes are sent, in milliseconds.\n"
"The value from /proc/sys/net/ipv4/tcp_keepalive_time (which is in seconds) "
"is used to find the default.",
           , , CI_TCP_TCONST_KEEPALIVE_TIME, MIN, MAX, time:msec)

CI_CFG_OPT("EF_KEEPALIVE_INTVL", keepalive_intvl, ci_iptime_t,
"Default interval between keepalives, in milliseconds.\n"
"The value from /proc/sys/net/ipv4/tcp_keepalive_intvl (which is in seconds) "
"is used to find the default.",
           , ,  CI_TCP_TCONST_KEEPALIVE_INTVL, MIN, MAX, time:msec)

CI_CFG_OPT("EF_KEEPALIVE_PROBES", keepalive_probes, ci_uint32,
"Default number of keepalive probes to try before aborting the connection.\n"
"The value from /proc/sys/net/ipv4/tcp_keepalive_probes is used by default.",
           , , CI_TCP_KEEPALIVE_PROBES, MIN, MAX, count)

CI_CFG_OPT("EF_TCP_RST_COOLDOWN", tcp_rst_cooldown, ci_uint32,
"Minimum time, in us, between consecutive sends of TCP RSTs to the same "
"destination (ip, port) pair.",
           , , CI_TCP_RST_COOLDOWN_DEFAULT, MIN, MAX, time:usec)

#ifndef NDEBUG
CI_CFG_OPT("EF_TCP_MAX_SEQERR_MSGS", tcp_max_seqerr_msg, ci_uint32,
"Maximum number of unacceptable sequence error messages to emit, per socket.",
           , , -1, MIN, MAX, count)
#endif

#if CI_CFG_BURST_CONTROL
CI_CFG_OPT("EF_BURST_CONTROL_LIMIT", burst_control_limit, ci_uint32,
"If non-zero, limits how many bytes of data are transmitted in a single burst. "
"This can be useful to avoid drops on low-end switches which contain limited "
"buffering or limited internal bandwidth.  This is not usually needed for use "
"with most modern, high-performance switches.",
           , , CI_CFG_TCP_BURST_CONTROL_LIMIT, MIN, MAX, count)
#endif

#if CI_CFG_CONG_AVOID_NOTIFIED
CI_CFG_OPT("EF_CONG_NOTIFY_THRESH", cong_notify_thresh, ci_uint32,
/* FIXME: need to introduce concept of burst control. */
"How much tx queue used before we activate burst control.",
           , , CI_CFG_CONG_NOTIFY_THRESH, MIN, MAX, bincount)
#endif

#if CI_CFG_CONG_AVOID_SCALE_BACK
CI_CFG_OPT("EF_CONG_AVOID_SCALE_BACK", cong_avoid_scale_back, ci_uint32,
"When >0, this option slows down the rate at which the TCP congestion window "
"is opened.  This can help to reduce loss in environments where there is lots "
"of congestion and loss.",
           , , 0, MIN, MAX, count/*?*/)
#endif

CI_CFG_OPT("EF_FREE_PACKETS_LOW_WATERMARK", free_packets_low, ci_uint16,
"Keep free packets number to be at least this value.  EF_MIN_FREE_PACKETS "
"defines initialisation behaviour; this value is about normal application "
"runtime.  In some combinations of hardware and software, Onload is not "
"able allocate packets at any context, so it makes sense to keep some "
"spare packets.  Default value 0 is interpreted as EF_RXQ_SIZE/2",
           , , 0, MIN, MAX, count)

#if CI_CFG_PIO
CI_CFG_OPT("EF_PIO_THRESHOLD", pio_thresh, ci_uint16,
"Sets a threshold for the size of packet that will use PIO (if turned on "
"using EF_PIO) or CTPIO (if turned on using EF_CTPIO).  Packets up to the "
"threshold will use PIO or CTPIO.  Larger packets will not.",
           , , 1514, 0, MAX, count)
#endif

#if CI_CFG_CTPIO
CI_CFG_OPT("EF_CTPIO_MAX_FRAME_LEN", ctpio_max_frame_len, ci_uint16,
"Sets the maximum frame length for the CTPIO low-latency transmit mechanism.  "
"Packets up to this length will use CTPIO, if CTPIO is supported by the "
"adapter and if CTPIO is enabled (see EF_CTPIO).  Longer packets will use "
"PIO and/or DMA.  The cost per byte of packet payload varies between host "
"architectures, as does the effect of packet size on the probability of "
"poisoning, and so on some hosts it may be beneficial to reduce this value.",
           , , 0, 0, 4092, count)
#endif

#if CI_CFG_CTPIO
CI_CFG_OPT("EF_CTPIO_CT_THRESH", ctpio_ct_thresh, ci_uint16,
"Experimental: Sets the cut-through threshold for CTPIO transmits, when "
"EF_CTPIO_MODE=ct.  This option is for test purposes only and is likely to be "
"changed or removed in a future release.",
           , , 64, 0, MAX, count)
#endif

#if CI_CFG_CTPIO
CI_CFG_OPT("EF_CTPIO_SWITCH_BYPASS", ctpio_switch_bypass, ci_uint32,
"Allows CTPIO to be enabled on interfaces using the adapter's internal "
"switch (i.e. on interfaces running full-feature firmware).  This switching "
"functionality is used to implement hardware multicast loopback and hardware "
"loopback between interfaces, as used by virtual machines.  CTPIO bypasses "
"the switch, and hence is not compatible with those features.",
           1, , 0, 0, 1, yesno)
#endif

CI_CFG_OPT("EF_TX_PUSH_THRESHOLD", tx_push_thresh, ci_uint16,
"Sets a threshold for the number of outstanding sends before we stop using "
"TX descriptor push.  This has no effect if EF_TX_PUSH=0.  This "
"threshold is ignored, and assumed to be 1, on pre-SFN7000-series "
"hardware. It makes sense to set this value similar to EF_SEND_POLL_THRESH",
           , , 100, 1, MAX, count)

#define CI_EF_LOG_DEFAULT ((1 << EF_LOG_BANNER) | (1 << EF_LOG_RESOURCE_WARNINGS) | (1 << EF_LOG_CONFIG_WARNINGS) | (1 << EF_LOG_USAGE_WARNINGS))
CI_CFG_OPT("EF_LOG", log_category, ci_uint32,
"Designed to control how chatty Onload's informative/warning messages are.  "
"Specified as a comma seperated list of options to enable and disable "
"(with a minus sign).  Valid options are 'banner' (on by default), "
"'resource_warnings' (on by default), 'config_warnings' (on by default), "
"'more_config_warnings' (off by default), 'conn_drop' (off by default) and "
"'usage_warnings' (on by default).  E.g.: To enable conn_drop: EF_LOG=conn_drop. "
"E.g.: To enable conn_drop and turn off resource warnings: "
"EF_LOG=conn_drop,-resource_warnings",
           , , CI_EF_LOG_DEFAULT, 0, MAX, count)


#if CI_CFG_TCP_SHARED_LOCAL_PORTS
CI_CFG_OPT("EF_TCP_SHARED_LOCAL_PORTS", tcp_shared_local_ports, ci_uint32,
"This feature improves the performance of TCP active-opens.  It reduces the "
"cost of both blocking and non-blocking connect() calls, reduces the "
"latency to establish new connections, and enables scaling to large numbers "
"of active-open connections.  It also reduces the cost of closing these "
"connections."
"\n"
"These improvements are achieved by sharing a set of local port numbers "
"amongst active-open sockets, which saves the cost and scaling limits "
"associated with installing packet steering filters for each active-open "
"socket.  Shared local ports are only used when the local port is not "
"explicitly assigned by the application."
"\n"
"Set this option to >=1 to enable local port sharing.  The value set gives "
"the initial number of local ports to allocate when the Onload stack is "
"created.  More shared local ports are allocated on demand as needed up to "
"the maximum given by EF_TCP_SHARED_LOCAL_PORTS_MAX."
"\n"
"Note that typically only one local shared port is needed, as different "
"local ports are only needed when multiple connections are made to the same "
"remote IP:port.",
           , , 0, 0, MAX, count)

CI_CFG_OPT("EF_TCP_SHARED_LOCAL_PORTS_REUSE_FAST",
           tcp_shared_local_ports_reuse_fast, ci_uint32,
"When enabled, this option allows shared local ports (as controlled by the "
"EF_TCP_SHARED_LOCAL_PORTS option) to be reused immediately when the previous "
"socket using that port has reached the CLOSED state, even if it did so via "
"LAST-ACK.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_SHARED_LOCAL_PORTS_MAX", tcp_shared_local_ports_max,
           ci_uint32,
"This setting sets the maximum size of the pool of local shared ports "
"in the stack.  See EF_TCP_SHARED_LOCAL_PORTS for details.",
           , , 100, 0, MAX, count)

CI_CFG_OPT("EF_TCP_SHARED_LOCAL_PORTS_NO_FALLBACK",
           tcp_shared_local_no_fallback, ci_uint32,
"When set, connecting TCP sockets will use ports only from the TCP shared "
"local port pool (unless explicitly bound).  If all shared local ports are in "
"use, the connect() call will fail.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_SHARED_LOCAL_PORTS_PER_IP",
           tcp_shared_local_ports_per_ip, ci_uint32,
"When set, ports reserved for the pool of shared local ports will be reserved "
"per local IP address on demand.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_SHARED_LOCAL_PORTS_PER_IP_MAX", tcp_shared_local_ports_per_ip_max,
           ci_uint32,
"Sets the maximum size of the pool of local shared ports "
"for given local IP address.  When used with scalable RSS mode this "
"setting limits the total number within the cluster.  0 - no limit.  "
"See EF_TCP_SHARED_LOCAL_PORTS for details.",
           , , 0, 0, MAX, count)

CI_CFG_OPT("EF_TCP_SHARED_LOCAL_PORTS_STEP",
           tcp_shared_local_ports_step, ci_uint32,
"Controls the number of ports allocated when expanding the pool of shared "
"local ports.",
           , , 1, 1, MAX, count)
#endif /* CI_CFG_TCP_SHARED_LOCAL_PORTS */

CI_CFG_STR_OPT("EF_SCALABLE_FILTERS", scalable_filter_string, ci_string256,
"Specifies the interface on which to enable support for scalable filters, "
"and configures the scalable filter mode(s) to use.  Scalable filters "
"allow Onload to use a single hardware MAC-address filter to avoid "
"hardware limitations and overheads.  This removes restrictions on "
"the number of simultaneous connections and increases performance of "
"active connect calls, but kernel support on the selected interface is "
"limited to ARP/DHCP/ICMP protocols and some Onload features that rely "
"on unaccelerated traffic (such as receiving fragmented UDP datagrams) "
" will not work.  Please see the Onload user guide for full details.\n"
"\n"
"Depending on the mode selected this option will enable support for:\n"
" - scalable listening sockets;\n"
" - IP_TRANSPARENT socket option;\n"
" - scalable active open;\n"
"\n"
"The interface specified must be a SFN7000 or later NIC."
"\n"
"Format of EF_SCALABLE_FILTERS variable is as follows:\n"
"  EF_SCALABLE_FILTERS=[<interface-name>[=mode[:mode]],]<interface-name>[=mode[:mode]]\n"
"      where mode is one of: transparent_active,passive,rss\n"
"The following modes and their combinations can be specified:\n"
"  transparent_active, rss:transparent_active, passive,"
" rss:passive, transparent_active:passive, active, rss:active, rss:passive:active.\n "
"It is possible to specify both an active mode interface and a passive mode "
"interface.  If two interfaces are specfied then both the active and passive "
"interfaces must have the same rss qualifier. Furthermore, if the interface "
"is the string 'any', scalable filters are installed on all interfaces.",
               ,  , "", none, none, )

#define CITP_SCALABLE_MODE_NONE              0x0
#define CITP_SCALABLE_MODE_RSS               0x1
#define CITP_SCALABLE_MODE_TPROXY_ACTIVE     0x2
#define CITP_SCALABLE_MODE_PASSIVE           0x4
#define CITP_SCALABLE_MODE_ACTIVE            0x8

#define CITP_SCALABLE_MODE_TPROXY_ACTIVE_RSS (CITP_SCALABLE_MODE_TPROXY_ACTIVE | \
                                              CITP_SCALABLE_MODE_RSS)
#define CITP_SCALABLE_MODE_ACTIVE_RSS (CITP_SCALABLE_MODE_ACTIVE | \
                                       CITP_SCALABLE_MODE_RSS)
#define CITP_SCALABLE_MODE_PASSIVE_RSS (CITP_SCALABLE_MODE_PASSIVE | \
                                       CITP_SCALABLE_MODE_RSS)

#define CITP_SCALABLE_MODE_PASSIVE_ACTIVE_RSS (CITP_SCALABLE_MODE_ACTIVE | \
                                       CITP_SCALABLE_MODE_PASSIVE | \
                                       CITP_SCALABLE_MODE_RSS)

/* Use scalable filters on all interfaces if scalable ifindex is set to this
 * magic value. */
#define CITP_SCALABLE_FILTERS_ALL   -1
#define CITP_SCALABLE_FILTERS_MIN   CITP_SCALABLE_FILTERS_ALL

CI_CFG_OPT("EF_SCALABLE_FILTERS_IFINDEX_ACTIVE", scalable_filter_ifindex_active,
           /* N.B. This must be signed to allow CITP_SCALABLE_FILTERS_ALL. */
           ci_int32,
           "Stores active scalable filter interface set with EF_SCALABLE_FILTERS.  "
           "To be set indirectly with EF_SCALABLE_FILTERS variable",
           , , 0, CITP_SCALABLE_FILTERS_MIN, SMAX, count)

CI_CFG_OPT("EF_SCALABLE_FILTERS_IFINDEX_PASSIVE", scalable_filter_ifindex_passive,
           /* N.B. This must be signed to allow CITP_SCALABLE_FILTERS_ALL. */
           ci_int32,
           "Stores passive scalable filter interface set with EF_SCALABLE_FILTERS.  "
           "To be set indirectly with EF_SCALABLE_FILTERS variable",
           , , 0, CITP_SCALABLE_FILTERS_MIN, SMAX, count)

CI_CFG_OPT("EF_SCALABLE_FILTERS_MODE", scalable_filter_mode, ci_int32,
           "Stores scalable filter mode set with EF_SCALABLE_FILTERS.  "
           "To be set indirectly with EF_SCALABLE_FILTERS variable",
           ,  , -1, -1, 13, oneof:
           auto;
/* Note: the enumerated values need to match flags above */
           none;reserved1;transparent_active;rss_transparent_active;
           passive;rss_passive;passive_tproxy_active;reserved7;
           active;rss_active;reserved10;reserved11;
           passive_active;rss_passive_active;
           )

CI_CFG_OPT("EF_PERIODIC_TIMER_CPU", periodic_timer_cpu, ci_int32,
           "Affinitises Onload's periodic tasks to the specified CPU core. "
           "To ensure that Onload internal tasks such as polling timers are "
           "correctly serviced, the user should select a CPU that is receiving "
           "periodic timer ticks."
           , , , -1, -1, SMAX, count)

#define CITP_SCALABLE_FILTERS_DISABLE 0
#define CITP_SCALABLE_FILTERS_ENABLE  1
#define CITP_SCALABLE_FILTERS_ENABLE_WORKER  2
CI_CFG_OPT("EF_SCALABLE_FILTERS_ENABLE", scalable_filter_enable, ci_int32,
"Turn the scalable filter feature on or off on a stack.  Takes one of the "
"following values:\n"
" 0 - Scalable filters are not used for this stack.\n"
" 1 - The configuration selected in EF_SCALABLE_FILTERS will be used.\n"
" 2 - Indicates a special mode to address a master-worker hierarchy of some "
"event driven applications.  The scalable filter get created for reuseport "
"bound sockets in the master process context.  However, active mode will become"
" available in worker processes once they add one of the sockets "
"to their epoll set.  Applies to rss:*active scalable mode.  This mode is not "
"compatible with use of the onload extensions stackname API.\n"
"If unset this will default to 1 if EF_SCALABLE_FILTERS is configured.",
           , , 0, 0, 2, yesno)

#define CITP_SCALABLE_LISTEN_BOUND 0
#define CITP_SCALABLE_LISTEN_ACCELERATED_ONLY 1
CI_CFG_OPT("EF_SCALABLE_LISTEN_MODE", scalable_listen, ci_uint32,
"Choose behaviour of scalable listening sockets when using EF_SCALABLE_INTERFACE:\n"
"  0  -  Listening sockets bound to a local address configured on the scalable"
"        interface use the scalable filter(default).  Connections on other interfaces"
"        are not accelerated.\n"
"  1  -  Listening sockets bound to a local address configured on the scalable"
"        interface use the scalable filter.  Connections on other interfaces"
"        including loopback are refused.  This mode avoids kernel scalability"
"        issue with large numbers of listen sockets.\n",
         , , 0, 0, 1, oneof:bound;accelerated_only;)

#if CI_CFG_TCP_SHARED_LOCAL_PORTS
CI_CFG_OPT("EF_SCALABLE_ACTIVE_WILDS_NEED_FILTER",
           scalable_active_wilds_need_filter, ci_uint32,
"When set to 1, IP filter is installed for every cached active-opened socket "
"(see EF_TCP_SHARED_LOCAL_PORTS).  Otherwise it is assumed that scalable "
"filters do the job."
"\n"
"Default: 1 if EF_SCALABLE_FILTERS_ENABLE=1 and scalable mode in "
"EF_SCALABLE_FILTERS_MODE is \"active\"; 0 otherwise.",
           , , 0, 0, 1, yesno)
#endif

CI_CFG_STR_OPT("EF_INTERFACE_WHITELIST", iface_whitelist, ci_string256,
               "List of names of interfaces to use by the stack.  "
               "Space separated.\n"
               "Note: beside passing network interface of Solarflare NIC itself, "
               "it is allowed to provide name of higher order interface such as "
               "VLAN, MACVLAN, team or bond.  At stack creation time these names "
               "will be used to identify underlaying Solarflare NICs on which the "
               "whitelisting operates.\n"
               "Note: the granularity of whitelisting is limited: all interfaces "
               "based on whitelisted Solarflare NICs are accelerated.",
               ,  , "", none, none, )

CI_CFG_STR_OPT("EF_INTERFACE_BLACKLIST", iface_blacklist, ci_string256,
               "List of names of interfaces not to be used by the stack.  "
               "Space separated.\n"
               "See EF_INTERFACE_WHITELIST for notes as the same caveats apply.\n"
               "Note: blacklist takes priority over whitelist.  That is when "
               "interface is present on both lists it will not be accelerated." ,
               ,  , "", none, none, )

#define EF_MULTIARCH_DATAPATH_FF 0
#define EF_MULTIARCH_DATAPATH_LLCT 1
#define EF_MULTIARCH_DATAPATH_BOTH 2

CI_CFG_OPT("EF_TX_DATAPATH", multiarch_tx_datapath, ci_uint32,
           "Select TX datapath on all multiarch NICs:"
           "  enterprise (fully featured)\n"
           "  express (lowest latency)\n",
           1, , 1, 0, 1, oneof:enterprise;express)

CI_CFG_OPT("EF_RX_DATAPATH", multiarch_rx_datapath, ci_uint32,
           "Select RX datapaths on all multiarch NICs:"
           "  enterprise (fully featured)\n"
           "  express (lowest latency)\n"
           "  both (prefer express, fallback to enterprise)\n",
           2, , 2, 0, 2, oneof:enterprise;express;both)

CI_CFG_OPT("EF_LLCT_TEST_SHRUB", llct_test_shrub, ci_uint32,
           "Experimental: force llct datapath to use shrub not local rxqs",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_KERNEL_PACKETS_BATCH_SIZE", kernel_packets_batch_size, ci_uint32,
"In some cases (for example, when using scalable filters), packets that "
"should be delivered to the kernel stack are "
"instead delivered to Onload.  Onload will forward these packets to the "
"kernel, and may do so in batches of size up to the value of this option.",
           , , 1, 0, 64/* 64 in NAPI weight*/, count)

CI_CFG_OPT("EF_KERNEL_PACKETS_TIMER_USEC", kernel_packets_timer_usec,
           ci_uint32,
"Controls the maximum time for which Onload will queue up a packet that was "
"received by Onload but should be forwarded to the kernel.",
           , , 500, MIN, MAX, count)

CI_CFG_OPT("EF_TCP_ISN_MODE", tcp_isn_mode, ci_uint16,
"Selects behaviour with which Onload interacts with peers when reusing four tuples:\n"
" * clocked - Linux compatible behaviour (default)\n"
" * clocked+cache - additional cache to avoid failed connection attempts "
"Note: the behaviour is relevant to high connection rate usecases with high "
"outgoing data rates.\n"
"When in clocked+cache mode, sequence numbers used by closed TCP connections "
"are remembered so that initial sequence numbers for subsequent uses of the "
"same four-tuple can be selected so as not to overlap with the previous "
"connection's sequence space.",
           1, , 1, 0, 1, oneof:clocked;clocked+cache)

CI_CFG_OPT("EF_TCP_ISN_INCLUDE_PASSIVE", tcp_isn_include_passive, ci_uint16,
"Enables populating isn cache with passively opened connections.  "
"Relevant when EF_TCP_ISN_MODE is set to clocked+cache.",
           1, , 0, 0, 1, yesno)


#define CITP_TCP_ISN_2MSL_DEFAULT 240
/* Needs to be less than half of isn clock's wrap time */
#define CITP_TCP_ISN_2MSL_MAX 480
CI_CFG_OPT("EF_TCP_ISN_2MSL", tcp_isn_2msl, ci_uint16,
"Maximum time that peer's are assumed to stay in TIMEWAIT state.  In seconds.  "
"Relevant when EF_TCP_ISN_MODE is set to clocked+cache",
         12, , CITP_TCP_ISN_2MSL_DEFAULT, MIN, CITP_TCP_ISN_2MSL_MAX, time:sec)

CI_CFG_OPT("EF_TCP_ISN_OFFSET", tcp_isn_offset, ci_uint32,
"Increase in sequence number between subsequent connections reusing the same 4-tuple.  "
"Lower value allows to reduce use of ISN cache, however potentially being unsafe "
"with some host types or rare usecases.",
         , , (65535 + 2), MIN, MAX, count)

CI_CFG_OPT("EF_TCP_ISN_CACHE_SIZE", tcp_isn_cache_size, ci_uint32,
"Cache size for recently used four tuples and their last sequence number.  "
"0 - automatically chosen.  "
"Relevant when EF_TCP_ISN_MODE is set to clocked+cache.",
           , , 0, MIN, MAX, time:sec)

#if CI_CFG_IPV6
#define CITP_IP6_AUTO_FLOW_LABEL_OFF     0
#define CITP_IP6_AUTO_FLOW_LABEL_OPTOUT  1
#define CITP_IP6_AUTO_FLOW_LABEL_OPTIN   2
#define CITP_IP6_AUTO_FLOW_LABEL_FORCED  3

CI_CFG_OPT("EF_AUTO_FLOWLABELS", auto_flowlabels, ci_uint32,
"Automatically generate flow labels based on a flow hash of the packet. "
" 0 - automatic flow labels are completely disabled"
" 1 - automatic flow labels are enabled by default, they can be"
"     disabled on a per socket basis using the IPV6_AUTOFLOWLABEL"
"     socket option"
" 2 - automatic flow labels are allowed, they may be enabled on a"
"     per socket basis using the IPV6_AUTOFLOWLABEL socket option"
" 3 - automatic flow labels are enabled and enforced, they cannot"
"     be disabled by the socket option\n"
"The value from /proc/sys/net/ipv6/auto_flowlabels is used by default.",
           , , CI_AUTO_FLOWLABELS_DEFAULT, 0, 3, count)
#endif

#ifdef CI_CFG_OPTGROUP
/* define some categories - currently more as an example than as the final
   thing */
CI_CFG_OPTGROUP(stripe_netmask_be32,         stripeing, 100)
CI_CFG_OPTGROUP(stripe_dupack_threshold,     stripeing, 100)
CI_CFG_OPTGROUP(stripe_tcp_opt,              stripeing, 100)

CI_CFG_OPTGROUP(keepalive_time,              keepalive, 100)
CI_CFG_OPTGROUP(keepalive_intvl,             keepalive, 100)
CI_CFG_OPTGROUP(keepalive_probes,            keepalive, 100)

CI_CFG_OPTGROUP(retransmit_threshold,        tcp_retransmission, 100)
CI_CFG_OPTGROUP(rto,                         tcp_retransmission, 100)
#endif


CI_CFG_OPT("EF_AF_XDP_ZEROCOPY", af_xdp_zerocopy, ci_uint32,
"Enables zerocopy on AF_XDP NICs. Support for zerocopy is required. ",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_ICMP_PKTS", icmp_msg_max, ci_uint32,
           "Maximum number of ICMP messages which can be queued to "
           "one Onload stack.",
           , , 64, 2, 1024, count)

CI_CFG_OPT("EF_NO_HW", no_hw, ci_uint32,
"Prevents the stack from allocating hardware resources. Local connections are "
"still accelerated, but remote connections are handed over to the kernel. If "
"the use of SO_REUSEPORT creates a cluster, then new stacks in the cluster "
"will allocate resources, and will be fully accelerated.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_DUMP_STACK_ON_EXIT", dump_stack_on_exit, ci_uint32,
"This is an unsupported option for debugging and may be removed at any time. "
"It causes details of the stack to be emitted to the kernel log when the "
"stack exits.",
           1, , 0, 0, 1, yesno)

#define EF_SHRUB_MAX_CONTROLLER 9999
CI_CFG_OPT("EF_SHRUB_CONTROLLER", shrub_controller_id ,ci_int32,
"Spawn or join onto a shrub controller with the given shrub controller id. ",
           , ,-1, -1, EF_SHRUB_MAX_CONTROLLER, count)

#define EF_SHRUB_DEFAULT_BUFFER_COUNT 4
CI_CFG_OPT("EF_SHRUB_BUFFER_COUNT", shrub_buffer_count, ci_uint32,
"Default value of superbufs that an onload client requests from "
"a shrub controller. ",
           , , EF_SHRUB_DEFAULT_BUFFER_COUNT, EF_SHRUB_DEFAULT_BUFFER_COUNT,
           100000, count)

CI_CFG_OPT("EF_SHRUB_UNICAST", shrub_unicast, ci_uint32,
"Direct unicast traffic to shrub managed queues.\n"
"By default multicast traffic on NICs that support shrub will be directed to "
"shrub managed queues. Unicast traffic will be directed to an exclusive queue."
" Setting this option forces unicast traffic to also be sent to the shrub "
"managed queue. This can be useful to reduce the number of queues consumed.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_SHRUB_DEBUG", shrub_debug, ci_uint32,
"Output debug logging from shrub controller.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_SHRUB_USE_INTERRUPTS", shrub_use_interrupts, ci_uint32,
"Enable interrupt driven mode when using shrub.\n"
"Setting this option will enable interrupts to be used with shrub. If it is "
"not set, applications must ensure they are actively polling to ensure that "
"data can be handled in userspace. If interrupts are not enabled and the "
"application does not spin, we will fall back to the periodic polling timer "
"to be woken up.",
           1, , 1, 0, 1, yesno)

#define EF_SHRUB_DEFAULT_AUTO_CLOSE_DELAY 15000
CI_CFG_OPT("EF_SHRUB_AUTO_CLOSE_DELAY", shrub_auto_close_delay, ci_int32,
"Set the number of milliseconds after which a shrub controller spawned by "
"Onload will close after all clients have disconnected. The special value of "
"-1 disables this feature, keeping a spawned controller alive indefinitely.",
           , , EF_SHRUB_DEFAULT_AUTO_CLOSE_DELAY, -1, SMAX, time:msec)

CI_CFG_OPT("EF_ENABLE_TX_ERROR_RECOVERY", tx_error_recovery, ci_uint32,
"Recover a broken TXQ after observing a TX error event.\n"
"If we see a TX error event for any reason, then the interface that saw it "
"will no longer be able to transmit on this TXQ. Setting this option to 0 "
"disables the automatic recovery of such a broken TXQ by onload.\n"
"When this option is enabled, all traffic we tried to send between the TX "
"error and recovery will be dropped. Notably, UDP packets will not be "
"retransmitted, but TCP data can be subsequently retransmitted via normal "
"TCP operation.",
           1, , 1, 0, 1, yesno)
