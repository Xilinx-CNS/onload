/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  Configuration options for transport lib
**   \date  2004/10/29
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__

/* This header is solely for configuration/compilation options!!
**
** In order to check for version skew between the driver and the user-mode
** library, we check against the CVS id for this header file.
** TODO: Checking against MD5 has of the file would be better.
** See also include/ci/internal/ip.h where we do the same thing.
*/
#define CI_CVS_OPT_HDR_VERSION ("$Revision$")

/* This just makes it a little neater to test for kernel. */
#ifdef __KERNEL__
# define CI_CFG_KERNEL                  1
#else
# define CI_CFG_KERNEL                  0
#endif

/* Maximum number of network interfaces (ports) per stack. */
#define CI_CFG_MAX_INTERFACES           8

/* Maximim number of hwports in the system */
#define CI_CFG_MAX_HWPORTS              8

/* Maximum number of local IP addresses in the system */
#define CI_CFG_MAX_LOCAL_IPADDRS        256

/* Do we need team/bond support? */
#define CI_CFG_TEAMING                  1

/* Some defaults.  These can be overridden at runtime. */
#define CI_CFG_NETIF_MAX_ENDPOINTS     (1<<13)
/* The real max for endpoint order.
 * Do not forget to change CI_EPLOCK_NETIF_SOCKET_LIST if you increase
 * this number.*/
#define CI_CFG_NETIF_MAX_ENDPOINTS_MAX (1<<21)

/* ANVL assumes the 2MSL time is 60 secs. Set slightly smaller */
#define CI_CFG_TCP_TCONST_MSL		25

#define CI_CFG_TCP_FIN_TIMEOUT         60

#define CI_CFG_BURST_CONTROL            1
#if CI_CFG_BURST_CONTROL
#define CI_CFG_TCP_BURST_CONTROL_LIMIT  0
#endif

#define CI_CFG_CONG_AVOID_NOTIFIED 0
#if CI_CFG_CONG_AVOID_NOTIFIED
#define CI_CFG_CONG_NOTIFY_THRESH 24
#endif

/* Debug aids.  Off by default, as some add lots of overhead. */
#ifndef CI_CFG_RANDOM_DROP
#define CI_CFG_RANDOM_DROP		0
#endif
#ifndef CI_CFG_POISON_BUFS
#define CI_CFG_POISON_BUFS		0
#endif
#ifndef CI_CFG_DETAILED_CHECKS
#define CI_CFG_DETAILED_CHECKS		0
#endif

/* Whether to hook the syscall function from libc. Currently supported only
 * on x86-64 to simplify the implementation.
 */
#ifdef __x86_64__
#define CI_CFG_USERSPACE_SYSCALL        1
#else
#define CI_CFG_USERSPACE_SYSCALL        0
#endif

/* Maximum number of onload stacks handled by single epoll object.
 * See also epoll_max_stacks module parameter.
 * Socket from other stacks will look just like "regular file descriptor"
 * for the onload object, without onload-specific acceleration. */
#define CI_CFG_EPOLL_MAX_STACKS         16

/* Maximum number of postponed epoll_ctl operations, in case of
 * EF_UL_EPOLL=2 and EF_EPOLL_CTL_FAST=1 */
#define CI_CFG_EPOLL_MAX_POSTPONED      10

/* Arbitrary limit of 1MB following linux kernel in Onload pipe
 * implementation */
#define CI_CFG_MAX_PIPE_SIZE            (1<<20)

/* Enable this to support port striping. */
#define CI_CFG_PORT_STRIPING            0

/* Non-RFC1191 recovery time:
 * when PMTU goes to min (a very small number, poss. a DoS attack) use
 * a shorter recovery time than the RFC allows. 
 * Set to 0 to keep ANVL happy */
#define CI_CFG_FAST_RECOVER_PMTU_AT_MIN 0 

#define CI_CFG_SUPPORT_STATS_COLLECTION	1
#define CI_CFG_TCP_SOCK_STATS           0

/* Enable this to cause buffered stats (from sockopt) to be output
 * to the log rather than written to a buffer */
#define CI_CFG_SEND_STATS_TO_LOG        1

#define CI_CFG_IP_TIMER_DEBUG		0

/* Enable this to return ENOTCONN when recv/recvfrom/recvmsg are
 * called when not bound/connected (UDP) (see udp_recv.c) */
#define CI_CFG_POSIX_RECV               0

/* Enable this to have recvmsg() on TCP socket fill the [msg_name].  Linux
 * certainly doesn't. */
#define CI_CFG_TCP_RECVMSG_MSGNAME	0

/*!
 * Enable this to return EOPNOTSUPP when connect() is called after
 * listen() on the same socket (see tcp_connect.c).
 */
#define CI_CFG_POSIX_CONNECT_AFTER_LISTEN   0

/*!
 * Enable this to return EAGAIN (EWOULDBLOCK) as close() errno,
 * if socket fails to send all data before linger timeout.
 */
#define CI_CFG_POSIX_SO_LINGER          0

/* send reset for connections with invalid options in SYN packets */ 
#define CI_CFG_TCP_INVALID_OPT_RST	1

/* slack factor when setting zero window probe timer 
** Useful as many ANVL test advertise zero/small windows during 
** shutdown which we can probe causing fails in some tests.
*/
#define CI_CFG_TCP_ZWIN_SLACK_FACTOR	2

/* additional slack time when setting zero window probe timer */
#define CI_CFG_TCP_ZWIN_SLACK_TICKS	20

/* initial cwnd setting possible according to rfcs:
** 2001, 2581, 3390
*/
#define CI_CFG_TCP_INITIAL_CWND_RFC	2581

/* check PAWs on fastpath
** Not necessary by rfc1323, but by ANVL tcp_highperf4.17
*/
#define CI_CFG_TCP_PAWS_ON_FASTPATH	1

/* strict check of SEG.SEQ <= Last.ACK.sent < SEG.SEQ + SEG.LEN 
** as on rfc1323 p16 or the looser on p35:
** SEG.SEQ <= Last.ACK.sent <= SEG.SEQ + SEG.LEN implied
** Setting this to 1 will cause it to not update the echoed value
** unless a packet contains tcp payload data.
** Setting this to 0 will leave it vulnerable to misdetection of
** failures when zero length packets get reordered.
*/
#define CI_CFG_TCP_RFC1323_STRICT_TSO	0

/* Minimum MSS value */
/* ANVL requires some pretty small MSS values.  
   This is chosen to match the ANVL parameter */
#define CI_CFG_TCP_MINIMUM_MSS		64

/* Default MSS value */
#define CI_CFG_TCP_DEFAULT_MSS		536

/* How many RX descriptors to push at a time. */
#define CI_CFG_RX_DESC_BATCH		16

/* How many packets to fill on TX path before pushing them out. */
#define CI_CFG_TCP_TX_BATCH		8

/* Maximum receive window size.  This used to be 0x7fff.  Here's why:
**
** A weakness in ANVL (described in bug 828) means that if we set this
** to 0xffff, ANVL will incorrectly fail a test, even though we are
** not doing anything wrong. When bug 953 is fixed, that will also mean
** that the legal scenario ANVL fails on should not occur.
**
** There's no other clear reason why this should not be 0xffff, although
** there's a rumour that issues with signed arithmetic may become a problem.
** We have done a few development days of testing with 0xffff without this.
*/
#define CI_CFG_TCP_MAX_WINDOW           0xffff

/* RFCs specify that if the receiver shrinks the window the sender
 * should be robust and notice this. We used to, in the name of
 * efficiency, ignore shrinking windows.  Set to zero to get this old
 * behaviour */
#define CI_CFG_NOTICE_WINDOW_SHRINKAGE  1

/*
** Base value for dupack threshold.
*/ 
#define CI_CFG_TCP_DUPACK_THRESH_BASE 3

/*
** Maximum value for dupack threshold. Should be less than typical window 
** size (in calculated packets, not in bytes).
*/
#define CI_CFG_TCP_DUPACK_THRESH_MAX 127

/* IP TTL settings */
#define CI_IP_DFLT_TTL 64
#define CI_IP_MAX_TTL 255 

/* IP TOS default */
#define CI_IP_DFLT_TOS 0
/* 8-bit field - but individual bits have (ignored) meaning */

/* IPv6 Traffic Class default */
#define CI_IPV6_DFLT_TCLASS 0

/* IPv6 hop limit defaults. Both are equal to corresponding Linux ones. */
#define CI_IPV6_DFLT_HOPLIMIT  64
#define CI_IPV6_DFLT_MCASTHOPS 1

/* Should we generate code that protects us against invalid shared state?
** By default we want the kernel to be robust to arbitrary shared state,
** but user-level to be fast.
*/
#ifndef CI_CFG_NETIF_HARDEN
# ifdef __KERNEL__
#  define CI_CFG_NETIF_HARDEN       1
# else
#  define CI_CFG_NETIF_HARDEN       0
# endif
#endif

/* Support H/W timer to give stack a kick when events are left unhandled
 * for a while.
 */
#define CI_CFG_HW_TIMER                 1

/* Enable invariant checking on entry/exit to library (sockcall intercept) */
#define CI_CFG_FDTABLE_CHECKS          0

/*
** Configuration options for TCP/IP striping.
**  - we stripe between hosts if we have a common netmask
**  - dupack threshold can be rasied to make the stack more 
**    tolerant to reordering
**  - default is all 1s - i.e. striping off
*/
#define CI_CFG_STRIPE_DEFAULT_NETMASK           0xffffffff
#define CI_CFG_STRIPE_DEFAULT_DUPACK_THRESHOLD  3

/* The default TCP header option number used for striping.  We'd like a
** proper assignment, but for now this will have to do:
**
** "And then they all sat down to supper.  And Black Mumbo ate Twenty-seven
** pancakes, and Black Jumbo ate Fifty-five but Little Black Sambo ate a
** Hundred and Sixty-nine, because he was so hungry."
*/
#define CI_CFG_STRIPE_DEFAULT_TCP_OPT		251

/* 
** Defaults for non-Linux and for broken Linux.
** Normally, we hope to get these values from OS. 
*/
#define CI_CFG_UDP_SNDBUF_DEFAULT		212992
#define CI_CFG_UDP_RCVBUF_DEFAULT		212992
#define CI_CFG_UDP_SNDBUF_MAX		212992
#define CI_CFG_UDP_RCVBUF_MAX		212992

/*
**These values are chosen to match the Linux definition of 
**SOCK_MIN_SNDBUF and SOCK_MIN_RCVBUF
*/
#ifndef SOCK_MIN_SNDBUF
# define CI_SOCK_MIN_SNDBUF               2048
#else
# define CI_SOCK_MIN_SNDBUF               SOCK_MIN_SNDBUF
#endif
#ifndef SOCK_MIN_RCVBUF
# define CI_SOCK_MIN_RCVBUF               256
#else
# define CI_SOCK_MIN_RCVBUF               SOCK_MIN_RCVBUF
#endif


#define CI_CFG_UDP_SNDBUF_MIN	        CI_SOCK_MIN_SNDBUF
#define CI_CFG_UDP_RCVBUF_MIN		CI_SOCK_MIN_RCVBUF

/* TCP sndbuf */
#define CI_CFG_TCP_SNDBUF_MIN	        CI_SOCK_MIN_SNDBUF
#define CI_CFG_TCP_SNDBUF_DEFAULT	16384
#define CI_CFG_TCP_SNDBUF_MAX		4194304

#define CI_CFG_TCP_RCVBUF_MIN           CI_SOCK_MIN_RCVBUF

#define CI_CFG_TCP_RCVBUF_DEFAULT	87380
#define CI_CFG_TCP_RCVBUF_MAX		6291456

/* These configuration "options" describe whether the host O/S normally
 * inherits specific socket state when accept() is called.
 */
#define CI_CFG_ACCEPT_INHERITS_NONBLOCK 0

/* Should the number of bytes reported by ioctl(FIONREAD) be limited
   to a maximum of the recieve buffer size? */
#define CI_CFG_FIONREAD_LIMIT          0

/* Maximum possible value for listen queue (backlog).
 * It is substituted from OS, when possible. */
#define CI_TCP_LISTENQ_MAX 256
/* Assume this number of listening socket per stack when calculating
 * EF_TCP_SYNRECV_MAX. */
#define CI_CFG_ASSUME_LISTEN_SOCKS 4

/* TCP window scale maximum and default.
 * Maximum is taken from RFC1323 and may be overriden by OS settings for
 * send value.
 * Default is overriden based on receive buffer. */
#define CI_TCP_WSCL_MAX      14     /* RFC 1323 max shift                 */

/* It is supposed that 
 * CI_TCP_RETRANSMIT_THRESHOLD > CI_TCP_RETRANSMIT_THRESHOLD_SYN.
 * Do not break this! */
#define CI_TCP_RETRANSMIT_THRESHOLD        15  /* retransmit 15 times */
#define CI_TCP_RETRANSMIT_THRESHOLD_ORPHAN 8   /* orphaned sock: 8 times */
#define CI_TCP_RETRANSMIT_THRESHOLD_SYN    4   /* retransmit SYN 4 times */

/* Should we send DSACK option in TCP? */
#define CI_CFG_TCP_DSACK 1

/* Do we assassinate TIME-WAIT TCP connections when needed?
 * Default value for EF_TCP_TIME_WAIT_ASSASSINATION. */
#define CI_CFG_TIME_WAIT_ASSASSINATE 1

/* Default challenge ACK limitation (in count per second),
 * same as of linux-4.19 */
#define CI_CFG_CHALLENGE_ACK_LIMIT 1000

/* Default ACK limitation when sending respnse to invalid packet,
 * in ms, same as of linux-4.19 */
#define CI_CFG_TCP_OUT_OF_WINDOW_ACK_RATELIMIT 500

/* Path to the /proc/sys/ */
#define CI_CFG_PROC_PATH		"/proc/sys/"
/* The real max is 30, but let's use larger value. */
#define CI_CFG_PROC_PATH_LEN_MAX	70
/* Match procfs/sysctl line limits. */
#define CI_CFG_PROC_LINE_LEN_MAX	1025

/*
 * CI_CFG_HANDLE_UDP_FRAG enables support for fragmented UDP interception
 * in the net driver (when disabled all UDP frags are passed to the kernel).
 * It also enabled the addition & removal of driverlink filters.
 *
 * When disabled no filter add/remove requests are sent from the char driver
 * and any ICMP messages seen at the net driver are filtered for type/code
 * and then passed across without reference to the dest. IP address.  In the
 * char driver the address is checked.
 *
 * DEPRECATED - ALWAYS set to 0 (net driver/kernel handle UDP frags)
 */
#define CI_CFG_HANDLE_UDP_FRAG      0

/*
 * CI_CFG_CONGESTION_WINDOW_VALIDATION actviates RFC2861 compliance;
 * if no packets are sent for N round trip times, then reduced the
 * congestion window by a factor of 2 for each round trip time since
 * the last transmit.  This is good for congested backbone links, but
 * not helpful for switched LANs, where round trip times can be very
 * short, and thus if applications do not send anything for even a few
 * miliseconds, they end with a tiny congestion window which needs to
 * be opened up.
 *
 * Make sure you read the comment below for 
 * CI_CFG_CONGESTION_WINDOW_VALIDATION_DELACK_SCALING if you activate this; 
 * it is recommended that you activate that option as well if you want this 
 * option.
 */
#define CI_CFG_CONGESTION_WINDOW_VALIDATION 0

/*
 * A substantial performance problem with congestion window validation
 * as it is defined in RFC2861 is that it will bottom out the
 * congestion window at one one MSS. The trouble with that is that if
 * using delayacked acknowledgements, there may still be a full
 * segment of unacknowledged data already with the client, which means
 * that we will choose not to send any more data until it has been
 * acknowledged. Enabling this option causes the congestion window to
 * bottom out at one MSS per delayed ack (i.e. typically two
 * MSS). This is in keeping with the idea in RFC2581 of setting the
 * initial congestion window to two MSS.
 *
 * See bug 623.
 */
#define CI_CFG_CONGESTION_WINDOW_VALIDATION_DELACK_SCALING 0

/* When the netif is wedged, due to userspace dying while the kernel is in an
 * inconsistent state, rather than go through the full process of closing the
 * endpoint (which could fail, due to the inconsistent state), if DESTROY_WEDGED
 * is set, we remove the filters and go straight to deleting data structures.
 */
#define CI_CFG_DESTROY_WEDGED 1


/* Include support for reducing the rate at which the congestion window is
 * increased during congestion avoidance.
 */
#define CI_CFG_CONG_AVOID_SCALE_BACK	1

/* 
 * Define how aggressive we should be in opening the congestion window
 * during slow start.
 * 0: RFC3465 behaviour (at most 2MSS increase for each received ACK)
 * 1: RFC2581 behaviour (1MSS increase for each received ACK)
 * 2: Linux kernel behaviour since 9f9843a751d0a (2013-10-31) (pure
 *    exponential increase for ACKed bytes)
 * See Section 2.2 and 2.3 of RFC3465 for discussion of this, and the
 * implementation of tcp_slow_start() in the kernel
 */
#define CI_CFG_CONG_AVOID_SLOW_START_MODE 2

/* 
 * When CI_CFG_CONG_AVOID_SLOW_START_MODE is zero, and so
 * RFC3465 behaviour is selected, this supplies the value for "L" from
 * that RFC.  It should be between 1 and 2 to comply
 */ 
#define CI_CFG_CONG_AVOID_RFC3465_L_VALUE 2

/* Detect cases where delayed acks could be detrimental to performance
 * (e.g. in slow start, or after data loss) and send ACKs for all
 * packets.
 */
#define CI_CFG_TCP_FASTSTART   1

/* Number of zero window probes to be sent before we try to split packets
** and fill the small window. We will never split packets when we have just 
** received an ack with zero window; we will wait for at least one zwin 
** timeout. Current default is CI_CFG_TCP_ZWIN_THRESH = 1, it means to wait 
** for two zwin timeouts.
*/
#define CI_CFG_TCP_ZWIN_THRESH 1

/* If a tail drop is suspected, try to probe it with a retransmission.
*/
#define CI_CFG_TAIL_DROP_PROBE 1

/* Dump users of TCP and UDP sockets to a log file. */
#define CI_CFG_LOG_SOCKET_USERS         0


/* Include fake IPv6 support (0 - off, 1 - on) */
#define CI_CFG_FAKE_IPV6 1


/* Include support for caching file descriptors at user-level.  */
#define CI_CFG_FD_CACHING      1

/* Support physical addressing (as well as protected buffer addressing). */
#ifdef __KERNEL__
# define CI_CFG_SUPPORT_PHYS_ADDR  1
#else
# define CI_CFG_SUPPORT_PHYS_ADDR  0
#endif

/* If set to 1, build ci_netif_dump() and friends inside the kernel, to allow
 * stackdump-like output to be generated for debugging purposes (useful for
 * iSCSI in particular).  Only tested with Linux so far.
 */
#define CI_CFG_BUILD_DUMP_CODE_IN_KERNEL 1

/* Maintain statistics for listening sockets.  At time of writing these are
** all gathered off the fast path, so there is no significant performance
** penalty for having them on.
*/
#define CI_CFG_STATS_TCP_LISTEN		1

/* Maintain per-netif statistics for things like event-queue callbacks etc.
** At time of writing these are all gathered off the fast path, so there is
** no significant performance penalty for having them on.
*/
#define CI_CFG_STATS_NETIF		1

/* Per-netif statistics for spin rounds inside each operation.
 * It depends on CI_CFG_STATS_NETIF being on. */
#ifdef NDEBUG
#define CI_CFG_SPIN_STATS 0
#else
#define CI_CFG_SPIN_STATS 1
#endif

/*
 * install broadcast hardware filters for UDP
 * - not needed currently as all such sockets get passed to OS
 */
#define CI_CFG_INSTALL_UDP_BROADCAST_FILTERS  0

/* Size of packet buffers.  Must be 2048 or 4096.  The larger value reduces
 * overhead when packets are large, but wastes memory when they aren't.
 */
#define CI_CFG_PKT_BUF_SIZE             2048

/* Maximum number of retransmit for SYN-ACKs */
#define CI_CFG_TCP_SYNACK_RETRANS_MAX 10

/* Enable inspection of packets before delivery */
#define CI_CFG_ZC_RECV_FILTER    1

/* HACK: Limit the advertised MSS for TCP because our TCP path does not
 * currently cope with frames that don't fit in a single packet buffer.
 * This define really exists just to make it easy to find and remove this
 * hack.
 */
#define CI_CFG_LIMIT_AMSS  1
#define CI_CFG_LIMIT_SMSS  1


/* Max length of "name" of a stack. */
#define CI_CFG_STACK_NAME_LEN  16

/* Max length of "name" of a cluster. */
#define CI_CFG_CLUSTER_NAME_LEN (CI_CFG_STACK_NAME_LEN >> 1)

/* Onload tcpdump support */
#define CI_CFG_TCPDUMP 1

#if CI_CFG_TCPDUMP
/* Dump queue length, should be 2^x, x <= 16 */
#define CI_CFG_DUMPQUEUE_LEN 128
#endif /* CI_CFG_TCPDUMP */


/* Set to use flag if you want stronger assertions, only zero-copy API
 * needs the re-entrancy of counting implementation 
 */
#define CI_CFG_CITP_INSIDE_LIB_IS_FLAG 0

/* Support for reducing ACK rate at high throughput to improve efficiency */
#define CI_CFG_DYNAMIC_ACK_RATE 1

/* Allocate packets in huge pages when possible
 * Ignored unless your kernel has CONFIG_HUGETLB_PAGE turned on (all the
 * distro kernels have it) and you are using x86_64. */
#define CI_CFG_PKTS_AS_HUGE_PAGES 1


/* Page=4KiB=2pkts; huge page=2MiB=2^10pkts.
 * To use huge pages, we should allocate exactly 2^10 pkts per set.
 * DO NOT CHANGE THIS VALUE if you have CI_CFG_PKTS_AS_HUGE_PAGES=1 */
#if CI_CFG_PKT_BUF_SIZE == 2048
#define CI_CFG_PKTS_PER_SET_S  10u
#elif CI_CFG_PKT_BUF_SIZE == 4096
#define CI_CFG_PKTS_PER_SET_S  9u
#else
#error "Incorrect CI_CFG_PKT_BUF_SIZE value"
#endif

#define PKTS_PER_SET    (1u << CI_CFG_PKTS_PER_SET_S)
#define PKTS_PER_SET_M  (PKTS_PER_SET - 1u)

/* When all packet sets have less than this number of packets available to
 * use, we'll allocate more packet sets */
#define CI_CFG_PKT_SET_LOW_WATER  (PKTS_PER_SET / 2)
/* A packet set with this number of available packets is considered as good
 * as a completely-unused set.  It allows for packet set reuse when there
 * are a few long-living TCP connections which use 1-10 packets from each
 * set. */
#define CI_CFG_PKT_SET_HIGH_WATER (PKTS_PER_SET - PKTS_PER_SET / 32)

#if CI_CFG_PKTS_AS_HUGE_PAGES
/* Maximum number of packet sets; each packet set is 2Mib (huge page)
 * = 2^9 or 2^10 packets, depending on CI_CFG_PKT_BUF_SIZE.
 * See also max_packets_per_stack module parameter. */
#define CI_CFG_MAX_PKT_SETS 1024
#endif

/* Whether to include code to transmit small packets via PIO */
#define CI_CFG_PIO 1
#define CI_CFG_MIN_PIO_BLOCK_ORDER 7

/* Whether to include code to transmit packets via CTPIO */
#define CI_CFG_CTPIO 1

/* Whether this build should use PIO/CTPIO or not.
 *
 * This is needed in addition to CI_CFG_PIO and CI_CFG_CTPIO as on some 32 bit
 * systems PIO is suspected to not be safe, but those builds may be sharing a
 * stack with a 64 bit system that is using PIO safely.
 */
#define CI_CFG_USE_PIO  (EF_VI_CONFIG_PIO && CI_CFG_PIO)
#define CI_CFG_USE_CTPIO (EF_VI_CONFIG_PIO && CI_CFG_CTPIO)

/* How many epolls sets will have a ready list maintained by the stack */
#define CI_CFG_EPOLL1_SETS_PER_STACK 4
/* How many ready lists are maintained */
#define CI_CFG_N_READY_LISTS CI_CFG_EPOLL1_SETS_PER_STACK

#define CI_CFG_MAX_SUPPORTED_INTERFACES 16

/* Do we need SO_TIMESTAMPING, WODA, ...? */
#define CI_CFG_TIMESTAMPING 1

/* Set to 1 to enable measuring the delta between packets being
 * received by the NIC and processed by the stack.
 */
#define CI_CFG_PROC_DELAY               0
#define CI_CFG_PROC_DELAY_BUCKETS       20
#define CI_CFG_PROC_DELAY_NS_SHIFT      10

/* Enable native kernel BPF program functionality
 * (subject to kernel support see CI_HAVE_BPF_NATIVE).
 * Currently aarch64 doesn't support Onload BPF. */
#ifndef __aarch64__
#define CI_CFG_WANT_BPF_NATIVE          1
#else
#define CI_CFG_WANT_BPF_NATIVE          0
#endif


#ifdef __KERNEL__
#include <linux/version.h>
/* Enable Berkeley Packet Filter program functionality
 * with kernel native implementation on supporting kernel
 * version.
 *  * required functionality
 *       bpf_prog_get_type_dev 4.15+
 *       BPF_PROG_GET_FD_BY_ID 4.13+
 *       IFLA_XDP_PROG_ID      4.13+
 *  * testing done on 4.18 (Ubuntu 18.10 and RHEL8)
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
#define CI_HAVE_BPF_NATIVE 1
#else
#define CI_HAVE_BPF_NATIVE 0
#endif
#endif
/* Include "extra" transport_config_opt to allow build-time profiles */
#include TRANSPORT_CONFIG_OPT_HDR

/* Size of socket shared state buffer.  Must be 1024 or 2048.  Larger
 * value is needed if you enable too many CI_CFG_* options, such as
 * CI_CFG_TCP_SOCK_STATS. */
#define CI_CFG_EP_BUF_SIZE              1024

#if CI_CFG_IPV6 && !CI_CFG_FAKE_IPV6
#error "CI_CFG_FAKE_IPV6 should be enabled to support IPv6"
#endif

#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__ */
/*! \cidoxg_end */
