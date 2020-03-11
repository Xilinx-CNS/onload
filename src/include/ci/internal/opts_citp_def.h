/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  ds
**  \brief  Definition of the transport configuration options
**   \date  2005/12/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/


/* For a detailed explanation of how this macro system works, look at
 * <include/ci/internal/opts_netif_def.h>
 *
 *     CI_CFG_OPT(type, type_modifider, name, group, default,
 *                minimum, maximum, presentation)
 */

#ifdef CI_CFG_OPTFILE_VERSION
CI_CFG_OPTFILE_VERSION(100)
#endif

CI_CFG_OPT("EF_PROBE", probe, ci_uint32,
"When set, file descriptors accessed following exec() will be 'probed' and "
"OpenOnload sockets will be mapped to user-land so that they can be "
"accelerated.  Otherwise OpenOnload sockets are not accelerated following "
"exec().",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_TCP", ul_tcp, ci_uint32,
"Clear to disable acceleration of new TCP sockets.",
           1, ,1, 0, 1, yesno)

CI_CFG_OPT("EF_UDP", ul_udp, ci_uint32,
"Clear to disable acceleration of new UDP sockets.",
           1, ,1, 0, 1, yesno)

CI_CFG_OPT("EF_UL_SELECT", ul_select, ci_uint32,
"Clear to disable acceleration of select() calls at user-level.",
           1, ,1, 0, 1, yesno)

CI_CFG_OPT("EF_SELECT_SPIN", ul_select_spin, ci_uint32,
"Spin in blocking select() calls until the select set is satisfied or the "
"spin timeout expires (whichever is the sooner).  If the spin timeout "
"expires, enter the kernel and block.  The spin timeout is set by "
"EF_SPIN_USEC or EF_POLL_USEC.",
           1, ,0, 0, 1, yesno)

CI_CFG_OPT("EF_SELECT_FAST", ul_select_fast, ci_uint32,
"Allow a select() call to return without inspecting the state of all selected "
"file descriptors when at least one selected event is satisfied.  This "
"allows the accelerated select() call to avoid a system call when accelerated "
"sockets are 'ready', and can increase performance substantially.\n"

"This option changes the semantics of select(), and as such could cause "
"applications to misbehave.  It effectively gives priority to accelerated "
"sockets over non-accelerated sockets and other file descriptors.  In "
"practice a vast majority of applications work fine with this option.",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_UL_POLL", ul_poll, ci_uint32,
"Clear to disable acceleration of poll() calls at user-level.",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_POLL_SPIN", ul_poll_spin, ci_uint32, 
"Spin in poll() calls until an event is satisfied or the spin timeout "
"expires (whichever is the sooner).  If the spin timeout expires, enter the "
"kernel and block.  The spin timeout is set by EF_SPIN_USEC or EF_POLL_USEC.",
           1, ,0, 0, 1, yesno)

CI_CFG_OPT("EF_POLL_FAST", ul_poll_fast, ci_uint32, 
"Allow a poll() call to return without inspecting the state of all polled "
"file descriptors when at least one event is satisfied.  This "
"allows the accelerated poll() call to avoid a system call when accelerated "
"sockets are 'ready', and can increase performance substantially.\n"

"This option changes the semantics of poll(), and as such could cause "
"applications to misbehave.  It effectively gives priority to accelerated "
"sockets over non-accelerated sockets and other file descriptors.  In "
"practice a vast majority of applications work fine with this option.",
           1, , 1, 0, 1, yesno)

#define CITP_EPOLL_KERNEL        0
#define CITP_EPOLL_UL            1
#define CITP_EPOLL_KERNEL_ACCEL  2
#define CITP_EPOLL_UL_SCALE      3
CI_CFG_OPT("EF_UL_EPOLL", ul_epoll, ci_uint32,
"Choose epoll implementation.  The choices are:\n"
"  0  -  kernel (unaccelerated)\n"
"  1  -  user-level (accelerated, lowest latency)\n"
"  2  -  kernel-accelerated (best when there are lots of sockets in the set"
"        and mode 3 is not suitable)\n"
"  3  -  user-level (accelerated, lowest latency, scalable, supports socket "
"        caching)\n"
"\n"
"The default is the user-level implementation (1).  Mode 3 can offer benefits "
"over mode 1, particularly with larger sets.  However, this mode has "
"some restrictions.  It does not support epoll sets that exist across fork(). "
"It does not support monitoring the readiness of the set's epoll fd via a "
"another epoll/poll/select.",
          2, , CITP_EPOLL_UL, 0, 3, oneof:kernel;ul;kernel_accel;ul_scale)

CI_CFG_OPT("EF_EPOLL_SPIN", ul_epoll_spin, ci_uint32, 
"Spin in epoll_wait() calls until an event is satisfied or the spin timeout "
"expires (whichever is the sooner).  If the spin timeout expires, enter the "
"kernel and block.  The spin timeout is set by EF_SPIN_USEC or EF_POLL_USEC.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_EPOLL_CTL_FAST", ul_epoll_ctl_fast, ci_uint32, 
"Avoid system calls in epoll_ctl() when using an accelerated epoll "
"implementation.  System calls are deferred until epoll_wait() blocks, and in "
"some cases removed completely.  This option improves performance for "
"applications that call epoll_ctl() frequently."
"\n"
"CAVEATS:\n"
"* This option has no effect when EF_UL_EPOLL=0.\n"
"* Do not turn this option on if your application uses dup(), fork() or "
"exec() in cojuction with epoll file descriptors or with the sockets "
"monitored by epoll.\n"
"* If you monitor the epoll fd in another poll, select or epoll set, "
"and have this option enabled, it may not give correct results.\n"
"* If you monitor the epoll fd in another poll, select or epoll set, "
"and the effects of epoll_ctl() are latency critical, then this option can "
"cause latency spikes or even deadlock.\n"
"* With EF_UL_EPOLL=2, this option is harmful if you are calling "
"epoll_wait() and epoll_ctl() simultaneously from different threads or "
"processes.",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_EPOLL_CTL_HANDOFF", ul_epoll_ctl_handoff, ci_uint32,
"Allow epoll_ctl() calls to be passed from one thread to another in order to "
"avoid lock contention, in EF_UL_EPOLL=1 or 3 case.  This optimisation is "
"particularly important when "
"epoll_ctl() calls are made concurrently with epoll_wait() and spinning is "
"enabled."
"\n"
"This option is enabled by default."
"\n"
"CAVEAT: This option may cause an error code returned by epoll_ctl() to be "
"hidden from the application when a call is deferred.  In such cases an error "
"message is emitted to stderr or the system log.",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_EPOLL_MT_SAFE", ul_epoll_mt_safe, ci_uint32, 
"This option disables concurrency control inside the accelerated epoll "
"implementations, reducing CPU overhead.  It is safe to enable this option if,"
" for each epoll set, all calls on the epoll set and all calls that may modify"
" a member of the epoll set are concurrency safe.  Calls that may modify a "
"member are bind(), connect(), listen() and close()."
"\n"
"This option improves performance with EF_UL_EPOLL=1 or 3 and also with "
"EF_UL_EPOLL=2 and EF_EPOLL_CTL_FAST=1.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_WODA_SINGLE_INTERFACE", woda_single_if, ci_uint32,
"This option alters the behaviour of onload_ordered_epoll_wait().  This "
"function would normally ensure correct ordering across multiple interfaces. "
"However, this impacts latency, as only events arriving before the first "
"interface polled can be returned and still guarantee ordering.  If the "
"traffic being ordered is only arriving on a single interface then this "
"additional constraint is not necessary.  If this option is enabled then "
"traffic will only be ordered relative to other traffic arriving on the same "
"interface.\n",
          , , 0, 0, 1, yesno)

CI_CFG_OPT("EF_FDS_MT_SAFE", fds_mt_safe, ci_uint32,
"This option allows less strict concurrency control when accessing the "
"user-level file descriptor table, resulting in increased performance, "
"particularly for multi-threaded applications.  Single-threaded applications "
"get a small latency benefit, but multi-threaded applications benefit most "
"due to decreased cache-line bouncing between CPU cores."
"\n"
"This option is unsafe for applications that make changes to file descriptors "
"in one thread while accessing the same file descriptors in other threads.  "
"For example, closing a file descriptor in one thread while invoking "
"another system call on that file descriptor in a second thread.  Concurrent "
"calls that do not change the object underlying the file descriptor remain "
"safe."
"\n"
"Calls to bind(), connect(), listen() may change underlying object.  "
"If you call such functions in one thread while accessing the same file "
"descriptor from the other thread, this option is also unsafe.  "
"In some special cases, any functions may change underlying object."
"\n"
"Also concurrent calls may happen from signal handlers, so set this to 0 "
"if your signal handlers call bind(), connect(), listen() or close()",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_FDTABLE_STRICT", fdtable_strict, ci_uint32,
"Enables more strict concurrency control for the user-level file descriptor "
"table.  Enabling this option can reduce performance for applications that "
"create and destroy many connections per second.",
/* FIXME: what are the symptoms to look for to find if this is causing
 * problems?
 */
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_LOG_TIMESTAMPS", log_timestamps, ci_uint32,
"If enabled this will add a timestamp to every Onload output log entry. "
"Timestamps are originated from the FRC counter.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_LOG_VIA_IOCTL", log_via_ioctl, ci_uint32,
"Causes error and log messages emitted by OpenOnload to be written to the "
"system log rather than written to standard error.  This includes the "
"copyright banner emitted when an application creates a new OpenOnload "
"stack."
"\n"
"By default, OpenOnload logs are written to the application standard error "
"if and only if it is a TTY."
"\n"
"Enable this option when it is important not to change what the application "
"writes to standard error."
"\n"
"Disable it to guarantee that log goes to standard error even if it is not "
"a TTY.",
           2, ,  0, 0, 1, oneof:no;yes;default)

CI_CFG_OPT("EF_LOAD_ENV", load_env, ci_uint32,
"OpenOnload will only consult other environment variables if this option is "
"set.  i.e. Clearing this option will cause all other EF_ environment "
"variables to be ignored.",
           1, , 1, 0, 1, yesno)

CI_CFG_OPT("EF_ACCEPT_INHERIT_NONBLOCK", accept_force_inherit_nonblock,
           ci_uint32, 
"If set to 1, TCP sockets accepted from a listening socket inherit the "
"O_NONBLOCK flag from the listening socket.",
           1, , CI_CFG_ACCEPT_INHERITS_NONBLOCK, 0, 1, yesno)

CI_CFG_OPT("EF_STACK_PER_THREAD", stack_per_thread, ci_uint32,
"Create a separate Onload stack for the sockets created by each thread.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_DONT_ACCELERATE", dont_accelerate, ci_uint32,
"Do not accelerate by default.  This option is usually used in conjuction "
"with onload_set_stackname() to allow individual sockets to be accelerated "
"selectively.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_UDP_RECV_SPIN", udp_recv_spin, ci_uint32,
"Spin in blocking UDP receive calls until data arrives, the spin timeout "
"expires or the socket timeout expires (whichever is the sooner).  If the "
"spin timeout expires, enter the kernel and block.  The spin timeout is set by"
" EF_SPIN_USEC or EF_POLL_USEC.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_UDP_SEND_SPIN", udp_send_spin, ci_uint32,
"Spin in blocking UDP send calls until space becomes available in the socket "
"buffer, the spin timeout expires or the socket timeout expires (whichever "
"is the sooner). If the spin timeout expires, enter the kernel and block.  "
"The spin timeout is set by EF_SPIN_USEC or EF_POLL_USEC.\n"

"Note: UDP sends usually complete very quickly, but can block if the "
"application does a large burst of sends at a high rate.  This option reduces "
"jitter when such blocking is needed.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_RECV_SPIN", tcp_recv_spin, ci_uint32,
"Spin in blocking TCP receive calls until data arrives, the spin timeout "
"expires or the socket timeout expires (whichever is the sooner).  If the "
"spin timeout expires, enter the kernel and block.  The spin timeout is "
"set by EF_SPIN_USEC or EF_POLL_USEC.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_SEND_SPIN", tcp_send_spin, ci_uint32,
"Spin in blocking TCP send calls until window is updated by peer, the spin "
"timeout expires or the socket timeout expires (whichever is the sooner).  "
"If the spin timeout expires, enter the kernel and block.  The spin timeout "
"is set by EF_SPIN_USEC or EF_POLL_USEC.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_ACCEPT_SPIN", tcp_accept_spin, ci_uint32,
"Spin in blocking TCP accept() calls until incoming connection is "
"established, the spin timeout "
"expires or the socket timeout expires(whichever is the sooner).  If the "
"spin timeout expires, enter the kernel and block.  The spin timeout is set "
"by EF_SPIN_USEC or EF_POLL_USEC.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_TCP_CONNECT_SPIN", tcp_connect_spin, ci_uint32,
"Spin in blocking TCP connect() calls until connection is established, "
"the spin timeout "
"expires or the socket timeout expires(whichever is the sooner).  If the "
"spin timeout expires, enter the kernel and block.  The spin timeout is set "
"by EF_SPIN_USEC or EF_POLL_USEC.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_PKT_WAIT_SPIN", pkt_wait_spin, ci_uint32,
"Spin while waiting for DMA buffers.  If the spin timeout expires, enter the "
"kernel and block.  The spin timeout is set by EF_SPIN_USEC or EF_POLL_USEC.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_PIPE_RECV_SPIN", pipe_recv_spin, ci_uint32,
"Spin in pipe receive calls until data arrives or the spin timeout expires "
"(whichever is the sooner).  If the spin timeout expires, enter the kernel "
"and block.  The spin timeout is set by EF_SPIN_USEC or EF_POLL_USEC.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_PIPE_SEND_SPIN", pipe_send_spin, ci_uint32,
"Spin in pipe send calls until space becomes available in the socket buffer or"
" the spin timeout expires (whichever is the sooner).  If the spin timeout "
"expires, enter the kernel and block.  The spin timeout is set by "
"EF_SPIN_USEC or EF_POLL_USEC.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_PIPE_SIZE", pipe_size, ci_int32,
"Default size of the pipe in bytes. Actual pipe size will be rounded up "
"to the size of packet buffer and subject to modifications by "
"fcntl F_SETPIPE_SZ where supported.",
           , , OO_PIPE_DEFAULT_SIZE, OO_PIPE_MIN_SIZE, CI_CFG_MAX_PIPE_SIZE,
           count)

CI_CFG_OPT("EF_SOCK_LOCK_BUZZ", sock_lock_buzz, ci_uint32,
"Spin while waiting to obtain a per-socket lock.  If the spin timeout "
"expires, enter the kernel and block.  The spin timeout is set by "
"EF_BUZZ_USEC.\n"
"The per-socket lock is taken in recv() calls and similar.  This option can "
"reduce jitter when multiple threads invoke recv() on the same socket, "
"but can reduce fairness between threads competing for the lock.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_STACK_LOCK_BUZZ", stack_lock_buzz, ci_uint32,
"Spin while waiting to obtain a per-stack lock.  If the spin timeout expires, "
"enter the kernel and block.  The spin timeout is set by EF_BUZZ_USEC.\n"
"This option reduces jitter caused by lock contention, but can reduce "
"fairness between threads competing for the lock.",
           1, , 0, 0, 1, yesno)

CI_CFG_OPT("EF_SO_BUSY_POLL_SPIN", so_busy_poll_spin, ci_uint32,
"Spin poll,select and epoll in a Linux-like way: enable spinning only if "
"a spinning soclet is preset in the poll/select/epoll set.  See Linux "
"documentation on SO_BUSY_POLL socket option for details.\n"
"You should also enable spinning via EF_{POLL,SELECT,EPOLL}_SPIN "
"variable if you'd like to spin in poll,select or epoll correspondingly.  "
"The spin duration is set via EF_SPIN_USEC, which is equivalent "
"to the Linux sysctl.net.busy_poll value.  EF_POLL_USEC is all-in-one "
"variable to set for all 4 variables mentioned here.\n"
"Linux never spins in epoll, but Onload does.  This variable does not "
"affect epoll behaviour if EF_UL_EPOLL=2.",
           1, , 0, 0, 1, yesno)

#define CITP_NETIF_DTOR_NONE                0
#define CITP_NETIF_DTOR_ONLY_SHARED         1
#define CITP_NETIF_DTOR_ALL                 2
#define CITP_NETIF_DTOR_DEFAULT             CITP_NETIF_DTOR_ONLY_SHARED
CI_CFG_OPT("EF_NETIF_DTOR", netif_dtor, ci_uint32,
"This option controls the lifetime of OpenOnload stacks when the last socket "
"in a stack is closed.",
           2, , CITP_NETIF_DTOR_DEFAULT, 0, 2, oneof:none;shared;all)

# define CI_UNIX_FORK_NETIF_NONE   0
# define CI_UNIX_FORK_NETIF_CHILD  1
# define CI_UNIX_FORK_NETIF_PARENT 2
# define CI_UNIX_FORK_NETIF_BOTH   3
CI_CFG_OPT("EF_FORK_NETIF", fork_netif, ci_uint32,
"This option controls behaviour after an application calls fork()."
"\n"
"  0 - Neither fork parent nor child creates a new OpenOnload stack"
"  1 - Child creates a new stack for new sockets"
"  2 - Parent creates a new stack for new sockets"
"  3 - Parent and child each create a new stack for new sockets",
           2, , CI_UNIX_FORK_NETIF_BOTH, CI_UNIX_FORK_NETIF_NONE,
           CI_UNIX_FORK_NETIF_BOTH, oneof:none;child;parent;both)

CI_CFG_OPT("EF_NO_FAIL", no_fail, ci_uint32,
"This option controls whether failure to create an accelerated socket "
"(due to resource limitations) is hidden by creating a conventional "
"unaccelerated socket.  Set this option to 0 to cause out-of-resources "
"errors to be propagated as errors to the application, or to 1 to "
"have Onload use the kernel stack instead when out of resources."
"\n"
"Disabling this option can be useful to ensure that sockets are being "
"accelerated as expected (ie. to find out when they are not).",
           1, , 1, 0, 1, level)

CI_CFG_OPT("EF_SA_ONSTACK_INTERCEPT", sa_onstack_intercept, ci_uint32,
"Intercept signals when signal handler is installed with SA_ONSTACK flag.\n"
"  0 - Don't intercept.  If you call socket-related functions such as send, "
"file-related functions such as close or dup from your signal handler, "
"then your application may deadlock. (default)"
"  1 - Intercept.  There is no guarantee that SA_ONSTACK flag will really "
"work, but OpenOnload library will do its best.",
           1, , 0, 0, 1, yesno)

#define CI_UNIX_PIPE_DONT_ACCELERATE 0
#define CI_UNIX_PIPE_ACCELERATE 1
#define CI_UNIX_PIPE_ACCELERATE_IF_NETIF 2
CI_CFG_OPT("EF_PIPE", ul_pipe, ci_uint32,
"0 - disable pipe acceleration, 1 - enable pipe acceleration, "
"2 - acclerate pipes only if an Onload stack already exists in the process.",
           2, , CI_UNIX_PIPE_ACCELERATE_IF_NETIF,
           CI_UNIX_PIPE_DONT_ACCELERATE, CI_UNIX_PIPE_ACCELERATE_IF_NETIF,
           level)

CI_CFG_OPT("EF_FDTABLE_SIZE", fdtable_size, ci_uint32,
"Limit the number of opened file descriptors by this value.  "
"If zero, the initial hard limit of open files (`ulimit -n -H`) is used.  "
"Hard and soft resource limits for opened file descriptors "
"(help ulimit, man 2 setrlimit) are bound by this value.",
           , , 0, MIN, MAX, count)

#define CI_UL_LOG_E     0x1            /* errors */
#define CI_UL_LOG_U     0x2            /* unexpected */
#define CI_UL_LOG_S     0x4            /* setup */
#define CI_UL_LOG_V     0x8            /* verbose */
#define CI_UL_LOG_SEL   0x10
#define CI_UL_LOG_POLL  0x20

#define CI_UL_LOG_VSS   0x100          /* socket set-up */
#define CI_UL_LOG_VSC   0x200          /* socket control */

#define CI_UL_LOG_EP    0x400          /* EP caching */

#define CI_UL_LOG_LIB   0x2000         /* library enter/exit */
#define CI_UL_LOG_CALL  0x4000         /* log call arguments */
#define CI_UL_LOG_CLUT  0x8000         /* context lookup */
#define CI_UL_LOG_PT    0x10000        /* pass-through */
#define CI_UL_LOG_VV    0x20000        /* very verbose */
#define CI_UL_LOG_VE    0x40000        /* Verbose returned error */
#define CI_UL_LOG_VVE   0x80000        /* V.Verbose errors: show "ok" too */

#define CI_UL_LOG_VTC   0x20000000     /* verbose transport control */
#define CI_UL_LOG_VVTC  0x40000000     /* very verbose transport control */
#define CI_UL_LOG_VPT   0x80000000     /* verbose pass-through */

CI_CFG_OPT("EF_UNIX_LOG", log_level, ci_uint32, 
"A bitmask determining which kinds of diagnostics messages will be logged.\n"
"  0x1            errors\n"
"  0x2            unexpected\n"
"  0x4            setup\n"
"  0x8            verbose\n"
"  0x10           select()\n"
"  0x20           poll()\n"
"  0x100          socket set-up\n"
"  0x200          socket control\n"
"  0x400          socket caching\n"
"  0x1000         signal interception\n"
"  0x2000         library enter/exit\n"
"  0x4000         log call arguments\n"
"  0x8000         context lookup\n"
"  0x10000        pass-through\n"
"  0x20000        very verbose\n"
"  0x40000        Verbose returned error\n"
"  0x80000        V.Verbose errors: show 'ok' too\n"
"  0x20000000     verbose transport control\n"
"  0x40000000     very verbose transport control\n"
"  0x80000000     verbose pass-through",
           , , CI_UL_LOG_E | CI_UL_LOG_U, MIN, MAX,
	   bitset:errors;unexpected;setup;verbose;sel;poll;;;setup;control;caching;;signalint;library;callargs;ctxtlookup;passthrough;veryverbose;;;;;;;;;;;;verbosetransportctrl;veryverbosetransportctrl;verbosepassthrough)


#define OO_SPIN_BLURB                                                   \
"Spinning typically reduces latency and jitter substantially, and can " \
"also improve throughput.  However, in some applications spinning can " \
"harm performance; particularly application that have many threads.  "  \
"When spinning is enabled you should normally dedicate a CPU core to "  \
"each thread that spins."                                               \
"\n"                                                                    \
"You can use the EF_*_SPIN options to selectively enable or disable "   \
"spinning for each API and transport.  You can also use the "           \
"onload_thread_set_spin() extension API to control spinning on a "      \
"per-thread and per-API basis."


CI_CFG_OPT("EF_POLL_USEC", ef_poll_usec_meta_option, ci_uint32, 
"This option enables spinning and sets the spin timeout in microseconds."
"\n"
"Setting this option is equivalent to: Setting EF_SPIN_USEC and EF_BUZZ_USEC, "
"enabling spinning for UDP sends and receives, TCP sends and receives, "
"select, poll and epoll_wait(), and enabling lock buzzing."
"\n"
OO_SPIN_BLURB,
           , , 0, MIN, MAX, time:usec)

CI_CFG_OPT("EF_SPIN_USEC", ul_spin_usec, ci_uint32, 
"Sets the timeout in microseconds for spinning options.  Set this to to -1 "
"to spin forever.  The spin timeout may also be set by the EF_POLL_USEC "
"option."
"\n"
OO_SPIN_BLURB,
           , , 0, MIN, MAX, time:usec)

CI_CFG_OPT("EF_SLEEP_SPIN_USEC", sleep_spin_usec, ci_uint32, 
"Sets the duration in microseconds of sleep after each spin iteration. "
"Currently applies to EPOLL3 epoll_wait only. "
"Enabling the option trades some of the benefits of spinning - latency - for reduction "
"in CPU utilisation and power consumption. "
"\n"
OO_SPIN_BLURB,
           , , 0, MIN, MAX, time:usec)

CI_CFG_OPT("EF_POLL_FAST_USEC", ul_poll_fast_usec, ci_uint32,
"When spinning in a poll() call, causes accelerated sockets to be polled for N "
"usecs before unaccelerated sockets are polled.  This reduces "
"latency for accelerated sockets, possibly at the expense of latency on "
"unaccelerated sockets.  Since accelerated sockets are typically the parts "
"of the application which are most performance-sensitive this is typically a "
"good tradeoff.",
           , , 32, MIN, MAX, time:usec)

CI_CFG_OPT("EF_POLL_NONBLOCK_FAST_USEC", ul_poll_nonblock_fast_usec, ci_uint32,
"When invoking poll() with timeout==0 (non-blocking), this option "
"causes non-accelerated sockets to be polled only every N usecs."
"This reduces latency for accelerated sockets, possibly "
"at the expense of latency on unaccelerated sockets.  Since accelerated "
"sockets are typically the parts of the application which are most "
"performance-sensitive this is often a good tradeoff."
"\n"
"Set this option to zero to disable, or to a higher value to further improve "
"latency for accelerated sockets."
"\n"
"This option changes the behaviour of poll() calls, so could potentially "
"cause an application to misbehave.",
           , , 200, MIN, MAX, time:usec)

CI_CFG_OPT("EF_SELECT_FAST_USEC", ul_select_fast_usec, ci_uint32,
"When spinning in a select() call, causes accelerated sockets to be polled for N "
"usecs before unaccelerated sockets are polled.  This reduces "
"latency for accelerated sockets, possibly at the expense of latency on "
"unaccelerated sockets.  Since accelerated sockets are typically the parts "
"of the application which are most performance-sensitive this is typically a "
"good tradeoff.",
           , , 32, MIN, MAX, time:usec)

CI_CFG_OPT("EF_SELECT_NONBLOCK_FAST_USEC", ul_select_nonblock_fast_usec,
           ci_uint32,
"When invoking select() with timeout==0 (non-blocking), this option "
"causes non-accelerated sockets to be polled only every N usecs."
"This reduces latency for accelerated sockets, possibly "
"at the expense of latency on unaccelerated sockets.  Since accelerated "
"sockets are typically the parts of the application which are most "
"performance-sensitive this is often a good tradeoff."
"\n"
"Set this option to zero to disable, or to a higher value to further improve "
"latency for accelerated sockets."
"\n"
"This option changes the behaviour of select() calls, so could potentially "
"cause an application to misbehave.",
           , , 200, MIN, MAX, time:usec)


CI_CFG_OPT("EF_SIGNALS_NOPOSTPONE", signals_no_postpone, ci_uint64,
"Comma-separated list of signal numbers to avoid postponing "
"of the signal handlers.  "
"Your application will deadlock if one of the handlers uses socket "
"function.  By default, the list includes SIGILL, SIGBUS, SIGFPE, "
"SIGSEGV and SIGPROF.\n"
"Please specify numbers, not string aliases: EF_SIGNALS_NOPOSTPONE=7,11,27 "
"instead of EF_SIGNALS_NOPOSTPONE=SIGBUS,SIGSEGV,SIGPROF.\n"
"You can set EF_SIGNALS_NOPOSTPONE to empty value to postpone "
"all signal handlers in the same way if you suspect these signals "
"to call network functions.",
        A8,,
        (1 << (SIGILL-1)) | (1 << (SIGBUS-1)) | (1 << (SIGFPE-1)) |
        (1 << (SIGSEGV-1)) | (1 << (SIGPROF-1)),
        0, (ci_uint64)(-1), bitmask)

# define CITP_VFORK_USE_FORK           0
# define CITP_VFORK_USE_FORK_WITH_PIPE 1
# define CITP_VFORK_USE_VFORK          2
CI_CFG_OPT("EF_VFORK_MODE", vfork_mode, ci_uint32,
"This option dictates how vfork() intercept should work.  "
"After a vfork(), parent and child still share address space but not "
"file descriptors.  We have to be careful about making changes in the child "
"that can be seen in the parent.  We offer three options here.  Different "
"apps may require different options depending on their use of vfork().  "
"If using EF_VFORK_MODE=2, it is not safe to create sockets or pipes in the "
"child before calling exec().\n"
"  0 - Old behavior.  Replace vfork() with fork()"
"  1 - Replace vfork() with fork() and block parent till child exits/execs"
"  2 - Replace vfork() with vfork()",
           2, , 1, 0, 2, level)

CI_CFG_OPT("EF_CLUSTER_SIZE", cluster_size, ci_uint32,
"If use of SO_REUSEPORT creates a cluster, this option specifies size "
"of the cluster to be created.  This option has no impact if use of "
"SO_REUSEPORT joins a cluster that already exists.  Note that if fewer "
"sockets than specified here join the cluster, then some traffic will "
"be lost.  Refer to the SO_REUSEPORT section in the manual for more "
"detail. To disable clustering set EF_CLUSTER_SIZE to 0.\n",
           , , 0, 0, MAX, count)

# define CITP_CLUSTER_RESTART_FAIL              0
# define CITP_CLUSTER_RESTART_TERMINATE_ORPHANS 1
CI_CFG_OPT("EF_CLUSTER_RESTART", cluster_restart_opt, ci_uint32,
"This option controls the behaviour when recreating a stack (e.g. due to "
"restarting a process) in an SO_REUSEPORT cluster and it encounters a resource "
"limitation such as an orphan stack from the previous process:\n "
" 0 - return an error.\n"
" 1 - terminate the orphan to allow the new process to continue",
           , , 0, 0, 1, level)

CI_CFG_OPT("EF_CLUSTER_HOT_RESTART", cluster_hot_restart_opt, ci_uint32,
    "This option controls whether or not clusters support the hot/seamless "
    "restart of applications. Enabling this reuses existing stacks in the "
    "cluster to allow up to two processes per stack to bind to the same port "
    "simultaneously. Note that it is required there will be as many new "
    "sockets on the port as old ones; traffic will be lost otherwise when the "
    "old sockets close.\n"
    " 0 - disable per-port stack sharing. (default)\n"
    " 1 - enable per-port stack sharing for hot restarts.",
           , , 0, 0, 1, level)

CI_CFG_OPT("EF_TCP_FORCE_REUSEPORT", tcp_reuseports, ci_uint64,
"This option specifies a comma-separated list of port numbers.  TCP "
"sockets that bind to those port numbers will have SO_REUSEPORT "
"automatically applied to them.\n",
           A8, , 0, MIN, MAX, list)

CI_CFG_OPT("EF_UDP_FORCE_REUSEPORT", udp_reuseports, ci_uint64,
"This option specifies a comma-separated list of port numbers.  UDP "
"sockets that bind to those port numbers will have SO_REUSEPORT "
"automatically applied to them.\n",
           A8, , 0, MIN, MAX, list)

#if CI_CFG_FD_CACHING
CI_CFG_OPT("EF_SOCKET_CACHE_PORTS", sock_cache_ports, ci_uint64,
"This option specifies a comma-separated list of port numbers.  When set (and "
"socket caching is enabled), only sockets bound to the specified ports will "
"be eligible to be cached.\n",
           A8, , 0, MIN, MAX, list)
#endif

CI_CFG_OPT("EF_ONLOAD_FD_BASE", fd_base, ci_uint32,
"Onload uses fds internally that are not visible to the application.  This can "
"cause problems for applications that make assumptions about their use of the "
"fd space, for example by doing dup2/3 onto a specific file descriptor.  If "
"this is done onto an fd that is internally in use by onload than an error of "
"the form 'citp_ep_dup3(29, 3): target is reserved, see EF_ONLOAD_FD_BASE' "
"will be emitted.\n"
"This option specifies a base file descriptor value, that onload should try to "
"make it's internal file descriptors greater than or equal to.  This allows "
"the application to direct onload to a part of the fd space that it is not "
"expecting to explicitly use.\n",
           A8, , 4, MIN, MAX, count)

CI_CFG_OPT("EF_SYNC_CPLANE_AT_CREATE", sync_cplane, ci_uint32,
"When this option is set to 2 Onload will force a sync of control plane "
"information from the kernel when a stack is created.  This can help to "
"ensure up to date information is used where a stack is created immediately "
"following interface configuration."
"\n"
"If this option is set to 1 then Onload will perform a lightweight sync of "
"control plane information without performing a full dump.  "
"It is the default mode."
"\n"
"Setting this option to 0 will disable forced sync.  Synchronising data from "
"the kernel will continue to happen periodically."
"\n"
"Sync operation time is limited by cplane_init_timeout onload module option.",
           2, , 1, 0, 2, oneof:never;first;always)

#ifdef CI_CFG_OPTGROUP
/* put definitions of categories and expertise levels here */
#endif
