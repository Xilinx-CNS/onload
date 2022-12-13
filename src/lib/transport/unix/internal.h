/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author
**  \brief
**   \date
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */

#ifndef __CI_TRANSPORT_INTERNAL_H__
#define __CI_TRANSPORT_INTERNAL_H__


/* This is required to ensure all the features we want get defined.
** Need for pthread_rwlock_*, some fcntl defines etc.
*/
#define _GNU_SOURCE
/*#define _XOPEN_SOURCE 500
  #define _BSD_SOURCE*/

#include <ci/tools.h>
#pragma GCC poison ci_cpu_khz
#include <ci/internal/ip.h>
#include <ci/internal/ip_signal.h>
#include <ci/internal/ip_log.h>
#include <errno.h>
#include <stdlib.h>
#include <aio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <pthread.h>

#include <onload/extensions_zc.h>
#include <ci/internal/efabcfg.h>

#include <ci/internal/transport_config_opt.h>
#include <ci/internal/transport_common.h>


/* Define onload_<syscall> functions to use in the library. */
#define CI_MK_DECL(ret, fn, args) extern ret onload_##fn args;
# include <onload/declare_syscalls.h.tmpl>


/**********************************************************************
 ** Globals.
 */

typedef struct {
  int			log_fd;

  ci_uint64             spin_cycles;
  ci_uint64             poll_nonblock_fast_cycles;
  ci_uint64             poll_fast_cycles;
  ci_uint64             select_nonblock_fast_cycles;
  ci_uint64             select_fast_cycles;
  ci_uint32             cpu_khz;

  enum {
    CITP_INIT_NONE = 0,
#define STARTUP_ITEM(level, func) level,
#include "startup_order.h"
#undef STARTUP_ITEM
  } init_level;
/* CITP_INIT_ALL means that Onload library os ready to serve any
 * application request.
 * CITP_INIT_MAX may contains some post-init actions.
 */
#define CITP_INIT_ALL   CITP_INIT_PROTO
#define CITP_INIT_MAX   CITP_INIT_SIGNALS

  char			process_path[128];
  char*			process_name;
#if CI_CFG_FD_CACHING
  ci_uint32             pid;
#endif
} citp_globals_t;


extern citp_globals_t		citp  CI_HV;


#define fdtable_strict()	(CITP_OPTS.fdtable_strict)


/**********************************************************************
 ** Atomic ops that are not atomic when app is single-threaded.
 */

ci_inline int citp_fdtable_is_mt_safe(void) {
  return ! ci_is_multithreaded() || CITP_OPTS.fds_mt_safe;
}

ci_inline int citp_fdtable_not_mt_safe(void) {
  return ci_is_multithreaded() && ! CITP_OPTS.fds_mt_safe;
}

ci_inline void oo_atomic_quick_inc (oo_atomic_t *a) {
  if( ci_is_multithreaded() )  oo_atomic_inc(a);
  else                         ++a->n;
}

ci_inline int oo_atomic_quick_dec_and_test(oo_atomic_t* a) {
  if( ci_is_multithreaded() ) return oo_atomic_dec_and_test(a);
  else                        return --a->n == 0;
}


/**********************************************************************
 ** Per-thread library context, for controlling signal deferral and
 ** ensuring that errno is updated correctly
 */

typedef struct {
  struct oo_per_thread* thread;
  int                   saved_errno;
} citp_lib_context_t;


/**********************************************************************
 ** Protocol implementations.
 */

typedef struct citp_protocol_impl_s citp_protocol_impl;
typedef struct citp_fdinfo_s citp_fdinfo;
struct oo_ul_poll_state;
struct oo_ul_select_state;
struct citp_epoll_member;
struct oo_ul_epoll_state;

typedef struct {
  int  (*socket      )(int domain, int type, int protocol);
  citp_fdinfo*
       (*dup         )(citp_fdinfo*);
#if CI_CFG_FD_CACHING
  void (*close       )(citp_fdinfo*);
#endif
  void (*dtor        )(citp_fdinfo*, int fdt_locked);
  int  (*bind        )(citp_fdinfo*, const struct sockaddr*, socklen_t);
  int  (*listen      )(citp_fdinfo*, int);
  int  (*accept      )(citp_fdinfo*, struct sockaddr*, socklen_t*, int flags,
                       citp_lib_context_t*);
  int  (*connect     )(citp_fdinfo*, const struct sockaddr*, socklen_t,
                       citp_lib_context_t*);
  int  (*shutdown    )(citp_fdinfo*, int);
  int  (*getsockname )(citp_fdinfo*, struct sockaddr*, socklen_t*);
  int  (*getpeername )(citp_fdinfo*, struct sockaddr*, socklen_t*);
  int  (*getsockopt  )(citp_fdinfo*, int, int, void*, socklen_t*);
  int  (*setsockopt  )(citp_fdinfo*, int, int, const void*, socklen_t);
  int  (*recv        )(citp_fdinfo*, struct msghdr*, int);
  int  (*recvmmsg    )(citp_fdinfo*, struct mmsghdr*, unsigned, int,
                       ci_recvmmsg_timespec*);
  int  (*send        )(citp_fdinfo*, const struct msghdr*, int);
  int  (*sendmmsg    )(citp_fdinfo*, struct mmsghdr*, unsigned, int);
  int  (*fcntl       )(citp_fdinfo*, int, long);
  int  (*ioctl       )(citp_fdinfo*, int, void *);
  /* poll() and select() return "I've handled it" bool */
  int  (*select      )(citp_fdinfo*, int*, int, int, int,
                       struct oo_ul_select_state*);
  int  (*poll        )(citp_fdinfo*, struct pollfd*, struct oo_ul_poll_state*);
  /* epoll() and sleep_seq() should be present both or none.
   * epoll() returns "poll again" bool */
  int (*epoll       )(citp_fdinfo*, struct citp_epoll_member* eitem,
                       struct oo_ul_epoll_state*, int* stored_event);
  ci_uint64 (*sleep_seq)(citp_fdinfo*);
  int  (*zc_send     )(citp_fdinfo*, struct onload_zc_mmsg*, int);
  int  (*zc_recv     )(citp_fdinfo*, struct onload_zc_recv_args*);
  int  (*zc_recv_filter)(citp_fdinfo*, onload_zc_recv_filter_callback,
                         void*, int);
  int  (*recvmsg_kernel)(citp_fdinfo*, struct msghdr*, int);
  int  (*tmpl_alloc)(citp_fdinfo*, const struct iovec*, int,
                     struct oo_msg_template**, unsigned);
  int  (*tmpl_update)(citp_fdinfo*, struct oo_msg_template*,
                      const struct onload_template_msg_update_iovec*, int,
                      unsigned);
  int  (*tmpl_abort)(citp_fdinfo*, struct oo_msg_template*);
#if CI_CFG_TIMESTAMPING
  /* Examines receive queue up to timespec limit, and fills in first_out
   * with the timestamp of the first data available, and bytes_out with the
   * number of bytes available to be read before reaching limit.
   */
  int  (*ordered_data)(citp_fdinfo*, struct timespec* limit,
                       struct timespec* first_out, int* bytes_out);
#endif
  int (*is_spinning)(citp_fdinfo*);
#if CI_CFG_FD_CACHING
  int  (*cache     )(citp_fdinfo*);
#endif
  enum onload_delegated_send_rc
       (*dsend_prepare)(citp_fdinfo*, int size, unsigned flags,
                        struct onload_delegated_send* out);
  int  (*dsend_complete)(citp_fdinfo*, const ci_iovec *iov, int iovlen,
                         int flags);
  int  (*dsend_cancel)(citp_fdinfo*);
} citp_fdops;


struct citp_protocol_impl_s {
  int           type;
# define        CITP_CI_SOCKET       0
# define        CITP_TCP_SOCKET      1
# define        CITP_UDP_SOCKET      2
# define        CITP_PASSTHROUGH_FD  3
# define        CITP_EPOLL_FD        4
# define        CITP_EPOLLB_FD       5
# define        CITP_PIPE_FD         6

  citp_fdops    ops;

  ci_dllink     link;
};


#define CITP_PROTOCOL_IMPL_ASSERT_VALID  citp_protocol_impl_assert_valid
extern void citp_protocol_impl_assert_valid(citp_protocol_impl*) CI_HF;

extern void citp_protocol_manager_add(citp_protocol_impl*,
				      int is_stream) CI_HF;

extern int citp_protocol_manager_create_socket(int dom,
					       int type, int proto) CI_HF;

#define citp_protocol_impl_get_ops(p)  (&(p)->ops)

#define citp_protocol_impl_get_type(p)  ((p)->type)

/*! Call not handled - this is not the same as a handover! */
#define CITP_NOT_HANDLED -2


/*******************************************************************************
 ** Invaraint checking
 */
#if CI_CFG_FDTABLE_CHECKS
extern void citp_fdtable_assert_valid(void) CI_HF;
# define FDTABLE_ASSERT_VALID()    citp_fdtable_assert_valid()
#else
# define FDTABLE_ASSERT_VALID()
#endif

#define PTHREAD_NULL    ((pthread_t)(-1L))

/**********************************************************************
 ** File descriptor info.
 */

/* One of these structures for each FD.  Usually, one of these is pointed to
 * by one slot from the FD table.  When it's been closed but other threads
 * have outstanding operations on it, these structures can become 'detached'
 * from the FD table.  Also, if an end-point is cached, one of these
 * structures exists for the end-point, and is also detatched from the FD
 * table.
 *
 * Note that if there are two FDs refering to the same socket, then there
 * are two [citp_fdinfo]s.
 */
struct citp_fdinfo_s {
  /* Sequence no.  Used by epoll to detect change in meaning of an fd. */
  ci_uint64            seq;

  /* Seq no. of epoll fd this fd has been added to. */
  ci_uint64            epoll_fd_seq;

  /* The implementation for this fdinfo. */
  citp_protocol_impl*  protocol;

  /* Number of threads using this (+1 if it's in the table). */
  oo_atomic_t          ref_count;

  union {
    struct {
      unsigned           fd;
      int                flags;
    } dup3_args;
    int                dup2_result;
    int                handover_nonb_switch;
  } on_rcz;

  /* The O/S file descriptor. */
  int                  fd;

  /* epoll fd this fd has been added to, or -1 if not in an epoll set. */
  int                  epoll_fd;

  /* thread id using this fdi */
  pthread_t            thread_id;

  /* What to do when the ref count goes to zero. */
# define FDI_ON_RCZ_NONE	0
# define FDI_ON_RCZ_CLOSE	1
# define FDI_ON_RCZ_DUP2	2
# define FDI_ON_RCZ_HANDOVER	3
# define FDI_ON_RCZ_MOVED	5
# define FDI_ON_RCZ_DONE	6
  volatile char        on_ref_count_zero;

#if CI_CFG_FD_CACHING
  /* Non-zero if this fd is eligable for caching (i.e. if created via
   * accept).
   */
  char                 can_cache;
#endif

  /* This bit is redundant -- can be calculated from other state.  However,
   * it allows us to calculate more quickly whether a FD needs special
   * action; without it, we'd need the test:
   *
   * if( (fdi == &the_reserved_fd) || (fdi == &the_closed_fd) )
   *
   * before using an fd.  Since we'd pad the structure up to a 32-bit
   * boundary anyway, might as well make use of the space.  (Note we use
   * 'chars' rather than bit-fields because this is quicker on
   * architectures that allow byte- aligned access (e.g. x86).
   */
  char                 is_special;
};


extern ci_uint64 fdtable_seq_no;

ci_inline void citp_fdinfo_init(citp_fdinfo* fdi, citp_protocol_impl* p) {
  /* The rest of the initialisation is done in citp_fdtable_insert(). */
  oo_atomic_set(&fdi->ref_count, 1);
#if CI_CFG_FD_CACHING
  fdi->can_cache = 0;
#endif
  fdi->protocol = p;
  fdi->seq = fdtable_seq_no++;
  fdi->epoll_fd = -1;
  fdi->thread_id = PTHREAD_NULL;
}

ci_inline int citp_sys_socket(int domain, int type, int protocol)
{
  int s = -1;
  s = ci_sys_socket(domain, type | SOCK_CLOEXEC, protocol);
  return s;
}


#define CITP_FDINFO_ASSERT_VALID  citp_fdinfo_assert_valid
extern void citp_fdinfo_assert_valid(citp_fdinfo*) CI_HF;


#define citp_fdinfo_get_ops(fdinfo)  \
  (citp_protocol_impl_get_ops((fdinfo)->protocol))

#define citp_fdinfo_get_type(fdinfo)  \
  (citp_protocol_impl_get_type((fdinfo)->protocol))

extern citp_fdinfo citp_the_closed_fd CI_HV;
extern citp_fdinfo citp_the_reserved_fd CI_HV;

extern citp_protocol_impl citp_closed_protocol_impl CI_HV;

/*! Handles release of resources etc. when the ref count hits
 * zero. Call with [fdt_locked] = 0 if the fd table lock is NOT held
 * or [fdt_locked] != 0 if * the fd table lock IS held.
 */
extern void __citp_fdinfo_ref_count_zero(citp_fdinfo*, int fdt_locked) CI_HF;

#define citp_fdinfo_ref(fdi) \
  do {                                      \
    oo_atomic_quick_inc(&(fdi)->ref_count); \
    if( ci_is_multithreaded() )             \
      (fdi)->thread_id = pthread_self();    \
  } while(0)

/*! Release one ref count. When the ref count hits zero will cause
 * release of resources, handles etc. 
 * Call with [fdt_locked] = 0 if the fd table lock is NOT held (this
 * is the legacy operation) or [fdt_locked] != 0 if * the fd table 
 * lock IS held.
 */
ci_inline void citp_fdinfo_release_ref(citp_fdinfo* fdinfo,
				       int fdt_locked) {
  /* If we're releasing a reference from one of our "magic" fd's, then we
   * should never drop the ref-count below 1,000,000
   */
  ci_assert (((fdinfo != &citp_the_closed_fd)   && 
              (fdinfo != &citp_the_reserved_fd)) ||
             (oo_atomic_read (&fdinfo->ref_count) > 1000000));
  ci_assert_gt(oo_atomic_read(&fdinfo->ref_count), 0);

  /* We might call ref_count_zero, which locks fdtable.  Assert that
   * it is possible: */
  ci_assert(oo_per_thread_get()->sig.c.inside_lib);

  if( oo_atomic_quick_dec_and_test(&fdinfo->ref_count) )
    __citp_fdinfo_ref_count_zero(fdinfo, fdt_locked);
}

/*! Release reference obtained by calling citp_fdtable_lookup_fast(). */
ci_inline void citp_fdinfo_release_ref_fast(citp_fdinfo* fdinfo) {
  if( citp_fdtable_not_mt_safe() )
    citp_fdinfo_release_ref(fdinfo, 0);
}
/*! Take the same number of references as with citp_fdtable_lookup_fast(). */
ci_inline void citp_fdinfo_ref_fast(citp_fdinfo* fdinfo) {
  if( citp_fdtable_not_mt_safe() )
    citp_fdinfo_ref(fdinfo);
}

/* Called when refcount reaches zero. */
# define citp_fdinfo_free	CI_FREE_OBJ


/* Hands-over the socket to the kernel.  That is, it replaces the
** user-level socket in the kernel fd table with the O/S socket (which is
** saved by the driver).  Of course this must be a socket that *has* an O/S
** socket (ie. not passive open TCP).
**
** On return the [fdi] has been removed from the fdtable, and the reference
** passed in has been dropped.  ie. Caller must not touch [fdi] again.  The
** caller must also not use the [fd] (without going through
** citp_fdtable_lookup()) as we may have to wait for other threads to go
** away before doing the actual handover.
**
** If [nonb_switch == 0] O_NONBLOCK is cleared for the socket.  If
** [nonb_switch > 0] if is set.  Otherwise nothing is done.
*/
extern void citp_fdinfo_handover(citp_fdinfo* fdi, int nonb_switch) CI_HF;

ci_inline int citp_fdinfo_is_socket(const citp_fdinfo* fdi)
{
  return (fdi->protocol->type == CITP_TCP_SOCKET) ||
         (fdi->protocol->type == CITP_UDP_SOCKET);
}

extern int citp_ep_dup(unsigned oldfd, int (*syscall)(int,long), long) CI_HF;

/* One of these should be used as an arg to citp_ep_dup(). */
extern int citp_ep_dup_dup(int oldfd, long arg_unused) CI_HF;
extern int citp_ep_dup_fcntl_dup(int oldfd, long arg) CI_HF;
extern int citp_ep_dup_fcntl_dup_cloexec(int oldfd, long arg) CI_HF;

extern int citp_ep_dup3(unsigned oldfd, unsigned newfd, int flags) CI_HF;
extern int citp_ep_close(unsigned fd) CI_HF;


/**********************************************************************
 ** exec() support
 */
extern int         __citp_exec_restore( int fd ) CI_HF;


/**********************************************************************
 ** Transport implementations.
 */

extern citp_protocol_impl citp_tcp_protocol_impl CI_HV;
extern citp_protocol_impl citp_udp_protocol_impl CI_HV;
extern citp_protocol_impl citp_epoll_protocol_impl CI_HV;
#if CI_CFG_EPOLL2
extern citp_protocol_impl citp_epollb_protocol_impl CI_HV;
#endif
extern citp_protocol_impl citp_pipe_read_protocol_impl CI_HV;
extern citp_protocol_impl citp_pipe_write_protocol_impl CI_HV;
extern citp_protocol_impl citp_passthrough_protocol_impl;


typedef struct {
  citp_fdinfo  fdinfo;
  citp_socket  sock;
} citp_sock_fdi;

#define fdi_to_sock_fdi(fdi)    CI_CONTAINER(citp_sock_fdi, fdinfo, (fdi))
#define fdi_to_socket(fdi)      (&fdi_to_sock_fdi(fdi)->sock)

typedef struct {
  citp_fdinfo  fdinfo;
  ci_netif*     netif;
  citp_waitable* ep;
  int os_socket;
} citp_alien_fdi;

#define fdi_to_alien_fdi(fdi)    CI_CONTAINER(citp_alien_fdi, fdinfo, (fdi))

extern void citp_passthrough_init(citp_alien_fdi* epi);

#include <onload/epoll.h>
typedef struct {
  citp_fdinfo        fdinfo;
  int                kepfd;
  int                is_accel;

  int                not_mt_safe;
  int                have_postponed;
  pthread_mutex_t    lock_postponed;
  struct oo_epoll_item  postponed[CI_CFG_EPOLL_MAX_POSTPONED];
} citp_epollb_fdi;
#define fdi_to_epollb_fdi(fdi)  CI_CONTAINER(citp_epollb_fdi, fdinfo, (fdi))
extern void oo_epollb_ctor(citp_epollb_fdi *epi);


/**********************************************************************
 ** Netif initialisation (netif_init.c).
 */

extern int citp_netif_init_ctor(void) CI_HF;

/* Set up fork handling at start-of-day */
extern int ci_setup_fork(void);

/*! Handles user-level netif internals pre bproc_move() */
extern void citp_netif_pre_bproc_move_hook(void) CI_HF;

#if CI_CFG_FD_CACHING
extern void citp_uncache_fds_ul(ci_netif* netif);
extern void uncache_active_netifs(void);
#endif

extern void exit_lock_all_stacks(void);
extern bool have_active_netifs(void);


/**********************************************************************
 ** Misc.
 */

extern void citp_log_fn_ul(const char* msg)  CI_HF;
extern void citp_log_fn_drv(const char* msg)  CI_HF;

extern void citp_setup_logging_prefix(void) CI_HF;

extern int citp_packet_interceptor_startup(void) CI_HF;

extern int _citp_do_init_inprogress CI_HV;
extern int citp_do_init(int max_init_level) CI_HF;

extern int citp_basic_syscall_init(void) CI_HF;
extern int citp_syscall_init(void) CI_HF;

#undef socklen_t

extern citp_fdinfo* citp_tcp_dup(citp_fdinfo* orig_fdi);

/* Locking order:
 * - citp_pkt_map_lock is the innermost lock;
 * - citp_dup_lock should be taken before citp_ul_lock.
 * citp_dup_lock protects dups and forks, which are not async-safe and can
 * not be called from signal handler.  So, citp_dup_lock may be taken
 * without enter_lib.
 */
extern pthread_mutex_t citp_dup_lock;
extern pthread_mutex_t citp_pkt_map_lock;

extern int citp_timespec_compare(const struct timespec* a,
                                 const struct timespec* b) CI_HF;

extern int citp_oo_timespec_compare(const struct oo_timespec* a,
                                    const struct timespec* b) CI_HF;

/**********************************************************************
 ** fdtable internals.
 */

/*! A pointer to an citp_fdinfo.  Must be used with extreme care, as these
** may be accessed concurrently from multiple threads, and also take
** certain special values.
*/
typedef ci_uintptr_t		citp_fdinfo_p;

#define fdip_passthru		((citp_fdinfo_p)1u)
#define fdip_unknown		((citp_fdinfo_p)2u)
#define fdip_busy		((citp_fdinfo_p)3u)
#define fdip_closing		fdi_to_fdip(&citp_the_closed_fd)
#define fdip_reserved		fdi_to_fdip(&citp_the_reserved_fd)

#define fdip_is_normal(fdip)	(((fdip) & fdip_busy) == 0)
#define fdip_is_busy(fdip)	(((fdip) & fdip_busy) == fdip_busy)
#define fdip_is_passthru(fdip)	((fdip) == fdip_passthru)
#define fdip_is_unknown(fdip)	((fdip) == fdip_unknown)
#define fdip_is_closing(fdip)	((fdip) == fdip_closing)
#define fdip_is_reserved(fdip)	((fdip) == fdip_reserved)

ci_inline citp_fdinfo* fdip_to_fdi(citp_fdinfo_p fdip) {
  ci_assert(fdip_is_normal(fdip));
  ci_assert(fdip);
  return (citp_fdinfo*) fdip;
}

#define fdi_to_fdip(fdi)	((citp_fdinfo_p)(ci_uintptr_t) (fdi))

#define fdip_cas_succeed	ci_cas_uintptr_succeed
#define fdip_cas_fail		ci_cas_uintptr_fail


typedef struct {
  volatile citp_fdinfo_p fdip;
} citp_fdtable_entry;


typedef struct {
  citp_fdtable_entry*	table;
  unsigned		size;
  unsigned		inited_count;
} citp_fdtable_globals;


extern citp_fdtable_globals	citp_fdtable CI_HV;


/* The following stuff is used to block when an fdtable entry is busy. */
typedef struct {
  citp_fdinfo_p		next;
  oo_rwlock_cond	cond;
} citp_fdtable_waiter;

#define fdip_to_waiter(fdip)	((citp_fdtable_waiter*)(ci_uintptr_t)	\
				 ((fdip) & ~(fdip_busy)))

#define waiter_to_fdip(w)	((citp_fdinfo_p)(ci_uintptr_t)(w) | fdip_busy)

extern void __citp_fdtable_busy_clear_slow(unsigned fd, citp_fdinfo_p,
					   int fdt_locked) CI_HF;

ci_inline void citp_fdtable_busy_clear(unsigned fd, citp_fdinfo_p fdip,
				       int fdt_locked) {
  if( fdip_cas_fail(&citp_fdtable.table[fd].fdip, fdip_busy, fdip) )
    __citp_fdtable_busy_clear_slow(fd, fdip, fdt_locked);
}

/*! Block until fdtable entry is not busy, and return the new (non-busy)
** fdip. */
extern citp_fdinfo_p citp_fdtable_busy_wait(unsigned fd, int fdt_locked) CI_HF;




/**********************************************************************
 ** Transport library user-level lock
 */

/******************************************************************************
 * Even our carefully optimized lock operations and atomic ops are quite slow.
 * Specifically, this is caused by the presence of the LOCK prefix seems to
 * cost up to 100 cycles.  The glibc boys have apparently noticed the same
 * issues, and so keep a bit hanging of gs (at gs:0x10) that says whether the
 * current process is multithreaded.  We use this to determine whether or not
 * we need to assert the LOCK bit on the bus when doing atomic operations.
 * Note however that any atomic types in the shared state must assert the LOCK
 * bit regardless of whether the app is multithreaded -- it's only the state
 * private to the process for which we can play this game.
 */

#define __CITP_LOCK(l) do {	\
    if (ci_is_multithreaded())	\
      oo_rwlock_lock_write(l);	\
  } while(0)

#define __CITP_LOCK_RD(l) do {	\
    if (ci_is_multithreaded())	\
      oo_rwlock_lock_read(l);	\
  } while(0)

#define __CITP_UNLOCK(l) do {	\
    if (ci_is_multithreaded())	\
      oo_rwlock_unlock_write(l);\
  } while(0)

#define __CITP_UNLOCK_RD(l) do {\
    if (ci_is_multithreaded())	\
      oo_rwlock_unlock_read(l);	\
  } while(0)

/* \TODO Add specific unlock read and unlock write operations */

#ifdef NDEBUG

#define CITP_FDTABLE_LOCK()	__CITP_LOCK(&citp_ul_lock)
#define CITP_FDTABLE_LOCK_RD()	__CITP_LOCK_RD(&citp_ul_lock)
#define CITP_FDTABLE_UNLOCK()	__CITP_UNLOCK(&citp_ul_lock)
#define CITP_FDTABLE_UNLOCK_RD() __CITP_UNLOCK_RD(&citp_ul_lock)

#define CITP_FDTABLE_ASSERT_LOCKED(fdt_locked)
#define CITP_FDTABLE_ASSERT_LOCKED_RD

#else

ci_inline void CITP_FDTABLE_LOCK(void)
{
  citp_signal_info* si = &oo_per_thread_get()->sig;
  ci_assert(si->c.inside_lib);
  ci_atomic32_or(&si->c.aflags, OO_SIGNAL_FLAG_FDTABLE_LOCKED);
  __CITP_LOCK(&citp_ul_lock);
}
ci_inline void CITP_FDTABLE_LOCK_RD(void)
{
  citp_signal_info* si = &oo_per_thread_get()->sig;
  ci_assert(si->c.inside_lib);
  ci_atomic32_or(&si->c.aflags, OO_SIGNAL_FLAG_FDTABLE_LOCKED);
  __CITP_LOCK_RD(&citp_ul_lock);
}
ci_inline void CITP_FDTABLE_UNLOCK(void)
{
  citp_signal_info* si = &oo_per_thread_get()->sig;
  ci_assert(si->c.inside_lib);
  ci_atomic32_and(&si->c.aflags, ~OO_SIGNAL_FLAG_FDTABLE_LOCKED);
  __CITP_UNLOCK(&citp_ul_lock);
}
ci_inline void CITP_FDTABLE_UNLOCK_RD(void)
{
  citp_signal_info* si = &oo_per_thread_get()->sig;
  ci_assert(si->c.inside_lib);
  ci_atomic32_and(&si->c.aflags, ~OO_SIGNAL_FLAG_FDTABLE_LOCKED);
  __CITP_UNLOCK_RD(&citp_ul_lock);
}

ci_inline void
_CITP_FDTABLE_ASSERT_LOCKED(int fdt_locked, char* file, int line)
{
  citp_signal_info* si = &oo_per_thread_get()->sig;
  if( ! fdt_locked )
    return;
  _ci_assert(si->c.aflags & OO_SIGNAL_FLAG_FDTABLE_LOCKED, file, line);
  _ci_assert(si->c.inside_lib, file, line);
}
#define CITP_FDTABLE_ASSERT_LOCKED(fdt_locked)			\
  _CITP_FDTABLE_ASSERT_LOCKED(fdt_locked, __FILE__, __LINE__)

#define CITP_FDTABLE_ASSERT_LOCKED_RD CITP_FDTABLE_ASSERT_LOCKED(1)
#endif

/**********************************************************************
 ** File-descriptor table.
 */

extern int           citp_fdtable_ctor(void) CI_HF;

/* Looks up the user-level fdinfo for a given file descriptor.  If found,
 * increments the ref count and returns pointer to the fdinfo.
 *
 * If [fd] is not handled at userlevel, returns NULL.
 *
 * Must have "entered" the library before calling this.
 */
extern citp_fdinfo*  citp_fdtable_lookup(unsigned fd) CI_HF;

/* Faster version of citp_fdtable_lookup().  In most cases (but not always)
 * avoids entering the library when [fd] is pass-through.
 */
extern citp_fdinfo*  citp_fdtable_lookup_fast(citp_lib_context_t*,
                                              unsigned fd) CI_HF;

extern citp_fdinfo*  citp_fdtable_lookup_noprobe(unsigned fd, int fdt_locked) CI_HF;

extern int
citp_reprobe_moved_common(citp_fdinfo* fdinfo, int from_fast_lookup,
                          int fdip_is_already_busy, citp_fdinfo** fdinfo_out);

ci_inline citp_fdinfo*
citp_reprobe_moved(citp_fdinfo* fdinfo, int from_fast_lookup,
                   int fdip_is_already_busy)
{
  citp_fdinfo* new_fdinfo;
  citp_reprobe_moved_common(fdinfo, from_fast_lookup, fdip_is_already_busy,
                            &new_fdinfo);
  return new_fdinfo;
}

#if CI_CFG_FD_CACHING
extern void          citp_netif_cache_disable(void) CI_HF;
extern void          citp_netif_cache_warn_on_fork(void) CI_HF;
#endif
extern void          citp_fdtable_fork_hook(void) CI_HF;
extern citp_fdinfo_p citp_fdtable_new_fd_set(unsigned fd, citp_fdinfo_p,
					     int fdt_locked) CI_HF;
extern void          citp_fdtable_insert(citp_fdinfo*,
					 unsigned fd, int fdt_locked) CI_HF;
extern void        __citp_fdtable_reserve(int fd, int reserve) CI_HF;

  /* Marks [fd] as reserved, so any external attempt to use it will give
  ** EBADF.  Caller should ensure that the fdtable lock is held (or can be
  ** called at init time without the lock).
  **
  ** If [reserve] is zero, the entry is un-reserved.
  */


ci_inline bool citp_fd_is_special(int fd) {
   return fd == citp.log_fd;
}

/* Extend the initialisation of the FD table, marking each FD as unknown */
ci_inline void __citp_fdtable_extend(unsigned fd) {
  unsigned i, max;

  CITP_FDTABLE_ASSERT_LOCKED(1);

  /* ?? TODO: ensure only called if fd < citp_fdtable.size */
  ++fd;
  max = CI_MIN(citp_fdtable.size, fd);

  if( max > citp_fdtable.inited_count ) {
    for( i = citp_fdtable.inited_count; i < max; ++i ) {
      if( ! citp_fd_is_special(i) )
	citp_fdtable.table[i].fdip = fdip_unknown;
      else
	citp_fdtable.table[i].fdip = fdi_to_fdip(&citp_the_reserved_fd);
    }
    ci_wmb();
    citp_fdtable.inited_count = max;
  }
}


/*! Marks an fdtable entry as pass-through. */
ci_inline void citp_fdtable_passthru(int fd, int fdt_locked) {
  if( fd >= 0 && fd < citp_fdtable.inited_count &&
      !oo_per_thread_get()->in_vfork_child )
    citp_fdtable_new_fd_set(fd, fdip_passthru, fdt_locked);
}

extern int
citp_passthrough_bind(citp_fdinfo* fdi,
                      const struct sockaddr* sa, socklen_t sa_len);
extern int
citp_passthrough_accept(citp_fdinfo* fdi,
                        struct sockaddr* sa, socklen_t* p_sa_len, int flags,
                        citp_lib_context_t* lib_context);
extern int
citp_passthrough_connect(citp_fdinfo* fdi,
                         const struct sockaddr* sa, socklen_t sa_len,
                         citp_lib_context_t* lib_context);

/**********************************************************************
 ** Stack name state access
 */
extern int oo_extensions_init(void);

ci_inline struct oo_stackname_state *oo_stackname_thread_get(void)
{
  struct oo_per_thread* pt = oo_per_thread_get();
  return &pt->stackname;
}


/**********************************************************************
 ** Signal deferral and errno propagation
 */

ci_inline int __citp_checked_enter_lib(citp_lib_context_t *lib_context
                                       CI_DEBUG_ARG(const char *fn)
                                       CI_DEBUG_ARG(int line) ) 
{
  lib_context->saved_errno = errno;
  lib_context->thread = __oo_per_thread_get();
  Log_LIB(log("  citp_checked_enter_lib(%p) [was_in=%d] %s (%d)",
              lib_context->thread, lib_context->thread->sig.c.inside_lib > 0,
              fn, line));
  ci_assert(~lib_context->thread->sig.c.aflags &
            OO_SIGNAL_FLAG_FDTABLE_LOCKED);
  ++lib_context->thread->sig.c.inside_lib;    
  return (lib_context->thread->sig.c.inside_lib==1);
}


ci_inline void __citp_enter_lib(citp_lib_context_t *lib_context
                                CI_DEBUG_ARG(const char *fn)
                                CI_DEBUG_ARG(int line) ) 
{
  lib_context->saved_errno = errno;
  lib_context->thread = __oo_per_thread_get();
  Log_LIB(log("  citp_enter_lib(%p) inside_lib=%d %s (%d)",
              lib_context->thread, lib_context->thread->sig.c.inside_lib,
              fn, line));
  ci_assert_ge(lib_context->thread->sig.c.inside_lib, 0);
  ci_assert(~lib_context->thread->sig.c.aflags &
            OO_SIGNAL_FLAG_FDTABLE_LOCKED);
  ++lib_context->thread->sig.c.inside_lib;
}


ci_inline void __citp_reenter_lib(citp_lib_context_t *lib_context
                                  CI_DEBUG_ARG(const char *fn)
                                  CI_DEBUG_ARG(int line) ) 
{
  Log_LIB(log("  citp_reenter_lib(%p) inside_lib=%d %s (%d)",
              lib_context->thread, lib_context->thread->sig.c.inside_lib,
              fn, line));
  ci_assert_ge(lib_context->thread->sig.c.inside_lib, 0);
  ci_assert(~lib_context->thread->sig.c.aflags &
            OO_SIGNAL_FLAG_FDTABLE_LOCKED);
  ++lib_context->thread->sig.c.inside_lib;
}


ci_inline void __citp_exit_lib(citp_lib_context_t *lib_context, int do_errno
                               CI_DEBUG_ARG(const char *fn)
                               CI_DEBUG_ARG(int line) ) 
{
  Log_LIB(log("  citp_exit_lib(%p) inside_lib=%d %s (%d)",
              lib_context->thread, lib_context->thread->sig.c.inside_lib,
              fn, line));
  ci_assert_ge(lib_context->thread->sig.c.inside_lib, 1);
  ci_assert(~lib_context->thread->sig.c.aflags &
            OO_SIGNAL_FLAG_FDTABLE_LOCKED);
  --lib_context->thread->sig.c.inside_lib;
  ci_compiler_barrier();
  if(CI_UNLIKELY( lib_context->thread->sig.c.inside_lib == 0 && 
                  (lib_context->thread->sig.c.aflags &
                   OO_SIGNAL_FLAG_HAVE_PENDING) ))
    citp_signal_run_pending(&lib_context->thread->sig);
  if( do_errno )
    errno = lib_context->saved_errno;
}


#define citp_checked_enter_lib(c)				\
  __citp_checked_enter_lib((c) CI_DEBUG_ARG(__FUNCTION__)	\
			   CI_DEBUG_ARG(__LINE__))

#define citp_enter_lib(c)						  \
  __citp_enter_lib((c) CI_DEBUG_ARG(__FUNCTION__) CI_DEBUG_ARG(__LINE__))

#define citp_reenter_lib(c)					\
  __citp_reenter_lib((c) CI_DEBUG_ARG(__FUNCTION__) CI_DEBUG_ARG(__LINE__))

#define citp_exit_lib(c, de)						     \
  __citp_exit_lib((c), (de) CI_DEBUG_ARG(__FUNCTION__) CI_DEBUG_ARG(__LINE__))

#define citp_enter_lib_if(c)                    \
  do {                                          \
    if( (c)->thread == NULL )                   \
      citp_enter_lib(c);                        \
  } while( 0 )

#define citp_exit_lib_if(c, de)                 \
  do {                                          \
    if(CI_UNLIKELY( (c)->thread != NULL ))      \
      citp_exit_lib((c), (de));                 \
  } while( 0 )


#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif


/**********************************************************************
 ** Environment handling
 */

extern size_t citp_environ_count_args(const char* arg, va_list args) CI_HF;
extern void citp_environ_handle_args(char** argv, const char* arg,
                                     va_list args, char*** env_ptr) CI_HF;
extern char* const* citp_environ_check_preload(char* const* env,
                                               size_t* bytes_reqd) CI_HF;
extern void citp_environ_make_preload(char* const* env, char** new_env,
                               size_t new_env_bytes) CI_HF;
extern int    citp_environ_init(void) CI_HF;


/**********************************************************************
 ** TCP/UDP common functionality
 */

extern int citp_sock_fcntl_os_sock(citp_sock_fdi* epi, int fd, int cmd,
                                   long arg, const char* cmd_str,
                                   int* fcntl_result) CI_HF;

/*! Handler for fcntl() cmds that are common across sockets.
 *
 * \param epi     Context
 * \param fd      FD used by fcntl() originator
 * \param cmd     Param from original fcntl() call
 * \param arg     Param from original fcntl() call
 * \return        As per standard fcntl()
 */
extern int citp_sock_fcntl(citp_sock_fdi*, int fd, int cmd, long arg) CI_HF;

#define ci_major(dev) ((dev) & 0xff00)

/**********************************************************************
 * poll, select, epoll
 */

/* Generic poll/ppoll implementation.
 * This function is called after citp_enter_lib(), and it MUST NOT call
 * citp_exit_lib().
 * At exit time, if *timeout_ms!=0 and rc==0, caller should block in system
 * call for the specified timeout.
 */
int citp_ul_do_poll(struct pollfd*__restrict__ fds, nfds_t nfds,
                    ci_uint64 timeout_ms, ci_uint64 *used_ms,
                    citp_lib_context_t *lib_context,
                    const sigset_t *sigmask);
/* Generic select/pselect implementation.
 * This function is called after citp_enter_lib(), and it MUST NOT call
 * citp_exit_lib().
 * At exit time, if *timeout_ms!=0 and rc==0, caller should block in system
 * call for the specified timeout.
 */
int citp_ul_do_select(int nfds, fd_set* rds, fd_set* wrs, fd_set* exs,
                      ci_uint64 timeout_ms, ci_uint64 *used_ms,
                      citp_lib_context_t *lib_context,
                      const sigset_t *sigmask);

/* ppoll/pselect common code.
 *
 * ppoll/pselect functions work in following way:
 * - enter lib;
 * - non-blocking poll/select and fast exit if we've got anything;
 * - spin:
 *   - citp_ul_pwait_spin_pre():
 *     - exit lib;
 *     - block all signals to be blocked;
 *     - enter lib to prevent all signals to be handled;
 *     - set sigprocmask - allow some new signals;
 *     - check for pending signals and return -1(errno=EINTR) if necessary.
 *   - spin in poll/select/epoll
 *   - citp_ul_pwait_spin_done():
 *     - restore sigmask
 *     - check signals to return -1(errno=EINTR) if any;
 *     - exit lib;
 *   - return to user if we have found something;
 * - ci_sys_p(poll|select)
 *
 *
 *
 * Known bug
 * ---------
 * When spinning for a limited time (i.e. we spin, then block).
 * If a SIGX is allowed by sigsaved, it MAY be handled silently by
 * ppoll/pselect/epoll_pwait.  No reasonable application I can imagine
 * should not be broken by this.
 *
 * To fix this bug, we can block all signals between spinning and OS call.
 * I.e instead of current citp_ul_pwait_spin_done()+sys_ppoll() we can do:
 * sigprocmask(block all)+sys_ppoll()+sigprocmask(restore).
 * It makes the code much more complicated and adds sigprocmask syscall
 * to the latency-critical path without any visible benefit.
 */

static inline int
citp_ul_pwait_spin_pre(citp_lib_context_t *lib_context,
                       const sigset_t *sigmask, sigset_t *sigsaved)
{
  Log_POLL(log("%s(%p,%p)", __func__, sigmask, sigsaved));
  citp_exit_lib(lib_context, CI_FALSE);
  sigprocmask(SIG_BLOCK, sigmask, sigsaved);
  citp_enter_lib(lib_context);

  if( sigmask == NULL )
    return 0;

  sigprocmask(SIG_SETMASK, sigmask, NULL);
  if(CI_UNLIKELY( lib_context->thread->sig.c.aflags &
                  OO_SIGNAL_FLAG_HAVE_PENDING )) {
    sigprocmask(SIG_SETMASK, sigsaved, NULL);
    Log_POLL(log("%s: interrupted", __func__));
    errno = EINTR;
    return -1;
  }
  return 0;
}
static inline void
citp_ul_pwait_spin_done(citp_lib_context_t *lib_context,
                        sigset_t *sigsaved, int *p_rc)
{
  Log_POLL(log("%s(%p,%d)", __func__, sigsaved, *p_rc));
  sigprocmask(SIG_BLOCK, sigsaved, NULL);
  if(CI_UNLIKELY( lib_context->thread->sig.c.aflags &
                  OO_SIGNAL_FLAG_HAVE_PENDING )) {
    Log_POLL(log("%s: interrupted", __func__));
    errno = EINTR;
    *p_rc = -1;
  }
  citp_exit_lib(lib_context, *p_rc >= 0);

  /* If you want to fix the bug described above, move this sigprocmask to
   * after OS call. */
  sigprocmask(SIG_SETMASK, sigsaved, NULL);
}


/* As citp_poll_if_needed(), but leaves the stack locked after polling. */
static inline int __citp_poll_if_needed(ci_netif* ni, ci_uint64 recent_frc,
                                        int is_spinning)
{
  if( ci_netif_may_poll(ni) &&
      ci_netif_need_poll_maybe_spinning(ni, recent_frc, is_spinning) &&
      ci_netif_trylock(ni) ) {
    ci_netif_poll(ni);
    if( is_spinning )
      ni->state->last_spin_poll_frc = IPTIMER_STATE(ni)->frc;
    return 1;
  }
  return 0;
}


/* Poll the stack if allowed, needed and we can grab the lock.
 * Return true if we did poll the stack, otherwise return false.
 *
 * Used by poll(), select() and epoll_wait().
 */
static inline int citp_poll_if_needed(ci_netif* ni, ci_uint64 recent_frc,
                                      int is_spinning)
{
  int rc = __citp_poll_if_needed(ni, recent_frc, is_spinning);
  if( rc != 0 )
    ci_netif_unlock(ni);
  return rc;
}


/* Query onload driver for the cpu_khz value */
void citp_oo_get_cpu_khz(ci_uint32* cpu_khz);


ci_inline ci_uint64 citp_usec_to_cycles64(unsigned usec)
{ return (ci_uint64) usec * citp.cpu_khz / 1000; }


extern int citp_sock_is_spinning(citp_fdinfo* fdi);

/**********************************************************************
 * Utils
 */
ci_inline void
ms2timespec(ci_uint64 timeout, ci_uint64 spent, struct timespec* tv)
{
  if( timeout > spent ) {
    tv->tv_sec = (timeout - spent) / 1000;
    tv->tv_nsec = ((timeout - spent) % 1000) * 1000000;
  }
  else {
    tv->tv_sec = tv->tv_nsec = 0;
  }
}

#if CI_CFG_FD_CACHING
ci_inline int citp_getpid(void)
{
  return citp.pid;
}
#endif

/* Provides a non-specialised Onload fd solely for logging. */
extern void init_citp_log_fd(void);

extern void oo_signal_terminate(int signum);

#endif  /* __CI_TRANSPORT_INTERNAL_H__ */
/*! \cidoxg_end */
