/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2010-2020 Xilinx, Inc. */
#ifndef __UNIX_UL_EPOLL_H__
#define __UNIX_UL_EPOLL_H__

#include <limits.h>
#include <sys/epoll.h>
#include <onload/ul/wqlock.h>
#include <onload/timesync.h>
#include "internal.h"
#include "ul_poll.h"
#include "nonsock.h"


/* See comment in ef_onload_driver_open() about why we shift this fd */
static inline void ci_sys_epoll_move_fd(int oldfd, int* newfd)
{
  int fd = ci_sys_fcntl(oldfd, F_DUPFD_CLOEXEC, CITP_OPTS.fd_base);
  if( fd >= 0 ) {
    ci_sys_close(oldfd);
    *newfd = fd;
  }
  /* we ignore failure to shift the fd, in the hope that it won't cause a
   * problem in the place we got it originally.
   */
}


static inline int ci_sys_epoll_create_compat(int size, int flags, int cloexec)
{
  int rc;
  int fd;

  if( cloexec )
    flags |= EPOLL_CLOEXEC;

  /* Yes, it is VERY likely.  But if you compile with new libc, but run
   * with the old one, you get assert in citp_enter_lib. */
  if( flags && CI_LIKELY( ci_sys_epoll_create1 != epoll_create1 ) ) {
    rc = ci_sys_epoll_create1(flags);

    if( rc >= 0 && rc < CITP_OPTS.fd_base )
      ci_sys_epoll_move_fd(rc, &rc);

    /* ENOSYS means that kernel is older than libc; fall through
     * to the old epoll_create(). */
    if( rc >=0 || errno != ENOSYS )
      return rc;
  }

  /* EPOLL_CLOEXEC is known, but it failed somehow. */
  cloexec |= flags & EPOLL_CLOEXEC;

  fd = ci_sys_epoll_create(size);
  if( fd < 0 )
    return fd;

  if( fd < CITP_OPTS.fd_base )
    ci_sys_epoll_move_fd(fd, &fd);

  if( ! cloexec )
    return fd;
  rc = ci_sys_fcntl(fd, F_SETFD, FD_CLOEXEC);
  if( rc < 0 ) {
    Log_E(log("%s: fcntl(F_SETFD, FD_CLOEXEC) failed errno=%d",
              __FUNCTION__, errno));
    ci_sys_close(fd);
    return -1;
  }
  return fd;
}

ci_inline citp_fdinfo*
citp_epoll_fdi_from_member(citp_fdinfo* fd_fdi, int fdt_locked)
{
  citp_fdinfo* epoll_fdi = citp_fdtable_lookup_noprobe(fd_fdi->epoll_fd, fdt_locked);
  if( epoll_fdi == NULL ) {
    Log_POLL(ci_log("%s: epoll_fd=%d not found (fd=%d)", __FUNCTION__,
                    fd_fdi->epoll_fd, fd_fdi->fd));
    return NULL;
  }
  if( epoll_fdi->seq != fd_fdi->epoll_fd_seq ||
      ( epoll_fdi->protocol->type != CITP_EPOLL_FD &&
        epoll_fdi->protocol->type != CITP_EPOLLB_FD ) ) {
    Log_POLL(ci_log("%s: epoll_fd=%d changed (type=%d seq=%llx,%llx fd=%d)",
                    __FUNCTION__, fd_fdi->epoll_fd, epoll_fdi->protocol->type,
                    (unsigned long long) epoll_fdi->seq,
                    (unsigned long long) fd_fdi->epoll_fd_seq, fd_fdi->fd));
    citp_fdinfo_release_ref(epoll_fdi, fdt_locked);
    return NULL;
  }

  return epoll_fdi;
}


/*************************************************************************
 **************** The first EPOLL implementation *************************
 *************************************************************************/

/* We rely on the fact that EPOLLxxx == POLLxxx.  Check it at build time! */
CI_BUILD_ASSERT(EPOLLOUT == POLLOUT);
CI_BUILD_ASSERT(EPOLLIN == POLLIN);


/*! Per-fd structure to keep in epoll file. */
struct citp_epoll_member {
  ci_dllink             dllink;     /*!< Double-linked list links */
  ci_dllist*            item_list;  /*!< The list this member belong on */
#if CI_CFG_EPOLL3
  ci_dllink             dead_stack_link; /*!< Link for dead stack list */
  int                   ready_list_id;
#endif
  struct epoll_event    epoll_data;
  struct epoll_event    epfd_event; /*!< event synchronised to kernel */
  ci_uint64             fdi_seq;    /*!< fdi->seq */
  int                   fd;         /*!< Onload fd */
  ci_sleep_seq_t        reported_sleep_seq;

  int                   flags;
/*!< indicates after which eitem on ready list socket we should look
 * on other and os sockets */
#define CITP_EITEM_FLAG_POLL_END    1
/*!< this eitem is (or was) a non-home member of the epoll set,
 * and it was added to the kernel epoll set. */
#define CITP_EITEM_FLAG_OS_SYNC     2
};


enum {
  EPOLL_PHASE_DONE_ACCELERATED = 1,
  EPOLL_PHASE_DONE_OTHER = 2,
};

#define EPOLL_STACK_EITEM 1
#define EPOLL_NON_STACK_EITEM 2
/*! Data associated with each epoll epfd.  */
struct citp_epoll_fd {
  /* epoll_create() parameter */
  int     size;

  /* Os file descriptor for alien (kernel) fds */
  int     epfd_os;
  struct oo_epoll1_shared *shared;

  /* Lock for [oo_sockets] and [dead_sockets].  fdtable lock must be taken
   * after this one to avoid deadlock.
   */
  struct oo_wqlock      lock;
  int                   not_mt_safe;

#if CI_CFG_EPOLL3
  /* Lock for and [dead_stack_sockets].  fdtable lock must be taken
   * after this one to avoid deadlock.
   */
  struct oo_wqlock      dead_stack_lock;

  /* List of onload sockets in home stack (struct citp_epoll_member) */
  ci_dllist             oo_stack_sockets;
  ci_dllist             oo_stack_not_ready_sockets;
  int                   oo_stack_sockets_n;

  /* list of [citp_epoll_fdi] structures associated with this epoll set. */
  ci_dllist epi_list;
#endif

  /* List of onload sockets in non-home stack (struct citp_epoll_member) */
  ci_dllist             oo_sockets;
  int                   oo_sockets_n;

  /* List of deleted sockets (struct citp_epoll_member) */
  ci_dllist             dead_sockets;
  ci_dllist             dead_stack_sockets;

  /* Refcount to increment at dup() time. */
  oo_atomic_t refcount;

  /* Number of changes to u/l members not yet synchronised with kernel. */
  int         epfd_syncs_needed;

  /* Is a thread in a blocking call to sys_epoll_wait() ?  This is used to
   * decide whether epoll_ctl() should be allowed to delay update of kernel
   * state (EF_EPOLL_CTL_FAST).
   */
  int         blocking;

  /* Avoid spinning in next epoll_pwait call */
  int avoid_spin_once;

  /* We've entered the citp_epoll_dtor() function */
  int closing;

#if CI_CFG_EPOLL3
  ci_netif* home_stack;
  int ready_list;
#endif

  /*!< phase of the poll to ensure fairness between groups of sockets
   * value of highest bit matters */
  int phase;

#if CI_CFG_TIMESTAMPING
  /* When using WODA with large numbers of sockets performance can be harmed
   * by repeated large alloc/free calls, so we cache memory allocated for this
   * purpose.
   */
  struct citp_ordering_info* ordering_info;
  struct epoll_event* wait_events;
  int n_woda_events;
#endif
};


typedef struct {
  citp_fdinfo           fdinfo;
  struct citp_epoll_fd* epoll;
#if CI_CFG_EPOLL3
  /* link for citp_epoll_fd::epi_list list */
  ci_dllink dllink;
#endif
} citp_epoll_fdi;

#define fdi_to_epoll_fdi(fdi)  CI_CONTAINER(citp_epoll_fdi, fdinfo, (fdi))
#define fdi_to_epoll(fdi)      (fdi_to_epoll_fdi(fdi)->epoll)

struct citp_ordering_info {
  struct epoll_event* event;
  struct onload_ordered_epoll_event oo_event;
  struct timespec next_rx_ts;
  citp_fdinfo* fdi;
};

struct citp_ordered_wait {
  struct citp_ordering_info* ordering_info;
  int poll_again;
  ci_int64 next_timeout_hr;
  ci_netif* ordering_stack;
};

/* Epoll state in user-land poll.  Copied from oo_ul_poll_state */
struct oo_ul_epoll_state {
  /* Parameters of this epoll fd */
  struct citp_epoll_fd* ep;

  /* Where to store events. */
  struct epoll_event*__restrict__ events;

  /* End of the [events] array. */
  struct epoll_event*__restrict__ events_top;

  /* Information associated with ordering. */
  struct citp_ordering_info* ordering_info;

  /* Timestamp for the beginning of the current poll.  Used to avoid doing
   * ci_netif_poll() on stacks too frequently.
   */
  ci_uint64             this_poll_frc;

  /* Whether or not this call should spin */
  unsigned              ul_epoll_spin;

  /* We have found some EPOLLET or EPOLLONESHOT events, and they can not be
   * dropped. */
  int                   has_epollet;

#if CI_CFG_SPIN_STATS
  /* Have we incremented statistics for this spin round? */
  int stat_incremented;
#endif

  int phase;
};

#define OO_EPOLL_MIN_CPU_KHZ TIMESYNC_MIN_CPU_KHZ
#define OO_EPOLL_MAX_CPU_KHZ TIMESYNC_MAX_CPU_KHZ

/* Maximum timeout_hr we can handle.
 * timeout=-1 is converted to this value.
 */
#define OO_EPOLL_MAX_TIMEOUT_FRC ((INT64_MAX / NSEC_PER_MSEC) * \
                                  OO_EPOLL_MIN_CPU_KHZ)

/* Ensure oo_epoll_ms_to_frc can never return a value greater than
 * OO_EPOLL_MAX_TIMEOUT_FRC.
 */
CI_BUILD_ASSERT(INT_MAX * OO_EPOLL_MAX_CPU_KHZ <= OO_EPOLL_MAX_TIMEOUT_FRC);

/* Convert a ms timeout to one in cycles. */
static inline ci_int64 oo_epoll_ms_to_frc(int ms_timeout)
{
  if( ms_timeout < 0 )
    return OO_EPOLL_MAX_TIMEOUT_FRC;
  else
    return (ci_int64)ms_timeout * citp.cpu_khz;
}

/* Maximum timeout in seconds we could have if running on a 10GHz processor */
#define OO_EPOLL_MAX_TV_SEC ((OO_EPOLL_MAX_TIMEOUT_FRC \
                             / (10ULL*1000*1000*1000)) - 1)


/* Ensure oo_epoll_ts_to_frc can never return a value greater than
 * OO_EPOLL_MAX_TIMEOUT_FRC.
 */
CI_BUILD_ASSERT(OO_EPOLL_MAX_TV_SEC * 1000 * OO_EPOLL_MAX_CPU_KHZ +
                ((NSEC_PER_MSEC * OO_EPOLL_MAX_CPU_KHZ) / NSEC_PER_MSEC) <=
                OO_EPOLL_MAX_TIMEOUT_FRC);

/* Convert a timespec to a timeout in cycles */
static inline ci_int64 oo_epoll_ts_to_frc(const struct timespec *ts)
{
  if( ts == NULL || ts->tv_sec > OO_EPOLL_MAX_TV_SEC )
    return OO_EPOLL_MAX_TIMEOUT_FRC;
  return ts->tv_sec * 1000 * citp.cpu_khz +
         ((ts->tv_nsec * citp.cpu_khz) / NSEC_PER_MSEC);
}

/* Maximum timeout in ns we could have if running on a 10GHz processor */
#define OO_EPOLL_MAX_TIMEOUT_NS INT64_MAX

/* Convert a timeout in cycles to one in ns. */
static inline ci_uint64 oo_epoll_frc_to_ns(ci_int64 hr)
{
  ci_assert_ge(hr, 0);
  ci_assert_le((ci_uint64)hr, OO_EPOLL_MAX_TIMEOUT_FRC);
  /* Ensure that a huge hr-timeout is converted to huge ns-timeout */
  ci_uint128 ns = (ci_uint128)hr * (ci_uint128)citp.epoll_frc_to_ns_magic >> 44;
  return (ns > OO_EPOLL_MAX_TIMEOUT_NS) ? OO_EPOLL_MAX_TIMEOUT_NS : (ci_uint64)ns;
}

extern int citp_epoll_create(int size, int flags) CI_HF;
extern int citp_epoll_ctl(citp_fdinfo* fdi, int op, int fd,
                          struct epoll_event *event) CI_HF;
extern int citp_epoll_wait(citp_fdinfo*, struct epoll_event*,
                           struct citp_ordered_wait* ordering, int maxev,
                           ci_int64 timeout_hr, const sigset_t *sigmask,
                           const struct timespec *ts,
                           citp_lib_context_t*) CI_HF;
extern void citp_epoll_on_move(citp_fdinfo*, citp_fdinfo*, citp_fdinfo*,
                               int fdt_locked) CI_HF;
extern void citp_epoll_on_handover(citp_fdinfo*, citp_fdinfo*,
                                   int fdt_locked) CI_HF;
extern void citp_epoll_on_close(citp_fdinfo*, citp_fdinfo*,
                                int fdt_locked) CI_HF;

#if CI_CFG_TIMESTAMPING
struct onload_ordered_epoll_event;
extern int citp_epoll_ordered_wait(citp_fdinfo* fdi,
                                   struct epoll_event*__restrict__ events,
                                   struct onload_ordered_epoll_event* oo_events,
                                   int maxevents, int timeout,
                                   const sigset_t *sigmask,
                                   citp_lib_context_t *lib_context);
#endif
extern void citp_epoll_remove_if_not_ready(struct oo_ul_epoll_state* eps,
                                           struct citp_epoll_member* eitem,
                                           ci_netif* ni, citp_waitable* w);


/* At time of writing, we never generate the following epoll events:
 *
 *  EPOLLRDHUP
 *  EPOLLRDBAND
 *  EPOLLMSG
 */
#define OO_EPOLL_READ_EVENTS   (EPOLLIN | EPOLLRDNORM | EPOLLPRI)
#define OO_EPOLL_WRITE_EVENTS  (EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND)
#define OO_EPOLL_HUP_EVENTS    (EPOLLHUP | EPOLLERR)

#define OO_EPOLL_ALL_EVENTS    (OO_EPOLL_READ_EVENTS  | \
                                OO_EPOLL_WRITE_EVENTS | \
                                OO_EPOLL_HUP_EVENTS)


int
citp_ul_epoll_find_events(struct oo_ul_epoll_state* eps,
                          struct citp_epoll_member*__restrict__ eitem,
                          unsigned events, ci_uint64 sleep_seq,
                          volatile ci_uint64* sleep_seq_p, int* seq_mismatch);

/* Function to be called at the end of citp_protocol_impl->epoll()
 * function, when UL reports events "mask".
 *
 * sleep_seq should be the value of *sleep_seq_p taken _before_
 * looking for events.
 *
 * Returns true if an event was stored, else false.
 */
ci_inline int
citp_ul_epoll_set_ul_events(struct oo_ul_epoll_state*__restrict__ eps,
                            struct citp_epoll_member*__restrict__ eitem,
                            unsigned events, ci_uint64 sleep_seq,
                            volatile ci_uint64* sleep_seq_p,
                            int* seq_mismatch)
{
  Log_VVPOLL(
    if( events )
      ci_log("%s: member=%llx mask=%x events=%x report=%x",
               __FUNCTION__, (long long) eitem->epoll_data.data.u64,
                 eitem->epoll_data.events, events,
                   eitem->epoll_data.events & events)
          );
  events &= eitem->epoll_data.events;
  return events ?
      citp_ul_epoll_find_events(eps, eitem, events,
                                sleep_seq, sleep_seq_p, seq_mismatch) : 0;
}

ci_uint64 citp_sock_sleep_seq(citp_fdinfo* fdi);



/*************************************************************************
 ******************* The EPOLL implementation B **************************
 *************************************************************************/

extern int citp_epollb_create(int size, int flags) CI_HF;
extern int citp_epollb_ctl(citp_fdinfo* fdi, int op, int fd,
                    struct epoll_event *event) CI_HF;
extern int citp_epollb_wait(citp_fdinfo* fdi, struct epoll_event *events,
                     int maxevents, ci_int64 timeout_hr,
                     const sigset_t *sigmask, const struct timespec *ts,
                     citp_lib_context_t* lib_context) CI_HF;

extern void citp_epollb_on_handover(citp_fdinfo*, citp_fdinfo*) CI_HF;

#endif /* __UNIX_UL_EPOLL_H__ */
