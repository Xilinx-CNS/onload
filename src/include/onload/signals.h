/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mjs
**  \brief  Decls needed for async signal management.
**   \date  2005/03/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_SIGNALS_H__
#define __ONLOAD_SIGNALS_H__

/* Signal handler state: filled in kernel by OO_IOC_SIGACTION, used in UL */
struct oo_sigaction {
  ci_user_ptr_t handler; /*!< UL function pointer */
  ci_int32      flags;   /*!< SA_RESTART, SA_SIGINFO and SA_ONESHOT */
  volatile ci_int32  type;    /*!< Type of signal handler */
  /*! SIG_DFL handlers should start from 0 */
#define OO_SIGHANGLER_TERM 0 /*!< SIG_DFL: teminate */
#define OO_SIGHANGLER_STOP 1 /*!< SIG_DFL: stop */
#define OO_SIGHANGLER_CORE 2 /*!< SIG_DFL: core */
#define OO_SIGHANGLER_DFL_MAX 2 /*!< max value for SIG_DFL handlers */
#define OO_SIGHANGLER_BUSY 3 /*!< Locked now: wait for another value */
#define OO_SIGHANGLER_USER 4 /*!< User-specified handler */
#define OO_SIGHANGLER_TYPE_MASK 0x7
/*!< Non-intercepted signal: old interception data is available */
#define OO_SIGHANGLER_IGN_BIT  0x8

#define OO_SIGHANGLER_SEQ_MASK  0xffffff0
#define OO_SIGHANGLER_SEQ_SHIFT 4
};

#ifndef __KERNEL__
#include <ucontext.h>
#include <signal.h>


/* This value is tradeoff between saving Thread Local Storage space
 * and keeping as much pending signals as possible.
 *
 * On the app I've used (Ixia/endpoint) OO_SIGNAL_MAX_PENDING=50 works,
 * OO_SIGNAL_MAX_PENDING=55 does not because of libc bug
 * http://sourceware.org/bugzilla/show_bug.cgi?id=11787 .
 *
 * If we ever copy ucontect_t context in the same way as we do it
 * for siginfo_t, we should use OO_SIGNAL_MAX_PENDING=5 or
 * something like that.
 */
#define OO_SIGNAL_MAX_PENDING 20

/*! Info about pending signal.
 * This structure should be as small as possible because of the reasons
 * explained above. */
typedef struct citp_signal_state_s {
  ci_int32          signum;         /*!< Signal number */
  void *            saved_context;  /*!< Saved parameter for sa_sigaction */
  siginfo_t         saved_info;     /*!< Saved parameter for sa_sigaction */
} citp_signal_state_t;

typedef void (*sa_sigaction_t)(int, siginfo_t *, void *);

/* signal data for trampoline */
struct oo_sigaction citp_signal_data[NSIG];
void citp_signal_intercept(int signum, siginfo_t *info, void *context);
extern void *citp_signal_sarestorer_get(void);
extern sa_sigaction_t citp_signal_handlers[OO_SIGHANGLER_DFL_MAX+1];

#endif

struct oo_sig_thread_state {
  ci_int32  inside_lib;    /*!< >0 if inside library, so deferral needed */

  ci_uint32 aflags;
#define OO_SIGNAL_FLAG_HAVE_PENDING   0x1  /* have deferred signals pending */
#define OO_SIGNAL_FLAG_NEED_RESTART   0x2  /* SA_RESTART flag was set */
#ifndef NDEBUG
#define OO_SIGNAL_FLAG_FDTABLE_LOCKED 0x4  /* this thread owns fdtable lock */
#endif

#ifndef __KERNEL__
  /*! State of currently-pending signals; pure userland data. */
  citp_signal_state_t signals[OO_SIGNAL_MAX_PENDING];
#endif
};

#endif  /* __ONLOAD_SIGNALS_H__ */
