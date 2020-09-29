/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2009-2020 Xilinx, Inc. */
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

#include <onload/common.h> /* for oo_signal_common_state */

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
extern struct oo_sigaction citp_signal_data[NSIG];
void citp_signal_intercept(int signum, siginfo_t *info, void *context);
extern void *citp_signal_sarestorer_get(void);
extern sa_sigaction_t citp_signal_handlers[OO_SIGHANGLER_DFL_MAX+1];

#endif

struct oo_sig_thread_state {
  struct oo_signal_common_state c;

#ifndef __KERNEL__
  /*! State of currently-pending signals; pure userland data. */
  citp_signal_state_t signals[OO_SIGNAL_MAX_PENDING];
#endif
};

#endif  /* __ONLOAD_SIGNALS_H__ */
