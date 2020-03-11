/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author
**  \brief
**   \date
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */

#ifndef __CI_APP_UTILS_H__
#define __CI_APP_UTILS_H__


/*! *********************************************************************
 ** ci_sleep: at most 1e6 millisecs please.
 */

#ifndef __KERNEL__
ci_inline void ci_sleep(int millisecs)  { usleep(millisecs * 1000); }
#endif


/*! *********************************************************************
 ** ci_gettimeofday: microsecond counter.
 **
 ** Unlike ci_ctimer, this is capable of long term timing.
 */

/* NB. Granularity may not be as good as microseconds. */

# ifndef __KERNEL__
ci_inline void ci_gettimeofday(ci_uint64 *pval) {
  struct timeval tv;
  gettimeofday(&tv, 0);
  *pval = (ci_uint64) tv.tv_sec * 1000000 + tv.tv_usec;
}
#endif


/**********************************************************************
 ** ci_select_: simplified select interface.
 */

#define CI_SELECT_READABLE  0x1
#define CI_SELECT_WRITABLE  0x2
#define CI_SELECT_EXCEPT    0x4

/*! Comment? */
extern int ci_select_1(int fd, int which, int* state_out,
		       const struct timeval* timeout);
  /*! Wrapper to simplify select() on a single descriptor.  Not maximally
  ** efficient---it is assumed you are using this for convenience, and
  ** don't care desperately about performance.
  **
  ** [timeout] may be 0 (block forever), and {0,0} means return
  ** immediately.
  **
  ** Returns 0 on success, -ETIMEDOUT on timeout, or another negative error
  ** code.
  */

extern int ci_select_2(int fd1, int which1, int* state1_out,
		       int fd2, int which2, int* state2_out,
		       const struct timeval* timeout);


#define ci_wait_readable(fd, timeout)  \
ci_select_1( (fd), CI_SELECT_READABLE, 0, (timeout) )

#define ci_wait_writable(fd, timeout)  \
ci_select_1((fd), CI_SELECT_WRITABLE, 0, (timeout))


/*! *********************************************************************
 ** ci_fork_filter()
 */

extern int ci_fork_filter(char* const argv[]);


/**********************************************************************
 ** ci_rate_thread_fn()
 */

typedef struct ci_rate_thread_cfg_s ci_rate_thread_cfg;

struct ci_rate_thread_cfg_s {
  const volatile unsigned* pval;
  unsigned		interval_msec;
  void			(*action)(ci_rate_thread_cfg*, unsigned val_now,
				  unsigned val_prev, unsigned intvl_msec);
  volatile int		stop;
};

ci_inline void ci_rate_thread_cfg_init(ci_rate_thread_cfg* c,
				       const volatile unsigned* pval,
				       unsigned interval_msec,
				       void (*action)(ci_rate_thread_cfg*,
						      unsigned, unsigned,
						      unsigned)) {
  c->pval = pval;
  c->interval_msec = interval_msec;
  c->action = action;
  c->stop = 0;
}

extern void* ci_rate_thread_fn(void* p_ci_rate_thread_cfg);


#endif  /* __CI_APP_UTILS_H__ */
/*! \cidoxg_end */
