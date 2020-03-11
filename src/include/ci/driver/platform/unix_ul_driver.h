/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_platform  */

#ifndef __CI_DRIVER_PLATFORM_UNIX_UL_H__
#define __CI_DRIVER_PLATFORM_UNIX_UL_H__


/*--------------------------------------------------------------------
 *
 * ci_waitable_t, using pthreads
 *
 *--------------------------------------------------------------------*/

typedef struct {
  pthread_cond_t  cv;
  pthread_mutex_t mutex;
} ci_waitable_t;

typedef int ci_waiter_t;

typedef struct {
  struct timespec ts;
  int forever;
  int timedout;
} ci_waitable_timeout_t;


ci_inline void ci_waitable_ctor(ci_waitable_t* wq) { 
  pthread_cond_init(&wq->cv, 0); 
  pthread_mutex_init(&wq->mutex, 0); 
}

/*! Comment? */
ci_inline void ci_waitable_dtor(ci_waitable_t* wq) {
  pthread_cond_destroy(&wq->cv);  
  pthread_mutex_destroy(&wq->mutex);
}

ci_inline void ci_waitable_wakeup_one(ci_waitable_t* wq) {
  pthread_mutex_lock(&wq->mutex);  /*!< needed to prevent races... */
  pthread_mutex_unlock(&wq->mutex);
  pthread_cond_broadcast(&wq->cv); 
}
#define ci_waitable_wakeup_all	ci_waitable_wakeup_one

#define ci_waiter_pre(waiter, wq)		\
  do {						\
    *(waiter) = 0;				\
    pthread_mutex_lock(&(wq)->mutex);		\
  } while(0)

#define ci_waiter_exclusive_pre	ci_waiter_pre

#define ci_waiter_post(waiter, wq)		\
  pthread_mutex_unlock(&(wq)->mutex)

#define ci_waiter_prepare_continue_to_wait(a, b)
#define ci_waiter_dont_continue_to_wait(a, b)
  
#define ci_waiter_dont_wait  ci_waiter_post

#define CI_WAITER_CONTINUE_TO_WAIT	1
#define CI_WAITER_CONTINUE_TO_WAIT_REENTRANT  2
#define CI_WAITER_CONVERT_REENTRANT(x)    (x)

ci_inline int ci_waiter_wait(ci_waiter_t* waiter, ci_waitable_t* wq,
			     ci_waitable_timeout_t *timeout, void* opaque,
			     int (*on_wakeup)(ci_waiter_t*,
					      void* opaque, int rc)) {
  int rc;
  while( 1 ) {
    if ( (timeout == NULL) || timeout->forever)
      rc = pthread_cond_wait(&wq->cv, &wq->mutex);
    else
      rc = pthread_cond_timedwait(&wq->cv, &wq->mutex, &timeout->ts);
    if( rc == ETIMEDOUT )   rc = -ETIMEDOUT;
    else if( rc == EINTR )  rc = -EINTR;
    else                    rc = 0;
    rc = on_wakeup(waiter, opaque, rc);
    if( rc != CI_WAITER_CONTINUE_TO_WAIT )  break;
  }
  return rc;
}


/*--------------------------------------------------------------------
 *
 * wait_queue, using pthreads
 *
 *--------------------------------------------------------------------*/

/*! Comment? */
typedef struct {
  pthread_cond_t  cv;
  pthread_mutex_t mutex;
} ci_waitq_t;

typedef int ci_waitq_waiter_t;  /*!< dummy -- not used */

/*! Comment? */
typedef struct {
  struct timespec ts;
  int forever;
  int timedout;
} ci_waitq_timeout_t;


/*! Comment? */
ci_inline void ci_waitq_ctor(ci_waitq_t* wq) { 
  pthread_cond_init(&wq->cv, 0); 
  pthread_mutex_init(&wq->mutex, 0); 
}

/*! Comment? */
ci_inline void ci_waitq_dtor(ci_waitq_t* wq) {
  pthread_cond_destroy(&wq->cv);  
  pthread_mutex_destroy(&wq->mutex);
}

/*! Comment? */
ci_inline int ci_waitq_active(ci_waitq_t* wq) {
  return 1;
}

/*! Comment? */
ci_inline void ci_waitq_wakeup(ci_waitq_t* wq) {
  pthread_mutex_lock(&wq->mutex);  /*!< needed to prevent races... */
  pthread_mutex_unlock(&wq->mutex);
  pthread_cond_broadcast(&wq->cv); 
}

#define ci_waitq_init_timeout(_ts, _tv)				\
  do {								\
    (_ts)->timedout = 0;					\
    if( ci_waitq_wait_forever(_tv) ) {				\
      (_ts)->forever = 1;					\
    } else {							\
      struct timeval now;					\
      gettimeofday(&now, 0);					\
      now.tv_sec += (_tv)->tv_sec;				\
      now.tv_usec += (_tv)->tv_usec;				\
      (_ts)->ts.tv_sec = now.tv_sec + now.tv_usec / 1000000;	\
      (_ts)->ts.tv_nsec = now.tv_usec % 1000000 * 1000;		\
      (_ts)->forever = 0;					\
    }								\
  } while(0)

#define ci_waitq_waiter_pre(waiter, wq)		\
  do {						\
    *(waiter) = 0;				\
    pthread_mutex_lock(&(wq)->mutex);		\
  } while(0)

#define ci_waitq_waiter_exclusive_pre  ci_waitq_waiter_pre

#define ci_waitq_waiter_wait(waiter, wq, cond)			\
  do {								\
    if( !(cond) )  pthread_cond_wait(&(wq)->cv, &(wq)->mutex);	\
  } while(0)

#define ci_waitq_waiter_timedwait(waiter, wq , cond, tmo)		    \
  do {									    \
    if( !(cond) ) {							    \
      do {								    \
	int rc;								    \
	if( (tmo)->forever )						    \
	  rc = pthread_cond_wait(&(wq)->cv, &(wq)->mutex);		    \
	else								    \
	  rc = pthread_cond_timedwait(&(wq)->cv, &(wq)->mutex, &(tmo)->ts); \
	if( rc == 0 )  break;						    \
	if( rc == ETIMEDOUT ) { (tmo)->timedout = 1; break; }		    \
	/* Otherwise we got EINTR.  Keep waiting. */			    \
      } while( !(cond) );						    \
    }									    \
  } while(0)

#define ci_waitq_waiter_again(waiter, wq)

#define ci_waitq_waiter_post(waiter, wq)	\
  pthread_mutex_unlock(&(wq)->mutex)

#define ci_waitq_waiter_signalled(waiter, wq)  (*(waiter))

#define ci_waitq_waiter_timedout(timeout)      ((timeout)->timedout)


#endif  /* __CI_DRIVER_PLATFORM_UNIX_UL_H__ */
/*! \cidoxg_end */
