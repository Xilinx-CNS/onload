/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  slp
**  \brief  Spinlock support.
**   \date  2002/08/13
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifdef CI_HAVE_SPINLOCKS
#ifndef __CI_TOOLS_SPINLOCK_H__
#define __CI_TOOLS_SPINLOCK_H__


#if ! defined(NDEBUG) && ! defined(__PPC__)
# define CI_DEBUG_SPINLOCK                1
#else
# define CI_DEBUG_SPINLOCK                0
#endif


/*--------------------------------------------------------------------
 *
 * spinlock operations - safe (but not optimal) in all circumstances
 *
 * usage:
 *		ci_lock_ctor(l)
 *	        ci_lock_lock(l)
 *	        ci_lock_trylock(l)
 *	        ci_lock_unlock(l)
 *	        ci_lock_dtor(l)
 *
 *		ci_irqlock_ctor(l)
 *	        ci_irqlock_lock(l, flags)
 *	        ci_irqlock_unlock(l, flags)
 *	        ci_irqlock_dtor(l)
 *
 * You can also use the *_dbg versions of these macros to report your own
 * file position information (e.g. from your own macros)
 *
 *		ci_lock_ctor_dbg(l, file, line)
 *	        ci_lock_lock_dbg(l, file, line)
 *	        ci_lock_trylock_dbg(l, file, line)
 *	        ci_lock_unlock_dbg(l, file, line)
 *	        ci_lock_dtor_dbg(l, file, line)
 *
 *		ci_irqlock_ctor_dbg(l, file, line)
 *	        ci_irqlock_lock_dbg(l, flags, file, line)
 *	        ci_irqlock_unlock_dbg(l, flags, file, line)
 *	        ci_irqlock_dtor_dbg(l, file, line)
 *
 * (these macros are the same as the non _dbg versions if !CI_DEBUG_SPINLOCK)
 *
 * e.g.
 *        #define MY_LOCK(l) ci_lock_lock_dbg(l, __FILE__, __LINE__)
 *
 *        // and for other's to use: 
 *        #define MY_LOCK_DBG(l, fl, ln) ci_lock_lock_dbg(l, fl, ln)
 *
 *--------------------------------------------------------------------*/

/*--------------------------------------------------------------------
 *
 * NB platform specific lock declarations must have been included
 *
 *	e.g. tools/platform/linux_kernel.h
 *
 *	ci_lock_thisthread	- thread ident of caller
 *	ci_lock_no_holder	- value to use for nobody
 *	ci_lock_i		- platform specific spin lock
 *
 *--------------------------------------------------------------------*/


#define ci_lock_ctor(l)	          ci_lock_ctor_dbg(l, __FILE__, __LINE__)
#define ci_lock_dtor(l)	          ci_lock_dtor_dbg(l, __FILE__, __LINE__)
#define ci_lock_lock(l)           ci_lock_lock_dbg(l, __FILE__, __LINE__)
#define ci_lock_trylock(l)	  ci_lock_trylock_dbg(l, __FILE__, __LINE__)
#define ci_lock_unlock(l)	  ci_lock_unlock_dbg(l, __FILE__, __LINE__)
#define ci_lock_check_locked(l)     \
                           ci_lock_check_locked_dbg(l, __FILE__, __LINE__)

#define ci_irqlock_ctor(l)	  ci_irqlock_ctor_dbg(l, __FILE__, __LINE__)
#define ci_irqlock_dtor(l)	  ci_irqlock_dtor_dbg(l, __FILE__, __LINE__)
#define ci_irqlock_lock(l,s)	    \
                           ci_irqlock_lock_dbg((l),(s), __FILE__, __LINE__)
#define ci_irqlock_unlock(l,s)	    \
                           ci_irqlock_unlock_dbg((l),(s), __FILE__, __LINE__)
#define ci_irqlock_check_locked(l)  \
                           ci_irqlock_check_locked_dbg((l), __FILE__, __LINE__)


#if ! CI_DEBUG_SPINLOCK

# define ci_lock_t			ci_lock_i
# define ci_irqlock_t			ci_irqlock_i

# define ci_lock_ctor_dbg(l,fl,ln)	  ci_lock_ctor_i(l)
# define ci_lock_dtor_dbg(l,fl,ln)	  ci_lock_dtor_i(l)
# define ci_lock_lock_dbg(l,fl,ln)	  ci_lock_lock_i(l)
# define ci_lock_trylock_dbg(l,fl,ln)	  ci_lock_trylock_i(l)
# define ci_lock_unlock_dbg(l,fl,ln)	  ci_lock_unlock_i(l)
# define ci_lock_check_locked_dbg(l,fl,ln)     

# define ci_irqlock_ctor_dbg(l,fl,ln)	  ci_irqlock_ctor_i(l)
# define ci_irqlock_dtor_dbg(l,fl,ln)	  ci_irqlock_dtor_i(l)
# define ci_irqlock_lock_dbg(l,s,fl,ln)	  ci_irqlock_lock_i((l),(s))
# define ci_irqlock_unlock_dbg(l,s,fl,ln) ci_irqlock_unlock_i((l),(s))
# define ci_irqlock_check_locked_dbg(l,fl,ln)       

#else /* CI_DEBUG_SPINLOCK */

/*--------------------------------------------------------------------
 *
 * debug code - 
 *  checks for recursive locking.
 *  enforces unlocker must be same thread as locker. 
 *  obviously can't check for deadlock, but if you suspect being hung on a lock
 *  then you could try tracing at lock acquisition time - but beware of
 *  changing the race behaviour of the program.
 *
 *--------------------------------------------------------------------*/

/*! Spinlock type (Debug) */
typedef struct {
  unsigned long magic;			/*!< magic number */
  volatile ci_lock_holder_t holder;	/*!< thread identity of lock holder */
  const char *file;		/*!< filename of last lock taker */
  int line;			/*!< line in file of last lock taker */
  ci_uint32 frc32;              /*!< frc value at the time the lock was taken */
} ci_lock_debug_t;


/* Spinlock */
typedef struct {
  ci_lock_i		os;	/*!< platform specific spinlock */
  ci_lock_debug_t	debug;	/*!< state used for debug purposes */
} ci_lock_t;


/* IRQ-safe spinlock */
typedef struct {
  ci_irqlock_i		os;	/*!< platform specific spinlock */
  ci_lock_debug_t	debug;	/*!< state used for debug purposes */
} ci_irqlock_t;


# define ci_lock_ctor_dbg(l,fl,ln)	  _ci_lock_ctor((l), (fl), (ln))
# define ci_lock_dtor_dbg(l,fl,ln)	  _ci_lock_dtor((l), (fl), (ln))
# define ci_lock_lock_dbg(l,fl,ln)	  _ci_lock_lock((l), (fl),(ln))
# define ci_lock_trylock_dbg(l,fl,ln)	  _ci_lock_trylock((l), (fl),(ln))
# define ci_lock_unlock_dbg(l,fl,ln)	  _ci_lock_unlock((l), (fl),(ln))
# define ci_lock_check_locked_dbg(l,fl,ln)   \
                            _ci_lock_check_locked((l), (fl),(ln))


# define ci_irqlock_ctor_dbg(l,fl,ln)	  _ci_irqlock_ctor((l), (fl),(ln))
# define ci_irqlock_dtor_dbg(l,fl,ln)	  _ci_irqlock_dtor((l), (fl),(ln))
# define ci_irqlock_lock_dbg(l,s,fl,ln)	  _ci_irqlock_lock((l), (s), (fl),(ln))
# define ci_irqlock_unlock_dbg(l,s,fl,ln) _ci_irqlock_unlock((l),(s),(fl),(ln))
# define ci_irqlock_check_locked_dbg(l,fl,ln)     \
                            _ci_irqlock_check_locked((l), (fl),(ln))


# define _ci_lock_error(lock, msg, file, line)				     \
  ci_fail(("ci_lock_%s at %s:%d (prev %s:%d)(me:holder %p:%p)(magic %lx)", \
	  (msg), (file), (line), (lock)->debug.file, (lock)->debug.line,     \
	  (void *)ci_lock_thisthread, (void *)(lock)->debug.holder, \
    (lock)->debug.magic))


# define ci_lock_magic		(0x23121996 + (1))	/* magic number */    

# define ci_lock_debug_ctor \
do { lock->debug.magic = ci_lock_magic; \
     lock->debug.holder = ci_lock_no_holder;\
    } while(0)

# define ci_lock_debug_dtor	lock->debug.magic = 0xdeadbeef;

# define ci_lock_lock_trace			\
do { lock->debug.file = file;			\
     lock->debug.line = line;			\
     lock->debug.holder = ci_lock_thisthread;	\
   } while(0)

# define ci_lock_unlock_trace			\
do { lock->debug.file = file;			\
     lock->debug.line = line;			\
     lock->debug.holder = ci_lock_no_holder;	\
   } while(0)

# define ci_lock_bad_magic 	(lock->debug.magic != ci_lock_magic)
# define ci_lock_is_locked	(lock->debug.holder != ci_lock_no_holder)
# define ci_lock_by_me 		(lock->debug.holder == ci_lock_thisthread)
# define ci_lock_by_another	(ci_lock_is_locked && \
                                 (lock->debug.holder != ci_lock_thisthread))
# define ci_lock_error(l,m)	_ci_lock_error(l, m, file, line)


/*! Spinlock ctor */
ci_inline void 
_ci_lock_ctor(ci_lock_t* lock , const char* file, int line) {
  memset(lock, 0, sizeof(*lock));
  ci_lock_debug_ctor;
  ci_lock_ctor_i(&lock->os);
}


/*! Spinlock dtor */
ci_inline void 
_ci_lock_dtor(ci_lock_t* lock, const char* file, int line) {
  if ( ci_lock_bad_magic ) ci_lock_error(lock, "dtor: bad magic");
  if ( ci_lock_is_locked ) ci_lock_error(lock, "dtor: locked");
  ci_lock_debug_dtor;
  ci_lock_dtor_i(&lock->os);
  return;
}

/*! Spinlock lock */
ci_inline void
_ci_lock_lock(ci_lock_t* lock, const char* file, int line) {
  int i = 0;
  if ( ci_lock_bad_magic ) ci_lock_error(lock, "lock: bad magic");
  if ( ci_lock_by_me ) ci_lock_error(lock, "lock: deadlock");
  while( !ci_lock_trylock_i(&lock->os) )
    if( i++ > 1000000000 )  ci_lock_error(lock, "lock: timeout");
  ci_lock_lock_trace;
}

/*! Try to take out spinlock */
ci_inline int
_ci_lock_trylock(ci_lock_t* lock, const char* file, int line) {
  int ret;
  if ( ci_lock_bad_magic ) ci_lock_error(lock, "trylock: bad magic");
  if ( ci_lock_by_me ) ci_lock_error(lock, "trylock: deadlock");
  if( (ret = ci_lock_trylock_i(&lock->os)) )
    ci_lock_lock_trace;
  return ret;
}

/*! Spinlock unlock */
ci_inline void
_ci_lock_unlock(ci_lock_t*lock, const char* file, int line){
  if ( ci_lock_bad_magic ) ci_lock_error(lock, "unlock: bad magic");
  if ( !ci_lock_is_locked ) ci_lock_error(lock, "unlock: not locked");
  if ( ci_lock_by_another ) ci_lock_error(lock, "unlock: another");
  ci_lock_unlock_trace;
  ci_lock_unlock_i(&lock->os);
}

/*! Spinlock check locked */
ci_inline void
_ci_lock_check_locked(ci_lock_t*lock, const char* file, int line)
{
  if ( !ci_lock_is_locked ) 
    ci_lock_error(lock, "check_locked: not locked");
}


/**********************************************************************/

/*! Spinlock ctor */
ci_inline void 
_ci_irqlock_ctor(ci_irqlock_t* lock , const char* file, int line) {
  memset(lock, 0, sizeof(*lock));
  ci_lock_debug_ctor;
  ci_irqlock_ctor_i(&lock->os);
}

/*! Spinlock dtor */
ci_inline void 
_ci_irqlock_dtor(ci_irqlock_t* lock, const char* file, int line) {
  if ( ci_lock_bad_magic ) ci_lock_error(lock, "dtor: bad magic");
  if ( ci_lock_is_locked ) ci_lock_error(lock, "dtor: locked");
  ci_lock_debug_dtor;
  ci_irqlock_dtor_i(&lock->os);
  return;
}

/*! Spinlock lock */
ci_inline void
_ci_irqlock_lock(ci_irqlock_t* lock, ci_irqlock_state_t*s,
		 const char* file, int line) {
  if ( ci_lock_bad_magic ) ci_lock_error(lock, "lock: bad magic");
  if ( ci_lock_by_me ) ci_lock_error(lock, "lock: deadlock");
  ci_irqlock_lock_i(&lock->os, s);
  lock->debug.frc32 = ci_frc32_get();
  ci_lock_lock_trace;
}

/*! Spinlock unlock */
ci_inline void
_ci_irqlock_unlock(ci_irqlock_t*lock, ci_irqlock_state_t*s,
		   const char* file, int line){
  if ( ci_lock_bad_magic ) ci_lock_error(lock, "unlock: bad magic");
  if ( !ci_lock_is_locked ) ci_lock_error(lock, "unlock: not locked");
  if ( ci_lock_by_another ) ci_lock_error(lock, "unlock: another");
  ci_lock_unlock_trace;
  ci_irqlock_unlock_i(&lock->os, s);
}

/*! Spinlock check locked */
ci_inline void
_ci_irqlock_check_locked(ci_irqlock_t*lock,
		         const char* file, int line)
{
  if ( !ci_lock_is_locked ) 
    ci_lock_error(lock, "check_locked: not locked");
}


#endif /* CI_DEBUG_SPINLOCK */

#define ci_irqlock_safely_do(lockp, cmd)     \
  do {                                       \
    ci_irqlock_state_t __irqstate;           \
    ci_irqlock_lock((lockp), &__irqstate);   \
    {cmd;}                                   \
    ci_irqlock_unlock((lockp), &__irqstate); \
  } while(0)


#endif /* __CI_TOOLS_SPINLOCK_H__ */
#endif /* #ifdef CI_HAVE_SPINLOCKS   */

/*! \cidoxg_end */
