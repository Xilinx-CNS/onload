/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
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

/*! \cidoxg_include_ci_tools_platform  */

#ifndef __CI_TOOLS_UNIX_H__
#define __CI_TOOLS_UNIX_H__

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <stdarg.h>
#include <stddef.h>
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/stat.h>

/**********************************************************************
 * User level common includes
 */
#include <ci/tools/platform/ul_common.h>


/**********************************************************************
 * spinlock implementation: used by <ci/tools/spinlock.h>
 */

#define CI_HAVE_SPINLOCKS

typedef ci_uintptr_t			  ci_lock_holder_t;

#define ci_lock_thisthread 	(ci_lock_holder_t)pthread_self()
#define ci_lock_no_holder   (ci_lock_holder_t)NULL

typedef pthread_mutex_t			ci_lock_i;
typedef pthread_mutex_t			ci_irqlock_i;
typedef char				ci_irqlock_state_t;

#define IRQLOCK_CYCLES  500000

#define ci_lock_ctor_i(l)		pthread_mutex_init(l, 0)
#define ci_lock_dtor_i(l)		pthread_mutex_destroy(l)
#define ci_lock_lock_i(l)		pthread_mutex_lock(l)
#define ci_lock_trylock_i(l)		(pthread_mutex_trylock(l) == 0)
#define ci_lock_unlock_i(l)		pthread_mutex_unlock(l)

#define ci_irqlock_ctor_i(l)		pthread_mutex_init(l, 0)
#define ci_irqlock_dtor_i(l)		pthread_mutex_destroy(l)
ci_inline void ci_irqlock_lock_i(ci_irqlock_i* l, ci_irqlock_state_t* s)
{ pthread_mutex_lock(l); }
ci_inline void ci_irqlock_unlock_i(ci_irqlock_i* l, ci_irqlock_state_t* s)
{ pthread_mutex_unlock(l); }


/**********************************************************************
 * Thread-safe strtok
 */

#define ci_strtok_local(_ptr) char *_ptr
#define ci_strtok(_s, _delim, _ptrptr) strtok_r(_s, _delim, _ptrptr)

/**********************************************************************
 * struct iovec abstraction (for Windows port)
 */

typedef struct iovec ci_iovec;

/* Accessors for buffer/length */
#define CI_IOVEC_BASE(i) ((i)->iov_base)
#define CI_IOVEC_LEN(i)  ((i)->iov_len)

/* The memfd_create() system call first appeared in Linux 3.17, glibc
 * support was added in version 2.27, MFD_HUGETLB is available on Linux
 * since 4.14, as per man 2 memfd_create. To support newer kernels with
 * older glibc (e.g. in containers), we define these ourselves. At the
 * same time, they won't cause issues in the newer configurations where
 * they are available, as long as they are the correct values because
 * the macro redefinition is silently ignored. */
#define MFD_CLOEXEC 1U
#define MFD_HUGETLB 4U
#if defined __x86_64__
#define __NR_memfd_create 319
#elif defined __aarch64__
#define __NR_memfd_create 279
#endif

#endif  /* __CI_TOOLS_UNIX_H__ */

/*! \cidoxg_end */
