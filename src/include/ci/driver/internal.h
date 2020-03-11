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

/*! \cidoxg_include_ci_driver  */

#ifndef __CI_DRIVER_INTERNAL__
#define __CI_DRIVER_INTERNAL__

#ifndef __CI_TOOLS_H__
# include <ci/tools.h>
#endif
#include <ci/tools/timeval.h>


/* Needed by the platform code. */
#define ci_waitq_wait_forever(timevalp)     \
  (!(timevalp) || !((timevalp)->tv_sec + (timevalp)->tv_usec))


#ifndef NDEBUG
#include <ci/tools/memleak_debug.h>
#endif

#ifndef __ci_driver__
# error ci/driver/internal.h included, but __ci_driver__ is not defined.
#endif

#if defined(__ci_ul_driver__)

# include <ci/driver/platform/ul_driver_common.h>

#  include <ci/driver/platform/unix_common.h>
#  include <ci/driver/platform/unix_ul_driver.h>

#elif !defined(__KERNEL__)

# error Ooops.

#else

# include <ci/driver/platform/linux_kernel.h>

#endif


#endif  /* __CI_DRIVER_INTERNAL__ */
/*! \cidoxg_end */
