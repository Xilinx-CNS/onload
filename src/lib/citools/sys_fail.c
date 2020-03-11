/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
  
/*! \cidoxg_lib_citools */

#include "citools_internal.h"


void __ci_sys_fail(const char* fn, int rc, const char* file, int line)
{
  ci_log("*** UNEXPECTED ERROR ***");
  ci_log("        what: %s", fn);
  ci_log(" called from: %s:%d", file, line);
  ci_log(" return code: %d", rc);
#ifndef __KERNEL__
  ci_log("       errno: %d", errno);
  ci_log("    strerror: %s", strerror(errno));
#endif
  ci_fail((" "));
}

/*! \cidoxg_end */
