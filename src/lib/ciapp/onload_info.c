/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2009-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Tools for testing onload.
**   \date  2009/05/13
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */
#include <ci/app.h>
#include <ci/app/onload.h>


/* If the onload library is present, and defines onload_version, then this
 * will resolve to the onload library.  Otherwise &onload_version will be
 * null (because it is weak and undefined).
 */
extern const char*const onload_version __attribute__((weak));
extern char** environ;


int ci_onload_is_active(void)
{
  const char* ld_preload;
  if( &onload_version )
    return 1;
  ld_preload = getenv("LD_PRELOAD");
  if( ld_preload == NULL )
    return 0;
  return strstr(ld_preload, "libcitransport") != NULL
    ||   strstr(ld_preload, "libonload") != NULL;
}


void ci_onload_info_dump(FILE* f, const char* pf)
{
  const char* ld_preload;
  char** p;

  ld_preload = getenv("LD_PRELOAD");
  if( ld_preload )
    fprintf(f, "%sLD_PRELOAD=%s\n", pf, ld_preload);
  if( &onload_version )
    fprintf(f, "%sonload_version=%s\n", pf, onload_version);
  if( ci_onload_is_active() )
    for( p = environ; *p != NULL; ++p )
      if( strncmp("EF_", *p, 3) == 0 )
        fprintf(f, "%s%s\n", pf, *p);
}
